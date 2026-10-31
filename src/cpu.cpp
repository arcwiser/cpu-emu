#include "winemu/cpu.hpp"

#include "winemu/error.hpp"

#include <bit>
#include <cmath>
#include <iomanip>
#include <limits>
#include <sstream>

#include <intrin.h>

namespace winemu {

namespace {

constexpr std::uint64_t flag_cf = 1ULL << 0;
constexpr std::uint64_t flag_pf = 1ULL << 2;
constexpr std::uint64_t flag_af = 1ULL << 4;
constexpr std::uint64_t flag_zf = 1ULL << 6;
constexpr std::uint64_t flag_sf = 1ULL << 7;
constexpr std::uint64_t flag_df = 1ULL << 10;
constexpr std::uint64_t flag_of = 1ULL << 11;

std::string unknown_instruction(std::uint64_t address, std::uint8_t opcode) {
    std::ostringstream stream;
    stream << "unsupported instruction 0x" << std::hex << std::setw(2) << std::setfill('0')
           << static_cast<unsigned>(opcode) << " at 0x" << address;
    return stream.str();
}

std::uint64_t divide_unsigned_128(std::uint64_t high, std::uint64_t low, std::uint64_t divisor,
                                  std::uint64_t &remainder) {
    if (divisor == 0) {
        throw Error("guest integer divide by zero");
    }
    if (high >= divisor) {
        throw Error("guest integer divide overflow");
    }
    std::uint64_t quotient = 0;
    remainder = high;
    for (int bit = 63; bit >= 0; --bit) {
        const bool carry = (remainder >> 63) != 0;
        remainder = (remainder << 1) | ((low >> bit) & 1);
        if (carry || remainder >= divisor) {
            remainder -= divisor;
            quotient |= 1ULL << bit;
        }
    }
    return quotient;
}

} // namespace

Cpu::Cpu(Memory &memory) : memory_(memory) {}

void Cpu::reset(std::uint64_t entry, std::uint64_t stack_pointer) {
    registers_.fill(0);
    xmm_.fill({0, 0});
    history_.fill(0);
    history_cursor_ = 0;
    registers_[Rsp] = stack_pointer;
    rip_ = entry;
    flags_ = 2;
    instructions_ = 0;
}

std::uint64_t Cpu::reg(Register index) const { return registers_[index]; }

void Cpu::set_reg(Register index, std::uint64_t value) { registers_[index] = value; }

std::uint64_t Cpu::rip() const { return rip_; }

void Cpu::set_rip(std::uint64_t value) { rip_ = value; }

std::uint64_t Cpu::flags() const { return flags_; }

void Cpu::set_gs_base(std::uint64_t value) { gs_base_ = value; }

std::uint64_t Cpu::instructions() const { return instructions_; }

Memory &Cpu::memory() { return memory_; }

std::vector<std::uint64_t> Cpu::recent_instructions() const {
    std::vector<std::uint64_t> addresses;
    addresses.reserve(history_capacity);
    for (std::size_t offset = 0; offset < history_capacity; ++offset) {
        const auto index = (history_cursor_ + offset) % history_capacity;
        if (history_[index] != 0) {
            addresses.push_back(history_[index]);
        }
    }
    return addresses;
}

std::uint8_t Cpu::fetch8() {
    const auto value = memory_.read8(rip_);
    ++rip_;
    return value;
}

std::uint16_t Cpu::fetch16() {
    const auto value = memory_.read16(rip_);
    rip_ += 2;
    return value;
}

std::uint32_t Cpu::fetch32() {
    const auto value = memory_.read32(rip_);
    rip_ += 4;
    return value;
}

std::uint64_t Cpu::fetch64() {
    const auto value = memory_.read64(rip_);
    rip_ += 8;
    return value;
}

Cpu::DecodedRm Cpu::decode_rm(std::uint8_t rex, std::uint64_t pending_immediate) {
    const auto modrm = fetch8();
    const auto mod = static_cast<std::uint8_t>(modrm >> 6);
    const auto raw_reg = static_cast<std::uint8_t>((modrm >> 3) & 7);
    const auto raw_rm = static_cast<std::uint8_t>(modrm & 7);
    const auto reg_index = static_cast<std::uint8_t>(raw_reg + ((rex & 4) ? 8 : 0));
    const auto rm_index = static_cast<std::uint8_t>(raw_rm + ((rex & 1) ? 8 : 0));
    const auto reg_high_byte = rex == 0 && raw_reg >= 4;
    if (mod == 3) {
        return {{true, rm_index, 0, rex == 0 && raw_rm >= 4}, reg_index, reg_high_byte};
    }

    if (address32_) {
        std::uint32_t address = 0;
        bool has_base = true;
        if (raw_rm == 4) {
            const auto sib = fetch8();
            const auto scale = static_cast<unsigned>(sib >> 6);
            const auto raw_index = static_cast<std::uint8_t>((sib >> 3) & 7);
            const auto raw_base = static_cast<std::uint8_t>(sib & 7);
            if (raw_index != 4 || (rex & 2) != 0) {
                const auto index = static_cast<std::uint8_t>(raw_index + ((rex & 2) ? 8 : 0));
                address += static_cast<std::uint32_t>(registers_[index]) << scale;
            }
            if (mod == 0 && raw_base == 5) {
                has_base = false;
            } else {
                const auto base = static_cast<std::uint8_t>(raw_base + ((rex & 1) ? 8 : 0));
                address += static_cast<std::uint32_t>(registers_[base]);
            }
        } else if (mod == 0 && raw_rm == 5) {
            has_base = false;
        } else {
            address += static_cast<std::uint32_t>(registers_[rm_index]);
        }
        if (mod == 0 && !has_base) {
            address += fetch32();
        } else if (mod == 1) {
            address += static_cast<std::int8_t>(fetch8());
        } else if (mod == 2) {
            address += fetch32();
        }
        return {{false, 0, segment_base_ + address, false}, reg_index, reg_high_byte};
    }

    std::uint64_t address = 0;
    bool rip_relative = false;
    bool has_base = true;
    if (raw_rm == 4) {
        const auto sib = fetch8();
        const auto scale = static_cast<unsigned>(sib >> 6);
        const auto raw_index = static_cast<std::uint8_t>((sib >> 3) & 7);
        const auto raw_base = static_cast<std::uint8_t>(sib & 7);
        if (raw_index != 4 || (rex & 2) != 0) {
            const auto index = static_cast<std::uint8_t>(raw_index + ((rex & 2) ? 8 : 0));
            address += registers_[index] << scale;
        }
        if (mod == 0 && raw_base == 5) {
            has_base = false;
        } else {
            const auto base = static_cast<std::uint8_t>(raw_base + ((rex & 1) ? 8 : 0));
            address += registers_[base];
        }
    } else if (mod == 0 && raw_rm == 5) {
        has_base = false;
        rip_relative = true;
    } else {
        address += registers_[rm_index];
    }

    if (mod == 0 && !has_base) {
        const auto displacement = static_cast<std::int32_t>(fetch32());
        // RIP-relative addressing is relative to the address of the instruction that FOLLOWS
        // this one, which includes any immediate that trails the memory operand. Absolute
        // displacement-only addressing (SIB base 5) has no such adjustment.
        if (rip_relative) {
            address += rip_ + pending_immediate +
                       static_cast<std::uint64_t>(static_cast<std::int64_t>(displacement));
        } else {
            address += static_cast<std::uint64_t>(static_cast<std::int64_t>(displacement));
        }
    } else if (mod == 1) {
        address += static_cast<std::int8_t>(fetch8());
    } else if (mod == 2) {
        address += static_cast<std::int32_t>(fetch32());
    }
    return {{false, 0, address + segment_base_, false}, reg_index, reg_high_byte};
}

std::uint64_t Cpu::mask_for(unsigned width) {
    return width == 64 ? std::numeric_limits<std::uint64_t>::max() : (1ULL << width) - 1;
}

std::int64_t Cpu::sign_extend(std::uint64_t value, unsigned width) {
    if (width == 64) {
        return static_cast<std::int64_t>(value);
    }
    const auto sign = 1ULL << (width - 1);
    const auto mask = mask_for(width);
    value &= mask;
    return static_cast<std::int64_t>((value ^ sign) - sign);
}

std::uint64_t Cpu::read_register(std::uint8_t index, unsigned width) const {
    return registers_[index] & mask_for(width);
}

void Cpu::write_register(std::uint8_t index, unsigned width, std::uint64_t value) {
    value &= mask_for(width);
    if (width == 64 || width == 32) {
        registers_[index] = value;
    } else {
        registers_[index] = (registers_[index] & ~mask_for(width)) | value;
    }
}

std::uint64_t Cpu::read_encoded_register(std::uint8_t index, unsigned width, bool high_byte) const {
    if (width == 8 && high_byte) {
        return (registers_[index - 4] >> 8) & 0xff;
    }
    return read_register(index, width);
}

void Cpu::write_encoded_register(std::uint8_t index, unsigned width, bool high_byte,
                                 std::uint64_t value) {
    if (width == 8 && high_byte) {
        auto &target = registers_[index - 4];
        target = (target & ~0xff00ULL) | ((value & 0xff) << 8);
        return;
    }
    write_register(index, width, value);
}

std::uint64_t Cpu::read_operand(const Operand &operand, unsigned width) const {
    if (operand.is_register) {
        return read_encoded_register(operand.register_index, width, operand.high_byte);
    }
    switch (width) {
    case 8:
        return memory_.read8(operand.address);
    case 16:
        return memory_.read16(operand.address);
    case 32:
        return memory_.read32(operand.address);
    case 64:
        return memory_.read64(operand.address);
    default:
        throw Error("invalid operand width");
    }
}

void Cpu::write_operand(const Operand &operand, unsigned width, std::uint64_t value) {
    if (operand.is_register) {
        write_encoded_register(operand.register_index, width, operand.high_byte, value);
        return;
    }
    switch (width) {
    case 8:
        memory_.write8(operand.address, static_cast<std::uint8_t>(value));
        break;
    case 16:
        memory_.write16(operand.address, static_cast<std::uint16_t>(value));
        break;
    case 32:
        memory_.write32(operand.address, static_cast<std::uint32_t>(value));
        break;
    case 64:
        memory_.write64(operand.address, value);
        break;
    default:
        throw Error("invalid operand width");
    }
}

void Cpu::set_logic_flags(std::uint64_t result, unsigned width) {
    const auto masked = result & mask_for(width);
    flags_ &= ~(flag_cf | flag_pf | flag_af | flag_zf | flag_sf | flag_of);
    if (masked == 0) {
        flags_ |= flag_zf;
    }
    if ((masked & (1ULL << (width - 1))) != 0) {
        flags_ |= flag_sf;
    }
    if ((std::popcount(static_cast<std::uint8_t>(masked)) & 1) == 0) {
        flags_ |= flag_pf;
    }
}

void Cpu::set_add_flags(std::uint64_t left, std::uint64_t right, std::uint64_t result,
                        unsigned width) {
    const auto mask = mask_for(width);
    left &= mask;
    right &= mask;
    const auto masked = result & mask;
    set_logic_flags(masked, width);
    const bool carry = width == 64 ? masked < left : left + right > mask;
    if (carry) {
        flags_ |= flag_cf;
    }
    if (((left ^ right ^ masked) & 0x10) != 0) {
        flags_ |= flag_af;
    }
    const auto sign = 1ULL << (width - 1);
    if (((~(left ^ right) & (left ^ masked)) & sign) != 0) {
        flags_ |= flag_of;
    }
}

void Cpu::set_sub_flags(std::uint64_t left, std::uint64_t right, std::uint64_t result,
                        unsigned width) {
    const auto mask = mask_for(width);
    left &= mask;
    right &= mask;
    const auto masked = result & mask;
    set_logic_flags(masked, width);
    if (left < right) {
        flags_ |= flag_cf;
    }
    if (((left ^ right ^ masked) & 0x10) != 0) {
        flags_ |= flag_af;
    }
    const auto sign = 1ULL << (width - 1);
    if ((((left ^ right) & (left ^ masked)) & sign) != 0) {
        flags_ |= flag_of;
    }
}

bool Cpu::condition(std::uint8_t code) const {
    const bool cf = (flags_ & flag_cf) != 0;
    const bool pf = (flags_ & flag_pf) != 0;
    const bool zf = (flags_ & flag_zf) != 0;
    const bool sf = (flags_ & flag_sf) != 0;
    const bool of = (flags_ & flag_of) != 0;
    switch (code & 0xf) {
    case 0:
        return of;
    case 1:
        return !of;
    case 2:
        return cf;
    case 3:
        return !cf;
    case 4:
        return zf;
    case 5:
        return !zf;
    case 6:
        return cf || zf;
    case 7:
        return !cf && !zf;
    case 8:
        return sf;
    case 9:
        return !sf;
    case 10:
        return pf;
    case 11:
        return !pf;
    case 12:
        return sf != of;
    case 13:
        return sf == of;
    case 14:
        return zf || sf != of;
    case 15:
        return !zf && sf == of;
    default:
        return false;
    }
}

void Cpu::push64(std::uint64_t value) {
    registers_[Rsp] -= 8;
    memory_.write64(registers_[Rsp], value);
}

std::uint64_t Cpu::pop64() {
    const auto value = memory_.read64(registers_[Rsp]);
    registers_[Rsp] += 8;
    return value;
}

void Cpu::step() {
    const auto instruction_address = rip_;
    history_[history_cursor_] = instruction_address;
    history_cursor_ = (history_cursor_ + 1) % history_capacity;
    ++instructions_;
    bool operand16 = false;
    std::uint8_t repeat_prefix = 0;
    std::uint8_t rex = 0;
    segment_base_ = 0;
    address32_ = false;
    auto opcode = fetch8();
    while (opcode == 0x66 || opcode == 0x65 || opcode == 0xf0 || opcode == 0xf2 || opcode == 0xf3 ||
           opcode == 0x67 || opcode == 0x2e || opcode == 0x36 || opcode == 0x3e || opcode == 0x26 ||
           (opcode >= 0x40 && opcode <= 0x4f)) {
        if (opcode == 0x66) {
            operand16 = true;
        } else if (opcode == 0x65) {
            segment_base_ = gs_base_;
        } else if (opcode == 0xf0) {
            static_cast<void>(0);
        } else if (opcode == 0xf2 || opcode == 0xf3) {
            repeat_prefix = opcode;
        } else if (opcode == 0x67) {
            address32_ = true;
        } else if (opcode >= 0x40 && opcode <= 0x4f) {
            rex = opcode;
        }
        // 0x2e/0x36/0x3e/0x26 are segment overrides, which are no-ops in 64-bit code.
        opcode = fetch8();
    }
    const unsigned width = (rex & 8) != 0 ? 64 : (operand16 ? 16 : 32);

    if (opcode >= 0xb0 && opcode <= 0xb7) {
        const auto raw = static_cast<std::uint8_t>(opcode - 0xb0);
        const auto immediate = fetch8();
        if (rex == 0 && raw >= 4) {
            const auto destination = static_cast<std::uint8_t>(raw - 4);
            registers_[destination] = (registers_[destination] & ~0xff00ULL) |
                                      (static_cast<std::uint64_t>(immediate) << 8);
        } else {
            const auto destination = static_cast<std::uint8_t>(raw + ((rex & 1) ? 8 : 0));
            write_register(destination, 8, immediate);
        }
        return;
    }
    if (opcode >= 0xb8 && opcode <= 0xbf) {
        const auto destination = static_cast<std::uint8_t>((opcode - 0xb8) + ((rex & 1) ? 8 : 0));
        const auto immediate = width == 64 ? fetch64() : (width == 16 ? fetch16() : fetch32());
        write_register(destination, width, immediate);
        return;
    }
    if (opcode >= 0x50 && opcode <= 0x57) {
        const auto source = static_cast<std::uint8_t>((opcode - 0x50) + ((rex & 1) ? 8 : 0));
        push64(registers_[source]);
        return;
    }
    if (opcode >= 0x58 && opcode <= 0x5f) {
        const auto destination = static_cast<std::uint8_t>((opcode - 0x58) + ((rex & 1) ? 8 : 0));
        registers_[destination] = pop64();
        return;
    }
    if (opcode >= 0x70 && opcode <= 0x7f) {
        const auto displacement = static_cast<std::int8_t>(fetch8());
        if (condition(opcode & 0xf)) {
            rip_ += displacement;
        }
        return;
    }

    auto binary_rm_reg = [&](auto operation, auto flags, unsigned operation_width = 0U) {
        const auto decoded = decode_rm(rex);
        const auto actual_width = operation_width == 0 ? width : operation_width;
        const auto left = read_operand(decoded.rm, actual_width);
        const auto right = read_encoded_register(decoded.reg, actual_width, decoded.reg_high_byte);
        const auto result = operation(left, right);
        write_operand(decoded.rm, actual_width, result);
        flags(left, right, result, actual_width);
    };
    auto binary_reg_rm = [&](auto operation, auto flags, unsigned operation_width = 0U) {
        const auto decoded = decode_rm(rex);
        const auto actual_width = operation_width == 0 ? width : operation_width;
        const auto left = read_encoded_register(decoded.reg, actual_width, decoded.reg_high_byte);
        const auto right = read_operand(decoded.rm, actual_width);
        const auto result = operation(left, right);
        write_encoded_register(decoded.reg, actual_width, decoded.reg_high_byte, result);
        flags(left, right, result, actual_width);
    };
    auto add = [](std::uint64_t left, std::uint64_t right) { return left + right; };
    auto sub = [](std::uint64_t left, std::uint64_t right) { return left - right; };
    auto bit_and = [](std::uint64_t left, std::uint64_t right) { return left & right; };
    auto bit_or = [](std::uint64_t left, std::uint64_t right) { return left | right; };
    auto bit_xor = [](std::uint64_t left, std::uint64_t right) { return left ^ right; };
    auto add_flags = [&](auto left, auto right, auto result, auto bits) {
        set_add_flags(left, right, result, bits);
    };
    auto sub_flags = [&](auto left, auto right, auto result, auto bits) {
        set_sub_flags(left, right, result, bits);
    };
    auto logic_flags = [&](auto, auto, auto result, auto bits) { set_logic_flags(result, bits); };

    switch (opcode) {
    case 0x00:
        binary_rm_reg(add, add_flags, 8);
        return;
    case 0x01:
        binary_rm_reg(add, add_flags);
        return;
    case 0x02:
        binary_reg_rm(add, add_flags, 8);
        return;
    case 0x03:
        binary_reg_rm(add, add_flags);
        return;
    case 0x08:
        binary_rm_reg(bit_or, logic_flags, 8);
        return;
    case 0x09:
        binary_rm_reg(bit_or, logic_flags);
        return;
    case 0x0a:
        binary_reg_rm(bit_or, logic_flags, 8);
        return;
    case 0x0b:
        binary_reg_rm(bit_or, logic_flags);
        return;
    case 0x10:
    case 0x11:
    case 0x12:
    case 0x13: {
        const auto decoded = decode_rm(rex);
        const auto actual_width = (opcode == 0x10 || opcode == 0x12) ? 8U : width;
        const bool destination_is_register = opcode == 0x12 || opcode == 0x13;
        const auto left = destination_is_register ? read_encoded_register(decoded.reg, actual_width,
                                                                          decoded.reg_high_byte)
                                                  : read_operand(decoded.rm, actual_width);
        const auto right =
            destination_is_register
                ? read_operand(decoded.rm, actual_width)
                : read_encoded_register(decoded.reg, actual_width, decoded.reg_high_byte);
        const auto carry = (flags_ & flag_cf) != 0 ? 1ULL : 0ULL;
        const auto result = left + right + carry;
        if (destination_is_register) {
            write_encoded_register(decoded.reg, actual_width, decoded.reg_high_byte, result);
        } else {
            write_operand(decoded.rm, actual_width, result);
        }
        set_add_flags(left, right, result, actual_width);
        const auto mask = mask_for(actual_width);
        if (carry != 0 && (right & mask) == mask) {
            flags_ |= flag_cf;
        }
        return;
    }
    case 0x18:
    case 0x19:
    case 0x1a:
    case 0x1b: {
        const auto decoded = decode_rm(rex);
        const auto actual_width = (opcode == 0x18 || opcode == 0x1a) ? 8U : width;
        const bool destination_is_register = opcode == 0x1a || opcode == 0x1b;
        const auto left = destination_is_register ? read_encoded_register(decoded.reg, actual_width,
                                                                          decoded.reg_high_byte)
                                                  : read_operand(decoded.rm, actual_width);
        const auto right =
            destination_is_register
                ? read_operand(decoded.rm, actual_width)
                : read_encoded_register(decoded.reg, actual_width, decoded.reg_high_byte);
        const auto borrow = (flags_ & flag_cf) != 0 ? 1ULL : 0ULL;
        const auto result = left - right - borrow;
        if (destination_is_register) {
            write_encoded_register(decoded.reg, actual_width, decoded.reg_high_byte, result);
        } else {
            write_operand(decoded.rm, actual_width, result);
        }
        set_sub_flags(left, right, result, actual_width);
        if (left < right || (borrow != 0 && left == right)) {
            flags_ |= flag_cf;
        }
        return;
    }
    case 0x20:
        binary_rm_reg(bit_and, logic_flags, 8);
        return;
    case 0x21:
        binary_rm_reg(bit_and, logic_flags);
        return;
    case 0x22:
        binary_reg_rm(bit_and, logic_flags, 8);
        return;
    case 0x23:
        binary_reg_rm(bit_and, logic_flags);
        return;
    case 0x28:
        binary_rm_reg(sub, sub_flags, 8);
        return;
    case 0x29:
        binary_rm_reg(sub, sub_flags);
        return;
    case 0x2a:
        binary_reg_rm(sub, sub_flags, 8);
        return;
    case 0x2b:
        binary_reg_rm(sub, sub_flags);
        return;
    case 0x31:
        binary_rm_reg(bit_xor, logic_flags);
        return;
    case 0x33:
        binary_reg_rm(bit_xor, logic_flags);
        return;
    case 0x30:
        binary_rm_reg(bit_xor, logic_flags, 8);
        return;
    case 0x32:
        binary_reg_rm(bit_xor, logic_flags, 8);
        return;
    case 0x39: {
        const auto decoded = decode_rm(rex);
        const auto left = read_operand(decoded.rm, width);
        const auto right = read_register(decoded.reg, width);
        set_sub_flags(left, right, left - right, width);
        return;
    }
    case 0x38: {
        const auto decoded = decode_rm(rex);
        const auto left = read_operand(decoded.rm, 8);
        const auto right = read_encoded_register(decoded.reg, 8, decoded.reg_high_byte);
        set_sub_flags(left, right, left - right, 8);
        return;
    }
    case 0x3a: {
        const auto decoded = decode_rm(rex);
        const auto left = read_encoded_register(decoded.reg, 8, decoded.reg_high_byte);
        const auto right = read_operand(decoded.rm, 8);
        set_sub_flags(left, right, left - right, 8);
        return;
    }
    case 0x3b: {
        const auto decoded = decode_rm(rex);
        const auto left = read_register(decoded.reg, width);
        const auto right = read_operand(decoded.rm, width);
        set_sub_flags(left, right, left - right, width);
        return;
    }
    case 0x63: {
        const auto decoded = decode_rm(rex);
        const auto value = static_cast<std::int32_t>(read_operand(decoded.rm, 32));
        write_register(decoded.reg, width == 64 ? 64 : 32, static_cast<std::uint64_t>(value));
        return;
    }
    case 0x68:
        push64(static_cast<std::uint64_t>(
            static_cast<std::int64_t>(static_cast<std::int32_t>(fetch32()))));
        return;
    case 0x6a:
        push64(static_cast<std::uint64_t>(
            static_cast<std::int64_t>(static_cast<std::int8_t>(fetch8()))));
        return;
    case 0x69:
    case 0x6b: {
        const auto decoded = decode_rm(rex, opcode == 0x69 ? (operand16 ? 2U : 4U) : 1U);
        const auto left = sign_extend(read_operand(decoded.rm, width), width);
        const auto immediate = opcode == 0x69 ? static_cast<std::int32_t>(fetch32())
                                              : static_cast<std::int8_t>(fetch8());
        const auto result = static_cast<std::uint64_t>(left * immediate);
        write_register(decoded.reg, width, result);
        return;
    }
    case 0x80:
    case 0x81:
    case 0x83: {
        const auto decoded = decode_rm(rex, opcode == 0x80   ? 1U
                                            : opcode == 0x83 ? 1U
                                                             : (operand16 ? 2U : 4U));
        const auto group = static_cast<std::uint8_t>(decoded.reg & 7);
        const auto actual_width = opcode == 0x80 ? 8U : width;
        const auto left = read_operand(decoded.rm, actual_width);
        const auto immediate =
            opcode == 0x80 ? static_cast<std::uint64_t>(fetch8())
                           : (opcode == 0x83 ? static_cast<std::uint64_t>(static_cast<std::int64_t>(
                                                   static_cast<std::int8_t>(fetch8())))
                                             : static_cast<std::uint64_t>(static_cast<std::int64_t>(
                                                   static_cast<std::int32_t>(fetch32()))));
        std::uint64_t result = 0;
        switch (group) {
        case 0:
            result = left + immediate;
            write_operand(decoded.rm, actual_width, result);
            set_add_flags(left, immediate, result, actual_width);
            return;
        case 1:
            result = left | immediate;
            write_operand(decoded.rm, actual_width, result);
            set_logic_flags(result, actual_width);
            return;
        case 2: {
            const auto carry = (flags_ & flag_cf) != 0 ? 1ULL : 0ULL;
            result = left + immediate + carry;
            write_operand(decoded.rm, actual_width, result);
            set_add_flags(left, immediate, result, actual_width);
            if (carry != 0 && (immediate & mask_for(actual_width)) == mask_for(actual_width)) {
                flags_ |= flag_cf;
            }
            return;
        }
        case 3: {
            const auto borrow = (flags_ & flag_cf) != 0 ? 1ULL : 0ULL;
            result = left - immediate - borrow;
            write_operand(decoded.rm, actual_width, result);
            set_sub_flags(left, immediate, result, actual_width);
            const auto masked_left = left & mask_for(actual_width);
            const auto masked_immediate = immediate & mask_for(actual_width);
            if (masked_left < masked_immediate ||
                (borrow != 0 && masked_left == masked_immediate)) {
                flags_ |= flag_cf;
            }
            return;
        }
        case 4:
            result = left & immediate;
            write_operand(decoded.rm, actual_width, result);
            set_logic_flags(result, actual_width);
            return;
        case 5:
            result = left - immediate;
            write_operand(decoded.rm, actual_width, result);
            set_sub_flags(left, immediate, result, actual_width);
            return;
        case 6:
            result = left ^ immediate;
            write_operand(decoded.rm, actual_width, result);
            set_logic_flags(result, actual_width);
            return;
        case 7:
            set_sub_flags(left, immediate, left - immediate, actual_width);
            return;
        default:
            throw Error("unsupported immediate arithmetic group");
        }
    }
    case 0x84:
    case 0x85: {
        const auto decoded = decode_rm(rex);
        const auto actual_width = opcode == 0x84 ? 8U : width;
        set_logic_flags(read_operand(decoded.rm, actual_width) &
                            read_encoded_register(decoded.reg, actual_width, decoded.reg_high_byte),
                        actual_width);
        return;
    }
    case 0x86:
    case 0x87: {
        const auto decoded = decode_rm(rex);
        const auto actual_width = opcode == 0x86 ? 8U : width;
        const auto left = read_operand(decoded.rm, actual_width);
        const auto right = read_encoded_register(decoded.reg, actual_width, decoded.reg_high_byte);
        write_operand(decoded.rm, actual_width, right);
        write_encoded_register(decoded.reg, actual_width, decoded.reg_high_byte, left);
        return;
    }
    case 0x88:
    case 0x89: {
        const auto decoded = decode_rm(rex);
        const auto actual_width = opcode == 0x88 ? 8U : width;
        write_operand(decoded.rm, actual_width,
                      read_encoded_register(decoded.reg, actual_width, decoded.reg_high_byte));
        return;
    }
    case 0x8a:
    case 0x8b: {
        const auto decoded = decode_rm(rex);
        const auto actual_width = opcode == 0x8a ? 8U : width;
        write_encoded_register(decoded.reg, actual_width, decoded.reg_high_byte,
                               read_operand(decoded.rm, actual_width));
        return;
    }
    case 0x8d: {
        const auto decoded = decode_rm(rex);
        if (decoded.rm.is_register) {
            throw Error("invalid LEA register operand");
        }
        write_register(decoded.reg, width, decoded.rm.address);
        return;
    }
    case 0x90:
        return;
    case 0x98:
        if (width == 64) {
            registers_[Rax] = static_cast<std::uint64_t>(
                static_cast<std::int64_t>(static_cast<std::int32_t>(registers_[Rax])));
        } else if (width == 32) {
            write_register(Rax, 32,
                           static_cast<std::uint32_t>(static_cast<std::int32_t>(
                               static_cast<std::int16_t>(registers_[Rax]))));
        }
        return;
    case 0xc0:
    case 0xc1:
    case 0xd0:
    case 0xd1:
    case 0xd2:
    case 0xd3: {
        const bool byte_operation = opcode == 0xc0 || opcode == 0xd0 || opcode == 0xd2;
        const auto actual_width = byte_operation ? 8U : width;
        const bool immediate_count = opcode == 0xc0 || opcode == 0xc1;
        const auto decoded = decode_rm(rex, immediate_count ? 1U : 0U);
        const auto group = static_cast<std::uint8_t>(decoded.reg & 7);
        const auto raw_count = immediate_count ? fetch8()
                               : (opcode == 0xd0 || opcode == 0xd1)
                                   ? 1U
                                   : static_cast<unsigned>(read_register(Rcx, 8));
        const auto count = static_cast<unsigned>(raw_count & (actual_width == 64 ? 63 : 31));
        auto value = read_operand(decoded.rm, actual_width) & mask_for(actual_width);
        if (count == 0) {
            return;
        }
        if (group == 0 || group == 1) {
            const auto rotate_count = count % actual_width;
            if (rotate_count == 0) {
                return;
            }
            const auto mask = mask_for(actual_width);
            value =
                group == 0
                    ? ((value << rotate_count) | (value >> (actual_width - rotate_count))) & mask
                    : ((value >> rotate_count) | (value << (actual_width - rotate_count))) & mask;
            write_operand(decoded.rm, actual_width, value);
            flags_ &= ~(flag_cf | flag_of);
            if ((group == 0 ? value & 1 : value & (1ULL << (actual_width - 1))) != 0) {
                flags_ |= flag_cf;
            }
            if (rotate_count == 1) {
                const bool high = (value & (1ULL << (actual_width - 1))) != 0;
                const bool comparison = group == 0 ? (flags_ & flag_cf) != 0
                                                   : (value & (1ULL << (actual_width - 2))) != 0;
                if (high != comparison) {
                    flags_ |= flag_of;
                }
            }
            return;
        }
        const auto original = value;
        bool carry = false;
        if (group == 4) {
            carry = count <= actual_width && ((original >> (actual_width - count)) & 1) != 0;
            value = count >= actual_width ? 0 : original << count;
        } else if (group == 5) {
            carry = count <= actual_width && ((original >> (count - 1)) & 1) != 0;
            value = count >= actual_width ? 0 : original >> count;
        } else if (group == 7) {
            carry = count >= actual_width ? ((original >> (actual_width - 1)) & 1) != 0
                                          : ((original >> (count - 1)) & 1) != 0;
            value = count >= actual_width
                        ? (sign_extend(original, actual_width) < 0 ? mask_for(actual_width) : 0)
                        : static_cast<std::uint64_t>(sign_extend(original, actual_width) >> count);
        } else {
            std::ostringstream stream;
            stream << "unsupported shift operation group " << static_cast<unsigned>(group)
                   << " at 0x" << std::hex << instruction_address;
            throw Error(stream.str());
        }
        write_operand(decoded.rm, actual_width, value);
        set_logic_flags(value, actual_width);
        if (carry) {
            flags_ |= flag_cf;
        }
        if (count == 1) {
            const bool original_high = (original & (1ULL << (actual_width - 1))) != 0;
            const bool result_high = (value & (1ULL << (actual_width - 1))) != 0;
            if ((group == 4 && original_high != result_high) || (group == 5 && original_high)) {
                flags_ |= flag_of;
            }
        }
        return;
    }
    case 0xc2: {
        const auto adjustment = fetch16();
        rip_ = pop64();
        registers_[Rsp] += adjustment;
        return;
    }
    case 0xc3:
        rip_ = pop64();
        return;
    case 0xc6:
    case 0xc7: {
        const auto decoded = decode_rm(rex, opcode == 0xc6 ? 1U : (operand16 ? 2U : 4U));
        if ((decoded.reg & 7) != 0) {
            throw Error("unsupported immediate move instruction group");
        }
        if (opcode == 0xc6) {
            write_operand(decoded.rm, 8, fetch8());
            return;
        }
        const auto immediate = operand16 ? static_cast<std::uint64_t>(fetch16()) : fetch32();
        const auto value = width == 64 ? static_cast<std::uint64_t>(static_cast<std::int64_t>(
                                             static_cast<std::int32_t>(immediate)))
                                       : immediate;
        write_operand(decoded.rm, width, value);
        return;
    }
    case 0xc9:
        registers_[Rsp] = registers_[Rbp];
        registers_[Rbp] = pop64();
        return;
    case 0xe8: {
        const auto displacement = static_cast<std::int32_t>(fetch32());
        push64(rip_);
        rip_ += displacement;
        return;
    }
    case 0xe9:
        rip_ += static_cast<std::int32_t>(fetch32());
        return;
    case 0xeb:
        rip_ += static_cast<std::int8_t>(fetch8());
        return;
    case 0xf6:
    case 0xf7: {
        // The TEST subgroups (reg 0 and 1) carry a trailing immediate, which the RIP-relative
        // addressing of the memory operand must account for.
        const auto pending_group = static_cast<std::uint8_t>((memory_.read8(rip_) >> 3) & 7);
        const auto pending_immediate =
            pending_group <= 1 ? (opcode == 0xf6 ? 1U : (operand16 ? 2U : 4U)) : 0U;
        const auto decoded = decode_rm(rex, pending_immediate);
        const auto group = static_cast<std::uint8_t>(decoded.reg & 7);
        const auto actual_width = opcode == 0xf6 ? 8U : width;
        const auto value = read_operand(decoded.rm, actual_width);
        if (group == 0) {
            const auto immediate = opcode == 0xf6       ? fetch8()
                                   : actual_width == 16 ? fetch16()
                                                        : fetch32();
            set_logic_flags(value & immediate, actual_width);
            return;
        }
        if (group == 2) {
            write_operand(decoded.rm, actual_width, ~value);
            return;
        }
        if (group == 3) {
            const auto result = 0 - value;
            write_operand(decoded.rm, actual_width, result);
            set_sub_flags(0, value, result, actual_width);
            return;
        }
        if (group == 4 || group == 5) {
            std::uint64_t low = 0;
            std::uint64_t high = 0;
            bool overflow = false;
            if (actual_width == 64) {
                if (group == 4) {
                    low = _umul128(registers_[Rax], value, &high);
                    overflow = high != 0;
                } else {
                    auto signed_high = std::int64_t{};
                    low = static_cast<std::uint64_t>(
                        _mul128(static_cast<std::int64_t>(registers_[Rax]),
                                static_cast<std::int64_t>(value), &signed_high));
                    high = static_cast<std::uint64_t>(signed_high);
                    overflow = signed_high != (static_cast<std::int64_t>(low) < 0 ? -1 : 0);
                }
                registers_[Rax] = low;
                registers_[Rdx] = high;
            } else if (group == 4) {
                const auto product = read_register(Rax, actual_width) * value;
                low = product & mask_for(actual_width);
                high = product >> actual_width;
                overflow = high != 0;
                if (actual_width == 8) {
                    write_register(Rax, 16, product);
                } else {
                    write_register(Rax, actual_width, low);
                    write_register(Rdx, actual_width, high);
                }
            } else {
                const auto product = sign_extend(read_register(Rax, actual_width), actual_width) *
                                     sign_extend(value, actual_width);
                low = static_cast<std::uint64_t>(product) & mask_for(actual_width);
                high = static_cast<std::uint64_t>(product) >> actual_width;
                overflow = product != sign_extend(low, actual_width);
                if (actual_width == 8) {
                    write_register(Rax, 16, static_cast<std::uint64_t>(product));
                } else {
                    write_register(Rax, actual_width, low);
                    write_register(Rdx, actual_width, high);
                }
            }
            flags_ &= ~(flag_cf | flag_of);
            if (overflow) {
                flags_ |= flag_cf | flag_of;
            }
            return;
        }
        if (group == 6 || group == 7) {
            if (value == 0) {
                throw Error("guest integer divide by zero");
            }
            std::uint64_t quotient = 0;
            std::uint64_t remainder = 0;
            if (actual_width == 64) {
                if (group == 6) {
                    quotient =
                        divide_unsigned_128(registers_[Rdx], registers_[Rax], value, remainder);
                } else {
                    const bool numerator_negative = (registers_[Rdx] >> 63) != 0;
                    const bool divisor_negative = (value >> 63) != 0;
                    auto high = registers_[Rdx];
                    auto low = registers_[Rax];
                    if (numerator_negative) {
                        low = ~low + 1;
                        high = ~high + (low == 0 ? 1 : 0);
                    }
                    const auto divisor_magnitude = divisor_negative ? (~value + 1) : value;
                    quotient = divide_unsigned_128(high, low, divisor_magnitude, remainder);
                    const bool result_negative = numerator_negative != divisor_negative;
                    if ((!result_negative &&
                         quotient > static_cast<std::uint64_t>(
                                        std::numeric_limits<std::int64_t>::max())) ||
                        (result_negative && quotient > (1ULL << 63))) {
                        throw Error("guest integer divide overflow");
                    }
                    if (result_negative) {
                        quotient = ~quotient + 1;
                    }
                    if (numerator_negative && remainder != 0) {
                        remainder = ~remainder + 1;
                    }
                }
            } else {
                const auto mask = mask_for(actual_width);
                const auto numerator = actual_width == 8
                                           ? read_register(Rax, 16)
                                           : ((read_register(Rdx, actual_width) << actual_width) |
                                              read_register(Rax, actual_width));
                if (group == 6) {
                    quotient = numerator / value;
                    remainder = numerator % value;
                    if (quotient > mask) {
                        throw Error("guest integer divide overflow");
                    }
                } else {
                    const auto numerator_width = actual_width * 2;
                    const auto signed_numerator = sign_extend(numerator, numerator_width);
                    const auto signed_divisor = sign_extend(value, actual_width);
                    const auto signed_quotient = signed_numerator / signed_divisor;
                    const auto signed_remainder = signed_numerator % signed_divisor;
                    const auto minimum = -(1LL << (actual_width - 1));
                    const auto maximum = (1LL << (actual_width - 1)) - 1;
                    if (signed_quotient < minimum || signed_quotient > maximum) {
                        throw Error("guest integer divide overflow");
                    }
                    quotient = static_cast<std::uint64_t>(signed_quotient) & mask;
                    remainder = static_cast<std::uint64_t>(signed_remainder) & mask;
                }
            }
            if (actual_width == 8) {
                write_register(Rax, 16, quotient | (remainder << 8));
            } else {
                write_register(Rax, actual_width, quotient);
                write_register(Rdx, actual_width, remainder);
            }
            return;
        }
        std::ostringstream stream;
        stream << "unsupported F6/F7 instruction group " << static_cast<unsigned>(group) << " at 0x"
               << std::hex << instruction_address;
        throw Error(stream.str());
    }
    case 0xfe: {
        const auto decoded = decode_rm(rex);
        const auto group = static_cast<std::uint8_t>(decoded.reg & 7);
        if (group != 0 && group != 1) {
            throw Error("unsupported FE instruction group");
        }
        const auto old = read_operand(decoded.rm, 8);
        const auto result = group == 0 ? old + 1 : old - 1;
        const auto carry = flags_ & flag_cf;
        write_operand(decoded.rm, 8, result);
        if (group == 0) {
            set_add_flags(old, 1, result, 8);
        } else {
            set_sub_flags(old, 1, result, 8);
        }
        flags_ = (flags_ & ~flag_cf) | carry;
        return;
    }
    case 0xff: {
        const auto decoded = decode_rm(rex);
        const auto group = static_cast<std::uint8_t>(decoded.reg & 7);
        if (group == 0 || group == 1) {
            const auto old = read_operand(decoded.rm, width);
            const auto result = group == 0 ? old + 1 : old - 1;
            const auto carry = flags_ & flag_cf;
            write_operand(decoded.rm, width, result);
            if (group == 0) {
                set_add_flags(old, 1, result, width);
            } else {
                set_sub_flags(old, 1, result, width);
            }
            flags_ = (flags_ & ~flag_cf) | carry;
            return;
        }
        if (group == 2) {
            push64(rip_);
            rip_ = read_operand(decoded.rm, 64);
            return;
        }
        if (group == 4) {
            rip_ = read_operand(decoded.rm, 64);
            return;
        }
        if (group == 6) {
            push64(read_operand(decoded.rm, 64));
            return;
        }
        throw Error("unsupported FF instruction group");
    }
    case 0x05: {
        const auto raw_immediate = width == 16 ? static_cast<std::uint64_t>(fetch16()) : fetch32();
        const auto immediate = width == 64 ? static_cast<std::uint64_t>(static_cast<std::int64_t>(
                                                 static_cast<std::int32_t>(raw_immediate)))
                                           : raw_immediate;
        const auto left = read_register(Rax, width);
        const auto result = left + immediate;
        write_register(Rax, width, result);
        set_add_flags(left, immediate, result, width);
        return;
    }
    case 0x04: {
        const auto immediate = fetch8();
        const auto left = read_register(Rax, 8);
        const auto result = left + immediate;
        write_register(Rax, 8, result);
        set_add_flags(left, immediate, result, 8);
        return;
    }
    case 0x0d:
    case 0x25:
    case 0x35: {
        const auto raw_immediate = width == 16 ? static_cast<std::uint64_t>(fetch16()) : fetch32();
        const auto immediate = width == 64 ? static_cast<std::uint64_t>(static_cast<std::int64_t>(
                                                 static_cast<std::int32_t>(raw_immediate)))
                                           : raw_immediate;
        const auto left = read_register(Rax, width);
        const auto result = opcode == 0x0d   ? left | immediate
                            : opcode == 0x25 ? left & immediate
                                             : left ^ immediate;
        write_register(Rax, width, result);
        set_logic_flags(result, width);
        return;
    }
    case 0x0c:
    case 0x24:
    case 0x34: {
        const auto immediate = fetch8();
        const auto left = read_register(Rax, 8);
        const auto result = opcode == 0x0c   ? left | immediate
                            : opcode == 0x24 ? left & immediate
                                             : left ^ immediate;
        write_register(Rax, 8, result);
        set_logic_flags(result, 8);
        return;
    }
    case 0x2d: {
        const auto raw_immediate = width == 16 ? static_cast<std::uint64_t>(fetch16()) : fetch32();
        const auto immediate = width == 64 ? static_cast<std::uint64_t>(static_cast<std::int64_t>(
                                                 static_cast<std::int32_t>(raw_immediate)))
                                           : raw_immediate;
        const auto left = read_register(Rax, width);
        const auto result = left - immediate;
        write_register(Rax, width, result);
        set_sub_flags(left, immediate, result, width);
        return;
    }
    case 0x2c: {
        const auto immediate = fetch8();
        const auto left = read_register(Rax, 8);
        const auto result = left - immediate;
        write_register(Rax, 8, result);
        set_sub_flags(left, immediate, result, 8);
        return;
    }
    case 0x3c: {
        const auto immediate = fetch8();
        const auto left = read_register(Rax, 8);
        set_sub_flags(left, immediate, left - immediate, 8);
        return;
    }
    case 0x3d: {
        const auto raw_immediate = width == 16 ? static_cast<std::uint64_t>(fetch16()) : fetch32();
        const auto immediate = width == 64 ? static_cast<std::uint64_t>(static_cast<std::int64_t>(
                                                 static_cast<std::int32_t>(raw_immediate)))
                                           : raw_immediate;
        const auto left = read_register(Rax, width);
        set_sub_flags(left, immediate, left - immediate, width);
        return;
    }
    case 0xa8: {
        const auto immediate = fetch8();
        set_logic_flags(read_register(Rax, 8) & immediate, 8);
        return;
    }
    case 0xa9: {
        const auto immediate = width == 16 ? fetch16() : fetch32();
        set_logic_flags(read_register(Rax, width) & immediate, width);
        return;
    }
    case 0x99:
        if (width == 16) { // CWD
            write_register(Rdx, 16, (read_register(Rax, 16) & 0x8000) != 0 ? 0xffff : 0);
        } else if (width == 32) { // CDQ
            write_register(Rdx, 32,
                           (read_register(Rax, 32) & 0x80000000ULL) != 0 ? 0xffffffffULL : 0);
        } else { // CQO
            registers_[Rdx] = (registers_[Rax] & 0x8000000000000000ULL) != 0 ? ~0ULL : 0;
        }
        return;
    case 0xa4:
    case 0xa5: {
        const auto element_width = opcode == 0xa4 ? 8U : width;
        const auto element_size = element_width / 8;
        auto count = repeat_prefix != 0 ? registers_[Rcx] : 1ULL;
        const auto step = (flags_ & flag_df) != 0 ? -static_cast<std::int64_t>(element_size)
                                                  : static_cast<std::int64_t>(element_size);
        while (count-- != 0) {
            const auto value = element_width == 8    ? memory_.read8(registers_[Rsi])
                               : element_width == 16 ? memory_.read16(registers_[Rsi])
                               : element_width == 32 ? memory_.read32(registers_[Rsi])
                                                     : memory_.read64(registers_[Rsi]);
            if (element_width == 8) {
                memory_.write8(registers_[Rdi], static_cast<std::uint8_t>(value));
            } else if (element_width == 16) {
                memory_.write16(registers_[Rdi], static_cast<std::uint16_t>(value));
            } else if (element_width == 32) {
                memory_.write32(registers_[Rdi], static_cast<std::uint32_t>(value));
            } else {
                memory_.write64(registers_[Rdi], value);
            }
            registers_[Rsi] += step;
            registers_[Rdi] += step;
        }
        if (repeat_prefix != 0) {
            registers_[Rcx] = 0;
        }
        return;
    }
    case 0xaa:
    case 0xab: {
        const auto element_width = opcode == 0xaa ? 8U : width;
        const auto element_size = element_width / 8;
        auto count = repeat_prefix != 0 ? registers_[Rcx] : 1ULL;
        const auto step = (flags_ & flag_df) != 0 ? -static_cast<std::int64_t>(element_size)
                                                  : static_cast<std::int64_t>(element_size);
        const auto value = read_register(Rax, element_width);
        while (count-- != 0) {
            if (element_width == 8) {
                memory_.write8(registers_[Rdi], static_cast<std::uint8_t>(value));
            } else if (element_width == 16) {
                memory_.write16(registers_[Rdi], static_cast<std::uint16_t>(value));
            } else if (element_width == 32) {
                memory_.write32(registers_[Rdi], static_cast<std::uint32_t>(value));
            } else {
                memory_.write64(registers_[Rdi], value);
            }
            registers_[Rdi] += step;
        }
        if (repeat_prefix != 0) {
            registers_[Rcx] = 0;
        }
        return;
    }
    case 0xfc:
        flags_ &= ~flag_df;
        return;
    case 0xfd:
        flags_ |= flag_df;
        return;
    case 0x0f: {
        const auto second = fetch8();
        const auto xmm_low_float = [&](unsigned index) {
            return std::bit_cast<float>(static_cast<std::uint32_t>(xmm_[index][0] & 0xffffffffULL));
        };
        const auto set_xmm_low_float = [&](unsigned index, float value) {
            xmm_[index][0] =
                (xmm_[index][0] & 0xffffffff00000000ULL) | std::bit_cast<std::uint32_t>(value);
        };
        const auto xmm_low_double = [&](unsigned index) {
            return std::bit_cast<double>(xmm_[index][0]);
        };
        const auto set_xmm_low_double = [&](unsigned index, double value) {
            xmm_[index][0] = std::bit_cast<std::uint64_t>(value);
        };
        if (second == 0x2e || second == 0x2f) {
            const auto decoded = decode_rm(rex);
            const auto left = operand16 ? xmm_low_double(decoded.reg)
                                        : static_cast<double>(xmm_low_float(decoded.reg));
            const auto right =
                operand16 ? (decoded.rm.is_register
                                 ? xmm_low_double(decoded.rm.register_index)
                                 : std::bit_cast<double>(memory_.read64(decoded.rm.address)))
                          : static_cast<double>(
                                decoded.rm.is_register
                                    ? xmm_low_float(decoded.rm.register_index)
                                    : std::bit_cast<float>(memory_.read32(decoded.rm.address)));
            flags_ &= ~(flag_zf | flag_pf | flag_cf);
            if (std::isnan(left) || std::isnan(right)) {
                flags_ |= flag_zf | flag_pf | flag_cf;
            } else if (left < right) {
                flags_ |= flag_cf;
            } else if (left == right) {
                flags_ |= flag_zf;
            }
            return;
        }
        if (repeat_prefix == 0xf2 && (second == 0x58 || second == 0x59 || second == 0x5c ||
                                      second == 0x5d || second == 0x5e || second == 0x5f)) {
            const auto decoded = decode_rm(rex);
            const auto left = xmm_low_double(decoded.reg);
            const auto right = decoded.rm.is_register
                                   ? xmm_low_double(decoded.rm.register_index)
                                   : std::bit_cast<double>(memory_.read64(decoded.rm.address));
            double result = 0;
            switch (second) {
            case 0x58:
                result = left + right;
                break;
            case 0x59:
                result = left * right;
                break;
            case 0x5c:
                result = left - right;
                break;
            case 0x5d:
                result = std::isnan(left) || std::isnan(right) || left == right
                             ? right
                             : std::min(left, right);
                break;
            case 0x5e:
                result = left / right;
                break;
            case 0x5f:
                result = std::isnan(left) || std::isnan(right) || left == right
                             ? right
                             : std::max(left, right);
                break;
            }
            set_xmm_low_double(decoded.reg, result);
            return;
        }
        if (repeat_prefix == 0xf3 && (second == 0x58 || second == 0x59 || second == 0x5c ||
                                      second == 0x5d || second == 0x5e || second == 0x5f)) {
            // Scalar single-precision arithmetic: ADDSS/SUBSS/MULSS/DIVSS.
            const auto decoded = decode_rm(rex);
            const auto left = xmm_low_float(decoded.reg);
            const auto right = decoded.rm.is_register
                                   ? xmm_low_float(decoded.rm.register_index)
                                   : std::bit_cast<float>(memory_.read32(decoded.rm.address));
            float result = 0;
            switch (second) {
            case 0x58:
                result = left + right;
                break;
            case 0x59:
                result = left * right;
                break;
            case 0x5c:
                result = left - right;
                break;
            case 0x5d:
                result = std::isnan(left) || std::isnan(right) || left == right
                             ? right
                             : std::min(left, right);
                break;
            case 0x5e:
                result = left / right;
                break;
            case 0x5f:
                result = std::isnan(left) || std::isnan(right) || left == right
                             ? right
                             : std::max(left, right);
                break;
            }
            set_xmm_low_float(decoded.reg, result);
            return;
        }
        if (second == 0x14 && repeat_prefix == 0) { // UNPCKLPS
            const auto decoded = decode_rm(rex);
            const auto source =
                decoded.rm.is_register
                    ? xmm_[decoded.rm.register_index]
                    : std::array<std::uint64_t, 2>{memory_.read64(decoded.rm.address),
                                                   memory_.read64(decoded.rm.address + 8)};
            const auto destination = xmm_[decoded.reg];
            xmm_[decoded.reg] = {
                (destination[0] & 0xffffffffULL) | ((source[0] & 0xffffffffULL) << 32),
                ((destination[0] >> 32) & 0xffffffffULL) | (source[0] & 0xffffffff00000000ULL)};
            return;
        }
        if (operand16 && (second == 0x58 || second == 0x59 || second == 0x5c || second == 0x5e)) {
            // Packed double arithmetic: ADDPD/MULPD/SUBPD/DIVPD.
            const auto decoded = decode_rm(rex);
            const auto source =
                decoded.rm.is_register
                    ? xmm_[decoded.rm.register_index]
                    : std::array<std::uint64_t, 2>{memory_.read64(decoded.rm.address),
                                                   memory_.read64(decoded.rm.address + 8)};
            for (unsigned lane = 0; lane < 2; ++lane) {
                const auto left = std::bit_cast<double>(xmm_[decoded.reg][lane]);
                const auto right = std::bit_cast<double>(source[lane]);
                const auto result = second == 0x58   ? left + right
                                    : second == 0x59 ? left * right
                                    : second == 0x5c ? left - right
                                                     : left / right;
                xmm_[decoded.reg][lane] = std::bit_cast<std::uint64_t>(result);
            }
            return;
        }
        if (second == 0x7c && operand16) { // HADDPD
            const auto decoded = decode_rm(rex);
            const auto source =
                decoded.rm.is_register
                    ? xmm_[decoded.rm.register_index]
                    : std::array<std::uint64_t, 2>{memory_.read64(decoded.rm.address),
                                                   memory_.read64(decoded.rm.address + 8)};
            const auto destination = xmm_[decoded.reg];
            xmm_[decoded.reg] = {
                std::bit_cast<std::uint64_t>(std::bit_cast<double>(destination[0]) +
                                             std::bit_cast<double>(destination[1])),
                std::bit_cast<std::uint64_t>(std::bit_cast<double>(source[0]) +
                                             std::bit_cast<double>(source[1]))};
            return;
        }
        if (repeat_prefix == 0xf3 && second == 0x2a) {
            // CVTSI2SS: signed integer to scalar float.
            const auto decoded = decode_rm(rex);
            const auto value = read_operand(decoded.rm, (rex & 8) != 0 ? 64U : 32U);
            const float converted = (rex & 8) != 0
                                        ? static_cast<float>(static_cast<std::int64_t>(value))
                                        : static_cast<float>(static_cast<std::int32_t>(value));
            set_xmm_low_float(decoded.reg, converted);
            return;
        }
        if (repeat_prefix == 0xf2 && second == 0x2a) {
            const auto decoded = decode_rm(rex);
            const auto value = read_operand(decoded.rm, (rex & 8) != 0 ? 64U : 32U);
            const double converted = (rex & 8) != 0
                                         ? static_cast<double>(static_cast<std::int64_t>(value))
                                         : static_cast<double>(static_cast<std::int32_t>(value));
            set_xmm_low_double(decoded.reg, converted);
            return;
        }
        if (repeat_prefix == 0xf3 && second == 0x2c) {
            // CVTTSS2SI: scalar float to signed integer with truncation.
            const auto decoded = decode_rm(rex);
            const float value = decoded.rm.is_register
                                    ? xmm_low_float(decoded.rm.register_index)
                                    : std::bit_cast<float>(memory_.read32(decoded.rm.address));
            std::uint64_t result;
            if (std::isnan(value)) {
                result = (rex & 8) != 0 ? 0x8000000000000000ULL : 0x80000000ULL;
            } else if ((rex & 8) != 0) {
                result = value >= -9223372036854775808.0f && value < 9223372036854775808.0f
                             ? static_cast<std::uint64_t>(static_cast<std::int64_t>(value))
                             : 0x8000000000000000ULL;
            } else {
                result = value >= -2147483648.0f && value < 2147483648.0f
                             ? static_cast<std::uint64_t>(static_cast<std::int32_t>(value))
                             : 0x80000000ULL;
            }
            write_register(decoded.reg, (rex & 8) != 0 ? 64U : 32U, result);
            return;
        }
        if (repeat_prefix == 0xf2 && second == 0x2c) {
            const auto decoded = decode_rm(rex);
            const double value = decoded.rm.is_register
                                     ? xmm_low_double(decoded.rm.register_index)
                                     : std::bit_cast<double>(memory_.read64(decoded.rm.address));
            std::uint64_t result;
            if (std::isnan(value)) {
                result = (rex & 8) != 0 ? 0x8000000000000000ULL : 0x80000000ULL;
            } else if ((rex & 8) != 0) {
                result = value >= -9223372036854775808.0 && value < 9223372036854775808.0
                             ? static_cast<std::uint64_t>(static_cast<std::int64_t>(value))
                             : 0x8000000000000000ULL;
            } else {
                result = value >= -2147483648.0 && value < 2147483648.0
                             ? static_cast<std::uint64_t>(static_cast<std::int32_t>(value))
                             : 0x80000000ULL;
            }
            write_register(decoded.reg, (rex & 8) != 0 ? 64U : 32U, result);
            return;
        }
        if (second == 0x10 || second == 0x11) {
            const auto decoded = decode_rm(rex);
            if (repeat_prefix == 0xf3) {
                // MOVSS: only the low 32 bits move; the rest of the destination is preserved.
                if (second == 0x10) {
                    const auto source = decoded.rm.is_register
                                            ? xmm_[decoded.rm.register_index][0] & 0xffffffffULL
                                            : memory_.read32(decoded.rm.address);
                    xmm_[decoded.reg][0] = (xmm_[decoded.reg][0] & 0xffffffff00000000ULL) | source;
                } else {
                    const auto destination =
                        decoded.rm.is_register ? decoded.rm.register_index : decoded.rm.address;
                    if (decoded.rm.is_register) {
                        xmm_[destination][0] = (xmm_[destination][0] & 0xffffffff00000000ULL) |
                                               (xmm_[decoded.reg][0] & 0xffffffffULL);
                    } else {
                        memory_.write32(destination, static_cast<std::uint32_t>(
                                                         xmm_[decoded.reg][0] & 0xffffffffULL));
                    }
                }
                return;
            }
            if (repeat_prefix == 0xf2) {
                if (second == 0x10) {
                    if (decoded.rm.is_register) {
                        xmm_[decoded.reg][0] = xmm_[decoded.rm.register_index][0];
                    } else {
                        xmm_[decoded.reg] = {memory_.read64(decoded.rm.address), 0};
                    }
                } else if (decoded.rm.is_register) {
                    xmm_[decoded.rm.register_index][0] = xmm_[decoded.reg][0];
                } else {
                    memory_.write64(decoded.rm.address, xmm_[decoded.reg][0]);
                }
                return;
            }
            if (second == 0x10) {
                if (decoded.rm.is_register) {
                    xmm_[decoded.reg] = xmm_[decoded.rm.register_index];
                } else {
                    xmm_[decoded.reg] = {memory_.read64(decoded.rm.address),
                                         memory_.read64(decoded.rm.address + 8)};
                }
            } else if (decoded.rm.is_register) {
                xmm_[decoded.rm.register_index] = xmm_[decoded.reg];
            } else {
                memory_.write64(decoded.rm.address, xmm_[decoded.reg][0]);
                memory_.write64(decoded.rm.address + 8, xmm_[decoded.reg][1]);
            }
            return;
        }
        if (second == 0x28 || second == 0x29) {
            const auto decoded = decode_rm(rex);
            if (second == 0x28) {
                if (decoded.rm.is_register) {
                    xmm_[decoded.reg] = xmm_[decoded.rm.register_index];
                } else {
                    xmm_[decoded.reg] = {memory_.read64(decoded.rm.address),
                                         memory_.read64(decoded.rm.address + 8)};
                }
            } else if (decoded.rm.is_register) {
                xmm_[decoded.rm.register_index] = xmm_[decoded.reg];
            } else {
                memory_.write64(decoded.rm.address, xmm_[decoded.reg][0]);
                memory_.write64(decoded.rm.address + 8, xmm_[decoded.reg][1]);
            }
            return;
        }
        if (second == 0x57 || second == 0xef) {
            const auto decoded = decode_rm(rex);
            std::array<std::uint64_t, 2> source{};
            if (decoded.rm.is_register) {
                source = xmm_[decoded.rm.register_index];
            } else {
                source = {memory_.read64(decoded.rm.address),
                          memory_.read64(decoded.rm.address + 8)};
            }
            xmm_[decoded.reg][0] ^= source[0];
            xmm_[decoded.reg][1] ^= source[1];
            return;
        }
        if (second == 0xfc || second == 0xfd || second == 0xfe || second == 0xd4 ||
            second == 0xf8 || second == 0xf9 || second == 0xfa || second == 0xfb) {
            // Packed integer add/subtract: PADDB/W/D/Q (0xFC/FD/FE/D4) and PSUBB/W/D/Q
            // (0xF8/F9/FA/FB), each lane computed independently at its natural width.
            const auto decoded = decode_rm(rex);
            std::array<std::uint64_t, 2> source{};
            if (decoded.rm.is_register) {
                source = xmm_[decoded.rm.register_index];
            } else {
                source = {memory_.read64(decoded.rm.address),
                          memory_.read64(decoded.rm.address + 8)};
            }
            auto &destination = xmm_[decoded.reg];
            const unsigned lane_bits = second == 0xfc || second == 0xf8   ? 8U
                                       : second == 0xfd || second == 0xf9 ? 16U
                                       : second == 0xfe || second == 0xfa ? 32U
                                                                          : 64U;
            const auto subtract = (second & 0xf8) == 0xf8;
            const auto mask = lane_bits == 64 ? ~0ULL : ((1ULL << lane_bits) - 1);
            for (unsigned lane = 0; lane < 128 / lane_bits; ++lane) {
                const auto shift = lane * lane_bits;
                const auto left = (destination[shift / 64] >> (shift % 64)) & mask;
                const auto right = (source[shift / 64] >> (shift % 64)) & mask;
                const auto result = (subtract ? left - right : left + right) & mask;
                destination[shift / 64] =
                    (destination[shift / 64] & ~(mask << (shift % 64))) | (result << (shift % 64));
            }
            return;
        }
        if ((second == 0x6e || second == 0x7e) && operand16) {
            const auto decoded = decode_rm(rex);
            const auto move_width = (rex & 8) != 0 ? 64U : 32U;
            if (second == 0x6e) {
                xmm_[decoded.reg] = {read_operand(decoded.rm, move_width), 0};
            } else {
                write_operand(decoded.rm, move_width, xmm_[decoded.reg][0]);
            }
            return;
        }
        if ((second == 0x6c || second == 0x6d) && operand16) {
            const auto decoded = decode_rm(rex);
            const auto source =
                decoded.rm.is_register
                    ? xmm_[decoded.rm.register_index]
                    : std::array<std::uint64_t, 2>{memory_.read64(decoded.rm.address),
                                                   memory_.read64(decoded.rm.address + 8)};
            const auto destination = xmm_[decoded.reg];
            xmm_[decoded.reg] = second == 0x6c
                                    ? std::array<std::uint64_t, 2>{destination[0], source[0]}
                                    : std::array<std::uint64_t, 2>{destination[1], source[1]};
            return;
        }
        if (operand16 &&
            ((second >= 0x60 && second <= 0x62) || (second >= 0x68 && second <= 0x6a))) {
            // PUNPCKL/HBW, PUNPCKL/HWD, and PUNPCKL/HDQ interleave lanes
            // from the selected 64-bit half of each operand.
            const auto decoded = decode_rm(rex);
            const auto source =
                decoded.rm.is_register
                    ? xmm_[decoded.rm.register_index]
                    : std::array<std::uint64_t, 2>{memory_.read64(decoded.rm.address),
                                                   memory_.read64(decoded.rm.address + 8)};
            const auto destination = xmm_[decoded.reg];
            const bool high = second >= 0x68;
            const unsigned lane_bits = second == 0x60 || second == 0x68   ? 8U
                                       : second == 0x61 || second == 0x69 ? 16U
                                                                          : 32U;
            const auto mask = (1ULL << lane_bits) - 1;
            const unsigned lanes_per_half = 64 / lane_bits;
            std::array<std::uint64_t, 2> result{};
            for (unsigned lane = 0; lane < lanes_per_half; ++lane) {
                const auto input_lane = lane + (high ? lanes_per_half : 0);
                const auto input_shift = (input_lane * lane_bits) % 64;
                const auto input_half = (input_lane * lane_bits) / 64;
                const auto left = (destination[input_half] >> input_shift) & mask;
                const auto right = (source[input_half] >> input_shift) & mask;
                const auto output_bit = lane * lane_bits * 2;
                result[output_bit / 64] |= left << (output_bit % 64);
                result[(output_bit + lane_bits) / 64] |= right << ((output_bit + lane_bits) % 64);
            }
            xmm_[decoded.reg] = result;
            return;
        }
        if (second == 0x70 && (operand16 || repeat_prefix == 0xf2 || repeat_prefix == 0xf3)) {
            const auto decoded = decode_rm(rex);
            const auto source =
                decoded.rm.is_register
                    ? xmm_[decoded.rm.register_index]
                    : std::array<std::uint64_t, 2>{memory_.read64(decoded.rm.address),
                                                   memory_.read64(decoded.rm.address + 8)};
            const auto control = fetch8();
            auto result = source;
            if (operand16) { // PSHUFD
                result = {};
                for (unsigned lane = 0; lane < 4; ++lane) {
                    const auto source_lane = static_cast<unsigned>((control >> (lane * 2)) & 3);
                    const auto value = static_cast<std::uint32_t>(source[source_lane / 2] >>
                                                                  ((source_lane % 2) * 32));
                    result[lane / 2] |= static_cast<std::uint64_t>(value) << ((lane % 2) * 32);
                }
            } else {
                // PSHUFLW/PSHUFHW shuffle one group of four words and preserve the other.
                const unsigned half = repeat_prefix == 0xf2 ? 0U : 1U;
                const auto source_half = source[half];
                result[half] = 0;
                for (unsigned lane = 0; lane < 4; ++lane) {
                    const auto source_lane = static_cast<unsigned>((control >> (lane * 2)) & 3);
                    const auto value =
                        static_cast<std::uint16_t>(source_half >> (source_lane * 16));
                    result[half] |= static_cast<std::uint64_t>(value) << (lane * 16);
                }
            }
            xmm_[decoded.reg] = result;
            return;
        }
        if ((second == 0x74 || second == 0x75 || second == 0x76) && operand16) {
            const auto decoded = decode_rm(rex);
            const auto source =
                decoded.rm.is_register
                    ? xmm_[decoded.rm.register_index]
                    : std::array<std::uint64_t, 2>{memory_.read64(decoded.rm.address),
                                                   memory_.read64(decoded.rm.address + 8)};
            auto &destination = xmm_[decoded.reg];
            const unsigned lane_bits = second == 0x74 ? 8U : (second == 0x75 ? 16U : 32U);
            const auto mask = (1ULL << lane_bits) - 1;
            for (unsigned lane = 0; lane < 128 / lane_bits; ++lane) {
                const auto shift = (lane * lane_bits) % 64;
                const auto half = (lane * lane_bits) / 64;
                const auto equal =
                    ((destination[half] >> shift) & mask) == ((source[half] >> shift) & mask);
                destination[half] =
                    (destination[half] & ~(mask << shift)) | ((equal ? mask : 0) << shift);
            }
            return;
        }
        if (second == 0x56) { // ORPS/ORPD
            const auto decoded = decode_rm(rex);
            const auto source =
                decoded.rm.is_register
                    ? xmm_[decoded.rm.register_index]
                    : std::array<std::uint64_t, 2>{memory_.read64(decoded.rm.address),
                                                   memory_.read64(decoded.rm.address + 8)};
            xmm_[decoded.reg][0] |= source[0];
            xmm_[decoded.reg][1] |= source[1];
            return;
        }
        if (second == 0xd7 && operand16) { // PMOVMSKB
            const auto decoded = decode_rm(rex);
            if (!decoded.rm.is_register) {
                throw Error("PMOVMSKB requires an XMM register");
            }
            std::uint32_t result = 0;
            for (unsigned byte = 0; byte < 16; ++byte) {
                const auto sign =
                    (xmm_[decoded.rm.register_index][byte / 8] >> ((byte % 8) * 8 + 7)) & 1;
                result |= static_cast<std::uint32_t>(sign) << byte;
            }
            write_register(decoded.reg, 32, result);
            return;
        }
        if (second == 0x73 && operand16) {
            const auto decoded = decode_rm(rex);
            if (!decoded.rm.is_register) {
                throw Error("packed byte shift requires an XMM register");
            }
            const auto group = static_cast<std::uint8_t>(decoded.reg & 7);
            const auto count = static_cast<unsigned>(fetch8());
            auto &value = xmm_[decoded.rm.register_index];
            if (group == 3) { // PSRLDQ
                if (count >= 16) {
                    value = {0, 0};
                } else if (count >= 8) {
                    value = {value[1] >> ((count - 8) * 8), 0};
                } else if (count != 0) {
                    value = {(value[0] >> (count * 8)) | (value[1] << ((8 - count) * 8)),
                             value[1] >> (count * 8)};
                }
            } else if (group == 7) { // PSLLDQ
                if (count >= 16) {
                    value = {0, 0};
                } else if (count >= 8) {
                    value = {0, value[0] << ((count - 8) * 8)};
                } else if (count != 0) {
                    value = {value[0] << (count * 8),
                             (value[1] << (count * 8)) | (value[0] >> ((8 - count) * 8))};
                }
            } else {
                throw Error("unsupported 0F 73 instruction group");
            }
            return;
        }
        if (second == 0x6f || second == 0x7f) {
            if (!operand16 && !repeat_prefix) {
                throw Error("unsupported MMX move");
            }
            const auto decoded = decode_rm(rex);
            if (second == 0x6f) {
                if (decoded.rm.is_register) {
                    xmm_[decoded.reg] = xmm_[decoded.rm.register_index];
                } else {
                    xmm_[decoded.reg] = {memory_.read64(decoded.rm.address),
                                         memory_.read64(decoded.rm.address + 8)};
                }
            } else if (decoded.rm.is_register) {
                xmm_[decoded.rm.register_index] = xmm_[decoded.reg];
            } else {
                memory_.write64(decoded.rm.address, xmm_[decoded.reg][0]);
                memory_.write64(decoded.rm.address + 8, xmm_[decoded.reg][1]);
            }
            return;
        }
        if (second >= 0x40 && second <= 0x4f) {
            const auto decoded = decode_rm(rex);
            if (condition(second & 0xf)) {
                write_register(decoded.reg, width, read_operand(decoded.rm, width));
            }
            return;
        }
        if (second >= 0x80 && second <= 0x8f) {
            const auto displacement = static_cast<std::int32_t>(fetch32());
            if (condition(second & 0xf)) {
                rip_ += displacement;
            }
            return;
        }
        if (second >= 0x90 && second <= 0x9f) {
            const auto decoded = decode_rm(rex);
            write_operand(decoded.rm, 8, condition(second & 0xf) ? 1 : 0);
            return;
        }
        if (second == 0x1f) {
            static_cast<void>(decode_rm(rex));
            return;
        }
        if (second == 0x18) {
            // PREFETCH hints do not change architectural state.
            static_cast<void>(decode_rm(rex));
            return;
        }
        if (second == 0xa2) {
            int values[4]{};
            const auto leaf = static_cast<std::uint32_t>(registers_[Rax]);
            const auto subleaf = static_cast<std::uint32_t>(registers_[Rcx]);
            __cpuidex(values, static_cast<int>(leaf), static_cast<int>(subleaf));
            if (leaf == 1) {
                // x86-64 guarantees SSE2, but the optional ECX feature set selects instructions
                // that this interpreter does not implement completely yet (SSE3/4, AES,
                // POPCNT, XSAVE/AVX, RDRAND, and friends).
                values[2] = 0;
            } else if (leaf == 7 && subleaf == 0) {
                values[1] = 0;
                values[2] = 0;
                values[3] = 0;
            } else if (leaf == 0x80000001U) {
                values[2] = 0;
            }
            write_register(Rax, 32, static_cast<std::uint32_t>(values[0]));
            write_register(Rbx, 32, static_cast<std::uint32_t>(values[1]));
            write_register(Rcx, 32, static_cast<std::uint32_t>(values[2]));
            write_register(Rdx, 32, static_cast<std::uint32_t>(values[3]));
            return;
        }
        if (second == 0x31) {
            const auto timestamp = __rdtsc();
            write_register(Rax, 32, timestamp);
            write_register(Rdx, 32, timestamp >> 32);
            return;
        }
        if (second >= 0xc8 && second <= 0xcf) {
            const auto destination =
                static_cast<std::uint8_t>((second - 0xc8) + ((rex & 1) != 0 ? 8 : 0));
            if ((rex & 8) != 0) {
                write_register(destination, 64, _byteswap_uint64(registers_[destination]));
            } else {
                write_register(
                    destination, 32,
                    _byteswap_ulong(static_cast<unsigned long>(read_register(destination, 32))));
            }
            return;
        }
        if (second == 0xba) {
            const auto decoded = decode_rm(rex, 1U);
            const auto group = static_cast<std::uint8_t>(decoded.reg & 7);
            if (group < 4) {
                throw Error("unsupported 0F BA instruction group");
            }
            const auto bit = static_cast<unsigned>(fetch8()) & (width - 1);
            const auto bit_mask = 1ULL << bit;
            auto value = read_operand(decoded.rm, width);
            flags_ = (flags_ & ~flag_cf) | ((value & bit_mask) != 0 ? flag_cf : 0);
            if (group == 5) {
                value |= bit_mask;
                write_operand(decoded.rm, width, value);
            } else if (group == 6) {
                value &= ~bit_mask;
                write_operand(decoded.rm, width, value);
            } else if (group == 7) {
                value ^= bit_mask;
                write_operand(decoded.rm, width, value);
            }
            return;
        }
        if (second == 0xa3 || second == 0xab || second == 0xb3 || second == 0xbb) {
            const auto decoded = decode_rm(rex);
            auto target = decoded.rm;
            const auto signed_bit = sign_extend(read_register(decoded.reg, width), width);
            if (!target.is_register) {
                const auto word_offset = signed_bit >= 0
                                             ? signed_bit / static_cast<std::int64_t>(width)
                                             : (signed_bit - static_cast<std::int64_t>(width - 1)) /
                                                   static_cast<std::int64_t>(width);
                target.address += word_offset * static_cast<std::int64_t>(width / 8);
            }
            const auto bit = static_cast<unsigned>(signed_bit) & (width - 1);
            const auto bit_mask = 1ULL << bit;
            auto value = read_operand(target, width);
            flags_ = (flags_ & ~flag_cf) | ((value & bit_mask) != 0 ? flag_cf : 0);
            if (second == 0xab) {
                value |= bit_mask;
                write_operand(target, width, value);
            } else if (second == 0xb3) {
                value &= ~bit_mask;
                write_operand(target, width, value);
            } else if (second == 0xbb) {
                value ^= bit_mask;
                write_operand(target, width, value);
            }
            return;
        }
        if (second == 0xbc || second == 0xbd) {
            const auto decoded = decode_rm(rex);
            const auto source = read_operand(decoded.rm, width);
            if (source == 0) {
                flags_ |= flag_zf;
            } else {
                flags_ &= ~flag_zf;
                unsigned index = 0;
                if (second == 0xbc) {
                    index = static_cast<unsigned>(std::countr_zero(source));
                } else {
                    index =
                        width - 1 - static_cast<unsigned>(std::countl_zero(source) - (64 - width));
                }
                write_register(decoded.reg, width, index);
            }
            return;
        }
        if (second == 0xaf) {
            const auto decoded = decode_rm(rex);
            const auto left = sign_extend(read_register(decoded.reg, width), width);
            const auto right = sign_extend(read_operand(decoded.rm, width), width);
            write_register(decoded.reg, width, static_cast<std::uint64_t>(left * right));
            return;
        }
        if (second == 0xb0 || second == 0xb1) {
            const auto decoded = decode_rm(rex);
            const auto actual_width = second == 0xb0 ? 8U : width;
            const auto accumulator = read_register(Rax, actual_width);
            const auto destination = read_operand(decoded.rm, actual_width);
            set_sub_flags(accumulator, destination, accumulator - destination, actual_width);
            if (accumulator == destination) {
                write_operand(
                    decoded.rm, actual_width,
                    read_encoded_register(decoded.reg, actual_width, decoded.reg_high_byte));
            } else {
                write_register(Rax, actual_width, destination);
            }
            return;
        }
        if (second == 0xc0 || second == 0xc1) {
            const auto decoded = decode_rm(rex);
            const auto actual_width = second == 0xc0 ? 8U : width;
            const auto destination = read_operand(decoded.rm, actual_width);
            const auto source =
                read_encoded_register(decoded.reg, actual_width, decoded.reg_high_byte);
            const auto result = destination + source;
            write_operand(decoded.rm, actual_width, result);
            write_encoded_register(decoded.reg, actual_width, decoded.reg_high_byte, destination);
            set_add_flags(destination, source, result, actual_width);
            return;
        }
        if (second == 0xb6 || second == 0xb7 || second == 0xbe || second == 0xbf) {
            const auto decoded = decode_rm(rex);
            const auto source_width = (second == 0xb6 || second == 0xbe) ? 8U : 16U;
            auto value = read_operand(decoded.rm, source_width);
            if (second == 0xbe || second == 0xbf) {
                value = static_cast<std::uint64_t>(sign_extend(value, source_width));
            }
            write_register(decoded.reg, width == 64 ? 64 : 32, value);
            return;
        }
        throw Error(unknown_instruction(instruction_address, second));
    }
    default:
        throw Error(unknown_instruction(instruction_address, opcode));
    }
}

} // namespace winemu
