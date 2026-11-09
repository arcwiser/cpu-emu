#include "winemu/cpu.hpp"

#include "winemu/error.hpp"

#include <limits>

namespace winemu {

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

} // namespace winemu
