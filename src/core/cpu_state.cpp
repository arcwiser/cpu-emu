#include "winemu/cpu.hpp"

namespace winemu {

Cpu::Cpu(Memory &memory) : memory_(memory) {}

void Cpu::reset(std::uint64_t entry, std::uint64_t stack_pointer, bool long_mode) {
    registers_.fill(0);
    xmm_.fill({0, 0});
    x87_.fill(0);
    x87_depth_ = 0;
    history_.fill(0);
    history_cursor_ = 0;
    registers_[Rsp] = stack_pointer;
    rip_ = entry;
    flags_ = 2;
    x87_control_ = 0x037f;
    mxcsr_ = 0x1f80;
    instructions_ = 0;
    long_mode_ = long_mode;
}

std::uint64_t Cpu::reg(Register index) const { return registers_[index]; }

void Cpu::set_reg(Register index, std::uint64_t value) { registers_[index] = value; }

std::uint64_t Cpu::rip() const { return rip_; }

void Cpu::set_rip(std::uint64_t value) { rip_ = value; }

std::uint64_t Cpu::flags() const { return flags_; }

void Cpu::set_gs_base(std::uint64_t value) { gs_base_ = value; }

void Cpu::set_fs_base(std::uint64_t value) { fs_base_ = value; }

std::uint64_t Cpu::instructions() const { return instructions_; }

Memory &Cpu::memory() { return memory_; }

const Memory &Cpu::memory() const { return memory_; }

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

void Cpu::push64(std::uint64_t value) {
    const auto size = long_mode_ ? 8U : 4U;
    registers_[Rsp] = (registers_[Rsp] - size) & (long_mode_ ? UINT64_MAX : UINT32_MAX);
    if (long_mode_) {
        memory_.write64(registers_[Rsp], value);
    } else {
        memory_.write32(registers_[Rsp], static_cast<std::uint32_t>(value));
    }
}

std::uint64_t Cpu::pop64() {
    const auto value = long_mode_ ? memory_.read64(registers_[Rsp])
                                  : static_cast<std::uint64_t>(memory_.read32(registers_[Rsp]));
    registers_[Rsp] =
        (registers_[Rsp] + (long_mode_ ? 8U : 4U)) & (long_mode_ ? UINT64_MAX : UINT32_MAX);
    return value;
}

} // namespace winemu
