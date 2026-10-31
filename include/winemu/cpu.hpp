#pragma once

#include "winemu/memory.hpp"

#include <array>
#include <cstddef>
#include <cstdint>

namespace winemu {

enum Register : std::size_t {
    Rax,
    Rcx,
    Rdx,
    Rbx,
    Rsp,
    Rbp,
    Rsi,
    Rdi,
    R8,
    R9,
    R10,
    R11,
    R12,
    R13,
    R14,
    R15,
};

class Cpu {
  public:
    explicit Cpu(Memory &memory);
    void reset(std::uint64_t entry, std::uint64_t stack_pointer);
    void step();
    [[nodiscard]] std::uint64_t reg(Register index) const;
    void set_reg(Register index, std::uint64_t value);
    [[nodiscard]] std::uint64_t rip() const;
    void set_rip(std::uint64_t value);
    [[nodiscard]] std::uint64_t flags() const;
    void set_gs_base(std::uint64_t value);
    [[nodiscard]] std::uint64_t instructions() const;
    [[nodiscard]] std::vector<std::uint64_t> recent_instructions() const;
    [[nodiscard]] Memory &memory();
    [[nodiscard]] std::uint64_t pop64();
    void push64(std::uint64_t value);

  private:
    struct Operand {
        bool is_register;
        std::uint8_t register_index;
        std::uint64_t address;
        bool high_byte;
    };

    struct DecodedRm {
        Operand rm;
        std::uint8_t reg;
        bool reg_high_byte;
    };

    [[nodiscard]] std::uint8_t fetch8();
    [[nodiscard]] std::uint16_t fetch16();
    [[nodiscard]] std::uint32_t fetch32();
    [[nodiscard]] std::uint64_t fetch64();
    [[nodiscard]] DecodedRm decode_rm(std::uint8_t rex, std::uint64_t pending_immediate = 0);
    [[nodiscard]] std::uint64_t read_operand(const Operand &operand, unsigned width) const;
    void write_operand(const Operand &operand, unsigned width, std::uint64_t value);
    [[nodiscard]] std::uint64_t read_register(std::uint8_t index, unsigned width) const;
    void write_register(std::uint8_t index, unsigned width, std::uint64_t value);
    [[nodiscard]] std::uint64_t read_encoded_register(std::uint8_t index, unsigned width,
                                                      bool high_byte) const;
    void write_encoded_register(std::uint8_t index, unsigned width, bool high_byte,
                                std::uint64_t value);
    void set_logic_flags(std::uint64_t result, unsigned width);
    void set_add_flags(std::uint64_t left, std::uint64_t right, std::uint64_t result,
                       unsigned width);
    void set_sub_flags(std::uint64_t left, std::uint64_t right, std::uint64_t result,
                       unsigned width);
    [[nodiscard]] bool condition(std::uint8_t code) const;
    [[nodiscard]] static std::uint64_t mask_for(unsigned width);
    [[nodiscard]] static std::int64_t sign_extend(std::uint64_t value, unsigned width);

    Memory &memory_;
    std::array<std::uint64_t, 16> registers_{};
    std::array<std::array<std::uint64_t, 2>, 16> xmm_{};
    static constexpr std::size_t history_capacity = 64;
    std::array<std::uint64_t, history_capacity> history_{};
    std::size_t history_cursor_ = 0;
    std::uint64_t rip_ = 0;
    std::uint64_t flags_ = 2;
    std::uint64_t instructions_ = 0;
    std::uint64_t gs_base_ = 0;
    std::uint64_t segment_base_ = 0;
    bool address32_ = false;
};

} // namespace winemu
