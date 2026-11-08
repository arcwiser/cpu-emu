#include "winemu/cpu.hpp"
#include "winemu/error.hpp"
#include "winemu/log.hpp"
#include "winemu/memory.hpp"
#include "winemu/runtime.hpp"

#include <algorithm>
#include <bit>
#include <cstdint>
#include <filesystem>
#include <iostream>
#include <limits>
#include <sstream>
#include <stdexcept>
#include <string>

namespace {

void require(bool condition, const std::string &message) {
    if (!condition) {
        throw std::runtime_error(message);
    }
}

void test_memory() {
    winemu::Memory memory;
    memory.map(0x200000000ULL, 0x1000, winemu::Read | winemu::Write, "test");
    memory.write64(0x200000100ULL, 0x8877665544332211ULL);
    require(memory.read64(0x200000100ULL) == 0x8877665544332211ULL, "64-bit memory round trip");
    bool rejected = false;
    try {
        static_cast<void>(memory.read8(0x400000000ULL));
    } catch (const winemu::Error &) {
        rejected = true;
    }
    require(rejected, "unmapped access must fail");

    const std::uint8_t wide_text[] = {'C', 0, 'P', 0, 'U', 0, 0, 0};
    memory.write(0x200000200ULL, wide_text);
    require(memory.read_wide_string(0x200000200ULL) == L"CPU", "wide string round trip");
}

void test_cpu_loop() {
    winemu::Memory memory;
    memory.map(0x200000000ULL, 0x1000, winemu::Read | winemu::Write | winemu::Execute, "code");
    memory.map(0x300000000ULL, 0x1000, winemu::Read | winemu::Write, "stack");
    const std::uint8_t code[] = {
        0xb9, 0x0a, 0, 0, 0, 0x31, 0xc0, 0x01, 0xc8, 0x83, 0xe9, 0x01, 0x75, 0xf9, 0xc3,
    };
    memory.write(0x200000000ULL, code);
    memory.write64(0x300000ff8ULL, 0xdeadbeef);
    winemu::Cpu cpu(memory);
    cpu.reset(0x200000000ULL, 0x300000ff8ULL);
    while (cpu.rip() != 0xdeadbeef) {
        cpu.step();
    }
    require(cpu.reg(winemu::Rax) == 55, "CPU loop sum result");
}

void test_pshufd() {
    winemu::Memory memory;
    memory.map(0x200000000ULL, 0x1000, winemu::Read | winemu::Write | winemu::Execute, "code");
    memory.map(0x300000000ULL, 0x1000, winemu::Read | winemu::Write, "stack");
    const std::uint8_t code[] = {
        0x48, 0xb8, 0x44, 0x33, 0x22, 0x11, 0x88, 0x77, 0x66, 0x55, // mov rax, imm64
        0x66, 0x48, 0x0f, 0x6e, 0xc0,                               // movq xmm0, rax
        0x48, 0xba, 0xcc, 0xbb, 0xaa, 0x99, 0x00, 0xff, 0xee, 0xdd, // mov rdx, imm64
        0x66, 0x48, 0x0f, 0x6e, 0xca,                               // movq xmm1, rdx
        0x66, 0x0f, 0x6c, 0xc1,                                     // punpcklqdq xmm0, xmm1
        0x66, 0x0f, 0x70, 0xc0, 0x1b,                               // pshufd xmm0, xmm0, 1bh
        0xf3, 0x0f, 0x7f, 0x07,                                     // movdqu [rdi], xmm0
        0xc3,
    };
    memory.write(0x200000000ULL, code);
    memory.write64(0x300000ff8ULL, 0xdeadbeef);
    winemu::Cpu cpu(memory);
    cpu.reset(0x200000000ULL, 0x300000ff8ULL);
    cpu.set_reg(winemu::Rdi, 0x300000100ULL);
    while (cpu.rip() != 0xdeadbeef) {
        cpu.step();
    }
    require(memory.read64(0x300000100ULL) == 0x99aabbccddeeff00ULL, "PSHUFD low lanes");
    require(memory.read64(0x300000108ULL) == 0x1122334455667788ULL, "PSHUFD high lanes");
}

void test_pshufb() {
    constexpr std::uint64_t code_address = 0x200000000ULL;
    constexpr std::uint64_t data_address = 0x300000000ULL;
    constexpr std::uint64_t control_address = data_address + 0x20;
    constexpr std::uint64_t output_address = data_address + 0x40;
    constexpr std::uint64_t extended_output_address = data_address + 0x60;

    winemu::Memory memory;
    memory.map(code_address, 0x1000, winemu::Read | winemu::Write | winemu::Execute, "code");
    memory.map(data_address, 0x1000, winemu::Read | winemu::Write, "data");
    const std::uint8_t code[] = {
        0xf3, 0x0f, 0x6f, 0x07,             // movdqu xmm0, [rdi]
        0xf3, 0x0f, 0x6f, 0x0e,             // movdqu xmm1, [rsi]
        0x66, 0x0f, 0x38, 0x00, 0xc1,       // pshufb xmm0, xmm1
        0xf3, 0x0f, 0x7f, 0x02,             // movdqu [rdx], xmm0
        0xf3, 0x44, 0x0f, 0x6f, 0x07,       // movdqu xmm8, [rdi]
        0x66, 0x44, 0x0f, 0x38, 0x00, 0x06, // pshufb xmm8, [rsi]
        0xf3, 0x44, 0x0f, 0x7f, 0x42, 0x20, // movdqu [rdx + 20h], xmm8
        0xc3,
    };
    const std::uint8_t input[] = {
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
    };
    const std::uint8_t control[] = {
        0x0f, 0x0e, 0x0d, 0x0c, 0x8b, 0x0a, 0x19, 0x08,
        0x07, 0x86, 0x05, 0x04, 0x03, 0x02, 0x01, 0x00,
    };
    const std::uint8_t expected[] = {
        0xff, 0xee, 0xdd, 0xcc, 0x00, 0xaa, 0x99, 0x88,
        0x77, 0x00, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00,
    };
    memory.write(code_address, code);
    memory.write(data_address, input);
    memory.write(control_address, control);
    memory.write64(data_address + 0xff8, 0xdeadbeef);

    winemu::Cpu cpu(memory);
    cpu.reset(code_address, data_address + 0xff8);
    cpu.set_reg(winemu::Rdi, data_address);
    cpu.set_reg(winemu::Rsi, control_address);
    cpu.set_reg(winemu::Rdx, output_address);
    while (cpu.rip() != 0xdeadbeef) {
        cpu.step();
    }

    for (std::size_t byte = 0; byte < std::size(expected); ++byte) {
        require(memory.read8(output_address + byte) == expected[byte],
                "PSHUFB register control result");
        require(memory.read8(extended_output_address + byte) == expected[byte],
                "PSHUFB memory control and extended register result");
    }
}

void test_packed_absolute_values() {
    constexpr std::uint64_t code_address = 0x200000000ULL;
    constexpr std::uint64_t data_address = 0x300000000ULL;
    constexpr std::uint64_t output_address = data_address + 0x20;

    winemu::Memory memory;
    memory.map(code_address, 0x1000, winemu::Read | winemu::Write | winemu::Execute, "code");
    memory.map(data_address, 0x1000, winemu::Read | winemu::Write, "data");
    const std::uint8_t code[] = {
        0x66, 0x0f, 0x38, 0x1c, 0x07, // pabsb xmm0, [rdi]
        0xf3, 0x0f, 0x7f, 0x02,       // movdqu [rdx], xmm0
        0x66, 0x0f, 0x38, 0x1d, 0x0f, // pabsw xmm1, [rdi]
        0xf3, 0x0f, 0x7f, 0x4a, 0x10, // movdqu [rdx + 10h], xmm1
        0x66, 0x0f, 0x38, 0x1e, 0x17, // pabsd xmm2, [rdi]
        0xf3, 0x0f, 0x7f, 0x52, 0x20, // movdqu [rdx + 20h], xmm2
        0xc3,
    };
    const std::uint8_t input[] = {
        0x00, 0x01, 0xff, 0x80, 0x7f, 0xfe, 0x00, 0x80,
        0x01, 0x00, 0xff, 0xff, 0x00, 0x00, 0x00, 0x80,
    };
    const std::uint8_t expected_bytes[] = {
        0x00, 0x01, 0x01, 0x80, 0x7f, 0x02, 0x00, 0x80,
        0x01, 0x00, 0x01, 0x01, 0x00, 0x00, 0x00, 0x80,
    };
    const std::uint8_t expected_words[] = {
        0x00, 0x01, 0x01, 0x7f, 0x81, 0x01, 0x00, 0x80,
        0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x80,
    };
    const std::uint8_t expected_dwords[] = {
        0x00, 0xff, 0x00, 0x7f, 0x81, 0x01, 0xff, 0x7f,
        0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80,
    };
    memory.write(code_address, code);
    memory.write(data_address, input);
    memory.write64(data_address + 0xff8, 0xdeadbeef);

    winemu::Cpu cpu(memory);
    cpu.reset(code_address, data_address + 0xff8);
    cpu.set_reg(winemu::Rdi, data_address);
    cpu.set_reg(winemu::Rdx, output_address);
    while (cpu.rip() != 0xdeadbeef) {
        cpu.step();
    }

    for (std::size_t byte = 0; byte < std::size(input); ++byte) {
        require(memory.read8(output_address + byte) == expected_bytes[byte], "PABSB result");
        require(memory.read8(output_address + 0x10 + byte) == expected_words[byte], "PABSW result");
        require(memory.read8(output_address + 0x20 + byte) == expected_dwords[byte],
                "PABSD result");
    }
}

void test_bit_count_instructions() {
    winemu::Memory memory;
    memory.map(0x200000000ULL, 0x1000, winemu::Read | winemu::Write | winemu::Execute, "code");
    memory.map(0x300000000ULL, 0x1000, winemu::Read | winemu::Write, "stack");
    const std::uint8_t code[] = {
        0x48, 0xb8, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0xf0, 0x00, // mov rax, 00f0000000000100h
        0xf3, 0x48, 0x0f, 0xb8, 0xc8,                               // popcnt rcx, rax
        0xf3, 0x48, 0x0f, 0xbd, 0xd0,                               // lzcnt rdx, rax
        0xf3, 0x48, 0x0f, 0xbc, 0xd8,                               // tzcnt rbx, rax
        0xc3,
    };
    memory.write(0x200000000ULL, code);
    memory.write64(0x300000ff8ULL, 0xdeadbeef);
    winemu::Cpu cpu(memory);
    cpu.reset(0x200000000ULL, 0x300000ff8ULL);
    while (cpu.rip() != 0xdeadbeef) {
        cpu.step();
    }
    require(cpu.reg(winemu::Rcx) == 5, "POPCNT result");
    require(cpu.reg(winemu::Rdx) == 8, "LZCNT result");
    require(cpu.reg(winemu::Rbx) == 8, "TZCNT result");

    const std::uint8_t zero_code[] = {
        0x31, 0xc0,                   // xor eax, eax
        0xf3, 0x48, 0x0f, 0xbc, 0xd8, // tzcnt rbx, rax
        0xc3,
    };
    memory.write(0x200000100ULL, zero_code);
    memory.write64(0x300000ff8ULL, 0xdeadbeef);
    cpu.reset(0x200000100ULL, 0x300000ff8ULL);
    while (cpu.rip() != 0xdeadbeef) {
        cpu.step();
    }
    require(cpu.reg(winemu::Rbx) == 64, "TZCNT zero operand width");
    require((cpu.flags() & 1) != 0, "TZCNT zero operand carry flag");
    require((cpu.flags() & (1ULL << 6)) == 0, "TZCNT zero operand zero flag");
}

void test_extended_ssse3() {
    constexpr std::uint64_t code_address = 0x200000000ULL;
    constexpr std::uint64_t data_address = 0x300000000ULL;
    constexpr std::uint64_t source_address = data_address + 0x20;
    constexpr std::uint64_t output_address = data_address + 0x40;
    winemu::Memory memory;
    memory.map(code_address, 0x1000, winemu::Read | winemu::Write | winemu::Execute, "code");
    memory.map(data_address, 0x1000, winemu::Read | winemu::Write, "data");
    const std::uint8_t code[] = {
        0xf3, 0x0f, 0x6f, 0x07,             // movdqu xmm0, [rdi]
        0xf3, 0x0f, 0x6f, 0x0e,             // movdqu xmm1, [rsi]
        0x66, 0x0f, 0x38, 0x01, 0xc1,       // phaddw xmm0, xmm1
        0xf3, 0x0f, 0x7f, 0x02,             // movdqu [rdx], xmm0
        0xf3, 0x0f, 0x6f, 0x07,             // movdqu xmm0, [rdi]
        0x66, 0x0f, 0x3a, 0x0f, 0x06, 0x0c, // palignr xmm0, [rsi], 12
        0xf3, 0x0f, 0x7f, 0x42, 0x20,       // movdqu [rdx + 20h], xmm0
        0xc3,
    };
    const std::uint16_t destination_words[] = {1, 2, 3, 4, 5, 6, 7, 8};
    const std::uint16_t source_words[] = {10, 20, 30, 40, 50, 60, 70, 80};
    const std::uint16_t expected_words[] = {3, 7, 11, 15, 30, 70, 110, 150};
    memory.write(code_address, code);
    for (std::size_t lane = 0; lane < std::size(destination_words); ++lane) {
        memory.write16(data_address + lane * 2, destination_words[lane]);
        memory.write16(source_address + lane * 2, source_words[lane]);
    }
    memory.write64(data_address + 0xff8, 0xdeadbeef);
    winemu::Cpu cpu(memory);
    cpu.reset(code_address, data_address + 0xff8);
    cpu.set_reg(winemu::Rdi, data_address);
    cpu.set_reg(winemu::Rsi, source_address);
    cpu.set_reg(winemu::Rdx, output_address);
    while (cpu.rip() != 0xdeadbeef) {
        cpu.step();
    }
    for (std::size_t lane = 0; lane < std::size(expected_words); ++lane) {
        require(memory.read16(output_address + lane * 2) == expected_words[lane], "PHADDW result");
    }
    for (std::size_t byte = 0; byte < 16; ++byte) {
        const auto expected = byte < 4 ? memory.read8(source_address + byte + 12)
                                       : memory.read8(data_address + byte - 4);
        require(memory.read8(output_address + 0x20 + byte) == expected, "PALIGNR result");
    }

    const auto run_opcode = [&](std::uint8_t opcode) {
        const std::uint8_t operation[] = {
            0xf3, 0x0f, 0x6f, 0x07,         // movdqu xmm0, [rdi]
            0xf3, 0x0f, 0x6f, 0x0e,         // movdqu xmm1, [rsi]
            0x66, 0x0f, 0x38, opcode, 0xc1, // SSSE3 xmm0, xmm1
            0xf3, 0x0f, 0x7f, 0x02,         // movdqu [rdx], xmm0
            0xc3,
        };
        memory.write(code_address, operation);
        memory.write64(data_address + 0xff8, 0xdeadbeef);
        cpu.reset(code_address, data_address + 0xff8);
        cpu.set_reg(winemu::Rdi, data_address);
        cpu.set_reg(winemu::Rsi, source_address);
        cpu.set_reg(winemu::Rdx, output_address);
        while (cpu.rip() != 0xdeadbeef) {
            cpu.step();
        }
    };

    const std::int16_t saturating_left[] = {30000, 10000, -30000, -10000, 1, 2, -3, -4};
    const std::int16_t saturating_right[] = {32767, 1, -32768, -1, 100, 200, -100, -200};
    const std::int16_t saturating_expected[] = {32767, -32768, 3, -7, 32767, -32768, 300, -300};
    for (std::size_t lane = 0; lane < 8; ++lane) {
        memory.write16(data_address + lane * 2, static_cast<std::uint16_t>(saturating_left[lane]));
        memory.write16(source_address + lane * 2,
                       static_cast<std::uint16_t>(saturating_right[lane]));
    }
    run_opcode(0x03); // PHADDSW
    for (std::size_t lane = 0; lane < 8; ++lane) {
        require(static_cast<std::int16_t>(memory.read16(output_address + lane * 2)) ==
                    saturating_expected[lane],
                "PHADDSW saturation result");
    }

    const std::int32_t subtract_left[] = {10, 3, -5, 7};
    const std::int32_t subtract_right[] = {20, 8, 1, -2};
    const std::int32_t subtract_expected[] = {7, -12, 12, 3};
    for (std::size_t lane = 0; lane < 4; ++lane) {
        memory.write32(data_address + lane * 4, static_cast<std::uint32_t>(subtract_left[lane]));
        memory.write32(source_address + lane * 4, static_cast<std::uint32_t>(subtract_right[lane]));
    }
    run_opcode(0x06); // PHSUBD
    for (std::size_t lane = 0; lane < 4; ++lane) {
        require(static_cast<std::int32_t>(memory.read32(output_address + lane * 4)) ==
                    subtract_expected[lane],
                "PHSUBD result");
    }

    const std::uint8_t multiply_add_left[] = {2, 3, 255, 255, 255, 255, 1, 1,
                                              1, 1, 1,   1,   1,   1,   1, 1};
    const std::int8_t multiply_add_right[] = {4, -5, 127, 127, -128, -128, 1, 1,
                                              1, 1,  1,   1,   1,    1,    1, 1};
    const std::int16_t multiply_add_expected[] = {-7, 32767, -32768, 2, 2, 2, 2, 2};
    for (std::size_t byte = 0; byte < 16; ++byte) {
        memory.write8(data_address + byte, multiply_add_left[byte]);
        memory.write8(source_address + byte, static_cast<std::uint8_t>(multiply_add_right[byte]));
    }
    run_opcode(0x04); // PMADDUBSW
    for (std::size_t lane = 0; lane < 8; ++lane) {
        require(static_cast<std::int16_t>(memory.read16(output_address + lane * 2)) ==
                    multiply_add_expected[lane],
                "PMADDUBSW result");
    }

    const std::int32_t sign_left[] = {5, -7, std::numeric_limits<std::int32_t>::min(), 9};
    const std::int32_t sign_control[] = {-1, 0, 1, -2};
    const std::int32_t sign_expected[] = {-5, 0, std::numeric_limits<std::int32_t>::min(), -9};
    for (std::size_t lane = 0; lane < 4; ++lane) {
        memory.write32(data_address + lane * 4, static_cast<std::uint32_t>(sign_left[lane]));
        memory.write32(source_address + lane * 4, static_cast<std::uint32_t>(sign_control[lane]));
    }
    run_opcode(0x0a); // PSIGND
    for (std::size_t lane = 0; lane < 4; ++lane) {
        require(static_cast<std::int32_t>(memory.read32(output_address + lane * 4)) ==
                    sign_expected[lane],
                "PSIGND result");
    }

    const std::int16_t rounded_left[] = {0x4000, -0x4000, 0x7fff, -0x8000, 0, 0, 0, 0};
    const std::int16_t rounded_right[] = {0x4000, 0x4000, 0x7fff, -0x8000, 0, 0, 0, 0};
    const std::int16_t rounded_expected[] = {0x2000, -0x2000, 0x7ffe, -0x8000, 0, 0, 0, 0};
    for (std::size_t lane = 0; lane < 8; ++lane) {
        memory.write16(data_address + lane * 2, static_cast<std::uint16_t>(rounded_left[lane]));
        memory.write16(source_address + lane * 2, static_cast<std::uint16_t>(rounded_right[lane]));
    }
    run_opcode(0x0b); // PMULHRSW
    for (std::size_t lane = 0; lane < 8; ++lane) {
        require(static_cast<std::int16_t>(memory.read16(output_address + lane * 2)) ==
                    rounded_expected[lane],
                "PMULHRSW result");
    }

    const std::int8_t minimum_left[] = {5,  -2, 100, -128, 7,  8,  -9, 10,
                                        11, 12, 13,  14,   -1, -2, -3, -4};
    const std::int8_t minimum_right[] = {4,  3,  101, 127, -7, 9,  -10, 9,
                                         12, 11, 14,  13,  0,  -3, -2,  -5};
    for (std::size_t lane = 0; lane < 16; ++lane) {
        memory.write8(data_address + lane, static_cast<std::uint8_t>(minimum_left[lane]));
        memory.write8(source_address + lane, static_cast<std::uint8_t>(minimum_right[lane]));
    }
    run_opcode(0x38); // PMINSB
    for (std::size_t lane = 0; lane < 16; ++lane) {
        require(static_cast<std::int8_t>(memory.read8(output_address + lane)) ==
                    std::min(minimum_left[lane], minimum_right[lane]),
                "PMINSB result");
    }

    const std::uint32_t maximum_left[] = {1, 0xffffffffU, 20, 40};
    const std::uint32_t maximum_right[] = {2, 3, 30, 10};
    for (std::size_t lane = 0; lane < 4; ++lane) {
        memory.write32(data_address + lane * 4, maximum_left[lane]);
        memory.write32(source_address + lane * 4, maximum_right[lane]);
    }
    run_opcode(0x3f); // PMAXUD
    for (std::size_t lane = 0; lane < 4; ++lane) {
        require(memory.read32(output_address + lane * 4) ==
                    std::max(maximum_left[lane], maximum_right[lane]),
                "PMAXUD result");
    }

    const std::int32_t product_left[] = {2, -3, 0x40000000, -7};
    const std::int32_t product_right[] = {4, 5, 4, -9};
    const std::uint32_t product_expected[] = {8, static_cast<std::uint32_t>(-15), 0, 63};
    for (std::size_t lane = 0; lane < 4; ++lane) {
        memory.write32(data_address + lane * 4, static_cast<std::uint32_t>(product_left[lane]));
        memory.write32(source_address + lane * 4, static_cast<std::uint32_t>(product_right[lane]));
    }
    run_opcode(0x40); // PMULLD
    for (std::size_t lane = 0; lane < 4; ++lane) {
        require(memory.read32(output_address + lane * 4) == product_expected[lane],
                "PMULLD low product");
    }

    const std::int32_t pack_left[] = {-1, 0, 65535, 70000};
    const std::int32_t pack_right[] = {1, 32768, -500, 90000};
    const std::uint16_t pack_expected[] = {0, 0, 65535, 65535, 1, 32768, 0, 65535};
    for (std::size_t lane = 0; lane < 4; ++lane) {
        memory.write32(data_address + lane * 4, static_cast<std::uint32_t>(pack_left[lane]));
        memory.write32(source_address + lane * 4, static_cast<std::uint32_t>(pack_right[lane]));
    }
    run_opcode(0x2b); // PACKUSDW
    for (std::size_t lane = 0; lane < 8; ++lane) {
        require(memory.read16(output_address + lane * 2) == pack_expected[lane],
                "PACKUSDW saturation result");
    }

    memory.write64(data_address, 0x0f);
    memory.write64(data_address + 8, 0);
    memory.write64(source_address, 0xf0);
    memory.write64(source_address + 8, 0);
    run_opcode(0x17); // PTEST
    require((cpu.flags() & (1ULL << 6)) != 0, "PTEST zero intersection flag");
    require((cpu.flags() & 1) == 0, "PTEST masked-source carry flag");
}

void test_sse3_float_operations() {
    constexpr std::uint64_t code_address = 0x200000000ULL;
    constexpr std::uint64_t data_address = 0x300000000ULL;
    constexpr std::uint64_t source_address = data_address + 0x20;
    constexpr std::uint64_t output_address = data_address + 0x40;
    winemu::Memory memory;
    memory.map(code_address, 0x1000, winemu::Read | winemu::Write | winemu::Execute, "code");
    memory.map(data_address, 0x1000, winemu::Read | winemu::Write, "data");
    const std::uint8_t code[] = {
        0xf3, 0x0f, 0x6f, 0x07,       // movdqu xmm0, [rdi]
        0xf3, 0x0f, 0x6f, 0x0e,       // movdqu xmm1, [rsi]
        0xf2, 0x0f, 0x7c, 0xc1,       // haddps xmm0, xmm1
        0xf3, 0x0f, 0x7f, 0x02,       // movdqu [rdx], xmm0
        0xf3, 0x0f, 0x12, 0xc1,       // movsldup xmm0, xmm1
        0xf3, 0x0f, 0x7f, 0x42, 0x20, // movdqu [rdx + 20h], xmm0
        0xf3, 0x0f, 0x6f, 0x07,       // movdqu xmm0, [rdi]
        0xf2, 0x0f, 0xd0, 0xc1,       // addsubps xmm0, xmm1
        0xf3, 0x0f, 0x7f, 0x42, 0x40, // movdqu [rdx + 40h], xmm0
        0xc3,
    };
    const float destination[] = {1.0f, 2.0f, 3.0f, 4.0f};
    const float source[] = {10.0f, 20.0f, 30.0f, 40.0f};
    const float horizontal_expected[] = {3.0f, 7.0f, 30.0f, 70.0f};
    const float duplicate_expected[] = {10.0f, 10.0f, 30.0f, 30.0f};
    const float add_subtract_expected[] = {-9.0f, 22.0f, -27.0f, 44.0f};
    memory.write(code_address, code);
    for (std::size_t lane = 0; lane < 4; ++lane) {
        memory.write32(data_address + lane * 4, std::bit_cast<std::uint32_t>(destination[lane]));
        memory.write32(source_address + lane * 4, std::bit_cast<std::uint32_t>(source[lane]));
    }
    memory.write64(data_address + 0xff8, 0xdeadbeef);
    winemu::Cpu cpu(memory);
    cpu.reset(code_address, data_address + 0xff8);
    cpu.set_reg(winemu::Rdi, data_address);
    cpu.set_reg(winemu::Rsi, source_address);
    cpu.set_reg(winemu::Rdx, output_address);
    while (cpu.rip() != 0xdeadbeef) {
        cpu.step();
    }
    for (std::size_t lane = 0; lane < 4; ++lane) {
        require(std::bit_cast<float>(memory.read32(output_address + lane * 4)) ==
                    horizontal_expected[lane],
                "HADDPS result");
        require(std::bit_cast<float>(memory.read32(output_address + 0x20 + lane * 4)) ==
                    duplicate_expected[lane],
                "MOVSLDUP result");
        require(std::bit_cast<float>(memory.read32(output_address + 0x40 + lane * 4)) ==
                    add_subtract_expected[lane],
                "ADDSUBPS result");
    }
}

void test_sign_extend_accumulator() {
    winemu::Memory memory;
    memory.map(0x200000000ULL, 0x1000, winemu::Read | winemu::Write | winemu::Execute, "code");
    memory.map(0x300000000ULL, 0x1000, winemu::Read | winemu::Write, "stack");
    const std::uint8_t code[] = {
        0x48, 0xb8, 0xfe, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, // mov rax, -2
        0x48, 0x99,                                                 // cqo
        0xc3,
    };
    memory.write(0x200000000ULL, code);
    memory.write64(0x300000ff8ULL, 0xdeadbeef);
    winemu::Cpu cpu(memory);
    cpu.reset(0x200000000ULL, 0x300000ff8ULL);
    while (cpu.rip() != 0xdeadbeef) {
        cpu.step();
    }
    require(cpu.reg(winemu::Rdx) == UINT64_MAX, "CQO sign extension");
}

void test_apps() {
    const std::filesystem::path apps(WINEMU_TEST_APPS_DIR);
    {
        std::ostringstream output;
        winemu::Runtime runtime(output);
        const auto result = runtime.run(apps / "exit42.exe");
        require(result.exit_code == 42, "exit42 result");
        require(output.str().empty(), "exit42 output");
    }
    {
        std::ostringstream output;
        winemu::Runtime runtime(output);
        const auto result = runtime.run(apps / "sum.exe");
        require(result.exit_code == 55, "sum result");
    }
    {
        std::ostringstream output;
        winemu::Runtime runtime(output);
        const auto result = runtime.run(apps / "hello.exe");
        require(result.exit_code == 0, "hello result");
        require(output.str() == "Hello from an emulated Windows PE app!\r\n", "hello output");
    }
}

void test_logging() {
    using namespace winemu::log;
    set_level(Level::Warn);
    require(!enabled(Level::Info), "info must be filtered at warn level");
    require(enabled(Level::Error), "error must pass at warn level");
    set_level(Level::Trace);
    require(enabled(Level::Trace), "trace must pass at trace level");
    Level parsed = Level::Info;
    require(parse_level("api", parsed) && parsed == Level::Api, "parse api level name");
    require(!parse_level("nope", parsed), "reject unknown level name");
    set_level(Level::Info);
}

void test_paint_selftest() {
    const std::filesystem::path apps(WINEMU_TEST_APPS_DIR);
    std::ostringstream output;
    winemu::Runtime runtime(output);
    const auto result = runtime.run(apps / "paint.exe", 100'000'000, L"--selftest");
    require(result.exit_code == 0, "paint selftest exit code");
    require(output.str().find("PAINT SELFTEST PASSED") != std::string::npos,
            "paint selftest output");
}

} // namespace

int main() {
    try {
        test_memory();
        test_cpu_loop();
        test_pshufd();
        test_pshufb();
        test_packed_absolute_values();
        test_bit_count_instructions();
        test_extended_ssse3();
        test_sse3_float_operations();
        test_sign_extend_accumulator();
        test_logging();
        test_apps();
        test_paint_selftest();
        std::cout << "all tests passed\n";
        return 0;
    } catch (const std::exception &error) {
        std::cerr << "test failure: " << error.what() << '\n';
        return 1;
    }
}
