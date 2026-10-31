#include "winemu/cpu.hpp"
#include "winemu/error.hpp"
#include "winemu/log.hpp"
#include "winemu/memory.hpp"
#include "winemu/runtime.hpp"

#include <cstdint>
#include <filesystem>
#include <iostream>
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
