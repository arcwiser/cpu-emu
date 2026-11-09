#include "test_suite.hpp"

#include "winemu/cpu.hpp"
#include "winemu/log.hpp"
#include "winemu/memory.hpp"
#include "winemu/pe.hpp"
#include "winemu/runtime.hpp"

#include <filesystem>
#include <sstream>
#include <stdexcept>

namespace winemu::tests {

void test_apps() {
    const std::filesystem::path apps(WINEMU_TEST_APPS_DIR);
    {
        winemu::Memory memory;
        const auto image = winemu::PeLoader::load(
            apps / "exit32.exe", memory,
            [](const std::string &, const std::string &, bool) -> std::uint64_t {
                throw std::runtime_error("unexpected PE32 import");
            });
        require(!image.is_64_bit, "PE32 image mode");
        constexpr std::uint64_t stack_base = 0x00800000;
        memory.map(stack_base, 0x1000, winemu::Read | winemu::Write, "PE32 stack");
        memory.write32(stack_base + 0xffc, 0xdeadbeef);
        winemu::Cpu cpu(memory);
        cpu.reset(image.entry, stack_base + 0xffc, false);
        while (cpu.rip() != 0xdeadbeef) {
            cpu.step();
        }
        require(cpu.reg(winemu::Rax) == 42, "PE32 CPU result");
    }
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

void test_winrt_activation() {
    // A class with no dedicated adapter must still activate to a guest-owned instance; the
    // emulator must not report success while leaving the ActivateInstance out parameter null.
    std::ostringstream output;
    winemu::Runtime runtime(output);
    const auto result = runtime.run(WINEMU_TEST_APPS_DIR "/winrt.exe");
    require(result.exit_code == 0, "WinRT activation instance");
}

} // namespace winemu::tests
