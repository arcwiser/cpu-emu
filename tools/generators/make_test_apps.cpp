#include "guest_fixture_builders.hpp"
#include "pe_fixture_writer.hpp"

#include <algorithm>
#include <cstdint>
#include <filesystem>
#include <iostream>
#include <span>
#include <stdexcept>
#include <string>
#include <vector>

int main(int argc, char **argv) {
    using namespace cpuemu::fixtures;
    try {
        if (argc != 2) {
            std::cerr << "usage: make_test_apps <output-directory>\n";
            return 2;
        }
        const std::filesystem::path output(argv[1]);
        std::filesystem::create_directories(output);
        const std::vector<std::uint8_t> exit42{0xb8, 0x2a, 0, 0, 0, 0xc3};
        const std::vector<std::uint8_t> sum{
            0xb9, 0x0a, 0, 0, 0, 0x31, 0xc0, 0x01, 0xc8, 0x83, 0xe9, 0x01, 0x75, 0xf9, 0xc3,
        };
        write_pe(output / "exit42.exe", exit42);
        write_pe32(output / "exit32.exe", exit42);
        write_pe(output / "sum.exe", sum);
        make_hello(output / "hello.exe");
        make_winrt_activation(output / "winrt.exe");
        return 0;
    } catch (const std::exception &error) {
        std::cerr << "make_test_apps: " << error.what() << '\n';
        return 1;
    }
}
