#include <algorithm>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <span>
#include <stdexcept>
#include <string>
#include <vector>

namespace {

constexpr std::uint32_t section_rva = 0x1000;
constexpr std::uint64_t image_base = 0x140000000ULL;

void put16(std::vector<std::uint8_t> &bytes, std::size_t offset, std::uint16_t value) {
    for (unsigned index = 0; index < 2; ++index) {
        bytes.at(offset + index) = static_cast<std::uint8_t>(value >> (index * 8));
    }
}

void put32(std::vector<std::uint8_t> &bytes, std::size_t offset, std::uint32_t value) {
    for (unsigned index = 0; index < 4; ++index) {
        bytes.at(offset + index) = static_cast<std::uint8_t>(value >> (index * 8));
    }
}

void put64(std::vector<std::uint8_t> &bytes, std::size_t offset, std::uint64_t value) {
    for (unsigned index = 0; index < 8; ++index) {
        bytes.at(offset + index) = static_cast<std::uint8_t>(value >> (index * 8));
    }
}

std::uint32_t align_up(std::uint32_t value, std::uint32_t alignment) {
    return (value + alignment - 1) & ~(alignment - 1);
}

void write_pe(const std::filesystem::path &path, std::span<const std::uint8_t> section,
              std::uint32_t import_rva = 0, std::uint32_t import_size = 0,
              std::uint32_t iat_rva = 0, std::uint32_t iat_size = 0) {
    constexpr std::uint32_t headers_size = 0x200;
    const auto raw_size = align_up(static_cast<std::uint32_t>(section.size()), 0x200);
    std::vector<std::uint8_t> file(headers_size + raw_size);
    put16(file, 0, 0x5a4d);
    put32(file, 0x3c, 0x80);
    put32(file, 0x80, 0x00004550);
    put16(file, 0x84, 0x8664);
    put16(file, 0x86, 1);
    put16(file, 0x94, 0xf0);
    put16(file, 0x96, 0x0022);
    const std::size_t optional = 0x98;
    put16(file, optional, 0x20b);
    file[optional + 2] = 14;
    put32(file, optional + 4, raw_size);
    put32(file, optional + 16, section_rva);
    put32(file, optional + 20, section_rva);
    put64(file, optional + 24, image_base);
    put32(file, optional + 32, 0x1000);
    put32(file, optional + 36, 0x200);
    put16(file, optional + 40, 6);
    put16(file, optional + 48, 6);
    put32(file, optional + 56, 0x2000);
    put32(file, optional + 60, headers_size);
    put16(file, optional + 68, 3);
    put16(file, optional + 70, 0x0100);
    put64(file, optional + 72, 1024 * 1024);
    put64(file, optional + 80, 0x1000);
    put64(file, optional + 88, 1024 * 1024);
    put64(file, optional + 96, 0x1000);
    put32(file, optional + 108, 16);
    put32(file, optional + 112 + 8, import_rva);
    put32(file, optional + 112 + 12, import_size);
    put32(file, optional + 112 + 12 * 8, iat_rva);
    put32(file, optional + 112 + 12 * 8 + 4, iat_size);

    const std::size_t section_header = optional + 0xf0;
    const std::string name = ".text";
    std::copy(name.begin(), name.end(), file.begin() + static_cast<std::ptrdiff_t>(section_header));
    put32(file, section_header + 8, static_cast<std::uint32_t>(section.size()));
    put32(file, section_header + 12, section_rva);
    put32(file, section_header + 16, raw_size);
    put32(file, section_header + 20, headers_size);
    put32(file, section_header + 36, 0x60000020);
    std::copy(section.begin(), section.end(), file.begin() + headers_size);

    std::ofstream output(path, std::ios::binary);
    if (!output.write(reinterpret_cast<const char *>(file.data()),
                      static_cast<std::streamsize>(file.size()))) {
        throw std::runtime_error("failed to write " + path.string());
    }
}

void append32(std::vector<std::uint8_t> &code, std::uint32_t value) {
    for (unsigned index = 0; index < 4; ++index) {
        code.push_back(static_cast<std::uint8_t>(value >> (index * 8)));
    }
}

void make_hello(const std::filesystem::path &path) {
    constexpr std::uint32_t message_rva = 0x1080;
    constexpr std::uint32_t imports_rva = 0x1100;
    constexpr std::uint32_t dll_rva = 0x1140;
    constexpr std::uint32_t int_rva = 0x1160;
    constexpr std::uint32_t iat_rva = 0x1190;
    constexpr std::uint32_t names_rva = 0x11c0;
    const std::string message = "Hello from an emulated Windows PE app!\r\n";
    const std::vector<std::string> imports{"GetStdHandle", "WriteFile", "ExitProcess"};
    std::vector<std::uint8_t> section(0x400);
    std::vector<std::uint8_t> code;
    const auto emit = [&](std::initializer_list<std::uint8_t> values) {
        code.insert(code.end(), values.begin(), values.end());
    };
    const auto emit_rip_relative = [&](std::initializer_list<std::uint8_t> prefix,
                                       std::uint32_t target) {
        code.insert(code.end(), prefix.begin(), prefix.end());
        const auto next = section_rva + static_cast<std::uint32_t>(code.size()) + 4;
        append32(code, target - next);
    };
    emit({0x48, 0x83, 0xec, 0x38});
    emit({0xb9, 0xf5, 0xff, 0xff, 0xff});
    emit_rip_relative({0xff, 0x15}, iat_rva);
    emit({0x48, 0x89, 0xc1});
    emit_rip_relative({0x48, 0x8d, 0x15}, message_rva);
    emit({0x41, 0xb8});
    append32(code, static_cast<std::uint32_t>(message.size()));
    emit({0x4c, 0x8d, 0x4c, 0x24, 0x30});
    emit({0x48, 0xc7, 0x44, 0x24, 0x20, 0, 0, 0, 0});
    emit_rip_relative({0xff, 0x15}, iat_rva + 8);
    emit({0x31, 0xc9});
    emit_rip_relative({0xff, 0x15}, iat_rva + 16);
    emit({0x48, 0x83, 0xc4, 0x38, 0xc3});
    std::copy(code.begin(), code.end(), section.begin());
    std::copy(message.begin(), message.end(), section.begin() + (message_rva - section_rva));

    const auto section_offset = [](std::uint32_t rva) { return rva - section_rva; };
    put32(section, section_offset(imports_rva), int_rva);
    put32(section, section_offset(imports_rva) + 12, dll_rva);
    put32(section, section_offset(imports_rva) + 16, iat_rva);
    const std::string dll = "KERNEL32.dll";
    std::copy(dll.begin(), dll.end(), section.begin() + section_offset(dll_rva));

    auto current_name_rva = names_rva;
    for (std::size_t index = 0; index < imports.size(); ++index) {
        put64(section, section_offset(int_rva) + index * 8, current_name_rva);
        put64(section, section_offset(iat_rva) + index * 8, current_name_rva);
        const auto destination = section.begin() + section_offset(current_name_rva) + 2;
        std::copy(imports[index].begin(), imports[index].end(), destination);
        current_name_rva += align_up(static_cast<std::uint32_t>(imports[index].size() + 3), 2);
    }
    write_pe(path, section, imports_rva, 40, iat_rva, 32);
}

} // namespace

int main(int argc, char **argv) {
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
        write_pe(output / "sum.exe", sum);
        make_hello(output / "hello.exe");
        return 0;
    } catch (const std::exception &error) {
        std::cerr << "make_test_apps: " << error.what() << '\n';
        return 1;
    }
}
