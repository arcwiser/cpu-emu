#include "pe_fixture_writer.hpp"

#include <algorithm>
#include <fstream>
#include <stdexcept>
#include <string>
#include <vector>

namespace cpuemu::fixtures {

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
              std::uint32_t import_rva, std::uint32_t import_size, std::uint32_t iat_rva,
              std::uint32_t iat_size) {
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

void write_pe32(const std::filesystem::path &path, std::span<const std::uint8_t> section) {
    constexpr std::uint32_t headers_size = 0x200;
    constexpr std::uint32_t pe32_image_base = 0x00400000;
    const auto raw_size = align_up(static_cast<std::uint32_t>(section.size()), 0x200);
    std::vector<std::uint8_t> file(headers_size + raw_size);
    put16(file, 0, 0x5a4d);
    put32(file, 0x3c, 0x80);
    put32(file, 0x80, 0x00004550);
    put16(file, 0x84, 0x014c);
    put16(file, 0x86, 1);
    put16(file, 0x94, 0xe0);
    put16(file, 0x96, 0x0102);
    const std::size_t optional = 0x98;
    put16(file, optional, 0x10b);
    file[optional + 2] = 14;
    put32(file, optional + 4, raw_size);
    put32(file, optional + 16, section_rva);
    put32(file, optional + 20, section_rva);
    put32(file, optional + 28, pe32_image_base);
    put32(file, optional + 32, 0x1000);
    put32(file, optional + 36, 0x200);
    put16(file, optional + 40, 6);
    put16(file, optional + 48, 6);
    put32(file, optional + 56, 0x2000);
    put32(file, optional + 60, headers_size);
    put16(file, optional + 68, 3);
    put16(file, optional + 70, 0x0100);
    put32(file, optional + 72, 1024 * 1024);
    put32(file, optional + 76, 0x1000);
    put32(file, optional + 80, 1024 * 1024);
    put32(file, optional + 84, 0x1000);
    put32(file, optional + 92, 16);

    const std::size_t section_header = optional + 0xe0;
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

} // namespace cpuemu::fixtures
