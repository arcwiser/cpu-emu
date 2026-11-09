#pragma once

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <span>
#include <vector>

namespace cpuemu::fixtures {

inline constexpr std::uint32_t section_rva = 0x1000;
inline constexpr std::uint64_t image_base = 0x140000000ULL;

void put16(std::vector<std::uint8_t> &bytes, std::size_t offset, std::uint16_t value);
void put32(std::vector<std::uint8_t> &bytes, std::size_t offset, std::uint32_t value);
void put64(std::vector<std::uint8_t> &bytes, std::size_t offset, std::uint64_t value);
[[nodiscard]] std::uint32_t align_up(std::uint32_t value, std::uint32_t alignment);
void write_pe(const std::filesystem::path &path, std::span<const std::uint8_t> section,
              std::uint32_t import_rva = 0, std::uint32_t import_size = 0,
              std::uint32_t iat_rva = 0, std::uint32_t iat_size = 0);
void write_pe32(const std::filesystem::path &path, std::span<const std::uint8_t> section);

} // namespace cpuemu::fixtures
