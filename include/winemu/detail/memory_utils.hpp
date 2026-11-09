#pragma once

#include <cstdint>
#include <string>

namespace winemu::detail {

[[nodiscard]] std::string hex_address(std::uint64_t address);
[[nodiscard]] bool range_fits(std::uint64_t base, std::uint64_t size, std::uint64_t address,
                              std::uint64_t access_size);

} // namespace winemu::detail
