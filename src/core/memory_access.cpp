#include "winemu/memory.hpp"

#include "winemu/detail/memory_utils.hpp"
#include "winemu/error.hpp"

#include <algorithm>
#include <utility>

namespace winemu {

using detail::hex_address;
using detail::range_fits;

bool Memory::contains(std::uint64_t address, std::uint64_t size) const {
    return std::any_of(regions_.begin(), regions_.end(), [&](const Region &region) {
        return range_fits(region.base, region.size, address, size);
    });
}

const Memory::Region &Memory::region_for(std::uint64_t address, std::uint64_t size,
                                         std::uint8_t permission) const {
    const auto page = address >> region_page_shift;
    if (const auto cached = region_cache_.find(page); cached != region_cache_.end()) {
        const Region &region = regions_[cached->second];
        if (range_fits(region.base, region.size, address, size)) {
            if ((region.permissions & permission) != permission) {
                throw Error("memory protection violation at " + hex_address(address));
            }
            return region;
        }
    }
    for (std::size_t index = 0; index < regions_.size(); ++index) {
        const Region &region = regions_[index];
        if (range_fits(region.base, region.size, address, size)) {
            region_cache_[page] = index;
            if ((region.permissions & permission) != permission) {
                throw Error("memory protection violation at " + hex_address(address));
            }
            return region;
        }
    }
    throw Error("unmapped memory access at " + hex_address(address));
}

Memory::Region &Memory::region_for(std::uint64_t address, std::uint64_t size,
                                   std::uint8_t permission) {
    return const_cast<Region &>(std::as_const(*this).region_for(address, size, permission));
}

std::uint8_t Memory::read8(std::uint64_t address) const {
    const auto &region = region_for(address, 1, Read);
    return region.data[static_cast<std::size_t>(address - region.base)];
}

std::uint16_t Memory::read16(std::uint64_t address) const {
    return static_cast<std::uint16_t>(read8(address)) |
           (static_cast<std::uint16_t>(read8(address + 1)) << 8);
}

std::uint32_t Memory::read32(std::uint64_t address) const {
    std::uint32_t value = 0;
    for (unsigned index = 0; index < 4; ++index) {
        value |= static_cast<std::uint32_t>(read8(address + index)) << (index * 8);
    }
    return value;
}

std::uint64_t Memory::read64(std::uint64_t address) const {
    std::uint64_t value = 0;
    for (unsigned index = 0; index < 8; ++index) {
        value |= static_cast<std::uint64_t>(read8(address + index)) << (index * 8);
    }
    return value;
}

std::vector<std::uint8_t> Memory::read(std::uint64_t address, std::size_t size) const {
    const auto &region = region_for(address, size, Read);
    const auto offset = static_cast<std::size_t>(address - region.base);
    return {region.data + offset, region.data + offset + size};
}

std::string Memory::read_c_string(std::uint64_t address, std::size_t limit) const {
    std::string value;
    value.reserve(std::min<std::size_t>(limit, 256));
    for (std::size_t index = 0; index < limit; ++index) {
        const auto byte = read8(address + index);
        if (byte == 0) {
            return value;
        }
        value.push_back(static_cast<char>(byte));
    }
    throw Error("unterminated string at " + hex_address(address));
}

std::wstring Memory::read_wide_string(std::uint64_t address, std::size_t limit) const {
    std::wstring value;
    value.reserve(std::min<std::size_t>(limit, 256));
    for (std::size_t index = 0; index < limit; ++index) {
        const auto character = read16(address + index * 2);
        if (character == 0) {
            return value;
        }
        value.push_back(static_cast<wchar_t>(character));
    }
    throw Error("unterminated wide string at " + hex_address(address));
}

void Memory::write8(std::uint64_t address, std::uint8_t value) {
    auto &region = region_for(address, 1, Write);
    region.data[static_cast<std::size_t>(address - region.base)] = value;
}

void Memory::write16(std::uint64_t address, std::uint16_t value) {
    for (unsigned index = 0; index < 2; ++index) {
        write8(address + index, static_cast<std::uint8_t>(value >> (index * 8)));
    }
}

void Memory::write32(std::uint64_t address, std::uint32_t value) {
    for (unsigned index = 0; index < 4; ++index) {
        write8(address + index, static_cast<std::uint8_t>(value >> (index * 8)));
    }
}

void Memory::write64(std::uint64_t address, std::uint64_t value) {
    for (unsigned index = 0; index < 8; ++index) {
        write8(address + index, static_cast<std::uint8_t>(value >> (index * 8)));
    }
}

void Memory::write(std::uint64_t address, std::span<const std::uint8_t> bytes) {
    auto &region = region_for(address, bytes.size(), Write);
    const auto offset = static_cast<std::size_t>(address - region.base);
    std::copy(bytes.begin(), bytes.end(), region.data + offset);
}

} // namespace winemu
