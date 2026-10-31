#include "winemu/memory.hpp"

#include "winemu/error.hpp"
#include "winemu/log.hpp"

#include <algorithm>
#include <iostream>
#include <limits>
#include <sstream>
#include <utility>

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>

namespace winemu {

namespace {

std::string hex_address(std::uint64_t address) {
    std::ostringstream stream;
    stream << "0x" << std::hex << address;
    return stream.str();
}

bool range_fits(std::uint64_t base, std::uint64_t size, std::uint64_t address,
                std::uint64_t access_size) {
    if (access_size == 0 || address < base ||
        size > std::numeric_limits<std::uint64_t>::max() - base) {
        return false;
    }
    const auto end = base + size;
    return address < end && access_size <= end - address;
}

} // namespace

Memory::~Memory() {
    for (const auto &allocation : allocations_) {
        VirtualFree(reinterpret_cast<void *>(static_cast<std::uintptr_t>(allocation.base)), 0,
                    MEM_RELEASE);
    }
}

void Memory::map(std::uint64_t base, std::uint64_t size, std::uint8_t permissions,
                 std::string name) {
    if (size == 0 || size > std::numeric_limits<std::size_t>::max()) {
        throw Error("invalid mapping size");
    }
    if (base > std::numeric_limits<std::uint64_t>::max() - size) {
        throw Error("mapping address overflow");
    }
    const auto end = base + size;
    for (const auto &region : regions_) {
        const auto region_end = region.base + region.size;
        if (base < region_end && region.base < end) {
            throw Error("mapping overlaps " + region.name);
        }
    }
    auto *const requested = reinterpret_cast<void *>(static_cast<std::uintptr_t>(base));
    auto *const allocation = VirtualAlloc(requested, static_cast<SIZE_T>(size),
                                          MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    if (allocation != requested) {
        if (allocation != nullptr) {
            VirtualFree(allocation, 0, MEM_RELEASE);
        }
        throw Error("cannot reserve guest mapping at " + hex_address(base));
    }
    allocations_.push_back({base, size, name, false});
    regions_.push_back(
        {base, size, permissions, std::move(name), static_cast<std::uint8_t *>(allocation)});
    if (log::enabled(log::Level::Trace)) {
        std::string permission_text;
        if ((permissions & Read) != 0) {
            permission_text += 'r';
        }
        if ((permissions & Write) != 0) {
            permission_text += 'w';
        }
        if ((permissions & Execute) != 0) {
            permission_text += 'x';
        }
        log::trace("memory", "mapped '" + regions_.back().name + "' base=" + hex_address(base) +
                                 " size=" + hex_address(size) + " perms=" + permission_text);
    }
}

void Memory::map_existing(std::uint64_t base, std::uint64_t size, std::uint8_t permissions,
                          std::string name, std::uint8_t *data) {
    if (size == 0 || data == nullptr || base > std::numeric_limits<std::uint64_t>::max() - size) {
        throw Error("invalid mapping size");
    }
    const auto end = base + size;
    for (const auto &region : regions_) {
        const auto region_end = region.base + region.size;
        if (base < region_end && region.base < end) {
            throw Error("mapping overlaps " + region.name);
        }
    }
    regions_.push_back({base, size, permissions, std::move(name), data});
    log::trace("memory", "aliased '" + regions_.back().name + "' base=" + hex_address(base) +
                             " size=" + hex_address(size));
}

void Memory::track_allocation(std::uint64_t base, std::uint64_t size, std::string name) {
    if (size == 0 || base > std::numeric_limits<std::uint64_t>::max() - size) {
        throw Error("invalid tracked allocation");
    }
    const auto end = base + size;
    for (const auto &allocation : allocations_) {
        if (base < allocation.base + allocation.size && allocation.base < end) {
            throw Error("tracked allocation overlaps " + allocation.name);
        }
    }
    allocations_.push_back({base, size, std::move(name), true});
    log::trace("memory", "reserved guest virtual memory base=" + hex_address(base) +
                             " size=" + hex_address(size));
}

void Memory::remove_mappings(std::uint64_t base, std::uint64_t size) {
    const auto end = base + size;
    std::vector<Region> replacement;
    replacement.reserve(regions_.size() + 2);
    for (const auto &region : regions_) {
        const auto region_end = region.base + region.size;
        if (end <= region.base || region_end <= base) {
            replacement.push_back(region);
            continue;
        }
        if (region.base < base) {
            replacement.push_back(
                {region.base, base - region.base, region.permissions, region.name, region.data});
        }
        if (end < region_end) {
            replacement.push_back({end, region_end - end, region.permissions, region.name,
                                   region.data + (end - region.base)});
        }
    }
    regions_ = std::move(replacement);
}

void Memory::commit(std::uint64_t base, std::uint64_t size, std::uint8_t permissions,
                    std::string name) {
    if (size == 0 || base > std::numeric_limits<std::uint64_t>::max() - size) {
        throw Error("invalid commit range");
    }
    const auto contained =
        std::any_of(allocations_.begin(), allocations_.end(), [&](const Allocation &allocation) {
            return range_fits(allocation.base, allocation.size, base, size);
        });
    if (!contained) {
        throw Error("committed memory is outside a guest reservation");
    }
    remove_mappings(base, size);
    regions_.push_back({base, size, permissions, std::move(name),
                        reinterpret_cast<std::uint8_t *>(static_cast<std::uintptr_t>(base))});
}

bool Memory::decommit(std::uint64_t base, std::uint64_t size) {
    const auto contained =
        std::any_of(allocations_.begin(), allocations_.end(), [&](const Allocation &allocation) {
            return allocation.releasable &&
                   range_fits(allocation.base, allocation.size, base, size);
        });
    if (!contained || VirtualFree(reinterpret_cast<void *>(static_cast<std::uintptr_t>(base)),
                                  static_cast<SIZE_T>(size), MEM_DECOMMIT) == FALSE) {
        return false;
    }
    remove_mappings(base, size);
    return true;
}

bool Memory::release(std::uint64_t base) {
    const auto found =
        std::find_if(allocations_.begin(), allocations_.end(), [&](const Allocation &allocation) {
            return allocation.base == base && allocation.releasable;
        });
    if (found == allocations_.end() ||
        VirtualFree(reinterpret_cast<void *>(static_cast<std::uintptr_t>(base)), 0, MEM_RELEASE) ==
            FALSE) {
        return false;
    }
    remove_mappings(found->base, found->size);
    allocations_.erase(found);
    return true;
}

bool Memory::protect(std::uint64_t base, std::uint64_t size, std::uint8_t permissions) {
    if (size == 0 || base > std::numeric_limits<std::uint64_t>::max() - size) {
        return false;
    }
    const auto end = base + size;
    std::uint64_t covered = 0;
    for (const auto &region : regions_) {
        const auto overlap_begin = std::max(base, region.base);
        const auto overlap_end = std::min(end, region.base + region.size);
        if (overlap_begin < overlap_end) {
            covered += overlap_end - overlap_begin;
        }
    }
    if (covered != size) {
        return false;
    }
    std::vector<Region> additions;
    for (auto &region : regions_) {
        const auto region_end = region.base + region.size;
        if (end <= region.base || region_end <= base) {
            continue;
        }
        const auto original = region;
        region.base = std::max(base, original.base);
        region.size = std::min(end, region_end) - region.base;
        region.permissions = permissions;
        region.data = original.data + (region.base - original.base);
        if (original.base < region.base) {
            additions.push_back({original.base, region.base - original.base, original.permissions,
                                 original.name, original.data});
        }
        const auto protected_end = region.base + region.size;
        if (protected_end < region_end) {
            additions.push_back({protected_end, region_end - protected_end, original.permissions,
                                 original.name, original.data + (protected_end - original.base)});
        }
    }
    regions_.insert(regions_.end(), additions.begin(), additions.end());
    return true;
}

bool Memory::permissions(std::uint64_t address, std::uint8_t &result) const {
    const auto found = std::find_if(regions_.begin(), regions_.end(), [&](const Region &region) {
        return range_fits(region.base, region.size, address, 1);
    });
    if (found == regions_.end()) {
        return false;
    }
    result = found->permissions;
    return true;
}

bool Memory::query(std::uint64_t address, VirtualMemoryInfo &result) const {
    const auto region = std::find_if(regions_.begin(), regions_.end(), [&](const Region &entry) {
        return range_fits(entry.base, entry.size, address, 1);
    });
    if (region != regions_.end()) {
        const auto allocation =
            std::find_if(allocations_.begin(), allocations_.end(), [&](const Allocation &entry) {
                return range_fits(entry.base, entry.size, address, 1);
            });
        result = {region->base, allocation == allocations_.end() ? region->base : allocation->base,
                  region->size, region->permissions, true};
        return true;
    }
    const auto allocation =
        std::find_if(allocations_.begin(), allocations_.end(), [&](const Allocation &entry) {
            return range_fits(entry.base, entry.size, address, 1);
        });
    if (allocation == allocations_.end()) {
        return false;
    }
    auto base = allocation->base;
    auto end = allocation->base + allocation->size;
    for (const auto &entry : regions_) {
        if (entry.base >= allocation->base + allocation->size ||
            entry.base + entry.size <= allocation->base) {
            continue;
        }
        if (entry.base + entry.size <= address) {
            base = std::max(base, entry.base + entry.size);
        } else if (address < entry.base) {
            end = std::min(end, entry.base);
        }
    }
    result = {base, allocation->base, end - base, 0, false};
    return true;
}

bool Memory::contains(std::uint64_t address, std::uint64_t size) const {
    return std::any_of(regions_.begin(), regions_.end(), [&](const Region &region) {
        return range_fits(region.base, region.size, address, size);
    });
}

const Memory::Region &Memory::region_for(std::uint64_t address, std::uint64_t size,
                                         std::uint8_t permission) const {
    for (const auto &region : regions_) {
        if (range_fits(region.base, region.size, address, size)) {
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
