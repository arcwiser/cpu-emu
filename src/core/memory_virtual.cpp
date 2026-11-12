#include "winemu/memory.hpp"

#include "winemu/detail/memory_utils.hpp"
#include "winemu/error.hpp"
#include "winemu/log.hpp"

#include <algorithm>

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>

namespace winemu {

using detail::hex_address;
using detail::range_fits;

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

bool Memory::unmap_owned(std::uint64_t base) {
    const auto found =
        std::find_if(allocations_.begin(), allocations_.end(), [&](const Allocation &allocation) {
            return allocation.base == base && !allocation.releasable;
        });
    if (found == allocations_.end() || VirtualFree(found->data, 0, MEM_RELEASE) == FALSE) {
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
    region_cache_.clear();
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

} // namespace winemu
