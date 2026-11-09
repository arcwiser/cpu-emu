#include "winemu/memory.hpp"

#include "winemu/detail/memory_utils.hpp"
#include "winemu/error.hpp"
#include "winemu/log.hpp"

#include <algorithm>
#include <array>
#include <iostream>
#include <limits>
#include <sstream>
#include <utility>

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>

namespace winemu {

namespace detail {

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

} // namespace detail

using detail::hex_address;
using detail::range_fits;

Memory::~Memory() {
    for (const auto &allocation : allocations_) {
        VirtualFree(allocation.data, 0, MEM_RELEASE);
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
    auto *allocation = VirtualAlloc(requested, static_cast<SIZE_T>(size), MEM_RESERVE | MEM_COMMIT,
                                    PAGE_READWRITE);
    if (allocation != requested && allocation != nullptr) {
        VirtualFree(allocation, 0, MEM_RELEASE);
        allocation = nullptr;
    }
    if (allocation == nullptr) {
        const auto error = GetLastError();
        MEMORY_BASIC_INFORMATION information{};
        static_cast<void>(VirtualQuery(requested, &information, sizeof(information)));
        std::array<wchar_t, 32768> module_path{};
        const auto module_length =
            GetModuleFileNameW(static_cast<HMODULE>(information.AllocationBase), module_path.data(),
                               static_cast<DWORD>(module_path.size()));
        std::string occupied_by;
        for (DWORD index = 0; index < module_length; ++index) {
            occupied_by.push_back(module_path[index] < 0x80 ? static_cast<char>(module_path[index])
                                                            : '?');
        }
        allocation = VirtualAlloc(nullptr, static_cast<SIZE_T>(size), MEM_RESERVE | MEM_COMMIT,
                                  PAGE_READWRITE);
        if (allocation == nullptr) {
            throw Error("cannot reserve backing memory for guest mapping at " + hex_address(base) +
                        " (Win32 error " + std::to_string(error) + ")");
        }
        log::trace("memory", "guest address " + hex_address(base) +
                                 " uses non-identity backing; preferred state=" +
                                 hex_address(information.State) +
                                 (occupied_by.empty() ? "" : " module=" + occupied_by));
    }
    allocations_.push_back({base, size, name, false, static_cast<std::uint8_t *>(allocation)});
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
    allocations_.push_back({base, size, std::move(name), true,
                            reinterpret_cast<std::uint8_t *>(static_cast<std::uintptr_t>(base))});
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
    region_cache_.clear();
}

} // namespace winemu
