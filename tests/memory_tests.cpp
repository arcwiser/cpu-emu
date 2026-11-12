#include "test_suite.hpp"

#include "winemu/error.hpp"
#include "winemu/memory.hpp"

#include <cstdint>
#include <span>

namespace winemu::tests {

void test_memory() {
    winemu::Memory memory;
    memory.map(0x200000000ULL, 0x1000, winemu::Read | winemu::Write, "test");
    memory.write64(0x200000100ULL, 0x8877665544332211ULL);
    require(memory.read64(0x200000100ULL) == 0x8877665544332211ULL, "64-bit memory round trip");
    bool rejected = false;
    try {
        static_cast<void>(memory.read8(0x400000000ULL));
    } catch (const winemu::Error &) {
        rejected = true;
    }
    require(rejected, "unmapped access must fail");

    // Empty bulk operations do not dereference their address, matching memcpy/read semantics.
    require(memory.read(0xffffffffffffffffULL, 0).empty(), "zero-length read is empty");
    memory.write(0xffffffffffffffffULL, std::span<const std::uint8_t>{});

    const std::uint8_t wide_text[] = {'C', 0, 'P', 0, 'U', 0, 0, 0};
    memory.write(0x200000200ULL, wide_text);
    require(memory.read_wide_string(0x200000200ULL) == L"CPU", "wide string round trip");

    // Two small regions that share one lookup page must both stay reachable through the
    // region cache, and re-protecting a page must invalidate stale cache entries.
    memory.map(0x210000400ULL, 0x10, winemu::Read | winemu::Write, "low fragment");
    memory.map(0x210000800ULL, 0x10, winemu::Read | winemu::Write, "high fragment");
    memory.write32(0x210000400ULL, 0x11111111U);
    memory.write32(0x210000800ULL, 0x22222222U);
    require(memory.read32(0x210000400ULL) == 0x11111111U, "same-page fragment A");
    require(memory.read32(0x210000800ULL) == 0x22222222U, "same-page fragment B");
    require(memory.read32(0x210000400ULL) == 0x11111111U, "same-page fragment A re-read");
    require(memory.protect(0x210000800ULL, 0x10, winemu::Read), "protect fragment B read-only");
    bool write_rejected = false;
    try {
        memory.write32(0x210000800ULL, 0x33333333U);
    } catch (const winemu::Error &) {
        write_rejected = true;
    }
    require(write_rejected, "protect must invalidate the region cache for that page");
    require(memory.read32(0x210000800ULL) == 0x22222222U, "protected fragment stays readable");

    memory.map(0x220000000ULL, 0x1000, winemu::Read | winemu::Write, "owned view");
    memory.write8(0x220000fffULL, 0x5a);
    require(!memory.unmap_owned(0x220000001ULL), "owned mapping rejects an interior address");
    require(memory.read8(0x220000fffULL) == 0x5a,
            "failed owned unmap preserves the complete mapping");
    require(memory.unmap_owned(0x220000000ULL), "owned mapping unmaps at its exact base");
    require(!memory.unmap_owned(0x220000000ULL), "owned mapping rejects a repeated unmap");
    bool unmapped_read_rejected = false;
    try {
        static_cast<void>(memory.read8(0x220000000ULL));
    } catch (const winemu::Error &) {
        unmapped_read_rejected = true;
    }
    require(unmapped_read_rejected, "owned unmap removes access to the entire region");
}

} // namespace winemu::tests
