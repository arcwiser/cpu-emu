#include "test_suite.hpp"

#include "winemu/error.hpp"
#include "winemu/memory.hpp"

#include <cstdint>

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
}

} // namespace winemu::tests
