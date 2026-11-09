#include "winemu/cpu.hpp"

#include <bit>

namespace winemu {

namespace {

constexpr std::uint64_t flag_cf = 1ULL << 0;
constexpr std::uint64_t flag_pf = 1ULL << 2;
constexpr std::uint64_t flag_af = 1ULL << 4;
constexpr std::uint64_t flag_zf = 1ULL << 6;
constexpr std::uint64_t flag_sf = 1ULL << 7;
constexpr std::uint64_t flag_of = 1ULL << 11;

} // namespace

void Cpu::set_logic_flags(std::uint64_t result, unsigned width) {
    const auto masked = result & mask_for(width);
    flags_ &= ~(flag_cf | flag_pf | flag_af | flag_zf | flag_sf | flag_of);
    if (masked == 0) {
        flags_ |= flag_zf;
    }
    if ((masked & (1ULL << (width - 1))) != 0) {
        flags_ |= flag_sf;
    }
    if ((std::popcount(static_cast<std::uint8_t>(masked)) & 1) == 0) {
        flags_ |= flag_pf;
    }
}

void Cpu::set_add_flags(std::uint64_t left, std::uint64_t right, std::uint64_t result,
                        unsigned width) {
    const auto mask = mask_for(width);
    left &= mask;
    right &= mask;
    const auto masked = result & mask;
    set_logic_flags(masked, width);
    const bool carry = width == 64 ? masked < left : left + right > mask;
    if (carry) {
        flags_ |= flag_cf;
    }
    if (((left ^ right ^ masked) & 0x10) != 0) {
        flags_ |= flag_af;
    }
    const auto sign = 1ULL << (width - 1);
    if (((~(left ^ right) & (left ^ masked)) & sign) != 0) {
        flags_ |= flag_of;
    }
}

void Cpu::set_sub_flags(std::uint64_t left, std::uint64_t right, std::uint64_t result,
                        unsigned width) {
    const auto mask = mask_for(width);
    left &= mask;
    right &= mask;
    const auto masked = result & mask;
    set_logic_flags(masked, width);
    if (left < right) {
        flags_ |= flag_cf;
    }
    if (((left ^ right ^ masked) & 0x10) != 0) {
        flags_ |= flag_af;
    }
    const auto sign = 1ULL << (width - 1);
    if ((((left ^ right) & (left ^ masked)) & sign) != 0) {
        flags_ |= flag_of;
    }
}

bool Cpu::condition(std::uint8_t code) const {
    const bool cf = (flags_ & flag_cf) != 0;
    const bool pf = (flags_ & flag_pf) != 0;
    const bool zf = (flags_ & flag_zf) != 0;
    const bool sf = (flags_ & flag_sf) != 0;
    const bool of = (flags_ & flag_of) != 0;
    switch (code & 0xf) {
    case 0:
        return of;
    case 1:
        return !of;
    case 2:
        return cf;
    case 3:
        return !cf;
    case 4:
        return zf;
    case 5:
        return !zf;
    case 6:
        return cf || zf;
    case 7:
        return !cf && !zf;
    case 8:
        return sf;
    case 9:
        return !sf;
    case 10:
        return pf;
    case 11:
        return !pf;
    case 12:
        return sf != of;
    case 13:
        return sf == of;
    case 14:
        return zf || sf != of;
    case 15:
        return !zf && sf == of;
    default:
        return false;
    }
}

} // namespace winemu
