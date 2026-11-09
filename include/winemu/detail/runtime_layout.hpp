#pragma once

#include <cstdint>

namespace winemu::detail {

inline constexpr std::uint64_t return_thunk64 = 0xffff'0000'0000'0000ULL;
inline constexpr std::uint64_t return_thunk32 = 0x7ff0'0000ULL;
inline constexpr std::uint64_t stack_top = 0x0000'0000'7000'0000ULL;
inline constexpr std::uint64_t minimum_stack_size = 1024 * 1024;
inline constexpr std::uint64_t environment_base = 0x7fc0'0000ULL;
inline constexpr std::uint64_t environment_size = 0x0002'0000ULL;
inline constexpr std::uint64_t tls_base = 0x7fc2'0000ULL;
inline constexpr std::uint64_t tls_size = 0x0002'0000ULL;
inline constexpr std::uint64_t teb_base = environment_base + 0xe000;
inline constexpr std::uint64_t peb_base = environment_base + 0xf000;
inline constexpr std::uint64_t crt_commode = environment_base + 0x1000;
inline constexpr std::uint64_t crt_errno = environment_base + 0x1008;
inline constexpr std::uint64_t crt_argc = environment_base + 0x1100;
inline constexpr std::uint64_t crt_argv = environment_base + 0x1108;
inline constexpr std::uint64_t crt_wargv = environment_base + 0x1110;
inline constexpr std::uint64_t command_line_address = environment_base + 0x2000;
inline constexpr std::uint64_t winmain_command_line_address = environment_base + 0x3000;

} // namespace winemu::detail
