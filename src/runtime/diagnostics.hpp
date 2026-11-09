#pragma once

#include "winemu/cpu.hpp"

#include <string>

namespace winemu::detail {

// Renders the guest register state and the recent instruction history. Used whenever the
// emulator reports why a guest stopped, including fail-fast paths that return normally.
[[nodiscard]] std::string cpu_state_dump(const Cpu &cpu);

// Non-volatile registers often still point at the guest object the failing code was operating on,
// so a bounded window at each one usually shows the state that produced the fault.
[[nodiscard]] std::string callee_saved_windows(const Cpu &cpu);

} // namespace winemu::detail
