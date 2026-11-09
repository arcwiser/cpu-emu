#pragma once

#include <cstdint>
#include <exception>
#include <string>

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
// Common Controls depends on the base Windows declarations above.
#include <commctrl.h>

namespace winemu {

class Cpu;
class Runtime;

namespace detail {

void set_callback_context(Runtime &runtime, Cpu &cpu, std::uint32_t &exit_code, bool &exited);
void clear_callback_context();
[[nodiscard]] std::exception_ptr take_callback_exception();
[[nodiscard]] std::string window_message_name(std::uint32_t message);
LRESULT CALLBACK window_proc_bridge(HWND window, UINT message, WPARAM word_parameter,
                                    LPARAM long_parameter);
LRESULT CALLBACK window_subclass_bridge(HWND window, UINT message, WPARAM word_parameter,
                                        LPARAM long_parameter, UINT_PTR token,
                                        DWORD_PTR reference_data);

} // namespace detail
} // namespace winemu
