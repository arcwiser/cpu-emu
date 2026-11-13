#include "callbacks.hpp"

#include "winemu/runtime.hpp"

#include "winemu/detail/runtime_layout.hpp"
#include "winemu/error.hpp"
#include "winemu/log.hpp"

#include <algorithm>

namespace winemu {

namespace detail {

constexpr std::uint64_t callback_return = 0xffff'0000'0000'0080ULL;
constexpr std::uint64_t callback_return32 = 0x7ff0'0080ULL;

thread_local Runtime *active_runtime = nullptr;
thread_local Cpu *active_cpu = nullptr;
thread_local std::uint32_t *active_exit_code = nullptr;
thread_local bool *active_exited = nullptr;
thread_local std::exception_ptr callback_exception;

void set_callback_context(Runtime &runtime, Cpu &cpu, std::uint32_t &exit_code, bool &exited) {
    active_runtime = &runtime;
    active_cpu = &cpu;
    active_exit_code = &exit_code;
    active_exited = &exited;
    callback_exception = nullptr;
}

void clear_callback_context() {
    active_runtime = nullptr;
    active_cpu = nullptr;
    active_exit_code = nullptr;
    active_exited = nullptr;
}

std::exception_ptr take_callback_exception() {
    auto exception = callback_exception;
    callback_exception = nullptr;
    return exception;
}

std::string window_message_name(std::uint32_t message) {
    switch (message) {
    case WM_NULL:
        return "WM_NULL";
    case WM_CREATE:
        return "WM_CREATE";
    case WM_DESTROY:
        return "WM_DESTROY";
    case WM_MOVE:
        return "WM_MOVE";
    case WM_SIZE:
        return "WM_SIZE";
    case WM_ACTIVATE:
        return "WM_ACTIVATE";
    case WM_ACTIVATEAPP:
        return "WM_ACTIVATEAPP";
    case WM_SETFOCUS:
        return "WM_SETFOCUS";
    case WM_KILLFOCUS:
        return "WM_KILLFOCUS";
    case WM_ENABLE:
        return "WM_ENABLE";
    case WM_SETREDRAW:
        return "WM_SETREDRAW";
    case WM_SETTEXT:
        return "WM_SETTEXT";
    case WM_GETTEXT:
        return "WM_GETTEXT";
    case WM_GETTEXTLENGTH:
        return "WM_GETTEXTLENGTH";
    case WM_PAINT:
        return "WM_PAINT";
    case WM_CLOSE:
        return "WM_CLOSE";
    case WM_QUIT:
        return "WM_QUIT";
    case WM_ERASEBKGND:
        return "WM_ERASEBKGND";
    case WM_SHOWWINDOW:
        return "WM_SHOWWINDOW";
    case WM_SETCURSOR:
        return "WM_SETCURSOR";
    case WM_MOUSEACTIVATE:
        return "WM_MOUSEACTIVATE";
    case WM_GETICON:
        return "WM_GETICON";
    case WM_SETICON:
        return "WM_SETICON";
    case WM_KEYDOWN:
        return "WM_KEYDOWN";
    case WM_KEYUP:
        return "WM_KEYUP";
    case WM_CHAR:
        return "WM_CHAR";
    case WM_SYSKEYDOWN:
        return "WM_SYSKEYDOWN";
    case WM_SYSKEYUP:
        return "WM_SYSKEYUP";
    case WM_SYSCHAR:
        return "WM_SYSCHAR";
    case WM_SYSCOMMAND:
        return "WM_SYSCOMMAND";
    case WM_COMMAND:
        return "WM_COMMAND";
    case WM_TIMER:
        return "WM_TIMER";
    case WM_HSCROLL:
        return "WM_HSCROLL";
    case WM_VSCROLL:
        return "WM_VSCROLL";
    case WM_INITMENU:
        return "WM_INITMENU";
    case WM_INITMENUPOPUP:
        return "WM_INITMENUPOPUP";
    case WM_MENUSELECT:
        return "WM_MENUSELECT";
    case WM_CONTEXTMENU:
        return "WM_CONTEXTMENU";
    case WM_MOUSEMOVE:
        return "WM_MOUSEMOVE";
    case WM_LBUTTONDOWN:
        return "WM_LBUTTONDOWN";
    case WM_LBUTTONUP:
        return "WM_LBUTTONUP";
    case WM_LBUTTONDBLCLK:
        return "WM_LBUTTONDBLCLK";
    case WM_RBUTTONDOWN:
        return "WM_RBUTTONDOWN";
    case WM_RBUTTONUP:
        return "WM_RBUTTONUP";
    case WM_MOUSEWHEEL:
        return "WM_MOUSEWHEEL";
    case WM_GETMINMAXINFO:
        return "WM_GETMINMAXINFO";
    case WM_GETOBJECT:
        return "WM_GETOBJECT";
    case WM_NCCREATE:
        return "WM_NCCREATE";
    case WM_NCCALCSIZE:
        return "WM_NCCALCSIZE";
    case WM_NCHITTEST:
        return "WM_NCHITTEST";
    case WM_NCPAINT:
        return "WM_NCPAINT";
    case WM_NCACTIVATE:
        return "WM_NCACTIVATE";
    case WM_NCDESTROY:
        return "WM_NCDESTROY";
    case WM_NCMOUSEMOVE:
        return "WM_NCMOUSEMOVE";
    case WM_WINDOWPOSCHANGING:
        return "WM_WINDOWPOSCHANGING";
    case WM_WINDOWPOSCHANGED:
        return "WM_WINDOWPOSCHANGED";
    case WM_NOTIFY:
        return "WM_NOTIFY";
    case WM_STYLECHANGING:
        return "WM_STYLECHANGING";
    case WM_STYLECHANGED:
        return "WM_STYLECHANGED";
    case WM_SETTINGCHANGE:
        return "WM_SETTINGCHANGE";
    case WM_DISPLAYCHANGE:
        return "WM_DISPLAYCHANGE";
    case WM_DEVICECHANGE:
        return "WM_DEVICECHANGE";
    case WM_CAPTURECHANGED:
        return "WM_CAPTURECHANGED";
    case WM_ENTERSIZEMOVE:
        return "WM_ENTERSIZEMOVE";
    case WM_EXITSIZEMOVE:
        return "WM_EXITSIZEMOVE";
    case WM_IME_SETCONTEXT:
        return "WM_IME_SETCONTEXT";
    case WM_IME_NOTIFY:
        return "WM_IME_NOTIFY";
    case WM_THEMECHANGED:
        return "WM_THEMECHANGED";
    case WM_DPICHANGED:
        return "WM_DPICHANGED";
    default:
        return "message 0x" + log::hex(message);
    }
}

LRESULT CALLBACK window_proc_bridge(HWND window, UINT message, WPARAM word_parameter,
                                    LPARAM long_parameter) {
    if (active_runtime == nullptr || active_cpu == nullptr || active_exit_code == nullptr ||
        active_exited == nullptr) {
        return DefWindowProcW(window, message, word_parameter, long_parameter);
    }
    if (log::enabled(log::Level::Trace)) {
        log::trace("window", "callback " + window_message_name(message) +
                                 " window=" + log::hex(reinterpret_cast<std::uint64_t>(window)) +
                                 " wparam=" + log::hex(word_parameter) +
                                 " lparam=" + log::hex(static_cast<std::uint64_t>(long_parameter)));
    }
    std::intptr_t result = 0;
    try {
        result = active_runtime->invoke_window_proc(
            *active_cpu, reinterpret_cast<std::uint64_t>(window), message, word_parameter,
            long_parameter, *active_exit_code, *active_exited);
    } catch (...) {
        callback_exception = std::current_exception();
        log::error("window", "guest window procedure faulted on " + window_message_name(message) +
                                 ", falling back to DefWindowProcW");
        result = DefWindowProcW(window, message, word_parameter, long_parameter);
    }
    if (log::enabled(log::Level::Trace)) {
        log::trace("window", "callback " + window_message_name(message) + " -> " +
                                 log::hex(static_cast<std::uint64_t>(result)));
    }
    return result;
}

INT_PTR CALLBACK dialog_proc_bridge(HWND window, UINT message, WPARAM word_parameter,
                                    LPARAM long_parameter) {
    if (active_runtime == nullptr || active_cpu == nullptr || active_exit_code == nullptr ||
        active_exited == nullptr) {
        return FALSE;
    }
    std::intptr_t result = FALSE;
    try {
        result = active_runtime->invoke_dialog_proc(
            *active_cpu, reinterpret_cast<std::uint64_t>(window), message, word_parameter,
            long_parameter, *active_exit_code, *active_exited);
    } catch (...) {
        callback_exception = std::current_exception();
        log::error("dialog", "guest dialog procedure faulted on " + window_message_name(message));
        // A modal host dialog cannot be left running after its guest procedure faults.
        EndDialog(window, -1);
    }
    return result;
}

BOOL CALLBACK window_enum_bridge(HWND window, LPARAM parameter) {
    static_cast<void>(parameter);
    if (active_runtime == nullptr || active_cpu == nullptr || active_exit_code == nullptr ||
        active_exited == nullptr) {
        return FALSE;
    }
    try {
        return active_runtime->invoke_window_enum(*active_cpu,
                                                  reinterpret_cast<std::uint64_t>(window),
                                                  *active_exit_code, *active_exited)
                   ? TRUE
                   : FALSE;
    } catch (...) {
        callback_exception = std::current_exception();
        log::error("window", "guest window-enumeration procedure faulted");
        return FALSE;
    }
}

LRESULT CALLBACK window_subclass_bridge(HWND window, UINT message, WPARAM word_parameter,
                                        LPARAM long_parameter, UINT_PTR token,
                                        DWORD_PTR reference_data) {
    static_cast<void>(reference_data);
    if (active_runtime == nullptr || active_cpu == nullptr || active_exit_code == nullptr ||
        active_exited == nullptr) {
        return DefSubclassProc(window, message, word_parameter, long_parameter);
    }
    std::intptr_t result = 0;
    try {
        result = active_runtime->invoke_window_subclass(
            *active_cpu, token, reinterpret_cast<std::uint64_t>(window), message, word_parameter,
            long_parameter, *active_exit_code, *active_exited);
    } catch (...) {
        callback_exception = std::current_exception();
        log::error("window", "guest subclass procedure faulted on " + window_message_name(message) +
                                 ", falling back to DefSubclassProc");
        result = DefSubclassProc(window, message, word_parameter, long_parameter);
    }
    return result;
}

} // namespace detail

std::uint64_t Runtime::invoke_guest(Cpu &cpu, std::uint64_t target,
                                    const std::array<std::uint64_t, 4> &arguments,
                                    std::uint32_t &exit_code, bool &exited) {
    return invoke_guest(cpu, target, std::span<const std::uint64_t>(arguments), exit_code, exited);
}

std::uint64_t Runtime::invoke_guest(Cpu &cpu, std::uint64_t target,
                                    std::span<const std::uint64_t> arguments,
                                    std::uint32_t &exit_code, bool &exited) {
    if (arguments.size() > 6) {
        throw Error("guest callback has too many arguments");
    }
    const auto outer_stack = cpu.reg(Rsp);
    const auto outer_rip = cpu.rip();
    const auto callback_stack = outer_stack - (guest_is_64_bit_ ? 0x40 : 0x20);
    const auto return_address =
        guest_is_64_bit_ ? detail::callback_return : detail::callback_return32;
    if (guest_is_64_bit_) {
        const auto argument = [&](std::size_t index) {
            return index < arguments.size() ? arguments[index] : 0;
        };
        cpu.set_reg(Rcx, argument(0));
        cpu.set_reg(Rdx, argument(1));
        cpu.set_reg(R8, argument(2));
        cpu.set_reg(R9, argument(3));
        cpu.memory().write64(callback_stack, return_address);
        for (std::size_t index = 4; index < arguments.size(); ++index) {
            cpu.memory().write64(callback_stack + 8 + index * 8, arguments[index]);
        }
    } else {
        cpu.memory().write32(callback_stack, static_cast<std::uint32_t>(return_address));
        for (std::size_t index = 0; index < arguments.size(); ++index) {
            cpu.memory().write32(callback_stack + 4 + index * 4,
                                 static_cast<std::uint32_t>(arguments[index]));
        }
    }
    cpu.set_reg(Rsp, callback_stack);
    cpu.set_rip(target);
    try {
        while (!exited && cpu.rip() != return_address) {
            if (!dispatch(cpu, exit_code, exited)) {
                cpu.step();
            }
        }
    } catch (...) {
        cpu.set_reg(Rsp, outer_stack);
        cpu.set_rip(outer_rip);
        throw;
    }
    const auto result = cpu.reg(Rax);
    cpu.set_reg(Rsp, outer_stack);
    cpu.set_rip(outer_rip);
    return result;
}

std::intptr_t Runtime::invoke_window_proc(Cpu &cpu, std::uint64_t window, std::uint32_t message,
                                          std::uint64_t word_parameter, std::int64_t long_parameter,
                                          std::uint32_t &exit_code, bool &exited) {
    auto found = window_procedures_.find(window);
    if (found == window_procedures_.end() && creating_window_procedure_ != 0) {
        found = window_procedures_.emplace(window, creating_window_procedure_).first;
    }
    if (found == window_procedures_.end()) {
        const auto result =
            DefWindowProcW(reinterpret_cast<HWND>(window), message, word_parameter, long_parameter);
        if (message == WM_NCDESTROY) {
            edit_memory_handles_.erase(window);
        }
        return result;
    }
    const auto result = invoke_window_callback(cpu, found->second, window, message, word_parameter,
                                               long_parameter, 0, 0, false, exit_code, exited);
    if (message == WM_NCDESTROY) {
        window_procedures_.erase(window);
        edit_memory_handles_.erase(window);
    }
    return result;
}

std::intptr_t Runtime::invoke_window_subclass(Cpu &cpu, std::uint64_t token, std::uint64_t window,
                                              std::uint32_t message, std::uint64_t word_parameter,
                                              std::int64_t long_parameter, std::uint32_t &exit_code,
                                              bool &exited) {
    const auto found = window_subclasses_.find(token);
    if (found == window_subclasses_.end() || found->second.window != window) {
        return DefSubclassProc(reinterpret_cast<HWND>(window), message, word_parameter,
                               long_parameter);
    }
    const auto record = found->second;
    const auto result = invoke_window_callback(cpu, record.procedure, window, message,
                                               word_parameter, long_parameter, record.id,
                                               record.reference_data, true, exit_code, exited);
    if (message == WM_NCDESTROY) {
        window_subclasses_.erase(token);
    }
    return result;
}

std::intptr_t Runtime::invoke_dialog_proc(Cpu &cpu, std::uint64_t window, std::uint32_t message,
                                          std::uint64_t word_parameter, std::int64_t long_parameter,
                                          std::uint32_t &exit_code, bool &exited) {
    auto found = dialog_procedures_.find(window);
    if (found == dialog_procedures_.end() && !pending_dialogs_.empty()) {
        found = dialog_procedures_.emplace(window, pending_dialogs_.back().procedure).first;
    }
    if (found == dialog_procedures_.end()) {
        return FALSE;
    }
    if (message == WM_INITDIALOG && !pending_dialogs_.empty()) {
        long_parameter = static_cast<std::int64_t>(pending_dialogs_.back().init_parameter);
    }
    const auto result = invoke_window_callback(cpu, found->second, window, message, word_parameter,
                                               long_parameter, 0, 0, false, exit_code, exited);
    if (message == WM_NCDESTROY) {
        dialog_procedures_.erase(window);
    }
    return result;
}

bool Runtime::invoke_window_enum(Cpu &cpu, std::uint64_t window, std::uint32_t &exit_code,
                                 bool &exited) {
    if (pending_window_enumerations_.empty()) {
        return false;
    }
    const auto record = pending_window_enumerations_.back();
    if (record.current_process_only) {
        DWORD process_id = 0;
        GetWindowThreadProcessId(reinterpret_cast<HWND>(window), &process_id);
        if (process_id != GetCurrentProcessId()) {
            return true;
        }
    }
    const std::array<std::uint64_t, 2> arguments{window, record.parameter};
    return invoke_guest(cpu, record.procedure, std::span<const std::uint64_t>(arguments), exit_code,
                        exited) != 0;
}

std::intptr_t Runtime::invoke_window_callback(Cpu &cpu, std::uint64_t target, std::uint64_t window,
                                              std::uint32_t message, std::uint64_t word_parameter,
                                              std::int64_t long_parameter,
                                              std::uint64_t subclass_id,
                                              std::uint64_t reference_data, bool subclass,
                                              std::uint32_t &exit_code, bool &exited) {
    static constexpr std::uint32_t notable_messages[] = {
        WM_CREATE,     WM_NCCREATE, WM_DESTROY, WM_NCDESTROY,  WM_CLOSE,         WM_COMMAND,
        WM_SYSCOMMAND, WM_QUIT,     WM_SIZE,    WM_SHOWWINDOW, WM_INITMENUPOPUP, WM_TIMER,
    };
    if (log::enabled(log::Level::Api) &&
        std::find(std::begin(notable_messages), std::end(notable_messages), message) !=
            std::end(notable_messages)) {
        log::api("window", detail::window_message_name(message) + " window=" + log::hex(window) +
                               " wparam=" + log::hex(word_parameter) +
                               " lparam=" + log::hex(static_cast<std::uint64_t>(long_parameter)));
    }
    std::size_t pointer_size = 0;
    switch (message) {
    case WM_SETTEXT:
        if (long_parameter != 0) {
            pointer_size = (std::wcslen(reinterpret_cast<const wchar_t *>(long_parameter)) + 1) *
                           sizeof(wchar_t);
        }
        break;
    case WM_GETTEXT:
        pointer_size = static_cast<std::size_t>(word_parameter) * sizeof(wchar_t);
        break;
    case WM_GETMINMAXINFO:
        pointer_size = sizeof(MINMAXINFO);
        break;
    case WM_CREATE:
    case WM_NCCREATE:
        pointer_size = sizeof(CREATESTRUCTW);
        break;
    case WM_WINDOWPOSCHANGING:
    case WM_WINDOWPOSCHANGED:
        pointer_size = sizeof(WINDOWPOS);
        break;
    case WM_DRAWITEM:
        // DRAWITEMSTRUCT holds a host HDC and HWND, so it must be copied into guest memory rather
        // than handed over as a raw host pointer. Only the 64-bit layout matches the host one; the
        // 32-bit case is refused instead of silently corrupting the structure.
        if (!guest_is_64_bit_) {
            throw Error("WM_DRAWITEM marshaling is not implemented for 32-bit guests");
        }
        pointer_size = sizeof(DRAWITEMSTRUCT);
        break;
    case WM_NCCALCSIZE:
        pointer_size = word_parameter == 0 ? sizeof(RECT) : sizeof(NCCALCSIZE_PARAMS);
        break;
    case WM_DPICHANGED:
    case WM_SIZING:
    case WM_MOVING:
        pointer_size = sizeof(RECT);
        break;
    case WM_STYLECHANGING:
    case WM_STYLECHANGED:
        pointer_size = sizeof(STYLESTRUCT);
        break;
    default:
        break;
    }
    auto guest_long_parameter = static_cast<std::uint64_t>(long_parameter);
    std::uint64_t scratch = 0;
    bool copy_back_raw = false;
    if (pointer_size != 0 && long_parameter != 0) {
        if (callback_depth_ >= 16 || pointer_size > 0x1000) {
            throw Error("window callback scratch space exhausted");
        }
        scratch = detail::environment_base + 0x10000 + callback_depth_ * 0x1000;
        guest_long_parameter = scratch;
        if (message == WM_CREATE || message == WM_NCCREATE) {
            const auto *native = reinterpret_cast<const CREATESTRUCTW *>(long_parameter);
            const auto write_pointer = [&](std::uint32_t offset32, std::uint32_t offset64,
                                           std::uint64_t value) {
                if (guest_is_64_bit_) {
                    cpu.memory().write64(scratch + offset64, value);
                } else {
                    cpu.memory().write32(scratch + offset32, static_cast<std::uint32_t>(value));
                }
            };
            const auto marshal_string = [&](const wchar_t *value, std::uint64_t address) {
                if (value == nullptr || reinterpret_cast<std::uintptr_t>(value) <= 0xffff) {
                    return static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(value));
                }
                const std::wstring text(value);
                if ((text.size() + 1) * 2 > 0x300) {
                    throw Error("window callback string exceeds scratch space");
                }
                for (std::size_t index = 0; index <= text.size(); ++index) {
                    cpu.memory().write16(address + index * 2,
                                         static_cast<std::uint16_t>(text[index]));
                }
                return address;
            };
            cpu.memory().write(scratch, std::vector<std::uint8_t>(guest_is_64_bit_ ? 80U : 48U));
            write_pointer(0, 0, reinterpret_cast<std::uint64_t>(native->lpCreateParams));
            write_pointer(4, 8, guest_image_base_);
            write_pointer(8, 16, reinterpret_cast<std::uint64_t>(native->hMenu));
            write_pointer(12, 24, reinterpret_cast<std::uint64_t>(native->hwndParent));
            const auto integer_offset = guest_is_64_bit_ ? 32U : 16U;
            cpu.memory().write32(scratch + integer_offset, static_cast<std::uint32_t>(native->cy));
            cpu.memory().write32(scratch + integer_offset + 4,
                                 static_cast<std::uint32_t>(native->cx));
            cpu.memory().write32(scratch + integer_offset + 8,
                                 static_cast<std::uint32_t>(native->y));
            cpu.memory().write32(scratch + integer_offset + 12,
                                 static_cast<std::uint32_t>(native->x));
            cpu.memory().write32(scratch + integer_offset + 16, native->style);
            write_pointer(36, 56, marshal_string(native->lpszName, scratch + 0x200));
            write_pointer(40, 64, marshal_string(native->lpszClass, scratch + 0x600));
            cpu.memory().write32(scratch + (guest_is_64_bit_ ? 72U : 44U), native->dwExStyle);
        } else if (!guest_is_64_bit_ &&
                   (message == WM_WINDOWPOSCHANGING || message == WM_WINDOWPOSCHANGED)) {
            const auto *native = reinterpret_cast<const WINDOWPOS *>(long_parameter);
            cpu.memory().write32(scratch, static_cast<std::uint32_t>(
                                              reinterpret_cast<std::uintptr_t>(native->hwnd)));
            cpu.memory().write32(scratch + 4,
                                 static_cast<std::uint32_t>(
                                     reinterpret_cast<std::uintptr_t>(native->hwndInsertAfter)));
            cpu.memory().write32(scratch + 8, static_cast<std::uint32_t>(native->x));
            cpu.memory().write32(scratch + 12, static_cast<std::uint32_t>(native->y));
            cpu.memory().write32(scratch + 16, static_cast<std::uint32_t>(native->cx));
            cpu.memory().write32(scratch + 20, static_cast<std::uint32_t>(native->cy));
            cpu.memory().write32(scratch + 24, native->flags);
        } else {
            cpu.memory().write(
                scratch, std::span<const std::uint8_t>(
                             reinterpret_cast<const std::uint8_t *>(long_parameter), pointer_size));
            copy_back_raw = message != WM_SETTEXT;
        }
        callback_long_parameters_[scratch] = long_parameter;
    }
    ++callback_depth_;
    std::uint64_t result = 0;
    try {
        if (subclass) {
            const std::array<std::uint64_t, 6> arguments{
                window, message, word_parameter, guest_long_parameter, subclass_id, reference_data};
            result = invoke_guest(cpu, target, std::span<const std::uint64_t>(arguments), exit_code,
                                  exited);
        } else {
            result = invoke_guest(
                cpu, target,
                std::array<std::uint64_t, 4>{window, message, word_parameter, guest_long_parameter},
                exit_code, exited);
        }
    } catch (...) {
        if (scratch != 0) {
            callback_long_parameters_.erase(scratch);
        }
        --callback_depth_;
        throw;
    }
    --callback_depth_;
    if (scratch != 0) {
        callback_long_parameters_.erase(scratch);
    }
    if (scratch != 0 && !guest_is_64_bit_ &&
        (message == WM_WINDOWPOSCHANGING || message == WM_WINDOWPOSCHANGED)) {
        auto *native = reinterpret_cast<WINDOWPOS *>(long_parameter);
        native->hwnd = reinterpret_cast<HWND>(cpu.memory().read32(scratch));
        native->hwndInsertAfter = reinterpret_cast<HWND>(cpu.memory().read32(scratch + 4));
        native->x = static_cast<int>(cpu.memory().read32(scratch + 8));
        native->y = static_cast<int>(cpu.memory().read32(scratch + 12));
        native->cx = static_cast<int>(cpu.memory().read32(scratch + 16));
        native->cy = static_cast<int>(cpu.memory().read32(scratch + 20));
        native->flags = cpu.memory().read32(scratch + 24);
    } else if (scratch != 0 && copy_back_raw) {
        const auto bytes = cpu.memory().read(scratch, pointer_size);
        std::memcpy(reinterpret_cast<void *>(long_parameter), bytes.data(), bytes.size());
    }
    return static_cast<std::intptr_t>(result);
}

} // namespace winemu
