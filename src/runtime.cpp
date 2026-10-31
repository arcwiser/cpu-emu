#include "winemu/runtime.hpp"

#include "winemu/error.hpp"
#include "winemu/log.hpp"

#include <algorithm>
#include <cctype>
#include <cstring>
#include <exception>
#include <iostream>
#include <limits>
#include <ostream>
#include <sstream>
#include <unordered_set>

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>

extern "C" __declspec(dllimport) wchar_t **__stdcall CommandLineToArgvW(const wchar_t *, int *);
extern "C" __declspec(dllimport) DWORD __stdcall
GetSecurityInfo(HANDLE, DWORD, DWORD, void **, void **, void **, void **, void **);

namespace winemu {

namespace {

constexpr std::uint64_t return_thunk = 0xffff'0000'0000'0000ULL;
constexpr std::uint64_t callback_return = 0xffff'0000'0000'0080ULL;
constexpr std::uint64_t stack_top = 0x0000'0000'7000'0000ULL;
constexpr std::uint64_t minimum_stack_size = 1024 * 1024;
constexpr std::uint64_t environment_base = 0x0000'0005'0000'0000ULL;
constexpr std::uint64_t environment_size = 0x0002'0000ULL;
constexpr std::uint64_t tls_base = 0x0000'0005'0002'0000ULL;
constexpr std::uint64_t tls_size = 0x0002'0000ULL;
constexpr std::uint64_t teb_base = environment_base + 0xe000;
constexpr std::uint64_t peb_base = environment_base + 0xf000;
constexpr std::uint64_t crt_commode = environment_base + 0x1000;
constexpr std::uint64_t crt_errno = environment_base + 0x1008;
constexpr std::uint64_t command_line_address = environment_base + 0x2000;
constexpr std::uint64_t winmain_command_line_address = environment_base + 0x3000;

thread_local Runtime *active_runtime = nullptr;
thread_local Cpu *active_cpu = nullptr;
thread_local std::uint32_t *active_exit_code = nullptr;
thread_local bool *active_exited = nullptr;
thread_local std::exception_ptr callback_exception;

std::string lowercase(std::string value) {
    std::transform(value.begin(), value.end(), value.begin(), [](unsigned char character) {
        return static_cast<char>(std::tolower(character));
    });
    return value;
}

std::uint8_t permissions_from_page_protection(std::uint32_t protection) {
    switch (protection & 0xff) {
    case PAGE_NOACCESS:
        return 0;
    case PAGE_READONLY:
        return Read;
    case PAGE_READWRITE:
    case PAGE_WRITECOPY:
        return Read | Write;
    case PAGE_EXECUTE:
        return Execute;
    case PAGE_EXECUTE_READ:
        return Read | Execute;
    case PAGE_EXECUTE_READWRITE:
    case PAGE_EXECUTE_WRITECOPY:
        return Read | Write | Execute;
    default:
        return 0;
    }
}

std::uint32_t page_protection_from_permissions(std::uint8_t permissions) {
    if ((permissions & Execute) != 0) {
        return (permissions & Write) != 0 ? PAGE_EXECUTE_READWRITE : PAGE_EXECUTE_READ;
    }
    if ((permissions & Write) != 0) {
        return PAGE_READWRITE;
    }
    return (permissions & Read) != 0 ? PAGE_READONLY : PAGE_NOACCESS;
}

std::string narrow_string(const std::wstring &value) {
    std::string result;
    result.reserve(value.size());
    for (const wchar_t character : value) {
        result.push_back(character >= 0 && character < 0x80 ? static_cast<char>(character) : '?');
    }
    return result;
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

std::string cpu_state_dump(const Cpu &cpu) {
    static constexpr const char *register_names[16] = {"rax", "rcx", "rdx", "rbx", "rsp", "rbp",
                                                       "rsi", "rdi", "r8",  "r9",  "r10", "r11",
                                                       "r12", "r13", "r14", "r15"};
    std::ostringstream stream;
    for (std::size_t index = 0; index < 16; ++index) {
        stream << register_names[index] << '=' << log::hex(cpu.reg(static_cast<Register>(index)))
               << ((index % 4) == 3 ? '\n' : ' ');
    }
    stream << "rip history:";
    for (const auto address : cpu.recent_instructions()) {
        stream << ' ' << log::hex(address);
    }
    return stream.str();
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

} // namespace

Runtime::Runtime(std::ostream &output) : output_(output) {
    thunks_.emplace(return_thunk, Api::ProcessReturn);
}

Runtime::~Runtime() {
    if (resource_module_ != nullptr) {
        FreeLibrary(static_cast<HMODULE>(resource_module_));
    }
}

std::uint64_t Runtime::allocate_data_import(const std::string &module, const std::string &name) {
    // CRT variables are data exports: the guest reads and writes the value at the address
    // in its import table, so each one needs a real mapped slot rather than a code thunk.
    constexpr std::uint64_t slot_size = 0x400;
    constexpr std::uint64_t first_slot = environment_base + 0x4000;
    if (data_import_next_ == 0) {
        data_import_next_ = first_slot;
    }
    if (data_import_next_ + slot_size > teb_base) {
        throw Error("CRT data import space exhausted at " + module + "!" + name);
    }
    const auto address = data_import_next_;
    data_import_next_ += slot_size;
    data_import_slots_.emplace(name, address);
    log::trace("imports", module + "!" + name + " -> data slot " + log::hex(address));
    return address;
}

std::uint64_t Runtime::resolve_import(const std::string &module, const std::string &name) {
    static const std::unordered_set<std::string> data_imports{
        "_fmode",    "_commode",  "_wcmdln",   "_acmdln", "_environ",
        "_wenviron", "_winmajor", "_winminor", "_osver",  "_winver",
    };
    if (data_imports.contains(name)) {
        return allocate_data_import(module, name);
    }
    const auto normalized_module = lowercase(module);
    const bool kernel_module = normalized_module == "kernel32.dll" ||
                               normalized_module == "kernelbase.dll" ||
                               normalized_module.starts_with("api-ms-win-core-");
    Api api;
    if (kernel_module && name == "ExitProcess") {
        api = Api::ExitProcess;
    } else if (kernel_module && name == "GetStdHandle") {
        api = Api::GetStdHandle;
    } else if (kernel_module && name == "WriteFile") {
        api = Api::WriteFile;
    } else if (kernel_module && name == "GetLastError") {
        api = Api::GetLastError;
    } else if (kernel_module && name == "SetLastError") {
        api = Api::SetLastError;
    } else if (kernel_module && name == "OutputDebugStringA") {
        api = Api::OutputDebugStringA;
    } else if (name == "_initterm") {
        api = Api::InitTerm;
    } else if (name == "_initterm_e") {
        api = Api::InitTermE;
    } else if (name == "_register_thread_local_exe_atexit_callback" || name == "_crt_atexit" ||
               name == "_o__crt_atexit") {
        // Exit callbacks must stay guest-side; forwarding them would place guest code
        // pointers on the host's atexit list.
        api = Api::ReturnZero;
    } else if (name == "_initialize_onexit_table") {
        api = Api::InitializeOnexitTable;
    } else if (name == "_register_onexit_function") {
        api = Api::RegisterOnexitFunction;
    } else if (name == "_execute_onexit_table") {
        api = Api::ExecuteOnexitTable;
    } else if (name == "_o___p__commode" || name == "__p__commode") {
        api = Api::CommodePointer;
    } else if (name == "_o__errno" || name == "_errno") {
        api = Api::ErrnoPointer;
    } else if (name == "SetUnhandledExceptionFilter") {
        api = Api::SetUnhandledExceptionFilter;
    } else if (name == "GetCommandLineW") {
        api = Api::GetCommandLineW;
    } else if (name == "CommandLineToArgvW") {
        api = Api::CommandLineToArgvW;
    } else if (name == "GetSecurityInfo") {
        api = Api::GetSecurityInfo;
    } else if (name == "MapViewOfFile") {
        api = Api::MapViewOfFile;
    } else if (name == "GetEnvironmentStringsW") {
        api = Api::EnvironmentStringsW;
    } else if (name == "GetEnvironmentStringsA") {
        api = Api::EnvironmentStringsA;
    } else if (name == "FreeEnvironmentStringsW" || name == "FreeEnvironmentStringsA") {
        api = Api::ReturnOne;
    } else if (name == "_o__get_wide_winmain_command_line") {
        api = Api::WinMainCommandLine;
    } else if (name == "EventRegister") {
        api = Api::EventRegister;
    } else if (name == "EventUnregister" || name == "EventWriteTransfer" ||
               name == "EventSetInformation") {
        api = Api::ReturnZero;
    } else if (name == "VirtualAlloc") {
        api = Api::VirtualAlloc;
    } else if (name == "VirtualFree") {
        api = Api::VirtualFree;
    } else if (name == "VirtualProtect") {
        api = Api::VirtualProtect;
    } else if (name == "VirtualQuery") {
        api = Api::VirtualQuery;
    } else if (name == "TlsAlloc") {
        api = Api::TlsAlloc;
    } else if (name == "TlsFree") {
        api = Api::TlsFree;
    } else if (name == "TlsGetValue") {
        api = Api::TlsGetValue;
    } else if (name == "TlsSetValue") {
        api = Api::TlsSetValue;
    } else if (name == "FlsAlloc") {
        api = Api::FlsAlloc;
    } else if (name == "FlsFree") {
        api = Api::FlsFree;
    } else if (name == "FlsGetValue") {
        api = Api::FlsGetValue;
    } else if (name == "FlsSetValue") {
        api = Api::FlsSetValue;
    } else if (name == "InitOnceExecuteOnce") {
        api = Api::InitOnceExecuteOnce;
    } else if (name == "_o_malloc" || name == "malloc" || name == "CoTaskMemAlloc") {
        api = Api::AllocateRcx;
    } else if (name == "LocalAlloc" || name == "GlobalAlloc") {
        api = Api::AllocateRdx;
    } else if (name == "HeapAlloc") {
        api = Api::AllocateR8;
    } else if (name == "LocalReAlloc") {
        api = Api::Reallocate;
    } else if (name == "_o_free" || name == "free" || name == "CoTaskMemFree" ||
               name == "LocalFree" || name == "GlobalFree") {
        api = Api::FreeRcx;
    } else if (name == "HeapFree") {
        api = Api::HeapFree;
    } else if (name == "LocalSize") {
        api = Api::AllocationSize;
    } else if (name == "LocalLock" || name == "GlobalLock") {
        api = Api::IdentityRcx;
    } else if (name == "LocalUnlock" || name == "GlobalUnlock") {
        api = Api::ReturnZero;
    } else if (name == "GetProcessHeap") {
        api = Api::ProcessHeap;
    } else if (name == "HeapSetInformation") {
        api = Api::ReturnOne;
    } else if (name == "_o_exit" || name == "_o__exit" || name == "_exit" || name == "exit" ||
               name == "_amsg_exit") {
        api = Api::ExitProcess;
    } else if (name == "_o__cexit" || name == "_o__c_exit" || name == "_c_exit") {
        api = Api::ReturnZero;
    } else if (name == "TerminateProcess") {
        api = Api::TerminateProcess;
    } else if (name == "GetModuleHandleW" || name == "GetModuleHandleA") {
        api = Api::GuestModuleHandle;
    } else if (name == "GetModuleHandleExW") {
        api = Api::GetModuleHandleExW;
    } else if (name == "GetModuleFileNameW") {
        api = Api::GetModuleFileNameW;
    } else if (name == "GetModuleFileNameA") {
        api = Api::GetModuleFileNameA;
    } else if (name == "GetProcAddress") {
        api = Api::GetProcAddress;
    } else if (name == "LoadStringW") {
        api = Api::LoadStringW;
    } else if (name == "LoadCursorW") {
        api = Api::LoadCursorW;
    } else if (name == "LoadIconW") {
        api = Api::LoadIconW;
    } else if (name == "LoadImageW") {
        api = Api::LoadImageW;
    } else if (name == "LoadAcceleratorsW") {
        api = Api::LoadAcceleratorsW;
    } else if (name == "RegisterClassExW") {
        api = Api::RegisterClassExW;
    } else if (name == "CreateWindowExW") {
        api = Api::CreateWindowExW;
    } else if (name == "ResolveDelayLoadedAPI") {
        api = Api::ResolveDelayLoadedAPI;
    } else if (name == "SHGetKnownFolderPath") {
        api = Api::SHGetKnownFolderPath;
    } else if (name == "CoCreateInstance") {
        api = Api::CoCreateInstance;
    } else if (name == "RoGetActivationFactory") {
        api = Api::RoGetActivationFactory;
    } else if (name == "CreateThreadpoolTimer") {
        api = Api::CreateThreadpoolTimer;
    } else if (name == "SetThreadpoolTimer" || name == "WaitForThreadpoolTimerCallbacks" ||
               name == "CloseThreadpoolTimer") {
        api = Api::ReturnZero;
    } else if (name == "SetWinEventHook" || name == "UnhookWinEvent") {
        api = Api::ReturnOne;
    } else if (name == "_beginthreadex" || name == "_o__beginthreadex" || name == "_beginthread" ||
               name == "_o__beginthread") {
        // Guest callbacks cannot run on a native CRT-created thread. Report creation failure until
        // the emulator has a scheduler that can give each guest thread its own CPU state.
        api = Api::ReturnZero;
    } else if (name == "CreateThread" || name == "CreateRemoteThread" ||
               name == "CreateRemoteThreadEx" || name == "QueueUserWorkItem" ||
               name == "RegisterWaitForSingleObject" || name == "CreateThreadpoolWork" ||
               name == "CreateThreadpoolWait" || name == "CreateThreadpoolIo") {
        // These APIs retain a callback address and may invoke it on another native thread.
        // Passing guest code to the host would bypass the interpreter and fault (or worse).
        api = Api::ReturnZero;
    } else if (name == "SubmitThreadpoolWork" || name == "SetThreadpoolWait" ||
               name == "CloseThreadpoolWork" || name == "CloseThreadpoolWait" ||
               name == "CloseThreadpoolIo") {
        api = Api::ReturnZero;
    } else if (name == "CreateProcessW" || name == "CreateProcessA" ||
               name == "CreateProcessAsUserW" || name == "CreateProcessAsUserA") {
        // A child must be loaded as another guest process. Native forwarding here would silently
        // escape emulation, so fail until multi-process guest scheduling is implemented.
        api = Api::ReturnZero;
    } else if (name == "AddVectoredExceptionHandler" || name == "AddVectoredContinueHandler") {
        api = Api::ReturnZero;
    } else if (name == "RemoveVectoredExceptionHandler" ||
               name == "RemoveVectoredContinueHandler") {
        api = Api::ReturnOne;
    } else {
        static const std::unordered_set<std::string> unsafe_calls{
            "SetUnhandledExceptionFilter",
            "UnhandledExceptionFilter",
            "RaiseException",
            "_CxxThrowException",
            "__CxxFrameHandler3",
            "__C_specific_handler",
            "RegisterClassExW",
            "DialogBoxParamW",
            "CreateDialogParamW",
            "CreateDialogIndirectParamW",
            "EnumFontsW",
            "SetAbortProc",
            "GetProcAddress",
            "ResolveDelayLoadedAPI",
        };
        void *function = nullptr;
        if (!unsafe_calls.contains(name)) {
            if (const auto library = LoadLibraryA(module.c_str()); library != nullptr) {
                if (name.starts_with('#')) {
                    const auto ordinal = static_cast<WORD>(std::stoul(name.substr(1)));
                    function = reinterpret_cast<void *>(
                        GetProcAddress(library, MAKEINTRESOURCEA(ordinal)));
                } else {
                    function = reinterpret_cast<void *>(GetProcAddress(library, name.c_str()));
                }
            }
        }
        api = function == nullptr ? Api::Unsupported : Api::Native;
        if (function != nullptr) {
            native_functions_.emplace(next_thunk_, function);
        }
    }
    const auto address = next_thunk_;
    next_thunk_ += 0x100;
    thunks_.emplace(address, api);
    thunk_names_.emplace(address, module + "!" + name);
    if (log::enabled(log::Level::Trace)) {
        log::trace("imports",
                   module + "!" + name + " -> " + log::hex(address) +
                       (api == Api::Unsupported ? " (unimplemented; calling it will stop the guest)"
                                                : ""));
    }
    return address;
}

bool Runtime::dispatch(Cpu &cpu, std::uint32_t &exit_code, bool &exited) {
    const auto found = thunks_.find(cpu.rip());
    if (found == thunks_.end()) {
        return false;
    }
    const auto thunk_name_iterator = thunk_names_.find(cpu.rip());
    const auto thunk_name = thunk_name_iterator == thunk_names_.end()
                                ? std::string("process return")
                                : thunk_name_iterator->second;
    if (log::enabled(log::Level::Api)) {
        log::api("api", thunk_name + "(rcx=" + log::hex(cpu.reg(Rcx)) +
                            ", rdx=" + log::hex(cpu.reg(Rdx)) + ", r8=" + log::hex(cpu.reg(R8)) +
                            ", r9=" + log::hex(cpu.reg(R9)) + ")");
    }
    const auto finish_call = [&] { cpu.set_rip(cpu.pop64()); };
    const auto allocate = [&](std::uint64_t requested_size) {
        const auto size = std::max<std::uint64_t>(requested_size, 1);
        const auto mapped_size = (size + 0xffff) & ~0xffffULL;
        const auto address = heap_next_;
        heap_next_ += mapped_size;
        cpu.memory().map(address, mapped_size, Read | Write, "guest heap");
        heap_sizes_.emplace(address, size);
        return address;
    };
    switch (found->second) {
    case Api::ProcessReturn:
        exit_code = static_cast<std::uint32_t>(cpu.reg(Rax));
        exited = true;
        break;
    case Api::ExitProcess:
        exit_code = static_cast<std::uint32_t>(cpu.reg(Rcx));
        exited = true;
        break;
    case Api::TerminateProcess:
        exit_code = static_cast<std::uint32_t>(cpu.reg(Rdx));
        exited = true;
        break;
    case Api::GetStdHandle: {
        const auto requested = static_cast<std::int32_t>(cpu.reg(Rcx));
        std::uint64_t handle = 0;
        if (requested == -11) {
            handle = 0x101;
        } else if (requested == -12) {
            handle = 0x102;
        } else if (requested == -10) {
            handle = 0x100;
        } else {
            last_error_ = 6;
            handle = std::numeric_limits<std::uint64_t>::max();
        }
        cpu.set_reg(Rax, handle);
        finish_call();
        break;
    }
    case Api::WriteFile: {
        const auto handle = cpu.reg(Rcx);
        const auto buffer = cpu.reg(Rdx);
        const auto size = static_cast<std::uint32_t>(cpu.reg(R8));
        const auto written_pointer = cpu.reg(R9);
        const auto overlapped = cpu.memory().read64(cpu.reg(Rsp) + 0x28);
        if ((handle != 0x101 && handle != 0x102) || overlapped != 0) {
            last_error_ = handle != 0x101 && handle != 0x102 ? 6 : 87;
            cpu.set_reg(Rax, 0);
        } else {
            const auto bytes = cpu.memory().read(buffer, size);
            output_.write(reinterpret_cast<const char *>(bytes.data()),
                          static_cast<std::streamsize>(bytes.size()));
            output_.flush();
            if (written_pointer != 0) {
                cpu.memory().write32(written_pointer, size);
            }
            cpu.set_reg(Rax, 1);
        }
        finish_call();
        break;
    }
    case Api::GetLastError:
        cpu.set_reg(Rax, last_error_);
        finish_call();
        break;
    case Api::SetLastError:
        last_error_ = static_cast<std::uint32_t>(cpu.reg(Rcx));
        finish_call();
        break;
    case Api::OutputDebugStringA:
        log::info("guest", "OutputDebugStringA: " + cpu.memory().read_c_string(cpu.reg(Rcx)));
        finish_call();
        break;
    case Api::InitTerm:
    case Api::InitTermE: {
        const auto first = cpu.reg(Rcx);
        const auto last = cpu.reg(Rdx);
        std::uint32_t result = 0;
        if (last < first || (last - first) % 8 != 0) {
            throw Error("invalid CRT initializer range");
        }
        for (auto cursor = first; cursor < last && !exited; cursor += 8) {
            const auto target = cpu.memory().read64(cursor);
            if (target != 0) {
                result = static_cast<std::uint32_t>(
                    invoke_guest(cpu, target, {0, 0, 0, 0}, exit_code, exited));
                if (found->second == Api::InitTermE && result != 0) {
                    break;
                }
            }
        }
        cpu.set_reg(Rax, found->second == Api::InitTermE ? result : 0);
        if (!exited) {
            finish_call();
        }
        break;
    }
    case Api::ReturnZero:
        cpu.set_reg(Rax, 0);
        finish_call();
        break;
    case Api::InitializeOnexitTable:
        // The onexit table is {_first, _last, _end}; reset it in guest memory so later
        // registrations never touch host CRT state.
        for (unsigned index = 0; index < 3; ++index) {
            cpu.memory().write64(cpu.reg(Rcx) + index * 8, 0);
        }
        cpu.set_reg(Rax, 0);
        finish_call();
        break;
    case Api::RegisterOnexitFunction: {
        // Keep exit callbacks guest-side: forwarding this natively would place guest code
        // pointers on the host's atexit list, which the host would then execute on shutdown.
        const auto table = cpu.reg(Rcx);
        const auto function = cpu.reg(Rdx);
        auto first = cpu.memory().read64(table);
        const auto last = cpu.memory().read64(table + 8);
        auto end = cpu.memory().read64(table + 16);
        if (end == 0 || last >= end) {
            const auto entry_count = (first == 0 || end == 0) ? 0 : (last - first) / 8;
            constexpr std::uint64_t capacity = 32;
            const auto new_first = allocate(capacity * 8);
            if (entry_count != 0) {
                cpu.memory().write(new_first, cpu.memory().read(first, entry_count * 8));
            }
            first = new_first;
            end = new_first + capacity * 8;
            cpu.memory().write64(table, first);
            cpu.memory().write64(table + 16, end);
        }
        cpu.memory().write64(last, function);
        cpu.memory().write64(table + 8, last + 8);
        cpu.set_reg(Rax, 0);
        finish_call();
        break;
    }
    case Api::ExecuteOnexitTable: {
        const auto table = cpu.reg(Rcx);
        const auto first = cpu.memory().read64(table);
        const auto last = cpu.memory().read64(table + 8);
        for (auto cursor = first; cursor < last && !exited; cursor += 8) {
            const auto target = cpu.memory().read64(cursor);
            if (target != 0 && target != 0xffffffffffffffffULL) {
                static_cast<void>(invoke_guest(cpu, target, {0, 0, 0, 0}, exit_code, exited));
            }
        }
        cpu.set_reg(Rax, 0);
        if (!exited) {
            finish_call();
        }
        break;
    }
    case Api::CommodePointer:
        cpu.set_reg(Rax, crt_commode);
        finish_call();
        break;
    case Api::ErrnoPointer:
        cpu.set_reg(Rax, crt_errno);
        finish_call();
        break;
    case Api::SetUnhandledExceptionFilter: {
        const auto previous = guest_exception_filter_;
        guest_exception_filter_ = cpu.reg(Rcx);
        cpu.set_reg(Rax, previous);
        finish_call();
        break;
    }
    case Api::GetCommandLineW:
        cpu.set_reg(Rax, guest_command_line_);
        finish_call();
        break;
    case Api::CommandLineToArgvW: {
        int argument_count = 0;
        auto **const native_arguments =
            ::CommandLineToArgvW(reinterpret_cast<const wchar_t *>(cpu.reg(Rcx)), &argument_count);
        if (native_arguments == nullptr) {
            last_error_ = ::GetLastError();
            cpu.set_reg(Rax, 0);
        } else {
            std::size_t strings_size = 0;
            for (int index = 0; index < argument_count; ++index) {
                strings_size += (std::wcslen(native_arguments[index]) + 1) * sizeof(wchar_t);
            }
            const auto pointers_size =
                static_cast<std::size_t>(argument_count) * sizeof(std::uint64_t);
            const auto arguments = allocate(pointers_size + strings_size);
            auto string_address = arguments + pointers_size;
            for (int index = 0; index < argument_count; ++index) {
                const auto byte_size = (std::wcslen(native_arguments[index]) + 1) * sizeof(wchar_t);
                cpu.memory().write64(arguments + static_cast<std::uint64_t>(index) * 8,
                                     string_address);
                cpu.memory().write(string_address, std::span<const std::uint8_t>(
                                                       reinterpret_cast<const std::uint8_t *>(
                                                           native_arguments[index]),
                                                       byte_size));
                string_address += byte_size;
            }
            if (cpu.reg(Rdx) != 0) {
                cpu.memory().write32(cpu.reg(Rdx), static_cast<std::uint32_t>(argument_count));
            }
            ::LocalFree(native_arguments);
            cpu.set_reg(Rax, arguments);
        }
        finish_call();
        break;
    }
    case Api::GetSecurityInfo: {
        const auto owner_output = cpu.reg(R9);
        const auto group_output = cpu.memory().read64(cpu.reg(Rsp) + 0x28);
        const auto dacl_output = cpu.memory().read64(cpu.reg(Rsp) + 0x30);
        const auto sacl_output = cpu.memory().read64(cpu.reg(Rsp) + 0x38);
        const auto descriptor_output = cpu.memory().read64(cpu.reg(Rsp) + 0x40);
        void *native_descriptor = nullptr;
        const auto result =
            ::GetSecurityInfo(reinterpret_cast<HANDLE>(cpu.reg(Rcx)),
                              static_cast<DWORD>(cpu.reg(Rdx)), static_cast<DWORD>(cpu.reg(R8)),
                              nullptr, nullptr, nullptr, nullptr, &native_descriptor);
        if (owner_output != 0) {
            cpu.memory().write64(owner_output, 0);
        }
        if (group_output != 0) {
            cpu.memory().write64(group_output, 0);
        }
        if (dacl_output != 0) {
            cpu.memory().write64(dacl_output, 0);
        }
        if (sacl_output != 0) {
            cpu.memory().write64(sacl_output, 0);
        }
        if (result == ERROR_SUCCESS && native_descriptor != nullptr && descriptor_output != 0) {
            const auto size = ::GetSecurityDescriptorLength(native_descriptor);
            const auto guest_descriptor = allocate(size);
            cpu.memory().write(
                guest_descriptor,
                std::span<const std::uint8_t>(
                    reinterpret_cast<const std::uint8_t *>(native_descriptor), size));
            cpu.memory().write64(descriptor_output, guest_descriptor);
        } else if (descriptor_output != 0) {
            cpu.memory().write64(descriptor_output, 0);
        }
        if (native_descriptor != nullptr) {
            ::LocalFree(native_descriptor);
        }
        cpu.set_reg(Rax, result);
        finish_call();
        break;
    }
    case Api::MapViewOfFile: {
        const auto requested_size = cpu.memory().read64(cpu.reg(Rsp) + 0x28);
        auto *const native_view = ::MapViewOfFile(
            reinterpret_cast<HANDLE>(cpu.reg(Rcx)), static_cast<DWORD>(cpu.reg(Rdx)),
            static_cast<DWORD>(cpu.reg(R8)), static_cast<DWORD>(cpu.reg(R9)), requested_size);
        if (native_view == nullptr) {
            last_error_ = ::GetLastError();
            cpu.set_reg(Rax, 0);
        } else {
            std::uint64_t size = requested_size;
            if (size == 0) {
                MEMORY_BASIC_INFORMATION information{};
                if (::VirtualQuery(native_view, &information, sizeof(information)) == 0) {
                    ::UnmapViewOfFile(native_view);
                    last_error_ = ::GetLastError();
                    cpu.set_reg(Rax, 0);
                    finish_call();
                    break;
                }
                size = information.RegionSize;
            }
            const auto guest_view = allocate(size);
            cpu.memory().write(guest_view, std::span<const std::uint8_t>(
                                               reinterpret_cast<const std::uint8_t *>(native_view),
                                               static_cast<std::size_t>(size)));
            ::UnmapViewOfFile(native_view);
            cpu.set_reg(Rax, guest_view);
        }
        finish_call();
        break;
    }
    case Api::WinMainCommandLine:
        cpu.set_reg(Rax, guest_winmain_command_line_);
        finish_call();
        break;
    case Api::EnvironmentStringsW: {
        auto *const native = ::GetEnvironmentStringsW();
        if (native == nullptr) {
            last_error_ = ::GetLastError();
            cpu.set_reg(Rax, 0);
        } else {
            std::size_t length = 0;
            while (length < 1024 * 1024 &&
                   (native[length] != L'\0' || native[length + 1] != L'\0')) {
                ++length;
            }
            length += 2;
            const auto address = allocate(length * sizeof(wchar_t));
            cpu.memory().write(address, std::span<const std::uint8_t>(
                                            reinterpret_cast<const std::uint8_t *>(native),
                                            length * sizeof(wchar_t)));
            ::FreeEnvironmentStringsW(native);
            cpu.set_reg(Rax, address);
        }
        finish_call();
        break;
    }
    case Api::EnvironmentStringsA: {
        auto *const native = ::GetEnvironmentStringsA();
        if (native == nullptr) {
            last_error_ = ::GetLastError();
            cpu.set_reg(Rax, 0);
        } else {
            std::size_t length = 0;
            while (length < 1024 * 1024 && (native[length] != '\0' || native[length + 1] != '\0')) {
                ++length;
            }
            length += 2;
            const auto address = allocate(length);
            cpu.memory().write(address,
                               std::span<const std::uint8_t>(
                                   reinterpret_cast<const std::uint8_t *>(native), length));
            ::FreeEnvironmentStringsA(native);
            cpu.set_reg(Rax, address);
        }
        finish_call();
        break;
    }
    case Api::EventRegister:
        if (cpu.reg(R9) != 0) {
            cpu.memory().write64(cpu.reg(R9), 1);
        }
        cpu.set_reg(Rax, 0);
        finish_call();
        break;
    case Api::CreateThreadpoolTimer:
        cpu.set_reg(Rax, allocate(8));
        finish_call();
        break;
    case Api::VirtualAlloc: {
        const auto requested = cpu.reg(Rcx);
        const auto requested_size = cpu.reg(Rdx);
        const auto allocation_type = static_cast<std::uint32_t>(cpu.reg(R8));
        const auto protection = static_cast<std::uint32_t>(cpu.reg(R9));
        if (requested_size == 0 || (allocation_type & (MEM_RESERVE | MEM_COMMIT)) == 0) {
            last_error_ = ERROR_INVALID_PARAMETER;
            cpu.set_reg(Rax, 0);
            finish_call();
            break;
        }
        const auto host_protection =
            (allocation_type & MEM_COMMIT) != 0 ? PAGE_READWRITE : PAGE_NOACCESS;
        auto *const result =
            ::VirtualAlloc(reinterpret_cast<void *>(static_cast<std::uintptr_t>(requested)),
                           static_cast<SIZE_T>(requested_size), allocation_type, host_protection);
        if (result == nullptr) {
            last_error_ = ::GetLastError();
            cpu.set_reg(Rax, 0);
            finish_call();
            break;
        }
        const auto address = reinterpret_cast<std::uint64_t>(result);
        try {
            if ((allocation_type & MEM_RESERVE) != 0) {
                MEMORY_BASIC_INFORMATION information{};
                if (::VirtualQuery(result, &information, sizeof(information)) == 0) {
                    throw Error("cannot query new guest virtual allocation");
                }
                cpu.memory().track_allocation(
                    reinterpret_cast<std::uint64_t>(information.AllocationBase),
                    information.RegionSize, "guest VirtualAlloc reservation");
            }
            if ((allocation_type & MEM_COMMIT) != 0) {
                const auto page_base = address & ~0xfffULL;
                const auto page_end = (address + requested_size + 0xfffULL) & ~0xfffULL;
                cpu.memory().commit(page_base, page_end - page_base,
                                    permissions_from_page_protection(protection),
                                    "guest VirtualAlloc commit");
            }
        } catch (...) {
            if ((allocation_type & MEM_RESERVE) != 0) {
                static_cast<void>(cpu.memory().release(address));
            }
            throw;
        }
        cpu.set_reg(Rax, address);
        finish_call();
        break;
    }
    case Api::VirtualFree: {
        const auto address = cpu.reg(Rcx);
        const auto size = cpu.reg(Rdx);
        const auto free_type = static_cast<std::uint32_t>(cpu.reg(R8));
        const bool result = free_type == MEM_RELEASE ? (size == 0 && cpu.memory().release(address))
                                                     : (free_type == MEM_DECOMMIT && size != 0 &&
                                                        cpu.memory().decommit(address, size));
        if (!result) {
            last_error_ = ERROR_INVALID_PARAMETER;
        }
        cpu.set_reg(Rax, result ? 1 : 0);
        finish_call();
        break;
    }
    case Api::VirtualProtect: {
        const auto address = cpu.reg(Rcx);
        const auto size = cpu.reg(Rdx);
        const auto protection = static_cast<std::uint32_t>(cpu.reg(R8));
        const auto old_pointer = cpu.reg(R9);
        std::uint8_t old_permissions = 0;
        DWORD ignored = 0;
        const bool result =
            size != 0 && old_pointer != 0 && cpu.memory().permissions(address, old_permissions) &&
            ::VirtualProtect(reinterpret_cast<void *>(static_cast<std::uintptr_t>(address)),
                             static_cast<SIZE_T>(size), PAGE_READWRITE, &ignored) != FALSE &&
            cpu.memory().protect(address, size, permissions_from_page_protection(protection));
        if (result) {
            cpu.memory().write32(old_pointer, page_protection_from_permissions(old_permissions));
        } else {
            last_error_ = ERROR_INVALID_PARAMETER;
        }
        cpu.set_reg(Rax, result ? 1 : 0);
        finish_call();
        break;
    }
    case Api::VirtualQuery: {
        const auto address = cpu.reg(Rcx);
        const auto output = cpu.reg(Rdx);
        const auto output_size = cpu.reg(R8);
        MEMORY_BASIC_INFORMATION information{};
        VirtualMemoryInfo guest_information{};
        std::size_t result = 0;
        if (output != 0 && output_size >= sizeof(information)) {
            if (cpu.memory().query(address, guest_information)) {
                information.BaseAddress =
                    reinterpret_cast<void *>(static_cast<std::uintptr_t>(guest_information.base));
                information.AllocationBase = reinterpret_cast<void *>(
                    static_cast<std::uintptr_t>(guest_information.allocation_base));
                information.AllocationProtect = PAGE_NOACCESS;
                information.RegionSize = static_cast<SIZE_T>(guest_information.size);
                information.State = guest_information.committed ? MEM_COMMIT : MEM_RESERVE;
                information.Protect =
                    guest_information.committed
                        ? page_protection_from_permissions(guest_information.permissions)
                        : 0;
                information.Type = MEM_PRIVATE;
                result = sizeof(information);
            } else {
                result =
                    ::VirtualQuery(reinterpret_cast<void *>(static_cast<std::uintptr_t>(address)),
                                   &information, sizeof(information));
            }
            if (result != 0) {
                cpu.memory().write(output, std::span<const std::uint8_t>(
                                               reinterpret_cast<const std::uint8_t *>(&information),
                                               sizeof(information)));
            }
        }
        if (result == 0) {
            last_error_ = ERROR_INVALID_PARAMETER;
        }
        cpu.set_reg(Rax, result);
        finish_call();
        break;
    }
    case Api::TlsAlloc: {
        const auto index = next_tls_index_++;
        tls_values_.emplace(index, 0);
        cpu.set_reg(Rax, index);
        finish_call();
        break;
    }
    case Api::FlsAlloc: {
        // The cleanup callback in RCX is a guest address. Keep the slot guest-side so the host
        // never retains or invokes it outside the interpreter.
        const auto index = next_fls_index_++;
        fls_values_.emplace(index, 0);
        cpu.set_reg(Rax, index);
        finish_call();
        break;
    }
    case Api::TlsFree:
    case Api::FlsFree: {
        auto &values = found->second == Api::TlsFree ? tls_values_ : fls_values_;
        const auto erased = values.erase(static_cast<std::uint32_t>(cpu.reg(Rcx))) != 0;
        if (!erased) {
            last_error_ = ERROR_INVALID_PARAMETER;
        }
        cpu.set_reg(Rax, erased ? 1 : 0);
        finish_call();
        break;
    }
    case Api::TlsGetValue:
    case Api::FlsGetValue: {
        auto &values = found->second == Api::TlsGetValue ? tls_values_ : fls_values_;
        const auto value = values.find(static_cast<std::uint32_t>(cpu.reg(Rcx)));
        if (value == values.end()) {
            last_error_ = ERROR_INVALID_PARAMETER;
            cpu.set_reg(Rax, 0);
        } else {
            last_error_ = ERROR_SUCCESS;
            cpu.set_reg(Rax, value->second);
        }
        finish_call();
        break;
    }
    case Api::TlsSetValue:
    case Api::FlsSetValue: {
        auto &values = found->second == Api::TlsSetValue ? tls_values_ : fls_values_;
        const auto value = values.find(static_cast<std::uint32_t>(cpu.reg(Rcx)));
        if (value == values.end()) {
            last_error_ = ERROR_INVALID_PARAMETER;
            cpu.set_reg(Rax, 0);
        } else {
            value->second = cpu.reg(Rdx);
            cpu.set_reg(Rax, 1);
        }
        finish_call();
        break;
    }
    case Api::InitOnceExecuteOnce: {
        const auto once = cpu.reg(Rcx);
        const auto callback = cpu.reg(Rdx);
        const auto parameter = cpu.reg(R8);
        const auto context = cpu.reg(R9);
        bool success = true;
        if (cpu.memory().read64(once) == 0) {
            success = callback != 0 && invoke_guest(cpu, callback, {once, parameter, context, 0},
                                                    exit_code, exited) != 0;
            if (success) {
                cpu.memory().write64(once, 1);
            }
        }
        cpu.set_reg(Rax, success ? 1 : 0);
        if (!exited) {
            finish_call();
        }
        break;
    }
    case Api::AllocateRcx:
        cpu.set_reg(Rax, allocate(cpu.reg(Rcx)));
        finish_call();
        break;
    case Api::AllocateRdx:
        cpu.set_reg(Rax, allocate(cpu.reg(Rdx)));
        finish_call();
        break;
    case Api::AllocateR8:
        cpu.set_reg(Rax, allocate(cpu.reg(R8)));
        finish_call();
        break;
    case Api::Reallocate: {
        const auto old_address = cpu.reg(Rcx);
        const auto new_size = cpu.reg(Rdx);
        const auto new_address = allocate(new_size);
        if (const auto old = heap_sizes_.find(old_address); old != heap_sizes_.end()) {
            const auto copy_size = static_cast<std::size_t>(std::min(old->second, new_size));
            const auto bytes = cpu.memory().read(old_address, copy_size);
            cpu.memory().write(new_address, bytes);
        }
        cpu.set_reg(Rax, new_address);
        finish_call();
        break;
    }
    case Api::FreeRcx:
        cpu.set_reg(Rax, 0);
        finish_call();
        break;
    case Api::HeapFree:
        cpu.set_reg(Rax, 1);
        finish_call();
        break;
    case Api::AllocationSize: {
        const auto allocation = heap_sizes_.find(cpu.reg(Rcx));
        cpu.set_reg(Rax, allocation == heap_sizes_.end() ? 0 : allocation->second);
        finish_call();
        break;
    }
    case Api::IdentityRcx:
        cpu.set_reg(Rax, cpu.reg(Rcx));
        finish_call();
        break;
    case Api::ProcessHeap:
        cpu.set_reg(Rax, 1);
        finish_call();
        break;
    case Api::ReturnOne:
        cpu.set_reg(Rax, 1);
        finish_call();
        break;
    case Api::GuestModuleHandle:
        if (cpu.reg(Rcx) == 0) {
            cpu.set_reg(Rax, guest_image_base_);
        } else if (thunk_names_.at(cpu.rip()).ends_with("GetModuleHandleA")) {
            cpu.set_reg(Rax, reinterpret_cast<std::uint64_t>(
                                 ::GetModuleHandleA(reinterpret_cast<const char *>(cpu.reg(Rcx)))));
        } else {
            cpu.set_reg(Rax, reinterpret_cast<std::uint64_t>(::GetModuleHandleW(
                                 reinterpret_cast<const wchar_t *>(cpu.reg(Rcx)))));
        }
        finish_call();
        break;
    case Api::GetModuleHandleExW:
        if (cpu.reg(R8) != 0) {
            cpu.memory().write64(cpu.reg(R8), guest_image_base_);
        }
        cpu.set_reg(Rax, 1);
        finish_call();
        break;
    case Api::GetModuleFileNameW: {
        const auto path = guest_executable_.wstring();
        const auto capacity = static_cast<std::uint32_t>(cpu.reg(R8));
        const auto count = std::min<std::size_t>(path.size(), capacity == 0 ? 0 : capacity - 1);
        for (std::size_t index = 0; index < count; ++index) {
            cpu.memory().write16(cpu.reg(Rdx) + index * 2, static_cast<std::uint16_t>(path[index]));
        }
        if (capacity != 0) {
            cpu.memory().write16(cpu.reg(Rdx) + count * 2, 0);
        }
        cpu.set_reg(Rax, count);
        finish_call();
        break;
    }
    case Api::GetModuleFileNameA: {
        const auto path = guest_executable_.string();
        const auto capacity = static_cast<std::uint32_t>(cpu.reg(R8));
        const auto count = std::min<std::size_t>(path.size(), capacity == 0 ? 0 : capacity - 1);
        for (std::size_t index = 0; index < count; ++index) {
            cpu.memory().write8(cpu.reg(Rdx) + index, static_cast<std::uint8_t>(path[index]));
        }
        if (capacity != 0) {
            cpu.memory().write8(cpu.reg(Rdx) + count, 0);
        }
        cpu.set_reg(Rax, count);
        finish_call();
        break;
    }
    case Api::GetProcAddress: {
        const auto module = reinterpret_cast<HMODULE>(cpu.reg(Rcx));
        std::string import_name;
        if (cpu.reg(Rdx) <= 0xffff) {
            import_name = "#" + std::to_string(cpu.reg(Rdx));
        } else {
            import_name = cpu.memory().read_c_string(cpu.reg(Rdx));
        }
        std::array<char, 32768> module_path{};
        const auto length = ::GetModuleFileNameA(module, module_path.data(), module_path.size());
        if (length == 0) {
            cpu.set_reg(Rax, 0);
        } else {
            const auto module_name =
                std::filesystem::path(std::string(module_path.data(), module_path.data() + length))
                    .filename()
                    .string();
            cpu.set_reg(Rax, resolve_import(module_name, import_name));
        }
        finish_call();
        break;
    }
    case Api::LoadStringW: {
        const auto result =
            ::LoadStringW(static_cast<HMODULE>(resource_module_), static_cast<UINT>(cpu.reg(Rdx)),
                          reinterpret_cast<wchar_t *>(static_cast<std::uintptr_t>(cpu.reg(R8))),
                          static_cast<int>(cpu.reg(R9)));
        cpu.set_reg(Rax, static_cast<std::uint32_t>(result));
        finish_call();
        break;
    }
    case Api::LoadCursorW: {
        const auto module = cpu.reg(Rcx) == guest_image_base_
                                ? static_cast<HINSTANCE>(resource_module_)
                                : reinterpret_cast<HINSTANCE>(cpu.reg(Rcx));
        cpu.set_reg(Rax, reinterpret_cast<std::uint64_t>(
                             ::LoadCursorW(module, reinterpret_cast<LPCWSTR>(cpu.reg(Rdx)))));
        finish_call();
        break;
    }
    case Api::LoadIconW: {
        const auto module = cpu.reg(Rcx) == guest_image_base_
                                ? static_cast<HINSTANCE>(resource_module_)
                                : reinterpret_cast<HINSTANCE>(cpu.reg(Rcx));
        cpu.set_reg(Rax, reinterpret_cast<std::uint64_t>(
                             ::LoadIconW(module, reinterpret_cast<LPCWSTR>(cpu.reg(Rdx)))));
        finish_call();
        break;
    }
    case Api::LoadImageW: {
        const auto module = cpu.reg(Rcx) == guest_image_base_
                                ? static_cast<HINSTANCE>(resource_module_)
                                : reinterpret_cast<HINSTANCE>(cpu.reg(Rcx));
        const auto result =
            ::LoadImageW(module, reinterpret_cast<LPCWSTR>(cpu.reg(Rdx)),
                         static_cast<UINT>(cpu.reg(R8)), static_cast<int>(cpu.reg(R9)),
                         static_cast<int>(cpu.memory().read64(cpu.reg(Rsp) + 0x28)),
                         static_cast<UINT>(cpu.memory().read64(cpu.reg(Rsp) + 0x30)));
        cpu.set_reg(Rax, reinterpret_cast<std::uint64_t>(result));
        finish_call();
        break;
    }
    case Api::LoadAcceleratorsW: {
        const auto module = cpu.reg(Rcx) == guest_image_base_
                                ? static_cast<HINSTANCE>(resource_module_)
                                : reinterpret_cast<HINSTANCE>(cpu.reg(Rcx));
        cpu.set_reg(Rax, reinterpret_cast<std::uint64_t>(
                             ::LoadAcceleratorsW(module, reinterpret_cast<LPCWSTR>(cpu.reg(Rdx)))));
        finish_call();
        break;
    }
    case Api::RegisterClassExW: {
        const auto *guest_class =
            reinterpret_cast<const WNDCLASSEXW *>(static_cast<std::uintptr_t>(cpu.reg(Rcx)));
        if (guest_class == nullptr || guest_class->cbSize != sizeof(WNDCLASSEXW) ||
            guest_class->lpszClassName == nullptr || guest_class->lpfnWndProc == nullptr) {
            cpu.set_reg(Rax, 0);
            finish_call();
            break;
        }
        WNDCLASSEXW host_class = *guest_class;
        const auto guest_procedure = reinterpret_cast<std::uint64_t>(guest_class->lpfnWndProc);
        const std::wstring class_name(guest_class->lpszClassName);
        class_window_procedures_[class_name] = guest_procedure;
        host_class.lpfnWndProc = window_proc_bridge;
        host_class.hInstance = GetModuleHandleW(nullptr);
        host_class.lpszMenuName = nullptr;
        const auto atom = ::RegisterClassExW(&host_class);
        log::api("window", "RegisterClassExW class='" + narrow_string(class_name) + "' proc=" +
                               log::hex(guest_procedure) + " atom=" + std::to_string(atom));
        if (atom != 0) {
            atom_window_procedures_[atom] = guest_procedure;
        }
        cpu.set_reg(Rax, atom);
        finish_call();
        break;
    }
    case Api::CreateWindowExW: {
        const auto class_value = cpu.reg(Rdx);
        if (log::enabled(log::Level::Api)) {
            std::string class_description;
            if (class_value <= 0xffff) {
                class_description = "atom " + std::to_string(class_value);
            } else {
                const auto *name =
                    reinterpret_cast<const wchar_t *>(static_cast<std::uintptr_t>(class_value));
                class_description =
                    name == nullptr ? "<null>" : "'" + narrow_string(std::wstring(name)) + "'";
            }
            log::api("window", "CreateWindowExW class=" + class_description);
        }
        if (class_value <= 0xffff) {
            const auto found =
                atom_window_procedures_.find(static_cast<std::uint16_t>(class_value));
            creating_window_procedure_ = found == atom_window_procedures_.end() ? 0 : found->second;
        } else {
            const auto class_name =
                reinterpret_cast<const wchar_t *>(static_cast<std::uintptr_t>(class_value));
            const auto found = class_name == nullptr ? class_window_procedures_.end()
                                                     : class_window_procedures_.find(class_name);
            creating_window_procedure_ =
                found == class_window_procedures_.end() ? 0 : found->second;
        }
        const auto stack = cpu.reg(Rsp);
        const auto result = ::CreateWindowExW(
            static_cast<DWORD>(cpu.reg(Rcx)),
            reinterpret_cast<LPCWSTR>(static_cast<std::uintptr_t>(class_value)),
            reinterpret_cast<LPCWSTR>(static_cast<std::uintptr_t>(cpu.reg(R8))),
            static_cast<DWORD>(cpu.reg(R9)), static_cast<int>(cpu.memory().read64(stack + 0x28)),
            static_cast<int>(cpu.memory().read64(stack + 0x30)),
            static_cast<int>(cpu.memory().read64(stack + 0x38)),
            static_cast<int>(cpu.memory().read64(stack + 0x40)),
            reinterpret_cast<HWND>(cpu.memory().read64(stack + 0x48)),
            reinterpret_cast<HMENU>(cpu.memory().read64(stack + 0x50)), GetModuleHandleW(nullptr),
            reinterpret_cast<void *>(cpu.memory().read64(stack + 0x60)));
        if (callback_exception != nullptr) {
            auto exception = callback_exception;
            callback_exception = nullptr;
            std::rethrow_exception(exception);
        }
        log::api("window",
                 "CreateWindowExW -> hwnd=" + log::hex(reinterpret_cast<std::uint64_t>(result)));
        creating_window_procedure_ = 0;
        cpu.set_reg(Rax, reinterpret_cast<std::uint64_t>(result));
        finish_call();
        break;
    }
    case Api::ResolveDelayLoadedAPI: {
        const auto descriptor = cpu.reg(Rdx);
        const auto thunk_address = cpu.memory().read64(cpu.reg(Rsp) + 0x28);
        const auto attributes = cpu.memory().read32(descriptor);
        const auto dll_field = cpu.memory().read32(descriptor + 4);
        const auto module_field = cpu.memory().read32(descriptor + 8);
        const auto iat_field = cpu.memory().read32(descriptor + 12);
        const auto int_field = cpu.memory().read32(descriptor + 16);
        const bool rva_based = (attributes & 1) != 0;
        const auto field_address = [&](std::uint32_t field) {
            return rva_based ? guest_image_base_ + field : static_cast<std::uint64_t>(field);
        };
        const auto iat = field_address(iat_field);
        if (thunk_address < iat || (thunk_address - iat) % 8 != 0) {
            throw Error("invalid delay-import thunk");
        }
        const auto index = (thunk_address - iat) / 8;
        const auto lookup = cpu.memory().read64(field_address(int_field) + index * 8);
        std::string import_name;
        if ((lookup & (1ULL << 63)) != 0) {
            import_name = "#" + std::to_string(lookup & 0xffff);
        } else {
            import_name =
                cpu.memory().read_c_string((rva_based ? guest_image_base_ : 0) + lookup + 2);
        }
        const auto module_name = cpu.memory().read_c_string(field_address(dll_field));
        const auto resolved = resolve_import(module_name, import_name);
        cpu.memory().write64(thunk_address, resolved);
        if (module_field != 0) {
            cpu.memory().write64(field_address(module_field), 1);
        }
        cpu.set_reg(Rax, resolved);
        finish_call();
        break;
    }
    case Api::SHGetKnownFolderPath: {
        using GetKnownFolderPath = long(WINAPI *)(const GUID *, DWORD, HANDLE, wchar_t **);
        const auto shell = LoadLibraryW(L"shell32.dll");
        const auto function = reinterpret_cast<GetKnownFolderPath>(
            shell == nullptr ? nullptr : GetProcAddress(shell, "SHGetKnownFolderPath"));
        wchar_t *native_path = nullptr;
        const auto result = function == nullptr
                                ? static_cast<long>(0x80004005L)
                                : function(reinterpret_cast<const GUID *>(cpu.reg(Rcx)),
                                           static_cast<DWORD>(cpu.reg(Rdx)),
                                           reinterpret_cast<HANDLE>(cpu.reg(R8)), &native_path);
        if (result >= 0 && native_path != nullptr) {
            const auto length = std::wcslen(native_path);
            const auto guest_path = allocate((length + 1) * sizeof(wchar_t));
            for (std::size_t index = 0; index <= length; ++index) {
                cpu.memory().write16(guest_path + index * 2,
                                     static_cast<std::uint16_t>(native_path[index]));
            }
            cpu.memory().write64(cpu.reg(R9), guest_path);
            if (const auto ole = LoadLibraryW(L"ole32.dll"); ole != nullptr) {
                using FreeMemory = void(WINAPI *)(void *);
                if (const auto free_memory =
                        reinterpret_cast<FreeMemory>(GetProcAddress(ole, "CoTaskMemFree"));
                    free_memory != nullptr) {
                    free_memory(native_path);
                }
            }
        }
        cpu.set_reg(Rax, static_cast<std::uint32_t>(result));
        finish_call();
        break;
    }
    case Api::CoCreateInstance:
        // A native COM object exposes a host vtable, which guest code cannot execute directly.
        // Until individual interfaces have guest-side proxies, report an unavailable class so
        // applications can take their documented optional-feature fallback paths.
        if (cpu.reg(R9) != 0) {
            cpu.memory().write64(cpu.reg(R9), 0);
        }
        cpu.set_reg(Rax, 0x80040154U); // REGDB_E_CLASSNOTREG
        finish_call();
        break;
    case Api::RoGetActivationFactory:
        if (log::enabled(log::Level::Api)) {
            using GetRawBuffer = const wchar_t *(WINAPI *)(void *, std::uint32_t *);
            const auto combase = GetModuleHandleW(L"combase.dll");
            const auto get_raw_buffer = reinterpret_cast<GetRawBuffer>(
                combase == nullptr ? nullptr
                                   : GetProcAddress(combase, "WindowsGetStringRawBuffer"));
            std::uint32_t length = 0;
            const auto text = get_raw_buffer == nullptr
                                  ? nullptr
                                  : get_raw_buffer(reinterpret_cast<void *>(cpu.reg(Rcx)), &length);
            std::string description =
                text == nullptr ? "<unknown>" : narrow_string(std::wstring(text, length));
            const auto *iid = reinterpret_cast<const GUID *>(cpu.reg(Rdx));
            if (iid != nullptr) {
                std::ostringstream stream;
                stream << std::hex << iid->Data1 << '-' << iid->Data2 << '-' << iid->Data3 << '-';
                for (const auto byte : iid->Data4) {
                    stream << static_cast<unsigned>(byte);
                }
                description += " iid=" + stream.str();
            }
            log::api("api", "WinRT activation " + description);
        }
        if (protection_policy_proxy_ == 0) {
            const auto vtable = allocate(15 * 8);
            protection_policy_proxy_ = allocate(8);
            cpu.memory().write64(protection_policy_proxy_, vtable);
            for (std::uint32_t index = 0; index < 15; ++index) {
                const auto thunk = next_thunk_;
                next_thunk_ += 0x100;
                thunks_.emplace(thunk, Api::ProtectionPolicyMethod);
                thunk_names_.emplace(thunk,
                                     "IProtectionPolicyManagerStatics2#" + std::to_string(index));
                protection_policy_methods_.emplace(thunk, index);
                cpu.memory().write64(vtable + index * 8, thunk);
            }
        }
        if (cpu.reg(R8) != 0) {
            cpu.memory().write64(cpu.reg(R8), protection_policy_proxy_);
        }
        cpu.set_reg(Rax, 0);
        finish_call();
        break;
    case Api::ProtectionPolicyMethod: {
        const auto index = protection_policy_methods_.at(cpu.rip());
        switch (index) {
        case 0:
            if (cpu.reg(R8) != 0) {
                cpu.memory().write64(cpu.reg(R8), cpu.reg(Rcx));
            }
            cpu.set_reg(Rax, 0);
            break;
        case 1:
            cpu.set_reg(Rax, 2);
            break;
        case 2:
            cpu.set_reg(Rax, 1);
            break;
        case 3:
            if (cpu.reg(Rdx) != 0) {
                cpu.memory().write32(cpu.reg(Rdx), 0);
            }
            if (cpu.reg(R8) != 0) {
                cpu.memory().write64(cpu.reg(R8), 0);
            }
            cpu.set_reg(Rax, 0);
            break;
        case 4:
            if (cpu.reg(Rdx) != 0) {
                cpu.memory().write64(cpu.reg(Rdx), 0);
            }
            cpu.set_reg(Rax, 0);
            break;
        case 5:
            if (cpu.reg(Rdx) != 0) {
                cpu.memory().write32(cpu.reg(Rdx), 0);
            }
            cpu.set_reg(Rax, 0);
            break;
        case 6:
        case 7:
            if (cpu.reg(R9) != 0) {
                cpu.memory().write32(cpu.reg(R9), 0);
            }
            cpu.set_reg(Rax, 0);
            break;
        case 8:
            if (cpu.reg(R9) != 0) {
                cpu.memory().write64(cpu.reg(R9), 0);
            }
            cpu.set_reg(Rax, 0x80004001U);
            break;
        case 9:
        case 10:
        case 11:
            if (cpu.reg(R8) != 0) {
                cpu.memory().write32(cpu.reg(R8), 0);
            }
            cpu.set_reg(Rax, 0);
            break;
        case 12:
            if (cpu.reg(R8) != 0) {
                cpu.memory().write64(cpu.reg(R8), 0);
            }
            cpu.set_reg(Rax, 0);
            break;
        case 13:
            cpu.set_reg(Rax, 0);
            break;
        case 14:
            if (cpu.reg(Rdx) != 0) {
                cpu.memory().write32(cpu.reg(Rdx), 0);
            }
            cpu.set_reg(Rax, 0);
            break;
        default:
            throw Error("invalid protection policy method");
        }
        finish_call();
        break;
    }
    case Api::Native: {
        using NativeFunction =
            std::uint64_t(WINAPI *)(std::uint64_t, std::uint64_t, std::uint64_t, std::uint64_t,
                                    std::uint64_t, std::uint64_t, std::uint64_t, std::uint64_t,
                                    std::uint64_t, std::uint64_t, std::uint64_t, std::uint64_t,
                                    std::uint64_t, std::uint64_t, std::uint64_t, std::uint64_t);
        const auto stack = cpu.reg(Rsp);
        const auto argument = [&](std::uint64_t index) {
            return cpu.memory().read64(stack + 0x28 + index * 8);
        };
        const auto function = reinterpret_cast<NativeFunction>(native_functions_.at(cpu.rip()));
        const auto result =
            function(cpu.reg(Rcx), cpu.reg(Rdx), cpu.reg(R8), cpu.reg(R9), argument(0), argument(1),
                     argument(2), argument(3), argument(4), argument(5), argument(6), argument(7),
                     argument(8), argument(9), argument(10), argument(11));
        if (callback_exception != nullptr) {
            auto exception = callback_exception;
            callback_exception = nullptr;
            std::rethrow_exception(exception);
        }
        cpu.set_reg(Rax, result);
        finish_call();
        break;
    }
    case Api::Unsupported:
        throw Error("unsupported import called: " + thunk_names_.at(cpu.rip()));
    }
    switch (found->second) {
    case Api::ProcessReturn:
    case Api::ExitProcess:
    case Api::TerminateProcess:
        log::info("api",
                  "guest exit via " + thunk_name + " exit code " + std::to_string(exit_code));
        break;
    default:
        if (log::enabled(log::Level::Api)) {
            log::api("api", thunk_name + " -> " + log::hex(cpu.reg(Rax)));
        }
        break;
    }
    return true;
}

std::uint64_t Runtime::invoke_guest(Cpu &cpu, std::uint64_t target,
                                    const std::array<std::uint64_t, 4> &arguments,
                                    std::uint32_t &exit_code, bool &exited) {
    cpu.set_reg(Rcx, arguments[0]);
    cpu.set_reg(Rdx, arguments[1]);
    cpu.set_reg(R8, arguments[2]);
    cpu.set_reg(R9, arguments[3]);
    const auto outer_stack = cpu.reg(Rsp);
    const auto outer_rip = cpu.rip();
    const auto callback_stack = outer_stack - 0x30;
    cpu.set_reg(Rsp, callback_stack);
    cpu.memory().write64(callback_stack, callback_return);
    cpu.set_rip(target);
    try {
        while (!exited && cpu.rip() != callback_return) {
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
        return DefWindowProcW(reinterpret_cast<HWND>(window), message, word_parameter,
                              long_parameter);
    }
    static constexpr std::uint32_t notable_messages[] = {
        WM_CREATE,     WM_NCCREATE, WM_DESTROY, WM_NCDESTROY,  WM_CLOSE,         WM_COMMAND,
        WM_SYSCOMMAND, WM_QUIT,     WM_SIZE,    WM_SHOWWINDOW, WM_INITMENUPOPUP, WM_TIMER,
    };
    if (log::enabled(log::Level::Api) &&
        std::find(std::begin(notable_messages), std::end(notable_messages), message) !=
            std::end(notable_messages)) {
        log::api("window", window_message_name(message) + " window=" + log::hex(window) +
                               " wparam=" + log::hex(word_parameter) +
                               " lparam=" + log::hex(static_cast<std::uint64_t>(long_parameter)));
    }
    std::size_t pointer_size = 0;
    switch (message) {
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
    if (pointer_size != 0 && long_parameter != 0) {
        if (callback_depth_ >= 16 || pointer_size > 0x1000) {
            throw Error("window callback scratch space exhausted");
        }
        scratch = environment_base + 0x10000 + callback_depth_ * 0x1000;
        std::memcpy(reinterpret_cast<void *>(scratch),
                    reinterpret_cast<const void *>(long_parameter), pointer_size);
        guest_long_parameter = scratch;
    }
    ++callback_depth_;
    std::uint64_t result = 0;
    try {
        result = invoke_guest(cpu, found->second,
                              {window, message, word_parameter, guest_long_parameter}, exit_code,
                              exited);
    } catch (...) {
        --callback_depth_;
        throw;
    }
    --callback_depth_;
    if (scratch != 0) {
        std::memcpy(reinterpret_cast<void *>(long_parameter),
                    reinterpret_cast<const void *>(scratch), pointer_size);
    }
    if (message == WM_NCDESTROY) {
        window_procedures_.erase(found);
    }
    return static_cast<std::intptr_t>(result);
}

RunResult Runtime::run(const std::filesystem::path &executable, std::uint64_t instruction_limit,
                       const std::wstring &arguments) {
    log::info("runtime", "loading guest '" + executable.string() + "'");
    Memory memory;
    thunks_.clear();
    thunk_names_.clear();
    native_functions_.clear();
    thunks_.emplace(return_thunk, Api::ProcessReturn);
    next_thunk_ = return_thunk + 0x100;
    data_import_next_ = 0;
    data_import_slots_.clear();
    last_error_ = 0;
    guest_exception_filter_ = 0;
    heap_next_ = 0x0000'0006'0000'0000ULL;
    heap_sizes_.clear();
    protection_policy_proxy_ = 0;
    protection_policy_methods_.clear();
    next_tls_index_ = 1;
    next_fls_index_ = 1;
    tls_values_.clear();
    fls_values_.clear();
    const auto image =
        PeLoader::load(executable, memory, [&](const auto &module, const auto &name) {
            return resolve_import(module, name);
        });
    guest_image_base_ = image.base;
    guest_executable_ = std::filesystem::absolute(executable);
    if (resource_module_ != nullptr) {
        FreeLibrary(static_cast<HMODULE>(resource_module_));
    }
    resource_module_ =
        LoadLibraryExW(guest_executable_.c_str(), nullptr,
                       LOAD_LIBRARY_AS_DATAFILE_EXCLUSIVE | LOAD_LIBRARY_AS_IMAGE_RESOURCE);
    const auto requested_stack = std::max(image.stack_reserve, minimum_stack_size);
    if (requested_stack > std::numeric_limits<std::uint64_t>::max() - 0xffff) {
        throw Error("guest stack reserve is too large");
    }
    const auto stack_size = (requested_stack + 0xffff) & ~0xffffULL;
    if (stack_size >= stack_top) {
        throw Error("guest stack reserve is too large");
    }
    const auto stack_base = stack_top - stack_size;
    memory.map(stack_base, stack_size, Read | Write, "main stack");
    memory.map(environment_base, environment_size, Read | Write, "process environment");
    // KUSER_SHARED_DATA is mapped read-only into every Windows process; alias the host's own
    // page so guest code reading tick counts and system time sees real values.
    memory.map_existing(
        0x7ffe0000ULL, 0x1000, Read, "kuser shared data",
        reinterpret_cast<std::uint8_t *>(static_cast<std::uintptr_t>(0x7ffe0000ULL)));
    const auto initial_rsp = stack_base + stack_size - 0x1000 - 8;
    memory.write64(initial_rsp, return_thunk);
    memory.write64(teb_base + 0x08, stack_base + stack_size);
    memory.write64(teb_base + 0x10, stack_base);
    memory.write64(teb_base + 0x30, teb_base);
    memory.write64(teb_base + 0x40, 1);
    memory.write64(teb_base + 0x48, 1);
    memory.write64(teb_base + 0x60, peb_base);
    if (image.tls_start != 0 || image.tls_index != 0 || !image.tls_callbacks.empty()) {
        const auto template_size = image.tls_end - image.tls_start;
        if (template_size > tls_size - 0x1000) {
            throw Error("guest TLS template is too large");
        }
        memory.map(tls_base, tls_size, Read | Write, "main thread TLS");
        const auto tls_block = tls_base + 0x1000;
        memory.write64(teb_base + 0x58, tls_base);
        memory.write64(tls_base, tls_block);
        if (template_size != 0) {
            memory.write(tls_block,
                         memory.read(image.tls_start, static_cast<std::size_t>(template_size)));
        }
        if (image.tls_index != 0) {
            memory.write32(image.tls_index, 0);
        }
    }
    if (arguments.size() > 1000) {
        throw Error("guest command line arguments too long");
    }
    std::wstring full_command_line = L"\"" + executable.wstring() + L"\"";
    if (!arguments.empty()) {
        full_command_line += L' ';
        full_command_line += arguments;
    }
    if (full_command_line.size() > 2047) {
        throw Error("guest command line too long");
    }
    for (std::size_t index = 0; index < full_command_line.size(); ++index) {
        memory.write16(command_line_address + index * 2,
                       static_cast<std::uint16_t>(full_command_line[index]));
    }
    memory.write16(command_line_address + full_command_line.size() * 2, 0);
    for (std::size_t index = 0; index < arguments.size(); ++index) {
        memory.write16(winmain_command_line_address + index * 2,
                       static_cast<std::uint16_t>(arguments[index]));
    }
    memory.write16(winmain_command_line_address + arguments.size() * 2, 0);
    guest_command_line_ = command_line_address;
    guest_winmain_command_line_ = winmain_command_line_address;
    std::string narrow_command_line;
    narrow_command_line.reserve(full_command_line.size());
    for (const wchar_t character : full_command_line) {
        narrow_command_line.push_back(character < 0x80 ? static_cast<char>(character) : '_');
    }
    for (std::size_t index = 0; index < narrow_command_line.size(); ++index) {
        memory.write8(environment_base + 0x3800 + index,
                      static_cast<std::uint8_t>(narrow_command_line[index]));
    }
    memory.write8(environment_base + 0x3800 + narrow_command_line.size(), 0);
    const auto data_slot = [&](const char *name) {
        const auto found = data_import_slots_.find(name);
        return found == data_import_slots_.end() ? 0 : found->second;
    };
    if (const auto slot = data_slot("_wcmdln"); slot != 0) {
        memory.write64(slot, command_line_address);
    }
    if (const auto slot = data_slot("_acmdln"); slot != 0) {
        memory.write64(slot, environment_base + 0x3800);
    }
    // An empty environment is a single NULL pointer entry.
    if (const auto slot = data_slot("_environ"); slot != 0) {
        memory.write64(slot, slot + 8);
    }
    if (const auto slot = data_slot("_wenviron"); slot != 0) {
        memory.write64(slot, slot + 8);
    }
    if (const auto slot = data_slot("_winmajor"); slot != 0) {
        memory.write32(slot, 10);
    }
    if (const auto slot = data_slot("_winminor"); slot != 0) {
        memory.write32(slot, 0);
    }
    if (const auto slot = data_slot("_osver"); slot != 0) {
        memory.write32(slot, 0);
    }
    if (const auto slot = data_slot("_winver"); slot != 0) {
        memory.write32(slot, 0x0A00);
    }
    log::info("runtime", "guest command line: " + narrow_string(full_command_line));

    Cpu cpu(memory);
    cpu.reset(image.entry, initial_rsp);
    cpu.set_gs_base(teb_base);
    std::uint32_t exit_code = 0;
    bool exited = false;
    active_runtime = this;
    active_cpu = &cpu;
    active_exit_code = &exit_code;
    active_exited = &exited;
    callback_exception = nullptr;
    log::info("runtime", "starting guest at entry " + log::hex(image.entry));
    try {
        for (const auto callback : image.tls_callbacks) {
            log::trace("runtime", "calling TLS callback " + log::hex(callback));
            static_cast<void>(invoke_guest(cpu, callback, {image.base, DLL_PROCESS_ATTACH, 0, 0},
                                           exit_code, exited));
            if (exited) {
                break;
            }
        }
        while (!exited) {
            if (cpu.instructions() >= instruction_limit) {
                throw Error("instruction limit exceeded");
            }
            if (!dispatch(cpu, exit_code, exited)) {
                cpu.step();
            }
        }
    } catch (const std::exception &) {
        log::error("cpu",
                   "guest stopped after " + std::to_string(cpu.instructions()) + " instructions");
        log::error("cpu", cpu_state_dump(cpu));
        active_runtime = nullptr;
        active_cpu = nullptr;
        active_exit_code = nullptr;
        active_exited = nullptr;
        throw;
    }
    active_runtime = nullptr;
    active_cpu = nullptr;
    active_exit_code = nullptr;
    active_exited = nullptr;
    log::info("runtime", "guest finished cleanly");
    return {exit_code, cpu.instructions()};
}

} // namespace winemu
