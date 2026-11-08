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
extern "C" __declspec(dllimport) BOOL __stdcall PlaySoundA(const char *, HMODULE, DWORD);
extern "C" __declspec(dllimport) BOOL __stdcall PlaySoundW(const wchar_t *, HMODULE, DWORD);
extern "C" __declspec(dllimport) DWORD __stdcall timeGetTime();
extern "C" __declspec(dllimport) UINT __stdcall timeBeginPeriod(UINT);
extern "C" __declspec(dllimport) UINT __stdcall timeEndPeriod(UINT);

namespace winemu {

namespace {

constexpr std::uint64_t return_thunk64 = 0xffff'0000'0000'0000ULL;
constexpr std::uint64_t return_thunk32 = 0x7ff0'0000ULL;
constexpr std::uint64_t callback_return = 0xffff'0000'0000'0080ULL;
constexpr std::uint64_t stack_top = 0x0000'0000'7000'0000ULL;
constexpr std::uint64_t minimum_stack_size = 1024 * 1024;
constexpr std::uint64_t environment_base = 0x7fc0'0000ULL;
constexpr std::uint64_t environment_size = 0x0002'0000ULL;
constexpr std::uint64_t tls_base = 0x7fc2'0000ULL;
constexpr std::uint64_t tls_size = 0x0002'0000ULL;
constexpr std::uint64_t teb_base = environment_base + 0xe000;
constexpr std::uint64_t peb_base = environment_base + 0xf000;
constexpr std::uint64_t crt_commode = environment_base + 0x1000;
constexpr std::uint64_t crt_errno = environment_base + 0x1008;
constexpr std::uint64_t command_line_address = environment_base + 0x2000;
constexpr std::uint64_t winmain_command_line_address = environment_base + 0x3000;
constexpr DWORD sound_async = 0x0001;
constexpr DWORD sound_memory = 0x0004;
constexpr DWORD sound_loop = 0x0008;
constexpr DWORD sound_resource = 0x00040004;

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
    thunks_.emplace(return_thunk64, Api::ProcessReturn);
}

Runtime::~Runtime() {
    for (const auto &[guest_handle, host_handle] : find_handles_) {
        static_cast<void>(guest_handle);
        ::FindClose(static_cast<HANDLE>(host_handle));
    }
    for (const auto &[guest_handle, host_handle] : file_handles_) {
        static_cast<void>(guest_handle);
        ::CloseHandle(static_cast<HANDLE>(host_handle));
    }
    if (host_gdiplus_token_ != 0) {
        if (const auto library = ::LoadLibraryW(L"gdiplus.dll"); library != nullptr) {
            using Shutdown = void(WINAPI *)(std::uint64_t);
            if (const auto shutdown =
                    reinterpret_cast<Shutdown>(::GetProcAddress(library, "GdiplusShutdown"));
                shutdown != nullptr) {
                shutdown(host_gdiplus_token_);
            }
        }
    }
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
    if ((kernel_module && name == "ExitProcess") || name == "CorExitProcess") {
        api = Api::ExitProcess;
    } else if (kernel_module && name == "GetStdHandle") {
        api = Api::GetStdHandle;
    } else if (kernel_module && name == "SetHandleCount") {
        api = Api::SetHandleCount;
    } else if (kernel_module && name == "GetFileType") {
        api = Api::GuestFileType;
    } else if (kernel_module && (name == "GetConsoleCP" || name == "GetConsoleOutputCP" ||
                                 name == "GetACP" || name == "GetOEMCP")) {
        api = Api::ConsoleCodePage;
    } else if (kernel_module && name == "GetCPInfo") {
        api = Api::GuestCodePageInfo;
    } else if (kernel_module && name == "IsValidCodePage") {
        api = Api::ValidateCodePage;
    } else if (kernel_module && (name == "GetConsoleMode" || name == "SetConsoleMode")) {
        api = Api::ConsoleMode;
    } else if (kernel_module && name == "GetConsoleWindow") {
        api = Api::ConsoleWindow;
    } else if (kernel_module && (name == "GetCurrentProcess" || name == "GetCurrentThread")) {
        api = Api::CurrentPseudoHandle;
    } else if (name == "IsProcessorFeaturePresent") {
        api = Api::ProcessorFeature;
    } else if (kernel_module && (name == "SetConsoleCtrlHandler" || name == "SetStdHandle")) {
        api = Api::SimpleHandleSuccess;
    } else if (kernel_module && (name == "CreateFileA" || name == "CreateFileW")) {
        api = Api::GuestCreateFile;
    } else if (kernel_module && name == "ReadFile") {
        api = Api::GuestReadFile;
    } else if (kernel_module &&
               (name == "SetFilePointer" || name == "GetFileSize" || name == "SetEndOfFile")) {
        api = Api::GuestFilePosition;
    } else if (kernel_module && name == "WriteFile") {
        api = Api::WriteFile;
    } else if (kernel_module && name == "CloseHandle") {
        api = Api::GuestCloseHandle;
    } else if (kernel_module && name == "GetLastError") {
        api = Api::GetLastError;
    } else if (kernel_module && name == "SetLastError") {
        api = Api::SetLastError;
    } else if (kernel_module && name == "GetSystemTimeAsFileTime") {
        api = Api::GetSystemTimeAsFileTime;
    } else if (kernel_module &&
               (name == "FileTimeToLocalFileTime" || name == "LocalFileTimeToFileTime" ||
                name == "FileTimeToSystemTime" || name == "SystemTimeToFileTime")) {
        api = Api::TimeConversion;
    } else if (kernel_module && name == "GetTimeZoneInformation") {
        api = Api::TimeZoneInformation;
    } else if (kernel_module && name == "GetCurrentProcessId") {
        api = Api::GetCurrentProcessId;
    } else if (kernel_module && name == "GetCurrentThreadId") {
        api = Api::GetCurrentThreadId;
    } else if (kernel_module && (name == "GetStartupInfoA" || name == "GetStartupInfoW")) {
        api = Api::StartupInfo;
    } else if (kernel_module && (name == "InitializeCriticalSection" ||
                                 name == "InitializeCriticalSectionAndSpinCount")) {
        api = Api::CriticalSectionInitialize;
    } else if (kernel_module && (name == "EnterCriticalSection" || name == "LeaveCriticalSection" ||
                                 name == "DeleteCriticalSection")) {
        api = Api::CriticalSectionOperation;
    } else if (kernel_module && name == "TryEnterCriticalSection") {
        api = Api::CriticalSectionTry;
    } else if (kernel_module &&
               (name == "InterlockedIncrement" || name == "InterlockedDecrement" ||
                name == "InterlockedExchange" || name == "InterlockedExchangeAdd" ||
                name == "InterlockedCompareExchange" || name == "InterlockedAnd" ||
                name == "InterlockedOr" || name == "InterlockedXor" ||
                name == "InterlockedExchangePointer" ||
                name == "InterlockedCompareExchangePointer" || name == "InterlockedIncrement64" ||
                name == "InterlockedDecrement64" || name == "InterlockedExchange64" ||
                name == "InterlockedExchangeAdd64" || name == "InterlockedCompareExchange64" ||
                name == "InterlockedAnd64" || name == "InterlockedOr64" ||
                name == "InterlockedXor64")) {
        api = Api::InterlockedOperation;
    } else if (name == "GetProcessWindowStation") {
        api = Api::GetProcessWindowStation;
    } else if (name == "GetUserObjectInformationA" || name == "GetUserObjectInformationW") {
        api = Api::UserObjectInformation;
    } else if (name == "MessageBoxA" || name == "MessageBoxW") {
        api = Api::GuestMessageBox;
    } else if (name == "PeekMessageA" || name == "PeekMessageW" || name == "GetMessageA" ||
               name == "GetMessageW" || name == "TranslateMessage" || name == "DispatchMessageA" ||
               name == "DispatchMessageW" || name == "PostQuitMessage") {
        api = Api::GuestMessageLoop;
    } else if (name == "GetOpenFileNameA" || name == "GetOpenFileNameW" ||
               name == "GetSaveFileNameA" || name == "GetSaveFileNameW" ||
               name == "CommDlgExtendedError") {
        api = Api::GuestFileDialog;
    } else if (name == "InitCommonControlsEx") {
        api = Api::CommonControlsInitialize;
    } else if (name == "GdiplusStartup") {
        api = Api::GdiplusStartup;
    } else if (name == "GdiplusShutdown") {
        api = Api::GdiplusShutdown;
    } else if (name == "SteamAPI_RestartAppIfNecessary") {
        api = Api::SteamRestartApp;
    } else if (name == "SteamAPI_Init" || name == "SteamAPI_InitSafe") {
        api = Api::SteamInitialize;
    } else if (kernel_module && name == "OutputDebugStringA") {
        api = Api::OutputDebugStringA;
    } else if (kernel_module && name == "Beep") {
        api = Api::Beep;
    } else if (name == "MessageBeep") {
        api = Api::MessageBeep;
    } else if (name == "PlaySoundA") {
        api = Api::PlaySoundA;
    } else if (name == "PlaySoundW") {
        api = Api::PlaySoundW;
    } else if (name == "sndPlaySoundA") {
        api = Api::SndPlaySoundA;
    } else if (name == "sndPlaySoundW") {
        api = Api::SndPlaySoundW;
    } else if (kernel_module && name == "GetTickCount") {
        api = Api::GetTickCount;
    } else if (kernel_module && name == "GetTickCount64") {
        api = Api::GetTickCount64;
    } else if (kernel_module && name == "QueryPerformanceCounter") {
        api = Api::QueryPerformanceCounter;
    } else if (kernel_module && name == "QueryPerformanceFrequency") {
        api = Api::QueryPerformanceFrequency;
    } else if (kernel_module && name == "Sleep") {
        api = Api::Sleep;
    } else if (name == "timeGetTime") {
        api = Api::TimeGetTime;
    } else if (name == "timeBeginPeriod") {
        api = Api::TimeBeginPeriod;
    } else if (name == "timeEndPeriod") {
        api = Api::TimeEndPeriod;
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
    } else if (name == "GetCommandLineA") {
        api = Api::GetCommandLineA;
    } else if (name == "GetCommandLineW") {
        api = Api::GetCommandLineW;
    } else if (name == "WideCharToMultiByte") {
        api = Api::WideCharConversion;
    } else if (name == "MultiByteToWideChar") {
        api = Api::MultiByteConversion;
    } else if (name == "GetStringTypeA" || name == "GetStringTypeW") {
        api = Api::GuestStringType;
    } else if (name == "LCMapStringA" || name == "LCMapStringW") {
        api = Api::GuestMapString;
    } else if (name == "CommandLineToArgvW") {
        api = Api::CommandLineToArgvW;
    } else if (name == "GetSecurityInfo") {
        api = Api::GetSecurityInfo;
    } else if (name == "MapViewOfFile") {
        api = Api::MapViewOfFile;
    } else if (name == "GetEnvironmentStringsW") {
        api = Api::EnvironmentStringsW;
    } else if (name == "GetEnvironmentStringsA" || name == "GetEnvironmentStrings") {
        api = Api::EnvironmentStringsA;
    } else if (name == "GetEnvironmentVariableA" || name == "GetEnvironmentVariableW") {
        api = Api::EnvironmentVariable;
    } else if (name == "ExpandEnvironmentStringsA" || name == "ExpandEnvironmentStringsW") {
        api = Api::EnvironmentExpansion;
    } else if (name == "GetFullPathNameA" || name == "GetFullPathNameW") {
        api = Api::FullPathName;
    } else if (name == "GetCurrentDirectoryA" || name == "GetCurrentDirectoryW" ||
               name == "SetCurrentDirectoryA" || name == "SetCurrentDirectoryW") {
        api = Api::CurrentDirectory;
    } else if (name == "GetFileAttributesA" || name == "GetFileAttributesW" ||
               name == "SetFileAttributesA" || name == "SetFileAttributesW") {
        api = Api::FileAttributes;
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
    } else if (name == "HeapCreate" || name == "GetProcessHeap") {
        api = Api::ProcessHeap;
    } else if (name == "HeapDestroy") {
        api = Api::HeapDestroy;
    } else if (name == "LocalReAlloc" || name == "HeapReAlloc") {
        api = Api::Reallocate;
    } else if (name == "_o_free" || name == "free" || name == "CoTaskMemFree" ||
               name == "LocalFree" || name == "GlobalFree") {
        api = Api::FreeRcx;
    } else if (name == "HeapFree") {
        api = Api::HeapFree;
    } else if (name == "LocalSize" || name == "HeapSize") {
        api = Api::AllocationSize;
    } else if (name == "LocalLock" || name == "GlobalLock") {
        api = Api::IdentityRcx;
    } else if (kernel_module && (name == "EncodePointer" || name == "DecodePointer")) {
        api = Api::IdentityRcx;
    } else if (name == "LocalUnlock" || name == "GlobalUnlock") {
        api = Api::ReturnZero;
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
    } else if (name == "LoadLibraryA" || name == "LoadLibraryW") {
        api = Api::ModuleLoad;
    } else if (name == "FreeLibrary") {
        api = Api::ModuleFree;
    } else if (name == "FindFirstFileA" || name == "FindFirstFileW") {
        api = Api::GuestFindFirstFile;
    } else if (name == "FindNextFileA" || name == "FindNextFileW") {
        api = Api::GuestFindNextFile;
    } else if (name == "FindClose") {
        api = Api::GuestFindClose;
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
        if (guest_is_64_bit_ && !unsafe_calls.contains(name)) {
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
    const auto finish_call = [&](unsigned argument_count = 0) {
        cpu.set_rip(cpu.pop64());
        if (!guest_is_64_bit_ && argument_count != 0) {
            cpu.set_reg(Rsp, (cpu.reg(Rsp) + argument_count * 4) & UINT32_MAX);
        }
    };
    const auto argument = [&](unsigned index) {
        if (!guest_is_64_bit_) {
            return static_cast<std::uint64_t>(
                cpu.memory().read32(cpu.reg(Rsp) + 4 + static_cast<std::uint64_t>(index) * 4));
        }
        constexpr Register argument_registers[] = {Rcx, Rdx, R8, R9};
        if (index < std::size(argument_registers)) {
            return cpu.reg(argument_registers[index]);
        }
        return cpu.memory().read64(cpu.reg(Rsp) + 0x28 + (index - 4) * 8);
    };
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
        exit_code = static_cast<std::uint32_t>(argument(0));
        exited = true;
        break;
    case Api::TerminateProcess:
        exit_code = static_cast<std::uint32_t>(argument(1));
        exited = true;
        break;
    case Api::GetStdHandle: {
        const auto requested = static_cast<std::int32_t>(argument(0));
        std::uint64_t handle = 0;
        if (requested == -11) {
            handle = 0x101;
        } else if (requested == -12) {
            handle = 0x102;
        } else if (requested == -10) {
            handle = 0x100;
        } else {
            last_error_ = 6;
            handle = guest_is_64_bit_ ? std::numeric_limits<std::uint64_t>::max() : UINT32_MAX;
        }
        cpu.set_reg(Rax, handle);
        finish_call(1);
        break;
    }
    case Api::SetHandleCount:
        cpu.set_reg(Rax, argument(0));
        finish_call(1);
        break;
    case Api::GuestFileType: {
        const auto handle = argument(0);
        std::uint32_t type = FILE_TYPE_UNKNOWN;
        if (handle >= 0x100 && handle <= 0x102) {
            type = FILE_TYPE_CHAR;
        } else if (const auto found = file_handles_.find(handle); found != file_handles_.end()) {
            ::SetLastError(ERROR_SUCCESS);
            type = ::GetFileType(static_cast<HANDLE>(found->second));
            if (type == FILE_TYPE_UNKNOWN) {
                last_error_ = ::GetLastError();
            }
        } else {
            last_error_ = ERROR_INVALID_HANDLE;
        }
        cpu.set_reg(Rax, type);
        finish_call(1);
        break;
    }
    case Api::ConsoleCodePage:
        cpu.set_reg(Rax, thunk_name.ends_with("GetOEMCP") ? ::GetOEMCP() : ::GetACP());
        finish_call();
        break;
    case Api::GuestCodePageInfo: {
        CPINFO information{};
        const auto result = ::GetCPInfo(static_cast<UINT>(argument(0)), &information) != FALSE;
        if (result) {
            const auto destination = argument(1);
            cpu.memory().write32(destination, information.MaxCharSize);
            cpu.memory().write(destination + 4,
                               std::span<const std::uint8_t>(information.DefaultChar, 2));
            cpu.memory().write(destination + 6,
                               std::span<const std::uint8_t>(information.LeadByte, 12));
        } else {
            last_error_ = ::GetLastError();
        }
        cpu.set_reg(Rax, result ? 1 : 0);
        finish_call(2);
        break;
    }
    case Api::ValidateCodePage:
        cpu.set_reg(Rax, ::IsValidCodePage(static_cast<UINT>(argument(0))) != FALSE);
        finish_call(1);
        break;
    case Api::ConsoleMode:
        if (thunk_name.ends_with("GetConsoleMode")) {
            const auto destination = argument(1);
            if (destination != 0) {
                cpu.memory().write32(destination,
                                     ENABLE_PROCESSED_OUTPUT | ENABLE_WRAP_AT_EOL_OUTPUT);
            }
        }
        cpu.set_reg(Rax, 1);
        finish_call(2);
        break;
    case Api::ConsoleWindow:
        cpu.set_reg(Rax, 0);
        finish_call();
        break;
    case Api::CurrentPseudoHandle:
        cpu.set_reg(Rax, thunk_name.ends_with("GetCurrentProcess")
                             ? (guest_is_64_bit_ ? UINT64_MAX : UINT32_MAX)
                             : (guest_is_64_bit_ ? UINT64_MAX - 1 : UINT32_MAX - 1));
        finish_call();
        break;
    case Api::ProcessorFeature:
        cpu.set_reg(Rax,
                    ::IsProcessorFeaturePresent(static_cast<DWORD>(argument(0))) != FALSE ? 1 : 0);
        finish_call(1);
        break;
    case Api::SimpleHandleSuccess:
        // Console handlers are intentionally not retained: they are guest code addresses.
        cpu.set_reg(Rax, 1);
        finish_call(2);
        break;
    case Api::GuestCreateFile: {
        const bool ansi = thunk_name.ends_with("CreateFileA");
        const auto path = ansi ? std::filesystem::path(cpu.memory().read_c_string(argument(0)))
                               : std::filesystem::path(cpu.memory().read_wide_string(argument(0)));
        log::api("file", "CreateFile path='" + narrow_string(path.wstring()) + "'");
        HANDLE template_handle = nullptr;
        if (const auto found = file_handles_.find(argument(6)); found != file_handles_.end()) {
            template_handle = static_cast<HANDLE>(found->second);
        }
        const auto host_handle = ::CreateFileW(
            path.c_str(), static_cast<DWORD>(argument(1)), static_cast<DWORD>(argument(2)), nullptr,
            static_cast<DWORD>(argument(4)), static_cast<DWORD>(argument(5)), template_handle);
        if (host_handle == INVALID_HANDLE_VALUE) {
            last_error_ = ::GetLastError();
            cpu.set_reg(Rax, guest_is_64_bit_ ? UINT64_MAX : UINT32_MAX);
        } else {
            const auto guest_handle = next_file_handle_++;
            file_handles_.emplace(guest_handle, host_handle);
            cpu.set_reg(Rax, guest_handle);
        }
        finish_call(7);
        break;
    }
    case Api::GuestReadFile: {
        const auto found = file_handles_.find(argument(0));
        const auto requested = static_cast<DWORD>(argument(2));
        std::vector<std::uint8_t> bytes(requested);
        DWORD transferred = 0;
        const bool valid = found != file_handles_.end() && argument(4) == 0;
        const auto result = valid && ::ReadFile(static_cast<HANDLE>(found->second), bytes.data(),
                                                requested, &transferred, nullptr) != FALSE;
        if (result) {
            cpu.memory().write(argument(1),
                               std::span<const std::uint8_t>(bytes.data(), transferred));
            if (argument(3) != 0) {
                cpu.memory().write32(argument(3), transferred);
            }
        } else {
            last_error_ = valid ? ::GetLastError() : ERROR_INVALID_HANDLE;
        }
        cpu.set_reg(Rax, result ? 1 : 0);
        finish_call(5);
        break;
    }
    case Api::GuestFilePosition: {
        const auto found = file_handles_.find(argument(0));
        if (found == file_handles_.end()) {
            last_error_ = ERROR_INVALID_HANDLE;
            cpu.set_reg(Rax, thunk_name.ends_with("!SetEndOfFile") ? 0 : UINT32_MAX);
            finish_call(thunk_name.ends_with("!SetFilePointer")
                            ? 4
                            : (thunk_name.ends_with("!SetEndOfFile") ? 1 : 2));
            break;
        }
        const auto host_handle = static_cast<HANDLE>(found->second);
        if (thunk_name.ends_with("!SetEndOfFile")) {
            const auto result = ::SetEndOfFile(host_handle);
            if (result == FALSE) {
                last_error_ = ::GetLastError();
            }
            cpu.set_reg(Rax, result != FALSE ? 1 : 0);
            finish_call(1);
            break;
        }
        if (thunk_name.ends_with("!GetFileSize")) {
            LARGE_INTEGER size{};
            if (::GetFileSizeEx(host_handle, &size) == FALSE) {
                last_error_ = ::GetLastError();
                cpu.set_reg(Rax, UINT32_MAX);
            } else {
                if (argument(1) != 0) {
                    cpu.memory().write32(argument(1),
                                         static_cast<std::uint32_t>(size.QuadPart >> 32));
                }
                cpu.set_reg(Rax, static_cast<std::uint32_t>(size.QuadPart));
            }
            finish_call(2);
            break;
        }
        const auto high_pointer = argument(2);
        const auto low = static_cast<std::uint32_t>(argument(1));
        std::uint64_t distance_bits = low;
        if (high_pointer != 0) {
            distance_bits |= static_cast<std::uint64_t>(cpu.memory().read32(high_pointer)) << 32;
        } else if ((low & 0x80000000U) != 0) {
            distance_bits |= 0xffffffff00000000ULL;
        }
        LARGE_INTEGER distance{};
        distance.QuadPart = static_cast<std::int64_t>(distance_bits);
        LARGE_INTEGER position{};
        const auto result =
            ::SetFilePointerEx(host_handle, distance, &position, static_cast<DWORD>(argument(3)));
        if (result == FALSE) {
            last_error_ = ::GetLastError();
            cpu.set_reg(Rax, UINT32_MAX);
        } else {
            if (high_pointer != 0) {
                cpu.memory().write32(high_pointer,
                                     static_cast<std::uint32_t>(position.QuadPart >> 32));
            }
            cpu.set_reg(Rax, static_cast<std::uint32_t>(position.QuadPart));
        }
        finish_call(4);
        break;
    }
    case Api::GuestCloseHandle: {
        const auto found = file_handles_.find(argument(0));
        bool result = argument(0) >= 0x100 && argument(0) <= 0x102;
        if (found != file_handles_.end()) {
            result = ::CloseHandle(static_cast<HANDLE>(found->second)) != FALSE;
            file_handles_.erase(found);
        }
        if (!result) {
            last_error_ = ERROR_INVALID_HANDLE;
        }
        cpu.set_reg(Rax, result ? 1 : 0);
        finish_call(1);
        break;
    }
    case Api::WriteFile: {
        const auto handle = argument(0);
        const auto size = static_cast<std::uint32_t>(argument(2));
        const auto bytes = cpu.memory().read(argument(1), size);
        DWORD transferred = 0;
        bool result = false;
        if ((handle == 0x101 || handle == 0x102) && argument(4) == 0) {
            output_.write(reinterpret_cast<const char *>(bytes.data()),
                          static_cast<std::streamsize>(bytes.size()));
            output_.flush();
            transferred = size;
            result = true;
        } else if (const auto found = file_handles_.find(handle);
                   found != file_handles_.end() && argument(4) == 0) {
            result = ::WriteFile(static_cast<HANDLE>(found->second), bytes.data(), size,
                                 &transferred, nullptr) != FALSE;
        }
        if (result && argument(3) != 0) {
            cpu.memory().write32(argument(3), transferred);
        } else if (!result) {
            last_error_ = ERROR_INVALID_HANDLE;
        }
        cpu.set_reg(Rax, result ? 1 : 0);
        finish_call(5);
        break;
    }
    case Api::GetLastError:
        cpu.set_reg(Rax, last_error_);
        finish_call();
        break;
    case Api::SetLastError:
        last_error_ = static_cast<std::uint32_t>(argument(0));
        finish_call(1);
        break;
    case Api::GetSystemTimeAsFileTime: {
        FILETIME time{};
        ::GetSystemTimeAsFileTime(&time);
        cpu.memory().write32(argument(0), time.dwLowDateTime);
        cpu.memory().write32(argument(0) + 4, time.dwHighDateTime);
        finish_call(1);
        break;
    }
    case Api::TimeConversion: {
        const auto source = argument(0);
        const auto destination = argument(1);
        BOOL result = FALSE;
        if (thunk_name.ends_with("FileTimeToLocalFileTime") ||
            thunk_name.ends_with("LocalFileTimeToFileTime")) {
            FILETIME input{cpu.memory().read32(source), cpu.memory().read32(source + 4)};
            FILETIME output{};
            result = thunk_name.ends_with("FileTimeToLocalFileTime")
                         ? ::FileTimeToLocalFileTime(&input, &output)
                         : ::LocalFileTimeToFileTime(&input, &output);
            if (result != FALSE) {
                cpu.memory().write32(destination, output.dwLowDateTime);
                cpu.memory().write32(destination + 4, output.dwHighDateTime);
            }
        } else if (thunk_name.ends_with("FileTimeToSystemTime")) {
            FILETIME input{cpu.memory().read32(source), cpu.memory().read32(source + 4)};
            SYSTEMTIME output{};
            result = ::FileTimeToSystemTime(&input, &output);
            if (result != FALSE) {
                cpu.memory().write(destination, std::span<const std::uint8_t>(
                                                    reinterpret_cast<const std::uint8_t *>(&output),
                                                    sizeof(output)));
            }
        } else {
            SYSTEMTIME input{};
            const auto bytes = cpu.memory().read(source, sizeof(input));
            std::memcpy(&input, bytes.data(), sizeof(input));
            FILETIME output{};
            result = ::SystemTimeToFileTime(&input, &output);
            if (result != FALSE) {
                cpu.memory().write32(destination, output.dwLowDateTime);
                cpu.memory().write32(destination + 4, output.dwHighDateTime);
            }
        }
        if (result == FALSE) {
            last_error_ = ::GetLastError();
        }
        cpu.set_reg(Rax, result != FALSE);
        finish_call(2);
        break;
    }
    case Api::TimeZoneInformation: {
        TIME_ZONE_INFORMATION information{};
        const auto result = ::GetTimeZoneInformation(&information);
        if (result == TIME_ZONE_ID_INVALID) {
            last_error_ = ::GetLastError();
        } else {
            cpu.memory().write(
                argument(0),
                std::span<const std::uint8_t>(reinterpret_cast<const std::uint8_t *>(&information),
                                              sizeof(information)));
        }
        cpu.set_reg(Rax, result);
        finish_call(1);
        break;
    }
    case Api::GetCurrentProcessId:
        cpu.set_reg(Rax, ::GetCurrentProcessId());
        finish_call();
        break;
    case Api::GetCurrentThreadId:
        cpu.set_reg(Rax, ::GetCurrentThreadId());
        finish_call();
        break;
    case Api::StartupInfo: {
        const auto destination = argument(0);
        STARTUPINFOW native{};
        native.cb = sizeof(native);
        ::GetStartupInfoW(&native);
        if (!guest_is_64_bit_) {
            constexpr std::uint32_t guest_size = 68;
            for (std::uint32_t offset = 0; offset < guest_size; offset += 4) {
                cpu.memory().write32(destination + offset, 0);
            }
            cpu.memory().write32(destination, guest_size);
            cpu.memory().write32(destination + 16, native.dwX);
            cpu.memory().write32(destination + 20, native.dwY);
            cpu.memory().write32(destination + 24, native.dwXSize);
            cpu.memory().write32(destination + 28, native.dwYSize);
            cpu.memory().write32(destination + 32, native.dwXCountChars);
            cpu.memory().write32(destination + 36, native.dwYCountChars);
            cpu.memory().write32(destination + 40, native.dwFillAttribute);
            cpu.memory().write32(destination + 44, native.dwFlags);
            cpu.memory().write16(destination + 48, native.wShowWindow);
        } else {
            constexpr std::uint32_t guest_size = 104;
            for (std::uint32_t offset = 0; offset < guest_size; offset += 8) {
                cpu.memory().write64(destination + offset, 0);
            }
            cpu.memory().write32(destination, guest_size);
            cpu.memory().write32(destination + 32, native.dwX);
            cpu.memory().write32(destination + 36, native.dwY);
            cpu.memory().write32(destination + 40, native.dwXSize);
            cpu.memory().write32(destination + 44, native.dwYSize);
            cpu.memory().write32(destination + 48, native.dwXCountChars);
            cpu.memory().write32(destination + 52, native.dwYCountChars);
            cpu.memory().write32(destination + 56, native.dwFillAttribute);
            cpu.memory().write32(destination + 60, native.dwFlags);
            cpu.memory().write16(destination + 64, native.wShowWindow);
        }
        finish_call(1);
        break;
    }
    case Api::CriticalSectionInitialize: {
        const auto destination = argument(0);
        const auto size = guest_is_64_bit_ ? 40U : 24U;
        for (unsigned offset = 0; offset < size; offset += 4) {
            cpu.memory().write32(destination + offset, 0);
        }
        cpu.memory().write32(destination + (guest_is_64_bit_ ? 8U : 4U), UINT32_MAX);
        const bool returns_status = thunk_name.ends_with("InitializeCriticalSectionAndSpinCount");
        if (returns_status) {
            cpu.set_reg(Rax, 1);
        }
        finish_call(returns_status ? 2 : 1);
        break;
    }
    case Api::CriticalSectionOperation:
        finish_call(1);
        break;
    case Api::CriticalSectionTry:
        cpu.set_reg(Rax, 1);
        finish_call(1);
        break;
    case Api::InterlockedOperation: {
        const auto destination = argument(0);
        const bool wide =
            thunk_name.ends_with("64") || (guest_is_64_bit_ && thunk_name.ends_with("Pointer"));
        const auto old_value =
            wide ? cpu.memory().read64(destination) : cpu.memory().read32(destination);
        std::uint64_t new_value = old_value;
        unsigned argument_count = 1;
        if (thunk_name.find("Increment") != std::string::npos) {
            new_value = old_value + 1;
        } else if (thunk_name.find("Decrement") != std::string::npos) {
            new_value = old_value - 1;
        } else if (thunk_name.find("CompareExchange") != std::string::npos) {
            argument_count = 3;
            if (old_value == argument(2)) {
                new_value = argument(1);
            }
        } else {
            argument_count = 2;
            const auto operand = argument(1);
            if (thunk_name.find("ExchangeAdd") != std::string::npos) {
                new_value = old_value + operand;
            } else if (thunk_name.find("Exchange") != std::string::npos) {
                new_value = operand;
            } else if (thunk_name.find("InterlockedAnd") != std::string::npos) {
                new_value = old_value & operand;
            } else if (thunk_name.find("InterlockedOr") != std::string::npos) {
                new_value = old_value | operand;
            } else {
                new_value = old_value ^ operand;
            }
        }
        if (wide) {
            cpu.memory().write64(destination, new_value);
        } else {
            new_value &= UINT32_MAX;
            cpu.memory().write32(destination, static_cast<std::uint32_t>(new_value));
        }
        const bool returns_new = thunk_name.find("Increment") != std::string::npos ||
                                 thunk_name.find("Decrement") != std::string::npos;
        cpu.set_reg(Rax, returns_new ? new_value : old_value);
        finish_call(argument_count);
        break;
    }
    case Api::GetProcessWindowStation:
        // A stable opaque guest handle is sufficient for the single process/window-station model.
        cpu.set_reg(Rax, 0x201);
        finish_call();
        break;
    case Api::UserObjectInformation: {
        constexpr std::uint32_t uoi_flags = 1;
        constexpr std::uint32_t uoi_name = 2;
        constexpr std::uint32_t uoi_type = 3;
        constexpr std::uint32_t error_invalid_handle = 6;
        constexpr std::uint32_t error_invalid_parameter = 87;
        constexpr std::uint32_t error_insufficient_buffer = 122;
        const auto handle = argument(0);
        const auto index = static_cast<std::uint32_t>(argument(1));
        const auto destination = argument(2);
        const auto destination_size = static_cast<std::uint32_t>(argument(3));
        const auto required_size_pointer = argument(4);
        std::vector<std::uint8_t> value;
        if (index == uoi_flags) {
            value.resize(12);
        } else if (index == uoi_name || index == uoi_type) {
            const std::string text = index == uoi_name ? "WinSta0" : "WindowStation";
            if (thunk_name.ends_with("W")) {
                value.resize((text.size() + 1) * sizeof(char16_t));
                for (std::size_t i = 0; i < text.size(); ++i) {
                    value[i * 2] = static_cast<std::uint8_t>(text[i]);
                }
            } else {
                value.assign(text.begin(), text.end());
                value.push_back(0);
            }
        } else {
            last_error_ = error_invalid_parameter;
            cpu.set_reg(Rax, 0);
            finish_call(5);
            break;
        }
        if (required_size_pointer != 0) {
            cpu.memory().write32(required_size_pointer, static_cast<std::uint32_t>(value.size()));
        }
        if (handle != 0x201) {
            last_error_ = error_invalid_handle;
            cpu.set_reg(Rax, 0);
        } else if (destination == 0 || destination_size < value.size()) {
            last_error_ = error_insufficient_buffer;
            cpu.set_reg(Rax, 0);
        } else {
            cpu.memory().write(destination, value);
            cpu.set_reg(Rax, 1);
        }
        finish_call(5);
        break;
    }
    case Api::GuestMessageBox: {
        const auto text_pointer = argument(1);
        const auto caption_pointer = argument(2);
        const auto read_text = [&](std::uint64_t pointer) {
            if (pointer == 0) {
                return std::string{};
            }
            if (thunk_name.ends_with("W")) {
                return narrow_string(cpu.memory().read_wide_string(pointer));
            }
            return cpu.memory().read_c_string(pointer);
        };
        log::info("guest",
                  "MessageBox: " + read_text(caption_pointer) + ": " + read_text(text_pointer));
        cpu.set_reg(Rax, IDOK);
        finish_call(4);
        break;
    }
    case Api::GuestMessageLoop: {
        const auto read_message = [&](std::uint64_t address) {
            MSG message{};
            if (guest_is_64_bit_) {
                message.hwnd = reinterpret_cast<HWND>(cpu.memory().read64(address));
                message.message = cpu.memory().read32(address + 8);
                message.wParam = cpu.memory().read64(address + 16);
                message.lParam = static_cast<LPARAM>(cpu.memory().read64(address + 24));
                message.time = cpu.memory().read32(address + 32);
                message.pt.x = static_cast<LONG>(cpu.memory().read32(address + 36));
                message.pt.y = static_cast<LONG>(cpu.memory().read32(address + 40));
            } else {
                message.hwnd = reinterpret_cast<HWND>(cpu.memory().read32(address));
                message.message = cpu.memory().read32(address + 4);
                message.wParam = cpu.memory().read32(address + 8);
                message.lParam = static_cast<std::int32_t>(cpu.memory().read32(address + 12));
                message.time = cpu.memory().read32(address + 16);
                message.pt.x = static_cast<LONG>(cpu.memory().read32(address + 20));
                message.pt.y = static_cast<LONG>(cpu.memory().read32(address + 24));
            }
            return message;
        };
        const auto write_message = [&](std::uint64_t address, const MSG &message) {
            const auto size = guest_is_64_bit_ ? 48U : 28U;
            cpu.memory().write(address, std::vector<std::uint8_t>(size));
            if (guest_is_64_bit_) {
                cpu.memory().write64(address, reinterpret_cast<std::uint64_t>(message.hwnd));
                cpu.memory().write32(address + 8, message.message);
                cpu.memory().write64(address + 16, message.wParam);
                cpu.memory().write64(address + 24, static_cast<std::uint64_t>(message.lParam));
                cpu.memory().write32(address + 32, message.time);
                cpu.memory().write32(address + 36, static_cast<std::uint32_t>(message.pt.x));
                cpu.memory().write32(address + 40, static_cast<std::uint32_t>(message.pt.y));
            } else {
                cpu.memory().write32(address, static_cast<std::uint32_t>(
                                                  reinterpret_cast<std::uintptr_t>(message.hwnd)));
                cpu.memory().write32(address + 4, message.message);
                cpu.memory().write32(address + 8, static_cast<std::uint32_t>(message.wParam));
                cpu.memory().write32(address + 12, static_cast<std::uint32_t>(message.lParam));
                cpu.memory().write32(address + 16, message.time);
                cpu.memory().write32(address + 20, static_cast<std::uint32_t>(message.pt.x));
                cpu.memory().write32(address + 24, static_cast<std::uint32_t>(message.pt.y));
            }
        };
        if (thunk_name.ends_with("!PostQuitMessage")) {
            quit_message_pending_ = true;
            quit_message_code_ = static_cast<std::uint32_t>(argument(0));
            finish_call(1);
            break;
        }
        if (thunk_name.ends_with("!TranslateMessage")) {
            const auto message = read_message(argument(0));
            cpu.set_reg(Rax, ::TranslateMessage(&message) != FALSE ? 1 : 0);
            finish_call(1);
            break;
        }
        if (thunk_name.ends_with("!DispatchMessageA") ||
            thunk_name.ends_with("!DispatchMessageW")) {
            const auto message = read_message(argument(0));
            const auto result = thunk_name.ends_with("W") ? ::DispatchMessageW(&message)
                                                          : ::DispatchMessageA(&message);
            if (callback_exception != nullptr) {
                auto exception = callback_exception;
                callback_exception = nullptr;
                std::rethrow_exception(exception);
            }
            cpu.set_reg(Rax, static_cast<std::uint64_t>(result));
            finish_call(1);
            break;
        }
        MSG message{};
        const auto window = reinterpret_cast<HWND>(static_cast<std::uintptr_t>(argument(1)));
        int result = 0;
        if (quit_message_pending_) {
            message.message = WM_QUIT;
            message.wParam = quit_message_code_;
            write_message(argument(0), message);
            const bool get_message =
                thunk_name.ends_with("!GetMessageA") || thunk_name.ends_with("!GetMessageW");
            if (get_message || (static_cast<UINT>(argument(4)) & PM_REMOVE) != 0) {
                quit_message_pending_ = false;
            }
            cpu.set_reg(Rax, 0);
            finish_call(get_message ? 4 : 5);
            break;
        }
        if (thunk_name.ends_with("!PeekMessageA") || thunk_name.ends_with("!PeekMessageW")) {
            // Keep CPUEmu's own host-thread messages out of the guest queue. Native
            // PeekMessage can synchronously dispatch sent messages even when it returns zero.
            if (!window_procedures_.empty()) {
                result = thunk_name.ends_with("W")
                             ? ::PeekMessageW(&message, window, static_cast<UINT>(argument(2)),
                                              static_cast<UINT>(argument(3)),
                                              static_cast<UINT>(argument(4)))
                             : ::PeekMessageA(&message, window, static_cast<UINT>(argument(2)),
                                              static_cast<UINT>(argument(3)),
                                              static_cast<UINT>(argument(4)));
            }
            if (result != 0) {
                write_message(argument(0), message);
            }
            cpu.set_reg(Rax, static_cast<std::uint32_t>(result));
            finish_call(5);
        } else {
            result = thunk_name.ends_with("W")
                         ? ::GetMessageW(&message, window, static_cast<UINT>(argument(2)),
                                         static_cast<UINT>(argument(3)))
                         : ::GetMessageA(&message, window, static_cast<UINT>(argument(2)),
                                         static_cast<UINT>(argument(3)));
            if (result >= 0) {
                write_message(argument(0), message);
            } else {
                last_error_ = ::GetLastError();
            }
            cpu.set_reg(Rax, static_cast<std::uint32_t>(result));
            finish_call(4);
        }
        break;
    }
    case Api::GuestFileDialog: {
        // Treat an unavailable interactive host dialog as a user cancellation. The Win32
        // contract distinguishes this from an error by returning zero here and from
        // CommDlgExtendedError, while keeping guest-owned pointers and hooks off the host.
        if (!thunk_name.ends_with("!CommDlgExtendedError") && argument(0) != 0) {
            const auto structure = argument(0);
            const bool wide = thunk_name.ends_with("W");
            const auto read_dialog_string = [&](std::uint32_t offset32, std::uint32_t offset64) {
                const auto pointer = guest_is_64_bit_ ? cpu.memory().read64(structure + offset64)
                                                      : cpu.memory().read32(structure + offset32);
                if (pointer == 0) {
                    return std::string{};
                }
                return wide ? narrow_string(cpu.memory().read_wide_string(pointer))
                            : cpu.memory().read_c_string(pointer);
            };
            log::api("dialog",
                     "file='" + read_dialog_string(28, 48) + "' initial-dir='" +
                         read_dialog_string(44, 80) + "' title='" + read_dialog_string(48, 88) +
                         "' flags=" +
                         log::hex(cpu.memory().read32(structure + (guest_is_64_bit_ ? 96 : 52))));
        }
        cpu.set_reg(Rax, 0);
        finish_call(thunk_name.ends_with("!CommDlgExtendedError") ? 0 : 1);
        break;
    }
    case Api::CommonControlsInitialize: {
        struct CommonControls {
            DWORD size;
            DWORD classes;
        } controls{cpu.memory().read32(argument(0)), cpu.memory().read32(argument(0) + 4)};
        using Initialize = BOOL(WINAPI *)(const CommonControls *);
        const auto library = ::LoadLibraryW(L"comctl32.dll");
        const auto initialize =
            library == nullptr
                ? nullptr
                : reinterpret_cast<Initialize>(::GetProcAddress(library, "InitCommonControlsEx"));
        const auto result = initialize != nullptr && initialize(&controls) != FALSE;
        if (!result) {
            last_error_ = ::GetLastError();
        }
        cpu.set_reg(Rax, result ? 1 : 0);
        finish_call(1);
        break;
    }
    case Api::GdiplusStartup: {
        struct StartupInput {
            std::uint32_t version;
            void *debug_callback;
            BOOL suppress_background_thread;
            BOOL suppress_external_codecs;
        } input{cpu.memory().read32(argument(1)), nullptr, FALSE,
                static_cast<BOOL>(cpu.memory().read32(argument(1) + (guest_is_64_bit_ ? 20 : 12)))};
        // Guest callbacks can never be retained by native GDI+. Keep the native background thread
        // enabled even if the guest requested callback-driven notification hooks.
        using Startup = int(WINAPI *)(std::uint64_t *, const StartupInput *, void *);
        const auto library = ::LoadLibraryW(L"gdiplus.dll");
        const auto startup =
            library == nullptr
                ? nullptr
                : reinterpret_cast<Startup>(::GetProcAddress(library, "GdiplusStartup"));
        std::uint64_t token = 0;
        const auto status = startup == nullptr ? 1 : startup(&token, &input, nullptr);
        if (status == 0) {
            host_gdiplus_token_ = token;
            if (guest_is_64_bit_) {
                cpu.memory().write64(argument(0), 0x500);
            } else {
                cpu.memory().write32(argument(0), 0x500);
            }
            if (argument(2) != 0) {
                const auto output_size = guest_is_64_bit_ ? 16U : 8U;
                cpu.memory().write(argument(2), std::vector<std::uint8_t>(output_size));
            }
        }
        cpu.set_reg(Rax, static_cast<std::uint32_t>(status));
        finish_call(3);
        break;
    }
    case Api::GdiplusShutdown:
        if (host_gdiplus_token_ != 0) {
            if (const auto library = ::LoadLibraryW(L"gdiplus.dll"); library != nullptr) {
                using Shutdown = void(WINAPI *)(std::uint64_t);
                if (const auto shutdown =
                        reinterpret_cast<Shutdown>(::GetProcAddress(library, "GdiplusShutdown"));
                    shutdown != nullptr) {
                    shutdown(host_gdiplus_token_);
                }
            }
            host_gdiplus_token_ = 0;
        }
        finish_call(1);
        break;
    case Api::SteamRestartApp:
        // CPUEmu cannot safely hand the guest process to the native Steam client. Reporting that
        // no restart is required is Steamworks' documented offline-friendly continuation path.
        cpu.set_reg(Rax, 0);
        finish_call();
        break;
    case Api::SteamInitialize:
        // Report offline initialization failure instead of loading native Steamworks objects,
        // which retain callbacks and return host-owned interface pointers.
        cpu.set_reg(Rax, 0);
        finish_call();
        break;
    case Api::OutputDebugStringA:
        log::info("guest", "OutputDebugStringA: " + cpu.memory().read_c_string(cpu.reg(Rcx)));
        finish_call();
        break;
    case Api::Beep:
        cpu.set_reg(Rax, ::Beep(static_cast<DWORD>(cpu.reg(Rcx)),
                                static_cast<DWORD>(cpu.reg(Rdx))) != FALSE);
        finish_call();
        break;
    case Api::MessageBeep:
        cpu.set_reg(Rax, ::MessageBeep(static_cast<UINT>(cpu.reg(Rcx))) != FALSE);
        finish_call();
        break;
    case Api::PlaySoundA:
    case Api::PlaySoundW:
    case Api::SndPlaySoundA:
    case Api::SndPlaySoundW: {
        const bool legacy =
            found->second == Api::SndPlaySoundA || found->second == Api::SndPlaySoundW;
        const bool wide = found->second == Api::PlaySoundW || found->second == Api::SndPlaySoundW;
        const auto sound = cpu.reg(Rcx);
        const auto module = legacy ? 0 : cpu.reg(Rdx);
        const auto requested_flags = static_cast<DWORD>(legacy ? cpu.reg(Rdx) : cpu.reg(R8));
        constexpr DWORD retained_or_pointer_flags =
            sound_async | sound_loop | sound_memory | sound_resource;
        if (module != 0 || (requested_flags & retained_or_pointer_flags) != 0) {
            // Async playback can retain the name pointer, while memory/resource modes interpret
            // the argument as non-string host data. Both require guest-owned lifetime adapters.
            cpu.set_reg(Rax, 0);
        } else if (sound == 0) {
            cpu.set_reg(Rax, ::PlaySoundW(nullptr, nullptr, 0) != FALSE);
        } else if (wide) {
            const auto name = cpu.memory().read_wide_string(sound);
            cpu.set_reg(Rax, ::PlaySoundW(name.c_str(), nullptr, requested_flags) != FALSE);
        } else {
            const auto name = cpu.memory().read_c_string(sound);
            cpu.set_reg(Rax, ::PlaySoundA(name.c_str(), nullptr, requested_flags) != FALSE);
        }
        finish_call();
        break;
    }
    case Api::GetTickCount:
        cpu.set_reg(Rax, ::GetTickCount());
        finish_call();
        break;
    case Api::GetTickCount64:
        cpu.set_reg(Rax, ::GetTickCount64());
        finish_call();
        break;
    case Api::QueryPerformanceCounter:
    case Api::QueryPerformanceFrequency: {
        LARGE_INTEGER value{};
        const auto success = found->second == Api::QueryPerformanceCounter
                                 ? ::QueryPerformanceCounter(&value)
                                 : ::QueryPerformanceFrequency(&value);
        if (success != FALSE) {
            cpu.memory().write64(argument(0), static_cast<std::uint64_t>(value.QuadPart));
        }
        cpu.set_reg(Rax, success != FALSE);
        finish_call(1);
        break;
    }
    case Api::Sleep:
        ::Sleep(static_cast<DWORD>(argument(0)));
        cpu.set_reg(Rax, 0);
        finish_call(1);
        break;
    case Api::TimeGetTime:
        cpu.set_reg(Rax, ::timeGetTime());
        finish_call();
        break;
    case Api::TimeBeginPeriod:
        cpu.set_reg(Rax, ::timeBeginPeriod(static_cast<UINT>(argument(0))));
        finish_call(1);
        break;
    case Api::TimeEndPeriod:
        cpu.set_reg(Rax, ::timeEndPeriod(static_cast<UINT>(argument(0))));
        finish_call(1);
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
        finish_call(
            thunk_name.find("_cexit") != std::string::npos ||
                    thunk_name.find("_c_exit") != std::string::npos
                ? 0
            : thunk_name.ends_with("EventWriteTransfer")  ? 6
            : thunk_name.ends_with("EventSetInformation") ? 4
            : thunk_name.ends_with("CreateProcessAsUserW") ||
                    thunk_name.ends_with("CreateProcessAsUserA")
                ? 11
            : thunk_name.ends_with("CreateProcessW") || thunk_name.ends_with("CreateProcessA") ? 10
            : thunk_name.ends_with("AddVectoredExceptionHandler") ||
                    thunk_name.ends_with("AddVectoredContinueHandler")
                ? 2
                : 1);
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
        guest_exception_filter_ = argument(0);
        cpu.set_reg(Rax, previous);
        finish_call(1);
        break;
    }
    case Api::GetCommandLineW:
        cpu.set_reg(Rax, guest_command_line_);
        finish_call();
        break;
    case Api::GetCommandLineA:
        cpu.set_reg(Rax, guest_command_line_a_);
        finish_call();
        break;
    case Api::WideCharConversion: {
        const auto code_page = static_cast<UINT>(argument(0));
        const auto flags = static_cast<DWORD>(argument(1));
        const auto source = argument(2);
        const auto source_count = static_cast<std::int32_t>(argument(3));
        const auto destination = argument(4);
        const auto destination_count = static_cast<int>(argument(5));
        const auto default_pointer = argument(6);
        const auto used_default_pointer = argument(7);
        std::wstring source_text;
        if (source_count == -1) {
            source_text = cpu.memory().read_wide_string(source);
            source_text.push_back(L'\0');
        } else if (source_count >= 0) {
            const auto bytes =
                cpu.memory().read(source, static_cast<std::size_t>(source_count) * 2);
            source_text.resize(static_cast<std::size_t>(source_count));
            std::memcpy(source_text.data(), bytes.data(), bytes.size());
        }
        char default_character = 0;
        const char *default_character_pointer = nullptr;
        if (default_pointer != 0) {
            default_character = static_cast<char>(cpu.memory().read8(default_pointer));
            default_character_pointer = &default_character;
        }
        BOOL used_default = FALSE;
        std::vector<char> converted(destination_count > 0 ? destination_count : 0);
        const auto result =
            source_count < -1 || destination_count < 0
                ? 0
                : ::WideCharToMultiByte(code_page, flags, source_text.data(), source_count,
                                        converted.empty() ? nullptr : converted.data(),
                                        destination_count, default_character_pointer,
                                        used_default_pointer == 0 ? nullptr : &used_default);
        if (result == 0) {
            last_error_ = source_count < -1 || destination_count < 0 ? ERROR_INVALID_PARAMETER
                                                                     : ::GetLastError();
        } else if (destination != 0) {
            cpu.memory().write(destination,
                               std::span<const std::uint8_t>(
                                   reinterpret_cast<const std::uint8_t *>(converted.data()),
                                   static_cast<std::size_t>(result)));
        }
        if (used_default_pointer != 0) {
            cpu.memory().write32(used_default_pointer, used_default != FALSE);
        }
        cpu.set_reg(Rax, static_cast<std::uint32_t>(result));
        finish_call(8);
        break;
    }
    case Api::MultiByteConversion: {
        const auto code_page = static_cast<UINT>(argument(0));
        const auto flags = static_cast<DWORD>(argument(1));
        const auto source = argument(2);
        const auto source_count = static_cast<std::int32_t>(argument(3));
        const auto destination = argument(4);
        const auto destination_count = static_cast<int>(argument(5));
        std::string source_text;
        if (source_count == -1) {
            source_text = cpu.memory().read_c_string(source);
            source_text.push_back('\0');
        } else if (source_count >= 0) {
            const auto bytes = cpu.memory().read(source, static_cast<std::size_t>(source_count));
            source_text.assign(reinterpret_cast<const char *>(bytes.data()), bytes.size());
        }
        std::vector<wchar_t> converted(destination_count > 0 ? destination_count : 0);
        const auto result =
            source_count < -1 || destination_count < 0
                ? 0
                : ::MultiByteToWideChar(code_page, flags, source_text.data(), source_count,
                                        converted.empty() ? nullptr : converted.data(),
                                        destination_count);
        if (result == 0) {
            last_error_ = source_count < -1 || destination_count < 0 ? ERROR_INVALID_PARAMETER
                                                                     : ::GetLastError();
        } else if (destination != 0) {
            cpu.memory().write(destination,
                               std::span<const std::uint8_t>(
                                   reinterpret_cast<const std::uint8_t *>(converted.data()),
                                   static_cast<std::size_t>(result) * sizeof(wchar_t)));
        }
        cpu.set_reg(Rax, static_cast<std::uint32_t>(result));
        finish_call(6);
        break;
    }
    case Api::GuestStringType: {
        const bool ansi = thunk_name.ends_with("GetStringTypeA");
        const auto information_type = static_cast<DWORD>(argument(ansi ? 1 : 0));
        const auto source = argument(ansi ? 2 : 1);
        const auto source_count = static_cast<std::int32_t>(argument(ansi ? 3 : 2));
        const auto destination = argument(ansi ? 4 : 3);
        const auto character_count = source_count == -1
                                         ? (ansi ? cpu.memory().read_c_string(source).size() + 1
                                                 : cpu.memory().read_wide_string(source).size() + 1)
                                         : static_cast<std::size_t>(std::max(source_count, 0));
        std::vector<WORD> types(character_count);
        BOOL result = FALSE;
        if (source_count >= -1 && destination != 0) {
            if (ansi) {
                auto text = cpu.memory().read_c_string(source);
                if (source_count >= 0) {
                    const auto bytes = cpu.memory().read(source, character_count);
                    text.assign(reinterpret_cast<const char *>(bytes.data()), bytes.size());
                }
                result = ::GetStringTypeA(static_cast<LCID>(argument(0)), information_type,
                                          text.c_str(), source_count, types.data());
            } else {
                auto text = cpu.memory().read_wide_string(source);
                if (source_count >= 0) {
                    const auto bytes = cpu.memory().read(source, character_count * 2);
                    text.resize(character_count);
                    std::memcpy(text.data(), bytes.data(), bytes.size());
                }
                result =
                    ::GetStringTypeW(information_type, text.c_str(), source_count, types.data());
            }
        }
        if (result != FALSE) {
            cpu.memory().write(
                destination,
                std::span<const std::uint8_t>(reinterpret_cast<const std::uint8_t *>(types.data()),
                                              types.size() * sizeof(WORD)));
        } else {
            last_error_ =
                source_count < -1 || destination == 0 ? ERROR_INVALID_PARAMETER : ::GetLastError();
        }
        cpu.set_reg(Rax, result != FALSE);
        finish_call(ansi ? 5 : 4);
        break;
    }
    case Api::GuestMapString: {
        const bool ansi = thunk_name.ends_with("LCMapStringA");
        const auto locale = static_cast<LCID>(argument(0));
        const auto flags = static_cast<DWORD>(argument(1));
        const auto source = argument(2);
        const auto source_count = static_cast<std::int32_t>(argument(3));
        const auto destination = argument(4);
        const auto destination_count = static_cast<int>(argument(5));
        int result = 0;
        std::vector<std::uint8_t> output;
        if (source_count >= -1 && destination_count >= 0) {
            if (ansi) {
                auto text = cpu.memory().read_c_string(source);
                if (source_count >= 0) {
                    const auto bytes = cpu.memory().read(source, source_count);
                    text.assign(reinterpret_cast<const char *>(bytes.data()), bytes.size());
                }
                output.resize(static_cast<std::size_t>(destination_count));
                result = ::LCMapStringA(locale, flags, text.c_str(), source_count,
                                        output.empty() ? nullptr
                                                       : reinterpret_cast<char *>(output.data()),
                                        destination_count);
            } else {
                auto text = cpu.memory().read_wide_string(source);
                if (source_count >= 0) {
                    const auto bytes = cpu.memory().read(source, source_count * 2ULL);
                    text.resize(static_cast<std::size_t>(source_count));
                    std::memcpy(text.data(), bytes.data(), bytes.size());
                }
                const bool sort_key = (flags & LCMAP_SORTKEY) != 0;
                output.resize(static_cast<std::size_t>(destination_count) *
                              (sort_key ? 1U : sizeof(wchar_t)));
                result = ::LCMapStringW(locale, flags, text.c_str(), source_count,
                                        output.empty() ? nullptr
                                                       : reinterpret_cast<wchar_t *>(output.data()),
                                        destination_count);
                if (!sort_key && result > 0) {
                    output.resize(static_cast<std::size_t>(result) * sizeof(wchar_t));
                } else if (result > 0) {
                    output.resize(static_cast<std::size_t>(result));
                }
            }
        }
        if (result == 0) {
            last_error_ = source_count < -1 || destination_count < 0 ? ERROR_INVALID_PARAMETER
                                                                     : ::GetLastError();
        } else if (destination != 0) {
            if (ansi) {
                output.resize(static_cast<std::size_t>(result));
            }
            cpu.memory().write(destination, output);
        }
        cpu.set_reg(Rax, static_cast<std::uint32_t>(result));
        finish_call(6);
        break;
    }
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
    case Api::EnvironmentVariable: {
        const bool ansi = thunk_name.ends_with("GetEnvironmentVariableA");
        const auto capacity = static_cast<DWORD>(argument(2));
        DWORD result = 0;
        ::SetLastError(ERROR_SUCCESS);
        if (ansi) {
            const auto name = cpu.memory().read_c_string(argument(0));
            std::vector<char> value(capacity);
            result = ::GetEnvironmentVariableA(name.c_str(), value.empty() ? nullptr : value.data(),
                                               capacity);
            if (result != 0 && result < capacity) {
                cpu.memory().write(argument(1),
                                   std::span<const std::uint8_t>(
                                       reinterpret_cast<const std::uint8_t *>(value.data()),
                                       static_cast<std::size_t>(result) + 1));
            }
        } else {
            const auto name = cpu.memory().read_wide_string(argument(0));
            std::vector<wchar_t> value(capacity);
            result = ::GetEnvironmentVariableW(name.c_str(), value.empty() ? nullptr : value.data(),
                                               capacity);
            if (result != 0 && result < capacity) {
                cpu.memory().write(argument(1),
                                   std::span<const std::uint8_t>(
                                       reinterpret_cast<const std::uint8_t *>(value.data()),
                                       (static_cast<std::size_t>(result) + 1) * sizeof(wchar_t)));
            }
        }
        if (result == 0) {
            last_error_ = ::GetLastError();
        }
        cpu.set_reg(Rax, result);
        finish_call(3);
        break;
    }
    case Api::EnvironmentExpansion: {
        const bool wide = thunk_name.ends_with("W");
        const auto capacity = static_cast<DWORD>(argument(2));
        DWORD result = 0;
        if (wide) {
            const auto source = cpu.memory().read_wide_string(argument(0));
            std::vector<wchar_t> buffer(std::max<DWORD>(capacity, 1));
            result = ::ExpandEnvironmentStringsW(source.c_str(),
                                                 capacity == 0 ? nullptr : buffer.data(), capacity);
            if (result != 0 && result <= capacity) {
                cpu.memory().write(argument(1),
                                   std::span<const std::uint8_t>(
                                       reinterpret_cast<const std::uint8_t *>(buffer.data()),
                                       static_cast<std::size_t>(result) * sizeof(wchar_t)));
            }
        } else {
            const auto source = cpu.memory().read_c_string(argument(0));
            std::vector<char> buffer(std::max<DWORD>(capacity, 1));
            result = ::ExpandEnvironmentStringsA(source.c_str(),
                                                 capacity == 0 ? nullptr : buffer.data(), capacity);
            if (result != 0 && result <= capacity) {
                cpu.memory().write(
                    argument(1),
                    std::span<const std::uint8_t>(
                        reinterpret_cast<const std::uint8_t *>(buffer.data()), result));
            }
        }
        if (result == 0) {
            last_error_ = ::GetLastError();
        }
        cpu.set_reg(Rax, result);
        finish_call(3);
        break;
    }
    case Api::FullPathName: {
        const bool wide = thunk_name.ends_with("W");
        const auto capacity = static_cast<DWORD>(argument(1));
        const auto destination = argument(2);
        DWORD result = 0;
        std::size_t file_part_offset = 0;
        bool has_file_part = false;
        if (wide) {
            const auto input = cpu.memory().read_wide_string(argument(0));
            std::vector<wchar_t> buffer(std::max<DWORD>(capacity, 1));
            wchar_t *file_part = nullptr;
            result = ::GetFullPathNameW(input.c_str(), capacity,
                                        capacity == 0 ? nullptr : buffer.data(), &file_part);
            if (result != 0 && result < capacity) {
                cpu.memory().write(destination,
                                   std::span<const std::uint8_t>(
                                       reinterpret_cast<const std::uint8_t *>(buffer.data()),
                                       (static_cast<std::size_t>(result) + 1) * sizeof(wchar_t)));
                if (file_part != nullptr) {
                    file_part_offset = static_cast<std::size_t>(file_part - buffer.data()) * 2;
                    has_file_part = true;
                }
            }
        } else {
            const auto input = cpu.memory().read_c_string(argument(0));
            std::vector<char> buffer(std::max<DWORD>(capacity, 1));
            char *file_part = nullptr;
            result = ::GetFullPathNameA(input.c_str(), capacity,
                                        capacity == 0 ? nullptr : buffer.data(), &file_part);
            if (result != 0 && result < capacity) {
                cpu.memory().write(
                    destination,
                    std::span<const std::uint8_t>(
                        reinterpret_cast<const std::uint8_t *>(buffer.data()), result + 1));
                if (file_part != nullptr) {
                    file_part_offset = static_cast<std::size_t>(file_part - buffer.data());
                    has_file_part = true;
                }
            }
        }
        if (result == 0) {
            last_error_ = ::GetLastError();
        }
        if (argument(3) != 0 && result != 0 && result < capacity) {
            const auto guest_file_part = has_file_part ? destination + file_part_offset : 0;
            if (guest_is_64_bit_) {
                cpu.memory().write64(argument(3), guest_file_part);
            } else {
                cpu.memory().write32(argument(3), static_cast<std::uint32_t>(guest_file_part));
            }
        }
        cpu.set_reg(Rax, result);
        finish_call(4);
        break;
    }
    case Api::CurrentDirectory: {
        const bool get = thunk_name.find("!GetCurrentDirectory") != std::string::npos;
        const bool wide = thunk_name.ends_with("W");
        if (!get) {
            const auto result =
                wide ? ::SetCurrentDirectoryW(cpu.memory().read_wide_string(argument(0)).c_str())
                     : ::SetCurrentDirectoryA(cpu.memory().read_c_string(argument(0)).c_str());
            if (result == FALSE) {
                last_error_ = ::GetLastError();
            }
            cpu.set_reg(Rax, result != FALSE ? 1 : 0);
            finish_call(1);
            break;
        }
        const auto capacity = static_cast<DWORD>(argument(0));
        DWORD result = 0;
        if (wide) {
            std::vector<wchar_t> buffer(std::max<DWORD>(capacity, 1));
            result = ::GetCurrentDirectoryW(capacity, capacity == 0 ? nullptr : buffer.data());
            if (result != 0 && result < capacity) {
                cpu.memory().write(argument(1),
                                   std::span<const std::uint8_t>(
                                       reinterpret_cast<const std::uint8_t *>(buffer.data()),
                                       (static_cast<std::size_t>(result) + 1) * sizeof(wchar_t)));
            }
        } else {
            std::vector<char> buffer(std::max<DWORD>(capacity, 1));
            result = ::GetCurrentDirectoryA(capacity, capacity == 0 ? nullptr : buffer.data());
            if (result != 0 && result < capacity) {
                cpu.memory().write(
                    argument(1),
                    std::span<const std::uint8_t>(
                        reinterpret_cast<const std::uint8_t *>(buffer.data()), result + 1));
            }
        }
        if (result == 0) {
            last_error_ = ::GetLastError();
        }
        cpu.set_reg(Rax, result);
        finish_call(2);
        break;
    }
    case Api::FileAttributes: {
        const bool get = thunk_name.find("!GetFileAttributes") != std::string::npos;
        const bool wide = thunk_name.ends_with("W");
        const auto ansi_path = wide ? std::string{} : cpu.memory().read_c_string(argument(0));
        const auto wide_path = wide ? cpu.memory().read_wide_string(argument(0)) : std::wstring{};
        if (get) {
            const auto result = wide ? ::GetFileAttributesW(wide_path.c_str())
                                     : ::GetFileAttributesA(ansi_path.c_str());
            if (result == INVALID_FILE_ATTRIBUTES) {
                last_error_ = ::GetLastError();
            }
            cpu.set_reg(Rax, result);
            finish_call(1);
        } else {
            const auto attributes = static_cast<DWORD>(argument(1));
            const auto result = wide ? ::SetFileAttributesW(wide_path.c_str(), attributes)
                                     : ::SetFileAttributesA(ansi_path.c_str(), attributes);
            if (result == FALSE) {
                last_error_ = ::GetLastError();
            }
            cpu.set_reg(Rax, result != FALSE ? 1 : 0);
            finish_call(2);
        }
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
        finish_call(1);
        break;
    }
    case Api::TlsFree:
    case Api::FlsFree: {
        auto &values = found->second == Api::TlsFree ? tls_values_ : fls_values_;
        const auto erased = values.erase(static_cast<std::uint32_t>(argument(0))) != 0;
        if (!erased) {
            last_error_ = ERROR_INVALID_PARAMETER;
        }
        cpu.set_reg(Rax, erased ? 1 : 0);
        finish_call(1);
        break;
    }
    case Api::TlsGetValue:
    case Api::FlsGetValue: {
        auto &values = found->second == Api::TlsGetValue ? tls_values_ : fls_values_;
        const auto value = values.find(static_cast<std::uint32_t>(argument(0)));
        if (value == values.end()) {
            last_error_ = ERROR_INVALID_PARAMETER;
            cpu.set_reg(Rax, 0);
        } else {
            last_error_ = ERROR_SUCCESS;
            cpu.set_reg(Rax, value->second);
        }
        finish_call(1);
        break;
    }
    case Api::TlsSetValue:
    case Api::FlsSetValue: {
        auto &values = found->second == Api::TlsSetValue ? tls_values_ : fls_values_;
        const auto value = values.find(static_cast<std::uint32_t>(argument(0)));
        if (value == values.end()) {
            last_error_ = ERROR_INVALID_PARAMETER;
            cpu.set_reg(Rax, 0);
        } else {
            value->second = argument(1);
            cpu.set_reg(Rax, 1);
        }
        finish_call(2);
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
        cpu.set_reg(Rax, allocate(argument(0)));
        finish_call(1);
        break;
    case Api::AllocateRdx:
        cpu.set_reg(Rax, allocate(argument(1)));
        finish_call(2);
        break;
    case Api::AllocateR8:
        cpu.set_reg(Rax, allocate(argument(2)));
        finish_call(3);
        break;
    case Api::Reallocate: {
        const bool heap_reallocate = thunk_name.ends_with("HeapReAlloc");
        const auto old_address = argument(heap_reallocate ? 2 : 0);
        const auto new_size = argument(heap_reallocate ? 3 : 1);
        const auto new_address = allocate(new_size);
        if (const auto old = heap_sizes_.find(old_address); old != heap_sizes_.end()) {
            const auto copy_size = static_cast<std::size_t>(std::min(old->second, new_size));
            const auto bytes = cpu.memory().read(old_address, copy_size);
            cpu.memory().write(new_address, bytes);
        }
        cpu.set_reg(Rax, new_address);
        finish_call(heap_reallocate ? 4 : 3);
        break;
    }
    case Api::FreeRcx:
        cpu.set_reg(Rax, 0);
        finish_call(1);
        break;
    case Api::HeapFree:
        cpu.set_reg(Rax, 1);
        finish_call(3);
        break;
    case Api::HeapDestroy:
        cpu.set_reg(Rax, 1);
        finish_call(1);
        break;
    case Api::AllocationSize: {
        const bool heap_size = thunk_name.ends_with("HeapSize");
        const auto allocation = heap_sizes_.find(argument(heap_size ? 2 : 0));
        const auto failure = guest_is_64_bit_ ? UINT64_MAX : UINT32_MAX;
        cpu.set_reg(Rax, allocation == heap_sizes_.end() ? (heap_size ? failure : 0)
                                                         : allocation->second);
        finish_call(heap_size ? 3 : 1);
        break;
    }
    case Api::IdentityRcx:
        cpu.set_reg(Rax, argument(0));
        finish_call(1);
        break;
    case Api::ProcessHeap:
        cpu.set_reg(Rax, 1);
        finish_call(thunk_name.ends_with("!HeapCreate") ? 3 : 0);
        break;
    case Api::ReturnOne:
        cpu.set_reg(Rax, 1);
        finish_call(thunk_name.ends_with("HeapSetInformation") ? 4
                    : thunk_name.ends_with("SetWinEventHook")  ? 7
                                                               : 1);
        break;
    case Api::GuestModuleHandle:
        if (argument(0) == 0) {
            cpu.set_reg(Rax, guest_image_base_);
        } else {
            const auto requested = thunk_name.ends_with("GetModuleHandleA")
                                       ? cpu.memory().read_c_string(argument(0))
                                       : narrow_string(cpu.memory().read_wide_string(argument(0)));
            const auto filename = guest_executable_.filename().string();
            if (lowercase(requested) == lowercase(filename)) {
                cpu.set_reg(Rax, guest_image_base_);
            } else {
                const auto normalized = lowercase(requested);
                const auto existing = std::find_if(
                    guest_modules_.begin(), guest_modules_.end(),
                    [&](const auto &entry) { return lowercase(entry.second) == normalized; });
                if (existing != guest_modules_.end()) {
                    cpu.set_reg(Rax, existing->first);
                } else {
                    const auto handle = next_module_handle_;
                    next_module_handle_ += 0x1000;
                    guest_modules_.emplace(handle, requested);
                    cpu.set_reg(Rax, handle);
                }
            }
        }
        finish_call(1);
        break;
    case Api::ModuleLoad: {
        const auto requested = thunk_name.ends_with("LoadLibraryA")
                                   ? cpu.memory().read_c_string(argument(0))
                                   : narrow_string(cpu.memory().read_wide_string(argument(0)));
        const auto normalized = lowercase(requested);
        const auto existing =
            std::find_if(guest_modules_.begin(), guest_modules_.end(),
                         [&](const auto &entry) { return lowercase(entry.second) == normalized; });
        if (existing != guest_modules_.end()) {
            cpu.set_reg(Rax, existing->first);
        } else {
            const auto handle = next_module_handle_;
            next_module_handle_ += 0x1000;
            guest_modules_.emplace(handle, requested);
            cpu.set_reg(Rax, handle);
        }
        finish_call(1);
        break;
    }
    case Api::ModuleFree: {
        const auto handle = argument(0);
        const auto loaded = guest_modules_.find(handle);
        const bool result = loaded != guest_modules_.end();
        if (result) {
            guest_modules_.erase(loaded);
        } else {
            last_error_ = ERROR_INVALID_HANDLE;
        }
        cpu.set_reg(Rax, result ? 1 : 0);
        finish_call(1);
        break;
    }
    case Api::GuestFindFirstFile: {
        const bool ansi = thunk_name.ends_with("FindFirstFileA");
        HANDLE host_handle = INVALID_HANDLE_VALUE;
        if (ansi) {
            WIN32_FIND_DATAA data{};
            host_handle = ::FindFirstFileA(cpu.memory().read_c_string(argument(0)).c_str(), &data);
            if (host_handle != INVALID_HANDLE_VALUE) {
                cpu.memory().write(
                    argument(1), std::span<const std::uint8_t>(
                                     reinterpret_cast<const std::uint8_t *>(&data), sizeof(data)));
            }
        } else {
            WIN32_FIND_DATAW data{};
            host_handle =
                ::FindFirstFileW(cpu.memory().read_wide_string(argument(0)).c_str(), &data);
            if (host_handle != INVALID_HANDLE_VALUE) {
                cpu.memory().write(
                    argument(1), std::span<const std::uint8_t>(
                                     reinterpret_cast<const std::uint8_t *>(&data), sizeof(data)));
            }
        }
        if (host_handle == INVALID_HANDLE_VALUE) {
            last_error_ = ::GetLastError();
            cpu.set_reg(Rax, guest_is_64_bit_ ? UINT64_MAX : UINT32_MAX);
        } else {
            const auto guest_handle = next_find_handle_++;
            find_handles_.emplace(guest_handle, host_handle);
            cpu.set_reg(Rax, guest_handle);
        }
        finish_call(2);
        break;
    }
    case Api::GuestFindNextFile: {
        const auto found = find_handles_.find(argument(0));
        BOOL result = FALSE;
        if (found == find_handles_.end()) {
            last_error_ = ERROR_INVALID_HANDLE;
        } else if (thunk_name.ends_with("FindNextFileA")) {
            WIN32_FIND_DATAA data{};
            result = ::FindNextFileA(static_cast<HANDLE>(found->second), &data);
            if (result != FALSE) {
                cpu.memory().write(
                    argument(1), std::span<const std::uint8_t>(
                                     reinterpret_cast<const std::uint8_t *>(&data), sizeof(data)));
            }
        } else {
            WIN32_FIND_DATAW data{};
            result = ::FindNextFileW(static_cast<HANDLE>(found->second), &data);
            if (result != FALSE) {
                cpu.memory().write(
                    argument(1), std::span<const std::uint8_t>(
                                     reinterpret_cast<const std::uint8_t *>(&data), sizeof(data)));
            }
        }
        if (result == FALSE && found != find_handles_.end()) {
            last_error_ = ::GetLastError();
        }
        cpu.set_reg(Rax, result != FALSE);
        finish_call(2);
        break;
    }
    case Api::GuestFindClose: {
        const auto found = find_handles_.find(argument(0));
        const bool result = found != find_handles_.end() &&
                            ::FindClose(static_cast<HANDLE>(found->second)) != FALSE;
        if (found != find_handles_.end()) {
            find_handles_.erase(found);
        }
        if (!result) {
            last_error_ = ERROR_INVALID_HANDLE;
        }
        cpu.set_reg(Rax, result ? 1 : 0);
        finish_call(1);
        break;
    }
    case Api::GetModuleHandleExW:
        if (cpu.reg(R8) != 0) {
            cpu.memory().write64(cpu.reg(R8), guest_image_base_);
        }
        cpu.set_reg(Rax, 1);
        finish_call();
        break;
    case Api::GetModuleFileNameW: {
        const auto path = guest_executable_.wstring();
        const auto destination = argument(1);
        const auto capacity = static_cast<std::uint32_t>(argument(2));
        const auto count = std::min<std::size_t>(path.size(), capacity == 0 ? 0 : capacity - 1);
        for (std::size_t index = 0; index < count; ++index) {
            cpu.memory().write16(destination + index * 2, static_cast<std::uint16_t>(path[index]));
        }
        if (capacity != 0) {
            cpu.memory().write16(destination + count * 2, 0);
        }
        cpu.set_reg(Rax, count);
        finish_call(3);
        break;
    }
    case Api::GetModuleFileNameA: {
        const auto path = guest_executable_.string();
        const auto destination = argument(1);
        const auto capacity = static_cast<std::uint32_t>(argument(2));
        const auto count = std::min<std::size_t>(path.size(), capacity == 0 ? 0 : capacity - 1);
        for (std::size_t index = 0; index < count; ++index) {
            cpu.memory().write8(destination + index, static_cast<std::uint8_t>(path[index]));
        }
        if (capacity != 0) {
            cpu.memory().write8(destination + count, 0);
        }
        cpu.set_reg(Rax, count);
        finish_call(3);
        break;
    }
    case Api::GetProcAddress: {
        const auto module_value = argument(0);
        std::string import_name;
        if (argument(1) <= 0xffff) {
            import_name = "#" + std::to_string(argument(1));
        } else {
            import_name = cpu.memory().read_c_string(argument(1));
        }
        if (!guest_is_64_bit_) {
            const auto module = guest_modules_.find(module_value);
            const auto module_name =
                module_value == guest_image_base_
                    ? guest_executable_.filename().string()
                    : (module == guest_modules_.end() ? std::string() : module->second);
            cpu.set_reg(Rax, module_name.empty() ? 0 : resolve_import(module_name, import_name));
        } else {
            std::array<char, 32768> module_path{};
            const auto length = ::GetModuleFileNameA(reinterpret_cast<HMODULE>(module_value),
                                                     module_path.data(), module_path.size());
            if (length == 0) {
                cpu.set_reg(Rax, 0);
            } else {
                const auto module_name =
                    std::filesystem::path(
                        std::string(module_path.data(), module_path.data() + length))
                        .filename()
                        .string();
                cpu.set_reg(Rax, resolve_import(module_name, import_name));
            }
        }
        finish_call(2);
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
    bool format_initialized = false;
    const auto configure_format = [&](bool is_64_bit) {
        if (!format_initialized) {
            guest_is_64_bit_ = is_64_bit;
            const auto return_thunk = is_64_bit ? return_thunk64 : return_thunk32;
            thunks_.emplace(return_thunk, Api::ProcessReturn);
            next_thunk_ = return_thunk + 0x100;
            format_initialized = true;
        } else if (guest_is_64_bit_ != is_64_bit) {
            throw Error("PE architecture changed while resolving imports");
        }
    };
    data_import_next_ = 0;
    data_import_slots_.clear();
    last_error_ = 0;
    guest_exception_filter_ = 0;
    heap_next_ = 0x0000'0006'0000'0000ULL;
    heap_sizes_.clear();
    next_module_handle_ = 0x7fe0'0000ULL;
    guest_modules_.clear();
    for (const auto &[guest_handle, host_handle] : find_handles_) {
        static_cast<void>(guest_handle);
        ::FindClose(static_cast<HANDLE>(host_handle));
    }
    find_handles_.clear();
    next_find_handle_ = 0x300;
    for (const auto &[guest_handle, host_handle] : file_handles_) {
        static_cast<void>(guest_handle);
        ::CloseHandle(static_cast<HANDLE>(host_handle));
    }
    file_handles_.clear();
    next_file_handle_ = 0x400;
    class_window_procedures_.clear();
    atom_window_procedures_.clear();
    window_procedures_.clear();
    creating_window_procedure_ = 0;
    quit_message_pending_ = false;
    quit_message_code_ = 0;
    protection_policy_proxy_ = 0;
    protection_policy_methods_.clear();
    next_tls_index_ = 1;
    next_fls_index_ = 1;
    tls_values_.clear();
    fls_values_.clear();
    const auto image = PeLoader::load(executable, memory,
                                      [&](const auto &module, const auto &name, bool is_64_bit) {
                                          configure_format(is_64_bit);
                                          return resolve_import(module, name);
                                      });
    configure_format(image.is_64_bit);
    heap_next_ = image.is_64_bit ? 0x0000'0006'0000'0000ULL : 0x1000'0000ULL;
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
    const auto stack_entry_size = image.is_64_bit ? 8U : 4U;
    const auto initial_rsp = stack_base + stack_size - 0x1000 - stack_entry_size;
    const auto return_thunk = image.is_64_bit ? return_thunk64 : return_thunk32;
    if (image.is_64_bit) {
        memory.write64(initial_rsp, return_thunk);
    } else {
        memory.write32(initial_rsp, static_cast<std::uint32_t>(return_thunk));
    }
    if (image.is_64_bit) {
        memory.write64(teb_base + 0x08, stack_base + stack_size);
        memory.write64(teb_base + 0x10, stack_base);
        memory.write64(teb_base + 0x30, teb_base);
        memory.write64(teb_base + 0x40, 1);
        memory.write64(teb_base + 0x48, 1);
        memory.write64(teb_base + 0x60, peb_base);
    } else {
        memory.write32(teb_base + 0x04, static_cast<std::uint32_t>(stack_base + stack_size));
        memory.write32(teb_base + 0x08, static_cast<std::uint32_t>(stack_base));
        memory.write32(teb_base + 0x18, static_cast<std::uint32_t>(teb_base));
        memory.write32(teb_base + 0x20, 1);
        memory.write32(teb_base + 0x24, 1);
        memory.write32(teb_base + 0x30, static_cast<std::uint32_t>(peb_base));
    }
    if (image.tls_start != 0 || image.tls_index != 0 || !image.tls_callbacks.empty()) {
        const auto template_size = image.tls_end - image.tls_start;
        if (template_size > tls_size - 0x1000) {
            throw Error("guest TLS template is too large");
        }
        memory.map(tls_base, tls_size, Read | Write, "main thread TLS");
        const auto tls_block = tls_base + 0x1000;
        if (image.is_64_bit) {
            memory.write64(teb_base + 0x58, tls_base);
            memory.write64(tls_base, tls_block);
        } else {
            memory.write32(teb_base + 0x2c, static_cast<std::uint32_t>(tls_base));
            memory.write32(tls_base, static_cast<std::uint32_t>(tls_block));
        }
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
    guest_command_line_a_ = environment_base + 0x3800;
    const auto data_slot = [&](const char *name) {
        const auto found = data_import_slots_.find(name);
        return found == data_import_slots_.end() ? 0 : found->second;
    };
    const auto write_guest_pointer = [&](std::uint64_t address, std::uint64_t value) {
        if (image.is_64_bit) {
            memory.write64(address, value);
        } else {
            memory.write32(address, static_cast<std::uint32_t>(value));
        }
    };
    if (const auto slot = data_slot("_wcmdln"); slot != 0) {
        write_guest_pointer(slot, command_line_address);
    }
    if (const auto slot = data_slot("_acmdln"); slot != 0) {
        write_guest_pointer(slot, environment_base + 0x3800);
    }
    // An empty environment is a single NULL pointer entry.
    if (const auto slot = data_slot("_environ"); slot != 0) {
        const auto pointer_size = image.is_64_bit ? 8U : 4U;
        write_guest_pointer(slot, slot + pointer_size);
    }
    if (const auto slot = data_slot("_wenviron"); slot != 0) {
        const auto pointer_size = image.is_64_bit ? 8U : 4U;
        write_guest_pointer(slot, slot + pointer_size);
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
    cpu.reset(image.entry, initial_rsp, image.is_64_bit);
    if (image.is_64_bit) {
        cpu.set_gs_base(teb_base);
    } else {
        cpu.set_fs_base(teb_base);
    }
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
