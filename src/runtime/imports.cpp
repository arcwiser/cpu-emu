#include "winemu/runtime.hpp"

#include "winemu/detail/runtime_layout.hpp"
#include "winemu/detail/runtime_strings.hpp"
#include "winemu/error.hpp"
#include "winemu/log.hpp"

#include <unordered_set>

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>

namespace winemu {

bool Runtime::ensure_guest_activation_context() {
    if (guest_activation_context_ != nullptr) {
        return true;
    }
    // Create the context from the guest image itself, which is where Windows reads the manifest
    // that selects Side-by-Side assemblies such as Common-Controls v6.
    ACTCTXW context{};
    context.cbSize = sizeof(context);
    context.dwFlags = ACTCTX_FLAG_RESOURCE_NAME_VALID;
    const auto source = guest_executable_.wstring();
    context.lpSource = source.c_str();
    context.lpResourceName = MAKEINTRESOURCEW(1);
    const auto handle = ::CreateActCtxW(&context);
    if (handle == INVALID_HANDLE_VALUE) {
        log::error("runtime", "cannot create the guest activation context for '" +
                                  guest_executable_.string() + "' (Win32 error " +
                                  std::to_string(::GetLastError()) + ")");
        return false;
    }
    guest_activation_context_ = handle;
    return true;
}

std::uintptr_t Runtime::activate_guest_context() const {
    if (guest_activation_context_ == nullptr) {
        return 0;
    }
    ULONG_PTR cookie = 0;
    if (!::ActivateActCtx(static_cast<HANDLE>(guest_activation_context_), &cookie)) {
        return 0;
    }
    return static_cast<std::uintptr_t>(cookie);
}

void Runtime::deactivate_guest_context(std::uintptr_t cookie) const {
    if (cookie == 0) {
        return;
    }
    ::DeactivateActCtx(0, static_cast<ULONG_PTR>(cookie));
}

std::uint64_t Runtime::allocate_data_import(const std::string &module, const std::string &name) {
    // CRT variables are data exports: the guest reads and writes the value at the address
    // in its import table, so each one needs a real mapped slot rather than a code thunk.
    constexpr std::uint64_t slot_size = 0x400;
    constexpr std::uint64_t first_slot = detail::environment_base + 0x4000;
    if (data_import_next_ == 0) {
        data_import_next_ = first_slot;
    }
    if (data_import_next_ + slot_size > detail::teb_base) {
        throw Error("CRT data import space exhausted at " + module + "!" + name);
    }
    const auto address = data_import_next_;
    data_import_next_ += slot_size;
    data_import_slots_.emplace(name, address);
    log::trace("imports", module + "!" + name + " -> data slot " + log::hex(address));
    return address;
}

std::uint64_t Runtime::resolve_import(const std::string &module, const std::string &name) {
    const auto normalized_module = detail::lowercase(module);
    static const std::unordered_set<std::string> data_imports{
        "_fmode",    "_commode",  "_wcmdln",   "_acmdln", "_environ",
        "_wenviron", "_winmajor", "_winminor", "_osver",  "_winver",
    };
    const bool msvcp_locale_data =
        normalized_module == "msvcp140.dll" &&
        (name == "?_Id_cnt@id@locale@std@@0HA" ||
         (name.starts_with("?id@?$") && name.ends_with("@@2V0locale@2@A")));
    if (data_imports.contains(name) || msvcp_locale_data) {
        return allocate_data_import(module, name);
    }
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
    } else if (kernel_module && name == "GetFileInformationByHandle") {
        api = Api::GuestFileInformation;
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
               (name == "InitializeSRWLock" || name == "AcquireSRWLockExclusive" ||
                name == "AcquireSRWLockShared" || name == "ReleaseSRWLockExclusive" ||
                name == "ReleaseSRWLockShared" || name == "TryAcquireSRWLockExclusive" ||
                name == "TryAcquireSRWLockShared")) {
        api = Api::GuestSrwLock;
    } else if (kernel_module && (name == "CreateMutexExW" || name == "CreateSemaphoreExW" ||
                                 name == "OpenSemaphoreW" || name == "CreateEventExW" ||
                                 name == "WaitForSingleObject" || name == "WaitForSingleObjectEx" ||
                                 name == "ReleaseMutex" || name == "ReleaseSemaphore" ||
                                 name == "SetEvent" || name == "ResetEvent")) {
        api = Api::GuestSynchronization;
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
    } else if (name == "GetSystemMetrics") {
        api = Api::SystemMetrics;
    } else if (name == "AdjustWindowRect" || name == "AdjustWindowRectEx") {
        api = Api::WindowRectAdjustment;
    } else if (name == "GetClientRect" || name == "GetWindowRect") {
        api = Api::WindowRectQuery;
    } else if (name == "DefWindowProcA" || name == "DefWindowProcW") {
        api = Api::GuestDefWindowProc;
    } else if (name == "SetWindowTextA" || name == "SetWindowTextW" || name == "GetWindowTextA" ||
               name == "GetWindowTextW" || name == "GetWindowTextLengthA" ||
               name == "GetWindowTextLengthW") {
        api = Api::GuestWindowText;
    } else if (name == "SendMessageA" || name == "SendMessageW") {
        api = Api::GuestSendMessage;
    } else if (name == "SetCursor" || name == "ShowCursor") {
        api = Api::GuestCursor;
    } else if (name == "EnumDisplaySettingsA" || name == "EnumDisplaySettingsW" ||
               name == "EnumDisplaySettingsExA" || name == "EnumDisplaySettingsExW") {
        api = Api::GuestDisplaySettings;
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
    } else if (normalized_module == "urlmon.dll" && name == "FindMimeFromData") {
        api = Api::GuestMimeType;
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
    } else if (name == "__p___argc") {
        api = Api::ArgcPointer;
    } else if (name == "__p___argv") {
        api = Api::ArgvPointer;
    } else if (name == "__p___wargv") {
        api = Api::WideArgvPointer;
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
    } else if (name == "FormatMessageA" || name == "FormatMessageW") {
        api = Api::GuestFormatMessage;
    } else if (name == "GetStringTypeA" || name == "GetStringTypeW") {
        api = Api::GuestStringType;
    } else if (name == "LCMapStringA" || name == "LCMapStringW") {
        api = Api::GuestMapString;
    } else if (name == "CommandLineToArgvW") {
        api = Api::CommandLineToArgvW;
    } else if (name == "GetSecurityInfo") {
        api = Api::GetSecurityInfo;
    } else if (name == "CreateFileMappingA" || name == "CreateFileMappingW" ||
               name == "MapViewOfFile" || name == "UnmapViewOfFile") {
        api = Api::GuestFileMapping;
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
    } else if (name == "DwmEnableMMCSS") {
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
    } else if (name == "calloc" || name == "_o_calloc" || name == "_calloc_base") {
        api = Api::AllocateProduct;
    } else if (name == "LocalAlloc" || name == "GlobalAlloc") {
        api = Api::AllocateRdx;
    } else if (name == "HeapAlloc") {
        api = Api::AllocateR8;
    } else if (name == "HeapCreate" || name == "GetProcessHeap") {
        api = Api::ProcessHeap;
    } else if (name == "HeapDestroy") {
        api = Api::HeapDestroy;
    } else if (name == "LocalReAlloc" || name == "HeapReAlloc" || name == "realloc" ||
               name == "_o_realloc") {
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
    } else if (name == "abort") {
        // A guest CRT abort must never terminate or hang the host emulator process.
        api = Api::AbortProcess;
    } else if (name == "_invoke_watson" || name == "_invalid_parameter_noinfo" ||
               name == "_invalid_parameter_noinfo_noreturn" || name == "_wassert" ||
               name == "_assert") {
        // These CRT routines are noreturn fail-fast paths. Forwarding them natively raises the
        // fast-fail exception in the host process and kills the emulator, so the guest terminates
        // instead while keeping the same Windows process status.
        api = Api::GuestFailFast;
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
    } else if (name == "FindFirstFileA" || name == "FindFirstFileW" || name == "FindFirstFileExA" ||
               name == "FindFirstFileExW") {
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
    } else if (name == "RegisterClassW" || name == "RegisterClassExW") {
        api = Api::GuestRegisterClassW;
    } else if (name == "CreateWindowExW") {
        api = Api::CreateWindowExW;
    } else if (name == "DialogBoxParamW") {
        api = Api::DialogBoxParamW;
    } else if (name == "EndDialog") {
        api = Api::EndDialog;
    } else if (name == "DirectInput8Create") {
        api = Api::DirectInputCreate;
    } else if (name == "ResolveDelayLoadedAPI") {
        api = Api::ResolveDelayLoadedAPI;
    } else if (name == "SHGetKnownFolderPath") {
        api = Api::SHGetKnownFolderPath;
    } else if (name == "CoCreateInstance") {
        api = Api::CoCreateInstance;
    } else if (name == "WindowsCreateString") {
        api = Api::WindowsCreateString;
    } else if (name == "WindowsCreateStringReference") {
        api = Api::WindowsCreateStringReference;
    } else if (name == "WindowsDeleteString") {
        api = Api::WindowsDeleteString;
    } else if (name == "WindowsDuplicateString") {
        api = Api::WindowsDuplicateString;
    } else if (name == "WindowsGetStringRawBuffer") {
        api = Api::WindowsGetStringRawBuffer;
    } else if (name == "RoGetActivationFactory") {
        api = Api::RoGetActivationFactory;
    } else if (normalized_module == "msvcp140.dll" &&
               (name == "?_Init@locale@std@@CAPEAV_Locimp@12@_N@Z" ||
                name == "?_Getgloballocale@locale@std@@CAPEAV_Locimp@12@XZ")) {
        api = Api::MsvcpLocale;
    } else if (normalized_module == "msvcp140.dll" && name.starts_with("?_Getcat@?$")) {
        api = Api::MsvcpFacetFactory;
    } else if (normalized_module == "msvcp140.dll" && name.starts_with("??0?$basic_streambuf@")) {
        api = Api::MsvcpStreamBufferConstruct;
    } else if (normalized_module == "msvcp140.dll" &&
               name.starts_with("?_Init@?$basic_streambuf@D")) {
        api = Api::MsvcpStreamBufferInit;
    } else if (normalized_module == "msvcp140.dll" &&
               name.starts_with("?getloc@?$basic_streambuf@")) {
        api = Api::MsvcpStreamGetLocale;
    } else if (normalized_module == "msvcp140.dll" &&
               name == "?always_noconv@codecvt_base@std@@QEBA_NXZ") {
        // The narrow-character codecvt facet performs an identity conversion.
        api = Api::ReturnOne;
    } else if (normalized_module == "msvcp140.dll" && name.starts_with("?_Fiopen@std@@")) {
        api = Api::MsvcpFileOpen;
    } else if (name == "_get_stream_buffer_pointers" || name == "fread" || name == "fwrite" ||
               name == "fclose" || name == "fflush" || name == "fgetpos" || name == "fsetpos" ||
               name == "_fseeki64" || name == "fgetc" || name == "fputc") {
        api = Api::GuestFileMethod;
    } else if (normalized_module == "msvcp140.dll" && (name.starts_with("??0?$basic_istream@D") ||
                                                       name.starts_with("??0?$basic_iostream@D"))) {
        api = Api::MsvcpInputStreamConstruct;
    } else if (normalized_module == "msvcp140.dll" &&
               name.starts_with("?swap@?$basic_iostream@D")) {
        api = Api::MsvcpStreamSwap;
    } else if (normalized_module == "msvcp140.dll" &&
               name.starts_with("?seekg@?$basic_istream@D")) {
        api = Api::MsvcpStreamSeek;
    } else if (normalized_module == "msvcp140.dll" &&
               name.starts_with("?tellg@?$basic_istream@D")) {
        api = Api::MsvcpStreamTell;
    } else if (normalized_module == "msvcp140.dll" && name.starts_with("?read@?$basic_istream@D")) {
        api = Api::MsvcpStreamRead;
    } else if (normalized_module == "msvcp140.dll" &&
               name.starts_with("?readsome@?$basic_istream@D")) {
        api = Api::MsvcpStreamReadSome;
    } else if (normalized_module == "msvcp140.dll" && (name.starts_with("??1?$basic_streambuf@D") ||
                                                       name.starts_with("??1?$basic_istream@D") ||
                                                       name.starts_with("??1?$basic_iostream@D"))) {
        api = Api::MsvcpStreamDestroy;
    } else if (normalized_module == "msvcp140.dll" && name.starts_with("??0?$basic_ios@")) {
        api = Api::MsvcpIosConstruct;
    } else if (normalized_module == "msvcp140.dll" && name.starts_with("?clear@?$basic_ios@")) {
        api = Api::MsvcpIosClear;
    } else if (normalized_module == "msvcp140.dll" && name.starts_with("?setstate@?$basic_ios@")) {
        api = Api::MsvcpIosSetState;
    } else if (normalized_module == "msvcp140.dll" && name.starts_with("?good@ios_base@")) {
        api = Api::MsvcpIosGood;
    } else if (normalized_module == "msvcp140.dll" && name.starts_with("?fail@ios_base@")) {
        api = Api::MsvcpIosFail;
    } else if (normalized_module == "msvcp140.dll" && name.starts_with("?exceptions@ios_base@")) {
        api = Api::MsvcpIosExceptions;
    } else if (normalized_module == "msvcp140.dll" && name.starts_with("??1?$basic_ios@")) {
        api = Api::MsvcpIosDestroy;
    } else if (normalized_module == "msvcp140.dll" && name.starts_with("??0?$basic_ostream@")) {
        api = Api::MsvcpOutputStreamConstruct;
    } else if (normalized_module == "msvcp140.dll" && name.starts_with("?write@?$basic_ostream@")) {
        api = Api::MsvcpStreamWrite;
    } else if (normalized_module == "msvcp140.dll" &&
               (name.starts_with("?_Schedule_chore@details@Concurrency@@") ||
                name.starts_with("?_Reschedule_chore@details@Concurrency@@"))) {
        api = Api::MsvcpScheduleChore;
    } else if (normalized_module == "msvcp140.dll" &&
               name.starts_with("?_Release_chore@details@Concurrency@@")) {
        api = Api::MsvcpReleaseChore;
    } else if (normalized_module == "oleaut32.dll" && (name == "GetErrorInfo" || name == "#200")) {
        api = Api::GuestGetErrorInfo;
    } else if (normalized_module == "oleaut32.dll" && (name == "SetErrorInfo" || name == "#201")) {
        api = Api::GuestSetErrorInfo;
    } else if (name == "CreateThreadpoolTimer") {
        api = Api::CreateThreadpoolTimer;
    } else if (name == "SubscribeFeatureStateChangeNotification") {
        // The callback is a guest address. Native forwarding would let Windows invoke it from a
        // thread-pool timer thread, so the subscription is kept inert and guest-owned instead.
        api = Api::FeatureStateSubscribe;
    } else if (name == "UnsubscribeFeatureStateChangeNotification") {
        api = Api::FeatureStateUnsubscribe;
    } else if (name == "SetWindowSubclass" || name == "RemoveWindowSubclass" ||
               name == "DefSubclassProc" || name == "GetWindowSubclass") {
        // comctl32 subclassing retains a guest procedure and invokes it from message dispatch.
        api = Api::WindowSubclass;
    } else if (normalized_module == "comctl32.dll" &&
               (name == "#410" || name == "#411" || name == "#412" || name == "#413")) {
        // The same subclass family is exported by ordinal only in comctl32 v6: SetWindowSubclass
        // is 410, GetWindowSubclass 411, RemoveWindowSubclass 412, and DefSubclassProc 413.
        api = Api::WindowSubclass;
    } else if (name == "SetThreadpoolTimer" || name == "WaitForThreadpoolTimerCallbacks" ||
               name == "CloseThreadpoolTimer") {
        api = Api::ReturnZero;
    } else if (name == "SetWinEventHook" || name == "UnhookWinEvent") {
        api = Api::ReturnOne;
    } else if (name == "__std_atomic_wait_direct") {
        api = Api::GuestAtomicWait;
    } else if (name == "__std_atomic_notify_one_direct" ||
               name == "__std_atomic_notify_all_direct") {
        api = Api::ReturnZero;
    } else if (name == "EnumWindows" || name == "EnumThreadWindows" || name == "EnumChildWindows") {
        // The callback is guest code and cannot be passed to native USER32. This process owns no
        // host windows before CreateWindowExW, so a successful empty enumeration is accurate.
        api = Api::ReturnOne;
    } else if (name == "_beginthreadex" || name == "_o__beginthreadex") {
        api = Api::GuestThreadCreate;
    } else if (name == "_beginthread" || name == "_o__beginthread") {
        api = Api::GuestThreadCreate;
    } else if (name == "_Thrd_detach") {
        // Guest threads are currently cooperative and have completed before the handle is
        // returned. Never pass the guest-owned _Thrd_t descriptor to the host MSVC runtime.
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
            "CreateDialogParamW",
            "CreateDialogIndirectParamW",
            "EnumFontsW",
            "SetAbortProc",
            "GetProcAddress",
            "ResolveDelayLoadedAPI",
        };
        void *function = nullptr;
        if (guest_is_64_bit_ && !unsafe_calls.contains(name)) {
            // Resolve under the guest's activation context so manifest-selected Side-by-Side
            // assemblies bind the same way Windows binds them for the guest.
            const auto activation_cookie = activate_guest_context();
            if (const auto library = LoadLibraryA(module.c_str()); library != nullptr) {
                if (name.starts_with('#')) {
                    const auto ordinal = static_cast<WORD>(std::stoul(name.substr(1)));
                    function = reinterpret_cast<void *>(
                        GetProcAddress(library, MAKEINTRESOURCEA(ordinal)));
                } else {
                    function = reinterpret_cast<void *>(GetProcAddress(library, name.c_str()));
                }
            }
            deactivate_guest_context(activation_cookie);
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

} // namespace winemu
