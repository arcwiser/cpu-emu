#pragma once

#include "winemu/cpu.hpp"
#include "winemu/pe.hpp"

#include <array>
#include <cstdint>
#include <filesystem>
#include <iosfwd>
#include <string>
#include <unordered_map>

namespace winemu {

struct RunResult {
    std::uint32_t exit_code;
    std::uint64_t instructions;
};

class Runtime {
  public:
    explicit Runtime(std::ostream &output);
    ~Runtime();
    RunResult run(const std::filesystem::path &executable,
                  std::uint64_t instruction_limit = 10'000'000,
                  const std::wstring &arguments = std::wstring());
    std::intptr_t invoke_window_proc(Cpu &cpu, std::uint64_t window, std::uint32_t message,
                                     std::uint64_t word_parameter, std::int64_t long_parameter,
                                     std::uint32_t &exit_code, bool &exited);

  private:
    enum class Api {
        ProcessReturn,
        ExitProcess,
        TerminateProcess,
        GetStdHandle,
        WriteFile,
        GetLastError,
        SetLastError,
        OutputDebugStringA,
        InitTerm,
        InitTermE,
        ReturnZero,
        InitializeOnexitTable,
        RegisterOnexitFunction,
        ExecuteOnexitTable,
        CommodePointer,
        ErrnoPointer,
        SetUnhandledExceptionFilter,
        GetCommandLineW,
        CommandLineToArgvW,
        GetSecurityInfo,
        MapViewOfFile,
        WinMainCommandLine,
        EnvironmentStringsW,
        EnvironmentStringsA,
        EventRegister,
        CreateThreadpoolTimer,
        VirtualAlloc,
        VirtualFree,
        VirtualProtect,
        VirtualQuery,
        TlsAlloc,
        TlsFree,
        TlsGetValue,
        TlsSetValue,
        FlsAlloc,
        FlsFree,
        FlsGetValue,
        FlsSetValue,
        InitOnceExecuteOnce,
        AllocateRcx,
        AllocateRdx,
        AllocateR8,
        Reallocate,
        FreeRcx,
        HeapFree,
        AllocationSize,
        IdentityRcx,
        ProcessHeap,
        ReturnOne,
        GuestModuleHandle,
        GetModuleHandleExW,
        GetModuleFileNameW,
        GetModuleFileNameA,
        GetProcAddress,
        LoadStringW,
        LoadCursorW,
        LoadIconW,
        LoadImageW,
        LoadAcceleratorsW,
        RegisterClassExW,
        CreateWindowExW,
        ResolveDelayLoadedAPI,
        SHGetKnownFolderPath,
        CoCreateInstance,
        RoGetActivationFactory,
        ProtectionPolicyMethod,
        Native,
        Unsupported,
    };

    [[nodiscard]] std::uint64_t resolve_import(const std::string &module, const std::string &name);
    [[nodiscard]] std::uint64_t allocate_data_import(const std::string &module,
                                                     const std::string &name);
    [[nodiscard]] bool dispatch(Cpu &cpu, std::uint32_t &exit_code, bool &exited);
    [[nodiscard]] std::uint64_t invoke_guest(Cpu &cpu, std::uint64_t target,
                                             const std::array<std::uint64_t, 4> &arguments,
                                             std::uint32_t &exit_code, bool &exited);
    std::ostream &output_;
    std::unordered_map<std::uint64_t, Api> thunks_;
    std::unordered_map<std::uint64_t, std::string> thunk_names_;
    std::unordered_map<std::uint64_t, void *> native_functions_;
    std::uint64_t next_thunk_ = 0xffff'0000'0000'0100ULL;
    std::uint64_t data_import_next_ = 0;
    std::unordered_map<std::string, std::uint64_t> data_import_slots_;
    std::uint32_t last_error_ = 0;
    std::uint64_t guest_exception_filter_ = 0;
    std::uint64_t guest_command_line_ = 0;
    std::uint64_t guest_winmain_command_line_ = 0;
    std::uint64_t heap_next_ = 0x0000'0006'0000'0000ULL;
    std::unordered_map<std::uint64_t, std::uint64_t> heap_sizes_;
    std::uint64_t guest_image_base_ = 0;
    std::filesystem::path guest_executable_;
    void *resource_module_ = nullptr;
    std::unordered_map<std::wstring, std::uint64_t> class_window_procedures_;
    std::unordered_map<std::uint16_t, std::uint64_t> atom_window_procedures_;
    std::unordered_map<std::uint64_t, std::uint64_t> window_procedures_;
    std::uint64_t creating_window_procedure_ = 0;
    std::uint32_t callback_depth_ = 0;
    std::uint64_t protection_policy_proxy_ = 0;
    std::unordered_map<std::uint64_t, std::uint32_t> protection_policy_methods_;
    std::uint32_t next_tls_index_ = 1;
    std::uint32_t next_fls_index_ = 1;
    std::unordered_map<std::uint32_t, std::uint64_t> tls_values_;
    std::unordered_map<std::uint32_t, std::uint64_t> fls_values_;
};

} // namespace winemu
