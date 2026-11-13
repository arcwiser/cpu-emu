#define _CRT_SECURE_NO_WARNINGS

#include "winemu/runtime.hpp"

#include "callbacks.hpp"
#include "diagnostics.hpp"

#include "winemu/detail/runtime_layout.hpp"
#include "winemu/detail/runtime_strings.hpp"
#include "winemu/error.hpp"
#include "winemu/log.hpp"

#include <algorithm>
#include <cctype>
#include <cstring>
#include <cwctype>
#include <exception>
#include <functional>
#include <iostream>
#include <limits>
#include <ostream>
#include <sstream>

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <share.h>
#include <windows.h>
// Common Dialogs depends on the base Windows declarations above.
#include <cderr.h>
#include <commdlg.h>
#include <urlmon.h>

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

using detail::crt_argc;
using detail::crt_argv;
using detail::crt_commode;
using detail::crt_errno;
using detail::crt_wargv;
constexpr DWORD sound_async = 0x0001;
constexpr DWORD sound_memory = 0x0004;
constexpr DWORD sound_loop = 0x0008;
constexpr DWORD sound_resource = 0x00040004;

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

using detail::narrow_string;

} // namespace

bool Runtime::dispatch(Cpu &cpu, std::uint32_t &exit_code, bool &exited) {
    // __fastfail always raises STATUS_STACK_BUFFER_OVERRUN on Windows, independent of the
    // fail-fast sub-code, so a guest fail-fast terminates with this status.
    constexpr std::uint32_t fail_fast_status = 0xc0000409U;
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
    const auto ensure_locale = [&] {
        if (locale_proxy_ != 0) {
            return;
        }
        constexpr std::uint64_t facet_capacity = 128;
        constexpr std::uint32_t facet_method_count = 10;
        locale_facet_vtable_ = allocate(facet_method_count * 8);
        const auto facets = allocate(facet_capacity * 8);
        const auto name = allocate(2);
        locale_proxy_ = allocate(0x38);
        cpu.memory().write8(name, '*');
        cpu.memory().write8(name + 1, 0);
        cpu.memory().write64(locale_proxy_, locale_facet_vtable_);
        cpu.memory().write32(locale_proxy_ + 8, 1);
        cpu.memory().write64(locale_proxy_ + 0x10, facets);
        cpu.memory().write64(locale_proxy_ + 0x18, facet_capacity);
        cpu.memory().write32(locale_proxy_ + 0x20, 0);
        cpu.memory().write8(locale_proxy_ + 0x24, 0);
        cpu.memory().write64(locale_proxy_ + 0x28, name);
        for (std::uint32_t index = 0; index < facet_method_count; ++index) {
            const auto thunk = next_thunk_;
            next_thunk_ += 0x100;
            thunks_.emplace(thunk, Api::LocaleFacetMethod);
            thunk_names_.emplace(thunk, "locale::facet#" + std::to_string(index));
            locale_facet_methods_.emplace(thunk, index);
            cpu.memory().write64(locale_facet_vtable_ + index * 8, thunk);
        }
    };
    const auto stream_file = [&](std::uint64_t stream_object) -> FILE * {
        const auto buffer = input_stream_buffers_.find(stream_object);
        if (buffer == input_stream_buffers_.end()) {
            return nullptr;
        }
        const auto file = stream_buffer_files_.find(buffer->second);
        if (file == stream_buffer_files_.end()) {
            return nullptr;
        }
        const auto host = guest_file_streams_.find(file->second);
        return host == guest_file_streams_.end() ? nullptr : static_cast<FILE *>(host->second);
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
    case Api::AbortProcess:
        throw Error("guest called abort from " + log::hex(cpu.memory().read64(cpu.reg(Rsp))));
    case Api::GuestFailFast: {
        // A guest fail-fast is noreturn. Terminate only the guest with the status Windows would
        // raise for __fastfail, and say which routine triggered it so the real blocker is visible.
        log::error("runtime", "guest fail-fast via " + thunk_name + " from " +
                                  log::hex(cpu.memory().read64(cpu.reg(Rsp))));
        log::error("cpu", detail::cpu_state_dump(cpu));
        log::error("cpu", detail::callee_saved_windows(cpu));
        exit_code = fail_fast_status;
        exited = true;
        break;
    }
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
    case Api::GuestFileInformation: {
        const auto found = file_handles_.find(argument(0));
        const auto destination = argument(1);
        if (found == file_handles_.end() || destination == 0) {
            last_error_ =
                found == file_handles_.end() ? ERROR_INVALID_HANDLE : ERROR_INVALID_PARAMETER;
            cpu.set_reg(Rax, 0);
            finish_call(2);
            break;
        }
        BY_HANDLE_FILE_INFORMATION information{};
        const auto result =
            ::GetFileInformationByHandle(static_cast<HANDLE>(found->second), &information);
        if (result == FALSE) {
            last_error_ = ::GetLastError();
        } else {
            cpu.memory().write32(destination, information.dwFileAttributes);
            cpu.memory().write32(destination + 4, information.ftCreationTime.dwLowDateTime);
            cpu.memory().write32(destination + 8, information.ftCreationTime.dwHighDateTime);
            cpu.memory().write32(destination + 12, information.ftLastAccessTime.dwLowDateTime);
            cpu.memory().write32(destination + 16, information.ftLastAccessTime.dwHighDateTime);
            cpu.memory().write32(destination + 20, information.ftLastWriteTime.dwLowDateTime);
            cpu.memory().write32(destination + 24, information.ftLastWriteTime.dwHighDateTime);
            cpu.memory().write32(destination + 28, information.dwVolumeSerialNumber);
            cpu.memory().write32(destination + 32, information.nFileSizeHigh);
            cpu.memory().write32(destination + 36, information.nFileSizeLow);
            cpu.memory().write32(destination + 40, information.nNumberOfLinks);
            cpu.memory().write32(destination + 44, information.nFileIndexHigh);
            cpu.memory().write32(destination + 48, information.nFileIndexLow);
        }
        cpu.set_reg(Rax, result != FALSE ? 1 : 0);
        finish_call(2);
        break;
    }
    case Api::GuestCloseHandle: {
        const auto found = file_handles_.find(argument(0));
        bool result = argument(0) >= 0x100 && argument(0) <= 0x102;
        if (found != file_handles_.end()) {
            result = ::CloseHandle(static_cast<HANDLE>(found->second)) != FALSE;
            file_handles_.erase(found);
        }
        if (const auto mapping = mapping_handles_.find(argument(0));
            mapping != mapping_handles_.end()) {
            result = ::CloseHandle(static_cast<HANDLE>(mapping->second)) != FALSE;
            mapping_handles_.erase(mapping);
        }
        if (const auto sync = sync_handles_.find(argument(0)); sync != sync_handles_.end()) {
            result = ::CloseHandle(static_cast<HANDLE>(sync->second)) != FALSE;
            sync_handles_.erase(sync);
        }
        if (!result) {
            last_error_ = ERROR_INVALID_HANDLE;
        }
        cpu.set_reg(Rax, result ? 1 : 0);
        finish_call(1);
        break;
    }
    case Api::GuestSrwLock: {
        if (argument(0) == 0) {
            last_error_ = ERROR_INVALID_PARAMETER;
            cpu.set_reg(Rax, 0);
            finish_call(1);
            break;
        }
        if (thunk_name.ends_with("!InitializeSRWLock")) {
            if (guest_is_64_bit_) {
                cpu.memory().write64(argument(0), 0);
            } else {
                cpu.memory().write32(argument(0), 0);
            }
        }
        // CPUEmu currently has one guest thread. Under that scheduler an SRW lock cannot
        // contend, so acquire/release are state-free and try-acquire always succeeds.
        cpu.set_reg(Rax, thunk_name.find("!TryAcquireSRWLock") != std::string::npos ? 1 : 0);
        finish_call(1);
        break;
    }
    case Api::GuestSynchronization: {
        auto isolate_name = [&](std::uint64_t address) -> std::wstring {
            if (address == 0) {
                return {};
            }
            const auto guest_name = cpu.memory().read_wide_string(address, 32767);
            std::wostringstream isolated;
            isolated << synchronization_namespace_ << std::hex
                     << std::hash<std::wstring>{}(guest_name);
            return isolated.str();
        };
        auto add_handle = [&](HANDLE host_handle) -> std::uint64_t {
            if (host_handle == nullptr) {
                last_error_ = ::GetLastError();
                return 0;
            }
            const auto guest_handle = next_sync_handle_++;
            sync_handles_.emplace(guest_handle, host_handle);
            return guest_handle;
        };
        auto find_handle = [&](std::uint64_t guest_handle) -> HANDLE {
            const auto found = sync_handles_.find(guest_handle);
            return found == sync_handles_.end() ? nullptr : static_cast<HANDLE>(found->second);
        };

        if (thunk_name.ends_with("!CreateMutexExW")) {
            if (argument(0) != 0) {
                last_error_ = ERROR_NOT_SUPPORTED;
                cpu.set_reg(Rax, 0);
            } else {
                const auto name = isolate_name(argument(1));
                ::SetLastError(ERROR_SUCCESS);
                const auto handle = ::CreateMutexExW(nullptr, name.empty() ? nullptr : name.c_str(),
                                                     static_cast<DWORD>(argument(2)),
                                                     static_cast<DWORD>(argument(3)));
                cpu.set_reg(Rax, add_handle(handle));
                if (handle != nullptr) {
                    last_error_ = ::GetLastError();
                }
            }
            finish_call(4);
            break;
        }
        if (thunk_name.ends_with("!CreateSemaphoreExW")) {
            if (argument(0) != 0) {
                last_error_ = ERROR_NOT_SUPPORTED;
                cpu.set_reg(Rax, 0);
            } else {
                const auto name = isolate_name(argument(3));
                ::SetLastError(ERROR_SUCCESS);
                const auto handle = ::CreateSemaphoreExW(
                    nullptr, static_cast<LONG>(argument(1)), static_cast<LONG>(argument(2)),
                    name.empty() ? nullptr : name.c_str(), static_cast<DWORD>(argument(4)),
                    static_cast<DWORD>(argument(5)));
                cpu.set_reg(Rax, add_handle(handle));
                if (handle != nullptr) {
                    last_error_ = ::GetLastError();
                }
            }
            finish_call(6);
            break;
        }
        if (thunk_name.ends_with("!OpenSemaphoreW")) {
            const auto name = isolate_name(argument(2));
            const auto handle = name.empty() ? nullptr
                                             : ::OpenSemaphoreW(static_cast<DWORD>(argument(0)),
                                                                argument(1) != 0, name.c_str());
            if (name.empty()) {
                ::SetLastError(ERROR_INVALID_NAME);
            }
            cpu.set_reg(Rax, add_handle(handle));
            finish_call(3);
            break;
        }
        if (thunk_name.ends_with("!CreateEventExW")) {
            if (argument(0) != 0) {
                last_error_ = ERROR_NOT_SUPPORTED;
                cpu.set_reg(Rax, 0);
            } else {
                const auto name = isolate_name(argument(1));
                ::SetLastError(ERROR_SUCCESS);
                const auto handle = ::CreateEventExW(nullptr, name.empty() ? nullptr : name.c_str(),
                                                     static_cast<DWORD>(argument(2)),
                                                     static_cast<DWORD>(argument(3)));
                cpu.set_reg(Rax, add_handle(handle));
                if (handle != nullptr) {
                    last_error_ = ::GetLastError();
                }
            }
            finish_call(4);
            break;
        }

        const auto host_handle = find_handle(argument(0));
        if (host_handle == nullptr) {
            last_error_ = ERROR_INVALID_HANDLE;
            cpu.set_reg(Rax, thunk_name.find("!WaitForSingleObject") != std::string::npos
                                 ? WAIT_FAILED
                                 : 0);
        } else if (thunk_name.ends_with("!WaitForSingleObject") ||
                   thunk_name.ends_with("!WaitForSingleObjectEx")) {
            const auto result =
                thunk_name.ends_with("Ex")
                    ? ::WaitForSingleObjectEx(host_handle, static_cast<DWORD>(argument(1)),
                                              argument(2) != 0)
                    : ::WaitForSingleObject(host_handle, static_cast<DWORD>(argument(1)));
            if (result == WAIT_FAILED) {
                last_error_ = ::GetLastError();
            }
            cpu.set_reg(Rax, result);
        } else if (thunk_name.ends_with("!ReleaseSemaphore")) {
            LONG previous = 0;
            const auto result = ::ReleaseSemaphore(host_handle, static_cast<LONG>(argument(1)),
                                                   argument(2) == 0 ? nullptr : &previous);
            if (result != FALSE && argument(2) != 0) {
                cpu.memory().write32(argument(2), static_cast<std::uint32_t>(previous));
            } else if (result == FALSE) {
                last_error_ = ::GetLastError();
            }
            cpu.set_reg(Rax, result != FALSE ? 1 : 0);
        } else {
            BOOL result = FALSE;
            if (thunk_name.ends_with("!ReleaseMutex")) {
                result = ::ReleaseMutex(host_handle);
            } else if (thunk_name.ends_with("!SetEvent")) {
                result = ::SetEvent(host_handle);
            } else if (thunk_name.ends_with("!ResetEvent")) {
                result = ::ResetEvent(host_handle);
            }
            if (result == FALSE) {
                last_error_ = ::GetLastError();
            }
            cpu.set_reg(Rax, result != FALSE ? 1 : 0);
        }
        finish_call(thunk_name.ends_with("!WaitForSingleObjectEx") ? 3
                    : thunk_name.ends_with("!ReleaseSemaphore")    ? 3
                    : thunk_name.ends_with("!WaitForSingleObject") ? 2
                                                                   : 1);
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
    case Api::SystemMetrics:
        cpu.set_reg(Rax,
                    static_cast<std::uint32_t>(::GetSystemMetrics(static_cast<int>(argument(0)))));
        finish_call(1);
        break;
    case Api::WindowRectAdjustment: {
        const auto destination = argument(0);
        RECT rectangle{static_cast<LONG>(cpu.memory().read32(destination)),
                       static_cast<LONG>(cpu.memory().read32(destination + 4)),
                       static_cast<LONG>(cpu.memory().read32(destination + 8)),
                       static_cast<LONG>(cpu.memory().read32(destination + 12))};
        const auto extended = thunk_name.ends_with("!AdjustWindowRectEx");
        const auto result =
            extended
                ? ::AdjustWindowRectEx(&rectangle, static_cast<DWORD>(argument(1)),
                                       argument(2) != 0, static_cast<DWORD>(argument(3)))
                : ::AdjustWindowRect(&rectangle, static_cast<DWORD>(argument(1)), argument(2) != 0);
        if (result != FALSE) {
            cpu.memory().write32(destination, static_cast<std::uint32_t>(rectangle.left));
            cpu.memory().write32(destination + 4, static_cast<std::uint32_t>(rectangle.top));
            cpu.memory().write32(destination + 8, static_cast<std::uint32_t>(rectangle.right));
            cpu.memory().write32(destination + 12, static_cast<std::uint32_t>(rectangle.bottom));
        } else {
            last_error_ = ::GetLastError();
        }
        cpu.set_reg(Rax, result != FALSE ? 1 : 0);
        finish_call(extended ? 4 : 3);
        break;
    }
    case Api::WindowRectQuery: {
        RECT rectangle{};
        const auto window = reinterpret_cast<HWND>(static_cast<std::uintptr_t>(argument(0)));
        const auto result = thunk_name.ends_with("!GetClientRect")
                                ? ::GetClientRect(window, &rectangle)
                                : ::GetWindowRect(window, &rectangle);
        if (result != FALSE) {
            const auto destination = argument(1);
            cpu.memory().write32(destination, static_cast<std::uint32_t>(rectangle.left));
            cpu.memory().write32(destination + 4, static_cast<std::uint32_t>(rectangle.top));
            cpu.memory().write32(destination + 8, static_cast<std::uint32_t>(rectangle.right));
            cpu.memory().write32(destination + 12, static_cast<std::uint32_t>(rectangle.bottom));
        } else {
            last_error_ = ::GetLastError();
        }
        cpu.set_reg(Rax, result != FALSE ? 1 : 0);
        finish_call(2);
        break;
    }
    case Api::GuestDefWindowProc: {
        auto native_long_parameter = static_cast<std::int64_t>(argument(3));
        if (const auto translated = callback_long_parameters_.find(argument(3));
            translated != callback_long_parameters_.end()) {
            native_long_parameter = translated->second;
        }
        const auto window = reinterpret_cast<HWND>(static_cast<std::uintptr_t>(argument(0)));
        const auto result = thunk_name.ends_with("W")
                                ? ::DefWindowProcW(window, static_cast<UINT>(argument(1)),
                                                   static_cast<WPARAM>(argument(2)),
                                                   static_cast<LPARAM>(native_long_parameter))
                                : ::DefWindowProcA(window, static_cast<UINT>(argument(1)),
                                                   static_cast<WPARAM>(argument(2)),
                                                   static_cast<LPARAM>(native_long_parameter));
        if (argument(1) == WM_GETTEXT && native_long_parameter != 0 && argument(3) != 0) {
            const auto byte_count = static_cast<std::size_t>(argument(2)) * sizeof(wchar_t);
            cpu.memory().write(
                argument(3),
                std::span<const std::uint8_t>(
                    reinterpret_cast<const std::uint8_t *>(native_long_parameter), byte_count));
        }
        cpu.set_reg(Rax, static_cast<std::uint64_t>(result));
        finish_call(4);
        break;
    }
    case Api::GuestWindowText: {
        const auto window = reinterpret_cast<HWND>(static_cast<std::uintptr_t>(argument(0)));
        const bool wide = thunk_name.ends_with("W");
        if (thunk_name.find("!SetWindowText") != std::string::npos) {
            const auto result =
                wide ? ::SetWindowTextW(window, cpu.memory().read_wide_string(argument(1)).c_str())
                     : ::SetWindowTextA(window, cpu.memory().read_c_string(argument(1)).c_str());
            if (result == FALSE) {
                last_error_ = ::GetLastError();
            }
            cpu.set_reg(Rax, result != FALSE ? 1 : 0);
            finish_call(2);
            break;
        }
        if (thunk_name.find("!GetWindowTextLength") != std::string::npos) {
            const auto result =
                wide ? ::GetWindowTextLengthW(window) : ::GetWindowTextLengthA(window);
            cpu.set_reg(Rax, static_cast<std::uint32_t>(result));
            finish_call(1);
            break;
        }
        const auto capacity = static_cast<int>(argument(2));
        int result = 0;
        if (wide) {
            std::vector<wchar_t> buffer(std::max(capacity, 1));
            result = ::GetWindowTextW(window, buffer.data(), capacity);
            if (result >= 0 && capacity > 0) {
                cpu.memory().write(argument(1),
                                   std::span<const std::uint8_t>(
                                       reinterpret_cast<const std::uint8_t *>(buffer.data()),
                                       (static_cast<std::size_t>(result) + 1) * sizeof(wchar_t)));
            }
        } else {
            std::vector<char> buffer(std::max(capacity, 1));
            result = ::GetWindowTextA(window, buffer.data(), capacity);
            if (result >= 0 && capacity > 0) {
                cpu.memory().write(
                    argument(1),
                    std::span<const std::uint8_t>(
                        reinterpret_cast<const std::uint8_t *>(buffer.data()), result + 1));
            }
        }
        cpu.set_reg(Rax, static_cast<std::uint32_t>(result));
        finish_call(3);
        break;
    }
    case Api::GuestSendMessage: {
        const auto window = reinterpret_cast<HWND>(static_cast<std::uintptr_t>(argument(0)));
        const auto message = static_cast<UINT>(argument(1));
        const auto word_parameter = static_cast<WPARAM>(argument(2));
        const auto guest_long_parameter = argument(3);
        const bool wide = thunk_name.ends_with("W");
        LRESULT result = 0;
        bool supported = true;
        if (message == EM_SETHANDLE) {
            const auto guest_handle = static_cast<std::uint64_t>(word_parameter);
            const auto allocation = heap_sizes_.find(guest_handle);
            if (allocation == heap_sizes_.end()) {
                last_error_ = ERROR_INVALID_HANDLE;
            } else if (wide) {
                const auto text = cpu.memory().read_wide_string(
                    guest_handle, static_cast<std::size_t>(allocation->second / sizeof(wchar_t)));
                result =
                    ::SendMessageW(window, WM_SETTEXT, 0, reinterpret_cast<LPARAM>(text.c_str()));
            } else {
                const auto text = cpu.memory().read_c_string(
                    guest_handle, static_cast<std::size_t>(allocation->second));
                result =
                    ::SendMessageA(window, WM_SETTEXT, 0, reinterpret_cast<LPARAM>(text.c_str()));
            }
            if (allocation != heap_sizes_.end() && result != 0) {
                edit_memory_handles_[reinterpret_cast<std::uint64_t>(window)] = guest_handle;
            }
        } else if (message == EM_GETHANDLE) {
            const auto retained =
                edit_memory_handles_.find(reinterpret_cast<std::uint64_t>(window));
            if (retained != edit_memory_handles_.end()) {
                auto guest_handle = retained->second;
                const auto length =
                    wide ? ::GetWindowTextLengthW(window) : ::GetWindowTextLengthA(window);
                const auto byte_count =
                    (static_cast<std::uint64_t>(std::max(length, 0)) + 1) * (wide ? 2 : 1);
                const auto allocation = heap_sizes_.find(guest_handle);
                if (allocation == heap_sizes_.end() || allocation->second < byte_count) {
                    guest_handle = allocate(byte_count);
                    retained->second = guest_handle;
                }
                if (wide) {
                    std::vector<wchar_t> text(static_cast<std::size_t>(length) + 1);
                    ::GetWindowTextW(window, text.data(), static_cast<int>(text.size()));
                    cpu.memory().write(
                        guest_handle,
                        std::span<const std::uint8_t>(
                            reinterpret_cast<const std::uint8_t *>(text.data()), byte_count));
                } else {
                    std::vector<char> text(static_cast<std::size_t>(length) + 1);
                    ::GetWindowTextA(window, text.data(), static_cast<int>(text.size()));
                    cpu.memory().write(
                        guest_handle,
                        std::span<const std::uint8_t>(
                            reinterpret_cast<const std::uint8_t *>(text.data()), byte_count));
                }
                result = static_cast<LRESULT>(guest_handle);
            }
        } else if (message == WM_SETTEXT) {
            if (wide) {
                const auto text = guest_long_parameter == 0
                                      ? std::wstring{}
                                      : cpu.memory().read_wide_string(guest_long_parameter);
                result = ::SendMessageW(window, message, word_parameter,
                                        reinterpret_cast<LPARAM>(text.c_str()));
            } else {
                const auto text = guest_long_parameter == 0
                                      ? std::string{}
                                      : cpu.memory().read_c_string(guest_long_parameter);
                result = ::SendMessageA(window, message, word_parameter,
                                        reinterpret_cast<LPARAM>(text.c_str()));
            }
        } else if (message == WM_GETTEXT) {
            const auto capacity = static_cast<std::size_t>(word_parameter);
            if (capacity > 0x100000) {
                supported = false;
            } else if (wide) {
                std::vector<wchar_t> buffer(std::max<std::size_t>(capacity, 1));
                result = ::SendMessageW(window, message, word_parameter,
                                        reinterpret_cast<LPARAM>(buffer.data()));
                if (guest_long_parameter != 0 && capacity != 0) {
                    const auto characters = std::min<std::size_t>(
                        static_cast<std::size_t>(std::max<LRESULT>(result, 0)) + 1, capacity);
                    cpu.memory().write(guest_long_parameter,
                                       std::span<const std::uint8_t>(
                                           reinterpret_cast<const std::uint8_t *>(buffer.data()),
                                           characters * sizeof(wchar_t)));
                }
            } else {
                std::vector<char> buffer(std::max<std::size_t>(capacity, 1));
                result = ::SendMessageA(window, message, word_parameter,
                                        reinterpret_cast<LPARAM>(buffer.data()));
                if (guest_long_parameter != 0 && capacity != 0) {
                    const auto characters = std::min<std::size_t>(
                        static_cast<std::size_t>(std::max<LRESULT>(result, 0)) + 1, capacity);
                    cpu.memory().write(
                        guest_long_parameter,
                        std::span<const std::uint8_t>(
                            reinterpret_cast<const std::uint8_t *>(buffer.data()), characters));
                }
            }
        } else {
            switch (message) {
            case WM_CREATE:
            case WM_NCCREATE:
            case WM_GETMINMAXINFO:
            case WM_NCCALCSIZE:
            case WM_WINDOWPOSCHANGING:
            case WM_WINDOWPOSCHANGED:
            case WM_STYLECHANGING:
            case WM_STYLECHANGED:
            case WM_SIZING:
            case WM_MOVING:
            case WM_DPICHANGED:
            case WM_COPYDATA:
            case WM_NOTIFY:
            case WM_HELP:
            case WM_DEVICECHANGE:
                supported = false;
                break;
            default:
                result = wide ? ::SendMessageW(window, message, word_parameter,
                                               static_cast<LPARAM>(guest_long_parameter))
                              : ::SendMessageA(window, message, word_parameter,
                                               static_cast<LPARAM>(guest_long_parameter));
                break;
            }
        }
        if (!supported) {
            last_error_ = ERROR_NOT_SUPPORTED;
            log::warn("window", thunk_name + " refused pointer-bearing " +
                                    detail::window_message_name(message));
        }
        if (auto exception = detail::take_callback_exception(); exception != nullptr) {
            std::rethrow_exception(exception);
        }
        cpu.set_reg(Rax, static_cast<std::uint64_t>(result));
        finish_call(4);
        break;
    }
    case Api::GuestCursor:
        if (thunk_name.ends_with("!SetCursor")) {
            const auto result =
                ::SetCursor(reinterpret_cast<HCURSOR>(static_cast<std::uintptr_t>(argument(0))));
            cpu.set_reg(Rax, reinterpret_cast<std::uint64_t>(result));
        } else {
            cpu.set_reg(Rax, static_cast<std::uint32_t>(::ShowCursor(argument(0) != 0)));
        }
        finish_call(1);
        break;
    case Api::GuestDisplaySettings: {
        const bool wide = thunk_name.ends_with("W");
        const bool extended = thunk_name.find("SettingsEx") != std::string::npos;
        const auto device_pointer = argument(0);
        const auto output = argument(2);
        BOOL result = FALSE;
        if (output != 0) {
            if (wide) {
                const auto device = device_pointer == 0
                                        ? std::wstring{}
                                        : cpu.memory().read_wide_string(device_pointer);
                DEVMODEW mode{};
                mode.dmSize = sizeof(mode);
                result =
                    extended
                        ? ::EnumDisplaySettingsExW(device_pointer == 0 ? nullptr : device.c_str(),
                                                   static_cast<DWORD>(argument(1)), &mode,
                                                   static_cast<DWORD>(argument(3)))
                        : ::EnumDisplaySettingsW(device_pointer == 0 ? nullptr : device.c_str(),
                                                 static_cast<DWORD>(argument(1)), &mode);
                if (result != FALSE) {
                    cpu.memory().write(
                        output, std::span<const std::uint8_t>(
                                    reinterpret_cast<const std::uint8_t *>(&mode), sizeof(mode)));
                }
            } else {
                const auto device = device_pointer == 0
                                        ? std::string{}
                                        : cpu.memory().read_c_string(device_pointer);
                DEVMODEA mode{};
                mode.dmSize = sizeof(mode);
                result =
                    extended
                        ? ::EnumDisplaySettingsExA(device_pointer == 0 ? nullptr : device.c_str(),
                                                   static_cast<DWORD>(argument(1)), &mode,
                                                   static_cast<DWORD>(argument(3)))
                        : ::EnumDisplaySettingsA(device_pointer == 0 ? nullptr : device.c_str(),
                                                 static_cast<DWORD>(argument(1)), &mode);
                if (result != FALSE) {
                    cpu.memory().write(
                        output, std::span<const std::uint8_t>(
                                    reinterpret_cast<const std::uint8_t *>(&mode), sizeof(mode)));
                }
            }
        } else {
            last_error_ = ERROR_INVALID_PARAMETER;
        }
        cpu.set_reg(Rax, result != FALSE ? 1 : 0);
        finish_call(extended ? 4 : 3);
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
            const auto message_address = argument(0);
            const auto message = read_message(message_address);
            cpu.set_reg(Rax, ::TranslateMessage(&message) != FALSE ? 1 : 0);
            finish_call(1);
            break;
        }
        if (thunk_name.ends_with("!DispatchMessageA") ||
            thunk_name.ends_with("!DispatchMessageW")) {
            const auto message_address = argument(0);
            const auto message = read_message(message_address);
            const auto result = thunk_name.ends_with("W") ? ::DispatchMessageW(&message)
                                                          : ::DispatchMessageA(&message);
            if (auto exception = detail::take_callback_exception(); exception != nullptr) {
                std::rethrow_exception(exception);
            }
            cpu.set_reg(Rax, static_cast<std::uint64_t>(result));
            finish_call(1);
            break;
        }
        // Get/PeekMessage can synchronously deliver sent messages before returning. Those
        // callbacks legally clobber volatile argument registers, so retain the outer API
        // arguments before entering USER32 rather than calling argument() afterward.
        const auto message_address = argument(0);
        const auto window_value = argument(1);
        const auto minimum_message = static_cast<UINT>(argument(2));
        const auto maximum_message = static_cast<UINT>(argument(3));
        const auto remove_flags = static_cast<UINT>(argument(4));
        MSG message{};
        const auto window = reinterpret_cast<HWND>(static_cast<std::uintptr_t>(window_value));
        int result = 0;
        if (quit_message_pending_) {
            message.message = WM_QUIT;
            message.wParam = quit_message_code_;
            write_message(message_address, message);
            const bool get_message =
                thunk_name.ends_with("!GetMessageA") || thunk_name.ends_with("!GetMessageW");
            if (get_message || (remove_flags & PM_REMOVE) != 0) {
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
                             ? ::PeekMessageW(&message, window, minimum_message, maximum_message,
                                              remove_flags)
                             : ::PeekMessageA(&message, window, minimum_message, maximum_message,
                                              remove_flags);
            }
            if (result != 0) {
                write_message(message_address, message);
            }
            cpu.set_reg(Rax, static_cast<std::uint32_t>(result));
            finish_call(5);
        } else {
            result = thunk_name.ends_with("W")
                         ? ::GetMessageW(&message, window, minimum_message, maximum_message)
                         : ::GetMessageA(&message, window, minimum_message, maximum_message);
            if (result >= 0) {
                write_message(message_address, message);
            } else {
                last_error_ = ::GetLastError();
            }
            cpu.set_reg(Rax, static_cast<std::uint32_t>(result));
            finish_call(4);
        }
        break;
    }
    case Api::GuestFileDialog: {
        if (thunk_name.ends_with("!CommDlgExtendedError")) {
            cpu.set_reg(Rax, common_dialog_error_);
            finish_call();
            break;
        }
        common_dialog_error_ = 0;
        const auto structure = argument(0);
        const auto expected_size = guest_is_64_bit_ ? 152U : 88U;
        if (structure == 0 || cpu.memory().read32(structure) != expected_size) {
            common_dialog_error_ = CDERR_STRUCTSIZE;
            cpu.set_reg(Rax, 0);
            finish_call(1);
            break;
        }
        const auto pointer = [&](std::uint32_t offset32, std::uint32_t offset64) {
            return guest_is_64_bit_ ? cpu.memory().read64(structure + offset64)
                                    : cpu.memory().read32(structure + offset32);
        };
        constexpr std::uint32_t maximum_dialog_characters = 1024 * 1024;
        const auto file_pointer = pointer(28, 48);
        const auto file_capacity = cpu.memory().read32(structure + (guest_is_64_bit_ ? 56 : 32));
        const auto title_pointer = pointer(36, 64);
        const auto title_capacity = cpu.memory().read32(structure + (guest_is_64_bit_ ? 72 : 40));
        if (file_pointer == 0 || file_capacity == 0 || file_capacity > maximum_dialog_characters ||
            title_capacity > maximum_dialog_characters) {
            common_dialog_error_ = FNERR_BUFFERTOOSMALL;
            cpu.set_reg(Rax, 0);
            finish_call(1);
            break;
        }
        auto flags = cpu.memory().read32(structure + (guest_is_64_bit_ ? 96 : 52));
        constexpr DWORD callback_or_template_flags =
            OFN_ENABLEHOOK | OFN_ENABLETEMPLATE | OFN_ENABLETEMPLATEHANDLE;
        if ((flags & callback_or_template_flags) != 0) {
            log::warn("dialog", "ignoring guest file-dialog hook/template customization");
            flags &= ~callback_or_template_flags;
        }
        const auto open = thunk_name.find("!GetOpenFileName") != std::string::npos;
        BOOL success = FALSE;
        if (thunk_name.ends_with("W")) {
            const auto read_string = [&](std::uint64_t address) {
                std::wstring value;
                if (address == 0) {
                    return value;
                }
                for (std::uint32_t index = 0; index < maximum_dialog_characters; ++index) {
                    const auto character = cpu.memory().read16(address + index * 2);
                    if (character == 0) {
                        return value;
                    }
                    value.push_back(static_cast<wchar_t>(character));
                }
                throw Error("unterminated guest file-dialog string");
            };
            const auto read_filter = [&](std::uint64_t address) {
                std::vector<wchar_t> value;
                if (address == 0) {
                    return value;
                }
                bool previous_null = false;
                for (std::uint32_t index = 0; index < maximum_dialog_characters; ++index) {
                    const auto character = cpu.memory().read16(address + index * 2);
                    value.push_back(static_cast<wchar_t>(character));
                    if (character == 0 && previous_null) {
                        return value;
                    }
                    previous_null = character == 0;
                }
                throw Error("unterminated guest file-dialog filter");
            };
            std::vector<wchar_t> file(file_capacity);
            const auto initial_file = read_string(file_pointer);
            const auto initial_count = std::min<std::size_t>(initial_file.size(), file.size() - 1);
            std::copy_n(initial_file.c_str(), initial_count, file.begin());
            file[initial_count] = L'\0';
            std::vector<wchar_t> file_title(title_pointer == 0 ? 0 : title_capacity);
            const auto filter = read_filter(pointer(12, 24));
            const auto initial_directory = read_string(pointer(44, 80));
            const auto dialog_title = read_string(pointer(48, 88));
            const auto default_extension = read_string(pointer(60, 104));
            OPENFILENAMEW dialog{};
            dialog.lStructSize = sizeof(dialog);
            dialog.hwndOwner = reinterpret_cast<HWND>(static_cast<std::uintptr_t>(pointer(4, 8)));
            dialog.lpstrFilter = filter.empty() ? nullptr : filter.data();
            dialog.nFilterIndex = cpu.memory().read32(structure + (guest_is_64_bit_ ? 44 : 24));
            dialog.lpstrFile = file.data();
            dialog.nMaxFile = file_capacity;
            dialog.lpstrFileTitle = file_title.empty() ? nullptr : file_title.data();
            dialog.nMaxFileTitle = title_capacity;
            dialog.lpstrInitialDir =
                initial_directory.empty() ? nullptr : initial_directory.c_str();
            dialog.lpstrTitle = dialog_title.empty() ? nullptr : dialog_title.c_str();
            dialog.Flags = flags;
            dialog.lpstrDefExt = default_extension.empty() ? nullptr : default_extension.c_str();
            success = open ? ::GetOpenFileNameW(&dialog) : ::GetSaveFileNameW(&dialog);
            common_dialog_error_ = success != FALSE ? 0 : ::CommDlgExtendedError();
            if (success != FALSE) {
                const auto multiple = (flags & OFN_ALLOWMULTISELECT) != 0;
                bool previous_null = false;
                for (std::size_t index = 0; index < file.size(); ++index) {
                    cpu.memory().write16(file_pointer + index * 2,
                                         static_cast<std::uint16_t>(file[index]));
                    if (file[index] == L'\0' && (!multiple || previous_null)) {
                        break;
                    }
                    previous_null = file[index] == L'\0';
                }
                if (title_pointer != 0) {
                    for (std::size_t index = 0; index < file_title.size(); ++index) {
                        cpu.memory().write16(title_pointer + index * 2,
                                             static_cast<std::uint16_t>(file_title[index]));
                        if (file_title[index] == L'\0') {
                            break;
                        }
                    }
                }
                cpu.memory().write32(structure + (guest_is_64_bit_ ? 44 : 24), dialog.nFilterIndex);
                cpu.memory().write16(structure + (guest_is_64_bit_ ? 100 : 56), dialog.nFileOffset);
                cpu.memory().write16(structure + (guest_is_64_bit_ ? 102 : 58),
                                     dialog.nFileExtension);
            }
        } else {
            const auto read_string = [&](std::uint64_t address) {
                std::string value;
                if (address == 0) {
                    return value;
                }
                for (std::uint32_t index = 0; index < maximum_dialog_characters; ++index) {
                    const auto character = cpu.memory().read8(address + index);
                    if (character == 0) {
                        return value;
                    }
                    value.push_back(static_cast<char>(character));
                }
                throw Error("unterminated guest file-dialog string");
            };
            const auto read_filter = [&](std::uint64_t address) {
                std::vector<char> value;
                if (address == 0) {
                    return value;
                }
                bool previous_null = false;
                for (std::uint32_t index = 0; index < maximum_dialog_characters; ++index) {
                    const auto character = cpu.memory().read8(address + index);
                    value.push_back(static_cast<char>(character));
                    if (character == 0 && previous_null) {
                        return value;
                    }
                    previous_null = character == 0;
                }
                throw Error("unterminated guest file-dialog filter");
            };
            std::vector<char> file(file_capacity);
            const auto initial_file = read_string(file_pointer);
            const auto initial_count = std::min<std::size_t>(initial_file.size(), file.size() - 1);
            std::copy_n(initial_file.c_str(), initial_count, file.begin());
            file[initial_count] = '\0';
            std::vector<char> file_title(title_pointer == 0 ? 0 : title_capacity);
            const auto filter = read_filter(pointer(12, 24));
            const auto initial_directory = read_string(pointer(44, 80));
            const auto dialog_title = read_string(pointer(48, 88));
            const auto default_extension = read_string(pointer(60, 104));
            OPENFILENAMEA dialog{};
            dialog.lStructSize = sizeof(dialog);
            dialog.hwndOwner = reinterpret_cast<HWND>(static_cast<std::uintptr_t>(pointer(4, 8)));
            dialog.lpstrFilter = filter.empty() ? nullptr : filter.data();
            dialog.nFilterIndex = cpu.memory().read32(structure + (guest_is_64_bit_ ? 44 : 24));
            dialog.lpstrFile = file.data();
            dialog.nMaxFile = file_capacity;
            dialog.lpstrFileTitle = file_title.empty() ? nullptr : file_title.data();
            dialog.nMaxFileTitle = title_capacity;
            dialog.lpstrInitialDir =
                initial_directory.empty() ? nullptr : initial_directory.c_str();
            dialog.lpstrTitle = dialog_title.empty() ? nullptr : dialog_title.c_str();
            dialog.Flags = flags;
            dialog.lpstrDefExt = default_extension.empty() ? nullptr : default_extension.c_str();
            success = open ? ::GetOpenFileNameA(&dialog) : ::GetSaveFileNameA(&dialog);
            common_dialog_error_ = success != FALSE ? 0 : ::CommDlgExtendedError();
            if (success != FALSE) {
                const auto multiple = (flags & OFN_ALLOWMULTISELECT) != 0;
                std::size_t file_bytes = 0;
                bool previous_null = false;
                for (; file_bytes < file.size(); ++file_bytes) {
                    const auto current_null = file[file_bytes] == '\0';
                    if (current_null && (!multiple || previous_null)) {
                        ++file_bytes;
                        break;
                    }
                    previous_null = current_null;
                }
                cpu.memory().write(
                    file_pointer,
                    std::span<const std::uint8_t>(
                        reinterpret_cast<const std::uint8_t *>(file.data()), file_bytes));
                if (title_pointer != 0 && !file_title.empty()) {
                    cpu.memory().write(title_pointer, std::span<const std::uint8_t>(
                                                          reinterpret_cast<const std::uint8_t *>(
                                                              file_title.data()),
                                                          std::strlen(file_title.data()) + 1));
                }
                cpu.memory().write32(structure + (guest_is_64_bit_ ? 44 : 24), dialog.nFilterIndex);
                cpu.memory().write16(structure + (guest_is_64_bit_ ? 100 : 56), dialog.nFileOffset);
                cpu.memory().write16(structure + (guest_is_64_bit_ ? 102 : 58),
                                     dialog.nFileExtension);
            }
        }
        cpu.set_reg(Rax, success != FALSE ? 1 : 0);
        finish_call(1);
        break;
    }
    case Api::GuestMimeType: {
        constexpr std::uint32_t maximum_input_bytes = 1024 * 1024;
        constexpr std::uint32_t maximum_string_characters = 32 * 1024;
        const auto output_pointer = argument(6);
        const auto finish_result = [&](HRESULT result) {
            cpu.set_reg(Rax, static_cast<std::uint32_t>(result));
            finish_call(8);
        };
        if (output_pointer == 0) {
            finish_result(E_INVALIDARG);
            break;
        }
        if (guest_is_64_bit_) {
            cpu.memory().write64(output_pointer, 0);
        } else {
            cpu.memory().write32(output_pointer, 0);
        }
        const auto binding_context = argument(0);
        const auto url_pointer = argument(1);
        const auto data_pointer = argument(2);
        const auto data_size = argument(3);
        const auto proposed_pointer = argument(4);
        const auto flags = static_cast<DWORD>(argument(5));
        const auto reserved = argument(7);
        if (binding_context != 0 || reserved != 0 || data_size > maximum_input_bytes ||
            (data_pointer == 0 && data_size != 0)) {
            finish_result(E_INVALIDARG);
            break;
        }
        const auto read_wide_string = [&](std::uint64_t address) {
            std::wstring value;
            for (std::uint32_t index = 0; index < maximum_string_characters; ++index) {
                const auto character = cpu.memory().read16(address + index * sizeof(wchar_t));
                if (character == 0) {
                    return value;
                }
                value.push_back(static_cast<wchar_t>(character));
            }
            throw Error("unterminated guest MIME string");
        };
        const auto url = url_pointer == 0 ? std::wstring{} : read_wide_string(url_pointer);
        const auto proposed =
            proposed_pointer == 0 ? std::wstring{} : read_wide_string(proposed_pointer);
        const auto data =
            data_size == 0 ? std::vector<std::uint8_t>{}
                           : cpu.memory().read(data_pointer, static_cast<std::size_t>(data_size));
        wchar_t *host_mime = nullptr;
        auto result = ::FindMimeFromData(
            nullptr, url_pointer == 0 ? nullptr : url.c_str(),
            data.empty() ? nullptr : const_cast<std::uint8_t *>(data.data()),
            static_cast<DWORD>(data.size()), proposed_pointer == 0 ? nullptr : proposed.c_str(),
            flags, &host_mime, 0);
        if (SUCCEEDED(result)) {
            std::size_t length = 0;
            if (host_mime == nullptr) {
                result = E_FAIL;
            } else {
                while (length < maximum_string_characters && host_mime[length] != L'\0') {
                    ++length;
                }
                if (length == maximum_string_characters) {
                    result = E_FAIL;
                } else {
                    const auto guest_mime = allocate((length + 1) * sizeof(wchar_t));
                    cpu.memory().write(guest_mime,
                                       std::span<const std::uint8_t>(
                                           reinterpret_cast<const std::uint8_t *>(host_mime),
                                           (length + 1) * sizeof(wchar_t)));
                    if (guest_is_64_bit_) {
                        cpu.memory().write64(output_pointer, guest_mime);
                    } else {
                        cpu.memory().write32(output_pointer,
                                             static_cast<std::uint32_t>(guest_mime));
                    }
                }
            }
        }
        ::CoTaskMemFree(host_mime);
        finish_result(result);
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
    case Api::ArgcPointer:
        cpu.set_reg(Rax, crt_argc);
        finish_call();
        break;
    case Api::ArgvPointer:
        cpu.set_reg(Rax, crt_argv);
        finish_call();
        break;
    case Api::WideArgvPointer:
        cpu.set_reg(Rax, crt_wargv);
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
    case Api::GuestFormatMessage: {
        const bool ansi = thunk_name.ends_with("FormatMessageA");
        const auto flags = static_cast<DWORD>(argument(0));
        const auto source_address = argument(1);
        const auto output_address = argument(4);
        const auto output_size = static_cast<DWORD>(argument(5));
        const auto arguments_address = argument(6);
        if (ansi) {
            std::string source;
            const char *host_source = nullptr;
            if ((flags & FORMAT_MESSAGE_FROM_STRING) != 0) {
                if (source_address == 0) {
                    last_error_ = ERROR_INVALID_PARAMETER;
                    cpu.set_reg(Rax, 0);
                    finish_call(7);
                    break;
                }
                source = cpu.memory().read_c_string(source_address, 32767);
                host_source = source.c_str();
            } else if ((flags & FORMAT_MESSAGE_FROM_SYSTEM) == 0) {
                last_error_ = ERROR_NOT_SUPPORTED;
                cpu.set_reg(Rax, 0);
                finish_call(7);
                break;
            }
            if ((flags & FORMAT_MESSAGE_IGNORE_INSERTS) == 0 && arguments_address != 0) {
                last_error_ = ERROR_NOT_SUPPORTED;
                cpu.set_reg(Rax, 0);
                finish_call(7);
                break;
            }
            std::vector<char> buffer(32768);
            ::SetLastError(ERROR_SUCCESS);
            const auto length =
                ::FormatMessageA(flags & ~FORMAT_MESSAGE_ALLOCATE_BUFFER, host_source,
                                 static_cast<DWORD>(argument(2)), static_cast<DWORD>(argument(3)),
                                 buffer.data(), static_cast<DWORD>(buffer.size()), nullptr);
            if (length == 0) {
                last_error_ = ::GetLastError();
                cpu.set_reg(Rax, 0);
                finish_call(7);
                break;
            }
            if ((flags & FORMAT_MESSAGE_ALLOCATE_BUFFER) != 0) {
                if (output_address == 0) {
                    last_error_ = ERROR_INVALID_PARAMETER;
                    cpu.set_reg(Rax, 0);
                    finish_call(7);
                    break;
                }
                const auto guest_buffer = allocate(static_cast<std::uint64_t>(length) + 1);
                cpu.memory().write(
                    guest_buffer,
                    std::span<const std::uint8_t>(
                        reinterpret_cast<const std::uint8_t *>(buffer.data()), length + 1));
                if (guest_is_64_bit_) {
                    cpu.memory().write64(output_address, guest_buffer);
                } else {
                    cpu.memory().write32(output_address, static_cast<std::uint32_t>(guest_buffer));
                }
            } else {
                if (output_address == 0 || output_size <= length) {
                    last_error_ = ERROR_INSUFFICIENT_BUFFER;
                    cpu.set_reg(Rax, 0);
                    finish_call(7);
                    break;
                }
                cpu.memory().write(
                    output_address,
                    std::span<const std::uint8_t>(
                        reinterpret_cast<const std::uint8_t *>(buffer.data()), length + 1));
            }
            cpu.set_reg(Rax, length);
            finish_call(7);
            break;
        }
        std::wstring source;
        const wchar_t *host_source = nullptr;
        if ((flags & FORMAT_MESSAGE_FROM_STRING) != 0) {
            if (source_address == 0) {
                last_error_ = ERROR_INVALID_PARAMETER;
                cpu.set_reg(Rax, 0);
                finish_call(7);
                break;
            }
            source = cpu.memory().read_wide_string(source_address, 32767);
            host_source = source.c_str();
        } else if ((flags & FORMAT_MESSAGE_FROM_SYSTEM) == 0) {
            // Guest module handles and host HMODULE values are intentionally not interchangeable.
            last_error_ = ERROR_NOT_SUPPORTED;
            cpu.set_reg(Rax, 0);
            finish_call(7);
            break;
        }

        std::array<std::uint64_t, 99> host_arguments{};
        std::array<std::wstring, 99> host_strings{};
        unsigned maximum_insert = 0;
        if ((flags & FORMAT_MESSAGE_IGNORE_INSERTS) == 0) {
            for (std::size_t index = 0; index < source.size(); ++index) {
                if (source[index] != L'%' || index + 1 >= source.size() ||
                    !std::iswdigit(source[index + 1])) {
                    continue;
                }
                std::size_t cursor = index + 1;
                unsigned insert = 0;
                while (cursor < source.size() && std::iswdigit(source[cursor])) {
                    insert = insert * 10 + static_cast<unsigned>(source[cursor] - L'0');
                    ++cursor;
                }
                if (insert == 0 || insert > host_arguments.size()) {
                    last_error_ = ERROR_INVALID_PARAMETER;
                    cpu.set_reg(Rax, 0);
                    finish_call(7);
                    return true;
                }
                maximum_insert = std::max(maximum_insert, insert);
                bool string_insert = true;
                if (cursor < source.size() && source[cursor] == L'!') {
                    const auto end = source.find(L'!', cursor + 1);
                    if (end != std::wstring::npos) {
                        const auto format = source.substr(cursor + 1, end - cursor - 1);
                        string_insert = format.find(L's') != std::wstring::npos ||
                                        format.find(L'S') != std::wstring::npos;
                    }
                }
                if (arguments_address == 0) {
                    last_error_ = ERROR_INVALID_PARAMETER;
                    cpu.set_reg(Rax, 0);
                    finish_call(7);
                    return true;
                }
                const auto value = guest_is_64_bit_
                                       ? cpu.memory().read64(arguments_address + (insert - 1) * 8)
                                       : cpu.memory().read32(arguments_address + (insert - 1) * 4);
                host_arguments[insert - 1] = value;
                if (string_insert && value != 0) {
                    host_strings[insert - 1] = cpu.memory().read_wide_string(value, 32767);
                    host_arguments[insert - 1] =
                        reinterpret_cast<std::uint64_t>(host_strings[insert - 1].c_str());
                }
                index = cursor - 1;
            }
        }

        std::vector<wchar_t> buffer(32768);
        ::SetLastError(ERROR_SUCCESS);
        const auto native_flags = flags & ~FORMAT_MESSAGE_ALLOCATE_BUFFER;
        const auto length = ::FormatMessageW(
            native_flags, host_source, static_cast<DWORD>(argument(2)),
            static_cast<DWORD>(argument(3)), buffer.data(), static_cast<DWORD>(buffer.size()),
            maximum_insert == 0 ? nullptr : reinterpret_cast<va_list *>(host_arguments.data()));
        if (length == 0) {
            last_error_ = ::GetLastError();
            cpu.set_reg(Rax, 0);
            finish_call(7);
            break;
        }
        if ((flags & FORMAT_MESSAGE_ALLOCATE_BUFFER) != 0) {
            if (output_address == 0) {
                last_error_ = ERROR_INVALID_PARAMETER;
                cpu.set_reg(Rax, 0);
                finish_call(7);
                break;
            }
            const auto guest_buffer = allocate((static_cast<std::uint64_t>(length) + 1) * 2);
            for (std::size_t index = 0; index <= length; ++index) {
                cpu.memory().write16(guest_buffer + index * 2,
                                     static_cast<std::uint16_t>(buffer[index]));
            }
            if (guest_is_64_bit_) {
                cpu.memory().write64(output_address, guest_buffer);
            } else {
                cpu.memory().write32(output_address, static_cast<std::uint32_t>(guest_buffer));
            }
        } else {
            if (output_address == 0 || output_size <= length) {
                last_error_ = ERROR_INSUFFICIENT_BUFFER;
                cpu.set_reg(Rax, 0);
                finish_call(7);
                break;
            }
            for (std::size_t index = 0; index <= length; ++index) {
                cpu.memory().write16(output_address + index * 2,
                                     static_cast<std::uint16_t>(buffer[index]));
            }
        }
        cpu.set_reg(Rax, length);
        finish_call(7);
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
    case Api::GuestFileMapping: {
        constexpr std::uint64_t maximum_view_size = 256ULL * 1024 * 1024;
        if (thunk_name.ends_with("!CreateFileMappingA") ||
            thunk_name.ends_with("!CreateFileMappingW")) {
            const auto file = argument(0);
            HANDLE host_file = INVALID_HANDLE_VALUE;
            if (file != (guest_is_64_bit_ ? UINT64_MAX : UINT32_MAX)) {
                const auto found = file_handles_.find(file);
                if (found == file_handles_.end()) {
                    last_error_ = ERROR_INVALID_HANDLE;
                    cpu.set_reg(Rax, 0);
                    finish_call(6);
                    break;
                }
                host_file = static_cast<HANDLE>(found->second);
            }
            const auto maximum_size =
                ((argument(3) & UINT32_MAX) << 32) | (argument(4) & UINT32_MAX);
            if (argument(1) != 0 || argument(5) != 0) {
                last_error_ = ERROR_NOT_SUPPORTED;
                cpu.set_reg(Rax, 0);
                finish_call(6);
                break;
            }
            if (maximum_size > maximum_view_size) {
                last_error_ = ERROR_NOT_ENOUGH_MEMORY;
                cpu.set_reg(Rax, 0);
                finish_call(6);
                break;
            }
            const auto host_mapping = ::CreateFileMappingW(
                host_file, nullptr, static_cast<DWORD>(argument(2)),
                static_cast<DWORD>(argument(3)), static_cast<DWORD>(argument(4)), nullptr);
            if (host_mapping == nullptr) {
                last_error_ = ::GetLastError();
                cpu.set_reg(Rax, 0);
            } else {
                const auto guest_handle = next_mapping_handle_++;
                mapping_handles_.emplace(guest_handle, host_mapping);
                cpu.set_reg(Rax, guest_handle);
            }
            finish_call(6);
            break;
        }
        if (thunk_name.ends_with("!UnmapViewOfFile")) {
            const auto address = argument(0);
            const auto found = mapped_views_.find(address);
            const auto result = found != mapped_views_.end() && cpu.memory().unmap_owned(address);
            if (result) {
                mapped_views_.erase(found);
                heap_sizes_.erase(address);
            } else {
                last_error_ = ERROR_INVALID_ADDRESS;
            }
            cpu.set_reg(Rax, result ? 1 : 0);
            finish_call(1);
            break;
        }
        const auto mapping = mapping_handles_.find(argument(0));
        const auto access = static_cast<DWORD>(argument(1));
        const auto requested_size = argument(4);
        if (mapping == mapping_handles_.end() ||
            (access != FILE_MAP_READ && access != FILE_MAP_COPY) ||
            requested_size > maximum_view_size) {
            last_error_ = mapping == mapping_handles_.end()    ? ERROR_INVALID_HANDLE
                          : requested_size > maximum_view_size ? ERROR_NOT_ENOUGH_MEMORY
                                                               : ERROR_ACCESS_DENIED;
            cpu.set_reg(Rax, 0);
            finish_call(5);
            break;
        }
        auto *const native_view = ::MapViewOfFile(
            static_cast<HANDLE>(mapping->second), access, static_cast<DWORD>(argument(2)),
            static_cast<DWORD>(argument(3)), static_cast<SIZE_T>(requested_size));
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
                    finish_call(5);
                    break;
                }
                size = information.RegionSize;
            }
            if (size == 0 || size > maximum_view_size) {
                ::UnmapViewOfFile(native_view);
                last_error_ =
                    size > maximum_view_size ? ERROR_NOT_ENOUGH_MEMORY : ERROR_INVALID_PARAMETER;
                cpu.set_reg(Rax, 0);
                finish_call(5);
                break;
            }
            const auto guest_view = allocate(size);
            cpu.memory().write(guest_view, std::span<const std::uint8_t>(
                                               reinterpret_cast<const std::uint8_t *>(native_view),
                                               static_cast<std::size_t>(size)));
            ::UnmapViewOfFile(native_view);
            if (access == FILE_MAP_READ) {
                static_cast<void>(cpu.memory().protect(guest_view, size, Read));
            }
            mapped_views_.emplace(guest_view, size);
            cpu.set_reg(Rax, guest_view);
        }
        finish_call(5);
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
    case Api::FeatureStateSubscribe: {
        // The guest callback is retained here rather than handed to Windows, which would execute
        // it as native host code from a thread-pool timer thread.
        const auto subscription = allocate(8);
        feature_state_callbacks_.emplace(subscription, cpu.reg(Rdx));
        if (cpu.reg(Rcx) != 0) {
            cpu.memory().write64(cpu.reg(Rcx), subscription);
        }
        cpu.set_reg(Rax, 0);
        finish_call(3);
        break;
    }
    case Api::FeatureStateUnsubscribe:
        feature_state_callbacks_.erase(cpu.reg(Rcx));
        cpu.set_reg(Rax, 0);
        finish_call(1);
        break;
    case Api::WindowSubclass: {
        if (thunk_name.ends_with("SetWindowSubclass") || thunk_name.ends_with("#410")) {
            const auto window = argument(0);
            const auto procedure = argument(1);
            const auto id = argument(2);
            const auto reference_data = argument(3);
            auto token = std::uint64_t{0};
            WindowSubclass *existing = nullptr;
            for (const auto &[candidate, record] : window_subclasses_) {
                if (record.window == window && record.procedure == procedure && record.id == id) {
                    token = candidate;
                    existing = &window_subclasses_.at(candidate);
                    break;
                }
            }
            if (token == 0) {
                token = next_window_subclass_token_++;
                window_subclasses_[token] = {window, procedure, id, reference_data};
            }
            const auto success =
                procedure != 0 &&
                ::SetWindowSubclass(reinterpret_cast<HWND>(static_cast<std::uintptr_t>(window)),
                                    detail::window_subclass_bridge, token, 0) != FALSE;
            if (success && existing != nullptr) {
                existing->reference_data = reference_data;
            } else if (!success && existing == nullptr) {
                window_subclasses_.erase(token);
            }
            cpu.set_reg(Rax, success ? 1 : 0);
            finish_call(4);
        } else if (thunk_name.ends_with("RemoveWindowSubclass") || thunk_name.ends_with("#412")) {
            auto found = window_subclasses_.end();
            for (auto candidate = window_subclasses_.begin(); candidate != window_subclasses_.end();
                 ++candidate) {
                if (candidate->second.window == argument(0) &&
                    candidate->second.procedure == argument(1) &&
                    candidate->second.id == argument(2)) {
                    found = candidate;
                    break;
                }
            }
            const auto success =
                found != window_subclasses_.end() &&
                ::RemoveWindowSubclass(
                    reinterpret_cast<HWND>(static_cast<std::uintptr_t>(argument(0))),
                    detail::window_subclass_bridge, found->first) != FALSE;
            if (success) {
                window_subclasses_.erase(found);
            }
            cpu.set_reg(Rax, success ? 1 : 0);
            finish_call(3);
        } else if (thunk_name.ends_with("DefSubclassProc") || thunk_name.ends_with("#413")) {
            auto native_long_parameter = static_cast<std::int64_t>(argument(3));
            if (const auto translated = callback_long_parameters_.find(argument(3));
                translated != callback_long_parameters_.end()) {
                native_long_parameter = translated->second;
            }
            const auto result =
                ::DefSubclassProc(reinterpret_cast<HWND>(static_cast<std::uintptr_t>(argument(0))),
                                  static_cast<UINT>(argument(1)), static_cast<WPARAM>(argument(2)),
                                  static_cast<LPARAM>(native_long_parameter));
            cpu.set_reg(Rax, static_cast<std::uint64_t>(result));
            finish_call(4);
        } else {
            auto found = window_subclasses_.end();
            for (auto candidate = window_subclasses_.begin(); candidate != window_subclasses_.end();
                 ++candidate) {
                if (candidate->second.window == argument(0) &&
                    candidate->second.procedure == argument(1) &&
                    candidate->second.id == argument(2)) {
                    found = candidate;
                    break;
                }
            }
            const auto success = found != window_subclasses_.end() && argument(3) != 0;
            if (success) {
                if (guest_is_64_bit_) {
                    cpu.memory().write64(argument(3), found->second.reference_data);
                } else {
                    cpu.memory().write32(argument(3),
                                         static_cast<std::uint32_t>(found->second.reference_data));
                }
            }
            cpu.set_reg(Rax, success ? 1 : 0);
            finish_call(4);
        }
        break;
    }
    case Api::CreateThreadpoolTimer:
        cpu.set_reg(Rax, allocate(8));
        finish_call();
        break;
    case Api::GuestThreadCreate: {
        const auto entry = cpu.reg(R8);
        const auto parameter = cpu.reg(R9);
        if (entry == 0) {
            cpu.set_reg(Rax, 0);
            finish_call();
            break;
        }
        // Run cooperatively on the current interpreted CPU. This preserves guest/host isolation;
        // a scheduler can later provide independent CPU state without changing the ABI adapter.
        const auto result = invoke_guest(cpu, entry, {parameter, 0, 0, 0}, exit_code, exited);
        if (argument(5) != 0) {
            if (guest_is_64_bit_) {
                cpu.memory().write32(argument(5), GetCurrentThreadId());
            } else {
                cpu.memory().write32(argument(5), GetCurrentThreadId());
            }
        }
        cpu.set_reg(Rax, result == 0 ? 1 : result);
        finish_call();
        break;
    }
    case Api::GuestAtomicWait: {
        const auto storage = cpu.reg(Rcx);
        const auto comparand = cpu.reg(Rdx);
        const auto width = cpu.reg(R8);
        if (storage != 0 && comparand != 0) {
            if (width == 1) {
                cpu.memory().write8(storage,
                                    static_cast<std::uint8_t>(cpu.memory().read8(comparand) + 1));
            } else if (width == 2) {
                cpu.memory().write16(
                    storage, static_cast<std::uint16_t>(cpu.memory().read16(comparand) + 1));
            } else if (width == 4) {
                cpu.memory().write32(storage, cpu.memory().read32(comparand) + 1);
            } else if (width == 8) {
                cpu.memory().write64(storage, cpu.memory().read64(comparand) + 1);
            }
        }
        cpu.set_reg(Rax, 0);
        finish_call();
        break;
    }
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
    case Api::AllocateProduct: {
        const auto count = argument(0);
        const auto element_size = argument(1);
        if (count != 0 && element_size > std::numeric_limits<std::uint64_t>::max() / count) {
            last_error_ = ERROR_NOT_ENOUGH_MEMORY;
            cpu.set_reg(Rax, 0);
        } else {
            cpu.set_reg(Rax, allocate(count * element_size));
        }
        finish_call(2);
        break;
    }
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
        const bool local_reallocate = thunk_name.ends_with("LocalReAlloc");
        const auto old_address = argument(heap_reallocate ? 2 : 0);
        const auto new_size = argument(heap_reallocate ? 3 : 1);
        const auto new_address = allocate(new_size);
        if (const auto old = heap_sizes_.find(old_address); old != heap_sizes_.end()) {
            const auto copy_size = static_cast<std::size_t>(std::min(old->second, new_size));
            const auto bytes = cpu.memory().read(old_address, copy_size);
            cpu.memory().write(new_address, bytes);
        }
        cpu.set_reg(Rax, new_address);
        finish_call(heap_reallocate ? 4 : local_reallocate ? 3 : 2);
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
            if (detail::lowercase(requested) == detail::lowercase(filename)) {
                cpu.set_reg(Rax, guest_image_base_);
            } else {
                const auto normalized = detail::lowercase(requested);
                const auto existing = std::find_if(
                    guest_modules_.begin(), guest_modules_.end(), [&](const auto &entry) {
                        return detail::lowercase(entry.second) == normalized;
                    });
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
        const auto normalized = detail::lowercase(requested);
        const auto existing =
            std::find_if(guest_modules_.begin(), guest_modules_.end(), [&](const auto &entry) {
                return detail::lowercase(entry.second) == normalized;
            });
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
        const bool ansi = thunk_name.ends_with('A');
        const bool extended = thunk_name.find("FindFirstFileEx") != std::string::npos;
        const auto data_argument = extended ? 2 : 1;
        HANDLE host_handle = INVALID_HANDLE_VALUE;
        if (ansi) {
            WIN32_FIND_DATAA data{};
            const auto path = cpu.memory().read_c_string(argument(0));
            log::api("api", "guest file search path '" + path + "'");
            host_handle =
                extended
                    ? ::FindFirstFileExA(path.c_str(), static_cast<FINDEX_INFO_LEVELS>(argument(1)),
                                         &data, static_cast<FINDEX_SEARCH_OPS>(argument(3)),
                                         nullptr, static_cast<DWORD>(argument(5)))
                    : ::FindFirstFileA(path.c_str(), &data);
            if (host_handle != INVALID_HANDLE_VALUE) {
                cpu.memory().write(
                    argument(data_argument),
                    std::span<const std::uint8_t>(reinterpret_cast<const std::uint8_t *>(&data),
                                                  sizeof(data)));
            }
        } else {
            WIN32_FIND_DATAW data{};
            const auto path = cpu.memory().read_wide_string(argument(0));
            log::api("api", "guest file search path '" + narrow_string(path) + "'");
            host_handle =
                extended
                    ? ::FindFirstFileExW(path.c_str(), static_cast<FINDEX_INFO_LEVELS>(argument(1)),
                                         &data, static_cast<FINDEX_SEARCH_OPS>(argument(3)),
                                         nullptr, static_cast<DWORD>(argument(5)))
                    : ::FindFirstFileW(path.c_str(), &data);
            if (host_handle != INVALID_HANDLE_VALUE) {
                cpu.memory().write(
                    argument(data_argument),
                    std::span<const std::uint8_t>(reinterpret_cast<const std::uint8_t *>(&data),
                                                  sizeof(data)));
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
        finish_call(extended ? 6 : 2);
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
        const auto capacity = static_cast<int>(argument(3));
        std::vector<wchar_t> buffer(std::max(capacity, 1));
        const auto module =
            argument(0) == guest_image_base_ ? static_cast<HMODULE>(resource_module_) : nullptr;
        const auto result =
            module == nullptr || capacity <= 0
                ? 0
                : ::LoadStringW(module, static_cast<UINT>(argument(1)), buffer.data(), capacity);
        if (result > 0 && argument(2) != 0) {
            cpu.memory().write(argument(2),
                               std::span<const std::uint8_t>(
                                   reinterpret_cast<const std::uint8_t *>(buffer.data()),
                                   (static_cast<std::size_t>(result) + 1) * sizeof(wchar_t)));
        }
        cpu.set_reg(Rax, static_cast<std::uint32_t>(result));
        finish_call(4);
        break;
    }
    case Api::LoadCursorW: {
        const auto module = argument(0) == guest_image_base_
                                ? static_cast<HINSTANCE>(resource_module_)
                                : static_cast<HINSTANCE>(nullptr);
        const auto name_value = argument(1);
        const auto name_storage =
            name_value > 0xffff ? cpu.memory().read_wide_string(name_value) : std::wstring{};
        const auto name =
            name_value <= 0xffff ? MAKEINTRESOURCEW(name_value) : name_storage.c_str();
        const auto result = ::LoadCursorW(module, name);
        if (result == nullptr) {
            last_error_ = ::GetLastError();
        }
        cpu.set_reg(Rax, reinterpret_cast<std::uint64_t>(result));
        finish_call(2);
        break;
    }
    case Api::LoadIconW: {
        const auto module = argument(0) == guest_image_base_
                                ? static_cast<HINSTANCE>(resource_module_)
                                : static_cast<HINSTANCE>(nullptr);
        const auto name_value = argument(1);
        const auto name_storage =
            name_value > 0xffff ? cpu.memory().read_wide_string(name_value) : std::wstring{};
        const auto name =
            name_value <= 0xffff ? MAKEINTRESOURCEW(name_value) : name_storage.c_str();
        const auto result = ::LoadIconW(module, name);
        if (result == nullptr) {
            last_error_ = ::GetLastError();
        }
        cpu.set_reg(Rax, reinterpret_cast<std::uint64_t>(result));
        finish_call(2);
        break;
    }
    case Api::LoadImageW: {
        const auto module = argument(0) == guest_image_base_
                                ? static_cast<HINSTANCE>(resource_module_)
                                : static_cast<HINSTANCE>(nullptr);
        const auto name_value = argument(1);
        const auto name_storage =
            name_value > 0xffff ? cpu.memory().read_wide_string(name_value) : std::wstring{};
        const auto name =
            name_value <= 0xffff ? MAKEINTRESOURCEW(name_value) : name_storage.c_str();
        const auto result = ::LoadImageW(
            module, name, static_cast<UINT>(argument(2)), static_cast<int>(argument(3)),
            static_cast<int>(argument(4)), static_cast<UINT>(argument(5)));
        if (result == nullptr) {
            last_error_ = ::GetLastError();
        }
        cpu.set_reg(Rax, reinterpret_cast<std::uint64_t>(result));
        finish_call(6);
        break;
    }
    case Api::LoadAcceleratorsW: {
        const auto module = argument(0) == guest_image_base_
                                ? static_cast<HINSTANCE>(resource_module_)
                                : static_cast<HINSTANCE>(nullptr);
        const auto name_value = argument(1);
        const auto name_storage =
            name_value > 0xffff ? cpu.memory().read_wide_string(name_value) : std::wstring{};
        const auto name =
            name_value <= 0xffff ? MAKEINTRESOURCEW(name_value) : name_storage.c_str();
        const auto result = module == nullptr ? nullptr : ::LoadAcceleratorsW(module, name);
        if (result == nullptr) {
            last_error_ = ::GetLastError();
        }
        cpu.set_reg(Rax, reinterpret_cast<std::uint64_t>(result));
        finish_call(2);
        break;
    }
    case Api::GuestRegisterClassW: {
        const auto structure = argument(0);
        const bool extended = thunk_name.ends_with("!RegisterClassExW");
        const auto guest_size =
            extended ? (guest_is_64_bit_ ? 80U : 48U) : (guest_is_64_bit_ ? 72U : 40U);
        if (structure == 0 || !cpu.memory().contains(structure, guest_size) ||
            (extended && cpu.memory().read32(structure) != guest_size)) {
            last_error_ = ERROR_INVALID_PARAMETER;
            cpu.set_reg(Rax, 0);
            finish_call(1);
            break;
        }
        const auto read_pointer = [&](std::uint32_t offset32, std::uint32_t offset64) {
            return guest_is_64_bit_
                       ? cpu.memory().read64(structure + offset64)
                       : static_cast<std::uint64_t>(cpu.memory().read32(structure + offset32));
        };
        const auto guest_procedure = read_pointer(extended ? 8U : 4U, 8);
        const auto class_pointer = read_pointer(extended ? 40U : 36U, 64);
        if (class_pointer == 0 || guest_procedure == 0) {
            last_error_ = ERROR_INVALID_PARAMETER;
            cpu.set_reg(Rax, 0);
            finish_call(1);
            break;
        }
        const auto class_name = cpu.memory().read_wide_string(class_pointer);
        const auto menu_pointer = read_pointer(extended ? 36U : 32U, 56);
        const auto menu_name =
            menu_pointer > 0xffff ? cpu.memory().read_wide_string(menu_pointer) : std::wstring{};
        WNDCLASSEXW host_class{};
        host_class.cbSize = sizeof(host_class);
        host_class.style = cpu.memory().read32(structure + (extended ? 4U : 0U));
        host_class.lpfnWndProc = detail::window_proc_bridge;
        host_class.cbClsExtra =
            static_cast<int>(cpu.memory().read32(structure + (guest_is_64_bit_ ? 16U
                                                              : extended       ? 12U
                                                                               : 8U)));
        host_class.cbWndExtra =
            static_cast<int>(cpu.memory().read32(structure + (guest_is_64_bit_ ? 20U
                                                              : extended       ? 16U
                                                                               : 12U)));
        host_class.hInstance = resource_module_ != nullptr ? static_cast<HMODULE>(resource_module_)
                                                           : GetModuleHandleW(nullptr);
        host_class.hIcon = reinterpret_cast<HICON>(read_pointer(extended ? 24U : 20U, 32));
        host_class.hCursor = reinterpret_cast<HCURSOR>(read_pointer(extended ? 28U : 24U, 40));
        host_class.hbrBackground = reinterpret_cast<HBRUSH>(read_pointer(extended ? 32U : 28U, 48));
        host_class.lpszMenuName = menu_pointer == 0        ? nullptr
                                  : menu_pointer <= 0xffff ? MAKEINTRESOURCEW(menu_pointer)
                                                           : menu_name.c_str();
        host_class.lpszClassName = class_name.c_str();
        host_class.hIconSm = extended ? reinterpret_cast<HICON>(read_pointer(44, 72)) : nullptr;
        const auto atom = ::RegisterClassExW(&host_class);
        log::api("window", (extended ? "RegisterClassExW" : "RegisterClassW") +
                               std::string(" class='") + narrow_string(class_name) + "' proc=" +
                               log::hex(guest_procedure) + " atom=" + std::to_string(atom));
        if (atom != 0) {
            class_window_procedures_[class_name] = guest_procedure;
            atom_window_procedures_[atom] = guest_procedure;
        } else {
            last_error_ = ::GetLastError();
        }
        cpu.set_reg(Rax, atom);
        finish_call(1);
        break;
    }
    case Api::CreateWindowExW: {
        const auto class_value = argument(1);
        const auto class_name =
            class_value > 0xffff ? cpu.memory().read_wide_string(class_value) : std::wstring{};
        const auto native_class =
            class_value <= 0xffff ? MAKEINTRESOURCEW(class_value) : class_name.c_str();
        const auto title_pointer = argument(2);
        const auto title =
            title_pointer == 0 ? std::wstring{} : cpu.memory().read_wide_string(title_pointer);
        if (log::enabled(log::Level::Api)) {
            const auto class_description = class_value <= 0xffff
                                               ? "atom " + std::to_string(class_value)
                                               : "'" + narrow_string(class_name) + "'";
            log::api("window", "CreateWindowExW class=" + class_description);
        }
        if (class_value <= 0xffff) {
            const auto found =
                atom_window_procedures_.find(static_cast<std::uint16_t>(class_value));
            creating_window_procedure_ = found == atom_window_procedures_.end() ? 0 : found->second;
        } else {
            const auto found = class_window_procedures_.find(class_name);
            creating_window_procedure_ =
                found == class_window_procedures_.end() ? 0 : found->second;
        }
        // The instance must match the one the class was registered with, and it is also where
        // Windows resolves a class menu name, so it has to be the guest image rather than
        // CPUEmu itself.
        const auto window_instance = resource_module_ != nullptr
                                         ? static_cast<HINSTANCE>(resource_module_)
                                         : GetModuleHandleW(nullptr);
        const auto result = ::CreateWindowExW(
            static_cast<DWORD>(argument(0)), native_class,
            title_pointer == 0 ? nullptr : title.c_str(), static_cast<DWORD>(argument(3)),
            static_cast<int>(argument(4)), static_cast<int>(argument(5)),
            static_cast<int>(argument(6)), static_cast<int>(argument(7)),
            reinterpret_cast<HWND>(static_cast<std::uintptr_t>(argument(8))),
            reinterpret_cast<HMENU>(static_cast<std::uintptr_t>(argument(9))), window_instance,
            reinterpret_cast<void *>(static_cast<std::uintptr_t>(argument(11))));
        if (auto exception = detail::take_callback_exception(); exception != nullptr) {
            std::rethrow_exception(exception);
        }
        log::api("window",
                 "CreateWindowExW -> hwnd=" + log::hex(reinterpret_cast<std::uint64_t>(result)));
        if (result == nullptr) {
            last_error_ = ::GetLastError();
        }
        creating_window_procedure_ = 0;
        cpu.set_reg(Rax, reinterpret_cast<std::uint64_t>(result));
        finish_call(12);
        break;
    }
    case Api::DialogBoxParamW: {
        const auto module_value = argument(0);
        const auto template_value = argument(1);
        const auto guest_procedure = argument(3);
        std::uint8_t procedure_permissions = 0;
        if ((module_value != 0 && module_value != guest_image_base_) || template_value == 0 ||
            guest_procedure == 0 ||
            !cpu.memory().permissions(guest_procedure, procedure_permissions) ||
            (procedure_permissions & Execute) == 0) {
            last_error_ = ERROR_INVALID_PARAMETER;
            cpu.set_reg(Rax, static_cast<std::uint64_t>(-1));
            finish_call(5);
            break;
        }
        const auto module = module_value == guest_image_base_
                                ? static_cast<HINSTANCE>(resource_module_)
                                : static_cast<HINSTANCE>(nullptr);
        const auto template_storage = template_value > 0xffff
                                          ? cpu.memory().read_wide_string(template_value)
                                          : std::wstring{};
        const auto template_name =
            template_value <= 0xffff ? MAKEINTRESOURCEW(template_value) : template_storage.c_str();
        pending_dialogs_.push_back(PendingDialog{guest_procedure, argument(4)});
        INT_PTR result = -1;
        try {
            result =
                ::DialogBoxParamW(module, template_name,
                                  reinterpret_cast<HWND>(static_cast<std::uintptr_t>(argument(2))),
                                  detail::dialog_proc_bridge, static_cast<LPARAM>(argument(4)));
        } catch (...) {
            pending_dialogs_.pop_back();
            throw;
        }
        pending_dialogs_.pop_back();
        if (auto exception = detail::take_callback_exception(); exception != nullptr) {
            std::rethrow_exception(exception);
        }
        if (result == -1) {
            last_error_ = ::GetLastError();
        }
        cpu.set_reg(Rax, static_cast<std::uint64_t>(result));
        finish_call(5);
        break;
    }
    case Api::EndDialog: {
        const auto result =
            ::EndDialog(reinterpret_cast<HWND>(static_cast<std::uintptr_t>(argument(0))),
                        static_cast<INT_PTR>(argument(1)));
        if (result == FALSE) {
            last_error_ = ::GetLastError();
        }
        cpu.set_reg(Rax, result);
        finish_call(2);
        break;
    }
    case Api::GuestEnumWindows: {
        const bool children = thunk_name.ends_with("!EnumChildWindows");
        const auto guest_procedure = argument(children ? 1 : 0);
        std::uint8_t procedure_permissions = 0;
        if (guest_procedure == 0 ||
            !cpu.memory().permissions(guest_procedure, procedure_permissions) ||
            (procedure_permissions & Execute) == 0) {
            last_error_ = ERROR_INVALID_PARAMETER;
            cpu.set_reg(Rax, FALSE);
            finish_call(children ? 3 : 2);
            break;
        }
        const auto parameter = argument(children ? 2 : 1);
        pending_window_enumerations_.push_back(
            PendingWindowEnumeration{guest_procedure, parameter, !children});
        BOOL result = FALSE;
        try {
            result = children ? ::EnumChildWindows(reinterpret_cast<HWND>(
                                                       static_cast<std::uintptr_t>(argument(0))),
                                                   detail::window_enum_bridge, 0)
                              : ::EnumWindows(detail::window_enum_bridge, 0);
        } catch (...) {
            pending_window_enumerations_.pop_back();
            throw;
        }
        pending_window_enumerations_.pop_back();
        if (auto exception = detail::take_callback_exception(); exception != nullptr) {
            std::rethrow_exception(exception);
        }
        cpu.set_reg(Rax, result);
        finish_call(children ? 3 : 2);
        break;
    }
    case Api::DirectInputCreate: {
        const auto pointer_size = guest_is_64_bit_ ? 8U : 4U;
        const auto write_pointer = [&](std::uint64_t address, std::uint64_t value) {
            if (guest_is_64_bit_) {
                cpu.memory().write64(address, value);
            } else {
                cpu.memory().write32(address, static_cast<std::uint32_t>(value));
            }
        };
        const auto make_proxy = [&](std::uint32_t method_count, std::uint32_t interface_tag) {
            const auto vtable = allocate(method_count * pointer_size);
            const auto object = allocate(pointer_size);
            write_pointer(object, vtable);
            for (std::uint32_t index = 0; index < method_count; ++index) {
                const auto thunk = next_thunk_;
                next_thunk_ += 0x100;
                thunks_.emplace(thunk, Api::DirectInputMethod);
                thunk_names_.emplace(
                    thunk, (interface_tag == 0 ? "IDirectInput8#" : "IDirectInputDevice8#") +
                               std::to_string(index));
                direct_input_methods_.emplace(thunk, interface_tag | index);
                write_pointer(vtable + index * pointer_size, thunk);
            }
            return object;
        };
        if (direct_input_device_proxy_ == 0) {
            direct_input_device_proxy_ = make_proxy(32, 0x100U);
        }
        if (direct_input_proxy_ == 0) {
            direct_input_proxy_ = make_proxy(11, 0);
        }
        const auto output = argument(3);
        if (output == 0 || argument(4) != 0) {
            cpu.set_reg(Rax, 0x80070057U); // E_INVALIDARG
        } else {
            write_pointer(output, direct_input_proxy_);
            cpu.set_reg(Rax, 0); // DI_OK
        }
        finish_call(5);
        break;
    }
    case Api::DirectInputMethod: {
        constexpr std::uint32_t device_tag = 0x100U;
        constexpr std::uint32_t not_implemented = 0x80004001U;
        const auto tagged_method = direct_input_methods_.at(cpu.rip());
        const auto device = (tagged_method & device_tag) != 0;
        const auto method = tagged_method & 0xffU;
        const auto write_pointer = [&](std::uint64_t address, std::uint64_t value) {
            if (guest_is_64_bit_) {
                cpu.memory().write64(address, value);
            } else {
                cpu.memory().write32(address, static_cast<std::uint32_t>(value));
            }
        };
        static constexpr unsigned input_arguments[] = {3, 1, 1, 4, 5, 2, 3, 4, 4, 7, 6};
        static constexpr unsigned device_arguments[] = {
            3, 1, 1, 2, 4, 3, 3, 1, 1, 3, 5, 2, 2, 3, 4, 2,
            3, 4, 4, 4, 3, 2, 2, 3, 2, 1, 5, 5, 4, 4, 4, 2,
        };
        if ((!device && method >= std::size(input_arguments)) ||
            (device && method >= std::size(device_arguments))) {
            throw Error("invalid DirectInput proxy method");
        }
        std::uint32_t result = 0;
        if (method == 0) { // QueryInterface
            if (argument(2) == 0) {
                result = 0x80070057U;
            } else {
                write_pointer(argument(2),
                              device ? direct_input_device_proxy_ : direct_input_proxy_);
            }
        } else if (method == 1) { // AddRef
            result = 2;
        } else if (method == 2) { // Release
            result = 1;
        } else if (!device && method == 3) { // IDirectInput8::CreateDevice
            if (argument(2) == 0 || argument(3) != 0) {
                result = 0x80070057U;
            } else {
                write_pointer(argument(2), direct_input_device_proxy_);
            }
        } else if (device && method == 3) { // GetCapabilities
            const auto capabilities = argument(1);
            if (capabilities == 0) {
                result = 0x80070057U;
            } else {
                const auto size = cpu.memory().read32(capabilities);
                if (size >= 24 && size <= 0x1000) {
                    cpu.memory().write(capabilities + 4, std::vector<std::uint8_t>(size - 4));
                }
            }
        } else if (device && method == 9) { // GetDeviceState
            const auto size = static_cast<std::size_t>(argument(1));
            if (argument(2) == 0 || size > 0x100000) {
                result = 0x80070057U;
            } else {
                cpu.memory().write(argument(2), std::vector<std::uint8_t>(size));
            }
        } else if (device && method == 10) { // GetDeviceData
            if (argument(3) == 0) {
                result = 0x80070057U;
            } else {
                cpu.memory().write32(argument(3), 0);
            }
        } else if (device && (method == 7 || method == 8 || method == 11 || method == 12 ||
                              method == 13 || method == 25)) {
            result = 0;
        } else if (!device && (method == 5 || method == 6 || method == 7)) {
            result = 0;
        } else {
            result = not_implemented;
        }
        cpu.set_reg(Rax, result);
        finish_call(device ? device_arguments[method] : input_arguments[method]);
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
    case Api::CoCreateInstance: {
        const auto class_id = cpu.reg(Rcx);
        const auto interface_id = cpu.reg(R9);
        const auto output = argument(4);
        const auto guid_is = [&](std::uint64_t address, std::uint64_t low, std::uint64_t high) {
            return address != 0 && cpu.memory().read64(address) == low &&
                   cpu.memory().read64(address + 8) == high;
        };
        const bool acc_prop_services = class_id != 0 && interface_id != 0 &&
                                       cpu.memory().read32(class_id) == 0xb5f8350bU &&
                                       cpu.memory().read16(class_id + 4) == 0x0548U &&
                                       cpu.memory().read16(class_id + 6) == 0x48b1U &&
                                       cpu.memory().read32(interface_id) == 0x6e26e776U &&
                                       cpu.memory().read16(interface_id + 4) == 0x04f0U &&
                                       cpu.memory().read16(interface_id + 6) == 0x495dU;
        if (acc_prop_services && output != 0) {
            if (acc_prop_services_proxy_ == 0) {
                const auto vtable = allocate(18 * 8);
                acc_prop_services_proxy_ = allocate(8);
                cpu.memory().write64(acc_prop_services_proxy_, vtable);
                for (std::uint32_t index = 0; index < 18; ++index) {
                    const auto thunk = next_thunk_;
                    next_thunk_ += 0x100;
                    thunks_.emplace(thunk, Api::AccPropServicesMethod);
                    thunk_names_.emplace(thunk, "IAccPropServices#" + std::to_string(index));
                    acc_prop_services_methods_.emplace(thunk, index);
                    cpu.memory().write64(vtable + index * 8, thunk);
                }
            }
            cpu.memory().write64(output, acc_prop_services_proxy_);
            cpu.set_reg(Rax, 0);
            finish_call();
            break;
        }
        const bool application_document_lists =
            guid_is(class_id, 0x47e030f286bec222ULL, 0x285cd71cd160259fULL) &&
            guid_is(interface_id, 0x47a19f303c594f9fULL, 0x060a3d3de8c99a97ULL);
        if (application_document_lists && output != 0) {
            if (application_document_lists_proxy_ == 0) {
                const auto vtable = allocate(5 * 8);
                application_document_lists_proxy_ = allocate(8);
                cpu.memory().write64(application_document_lists_proxy_, vtable);
                for (std::uint32_t index = 0; index < 5; ++index) {
                    const auto thunk = next_thunk_;
                    next_thunk_ += 0x100;
                    thunks_.emplace(thunk, Api::ApplicationDocumentListsMethod);
                    thunk_names_.emplace(thunk,
                                         "IApplicationDocumentLists#" + std::to_string(index));
                    application_document_lists_methods_.emplace(thunk, index);
                    cpu.memory().write64(vtable + index * 8, thunk);
                }
            }
            cpu.memory().write64(output, application_document_lists_proxy_);
            cpu.set_reg(Rax, 0);
            finish_call();
            break;
        }
        // A native COM object exposes a host vtable, which guest code cannot execute directly.
        // Until individual interfaces have guest-side proxies, report an unavailable class so
        // applications can take their documented optional-feature fallback paths.
        if (output != 0) {
            cpu.memory().write64(output, 0);
        }
        cpu.set_reg(Rax, 0x80040154U); // REGDB_E_CLASSNOTREG
        finish_call();
        break;
    }
    case Api::AccPropServicesMethod: {
        const auto index = acc_prop_services_methods_.at(cpu.rip());
        if (index == 0) {
            if (cpu.reg(R8) != 0) {
                cpu.memory().write64(cpu.reg(R8), cpu.reg(Rcx));
            }
            cpu.set_reg(Rax, 0);
        } else if (index == 1) {
            cpu.set_reg(Rax, 2);
        } else if (index == 2) {
            cpu.set_reg(Rax, 1);
        } else if ((index >= 3 && index <= 9) || (index >= 12 && index <= 15)) {
            cpu.set_reg(Rax, 0);
        } else {
            cpu.set_reg(Rax, 0x80004001U); // E_NOTIMPL
        }
        finish_call();
        break;
    }
    case Api::ApplicationDocumentListsMethod: {
        const auto index = application_document_lists_methods_.at(cpu.rip());
        if (index == 0) {
            const auto iid = cpu.reg(Rdx);
            const auto output = cpu.reg(R8);
            const bool supported =
                iid != 0 && ((cpu.memory().read64(iid) == 0x0000000000000000ULL &&
                              cpu.memory().read64(iid + 8) == 0x46000000000000c0ULL) ||
                             (cpu.memory().read64(iid) == 0x47a19f303c594f9fULL &&
                              cpu.memory().read64(iid + 8) == 0x060a3d3de8c99a97ULL));
            if (output != 0) {
                cpu.memory().write64(output, supported ? application_document_lists_proxy_ : 0);
            }
            cpu.set_reg(Rax, output == 0 ? 0x80070057U : (supported ? 0 : 0x80004002U));
        } else if (index == 1) {
            cpu.set_reg(Rax, 2);
        } else if (index == 2) {
            cpu.set_reg(Rax, 1);
        } else if (index == 3) {
            cpu.set_reg(Rax, cpu.reg(Rdx) == 0 ? 0x80070057U : 0);
        } else if (index == 4) {
            const auto iid = cpu.reg(R9);
            const auto output = argument(4);
            const bool wants_object_array = iid != 0 &&
                                            cpu.memory().read64(iid) == 0x4bba562292ca9dcdULL &&
                                            cpu.memory().read64(iid + 8) == 0xc9d81b549f5e05a8ULL;
            if (output != 0) {
                cpu.memory().write64(output, 0);
            }
            if (output == 0 || iid == 0) {
                cpu.set_reg(Rax, 0x80070057U); // E_INVALIDARG
            } else if (!wants_object_array) {
                cpu.set_reg(Rax, 0x80004002U); // E_NOINTERFACE
            } else {
                if (empty_object_array_proxy_ == 0) {
                    const auto vtable = allocate(5 * 8);
                    empty_object_array_proxy_ = allocate(8);
                    cpu.memory().write64(empty_object_array_proxy_, vtable);
                    for (std::uint32_t method = 0; method < 5; ++method) {
                        const auto thunk = next_thunk_;
                        next_thunk_ += 0x100;
                        thunks_.emplace(thunk, Api::ObjectArrayMethod);
                        thunk_names_.emplace(thunk, "IObjectArray#" + std::to_string(method));
                        object_array_methods_.emplace(thunk, method);
                        cpu.memory().write64(vtable + method * 8, thunk);
                    }
                }
                cpu.memory().write64(output, empty_object_array_proxy_);
                cpu.set_reg(Rax, 0);
            }
        } else {
            cpu.set_reg(Rax, 0x80004001U); // E_NOTIMPL
        }
        finish_call();
        break;
    }
    case Api::ObjectArrayMethod: {
        const auto index = object_array_methods_.at(cpu.rip());
        if (index == 0) {
            const auto iid = cpu.reg(Rdx);
            const auto output = cpu.reg(R8);
            const bool supported =
                iid != 0 && ((cpu.memory().read64(iid) == 0x0000000000000000ULL &&
                              cpu.memory().read64(iid + 8) == 0x46000000000000c0ULL) ||
                             (cpu.memory().read64(iid) == 0x4bba562292ca9dcdULL &&
                              cpu.memory().read64(iid + 8) == 0xc9d81b549f5e05a8ULL));
            if (output != 0) {
                cpu.memory().write64(output, supported ? empty_object_array_proxy_ : 0);
            }
            cpu.set_reg(Rax, output == 0 ? 0x80070057U : (supported ? 0 : 0x80004002U));
        } else if (index == 1) {
            cpu.set_reg(Rax, 2);
        } else if (index == 2) {
            cpu.set_reg(Rax, 1);
        } else if (index == 3) {
            if (cpu.reg(Rdx) != 0) {
                cpu.memory().write32(cpu.reg(Rdx), 0);
            }
            cpu.set_reg(Rax, cpu.reg(Rdx) == 0 ? 0x80070057U : 0);
        } else if (index == 4) {
            const auto output = cpu.reg(R9);
            if (output != 0) {
                cpu.memory().write64(output, 0);
            }
            cpu.set_reg(Rax, output == 0 ? 0x80070057U : 0x8000000bU); // E_BOUNDS
        } else {
            cpu.set_reg(Rax, 0x80004001U); // E_NOTIMPL
        }
        finish_call();
        break;
    }
    case Api::WindowsCreateString: {
        const auto source = cpu.reg(Rcx);
        const auto length = static_cast<std::uint32_t>(cpu.reg(Rdx));
        const auto output = cpu.reg(R8);
        if (output == 0 || (length != 0 && source == 0)) {
            cpu.set_reg(Rax, 0x80070057U); // E_INVALIDARG
            finish_call();
            break;
        }
        const auto handle = allocate(28 + (static_cast<std::uint64_t>(length) + 1) * 2);
        cpu.memory().write32(handle, 0);
        cpu.memory().write32(handle + 4, length);
        cpu.memory().write64(handle + 8, 0);
        cpu.memory().write64(handle + 16, handle + 28);
        cpu.memory().write32(handle + 24, 1);
        for (std::uint32_t index = 0; index < length; ++index) {
            cpu.memory().write16(handle + 28 + index * 2, cpu.memory().read16(source + index * 2));
        }
        cpu.memory().write16(handle + 28 + static_cast<std::uint64_t>(length) * 2, 0);
        cpu.memory().write64(output, handle);
        cpu.set_reg(Rax, 0);
        finish_call();
        break;
    }
    case Api::WindowsCreateStringReference: {
        const auto source = cpu.reg(Rcx);
        const auto length = static_cast<std::uint32_t>(cpu.reg(Rdx));
        const auto header = cpu.reg(R8);
        const auto output = cpu.reg(R9);
        if (header == 0 || output == 0 || (length != 0 && source == 0)) {
            cpu.set_reg(Rax, 0x80070057U); // E_INVALIDARG
            finish_call();
            break;
        }
        cpu.memory().write32(header, 1);
        cpu.memory().write32(header + 4, length);
        cpu.memory().write64(header + 8, 0);
        cpu.memory().write64(header + 16, source);
        cpu.memory().write64(output, header);
        cpu.set_reg(Rax, 0);
        finish_call();
        break;
    }
    case Api::WindowsDeleteString: {
        const auto handle = cpu.reg(Rcx);
        if (handle != 0 && (cpu.memory().read32(handle) & 1U) == 0) {
            const auto references = cpu.memory().read32(handle + 24);
            if (references != 0) {
                cpu.memory().write32(handle + 24, references - 1);
            }
        }
        // Guest heap mappings live for the process lifetime, so reaching zero does not unmap the
        // backing allocation. The reference count still matters because C++/WinRT may update it
        // inline and treats underflow as corruption.
        cpu.set_reg(Rax, 0);
        finish_call();
        break;
    }
    case Api::WindowsDuplicateString: {
        const auto handle = cpu.reg(Rcx);
        const auto output = cpu.reg(Rdx);
        if (output == 0) {
            cpu.set_reg(Rax, 0x80070057U); // E_INVALIDARG
        } else {
            if (handle != 0 && (cpu.memory().read32(handle) & 1U) == 0) {
                cpu.memory().write32(handle + 24, cpu.memory().read32(handle + 24) + 1);
            }
            cpu.memory().write64(output, handle);
            cpu.set_reg(Rax, 0);
        }
        finish_call();
        break;
    }
    case Api::WindowsGetStringRawBuffer: {
        const auto handle = cpu.reg(Rcx);
        if (cpu.reg(Rdx) != 0) {
            cpu.memory().write32(cpu.reg(Rdx), handle == 0 ? 0 : cpu.memory().read32(handle + 4));
        }
        cpu.set_reg(Rax, handle == 0 ? 0 : cpu.memory().read64(handle + 16));
        finish_call();
        break;
    }
    case Api::RoGetActivationFactory: {
        const auto class_handle = cpu.reg(Rcx);
        const auto length = class_handle == 0 ? 0 : cpu.memory().read32(class_handle + 4);
        const auto text = class_handle == 0 ? 0 : cpu.memory().read64(class_handle + 16);
        std::wstring class_name;
        class_name.reserve(length);
        for (std::uint32_t index = 0; index < length; ++index) {
            class_name.push_back(static_cast<wchar_t>(cpu.memory().read16(text + index * 2)));
        }
        std::string description = class_name.empty() ? "<unknown>" : narrow_string(class_name);
        const auto iid_address = cpu.reg(Rdx);
        if (iid_address != 0) {
            std::ostringstream stream;
            stream << std::hex << std::setfill('0') << std::setw(8)
                   << cpu.memory().read32(iid_address) << '-' << std::setw(4)
                   << cpu.memory().read16(iid_address + 4) << '-' << std::setw(4)
                   << cpu.memory().read16(iid_address + 6) << '-';
            for (std::uint64_t offset = 8; offset < 16; ++offset) {
                stream << std::setw(2)
                       << static_cast<unsigned>(cpu.memory().read8(iid_address + offset));
            }
            description += " iid=" + stream.str();
        }
        if (log::enabled(log::Level::Api)) {
            log::api("api", "WinRT activation " + description);
        }

        const bool activation_factory_iid = iid_address != 0 &&
                                            cpu.memory().read32(iid_address) == 0x35 &&
                                            cpu.memory().read16(iid_address + 4) == 0 &&
                                            cpu.memory().read16(iid_address + 6) == 0 &&
                                            cpu.memory().read8(iid_address + 8) == 0xc0 &&
                                            cpu.memory().read8(iid_address + 15) == 0x46;

        if (class_name == L"Windows.Globalization.GeographicRegion" && activation_factory_iid) {
            if (winrt_activation_factory_proxy_ == 0) {
                const auto vtable = allocate(7 * 8);
                winrt_activation_factory_proxy_ = allocate(8);
                cpu.memory().write64(winrt_activation_factory_proxy_, vtable);
                for (std::uint32_t index = 0; index < 7; ++index) {
                    const auto thunk = next_thunk_;
                    next_thunk_ += 0x100;
                    thunks_.emplace(thunk, Api::WinrtActivationFactoryMethod);
                    thunk_names_.emplace(thunk, "IActivationFactory#" + std::to_string(index));
                    winrt_activation_factory_methods_.emplace(thunk, index);
                    cpu.memory().write64(vtable + index * 8, thunk);
                }
            }
            if (cpu.reg(R8) != 0) {
                cpu.memory().write64(cpu.reg(R8), winrt_activation_factory_proxy_);
            }
            cpu.set_reg(Rax, 0);
            finish_call();
            break;
        }

        if (class_name == L"Windows.Storage.ApplicationData") {
            if (application_data_statics_proxy_ == 0) {
                const auto vtable = allocate(7 * 8);
                application_data_statics_proxy_ = allocate(8);
                cpu.memory().write64(application_data_statics_proxy_, vtable);
                for (std::uint32_t index = 0; index < 7; ++index) {
                    const auto thunk = next_thunk_;
                    next_thunk_ += 0x100;
                    thunks_.emplace(thunk, Api::ApplicationDataStaticsMethod);
                    thunk_names_.emplace(thunk, "IApplicationDataStatics#" + std::to_string(index));
                    application_data_statics_methods_.emplace(thunk, index);
                    cpu.memory().write64(vtable + index * 8, thunk);
                }
            }
            if (cpu.reg(R8) != 0) {
                cpu.memory().write64(cpu.reg(R8), application_data_statics_proxy_);
            }
            cpu.set_reg(Rax, 0);
            finish_call();
            break;
        }

        if (class_name == L"Windows.Storage.AppDataPaths") {
            if (app_data_paths_statics_proxy_ == 0) {
                const auto paths_vtable = allocate(15 * 8);
                app_data_paths_proxy_ = allocate(8);
                cpu.memory().write64(app_data_paths_proxy_, paths_vtable);
                for (std::uint32_t index = 0; index < 15; ++index) {
                    const auto thunk = next_thunk_;
                    next_thunk_ += 0x100;
                    thunks_.emplace(thunk, Api::AppDataPathsMethod);
                    thunk_names_.emplace(thunk, "IAppDataPaths#" + std::to_string(index));
                    app_data_paths_methods_.emplace(thunk, index);
                    cpu.memory().write64(paths_vtable + index * 8, thunk);
                }

                const auto statics_vtable = allocate(8 * 8);
                app_data_paths_statics_proxy_ = allocate(8);
                cpu.memory().write64(app_data_paths_statics_proxy_, statics_vtable);
                for (std::uint32_t index = 0; index < 8; ++index) {
                    const auto thunk = next_thunk_;
                    next_thunk_ += 0x100;
                    thunks_.emplace(thunk, Api::AppDataPathsStaticsMethod);
                    thunk_names_.emplace(thunk, "IAppDataPathsStatics#" + std::to_string(index));
                    app_data_paths_statics_methods_.emplace(thunk, index);
                    cpu.memory().write64(statics_vtable + index * 8, thunk);
                }
            }
            if (cpu.reg(R8) != 0) {
                cpu.memory().write64(cpu.reg(R8), app_data_paths_statics_proxy_);
            }
            cpu.set_reg(Rax, 0);
            finish_call();
            break;
        }

        if (class_name == L"NotepadXamlUI.XamlResourceFactory") {
            if (xaml_resource_factory_proxy_ == 0) {
                const auto vtable = allocate(32 * 8);
                xaml_resource_factory_proxy_ = allocate(8);
                cpu.memory().write64(xaml_resource_factory_proxy_, vtable);
                for (std::uint32_t index = 0; index < 32; ++index) {
                    const auto thunk = next_thunk_;
                    next_thunk_ += 0x100;
                    thunks_.emplace(thunk, Api::XamlResourceFactoryMethod);
                    thunk_names_.emplace(thunk, "IXamlResourceFactory#" + std::to_string(index));
                    xaml_resource_factory_methods_.emplace(thunk, index);
                    cpu.memory().write64(vtable + index * 8, thunk);
                }
            }
            if (cpu.reg(R8) != 0) {
                cpu.memory().write64(cpu.reg(R8), xaml_resource_factory_proxy_);
            }
            cpu.set_reg(Rax, 0);
            finish_call();
            break;
        }

        if (class_name == L"Microsoft.UI.Xaml.Application") {
            if (xaml_application_statics_proxy_ == 0) {
                const auto vtable = allocate(7 * 8);
                xaml_application_statics_proxy_ = allocate(8);
                cpu.memory().write64(xaml_application_statics_proxy_, vtable);
                for (std::uint32_t index = 0; index < 7; ++index) {
                    const auto thunk = next_thunk_;
                    next_thunk_ += 0x100;
                    thunks_.emplace(thunk, Api::XamlApplicationStaticsMethod);
                    thunk_names_.emplace(thunk, "IXamlApplicationStatics#" + std::to_string(index));
                    xaml_application_statics_methods_.emplace(thunk, index);
                    cpu.memory().write64(vtable + index * 8, thunk);
                }
            }
            if (cpu.reg(R8) != 0) {
                cpu.memory().write64(cpu.reg(R8), xaml_application_statics_proxy_);
            }
            cpu.set_reg(Rax, 0);
            finish_call();
            break;
        }

        if (class_name == L"Microsoft.UI.Dispatching.DispatcherQueueController") {
            if (dispatcher_queue_controller_statics_proxy_ == 0) {
                const auto vtable = allocate(8 * 8);
                dispatcher_queue_controller_statics_proxy_ = allocate(8);
                cpu.memory().write64(dispatcher_queue_controller_statics_proxy_, vtable);
                for (std::uint32_t index = 0; index < 8; ++index) {
                    const auto thunk = next_thunk_;
                    next_thunk_ += 0x100;
                    thunks_.emplace(thunk, Api::DispatcherQueueControllerStaticsMethod);
                    thunk_names_.emplace(thunk, "IDispatcherQueueControllerStatics#" +
                                                    std::to_string(index));
                    dispatcher_queue_controller_statics_methods_.emplace(thunk, index);
                    cpu.memory().write64(vtable + index * 8, thunk);
                }
            }
            if (cpu.reg(R8) != 0) {
                cpu.memory().write64(cpu.reg(R8), dispatcher_queue_controller_statics_proxy_);
            }
            cpu.set_reg(Rax, 0);
            finish_call();
            break;
        }

        if (class_name == L"NotepadXamlUI.App" && activation_factory_iid) {
            if (xaml_app_factory_proxy_ == 0) {
                const auto app_vtable = allocate(12 * 8);
                xaml_app_proxy_ = allocate(8);
                cpu.memory().write64(xaml_app_proxy_, app_vtable);
                for (std::uint32_t index = 0; index < 12; ++index) {
                    const auto thunk = next_thunk_;
                    next_thunk_ += 0x100;
                    thunks_.emplace(thunk, Api::XamlAppMethod);
                    thunk_names_.emplace(thunk, "NotepadXamlUI.IApp#" + std::to_string(index));
                    xaml_app_methods_.emplace(thunk, index);
                    cpu.memory().write64(app_vtable + index * 8, thunk);
                }

                const auto factory_vtable = allocate(7 * 8);
                xaml_app_factory_proxy_ = allocate(8);
                cpu.memory().write64(xaml_app_factory_proxy_, factory_vtable);
                for (std::uint32_t index = 0; index < 7; ++index) {
                    const auto thunk = next_thunk_;
                    next_thunk_ += 0x100;
                    thunks_.emplace(thunk, Api::XamlAppFactoryMethod);
                    thunk_names_.emplace(thunk,
                                         "NotepadXamlUI.AppFactory#" + std::to_string(index));
                    xaml_app_factory_methods_.emplace(thunk, index);
                    cpu.memory().write64(factory_vtable + index * 8, thunk);
                }
            }
            if (cpu.reg(R8) != 0) {
                cpu.memory().write64(cpu.reg(R8), xaml_app_factory_proxy_);
            }
            cpu.set_reg(Rax, 0);
            finish_call();
            break;
        }

        if (class_name == L"Windows.ApplicationModel.Resources.Core.ResourceManager") {
            if (resource_manager_statics_proxy_ == 0) {
                const auto candidate_vtable = allocate(15 * 8);
                resource_candidate_proxy_ = allocate(8);
                cpu.memory().write64(resource_candidate_proxy_, candidate_vtable);
                for (std::uint32_t index = 0; index < 15; ++index) {
                    const auto thunk = next_thunk_;
                    next_thunk_ += 0x100;
                    thunks_.emplace(thunk, Api::ResourceCandidateMethod);
                    thunk_names_.emplace(thunk, "IResourceCandidate#" + std::to_string(index));
                    resource_candidate_methods_.emplace(thunk, index);
                    cpu.memory().write64(candidate_vtable + index * 8, thunk);
                }

                const auto map_vtable = allocate(10 * 8);
                resource_map_proxy_ = allocate(8);
                cpu.memory().write64(resource_map_proxy_, map_vtable);
                for (std::uint32_t index = 0; index < 10; ++index) {
                    const auto thunk = next_thunk_;
                    next_thunk_ += 0x100;
                    thunks_.emplace(thunk, Api::ResourceMapMethod);
                    thunk_names_.emplace(thunk, "IResourceMap#" + std::to_string(index));
                    resource_map_methods_.emplace(thunk, index);
                    cpu.memory().write64(map_vtable + index * 8, thunk);
                }

                const auto manager_vtable = allocate(13 * 8);
                resource_manager_proxy_ = allocate(8);
                cpu.memory().write64(resource_manager_proxy_, manager_vtable);
                for (std::uint32_t index = 0; index < 13; ++index) {
                    const auto thunk = next_thunk_;
                    next_thunk_ += 0x100;
                    thunks_.emplace(thunk, Api::ResourceManagerMethod);
                    thunk_names_.emplace(thunk, "IResourceManager#" + std::to_string(index));
                    resource_manager_methods_.emplace(thunk, index);
                    cpu.memory().write64(manager_vtable + index * 8, thunk);
                }

                const auto statics_vtable = allocate(8 * 8);
                resource_manager_statics_proxy_ = allocate(8);
                cpu.memory().write64(resource_manager_statics_proxy_, statics_vtable);
                for (std::uint32_t index = 0; index < 8; ++index) {
                    const auto thunk = next_thunk_;
                    next_thunk_ += 0x100;
                    thunks_.emplace(thunk, Api::ResourceManagerStaticsMethod);
                    thunk_names_.emplace(thunk, "IResourceManagerStatics#" + std::to_string(index));
                    resource_manager_statics_methods_.emplace(thunk, index);
                    cpu.memory().write64(statics_vtable + index * 8, thunk);
                }
            }
            if (cpu.reg(R8) != 0) {
                cpu.memory().write64(cpu.reg(R8), resource_manager_statics_proxy_);
            }
            cpu.set_reg(Rax, 0);
            finish_call();
            break;
        }

        if (class_name == L"Windows.ApplicationModel.Resources.Core.ResourceContext") {
            if (resource_context_statics_proxy_ == 0) {
                const auto context_vtable = allocate(13 * 8);
                resource_context_proxy_ = allocate(8);
                cpu.memory().write64(resource_context_proxy_, context_vtable);
                for (std::uint32_t index = 0; index < 13; ++index) {
                    const auto thunk = next_thunk_;
                    next_thunk_ += 0x100;
                    thunks_.emplace(thunk, Api::ResourceContextMethod);
                    thunk_names_.emplace(thunk, "IResourceContext#" + std::to_string(index));
                    resource_context_methods_.emplace(thunk, index);
                    cpu.memory().write64(context_vtable + index * 8, thunk);
                }

                const auto statics_vtable = allocate(11 * 8);
                resource_context_statics_proxy_ = allocate(8);
                cpu.memory().write64(resource_context_statics_proxy_, statics_vtable);
                for (std::uint32_t index = 0; index < 11; ++index) {
                    const auto thunk = next_thunk_;
                    next_thunk_ += 0x100;
                    thunks_.emplace(thunk, Api::ResourceContextStaticsMethod);
                    thunk_names_.emplace(thunk, "IResourceContextStatics#" + std::to_string(index));
                    resource_context_statics_methods_.emplace(thunk, index);
                    cpu.memory().write64(statics_vtable + index * 8, thunk);
                }
            }
            if (cpu.reg(R8) != 0) {
                cpu.memory().write64(cpu.reg(R8), resource_context_statics_proxy_);
            }
            cpu.set_reg(Rax, 0);
            finish_call();
            break;
        }

        if (class_name == L"Windows.UI.ViewManagement.UISettings" && activation_factory_iid) {
            if (ui_settings_factory_proxy_ == 0) {
                const auto settings3_vtable = allocate(9 * 8);
                ui_settings3_proxy_ = allocate(8);
                cpu.memory().write64(ui_settings3_proxy_, settings3_vtable);
                for (std::uint32_t index = 0; index < 9; ++index) {
                    const auto thunk = next_thunk_;
                    next_thunk_ += 0x100;
                    thunks_.emplace(thunk, Api::UISettings3Method);
                    thunk_names_.emplace(thunk, "IUISettings3#" + std::to_string(index));
                    ui_settings3_methods_.emplace(thunk, index);
                    cpu.memory().write64(settings3_vtable + index * 8, thunk);
                }

                const auto settings_vtable = allocate(19 * 8);
                ui_settings_proxy_ = allocate(8);
                cpu.memory().write64(ui_settings_proxy_, settings_vtable);
                for (std::uint32_t index = 0; index < 19; ++index) {
                    const auto thunk = next_thunk_;
                    next_thunk_ += 0x100;
                    thunks_.emplace(thunk, Api::UISettingsMethod);
                    thunk_names_.emplace(thunk, "IUISettings#" + std::to_string(index));
                    ui_settings_methods_.emplace(thunk, index);
                    cpu.memory().write64(settings_vtable + index * 8, thunk);
                }

                const auto factory_vtable = allocate(7 * 8);
                ui_settings_factory_proxy_ = allocate(8);
                cpu.memory().write64(ui_settings_factory_proxy_, factory_vtable);
                for (std::uint32_t index = 0; index < 7; ++index) {
                    const auto thunk = next_thunk_;
                    next_thunk_ += 0x100;
                    thunks_.emplace(thunk, Api::UISettingsFactoryMethod);
                    thunk_names_.emplace(thunk, "UISettingsFactory#" + std::to_string(index));
                    ui_settings_factory_methods_.emplace(thunk, index);
                    cpu.memory().write64(factory_vtable + index * 8, thunk);
                }
            }
            if (cpu.reg(R8) != 0) {
                cpu.memory().write64(cpu.reg(R8), ui_settings_factory_proxy_);
            }
            cpu.set_reg(Rax, 0);
            finish_call();
            break;
        }

        if (class_name == L"Windows.Foundation.PropertyValue") {
            if (property_value_statics_proxy_ == 0) {
                property_value_vtable_ = allocate(45 * 8);
                for (std::uint32_t index = 0; index < 45; ++index) {
                    const auto thunk = next_thunk_;
                    next_thunk_ += 0x100;
                    thunks_.emplace(thunk, Api::PropertyValueMethod);
                    thunk_names_.emplace(thunk, "IPropertyValue#" + std::to_string(index));
                    property_value_methods_.emplace(thunk, index);
                    cpu.memory().write64(property_value_vtable_ + index * 8, thunk);
                }

                const auto statics_vtable = allocate(45 * 8);
                property_value_statics_proxy_ = allocate(8);
                cpu.memory().write64(property_value_statics_proxy_, statics_vtable);
                for (std::uint32_t index = 0; index < 45; ++index) {
                    const auto thunk = next_thunk_;
                    next_thunk_ += 0x100;
                    thunks_.emplace(thunk, Api::PropertyValueStaticsMethod);
                    thunk_names_.emplace(thunk, "IPropertyValueStatics#" + std::to_string(index));
                    property_value_statics_methods_.emplace(thunk, index);
                    cpu.memory().write64(statics_vtable + index * 8, thunk);
                }
            }
            if (cpu.reg(R8) != 0) {
                cpu.memory().write64(cpu.reg(R8), property_value_statics_proxy_);
            }
            cpu.set_reg(Rax, 0);
            finish_call();
            break;
        }

        // Any other class activated through IActivationFactory still needs a factory whose
        // ActivateInstance writes a guest-owned object. Returning the generic statics proxy here
        // made such calls report success while leaving the out parameter untouched, so the guest
        // dereferenced a null instance. One factory and one instance per class keeps them distinct.
        if (activation_factory_iid) {
            auto factory = winrt_generic_factories_.find(class_name);
            if (factory == winrt_generic_factories_.end()) {
                const auto instance_vtable = allocate(16 * 8);
                const auto instance = allocate(8);
                cpu.memory().write64(instance, instance_vtable);
                for (std::uint32_t method = 0; method < 16; ++method) {
                    const auto thunk = next_thunk_;
                    next_thunk_ += 0x100;
                    thunks_.emplace(thunk, Api::WinrtInspectableMethod);
                    thunk_names_.emplace(thunk, "IInspectable#" + std::to_string(method));
                    winrt_inspectable_methods_.emplace(thunk, method);
                    cpu.memory().write64(instance_vtable + method * 8, thunk);
                }
                const auto factory_vtable = allocate(7 * 8);
                factory = winrt_generic_factories_.emplace(class_name, allocate(8)).first;
                cpu.memory().write64(factory->second, factory_vtable);
                for (std::uint32_t index = 0; index < 7; ++index) {
                    const auto thunk = next_thunk_;
                    next_thunk_ += 0x100;
                    thunks_.emplace(thunk, Api::WinrtGenericFactoryMethod);
                    thunk_names_.emplace(thunk, "IActivationFactory#" + std::to_string(index));
                    winrt_generic_factory_methods_.emplace(thunk, index);
                    cpu.memory().write64(factory_vtable + index * 8, thunk);
                }
                winrt_factory_instances_.emplace(factory->second, instance);
            }
            if (cpu.reg(R8) != 0) {
                cpu.memory().write64(cpu.reg(R8), factory->second);
            }
            cpu.set_reg(Rax, 0);
            finish_call();
            break;
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
    }
    case Api::WinrtActivationFactoryMethod: {
        const auto index = winrt_activation_factory_methods_.at(cpu.rip());
        if (index == 0) {
            if (cpu.reg(R8) != 0) {
                cpu.memory().write64(cpu.reg(R8), cpu.reg(Rcx));
            }
            cpu.set_reg(Rax, 0);
        } else if (index == 1) {
            cpu.set_reg(Rax, 2);
        } else if (index == 2) {
            cpu.set_reg(Rax, 1);
        } else if (index == 6) {
            if (geographic_region_proxy_ == 0) {
                const auto vtable = allocate(13 * 8);
                geographic_region_proxy_ = allocate(8);
                cpu.memory().write64(geographic_region_proxy_, vtable);
                for (std::uint32_t method = 0; method < 13; ++method) {
                    const auto thunk = next_thunk_;
                    next_thunk_ += 0x100;
                    thunks_.emplace(thunk, Api::GeographicRegionMethod);
                    thunk_names_.emplace(thunk, "IGeographicRegion#" + std::to_string(method));
                    geographic_region_methods_.emplace(thunk, method);
                    cpu.memory().write64(vtable + method * 8, thunk);
                }
            }
            if (cpu.reg(Rdx) != 0) {
                cpu.memory().write64(cpu.reg(Rdx), geographic_region_proxy_);
            }
            cpu.set_reg(Rax, 0);
        } else {
            cpu.set_reg(Rax, 0x80004001U); // E_NOTIMPL
        }
        finish_call();
        break;
    }
    case Api::WinrtGenericFactoryMethod: {
        const auto index = winrt_generic_factory_methods_.at(cpu.rip());
        if (index == 0) {
            if (cpu.reg(R8) != 0) {
                cpu.memory().write64(cpu.reg(R8), cpu.reg(Rcx));
            }
            cpu.set_reg(Rax, 0);
        } else if (index == 1) {
            cpu.set_reg(Rax, 2);
        } else if (index == 2) {
            cpu.set_reg(Rax, 1);
        } else if (index == 6) {
            // IActivationFactory::ActivateInstance returns the class's guest-owned instance.
            const auto instance = winrt_factory_instances_.find(cpu.reg(Rcx));
            if (cpu.reg(Rdx) != 0) {
                cpu.memory().write64(cpu.reg(Rdx), instance == winrt_factory_instances_.end()
                                                       ? 0
                                                       : instance->second);
            }
            cpu.set_reg(Rax, instance == winrt_factory_instances_.end() ? 0x80004005U : 0);
        } else {
            cpu.set_reg(Rax, 0x80004001U); // E_NOTIMPL
        }
        finish_call();
        break;
    }
    case Api::WinrtInspectableMethod: {
        const auto index = winrt_inspectable_methods_.at(cpu.rip());
        if (index == 0) {
            if (cpu.reg(R8) != 0) {
                cpu.memory().write64(cpu.reg(R8), cpu.reg(Rcx));
            }
            cpu.set_reg(Rax, 0);
        } else if (index == 1) {
            cpu.set_reg(Rax, 2);
        } else if (index == 2) {
            cpu.set_reg(Rax, 1);
        } else if (index == 3) {
            // GetIids: no interfaces beyond IInspectable, so the caller sees an empty list.
            if (cpu.reg(Rdx) != 0) {
                cpu.memory().write32(cpu.reg(Rdx), 0);
            }
            if (cpu.reg(R8) != 0) {
                cpu.memory().write64(cpu.reg(R8), 0);
            }
            cpu.set_reg(Rax, 0);
        } else if (index == 4) {
            // GetRuntimeClassName returns an empty guest-owned HSTRING; never a host pointer.
            const auto handle = allocate(28);
            cpu.memory().write32(handle, 0);
            cpu.memory().write32(handle + 4, 0);
            cpu.memory().write64(handle + 8, 0);
            cpu.memory().write64(handle + 16, handle + 28);
            cpu.memory().write32(handle + 24, 1);
            cpu.memory().write16(handle + 28, 0);
            if (cpu.reg(Rdx) != 0) {
                cpu.memory().write64(cpu.reg(Rdx), handle);
            }
            cpu.set_reg(Rax, 0);
        } else if (index == 5) {
            if (cpu.reg(Rdx) != 0) {
                cpu.memory().write32(cpu.reg(Rdx), 0); // BaseTrust
            }
            cpu.set_reg(Rax, 0);
        } else {
            // Fail closed so the guest takes its error path instead of using a fabricated result.
            cpu.set_reg(Rax, 0x80004001U); // E_NOTIMPL
        }
        finish_call();
        break;
    }
    case Api::ApplicationDataContainerMethod: {
        const auto index = application_data_container_methods_.at(cpu.rip());
        if (index == 0) {
            if (cpu.reg(R8) != 0) {
                cpu.memory().write64(cpu.reg(R8), cpu.reg(Rcx));
            }
            cpu.set_reg(Rax, 0);
        } else if (index == 1) {
            cpu.set_reg(Rax, 2);
        } else if (index == 2) {
            cpu.set_reg(Rax, 1);
        } else if (index == 7) {
            if (cpu.reg(Rdx) != 0) {
                cpu.memory().write32(cpu.reg(Rdx), 0);
            }
            cpu.set_reg(Rax, 0);
        } else if (index == 8) {
            if (property_set_proxy_ == 0) {
                const auto vtable = allocate(13 * 8);
                property_set_proxy_ = allocate(8);
                cpu.memory().write64(property_set_proxy_, vtable);
                for (std::uint32_t method = 0; method < 13; ++method) {
                    const auto thunk = next_thunk_;
                    next_thunk_ += 0x100;
                    thunks_.emplace(thunk, Api::PropertySetMethod);
                    thunk_names_.emplace(thunk, "IPropertySet#" + std::to_string(method));
                    property_set_methods_.emplace(thunk, method);
                    cpu.memory().write64(vtable + method * 8, thunk);
                }
            }
            if (cpu.reg(Rdx) != 0) {
                cpu.memory().write64(cpu.reg(Rdx), property_set_proxy_);
            }
            cpu.set_reg(Rax, 0);
        } else {
            cpu.set_reg(Rax, 0x80004001U);
        }
        finish_call();
        break;
    }
    case Api::PropertySetMethod: {
        const auto index = property_set_methods_.at(cpu.rip());
        if (index == 0) {
            if (cpu.reg(R8) != 0) {
                cpu.memory().write64(cpu.reg(R8), cpu.reg(Rcx));
            }
            cpu.set_reg(Rax, 0);
        } else if (index == 1) {
            cpu.set_reg(Rax, 2);
        } else if (index == 2) {
            cpu.set_reg(Rax, 1);
        } else if (index == 7) {
            if (cpu.reg(Rdx) != 0) {
                cpu.memory().write32(cpu.reg(Rdx), 0);
            }
            cpu.set_reg(Rax, 0);
        } else if (index == 8) {
            if (cpu.reg(R8) != 0) {
                cpu.memory().write8(cpu.reg(R8), 0);
            }
            cpu.set_reg(Rax, 0);
        } else if (index == 10) {
            if (cpu.reg(R9) != 0) {
                cpu.memory().write8(cpu.reg(R9), 0);
            }
            cpu.set_reg(Rax, 0);
        } else if (index == 11 || index == 12) {
            cpu.set_reg(Rax, 0);
        } else if (index == 6) {
            if (cpu.reg(R8) != 0) {
                cpu.memory().write64(cpu.reg(R8), 0);
            }
            // An absent setting is represented as an empty inspectable so the guest can use its
            // normal default-value path without requiring emulated language exceptions.
            cpu.set_reg(Rax, 0);
        } else {
            cpu.set_reg(Rax, 0x80004001U);
        }
        finish_call();
        break;
    }
    case Api::AppDataPathsStaticsMethod: {
        const auto index = app_data_paths_statics_methods_.at(cpu.rip());
        if (index == 0) {
            if (cpu.reg(R8) != 0) {
                cpu.memory().write64(cpu.reg(R8), cpu.reg(Rcx));
            }
            cpu.set_reg(Rax, cpu.reg(R8) == 0 ? 0x80070057U : 0);
        } else if (index == 1) {
            cpu.set_reg(Rax, 2);
        } else if (index == 2) {
            cpu.set_reg(Rax, 1);
        } else if (index == 6) {
            if (cpu.reg(R8) != 0) {
                cpu.memory().write64(cpu.reg(R8), app_data_paths_proxy_);
            }
            cpu.set_reg(Rax, cpu.reg(R8) == 0 ? 0x80070057U : 0);
        } else if (index == 7) {
            if (cpu.reg(Rdx) != 0) {
                cpu.memory().write64(cpu.reg(Rdx), app_data_paths_proxy_);
            }
            cpu.set_reg(Rax, cpu.reg(Rdx) == 0 ? 0x80070057U : 0);
        } else {
            cpu.set_reg(Rax, 0x80004001U); // E_NOTIMPL
        }
        finish_call();
        break;
    }
    case Api::AppDataPathsMethod: {
        const auto index = app_data_paths_methods_.at(cpu.rip());
        if (index == 0) {
            if (cpu.reg(R8) != 0) {
                cpu.memory().write64(cpu.reg(R8), cpu.reg(Rcx));
            }
            cpu.set_reg(Rax, cpu.reg(R8) == 0 ? 0x80070057U : 0);
        } else if (index == 1) {
            cpu.set_reg(Rax, 2);
        } else if (index == 2) {
            cpu.set_reg(Rax, 1);
        } else if (index >= 6 && index <= 14) {
            const auto output = cpu.reg(Rdx);
            if (output == 0) {
                cpu.set_reg(Rax, 0x80070057U); // E_INVALIDARG
                finish_call();
                break;
            }
            const auto path_index = static_cast<std::size_t>(index - 6);
            if (app_data_path_strings_[path_index] == 0) {
                const auto environment_path = [](const wchar_t *name) {
                    std::wstring value(32768, L'\0');
                    const auto length = GetEnvironmentVariableW(name, value.data(),
                                                                static_cast<DWORD>(value.size()));
                    value.resize(length < value.size() ? length : 0);
                    return value;
                };
                const auto user_profile = environment_path(L"USERPROFILE");
                const auto local_app_data = environment_path(L"LOCALAPPDATA");
                const auto roaming_app_data = environment_path(L"APPDATA");
                const auto program_data = environment_path(L"PROGRAMDATA");
                auto package_install_root = guest_executable_.parent_path();
                while (!package_install_root.empty() &&
                       !std::filesystem::exists(package_install_root / L"AppxManifest.xml")) {
                    const auto parent = package_install_root.parent_path();
                    if (parent == package_install_root) {
                        package_install_root.clear();
                        break;
                    }
                    package_install_root = parent;
                }
                std::wstring package_data_root;
                if (!package_install_root.empty()) {
                    const auto package_full_name = package_install_root.filename().wstring();
                    const auto first_separator = package_full_name.find(L'_');
                    const auto last_separator = package_full_name.rfind(L'_');
                    if (first_separator != std::wstring::npos &&
                        last_separator != std::wstring::npos && first_separator != last_separator) {
                        const auto family_name = package_full_name.substr(0, first_separator) +
                                                 L"_" +
                                                 package_full_name.substr(last_separator + 1);
                        package_data_root = local_app_data + L"\\Packages\\" + family_name;
                    }
                }
                const auto isolated_local = package_data_root.empty()
                                                ? local_app_data
                                                : package_data_root + L"\\LocalState";
                const auto isolated_roaming = package_data_root.empty()
                                                  ? roaming_app_data
                                                  : package_data_root + L"\\RoamingState";
                const std::array<std::wstring, 9> paths = {
                    local_app_data + L"\\Microsoft\\Windows\\INetCookies",
                    user_profile + L"\\Desktop",
                    user_profile + L"\\Documents",
                    user_profile + L"\\Favorites",
                    local_app_data + L"\\Microsoft\\Windows\\History",
                    local_app_data + L"\\Microsoft\\Windows\\INetCache",
                    isolated_local,
                    program_data,
                    isolated_roaming,
                };
                const auto &path = paths[path_index];
                const auto handle = allocate(28 + (path.size() + 1) * 2);
                cpu.memory().write32(handle, 0);
                cpu.memory().write32(handle + 4, static_cast<std::uint32_t>(path.size()));
                cpu.memory().write64(handle + 8, 0);
                cpu.memory().write64(handle + 16, handle + 28);
                cpu.memory().write32(handle + 24, 0);
                for (std::size_t character = 0; character < path.size(); ++character) {
                    cpu.memory().write16(handle + 28 + character * 2,
                                         static_cast<std::uint16_t>(path[character]));
                }
                cpu.memory().write16(handle + 28 + path.size() * 2, 0);
                app_data_path_strings_[path_index] = handle;
            }
            cpu.memory().write32(app_data_path_strings_[path_index] + 24,
                                 cpu.memory().read32(app_data_path_strings_[path_index] + 24) + 1);
            cpu.memory().write64(output, app_data_path_strings_[path_index]);
            cpu.set_reg(Rax, 0);
        } else {
            cpu.set_reg(Rax, 0x80004001U); // E_NOTIMPL
        }
        finish_call();
        break;
    }
    case Api::XamlResourceFactoryMethod: {
        const auto index = xaml_resource_factory_methods_.at(cpu.rip());
        if (index == 0) {
            if (cpu.reg(R8) != 0) {
                cpu.memory().write64(cpu.reg(R8), cpu.reg(Rcx));
            }
            cpu.set_reg(Rax, 0);
        } else if (index == 1) {
            cpu.set_reg(Rax, 2);
        } else if (index == 2) {
            cpu.set_reg(Rax, 1);
        } else {
            if (xaml_resource_proxy_ == 0) {
                const auto vtable = allocate(32 * 8);
                xaml_resource_proxy_ = allocate(8);
                cpu.memory().write64(xaml_resource_proxy_, vtable);
                for (std::uint32_t method = 0; method < 32; ++method) {
                    const auto thunk = next_thunk_;
                    next_thunk_ += 0x100;
                    thunks_.emplace(thunk, Api::XamlResourceMethod);
                    thunk_names_.emplace(thunk, "IXamlResource#" + std::to_string(method));
                    xaml_resource_methods_.emplace(thunk, method);
                    cpu.memory().write64(vtable + method * 8, thunk);
                }
            }
            if (cpu.reg(Rdx) != 0) {
                cpu.memory().write64(cpu.reg(Rdx), xaml_resource_proxy_);
            }
            cpu.set_reg(Rax, 0);
        }
        finish_call();
        break;
    }
    case Api::XamlResourceMethod: {
        const auto index = xaml_resource_methods_.at(cpu.rip());
        if (index == 0) {
            if (cpu.reg(R8) != 0) {
                cpu.memory().write64(cpu.reg(R8), cpu.reg(Rcx));
            }
            cpu.set_reg(Rax, 0);
        } else if (index == 1) {
            cpu.set_reg(Rax, 2);
        } else if (index == 2) {
            cpu.set_reg(Rax, 1);
        } else {
            if (cpu.reg(Rdx) != 0) {
                cpu.memory().write64(cpu.reg(Rdx), 0);
            }
            cpu.set_reg(Rax, 0);
        }
        finish_call();
        break;
    }
    case Api::XamlApplicationStaticsMethod: {
        const auto index = xaml_application_statics_methods_.at(cpu.rip());
        if (index == 0) {
            if (cpu.reg(R8) != 0) {
                cpu.memory().write64(cpu.reg(R8), cpu.reg(Rcx));
            }
            cpu.set_reg(Rax, 0);
        } else if (index == 1) {
            cpu.set_reg(Rax, 2);
        } else if (index == 2) {
            cpu.set_reg(Rax, 1);
        } else if (index == 6) {
            if (xaml_resource_proxy_ == 0) {
                const auto vtable = allocate(32 * 8);
                xaml_resource_proxy_ = allocate(8);
                cpu.memory().write64(xaml_resource_proxy_, vtable);
                for (std::uint32_t method = 0; method < 32; ++method) {
                    const auto thunk = next_thunk_;
                    next_thunk_ += 0x100;
                    thunks_.emplace(thunk, Api::XamlResourceMethod);
                    thunk_names_.emplace(thunk, "IXamlApplication#" + std::to_string(method));
                    xaml_resource_methods_.emplace(thunk, method);
                    cpu.memory().write64(vtable + method * 8, thunk);
                }
            }
            if (cpu.reg(Rdx) != 0) {
                cpu.memory().write64(cpu.reg(Rdx), xaml_resource_proxy_);
            }
            cpu.set_reg(Rax, 0);
        } else {
            cpu.set_reg(Rax, 0x80004001U);
        }
        finish_call();
        break;
    }
    case Api::XamlAppFactoryMethod: {
        const auto index = xaml_app_factory_methods_.at(cpu.rip());
        if (index == 0) {
            if (cpu.reg(R8) != 0) {
                cpu.memory().write64(cpu.reg(R8), cpu.reg(Rcx));
            }
            cpu.set_reg(Rax, 0);
        } else if (index == 1) {
            cpu.set_reg(Rax, 2);
        } else if (index == 2) {
            cpu.set_reg(Rax, 1);
        } else if (index == 6) {
            if (cpu.reg(Rdx) == 0) {
                cpu.set_reg(Rax, 0x80070057U); // E_INVALIDARG
            } else {
                cpu.memory().write64(cpu.reg(Rdx), xaml_app_proxy_);
                cpu.set_reg(Rax, 0);
            }
        } else {
            cpu.set_reg(Rax, 0x80004001U); // E_NOTIMPL
        }
        finish_call();
        break;
    }
    case Api::XamlAppMethod: {
        const auto index = xaml_app_methods_.at(cpu.rip());
        if (index == 0) {
            if (cpu.reg(R8) != 0) {
                cpu.memory().write64(cpu.reg(R8), cpu.reg(Rcx));
            }
            cpu.set_reg(Rax, 0);
        } else if (index == 1) {
            cpu.set_reg(Rax, 2);
        } else if (index == 2) {
            cpu.set_reg(Rax, 1);
        } else if (index == 6) {
            cpu.set_reg(Rax, 0);
        } else if (index == 7) {
            if (cpu.reg(Rdx) == 0) {
                cpu.set_reg(Rax, 0x80070057U); // E_INVALIDARG
            } else {
                cpu.memory().write64(cpu.reg(Rdx), xaml_app_drag_verifier_);
                cpu.set_reg(Rax, 0);
            }
        } else if (index == 8) {
            xaml_app_drag_verifier_ = cpu.reg(Rdx);
            cpu.set_reg(Rax, 0);
        } else if (index == 11) {
            xaml_app_localized_key_storage_ = cpu.reg(Rdx);
            cpu.set_reg(Rax, 0);
        } else {
            cpu.set_reg(Rax, 0x80004001U); // E_NOTIMPL
        }
        finish_call();
        break;
    }
    case Api::DispatcherQueueControllerStaticsMethod: {
        const auto index = dispatcher_queue_controller_statics_methods_.at(cpu.rip());
        if (index == 0) {
            if (cpu.reg(R8) != 0) {
                cpu.memory().write64(cpu.reg(R8), cpu.reg(Rcx));
            }
            cpu.set_reg(Rax, 0);
        } else if (index == 1) {
            cpu.set_reg(Rax, 2);
        } else if (index == 2) {
            cpu.set_reg(Rax, 1);
        } else if (index == 6 || index == 7) {
            if (dispatcher_queue_controller_proxy_ == 0) {
                const auto vtable = allocate(8 * 8);
                dispatcher_queue_controller_proxy_ = allocate(8);
                cpu.memory().write64(dispatcher_queue_controller_proxy_, vtable);
                for (std::uint32_t method = 0; method < 8; ++method) {
                    const auto thunk = next_thunk_;
                    next_thunk_ += 0x100;
                    thunks_.emplace(thunk, Api::DispatcherQueueControllerMethod);
                    thunk_names_.emplace(thunk,
                                         "IDispatcherQueueController#" + std::to_string(method));
                    dispatcher_queue_controller_methods_.emplace(thunk, method);
                    cpu.memory().write64(vtable + method * 8, thunk);
                }
            }
            if (cpu.reg(Rdx) != 0) {
                cpu.memory().write64(cpu.reg(Rdx), dispatcher_queue_controller_proxy_);
            }
            cpu.set_reg(Rax, 0);
        } else {
            cpu.set_reg(Rax, 0x80004001U);
        }
        finish_call();
        break;
    }
    case Api::DispatcherQueueControllerMethod: {
        const auto index = dispatcher_queue_controller_methods_.at(cpu.rip());
        if (index == 0) {
            if (cpu.reg(R8) != 0) {
                cpu.memory().write64(cpu.reg(R8), cpu.reg(Rcx));
            }
            cpu.set_reg(Rax, 0);
        } else if (index == 1) {
            cpu.set_reg(Rax, 2);
        } else if (index == 2) {
            cpu.set_reg(Rax, 1);
        } else if (index == 6) {
            cpu.set_reg(Rax, 0);
        } else {
            cpu.set_reg(Rax, 0x80004001U);
        }
        finish_call();
        break;
    }
    case Api::ResourceManagerStaticsMethod: {
        const auto index = resource_manager_statics_methods_.at(cpu.rip());
        if (index == 0) {
            if (cpu.reg(R8) != 0) {
                cpu.memory().write64(cpu.reg(R8), cpu.reg(Rcx));
            }
            cpu.set_reg(Rax, 0);
        } else if (index == 1) {
            cpu.set_reg(Rax, 2);
        } else if (index == 2) {
            cpu.set_reg(Rax, 1);
        } else if (index == 6) {
            if (cpu.reg(Rdx) == 0) {
                cpu.set_reg(Rax, 0x80070057U); // E_INVALIDARG
            } else {
                cpu.memory().write64(cpu.reg(Rdx), resource_manager_proxy_);
                cpu.set_reg(Rax, 0);
            }
        } else if (index == 7) {
            if (cpu.reg(R8) == 0) {
                cpu.set_reg(Rax, 0x80070057U); // E_INVALIDARG
            } else {
                cpu.memory().write8(cpu.reg(R8), 0);
                cpu.set_reg(Rax, 0);
            }
        } else {
            cpu.set_reg(Rax, 0x80004001U); // E_NOTIMPL
        }
        finish_call();
        break;
    }
    case Api::ResourceManagerMethod: {
        const auto index = resource_manager_methods_.at(cpu.rip());
        if (index == 0) {
            if (cpu.reg(R8) != 0) {
                cpu.memory().write64(cpu.reg(R8), cpu.reg(Rcx));
            }
            cpu.set_reg(Rax, 0);
        } else if (index == 1) {
            cpu.set_reg(Rax, 2);
        } else if (index == 2) {
            cpu.set_reg(Rax, 1);
        } else if (index == 6) {
            if (cpu.reg(Rdx) == 0) {
                cpu.set_reg(Rax, 0x80070057U); // E_INVALIDARG
            } else {
                cpu.memory().write64(cpu.reg(Rdx), resource_map_proxy_);
                cpu.set_reg(Rax, 0);
            }
        } else {
            cpu.set_reg(Rax, 0x80004001U); // E_NOTIMPL
        }
        finish_call();
        break;
    }
    case Api::ResourceMapMethod: {
        const auto index = resource_map_methods_.at(cpu.rip());
        if (index == 0) {
            if (cpu.reg(R8) != 0) {
                cpu.memory().write64(cpu.reg(R8), cpu.reg(Rcx));
            }
            cpu.set_reg(Rax, 0);
        } else if (index == 1) {
            cpu.set_reg(Rax, 2);
        } else if (index == 2) {
            cpu.set_reg(Rax, 1);
        } else if (index == 7) {
            if (cpu.reg(R8) == 0) {
                cpu.set_reg(Rax, 0x80070057U); // E_INVALIDARG
            } else {
                resource_candidate_value_ = cpu.reg(Rdx);
                cpu.memory().write64(cpu.reg(R8), resource_candidate_proxy_);
                cpu.set_reg(Rax, 0);
            }
        } else if (index == 8) {
            if (cpu.reg(R9) == 0) {
                cpu.set_reg(Rax, 0x80070057U); // E_INVALIDARG
            } else {
                resource_candidate_value_ = cpu.reg(Rdx);
                cpu.memory().write64(cpu.reg(R9), resource_candidate_proxy_);
                cpu.set_reg(Rax, 0);
            }
        } else {
            cpu.set_reg(Rax, 0x80004001U); // E_NOTIMPL
        }
        finish_call();
        break;
    }
    case Api::ResourceContextStaticsMethod: {
        const auto index = resource_context_statics_methods_.at(cpu.rip());
        if (index == 0) {
            if (cpu.reg(R8) != 0) {
                cpu.memory().write64(cpu.reg(R8), cpu.reg(Rcx));
            }
            cpu.set_reg(Rax, 0);
        } else if (index == 1) {
            cpu.set_reg(Rax, 2);
        } else if (index == 2) {
            cpu.set_reg(Rax, 1);
        } else if (index == 7 || index == 10) {
            if (cpu.reg(Rdx) == 0) {
                cpu.set_reg(Rax, 0x80070057U); // E_INVALIDARG
            } else {
                cpu.memory().write64(cpu.reg(Rdx), resource_context_proxy_);
                cpu.set_reg(Rax, 0);
            }
        } else {
            cpu.set_reg(Rax, 0x80004001U); // E_NOTIMPL
        }
        finish_call();
        break;
    }
    case Api::ResourceContextMethod: {
        const auto index = resource_context_methods_.at(cpu.rip());
        if (index == 0) {
            if (cpu.reg(R8) != 0) {
                cpu.memory().write64(cpu.reg(R8), cpu.reg(Rcx));
            }
            cpu.set_reg(Rax, 0);
        } else if (index == 1) {
            cpu.set_reg(Rax, 2);
        } else if (index == 2) {
            cpu.set_reg(Rax, 1);
        } else {
            cpu.set_reg(Rax, 0x80004001U); // E_NOTIMPL
        }
        finish_call();
        break;
    }
    case Api::ResourceCandidateMethod: {
        const auto index = resource_candidate_methods_.at(cpu.rip());
        if (index == 0) {
            if (cpu.reg(R8) != 0) {
                cpu.memory().write64(cpu.reg(R8), cpu.reg(Rcx));
            }
            cpu.set_reg(Rax, 0);
        } else if (index == 1) {
            cpu.set_reg(Rax, 2);
        } else if (index == 2) {
            cpu.set_reg(Rax, 1);
        } else if (index == 10) {
            if (cpu.reg(Rdx) == 0) {
                cpu.set_reg(Rax, 0x80070057U); // E_INVALIDARG
            } else {
                if (resource_candidate_value_ != 0 &&
                    (cpu.memory().read32(resource_candidate_value_) & 1U) == 0) {
                    cpu.memory().write32(resource_candidate_value_ + 24,
                                         cpu.memory().read32(resource_candidate_value_ + 24) + 1);
                }
                cpu.memory().write64(cpu.reg(Rdx), resource_candidate_value_);
                cpu.set_reg(Rax, 0);
            }
        } else if (index == 12) {
            if (cpu.reg(R8) == 0) {
                cpu.set_reg(Rax, 0x80070057U); // E_INVALIDARG
            } else {
                if (resource_candidate_language_ == 0) {
                    constexpr std::u16string_view language = u"en-US";
                    resource_candidate_language_ = allocate(28 + (language.size() + 1) * 2);
                    cpu.memory().write32(resource_candidate_language_, 0);
                    cpu.memory().write32(resource_candidate_language_ + 4,
                                         static_cast<std::uint32_t>(language.size()));
                    cpu.memory().write64(resource_candidate_language_ + 8, 0);
                    cpu.memory().write64(resource_candidate_language_ + 16,
                                         resource_candidate_language_ + 28);
                    cpu.memory().write32(resource_candidate_language_ + 24, 0);
                    for (std::size_t character = 0; character < language.size(); ++character) {
                        cpu.memory().write16(resource_candidate_language_ + 28 + character * 2,
                                             language[character]);
                    }
                    cpu.memory().write16(resource_candidate_language_ + 28 + language.size() * 2,
                                         0);
                }
                cpu.memory().write32(resource_candidate_language_ + 24,
                                     cpu.memory().read32(resource_candidate_language_ + 24) + 1);
                cpu.memory().write64(cpu.reg(R8), resource_candidate_language_);
                cpu.set_reg(Rax, 0);
            }
        } else {
            cpu.set_reg(Rax, 0x80004001U); // E_NOTIMPL
        }
        finish_call();
        break;
    }
    case Api::UISettingsFactoryMethod: {
        const auto index = ui_settings_factory_methods_.at(cpu.rip());
        if (index == 0) {
            if (cpu.reg(R8) != 0) {
                cpu.memory().write64(cpu.reg(R8), cpu.reg(Rcx));
            }
            cpu.set_reg(Rax, 0);
        } else if (index == 1) {
            cpu.set_reg(Rax, 2);
        } else if (index == 2) {
            cpu.set_reg(Rax, 1);
        } else if (index == 6) {
            if (cpu.reg(Rdx) == 0) {
                cpu.set_reg(Rax, 0x80070057U); // E_INVALIDARG
            } else {
                cpu.memory().write64(cpu.reg(Rdx), ui_settings_proxy_);
                cpu.set_reg(Rax, 0);
            }
        } else {
            cpu.set_reg(Rax, 0x80004001U); // E_NOTIMPL
        }
        finish_call();
        break;
    }
    case Api::UISettingsMethod:
    case Api::UISettings3Method: {
        const bool settings3 = found->second == Api::UISettings3Method;
        const auto index =
            settings3 ? ui_settings3_methods_.at(cpu.rip()) : ui_settings_methods_.at(cpu.rip());
        if (index == 0) {
            const auto iid = cpu.reg(Rdx);
            auto result = settings3 ? ui_settings3_proxy_ : ui_settings_proxy_;
            if (iid != 0 && cpu.memory().read32(iid) == 0x03021be4U &&
                cpu.memory().read16(iid + 4) == 0x5254U &&
                cpu.memory().read16(iid + 6) == 0x4781U) {
                result = ui_settings3_proxy_;
            } else if (iid != 0 && cpu.memory().read32(iid) == 0x85361600U &&
                       cpu.memory().read16(iid + 4) == 0x1c63U &&
                       cpu.memory().read16(iid + 6) == 0x4627U) {
                result = ui_settings_proxy_;
            }
            if (cpu.reg(R8) != 0) {
                cpu.memory().write64(cpu.reg(R8), result);
            }
            cpu.set_reg(Rax, 0);
        } else if (index == 1) {
            cpu.set_reg(Rax, 2);
        } else if (index == 2) {
            cpu.set_reg(Rax, 1);
        } else if (settings3 && index == 6) {
            if (cpu.reg(R8) == 0) {
                cpu.set_reg(Rax, 0x80070057U); // E_INVALIDARG
            } else {
                cpu.memory().write8(cpu.reg(R8), 0xff);
                cpu.memory().write8(cpu.reg(R8) + 1, 0);
                cpu.memory().write8(cpu.reg(R8) + 2, 0);
                cpu.memory().write8(cpu.reg(R8) + 3, 0);
                cpu.set_reg(Rax, 0);
            }
        } else {
            cpu.set_reg(Rax, 0x80004001U); // E_NOTIMPL
        }
        finish_call();
        break;
    }
    case Api::PropertyValueStaticsMethod: {
        const auto index = property_value_statics_methods_.at(cpu.rip());
        if (index == 0) {
            if (cpu.reg(R8) != 0) {
                cpu.memory().write64(cpu.reg(R8), cpu.reg(Rcx));
            }
            cpu.set_reg(Rax, 0);
        } else if (index == 1) {
            cpu.set_reg(Rax, 2);
        } else if (index == 2) {
            cpu.set_reg(Rax, 1);
        } else if (index >= 6 && index <= 17) {
            if (cpu.reg(R8) == 0) {
                cpu.set_reg(Rax, 0x80070057U); // E_INVALIDARG
            } else {
                const auto value = allocate(8);
                cpu.memory().write64(value, property_value_vtable_);
                property_value_types_[value] = index == 6 ? 0 : index - 6;
                property_value_data_[value] = cpu.reg(Rdx);
                cpu.memory().write64(cpu.reg(R8), value);
                cpu.set_reg(Rax, 0);
            }
        } else {
            cpu.set_reg(Rax, 0x80004001U); // E_NOTIMPL
        }
        finish_call();
        break;
    }
    case Api::PropertyValueMethod: {
        const auto index = property_value_methods_.at(cpu.rip());
        const auto type = property_value_types_.find(cpu.reg(Rcx));
        const auto data = property_value_data_.find(cpu.reg(Rcx));
        if (index == 0) {
            if (cpu.reg(R8) != 0) {
                cpu.memory().write64(cpu.reg(R8), cpu.reg(Rcx));
            }
            cpu.set_reg(Rax, 0);
        } else if (index == 1) {
            cpu.set_reg(Rax, 2);
        } else if (index == 2) {
            cpu.set_reg(Rax, 1);
        } else if (index == 6) {
            if (cpu.reg(Rdx) != 0) {
                cpu.memory().write32(cpu.reg(Rdx),
                                     type == property_value_types_.end() ? 0 : type->second);
            }
            cpu.set_reg(Rax, cpu.reg(Rdx) == 0 ? 0x80070057U : 0);
        } else if (index == 7) {
            if (cpu.reg(Rdx) != 0) {
                const auto property_type = type == property_value_types_.end() ? 0 : type->second;
                cpu.memory().write8(cpu.reg(Rdx), property_type >= 1 && property_type <= 9 ? 1 : 0);
            }
            cpu.set_reg(Rax, cpu.reg(Rdx) == 0 ? 0x80070057U : 0);
        } else if (index >= 8 && index <= 18) {
            if (cpu.reg(Rdx) == 0 || type == property_value_types_.end() ||
                data == property_value_data_.end() || type->second != index - 7) {
                cpu.set_reg(Rax, cpu.reg(Rdx) == 0 ? 0x80070057U : 0x80028ca0U);
            } else {
                const auto bits = data->second;
                if (index == 8 || index == 18) {
                    cpu.memory().write8(cpu.reg(Rdx), static_cast<std::uint8_t>(bits));
                } else if (index == 9 || index == 10 || index == 17) {
                    cpu.memory().write16(cpu.reg(Rdx), static_cast<std::uint16_t>(bits));
                } else if (index == 11 || index == 12 || index == 15) {
                    cpu.memory().write32(cpu.reg(Rdx), static_cast<std::uint32_t>(bits));
                } else {
                    cpu.memory().write64(cpu.reg(Rdx), bits);
                }
                cpu.set_reg(Rax, 0);
            }
        } else {
            cpu.set_reg(Rax, 0x80004001U); // E_NOTIMPL
        }
        finish_call();
        break;
    }
    case Api::MsvcpStreamBufferConstruct: {
        const auto object = cpu.reg(Rcx);
        // Replicates basic_streambuf::_Init(). The six _IG*/_IP* members are pointers to the
        // direct _Gfirst (+0x08), _Pfirst (+0x10), _Gnext (+0x28), _Pnext (+0x30), _Gcount
        // (+0x48), and _Pcount (+0x4c) members, and every buffer starts empty. Direct member
        // storage is required: the fields past +0x60 belong to basic_filebuf, so pointing the
        // indirections there overwrote its own state and made the guest see a write area whose
        // "current position" was a vtable pointer.
        constexpr std::uint64_t storage_size = 4096;
        const auto storage = allocate(storage_size);
        stream_buffer_storage_[object] = storage;
        stream_buffer_lengths_[object] = 0;
        cpu.memory().write64(object + 0x08, 0);             // _Gfirst
        cpu.memory().write64(object + 0x10, 0);             // _Pfirst
        cpu.memory().write64(object + 0x18, object + 0x08); // _IGfirst -> &_Gfirst
        cpu.memory().write64(object + 0x20, object + 0x10); // _IPfirst -> &_Pfirst
        cpu.memory().write64(object + 0x28, 0);             // _Gnext
        cpu.memory().write64(object + 0x30, 0);             // _Pnext
        cpu.memory().write64(object + 0x38, object + 0x28); // _IGnext -> &_Gnext
        cpu.memory().write64(object + 0x40, object + 0x30); // _IPnext -> &_Pnext
        cpu.memory().write32(object + 0x48, 0);             // _Gcount
        cpu.memory().write32(object + 0x4c, 0);             // _Pcount
        cpu.memory().write64(object + 0x50, object + 0x48); // _IGcount -> &_Gcount
        cpu.memory().write64(object + 0x58, object + 0x4c); // _IPcount -> &_Pcount
        cpu.memory().write64(object + 0x60, 0);             // _Plocale
        cpu.set_reg(Rax, object);
        finish_call();
        break;
    }
    case Api::MsvcpStreamBufferInit: {
        const auto stream_buffer = cpu.reg(Rcx);
        const auto guest_file = cpu.reg(Rdx);
        if (guest_file != 0 && guest_file_streams_.contains(guest_file)) {
            stream_buffer_files_[stream_buffer] = guest_file;
            if (pending_guest_file_stream_ == guest_file) {
                pending_guest_file_stream_ = 0;
            }
        } else if (pending_guest_file_stream_ != 0) {
            // The parameterless MSVC streambuf initializer follows _Fiopen in the filebuf
            // constructor. Carry that guest-owned handle explicitly instead of depending on a
            // stale value in RDX, which is volatile under the x64 ABI.
            stream_buffer_files_[stream_buffer] = pending_guest_file_stream_;
            pending_guest_file_stream_ = 0;
        } else {
            stream_buffer_files_.erase(stream_buffer);
        }
        cpu.set_reg(Rax, stream_buffer);
        finish_call();
        break;
    }
    case Api::MsvcpStreamGetLocale: {
        const auto output = cpu.reg(Rdx);
        if (output == 0) {
            throw Error("basic_streambuf::getloc received a null output object");
        }
        ensure_locale();
        cpu.memory().write32(locale_proxy_ + 8, cpu.memory().read32(locale_proxy_ + 8) + 1);
        cpu.memory().write64(output, locale_proxy_);
        // The MSVC x64 return object used by this overload carries its _Locimp pointer in the
        // second pointer-sized field; callers pass that wrapper directly to use_facet.
        cpu.memory().write64(output + 8, locale_proxy_);
        cpu.set_reg(Rax, output);
        finish_call();
        break;
    }
    case Api::MsvcpFileOpen: {
        const auto path = cpu.memory().read_wide_string(cpu.reg(Rcx));
        const auto mode = static_cast<std::uint32_t>(cpu.reg(Rdx));
        constexpr std::uint32_t open_in = 0x01;
        constexpr std::uint32_t open_out = 0x02;
        constexpr std::uint32_t open_at_end = 0x04;
        constexpr std::uint32_t open_append = 0x08;
        constexpr std::uint32_t open_truncate = 0x10;
        constexpr std::uint32_t open_binary = 0x20;
        const bool input = (mode & open_in) != 0;
        const bool output = (mode & open_out) != 0;
        const bool binary = (mode & open_binary) != 0;
        std::wstring native_mode;
        if (input && output) {
            native_mode = (mode & open_truncate) != 0 ? L"w+" : L"r+";
        } else if (output) {
            native_mode = (mode & open_append) != 0 ? L"a" : L"w";
        } else {
            native_mode = L"r";
        }
        if (binary) {
            native_mode.push_back(L'b');
        }
        FILE *stream = _wfsopen(path.c_str(), native_mode.c_str(), static_cast<int>(cpu.reg(R8)));
        const auto open_error = stream == nullptr ? errno : 0;
        if (log::enabled(log::Level::Api)) {
            log::api("api", "guest file open path '" + narrow_string(path) +
                                "' mode=" + narrow_string(native_mode) +
                                " result=" + std::to_string(open_error));
        }
        if (stream == nullptr && input && output && (mode & open_truncate) == 0) {
            // ios::in|ios::out does not create a missing file, matching the standard mode table.
            cpu.set_reg(Rax, 0);
        } else if (stream == nullptr) {
            cpu.set_reg(Rax, 0);
        } else {
            if ((mode & open_at_end) != 0) {
                static_cast<void>(_fseeki64(stream, 0, SEEK_END));
            }
            const auto guest_stream = allocate(0x40);
            for (std::uint64_t offset = 0; offset < 0x40; offset += 8) {
                cpu.memory().write64(guest_stream + offset, 0);
            }
            guest_file_streams_.emplace(guest_stream, stream);
            pending_guest_file_stream_ = guest_stream;
            cpu.set_reg(Rax, guest_stream);
        }
        finish_call();
        break;
    }
    case Api::GuestFileMethod: {
        if (thunk_name.ends_with("_get_stream_buffer_pointers")) {
            const auto found = guest_file_streams_.find(cpu.reg(Rcx));
            if (found == guest_file_streams_.end()) {
                cpu.set_reg(Rax, EINVAL);
            } else {
                if (cpu.reg(Rdx) != 0) {
                    cpu.memory().write64(cpu.reg(Rdx), cpu.reg(Rcx));
                }
                if (cpu.reg(R8) != 0) {
                    cpu.memory().write64(cpu.reg(R8), cpu.reg(Rcx) + 8);
                }
                if (cpu.reg(R9) != 0) {
                    cpu.memory().write64(cpu.reg(R9), cpu.reg(Rcx) + 16);
                }
                cpu.set_reg(Rax, 0);
            }
            finish_call();
            break;
        }
        const auto stream_argument =
            thunk_name.ends_with("fread") || thunk_name.ends_with("fwrite")
                ? cpu.reg(R9)
                : (thunk_name.ends_with("fputc") ? cpu.reg(Rdx) : cpu.reg(Rcx));
        const auto found = guest_file_streams_.find(stream_argument);
        if (found == guest_file_streams_.end()) {
            cpu.set_reg(Rax, thunk_name.ends_with("fgetc") ? static_cast<std::uint32_t>(EOF) : 0);
            finish_call();
            break;
        }
        auto *stream = static_cast<FILE *>(found->second);
        if (thunk_name.ends_with("fread") || thunk_name.ends_with("fwrite")) {
            const auto size = cpu.reg(Rdx);
            const auto count = cpu.reg(R8);
            if (size != 0 && count > (64ULL * 1024 * 1024) / size) {
                cpu.set_reg(Rax, 0);
            } else {
                std::vector<std::uint8_t> bytes(static_cast<std::size_t>(size * count));
                if (thunk_name.ends_with("fwrite")) {
                    bytes = cpu.memory().read(cpu.reg(Rcx), bytes.size());
                    cpu.set_reg(Rax, std::fwrite(bytes.data(), static_cast<std::size_t>(size),
                                                 static_cast<std::size_t>(count), stream));
                } else {
                    const auto read = std::fread(bytes.data(), static_cast<std::size_t>(size),
                                                 static_cast<std::size_t>(count), stream);
                    cpu.memory().write(cpu.reg(Rcx),
                                       std::span<const std::uint8_t>(bytes.data(), read * size));
                    cpu.set_reg(Rax, read);
                }
            }
        } else if (thunk_name.ends_with("fclose")) {
            cpu.set_reg(Rax, std::fclose(stream));
            if (pending_guest_file_stream_ == stream_argument) {
                pending_guest_file_stream_ = 0;
            }
            guest_file_streams_.erase(found);
        } else if (thunk_name.ends_with("fflush")) {
            cpu.set_reg(Rax, std::fflush(stream));
        } else if (thunk_name.ends_with("fgetpos")) {
            const auto position = _ftelli64(stream);
            if (cpu.reg(Rdx) != 0) {
                cpu.memory().write64(cpu.reg(Rdx), static_cast<std::uint64_t>(position));
            }
            cpu.set_reg(Rax, position < 0 ? -1 : 0);
        } else if (thunk_name.ends_with("fsetpos")) {
            const auto position =
                cpu.reg(Rdx) == 0 ? -1
                                  : static_cast<std::int64_t>(cpu.memory().read64(cpu.reg(Rdx)));
            cpu.set_reg(Rax, position < 0 ? -1 : _fseeki64(stream, position, SEEK_SET));
        } else if (thunk_name.ends_with("_fseeki64")) {
            cpu.set_reg(Rax, _fseeki64(stream, static_cast<std::int64_t>(cpu.reg(Rdx)),
                                       static_cast<int>(cpu.reg(R8))));
        } else if (thunk_name.ends_with("fgetc")) {
            cpu.set_reg(Rax, std::fgetc(stream));
        } else if (thunk_name.ends_with("fputc")) {
            cpu.set_reg(Rax, std::fputc(static_cast<int>(cpu.reg(Rcx)), stream));
        }
        finish_call();
        break;
    }
    case Api::MsvcpInputStreamConstruct:
        input_stream_buffers_[cpu.reg(Rcx)] = cpu.reg(Rdx);
        if (pending_ios_object_ != 0) {
            input_stream_ios_[cpu.reg(Rcx)] = pending_ios_object_;
            pending_ios_object_ = 0;
        }
        cpu.set_reg(Rax, cpu.reg(Rcx));
        finish_call();
        break;
    case Api::MsvcpStreamSwap: {
        const auto left = input_stream_buffers_.find(cpu.reg(Rcx));
        const auto right = input_stream_buffers_.find(cpu.reg(Rdx));
        if (left != input_stream_buffers_.end() && right != input_stream_buffers_.end()) {
            const auto left_file = stream_buffer_files_.find(left->second);
            const auto right_file = stream_buffer_files_.find(right->second);
            const auto left_handle =
                left_file == stream_buffer_files_.end() ? 0 : left_file->second;
            const auto right_handle =
                right_file == stream_buffer_files_.end() ? 0 : right_file->second;
            if (right_handle == 0) {
                stream_buffer_files_.erase(left->second);
            } else {
                stream_buffer_files_[left->second] = right_handle;
            }
            if (left_handle == 0) {
                stream_buffer_files_.erase(right->second);
            } else {
                stream_buffer_files_[right->second] = left_handle;
            }
        }
        cpu.set_reg(Rax, cpu.reg(Rcx));
        finish_call();
        break;
    }
    case Api::MsvcpStreamSeek: {
        auto *stream = stream_file(cpu.reg(Rcx));
        std::int64_t position = -1;
        if (cpu.reg(Rdx) != 0) {
            // MSVC streampos is {streamoff _Myoff, fpos_t _Fpos, mbstate_t _Mystate}.
            // Old basic_filebuf objects may still use _Fpos, so its conversion operator adds both
            // signed 64-bit fields. The trailing conversion state does not affect a byte seek.
            const auto offset = static_cast<std::int64_t>(cpu.memory().read64(cpu.reg(Rdx)));
            const auto file_position =
                static_cast<std::int64_t>(cpu.memory().read64(cpu.reg(Rdx) + 8));
            if ((file_position <= 0 ||
                 offset <= std::numeric_limits<std::int64_t>::max() - file_position) &&
                (file_position >= 0 ||
                 offset >= std::numeric_limits<std::int64_t>::min() - file_position)) {
                position = offset + file_position;
            }
        }
        if (stream != nullptr && position >= 0) {
            static_cast<void>(_fseeki64(stream, position, SEEK_SET));
        }
        cpu.set_reg(Rax, cpu.reg(Rcx));
        finish_call();
        break;
    }
    case Api::MsvcpStreamTell: {
        const auto output = cpu.reg(Rdx);
        auto *file = stream_file(cpu.reg(Rcx));
        if (output == 0) {
            throw Error("basic_istream::tellg received a null return object");
        }
        const auto position = file == nullptr ? -1 : _ftelli64(file);
        // Construct the complete 24-byte MSVC streampos value in guest memory. Hidden return
        // storage is uninitialized, so leaving the legacy _Fpos field untouched can make the
        // caller observe an arbitrary offset even when _Myoff is correct.
        cpu.memory().write64(output, static_cast<std::uint64_t>(position));
        cpu.memory().write64(output + 8, 0);  // fpos_t _Fpos
        cpu.memory().write64(output + 16, 0); // mbstate_t _Mystate
        cpu.set_reg(Rax, output);
        finish_call();
        break;
    }
    case Api::MsvcpStreamRead:
    case Api::MsvcpStreamReadSome: {
        auto *stream = stream_file(cpu.reg(Rcx));
        const auto requested = static_cast<std::int64_t>(cpu.reg(R8));
        std::size_t count = 0;
        if (stream != nullptr && requested > 0 && requested <= 64LL * 1024 * 1024) {
            std::vector<std::uint8_t> bytes(static_cast<std::size_t>(requested));
            count = std::fread(bytes.data(), 1, bytes.size(), stream);
            cpu.memory().write(cpu.reg(Rdx), std::span<const std::uint8_t>(bytes.data(), count));
            if (found->second == Api::MsvcpStreamRead &&
                count < static_cast<std::size_t>(requested)) {
                if (const auto ios = input_stream_ios_.find(cpu.reg(Rcx));
                    ios != input_stream_ios_.end()) {
                    ios_states_[ios->second] |= 3U; // eofbit | failbit
                }
            }
        }
        cpu.set_reg(Rax, found->second == Api::MsvcpStreamReadSome ? count : cpu.reg(Rcx));
        finish_call();
        break;
    }
    case Api::MsvcpStreamDestroy:
        if (const auto stream = input_stream_buffers_.find(cpu.reg(Rcx));
            stream != input_stream_buffers_.end()) {
            input_stream_buffers_.erase(stream);
        }
        input_stream_ios_.erase(cpu.reg(Rcx));
        stream_buffer_files_.erase(cpu.reg(Rcx));
        cpu.set_reg(Rax, 0);
        finish_call();
        break;
    case Api::MsvcpIosConstruct:
        ios_states_[cpu.reg(Rcx)] = 0;
        ios_exception_masks_[cpu.reg(Rcx)] = 0;
        pending_ios_object_ = cpu.reg(Rcx);
        cpu.set_reg(Rax, cpu.reg(Rcx));
        finish_call();
        break;
    case Api::MsvcpIosClear:
        ios_states_[cpu.reg(Rcx)] = static_cast<std::uint32_t>(cpu.reg(Rdx));
        cpu.set_reg(Rax, cpu.reg(Rcx));
        finish_call();
        break;
    case Api::MsvcpIosSetState:
        ios_states_[cpu.reg(Rcx)] |= static_cast<std::uint32_t>(cpu.reg(Rdx));
        cpu.set_reg(Rax, cpu.reg(Rcx));
        finish_call();
        break;
    case Api::MsvcpIosGood:
        cpu.set_reg(Rax, ios_states_[cpu.reg(Rcx)] == 0 ? 1 : 0);
        finish_call();
        break;
    case Api::MsvcpIosFail:
        cpu.set_reg(Rax, (ios_states_[cpu.reg(Rcx)] & 6U) != 0 ? 1 : 0);
        finish_call();
        break;
    case Api::MsvcpIosExceptions:
        ios_exception_masks_[cpu.reg(Rcx)] = static_cast<std::uint32_t>(cpu.reg(Rdx));
        cpu.set_reg(Rax, cpu.reg(Rcx));
        finish_call();
        break;
    case Api::MsvcpIosDestroy:
        ios_states_.erase(cpu.reg(Rcx));
        ios_exception_masks_.erase(cpu.reg(Rcx));
        if (pending_ios_object_ == cpu.reg(Rcx)) {
            pending_ios_object_ = 0;
        }
        cpu.set_reg(Rax, 0);
        finish_call();
        break;
    case Api::MsvcpOutputStreamConstruct:
        output_stream_buffers_[cpu.reg(Rcx)] = cpu.reg(Rdx);
        cpu.set_reg(Rax, cpu.reg(Rcx));
        finish_call();
        break;
    case Api::MsvcpStreamWrite: {
        const auto found = output_stream_buffers_.find(cpu.reg(Rcx));
        if (found != output_stream_buffers_.end()) {
            const auto stream_buffer = found->second;
            const auto storage = stream_buffer_storage_.at(stream_buffer);
            auto &length = stream_buffer_lengths_.at(stream_buffer);
            const auto count = std::min<std::uint64_t>(cpu.reg(R8), 4095 - length);
            for (std::uint64_t index = 0; index < count; ++index) {
                cpu.memory().write8(storage + length + index,
                                    cpu.memory().read8(cpu.reg(Rdx) + index));
            }
            length += count;
            cpu.memory().write8(storage + length, 0);
            // basic_streambuf stores the write area through _Pfirst (+0x10), _Pnext (+0x30) and
            // _Pcount (+0x4c); pptr() is _Pnext and epptr() is _Pnext + _Pcount.
            cpu.memory().write64(stream_buffer + 0x10, storage);
            cpu.memory().write64(stream_buffer + 0x30, storage + length);
            cpu.memory().write32(stream_buffer + 0x4c, static_cast<std::uint32_t>(4096 - length));
        }
        cpu.set_reg(Rax, cpu.reg(Rcx));
        finish_call();
        break;
    }
    case Api::MsvcpScheduleChore: {
        const auto chore = cpu.reg(Rcx);
        if (chore == 0) {
            cpu.set_reg(Rax, EINVAL);
            finish_call();
            break;
        }
        // MSVC's _Threadpool_chore stores its callback and context at +8 and +16. Native
        // _Schedule_chore would retain that callback and execute the guest address on a host
        // thread. Run it cooperatively through the interpreter until CPUEmu has a guest scheduler.
        const auto callback = cpu.memory().read64(chore + 8);
        const auto context = cpu.memory().read64(chore + 16);
        if (callback == 0) {
            cpu.set_reg(Rax, EINVAL);
            finish_call();
            break;
        }
        cpu.memory().write64(chore,
                             1); // Guest-visible scheduled marker, never a host work pointer.
        static_cast<void>(invoke_guest(cpu, callback, {context, 0, 0, 0}, exit_code, exited));
        cpu.set_reg(Rax, 0);
        finish_call();
        break;
    }
    case Api::MsvcpReleaseChore:
        if (cpu.reg(Rcx) != 0) {
            cpu.memory().write64(cpu.reg(Rcx), 0);
        }
        cpu.set_reg(Rax, 0);
        finish_call();
        break;
    case Api::GuestGetErrorInfo:
        if (cpu.reg(Rdx) == 0 || cpu.reg(Rcx) != 0) {
            cpu.set_reg(Rax, 0x80070057U); // E_INVALIDARG
        } else {
            // CPUEmu has no pending guest IErrorInfo. Never forward the output pointer to
            // OLEAUT32: a native IErrorInfo pointer is not a valid guest COM object.
            cpu.memory().write64(cpu.reg(Rdx), 0);
            cpu.set_reg(Rax, 1); // S_FALSE
        }
        finish_call();
        break;
    case Api::GuestSetErrorInfo:
        // Retaining a guest COM pointer needs AddRef/Release re-entry and per-thread lifetime
        // tracking. Fail closed until that adapter exists.
        cpu.set_reg(Rax, cpu.reg(Rcx) == 0 ? 0x80004001U : 0x80070057U); // E_NOTIMPL/E_INVALIDARG
        finish_call();
        break;
    case Api::GeographicRegionMethod: {
        const auto index = geographic_region_methods_.at(cpu.rip());
        if (index == 0) {
            if (cpu.reg(R8) != 0) {
                cpu.memory().write64(cpu.reg(R8), cpu.reg(Rcx));
            }
            cpu.set_reg(Rax, 0);
        } else if (index == 1) {
            cpu.set_reg(Rax, 2);
        } else if (index == 2) {
            cpu.set_reg(Rax, 1);
        } else if (index >= 6 && index <= 10) {
            wchar_t region[16] = {};
            if (GetLocaleInfoEx(LOCALE_NAME_USER_DEFAULT, LOCALE_SISO3166CTRYNAME, region,
                                static_cast<int>(std::size(region))) == 0) {
                region[0] = L'U';
                region[1] = L'S';
            }
            const auto length = static_cast<std::uint32_t>(std::wcslen(region));
            const auto result = allocate(28 + (static_cast<std::uint64_t>(length) + 1) * 2);
            cpu.memory().write32(result, 0);
            cpu.memory().write32(result + 4, length);
            cpu.memory().write64(result + 8, 0);
            cpu.memory().write64(result + 16, result + 28);
            cpu.memory().write32(result + 24, 1);
            for (std::uint32_t character = 0; character <= length; ++character) {
                cpu.memory().write16(result + 28 + character * 2,
                                     static_cast<std::uint16_t>(region[character]));
            }
            if (cpu.reg(Rdx) != 0) {
                cpu.memory().write64(cpu.reg(Rdx), result);
            }
            cpu.set_reg(Rax, 0);
        } else {
            cpu.set_reg(Rax, 0x80004001U); // E_NOTIMPL
        }
        finish_call();
        break;
    }
    case Api::ApplicationDataStaticsMethod: {
        const auto index = application_data_statics_methods_.at(cpu.rip());
        if (index == 0) {
            if (cpu.reg(R8) != 0) {
                cpu.memory().write64(cpu.reg(R8), cpu.reg(Rcx));
            }
            cpu.set_reg(Rax, 0);
        } else if (index == 1) {
            cpu.set_reg(Rax, 2);
        } else if (index == 2) {
            cpu.set_reg(Rax, 1);
        } else if (index == 6) {
            if (application_data_proxy_ == 0) {
                const auto vtable = allocate(24 * 8);
                application_data_proxy_ = allocate(8);
                cpu.memory().write64(application_data_proxy_, vtable);
                for (std::uint32_t method = 0; method < 24; ++method) {
                    const auto thunk = next_thunk_;
                    next_thunk_ += 0x100;
                    thunks_.emplace(thunk, Api::ApplicationDataMethod);
                    thunk_names_.emplace(thunk, "IApplicationData#" + std::to_string(method));
                    application_data_methods_.emplace(thunk, method);
                    cpu.memory().write64(vtable + method * 8, thunk);
                }
            }
            if (cpu.reg(Rdx) != 0) {
                cpu.memory().write64(cpu.reg(Rdx), application_data_proxy_);
            }
            cpu.set_reg(Rax, 0);
        } else {
            cpu.set_reg(Rax, 0x80004001U);
        }
        finish_call();
        break;
    }
    case Api::ApplicationDataMethod: {
        const auto index = application_data_methods_.at(cpu.rip());
        if (index == 0) {
            if (cpu.reg(R8) != 0) {
                cpu.memory().write64(cpu.reg(R8), cpu.reg(Rcx));
            }
            cpu.set_reg(Rax, 0);
        } else if (index == 1) {
            cpu.set_reg(Rax, 2);
        } else if (index == 2) {
            cpu.set_reg(Rax, 1);
        } else if (index == 6) {
            if (cpu.reg(Rdx) != 0) {
                cpu.memory().write32(cpu.reg(Rdx), 0);
            }
            cpu.set_reg(Rax, 0);
        } else if (index == 10) {
            if (application_data_container_proxy_ == 0) {
                const auto vtable = allocate(12 * 8);
                application_data_container_proxy_ = allocate(8);
                cpu.memory().write64(application_data_container_proxy_, vtable);
                for (std::uint32_t method = 0; method < 12; ++method) {
                    const auto thunk = next_thunk_;
                    next_thunk_ += 0x100;
                    thunks_.emplace(thunk, Api::ApplicationDataContainerMethod);
                    thunk_names_.emplace(thunk,
                                         "IApplicationDataContainer#" + std::to_string(method));
                    application_data_container_methods_.emplace(thunk, method);
                    cpu.memory().write64(vtable + method * 8, thunk);
                }
            }
            if (cpu.reg(Rdx) != 0) {
                cpu.memory().write64(cpu.reg(Rdx), application_data_container_proxy_);
            }
            cpu.set_reg(Rax, 0);
        } else {
            if (cpu.reg(Rdx) != 0) {
                cpu.memory().write64(cpu.reg(Rdx), 0);
            }
            cpu.set_reg(Rax, 0x80004001U);
        }
        finish_call();
        break;
    }
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
    case Api::MsvcpLocale: {
        ensure_locale();
        if (thunk_name.find("?_Init@locale") != std::string::npos && argument(0) != 0) {
            cpu.memory().write32(locale_proxy_ + 8, cpu.memory().read32(locale_proxy_ + 8) + 1);
        }
        cpu.set_reg(Rax, locale_proxy_);
        finish_call(thunk_name.find("?_Init@locale") != std::string::npos ? 1 : 0);
        break;
    }
    case Api::MsvcpFacetFactory: {
        std::uint32_t category = 0;
        if (thunk_name.find("collate@") != std::string::npos) {
            category = 1;
        } else if (thunk_name.find("ctype@") != std::string::npos ||
                   thunk_name.find("codecvt@") != std::string::npos) {
            category = 2;
        } else if (thunk_name.find("money") != std::string::npos) {
            category = 4;
        } else if (thunk_name.find("num") != std::string::npos) {
            category = 8;
        } else if (thunk_name.find("time_") != std::string::npos) {
            category = 0x10;
        } else if (thunk_name.find("messages@") != std::string::npos) {
            category = 0x20;
        }
        if (argument(0) != 0) {
            auto &facet = locale_facets_[cpu.rip()];
            if (facet == 0) {
                if (locale_facet_vtable_ == 0) {
                    throw Error("locale facet factory called before locale initialization");
                }
                facet = allocate(0x10);
                cpu.memory().write64(facet, locale_facet_vtable_);
                cpu.memory().write32(facet + 8, 1);
            }
            cpu.memory().write64(argument(0), facet);
        }
        cpu.set_reg(Rax, category);
        finish_call(2);
        break;
    }
    case Api::LocaleFacetMethod: {
        const auto method = locale_facet_methods_.at(cpu.rip());
        const auto object = argument(0);
        if (object == 0) {
            throw Error("locale facet method received a null object");
        }
        if (method == 1) {
            cpu.memory().write32(object + 8, cpu.memory().read32(object + 8) + 1);
            cpu.set_reg(Rax, 0);
        } else if (method == 2) {
            const auto references = cpu.memory().read32(object + 8);
            cpu.memory().write32(object + 8, references > 1 ? references - 1 : 1);
            cpu.set_reg(Rax, 0);
        } else if (method == 3) {
            // codecvt<char, char, mbstate_t>::do_always_noconv: narrow file streams copy bytes
            // directly and therefore never pass guest buffers through native conversion code.
            cpu.set_reg(Rax, 1);
        } else {
            cpu.set_reg(Rax, object);
        }
        finish_call(1);
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
        if (auto exception = detail::take_callback_exception(); exception != nullptr) {
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

} // namespace winemu
