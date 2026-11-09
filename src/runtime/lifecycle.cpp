#include "winemu/runtime.hpp"

#include "winemu/detail/runtime_layout.hpp"

#include <sstream>

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>

namespace winemu {

Runtime::Runtime(std::ostream &output) : output_(output) {
    thunks_.emplace(detail::return_thunk64, Api::ProcessReturn);
    std::wostringstream namespace_stream;
    namespace_stream << L"Local\\CPUEmu." << ::GetCurrentProcessId() << L'.' << std::hex
                     << reinterpret_cast<std::uintptr_t>(this) << L'.';
    synchronization_namespace_ = namespace_stream.str();
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
    for (const auto &[guest_handle, host_handle] : sync_handles_) {
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

} // namespace winemu
