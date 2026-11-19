#include "winemu/runtime.hpp"

#include "callbacks.hpp"
#include "winemu/detail/runtime_layout.hpp"

#include <sstream>

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <d3d9.h>
#include <mmsystem.h>
#include <windows.h>
// DirectSound declarations use the multimedia wave-format types above.
#include <dsound.h>

namespace winemu {

Runtime::Runtime(std::ostream &output) : output_(output) {
    thunks_.emplace(detail::return_thunk64, Api::ProcessReturn);
    std::wostringstream namespace_stream;
    namespace_stream << L"Local\\CPUEmu." << ::GetCurrentProcessId() << L'.' << std::hex
                     << reinterpret_cast<std::uintptr_t>(this) << L'.';
    synchronization_namespace_ = namespace_stream.str();
}

Runtime::~Runtime() {
    for (const auto &[guest_object, object] : direct_sound_buffer_objects_) {
        static_cast<void>(guest_object);
        auto *host = static_cast<IDirectSoundBuffer *>(object.host);
        if (object.host_region1 != nullptr) {
            host->Unlock(object.host_region1, object.region1_size, object.host_region2,
                         object.region2_size);
        }
        for (std::uint32_t reference = 0; reference < object.references; ++reference) {
            host->Release();
        }
    }
    for (const auto &[guest_object, object] : direct_sound_objects_) {
        static_cast<void>(guest_object);
        auto *host = static_cast<IDirectSound *>(object.host);
        for (std::uint32_t reference = 0; reference < object.references; ++reference) {
            host->Release();
        }
    }
    for (const auto &[guest_object, object] : direct3d_surface9_objects_) {
        static_cast<void>(guest_object);
        auto *host = static_cast<IDirect3DSurface9 *>(object.host);
        for (std::uint32_t reference = 0; reference < object.references; ++reference) {
            host->Release();
        }
    }
    for (const auto &[guest_object, object] : direct3d_buffer9_objects_) {
        static_cast<void>(guest_object);
        auto *host = static_cast<IDirect3DResource9 *>(object.host);
        if (object.host_locked != nullptr) {
            if (object.index) {
                static_cast<IDirect3DIndexBuffer9 *>(object.host)->Unlock();
            } else {
                static_cast<IDirect3DVertexBuffer9 *>(object.host)->Unlock();
            }
        }
        for (std::uint32_t reference = 0; reference < object.references; ++reference) {
            host->Release();
        }
    }
    for (const auto &[guest_object, object] : direct3d_texture9_objects_) {
        static_cast<void>(guest_object);
        auto *host = static_cast<IDirect3DTexture9 *>(object.host);
        if (object.host_locked != nullptr) {
            host->UnlockRect(object.locked_level);
        }
        for (std::uint32_t reference = 0; reference < object.references; ++reference) {
            host->Release();
        }
    }
    for (const auto &[guest_object, object] : direct3d_device9_objects_) {
        static_cast<void>(guest_object);
        auto *host = static_cast<IDirect3DDevice9 *>(object.host);
        for (std::uint32_t reference = 0; reference < object.references; ++reference) {
            host->Release();
        }
    }
    for (const auto &[guest_object, object] : direct3d9_ex_objects_) {
        static_cast<void>(guest_object);
        auto *host = static_cast<IDirect3D9Ex *>(object.host);
        for (std::uint32_t reference = 0; reference < object.references; ++reference) {
            host->Release();
        }
    }
    for (const auto &timer : window_timers_) {
        ::KillTimer(reinterpret_cast<HWND>(static_cast<std::uintptr_t>(timer.window)), timer.id);
    }
    for (const auto &[window, callback] : dialog_callbacks_) {
        if (!callback.modal) {
            ::DestroyWindow(reinterpret_cast<HWND>(static_cast<std::uintptr_t>(window)));
        }
    }
    for (const auto &[token, record] : window_subclasses_) {
        ::RemoveWindowSubclass(reinterpret_cast<HWND>(static_cast<std::uintptr_t>(record.window)),
                               detail::window_subclass_bridge, token);
    }
    for (const auto &[guest_handle, host_handle] : find_handles_) {
        static_cast<void>(guest_handle);
        ::FindClose(static_cast<HANDLE>(host_handle));
    }
    for (const auto &[guest_handle, host_handle] : file_handles_) {
        static_cast<void>(guest_handle);
        ::CloseHandle(static_cast<HANDLE>(host_handle));
    }
    for (const auto &[guest_handle, host_handle] : mapping_handles_) {
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
