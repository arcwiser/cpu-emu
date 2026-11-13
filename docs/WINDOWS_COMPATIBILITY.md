# Windows compatibility

CPUEmu interprets x86 PE32 and x86-64 PE32+ applications and presents a deliberately bounded Win32
compatibility layer. It is not Wine, a virtual machine, or a transparent native-call forwarder.
Every guest pointer is untrusted, and APIs that retain pointers or invoke callbacks need an
explicit adapter.

## Compatibility levels

- **Guest-owned adapter:** CPUEmu implements the operation and keeps all returned memory and
  callback state in guest space. This is the preferred level.
- **Marshalled host adapter:** CPUEmu validates guest input, converts it to host data, calls a
  Windows API, and copies safe results back to guest memory.
- **Direct native call:** Only simple calls that do not retain pointers, return host-owned
  pointers, or invoke callbacks may use the generic native bridge.
- **Safe refusal:** Process, thread, exception, and callback-bearing APIs return failure when a
  correct guest-side implementation does not exist. This prevents guest code addresses from
  being executed as native host callbacks.

## Implemented guest-owned facilities

| Area | APIs and behavior | Current limits |
| --- | --- | --- |
| Process lifecycle | `ExitProcess`, CRT exit functions, `TerminateProcess` | Single guest process |
| Import binding | `LoadLibraryA`/`GetProcAddress` under the guest's own activation context | Side-by-Side assemblies such as Common-Controls v6 bind as Windows binds them for the guest; contexts are created from the guest image's embedded manifest |
| Window classes | `RegisterClassExW`, `CreateWindowExW` under the guest's resource module | Class menu names resolve against the guest image, so class menus load; child controls are real host windows |
| Subclassing | `SetWindowSubclass`, `GetWindowSubclass`, `RemoveWindowSubclass`, `DefSubclassProc`, and comctl32 v6 ordinals 410–413 | Common Controls retains only a host bridge and opaque token; six-argument guest procedures re-enter the interpreter, use the normal message-pointer marshaler, and can continue the native chain |
| File dialogs | `GetOpenFileNameA/W`, `GetSaveFileNameA/W`, `CommDlgExtendedError` | Synchronous strings, filters, buffers, selection offsets, and errors are marshaled; guest hook/template pointers are deliberately omitted rather than executed natively |
| MIME detection | `FindMimeFromData` | URL, proposed type, and bounded sniffing bytes are copied to host storage; the host result is copied into guest-owned memory and native allocation is released before returning |
| Read-only file mappings | `CreateFileMappingA/W`, `MapViewOfFile`, `UnmapViewOfFile`, `CloseHandle` | Mapping handles are opaque guest tokens; mapped bytes are copied into read-only guest memory and remain valid after the token closes; unmapping removes guest access. Writable, named, security-attribute, and larger-than-256-MiB mappings fail closed |
| Edit memory handles | `SendMessageA/W` with `EM_SETHANDLE` and `EM_GETHANDLE` | Guest `LocalAlloc` addresses are copied to and from the native Edit control; copy-back grows undersized guest buffers; no guest address is passed to Windows as an `HLOCAL`; retained guest ownership is cleared when the window is destroyed |
| Guest fail-fast | `abort`, `_invoke_watson`, `_invalid_parameter_noinfo`, `_invalid_parameter_noinfo_noreturn`, `_wassert`, `_assert` | Noreturn paths terminate only the guest with the Windows fast-fail status; never forwarded natively |
| Console output | `GetStdHandle`, `WriteFile` | Focused on standard output/error handles |
| Errors and diagnostics | `GetLastError`, `SetLastError`, `OutputDebugStringA` | Per-runtime error state |
| Virtual memory | `VirtualAlloc`, `VirtualFree`, `VirtualProtect`, `VirtualQuery` | No placeholders, write-watch, or full mapped-section semantics |
| Heap and local/global memory | `malloc`, `free`, `HeapAlloc`, `HeapFree`, `LocalAlloc`, `GlobalAlloc`, related size/lock calls | Guest heap rather than a host heap handle model |
| TLS/FLS | `TlsAlloc`, `TlsFree`, `TlsGetValue`, `TlsSetValue`, FLS equivalents | No guest thread scheduler; FLS cleanup callbacks are not invoked |
| Startup and environment | command line, environment blocks, CRT on-exit tables, static TLS initialization | Main thread only |
| Module queries | module handles, module filename, selected `GetProcAddress`, delay imports | Loaded main image and emulated thunks; no general guest DLL loader |
| Basic audio | `Beep`, `MessageBeep`, synchronous `PlaySoundA/W`, `sndPlaySoundA/W` | No retained guest buffers, asynchronous playback, loops, resource audio, or streaming APIs |
| Game-loop timing | `GetTickCount`, `GetTickCount64`, performance counter/frequency, `Sleep`, `timeGetTime`, timer period begin/end | Host-clock backed; no virtual or deterministic clock |
| PE32 startup | stack-based stdcall arguments, low thunk/module handles, startup info, process/thread IDs, security cookie helpers, heap, TLS, and critical-section adapters | Adapter-by-adapter ABI audit remains in progress |

## Marshalled Windows adapters

CPUEmu currently has explicit adapters for `CommandLineToArgvW`, `GetSecurityInfo`, read-only file
mapping, `FindMimeFromData`, `SHGetKnownFolderPath`, resource loading, cursor/icon/image loading,
accelerator loading, window-class registration, window creation, and selected WinRT
protection-policy calls.
The window bridge re-enters interpreted code through `Runtime::invoke_guest`; it never casts a
guest window procedure to a native function pointer.

## Safely refused operations

The following families currently report failure or remain inert because native forwarding would
escape emulation or retain unsafe guest state:

- `CreateThread`, `_beginthreadex`, remote-thread creation, work items, waits, and thread-pool
  callback objects.
- `CreateProcess*` and child-process creation.
- Vectored exception handlers and native language exception callbacks.
- General COM objects whose interface pointers and vtables have not been proxied into guest
  memory.
- Dialog, font-enumeration, printing, and other APIs that retain or synchronously invoke callbacks
  without a dedicated adapter.
- WaveOut, DirectSound, WASAPI, Media Foundation, and other streaming or callback-driven audio
  interfaces.

## Adding an API

1. Determine every pointer's ownership and lifetime, including nested pointers.
2. Validate all guest ranges through `Memory` before reading or writing them.
3. Marshal host results into guest-owned allocations; never return a host pointer.
4. Route guest callbacks through `Runtime::invoke_guest` and account for re-entry.
5. Add success, failure, invalid-pointer, output-pointer, and lifetime tests where the fixture
   system permits them.

## MSVC runtime ownership

CPUEmu constructs guest-owned argument vectors for `__p___argc`, `__p___argv`, and
`__p___wargv`. MSVC file and input-stream adapters keep native `FILE` pointers in runtime-owned
maps; guest stream objects contain only guest addresses and opaque handles. Stream initialization,
seek, position queries, read, swap, `basic_ios` state, and destruction are marshaled by the runtime.
Position queries construct the complete 24-byte MSVC `streampos` value, and seeks honor its legacy
`fpos_t` offset field. Short input reads update the associated guest `basic_ios` EOF/fail state.
MSVC PPL chores re-enter the interpreter cooperatively; they are never handed to the native thread
pool. Unimplemented C++ object methods must fail closed rather than invoking host STL code against
a guest object layout.

OLEAUT error-info outputs and WinRT `PropertyValue` scalars are guest-owned. Native COM interface
pointers must never be written to a guest output parameter.

See `src/runtime/dispatch.cpp` and `src/runtime/imports.cpp` for the authoritative dispatch and
resolver implementations. This document is
an overview, not a promise that every flag and structure variant of a named API is complete.
