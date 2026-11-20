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
| Process lifecycle | `ExitProcess`, CRT exit functions, `TerminateProcess`, `IsDebuggerPresent` | Single guest process; host debugger state is intentionally not exposed as guest debugger state |
| Import binding | `LoadLibraryA`/`GetProcAddress` under the guest's own activation context | Side-by-Side assemblies such as Common-Controls v6 bind as Windows binds them for the guest; contexts are created from the guest image's embedded manifest |
| Window classes | `RegisterClassW`, `RegisterClassExW`, `CreateWindowExW`, `ShowWindow`, `UpdateWindow`, and `GetForegroundWindow` under the guest's resource module | Class menu names resolve against the guest image, so class menus load; child controls are real host windows; display/update calls check for faults from synchronous guest window-procedure re-entry; foreground queries expose only windows registered to the current runtime |
| Modal dialogs | `DialogBoxParamW`, `EndDialog` | Resource templates resolve from the guest image; Windows retains only a host bridge while guest dialog procedures, initialization values, and nested-dialog state remain in the runtime |
| Modeless dialogs | `CreateDialogParamW`, `DestroyWindow` | Resource templates and guest callback ownership use the dialog bridge on PE32 and PE32+; callback faults destroy modeless windows rather than applying modal `EndDialog` semantics |
| Window enumeration | `EnumWindows`, `EnumChildWindows` | Synchronous callbacks re-enter guest code; top-level enumeration is filtered to windows owned by CPUEmu, and nested enumeration state remains runtime-owned |
| Window timers | `SetTimer`, `KillTimer` | Message-only timers use the native queue; retained procedures are stored as guest addresses and invoked only through the interpreter, then removed on kill, registered guest-window destruction, or runtime teardown |
| Font enumeration | `EnumFontsW`, `EnumFontFamiliesW`, `EnumFontFamiliesExW` | Font and metric structures are copied into bounded guest scratch memory for synchronous callback re-entry; nested enumerations use separate frames |
| GDI line enumeration | `LineDDA` | Point callbacks synchronously re-enter interpreted code with exact signed coordinates and guest LPARAM; nested enumerations retain separate callback records |
| Subclassing | `SetWindowSubclass`, `GetWindowSubclass`, `RemoveWindowSubclass`, `DefSubclassProc`, and comctl32 v6 ordinals 410–413 | Common Controls retains only a host bridge and opaque token; six-argument guest procedures re-enter the interpreter, use the normal message-pointer marshaler, and can continue the native chain |
| File dialogs | `GetOpenFileNameA/W`, `GetSaveFileNameA/W`, `CommDlgExtendedError` | Synchronous strings, filters, buffers, selection offsets, and errors are marshaled; guest hook/template pointers are deliberately omitted rather than executed natively |
| MIME detection | `FindMimeFromData` | URL, proposed type, and bounded sniffing bytes are copied to host storage; the host result is copied into guest-owned memory and native allocation is released before returning |
| Read-only file mappings | `CreateFileMappingA/W`, `MapViewOfFile`, `UnmapViewOfFile`, `CloseHandle` | Mapping handles are opaque guest tokens; mapped bytes are copied into read-only guest memory and remain valid after the token closes; unmapping removes guest access and returns its arena span for safe reuse. Writable, named, security-attribute, and larger-than-256-MiB mappings fail closed |
| Edit memory handles | `SendMessageA/W` with `EM_SETHANDLE` and `EM_GETHANDLE` | Guest `LocalAlloc` addresses are copied to and from the native Edit control; copy-back grows undersized guest buffers; no guest address is passed to Windows as an `HLOCAL`; retained guest ownership is cleared when the window is destroyed |
| Guest fail-fast | `abort`, `_invoke_watson`, `_invalid_parameter_noinfo`, `_invalid_parameter_noinfo_noreturn`, `_wassert`, `_assert` | Noreturn paths terminate only the guest with the Windows fast-fail status; never forwarded natively |
| Console output | `GetStdHandle`, `WriteFile` | Focused on standard output/error handles |
| Errors and diagnostics | `GetLastError`, `SetLastError`, `OutputDebugStringA` | Per-runtime error state |
| Virtual memory | `VirtualAlloc`, `VirtualFree`, `VirtualProtect`, `VirtualQuery` | No placeholders, write-watch, or full mapped-section semantics |
| Pointer probes | `IsBadReadPtr`, `IsBadWritePtr` | Checks guest mapping commitment and permissions across the complete requested range; deprecated host probing is never used |
| Heap and local/global memory | `malloc`, `free`, `realloc`, `HeapAlloc`, `HeapFree`, `HeapReAlloc`, `LocalAlloc`, `GlobalAlloc`, related size/lock calls | Checked 16-byte-aligned allocations come from bounded guest arenas; freed spans become inaccessible, reject double-free, and can be reused without exposing host pointers; heap handles remain simplified guest tokens |
| Guest threads | `CreateThread`, `_beginthreadex`, `_beginthread`, independent interpreted CPU/stack contexts, guest IDs and opaque handles, guest-local `SetThreadPriority`/`GetThreadPriority`, and single-thread-handle waits | Cooperative round-robin scheduling; suspended creation, per-thread TEB/static PE TLS, termination, priority-weighted scheduling, and thread-pool work remain |
| TLS/FLS | `TlsAlloc`, `TlsFree`, `TlsGetValue`, `TlsSetValue`, FLS equivalents | Dynamically allocated values are isolated per interpreted thread; static PE TLS still uses the main-thread block and FLS cleanup callbacks are not invoked |
| Startup and environment | command line, environment blocks, CRT on-exit tables, static TLS initialization | Main thread only |
| Locale discovery | `GetUserDefaultLCID`, `IsValidLocale`, and bounded `GetLocaleInfoA/W` size/output queries | Host user locale is exposed; callback enumeration and locale mutation are not adapted |
| Module queries | module handles, module filename, selected `GetProcAddress`, delay imports | Loaded main image and emulated thunks; no general guest DLL loader |
| Game input discovery | `DirectInput8Create`, ANSI/Unicode `IDirectInput8::EnumDevices`, `XInputGetState`, `XInputSetState`, `XInputGetCapabilities`, `XInputEnable` | DirectInput synchronously enumerates guest-owned keyboard and mouse descriptors through interpreted callbacks; XInput currently reports no connected controller without forwarding guest buffers or host controller state; DirectInput device state remains inert |
| Basic audio | `Beep`, `MessageBeep`, synchronous `PlaySoundA/W`, `sndPlaySoundA/W` | No retained guest buffers, asynchronous playback, loops, resource audio, or streaming APIs |
| DirectSound | `DirectSoundCreate`, base `IDirectSound` lifetime/configuration, sound-buffer creation, capabilities, position/format/state queries, staged lock/unlock, playback controls, and lifetime | Interfaces and lock storage are guest-owned proxies; formats and audio bytes are bounded and copied, so native COM and lock pointers never cross the boundary. Persistent audio worker threads and notifications are not implemented yet |
| Game-loop timing | `GetTickCount`, `GetTickCount64`, performance counter/frequency, scheduler-aware `Sleep` and `WaitForSingleObject`/`Ex`, waitable-timer create/set/cancel/wait, `timeGetTime`, timer period begin/end | Host-clock backed; sleeps and single-handle waits suspend only the calling guest context; no virtual or deterministic clock, wait-all/any, or APC delivery |
| Direct3D 9/9Ex | `Direct3DCreate9Ex`, adapter enumeration, display modes, format checks, capabilities, monitor/LUID queries, base `CreateDevice`, device texture/surface and vertex/index-buffer creation/binding, resource metadata/lifetime methods, buffer and texture lock/unlock, cross-pool `UpdateTexture`, scene begin/end, clear, `DrawPrimitive`, `Present`, and scalar render-state setters; `D3DXCreateTextureFromFileW` and `D3DXCreateTextureFromFileInMemoryEx` | Guest-owned parent/device/resource COM objects marshal PE32/PE32+ structures and retain their parent mappings; surface-level objects retain guest texture/device identity; buffer and texture locks use checked guest staging allocations and row-bounded copies, so native object and lock pointers never cross into guest memory; successful presentation touches the host queue with `PM_NOREMOVE` so slow interpreted frames do not trigger window ghosting while every message remains guest-owned; indexed/UP draws, shaders, surface locks, and explicit swap-chain methods still require adapters |
| PE32 startup | stack-based stdcall arguments, low thunk/module handles, startup info, process/thread IDs, security cookie helpers, heap, TLS, and critical-section adapters | Adapter-by-adapter ABI audit remains in progress |

## Marshalled Windows adapters

CPUEmu currently has explicit adapters for `CommandLineToArgvW`, `GetSecurityInfo`, read-only file
mapping, `FindMimeFromData`, `SHGetKnownFolderPath`, `SHGetSpecialFolderPathA/W`, resource loading, cursor/icon/image loading,
accelerator loading, window-class registration, window creation, modal resource dialogs, and
selected WinRT protection-policy calls. Window and dialog bridges re-enter interpreted code
through `Runtime::invoke_guest`; they never cast a guest procedure to a native function pointer.

## Safely refused operations

The following families currently report failure or remain inert because native forwarding would
escape emulation or retain unsafe guest state:

- Remote-thread creation, work items, thread-pool callback objects, and multiple-object waits.
- `CreateProcess*` and child-process creation.
- Vectored exception handlers and native language exception callbacks.
- General COM objects whose interface pointers and vtables have not been proxied into guest
  memory.
- Indirect dialogs, ANSI font enumeration, printing, and other APIs that retain or synchronously
  invoke callbacks without a dedicated adapter.
- WaveOut, DirectSound notifications/worker threads, WASAPI, Media Foundation, and other
  callback-driven audio
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
pool. `CreateThread` and CRT thread entry points receive independent interpreted register and stack
state under a round-robin scheduler. Single-object waits, including joins on guest thread handles,
suspend only their calling guest context and are polled by the scheduler. Dynamic TLS/FLS values
are stored per scheduled context. This is concurrency, not host-parallel execution. Unimplemented
C++ object methods must fail closed rather than invoking host STL code against a guest object
layout.

OLEAUT error-info outputs and WinRT `PropertyValue` scalars are guest-owned. Native COM interface
pointers must never be written to a guest output parameter.

See `src/runtime/dispatch.cpp` and `src/runtime/imports.cpp` for the authoritative dispatch and
resolver implementations. This document is
an overview, not a promise that every flag and structure variant of a named API is complete.
