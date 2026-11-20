# Devlog

A running record of what the coding agent changed while building CPUEmu, newest first. The
emulator's own activity is visible through its logging system (see `README.md` → Logging);
this file is the companion log of development decisions.

## 2026-11-20 — Keyboard state adapters

- Added pointer-free `GetAsyncKeyState` and `GetKeyState` forwarding plus a marshaled
  `GetKeyboardState` adapter. The latter obtains the table in host storage and copies it only after
  walking the complete 256-byte guest output range for committed write permission.
- Added success and null-output regressions to the Paint synchronization fixture; no guest pointer
  is passed to native User32. This exposes host keyboard state but does not by itself verify that
  Undertale consumes title-screen input.

## 2026-11-20 — Guest-safe DirectInput enumeration and XInput discovery

- Added ANSI and Unicode `IDirectInput8::EnumDevices` adapters that marshal keyboard and mouse
  descriptors into guest-owned memory and synchronously invoke guest callbacks through the
  interpreter. Separate root proxies preserve each interface's string encoding.
- Added fail-closed XInput state, vibration, capability, and enable adapters, including SDK ordinal
  imports. With no controller backend, queries report `ERROR_DEVICE_NOT_CONNECTED`; null outputs
  report `ERROR_BAD_ARGUMENTS`, and failed queries do not alter guest output buffers.
- Extended the synchronization fixture with Unicode enumeration, ANSI early-stop, nested callback
  context preservation, disconnected XInput, and invalid-output regressions.
- Undertale now completes DirectInput enumeration and four XInput controller probes instead of
  stopping on `XInputGetState`; an 80,000,000 aggregate-instruction probe reaches only its limit.
  Keyboard gameplay input and physical controller state remain unverified.

## 2026-11-20 — Per-thread dynamic TLS and guest joins

- Isolated `TlsGetValue`/`TlsSetValue` and their FLS equivalents per interpreted execution context
  while retaining process-wide slot allocation and freeing values from every context on release.
- Added scheduler-aware waits on opaque guest thread handles, allowing one guest context to join a
  worker without blocking the native interpreter thread.
- Extended the Paint synchronization regression to create and join a worker, verify its initially
  empty TLS slot, set a worker-only value, return code 7, and preserve the main thread's value.
  Per-thread TEBs, static PE TLS blocks, and FLS cleanup callbacks remain unimplemented.

## 2026-11-20 — Scheduler-aware guest Sleep

- Changed `Sleep` from a native host-thread block into a timed suspension of only the calling guest
  execution context. `Sleep(0)` remains an immediate cooperative yield point.
- Strengthened the generated thread regression: the worker signals that it entered a 50 ms sleep,
  the main guest must change shared state during that interval, and the worker validates the change
  after waking before returning code 7. The fixture also moved code and shared data into disjoint
  ranges, removing accidental self-modifying overlap from the earlier layout.

## 2026-11-19 — Guest permission-aware pointer probes

- Added `IsBadReadPtr` and `IsBadWritePtr` adapters that walk the complete guest range and validate
  committed read/write permissions without ever forwarding a guest address to native Windows.
- Added readable, nonwritable, cross-mapping, null, and zero-length regressions in the Paint
  synchronization fixture.
- Undertale's OpenAL worker cleared its pointer probe and continued DirectSound playback/position
  activity until the 100,000,000 aggregate instruction limit (83,190,673 on the main context plus
  worker execution), with no new unsupported API/instruction or memory fault. Audible sound is not
  yet verified.

## 2026-11-19 — x87 FPATAN stack semantics

- Implemented `D9 F3` `FPATAN` as `atan2(ST(1), ST(0))` with the architectural single stack pop.
- Added first- and second-quadrant results, TOP transition, and stack-underflow regressions.
- Undertale's OpenAL path passed `FPATAN`, performed additional worker/TLS initialization, and
  reached `IsBadWritePtr` at 66,508,527 instructions. Audible output remains unverified.

## 2026-11-19 — Complete x87 signed-m32 integer arithmetic family

- Implemented all `DA /0`–`/7` memory forms: `FIADD`, `FIMUL`, `FICOM`, `FICOMP`, `FISUB`,
  `FISUBR`, `FIDIV`, and `FIDIVR` with signed 32-bit integer operands.
- Added exact arithmetic, comparison-condition, and pop/TOP regressions. Undertale's OpenAL worker
  passed the observed `FIDIV m32int`, continued polling the DirectSound buffer, and exposed the
  general missing `FPATAN` form next. Audible output remains unverified.

## 2026-11-19 — First independent cooperative guest threads

- Added independent interpreted CPU and stack contexts for `CreateThread`, `_beginthreadex`, and
  `_beginthread`, scheduled in bounded round-robin quanta without executing guest entry points as
  native callbacks.
- Added opaque guest thread handles and stable guest thread IDs. A dedicated thread-return thunk
  completes only the worker; returning from a worker no longer terminates the guest process.
- Added a generated regression whose main thread spins until a separately scheduled worker writes
  shared guest memory, then verifies the assigned thread ID.
- Made `WaitForSingleObject`/`Ex` suspend only the calling guest context. The regression now has a
  worker wait indefinitely while the main thread continues and signals its event. Added guest-local
  thread priorities without changing CPUEmu's native host thread priority.
- A recorded Undertale probe reached OpenAL worker creation at 66,382,450 instructions, accepted
  its priority request, and executed repeated DirectSound buffer-position calls on the worker. It
  then exposed the general missing x87 `DA /6` `FIDIV m32int` form at `0x5ee70a`; audible output is
  still unverified and not claimed.

## 2026-11-18 — MOVBE load/store matrix

- Implemented unprefixed `0F 38 F0/F1` `MOVBE` loads and stores for 16-, 32-, and 64-bit operands,
  sharing the opcode bytes with—but remaining correctly distinct from—the mandatory-`F2` `CRC32`
  family.
- Added PE32 and PE32+ regressions covering loads, stores, upper-bit preservation/zero-extension,
  REX destinations, a qword read at a mapping boundary, unchanged flags, absolute addressing, and
  rejection of the architecturally invalid register-source form.
- `CPUID` continues to hide MOVBE because implementing an instruction does not by itself authorize
  advertising its feature bit to general guest software.

## 2026-11-18 — Initial SSE4.2 CRC32 and missing carry controls

- Implemented the mandatory-`F2` `CRC32` encodings for byte, word, dword, and qword sources using
  the reflected CRC32C polynomial. Register and checked-memory forms work in PE32 and PE32+, REX
  destinations zero-extend the 32-bit result, and architectural flags remain unchanged.
- Added regressions for high-byte registers, 16/32-bit memory, a qword at the end of a mapped page,
  extended registers, PE32 absolute addressing, and the standard `123456789` CRC32C vector.
- The new flag-preservation regression exposed that `CLC` and `STC` were documented but absent.
  Implemented both plus `CMC`, with carry-only semantics. SSE4.2 remains hidden from `CPUID`
  because packed-string comparison instructions are still missing.

## 2026-11-18 — LineDDA points re-enter guest code safely

- Added a dedicated `LineDDA` adapter so GDI receives a host bridge rather than a guest procedure
  address. Signed point coordinates and the guest LPARAM are passed through the interpreter using
  the correct three-argument callback ABI.
- Callback records are stacked for nested `LineDDA` calls, callback exceptions propagate after GDI
  returns, and further host points are ignored if the guest exits from inside its callback.
- Paint verifies exact negative/positive point sequences, a nested line enumeration with an
  independent LPARAM, and rejection of a non-executable callback address.

## 2026-11-18 — Unicode font enumeration callbacks are marshalled

- Added dedicated `EnumFontsW`, `EnumFontFamiliesW`, and `EnumFontFamiliesExW` adapters. GDI sees
  only a host bridge; `LOGFONTW`/`ENUMLOGFONTEXW` and the matching metric layout are copied into
  bounded guest scratch frames before the interpreted callback runs.
- Extended callbacks distinguish TrueType `NEWTEXTMETRICEXW` from the smaller non-TrueType
  `NEWTEXTMETRICW`, avoiding reads beyond host-owned structures. Nested enumeration receives a
  separate scratch frame, and callback exceptions return through the normal runtime boundary.
- Paint now verifies nested standard/extended enumeration, family enumeration, readable font and
  metric output, invalid callback rejection, and a null extended request. ANSI callback variants
  remain safely refused until their structure conversion is implemented.

## 2026-11-18 — Modeless resource dialogs retain safe guest callbacks

- Added a dedicated `CreateDialogParamW` adapter. Resource templates resolve from the guest image,
  while the native dialog stores only CPUEmu's bridge and the interpreted procedure remains in a
  runtime-owned record for the dialog's full lifetime.
- Added explicit `DestroyWindow` dispatch so both PE32 and PE32+ guests close modeless dialogs with
  callback-fault propagation and retained window/timer/edit ownership cleanup.
- Dialog records now distinguish modal from modeless ownership. Callback faults use `EndDialog`
  for modal dialogs and `DestroyWindow` for modeless dialogs; runtime reset and destruction also
  destroy any surviving modeless windows before guest memory is replaced.
- Extended Paint coverage with initialization parameters, later message re-entry, explicit
  destruction, invalid callback and missing-resource failures, plus runtime reuse with an
  intentionally retained modeless dialog.

## 2026-11-18 — Window timer callbacks stay inside the interpreter

- Added dedicated `SetTimer` and `KillTimer` adapters. Native USER32 retains only CPUEmu's bridge;
  guest `TIMERPROC` addresses stay in runtime-owned records and receive the four documented
  arguments through `Runtime::invoke_guest`.
- Timer records are replaced by window/ID, removed after successful `KillTimer`, and cancelled
  during runtime reset or destruction. Invalid non-executable guest callback addresses fail before
  reaching USER32.
- Extended the Paint message-loop regression to combine subclass and timer callback re-entry,
  message-only timers, invalid callbacks, repeated kill behavior, and a retained windowless timer.
  A runtime-reuse test verifies the retained timer is torn down before the next guest starts.

## 2026-11-14 — Guest modal dialog callbacks

- Added dedicated `DialogBoxParamW` and `EndDialog` adapters. Windows receives a host bridge, while
  guest procedures and initialization parameters remain in CPUEmu and re-enter the interpreter.
  A stack preserves the correct procedure and initialization value across nested modal dialogs.
- Extended the Paint fixture with a real dialog resource. Its synchronization test covers nested
  callbacks, initialized controls, result propagation, a null callback, and a missing resource.
- Probed x64 WinAPI Minesweeper revision `dda5200` at commit `50a606f`. Game → Custom displayed and
  initialized the real preferences dialog; Cancel returned to the board, and the guest later
  exited cleanly with code 0. Full gameplay, audio, persistence, and x86 remain unverified.

## 2026-11-14 — Large Notepad Edit buffers grow safely

- Replaced the contents of a disposable Notepad document with 2,048 Unicode lines totaling 52,138
  characters. Save and reopen returned every character exactly.
- At commit `8192754`, the hidden multiline Edit regression now expands beyond its original guest
  allocation. `EM_GETHANDLE` must return a new larger guest-owned buffer containing the complete
  native text, covering the reallocation path used by larger documents.

## 2026-11-14 — Classic Notepad UTF-8 round-trip

- Loaded a disposable UTF-8 file without a BOM containing accented Latin, Greek, CJK, and emoji
  text. The CPUEmu-owned Edit control returned the complete Unicode text.
- Replaced and saved the content through Notepad, producing 72 bytes of UTF-8 without a BOM for a
  61-character document. Reopening returned all 61 characters exactly. The probe and trace files
  were deleted afterward.
- UTF-16, legacy code pages, encoding changes through Save As, and sustained editing remain
  unverified.

## 2026-11-14 — Classic Notepad Save As reaches a new file

- Exercised File → Save As through CPUEmu's real marshalled common dialog using disposable source
  and target paths. The shell filename field and confirmation completed, and the target contained
  the full 5,010-character loaded `CMakeLists.txt`.
- Removed the source, target, and one intermediate copy after verification. This probe establishes
  Save As for unchanged loaded content only; edited-content Save As, alternate encodings, and
  sustained editing remain unverified.

## 2026-11-13 — Classic Notepad displays loaded file text

- Added dedicated `EM_SETHANDLE`/`EM_GETHANDLE` marshaling at commit `837f6a5`. Guest
  `LocalAlloc` addresses are copied into native Edit text rather than forwarded as host `HLOCAL`
  values; later native edits copy back to guest-owned storage. Invalid handles fail closed, and
  retained ownership is removed on `WM_NCDESTROY`.
- Added a multiline Edit regression covering guest-to-native text, native-to-guest copy-back,
  invalid guest handles, and window teardown.
- Re-probed classic Notepad with `CMakeLists.txt`. Its CPUEmu-owned Edit control returned length
  5,010 through `WM_GETTEXT`, and the complete text began with
  `cmake_minimum_required(VERSION 3.24)`.
- Re-probed Save with a disposable existing file. After replacing the Edit text and marking it
  modified, Notepad's own File → Save command persisted the exact 47-character CRLF payload. The
  temporary file was removed afterward. Save As, encoding variants, and sustained editing remain
  unverified.

## 2026-11-13 — Classic Notepad completes the read-only file-open pipeline

- Added field-by-field `GetFileInformationByHandle` marshaling for CPUEmu's opaque file tokens at
  commit `d040900`; raw host handles never enter guest memory.
- Replaced direct file-mapping forwarding with guest-owned mapping tokens and copied read-only
  views at commit `e0e4f0e`. Views remain valid after their mapping token closes, explicit unmap
  removes guest access, and runtime reset/destruction closes retained host handles. Named mappings,
  guest security attributes, writable access, and views larger than 256 MiB fail closed.
- Added memory and Paint regressions for exact-base teardown, invalid tokens, mapping output,
  handle/view lifetime, double close/unmap, write rejection, host-namespace isolation, and size
  limits.
- On Windows build `10.0.26200.0`, classic Notepad `10.0.26100.8457` opened the requested
  `CMakeLists.txt` through file metadata, MIME detection, mapping, edit-control messages, successful
  unmap, and title update, then remained in its message loop. Visual text correctness, saving,
  persistence, and sustained editing were not verified.

## 2026-11-13 — MIME results stay in guest memory

- Added a dedicated `FindMimeFromData` adapter. Guest URL, proposed-type, and bounded sniffing
  buffers are copied into host-owned storage; URLMON's result is copied into CPUEmu's guest heap,
  and the host allocation is released before control returns to interpreted code. Non-null guest
  binding contexts are refused because CPUEmu cannot safely expose them to URLMON.
- Added `mimetype.exe`, a generated machine-code regression covering successful MIME detection,
  readable guest output, native classification failure with a null output, and rejection of a
  null output parameter.
- At commit `e3c3f39`, Classic Notepad file selection advances past the previous host-pointer
  fault. It opens the selected path and completes MIME detection. File contents still do not load:
  `GetFileInformationByHandle` receives opaque guest token `0x400`, returns
  `ERROR_INVALID_HANDLE`, and Notepad displays that error before returning to its message loop.

## 2026-11-10 — Classic Notepad reaches window and menu rendering

- Adapted the comctl32 v6 subclass family. `SetWindowSubclass` is exported as ordinal 410,
  `GetWindowSubclass` as 411, `RemoveWindowSubclass` as 412, and `DefSubclassProc` as 413; Notepad
  imports them by ordinal.
  Native forwarding let comctl32 invoke a guest subclass procedure as host code from its message
  dispatch. Common Controls now retains a host bridge and opaque token; the six-argument guest
  procedure re-enters the interpreter, uses the shared message marshaler, and can chain through
  `DefSubclassProc`. The Paint message-loop fixture verifies ID/reference data, lookup, removal,
  and callback re-entry.
- `WM_DRAWITEM` was not in the window-procedure marshaling table, so its LPARAM, a host
  `DRAWITEMSTRUCT` pointer, reached guest code directly and faulted. It is now copied into guest
  scratch space with copy-back. The 32-bit layout differs, so that case is refused rather than
  silently corrupted.
- Window classes registered with CPUEmu's own instance handle, so Windows resolved a class menu
  name against CPUEmu and produced no menu. Registration and `CreateWindowExW` now both use the
  guest's resource module.
- Classic `System32\notepad.exe` now runs with a real window, a menu bar rendering File, Edit,
  Format, View, and Help, and its edit, banner, button, and tooltip child windows. Verified
  against the `cpuemu.exe`-owned window. A follow-up probe typed `CPUEmu input test` into the real
  Edit control, observed the dirty title, and opened a populated File menu. Open/save, persistence,
  and sustained editing remain unverified. The modern packaged Notepad still blocks in WinRT/XAML
  startup and produces no window.
- Replaced the file-dialog cancellation stub with field-by-field `OPENFILENAMEA/W` marshaling.
  Host dialogs receive host-owned string and output buffers, selected paths and offsets copy back
  into checked guest memory, and `CommDlgExtendedError` is retained per runtime. Guest hooks and
  templates are stripped instead of being executed natively. Classic Notepad's Open picker was
  displayed and cancelled successfully; selecting/loading a file is not yet claimed.

## 2026-11-10 — Guest activation contexts and stream buffer layout

- Guest imports now bind under an activation context created from the guest image. Without it a
  manifest requesting Common-Controls v6 silently bound to the older system `comctl32.dll`, whose
  export table lacks ordinals 381 and 345 that Notepad imports; those imports then reported
  unsupported. `CreateActCtxW` failure is logged rather than silently ignored.
- Corrected `basic_streambuf` construction to the real MSVC layout. The adapter pointed its six
  `_IG*`/`_IP*` indirection members at offsets `+0x78`-`+0xa8`, which are `basic_filebuf`'s own
  members, so buffer state overwrote them and the guest observed a write position holding a
  vtable pointer. The indirections now point at the direct `_Gfirst`/`_Pfirst`/`_Gnext`/`_Pnext`/
  `_Gcount`/`_Pcount` members, matching `basic_streambuf::_Init()` in the installed MSVC headers.
- Feature-state change subscriptions no longer hand the guest callback to Windows, which invoked
  it from a thread-pool timer thread as native code. The subscription is inert and guest-owned.
- Added `callee_saved_windows` diagnostics so a guest fail-fast also reports the state of the
  non-volatile registers that still point at the object being processed.
- Classic `System32\notepad.exe` now passes the Common-Controls import that previously stopped it
  at 53,726 instructions and reaches real window creation: it creates its edit, button, and
  tooltip windows and runs layout (`MoveWindow`, `WM_WINDOWPOSCHANGING`). It still does not stay
  running; the next blocker is a host-side callback fault during layout, so no rendered window is
  claimed.

## 2026-11-10 — Guest fail-fast isolation

- Routed the noreturn UCRT fail-fast family (`_invoke_watson`, `_invalid_parameter_noinfo`,
  `_invalid_parameter_noinfo_noreturn`, `_wassert`, `_assert`) to a guest-owned adapter. These
  imports previously fell through to native forwarding, so a guest fail-fast raised
  `STATUS_STACK_BUFFER_OVERRUN` inside the emulator and killed the host process with 0xC0000409.
- The adapter terminates only the guest, with the same status Windows raises for `__fastfail`,
  and logs the triggering routine plus the guest return address.
- Added the `failfast.exe` fixture and the `test_fail_fast_isolation` regression, which asserts
  the guest exits with 0xC0000409 and that the sentinel after the noreturn call is never reached.
- Packaged Notepad 11.2607.14.0 now runs to 245,610 instructions and terminates its own state
  deserializer instead of crashing the emulator. The deserializer computes a value, rejects it
  with `cmp rcx, 0x1f; ja`, and invokes `_invoke_watson` from `0x14006ec1c` (return address
  `0x14006ec22`), so the real blocker is a serialized field the guest bounds-checks to 0-31.

## 2026-11-09 — Notepad probe reaches one million instructions

- Prevented native MSVC PPL from retaining and executing guest `_Threadpool_chore` callbacks.
  Chores now run cooperatively through interpreter re-entry; a generated fixture verifies the
  callback modifies guest memory.
- Added guest-safe OLEAUT `GetErrorInfo` ordinal handling so native COM pointers cannot be written
  into guest memory, plus an ordinal-import regression.
- Expanded `Windows.Foundation.PropertyValue` from a Boolean singleton to per-object scalar
  values with type reporting and typed getters. A generated fixture covers `CreateUInt32` and
  `GetUInt32`.
- Added guest-owned MSVC `basic_ios` state/mask adapters and `basic_istream::tellg`, extended the
  stream fixture, associated stream objects with their `basic_ios` state, propagated EOF/fail on
  short reads, constructed the complete MSVC `streampos` ABI value, and made zero-length bulk
  memory reads/writes no-ops.
- Added `LFENCE`, `MFENCE`, and `SFENCE`; the sequential interpreter already provides their memory
  ordering, and a compact machine-code regression covers all three encodings.
- Modern packaged Notepad 11.2607.14.0 reached the 1,000,000-instruction probe limit without a
  host crash, unsupported import, or unsupported instruction. It has not created a window, so no
  launch or input support is claimed.

## 2026-11-09 — Guest-safe MSVC input streams

- Added guest-owned `argc`/`argv`/wide-`argv` tables so MSVC startup code never receives host
  process pointers.
- Added adapters for the MSVC character stream-buffer initializer, input-stream construction,
  swapping, seeking, reading, partial reading, and destruction. Host `FILE` pointers remain in
  runtime-owned maps and are never written into guest C++ objects.
- Made the file-to-stream-buffer constructor handoff explicit runtime state instead of depending
  on a stale volatile argument register. Added the `stream.exe` regression for binary seek/read.
- This removes the native-host `basic_istream::seekg` ABI mismatch seen in the modern Notepad
  startup probe. It does not claim that packaged Notepad creates a window; a fresh probe is still
  required to identify and record the next blocker.

## 2026-11-09 — Implementation-level modularization

- Extracted real CPU state/stack, operand decoding, and flag implementations from the instruction
  execution state machine; `cpu_execute.cpp` now owns only execution-specific helpers and
  `Cpu::step`.
- Split guest memory into mapping ownership, checked access, and virtual-memory state/query
  modules without changing the public `Memory` interface.
- Split runtime import resolution, lifecycle, process execution, callback re-entry, and shared
  string/layout support from the Win32/CRT/COM dispatch state machine.
- Split regressions by CPU, memory, and runtime responsibility, and separated deterministic PE
  serialization from the guest-program fixture builders.
- Kept the remaining single-function CPU execution, API dispatch, and PE loading state machines
  intact because further separation would require control-flow redesign rather than moving
  existing definitions.

## 2026-11-09 — Generic WinRT activation factories

- Fixed the adapter contract for `RoGetActivationFactory` calls that use the `IActivationFactory`
  IID on a class without a dedicated adapter. The generic fallback returned `S_OK` while writing
  its result to `R9`, but `ActivateInstance` returns the instance through the out parameter in
  `RDX`, so the guest received success plus a null object and faulted dereferencing it.
- Unknown classes now receive a factory-shaped proxy whose `ActivateInstance` writes a
  guest-owned, `IInspectable`-conformant instance into `RDX`. Factories and instances are cached
  per WinRT class name so distinct classes cannot alias one another. Methods beyond
  `IInspectable` fail closed with `E_NOTIMPL` instead of fabricating a result.
- Added the `winrt.exe` fixture, which activates an unknown class and verifies the instance is
  non-null, and the `test_winrt_activation` regression.
- Modern packaged Notepad probe (11.2607.14.0, `--limit 200000 -v`): advanced from 73,885 to
  74,024 interpreted instructions. Startup now creates and uses the application instance and its
  resource lookup (vtable slot 8) is the first unsupported method; because it fails closed, the
  guest raises a WinRT language exception that the emulator cannot yet unwind. Packaged Notepad
  still does not reach window creation, and no editor window or typing is claimed.

## 2026-11-08 — Catalog-backed atlas and verified UI captures

- Replaced the decorative instruction texture with a generated 200-cell catalog dashboard. Every
  treemap cell now maps to a named instruction, grouped mnemonic, encoding subset, or capability;
  the source CSV and PowerShell generator are committed for review.
- Fixed message-loop callback re-entry by retaining API arguments before native `GetMessage` or
  `PeekMessage` can synchronously clobber volatile registers, and added an end-to-end regression.
- Captured genuine CPUEmu-owned Paint and About Windows UI. Corrected current Windows 11 Notepad to
  blocked because its packaged launcher handoff does not produce a reproducible editor window.

## 2026-11-08 — Coverage credibility and impact mapping

- Made the instruction atlas explicitly self-describing: its cells are decorative family-level
  texture, not opcode counts, encoding units, or percentages.
- Connected instruction-family gaps to affected workload classes, required implementation work,
  verification targets, and non-CPU dependencies so contributors can see why a family matters.

## 2026-11-08 — Documentation and contribution standards

- Consolidated compatibility, roadmap, and development-history material under `docs/`, added a
  repository structure guide, and rebuilt the README around an honest game-support status board.
- Added a dark green instruction-family atlas and expanded the coverage document into an auditable
  mnemonic/family inventory with explicit partial and planned areas instead of inflated counts.
- Strengthened agent, contributor, and pull-request requirements for exact testing, AI disclosure,
  guest/host ownership review, legal hygiene, and precise compatibility language.

## 2026-11-08 — Undertale input and display discovery

- Added guest-memory `IDirectInput8` and `IDirectInputDevice8` vtables so x86 guest code never
  receives or executes a native COM pointer. The initial backend safely exposes no devices and
  provides zeroed state/event polling for future keyboard and mouse activation.
- Added guest-safe ANSI/Unicode display-mode enumeration and optional DWM multimedia scheduling.
- Undertale now completes optional input discovery, reads the desktop modes, and reaches
  `Direct3DCreate9Ex` after 15,130,126 interpreted instructions.

## 2026-11-18 — Direct3D 9Ex adapter discovery

- Added guest-owned `IDirect3D9Ex` objects backed by host Direct3D solely for adapter, mode,
  format, capability, monitor, and LUID discovery. Pointer-free results are range-checked and
  copied into guest memory; native COM pointers never cross the boundary.
- Added reference tracking, interface-query validation, runtime teardown, and a guest regression
  covering creation, discovery, QueryInterface lifetime, invalid output, and fail-closed device
  creation. Rendering devices remain deliberately unsupported pending a guest-owned device proxy.
- A recorded Undertale probe completed adapter count, device caps, adapter identifier, and monitor
  queries, then stopped at unsupported opcode `0x8C` after 15,149,324 instructions. No visible
  rendering or device creation is claimed.
- Implemented register and memory forms of `MOV r/m16, Sreg`, including Windows user-mode selector
  state, width behavior, and rejection of reserved segment encodings. Undertale executes the six
  consecutive selector stores and reaches opcode `0x8F` after 15,149,331 instructions.
- Added the `POP r/m` opcode family with mode-correct widths, reserved-group validation, and the
  architectural rule that an ESP-based memory destination is calculated after the stack advances.
- The follow-up Undertale probe executes the saved-flags `POP` and reaches
  `KERNEL32!IsDebuggerPresent` after 15,149,348 instructions.
- Added an isolated guest-process implementation of `IsDebuggerPresent`; a debugger attached to
  the CPUEmu host is not misreported as a debugger attached inside the emulated process. Undertale
  advances to `UnhandledExceptionFilter` after 15,149,358 instructions.
- Traced that apparent exception boundary to a cross-bitness ABI overwrite: the 64-bit host's
  `D3DADAPTER_IDENTIFIER9` has four bytes of trailing alignment padding beyond the 1,100 bytes of
  defined fields, which had overwritten the adjacent PE32 GS cookie. The adapter now copies only
  the defined field extent and a canary regression guards the boundary.
- Undertale now passes the cookie check, attempts `IDirect3D9Ex::CreateDevice` three times, and
  exits through its normal graphics-initialization failure path with `-1` after 15,201,662
  instructions. Device creation is the current first blocker; guest SEH was not invoked.
- Added a guest-owned 119-slot `IDirect3DDevice9` proxy with PE32/PE32+ presentation-parameter
  marshaling, host COM lifetime tracking, capability/creation queries, scene/clear operations, and
  common pointer-free render-state setters. Pointer-retaining resource methods remain refused.
- Undertale creates the host-backed device on its first attempt, queries its caps, and advances to
  `SHLD r/m32, r32, CL` after 15,206,998 instructions.
- Added `SHLD` and `SHRD` immediate/`CL` forms across 16/32/64-bit register and memory operands,
  including zero-count state preservation and defined carry/overflow behavior. Undertale advances
  through device render/sampler-state initialization to x87 `FADDP` after 15,211,857 instructions.
- Added the x87 arithmetic-and-pop register family (`FADDP`, `FMULP`, both subtract orders, and
  both divide orders) with explicit stack-depth checks and result/pop regressions. Undertale
  advances through its transform calculations and viewport setup to packed `CVTPS2PD` after
  15,222,460 instructions.

## 2026-11-08 — Undertale PE32 window creation

- Added PE32-safe `WNDCLASSEXW`, `CREATESTRUCTW`, `WINDOWPOS`, rectangle, resource, and window-text
  marshaling without exposing host-owned pointers to the guest.
- Added x86 callback-stack re-entry so native window messages execute the interpreted GameMaker
  procedure, plus controlled `DefWindowProc`, `SendMessage`, cursor, metric, and rectangle adapters.
- Undertale now creates a native `YYGameMakerYY` window, handles `WM_NCCREATE` and `WM_CREATE`, sets
  its title and icons, and advances to `DirectInput8Create` after 15,129,726 instructions.

## 2026-11-08 — Undertale game-data and offline Steam startup

- Corrected guest file-type reporting so the CRT accepts mapped disk handles instead of rejecting
  `data.win` with `ERROR_INVALID_HANDLE`; this removed the runner's fallback file-picker path.
- Added guest-safe full/current-path, file-attribute, seek/size/end-of-file, environment expansion,
  module unloading, and offline Steam restart/initialization behavior.
- Added `SCASB/W/D/Q` repeat and direction semantics, corrected address-width handling in existing
  string moves/stores, and added the SSE2 `F3 0F 7E` `MOVQ` load form with regressions.
- Undertale now parses `data.win`, probes `options.ini` and config/save paths, takes the offline
  Steam fallback, and reaches the 15,000,000-instruction limit without an unsupported operation.

## 2026-11-08 — Guest page-indexed memory lookup

- Replaced the per-access linear scan of guest regions in `Memory::region_for` with a verified
  page-index cache. Regions never overlap, so a cached region is accepted only when it covers the
  full access, otherwise the code falls back to a scan and refreshes the entry; mutations that
  reorder or resize regions (`remove_mappings`, `protect`) clear the cache.
- This removes the dominant cost of the growing guest heap, where every heap allocation added a
  region and every byte access rescanned them all. The Undertale probe now executes 6,000,000
  instructions in ~6.6 seconds instead of ~317 seconds (about 48x) with an identical final CPU
  state.
- Added a regression covering two same-page fragments and cache invalidation after `protect`.
- With the faster core the probe exposed `KERNEL32.dll!ExpandEnvironmentStringsW`, which is now
  implemented and no longer blocks Undertale startup.

## 2026-11-08 — Undertale runner and message-loop bring-up

- Corrected x86 stdcall argument handling for module filenames and generic return adapters, then
  added guest-safe file enumeration, file reading/writing, environment variables, time conversion,
  timezone, common-controls, and GDI+ startup adapters.
- Added `LDMXCSR`/`STMXCSR`, x87 memory arithmetic, sine/cosine and constant loads, `FNSTSW AX`,
  `LAHF`, and `SAHF`, with focused machine-code regressions.
- Added isolated 32/64-bit `MSG` marshaling for peek/get/translate/dispatch and guest-owned
  `PostQuitMessage` state. Host-thread messages are not exposed before a guest window exists.
- Undertale now discovers its files, initializes GDI+, enters the message-pump path, and executes
  2,957,604 instructions before cleanly exiting with code 1 after the safe file-dialog cancellation
  path. This replaces the previous 507,053-instruction early exit and leaves no unsupported opcode
  or import at the current probe point.

## 2026-11-08 — Undertale CRT and x87 bring-up

- Corrected the x86 TEB, static TLS pointer array, process-environment addresses, guest data-import
  pointer widths, and low-address heap so the Visual C++ runtime no longer reports R6016.
- Added guest-safe window-station, code-page, locale, character conversion, console, pseudo-handle,
  interlocked, heap-size/reallocation, processor-feature, and controlled termination adapters.
- Added x86 `XCHG` register opcodes, `WAIT`, `PUSHF`/`POPF`, SSE scalar float/double conversion,
  `MOVQ` XMM stores, and an initial x87 stack with control-word, load, store, multiply, integer
  conversion, clear/init, and pop support.
- Undertale now executes 507,053 instructions without an unsupported instruction or import. It
  exits through `CorExitProcess` with code 255 before creating a window; tracing that early-return
  decision is the next compatibility milestone.

## 2026-11-08 — PE32 execution and Undertale startup

### Added

- Added PE32 loader support with x86 machine validation, 32-bit optional headers, four-byte import
  thunks, ordinal handling, and 32-bit TLS directories/callback arrays.
- Added explicit x86 CPU mode with 32-bit addressing, legacy `INC`/`DEC`, four-byte stack/call/return
  behavior, `FS` segment state, and absolute `moffs` moves.
- Added non-identity guest-memory backing so fixed PE32 images can occupy guest addresses already
  used by the 64-bit host process without exposing host pointers.
- Added low 32-bit import/module thunks, stack-based stdcall argument access and cleanup, safe module
  lookup/loading, dynamic procedure lookup, startup/time/process helpers, heap/TLS fixes, pointer
  encoding helpers, and single-threaded critical-section adapters.

### Verified

- Added a generated PE32 fixture and focused regressions for loading, absolute addressing,
  four-byte stack behavior, legacy opcodes, `FS`, and `moffs` stores.
- The installed Undertale PE32 image now loads at `0x00400000`, resolves 313 imports, and advances
  from immediate loader rejection to 4,010 interpreted instructions. The next blocker is
  `USER32!GetProcessWindowStation`.

## 2026-11-08 — SSE4.1 packed-integer foundation

### Added

- Added `PTEST`, `PACKUSDW`, `PMINSB`, `PMINSD`, `PMINUW`, `PMINUD`, `PMAXSB`, `PMAXSD`,
  `PMAXUW`, `PMAXUD`, and `PMULLD` with register/memory operands, packed signedness, saturation,
  low-product wrapping, and architectural flag behavior.
- Kept SSE4.1 hidden from `CPUID` until broader family coverage prevents software from selecting
  unsupported operations.

### Verified

- Added machine-code regressions for signed and unsigned comparisons, saturation boundaries,
  multiplication overflow, and both `PTEST` flag results.

## 2026-11-08 — Undertale target groundwork

### Added

- Added SSE3 duplicate loads, `LDDQU`, horizontal packed float/double add/subtract, and alternating
  packed add/subtract operations used by multimedia-oriented native runtimes.
- Added explicit guest-safe adapters for performance counters, tick counts, sleeping, and WinMM
  millisecond/timer-period functions.
- Added an Undertale bring-up document covering executable validation, relative assets, Direct3D
  9, audio, Steamworks, persistence, probe commands, and the first-failure workflow.

### Verified

- Added machine-code regressions for packed horizontal arithmetic, duplicate loads, and alternating
  add/subtract behavior.

## 2026-11-08 — SSSE3, audio, and application compatibility

### Added

- Added `PHADDW`, `PHADDD`, `PHADDSW`, `PHSUBW`, `PHSUBD`, `PHSUBSW`, `PMADDUBSW`,
  `PSIGNB/W/D`, `PMULHRSW`, and `PALIGNR` with packed-lane, saturation, immediate, register, and
  memory semantics.
- Added safe synchronous adapters for `Beep`, `MessageBeep`, `PlaySoundA/W`, and
  `sndPlaySoundA/W`. Retained-pointer audio modes are rejected until lifetime-aware guest objects
  exist.
- Added checked UTF-16 string reads to `Memory` and a compatibility matrix covering the
  test fixtures, Paint, Windows 11 Notepad, and the current Discord/Chromium probe.

### Verified

- Added machine-code tests for horizontal SSSE3 arithmetic and byte alignment, plus a checked
  guest wide-string regression.

## 2026-11-08 — Bit-count instructions and compatibility documentation

### Added

- Implemented width-correct `POPCNT`, `LZCNT`, and `TZCNT`, including their defined flag behavior,
  zero-input edge cases, register/memory decoding, and optional-feature `CPUID` reporting.
- Added Windows compatibility documentation describing ownership rules, adapter categories,
  currently supported facilities, safe refusals, and the checklist for new API bridges.
- Added an instruction-coverage document that records feature-advertising policy and expansion
  priorities without using a misleading raw mnemonic count.

### Verified

- Added compact machine-code regressions for nonzero and zero-input bit counting.

## 2026-11-08 — Packed byte shuffle support

### Added

- Implemented the SSSE3 `PSHUFB`, `PABSB`, `PABSW`, and `PABSD` XMM instructions, including
  register and memory operands, high-bit zeroing for shuffle controls, and REX-extended registers.
- Added compact machine-code regressions covering shuffle selection, selector low-nibble wrapping,
  zeroed lanes, packed absolute-value edge cases, memory operands, and extended registers.

## 2026-10-31 — Compatibility audit and Discord probe

### Improved

- Corrected legacy high-byte register decoding (`AH`, `CH`, `DH`, `BH`) when a byte
  instruction has no REX prefix.
- Added PE stack-reserve handling plus main-thread TLS template, index, and callback
  initialization before the executable entry point.
- Added portable signed and unsigned 128-by-64 division, variable-count shifts and rotates,
  immediate `ADC`/`SBB`, register-indexed bit operations, `BSF`/`BSR`, packed-unpack
  operations, and more scalar SSE2 double operations.
- Hardened PE and external-memory validation and removed a leftover hard-coded memory watch.
- Refused native forwarding for process/thread creation and retained-callback APIs that
  would otherwise execute guest addresses directly on the host.
- Added tracked guest virtual-memory reservation, commit, decommit, release, protection,
  and query handling instead of blindly forwarding those operations.
- Replaced host TLS/FLS forwarding with guest-owned slots, preventing Windows from retaining
  guest cleanup callbacks. CPUID now hides instruction families the interpreter cannot execute.
- Corrected sign extension for 64-bit accumulator immediates and added 32-bit address-size
  decoding, `CWD`/`CDQ`/`CQO`, `PSHUFD`, `PSHUFLW`/`PSHUFHW`, packed compares, unpacking,
  mask extraction, packed-double arithmetic, and related SIMD operations used by V8.
- Added guest-memory adapters for `InitOnceExecuteOnce`, environment blocks,
  `CommandLineToArgvW`, `GetSecurityInfo`, and read-only `MapViewOfFile` views so host pointers
  and guest callback addresses do not cross the emulation boundary.

### Verified

- The regression suite and emulated Paint GDI self-test pass. A focused test now covers packed
  dword shuffling and `CQO` sign extension.
- The installed 235 MB x64 Discord/Chromium executable now loads with its requested 8 MiB
  stack and TLS data. Iterative probing advanced startup from 1,106 to 2,658,513 interpreted
  instructions. It now passes early V8 initialization, file mapping, security-descriptor, and
  command-line paths before reaching a later V8 invariant trap. Complete mapped-section semantics,
  threads, DLL loading, exceptions, and multi-process scheduling remain architectural blockers
  before Discord can show a usable UI.

## 2026-10-31 — Logging pass

Goal: make the emulator explain itself while it runs, and keep a written trail of
development.

### Added

- **Leveled logger** (`include/winemu/log.hpp`, `src/core/log.cpp`). Every log line is
  `[HH:MM:SS.mmm] [level] component: message`. Levels are `error` < `warn` < `info` < `api` <
  `trace`. Logs go to stderr so the guest program keeps stdout to itself; `--log-file`
  mirrors every line into a file. Expensive message building is gated behind
  `log::enabled(level)` so disabled levels cost nothing.
- **New CLI** in `cpuemu`: `-v`/`--verbose` (api level), `-vv` (trace), `--log-level <name>`,
  `--log-file <path>`, `--help`. Flags may appear in any order. `--limit 0` now means
  "no instruction limit", and the default limit was raised to 100,000,000 so Notepad runs
  out of the box.
- **API call tracing**: `Runtime::dispatch` logs every guest thunk call at api level with
  the four register arguments and the returned value. Exit calls are reported at info level
  with the guest's exit code. This replaces the old scattered
  `GetEnvironmentVariableA("WINEMU_TRACE_API")` checks.
- **Window message tracing**: callbacks into guest window procedures are named
  (`WM_NCCREATE`, `WM_PAINT`, ...) at trace level with parameters and results; important
  lifecycle messages (create, destroy, close, command, size, menu, timer) are surfaced at
  api level. `RegisterClassExW` and `CreateWindowExW` log the class name and resulting
  window handle.
- **Fault diagnostics**: `Cpu` now keeps a 64-entry ring buffer of executed instruction
  addresses (`Cpu::recent_instructions()`). When the guest stops on an error, `Runtime::run`
  logs all 16 registers plus the rip history at error level before propagating the
  exception.
- **PE and memory tracing**: image load summary (base, entry, size) and resolved-import
  count at info level; per-section and per-import details, and every guest memory mapping
  with permissions, at trace level.
- **Guest debug output**: `OutputDebugStringA` now goes through the logger
  (`guest: OutputDebugStringA: ...`) instead of mixing into the program's stdout.
- **Window-procedure fault guard**: if a guest window procedure throws, the bridge logs the
  message it failed on before falling back to `DefWindowProcW`.
- **Devlog** (this file) so development decisions stay visible.

### Verified

- `ctest` passes: memory, CPU loop, logging, and the three guest fixture apps.
- `hello.exe` logs a clean end-to-end story: PE load → `GetStdHandle` → `WriteFile`
  (stdout intact) → `ExitProcess` → exit code 0.
- `notepad.exe` ran 15 seconds under `-v --log-file`, producing ~1000 log lines covering
  315 resolved imports, class registration (`class='Notepad'`), window creation,
  `WM_NCCREATE`/`WM_CREATE` delivery, and the live `GetMessageW` message loop.
- `--limit 500` on Notepad produces the register dump + rip history fault report.

## 2026-11-18 — Packed cross-precision conversions

- Added register and checked-memory forms of `CVTPS2PD` and `CVTPD2PS`, including the required
  upper-lane clearing behavior of the legacy `CVTPD2PS` destination.
- Added a compact lane round-trip regression covering both conversions and destination clearing.
- The Undertale probe advances from `CVTPS2PD` after 15,222,460 instructions to `ANDPD` after
  15,222,461 instructions. This is CPU progress only; the existing window is still not visibly
  rendering.

## 2026-11-18 — Packed SIMD logical family

- Completed the legacy SSE/SSE2 `ANDPS`/`ANDPD`, `ANDNPS`/`ANDNPD`, `ORPS`/`ORPD`, and
  `XORPS`/`XORPD` family for register and checked-memory sources.
- Added bit-pattern regressions covering every PS/PD spelling and both source forms, including
  the destination-complement ordering required by `ANDN`.
- Undertale now passes the packed transform block and advances 39 instructions, stopping at x87
  `FCHS` after 15,222,500 instructions.

## 2026-11-18 — x87 unary sign operations

- Added `FCHS` and `FABS` with explicit non-empty-stack validation and focused value/underflow
  regressions.
- Undertale advances another 171 instructions through mixed x87/SSE transform work and now stops
  at `FXCH ST(1)` after 15,222,671 instructions.

## 2026-11-18 — x87 stack exchange

- Added bounded `FXCH ST(i)` behavior with value-order and unavailable-register regressions.
- Undertale passes `FXCH ST(1)` and reaches the register form of x87 `FMUL` after 15,222,673
  instructions.

## 2026-11-18 — x87 double arithmetic matrix

- Completed non-comparison `DC` arithmetic for register destinations and checked double-memory
  operands: add, multiply, subtract/reverse, and divide/reverse.
- Added value regressions for all twelve operation/source combinations, including operand ordering
  for reverse subtraction and division.
- Undertale advances through the x87 vector expression and reaches `FSQRT` after 15,222,702
  instructions.

## 2026-11-18 — x87 square root

- Added `FSQRT` with positive, signed-zero, masked-invalid-result, and stack-underflow regressions.
  CPUEmu still does not model complete x87 exception/status delivery.
- Undertale advances 909 instructions through additional transform and runtime math, reaching
  `FUCOM ST(1)` after 15,223,611 instructions.

## 2026-11-18 — x87 comparison and status state

- Added tracked x87 TOP and status state, `FUCOM`/`FUCOMP` ordered and unordered condition results,
  register `FST`/`FSTP`, status-aware `FNSTSW AX`, and state-correct `FNCLEX`/`FNINIT` behavior.
- Added regressions for greater/less/equal/unordered C0/C2/C3 results, TOP transitions, comparison
  popping, and register-store lifetime.
- Undertale follows the real comparison branch and advances to register-form `FSUB ST(0), ST(2)`
  after 15,223,654 instructions.

## 2026-11-18 — x87 D8 register arithmetic

- Completed the `D8` register-destination arithmetic matrix for ST(0), plus register and
  single-memory `FCOM`/`FCOMP`, using the shared status-word comparison path.
- Added value regressions for all six arithmetic directions and comparison regressions for result
  flags and pop/TOP behavior.
- Undertale clears the current CPU instruction blockers, advances 708 instructions, and reaches
  its first `D3DXCreateTextureFromFileInMemoryEx` call after 15,224,362 instructions.

## 2026-11-18 — guest-owned Direct3D textures

- Added a guest-owned 22-slot `IDirect3DTexture9` proxy with parent-device retention,
  `IUnknown`/resource/base-texture lifetime and metadata methods, level descriptions, dirty-rect
  forwarding, device `CreateTexture`, and texture bind/unbind support.
- Added `D3DXCreateTextureFromFileInMemoryEx` using a bounded copy of untrusted guest image data,
  PE32-safe image-info/palette output marshaling, and the host system D3DX decoder. Native texture
  and lock pointers never enter guest memory; surface and lock methods still fail closed.
- Expanded the Paint synchronization fixture to cover texture creation, metadata, parent lifetime,
  `QueryInterface`, binding, invalid output, and teardown. Undertale successfully decodes its first
  embedded texture and advances to `D3DXCreateTextureFromFileW` after 15,224,537 instructions.

## 2026-11-18 — D3DX file textures

- Added `D3DXCreateTextureFromFileW` with checked guest path/output handling, native system-D3DX
  forwarding, and the same guest-owned texture lifetime path as in-memory decoding.
- The observed splash-file call returns the native D3DX invalid-data failure (`0x88760b59`), which
  Undertale handles before successfully decoding the file contents through the in-memory adapter.
- Undertale advances 37,251 instructions to two `CreateVertexBuffer` calls; those still fail closed,
  and later renderer state is null at 15,261,788 instructions.

## 2026-11-18 — guest-owned Direct3D buffers

- Added guest-owned `IDirect3DVertexBuffer9` and `IDirect3DIndexBuffer9` proxies with checked
  creation limits, parent-device retention, COM/resource lifetime methods, descriptions, and
  device stream/index binding.
- Buffer `Lock` returns a guest allocation and `Unlock` copies its bounded range into the retained
  native lock. Native pointers never enter guest state, overlapping locks and invalid ranges fail
  closed, and teardown unlocks live resources before releasing them.
- Expanded the Paint synchronization fixture across creation, lock/upload/unlock, metadata,
  parent lifetime, `QueryInterface`, binding, invalid output, and teardown. Undertale passes both
  observed vertex-buffer creations and reaches x87 `FCOMIP` after 15,252,462 instructions.

## 2026-11-18 — x87 integer-flag comparisons

- Added all register encodings of `FUCOMI`, `FCOMI`, `FUCOMIP`, and `FCOMIP`, including ordered
  and unordered `ZF`/`PF`/`CF` results, architectural clearing of `OF`/`SF`/`AF`, stack-depth
  validation, and pop behavior.
- Focused regressions cover greater, less, equal, NaN/unordered, all four opcode families, and the
  physical TOP change after a popping comparison. Undertale passes its `FCOMIP ST(0), ST(1)` and
  reaches `CreateWaitableTimerW` after 15,252,701 instructions.

## 2026-11-18 — SSE square root and x87 runtime rounding

- Added register and memory forms of `SQRTPS`, `SQRTPD`, `SQRTSS`, and `SQRTSD`, preserving the
  untouched scalar lanes and covering packed results and negative masked-invalid results.
- Added control-word-aware `FRNDINT` for all four rounding modes and completed `DC` register and
  double-memory `FCOM`/`FCOMP`, including status and pop behavior.
- Undertale passes the renderer's `SQRTSD`, the CRT `FRNDINT`, and its subsequent double compare;
  the next non-CPU work exposed the guest heap's one-mapping-per-allocation exhaustion behavior.

## 2026-11-18 — waitable timers, window display, and reusable heap arenas

- Added guest-token-backed waitable timers with checked due-time input and native wait behavior;
  guest APC routines and security attributes fail closed. Added `ShowWindow`/`UpdateWindow`
  forwarding with synchronous guest callback-fault propagation.
- Replaced the one-64-KiB-mapping-per-allocation heap with 16-byte-aligned guest arenas, real
  free/reallocate ownership, inaccessible released spans, best-fit reuse, and double-free
  rejection. Free spans never merge across distinct host backing allocations.
- Restoring permissions now coalesces compatible adjacent memory regions, so reused ranges can
  safely cross a former protection boundary without crossing host backing. Regressions cover
  heap content preservation/reuse and cross-boundary access after protection restoration.
- Undertale passes its former stack-collision point and advances to `SHGetSpecialFolderPathA`
  after 66,370,113 instructions. The offline Steam messages still are not the active blocker.

## 2026-11-18 — legacy special-folder paths

- Added bounded `SHGetSpecialFolderPathA/W` adapters that keep the native `MAX_PATH` buffers on
  the host and copy only terminated results into validated guest output ranges.
- The synchronization fixture covers a real application-data result and null-output rejection.
  Undertale discovers its save/config folder and reaches `DirectSoundCreate` after 66,394,276
  instructions, making DirectSound the first observed audio blocker.

## 2026-11-18 — guest-owned DirectSound discovery

- Added name and ordinal-1 import routing for `DirectSoundCreate` plus an 11-slot guest-owned
  `IDirectSound` proxy. Capability, cooperative-level, speaker-configuration, initialization,
  compaction, `QueryInterface`, and reference-lifetime calls marshal through retained host state;
  no native interface pointer enters guest memory.
- Expanded the synchronization fixture with creation, capability, invalid-output, cooperative
  level, interface-lifetime, and teardown checks. Sound-buffer creation still fails closed until
  it has guest-owned buffer and lock staging adapters.
- Undertale passes DirectSound discovery and advances to `GetForegroundWindow` after 66,392,948
  instructions. The offline Steam failure remains a handled startup path, not this blocker.

## 2026-11-18 — isolated foreground-window queries

- Added `GetForegroundWindow` routing that returns a native HWND only when it belongs to a window
  procedure registered with the current runtime. An unrelated host desktop window is reported as
  null instead of leaking another process's handle into guest state.
- The synchronization fixture covers the permitted guest-window/null result after a foreground
  request; Windows may deny focus transfer to a headless test process, so the regression accepts
  that documented native outcome while rejecting every unrelated HWND.
- Undertale passes its former foreground query and reaches the 100,000,000-instruction limit in a
  sustained loop. OpenAL reports context/source initialization errors, and no visible rendered
  frame or working audio is claimed yet.

## 2026-11-18 — guest-owned DirectSound buffers

- Added a 21-slot guest-owned `IDirectSoundBuffer` proxy with PE32/PE32+ `DSBUFFERDESC` and
  bounded `WAVEFORMATEX` marshaling, capabilities/format/state queries, playback controls, parent
  lifetime retention, and teardown of live locks.
- Buffer `Lock` copies native regions into bounded guest staging storage; `Unlock` validates the
  exact returned regions and copies guest audio back before releasing the native lock. Native COM
  and audio pointers never enter guest state.
- Corrected fail-closed PE32 stdcall cleanup for retained thread/work callbacks. `CreateThread`
  now reports `ERROR_NOT_SUPPORTED` without corrupting the guest stack or invoking guest code as
  native code. Foreground state also retains the latest visible top-level guest window when host
  focus policy denies a foreground transfer, without exposing another process's HWND.
- The synchronization fixture covers creation, capabilities, lock/upload, playback, invalid
  output, COM lifetime, parent retention, and thread refusal. Undertale creates and starts primary
  and secondary DirectSound buffers, then reaches the 100,000,000-instruction limit. Its OpenAL
  layer still reports error 40964 because CPUEmu has no persistent cooperative guest-thread
  scheduler; working audio is not claimed.

## 2026-11-19 — primitive draw and presentation

- Added host-backed `IDirect3DDevice9::DrawPrimitive` forwarding and bounded `Present` marshaling.
  Optional source/destination rectangles are copied from checked guest memory, dirty regions fail
  closed, and an override HWND is accepted only when it belongs to the CPUEmu host process.
- Extended the Paint synchronization fixture to bind an uploaded guest-owned vertex buffer, set
  its FVF, draw a triangle inside a scene, and present the resulting back buffer.
- Undertale repeatedly reaches both methods and creates a native `UNDERTALE` window, but live
  inspection still shows a blank/non-responsive surface. Its repeated texture `LockRect` calls
  currently return `D3DERR_NOTAVAILABLE`; visible rendering is not claimed.

## 2026-11-19 — staged texture locking

- Added checked `IDirect3DTexture9::LockRect`/`UnlockRect` adapters for common packed, floating,
  YUV, palette/luminance, and DXT formats. Guest-visible storage preserves the native pitch while
  copying only defined row bytes, validates rectangles and size arithmetic, and caps each lock at
  256 MiB.
- Writable locks copy staged rows back before native unlock; read-only and discard behavior avoids
  unnecessary transfers. Live locks are released safely on final COM release and runtime teardown.
- The Paint fixture covers a dynamic ARGB texture lock/upload and null-output rejection. Undertale's
  real texture upload now succeeds; repeated `GetSurfaceLevel` calls remain the next observed
  graphics gap, and visible rendering is not yet verified.

## 2026-11-19 — first verified Undertale frame

- Added a guest-owned 17-slot `IDirect3DSurface9` proxy returned by `GetSurfaceLevel`, including
  COM/resource identity, parent texture/device retention, descriptions, and deterministic teardown.
  Native surface pointers and vtables never enter guest memory.
- Added `IDirect3DDevice9::UpdateTexture` between validated guest texture proxies and bounded
  `GetRasterStatus` output marshaling. The Paint fixture covers surface metadata/container/device
  identity, COM lifetime, invalid output, a staged system-memory texture, and upload into a
  default-pool texture.
- Live inspection verified the real UNDERTALE title logo rendered in the CPUEmu-owned window. This
  is the first verified game frame, not a playability claim: the window still reports “Not
  Responding,” a `Z` input attempt was inconclusive, and audio still lacks a persistent guest
  worker thread.
- A longer probe advanced to 897,619,440 instructions and stopped at unsupported
  `GetUserDefaultLCID`, establishing the next general startup/runtime adapter gap.

## 2026-11-19 — bounded locale discovery

- Added exact scalar adapters for `GetUserDefaultLCID` and `IsValidLocale`, plus shared ANSI and
  Unicode `GetLocaleInfo` marshaling. Size-only queries are preserved, output ranges and signed
  counts are validated, and only the host-defined returned extent is copied into guest memory.
- The Paint synchronization fixture covers a real ISO language result, invalid output rejection,
  and valid/invalid LCID classification.
- Undertale clears the former 897-million-instruction locale sequence and reaches the full
  1,000,000,000-instruction limit without an unsupported import or CPU/memory fault. Visible title
  rendering remains verified; responsive input and working audio remain unproven.

## 2026-11-19 — non-removing presentation heartbeat

- Successful Direct3D presentation now performs a native `PeekMessageW(PM_NOREMOVE)` heartbeat.
  This lets Windows observe queue progress when an interpreted frame exceeds the hung-window
  timeout without consuming, translating, reordering, or dispatching any message on the guest's
  behalf. Synchronous callback faults are still propagated through the normal bridge.
- The Paint fixture posts a thread message before presentation and verifies the guest retrieves
  the exact HWND/message/parameter tuple afterward, proving the heartbeat does not consume it.
- Live inspection showed the rendered window remain titled `UNDERTALE` rather than Windows'
  ghosted `UNDERTALE (Not Responding)`. UI automation still timed out injecting `Z`, so working
  title input is not claimed.

## 2026-10-30 — Earlier sessions (pre-devlog)

Baseline reconstructed from the tree: PE32+ loader, x86-64 interpreter with selected SSE2,
TEB/PEB setup, guest heap, Win32 window bridging, and the Windows 11 `notepad.exe` smoke
test. Command-line form was `winemu <exe> [--limit <n>]` with a single ad-hoc trace
environment variable.
