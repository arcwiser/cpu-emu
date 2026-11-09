# Devlog

A running record of what the coding agent changed while building CPUEmu, newest first. The
emulator's own activity is visible through its logging system (see `README.md` → Logging);
this file is the companion log of development decisions.

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

## 2026-10-30 — Earlier sessions (pre-devlog)

Baseline reconstructed from the tree: PE32+ loader, x86-64 interpreter with selected SSE2,
TEB/PEB setup, guest heap, Win32 window bridging, and the Windows 11 `notepad.exe` smoke
test. Command-line form was `winemu <exe> [--limit <n>]` with a single ad-hoc trace
environment variable.
