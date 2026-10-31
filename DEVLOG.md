# Devlog

A running record of what the coding agent changed while building CPUEmu, newest first. The
emulator's own activity is visible through its logging system (see `README.md` → Logging);
this file is the companion log of development decisions.

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

- **Leveled logger** (`include/winemu/log.hpp`, `src/log.cpp`). Every log line is
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
