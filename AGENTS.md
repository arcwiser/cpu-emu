# CPUEmu Agent Guide

This file defines repository-wide instructions for coding agents. More specific `AGENTS.md` files
in subdirectories may refine these rules.

## Mission

CPUEmu is a Windows-hosted x86-64 user-mode interpreter and Win32 compatibility layer. It is not a
virtual machine. Prefer correct, general CPU and ABI behavior over application-specific patches.

## Repository map

- `src/cpu.cpp`: instruction decoding, execution, registers, and flags.
- `src/memory.cpp`: checked guest mappings and virtual-memory bookkeeping.
- `src/pe.cpp`: PE32+ validation, loading, sections, imports, TLS, and stack metadata.
- `src/runtime.cpp`: guest process setup and controlled Win32 API adapters.
- `tests/tests.cpp`: core regression and end-to-end fixture tests.
- `tools/guest/paint.cpp`: interactive and headless GDI guest smoke test.
- `README.md`: user documentation; `DEVLOG.md`: compatibility milestones.

The internal namespace and include directory remain `winemu` for compatibility. The public project
and executable name are CPUEmu and `cpuemu.exe`.

## Build and verify

Use an out-of-tree build directory:

```powershell
cmake -S . -B build -G Ninja -DCMAKE_CXX_COMPILER=clang++ -DCMAKE_BUILD_TYPE=Release
cmake --build build
ctest --test-dir build --output-on-failure
build\cpuemu.exe build\test-apps\paint.exe -- --selftest
```

Run `clang-format` on modified C++ headers and sources. Run `git diff --check` before committing.
Do not commit build outputs, executables, logs, crash dumps, or third-party application files.

## Implementation rules

- Preserve exact x86-64 operand width, sign-extension, flag, prefix, and address-size semantics.
- Add instruction behavior by opcode family when appropriate; never patch behavior for a single
  instruction address or executable.
- Treat every guest pointer as untrusted and validate it through `Memory`.
- Never call a guest callback as native host code. Use `Runtime::invoke_guest` and manage re-entry.
- Never expose host-owned pointers to the guest. Marshal strings, arrays, structures, interfaces,
  and nested pointers into guest memory.
- Native APIs that retain callbacks or pointers require explicit lifetime-aware adapters. Refuse
  them safely when that support does not exist.
- Preserve user changes and keep unrelated cleanup out of focused patches.

## Testing expectations

- CPU changes should include a compact machine-code regression test when feasible.
- Loader and memory fixes should test malformed input and boundary behavior.
- Runtime adapters should test success, failure, output pointers, and guest ownership where the
  fixture system permits it.
- A compatibility probe is evidence, not a replacement for regression tests.
- If Windows policy blocks a newly linked test executable, report that separately; do not claim the
  suite passed and do not weaken system security settings.

## Pull requests and commits

Follow `CONTRIBUTING.md` and the pull-request template. Use conventional commit subjects such as
`feat:`, `fix:`, `test:`, `docs:`, or `refactor:`. Keep commits reviewable and explain remaining
limitations honestly.
