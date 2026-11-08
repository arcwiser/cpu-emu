# CPUEmu Agent Guide

These repository-wide rules apply to AI coding agents and automated contributors. A more specific
`AGENTS.md` may refine them within a subdirectory, but may not weaken safety, testing, disclosure,
or guest/host isolation requirements.

## Mission and priorities

CPUEmu is a Windows-hosted x86/x86-64 user-mode interpreter and Win32 compatibility layer. It is
not a virtual machine. Work in this priority order:

1. Correct architectural and ABI behavior.
2. Guest/host memory and callback safety.
3. Regression-backed general solutions.
4. Honest compatibility evidence and documentation.
5. Performance improvements that preserve the first four priorities.

Never patch a single instruction address, executable hash, game asset, or application-specific
constant to make a probe advance.

## Repository map

- `src/cpu.cpp`: decoding, execution, registers, flags, x87/XMM state.
- `src/memory.cpp`: checked mappings, permissions, and virtual-memory bookkeeping.
- `src/pe.cpp`: PE32/PE32+ validation, sections, imports, TLS, and stack metadata.
- `src/runtime.cpp`: process setup, ABI adapters, Win32 marshaling, guest callbacks/interfaces.
- `tests/tests.cpp`: machine-code regressions and end-to-end fixture tests.
- `tools/guest/paint.cpp`: interactive/headless GDI smoke guest.
- `docs/`: compatibility evidence, coverage, roadmap, structure, and milestones.
- `README.md`: user-facing overview; `CONTRIBUTING.md`: PR requirements.

The internal namespace/include directory remains `winemu` for compatibility. The public project and
executable are CPUEmu and `cpuemu.exe`.

## Required workflow

Before editing:

1. Read the relevant implementation, tests, and documentation.
2. Check `git status`; preserve existing user changes and unrelated work.
3. Identify guest/host ownership, ABI, widths, flags, and callback lifetime risks.
4. Prefer the smallest general change that can be tested independently.

Before committing or handing off:

```powershell
cmake -S . -B build -G Ninja -DCMAKE_CXX_COMPILER=clang++ -DCMAKE_BUILD_TYPE=Release
cmake --build build
ctest --test-dir build --output-on-failure
build\cpuemu.exe build\test-apps\paint.exe -- --selftest
git diff --check
```

Run `clang-format` on every modified C++ header/source. If a required check cannot run, report the
exact command, reason, and remaining risk; never mark an unrun check as passed.

## CPU implementation rules

- Preserve exact operand width, sign/zero extension, prefix, address-size, and flag semantics.
- Implement opcode families and shared helpers, not one observed byte sequence alone.
- Test register and memory forms, relevant widths, boundary values, and flag transitions.
- Treat undefined architectural flags as undefined rather than inventing stable behavior.
- Gate `CPUID` features conservatively. Advertising a feature is a compatibility contract.
- Keep x86 and x86-64 differences explicit: stack width, addressing, segments, REX/high-byte
  registers, callbacks, and calling conventions.

## Memory, ABI, and Windows safety rules

- Treat every guest address, length, count, offset, nested pointer, and handle as untrusted.
- Validate guest ranges through `Memory` and check integer overflow before accessing them.
- Never return a raw host-owned pointer, vtable, string, array, or structure to guest code.
- Marshal pointer-rich structures field by field when host/guest layouts or widths can differ.
- Never call a guest callback as native code. Use `Runtime::invoke_guest` and account for re-entry,
  stack ABI, exception cleanup, object lifetime, and nested callbacks.
- APIs retaining pointers/callbacks require explicit lifetime-aware guest adapters. Fail closed
  until one exists.
- Do not forward guest process/thread creation to native Windows. It would escape emulation.
- Preserve the guest's last-error and return-value conventions, including x86 stdcall cleanup.

## Testing expectations by change type

| Change | Minimum evidence |
| --- | --- |
| CPU instruction | Compact machine-code regression; flags and edge widths where applicable |
| Loader/parser | Valid fixture plus malformed/boundary case |
| Memory | Permission, overflow, overlap/boundary, and invalid-range behavior |
| Runtime adapter | Success, native failure, guest output, invalid input, and ownership/lifetime |
| Callback/COM proxy | Re-entry or vtable test plus teardown/nesting behavior |
| Performance | Identical result/state before and after plus reproducible measurement |
| Documentation only | Link/path/render check and `git diff --check` |

A commercial application probe is evidence, not a substitute for regression tests. Never commit
the application, its assets, copied SDK headers with incompatible terms, logs containing private
data, or generated binaries.

If Windows policy blocks a newly linked test executable, report that separately. Do not claim the
suite passed and do not weaken system security settings.

## AI-generated change requirements

Agents must make AI involvement visible to the human author and reviewer:

- Tell the author which files and behaviors were materially generated or changed by AI.
- Provide exact tests run and their results; do not use vague statements such as “tested.”
- Call out assumptions, unverified APIs/encodings, compatibility probes, and remaining limitations.
- Never invent benchmark numbers, instruction coverage percentages, application status, citations,
  or test results.
- Review generated code against primary architecture/API documentation and existing invariants.
- Keep generated patches reviewable. Split unrelated mechanical, behavioral, and documentation
  work when practical.
- The PR must complete the AI Assistance section in the pull-request template, even when the answer
  is “none.” The human submitter remains responsible for every line.

## Documentation and compatibility claims

- Update `docs/INSTRUCTION_COVERAGE.md` when a family meaningfully changes.
- Update `docs/WINDOWS_COMPATIBILITY.md` for new adapter ownership/lifetime behavior.
- Update `docs/GAME_COMPATIBILITY.md` only from a recorded probe with version, command, milestone,
  first blocker, and relevant commit.
- Add significant milestones to `docs/DEVLOG.md`; do not turn it into a per-commit changelog.
- Use “loads,” “starts,” “creates a window,” or “reaches X” precisely. Do not call an application
  playable until input, rendering, audio, persistence, and sustained execution were verified.

## Git and scope discipline

- Do not delete, reset, overwrite, or reformat unrelated user changes.
- Never commit build outputs, executables, logs, crash dumps, proprietary files, or credentials.
- Use conventional commit subjects: `feat:`, `fix:`, `test:`, `docs:`, or `refactor:`.
- Keep commits reviewable and focused. Explain remaining limitations honestly.
- Do not amend, force-push, rewrite published history, or change repository settings unless the
  human explicitly requests it.
- Follow `CONTRIBUTING.md` and the PR template for every submission.
