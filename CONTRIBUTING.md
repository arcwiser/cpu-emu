# Contributing to CPUEmu

Thanks for helping CPUEmu grow. Instruction implementations, loader and memory fixes, safe Win32
adapters, controlled fixtures, documentation, and reproducible compatibility reports are welcome.

By submitting a contribution, you confirm that you have the right to provide it and that it does
not contain proprietary application code/assets, credentials, private logs, or generated binaries.

## Before starting

1. Search open issues and pull requests for overlapping work.
2. Open an issue before a large architecture, scheduler, JIT, or compatibility-layer redesign.
3. Choose one reviewable problem. Split unrelated cleanup from behavioral changes.
4. Read the relevant coverage/compatibility document and existing tests.
5. If using an AI assistant, read [AI-assisted contributions](#ai-assisted-contributions) before
   generating code.

## Development setup

CPUEmu targets Windows and requires CMake 3.24+, Ninja, and a C++20 compiler. The supported project
workflow uses LLVM/Clang:

```powershell
git clone https://github.com/arcwiser/cpu-emu.git
cd cpu-emu
cmake -S . -B build -G Ninja -DCMAKE_CXX_COMPILER=clang++ -DCMAKE_BUILD_TYPE=Release
cmake --build build
ctest --test-dir build --output-on-failure
build\cpuemu.exe build\test-apps\paint.exe -- --selftest
```

Create a focused branch such as `feat/packed-simd`, `fix/pe32-tls`, or
`docs/compatibility-levels`.

## Engineering requirements

### General quality

- Follow the existing four-space C++ style and run `clang-format` on changed C++ files.
- Build with warnings enabled; the Clang core target treats warnings as errors.
- Prefer simple, explicit ownership and ABI code over clever forwarding.
- Avoid drive-by renames, broad formatting, generated rewrites, and unrelated dependency changes.
- Comments should explain architectural intent, ownership, or a non-obvious invariant—not restate
  the code.

### Emulator correctness and safety

- Implement general instruction/API behavior, never a single guest address or executable patch.
- Preserve widths, sign extension, prefixes, address-size rules, flags, and calling conventions.
- Treat every guest pointer and length as untrusted; validate overflow and mapped permissions.
- Never execute a guest callback natively or expose host-owned pointers/vtables to the guest.
- Marshal nested pointer structures and cross-bitness layouts explicitly.
- Refuse unsupported retained callbacks, process/thread creation, and COM interfaces safely.
- Advertise optional CPU features only when their required behavior is dependable.

See [AGENTS.md](AGENTS.md) for the complete implementation invariants. They apply to human-written
and AI-generated code alike.

## Tests are required

Every behavioral pull request must add or update a test unless the PR explains why the existing
fixture system cannot express the case. A compatibility probe alone is not sufficient.

| Change | Expected tests |
| --- | --- |
| Instruction | Minimal machine code, widths/forms, result, flags, and boundary values |
| PE loader | Successful fixture plus malformed/bounds rejection |
| Memory | Permissions, overflow, page/region boundary, invalid access |
| Runtime/API | Success/failure, outputs, invalid pointers, ownership and lifetime |
| Callback/interface | Re-entry, ABI cleanup, nested call or teardown where applicable |
| Performance | Same final state plus reproducible before/after commands |
| Documentation | Links/paths/rendering checked; no unsupported compatibility claim |

Before opening the PR, run:

```powershell
cmake --build build
ctest --test-dir build --output-on-failure
build\cpuemu.exe build\test-apps\paint.exe -- --selftest
git diff --check
```

List the exact commands and outcomes in the PR. If a check is skipped or blocked, say so and explain
the risk. “Tests pass” without commands is not enough.

## AI-assisted contributions

AI assistance is allowed, but disclosure and human verification are mandatory. In the pull-request
template, state:

- whether AI was used (`none`, `assisted`, or `substantial`);
- the tool/model when known;
- which files or parts were generated or materially transformed;
- what the human author manually reviewed;
- which primary specifications or API documentation were checked;
- all tests actually run and any behavior that remains unverified.

The submitter is responsible for the entire patch. AI output must not be treated as a source of
truth, test evidence, or licensing provenance. Do not submit code you cannot explain. Never include
private prompts, credentials, proprietary source, commercial binaries/assets, or fabricated
benchmarks/citations.

Maintainers may ask for a smaller human-auditable patch, additional tests, or a rewrite if generated
code obscures ownership, safety, or architectural reasoning.

## Compatibility reports

A useful application report includes:

- CPUEmu commit and build configuration;
- Windows version and guest architecture;
- exact command and instruction limit;
- application version/source (without uploading it);
- last verified milestone and first reproducible blocker;
- sanitized log excerpt at the narrowest useful level;
- whether the result is repeatable.

Use precise status language. Creating an `HWND` is not the same as showing a window; showing a
window is not rendering; rendering one frame is not “playable.”

## Files and legal hygiene

Do not commit:

- Windows or commercial application executables, DLLs, game data, audio, images, or extracted
  resources;
- SDK code or headers unless their license clearly permits redistribution and they are necessary;
- build trees, object files, executables, PDBs, logs, dumps, or benchmark caches;
- Steam/authentication data, access tokens, cookies, usernames, machine IDs, or private paths;
- material copied from reverse-engineered proprietary source.

Clean-room behavioral observations, public specifications, minimal original fixtures, and general
interoperability work are appropriate. Record sources when a non-obvious behavior comes from a
public specification.

## Documentation requirements

- User-visible behavior: update `README.md` where appropriate.
- Instruction family changes: update `docs/INSTRUCTION_COVERAGE.md`.
- Win32/API ownership changes: update `docs/WINDOWS_COMPATIBILITY.md`.
- Reproducible app/game milestones: update `docs/GAME_COMPATIBILITY.md`.
- Significant project milestone: add a concise entry to `docs/DEVLOG.md`.
- New future work: update `docs/ROADMAP.md` with a measurable completion condition.

## Commits

Use short conventional subjects:

- `feat: implement PSHUFB memory forms`
- `fix: preserve carry in 32-bit shifts`
- `test: cover malformed PE32 TLS ranges`
- `docs: add Direct3D compatibility status`
- `refactor: share packed lane helpers`

Keep commits bisectable when practical. Do not commit a known failing test merely to make a later
commit pass, and do not mix generated artifacts into source commits.

## Pull-request checklist

Before requesting review, confirm that the PR:

- explains the problem and why the solution is general;
- includes focused tests and exact results;
- discloses AI assistance, including “none”;
- preserves guest/host ownership and callback safety;
- contains no application-address special cases or proprietary files;
- updates relevant coverage/compatibility documentation;
- identifies known limitations and follow-up work;
- has a clean `git diff --check` and no unrelated changes.

Maintainers may request smaller commits, more edge cases, primary-source verification, or safer
marshaling before merge.
