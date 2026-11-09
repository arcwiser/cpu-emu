# Project structure

CPUEmu keeps implementation, tests, fixtures, and documentation separate so compatibility work is
easy to review and generated or proprietary artifacts cannot enter the source tree accidentally.

```text
cpu-emu/
├─ .github/
│  ├─ ISSUE_TEMPLATE/       Structured bug and feature reports
│  └─ pull_request_template.md
├─ docs/
│  ├─ assets/               Repository-native README/documentation visuals
│  ├─ DEVLOG.md             Chronological implementation milestones
│  ├─ GAME_COMPATIBILITY.md Verified application and game status
│  ├─ INSTRUCTION_COVERAGE.md
│  ├─ ROADMAP.md
│  ├─ UNDERTALE.md
│  └─ WINDOWS_COMPATIBILITY.md
├─ include/winemu/          Core public headers; legacy internal name retained
├─ src/
│  ├─ cli/                  Command-line executable and option handling
│  ├─ core/                 CPU interpreter, memory model, and logging
│  ├─ loader/               PE32/PE32+ parsing and image loading
│  └─ runtime/              Process setup and Windows compatibility adapters
├─ tests/                   Split CPU, memory, runtime, support, and runner sources
├─ tools/
│  ├─ generators/           PE serialization and deterministic guest builders
│  └─ guests/               Source for controlled guest applications
├─ AGENTS.md                Coding-agent operating rules
├─ CONTRIBUTING.md          Contribution and PR requirements
├─ CMakeLists.txt
└─ README.md                User-facing project entry point
```

## Change routing

| Change | Primary file | Expected companion work |
| --- | --- | --- |
| CPU instruction execution | `src/core/cpu_execute.cpp` | Machine-code regression; coverage update |
| CPU decode, flags, or state | `src/core/cpu_decode.cpp`, `cpu_flags.cpp`, `cpu_state.cpp` | Width/form and flag regressions |
| Guest checked access | `src/core/memory_access.cpp` | Boundary, permission, and invalid-range tests |
| Guest mapping or virtual state | `src/core/memory.cpp`, `memory_virtual.cpp` | Overlap, commit, protection, and query tests |
| PE parsing/loading | `src/loader/pe.cpp` | Valid and malformed fixture tests |
| Imported API selection | `src/runtime/imports.cpp` | Import fixture and unsupported-call behavior |
| Win32/ABI adapter | `src/runtime/dispatch.cpp` | Success/failure/ownership test or controlled probe |
| Guest callback ABI | `src/runtime/callbacks.cpp` | Re-entry, nesting, and teardown tests |
| Process setup/lifecycle | `src/runtime/execution.cpp`, `lifecycle.cpp` | End-to-end fixture and cleanup tests |
| CPU regression | `tests/cpu_tests.cpp` | Minimal machine code and architectural assertions |
| Memory regression | `tests/memory_tests.cpp` | Range, permission, cache, and mapping assertions |
| Runtime regression | `tests/runtime_case_tests.cpp` | PE fixtures, output, WinRT, and smoke guests |
| Generated PE fixture | `tools/generators/` | Writer plus focused guest builder implementation |
| CLI/logging | `src/cli/main.cpp`, `src/core/log.cpp` | CLI regression/manual command and README update |
| Guest smoke fixture | `tools/guests/` | CMake target and deterministic self-test mode |
| Compatibility claim | `docs/GAME_COMPATIBILITY.md` | Version, command, milestone, first blocker |

## Remaining cohesive large modules

- `src/runtime/dispatch.cpp` contains the single `Runtime::dispatch` state machine. Its API cases
  share argument/return helpers, guest CPU state, last-error state, callback exception transfer,
  and thunk completion. Separating individual case ranges would require changing that control flow
  into a new handler abstraction, so it was not performed as a move-only refactor.
- `src/core/cpu_execute.cpp` contains the single `Cpu::step` decode/execute state machine and its
  execution-only helpers. Prefix state, decoded operands, flags, x87 state, and XMM state are local
  to one instruction step; instruction-family extraction would therefore be a behavioral rewrite.
- `src/loader/pe.cpp` intentionally keeps one transactional `PeLoader::load`. Header values,
  mapped sections, import addresses, and TLS ranges are validated against the same image bounds;
  splitting its phases would require introducing a new partially initialized loader object.

These boundaries may be redesigned later with focused regressions, but they are not safe mechanical
extractions.

## Files that never belong in Git

- `build/`, `build-release/`, CMake caches, Ninja state, object files, PDBs, or executables.
- Commercial games, Windows binaries, DLLs, `data.win`, soundtrack files, or extracted assets.
- Runtime logs, minidumps, screenshots containing personal information, or local absolute paths.
- Credentials, Steam session data, access tokens, cookies, signing keys, or machine identifiers.
- Generated compatibility output that cannot be reproduced from committed source and commands.

Keep experimental scripts only when they are reusable, documented, and safe. One-off local probes
belong outside the repository; their findings belong in a focused regression or compatibility note.
