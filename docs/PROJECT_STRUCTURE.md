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
├─ src/                     Emulator and compatibility-layer implementation
├─ tests/                   Regression and fixture-driven tests
├─ tools/
│  ├─ guest/                Source for controlled guest applications
│  └─ make_test_apps.cpp    Minimal PE fixture generator
├─ AGENTS.md                Coding-agent operating rules
├─ CONTRIBUTING.md          Contribution and PR requirements
├─ CMakeLists.txt
└─ README.md                User-facing project entry point
```

## Change routing

| Change | Primary file | Expected companion work |
| --- | --- | --- |
| CPU instruction or flags | `src/cpu.cpp` | Machine-code regression in `tests/tests.cpp`; coverage update |
| Guest address/mapping behavior | `src/memory.cpp` | Boundary, permission, and invalid-range tests |
| PE parsing/loading | `src/pe.cpp` | Valid and malformed fixture tests |
| Win32/ABI adapter | `src/runtime.cpp` | Success/failure/ownership test or controlled probe |
| CLI/logging | `src/main.cpp`, `src/log.cpp` | CLI regression/manual command and README update |
| Guest smoke fixture | `tools/guest/` | CMake target and deterministic self-test mode |
| Compatibility claim | `docs/GAME_COMPATIBILITY.md` | Version, command, milestone, first blocker |

## Files that never belong in Git

- `build/`, `build-release/`, CMake caches, Ninja state, object files, PDBs, or executables.
- Commercial games, Windows binaries, DLLs, `data.win`, soundtrack files, or extracted assets.
- Runtime logs, minidumps, screenshots containing personal information, or local absolute paths.
- Credentials, Steam session data, access tokens, cookies, signing keys, or machine identifiers.
- Generated compatibility output that cannot be reproduced from committed source and commands.

Keep experimental scripts only when they are reusable, documented, and safe. One-off local probes
belong outside the repository; their findings belong in a focused regression or compatibility note.
