# Game and application compatibility

This list records observed behavior, not a guarantee for every version of an application. Results
are tied to the current CPUEmu tree on 64-bit Windows. “Starts” means the image reached its UI or
documented probe point under interpreted execution; it does not imply that every feature works.

## Status levels

| Badge | Level | Meaning |
| :---: | --- | --- |
| 🟢 | Supported fixture | Deterministic scoped behavior passes its regression/self-test |
| 🟡 | Starts | Reaches a real UI or documented startup milestone; major features may be absent |
| 🟠 | Bring-up | Advances through meaningful initialization but is blocked before normal use |
| 🔴 | Blocked | Loads or executes partially but cannot reach a useful UI/workload |
| ⚪ | Untested | No current-tree probe with enough evidence to classify |

The levels are deliberately stricter than “the process did not crash.” For games:

```text
loads → creates window → visible window → first frame → input → audio → sustained gameplay → playable
```

Each arrow is a separate milestone. Reports must state the last verified milestone and first
reproducible blocker.

## Compatibility board

| Application | Status | Verified behavior | Important limitations |
| --- | --- | --- | --- |
| `exit42.exe` fixture | Supported | Loads, exits through the Win32/CRT bridge, and returns code 42 | Test fixture only |
| `sum.exe` fixture | Supported | Integer loop, arithmetic, flags, branches, and process return | Test fixture only |
| `hello.exe` fixture | Supported | Imports resolve and console output passes through `GetStdHandle`/`WriteFile` | Test fixture only |
| CPUEmu Paint fixture | 🟢 Supported smoke test | Interactive GDI path starts; `--selftest` draws and reports success | Intended as a compatibility probe, not a full paint program |
| Windows 11 Notepad | 🟡 Starts | Main image loads, basic window/editor UI starts, resources load, and the message loop runs | No guest threads, broad COM support, exceptions, or complete Windows API surface |
| Undertale (Windows, PE32) | 🟠 Graphics bring-up | Fixed-base image loads, all 313 imports resolve, parses `data.win`, creates the `YYGameMakerYY` native window, initializes a safe DirectInput proxy, enumerates display modes, and reaches `Direct3DCreate9Ex` after about 15.1M instructions | The HWND is created but not visibly shown/rendering yet; Direct3D 9, active input, streaming audio, and full Steamworks interfaces remain |
| Discord / Chromium | 🔴 Blocked | Loads the installed x64 image and advances through more than 2.6 million V8 startup instructions | Blocked by guest threads/processes, DLL loading, exceptions, mapped sections, and broader SIMD support |

## Undertale subsystem board

| Subsystem | State | Evidence |
| --- | :---: | --- |
| PE32 image/imports | ✅ | Fixed image at `0x00400000`; 313 imports resolve |
| x86 CRT/TLS/heap | ✅ | Completes runtime initialization without R6016 |
| Files and game data | ✅ | Opens and parses adjacent `data.win`; probes config/save paths |
| Steam startup | ⚠️ | Safe offline failure path; not the current startup blocker |
| Window class/callback | ✅ | Registers `YYGameMakerYY`; interpreted `WM_NCCREATE`/`WM_CREATE` run |
| Visible window | 🚧 | Native HWND exists, but GameMaker has not shown/rendered it before graphics setup |
| Input discovery | ✅ | Guest-owned inert DirectInput proxy completes optional discovery |
| Direct3D 9Ex | 🚧 | Current first unsupported boundary: `Direct3DCreate9Ex` |
| Audio | ○ | Basic synchronous WinMM only; GameMaker streaming path not reached |
| Playable | ○ | Requires rendering, input, audio, persistence, and sustained loop |

## Audio status

CPUEmu adapts synchronous `Beep`, `MessageBeep`, `PlaySoundA`, `PlaySoundW`, and the legacy
`sndPlaySoundA/W` aliases. Filename and system-alias playback are supported when Windows accepts
the requested sound. Stopping playback with a null sound name is supported.

Asynchronous, looping, memory-buffer, and resource-backed playback is refused for now because the
host can retain guest pointers after the call returns. WaveOut, DirectSound, WASAPI, Media
Foundation, and audio callbacks are not implemented yet.

The Undertale-specific probe and subsystem roadmap are in [`UNDERTALE.md`](UNDERTALE.md).

## Reporting results

When adding an entry, record the exact application version, Windows version, command line, last
successful milestone, and first reproducible failure. A compatibility probe should produce a
regression test before its workaround is considered supported behavior.
