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
| Classic Notepad (`System32\notepad.exe` 10.0.26100.8457) | 🟡 Starts | CPUEmu-owned editor window renders; typing and menus work; file open places all 5,010 characters of `CMakeLists.txt` in the real Edit control; Save persisted exact replacement text to an existing disposable file | Save As, encoding variants, long editing sessions, and broader editor behavior remain unverified |
| Modern packaged Notepad 11.2607.14.0 | 🔴 Blocked | Creates and uses a guest-owned WinRT application instance | XAML resource lookup reaches an unimplemented interface method, then requires guest exception unwinding; no window |
| About Windows (`winver.exe`) | 🟡 Starts | Creates and displays the genuine Microsoft version dialog through CPUEmu | Modal dialog probe only; does not exercise a sustained app loop |
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

The basic input/menu result was re-probed at commit `47a1640` with:

```powershell
build\cpuemu.exe C:\Windows\System32\notepad.exe --limit 100000000
```

The CPUEmu-owned window accepted `CPUEmu input test`, changed its title to `*Untitled - Notepad`,
opened a populated File menu, and displayed/cancelled a real Open picker. This is evidence for
basic input, menu routing, and synchronous dialog marshaling only; it does not establish correct
file loading, saving, or full editor compatibility.

File selection and command-line loading were re-probed at commit `e3c3f39` on Windows build
`10.0.26200.0` with classic Notepad file version `10.0.26100.8457`:

```powershell
build\cpuemu.exe C:\Windows\System32\notepad.exe --limit 20000000 -vv -- `
  (Resolve-Path .\CMakeLists.txt).Path
```

The selected path reached `CreateFileW`, and `FindMimeFromData` returned a guest-owned MIME string
without the former unmapped host-pointer fault. At commit `d040900`, field-by-field
`GetFileInformationByHandle` marshaling advanced the probe to file mapping.

The same command was repeated at commit `e0e4f0e`. `CreateFileMappingW` returned opaque guest token
`0x500`; `MapViewOfFile` returned guest address `0x600190000`; Notepad sent the mapped data through
its edit-control path; `UnmapViewOfFile` succeeded; the window title updated; and the process
remained in its message loop. This verifies the read-only command-line file-open pipeline, not the
visual correctness of the resulting text, saving, persistence, or full editor compatibility.

At commit `837f6a5`, `EM_SETHANDLE` stopped forwarding a guest `LocalAlloc` address as a native
`HLOCAL`. The adapter instead copied the guest text into the native control and retained only the
guest handle for a safe `EM_GETHANDLE` copy-back. Repeating the command above and querying the
CPUEmu-owned child Edit with `WM_GETTEXT` returned length 5,010 and the complete `CMakeLists.txt`,
beginning with `cmake_minimum_required(VERSION 3.24)`. This verifies read-only text loading; save,
persistence, and sustained editing remain unverified.

The same commit was probed against a disposable copy at
`%TEMP%\cpuemu-notepad-save-probe.txt`. After `WM_SETTEXT` replaced the Edit contents and
`EM_SETMODIFY` marked it dirty, Notepad's own File → Save command (menu ID 3) persisted exactly
`CPUEmu Notepad persistence probe\r\nsecond line\r\n` (47 characters). The temporary file was
deleted after verification. This establishes Save to an existing file, not Save As, alternate
encodings, or sustained editing.
