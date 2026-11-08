# Application compatibility

This list records observed behavior, not a guarantee for every version of an application. Results
are tied to the current CPUEmu tree on 64-bit Windows. “Starts” means the image reached its UI or
documented probe point under interpreted execution; it does not imply that every feature works.

| Application | Status | Verified behavior | Important limitations |
| --- | --- | --- | --- |
| `exit42.exe` fixture | Supported | Loads, exits through the Win32/CRT bridge, and returns code 42 | Test fixture only |
| `sum.exe` fixture | Supported | Integer loop, arithmetic, flags, branches, and process return | Test fixture only |
| `hello.exe` fixture | Supported | Imports resolve and console output passes through `GetStdHandle`/`WriteFile` | Test fixture only |
| CPUEmu Paint fixture | Supported smoke test | Interactive GDI path starts; `--selftest` draws and reports success | Intended as a compatibility probe, not a full paint program |
| Windows 11 Notepad | Partially supported | Main image loads, basic window/editor UI starts, resources load, and the message loop runs | No guest threads, broad COM support, exceptions, or complete Windows API surface |
| Undertale (Windows, PE32) | Bring-up in progress | Fixed-base image loads, all 313 imports resolve, and CRT/heap/TLS/x87 startup executes 507,053 instructions without an unsupported-operation stop | Guest currently returns exit code 255 before window creation; Direct3D 9, streaming audio, and Steamworks remain |
| Discord / Chromium | Not usable | Loads the installed x64 image and advances through more than 2.6 million V8 startup instructions | Blocked by guest threads/processes, DLL loading, exceptions, mapped sections, and broader SIMD support |

## Audio status

CPUEmu adapts synchronous `Beep`, `MessageBeep`, `PlaySoundA`, `PlaySoundW`, and the legacy
`sndPlaySoundA/W` aliases. Filename and system-alias playback are supported when Windows accepts
the requested sound. Stopping playback with a null sound name is supported.

Asynchronous, looping, memory-buffer, and resource-backed playback is refused for now because the
host can retain guest pointers after the call returns. WaveOut, DirectSound, WASAPI, Media
Foundation, and audio callbacks are not implemented yet.

The Undertale-specific probe and subsystem roadmap are in
[`docs/UNDERTALE.md`](docs/UNDERTALE.md).

## Reporting results

When adding an entry, record the exact application version, Windows version, command line, last
successful milestone, and first reproducible failure. A compatibility probe should produce a
regression test before its workaround is considered supported behavior.
