# Undertale bring-up target

CPUEmu is targeting the current Windows GameMaker build of Undertale. The Windows depot contains
`UNDERTALE.exe`, `data.win`, `D3DX9_43.dll`, `steam_api.dll`, and a large OGG soundtrack. SteamDB's
branch history includes explicit 64-bit test branches. The installed executable is a fixed-base
x86 PE32 image, which CPUEmu now loads through its 32-bit execution path.

Depot reference: <https://steamdb.info/depot/391541/>

## First probe

Keep `data.win`, the DLLs, and the audio assets beside `UNDERTALE.exe`. Run from the installation
directory so GameMaker's relative file lookups resolve correctly:

```powershell
Push-Location 'C:\Program Files (x86)\Steam\steamapps\common\Undertale'
C:\path\to\cpuemu.exe .\UNDERTALE.exe --limit 100000000 -vv --log-file undertale.log
Pop-Location
```

Record the executable's machine type, resolved imports, instruction count, final RIP, recent RIP
history, and first error. Do not copy the commercial executable, `data.win`, soundtrack, or Steam
DLLs into this repository.

## Expected compatibility layers

1. **Image and startup:** PE32/PE32+ loading, sections, imports, CRT initialization, TLS, stack, TEB,
   PEB, command line, environment, and relative asset paths.
2. **Game loop:** high-resolution timers, sleep/yield behavior, window creation, message pumping,
   keyboard/gamepad input, and stable interpreted callbacks.
3. **Rendering:** GameMaker's Direct3D 9 setup, COM interface proxies, surfaces, textures, shaders,
   presentation, and device reset/loss behavior.
4. **Audio:** OGG decoding in guest code plus the audio backend actually selected by this runner.
   Basic WinMM sound calls exist, but DirectSound/XAudio/WASAPI objects require guest-side COM
   proxies and lifetime handling.
5. **Steam integration:** either a safe Steamworks adapter or a documented offline failure path;
   native callbacks may never execute guest addresses.
6. **Persistence:** sandboxed save/config paths, Unicode filenames, file enumeration, and atomic
   replacement behavior.

## Current readiness

- The CPU covers broad integer/SSE2 behavior plus growing SSE3/SSSE3 support.
- Game-loop timing adapters cover performance counters, tick counts, sleeps, and WinMM timer
  periods.
- PE32 window-class registration, native window creation, callback re-entry, resource loading,
  text, geometry, cursor, and synchronous scalar/text messages are implemented.
- A guest-owned DirectInput 8 COM proxy provides safe device creation and zeroed state polling;
  display-mode enumeration is marshaled without exposing host structures.
- Basic synchronous WinMM playback exists, but streaming/game audio is not complete.
- Direct3D 9Ex creation is the current first unsupported boundary. Steam startup is validated only
  through the safe offline failure path; authenticated Steamworks interfaces are not implemented.
- The installed Steam executable loads at `0x00400000`, resolves all 313 imports, opens and parses
  `data.win`, probes `options.ini` and save/config paths, and passes the safe offline Steam startup
  path. It creates the native `YYGameMakerYY` window, executes its interpreted `WM_NCCREATE` and
  `WM_CREATE` callbacks, sets the title and icons, completes optional input/display discovery, and
  reaches `Direct3DCreate9Ex` after 15,130,126 instructions.
- A page-indexed guest-memory lookup cache makes large heap-backed parsing practical; the same
  six-million-instruction state runs about 48 times faster than the previous linear region scan.

The next engineering step is a guest-owned Direct3D 9Ex COM proxy, beginning with adapter queries,
device creation, and presentation. Streaming audio work follows once the selected GameMaker
backend is observed.
