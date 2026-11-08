# Undertale bring-up target

CPUEmu is targeting the current Windows GameMaker build of Undertale. The Windows depot contains
`UNDERTALE.exe`, `data.win`, `D3DX9_43.dll`, `steam_api.dll`, and a large OGG soundtrack. SteamDB's
branch history includes explicit 64-bit test branches, but the exact installed executable must
still be checked because CPUEmu currently loads only x86-64 PE32+ images.

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

1. **Image and startup:** PE32+ loading, sections, imports, CRT initialization, TLS, stack, TEB,
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
- Window callback re-entry exists and is exercised by the Paint and Notepad paths.
- Basic synchronous WinMM playback exists, but streaming/game audio is not complete.
- Direct3D 9 and Steamworks have not been validated against Undertale yet.
- No Undertale installation was found in the standard local Steam library paths during the latest
  audit, so there is not yet an authoritative first-failure trace.

The next engineering step is to run the owned x64 executable and implement the earliest general
failure with a regression. Guessing later Direct3D or audio interfaces before that trace risks
building the wrong compatibility layer.
