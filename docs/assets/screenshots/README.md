# Screenshot provenance

Screenshots in this directory must come from a window whose owning process is the built
`cpuemu.exe`. Native lookalikes, mockups, and windows launched outside the interpreter are not
accepted as compatibility evidence.

## CPUEmu Paint

- Guest: `build\test-apps\paint.exe`
- Mode: deterministic visual probe; sample GDI content plus a responsive message pump
- Command:

```powershell
build\cpuemu.exe build\test-apps\paint.exe -- --screenshot
```

- File: `paint-cpuemu.png`
- Evidence: the captured window owner was the repository's `build\cpuemu.exe`.

## About Windows

- Guest: `C:\Windows\System32\winver.exe`
- Host version shown: Windows 11 25H2, build 26200.9711
- Command:

```powershell
build\cpuemu.exe C:\Windows\System32\winver.exe
```

- File: `winver-cpuemu.png`
- Evidence: the captured `About Windows` dialog owner was the repository's `build\cpuemu.exe`.

## Notepad

No current screenshot is included. The Windows 11 25H2 system `notepad.exe` loads under CPUEmu but
enters packaged-instance synchronization/cross-process activation before an editor window exists.
Presenting a native Notepad window as emulated would be misleading. Add a screenshot only after a
current-tree probe produces a genuine `cpuemu.exe`-owned Notepad editor window.
