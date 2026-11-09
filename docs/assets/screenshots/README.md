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

No repository screenshot is included yet. At commit `47a1640`, classic
`C:\Windows\System32\notepad.exe` version 10.0.26100.8457 produced a genuine `cpuemu.exe`-owned
editor window. Basic typing and the populated File menu were verified interactively with:

```powershell
build\cpuemu.exe C:\Windows\System32\notepad.exe --limit 100000000
```

The modern packaged Notepad is a different executable and still does not create a window. Any
future image must show the classic CPUEmu-owned window and record the commit and capture method;
a native or packaged Notepad lookalike is not acceptable evidence.
