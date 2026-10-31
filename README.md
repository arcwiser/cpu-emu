# CPUEmu

CPUEmu is a Windows-hosted x86-64 user-mode CPU emulator. It loads PE32+ executables, interprets guest machine instructions, isolates guest memory, and bridges selected Win32 APIs to the host. It does not boot a guest operating system and is not a virtual machine.

The current milestone runs small native Windows applications end to end and can start the Windows
11 `notepad.exe` UI under interpreted guest execution. The included fixtures cover:

- Returning an application exit code
- Arithmetic, flags, loops, and conditional branches
- PE imports and indirect calls
- `GetStdHandle`, `WriteFile`, and `ExitProcess`
- Guest-to-host console output

The Notepad path additionally exercises PE resources, delay imports, TEB/PEB state, a guest heap,
Win32 window creation, re-entrant guest window procedures, a native message loop, selected SSE2
instructions, and guest-side proxies for APIs that cannot safely expose host pointers.

## Contributing

Pull requests are welcome. Read [CONTRIBUTING.md](CONTRIBUTING.md) for the build workflow, emulator
safety rules, testing expectations, commit style, and the official pull-request process. Bug reports
and feature proposals can use the repository's GitHub issue templates.

## Build

The project requires CMake, Ninja, and a C++20 compiler. On Windows with LLVM:

```powershell
cmake -S . -B build -G Ninja -DCMAKE_CXX_COMPILER=clang++ -DCMAKE_BUILD_TYPE=Release
cmake --build build
ctest --test-dir build --output-on-failure
```

## Run

```powershell
build\cpuemu.exe path\to\program.exe
```

The emulator returns the guest application's exit code. An optional instruction limit prevents a malformed guest from running indefinitely (`0` removes the limit entirely):

```powershell
build\cpuemu.exe path\to\program.exe --limit 1000000
```

### Logging

The emulator logs what it is doing to stderr, separate from the guest program's own stdout
output. Log levels, from quietest to chattiest: `error`, `warn`, `info` (default), `api`,
`trace`.

```powershell
build\cpuemu.exe program.exe            # info: lifecycle, PE loading, guest exit, debug strings
build\cpuemu.exe program.exe -v         # api: every guest API call with arguments and results
build\cpuemu.exe program.exe -vv        # trace: also per-window-message callbacks, sections,
                                        #       imports, and guest memory mappings
```

Additional options:

```powershell
build\cpuemu.exe program.exe --log-level api      # pick any level by name
build\cpuemu.exe program.exe --log-file run.log   # mirror all log lines into a file
build\cpuemu.exe --version                        # print the installed version
build\cpuemu.exe --help                           # full usage
```

When the guest faults, the emulator logs the full CPU register state plus a history of the
last 64 executed instruction addresses to make diagnosis possible.

A running record of agent-assisted development changes lives in `DEVLOG.md`.

After building, generated test applications are available in `build/test-apps`.

### Run Windows Notepad

From the project directory:

```powershell
build-release\cpuemu.exe C:\Windows\System32\notepad.exe --limit 100000000
```

Keep the terminal open while Notepad is running. Closing the Notepad window ends the guest and
returns control to the terminal.

To watch everything Notepad does through the emulator:

```powershell
build-release\cpuemu.exe C:\Windows\System32\notepad.exe --limit 100000000 -v --log-file notepad.log
```

## Architecture

- `Memory` owns checked guest mappings and rejects unmapped or disallowed accesses.
- `PeLoader` validates and maps PE32+ images and resolves their import tables.
- `Cpu` implements x86-64 fetch, decode, addressing, execution, and flags, and keeps a
  recent-instruction ring buffer for fault diagnostics.
- `Runtime` owns the stack, instruction budget, and controlled Win32 API thunks.
- `log` is the leveled logger shared by all components; it writes to stderr and optionally a
  log file, never to the guest program's stdout.

This is an early user-mode compatibility layer, not general Windows application compatibility yet.
Notepad's basic window and editor start, but guest threads are currently reported as unavailable,
thread-pool timers are inert, optional native COM objects are declined, and many x86-64, SIMD,
exception, TLS, NT, and callback-bearing API paths remain. These facilities need guest-side
scheduling and per-interface adapters rather than forwarding native pointers or callback addresses.
A JIT can be added behind the same runtime interfaces after correctness coverage is broader.

### Large applications

Large Chromium/Electron applications such as Discord are not usable yet. CPUEmu can load the
installed x64 Discord image, initialize its stack and static TLS, and execute more than 2.6 million
instructions through early V8 startup, command-line parsing, security queries, and file mapping,
but Chromium depends on a guest virtual-memory manager, interpreted guest threads, child guest
processes, DLL/TLS loading, exceptions, and much broader SIMD support. Basic private virtual-memory
reserve/commit/protect/query operations are tracked now, but Windows placeholder, mapped-section,
and write-watch semantics are not complete. CPUEmu deliberately refuses
to forward process/thread creation callbacks natively, because doing so would escape emulation and
attempt to execute guest addresses directly on the host.
