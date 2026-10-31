# Contributing to CPUEmu

Thanks for helping improve CPUEmu. Bug fixes, instruction implementations, Win32 adapters,
tests, documentation, and focused compatibility improvements are welcome.

## Before opening a pull request

1. Search existing issues and pull requests to avoid duplicating work.
2. For a large architectural change, open an issue first and describe the proposed design.
3. Keep each pull request focused on one related change.
4. Do not add copyrighted Windows binaries, application assets, credentials, logs containing
   private data, or generated build directories.

## Set up a development build

CPUEmu currently targets Windows and requires CMake, Ninja, and a C++20 compiler. With LLVM:

```powershell
git clone https://github.com/arcwiser/cpu-emu.git
cd cpu-emu
cmake -S . -B build -G Ninja -DCMAKE_CXX_COMPILER=clang++ -DCMAKE_BUILD_TYPE=Release
cmake --build build
ctest --test-dir build --output-on-failure
```

Run the included end-to-end guest smoke test with:

```powershell
build\cpuemu.exe build\test-apps\paint.exe -- --selftest
```

## Make a change

- Create a branch such as `feat/packed-simd` or `fix/pe-validation`.
- Follow the existing four-space C++ style and run `clang-format` on changed C++ files.
- Compile with warnings enabled; the core library treats Clang warnings as errors.
- Add a regression test for instruction semantics, loader validation, or runtime behavior when
  practical.
- Update `README.md` for user-facing behavior and `DEVLOG.md` for significant compatibility
  milestones.

### Emulator safety rules

- Guest addresses are not host function pointers. Never let Windows execute a guest callback
  directly; route callbacks through `Runtime::invoke_guest` or a purpose-built bridge.
- Do not return raw host pointers to guest code. Copy returned data into checked guest memory and
  translate nested pointers where necessary.
- Keep unsupported process, thread, asynchronous callback, and COM paths safely refused until a
  guest-aware implementation exists.
- Validate guest ranges and integer arithmetic before reading, writing, mapping, or allocating.
- Implement architectural flags and operand widths precisely; do not special-case one application.

## Commit style

Use short conventional commit subjects:

- `feat: implement PSHUFB`
- `fix: sign extend 64-bit immediates`
- `test: cover TLS callback ordering`
- `docs: explain guest memory adapters`
- `refactor: share packed lane helpers`

## Open the pull request

Push your branch to your fork and open a pull request against `arcwiser/cpu-emu:main`. Complete the
pull-request template with:

- what changed and why;
- how it was tested;
- applications or instruction sequences affected;
- known limitations or follow-up work.

Maintainers may request smaller commits, additional tests, or changes that keep guest and host
state isolated. Once review and checks are complete, the pull request can be merged.
