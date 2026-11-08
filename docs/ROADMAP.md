# CPUEmu roadmap

This roadmap records measurable compatibility work, not release promises or dates. Priorities may
change when a smaller regression exposes a more fundamental correctness issue.

## Current vertical target: Undertale first frame

```text
[x] PE32 load and x86 execution
[x] CRT, TLS, heap, files, paths, environment
[x] Parse data.win and reach GameMaker startup
[x] Register class and create native HWND with interpreted callbacks
[x] Safe DirectInput discovery and display enumeration
[ ] Direct3DCreate9Ex guest interface
[ ] Adapter/capability/mode queries
[ ] Device creation and presentation parameters
[ ] Clear/begin/end/present a first frame
[ ] Texture, surface, buffer, state, and shader interfaces used by the runner
[ ] Active keyboard/mouse delivery
[ ] Streaming audio backend selected by the runner
[ ] Sustained message/game loop with persistence
```

“First frame” requires a visible window with a frame produced through interpreted guest calls. It
does not mean playable. “Playable” additionally requires stable input, audio, timing, persistence,
scene transitions, and a sustained run.

## CPU correctness

- Complete the MMX `MOVD`/`MOVQ` form matrix and define MMX/x87 state transitions.
- Finish coherent SSE/SSE2 form audits before expanding optional feature advertising.
- Complete SSE3, SSSE3, SSE4.1, and SSE4.2 with register/memory/width regressions.
- Add BMI1/BMI2 only with exact flags, zero-count behavior, widths, and `CPUID` gating.
- Add a generated encoding matrix so supported forms and missing cases are mechanically auditable.
- Deliver guest exception state for divide errors, access violations, illegal instructions, and
  language-runtime unwinding.

Completion condition: each advertised family has a documented form matrix and focused tests for
prefixes, widths, memory/register operands, flags, and architectural boundaries.

## Runtime and Windows compatibility

- Build a guest-thread scheduler with independent CPU, stack, TEB, TLS, and last-error state.
- Add a guest DLL loader with architecture checks, imports, TLS callbacks, and module lifetimes.
- Expand delay-import and `GetProcAddress` handling without returning native unsafe callbacks.
- Create reusable guest-owned COM proxy infrastructure with `IUnknown`, reference counts, queried
  interfaces, method ABI metadata, and deterministic teardown.
- Add mapped-section/file-mapping semantics, exceptions, synchronization, and message waits needed
  by larger applications.

Completion condition: no supported API relies on exposing a host pointer or executing guest code
natively; success, failure, ownership, and lifetime paths are regression-backed.

## Graphics, input, audio, and services

- Direct3D 9Ex adapter/device/resource interfaces for GameMaker.
- Active DirectInput keyboard/mouse state with focus and cooperative-level behavior.
- Streaming audio through the backend actually selected by the guest, with guest-safe buffer and
  callback lifetimes.
- Offline Steamworks guest proxy for optional stats/achievements behavior.
- Authenticated Steam integration only through an explicit 32-bit helper process and marshaled IPC;
  never bypass ownership checks or load a 32-bit DLL into the 64-bit host.

## Tooling and project health

- Add CI for Clang release builds, unit tests, Paint self-test, formatting, and diff hygiene.
- Generate documentation coverage data from source/test metadata instead of hand-maintained
  percentages.
- Add deterministic benchmark scenarios for decoder/memory/runtime regressions.
- Grow controlled guest fixtures for callbacks, COM vtables, x86 ABI, graphics, and audio.
- Keep compatibility reports tied to commit, guest version, command, milestone, and first blocker.

## Non-goals for the current stage

- Kernel, driver, ring-0, boot, or full operating-system emulation.
- Native execution of untrusted guest code or callbacks.
- Application-address patches that bypass missing general behavior.
- Claims of broad game compatibility based on a title screen or one rendered frame.
