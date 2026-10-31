# TODO – CPUEmu compatibility improvements

- Add support for `PSHUFB` SIMD instruction (packed byte shuffle) in `src/cpu.cpp`.
- Implement missing MMX move operations (`MOVQ`, `MOVD`) in the MMX instruction group.
- Extend the import resolver to handle delayed-load APIs that return function pointers (e.g., `GetProcAddress` for callbacks) safely.
- Add a runtime adapter for `CreateThread` that creates a guest‑visible thread context and marshals callbacks.
- Implement basic support for COM `IUnknown` interface queries in the Win32 compatibility layer.
- Write regression tests for each new instruction/adapter in `tests/tests.cpp`.
- Update `DEVLOG.md` with a summary of added compatibility features.
