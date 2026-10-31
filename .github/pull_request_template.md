## Summary

<!-- What changed, and why is this the right general solution? -->

## Technical details

<!-- Mention relevant opcodes, ABI rules, guest-memory ownership, or Win32 adapters. -->

## Testing

<!-- List exact commands and results. Include focused regression tests and compatibility probes. -->

- [ ] Release build succeeds
- [ ] `ctest --test-dir build --output-on-failure` passes
- [ ] Paint self-test passes, or is not affected
- [ ] Changed C++ files were formatted
- [ ] `git diff --check` reports no errors

## Safety and compatibility

- [ ] No guest callback is executed directly by the host
- [ ] No raw host-owned pointer is exposed to guest code
- [ ] The change is general and does not special-case an application address
- [ ] Known limitations and follow-up work are documented

## Applications or cases tested

<!-- List guest fixtures, Windows applications, or minimal instruction sequences. -->
