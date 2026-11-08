## Summary

<!-- What changed, and why is this the right general solution? -->

## AI assistance disclosure

<!-- This section is required. Write "none" if no AI tool was used. -->

- **Level:** none / assisted / substantial
- **Tool/model:**
- **Files or work materially generated/transformed:**
- **Human review performed:**
- **Primary specifications/API references checked:**
- **AI-originated behavior not independently verified:**

## Technical details

<!-- Mention relevant opcodes, ABI rules, guest-memory ownership, or Win32 adapters. -->

## Testing

<!-- List exact commands, environment, and results. Do not write only "tests pass." -->

### Focused regression

<!-- New/changed test names and what each proves. -->

### Commands and results

```text
Paste the exact commands and PASS/FAIL/BLOCKED results here.
```

- [ ] Release build succeeds
- [ ] `ctest --test-dir build --output-on-failure` passes
- [ ] Paint self-test passes, or is not affected
- [ ] Changed C++ files were formatted
- [ ] `git diff --check` reports no errors
- [ ] Every skipped/blocked check is explained below

### Skipped, blocked, or unverified

<!-- Write "none" or explain the reason and risk. -->

## Safety and compatibility

- [ ] No guest callback is executed directly by the host
- [ ] No raw host-owned pointer is exposed to guest code
- [ ] The change is general and does not special-case an application address
- [ ] Guest pointer ranges, sizes, and integer overflow are validated
- [ ] Cross-bitness structures and calling conventions were audited where applicable
- [ ] Optional CPU features are not advertised before their contract is complete
- [ ] Known limitations and follow-up work are documented

## Ownership and lifetime notes

<!-- For runtime/ABI changes: who owns each pointer/handle/interface and for how long? -->

## Applications or cases tested

<!-- Include version, architecture, command, instruction limit, milestone, and first blocker. -->

## Documentation and repository hygiene

- [ ] Relevant instruction/Windows/game compatibility document is updated, or not affected
- [ ] No build output, executable, log, dump, credential, proprietary binary, or game asset added
- [ ] No unrelated formatting, generated rewrite, or dependency change included
- [ ] Compatibility wording precisely distinguishes load/start/window/render/playable states

## Known limitations and follow-up work

<!-- Be explicit. Write "none" only when there truly are no known limits. -->
