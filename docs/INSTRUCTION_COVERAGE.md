# Instruction coverage

CPUEmu tracks instruction support by architectural behavior and encoding family, not by a raw
instruction-name count. Prefixes, operand widths, ModRM forms, memory addressing, flags, and edge
cases can make one mnemonic represent many distinct behaviors; claiming “3,000 instructions”
without those semantics would be misleading.

## Current coverage areas

- Core integer moves, arithmetic, logic, comparisons, shifts, rotates, branches, calls, returns,
  stack operations, string moves/stores, multiply, and divide.
- Conditional branches, conditional moves, set-on-condition, bit tests/modification, `BSF`, `BSR`,
  `POPCNT`, `LZCNT`, and `TZCNT`.
- Selected SSE/SSE2 packed and scalar moves, arithmetic, comparisons, unpacking, shuffling, and
  byte shifts. SSE3 coverage includes duplicate loads, unaligned loads, horizontal packed
  add/subtract, and alternating packed add/subtract.
- Selected SSSE3 operations: `PSHUFB`, horizontal packed add/subtract variants, `PMADDUBSW`,
  `PSIGNB/W/D`, `PMULHRSW`, `PALIGNR`, and `PABSB/W/D`.
- System-query operations needed in user mode, including filtered `CPUID` and `RDTSC`.

## Feature-advertising rule

`CPUID` exposes an optional feature only when software may safely rely on its required instruction
set. CPUEmu advertises `POPCNT` and `LZCNT` now that their complete scalar forms are implemented.
It does not yet advertise SSSE3 or BMI1 as families because only selected operations are present.

## Expansion priorities

1. Complete coherent SSE3, SSSE3, SSE4.1, and SSE4.2 families with register and memory tests.
2. Add BMI1/BMI2 only alongside correct flags, widths, and `CPUID` gating.
3. Add x87 and MMX state rather than aliasing them onto XMM storage.
4. Add exception delivery for divide, access, and illegal-instruction faults.
5. Build a generated encoding matrix so every supported form has an auditable regression.

New CPU behavior belongs in `src/cpu.cpp` and should include compact machine-code regressions in
`tests/tests.cpp`. Application-address-specific patches are not accepted.
