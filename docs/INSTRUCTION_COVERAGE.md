# Instruction coverage

This is CPUEmu's human-auditable instruction inventory. It tracks architectural behavior rather
than marketing totals: a mnemonic is not complete unless its implemented register/memory forms,
operand widths, prefixes, flags, sign extension, address calculation, and failure behavior agree
with the architecture.

Legend:

- 🟩 **Broad** — the commonly used forms are regression-backed in both applicable modes.
- 🟨 **Partial** — useful forms exist, but the family or encoding matrix is incomplete.
- 🟧 **Initial** — a narrow startup/compatibility subset exists.
- ⬜ **Planned** — recognized as required, but not implemented as a dependable family.

The [visual completion map](assets/instruction-status.svg) is generated from
[`instruction-atlas.csv`](instruction-atlas.csv). Every cell maps to one named catalog entry, but
entries deliberately mix individual mnemonics, grouped condition families, encoding subsets, and
architectural capabilities; they are not equal-sized encoding units or a percentage denominator.
`src/core/cpu_execute.cpp` and `tests/cpu_tests.cpp` remain authoritative when documentation and code
disagree.

## Compatibility impact map

Instruction work is prioritized by reusable architectural value and reproducible evidence, not by
one application's instruction address. This table connects known gaps to the kinds of workloads
they can unlock while keeping non-CPU blockers visible.

| Coverage area | Evidence or affected workload | Required work | Verification target | Non-instruction dependencies |
| --- | --- | --- | --- | --- |
| x87 completeness | Older x86 games and CRT/math paths | Comparisons, status flags, 80-bit values, remaining arithmetic/transcendentals, exceptions | Focused stack/control/rounding tests plus an older-game probe | Win32, graphics, and audio still apply |
| MMX moves/state | Legacy multimedia/game code | Complete `MOVD`/`MOVQ`, register/memory widths, MMX↔x87 state rules | Encoding matrix and state-transition regressions | Media APIs and timing |
| SSE/SSE2 audit | Notepad, GameMaker, Chromium startup | Finish register/memory/prefix variants and exact scalar lane preservation | Generated form matrix plus current app probes | Threads/COM/graphics for deeper progress |
| SSE3/SSSE3 | Modern runtimes and codecs | Complete advertised-family requirements beyond selected operations | Family tests with `CPUID` remaining gated until complete | DLL loading and exception delivery |
| SSE4.1/SSE4.2 | Chromium/V8 and newer application libraries | Complete packed integer forms, string compare, CRC behavior | V8 startup delta plus independent opcode regressions | Guest processes, threads, mapped sections |
| BMI1/BMI2 | Modern compiler output | Widths, zero-input behavior, flags, memory forms, feature gating | Compiler-generated fixture and edge-value tests | Usually not the first current blocker |
| Exception delivery | Divide/access/illegal-instruction recovery and C++ runtimes | Guest exception records, stack dispatch/unwind, handler ABI | Controlled fault/handler fixtures | Loader metadata and per-thread state |
| AVX/AVX2 | Newer codecs, browsers, game middleware | VEX decode, YMM state, context switching, `CPUID`/XSAVE contract | Generated encoding/state tests before advertising | Scheduler and exception/context model |

The current Undertale blocker is **not** an instruction gap: it is the Direct3D 9Ex interface
boundary. Filling the instruction atlas alone cannot make a game playable; Win32 APIs, graphics,
input, audio, threading, loading, services, and persistence are independent compatibility axes.

## Execution modes

| Area | x86 PE32 | x86-64 PE32+ | Status |
| --- | :---: | :---: | :---: |
| General-purpose registers and subregister writes | Yes | Yes, including REX | 🟩 |
| Effective addressing | 32-bit ModRM/SIB/absolute | ModRM/SIB/RIP-relative | 🟩 |
| Stack/call/return width | 4 bytes | 8 bytes | 🟩 |
| Segment base used by applications | `FS` | `GS` | 🟩 |
| Legacy one-byte `INC`/`DEC` | Yes | REX occupies those opcodes | 🟩 |
| `moffs` absolute moves | 32-bit addresses | 64-bit addresses | 🟩 |

## Integer, data movement, and flags

| Status | Implemented mnemonic groups | Important scope |
| :---: | --- | --- |
| 🟩 | `MOV`, immediate `MOV`, `MOVSX`, `MOVZX`, `LEA`, `XCHG` | Register and checked-memory forms across implemented widths |
| 🟩 | `PUSH`, `POP`, `PUSHF`, `POPF`, `LEAVE` | Mode-correct stack width and x86 callback stacks |
| 🟩 | `ADD`, `ADC`, `SUB`, `SBB`, `CMP`, `INC`, `DEC`, `NEG` | Arithmetic flags and immediate groups |
| 🟩 | `AND`, `OR`, `XOR`, `TEST`, `NOT` | Register, memory, and immediate groups |
| 🟩 | `MUL`, `IMUL`, `DIV`, `IDIV` | One-operand and common immediate/two-operand forms |
| 🟩 | `SHL`/`SAL`, `SHR`, `SAR`, `ROL`, `ROR` | Immediate, one-bit, and `CL` counts where decoded |
| 🟩 | `CBW`/`CWDE`/`CDQE`, `CWD`/`CDQ`/`CQO` | Mode- and operand-size-aware sign extension |
| 🟩 | `LAHF`, `SAHF`, `CLC`, `STC`, `CLD`, `STD` | User-mode flag transfer/control used by current guests |
| 🟩 | `NOP`, multi-byte NOP/prefetch hints, `WAIT`/`FWAIT` | Hints are architecturally inert; deferred x87 faults are not modeled |

## Control flow and conditions

| Status | Implemented mnemonic groups | Important scope |
| :---: | --- | --- |
| 🟩 | `JMP`, `CALL`, `RET` | Relative and decoded indirect forms; x86/x64 return widths |
| 🟩 | `Jcc` condition family | Short and near branches using interpreted flags |
| 🟩 | `CMOVcc`, `SETcc` condition families | Register destinations and decoded memory sources |
| 🟩 | Direct/indirect import thunk calls | Runtime ABI boundary, not native execution of guest code |
| ⬜ | Far calls/returns, task gates, privilege transitions | Outside the current user-mode process model |

## String instructions

| Status | Instructions | Behavior covered |
| :---: | --- | --- |
| 🟩 | `MOVSB`, `MOVSW`, `MOVSD`, `MOVSQ` | `REP`, direction flag, address-size count/index semantics |
| 🟩 | `STOSB`, `STOSW`, `STOSD`, `STOSQ` | `REP`, direction flag, width-correct accumulator |
| 🟩 | `SCASB`, `SCASW`, `SCASD`, `SCASQ` | `REP`/`REPE`/`REPNE`, flags, direction and count |
| 🟨 | `CMPS*`, `LODS*`, port strings | Not a complete audited family yet |

## Bit operations and system queries

| Status | Instructions | Notes |
| :---: | --- | --- |
| 🟩 | `BT`, `BTS`, `BTR`, `BTC` | Selected register/memory and immediate forms |
| 🟩 | `BSF`, `BSR`, `POPCNT`, `LZCNT`, `TZCNT` | Scalar widths implemented; advertised features are gated |
| 🟨 | `CPUID` | Filtered synthetic feature leaves; never mirrors unsafe host features blindly |
| 🟨 | `RDTSC` | Host-clock-backed timestamp behavior, not deterministic virtualization |
| ⬜ | `RDTSCP`, `RDRAND`, `RDSEED`, `XSAVE*`, `XRSTOR*` | Not advertised |
| ⬜ | Privileged control/debug/MSR/descriptor instructions | Deliberately outside current user-mode scope |

## x87 floating point

The x87 stack and control word are independent state; they are not aliases of XMM registers.

| Status | Implemented operations |
| :---: | --- |
| 🟧 | `FLD` for `m32real`, `m64real`, and `ST(i)`; constants `FLD1`, `FLDL2T`, `FLDL2E`, `FLDPI`, `FLDLG2`, `FLDLN2`, `FLDZ` |
| 🟧 | `FST`/`FSTP` for `m32real` and `m64real` |
| 🟧 | Memory `FADD`, `FMUL`, `FSUB`, reverse subtract, `FDIV`, reverse divide in implemented D8/DC forms |
| 🟧 | `FSUBP`, `FSIN`, `FCOS` |
| 🟧 | `FILD m32int`, `FILD m64int`, `FISTP m64int` with control-word rounding |
| 🟧 | `FLDCW`, `FNSTCW`, `FNSTSW AX`, `FNCLEX`, `FNINIT`, `WAIT` |
| ⬜ | Complete comparisons/status flags, 80-bit memory values, BCD, remainder, transcendental and exception semantics |

## SIMD and packed integer coverage

| Family | Status | Implemented or observed forms |
| --- | :---: | --- |
| SSE | 🟨 | Scalar single moves/arithmetic and conversions; packed single arithmetic; logical operations; unpack and shuffle forms used by current guests |
| SSE2 | 🟨 | Packed double arithmetic; scalar double conversions; XMM moves; packed integer add/subtract, compare, unpack, shuffle, byte shifts, and `PMOVMSKB` subsets |
| SSE3 | 🟨 | `MOVDDUP`, `LDDQU`, horizontal add/subtract, alternating add/subtract |
| SSSE3 | 🟨 | `PSHUFB`, horizontal packed add/subtract variants, `PMADDUBSW`, `PSIGNB/W/D`, `PMULHRSW`, `PALIGNR`, `PABSB/W/D` |
| SSE4.1 | 🟨 | `PTEST`, `PACKUSDW`, signed/unsigned packed min/max subset, `PMULLD` |
| MXCSR | 🟨 | `LDMXCSR`, `STMXCSR`; complete SIMD exception delivery is not modeled |
| MMX | 🟧 | Initial decode/state only; the MMX `MOVD`/`MOVQ` matrix remains incomplete |
| SSE4.2 | ⬜ | String/CRC family not implemented or advertised |
| AVX/AVX2/AVX-512 | ⬜ | VEX/EVEX decode and extended vector state not implemented |
| AES/PCLMUL/SHA | ⬜ | Not implemented or advertised |

### Named SIMD operations currently represented

This checklist is intentionally mnemonic-level, not a guarantee for every encoding:

```text
MOVSS      MOVSD      MOVQ(XMM)  MOVDDUP    LDDQU      MOVAPS/MOVUPS-family moves
ADDSS      SUBSS      MULSS      DIVSS      ADDPS      SUBPS      MULPS      DIVPS
ADDPD      SUBPD      MULPD      DIVPD      MIN*/MAX*  ORPS/ORPD  UNPCKLPS
CVTSI2SS   CVTTSS2SI  CVTSS2SD   CVTSD2SS   PSHUFD     PSHUFLW    PSHUFHW
PADDB/W/D/Q            PSUBB/W/D/Q           PUNPCKL/HBW/WD/DQ
PSRLDQ     PSLLDQ     PMOVMSKB   PSHUFB     PHADD*     PHSUB*
PMADDUBSW  PSIGNB/W/D  PMULHRSW  PALIGNR    PABSB/W/D  PTEST
PACKUSDW   PMIN*/PMAX*            PMULLD
```

`MIN*`, `MAX*`, `PHADD*`, and `PHSUB*` denote only the decoded variants in the current source.
Consult focused tests before relying on a particular lane width, signedness, prefix, or memory form.

## Prefixes and encoding dimensions

The decoder currently accounts for the dimensions below where the target opcode implements them:

- Operand-size override (`66`) and address-size override (`67`).
- `REP`/`REPE` (`F3`) and `REPNE` (`F2`) for string behavior and mandatory SIMD prefixes.
- Segment overrides needed by guest code, especially `FS` in x86 and `GS` in x86-64.
- REX register extension and 64-bit operand selection.
- ModRM register/memory selection, SIB addressing, displacement-only forms, and RIP-relative
  addresses including trailing immediates.

Locking, atomicity, and every legacy segment/prefix interaction are not yet a complete matrix.

## Feature-advertising rule

`CPUID` exposes an optional feature only when software may safely rely on the family CPUEmu claims.
`POPCNT` and `LZCNT` are advertised independently because their scalar forms are implemented.
SSSE3, SSE4.x, BMI, AVX, AES, XSAVE, and random-number families stay hidden until their required
instruction/state contracts are complete enough for general software.

## Completion requirements

An instruction family moves toward 🟩 only when it has:

1. Register and memory coverage where the architecture defines both.
2. Applicable 8/16/32/64-bit or lane-width tests.
3. Prefix, sign-extension, high-byte/REX, and address-size tests.
4. Exact defined flag behavior and no reliance on undefined flags.
5. Boundary and fault behavior through checked guest memory.
6. Correct `CPUID` advertising, or an explicit reason the family stays hidden.

New CPU behavior belongs in `src/core/cpu_execute.cpp` with compact machine-code regressions in
`tests/cpu_tests.cpp`. Application-address-specific instruction patches are not accepted.
