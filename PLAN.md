# binlens: project plan

A static analyser for Windows executables, written from scratch. Point it at an `.exe`: it parses the file, disassembles the code to x86-64 assembly, and flags suspicious capabilities. It never runs the binary.

```
program.exe ──► PE loader ──► code bytes + addresses ──► decoder ──► assembly listing
                                                                       │
                                                                       ▼
                                                             capability rules ──► findings
```

Example output:

```
0x140001000  48 83 ec 28        sub   rsp, 0x28
0x140001004  e8 37 00 00 00     call  0x140001040
0x140001009  33 c9              xor   ecx, ecx

[anti-debug] rdtsc timing check at 0x1400012a0
```

## Why it's worth building

- Assembly is the level analysts actually work at. A decompiler is a convenience on top of it, and an unreliable one on obfuscated code.
- It's static: it reads the file's bytes and never executes the binary.
- Pairs with dgalens: same habits (a hand-written core, measured evaluation, honest limits), applied to binaries instead of domains.

## Milestones

Each one is a complete stopping point.

### 1. Decoder (2–4 weekends)

Turn raw bytes into instructions. Start by decoding a hex string or raw blob, before any file parsing.

Steps per instruction:

1. **Prefixes**: legacy (`66` operand size, `67` address size, `F2`/`F3`, segment), then REX (`40`–`4F`: W = 64-bit operands, R/X/B extend registers to r8–r15).
2. **Opcode**: 1 byte, or 2–3 bytes after `0F`. Some opcodes take the actual instruction from ModRM.reg (`83 /0` = `add`, `83 /7` = `cmp`).
3. **ModRM, SIB, displacement**, where most bugs live:
   - `rm=100` → a SIB byte follows
   - `mod=00, rm=101` → RIP-relative in 64-bit mode
   - SIB `base=101` with `mod=00` → no base register, disp32
   - r12 and r13 inherit those same quirks
4. **Immediate**: 1, 2, 4, or (rarely) 8 bytes.
5. **Operand size**: 32-bit default; REX.W → 64; `66` → 16. With any REX prefix, the encodings for `ah`/`ch`/`dh`/`bh` become `spl`/`bpl`/`sil`/`dil`.

Worked example:

```
48 8b 44 24 08   →   mov rax, [rsp+8]

48  REX     W=1 → 64-bit operands
8b  opcode  MOV r64, r/m64
44  ModRM   mod=01 (disp8), reg=000 (rax), rm=100 (SIB follows)
24  SIB     scale=1, index=none, base=rsp
08  disp8   +8
```

**Scope:** the integer instructions compilers emit: `mov`, `lea`, `add`/`sub`/`and`/`or`/`xor`/`cmp`/`test`, `push`/`pop`, `call`/`ret`/`jmp`/`jcc`, `inc`/`dec`, `imul`, shifts, `movzx`/`movsx`, `setcc`, `cmovcc`, `cdq`/`cqo`, `nop`.

**Out of scope:** SSE/AVX (VEX/EVEX), x87, 16-bit and 32-bit modes. List these in the README.

Order of work: `mov`, `add` and `ret` with full ModRM/SIB/REX handling first, then widen the instruction set until a small `-O0` C program disassembles cleanly.

### 2. PE loader (1–2 weekends)

Parse the headers (DOS header → PE signature → COFF header → optional header → section table) to get `.text`, its virtual address, the image base, the entry point, and the import table.

Then disassemble:

- Start with **linear sweep**: decode `.text` from start to end. Padding and jump tables mixed into the code can throw it out of step.
- Upgrade later to **recursive descent**: follow jumps and calls from the entry point. This is how real disassemblers work.

The loader alone already yields useful signals: imported APIs, section entropy (packed or encrypted code), a tiny import table, or an entry point in an unusual section.

### 3. Capability rules (2–3 weekends)

Rules that run over the disassembly and report what the code can do, with an address for each finding.

| Capability                    | Pattern                                                                                |
| ----------------------------- | -------------------------------------------------------------------------------------- |
| Anti-debugging                | `rdtsc` timing pairs, `cpuid`, reads of the debugger flag through `gs:[0x60]`          |
| Encoded data                  | XOR-decoding loops (load, `xor` with key, store, advance pointer, loop)                |
| Resolving APIs by name hash   | a loop of `rol`/`ror` + `xor`/`add` over a string, then a compare with a constant      |
| Direct system calls           | `syscall` instructions in ordinary application code                                    |
| Likely packed                 | high-entropy sections combined with very few imports                                   |

Prior art: Mandiant's open-source capa does this at full scale. Say so in the README. A small version on a decoder you wrote yourself is the point, not novelty.

### 4. Optional: emulator (3–5 weekends)

Execute instructions in software: 16 general registers, RIP, RFLAGS, sparse paged memory, a stack, and a fetch–decode–execute loop.

- **Flags (CF, OF, ZF, SF, PF) are where the time goes.** Every conditional jump depends on them.
- **Showcase:** run a self-decrypting string routine from a crackme-style sample and print the strings it recovers, without ever executing the binary natively.

## Validation

This is what makes the project credible.

- **Differential testing:** disassemble real binaries and compare with a reference (Capstone or `llvm-objdump`), instruction by instruction. Publish the match rate within the supported subset.
- **Fuzzing:** feed random bytes to the decoder. It must never crash, never read past its input, and always return either a length or a rejection. A crashing decoder is itself a security bug.
- **Labelled samples:** each capability rule gets a small, benign C program that exhibits exactly that pattern, plus clean programs that must stay quiet. These work like dgalens's synthetic generators.
- **Emulator:** compare full register state after each step against a real CPU or a debugger.

## Ground rules

- **No live malware, ever.** Test only on programs you wrote and compiled yourself.
- **No decompiler.** It's research-grade and not needed for any of the goals above.
- **Check licences** of any reference tool or dataset before depending on it.
- **Test binaries** must be cross-compiled for Windows x86-64 (e.g. `zig cc -target x86_64-windows-gnu`, or MinGW). Native macOS binaries are Mach-O, and ARM on Apple Silicon.

## Open decisions

- **Language: leaning Python** (production experience).
  - Python: fast to write, and matches dgalens. Fuzz with Hypothesis or atheris. Speed is fine at this scale.
  - Rust: shows more range and suits the low-level theme, but would mean learning the language on a hard project.
  - Middle path: build in Python, then later port only the decoder to Rust as a learning exercise. The differential tests make the port safe to check.
- **Output syntax.** Intel is the recommended choice: Windows tools and most analysts use it. AT&T is the alternative.

## References

- Intel 64 and IA-32 Architectures Software Developer's Manual, Volume 2 (instruction encoding)
- Microsoft's PE format specification (learn.microsoft.com, "PE Format")
- Capstone and `llvm-objdump` as differential-testing oracles
- capa (Mandiant), as prior art for capability rules
