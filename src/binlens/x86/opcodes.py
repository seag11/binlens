"""Opcode table for the supported instruction subset.

Operand kinds use the notation of the Intel SDM opcode map (Vol. 2, Appendix A.2):

    Eb, Ev   ModRM.rm: a register or memory operand, byte / operand-size
    Gb, Gv   ModRM.reg: a register, byte / operand-size
    Zb, Zv   a register in the low 3 bits of the opcode (extended by REX.B)
    AL, rAX  the accumulator, fixed by the opcode
    Ib, Iw   an 8-bit / 16-bit immediate
    sIb      an 8-bit immediate sign-extended to the operand size
    Iz       16 bits with a 16-bit operand size, else 32 bits sign-extended to the operand size
    Iv       the full operand size: 16, 32 or 64 bits

Widening the instruction set should mostly mean adding rows here.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class OpSpec:
    mnemonic: str
    operands: tuple[str, ...] = ()
    lockable: bool = False  # LOCK is allowed (only ever with a memory destination)
    allow_rep: bool = False  # an F3 prefix is accepted and printed as "rep"
    # 66 on near branches behaves differently on Intel and AMD, so reject it rather than guess.
    allow_opsize_override: bool = True
    mnemonic64: str | None = None  # replaces the mnemonic at 64-bit operand size

    @property
    def has_modrm(self) -> bool:
        return any(kind[0] in "EG" for kind in self.operands)


# Opcodes where ModRM.reg is part of the opcode ("83 /0" is add, "83 /7" is cmp).
GROUPS: dict[int, dict[int, OpSpec]] = {
    0xC6: {0: OpSpec("mov", ("Eb", "Ib"))},
    0xC7: {0: OpSpec("mov", ("Ev", "Iz"))},
}

ONE_BYTE: dict[int, OpSpec] = {
    0x88: OpSpec("mov", ("Eb", "Gb")),
    0x89: OpSpec("mov", ("Ev", "Gv")),
    0x8A: OpSpec("mov", ("Gb", "Eb")),
    0x8B: OpSpec("mov", ("Gv", "Ev")),
    # "rep ret" (F3 C3) is a common padding idiom in compiler output.
    0xC2: OpSpec("ret", ("Iw",), allow_rep=True, allow_opsize_override=False),
    0xC3: OpSpec("ret", (), allow_rep=True, allow_opsize_override=False),
}

# The eight arithmetic/logic operations share one layout. Operation n owns opcodes
# n*8 + 0..5, and is /n in the immediate groups 80, 81 and 83. (n*8 + 6 and 7 are segment
# prefixes or invalid in 64-bit mode; 82 is an invalid alias of 80.) cmp only reads its
# destination, so it can't take LOCK.
ALU_OPERATIONS = ("add", "or", "adc", "sbb", "and", "sub", "xor", "cmp")

GROUPS[0x80], GROUPS[0x81], GROUPS[0x83] = {}, {}, {}
for _n, _mnemonic in enumerate(ALU_OPERATIONS):
    _lockable = _mnemonic != "cmp"
    ONE_BYTE[_n * 8 + 0] = OpSpec(_mnemonic, ("Eb", "Gb"), lockable=_lockable)
    ONE_BYTE[_n * 8 + 1] = OpSpec(_mnemonic, ("Ev", "Gv"), lockable=_lockable)
    ONE_BYTE[_n * 8 + 2] = OpSpec(_mnemonic, ("Gb", "Eb"))
    ONE_BYTE[_n * 8 + 3] = OpSpec(_mnemonic, ("Gv", "Ev"))
    ONE_BYTE[_n * 8 + 4] = OpSpec(_mnemonic, ("AL", "Ib"))
    ONE_BYTE[_n * 8 + 5] = OpSpec(_mnemonic, ("rAX", "Iz"))
    GROUPS[0x80][_n] = OpSpec(_mnemonic, ("Eb", "Ib"), lockable=_lockable)
    GROUPS[0x81][_n] = OpSpec(_mnemonic, ("Ev", "Iz"), lockable=_lockable)
    GROUPS[0x83][_n] = OpSpec(_mnemonic, ("Ev", "sIb"), lockable=_lockable)
del _n, _mnemonic, _lockable

for _reg in range(8):
    ONE_BYTE[0xB0 + _reg] = OpSpec("mov", ("Zb", "Ib"))
    # With REX.W this takes a full 64-bit immediate; Capstone and objdump call that form movabs.
    ONE_BYTE[0xB8 + _reg] = OpSpec("mov", ("Zv", "Iv"), mnemonic64="movabs")
del _reg
