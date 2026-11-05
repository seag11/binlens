"""General-purpose register names."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class Register:
    name: str
    size: int  # width in bits

    def __str__(self) -> str:
        return self.name


def _bank(size: int, names: str) -> tuple[Register, ...]:
    return tuple(Register(name, size) for name in names.split())


# Indexed by register number 0-15 (the 3-bit ModRM/SIB/opcode field plus the REX extension bit).
GPR64 = _bank(64, "rax rcx rdx rbx rsp rbp rsi rdi r8 r9 r10 r11 r12 r13 r14 r15")
GPR32 = _bank(32, "eax ecx edx ebx esp ebp esi edi r8d r9d r10d r11d r12d r13d r14d r15d")
GPR16 = _bank(16, "ax cx dx bx sp bp si di r8w r9w r10w r11w r12w r13w r14w r15w")
GPR8 = _bank(8, "al cl dl bl spl bpl sil dil r8b r9b r10b r11b r12b r13b r14b r15b")

# Without a REX prefix, byte-register numbers 4-7 mean these instead of spl/bpl/sil/dil.
GPR8_HIGH = _bank(8, "ah ch dh bh")

RIP = Register("rip", 64)
EIP = Register("eip", 32)  # RIP-relative addressing under a 67 (address-size) prefix

_BY_SIZE = {16: GPR16, 32: GPR32, 64: GPR64}


def gpr(number: int, size: int, *, rex: bool = False) -> Register:
    """Register ``number`` (0-15) at ``size`` bits.

    ``rex`` says whether the instruction has a REX prefix, which only matters for byte
    registers 4-7: ``spl``/``bpl``/``sil``/``dil`` with REX, ``ah``/``ch``/``dh``/``bh`` without.
    """
    if size == 8:
        if not rex and 4 <= number <= 7:
            return GPR8_HIGH[number - 4]
        return GPR8[number]
    return _BY_SIZE[size][number]
