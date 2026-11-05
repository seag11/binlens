"""Decoded instructions and their operands."""

from __future__ import annotations

from dataclasses import dataclass

from binlens.x86.registers import EIP, RIP, Register


@dataclass(frozen=True, slots=True)
class RegisterOperand:
    reg: Register

    @property
    def size(self) -> int:
        return self.reg.size


@dataclass(frozen=True, slots=True)
class ImmediateOperand:
    """An immediate, already sign-extended where the encoding says so.

    ``value`` is the unsigned bit pattern at ``size`` bits, so ``83 c0 ff`` (``add eax, -1``)
    stores ``0xffffffff``. Use ``signed`` for the two's-complement reading.
    """

    value: int
    size: int

    @property
    def signed(self) -> int:
        if self.value >> (self.size - 1):
            return self.value - (1 << self.size)
        return self.value


@dataclass(frozen=True, slots=True)
class MemoryOperand:
    """``segment:[base + index*scale + disp]``, accessing ``size`` bits.

    ``base`` is ``RIP``/``EIP`` for RIP-relative operands. With neither base nor index, ``disp``
    is an absolute address (sign-extended from 32 bits, as the CPU does).
    """

    size: int
    base: Register | None
    index: Register | None
    scale: int  # 1, 2, 4 or 8; 1 when there is no index
    disp: int  # signed
    segment: str | None = None  # "fs" or "gs"; other overrides do nothing in 64-bit mode
    address_size: int = 64  # 32 under a 67 prefix

    @property
    def rip_relative(self) -> bool:
        return self.base is RIP or self.base is EIP


Operand = RegisterOperand | ImmediateOperand | MemoryOperand


@dataclass(frozen=True, slots=True)
class Instruction:
    address: int
    raw: bytes
    mnemonic: str
    operands: tuple[Operand, ...]
    prefixes: tuple[str, ...] = ()  # printed before the mnemonic: "lock", "rep"

    @property
    def length(self) -> int:
        return len(self.raw)

    @property
    def next_address(self) -> int:
        return self.address + len(self.raw)

    def memory_target(self, operand: MemoryOperand) -> int | None:
        """The absolute address a RIP-relative operand refers to, or None for other operands.

        RIP-relative displacements count from the end of the instruction, immediates included.
        """
        if not operand.rip_relative:
            return None
        return (self.next_address + operand.disp) & ((1 << operand.address_size) - 1)
