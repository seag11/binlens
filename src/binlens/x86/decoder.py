"""x86-64 instruction decoder, 64-bit mode only.

Decodes one instruction at a time. An instruction is laid out as::

    [legacy prefixes] [REX] opcode [ModRM [SIB] [displacement]] [immediate]

Only the opcodes in :mod:`binlens.x86.opcodes` are decoded; anything else raises
:class:`UnsupportedInstruction` instead of being guessed at.

Out of scope: SSE/AVX (VEX/EVEX), x87, and 16-bit and 32-bit modes.
"""

from __future__ import annotations

from binlens.x86.errors import InvalidInstruction, TruncatedInstruction, UnsupportedInstruction
from binlens.x86.instruction import (
    ImmediateOperand,
    Instruction,
    MemoryOperand,
    Operand,
    RegisterOperand,
)
from binlens.x86.opcodes import GROUPS, ONE_BYTE, OpSpec
from binlens.x86.registers import EIP, GPR8, RIP, Register, gpr

MAX_LENGTH = 15

# In 64-bit mode CS/DS/ES/SS overrides have no effect; only FS and GS change the address.
_SEGMENT_PREFIXES = {0x26: None, 0x2E: None, 0x36: None, 0x3E: None, 0x64: "fs", 0x65: "gs"}

_REX_W, _REX_R, _REX_X, _REX_B = 8, 4, 2, 1

Bytes = bytes | bytearray | memoryview


class _Reader:
    """Cursor over one instruction, enforcing the input end and the 15-byte limit."""

    __slots__ = ("_data", "_start", "pos")

    def __init__(self, data: Bytes, start: int) -> None:
        self._data = data
        self._start = start
        self.pos = start

    def _take(self, n: int) -> int:
        pos = self.pos
        if pos + n - self._start > MAX_LENGTH:
            raise InvalidInstruction(f"longer than {MAX_LENGTH} bytes", self._start)
        if pos + n > len(self._data):
            raise TruncatedInstruction("input ends mid-instruction", self._start)
        self.pos = pos + n
        return pos

    def u8(self) -> int:
        return self._data[self._take(1)]

    def signed(self, n: int) -> int:
        pos = self._take(n)
        return int.from_bytes(self._data[pos : pos + n], "little", signed=True)

    def unsigned(self, n: int) -> int:
        pos = self._take(n)
        return int.from_bytes(self._data[pos : pos + n], "little")


def decode(data: Bytes, offset: int = 0, address: int = 0) -> Instruction:
    """Decode the instruction starting at ``data[offset]``.

    ``address`` is the virtual address of ``data[offset]``; it sets ``Instruction.address`` and
    so the targets of RIP-relative operands.

    Raises a :class:`~binlens.x86.errors.DecodeError` subclass for input that does not decode.
    Never reads past the end of ``data`` or more than 15 bytes from ``offset``.
    """
    if not 0 <= offset <= len(data):
        raise ValueError(f"offset {offset} is outside a {len(data)}-byte buffer")
    reader = _Reader(data, offset)

    # Legacy prefixes, then REX. Within a prefix group the last one wins. REX only counts
    # directly before the opcode: a legacy prefix after it cancels it.
    opsize_override = addrsize_override = lock = False
    rep: int | None = None
    segment: str | None = None
    rex: int | None = None
    while True:
        byte = reader.u8()
        if 0x40 <= byte <= 0x4F:
            rex = byte
            continue
        if byte == 0x66:
            opsize_override = True
        elif byte == 0x67:
            addrsize_override = True
        elif byte == 0xF0:
            lock = True
        elif byte in (0xF2, 0xF3):
            rep = byte
        elif byte in _SEGMENT_PREFIXES:
            segment = _SEGMENT_PREFIXES[byte]
        else:
            break
        rex = None
    opcode = byte

    if opcode == 0x0F:
        raise UnsupportedInstruction("two-byte opcode 0f xx", offset)

    modrm: int | None = None
    group = GROUPS.get(opcode)
    if group is not None:
        modrm = reader.u8()
        reg_field = (modrm >> 3) & 7
        spec = group.get(reg_field)
        if spec is None:
            raise UnsupportedInstruction(f"opcode {opcode:02x} /{reg_field}", offset)
    else:
        found = ONE_BYTE.get(opcode)
        if found is None:
            raise UnsupportedInstruction(f"opcode {opcode:02x}", offset)
        spec = found
        if spec.has_modrm:
            modrm = reader.u8()

    if rep == 0xF2 or (rep == 0xF3 and not spec.allow_rep):
        raise UnsupportedInstruction(f"{rep:02x} prefix on {spec.mnemonic}", offset)
    if opsize_override and not spec.allow_opsize_override:
        raise UnsupportedInstruction(f"66 prefix on {spec.mnemonic}", offset)

    rex_bits = rex or 0
    has_rex = rex is not None
    if rex_bits & _REX_W:
        opsize = 64  # REX.W takes priority over 66
    elif opsize_override:
        opsize = 16
    else:
        opsize = 32
    addrsize = 32 if addrsize_override else 64

    # ModRM.rm (with SIB and displacement) comes before any immediate in the byte stream,
    # so decode it first whatever its position in the operand list.
    rm_operand: Operand | None = None
    for kind in spec.operands:
        if kind[0] == "E":
            assert modrm is not None
            size = 8 if kind == "Eb" else opsize
            rm_operand = _decode_rm(reader, modrm, rex_bits, has_rex, size, addrsize, segment)

    operands = tuple(
        _operand(kind, reader, spec, opcode, modrm, rm_operand, rex_bits, has_rex, opsize)
        for kind in spec.operands
    )

    if lock:
        if not spec.lockable:
            raise InvalidInstruction(f"LOCK prefix on {spec.mnemonic}", offset)
        if not isinstance(operands[0], MemoryOperand):
            raise InvalidInstruction(f"LOCK {spec.mnemonic} without a memory destination", offset)

    mnemonic = spec.mnemonic64 if spec.mnemonic64 and opsize == 64 else spec.mnemonic
    prefixes = ("lock",) if lock else ("rep",) if rep == 0xF3 else ()
    return Instruction(
        address=address,
        raw=bytes(data[offset : reader.pos]),
        mnemonic=mnemonic,
        operands=operands,
        prefixes=prefixes,
    )


def _operand(
    kind: str,
    reader: _Reader,
    spec: OpSpec,
    opcode: int,
    modrm: int | None,
    rm_operand: Operand | None,
    rex: int,
    has_rex: bool,
    opsize: int,
) -> Operand:
    match kind:
        case "Eb" | "Ev":
            assert rm_operand is not None
            return rm_operand
        case "Gb" | "Gv":
            assert modrm is not None
            number = ((modrm >> 3) & 7) | (8 if rex & _REX_R else 0)
            return RegisterOperand(gpr(number, 8 if kind == "Gb" else opsize, rex=has_rex))
        case "Zb" | "Zv":
            number = (opcode & 7) | (8 if rex & _REX_B else 0)
            return RegisterOperand(gpr(number, 8 if kind == "Zb" else opsize, rex=has_rex))
        case "AL":
            return RegisterOperand(GPR8[0])
        case "rAX":
            return RegisterOperand(gpr(0, opsize))
        case "Ib":
            return _immediate(reader.signed(1), 8)
        case "sIb":
            return _immediate(reader.signed(1), opsize)
        case "Iw":
            return _immediate(reader.unsigned(2), 16)
        case "Iz":
            return _immediate(reader.signed(2 if opsize == 16 else 4), opsize)
        case "Iv":
            return _immediate(reader.signed(opsize // 8), opsize)
    raise AssertionError(f"{spec.mnemonic}: unknown operand kind {kind!r}")


def _immediate(value: int, size: int) -> ImmediateOperand:
    return ImmediateOperand(value & ((1 << size) - 1), size)


def _decode_rm(
    reader: _Reader,
    modrm: int,
    rex: int,
    has_rex: bool,
    size: int,
    addrsize: int,
    segment: str | None,
) -> Operand:
    """The operand named by ModRM.mod/rm, reading any SIB byte and displacement."""
    mod, rm = modrm >> 6, modrm & 7
    b_ext = 8 if rex & _REX_B else 0
    if mod == 3:
        return RegisterOperand(gpr(rm | b_ext, size, rex=has_rex))

    # The special cases below test the raw 3-bit fields, before REX.B is applied. That is why
    # r12 needs a SIB byte like rsp, and [r13] needs a displacement like rbp.
    base: Register | None
    index: Register | None = None
    scale = 1
    disp = 0
    if rm == 4:  # a SIB byte follows
        sib = reader.u8()
        index_number = ((sib >> 3) & 7) | (8 if rex & _REX_X else 0)
        if index_number != 4:  # index 100 means "none"; with REX.X it is r12, a real index
            index = gpr(index_number, addrsize)
            scale = 1 << (sib >> 6)
        if sib & 7 == 5 and mod == 0:  # no base register, disp32 instead
            base = None
            disp = reader.signed(4)
        else:
            base = gpr((sib & 7) | b_ext, addrsize)
    elif rm == 5 and mod == 0:  # RIP-relative, disp32
        base = RIP if addrsize == 64 else EIP
        disp = reader.signed(4)
    else:
        base = gpr(rm | b_ext, addrsize)

    if mod == 1:
        disp = reader.signed(1)
    elif mod == 2:
        disp = reader.signed(4)

    return MemoryOperand(
        size=size,
        base=base,
        index=index,
        scale=scale,
        disp=disp,
        segment=segment,
        address_size=addrsize,
    )
