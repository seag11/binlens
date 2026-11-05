"""Intel-syntax text: lower-case, hex immediates, explicit memory sizes."""

from __future__ import annotations

from binlens.x86.instruction import (
    ImmediateOperand,
    Instruction,
    MemoryOperand,
    Operand,
    RegisterOperand,
)

_PTR = {8: "byte", 16: "word", 32: "dword", 64: "qword"}

# Listing columns, matching the layout in PLAN.md.
_BYTES_WIDTH = 17  # six bytes of hex
_MNEMONIC_WIDTH = 5


def format_operand(operand: Operand) -> str:
    match operand:
        case RegisterOperand(reg=reg):
            return reg.name
        case ImmediateOperand(value=value):
            return f"{value:#x}"
        case MemoryOperand():
            return _format_memory(operand)
    raise TypeError(f"not an operand: {operand!r}")


def _format_memory(op: MemoryOperand) -> str:
    terms = []
    if op.base is not None:
        terms.append(op.base.name)
    if op.index is not None:
        terms.append(op.index.name if op.scale == 1 else f"{op.index.name}*{op.scale}")

    if not terms:  # absolute address
        inner = f"{op.disp & ((1 << op.address_size) - 1):#x}"
    else:
        inner = "+".join(terms)
        if op.disp > 0:
            inner += f"+{op.disp:#x}"
        elif op.disp < 0:
            inner += f"-{-op.disp:#x}"

    segment = f"{op.segment}:" if op.segment else ""
    return f"{_PTR[op.size]} ptr {segment}[{inner}]"


def format_instruction(insn: Instruction) -> str:
    """``mov rax, qword ptr [rsp+0x8]``"""
    head = " ".join((*insn.prefixes, insn.mnemonic))
    if not insn.operands:
        return head
    return f"{head} {', '.join(format_operand(op) for op in insn.operands)}"


def format_listing_line(insn: Instruction) -> str:
    """``0x140001000  48 8b 44 24 08     mov   rax, qword ptr [rsp+0x8]``

    RIP-relative operands get their resolved address as a trailing comment.
    """
    head = " ".join((*insn.prefixes, insn.mnemonic))
    text = f"{head:<{_MNEMONIC_WIDTH}} {', '.join(format_operand(op) for op in insn.operands)}"
    line = _columns(insn.address, insn.raw.hex(" "), text.rstrip())
    targets = [
        target
        for op in insn.operands
        if isinstance(op, MemoryOperand) and (target := insn.memory_target(op)) is not None
    ]
    if targets:
        line += "  ; " + ", ".join(f"{target:#x}" for target in targets)
    return line


def format_bad_line(address: int, byte: int, reason: str) -> str:
    """A listing line for a byte that did not decode."""
    return _columns(address, f"{byte:02x}", f"{'(bad)':<{_MNEMONIC_WIDTH}}  ; {reason}")


def _columns(address: int, hex_bytes: str, text: str) -> str:
    return f"{address:#010x}  {hex_bytes:<{_BYTES_WIDTH}}  {text}"
