"""Linear sweep: decode a block of code front to back.

Simple, but it trusts that instructions are packed end to end. Data or padding inside the
code throws it out of step until it happens to land on an instruction boundary again.
"""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass

from binlens.x86 import DecodeError, Instruction, decode


@dataclass(frozen=True, slots=True)
class BadByte:
    """A byte where decoding failed. The sweep moves on to the next byte."""

    address: int
    byte: int
    error: DecodeError


def linear_sweep(code: bytes, address: int = 0) -> Iterator[Instruction | BadByte]:
    """Decode ``code``, whose first byte is at virtual ``address``, from start to end.

    Every byte is covered exactly once, by either an instruction or a ``BadByte``.
    """
    offset = 0
    while offset < len(code):
        try:
            insn = decode(code, offset, address + offset)
        except DecodeError as err:
            yield BadByte(address + offset, code[offset], err)
            offset += 1
            continue
        yield insn
        offset += insn.length
