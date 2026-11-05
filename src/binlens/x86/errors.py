"""Decoder rejections. Every input either decodes or raises one of these."""

from __future__ import annotations


class DecodeError(Exception):
    """The bytes at ``offset`` could not be decoded. ``reason`` is a short description."""

    def __init__(self, reason: str, offset: int) -> None:
        super().__init__(f"{reason} (instruction at offset {offset})")
        self.reason = reason
        self.offset = offset


class TruncatedInstruction(DecodeError):
    """The input ended before the instruction did."""


class InvalidInstruction(DecodeError):
    """An encoding the CPU itself rejects, such as one longer than 15 bytes or a misplaced LOCK."""


class UnsupportedInstruction(DecodeError):
    """Outside the subset binlens decodes. The bytes may still be a valid instruction."""
