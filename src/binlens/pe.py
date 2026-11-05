"""Minimal PE32+ reader: headers, section table and entry point.

Reads only what disassembly needs so far. Imports, resources, relocations and the rest of
the format come later (Milestone 2 in PLAN.md).

Every field is bounds-checked: malformed input raises PEFormatError, never IndexError or
struct.error.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field

MACHINE_AMD64 = 0x8664
_PE32_PLUS_MAGIC = 0x20B
_SCN_MEM_EXECUTE = 0x2000_0000
_SECTION_HEADER_SIZE = 40


class PEFormatError(ValueError):
    """The file is not a PE32+ x86-64 image this reader understands."""


@dataclass(frozen=True, slots=True)
class Section:
    name: str
    virtual_address: int  # RVA: offset from the image base once loaded
    virtual_size: int  # size in memory
    raw_offset: int  # PointerToRawData: where the bytes are in the file
    raw_size: int  # SizeOfRawData: rounded up to the file alignment
    characteristics: int

    @property
    def executable(self) -> bool:
        return bool(self.characteristics & _SCN_MEM_EXECUTE)


@dataclass(frozen=True, slots=True)
class PEImage:
    image_base: int
    entry_point_rva: int
    sections: tuple[Section, ...]
    data: bytes = field(repr=False)

    @property
    def entry_point(self) -> int:
        return self.image_base + self.entry_point_rva

    def section_bytes(self, section: Section) -> bytes:
        """The section's bytes from the file, without the file-alignment padding.

        Uses VirtualSize when it is set and smaller than the raw size: the zero padding after
        the code would otherwise decode as instructions (``00 00`` is ``add [rax], al``).
        Bytes past the end of the file are left out.
        """
        size = section.raw_size
        if 0 < section.virtual_size < size:
            size = section.virtual_size
        return self.data[section.raw_offset : section.raw_offset + size]


def parse_pe(data: bytes | bytearray | memoryview) -> PEImage:
    """Parse the headers and section table of a PE32+ x86-64 file."""
    data = bytes(data)

    def unpack(fmt: str, offset: int, what: str) -> tuple[int, ...]:
        try:
            return struct.unpack_from(fmt, data, offset)
        except struct.error:
            raise PEFormatError(f"file ends inside the {what}") from None

    if data[:2] != b"MZ":
        raise PEFormatError("no MZ signature")
    (pe_offset,) = unpack("<I", 0x3C, "DOS header")
    if data[pe_offset : pe_offset + 4] != b"PE\0\0":
        raise PEFormatError("no PE signature")

    machine, section_count, _, _, _, optional_size, _ = unpack(
        "<HHIIIHH", pe_offset + 4, "COFF header"
    )
    if machine != MACHINE_AMD64:
        raise PEFormatError(f"machine type {machine:#06x} is not x86-64")

    optional = pe_offset + 24
    if optional_size < 32:  # must reach at least ImageBase, at offset 24
        raise PEFormatError(f"optional header is only {optional_size} bytes")
    (magic,) = unpack("<H", optional, "optional header")
    if magic != _PE32_PLUS_MAGIC:
        raise PEFormatError(f"optional header magic {magic:#x} is not PE32+")
    (entry_rva,) = unpack("<I", optional + 16, "optional header")
    (image_base,) = unpack("<Q", optional + 24, "optional header")

    table = optional + optional_size
    sections = []
    for i in range(section_count):
        header = table + i * _SECTION_HEADER_SIZE
        raw_name, vsize, vaddr, raw_size, raw_offset = unpack("<8sIIII", header, "section table")
        (characteristics,) = unpack("<I", header + 36, "section table")
        sections.append(
            Section(
                name=raw_name.rstrip(b"\0").decode("latin-1"),
                virtual_address=vaddr,
                virtual_size=vsize,
                raw_offset=raw_offset,
                raw_size=raw_size,
                characteristics=characteristics,
            )
        )

    return PEImage(
        image_base=image_base,
        entry_point_rva=entry_rva,
        sections=tuple(sections),
        data=data,
    )
