"""Builds minimal PE32+ files byte by byte, so PE tests don't depend on a compiler."""

import struct

FILE_ALIGNMENT = 0x200
TEXT_RVA = 0x1000
IMAGE_BASE = 0x1_4000_0000


def _align(n: int, alignment: int) -> int:
    return (n + alignment - 1) // alignment * alignment


def make_pe(
    code: bytes,
    *,
    image_base: int = IMAGE_BASE,
    entry_rva: int = TEXT_RVA,
    machine: int = 0x8664,
    magic: int = 0x20B,
) -> bytes:
    """A one-section image: ``code`` in an executable .text section at ``TEXT_RVA``."""
    pe_offset = 0x40
    optional_size = 0xF0  # the standard PE32+ size, including the 16 data directories

    dos = bytearray(0x40)
    dos[0:2] = b"MZ"
    struct.pack_into("<I", dos, 0x3C, pe_offset)

    coff = struct.pack("<HHIIIHH", machine, 1, 0, 0, 0, optional_size, 0x0022)

    optional = bytearray(optional_size)
    struct.pack_into("<H", optional, 0, magic)
    struct.pack_into("<I", optional, 16, entry_rva)
    struct.pack_into("<Q", optional, 24, image_base)
    struct.pack_into("<II", optional, 32, 0x1000, FILE_ALIGNMENT)  # section/file alignment
    struct.pack_into("<I", optional, 108, 16)  # NumberOfRvaAndSizes

    raw_size = _align(len(code), FILE_ALIGNMENT)
    section = struct.pack(
        "<8sIIIIIIHHI",
        b".text",
        len(code),  # VirtualSize
        TEXT_RVA,
        raw_size,
        FILE_ALIGNMENT,  # PointerToRawData: code starts right after the headers
        0,
        0,
        0,
        0,
        0x6000_0020,  # code, execute, read
    )

    headers = bytes(dos) + b"PE\0\0" + coff + bytes(optional) + section
    assert len(headers) <= FILE_ALIGNMENT
    return headers.ljust(FILE_ALIGNMENT, b"\0") + code.ljust(raw_size, b"\0")
