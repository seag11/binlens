import struct

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st
from pebuild import IMAGE_BASE, TEXT_RVA, make_pe

from binlens.pe import PEFormatError, parse_pe

CODE = bytes.fromhex("48 83 c4 28 c3")


def test_parses_headers_and_text_section() -> None:
    image = parse_pe(make_pe(CODE))
    assert image.image_base == IMAGE_BASE
    assert image.entry_point == IMAGE_BASE + TEXT_RVA
    [text] = image.sections
    assert text.name == ".text"
    assert text.virtual_address == TEXT_RVA
    assert text.executable


def test_section_bytes_drop_file_alignment_padding() -> None:
    image = parse_pe(make_pe(CODE))
    [text] = image.sections
    assert text.raw_size == 0x200
    assert image.section_bytes(text) == CODE


@pytest.mark.parametrize(
    ("data", "message"),
    [
        (b"", "no MZ signature"),
        (b"ZM" + bytes(100), "no MZ signature"),
        (b"MZ" + bytes(10), "file ends inside the DOS header"),
        (b"MZ" + bytes(0x3A) + struct.pack("<I", 0x1000), "no PE signature"),
        (make_pe(CODE, machine=0x14C), "machine type 0x014c is not x86-64"),
        (make_pe(CODE, magic=0x10B), "optional header magic 0x10b is not PE32+"),
        (make_pe(CODE)[:0x150], "file ends inside the section table"),
    ],
)
def test_rejects_malformed(data: bytes, message: str) -> None:
    with pytest.raises(PEFormatError, match=message):
        parse_pe(data)


@settings(max_examples=1000)
@given(st.binary(max_size=600))
def test_random_bytes_parse_or_reject(data: bytes) -> None:
    _check_parse_or_reject(b"MZ" + data)


@settings(max_examples=2000)
@given(st.lists(st.tuples(st.integers(0, 0x204), st.integers(0, 255)), min_size=1, max_size=8))
def test_corrupted_headers_parse_or_reject(edits: list[tuple[int, int]]) -> None:
    data = bytearray(make_pe(CODE))
    for offset, value in edits:
        data[offset] = value
    _check_parse_or_reject(bytes(data))


def _check_parse_or_reject(data: bytes) -> None:
    try:
        image = parse_pe(data)
    except PEFormatError:
        return
    for section in image.sections:
        assert len(image.section_bytes(section)) <= section.raw_size
