"""Property tests: the decoder must accept or reject any input, never crash or over-read."""

from hypothesis import given, settings
from hypothesis import strategies as st

from binlens.x86 import DecodeError, TruncatedInstruction, decode, format_instruction
from binlens.x86.decoder import MAX_LENGTH
from binlens.x86.intel import format_listing_line
from binlens.x86.opcodes import GROUPS, ONE_BYTE

PREFIXES = [0x66, 0x67, 0xF0, 0xF2, 0xF3, 0x26, 0x2E, 0x36, 0x3E, 0x64, 0x65, *range(0x40, 0x50)]
OPCODES = sorted({*ONE_BYTE, *GROUPS})

# Random bytes rarely land on a supported opcode, so also generate prefix + known opcode + tail.
instruction_like = st.builds(
    lambda prefixes, opcode, tail: bytes(prefixes) + bytes([opcode]) + tail,
    st.lists(st.sampled_from(PREFIXES), max_size=5),
    st.sampled_from(OPCODES),
    st.binary(max_size=MAX_LENGTH),
)
inputs = st.one_of(st.binary(max_size=24), instruction_like)


@settings(max_examples=3000)
@given(inputs)
def test_decode_accepts_or_rejects(data: bytes) -> None:
    try:
        insn = decode(data)
    except DecodeError:
        return
    assert 1 <= insn.length <= min(MAX_LENGTH, len(data))
    assert insn.raw == data[: insn.length]
    format_instruction(insn)
    format_listing_line(insn)


@settings(max_examples=3000)
@given(inputs)
def test_decode_depends_only_on_its_own_bytes(data: bytes) -> None:
    try:
        insn = decode(data)
    except DecodeError:
        return
    # Re-decoding just the instruction's bytes gives the same result...
    assert decode(insn.raw) == insn
    # ...and every shorter prefix of them is reported as truncated, not as something else.
    for cut in range(insn.length):
        try:
            decode(insn.raw[:cut])
        except TruncatedInstruction:
            continue
        raise AssertionError(f"{insn.raw[:cut].hex(' ')} should be truncated")


@given(st.binary(min_size=1, max_size=24), st.integers(min_value=0, max_value=23))
def test_decode_at_offset_never_reads_before_it(data: bytes, offset: int) -> None:
    offset = min(offset, len(data))
    try:
        insn = decode(data, offset)
    except DecodeError:
        return
    assert insn.raw == data[offset : offset + insn.length]
