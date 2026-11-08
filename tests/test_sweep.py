from hypothesis import given
from hypothesis import strategies as st

from binlens.sweep import BadByte, linear_sweep
from binlens.x86 import Instruction, UnsupportedInstruction, format_instruction


def test_yields_instructions_and_bad_bytes_in_order() -> None:
    items = list(linear_sweep(bytes.fromhex("90 48 83 c4 28 c3"), address=0x1000))

    bad, add, ret = items
    assert isinstance(bad, BadByte)
    assert (bad.address, bad.byte) == (0x1000, 0x90)
    assert isinstance(bad.error, UnsupportedInstruction)

    assert isinstance(add, Instruction) and isinstance(ret, Instruction)
    assert (add.address, format_instruction(add)) == (0x1001, "add rsp, 0x28")
    assert (ret.address, format_instruction(ret)) == (0x1005, "ret")


def test_empty_input() -> None:
    assert list(linear_sweep(b"")) == []


@given(st.binary(max_size=64), st.integers(min_value=0, max_value=2**48))
def test_covers_every_byte_exactly_once(code: bytes, address: int) -> None:
    expected = address
    for item in linear_sweep(code, address):
        assert item.address == expected
        expected += 1 if isinstance(item, BadByte) else item.length
    assert expected == address + len(code)
