"""End-to-end checks on the compiled test programs in tests/fixtures/."""

from pathlib import Path

import pytest

from binlens.pe import parse_pe
from binlens.sweep import BadByte, linear_sweep
from binlens.x86 import Instruction

FIXTURES = Path(__file__).parent / "fixtures"


def sweep_text(name: str) -> list[Instruction | BadByte]:
    image = parse_pe((FIXTURES / name).read_bytes())
    [text] = [s for s in image.sections if s.executable]
    start = image.image_base + text.virtual_address
    return list(linear_sweep(image.section_bytes(text), start))


@pytest.mark.parametrize("name", ["basic.exe"])
def test_disassembles_without_bad_bytes(name: str) -> None:
    bad = [item for item in sweep_text(name) if isinstance(item, BadByte)]
    assert bad == []


@pytest.mark.parametrize("name", ["basic.exe"])
def test_direct_branches_land_on_instruction_boundaries(name: str) -> None:
    # A wrong length anywhere would knock later instructions out of step, and branch targets
    # would then point into the middle of instructions.
    items = sweep_text(name)
    starts = {item.address for item in items}
    targets = [i.branch_target for i in items if isinstance(i, Instruction) and i.branch_target]
    assert targets, "expected some direct branches"
    assert [t for t in targets if t not in starts] == []
