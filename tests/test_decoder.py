"""Hand-checked encodings, chosen to hit each ModRM/SIB/REX/prefix rule at least once."""

import pytest

from binlens.x86 import (
    ImmediateOperand,
    InvalidInstruction,
    MemoryOperand,
    RegisterOperand,
    TruncatedInstruction,
    UnsupportedInstruction,
    decode,
    format_instruction,
)
from binlens.x86.registers import GPR64, RIP

# (hex bytes, expected Intel text). Each case is exactly one instruction.
CASES = [
    # --- mov: register forms, operand sizes, REX ---
    ("89 c3", "mov ebx, eax"),
    ("48 89 c3", "mov rbx, rax"),
    ("66 89 c3", "mov bx, ax"),
    ("88 c3", "mov bl, al"),
    ("4d 89 c8", "mov r8, r9"),  # REX.R extends reg, REX.B extends rm
    ("8b c3", "mov eax, ebx"),
    ("66 48 89 c3", "mov rbx, rax"),  # REX.W beats 66
    ("48 66 89 c3", "mov bx, ax"),  # REX not directly before the opcode is ignored
    ("48 40 89 c3", "mov ebx, eax"),  # only the last REX counts
    # --- byte registers: ah/ch/dh/bh vs spl/bpl/sil/dil ---
    ("88 e0", "mov al, ah"),
    ("40 88 e0", "mov al, spl"),
    ("41 88 c0", "mov r8b, al"),
    ("44 88 e0", "mov al, r12b"),
    # --- memory: ModRM / SIB / displacement ---
    ("48 8b 44 24 08", "mov rax, qword ptr [rsp+0x8]"),  # the worked example in PLAN.md
    ("48 8b 00", "mov rax, qword ptr [rax]"),
    ("48 8b 45 f8", "mov rax, qword ptr [rbp-0x8]"),  # disp8 is signed
    ("48 8b 85 00 01 00 00", "mov rax, qword ptr [rbp+0x100]"),  # disp32
    ("48 8b 44 88 10", "mov rax, qword ptr [rax+rcx*4+0x10]"),
    ("8b 04 24", "mov eax, dword ptr [rsp]"),  # SIB index 100: no index
    ("4a 8b 04 24", "mov rax, qword ptr [rsp+r12]"),  # ...unless REX.X makes it r12
    ("49 8b 04 24", "mov rax, qword ptr [r12]"),  # r12 base needs a SIB byte, like rsp
    ("49 8b 45 00", "mov rax, qword ptr [r13]"),  # r13 base needs a displacement, like rbp
    ("8b 04 25 78 56 34 12", "mov eax, dword ptr [0x12345678]"),  # SIB, no base, no index
    ("41 8b 04 25 78 56 34 12", "mov eax, dword ptr [0x12345678]"),  # REX.B doesn't give r13
    ("8b 04 8d 00 10 00 00", "mov eax, dword ptr [rcx*4+0x1000]"),  # SIB, no base
    ("8b 04 25 00 00 00 80", "mov eax, dword ptr [0xffffffff80000000]"),  # disp32 sign-extends
    ("48 8b 05 10 00 00 00", "mov rax, qword ptr [rip+0x10]"),
    ("49 8b 05 10 00 00 00", "mov rax, qword ptr [rip+0x10]"),  # REX.B doesn't give r13
    ("48 89 0d f0 ff ff ff", "mov qword ptr [rip-0x10], rcx"),
    # --- address-size and segment prefixes ---
    ("67 8b 00", "mov eax, dword ptr [eax]"),
    ("67 8b 05 10 00 00 00", "mov eax, dword ptr [eip+0x10]"),
    ("67 8b 04 25 00 00 00 80", "mov eax, dword ptr [0x80000000]"),
    ("65 48 8b 04 25 60 00 00 00", "mov rax, qword ptr gs:[0x60]"),  # PEB pointer on x64 Windows
    ("64 8b 00", "mov eax, dword ptr fs:[rax]"),
    ("3e 8b 00", "mov eax, dword ptr [rax]"),  # DS override does nothing in 64-bit mode
    # --- mov immediates ---
    ("b8 78 56 34 12", "mov eax, 0x12345678"),
    ("66 b8 34 12", "mov ax, 0x1234"),
    ("48 b8 88 77 66 55 44 33 22 11", "movabs rax, 0x1122334455667788"),
    ("49 bf 01 00 00 00 00 00 00 00", "movabs r15, 0x1"),
    ("41 b8 01 00 00 00", "mov r8d, 0x1"),
    ("b0 05", "mov al, 0x5"),
    ("b4 05", "mov ah, 0x5"),
    ("40 b4 05", "mov spl, 0x5"),
    ("41 b0 05", "mov r8b, 0x5"),
    ("c6 00 05", "mov byte ptr [rax], 0x5"),
    ("66 c7 00 34 12", "mov word ptr [rax], 0x1234"),
    ("c7 00 01 00 00 00", "mov dword ptr [rax], 0x1"),
    ("48 c7 c0 ff ff ff ff", "mov rax, 0xffffffffffffffff"),  # imm32 sign-extends to 64
    ("c7 44 24 08 2a 00 00 00", "mov dword ptr [rsp+0x8], 0x2a"),
    ("c7 05 10 00 00 00 01 00 00 00", "mov dword ptr [rip+0x10], 0x1"),
    # --- add ---
    ("00 c8", "add al, cl"),
    ("01 c8", "add eax, ecx"),
    ("48 01 c8", "add rax, rcx"),
    ("02 03", "add al, byte ptr [rbx]"),
    ("03 45 f8", "add eax, dword ptr [rbp-0x8]"),
    ("04 05", "add al, 0x5"),
    ("05 78 56 34 12", "add eax, 0x12345678"),
    ("66 05 34 12", "add ax, 0x1234"),
    ("48 05 ff ff ff ff", "add rax, 0xffffffffffffffff"),
    ("80 c1 05", "add cl, 0x5"),
    ("81 c1 78 56 34 12", "add ecx, 0x12345678"),
    ("48 81 c4 00 01 00 00", "add rsp, 0x100"),
    ("48 83 c4 28", "add rsp, 0x28"),
    ("83 c0 ff", "add eax, 0xffffffff"),  # imm8 sign-extends to the operand size
    ("66 83 c0 ff", "add ax, 0xffff"),
    ("48 83 c0 ff", "add rax, 0xffffffffffffffff"),
    ("f0 01 08", "lock add dword ptr [rax], ecx"),
    ("f0 48 83 00 01", "lock add qword ptr [rax], 0x1"),
    # --- ret ---
    ("c3", "ret"),
    ("c2 08 00", "ret 0x8"),
    ("f3 c3", "rep ret"),
    ("40 c3", "ret"),  # a REX prefix with nothing to extend is harmless
    # --- the 15-byte limit, exactly ---
    ("66 " * 13 + "89 c3", "mov bx, ax"),
]


@pytest.mark.parametrize(("hex_bytes", "text"), CASES, ids=[text for _, text in CASES])
def test_decode(hex_bytes: str, text: str) -> None:
    data = bytes.fromhex(hex_bytes)
    insn = decode(data)
    assert format_instruction(insn) == text
    assert insn.raw == data


def test_operand_structure_for_sib_no_base() -> None:
    # 41 8b 04 25: REX.B is set but SIB base=101 with mod=00 still means "no base".
    insn = decode(bytes.fromhex("41 8b 04 25 78 56 34 12"))
    assert insn.operands[1] == MemoryOperand(
        size=32, base=None, index=None, scale=1, disp=0x12345678
    )


def test_operand_structure_for_r13_index() -> None:
    # REX.X turns SIB index 101 into r13; base=101 with mod=00 means no base.
    insn = decode(bytes.fromhex("42 8b 04 2d 00 00 00 00"))
    mem = insn.operands[1]
    assert isinstance(mem, MemoryOperand)
    assert mem.base is None
    assert mem.index == GPR64[13]
    assert mem.disp == 0


def test_gs_operand_records_segment() -> None:
    insn = decode(bytes.fromhex("65 48 8b 04 25 60 00 00 00"))
    assert insn.operands == (
        RegisterOperand(GPR64[0]),
        MemoryOperand(size=64, base=None, index=None, scale=1, disp=0x60, segment="gs"),
    )


def test_immediate_signed_view() -> None:
    insn = decode(bytes.fromhex("48 83 c4 f8"))
    imm = insn.operands[1]
    assert isinstance(imm, ImmediateOperand)
    assert imm.value == 0xFFFF_FFFF_FFFF_FFF8
    assert imm.signed == -8


def test_rip_relative_target_counts_from_end_of_instruction() -> None:
    # Ten bytes long, including the trailing imm32, so the target is address + 10 + 0x10.
    insn = decode(bytes.fromhex("c7 05 10 00 00 00 01 00 00 00"), address=0x1000)
    mem = insn.operands[0]
    assert isinstance(mem, MemoryOperand) and mem.base is RIP
    assert insn.memory_target(mem) == 0x101A


def test_memory_target_is_none_for_other_operands() -> None:
    insn = decode(bytes.fromhex("48 8b 00"))
    mem = insn.operands[1]
    assert isinstance(mem, MemoryOperand)
    assert insn.memory_target(mem) is None


def test_offset_and_address() -> None:
    data = bytes.fromhex("90 90 48 83 c4 28 c3")
    insn = decode(data, offset=2, address=0x140001002)
    assert insn.address == 0x140001002
    assert insn.raw == bytes.fromhex("48 83 c4 28")
    assert insn.next_address == 0x140001006


def test_offset_outside_buffer() -> None:
    with pytest.raises(ValueError):
        decode(b"\xc3", offset=2)


@pytest.mark.parametrize(
    "hex_bytes",
    [
        "",
        "48",  # REX, then nothing
        "66 66",
        "8b",  # missing ModRM
        "8b 04",  # missing SIB
        "8b 44 24",  # missing disp8
        "8b 05 10 00",  # incomplete disp32
        "b8 01 02",  # incomplete imm32
        "48 b8 01 02 03 04 05 06 07",  # incomplete imm64
        "c2 08",  # incomplete imm16
        "c7 05 10 00 00 00 01",  # disp32 present, imm32 incomplete
    ],
)
def test_truncated(hex_bytes: str) -> None:
    with pytest.raises(TruncatedInstruction):
        decode(bytes.fromhex(hex_bytes))


@pytest.mark.parametrize(
    "hex_bytes",
    [
        "66 " * 14 + "89 c3",  # 16 bytes
        "66 " * 15 + "89 c3",  # limit hit while still reading prefixes
        "f0 01 c8",  # LOCK with a register destination
        "f0 89 08",  # mov is not lockable
        "f0 c3",
    ],
)
def test_invalid(hex_bytes: str) -> None:
    with pytest.raises(InvalidInstruction):
        decode(bytes.fromhex(hex_bytes))


@pytest.mark.parametrize(
    "hex_bytes",
    [
        "90",  # nop: not in the table yet
        "0f 0b",  # ud2: two-byte opcodes not yet supported
        "83 c8 01",  # or (83 /1): only /0 is in the table so far
        "c7 c8 00 00 00 00",  # C7 /1 is not mov
        "66 c3",  # 16-bit ret: Intel and AMD disagree
        "f2 c3",  # bnd ret
        "f3 89 c3",  # rep on mov
        "c5 f8 77",  # VEX (vzeroupper): out of scope
    ],
)
def test_unsupported(hex_bytes: str) -> None:
    with pytest.raises(UnsupportedInstruction):
        decode(bytes.fromhex(hex_bytes))


def test_long_buffer_does_not_affect_limit_error() -> None:
    # Truncation and the 15-byte limit are independent: plenty of input left, still too long.
    with pytest.raises(InvalidInstruction):
        decode(bytes.fromhex("66 " * 14 + "89 c3") + bytes(100))
