from pathlib import Path

import pytest

from binlens.cli import main


def run(capsys: pytest.CaptureFixture[str], *argv: str) -> list[str]:
    assert main(list(argv)) == 0
    return capsys.readouterr().out.splitlines()


def test_hex_listing_layout(capsys: pytest.CaptureFixture[str]) -> None:
    lines = run(capsys, "hex", "48 83 c4 28", "c3", "--address", "0x140001000")
    assert lines == [
        "0x140001000  48 83 c4 28        add   rsp, 0x28",
        "0x140001004  c3                 ret",
    ]


def test_rip_relative_target_comment(capsys: pytest.CaptureFixture[str]) -> None:
    lines = run(capsys, "hex", "48 8b 05 f9 0f 00 00", "--address", "0x140001000")
    assert lines == [
        "0x140001000  48 8b 05 f9 0f 00 00  mov   rax, qword ptr [rip+0xff9]  ; 0x140002000",
    ]


def test_bad_bytes_are_skipped_one_at_a_time(capsys: pytest.CaptureFixture[str]) -> None:
    lines = run(capsys, "hex", "90 c3")
    assert lines == [
        "0x00000000  90                 (bad)  ; opcode 90",
        "0x00000001  c3                 ret",
    ]


def test_raw_file(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    blob = tmp_path / "code.bin"
    blob.write_bytes(bytes.fromhex("cc cc 48 89 c3 c3"))
    lines = run(capsys, "raw", str(blob), "--offset", "2", "--address", "0x1000")
    assert lines == [
        "0x00001000  48 89 c3           mov   rbx, rax",
        "0x00001003  c3                 ret",
    ]


def test_invalid_hex_is_a_usage_error(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as exc:
        main(["hex", "zz"])
    assert exc.value.code == 2
