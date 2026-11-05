"""Command-line entry point."""

from __future__ import annotations

import argparse
from collections.abc import Iterator, Sequence
from pathlib import Path

from binlens.pe import PEFormatError, parse_pe
from binlens.x86 import DecodeError, decode
from binlens.x86.intel import format_bad_line, format_listing_line


def listing(data: bytes, address: int = 0) -> Iterator[str]:
    """Linear sweep: decode ``data`` front to back. A byte that fails to decode is shown as
    ``(bad)`` and the sweep resumes at the next byte."""
    offset = 0
    while offset < len(data):
        try:
            insn = decode(data, offset, address + offset)
        except DecodeError as err:
            yield format_bad_line(address + offset, data[offset], err.reason)
            offset += 1
            continue
        yield format_listing_line(insn)
        offset += insn.length


def _int(text: str) -> int:
    return int(text, 0)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="binlens",
        description="Disassemble x86-64 machine code (64-bit mode, Intel syntax).",
    )
    commands = parser.add_subparsers(dest="command", required=True)

    hex_cmd = commands.add_parser("hex", help="disassemble bytes written as hex")
    hex_cmd.add_argument("hex", nargs="+", metavar="HEX", help='e.g. "48 8b 44 24 08 c3"')

    raw_cmd = commands.add_parser("raw", help="disassemble a file as raw code bytes (no PE parsing)")
    raw_cmd.add_argument("path", type=Path)
    raw_cmd.add_argument("--offset", type=_int, default=0, help="file offset to start at")

    for cmd in (hex_cmd, raw_cmd):
        cmd.add_argument(
            "--address", type=_int, default=0, help="virtual address of the first byte (default 0)"
        )

    exe_cmd = commands.add_parser("exe", help="disassemble the executable sections of a PE file")
    exe_cmd.add_argument("path", type=Path)

    args = parser.parse_args(argv)
    if args.command == "exe":
        try:
            image = parse_pe(args.path.read_bytes())
        except PEFormatError as err:
            parser.exit(1, f"binlens: {args.path}: {err}\n")
        print(f"; entry point {image.entry_point:#x}")
        for section in image.sections:
            if not section.executable:
                continue
            start = image.image_base + section.virtual_address
            code = image.section_bytes(section)
            print(f"\n; section {section.name}  {start:#x}  {len(code):#x} bytes")
            for line in listing(code, start):
                print(line)
        return 0

    if args.command == "hex":
        try:
            data = bytes.fromhex(" ".join(args.hex))
        except ValueError as err:
            parser.error(f"invalid hex: {err}")
    else:
        data = args.path.read_bytes()[args.offset :]

    for line in listing(data, args.address):
        print(line)
    return 0
