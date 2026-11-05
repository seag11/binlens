"""Compile the C test programs in tests/fixtures/src/ into Windows x86-64 executables.

    uv run python scripts/build_fixtures.py            # every source
    uv run python scripts/build_fixtures.py basic      # just tests/fixtures/src/basic.c

Uses the zig compiler pinned in uv.lock. The flags keep each .exe down to code we wrote:
no C runtime and no compiler-inserted checks. Each program's entry point is a function
named mainCRTStartup, set explicitly with --entry.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

FIXTURES = Path(__file__).resolve().parent.parent / "tests" / "fixtures"
SOURCES = FIXTURES / "src"

FLAGS = [
    "-target", "x86_64-windows-gnu",
    "-O0",
    "-nostdlib",  # no C runtime: nothing linked in that we didn't write
    "-fno-sanitize=undefined",  # zig enables UBSan traps at -O0 by default
    "-fno-stack-protector",
    "-g0",  # no debug sections
    "-s",  # strip: no .pdb, which would record local paths and the full link command
    # Without the C runtime the linker's default entry is wWinMainCRTStartup (a GUI program).
    "-Wl,--entry=mainCRTStartup",
    "-Wl,--subsystem,console",
    # Reproducible output: /Brepro writes a hash of the contents where the build time would
    # go. The .buildid section remains, holding only that hash.
    "-Wl,/Brepro",
    "-Wl,--build-id=none",
]


def build(source: Path) -> Path:
    output = FIXTURES / f"{source.stem}.exe"
    command = [sys.executable, "-m", "ziglang", "cc", *FLAGS, "-o", str(output), str(source)]
    print(" ".join(command[1:]))
    subprocess.run(command, check=True)
    return output


def main(names: list[str]) -> int:
    sources = [SOURCES / f"{name}.c" for name in names] or sorted(SOURCES.glob("*.c"))
    missing = [str(s) for s in sources if not s.is_file()]
    if missing:
        print(f"no such source: {', '.join(missing)}", file=sys.stderr)
        return 1
    for source in sources:
        build(source)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
