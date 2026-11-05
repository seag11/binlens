# binlens

A static analyzer for Windows x86-64 executables, built on a from-scratch disassembler.

**Status: early.** The x86-64 decoder handles `mov`, `add` and `ret` so far. PE loading and capability detection come next; see [PLAN.md](PLAN.md) for the roadmap.

## Usage

Requires Python 3.11+ and [uv](https://docs.astral.sh/uv/).

```
uv sync
uv run binlens hex "48 83 c4 28 c3" --address 0x140001000
```

```
0x140001000  48 83 c4 28        add   rsp, 0x28
0x140001004  c3                 ret
```

`binlens raw FILE [--offset N] [--address A]` disassembles a file as raw code bytes. Bytes that don't decode are listed as `(bad)` with the reason.

## Scope

64-bit mode only, Intel syntax. Not supported: SSE/AVX (VEX/EVEX), x87, and 16-bit and 32-bit modes.

## Development

```
uv run pytest
```

The tests combine hand-checked encodings with Hypothesis property tests: any input must either decode or be rejected, without reading past the input or past the 15-byte instruction limit.
