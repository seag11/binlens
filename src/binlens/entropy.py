"""Shannon entropy of byte data: how close the bytes are to random.

Rough ranges, in bits per byte: zero padding ~0, text ~4-5, x86-64 code ~5.5-6.5,
compressed or encrypted data ~7.5-8. A high score is one signal of a packed executable,
not proof: compressed resources and legitimately packed software score high too.
"""

from __future__ import annotations

import math
from collections import Counter

# With n bytes the score can't exceed log2(n), and random data only gets close to 8 with
# plenty of samples: ~7.2 for 256 random bytes, ~7.8 for 1 KiB. Below this size a score
# can't tell code from compressed data.
MIN_RELIABLE_SIZE = 1024


def shannon_entropy(data: bytes) -> float:
    """Bits per byte: 0.0 for empty data or a single repeated value, up to 8.0 when all 256
    byte values appear equally often."""
    n = len(data)
    if n == 0:
        return 0.0
    return sum(count / n * math.log2(n / count) for count in Counter(data).values())
