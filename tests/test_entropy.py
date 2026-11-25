import math
import random

import pytest
from hypothesis import given
from hypothesis import strategies as st

from binlens.entropy import MIN_RELIABLE_SIZE, shannon_entropy


@pytest.mark.parametrize(
    ("data", "expected"),
    [
        (b"", 0.0),
        (b"\x00" * 100, 0.0),  # one repeated value
        (b"\x00\x01" * 50, 1.0),  # two values, equally often
        (bytes(range(4)) * 25, 2.0),
        (bytes(range(256)), 8.0),  # every value once: the maximum
        (bytes(range(256)) * 4, 8.0),
    ],
)
def test_exact_values(data: bytes, expected: float) -> None:
    assert shannon_entropy(data) == pytest.approx(expected)


def test_never_negative_zero() -> None:
    # A single repeated value must print as 0.00, not -0.00.
    assert math.copysign(1.0, shannon_entropy(b"aaaa")) == 1.0


def test_random_data_scores_near_8_once_large_enough() -> None:
    data = random.Random(0).randbytes(MIN_RELIABLE_SIZE * 4)
    assert shannon_entropy(data) > 7.9


def test_random_data_below_the_reliable_size_cannot_reach_8() -> None:
    # Why small sections are marked "too small to judge".
    data = random.Random(0).randbytes(256)
    assert shannon_entropy(data) < 7.5


@given(st.binary(min_size=1, max_size=600))
def test_bounded_by_8_and_by_log2_of_length(data: bytes) -> None:
    score = shannon_entropy(data)
    assert 0.0 <= score <= min(8.0, math.log2(len(data))) + 1e-9
