"""Freeze original-build timing samples across the shared constructor extraction."""

import pytest

from evidenceforge.generation.timing import TimingSampler, TimingScope, uniform_distribution


@pytest.mark.parametrize(
    ("seed", "expected"),
    [
        (42, [1.4277049167340707, 2.161054572835351, 3.355211371474313, 2.7570133250915037]),
        (137, [2.403805815326017, 0.8514868154260924, 1.4834049756883143, 1.3154280336035868]),
    ],
)
def test_uniform_samples_match_original_dev(seed: int, expected: list[float]) -> None:
    # Captured from e4035435's DHCP constructor, before the shared implementation.
    sampler = TimingSampler(generation_seed=seed)
    actual = [
        sampler.sample_value(
            uniform_distribution(0.25, 4.0),
            relationship_key="cleanup.uniform",
            scope=TimingScope(stable_id="transport", host="WIN-01", ordinal=ordinal),
        )
        for ordinal in range(4)
    ]
    assert actual == expected


def test_equal_uniform_bounds_preserve_exact_constant() -> None:
    assert (
        TimingSampler(generation_seed=42).sample_value(
            uniform_distribution(3.0, 3.0),
            relationship_key="cleanup.uniform",
            scope=TimingScope(stable_id="constant"),
        )
        == 3.0
    )
