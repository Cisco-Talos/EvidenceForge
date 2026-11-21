# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Pure allocation of ordered canonical phases inside an existing timing budget."""

from datetime import datetime, timedelta

from evidenceforge.generation.timing.distributions import TimingDistributionError
from evidenceforge.utils.time import ensure_utc


def _microseconds(value: timedelta) -> int:
    return (value.days * 86_400 + value.seconds) * 1_000_000 + value.microseconds


def partition_phase_interval(
    start: datetime, end: datetime, weights: tuple[timedelta, ...]
) -> tuple[datetime, ...]:
    """Allocate positive ordered stage intervals while retaining both exact anchors.

    Args:
        start: Existing canonical first phase, with an explicit timezone.
        end: Existing canonical final phase, with an explicit timezone.
        weights: Separately planned positive transition weights. They determine
            conditional shares of the available budget, not absolute durations.

    Returns:
        Both anchors and the strictly ordered interior phase times.

    Raises:
        TimingDistributionError: The inputs cannot represent positive stages.
    """
    if (
        type(start) is not datetime
        or start.utcoffset() is None
        or type(end) is not datetime
        or end.utcoffset() is None
        or type(weights) is not tuple
        or not weights
        or any(type(weight) is not timedelta or weight <= timedelta(0) for weight in weights)
    ):
        raise TimingDistributionError(
            "Phase allocation requires aware anchors and positive weights"
        )
    start, end = ensure_utc(start), ensure_utc(end)
    total = _microseconds(end - start)
    if total < len(weights):
        raise TimingDistributionError("Phase interval cannot represent all positive transitions")
    values = tuple(_microseconds(weight) for weight in weights)
    denominator = sum(values)
    distributable = total - len(values)
    cumulative = 0
    phases = [start]
    for ordinal, value in enumerate(values[:-1], start=1):
        cumulative += value
        phases.append(
            start + timedelta(microseconds=ordinal + distributable * cumulative // denominator)
        )
    phases.append(end)
    return tuple(phases)
