# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Configured bounded-noise opportunities across host windows."""

from datetime import UTC, datetime, timedelta

import pytest
from pydantic import ValidationError

from evidenceforge.config.schemas import SyslogProgramEntry
from evidenceforge.generation.engine.baseline import _extra_syslog_arrival_offsets
from evidenceforge.generation.timing import TimingSampler
from evidenceforge.models.scenario import System


@pytest.mark.parametrize("app,ceiling", [("dbus-daemon", 8), ("polkitd", 3), ("other-daemon", 6)])
def test_bounded_arrivals_vary_by_host_window_and_seed(app: str, ceiling: int) -> None:
    start = datetime(2026, 11, 2, 13, tzinfo=UTC)
    entry = {
        "app": app,
        "messages": ["health"],
        "max_per_host_window": ceiling,
        "window_occurrence_probability": 0.65,
        "window_arrival_mode": 0.5,
    }
    hosts = [
        System(hostname=f"LINUX-{i}", ip=f"10.0.0.{i + 1}", os="Ubuntu 22.04", type="server")
        for i in range(24)
    ]

    def schedules(seed: int) -> list[tuple[float, ...]]:
        return [
            _extra_syslog_arrival_offsets(
                host, entry, start, start + timedelta(hours=8), TimingSampler(generation_seed=seed)
            )
            for host in hosts
        ]

    first = schedules(17)
    assert first == schedules(17)
    assert first != schedules(18)
    assert len({len(times) for times in first}) >= 3
    assert all(len(times) <= ceiling and tuple(sorted(times)) == times for times in first)
    assert all(0 <= offset <= 8 * 3600 for times in first for offset in times)
    assert sum(offset > 4 * 3600 for times in first for offset in times) > 10
    assert first[0] != _extra_syslog_arrival_offsets(
        hosts[0],
        entry,
        start + timedelta(days=1),
        start + timedelta(days=1, hours=8),
        TimingSampler(generation_seed=17),
    )


def test_unconfigured_cap_keeps_existing_admission_semantics() -> None:
    start = datetime(2026, 11, 2, tzinfo=UTC)
    host = System(hostname="LINUX", ip="10.0.0.1", os="Ubuntu 22.04", type="server")
    entry = {"app": "anacron", "messages": ["health"], "max_per_host_window": 1}
    assert (
        _extra_syslog_arrival_offsets(
            host, entry, start, start + timedelta(hours=8), TimingSampler(generation_seed=1)
        )
        is None
    )


@pytest.mark.parametrize(
    "patch",
    [
        {"window_occurrence_probability": 0.5},
        {"max_per_host_window": 3, "window_occurrence_probability": -0.1},
        {"max_per_host_window": 3, "window_occurrence_probability": 1.1},
        {"max_per_host_window": 3, "window_arrival_mode": 0},
        {"max_per_host_window": 3, "window_arrival_mode": 1},
    ],
)
def test_bounded_arrival_config_rejects_invalid_profiles(patch: dict[str, object]) -> None:
    with pytest.raises(ValidationError):
        SyslogProgramEntry.model_validate({"app": "daemon", "messages": ["health"], **patch})
