# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Source delay bounds do not quantize otherwise precise native timestamps."""

from datetime import UTC, datetime, timedelta

import pytest

from evidenceforge.events.base import OccurrenceBuilder
from evidenceforge.events.contexts import HostContext, SyslogContext
from evidenceforge.events.observation import ObservationPolicy
from evidenceforge.utils.rng import _get_rng, generation_seed_scope


def _event(index: int) -> OccurrenceBuilder:
    return OccurrenceBuilder(
        timestamp=datetime(2026, 11, 2, 13, tzinfo=UTC) + timedelta(seconds=index),
        event_type="syslog",
        src_host=HostContext(
            hostname=f"LINUX-{index % 20}",
            ip="10.0.0.10",
            os="Ubuntu 24.04",
            os_category="linux",
            system_type="server",
        ),
        syslog=SyslogContext(app_name="daemon", message="startup", pid=100 + index),
    )


def test_whole_second_occurrences_retain_continuous_bounded_source_delay(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        "evidenceforge.events.observation.get_observation_profile",
        lambda _name: {"default": {"missingness": 0.0, "delay_ms": {"min_ms": 0, "max_ms": 250}}},
    )
    policy = ObservationPolicy("continuous-delay-contract")
    with generation_seed_scope(42):
        delays = [policy.decide("syslog", _event(i)).delay for i in range(100)]
    assert all(timedelta(0) <= delay <= timedelta(milliseconds=250) for delay in delays)
    # A profile's millisecond bounds must not reveal whether the canonical
    # occurrence was scheduled on a whole second. Test a family of hosts/rows.
    assert len({delay.microseconds % 1000 for delay in delays}) > 50


@pytest.mark.parametrize("milliseconds", [0, 5, 250])
def test_fixed_source_delay_preserves_the_exact_configured_value(
    monkeypatch: pytest.MonkeyPatch, milliseconds: int
) -> None:
    monkeypatch.setattr(
        "evidenceforge.events.observation.get_observation_profile",
        lambda _name: {
            "default": {
                "missingness": 0.0,
                "delay_ms": {"min_ms": milliseconds, "max_ms": milliseconds},
            }
        },
    )
    decision = ObservationPolicy("fixed-delay-contract").decide("syslog", _event(1))
    assert decision.delay == timedelta(milliseconds=milliseconds)
    assert decision.status == ("delayed" if milliseconds else "visible")


def test_continuous_delay_is_seed_scoped_and_leaves_the_shared_rng_untouched() -> None:
    policy = ObservationPolicy("enterprise_standard")
    event = _event(3)
    with generation_seed_scope(42):
        before = _get_rng().getstate()
        first = policy.decide("syslog", event)
        assert first == policy.decide("syslog", event)
        assert _get_rng().getstate() == before
    with generation_seed_scope(43):
        second = policy.decide("syslog", event)
    with generation_seed_scope(42):
        assert policy.decide("syslog", event) == first
    assert first.delay != second.delay


def test_exact_source_delay_is_stable_within_one_projection_and_separates_collectors() -> None:
    policy = ObservationPolicy("enterprise_standard")
    event = _event(3)
    kwargs = {"source_hostname": "LINUX-3", "missingness": 0.0}
    first = policy.decide_projection("syslog", event, source_instance="collector:a", **kwargs)
    second = policy.decide_projection("syslog", event, source_instance="collector:b", **kwargs)
    assert first == policy.decide_projection(
        "syslog", event, source_instance="collector:a", **kwargs
    )
    assert first.delay != second.delay
