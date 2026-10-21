# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Short HTTP lifetimes vary without escaping the same owner's close bound."""

from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import pytest
from pydantic import ValidationError

from evidenceforge.config.schemas import HttpTransportFloorSlackConfig
from evidenceforge.generation.actions.network_connection import NetworkConnectionRequest
from evidenceforge.generation.actions.network_transaction_planner import (
    NetworkTransactionPlanner,
    http_completed_transport_close_bound_seconds,
)
from evidenceforge.generation.activity import network_params
from evidenceforge.generation.timing import TimingRuntime


def test_short_http_lifetimes_have_scoped_variation_and_stay_inside_admission_bound() -> None:
    at = datetime(2026, 10, 21, 14, tzinfo=UTC)
    runtime = TimingRuntime(reference_time=at, generation_seed=329)
    planner = NetworkTransactionPlanner(SimpleNamespace(timing_runtime=runtime))
    durations: list[float] = []
    for index in range(80):
        request = NetworkConnectionRequest(
            src_ip="192.0.2.10",
            dst_ip="198.51.100.20",
            dst_port=80,
            proto="tcp",
            service="http",
            time=at + timedelta(seconds=index),
            duration=0.03,
            conn_state="SF",
        )
        duration = planner._completed_http_duration_seconds(request, request.duration)
        assert duration == planner._completed_http_duration_seconds(request, request.duration)
        assert duration <= http_completed_transport_close_bound_seconds(
            caller_duration_maximum=0.03
        )
        assert planner._completed_http_duration_seconds(request, 5.0) == 5.0
        durations.append(duration)
    assert len(set(durations)) == len(durations)
    assert max(durations) - min(durations) > 0.3


def test_missing_frozen_http_policy_retains_legacy_parameters(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(network_params, "load_network_params", lambda: {})
    profile = network_params.http_transport_floor_slack_config()
    assert profile.model_dump() == {
        "median_ms": 3.6,
        "sigma": 0.88,
        "minimum_ms": 0.0,
        "maximum_ms": 25.001,
    }
    merged = network_params.merge_network_params(
        {"http_transport_floor_slack": {"median_ms": 7, "maximum_ms": 100}},
        {"http_transport_floor_slack": {"sigma": 0.7}},
    )
    assert merged["http_transport_floor_slack"] == {
        "median_ms": 7,
        "maximum_ms": 100,
        "sigma": 0.7,
    }


@pytest.mark.parametrize(
    "changes",
    [{"median_ms": 80}, {"sigma": 0}, {"maximum_ms": float("inf")}, {"minimum_ms": 6}],
)
def test_http_close_policy_rejects_unbounded_or_inverted_ranges(changes: dict[str, float]) -> None:
    with pytest.raises(ValidationError):
        HttpTransportFloorSlackConfig.model_validate(changes)
