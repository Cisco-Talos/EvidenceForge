# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""First-request readiness comes from continuous scoped canonical timing."""

from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import pytest
from pydantic import ValidationError

from evidenceforge.config.schemas import HttpRequestPhaseConfig
from evidenceforge.generation.actions.network_connection import NetworkConnectionRequest
from evidenceforge.generation.actions.network_transaction_planner import NetworkTransactionPlanner
from evidenceforge.generation.activity import network_params
from evidenceforge.generation.timing import TimingRuntime


@pytest.mark.parametrize("port", [80, 8080])
def test_http_request_phase_has_microsecond_variation_and_replays(port: int) -> None:
    at = datetime(2026, 11, 2, 13, tzinfo=UTC)
    planner = NetworkTransactionPlanner(
        SimpleNamespace(timing_runtime=TimingRuntime(reference_time=at, generation_seed=35))
    )
    phases: list[timedelta] = []
    for i in range(100):
        request = NetworkConnectionRequest(
            src_ip="192.0.2.1",
            dst_ip="198.51.100.2",
            dst_port=port,
            proto="tcp",
            service="http",
            time=at + timedelta(seconds=i),
            duration=2.0,
            conn_state="SF",
        )
        value = planner._http_request_phase_delay(request)
        assert value == planner._http_request_phase_delay(request)
        phases.append(value)
    assert len(set(phases)) == 100
    assert sum(v.microseconds % 1000 == 0 for v in phases) <= 2
    assert all(0.003 < v.total_seconds() < 0.180 for v in phases)


def test_http_request_phase_overlay_preserves_unspecified_policy(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    merged = network_params.merge_network_params(
        {
            "http_request_phase": {
                "minimum_ms": 3,
                "median_ms": 28,
                "maximum_ms": 180,
                "sigma": 0.65,
            }
        },
        {"http_request_phase": {"median_ms": 40}},
    )
    monkeypatch.setattr(network_params, "load_network_params", lambda: merged)
    assert network_params.http_request_phase_config().median_ms == 40
    assert network_params.http_request_phase_config().minimum_ms == 3


@pytest.mark.parametrize(
    "patch",
    [
        {"median_ms": 1},
        {"maximum_ms": 2},
        {"sigma": 0},
        {"minimum_ms": float("nan")},
        {"maximum_ms": float("inf")},
    ],
)
def test_http_request_phase_rejects_invalid_policy(patch: dict[str, float]) -> None:
    with pytest.raises(ValidationError):
        HttpRequestPhaseConfig.model_validate(patch)
