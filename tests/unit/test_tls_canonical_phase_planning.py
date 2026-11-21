# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT
"""Canonical TLS first detection respects parent time and physical transport bounds."""

from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import pytest

from evidenceforge.events.contexts import HttpContext, SslContext
from evidenceforge.generation.actions import NetworkConnectionRequest
from evidenceforge.generation.actions.network_transaction_planner import NetworkTransactionPlanner
from evidenceforge.generation.timing import TimingRuntime

_START = datetime(2026, 11, 2, 13, tzinfo=UTC)


def _planner(parent: object = None) -> NetworkTransactionPlanner:
    return NetworkTransactionPlanner(
        SimpleNamespace(
            timing_runtime=TimingRuntime(reference_time=_START),
            state_manager=SimpleNamespace(get_connection=lambda _: parent),
        )
    )


def _event(http_time: datetime | None = None, *, child: bool = False) -> SimpleNamespace:
    return SimpleNamespace(
        ssl=SslContext(version="TLSv13", established=True),
        x509=None,
        x509_chain=(),
        network=SimpleNamespace(application_layer_only=child, conn_id="physical-parent"),
        http=HttpContext(canonical_request_time=http_time) if http_time is not None else None,
    )


def _request(offset: int = 0) -> NetworkConnectionRequest:
    return NetworkConnectionRequest(
        src_ip="10.0.0.10",
        dst_ip="10.0.1.20",
        dst_port=443,
        service="ssl",
        time=_START + timedelta(microseconds=offset),
        duration=2,
    )


@pytest.mark.parametrize("http_microseconds", [20, 5000, 1500000])
def test_canonical_detection_fits_before_known_http_request(http_microseconds: int) -> None:
    planner = _planner()
    http_time = _START + timedelta(microseconds=http_microseconds)
    phase = planner._tls_detection_time(
        _request(), _event(http_time), _START, _START + timedelta(seconds=2)
    )
    assert _START < phase < http_time


def test_canonical_detection_uses_native_quantum_for_one_microsecond_parent() -> None:
    planner = _planner()
    phase = planner._tls_detection_time(
        _request(), _event(), _START, _START + timedelta(microseconds=1)
    )
    assert phase == _START


def test_open_tls_transport_keeps_bounded_detection_and_replay() -> None:
    planner = _planner()
    request = _request()
    first = planner._tls_detection_time(request, _event(), _START, None)
    assert _START < first < _START + timedelta(milliseconds=650)
    assert planner._tls_detection_time(request, _event(), _START, None) == first


def test_tls_phases_vary_by_physical_request_instead_of_sensor() -> None:
    planner = _planner()
    phases = [
        planner._tls_detection_time(_request(n), _event(), _START, _START + timedelta(seconds=2))
        for n in range(50)
    ]
    assert len(set(phases)) > 40
    assert all(_START < phase < _START + timedelta(milliseconds=650) for phase in phases)


def test_http_child_reuses_parent_tls_phase() -> None:
    known = _START + timedelta(milliseconds=140)
    parent = SimpleNamespace(
        http_capture_transaction=SimpleNamespace(
            phase_times=(("transport_start", _START), ("tls_detected", known))
        )
    )
    planner = _planner(parent)
    phase = planner._tls_detection_time(
        _request(1000000),
        _event(_START + timedelta(seconds=1), child=True),
        _START,
        _START + timedelta(seconds=2),
    )
    assert phase == known
