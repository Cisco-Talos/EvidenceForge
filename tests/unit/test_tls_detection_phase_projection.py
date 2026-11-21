# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT
"""Each sensor observes the same canonical TLS first-detection phase."""

from dataclasses import replace
from datetime import UTC, datetime, timedelta

import pytest

from evidenceforge.events.base import OccurrenceBuilder
from evidenceforge.events.contexts import SslContext
from evidenceforge.generation import network_observation
from evidenceforge.generation.activity.timing_profiles import NetworkSensorObservationTiming
from evidenceforge.generation.network_observation import (
    NetworkObservationPlanner,
    network_source_timing_key,
)
from evidenceforge.generation.timing import TimingRuntime
from tests.network_factories import network_plan

_START = datetime(2026, 11, 2, 13, tzinfo=UTC)
_FORMATS = {"zeek_conn", "zeek_ssl"}


def _clock(offset_us: int = 0, drift_ppm: int = 0) -> NetworkSensorObservationTiming:
    return NetworkSensorObservationTiming(
        profile_name="tls-phase-test",
        clock_offset_min_us=offset_us,
        clock_offset_max_us=offset_us,
        clock_drift_min_ppm=drift_ppm,
        clock_drift_max_ppm=drift_ppm,
        route_delay_min_us=0,
        route_delay_max_us=0,
        event_jitter_min_us=0,
        event_jitter_max_us=0,
        capture_loss_probability=0,
        capture_loss_min_fraction=0,
        capture_loss_max_fraction=0,
        capture_loss_max_missed_bytes=0,
    )


def _event(
    version: str = "TLSv12", state: str = "SF", phase_seconds: float = 0.125
) -> OccurrenceBuilder:
    transport = network_plan(
        src_ip="10.0.0.10",
        src_port=50100,
        dst_ip="10.0.1.20",
        dst_port=443,
        protocol="tcp",
        service="ssl",
        zeek_uid="CSharedTlsPhase001",
        conn_id="shared-tls-phase",
        duration=2.0,
        source_visible_start_time=_START,
        orig_bytes=1000,
        resp_bytes=2000,
        orig_pkts=6,
        resp_pkts=8,
        orig_ip_bytes=1312,
        resp_ip_bytes=2416,
        conn_state=state,
        history="ShADadfF" if state == "SF" else "ShADadRr",
    )
    transport = replace(
        transport,
        phase_times=(
            ("transport_start", _START),
            ("tls_detected", _START + timedelta(seconds=phase_seconds)),
            ("transport_close", _START + timedelta(seconds=2)),
        ),
    )
    event = OccurrenceBuilder(
        timestamp=_START,
        event_type="connection",
        network=transport,
        ssl=SslContext(
            version=version,
            cipher="TLS_AES_128_GCM_SHA256"
            if version == "TLSv13"
            else "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
            server_name="service.example.test",
            established=True,
        ),
    )
    event._sensor_hostnames_by_format = {name: ["tap-one"] for name in _FORMATS}
    return event


@pytest.mark.parametrize(
    "version, state", [("TLSv12", "SF"), ("TLSv13", "SF"), ("TLSv12", "RSTO"), ("TLSv13", "RSTR")]
)
def test_sensors_preserve_one_tls_detection_phase(
    monkeypatch: pytest.MonkeyPatch, version: str, state: str
) -> None:
    monkeypatch.setattr(
        network_observation, "network_sensor_observation_timing", lambda _: _clock()
    )
    planner = NetworkObservationPlanner(None, timing_runtime=TimingRuntime(reference_time=_START))
    observations = planner.plan(
        _event(version, state), _FORMATS, sensor_formats={"tap-one": _FORMATS, "tap-two": _FORMATS}
    )
    assert len(observations) == 2
    assert [row.source_time(network_source_timing_key("zeek_ssl")) for row in observations] == [
        _START + timedelta(milliseconds=125)
    ] * 2


@pytest.mark.parametrize("drift_ppm", [-2000, 2000])
def test_tls_phase_projects_clock_rate_and_offset(
    monkeypatch: pytest.MonkeyPatch, drift_ppm: int
) -> None:
    monkeypatch.setattr(
        network_observation, "network_sensor_observation_timing", lambda _: _clock(70000, drift_ppm)
    )
    planner = NetworkObservationPlanner(None, timing_runtime=TimingRuntime(reference_time=_START))
    observed = planner.plan(_event(), _FORMATS)[0]
    phase = observed.source_time(network_source_timing_key("zeek_ssl"))
    assert phase is not None
    assert (phase - observed.observed_start_time).total_seconds() == pytest.approx(
        0.125 * (1 + drift_ppm / 1000000), abs=0.000002
    )


def test_supplied_late_tls_phase_is_not_replaced_with_analyzer_delay(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        network_observation, "network_sensor_observation_timing", lambda _: _clock()
    )
    planner = NetworkObservationPlanner(None, timing_runtime=TimingRuntime(reference_time=_START))
    observed = planner.plan(_event(phase_seconds=1.6), _FORMATS)[0]
    assert observed.source_time(network_source_timing_key("zeek_ssl")) == _START + timedelta(
        seconds=1.6
    )
