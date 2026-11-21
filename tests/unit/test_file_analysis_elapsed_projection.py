# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Sensors project one canonical file elapsed time instead of inventing speeds."""

from datetime import UTC, datetime, timedelta

import pytest

from evidenceforge.events.base import OccurrenceBuilder
from evidenceforge.events.contexts import FileTransferContext, HttpContext
from evidenceforge.generation import network_observation
from evidenceforge.generation.activity.timing_profiles import NetworkSensorObservationTiming
from evidenceforge.generation.network_observation import (
    NetworkObservationPlanner,
    network_source_timing_key,
)
from evidenceforge.generation.timing import TimingRuntime
from tests.network_factories import network_plan

_START = datetime(2026, 11, 2, 13, tzinfo=UTC)
_FUID = "FSharedElapsed001"
_FORMATS = {"zeek_conn", "zeek_http", "zeek_files"}


def _clock(drift_ppm: int = 0) -> NetworkSensorObservationTiming:
    return NetworkSensorObservationTiming(
        profile_name=f"elapsed-test-{drift_ppm}",
        clock_offset_min_us=0,
        clock_offset_max_us=0,
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


def _event(file_seconds: float, *, flow_seconds: float = 20) -> OccurrenceBuilder:
    event = OccurrenceBuilder(
        timestamp=_START,
        event_type="connection",
        network=network_plan(
            src_ip="10.0.0.10",
            src_port=50100,
            dst_ip="198.51.100.20",
            dst_port=80,
            protocol="tcp",
            service="http",
            zeek_uid="CSharedElapsed001",
            conn_id="shared-elapsed-connection",
            duration=flow_seconds,
            source_visible_start_time=_START,
            source_visible_close_time=_START + timedelta(seconds=flow_seconds),
            orig_bytes=1000,
            resp_bytes=100000,
            orig_pkts=10,
            resp_pkts=80,
            orig_ip_bytes=1600,
            resp_ip_bytes=104160,
            conn_state="SF",
            history="ShADadFf",
        ),
        http=HttpContext(
            method="GET",
            host="files.example.test",
            uri="/data.bin",
            response_body_len=100000,
            resp_fuids=(_FUID,),
            canonical_request_time=_START + timedelta(milliseconds=10),
        ),
        file_transfer=FileTransferContext(
            fuid=_FUID,
            source="HTTP",
            duration=file_seconds,
            seen_bytes=100000,
            total_bytes=100000,
        ),
    )
    event._sensor_hostnames_by_format = {name: ["tap-one"] for name in _FORMATS}
    return event


@pytest.mark.parametrize("file_seconds", [0.2, 7.123456])
def test_two_sensors_preserve_shared_elapsed_with_flat_clocks(
    monkeypatch: pytest.MonkeyPatch,
    file_seconds: float,
) -> None:
    monkeypatch.setattr(
        network_observation, "network_sensor_observation_timing", lambda _: _clock()
    )
    planner = NetworkObservationPlanner(None, timing_runtime=TimingRuntime(reference_time=_START))
    observations = planner.plan(
        _event(file_seconds),
        _FORMATS,
        sensor_formats={"tap-one": _FORMATS, "tap-two": _FORMATS},
    )
    assert len(observations) == 2
    key = network_source_timing_key("zeek_files", _FUID)
    assert [row.source_duration(key) for row in observations] == [file_seconds, file_seconds]


@pytest.mark.parametrize("drift_ppm", [-2000, 2000])
def test_file_elapsed_follows_sensor_clock_rate(
    monkeypatch: pytest.MonkeyPatch,
    drift_ppm: int,
) -> None:
    monkeypatch.setattr(
        network_observation, "network_sensor_observation_timing", lambda _: _clock(drift_ppm)
    )
    planner = NetworkObservationPlanner(None, timing_runtime=TimingRuntime(reference_time=_START))
    observation = planner.plan(_event(7), _FORMATS)[0]
    elapsed = observation.source_duration(network_source_timing_key("zeek_files", _FUID))
    assert elapsed == pytest.approx(7 * (1 + drift_ppm / 1000000), abs=0.000002)


def test_source_file_start_reserves_full_elapsed_before_close(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        network_observation, "network_sensor_observation_timing", lambda _: _clock()
    )
    planner = NetworkObservationPlanner(None, timing_runtime=TimingRuntime(reference_time=_START))
    observation = planner.plan(_event(0.2, flow_seconds=0.23), _FORMATS)[0]
    key = network_source_timing_key("zeek_files", _FUID)
    start, elapsed = observation.source_time(key), observation.source_duration(key)
    assert start is not None and elapsed == 0.2
    assert start >= _START + timedelta(milliseconds=10)
    assert start + timedelta(seconds=elapsed) < observation.observed_close_time
