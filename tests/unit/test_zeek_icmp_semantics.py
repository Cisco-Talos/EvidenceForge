# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""ICMP conn fields preserve Zeek protocol-specific semantics."""

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from evidenceforge.evaluation.ground_truth_agreement import _fields_match
from evidenceforge.evaluation.parsers import ParsedRecord
from evidenceforge.events.base import OccurrenceBuilder
from evidenceforge.events.evidence_projection import native_requirements
from evidenceforge.events.network import NetworkSensorObservation, NetworkTuple
from evidenceforge.formats import load_format
from evidenceforge.generation.emitters.zeek import ZeekEmitter
from evidenceforge.generation.emitters.zeek_base import (
    native_zeek_connection_history,
    native_zeek_connection_state,
)
from tests.network_factories import network_plan


@pytest.mark.parametrize("answered", [True, False])
@pytest.mark.parametrize("planned", [True, False])
@pytest.mark.parametrize("icmp_type", [0, 8, 3])
def test_icmp_native_state_and_history_with_optional_sensor_projection(
    tmp_path: Path, answered: bool, planned: bool, icmp_type: int
) -> None:
    started = datetime(2026, 11, 2, 13, tzinfo=UTC)
    network = network_plan(
        src_ip="192.0.2.1",
        src_port=icmp_type,
        dst_ip="192.0.2.2",
        dst_port=0,
        protocol="icmp",
        ip_proto=1,
        service="icmp",
        duration=0.1,
        zeek_uid="CIcmpNative",
        conn_state="SF" if answered else "S0",
        history="Dd" if answered else "D",
        orig_bytes=56,
        resp_bytes=56 if answered else 0,
        orig_pkts=1,
        resp_pkts=1 if answered else 0,
        orig_ip_bytes=84,
        resp_ip_bytes=84 if answered else 0,
        source_visible_start_time=started,
        source_visible_close_time=started + timedelta(seconds=0.1),
    )
    event = OccurrenceBuilder(timestamp=started, event_type="connection", network=network)
    output = tmp_path / "conn.json"
    if planned:
        event.network_observations = (
            NetworkSensorObservation(
                sensor_identity="tap",
                path_role="internal",
                capture_profile="full",
                tuple_view=NetworkTuple("192.0.2.1", icmp_type, "192.0.2.2", 0, "icmp"),
                connection_uid="CIcmpNativeObserved",
                connection_ids=(),
                file_ids=(),
                local_orig=True,
                local_resp=False,
                observed_start_time=started,
                observed_close_time=started + timedelta(seconds=0.1),
                traffic=network.traffic,
                visible_formats=frozenset({"zeek_conn"}),
                history=network.history,
                source_times=(("zeek_conn", started),),
                source_durations=(("zeek_conn", 0.1),),
            ),
        )
        event.network_observations_planned = True
        output = tmp_path / "tap" / "conn.json"
    emitter = ZeekEmitter(
        load_format("zeek_conn"),
        tmp_path if planned else output,
        sensor_hostnames=["tap"] if planned else None,
        threaded=False,
    )
    emitter.emit(event)
    emitter.close()
    row = json.loads(output.read_text())
    assert row["conn_state"] == "OTH" and "history" not in row
    assert row["orig_bytes"] == 56 and row["orig_pkts"] == 1 and row["orig_ip_bytes"] == 84
    assert row["resp_bytes"] == (56 if answered else 0)
    assert row["id.orig_p"] == (icmp_type or 8) and row["id.resp_p"] == 0
    assert "service" not in row
    if not answered:
        assert "duration" not in row
    assert event.network.conn_state == ("SF" if answered else "S0")
    assert event.network.history == ("Dd" if answered else "D")
    requirement = native_requirements(
        "zeek_conn",
        "connection",
        {
            "network": {
                "protocol": "icmp",
                "src_ip": network.src_ip,
                "src_port": network.src_port,
                "dst_ip": network.dst_ip,
                "dst_port": network.dst_port,
                "conn_state": network.conn_state,
            }
        },
        {"zeek_uid": "CIcmpNative"},
        "sensor",
    )[0]
    record = ParsedRecord(source_format="zeek_conn", raw="", fields=row)
    assert _fields_match(record, requirement.selector)
    assert _fields_match(record, requirement.required)
    record.fields = {**row, "id.orig_p": 99}
    assert not _fields_match(record, requirement.required)
    record.fields = {**row, "conn_state": network.conn_state}
    assert not _fields_match(record, requirement.required)


@pytest.mark.parametrize(
    ("protocol", "state", "history"),
    [
        ("tcp", "SF", "ShADadFf"),
        ("tcp", "RSTO", "ShADadR"),
        ("udp", "SF", "Dd"),
        ("udp", "S0", "D"),
    ],
)
def test_tcp_udp_native_fields_are_preserved(protocol: str, state: str, history: str) -> None:
    assert native_zeek_connection_state(protocol, state) == state
    assert native_zeek_connection_history(protocol, history) == history
