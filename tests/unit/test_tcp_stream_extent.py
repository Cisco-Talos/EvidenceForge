# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Known TCP sequence extent survives content loss without rewriting captured packets."""

import json
from dataclasses import replace
from pathlib import Path

import pytest

from evidenceforge.events.contexts import FileTransferContext, HttpContext
from evidenceforge.events.network import (
    DirectionalTrafficLedger,
    NetworkTrafficLedger,
    TcpStreamExtent,
)
from evidenceforge.formats import load_format
from evidenceforge.generation.activity.timing_profiles import NetworkSensorObservationTiming
from evidenceforge.generation.checkpoints.errors import CheckpointCorruptionError
from evidenceforge.generation.checkpoints.state_values import decode_state_value, encode_state_value
from evidenceforge.generation.emitters.zeek import ZeekEmitter
from evidenceforge.generation.network_observation import (
    NetworkObservationPlanner,
    PersistentSmbTrafficRebindAuthority,
    plan_tcp_stream_extent,
)
from evidenceforge.generation.smb_channels import _smb_admission_graph_bytes
from tests.unit.test_network_observation import (
    _authenticated_persistent_smb_rebind,
    _final_lossy_smb_traffic,
    _final_smb_traffic,
    _lossy_smb_traffic,
    _network_event,
    _persistent_smb_observation,
    _persistent_smb_transport,
    _visibility_engine,
)


@pytest.mark.parametrize("invalid", [-1, True, 1.25, "12"])
def test_extent_rejects_non_native_integer_counts(invalid: object) -> None:
    with pytest.raises(ValueError):
        TcpStreamExtent(invalid, 0)
    with pytest.raises(CheckpointCorruptionError):
        decode_state_value(["record", "tcp-stream-extent-v1", [invalid, 0]])


@pytest.mark.parametrize(
    ("history", "expected"),
    [
        ("ShADadFfGg", TcpStreamExtent(1200, 8400)),
        ("ShADadF", TcpStreamExtent(1200, None)),
        ("ShADadf", TcpStreamExtent(None, 8400)),
        ("DdFfGg", None),
        ("ShADadGg", None),
    ],
)
def test_extent_requires_directional_sequence_boundaries(
    history: str, expected: TcpStreamExtent | None
) -> None:
    traffic = _network_event(protocol="tcp").network.traffic
    assert plan_tcp_stream_extent(traffic, "tcp", history) == expected
    assert plan_tcp_stream_extent(traffic, "udp", history) is None
    assert plan_tcp_stream_extent(traffic, "icmp", history) is None


def test_native_stream_totals_and_file_capture_have_separate_owners(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    event = _network_event(protocol="tcp")
    event.dns = None
    event.network = replace(event.network, history="ShADadFf", service="http", dst_port=80)
    event.http = HttpContext(
        method="GET", host="files.example.com", uri="/payload.bin", response_body_len=8000
    )
    event.file_transfer = FileTransferContext(
        fuid="FExtentFile1", source="HTTP", is_orig=False, seen_bytes=8000, total_bytes=8000
    )
    captured = NetworkTrafficLedger(
        orig=DirectionalTrafficLedger(200, 4, 360),
        resp=DirectionalTrafficLedger(4200, 12, 4680),
        missed_orig_bytes=1000,
        missed_resp_bytes=4200,
    )

    def observe(
        canonical: NetworkTrafficLedger,
        _timing: NetworkSensorObservationTiming,
        sensor: str,
        _transaction: str,
        _protocol: str,
        _history: str,
    ) -> NetworkTrafficLedger:
        return canonical if sensor == "source-tap" else captured

    monkeypatch.setattr(NetworkObservationPlanner, "_observed_traffic", staticmethod(observe))
    event.network_observations = NetworkObservationPlanner(_visibility_engine()).plan(
        event, {"zeek_conn"}
    )
    event.network_observations_planned = True
    observations = {item.sensor_identity: item for item in event.network_observations}
    lossy = observations["destination-tap"]
    assert lossy.tcp_stream == TcpStreamExtent(1200, 8400)
    assert lossy.traffic is captured
    # Recognized stream gaps remain part of the HTTP body extent, while files
    # separately report the captured and missing portions of that body.
    assert lossy.http_response_body_len == 8000
    assert lossy.file_observations[0].seen_bytes == 4000
    assert lossy.file_observations[0].missing_bytes == 4000
    assert lossy.traffic.orig.ip_bytes < lossy.tcp_stream.orig_bytes
    emitter = ZeekEmitter(load_format("zeek_conn"), tmp_path)
    emitter.emit(event)
    emitter.close()
    rendered = {
        path.parent.name: json.loads(path.read_text().strip())
        for path in tmp_path.rglob("conn.json")
    }
    assert len(rendered) == 2
    for row in rendered.values():
        assert (row["orig_bytes"], row["resp_bytes"]) == (1200, 8400)
    row = rendered["destination-tap"]
    assert (row["orig_pkts"], row["orig_ip_bytes"], row["resp_pkts"], row["resp_ip_bytes"]) == (
        4,
        360,
        12,
        4680,
    )
    assert row["missed_bytes"] == 5200
    assert "G" in row["history"] and "g" in row["history"]
    encoded = encode_state_value(lossy)
    assert encoded[1] == "network-sensor-observation-v2"
    assert decode_state_value(encoded) == lossy
    legacy = ["record", "network-sensor-observation", encoded[2][:-1]]
    restored = decode_state_value(legacy)
    assert restored.tcp_stream is None
    assert restored.traffic == captured


def test_persistent_terminal_extent_uses_final_wire_totals_and_authenticates_opening() -> None:
    transport = _persistent_smb_transport()
    first = replace(
        _persistent_smb_observation(transport.traffic, sensor_identity="sensor-a"),
        tcp_stream=plan_tcp_stream_extent(transport.traffic, "tcp", transport.history),
    )
    second = replace(
        _persistent_smb_observation(_lossy_smb_traffic(), sensor_identity="sensor-b"),
        tcp_stream=first.tcp_stream,
    )
    assert _smb_admission_graph_bytes(first)
    authority = PersistentSmbTrafficRebindAuthority()
    binding = authority.issue_binding(transport, (first, second))
    final = _final_smb_traffic()
    _, observations = _authenticated_persistent_smb_rebind(
        authority, binding, transport, final, (first, second), (final, _final_lossy_smb_traffic())
    )
    assert all(
        item.tcp_stream == TcpStreamExtent(final.orig.payload_bytes, final.resp.payload_bytes)
        for item in observations
    )
    assert observations[1].traffic == _final_lossy_smb_traffic()
    assert observations[1].tcp_stream != second.tcp_stream
    forged = replace(
        first, tcp_stream=TcpStreamExtent(transport.traffic.orig.payload_bytes + 1, 500)
    )
    with pytest.raises(ValueError, match="canonical boundary truth"):
        authority.issue_binding(transport, (forged,))


@pytest.mark.parametrize("damage", ["too_small", "non_tcp", "untyped"])
def test_observation_rejects_incompatible_stream_truth(damage: str) -> None:
    transport = _persistent_smb_transport()
    observation = _persistent_smb_observation(transport.traffic, sensor_identity="sensor-a")
    with pytest.raises(ValueError):
        if damage == "too_small":
            replace(observation, tcp_stream=TcpStreamExtent(999, 500))
        elif damage == "non_tcp":
            replace(
                observation,
                tuple_view=replace(observation.tuple_view, protocol="udp"),
                tcp_stream=TcpStreamExtent(1000, 500),
            )
        else:
            replace(observation, tcp_stream={"orig_bytes": 1000, "resp_bytes": 500})
