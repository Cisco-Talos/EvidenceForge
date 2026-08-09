# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Tests for canonical network-sensor observation and lifecycle admission."""

from __future__ import annotations

import json
import statistics
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from unittest.mock import MagicMock

import pytest

from evidenceforge.events import HostContext
from evidenceforge.events.base import CanonicalOccurrence, OccurrenceBuilder, RawProjectionRequest
from evidenceforge.events.contexts import (
    DnsContext,
    FileTransferContext,
    HttpContext,
    IdsAlertPlan,
    NatContext,
    SyslogContext,
)
from evidenceforge.events.dispatcher import EventDispatcher
from evidenceforge.events.lifecycle import ActionLifecycleContext
from evidenceforge.events.network import (
    DirectionalTrafficLedger,
    NetworkSensorObservation,
    NetworkTrafficLedger,
)
from evidenceforge.formats import load_format
from evidenceforge.generation.activity.timing_profiles import NetworkSensorObservationTiming
from evidenceforge.generation.emitters.snort import SnortEmitter
from evidenceforge.generation.emitters.zeek import ZeekEmitter
from evidenceforge.generation.emitters.zeek_dns import ZeekDnsEmitter
from evidenceforge.generation.emitters.zeek_http import ZeekHttpEmitter
from evidenceforge.generation.network_observation import NetworkObservationPlanner
from evidenceforge.generation.network_visibility import NetworkVisibilityEngine
from evidenceforge.generation.state_manager import StateManager
from evidenceforge.models.scenario import (
    NetworkConfig,
    NetworkSegment,
    NetworkSensor,
)
from tests.network_factories import network_plan

T0 = datetime(2026, 3, 19, 10, 0, 0, tzinfo=UTC)


def _assert_published_once(mock: MagicMock, builder: OccurrenceBuilder) -> CanonicalOccurrence:
    """Assert one call received the sealed occurrence derived from ``builder``."""

    mock.assert_called_once()
    occurrence = mock.call_args.args[0]
    assert isinstance(occurrence, CanonicalOccurrence)
    assert occurrence.occurrence_id == builder.occurrence_id
    return occurrence


def _visibility_engine(
    *,
    source_profile: str = "",
    destination_profile: str = "",
) -> NetworkVisibilityEngine:
    config = NetworkConfig(
        segments=[
            NetworkSegment(
                name="workstations",
                cidr="10.0.1.0/24",
                exposure="internal",
            ),
            NetworkSegment(
                name="servers",
                cidr="10.0.2.0/24",
                exposure="internal",
            ),
        ],
        sensors=[
            NetworkSensor(
                type="network",
                name="source-tap",
                monitoring_segments=["workstations"],
                capture_profile=source_profile,
                log_formats=["zeek"],
            ),
            NetworkSensor(
                type="network",
                name="destination-tap",
                monitoring_segments=["servers"],
                capture_profile=destination_profile,
                log_formats=["zeek"],
            ),
        ],
    )
    return NetworkVisibilityEngine(config, systems=[])


def _network_event(
    *,
    start: datetime = T0,
    stable_id: str = "network:test-transaction",
    protocol: str = "udp",
    zeek_uid: str = "CObservationTest1",
) -> OccurrenceBuilder:
    duration = 2.5
    network = network_plan(
        src_ip="10.0.1.25",
        src_port=51000,
        dst_ip="10.0.2.40",
        dst_port=53,
        protocol=protocol,
        service="dns",
        zeek_uid=zeek_uid,
        conn_id="conn-observation-test",
        duration=duration,
        source_visible_start_time=start,
        source_visible_close_time=start + timedelta(seconds=duration),
        orig_bytes=1200,
        resp_bytes=8400,
        orig_pkts=12,
        resp_pkts=24,
        orig_ip_bytes=1536,
        resp_ip_bytes=9072,
        conn_state="SF",
        history="Dd",
        ip_proto=6 if protocol == "tcp" else 17,
    )
    transaction = replace(
        network,
        stable_id=stable_id,
        hostname="resolver.corp.local",
        phase_times=(
            ("transport_start", start),
            ("transport_close", start + timedelta(seconds=duration)),
        ),
    )
    event = OccurrenceBuilder(
        timestamp=start,
        event_type="connection",
        network=transaction,
        dns=DnsContext(
            query="updates.example.com",
            answers=["10.0.2.40"],
            TTLs=[300.0],
            trans_id=4242,
            rtt=0.04,
        ),
        lifecycle=ActionLifecycleContext(
            group_id=transaction.stable_id,
            canonical_start=transaction.started_at,
            phase="start",
        ),
    )
    event._sensor_hostnames_by_format = {
        "zeek_conn": ["source-tap", "destination-tap"],
        "zeek_dns": ["source-tap", "destination-tap"],
    }
    return event


def _observation_by_sensor(
    observations: tuple[NetworkSensorObservation, ...],
) -> dict[str, NetworkSensorObservation]:
    return {observation.sensor_identity: observation for observation in observations}


def test_lossless_and_nat_only_observations_retain_canonical_accounting() -> None:
    """Lossless mirrors may change tuple view and identity, never traffic truth."""

    event = _network_event()
    event.nat = NatContext(
        nat_type="dynamic_pat",
        mapped_src_ip="198.51.100.25",
        mapped_src_port=62000,
        mapped_dst_ip=event.network.dst_ip,
        mapped_dst_port=event.network.dst_port,
    )
    planner = NetworkObservationPlanner(
        _visibility_engine(source_profile="well_synced", destination_profile="well_synced")
    )

    first = planner.plan(event, {"zeek_conn", "zeek_dns"})
    second = planner.plan(event, {"zeek_conn", "zeek_dns"})
    observations = _observation_by_sensor(first)

    assert first == second
    assert observations["source-tap"].path_role == "source_side"
    assert observations["destination-tap"].path_role == "destination_side"
    assert observations["source-tap"].traffic is event.network.traffic
    assert observations["destination-tap"].traffic is event.network.traffic
    assert observations["source-tap"].traffic == observations["destination-tap"].traffic
    assert observations["source-tap"].tuple_view.src_ip == "10.0.1.25"
    assert observations["destination-tap"].tuple_view.src_ip == "198.51.100.25"
    assert observations["destination-tap"].tuple_view.src_port == 62000
    assert (
        observations["source-tap"].connection_uid != observations["destination-tap"].connection_uid
    )
    for observation in observations.values():
        assert observation.visible_formats == frozenset({"zeek_conn", "zeek_dns"})
        assert observation.connection_id(event.network.zeek_uid) == observation.connection_uid
        assert observation.traffic.missed_bytes == 0
        assert observation.observed_duration >= event.network.duration


def test_capture_loss_projects_file_and_http_completeness_with_gap_history() -> None:
    """Sensor loss must propagate beyond conn.log without changing canonical truth."""

    event = _network_event(protocol="tcp")
    event.http = HttpContext(
        method="GET",
        host="files.example.com",
        uri="/payload.bin",
        response_body_len=8_000,
    )
    event.file_transfer = FileTransferContext(
        fuid="FObservationFile1",
        source="HTTP",
        analyzers=("SHA256",),
        is_orig=False,
        seen_bytes=8_000,
        total_bytes=8_000,
        sha256="a" * 64,
    )
    observed = NetworkTrafficLedger(
        orig=event.network.traffic.orig,
        resp=DirectionalTrafficLedger(payload_bytes=4_200, packets=12, ip_bytes=4_536),
        missed_resp_bytes=4_200,
    )

    history, files, request_body, response_body = NetworkObservationPlanner._observed_protocol(
        event,
        observed,
    )

    assert history.endswith("g")
    assert request_body == 0
    assert response_body == 4_000
    assert files[0].seen_bytes == 4_000
    assert files[0].missing_bytes == 4_000
    assert not files[0].analyzers_visible
    assert event.file_transfer.seen_bytes == 8_000


def test_inbound_static_nat_sensor_views_come_from_topology_and_nat_context() -> None:
    """Inside and outside tuple views need no mutable event-side swap map."""

    config = NetworkConfig(
        segments=[
            NetworkSegment(name="outside", cidr="198.51.100.0/24", exposure="external"),
            NetworkSegment(name="servers", cidr="10.0.2.0/24", exposure="internal"),
        ],
        sensors=[
            NetworkSensor(
                type="network",
                name="outside-tap",
                monitoring_segments=["outside"],
                log_formats=["zeek"],
            ),
            NetworkSensor(
                type="network",
                name="inside-tap",
                monitoring_segments=["servers"],
                log_formats=["zeek"],
            ),
        ],
    )
    network = network_plan(
        src_ip="198.51.100.25",
        src_port=51000,
        dst_ip="203.0.113.80",
        dst_port=443,
        protocol="tcp",
        zeek_uid="CInboundNatView1",
        conn_id="conn-inbound-nat-view",
        duration=2.0,
        source_visible_start_time=T0,
        source_visible_close_time=T0 + timedelta(seconds=2),
        orig_bytes=200,
        resp_bytes=800,
        orig_pkts=3,
        resp_pkts=4,
        orig_ip_bytes=320,
        resp_ip_bytes=960,
        conn_state="SF",
        history="ShADadFf",
        local_orig=False,
        local_resp=True,
    )
    network = replace(
        network,
        stable_id="network:inbound-nat-view",
        hostname="web.corp.local",
        phase_times=(("transport_start", T0), ("transport_close", T0 + timedelta(seconds=2))),
    )
    event = OccurrenceBuilder(
        timestamp=T0,
        event_type="connection",
        network=network,
        nat=NatContext(
            nat_type="static",
            mapped_src_ip="198.51.100.25",
            mapped_src_port=51000,
            mapped_dst_ip="10.0.2.40",
            mapped_dst_port=443,
        ),
    )
    event._sensor_hostnames_by_format = {
        "zeek_conn": ["outside-tap", "inside-tap"],
    }

    observations = _observation_by_sensor(
        NetworkObservationPlanner(NetworkVisibilityEngine(config, systems=[])).plan(
            event,
            {"zeek_conn"},
        )
    )

    assert observations["outside-tap"].tuple_view.dst_ip == "203.0.113.80"
    assert observations["outside-tap"].tuple_view.dst_port == 443
    assert observations["inside-tap"].tuple_view.dst_ip == "10.0.2.40"
    assert observations["inside-tap"].tuple_view.dst_port == 443
    assert observations["inside-tap"].local_resp is True


def test_distributed_taps_have_sensor_local_timing_and_accounting_texture() -> None:
    """Distributed taps vary accounting while nearby clock offsets stay coherent."""

    planner = NetworkObservationPlanner(_visibility_engine())
    differing_traffic = 0
    relative_offsets: list[float] = []
    for index in range(200):
        event = _network_event(
            start=T0 + timedelta(seconds=index * 3),
            stable_id=f"network:distributed-texture:{index}",
            protocol="tcp",
            zeek_uid=f"CDistributedTexture{index}",
        )
        observations = _observation_by_sensor(planner.plan(event, {"zeek_conn", "zeek_dns"}))
        source = observations["source-tap"]
        destination = observations["destination-tap"]
        differing_traffic += source.traffic != destination.traffic
        relative_offsets.append(
            (destination.observed_start_time - source.observed_start_time).total_seconds()
        )

    assert differing_traffic >= 20
    assert statistics.pstdev(relative_offsets) < 0.005
    assert max(relative_offsets) - min(relative_offsets) < 0.015


def test_clock_wander_is_shared_by_nearby_flows_and_changes_slowly() -> None:
    """A sensor clock follows time, not independent transaction identities."""

    planner = NetworkObservationPlanner(_visibility_engine())
    observed_offsets: list[float] = []
    for index in range(60):
        event = _network_event(
            start=T0 + timedelta(seconds=index),
            stable_id=f"network:clock-coherence:{index}",
            zeek_uid=f"CClockCoherence{index}",
        )
        observation = _observation_by_sensor(planner.plan(event, {"zeek_conn", "zeek_dns"}))[
            "source-tap"
        ]
        observed_offsets.append((observation.observed_start_time - event.timestamp).total_seconds())

    assert max(observed_offsets) - min(observed_offsets) < 0.001
    consecutive_changes = [
        abs(current - previous)
        for previous, current in zip(observed_offsets, observed_offsets[1:], strict=False)
    ]
    assert max(consecutive_changes) < 0.0001


def test_same_connection_observations_preserve_canonical_request_order() -> None:
    """Per-sensor timing texture cannot reorder transactions on one TCP stream."""

    planner = NetworkObservationPlanner(_visibility_engine())
    first_event = _network_event(
        start=T0,
        stable_id="network:http-parent",
        protocol="tcp",
    )
    second_event = _network_event(
        start=T0 + timedelta(milliseconds=1),
        stable_id="network:http-child",
        protocol="tcp",
    )
    second_event.network = replace(second_event.network, application_layer_only=True)

    first = _observation_by_sensor(planner.plan(first_event, {"zeek_conn", "zeek_dns"}))
    second = _observation_by_sensor(planner.plan(second_event, {"zeek_conn", "zeek_dns"}))

    for sensor_identity in first:
        observed_delta = (
            second[sensor_identity].observed_start_time - first[sensor_identity].observed_start_time
        )
        assert timedelta(microseconds=990) <= observed_delta <= timedelta(microseconds=1010)


def test_explicit_loss_profile_is_deterministic_bounded_and_auditable(monkeypatch) -> None:
    """Only an explicit capture-loss profile may change observed counters."""

    forced_loss = NetworkSensorObservationTiming(
        profile_name="lossy_span",
        clock_offset_min_us=0,
        clock_offset_max_us=0,
        clock_drift_min_ppm=0,
        clock_drift_max_ppm=0,
        route_delay_min_us=0,
        route_delay_max_us=0,
        event_jitter_min_us=0,
        event_jitter_max_us=0,
        capture_loss_probability=1.0,
        capture_loss_min_fraction=0.1,
        capture_loss_max_fraction=0.1,
        capture_loss_max_missed_bytes=10_000,
    )
    monkeypatch.setattr(
        "evidenceforge.generation.network_observation.network_sensor_observation_timing",
        lambda _profile_name: forced_loss,
    )
    event = _network_event(protocol="tcp")
    event._sensor_hostnames_by_format = {"zeek_conn": ["destination-tap"]}
    planner = NetworkObservationPlanner(_visibility_engine(destination_profile="lossy_span"))

    first = planner.plan(event, {"zeek_conn"})[0]
    second = planner.plan(event, {"zeek_conn"})[0]
    canonical = event.network.traffic

    assert first == second
    assert first.capture_profile == "lossy_span"
    assert first.traffic.missed_bytes > 0
    assert first.traffic.orig.payload_bytes < canonical.orig.payload_bytes
    assert first.traffic.resp.payload_bytes < canonical.resp.payload_bytes
    assert canonical.orig.payload_bytes - first.traffic.orig.payload_bytes == pytest.approx(
        canonical.orig.payload_bytes * 0.1,
        abs=1,
    )
    assert canonical.resp.payload_bytes - first.traffic.resp.payload_bytes == pytest.approx(
        canonical.resp.payload_bytes * 0.1,
        abs=1,
    )


@pytest.mark.parametrize("protocol", ["udp", "icmp"])
def test_non_tcp_capture_loss_requires_packet_level_truth(protocol: str) -> None:
    """Datagram views cannot invent fractional loss without a packet sequence."""

    timing = NetworkSensorObservationTiming(
        profile_name="lossy_datagrams",
        clock_offset_min_us=0,
        clock_offset_max_us=0,
        clock_drift_min_ppm=0,
        clock_drift_max_ppm=0,
        route_delay_min_us=0,
        route_delay_max_us=0,
        event_jitter_min_us=0,
        event_jitter_max_us=0,
        capture_loss_probability=1.0,
        capture_loss_min_fraction=0.1,
        capture_loss_max_fraction=0.1,
        capture_loss_max_missed_bytes=10_000,
    )
    canonical = NetworkTrafficLedger(
        orig=DirectionalTrafficLedger(payload_bytes=1_000, packets=10, ip_bytes=1_280),
        resp=DirectionalTrafficLedger(payload_bytes=500, packets=5, ip_bytes=640),
    )

    observed = NetworkObservationPlanner._observed_traffic(
        canonical, timing, "zeek-core", f"{protocol}-loss", protocol
    )

    assert observed is canonical
    assert observed.orig.payload_bytes == canonical.orig.payload_bytes
    assert observed.resp.payload_bytes == canonical.resp.payload_bytes
    assert observed.orig.packets == canonical.orig.packets
    assert observed.resp.packets == canonical.resp.packets
    assert observed.missed_bytes == 0


def test_sensor_clock_offset_drift_and_route_delay_are_stable(monkeypatch) -> None:
    """One sensor keeps a stable clock model while drift evolves with time."""

    timing = NetworkSensorObservationTiming(
        profile_name="clock-test",
        clock_offset_min_us=1000,
        clock_offset_max_us=1000,
        clock_drift_min_ppm=2,
        clock_drift_max_ppm=2,
        route_delay_min_us=3000,
        route_delay_max_us=3000,
        event_jitter_min_us=0,
        event_jitter_max_us=0,
        capture_loss_probability=0.0,
        capture_loss_min_fraction=0.0,
        capture_loss_max_fraction=0.0,
        capture_loss_max_missed_bytes=0,
    )
    monkeypatch.setattr(
        "evidenceforge.generation.network_observation.network_sensor_observation_timing",
        lambda _profile_name: timing,
    )
    planner = NetworkObservationPlanner(_visibility_engine())
    first_event = _network_event(start=T0, stable_id="network:clock-first")
    second_event = _network_event(
        start=T0 + timedelta(hours=1),
        stable_id="network:clock-second",
    )
    for event in (first_event, second_event):
        event._sensor_hostnames_by_format = {"zeek_conn": ["source-tap"]}

    first = planner.plan(first_event, {"zeek_conn"})[0]
    second = planner.plan(second_event, {"zeek_conn"})[0]

    assert first.observed_start_time - first_event.timestamp == timedelta(microseconds=76_000)
    assert second.observed_start_time - second_event.timestamp == timedelta(microseconds=83_200)
    assert second.observed_start_time - first.observed_start_time == timedelta(
        hours=1,
        microseconds=7200,
    )


def test_protocol_siblings_share_one_sensor_identity_and_tuple(tmp_path) -> None:
    """conn.log and dns.log consume the same frozen observation projection."""

    event = _network_event()
    event.nat = NatContext(
        nat_type="dynamic_pat",
        mapped_src_ip="198.51.100.25",
        mapped_src_port=62000,
        mapped_dst_ip=event.network.dst_ip,
        mapped_dst_port=event.network.dst_port,
    )
    event.network_observations = NetworkObservationPlanner(
        _visibility_engine(source_profile="well_synced", destination_profile="well_synced")
    ).plan(event, {"zeek_conn", "zeek_dns"})
    event.network_observations_planned = True
    conn_emitter = ZeekEmitter(
        load_format("zeek_conn"),
        tmp_path,
        sensor_hostnames=["source-tap", "destination-tap"],
    )
    dns_emitter = ZeekDnsEmitter(
        load_format("zeek_dns"),
        tmp_path,
        sensor_hostnames=["source-tap", "destination-tap"],
    )

    conn_emitter.emit(event)
    dns_emitter.emit(event)
    conn_emitter.close()
    dns_emitter.close()

    rows: dict[str, tuple[dict[str, object], dict[str, object]]] = {}
    for sensor in ("source-tap", "destination-tap"):
        conn = json.loads((tmp_path / sensor / "conn.json").read_text())
        dns = json.loads((tmp_path / sensor / "dns.json").read_text())
        observation = _observation_by_sensor(event.network_observations)[sensor]
        rows[sensor] = conn, dns
        assert conn["uid"] == dns["uid"]
        assert conn["id.orig_h"] == dns["id.orig_h"]
        assert conn["id.orig_p"] == dns["id.orig_p"]
        assert conn["id.resp_h"] == dns["id.resp_h"]
        assert conn["id.resp_p"] == dns["id.resp_p"]
        assert conn["orig_bytes"] == 1200
        assert conn["resp_bytes"] == 8400
        assert conn["missed_bytes"] == 0
        assert conn["ts"] == pytest.approx(observation.observed_start_time.timestamp())
        assert dns["ts"] >= conn["ts"]
        assert dns["ts"] + dns["rtt"] <= conn["ts"] + conn["duration"]
    assert rows["source-tap"][0]["uid"] != rows["destination-tap"][0]["uid"]
    assert rows["destination-tap"][0]["id.orig_h"] == "198.51.100.25"


def test_short_dns_companion_stays_inside_planned_sensor_interval(tmp_path) -> None:
    """DNS query and response timing stays within a very short parent flow."""

    event = _network_event(start=T0, stable_id="network:short-dns")
    event.timestamp = T0 + timedelta(milliseconds=2)
    short_close = T0 + timedelta(seconds=0.000744)
    event.network = replace(
        event.network,
        stable_id="network:short-dns",
        hostname="resolver.corp.local",
        duration=0.000744,
        closed_at=short_close,
        traffic=NetworkTrafficLedger(
            orig=DirectionalTrafficLedger(52, 1, 80),
            resp=DirectionalTrafficLedger(83, 1, 111),
        ),
        phase_times=(
            ("transport_start", T0),
            ("transport_close", short_close),
        ),
    )
    event.dns.rtt = 0.000744
    event.lifecycle = ActionLifecycleContext(
        group_id="network:short-dns",
        canonical_start=T0,
        phase="start",
    )
    event._sensor_hostnames_by_format = {
        "zeek_conn": ["source-tap"],
        "zeek_dns": ["source-tap"],
    }
    event.network_observations = NetworkObservationPlanner(_visibility_engine()).plan(
        event,
        {"zeek_conn", "zeek_dns"},
    )
    event.network_observations_planned = True
    conn_emitter = ZeekEmitter(
        load_format("zeek_conn"),
        tmp_path,
        sensor_hostnames=["source-tap"],
    )
    dns_emitter = ZeekDnsEmitter(
        load_format("zeek_dns"),
        tmp_path,
        sensor_hostnames=["source-tap"],
    )

    conn_emitter.emit(event)
    dns_emitter.emit(event)
    conn_emitter.close()
    dns_emitter.close()

    conn = json.loads((tmp_path / "source-tap" / "conn.json").read_text())
    dns = json.loads((tmp_path / "source-tap" / "dns.json").read_text())
    assert dns["ts"] == pytest.approx(conn["ts"])
    assert dns["ts"] + dns["rtt"] <= conn["ts"] + conn["duration"]


def test_http_companion_never_precedes_planned_sensor_connection(tmp_path) -> None:
    """A sensor-local HTTP row cannot precede its same-UID connection start."""

    event = _network_event(stable_id="network:http-observation-order")
    event.dns = None
    event.network = replace(event.network, service="http")
    event.http = HttpContext(
        method="GET",
        host="updates.example.com",
        uri="/manifest.json",
        canonical_request_time=event.timestamp,
    )
    event._sensor_hostnames_by_format = {
        "zeek_conn": ["source-tap", "destination-tap"],
        "zeek_http": ["source-tap", "destination-tap"],
    }
    event.network_observations = NetworkObservationPlanner(_visibility_engine()).plan(
        event,
        {"zeek_conn", "zeek_http"},
    )
    event.network_observations_planned = True
    conn_emitter = ZeekEmitter(
        load_format("zeek_conn"),
        tmp_path,
        sensor_hostnames=["source-tap", "destination-tap"],
    )
    http_emitter = ZeekHttpEmitter(
        load_format("zeek_http"),
        tmp_path,
        sensor_hostnames=["source-tap", "destination-tap"],
    )

    conn_emitter.emit(event)
    http_emitter.emit(event)
    conn_emitter.close()
    http_emitter.close()

    observations = _observation_by_sensor(event.network_observations)
    for sensor in ("source-tap", "destination-tap"):
        conn = json.loads((tmp_path / sensor / "conn.json").read_text())
        http = json.loads((tmp_path / sensor / "http.json").read_text())
        assert conn["ts"] == pytest.approx(observations[sensor].observed_start_time.timestamp())
        assert http["ts"] >= conn["ts"]


def test_snort_consumes_planned_sensor_timestamp_and_tuple(tmp_path) -> None:
    """Snort renders observation-owned clock and NAT views without local jitter."""

    event = _network_event()
    event.ids_alerts = (
        IdsAlertPlan(
            sid=2_000_001,
            message="Planned observation alert",
            classification="Attempted Information Leak",
        ),
    )
    event._sensor_hostnames_by_format = {"snort_alert": ["destination-tap"]}
    event.nat = NatContext(
        nat_type="dynamic_pat",
        mapped_src_ip="198.51.100.25",
        mapped_src_port=62000,
        mapped_dst_ip=event.network.dst_ip,
        mapped_dst_port=event.network.dst_port,
    )
    event.network_observations = NetworkObservationPlanner(_visibility_engine()).plan(
        event,
        {"snort_alert"},
    )
    event.network_observations_planned = True
    observation = event.network_observations[0]
    emitter = SnortEmitter(
        load_format("snort_alert"),
        tmp_path,
        sensor_hostnames=["destination-tap"],
    )

    emitter.emit(event)
    emitter.close()

    line = (tmp_path / "destination-tap" / "snort_alert.log").read_text()
    expected_timestamp = observation.observed_start_time.strftime("%m/%d-%H:%M:%S.%f")
    assert line.startswith(expected_timestamp)
    assert "198.51.100.25:62000 -> 10.0.2.40:53" in line


def test_firewall_observation_owns_fixed_syn_timeout_policy() -> None:
    """One firewall policy supplies the SYN timeout instead of per-flow emitter jitter."""

    config = NetworkConfig(
        segments=[
            NetworkSegment(name="outside", cidr="198.51.100.0/24", exposure="external"),
            NetworkSegment(name="servers", cidr="10.0.2.0/24", exposure="internal"),
        ],
        sensors=[
            NetworkSensor(
                type="network",
                name="fw-perimeter",
                monitoring_segments=["outside", "servers"],
                log_formats=["cisco_asa"],
            )
        ],
    )
    network = network_plan(
        src_ip="198.51.100.25",
        src_port=51000,
        dst_ip="10.0.2.40",
        dst_port=443,
        protocol="tcp",
        zeek_uid="CFirewallTimeout1",
        conn_id="conn-firewall-timeout",
        conn_state="S0",
        history="S",
        orig_pkts=1,
        orig_ip_bytes=40,
        source_visible_start_time=T0,
    )
    network = replace(
        network,
        stable_id="network:firewall-timeout",
        hostname="web.corp.local",
        outcome="failure",
        phase_times=(("transport_start", T0),),
    )
    event = OccurrenceBuilder(timestamp=T0, event_type="connection", network=network)
    event._sensor_hostnames_by_format = {"cisco_asa": ["fw-perimeter"]}

    observation = NetworkObservationPlanner(NetworkVisibilityEngine(config, systems=[])).plan(
        event,
        {"cisco_asa"},
    )[0]

    assert observation.firewall_teardown_reason == "SYN Timeout"
    assert observation.firewall_teardown_time is not None
    assert observation.firewall_teardown_time - observation.observed_start_time == timedelta(
        seconds=30
    )


def test_firewall_observation_keeps_dynamic_pat_alive_through_syn_timeout() -> None:
    """A dynamic translation cannot close before its S0 connection lifecycle."""

    config = NetworkConfig(
        segments=[
            NetworkSegment(name="inside", cidr="10.0.2.0/24", exposure="internal"),
        ],
        sensors=[
            NetworkSensor(
                type="firewall",
                name="fw-perimeter",
                monitoring_segments=["inside"],
                log_formats=["cisco_asa"],
            )
        ],
    )
    network = network_plan(
        src_ip="10.0.2.40",
        src_port=51000,
        dst_ip="198.51.100.25",
        dst_port=443,
        protocol="tcp",
        zeek_uid="CNatTimeout1",
        conn_id="conn-nat-timeout",
        conn_state="S0",
        history="S",
        orig_pkts=1,
        orig_ip_bytes=40,
        source_visible_start_time=T0,
    )
    network = replace(
        network,
        stable_id="network:nat-timeout",
        hostname="edge.example",
        outcome="failure",
        phase_times=(("transport_start", T0),),
    )
    event = OccurrenceBuilder(
        timestamp=T0,
        event_type="connection",
        network=network,
        nat=NatContext(
            nat_type="dynamic_pat",
            mapped_src_ip="203.0.113.10",
            mapped_src_port=62001,
            mapped_dst_ip="198.51.100.25",
            mapped_dst_port=443,
        ),
    )
    event._sensor_hostnames_by_format = {"cisco_asa": ["fw-perimeter"]}

    observation = NetworkObservationPlanner(NetworkVisibilityEngine(config, systems=[])).plan(
        event,
        {"cisco_asa"},
    )[0]

    assert observation.nat is not None
    assert observation.nat.direction == "source"
    assert observation.nat.local_ip == "10.0.2.40"
    assert observation.nat.global_ip == "203.0.113.10"
    assert observation.nat.teardown_time == observation.firewall_teardown_time
    assert observation.nat.teardown_time == observation.observed_start_time + timedelta(seconds=30)


def test_firewall_observation_owns_inbound_static_nat_address_roles() -> None:
    """Inbound translation records distinguish the public VIP from the local host."""

    network = network_plan(
        src_ip="198.51.100.25",
        src_port=0,
        dst_ip="203.0.113.5",
        dst_port=8,
        protocol="icmp",
        duration=1.0,
        zeek_uid="CInboundIcmp1",
        conn_id="conn-inbound-icmp",
        conn_state="SF",
        history="Dd",
        orig_pkts=1,
        resp_pkts=1,
        orig_ip_bytes=84,
        resp_ip_bytes=84,
        source_visible_start_time=T0,
        source_visible_close_time=T0 + timedelta(seconds=1),
    )
    network = replace(
        network,
        stable_id="network:inbound-icmp",
        hostname="web.corp.local",
        outcome="success",
        phase_times=(
            ("transport_start", T0),
            ("transport_close", T0 + timedelta(seconds=1)),
        ),
    )
    event = OccurrenceBuilder(
        timestamp=T0,
        event_type="connection",
        network=network,
        nat=NatContext(
            nat_type="static",
            mapped_src_ip="198.51.100.25",
            mapped_src_port=0,
            mapped_dst_ip="10.0.2.40",
            mapped_dst_port=8,
        ),
    )
    event._sensor_hostnames_by_format = {"cisco_asa": ["fw-perimeter"]}

    observation = NetworkObservationPlanner(None).plan(event, {"cisco_asa"})[0]

    assert observation.nat is not None
    assert observation.nat.direction == "destination"
    assert observation.nat.global_ip == "203.0.113.5"
    assert observation.nat.local_ip == "10.0.2.40"


def test_subsecond_midstream_fragment_is_not_labeled_connection_timeout() -> None:
    """A short OTH/Cc observation cannot expire an ASA idle timer immediately."""

    config = NetworkConfig(
        segments=[
            NetworkSegment(name="dmz", cidr="10.0.3.0/24", exposure="both"),
            NetworkSegment(name="outside", cidr="198.51.100.0/24", exposure="external"),
        ],
        sensors=[
            NetworkSensor(
                type="network",
                name="fw-perimeter",
                monitoring_segments=["dmz", "outside"],
                log_formats=["cisco_asa"],
            )
        ],
    )
    close = T0 + timedelta(milliseconds=250)
    network = network_plan(
        src_ip="10.0.3.20",
        src_port=51000,
        dst_ip="198.51.100.40",
        dst_port=443,
        protocol="tcp",
        zeek_uid="CFirewallFragment1",
        conn_id="conn-firewall-fragment",
        duration=0.25,
        conn_state="OTH",
        history="Cc",
        orig_pkts=1,
        resp_pkts=1,
        orig_ip_bytes=52,
        resp_ip_bytes=52,
        source_visible_start_time=T0,
        source_visible_close_time=close,
    )
    network = replace(
        network,
        stable_id="network:firewall-fragment",
        hostname="edge.example",
        outcome="success",
        phase_times=(("transport_start", T0), ("transport_close", close)),
    )
    event = OccurrenceBuilder(timestamp=T0, event_type="connection", network=network)
    event._sensor_hostnames_by_format = {"cisco_asa": ["fw-perimeter"]}

    observation = NetworkObservationPlanner(NetworkVisibilityEngine(config, systems=[])).plan(
        event,
        {"cisco_asa"},
    )[0]

    assert observation.firewall_teardown_reason == "TCP Reset-O"
    assert observation.firewall_teardown_reason != "Conn-timeout"
    assert observation.firewall_teardown_time == observation.observed_close_time


def test_firewall_teardown_after_export_window_is_marked_unobserved() -> None:
    """Perimeter lifecycle fan-out respects the half-open collection boundary."""

    config = NetworkConfig(
        segments=[
            NetworkSegment(name="inside", cidr="10.0.1.0/24", exposure="internal"),
            NetworkSegment(name="outside", cidr="198.51.100.0/24", exposure="external"),
        ],
        sensors=[
            NetworkSensor(
                type="firewall",
                name="fw-perimeter",
                monitoring_segments=["inside", "outside"],
                log_formats=["cisco_asa"],
            )
        ],
    )
    close = T0 + timedelta(minutes=10)
    network = network_plan(
        src_ip="10.0.1.20",
        src_port=51000,
        dst_ip="198.51.100.40",
        dst_port=22,
        protocol="tcp",
        zeek_uid="CFirewallBoundary1",
        conn_id="conn-firewall-boundary",
        duration=600.0,
        conn_state="SF",
        history="ShADadFf",
        orig_pkts=4,
        resp_pkts=4,
        orig_ip_bytes=500,
        resp_ip_bytes=500,
        source_visible_start_time=T0,
        source_visible_close_time=close,
    )
    network = replace(
        network,
        stable_id="network:firewall-boundary",
        hostname="edge.example",
        outcome="success",
        phase_times=(("transport_start", T0), ("transport_close", close)),
    )
    event = OccurrenceBuilder(timestamp=T0, event_type="connection", network=network)
    event._sensor_hostnames_by_format = {"cisco_asa": ["fw-perimeter"]}

    observation = NetworkObservationPlanner(
        NetworkVisibilityEngine(config, systems=[]),
        output_end_time=T0 + timedelta(minutes=5),
    ).plan(event, {"cisco_asa"})[0]

    assert observation.firewall_teardown_time is not None
    assert observation.firewall_teardown_time >= T0 + timedelta(minutes=5)
    assert observation.firewall_teardown_observed is False


def test_capture_profile_accepts_blank_and_rejects_unknown_names() -> None:
    """Scenario sensors inherit the default profile but fail fast on typos."""

    sensor = NetworkSensor(
        type="network",
        name="default-tap",
        monitoring_segments=["workstations"],
        capture_profile="   ",
    )
    assert sensor.capture_profile == ""
    with pytest.raises(ValueError, match="Unknown network sensor capture_profile"):
        NetworkSensor(
            type="network",
            name="typo-tap",
            monitoring_segments=["workstations"],
            capture_profile="lossy-spna",
        )


def _mock_emitter() -> MagicMock:
    emitter = MagicMock()
    emitter.can_handle.return_value = True
    return emitter


def _lifecycle_event(
    *,
    timestamp: datetime,
    group_id: str,
    canonical_start: datetime,
    phase: str,
    parent_group_id: str | None = None,
) -> OccurrenceBuilder:
    """Return a contract-valid source-local event for admission-boundary tests."""

    return OccurrenceBuilder(
        timestamp=timestamp,
        event_type="syslog",
        src_host=HostContext(
            hostname="server-01",
            ip="10.0.2.40",
            os="Ubuntu 22.04",
            os_category="linux",
            system_type="server",
        ),
        syslog=SyslogContext(
            app_name="systemd",
            pid=1,
            facility=3,
            severity=6,
            message="lifecycle admission test",
        ),
        lifecycle=ActionLifecycleContext(
            group_id=group_id,
            canonical_start=canonical_start,
            phase=phase,
            parent_group_id=parent_group_id,
        ),
    )


def test_half_open_end_suppresses_group_start_and_dependents_but_updates_state() -> None:
    """Source-visible starts and dependent rows at ``end`` are excluded."""

    state_manager = MagicMock(spec=StateManager)
    emitter = _mock_emitter()
    output_end = T0 + timedelta(minutes=5)
    dispatcher = EventDispatcher(
        state_manager=state_manager,
        emitters={"windows_event_security": emitter},
        output_end_time=output_end,
    )
    start = _lifecycle_event(
        timestamp=output_end,
        group_id="session-at-end",
        canonical_start=output_end,
        phase="start",
    )
    dependent = _lifecycle_event(
        timestamp=output_end + timedelta(seconds=1),
        group_id="session-before-end",
        canonical_start=output_end - timedelta(seconds=10),
        phase="dependent",
    )

    dispatcher.dispatch_builder(start)
    dispatcher.dispatch_builder(dependent)

    assert state_manager.apply.call_count == 2
    emitter.emit.assert_not_called()


def test_closure_after_end_is_suppressed_even_when_group_started_before_end() -> None:
    """A still-open action does not leak a discrete closure beyond the slice."""

    state_manager = MagicMock(spec=StateManager)
    emitter = _mock_emitter()
    output_end = T0 + timedelta(minutes=5)
    dispatcher = EventDispatcher(
        state_manager=state_manager,
        emitters={"windows_event_security": emitter},
        output_end_time=output_end,
    )
    admitted = _lifecycle_event(
        timestamp=output_end + timedelta(seconds=30),
        group_id="session-before-end",
        canonical_start=output_end - timedelta(minutes=1),
        phase="closure",
    )
    suppressed = _lifecycle_event(
        timestamp=output_end + timedelta(seconds=30),
        group_id="session-at-end",
        canonical_start=output_end,
        phase="closure",
    )

    dispatcher.dispatch_builder(admitted)
    dispatcher.dispatch_builder(suppressed)

    emitter.emit.assert_not_called()
    assert state_manager.apply.call_count == 2


def test_nested_parent_closure_and_child_start_at_end_are_both_suppressed() -> None:
    """Both closure and child records respect the half-open source interval."""

    state_manager = MagicMock(spec=StateManager)
    emitter = _mock_emitter()
    output_end = T0 + timedelta(minutes=5)
    dispatcher = EventDispatcher(
        state_manager=state_manager,
        emitters={"windows_event_security": emitter},
        output_end_time=output_end,
    )
    parent_closure = _lifecycle_event(
        timestamp=output_end + timedelta(seconds=2),
        group_id="proxy-parent",
        canonical_start=output_end - timedelta(seconds=10),
        phase="closure",
    )
    child_start = _lifecycle_event(
        timestamp=output_end,
        group_id="origin-child",
        canonical_start=output_end,
        phase="start",
        parent_group_id="proxy-parent",
    )

    dispatcher.dispatch_builder(parent_closure)
    dispatcher.dispatch_builder(child_start)

    emitter.emit.assert_not_called()


def test_sensor_observation_at_end_is_suppressed_without_emitter_fallback() -> None:
    """An empty admitted observation set cannot fall back to configured sensor routing."""

    state_manager = MagicMock(spec=StateManager)
    emitter = _mock_emitter()
    output_end = T0 + timedelta(minutes=5)
    event = _network_event(start=output_end - timedelta(seconds=1))
    planned = NetworkObservationPlanner(_visibility_engine()).plan(event, {"zeek_conn"})[0]
    planned_at_end = NetworkSensorObservation(
        sensor_identity=planned.sensor_identity,
        path_role=planned.path_role,
        capture_profile=planned.capture_profile,
        tuple_view=planned.tuple_view,
        connection_uid=planned.connection_uid,
        connection_ids=planned.connection_ids,
        file_ids=planned.file_ids,
        local_orig=planned.local_orig,
        local_resp=planned.local_resp,
        observed_start_time=output_end,
        observed_close_time=output_end + timedelta(seconds=2),
        traffic=planned.traffic,
        visible_formats=frozenset({"zeek_conn"}),
    )
    dispatcher = EventDispatcher(
        state_manager=state_manager,
        emitters={"zeek_conn": emitter},
        output_end_time=output_end,
    )
    dispatcher.network_observation_planner.plan = MagicMock(return_value=(planned_at_end,))

    identifiers = dispatcher.dispatch_builder(event)

    _assert_published_once(state_manager.apply, event)
    emitter.emit.assert_not_called()
    assert identifiers == {"zeek_conn": ""}


def test_raw_entry_at_end_is_suppressed() -> None:
    """Raw source admission follows the same half-open interval."""

    emitter = _mock_emitter()
    dispatcher = EventDispatcher(
        state_manager=MagicMock(spec=StateManager),
        emitters={"syslog": emitter},
        output_end_time=T0,
    )

    dispatcher.dispatch_raw(RawProjectionRequest(T0, "syslog", {"message": "at end"}))

    emitter.emit_raw.assert_not_called()
