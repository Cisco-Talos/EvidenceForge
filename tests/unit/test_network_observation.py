# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Tests for canonical network-sensor observation and lifecycle admission."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from unittest.mock import MagicMock

import pytest

from evidenceforge.events.base import RawLogEntry, SecurityEvent
from evidenceforge.events.contexts import DnsContext, IdsContext, NetworkContext
from evidenceforge.events.dispatcher import EventDispatcher
from evidenceforge.events.lifecycle import ActionLifecycleContext
from evidenceforge.events.network import NetworkSensorObservation
from evidenceforge.formats import load_format
from evidenceforge.generation.activity.timing_profiles import NetworkSensorObservationTiming
from evidenceforge.generation.emitters.snort import SnortEmitter
from evidenceforge.generation.emitters.zeek import ZeekEmitter
from evidenceforge.generation.emitters.zeek_dns import ZeekDnsEmitter
from evidenceforge.generation.network_observation import NetworkObservationPlanner
from evidenceforge.generation.network_visibility import NetworkVisibilityEngine
from evidenceforge.generation.state_manager import StateManager
from evidenceforge.models.scenario import (
    NetworkConfig,
    NetworkSegment,
    NetworkSensor,
)

T0 = datetime(2026, 3, 19, 10, 0, 0, tzinfo=UTC)


def _visibility_engine(*, destination_profile: str = "") -> NetworkVisibilityEngine:
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
) -> SecurityEvent:
    duration = 2.5
    network = NetworkContext(
        src_ip="10.0.1.25",
        src_port=51000,
        dst_ip="10.0.2.40",
        dst_port=53,
        protocol="udp",
        service="dns",
        zeek_uid="CObservationTest1",
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
        ip_proto=17,
    )
    transaction = network.finalize_transaction(
        stable_id,
        hostname="resolver.corp.local",
        phase_times=(
            ("transport_start", start),
            ("transport_close", start + timedelta(seconds=duration)),
        ),
    )
    event = SecurityEvent(
        timestamp=start,
        event_type="connection",
        network=network,
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
    event._nat_swaps_by_sensor = {
        "destination-tap": {
            "src_ip": "198.51.100.25",
            "src_port": 62000,
            "local_orig": False,
        }
    }
    planner = NetworkObservationPlanner(_visibility_engine())

    first = planner.plan(event, {"zeek_conn", "zeek_dns"})
    second = planner.plan(event, {"zeek_conn", "zeek_dns"})
    observations = _observation_by_sensor(first)

    assert first == second
    assert observations["source-tap"].path_role == "source_side"
    assert observations["destination-tap"].path_role == "destination_side"
    assert observations["source-tap"].traffic is event.network.transaction.traffic
    assert observations["destination-tap"].traffic is event.network.transaction.traffic
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
    event = _network_event()
    event._sensor_hostnames_by_format = {"zeek_conn": ["destination-tap"]}
    planner = NetworkObservationPlanner(_visibility_engine(destination_profile="lossy_span"))

    first = planner.plan(event, {"zeek_conn"})[0]
    second = planner.plan(event, {"zeek_conn"})[0]
    canonical = event.network.transaction.traffic

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
    event._nat_swaps_by_sensor = {"destination-tap": {"src_ip": "198.51.100.25", "src_port": 62000}}
    event.network_observations = NetworkObservationPlanner(_visibility_engine()).plan(
        event,
        {"zeek_conn", "zeek_dns"},
    )
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
        rows[sensor] = conn, dns
        assert conn["uid"] == dns["uid"]
        assert conn["id.orig_h"] == dns["id.orig_h"]
        assert conn["id.orig_p"] == dns["id.orig_p"]
        assert conn["id.resp_h"] == dns["id.resp_h"]
        assert conn["id.resp_p"] == dns["id.resp_p"]
        assert conn["orig_bytes"] == 1200
        assert conn["resp_bytes"] == 8400
        assert conn["missed_bytes"] == 0
    assert rows["source-tap"][0]["uid"] != rows["destination-tap"][0]["uid"]
    assert rows["destination-tap"][0]["id.orig_h"] == "198.51.100.25"


def test_snort_consumes_planned_sensor_timestamp_and_tuple(tmp_path) -> None:
    """Snort renders observation-owned clock and NAT views without local jitter."""

    event = _network_event()
    event.ids = IdsContext(
        sid=2_000_001,
        message="Planned observation alert",
        classification="Attempted Information Leak",
    )
    event._sensor_hostnames_by_format = {"snort_alert": ["source-tap"]}
    event._nat_swaps_by_sensor = {"source-tap": {"src_ip": "198.51.100.25", "src_port": 62000}}
    event.network_observations = NetworkObservationPlanner(_visibility_engine()).plan(
        event,
        {"snort_alert"},
    )
    event.network_observations_planned = True
    observation = event.network_observations[0]
    emitter = SnortEmitter(
        load_format("snort_alert"),
        tmp_path,
        sensor_hostnames=["source-tap"],
    )

    emitter.emit(event)
    emitter.close()

    line = (tmp_path / "source-tap" / "snort_alert.log").read_text()
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
    network = NetworkContext(
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
    network.finalize_transaction(
        "network:firewall-timeout",
        hostname="web.corp.local",
        outcome="failure",
        phase_times=(("transport_start", T0),),
    )
    event = SecurityEvent(timestamp=T0, event_type="connection", network=network)
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
    network = NetworkContext(
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
    network.finalize_transaction(
        "network:firewall-fragment",
        hostname="edge.example",
        outcome="success",
        phase_times=(("transport_start", T0), ("transport_close", close)),
    )
    event = SecurityEvent(timestamp=T0, event_type="connection", network=network)
    event._sensor_hostnames_by_format = {"cisco_asa": ["fw-perimeter"]}

    observation = NetworkObservationPlanner(NetworkVisibilityEngine(config, systems=[])).plan(
        event,
        {"cisco_asa"},
    )[0]

    assert observation.firewall_teardown_reason == "TCP Reset-O"
    assert observation.firewall_teardown_reason != "Conn-timeout"
    assert observation.firewall_teardown_time == observation.observed_close_time


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
    start = SecurityEvent(
        timestamp=output_end,
        event_type="logon",
        lifecycle=ActionLifecycleContext(
            group_id="session-at-end",
            canonical_start=output_end,
            phase="start",
        ),
    )
    dependent = SecurityEvent(
        timestamp=output_end + timedelta(seconds=1),
        event_type="process_create",
        lifecycle=ActionLifecycleContext(
            group_id="session-before-end",
            canonical_start=output_end - timedelta(seconds=10),
            phase="dependent",
        ),
    )

    dispatcher.dispatch(start)
    dispatcher.dispatch(dependent)

    assert state_manager.apply.call_count == 2
    emitter.emit.assert_not_called()


def test_closure_tail_is_admitted_only_when_group_started_before_end() -> None:
    """Closure rows may trail the slice only for an already-admitted action."""

    state_manager = MagicMock(spec=StateManager)
    emitter = _mock_emitter()
    output_end = T0 + timedelta(minutes=5)
    dispatcher = EventDispatcher(
        state_manager=state_manager,
        emitters={"windows_event_security": emitter},
        output_end_time=output_end,
    )
    admitted = SecurityEvent(
        timestamp=output_end + timedelta(seconds=30),
        event_type="logoff",
        lifecycle=ActionLifecycleContext(
            group_id="session-before-end",
            canonical_start=output_end - timedelta(minutes=1),
            phase="closure",
        ),
    )
    suppressed = SecurityEvent(
        timestamp=output_end + timedelta(seconds=30),
        event_type="logoff",
        lifecycle=ActionLifecycleContext(
            group_id="session-at-end",
            canonical_start=output_end,
            phase="closure",
        ),
    )

    dispatcher.dispatch(admitted)
    dispatcher.dispatch(suppressed)

    emitter.emit.assert_called_once_with(admitted)
    assert state_manager.apply.call_count == 2


def test_nested_child_action_has_independent_admission() -> None:
    """A child beginning at end is suppressed without removing its parent's tail."""

    state_manager = MagicMock(spec=StateManager)
    emitter = _mock_emitter()
    output_end = T0 + timedelta(minutes=5)
    dispatcher = EventDispatcher(
        state_manager=state_manager,
        emitters={"windows_event_security": emitter},
        output_end_time=output_end,
    )
    parent_closure = SecurityEvent(
        timestamp=output_end + timedelta(seconds=2),
        event_type="logoff",
        lifecycle=ActionLifecycleContext(
            group_id="proxy-parent",
            canonical_start=output_end - timedelta(seconds=10),
            phase="closure",
        ),
    )
    child_start = SecurityEvent(
        timestamp=output_end,
        event_type="connection",
        lifecycle=ActionLifecycleContext(
            group_id="origin-child",
            canonical_start=output_end,
            phase="start",
            parent_group_id="proxy-parent",
        ),
    )

    dispatcher.dispatch(parent_closure)
    dispatcher.dispatch(child_start)

    emitter.emit.assert_called_once_with(parent_closure)


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

    dispatcher.dispatch(event)

    state_manager.apply.assert_called_once_with(event)
    emitter.emit.assert_not_called()
    assert event.network_observations_planned is True
    assert event.network_observations == ()


def test_raw_entry_at_end_is_suppressed() -> None:
    """Raw source admission follows the same half-open interval."""

    emitter = _mock_emitter()
    dispatcher = EventDispatcher(
        state_manager=MagicMock(spec=StateManager),
        emitters={"syslog": emitter},
        output_end_time=T0,
    )

    dispatcher.dispatch_raw(RawLogEntry(T0, "syslog", {"message": "at end"}))

    emitter.emit_raw.assert_not_called()
