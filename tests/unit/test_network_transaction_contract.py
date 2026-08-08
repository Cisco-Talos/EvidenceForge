# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
#
# SPDX-License-Identifier: MIT

"""Tests for the canonical network transaction and traffic-ledger contract."""

from dataclasses import FrozenInstanceError, replace
from datetime import UTC, datetime, timedelta
from unittest.mock import Mock

import pytest

from evidenceforge.events.base import OccurrenceBuilder
from evidenceforge.events.contexts import IdsAlertPlan
from evidenceforge.events.lifecycle import SessionEndPlan
from evidenceforge.events.network import (
    DirectionalTrafficLedger,
    NetworkTrafficLedger,
    NetworkTransactionPlan,
    SignaturePredicate,
)
from evidenceforge.generation.activity import ActivityGenerator
from evidenceforge.generation.state_manager import StateManager
from evidenceforge.models import System
from tests.network_factories import network_plan


def _network_context(start: datetime) -> NetworkTransactionPlan:
    """Return a complete network context ready for transaction finalization."""

    return network_plan(
        src_ip="10.0.0.10",
        src_port=49152,
        dst_ip="203.0.113.10",
        dst_port=443,
        protocol="tcp",
        service="ssl",
        zeek_uid="Ccanonical123",
        conn_id="conn-1",
        duration=1.25,
        source_visible_start_time=start,
        source_visible_close_time=start + timedelta(seconds=1.25),
        orig_bytes=512,
        resp_bytes=4096,
        orig_pkts=7,
        resp_pkts=11,
        orig_ip_bytes=792,
        resp_ip_bytes=4536,
        conn_state="SF",
        history="ShADadfF",
        initiating_pid=4100,
        responding_pid=900,
    )


def test_directional_traffic_ledger_accumulates_without_mutation() -> None:
    """Persistent transport accounting should use immutable cumulative values."""

    first = DirectionalTrafficLedger(payload_bytes=100, packets=2, ip_bytes=180)
    second = DirectionalTrafficLedger(payload_bytes=250, packets=4, ip_bytes=410)

    combined = first.accumulate(second)

    assert combined == DirectionalTrafficLedger(payload_bytes=350, packets=6, ip_bytes=590)
    assert first == DirectionalTrafficLedger(payload_bytes=100, packets=2, ip_bytes=180)


@pytest.mark.parametrize(
    ("payload_bytes", "packets", "ip_bytes"),
    [(-1, 0, 0), (10, 1, 9), (0, 0, 40)],
)
def test_directional_traffic_ledger_rejects_impossible_accounting(
    payload_bytes: int,
    packets: int,
    ip_bytes: int,
) -> None:
    """The canonical boundary should reject negative and contradictory totals."""

    with pytest.raises(ValueError):
        DirectionalTrafficLedger(payload_bytes, packets, ip_bytes)


def test_network_context_finalizes_one_canonical_transaction() -> None:
    """The finalized immutable transaction carries all shared network truth."""

    start = datetime(2026, 7, 14, 12, 0, tzinfo=UTC)
    network = _network_context(start)

    transaction = replace(
        network,
        stable_id="network-connection-test",
        hostname="api.example.test",
        outcome="success",
        phase_times=(
            ("transport_start", start),
            ("application_response", start + timedelta(seconds=0.75)),
            ("transport_close", start + timedelta(seconds=1.25)),
        ),
    )

    assert transaction.hostname == "api.example.test"
    assert transaction.outcome == "success"
    assert transaction.phase_times[1] == (
        "application_response",
        start + timedelta(seconds=0.75),
    )
    assert transaction.started_at == start
    assert transaction.closed_at == start + timedelta(seconds=1.25)
    assert transaction.traffic.orig == DirectionalTrafficLedger(512, 7, 792)
    assert transaction.traffic.resp == DirectionalTrafficLedger(4096, 11, 4536)
    assert network.traffic is transaction.traffic


def test_network_context_detects_post_finalization_counter_drift() -> None:
    """Downstream code cannot rewrite finalized canonical accounting."""

    network = _network_context(datetime(2026, 7, 14, 12, 0, tzinfo=UTC))

    with pytest.raises(FrozenInstanceError):
        network.traffic = NetworkTrafficLedger()  # type: ignore[misc]


def test_direct_context_without_transaction_has_compatibility_ledger() -> None:
    """Direct canonical plans expose one immutable directional ledger."""

    network = network_plan(
        src_ip="10.0.0.10",
        src_port=53000,
        dst_ip="10.0.0.53",
        dst_port=53,
        protocol="udp",
        orig_bytes=48,
        resp_bytes=96,
        orig_pkts=1,
        resp_pkts=1,
        orig_ip_bytes=76,
        resp_ip_bytes=124,
    )

    assert network.traffic == NetworkTrafficLedger(
        orig=DirectionalTrafficLedger(48, 1, 76),
        resp=DirectionalTrafficLedger(96, 1, 124),
    )


def test_state_manager_persists_finalized_transaction_ledger() -> None:
    """Runtime connection state should retain the same immutable transaction truth."""

    start = datetime(2026, 7, 14, 12, 0, tzinfo=UTC)
    manager = StateManager()
    manager.set_current_time(start)
    conn_id = manager.open_connection(
        "10.0.0.10",
        49152,
        "203.0.113.10",
        443,
        "tcp",
        close_time=start + timedelta(seconds=1.25),
    )
    network = _network_context(start)
    transaction = replace(
        network,
        stable_id="network-connection-state-test",
        conn_id=conn_id,
    )

    assert manager.update_connection_transaction(conn_id, transaction)

    connection = manager.get_connection(conn_id)
    assert connection is not None
    assert connection.traffic_ledger is transaction.traffic
    assert connection.bytes_sent == 512
    assert connection.bytes_received == 4096
    assert connection.conn_state == "SF"
    assert connection.history == "ShADadfF"
    assert connection.duration == 1.25
    assert connection.state == "closed"


def test_state_manager_accumulates_persistent_application_transactions() -> None:
    """HTTP transactions on one persistent flow should extend one durable ledger."""

    start = datetime(2026, 7, 14, 12, 0, tzinfo=UTC)
    manager = StateManager()
    manager.set_current_time(start)
    conn_id = manager.open_connection(
        "10.0.0.10",
        49152,
        "203.0.113.10",
        80,
        "tcp",
    )
    first = _network_context(start)
    first = replace(
        first,
        stable_id="network-connection-first",
        conn_id=conn_id,
        dst_port=80,
        service="http",
    )
    manager.apply(OccurrenceBuilder(timestamp=start, event_type="connection", network=first))

    second_start = start + timedelta(milliseconds=500)
    second = network_plan(
        src_ip=first.src_ip,
        src_port=first.src_port,
        dst_ip=first.dst_ip,
        dst_port=80,
        protocol="tcp",
        service="http",
        zeek_uid=first.zeek_uid,
        conn_id=conn_id,
        duration=0.25,
        source_visible_start_time=second_start,
        source_visible_close_time=second_start + timedelta(milliseconds=250),
        orig_bytes=100,
        resp_bytes=300,
        orig_pkts=2,
        resp_pkts=3,
        orig_ip_bytes=180,
        resp_ip_bytes=420,
        conn_state="SF",
        history="ShADadfF",
        application_layer_only=True,
    )
    second = replace(second, stable_id="network-connection-second")
    manager.apply(
        OccurrenceBuilder(timestamp=second_start, event_type="connection", network=second)
    )

    connection = manager.get_connection(conn_id)
    assert connection is not None
    assert connection.start_time == start
    assert connection.traffic_ledger.orig.payload_bytes == 612
    assert connection.traffic_ledger.resp.payload_bytes == 4396
    assert connection.traffic_ledger.orig.packets == 9
    assert connection.traffic_ledger.resp.packets == 14


def test_process_owned_connection_is_capped_before_authoritative_session_end() -> None:
    """The network planner must shorten a child transport instead of moving logoff."""
    state = StateManager()
    start = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)
    deadline = start + timedelta(hours=1)
    source = System(
        hostname="WKS-01",
        ip="10.0.0.10",
        os="Windows 11",
        type="workstation",
    )
    state.set_current_time(start)
    logon_id = state.create_session(
        username="alice",
        system=source.hostname,
        logon_type=10,
        source_ip="10.0.0.50",
        start_time=start,
        session_kind="rdp",
    )
    plan = SessionEndPlan(deadline, "explicit_storyline", "rdp-close")
    state.plan_session_end(logon_id, plan)
    pid = state.create_process(
        source.hostname,
        4,
        r"C:\Windows\System32\OpenSSH\ssh.exe",
        "ssh app@example",
        "alice",
        "Medium",
        logon_id=logon_id,
    )
    emitter = Mock()
    emitter.can_handle.return_value = True
    generator = ActivityGenerator(state, {"zeek_conn": emitter})
    generator._ip_to_system = {source.ip: source}
    connection_start = deadline - timedelta(minutes=10)

    generator.generate_connection(
        src_ip=source.ip,
        dst_ip="203.0.113.20",
        time=connection_start,
        dst_port=22,
        proto="tcp",
        service="ssh",
        duration=3600.0,
        source_system=source,
        pid=pid,
        conn_state="SF",
    )

    event = next(
        call.args[0]
        for call in emitter.emit.call_args_list
        if call.args[0].event_type == "connection"
    )
    assert event.network.closed_at is not None
    assert event.network.closed_at <= deadline - timedelta(milliseconds=100)
    assert event.network.duration < 600
    process = state.get_process(source.hostname, pid)
    assert process is not None
    assert process.last_activity_time < deadline


def test_inferred_connection_pid_is_omitted_after_owning_session_end() -> None:
    """Stale inference must not turn later traffic into a session dependent."""
    state = StateManager()
    start = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)
    deadline = start + timedelta(hours=1)
    source = System(
        hostname="WKS-01",
        ip="10.0.0.10",
        os="Windows 11",
        type="workstation",
    )
    state.set_current_time(start)
    logon_id = state.create_session(
        username="alice",
        system=source.hostname,
        logon_type=2,
        source_ip="-",
        start_time=start,
        session_kind="interactive",
    )
    state.plan_session_end(
        logon_id,
        SessionEndPlan(deadline, "explicit_storyline", "interactive-close"),
    )
    pid = state.create_process(
        source.hostname,
        4,
        r"C:\Windows\System32\OpenSSH\ssh.exe",
        "ssh app@example",
        "alice",
        "Medium",
        logon_id=logon_id,
    )
    emitter = Mock()
    emitter.can_handle.return_value = True
    generator = ActivityGenerator(state, {"zeek_conn": emitter})
    generator._ip_to_system = {source.ip: source}
    generator._system_pids = {source.hostname: {"sshd": pid}}

    generator.generate_connection(
        src_ip=source.ip,
        dst_ip="203.0.113.20",
        time=deadline + timedelta(seconds=30),
        dst_port=22,
        proto="tcp",
        service="ssh",
        duration=15.0,
        source_system=source,
        conn_state="SF",
    )

    event = next(
        call.args[0]
        for call in emitter.emit.call_args_list
        if call.args[0].event_type == "connection"
    )
    assert event.network.initiating_pid == -1


def test_network_planner_filters_ids_only_after_final_transport_outcome() -> None:
    """A prepared content alert must not survive a payload-free failed transport."""

    state = StateManager()
    state.set_current_time(datetime(2024, 1, 15, 10, 0, tzinfo=UTC))
    emitter = Mock()
    emitter.can_handle.return_value = True
    generator = ActivityGenerator(state, {"zeek_conn": emitter})
    alert = IdsAlertPlan(
        sid=2012647,
        message="upload",
        classification="web-application-attack",
        predicate=SignaturePredicate(
            transport_protocol="tcp",
            destination_port=80,
            phase="application",
            payload_direction="orig",
            minimum_payload_bytes=1,
            application_protocol="http",
            inspection="payload_cleartext",
            http_methods=("POST",),
            requires_http_body=True,
            semantic_claim="upload_request",
        ),
    )

    generator.generate_connection(
        src_ip="198.51.100.20",
        dst_ip="10.0.0.20",
        time=datetime(2024, 1, 15, 10, 0, tzinfo=UTC),
        dst_port=80,
        proto="tcp",
        service="http",
        duration=1.0,
        orig_bytes=200,
        resp_bytes=500,
        conn_state="S0",
        ids_alerts=[alert],
    )

    event = next(call.args[0] for call in emitter.emit.call_args_list)
    assert event.network is not None
    assert event.network.conn_state == "S0"
    assert event.ids_alerts == ()


def test_network_planner_clears_unconfirmed_service_without_payload() -> None:
    """A port hint cannot become Zeek service truth without analyzer-visible payload."""

    state = StateManager()
    start = datetime(2024, 1, 15, 10, 0, tzinfo=UTC)
    state.set_current_time(start)
    emitter = Mock()
    emitter.can_handle.return_value = True
    generator = ActivityGenerator(state, {"zeek_conn": emitter})

    generator.generate_connection(
        src_ip="198.51.100.20",
        dst_ip="10.0.0.20",
        time=start,
        dst_port=443,
        proto="tcp",
        service="ssl",
        duration=0.25,
        orig_bytes=0,
        resp_bytes=0,
        conn_state="OTH",
        suppress_application_side_effects=True,
        preserve_explicit_payload=True,
    )

    event = next(call.args[0] for call in emitter.emit.call_args_list)
    assert event.network is not None
    assert event.network.traffic.orig.payload_bytes == 0
    assert event.network.traffic.resp.payload_bytes == 0
    assert event.network.service == ""
    assert event.network.service == ""


def test_network_planner_retains_service_with_modeled_payload() -> None:
    """A payload-bearing completed exchange may retain its confirmed service."""

    state = StateManager()
    start = datetime(2024, 1, 15, 10, 0, tzinfo=UTC)
    state.set_current_time(start)
    emitter = Mock()
    emitter.can_handle.return_value = True
    generator = ActivityGenerator(state, {"zeek_conn": emitter})

    generator.generate_connection(
        src_ip="198.51.100.20",
        dst_ip="10.0.0.20",
        time=start,
        dst_port=445,
        proto="tcp",
        service="smb",
        duration=1.25,
        orig_bytes=512,
        resp_bytes=2048,
        conn_state="SF",
        suppress_application_side_effects=True,
        preserve_explicit_payload=True,
    )

    event = next(call.args[0] for call in emitter.emit.call_args_list)
    assert event.network is not None
    assert event.network.service == "smb"
