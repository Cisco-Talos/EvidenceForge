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

from datetime import UTC, datetime, timedelta

import pytest

from evidenceforge.events.base import SecurityEvent
from evidenceforge.events.contexts import NetworkContext
from evidenceforge.events.network import DirectionalTrafficLedger, NetworkTrafficLedger
from evidenceforge.generation.state_manager import StateManager


def _network_context(start: datetime) -> NetworkContext:
    """Return a complete network context ready for transaction finalization."""

    return NetworkContext(
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
    """Legacy fields and the immutable transaction should agree exactly."""

    start = datetime(2026, 7, 14, 12, 0, tzinfo=UTC)
    network = _network_context(start)

    transaction = network.finalize_transaction(
        "network-connection-test",
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
    assert network.traffic_ledger is transaction.traffic
    network.validate_finalized_transaction()


def test_network_context_detects_post_finalization_counter_drift() -> None:
    """Downstream code may not rewrite finalized canonical accounting."""

    network = _network_context(datetime(2026, 7, 14, 12, 0, tzinfo=UTC))
    network.finalize_transaction("network-connection-test")

    network.orig_pkts += 1

    with pytest.raises(ValueError, match="changed after canonical"):
        network.validate_finalized_transaction()


def test_direct_context_without_transaction_has_compatibility_ledger() -> None:
    """Direct test/raw contexts remain readable before migration to action bundles."""

    network = NetworkContext(
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

    assert network.transaction is None
    assert network.traffic_ledger == NetworkTrafficLedger(
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
    network.conn_id = conn_id
    transaction = network.finalize_transaction("network-connection-state-test")

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
    first.conn_id = conn_id
    first.dst_port = 80
    first.service = "http"
    first.finalize_transaction("network-connection-first")
    manager.apply(SecurityEvent(timestamp=start, event_type="connection", network=first))

    second_start = start + timedelta(milliseconds=500)
    second = NetworkContext(
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
    second.finalize_transaction("network-connection-second")
    manager.apply(SecurityEvent(timestamp=second_start, event_type="connection", network=second))

    connection = manager.get_connection(conn_id)
    assert connection is not None
    assert connection.start_time == start
    assert connection.traffic_ledger.orig.payload_bytes == 612
    assert connection.traffic_ledger.resp.payload_bytes == 4396
    assert connection.traffic_ledger.orig.packets == 9
    assert connection.traffic_ledger.resp.packets == 14
