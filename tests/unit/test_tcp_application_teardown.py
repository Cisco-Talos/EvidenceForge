# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Application progress survives independent TCP teardown outcomes."""

from datetime import UTC, datetime
from unittest.mock import Mock

import pytest

from evidenceforge.events.contexts import HttpContext
from evidenceforge.generation.activity import ActivityGenerator
from evidenceforge.generation.engine.baseline import BaselineMixin
from evidenceforge.generation.state_manager import StateManager
from evidenceforge.utils.rng import generation_seed_scope


@pytest.mark.parametrize("state", ["RSTO", "RSTR", "S2", "S3"])
@pytest.mark.parametrize("service", ["ssl", "http"])
def test_response_bearing_transport_retains_protocol_before_reset_or_half_close(
    state: str, service: str
) -> None:
    at = datetime(2026, 11, 2, 13, tzinfo=UTC)
    manager = StateManager()
    manager.set_current_time(at)
    emitter = Mock()
    emitter.can_handle.return_value = True
    with generation_seed_scope(42):
        generator = ActivityGenerator(manager, {"zeek_conn": emitter})
        uid = generator.generate_connection(
            src_ip="10.0.0.10",
            dst_ip="10.0.0.20",
            src_port=51000,
            time=at,
            dst_port=443 if service == "ssl" else 80,
            proto="tcp",
            service=service,
            conn_state=state,
            duration=0.0001,
            orig_bytes=2436,
            resp_bytes=20416,
            hostname="app.example.test",
        )
    event = next(
        call.args[0] for call in emitter.emit.call_args_list if call.args[0].network.zeek_uid == uid
    )
    net = event.network
    assert net.conn_state == state
    baseline = BaselineMixin()
    baseline.activity_generator = generator
    close_bound = baseline._baseline_network_close_bound_seconds(
        src_ip=net.src_ip,
        dst_ip=net.dst_ip,
        proto="tcp",
        dst_port=net.dst_port,
        service=service,
        requested_duration_max=0.0001,
        conn_state=state,
    )
    assert net.duration <= close_bound
    assert event.protocol.ssl is not None if service == "ssl" else event.protocol.http is not None
    assert "D" in net.history and "d" in net.history
    assert net.history.endswith({"RSTO": "R", "RSTR": "r", "S2": "F", "S3": "f"}[state])
    for payload, packets, ip_bytes in [
        (net.orig_bytes, net.orig_pkts, net.orig_ip_bytes),
        (net.resp_bytes, net.resp_pkts, net.resp_ip_bytes),
    ]:
        assert payload > 0
        assert payload + 40 * packets <= ip_bytes <= 1500 * packets
    if event.protocol.ssl is not None:
        assert event.protocol.ssl.established
        if event.protocol.ssl.version == "TLSv13":
            assert not event.protocol.ssl.cert_chain_fuids
            assert not event.protocol.x509_chain


@pytest.mark.parametrize("state", ["RSTO", "RSTR", "S2", "S3", "OTH"])
def test_explicit_http_response_does_not_rewrite_tcp_teardown(state: str) -> None:
    at = datetime(2026, 11, 2, 13, tzinfo=UTC)
    manager = StateManager()
    manager.set_current_time(at)
    emitter = Mock()
    emitter.can_handle.return_value = True
    generator = ActivityGenerator(manager, {"zeek_conn": emitter})
    uid = generator.generate_connection(
        src_ip="10.0.0.10",
        dst_ip="10.0.0.20",
        src_port=51000,
        time=at,
        dst_port=80,
        proto="tcp",
        service="http",
        conn_state=state,
        duration=3,
        http=HttpContext(
            method="GET", host="app.example.test", uri="/", status_code=200, response_body_len=1200
        ),
    )
    event = next(
        call.args[0] for call in emitter.emit.call_args_list if call.args[0].network.zeek_uid == uid
    )
    assert event.network.conn_state == state
    assert event.protocol.http.status_code == 200
    assert event.network.resp_bytes >= 1200
    assert "D" in event.network.history and "d" in event.network.history


@pytest.mark.parametrize("state", ["S0", "REJ", "S1", "SH", "SHR", "OTH"])
@pytest.mark.parametrize("service", ["ssl", "http"])
def test_unproven_exchange_does_not_gain_automatic_application_evidence(
    state: str, service: str
) -> None:
    at = datetime(2026, 11, 2, 13, tzinfo=UTC)
    manager = StateManager()
    manager.set_current_time(at)
    emitter = Mock()
    emitter.can_handle.return_value = True
    generator = ActivityGenerator(manager, {"zeek_conn": emitter})
    uid = generator.generate_connection(
        src_ip="10.0.0.10",
        dst_ip="10.0.0.20",
        src_port=51000,
        time=at,
        dst_port=443 if service == "ssl" else 80,
        proto="tcp",
        service=service,
        conn_state=state,
        duration=0.03,
        orig_bytes=200,
        resp_bytes=0,
        hostname="app.example.test",
    )
    event = next(
        call.args[0] for call in emitter.emit.call_args_list if call.args[0].network.zeek_uid == uid
    )
    assert event.network.conn_state == state
    assert event.protocol.ssl is None
    assert event.protocol.http is None


@pytest.mark.parametrize("service,port", [("ssl", 443), ("http", 80), ("", 443)])
def test_suppressed_or_raw_transports_do_not_gain_application_contexts(
    service: str, port: int
) -> None:
    at = datetime(2026, 11, 2, 13, tzinfo=UTC)
    manager = StateManager()
    manager.set_current_time(at)
    emitter = Mock()
    emitter.can_handle.return_value = True
    generator = ActivityGenerator(manager, {"zeek_conn": emitter})
    uid = generator.generate_connection(
        src_ip="10.0.0.10",
        dst_ip="10.0.0.20",
        src_port=51000,
        time=at,
        dst_port=port,
        proto="tcp",
        service=service,
        conn_state="RSTR",
        duration=3,
        orig_bytes=2000,
        resp_bytes=20000,
        suppress_application_side_effects=bool(service),
    )
    event = next(
        call.args[0] for call in emitter.emit.call_args_list if call.args[0].network.zeek_uid == uid
    )
    assert event.network.conn_state == "RSTR"
    assert event.protocol.http is None
    assert event.protocol.ssl is None


def test_failed_tls_handshake_keeps_partial_payload_and_duration(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import evidenceforge.generation.actions.network_transaction_planner as planner_module
    import evidenceforge.generation.activity.generator as generator_module

    monkeypatch.setattr(generator_module, "_SSL_FAILURE_RATE", 1.0)
    monkeypatch.setattr(
        planner_module, "connection_state_distribution", lambda _protocol: [("SF", 1, "ShADadfF")]
    )
    at = datetime(2026, 11, 2, 13, tzinfo=UTC)
    manager = StateManager()
    manager.set_current_time(at)
    emitter = Mock()
    emitter.can_handle.return_value = True
    with generation_seed_scope(42):
        generator = ActivityGenerator(manager, {"zeek_conn": emitter})
        uid = generator.generate_connection(
            src_ip="10.0.0.10",
            dst_ip="10.0.0.20",
            src_port=51000,
            time=at,
            dst_port=443,
            proto="tcp",
            service="ssl",
            duration=3,
            hostname="app.example.test",
        )
    event = next(
        call.args[0] for call in emitter.emit.call_args_list if call.args[0].network.zeek_uid == uid
    )
    assert event.protocol.ssl is not None and not event.protocol.ssl.established
    assert event.network.conn_state == "S1"
    assert 90 <= event.network.orig_bytes <= 260
    assert 0 <= event.network.resp_bytes <= 180
    assert event.network.duration <= 0.500001
    assert not event.protocol.x509_chain
