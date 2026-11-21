# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT
"""Dovecot session bytes encode canonical time, remote port and address."""

import base64
import ipaddress
from datetime import UTC, datetime, timedelta, timezone

import pytest

from evidenceforge.generation.activity.generator import ActivityGenerator


@pytest.mark.parametrize("client_ip", ["10.10.1.22", "2001:db8::1234", "::ffff:10.10.1.22"])
def test_session_payload_retains_native_address_and_port(client_ip: str) -> None:
    generator = object.__new__(ActivityGenerator)
    time = datetime(2026, 11, 2, 13, 42, 24, 238701, tzinfo=UTC)
    token = generator._dovecot_session_token(time=time, client_ip=client_ip, remote_port=54321)
    raw = base64.b64decode(token, validate=True)
    elapsed = time - datetime(1970, 1, 1, tzinfo=UTC)
    micros = (elapsed.days * 86400 + elapsed.seconds) * 1_000_000 + elapsed.microseconds
    assert raw[:6] == (micros % (1 << 48)).to_bytes(6, "little")
    assert raw[6:8] == bytes([0x31, 0xD4])
    assert raw[8:] == ipaddress.ip_address(client_ip).packed
    assert len(token) == (16 if ipaddress.ip_address(client_ip).version == 4 else 32)
    assert (
        generator._dovecot_session_token(time=time, client_ip=client_ip, remote_port=54321) == token
    )


def test_session_timestamp_wrap_preserves_exact_low_microseconds() -> None:
    generator = object.__new__(ActivityGenerator)
    epoch = datetime(1970, 1, 1, tzinfo=UTC)
    time = epoch + timedelta(microseconds=(1 << 48) + 123457)
    token = generator._dovecot_session_token(time=time, client_ip="10.0.0.1", remote_port=1)
    assert int.from_bytes(base64.b64decode(token)[:6], "little") == 123457
    equivalent = time.astimezone(timezone(timedelta(hours=-5)))
    assert (
        generator._dovecot_session_token(time=equivalent, client_ip="10.0.0.1", remote_port=1)
        == token
    )


@pytest.mark.parametrize("port", [-1, 0, 65536])
def test_session_rejects_non_remote_tcp_port(port: int) -> None:
    generator = object.__new__(ActivityGenerator)
    with pytest.raises(ValueError, match="port"):
        generator._dovecot_session_token(
            time=datetime(2026, 1, 1, tzinfo=UTC), client_ip="10.0.0.1", remote_port=port
        )


@pytest.mark.parametrize(
    "captured_uid, public_uid",
    [(None, "imap-uid"), ("wrong-uid", "imap-uid"), ("imap-uid", "imap-uid"), ("imap-uid", "")],
)
def test_mail_access_requires_its_exact_captured_transport(
    monkeypatch: pytest.MonkeyPatch, captured_uid: str | None, public_uid: str
) -> None:
    from types import SimpleNamespace
    from unittest.mock import Mock

    from evidenceforge.generation.actions.email import EmailAccessRequest
    from evidenceforge.generation.activity import generator as generator_module
    from evidenceforge.generation.state_manager import StateError
    from evidenceforge.models.scenario import System, User
    from tests.network_factories import network_plan

    start = datetime(2026, 11, 2, 13, tzinfo=UTC)
    client = System(hostname="CLIENT", ip="10.0.0.10", os="Windows 11", type="workstation")
    server = System(
        hostname="MAIL", ip="10.0.0.20", os="Ubuntu 22.04", type="server", roles=["mail_server"]
    )
    user = User(username="bob", full_name="Bob Brown", email="bob@example.test")
    transport = (
        network_plan(
            src_ip=client.ip,
            src_port=54321,
            dst_ip=server.ip,
            dst_port=993,
            protocol="tcp",
            zeek_uid=captured_uid,
            duration=20.0,
            source_visible_start_time=start + timedelta(seconds=5),
            conn_state="SF",
        )
        if captured_uid is not None
        else None
    )
    capture = SimpleNamespace(transaction=transport)
    monkeypatch.setattr(generator_module, "NetworkConnectionIdentityCapture", lambda: capture)
    generator = object.__new__(ActivityGenerator)
    monkeypatch.setattr(generator, "_email_server_fqdn", Mock(return_value="mail.example.test"))
    monkeypatch.setattr(generator, "_email_access_process_image", Mock(return_value="outlook.exe"))
    monkeypatch.setattr(
        generator, "_ensure_email_client_process", Mock(return_value=(1234, "outlook.exe"))
    )
    monkeypatch.setattr(
        generator, "_email_access_process_command_line", Mock(return_value="outlook.exe")
    )
    monkeypatch.setattr(generator, "_email_responding_process_pid", Mock(return_value=4321))
    network = Mock(return_value=public_uid)
    emit = Mock()
    monkeypatch.setattr(generator, "generate_connection", network)
    monkeypatch.setattr(generator, "_emit_dovecot_imap_syslog", emit)
    request = EmailAccessRequest(
        user=user, system=client, server=server, time=start, protocol="imaps", duration=20.0
    )
    if captured_uid != "imap-uid":
        with pytest.raises(StateError, match="exact canonical identity"):
            generator._execute_email_access_bundle(request)
        emit.assert_not_called()
    else:
        assert generator._execute_email_access_bundle(request) == public_uid
        assert emit.call_args.kwargs["transport"] is transport
    assert network.call_args.kwargs["identity_capture"] is capture


def test_dovecot_login_uses_committed_interval_instead_of_request_anchor(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from types import SimpleNamespace
    from unittest.mock import Mock

    from evidenceforge.models.scenario import System, User
    from tests.network_factories import network_plan

    generator = object.__new__(ActivityGenerator)
    allocate = Mock(return_value=2345)
    generator.state_manager = SimpleNamespace(allocate_transient_linux_pid=allocate)
    emit = Mock()
    monkeypatch.setattr(generator, "generate_syslog_event", emit)
    requested = datetime(2026, 11, 2, 13, tzinfo=UTC)
    actual = requested + timedelta(seconds=5)
    client = System(hostname="CLIENT", ip="10.0.0.10", os="Windows 11", type="workstation")
    server = System(
        hostname="MAIL", ip="10.0.0.20", os="Ubuntu 22.04", type="server", roles=["mail_server"]
    )
    user = User(username="bob", full_name="Bob Brown", email="bob@example.test")
    transport = network_plan(
        src_ip=client.ip,
        src_port=54321,
        dst_ip=server.ip,
        dst_port=993,
        protocol="tcp",
        zeek_uid="imap-uid",
        duration=20.0,
        source_visible_start_time=actual,
        conn_state="SF",
    )
    generator._emit_dovecot_imap_syslog(
        user=user,
        client_system=client,
        server=server,
        time=requested,
        duration=30.0,
        orig_bytes=2000,
        resp_bytes=20000,
        message_ids=(),
        master_pid=1234,
        transport=transport,
    )
    login, logout = emit.call_args_list
    assert actual < login.args[1] < logout.args[1] < transport.closed_at
    assert allocate.call_args.args[1] >= actual
    token = login.args[3].split("session=<", 1)[1].split(">", 1)[0]
    raw = base64.b64decode(token, validate=True)
    assert int.from_bytes(raw[6:8], "little") == transport.src_port
    elapsed = login.args[1] - datetime(1970, 1, 1, tzinfo=UTC)
    micros = (elapsed.days * 86400 + elapsed.seconds) * 1_000_000 + elapsed.microseconds
    assert int.from_bytes(raw[:6], "little") == micros % (1 << 48)
    assert f"><{token}>: Disconnected:" in logout.args[3]


@pytest.mark.parametrize("mapped_real_ip", ["10.0.0.20", "10.0.0.21", None])
def test_dovecot_destination_requires_exact_direct_or_static_nat_binding(
    monkeypatch: pytest.MonkeyPatch, mapped_real_ip: str | None
) -> None:
    from types import SimpleNamespace
    from unittest.mock import Mock

    from evidenceforge.generation.network_visibility import NetworkVisibilityEngine
    from evidenceforge.models.exceptions import StateError
    from evidenceforge.models.scenario import NetworkConfig, System, User
    from tests.network_factories import network_plan

    start = datetime(2026, 11, 2, 13, tzinfo=UTC)
    config = NetworkConfig.model_validate(
        {
            "segments": [
                {"name": "corp", "cidr": "10.0.0.0/24", "systems": [], "exposure": "internal"}
            ],
            "sensors": [
                {
                    "type": "firewall",
                    "name": "gateway",
                    "monitoring_segments": ["corp"],
                    "log_formats": ["cisco_asa"],
                    "nat_rules": [
                        {
                            "type": "static",
                            "src": ["corp"],
                            "real_ip": mapped_real_ip,
                            "mapped_ip": "203.0.113.20",
                        }
                    ]
                    if mapped_real_ip
                    else [],
                }
            ],
        }
    )
    visibility = NetworkVisibilityEngine(config, [])
    assert visibility.resolve_endpoint_ip("10.0.0.20") == "10.0.0.20"
    assert visibility.resolve_endpoint_ip("203.0.113.20") == (mapped_real_ip or "203.0.113.20")
    generator = object.__new__(ActivityGenerator)
    generator.dispatcher = SimpleNamespace(visibility_engine=visibility)
    allocate = Mock(return_value=2345)
    generator.state_manager = SimpleNamespace(allocate_transient_linux_pid=allocate)
    emit = Mock()
    monkeypatch.setattr(generator, "generate_syslog_event", emit)
    client = System(hostname="CLIENT", ip="10.0.0.10", os="Windows 11", type="workstation")
    server = System(hostname="MAIL", ip="10.0.0.20", os="Ubuntu 22.04", type="server")
    user = User(username="bob", full_name="Bob Brown", email="bob@example.test")
    transport = network_plan(
        src_ip=client.ip,
        src_port=54321,
        dst_ip="203.0.113.20",
        dst_port=993,
        protocol="tcp",
        zeek_uid="imap-uid",
        duration=20.0,
        source_visible_start_time=start,
        conn_state="SF",
    )
    kwargs = dict(
        user=user,
        client_system=client,
        server=server,
        time=start,
        duration=20.0,
        orig_bytes=2000,
        resp_bytes=20000,
        message_ids=(),
        master_pid=1234,
        transport=transport,
    )
    if mapped_real_ip == server.ip:
        generator._emit_dovecot_imap_syslog(**kwargs)
        assert emit.call_count == 2
        assert "lip=10.0.0.20" in emit.call_args_list[0].args[3]
        assert transport.dst_ip == "203.0.113.20"
    else:
        with pytest.raises(StateError, match="canonical IMAPS transport"):
            generator._emit_dovecot_imap_syslog(**kwargs)
        allocate.assert_not_called()
        emit.assert_not_called()
