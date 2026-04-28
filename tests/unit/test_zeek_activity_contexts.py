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

"""Tests for activity generator SSL/HTTP/FileTransfer context population."""

from datetime import UTC, datetime, timedelta
from unittest.mock import MagicMock

import pytest

from evidenceforge.events.contexts import HttpContext
from evidenceforge.events.dispatcher import EventDispatcher
from evidenceforge.generation.activity import ActivityGenerator
from evidenceforge.generation.state_manager import StateManager
from evidenceforge.models.scenario import System, User


@pytest.fixture
def activity_gen():
    """Create ActivityGenerator with mock dependencies that capture dispatched events."""
    state_manager = StateManager()
    state_manager.set_current_time(datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC))

    # Create mock emitters dict
    mock_emitters = {}
    for name in [
        "zeek_conn",
        "zeek_dns",
        "zeek_ssl",
        "zeek_http",
        "zeek_files",
        "windows_event_security",
        "ecar",
        "syslog",
        "bash_history",
        "snort_alert",
        "web_access",
    ]:
        m = MagicMock()
        m.can_handle.return_value = False
        mock_emitters[name] = m
    # conn emitter accepts connection events
    mock_emitters["zeek_conn"].can_handle.side_effect = lambda e: (
        e.event_type in {"connection", "ssh_session"} and e.network is not None
    )

    dispatcher = EventDispatcher(state_manager, mock_emitters)

    captured_events = []
    original_dispatch = dispatcher.dispatch

    def capturing_dispatch(event):
        captured_events.append(event)
        original_dispatch(event)

    dispatcher.dispatch = capturing_dispatch

    gen = ActivityGenerator(state_manager, mock_emitters, dispatcher=dispatcher)
    return gen, captured_events


class TestSslContextPopulation:
    """Verify SSL context is attached to connection events for port 443."""

    def test_ssl_service_gets_ssl_context(self, activity_gen):
        gen, events = activity_gen

        gen.generate_connection(
            src_ip="10.0.10.50",
            dst_ip="93.184.216.34",
            time=datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC),
            dst_port=443,
            proto="tcp",
            service="ssl",
            duration=2.0,
            orig_bytes=1024,
            resp_bytes=4096,
            conn_state="SF",
        )

        assert len(events) > 0
        event = events[-1]
        # SF connections with ssl service should have SslContext
        if event.network.conn_state == "SF":
            assert event.ssl is not None
            assert event.ssl.version in {"TLSv12", "TLSv13"}
            assert event.ssl.cipher != ""
            assert event.ssl.established is True
            assert event.x509 is not None
            assert event.x509.fuid.startswith("F")
            assert event.x509_chain
            assert event.x509_chain[0] is event.x509
            assert event.ssl.cert_chain_fuids == [cert.fuid for cert in event.x509_chain]

    def test_ssh_session_returns_empty_uid_when_network_not_visible(self, activity_gen):
        gen, events = activity_gen
        visibility = MagicMock()
        visibility.is_connection_visible.return_value = False
        gen._network_visibility = visibility

        user = User(username="alice", full_name="Alice Admin", email="alice@example.com")
        target = System(
            hostname="linux01",
            ip="10.0.20.10",
            os="Ubuntu 24.04",
            type="server",
            roles=["web_server"],
        )

        uid = gen.generate_ssh_session(
            user=user,
            target_system=target,
            time=datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC),
            source_ip="10.0.10.50",
        )

        assert uid == ""
        assert any(event.event_type == "ssh_session" for event in events)
        visibility.is_connection_visible.assert_any_call("10.0.10.50", "10.0.20.10")

    def test_ssh_session_pam_message_uses_non_root_user_uid(self, activity_gen):
        gen, events = activity_gen

        user = User(username="admin", full_name="Admin User", email="admin@example.com")
        target = System(
            hostname="linux01",
            ip="10.0.20.10",
            os="Ubuntu 24.04",
            type="server",
            roles=["web_server"],
        )

        gen.generate_ssh_session(
            user=user,
            target_system=target,
            time=datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC),
            source_ip="10.0.10.50",
        )

        pam_messages = [
            event.syslog.message
            for event in events
            if event.syslog is not None and "pam_unix(sshd:session)" in event.syslog.message
        ]
        assert pam_messages
        assert "admin(uid=1001) by (uid=0)" in pam_messages[0]
        assert "admin(uid=0)" not in pam_messages[0]

    def test_http_service_no_ssl_context(self, activity_gen):
        gen, events = activity_gen

        gen.generate_connection(
            src_ip="10.0.10.50",
            dst_ip="93.184.216.34",
            time=datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC),
            dst_port=80,
            proto="tcp",
            service="http",
            duration=1.0,
            orig_bytes=200,
            resp_bytes=5000,
        )

        event = events[-1]
        assert event.ssl is None

    def test_dns_service_gets_dns_context(self, activity_gen):
        gen, events = activity_gen

        gen.generate_connection(
            src_ip="10.0.10.50",
            dst_ip="10.0.20.10",
            time=datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC),
            dst_port=53,
            proto="udp",
            service="dns",
            duration=0.01,
            orig_bytes=60,
            resp_bytes=120,
            hostname="example.com",
        )

        event = events[-1]
        assert event.dns is not None
        assert event.dns.query == "example.com"
        assert event.dns.answers == ["10.0.20.10"]

    def test_tls12_cipher_matches_certificate_key_type(self, activity_gen):
        gen, events = activity_gen

        gen.generate_connection(
            src_ip="10.0.10.50",
            dst_ip="142.250.72.36",
            time=datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC),
            dst_port=443,
            proto="tcp",
            service="ssl",
            duration=2.0,
            orig_bytes=1024,
            resp_bytes=4096,
            hostname="www.gstatic.com",
            conn_state="SF",
        )

        event = events[-1]
        assert event.ssl is not None
        assert event.x509 is not None
        if event.ssl.version == "TLSv12":
            if "ECDSA" in event.ssl.cipher:
                assert event.x509.certificate_key_type == "ecdsa"
            if "RSA" in event.ssl.cipher:
                assert event.x509.certificate_key_type == "rsa"

    def test_raw_ip_ssl_does_not_invent_sni_from_reverse_dns(self, activity_gen):
        """Raw-IP SSL without DNS evidence should not invent SNI from PTR data."""
        gen, events = activity_gen

        gen.generate_connection(
            src_ip="10.0.10.50",
            dst_ip="93.184.216.34",
            time=datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC),
            dst_port=443,
            proto="tcp",
            service="ssl",
            duration=2.0,
            orig_bytes=1024,
            resp_bytes=4096,
            conn_state="SF",
        )

        event = events[-1]
        assert event.ssl is not None
        assert event.ssl.server_name in (None, "")
        assert event.x509 is not None
        assert event.x509.certificate_subject == "CN=93.184.216.34"
        assert event.x509.san_dns == []

    def test_explicit_hostname_ssl_uses_hostname_for_sni_and_cert(self, activity_gen):
        """Explicit hostnames remain the shared SNI/certificate identity."""
        gen, events = activity_gen

        gen.generate_connection(
            src_ip="10.0.10.50",
            dst_ip="142.250.72.36",
            time=datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC),
            dst_port=443,
            proto="tcp",
            service="ssl",
            duration=2.0,
            orig_bytes=1024,
            resp_bytes=4096,
            hostname="www.gstatic.com",
            conn_state="SF",
        )

        event = events[-1]
        assert event.ssl is not None
        assert event.x509 is not None
        assert event.ssl.server_name == "www.gstatic.com"
        assert event.x509.certificate_subject == "CN=www.gstatic.com"
        assert event.x509.san_dns == ["www.gstatic.com", "*.gstatic.com"]
        assert event.x509_chain[0] is event.x509

    def test_auto_tls_uses_profiled_destination_for_sni_and_dns(self, activity_gen):
        """Auto-generated external TLS should use profiled destinations, not tiny random pools."""
        gen, events = activity_gen
        system = System(
            hostname="WKS-01",
            ip="10.0.10.50",
            os="Windows 11",
            type="workstation",
            assigned_user="jsmith",
        )
        user = User(
            username="jsmith",
            full_name="Jane Smith",
            email="j.smith@example.com",
            persona="developer",
            primary_system="WKS-01",
        )
        gen._ip_to_system = {system.ip: system}
        gen._users_by_username = {user.username: user}

        gen.generate_connection(
            src_ip=system.ip,
            dst_ip="93.184.216.34",
            time=datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC),
            dst_port=443,
            proto="tcp",
            service="ssl",
            duration=2.0,
            orig_bytes=1024,
            resp_bytes=4096,
            emit_dns=True,
            conn_state="SF",
        )

        tls_event = next(event for event in reversed(events) if event.ssl is not None)
        assert tls_event.ssl.server_name
        assert tls_event.x509 is not None
        assert tls_event.x509.certificate_subject == f"CN={tls_event.ssl.server_name}"
        assert not tls_event.ssl.server_name.startswith("host-")

    def test_tls_certificate_chains_include_intermediates_across_sample(self, activity_gen):
        """Configured TLS chain generation should produce CA/intermediate x509 rows."""
        gen, events = activity_gen

        for idx in range(12):
            gen.generate_connection(
                src_ip="10.0.10.50",
                dst_ip="142.250.72.36",
                time=datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC) + timedelta(minutes=idx),
                dst_port=443,
                proto="tcp",
                service="ssl",
                duration=2.0,
                orig_bytes=1024,
                resp_bytes=4096,
                hostname=f"asset{idx}.gstatic.com",
                conn_state="SF",
            )

        chains = [event.x509_chain for event in events if event.x509_chain]
        assert chains
        assert any(any(cert.basic_constraints_ca for cert in chain[1:]) for chain in chains)
        for chain in chains:
            assert chain[0].basic_constraints_ca is False
            assert [cert.fuid for cert in chain] == next(
                event.ssl.cert_chain_fuids for event in events if event.x509_chain is chain
            )

    def test_resumed_ssl_sessions_omit_fresh_certificate_chain(self, activity_gen):
        """Resumed handshakes should not repeatedly emit full x509 chains."""
        gen, events = activity_gen

        for offset in range(40):
            gen.generate_connection(
                src_ip="10.0.10.50",
                dst_ip="142.250.72.36",
                time=datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC) + timedelta(minutes=offset),
                dst_port=443,
                proto="tcp",
                service="ssl",
                duration=2.0,
                orig_bytes=1024,
                resp_bytes=4096,
                hostname="www.gstatic.com",
                conn_state="SF",
            )

        resumed_events = [
            event for event in events if event.ssl is not None and event.ssl.resumed is True
        ]
        assert resumed_events
        for event in resumed_events:
            assert event.x509 is None
            assert event.ssl.cert_chain_fuids == []

    def test_ocsp_status_and_update_window_are_cached_per_certificate(self, activity_gen):
        """OCSP responses should not expire at observation time or flip status per serial."""
        gen, events = activity_gen

        for offset in range(100):
            gen.generate_connection(
                src_ip="10.0.10.50",
                dst_ip="142.250.72.36",
                time=datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC) + timedelta(minutes=offset),
                dst_port=443,
                proto="tcp",
                service="ssl",
                duration=2.0,
                orig_bytes=1024,
                resp_bytes=4096,
                hostname="www.gstatic.com",
                conn_state="SF",
            )
            gen._tls_seen_server_names.clear()

        ocsp_events = [event for event in events if event.ocsp is not None]
        assert ocsp_events
        statuses_by_serial: dict[str, set[str]] = {}
        windows_by_serial: dict[str, set[tuple[float, float]]] = {}
        for event in ocsp_events:
            serial = event.ocsp.serial_number
            statuses_by_serial.setdefault(serial, set()).add(event.ocsp.cert_status)
            windows_by_serial.setdefault(serial, set()).add(
                (event.ocsp.this_update, event.ocsp.next_update)
            )
            assert event.ocsp.this_update <= event.timestamp.timestamp()
            assert event.ocsp.next_update > event.timestamp.timestamp()
            assert event.file_transfer is None

        assert all(len(statuses) == 1 for statuses in statuses_by_serial.values())
        assert all(len(windows) <= 2 for windows in windows_by_serial.values())

    def test_same_certificate_identity_has_stable_validity_window(self, activity_gen):
        gen, events = activity_gen

        for offset in (0, 3600):
            gen.generate_connection(
                src_ip="10.0.10.50",
                dst_ip="142.250.72.36",
                time=datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC) + timedelta(seconds=offset),
                dst_port=443,
                proto="tcp",
                service="ssl",
                duration=2.0,
                orig_bytes=1024,
                resp_bytes=4096,
                hostname="www.gstatic.com",
                conn_state="SF",
            )
            gen._tls_seen_server_names.clear()

        cert_events = [event for event in events if event.x509 is not None]
        assert len(cert_events) == 2
        first = cert_events[0].x509
        second = cert_events[1].x509
        assert first.fingerprint == second.fingerprint
        assert first.certificate_serial == second.certificate_serial
        assert first.certificate_not_valid_before == second.certificate_not_valid_before
        assert first.certificate_not_valid_after == second.certificate_not_valid_after


class TestHttpContextPopulation:
    """Verify HTTP context is attached to connection events for port 80."""

    def test_http_service_gets_http_context(self, activity_gen):
        gen, events = activity_gen

        gen.generate_connection(
            src_ip="10.0.10.50",
            dst_ip="93.184.216.34",
            time=datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC),
            dst_port=80,
            proto="tcp",
            service="http",
            duration=1.0,
            orig_bytes=200,
            resp_bytes=5000,
        )

        event = events[-1]
        if event.network.conn_state == "SF":
            assert event.http is not None
            assert event.http.method == "GET"
            assert event.http.host != ""
            assert event.http.uri.startswith("/")
            assert event.http.status_code in {200, 301, 302, 304, 403, 404, 500}

    def test_http_host_includes_port_for_non_standard(self, activity_gen):
        """Host header should include port for non-80/443 ports."""
        gen, events = activity_gen

        gen.generate_connection(
            src_ip="10.0.10.50",
            dst_ip="93.184.216.34",
            time=datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC),
            dst_port=8080,
            proto="tcp",
            service="http",
            duration=1.0,
            orig_bytes=200,
            resp_bytes=5000,
        )

        event = events[-1]
        if event.http is not None:
            assert ":8080" in event.http.host

    def test_ssl_service_no_http_context(self, activity_gen):
        gen, events = activity_gen

        gen.generate_connection(
            src_ip="10.0.10.50",
            dst_ip="93.184.216.34",
            time=datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC),
            dst_port=443,
            proto="tcp",
            service="ssl",
            duration=2.0,
            orig_bytes=1024,
            resp_bytes=4096,
        )

        event = events[-1]
        assert event.http is None

    def test_caller_provided_http_forces_conn_accounting_consistency(self, activity_gen):
        gen, events = activity_gen

        gen.generate_connection(
            src_ip="10.0.10.50",
            dst_ip="93.184.216.34",
            time=datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC),
            dst_port=80,
            proto="tcp",
            service="http",
            duration=1.0,
            orig_bytes=0,
            resp_bytes=0,
            conn_state="S1",
            http=HttpContext(
                method="GET",
                host="example.com",
                uri="/index.html",
                version="1.1",
                user_agent="Mozilla/5.0",
                response_body_len=4096,
                status_code=200,
                status_msg="OK",
            ),
        )

        event = events[-1]
        assert event.network.conn_state == "SF"
        assert event.network.resp_bytes >= event.http.response_body_len
        assert event.network.resp_pkts > 0


class TestFileTransferContext:
    """Verify FileTransferContext populated probabilistically for HTTP."""

    def test_file_transfer_sometimes_populated(self, activity_gen):
        """Over many HTTP connections, some should have FileTransferContext."""
        gen, events = activity_gen

        has_file_transfer = False
        for _ in range(100):
            gen.generate_connection(
                src_ip="10.0.10.50",
                dst_ip="93.184.216.34",
                time=datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC),
                dst_port=80,
                proto="tcp",
                service="http",
                duration=1.0,
                orig_bytes=200,
                resp_bytes=5000,
            )

        for event in events:
            if event.file_transfer is not None:
                has_file_transfer = True
                assert event.file_transfer.fuid.startswith("F")
                assert event.file_transfer.source == "HTTP"
                assert event.file_transfer.seen_bytes > 0
                if event.http is not None:
                    assert event.file_transfer.fuid in event.http.resp_fuids
                break

        assert has_file_transfer, (
            "Expected at least one FileTransferContext in 100 HTTP connections"
        )
