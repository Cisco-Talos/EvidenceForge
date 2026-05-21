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

import math
import random
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from unittest.mock import MagicMock

import pytest

from evidenceforge.events.base import SecurityEvent
from evidenceforge.events.contexts import (
    HttpContext,
    NetworkContext,
    OcspContext,
    ProxyContext,
    X509Context,
)
from evidenceforge.events.dispatcher import EventDispatcher
from evidenceforge.generation.activity import ActivityGenerator
from evidenceforge.generation.activity.dns_registry import resolve_domain_ip
from evidenceforge.generation.emitters.ecar import EcarEmitter
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
            assert "S" in event.ssl.ssl_history
            if event.ssl.version == "TLSv13":
                assert event.x509 is None
                assert event.x509_chain == []
                assert event.ssl.cert_chain_fuids == []
            else:
                assert event.x509 is not None
                assert event.x509.fuid.startswith("F")
                assert event.x509_chain
                assert event.x509_chain[0] is event.x509
                assert event.ssl.cert_chain_fuids == [cert.fuid for cert in event.x509_chain]

    def test_tls13_omits_passive_certificate_artifacts(self, activity_gen):
        """Passive Zeek should not emit certificate FUIds or x509 rows for TLS 1.3."""
        gen, events = activity_gen

        gen.generate_connection(
            src_ip="10.0.10.50",
            dst_ip="140.82.112.5",
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
        assert event.ssl.version == "TLSv13"
        assert event.x509 is None
        assert event.x509_chain == []
        assert event.ssl.cert_chain_fuids == []

    def test_tls12_preserves_passive_certificate_artifacts(self, activity_gen):
        """TLS 1.2 handshakes still expose certificates to passive Zeek."""
        gen, events = activity_gen

        gen.generate_connection(
            src_ip="10.0.10.50",
            dst_ip="151.101.0.223",
            time=datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC),
            dst_port=443,
            proto="tcp",
            service="ssl",
            duration=2.0,
            orig_bytes=1024,
            resp_bytes=4096,
            hostname="pypi.org",
            conn_state="SF",
        )

        event = events[-1]
        assert event.ssl is not None
        assert event.ssl.version == "TLSv12"
        assert event.x509 is not None
        assert event.x509_chain
        assert event.ssl.cert_chain_fuids == [cert.fuid for cert in event.x509_chain]

    def test_explicit_successful_tls_does_not_fail_handshake(self, activity_gen):
        """A caller-pinned SF TLS connection should not be downgraded by SSL failure noise."""
        gen, events = activity_gen

        gen.generate_connection(
            src_ip="10.0.10.50",
            dst_ip="45.33.32.30",
            time=datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC),
            dst_port=8443,
            proto="tcp",
            service="ssl",
            duration=2.0,
            orig_bytes=620,
            resp_bytes=1840,
            conn_state="SF",
        )

        event = events[-1]
        assert event.network.conn_state == "SF"
        assert event.network.orig_bytes >= 620
        assert event.network.resp_bytes >= 1840
        assert event.ssl is not None
        assert event.ssl.established is True
        assert "S" in event.ssl.ssl_history

    def test_http_over_tls_forces_established_ssl_context(self, activity_gen, monkeypatch):
        """Successful HTTP evidence on TLS cannot coexist with failed ssl.log state."""
        gen, _ = activity_gen
        monkeypatch.setattr(
            "evidenceforge.generation.activity.generator._SSL_FAILURE_RATE",
            1.0,
        )
        event = SecurityEvent(
            timestamp=datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC),
            event_type="connection",
            network=NetworkContext(
                src_ip="10.0.10.50",
                src_port=51432,
                dst_ip="93.184.216.34",
                dst_port=443,
                protocol="tcp",
                service="ssl",
                conn_state="SF",
                history="ShADadFf",
            ),
            http=HttpContext(
                method="GET",
                host="example.com",
                uri="/index.html",
                status_code=200,
                status_msg="OK",
                response_body_len=4096,
            ),
        )

        gen._attach_ssl_context(
            event,
            hostname="example.com",
            dns=None,
            dst_ip="93.184.216.34",
            rng=random.Random(7),
            allow_failure=True,
        )

        assert event.network.conn_state == "SF"
        assert event.ssl is not None
        assert event.ssl.established is True
        assert event.ssl.cipher
        assert "S" in event.ssl.ssl_history

    def test_explicit_proxy_https_post_carries_body_bytes_to_egress(self, activity_gen):
        """Proxy egress should preserve canonical POST body size for exfil-style uploads."""
        gen, events = activity_gen
        source = System(hostname="WKS-01", ip="10.0.10.50", os="Windows 10", type="workstation")
        proxy = System(
            hostname="PROXY-01",
            ip="10.0.20.10",
            os="Ubuntu 22.04",
            type="server",
            roles=["forward_proxy"],
        )
        gen._ip_to_system = {source.ip: source, proxy.ip: proxy}
        gen._proxy_mode = "explicit"
        gen._proxy_routes = {source.ip: [proxy]}
        body_bytes = 268_435_700

        gen.generate_connection(
            src_ip=source.ip,
            dst_ip="45.33.32.30",
            time=datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC),
            dst_port=443,
            proto="tcp",
            service="ssl",
            duration=4.0,
            orig_bytes=body_bytes,
            resp_bytes=1711,
            conn_state="SF",
            source_system=source,
            hostname="cdn-assets-update.com",
            http=HttpContext(
                method="POST",
                host="cdn-assets-update.com",
                uri="/upload/telemetry/7f3a2b19",
                user_agent="Mozilla/5.0",
                request_body_len=body_bytes,
                response_body_len=1711,
                resp_mime_types=["application/json"],
            ),
        )

        egress_events = [
            event
            for event in events
            if event.network
            and event.network.src_ip == proxy.ip
            and event.network.dst_ip
            == resolve_domain_ip("cdn-assets-update.com", src_host=proxy.hostname)
        ]
        assert egress_events
        egress = egress_events[-1]
        assert egress.network.conn_state == "SF"
        assert egress.network.orig_bytes >= body_bytes

    def test_explicit_proxy_http_origin_leg_preserves_forwarded_request(self, activity_gen):
        """Plain HTTP proxy egress should render the forwarded request, not invent a new one."""
        gen, events = activity_gen
        source = System(hostname="WKS-01", ip="10.0.10.50", os="Windows 10", type="workstation")
        proxy = System(
            hostname="PROXY-01",
            ip="10.0.20.10",
            os="Ubuntu 22.04",
            type="server",
            roles=["forward_proxy"],
        )
        gen._ip_to_system = {source.ip: source, proxy.ip: proxy}
        gen._proxy_mode = "explicit"
        gen._proxy_routes = {source.ip: [proxy]}
        user_agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Firefox/121.0"
        proxy_context = ProxyContext(
            client_ip=source.ip,
            method="GET",
            url="http://www.google.com/complete/search?q=vpn+configuration",
            host="www.google.com",
            status_code=200,
            tunnel_status_code=200,
            sc_bytes=4250,
            cs_bytes=620,
            time_taken=1400,
            user_agent=user_agent,
            content_type="application/json",
            cache_result="MISS",
            referrer="",
            proxy_fqdn=gen._proxy_fqdn(proxy),
        )

        gen.generate_connection(
            src_ip=source.ip,
            dst_ip="142.250.80.46",
            time=datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC),
            dst_port=80,
            proto="tcp",
            service="http",
            duration=1.0,
            orig_bytes=180,
            resp_bytes=4000,
            conn_state="SF",
            source_system=source,
            hostname="www.google.com",
            proxy=proxy_context,
        )

        http_events = [event for event in events if event.http is not None and event.network]
        client = next(
            event
            for event in http_events
            if event.network.src_ip == source.ip and event.network.dst_ip == proxy.ip
        )
        egress = next(event for event in http_events if event.network.src_ip == proxy.ip)

        assert client.http.uri == "http://www.google.com/complete/search?q=vpn+configuration"
        assert egress.http.uri == "/complete/search?q=vpn+configuration"
        assert egress.http.host == "www.google.com"
        assert egress.http.user_agent == client.http.user_agent == user_agent
        assert egress.http.status_code == client.http.status_code == 200
        assert egress.http.response_body_len == client.http.response_body_len == 4000

    def test_same_scheduled_connections_get_distinct_start_jitter(self, activity_gen):
        """Batched logical connections should not render with identical Zeek start times."""
        gen, events = activity_gen
        base_time = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)

        gen.generate_connection(
            src_ip="10.0.10.1",
            dst_ip="10.0.20.10",
            time=base_time,
            dst_port=445,
            proto="tcp",
            service="smb",
            duration=1.0,
            orig_bytes=500,
            resp_bytes=1000,
            src_port=50001,
            conn_state="SF",
        )
        gen.generate_connection(
            src_ip="10.0.10.1",
            dst_ip="10.0.20.11",
            time=base_time,
            dst_port=445,
            proto="tcp",
            service="smb",
            duration=1.0,
            orig_bytes=500,
            resp_bytes=1000,
            src_port=50002,
            conn_state="SF",
        )

        conn_events = [event for event in events if event.event_type == "connection"]
        assert len(conn_events) == 2
        assert conn_events[0].timestamp != conn_events[1].timestamp
        assert conn_events[0].timestamp >= base_time
        assert conn_events[1].timestamp >= base_time

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

    def test_ssh_syslog_sub_events_are_source_ordered_with_subsecond_texture(self, activity_gen):
        gen, events = activity_gen

        user = User(username="admin", full_name="Admin User", email="admin@example.com")
        target = System(
            hostname="linux01",
            ip="10.0.20.10",
            os="Ubuntu 24.04",
            type="server",
            roles=["web_server"],
        )
        base_time = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)

        gen.generate_ssh_session(
            user=user,
            target_system=target,
            time=base_time,
            source_ip="10.0.10.50",
            source_port=51111,
            sshd_pid=6505,
        )

        syslog_events = [
            event for event in events if event.syslog is not None and event.syslog.pid == 6505
        ]
        messages = [event.syslog.message for event in syslog_events]
        times = [event.timestamp for event in syslog_events]
        assert messages == [
            "Connection from 10.0.10.50 port 51111 on 10.0.20.10 port 22",
            "Accepted password for admin from 10.0.10.50 port 51111 ssh2",
            "pam_unix(sshd:session): session opened for user admin(uid=1001) by (uid=0)",
        ]
        assert base_time < times[0] < times[1] < times[2]
        assert timedelta(milliseconds=35) <= times[0] - base_time <= timedelta(milliseconds=160)
        assert timedelta(milliseconds=450) <= times[1] - times[0] <= timedelta(milliseconds=3501)
        assert timedelta(milliseconds=45) <= times[2] - times[1] <= timedelta(milliseconds=181)
        assert times[2] - times[0] != timedelta(seconds=1)
        assert len({timestamp.microsecond % 1000 for timestamp in times}) == len(times)

        logind_events = [
            event
            for event in events
            if event.syslog is not None and event.syslog.app_name == "systemd-logind"
        ]
        assert len(logind_events) == 1
        assert logind_events[0].timestamp - times[2] >= timedelta(milliseconds=420)
        assert logind_events[0].timestamp.microsecond % 1000 not in {
            timestamp.microsecond % 1000 for timestamp in times
        }

    def test_ssh_ecar_login_source_time_follows_accepted_syslog(self, activity_gen):
        gen, events = activity_gen

        user = User(username="admin", full_name="Admin User", email="admin@example.com")
        target = System(
            hostname="linux01",
            ip="10.0.20.10",
            os="Ubuntu 24.04",
            type="server",
            roles=["web_server"],
        )
        base_time = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)

        gen.generate_ssh_session(
            user=user,
            target_system=target,
            time=base_time,
            source_ip="10.0.10.50",
            source_port=51111,
            sshd_pid=6505,
        )

        ssh_event = next(event for event in events if event.event_type == "ssh_session")
        accepted_event = next(
            event
            for event in events
            if event.syslog is not None and event.syslog.message.startswith("Accepted password")
        )
        ecar_login_time = gen._source_timing_planner.source_time(
            ssh_event,
            "source.ecar_session",
            seed_parts=(
                "login",
                ssh_event.dst_host.hostname,
                user.username,
                "10.0.10.50",
                51111,
                "",
                10,
                "",
                ssh_event.timestamp,
            ),
        )

        assert ecar_login_time > accepted_event.timestamp
        assert ecar_login_time > accepted_event.timestamp + timedelta(milliseconds=250)
        delayed_for_observation_profile = replace(
            ssh_event,
            timestamp=ssh_event.timestamp + timedelta(milliseconds=750),
            storyline_cluster_id="storyline-ssh",
        )
        delayed_ecar_time = EcarEmitter._session_timestamp(
            object.__new__(EcarEmitter),
            delayed_for_observation_profile,
            delayed_for_observation_profile.dst_host,
            "login",
        )

        assert delayed_ecar_time == ecar_login_time

    def test_ocsp_repeated_response_profile_keeps_body_size_stable(self, activity_gen):
        gen, _events = activity_gen
        calls = []

        def capture_connection(**kwargs):
            calls.append(kwargs)

        gen.generate_connection = capture_connection
        tls_event = SecurityEvent(
            timestamp=datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC),
            event_type="connection",
            network=NetworkContext(
                src_ip="10.0.10.50",
                src_port=51111,
                dst_ip="93.184.216.34",
                dst_port=443,
                protocol="tcp",
                service="ssl",
                zeek_uid="CsslOcspStable",
                conn_state="SF",
            ),
            x509=X509Context(
                fuid="Fcert",
                certificate_serial="789E942DD4A61EF31D",
                certificate_subject="CN=example.com",
                certificate_issuer="CN=DigiCert TLS RSA SHA256 2020 CA1, O=DigiCert Inc, C=US",
            ),
        )
        ocsp_a = OcspContext(
            id="FocspA",
            serial_number="789E942DD4A61EF31D",
            cert_status="good",
            this_update=1710762449.0,
            next_update=1711055820.0,
        )
        ocsp_b = OcspContext(
            id="FocspB",
            serial_number="789E942DD4A61EF31D",
            cert_status="good",
            this_update=1710762449.0,
            next_update=1711055820.0,
        )

        gen._emit_ocsp_http_response(
            tls_event,
            cert_name="example.com",
            ocsp=ocsp_a,
            rng=random.Random(1),
        )
        gen._emit_ocsp_http_response(
            tls_event,
            cert_name="example.com",
            ocsp=ocsp_b,
            rng=random.Random(2),
        )

        assert len(calls) == 2
        assert calls[0]["http"].response_body_len == calls[1]["http"].response_body_len
        assert calls[0]["file_transfer"].total_bytes == calls[1]["file_transfer"].total_bytes
        assert calls[0]["http"].tags == calls[1]["http"].tags == ["ocsp"]

    def test_ssh_systemd_session_ids_stay_in_same_integer_regime(self, activity_gen):
        gen, events = activity_gen

        user = User(username="admin", full_name="Admin User", email="admin@example.com")
        target = System(
            hostname="linux01",
            ip="10.0.20.10",
            os="Ubuntu 24.04",
            type="server",
            roles=["web_server"],
        )

        for idx in range(3):
            gen.generate_ssh_session(
                user=user,
                target_system=target,
                time=datetime(2024, 1, 15, 10, idx, 0, tzinfo=UTC),
                source_ip="10.0.10.50",
            )

        session_ids = []
        for event in events:
            if event.syslog is None or event.syslog.app_name != "systemd-logind":
                continue
            session_ids.append(int(event.syslog.message.split()[2]))

        assert len(session_ids) == 3
        assert session_ids == sorted(session_ids)
        assert max(session_ids) < 1000

    def test_ssh_systemd_logind_uses_seeded_host_pid(self, activity_gen):
        gen, events = activity_gen
        gen._system_pids = {"linux01": {"logind": 789}}

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

        logind_events = [
            event for event in events if event.syslog and event.syslog.app_name == "systemd-logind"
        ]
        assert logind_events
        assert {event.syslog.pid for event in logind_events} == {789}

    def test_ssh_connection_carries_ip_byte_counters(self, activity_gen):
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

        ssh_events = [
            event
            for event in events
            if event.network is not None and event.network.service == "ssh"
        ]
        assert ssh_events
        event = ssh_events[0]
        assert event.network.orig_ip_bytes is not None
        assert event.network.resp_ip_bytes is not None
        assert event.network.orig_ip_bytes > event.network.orig_bytes
        assert event.network.resp_ip_bytes > event.network.resp_bytes
        assert (
            event.network.orig_ip_bytes != event.network.orig_bytes + event.network.orig_pkts * 40
        )
        assert (
            event.network.resp_ip_bytes != event.network.resp_bytes + event.network.resp_pkts * 40
        )

    def test_ssh_session_records_transport_close_time(self, activity_gen):
        gen, events = activity_gen

        user = User(username="admin", full_name="Admin User", email="admin@example.com")
        target = System(
            hostname="linux01",
            ip="10.0.20.10",
            os="Ubuntu 24.04",
            type="server",
            roles=["web_server"],
        )
        base_time = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)
        logon_id = gen.state_manager.create_session(
            username=user.username,
            system=target.hostname,
            logon_type=10,
            source_ip="10.0.10.50",
            source_port=51111,
            session_kind="ssh",
        )

        gen.generate_ssh_session(
            user=user,
            target_system=target,
            time=base_time,
            source_ip="10.0.10.50",
            source_port=51111,
            logon_id=logon_id,
        )

        ssh_event = next(
            event
            for event in events
            if event.network is not None and event.network.service == "ssh"
        )
        session = gen.state_manager.get_session(logon_id)
        assert session is not None
        assert session.network_close_time == base_time + timedelta(
            seconds=ssh_event.network.duration
        )

    def test_ssh_session_records_transport_close_time_with_existing_object_id(self, activity_gen):
        gen, events = activity_gen

        user = User(username="admin", full_name="Admin User", email="admin@example.com")
        target = System(
            hostname="linux01",
            ip="10.0.20.10",
            os="Ubuntu 24.04",
            type="server",
            roles=["web_server"],
        )
        base_time = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)
        logon_id = gen.state_manager.create_session(
            username=user.username,
            system=target.hostname,
            logon_type=10,
            source_ip="10.0.10.50",
            source_port=51111,
            session_kind="ssh",
        )
        session_obj_id = gen.state_manager.get_session_object_id(logon_id)

        gen.generate_ssh_session(
            user=user,
            target_system=target,
            time=base_time,
            source_ip="10.0.10.50",
            source_port=51111,
            logon_id=logon_id,
            session_obj_id=session_obj_id,
        )

        ssh_event = next(
            event
            for event in events
            if event.network is not None and event.network.service == "ssh"
        )
        session = gen.state_manager.get_session(logon_id)
        assert session is not None
        assert session.network_close_time == base_time + timedelta(
            seconds=ssh_event.network.duration
        )

    def test_ssh_session_honors_min_duration(self, activity_gen):
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
            min_duration=7200.0,
        )

        ssh_event = next(
            event
            for event in events
            if event.network is not None and event.network.service == "ssh"
        )
        assert ssh_event.network.duration >= 7200.0

    def test_ssh_source_ports_are_unique_per_endpoint_tuple(self, activity_gen):
        gen, events = activity_gen

        user = User(username="admin", full_name="Admin User", email="admin@example.com")
        target = System(
            hostname="linux01",
            ip="10.0.20.10",
            os="Ubuntu 24.04",
            type="server",
            roles=["web_server"],
        )
        base_time = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)

        for idx in range(2):
            gen.generate_ssh_session(
                user=user,
                target_system=target,
                time=base_time + timedelta(minutes=idx),
                source_ip="10.0.10.50",
                source_port=51111,
            )

        ssh_ports = [
            event.network.src_port
            for event in events
            if event.network is not None and event.network.service == "ssh"
        ]
        assert len(ssh_ports) == 2
        assert len(set(ssh_ports)) == 2

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
            hostname="pypi.org",
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
            src_ip="10.30.40.1",
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
            hostname="pypi.org",
            conn_state="SF",
        )

        event = events[-1]
        assert event.ssl is not None
        assert event.x509 is not None
        assert event.ssl.server_name == "pypi.org"
        assert event.x509.certificate_subject == "CN=pypi.org"
        assert event.x509.san_dns == ["pypi.org", "*.pypi.org"]
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
        if tls_event.ssl.version == "TLSv13":
            assert tls_event.x509 is None
            assert tls_event.ssl.cert_chain_fuids == []
        else:
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
                hostname="pypi.org",
                conn_state="SF",
            )

        resumed_events = [
            event for event in events if event.ssl is not None and event.ssl.resumed is True
        ]
        assert resumed_events
        for event in resumed_events:
            assert event.x509 is None
            assert event.ssl.cert_chain_fuids == []

    def test_single_observed_tls_clients_do_not_resume(self, activity_gen):
        """TLS resumption should require prior client/server pair state."""
        gen, events = activity_gen

        for offset in range(20):
            gen.generate_connection(
                src_ip=f"198.51.100.{offset + 1}",
                dst_ip="203.14.220.10",
                time=datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC) + timedelta(seconds=offset),
                dst_port=443,
                proto="tcp",
                service="ssl",
                duration=2.0,
                orig_bytes=1024,
                resp_bytes=4096,
                hostname="ehr-portal.example.org",
                conn_state="SF",
            )

        tls_events = [event for event in events if event.ssl is not None]
        assert len(tls_events) == 20
        assert all(event.ssl.resumed is False for event in tls_events)

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
                hostname="pypi.org",
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
            assert event.ocsp.hash_algorithm == "sha1"
            assert len(event.ocsp.issuer_name_hash) == 40
            assert len(event.ocsp.issuer_key_hash) == 40
            assert event.network.service == "http"
            assert event.http is not None
            assert event.http.resp_fuids == [event.ocsp.id]
            assert event.file_transfer is not None
            assert event.file_transfer.fuid == event.ocsp.id
            assert event.file_transfer.mime_type == "application/ocsp-response"
            assert event.network.zeek_uid

        assert all(len(statuses) == 1 for statuses in statuses_by_serial.values())
        assert all(len(windows) <= 2 for windows in windows_by_serial.values())

    def test_linux_proxy_originated_ocsp_uses_linux_agent(self, activity_gen):
        """Proxy-side OCSP fetches should not inherit Windows CryptoAPI identity."""
        gen, events = activity_gen
        proxy = System(
            hostname="PROXY-01",
            ip="10.10.3.20",
            os="Ubuntu 22.04",
            type="server",
            roles=["forward_proxy"],
        )
        gen._ip_to_system = {proxy.ip: proxy}

        for offset in range(120):
            gen.generate_connection(
                src_ip=proxy.ip,
                dst_ip="91.189.91.81",
                time=datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC) + timedelta(minutes=offset),
                dst_port=443,
                proto="tcp",
                service="ssl",
                duration=2.0,
                orig_bytes=1024,
                resp_bytes=4096,
                hostname="security.ubuntu.com",
                conn_state="SF",
                source_system=proxy,
            )
            gen._tls_seen_server_names.clear()

        ocsp_events = [event for event in events if event.ocsp is not None]
        assert ocsp_events
        assert all(event.http is not None for event in ocsp_events)
        assert all(event.http.user_agent != "Microsoft-CryptoAPI/10.0" for event in ocsp_events)

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
                hostname="pypi.org",
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

    def test_syn_only_tcp_connection_has_no_analyzer_service(self, activity_gen):
        gen, events = activity_gen

        gen.generate_connection(
            src_ip="10.0.10.50",
            dst_ip="10.0.20.10",
            time=datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC),
            dst_port=1433,
            proto="tcp",
            service="mssql",
            conn_state="S0",
        )

        event = events[-1]
        assert event.network.conn_state == "S0"
        assert event.network.service == ""
        assert event.network.orig_bytes == 0
        assert event.network.resp_bytes == 0
        assert event.network.resp_pkts == 0
        assert event.network.resp_ip_bytes == 0

    def test_empty_service_suppresses_port_based_tls_inference(self, activity_gen):
        gen, events = activity_gen

        gen.generate_connection(
            src_ip="10.0.10.50",
            dst_ip="203.0.113.10",
            time=datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC),
            dst_port=443,
            proto="tcp",
            service="",
            conn_state="SF",
            duration=2.0,
            orig_bytes=620,
            resp_bytes=1840,
            hostname="",
        )

        event = events[-1]
        assert event.network.service == ""
        assert event.ssl is None

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

    def test_http_conn_response_bytes_include_protocol_overhead(self, activity_gen):
        """Zeek conn.resp_bytes should not exactly mirror HTTP entity body size."""
        gen, events = activity_gen

        gen.generate_connection(
            src_ip="10.0.10.50",
            dst_ip="93.184.216.34",
            time=datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC),
            dst_port=80,
            proto="tcp",
            service="http",
            duration=1.0,
            orig_bytes=128,
            resp_bytes=4096,
            conn_state="SF",
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
        assert event.network.resp_bytes > event.http.response_body_len

    def test_large_tcp_transfer_counts_reverse_ack_packets(self, activity_gen, monkeypatch):
        """Large one-way TCP transfers should not keep single-digit ACK-side packet counts."""
        import evidenceforge.generation.activity.generator as generator_module

        gen, events = activity_gen
        monkeypatch.setattr(generator_module, "_tcp_effective_mss_bytes", lambda _rng: 1200)

        gen.generate_connection(
            src_ip="10.0.10.50",
            dst_ip="10.0.20.20",
            time=datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC),
            dst_port=8080,
            proto="tcp",
            service="http",
            duration=9.0,
            orig_bytes=314_783_347,
            resp_bytes=2631,
            conn_state="SF",
        )
        upload = events[-1].network

        gen.generate_connection(
            src_ip="10.0.10.50",
            dst_ip="10.0.20.20",
            time=datetime(2024, 1, 15, 10, 1, 0, tzinfo=UTC),
            dst_port=445,
            proto="tcp",
            service="smb",
            duration=9.0,
            orig_bytes=93_264,
            resp_bytes=313_934_166,
            conn_state="SF",
        )
        download = events[-1].network

        assert upload.resp_pkts >= math.ceil((upload.orig_bytes or 0) / 1460 / 4)
        assert upload.resp_ip_bytes >= (upload.resp_bytes or 0) + (upload.resp_pkts * 40)
        assert upload.orig_pkts > math.ceil((upload.orig_bytes or 0) / 1460)
        assert upload.orig_ip_bytes != (upload.orig_bytes or 0) + (upload.orig_pkts * 52)
        assert download.orig_pkts >= math.ceil((download.resp_bytes or 0) / 1460 / 4)
        assert download.orig_ip_bytes >= (download.orig_bytes or 0) + (download.orig_pkts * 40)
        assert download.resp_pkts > math.ceil((download.resp_bytes or 0) / 1460)
        assert download.resp_ip_bytes != (download.resp_bytes or 0) + (download.resp_pkts * 52)

    def test_http_enrichment_counts_control_packets(self, activity_gen, monkeypatch):
        """HTTP body accounting should retain Zeek history control packets in conn.log counts."""
        import evidenceforge.generation.activity.generator as generator_module

        gen, events = activity_gen
        monkeypatch.setattr(generator_module, "_tcp_success_history", lambda _rng: "ShADadf")

        gen.generate_connection(
            src_ip="10.0.10.50",
            dst_ip="10.0.20.20",
            time=datetime(2024, 1, 15, 10, 2, 0, tzinfo=UTC),
            dst_port=8080,
            proto="tcp",
            service="http",
            duration=1.2,
            conn_state="SF",
            http=HttpContext(
                method="GET",
                host="app.internal",
                uri="/download/report.csv",
                version="1.1",
                user_agent="Mozilla/5.0",
                request_body_len=0,
                response_body_len=11_396,
                status_code=200,
                status_msg="OK",
                resp_mime_types=["text/csv"],
            ),
        )

        net = events[-1].network
        assert net.resp_pkts > math.ceil((net.resp_bytes or 0) / 1460)
        assert net.resp_ip_bytes != (net.resp_bytes or 0) + (net.resp_pkts * 52)

    def test_icmp_accounting_is_echo_like(self, activity_gen):
        """ICMP echo-style flows should not inherit bulk TCP byte/packet accounting."""
        gen, events = activity_gen

        gen.generate_connection(
            src_ip="10.0.10.50",
            dst_ip="10.0.10.1",
            time=datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC),
            proto="icmp",
            service="icmp",
            duration=0.05,
            orig_bytes=1204,
            resp_bytes=72384,
        )

        event = events[-1]
        assert event.network.orig_pkts == 1
        assert event.network.resp_pkts == 1
        assert event.network.resp_bytes <= 1520
        assert event.network.resp_bytes == event.network.orig_bytes
        assert event.network.duration <= 0.15

    def test_duplicate_icmp_tuple_times_are_disambiguated(self, activity_gen):
        """Repeated ICMP observations should not render exact same tuple and microsecond."""
        gen, events = activity_gen
        timestamp = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)

        for requested_size in (64, 84, 120):
            gen.generate_connection(
                src_ip="10.10.4.10",
                dst_ip="10.10.3.20",
                time=timestamp,
                proto="icmp",
                service="icmp",
                duration=0.02,
                orig_bytes=requested_size,
                resp_bytes=requested_size,
            )

        icmp_events = [
            event for event in events if event.network and event.network.protocol == "icmp"
        ]
        assert len(icmp_events) == 3
        rendered_keys = {
            (
                event.timestamp,
                event.network.src_ip,
                event.network.src_port or 8,
                event.network.dst_ip,
                event.network.dst_port or 0,
            )
            for event in icmp_events
        }
        assert len(rendered_keys) == 3


class TestFileTransferContext:
    """Verify FileTransferContext populated probabilistically for HTTP."""

    def test_redirect_asset_response_does_not_attach_asset_file_transfer(
        self, activity_gen, monkeypatch
    ):
        """Redirect bodies keep text/html MIME instead of asset extension MIME."""
        gen, events = activity_gen

        class LowRandom(random.Random):
            def random(self) -> float:
                return 0.05

        import evidenceforge.generation.activity.generator as generator_module
        import evidenceforge.generation.activity.proxy_uri as proxy_uri_module

        monkeypatch.setattr(generator_module, "_get_rng", lambda: LowRandom(7))
        monkeypatch.setattr(
            generator_module,
            "_get_http_status",
            lambda _dst_ip, _uri: (301, "Moved Permanently"),
        )
        monkeypatch.setattr(
            proxy_uri_module,
            "pick_proxy_uri",
            lambda *_args, **_kwargs: (
                "/assets/app.js",
                "application/javascript",
                "GET",
                "",
                "none",
            ),
        )

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
            conn_state="SF",
        )

        event = events[-1]
        assert event.http is not None
        assert event.http.status_code == 301
        assert event.http.resp_mime_types == ["text/html"]
        assert event.file_transfer is None

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
