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
    HostContext,
    HttpContext,
    NetworkContext,
    OcspContext,
    ProxyContext,
    X509Context,
)
from evidenceforge.events.dispatcher import EventDispatcher
from evidenceforge.events.observation import ObservationPolicy
from evidenceforge.generation.actions import (
    ProxyTransactionActionBundle,
    ProxyTransactionRequest,
    SshSessionActionBundle,
    SshSessionRequest,
)
from evidenceforge.generation.actions import (
    ssh_session as ssh_session_module,
)
from evidenceforge.generation.activity import ActivityGenerator
from evidenceforge.generation.activity import generator as generator_module
from evidenceforge.generation.activity.dns_registry import resolve_domain_ip
from evidenceforge.generation.activity.timing_profiles import (
    get_timing_window,
    sample_packet_timing_delta,
    sample_timing_delta,
)
from evidenceforge.generation.emitters.ecar import EcarEmitter
from evidenceforge.generation.emitters.zeek_files import _bounded_file_transfer_observation
from evidenceforge.generation.state_manager import StateManager
from evidenceforge.models.scenario import System, User
from evidenceforge.utils.rng import _thread_local


def _reset_thread_rng() -> None:
    """Reset the test thread RNG so identical-input bundle probes are stable."""

    if hasattr(_thread_local, "rng"):
        delattr(_thread_local, "rng")


def _make_activity_gen() -> tuple[ActivityGenerator, list[SecurityEvent]]:
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
        e.event_type == "connection" and e.network is not None
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


def test_closed_connections_do_not_force_tuple_recent_scan_matches():
    """Closed state should not make high-volume DNS source-port scans grow quadratically."""
    gen, _events = _make_activity_gen()
    now = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)
    gen.state_manager.set_current_time(now)
    conn_id = gen.state_manager.open_connection(
        "10.0.0.10",
        53124,
        "10.0.0.1",
        53,
        "udp",
    )
    gen.state_manager.state.open_connections[conn_id].state = "closed"

    assert not gen._connection_tuple_recently_used(
        "10.0.0.10",
        53124,
        "10.0.0.1",
        53,
        "udp",
        now,
    )


def test_explicit_http_upload_bytes_survive_protocol_shaping():
    """Explicit server-egress orig_bytes should not be shrunk by HTTP shaping."""
    gen, events = _make_activity_gen()
    server = System(
        hostname="APP-01",
        ip="10.0.20.10",
        os="Windows Server 2022",
        type="server",
    )
    gen._ip_to_system = {server.ip: server}
    now = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)

    gen.generate_connection(
        src_ip=server.ip,
        dst_ip="198.51.100.25",
        time=now,
        dst_port=80,
        proto="tcp",
        service="http",
        source_system=server,
        hostname="collector.example",
        preserve_dst_ip=True,
        http=HttpContext(
            method="POST",
            host="collector.example",
            uri="/upload",
            request_body_len=1024,
            response_body_len=512,
            status_code=200,
        ),
        orig_bytes=50_000_000,
        resp_bytes=2_048,
        conn_state="SF",
        duration=12.0,
        preserve_explicit_payload=True,
    )

    connection = next(
        event
        for event in events
        if event.event_type == "connection"
        and event.network is not None
        and event.network.dst_ip == "198.51.100.25"
    )
    assert connection.network.orig_bytes >= 50_000_000
    assert connection.network.resp_bytes >= 2_048


def _event_signature(event: SecurityEvent) -> tuple:
    """Return a deterministic signature for SSH bundle evidence events."""

    return (
        event.event_type,
        event.timestamp.isoformat(),
        event.src_host.hostname if event.src_host else "",
        event.dst_host.hostname if event.dst_host else "",
        (
            event.auth.username,
            event.auth.source_ip,
            event.auth.source_port,
            event.auth.logon_id,
            event.auth.logon_type,
        )
        if event.auth
        else None,
        (
            event.network.src_ip,
            event.network.src_port,
            event.network.dst_ip,
            event.network.dst_port,
            event.network.protocol,
            event.network.service,
            event.network.zeek_uid,
            event.network.conn_id,
            event.network.duration,
            event.network.orig_bytes,
            event.network.resp_bytes,
            event.network.orig_pkts,
            event.network.resp_pkts,
            event.network.orig_ip_bytes,
            event.network.resp_ip_bytes,
            event.network.conn_state,
            event.network.history,
            event.network.initiating_pid,
            event.network.responding_pid,
        )
        if event.network
        else None,
        (
            event.process.pid,
            event.process.parent_pid,
            event.process.image,
            event.process.command_line,
            event.process.username,
            event.process.logon_id,
            event.process.start_time.isoformat() if event.process.start_time else "",
        )
        if event.process
        else None,
        (
            event.dns.query,
            event.dns.query_type,
            event.dns.response_ip,
            tuple(event.dns.answers),
            tuple(event.dns.TTLs),
        )
        if event.dns
        else None,
        (
            event.syslog.app_name,
            event.syslog.pid,
            event.syslog.facility,
            event.syslog.severity,
            event.syslog.message,
        )
        if event.syslog
        else None,
        (
            event.edr.object_id,
            event.edr.actor_id,
            event.edr.tid,
        )
        if event.edr
        else None,
    )


def _ssh_transport_event(events: list[SecurityEvent]) -> SecurityEvent:
    """Return the canonical connection event that owns an SSH session transport."""

    return next(
        event
        for event in events
        if event.event_type == "connection"
        and event.network is not None
        and event.network.service == "ssh"
    )


@pytest.fixture
def activity_gen():
    """Create ActivityGenerator with mock dependencies that capture dispatched events."""

    return _make_activity_gen()


def test_direct_http_infrastructure_domain_uses_source_native_user_agent(activity_gen):
    """Direct HTTP auto-generation should honor domain-specific client contracts."""
    gen, events = activity_gen
    source = System(
        hostname="WKS-01",
        ip="10.0.10.50",
        os="Windows 11",
        type="workstation",
    )
    gen._ip_to_system = {source.ip: source}

    gen.generate_connection(
        src_ip=source.ip,
        dst_ip="142.250.80.46",
        time=datetime(2024, 1, 15, 10, 0, tzinfo=UTC),
        dst_port=80,
        proto="tcp",
        service="http",
        duration=1.0,
        orig_bytes=500,
        resp_bytes=2000,
        source_system=source,
        hostname="clients4.google.com",
        conn_state="SF",
    )

    http_event = next(event for event in events if event.http is not None)
    assert http_event.http.host == "clients4.google.com"
    assert http_event.http.user_agent == "GoogleDriveFS/97.0.1.0 Windows"


def test_direct_http_https_first_domain_redirects_instead_of_success_page(activity_gen):
    """Direct HTTP auto-generation should not serve plaintext login pages for HTTPS-first sites."""
    gen, events = activity_gen
    source = System(
        hostname="WKS-01",
        ip="10.0.10.50",
        os="Windows 11",
        type="workstation",
    )
    gen._ip_to_system = {source.ip: source}

    gen.generate_connection(
        src_ip=source.ip,
        dst_ip="142.250.80.46",
        time=datetime(2024, 1, 15, 10, 0, tzinfo=UTC),
        dst_port=80,
        proto="tcp",
        service="http",
        duration=1.0,
        orig_bytes=500,
        resp_bytes=20_000,
        source_system=source,
        hostname="accounts.google.com",
        conn_state="SF",
    )

    http_event = next(event for event in events if event.http is not None)
    assert http_event.http.status_code in {301, 302}
    assert 120 <= http_event.http.response_body_len <= 480


def test_direct_http_public_browser_domain_redirects_by_default(activity_gen):
    """Public browser-like domains should redirect on port 80 without exact policy entries."""
    gen, events = activity_gen
    source = System(
        hostname="WKS-01",
        ip="10.0.10.50",
        os="Windows 11",
        type="workstation",
    )
    gen._ip_to_system = {source.ip: source}

    gen.generate_connection(
        src_ip=source.ip,
        dst_ip="13.107.42.14",
        time=datetime(2024, 1, 15, 10, 0, tzinfo=UTC),
        dst_port=80,
        proto="tcp",
        service="http",
        duration=1.0,
        orig_bytes=500,
        resp_bytes=20_000,
        source_system=source,
        hostname="www.office.com",
        conn_state="SF",
    )

    http_event = next(event for event in events if event.http is not None)
    assert http_event.http.status_code in {301, 302}


def test_direct_http_download_path_replaces_tiny_caller_response_bytes(activity_gen, monkeypatch):
    """HTTP download semantics should not inherit tiny generic flow byte counts."""
    gen, events = activity_gen
    monkeypatch.setattr(generator_module, "_get_rng", lambda: random.Random(0))
    monkeypatch.setattr(generator_module, "_get_http_status", lambda _dst_ip, _uri: (200, "OK"))
    source = System(
        hostname="WKS-01",
        ip="10.0.10.50",
        os="Windows 11",
        type="workstation",
    )
    gen._ip_to_system = {source.ip: source}

    gen.generate_connection(
        src_ip=source.ip,
        dst_ip="104.21.73.124",
        time=datetime(2024, 1, 15, 10, 0, tzinfo=UTC),
        dst_port=80,
        proto="tcp",
        service="http",
        duration=1.0,
        orig_bytes=500,
        resp_bytes=32_000,
        source_system=source,
        hostname="update.dbeaver.io",
        conn_state="SF",
    )

    http_event = next(
        event for event in events if event.http is not None and event.http.uri.endswith(".exe")
    )
    assert http_event.http.resp_mime_types == ["application/x-msdownload"]
    assert http_event.http.response_body_len >= 5_000_000
    assert http_event.network is not None
    assert http_event.network.resp_bytes >= http_event.http.response_body_len


class TestSslContextPopulation:
    """Verify SSL context is attached to connection events for port 443."""

    def test_ssh_session_request_has_stable_action_anchor(self):
        user = User(username="admin", full_name="Admin User", email="admin@example.com")
        target = System(
            hostname="linux01",
            ip="10.0.20.10",
            os="Ubuntu 24.04",
            type="server",
            roles=["web_server"],
        )
        source = System(
            hostname="wks01",
            ip="10.0.10.50",
            os="Windows 11",
            type="workstation",
        )
        request = SshSessionRequest(
            user=user,
            target_system=target,
            time=datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC),
            source_ip=source.ip,
            source_system=source,
            source_port=51111,
            logon_id="0xabc",
        )
        same_request = replace(request)
        bundle = SshSessionActionBundle(request=request, executor=MagicMock())

        assert request.stable_id == same_request.stable_id
        assert bundle.anchor.family == "ssh_session"
        assert bundle.anchor.stable_id == request.stable_id

    def test_ssh_session_request_execution_anchor_uses_resolved_source_port(self):
        user = User(username="admin", full_name="Admin User", email="admin@example.com")
        target = System(
            hostname="linux01",
            ip="10.0.20.10",
            os="Ubuntu 24.04",
            type="server",
            roles=["web_server"],
        )
        request = SshSessionRequest(
            user=user,
            target_system=target,
            time=datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC),
            source_ip="10.0.10.50",
        )

        assert request.execution_stable_id(51111) == request.execution_stable_id(51111)
        assert request.execution_stable_id(51111) != request.execution_stable_id(51112)

    def test_generate_ssh_session_routes_through_action_bundle_adapter(
        self,
        activity_gen,
        monkeypatch,
    ):
        gen, _events = activity_gen
        captured = {}

        def execute_bundle(bundle):
            captured["request"] = bundle.request
            captured["executor"] = bundle.executor
            return "CsshBundleUid"

        monkeypatch.setattr(SshSessionActionBundle, "execute", execute_bundle)
        user = User(username="admin", full_name="Admin User", email="admin@example.com")
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
            source_port=51111,
            logon_id="0xabc",
            auth_method="publickey",
            public_key_type="ED25519",
            public_key_hash="SHA256:test",
            source="unit_test",
        )

        request = captured["request"]
        assert uid == "CsshBundleUid"
        assert isinstance(request, SshSessionRequest)
        assert request.user is user
        assert request.target_system is target
        assert request.source_ip == "10.0.10.50"
        assert request.source_port == 51111
        assert request.logon_id == "0xabc"
        assert request.auth_method == "publickey"
        assert request.public_key_type == "ED25519"
        assert request.public_key_hash == "SHA256:test"
        assert request.source == "unit_test"
        assert captured["executor"] is gen

    def test_ssh_session_bundle_execute_expands_lifecycle_events(self, activity_gen):
        gen, events = activity_gen
        user = User(username="admin", full_name="Admin User", email="admin@example.com")
        target = System(
            hostname="linux01",
            ip="10.0.20.10",
            os="Ubuntu 24.04",
            type="server",
            roles=["web_server"],
        )
        request = SshSessionRequest(
            user=user,
            target_system=target,
            time=datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC),
            source_ip="10.0.10.50",
            source_port=51111,
            logon_id="0xabc",
        )

        uid = SshSessionActionBundle(request=request, executor=gen).execute()

        assert uid
        ssh_event = next(event for event in events if event.event_type == "ssh_session")
        transport_event = _ssh_transport_event(events)
        assert ssh_event.network is None
        assert transport_event.network.src_port == 51111
        assert transport_event.network.responding_pid is not None

        syslog_events = [
            event for event in events if event.event_type == "syslog" and event.syslog is not None
        ]
        connection_event = next(
            event for event in syslog_events if event.syslog.message.startswith("Connection from")
        )
        accepted_event = next(
            event for event in syslog_events if event.syslog.message.startswith("Accepted password")
        )
        pam_event = next(
            event
            for event in syslog_events
            if event.syslog.message.startswith("pam_unix(sshd:session)")
        )
        logind_event = next(
            event for event in syslog_events if event.syslog.message.startswith("New session")
        )

        assert connection_event.timestamp < accepted_event.timestamp
        assert accepted_event.timestamp < pam_event.timestamp
        assert pam_event.timestamp < logind_event.timestamp
        assert transport_event.timestamp < connection_event.timestamp
        assert connection_event.syslog.pid == transport_event.network.responding_pid
        assert accepted_event.syslog.pid == transport_event.network.responding_pid
        assert pam_event.syslog.pid == transport_event.network.responding_pid

    def test_ssh_session_bundle_graph_orders_collapsed_auth_timestamps(
        self,
        activity_gen,
        monkeypatch,
    ):
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

        monkeypatch.setattr(
            ssh_session_module,
            "_ssh_syslog_time",
            lambda base_time, label, milliseconds, *seed_parts, before=False: base_time,
        )

        request = SshSessionRequest(
            user=user,
            target_system=target,
            time=base_time,
            source_ip="10.0.10.50",
            source_port=51111,
            logon_id="0xabc",
        )

        SshSessionActionBundle(request=request, executor=gen).execute()

        syslog_events = [
            event for event in events if event.event_type == "syslog" and event.syslog is not None
        ]
        connection_event = next(
            event for event in syslog_events if event.syslog.message.startswith("Connection from")
        )
        accepted_event = next(
            event for event in syslog_events if event.syslog.message.startswith("Accepted password")
        )
        pam_event = next(
            event
            for event in syslog_events
            if event.syslog.message.startswith("pam_unix(sshd:session)")
        )
        logind_event = next(
            event for event in syslog_events if event.syslog.message.startswith("New session")
        )
        transport_event = _ssh_transport_event(events)

        assert transport_event.timestamp < connection_event.timestamp
        assert connection_event.timestamp < accepted_event.timestamp
        assert accepted_event.timestamp < pam_event.timestamp
        assert pam_event.timestamp < logind_event.timestamp

    def test_ssh_session_auth_graph_accounts_for_ecar_flow_offset(self):
        """SSH syslog auth should wait for source-timed eCAR FLOW visibility."""
        base_time = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)
        user = User(username="admin", full_name="Admin User", email="admin@example.com")
        target = System(
            hostname="linux01",
            ip="10.0.20.10",
            os="Ubuntu 24.04",
            type="server",
            roles=["web_server"],
        )
        request = SshSessionRequest(
            user=user,
            target_system=target,
            time=base_time,
            source_ip="10.0.10.50",
            source_port=51111,
        )
        event = SecurityEvent(
            timestamp=base_time + timedelta(milliseconds=600),
            event_type="connection",
            dst_host=HostContext(
                hostname="linux01",
                ip="10.0.20.10",
                os="Ubuntu 24.04",
                os_category="linux",
                system_type="server",
                fqdn="linux01.example.org",
            ),
            network=NetworkContext(
                src_ip="10.0.10.50",
                src_port=51111,
                dst_ip="10.0.20.10",
                dst_port=22,
                protocol="tcp",
                duration=60.0,
            ),
        )

        resolved = SshSessionActionBundle(
            request=request,
            executor=MagicMock(),
        )._resolve_linux_auth_lifecycle(
            event=event,
            syslog_seed=("linux01", "10.0.10.50", 51111, 4242, base_time.isoformat()),
            conn_delay_ms=35,
            accepted_gap_ms=90,
            pam_gap_ms=45,
            logind_gap_ms=420,
            transport_open_time=base_time,
        )

        assert resolved["accepted"] > EcarEmitter._flow_identity_deadline(event)

    def test_ssh_session_auth_waits_for_jittered_ecar_flow_deadline(self, activity_gen):
        """SSH auth timing should account for connection-start jitter before eCAR FLOW."""
        gen, events = activity_gen
        user = User(username="admin", full_name="Admin User", email="admin@example.com")
        target = System(
            hostname="linux01",
            ip="10.0.20.10",
            os="Ubuntu 24.04",
            type="server",
            roles=["web_server"],
            services=["ssh"],
        )
        base_time = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)

        gen.generate_ssh_session(
            user=user,
            target_system=target,
            time=base_time,
            source_ip="10.0.10.50",
            source_port=51111,
        )

        transport_event = _ssh_transport_event(events)
        accepted_event = next(
            event
            for event in events
            if event.syslog is not None and event.syslog.message.startswith("Accepted password")
        )
        flow_window = get_timing_window(
            "source.ecar_flow",
            default_min_ms=40,
            default_max_ms=300,
            default_position="after",
            default_class="source_latency",
        )

        assert accepted_event.timestamp > transport_event.timestamp + timedelta(
            milliseconds=flow_window.max_ms
        )

    def test_ssh_auth_budgets_messy_collection_ecar_delay(self, activity_gen):
        """SSH acceptance must remain after target eCAR FLOW under delayed collection."""

        gen, events = activity_gen
        gen.dispatcher.observation_policy = ObservationPolicy("messy_collection")
        user = User(username="admin", full_name="Admin User", email="admin@example.com")
        target = System(
            hostname="linux01",
            ip="10.0.20.10",
            os="Ubuntu 24.04",
            type="server",
            roles=["web_server"],
            services=["ssh"],
        )
        base_time = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)

        gen.generate_ssh_session(
            user=user,
            target_system=target,
            time=base_time,
            source_ip="10.0.10.50",
            source_port=51112,
        )

        transport_event = _ssh_transport_event(events)
        accepted_event = next(
            event
            for event in events
            if event.syslog is not None and event.syslog.message.startswith("Accepted password")
        )
        flow_window = get_timing_window(
            "source.ecar_flow",
            default_min_ms=40,
            default_max_ms=300,
            default_position="after",
            default_class="source_latency",
        )
        observation_gap = gen.dispatcher.observation_policy.maximum_delay_difference(
            "ecar",
            "syslog",
        )

        assert (
            accepted_event.timestamp
            > transport_event.timestamp
            + timedelta(milliseconds=flow_window.max_ms)
            + observation_gap
        )

    def test_ssh_connection_syslog_precedes_responder_process_source_time(self, activity_gen):
        gen, events = activity_gen

        user = User(username="admin", full_name="Admin User", email="admin@example.com")
        target = System(
            hostname="linux01",
            ip="10.0.20.10",
            os="Ubuntu 24.04",
            type="server",
            roles=["web_server"],
            services=["ssh"],
        )
        base_time = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)
        source_port = next(
            port
            for port in range(40000, 65000)
            if sample_packet_timing_delta(
                "network.connection_start_jitter",
                seed_parts=(
                    "10.0.10.50",
                    port,
                    target.ip,
                    22,
                    "tcp",
                    "ssh",
                    base_time,
                ),
            )
            > timedelta(milliseconds=650)
        )

        gen.generate_ssh_session(
            user=user,
            target_system=target,
            time=base_time,
            source_ip="10.0.10.50",
            source_port=source_port,
        )

        transport_event = _ssh_transport_event(events)
        connection_event = next(
            event
            for event in events
            if event.syslog is not None and event.syslog.message.startswith("Connection from")
        )
        responder_event = next(
            event
            for event in events
            if event.event_type == "system_process_create"
            and event.process is not None
            and event.process.command_line == "sshd: admin [priv]"
        )
        assert responder_event.source_timing is not None
        ecar_process_times = [
            timestamp
            for key, timestamp in responder_event.source_timing.source_times.items()
            if key.startswith("source.ecar_process_create|")
        ]

        assert ecar_process_times
        assert responder_event.timestamp >= transport_event.timestamp
        assert min(ecar_process_times) > connection_event.timestamp

    def test_ssh_session_bundle_renders_publickey_and_optional_close(self, activity_gen):
        gen, events = activity_gen
        user = User(username="deploy", full_name="Deploy User", email="deploy@example.com")
        target = System(
            hostname="linux01",
            ip="10.0.20.10",
            os="Ubuntu 24.04",
            type="server",
            roles=["web_server"],
        )
        base_time = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)
        request = SshSessionRequest(
            user=user,
            target_system=target,
            time=base_time,
            source_ip="10.0.10.50",
            source_port=51111,
            duration=120.0,
            orig_bytes=12_000,
            resp_bytes=44_000,
            auth_method="publickey",
            public_key_type="ED25519",
            public_key_hash="SHA256:abc",
            emit_session_close=True,
        )

        SshSessionActionBundle(request=request, executor=gen).execute()

        transport_event = _ssh_transport_event(events)
        assert transport_event.network.duration == 120.0
        assert transport_event.network.orig_bytes == 12_000
        assert transport_event.network.resp_bytes == 44_000

        syslog_messages = [event.syslog.message for event in events if event.syslog is not None]
        assert any(
            message.startswith(
                "Accepted publickey for deploy from 10.0.10.50 port 51111 ssh2: ED25519 SHA256:abc"
            )
            for message in syslog_messages
        )
        close_event = next(
            event
            for event in events
            if event.syslog is not None and "session closed for user deploy" in event.syslog.message
        )
        logind_event = next(
            event
            for event in events
            if event.syslog is not None and event.syslog.message.startswith("New session ")
        )
        logind_session_id = int(logind_event.syslog.message.split()[2])
        logind_removed_event = next(
            event
            for event in events
            if event.syslog is not None
            and event.syslog.message == f"Removed session {logind_session_id}."
        )
        transport_close = transport_event.timestamp + timedelta(seconds=120)
        assert close_event.event_type == "logoff"
        assert close_event.auth is not None
        assert close_event.auth.source_ip == "10.0.10.50"
        assert close_event.auth.source_port == 51111
        assert close_event.auth.session_id == logind_session_id
        assert transport_close < close_event.timestamp
        assert close_event.timestamp <= transport_close + timedelta(seconds=3)
        login_event = next(event for event in events if event.event_type == "ssh_session")
        assert login_event.auth is not None
        assert login_event.auth.logon_id
        assert close_event.auth.logon_id == login_event.auth.logon_id
        assert login_event.auth.session_id == logind_session_id
        assert close_event.edr is not None
        assert login_event.edr is not None
        assert close_event.edr.object_id == login_event.edr.object_id
        assert logind_removed_event.syslog.app_name == "systemd-logind"
        assert logind_removed_event.timestamp > close_event.timestamp
        assert logind_removed_event.timestamp <= close_event.timestamp + timedelta(seconds=1)

        terminate_event = next(
            event
            for event in events
            if event.event_type == "process_terminate"
            and event.process is not None
            and event.process.pid == close_event.syslog.pid
        )
        assert terminate_event.timestamp > close_event.timestamp
        assert terminate_event.timestamp <= close_event.timestamp + timedelta(seconds=2)

    def test_ssh_session_bundle_identical_input_regenerates_same_event_signature(self):
        def run_bundle_once() -> list[tuple]:
            _reset_thread_rng()
            gen, events = _make_activity_gen()
            user = User(username="admin", full_name="Admin User", email="admin@example.com")
            target = System(
                hostname="linux01",
                ip="10.0.20.10",
                os="Ubuntu 24.04",
                type="server",
                roles=["web_server"],
            )
            base_time = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)
            gen.state_manager.set_current_time(base_time - timedelta(seconds=5))
            sshd_pid = gen.state_manager.create_process(
                system=target.hostname,
                parent_pid=0,
                image="/usr/sbin/sshd",
                command_line="sshd: admin [priv]",
                username="admin",
                integrity_level="Medium",
            )
            gen.state_manager.set_current_time(base_time)

            request = SshSessionRequest(
                user=user,
                target_system=target,
                time=base_time,
                source_ip="10.0.10.50",
                source_port=51111,
                sshd_pid=sshd_pid,
                logon_id="0xabc",
                session_obj_id="session-obj-stable",
            )

            SshSessionActionBundle(request=request, executor=gen).execute()

            return [
                _event_signature(event)
                for event in events
                if event.event_type in {"dns", "ssh_session", "syslog"}
            ]

        assert run_bundle_once() == run_bundle_once()

    def test_ssh_session_bundle_records_session_lifecycle_bounds(self, activity_gen):
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
            start_time=base_time,
        )

        request = SshSessionRequest(
            user=user,
            target_system=target,
            time=base_time,
            source_ip="10.0.10.50",
            source_port=51111,
            logon_id=logon_id,
            min_duration=300.0,
        )

        SshSessionActionBundle(request=request, executor=gen).execute()

        ssh_event = next(event for event in events if event.event_type == "ssh_session")
        transport_event = _ssh_transport_event(events)
        assert ssh_event.network is None
        session = gen.state_manager.get_session(logon_id)
        assert session is not None
        close_time = transport_event.timestamp + timedelta(seconds=transport_event.network.duration)
        assert session.network_close_time == close_time
        assert session.transport_pid == transport_event.network.responding_pid
        assert session.source_ready_time is not None
        assert session.source_ready_time < close_time
        tuple_ready_time = gen.ssh_session_ready_time_for_tuple(
            "10.0.10.50",
            51111,
            target.ip,
        )
        assert tuple_ready_time == session.source_ready_time

        responder = gen.state_manager.get_process(target.hostname, session.transport_pid)
        assert responder is not None
        assert responder.image == "/usr/sbin/sshd"

        syslog_events = [
            event for event in events if event.event_type == "syslog" and event.syslog is not None
        ]
        connection_event = next(
            event for event in syslog_events if event.syslog.message.startswith("Connection from")
        )
        accepted_event = next(
            event for event in syslog_events if event.syslog.message.startswith("Accepted password")
        )
        pam_event = next(
            event
            for event in syslog_events
            if event.syslog.message.startswith("pam_unix(sshd:session)")
        )
        logind_event = next(
            event for event in syslog_events if event.syslog.message.startswith("New session")
        )

        assert connection_event.timestamp < accepted_event.timestamp
        assert accepted_event.timestamp < pam_event.timestamp
        assert pam_event.timestamp < logind_event.timestamp
        assert pam_event.timestamp < session.source_ready_time
        assert all(event.timestamp < close_time for event in syslog_events)

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

    def test_explicit_proxy_http_origin_leg_uses_corrected_domain_user_agent(self, activity_gen):
        """Proxy egress HTTP should not keep stale browser UAs after domain correction."""
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
        proxy_context = ProxyContext(
            client_ip=source.ip,
            method="POST",
            url="http://settings-win.data.microsoft.com/settings/v2.0/global",
            host="settings-win.data.microsoft.com",
            status_code=200,
            tunnel_status_code=200,
            sc_bytes=1800,
            cs_bytes=800,
            time_taken=450,
            user_agent="Windows-Device-Management/10.0",
            content_type="application/json",
            cache_result="MISS",
            referrer="",
            proxy_fqdn=gen._proxy_fqdn(proxy),
        )

        gen.generate_connection(
            src_ip=source.ip,
            dst_ip="13.107.4.50",
            time=datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC),
            dst_port=80,
            proto="tcp",
            service="http",
            duration=3.0,
            orig_bytes=600,
            resp_bytes=1600,
            conn_state="SF",
            source_system=source,
            hostname="settings-win.data.microsoft.com",
            proxy=proxy_context,
            http=HttpContext(
                method="POST",
                host="settings-win.data.microsoft.com",
                uri="/settings/v2.0/global",
                version="1.1",
                user_agent=(
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                    "AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36"
                ),
                request_body_len=300,
                response_body_len=1600,
                status_code=200,
                status_msg="OK",
                resp_mime_types=["application/json"],
            ),
        )

        egress = next(
            event
            for event in events
            if event.http is not None and event.network and event.network.src_ip == proxy.ip
        )
        assert egress.http.user_agent == "Windows-Device-Management/10.0"

    def test_explicit_proxy_https_cacheable_request_still_emits_origin_leg(
        self, activity_gen, monkeypatch
    ):
        """A successful CONNECT tunnel with bytes must not terminalize as a cache HIT."""

        class ZeroRollRandom(random.Random):
            def random(self) -> float:
                return 0.0

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
        monkeypatch.setattr(generator_module, "_get_rng", lambda: ZeroRollRandom(7))
        monkeypatch.setattr(
            generator_module,
            "_proxy_request_allows_cache_hit",
            lambda **_kwargs: True,
        )

        gen.generate_connection(
            src_ip=source.ip,
            dst_ip="40.126.28.19",
            time=datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC),
            dst_port=443,
            proto="tcp",
            service="ssl",
            duration=1.0,
            orig_bytes=620,
            resp_bytes=120_000,
            conn_state="SF",
            source_system=source,
            hostname="graph.microsoft.com",
            http=HttpContext(
                method="GET",
                host="graph.microsoft.com",
                uri="/v1.0/me",
                version="1.1",
                user_agent="Mozilla/5.0",
                request_body_len=0,
                response_body_len=120_000,
                status_code=200,
                status_msg="OK",
                resp_mime_types=["application/json"],
            ),
        )

        client = next(
            event
            for event in events
            if event.proxy is not None
            and event.network is not None
            and event.network.src_ip == source.ip
            and event.network.dst_ip == proxy.ip
        )
        egress = next(
            event
            for event in events
            if event.network is not None
            and event.network.src_ip == proxy.ip
            and event.network.dst_port == 443
        )

        assert client.proxy.cache_result == "MISS"
        assert client.http is not None
        assert client.http.method == "CONNECT"
        assert egress.network.conn_state == "SF"
        assert egress.http is not None
        assert egress.http.host == "graph.microsoft.com"
        assert egress.network.resp_bytes >= 120_000

    def test_proxy_transaction_request_has_stable_action_anchor(self):
        proxy = System(
            hostname="PROXY-01",
            ip="10.0.20.10",
            os="Ubuntu 22.04",
            type="server",
            roles=["forward_proxy"],
        )
        request = ProxyTransactionRequest(
            src_ip="10.0.10.50",
            dst_ip="142.250.80.46",
            time=datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC),
            dst_port=80,
            proto="tcp",
            service="http",
            duration=1.0,
            orig_bytes=180,
            resp_bytes=4000,
            src_port=52800,
            pid=-1,
            source_system=None,
            conn_state="SF",
            dns=None,
            ids=None,
            http=None,
            file_transfer=None,
            ocsp=None,
            proxy=None,
            firewall=None,
            hostname="www.google.com",
            process_image=None,
            proxy_chain=[proxy],
            preserve_explicit_proxy_dst_ip=False,
            caller_provided_conn_state=True,
            ad_domain="corp.local",
        )
        same_request = replace(request)
        bundle = ProxyTransactionActionBundle(request=request, executor=MagicMock())

        assert request.stable_id == same_request.stable_id
        assert bundle.anchor.family == "proxy_transaction"
        assert bundle.anchor.stable_id == request.stable_id

    def test_generate_connection_routes_explicit_proxy_through_transaction_bundle(
        self,
        activity_gen,
        monkeypatch,
    ):
        gen, _events = activity_gen
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
        captured = {}

        def execute_bundle(bundle):
            captured["request"] = bundle.request
            captured["executor"] = bundle.executor
            return "CproxyBundleUid"

        monkeypatch.setattr(ProxyTransactionActionBundle, "execute", execute_bundle)

        uid = gen.generate_connection(
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
        )

        request = captured["request"]
        assert uid == "CproxyBundleUid"
        assert isinstance(request, ProxyTransactionRequest)
        assert request.src_ip == source.ip
        assert request.dst_ip == "142.250.80.46"
        assert request.dst_port == 80
        assert request.service == "http"
        assert request.proxy_chain == [proxy]
        assert captured["executor"] is gen

    def test_explicit_proxy_egress_waits_for_client_proxy_request_graph(
        self,
        activity_gen,
        monkeypatch,
    ):
        """Origin egress should follow the canonical proxy request and DNS phases."""
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
        base_time = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)
        egress_ip = resolve_domain_ip("www.google.com", src_host=proxy.hostname)
        proxy_context = ProxyContext(
            client_ip=source.ip,
            method="GET",
            url="http://www.google.com/search?q=vpn",
            host="www.google.com",
            status_code=200,
            tunnel_status_code=200,
            sc_bytes=4250,
            cs_bytes=620,
            time_taken=1400,
            user_agent="Mozilla/5.0",
            content_type="text/html",
            cache_result="MISS",
            proxy_fqdn=gen._proxy_fqdn(proxy),
        )

        def skew_client_observation(
            observed_base_time,
            observed_src_ip,
            _observed_src_port,
            observed_dst_ip,
            _observed_dst_port,
            _observed_proto,
            _observed_service,
        ):
            if observed_src_ip == source.ip and observed_dst_ip == proxy.ip:
                return base_time - timedelta(seconds=5)
            return observed_base_time

        monkeypatch.setattr(
            generator_module, "_zeek_conn_observation_time", skew_client_observation
        )
        dns_requests = []
        original_emit_dns_lookup = gen._emit_dns_lookup

        def capture_emit_dns_lookup(
            src_ip,
            dst_ip,
            time,
            *,
            hostname=None,
            force_address=False,
            bypass_cache=False,
            source_system=None,
            source_pid=-1,
            source_process_image="",
        ):
            dns_requests.append(
                {
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "hostname": hostname,
                    "force_address": force_address,
                    "bypass_cache": bypass_cache,
                    "source_system": source_system,
                    "source_pid": source_pid,
                    "source_process_image": source_process_image,
                }
            )
            return original_emit_dns_lookup(
                src_ip,
                dst_ip,
                time,
                hostname=hostname,
                force_address=force_address,
                bypass_cache=bypass_cache,
                source_system=source_system,
                source_pid=source_pid,
                source_process_image=source_process_image,
            )

        monkeypatch.setattr(gen, "_emit_dns_lookup", capture_emit_dns_lookup)

        gen.generate_connection(
            src_ip=source.ip,
            dst_ip="142.250.80.46",
            time=base_time,
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

        client = next(
            event
            for event in events
            if event.network
            and event.network.src_ip == source.ip
            and event.network.dst_ip == proxy.ip
        )
        egress = next(
            event
            for event in events
            if event.network
            and event.network.src_ip == proxy.ip
            and event.network.dst_ip == egress_ip
        )
        dns_events = [
            event
            for event in events
            if event.dns
            and event.network
            and event.network.src_ip == proxy.ip
            and event.dns.query == "www.google.com"
        ]
        assert client.proxy is not None
        transaction = client.proxy.transaction
        assert transaction is not None
        assert client.timestamp == transaction.client_connect_at == base_time
        assert client.timestamp < transaction.request_at
        assert egress.timestamp == transaction.origin_connect_at
        assert transaction.resolver_mode == "resolver_cache_hit"
        assert transaction.dns_query_at is None
        assert transaction.dns_response_at is None
        assert not dns_events
        assert not dns_requests

    def test_explicit_proxy_download_keeps_file_identity_and_order(self, activity_gen):
        """Proxy client and origin legs should preserve object identity and file timing."""
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
        body_len = 97_117_831
        host = "dellupdater.dell.com"
        uri = "/FOLDER16e0077c/M/335e80f3/Dell-Command-Update.exe"

        gen.generate_connection(
            src_ip=source.ip,
            dst_ip="203.0.113.25",
            time=datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC),
            dst_port=80,
            proto="tcp",
            service="http",
            duration=0.5,
            orig_bytes=220,
            resp_bytes=body_len,
            conn_state="SF",
            source_system=source,
            hostname=host,
            http=HttpContext(
                method="GET",
                host=host,
                uri=uri,
                response_body_len=body_len,
                status_code=200,
                status_msg="OK",
                resp_mime_types=["application/x-msdownload"],
            ),
        )

        client = next(
            event
            for event in events
            if event.network
            and event.network.src_ip == source.ip
            and event.network.dst_ip == proxy.ip
        )
        egress = next(
            event
            for event in events
            if event.network and event.network.src_ip == proxy.ip and event.http is not None
        )

        assert client.file_transfer is not None
        assert egress.file_transfer is not None
        assert client.file_transfer.fuid != egress.file_transfer.fuid
        assert client.file_transfer.sha1 == egress.file_transfer.sha1
        assert client.http is not None
        assert egress.http is not None
        assert client.http.uri == f"http://{host}{uri}"
        assert egress.http.uri == uri
        assert client.http.resp_fuids == [client.file_transfer.fuid]
        assert egress.http.resp_fuids == [egress.file_transfer.fuid]

        client_file_ts, client_file_duration = _bounded_file_transfer_observation(client)
        egress_file_ts, egress_file_duration = _bounded_file_transfer_observation(egress)
        assert client_file_ts >= egress_file_ts
        assert client_file_ts + timedelta(seconds=client_file_duration) >= (
            egress_file_ts + timedelta(seconds=egress_file_duration)
        )

    def test_explicit_proxy_installer_template_uses_download_scale_body_and_files(
        self,
        activity_gen,
    ):
        """Software-update installer paths should not render as tiny full 200 bodies."""
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

        gen.generate_connection(
            src_ip=source.ip,
            dst_ip="203.0.113.25",
            time=datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC),
            dst_port=80,
            proto="tcp",
            service="http",
            duration=0.25,
            orig_bytes=220,
            resp_bytes=23_000,
            conn_state="SF",
            source_system=source,
            hostname="dl.duosecurity.com",
        )

        client = next(
            event
            for event in events
            if event.network
            and event.network.src_ip == source.ip
            and event.network.dst_ip == proxy.ip
            and event.http is not None
        )
        egress = next(
            event
            for event in events
            if event.network and event.network.src_ip == proxy.ip and event.http is not None
        )

        for event in (client, egress):
            assert event.http is not None
            assert event.network is not None
            assert event.http.uri.endswith(".msi")
            assert event.http.response_body_len >= 5_000_000
            assert event.http.resp_mime_types == ["application/x-msi"]
            assert event.http.resp_fuids
            assert event.file_transfer is not None
            assert event.file_transfer.mime_type == "application/x-msi"
            assert event.file_transfer.total_bytes == event.http.response_body_len
            assert event.network.resp_bytes >= event.http.response_body_len
            assert event.pe is None

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

    def test_ssh_session_keeps_canonical_uid_when_network_not_visible(self, activity_gen):
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

        assert uid
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

    def test_ssh_session_sets_destination_side_transport_pid(self, activity_gen):
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
            source_port=51111,
        )

        transport_event = _ssh_transport_event(events)
        transport_events = [
            event
            for event in events
            if event.event_type == "system_process_create"
            and event.process is not None
            and event.process.command_line == "sshd: admin [priv]"
        ]
        assert transport_events
        assert transport_event.network.responding_pid == transport_events[0].process.pid
        syslog_pids = {
            event.syslog.pid
            for event in events
            if event.syslog is not None and event.syslog.app_name == "sshd"
        }
        assert syslog_pids == {transport_event.network.responding_pid}

    def test_ssh_session_linux_source_uses_client_process_not_local_sshd(self, activity_gen):
        gen, events = activity_gen

        user = User(username="admin", full_name="Admin User", email="admin@example.com")
        source = System(
            hostname="admin01",
            ip="10.0.10.50",
            os="Ubuntu 24.04",
            type="server",
            assigned_user="admin",
            services=["ssh"],
        )
        target = System(
            hostname="linux01",
            ip="10.0.20.10",
            os="Ubuntu 24.04",
            type="server",
            roles=["web_server"],
            services=["ssh"],
        )
        gen._ip_to_system = {source.ip: source, target.ip: target}
        systemd_pid = gen.state_manager.create_process(
            source.hostname,
            0,
            "/usr/lib/systemd/systemd",
            "/usr/lib/systemd/systemd",
            "root",
            "System",
        )
        source_sshd_pid = gen.state_manager.create_process(
            source.hostname,
            systemd_pid,
            "/usr/sbin/sshd",
            "/usr/sbin/sshd -D",
            "root",
            "System",
        )
        gen._system_pids = {source.hostname: {"systemd": systemd_pid, "sshd": source_sshd_pid}}

        gen.generate_ssh_session(
            user=user,
            target_system=target,
            time=datetime(2024, 1, 15, 10, 0, 30, tzinfo=UTC),
            source_ip=source.ip,
            source_system=source,
            source_port=51111,
        )

        transport_event = _ssh_transport_event(events)
        assert transport_event.network.initiating_pid > 0
        assert transport_event.network.initiating_pid != source_sshd_pid
        assert transport_event.process is not None
        assert transport_event.process.image == "/usr/bin/ssh"
        assert transport_event.process.command_line.startswith("ssh ")
        assert "admin@" in transport_event.process.command_line or "-l admin" in (
            transport_event.process.command_line
        )

    def test_generic_ssh_connection_sets_destination_side_transport_pid(self, activity_gen):
        gen, events = activity_gen

        target = System(
            hostname="linux01",
            ip="10.0.20.10",
            os="Ubuntu 24.04",
            type="server",
            roles=["web_server"],
            services=["ssh"],
        )
        gen._ip_to_system = {target.ip: target}

        gen.generate_connection(
            src_ip="10.0.10.50",
            dst_ip=target.ip,
            time=datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC),
            dst_port=22,
            proto="tcp",
            service="ssh",
            duration=8.0,
            orig_bytes=1200,
            resp_bytes=2400,
            src_port=51111,
            conn_state="SF",
        )

        conn_event = next(event for event in events if event.event_type == "connection")
        transport_events = [
            event
            for event in events
            if event.event_type == "system_process_create"
            and event.process is not None
            and event.process.command_line == "sshd: unknown [priv]"
        ]
        assert transport_events
        assert conn_event.network.responding_pid == transport_events[0].process.pid

    def test_generic_ssh_connection_emits_preauth_failure_syslog(self, activity_gen):
        """Generic port-22 responder children should have source-native auth companions."""
        gen, events = activity_gen

        target = System(
            hostname="linux01",
            ip="10.0.20.10",
            os="Ubuntu 24.04",
            type="server",
            roles=["web_server"],
            services=["ssh"],
        )
        gen._ip_to_system = {target.ip: target}

        gen.generate_connection(
            src_ip="10.0.10.50",
            dst_ip=target.ip,
            time=datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC),
            dst_port=22,
            proto="tcp",
            service="ssh",
            duration=8.0,
            orig_bytes=1200,
            resp_bytes=2400,
            src_port=51111,
            conn_state="SF",
        )

        conn_event = next(event for event in events if event.event_type == "connection")
        syslog_events = [
            event
            for event in events
            if event.event_type == "syslog"
            and event.syslog is not None
            and event.syslog.app_name == "sshd"
        ]
        messages = [event.syslog.message for event in syslog_events]
        assert "Connection from 10.0.10.50 port 51111 on 10.0.20.10 port 22" in messages
        assert "Invalid user unknown from 10.0.10.50 port 51111" in messages
        assert (
            "Failed password for invalid user unknown from 10.0.10.50 port 51111 ssh2" in messages
        )
        assert (
            "Connection closed by invalid user unknown 10.0.10.50 port 51111 [preauth]" in messages
        )
        assert {event.syslog.pid for event in syslog_events} == {conn_event.network.responding_pid}
        assert all(conn_event.timestamp < event.timestamp for event in syslog_events)
        connection_syslog_event = next(
            event for event in syslog_events if event.syslog.message.startswith("Connection from")
        )
        responder_event = next(
            event
            for event in events
            if event.event_type == "system_process_create"
            and event.process is not None
            and event.process.pid == conn_event.network.responding_pid
        )
        assert responder_event.source_timing is not None
        ecar_process_times = [
            timestamp
            for key, timestamp in responder_event.source_timing.source_times.items()
            if key.startswith("source.ecar_process_create|")
        ]
        assert ecar_process_times
        assert min(ecar_process_times) > connection_syslog_event.timestamp

    def test_port_22_connection_without_service_sets_destination_side_transport_pid(
        self, activity_gen
    ):
        gen, events = activity_gen

        target = System(
            hostname="linux01",
            ip="10.0.20.10",
            os="Ubuntu 24.04",
            type="server",
            roles=["web_server"],
            services=["ssh"],
        )
        gen._ip_to_system = {target.ip: target}

        gen.generate_connection(
            src_ip="10.0.10.50",
            dst_ip=target.ip,
            time=datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC),
            dst_port=22,
            proto="tcp",
            duration=0.4,
            orig_bytes=120,
            resp_bytes=200,
            src_port=51111,
            conn_state="SF",
        )

        conn_event = next(event for event in events if event.event_type == "connection")
        transport_events = [
            event
            for event in events
            if event.event_type == "system_process_create"
            and event.process is not None
            and event.process.command_line == "sshd: unknown [priv]"
        ]
        assert transport_events
        assert conn_event.network.responding_pid == transport_events[0].process.pid

    def test_generic_linux_outbound_ssh_does_not_use_source_sshd_pid(self, activity_gen):
        gen, events = activity_gen

        source = System(
            hostname="admin01",
            ip="10.0.10.50",
            os="Ubuntu 24.04",
            type="server",
            services=["ssh"],
        )
        target = System(
            hostname="linux01",
            ip="10.0.20.10",
            os="Ubuntu 24.04",
            type="server",
            roles=["web_server"],
            services=["ssh"],
        )
        gen._ip_to_system = {source.ip: source, target.ip: target}
        systemd_pid = gen.state_manager.create_process(
            source.hostname,
            0,
            "/usr/lib/systemd/systemd",
            "/usr/lib/systemd/systemd",
            "root",
            "System",
        )
        source_sshd_pid = gen.state_manager.create_process(
            source.hostname,
            systemd_pid,
            "/usr/sbin/sshd",
            "/usr/sbin/sshd -D",
            "root",
            "System",
        )
        gen._system_pids = {source.hostname: {"systemd": systemd_pid, "sshd": source_sshd_pid}}

        gen.generate_connection(
            src_ip=source.ip,
            dst_ip=target.ip,
            time=datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC),
            dst_port=22,
            proto="tcp",
            service="ssh",
            duration=8.0,
            orig_bytes=1200,
            resp_bytes=2400,
            src_port=51111,
            source_system=source,
            conn_state="SF",
        )

        conn_event = next(event for event in events if event.event_type == "connection")
        assert conn_event.network.initiating_pid != source_sshd_pid
        assert conn_event.process is None
        assert conn_event.network.responding_pid > 0

    def test_ssh_session_avoids_existing_destination_endpoint_tuple(self, activity_gen):
        gen, events = activity_gen

        user = User(username="admin", full_name="Admin User", email="admin@example.com")
        target = System(
            hostname="linux01",
            ip="10.0.20.10",
            os="Ubuntu 24.04",
            type="server",
            roles=["web_server"],
            services=["ssh"],
        )
        gen._ip_to_system = {target.ip: target}

        gen.generate_connection(
            src_ip="10.0.10.50",
            dst_ip=target.ip,
            time=datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC),
            dst_port=22,
            proto="tcp",
            service="ssh",
            duration=4.0,
            orig_bytes=1200,
            resp_bytes=2400,
            src_port=51111,
            conn_state="SF",
        )
        first_conn = next(event for event in events if event.event_type == "connection")

        gen.generate_ssh_session(
            user=user,
            target_system=target,
            time=datetime(2024, 1, 15, 10, 0, 1, tzinfo=UTC),
            source_ip="10.0.10.50",
            source_port=51111,
        )

        ssh_transport = [event for event in events if event.event_type == "connection"][-1]
        assert ssh_transport.network.src_port != first_conn.network.src_port
        assert ssh_transport.network.responding_pid != first_conn.network.responding_pid
        session_syslog_pids = {
            event.syslog.pid
            for event in events
            if event.syslog is not None
            and event.syslog.app_name == "sshd"
            and (
                event.syslog.message.startswith("Accepted ")
                or event.syslog.message.startswith("pam_unix(sshd:session)")
            )
        }
        preauth_syslog_pids = {
            event.syslog.pid
            for event in events
            if event.syslog is not None
            and event.syslog.app_name == "sshd"
            and "invalid user unknown" in event.syslog.message
        }
        assert session_syslog_pids == {ssh_transport.network.responding_pid}
        assert preauth_syslog_pids == {first_conn.network.responding_pid}

    def test_sshd_syslog_reuses_existing_destination_responder_pid_for_tuple(self, activity_gen):
        gen, events = activity_gen

        target = System(
            hostname="linux01",
            ip="10.0.20.10",
            os="Ubuntu 24.04",
            type="server",
            roles=["web_server"],
            services=["ssh"],
        )
        gen._ip_to_system = {target.ip: target}

        gen.generate_connection(
            src_ip="10.0.10.50",
            dst_ip=target.ip,
            time=datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC),
            dst_port=22,
            proto="tcp",
            service="ssh",
            duration=4.0,
            orig_bytes=1200,
            resp_bytes=2400,
            src_port=51111,
            conn_state="SF",
        )
        first_conn = next(event for event in events if event.event_type == "connection")

        gen.generate_syslog_event(
            system=target,
            time=datetime(2024, 1, 15, 10, 0, 1, tzinfo=UTC),
            app_name="sshd",
            message="Connection from 10.0.10.50 port 51111 on 10.0.20.10 port 22",
            pid=6505,
            facility=10,
        )
        gen.generate_syslog_event(
            system=target,
            time=datetime(2024, 1, 15, 10, 0, 2, tzinfo=UTC),
            app_name="sshd",
            message="Accepted publickey for admin from 10.0.10.50 port 51111 ssh2",
            pid=6505,
            facility=10,
        )
        gen.generate_syslog_event(
            system=target,
            time=datetime(2024, 1, 15, 10, 0, 3, tzinfo=UTC),
            app_name="sshd",
            message="pam_unix(sshd:session): session opened for user admin(uid=1001) by (uid=0)",
            pid=6505,
            facility=10,
        )

        syslog_pids = [
            event.syslog.pid
            for event in events
            if event.syslog is not None and event.syslog.app_name == "sshd"
        ]
        assert syslog_pids
        assert set(syslog_pids) == {first_conn.network.responding_pid}
        messages = [
            event.syslog.message
            for event in events
            if event.syslog is not None and event.syslog.app_name == "sshd"
        ]
        assert "Accepted publickey for admin from 10.0.10.50 port 51111 ssh2" in messages
        assert (
            "pam_unix(sshd:session): session opened for user admin(uid=1001) by (uid=0)" in messages
        )

    def test_reserved_ssh_source_port_blocks_generic_tuple_reuse(
        self,
        activity_gen,
        monkeypatch,
    ):
        gen, events = activity_gen

        target = System(
            hostname="linux01",
            ip="10.0.20.10",
            os="Ubuntu 24.04",
            type="server",
            roles=["web_server"],
            services=["ssh"],
        )
        gen._ip_to_system = {target.ip: target}
        base_time = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)

        reserved = gen.reserve_ssh_source_port(
            "10.0.10.50",
            target.ip,
            51111,
            random.Random(7),
            "linux",
            time=base_time,
        )

        assert reserved == 51111

        candidate_ports = iter([51111, 51112])
        monkeypatch.setattr(
            generator_module,
            "_ephemeral_port",
            lambda rng, os_category: next(candidate_ports),
        )

        gen.generate_connection(
            src_ip="10.0.10.50",
            dst_ip=target.ip,
            time=base_time + timedelta(seconds=1),
            dst_port=22,
            proto="tcp",
            service="ssh",
            duration=4.0,
            orig_bytes=1200,
            resp_bytes=2400,
            conn_state="SF",
        )

        conn_event = next(event for event in events if event.event_type == "connection")
        assert conn_event.network.src_port == 51112

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
        )

        transport_event = _ssh_transport_event(events)
        syslog_events = [
            event
            for event in events
            if event.syslog is not None
            and event.syslog.pid == transport_event.network.responding_pid
        ]
        messages = [event.syslog.message for event in syslog_events]
        times = [event.timestamp for event in syslog_events]
        assert messages == [
            "Connection from 10.0.10.50 port 51111 on 10.0.20.10 port 22",
            "Accepted password for admin from 10.0.10.50 port 51111 ssh2",
            "pam_unix(sshd:session): session opened for user admin(uid=1001) by (uid=0)",
        ]
        assert base_time < transport_event.timestamp < times[0] < times[1] < times[2]
        assert (
            timedelta(milliseconds=30)
            <= times[0] - transport_event.timestamp
            <= timedelta(milliseconds=170)
        )
        assert times[1] > EcarEmitter._flow_identity_deadline(transport_event)
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
        assert ssh_event.edr is not None
        assert ssh_event.edr.object_id
        accepted_event = next(
            event
            for event in events
            if event.syslog is not None and event.syslog.message.startswith("Accepted password")
        )
        pam_event = next(
            event
            for event in events
            if event.syslog is not None
            and event.syslog.message.startswith("pam_unix(sshd:session)")
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
                ssh_event.auth.logon_id if ssh_event.auth else "",
                10,
                ssh_event.edr.object_id,
                ssh_event.timestamp,
            ),
        )

        assert ecar_login_time > accepted_event.timestamp
        assert ecar_login_time > pam_event.timestamp
        assert ecar_login_time > pam_event.timestamp + timedelta(milliseconds=250)
        gen.dispatcher.source_timing_planner.plan_event(ssh_event, format_name="ecar")
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

        transport_event = _ssh_transport_event(events)
        session = gen.state_manager.get_session(logon_id)
        assert session is not None
        assert session.network_close_time == transport_event.timestamp + timedelta(
            seconds=transport_event.network.duration
        )

    def test_ssh_session_records_logind_session_id_for_later_logoff(self, activity_gen):
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
        logind_event = next(
            event
            for event in events
            if event.syslog is not None and event.syslog.message.startswith("New session ")
        )
        logind_session_id = int(logind_event.syslog.message.split()[2])

        session = gen.state_manager.get_session(logon_id)
        assert session is not None
        assert session.session_id == logind_session_id

        gen.generate_logoff(
            user,
            target,
            base_time + timedelta(minutes=5),
            logon_id,
            logon_type=10,
        )

        login_event = next(event for event in events if event.event_type == "ssh_session")
        logoff_event = next(event for event in events if event.event_type == "logoff")
        assert login_event.auth is not None
        assert logoff_event.auth is not None
        assert logoff_event.auth.logon_id == login_event.auth.logon_id == logon_id
        assert logoff_event.auth.session_id == login_event.auth.session_id == logind_session_id
        assert logoff_event.auth.source_ip == login_event.auth.source_ip == "10.0.10.50"
        assert logoff_event.auth.source_port == login_event.auth.source_port == 51111

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

        transport_event = _ssh_transport_event(events)
        session = gen.state_manager.get_session(logon_id)
        assert session is not None
        assert session.network_close_time == transport_event.timestamp + timedelta(
            seconds=transport_event.network.duration
        )

    def test_ssh_logoff_after_transport_close_is_bounded_to_close(self, activity_gen):
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
            duration=120.0,
        )
        transport_event = _ssh_transport_event(events)
        transport_close = transport_event.timestamp + timedelta(
            seconds=transport_event.network.duration
        )
        expected_delta = sample_timing_delta(
            "windows.logoff_after_last_activity",
            seed_parts=(target.hostname, logon_id, transport_close),
        )

        gen.generate_logoff(
            user=user,
            system=target,
            time=base_time + timedelta(hours=4),
            logon_id=logon_id,
            logon_type=10,
        )

        logoff_event = next(event for event in events if event.event_type == "logoff")
        assert logoff_event.timestamp == transport_close + expected_delta
        assert logoff_event.auth.source_ip == "10.0.10.50"
        assert logoff_event.auth.source_port == 51111

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

        transport_event = _ssh_transport_event(events)
        assert transport_event.network.duration >= 7200.0

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
            if event.ssl.version == "TLSv12":
                assert event.ssl.ssl_history == "CSIFIFD"
            else:
                assert event.ssl.ssl_history == "CSOFFD"

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

    def test_client_first_reset_response_keeps_originator_payload(self, activity_gen, monkeypatch):
        """SMB responder payload must not appear before any originator application payload."""
        gen, events = activity_gen
        monkeypatch.setattr(generator_module, "_TCP_CONN_ENTRIES", [("RSTR", 1, "ShAdr")])
        monkeypatch.setattr(generator_module, "_TCP_CONN_WEIGHTS", [1])

        gen.generate_connection(
            src_ip="10.0.10.50",
            dst_ip="10.0.20.10",
            time=datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC),
            dst_port=445,
            proto="tcp",
            service="smb",
            duration=1.0,
            orig_bytes=0,
            resp_bytes=1600,
        )

        net = events[-1].network
        assert net.conn_state == "RSTR"
        assert net.resp_bytes > 0
        assert net.orig_bytes > 0
        assert "D" in net.history
        assert net.history.index("D") < net.history.index("d")

    def test_client_first_payload_order_uses_port_when_service_unknown(
        self, activity_gen, monkeypatch
    ):
        """Port-only database flows should follow the same client-before-server invariant."""
        gen, events = activity_gen
        monkeypatch.setattr(generator_module, "_TCP_CONN_ENTRIES", [("RSTR", 1, "ShAdr")])
        monkeypatch.setattr(generator_module, "_TCP_CONN_WEIGHTS", [1])

        gen.generate_connection(
            src_ip="10.0.10.50",
            dst_ip="10.0.20.10",
            time=datetime(2024, 1, 15, 10, 0, 1, tzinfo=UTC),
            dst_port=1433,
            proto="tcp",
            service="",
            duration=1.0,
            orig_bytes=0,
            resp_bytes=900,
        )

        net = events[-1].network
        assert net.conn_state == "RSTR"
        assert net.service == ""
        assert net.resp_bytes > 0
        assert net.orig_bytes > 0
        assert "D" in net.history
        assert net.history.index("D") < net.history.index("d")

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

    def test_tcp_payload_segment_count_handles_huge_payload_without_float_overflow(self):
        """Huge payload sizes should use integer-only ceiling division."""
        huge_payload = 10**400
        expected_segments = (huge_payload + generator_module._TCP_MSS_BYTES - 1) // (
            generator_module._TCP_MSS_BYTES
        )

        segments = generator_module._tcp_payload_segment_count(huge_payload)

        assert segments == expected_segments

    def test_tcp_ack_packet_floor_handles_huge_payload_without_float_overflow(self, monkeypatch):
        """ACK packet floor should stay integer-only for huge payload segment counts."""
        rng = random.Random(7)
        monkeypatch.setattr(rng, "choices", lambda *_args, **_kwargs: [2])
        huge_payload = 10**400
        expected_segments = (huge_payload + generator_module._TCP_MSS_BYTES - 1) // (
            generator_module._TCP_MSS_BYTES
        )
        expected_floor = max(16, (expected_segments + 1) // 2)

        ack_floor = generator_module._tcp_ack_packet_floor(huge_payload, rng)

        assert ack_floor == expected_floor

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

    def test_large_http_file_transfer_extends_parent_connection_duration(self, activity_gen):
        """Large HTTP files.log rows should have plausible duration inside the parent flow."""
        gen, events = activity_gen
        response_body_len = 78_306_264

        gen.generate_connection(
            src_ip="10.0.10.50",
            dst_ip="93.184.216.34",
            time=datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC),
            dst_port=80,
            proto="tcp",
            service="http",
            duration=0.05,
            orig_bytes=200,
            resp_bytes=response_body_len,
            conn_state="SF",
            http=HttpContext(
                method="GET",
                host="downloads.example.test",
                uri="/installer.exe",
                response_body_len=response_body_len,
                status_code=200,
                status_msg="OK",
                resp_mime_types=["application/x-msdownload"],
            ),
        )

        event = events[-1]
        assert event.file_transfer is not None
        assert event.network is not None
        assert event.file_transfer.duration > 1.0
        assert event.network.duration is not None
        assert event.network.duration > 4.5
        assert event.network.duration > event.file_transfer.duration
        assert event.file_transfer.duration > 0.5
        assert event.network.duration is not None
        assert event.network.duration > event.file_transfer.duration

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
