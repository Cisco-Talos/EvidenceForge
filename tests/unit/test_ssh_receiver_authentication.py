# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Source-independent SSH phase facts reject impossible receiver histories."""

from dataclasses import replace
from datetime import UTC, datetime, timedelta
from unittest.mock import Mock

import pytest

from evidenceforge.events.contexts import HostContext
from evidenceforge.generation.actions.ssh_session import (
    SshReceiverAuthentication,
    SshSessionActionBundle,
    SshSessionRequest,
    _SshLinuxAuthState,
    _SshTransportState,
)
from evidenceforge.models.scenario import System, User


def _authentication() -> SshReceiverAuthentication:
    start = datetime(2026, 10, 16, 12, tzinfo=UTC)
    return SshReceiverAuthentication(
        responder_pid=412,
        session_id=100_000,
        connection_time=start,
        authenticated_at=start + timedelta(seconds=1),
        session_open_time=start + timedelta(seconds=2),
        ready_at=start + timedelta(seconds=3),
    )


@pytest.mark.parametrize(
    "field,value",
    [
        ("responder_pid", 0),
        ("responder_pid", True),
        ("session_id", -1),
        ("session_id", False),
        ("authenticated_at", datetime(2026, 10, 16, 12)),
        ("ready_at", "2026-10-16T12:00:03Z"),
    ],
)
def test_invalid_receiver_facts_are_rejected(field: str, value: object) -> None:
    with pytest.raises(ValueError):
        replace(_authentication(), **{field: value})


@pytest.mark.parametrize("phase", ["authenticated_at", "session_open_time", "ready_at"])
def test_receiver_phases_cannot_precede_transport(phase: str) -> None:
    authentication = _authentication()
    with pytest.raises(ValueError, match="order"):
        replace(authentication, **{phase: authentication.connection_time - timedelta(seconds=1)})


def test_canonical_session_occurrence_needs_no_linux_observation_wrapper() -> None:
    authentication = _authentication()
    target = System(hostname="MAC-RECEIVER", ip="192.0.2.20", os="macOS 26", type="workstation")
    request = SshSessionRequest(
        user=User(username="casey", full_name="Casey", email="casey@example.test"),
        target_system=target,
        time=authentication.connection_time,
        source_ip="198.51.100.10",
    )
    state = Mock(spec=_SshTransportState)
    state.src_host = None
    state.dst_host = HostContext(
        hostname=target.hostname,
        ip=target.ip,
        os=target.os,
        os_category="macos",
        system_type="workstation",
    )
    state.source_port = 49152
    state.source_process = None
    state.logon_id = "0x1234"
    event = SshSessionActionBundle(request, Mock())._build_session_event(state, authentication)
    assert event.timestamp == authentication.session_open_time
    assert event.auth.session_id == 100_000
    assert event.auth.logon_id == "0x1234"
    assert event.auth.source_port == 49152
    assert event.dst_host.os_category == "macos"


def test_linux_adapter_requires_exact_phase_facts() -> None:
    with pytest.raises(ValueError, match="exact authentication"):
        _SshLinuxAuthState(receiver=Mock(), syslog_seed=())
