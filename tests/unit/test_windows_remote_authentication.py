# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Focused tests for canonical Windows remote-authentication transport texture."""

from datetime import UTC, datetime, timedelta
from unittest.mock import Mock

from evidenceforge.generation.actions import (
    WindowsRemoteAuthenticationPlanner,
    WindowsRemoteAuthenticationRequest,
)
from evidenceforge.models import System


def _request(
    *,
    source: str,
    outcome: str = "success",
    source_port: int = 51000,
    time: datetime | None = None,
) -> WindowsRemoteAuthenticationRequest:
    return WindowsRemoteAuthenticationRequest(
        target_system=System(
            hostname="FILE-01",
            ip="10.0.0.20",
            os="Windows Server 2022",
            type="server",
        ),
        time=time or datetime(2024, 3, 18, 12, 0, 0, tzinfo=UTC),
        source_ip="10.0.0.10",
        source_port=source_port,
        logon_type=3,
        auth_protocol="NTLM",
        outcome=outcome,
        destination_port=445,
        source=source,
    )


def test_planner_uses_request_source_and_outcome_for_duration(monkeypatch):
    """The canonical planner delegates duration ownership to the typed profile selector."""

    observed: list[tuple[str, str]] = []

    def sample_duration(*, source, outcome, rng):
        observed.append((source, outcome))
        assert rng is not None
        return 17.25

    monkeypatch.setattr(
        "evidenceforge.generation.actions.windows_remote_authentication."
        "sample_remote_auth_transport_duration",
        sample_duration,
    )
    planner = WindowsRemoteAuthenticationPlanner(Mock())

    network = planner._network_request(_request(source="anonymous_logon"))

    assert observed == [("anonymous_logon", "success")]
    assert network.duration == 17.25
    assert network.service == "smb"


def test_failed_remote_auth_attempts_remain_short_and_newly_identified():
    """Failed attempts retain a short profile and distinct transaction identity."""

    planner = WindowsRemoteAuthenticationPlanner(Mock())
    timestamp = datetime(2024, 3, 18, 12, 0, 0, tzinfo=UTC)
    first = planner._network_request(
        _request(source="activity_generator", outcome="failure", time=timestamp)
    )
    second = planner._network_request(
        _request(
            source="activity_generator",
            outcome="failure",
            source_port=51001,
            time=timestamp + timedelta(seconds=1),
        )
    )

    assert 0.02 <= first.duration <= 1.5
    assert 0.02 <= second.duration <= 1.5
    assert first.stable_id != second.stable_id
    assert first.src_port != second.src_port
