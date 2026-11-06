# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Remote session observation owns closure and preserves protocol boundaries."""

from datetime import UTC, datetime, timedelta

import pytest

from evidenceforge.events.base import OccurrenceBuilder
from evidenceforge.events.contexts import AuthContext, HostContext
from evidenceforge.events.identity import EventIdentityPlan, SessionIdentity
from evidenceforge.events.lifecycle import ActionLifecycleContext
from evidenceforge.events.observation import ObservationPolicy
from tests.network_factories import network_plan

T0 = datetime(2026, 11, 2, 13, tzinfo=UTC)


@pytest.fixture
def policy(monkeypatch: pytest.MonkeyPatch) -> ObservationPolicy:
    monkeypatch.setattr(
        "evidenceforge.events.observation.get_observation_profile",
        lambda _: {"default": {"missingness": 0.5, "delay_ms": {"min_ms": 5, "max_ms": 900}}},
    )
    return ObservationPolicy("remote-session-close-contract")


@pytest.mark.parametrize(
    ("platform", "kind", "port"),
    [("macos", "ssh", 22), ("linux", "ssh", 22), ("windows", "rdp", 3389)],
)
@pytest.mark.parametrize("typed", [True, False])
def test_remote_transport_login_logout_share_drop_and_delay(
    policy: ObservationPolicy, platform: str, kind: str, port: int, typed: bool
) -> None:
    host = HostContext(
        hostname="target", ip="192.0.2.2", os=platform, os_category=platform, system_type="server"
    )
    statuses: set[str] = set()
    for source_port in range(50000, 50032):
        session = SessionIdentity(
            "target", f"session-{source_port}", "0x123", 1, "alice", kind, T0, "session-life"
        )
        identity = EventIdentityPlan(subject=session, session=session) if typed else None
        transport = OccurrenceBuilder(
            timestamp=T0,
            event_type="connection",
            dst_host=host,
            network=network_plan(
                src_ip="192.0.2.1",
                src_port=source_port,
                dst_ip=host.ip,
                dst_port=port,
                protocol="tcp",
                zeek_uid=f"C{source_port}",
            ),
        )

        def auth(remote_port: int = source_port) -> AuthContext:
            return AuthContext(
                username="alice",
                source_ip="192.0.2.1",
                source_port=remote_port,
                logon_id="0x123",
                logon_type=10,
                auth_protocol="kerberos" if platform == "windows" else "",
            )

        login = OccurrenceBuilder(
            timestamp=T0 + timedelta(seconds=1),
            event_type="ssh_session" if kind == "ssh" else "logon",
            dst_host=host,
            auth=auth(),
            identity_plan=identity,
        )
        logout = OccurrenceBuilder(
            timestamp=T0 + timedelta(minutes=10),
            event_type="logoff",
            dst_host=host,
            auth=auth(),
            identity_plan=identity,
            lifecycle=ActionLifecycleContext(
                group_id="session-life", canonical_start=T0, phase="closure"
            ),
        )
        keys = [policy._coherent_group_key("ecar", event) for event in (transport, login, logout)]
        assert len(set(keys)) == 1 and keys[0].startswith(f"remote-session:{port}:")
        decisions = [policy.decide("ecar", event) for event in (transport, login, logout)]
        assert decisions[0] == decisions[1] == decisions[2]
        statuses.add(decisions[0].status)
    assert "dropped" in statuses and len(statuses) > 1


@pytest.mark.parametrize("kind", ["smb", "interactive", "network"])
def test_non_remote_session_kind_does_not_become_ssh(policy: ObservationPolicy, kind: str) -> None:
    host = HostContext(
        hostname="target", ip="192.0.2.2", os="macos", os_category="macos", system_type="server"
    )
    event = OccurrenceBuilder(
        timestamp=T0,
        event_type="logoff",
        dst_host=host,
        auth=AuthContext(
            username="alice",
            source_ip="192.0.2.1",
            source_port=50000,
            session_kind=kind,
            logon_type=3,
        ),
    )
    assert policy._ecar_remote_session_group_key(event) == ""
