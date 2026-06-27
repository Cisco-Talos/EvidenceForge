# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Tests for central identity-directory behavior."""

import pytest
from pydantic import ValidationError

from evidenceforge.generation.identity import IdentityDirectory
from evidenceforge.models import (
    BaselineActivity,
    Environment,
    OutputSpec,
    Scenario,
    System,
    TimeWindow,
    User,
)


def _scenario(environment: Environment) -> Scenario:
    return Scenario(
        version="1.0",
        name="identity-test",
        description="Identity test scenario",
        environment=environment,
        time_window=TimeWindow(start="2024-01-01T00:00:00Z", duration="1h"),
        baseline_activity=BaselineActivity(
            description="quiet",
            intensity="low",
            variation="low",
        ),
        output=OutputSpec(logs=[{"format": "windows_event_security"}], destination="./out"),
    )


def test_domain_environment_users_get_windows_domain_sids() -> None:
    """A domain/DC environment gives scenario users domain-backed Windows accounts."""
    scenario = _scenario(
        Environment(
            description="domain env",
            domain="corp.example.com",
            users=[
                User(username="aisha.johnson", full_name="Aisha", email="aisha@corp.example.com")
            ],
            systems=[
                System(
                    hostname="DC-01", ip="10.0.0.10", os="Windows Server", type="domain_controller"
                ),
                System(
                    hostname="WS-01",
                    ip="10.0.0.20",
                    os="Windows 11",
                    type="workstation",
                    assigned_user="aisha.johnson",
                ),
            ],
        )
    )

    directory = IdentityDirectory.from_scenario(scenario)
    account = directory.windows_account("aisha.johnson", host="WS-01")

    assert account is not None
    assert account.scope == "domain"
    assert account.sid.startswith(f"{directory.domain_sid_base}-")
    assert directory.sid_registry["aisha.johnson"] == account.sid


def test_non_domain_windows_users_default_to_host_local_accounts() -> None:
    """Without a domain, Windows accounts are host-local on assigned systems."""
    scenario = _scenario(
        Environment(
            description="workgroup env",
            users=[User(username="sam.lee", full_name="Sam", email="sam@example.com")],
            systems=[
                System(
                    hostname="WS-01",
                    ip="10.0.0.20",
                    os="Windows 11",
                    type="workstation",
                    assigned_user="sam.lee",
                ),
                System(
                    hostname="WS-02",
                    ip="10.0.0.21",
                    os="Windows 11",
                    type="workstation",
                    assigned_user="sam.lee",
                ),
            ],
        )
    )

    directory = IdentityDirectory.from_scenario(scenario)
    ws01 = directory.windows_account("sam.lee", host="WS-01")
    ws02 = directory.windows_account("sam.lee", host="WS-02")

    assert ws01 is not None
    assert ws02 is not None
    assert ws01.scope == "local"
    assert ws02.scope == "local"
    assert ws01.sid != ws02.sid


def test_logical_user_can_have_windows_sid_and_linux_uid() -> None:
    """Logical people can own independent Windows and Linux platform identities."""
    scenario = _scenario(
        Environment(
            description="mixed env",
            domain="corp.example.com",
            users=[
                User(username="aisha.johnson", full_name="Aisha", email="aisha@corp.example.com")
            ],
            systems=[
                System(
                    hostname="DC-01", ip="10.0.0.10", os="Windows Server", type="domain_controller"
                ),
                System(hostname="LINUX-01", ip="10.0.1.10", os="Ubuntu Linux", type="server"),
            ],
        )
    )

    directory = IdentityDirectory.from_scenario(scenario)
    windows = directory.windows_account("aisha.johnson")
    linux = directory.linux_account("aisha.johnson", host="LINUX-01")

    assert windows is not None
    assert linux is not None
    assert windows.sid != str(linux.uid)
    assert linux.uid == directory.linux_uid_for_user("aisha.johnson", host="LINUX-01")


def test_directory_backed_linux_uid_is_stable_across_hosts() -> None:
    """Directory-backed Linux identities keep stable UIDs across Linux hosts."""
    scenario = _scenario(
        Environment(
            description="linux env",
            users=[User(username="dev.user", full_name="Dev", email="dev@example.com")],
            systems=[
                System(hostname="LINUX-01", ip="10.0.1.10", os="Ubuntu Linux", type="server"),
                System(hostname="LINUX-02", ip="10.0.1.11", os="Ubuntu Linux", type="server"),
            ],
        )
    )

    directory = IdentityDirectory.from_scenario(scenario)

    assert directory.linux_uid_for_user(
        "dev.user", host="LINUX-01"
    ) == directory.linux_uid_for_user("dev.user", host="LINUX-02")


def test_host_local_linux_accounts_can_differ_per_host() -> None:
    """A local Linux identity override creates host-scoped accounts."""
    scenario = _scenario(
        Environment(
            description="local linux env",
            identity={
                "linux_default_scope": "local",
            },
            users=[User(username="ops.user", full_name="Ops", email="ops@example.com")],
            systems=[
                System(hostname="LINUX-01", ip="10.0.1.10", os="Ubuntu Linux", type="server"),
                System(hostname="LINUX-02", ip="10.0.1.11", os="Ubuntu Linux", type="server"),
            ],
        )
    )

    directory = IdentityDirectory.from_scenario(scenario)

    assert directory.linux_account("ops.user", host="LINUX-01") is not None
    assert directory.linux_account("ops.user", host="LINUX-02") is not None
    assert directory.linux_uid_for_user(
        "ops.user", host="LINUX-01"
    ) != directory.linux_uid_for_user("ops.user", host="LINUX-02")


def test_duplicate_identity_overrides_are_rejected() -> None:
    """Explicit UID and SID overrides must be unique within their namespaces."""
    with pytest.raises(ValidationError, match="Linux UID overrides must be unique"):
        Environment(
            description="bad uid env",
            identity={
                "users": {
                    "a": {"linux": {"uid": 2528}},
                    "b": {"linux": {"uid": 2528}},
                }
            },
            users=[
                User(username="a", full_name="A", email="a@example.com"),
                User(username="b", full_name="B", email="b@example.com"),
            ],
            systems=[System(hostname="LINUX-01", ip="10.0.1.10", os="Ubuntu Linux", type="server")],
        )

    with pytest.raises(ValidationError, match="Windows SID overrides must be unique"):
        Environment(
            description="bad sid env",
            identity={
                "users": {
                    "a": {"windows": {"sid": "S-1-5-21-1-2-3-1001"}},
                    "b": {"windows": {"sid": "S-1-5-21-1-2-3-1001"}},
                }
            },
            users=[
                User(username="a", full_name="A", email="a@example.com"),
                User(username="b", full_name="B", email="b@example.com"),
            ],
            systems=[System(hostname="WS-01", ip="10.0.0.20", os="Windows 11", type="workstation")],
        )
