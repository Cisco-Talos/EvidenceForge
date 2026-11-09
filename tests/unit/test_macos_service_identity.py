# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Invented host inventories exercise published Mac service-account facts."""

import pytest

from evidenceforge.generation.identity import IdentityDirectory
from evidenceforge.models import Environment, System, User
from tests.unit.test_identity_directory import _scenario


def _directory(names: tuple[str, ...] = ("alex",)) -> IdentityDirectory:
    return IdentityDirectory.from_scenario(
        _scenario(
            Environment(
                description="Invented mixed fleet",
                systems=[
                    System(
                        hostname=host,
                        ip=ip,
                        os=os_name,
                        type="workstation",
                    )
                    for host, ip, os_name in (
                        ("MAC-A", "192.0.2.10", "macOS 26"),
                        ("MAC-B", "192.0.2.11", "macOS 26"),
                        ("LINUX", "192.0.2.12", "Ubuntu 24.04"),
                        ("WINDOWS", "192.0.2.13", "Windows 11"),
                    )
                ],
                users=[
                    User(
                        username=name,
                        full_name="Invented Person",
                        email=f"{name}@example.test",
                        primary_system="MAC-A",
                    )
                    for name in names
                ],
            )
        )
    )


@pytest.mark.parametrize("name", ["_sshd", "sshd", "_SSHD", "SSHD"])
def test_service_aliases_resolve_one_host_local_noninteractive_account(name: str) -> None:
    directory = _directory()
    account = directory.macos_account(name, "mac-a")
    assert account is directory.macos_account("_sshd", "MAC-A")
    assert account is not None
    assert (account.logical_name, account.account_name, account.uid, account.gid) == (
        "_sshd",
        "_sshd",
        75,
        75,
    )
    assert (account.home, account.shell, account.scope) == (
        "/var/empty",
        "/usr/bin/false",
        "well_known",
    )
    other = directory.macos_account(name, "MAC-B")
    assert other is not None and other.host == "MAC-B" and other != account
    for host in ("LINUX", "WINDOWS", "UNKNOWN"):
        assert directory.macos_account(name, host) is None
    assert directory.linux_account(name) is None
    assert directory.windows_account(name) is None


@pytest.mark.parametrize("reserved", ["root", "ROOT", "_sshd", "_SSHD", "sshd", "SSHD"])
def test_authored_builtin_names_preserve_platform_identity_and_human_allocation(
    reserved: str,
) -> None:
    directory = _directory((reserved, "alex"))
    expected_uid = 0 if reserved.casefold() == "root" else 75
    builtin = directory.macos_account(reserved, "MAC-A")
    assert builtin is not None and builtin.uid == expected_uid and builtin.scope == "well_known"
    human = directory.macos_account("alex", "MAC-A")
    assert human is not None and (human.uid, human.gid) == (501, 20)
    assert human == _directory().macos_account("alex", "MAC-A")


def test_account_inventory_is_deterministic_without_host_inspection() -> None:
    first = _directory(("zoe", "alex"))
    second = _directory(("alex", "zoe"))
    assert first.macos_accounts == second.macos_accounts
    assert first.macos_account("zoe", "MAC-A").uid == 502
    assert first.macos_account("alex", "MAC-B") is None
