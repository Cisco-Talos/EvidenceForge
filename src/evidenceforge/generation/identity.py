# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Central identity directory for logical users and platform accounts."""

from __future__ import annotations

import random
from dataclasses import dataclass, field
from typing import Literal

from evidenceforge.models.scenario import Scenario, System, User
from evidenceforge.utils.rng import _stable_seed

WindowsScope = Literal["domain", "local", "well_known", "machine", "service"]
LinuxScope = Literal["directory", "local", "well_known", "service"]


@dataclass(frozen=True, slots=True)
class WindowsAccount:
    """One Windows platform account for a logical user or platform principal."""

    logical_name: str
    account_name: str
    sid: str
    scope: WindowsScope
    domain: str = ""
    host: str | None = None

    @property
    def sam_name(self) -> str:
        """Return a native SAM-style account name."""
        authority = self.host or self.domain
        if not authority:
            return self.account_name
        return f"{authority}\\{self.account_name}"


@dataclass(frozen=True, slots=True)
class LinuxAccount:
    """One Linux platform account for a logical user or platform principal."""

    logical_name: str
    account_name: str
    uid: int
    gid: int
    scope: LinuxScope
    host: str | None = None
    home: str = ""
    shell: str = "/bin/bash"


@dataclass(slots=True)
class IdentityDirectory:
    """Resolved logical-person and platform-account identity model."""

    windows_domain: str
    domain_sid_base: str
    has_windows_domain: bool
    windows_accounts: dict[tuple[str, str], WindowsAccount] = field(default_factory=dict)
    linux_accounts: dict[tuple[str, str], LinuxAccount] = field(default_factory=dict)
    sid_registry: dict[str, str] = field(default_factory=dict)
    _next_domain_rid: int = 1001

    @classmethod
    def from_scenario(cls, scenario: Scenario) -> IdentityDirectory:
        """Build an identity directory from scenario environment data."""
        env = scenario.environment
        has_windows_domain = _has_windows_domain(env.domain, env.systems)
        domain = env.domain or _infer_domain_from_users(env.users) or "corp.local"
        domain_sid_base = _domain_sid_base(scenario.name)
        directory = cls(
            windows_domain=domain,
            domain_sid_base=domain_sid_base,
            has_windows_domain=has_windows_domain,
        )
        directory._add_well_known_windows_accounts()
        directory._add_well_known_linux_accounts()
        directory._add_scenario_users(scenario)
        directory._add_machine_accounts(env.systems)
        directory._add_service_accounts(env.service_accounts)
        return directory

    def windows_account(self, username: str, host: str | None = None) -> WindowsAccount | None:
        """Return the best Windows account for a logical user and optional host."""
        normalized = _key(username)
        if host:
            host_account = self.windows_accounts.get((normalized, _key(host)))
            if host_account is not None:
                return host_account
        return self.windows_accounts.get((normalized, "*"))

    def linux_account(self, username: str, host: str | None = None) -> LinuxAccount | None:
        """Return the best Linux account for a logical user and optional host."""
        normalized = _key(username)
        if host:
            host_account = self.linux_accounts.get((normalized, _key(host)))
            if host_account is not None:
                return host_account
        return self.linux_accounts.get((normalized, "*"))

    def linux_uid_for_user(self, username: str, host: str | None = None) -> int:
        """Return a stable Linux UID for a logical user and optional host."""
        account = self.linux_account(username, host)
        if account is not None:
            return account.uid
        return default_linux_uid_for_user(username, host=host)

    def _add_well_known_windows_accounts(self) -> None:
        for account_name, sid in {
            "SYSTEM": "S-1-5-18",
            "LOCAL SERVICE": "S-1-5-19",
            "NETWORK SERVICE": "S-1-5-20",
        }.items():
            self._store_windows(
                WindowsAccount(
                    logical_name=account_name,
                    account_name=account_name,
                    sid=sid,
                    scope="well_known",
                    domain="NT AUTHORITY",
                )
            )
        self._store_windows(
            WindowsAccount(
                logical_name="Administrator",
                account_name="Administrator",
                sid=f"{self.domain_sid_base}-500",
                scope="domain" if self.has_windows_domain else "local",
                domain=self.windows_domain,
            )
        )
        self._store_windows(
            WindowsAccount(
                logical_name="Guest",
                account_name="Guest",
                sid=f"{self.domain_sid_base}-501",
                scope="domain" if self.has_windows_domain else "local",
                domain=self.windows_domain,
            )
        )
        if self.has_windows_domain:
            self._store_windows(
                WindowsAccount(
                    logical_name="krbtgt",
                    account_name="krbtgt",
                    sid=f"{self.domain_sid_base}-502",
                    scope="domain",
                    domain=self.windows_domain,
                )
            )

    def _add_scenario_users(self, scenario: Scenario) -> None:
        env = scenario.environment
        used_linux_uids = {account.uid for account in self.linux_accounts.values()}
        for user in env.users:
            override = env.identity.users.get(user.username)
            windows_override = override.windows if override else None
            linux_override = override.linux if override else None

            windows_scope = _resolve_windows_scope(
                configured=windows_override.scope if windows_override else "auto",
                default=env.identity.windows_default_scope,
                has_domain=self.has_windows_domain,
            )
            if windows_scope != "disabled":
                account_name = (
                    windows_override.account_name
                    if windows_override and windows_override.account_name
                    else user.username
                )
                sid = windows_override.sid if windows_override and windows_override.sid else None
                if windows_scope == "domain":
                    assigned_sid = sid or f"{self.domain_sid_base}-{self._next_domain_rid}"
                    self._store_windows(
                        WindowsAccount(
                            logical_name=user.username,
                            account_name=account_name,
                            sid=assigned_sid,
                            scope="domain",
                            domain=self.windows_domain,
                        )
                    )
                    self._next_domain_rid += 1
                else:
                    for system in _assigned_windows_systems(user, env.systems):
                        self._store_windows(
                            WindowsAccount(
                                logical_name=user.username,
                                account_name=account_name,
                                sid=sid or _local_windows_sid(system.hostname, account_name),
                                scope="local",
                                host=system.hostname,
                            )
                        )

            linux_scope = _resolve_linux_scope(
                configured=linux_override.scope if linux_override else "auto",
                default=env.identity.linux_default_scope,
            )
            if linux_scope != "disabled":
                account_name = (
                    linux_override.account_name
                    if linux_override and linux_override.account_name
                    else user.username
                )
                explicit_uid = linux_override.uid if linux_override else None
                explicit_gid = linux_override.gid if linux_override else None
                home = linux_override.home if linux_override and linux_override.home else None
                shell = linux_override.shell if linux_override and linux_override.shell else None
                if linux_scope == "directory":
                    uid = explicit_uid or _unique_uid(
                        default_linux_uid_for_user(account_name),
                        used_linux_uids,
                    )
                    used_linux_uids.add(uid)
                    self._store_linux(
                        LinuxAccount(
                            logical_name=user.username,
                            account_name=account_name,
                            uid=uid,
                            gid=explicit_gid if explicit_gid is not None else uid,
                            scope="directory",
                            home=home or _linux_home(account_name),
                            shell=shell or "/bin/bash",
                        )
                    )
                else:
                    for system in _assigned_linux_systems(user, env.systems):
                        uid = explicit_uid or default_linux_uid_for_user(
                            account_name, host=system.hostname
                        )
                        self._store_linux(
                            LinuxAccount(
                                logical_name=user.username,
                                account_name=account_name,
                                uid=uid,
                                gid=explicit_gid if explicit_gid is not None else uid,
                                scope="local",
                                host=system.hostname,
                                home=home or _linux_home(account_name),
                                shell=shell or "/bin/bash",
                            )
                        )

    def _add_machine_accounts(self, systems: list[System]) -> None:
        if not self.has_windows_domain:
            for system in systems:
                account_name = f"{system.hostname}$"
                self._store_windows(
                    WindowsAccount(
                        logical_name=account_name,
                        account_name=account_name,
                        sid=_local_windows_sid(system.hostname, account_name),
                        scope="machine",
                        host=system.hostname,
                    )
                )
            return
        for system in systems:
            account_name = f"{system.hostname}$"
            self._store_windows(
                WindowsAccount(
                    logical_name=account_name,
                    account_name=account_name,
                    sid=f"{self.domain_sid_base}-{self._next_domain_rid}",
                    scope="machine",
                    domain=self.windows_domain,
                )
            )
            self._next_domain_rid += 1

    def _add_service_accounts(self, service_accounts: list[str]) -> None:
        for service in service_accounts:
            if self.sid_registry.get(service):
                continue
            scope: WindowsScope = "service" if self.has_windows_domain else "local"
            self._store_windows(
                WindowsAccount(
                    logical_name=service,
                    account_name=service,
                    sid=f"{self.domain_sid_base}-{self._next_domain_rid}",
                    scope=scope,
                    domain=self.windows_domain if self.has_windows_domain else "",
                )
            )
            self._next_domain_rid += 1

    def _add_well_known_linux_accounts(self) -> None:
        for name, uid in _LINUX_WELL_KNOWN_UIDS.items():
            self._store_linux(
                LinuxAccount(
                    logical_name=name,
                    account_name=name,
                    uid=uid,
                    gid=uid,
                    scope="well_known",
                    home=_linux_home(name),
                    shell="/bin/bash" if name != "root" else "/bin/bash",
                )
            )

    def _store_windows(self, account: WindowsAccount) -> None:
        host_key = _key(account.host) if account.host else "*"
        self.windows_accounts[(_key(account.logical_name), host_key)] = account
        self.sid_registry.setdefault(account.logical_name, account.sid)
        self.sid_registry.setdefault(account.account_name, account.sid)
        self.sid_registry.setdefault(account.sam_name, account.sid)

    def _store_linux(self, account: LinuxAccount) -> None:
        host_key = _key(account.host) if account.host else "*"
        self.linux_accounts[(_key(account.logical_name), host_key)] = account


_LINUX_WELL_KNOWN_UIDS = {
    "root": 0,
    "ubuntu": 1000,
    "ec2-user": 1000,
    "admin": 1001,
    "ansible": 998,
    "deploy": 1002,
}


def default_linux_uid_for_user(username: str, host: str | None = None) -> int:
    """Return the legacy-compatible stable Linux UID for a login username."""
    if username in _LINUX_WELL_KNOWN_UIDS:
        return _LINUX_WELL_KNOWN_UIDS[username]
    if host:
        return 2000 + (_stable_seed(f"linux_uid_{host}:{username}") % 5000)
    return 2000 + (_stable_seed(f"linux_uid_{username}") % 5000)


def _key(value: str | None) -> str:
    return (value or "").lower()


def _domain_sid_base(scenario_name: str) -> str:
    rng = random.Random(_stable_seed(scenario_name))
    return (
        f"S-1-5-21-{rng.randint(1000000000, 3999999999)}"
        f"-{rng.randint(1000000000, 3999999999)}"
        f"-{rng.randint(1000000000, 3999999999)}"
    )


def _has_windows_domain(domain: str | None, systems: list[System]) -> bool:
    if domain:
        return True
    for system in systems:
        system_type = str(system.type or "").lower()
        roles = {str(role).lower() for role in system.roles or []}
        if system_type == "domain_controller" or "domain_controller" in roles:
            return True
    return False


def _infer_domain_from_users(users: list[User]) -> str | None:
    for user in users:
        email = getattr(user, "email", "") or ""
        if "@" in email:
            return email.split("@", 1)[1].lower()
    return None


def _resolve_windows_scope(
    *,
    configured: str,
    default: str,
    has_domain: bool,
) -> str:
    if configured == "disabled":
        return "disabled"
    requested = configured if configured != "auto" else default
    if requested == "domain":
        return "domain" if has_domain else "local"
    if requested == "local":
        return "local"
    return "domain" if has_domain else "local"


def _resolve_linux_scope(*, configured: str, default: str) -> str:
    if configured == "disabled":
        return "disabled"
    return default if configured == "auto" else configured


def _assigned_windows_systems(user: User, systems: list[System]) -> list[System]:
    assigned = [
        system
        for system in systems
        if _is_windows(system)
        and (
            system.assigned_user == user.username
            or system.hostname == getattr(user, "primary_system", None)
        )
    ]
    if assigned:
        return assigned
    workstations = [
        system for system in systems if _is_windows(system) and system.type == "workstation"
    ]
    if workstations:
        return workstations[:1]
    windows = [system for system in systems if _is_windows(system)]
    return windows[:1]


def _assigned_linux_systems(user: User, systems: list[System]) -> list[System]:
    assigned = [
        system
        for system in systems
        if _is_linux(system)
        and (
            system.assigned_user == user.username
            or system.hostname == getattr(user, "primary_system", None)
        )
    ]
    if assigned:
        return assigned
    linux = [system for system in systems if _is_linux(system)]
    return linux


def _is_windows(system: System) -> bool:
    return "windows" in str(system.os or "").lower()


def _is_linux(system: System) -> bool:
    os_name = str(system.os or "").lower()
    return any(token in os_name for token in ("linux", "ubuntu", "debian", "centos", "rhel"))


def _local_windows_sid(hostname: str, account_name: str) -> str:
    base_seed = _stable_seed(f"local_windows_sid_base:{hostname}")
    rid_seed = _stable_seed(f"local_windows_rid:{hostname}:{account_name}")
    base = (
        f"S-1-5-21-{1000000000 + (base_seed % 3000000000)}"
        f"-{1000000000 + ((base_seed >> 32) % 3000000000)}"
        f"-{1000000000 + ((base_seed >> 16) % 3000000000)}"
    )
    rid = 1001 + (rid_seed % 49_000)
    return f"{base}-{rid}"


def _unique_uid(preferred: int, used: set[int]) -> int:
    uid = preferred
    while uid in used:
        uid += 1
    return uid


def _linux_home(account_name: str) -> str:
    if account_name == "root":
        return "/root"
    return f"/home/{account_name}"
