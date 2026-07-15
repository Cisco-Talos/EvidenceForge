"""Compiled world-model and session/activity planners.

The canonical event model guarantees field consistency once a SecurityEvent
exists. This module adds the missing "why would this happen here?" layer:

- resolve authoritative host capabilities and infrastructure roles once
- resolve user placement and remote-admin source systems once
- centralize session bootstrap (interactive, SSH, RDP, network)
- centralize process-first attribution for persona traffic
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any

from evidenceforge.events.lifecycle import SessionEndPlan
from evidenceforge.generation.activity.generator import _ephemeral_port, _linux_foreground_lifetime
from evidenceforge.generation.activity.helpers import _get_os_category
from evidenceforge.generation.activity.network_params import public_ntp_ips
from evidenceforge.generation.activity.process_network import get_service_to_exes
from evidenceforge.models.state import ActiveSession
from evidenceforge.utils.rng import _stable_seed
from evidenceforge.utils.time import ensure_utc

if TYPE_CHECKING:
    import random

    from evidenceforge.generation.activity.generator import ActivityGenerator
    from evidenceforge.generation.state_manager import StateManager
    from evidenceforge.models.scenario import Scenario, System, User


_ROLE_ALIASES = {
    "app": "app_server",
    "application": "app_server",
    "application_server": "app_server",
    "database": "database",
    "database_server": "database",
    "db": "database",
    "db_server": "database",
    "dc": "domain_controller",
    "dns": "dns_server",
    "email": "mail_server",
    "exchange": "mail_server",
    "file": "file_server",
    "fileserver": "file_server",
    "log": "log_server",
    "mail": "mail_server",
    "nfs": "nfs_server",
    "print": "print_server",
    "proxy": "forward_proxy",
    "siem": "log_server",
    "sql_server": "database",
    "web": "web_server",
    "webserver": "web_server",
}

_SERVICE_ROLE_HINTS: tuple[tuple[tuple[str, ...], str], ...] = (
    (("mysql", "postgres", "postgresql", "mariadb", "sql server", "mssql"), "database"),
    (("apache", "nginx", "httpd", "iis", "tomcat"), "web_server"),
    (("bind", "named"), "dns_server"),
    (("exchange", "postfix", "smtp", "dovecot"), "mail_server"),
    (("splunk", "elasticsearch", "logstash", "syslog"), "log_server"),
    (("nfs",), "nfs_server"),
    (("smb", "cifs", "fileshare"), "file_server"),
    (("squid", "proxy"), "forward_proxy"),
)

_HOSTNAME_ROLE_HINTS: tuple[tuple[tuple[str, ...], str], ...] = (
    (("db", "sql"), "database"),
    (("web",), "web_server"),
    (("app",), "app_server"),
    (("mail", "exch"), "mail_server"),
    (("dns",), "dns_server"),
    (("proxy",), "forward_proxy"),
    (("log", "siem", "splunk"), "log_server"),
    (("print",), "print_server"),
)

_ROLE_PERSONAS: dict[str, set[str]] = {
    "database": {"developer", "data_analyst", "analyst"},
    "log_server": {"security_analyst"},
    "web_server": {"developer"},
}

_DNS_SERVER_SERVICES = {
    "dns",
    "dns-server",
    "dns_server",
    "bind",
    "bind9",
    "named",
    "ad-ds",
}

_ADMIN_PERSONAS = {"sysadmin", "help_desk"}
_LINUX_SSH_ADMIN_PERSONAS = {"sysadmin"}
_LINUX_SSH_ADMIN_GROUPS = {
    "domain-admins",
    "infrastructure",
    "it-admins",
    "linux-admins",
    "server-admins",
    "sysadmins",
}
_LINUX_SSH_ROLE_PERSONAS: dict[str, set[str]] = {
    "app_server": {"developer"},
    "database": {"developer"},
    "forward_proxy": {"security_analyst"},
    "log_server": {"security_analyst"},
    "web_server": {"developer"},
}

_DB_PORTS = {
    "mssql": 1433,
    "mysql": 3306,
    "postgresql": 5432,
}

_DB_SERVICE_ALIASES = {
    "mssql": "mssql",
    "sql": "mssql",
    "sql-server": "mssql",
    "sql server": "mssql",
    "sqlserver": "mssql",
    "tds": "mssql",
    "mysql": "mysql",
    "mariadb": "mysql",
    "maria": "mysql",
    "postgres": "postgresql",
    "postgresql": "postgresql",
    "pgsql": "postgresql",
}

_DB_SERVICE_MATCH: dict[str, set[str]] = {
    "mssql": {"mssql", "sqlserver", "sql-server", "sql server"},
    "postgresql": {"postgres", "postgresql", "pgsql"},
    "mysql": {"mysql", "maria", "mariadb"},
}

_OS_DB_DEFAULT = {"linux": "postgresql", "windows": "mssql"}


def normalize_database_service(service: str | None) -> str | None:
    """Return the canonical database engine name for a service label."""
    if not service:
        return None
    normalized = service.lower().replace("_", "-")
    return _DB_SERVICE_ALIASES.get(normalized)


def database_services_for_host(
    services: tuple[str, ...] | list[str] | None,
    os_category: str,
    *,
    has_database_role: bool = False,
) -> set[str]:
    """Return canonical DB engines declared or inferred for a host."""
    explicit = {
        normalized
        for service in services or ()
        if (normalized := normalize_database_service(service)) is not None
    }
    if explicit:
        return explicit
    if has_database_role:
        inferred = _OS_DB_DEFAULT.get(os_category)
        return {inferred} if inferred else set()
    return set()


def host_services_support_database_service(
    services: tuple[str, ...] | list[str] | None,
    os_category: str,
    service: str | None,
) -> bool:
    """Return whether a host service inventory supports the requested DB engine."""
    requested = normalize_database_service(service)
    if requested is None:
        return True
    declared = database_services_for_host(services, os_category, has_database_role=True)
    return requested in declared


_SHELL_EXES = {"bash", "sh", "zsh"}


def _normalize_role_name(role: str) -> str:
    key = role.strip().lower().replace("-", "_").replace(" ", "_")
    return _ROLE_ALIASES.get(key, key)


def known_topology_roles() -> set[str]:
    """Return canonical role names recognized by world-model topology hints."""
    roles = set(_ROLE_ALIASES.values())
    roles.update(role for _hints, role in _SERVICE_ROLE_HINTS)
    roles.update(role for _hints, role in _HOSTNAME_ROLE_HINTS)
    roles.update(_ROLE_PERSONAS)
    return roles


@dataclass(frozen=True, slots=True)
class HostWorld:
    """Canonical capabilities for a single system."""

    system: System
    os_category: str
    canonical_roles: tuple[str, ...]
    services: tuple[str, ...]
    is_server: bool
    supports_ssh: bool
    supports_rdp: bool


@dataclass(frozen=True, slots=True)
class UserWorld:
    """Canonical placement and likely remote source hosts for a user."""

    user: User
    primary_system: System | None
    activity_systems: tuple[System, ...]
    remote_source_systems: tuple[System, ...]


@dataclass(frozen=True, slots=True)
class DatabaseEndpoint:
    """Database endpoint resolved from host roles/services."""

    system: System
    port: int
    service: str


@dataclass(frozen=True, slots=True)
class SessionPlan:
    """Planned session semantics for a user on a target host."""

    target_system: System
    source_system: System | None
    source_ip: str
    logon_type: int
    session_kind: str
    requires_transport: bool


@dataclass(frozen=True, slots=True)
class SessionBootstrapResult:
    """Result of creating or reusing a session."""

    session: ActiveSession
    network_uid: str | None = None


class WorldModel:
    """Compiled environment model used by baseline and storyline generation."""

    def __init__(self, scenario: Scenario, ad_domain: str) -> None:
        self.scenario = scenario
        self.ad_domain = ad_domain
        self.systems_by_hostname: dict[str, System] = {
            system.hostname: system for system in scenario.environment.systems
        }
        self.systems_by_ip: dict[str, System] = {
            system.ip: system for system in scenario.environment.systems
        }
        self.users_by_username: dict[str, User] = {
            user.username: user for user in scenario.environment.users
        }
        self.hosts: dict[str, HostWorld] = {
            system.hostname: self._compile_host(system) for system in scenario.environment.systems
        }
        self.systems_by_role: dict[str, list[System]] = self._index_systems_by_role()
        self.service_defaults_by_host: dict[str, list[str]] = {
            system.hostname: self._resolve_service_defaults(system)
            for system in scenario.environment.systems
        }
        self.proxy_routes: dict[str, list[System]] = self._build_proxy_routes()
        self.users: dict[str, UserWorld] = {
            user.username: self._compile_user(user) for user in scenario.environment.users
        }
        self.db_servers: list[DatabaseEndpoint] = self._collect_db_servers()
        self.dns_servers: list[System] = self._collect_role_systems("dns_server")
        self.domain_controllers: list[System] = self._collect_role_systems("domain_controller")
        self.mail_servers: list[System] = self._collect_role_systems("mail_server")
        self.ntp_ips: list[str] = self._resolve_ntp_ips()

    def _compile_host(self, system: System) -> HostWorld:
        os_category = _get_os_category(system.os)
        roles: set[str] = {_normalize_role_name(system.type)}
        for role in system.roles or []:
            roles.add(_normalize_role_name(role))

        service_values = tuple(system.services or ())
        hostname_lower = system.hostname.lower()

        service_blob = " ".join(service.lower() for service in service_values)

        if system.type == "domain_controller":
            roles.update({"domain_controller", "dns_server"})
        elif system.type == "workstation":
            roles.add("workstation")

        # Service/hostname heuristics are always additive — they supplement
        # explicit roles, not override them. Mixed-use hosts (e.g.,
        # roles=[web_server] + services=[postgresql]) get both capabilities.
        normalized_services = {
            service.lower().replace(" ", "-").replace("_", "-") for service in service_values
        }
        if normalized_services.intersection(_DNS_SERVER_SERVICES):
            roles.add("dns_server")
        for hints, role_name in _SERVICE_ROLE_HINTS:
            if any(hint in service_blob for hint in hints):
                roles.add(role_name)
        for hints, role_name in _HOSTNAME_ROLE_HINTS:
            if any(hint in hostname_lower for hint in hints):
                roles.add(role_name)

        supports_ssh = os_category == "linux"
        supports_rdp = os_category == "windows" and system.type in ("server", "domain_controller")

        return HostWorld(
            system=system,
            os_category=os_category,
            canonical_roles=tuple(sorted(roles)),
            services=service_values,
            is_server=system.type in ("server", "domain_controller"),
            supports_ssh=supports_ssh,
            supports_rdp=supports_rdp,
        )

    def _index_systems_by_role(self) -> dict[str, list[System]]:
        index: dict[str, list[System]] = {}
        for host in self.hosts.values():
            for role in host.canonical_roles:
                index.setdefault(role, []).append(host.system)
        return index

    def _resolve_service_defaults(self, system: System) -> list[str]:
        if system.services:
            return list(system.services)
        host = self.hosts[system.hostname]
        if host.os_category == "windows":
            services = [
                "dns-client",
                "ntp-client",
                "smb-client",
                "kerberos-client",
                "ldap-client",
            ]
            if host.is_server:
                services.append("smb-server")
            return services
        return ["dns-client", "ntp-client", "syslog"]

    def _build_proxy_routes(self) -> dict[str, list[System]]:
        proxies = self.systems_by_role.get("forward_proxy", [])
        if not proxies:
            return {}
        proxy = proxies[0]
        routes: dict[str, list[System]] = {}
        for host in self.hosts.values():
            if "forward_proxy" in host.canonical_roles:
                continue
            routes[host.system.ip] = [proxy]
        return routes

    def _compile_user(self, user: User) -> UserWorld:
        primary = self.systems_by_hostname.get(user.primary_system or "")
        assigned = [
            system
            for system in self.scenario.environment.systems
            if system.assigned_user == user.username
        ]
        activity_systems: list[System] = []
        if primary is not None:
            activity_systems.append(primary)
        for system in assigned:
            if system not in activity_systems:
                activity_systems.append(system)
        if not activity_systems:
            workstations = self.systems_by_role.get("workstation", [])
            if workstations:
                seed = _stable_seed(f"user_home_{user.username}")
                activity_systems.append(workstations[seed % len(workstations)])
            elif self.scenario.environment.systems:
                activity_systems.append(self.scenario.environment.systems[0])

        remote_sources = [system for system in activity_systems if system.type == "workstation"]
        if not remote_sources:
            remote_sources = [system for system in self.systems_by_role.get("workstation", [])]

        return UserWorld(
            user=user,
            primary_system=primary,
            activity_systems=tuple(activity_systems),
            remote_source_systems=tuple(remote_sources),
        )

    def _collect_role_systems(self, role: str) -> list[System]:
        return list(self.systems_by_role.get(role, []))

    def _collect_db_servers(self) -> list[DatabaseEndpoint]:
        endpoints: list[DatabaseEndpoint] = []
        for system in self.systems_by_role.get("database", []):
            host = self.hosts[system.hostname]
            services = database_services_for_host(
                host.services,
                host.os_category,
                has_database_role=True,
            )
            db_service = next(
                (service for service in ("mssql", "mysql", "postgresql") if service in services),
                "mssql",
            )
            endpoints.append(
                DatabaseEndpoint(
                    system=system,
                    port=_DB_PORTS[db_service],
                    service=db_service,
                )
            )
        return endpoints

    def _resolve_ntp_ips(self) -> list[str]:
        ntp_hosts = [
            host.system
            for host in self.hosts.values()
            if "ntp" in host.system.hostname.lower() or "ntp_server" in host.canonical_roles
        ]
        if ntp_hosts:
            return [system.ip for system in ntp_hosts]
        # AD environments: workstations sync NTP from the DC (W32Time service)
        if self.domain_controllers:
            return [dc.ip for dc in self.domain_controllers]
        return public_ntp_ips() or ["129.6.15.28", "132.163.97.1"]

    def to_infrastructure_ips(self) -> dict[str, str | list[Any]]:
        return {
            "dns": [system.ip for system in self.dns_servers] or ["10.0.0.1"],
            "ntp": list(self.ntp_ips),
            "dc": [system.ip for system in self.domain_controllers] or ["10.0.0.1"],
            "dc_hostnames": [system.hostname for system in self.domain_controllers] or ["DC-01"],
            "db_servers": [
                {
                    "ip": endpoint.system.ip,
                    "port": endpoint.port,
                    "service": endpoint.service,
                }
                for endpoint in self.db_servers
            ],
            "exchange": self.mail_servers[0].ip if self.mail_servers else None,
        }

    def host_for(self, system_or_ip: System | str) -> HostWorld | None:
        if hasattr(system_or_ip, "hostname"):
            return self.hosts.get(system_or_ip.hostname)
        if system_or_ip in self.hosts:
            return self.hosts.get(system_or_ip)
        system = self.systems_by_ip.get(system_or_ip)
        return self.hosts.get(system.hostname) if system else None

    def system_for_ip(self, ip: str) -> System | None:
        return self.systems_by_ip.get(ip)

    def user_for(self, username: str) -> UserWorld | None:
        return self.users.get(username)

    def pick_activity_system(self, user: User, rng: random.Random) -> System:
        world_user = self.users.get(user.username)
        if world_user and world_user.activity_systems:
            return rng.choice(list(world_user.activity_systems))
        return rng.choice(list(self.scenario.environment.systems))

    def pick_remote_source_system(
        self,
        user: User,
        target_system: System,
        rng: random.Random,
    ) -> System | None:
        world_user = self.users.get(user.username)
        candidates = list(world_user.remote_source_systems) if world_user else []
        candidates = [system for system in candidates if system.hostname != target_system.hostname]

        if self.hosts[target_system.hostname].supports_rdp:
            windows_workstations = [
                system
                for system in candidates
                if self.hosts[system.hostname].os_category == "windows"
            ]
            if windows_workstations:
                return rng.choice(windows_workstations)

        if candidates:
            return rng.choice(candidates)

        compatible = [
            system
            for system in self.systems_by_role.get("workstation", [])
            if system.hostname != target_system.hostname
        ]
        if compatible:
            return rng.choice(compatible)

        others = [
            system
            for system in self.scenario.environment.systems
            if system.hostname != target_system.hostname
        ]
        return rng.choice(others) if others else None

    def get_remote_admin_users(self, target_system: System) -> list[User]:
        host = self.hosts[target_system.hostname]
        enabled = [user for user in self.scenario.environment.users if user.enabled]

        if target_system.type == "workstation" and target_system.assigned_user:
            return [user for user in enabled if user.username == target_system.assigned_user]

        personas = set(_ADMIN_PERSONAS)
        for role in host.canonical_roles:
            personas.update(_ROLE_PERSONAS.get(role, set()))

        roster: list[User] = []
        seen: set[str] = set()
        for user in enabled:
            persona = (user.persona or "").lower()
            if persona not in personas:
                continue
            if user.username in seen:
                continue
            seen.add(user.username)
            roster.append(user)

        if len(roster) < 2:
            for user in enabled:
                persona = (user.persona or "").lower()
                if persona not in (_ADMIN_PERSONAS | {"developer", "security_analyst"}):
                    continue
                if user.username in seen:
                    continue
                seen.add(user.username)
                roster.append(user)
                if len(roster) >= 2:
                    break

        return roster

    def effective_user_groups(self, user: User) -> set[str]:
        """Return direct and environment-group memberships for a user."""
        groups = {group.lower() for group in user.groups}
        for group in self.scenario.environment.groups or []:
            if user.username in group.members:
                groups.add(group.name.lower())
        return groups

    def can_user_ssh_admin(self, user: User, target_system: System) -> bool:
        """Return whether a scenario user plausibly opens baseline SSH admin sessions."""
        host = self.hosts[target_system.hostname]
        if not host.supports_ssh or not host.is_server:
            return False

        persona = (user.persona or "").lower()
        if persona in _LINUX_SSH_ADMIN_PERSONAS:
            return True
        if self.effective_user_groups(user) & _LINUX_SSH_ADMIN_GROUPS:
            return True
        for role in host.canonical_roles:
            if persona in _LINUX_SSH_ROLE_PERSONAS.get(role, set()):
                return True
        return False

    def get_ssh_admin_users(self, target_system: System) -> list[User]:
        """Return scenario users eligible for ordinary baseline SSH to a Linux server."""
        enabled = [user for user in self.scenario.environment.users if user.enabled]
        roster: list[User] = []
        seen: set[str] = set()
        for user in enabled:
            if user.username in seen:
                continue
            if not self.can_user_ssh_admin(user, target_system):
                continue
            seen.add(user.username)
            roster.append(user)
        return roster

    def resolve_destination(
        self,
        dest_role: str,
        src_system: System,
        rng: random.Random,
        os_category: str = "windows",
        dns_tags: list[str] | None = None,
        service: str = "",
    ) -> tuple[str | None, str | None]:
        """Resolve a profile destination role to a concrete IP and hostname."""
        if dest_role == "_external":
            from evidenceforge.generation.activity.dns_registry import pick_domain_and_ip

            tags = tuple(dns_tags) if dns_tags else ("background", os_category)
            domain, ip = pick_domain_and_ip(
                rng,
                *tags,
                src_host=src_system.hostname,
                include_os=os_category,
                source_system_type=src_system.type,
            )
            return ip, domain

        if dest_role in ("_dc", "domain_controller"):
            dc_candidates = [
                system
                for system in self.domain_controllers
                if system.hostname != src_system.hostname
            ]
            # Single-DC: no peer exists — skip rather than self-target
            if dc_candidates:
                target = rng.choice(dc_candidates)
                return target.ip, self.fqdn_for_system(target)
            return None, None

        if dest_role == "_any_server":
            servers = [
                host.system
                for host in self.hosts.values()
                if host.is_server and host.system.hostname != src_system.hostname
            ]
            if servers:
                target = rng.choice(servers)
                return target.ip, self.fqdn_for_system(target)
            return None, None

        if dest_role == "_any":
            others = [
                system
                for system in self.scenario.environment.systems
                if system.hostname != src_system.hostname
            ]
            if others:
                target = rng.choice(others)
                return target.ip, self.fqdn_for_system(target)
            return None, None

        role = _normalize_role_name(dest_role)
        candidates = [
            system
            for system in self.systems_by_role.get(role, [])
            if system.hostname != src_system.hostname
        ]
        # Filter database candidates by service compatibility.
        # When a host has no explicit services, use the OS-inferred DB type
        # (Linux→postgresql, Windows→mssql) to avoid impossible protocol targets.
        if role == "database" and service and candidates:
            filtered = [
                system
                for system in candidates
                if (
                    (host := self.hosts.get(system.hostname)) is not None
                    and host_services_support_database_service(
                        host.services,
                        host.os_category,
                        service,
                    )
                )
            ]
            # If no service-compatible host exists, skip rather than routing to
            # an incompatible DB engine.
            candidates = filtered
        if candidates:
            target = rng.choice(candidates)
            return target.ip, self.fqdn_for_system(target)
        return None, None

    def fqdn_for_system(self, system: System) -> str:
        return f"{system.hostname}.{self.ad_domain}" if self.ad_domain else system.hostname

    def plan_session(
        self,
        user: User,
        target_system: System,
        rng: random.Random,
        session_kind: str | None = None,
        source_system: System | None = None,
        source_ip_override: str | None = None,
    ) -> SessionPlan:
        """Plan how a user should reach a target host.

        Args:
            source_ip_override: Explicit source IP from the scenario
                storyline. When set and the IP doesn't map to a scenario
                system, we preserve it in the plan instead of inventing
                a different source.
        """
        host = self.hosts[target_system.hostname]
        kind = session_kind

        if kind is None:
            world_user = self.users.get(user.username)
            is_primary = (
                world_user is not None
                and world_user.primary_system is not None
                and world_user.primary_system.hostname == target_system.hostname
            )
            is_assigned = target_system.assigned_user == user.username
            if is_primary or is_assigned or not host.is_server:
                kind = "interactive"
            elif host.supports_ssh:
                kind = "ssh"
            elif host.supports_rdp:
                kind = "rdp"
            else:
                kind = "network"

        if kind == "interactive":
            return SessionPlan(
                target_system=target_system,
                source_system=None,
                source_ip=source_ip_override or target_system.ip,
                logon_type=2,
                session_kind="interactive",
                requires_transport=False,
            )

        if kind == "network":
            source = source_system or self.pick_remote_source_system(user, target_system, rng)
            source_ip = source_ip_override or (
                source.ip if source is not None else target_system.ip
            )
            return SessionPlan(
                target_system=target_system,
                source_system=source,
                source_ip=source_ip,
                logon_type=3,
                session_kind="network",
                requires_transport=False,
            )

        source = source_system or self.pick_remote_source_system(user, target_system, rng)

        # RDP requires a Windows source — mstsc.exe can't exist on Linux.
        # If the selected source is non-Windows, downgrade to SSH or network.
        if kind == "rdp" and source is not None:
            source_host = self.hosts.get(source.hostname)
            if source_host and source_host.os_category != "windows":
                if host.supports_ssh:
                    kind = "ssh"
                else:
                    source = None  # will trigger fallback below

        if source is None:
            if source_ip_override:
                # Explicit source IP from storyline but no modeled source
                # host.  Keep the session kind so the transport connection
                # (port 22 / 3389) is still generated — we just won't have
                # source-side process evidence (mstsc.exe / ssh client).
                return SessionPlan(
                    target_system=target_system,
                    source_system=None,
                    source_ip=source_ip_override,
                    logon_type=10,
                    session_kind=kind,
                    requires_transport=True,
                )
            # No explicit IP and no suitable source — fall back.
            # RDP without a Windows source is impossible (no mstsc.exe),
            # so coerce for auto-selected sessions only.
            if kind == "rdp":
                kind = "ssh" if host.supports_ssh else "network"
            fallback_kind = (
                kind
                if kind in ("ssh", "network")
                else ("network" if host.is_server else "interactive")
            )
            return self.plan_session(
                user=user,
                target_system=target_system,
                rng=rng,
                session_kind=fallback_kind,
                source_system=None,
            )

        # If the caller specified a source IP that doesn't belong to the
        # auto-selected source system, don't attach internal host evidence
        # to the external IP — that creates impossible host↔network correlation.
        effective_source = source
        if source_ip_override and source is not None and source_ip_override != source.ip:
            effective_source = None

        return SessionPlan(
            target_system=target_system,
            source_system=effective_source,
            source_ip=source_ip_override or source.ip,
            logon_type=10,
            session_kind=kind,
            requires_transport=True,
        )


class WorldPlanner:
    """Operational planner that uses the compiled WorldModel."""

    def __init__(
        self,
        world_model: WorldModel,
        state_manager: StateManager,
        activity_generator: ActivityGenerator,
    ) -> None:
        self.world_model = world_model
        self.state_manager = state_manager
        self.activity_generator = activity_generator

    def ensure_user_session(
        self,
        user: User,
        target_system: System,
        time: datetime,
        rng: random.Random,
        session_kind: str | None = None,
        source_system: System | None = None,
        allow_existing: bool = True,
        storyline_protected: bool = False,
        required_until: datetime | None = None,
        session_end_plan: SessionEndPlan | None = None,
    ) -> ActiveSession:
        return self.bootstrap_user_session(
            user=user,
            target_system=target_system,
            time=time,
            rng=rng,
            session_kind=session_kind,
            source_system=source_system,
            allow_existing=allow_existing,
            storyline_protected=storyline_protected,
            required_until=required_until,
            session_end_plan=session_end_plan,
        ).session

    def _find_windows_interactive_session(
        self,
        username: str,
        target_system: System,
        at_time: datetime,
    ) -> ActiveSession | None:
        """Return a durable same-user Windows interactive session, if one exists."""
        host = self.world_model.hosts.get(target_system.hostname)
        if host is None or host.os_category != "windows":
            return None

        cutoff = at_time.replace(tzinfo=UTC) if at_time.tzinfo is None else at_time.astimezone(UTC)
        candidates = [
            session
            for session in self.state_manager.get_sessions_for_user_at(username, at_time)
            if session.system == target_system.hostname
            and session.logon_type in {2, 10, 11}
            and session.session_kind not in {"network", "service"}
            and self._session_start_sort_key(session) <= cutoff
        ]
        if not candidates:
            return None
        return max(candidates, key=self._session_start_sort_key)

    def bootstrap_user_session(
        self,
        user: User,
        target_system: System,
        time: datetime,
        rng: random.Random,
        session_kind: str | None = None,
        source_system: System | None = None,
        allow_existing: bool = True,
        source_ip_override: str | None = None,
        storyline_protected: bool = False,
        required_until: datetime | None = None,
        session_end_plan: SessionEndPlan | None = None,
    ) -> SessionBootstrapResult:
        if allow_existing and session_kind in (None, "interactive"):
            existing_interactive = self._find_windows_interactive_session(
                user.username,
                target_system,
                time,
            )
            if existing_interactive is not None:
                existing_interactive.last_activity_time = time
                if session_end_plan is not None:
                    self.state_manager.plan_session_end(
                        existing_interactive.logon_id,
                        session_end_plan,
                    )
                if storyline_protected:
                    existing_interactive.storyline_protected = True
                return SessionBootstrapResult(session=existing_interactive, network_uid=None)

        existing = self._find_user_session(
            user.username, target_system.hostname, session_kind, at_time=time
        )
        if allow_existing and existing is not None:
            # Require exact session_kind match when the caller specifies one.
            # Prevents interactive requests from reusing network/rdp sessions
            # and vice versa — each kind carries different transport evidence.
            transport_compatible = True
            if session_kind and existing.session_kind != session_kind:
                transport_compatible = False
            if (
                transport_compatible
                and required_until is not None
                and existing.session_kind == "ssh"
                and existing.network_close_time is not None
                and not (existing.end_plan and existing.end_plan.is_authoritative)
            ):
                required_until_utc = (
                    required_until.replace(tzinfo=UTC)
                    if required_until.tzinfo is None
                    else required_until.astimezone(UTC)
                )
                network_close_time = (
                    existing.network_close_time.replace(tzinfo=UTC)
                    if existing.network_close_time.tzinfo is None
                    else existing.network_close_time.astimezone(UTC)
                )
                if network_close_time < required_until_utc:
                    transport_compatible = False
            if transport_compatible:
                existing.last_activity_time = time
                if session_end_plan is not None:
                    self.state_manager.plan_session_end(existing.logon_id, session_end_plan)
                if existing.session_kind == "ssh":
                    ensure_shell = getattr(
                        self.activity_generator,
                        "ensure_linux_ssh_session_shell",
                        None,
                    )
                    if ensure_shell is not None:
                        ensure_shell(
                            user=user,
                            target_system=target_system,
                            logon_id=existing.logon_id,
                            logon_time=self._session_start_sort_key(existing),
                            activity_time=time,
                        )
                if storyline_protected:
                    existing.storyline_protected = True
                return SessionBootstrapResult(session=existing, network_uid=None)

        plan = self.world_model.plan_session(
            user=user,
            target_system=target_system,
            rng=rng,
            session_kind=session_kind,
            source_system=source_system,
            source_ip_override=source_ip_override,
        )
        if plan.session_kind == "ssh":
            # SSH emits connection, accepted-auth, PAM, eCAR session, then shell
            # process evidence. Give that source-native sequence room before
            # the first user-visible command tied to the session.
            logon_time = time - timedelta(seconds=rng.uniform(6.0, 12.0))
        elif plan.session_kind == "interactive" and _get_os_category(target_system.os) == "linux":
            logon_time = time - timedelta(seconds=rng.uniform(7.0, 15.0))
        else:
            logon_time = time - timedelta(seconds=rng.uniform(0.5, 5.0))
        self.state_manager.set_current_time(logon_time)

        if plan.session_kind == "ssh":
            result = self._bootstrap_ssh_session(
                user,
                plan,
                logon_time,
                time,
                rng,
                required_until=required_until,
                session_end_plan=session_end_plan,
            )
            if storyline_protected and result.session:
                result.session.storyline_protected = True
            return result
        if plan.session_kind == "rdp":
            result = self._bootstrap_rdp_session(
                user,
                plan,
                logon_time,
                time,
                rng,
                session_end_plan=session_end_plan,
            )
            if storyline_protected and result.session:
                result.session.storyline_protected = True
            return result

        logon_id = self.activity_generator.generate_logon(
            user=user,
            system=target_system,
            time=logon_time,
            logon_type=plan.logon_type,
            source_ip=plan.source_ip,
            session_end_plan=session_end_plan,
        )
        session = self.state_manager.get_session(logon_id)
        if session is None:
            raise RuntimeError(f"Failed to resolve planned session {logon_id} on {target_system}")
        session.last_activity_time = time
        if storyline_protected:
            session.storyline_protected = True
        return SessionBootstrapResult(session=session, network_uid=None)

    def ensure_connection_process(
        self,
        user: User,
        system: System,
        session: ActiveSession,
        time: datetime,
        service: str,
        rng: random.Random,
        effective_persona: str | None = None,
        destination_hostname: str | None = None,
    ) -> int:
        """Resolve or create a user process that can own a network connection.

        Args:
            effective_persona: Override persona for catalog filtering. When set
                (e.g. ``"_server_admin"``), restricts executables to those
                cataloged for this persona instead of the user's normal one.
            destination_hostname: Optional resolved destination hostname used to
                select a plausible owning app for generic services like SSL.
        """
        compatible_exes = get_service_to_exes().get(service, [])
        if not compatible_exes:
            return -1
        compatible_exes = [
            exe for exe in compatible_exes if exe.rsplit("/", 1)[-1].lower() not in _SHELL_EXES
        ]
        if not compatible_exes:
            return -1

        lock_time = getattr(self.activity_generator, "_last_workstation_lock_time", {}).get(
            (system.hostname, user.username, session.logon_id)
        )
        if lock_time is not None and ensure_utc(lock_time) <= ensure_utc(time):
            return -1

        destination_tags: set[str] = set()
        exe_tag_index: dict[str, set[str]] = {}
        if destination_hostname:
            from evidenceforge.generation.activity.dns_registry import get_domain_tags
            from evidenceforge.generation.activity.process_network import get_exe_to_service

            destination_tags = set(get_domain_tags(destination_hostname))
            exe_tag_index = {
                exe.lower(): set(info.get("dns_tags") or [])
                for exe, info in get_exe_to_service().items()
            }

        broad_tags = {"web", "saas", "cdn", "social", "background", "windows", "linux"}

        def _destination_score(exe: str) -> int:
            if not destination_tags:
                return 1
            exe_tags = exe_tag_index.get(exe.lower(), set())
            if not exe_tags:
                return 0
            specific = destination_tags - broad_tags
            specific_hits = len(exe_tags & specific)
            broad_hits = len(exe_tags & destination_tags & broad_tags)
            return specific_hits * 100 + broad_hits

        history_key = (system.hostname, user.username)
        history = self.activity_generator._user_process_history.get(history_key, [])
        best_existing: tuple[int, int, int] | None = None
        for idx, (pid, image) in enumerate(reversed(history)):
            proc = self.state_manager.get_process(system.hostname, pid)
            if proc is None or proc.start_time > time:
                continue
            if proc.logon_id and proc.logon_id != session.logon_id:
                continue
            exe = image.rsplit("\\", 1)[-1].rsplit("/", 1)[-1].lower()
            if exe in _SHELL_EXES:
                continue
            if exe in compatible_exes:
                score = _destination_score(exe)
                if score > 0 and (best_existing is None or (score, -idx) > best_existing[:2]):
                    best_existing = (score, -idx, pid)
        if best_existing is not None:
            return best_existing[2]

        from evidenceforge.generation.activity.application_catalog import (
            get_app_categories,
            has_catalog_entry,
            is_persona_allowed,
            is_system_type_allowed,
            load_catalog,
            resolve_image_path,
        )

        os_cat = self.world_model.hosts[system.hostname].os_category
        # _server_admin is a policy overlay: use the user's real persona for
        # catalog eligibility, then exclude browser/office categories that
        # are inappropriate on servers (no Chrome/Outlook on DC via RDP).
        # Also merge sysadmin access so non-sysadmin personas (developer,
        # security_analyst) can use admin tools (dsquery, ldapsearch) when
        # doing remote server administration.
        is_server_admin = effective_persona == "_server_admin"
        persona = (user.persona or "default").lower()
        _SERVER_EXCLUDED_CATEGORIES = {"browser", "office", "code", "build"}

        def _is_allowed(exe: str) -> bool:
            if not has_catalog_entry(exe, os_cat):
                return False
            system_type = getattr(system, "type", None)
            if not is_system_type_allowed(exe, os_cat, system_type):
                return False
            allowed = is_persona_allowed(exe, os_cat, persona)
            # Server-admin sessions also grant sysadmin-level tool access
            if not allowed and is_server_admin:
                allowed = is_persona_allowed(exe, os_cat, "sysadmin")
            if allowed and is_server_admin:
                cats = get_app_categories(exe, os_cat)
                if _SERVER_EXCLUDED_CATEGORIES.intersection(cats):
                    return False
            return allowed

        os_exes = [e for e in compatible_exes if _is_allowed(e)]
        if destination_tags:
            scored_exes = [(e, _destination_score(e)) for e in os_exes]
            os_exes = [e for e, score in scored_exes if score > 0]
        if not os_exes:
            # No persona-approved executable for this service — don't
            # relax past the allowlist (that would spawn forbidden tools
            # like sqlcmd.exe for accountants).  Return -1 (no owning process).
            return -1
        if destination_tags:
            weights = [_destination_score(e) for e in os_exes]
            target_exe = rng.choices(os_exes, weights=weights, k=1)[0]
        else:
            target_exe = rng.choice(os_exes)
        image = resolve_image_path(target_exe, os_cat, username=user.username)

        # Build a realistic command line from the catalog template when
        # available, instead of emitting the bare executable name.
        command_line = target_exe
        catalog = load_catalog()
        for app in catalog.get("applications", []):
            plat = app.get("platforms", {}).get(os_cat)
            if not plat:
                continue
            plat_image = plat.get("image_path", "")
            plat_exe = plat_image.rsplit("\\", 1)[-1].rsplit("/", 1)[-1].lower()
            if plat_exe == target_exe.lower() or plat_exe.replace(".exe", "") == target_exe.lower():
                templates = plat.get("command_templates", [])
                if templates:
                    command_line = rng.choice(templates)
                    command_line = self.activity_generator._parameterize_command_for_system(
                        rng,
                        command_line,
                        username=user.username,
                        system=system,
                    )
                break

        # Backdate the process slightly, but never before the session started
        proc_time = time - timedelta(seconds=rng.uniform(0.5, 3.0))
        min_proc_time = session.start_time + timedelta(milliseconds=100)
        if proc_time < min_proc_time:
            proc_time = min_proc_time
        self.state_manager.set_current_time(proc_time)
        parent_pid = self.activity_generator._resolve_parent(
            system, user, proc_time, session.logon_id, image
        )
        pid = self.activity_generator.generate_process(
            user=user,
            system=system,
            time=proc_time,
            logon_id=session.logon_id,
            process_name=image,
            command_line=command_line,
            parent_pid=parent_pid,
        )
        if target_exe.lower() == "ldapsearch":
            lifetime = _linux_foreground_lifetime(image, command_line) or (0.5, 4.0)
            termination_time = time + timedelta(seconds=rng.uniform(*lifetime))
            self.activity_generator._remember_foreground_process_finalizer(
                system=system,
                user=user,
                pid=pid,
                process_name=image,
                logon_id=session.logon_id,
                termination_time=termination_time,
            )
        self.activity_generator._record_user_process(system, user, pid, image)
        return pid

    def _find_user_session(
        self,
        username: str,
        hostname: str,
        session_kind: str | None = None,
        at_time: datetime | None = None,
    ) -> ActiveSession | None:
        """Find the newest compatible session for a user on a host.

        Prefers an exact session_kind match; falls back to any host session.
        Returns the most recent session (by start_time) to avoid picking
        stale network sessions over newer SSH/RDP ones.
        """
        sessions = (
            self.state_manager.get_sessions_for_user_at(username, at_time)
            if at_time is not None
            else self.state_manager.get_sessions_for_user(username)
        )
        host_sessions = [s for s in sessions if s.system == hostname]
        if at_time is not None:
            cutoff = (
                at_time.replace(tzinfo=UTC) if at_time.tzinfo is None else at_time.astimezone(UTC)
            )
            host_sessions = [s for s in host_sessions if self._session_start_sort_key(s) <= cutoff]
        if not host_sessions:
            return None
        if session_kind:
            exact = [s for s in host_sessions if s.session_kind == session_kind]
            if exact:
                return max(exact, key=self._session_start_sort_key)
        return max(host_sessions, key=self._session_start_sort_key)

    @staticmethod
    def _session_start_sort_key(session: ActiveSession) -> datetime:
        """Normalize session start_time so mixed aware/naive datetimes can be ordered safely."""
        start_time = session.start_time
        if start_time.tzinfo is None:
            return start_time.replace(tzinfo=UTC)
        return start_time.astimezone(UTC)

    def _bootstrap_ssh_session(
        self,
        user: User,
        plan: SessionPlan,
        logon_time: datetime,
        activity_time: datetime,
        rng: random.Random,
        required_until: datetime | None = None,
        session_end_plan: SessionEndPlan | None = None,
    ) -> SessionBootstrapResult:
        source_os = (
            self.world_model.hosts[plan.source_system.hostname].os_category
            if plan.source_system is not None
            else "windows"
        )
        source_port = _ephemeral_port(rng, source_os)
        min_duration = max(
            30.0,
            (activity_time - logon_time).total_seconds() + rng.uniform(2.0, 20.0),
        )
        if required_until is not None and session_end_plan is None:
            required_until = (
                required_until.replace(tzinfo=UTC)
                if required_until.tzinfo is None
                else required_until.astimezone(UTC)
            )
            min_duration = max(
                min_duration,
                (required_until - logon_time).total_seconds() + rng.uniform(20.0, 90.0),
            )
        uid, logon_id = self.activity_generator._execute_ssh_session_bundle(
            user=user,
            target_system=plan.target_system,
            time=logon_time,
            source_ip=plan.source_ip,
            source_system=plan.source_system,
            source_port=source_port,
            min_duration=min_duration,
            session_end_plan=session_end_plan,
        )
        session = self.state_manager.get_session(logon_id)
        if session is None:
            raise RuntimeError(f"Failed to resolve SSH session {logon_id}")
        session.last_activity_time = max(
            marker
            for marker in (session.last_activity_time, session.network_close_time, activity_time)
            if marker is not None
        )

        # Create visible per-session sshd child + bash login shell for realistic
        # Linux process trees. Each SSH session gets its own sshd fork
        # (privilege separation) and bash PID so user commands have distinct
        # parent PIDs and eCAR can observe the parent lifecycle.
        ensure_shell = getattr(self.activity_generator, "ensure_linux_ssh_session_shell", None)
        if ensure_shell is not None:
            ensure_shell(
                user=user,
                target_system=plan.target_system,
                logon_id=logon_id,
                logon_time=logon_time,
                activity_time=activity_time,
            )

        return SessionBootstrapResult(session=session, network_uid=uid)

    def _bootstrap_rdp_session(
        self,
        user: User,
        plan: SessionPlan,
        logon_time: datetime,
        activity_time: datetime,
        rng: random.Random,
        session_end_plan: SessionEndPlan | None = None,
    ) -> SessionBootstrapResult:
        source_pid = -1
        source_process_time = logon_time - timedelta(milliseconds=rng.randint(1800, 3200))
        source_process_factory = None
        if plan.source_system is not None:
            aligned_source_time = self._align_rdp_source_after_future_workstation_session(
                username=user.username,
                source_system=plan.source_system,
                source_process_time=source_process_time,
                rng=rng,
            )
            if aligned_source_time > source_process_time:
                shift = aligned_source_time - source_process_time
                source_process_time = aligned_source_time
                logon_time += shift
                activity_time += shift
            source_process_factory = self._rdp_source_process_factory(rng)
        uid, logon_id = self.activity_generator._execute_rdp_session_bundle(
            user=user,
            target_system=plan.target_system,
            time=logon_time,
            source_ip=plan.source_ip,
            source_system=plan.source_system,
            source_pid=source_pid,
            source_process_time=source_process_time if plan.source_system is not None else None,
            source_process_factory=source_process_factory,
            session_end_plan=session_end_plan,
        )
        session = self.state_manager.get_session(logon_id)
        if session is None:
            raise RuntimeError(
                f"Failed to resolve planned RDP session {logon_id} on {plan.target_system.hostname}"
            )
        session.last_activity_time = activity_time
        return SessionBootstrapResult(session=session, network_uid=uid)

    def _rdp_source_process_factory(self, rng: random.Random) -> Callable[..., int]:
        """Return a callback that materializes source-side mstsc.exe inside the bundle."""

        def materialize(
            *,
            user: User,
            source_system: System,
            target_system: System,
            time: datetime,
        ) -> int:
            return self._ensure_rdp_client_process(
                user=user,
                source_system=source_system,
                target_system=target_system,
                time=time,
                rng=rng,
            )

        return materialize

    def _align_rdp_source_after_future_workstation_session(
        self,
        *,
        username: str,
        source_system: System,
        source_process_time: datetime,
        rng: random.Random,
    ) -> datetime:
        """Move source-side RDP work after an already-planned workstation session."""
        host = self.world_model.hosts.get(source_system.hostname)
        if host is None or host.os_category != "windows":
            return source_process_time

        source_utc = (
            source_process_time.replace(tzinfo=UTC)
            if source_process_time.tzinfo is None
            else source_process_time.astimezone(UTC)
        )
        hour_end = source_utc.replace(minute=0, second=0, microsecond=0) + timedelta(hours=1)
        future_sessions = [
            session
            for session in self.state_manager.get_sessions_for_user(username)
            if session.system == source_system.hostname
            and session.logon_type in {2, 10, 11}
            and session.session_kind not in {"network", "service"}
            and source_utc < self._session_start_sort_key(session) < hour_end
        ]
        if not future_sessions:
            return source_process_time

        next_session = min(future_sessions, key=self._session_start_sort_key)
        aligned_utc = self._session_start_sort_key(next_session) + timedelta(
            seconds=rng.uniform(20.0, 90.0)
        )
        if aligned_utc >= hour_end:
            return source_process_time
        if source_process_time.tzinfo is None:
            return aligned_utc.replace(tzinfo=None)
        return aligned_utc.astimezone(source_process_time.tzinfo)

    def _ensure_rdp_client_process(
        self,
        user: User,
        source_system: System,
        target_system: System,
        time: datetime,
        rng: random.Random,
    ) -> int:
        source_session = self.ensure_user_session(
            user=user,
            target_system=source_system,
            time=time,
            rng=rng,
            session_kind="interactive",
            allow_existing=True,
        )
        parent_pid = source_session.explorer_pid or source_session.process_tree_root
        if parent_pid is None:
            sys_pids = getattr(self.activity_generator, "_system_pids", {}).get(
                source_system.hostname, {}
            )
            parent_pid = sys_pids.get(
                "explorer", sys_pids.get("winlogon", sys_pids.get("services", 4))
            )
        self.state_manager.set_current_time(time)
        pid = self.activity_generator.generate_process(
            user=user,
            system=source_system,
            time=time,
            logon_id=source_session.logon_id,
            process_name=r"C:\Windows\System32\mstsc.exe",
            command_line=f"mstsc.exe /v:{target_system.hostname}",
            parent_pid=parent_pid,
        )
        self.activity_generator._record_user_process(
            source_system,
            user,
            pid,
            r"C:\Windows\System32\mstsc.exe",
        )
        return pid
