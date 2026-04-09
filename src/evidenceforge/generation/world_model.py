"""Compiled world-model and session/activity planners.

The canonical event model guarantees field consistency once a SecurityEvent
exists. This module adds the missing "why would this happen here?" layer:

- resolve authoritative host capabilities and infrastructure roles once
- resolve user placement and remote-admin source systems once
- centralize session bootstrap (interactive, SSH, RDP, network)
- centralize process-first attribution for persona traffic
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import TYPE_CHECKING, Any

from evidenceforge.generation.activity.generator import _ephemeral_port
from evidenceforge.generation.activity.helpers import _get_os_category
from evidenceforge.generation.activity.process_network import get_service_to_exes
from evidenceforge.models.state import ActiveSession
from evidenceforge.utils.rng import _stable_seed

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
    (("dns", "bind", "named"), "dns_server"),
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

_ADMIN_PERSONAS = {"sysadmin", "help_desk"}

_DB_PORTS = {
    "mssql": 1433,
    "mysql": 3306,
    "postgresql": 5432,
}


def _normalize_role_name(role: str) -> str:
    key = role.strip().lower().replace("-", "_").replace(" ", "_")
    return _ROLE_ALIASES.get(key, key)


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
        service_blob = " ".join(service.lower() for service in service_values)
        hostname_lower = system.hostname.lower()

        if system.type == "domain_controller":
            roles.update({"domain_controller", "dns_server"})
        elif system.type == "workstation":
            roles.add("workstation")

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
            service_names = [service.lower() for service in self.hosts[system.hostname].services]
            db_service = "mssql"
            if any("postgres" in service for service in service_names):
                db_service = "postgresql"
            elif any("mysql" in service or "maria" in service for service in service_names):
                db_service = "mysql"
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
        return ["129.6.15.28", "132.163.97.1"]

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

    def resolve_destination(
        self,
        dest_role: str,
        src_system: System,
        rng: random.Random,
        os_category: str = "windows",
        dns_tags: list[str] | None = None,
    ) -> tuple[str | None, str | None]:
        """Resolve a profile destination role to a concrete IP and hostname."""
        if dest_role == "_external":
            from evidenceforge.generation.activity.dns_registry import pick_domain_and_ip

            tags = tuple(dns_tags) if dns_tags else ("background", os_category)
            domain, ip = pick_domain_and_ip(rng, *tags, src_host=src_system.hostname)
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
            # No suitable source system — if we have an explicit IP from
            # the storyline, use it directly with a network logon.
            # RDP without a Windows source_system is impossible (no mstsc.exe),
            # so coerce to SSH or network.
            if kind == "rdp":
                kind = "ssh" if host.supports_ssh else "network"
            if source_ip_override:
                return SessionPlan(
                    target_system=target_system,
                    source_system=None,
                    source_ip=source_ip_override,
                    logon_type=10,
                    session_kind=kind,
                    requires_transport=True,
                )
            fallback_kind = "network" if host.is_server else "interactive"
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
    ) -> ActiveSession:
        return self.bootstrap_user_session(
            user=user,
            target_system=target_system,
            time=time,
            rng=rng,
            session_kind=session_kind,
            source_system=source_system,
            allow_existing=allow_existing,
        ).session

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
    ) -> SessionBootstrapResult:
        existing = self._find_user_session(user.username, target_system.hostname)
        if allow_existing and existing is not None:
            existing.last_activity_time = time
            return SessionBootstrapResult(session=existing, network_uid=None)

        plan = self.world_model.plan_session(
            user=user,
            target_system=target_system,
            rng=rng,
            session_kind=session_kind,
            source_system=source_system,
            source_ip_override=source_ip_override,
        )
        logon_time = time - timedelta(seconds=rng.uniform(0.5, 5.0))
        self.state_manager.set_current_time(logon_time)

        if plan.session_kind == "ssh":
            return self._bootstrap_ssh_session(user, plan, logon_time, time, rng)
        if plan.session_kind == "rdp":
            return self._bootstrap_rdp_session(user, plan, logon_time, time, rng)

        logon_id = self.state_manager.create_session(
            username=user.username,
            system=target_system.hostname,
            logon_type=plan.logon_type,
            source_ip=plan.source_ip,
            session_kind=plan.session_kind,
        )
        self.activity_generator.generate_logon(
            user=user,
            system=target_system,
            time=logon_time,
            logon_type=plan.logon_type,
            source_ip=plan.source_ip,
            logon_id=logon_id,
        )
        session = self.state_manager.get_session(logon_id)
        if session is None:
            raise RuntimeError(f"Failed to resolve planned session {logon_id} on {target_system}")
        session.last_activity_time = time
        return SessionBootstrapResult(session=session, network_uid=None)

    def ensure_connection_process(
        self,
        user: User,
        system: System,
        session: ActiveSession,
        time: datetime,
        service: str,
        rng: random.Random,
    ) -> int:
        """Resolve or create a user process that can own a network connection."""
        compatible_exes = get_service_to_exes().get(service, [])
        if not compatible_exes:
            return -1

        history_key = (system.hostname, user.username)
        history = self.activity_generator._user_process_history.get(history_key, [])
        for pid, image in reversed(history):
            proc = self.state_manager.get_process(system.hostname, pid)
            if proc is None or proc.start_time > time:
                continue
            if proc.logon_id and proc.logon_id != session.logon_id:
                continue
            exe = image.rsplit("\\", 1)[-1].rsplit("/", 1)[-1].lower()
            if exe in compatible_exes:
                return pid

        from evidenceforge.generation.activity.application_catalog import (
            has_catalog_entry,
            is_persona_allowed,
            load_catalog,
            resolve_image_path,
        )
        from evidenceforge.generation.activity.helpers import _parameterize_command

        os_cat = self.world_model.hosts[system.hostname].os_category
        persona = (user.persona or "default").lower()
        # Filter to executables that exist in the catalog for this OS AND
        # are allowed for this user's persona (prevents dev tools on HR)
        os_exes = [
            e
            for e in compatible_exes
            if has_catalog_entry(e, os_cat) and is_persona_allowed(e, os_cat, persona)
        ]
        if not os_exes:
            # Relax to OS-only filter
            os_exes = [e for e in compatible_exes if has_catalog_entry(e, os_cat)]
        if not os_exes:
            os_exes = compatible_exes
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
                    command_line = _parameterize_command(rng, command_line, username=user.username)
                break

        proc_time = time - timedelta(seconds=rng.uniform(0.5, 3.0))
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
        self.activity_generator._record_user_process(system, user, pid, image)
        return pid

    def _find_user_session(self, username: str, hostname: str) -> ActiveSession | None:
        sessions = self.state_manager.get_sessions_for_user(username)
        return next((session for session in sessions if session.system == hostname), None)

    def _bootstrap_ssh_session(
        self,
        user: User,
        plan: SessionPlan,
        logon_time: datetime,
        activity_time: datetime,
        rng: random.Random,
    ) -> SessionBootstrapResult:
        source_os = (
            self.world_model.hosts[plan.source_system.hostname].os_category
            if plan.source_system is not None
            else "windows"
        )
        source_port = _ephemeral_port(rng, source_os)
        logon_id = self.state_manager.create_session(
            username=user.username,
            system=plan.target_system.hostname,
            logon_type=plan.logon_type,
            source_ip=plan.source_ip,
            source_port=source_port,
            session_kind="ssh",
        )
        sshd_pid = 1000 + (_stable_seed(f"sshd_pid_{logon_id}") % 59000)
        self.state_manager.update_session_metadata(logon_id, transport_pid=sshd_pid)
        session_obj_id = self.state_manager.get_session_object_id(logon_id)
        uid = self.activity_generator.generate_ssh_session(
            user=user,
            target_system=plan.target_system,
            time=logon_time,
            source_ip=plan.source_ip,
            source_system=plan.source_system,
            source_port=source_port,
            sshd_pid=sshd_pid,
            logon_id=logon_id,
            session_obj_id=session_obj_id,
        )
        session = self.state_manager.get_session(logon_id)
        if session is None:
            raise RuntimeError(f"Failed to resolve SSH session {logon_id}")
        session.last_activity_time = activity_time
        return SessionBootstrapResult(session=session, network_uid=uid)

    def _bootstrap_rdp_session(
        self,
        user: User,
        plan: SessionPlan,
        logon_time: datetime,
        activity_time: datetime,
        rng: random.Random,
    ) -> SessionBootstrapResult:
        source_pid = -1
        if plan.source_system is not None:
            source_pid = self._ensure_rdp_client_process(
                user=user,
                source_system=plan.source_system,
                target_system=plan.target_system,
                time=logon_time - timedelta(milliseconds=rng.randint(50, 300)),
                rng=rng,
            )
        logon_id = self.state_manager.create_session(
            username=user.username,
            system=plan.target_system.hostname,
            logon_type=plan.logon_type,
            source_ip=plan.source_ip,
            session_kind="rdp",
        )
        uid = self.activity_generator.generate_rdp_session(
            user=user,
            target_system=plan.target_system,
            time=logon_time,
            source_ip=plan.source_ip,
            source_system=plan.source_system,
            source_pid=source_pid,
            logon_id=logon_id,
        )
        session = self.state_manager.get_session(logon_id)
        if session is None:
            raise RuntimeError(
                f"Failed to resolve planned RDP session {logon_id} on {plan.target_system.hostname}"
            )
        session.last_activity_time = activity_time
        return SessionBootstrapResult(session=session, network_uid=uid)

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
            parent_pid = sys_pids.get("explorer", 4)
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
