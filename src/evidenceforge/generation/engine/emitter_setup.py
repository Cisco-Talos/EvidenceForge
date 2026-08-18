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

"""Emitter initialization, format group expansion, and infrastructure setup.

Contains the EmitterSetupMixin with methods for:
- Emitter class mapping and initialization
- Proxy routing
- Sensor startup/DHCP emission
- System process tree seeding
- Infrastructure detection
- SID registry building
"""

import hashlib
import logging
import random
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from evidenceforge.formats import load_format
from evidenceforge.generation.actions import dhcp_renewal_interval_seconds
from evidenceforge.generation.activity.edr_pools import normalize_defender_platform_path
from evidenceforge.generation.activity.network_params import (
    external_client_excluded_cidrs,
    load_network_params,
)
from evidenceforge.generation.activity.smb_profiles import (
    render_process as render_smb_process,
)
from evidenceforge.generation.activity.smb_profiles import (
    select_server_profile,
)
from evidenceforge.generation.emitters import (
    BashHistoryEmitter,
    CiscoAsaEmitter,
    EcarEmitter,
    ProxyEmitter,
    SnortEmitter,
    SyslogEmitter,
    SysmonEventEmitter,
    WebEmitter,
    WindowsEventEmitter,
    ZeekDhcpEmitter,
    ZeekDnsEmitter,
    ZeekEmitter,
    ZeekFilesEmitter,
    ZeekHttpEmitter,
    ZeekNtpEmitter,
    ZeekOcspEmitter,
    ZeekPacketFilterEmitter,
    ZeekPeEmitter,
    ZeekReporterEmitter,
    ZeekSmbFilesEmitter,
    ZeekSmbMappingEmitter,
    ZeekSmtpEmitter,
    ZeekSslEmitter,
    ZeekWeirdEmitter,
    ZeekX509Emitter,
)
from evidenceforge.generation.identity import IdentityDirectory
from evidenceforge.generation.lifecycle_authority import (
    GeneratorLifecycleAuthority,
    LifecycleMaterializationBatchPlanningAttempt,
    LifecycleMaterializationBatchPlanningCapability,
    LifecycleMaterializationBatchTerminalResult,
    LifecycleMaterializationBatchTransaction,
)
from evidenceforge.generation.lifecycle_registry import LifecycleRegistry
from evidenceforge.generation.state_manager import (
    MaterializationBatchBuilder,
    ProcessMaterializationPlan,
)
from evidenceforge.generation.world_model import (
    HostCapability,
    WorldModel,
    database_services_for_host,
)
from evidenceforge.models.exceptions import StateError
from evidenceforge.models.scenario import System
from evidenceforge.utils.rng import _stable_seed, stable_uuid

logger = logging.getLogger(__name__)


@dataclass(frozen=True, slots=True)
class _BootProcessSpec:
    """One allocation-free symbolic member of a boot process forest."""

    alias: str
    parent_alias: str | None
    fixed_pid: int | None
    image: str
    command_line: str
    username: str
    integrity_level: str
    os_category: str
    logon_id: str
    start_time: datetime | None

    def canonical_payload(self) -> tuple[object, ...]:
        """Return the exact immutable request projection used by planning."""

        return (
            self.alias,
            self.parent_alias,
            self.fixed_pid,
            self.image,
            self.command_line,
            self.username,
            self.integrity_level,
            self.os_category,
            self.logon_id,
            self.start_time,
        )


@dataclass(frozen=True, slots=True)
class _BootHostSpec:
    """One host's exact symbolic process forest and durable boot metadata."""

    hostname: str
    os_category: str
    boot_time: datetime | None
    machine_id: str
    processes: tuple[_BootProcessSpec, ...]
    aliases: tuple[tuple[str, str], ...]

    def canonical_payload(self) -> tuple[object, ...]:
        """Return every value that can affect State planning or engine PID maps."""

        return (
            self.hostname,
            self.os_category,
            self.boot_time,
            self.machine_id,
            tuple(member.canonical_payload() for member in self.processes),
            self.aliases,
        )


@dataclass(frozen=True, slots=True)
class BootFleetSpec:
    """Allocation-free complete input to one atomic fleet boot materialization."""

    state_time: datetime | None
    hosts: tuple[_BootHostSpec, ...]

    def canonical_payload(self) -> tuple[object, ...]:
        """Return the single immutable projection shared by hashing and planning."""

        return (
            "boot-process-fleet-spec-v2",
            self.state_time,
            tuple(host.canonical_payload() for host in self.hosts),
        )


def _canonical_boot_payload_bytes(value: object) -> bytes:
    """Encode an exact inert boot payload without invoking caller-defined methods."""

    if value is None:
        return b"n"
    if type(value) is bool:
        return b"b1" if value else b"b0"
    if type(value) is int:
        encoded = str(value).encode("ascii")
        return b"i" + str(len(encoded)).encode("ascii") + b":" + encoded
    if type(value) is str:
        encoded = value.encode("utf-8")
        return b"s" + str(len(encoded)).encode("ascii") + b":" + encoded
    if type(value) is datetime:
        if value.tzinfo is not UTC:
            raise StateError("Boot fleet datetimes must use the exact UTC timezone")
        encoded = value.isoformat(timespec="microseconds").encode("ascii")
        return b"d" + str(len(encoded)).encode("ascii") + b":" + encoded
    if type(value) is tuple:
        members = tuple(_canonical_boot_payload_bytes(member) for member in value)
        return (
            b"t"
            + str(len(members)).encode("ascii")
            + b":"
            + b"".join(str(len(member)).encode("ascii") + b":" + member for member in members)
        )
    raise StateError("Boot fleet specifications require exact inert built-in values")


def _system_uses_dhcp(system: System) -> bool:
    """Return whether baseline should model this host as a DHCP client."""
    system_type = str(getattr(system, "type", "") or "").lower()
    services = {str(s).lower() for s in (getattr(system, "services", []) or [])}
    roles = {str(r).lower() for r in (getattr(system, "roles", []) or [])}
    if "dhclient" in services:
        return True
    if system_type == "workstation":
        return True
    static_roles = {
        "domain_controller",
        "dns_server",
        "file_server",
        "web_server",
        "forward_proxy",
        "app_server",
        "database",
    }
    return not roles.intersection(static_roles) and system_type not in {
        "server",
        "domain_controller",
    }


def _has_dhcp_event(step: object) -> bool:
    """Return whether a storyline step contains an explicit DHCP lease event."""

    return any(
        getattr(event, "type", None) == "dhcp_lease" for event in getattr(step, "events", [])
    )


def _build_emitter_classes() -> dict:
    """Build emitter class map at call time (supports test patching of module-level names)."""
    return {
        "windows_event_security": WindowsEventEmitter,
        "windows_event_sysmon": SysmonEventEmitter,
        "zeek_conn": ZeekEmitter,
        "zeek_dns": ZeekDnsEmitter,
        "zeek_http": ZeekHttpEmitter,
        "zeek_smtp": ZeekSmtpEmitter,
        "zeek_ssl": ZeekSslEmitter,
        "zeek_files": ZeekFilesEmitter,
        "zeek_smb_files": ZeekSmbFilesEmitter,
        "zeek_smb_mapping": ZeekSmbMappingEmitter,
        "zeek_dhcp": ZeekDhcpEmitter,
        "zeek_ntp": ZeekNtpEmitter,
        "zeek_weird": ZeekWeirdEmitter,
        "zeek_x509": ZeekX509Emitter,
        "zeek_ocsp": ZeekOcspEmitter,
        "zeek_pe": ZeekPeEmitter,
        "zeek_packet_filter": ZeekPacketFilterEmitter,
        "zeek_reporter": ZeekReporterEmitter,
        "ecar": EcarEmitter,
        "syslog": SyslogEmitter,
        "bash_history": BashHistoryEmitter,
        "snort_alert": SnortEmitter,
        "cisco_asa": CiscoAsaEmitter,
        "web_access": WebEmitter,
        "proxy_access": ProxyEmitter,
    }


_ZEEK_FORMAT_NAMES = {
    "zeek_conn",
    "zeek_dns",
    "zeek_http",
    "zeek_smtp",
    "zeek_ssl",
    "zeek_files",
    "zeek_smb_files",
    "zeek_smb_mapping",
    "zeek_dhcp",
    "zeek_ntp",
    "zeek_weird",
    "zeek_x509",
    "zeek_ocsp",
    "zeek_pe",
    "zeek_packet_filter",
    "zeek_reporter",
}
_ZEEK_FORMATS = _ZEEK_FORMAT_NAMES
# Network sensor formats get per-sensor dirs; host-based formats get per-host FQDN dirs
_SENSOR_FORMATS = _ZEEK_FORMATS | {"snort_alert", "cisco_asa"}
_HOST_FORMATS = {
    "windows_event_security",
    "windows_event_sysmon",
    "ecar",
    "syslog",
    "bash_history",
    "web_access",
    "proxy_access",
}


class EmitterSetupMixin:
    """Mixin providing emitter initialization and infrastructure setup methods."""

    def _storyline_dhcp_lease_times_by_host(self) -> dict[str, list[datetime]]:
        """Return explicit storyline DHCP lease times grouped by host."""

        cached = getattr(self, "_storyline_dhcp_times_by_host", None)
        if cached is not None:
            return cached

        times_by_host: dict[str, list[datetime]] = {}
        for step in self.scenario.storyline or []:
            hostname = getattr(step, "system", "")
            if not hostname or not _has_dhcp_event(step):
                continue
            times_by_host.setdefault(hostname, []).append(self._parse_storyline_time(step.time))
        for times in times_by_host.values():
            times.sort()
        self._storyline_dhcp_times_by_host = times_by_host
        return times_by_host

    def _storyline_dhcp_lease_time_in_hour(
        self,
        hostname: str,
        current_hour: datetime,
    ) -> datetime | None:
        """Return the explicit DHCP storyline time for a host in the current hour."""

        hour_start = current_hour.replace(minute=0, second=0, microsecond=0)
        hour_end = hour_start + timedelta(hours=1)
        for event_time in self._storyline_dhcp_lease_times_by_host().get(hostname, []):
            if hour_start <= event_time < hour_end:
                return event_time
        return None

    def _init_emitters(self) -> None:
        """Initialize emitters for each requested format.

        Expands group format names, creates per-format emitter instances
        with appropriate directory routing (sensor-based or host-based).
        """
        from evidenceforge.events.dispatcher import expand_formats

        requested = {log["format"] for log in self.scenario.output.logs if "format" in log}
        formats_to_generate = expand_formats(requested)

        emitter_classes = _build_emitter_classes()

        # Build per-format sensor hostname mapping (expand group names)
        _sensor_hostnames_by_format: dict[str, list[str]] = {}
        if self.scenario.environment.network and self.scenario.environment.network.sensors:
            for s in self.scenario.environment.network.sensors:
                hostname = s.hostname or s.name
                for fmt in expand_formats(s.log_formats):
                    _sensor_hostnames_by_format.setdefault(fmt, []).append(hostname)

        for format_name in sorted(formats_to_generate):
            if format_name not in emitter_classes:
                logger.debug(f"No emitter class for format: {format_name}")
                continue
            format_def = load_format(format_name)

            if format_name in _SENSOR_FORMATS:
                sensor_hostnames = _sensor_hostnames_by_format.get(format_name, [])
                emitter_class = emitter_classes[format_name]
                emitter = emitter_class(
                    format_def,
                    self.output_dir,
                    threaded=True,
                    sensor_hostnames=sensor_hostnames,
                )
            elif format_name in _HOST_FORMATS:
                emitter = emitter_classes[format_name](format_def, self.output_dir, threaded=True)
            else:
                output_path = self.output_dir / f"{format_name}{format_def.output.file_extension}"
                emitter = emitter_classes[format_name](format_def, output_path, threaded=True)

            emitter.configure_output_target(self.output_target)
            self.emitters[format_name] = emitter
            logger.info(f"Initialized {format_name} emitter (threaded)")

        # Configure ASA emitters with network topology for interface resolution
        if "cisco_asa" in self.emitters:
            asa_emitter = self.emitters["cisco_asa"]
            if self.scenario.environment.network:
                asa_emitter._segment_config = [
                    {"name": seg.name, "cidr": seg.cidr}
                    for seg in self.scenario.environment.network.segments
                ]
                for sensor in self.scenario.environment.network.sensors:
                    if sensor.interfaces:
                        hostname = sensor.hostname or sensor.name
                        asa_emitter._sensor_interfaces[hostname] = sensor.interfaces
                        asa_emitter._sensor_security_levels[hostname] = (
                            sensor.interface_security_levels
                        )
                    if sensor.type == "firewall":
                        asa_emitter._td_burst_threshold = sensor.threat_detection_rate
                        asa_emitter._td_avg_threshold = max(1, sensor.threat_detection_rate // 2)
                        # Pass VIP→real_ip for interface resolution
                        for rule in sensor.nat_rules:
                            if rule.type == "static" and rule.mapped_ip and rule.real_ip:
                                asa_emitter._vip_to_real_ip[rule.mapped_ip] = rule.real_ip

    def _build_proxy_routes(self) -> None:
        """Build proxy routing table: which systems route through which proxies.

        Default: all internal systems route outbound HTTP/HTTPS through any
        forward_proxy in the scenario. With multiple proxies, internal segments
        route through the first proxy found, which may chain to another.
        """
        if hasattr(self, "world_model"):
            self._proxy_routes = dict(self.world_model.proxy_routes)
            if self._proxy_routes:
                proxy = next(iter(self._proxy_routes.values()))[0]
                logger.info(
                    "Proxy routing: %d systems -> %s",
                    len(self._proxy_routes),
                    proxy.hostname,
                )
            return

        proxies = [
            s for s in self.scenario.environment.systems if "forward_proxy" in (s.roles or [])
        ]
        if not proxies or "proxy_access" not in self.emitters:
            return

        proxy = proxies[0]
        for system in self.scenario.environment.systems:
            if "forward_proxy" in (system.roles or []):
                continue
            self._proxy_routes[system.ip] = [proxy]
        logger.info(f"Proxy routing: {len(self._proxy_routes)} systems -> {proxy.hostname}")

    def _get_proxy_for_system(self, system) -> "System | None":
        """Get the first proxy in the chain for a given system, or None."""
        chain = self._proxy_routes.get(system.ip)
        return chain[0] if chain else None

    def _emit_sensor_startup(self) -> None:
        """Emit Zeek sensor startup records (packet_filter.log, reporter.log).

        Fired once per sensor at scenario start time.
        """
        if not self.scenario.environment.network:
            return
        from evidenceforge.events.dispatcher import expand_formats

        rng = random.Random(_stable_seed("sensor_startup"))
        for sensor in self.scenario.environment.network.sensors:
            sensor_fmts = expand_formats(sensor.log_formats)
            if not any(f.startswith("zeek_") for f in sensor_fmts):
                continue
            hostname = sensor.hostname or sensor.name
            ts = self.start_time + timedelta(seconds=rng.uniform(0.1, 2.0))

            reporter_msgs: list[tuple[str, str]] = []
            if "zeek_reporter" in self.emitters:
                reporter_msgs = [
                    ("Reporter::INFO", "zeek_init() called"),
                    ("Reporter::INFO", f"listening on {rng.choice(['eth0', 'ens160', 'ens192'])}"),
                    ("Reporter::INFO", "loaded base/frameworks/notice/main.zeek"),
                ]
                if rng.random() < 0.5:
                    reporter_msgs.append(
                        ("Reporter::WARNING", "Zeek compiled without GeoIP support")
                    )

            self.activity_generator.generate_sensor_startup(
                sensor_hostname=hostname,
                time=ts,
                reporter_messages=reporter_msgs if reporter_msgs else None,
            )

    def _emit_dhcp_leases(self) -> None:
        """Emit initial DHCP lease records during warm-up period.

        Leases are staggered across the first 5 minutes of generation using
        per-host hash offsets. During warm-up these are suppressed from output
        but establish lease state. Lease times and MACs are stored in
        _dhcp_lease_state for periodic renewal in _generate_system_traffic().
        """
        rng = random.Random(_stable_seed("dhcp_leases"))
        from evidenceforge.utils.ids import generate_zeek_uid

        # Track lease state for periodic renewals
        self._dhcp_lease_state: dict[str, dict] = {}
        world_model = getattr(self, "world_model", None)
        if world_model is None:
            ad_domain = getattr(self, "_ad_domain", self._resolve_ad_domain())
            world_model = WorldModel(self.scenario, ad_domain)
            self.world_model = world_model
        if not world_model.dhcp_servers:
            return
        # Stagger across first 5 minutes using per-host deterministic offsets
        base_time = getattr(self, "warmup_start_time", self.start_time)

        # Load OUI prefixes for diverse MAC generation
        _net_params = load_network_params()
        _oui_prefixes = _net_params.get("oui_prefixes", [{"prefix": "00:50:56", "weight": 100}])
        _oui_weights = [o["weight"] for o in _oui_prefixes]
        _oui_values = [o["prefix"] for o in _oui_prefixes]
        storyline_macs: dict[str, str] = {}
        for step in self.scenario.storyline or []:
            system_name = getattr(step, "system", "")
            if not system_name:
                continue
            for event in getattr(step, "events", []) or []:
                if getattr(event, "type", None) != "dhcp_lease":
                    continue
                mac_address = getattr(event, "mac_address", None)
                if mac_address:
                    storyline_macs.setdefault(system_name, mac_address.lower())

        for system in self.scenario.environment.systems:
            if not _system_uses_dhcp(system):
                continue
            ip_seed = _stable_seed(f"mac_{system.ip}")
            # Select OUI prefix deterministically per host using weighted distribution
            oui_rng = random.Random(ip_seed)
            oui = oui_rng.choices(_oui_values, weights=_oui_weights, k=1)[0]
            mac = storyline_macs.get(
                system.hostname,
                f"{oui}:{(ip_seed >> 16) & 0xFF:02x}"
                f":{(ip_seed >> 8) & 0xFF:02x}:{ip_seed & 0xFF:02x}",
            )
            offset = (_stable_seed(f"dhcp_offset_{system.hostname}") % 300) + rng.uniform(0, 5)
            ts = base_time + timedelta(seconds=offset)
            uid = generate_zeek_uid("C")
            lease_time = float(rng.choice([3600, 7200, 14400, 86400]))
            dhcp_servers = world_model.systems_with_capability(
                HostCapability.DHCP_SERVER,
                distinct_from=system,
            )
            if not dhcp_servers:
                continue
            dhcp_server = dhcp_servers[
                _stable_seed(f"dhcp_server:{system.hostname}") % len(dhcp_servers)
            ].ip
            renewal_rng = random.Random(_stable_seed(f"dhcp_renewal_timer:{system.hostname}:{mac}"))
            timer_granularity = renewal_rng.choice([0.25, 1.0, 1.0, 5.0])
            renewal_interval = dhcp_renewal_interval_seconds(
                lease_time,
                renewal_rng,
                timer_granularity=timer_granularity,
            )
            self.state_manager.set_current_time(ts)
            self.activity_generator.generate_dhcp_lease(
                system=system,
                time=ts,
                mac=mac,
                server_addr=dhcp_server,
                lease_time=lease_time,
                uid=uid,
                renewal_interval=renewal_interval,
            )
            # Store state for renewals
            self._dhcp_lease_state[system.hostname] = {
                "mac": mac,
                "lease_time": lease_time,
                "last_renewal": ts.timestamp(),
                "next_renewal": ts.timestamp() + renewal_interval,
                "renewal_interval": renewal_interval,
                "renewal_rng": renewal_rng,
                "timer_granularity": timer_granularity,
                "server_addr": dhcp_server,
                "system": system,
            }

    def _build_identity_directory(self) -> IdentityDirectory:
        """Build the central identity directory for this scenario."""
        directory = IdentityDirectory.from_scenario(self.scenario)
        self._identity_directory = directory
        logger.info(
            "Built identity directory: %d Windows SID entries, %d Linux account entries",
            len(directory.sid_registry),
            len(directory.linux_accounts),
        )
        return directory

    def _build_sid_registry(self) -> dict[str, str]:
        """Return the compatibility Windows SID registry view."""
        directory = getattr(self, "_identity_directory", None)
        if directory is None:
            directory = self._build_identity_directory()
        return dict(directory.sid_registry)

    def _resolve_ad_domain(self) -> str:
        """Resolve Active Directory domain FQDN from scenario.

        Priority: environment.domain > inferred from user emails > 'corp.local'
        """
        env = self.scenario.environment
        if env.domain:
            return env.domain
        for user in env.users:
            if user.email and "@" in user.email:
                email_domain = user.email.split("@", 1)[1]
                if "." in email_domain:
                    return email_domain
        return "corp.local"

    def _detect_infrastructure_ips(self) -> dict[str, str | list]:
        """Return the authoritative world-model infrastructure projection."""

        world_model = getattr(self, "world_model", None)
        if world_model is None:
            ad_domain = getattr(self, "_ad_domain", self._resolve_ad_domain())
            world_model = WorldModel(self.scenario, ad_domain)
            self.world_model = world_model
        return world_model.to_infrastructure_ips()

    def _build_service_defaults(self) -> dict[str, list[str]]:
        """Build per-system service lists, auto-populating defaults if empty."""
        if hasattr(self, "world_model"):
            return {
                hostname: list(services)
                for hostname, services in self.world_model.service_defaults_by_host.items()
            }

        from evidenceforge.generation.activity import _get_os_category

        defaults: dict[str, list[str]] = {}
        for system in self.scenario.environment.systems:
            if system.services:
                defaults[system.hostname] = list(system.services)
            else:
                os_cat = _get_os_category(system.os)
                if os_cat == "windows":
                    svcs = [
                        "dns-client",
                        "ntp-client",
                        "smb-client",
                        "kerberos-client",
                        "ldap-client",
                    ]
                    if system.type and system.type.lower() in ("server", "domain_controller"):
                        svcs.append("smb-server")
                else:
                    svcs = ["dns-client", "ntp-client", "syslog"]
                defaults[system.hostname] = svcs
        return defaults

    def _boot_lifecycle_authority(self) -> GeneratorLifecycleAuthority | None:
        """Resolve and authenticate the optional engine boot lifecycle owner."""

        authority = getattr(self, "lifecycle_authority", None)
        if authority is None:
            return None
        if type(authority) is not GeneratorLifecycleAuthority:
            raise TypeError("Boot lifecycle authority must be an exact typed engine owner")
        if authority.state_manager is not self.state_manager:
            raise StateError("Boot lifecycle authority must share the engine StateManager")
        if type(authority.registry) is not LifecycleRegistry:
            raise TypeError("Boot lifecycle authority must own an exact LifecycleRegistry")
        if (
            authority.lifecycle_shadow.state_manager is not self.state_manager
            or authority.lifecycle_shadow.registry is not authority.registry
        ):
            raise StateError("Boot lifecycle authority has inconsistent State/registry ownership")
        engine_registry = getattr(self, "lifecycle_registry", None)
        if engine_registry is not None and engine_registry is not authority.registry:
            raise StateError("Boot lifecycle authority must share the engine lifecycle registry")
        return authority

    def _build_windows_boot_host_spec(
        self,
        system: System,
        boot_time: datetime | None,
    ) -> _BootHostSpec:
        """Resolve the exact Windows boot forest without allocating State identity."""

        from evidenceforge.generation.activity.system_processes import (
            get_scheduled_task_entries,
        )

        hostname = system.hostname
        boot_rng = random.Random(_stable_seed(f"windows_boot_sequence:{hostname}"))
        boot_elapsed = 0.0
        processes: list[_BootProcessSpec] = []
        aliases: list[tuple[str, str]] = []

        def process_time() -> datetime | None:
            nonlocal boot_elapsed
            if boot_time is None:
                return None
            boot_elapsed += boot_rng.uniform(0.08, 2.75)
            return boot_time + timedelta(seconds=boot_elapsed)

        def add(
            alias: str,
            parent_alias: str,
            image: str,
            command_line: str,
            username: str,
            logon_id: str = "",
        ) -> None:
            processes.append(
                _BootProcessSpec(
                    alias=alias,
                    parent_alias=parent_alias,
                    fixed_pid=None,
                    image=normalize_defender_platform_path(image, hostname),
                    command_line=command_line,
                    username=username,
                    integrity_level="System",
                    os_category="windows",
                    logon_id=logon_id,
                    start_time=process_time(),
                )
            )

        processes.append(
            _BootProcessSpec(
                alias="system",
                parent_alias=None,
                fixed_pid=4,
                image="System",
                command_line="",
                username="SYSTEM",
                integrity_level="System",
                os_category="windows",
                logon_id="",
                start_time=boot_time,
            )
        )
        add("smss", "system", r"C:\Windows\System32\smss.exe", "smss.exe", "SYSTEM")
        add("csrss_s0", "smss", r"C:\Windows\System32\csrss.exe", "csrss.exe", "SYSTEM")
        add(
            "wininit",
            "smss",
            r"C:\Windows\System32\wininit.exe",
            "wininit.exe",
            "SYSTEM",
        )
        add(
            "services",
            "wininit",
            r"C:\Windows\System32\services.exe",
            "services.exe",
            "SYSTEM",
        )
        add("lsass", "wininit", r"C:\Windows\System32\lsass.exe", "lsass.exe", "SYSTEM")

        for alias, command_line, username in (
            ("svchost_dcom", "svchost.exe -k DcomLaunch", "SYSTEM"),
            ("svchost_local_system", "svchost.exe -k LocalSystem", "SYSTEM"),
            ("svchost_netsvcs", "svchost.exe -k netsvcs", "NETWORK SERVICE"),
            ("svchost_local_svc", "svchost.exe -k LocalService", "LOCAL SERVICE"),
            ("svchost_net_svc", "svchost.exe -k NetworkService", "NETWORK SERVICE"),
            (
                "svchost_local_nr",
                "svchost.exe -k LocalServiceNetworkRestricted",
                "LOCAL SERVICE",
            ),
            (
                "svchost_local_nn",
                "svchost.exe -k LocalServiceNoNetwork",
                "LOCAL SERVICE",
            ),
            ("svchost_wusvcs", "svchost.exe -k wusvcs", "SYSTEM"),
        ):
            add(
                alias,
                "services",
                r"C:\Windows\System32\svchost.exe",
                command_line,
                username,
            )
        aliases.append(("svchost_schedule", "svchost_netsvcs"))

        environment = getattr(getattr(self, "scenario", None), "environment", None)
        requires_taskeng = bool(getattr(environment, "service_accounts", [])) or any(
            str(entry.get("parent") or "") == "taskeng"
            for entry in get_scheduled_task_entries(system)
        )
        if requires_taskeng:
            task_identity = uuid.UUID(
                int=(
                    (_stable_seed(f"task_scheduler_guid_hi:{hostname}") << 64)
                    | _stable_seed(f"task_scheduler_guid_lo:{hostname}")
                )
            )
            add(
                "taskeng",
                "svchost_schedule",
                r"C:\Windows\System32\taskeng.exe",
                f"taskeng.exe {{{str(task_identity).upper()}}}",
                "SYSTEM",
            )

        if (system.type or "").lower() == "domain_controller":
            add("dns", "services", r"C:\Windows\System32\dns.exe", "dns.exe", "SYSTEM")

        add(
            "msmpeng",
            "services",
            r"C:\ProgramData\Microsoft\Windows Defender\Platform\MsMpEng.exe",
            "MsMpEng.exe",
            "SYSTEM",
        )
        add(
            "search_indexer",
            "services",
            r"C:\Windows\System32\SearchIndexer.exe",
            "SearchIndexer.exe",
            "SYSTEM",
            "0x3e7",
        )
        add(
            "wmiprvse",
            "svchost_dcom",
            r"C:\Windows\System32\wbem\WmiPrvSE.exe",
            "WmiPrvSE.exe -Embedding",
            "NETWORK SERVICE",
        )
        add(
            "dllhost",
            "svchost_dcom",
            r"C:\Windows\System32\dllhost.exe",
            "dllhost.exe /Processid:{02D4B3F1-FD88-11D1-960D-00805FC79235}",
            "SYSTEM",
        )
        add(
            "search_protocol_host",
            "search_indexer",
            r"C:\Windows\System32\SearchProtocolHost.exe",
            "SearchProtocolHost.exe Global\\UsGthrFltPipeMssGthrPipe",
            "SYSTEM",
        )
        add(
            "mpcmdrun",
            "msmpeng",
            r"C:\ProgramData\Microsoft\Windows Defender\Platform\MpCmdRun.exe",
            "MpCmdRun.exe -Scan -ScanType 1",
            "SYSTEM",
        )
        add(
            "msiexec",
            "services",
            r"C:\Windows\System32\msiexec.exe",
            "msiexec.exe /V",
            "SYSTEM",
        )
        add(
            "taskhostw",
            "svchost_schedule",
            r"C:\Windows\System32\taskhostw.exe",
            "taskhostw.exe",
            "SYSTEM",
        )
        add("csrss_s1", "smss", r"C:\Windows\System32\csrss.exe", "csrss.exe", "SYSTEM")
        add(
            "winlogon",
            "smss",
            r"C:\Windows\System32\winlogon.exe",
            "winlogon.exe",
            "SYSTEM",
        )
        add(
            "userinit",
            "winlogon",
            r"C:\Windows\System32\userinit.exe",
            "userinit.exe",
            "SYSTEM",
        )
        desktop_user = system.assigned_user
        if desktop_user:
            add(
                "explorer",
                "userinit",
                r"C:\Windows\explorer.exe",
                "explorer.exe",
                desktop_user,
            )
            add(
                "runtime_broker",
                "svchost_local_system",
                r"C:\Windows\System32\RuntimeBroker.exe",
                "RuntimeBroker.exe",
                desktop_user,
            )
        else:
            aliases.append(("explorer", "winlogon"))
        add("dwm", "csrss_s0", r"C:\Windows\System32\dwm.exe", "dwm.exe", "SYSTEM")

        roles = {role.lower() for role in (system.roles or [])}
        service_defaults = getattr(self, "_system_service_defaults", {})
        services = tuple(service_defaults.get(system.hostname, system.services or ()))
        db_services = database_services_for_host(
            services,
            "windows",
            has_database_role=bool(roles & {"database", "db_server"}),
        )
        if "mssql" in db_services:
            add(
                "sqlservr",
                "services",
                r"C:\Program Files\Microsoft SQL Server\MSSQL16.MSSQLSERVER\MSSQL\Binn\sqlservr.exe",
                "sqlservr.exe -sMSSQLSERVER",
                r"NT SERVICE\MSSQLSERVER",
            )
        return _BootHostSpec(
            hostname=hostname,
            os_category="windows",
            boot_time=boot_time,
            machine_id="",
            processes=tuple(processes),
            aliases=tuple(aliases),
        )

    def _build_linux_boot_host_spec(
        self,
        system: System,
        boot_time: datetime | None,
    ) -> _BootHostSpec:
        """Resolve the exact Linux boot forest without allocating State identity."""

        hostname = system.hostname
        is_rhel = any(
            marker in system.os.lower() for marker in ("centos", "rhel", "red hat", "rocky", "alma")
        )
        boot_rng = random.Random(_stable_seed(f"linux_boot_sequence:{hostname}"))
        boot_elapsed = 0.0
        processes: list[_BootProcessSpec] = []
        aliases: list[tuple[str, str]] = []

        def process_time() -> datetime | None:
            nonlocal boot_elapsed
            if boot_time is None:
                return None
            boot_elapsed += boot_rng.uniform(0.05, 1.9)
            return boot_time + timedelta(seconds=boot_elapsed)

        def add(
            alias: str,
            parent_alias: str,
            image: str,
            command_line: str,
            username: str,
        ) -> None:
            processes.append(
                _BootProcessSpec(
                    alias=alias,
                    parent_alias=parent_alias,
                    fixed_pid=None,
                    image=image,
                    command_line=command_line,
                    username=username,
                    integrity_level="System",
                    os_category="linux",
                    logon_id="",
                    start_time=process_time(),
                )
            )

        processes.append(
            _BootProcessSpec(
                alias="systemd",
                parent_alias=None,
                fixed_pid=1,
                image="/usr/lib/systemd/systemd",
                command_line="/usr/lib/systemd/systemd --system --deserialize 26",
                username="root",
                integrity_level="System",
                os_category="linux",
                logon_id="",
                start_time=boot_time,
            )
        )
        journal_path = "/usr/lib/systemd/systemd-journald"
        add("journald", "systemd", journal_path, journal_path, "root")
        udev_path = "/usr/lib/systemd/systemd-udevd" if is_rhel else "/lib/systemd/systemd-udevd"
        add("udevd", "systemd", udev_path, udev_path, "root")
        add("rsyslogd", "systemd", "/usr/sbin/rsyslogd", "rsyslogd -n", "syslog")
        add(
            "networkmanager",
            "systemd",
            "/usr/sbin/NetworkManager",
            "/usr/sbin/NetworkManager --no-daemon",
            "root",
        )
        add(
            "dbus",
            "systemd",
            "/usr/bin/dbus-daemon",
            "/usr/bin/dbus-daemon --system",
            "messagebus",
        )
        logind_path = "/usr/lib/systemd/systemd-logind"
        add("logind", "systemd", logind_path, logind_path, "root")
        add("sshd", "systemd", "/usr/sbin/sshd", "/usr/sbin/sshd -D", "root")

        roles = {role.lower() for role in (system.roles or [])}
        service_defaults = getattr(self, "_system_service_defaults", {})
        services = tuple(service_defaults.get(system.hostname, system.services or ()))
        service_tokens = {service.lower() for service in services}
        world_model = getattr(self, "world_model", None)
        host_world = getattr(world_model, "hosts", {}).get(system.hostname)
        if host_world is not None and host_world.supports(HostCapability.SMB_SERVER):
            server_profile = select_server_profile("linux", services)
            listener = render_smb_process(server_profile.listener)
            add(
                "smbd",
                "systemd",
                listener.image,
                listener.command_line,
                listener.username,
            )
            aliases.append(("smbd_master", "smbd"))
        proxy_markers = {"forward_proxy", "squid", "proxy"}
        if roles & proxy_markers or service_tokens & proxy_markers:
            add(
                "squid",
                "systemd",
                "/usr/sbin/squid",
                "/usr/sbin/squid --foreground -YC",
                "squid" if is_rhel else "proxy",
            )
        web_markers = {"web_server", "apache", "apache2", "httpd", "nginx"}
        if roles & web_markers or service_tokens & web_markers or "web" in hostname.lower():
            if is_rhel:
                add("httpd", "systemd", "/usr/sbin/httpd", "/usr/sbin/httpd -DFOREGROUND", "apache")
            else:
                add(
                    "apache2",
                    "systemd",
                    "/usr/sbin/apache2",
                    "/usr/sbin/apache2 -DFOREGROUND",
                    "www-data",
                )
        db_services = database_services_for_host(
            services,
            "linux",
            has_database_role=bool(roles & {"database", "db_server"}),
        )
        if "mysql" in db_services:
            add(
                "mysqld",
                "systemd",
                "/usr/sbin/mysqld",
                "/usr/sbin/mysqld --daemonize --pid-file=/run/mysqld/mysqld.pid",
                "mysql",
            )
        if "postgresql" in db_services:
            add(
                "postgres",
                "systemd",
                "/usr/bin/postgres",
                "/usr/bin/postgres -D /var/lib/pgsql/data",
                "postgres",
            )
        add(
            "cron",
            "systemd",
            "/usr/sbin/crond" if is_rhel else "/usr/sbin/cron",
            "/usr/sbin/crond -n" if is_rhel else "/usr/sbin/cron -f",
            "root",
        )
        add("agetty1", "systemd", "/sbin/agetty", "/sbin/agetty --noclear tty1 linux", "root")
        add("agetty2", "systemd", "/sbin/agetty", "/sbin/agetty --noclear tty2 linux", "root")
        add("snapd", "systemd", "/usr/lib/snapd/snapd", "/usr/lib/snapd/snapd", "root")
        if is_rhel:
            add("chronyd", "systemd", "/usr/sbin/chronyd", "/usr/sbin/chronyd -F 2", "chrony")
        else:
            add(
                "timesyncd",
                "systemd",
                "/usr/lib/systemd/systemd-timesyncd",
                "/usr/lib/systemd/systemd-timesyncd",
                "systemd-timesync",
            )
            add(
                "systemd_resolved",
                "systemd",
                "/usr/lib/systemd/systemd-resolved",
                "/usr/lib/systemd/systemd-resolved",
                "systemd-resolve",
            )
        add("bash", "sshd", "/bin/bash", "-bash", "root")
        machine_id = hashlib.md5(
            f"machine_id_{hostname}".encode(),
            usedforsecurity=False,
        ).hexdigest()
        return _BootHostSpec(
            hostname=hostname,
            os_category="linux",
            boot_time=boot_time,
            machine_id=machine_id,
            processes=tuple(processes),
            aliases=tuple(aliases),
        )

    def _build_boot_fleet_spec(self, original_time: datetime | None) -> BootFleetSpec:
        """Resolve every boot input once into the exact symbolic fleet forest."""

        from evidenceforge.generation.activity import _get_os_category

        start_time = getattr(self, "start_time", None)
        uptimes = getattr(self, "_kernel_boot_uptimes", {})
        hosts: list[_BootHostSpec] = []
        for system in self.scenario.environment.systems:
            boot_uptime = uptimes.get(system.hostname)
            boot_time = (
                start_time - timedelta(seconds=boot_uptime)
                if start_time is not None and boot_uptime is not None
                else original_time
            )
            if _get_os_category(system.os) == "windows":
                hosts.append(self._build_windows_boot_host_spec(system, boot_time))
            else:
                hosts.append(self._build_linux_boot_host_spec(system, boot_time))
        return BootFleetSpec(
            state_time=original_time,
            hosts=tuple(hosts),
        )

    def _boot_materialization_request(
        self,
        fleet_spec: BootFleetSpec,
    ) -> tuple[str, str, tuple[object, ...]]:
        """Return one retry-stable transaction bound to the exact planned forest."""

        if type(fleet_spec) is not BootFleetSpec:
            raise StateError("Boot materialization requires an exact BootFleetSpec")
        request = fleet_spec.canonical_payload()
        request_digest = hashlib.sha256(_canonical_boot_payload_bytes(request)).hexdigest()
        return (
            stable_uuid("boot-process-fleet-transaction", "engine-owned-boot-fleet-v2"),
            request_digest,
            request,
        )

    @staticmethod
    def _boot_materialization_terminal_reservation(
        fleet_spec: BootFleetSpec,
        transaction_id: str,
        request_digest: str,
        existing_system_pids: tuple[tuple[str, tuple[tuple[str, int], ...]], ...],
    ) -> tuple[tuple[object, ...], int]:
        """Return the full preplanning terminal bound and its retained byte charge."""

        if type(fleet_spec) is not BootFleetSpec:
            raise StateError("Boot materialization requires an exact BootFleetSpec")
        uuid_upper = "ffffffff-ffff-ffff-ffff-ffffffffffff"
        integer_upper = 10**20 - 1
        generation_upper = 10**128 - 1
        fallback_time = fleet_spec.state_time or datetime.max.replace(tzinfo=UTC)
        process_projections: list[tuple[object, ...]] = []
        machine_ids: list[tuple[str, str]] = []
        system_pids: dict[str, dict[str, int]] = {
            hostname: dict(members) for hostname, members in existing_system_pids
        }
        boot_times: list[tuple[str, datetime]] = []
        final_state_time = fallback_time
        for host in fleet_spec.hosts:
            if host.boot_time is not None:
                boot_times.append((host.hostname, host.boot_time))
            if host.machine_id:
                machine_ids.append((host.hostname, host.machine_id))
            host_pids = {member.alias: integer_upper for member in host.processes}
            host_pids.update({alias: integer_upper for alias, _target in host.aliases})
            system_pids[host.hostname] = host_pids
            for member in host.processes:
                started_at = member.start_time or fallback_time
                final_state_time = max(final_state_time, started_at)
                thread_projection: tuple[object, ...] = (
                    "thread-identity-v1",
                    host.hostname,
                    uuid_upper,
                    integer_upper,
                    integer_upper,
                    uuid_upper,
                    started_at,
                    "primary",
                )
                process_projections.append(
                    (
                        "process-identity-v1",
                        host.hostname,
                        uuid_upper,
                        integer_upper,
                        integer_upper,
                        member.image,
                        member.command_line,
                        member.username,
                        member.logon_id,
                        started_at,
                        uuid_upper,
                        uuid_upper,
                        thread_projection,
                    )
                )
        external_projection = EmitterSetupMixin._boot_materialization_external_result(
            dict(machine_ids),
            system_pids,
        )
        terminal_projection: tuple[object, ...] = (
            "materialization-batch-terminal-size-v1",
            transaction_id,
            request_digest,
            generation_upper,
            uuid_upper,
            None,
            tuple(process_projections),
            tuple(sorted(boot_times)),
            external_projection,
            final_state_time,
        )
        return (
            terminal_projection,
            512 + len(_canonical_boot_payload_bytes(terminal_projection)),
        )

    @staticmethod
    def _plan_boot_host_spec(
        batch_builder: MaterializationBatchBuilder,
        host_spec: _BootHostSpec,
    ) -> dict[str, int]:
        """Allocate one exact symbolic host forest into the shared fleet builder."""

        if host_spec.boot_time is not None:
            batch_builder.plan_boot_time(host_spec.hostname, host_spec.boot_time)
        pids: dict[str, int] = {}
        plans_by_alias: dict[str, ProcessMaterializationPlan] = {}
        for member in host_spec.processes:
            if member.parent_alias is None:
                parent_pid = 0
                parent_plan = None
            else:
                if member.parent_alias not in pids:
                    raise StateError(
                        f"Boot process {member.alias} precedes parent {member.parent_alias}"
                    )
                parent_pid = pids[member.parent_alias]
                parent_plan = plans_by_alias.get(member.parent_alias)
            plan = batch_builder.plan_process(
                system=host_spec.hostname,
                fixed_pid=member.fixed_pid,
                parent_pid=parent_pid,
                image=member.image,
                command_line=member.command_line,
                username=member.username,
                integrity_level=member.integrity_level,
                os_category=member.os_category,
                logon_id=member.logon_id,
                start_time=member.start_time,
                parent_plan=parent_plan,
            )
            pids[member.alias] = plan.identity.pid
            plans_by_alias[member.alias] = plan
            for alias, target in host_spec.aliases:
                if target == member.alias:
                    pids[alias] = plan.identity.pid
                    plans_by_alias[alias] = plan
        unresolved = {alias for alias, _target in host_spec.aliases} - pids.keys()
        if unresolved:
            raise StateError(f"Boot PID aliases have unresolved targets: {sorted(unresolved)!r}")
        return pids

    @staticmethod
    def _boot_materialization_external_result(
        machine_ids: dict[str, str],
        system_pids: dict[str, dict[str, int]],
    ) -> tuple[object, ...]:
        """Freeze exact engine maps for authenticated retry reconciliation."""

        return (
            "boot-process-fleet-external-v1",
            tuple(sorted(machine_ids.items())),
            tuple(
                (hostname, tuple(sorted(pids.items())))
                for hostname, pids in sorted(system_pids.items())
            ),
        )

    @staticmethod
    def _decode_boot_materialization_external_result(
        external_result: tuple[object, ...],
    ) -> tuple[dict[str, str], dict[str, dict[str, int]]]:
        """Validate and precompute exact maps from an authenticated terminal."""

        if (
            type(external_result) is not tuple
            or len(external_result) != 3
            or external_result[0] != "boot-process-fleet-external-v1"
            or type(external_result[1]) is not tuple
            or type(external_result[2]) is not tuple
        ):
            raise StateError("Boot materialization terminal has malformed external maps")
        machine_ids: dict[str, str] = {}
        for member in external_result[1]:
            if (
                type(member) is not tuple
                or len(member) != 2
                or type(member[0]) is not str
                or type(member[1]) is not str
                or member[0] in machine_ids
            ):
                raise StateError("Boot materialization terminal has malformed machine IDs")
            machine_ids[member[0]] = member[1]
        system_pids: dict[str, dict[str, int]] = {}
        for host_member in external_result[2]:
            if (
                type(host_member) is not tuple
                or len(host_member) != 2
                or type(host_member[0]) is not str
                or type(host_member[1]) is not tuple
                or host_member[0] in system_pids
            ):
                raise StateError("Boot materialization terminal has malformed PID maps")
            pids: dict[str, int] = {}
            for pid_member in host_member[1]:
                if (
                    type(pid_member) is not tuple
                    or len(pid_member) != 2
                    or type(pid_member[0]) is not str
                    or type(pid_member[1]) is not int
                    or pid_member[0] in pids
                ):
                    raise StateError("Boot materialization terminal has malformed PID aliases")
                pids[pid_member[0]] = pid_member[1]
            system_pids[host_member[0]] = pids
        return machine_ids, system_pids

    def _apply_boot_materialization_external_result(
        self,
        external_result: tuple[object, ...],
    ) -> None:
        """Idempotently install exact engine maps from an authenticated terminal."""

        machine_ids, system_pids = self._decode_boot_materialization_external_result(
            external_result
        )
        self._machine_ids = machine_ids
        self._system_pids = system_pids

    def _seed_system_process_trees(self) -> None:
        """Pre-seed StateManager with long-running system processes.

        These processes were started at boot (before the scenario window).
        We register them silently (no log events) so they exist as valid
        parents for child processes spawned during the scenario.
        """
        original_time = self.state_manager.state.current_time
        lifecycle_authority = self._boot_lifecycle_authority()
        fleet_spec: BootFleetSpec | None = None
        boot_transaction: LifecycleMaterializationBatchTransaction | None = None
        boot_terminal: LifecycleMaterializationBatchTerminalResult | None = None
        boot_planning_attempt: LifecycleMaterializationBatchPlanningAttempt | None = None
        boot_planning_capability: LifecycleMaterializationBatchPlanningCapability | None = None
        boot_existing_system_pids: tuple[tuple[str, tuple[tuple[str, int], ...]], ...] = ()
        lost_planning_return: BaseException | None = None
        if lifecycle_authority is not None:
            pinned_transaction = getattr(self, "_boot_materialization_transaction", None)
            request_state_time = (
                getattr(self, "_boot_materialization_state_time", original_time)
                if pinned_transaction is not None
                else original_time
            )
            fleet_spec = self._build_boot_fleet_spec(request_state_time)
            materialized_hostnames = {host.hostname for host in fleet_spec.hosts}
            current_existing_system_pids = tuple(
                (hostname, tuple(sorted(pids.items())))
                for hostname, pids in sorted(getattr(self, "_system_pids", {}).items())
                if hostname not in materialized_hostnames
            )
            transaction_id, request_digest, request_payload = self._boot_materialization_request(
                fleet_spec
            )
            pinned_terminal = getattr(self, "_boot_materialization_terminal_result", None)
            if pinned_transaction is not None:
                if (
                    type(pinned_transaction) is not LifecycleMaterializationBatchTransaction
                    or getattr(self, "_boot_materialization_transaction_identity", None)
                    is not pinned_transaction
                    or pinned_transaction.transaction_id != transaction_id
                    or pinned_transaction.request_digest != request_digest
                ):
                    raise StateError("Pinned boot materialization transaction is not authentic")
                boot_transaction = pinned_transaction
                boot_existing_system_pids = getattr(
                    self,
                    "_boot_materialization_existing_system_pids",
                    current_existing_system_pids,
                )
            else:
                anticipated_terminal_payload, _anticipated_terminal_bytes = (
                    self._boot_materialization_terminal_reservation(
                        fleet_spec,
                        transaction_id,
                        request_digest,
                        current_existing_system_pids,
                    )
                )
                boot_transaction = lifecycle_authority.reserve_materialization_batch_transaction(
                    transaction_id=transaction_id,
                    request_digest=request_digest,
                    request_payload=request_payload,
                    anticipated_terminal_payload=anticipated_terminal_payload,
                )
                self._boot_materialization_transaction_identity = boot_transaction
                self._boot_materialization_transaction = boot_transaction
                self._boot_materialization_state_time = original_time
                self._boot_materialization_existing_system_pids = current_existing_system_pids
                boot_existing_system_pids = current_existing_system_pids
            if pinned_terminal is not None:
                if (
                    type(pinned_terminal) is not LifecycleMaterializationBatchTerminalResult
                    or getattr(self, "_boot_materialization_terminal_identity", None)
                    is not pinned_terminal
                    or not lifecycle_authority.validates_archived_materialization_batch_terminal_result(
                        boot_transaction,
                        pinned_terminal,
                    )
                ):
                    raise StateError("Pinned boot materialization terminal is not authentic")
                lifecycle_authority.validate_archived_materialization_batch_terminal_state(
                    boot_transaction,
                    pinned_terminal,
                )
                boot_terminal = pinned_terminal
                self._apply_boot_materialization_external_result(pinned_terminal.external_result)
            else:
                boot_terminal = lifecycle_authority.reconcile_materialization_batch_transaction(
                    boot_transaction
                )
                if boot_terminal is None:
                    boot_planning_attempt = lifecycle_authority.prepare_materialization_batch_transaction_planning_attempt(
                        boot_transaction
                    )
                    try:
                        planning_result = lifecycle_authority.claim_materialization_batch_transaction_for_planning(
                            boot_transaction,
                            attempt=boot_planning_attempt,
                        )
                    except BaseException as error:
                        try:
                            boot_planning_capability = lifecycle_authority.reconcile_materialization_batch_transaction_planning_claim(
                                boot_transaction,
                                attempt=boot_planning_attempt,
                            )
                        except StateError:
                            raise error from None
                        if boot_planning_capability is None:
                            raise
                        lost_planning_return = error
                    else:
                        if type(planning_result) is LifecycleMaterializationBatchPlanningCapability:
                            boot_planning_capability = planning_result
                        else:
                            boot_terminal = planning_result
                    if boot_terminal is not None:
                        boot_terminal = (
                            lifecycle_authority.reconcile_materialization_batch_transaction(
                                boot_transaction
                            )
                        )
                if boot_terminal is not None:
                    self._apply_boot_materialization_external_result(boot_terminal.external_result)
                    self._boot_materialization_terminal_identity = boot_terminal
                    self._boot_materialization_terminal_result = boot_terminal
        batch_builder: MaterializationBatchBuilder | None = None
        staged_machine_ids: dict[str, str] = {}
        staged_system_pids: dict[str, dict[str, int]] = {}
        if lifecycle_authority is None:
            self._machine_ids = {}

        completed = False
        try:
            if lifecycle_authority is not None and boot_terminal is None:
                assert fleet_spec is not None
                if original_time != fleet_spec.state_time:
                    raise StateError(
                        "Pending boot materialization cannot cross a State-time change"
                    )
                batch_builder = self.state_manager.begin_materialization_batch()
            if boot_terminal is None:
                if lifecycle_authority is None:
                    from evidenceforge.generation.activity import _get_os_category

                    for system in self.scenario.environment.systems:
                        pids: dict[str, int] = {}
                        boot_uptime = getattr(self, "_kernel_boot_uptimes", {}).get(system.hostname)
                        boot_time = (
                            self.start_time - timedelta(seconds=boot_uptime)
                            if self.start_time and boot_uptime is not None
                            else original_time
                        )
                        if boot_time is not None:
                            self.state_manager.set_current_time(boot_time)
                        if _get_os_category(system.os) == "windows":
                            self._seed_windows_process_tree(
                                system,
                                pids,
                                _batch_builder=None,
                                _boot_base=boot_time,
                            )
                        else:
                            self._seed_linux_process_tree(
                                system,
                                pids,
                                _batch_builder=None,
                                _boot_base=boot_time,
                            )
                            self._machine_ids[system.hostname] = hashlib.md5(
                                f"machine_id_{system.hostname}".encode(),
                                usedforsecurity=False,
                            ).hexdigest()
                        self._system_pids[system.hostname] = pids
                        if boot_time is not None:
                            self.state_manager.register_boot_time(
                                system.hostname,
                                boot_time,
                            )
                else:
                    assert fleet_spec is not None
                    for host_spec in fleet_spec.hosts:
                        assert batch_builder is not None
                        staged_system_pids[host_spec.hostname] = self._plan_boot_host_spec(
                            batch_builder,
                            host_spec,
                        )
                        if host_spec.machine_id:
                            staged_machine_ids[host_spec.hostname] = host_spec.machine_id

                if lifecycle_authority is not None:
                    assert batch_builder is not None
                    assert boot_transaction is not None
                    assert fleet_spec is not None
                    published_system_pids = {
                        hostname: dict(members) for hostname, members in boot_existing_system_pids
                    }
                    published_system_pids.update(
                        {
                            **staged_system_pids,
                        }
                    )
                    external_result = self._boot_materialization_external_result(
                        staged_machine_ids,
                        published_system_pids,
                    )
                    batch_plan = batch_builder.seal()
                    lifecycle_authority.materialize_batch(
                        batch_plan,
                        transaction=boot_transaction,
                        external_result=external_result,
                        planning_capability=boot_planning_capability,
                    )
                    boot_planning_capability = None
                    boot_terminal = lifecycle_authority.reconcile_materialization_batch_transaction(
                        boot_transaction
                    )
                    if boot_terminal is None:
                        raise StateError("Boot materialization committed without a terminal result")
                    if lost_planning_return is not None:
                        raise lost_planning_return
                    self._apply_boot_materialization_external_result(boot_terminal.external_result)
                    self._boot_materialization_terminal_identity = boot_terminal
                    self._boot_materialization_terminal_result = boot_terminal
            completed = True
        finally:
            if (
                boot_planning_capability is not None
                and lifecycle_authority is not None
                and boot_transaction is not None
            ):
                lifecycle_authority.release_materialization_batch_transaction_planning_claim(
                    boot_transaction,
                    boot_planning_capability,
                )
            if completed and original_time is not None and lifecycle_authority is None:
                self.state_manager.set_current_time(original_time)

        total = sum(len(p) for p in self._system_pids.values())
        logger.info(f"Seeded {total} system processes across {len(self._system_pids)} systems")

        # Build Zipf-weighted external scanner IP pool for realistic scanning distribution
        from evidenceforge.utils.rng import _stable_seed

        scanner_rng = random.Random(_stable_seed("external_scanners"))
        prolific = []
        for _ in range(scanner_rng.randint(8, 15)):
            ip = self._generate_external_client_ip(scanner_rng)
            weight = scanner_rng.randint(45, 2000)
            prolific.append((ip, weight))
        tail = [
            (self._generate_external_client_ip(scanner_rng), 1)
            for _ in range(scanner_rng.randint(30, 80))
        ]
        pool = prolific + tail
        self._external_scanner_ips = [ip for ip, _ in pool]
        self._external_scanner_weights = [w for _, w in pool]

        # Share system PIDs with activity generator for dynamic ParentProcessName
        self.activity_generator._system_pids = self._system_pids
        self.activity_generator._all_system_ips = [s.ip for s in self.scenario.environment.systems]
        self.activity_generator._db_servers = self._infra_ips.get("db_servers", [])
        self.activity_generator._dns_server_ips = self._infra_ips.get("dns", [])
        world_model = getattr(self, "world_model", None)
        self.activity_generator._dns_server_ips_are_public_fallback = bool(
            world_model is not None and not world_model.dns_servers
        )
        self.activity_generator._exchange_ip = self._infra_ips.get("exchange")
        self.activity_generator._dc_hostnames = self._infra_ips.get("dc_hostnames", [])
        self.activity_generator._dc_ips = self._infra_ips.get("dc", [])
        self.activity_generator._dc_systems = [
            s for s in self.scenario.environment.systems if s.type == "domain_controller"
        ]
        if (
            lifecycle_authority is not None
            and boot_transaction is not None
            and boot_terminal is not None
        ):
            lifecycle_authority.acknowledge_materialization_batch_transaction_if_retained(
                boot_transaction,
                boot_terminal,
            )

    def _seed_windows_process_tree(
        self,
        system: System,
        pids: dict[str, int],
        *,
        _batch_builder: MaterializationBatchBuilder | None = None,
        _boot_base: datetime | None = None,
    ) -> None:
        """Seed a Windows boot tree; direct strict calls are fixture-only."""
        sm = self.state_manager
        lifecycle_authority = self._boot_lifecycle_authority()
        hn = system.hostname
        boot_base = _boot_base if _batch_builder is not None else sm.state.current_time
        boot_rng = random.Random(_stable_seed(f"windows_boot_sequence:{hn}"))
        boot_elapsed = 0.0
        owns_batch = lifecycle_authority is not None and _batch_builder is None
        batch_builder = sm.begin_materialization_batch() if owns_batch else _batch_builder
        boot_pids = pids if lifecycle_authority is None else {}
        process_plans_by_pid: dict[int, ProcessMaterializationPlan] = {}
        if batch_builder is not None and boot_base is not None:
            batch_builder.plan_boot_time(hn, boot_base)

        def _advance_boot_clock() -> datetime | None:
            nonlocal boot_elapsed
            if boot_base is None:
                return None
            boot_elapsed += boot_rng.uniform(0.08, 2.75)
            process_time = boot_base + timedelta(seconds=boot_elapsed)
            if lifecycle_authority is None:
                sm.set_current_time(process_time)
            return process_time

        def _c(parent: int, image: str, cmd: str, user: str, logon_id: str = "") -> int:
            process_time = _advance_boot_clock()
            image = normalize_defender_platform_path(image, hn)
            if lifecycle_authority is None:
                # Compatibility fixtures deliberately omit the engine owner.
                return sm.create_process(
                    hn,
                    parent,
                    image,
                    cmd,
                    user,
                    "System",
                    logon_id=logon_id,
                )
            assert batch_builder is not None
            plan = batch_builder.plan_process(
                system=hn,
                parent_pid=parent,
                image=image,
                command_line=cmd,
                username=user,
                integrity_level="System",
                os_category="windows",
                logon_id=logon_id,
                start_time=process_time,
                parent_plan=process_plans_by_pid.get(parent),
            )
            process_plans_by_pid[plan.identity.pid] = plan
            return plan.identity.pid

        # PID 4 is always the Windows System process. Keep the fixed native PID
        # while registering it through the same canonical identity boundary.
        if lifecycle_authority is None:
            sm.register_process(
                system=hn,
                pid=4,
                parent_pid=0,
                image="System",
                command_line="",
                username="SYSTEM",
                integrity_level="System",
                os_category="windows",
            )
            boot_pids["system"] = 4
        else:
            assert batch_builder is not None
            plan = batch_builder.plan_process(
                system=hn,
                fixed_pid=4,
                parent_pid=0,
                image="System",
                command_line="",
                username="SYSTEM",
                integrity_level="System",
                os_category="windows",
                start_time=boot_base,
            )
            process_plans_by_pid[plan.identity.pid] = plan
            boot_pids["system"] = plan.identity.pid
        boot_pids["smss"] = _c(4, r"C:\Windows\System32\smss.exe", "smss.exe", "SYSTEM")
        boot_pids["csrss_s0"] = _c(
            boot_pids["smss"],
            r"C:\Windows\System32\csrss.exe",
            "csrss.exe",
            "SYSTEM",
        )
        boot_pids["wininit"] = _c(
            boot_pids["smss"], r"C:\Windows\System32\wininit.exe", "wininit.exe", "SYSTEM"
        )
        boot_pids["services"] = _c(
            boot_pids["wininit"],
            r"C:\Windows\System32\services.exe",
            "services.exe",
            "SYSTEM",
        )
        boot_pids["lsass"] = _c(
            boot_pids["wininit"],
            r"C:\Windows\System32\lsass.exe",
            "lsass.exe",
            "SYSTEM",
        )

        svchost_groups = [
            ("svchost_dcom", "svchost.exe -k DcomLaunch", "SYSTEM"),
            ("svchost_local_system", "svchost.exe -k LocalSystem", "SYSTEM"),
            ("svchost_netsvcs", "svchost.exe -k netsvcs", "NETWORK SERVICE"),
            ("svchost_local_svc", "svchost.exe -k LocalService", "LOCAL SERVICE"),
            ("svchost_net_svc", "svchost.exe -k NetworkService", "NETWORK SERVICE"),
            ("svchost_local_nr", "svchost.exe -k LocalServiceNetworkRestricted", "LOCAL SERVICE"),
            ("svchost_local_nn", "svchost.exe -k LocalServiceNoNetwork", "LOCAL SERVICE"),
            ("svchost_wusvcs", "svchost.exe -k wusvcs", "SYSTEM"),
        ]
        for name, cmdline, user in svchost_groups:
            boot_pids[name] = _c(
                boot_pids["services"],
                r"C:\Windows\System32\svchost.exe",
                cmdline,
                user,
            )

        # The Schedule service is part of the shared netsvcs host on this modeled
        # Windows profile. Keep a semantic alias rather than inventing another
        # svchost instance and perturbing unrelated process-allocation streams.
        boot_pids["svchost_schedule"] = boot_pids["svchost_netsvcs"]

        from evidenceforge.generation.activity.system_processes import (
            get_scheduled_task_entries,
        )

        environment = getattr(getattr(self, "scenario", None), "environment", None)
        requires_taskeng = bool(getattr(environment, "service_accounts", [])) or any(
            str(entry.get("parent") or "") == "taskeng"
            for entry in get_scheduled_task_entries(system)
        )
        if requires_taskeng:
            task_identity = uuid.UUID(
                int=(
                    (_stable_seed(f"task_scheduler_guid_hi:{hn}") << 64)
                    | _stable_seed(f"task_scheduler_guid_lo:{hn}")
                )
            )
            boot_pids["taskeng"] = _c(
                boot_pids["svchost_schedule"],
                r"C:\Windows\System32\taskeng.exe",
                f"taskeng.exe {{{str(task_identity).upper()}}}",
                "SYSTEM",
            )

        if (system.type or "").lower() == "domain_controller":
            boot_pids["dns"] = _c(
                boot_pids["services"],
                r"C:\Windows\System32\dns.exe",
                "dns.exe",
                "SYSTEM",
            )

        boot_pids["msmpeng"] = _c(
            boot_pids["services"],
            r"C:\ProgramData\Microsoft\Windows Defender\Platform\MsMpEng.exe",
            "MsMpEng.exe",
            "SYSTEM",
        )
        boot_pids["search_indexer"] = _c(
            boot_pids["services"],
            r"C:\Windows\System32\SearchIndexer.exe",
            "SearchIndexer.exe",
            "SYSTEM",
            "0x3e7",
        )
        boot_pids["wmiprvse"] = _c(
            boot_pids["svchost_dcom"],
            r"C:\Windows\System32\wbem\WmiPrvSE.exe",
            "WmiPrvSE.exe -Embedding",
            "NETWORK SERVICE",
        )
        boot_pids["dllhost"] = _c(
            boot_pids["svchost_dcom"],
            r"C:\Windows\System32\dllhost.exe",
            "dllhost.exe /Processid:{02D4B3F1-FD88-11D1-960D-00805FC79235}",
            "SYSTEM",
        )
        boot_pids["search_protocol_host"] = _c(
            boot_pids["search_indexer"],
            r"C:\Windows\System32\SearchProtocolHost.exe",
            "SearchProtocolHost.exe Global\\UsGthrFltPipeMssGthrPipe",
            "SYSTEM",
        )
        boot_pids["mpcmdrun"] = _c(
            boot_pids["msmpeng"],
            r"C:\ProgramData\Microsoft\Windows Defender\Platform\MpCmdRun.exe",
            "MpCmdRun.exe -Scan -ScanType 1",
            "SYSTEM",
        )
        boot_pids["msiexec"] = _c(
            boot_pids["services"],
            r"C:\Windows\System32\msiexec.exe",
            "msiexec.exe /V",
            "SYSTEM",
        )
        boot_pids["taskhostw"] = _c(
            boot_pids["svchost_schedule"],
            r"C:\Windows\System32\taskhostw.exe",
            "taskhostw.exe",
            "SYSTEM",
        )

        boot_pids["csrss_s1"] = _c(
            boot_pids["smss"],
            r"C:\Windows\System32\csrss.exe",
            "csrss.exe",
            "SYSTEM",
        )
        boot_pids["winlogon"] = _c(
            boot_pids["smss"],
            r"C:\Windows\System32\winlogon.exe",
            "winlogon.exe",
            "SYSTEM",
        )
        boot_pids["userinit"] = _c(
            boot_pids["winlogon"],
            r"C:\Windows\System32\userinit.exe",
            "userinit.exe",
            "SYSTEM",
        )
        # User-context processes run under the logged-in user, not SYSTEM.
        # Only seed them for workstations with an assigned user; servers/DCs
        # start explorer only when an admin logs in interactively.
        _desktop_user = getattr(system, "assigned_user", None)
        if _desktop_user:
            boot_pids["explorer"] = _c(
                boot_pids["userinit"],
                r"C:\Windows\explorer.exe",
                "explorer.exe",
                _desktop_user,
            )
            boot_pids["runtime_broker"] = _c(
                boot_pids["svchost_local_system"],
                r"C:\Windows\System32\RuntimeBroker.exe",
                "RuntimeBroker.exe",
                _desktop_user,
            )
        else:
            # Servers/DCs: no persistent desktop session at boot
            boot_pids["explorer"] = boot_pids["winlogon"]  # Alias for fallback lookups
        boot_pids["dwm"] = _c(
            boot_pids["csrss_s0"],
            r"C:\Windows\System32\dwm.exe",
            "dwm.exe",
            "SYSTEM",
        )

        roles = {role.lower() for role in (system.roles or [])}
        service_defaults = getattr(self, "_system_service_defaults", {})
        services = tuple(service_defaults.get(system.hostname, system.services or ()))
        db_services = database_services_for_host(
            services,
            "windows",
            has_database_role=bool(roles & {"database", "db_server"}),
        )
        if "mssql" in db_services:
            boot_pids["sqlservr"] = _c(
                boot_pids["services"],
                r"C:\Program Files\Microsoft SQL Server\MSSQL16.MSSQLSERVER\MSSQL\Binn\sqlservr.exe",
                "sqlservr.exe -sMSSQLSERVER",
                r"NT SERVICE\MSSQLSERVER",
            )
        if lifecycle_authority is None:
            if boot_base is not None:
                sm.set_current_time(boot_base)
            return

        assert batch_builder is not None
        if owns_batch:
            # Fixture-only direct callers own a one-host batch. Production injects
            # the single fleet builder from _seed_system_process_trees().
            try:
                lifecycle_authority.materialize_batch(batch_builder.seal())
            finally:
                if boot_base is not None and sm.state.current_time != boot_base:
                    sm.set_current_time(boot_base)
        pids.update(boot_pids)

    def _seed_linux_process_tree(
        self,
        system: System,
        pids: dict[str, int],
        *,
        _batch_builder: MaterializationBatchBuilder | None = None,
        _boot_base: datetime | None = None,
    ) -> None:
        """Seed a Linux boot tree; direct strict calls are fixture-only."""
        sm = self.state_manager
        lifecycle_authority = self._boot_lifecycle_authority()
        hn = system.hostname
        os_str = system.os.lower()

        is_rhel = any(d in os_str for d in ("centos", "rhel", "red hat", "rocky", "alma"))
        boot_base = _boot_base if _batch_builder is not None else sm.state.current_time
        boot_rng = random.Random(_stable_seed(f"linux_boot_sequence:{hn}"))
        boot_elapsed = 0.0
        owns_batch = lifecycle_authority is not None and _batch_builder is None
        batch_builder = sm.begin_materialization_batch() if owns_batch else _batch_builder
        boot_pids = pids if lifecycle_authority is None else {}
        process_plans_by_pid: dict[int, ProcessMaterializationPlan] = {}
        if batch_builder is not None and boot_base is not None:
            batch_builder.plan_boot_time(hn, boot_base)

        def _advance_boot_clock() -> datetime | None:
            nonlocal boot_elapsed
            if boot_base is None:
                return None
            boot_elapsed += boot_rng.uniform(0.05, 1.9)
            process_time = boot_base + timedelta(seconds=boot_elapsed)
            if lifecycle_authority is None:
                sm.set_current_time(process_time)
            return process_time

        def _c(parent: int, image: str, cmd: str, user: str) -> int:
            process_time = _advance_boot_clock()
            if lifecycle_authority is None:
                # Compatibility fixtures deliberately omit the engine owner.
                return sm.create_process(hn, parent, image, cmd, user, "System")
            assert batch_builder is not None
            plan = batch_builder.plan_process(
                system=hn,
                parent_pid=parent,
                image=image,
                command_line=cmd,
                username=user,
                integrity_level="System",
                os_category="linux",
                start_time=process_time,
                parent_plan=process_plans_by_pid.get(parent),
            )
            process_plans_by_pid[plan.identity.pid] = plan
            return plan.identity.pid

        if lifecycle_authority is None:
            sm.register_process(
                system=hn,
                pid=1,
                parent_pid=0,
                image="/usr/lib/systemd/systemd",
                command_line="/usr/lib/systemd/systemd --system --deserialize 26",
                username="root",
                integrity_level="System",
                os_category="linux",
            )
            boot_pids["systemd"] = 1
        else:
            assert batch_builder is not None
            plan = batch_builder.plan_process(
                system=hn,
                fixed_pid=1,
                parent_pid=0,
                image="/usr/lib/systemd/systemd",
                command_line="/usr/lib/systemd/systemd --system --deserialize 26",
                username="root",
                integrity_level="System",
                os_category="linux",
                start_time=boot_base,
            )
            process_plans_by_pid[plan.identity.pid] = plan
            boot_pids["systemd"] = plan.identity.pid

        journal_path = "/usr/lib/systemd/systemd-journald"
        boot_pids["journald"] = _c(boot_pids["systemd"], journal_path, journal_path, "root")

        udev_path = "/usr/lib/systemd/systemd-udevd" if is_rhel else "/lib/systemd/systemd-udevd"
        boot_pids["udevd"] = _c(boot_pids["systemd"], udev_path, udev_path, "root")

        boot_pids["rsyslogd"] = _c(
            boot_pids["systemd"], "/usr/sbin/rsyslogd", "rsyslogd -n", "syslog"
        )
        boot_pids["networkmanager"] = _c(
            boot_pids["systemd"],
            "/usr/sbin/NetworkManager",
            "/usr/sbin/NetworkManager --no-daemon",
            "root",
        )
        boot_pids["dbus"] = _c(
            boot_pids["systemd"],
            "/usr/bin/dbus-daemon",
            "/usr/bin/dbus-daemon --system",
            "messagebus",
        )

        logind_path = "/usr/lib/systemd/systemd-logind"
        boot_pids["logind"] = _c(boot_pids["systemd"], logind_path, logind_path, "root")

        boot_pids["sshd"] = _c(boot_pids["systemd"], "/usr/sbin/sshd", "/usr/sbin/sshd -D", "root")

        roles = {role.lower() for role in (system.roles or [])}
        service_defaults = getattr(self, "_system_service_defaults", {})
        services = tuple(service_defaults.get(system.hostname, system.services or ()))
        service_tokens = {svc.lower() for svc in services}
        world_model = getattr(self, "world_model", None)
        host_world = getattr(world_model, "hosts", {}).get(system.hostname)
        if host_world is not None and host_world.supports(HostCapability.SMB_SERVER):
            server_profile = select_server_profile("linux", services)
            listener = render_smb_process(server_profile.listener)
            boot_pids["smbd"] = _c(
                boot_pids["systemd"],
                listener.image,
                listener.command_line,
                listener.username,
            )
            boot_pids["smbd_master"] = boot_pids["smbd"]
        proxy_markers = {"forward_proxy", "squid", "proxy"}
        if roles & proxy_markers or service_tokens & proxy_markers:
            squid_user = "squid" if is_rhel else "proxy"
            boot_pids["squid"] = _c(
                boot_pids["systemd"],
                "/usr/sbin/squid",
                "/usr/sbin/squid --foreground -YC",
                squid_user,
            )

        web_markers = {"web_server", "apache", "apache2", "httpd", "nginx"}
        if roles & web_markers or service_tokens & web_markers or "web" in system.hostname.lower():
            if is_rhel:
                boot_pids["httpd"] = _c(
                    boot_pids["systemd"],
                    "/usr/sbin/httpd",
                    "/usr/sbin/httpd -DFOREGROUND",
                    "apache",
                )
            else:
                boot_pids["apache2"] = _c(
                    boot_pids["systemd"],
                    "/usr/sbin/apache2",
                    "/usr/sbin/apache2 -DFOREGROUND",
                    "www-data",
                )

        db_services = database_services_for_host(
            services,
            "linux",
            has_database_role=bool(roles & {"database", "db_server"}),
        )
        if "mysql" in db_services:
            boot_pids["mysqld"] = _c(
                boot_pids["systemd"],
                "/usr/sbin/mysqld",
                "/usr/sbin/mysqld --daemonize --pid-file=/run/mysqld/mysqld.pid",
                "mysql",
            )
        if "postgresql" in db_services:
            boot_pids["postgres"] = _c(
                boot_pids["systemd"],
                "/usr/bin/postgres",
                "/usr/bin/postgres -D /var/lib/pgsql/data",
                "postgres",
            )

        cron_name = "/usr/sbin/crond" if is_rhel else "/usr/sbin/cron"
        cron_cmd = "/usr/sbin/crond -n" if is_rhel else "/usr/sbin/cron -f"
        boot_pids["cron"] = _c(boot_pids["systemd"], cron_name, cron_cmd, "root")

        boot_pids["agetty1"] = _c(
            boot_pids["systemd"],
            "/sbin/agetty",
            "/sbin/agetty --noclear tty1 linux",
            "root",
        )
        boot_pids["agetty2"] = _c(
            boot_pids["systemd"],
            "/sbin/agetty",
            "/sbin/agetty --noclear tty2 linux",
            "root",
        )
        boot_pids["snapd"] = _c(
            boot_pids["systemd"],
            "/usr/lib/snapd/snapd",
            "/usr/lib/snapd/snapd",
            "root",
        )
        # NTP: Ubuntu uses systemd-timesyncd, RHEL uses chronyd
        if is_rhel:
            boot_pids["chronyd"] = _c(
                boot_pids["systemd"],
                "/usr/sbin/chronyd",
                "/usr/sbin/chronyd -F 2",
                "chrony",
            )
        else:
            boot_pids["timesyncd"] = _c(
                boot_pids["systemd"],
                "/usr/lib/systemd/systemd-timesyncd",
                "/usr/lib/systemd/systemd-timesyncd",
                "systemd-timesync",
            )

        # DNS: Ubuntu uses systemd-resolved; RHEL apps resolve directly via glibc
        if not is_rhel:
            boot_pids["systemd_resolved"] = _c(
                boot_pids["systemd"],
                "/usr/lib/systemd/systemd-resolved",
                "/usr/lib/systemd/systemd-resolved",
                "systemd-resolve",
            )

        boot_pids["bash"] = _c(boot_pids["sshd"], "/bin/bash", "-bash", "root")
        if lifecycle_authority is None:
            if boot_base is not None:
                sm.set_current_time(boot_base)
            return

        assert batch_builder is not None
        if owns_batch:
            # Fixture-only direct callers own a one-host batch. Production injects
            # the single fleet builder from _seed_system_process_trees().
            try:
                lifecycle_authority.materialize_batch(batch_builder.seal())
            finally:
                if boot_base is not None and sm.state.current_time != boot_base:
                    sm.set_current_time(boot_base)
        pids.update(boot_pids)

    def _get_system_exposure(self, system) -> str:
        """Get the network exposure for a system based on its segment.

        Returns 'internal', 'external', or 'both'. Defaults to 'both' if
        no network config exists (backward compat).
        """
        if not self.scenario.environment.network:
            return "both"
        import ipaddress as _ipa

        sys_ip = _ipa.ip_address(system.ip)
        for seg in self.scenario.environment.network.segments:
            net = _ipa.ip_network(seg.cidr, strict=False)
            if sys_ip in net:
                return seg.exposure
        return "internal"

    def _get_segment_for_system(self, system):
        """Return the NetworkSegment for a system's IP, or None if no match."""
        if not self.scenario.environment.network:
            return None
        import ipaddress as _ipa

        sys_ip = _ipa.ip_address(system.ip)
        for seg in self.scenario.environment.network.segments:
            if sys_ip in _ipa.ip_network(seg.cidr, strict=False):
                return seg
        return None

    def _generate_external_client_ip(self, rng) -> str:
        """Generate a random external (non-RFC1918) IP for web server clients.

        Excludes non-global special-use ranges and the scenario's own
        org CIDRs (internal segments + public_cidrs) so generated external
        client IPs never accidentally land inside the org's address space.
        """
        import ipaddress as _ipa_ext

        org_nets = getattr(self, "_org_cidr_networks", [])
        excluded_nets = [
            _ipa_ext.ip_network(cidr, strict=False) for cidr in external_client_excluded_cidrs()
        ]
        for _ in range(1000):  # safety bound
            ip = f"{rng.randint(1, 223)}.{rng.randint(0, 255)}.{rng.randint(0, 255)}.{rng.randint(1, 254)}"
            addr = _ipa_ext.ip_address(ip)
            if not addr.is_global:
                continue
            if any(addr in net for net in excluded_nets):
                continue
            # Exclude org's own CIDRs
            if org_nets:
                if any(addr in net for net in org_nets):
                    continue
            return ip
        return ip  # fallback after safety bound
