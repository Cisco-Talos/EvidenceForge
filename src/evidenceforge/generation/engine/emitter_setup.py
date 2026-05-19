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

import logging
import random
from datetime import timedelta

from evidenceforge.formats import load_format
from evidenceforge.generation.activity.edr_pools import normalize_defender_platform_path
from evidenceforge.generation.activity.network_params import load_network_params, public_ntp_ips
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
    ZeekSslEmitter,
    ZeekWeirdEmitter,
    ZeekX509Emitter,
)
from evidenceforge.models.scenario import System
from evidenceforge.utils.rng import _stable_seed

logger = logging.getLogger(__name__)


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


def _build_emitter_classes() -> dict:
    """Build emitter class map at call time (supports test patching of module-level names)."""
    return {
        "windows_event_security": WindowsEventEmitter,
        "windows_event_sysmon": SysmonEventEmitter,
        "zeek_conn": ZeekEmitter,
        "zeek_dns": ZeekDnsEmitter,
        "zeek_http": ZeekHttpEmitter,
        "zeek_ssl": ZeekSslEmitter,
        "zeek_files": ZeekFilesEmitter,
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
    "zeek_ssl",
    "zeek_files",
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

# Service name -> (port, zeek_service) mapping for database detection
DB_SERVICE_MAP = {
    "mssql": (1433, "mssql"),
    "sql server": (1433, "mssql"),
    "mysql": (3306, "mysql"),
    "mariadb": (3306, "mysql"),
    "postgres": (5432, "postgresql"),
    "postgresql": (5432, "postgresql"),
}


class EmitterSetupMixin:
    """Mixin providing emitter initialization and infrastructure setup methods."""

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
            asa_emitter._output_end_time = self.end_time
            if self.scenario.environment.network:
                asa_emitter._segment_config = [
                    {"name": seg.name, "cidr": seg.cidr}
                    for seg in self.scenario.environment.network.segments
                ]
                for sensor in self.scenario.environment.network.sensors:
                    if sensor.interfaces:
                        hostname = sensor.hostname or sensor.name
                        asa_emitter._sensor_interfaces[hostname] = sensor.interfaces
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
        if "zeek_dhcp" not in self.emitters:
            return
        rng = random.Random(_stable_seed("dhcp_leases"))
        from evidenceforge.utils.ids import generate_zeek_uid

        # Track lease state for periodic renewals
        self._dhcp_lease_state: dict[str, dict] = {}
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
            infra_ips = getattr(self, "_infra_ips", {})
            dhcp_servers = infra_ips.get("dc") or infra_ips.get("dns") or ["10.0.0.1"]
            dhcp_server = dhcp_servers[0] if isinstance(dhcp_servers, list) else dhcp_servers
            self.state_manager.set_current_time(ts)
            self.activity_generator.generate_dhcp_lease(
                system=system,
                time=ts,
                mac=mac,
                server_addr=dhcp_server,
                lease_time=lease_time,
                uid=uid,
            )
            # Store state for renewals
            self._dhcp_lease_state[system.hostname] = {
                "mac": mac,
                "lease_time": lease_time,
                "last_renewal": ts.timestamp(),
                "server_addr": dhcp_server,
                "system": system,
            }

    def _build_sid_registry(self) -> dict[str, str]:
        """Build a SID registry mapping usernames to Windows SIDs.

        Generates a domain base SID (S-1-5-21-{3 sub-authorities}) and assigns
        each user a unique RID starting at 1001. Well-known SIDs are included
        for system accounts.

        Returns:
            Dict mapping username to full SID string
        """
        rng = random.Random(_stable_seed(self.scenario.name))
        base_sid = (
            f"S-1-5-21-{rng.randint(1000000000, 3999999999)}"
            f"-{rng.randint(1000000000, 3999999999)}"
            f"-{rng.randint(1000000000, 3999999999)}"
        )

        registry: dict[str, str] = {
            "SYSTEM": "S-1-5-18",
            "LOCAL SERVICE": "S-1-5-19",
            "NETWORK SERVICE": "S-1-5-20",
            "Administrator": f"{base_sid}-500",
            "Guest": f"{base_sid}-501",
            "krbtgt": f"{base_sid}-502",
        }

        # Single domain-wide monotonic RID counter (mirrors real AD RID Master FSMO).
        # Objects are allocated sequentially: users → machines → service accounts.
        rid = 1001
        for user in self.scenario.environment.users:
            registry[user.username] = f"{base_sid}-{rid}"
            rid += 1
        for system in self.scenario.environment.systems:
            machine_name = f"{system.hostname}$"
            registry[machine_name] = f"{base_sid}-{rid}"
            rid += 1
        for svc in self.scenario.environment.service_accounts:
            if svc not in registry:
                registry[svc] = f"{base_sid}-{rid}"
                rid += 1

        logger.info(f"Built SID registry: {len(registry)} entries (domain: {base_sid})")
        return registry

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
        """Detect infrastructure IPs from scenario systems.

        Scans system hostnames/types/services for role hints and
        maps them to IPs. Falls back to defaults for missing roles.
        """
        if hasattr(self, "world_model"):
            return self.world_model.to_infrastructure_ips()

        infra: dict[str, str | list] = {
            "dns": [],
            "ntp": [],  # Populated from DCs (AD) or external (non-domain)
            "dc": [],
            "dc_hostnames": [],
            "db_servers": [],
            "exchange": None,
        }

        for system in self.scenario.environment.systems:
            hn = system.hostname.lower()
            stype = system.type.lower() if system.type else ""
            if "dc" in hn or stype == "domain_controller":
                infra["dc"].append(system.ip)
                infra["dc_hostnames"].append(system.hostname)
                if system.ip not in infra["dns"]:
                    infra["dns"].append(system.ip)
            elif "dns" in hn:
                if system.ip not in infra["dns"]:
                    infra["dns"].append(system.ip)
            elif "ntp" in hn:
                infra["ntp"] = [system.ip]
            elif "exch" in hn or "mail" in hn or stype == "mail_server":
                infra["exchange"] = system.ip

            for svc in system.services:
                svc_lower = svc.lower()
                for svc_key, (port, zeek_svc) in DB_SERVICE_MAP.items():
                    if svc_key in svc_lower:
                        infra["db_servers"].append(
                            {
                                "ip": system.ip,
                                "port": port,
                                "service": zeek_svc,
                            }
                        )
                        break

        if not infra["dns"]:
            infra["dns"] = ["10.0.0.1"]
        if not infra["dc"]:
            infra["dc"] = [infra["dns"][0]]
            infra["dc_hostnames"] = ["DC-01"]

        # AD environments: workstations sync NTP from the DC (W32Time service).
        # Only use external NIST servers for non-domain environments.
        if not infra["ntp"]:
            if infra["dc"]:
                infra["ntp"] = list(infra["dc"])
            else:
                infra["ntp"] = public_ntp_ips() or ["129.6.15.28", "132.163.97.1"]

        return infra

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

    def _seed_system_process_trees(self) -> None:
        """Pre-seed StateManager with long-running system processes.

        These processes were started at boot (before the scenario window).
        We register them silently (no log events) so they exist as valid
        parents for child processes spawned during the scenario.
        """
        import hashlib as _hl

        from evidenceforge.generation.activity import _get_os_category

        self._machine_ids: dict[str, str] = {}
        original_time = self.state_manager.state.current_time

        for system in self.scenario.environment.systems:
            os_cat = _get_os_category(system.os)
            pids: dict[str, int] = {}
            boot_uptime = getattr(self, "_kernel_boot_uptimes", {}).get(system.hostname)
            boot_time = (
                self.start_time - timedelta(seconds=boot_uptime)
                if self.start_time and boot_uptime is not None
                else original_time
            )
            if boot_time is not None:
                self.state_manager.set_current_time(boot_time)

            if os_cat == "windows":
                self._seed_windows_process_tree(system, pids)
            else:
                self._seed_linux_process_tree(system, pids)
                # Per-host persistent machine-ID (like /etc/machine-id)
                self._machine_ids[system.hostname] = _hl.md5(
                    f"machine_id_{system.hostname}".encode(), usedforsecurity=False
                ).hexdigest()

            self._system_pids[system.hostname] = pids

            # Register boot time for entity lifecycle validation
            if boot_time is not None:
                self.state_manager.register_boot_time(system.hostname, boot_time)

        if original_time is not None:
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

        # Register system IP→FQDN mappings so DNS queries use correct hostnames
        # (e.g., DC-01.meridian-healthcare.com instead of host-10.corp.local)
        from evidenceforge.generation.activity.network import REVERSE_DNS

        ad_domain = self._resolve_ad_domain()
        for system in self.scenario.environment.systems:
            fqdn = f"{system.hostname}.{ad_domain}"
            REVERSE_DNS[system.ip] = fqdn

        # Share system PIDs with activity generator for dynamic ParentProcessName
        self.activity_generator._system_pids = self._system_pids
        self.activity_generator._all_system_ips = [s.ip for s in self.scenario.environment.systems]
        self.activity_generator._db_servers = self._infra_ips.get("db_servers", [])
        self.activity_generator._dns_server_ips = self._infra_ips.get("dns", ["10.0.0.1"])
        self.activity_generator._exchange_ip = self._infra_ips.get("exchange")
        self.activity_generator._dc_hostnames = self._infra_ips.get("dc_hostnames", [])
        self.activity_generator._dc_ips = self._infra_ips.get("dc", [])
        self.activity_generator._dc_systems = [
            s for s in self.scenario.environment.systems if s.type == "domain_controller"
        ]

    def _seed_windows_process_tree(self, system: System, pids: dict[str, int]) -> None:
        """Seed Windows system process tree in StateManager."""
        sm = self.state_manager
        hn = system.hostname
        boot_base = sm.state.current_time
        boot_rng = random.Random(_stable_seed(f"windows_boot_sequence:{hn}"))
        boot_elapsed = 0.0

        def _advance_boot_clock() -> None:
            nonlocal boot_elapsed
            if boot_base is None:
                return
            boot_elapsed += boot_rng.uniform(0.08, 2.75)
            sm.set_current_time(boot_base + timedelta(seconds=boot_elapsed))

        def _c(parent, image, cmd, user):
            _advance_boot_clock()
            image = normalize_defender_platform_path(image, hn)
            return sm.create_process(hn, parent, image, cmd, user, "System")

        # PID 4 is always the Windows System process (parent of smss.exe).
        # Register it directly — create_process() auto-allocates PIDs so we
        # bypass it to hardcode PID 4 as Windows requires.
        from evidenceforge.models.state import RunningProcess

        sm.state.running_processes[(hn, 4)] = RunningProcess(
            pid=4,
            parent_pid=0,
            image="System",
            command_line="",
            username="SYSTEM",
            system=hn,
            start_time=sm.state.current_time,
            integrity_level="System",
        )
        pids["system"] = 4
        pids["smss"] = _c(4, r"C:\Windows\System32\smss.exe", "smss.exe", "SYSTEM")
        pids["csrss_s0"] = _c(pids["smss"], r"C:\Windows\System32\csrss.exe", "csrss.exe", "SYSTEM")
        pids["wininit"] = _c(
            pids["smss"], r"C:\Windows\System32\wininit.exe", "wininit.exe", "SYSTEM"
        )
        pids["services"] = _c(
            pids["wininit"], r"C:\Windows\System32\services.exe", "services.exe", "SYSTEM"
        )
        pids["lsass"] = _c(pids["wininit"], r"C:\Windows\System32\lsass.exe", "lsass.exe", "SYSTEM")

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
            pids[name] = _c(pids["services"], r"C:\Windows\System32\svchost.exe", cmdline, user)

        pids["msmpeng"] = _c(
            pids["services"],
            r"C:\ProgramData\Microsoft\Windows Defender\Platform\MsMpEng.exe",
            "MsMpEng.exe",
            "SYSTEM",
        )
        pids["search_indexer"] = _c(
            pids["services"],
            r"C:\Windows\System32\SearchIndexer.exe",
            "SearchIndexer.exe",
            "SYSTEM",
        )
        pids["wmiprvse"] = _c(
            pids["svchost_dcom"],
            r"C:\Windows\System32\wbem\WmiPrvSE.exe",
            "WmiPrvSE.exe -Embedding",
            "NETWORK SERVICE",
        )
        pids["dllhost"] = _c(
            pids["svchost_dcom"],
            r"C:\Windows\System32\dllhost.exe",
            "dllhost.exe /Processid:{02D4B3F1-FD88-11D1-960D-00805FC79235}",
            "SYSTEM",
        )
        pids["search_protocol_host"] = _c(
            pids["search_indexer"],
            r"C:\Windows\System32\SearchProtocolHost.exe",
            "SearchProtocolHost.exe Global\\UsGthrFltPipeMssGthrPipe",
            "SYSTEM",
        )
        pids["mpcmdrun"] = _c(
            pids["msmpeng"],
            r"C:\ProgramData\Microsoft\Windows Defender\Platform\MpCmdRun.exe",
            "MpCmdRun.exe -Scan -ScanType 1",
            "SYSTEM",
        )
        pids["msiexec"] = _c(
            pids["services"],
            r"C:\Windows\System32\msiexec.exe",
            "msiexec.exe /V",
            "SYSTEM",
        )
        pids["taskhostw"] = _c(
            pids["services"], r"C:\Windows\System32\taskhostw.exe", "taskhostw.exe", "SYSTEM"
        )

        pids["csrss_s1"] = _c(pids["smss"], r"C:\Windows\System32\csrss.exe", "csrss.exe", "SYSTEM")
        pids["winlogon"] = _c(
            pids["smss"], r"C:\Windows\System32\winlogon.exe", "winlogon.exe", "SYSTEM"
        )
        pids["userinit"] = _c(
            pids["winlogon"], r"C:\Windows\System32\userinit.exe", "userinit.exe", "SYSTEM"
        )
        # User-context processes run under the logged-in user, not SYSTEM.
        # Only seed them for workstations with an assigned user; servers/DCs
        # start explorer only when an admin logs in interactively.
        _desktop_user = getattr(system, "assigned_user", None)
        if _desktop_user:
            pids["explorer"] = _c(
                pids["userinit"], r"C:\Windows\explorer.exe", "explorer.exe", _desktop_user
            )
            pids["runtime_broker"] = _c(
                pids["svchost_local_system"],
                r"C:\Windows\System32\RuntimeBroker.exe",
                "RuntimeBroker.exe",
                _desktop_user,
            )
        else:
            # Servers/DCs: no persistent desktop session at boot
            pids["explorer"] = pids["winlogon"]  # Alias for fallback lookups
        pids["dwm"] = _c(pids["csrss_s0"], r"C:\Windows\System32\dwm.exe", "dwm.exe", "SYSTEM")
        if boot_base is not None:
            sm.set_current_time(boot_base)

    def _seed_linux_process_tree(self, system: System, pids: dict[str, int]) -> None:
        """Seed Linux system process tree in StateManager."""
        sm = self.state_manager
        hn = system.hostname
        os_str = system.os.lower()

        is_rhel = any(d in os_str for d in ("centos", "rhel", "red hat", "rocky", "alma"))
        boot_base = sm.state.current_time
        boot_rng = random.Random(_stable_seed(f"linux_boot_sequence:{hn}"))
        boot_elapsed = 0.0

        def _advance_boot_clock() -> None:
            nonlocal boot_elapsed
            if boot_base is None:
                return
            boot_elapsed += boot_rng.uniform(0.05, 1.9)
            sm.set_current_time(boot_base + timedelta(seconds=boot_elapsed))

        def _c(parent, image, cmd, user):
            _advance_boot_clock()
            return sm.create_process(hn, parent, image, cmd, user, "System")

        import uuid

        from evidenceforge.models.state import RunningProcess

        systemd_object_id = str(uuid.uuid5(uuid.NAMESPACE_DNS, f"linux-systemd:{hn}"))
        sm.state.running_processes[(hn, 1)] = RunningProcess(
            pid=1,
            parent_pid=0,
            image="/usr/lib/systemd/systemd",
            command_line="/usr/lib/systemd/systemd --system --deserialize 26",
            username="root",
            system=hn,
            start_time=sm.state.current_time,
            integrity_level="System",
            ecar_object_id=systemd_object_id,
        )
        sm._process_object_ids[(hn, 1)] = systemd_object_id
        pids["systemd"] = 1

        journal_path = "/usr/lib/systemd/systemd-journald"
        pids["journald"] = _c(pids["systemd"], journal_path, journal_path, "root")

        udev_path = "/usr/lib/systemd/systemd-udevd" if is_rhel else "/lib/systemd/systemd-udevd"
        pids["udevd"] = _c(pids["systemd"], udev_path, udev_path, "root")

        pids["rsyslogd"] = _c(pids["systemd"], "/usr/sbin/rsyslogd", "rsyslogd -n", "syslog")
        pids["networkmanager"] = _c(
            pids["systemd"],
            "/usr/sbin/NetworkManager",
            "/usr/sbin/NetworkManager --no-daemon",
            "root",
        )
        pids["dbus"] = _c(
            pids["systemd"], "/usr/bin/dbus-daemon", "/usr/bin/dbus-daemon --system", "messagebus"
        )

        logind_path = "/usr/lib/systemd/systemd-logind"
        pids["logind"] = _c(pids["systemd"], logind_path, logind_path, "root")

        pids["sshd"] = _c(pids["systemd"], "/usr/sbin/sshd", "/usr/sbin/sshd -D [listener]", "root")

        roles = {role.lower() for role in (system.roles or [])}
        service_defaults = getattr(self, "_system_service_defaults", {})
        services = {svc.lower() for svc in service_defaults.get(system.hostname, [])}
        web_markers = {"web_server", "forward_proxy", "apache", "apache2", "httpd", "nginx"}
        if roles & web_markers or services & web_markers or "web" in system.hostname.lower():
            if is_rhel:
                pids["httpd"] = _c(
                    pids["systemd"],
                    "/usr/sbin/httpd",
                    "/usr/sbin/httpd -DFOREGROUND",
                    "apache",
                )
            else:
                pids["apache2"] = _c(
                    pids["systemd"],
                    "/usr/sbin/apache2",
                    "/usr/sbin/apache2 -DFOREGROUND",
                    "www-data",
                )

        cron_name = "/usr/sbin/crond" if is_rhel else "/usr/sbin/cron"
        cron_cmd = "/usr/sbin/crond -n" if is_rhel else "/usr/sbin/cron -f"
        pids["cron"] = _c(pids["systemd"], cron_name, cron_cmd, "root")

        pids["agetty1"] = _c(
            pids["systemd"], "/sbin/agetty", "/sbin/agetty --noclear tty1 linux", "root"
        )
        pids["agetty2"] = _c(
            pids["systemd"], "/sbin/agetty", "/sbin/agetty --noclear tty2 linux", "root"
        )
        pids["snapd"] = _c(pids["systemd"], "/usr/lib/snapd/snapd", "/usr/lib/snapd/snapd", "root")
        # NTP: Ubuntu uses systemd-timesyncd, RHEL uses chronyd
        if is_rhel:
            pids["chronyd"] = _c(
                pids["systemd"], "/usr/sbin/chronyd", "/usr/sbin/chronyd -F 2", "chrony"
            )
        else:
            pids["timesyncd"] = _c(
                pids["systemd"],
                "/usr/lib/systemd/systemd-timesyncd",
                "/usr/lib/systemd/systemd-timesyncd",
                "systemd-timesync",
            )

        # DNS: Ubuntu uses systemd-resolved; RHEL apps resolve directly via glibc
        if not is_rhel:
            pids["systemd_resolved"] = _c(
                pids["systemd"],
                "/usr/lib/systemd/systemd-resolved",
                "/usr/lib/systemd/systemd-resolved",
                "systemd-resolve",
            )

        pids["bash"] = _c(pids["sshd"], "/bin/bash", "-bash", "root")
        if boot_base is not None:
            sm.set_current_time(boot_base)

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
        for _ in range(1000):  # safety bound
            ip = f"{rng.randint(1, 223)}.{rng.randint(0, 255)}.{rng.randint(0, 255)}.{rng.randint(1, 254)}"
            addr = _ipa_ext.ip_address(ip)
            if not addr.is_global:
                continue
            # Exclude org's own CIDRs
            if org_nets:
                if any(addr in net for net in org_nets):
                    continue
            return ip
        return ip  # fallback after safety bound
