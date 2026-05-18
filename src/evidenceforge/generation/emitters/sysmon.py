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

"""Windows Sysmon Event Log emitter.

Mirrors WindowsEventEmitter architecture: buffers raw event dicts, sorts by
timestamp on flush, assigns per-computer EventRecordIDs, renders to XML,
and writes to per-host FQDN directories as windows_event_sysmon.xml.
"""

import hashlib
import random
from datetime import datetime, timedelta
from pathlib import Path
from queue import Empty
from threading import Lock
from typing import Any

from evidenceforge.config.sysmon_filters import load_sysmon_filters
from evidenceforge.events.base import SecurityEvent
from evidenceforge.events.contexts import ProcessContext
from evidenceforge.formats.format_def import FormatDefinition
from evidenceforge.generation.activity.timing_profiles import sample_timing_delta
from evidenceforge.generation.emitters.base import LogEmitter
from evidenceforge.generation.emitters.host_base import _SingleHostWriter
from evidenceforge.generation.emitters.syslog_family import (
    make_syslog_family_route_key,
    sanitize_syslog_family_route_key,
    syslog_family_writer_path,
)
from evidenceforge.generation.emitters.windows import (
    _normalize_windows_time_created,
    _subject_domain,
)
from evidenceforge.generation.emitters.windows_event import format_windows_system_time
from evidenceforge.generation.emitters.windows_snare import (
    WINDOWS_SYSMON_SNARE_FILENAME,
    render_windows_sysmon_snare_syslog,
)
from evidenceforge.utils.paths import sanitize_path_component
from evidenceforge.utils.rng import _stable_seed
from evidenceforge.utils.time import ensure_utc
from evidenceforge.utils.windows_ids import (
    align_windows_id,
    normalize_windows_id_value,
    windows_id_randint,
)

# Well-known Windows port names for Sysmon Event 3
_PORT_NAMES: dict[int, str] = {
    20: "ftp-data",
    21: "ftp",
    22: "ssh",
    25: "smtp",
    53: "domain",
    80: "http",
    88: "kerberos",
    110: "pop3",
    123: "ntp",
    135: "epmap",
    139: "netbios-ssn",
    143: "imap",
    389: "ldap",
    443: "https",
    445: "microsoft-ds",
    636: "ldaps",
    993: "imaps",
    995: "pop3s",
    1433: "ms-sql-s",
    3306: "mysql",
    3389: "ms-wbt-server",
    5432: "postgresql",
    5985: "wsman",
    5986: "wsmans",
    8080: "http-alt",
}

# DNS rcode → Windows DNS QueryStatus mapping
_DNS_STATUS_MAP: dict[str, str] = {
    "NOERROR": "0",
    "SERVFAIL": "9002",
    "NXDOMAIN": "9003",
    "NOTIMP": "9501",
    "REFUSED": "9005",
}


def _format_sysmon_utc_time(timestamp: datetime) -> str:
    """Return Sysmon EventData UtcTime from the rendered source timestamp."""
    return ensure_utc(timestamp).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]


class SysmonEventEmitter(LogEmitter):
    """Emitter for Windows Sysmon Event Log format (XML).

    Same deferred-rendering architecture as WindowsEventEmitter but outputs
    to a separate file (windows_event_sysmon.xml) with Sysmon Provider/Channel.
    """

    _supported_types: set[str] = {
        "process_create",
        "system_process_create",
        "process_terminate",
        "create_remote_thread",
        "process_access",
        "connection",  # Event 3 (NetworkConnect) + Event 22 (DNSQuery)
        "file_create",  # Event 11 (FileCreate)
        "file_modify",  # Event 11 (FileCreate — overwrites also trigger)
        "registry_modify",  # Events 12/13 (RegistryEvent)
        "image_load",  # Event 7 (ImageLoaded)
    }
    # Per-host boot datetimes for realistic parent ProcessGUID timestamps.
    # Set by emitter_setup after initialization.
    _host_boot_times: dict[str, datetime] = {}

    # Per-host cached CallTrace patterns. Real ASLR randomizes DLL base
    # addresses per boot, but intra-module offsets (function entry points)
    # are fixed. All Event 10 events on the same host share the same offsets.
    _call_trace_cache: dict[str, list[str]] = {}

    # PE metadata for common Windows binaries (FileVersion, Description, Product, Company, OriginalFileName)
    _PE_METADATA: dict[str, tuple[str, str, str, str, str]] = {
        "cmd.exe": (
            "10.0.19041.1",
            "Windows Command Processor",
            "Microsoft Windows Operating System",
            "Microsoft Corporation",
            "Cmd.Exe",
        ),
        "powershell.exe": (
            "10.0.19041.1",
            "Windows PowerShell",
            "Microsoft Windows Operating System",
            "Microsoft Corporation",
            "PowerShell.EXE",
        ),
        "svchost.exe": (
            "10.0.19041.1",
            "Host Process for Windows Services",
            "Microsoft Windows Operating System",
            "Microsoft Corporation",
            "svchost.exe",
        ),
        "explorer.exe": (
            "10.0.19041.1",
            "Windows Explorer",
            "Microsoft Windows Operating System",
            "Microsoft Corporation",
            "EXPLORER.EXE",
        ),
        "taskhostw.exe": (
            "10.0.19041.1",
            "Host Process for Windows Tasks",
            "Microsoft Windows Operating System",
            "Microsoft Corporation",
            "taskhostw.exe",
        ),
        "usoclient.exe": (
            "10.0.19041.1",
            "Update Session Orchestrator",
            "Microsoft Windows Operating System",
            "Microsoft Corporation",
            "UsoClient.exe",
        ),
        "lsass.exe": (
            "10.0.19041.1",
            "Local Security Authority Process",
            "Microsoft Windows Operating System",
            "Microsoft Corporation",
            "lsass.exe",
        ),
        "services.exe": (
            "10.0.19041.1",
            "Services and Controller app",
            "Microsoft Windows Operating System",
            "Microsoft Corporation",
            "services.exe",
        ),
        "net.exe": (
            "10.0.19041.1",
            "Net Command",
            "Microsoft Windows Operating System",
            "Microsoft Corporation",
            "net.exe",
        ),
        "net1.exe": (
            "10.0.19041.1",
            "Net Command",
            "Microsoft Windows Operating System",
            "Microsoft Corporation",
            "net1.exe",
        ),
        "sc.exe": (
            "10.0.19041.1",
            "Service Control Manager Configuration Tool",
            "Microsoft Windows Operating System",
            "Microsoft Corporation",
            "sc.exe",
        ),
        "schtasks.exe": (
            "10.0.19041.1",
            "Task Scheduler Configuration Tool",
            "Microsoft Windows Operating System",
            "Microsoft Corporation",
            "schtasks.exe",
        ),
        "whoami.exe": (
            "10.0.19041.1",
            "whoami - displays logged on user information",
            "Microsoft Windows Operating System",
            "Microsoft Corporation",
            "whoami.exe",
        ),
        "notepad.exe": (
            "10.0.19041.1",
            "Notepad",
            "Microsoft Windows Operating System",
            "Microsoft Corporation",
            "NOTEPAD.EXE",
        ),
        "mstsc.exe": (
            "10.0.19041.1",
            "Remote Desktop Connection",
            "Microsoft Windows Operating System",
            "Microsoft Corporation",
            "mstsc.exe",
        ),
        "wmic.exe": (
            "10.0.19041.1",
            "WMI Commandline Utility",
            "Microsoft Windows Operating System",
            "Microsoft Corporation",
            "wmic.exe",
        ),
        "rundll32.exe": (
            "10.0.19041.1",
            "Windows host process (Rundll32)",
            "Microsoft Windows Operating System",
            "Microsoft Corporation",
            "RUNDLL32.EXE",
        ),
        "conhost.exe": (
            "10.0.19041.1",
            "Console Window Host",
            "Microsoft Windows Operating System",
            "Microsoft Corporation",
            "conhost.exe",
        ),
        # Additional system binaries from system_processes.yaml
        "wmiprvse.exe": (
            "10.0.19041.1",
            "WMI Provider Host",
            "Microsoft Windows Operating System",
            "Microsoft Corporation",
            "WmiPrvSE.exe",
        ),
        "dllhost.exe": (
            "10.0.19041.1",
            "COM Surrogate",
            "Microsoft Windows Operating System",
            "Microsoft Corporation",
            "dllhost.exe",
        ),
        "runtimebroker.exe": (
            "10.0.19041.1",
            "Runtime Broker",
            "Microsoft Windows Operating System",
            "Microsoft Corporation",
            "RuntimeBroker.exe",
        ),
        "spoolsv.exe": (
            "10.0.19041.1",
            "Spooler SubSystem App",
            "Microsoft Windows Operating System",
            "Microsoft Corporation",
            "spoolsv.exe",
        ),
        "sihost.exe": (
            "10.0.19041.1",
            "Shell Infrastructure Host",
            "Microsoft Windows Operating System",
            "Microsoft Corporation",
            "sihost.exe",
        ),
        "tiworker.exe": (
            "10.0.19041.1",
            "Windows Module Installer Worker",
            "Microsoft Windows Operating System",
            "Microsoft Corporation",
            "TiWorker.exe",
        ),
        "backgroundtaskhost.exe": (
            "10.0.19041.1",
            "Background Task Host",
            "Microsoft Windows Operating System",
            "Microsoft Corporation",
            "backgroundTaskHost.exe",
        ),
        "searchhost.exe": (
            "10.0.19041.1",
            "Search application",
            "Microsoft Windows Operating System",
            "Microsoft Corporation",
            "SearchHost.exe",
        ),
        "searchprotocolhost.exe": (
            "10.0.19041.1",
            "Microsoft Windows Search Protocol Host",
            "Microsoft Windows Operating System",
            "Microsoft Corporation",
            "SearchProtocolHost.exe",
        ),
        "searchfilterhost.exe": (
            "10.0.19041.1",
            "Microsoft Windows Search Filter Host",
            "Microsoft Windows Operating System",
            "Microsoft Corporation",
            "SearchFilterHost.exe",
        ),
        "searchindexer.exe": (
            "10.0.19041.1",
            "Microsoft Windows Search Indexer",
            "Microsoft Windows Operating System",
            "Microsoft Corporation",
            "SearchIndexer.exe",
        ),
        "dfsr.exe": (
            "10.0.19041.1",
            "DFS Replication Service",
            "Microsoft Windows Operating System",
            "Microsoft Corporation",
            "dfsr.exe",
        ),
        "dns.exe": (
            "10.0.19041.1",
            "DNS Server Service",
            "Microsoft Windows Operating System",
            "Microsoft Corporation",
            "dns.exe",
        ),
        "ntdsutil.exe": (
            "10.0.19041.1",
            "NT Directory Services Utility",
            "Microsoft Windows Operating System",
            "Microsoft Corporation",
            "ntdsutil.exe",
        ),
        "mpcmdrun.exe": (
            "4.18.2211.5",
            "Microsoft Malware Protection Command Line Utility",
            "Microsoft Antimalware",
            "Microsoft Corporation",
            "MpCmdRun.exe",
        ),
        "msmpeng.exe": (
            "4.18.2211.5",
            "Antimalware Service Executable",
            "Microsoft Antimalware",
            "Microsoft Corporation",
            "MsMpEng.exe",
        ),
        "compattelrunner.exe": (
            "10.0.19041.1",
            "Microsoft Compatibility Appraiser",
            "Microsoft Windows Operating System",
            "Microsoft Corporation",
            "CompatTelRunner.exe",
        ),
        "cleanmgr.exe": (
            "10.0.19041.1",
            "Disk Cleanup",
            "Microsoft Windows Operating System",
            "Microsoft Corporation",
            "cleanmgr.exe",
        ),
        "msdtc.exe": (
            "10.0.19041.1",
            "Microsoft Distributed Transaction Coordinator",
            "Microsoft Windows Operating System",
            "Microsoft Corporation",
            "msdtc.exe",
        ),
        "ismserv.exe": (
            "10.0.19041.1",
            "Intersite Messaging Service",
            "Microsoft Windows Operating System",
            "Microsoft Corporation",
            "ismserv.exe",
        ),
        "wsqmcons.exe": (
            "10.0.19041.1",
            "Windows SQM Consolidator",
            "Microsoft Windows Operating System",
            "Microsoft Corporation",
            "wsqmcons.exe",
        ),
        "consent.exe": (
            "10.0.19041.1",
            "Consent UI for administrative applications",
            "Microsoft Windows Operating System",
            "Microsoft Corporation",
            "consent.exe",
        ),
        "slui.exe": (
            "10.0.19041.1",
            "Windows Activation Client",
            "Microsoft Windows Operating System",
            "Microsoft Corporation",
            "slui.exe",
        ),
        "sppsvc.exe": (
            "10.0.19041.1",
            "Microsoft Software Protection Platform Service",
            "Microsoft Windows Operating System",
            "Microsoft Corporation",
            "sppsvc.exe",
        ),
        "ssh.exe": (
            "8.6.0.1",
            "OpenSSH SSH client",
            "OpenSSH for Windows",
            "Microsoft Corporation",
            "ssh.exe",
        ),
    }

    @classmethod
    def _get_pe_metadata(
        cls, image_path: str, host: Any | None = None
    ) -> tuple[str, str, str, str, str]:
        """Look up PE metadata for a Windows binary by image path or name.

        Checks the built-in OS binary table first, then falls back to the
        application catalog for user-installed apps (Chrome, Firefox, etc.).
        """
        # Handle Windows paths on any OS (backslash is not a separator on Unix)
        basename = image_path.rsplit("\\", 1)[-1].rsplit("/", 1)[-1].lower()
        if basename.endswith((".dll", ".api", ".p5x")):
            from evidenceforge.generation.activity.dll_load_profiles import (
                get_module_pe_metadata,
            )

            result = get_module_pe_metadata(image_path)
            if result != ("-", "-", "-", "-", "-"):
                return result
        result = cls._PE_METADATA.get(basename)
        if result:
            return cls._normalize_os_binary_metadata(image_path, result, host)
        # Fall back to application catalog for user-installed apps
        from evidenceforge.generation.activity.application_catalog import get_pe_metadata

        result = get_pe_metadata(basename)
        return cls._normalize_os_binary_metadata(image_path, result, host)

    @staticmethod
    def _signed_module_metadata(
        image_path: str,
        signature: str,
    ) -> tuple[str, str, str, str, str]:
        """Return plausible version metadata for signed DLLs missing catalog data."""
        basename = image_path.rsplit("\\", 1)[-1].rsplit("/", 1)[-1]
        normalized_path = image_path.replace("/", "\\").lower()
        signature_lower = signature.lower()
        if "\\windows\\" in normalized_path or "microsoft" in signature_lower:
            return (
                "10.0.19041.1",
                f"{basename} system library",
                "Microsoft Windows Operating System",
                "Microsoft Corporation",
                basename,
            )
        if "cisco" in normalized_path or "cisco" in signature_lower:
            return (
                "5.1.8.42",
                f"{basename} module",
                "Cisco Secure Client",
                "Cisco Systems, Inc.",
                basename,
            )
        company = signature.strip() or "Verified Publisher"
        return ("1.0.0.0", f"{basename} module", company, company, basename)

    @classmethod
    def _normalize_os_binary_metadata(
        cls,
        image_path: str,
        metadata: tuple[str, str, str, str, str],
        host: Any | None,
    ) -> tuple[str, str, str, str, str]:
        """Keep Microsoft OS binary file versions consistent for the host OS."""
        fv, desc, prod, company, orig = metadata
        if not host:
            return metadata
        if company != "Microsoft Corporation" or prod not in {
            "Microsoft Windows",
            "Microsoft Windows Operating System",
        }:
            return metadata
        if not cls._is_windows_os_binary_path(image_path):
            return metadata
        component_version = cls._servicing_stack_version_from_path(image_path)
        if component_version and orig.lower() == "tiworker.exe":
            return component_version, desc, prod, company, orig
        return cls._host_windows_file_version(host), desc, prod, company, orig

    @staticmethod
    def _is_windows_os_binary_path(image_path: str) -> bool:
        image_lower = image_path.replace("/", "\\").lower()
        return (
            "\\windows\\system32\\" in image_lower
            or "\\windows\\syswow64\\" in image_lower
            or image_lower.startswith("c:\\windows\\")
        )

    @staticmethod
    def _servicing_stack_version_from_path(image_path: str) -> str:
        image_lower = image_path.replace("/", "\\").lower()
        marker = "microsoft-windows-servicingstack_31bf3856ad364e35_"
        if marker not in image_lower:
            return ""
        tail = image_lower.split(marker, 1)[1]
        version = tail.split("_", 1)[0]
        parts = version.split(".")
        if len(parts) == 4 and all(part.isdigit() for part in parts):
            return version
        return ""

    @staticmethod
    def _host_windows_file_version(host: Any) -> str:
        os_name = str(getattr(host, "os", "") or "").lower()
        system_type = str(getattr(host, "system_type", "") or "").lower()
        if "windows 11" in os_name:
            return "10.0.22621.1"
        if "server" in os_name or system_type in {"server", "domain_controller"}:
            if "2019" in os_name:
                return "10.0.17763.1"
            return "10.0.20348.1"
        return "10.0.19041.1"

    def _get_sysmon_thread_id(self, hostname: str) -> int:
        """Return a ThreadID from a small reused pool for this host.

        Real Sysmon reuses a small thread pool (3-5 threads), not random IDs.
        """
        cache = getattr(self, "_sysmon_thread_pools", None)
        if cache is None:
            cache = self._sysmon_thread_pools = {}
        counters = getattr(self, "_sysmon_thread_counters", None)
        if counters is None:
            counters = self._sysmon_thread_counters = {}
        last_threads = getattr(self, "_sysmon_last_thread_by_host", None)
        if last_threads is None:
            last_threads = self._sysmon_last_thread_by_host = {}
        if hostname not in cache:
            rng = random.Random(_stable_seed(f"sysmon_threads_{hostname}"))
            cache[hostname] = [
                windows_id_randint(rng, 1000, 5000) for _ in range(rng.randint(3, 5))
            ]
            counters[hostname] = 0
        pool = cache[hostname]
        counter = counters.get(hostname, 0)
        counters[hostname] = counter + 1
        rng = random.Random(_stable_seed(f"sysmon_thread_choice:{hostname}:{counter}"))
        previous = last_threads.get(hostname)
        if previous in pool and rng.random() < 0.58:
            return previous
        weights = [max(1, len(pool) * 3 - index * 2) for index, _thread_id in enumerate(pool)]
        thread_id = rng.choices(pool, weights=weights, k=1)[0]
        last_threads[hostname] = thread_id
        return thread_id

    def _get_sysmon_pid(self, hostname: str) -> int:
        """Return stable Sysmon service PID for a given host.

        The Sysmon driver runs as a single persistent process; its PID
        must be the same across all events from that host.
        """
        cache = getattr(self, "_sysmon_pids", None)
        if cache is None:
            cache = self._sysmon_pids = {}
        if hostname not in cache:
            h = int(
                hashlib.md5(f"sysmon:{hostname}".encode(), usedforsecurity=False).hexdigest(), 16
            )
            cache[hostname] = align_windows_id(1800 + (h % 1200))  # range 1800-3000
        return cache[hostname]

    def _get_call_trace(self, hostname: str) -> str:
        """Return a CallTrace string with per-host stable offsets.

        Loads call chain patterns from calltrace_patterns.yaml, then generates
        concrete offsets per-host using a hostname-seeded RNG. Offsets are fixed
        within a boot session (matching real ASLR behavior) but vary across hosts.
        """
        if hostname not in self._call_trace_cache:
            from evidenceforge.generation.activity.calltrace_patterns import (
                load_calltrace_patterns,
            )

            patterns = load_calltrace_patterns()
            rng = random.Random(_stable_seed(f"calltrace_{hostname}"))
            rendered = []
            for pat in patterns:
                modules = pat["modules"]
                ranges = pat["offset_ranges"]
                parts = []
                for mod in modules:
                    lo, hi = ranges[mod]
                    off = rng.randint(lo, hi)
                    parts.append(f"C:\\Windows\\SYSTEM32\\{mod}+{off:X}")
                rendered.append("|".join(parts))
            self._call_trace_cache[hostname] = rendered
        return random.choice(self._call_trace_cache[hostname])

    def _resolve_process_from_pid(self, hostname: str, pid: int) -> tuple[int, str]:
        """Look up process image from StateManager by PID.

        Returns (pid, image_path). Falls back to "-" (Sysmon convention for
        unknown) when the PID is not found, rather than guessing svchost.exe
        which would produce misleading Event 3/11/12 attributions.
        """
        if pid <= 0:
            return (pid, "-")
        sm = getattr(self, "_state_manager", None)
        if sm is None:
            return (pid, "-")
        proc = sm.get_process(hostname, pid)
        if proc is not None:
            return (pid, proc.image)
        return (pid, "-")

    @staticmethod
    def _resolve_destination_hostname(ip: str) -> str:
        """Resolve destination IP to hostname via REVERSE_DNS.

        Returns FQDN for known internal hosts (scenario systems), "-" for unknown.
        """
        from evidenceforge.generation.activity.network import REVERSE_DNS

        return REVERSE_DNS.get(ip, "-")

    def _get_stable_process_guid(
        self, hostname: str, pid: int, fallback_timestamp: datetime
    ) -> str:
        """Generate ProcessGuid using the process creation time for stability.

        Real Sysmon keyed ProcessGuid on the process start time, so the same
        PID produces the same GUID across Events 1, 3, 5, 7, 11, 12/13, 22.
        Falls back to the event timestamp when the process isn't in StateManager.
        """
        ts = fallback_timestamp
        sm = getattr(self, "_state_manager", None)
        if sm and pid > 0:
            proc = sm.get_process(hostname, pid)
            if proc is not None and proc.start_time <= fallback_timestamp:
                ts = proc.start_time
        return self._generate_process_guid(hostname, pid, ts)

    def can_handle(self, event: SecurityEvent) -> bool:
        """Sysmon emitter handles supported event types on Windows hosts."""
        if event.event_type not in self._supported_types:
            return False
        if event.src_host is None or event.src_host.os_category != "windows":
            return False
        return True

    def emit(self, event: SecurityEvent) -> None:
        """Dispatch to per-type render method, applying Sysmon filters."""
        if event.event_type in ("process_create", "system_process_create"):
            self._render_sysmon_process_create(event)
        elif event.event_type == "process_terminate":
            self._render_sysmon_process_terminate(event)
        elif event.event_type == "create_remote_thread":
            self._render_sysmon_create_remote_thread(event)
        elif event.event_type == "process_access":
            self._render_sysmon_process_access(event)
        elif event.event_type == "connection":
            # Connection events can produce Event 3 (NetworkConnect) and/or Event 22 (DNSQuery)
            is_application_layer_only = (
                event.network is not None and event.network.application_layer_only
            )
            if not is_application_layer_only and self._passes_event3_filter(event):
                self._render_sysmon_network_connect(event)
            if event.dns and self._passes_event22_filter(event):
                self._render_sysmon_dns_query(event)
        elif event.event_type in ("file_create", "file_modify"):
            if event.file and self._passes_event11_filter(event):
                self._render_sysmon_file_create(event)
        elif event.event_type == "registry_modify":
            if event.registry:
                self._render_sysmon_registry_event(event)
        elif event.event_type == "image_load":
            if event.image_load and self._passes_event7_filter(event):
                self._render_sysmon_image_loaded(event)

    @staticmethod
    def _format_user(username: str, netbios_domain: str) -> str:
        """Format Sysmon User field with correct domain for well-known accounts.

        Windows always reports SYSTEM, LOCAL SERVICE, and NETWORK SERVICE
        under 'NT AUTHORITY', never under the AD domain name.
        """
        if "\\" in username:
            return username
        domain = _subject_domain(username, netbios_domain)
        return f"{domain}\\{username}"

    @staticmethod
    def _fallback_user_sid(username: str) -> str:
        """Return a deterministic SID when older callers omit AuthContext.user_sid."""
        normalized = username.split("\\")[-1].upper()
        well_known = {
            "SYSTEM": "S-1-5-18",
            "LOCAL SERVICE": "S-1-5-19",
            "NETWORK SERVICE": "S-1-5-20",
        }
        if normalized in well_known:
            return well_known[normalized]
        rid = 1000 + (_stable_seed(f"sysmon_hku_sid:{normalized.lower()}") % 50000)
        return f"S-1-5-21-0-0-0-{rid}"

    def _native_registry_target_object(self, target_object: str, event: SecurityEvent) -> str:
        """Render user-hive aliases as Sysmon-native HKU\\SID paths."""
        if not target_object.startswith("HKCU\\"):
            return target_object
        username = ""
        sid = ""
        if event.auth is not None:
            username = event.auth.username or ""
            sid = event.auth.user_sid or ""
        if not username and event.process is not None:
            username = event.process.username or ""
        if not sid:
            sid = self._fallback_user_sid(username or "user")
        suffix = target_object.removeprefix("HKCU\\")
        return f"HKU\\{sid}\\{suffix}"

    def _generate_process_guid(self, hostname: str, pid: int, timestamp: datetime) -> str:
        """Generate a deterministic Sysmon ProcessGuid from host+pid+time.

        Real Sysmon ProcessGUID format: {machine_guid}-HHHH-HHHH-SSSS-XXXXXXXXXXXX}
        where HHHHHHHH is the hex Unix timestamp of the process creation time
        and SSSS is a PID-based sequence number.

        The first DWORD is a stable machine-specific value (same for all
        processes on a given host), matching real Sysmon behavior.

        The timestamp segments use the process creation timestamp so the GUID
        does not expose synthetic boot-relative low counters. Host boot time is
        still included in the stable hash material for per-host uniqueness.
        """
        # Machine-specific first DWORD (stable across all processes on this host)
        machine_prefix = hashlib.md5(
            f"sysmon_machine_{hostname}".encode(), usedforsecurity=False
        ).hexdigest()[:8]

        # Second/third segments: source-native-looking process creation time.
        unix_ts = int(timestamp.timestamp())
        boot_time = getattr(self, "_host_boot_times", {}).get(hostname)
        hex_ts = f"{unix_ts:08x}"

        boot_seed = int(boot_time.timestamp()) if boot_time else 0
        seed = f"{hostname}:{pid}:{unix_ts}:{boot_seed}"
        h = hashlib.md5(seed.encode(), usedforsecurity=False).hexdigest()
        # Third segment: source-native-looking deterministic sequence. Avoid
        # directly exposing the PID in the GUID shape while preserving stable
        # per-process correlation across Sysmon event types.
        seq = h[:4]

        # Remaining segments: deterministic filler for uniqueness
        return f"{{{machine_prefix}-{hex_ts[:4]}-{hex_ts[4:]}-{seq}-{h[20:32]}}}"

    @classmethod
    def _generate_hashes(
        cls,
        image: str,
        host: Any | str | None = None,
        rendered_identity: tuple[Any, ...] | None = None,
    ) -> str:
        """Generate deterministic fake file hashes from image path.

        Hashes are keyed by rendered file identity, not signature validation
        state. That keeps identical Image/FileVersion/OriginalFileName tuples
        stable across the fleet while still allowing different Windows builds
        or app versions to differ.
        """
        normalized_image = image.replace("/", "\\").lower()
        seed = normalized_image
        if rendered_identity is not None:
            file_identity = rendered_identity[:5]
            seed = f"{normalized_image}:{':'.join(str(part) for part in file_identity)}"
        elif host is not None and not isinstance(host, str):
            fv, _desc, prod, company, orig = cls._get_pe_metadata(image, host)
            seed = f"{normalized_image}:{fv}:{prod}:{company}:{orig}"
        sha1 = hashlib.sha1(seed.encode(), usedforsecurity=False).hexdigest().upper()
        md5 = hashlib.md5(seed.encode(), usedforsecurity=False).hexdigest().upper()
        sha256 = hashlib.sha256(seed.encode(), usedforsecurity=False).hexdigest().upper()
        imphash = hashlib.md5(f"imp:{seed}".encode(), usedforsecurity=False).hexdigest().upper()
        return f"SHA1={sha1},MD5={md5},SHA256={sha256},IMPHASH={imphash}"

    @staticmethod
    def _generate_logon_guid(hostname: str, logon_id: str) -> str:
        """Generate one stable Sysmon LogonGuid per host/logon session."""
        normalized = logon_id or "0x0"
        digest = hashlib.md5(
            f"sysmon_logon_guid:{hostname}:{normalized}".encode(),
            usedforsecurity=False,
        ).hexdigest()
        return f"{{{digest[:8]}-{digest[8:12]}-{digest[12:16]}-{digest[16:20]}-{digest[20:32]}}}"

    def _resolve_logon_guid(self, hostname: str, logon_id: str, auth: Any | None) -> str:
        """Resolve the canonical Windows LogonGuid for Sysmon process telemetry."""
        if auth is not None and getattr(auth, "logon_guid", ""):
            return auth.logon_guid
        sm = getattr(self, "_state_manager", None)
        if sm is not None and logon_id:
            session = sm.get_session(logon_id)
            if session is not None and getattr(session, "logon_guid", ""):
                return session.logon_guid
        return self._generate_logon_guid(hostname, logon_id)

    def _render_sysmon_process_create(self, event: SecurityEvent) -> None:
        """Render Sysmon Event 1 (ProcessCreate)."""
        random.Random()
        proc = event.process
        auth = event.auth
        host = event.src_host
        render_time = event.timestamp + self._source_offset(
            "process_create",
            host.hostname,
            proc.pid,
            event.timestamp,
            minimum_ms=3,
            maximum_ms=85,
        )

        utc_time = _format_sysmon_utc_time(render_time)
        process_guid = self._get_stable_process_guid(
            host.hostname, proc.pid, proc.start_time or event.timestamp
        )
        parent_proc = None
        sm = getattr(self, "_state_manager", None)
        if sm and proc.parent_pid > 0:
            parent_proc = sm.get_process(host.hostname, proc.parent_pid)
        child_start = proc.start_time or event.timestamp
        _parent_ts = (
            proc.parent_start_time
            if proc.parent_start_time is not None
            else parent_proc.start_time
            if parent_proc is not None and parent_proc.start_time <= child_start
            else self._host_boot_times.get(host.hostname, child_start - timedelta(days=7))
        )
        parent_guid = self._generate_process_guid(
            host.hostname,
            proc.parent_pid,
            _parent_ts,
        )

        # Determine user string
        if auth and auth.username:
            user = self._format_user(auth.username, host.netbios_domain)
            logon_id = auth.logon_id if hasattr(auth, "logon_id") and auth.logon_id else "0x3e7"
        else:
            user = "NT AUTHORITY\\SYSTEM"
            logon_id = "0x3e7"

        integrity = proc.integrity_level if proc.integrity_level else "Medium"

        event_data = {
            "EventID": 1,
            "TimeCreated": render_time,
            "Computer": host.fqdn,
            "Channel": "Microsoft-Windows-Sysmon/Operational",
            "Level": 4,
            "ExecutionProcessID": self._get_sysmon_pid(host.hostname),
            "ExecutionThreadID": self._get_sysmon_thread_id(host.hostname),
            "UtcTime": utc_time,
            "ProcessGuid": process_guid,
            "ProcessId": proc.pid,
            "Image": proc.image,
            "CommandLine": proc.command_line,
            "User": user,
            "LogonGuid": self._resolve_logon_guid(host.hostname, logon_id, auth),
            "LogonId": logon_id,
            "TerminalSessionId": self._terminal_session_id(auth, logon_id),
            "IntegrityLevel": integrity,
            "Hashes": self._generate_hashes(proc.image, host),
            "ParentProcessGuid": parent_guid,
            "ParentProcessId": proc.parent_pid,
            "ParentImage": proc.parent_image or "-",
            "ParentCommandLine": proc.parent_command_line
            if hasattr(proc, "parent_command_line") and proc.parent_command_line
            else "-",
            "CurrentDirectory": proc.current_directory or self._default_current_directory(proc),
        }
        # Populate PE metadata from known binary lookup
        fv, desc, prod, company, orig = self._get_pe_metadata(proc.image, host)
        event_data["FileVersion"] = fv
        event_data["Description"] = desc
        event_data["Product"] = prod
        event_data["Company"] = company
        event_data["OriginalFileName"] = orig
        self.emit_event(event_data)

    @staticmethod
    def _default_current_directory(proc: ProcessContext) -> str:
        """Fallback for older ProcessContext callers that do not set a working directory."""
        image = proc.image.replace("/", "\\")
        image_lower = image.lower()
        username = proc.username.split("\\")[-1]
        if username in {"SYSTEM", "LOCAL SERVICE", "NETWORK SERVICE"} or username.endswith("$"):
            return "C:\\Windows\\System32\\"
        if "\\windows\\system32\\" in image_lower or "\\windows\\syswow64\\" in image_lower:
            return "C:\\Windows\\System32\\"
        if "\\" in image:
            return image.rsplit("\\", 1)[0] + "\\"
        return f"C:\\Users\\{username}\\"

    @staticmethod
    def _source_offset(
        event_type: str,
        hostname: str,
        pid: int,
        timestamp: datetime,
        *,
        minimum_ms: int,
        maximum_ms: int,
    ) -> timedelta:
        """Deterministic Sysmon collection latency for cross-source events."""
        span = maximum_ms - minimum_ms
        offset = minimum_ms + (
            _stable_seed(f"sysmon:{event_type}:{hostname}:{pid}:{timestamp}") % span
        )
        return timedelta(milliseconds=offset)

    def _render_sysmon_process_terminate(self, event: SecurityEvent) -> None:
        """Render Sysmon Event 5 (ProcessTerminate)."""
        random.Random()
        proc = event.process
        auth = event.auth
        host = event.src_host
        render_time = event.timestamp + self._source_offset(
            "process_terminate",
            host.hostname,
            proc.pid,
            event.timestamp,
            minimum_ms=12,
            maximum_ms=180,
        )

        utc_time = _format_sysmon_utc_time(render_time)
        process_guid = self._get_stable_process_guid(
            host.hostname, proc.pid, proc.start_time or event.timestamp
        )

        if auth and auth.username:
            user = self._format_user(auth.username, host.netbios_domain)
        else:
            user = "NT AUTHORITY\\SYSTEM"

        event_data = {
            "EventID": 5,
            "TimeCreated": render_time,
            "Computer": host.fqdn,
            "Channel": "Microsoft-Windows-Sysmon/Operational",
            "Level": 4,
            "ExecutionProcessID": self._get_sysmon_pid(host.hostname),
            "ExecutionThreadID": self._get_sysmon_thread_id(host.hostname),
            "UtcTime": utc_time,
            "ProcessGuid": process_guid,
            "ProcessId": proc.pid,
            "Image": proc.image,
            "User": user,
        }
        self.emit_event(event_data)

    @staticmethod
    def _resolve_full_image_path(image: str, username: str = "") -> str:
        """Ensure a Windows image path is fully qualified.

        Sysmon always logs full paths. If only a bare filename is provided,
        resolve it via the application catalog (user apps get Program Files,
        system binaries get System32).
        """
        if "\\" not in image and "/" not in image:
            from evidenceforge.generation.activity.application_catalog import (
                resolve_image_path,
            )

            return resolve_image_path(image, "windows", username=username)
        return image

    @staticmethod
    def _terminal_session_id(auth, logon_id: str) -> int:
        """Return a source-native TerminalSessionId for Sysmon process creates."""
        if auth is None:
            return 0
        username = (auth.username or "").upper()
        if username in {"SYSTEM", "LOCAL SERVICE", "NETWORK SERVICE", "ANONYMOUS LOGON"}:
            return 0
        if auth.logon_type in {2, 7, 10, 11}:
            return 1 + (_stable_seed(f"sysmon_terminal_session:{logon_id or username}") % 8)
        return 0

    def _render_sysmon_create_remote_thread(self, event: SecurityEvent) -> None:
        """Render Sysmon Event 8 (CreateRemoteThread)."""
        host = event.src_host
        proc = event.process  # Source process
        auth = event.auth
        remote_thread = event.remote_thread

        utc_time = event.timestamp.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
        source_guid = self._get_stable_process_guid(
            host.hostname, proc.pid, proc.start_time or event.timestamp
        )

        target_pid = (
            remote_thread.target_pid
            if remote_thread is not None
            else int(auth.source_port)
            if auth and auth.source_port
            else 0
        )
        target_username = auth.username if auth else ""
        target_image = self._resolve_full_image_path(
            remote_thread.target_image
            if remote_thread is not None
            else auth.target_server
            if auth and auth.target_server
            else r"C:\Windows\explorer.exe",
            username=target_username,
        )
        target_guid = self._get_stable_process_guid(host.hostname, target_pid, event.timestamp)

        event_data = {
            "EventID": 8,
            "TimeCreated": event.timestamp,
            "Computer": host.fqdn,
            "Channel": "Microsoft-Windows-Sysmon/Operational",
            "Level": 4,
            "ExecutionProcessID": self._get_sysmon_pid(host.hostname),
            "ExecutionThreadID": self._get_sysmon_thread_id(host.hostname),
            "UtcTime": utc_time,
            "SourceProcessGuid": source_guid,
            "SourceProcessId": proc.pid,
            "SourceImage": proc.image,
            "TargetProcessGuid": target_guid,
            "TargetProcessId": target_pid,
            "TargetImage": target_image,
            "NewThreadId": remote_thread.new_thread_id if remote_thread else 0,
            "StartAddress": f"0x{remote_thread.start_address:08X}" if remote_thread else "0x0",
            "StartModule": remote_thread.start_module if remote_thread else "",
            "StartFunction": remote_thread.start_function if remote_thread else "",
        }
        self.emit_event(event_data)

    def _render_sysmon_process_access(self, event: SecurityEvent) -> None:
        """Render Sysmon Event 10 (ProcessAccess).

        Primary detection for credential dumping (e.g., mimikatz accessing lsass.exe).
        Source process reads target process memory with specific access rights.
        """
        rng = random.Random()
        host = event.src_host
        proc = event.process  # Source process
        access = event.process_access

        utc_time = event.timestamp.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
        source_guid = self._get_stable_process_guid(
            host.hostname, proc.pid, proc.start_time or event.timestamp
        )

        target_pid = access.target_pid if access else rng.randint(500, 800)
        target_image = self._resolve_full_image_path(
            access.target_image if access else r"C:\Windows\System32\lsass.exe",
            username=proc.username,
        )
        target_guid = self._get_stable_process_guid(host.hostname, target_pid, event.timestamp)

        # Determine user string
        if event.auth and event.auth.username:
            user = self._format_user(event.auth.username, host.netbios_domain)
        elif proc.username:
            user = self._format_user(proc.username, host.netbios_domain)
        else:
            user = "NT AUTHORITY\\SYSTEM"

        # GrantedAccess values for credential dumping:
        # 0x1010 = PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ
        # 0x1FFFFF = PROCESS_ALL_ACCESS
        # 0x1438 = typical mimikatz access mask
        granted_access = access.granted_access if access else "0x1010"
        target_user = (
            self._format_user(access.target_user, host.netbios_domain)
            if access and access.target_user
            else "NT AUTHORITY\\SYSTEM"
        )

        event_data = {
            "EventID": 10,
            "TimeCreated": event.timestamp,
            "Computer": host.fqdn,
            "Channel": "Microsoft-Windows-Sysmon/Operational",
            "Level": 4,
            "ExecutionProcessID": self._get_sysmon_pid(host.hostname),
            "ExecutionThreadID": self._get_sysmon_thread_id(host.hostname),
            "UtcTime": utc_time,
            "SourceProcessGUID": source_guid,
            "SourceProcessId": proc.pid,
            "SourceImage": proc.image,
            "SourceThreadId": access.source_thread_id if access else -1,
            "SourceUser": user,
            "TargetProcessGUID": target_guid,
            "TargetProcessId": target_pid,
            "TargetImage": target_image,
            "TargetUser": target_user,
            "GrantedAccess": granted_access,
            "CallTrace": access.call_trace
            if access and access.call_trace
            else self._get_call_trace(host.hostname),
        }
        self.emit_event(event_data)

    # --- Sysmon filter methods (data-driven from sysmon_filters.yaml) ---

    def _get_filters(self) -> dict:
        """Return the loaded Sysmon filter config (cached)."""
        if not hasattr(self, "_filters"):
            self._filters = load_sysmon_filters()
        return self._filters

    def _passes_event3_filter(self, event: SecurityEvent) -> bool:
        """Check if a connection event passes the Event 3 (NetworkConnect) filter."""
        cfg = self._get_filters().get("network_connect", {})
        if not cfg.get("enabled", True):
            return False
        if not event.network:
            return False

        mode = cfg.get("mode", "include")
        if mode != "include":
            return True  # No filtering

        # Check excluded destination IPs
        dst_ip = event.network.dst_ip or ""
        exclude_ips = cfg.get("exclude_dest_ips", [])
        if dst_ip in exclude_ips:
            return False

        # Check include rules — pass if image matches OR dest port matches.
        # Resolve image from ProcessContext first, then fall back to PID lookup
        # via StateManager (connection events often lack ProcessContext but carry
        # initiating_pid on NetworkContext).
        image = ""
        if event.process:
            image = event.process.image.rsplit("\\", 1)[-1].rsplit("/", 1)[-1].lower()
        elif event.network and event.network.initiating_pid > 0 and event.src_host:
            _pid, resolved_image = self._resolve_process_from_pid(
                event.src_host.hostname, event.network.initiating_pid
            )
            image = resolved_image.rsplit("\\", 1)[-1].rsplit("/", 1)[-1].lower()
        include_images = [img.lower() for img in cfg.get("include_images", [])]
        if image in include_images:
            return True

        # Baseline system images: sampled at a lower rate for volume balance
        # Use stable seed for deterministic sampling (same connection → same decision)
        hostname = event.src_host.hostname if event.src_host else ""
        _net = event.network
        _uid = _net.zeek_uid or _net.conn_id or event.timestamp.isoformat()
        _seed_key = f"sysmon3_{hostname}_{image}_{_net.dst_ip}_{_net.dst_port}_{_uid}"
        _sample_float = (_stable_seed(_seed_key) & 0xFFFFFFFF) / 0xFFFFFFFF

        baseline_images = [img.lower() for img in cfg.get("include_baseline_images", [])]
        if image in baseline_images:
            sample_rate = cfg.get("baseline_sample_rate", 0.10)
            if _sample_float < sample_rate:
                return True

        # User application images: low sampling rate for non-zero presence
        user_app_images = [img.lower() for img in cfg.get("include_user_app_images", [])]
        if image in user_app_images:
            rate = cfg.get("user_app_sample_rate", 0.05)
            if _sample_float < rate:
                return True

        dst_port = event.network.dst_port or 0
        include_ports = cfg.get("include_dest_ports", [])
        if dst_port in include_ports:
            # Enforce port-process constraints if defined (e.g., port 22 only from ssh.exe)
            constraints = cfg.get("port_process_constraints", {})
            allowed = constraints.get(dst_port)
            if allowed is not None:
                if not image or image not in [p.lower() for p in allowed]:
                    return False
            return True

        return False

    def _passes_event7_filter(self, event: SecurityEvent) -> bool:
        """Check if an image_load event passes the Event 7 (ImageLoaded) filter."""
        cfg = self._get_filters().get("image_loaded", {})
        if not cfg.get("enabled", True):
            return False
        if not event.image_load:
            return False

        mode = cfg.get("mode", "exclude")
        if mode != "exclude":
            return True

        dll_path = event.image_load.image_loaded
        exclude_prefixes = cfg.get("exclude_image_loaded_prefixes", [])
        for prefix in exclude_prefixes:
            if dll_path.lower().startswith(prefix.lower()):
                # Also check signature exclusion for Microsoft-signed DLLs
                exclude_sigs = cfg.get("exclude_signatures", [])
                sig = event.image_load.signature
                if sig and any(s.lower() in sig.lower() for s in exclude_sigs):
                    return False
        return True

    def _passes_event11_filter(self, event: SecurityEvent) -> bool:
        """Check if a file event passes the Event 11 (FileCreate) filter."""
        cfg = self._get_filters().get("file_create", {})
        if not cfg.get("enabled", True):
            return False
        if not event.file:
            return False

        mode = cfg.get("mode", "include")
        if mode != "include":
            return True

        path = event.file.path
        path_lower = path.lower()

        # Check path patterns
        for pattern in cfg.get("include_target_paths", []):
            if pattern.lower() in path_lower:
                return True

        # Check extensions
        for ext in cfg.get("include_extensions", []):
            if path_lower.endswith(ext.lower()):
                return True

        return False

    def _passes_event12_13_filter(self, event: SecurityEvent) -> bool:
        """Check if a registry event passes the Events 12/13 filter."""
        cfg = self._get_filters().get("registry_event", {})
        if not cfg.get("enabled", True):
            return False
        if not event.registry:
            return False

        # Determine if this is Event 12 (create/delete) or 13 (modify/set)
        action = event.registry.action
        if action == "create" and not cfg.get("log_create_key", False):
            return False

        mode = cfg.get("mode", "include")
        if mode != "include":
            return True

        key = event.registry.key
        key_lower = key.lower()
        for pattern in cfg.get("include_key_patterns", []):
            if pattern.lower() in key_lower:
                return True

        return False

    def _passes_event22_filter(self, event: SecurityEvent) -> bool:
        """Check if a DNS event passes the Event 22 (DNSQuery) filter."""
        cfg = self._get_filters().get("dns_query", {})
        if not cfg.get("enabled", True):
            return False
        if not event.dns:
            return False

        exclude_suffixes = cfg.get("exclude_query_suffixes", [])
        query = event.dns.query.lower()
        for suffix in exclude_suffixes:
            if query.endswith(suffix.lower()):
                return False

        return True

    # --- New render methods for Events 3, 7, 11, 12/13, 22 ---

    def _render_sysmon_network_connect(self, event: SecurityEvent) -> None:
        """Render Sysmon Event 3 (NetworkConnect)."""
        random.Random()
        host = event.src_host
        net = event.network
        proc = event.process

        render_time = event.timestamp + sample_timing_delta(
            "source.sysmon_network_connection",
            seed_parts=(
                host.hostname,
                net.initiating_pid if net else -1,
                net.src_ip if net else "",
                net.src_port if net else 0,
                net.dst_ip if net else "",
                net.dst_port if net else 0,
                event.timestamp,
            ),
        )
        utc_time = render_time.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]

        # Process info — use ProcessContext if available, else resolve from
        # initiating_pid via StateManager lookup. Real Sysmon always knows the
        # originating process; skip Event 3 if we can't resolve one.
        if proc:
            pid = proc.pid
            image = proc.image
        else:
            initiating_pid = net.initiating_pid if net else -1
            pid, image = self._resolve_process_from_pid(host.hostname, initiating_pid)
        if pid <= 0 or image == "-":
            return  # Cannot attribute to a process — don't emit phantom Event 3
        process_guid = self._get_stable_process_guid(
            host.hostname, pid, proc.start_time if proc and proc.start_time else event.timestamp
        )

        # User — resolve from AuthContext, ProcessContext, or StateManager
        user = ""
        if event.auth and event.auth.username:
            user = self._format_user(event.auth.username, host.netbios_domain)
        elif proc and proc.username:
            user = self._format_user(proc.username, host.netbios_domain)
        elif pid > 0:
            sm = getattr(self, "_state_manager", None)
            if sm:
                rp = sm.get_process(host.hostname, pid)
                if rp and rp.username:
                    user = self._format_user(rp.username, host.netbios_domain)
        if not user:
            user = "NT AUTHORITY\\SYSTEM"

        src_ip = net.src_ip or host.ip
        dst_ip = net.dst_ip or ""
        src_port = net.src_port or 0
        dst_port = net.dst_port or 0
        proto = (net.protocol or "tcp").lower()

        event_data = {
            "EventID": 3,
            "TimeCreated": render_time,
            "Computer": host.fqdn,
            "Channel": "Microsoft-Windows-Sysmon/Operational",
            "Level": 4,
            "ExecutionProcessID": self._get_sysmon_pid(host.hostname),
            "ExecutionThreadID": self._get_sysmon_thread_id(host.hostname),
            "UtcTime": utc_time,
            "ProcessGuid": process_guid,
            "ProcessId": pid,
            "Image": image,
            "User": user,
            "Protocol": proto,
            "Initiated": "true",
            "SourceIsIpv6": "true" if ":" in src_ip else "false",
            "SourceIp": src_ip,
            "SourceHostname": host.fqdn,
            "SourcePort": src_port,
            "SourcePortName": _PORT_NAMES.get(src_port, "-"),
            "DestinationIsIpv6": "true" if ":" in dst_ip else "false",
            "DestinationIp": dst_ip,
            "DestinationHostname": self._resolve_destination_hostname(dst_ip),
            "DestinationPort": dst_port,
            "DestinationPortName": _PORT_NAMES.get(dst_port, "-"),
        }
        self.emit_event(event_data)

    def _render_sysmon_image_loaded(self, event: SecurityEvent) -> None:
        """Render Sysmon Event 7 (ImageLoaded)."""
        rng = random.Random()
        host = event.src_host
        proc = event.process
        il = event.image_load

        utc_time = event.timestamp.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
        pid = proc.pid if proc else rng.randint(1000, 5000)
        image = proc.image if proc else r"C:\Windows\System32\svchost.exe"
        process_guid = self._get_stable_process_guid(
            host.hostname, pid, proc.start_time if proc and proc.start_time else event.timestamp
        )

        # PE metadata for the loaded DLL
        fv, desc, prod, company, orig = self._get_pe_metadata(il.image_loaded, host)
        if il.signed and (fv, desc, prod, company, orig) == ("-", "-", "-", "-", "-"):
            fv, desc, prod, company, orig = self._signed_module_metadata(
                il.image_loaded,
                il.signature,
            )
        signature_status = il.signature_status if il.signed else "Unavailable"
        hashes = self._generate_hashes(
            il.image_loaded,
            host,
            rendered_identity=(
                fv,
                desc,
                prod,
                company,
                orig,
            ),
        )

        event_data = {
            "EventID": 7,
            "TimeCreated": event.timestamp,
            "Computer": host.fqdn,
            "Channel": "Microsoft-Windows-Sysmon/Operational",
            "Level": 4,
            "ExecutionProcessID": self._get_sysmon_pid(host.hostname),
            "ExecutionThreadID": self._get_sysmon_thread_id(host.hostname),
            "UtcTime": utc_time,
            "ProcessGuid": process_guid,
            "ProcessId": pid,
            "Image": image,
            "ImageLoaded": il.image_loaded,
            "FileVersion": fv,
            "Description": desc,
            "Product": prod,
            "Company": company,
            "OriginalFileName": orig,
            "Hashes": hashes,
            "Signed": "true" if il.signed else "false",
            "Signature": il.signature if il.signed else "-",
            "SignatureStatus": signature_status,
        }
        self.emit_event(event_data)

    def _render_sysmon_file_create(self, event: SecurityEvent) -> None:
        """Render Sysmon Event 11 (FileCreate)."""
        random.Random()
        host = event.src_host
        proc = event.process
        fc = event.file

        utc_time = event.timestamp.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
        if proc:
            pid = proc.pid
            image = proc.image
        else:
            file_pid = fc.pid if fc else 0
            pid, image = self._resolve_process_from_pid(host.hostname, file_pid)
        process_guid = self._get_stable_process_guid(
            host.hostname, pid, proc.start_time if proc and proc.start_time else event.timestamp
        )

        event_data = {
            "EventID": 11,
            "TimeCreated": event.timestamp,
            "Computer": host.fqdn,
            "Channel": "Microsoft-Windows-Sysmon/Operational",
            "Level": 4,
            "ExecutionProcessID": self._get_sysmon_pid(host.hostname),
            "ExecutionThreadID": self._get_sysmon_thread_id(host.hostname),
            "UtcTime": utc_time,
            "ProcessGuid": process_guid,
            "ProcessId": pid,
            "Image": image,
            "TargetFilename": fc.path,
            "CreationUtcTime": utc_time,
        }
        self.emit_event(event_data)

    def _render_sysmon_registry_event(self, event: SecurityEvent) -> None:
        """Render Sysmon Event 12 (CreateKey/DeleteKey) or 13 (SetValue)."""
        reg = event.registry
        if not self._passes_event12_13_filter(event):
            return

        random.Random()
        host = event.src_host
        proc = event.process

        utc_time = event.timestamp.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
        if proc:
            pid = proc.pid
            image = proc.image
        else:
            reg_pid = reg.pid if reg else 0
            pid, image = self._resolve_process_from_pid(host.hostname, reg_pid)
        process_guid = self._get_stable_process_guid(
            host.hostname, pid, proc.start_time if proc and proc.start_time else event.timestamp
        )
        if event.auth and event.auth.username:
            user = self._format_user(event.auth.username, host.netbios_domain)
        elif proc and proc.username:
            user = self._format_user(proc.username, host.netbios_domain)
        else:
            user = "NT AUTHORITY\\SYSTEM"

        # Route value operations to Event 13. Sysmon Event 12 is key create/delete;
        # Event 14 would be value rename, and value deletes are not modeled separately.
        action = reg.action
        if reg.value or action == "modify":
            event_id = 13
            event_type = "SetValue"
        elif action == "delete":
            event_id = 12
            event_type = "DeleteKey"
        elif action == "create":
            event_id = 12
            event_type = "CreateKey"
        else:
            event_id = 13
            event_type = "SetValue"

        event_data = {
            "EventID": event_id,
            "TimeCreated": event.timestamp,
            "Computer": host.fqdn,
            "Channel": "Microsoft-Windows-Sysmon/Operational",
            "Level": 4,
            "ExecutionProcessID": self._get_sysmon_pid(host.hostname),
            "ExecutionThreadID": self._get_sysmon_thread_id(host.hostname),
            "UtcTime": utc_time,
            "ProcessGuid": process_guid,
            "ProcessId": pid,
            "Image": image,
            "User": user,
            "EventType": event_type,
            "TargetObject": self._native_registry_target_object(reg.key, event),
        }

        # Event 13 includes the Details field
        if event_id == 13:
            event_data["Details"] = reg.value or "-"

        self.emit_event(event_data)

    def _render_sysmon_dns_query(self, event: SecurityEvent) -> None:
        """Render Sysmon Event 22 (DNSQuery)."""
        random.Random()
        host = event.src_host
        dns = event.dns

        render_time = event.timestamp + sample_timing_delta(
            "source.sysmon_dns_query",
            seed_parts=(
                host.hostname,
                dns.query if dns else "",
                dns.query_type if dns else "",
                event.timestamp,
            ),
        )
        utc_time = render_time.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]

        # DESIGN DECISION: svchost.exe is correct here. Windows DNS Client
        # service (dnscache, hosted by svchost.exe -k LocalService) proxies
        # all DnsQuery_A() / getaddrinfo() calls from applications. Real
        # Sysmon Event 22 shows svchost.exe, not the originating process.
        # Only tools that bypass the DNS Client (nslookup.exe, certain
        # malware doing raw UDP to port 53) would show a different process.
        # Use the seeded svchost PID for the DNS Client service group
        # (svchost_local_svc = svchost.exe -k LocalService) so the PID
        # exists in StateManager's process tree and correlates with Event 1.
        sys_pids = getattr(self, "_system_pids", {}).get(host.hostname, {})
        dns_client_pid = sys_pids.get(
            "svchost_local_svc",
            sys_pids.get("svchost_netsvcs", self._get_dns_client_pid(host.hostname)),
        )
        process_guid = self._get_stable_process_guid(host.hostname, dns_client_pid, event.timestamp)

        # Map DNS rcode to Windows QueryStatus
        query_status = _DNS_STATUS_MAP.get(dns.rcode, "0")

        # QueryResults: semicolon-separated IP addresses with trailing semicolon
        if dns.answers:
            query_results = ";".join(dns.answers) + ";"
        else:
            query_results = "-"

        event_data = {
            "EventID": 22,
            "TimeCreated": render_time,
            "Computer": host.fqdn,
            "Channel": "Microsoft-Windows-Sysmon/Operational",
            "Level": 4,
            "ExecutionProcessID": self._get_sysmon_pid(host.hostname),
            "ExecutionThreadID": self._get_sysmon_thread_id(host.hostname),
            "UtcTime": utc_time,
            "ProcessGuid": process_guid,
            "ProcessId": dns_client_pid,
            "QueryName": dns.query,
            "QueryStatus": query_status,
            "QueryResults": query_results,
            "Image": r"C:\Windows\System32\svchost.exe",
            "User": "NT AUTHORITY\\LOCAL SERVICE",
        }
        self.emit_event(event_data)

    def _get_dns_client_pid(self, hostname: str) -> int:
        """Return stable DNS Client svchost.exe PID for a given host."""
        cache = getattr(self, "_dns_client_pids", None)
        if cache is None:
            cache = self._dns_client_pids = {}
        if hostname not in cache:
            h = int(
                hashlib.md5(f"dns_client:{hostname}".encode(), usedforsecurity=False).hexdigest(),
                16,
            )
            cache[hostname] = 900 + (h % 400)  # range 900-1299
        return cache[hostname]

    # --- Infrastructure (same pattern as WindowsEventEmitter) ---

    def __init__(
        self,
        format_def: FormatDefinition,
        output_path: Path,
        buffer_size: int = 10000,
        threaded: bool = False,
    ):
        self._direct_file_mode = output_path.suffix != ""
        self._base_dir = output_path.parent if self._direct_file_mode else output_path
        self._direct_file_path = output_path if self._direct_file_mode else None
        self._host_writers: dict[str, _SingleHostWriter] = {}
        self._snare_writers: dict[str, _SingleHostWriter] = {}
        self._host_writers_lock = Lock()

        super().__init__(format_def, output_path, buffer_size, threaded)
        self._event_dicts: list[dict[str, Any]] = []
        self._record_id_counters: dict[str, int] = {}
        self._erid_rngs: dict[str, random.Random] = {}
        self._last_time_created_by_computer: dict[str, datetime] = {}
        self._time_collision_count_by_computer: dict[str, int] = {}

    def _get_host_writer(self, host_fqdn: str) -> _SingleHostWriter:
        safe_host = sanitize_path_component(host_fqdn)
        writer = self._host_writers.get(safe_host)
        if writer is not None:
            return writer
        with self._host_writers_lock:
            writer = self._host_writers.get(safe_host)
            if writer is not None:
                return writer
            if safe_host and not self._direct_file_mode:
                path = self._base_dir / safe_host / "windows_event_sysmon.xml"
            elif self._direct_file_path:
                path = self._direct_file_path
            else:
                path = self._base_dir / "windows_event_sysmon.xml"
            writer = _SingleHostWriter(path, self.buffer_size)
            header = self.format_def.output.header_template
            if header:
                writer.write_header(header)
            self._host_writers[safe_host] = writer
            return writer

    def _get_snare_writer(self, host_fqdn: str, timestamp: datetime) -> _SingleHostWriter:
        route_key = make_syslog_family_route_key(
            host_fqdn or "default",
            timestamp,
            direct_file_mode=self._direct_file_mode,
        )
        safe_route_key = sanitize_syslog_family_route_key(route_key)
        writer = self._snare_writers.get(safe_route_key)
        if writer is not None:
            return writer
        with self._host_writers_lock:
            writer = self._snare_writers.get(safe_route_key)
            if writer is not None:
                return writer
            if self._direct_file_path is not None:
                path = self._direct_file_path.with_name(WINDOWS_SYSMON_SNARE_FILENAME)
            else:
                path = syslog_family_writer_path(
                    base_dir=self._base_dir,
                    safe_route_key=safe_route_key,
                    log_filename=WINDOWS_SYSMON_SNARE_FILENAME,
                    direct_file_path=None,
                    flat_filename=WINDOWS_SYSMON_SNARE_FILENAME,
                )
            writer = _SingleHostWriter(path, self.buffer_size)
            self._snare_writers[safe_route_key] = writer
            return writer

    def _buffer_event(self, rendered: str) -> None:
        self._get_host_writer("").write(rendered)

    def emit_event(self, event_data: dict[str, Any]) -> None:
        event_data = dict(event_data)
        for field in ("ExecutionProcessID", "ExecutionThreadID"):
            value = event_data.get(field)
            event_data[field] = normalize_windows_id_value(value)
        if self.threaded:
            self._emit_threaded(event_data)
        else:
            with self._file_lock:
                self._event_dicts.append(event_data)
                if len(self._event_dicts) >= self.buffer_size:
                    self._flush_unlocked()

    def _render_event(self, event_data: dict[str, Any]) -> str:
        from xml.sax.saxutils import escape as xml_escape

        if "TimeCreated" in event_data:
            ts = event_data["TimeCreated"]
            if isinstance(ts, datetime):
                if "UtcTime" in event_data:
                    event_data["UtcTime"] = _format_sysmon_utc_time(ts)
                event_data["TimeCreated"] = format_windows_system_time(ts, event_data)
        for key, val in event_data.items():
            if isinstance(val, str) and key != "TimeCreated":
                event_data[key] = xml_escape(val)
        return self._template.render(**event_data)

    def _run(self) -> None:
        while not self._stop_event.is_set():
            try:
                event_data = self._event_queue.get(timeout=0.1)
                with self._file_lock:
                    self._event_dicts.append(event_data)
                    if not self.threaded and len(self._event_dicts) >= self.buffer_size:
                        self._flush_unlocked()
                self._event_queue.task_done()
            except Empty:
                if self._flush_barrier.is_set():
                    self.flush()
                    self._flush_barrier.clear()
        self.flush()

    def _flush_unlocked(self) -> None:
        if not self._event_dicts:
            return

        self._shift_process_creates_after_visible_parent()
        self._shift_followons_after_process_create()
        self._shift_terminations_after_followons()

        def _sort_key(event: dict) -> Any:
            ts = event.get("TimeCreated", "")
            if isinstance(ts, datetime):
                return ensure_utc(ts)
            return ts

        self._event_dicts.sort(key=_sort_key)

        for sequence, event in enumerate(self._event_dicts):
            _normalize_windows_time_created(
                event,
                self._last_time_created_by_computer,
                self._time_collision_count_by_computer,
                sequence,
                "sysmon_time_created",
                jitter_existing_microseconds=True,
            )
            computer = event.get("Computer", "")
            counter_key = computer.split(".")[0] if "." in computer else computer
            if counter_key not in self._record_id_counters:
                self._erid_rngs[counter_key] = random.Random(f"sysmon_erid_{counter_key}")
                self._record_id_counters[counter_key] = self._erid_rngs[counter_key].randint(
                    100_000, 500_000
                )
            rng = self._erid_rngs[counter_key]
            # Simulate gaps from event types we don't generate (6, 9, 14-21, 23-29, etc.)
            # Real Sysmon shares ETW session with other providers; gaps vary widely.
            if rng.random() < 0.15:
                gap = rng.randint(8, 50)  # Occasional large gap (batch ETW events)
            else:
                gap = rng.randint(1, 7)
            self._record_id_counters[counter_key] += gap
            event["EventRecordID"] = self._record_id_counters[counter_key]

        for event in self._event_dicts:
            host_fqdn = event.get("Computer", "")
            snare_timestamp = event.get("TimeCreated")
            if isinstance(snare_timestamp, datetime):
                snare_rendered = render_windows_sysmon_snare_syslog(event)
                self._get_snare_writer(host_fqdn, snare_timestamp).write(snare_rendered)
            rendered = self._render_event(event)
            self._get_host_writer(host_fqdn).write(rendered)

        self._event_dicts.clear()

    def _shift_process_creates_after_visible_parent(self) -> None:
        """Prevent visible Sysmon Event 1 children from preceding their parent Event 1."""
        process_create_events: dict[tuple[str, str], dict[str, Any]] = {}
        parent_keys: dict[tuple[str, str], tuple[str, str]] = {}

        for event in self._event_dicts:
            if event.get("EventID") != 1:
                continue
            ts = event.get("TimeCreated")
            guid = event.get("ProcessGuid")
            if not isinstance(ts, datetime) or not guid:
                continue
            computer = str(event.get("Computer", ""))
            key = (computer, str(guid))
            process_create_events[key] = event
            parent_guid = event.get("ParentProcessGuid")
            if parent_guid:
                parent_keys[key] = (computer, str(parent_guid))

        if not process_create_events:
            return

        cyclic_keys: set[tuple[str, str]] = set()
        for key in process_create_events:
            path: list[tuple[str, str]] = []
            seen: set[tuple[str, str]] = set()
            current: tuple[str, str] | None = key
            while current is not None:
                if current in seen:
                    cyclic_keys.update(path[path.index(current) :])
                    break
                if current in cyclic_keys:
                    break
                seen.add(current)
                path.append(current)
                parent_key = parent_keys.get(current)
                current = parent_key if parent_key in process_create_events else None

        max_passes = len(process_create_events)
        for _ in range(max_passes):
            changed = False
            process_create_times: dict[tuple[str, str], datetime] = {}
            for key, event in process_create_events.items():
                ts = event.get("TimeCreated")
                if isinstance(ts, datetime):
                    process_create_times[key] = ts

            for key, event in process_create_events.items():
                if key in cyclic_keys:
                    continue
                ts = event.get("TimeCreated")
                parent_key = parent_keys.get(key)
                if not isinstance(ts, datetime) or parent_key is None or parent_key in cyclic_keys:
                    continue
                parent_time = process_create_times.get(parent_key)
                if parent_time is not None and ts <= parent_time:
                    event["TimeCreated"] = parent_time + timedelta(milliseconds=1)
                    changed = True
            if not changed:
                break

    def _shift_followons_after_process_create(self) -> None:
        """Prevent same-ProcessGuid Sysmon follow-ons from preceding Event 1."""
        process_create_times: dict[tuple[str, str], datetime] = {}
        for event in self._event_dicts:
            if event.get("EventID") != 1:
                continue
            ts = event.get("TimeCreated")
            guid = event.get("ProcessGuid")
            computer = str(event.get("Computer", ""))
            if isinstance(ts, datetime) and guid:
                process_create_times[(computer, str(guid))] = ts

        for event in self._event_dicts:
            event_id = event.get("EventID")
            if event_id == 1:
                continue
            ts = event.get("TimeCreated")
            computer = str(event.get("Computer", ""))
            guid = event.get("ProcessGuid") or event.get("SourceProcessGuid")
            if not isinstance(ts, datetime) or not guid:
                continue
            create_time = process_create_times.get((computer, str(guid)))
            if create_time is not None and ts <= create_time:
                event["TimeCreated"] = create_time + timedelta(milliseconds=1)

    def _shift_terminations_after_followons(self) -> None:
        """Prevent Event 5 from preceding visible same-process follow-on telemetry."""
        latest_followon: dict[tuple[str, str], datetime] = {}
        terminations: list[tuple[tuple[str, str], dict[str, Any]]] = []
        for event in self._event_dicts:
            ts = event.get("TimeCreated")
            guid = event.get("ProcessGuid")
            if not isinstance(ts, datetime) or not guid:
                continue
            key = (str(event.get("Computer", "")), str(guid))
            if event.get("EventID") == 5:
                terminations.append((key, event))
                continue
            if event.get("EventID") == 1:
                parent_guid = event.get("ParentProcessGuid")
                if parent_guid:
                    parent_key = (str(event.get("Computer", "")), str(parent_guid))
                    latest_followon[parent_key] = max(ts, latest_followon.get(parent_key, ts))
                continue
            latest_followon[key] = max(ts, latest_followon.get(key, ts))

        for key, event in terminations:
            ts = event.get("TimeCreated")
            latest = latest_followon.get(key)
            if isinstance(ts, datetime) and latest is not None and ts <= latest:
                event["TimeCreated"] = latest + timedelta(milliseconds=1)

    def flush(self, force: bool = False) -> None:
        if not self.threaded:
            force = True
        if not force:
            return
        with self._file_lock:
            self._flush_unlocked()
        with self._host_writers_lock:
            for writer in self._host_writers.values():
                writer.flush()
            for writer in self._snare_writers.values():
                writer.flush()

    def close(self) -> None:
        if self.threaded:
            self.barrier_flush()
            self.stop_thread()
        else:
            self.flush(force=True)
        self.flush(force=True)
        footer = self.format_def.output.footer_template or ""
        for writer in self._host_writers.values():
            writer.flush()
            if footer and writer.event_count > 0:
                writer.write_footer(footer)
        for writer in self._snare_writers.values():
            writer.flush()

    @property
    def event_count(self) -> int:
        return sum(w.event_count for w in self._host_writers.values())

    @event_count.setter
    def event_count(self, value: int) -> None:
        pass
