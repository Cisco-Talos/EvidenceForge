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
from datetime import datetime
from pathlib import Path
from queue import Empty
from threading import Lock
from typing import Any

from evidenceforge.events.base import SecurityEvent
from evidenceforge.formats.format_def import FormatDefinition
from evidenceforge.generation.emitters.base import LogEmitter
from evidenceforge.generation.emitters.host_base import _SingleHostWriter


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
    }

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
    }

    @classmethod
    def _get_pe_metadata(cls, image_path: str) -> tuple[str, str, str, str, str]:
        """Look up PE metadata for a Windows binary by image path or name."""
        # Handle Windows paths on any OS (backslash is not a separator on Unix)
        basename = image_path.rsplit("\\", 1)[-1].rsplit("/", 1)[-1].lower()
        return cls._PE_METADATA.get(basename, ("-", "-", "-", "-", "-"))

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
            cache[hostname] = 1800 + (h % 1200)  # range 1800-2999
        return cache[hostname]

    def can_handle(self, event: SecurityEvent) -> bool:
        """Sysmon emitter handles process events on Windows hosts."""
        return (
            event.event_type in self._supported_types
            and event.src_host is not None
            and event.src_host.os_category == "windows"
        )

    def emit(self, event: SecurityEvent) -> None:
        """Dispatch to per-type render method."""
        if event.event_type in ("process_create", "system_process_create"):
            self._render_sysmon_process_create(event)
        elif event.event_type == "process_terminate":
            self._render_sysmon_process_terminate(event)
        elif event.event_type == "create_remote_thread":
            self._render_sysmon_create_remote_thread(event)
        elif event.event_type == "process_access":
            self._render_sysmon_process_access(event)
        else:
            raise NotImplementedError(
                f"SysmonEventEmitter: no render method for {event.event_type}"
            )

    @staticmethod
    def _generate_process_guid(hostname: str, pid: int, timestamp: datetime) -> str:
        """Generate a deterministic Sysmon ProcessGuid from host+pid+time.

        The first DWORD is a stable machine-specific value (same for all
        processes on a given host), matching real Sysmon behavior. The
        remaining segments are per-process unique.

        The timestamp should be the process creation time, not the event time.
        This ensures the same PID produces the same GUID across all Sysmon
        events (Event 1, 8, 10) referencing that process.
        """
        # Machine-specific first DWORD (stable across all processes on this host)
        machine_prefix = hashlib.md5(
            f"sysmon_machine_{hostname}".encode(), usedforsecurity=False
        ).hexdigest()[:8]

        # Per-process uniqueness from remaining hash segments
        ts_key = timestamp.strftime("%Y-%m-%dT%H:%M:%S")
        seed = f"{hostname}:{pid}:{ts_key}"
        h = hashlib.md5(seed.encode(), usedforsecurity=False).hexdigest()
        return f"{{{machine_prefix}-{h[8:12]}-{h[12:16]}-{h[16:20]}-{h[20:32]}}}"

    @staticmethod
    def _generate_hashes(image: str, hostname: str) -> str:
        """Generate deterministic fake file hashes from image path.

        Hashes are keyed on image path only (not hostname) so the same
        binary produces identical hashes across all hosts — matching
        real Windows behavior for identical OS builds.
        """
        seed = image
        sha1 = hashlib.sha1(seed.encode(), usedforsecurity=False).hexdigest().upper()
        md5 = hashlib.md5(seed.encode(), usedforsecurity=False).hexdigest().upper()
        sha256 = hashlib.sha256(seed.encode(), usedforsecurity=False).hexdigest().upper()
        imphash = hashlib.md5(f"imp:{seed}".encode(), usedforsecurity=False).hexdigest().upper()
        return f"SHA1={sha1},MD5={md5},SHA256={sha256},IMPHASH={imphash}"

    def _render_sysmon_process_create(self, event: SecurityEvent) -> None:
        """Render Sysmon Event 1 (ProcessCreate)."""
        rng = random.Random()
        proc = event.process
        auth = event.auth
        host = event.src_host

        utc_time = event.timestamp.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
        process_guid = self._generate_process_guid(host.hostname, proc.pid, event.timestamp)
        parent_guid = self._generate_process_guid(
            host.hostname,
            proc.parent_pid,
            datetime(event.timestamp.year, 1, 1),  # Stable parent GUID
        )

        # Determine user string
        if auth:
            user = (
                f"{host.netbios_domain}\\{auth.username}"
                if auth.username
                else "NT AUTHORITY\\SYSTEM"
            )
            logon_id = auth.logon_id if hasattr(auth, "logon_id") and auth.logon_id else "0x3e7"
        else:
            user = "NT AUTHORITY\\SYSTEM"
            logon_id = "0x3e7"

        integrity = proc.integrity_level if proc.integrity_level else "Medium"

        event_data = {
            "EventID": 1,
            "TimeCreated": event.timestamp,
            "Computer": host.fqdn,
            "Channel": "Microsoft-Windows-Sysmon/Operational",
            "Level": 4,
            "ExecutionProcessID": self._get_sysmon_pid(host.hostname),
            "ExecutionThreadID": rng.randint(1000, 5000),
            "UtcTime": utc_time,
            "ProcessGuid": process_guid,
            "ProcessId": proc.pid,
            "Image": proc.image,
            "CommandLine": proc.command_line,
            "User": user,
            "LogonGuid": self._generate_process_guid(
                host.hostname,
                int(logon_id, 16) if logon_id.startswith("0x") else hash(logon_id) & 0xFFFFFFFF,
                event.timestamp,
            ),
            "LogonId": logon_id,
            "IntegrityLevel": integrity,
            "Hashes": self._generate_hashes(proc.image, host.hostname),
            "ParentProcessGuid": parent_guid,
            "ParentProcessId": proc.parent_pid,
            "ParentImage": proc.parent_image or "-",
            "ParentCommandLine": proc.parent_command_line
            if hasattr(proc, "parent_command_line") and proc.parent_command_line
            else "-",
        }
        # Populate PE metadata from known binary lookup
        fv, desc, prod, company, orig = self._get_pe_metadata(proc.image)
        event_data["FileVersion"] = fv
        event_data["Description"] = desc
        event_data["Product"] = prod
        event_data["Company"] = company
        event_data["OriginalFileName"] = orig
        self.emit_event(event_data)

    def _render_sysmon_process_terminate(self, event: SecurityEvent) -> None:
        """Render Sysmon Event 5 (ProcessTerminate)."""
        rng = random.Random()
        proc = event.process
        auth = event.auth
        host = event.src_host

        utc_time = event.timestamp.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
        process_guid = self._generate_process_guid(host.hostname, proc.pid, event.timestamp)

        if auth and auth.username:
            user = f"{host.netbios_domain}\\{auth.username}"
        else:
            user = "NT AUTHORITY\\SYSTEM"

        event_data = {
            "EventID": 5,
            "TimeCreated": event.timestamp,
            "Computer": host.fqdn,
            "Channel": "Microsoft-Windows-Sysmon/Operational",
            "Level": 4,
            "ExecutionProcessID": self._get_sysmon_pid(host.hostname),
            "ExecutionThreadID": rng.randint(1000, 5000),
            "UtcTime": utc_time,
            "ProcessGuid": process_guid,
            "ProcessId": proc.pid,
            "Image": proc.image,
            "User": user,
        }
        self.emit_event(event_data)

    @staticmethod
    def _resolve_full_image_path(image: str) -> str:
        """Ensure a Windows image path is fully qualified.

        Sysmon always logs full paths. If only a bare filename is provided
        (e.g., 'lsass.exe'), prepend the standard System32 directory.
        """
        if "\\" not in image and "/" not in image:
            return rf"C:\Windows\System32\{image}"
        return image

    def _render_sysmon_create_remote_thread(self, event: SecurityEvent) -> None:
        """Render Sysmon Event 8 (CreateRemoteThread)."""
        rng = random.Random()
        host = event.src_host
        proc = event.process  # Source process
        # Target info passed via network context fields or extra context
        # For simplicity, we use process context for source and auth for target hints
        auth = event.auth

        utc_time = event.timestamp.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
        source_guid = self._generate_process_guid(host.hostname, proc.pid, event.timestamp)

        # Target process info from auth context (target_server=target_image, process_name=unused)
        target_pid = int(auth.source_port) if auth and auth.source_port else rng.randint(1000, 8000)
        target_image = self._resolve_full_image_path(
            auth.target_server if auth and auth.target_server else r"C:\Windows\explorer.exe"
        )
        target_guid = self._generate_process_guid(host.hostname, target_pid, event.timestamp)

        event_data = {
            "EventID": 8,
            "TimeCreated": event.timestamp,
            "Computer": host.fqdn,
            "Channel": "Microsoft-Windows-Sysmon/Operational",
            "Level": 4,
            "ExecutionProcessID": self._get_sysmon_pid(host.hostname),
            "ExecutionThreadID": rng.randint(1000, 5000),
            "UtcTime": utc_time,
            "SourceProcessGuid": source_guid,
            "SourceProcessId": proc.pid,
            "SourceImage": proc.image,
            "TargetProcessGuid": target_guid,
            "TargetProcessId": target_pid,
            "TargetImage": target_image,
            "NewThreadId": rng.randint(100, 9999),
            "StartAddress": f"0x{rng.randint(0x01000000, 0x7FFFFFFF):08X}",
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
        auth = event.auth

        utc_time = event.timestamp.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
        source_guid = self._generate_process_guid(host.hostname, proc.pid, event.timestamp)

        # Target process info from auth context (same pattern as create_remote_thread)
        target_pid = int(auth.source_port) if auth and auth.source_port else rng.randint(500, 800)
        target_image = self._resolve_full_image_path(
            auth.target_server if auth and auth.target_server else r"C:\Windows\System32\lsass.exe"
        )
        target_guid = self._generate_process_guid(host.hostname, target_pid, event.timestamp)

        # Determine user string
        if auth and auth.username:
            user = f"{host.netbios_domain}\\{auth.username}"
        else:
            user = "NT AUTHORITY\\SYSTEM"

        # GrantedAccess values for credential dumping:
        # 0x1010 = PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ
        # 0x1FFFFF = PROCESS_ALL_ACCESS
        # 0x1438 = typical mimikatz access mask
        granted_access = auth.failure_status if auth and auth.failure_status else "0x1010"

        event_data = {
            "EventID": 10,
            "TimeCreated": event.timestamp,
            "Computer": host.fqdn,
            "Channel": "Microsoft-Windows-Sysmon/Operational",
            "Level": 4,
            "ExecutionProcessID": self._get_sysmon_pid(host.hostname),
            "ExecutionThreadID": rng.randint(1000, 5000),
            "UtcTime": utc_time,
            "SourceProcessGUID": source_guid,
            "SourceProcessId": proc.pid,
            "SourceImage": proc.image,
            "SourceThreadId": rng.randint(100, 9999),
            "SourceUser": user,
            "TargetProcessGUID": target_guid,
            "TargetProcessId": target_pid,
            "TargetImage": target_image,
            "TargetUser": "NT AUTHORITY\\SYSTEM",
            "GrantedAccess": granted_access,
            "CallTrace": (
                f"C:\\Windows\\SYSTEM32\\ntdll.dll+{rng.randint(0x9C000, 0x9F000):X}"
                f"|C:\\Windows\\System32\\KERNELBASE.dll+{rng.randint(0x2C000, 0x2F000):X}"
            ),
        }
        self.emit_event(event_data)

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
        self._host_writers_lock = Lock()

        super().__init__(format_def, output_path, buffer_size, threaded)
        self._event_dicts: list[dict[str, Any]] = []
        self._record_id_counters: dict[str, int] = {}

    def _get_host_writer(self, host_fqdn: str) -> _SingleHostWriter:
        writer = self._host_writers.get(host_fqdn)
        if writer is not None:
            return writer
        with self._host_writers_lock:
            writer = self._host_writers.get(host_fqdn)
            if writer is not None:
                return writer
            if host_fqdn and not self._direct_file_mode:
                path = self._base_dir / host_fqdn / "windows_event_sysmon.xml"
            elif self._direct_file_path:
                path = self._direct_file_path
            else:
                path = self._base_dir / "windows_event_sysmon.xml"
            writer = _SingleHostWriter(path, self.buffer_size)
            header = self.format_def.output.header_template
            if header:
                writer.write_header(header)
            self._host_writers[host_fqdn] = writer
            return writer

    def _buffer_event(self, rendered: str) -> None:
        self._get_host_writer("").write(rendered)

    def emit_event(self, event_data: dict[str, Any]) -> None:
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
                event_data["TimeCreated"] = ts.strftime("%Y-%m-%dT%H:%M:%S.%f") + "Z"
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
                    if len(self._event_dicts) >= self.buffer_size:
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

        def _sort_key(event: dict) -> Any:
            ts = event.get("TimeCreated", "")
            return ts if isinstance(ts, datetime) else ts

        self._event_dicts.sort(key=_sort_key)

        # Per-host RNGs for deterministic gap generation
        _erid_rngs: dict[str, random.Random] = {}

        for event in self._event_dicts:
            computer = event.get("Computer", "")
            counter_key = computer.split(".")[0] if "." in computer else computer
            if counter_key not in self._record_id_counters:
                _erid_rngs[counter_key] = random.Random(f"sysmon_erid_{counter_key}")
                self._record_id_counters[counter_key] = _erid_rngs[counter_key].randint(
                    100_000, 500_000
                )
            rng = _erid_rngs[counter_key]
            # Simulate gaps from event types we don't generate (3, 7, 11, 12-14, 22, etc.)
            # Real Sysmon generates ~3-8x more events than just types 1/5/8/10
            gap = rng.randint(1, 8)
            self._record_id_counters[counter_key] += gap
            event["EventRecordID"] = self._record_id_counters[counter_key]

        for event in self._event_dicts:
            rendered = self._render_event(event)
            host_fqdn = event.get("Computer", "")
            self._get_host_writer(host_fqdn).write(rendered)

        self._event_dicts.clear()

    def flush(self) -> None:
        with self._file_lock:
            self._flush_unlocked()
        with self._host_writers_lock:
            for writer in self._host_writers.values():
                writer.flush()

    def close(self) -> None:
        if self.threaded:
            self.stop_thread()
        else:
            self.flush()
        footer = self.format_def.output.footer_template or ""
        for writer in self._host_writers.values():
            writer.flush()
            if footer and writer.event_count > 0:
                writer.write_footer(footer)

    @property
    def event_count(self) -> int:
        return sum(w.event_count for w in self._host_writers.values())

    @event_count.setter
    def event_count(self, value: int) -> None:
        pass
