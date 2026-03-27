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
        "create_remote_thread",
        "process_access",
    }

    def can_handle(self, event: SecurityEvent) -> bool:
        """Sysmon emitter handles process events on Windows hosts."""
        return (
            event.event_type in self._supported_types
            and event.host is not None
            and event.host.os_category == "windows"
        )

    def emit(self, event: SecurityEvent) -> None:
        """Dispatch to per-type render method."""
        if event.event_type in ("process_create", "system_process_create"):
            self._render_sysmon_process_create(event)
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
        """Generate a deterministic Sysmon ProcessGuid from host+pid+time."""
        seed = f"{hostname}:{pid}:{timestamp.isoformat()}"
        h = hashlib.md5(seed.encode(), usedforsecurity=False).hexdigest()
        return f"{{{h[:8]}-{h[8:12]}-{h[12:16]}-{h[16:20]}-{h[20:32]}}}"

    @staticmethod
    def _generate_hashes(image: str, hostname: str) -> str:
        """Generate deterministic fake file hashes from image+hostname."""
        seed = f"{image}:{hostname}"
        random.Random(seed)
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
        host = event.host

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
            "ExecutionProcessID": rng.randint(1800, 3000),  # Sysmon service PID
            "ExecutionThreadID": rng.randint(1000, 5000),
            "UtcTime": utc_time,
            "ProcessGuid": process_guid,
            "ProcessId": proc.pid,
            "Image": proc.image,
            "CommandLine": proc.command_line,
            "User": user,
            "LogonGuid": self._generate_process_guid(
                host.hostname, 0, datetime(event.timestamp.year, 1, 1)
            ),
            "LogonId": logon_id,
            "IntegrityLevel": integrity,
            "Hashes": self._generate_hashes(proc.image, host.hostname),
            "ParentProcessGuid": parent_guid,
            "ParentProcessId": proc.parent_pid,
            "ParentImage": proc.parent_image or "-",
            "ParentCommandLine": "-",
        }
        self.emit_event(event_data)

    def _render_sysmon_create_remote_thread(self, event: SecurityEvent) -> None:
        """Render Sysmon Event 8 (CreateRemoteThread)."""
        rng = random.Random()
        host = event.host
        proc = event.process  # Source process
        # Target info passed via network context fields or extra context
        # For simplicity, we use process context for source and auth for target hints
        auth = event.auth

        utc_time = event.timestamp.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
        source_guid = self._generate_process_guid(host.hostname, proc.pid, event.timestamp)

        # Target process info from auth context (target_server=target_image, process_name=unused)
        target_pid = int(auth.source_port) if auth and auth.source_port else rng.randint(1000, 8000)
        target_image = (
            auth.target_server if auth and auth.target_server else r"C:\Windows\explorer.exe"
        )
        target_guid = self._generate_process_guid(host.hostname, target_pid, event.timestamp)

        event_data = {
            "EventID": 8,
            "TimeCreated": event.timestamp,
            "Computer": host.fqdn,
            "Channel": "Microsoft-Windows-Sysmon/Operational",
            "Level": 4,
            "ExecutionProcessID": rng.randint(1800, 3000),
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
        host = event.host
        proc = event.process  # Source process
        auth = event.auth

        utc_time = event.timestamp.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
        source_guid = self._generate_process_guid(host.hostname, proc.pid, event.timestamp)

        # Target process info from auth context (same pattern as create_remote_thread)
        target_pid = int(auth.source_port) if auth and auth.source_port else rng.randint(500, 800)
        target_image = (
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
            "ExecutionProcessID": rng.randint(1800, 3000),
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

        for event in self._event_dicts:
            computer = event.get("Computer", "")
            counter_key = computer.split(".")[0] if "." in computer else computer
            if counter_key not in self._record_id_counters:
                rng = random.Random(f"sysmon_erid_{counter_key}")
                self._record_id_counters[counter_key] = rng.randint(100_000, 500_000)
            self._record_id_counters[counter_key] += 1
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
