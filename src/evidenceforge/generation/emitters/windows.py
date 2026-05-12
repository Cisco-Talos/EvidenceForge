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

"""Windows Event Log emitter.

Buffers raw event dicts, sorts by timestamp on flush, assigns per-computer
EventRecordIDs in sorted order (ensuring monotonic IDs match chronological
order), then renders to XML and writes to per-host FQDN directories.
"""

import json
import logging
import os
import random
import sqlite3
import tempfile
from datetime import UTC, datetime, timedelta
from pathlib import Path
from queue import Empty
from threading import Lock
from typing import Any

from evidenceforge.events.base import SecurityEvent
from evidenceforge.events.contexts import HostContext
from evidenceforge.formats.format_def import FormatDefinition
from evidenceforge.generation.activity.timing_profiles import (
    sample_timing_delta,
    windows_collision_spacing_config,
)
from evidenceforge.generation.emitters.base import LogEmitter
from evidenceforge.generation.emitters.host_base import _SingleHostWriter
from evidenceforge.generation.emitters.windows_event import format_windows_system_time
from evidenceforge.utils.paths import sanitize_path_component
from evidenceforge.utils.rng import _stable_seed
from evidenceforge.utils.time import ensure_utc

win_logger = logging.getLogger(__name__)

# Well-known service accounts that always use "NT AUTHORITY" as their domain
_NT_AUTHORITY_ACCOUNTS = {"SYSTEM", "NETWORK SERVICE", "LOCAL SERVICE", "ANONYMOUS LOGON"}


def _normalize_windows_time_created(
    event: dict[str, Any],
    last_by_computer: dict[str, datetime],
    collision_count_by_computer: dict[str, int],
    sequence: int,
    seed_prefix: str,
    *,
    jitter_existing_microseconds: bool = False,
) -> None:
    """Apply deterministic jitter while preserving per-computer chronological order.

    Storyline-origin events (_storyline_origin=True) are exempt from both the
    monotonic-clock clamp and the last_by_computer update so that baseline events
    in subsequent flush batches are not pushed forward past the storyline time.
    """
    ts = event.get("TimeCreated")
    if not isinstance(ts, datetime):
        return

    # Storyline events have a fixed authoritative timestamp; skip normalization
    # to avoid the per-host clock inheriting a far-future value that would shift
    # all later baseline events on the same host.
    if event.get("_storyline_origin"):
        computer = str(event.get("Computer", ""))
        original = ensure_utc(ts)
        if original.microsecond == 0:
            seed = f"{seed_prefix}_{computer}_{sequence}_{event.get('EventID', '')}_storyline"
            rng = random.Random(_stable_seed(seed))
            event["TimeCreated"] = original.replace(microsecond=rng.randint(100_000, 999_999))
        return

    computer = str(event.get("Computer", ""))
    original = ensure_utc(ts)
    normalized = original
    seed = (
        f"{seed_prefix}_{computer}_{sequence}_{event.get('EventID', '')}_"
        f"{event.get('ExecutionProcessID', '')}_{event.get('ExecutionThreadID', '')}"
    )
    rng = random.Random(_stable_seed(seed))
    if normalized.microsecond == 0:
        normalized = normalized.replace(microsecond=rng.randint(100_000, 999_999))
    elif jitter_existing_microseconds:
        normalized = normalized + timedelta(microseconds=rng.randint(50, 500))

    previous = last_by_computer.get(computer)
    if previous is not None and original <= previous:
        collision_count = collision_count_by_computer.get(computer, 0) + 1
        collision_count_by_computer[computer] = collision_count
        spacing = windows_collision_spacing_config()
        seed = (
            f"{seed_prefix}:collision:{computer}:{sequence}:{event.get('EventID', '')}:"
            f"{event.get('EventRecordID', '')}"
        )
        rng = random.Random(_stable_seed(seed))
        if collision_count <= spacing["near_zero_until"]:
            gap_us = rng.randint(spacing["near_gap_min_us"], spacing["near_gap_max_us"])
            normalized = previous + timedelta(microseconds=gap_us)
        else:
            gap_ms = rng.randint(spacing["large_gap_min_ms"], spacing["large_gap_max_ms"])
            normalized = previous + timedelta(milliseconds=gap_ms)
    else:
        collision_count_by_computer[computer] = 0
    last_by_computer[computer] = normalized
    event["TimeCreated"] = normalized


def _subject_domain(username: str, netbios_domain: str) -> str:
    """Return the correct domain for SubjectDomainName / TargetDomainName.

    Windows well-known service accounts always use 'NT AUTHORITY', never
    the AD domain name.
    """
    if username.upper() in _NT_AUTHORITY_ACCOUNTS:
        return "NT AUTHORITY"
    return netbios_domain


def _auth_subject_domain(auth: Any, netbios_domain: str) -> str:
    """Normalize SubjectDomainName for well-known Windows subject identities."""
    subject_name = getattr(auth, "subject_username", "") or getattr(auth, "username", "")
    subject_sid = getattr(auth, "subject_sid", "") or getattr(auth, "user_sid", "")
    if subject_sid == "S-1-5-18" or subject_name.upper() in _NT_AUTHORITY_ACCOUNTS:
        return "NT AUTHORITY"
    return getattr(auth, "subject_domain", "") or _subject_domain(subject_name, netbios_domain)


def _special_privilege_fallback(username: str) -> str:
    """Return a realistic 4672 privilege set when AuthContext omits one."""
    normalized = username.upper()
    if normalized in {"LOCAL SERVICE", "NETWORK SERVICE"}:
        return (
            "SeAssignPrimaryTokenPrivilege\n\t\t\t"
            "SeAuditPrivilege\n\t\t\t"
            "SeImpersonatePrivilege\n\t\t\t"
            "SeChangeNotifyPrivilege"
        )
    if normalized == "SYSTEM" or normalized.endswith("$"):
        return (
            "SeTcbPrivilege\n\t\t\t"
            "SeSecurityPrivilege\n\t\t\t"
            "SeTakeOwnershipPrivilege\n\t\t\t"
            "SeLoadDriverPrivilege\n\t\t\t"
            "SeBackupPrivilege\n\t\t\t"
            "SeRestorePrivilege\n\t\t\t"
            "SeDebugPrivilege\n\t\t\t"
            "SeAuditPrivilege\n\t\t\t"
            "SeSystemEnvironmentPrivilege\n\t\t\t"
            "SeImpersonatePrivilege\n\t\t\t"
            "SeDelegateSessionUserImpersonatePrivilege"
        )
    return (
        "SeSecurityPrivilege\n\t\t\t"
        "SeBackupPrivilege\n\t\t\t"
        "SeRestorePrivilege\n\t\t\t"
        "SeTakeOwnershipPrivilege\n\t\t\t"
        "SeDebugPrivilege\n\t\t\t"
        "SeImpersonatePrivilege"
    )


_SPOOL_FIELDS_KEY = "fields"
_SPOOL_VALUE_TYPE_KEY = "type"
_SPOOL_VALUE_KEY = "value"
_SPOOL_DATETIME_TYPE = "datetime"
_SPOOL_JSON_TYPE = "json"


def _spool_encode(event: dict[str, Any]) -> str:
    """Encode a Windows event dictionary for the on-disk spool.

    The wrapper keeps datetime metadata out of attacker-controlled string values.
    Raw Windows fields such as TargetUserName may contain any string, including
    legacy sentinel prefixes, without being interpreted during decode.
    """
    fields: dict[str, dict[str, Any]] = {}
    for key, value in event.items():
        if isinstance(value, datetime):
            fields[key] = {
                _SPOOL_VALUE_TYPE_KEY: _SPOOL_DATETIME_TYPE,
                _SPOOL_VALUE_KEY: value.isoformat(),
            }
        else:
            fields[key] = {_SPOOL_VALUE_TYPE_KEY: _SPOOL_JSON_TYPE, _SPOOL_VALUE_KEY: value}
    return json.dumps({_SPOOL_FIELDS_KEY: fields})


def _spool_decode(payload: str) -> dict[str, Any]:
    """Decode a Windows event dictionary from the on-disk spool."""
    decoded = json.loads(payload)
    if not isinstance(decoded, dict):
        raise ValueError("Windows spool payload must decode to an object")
    fields = decoded.get(_SPOOL_FIELDS_KEY)
    if not isinstance(fields, dict):
        raise ValueError("Windows spool payload is missing fields object")

    event: dict[str, Any] = {}
    for key, wrapped in fields.items():
        if not isinstance(key, str) or not isinstance(wrapped, dict):
            raise ValueError("Windows spool field entries must be keyed objects")
        value_type = wrapped.get(_SPOOL_VALUE_TYPE_KEY)
        value = wrapped.get(_SPOOL_VALUE_KEY)
        if value_type == _SPOOL_DATETIME_TYPE:
            if not isinstance(value, str):
                raise ValueError("Windows spool datetime value must be a string")
            event[key] = datetime.fromisoformat(value).replace(tzinfo=UTC)
        elif value_type == _SPOOL_JSON_TYPE:
            event[key] = value
        else:
            raise ValueError(f"unknown Windows spool field type: {value_type!r}")
    return event


class WindowsEventEmitter(LogEmitter):
    """Emitter for Windows Event Log format (XML).

    Unlike other emitters that buffer rendered strings, this emitter buffers
    raw event dicts and defers rendering until flush time. This allows
    EventRecordIDs to be assigned after chronological sorting, ensuring
    higher RecordID always corresponds to same-or-later timestamp (matching
    real Windows Event Log behavior).

    _supported_types will be populated during Phase 7.2 migration.
    """

    _supported_types: set[str] = {
        "logon",
        "logoff",
        "failed_logon",
        "process_create",
        "process_terminate",
        "system_process_create",
        "machine_logon",
        "kerberos_tgt",
        "kerberos_tgt_renewal",
        "kerberos_service",
        "kerberos_preauth_failed",
        "ntlm_validation",
        "explicit_credentials",
        "wfp_connection",
        "log_cleared",
        "service_installed",
        "scheduled_task_created",
        "scheduled_task_deleted",
        "scheduled_task_enabled",
        "scheduled_task_disabled",
        "group_member_added_global",
        "group_member_removed_global",
        "group_member_added_local",
        "group_member_removed_local",
        "group_member_added_universal",
        "group_member_removed_universal",
        "account_created",
        "account_deleted",
        "account_changed",
        "password_change",
        "password_reset",
        "special_privileges",
        "workstation_locked",
        "workstation_unlocked",
    }

    @staticmethod
    def _ipv6_mapped(ip: str | None) -> str:
        """Format IPv4 as ::ffff:-mapped for Windows event consistency."""
        if not ip or ip == "-":
            return "-"
        if ":" in ip:
            return ip  # Already IPv6
        return f"::ffff:{ip}"

    # Event types where the Windows host is dst_host (target of the action)
    _DST_HOST_TYPES: set[str] = {
        "logon",
        "logoff",
        "failed_logon",
        "machine_logon",
        "special_privileges",
        "kerberos_tgt",
        "kerberos_tgt_renewal",
        "kerberos_service",
        "ntlm_validation",
        "kerberos_preauth_failed",
        "explicit_credentials",
        "account_created",
        "account_deleted",
        "account_changed",
        "password_change",
        "password_reset",
        "group_member_added_global",
        "group_member_removed_global",
        "group_member_added_local",
        "group_member_removed_local",
        "group_member_added_universal",
        "group_member_removed_universal",
        "workstation_locked",
        "workstation_unlocked",
    }

    def _get_host(self, event: SecurityEvent) -> "HostContext":
        """Select the correct Windows host for this event type."""
        if event.event_type in self._DST_HOST_TYPES:
            return event.dst_host or event.src_host
        return event.src_host or event.dst_host

    def can_handle(self, event: SecurityEvent) -> bool:
        """Windows emitter handles events on Windows hosts."""
        host = self._get_host(event)
        return (
            event.event_type in self._supported_types
            and host is not None
            and host.os_category == "windows"
        )

    def emit(self, event: SecurityEvent) -> None:
        """Dispatch to per-type render method."""
        self._current_storyline_origin = event.storyline_origin
        renderer = {
            "logon": self._render_logon,
            "logoff": self._render_logoff,
            "failed_logon": self._render_failed_logon,
            "process_create": self._render_process_create,
            "process_terminate": self._render_process_terminate,
            "system_process_create": self._render_system_process_create,
            "machine_logon": self._render_machine_logon,
            "kerberos_tgt": self._render_kerberos_tgt,
            "kerberos_tgt_renewal": self._render_kerberos_tgt_renewal,
            "kerberos_service": self._render_kerberos_service,
            "ntlm_validation": self._render_ntlm_validation,
            "explicit_credentials": self._render_explicit_credentials,
            "wfp_connection": self._render_wfp_connection,
            "kerberos_preauth_failed": self._render_kerberos_preauth_failed,
            "log_cleared": self._render_log_cleared,
            "service_installed": self._render_service_installed,
            "scheduled_task_created": self._render_scheduled_task,
            "scheduled_task_deleted": self._render_scheduled_task,
            "scheduled_task_enabled": self._render_scheduled_task,
            "scheduled_task_disabled": self._render_scheduled_task,
            "group_member_added_global": self._render_group_membership_change,
            "group_member_removed_global": self._render_group_membership_change,
            "group_member_added_local": self._render_group_membership_change,
            "group_member_removed_local": self._render_group_membership_change,
            "group_member_added_universal": self._render_group_membership_change,
            "group_member_removed_universal": self._render_group_membership_change,
            "account_created": self._render_account_created,
            "account_deleted": self._render_account_deleted,
            "account_changed": self._render_account_changed,
            "password_change": self._render_password_change,
            "password_reset": self._render_password_reset,
            "special_privileges": self._render_special_privileges,
            "workstation_locked": self._render_workstation_lock,
            "workstation_unlocked": self._render_workstation_unlock,
        }.get(event.event_type)
        if renderer is None:
            raise NotImplementedError(
                f"WindowsEventEmitter: no render method for {event.event_type}"
            )
        try:
            renderer(event)
        finally:
            self._current_storyline_origin = False

    def _render_logon(self, event: SecurityEvent) -> None:
        """Render Windows 4624 (successful logon) + optional 4672 (special privileges)."""
        rng = random.Random()
        auth = event.auth
        host = self._get_host(event)
        workstation_name = auth.workstation_name or (
            event.src_host.hostname
            if auth.logon_type in (3, 10) and event.src_host is not None
            else host.hostname
        )

        event_data = {
            "EventID": 4624,
            "TimeCreated": event.timestamp,
            "Computer": host.fqdn,
            "Channel": "Security",
            "Level": 0,
            "ExecutionProcessID": auth.reporting_pid or 600,
            "ExecutionThreadID": rng.randint(100, 500),
            "SubjectUserSid": auth.subject_sid,
            "SubjectUserName": auth.subject_username,
            "SubjectDomainName": _auth_subject_domain(auth, host.netbios_domain),
            "SubjectLogonId": auth.subject_logon_id,
            "TargetUserSid": auth.user_sid,
            "TargetUserName": auth.username,
            "TargetDomainName": _subject_domain(auth.username, host.netbios_domain),
            "TargetLogonId": auth.logon_id,
            "LogonType": auth.logon_type,
            "WorkstationName": workstation_name,
            "ProcessId": f"0x{auth.reporting_pid:x}" if auth.reporting_pid else "0x2e0",
            "ProcessName": r"C:\Windows\System32\lsass.exe",
            "IpAddress": self._ipv6_mapped(auth.source_ip),
            "IpPort": auth.source_port if auth.logon_type in (3, 10) else 0,
            "LogonProcessName": auth.logon_process,
            "AuthenticationPackageName": auth.auth_package,
            "LmPackageName": auth.lm_package,
            "KeyLength": 128 if auth.lm_package == "NTLM V2" else 0,
            "LogonGuid": auth.logon_guid,
            "VirtualAccount": "%%1843",
            "ElevatedToken": "%%1842" if auth.elevated else "%%1843",
        }
        self.emit_event(event_data)

        # 4672 special privileges (when auth.elevated is True)
        if auth.elevated:
            privs = auth.privilege_list or _special_privilege_fallback(auth.username)
            priv_data = {
                "EventID": 4672,
                "TimeCreated": event.timestamp,
                "Computer": host.fqdn,
                "Channel": "Security",
                "Level": 0,
                "ExecutionProcessID": auth.reporting_pid or 600,
                "ExecutionThreadID": rng.randint(100, 500),
                "SubjectUserSid": auth.user_sid,
                "SubjectUserName": auth.username,
                "SubjectDomainName": _subject_domain(auth.username, host.netbios_domain),
                "SubjectLogonId": auth.logon_id,
                "PrivilegeList": privs,
            }
            self.emit_event(priv_data)

    def _render_special_privileges(self, event: SecurityEvent) -> None:
        """Render standalone Windows 4672 (Special Privileges Assigned).

        Used for explicit standalone 4672 events. Normal elevated logons render
        4672 from _render_logon() so the privilege event shares the target
        host and LogonID with its 4624.
        """
        rng = random.Random()
        auth = event.auth
        host = self._get_host(event)

        privs = auth.privilege_list or _special_privilege_fallback(auth.username)

        priv_data = {
            "EventID": 4672,
            "TimeCreated": event.timestamp,
            "Computer": host.fqdn,
            "Channel": "Security",
            "Level": 0,
            "ExecutionProcessID": auth.reporting_pid or 600,
            "ExecutionThreadID": rng.randint(100, 500),
            "SubjectUserSid": auth.user_sid,
            "SubjectUserName": auth.username,
            "SubjectDomainName": _subject_domain(auth.username, host.netbios_domain),
            "SubjectLogonId": auth.logon_id or "0x0",
            "PrivilegeList": privs,
        }
        self.emit_event(priv_data)

    def _render_workstation_lock(self, event: SecurityEvent) -> None:
        """Render Windows 4800 (workstation locked)."""
        rng = random.Random()
        auth = event.auth
        host = self._get_host(event)
        session_id = self._session_id_for_logon(auth.logon_id)
        event_data = {
            "EventID": 4800,
            "TimeCreated": event.timestamp,
            "Computer": host.fqdn,
            "Channel": "Security",
            "Level": 0,
            "ExecutionProcessID": 500 + rng.randint(0, 100),
            "ExecutionThreadID": rng.randint(100, 500),
            "TargetUserSid": auth.user_sid,
            "TargetUserName": auth.username,
            "TargetDomainName": _subject_domain(auth.username, host.netbios_domain),
            "TargetLogonId": auth.logon_id or "0x0",
            "SessionId": session_id,
        }
        self.emit_event(event_data)

    def _render_workstation_unlock(self, event: SecurityEvent) -> None:
        """Render Windows 4801 (workstation unlocked)."""
        rng = random.Random()
        auth = event.auth
        host = self._get_host(event)
        session_id = self._session_id_for_logon(auth.logon_id)
        event_data = {
            "EventID": 4801,
            "TimeCreated": event.timestamp,
            "Computer": host.fqdn,
            "Channel": "Security",
            "Level": 0,
            "ExecutionProcessID": 500 + rng.randint(0, 100),
            "ExecutionThreadID": rng.randint(100, 500),
            "TargetUserSid": auth.user_sid,
            "TargetUserName": auth.username,
            "TargetDomainName": _subject_domain(auth.username, host.netbios_domain),
            "TargetLogonId": auth.logon_id or "0x0",
            "SessionId": session_id,
        }
        self.emit_event(event_data)

    def _render_logoff(self, event: SecurityEvent) -> None:
        """Render Windows 4634 (logoff)."""
        rng = random.Random()
        auth = event.auth
        host = self._get_host(event)

        event_data = {
            "EventID": 4634,
            "TimeCreated": event.timestamp,
            "Computer": host.fqdn,
            "Channel": "Security",
            "Level": 0,
            "ExecutionProcessID": auth.reporting_pid or 600,
            "ExecutionThreadID": rng.randint(100, 500),
            "TargetUserSid": auth.user_sid,
            "TargetUserName": auth.username,
            "TargetDomainName": _subject_domain(auth.username, host.netbios_domain),
            "TargetLogonId": auth.logon_id,
            "LogonType": auth.logon_type,
        }
        if event.storyline_origin:
            event_data["_storyline_origin"] = True
        self.emit_event(event_data)

    def _render_failed_logon(self, event: SecurityEvent) -> None:
        """Render Windows 4625 (failed logon)."""
        rng = random.Random()
        auth = event.auth
        host = self._get_host(event)

        event_data = {
            "EventID": 4625,
            "TimeCreated": event.timestamp,
            "Computer": host.fqdn,
            "Channel": "Security",
            "Level": 0,
            "Keywords": "0x8010000000000000",  # Audit Failure
            "ExecutionProcessID": auth.reporting_pid or 600,
            "ExecutionThreadID": rng.randint(100, 9999),
            "SubjectUserSid": auth.subject_sid,
            "SubjectUserName": auth.subject_username,
            "SubjectDomainName": _auth_subject_domain(auth, host.netbios_domain),
            "SubjectLogonId": auth.subject_logon_id,
            "TargetUserSid": auth.user_sid,
            "TargetUserName": auth.username,
            "TargetDomainName": _subject_domain(auth.username, host.netbios_domain),
            "Status": auth.failure_status,
            "SubStatus": auth.failure_substatus,
            "FailureReason": auth.failure_reason,
            "LogonType": auth.logon_type,
            "LogonProcessName": auth.logon_process or "NtLmSsp",
            "AuthenticationPackageName": auth.auth_package or "NTLM",
            "WorkstationName": auth.workstation_name or "-",
            "LmPackageName": auth.lm_package or "-",
            "KeyLength": 128 if auth.lm_package == "NTLM V2" else 0,
            "ProcessId": f"0x{auth.process_pid:x}" if auth.process_pid else "0x0",
            "ProcessName": auth.process_name or "-",
            "IpAddress": self._ipv6_mapped(auth.source_ip),
            "IpPort": auth.source_port
            or (rng.randint(49152, 65535) if auth.logon_type == 3 else 0),
        }
        self.emit_event(event_data)

    def _render_process_create(self, event: SecurityEvent) -> None:
        """Render Windows 4688 (new process created)."""
        rng = random.Random()
        proc = event.process
        auth = event.auth
        host = self._get_host(event)

        event_data = {
            "EventID": 4688,
            "TimeCreated": event.timestamp,
            "Computer": host.fqdn,
            "Channel": "Security",
            "Level": 0,
            "ExecutionProcessID": 4,
            "ExecutionThreadID": rng.randint(100, 9999),
            "SubjectUserSid": auth.user_sid,
            "SubjectUserName": auth.username,
            "SubjectDomainName": _subject_domain(auth.username, host.netbios_domain),
            "SubjectLogonId": proc.logon_id,
            "NewProcessId": f"0x{proc.pid:x}",
            "NewProcessName": proc.image,
            "TokenElevationType": proc.token_elevation or "%%1938",
            "ProcessId": f"0x{proc.parent_pid:x}",
            "CommandLine": proc.command_line,
            "TargetUserSid": auth.user_sid,
            "TargetUserName": auth.username,
            "TargetDomainName": _subject_domain(auth.username, host.netbios_domain),
            "TargetLogonId": proc.logon_id,
            "ParentProcessName": proc.parent_image,
            "MandatoryLabel": proc.mandatory_label or "S-1-16-8192",
        }
        self.emit_event(event_data)

    def _render_process_terminate(self, event: SecurityEvent) -> None:
        """Render Windows 4689 (process exited)."""
        rng = random.Random()
        proc = event.process
        auth = event.auth
        host = self._get_host(event)

        event_data = {
            "EventID": 4689,
            "TimeCreated": event.timestamp,
            "Computer": host.fqdn,
            "Channel": "Security",
            "Level": 0,
            "ExecutionProcessID": 4,
            "ExecutionThreadID": rng.randint(100, 500),
            "SubjectUserSid": auth.user_sid,
            "SubjectUserName": auth.username,
            "SubjectDomainName": _subject_domain(auth.username, host.netbios_domain),
            "SubjectLogonId": proc.logon_id,
            "Status": "0x0",
            "ProcessId": f"0x{proc.pid:x}",
            "ProcessName": proc.image,
        }
        self.emit_event(event_data)

    def _render_system_process_create(self, event: SecurityEvent) -> None:
        """Render Windows 4688 for system-account process (SYSTEM, LOCAL SERVICE, etc.)."""
        rng = random.Random()
        proc = event.process
        auth = event.auth
        host = self._get_host(event)

        event_data = {
            "EventID": 4688,
            "TimeCreated": event.timestamp,
            "Computer": host.fqdn,
            "Channel": "Security",
            "Level": 0,
            "ExecutionProcessID": 4,
            "ExecutionThreadID": rng.randint(100, 9999),
            "SubjectUserSid": auth.subject_sid,
            "SubjectUserName": auth.subject_username,
            "SubjectDomainName": _auth_subject_domain(auth, host.netbios_domain),
            "SubjectLogonId": auth.subject_logon_id,
            "NewProcessId": f"0x{proc.pid:x}",
            "NewProcessName": proc.image,
            "TokenElevationType": proc.token_elevation or "%%1936",
            "ProcessId": f"0x{proc.parent_pid:x}",
            "CommandLine": proc.command_line,
            "TargetUserSid": auth.user_sid,
            "TargetUserName": auth.username,
            "TargetDomainName": auth.subject_domain,
            "TargetLogonId": proc.logon_id,
            "ParentProcessName": proc.parent_image,
            "MandatoryLabel": proc.mandatory_label or "S-1-16-16384",
        }
        self.emit_event(event_data)

    def _render_machine_logon(self, event: SecurityEvent) -> None:
        """Render Windows 4624 for machine account logon (type 3 on DC)."""
        rng = random.Random()
        auth = event.auth
        host = self._get_host(event)
        # Derive WorkstationName from machine account (WKS-01$ → WKS-01)
        workstation = auth.username.rstrip("$") if auth.username.endswith("$") else auth.username

        event_data = {
            "EventID": 4624,
            "TimeCreated": event.timestamp,
            "Computer": host.fqdn,
            "Channel": "Security",
            "Level": 0,
            "ExecutionProcessID": auth.reporting_pid or 600,
            "ExecutionThreadID": rng.randint(100, 500),
            "SubjectUserSid": auth.subject_sid,
            "SubjectUserName": auth.subject_username,
            "SubjectDomainName": _auth_subject_domain(auth, host.netbios_domain),
            "SubjectLogonId": auth.subject_logon_id,
            "TargetUserSid": auth.user_sid,
            "TargetUserName": auth.username,
            "TargetDomainName": _subject_domain(auth.username, host.netbios_domain),
            "TargetLogonId": auth.logon_id,
            "LogonType": 3,
            "LogonProcessName": auth.logon_process,
            "AuthenticationPackageName": auth.auth_package,
            "WorkstationName": workstation,
            "LogonGuid": auth.logon_guid,
            "TransmittedServices": "-",
            "LmPackageName": auth.lm_package,
            "KeyLength": 128 if auth.lm_package == "NTLM V2" else 0,
            "ProcessId": "0x0",
            "ProcessName": "-",
            "IpAddress": self._ipv6_mapped(auth.source_ip),
            "IpPort": str(rng.randint(49152, 65535)),
            "ImpersonationLevel": "%%1833",
            "RestrictedAdminMode": "-",
            "TargetOutboundUserName": "-",
            "TargetOutboundDomainName": "-",
            "VirtualAccount": "%%1843",
            "TargetLinkedLogonId": "0x0",
            "ElevatedToken": "%%1842",
        }
        self.emit_event(event_data)

        # 4672 special privileges for machine accounts
        if auth.elevated:
            priv_data = {
                "EventID": 4672,
                "TimeCreated": event.timestamp,
                "Computer": host.fqdn,
                "Channel": "Security",
                "Level": 0,
                "ExecutionProcessID": auth.reporting_pid or 600,
                "ExecutionThreadID": rng.randint(100, 500),
                "SubjectUserSid": auth.user_sid,
                "SubjectUserName": auth.username,
                "SubjectDomainName": _subject_domain(auth.username, host.netbios_domain),
                "SubjectLogonId": auth.logon_id,
                "PrivilegeList": (
                    "SeSecurityPrivilege\n\t\t\tSeBackupPrivilege\n\t\t\t"
                    "SeRestorePrivilege\n\t\t\tSeTakeOwnershipPrivilege\n\t\t\t"
                    "SeDebugPrivilege\n\t\t\tSeSystemEnvironmentPrivilege\n\t\t\t"
                    "SeLoadDriverPrivilege\n\t\t\tSeImpersonatePrivilege\n\t\t\t"
                    "SeDelegateSessionUserImpersonatePrivilege"
                ),
            }
            self.emit_event(priv_data)

    def _render_kerberos_tgt(self, event: SecurityEvent) -> None:
        """Render Windows 4768 (Kerberos TGT request)."""
        rng = random.Random()
        krb = event.kerberos
        host = self._get_host(event)
        is_failure = krb.ticket_status != "0x0"

        event_data = {
            "EventID": 4768,
            "TimeCreated": event.timestamp,
            "Computer": host.fqdn,
            "Channel": "Security",
            "Level": 0,
            "Keywords": "0x8010000000000000" if is_failure else "0x8020000000000000",
            "ExecutionProcessID": krb.reporting_pid or 600,
            "ExecutionThreadID": rng.randint(100, 500),
            "TargetUserName": krb.target_username,
            "TargetDomainName": krb.target_domain,
            "TargetSid": krb.target_sid,
            "ServiceName": krb.service_name,
            "ServiceSid": krb.service_sid,
            "TicketOptions": krb.ticket_options,
            "Status": krb.ticket_status,
            "TicketEncryptionType": krb.encryption_type,
            "PreAuthType": krb.pre_auth_type,
            "IpAddress": krb.source_ip,
            "IpPort": krb.source_port,
            "CertIssuerName": krb.cert_issuer_name,
            "CertSerialNumber": krb.cert_serial_number,
            "CertThumbprint": krb.cert_thumbprint,
        }
        self.emit_event(event_data)

    def _render_kerberos_service(self, event: SecurityEvent) -> None:
        """Render Windows 4769 (Kerberos service ticket request)."""
        rng = random.Random()
        krb = event.kerberos
        host = self._get_host(event)
        is_failure = krb.ticket_status != "0x0"

        event_data = {
            "EventID": 4769,
            "TimeCreated": event.timestamp,
            "Computer": host.fqdn,
            "Channel": "Security",
            "Level": 0,
            "Keywords": "0x8010000000000000" if is_failure else "0x8020000000000000",
            "ExecutionProcessID": krb.reporting_pid or 600,
            "ExecutionThreadID": rng.randint(100, 500),
            "TargetUserName": krb.target_username
            if "@" in krb.target_username
            else f"{krb.target_username}@{krb.target_domain.upper()}",
            "TargetDomainName": krb.target_domain,
            "ServiceName": krb.service_name,
            "ServiceSid": krb.service_sid,
            "TicketOptions": krb.ticket_options,
            "TicketEncryptionType": krb.encryption_type,
            "IpAddress": krb.source_ip,
            "IpPort": krb.source_port,
            "Status": krb.ticket_status,
        }
        self.emit_event(event_data)

    def _render_kerberos_tgt_renewal(self, event: SecurityEvent) -> None:
        """Render Windows 4770 (Kerberos TGT renewal)."""
        rng = random.Random()
        krb = event.kerberos
        host = self._get_host(event)

        event_data = {
            "EventID": 4770,
            "TimeCreated": event.timestamp,
            "Computer": host.fqdn,
            "Channel": "Security",
            "Level": 0,
            "ExecutionProcessID": krb.reporting_pid or 600,
            "ExecutionThreadID": rng.randint(100, 500),
            "TargetUserName": krb.target_username,
            "TargetDomainName": krb.target_domain,
            "ServiceName": krb.service_name,
            "ServiceSid": krb.service_sid,
            "TicketOptions": krb.ticket_options,
            "TicketEncryptionType": krb.encryption_type,
            "IpAddress": krb.source_ip,
            "IpPort": krb.source_port,
            "Status": "0x0",
        }
        self.emit_event(event_data)

    def _render_ntlm_validation(self, event: SecurityEvent) -> None:
        """Render Windows 4776 (NTLM credential validation)."""
        rng = random.Random()
        auth = event.auth
        host = self._get_host(event)

        event_data = {
            "EventID": 4776,
            "TimeCreated": event.timestamp,
            "Computer": host.fqdn,
            "Channel": "Security",
            "Level": 0,
            "ExecutionProcessID": auth.reporting_pid or 600,
            "ExecutionThreadID": rng.randint(100, 500),
            "PackageName": "MICROSOFT_AUTHENTICATION_PACKAGE_V1_0",
            "TargetUserName": auth.username,
            "Workstation": auth.source_ip,  # workstation stored in source_ip
            "Status": auth.failure_status or "0x0",
        }
        self.emit_event(event_data)

    def _render_explicit_credentials(self, event: SecurityEvent) -> None:
        """Render Windows 4648 (explicit credentials logon)."""
        rng = random.Random()
        auth = event.auth
        host = self._get_host(event)

        event_data = {
            "EventID": 4648,
            "TimeCreated": event.timestamp,
            "Computer": host.fqdn,
            "Channel": "Security",
            "Level": 0,
            "ExecutionProcessID": auth.reporting_pid or 600,
            "ExecutionThreadID": rng.randint(100, 9999),
            "SubjectUserSid": auth.subject_sid,
            "SubjectUserName": auth.subject_username,
            "SubjectDomainName": _auth_subject_domain(auth, host.netbios_domain),
            "SubjectLogonId": auth.subject_logon_id,
            "LogonGuid": auth.logon_guid or "{00000000-0000-0000-0000-000000000000}",
            "TargetUserName": auth.username,
            "TargetDomainName": auth.target_domain
            or _subject_domain(auth.username, host.netbios_domain),
            "TargetLogonGuid": "{00000000-0000-0000-0000-000000000000}",
            "TargetServerName": auth.target_server or "localhost",
            "TargetInfo": auth.target_server or "localhost",
            "ProcessId": f"0x{auth.process_pid:x}" if auth.process_pid else "0x0",
            "ProcessName": auth.process_name or r"C:\Windows\System32\svchost.exe",
            "NetworkAddress": auth.source_ip or "-",
            "NetworkPort": auth.source_port or 0,
        }
        self.emit_event(event_data)

    def _render_wfp_connection(self, event: SecurityEvent) -> None:
        """Render Windows 5156 (WFP connection permitted)."""
        rng = random.Random()
        net = event.network
        host = self._get_host(event)
        proc = event.process
        is_outbound = net.src_ip == host.ip
        pid = net.initiating_pid if net.initiating_pid > 0 else 4
        image = proc.image if proc else ""
        if is_outbound and net.protocol.lower() == "udp" and net.dst_port == 53:
            sys_pids = getattr(self, "_system_pids", {}).get(host.hostname, {})
            pid = sys_pids.get("svchost_local_svc", sys_pids.get("svchost_netsvcs", pid))
            image = r"C:\Windows\System32\svchost.exe"
        if not image and pid > 0:
            sm = getattr(self, "_state_manager", None)
            if sm is not None:
                running = sm.get_process(host.hostname, pid)
                if running is not None:
                    image = running.image
        if not image:
            if pid == 4:
                image = "System"
            else:
                return
        render_time = event.timestamp + sample_timing_delta(
            "source.windows_wfp_connection",
            seed_parts=(
                host.hostname,
                pid,
                net.src_ip,
                net.src_port,
                net.dst_ip,
                net.dst_port,
                event.timestamp,
            ),
        )

        event_data = {
            "EventID": 5156,
            "TimeCreated": render_time,
            "Computer": host.fqdn,
            "Channel": "Security",
            "Level": 0,
            "ExecutionProcessID": 4,
            "ExecutionThreadID": rng.randint(50, 200),
            "ProcessID": pid,
            "Application": self._to_device_path(image),
            "Direction": "%%14593" if is_outbound else "%%14592",
            "SourceAddress": net.src_ip,
            "SourcePort": net.src_port,
            "DestAddress": net.dst_ip,
            "DestPort": net.dst_port,
            "Protocol": net.ip_proto,
            "FilterRTID": rng.randint(0, 70000),
            "LayerName": "%%14611",
            "LayerRTID": 48,
            "RemoteUserID": "S-1-0-0",
            "RemoteMachineID": "S-1-0-0",
        }
        self.emit_event(event_data)

    @staticmethod
    def _to_device_path(path: str) -> str:
        """Convert C:\\path to \\device\\harddiskvolume1\\path (lowercase)."""
        if path == "System":
            return path
        if path and len(path) > 2 and path[1] == ":":
            return f"\\device\\harddiskvolume1\\{path[3:]}".lower()
        return path.lower()

    @staticmethod
    def _session_id_for_logon(logon_id: str) -> int:
        """Return a stable Terminal Services session ID for a LogonID."""
        return 1 + (_stable_seed(f"windows_session_id_{logon_id or '0x0'}") % 5)

    # --- Phase 1: Kerberos Pre-Auth Failed (4771) ---

    def _render_kerberos_preauth_failed(self, event: SecurityEvent) -> None:
        """Render Windows 4771 (Kerberos pre-authentication failed)."""
        rng = random.Random()
        krb = event.kerberos
        host = self._get_host(event)

        event_data = {
            "EventID": 4771,
            "TimeCreated": event.timestamp,
            "Computer": host.fqdn,
            "Channel": "Security",
            "Level": 0,
            "Keywords": "0x8010000000000000",  # Always Audit Failure
            "ExecutionProcessID": krb.reporting_pid or 600,
            "ExecutionThreadID": rng.randint(100, 500),
            "TargetUserName": krb.target_username,
            "TargetSid": krb.target_sid,
            "ServiceName": krb.service_name,
            "TicketOptions": krb.ticket_options,
            "Status": krb.ticket_status,
            "PreAuthType": krb.pre_auth_type,
            "IpAddress": krb.source_ip,
            "IpPort": krb.source_port,
        }
        self.emit_event(event_data)

    # --- Phase 2: Security Log Cleared (1102) ---

    def _render_log_cleared(self, event: SecurityEvent) -> None:
        """Render Windows 1102 (security log cleared)."""
        rng = random.Random()
        auth = event.auth
        host = self._get_host(event)

        event_data = {
            "EventID": 1102,
            "TimeCreated": event.timestamp,
            "Computer": host.fqdn,
            "Channel": "Security",
            "Level": 4,
            "Keywords": "0x4020000000000000",
            "ExecutionProcessID": rng.randint(600, 1400),
            "ExecutionThreadID": rng.randint(100, 9999),
            "SubjectUserSid": auth.subject_sid,
            "SubjectUserName": auth.subject_username,
            "SubjectDomainName": _auth_subject_domain(auth, host.netbios_domain),
            "SubjectLogonId": auth.subject_logon_id,
        }
        self.emit_event(event_data)

    # --- Phase 3: Service Installed (4697) ---

    def _render_service_installed(self, event: SecurityEvent) -> None:
        """Render Windows 4697 (service installed in the system)."""
        rng = random.Random()
        auth = event.auth
        host = self._get_host(event)
        svc = event.service

        event_data = {
            "EventID": 4697,
            "TimeCreated": event.timestamp,
            "Computer": host.fqdn,
            "Channel": "Security",
            "Level": 0,
            "ExecutionProcessID": auth.reporting_pid or 600,
            "ExecutionThreadID": rng.randint(100, 9999),
            "SubjectUserSid": auth.subject_sid,
            "SubjectUserName": auth.subject_username,
            "SubjectDomainName": _auth_subject_domain(auth, host.netbios_domain),
            "SubjectLogonId": auth.subject_logon_id,
            "ServiceName": svc.service_name,
            "ServiceFileName": svc.service_file_name,
            "ServiceType": svc.service_type,
            "ServiceStartType": svc.service_start_type,
            "ServiceAccount": svc.service_account,
        }
        self.emit_event(event_data)

    # --- Phase 4: Scheduled Tasks (4698/4699/4700/4701) ---

    _SCHEDULED_TASK_EVENT_IDS = {
        "scheduled_task_created": 4698,
        "scheduled_task_deleted": 4699,
        "scheduled_task_enabled": 4700,
        "scheduled_task_disabled": 4701,
    }

    def _render_scheduled_task(self, event: SecurityEvent) -> None:
        """Render Windows 4698/4699/4700/4701 (scheduled task operations)."""
        rng = random.Random()
        auth = event.auth
        host = self._get_host(event)
        task = event.scheduled_task

        event_data = {
            "EventID": self._SCHEDULED_TASK_EVENT_IDS[event.event_type],
            "TimeCreated": event.timestamp,
            "Computer": host.fqdn,
            "Channel": "Security",
            "Level": 0,
            "ExecutionProcessID": auth.reporting_pid or 600,
            "ExecutionThreadID": rng.randint(100, 9999),
            "SubjectUserSid": auth.subject_sid,
            "SubjectUserName": auth.subject_username,
            "SubjectDomainName": _auth_subject_domain(auth, host.netbios_domain),
            "SubjectLogonId": auth.subject_logon_id,
            "TaskName": task.task_name,
            "TaskContent": task.task_content,
        }
        self.emit_event(event_data)

    # --- Phase 5: Group Membership Changes (4728/4729/4732/4733/4756/4757) ---

    _GROUP_MEMBERSHIP_EVENT_IDS = {
        "group_member_added_global": 4728,
        "group_member_removed_global": 4729,
        "group_member_added_local": 4732,
        "group_member_removed_local": 4733,
        "group_member_added_universal": 4756,
        "group_member_removed_universal": 4757,
    }

    def _render_group_membership_change(self, event: SecurityEvent) -> None:
        """Render Windows 4728/4729/4732/4733/4756/4757 (group membership change)."""
        rng = random.Random()
        auth = event.auth
        host = self._get_host(event)
        grp = event.group_membership

        event_data = {
            "EventID": self._GROUP_MEMBERSHIP_EVENT_IDS[event.event_type],
            "TimeCreated": event.timestamp,
            "Computer": host.fqdn,
            "Channel": "Security",
            "Level": 0,
            "ExecutionProcessID": auth.reporting_pid or 600,
            "ExecutionThreadID": rng.randint(100, 9999),
            "MemberName": grp.member_name,
            "MemberSid": grp.member_sid,
            "TargetUserName": grp.group_name,
            "TargetDomainName": grp.group_domain,
            "TargetSid": grp.group_sid,
            "SubjectUserSid": auth.subject_sid,
            "SubjectUserName": auth.subject_username,
            "SubjectDomainName": _auth_subject_domain(auth, host.netbios_domain),
            "SubjectLogonId": auth.subject_logon_id,
            "PrivilegeList": "-",
        }
        self.emit_event(event_data)

    # --- Phase 6: Account Management (4720/4723/4724/4726/4738) ---

    def _render_account_created(self, event: SecurityEvent) -> None:
        """Render Windows 4720 (user account created)."""
        self._render_account_full(event, 4720)

    def _render_account_changed(self, event: SecurityEvent) -> None:
        """Render Windows 4738 (user account changed)."""
        self._render_account_full(event, 4738)

    def _render_account_full(self, event: SecurityEvent, event_id: int) -> None:
        """Render 4720/4738 with full account property fields."""
        rng = random.Random()
        auth = event.auth
        host = self._get_host(event)
        acct = event.account_management

        event_data = {
            "EventID": event_id,
            "TimeCreated": event.timestamp,
            "Computer": host.fqdn,
            "Channel": "Security",
            "Level": 0,
            "ExecutionProcessID": auth.reporting_pid or 600,
            "ExecutionThreadID": rng.randint(100, 9999),
            "TargetUserName": acct.target_username,
            "TargetDomainName": acct.target_domain or host.netbios_domain,
            "TargetSid": acct.target_sid,
            "SubjectUserSid": auth.subject_sid,
            "SubjectUserName": auth.subject_username,
            "SubjectDomainName": _auth_subject_domain(auth, host.netbios_domain),
            "SubjectLogonId": auth.subject_logon_id,
            "SamAccountName": acct.sam_account_name or acct.target_username,
            "OldUacValue": acct.old_uac_value,
            "NewUacValue": acct.new_uac_value,
            "UserAccountControl": acct.user_account_control,
            "PasswordLastSet": acct.password_last_set,
            "PrimaryGroupId": acct.primary_group_id,
        }
        self.emit_event(event_data)

    def _render_account_deleted(self, event: SecurityEvent) -> None:
        """Render Windows 4726 (user account deleted)."""
        self._render_account_simple(event, 4726, include_privs=True)

    def _render_password_reset(self, event: SecurityEvent) -> None:
        """Render Windows 4724 (password reset attempt)."""
        self._render_account_simple(event, 4724, include_privs=False)

    def _render_password_change(self, event: SecurityEvent) -> None:
        """Render Windows 4723 (password change attempt)."""
        self._render_account_simple(event, 4723, include_privs=True)

    def _render_account_simple(
        self, event: SecurityEvent, event_id: int, include_privs: bool
    ) -> None:
        """Render 4723/4724/4726 with minimal account fields."""
        rng = random.Random()
        auth = event.auth
        host = self._get_host(event)
        acct = event.account_management

        event_data = {
            "EventID": event_id,
            "TimeCreated": event.timestamp,
            "Computer": host.fqdn,
            "Channel": "Security",
            "Level": 0,
            "ExecutionProcessID": auth.reporting_pid or 600,
            "ExecutionThreadID": rng.randint(100, 9999),
            "TargetUserName": acct.target_username,
            "TargetDomainName": acct.target_domain or host.netbios_domain,
            "TargetSid": acct.target_sid,
            "SubjectUserSid": auth.subject_sid,
            "SubjectUserName": auth.subject_username,
            "SubjectDomainName": _auth_subject_domain(auth, host.netbios_domain),
            "SubjectLogonId": auth.subject_logon_id,
        }
        if include_privs:
            event_data["PrivilegeList"] = "-"
        self.emit_event(event_data)

    def __init__(
        self,
        format_def: FormatDefinition,
        output_path: Path,
        buffer_size: int = 10000,
        threaded: bool = False,
    ):
        # Detect direct file mode (backward compat for tests)
        self._direct_file_mode = output_path.suffix != ""
        self._base_dir = output_path.parent if self._direct_file_mode else output_path
        self._direct_file_path = output_path if self._direct_file_mode else None
        self._host_writers: dict[str, _SingleHostWriter] = {}
        self._host_writers_lock = Lock()

        super().__init__(format_def, output_path, buffer_size, threaded)
        # Buffer raw event dicts instead of rendered strings
        self._event_dicts: list[dict[str, Any]] = []
        # Per-computer RecordID counters persist across flushes
        self._record_id_counters: dict[str, int] = {}
        self._last_time_created_by_computer: dict[str, datetime] = {}
        self._last_record_time_created_by_computer: dict[str, datetime] = {}
        self._time_collision_count_by_computer: dict[str, int] = {}
        self._current_storyline_origin: bool = False
        self._spool_path: Path | None = None
        self._spool_conn: sqlite3.Connection | None = None
        self._spooled_count: int = 0
        self._spool_sequence: int = 0

    def _get_host_writer(self, host_fqdn: str) -> _SingleHostWriter:
        safe_host_fqdn = sanitize_path_component(host_fqdn)
        writer = self._host_writers.get(safe_host_fqdn)
        if writer is not None:
            return writer
        with self._host_writers_lock:
            writer = self._host_writers.get(safe_host_fqdn)
            if writer is not None:
                return writer
            if safe_host_fqdn and not self._direct_file_mode:
                path = self._base_dir / safe_host_fqdn / "windows_event_security.xml"
            elif self._direct_file_path:
                path = self._direct_file_path
            else:
                path = self._base_dir / "windows_event_security.xml"
            writer = _SingleHostWriter(path, self.buffer_size)
            # Write XML header immediately for new host files
            header = self.format_def.output.header_template
            if header:
                writer.write_header(header)
            self._host_writers[safe_host_fqdn] = writer
            return writer

    def _buffer_event(self, rendered: str) -> None:
        """Override base class to route through default host writer (backward compat for tests)."""
        self._get_host_writer("").write(rendered)

    def emit_event(self, event_data: dict[str, Any]) -> None:
        """Buffer a Windows Event dict for deferred rendering."""
        if getattr(self, "_current_storyline_origin", False):
            event_data["_storyline_origin"] = True
        if self.threaded:
            self._emit_threaded(event_data)
        else:
            with self._file_lock:
                self._event_dicts.append(event_data)
                if len(self._event_dicts) >= self.buffer_size:
                    self._spool_event_dicts_unlocked()

    def _render_event(self, event_data: dict[str, Any]) -> str:
        """Render Windows Event dict to XML format."""
        from xml.sax.saxutils import escape as xml_escape

        # Strip internal metadata keys before rendering
        event_data.pop("_storyline_origin", None)

        if "TimeCreated" in event_data:
            ts = event_data["TimeCreated"]
            if isinstance(ts, datetime):
                event_data["TimeCreated"] = format_windows_system_time(ts, event_data)
        # Escape XML special characters in string values to prevent parse errors
        for key, val in event_data.items():
            if isinstance(val, str) and key != "TimeCreated":
                event_data[key] = xml_escape(val)
        return self._template.render(**event_data)

    def _run(self) -> None:
        """Thread run loop — buffers dicts from queue instead of rendering."""
        win_logger.debug(f"Emitter thread started for {self.format_def.name}")

        while not self._stop_event.is_set():
            try:
                event_data = self._event_queue.get(timeout=0.1)
                with self._file_lock:
                    self._event_dicts.append(event_data)
                    if len(self._event_dicts) >= self.buffer_size:
                        self._spool_event_dicts_unlocked()
                self._event_queue.task_done()
            except Empty:
                if self._flush_barrier.is_set():
                    with self._file_lock:
                        self._spool_event_dicts_unlocked()
                    self._flush_barrier.clear()

        win_logger.debug(f"Emitter thread stopped for {self.format_def.name}")

    def _event_sort_key(self, event: dict[str, Any]) -> str:
        """Return a stable sortable timestamp key for deferred Windows events."""
        ts = event.get("TimeCreated", "")
        if isinstance(ts, datetime):
            return ensure_utc(ts).isoformat()
        return str(ts)

    def _get_spool_conn_unlocked(self) -> sqlite3.Connection:
        """Open the on-disk Windows event spool database while holding _file_lock."""
        if self._spool_conn is None:
            self._base_dir.mkdir(parents=True, exist_ok=True)
            fd, path = tempfile.mkstemp(
                prefix=".windows_event_spool_", suffix=".sqlite3", dir=self._base_dir
            )
            os.close(fd)
            Path(path).unlink(missing_ok=True)
            self._spool_path = Path(path)
            self._spool_conn = sqlite3.connect(path, check_same_thread=False)
            self._spool_conn.execute(
                "CREATE TABLE events ("
                "sort_key TEXT NOT NULL, "
                "sequence INTEGER NOT NULL, "
                "payload TEXT NOT NULL)"
            )
        return self._spool_conn

    def _spool_event_dicts_unlocked(self) -> None:
        """Move buffered event dictionaries to disk to bound emitter memory usage."""
        if not self._event_dicts:
            return
        conn = self._get_spool_conn_unlocked()
        rows = []
        for event in self._event_dicts:
            rows.append((self._event_sort_key(event), self._spool_sequence, _spool_encode(event)))
            self._spool_sequence += 1
        conn.executemany("INSERT INTO events VALUES (?, ?, ?)", rows)
        conn.commit()
        self._spooled_count += len(rows)
        self._event_dicts.clear()

    def _iter_spooled_events_unlocked(self):
        """Yield spooled Windows events in chronological order while holding _file_lock."""
        if self._spool_conn is None:
            return
        cursor = self._spool_conn.execute("SELECT payload FROM events ORDER BY sort_key, sequence")
        for (payload,) in cursor:
            yield _spool_decode(payload)

    def _iter_spooled_rows_unlocked(self, *, ordered: bool = False):
        """Yield row IDs and decoded Windows events while holding _file_lock."""
        if self._spool_conn is None:
            return
        query = "SELECT rowid, payload FROM events"
        if ordered:
            query += " ORDER BY sort_key, sequence"
        cursor = self._spool_conn.execute(query)
        for rowid, payload in cursor:
            yield int(rowid), _spool_decode(payload)

    def _update_spooled_events_unlocked(self, updates: list[tuple[str, str, int]]) -> None:
        """Persist encoded payload and sort-key updates for spooled Windows events."""
        if not updates or self._spool_conn is None:
            return
        self._spool_conn.executemany(
            "UPDATE events SET payload = ?, sort_key = ? WHERE rowid = ?", updates
        )
        self._spool_conn.commit()

    def _delete_spooled_events_unlocked(self, rowids: set[int]) -> None:
        """Delete spooled Windows events by row ID."""
        if not rowids or self._spool_conn is None:
            return
        self._spool_conn.executemany(
            "DELETE FROM events WHERE rowid = ?", [(rowid,) for rowid in rowids]
        )
        self._spool_conn.commit()
        self._spooled_count = max(0, self._spooled_count - len(rowids))

    def _shift_spooled_process_creates_after_visible_parent_unlocked(self) -> None:
        """Prevent spooled Security 4688 children from preceding parent 4688 rows."""
        max_passes = max(1, self._spooled_count)
        for _ in range(max_passes):
            process_create_times: dict[tuple[str, str], datetime] = {}
            for _, event in self._iter_spooled_rows_unlocked():
                if event.get("EventID") != 4688:
                    continue
                ts = event.get("TimeCreated")
                process_pid = str(event.get("NewProcessId") or "").lower()
                computer = str(event.get("Computer", ""))
                if isinstance(ts, datetime) and process_pid and process_pid not in {"0x0", "0x4"}:
                    process_create_times[(computer, process_pid)] = ts

            changed = False
            updates: list[tuple[str, str, int]] = []
            for rowid, event in self._iter_spooled_rows_unlocked():
                if event.get("EventID") != 4688:
                    continue
                ts = event.get("TimeCreated")
                parent_pid = str(event.get("ProcessId") or "").lower()
                computer = str(event.get("Computer", ""))
                if not isinstance(ts, datetime) or parent_pid in {"", "0x0", "0x4", "-"}:
                    continue
                parent_time = process_create_times.get((computer, parent_pid))
                if parent_time is not None and ts <= parent_time:
                    event["TimeCreated"] = parent_time + timedelta(milliseconds=1)
                    updates.append((_spool_encode(event), self._event_sort_key(event), rowid))
                    changed = True
                    if len(updates) >= 1000:
                        self._update_spooled_events_unlocked(updates)
                        updates.clear()
            self._update_spooled_events_unlocked(updates)
            if not changed:
                break

    def _shift_spooled_logoffs_after_dependents_unlocked(self) -> None:
        """Prevent spooled 4634 records from preceding same-session dependents."""
        latest_dependent: dict[tuple[str, str], datetime] = {}
        for _, event in self._iter_spooled_rows_unlocked():
            ts = event.get("TimeCreated")
            if not isinstance(ts, datetime):
                continue
            if event.get("EventID") not in {4688, 4689, 4801}:
                continue
            logon_id = str(event.get("SubjectLogonId") or event.get("TargetLogonId") or "")
            if not logon_id or logon_id in {"0x3e7", "0x3e4", "0x3e5", "-"}:
                continue
            key = (str(event.get("Computer", "")), logon_id)
            latest_dependent[key] = max(ts, latest_dependent.get(key, ts))

        updates: list[tuple[str, str, int]] = []
        for rowid, event in self._iter_spooled_rows_unlocked():
            ts = event.get("TimeCreated")
            if not isinstance(ts, datetime) or event.get("EventID") != 4634:
                continue
            logon_id = str(event.get("TargetLogonId") or event.get("SubjectLogonId") or "")
            key = (str(event.get("Computer", "")), logon_id)
            latest = latest_dependent.get(key)
            if logon_id and latest is not None and ts <= latest:
                event["TimeCreated"] = latest + sample_timing_delta(
                    "windows.logoff_after_rendered_dependents",
                    seed_parts=(key[0], key[1], latest),
                )
                updates.append((_spool_encode(event), self._event_sort_key(event), rowid))
                if len(updates) >= 1000:
                    self._update_spooled_events_unlocked(updates)
                    updates.clear()
        self._update_spooled_events_unlocked(updates)

    def _shift_spooled_process_terminations_after_dependents_unlocked(self) -> None:
        """Keep spooled Security 4689 events after visible child-process lifecycle."""
        latest_child_create: dict[tuple[str, str], datetime] = {}
        for _, event in self._iter_spooled_rows_unlocked():
            ts = event.get("TimeCreated")
            if not isinstance(ts, datetime) or event.get("EventID") != 4688:
                continue
            parent_pid = str(event.get("ProcessId") or "")
            if parent_pid and parent_pid not in {"0x0", "0x4", "-"}:
                key = (str(event.get("Computer", "")), parent_pid.lower())
                latest_child_create[key] = max(ts, latest_child_create.get(key, ts))

        updates: list[tuple[str, str, int]] = []
        for rowid, event in self._iter_spooled_rows_unlocked():
            ts = event.get("TimeCreated")
            if not isinstance(ts, datetime) or event.get("EventID") != 4689:
                continue
            process_pid = str(event.get("ProcessId") or "")
            key = (str(event.get("Computer", "")), process_pid.lower())
            latest = latest_child_create.get(key)
            if process_pid and latest is not None and ts <= latest:
                event["TimeCreated"] = latest + sample_timing_delta(
                    "windows.process_exit_after_visible_child",
                    seed_parts=(key[0], key[1], latest),
                )
                updates.append((_spool_encode(event), self._event_sort_key(event), rowid))
                if len(updates) >= 1000:
                    self._update_spooled_events_unlocked(updates)
                    updates.clear()
        self._update_spooled_events_unlocked(updates)

    def _suppress_spooled_duplicate_lock_unlock_transitions_unlocked(self) -> None:
        """Keep spooled 4800/4801 as a chronological session state machine."""
        session_state: dict[tuple[str, str, str], str] = {}
        dropped_rowids: set[int] = set()
        dropped_unlocks: list[tuple[str, str, str, datetime]] = []

        for rowid, event in self._iter_spooled_rows_unlocked(ordered=True):
            event_id = event.get("EventID")
            if event_id not in {4800, 4801}:
                continue
            ts = event.get("TimeCreated")
            if not isinstance(ts, datetime):
                continue
            computer = str(event.get("Computer", ""))
            logon_id = str(event.get("TargetLogonId") or "")
            session_id = str(event.get("SessionId") or "")
            if not computer or not logon_id:
                continue
            key = (computer, logon_id, session_id)
            next_state = "locked" if event_id == 4800 else "unlocked"
            if session_state.get(key) == next_state:
                dropped_rowids.add(rowid)
                if event_id == 4801:
                    dropped_unlocks.append((*key, ensure_utc(ts)))
                continue
            session_state[key] = next_state

        for rowid, event in self._iter_spooled_rows_unlocked(ordered=True):
            if rowid in dropped_rowids or event.get("EventID") != 4624:
                continue
            if str(event.get("LogonType") or "") != "7":
                continue
            ts = event.get("TimeCreated")
            if not isinstance(ts, datetime):
                continue
            computer = str(event.get("Computer", ""))
            logon_id = str(event.get("TargetLogonId") or "")
            for drop_computer, drop_logon_id, _session_id, unlock_ts in dropped_unlocks:
                delta = ensure_utc(ts) - unlock_ts
                if (
                    computer == drop_computer
                    and logon_id == drop_logon_id
                    and timedelta(0) <= delta <= timedelta(seconds=2)
                ):
                    dropped_rowids.add(rowid)
                    break

        self._delete_spooled_events_unlocked(dropped_rowids)

    def _cleanup_spool_unlocked(self) -> None:
        """Remove the temporary Windows event spool database."""
        if self._spool_conn is not None:
            self._spool_conn.close()
            self._spool_conn = None
        if self._spool_path is not None:
            self._spool_path.unlink(missing_ok=True)
            self._spool_path = None
        self._spooled_count = 0

    def _flush_unlocked(self) -> None:
        """Sort events, assign RecordIDs, render, and write to per-host files."""
        if not self._event_dicts and self._spooled_count == 0:
            return

        if self._spooled_count:
            self._spool_event_dicts_unlocked()
            self._shift_spooled_process_creates_after_visible_parent_unlocked()
            self._shift_spooled_process_terminations_after_dependents_unlocked()
            self._shift_spooled_logoffs_after_dependents_unlocked()
            self._suppress_spooled_duplicate_lock_unlock_transitions_unlocked()
            events = self._iter_spooled_events_unlocked()
        else:
            self._shift_process_creates_after_visible_parent()
            self._shift_process_terminations_after_dependents()
            self._shift_logoffs_after_dependents()
            self._suppress_duplicate_lock_unlock_transitions()

            def _sort_key(event: dict) -> Any:
                ts = event.get("TimeCreated", "")
                if isinstance(ts, datetime):
                    return ensure_utc(ts)
                return ts

            self._event_dicts.sort(key=_sort_key)
            events = iter(self._event_dicts)

        # Assign per-computer EventRecordIDs in sorted order
        for sequence, event in enumerate(events):
            _normalize_windows_time_created(
                event,
                self._last_time_created_by_computer,
                self._time_collision_count_by_computer,
                sequence,
                "windows_time_created",
            )
            computer = sanitize_path_component(event.get("Computer", ""))
            counter_key = computer.split(".")[0] if "." in computer else computer
            if counter_key not in self._record_id_counters:
                rng = random.Random(f"erid_{counter_key}")
                key_lower = counter_key.lower()
                if "dc" in key_lower:
                    self._record_id_counters[counter_key] = rng.randint(5_000_000, 15_000_000)
                elif any(
                    x in key_lower for x in ("srv", "server", "web", "file", "db", "mail", "exch")
                ):
                    self._record_id_counters[counter_key] = rng.randint(50_000, 550_000)
                else:
                    self._record_id_counters[counter_key] = rng.randint(5_000, 55_000)
            if event.get("EventID") == 1102:
                reset_rng = random.Random(f"erid_reset_{counter_key}_{sequence}")
                self._record_id_counters[counter_key] = reset_rng.randint(0, 3) + 1
                event["EventRecordID"] = self._record_id_counters[counter_key]
            else:
                gap_rng = random.Random(
                    f"erid_gap_{counter_key}_{self._record_id_counters[counter_key]}"
                )
                if gap_rng.random() < 0.15:
                    self._record_id_counters[counter_key] += gap_rng.randint(2, 8)
                elif gap_rng.random() < 0.03:
                    self._record_id_counters[counter_key] += gap_rng.randint(20, 200)
                else:
                    self._record_id_counters[counter_key] += 1
                event["EventRecordID"] = self._record_id_counters[counter_key]

            normalized_time = event.get("TimeCreated")
            if isinstance(normalized_time, datetime):
                current_time = ensure_utc(normalized_time)
                previous_record_time = self._last_record_time_created_by_computer.get(counter_key)
                if previous_record_time is not None and current_time <= previous_record_time:
                    current_time = previous_record_time + timedelta(microseconds=1)
                    event["TimeCreated"] = current_time
                self._last_record_time_created_by_computer[counter_key] = current_time

            rendered = self._render_event(event)
            host_fqdn = event.get("Computer", "")
            self._get_host_writer(host_fqdn).write(rendered)

        self._event_dicts.clear()
        self._cleanup_spool_unlocked()

    def _shift_logoffs_after_dependents(self) -> None:
        """Prevent visible 4634 records from preceding same-session dependents.

        Sysmon and EDR sources render small source-native collection offsets after
        canonical process lifecycle events. A visible Security logoff needs to clear
        that offset window, not just the Security 4688 timestamp.
        """
        latest_dependent: dict[tuple[str, str], datetime] = {}
        logoffs: list[tuple[tuple[str, str], dict[str, Any]]] = []
        for event in self._event_dicts:
            ts = event.get("TimeCreated")
            if not isinstance(ts, datetime):
                continue
            event_id = event.get("EventID")
            computer = str(event.get("Computer", ""))
            if event_id == 4634:
                logon_id = str(event.get("TargetLogonId") or event.get("SubjectLogonId") or "")
                if logon_id:
                    logoffs.append(((computer, logon_id), event))
                continue
            if event_id not in {4688, 4689, 4801}:
                continue
            logon_id = str(event.get("SubjectLogonId") or event.get("TargetLogonId") or "")
            if not logon_id or logon_id in {"0x3e7", "0x3e4", "0x3e5", "-"}:
                continue
            key = (computer, logon_id)
            latest_dependent[key] = max(ts, latest_dependent.get(key, ts))

        for key, event in logoffs:
            ts = event.get("TimeCreated")
            latest = latest_dependent.get(key)
            if isinstance(ts, datetime) and latest is not None and ts <= latest:
                event["TimeCreated"] = latest + sample_timing_delta(
                    "windows.logoff_after_rendered_dependents",
                    seed_parts=(key[0], key[1], latest),
                )

    def _suppress_duplicate_lock_unlock_transitions(self) -> None:
        """Keep 4800/4801 as a chronological session state machine.

        Baseline code can schedule a future unlock before an earlier storyline
        transition is generated. Final Security rendering has the complete
        chronological view, so it owns suppression of duplicate visible states.
        """

        def _sort_key(index_and_event: tuple[int, dict[str, Any]]) -> tuple[datetime, int]:
            index, event = index_and_event
            ts = event.get("TimeCreated")
            if isinstance(ts, datetime):
                return (ensure_utc(ts), index)
            return (datetime.max.replace(tzinfo=UTC), index)

        session_state: dict[tuple[str, str, str], str] = {}
        dropped_indexes: set[int] = set()
        dropped_unlocks: list[tuple[str, str, str, datetime]] = []

        for index, event in sorted(enumerate(self._event_dicts), key=_sort_key):
            event_id = event.get("EventID")
            if event_id not in {4800, 4801}:
                continue
            ts = event.get("TimeCreated")
            if not isinstance(ts, datetime):
                continue
            computer = str(event.get("Computer", ""))
            logon_id = str(event.get("TargetLogonId") or "")
            session_id = str(event.get("SessionId") or "")
            if not computer or not logon_id:
                continue
            key = (computer, logon_id, session_id)
            next_state = "locked" if event_id == 4800 else "unlocked"
            if session_state.get(key) == next_state:
                dropped_indexes.add(index)
                if event_id == 4801:
                    dropped_unlocks.append((*key, ensure_utc(ts)))
                continue
            session_state[key] = next_state

        for index, event in enumerate(self._event_dicts):
            if index in dropped_indexes or event.get("EventID") != 4624:
                continue
            if str(event.get("LogonType") or "") != "7":
                continue
            ts = event.get("TimeCreated")
            if not isinstance(ts, datetime):
                continue
            computer = str(event.get("Computer", ""))
            logon_id = str(event.get("TargetLogonId") or "")
            for drop_computer, drop_logon_id, _session_id, unlock_ts in dropped_unlocks:
                delta = ensure_utc(ts) - unlock_ts
                if (
                    computer == drop_computer
                    and logon_id == drop_logon_id
                    and timedelta(0) <= delta <= timedelta(seconds=2)
                ):
                    dropped_indexes.add(index)
                    break

        if dropped_indexes:
            self._event_dicts = [
                event
                for index, event in enumerate(self._event_dicts)
                if index not in dropped_indexes
            ]

    def _shift_process_creates_after_visible_parent(self) -> None:
        """Prevent visible Security 4688 children from preceding parent 4688 rows."""
        changed = True
        while changed:
            changed = False
            process_create_times: dict[tuple[str, str], datetime] = {}
            for event in self._event_dicts:
                if event.get("EventID") != 4688:
                    continue
                ts = event.get("TimeCreated")
                process_pid = str(event.get("NewProcessId") or "").lower()
                computer = str(event.get("Computer", ""))
                if isinstance(ts, datetime) and process_pid and process_pid not in {"0x0", "0x4"}:
                    process_create_times[(computer, process_pid)] = ts

            for event in self._event_dicts:
                if event.get("EventID") != 4688:
                    continue
                ts = event.get("TimeCreated")
                parent_pid = str(event.get("ProcessId") or "").lower()
                computer = str(event.get("Computer", ""))
                if not isinstance(ts, datetime) or parent_pid in {"", "0x0", "0x4", "-"}:
                    continue
                parent_time = process_create_times.get((computer, parent_pid))
                if parent_time is not None and ts <= parent_time:
                    event["TimeCreated"] = parent_time + timedelta(milliseconds=1)
                    changed = True

    def _shift_process_terminations_after_dependents(self) -> None:
        """Keep Security 4689 aligned with visible child-process lifecycle.

        Sysmon Event 5 already moves after visible same-process follow-on
        telemetry. Security 4689 needs the same source-native lifecycle truth
        for parent processes that visibly spawn children later in the buffer.
        """
        latest_child_create: dict[tuple[str, str], datetime] = {}
        terminations: list[tuple[tuple[str, str], dict[str, Any]]] = []

        for event in self._event_dicts:
            ts = event.get("TimeCreated")
            if not isinstance(ts, datetime):
                continue
            computer = str(event.get("Computer", ""))
            event_id = event.get("EventID")
            if event_id == 4688:
                parent_pid = str(event.get("ProcessId") or "")
                if parent_pid and parent_pid not in {"0x0", "0x4", "-"}:
                    key = (computer, parent_pid.lower())
                    latest_child_create[key] = max(ts, latest_child_create.get(key, ts))
            elif event_id == 4689:
                process_pid = str(event.get("ProcessId") or "")
                if process_pid:
                    terminations.append(((computer, process_pid.lower()), event))

        for key, event in terminations:
            ts = event.get("TimeCreated")
            latest = latest_child_create.get(key)
            if isinstance(ts, datetime) and latest is not None and ts <= latest:
                event["TimeCreated"] = latest + sample_timing_delta(
                    "windows.process_exit_after_visible_child",
                    seed_parts=(key[0], key[1], latest),
                )

    def flush(self, *, force: bool = False) -> None:
        """Flush host writers and spill deferred Windows events to bounded disk storage."""
        with self._file_lock:
            if force:
                self._flush_unlocked()
            else:
                self._spool_event_dicts_unlocked()
        with self._host_writers_lock:
            for writer in self._host_writers.values():
                writer.flush()

    def close(self) -> None:
        """Close emitter — flush and write XML footers for each host file."""
        if self.threaded:
            self.stop_thread()
        else:
            self.flush(force=True)
        if self.threaded:
            self.flush(force=True)
        # Write XML footer for each host file that has events
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
