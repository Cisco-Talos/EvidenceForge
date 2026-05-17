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

"""Snare-over-syslog sidecar rendering for Windows Event Log emitters."""

from __future__ import annotations

import re
from datetime import datetime
from typing import Any

from evidenceforge.generation.emitters.syslog_family import (
    render_rfc3164_syslog,
    syslog_priority,
)
from evidenceforge.utils.time import ensure_utc

WINDOWS_SECURITY_SNARE_FILENAME = "windows_event_security_snare.log"
WINDOWS_SYSMON_SNARE_FILENAME = "windows_event_sysmon_snare.log"

_WINDOWS_SECURITY_PROVIDER = "Microsoft-Windows-Security-Auditing"
_WINDOWS_EVENTLOG_PROVIDER = "Microsoft-Windows-Eventlog"
_SYSMON_PROVIDER = "Microsoft-Windows-Sysmon"
_SNARE_MARKER = "MSWinEventLog"
_WHITESPACE_RE = re.compile(r"[\t\r\n]+")
_DOUBLE_PIPE_RE = re.compile(r"\|\|")

_SECURITY_FAILURE_EVENTS = frozenset({4625, 4771})
_SECURITY_SUMMARIES: dict[int, str] = {
    1102: "The audit log was cleared.",
    4624: "An account was successfully logged on.",
    4625: "An account failed to log on.",
    4634: "An account was logged off.",
    4648: "A logon was attempted using explicit credentials.",
    4672: "Special privileges assigned to new logon.",
    4688: "A new process has been created.",
    4689: "A process has exited.",
    4697: "A service was installed in the system.",
    4698: "A scheduled task was created.",
    4699: "A scheduled task was deleted.",
    4700: "A scheduled task was enabled.",
    4701: "A scheduled task was disabled.",
    4720: "A user account was created.",
    4723: "An attempt was made to change an account's password.",
    4724: "An attempt was made to reset an account's password.",
    4726: "A user account was deleted.",
    4728: "A member was added to a security-enabled global group.",
    4729: "A member was removed from a security-enabled global group.",
    4732: "A member was added to a security-enabled local group.",
    4733: "A member was removed from a security-enabled local group.",
    4738: "A user account was changed.",
    4756: "A member was added to a security-enabled universal group.",
    4757: "A member was removed from a security-enabled universal group.",
    4768: "A Kerberos authentication ticket was requested.",
    4769: "A Kerberos service ticket was requested.",
    4770: "A Kerberos service ticket was renewed.",
    4771: "Kerberos pre-authentication failed.",
    4776: "The computer attempted to validate credentials for an account.",
    4800: "The workstation was locked.",
    4801: "The workstation was unlocked.",
    5156: "The Windows Filtering Platform allowed a connection.",
}
_SECURITY_TASKS: dict[int, str] = {
    4624: "Logon",
    4625: "Logon",
    4634: "Logoff",
    4648: "Logon",
    4672: "Special Logon",
    4688: "Process Creation",
    4689: "Process Termination",
    4768: "Kerberos Authentication Service",
    4769: "Kerberos Service Ticket Operations",
    4770: "Kerberos Service Ticket Operations",
    4771: "Kerberos Authentication Service",
    4776: "Credential Validation",
    4800: "Other Logon/Logoff Events",
    4801: "Other Logon/Logoff Events",
    5156: "Filtering Platform Connection",
}
_SYSMON_TASKS: dict[int, str] = {
    1: "Process Create",
    3: "Network connection detected",
    5: "Process terminated",
    7: "Image loaded",
    8: "CreateRemoteThread detected",
    10: "Process accessed",
    11: "File created",
    12: "Registry object added or deleted",
    13: "Registry value set",
    22: "Dns query",
}

_SECURITY_FIELD_LABELS: dict[str, str] = {
    "SubjectUserSid": "Security ID",
    "TargetUserSid": "Security ID",
    "SubjectUserName": "Account Name",
    "TargetUserName": "Account Name",
    "SubjectDomainName": "Account Domain",
    "TargetDomainName": "Account Domain",
    "SubjectLogonId": "Logon ID",
    "TargetLogonId": "Logon ID",
    "NewProcessId": "Process ID",
    "ProcessId": "Process ID",
    "NewProcessName": "Process Name",
    "ProcessName": "Process Name",
    "Status": "Exit Status",
    "SourcePort": "SourcePort",
    "DestinationPort": "DestinationPort",
    "SourceAddress": "SourceIp",
    "DestAddress": "DestinationIp",
}
_INTERNAL_FIELDS = frozenset({"_storyline_origin"})
_COMMON_SYSTEM_FIELDS = frozenset(
    {
        "EventID",
        "TimeCreated",
        "Computer",
        "Channel",
        "Level",
        "EventRecordID",
        "ExecutionProcessID",
        "ExecutionThreadID",
        "Provider",
    }
)


def render_windows_security_snare_syslog(event_data: dict[str, Any]) -> str:
    """Render a Windows Security event dict as an RFC3164 Snare syslog row."""
    event_id = _event_id(event_data)
    timestamp = _timestamp(event_data)
    computer = _clean_field(event_data.get("Computer") or "windows-host")
    provider = _WINDOWS_EVENTLOG_PROVIDER if event_id == 1102 else _WINDOWS_SECURITY_PROVIDER
    payload = _snare_payload(
        event_data=event_data,
        computer=computer,
        channel="Security",
        provider=provider,
        username=_event_username(event_data),
        logtype=_security_logtype(event_id),
        category=_SECURITY_TASKS.get(event_id, "Audit"),
        summary=_SECURITY_SUMMARIES.get(event_id, f"Windows Security event {event_id}."),
        timestamp=timestamp,
        field_labels=_SECURITY_FIELD_LABELS,
    )
    severity = 5 if event_id in _SECURITY_FAILURE_EVENTS else 6
    return render_rfc3164_syslog(
        pri=syslog_priority(10, severity),
        timestamp=timestamp,
        hostname=computer,
        app_name="",
        message=payload,
        include_app_tag=False,
    )


def render_windows_sysmon_snare_syslog(event_data: dict[str, Any]) -> str:
    """Render a Windows Sysmon event dict as an RFC3164 Snare syslog row."""
    event_id = _event_id(event_data)
    timestamp = _timestamp(event_data)
    computer = _clean_field(event_data.get("Computer") or "windows-host")
    summary = _SYSMON_TASKS.get(event_id, f"Sysmon event {event_id}.")
    payload = _snare_payload(
        event_data={**event_data, "UtcTime": _sysmon_utc_time(timestamp)},
        computer=computer,
        channel="Microsoft-Windows-Sysmon/Operational",
        provider=_SYSMON_PROVIDER,
        username=_event_username(event_data),
        logtype="Information",
        category=summary,
        summary=summary,
        timestamp=timestamp,
        field_labels={},
    )
    return render_rfc3164_syslog(
        pri=syslog_priority(1, 6),
        timestamp=timestamp,
        hostname=computer,
        app_name="",
        message=payload,
        include_app_tag=False,
    )


def _snare_payload(
    *,
    event_data: dict[str, Any],
    computer: str,
    channel: str,
    provider: str,
    username: str,
    logtype: str,
    category: str,
    summary: str,
    timestamp: datetime,
    field_labels: dict[str, str],
) -> str:
    expanded = _expanded_event_data(event_data, field_labels)
    full_data = f"{summary}:  {expanded}" if expanded else summary
    columns = (
        computer,
        _SNARE_MARKER,
        str(_criticality(logtype)),
        channel,
        str(event_data.get("EventRecordID") or 0),
        _snare_datetime(timestamp),
        str(_event_id(event_data)),
        provider,
        username,
        "N/A",
        logtype,
        computer,
        category,
        full_data,
    )
    return "\t".join(_clean_field(value) for value in columns)


def _expanded_event_data(event_data: dict[str, Any], field_labels: dict[str, str]) -> str:
    pieces: list[str] = []
    for key, value in event_data.items():
        if key in _COMMON_SYSTEM_FIELDS or key in _INTERNAL_FIELDS or value in (None, ""):
            continue
        label = field_labels.get(key, key)
        pieces.append(f"{label}: {_clean_field(value)}")
    if not pieces:
        return ""
    return "  ".join(pieces) + "  "


def _event_id(event_data: dict[str, Any]) -> int:
    try:
        return int(event_data.get("EventID", 0))
    except (TypeError, ValueError):
        return 0


def _timestamp(event_data: dict[str, Any]) -> datetime:
    value = event_data.get("TimeCreated")
    if not isinstance(value, datetime):
        raise ValueError("Windows Snare sidecar rendering requires datetime TimeCreated")
    return ensure_utc(value)


def _snare_datetime(timestamp: datetime) -> str:
    return ensure_utc(timestamp).strftime("%a %b %d %H:%M:%S %Y")


def _sysmon_utc_time(timestamp: datetime) -> str:
    return ensure_utc(timestamp).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]


def _event_username(event_data: dict[str, Any]) -> str:
    for field in (
        "TargetUserName",
        "SubjectUserName",
        "User",
        "SourceUser",
        "TargetUser",
        "AccountName",
    ):
        value = event_data.get(field)
        if value not in (None, ""):
            return _clean_field(value)
    return "N/A"


def _security_logtype(event_id: int) -> str:
    return "Failure Audit" if event_id in _SECURITY_FAILURE_EVENTS else "Success Audit"


def _criticality(logtype: str) -> int:
    if logtype in {"Error", "Failure Audit"}:
        return 2
    if logtype == "Warning":
        return 1
    return 0


def _clean_field(value: Any) -> str:
    text = "" if value is None else str(value)
    text = _WHITESPACE_RE.sub(" ", text).strip()
    return _DOUBLE_PIPE_RE.sub("|", text)
