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

"""Lightweight statistical anomaly detection for background events.

Flags events that are anomalous-but-benign (realistic noise for hunters).
Used by Dimension 3 (Background Noise Realism) to score Organic Anomaly Rate.
"""

import random
from collections import Counter
from datetime import UTC
from zoneinfo import ZoneInfo

from evidenceforge.evaluation.dimensions.temporal import _extract_username
from evidenceforge.evaluation.parsers import ParsedRecord
from evidenceforge.models.scenario import Scenario

# Failed operation indicators
_FAILED_EVENT_IDS = {4625}  # Failed logon (flagged only in burst context)
_FAILED_HTTP_CODES = set(range(400, 600))
# Specific failure patterns (not bare keywords — avoids false positives on benign logs)
_FAILED_SYSLOG_PATTERNS = [
    "authentication failure",
    "failed password",
    "permission denied",
    "access denied",
    "invalid user",
    "connection refused",
    "unauthorized access",
    "login failed",
]

# Common application ports that are expected even if not in scenario services
_COMMON_APP_PORTS = {
    21,
    22,
    25,
    53,
    80,
    88,
    123,
    135,
    143,
    443,
    445,  # Standard services + Kerberos
    389,
    464,
    587,
    636,
    993,
    995,  # LDAP, kpasswd, LDAPS, mail
    1433,
    3306,
    3389,
    5432,
    5353,  # Database/RDP/mDNS
    8080,
    8443,
    3128,
    8888,
    9090,  # Proxy/dev ports
}


def _build_failed_logon_bursts(
    records: dict[str, list[ParsedRecord]],
) -> set[tuple[str, int]]:
    """Identify (user, 10min_bucket) pairs with 3+ failed logons.

    Isolated failed logons are normal; bursts suggest brute-force and are anomalous.
    """
    bucket_counts: Counter[tuple[str, int]] = Counter()
    win_records = records.get("windows_event_security", [])
    for rec in win_records:
        if rec.fields.get("EventID") != 4625 or rec.timestamp is None:
            continue
        user = rec.fields.get("TargetUserName", "")
        if not user or user == "-":
            continue
        bucket = int(rec.timestamp.timestamp()) // 600  # 10-minute buckets
        bucket_counts[(user.lower(), bucket)] += 1

    return {key for key, count in bucket_counts.items() if count >= 3}


def detect_anomalies(
    records: dict[str, list[ParsedRecord]],
    scenario: Scenario,
) -> tuple[int, int]:
    """Detect anomalous events in background noise.

    Returns:
        (anomalous_count, total_checked) — both ints.
    """
    # Build context
    persona_hours = _build_persona_hours(scenario)
    service_ports = _build_service_ports(scenario)
    process_freq = _build_process_frequency(records)
    failed_logon_bursts = _build_failed_logon_bursts(records)

    # Resolve scenario timezone for off-hours comparison
    tz_name = "UTC"
    if scenario.environment.timezone and scenario.environment.timezone.default:
        tz_name = scenario.environment.timezone.default
    try:
        scenario_tz = ZoneInfo(tz_name)
    except (KeyError, ValueError):
        scenario_tz = UTC

    # Collect all valid records, then sample for efficiency
    all_valid: list[tuple[str, ParsedRecord]] = []
    for format_name, record_list in records.items():
        for record in record_list:
            if not record.parse_errors:
                all_valid.append((format_name, record))

    # Sample up to 5,000 records (statistically sufficient for rate estimation)
    max_sample = 5000
    if len(all_valid) > max_sample:
        sample = random.sample(all_valid, max_sample)
    else:
        sample = all_valid

    total = len(sample)
    anomalous = 0

    for format_name, record in sample:
        is_anomalous = (
            _is_off_hours(record, persona_hours, scenario_tz)
            or _is_failed_operation(record, format_name, failed_logon_bursts)
            or _is_rare_process(record, format_name, process_freq)
            or _is_unexpected_port(record, format_name, service_ports)
        )
        if is_anomalous:
            anomalous += 1

    return anomalous, total


def _build_persona_hours(scenario: Scenario) -> dict[str, list[int]]:
    """Map username → list of work hours from persona."""
    result: dict[str, list[int]] = {}
    persona_map = {}
    if scenario.personas:
        persona_map = {p.name: p for p in scenario.personas}

    for user in scenario.environment.users:
        if user.persona and user.persona in persona_map:
            persona = persona_map[user.persona]
            if persona.work_hours_parsed:
                result[user.username.lower()] = persona.work_hours_parsed.get("hours", [])

    return result


def _build_service_ports(scenario: Scenario) -> set[int]:
    """Collect all declared service ports from scenario systems."""
    # Common service-to-port mappings
    service_ports: set[int] = set()
    port_map = {
        "ssh": 22,
        "http": 80,
        "https": 443,
        "ftp": 21,
        "smtp": 25,
        "dns": 53,
        "rdp": 3389,
        "smb": 445,
        "mysql": 3306,
        "postgres": 5432,
        "iis": 80,
        "nginx": 80,
        "apache": 80,
        "sql server": 1433,
    }
    for system in scenario.environment.systems:
        for svc in system.services:
            port = port_map.get(svc.lower())
            if port:
                service_ports.add(port)
    return service_ports


def _build_process_frequency(records: dict[str, list[ParsedRecord]]) -> Counter:
    """Count process/command frequencies across all records."""
    freq: Counter = Counter()
    for fmt, record_list in records.items():
        for rec in record_list:
            proc = _extract_process_key(rec, fmt)
            if proc:
                freq[proc] += 1
    return freq


def _extract_process_key(record: ParsedRecord, fmt: str) -> str | None:
    """Extract a process/command identifier from a record."""
    f = record.fields
    if fmt == "windows_event_security" and f.get("EventID") == 4688:
        return f.get("NewProcessName", "")
    if fmt == "bash_history":
        cmd = f.get("command", "")
        return cmd.split()[0] if cmd else None
    if fmt == "ecar" and f.get("object") == "PROCESS":
        return f.get("image_path", "")
    return None


def _is_off_hours(
    record: ParsedRecord, persona_hours: dict[str, list[int]], scenario_tz=None
) -> bool:
    """Check if event is in deep off-hours for the user.

    Only flags events during truly unusual hours (midnight-5am local) for users
    whose persona doesn't include those hours. Events just outside normal work
    hours (e.g., 6-8am, 6-10pm) are common in real environments and not anomalous.

    Converts timestamp to scenario timezone since persona work hours are in local time.
    """
    if not record.timestamp:
        return False
    user = _extract_username(record)
    if not user or user not in persona_hours:
        return False
    hours = persona_hours[user]
    if not hours:
        return False
    ts = record.timestamp
    if scenario_tz is not None:
        ts = ts.astimezone(scenario_tz)
    local_hour = ts.hour
    # Only flag deep off-hours (midnight-5am) not covered by work hours
    deep_off_hours = {0, 1, 2, 3, 4, 5}
    return local_hour in deep_off_hours and local_hour not in hours


def _is_failed_operation(
    record: ParsedRecord,
    fmt: str,
    failed_logon_bursts: set[tuple[str, int]] | None = None,
) -> bool:
    """Check if event represents a failed operation.

    For Windows 4625, only flags events that are part of a burst (3+ in 10 min).
    Isolated failed logons are normal noise, not anomalous.
    """
    f = record.fields
    if fmt == "windows_event_security":
        eid = f.get("EventID")
        if eid == 4625 and failed_logon_bursts and record.timestamp:
            user = f.get("TargetUserName", "")
            if user and user != "-":
                bucket = int(record.timestamp.timestamp()) // 600
                return (user.lower(), bucket) in failed_logon_bursts
        return False
    if fmt == "web_access":
        code = f.get("status_code")
        return isinstance(code, int) and code in _FAILED_HTTP_CODES
    if fmt == "syslog":
        msg = f.get("message", "").lower()
        return any(pattern in msg for pattern in _FAILED_SYSLOG_PATTERNS)
    return False


def _is_rare_process(
    record: ParsedRecord,
    fmt: str,
    process_freq: Counter,
) -> bool:
    """Check if event involves a rarely-seen process/command."""
    proc = _extract_process_key(record, fmt)
    if not proc or not process_freq:
        return False

    # Bottom 3% by frequency = rare
    total_procs = sum(process_freq.values())
    if total_procs == 0:
        return False

    threshold = max(1, total_procs * 0.03 / len(process_freq))
    return process_freq[proc] <= threshold


def _is_unexpected_port(
    record: ParsedRecord,
    fmt: str,
    service_ports: set[int],
) -> bool:
    """Check if connection goes to a port not associated with declared services."""
    if fmt != "zeek_conn":
        return False

    resp_port = record.fields.get("id.resp_p")
    if not isinstance(resp_port, int):
        return False

    # Common always-expected ports
    if resp_port in _COMMON_APP_PORTS or resp_port in service_ports:
        return False

    # Only well-known ports (1-1023) not in known sets are suspicious.
    # Registered/high ports are common for legitimate applications.
    if resp_port <= 1023:
        return True
    return False
