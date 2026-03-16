"""Lightweight statistical anomaly detection for background events.

Flags events that are anomalous-but-benign (realistic noise for hunters).
Used by Dimension 3 (Background Noise Realism) to score Organic Anomaly Rate.
"""

from collections import Counter
from typing import Any

from evidenceforge.evaluation.dimensions.temporal import _extract_username
from evidenceforge.evaluation.parsers import ParsedRecord
from evidenceforge.models.scenario import Scenario
from evidenceforge.validation.schema import BUILTIN_ACCOUNTS

# Failed operation indicators
_FAILED_EVENT_IDS = {4625}  # Windows failed logon
_FAILED_HTTP_CODES = set(range(400, 600))
_FAILED_SYSLOG_KEYWORDS = ["failed", "denied", "error", "invalid", "unauthorized"]


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
    system_accounts = {a.lower() for a in BUILTIN_ACCOUNTS}

    total = 0
    anomalous = 0

    for format_name, record_list in records.items():
        for record in record_list:
            if record.parse_errors:
                continue
            total += 1

            is_anomalous = (
                _is_off_hours(record, persona_hours)
                or _is_failed_operation(record, format_name)
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
        "ssh": 22, "http": 80, "https": 443, "ftp": 21, "smtp": 25,
        "dns": 53, "rdp": 3389, "smb": 445, "mysql": 3306, "postgres": 5432,
        "iis": 80, "nginx": 80, "apache": 80, "sql server": 1433,
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


def _is_off_hours(record: ParsedRecord, persona_hours: dict[str, list[int]]) -> bool:
    """Check if event is outside user's persona work hours."""
    if not record.timestamp:
        return False
    user = _extract_username(record)
    if not user or user not in persona_hours:
        return False
    hours = persona_hours[user]
    if not hours:
        return False
    return record.timestamp.hour not in hours


def _is_failed_operation(record: ParsedRecord, fmt: str) -> bool:
    """Check if event represents a failed operation."""
    f = record.fields
    if fmt == "windows_event_security":
        return f.get("EventID") in _FAILED_EVENT_IDS
    if fmt == "web_access":
        code = f.get("status_code")
        return isinstance(code, int) and code in _FAILED_HTTP_CODES
    if fmt == "syslog":
        msg = f.get("message", "").lower()
        return any(kw in msg for kw in _FAILED_SYSLOG_KEYWORDS)
    return False


def _is_rare_process(
    record: ParsedRecord, fmt: str, process_freq: Counter,
) -> bool:
    """Check if event involves a rarely-seen process/command."""
    proc = _extract_process_key(record, fmt)
    if not proc or not process_freq:
        return False

    # Bottom 5% by frequency = rare
    total_procs = sum(process_freq.values())
    if total_procs == 0:
        return False

    threshold = max(1, total_procs * 0.05 / len(process_freq))
    return process_freq[proc] <= threshold


def _is_unexpected_port(
    record: ParsedRecord, fmt: str, service_ports: set[int],
) -> bool:
    """Check if connection goes to a port not associated with declared services."""
    if fmt != "zeek_conn" or not service_ports:
        return False

    resp_port = record.fields.get("id.resp_p")
    if not isinstance(resp_port, int):
        return False

    # Common always-expected ports
    always_ok = {80, 443, 53, 22}
    if resp_port in always_ok or resp_port in service_ports:
        return False

    # High ports (ephemeral) are not unexpected
    if resp_port > 1024:
        return False

    return True
