#!/usr/bin/env python3
"""Probe rendered EvidenceForge output for cross-source realism invariants.

This utility is intentionally read-only with respect to generated evidence. It
parses one output directory and writes a deterministic JSON assessment either
to stdout or to ``--output``. It does not participate in generation.
"""

from __future__ import annotations

import argparse
import json
import math
import re
import sys
import xml.etree.ElementTree as ET
from collections import Counter, defaultdict
from dataclasses import asdict, dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

from evidenceforge.generation.activity.dll_load_profiles import (
    module_is_compatible_with_process,
)

_ZEEK_UID_FILES = {"dns", "http", "ntp", "smtp", "ssl"}
_TUPLE_FIELDS = ("id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p")
_WINDOW_TOLERANCE_SECONDS = 1.0
_WINDOWS_RECORD_ID_BURST_ALLOWANCE = 64
_WINDOWS_RECORD_ID_CONSERVATIVE_PEAK_RATE = 2_000.0
_RFC5424_SSHD_RE = re.compile(
    r"^<\d+>1\s+(?P<timestamp>\S+)\s+(?P<host>\S+)\s+sshd\s+(?P<pid>\d+)\s"
)
_ASA_OUTBOUND_CONNECTION_BUILD_RE = re.compile(
    r"%ASA-6-30201[35]: Built outbound (?:TCP|UDP) connection (?P<connection_id>\d+) "
    r"for \S+:(?P<local_ip>[^/\s]+)/(?P<local_port>\d+)"
)
_ASA_CONNECTION_TEARDOWN_RE = re.compile(
    r"%ASA-6-30201[46]: Teardown (?:TCP|UDP) connection (?P<connection_id>\d+)"
)
_ASA_DYNAMIC_XLATE_BUILD_RE = re.compile(
    r"%ASA-6-305011: Built dynamic (?:TCP|UDP) translation from "
    r"\S+:(?P<local_ip>[^/\s]+)/(?P<local_port>\d+) to "
    r"\S+:(?P<global_ip>[^/\s]+)/(?P<global_port>\d+)"
)
_ASA_DYNAMIC_XLATE_TEARDOWN_RE = re.compile(
    r"%ASA-6-305012: Teardown dynamic (?:TCP|UDP) translation from "
    r"\S+:(?P<local_ip>[^/\s]+)/(?P<local_port>\d+) to "
    r"\S+:(?P<global_ip>[^/\s]+)/(?P<global_port>\d+)"
)
_ASA_INBOUND_STATIC_BUILD_RE = re.compile(
    r"%ASA-6-30201[35]: Built inbound (?:TCP|UDP) connection \d+ .*? to "
    r"\S+:(?P<local_ip>[^/\s]+)/\d+ \((?P<global_ip>[^/\s]+)/\d+\)"
)
_ASA_INBOUND_ICMP_RE = re.compile(
    r"%ASA-6-302020: Built inbound ICMP connection .*? "
    r"gaddr (?P<global_ip>[^/\s]+)/\d+ laddr (?P<local_ip>[^/\s]+)/\d+"
)


@dataclass(frozen=True)
class Finding:
    """One reproducible invariant violation."""

    check: str
    severity: str
    path: str
    message: str
    evidence: dict[str, Any]


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("dataset", type=Path, help="Generated EvidenceForge output directory")
    parser.add_argument("--output", type=Path, help="Optional JSON report path")
    return parser.parse_args()


def _read_json_lines(path: Path, findings: list[Finding]) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    with path.open(encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, start=1):
            if not line.strip():
                continue
            try:
                value = json.loads(line)
            except json.JSONDecodeError as exc:
                findings.append(
                    Finding(
                        check="json_parse",
                        severity="error",
                        path=str(path),
                        message=f"Invalid JSON on line {line_number}: {exc.msg}",
                        evidence={"line": line_number, "column": exc.colno},
                    )
                )
                continue
            if not isinstance(value, dict):
                findings.append(
                    Finding(
                        check="json_record_shape",
                        severity="error",
                        path=str(path),
                        message=f"Line {line_number} is not a JSON object",
                        evidence={"line": line_number, "type": type(value).__name__},
                    )
                )
                continue
            records.append(value)
    return records


def _numeric_timestamp(record: dict[str, Any]) -> float | None:
    for key in ("ts", "timestamp_ms", "timestamp"):
        value = record.get(key)
        if isinstance(value, int | float) and math.isfinite(float(value)):
            timestamp = float(value)
            return timestamp / 1000.0 if key == "timestamp_ms" else timestamp
    return None


def _record_tuple(record: dict[str, Any]) -> tuple[Any, ...]:
    return tuple(record.get(field) for field in _TUPLE_FIELDS)


def _check_monotonic(
    path: Path,
    records: list[dict[str, Any]],
    findings: list[Finding],
) -> None:
    prior: float | None = None
    for index, record in enumerate(records, start=1):
        timestamp = _numeric_timestamp(record)
        if timestamp is None:
            continue
        if prior is not None and timestamp < prior:
            findings.append(
                Finding(
                    check="record_order",
                    severity="error",
                    path=str(path),
                    message="Records are not in nondecreasing timestamp order",
                    evidence={"record": index, "previous_ts": prior, "current_ts": timestamp},
                )
            )
            return
        prior = timestamp


def _check_window(
    path: Path,
    records: list[dict[str, Any]],
    window: tuple[float, float] | None,
    findings: list[Finding],
) -> None:
    if window is None:
        return
    start, end = window
    is_endpoint = path.suffix == ".xml" or path.name == "ecar.json"
    for index, record in enumerate(records, start=1):
        timestamp = _numeric_timestamp(record)
        if timestamp is None:
            continue
        if timestamp < start - _WINDOW_TOLERANCE_SECONDS:
            findings.append(
                Finding(
                    check="collection_window",
                    severity="error",
                    path=str(path),
                    message="Record precedes the declared collection window",
                    evidence={"record": index, "ts": timestamp, "window_start": start},
                )
            )
        elif not is_endpoint and timestamp > end + _WINDOW_TOLERANCE_SECONDS:
            findings.append(
                Finding(
                    check="collection_window",
                    severity="error",
                    path=str(path),
                    message="Non-endpoint record exceeds the declared collection window",
                    evidence={"record": index, "ts": timestamp, "window_end": end},
                )
            )


def _check_zeek_sensor(
    directory: Path,
    records_by_name: dict[str, list[dict[str, Any]]],
    findings: list[Finding],
) -> None:
    conn_records = records_by_name.get("conn", [])
    conn_by_uid: dict[str, dict[str, Any]] = {}
    uid_counts = Counter(str(record.get("uid")) for record in conn_records if record.get("uid"))
    for uid, count in uid_counts.items():
        if count > 1:
            findings.append(
                Finding(
                    check="zeek_conn_uid_unique",
                    severity="error",
                    path=str(directory / "conn.json"),
                    message="A Zeek connection UID occurs more than once in one sensor view",
                    evidence={"uid": uid, "count": count},
                )
            )
    for record in conn_records:
        uid = record.get("uid")
        if uid:
            conn_by_uid[str(uid)] = record
        for direction in ("orig", "resp"):
            payload = record.get(f"{direction}_bytes")
            ip_bytes = record.get(f"{direction}_ip_bytes")
            packets = record.get(f"{direction}_pkts")
            if all(isinstance(value, int | float) for value in (payload, ip_bytes, packets)):
                if payload < 0 or ip_bytes < 0 or packets < 0 or ip_bytes < payload:
                    findings.append(
                        Finding(
                            check="zeek_accounting",
                            severity="error",
                            path=str(directory / "conn.json"),
                            message="Zeek byte/packet accounting violates nonnegative IP-byte bounds",
                            evidence={
                                "uid": uid,
                                "direction": direction,
                                "payload_bytes": payload,
                                "ip_bytes": ip_bytes,
                                "packets": packets,
                            },
                        )
                    )
        if (
            record.get("id.orig_h") == record.get("id.resp_h")
            and record.get("id.orig_h") is not None
        ):
            findings.append(
                Finding(
                    check="zeek_self_connection",
                    severity="warning",
                    path=str(directory / "conn.json"),
                    message="Connection originator and responder are the same IP",
                    evidence={"uid": uid, "tuple": _record_tuple(record)},
                )
            )
        service = record.get("service")
        payload_bytes = int(record.get("orig_bytes") or 0) + int(record.get("resp_bytes") or 0)
        if service not in (None, "", "-") and record.get("proto") != "icmp" and payload_bytes == 0:
            findings.append(
                Finding(
                    check="zeek_unconfirmed_service",
                    severity="error",
                    path=str(directory / "conn.json"),
                    message="A payload-free connection carries an analyzer-confirmed service label",
                    evidence={
                        "uid": uid,
                        "service": service,
                        "conn_state": record.get("conn_state"),
                        "orig_bytes": record.get("orig_bytes"),
                        "resp_bytes": record.get("resp_bytes"),
                    },
                )
            )

    for name in sorted(_ZEEK_UID_FILES):
        for record in records_by_name.get(name, []):
            uid = record.get("uid")
            if not uid:
                continue
            conn = conn_by_uid.get(str(uid))
            if conn is None:
                findings.append(
                    Finding(
                        check="zeek_uid_join",
                        severity="error",
                        path=str(directory / f"{name}.json"),
                        message="Protocol row references a UID absent from conn.json",
                        evidence={"uid": uid},
                    )
                )
                continue
            if _record_tuple(record) != _record_tuple(conn):
                findings.append(
                    Finding(
                        check="zeek_tuple_join",
                        severity="error",
                        path=str(directory / f"{name}.json"),
                        message="Protocol row tuple differs from its conn.json tuple",
                        evidence={
                            "uid": uid,
                            "protocol_tuple": _record_tuple(record),
                            "conn_tuple": _record_tuple(conn),
                        },
                    )
                )
            timestamp = _numeric_timestamp(record)
            conn_start = _numeric_timestamp(conn)
            duration = conn.get("duration")
            if timestamp is not None and conn_start is not None:
                conn_end = conn_start + float(duration or 0.0)
                if timestamp < conn_start - 1e-6 or timestamp > conn_end + 1e-6:
                    findings.append(
                        Finding(
                            check="zeek_protocol_interval",
                            severity="error",
                            path=str(directory / f"{name}.json"),
                            message="Protocol timestamp falls outside its connection interval",
                            evidence={
                                "uid": uid,
                                "protocol_ts": timestamp,
                                "conn_start": conn_start,
                                "conn_end": conn_end,
                            },
                        )
                    )
            if name == "ntp" and (
                conn.get("conn_state") == "S0" or int(conn.get("resp_pkts") or 0) == 0
            ):
                findings.append(
                    Finding(
                        check="zeek_ntp_response",
                        severity="error",
                        path=str(directory / "ntp.json"),
                        message="NTP analyzer row is attached to a response-less connection",
                        evidence={"uid": uid, "conn_state": conn.get("conn_state")},
                    )
                )

    files_by_fuid = {
        str(record["fuid"]): record
        for record in records_by_name.get("files", [])
        if record.get("fuid")
    }
    for record in records_by_name.get("files", []):
        for uid in record.get("conn_uids") or []:
            conn = conn_by_uid.get(str(uid))
            if conn is None:
                findings.append(
                    Finding(
                        check="zeek_file_conn_join",
                        severity="error",
                        path=str(directory / "files.json"),
                        message="files.log row references a connection UID absent from conn.log",
                        evidence={"fuid": record.get("fuid"), "uid": uid},
                    )
                )
                continue
            file_start = _numeric_timestamp(record)
            conn_start = _numeric_timestamp(conn)
            if file_start is None or conn_start is None:
                continue
            file_end = file_start + float(record.get("duration") or 0.0)
            conn_end = conn_start + float(conn.get("duration") or 0.0)
            if file_start < conn_start - 1e-6 or file_end > conn_end + 1e-6:
                findings.append(
                    Finding(
                        check="zeek_file_interval",
                        severity="error",
                        path=str(directory / "files.json"),
                        message="File observation falls outside its connection interval",
                        evidence={
                            "fuid": record.get("fuid"),
                            "uid": uid,
                            "file_start": file_start,
                            "file_end": file_end,
                            "conn_start": conn_start,
                            "conn_end": conn_end,
                        },
                    )
                )
    for name, field in (("http", "resp_fuids"), ("ssl", "cert_chain_fuids")):
        for record in records_by_name.get(name, []):
            for fuid in record.get(field) or []:
                if str(fuid) not in files_by_fuid:
                    findings.append(
                        Finding(
                            check="zeek_file_reference",
                            severity="error",
                            path=str(directory / f"{name}.json"),
                            message=f"{name}.log references a file absent from files.log",
                            evidence={"uid": record.get("uid"), "fuid": fuid},
                        )
                    )
    for name in ("x509", "ocsp", "pe"):
        for record in records_by_name.get(name, []):
            fuid = record.get("id")
            if fuid and str(fuid) not in files_by_fuid:
                findings.append(
                    Finding(
                        check="zeek_file_reference",
                        severity="error",
                        path=str(directory / f"{name}.json"),
                        message=f"{name}.log references a file absent from files.log",
                        evidence={"fuid": fuid},
                    )
                )

    for record in records_by_name.get("dhcp", []):
        addresses = (
            record.get("client_addr"),
            record.get("server_addr"),
            record.get("assigned_addr"),
        )
        populated = [address for address in addresses if address is not None]
        if len(populated) == 3 and len(set(populated)) == 1:
            findings.append(
                Finding(
                    check="dhcp_role_separation",
                    severity="error",
                    path=str(directory / "dhcp.json"),
                    message="DHCP client, server, and assigned address are identical",
                    evidence={"address": populated[0], "uids": record.get("uids")},
                )
            )
        for uid in record.get("uids") or []:
            if str(uid) not in conn_by_uid:
                findings.append(
                    Finding(
                        check="zeek_uid_join",
                        severity="error",
                        path=str(directory / "dhcp.json"),
                        message="DHCP row references a UID absent from conn.json",
                        evidence={"uid": uid},
                    )
                )

    ocsp_durations = [
        float(record["duration"])
        for record in records_by_name.get("files", [])
        if record.get("mime_type") == "application/ocsp-response"
        and isinstance(record.get("duration"), int | float)
    ]
    if len(ocsp_durations) >= 5 and len(set(ocsp_durations)) == 1:
        findings.append(
            Finding(
                check="zeek_ocsp_duration_distribution",
                severity="warning",
                path=str(directory / "files.json"),
                message="Every OCSP file observation has exactly the same duration",
                evidence={"count": len(ocsp_durations), "duration": ocsp_durations[0]},
            )
        )

    aaaa_records = [
        record
        for record in records_by_name.get("dns", [])
        if str(record.get("qtype_name") or "").upper() == "AAAA"
    ]
    successful_aaaa = [
        record
        for record in aaaa_records
        if str(record.get("rcode_name") or "").upper() == "NOERROR" and record.get("answers")
    ]
    if len(aaaa_records) >= 10 and len(successful_aaaa) == len(aaaa_records):
        findings.append(
            Finding(
                check="zeek_aaaa_success_distribution",
                severity="warning",
                path=str(directory / "dns.json"),
                message="Every AAAA query succeeds with an answer",
                evidence={"count": len(aaaa_records)},
            )
        )


def _check_ecar_lifecycles(
    path: Path,
    records: list[dict[str, Any]],
    findings: list[Finding],
) -> None:
    """Check source-local eCAR identity and lifecycle invariants."""
    event_ids = Counter(str(record.get("id")) for record in records if record.get("id"))
    for event_id, count in event_ids.items():
        if count > 1:
            findings.append(
                Finding(
                    check="ecar_event_id_unique",
                    severity="error",
                    path=str(path),
                    message="An eCAR event identifier occurs more than once in one host stream",
                    evidence={"id": event_id, "count": count},
                )
            )

    failed_attempts = [
        record
        for record in records
        if record.get("object") == "USER_SESSION"
        and record.get("action") == "LOGIN"
        and (record.get("properties") or {}).get("outcome") == "failure"
        and record.get("objectID")
    ]
    failed_attempt_ids = Counter(str(record["objectID"]) for record in failed_attempts)
    for object_id, count in failed_attempt_ids.items():
        if count > 1:
            findings.append(
                Finding(
                    check="ecar_failed_attempt_identity_unique",
                    severity="error",
                    path=str(path),
                    message="Multiple failed login attempts share one eCAR object identity",
                    evidence={"object_id": object_id, "count": count},
                )
            )

    lifecycle_actions = {"PROCESS": ("CREATE", "TERMINATE"), "USER_SESSION": ("LOGIN", "LOGOUT")}
    for object_type, (start_action, end_action) in lifecycle_actions.items():
        by_object: dict[str, list[dict[str, Any]]] = defaultdict(list)
        for record in records:
            if record.get("object") == object_type and record.get("objectID"):
                if (
                    object_type == "USER_SESSION"
                    and (record.get("properties") or {}).get("outcome") == "failure"
                ):
                    continue
                by_object[str(record["objectID"])].append(record)
        for object_id, lifecycle in by_object.items():
            starts = [record for record in lifecycle if record.get("action") == start_action]
            ends = [record for record in lifecycle if record.get("action") == end_action]
            if len(starts) > 1:
                findings.append(
                    Finding(
                        check="ecar_lifecycle_duplicate_start",
                        severity="error",
                        path=str(path),
                        message=f"An eCAR {object_type} has multiple {start_action} records",
                        evidence={"object_id": object_id, "count": len(starts)},
                    )
                )
            if len(ends) > 1:
                findings.append(
                    Finding(
                        check="ecar_lifecycle_duplicate_end",
                        severity="error",
                        path=str(path),
                        message=f"An eCAR {object_type} has multiple {end_action} records",
                        evidence={"object_id": object_id, "count": len(ends)},
                    )
                )
            if starts and ends:
                start_ts = min(float(record["timestamp_ms"]) for record in starts)
                end_ts = min(float(record["timestamp_ms"]) for record in ends)
                if end_ts < start_ts:
                    findings.append(
                        Finding(
                            check="ecar_lifecycle_order",
                            severity="error",
                            path=str(path),
                            message=f"An eCAR {object_type} ends before it starts",
                            evidence={
                                "object_id": object_id,
                                "start_timestamp_ms": start_ts,
                                "end_timestamp_ms": end_ts,
                            },
                        )
                    )

    process_terminations = {
        str(record["objectID"]): float(record["timestamp_ms"])
        for record in records
        if record.get("object") == "PROCESS"
        and record.get("action") == "TERMINATE"
        and record.get("objectID")
        and isinstance(record.get("timestamp_ms"), int | float)
    }
    for record in records:
        actor_id = record.get("actorID")
        timestamp_ms = record.get("timestamp_ms")
        if not actor_id or not isinstance(timestamp_ms, int | float):
            continue
        termination_ms = process_terminations.get(str(actor_id))
        if termination_ms is not None and float(timestamp_ms) > termination_ms:
            findings.append(
                Finding(
                    check="ecar_actor_after_termination",
                    severity="error",
                    path=str(path),
                    message="An eCAR record is attributed to a process after its termination",
                    evidence={
                        "record_id": record.get("id"),
                        "actor_id": actor_id,
                        "record_timestamp_ms": timestamp_ms,
                        "termination_timestamp_ms": termination_ms,
                    },
                )
            )

    process_creates = {
        str(record["objectID"]): record
        for record in records
        if record.get("object") == "PROCESS"
        and record.get("action") == "CREATE"
        and record.get("objectID")
        and isinstance(record.get("timestamp_ms"), int | float)
    }
    linux_process_creates = sorted(
        (
            record
            for record in process_creates.values()
            if str((record.get("properties") or {}).get("image_path") or "").startswith("/")
            and isinstance(record.get("pid"), int)
        ),
        key=lambda record: (float(record["timestamp_ms"]), str(record.get("id") or "")),
    )
    linux_pid_reversals: list[dict[str, Any]] = []
    for prior, current in zip(linux_process_creates, linux_process_creates[1:], strict=False):
        if int(current["pid"]) <= int(prior["pid"]):
            linux_pid_reversals.append(
                {
                    "prior_pid": prior["pid"],
                    "prior_timestamp_ms": prior["timestamp_ms"],
                    "prior_record_id": prior.get("id"),
                    "pid": current["pid"],
                    "timestamp_ms": current["timestamp_ms"],
                    "record_id": current.get("id"),
                }
            )
    if linux_pid_reversals:
        findings.append(
            Finding(
                check="ecar_linux_pid_chronology",
                severity="error",
                path=str(path),
                message="Linux process-create PIDs reverse without a modeled PID-space wrap",
                evidence={
                    "count": len(linux_pid_reversals),
                    "sample": linux_pid_reversals[0],
                },
            )
        )
    startup_names = {"ntdll.dll", "kernel32.dll", "kernelbase.dll"}
    late_startup_modules: list[dict[str, Any]] = []
    incompatible_modules: list[dict[str, Any]] = []
    startup_modules_by_actor: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for record in records:
        if record.get("object") != "MODULE" or record.get("action") != "LOAD":
            continue
        properties = record.get("properties") or {}
        module_path = str(properties.get("file_path") or "")
        image_path = str(properties.get("image_path") or "")
        actor_id = str(record.get("actorID") or "")
        create = process_creates.get(actor_id)
        module_timestamp = record.get("timestamp_ms")
        module_name = module_path.rsplit("\\", 1)[-1].rsplit("/", 1)[-1].lower()
        if create is not None and isinstance(module_timestamp, int | float):
            delay_ms = float(module_timestamp) - float(create["timestamp_ms"])
            if 0 <= delay_ms <= 5_000:
                startup_modules_by_actor[actor_id].append(record)
            if module_name in startup_names and delay_ms > 5_000:
                late_startup_modules.append(
                    {
                        "actor_id": actor_id,
                        "image_path": image_path,
                        "module_path": module_path,
                        "delay_ms": delay_ms,
                        "module_record_id": record.get("id"),
                    }
                )
        exe_name = image_path.rsplit("\\", 1)[-1].rsplit("/", 1)[-1]
        if (
            module_path
            and exe_name
            and not module_is_compatible_with_process(
                exe_name,
                module_path,
            )
        ):
            incompatible_modules.append(
                {
                    "actor_id": actor_id,
                    "image_path": image_path,
                    "module_path": module_path,
                    "module_record_id": record.get("id"),
                }
            )

    common_startup_signature = (
        "ntdll.dll",
        "kernel32.dll",
        "kernelbase.dll",
        "msvcrt.dll",
        "ucrtbase.dll",
        "advapi32.dll",
        "sechost.dll",
        "rpcrt4.dll",
        "bcryptprimitives.dll",
    )
    startup_signatures: list[tuple[str, ...]] = []
    startup_executables_by_signature: dict[tuple[str, ...], set[str]] = defaultdict(set)
    cadence_signatures: Counter[tuple[tuple[str, ...], tuple[float, ...]]] = Counter()
    for actor_id, module_records in startup_modules_by_actor.items():
        ordered = sorted(
            module_records,
            key=lambda record: (float(record["timestamp_ms"]), str(record.get("id") or "")),
        )
        names = tuple(
            str((record.get("properties") or {}).get("file_path") or "")
            .replace("/", "\\")
            .rsplit("\\", 1)[-1]
            .lower()
            for record in ordered
        )
        if not names or names[0] != "ntdll.dll":
            continue
        startup_signatures.append(names)
        create = process_creates.get(actor_id)
        if create is not None:
            executable = str((create.get("properties") or {}).get("image_path") or "")
            if executable:
                startup_executables_by_signature[names].add(executable.lower())
        if len(ordered) >= 5:
            gaps = tuple(
                round(
                    float(current["timestamp_ms"]) - float(prior["timestamp_ms"]),
                    3,
                )
                for prior, current in zip(ordered, ordered[1:], strict=False)
            )
            cadence_signatures[(names, gaps)] += 1

    exact_common_count = sum(
        signature == common_startup_signature for signature in startup_signatures
    )
    exact_common_executables = startup_executables_by_signature[common_startup_signature]
    if (
        len(startup_signatures) >= 10
        and exact_common_count >= 10
        and exact_common_count / len(startup_signatures) >= 0.5
        and len(exact_common_executables) >= 3
    ):
        findings.append(
            Finding(
                check="ecar_startup_module_template_concentration",
                severity="error",
                path=str(path),
                message="One exact nine-module startup template dominates a host process population",
                evidence={
                    "startup_processes": len(startup_signatures),
                    "exact_common_signature_count": exact_common_count,
                    "share": exact_common_count / len(startup_signatures),
                    "executable_count": len(exact_common_executables),
                    "executables": sorted(exact_common_executables),
                },
            )
        )
    if cadence_signatures:
        (names, gaps), cadence_count = cadence_signatures.most_common(1)[0]
        if cadence_count >= 3 and gaps and max(gaps) <= 5:
            findings.append(
                Finding(
                    check="ecar_startup_module_cadence_repetition",
                    severity="error",
                    path=str(path),
                    message="An exact compact startup-module cadence repeats across processes",
                    evidence={
                        "count": cadence_count,
                        "module_names": names,
                        "gaps_ms": gaps,
                    },
                )
            )

    if late_startup_modules:
        findings.append(
            Finding(
                check="ecar_startup_module_chronology",
                severity="error",
                path=str(path),
                message="Foundational Windows modules load more than five seconds after CREATE",
                evidence={
                    "count": len(late_startup_modules),
                    "sample": late_startup_modules[0],
                },
            )
        )
    if incompatible_modules:
        findings.append(
            Finding(
                check="ecar_module_process_compatibility",
                severity="error",
                path=str(path),
                message="A configured non-OS module is attached to an undeclared executable",
                evidence={
                    "count": len(incompatible_modules),
                    "sample": incompatible_modules[0],
                },
            )
        )

    process_logon_ids = {
        str(record["objectID"]): str((record.get("properties") or {}).get("logon_id"))
        for record in records
        if record.get("object") == "PROCESS"
        and record.get("action") == "CREATE"
        and record.get("objectID")
        and (record.get("properties") or {}).get("logon_id")
    }
    logout_by_logon_id: dict[str, float] = {}
    for record in records:
        properties = record.get("properties") or {}
        if (
            record.get("object") == "USER_SESSION"
            and record.get("action") == "LOGOUT"
            and properties.get("logon_id")
            and isinstance(record.get("timestamp_ms"), int | float)
        ):
            logon_id = str(properties["logon_id"])
            logout_by_logon_id[logon_id] = min(
                float(record["timestamp_ms"]),
                logout_by_logon_id.get(logon_id, math.inf),
            )
    violations: dict[str, dict[str, Any]] = {}
    for record in records:
        process_id = record.get("actorID")
        if record.get("object") == "PROCESS" and record.get("action") == "TERMINATE":
            process_id = record.get("objectID")
        if not process_id or not isinstance(record.get("timestamp_ms"), int | float):
            continue
        logon_id = process_logon_ids.get(str(process_id))
        logout_ms = logout_by_logon_id.get(str(logon_id)) if logon_id else None
        if logout_ms is None or float(record["timestamp_ms"]) <= logout_ms:
            continue
        violations.setdefault(
            str(process_id),
            {
                "process_id": process_id,
                "logon_id": logon_id,
                "logout_timestamp_ms": logout_ms,
                "first_post_logout_timestamp_ms": record["timestamp_ms"],
                "first_record_id": record.get("id"),
            },
        )
    for evidence in violations.values():
        findings.append(
            Finding(
                check="ecar_process_after_session_logout",
                severity="error",
                path=str(path),
                message="Process-owned evidence occurs after its owning logon session ended",
                evidence=evidence,
            )
        )

    inverted_linux_logins = [
        record
        for record in records
        if record.get("object") == "PROCESS"
        and record.get("action") == "CREATE"
        and str((record.get("properties") or {}).get("image_path") or "").endswith("/login")
        and "systemd" in str((record.get("properties") or {}).get("parent_image_path") or "")
        and str((record.get("properties") or {}).get("source_principal") or "").lower()
        not in {"root", "nt authority\\system", "system"}
    ]
    if inverted_linux_logins:
        findings.append(
            Finding(
                check="ecar_linux_login_parentage",
                severity="error",
                path=str(path),
                message="Linux /bin/login is parented by a per-user systemd process",
                evidence={
                    "count": len(inverted_linux_logins),
                    "sample_record_id": inverted_linux_logins[0].get("id"),
                    "sample_properties": inverted_linux_logins[0].get("properties"),
                },
            )
        )

    session_login_ids = {
        str((record.get("properties") or {}).get("logon_id"))
        for record in records
        if record.get("object") == "USER_SESSION"
        and record.get("action") == "LOGIN"
        and (record.get("properties") or {}).get("logon_id")
    }
    local_login_without_session_open = [
        record
        for record in records
        if record.get("object") == "PROCESS"
        and record.get("action") == "CREATE"
        and str((record.get("properties") or {}).get("image_path") or "") == "/bin/login"
        and str((record.get("properties") or {}).get("logon_id") or "") not in session_login_ids
    ]
    if local_login_without_session_open:
        findings.append(
            Finding(
                check="ecar_local_login_session_open",
                severity="error",
                path=str(path),
                message="An in-window /bin/login process has no matching eCAR session opening",
                evidence={
                    "count": len(local_login_without_session_open),
                    "sample_record_id": local_login_without_session_open[0].get("id"),
                    "sample_properties": local_login_without_session_open[0].get("properties"),
                },
            )
        )

    service_parented_explorer = [
        record
        for record in records
        if record.get("object") == "PROCESS"
        and record.get("action") == "CREATE"
        and str((record.get("properties") or {}).get("image_path") or "")
        .lower()
        .endswith("\\explorer.exe")
        and str((record.get("properties") or {}).get("parent_image_path") or "")
        .lower()
        .endswith("\\services.exe")
    ]
    if service_parented_explorer:
        findings.append(
            Finding(
                check="ecar_explorer_parentage",
                severity="error",
                path=str(path),
                message="Interactive explorer.exe is directly parented by services.exe",
                evidence={
                    "count": len(service_parented_explorer),
                    "sample_record_id": service_parented_explorer[0].get("id"),
                    "sample_properties": service_parented_explorer[0].get("properties"),
                },
            )
        )


def _parse_xml_records(path: Path, findings: list[Finding]) -> list[dict[str, Any]]:
    try:
        root = ET.parse(path).getroot()
    except ET.ParseError as exc:
        findings.append(
            Finding(
                check="xml_parse",
                severity="error",
                path=str(path),
                message=f"Invalid XML: {exc}",
                evidence={},
            )
        )
        return []
    namespace = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}
    records: list[dict[str, Any]] = []
    for event in root.findall("e:Event", namespace):
        event_id = event.findtext("e:System/e:EventID", namespaces=namespace)
        record_id_text = event.findtext("e:System/e:EventRecordID", namespaces=namespace)
        try:
            record_id = int(record_id_text) if record_id_text is not None else None
        except ValueError:
            record_id = None
        created = event.find("e:System/e:TimeCreated", namespace)
        timestamp_text = created.get("SystemTime") if created is not None else None
        timestamp: float | None = None
        if timestamp_text:
            try:
                timestamp = datetime.fromisoformat(
                    timestamp_text.replace("Z", "+00:00")
                ).timestamp()
            except ValueError:
                pass
        fields = {
            item.get("Name", ""): item.text
            for item in event.findall("e:EventData/e:Data", namespace)
        }
        records.append(
            {
                "event_id": event_id,
                "record_id": record_id,
                "timestamp": timestamp,
                "fields": fields,
            }
        )
    return records


def _check_windows_record_id_sequence(
    path: Path,
    records: list[dict[str, Any]],
    findings: list[Finding],
) -> None:
    """Check channel-local sequence order and conservative throughput bounds."""
    prior: dict[str, Any] | None = None
    order_violations: list[dict[str, Any]] = []
    rate_violations: list[dict[str, Any]] = []
    reset_violations: list[dict[str, Any]] = []
    security_channel = path.name == "windows_event_security.xml"

    for record in records:
        record_id = record.get("record_id")
        timestamp = record.get("timestamp")
        if not isinstance(record_id, int) or not isinstance(timestamp, int | float):
            continue
        if security_channel and record.get("event_id") == "1102":
            if record_id != 1:
                reset_violations.append(
                    {
                        "event_record_id": record_id,
                        "timestamp": timestamp,
                    }
                )
            prior = record
            continue
        if prior is None:
            prior = record
            continue

        prior_id = prior.get("record_id")
        prior_timestamp = prior.get("timestamp")
        if not isinstance(prior_id, int) or not isinstance(prior_timestamp, int | float):
            prior = record
            continue
        if record_id <= prior_id:
            order_violations.append(
                {
                    "prior_event_record_id": prior_id,
                    "event_record_id": record_id,
                    "prior_timestamp": prior_timestamp,
                    "timestamp": timestamp,
                }
            )
            prior = record
            continue

        elapsed = max(0.0, float(timestamp) - float(prior_timestamp))
        hidden_records = record_id - prior_id - 1
        allowed_hidden = max(
            _WINDOWS_RECORD_ID_BURST_ALLOWANCE,
            math.ceil(elapsed * _WINDOWS_RECORD_ID_CONSERVATIVE_PEAK_RATE),
        )
        if hidden_records > allowed_hidden:
            rate_violations.append(
                {
                    "prior_event_record_id": prior_id,
                    "event_record_id": record_id,
                    "prior_timestamp": prior_timestamp,
                    "timestamp": timestamp,
                    "elapsed_seconds": elapsed,
                    "hidden_records": hidden_records,
                    "allowed_hidden_records": allowed_hidden,
                    "implied_hidden_records_per_second": (
                        hidden_records / elapsed if elapsed > 0.0 else None
                    ),
                }
            )
        prior = record

    if order_violations:
        findings.append(
            Finding(
                check="windows_record_id_order",
                severity="error",
                path=str(path),
                message="EventRecordID does not increase within one channel epoch",
                evidence={"count": len(order_violations), "sample": order_violations[0]},
            )
        )
    if reset_violations:
        findings.append(
            Finding(
                check="windows_record_id_clear_epoch",
                severity="error",
                path=str(path),
                message="Security Event 1102 does not begin a new record-ID epoch at 1",
                evidence={"count": len(reset_violations), "sample": reset_violations[0]},
            )
        )
    if rate_violations:
        findings.append(
            Finding(
                check="windows_record_id_rate",
                severity="error",
                path=str(path),
                message="EventRecordID gap implies implausible same-channel write throughput",
                evidence={"count": len(rate_violations), "sample": rate_violations[0]},
            )
        )


def _check_windows_contracts(
    path: Path,
    records: list[dict[str, Any]],
    findings: list[Finding],
) -> None:
    """Check stable Windows source-native field and identity contracts."""
    if path.name == "windows_event_security.xml":
        invalid_4648 = [
            record
            for record in records
            if record.get("event_id") == "4648"
            and (
                "NetworkAddress" in record["fields"]
                or "NetworkPort" in record["fields"]
                or "IpAddress" not in record["fields"]
                or "IpPort" not in record["fields"]
            )
        ]
        if invalid_4648:
            findings.append(
                Finding(
                    check="windows_4648_native_fields",
                    severity="error",
                    path=str(path),
                    message="Event 4648 uses non-native network field names",
                    evidence={
                        "count": len(invalid_4648),
                        "sample_fields": sorted(invalid_4648[0]["fields"]),
                    },
                )
            )

        interactive_logons = [
            record
            for record in records
            if record.get("event_id") == "4624"
            and str(record["fields"].get("LogonType") or "") in {"2", "10", "11"}
            and record["fields"].get("TargetLogonId")
            and record["fields"].get("ProcessId")
            and isinstance(record.get("timestamp"), int | float)
        ]
        logout_times: dict[str, float] = {}
        for record in records:
            logon_id = str(record["fields"].get("TargetLogonId") or "")
            timestamp = record.get("timestamp")
            if record.get("event_id") == "4634" and logon_id and isinstance(timestamp, int | float):
                logout_times[logon_id] = min(
                    float(timestamp),
                    logout_times.get(logon_id, math.inf),
                )
        overlapping_winlogon_owners: list[dict[str, Any]] = []
        for index, first in enumerate(interactive_logons):
            first_fields = first["fields"]
            first_id = str(first_fields["TargetLogonId"])
            first_end = logout_times.get(first_id, math.inf)
            for second in interactive_logons[index + 1 :]:
                second_fields = second["fields"]
                second_id = str(second_fields["TargetLogonId"])
                if first_id == second_id:
                    continue
                if first_fields["ProcessId"] != second_fields["ProcessId"]:
                    continue
                second_end = logout_times.get(second_id, math.inf)
                first_start = float(first["timestamp"])
                second_start = float(second["timestamp"])
                if first_start >= second_end or second_start >= first_end:
                    continue
                overlapping_winlogon_owners.append(
                    {
                        "process_id": first_fields["ProcessId"],
                        "first_logon_id": first_id,
                        "first_start": first_start,
                        "first_end": first_end if math.isfinite(first_end) else None,
                        "second_logon_id": second_id,
                        "second_start": second_start,
                        "second_end": second_end if math.isfinite(second_end) else None,
                    }
                )
        if overlapping_winlogon_owners:
            findings.append(
                Finding(
                    check="windows_interactive_session_winlogon_owner",
                    severity="error",
                    path=str(path),
                    message="Overlapping interactive sessions share one winlogon PID",
                    evidence={
                        "count": len(overlapping_winlogon_owners),
                        "sample": overlapping_winlogon_owners[0],
                    },
                )
            )

    if path.name != "windows_event_sysmon.xml":
        return
    process_creates = {
        str(record["fields"].get("ProcessGuid")): record
        for record in records
        if record.get("event_id") == "1"
        and record["fields"].get("ProcessGuid")
        and isinstance(record.get("timestamp"), int | float)
    }
    early_modules: list[dict[str, Any]] = []
    incompatible_modules: list[dict[str, Any]] = []
    for record in records:
        if record.get("event_id") != "7":
            continue
        fields = record["fields"]
        process_guid = str(fields.get("ProcessGuid") or "")
        create = process_creates.get(process_guid)
        if (
            create is not None
            and isinstance(record.get("timestamp"), int | float)
            and float(record["timestamp"]) < float(create["timestamp"])
        ):
            early_modules.append(
                {
                    "process_guid": process_guid,
                    "image": fields.get("Image"),
                    "image_loaded": fields.get("ImageLoaded"),
                    "create_timestamp": create["timestamp"],
                    "module_timestamp": record["timestamp"],
                }
            )
        image = str(fields.get("Image") or "")
        module = str(fields.get("ImageLoaded") or "")
        exe_name = image.rsplit("\\", 1)[-1].rsplit("/", 1)[-1]
        if module and exe_name and not module_is_compatible_with_process(exe_name, module):
            incompatible_modules.append(
                {
                    "process_guid": process_guid,
                    "image": image,
                    "image_loaded": module,
                }
            )
    if early_modules:
        findings.append(
            Finding(
                check="sysmon_module_after_process_create",
                severity="error",
                path=str(path),
                message="A Sysmon Event 7 precedes the matching Event 1",
                evidence={"count": len(early_modules), "sample": early_modules[0]},
            )
        )
    if incompatible_modules:
        findings.append(
            Finding(
                check="sysmon_module_process_compatibility",
                severity="error",
                path=str(path),
                message="A configured non-OS Event 7 module has an undeclared executable owner",
                evidence={"count": len(incompatible_modules), "sample": incompatible_modules[0]},
            )
        )
    guids_by_logon_id: dict[str, set[str]] = defaultdict(set)
    for record in records:
        fields = record["fields"]
        logon_id = fields.get("LogonId")
        logon_guid = fields.get("LogonGuid")
        if logon_id and logon_guid:
            guids_by_logon_id[str(logon_id)].add(str(logon_guid).lower())
    for logon_id, guids in guids_by_logon_id.items():
        if len(guids) > 1:
            findings.append(
                Finding(
                    check="sysmon_logon_guid_immutable",
                    severity="error",
                    path=str(path),
                    message="One Sysmon LogonId is associated with multiple LogonGuid values",
                    evidence={"logon_id": logon_id, "logon_guids": sorted(guids)},
                )
            )


_SNORT_TUPLE_RE = re.compile(
    r"\[\d+:(?P<sid>\d+):\d+\]\s+(?P<message>.*?)\s+\[\*\*\].*?"
    r"\{TCP\}\s+(?P<src>[^:\s]+):(?P<src_port>\d+)\s+->\s+"
    r"(?P<dst>[^:\s]+):(?P<dst_port>\d+)"
)


def _check_cross_source_contracts(
    data_dir: Path,
    json_records: dict[Path, list[dict[str, Any]]],
    findings: list[Finding],
) -> None:
    """Check invariants whose evidence spans host and network source trees."""
    all_ecar = [
        (path, record)
        for path, records in json_records.items()
        if path.name == "ecar.json"
        for record in records
    ]
    for path, records in json_records.items():
        if path.name != "ecar.json":
            continue
        syslog_path = path.with_name("syslog.log")
        if not syslog_path.is_file():
            continue
        process_create_by_pid = {
            int(record["pid"]): record
            for record in records
            if record.get("object") == "PROCESS"
            and record.get("action") == "CREATE"
            and isinstance(record.get("pid"), int)
            and isinstance(record.get("timestamp_ms"), int | float)
        }
        first_sshd_by_pid: dict[int, tuple[float, int, str]] = {}
        for line_number, line in enumerate(
            syslog_path.read_text(encoding="utf-8").splitlines(),
            start=1,
        ):
            match = _RFC5424_SSHD_RE.match(line)
            if match is None:
                continue
            try:
                pid = int(match.group("pid"))
                timestamp = datetime.fromisoformat(
                    match.group("timestamp").replace("Z", "+00:00")
                ).timestamp()
            except ValueError:
                continue
            current = first_sshd_by_pid.get(pid)
            if current is None or timestamp < current[0]:
                first_sshd_by_pid[pid] = (timestamp, line_number, line)

        inverted: list[dict[str, Any]] = []
        for pid, (syslog_timestamp, line_number, line) in first_sshd_by_pid.items():
            create = process_create_by_pid.get(pid)
            if create is None:
                continue
            create_timestamp = float(create["timestamp_ms"]) / 1000.0
            if syslog_timestamp < create_timestamp:
                inverted.append(
                    {
                        "pid": pid,
                        "process_create_timestamp": create_timestamp,
                        "process_create_record_id": create.get("id"),
                        "first_syslog_timestamp": syslog_timestamp,
                        "syslog_line": line_number,
                        "syslog_text": line,
                    }
                )
        if inverted:
            findings.append(
                Finding(
                    check="ssh_syslog_after_ecar_process_create",
                    severity="error",
                    path=str(syslog_path),
                    message="An sshd syslog message precedes the same PID's eCAR process create",
                    evidence={"count": len(inverted), "sample": inverted[0]},
                )
            )

    conn_by_tuple: dict[tuple[str, int, str, int], dict[str, Any]] = {}
    for path, records in json_records.items():
        if path.name != "conn.json":
            continue
        for record in records:
            try:
                key = (
                    str(record["id.orig_h"]),
                    int(record["id.orig_p"]),
                    str(record["id.resp_h"]),
                    int(record["id.resp_p"]),
                )
            except (KeyError, TypeError, ValueError):
                continue
            conn_by_tuple[key] = record

    ssh_intervals_by_actor: dict[str, list[tuple[float, float, dict[str, Any]]]] = defaultdict(list)
    rdp_outbound_by_tuple: dict[tuple[str, int, str, int], tuple[Path, dict[str, Any]]] = {}
    rdp_logins: list[tuple[Path, dict[str, Any]]] = []
    for path, record in all_ecar:
        properties = record.get("properties") or {}
        if record.get("object") == "FLOW":
            try:
                key = (
                    str(properties["src_ip"]),
                    int(properties["src_port"]),
                    str(properties["dst_ip"]),
                    int(properties["dst_port"]),
                )
            except (KeyError, TypeError, ValueError):
                continue
            if key[3] == 22 and record.get("actorID"):
                conn = conn_by_tuple.get(key)
                if conn is not None:
                    start = float(conn["ts"])
                    end = start + float(conn.get("duration") or 0.0)
                    ssh_intervals_by_actor[str(record["actorID"])].append((start, end, record))
            if key[3] == 3389 and properties.get("direction") == "OUTBOUND":
                rdp_outbound_by_tuple[key] = (path, record)
        elif (
            record.get("object") == "USER_SESSION"
            and record.get("action") == "LOGIN"
            and str(properties.get("logon_type")) == "10"
            and properties.get("outcome") == "success"
        ):
            rdp_logins.append((path, record))

    for actor_id, intervals in ssh_intervals_by_actor.items():
        ordered = sorted(intervals, key=lambda item: (item[0], item[1]))
        for prior, current in zip(ordered, ordered[1:], strict=False):
            if current[0] < prior[1] - 1e-6:
                findings.append(
                    Finding(
                        check="ecar_ssh_actor_overlapping_connections",
                        severity="error",
                        path=str(data_dir),
                        message="One SSH client process owns overlapping independent transports",
                        evidence={
                            "actor_id": actor_id,
                            "first_record_id": prior[2].get("id"),
                            "first_interval": [prior[0], prior[1]],
                            "second_record_id": current[2].get("id"),
                            "second_interval": [current[0], current[1]],
                        },
                    )
                )
                break

    for path, login in rdp_logins:
        properties = login.get("properties") or {}
        try:
            key = (
                str(properties["src_ip"]),
                int(properties["src_port"]),
                str(properties["dst_ip"]),
                int(properties["dst_port"]),
            )
        except (KeyError, TypeError, ValueError):
            continue
        flow_item = rdp_outbound_by_tuple.get(key)
        if flow_item is None:
            continue
        flow_path, flow = flow_item
        if float(flow["timestamp_ms"]) > float(login["timestamp_ms"]):
            findings.append(
                Finding(
                    check="ecar_rdp_transport_before_auth",
                    severity="error",
                    path=str(flow_path),
                    message="Source-visible RDP transport occurs after target authentication",
                    evidence={
                        "tuple": key,
                        "flow_record_id": flow.get("id"),
                        "flow_timestamp_ms": flow.get("timestamp_ms"),
                        "login_record_id": login.get("id"),
                        "login_timestamp_ms": login.get("timestamp_ms"),
                        "login_path": str(path),
                    },
                )
            )

    response_terms = ("403", "forbidden", "server response", "http response")
    for path in sorted(data_dir.rglob("snort_alert.log")):
        for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
            match = _SNORT_TUPLE_RE.search(line)
            if match is None or not any(
                term in match.group("message").lower() for term in response_terms
            ):
                continue
            key = (
                match.group("src"),
                int(match.group("src_port")),
                match.group("dst"),
                int(match.group("dst_port")),
            )
            conn = conn_by_tuple.get(key)
            if conn is None:
                continue
            if conn.get("conn_state") == "S0" or int(conn.get("resp_pkts") or 0) == 0:
                findings.append(
                    Finding(
                        check="ids_transport_semantics",
                        severity="error",
                        path=str(path),
                        message="Response-oriented IDS alert is attached to a response-less flow",
                        evidence={
                            "line": line_number,
                            "sid": match.group("sid"),
                            "message": match.group("message"),
                            "tuple": key,
                            "zeek_uid": conn.get("uid"),
                            "conn_state": conn.get("conn_state"),
                            "resp_pkts": conn.get("resp_pkts"),
                        },
                    )
                )


def _check_cisco_asa_contracts(path: Path, findings: list[Finding]) -> None:
    """Check rendered NAT address roles and connection-contained PAT lifetimes."""

    lines = path.read_text(encoding="utf-8").splitlines()
    static_local_by_global: dict[str, str] = {}
    for line in lines:
        match = _ASA_INBOUND_STATIC_BUILD_RE.search(line)
        if match is not None and match.group("local_ip") != match.group("global_ip"):
            static_local_by_global[match.group("global_ip")] = match.group("local_ip")

    active_connections: dict[str, tuple[tuple[str, int], int]] = {}
    active_xlates: dict[tuple[str, int], int] = {}
    for line_number, line in enumerate(lines, start=1):
        if match := _ASA_OUTBOUND_CONNECTION_BUILD_RE.search(line):
            local_tuple = (match.group("local_ip"), int(match.group("local_port")))
            active_connections[match.group("connection_id")] = (local_tuple, line_number)
        elif match := _ASA_CONNECTION_TEARDOWN_RE.search(line):
            active_connections.pop(match.group("connection_id"), None)
        elif match := _ASA_DYNAMIC_XLATE_BUILD_RE.search(line):
            local_tuple = (match.group("local_ip"), int(match.group("local_port")))
            active_xlates[local_tuple] = line_number
        elif match := _ASA_DYNAMIC_XLATE_TEARDOWN_RE.search(line):
            local_tuple = (match.group("local_ip"), int(match.group("local_port")))
            active_connection = next(
                (
                    (connection_id, build_line)
                    for connection_id, (candidate_tuple, build_line) in active_connections.items()
                    if candidate_tuple == local_tuple
                ),
                None,
            )
            if active_connection is not None:
                findings.append(
                    Finding(
                        check="asa_pat_lifetime",
                        severity="error",
                        path=str(path),
                        message="Dynamic PAT teardown precedes its owning connection teardown",
                        evidence={
                            "xlate_teardown_line": line_number,
                            "xlate_build_line": active_xlates.get(local_tuple),
                            "connection_id": active_connection[0],
                            "connection_build_line": active_connection[1],
                            "local_tuple": list(local_tuple),
                        },
                    )
                )
            active_xlates.pop(local_tuple, None)

        icmp_match = _ASA_INBOUND_ICMP_RE.search(line)
        if icmp_match is None:
            continue
        global_ip = icmp_match.group("global_ip")
        expected_local_ip = static_local_by_global.get(global_ip)
        rendered_local_ip = icmp_match.group("local_ip")
        if expected_local_ip is not None and rendered_local_ip != expected_local_ip:
            findings.append(
                Finding(
                    check="asa_inbound_icmp_nat",
                    severity="error",
                    path=str(path),
                    message="Inbound ICMP static-NAT laddr does not use the translated local address",
                    evidence={
                        "line": line_number,
                        "global_ip": global_ip,
                        "rendered_local_ip": rendered_local_ip,
                        "expected_local_ip": expected_local_ip,
                    },
                )
            )


def _load_window(dataset: Path) -> tuple[float, float] | None:
    path = dataset / "COLLECTION_PROFILE.json"
    if not path.exists():
        return None
    value = json.loads(path.read_text(encoding="utf-8"))
    window = value.get("collection_window", {})
    try:
        start = datetime.fromisoformat(str(window["start"]).replace("Z", "+00:00")).timestamp()
        end = datetime.fromisoformat(str(window["end"]).replace("Z", "+00:00")).timestamp()
    except (KeyError, TypeError, ValueError):
        return None
    return start, end


def _summarize_findings(findings: list[Finding]) -> dict[str, Any]:
    return {
        "total": len(findings),
        "by_severity": dict(sorted(Counter(item.severity for item in findings).items())),
        "by_check": dict(sorted(Counter(item.check for item in findings).items())),
    }


def main() -> int:
    """Run the rendered-output probe."""
    args = _parse_args()
    dataset = args.dataset.resolve()
    data_dir = dataset / "data"
    if not data_dir.is_dir():
        raise SystemExit(f"Dataset has no data directory: {data_dir}")

    findings: list[Finding] = []
    json_records: dict[Path, list[dict[str, Any]]] = {}
    xml_records: dict[Path, list[dict[str, Any]]] = {}
    window = _load_window(dataset)

    for path in sorted(data_dir.rglob("*.json")):
        records = _read_json_lines(path, findings)
        json_records[path] = records
        _check_monotonic(path, records, findings)
        _check_window(path, records, window, findings)
        if path.name == "ecar.json":
            _check_ecar_lifecycles(path, records, findings)
    for path in sorted(data_dir.rglob("*.xml")):
        records = _parse_xml_records(path, findings)
        xml_records[path] = records
        _check_windows_record_id_sequence(path, records, findings)
        _check_windows_contracts(path, records, findings)
        timestamps = [record["timestamp"] for record in records if record["timestamp"] is not None]
        if timestamps != sorted(timestamps):
            findings.append(
                Finding(
                    check="record_order",
                    severity="error",
                    path=str(path),
                    message="Windows XML events are not in nondecreasing timestamp order",
                    evidence={},
                )
            )
    for path in sorted(data_dir.rglob("cisco_asa.log")):
        _check_cisco_asa_contracts(path, findings)

    by_directory: dict[Path, dict[str, list[dict[str, Any]]]] = defaultdict(dict)
    for path, records in json_records.items():
        by_directory[path.parent][path.stem] = records
    for directory, records_by_name in by_directory.items():
        if "conn" in records_by_name:
            _check_zeek_sensor(directory, records_by_name, findings)
    _check_cross_source_contracts(data_dir, json_records, findings)

    report = {
        "schema_version": 1,
        "dataset": str(dataset),
        "collection_window_epoch": list(window) if window else None,
        "files": {
            "json": {str(path): len(records) for path, records in json_records.items()},
            "xml": {str(path): len(records) for path, records in xml_records.items()},
        },
        "summary": _summarize_findings(findings),
        "findings": [asdict(item) for item in findings],
    }
    rendered = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered, encoding="utf-8")
    else:
        sys.stdout.write(rendered)
    return 1 if any(item.severity == "error" for item in findings) else 0


if __name__ == "__main__":
    raise SystemExit(main())
