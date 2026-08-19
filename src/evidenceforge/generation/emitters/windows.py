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

import hashlib
import json
import logging
import os
import random
import secrets
import sqlite3
import stat
import tempfile
from bisect import bisect_left
from collections.abc import Iterator
from contextlib import contextmanager
from copy import deepcopy
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from queue import Empty, Full
from threading import Lock, get_ident, local
from typing import Any

from evidenceforge.events.base import CanonicalOccurrence
from evidenceforge.events.contexts import AuthContext, HostContext
from evidenceforge.formats.format_def import FormatDefinition
from evidenceforge.generation.activity.timing_profiles import windows_collision_spacing_config
from evidenceforge.generation.activity.windows_auth_realism import min_unlock_gap_seconds
from evidenceforge.generation.emitters.base import ExactPublicationError, LogEmitter
from evidenceforge.generation.emitters.host_base import _SingleHostWriter
from evidenceforge.generation.emitters.syslog_family import (
    make_syslog_family_route_key,
    sanitize_syslog_family_route_key,
    syslog_family_writer_path,
)
from evidenceforge.generation.emitters.windows_event import (
    compact_windows_event_xml,
    format_windows_system_time,
)
from evidenceforge.generation.emitters.windows_record_ids import (
    WindowsRecordIdSequence,
    coerce_windows_event_id,
    normalize_windows_event_id_value,
)
from evidenceforge.generation.emitters.windows_snare import (
    WINDOWS_SECURITY_SNARE_FILENAME,
    render_windows_security_snare_syslog,
)
from evidenceforge.generation.source_finalization import (
    ExactChunkPublisher,
    ExactSourceRow,
    SourceFinalizationEpoch,
    SourceFinalizationError,
)
from evidenceforge.generation.source_timing import (
    compatibility_endpoint_event_times,
    compatibility_relationship_time,
    finalized_endpoint_event_times,
)
from evidenceforge.output_targets import OutputTarget
from evidenceforge.utils.paths import sanitize_path_component
from evidenceforge.utils.rng import _stable_seed
from evidenceforge.utils.time import ensure_utc
from evidenceforge.utils.windows_ids import normalize_windows_id_value

win_logger = logging.getLogger(__name__)
_FROZEN_TIMING_MARKER = "windows-security-frozen-timing-v1"
_DEFAULT_FINALIZATION_ROW_CAPACITY = 2_000_000
_DEFAULT_FINALIZATION_BYTE_CAPACITY = 2 * 1024 * 1024 * 1024
_DEFAULT_FINALIZATION_ROUTE_CAPACITY = 100_000
_FINALIZATION_CHUNK_ROWS = 512
_FINALIZATION_CHUNK_BYTES = 16 * 1024 * 1024
_FINALIZATION_CHUNK_ROUTES = 128
_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)
_DIRECTORY = getattr(os, "O_DIRECTORY", 0)
_SQLITE_COMPANION_SUFFIXES = ("-journal", "-wal", "-shm")

# Well-known service accounts that always use "NT AUTHORITY" as their domain
_NT_AUTHORITY_ACCOUNTS = {"SYSTEM", "NETWORK SERVICE", "LOCAL SERVICE", "ANONYMOUS LOGON"}
_SECURITY_4689_NOISY_GUI_EXES = {"chrome.exe", "firefox.exe", "iexplore.exe", "msedge.exe"}
_WFP_FILTER_BUCKET_OFFSETS = {
    "dns": 1,
    "kerberos": 2,
    "ldap": 3,
    "smb": 4,
    "web": 5,
    "proxy": 6,
    "rdp": 7,
    "ssh": 8,
    "database": 9,
    "icmp": 10,
    "outbound_default": 20,
    "inbound_default": 21,
}
_WFP_OUTBOUND_LAYER_NAME = "%%14611"
_WFP_OUTBOUND_LAYER_RTID = 48
_WFP_INBOUND_LAYER_NAME = "%%14610"
_WFP_INBOUND_LAYER_RTID = 44
_LOCAL_SERVICE_LOGON_IDS = {"0x3e7", "0x3e4", "0x3e5", "-", "0x0"}


def _require_windows_source_finalization_capabilities() -> None:
    """Fail exact binding before generation without the required POSIX contract."""

    supports_dir_fd = getattr(os, "supports_dir_fd", frozenset())
    supports_follow_symlinks = getattr(os, "supports_follow_symlinks", frozenset())
    required_dir_fd = (os.open, os.mkdir, os.stat, os.unlink, os.rmdir)
    if (
        os.name != "posix"
        or _NOFOLLOW == 0
        or _DIRECTORY == 0
        or not callable(getattr(os, "geteuid", None))
        or not callable(getattr(os, "fsync", None))
        or any(operation not in supports_dir_fd for operation in required_dir_fd)
        or os.stat not in supports_follow_symlinks
    ):
        raise ExactPublicationError(
            "Exact Windows source finalization requires POSIX directory-descriptor, "
            "no-follow, durable-fsync, and effective-owner support"
        )
    configured = os.environ.get("EFORGE_SPOOL_DIR")
    probe = Path(
        os.path.realpath(
            os.fspath(Path(configured).expanduser() if configured else tempfile.gettempdir())
        )
    )
    while not probe.exists():
        if probe == probe.parent:
            raise ExactPublicationError(
                "Exact Windows source finalization has no existing filesystem probe root"
            )
        probe = probe.parent
    try:
        descriptor = os.open(probe, os.O_RDONLY | _DIRECTORY | _NOFOLLOW)
        try:
            os.stat(".", dir_fd=descriptor, follow_symlinks=False)
            os.listdir(descriptor)
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    except (OSError, TypeError, NotImplementedError) as error:
        raise ExactPublicationError(
            "Exact Windows source finalization requires working descriptor listing and fsync"
        ) from error


def _record_dropped_unlock(
    dropped_unlocks_by_session: dict[tuple[str, str], list[datetime]],
    computer: str,
    logon_id: str,
    unlock_ts: datetime,
) -> None:
    """Index a suppressed unlock for efficient LogonType 7 pairing."""
    dropped_unlocks_by_session.setdefault((computer, logon_id), []).append(unlock_ts)


def _has_nearby_dropped_unlock(
    dropped_unlocks_by_session: dict[tuple[str, str], list[datetime]],
    computer: str,
    logon_id: str,
    logon_ts: datetime,
) -> bool:
    """Return whether a type 7 logon is paired to a suppressed duplicate unlock."""
    unlock_times = dropped_unlocks_by_session.get((computer, logon_id))
    if not unlock_times:
        return False
    normalized_ts = ensure_utc(logon_ts)
    earliest_unlock_ts = normalized_ts - timedelta(seconds=2)
    unlock_index = bisect_left(unlock_times, earliest_unlock_ts)
    return unlock_index < len(unlock_times) and unlock_times[unlock_index] <= normalized_ts


_WINDOWS_AUTH_TRANSPORT_NEAR_WINDOW = timedelta(seconds=5)


def _windows_auth_transport_tuple(event: dict[str, Any]) -> tuple[str, str, str] | None:
    """Return ``(computer, source_ip, source_port)`` for remote auth/transport rows."""

    computer = str(event.get("Computer") or "")
    if not computer:
        return None
    event_id = event.get("EventID")
    if event_id == 4624 and str(event.get("LogonType") or "") in {"3", "10"}:
        source_ip = str(event.get("IpAddress") or "").removeprefix("::ffff:")
        source_port = str(event.get("IpPort") or "")
    elif event_id == 5156:
        source_ip = str(event.get("SourceAddress") or "").removeprefix("::ffff:")
        source_port = str(event.get("SourcePort") or "")
    else:
        return None
    if not source_ip or source_ip in {"-", "::1", "127.0.0.1"}:
        return None
    if not source_port or source_port in {"-", "0"}:
        return None
    return (computer, source_ip, source_port)


def _windows_logon_session_key(
    event: dict[str, Any],
    logon_id_field: str,
) -> tuple[str, str] | None:
    """Return a comparable ``(computer, logon_id)`` key for rendered Security rows."""
    computer = str(event.get("Computer") or "")
    logon_id = str(event.get(logon_id_field) or "")
    normalized_logon_id = logon_id.lower()
    if not computer or not logon_id or normalized_logon_id in _LOCAL_SERVICE_LOGON_IDS:
        return None
    return (computer, normalized_logon_id)


def _matching_privilege_logon_time(
    event: dict[str, Any],
    occurrence_times: dict[str, datetime],
    session_times: dict[tuple[str, str], list[datetime]],
) -> datetime | None:
    """Return the triggering 4624 time for one rendered 4672 companion."""
    occurrence_id = str(event.get("_auth_occurrence_id") or "")
    if occurrence_id and occurrence_id in occurrence_times:
        return occurrence_times[occurrence_id]
    timestamp = event.get("TimeCreated")
    key = _windows_logon_session_key(event, "SubjectLogonId")
    candidates = session_times.get(key, []) if key is not None else []
    if not isinstance(timestamp, datetime) or not candidates:
        return None
    return min(candidates, key=lambda candidate: abs((candidate - timestamp).total_seconds()))


def _nearest_auth_transport_time(
    transport_times: dict[tuple[str, str, str], list[datetime]],
    key: tuple[str, str, str],
    auth_time: datetime,
) -> datetime | None:
    """Return the nearest same-tuple transport observation for a remote auth row."""

    candidates = transport_times.get(key)
    if not candidates:
        return None
    near_candidates = [
        transport_time
        for transport_time in candidates
        if abs(transport_time - auth_time) <= _WINDOWS_AUTH_TRANSPORT_NEAR_WINDOW
    ]
    if not near_candidates:
        return None
    return min(near_candidates, key=lambda transport_time: abs(transport_time - auth_time))


def _windows_path_basename(path: str) -> str:
    """Return a lowercase basename for Windows or POSIX-looking paths."""
    return path.rsplit("\\", 1)[-1].rsplit("/", 1)[-1].lower()


def _windows_pid_hex(value: Any) -> str:
    """Return a normalized lowercase hex PID key from Security event fields."""
    max_decimal_pid_digits = 19
    if isinstance(value, int):
        return f"0x{value:x}"
    text = str(value or "").strip().lower()
    if not text or text == "-":
        return ""
    if text.startswith("0x"):
        return text
    if text.isdecimal():
        if len(text) > max_decimal_pid_digits:
            return text
        try:
            return f"0x{int(text):x}"
        except ValueError:
            return text
    return text


def _security_process_image_key(value: Any) -> str:
    """Return a loose image key that matches Win32 and device-path renderings."""
    return _windows_path_basename(str(value or ""))


def _security_process_key(
    computer: str,
    pid_value: Any,
    image_value: Any,
) -> tuple[str, str, str] | None:
    """Return a process lifecycle key for Security 4688/4689/5156 rows."""
    pid = _windows_pid_hex(pid_value)
    image = _security_process_image_key(image_value)
    if not computer or not pid or pid in {"0x0", "0x4"} or not image or image == "system":
        return None
    return (computer, pid, image)


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


def _shift_windows_lock_lifecycle_after_rendered_clock(
    event: dict[str, Any],
    last_by_computer: dict[str, datetime],
    shift_by_session: dict[tuple[str, str, str], timedelta],
) -> None:
    """Shift a clamped workstation lock lifecycle without compressing its dwell time.

    Windows rows are flushed incrementally, so an earlier batch can contain a
    long-lived process termination later than a lock lifecycle generated in the
    next batch. Move the matching 4800/4801 pair together when that happens;
    normalizing each row independently would collapse a human-scale locked
    interval into adjacent milliseconds.
    """
    event_id = event.get("EventID")
    if event_id not in {4800, 4801}:
        return
    ts = event.get("TimeCreated")
    if not isinstance(ts, datetime):
        return
    computer = str(event.get("Computer", ""))
    logon_id = str(event.get("TargetLogonId") or "")
    session_id = str(event.get("SessionId") or "")
    if not computer or not logon_id:
        return
    key = (computer, logon_id, session_id)
    original = ensure_utc(ts)

    if event_id == 4800:
        previous = last_by_computer.get(computer)
        shift = timedelta(0)
        if previous is not None and original <= previous:
            shifted = previous + timedelta(milliseconds=1)
            shift = shifted - original
            event["TimeCreated"] = shifted
        shift_by_session[key] = shift
        return

    shift = shift_by_session.pop(key, timedelta(0))
    if shift:
        event["TimeCreated"] = original + shift


def _enforce_windows_lock_dwell_after_normalization(
    event: dict[str, Any],
    rendered_lock_by_session: dict[tuple[str, str, str], datetime],
) -> None:
    """Preserve the minimum visible locked interval at the Security boundary."""
    event_id = event.get("EventID")
    if event_id not in {4800, 4801}:
        return
    ts = event.get("TimeCreated")
    if not isinstance(ts, datetime):
        return
    computer = str(event.get("Computer", ""))
    logon_id = str(event.get("TargetLogonId") or "")
    session_id = str(event.get("SessionId") or "")
    if not computer or not logon_id:
        return
    key = (computer, logon_id, session_id)
    normalized = ensure_utc(ts)
    if event_id == 4800:
        rendered_lock_by_session[key] = normalized
        return

    lock_time = rendered_lock_by_session.pop(key, None)
    if lock_time is None:
        return
    minimum_unlock = lock_time + timedelta(seconds=min_unlock_gap_seconds())
    if normalized < minimum_unlock:
        event["TimeCreated"] = minimum_unlock


def _subject_domain(username: str, netbios_domain: str) -> str:
    """Return the correct domain for SubjectDomainName / TargetDomainName.

    Windows well-known service accounts always use 'NT AUTHORITY', never
    the AD domain name.
    """
    if username.upper() in _NT_AUTHORITY_ACCOUNTS:
        return "NT AUTHORITY"
    return netbios_domain


def _logon_workstation_name(
    auth: AuthContext, host: HostContext, event: CanonicalOccurrence
) -> str:
    """Return native Windows WorkstationName semantics for successful logons."""
    if auth.workstation_name:
        return auth.workstation_name
    if (
        auth.logon_type == 3
        and (auth.auth_package or "").lower() == "kerberos"
        and auth.source_ip not in {"", "-", host.ip}
    ):
        seed = _stable_seed(
            f"kerberos_4624_workstation:{host.hostname}:{auth.logon_id}:"
            f"{auth.source_ip}:{event.timestamp.isoformat()}"
        )
        if seed % 100 < 72:
            return "-"
    if auth.logon_type in (3, 10) and event.src_host is not None:
        return event.src_host.hostname
    return host.hostname


def _auth_subject_domain(auth: Any, netbios_domain: str) -> str:
    """Normalize SubjectDomainName for well-known Windows subject identities."""
    subject_name = getattr(auth, "subject_username", "") or getattr(auth, "username", "")
    subject_sid = getattr(auth, "subject_sid", "") or getattr(auth, "user_sid", "")
    if subject_sid == "S-1-5-18" or subject_name.upper() in _NT_AUTHORITY_ACCOUNTS:
        return "NT AUTHORITY"
    return getattr(auth, "subject_domain", "") or _subject_domain(subject_name, netbios_domain)


def _windows_endpoint_port(address: str | None, port: int | str | None) -> int | str:
    """Return the native Windows EventData port value for an address field."""
    if not address or address == "-":
        return "-"
    return port if port not in (None, "") else 0


def _wfp_layer_fields(direction: Any) -> tuple[str, int]:
    """Return Windows Security 5156 layer fields compatible with WFP direction."""
    if str(direction or "") == "%%14592":
        return (_WFP_INBOUND_LAYER_NAME, _WFP_INBOUND_LAYER_RTID)
    return (_WFP_OUTBOUND_LAYER_NAME, _WFP_OUTBOUND_LAYER_RTID)


def _normalize_wfp_layer_fields(event_data: dict[str, Any]) -> None:
    """Align 5156 layer metadata with inbound/outbound WFP semantics."""
    if event_data.get("EventID") != 5156:
        return
    layer_name, layer_rtid = _wfp_layer_fields(event_data.get("Direction"))
    event_data["LayerName"] = layer_name
    event_data["LayerRTID"] = layer_rtid


def _kerberos_principal_source_key(event: dict[str, Any]) -> tuple[str, str, str, str] | None:
    """Return the same-user/source-port key for DC Kerberos ticket ordering checks."""
    if event.get("EventID") not in {4768, 4769}:
        return None
    username = str(event.get("TargetUserName") or "").split("@", 1)[0].lower()
    source_ip = str(event.get("IpAddress") or "")
    source_port = str(event.get("IpPort") or "")
    computer = str(event.get("Computer") or "")
    if not username or not source_ip or source_ip == "-" or not source_port or not computer:
        return None
    return (computer, username, source_ip, source_port)


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


@dataclass(frozen=True, slots=True)
class WindowsSourceFinalizationCensus:
    """Constant-time Windows candidate, final-row, route, and checkpoint counts."""

    state: str
    candidate_rows: int
    candidate_bytes: int
    final_rows: int
    final_bytes: int
    routes: int
    published_rows: int
    row_capacity: int
    byte_capacity: int
    route_capacity: int
    high_water_rows: int
    high_water_bytes: int
    high_water_routes: int


class _WindowsSourceFinalizationEpoch(SourceFinalizationEpoch):
    """Emitter-owned opaque reference to one sealed Windows Security cohort."""

    __slots__ = ("_footer", "_header", "_ordinal", "_output_target", "_owner")

    def __init__(
        self,
        owner: object,
        ordinal: int,
        output_target: OutputTarget,
        header: str,
        footer: str,
    ) -> None:
        self._owner = owner
        self._ordinal = ordinal
        self._output_target = output_target
        self._header = header
        self._footer = footer


@dataclass(frozen=True, slots=True)
class _WindowsFinalChunk:
    """One bounded page loaded from immutable Windows final-row storage."""

    chunk_id: int
    end_sequence: int
    rows: tuple[ExactSourceRow, ...]


@dataclass(slots=True)
class _WindowsRenderState:
    """Retry-local source-native sequence and clock state used during sealing."""

    record_id_sequences: dict[str, WindowsRecordIdSequence]
    last_time_created_by_computer: dict[str, datetime]
    last_record_time_created_by_computer: dict[str, datetime]
    time_collision_count_by_computer: dict[str, int]
    lock_lifecycle_shift_by_session: dict[tuple[str, str, str], timedelta]
    rendered_lock_time_by_session: dict[tuple[str, str, str], datetime]


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
        "workstation_locked",
        "workstation_unlocked",
        "smb_tree_connect",
        "smb_file_open",
        "smb_file_read",
        "smb_file_write",
        "smb_file_rename",
        "smb_file_delete",
        "smb_file_close",
    }

    @staticmethod
    def _ipv6_mapped(ip: str | None) -> str:
        """Format IPv4 as ::ffff:-mapped for Windows event consistency."""
        if not ip or ip == "-":
            return "-"
        if ":" in ip:
            return ip  # Already IPv6
        return f"::ffff:{ip}"

    @staticmethod
    def _normalize_execution_ids(event_data: dict[str, Any]) -> dict[str, Any]:
        """Align provider Execution PID/TID values before XML rendering."""
        normalized = dict(event_data)
        for field in ("ExecutionProcessID", "ExecutionThreadID"):
            value = normalized.get(field)
            normalized[field] = normalize_windows_id_value(value)
        return normalized

    def _event_rng(self, event: CanonicalOccurrence, salt: str = "") -> random.Random:
        """Return a deterministic renderer-local RNG for incidental Windows fields."""
        host = event.src_host or event.dst_host
        parts: list[object] = [
            salt or event.event_type,
            event.event_type,
            event.timestamp.isoformat(),
        ]
        if host is not None:
            parts.extend((host.hostname, host.fqdn, host.ip))
        if event.auth is not None:
            parts.extend(
                (
                    event.auth.username,
                    event.auth.logon_id,
                    event.auth.source_ip,
                    event.auth.source_port,
                    event.auth.logon_type,
                )
            )
        if event.process is not None:
            parts.extend(
                (
                    event.process.pid,
                    event.process.parent_pid,
                    event.process.image,
                    event.process.command_line,
                )
            )
        if event.network is not None:
            parts.extend(
                (
                    event.network.src_ip,
                    event.network.src_port,
                    event.network.dst_ip,
                    event.network.dst_port,
                    event.network.protocol,
                )
            )
        return random.Random(_stable_seed("|".join(str(part) for part in parts)))

    @staticmethod
    def _timing_phase(event: CanonicalOccurrence, event_id: int | None = None) -> str:
        """Return the frozen endpoint phase rendered by one Security row."""

        if event.event_type in {"process_create", "system_process_create"}:
            return "process_create"
        if event.event_type == "process_terminate":
            return "process_terminate"
        if event.event_type in {"logon", "machine_logon"} and event_id == 4672:
            return "privilege"
        if event.event_type == "smb_file_open" and event_id == 4656:
            return "smb_object_open"
        return "base"

    def _render_timestamp(
        self,
        event: CanonicalOccurrence,
        phase: str | None = None,
    ) -> datetime:
        """Return frozen Security time, with explicit stateless compatibility."""

        host = self._get_host(event)
        hostname = host.hostname if host is not None else ""
        effective_phase = phase or self._timing_phase(event)
        finalized = finalized_endpoint_event_times(
            event,
            "windows_event_security",
            hostname,
            effective_phase,
        )
        if finalized is None:
            if event.source_timing is not None and not event.source_timing.compatibility_mode:
                raise RuntimeError(
                    "Windows Security production projection requires frozen endpoint timing: "
                    f"host={hostname} event_type={event.event_type} phase={effective_phase}"
                )
            finalized = compatibility_endpoint_event_times(
                event,
                "windows_event_security",
                hostname,
                effective_phase,
            )
        return finalized[1]

    @staticmethod
    def _timing_is_finalized(event_data: dict[str, Any]) -> bool:
        """Return whether a row carries this emitter's frozen timing marker."""

        return event_data.get("_TimingFinalized") == _FROZEN_TIMING_MARKER

    # Event types where the Windows host is dst_host (target of the action)
    _DST_HOST_TYPES: set[str] = {
        "logon",
        "logoff",
        "failed_logon",
        "machine_logon",
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
        "smb_tree_connect",
        "smb_file_open",
        "smb_file_read",
        "smb_file_write",
        "smb_file_rename",
        "smb_file_delete",
        "smb_file_close",
    }

    def _get_host(self, event: CanonicalOccurrence) -> "HostContext":
        """Select the correct Windows host for this event type."""
        if event.event_type in self._DST_HOST_TYPES:
            return event.dst_host or event.src_host
        return event.src_host or event.dst_host

    def _security_provider_pid(self, host: "HostContext", reported_pid: int = 0) -> int:
        """Return the host's canonical Security-Auditing provider process PID."""
        if reported_pid > 0:
            return reported_pid
        system_pids = getattr(self, "_system_pids", {}).get(host.hostname, {})
        return int(system_pids.get("lsass", 600))

    def can_handle(self, event: CanonicalOccurrence) -> bool:
        """Windows emitter handles events on Windows hosts."""
        host = self._get_host(event)
        return (
            event.event_type in self._supported_types
            and host is not None
            and host.os_category == "windows"
        )

    def emit(self, event: CanonicalOccurrence) -> None:
        """Dispatch to per-type render method."""
        self._current_storyline_origin = event.storyline_origin
        host = self._get_host(event)
        self._emission_context.host_type = host.system_type if host is not None else ""
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
            "workstation_locked": self._render_workstation_lock,
            "workstation_unlocked": self._render_workstation_unlock,
            "smb_tree_connect": self._render_smb_audit,
            "smb_file_open": self._render_smb_audit,
            "smb_file_read": self._render_smb_audit,
            "smb_file_write": self._render_smb_audit,
            "smb_file_rename": self._render_smb_audit,
            "smb_file_delete": self._render_smb_audit,
            "smb_file_close": self._render_smb_audit,
        }.get(event.event_type)
        if renderer is None:
            raise NotImplementedError(
                f"WindowsEventEmitter: no render method for {event.event_type}"
            )
        self._emission_context.canonical_event = event
        try:
            renderer(event)
        finally:
            self._current_storyline_origin = False
            self._emission_context.host_type = ""
            self._emission_context.canonical_event = None

    def _render_logon(self, event: CanonicalOccurrence) -> None:
        """Render Windows 4624 (successful logon) + optional 4672 (special privileges)."""
        rng = self._event_rng(event)
        auth = event.auth
        host = self._get_host(event)
        workstation_name = _logon_workstation_name(auth, host, event)
        process_pid, process_name = self._logon_caller_process_identity(host, auth)
        ip_address = self._ipv6_mapped(auth.source_ip)
        logon_source_port = auth.source_port if auth.logon_type in (3, 10) else None

        event_data = {
            "EventID": 4624,
            "_auth_occurrence_id": event.occurrence_id,
            "TimeCreated": event.timestamp,
            "Computer": host.fqdn,
            "Channel": "Security",
            "Level": 0,
            "ExecutionProcessID": self._security_provider_pid(host, auth.reporting_pid),
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
            "ProcessId": f"0x{process_pid:x}" if process_pid else "0x0",
            "ProcessName": process_name,
            "IpAddress": ip_address,
            "IpPort": _windows_endpoint_port(ip_address, logon_source_port),
            "LogonProcessName": auth.logon_process,
            "AuthenticationPackageName": auth.auth_package,
            "LmPackageName": auth.lm_package,
            "KeyLength": 128 if auth.lm_package == "NTLM V2" else 0,
            "LogonGuid": auth.logon_guid,
            "TargetOutboundUserName": auth.outbound_username or "-",
            "TargetOutboundDomainName": auth.outbound_domain or "-",
            "VirtualAccount": "%%1843",
            "ElevatedToken": "%%1842" if auth.elevated else "%%1843",
        }
        self.emit_event(event_data)

        # 4672 special privileges (when auth.elevated is True)
        if auth.elevated and auth.emit_special_privileges:
            privs = auth.privilege_list or _special_privilege_fallback(auth.username)
            priv_data = {
                "EventID": 4672,
                "_auth_occurrence_id": event.occurrence_id,
                "TimeCreated": event.timestamp,
                "Computer": host.fqdn,
                "Channel": "Security",
                "Level": 0,
                "ExecutionProcessID": self._security_provider_pid(host, auth.reporting_pid),
                "ExecutionThreadID": rng.randint(100, 500),
                "SubjectUserSid": auth.user_sid,
                "SubjectUserName": auth.username,
                "SubjectDomainName": _subject_domain(auth.username, host.netbios_domain),
                "SubjectLogonId": auth.logon_id,
                "PrivilegeList": privs,
            }
            self.emit_event(priv_data)

    def _logon_caller_process_identity(
        self,
        host: HostContext,
        auth: AuthContext,
    ) -> tuple[int, str]:
        """Return EventData ProcessId/ProcessName for source-native 4624 semantics."""
        if auth.logon_type in {2, 7, 9, 10, 11} and auth.process_pid > 0:
            return (
                auth.process_pid,
                auth.process_name or r"C:\Windows\System32\winlogon.exe",
            )
        caller_by_type = {
            2: ("winlogon", 0x280, r"C:\Windows\System32\winlogon.exe"),
            4: ("services", 0x2BC, r"C:\Windows\System32\services.exe"),
            5: ("services", 0x2BC, r"C:\Windows\System32\services.exe"),
            7: ("winlogon", 0x280, r"C:\Windows\System32\winlogon.exe"),
            10: ("winlogon", 0x280, r"C:\Windows\System32\winlogon.exe"),
            11: ("winlogon", 0x280, r"C:\Windows\System32\winlogon.exe"),
        }
        role, default_pid, process_name = caller_by_type.get(
            auth.logon_type,
            ("lsass", auth.reporting_pid or 0x2E0, r"C:\Windows\System32\lsass.exe"),
        )
        sys_pids = getattr(self, "_system_pids", {}).get(host.hostname, {})
        return int(sys_pids.get(role, default_pid)), process_name

    def _render_workstation_lock(self, event: CanonicalOccurrence) -> None:
        """Render Windows 4800 (workstation locked)."""
        rng = self._event_rng(event)
        auth = event.auth
        host = self._get_host(event)
        session_id = auth.session_id or self._session_id_for_logon(auth.logon_id)
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

    def _render_workstation_unlock(self, event: CanonicalOccurrence) -> None:
        """Render Windows 4801 (workstation unlocked)."""
        rng = self._event_rng(event)
        auth = event.auth
        host = self._get_host(event)
        session_id = auth.session_id or self._session_id_for_logon(auth.logon_id)
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

    def _render_logoff(self, event: CanonicalOccurrence) -> None:
        """Render Windows 4634 (logoff)."""
        rng = self._event_rng(event)
        auth = event.auth
        host = self._get_host(event)

        event_data = {
            "EventID": 4634,
            "TimeCreated": event.timestamp,
            "Computer": host.fqdn,
            "Channel": "Security",
            "Level": 0,
            "ExecutionProcessID": self._security_provider_pid(host, auth.reporting_pid),
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

    def _render_failed_logon(self, event: CanonicalOccurrence) -> None:
        """Render Windows 4625 (failed logon)."""
        rng = self._event_rng(event)
        auth = event.auth
        host = self._get_host(event)
        ip_address = self._ipv6_mapped(auth.source_ip)
        has_source_ip = ip_address != "-"
        ip_port: int | str = auth.source_port if has_source_ip else "-"
        if not ip_port and has_source_ip and auth.logon_type == 3:
            ip_port = rng.randint(49152, 65535)

        event_data = {
            "EventID": 4625,
            "TimeCreated": event.timestamp,
            "Computer": host.fqdn,
            "Channel": "Security",
            "Level": 0,
            "Keywords": "0x8010000000000000",  # Audit Failure
            "ExecutionProcessID": self._security_provider_pid(host, auth.reporting_pid),
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
            "IpAddress": ip_address,
            "IpPort": ip_port,
        }
        self.emit_event(event_data)

    def _render_process_create(self, event: CanonicalOccurrence) -> None:
        """Render Windows 4688 (new process created)."""
        rng = self._event_rng(event)
        proc = event.process
        auth = event.auth
        host = self._get_host(event)
        target = proc.target_security_context

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
            "TargetUserSid": target.user_sid if target else "S-1-0-0",
            "TargetUserName": target.username if target else "-",
            "TargetDomainName": target.domain if target else "-",
            "TargetLogonId": target.logon_id if target else "0x0",
            "ParentProcessName": proc.parent_image,
            "MandatoryLabel": proc.mandatory_label or "S-1-16-8192",
        }
        self.emit_event(event_data)

    def _render_process_terminate(self, event: CanonicalOccurrence) -> None:
        """Render Windows 4689 (process exited)."""
        rng = self._event_rng(event)
        proc = event.process
        auth = event.auth
        host = self._get_host(event)
        if _windows_path_basename(proc.image) in _SECURITY_4689_NOISY_GUI_EXES:
            return

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

    def _render_system_process_create(self, event: CanonicalOccurrence) -> None:
        """Render Windows 4688 for system-account process (SYSTEM, LOCAL SERVICE, etc.)."""
        rng = self._event_rng(event)
        proc = event.process
        auth = event.auth
        host = self._get_host(event)
        target = proc.target_security_context

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
            "TargetUserSid": target.user_sid if target else "S-1-0-0",
            "TargetUserName": target.username if target else "-",
            "TargetDomainName": target.domain if target else "-",
            "TargetLogonId": target.logon_id if target else "0x0",
            "ParentProcessName": proc.parent_image,
            "MandatoryLabel": proc.mandatory_label or "S-1-16-16384",
        }
        self.emit_event(event_data)

    def _render_machine_logon(self, event: CanonicalOccurrence) -> None:
        """Render Windows 4624 for machine account logon (type 3 on DC)."""
        rng = self._event_rng(event)
        auth = event.auth
        host = self._get_host(event)
        # Derive WorkstationName from machine account (WKS-01$ → WKS-01)
        workstation = auth.username.rstrip("$") if auth.username.endswith("$") else auth.username
        ip_address = self._ipv6_mapped(auth.source_ip)

        event_data = {
            "EventID": 4624,
            "_auth_occurrence_id": event.occurrence_id,
            "TimeCreated": event.timestamp,
            "Computer": host.fqdn,
            "Channel": "Security",
            "Level": 0,
            "ExecutionProcessID": self._security_provider_pid(host, auth.reporting_pid),
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
            "IpAddress": ip_address,
            "IpPort": _windows_endpoint_port(ip_address, auth.source_port),
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
        if auth.elevated and auth.emit_special_privileges:
            priv_data = {
                "EventID": 4672,
                "_auth_occurrence_id": event.occurrence_id,
                "TimeCreated": event.timestamp,
                "Computer": host.fqdn,
                "Channel": "Security",
                "Level": 0,
                "ExecutionProcessID": self._security_provider_pid(host, auth.reporting_pid),
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

    def _render_kerberos_tgt(self, event: CanonicalOccurrence) -> None:
        """Render Windows 4768 (Kerberos TGT request)."""
        rng = self._event_rng(event)
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
            "ExecutionProcessID": self._security_provider_pid(host, krb.reporting_pid),
            "ExecutionThreadID": rng.randint(100, 500),
            "TargetUserName": krb.target_username,
            "TargetDomainName": krb.target_domain,
            "TargetSid": krb.target_sid,
            "ServiceName": krb.service_account_name or krb.service_name,
            "ServiceSid": krb.service_sid,
            "TicketOptions": krb.ticket_options,
            "Status": krb.ticket_status,
            "TicketEncryptionType": krb.encryption_type,
            "PreAuthType": krb.pre_auth_type,
            "IpAddress": krb.source_ip,
            "IpPort": _windows_endpoint_port(krb.source_ip, krb.source_port),
            "CertIssuerName": krb.cert_issuer_name,
            "CertSerialNumber": krb.cert_serial_number,
            "CertThumbprint": krb.cert_thumbprint,
        }
        self.emit_event(event_data)

    def _render_kerberos_service(self, event: CanonicalOccurrence) -> None:
        """Render Windows 4769 (Kerberos service ticket request)."""
        rng = self._event_rng(event)
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
            "ExecutionProcessID": self._security_provider_pid(host, krb.reporting_pid),
            "ExecutionThreadID": rng.randint(100, 500),
            "TargetUserName": krb.target_username.split("@", 1)[0],
            "TargetDomainName": krb.target_domain,
            "ServiceName": krb.service_account_name or krb.service_name,
            "ServiceSid": krb.service_sid,
            "TicketOptions": krb.ticket_options,
            "TicketEncryptionType": krb.encryption_type,
            "IpAddress": krb.source_ip,
            "IpPort": _windows_endpoint_port(krb.source_ip, krb.source_port),
            "Status": krb.ticket_status,
        }
        self.emit_event(event_data)

    def _render_kerberos_tgt_renewal(self, event: CanonicalOccurrence) -> None:
        """Render Windows 4770 (Kerberos TGT renewal)."""
        rng = self._event_rng(event)
        krb = event.kerberos
        host = self._get_host(event)

        event_data = {
            "EventID": 4770,
            "TimeCreated": event.timestamp,
            "Computer": host.fqdn,
            "Channel": "Security",
            "Level": 0,
            "ExecutionProcessID": self._security_provider_pid(host, krb.reporting_pid),
            "ExecutionThreadID": rng.randint(100, 500),
            "TargetUserName": krb.target_username,
            "TargetDomainName": krb.target_domain,
            "ServiceName": krb.service_account_name or krb.service_name,
            "ServiceSid": krb.service_sid,
            "TicketOptions": krb.ticket_options,
            "TicketEncryptionType": krb.encryption_type,
            "IpAddress": krb.source_ip,
            "IpPort": _windows_endpoint_port(krb.source_ip, krb.source_port),
            "Status": "0x0",
        }
        self.emit_event(event_data)

    def _render_ntlm_validation(self, event: CanonicalOccurrence) -> None:
        """Render Windows 4776 (NTLM credential validation)."""
        rng = self._event_rng(event)
        auth = event.auth
        host = self._get_host(event)

        event_data = {
            "EventID": 4776,
            "TimeCreated": event.timestamp,
            "Computer": host.fqdn,
            "Channel": "Security",
            "Level": 0,
            "ExecutionProcessID": self._security_provider_pid(host, auth.reporting_pid),
            "ExecutionThreadID": rng.randint(100, 500),
            "PackageName": "MICROSOFT_AUTHENTICATION_PACKAGE_V1_0",
            "TargetUserName": auth.username,
            "Workstation": auth.source_ip,  # workstation stored in source_ip
            "Status": auth.failure_status or "0x0",
        }
        self.emit_event(event_data)

    def _render_explicit_credentials(self, event: CanonicalOccurrence) -> None:
        """Render Windows 4648 (explicit credentials logon)."""
        rng = self._event_rng(event)
        auth = event.auth
        host = self._get_host(event)

        event_data = {
            "EventID": 4648,
            "TimeCreated": event.timestamp,
            "Computer": host.fqdn,
            "Channel": "Security",
            "Level": 0,
            "ExecutionProcessID": self._security_provider_pid(host, auth.reporting_pid),
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
            "IpAddress": auth.source_ip or "-",
            "IpPort": _windows_endpoint_port(auth.source_ip or "-", auth.source_port),
        }
        self.emit_event(event_data)

    def _render_smb_audit(self, event: CanonicalOccurrence) -> None:
        """Render profile-eligible Windows share and object-access auditing."""

        smb = event.smb
        auth = event.auth
        host = self._get_host(event)
        if smb is None or auth is None or smb.audit == "minimal":
            return
        failure = smb.result != "success"
        if event.event_type == "smb_tree_connect":
            event_ids = (5140,)
        elif failure:
            event_ids = (5145,)
        elif smb.audit == "high" and event.event_type == "smb_file_open":
            event_ids = (5145, 4656)
        elif event.event_type in {"smb_file_write", "smb_file_rename", "smb_file_delete"} or (
            smb.audit == "high" and event.event_type == "smb_file_read"
        ):
            if (
                smb.audit != "high"
                and _stable_seed(f"smb-standard-object-audit:{smb.file_id}:{smb.content_version}")
                % 100
                >= 65
            ):
                return
            event_ids = (4663,)
        elif smb.audit == "high" and event.event_type == "smb_file_close":
            event_ids = (4658,)
        else:
            return
        access_mask = {
            "read": "0x1",
            "write": "0x2",
            "rename": "0x10000",
            "delete": "0x10000",
            "open": {
                "list": "0x120089",
                "read": "0x120089",
                "write": "0x12019f",
                "rename": "0x110080",
                "delete": "0x110080",
            }[smb.requested_access],
        }.get(smb.phase, "0x1")
        access_list = {
            "read": "%%4416",
            "write": "%%4417",
            "rename": "%%1537",
            "delete": "%%1537",
            "open": {
                "list": "%%4416\n%%4419\n%%4423\n%%1538\n%%1541",
                "read": "%%4416\n%%4419\n%%4423\n%%1538\n%%1541",
                "write": ("%%4416\n%%4417\n%%4418\n%%4419\n%%4420\n%%4423\n%%4424\n%%1538\n%%1541"),
                "rename": "%%4423\n%%1537\n%%1541",
                "delete": "%%4423\n%%1537\n%%1541",
            }[smb.requested_access],
        }.get(smb.phase, "%%4416")
        process_id = event.network.responding_pid if event.network is not None else 4
        if process_id <= 0:
            process_id = 4
        process_name = "System"
        state_manager = getattr(self, "_state_manager", None)
        if state_manager is not None:
            running = state_manager.get_process(host.hostname, process_id)
            if running is not None:
                process_name = running.image
        handle_id = f"0x{_stable_seed(smb.handle_id or smb.tree_id) & 0xFFFFFFFF:x}"
        share_local_path = smb.share_local_path.rstrip("\\")
        if share_local_path and not share_local_path.startswith("\\??\\"):
            share_local_path = f"\\??\\{share_local_path}"
        common = {
            "Computer": host.fqdn,
            "Channel": "Security",
            "Level": 0,
            "ExecutionProcessID": self._security_provider_pid(host),
            "SubjectUserSid": auth.user_sid,
            "SubjectUserName": auth.username,
            "SubjectDomainName": _subject_domain(auth.username, host.netbios_domain),
            "SubjectLogonId": auth.logon_id,
        }
        for index, event_id in enumerate(event_ids):
            rng = self._event_rng(event, f"smb-{event_id}")
            data = {
                **common,
                "EventID": event_id,
                "TimeCreated": event.timestamp
                + timedelta(microseconds=index * rng.randint(120, 850)),
                "ExecutionThreadID": rng.randint(100, 500),
            }
            if event_id in {4656, 4663}:
                data.update(
                    {
                        "ObjectServer": "Security",
                        "ObjectType": "File",
                        "ObjectName": smb.server_path,
                        "HandleId": handle_id,
                        "AccessMask": access_mask,
                        "AccessList": access_list,
                        "ProcessId": f"0x{process_id:x}",
                        "ProcessName": process_name,
                        "ResourceAttributes": "-",
                    }
                )
                if event_id == 4656:
                    data.update(
                        {
                            "TransactionId": "{00000000-0000-0000-0000-000000000000}",
                            "AccessReason": "-",
                            "PrivilegeList": "-",
                            "RestrictedSidCount": 0,
                        }
                    )
            elif event_id == 4658:
                data.update(
                    {
                        "ObjectServer": "Security",
                        "HandleId": handle_id,
                        "ProcessId": f"0x{process_id:x}",
                        "ProcessName": process_name,
                    }
                )
            else:
                data.update(
                    {
                        "ObjectType": "File",
                        "IpAddress": self._ipv6_mapped(auth.source_ip),
                        "IpPort": auth.source_port,
                        "ShareName": f"\\\\*\\{smb.share_name}",
                        "ShareLocalPath": share_local_path,
                        "AccessMask": access_mask,
                        "AccessList": access_list,
                    }
                )
                if event_id == 5145:
                    data.update(
                        {
                            "RelativeTargetName": smb.share_path,
                            "AccessReason": "-",
                        }
                    )
            self.emit_event(data)

    def _render_wfp_connection(self, event: CanonicalOccurrence) -> None:
        """Render Windows 5156 (WFP connection permitted)."""
        rng = self._event_rng(event)
        net = event.network
        host = self._get_host(event)
        proc = event.process
        is_outbound = net.src_ip == host.ip
        local_process_pid = proc.pid if proc is not None and proc.pid > 0 else -1
        if is_outbound:
            pid = local_process_pid if local_process_pid > 0 else net.initiating_pid
        else:
            pid = local_process_pid if local_process_pid > 0 else net.responding_pid
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
            if pid <= 0:
                return
            if pid == 4:
                image = "System"
            else:
                return
        direction = "%%14593" if is_outbound else "%%14592"
        layer_name, layer_rtid = _wfp_layer_fields(direction)
        event_data = {
            "EventID": 5156,
            "TimeCreated": event.timestamp,
            "Computer": host.fqdn,
            "Channel": "Security",
            "Level": 0,
            "ExecutionProcessID": 4,
            "ExecutionThreadID": rng.randint(50, 200),
            "ProcessID": pid,
            "Application": self._to_device_path(image),
            "Direction": direction,
            "SourceAddress": net.src_ip,
            "SourcePort": net.src_port,
            "DestAddress": net.dst_ip,
            "DestPort": net.dst_port,
            "Protocol": net.ip_proto,
            "FilterRTID": self._wfp_filter_rtid(host, net, image, is_outbound),
            "LayerName": layer_name,
            "LayerRTID": layer_rtid,
            "RemoteUserID": "S-1-0-0",
            "RemoteMachineID": "S-1-0-0",
        }
        self.emit_event(event_data)

    @classmethod
    def _wfp_filter_rtid(
        cls,
        host: HostContext,
        net: Any,
        image: str,
        is_outbound: bool,
    ) -> int:
        """Return a stable WFP runtime filter ID for a host policy bucket."""
        bucket = cls._wfp_filter_bucket(net, image, is_outbound)
        direction = "out" if is_outbound else "in"
        proto = (net.protocol or "").lower() or str(net.ip_proto)
        base = 20000 + (_stable_seed(f"wfp_filter_base:{host.hostname}") % 30000)
        bucket_offset = _WFP_FILTER_BUCKET_OFFSETS.get(bucket, 99)
        variant = (
            _stable_seed(f"wfp_filter_policy:{host.hostname}:{direction}:{proto}:{bucket}") % 5
        )
        return base + (bucket_offset * 16) + variant

    @staticmethod
    def _wfp_filter_bucket(net: Any, image: str, is_outbound: bool) -> str:
        """Classify a 5156 connection into a small, reusable WFP policy bucket."""
        proto = (net.protocol or "").lower()
        port = net.dst_port
        basename = _windows_path_basename(image)
        if proto == "icmp" or net.ip_proto == 1:
            return "icmp"
        if proto == "udp" and port == 53:
            return "dns"
        if port in {88, 464}:
            return "kerberos"
        if port in {389, 636, 3268, 3269}:
            return "ldap"
        if port == 445:
            return "smb"
        if port in {80, 443, 8443}:
            return "web"
        if port in {8080, 3128, 8000, 8888} or "proxy" in basename:
            return "proxy"
        if port == 3389:
            return "rdp"
        if port == 22:
            return "ssh"
        if port in {1433, 3306, 5432, 1521}:
            return "database"
        return "outbound_default" if is_outbound else "inbound_default"

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

    def _render_kerberos_preauth_failed(self, event: CanonicalOccurrence) -> None:
        """Render Windows 4771 (Kerberos pre-authentication failed)."""
        rng = self._event_rng(event)
        krb = event.kerberos
        host = self._get_host(event)
        source_ip = krb.source_ip or "-"
        source_port = krb.source_port if source_ip not in {"", "-"} else 0

        event_data = {
            "EventID": 4771,
            "TimeCreated": event.timestamp,
            "Computer": host.fqdn,
            "Channel": "Security",
            "Level": 0,
            "Keywords": "0x8010000000000000",  # Always Audit Failure
            "ExecutionProcessID": self._security_provider_pid(host, krb.reporting_pid),
            "ExecutionThreadID": rng.randint(100, 500),
            "TargetUserName": krb.target_username,
            "TargetSid": krb.target_sid,
            "ServiceName": krb.service_name,
            "TicketOptions": krb.ticket_options,
            "Status": krb.ticket_status,
            "PreAuthType": krb.pre_auth_type,
            "IpAddress": source_ip,
            "IpPort": _windows_endpoint_port(source_ip, source_port),
        }
        self.emit_event(event_data)

    # --- Phase 2: Security Log Cleared (1102) ---

    def _render_log_cleared(self, event: CanonicalOccurrence) -> None:
        """Render Windows 1102 (security log cleared)."""
        rng = self._event_rng(event)
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

    def _render_service_installed(self, event: CanonicalOccurrence) -> None:
        """Render Windows 4697 (service installed in the system)."""
        rng = self._event_rng(event)
        auth = event.auth
        host = self._get_host(event)
        svc = event.service

        event_data = {
            "EventID": 4697,
            "TimeCreated": event.timestamp,
            "Computer": host.fqdn,
            "Channel": "Security",
            "Level": 0,
            "ExecutionProcessID": self._security_provider_pid(host, auth.reporting_pid),
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

    def _render_scheduled_task(self, event: CanonicalOccurrence) -> None:
        """Render Windows 4698/4699/4700/4701 (scheduled task operations)."""
        rng = self._event_rng(event)
        auth = event.auth
        host = self._get_host(event)
        task = event.scheduled_task

        event_data = {
            "EventID": self._SCHEDULED_TASK_EVENT_IDS[event.event_type],
            "TimeCreated": event.timestamp,
            "Computer": host.fqdn,
            "Channel": "Security",
            "Level": 0,
            "ExecutionProcessID": self._security_provider_pid(host, auth.reporting_pid),
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

    def _render_group_membership_change(self, event: CanonicalOccurrence) -> None:
        """Render Windows 4728/4729/4732/4733/4756/4757 (group membership change)."""
        rng = self._event_rng(event)
        auth = event.auth
        host = self._get_host(event)
        grp = event.group_membership

        event_data = {
            "EventID": self._GROUP_MEMBERSHIP_EVENT_IDS[event.event_type],
            "TimeCreated": event.timestamp,
            "Computer": host.fqdn,
            "Channel": "Security",
            "Level": 0,
            "ExecutionProcessID": self._security_provider_pid(host, auth.reporting_pid),
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

    def _render_account_created(self, event: CanonicalOccurrence) -> None:
        """Render Windows 4720 (user account created)."""
        self._render_account_full(event, 4720)

    def _render_account_changed(self, event: CanonicalOccurrence) -> None:
        """Render Windows 4738 (user account changed)."""
        self._render_account_full(event, 4738)

    def _render_account_full(self, event: CanonicalOccurrence, event_id: int) -> None:
        """Render 4720/4738 with full account property fields."""
        rng = self._event_rng(event)
        auth = event.auth
        host = self._get_host(event)
        acct = event.account_management

        event_data = {
            "EventID": event_id,
            "TimeCreated": event.timestamp,
            "Computer": host.fqdn,
            "Channel": "Security",
            "Level": 0,
            "ExecutionProcessID": self._security_provider_pid(host, auth.reporting_pid),
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

    def _render_account_deleted(self, event: CanonicalOccurrence) -> None:
        """Render Windows 4726 (user account deleted)."""
        self._render_account_simple(event, 4726, include_privs=True)

    def _render_password_reset(self, event: CanonicalOccurrence) -> None:
        """Render Windows 4724 (password reset attempt)."""
        self._render_account_simple(event, 4724, include_privs=False)

    def _render_password_change(self, event: CanonicalOccurrence) -> None:
        """Render Windows 4723 (password change attempt)."""
        self._render_account_simple(event, 4723, include_privs=True)

    def _render_account_simple(
        self, event: CanonicalOccurrence, event_id: int, include_privs: bool
    ) -> None:
        """Render 4723/4724/4726 with minimal account fields."""
        rng = self._event_rng(event)
        auth = event.auth
        host = self._get_host(event)
        acct = event.account_management

        event_data = {
            "EventID": event_id,
            "TimeCreated": event.timestamp,
            "Computer": host.fqdn,
            "Channel": "Security",
            "Level": 0,
            "ExecutionProcessID": self._security_provider_pid(host, auth.reporting_pid),
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
        *,
        source_finalization: bool = False,
        finalization_row_capacity: int = _DEFAULT_FINALIZATION_ROW_CAPACITY,
        finalization_byte_capacity: int = _DEFAULT_FINALIZATION_BYTE_CAPACITY,
        finalization_route_capacity: int = _DEFAULT_FINALIZATION_ROUTE_CAPACITY,
    ):
        if type(source_finalization) is not bool:
            raise ValueError("Windows source_finalization must be one exact bool")
        if source_finalization:
            _require_windows_source_finalization_capabilities()
        for value, label in (
            (finalization_row_capacity, "row"),
            (finalization_byte_capacity, "byte"),
            (finalization_route_capacity, "route"),
        ):
            if type(value) is not int or value <= 0:
                raise ValueError(
                    f"Windows finalization {label} capacity must be a positive exact int"
                )
        # Detect direct file mode (backward compat for tests)
        self._direct_file_mode = output_path.suffix != ""
        self._base_dir = output_path.parent if self._direct_file_mode else output_path
        self._direct_file_path = output_path if self._direct_file_mode else None
        if source_finalization:
            self._preflight_private_spool_root()
        self._host_writers: dict[str, _SingleHostWriter] = {}
        self._snare_writers: dict[str, _SingleHostWriter] = {}
        self._host_writers_lock = Lock()

        super().__init__(format_def, output_path, buffer_size, threaded)
        # Buffer raw event dicts instead of rendered strings
        self._event_dicts: list[dict[str, Any]] = []
        self._record_id_sequences: dict[str, WindowsRecordIdSequence] = {}
        self._last_time_created_by_computer: dict[str, datetime] = {}
        self._last_record_time_created_by_computer: dict[str, datetime] = {}
        self._time_collision_count_by_computer: dict[str, int] = {}
        self._lock_lifecycle_shift_by_session: dict[tuple[str, str, str], timedelta] = {}
        self._rendered_lock_time_by_session: dict[tuple[str, str, str], datetime] = {}
        self._current_storyline_origin: bool = False
        self._emission_context = local()
        self._spool_dir: Path | None = None
        self._owns_spool_dir: bool = False
        self._spool_path: Path | None = None
        self._spool_conn: sqlite3.Connection | None = None
        self._spooled_count: int = 0
        self._spool_sequence: int = 0
        self._spool_directory_descriptor: int | None = None
        self._spool_directory_identity: tuple[int, int] | None = None
        self._spool_root_descriptor: int | None = None
        self._spool_root_identity: tuple[int, int] | None = None
        self._spool_directory_name: str | None = None
        self._spool_initialization_pending = False
        self._spool_file_initialization_pending = False
        self._spool_file_identity: tuple[int, int] | None = None
        self._spool_filename: str | None = None
        self._candidate_admitted_rows = 0
        self._candidate_admitted_bytes = 0
        self._candidate_high_water_rows = 0
        self._candidate_high_water_bytes = 0
        self._source_high_water_rows = 0
        self._source_high_water_bytes = 0
        self._source_high_water_routes = 0
        self._candidate_admission_lock = Lock()
        self._finalization_row_capacity = finalization_row_capacity
        self._finalization_byte_capacity = finalization_byte_capacity
        self._finalization_route_capacity = finalization_route_capacity
        self._source_finalization_state = "open"
        self._source_finalization_owner: int | None = None
        self._source_finalization_operation_lock = Lock()
        self._source_finalization_epoch: _WindowsSourceFinalizationEpoch | None = None
        self._source_finalization_ordinal = 0
        self._source_finalization_routes: dict[int, _SingleHostWriter] = {}
        self._source_finalization_route_ids: dict[tuple[str, str], int] = {}
        self._sealing_transaction = False
        self._source_finalization_bound = source_finalization
        self._source_finalization_output_target: OutputTarget | None = None
        self._source_finalization_header: str | None = None
        self._source_finalization_footer: str | None = None

    def _preflight_private_spool_root(self) -> None:
        """Validate configured exact-spool trust and disjointness before generation."""

        configured = os.environ.get("EFORGE_SPOOL_DIR")
        root = Path(
            os.path.realpath(
                os.fspath(Path(configured).expanduser() if configured else tempfile.gettempdir())
            )
        )
        output_root = Path(os.path.realpath(os.fspath(self._base_dir)))
        if root == output_root or root.is_relative_to(output_root):
            raise ExactPublicationError("Windows private spool root must be outside public output")
        ancestor = root
        while not ancestor.exists():
            if ancestor == ancestor.parent:
                raise ExactPublicationError(
                    "Windows private spool has no existing trusted ancestor"
                )
            ancestor = ancestor.parent
        self._validate_private_spool_ancestry(ancestor)

    def configure_output_target(self, target: str | OutputTarget | None) -> None:
        """Reject target mutation after the terminal source cohort starts quiescing."""

        state, _ = self._source_lifecycle_snapshot()
        if self._source_finalization_bound and state != "open":
            raise SourceFinalizationError(
                "Windows output target cannot change after source quiescence"
            )
        super().configure_output_target(target)

    def _get_host_writer(self, host_fqdn: str) -> _SingleHostWriter:
        safe_host_fqdn = sanitize_path_component(host_fqdn)
        writer_key = "" if self._direct_file_mode else safe_host_fqdn
        writer = self._host_writers.get(writer_key)
        if writer is not None:
            return writer
        with self._host_writers_lock:
            writer = self._host_writers.get(writer_key)
            if writer is not None:
                return writer
            if safe_host_fqdn and not self._direct_file_mode:
                path = self._base_dir / safe_host_fqdn / "windows_event_security.xml"
            elif self._direct_file_path:
                path = self._direct_file_path
            else:
                path = self._base_dir / "windows_event_security.xml"
            writer = _SingleHostWriter(path, self.buffer_size)
            # The Splunk target is an event stream, not a rooted XML document.
            source_state, _ = self._source_lifecycle_snapshot()
            terminal = self._source_finalization_bound and source_state != "open"
            header = (
                self._source_finalization_header
                if terminal
                else self.format_def.output.header_template
            )
            output_target = (
                self._source_finalization_output_target if terminal else self.output_target
            )
            if header and output_target != OutputTarget.SPLUNK:
                writer.write_header(header)
            self._host_writers[writer_key] = writer
            return writer

    def _get_snare_writer(self, host_fqdn: str, timestamp: datetime) -> _SingleHostWriter:
        route_key = make_syslog_family_route_key(
            host_fqdn or "default",
            timestamp,
            direct_file_mode=self._direct_file_mode,
        )
        safe_route_key = sanitize_syslog_family_route_key(route_key)
        return self._get_snare_writer_for_route_key(safe_route_key)

    def _get_snare_writer_for_route_key(self, safe_route_key: str) -> _SingleHostWriter:
        """Resolve one already-sanitized immutable Snare route."""

        writer_key = "" if self._direct_file_mode else safe_route_key
        writer = self._snare_writers.get(writer_key)
        if writer is not None:
            return writer
        with self._host_writers_lock:
            writer = self._snare_writers.get(writer_key)
            if writer is not None:
                return writer
            if self._direct_file_path is not None:
                path = self._direct_file_path.with_name(WINDOWS_SECURITY_SNARE_FILENAME)
            else:
                path = syslog_family_writer_path(
                    base_dir=self._base_dir,
                    safe_route_key=safe_route_key,
                    log_filename=WINDOWS_SECURITY_SNARE_FILENAME,
                    direct_file_path=None,
                    flat_filename=WINDOWS_SECURITY_SNARE_FILENAME,
                )
            writer = _SingleHostWriter(path, self.buffer_size)
            self._snare_writers[writer_key] = writer
            return writer

    def _buffer_event(self, rendered: str) -> None:
        """Route rendered fallback output only in explicit direct-file mode."""
        if not self._direct_file_path:
            return
        self._get_host_writer("").write(rendered)

    def emit_event(self, event_data: dict[str, Any]) -> None:
        """Buffer a Windows Event dict for deferred rendering."""
        event_data = self._normalize_execution_ids(event_data)
        event_data.pop("_TimingFinalized", None)
        if "EventID" in event_data:
            event_data["EventID"] = normalize_windows_event_id_value(event_data["EventID"])
        _normalize_wfp_layer_fields(event_data)
        canonical_event = getattr(self._emission_context, "canonical_event", None)
        if canonical_event is not None:
            event_id = coerce_windows_event_id(event_data.get("EventID"))
            phase = self._timing_phase(canonical_event, event_id)
            event_data["TimeCreated"] = self._render_timestamp(canonical_event, phase)
            event_data["_TimingFinalized"] = _FROZEN_TIMING_MARKER
        if getattr(self, "_current_storyline_origin", False):
            event_data["_storyline_origin"] = True
        host_type = getattr(self._emission_context, "host_type", "")
        if host_type:
            event_data["_host_type"] = host_type
        self._begin_queue_admission()
        handed_off = False
        reserved_bytes = 0
        try:
            with self._candidate_admission_lock:
                event_data, reserved_bytes = self._reserve_candidate_admission_unlocked(event_data)
            if self.threaded:
                warned = False
                while True:
                    self._raise_if_thread_failed()
                    try:
                        self._event_queue.put(event_data, timeout=0.1)
                    except Full:
                        if not warned:
                            win_logger.warning(
                                "Event queue full for %s emitter, applying backpressure",
                                self.format_def.name,
                            )
                            warned = True
                        continue
                    handed_off = True
                    break
            else:
                with self._file_lock:
                    self._event_dicts.append(event_data)
                    handed_off = True
                    if len(self._event_dicts) >= self.buffer_size:
                        try:
                            self._spool_event_dicts_unlocked()
                        except BaseException:
                            if self._source_finalization_bound:
                                retained = self._event_dicts.pop()
                                handed_off = False
                                if retained is not event_data:
                                    raise SourceFinalizationError(
                                        "Windows candidate rollback lost its current row"
                                    ) from None
                            raise
        except BaseException:
            if self._source_finalization_bound and not handed_off:
                with self._candidate_admission_lock:
                    self._release_candidate_admission_unlocked(reserved_bytes)
            raise
        finally:
            self._finish_queue_admission()

    def _reserve_candidate_admission_unlocked(
        self,
        event_data: dict[str, Any],
    ) -> tuple[dict[str, Any], int]:
        """Charge one exact candidate before retaining it in memory or the FIFO."""

        if not self._source_finalization_bound:
            return event_data, 0
        payload = _spool_encode(event_data)
        payload_bytes = len(payload.encode("utf-8"))
        if payload_bytes > _FINALIZATION_CHUNK_BYTES:
            raise SourceFinalizationError(
                "Windows candidate row exceeds the finalization chunk byte capacity"
            )
        candidate_rows = self._candidate_admitted_rows + 1
        candidate_bytes = self._candidate_admitted_bytes + payload_bytes
        if candidate_rows > self._finalization_row_capacity:
            raise SourceFinalizationError("Windows finalization row capacity is exhausted")
        if candidate_bytes > self._finalization_byte_capacity:
            raise SourceFinalizationError("Windows finalization byte capacity is exhausted")
        self._candidate_admitted_rows = candidate_rows
        self._candidate_admitted_bytes = candidate_bytes
        self._candidate_high_water_rows = max(self._candidate_high_water_rows, candidate_rows)
        self._candidate_high_water_bytes = max(self._candidate_high_water_bytes, candidate_bytes)
        self._source_high_water_rows = max(self._source_high_water_rows, candidate_rows)
        self._source_high_water_bytes = max(self._source_high_water_bytes, candidate_bytes)
        return _spool_decode(payload), payload_bytes

    def _release_candidate_admission_unlocked(self, payload_bytes: int) -> None:
        """Undo a reserved candidate that never reached memory or the FIFO."""

        if payload_bytes == 0:
            return
        if self._candidate_admitted_rows <= 0 or self._candidate_admitted_bytes < payload_bytes:
            raise SourceFinalizationError("Windows candidate admission accounting underflowed")
        self._candidate_admitted_rows -= 1
        self._candidate_admitted_bytes -= payload_bytes

    def _render_event(self, event_data: dict[str, Any]) -> str:
        """Render Windows Event dict to XML format."""
        from xml.sax.saxutils import escape as xml_escape

        # Strip internal metadata keys before rendering
        event_data.pop("_storyline_origin", None)
        event_data.pop("_auth_occurrence_id", None)
        event_data.pop("_TimingFinalized", None)

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
            except Empty:
                continue
            try:
                try:
                    if self._handle_flush_request(event_data):
                        continue
                    with self._file_lock:
                        self._event_dicts.append(event_data)
                        if len(self._event_dicts) >= self.buffer_size:
                            self._spool_event_dicts_unlocked()
                finally:
                    self._event_queue.task_done()
            except Exception as error:  # noqa: BLE001
                self._thread_error = error
                win_logger.exception(
                    "Unhandled exception in %s emitter thread; stopping thread",
                    self.format_def.name,
                )
                self._stop_event.set()

        win_logger.debug(f"Emitter thread stopped for {self.format_def.name}")

    def _flush_at_barrier(self) -> None:
        """Spool deferred events at the same boundary as the former barrier."""
        with self._file_lock:
            self._spool_event_dicts_unlocked()

    def _event_sort_key(self, event: dict[str, Any]) -> str:
        """Return a stable sortable timestamp key for deferred Windows events."""
        ts = event.get("TimeCreated", "")
        if isinstance(ts, datetime):
            return ensure_utc(ts).isoformat()
        return str(ts)

    def _get_spool_conn_unlocked(self) -> sqlite3.Connection:
        """Open the on-disk Windows event spool database while holding _file_lock."""
        if self._spool_conn is not None:
            if self._source_finalization_bound and self._spool_file_initialization_pending:
                self._finish_private_journal_initialization_unlocked()
            return self._spool_conn

        spool_dir = self._get_spool_dir_unlocked()
        if not self._source_finalization_bound:
            descriptor, path = tempfile.mkstemp(
                prefix=".windows_event_spool_",
                suffix=".sqlite3",
                dir=spool_dir,
            )
            os.close(descriptor)
            Path(path).unlink(missing_ok=True)
            self._spool_path = Path(path)
            self._spool_filename = self._spool_path.name
            self._spool_conn = sqlite3.connect(path, check_same_thread=False)
            self._initialize_spool_schema_unlocked(self._spool_conn)
            return self._spool_conn

        directory_descriptor = self._spool_directory_descriptor
        if directory_descriptor is None:
            raise ExactPublicationError("Windows private spool lost its directory descriptor")
        if self._spool_filename is None:
            for _attempt in range(128):
                filename = f".windows_event_spool_{secrets.token_hex(16)}.sqlite3"
                self._spool_filename = filename
                self._spool_path = spool_dir / filename
                self._spool_file_initialization_pending = True
                try:
                    descriptor = os.open(
                        filename,
                        os.O_RDWR | os.O_CREAT | os.O_EXCL | _NOFOLLOW,
                        0o600,
                        dir_fd=directory_descriptor,
                    )
                except FileExistsError:
                    self._spool_filename = None
                    self._spool_path = None
                    self._spool_file_initialization_pending = False
                    continue
                except BaseException:
                    self._adopt_private_journal_create_lost_return_unlocked()
                    raise
                else:
                    try:
                        self._adopt_private_journal_descriptor_unlocked(descriptor)
                    finally:
                        os.close(descriptor)
                    break
            else:
                raise ExactPublicationError("Unable to allocate a unique Windows private journal")
        self._finish_private_journal_initialization_unlocked()
        return self._spool_conn

    def _adopt_private_journal_descriptor_unlocked(self, descriptor: int) -> None:
        """Retain the identity returned by one exclusive journal create."""

        metadata = os.fstat(descriptor)
        effective_user = int(os.geteuid())
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_nlink != 1
            or int(metadata.st_uid) != effective_user
        ):
            raise ExactPublicationError("Windows private journal is not an owner file")
        os.fchmod(descriptor, 0o600)
        self._spool_file_identity = (int(metadata.st_dev), int(metadata.st_ino))

    def _adopt_private_journal_create_lost_return_unlocked(self) -> None:
        """Retain a journal entry created before its exclusive-open return was lost."""

        directory_descriptor = self._spool_directory_descriptor
        filename = self._spool_filename
        if directory_descriptor is None or filename is None:
            raise ExactPublicationError("Windows private journal lost its create owner")
        try:
            descriptor = os.open(
                filename,
                os.O_RDWR | _NOFOLLOW,
                dir_fd=directory_descriptor,
            )
        except FileNotFoundError:
            return
        try:
            self._adopt_private_journal_descriptor_unlocked(descriptor)
        finally:
            os.close(descriptor)

    def _finish_private_journal_initialization_unlocked(self) -> None:
        """Retryably create, initialize, and durably publish the retained journal."""

        directory_descriptor = self._spool_directory_descriptor
        filename = self._spool_filename
        path = self._spool_path
        if directory_descriptor is None or filename is None or path is None:
            raise ExactPublicationError("Windows private journal lost its initialization owner")
        if self._spool_file_identity is None:
            try:
                descriptor = os.open(
                    filename,
                    os.O_RDWR | os.O_CREAT | os.O_EXCL | _NOFOLLOW,
                    0o600,
                    dir_fd=directory_descriptor,
                )
            except FileExistsError as error:
                raise ExactPublicationError(
                    "Windows private journal create ownership is ambiguous"
                ) from error
            except BaseException:
                self._adopt_private_journal_create_lost_return_unlocked()
                raise
            else:
                try:
                    self._adopt_private_journal_descriptor_unlocked(descriptor)
                finally:
                    os.close(descriptor)
        self._validate_spool_file_unlocked()
        if self._spool_conn is None:
            self._spool_conn = sqlite3.connect(
                f"{path.as_uri()}?mode=rw",
                uri=True,
                check_same_thread=False,
            )
        self._initialize_spool_schema_unlocked(self._spool_conn)
        self._validate_spool_file_unlocked()
        os.fsync(directory_descriptor)
        self._spool_file_initialization_pending = False

    def _initialize_spool_schema_unlocked(self, connection: sqlite3.Connection) -> None:
        """Create one bounded candidate/final journal with memory-only SQLite temp state."""

        connection.execute("PRAGMA temp_store=MEMORY")
        if connection.execute("PRAGMA temp_store").fetchone() != (2,):
            raise ExactPublicationError("Windows journal could not confine SQLite temp storage")
        connection.execute("PRAGMA journal_mode=DELETE")
        connection.execute("PRAGMA synchronous=FULL")
        if connection.execute("PRAGMA user_version").fetchone() == (1,):
            self._validate_initial_spool_schema_unlocked(connection)
            return
        connection.execute("BEGIN IMMEDIATE")
        try:
            connection.execute(
                """CREATE TABLE events (
                    sequence INTEGER PRIMARY KEY,
                    sort_key TEXT NOT NULL,
                    phase TEXT NOT NULL CHECK (phase IN ('candidate', 'final')),
                    payload TEXT NOT NULL,
                    payload_bytes INTEGER NOT NULL CHECK (payload_bytes >= 0),
                    ordinal INTEGER,
                    route_kind TEXT,
                    route_key TEXT,
                    payload_digest TEXT
                )"""
            )
            connection.execute(
                "CREATE INDEX events_candidate_order ON events (phase, sort_key, sequence)"
            )
            connection.execute("CREATE UNIQUE INDEX events_final_order ON events (phase, ordinal)")
            connection.execute(
                """CREATE TABLE finalization_state (
                    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
                    phase TEXT NOT NULL,
                    candidate_rows INTEGER NOT NULL,
                    candidate_bytes INTEGER NOT NULL,
                    final_rows INTEGER NOT NULL,
                    final_bytes INTEGER NOT NULL,
                    routes INTEGER NOT NULL,
                    published_rows INTEGER NOT NULL,
                    epoch INTEGER NOT NULL,
                    high_water_rows INTEGER NOT NULL,
                    high_water_bytes INTEGER NOT NULL,
                    high_water_routes INTEGER NOT NULL
                )"""
            )
            connection.execute(
                """INSERT INTO finalization_state
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (1, "candidate", 0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
            )
            connection.execute("PRAGMA user_version=1")
            connection.commit()
        except BaseException:
            if not connection.in_transaction:
                try:
                    self._validate_initial_spool_schema_unlocked(connection)
                except ExactPublicationError:
                    pass
                else:
                    return
            connection.rollback()
            raise
        self._validate_initial_spool_schema_unlocked(connection)

    @staticmethod
    def _validate_initial_spool_schema_unlocked(connection: sqlite3.Connection) -> None:
        """Adopt only the exact empty schema after an initialization lost return."""

        objects = set(
            connection.execute(
                """SELECT type, name FROM sqlite_master
                   WHERE name IN (?, ?, ?, ?)""",
                (
                    "events",
                    "events_candidate_order",
                    "events_final_order",
                    "finalization_state",
                ),
            ).fetchall()
        )
        expected = {
            ("table", "events"),
            ("index", "events_candidate_order"),
            ("index", "events_final_order"),
            ("table", "finalization_state"),
        }
        state = connection.execute(
            "SELECT * FROM finalization_state WHERE singleton = ?",
            (1,),
        ).fetchone()
        if (
            connection.execute("PRAGMA user_version").fetchone() != (1,)
            or objects != expected
            or state != (1, "candidate", 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
            or connection.execute("SELECT COUNT(*) FROM events").fetchone() != (0,)
        ):
            raise ExactPublicationError("Windows private journal schema is not immutable")

    @staticmethod
    def _open_directory_nofollow(path: Path, *, create: bool = False) -> int:
        """Open every existing absolute directory component without following symlinks."""

        absolute = Path(os.path.abspath(os.fspath(path)))
        descriptor = os.open(absolute.anchor, os.O_RDONLY | _DIRECTORY | _NOFOLLOW)
        try:
            for component in absolute.parts[1:]:
                try:
                    next_descriptor = os.open(
                        component,
                        os.O_RDONLY | _DIRECTORY | _NOFOLLOW,
                        dir_fd=descriptor,
                    )
                except FileNotFoundError:
                    if not create:
                        raise
                    try:
                        os.mkdir(component, mode=0o755, dir_fd=descriptor)
                    except FileExistsError:
                        pass
                    else:
                        os.fsync(descriptor)
                    next_descriptor = os.open(
                        component,
                        os.O_RDONLY | _DIRECTORY | _NOFOLLOW,
                        dir_fd=descriptor,
                    )
                os.close(descriptor)
                descriptor = next_descriptor
            return descriptor
        except BaseException:
            os.close(descriptor)
            raise

    @classmethod
    def _validate_private_spool_ancestry(cls, path: Path) -> None:
        """Require root-or-process-owned ancestry with sticky shared roots."""

        effective_user = int(os.geteuid())
        current = path
        while True:
            descriptor = cls._open_directory_nofollow(current)
            try:
                metadata = os.fstat(descriptor)
            finally:
                os.close(descriptor)
            if int(metadata.st_uid) not in {0, effective_user}:
                raise ExactPublicationError(
                    "Windows private spool ancestry is not process controlled"
                )
            permissions = stat.S_IMODE(metadata.st_mode)
            if permissions & 0o022 and not metadata.st_mode & stat.S_ISVTX:
                raise ExactPublicationError(
                    "Windows private spool ancestry is externally writable without sticky mode"
                )
            if current == current.parent:
                return
            current = current.parent

    def _validate_spool_directory_unlocked(self) -> None:
        """Revalidate the owner-only private directory and its pinned identity."""

        if not self._source_finalization_bound:
            if self._spool_dir is None or not self._spool_dir.is_dir():
                raise ExactPublicationError("Windows legacy spool directory disappeared")
            return
        spool_dir = self._spool_dir
        descriptor = self._spool_directory_descriptor
        identity = self._spool_directory_identity
        root_descriptor = self._spool_root_descriptor
        root_identity = self._spool_root_identity
        directory_name = self._spool_directory_name
        if (
            spool_dir is None
            or descriptor is None
            or identity is None
            or root_descriptor is None
            or root_identity is None
            or directory_name is None
        ):
            raise ExactPublicationError("Windows private spool lost its identity")
        retained = os.fstat(descriptor)
        retained_root = os.fstat(root_descriptor)
        reopened = os.stat(directory_name, dir_fd=root_descriptor, follow_symlinks=False)
        effective_user = getattr(os, "geteuid", lambda: None)()
        if (
            not stat.S_ISDIR(retained_root.st_mode)
            or (int(retained_root.st_dev), int(retained_root.st_ino)) != root_identity
        ):
            raise ExactPublicationError("Windows private spool root identity changed")
        for metadata in (retained, reopened):
            if (
                not stat.S_ISDIR(metadata.st_mode)
                or (int(metadata.st_dev), int(metadata.st_ino)) != identity
                or (effective_user is not None and int(metadata.st_uid) != effective_user)
                or stat.S_IMODE(metadata.st_mode) != 0o700
            ):
                raise ExactPublicationError("Windows private spool identity or mode changed")

    def _validate_spool_file_unlocked(self) -> None:
        """Revalidate the SQLite main file without following its directory entry."""

        if not self._source_finalization_bound:
            if self._spool_path is None or not self._spool_path.is_file():
                raise ExactPublicationError("Windows legacy spool file disappeared")
            return
        self._validate_spool_directory_unlocked()
        descriptor = self._spool_directory_descriptor
        filename = self._spool_filename
        identity = self._spool_file_identity
        if descriptor is None or filename is None or identity is None:
            raise ExactPublicationError("Windows private journal lost its identity")
        metadata = os.stat(filename, dir_fd=descriptor, follow_symlinks=False)
        effective_user = getattr(os, "geteuid", lambda: None)()
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_nlink != 1
            or (int(metadata.st_dev), int(metadata.st_ino)) != identity
            or (effective_user is not None and int(metadata.st_uid) != effective_user)
            or stat.S_IMODE(metadata.st_mode) != 0o600
        ):
            raise ExactPublicationError("Windows private journal identity or mode changed")

    def _get_spool_dir_unlocked(self) -> Path:
        """Return the local runtime directory used for SQLite spool state."""
        if self._spool_dir is not None:
            if self._source_finalization_bound and self._spool_initialization_pending:
                self._finish_private_spool_initialization_unlocked()
            self._validate_spool_directory_unlocked()
            return self._spool_dir

        configured = os.environ.get("EFORGE_SPOOL_DIR")
        if configured and not self._source_finalization_bound:
            requested = Path(configured).expanduser()
            requested.mkdir(parents=True, exist_ok=True)
            spool_dir = Path(os.path.realpath(os.fspath(requested)))
            self._spool_dir = spool_dir
            self._owns_spool_dir = False
            return self._spool_dir
        if not self._source_finalization_bound:
            self._spool_dir = Path(tempfile.mkdtemp(prefix="evidenceforge-windows-spool-"))
            self._owns_spool_dir = True
            return self._spool_dir

        protected_root = Path(
            os.path.realpath(
                os.fspath(Path(configured).expanduser() if configured else tempfile.gettempdir())
            )
        )
        output_root = Path(os.path.realpath(os.fspath(self._base_dir)))
        if protected_root == output_root or protected_root.is_relative_to(output_root):
            raise ExactPublicationError("Windows private spool must be outside public output")
        if configured:
            ancestor = protected_root
            while not ancestor.exists():
                if ancestor == ancestor.parent:
                    raise ExactPublicationError(
                        "Windows private spool has no existing trusted ancestor"
                    )
                ancestor = ancestor.parent
            self._validate_private_spool_ancestry(ancestor)
        root_descriptor = self._open_directory_nofollow(
            protected_root,
            create=configured is not None,
        )
        root_metadata = os.fstat(root_descriptor)
        try:
            self._validate_private_spool_ancestry(protected_root)
        except BaseException:
            os.close(root_descriptor)
            raise
        self._spool_root_descriptor = root_descriptor
        self._spool_root_identity = (
            int(root_metadata.st_dev),
            int(root_metadata.st_ino),
        )
        for _attempt in range(128):
            directory_name = f"evidenceforge-windows-spool-{secrets.token_hex(16)}"
            self._spool_directory_name = directory_name
            self._spool_dir = protected_root / directory_name
            self._owns_spool_dir = True
            self._spool_initialization_pending = True
            try:
                os.mkdir(directory_name, mode=0o700, dir_fd=root_descriptor)
            except FileExistsError:
                self._spool_directory_name = None
                self._spool_dir = None
                self._owns_spool_dir = False
                self._spool_initialization_pending = False
                continue
            except BaseException:
                self._adopt_private_spool_create_lost_return_unlocked()
                raise
            break
        else:
            os.close(root_descriptor)
            self._spool_root_descriptor = None
            self._spool_root_identity = None
            raise ExactPublicationError("Unable to allocate a unique Windows private spool")
        self._finish_private_spool_initialization_unlocked()
        self._validate_spool_directory_unlocked()
        return self._spool_dir

    def _adopt_private_spool_create_lost_return_unlocked(self) -> None:
        """Retain an owner-only leaf created before mkdir's return was lost."""

        root_descriptor = self._spool_root_descriptor
        directory_name = self._spool_directory_name
        if root_descriptor is None or directory_name is None:
            raise ExactPublicationError("Windows private spool lost its create owner")
        try:
            metadata = os.stat(directory_name, dir_fd=root_descriptor, follow_symlinks=False)
        except FileNotFoundError:
            return
        effective_user = int(os.geteuid())
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or int(metadata.st_uid) != effective_user
            or stat.S_IMODE(metadata.st_mode) != 0o700
        ):
            raise ExactPublicationError("Windows private spool leaf is not owner-only")
        self._spool_directory_identity = (int(metadata.st_dev), int(metadata.st_ino))

    def _finish_private_spool_initialization_unlocked(self) -> None:
        """Retryably pin and durably publish one newly allocated private leaf."""

        root_descriptor = self._spool_root_descriptor
        directory_name = self._spool_directory_name
        if root_descriptor is None or directory_name is None:
            raise ExactPublicationError("Windows private spool lost its initialization owner")
        try:
            metadata = os.stat(directory_name, dir_fd=root_descriptor, follow_symlinks=False)
        except FileNotFoundError:
            try:
                os.mkdir(directory_name, mode=0o700, dir_fd=root_descriptor)
            except BaseException:
                self._adopt_private_spool_create_lost_return_unlocked()
                raise
            metadata = os.stat(directory_name, dir_fd=root_descriptor, follow_symlinks=False)
        effective_user = int(os.geteuid())
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or int(metadata.st_uid) != effective_user
            or stat.S_IMODE(metadata.st_mode) != 0o700
        ):
            raise ExactPublicationError("Windows private spool leaf is not owner-only")
        identity = (int(metadata.st_dev), int(metadata.st_ino))
        if self._spool_directory_identity not in {None, identity}:
            raise ExactPublicationError("Windows private spool leaf identity changed")
        if self._spool_directory_descriptor is None:
            self._spool_directory_descriptor = os.open(
                directory_name,
                os.O_RDONLY | _DIRECTORY | _NOFOLLOW,
                dir_fd=root_descriptor,
            )
        retained = os.fstat(self._spool_directory_descriptor)
        if (int(retained.st_dev), int(retained.st_ino)) != identity:
            raise ExactPublicationError("Windows private spool descriptor changed identity")
        self._spool_directory_identity = identity
        os.fsync(self._spool_directory_descriptor)
        os.fsync(root_descriptor)
        self._spool_initialization_pending = False

    def _spool_event_dicts_unlocked(self) -> None:
        """Move buffered event dictionaries to disk to bound emitter memory usage."""
        if not self._event_dicts:
            return
        conn = self._get_spool_conn_unlocked()
        self._validate_spool_file_unlocked()
        rows: list[tuple[int, str, str, str, int]] = []
        added_bytes = 0
        start_sequence = self._spool_sequence
        for offset, event in enumerate(self._event_dicts):
            payload = _spool_encode(event)
            payload_bytes = len(payload.encode("utf-8"))
            if self._source_finalization_bound and payload_bytes > _FINALIZATION_CHUNK_BYTES:
                raise SourceFinalizationError(
                    "Windows candidate row exceeds the finalization chunk byte capacity"
                )
            rows.append(
                (
                    start_sequence + offset,
                    self._event_sort_key(event),
                    "candidate",
                    payload,
                    payload_bytes,
                )
            )
            added_bytes += payload_bytes
        state = conn.execute(
            "SELECT phase, candidate_rows, candidate_bytes FROM finalization_state WHERE singleton = ?",
            (1,),
        ).fetchone()
        if state is None or state[0] != "candidate":
            raise SourceFinalizationError("Windows journal rejected a late candidate cohort")
        candidate_rows = int(state[1]) + len(rows)
        candidate_bytes = int(state[2]) + added_bytes
        if self._source_finalization_bound and candidate_rows > self._finalization_row_capacity:
            raise SourceFinalizationError("Windows finalization row capacity is exhausted")
        if self._source_finalization_bound and candidate_bytes > self._finalization_byte_capacity:
            raise SourceFinalizationError("Windows finalization byte capacity is exhausted")
        with self._candidate_admission_lock:
            admitted_rows = self._candidate_admitted_rows
            admitted_bytes = self._candidate_admitted_bytes
            high_water_rows = self._candidate_high_water_rows
            high_water_bytes = self._candidate_high_water_bytes
        if self._source_finalization_bound and (
            candidate_rows > admitted_rows or candidate_bytes > admitted_bytes
        ):
            raise SourceFinalizationError("Windows candidate journal exceeded admitted capacity")
        try:
            conn.executemany(
                """INSERT INTO events
                (sequence, sort_key, phase, payload, payload_bytes)
                VALUES (?, ?, ?, ?, ?)""",
                rows,
            )
            conn.execute(
                """UPDATE finalization_state
                SET candidate_rows = ?, candidate_bytes = ?,
                    high_water_rows = MAX(high_water_rows, ?),
                    high_water_bytes = MAX(high_water_bytes, ?)
                WHERE singleton = ?""",
                (
                    candidate_rows,
                    candidate_bytes,
                    high_water_rows,
                    high_water_bytes,
                    1,
                ),
            )
            if self._source_finalization_bound:
                self._commit_journal_unlocked()
            else:
                conn.commit()
        except BaseException:
            retained_rows = conn.execute(
                """SELECT sequence, sort_key, phase, payload, payload_bytes
                   FROM events WHERE sequence >= ? AND sequence < ? ORDER BY sequence""",
                (start_sequence, start_sequence + len(rows)),
            ).fetchall()
            retained_state = conn.execute(
                """SELECT phase, candidate_rows, candidate_bytes
                   FROM finalization_state WHERE singleton = ?""",
                (1,),
            ).fetchone()
            committed = (
                not conn.in_transaction
                and retained_rows == rows
                and retained_state == ("candidate", candidate_rows, candidate_bytes)
            )
            if not committed:
                conn.rollback()
                raise
        self._spool_sequence = start_sequence + len(rows)
        self._spooled_count += len(rows)
        self._event_dicts.clear()

    def _iter_spooled_events_unlocked(self):
        """Yield spooled Windows events in chronological order while holding _file_lock."""
        if self._spool_conn is None:
            return
        cursor = self._spool_conn.execute(
            "SELECT payload FROM events WHERE phase = ? ORDER BY sort_key, sequence",
            ("candidate",),
        )
        for (payload,) in cursor:
            yield _spool_decode(payload)

    def _iter_spooled_rows_unlocked(self, *, ordered: bool = False):
        """Yield row IDs and decoded Windows events while holding _file_lock."""
        if self._spool_conn is None:
            return
        query = "SELECT sequence, payload FROM events WHERE phase = ?"
        if ordered:
            query += " ORDER BY sort_key, sequence"
        cursor = self._spool_conn.execute(query, ("candidate",))
        for rowid, payload in cursor:
            yield int(rowid), _spool_decode(payload)

    def _iter_spooled_kerberos_rows_unlocked(self):
        """Yield only Security Kerberos (4768/4769) rows from the spool."""
        if self._spool_conn is None:
            return
        cursor = self._spool_conn.execute(
            "SELECT sequence, payload FROM events "
            "WHERE phase = ? AND "
            "CAST(json_extract(payload, '$.fields.EventID.value') AS INTEGER) IN (?, ?)",
            ("candidate", 4768, 4769),
        )
        for rowid, payload in cursor:
            yield int(rowid), _spool_decode(payload)

    def _update_spooled_events_unlocked(self, updates: list[tuple[str, str, int]]) -> None:
        """Persist encoded payload and sort-key updates for spooled Windows events."""
        if not updates or self._spool_conn is None:
            return
        self._spool_conn.executemany(
            "UPDATE events SET payload = ?, payload_bytes = ?, sort_key = ? "
            "WHERE sequence = ? AND phase = ?",
            (
                (payload, len(payload.encode("utf-8")), sort_key, sequence, "candidate")
                for payload, sort_key, sequence in updates
            ),
        )
        if not self._sealing_transaction:
            self._spool_conn.commit()

    def _delete_spooled_events_unlocked(self, rowids: set[int]) -> None:
        """Delete spooled Windows events by row ID."""
        if not rowids or self._spool_conn is None:
            return
        self._spool_conn.executemany(
            "DELETE FROM events WHERE sequence = ? AND phase = ?",
            ((rowid, "candidate") for rowid in rowids),
        )
        if not self._sealing_transaction:
            self._spool_conn.commit()
        self._spooled_count = max(0, self._spooled_count - len(rowids))

    @staticmethod
    def _shift_kerberos_tgts_before_service_ticket_rows(
        rows: list[tuple[int, dict[str, Any]]],
    ) -> set[int]:
        """Move visible 4768 TGT rows before near-term same-principal 4769 rows."""
        ordered = sorted(
            rows,
            key=lambda row: (
                ensure_utc(row[1]["TimeCreated"])
                if isinstance(row[1].get("TimeCreated"), datetime)
                else datetime.max.replace(tzinfo=UTC),
                row[0],
            ),
        )
        tgts_by_key: dict[
            tuple[str, str, str, str], list[tuple[int, dict[str, Any], datetime]]
        ] = {}
        for rowid, event in ordered:
            if event.get("EventID") != 4768:
                continue
            ts = event.get("TimeCreated")
            key = _kerberos_principal_source_key(event)
            if key is not None and isinstance(ts, datetime):
                tgts_by_key.setdefault(key, []).append((rowid, event, ensure_utc(ts)))

        prior_tgt_by_key: dict[tuple[str, str, str, str], datetime] = {}
        moved: set[int] = set()
        for rowid, event in ordered:
            ts = event.get("TimeCreated")
            if not isinstance(ts, datetime):
                continue
            ts = ensure_utc(ts)
            key = _kerberos_principal_source_key(event)
            if key is None:
                continue
            if event.get("EventID") == 4768:
                prior = prior_tgt_by_key.get(key)
                prior_tgt_by_key[key] = min(prior, ts) if prior is not None else ts
                continue
            if event.get("EventID") != 4769:
                continue
            prior = prior_tgt_by_key.get(key)
            if prior is not None and prior <= ts:
                continue
            future_tgt = next(
                (
                    candidate
                    for candidate in tgts_by_key.get(key, [])
                    if candidate[0] not in moved
                    and candidate[1].get("_TimingFinalized") != _FROZEN_TIMING_MARKER
                    and candidate[2] > ts
                    and candidate[2] - ts <= timedelta(seconds=1)
                ),
                None,
            )
            if future_tgt is None:
                continue
            tgt_rowid, tgt_event, _ = future_tgt
            gap_ms = 20 + (
                _stable_seed(f"kerberos_tgt_before_tgs:{key}:{rowid}:{tgt_rowid}:{ts.isoformat()}")
                % 181
            )
            gap_us = 41 + (
                _stable_seed(
                    f"kerberos_tgt_before_tgs_us:{key}:{rowid}:{tgt_rowid}:{ts.isoformat()}"
                )
                % 911
            )
            new_time = ts - timedelta(milliseconds=gap_ms, microseconds=gap_us)
            tgt_event["TimeCreated"] = new_time
            prior_tgt_by_key[key] = new_time
            moved.add(tgt_rowid)
        return moved

    def _shift_kerberos_tgts_before_service_tickets(self) -> None:
        """Prevent in-memory Security 4769 rows from preceding their visible 4768 rows."""
        rows = list(enumerate(self._event_dicts))
        self._shift_kerberos_tgts_before_service_ticket_rows(rows)

    def _shift_spooled_kerberos_tgts_before_service_tickets_unlocked(self) -> None:
        """Prevent spooled Security 4769 rows from preceding their visible 4768 rows."""
        rows = list(self._iter_spooled_kerberos_rows_unlocked())
        if not rows:
            return
        moved = self._shift_kerberos_tgts_before_service_ticket_rows(rows)
        if not moved:
            return
        updates = [
            (_spool_encode(event), self._event_sort_key(event), rowid)
            for rowid, event in rows
            if rowid in moved
        ]
        self._update_spooled_events_unlocked(updates)

    def _shift_spooled_process_creates_after_visible_parent_unlocked(self) -> None:
        """Prevent spooled Security 4688 children from preceding parent 4688 rows."""
        process_create_events: dict[tuple[str, str], int] = {}
        parent_keys: dict[tuple[str, str], tuple[str, str]] = {}
        for rowid, event in self._iter_spooled_rows_unlocked():
            if event.get("EventID") != 4688:
                continue
            ts = event.get("TimeCreated")
            process_pid = str(event.get("NewProcessId") or "").lower()
            computer = str(event.get("Computer", ""))
            if not isinstance(ts, datetime) or not process_pid or process_pid in {"0x0", "0x4"}:
                continue
            key = (computer, process_pid)
            process_create_events[key] = rowid
            parent_pid = str(event.get("ProcessId") or "").lower()
            if parent_pid and parent_pid not in {"0x0", "0x4", "-"}:
                parent_keys[key] = (computer, parent_pid)

        if not process_create_events:
            return

        cyclic_keys = self._detect_process_parent_cycles(process_create_events, parent_keys)
        max_passes = len(process_create_events)
        for _ in range(max_passes):
            process_create_times: dict[tuple[str, str], datetime] = {}
            for _, event in self._iter_spooled_rows_unlocked():
                if event.get("EventID") != 4688:
                    continue
                ts = event.get("TimeCreated")
                process_pid = str(event.get("NewProcessId") or "").lower()
                computer = str(event.get("Computer", ""))
                key = (computer, process_pid)
                if isinstance(ts, datetime) and key in process_create_events:
                    process_create_times[key] = ts

            changed = False
            updates: list[tuple[str, str, int]] = []
            for rowid, event in self._iter_spooled_rows_unlocked():
                if event.get("EventID") != 4688 or self._timing_is_finalized(event):
                    continue
                ts = event.get("TimeCreated")
                process_pid = str(event.get("NewProcessId") or "").lower()
                computer = str(event.get("Computer", ""))
                key = (computer, process_pid)
                parent_key = parent_keys.get(key)
                if (
                    not isinstance(ts, datetime)
                    or key in cyclic_keys
                    or parent_key is None
                    or parent_key in cyclic_keys
                ):
                    continue
                parent_time = process_create_times.get(parent_key)
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

    def _shift_spooled_process_creates_after_logons_unlocked(self) -> None:
        """Prevent spooled Security 4688 rows from preceding same-session 4624 rows."""
        logon_times: dict[tuple[str, str], datetime] = {}
        for _, event in self._iter_spooled_rows_unlocked():
            if event.get("EventID") != 4624 or str(event.get("LogonType") or "") == "7":
                continue
            ts = event.get("TimeCreated")
            logon_id = str(event.get("TargetLogonId") or "")
            key = (str(event.get("Computer", "")), logon_id)
            if isinstance(ts, datetime) and logon_id:
                logon_times[key] = min(ts, logon_times.get(key, ts))

        updates: list[tuple[str, str, int]] = []
        for rowid, event in self._iter_spooled_rows_unlocked():
            ts = event.get("TimeCreated")
            if (
                not isinstance(ts, datetime)
                or event.get("EventID") != 4688
                or self._timing_is_finalized(event)
            ):
                continue
            logon_id = str(event.get("SubjectLogonId") or "")
            if not logon_id or logon_id in {"0x3e7", "0x3e4", "0x3e5", "-"}:
                continue
            key = (str(event.get("Computer", "")), logon_id)
            logon_time = logon_times.get(key)
            if logon_time is not None and ts <= logon_time:
                event["TimeCreated"] = logon_time + timedelta(milliseconds=1)
                updates.append((_spool_encode(event), self._event_sort_key(event), rowid))
                if len(updates) >= 1000:
                    self._update_spooled_events_unlocked(updates)
                    updates.clear()
        self._update_spooled_events_unlocked(updates)

    def _shift_spooled_network_logons_after_transport_unlocked(self) -> None:
        """Keep remote 4624 rows after visible same-tuple WFP 5156 rows."""

        transport_times: dict[tuple[str, str, str], list[datetime]] = {}
        for _, event in self._iter_spooled_rows_unlocked():
            if event.get("EventID") != 5156:
                continue
            if str(event.get("Protocol") or "6") != "6":
                continue
            if str(event.get("Direction") or "%%14592") != "%%14592":
                continue
            ts = event.get("TimeCreated")
            key = _windows_auth_transport_tuple(event)
            if isinstance(ts, datetime) and key is not None:
                transport_times.setdefault(key, []).append(ts)

        updates: list[tuple[str, str, int]] = []
        for rowid, event in self._iter_spooled_rows_unlocked():
            if (
                event.get("EventID") != 4624
                or str(event.get("LogonType") or "") not in {"3", "10"}
                or self._timing_is_finalized(event)
            ):
                continue
            ts = event.get("TimeCreated")
            key = _windows_auth_transport_tuple(event)
            transport_time = (
                _nearest_auth_transport_time(transport_times, key, ts)
                if key is not None and isinstance(ts, datetime)
                else None
            )
            if isinstance(ts, datetime) and transport_time is not None and ts <= transport_time:
                event["TimeCreated"] = compatibility_relationship_time(
                    transport_time,
                    relationship_key="windows.network_logon_after_transport",
                    identity_parts=(*key, transport_time),
                )
                updates.append((_spool_encode(event), self._event_sort_key(event), rowid))
                if len(updates) >= 1000:
                    self._update_spooled_events_unlocked(updates)
                    updates.clear()
        self._update_spooled_events_unlocked(updates)

    def _shift_spooled_special_privileges_after_logons_unlocked(self) -> None:
        """Keep each spooled 4672 after its triggering 4624 occurrence."""
        occurrence_times: dict[str, datetime] = {}
        session_times: dict[tuple[str, str], list[datetime]] = {}
        for _, event in self._iter_spooled_rows_unlocked():
            if event.get("EventID") != 4624:
                continue
            ts = event.get("TimeCreated")
            key = _windows_logon_session_key(event, "TargetLogonId")
            if isinstance(ts, datetime) and key is not None:
                session_times.setdefault(key, []).append(ts)
                occurrence_id = str(event.get("_auth_occurrence_id") or "")
                if occurrence_id:
                    occurrence_times[occurrence_id] = ts

        updates: list[tuple[str, str, int]] = []
        for rowid, event in self._iter_spooled_rows_unlocked():
            if event.get("EventID") != 4672 or self._timing_is_finalized(event):
                continue
            ts = event.get("TimeCreated")
            key = _windows_logon_session_key(event, "SubjectLogonId")
            logon_time = _matching_privilege_logon_time(event, occurrence_times, session_times)
            occurrence_id = str(event.get("_auth_occurrence_id") or "")
            if (
                isinstance(ts, datetime)
                and key is not None
                and logon_time is not None
                and ts <= logon_time
            ):
                event["TimeCreated"] = compatibility_relationship_time(
                    logon_time,
                    relationship_key="windows.special_privilege_after_logon",
                    identity_parts=(
                        (*key, occurrence_id, logon_time) if occurrence_id else (*key, logon_time)
                    ),
                )
                updates.append((_spool_encode(event), self._event_sort_key(event), rowid))
                if len(updates) >= 1000:
                    self._update_spooled_events_unlocked(updates)
                    updates.clear()
        self._update_spooled_events_unlocked(updates)

    def _shift_spooled_logoffs_after_dependents_unlocked(self) -> None:
        """Prevent spooled 4634 records from preceding same-session source prerequisites."""
        latest_dependent: dict[tuple[str, str], datetime] = {}
        for _, event in self._iter_spooled_rows_unlocked():
            ts = event.get("TimeCreated")
            if not isinstance(ts, datetime):
                continue
            event_id = event.get("EventID")
            if event_id not in {4624, 4688, 4689, 4801}:
                continue
            logon_id = str(
                event.get("TargetLogonId" if event_id in {4624, 4801} else "SubjectLogonId")
                or event.get("SubjectLogonId")
                or event.get("TargetLogonId")
                or ""
            )
            if not logon_id or logon_id in {"0x3e7", "0x3e4", "0x3e5", "-"}:
                continue
            key = (str(event.get("Computer", "")), logon_id)
            latest_dependent[key] = max(ts, latest_dependent.get(key, ts))

        updates: list[tuple[str, str, int]] = []
        for rowid, event in self._iter_spooled_rows_unlocked():
            ts = event.get("TimeCreated")
            if (
                not isinstance(ts, datetime)
                or event.get("EventID") != 4634
                or self._timing_is_finalized(event)
            ):
                continue
            logon_id = str(event.get("TargetLogonId") or event.get("SubjectLogonId") or "")
            key = (str(event.get("Computer", "")), logon_id)
            latest = latest_dependent.get(key)
            if logon_id and latest is not None and ts <= latest:
                event["TimeCreated"] = compatibility_relationship_time(
                    latest,
                    relationship_key="windows.logoff_after_rendered_dependents",
                    identity_parts=(key[0], key[1], latest),
                )
                updates.append((_spool_encode(event), self._event_sort_key(event), rowid))
                if len(updates) >= 1000:
                    self._update_spooled_events_unlocked(updates)
                    updates.clear()
        self._update_spooled_events_unlocked(updates)

    def _shift_spooled_process_terminations_after_dependents_unlocked(self) -> None:
        """Keep spooled Security 4689 events after visible process dependents."""
        latest_child_create: dict[tuple[str, str], datetime] = {}
        latest_same_process_dependent: dict[tuple[str, str, str], datetime] = {}
        for _, event in self._iter_spooled_rows_unlocked():
            ts = event.get("TimeCreated")
            if not isinstance(ts, datetime):
                continue
            computer = str(event.get("Computer", ""))
            if event.get("EventID") == 4688:
                parent_pid = str(event.get("ProcessId") or "")
                if parent_pid and parent_pid not in {"0x0", "0x4", "-"}:
                    key = (computer, parent_pid.lower())
                    latest_child_create[key] = max(ts, latest_child_create.get(key, ts))
            elif event.get("EventID") == 5156:
                key = _security_process_key(
                    computer,
                    event.get("ProcessID"),
                    event.get("Application"),
                )
                if key is not None:
                    latest_same_process_dependent[key] = max(
                        ts,
                        latest_same_process_dependent.get(key, ts),
                    )

        updates: list[tuple[str, str, int]] = []
        for rowid, event in self._iter_spooled_rows_unlocked():
            ts = event.get("TimeCreated")
            if (
                not isinstance(ts, datetime)
                or event.get("EventID") != 4689
                or self._timing_is_finalized(event)
            ):
                continue
            process_pid = str(event.get("ProcessId") or "")
            computer = str(event.get("Computer", ""))
            child_key = (computer, process_pid.lower())
            process_key = _security_process_key(
                computer,
                event.get("ProcessId"),
                event.get("ProcessName"),
            )
            candidates: list[tuple[datetime, str, tuple[Any, ...]]] = []
            latest_child = latest_child_create.get(child_key)
            if process_pid and latest_child is not None:
                candidates.append(
                    (
                        latest_child,
                        "windows.process_exit_after_visible_child",
                        (child_key[0], child_key[1], latest_child),
                    )
                )
            if process_key is not None:
                latest_dependent = latest_same_process_dependent.get(process_key)
                if latest_dependent is not None:
                    candidates.append(
                        (
                            latest_dependent,
                            "windows.process_exit_after_visible_dependent",
                            (
                                process_key[0],
                                process_key[1],
                                process_key[2],
                                latest_dependent,
                            ),
                        )
                    )
            if not candidates:
                continue
            latest, relationship_key, seed_parts = max(candidates, key=lambda item: item[0])
            if ts <= latest:
                event["TimeCreated"] = compatibility_relationship_time(
                    latest,
                    relationship_key=relationship_key,
                    identity_parts=seed_parts,
                )
                updates.append((_spool_encode(event), self._event_sort_key(event), rowid))
                if len(updates) >= 1000:
                    self._update_spooled_events_unlocked(updates)
                    updates.clear()
        self._update_spooled_events_unlocked(updates)

    def _shift_spooled_process_dependents_after_create_unlocked(self) -> None:
        """Keep spooled same-process Security dependents after visible 4688 rows."""
        process_create_times: dict[tuple[str, str, str], datetime] = {}
        for _, event in self._iter_spooled_rows_unlocked():
            if event.get("EventID") != 4688:
                continue
            ts = event.get("TimeCreated")
            key = _security_process_key(
                str(event.get("Computer", "")),
                event.get("NewProcessId"),
                event.get("NewProcessName"),
            )
            if isinstance(ts, datetime) and key is not None:
                process_create_times[key] = ts

        updates: list[tuple[str, str, int]] = []
        for rowid, event in self._iter_spooled_rows_unlocked():
            ts = event.get("TimeCreated")
            event_id = event.get("EventID")
            if (
                not isinstance(ts, datetime)
                or event_id not in {4689, 5156}
                or self._timing_is_finalized(event)
            ):
                continue
            if event_id == 4689:
                key = _security_process_key(
                    str(event.get("Computer", "")),
                    event.get("ProcessId"),
                    event.get("ProcessName"),
                )
                relationship_key = "windows.process_exit_after_visible_create"
            else:
                key = _security_process_key(
                    str(event.get("Computer", "")),
                    event.get("ProcessID"),
                    event.get("Application"),
                )
                relationship_key = "source.windows_wfp_connection"
            create_time = process_create_times.get(key) if key is not None else None
            if create_time is not None and ts <= create_time:
                event["TimeCreated"] = compatibility_relationship_time(
                    create_time,
                    relationship_key=relationship_key,
                    identity_parts=(key[0], key[1], key[2], create_time),
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
        dropped_unlocks_by_session: dict[tuple[str, str], list[datetime]] = {}

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
                    _record_dropped_unlock(
                        dropped_unlocks_by_session, computer, logon_id, ensure_utc(ts)
                    )
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
            if _has_nearby_dropped_unlock(dropped_unlocks_by_session, computer, logon_id, ts):
                dropped_rowids.add(rowid)

        self._delete_spooled_events_unlocked(dropped_rowids)

    def _cleanup_spool_unlocked(self) -> None:
        """Remove the exact private journal after terminal source close."""

        if self._spool_conn is not None:
            self._spool_conn.close()
            self._spool_conn = None
        if not self._source_finalization_bound:
            if self._spool_path is not None:
                for candidate in (
                    self._spool_path,
                    *(Path(f"{self._spool_path}{suffix}") for suffix in _SQLITE_COMPANION_SUFFIXES),
                ):
                    candidate.unlink(missing_ok=True)
            if self._owns_spool_dir and self._spool_dir is not None:
                if any(self._spool_dir.iterdir()):
                    raise ExactPublicationError(
                        "Windows legacy spool contains an unexpected entry at cleanup"
                    )
                os.rmdir(self._spool_dir)
            self._spool_path = None
            self._spool_filename = None
            self._spool_dir = None
            self._owns_spool_dir = False
            self._spooled_count = 0
            self._candidate_admitted_rows = 0
            self._candidate_admitted_bytes = 0
            return
        descriptor = self._spool_directory_descriptor
        filename = self._spool_filename
        if descriptor is not None:
            self._validate_spool_directory_unlocked()
        if descriptor is not None and filename is not None:
            for candidate in (
                filename,
                *(filename + suffix for suffix in _SQLITE_COMPANION_SUFFIXES),
            ):
                try:
                    metadata = os.stat(candidate, dir_fd=descriptor, follow_symlinks=False)
                except FileNotFoundError:
                    continue
                if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
                    raise ExactPublicationError(
                        "Windows private journal cleanup found a non-regular entry"
                    )
                if (
                    candidate == filename
                    and (int(metadata.st_dev), int(metadata.st_ino)) != self._spool_file_identity
                ):
                    raise ExactPublicationError(
                        "Windows private journal changed before terminal cleanup"
                    )
                os.unlink(candidate, dir_fd=descriptor)
            os.fsync(descriptor)
        if descriptor is not None:
            os.close(descriptor)
            self._spool_directory_descriptor = None
        root_descriptor = self._spool_root_descriptor
        directory_name = self._spool_directory_name
        if self._owns_spool_dir and root_descriptor is not None and directory_name is not None:
            try:
                metadata = os.stat(
                    directory_name,
                    dir_fd=root_descriptor,
                    follow_symlinks=False,
                )
            except FileNotFoundError:
                metadata = None
            if metadata is not None:
                if (
                    not stat.S_ISDIR(metadata.st_mode)
                    or (int(metadata.st_dev), int(metadata.st_ino))
                    != self._spool_directory_identity
                ):
                    raise ExactPublicationError(
                        "Windows private spool changed before terminal directory cleanup"
                    )
                os.rmdir(directory_name, dir_fd=root_descriptor)
            os.fsync(root_descriptor)
            os.close(root_descriptor)
            self._spool_root_descriptor = None
        self._spool_path = None
        self._spool_filename = None
        self._spool_file_identity = None
        self._spool_file_initialization_pending = False
        self._spool_directory_identity = None
        self._spool_root_identity = None
        self._spool_directory_name = None
        self._spool_dir = None
        self._owns_spool_dir = False
        self._spooled_count = 0
        self._candidate_admitted_rows = 0
        self._candidate_admitted_bytes = 0

    def _snapshot_render_state(self) -> _WindowsRenderState:
        """Copy source-native mutable state so a failed seal cannot advance it."""

        return _WindowsRenderState(
            record_id_sequences=deepcopy(self._record_id_sequences),
            last_time_created_by_computer=dict(self._last_time_created_by_computer),
            last_record_time_created_by_computer=dict(self._last_record_time_created_by_computer),
            time_collision_count_by_computer=dict(self._time_collision_count_by_computer),
            lock_lifecycle_shift_by_session=dict(self._lock_lifecycle_shift_by_session),
            rendered_lock_time_by_session=dict(self._rendered_lock_time_by_session),
        )

    def _adopt_render_state(self, state: _WindowsRenderState) -> None:
        """Adopt source-native state only after the immutable journal commits."""

        self._record_id_sequences = state.record_id_sequences
        self._last_time_created_by_computer = state.last_time_created_by_computer
        self._last_record_time_created_by_computer = state.last_record_time_created_by_computer
        self._time_collision_count_by_computer = state.time_collision_count_by_computer
        self._lock_lifecycle_shift_by_session = state.lock_lifecycle_shift_by_session
        self._rendered_lock_time_by_session = state.rendered_lock_time_by_session

    def _finalize_event_for_output(
        self,
        event: dict[str, Any],
        sequence: int,
        state: _WindowsRenderState,
    ) -> tuple[str, str, _SingleHostWriter, str] | None:
        """Apply legacy source fixups and render one final immutable output string."""

        source_state, _ = self._source_lifecycle_snapshot()
        terminal = self._source_finalization_bound and source_state != "open"
        output_target = self._source_finalization_output_target if terminal else self.output_target
        if output_target is None:
            raise SourceFinalizationError("Windows final output target was not frozen")
        timing_finalized = self._timing_is_finalized(event)
        if not timing_finalized:
            _shift_windows_lock_lifecycle_after_rendered_clock(
                event,
                state.last_time_created_by_computer,
                state.lock_lifecycle_shift_by_session,
            )
            _normalize_windows_time_created(
                event,
                state.last_time_created_by_computer,
                state.time_collision_count_by_computer,
                sequence,
                "windows_time_created",
            )
            _enforce_windows_lock_dwell_after_normalization(
                event,
                state.rendered_lock_time_by_session,
            )
        normalized_event_time = event.get("TimeCreated")
        event_computer = str(event.get("Computer", ""))
        if isinstance(normalized_event_time, datetime) and event_computer:
            previous_event_time = state.last_time_created_by_computer.get(event_computer)
            if previous_event_time is None or normalized_event_time > previous_event_time:
                state.last_time_created_by_computer[event_computer] = normalized_event_time
        computer = sanitize_path_component(event.get("Computer", ""))
        counter_key = computer.split(".")[0] if "." in computer else computer
        sequence_model = state.record_id_sequences.setdefault(
            counter_key,
            WindowsRecordIdSequence(
                "security",
                counter_key,
                str(event.get("_host_type") or ""),
            ),
        )
        event["EventRecordID"] = sequence_model.next(
            event.get("TimeCreated"),
            coerce_windows_event_id(event.get("EventID")),
        )
        normalized_time = event.get("TimeCreated")
        if isinstance(normalized_time, datetime):
            current_time = ensure_utc(normalized_time)
            previous_record_time = state.last_record_time_created_by_computer.get(counter_key)
            if (
                not timing_finalized
                and previous_record_time is not None
                and current_time <= previous_record_time
            ):
                current_time = previous_record_time + timedelta(microseconds=1)
                event["TimeCreated"] = current_time
            if previous_record_time is None or current_time > previous_record_time:
                state.last_record_time_created_by_computer[counter_key] = current_time

        host_fqdn = str(event.get("Computer") or "")
        if not host_fqdn and not self._direct_file_path:
            return None
        snare_timestamp = event.get("TimeCreated")
        event.pop("_TimingFinalized", None)
        if output_target == OutputTarget.SOF_ELK and isinstance(snare_timestamp, datetime):
            route_key = sanitize_syslog_family_route_key(
                make_syslog_family_route_key(
                    host_fqdn or "default",
                    snare_timestamp,
                    direct_file_mode=self._direct_file_mode,
                )
            )
            writer = self._get_snare_writer_for_route_key(route_key)
            return (
                "snare",
                "" if self._direct_file_mode else route_key,
                writer,
                render_windows_security_snare_syslog(event),
            )
        if output_target in {OutputTarget.DEFAULT, OutputTarget.SPLUNK}:
            route_key = "" if self._direct_file_mode else sanitize_path_component(host_fqdn)
            rendered = self._render_event(event)
            if output_target == OutputTarget.SPLUNK:
                rendered = compact_windows_event_xml(rendered)
            return ("xml", route_key, self._get_host_writer(host_fqdn), rendered)
        return None

    def _flush_unlocked(self) -> None:
        """Sort events, assign RecordIDs, render, and write to per-host files."""
        if not self._event_dicts and self._spooled_count == 0:
            return

        if self._spooled_count:
            self._spool_event_dicts_unlocked()
            all_finalized = all(
                self._timing_is_finalized(event) for _, event in self._iter_spooled_rows_unlocked()
            )
            if not all_finalized:
                self._shift_spooled_kerberos_tgts_before_service_tickets_unlocked()
                self._shift_spooled_process_creates_after_logons_unlocked()
                self._shift_spooled_process_creates_after_visible_parent_unlocked()
                self._shift_spooled_process_dependents_after_create_unlocked()
                self._shift_spooled_special_privileges_after_logons_unlocked()
                self._shift_spooled_process_terminations_after_dependents_unlocked()
            self._suppress_spooled_duplicate_lock_unlock_transitions_unlocked()
            events = self._iter_spooled_events_unlocked()
        else:
            all_finalized = all(self._timing_is_finalized(event) for event in self._event_dicts)
            if not all_finalized:
                self._shift_kerberos_tgts_before_service_tickets()
                self._shift_process_creates_after_logons()
                self._shift_process_creates_after_visible_parent()
                self._shift_process_dependents_after_create()
                self._shift_special_privileges_after_logons()
                self._shift_process_terminations_after_dependents()
            self._suppress_duplicate_lock_unlock_transitions()

            def _sort_key(event: dict) -> Any:
                ts = event.get("TimeCreated", "")
                if isinstance(ts, datetime):
                    return ensure_utc(ts)
                return ts

            self._event_dicts.sort(key=_sort_key)
            events = iter(self._event_dicts)

        render_state = _WindowsRenderState(
            record_id_sequences=self._record_id_sequences,
            last_time_created_by_computer=self._last_time_created_by_computer,
            last_record_time_created_by_computer=self._last_record_time_created_by_computer,
            time_collision_count_by_computer=self._time_collision_count_by_computer,
            lock_lifecycle_shift_by_session=self._lock_lifecycle_shift_by_session,
            rendered_lock_time_by_session=self._rendered_lock_time_by_session,
        )

        # Assign per-computer EventRecordIDs in sorted order.
        for sequence, event in enumerate(events):
            final = self._finalize_event_for_output(event, sequence, render_state)
            if final is not None:
                final[2].write(final[3])

        self._event_dicts.clear()
        self._cleanup_spool_unlocked()

    def _shift_logoffs_after_dependents(self) -> None:
        """Prevent visible 4634 records from preceding same-session source prerequisites.

        Sysmon and EDR sources render small source-native collection offsets after
        canonical process lifecycle events. A visible Security logoff needs to clear
        that offset window and its own rendered 4624 row, not just the Security
        4688 timestamp.
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
                if logon_id and not self._timing_is_finalized(event):
                    logoffs.append(((computer, logon_id), event))
                continue
            if event_id not in {4624, 4688, 4689, 4801}:
                continue
            logon_id = str(
                event.get("TargetLogonId" if event_id in {4624, 4801} else "SubjectLogonId")
                or event.get("SubjectLogonId")
                or event.get("TargetLogonId")
                or ""
            )
            if not logon_id or logon_id in {"0x3e7", "0x3e4", "0x3e5", "-"}:
                continue
            key = (computer, logon_id)
            latest_dependent[key] = max(ts, latest_dependent.get(key, ts))

        for key, event in logoffs:
            ts = event.get("TimeCreated")
            latest = latest_dependent.get(key)
            if isinstance(ts, datetime) and latest is not None and ts <= latest:
                event["TimeCreated"] = compatibility_relationship_time(
                    latest,
                    relationship_key="windows.logoff_after_rendered_dependents",
                    identity_parts=(key[0], key[1], latest),
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
        dropped_unlocks_by_session: dict[tuple[str, str], list[datetime]] = {}

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
                    _record_dropped_unlock(
                        dropped_unlocks_by_session, computer, logon_id, ensure_utc(ts)
                    )
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
            if _has_nearby_dropped_unlock(dropped_unlocks_by_session, computer, logon_id, ts):
                dropped_indexes.add(index)

        if dropped_indexes:
            self._event_dicts = [
                event
                for index, event in enumerate(self._event_dicts)
                if index not in dropped_indexes
            ]

    def _shift_process_creates_after_logons(self) -> None:
        """Prevent visible Security 4688 rows from preceding same-session 4624 rows."""
        logon_times: dict[tuple[str, str], datetime] = {}
        for event in self._event_dicts:
            if event.get("EventID") != 4624 or str(event.get("LogonType") or "") == "7":
                continue
            ts = event.get("TimeCreated")
            logon_id = str(event.get("TargetLogonId") or "")
            key = (str(event.get("Computer", "")), logon_id)
            if isinstance(ts, datetime) and logon_id:
                logon_times[key] = min(ts, logon_times.get(key, ts))

        for event in self._event_dicts:
            ts = event.get("TimeCreated")
            if (
                not isinstance(ts, datetime)
                or event.get("EventID") != 4688
                or self._timing_is_finalized(event)
            ):
                continue
            logon_id = str(event.get("SubjectLogonId") or "")
            if not logon_id or logon_id in {"0x3e7", "0x3e4", "0x3e5", "-"}:
                continue
            key = (str(event.get("Computer", "")), logon_id)
            logon_time = logon_times.get(key)
            if logon_time is not None and ts <= logon_time:
                event["TimeCreated"] = logon_time + timedelta(milliseconds=1)

    def _shift_network_logons_after_transport(self) -> None:
        """Keep remote 4624 rows after visible same-tuple WFP 5156 rows."""

        transport_times: dict[tuple[str, str, str], list[datetime]] = {}
        for event in self._event_dicts:
            if event.get("EventID") != 5156:
                continue
            if str(event.get("Protocol") or "6") != "6":
                continue
            if str(event.get("Direction") or "%%14592") != "%%14592":
                continue
            ts = event.get("TimeCreated")
            key = _windows_auth_transport_tuple(event)
            if isinstance(ts, datetime) and key is not None:
                transport_times.setdefault(key, []).append(ts)

        for event in self._event_dicts:
            if (
                event.get("EventID") != 4624
                or str(event.get("LogonType") or "") not in {"3", "10"}
                or self._timing_is_finalized(event)
            ):
                continue
            ts = event.get("TimeCreated")
            key = _windows_auth_transport_tuple(event)
            transport_time = (
                _nearest_auth_transport_time(transport_times, key, ts)
                if key is not None and isinstance(ts, datetime)
                else None
            )
            if isinstance(ts, datetime) and transport_time is not None and ts <= transport_time:
                event["TimeCreated"] = compatibility_relationship_time(
                    transport_time,
                    relationship_key="windows.network_logon_after_transport",
                    identity_parts=(*key, transport_time),
                )

    def _shift_special_privileges_after_logons(self) -> None:
        """Keep each 4672 after its triggering same-session 4624 occurrence."""
        occurrence_times: dict[str, datetime] = {}
        session_times: dict[tuple[str, str], list[datetime]] = {}
        for event in self._event_dicts:
            if event.get("EventID") != 4624:
                continue
            ts = event.get("TimeCreated")
            key = _windows_logon_session_key(event, "TargetLogonId")
            if isinstance(ts, datetime) and key is not None:
                session_times.setdefault(key, []).append(ts)
                occurrence_id = str(event.get("_auth_occurrence_id") or "")
                if occurrence_id:
                    occurrence_times[occurrence_id] = ts

        for event in self._event_dicts:
            if event.get("EventID") != 4672 or self._timing_is_finalized(event):
                continue
            ts = event.get("TimeCreated")
            key = _windows_logon_session_key(event, "SubjectLogonId")
            logon_time = _matching_privilege_logon_time(event, occurrence_times, session_times)
            occurrence_id = str(event.get("_auth_occurrence_id") or "")
            if (
                isinstance(ts, datetime)
                and key is not None
                and logon_time is not None
                and ts <= logon_time
            ):
                event["TimeCreated"] = compatibility_relationship_time(
                    logon_time,
                    relationship_key="windows.special_privilege_after_logon",
                    identity_parts=(
                        (*key, occurrence_id, logon_time) if occurrence_id else (*key, logon_time)
                    ),
                )

    @staticmethod
    def _detect_process_parent_cycles(
        process_create_events: dict[tuple[str, str], Any],
        parent_keys: dict[tuple[str, str], tuple[str, str]],
    ) -> set[tuple[str, str]]:
        """Return process-create keys that are part of visible parent cycles."""
        cyclic_keys: set[tuple[str, str]] = set()
        for key in process_create_events:
            path: list[tuple[str, str]] = []
            seen: set[tuple[str, str]] = set()
            current: tuple[str, str] | None = key
            while current is not None:
                if current in seen:
                    cyclic_keys.update(path[path.index(current) :])
                    break
                if current in cyclic_keys:
                    break
                seen.add(current)
                path.append(current)
                parent_key = parent_keys.get(current)
                current = parent_key if parent_key in process_create_events else None
        return cyclic_keys

    def _shift_process_creates_after_visible_parent(self) -> None:
        """Prevent visible Security 4688 children from preceding parent 4688 rows."""
        process_create_events: dict[tuple[str, str], dict[str, Any]] = {}
        parent_keys: dict[tuple[str, str], tuple[str, str]] = {}

        for event in self._event_dicts:
            if event.get("EventID") != 4688:
                continue
            ts = event.get("TimeCreated")
            process_pid = str(event.get("NewProcessId") or "").lower()
            computer = str(event.get("Computer", ""))
            if not isinstance(ts, datetime) or not process_pid or process_pid in {"0x0", "0x4"}:
                continue
            key = (computer, process_pid)
            process_create_events[key] = event
            parent_pid = str(event.get("ProcessId") or "").lower()
            if parent_pid and parent_pid not in {"0x0", "0x4", "-"}:
                parent_keys[key] = (computer, parent_pid)

        if not process_create_events:
            return

        cyclic_keys = self._detect_process_parent_cycles(process_create_events, parent_keys)
        max_passes = len(process_create_events)
        for _ in range(max_passes):
            changed = False
            process_create_times: dict[tuple[str, str], datetime] = {}
            for key, event in process_create_events.items():
                ts = event.get("TimeCreated")
                if isinstance(ts, datetime):
                    process_create_times[key] = ts

            for key, event in process_create_events.items():
                if key in cyclic_keys or self._timing_is_finalized(event):
                    continue
                ts = event.get("TimeCreated")
                parent_key = parent_keys.get(key)
                if not isinstance(ts, datetime) or parent_key is None or parent_key in cyclic_keys:
                    continue
                parent_time = process_create_times.get(parent_key)
                if parent_time is not None and ts <= parent_time:
                    event["TimeCreated"] = parent_time + timedelta(milliseconds=1)
                    changed = True
            if not changed:
                break

    def _shift_process_terminations_after_dependents(self) -> None:
        """Keep Security 4689 aligned with visible process lifecycle dependents.

        Sysmon Event 5 already moves after visible same-process follow-on
        telemetry. Security 4689 needs the same source-native lifecycle truth for
        parent processes that visibly spawn children and for same-process
        dependents such as WFP 5156 connection rows.
        """
        latest_child_create: dict[tuple[str, str], datetime] = {}
        latest_same_process_dependent: dict[tuple[str, str, str], datetime] = {}
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
            elif event_id == 5156:
                key = _security_process_key(
                    computer,
                    event.get("ProcessID"),
                    event.get("Application"),
                )
                if key is not None:
                    latest_same_process_dependent[key] = max(
                        ts,
                        latest_same_process_dependent.get(key, ts),
                    )
            elif event_id == 4689:
                process_pid = str(event.get("ProcessId") or "")
                if process_pid and not self._timing_is_finalized(event):
                    terminations.append(((computer, process_pid.lower()), event))

        for child_key, event in terminations:
            ts = event.get("TimeCreated")
            if not isinstance(ts, datetime):
                continue
            process_key = _security_process_key(
                str(event.get("Computer", "")),
                event.get("ProcessId"),
                event.get("ProcessName"),
            )
            candidates: list[tuple[datetime, str, tuple[Any, ...]]] = []
            latest_child = latest_child_create.get(child_key)
            if latest_child is not None:
                candidates.append(
                    (
                        latest_child,
                        "windows.process_exit_after_visible_child",
                        (child_key[0], child_key[1], latest_child),
                    )
                )
            if process_key is not None:
                latest_dependent = latest_same_process_dependent.get(process_key)
                if latest_dependent is not None:
                    candidates.append(
                        (
                            latest_dependent,
                            "windows.process_exit_after_visible_dependent",
                            (
                                process_key[0],
                                process_key[1],
                                process_key[2],
                                latest_dependent,
                            ),
                        )
                    )
            if not candidates:
                continue
            latest, relationship_key, seed_parts = max(candidates, key=lambda item: item[0])
            if ts <= latest:
                event["TimeCreated"] = compatibility_relationship_time(
                    latest,
                    relationship_key=relationship_key,
                    identity_parts=seed_parts,
                )

    def _shift_process_dependents_after_create(self) -> None:
        """Keep same-process Security dependents after visible 4688 rows."""
        process_create_times: dict[tuple[str, str, str], datetime] = {}
        for event in self._event_dicts:
            if event.get("EventID") != 4688:
                continue
            ts = event.get("TimeCreated")
            key = _security_process_key(
                str(event.get("Computer", "")),
                event.get("NewProcessId"),
                event.get("NewProcessName"),
            )
            if isinstance(ts, datetime) and key is not None:
                process_create_times[key] = ts

        for event in self._event_dicts:
            ts = event.get("TimeCreated")
            event_id = event.get("EventID")
            if (
                not isinstance(ts, datetime)
                or event_id not in {4689, 5156}
                or self._timing_is_finalized(event)
            ):
                continue
            if event_id == 4689:
                key = _security_process_key(
                    str(event.get("Computer", "")),
                    event.get("ProcessId"),
                    event.get("ProcessName"),
                )
                relationship_key = "windows.process_exit_after_visible_create"
            else:
                key = _security_process_key(
                    str(event.get("Computer", "")),
                    event.get("ProcessID"),
                    event.get("Application"),
                )
                relationship_key = "source.windows_wfp_connection"
            create_time = process_create_times.get(key) if key is not None else None
            if create_time is not None and ts <= create_time:
                event["TimeCreated"] = compatibility_relationship_time(
                    create_time,
                    relationship_key=relationship_key,
                    identity_parts=(key[0], key[1], key[2], create_time),
                )

    def _source_lifecycle_snapshot(self) -> tuple[str, int | None]:
        """Read source owner state under the shared close admission lock."""

        with self._close_condition:
            return self._source_finalization_state, self._source_finalization_owner

    @contextmanager
    def _source_finalization_operation(self) -> Iterator[None]:
        """Fence one terminal mutation while allowing sequential thread transfer."""

        if not self._source_finalization_operation_lock.acquire(blocking=False):
            raise SourceFinalizationError(
                "Windows source finalization already has an active owner operation"
            )
        owner = get_ident()
        try:
            with self._close_condition:
                if self._source_finalization_owner is not None:
                    raise SourceFinalizationError(
                        "Windows source finalization retained a stale operation owner"
                    )
                self._source_finalization_owner = owner
            yield
        finally:
            with self._close_condition:
                if self._source_finalization_owner == owner:
                    self._source_finalization_owner = None
                    self._close_condition.notify_all()
            self._source_finalization_operation_lock.release()

    def _set_source_lifecycle_state(self, state: str) -> None:
        """Advance source owner state under the shared close admission lock."""

        with self._close_condition:
            owner = self._source_finalization_owner
            if owner is not None and owner != get_ident():
                raise SourceFinalizationError(
                    "Windows source-finalization state has a different owner"
                )
            self._source_finalization_state = state
            self._close_condition.notify_all()

    def _require_source_owner(self, allowed_states: set[str]) -> str:
        """Require the retained owner for every terminal source mutation entry."""

        state, owner = self._source_lifecycle_snapshot()
        if state not in allowed_states:
            raise SourceFinalizationError(
                f"Windows source-finalization state {state!r} is not mutable here"
            )
        if owner != get_ident():
            raise SourceFinalizationError(
                "Windows source-finalization mutation has a different owner"
            )
        return state

    def barrier_flush(self) -> None:
        """Reject external barriers after terminal source quiescence begins."""

        current = get_ident()
        with self._close_condition:
            state = self._source_finalization_state
            owner = self._source_finalization_owner
            if state != "open" and current != owner:
                raise SourceFinalizationError(
                    "Windows source-finalization rejected a barrier after quiescence"
                )
            if state == "open":
                legacy_close_owner = (
                    self._close_state == "closing" and self._close_thread == current
                )
                if not legacy_close_owner:
                    self._require_accepting_events_locked()
            elif state != "quiescing":
                raise SourceFinalizationError(
                    "Windows source-finalization rejected a terminal barrier"
                )
            self._queue_admissions += 1
        try:
            if self.threaded:
                super().barrier_flush()
            else:
                self._wait_for_exact_publication_turn(None)
                self._flush_at_barrier()
        finally:
            self._finish_queue_admission()

    def quiesce_source_finalization(self) -> None:
        """Reject late candidates, drain FIFO work, and spill without final output."""

        with self._source_finalization_operation():
            self._quiesce_source_finalization()

    def _quiesce_source_finalization(self) -> None:
        """Run source quiescence under the current operation capability."""

        if not self._source_finalization_bound:
            raise SourceFinalizationError(
                "Direct Windows emitters retain legacy close and cannot bind an exact epoch"
            )
        owner = get_ident()
        with self._close_condition:
            state = self._source_finalization_state
            if state in {"quiesced", "sealed", "published", "closed"}:
                return
            if state == "open":
                if self._close_state != "open":
                    raise SourceFinalizationError(
                        "Windows emitter close raced source-finalization quiescence"
                    )
                self._source_finalization_state = "quiescing"
                self._source_finalization_owner = owner
                self._source_finalization_output_target = self.output_target
                self._source_finalization_header = self.format_def.output.header_template or ""
                self._source_finalization_footer = self.format_def.output.footer_template or ""
                self._close_state = "closing"
                self._close_thread = owner
            elif state != "quiescing" or self._source_finalization_owner != owner:
                raise SourceFinalizationError(
                    "Windows source-finalization quiescence has a different owner"
                )
            while self._active_exact_publication_keys or self._queue_admissions:
                self._close_condition.wait()

        if self.threaded:
            self._raise_if_thread_failed()
            self.stop_thread()
            self._raise_if_thread_failed()
        with self._file_lock:
            self._spool_event_dicts_unlocked()
            state = self._journal_state_unlocked()
            with self._candidate_admission_lock:
                admitted_rows = self._candidate_admitted_rows
                admitted_bytes = self._candidate_admitted_bytes
            if (
                str(state[0]) != "candidate"
                or int(state[1]) != admitted_rows
                or int(state[2]) != admitted_bytes
            ):
                raise SourceFinalizationError(
                    "Windows candidate journal does not match admitted source capacity"
                )
        self._set_source_lifecycle_state("quiesced")

    def _journal_state_unlocked(self) -> tuple[Any, ...]:
        """Return the singleton source-journal state while holding `_file_lock`."""

        connection = self._get_spool_conn_unlocked()
        self._validate_spool_file_unlocked()
        row = connection.execute(
            """SELECT phase, candidate_rows, candidate_bytes, final_rows, final_bytes,
                      routes, published_rows, epoch, high_water_rows, high_water_bytes,
                      high_water_routes
               FROM finalization_state WHERE singleton = ?""",
            (1,),
        ).fetchone()
        if row is None:
            raise SourceFinalizationError("Windows source journal lost its singleton state")
        return tuple(row)

    def _commit_journal_unlocked(self) -> None:
        """Commit the private journal through one injectable lost-return boundary."""

        if self._spool_conn is None:
            raise SourceFinalizationError("Windows source journal is not open")
        self._spool_conn.commit()

    def _rollback_journal_unlocked(self) -> None:
        """Roll back an unsealed private-journal transaction."""

        if self._spool_conn is not None:
            self._spool_conn.rollback()

    def _apply_spooled_terminal_fixups_unlocked(self) -> None:
        """Run the complete existing Windows cohort fixup and suppression pass."""

        all_finalized = all(
            self._timing_is_finalized(event) for _, event in self._iter_spooled_rows_unlocked()
        )
        if not all_finalized:
            self._shift_spooled_kerberos_tgts_before_service_tickets_unlocked()
            self._shift_spooled_process_creates_after_logons_unlocked()
            self._shift_spooled_process_creates_after_visible_parent_unlocked()
            self._shift_spooled_process_dependents_after_create_unlocked()
            self._shift_spooled_special_privileges_after_logons_unlocked()
            self._shift_spooled_process_terminations_after_dependents_unlocked()
        self._suppress_spooled_duplicate_lock_unlock_transitions_unlocked()

    def _next_candidate_unlocked(
        self,
        after_sort_key: str | None,
        after_sequence: int,
    ) -> tuple[int, str, dict[str, Any]] | None:
        """Load one chronological candidate without retaining the cohort in Python."""

        if self._spool_conn is None:
            raise SourceFinalizationError("Windows source journal is not open")
        if after_sort_key is None:
            row = self._spool_conn.execute(
                """SELECT sequence, sort_key, payload FROM events
                   WHERE phase = ? ORDER BY sort_key, sequence LIMIT ?""",
                ("candidate", 1),
            ).fetchone()
        else:
            row = self._spool_conn.execute(
                """SELECT sequence, sort_key, payload FROM events
                   WHERE phase = ? AND (sort_key > ? OR (sort_key = ? AND sequence > ?))
                   ORDER BY sort_key, sequence LIMIT ?""",
                ("candidate", after_sort_key, after_sort_key, after_sequence, 1),
            ).fetchone()
        if row is None:
            return None
        return int(row[0]), str(row[1]), _spool_decode(row[2])

    def _route_id_unlocked(
        self,
        route_kind: str,
        route_key: str,
        writer: _SingleHostWriter,
    ) -> int:
        """Retain one already-resolved physical writer under the finite route cap."""

        token = (route_kind, route_key)
        route_id = self._source_finalization_route_ids.get(token)
        if route_id is not None:
            if self._source_finalization_routes.get(route_id) is not writer:
                raise SourceFinalizationError(
                    "Windows source route changed its physical writer during sealing"
                )
            return route_id
        if len(self._source_finalization_route_ids) >= self._finalization_route_capacity:
            raise SourceFinalizationError("Windows finalization route capacity is exhausted")
        route_id = len(self._source_finalization_route_ids)
        self._source_finalization_route_ids[token] = route_id
        self._source_finalization_routes[route_id] = writer
        return route_id

    def _epoch_from_sealed_state_unlocked(
        self,
        epoch_ordinal: int,
    ) -> _WindowsSourceFinalizationEpoch:
        """Return the strongly retained opaque epoch for one committed seal."""

        epoch = self._source_finalization_epoch
        output_target = self._source_finalization_output_target
        header = self._source_finalization_header
        footer = self._source_finalization_footer
        if output_target is None or header is None or footer is None:
            raise SourceFinalizationError("Windows source epoch lost its frozen output contract")
        if epoch is not None:
            if (
                epoch._owner is not self
                or epoch._ordinal != epoch_ordinal
                or epoch._output_target != output_target
                or epoch._header != header
                or epoch._footer != footer
            ):
                raise SourceFinalizationError("Windows source epoch identity changed")
            return epoch
        epoch = _WindowsSourceFinalizationEpoch(
            self,
            epoch_ordinal,
            output_target,
            header,
            footer,
        )
        self._source_finalization_epoch = epoch
        self._source_finalization_ordinal = epoch_ordinal
        return epoch

    def _validate_sealed_journal_unlocked(
        self,
        epoch_ordinal: int,
        *,
        expected_rows: int | None = None,
        expected_bytes: int | None = None,
        expected_routes: int | None = None,
    ) -> tuple[Any, ...]:
        """Stream-validate immutable final rows before adopting a seal lost return."""

        state = self._journal_state_unlocked()
        if str(state[0]) not in {"sealed", "published"} or int(state[7]) != epoch_ordinal:
            raise SourceFinalizationError("Windows source journal did not retain its sealed epoch")
        final_rows = int(state[3])
        final_bytes = int(state[4])
        routes = int(state[5])
        if expected_rows is not None and final_rows != expected_rows:
            raise SourceFinalizationError("Windows sealed row count changed after commit")
        if expected_bytes is not None and final_bytes != expected_bytes:
            raise SourceFinalizationError("Windows sealed byte count changed after commit")
        if expected_routes is not None and routes != expected_routes:
            raise SourceFinalizationError("Windows sealed route count changed after commit")
        if self._spool_conn is None:
            raise SourceFinalizationError("Windows source journal is not open")
        candidate_count = self._spool_conn.execute(
            "SELECT COUNT(*) FROM events WHERE phase = ?",
            ("candidate",),
        ).fetchone()
        if candidate_count != (0,):
            raise SourceFinalizationError("Windows sealed journal retained candidate rows")
        route_tokens: set[tuple[str, str]] = set()
        retained_rows = 0
        retained_bytes = 0
        cursor = self._spool_conn.execute(
            """SELECT ordinal, route_kind, route_key, payload, payload_bytes, payload_digest
               FROM events WHERE phase = ? ORDER BY ordinal""",
            ("final",),
        )
        for ordinal, route_kind, route_key, rendered, payload_bytes, payload_digest in cursor:
            if int(ordinal) != retained_rows:
                raise SourceFinalizationError("Windows sealed journal lost contiguous ordinals")
            if not all(isinstance(value, str) for value in (route_kind, route_key, rendered)):
                raise SourceFinalizationError("Windows sealed journal retained invalid row types")
            encoded = rendered.encode("utf-8")
            if len(encoded) != int(payload_bytes) or hashlib.sha256(encoded).hexdigest() != str(
                payload_digest
            ):
                raise SourceFinalizationError("Windows sealed journal row changed after commit")
            route_tokens.add((route_kind, route_key))
            retained_rows += 1
            retained_bytes += len(encoded)
        if (retained_rows, retained_bytes, len(route_tokens)) != (
            final_rows,
            final_bytes,
            routes,
        ):
            raise SourceFinalizationError("Windows sealed journal scalar state changed")
        if route_tokens != set(self._source_finalization_route_ids):
            raise SourceFinalizationError("Windows sealed journal lost its retained route owners")
        return state

    def seal_source_finalization(self) -> SourceFinalizationEpoch:
        """Seal the complete cohort into immutable routed final strings exactly once."""

        with self._source_finalization_operation():
            return self._seal_source_finalization()

    def _seal_source_finalization(self) -> SourceFinalizationEpoch:
        """Run source sealing under the current operation capability."""

        source_state = self._require_source_owner({"quiesced", "sealed", "published"})
        with self._file_lock:
            state = self._journal_state_unlocked()
            if str(state[0]) in {"sealed", "published"}:
                self._validate_sealed_journal_unlocked(int(state[7]))
                epoch = self._epoch_from_sealed_state_unlocked(int(state[7]))
                if source_state != "published":
                    self._set_source_lifecycle_state(str(state[0]))
                return epoch
            if str(state[0]) != "candidate":
                raise SourceFinalizationError("Windows source journal has an invalid seal phase")

            connection = self._spool_conn
            if connection is None:
                raise SourceFinalizationError("Windows source journal is not open")
            render_state = self._snapshot_render_state()
            initial_host_writer_keys = set(self._host_writers)
            initial_snare_writer_keys = set(self._snare_writers)
            self._source_finalization_routes.clear()
            self._source_finalization_route_ids.clear()
            epoch_ordinal = int(state[7]) + 1
            final_rows = 0
            final_bytes = 0
            processed_rows = 0
            after_sort_key: str | None = None
            after_sequence = -1
            sealed = False
            connection.execute("BEGIN IMMEDIATE")
            self._sealing_transaction = True
            try:
                self._apply_spooled_terminal_fixups_unlocked()
                while True:
                    candidate = self._next_candidate_unlocked(
                        after_sort_key,
                        after_sequence,
                    )
                    if candidate is None:
                        break
                    sequence, sort_key, event = candidate
                    after_sort_key = sort_key
                    after_sequence = sequence
                    final = self._finalize_event_for_output(
                        event,
                        processed_rows,
                        render_state,
                    )
                    processed_rows += 1
                    if final is None:
                        connection.execute(
                            "DELETE FROM events WHERE sequence = ? AND phase = ?",
                            (sequence, "candidate"),
                        )
                        continue
                    route_kind, route_key, writer, rendered = final
                    self._route_id_unlocked(route_kind, route_key, writer)
                    rendered_bytes = len(rendered.encode("utf-8"))
                    if rendered_bytes > _FINALIZATION_CHUNK_BYTES:
                        raise SourceFinalizationError(
                            "Windows final row exceeds the exact publication byte capacity"
                        )
                    final_rows += 1
                    final_bytes += rendered_bytes
                    if final_rows > self._finalization_row_capacity:
                        raise SourceFinalizationError(
                            "Windows finalization row capacity is exhausted"
                        )
                    if final_bytes > self._finalization_byte_capacity:
                        raise SourceFinalizationError(
                            "Windows finalization byte capacity is exhausted"
                        )
                    digest = hashlib.sha256(rendered.encode("utf-8")).hexdigest()
                    updated = connection.execute(
                        """UPDATE events
                           SET phase = ?, payload = ?, payload_bytes = ?, ordinal = ?,
                               route_kind = ?, route_key = ?, payload_digest = ?
                           WHERE sequence = ? AND phase = ?""",
                        (
                            "final",
                            rendered,
                            rendered_bytes,
                            final_rows - 1,
                            route_kind,
                            route_key,
                            digest,
                            sequence,
                            "candidate",
                        ),
                    )
                    if updated.rowcount != 1:
                        raise SourceFinalizationError(
                            "Windows candidate changed during terminal sealing"
                        )

                routes = len(self._source_finalization_route_ids)
                connection.execute(
                    """UPDATE finalization_state
                       SET phase = ?, candidate_rows = ?, candidate_bytes = ?,
                           final_rows = ?, final_bytes = ?, routes = ?, published_rows = ?,
                           epoch = ?, high_water_rows = MAX(high_water_rows, ?),
                           high_water_bytes = MAX(high_water_bytes, ?),
                           high_water_routes = MAX(high_water_routes, ?)
                       WHERE singleton = ? AND phase = ?""",
                    (
                        "sealed",
                        0,
                        0,
                        final_rows,
                        final_bytes,
                        routes,
                        0,
                        epoch_ordinal,
                        final_rows,
                        final_bytes,
                        routes,
                        1,
                        "candidate",
                    ),
                )
                self._commit_journal_unlocked()
                sealed = True
            except BaseException:
                if not connection.in_transaction:
                    try:
                        self._validate_sealed_journal_unlocked(
                            epoch_ordinal,
                            expected_rows=final_rows,
                            expected_bytes=final_bytes,
                            expected_routes=len(self._source_finalization_route_ids),
                        )
                    except SourceFinalizationError:
                        sealed = False
                    else:
                        sealed = True
                if not sealed:
                    self._rollback_journal_unlocked()
                    self._source_finalization_routes.clear()
                    self._source_finalization_route_ids.clear()
                    for writer_key in set(self._host_writers) - initial_host_writer_keys:
                        self._host_writers.pop(writer_key, None)
                    for writer_key in set(self._snare_writers) - initial_snare_writer_keys:
                        self._snare_writers.pop(writer_key, None)
                    raise
            finally:
                self._sealing_transaction = False

            if not sealed:
                raise SourceFinalizationError("Windows terminal source seal was not durable")
            self._spooled_count = 0
            self._candidate_admitted_rows = 0
            self._candidate_admitted_bytes = 0
            self._source_high_water_rows = max(self._source_high_water_rows, final_rows)
            self._source_high_water_bytes = max(self._source_high_water_bytes, final_bytes)
            self._source_high_water_routes = max(
                self._source_high_water_routes,
                len(self._source_finalization_route_ids),
            )
            self._adopt_render_state(render_state)
            epoch = self._epoch_from_sealed_state_unlocked(epoch_ordinal)
            self._set_source_lifecycle_state("sealed")
            return epoch

    def _resolve_sealed_writer_unlocked(
        self,
        route_kind: str,
        route_key: str,
    ) -> _SingleHostWriter:
        """Resolve the writer retained when this immutable route was sealed."""

        route_id = self._source_finalization_route_ids.get((route_kind, route_key))
        writer = self._source_finalization_routes.get(route_id) if route_id is not None else None
        if writer is None:
            raise SourceFinalizationError(
                "Windows sealed route lost its same-process physical writer"
            )
        return writer

    def _read_final_chunk_unlocked(self, cursor: int, final_rows: int) -> _WindowsFinalChunk | None:
        """Load one bounded immutable chunk from the private journal."""

        if cursor >= final_rows:
            return None
        connection = self._spool_conn
        if connection is None:
            raise SourceFinalizationError("Windows source journal is not open")
        rows: list[ExactSourceRow] = []
        retained_bytes = 0
        route_ids: set[int] = set()
        while len(rows) < _FINALIZATION_CHUNK_ROWS and cursor + len(rows) < final_rows:
            ordinal = cursor + len(rows)
            row = connection.execute(
                """SELECT route_kind, route_key, payload, payload_bytes, payload_digest
                   FROM events WHERE phase = ? AND ordinal = ?""",
                ("final", ordinal),
            ).fetchone()
            if row is None:
                raise SourceFinalizationError("Windows immutable final row is missing")
            route_kind, route_key, rendered, payload_bytes, payload_digest = row
            if not all(isinstance(value, str) for value in (route_kind, route_key, rendered)):
                raise SourceFinalizationError("Windows immutable final row has invalid types")
            encoded = rendered.encode("utf-8")
            if len(encoded) != int(payload_bytes) or hashlib.sha256(encoded).hexdigest() != str(
                payload_digest
            ):
                raise SourceFinalizationError("Windows immutable final row failed validation")
            writer = self._resolve_sealed_writer_unlocked(route_kind, route_key)
            next_bytes = retained_bytes + len(encoded)
            next_route_ids = route_ids | {id(writer)}
            if rows and (
                next_bytes > _FINALIZATION_CHUNK_BYTES
                or len(next_route_ids) > _FINALIZATION_CHUNK_ROUTES
            ):
                break
            if next_bytes > _FINALIZATION_CHUNK_BYTES:
                raise SourceFinalizationError(
                    "Windows immutable row exceeds exact chunk byte capacity"
                )
            retained_bytes = next_bytes
            route_ids = next_route_ids
            rows.append(ExactSourceRow(writer=writer, content=rendered))
        if not rows:
            raise SourceFinalizationError("Windows source chunk could not make bounded progress")
        return _WindowsFinalChunk(
            chunk_id=cursor,
            end_sequence=cursor + len(rows),
            rows=tuple(rows),
        )

    def _source_checkpoint_at_least_unlocked(self, cursor: int) -> bool:
        """Return whether the durable source cursor covers one exact child."""

        state = self._journal_state_unlocked()
        return int(state[6]) >= cursor

    def _checkpoint_source_chunk(self, start: int, end: int) -> None:
        """Durably advance the source cursor after exact sink commit and before release."""

        self._require_source_owner({"sealed"})
        with self._file_lock:
            state = self._journal_state_unlocked()
            if int(state[6]) >= end:
                return
            if str(state[0]) != "sealed" or int(state[6]) != start:
                raise SourceFinalizationError(
                    "Windows source checkpoint does not match the retained exact child"
                )
            if self._spool_conn is None:
                raise SourceFinalizationError("Windows source journal is not open")
            self._spool_conn.execute(
                """UPDATE finalization_state SET published_rows = ?
                   WHERE singleton = ? AND phase = ? AND published_rows = ?""",
                (end, 1, "sealed", start),
            )
            try:
                self._commit_journal_unlocked()
            except BaseException:
                if self._spool_conn.in_transaction or not self._source_checkpoint_at_least_unlocked(
                    end
                ):
                    self._rollback_journal_unlocked()
                    raise
            if not self._source_checkpoint_at_least_unlocked(end):
                raise SourceFinalizationError("Windows source checkpoint was not durable")

    def _source_checkpoint_at_least(self, cursor: int) -> bool:
        self._require_source_owner({"sealed"})
        with self._file_lock:
            return self._source_checkpoint_at_least_unlocked(cursor)

    def publish_source_finalization(
        self,
        epoch: SourceFinalizationEpoch,
        publisher: ExactChunkPublisher,
    ) -> None:
        """Publish sealed immutable rows through bounded exact final-writer children."""

        with self._source_finalization_operation():
            self._publish_source_finalization(epoch, publisher)

    def _publish_source_finalization(
        self,
        epoch: SourceFinalizationEpoch,
        publisher: ExactChunkPublisher,
    ) -> None:
        """Run exact source publication under the current operation capability."""

        source_state = self._require_source_owner({"sealed", "published"})
        if epoch is not self._source_finalization_epoch or not isinstance(
            epoch, _WindowsSourceFinalizationEpoch
        ):
            raise SourceFinalizationError("Windows source publication received a foreign epoch")
        if epoch._owner is not self:
            raise SourceFinalizationError("Windows source publication lost its epoch owner")
        if source_state == "published":
            return
        if source_state != "sealed":
            raise SourceFinalizationError("Windows source must seal before exact publication")

        publisher.resume(epoch)
        while True:
            with self._file_lock:
                state = self._journal_state_unlocked()
                phase = str(state[0])
                final_rows = int(state[3])
                cursor = int(state[6])
                if phase == "published":
                    self._set_source_lifecycle_state("published")
                    return
                if phase != "sealed":
                    raise SourceFinalizationError(
                        "Windows source journal left its exact publication phase"
                    )
                chunk = self._read_final_chunk_unlocked(cursor, final_rows)
            if chunk is None:
                with self._file_lock:
                    if self._spool_conn is None:
                        raise SourceFinalizationError("Windows source journal is not open")
                    self._spool_conn.execute(
                        """UPDATE finalization_state SET phase = ?
                           WHERE singleton = ? AND phase = ? AND published_rows = final_rows""",
                        ("published", 1, "sealed"),
                    )
                    try:
                        self._commit_journal_unlocked()
                    except BaseException:
                        if (
                            self._spool_conn.in_transaction
                            or str(self._journal_state_unlocked()[0]) != "published"
                        ):
                            self._rollback_journal_unlocked()
                            raise
                    if str(self._journal_state_unlocked()[0]) != "published":
                        raise SourceFinalizationError(
                            "Windows source terminal publication state was not durable"
                        )
                self._set_source_lifecycle_state("published")
                return

            publisher.publish_chunk(
                epoch,
                chunk.chunk_id,
                chunk.rows,
                is_checkpointed=lambda end=chunk.end_sequence: self._source_checkpoint_at_least(
                    end
                ),
                checkpoint=lambda start=chunk.chunk_id, end=chunk.end_sequence: (
                    self._checkpoint_source_chunk(start, end)
                ),
            )

    def source_finalization_census(self) -> WindowsSourceFinalizationCensus:
        """Return bounded source journal counts for tests and terminal diagnostics."""

        source_state, _ = self._source_lifecycle_snapshot()
        with self._candidate_admission_lock:
            admitted_rows = self._candidate_admitted_rows
            admitted_bytes = self._candidate_admitted_bytes
            source_high_water = (
                self._source_high_water_rows,
                self._source_high_water_bytes,
                self._source_high_water_routes,
            )
        with self._file_lock:
            if source_state == "closed":
                values = (0, 0, 0, 0, 0, 0)
                high_water = source_high_water
            elif source_state in {"open", "quiescing", "quiesced"}:
                values = (
                    admitted_rows,
                    admitted_bytes,
                    0,
                    0,
                    0,
                    0,
                )
                high_water = source_high_water
            elif self._spool_conn is None:
                values = (0, 0, 0, 0, 0, 0)
                high_water = source_high_water
            else:
                state = self._journal_state_unlocked()
                values = tuple(int(value) for value in state[1:7])
                high_water = tuple(int(value) for value in state[8:11])
            return WindowsSourceFinalizationCensus(
                state=source_state,
                candidate_rows=values[0],
                candidate_bytes=values[1],
                final_rows=values[2],
                final_bytes=values[3],
                routes=values[4],
                published_rows=values[5],
                row_capacity=self._finalization_row_capacity,
                byte_capacity=self._finalization_byte_capacity,
                route_capacity=self._finalization_route_capacity,
                high_water_rows=high_water[0],
                high_water_bytes=high_water[1],
                high_water_routes=high_water[2],
            )

    def flush(self, *, force: bool = False) -> None:
        """Flush host writers and spill deferred Windows events to bounded disk storage."""
        source_state, _ = self._source_lifecycle_snapshot()
        if self._source_finalization_bound and source_state != "open":
            raise SourceFinalizationError(
                "Windows source-finalization rejected legacy flush after quiescence"
            )
        with self._file_lock:
            if force:
                self._flush_unlocked()
            else:
                self._spool_event_dicts_unlocked()
        with self._host_writers_lock:
            for writer in self._host_writers.values():
                writer.flush()
            for writer in self._snare_writers.values():
                writer.flush()

    def close(self) -> None:
        """Close emitter — flush and write XML footers for each host file."""

        if self._source_finalization_bound:
            with self._source_finalization_operation():
                self._close_windows_emitter()
            return
        self._close_windows_emitter()

    def _close_windows_emitter(self) -> None:
        """Run exact or legacy close while any required source capability is held."""

        source_state, source_owner = self._source_lifecycle_snapshot()
        if self._source_finalization_bound and source_state != "open":
            if source_state in {"aborted", "closed"}:
                return
            if source_state != "published":
                raise SourceFinalizationError(
                    "Windows source close cannot legacy-render an unpublished sealed cohort"
                )
            if source_owner != get_ident():
                raise SourceFinalizationError(
                    "Windows source close has a different finalization owner"
                )
            footer = self._source_finalization_footer
            output_target = self._source_finalization_output_target
            if footer is None or output_target is None:
                raise SourceFinalizationError(
                    "Windows source close lost its frozen output contract"
                )
            for writer in self._host_writers.values():
                if footer and writer.event_count > 0 and output_target != OutputTarget.SPLUNK:
                    writer.write_footer(footer)
                else:
                    writer.flush()
            for writer in self._snare_writers.values():
                writer.flush()
            with self._file_lock:
                self._cleanup_spool_unlocked()
            self._source_finalization_routes.clear()
            self._source_finalization_route_ids.clear()
            self._set_source_lifecycle_state("closed")
            self._finish_close()
            return

        if not self._begin_close():
            return
        try:
            if self.threaded:
                self.stop_thread()
            self.flush(force=True)
            footer = self.format_def.output.footer_template or ""
            for writer in self._host_writers.values():
                writer.flush()
                if footer and writer.event_count > 0 and self.output_target != OutputTarget.SPLUNK:
                    writer.write_footer(footer)
            for writer in self._snare_writers.values():
                writer.flush()
        except BaseException:
            self._fail_close()
            raise
        if self._source_finalization_bound:
            self._set_source_lifecycle_state("aborted")
        self._finish_close()

    @property
    def event_count(self) -> int:
        return sum(w.event_count for w in self._host_writers.values()) + sum(
            w.event_count for w in self._snare_writers.values()
        )

    @event_count.setter
    def event_count(self, value: int) -> None:
        pass
