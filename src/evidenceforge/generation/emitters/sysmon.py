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

"""Windows Sysmon Event Log emitter.

Mirrors WindowsEventEmitter architecture: buffers raw event dicts, sorts by
timestamp on flush, assigns per-computer EventRecordIDs, renders to XML,
and writes to per-host FQDN directories as windows_event_sysmon.xml.
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
from collections.abc import Iterator
from contextlib import contextmanager
from copy import deepcopy
from dataclasses import dataclass
from dataclasses import field as dataclass_field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from queue import Empty, Full
from threading import Lock, get_ident, local
from typing import Any

from evidenceforge.config.sysmon_filters import load_sysmon_filters
from evidenceforge.events.base import CanonicalOccurrence, OccurrenceBuilder
from evidenceforge.events.contexts import HostContext, ProcessContext
from evidenceforge.events.identity import ProcessIdentity
from evidenceforge.formats.format_def import FormatDefinition
from evidenceforge.generation.emitters.base import (
    ExactPublicationError,
    ExactPublicationKey,
    ExactPublicationParticipantKey,
    LogEmitter,
    exact_publication_attempt_active,
    register_exact_publication_participant,
    stage_exact_publication_row,
)
from evidenceforge.generation.emitters.host_base import _SingleHostWriter
from evidenceforge.generation.emitters.syslog_family import (
    make_syslog_family_route_key,
    sanitize_syslog_family_route_key,
    syslog_family_writer_path,
)
from evidenceforge.generation.emitters.windows import (
    _normalize_windows_time_created,
    _require_windows_source_finalization_capabilities,
    _subject_domain,
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
    WINDOWS_SYSMON_SNARE_FILENAME,
    render_windows_sysmon_snare_syslog,
)
from evidenceforge.generation.source_finalization import (
    ExactChunkPublisher,
    ExactSourceRow,
    SourceFinalizationEpoch,
    SourceFinalizationError,
)
from evidenceforge.generation.source_timing import (
    compatibility_endpoint_event_times,
    compatibility_process_create_time,
    compatibility_sysmon_envelope_time,
    finalized_endpoint_event_times,
    sysmon_parent_process_render_key,
    sysmon_process_identity_render_key,
    sysmon_process_pid_render_key,
)
from evidenceforge.output_targets import OutputTarget
from evidenceforge.utils.paths import sanitize_path_component
from evidenceforge.utils.rng import _stable_seed
from evidenceforge.utils.time import ensure_utc
from evidenceforge.utils.windows_ids import (
    align_windows_id,
    normalize_windows_id_value,
    windows_id_randint,
)

# Well-known Windows port names for Sysmon Event 3
_PORT_NAMES: dict[int, str] = {
    20: "ftp-data",
    21: "ftp",
    22: "ssh",
    25: "smtp",
    53: "domain",
    80: "http",
    88: "kerberos",
    110: "pop3",
    123: "ntp",
    135: "epmap",
    139: "netbios-ssn",
    143: "imap",
    389: "ldap",
    443: "https",
    445: "microsoft-ds",
    636: "ldaps",
    993: "imaps",
    995: "pop3s",
    1433: "ms-sql-s",
    3306: "mysql",
    3389: "ms-wbt-server",
    5432: "postgresql",
    5985: "wsman",
    5986: "wsmans",
    8080: "http-alt",
}

# DNS rcode → Windows DNS QueryStatus mapping
_DNS_STATUS_MAP: dict[str, str] = {
    "NOERROR": "0",
    "SERVFAIL": "9002",
    "NXDOMAIN": "9003",
    "NOTIMP": "9501",
    "REFUSED": "9005",
}

_PROCESS_GUID_FIELDS: tuple[str, ...] = (
    "ProcessGuid",
    "ParentProcessGuid",
    "SourceProcessGuid",
    "TargetProcessGuid",
    "SourceProcessGUID",
    "TargetProcessGUID",
)
_FROZEN_TIMING_MARKER = object()
logger = logging.getLogger(__name__)

_EXACT_CANDIDATE_MARKER = "exact-candidate-v1"

_DEFAULT_FINALIZATION_ROW_CAPACITY = 2_000_000
_DEFAULT_FINALIZATION_BYTE_CAPACITY = 2 * 1024 * 1024 * 1024
_DEFAULT_FINALIZATION_ROUTE_CAPACITY = 100_000
_FINALIZATION_CHUNK_ROWS = 512
_FINALIZATION_CHUNK_BYTES = 16 * 1024 * 1024
_FINALIZATION_CHUNK_ROUTES = 128
_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)
_DIRECTORY = getattr(os, "O_DIRECTORY", 0)
_SQLITE_COMPANION_SUFFIXES = ("-journal", "-wal", "-shm")

_SPOOL_FIELDS_KEY = "fields"
_SPOOL_VALUE_TYPE_KEY = "type"
_SPOOL_VALUE_KEY = "value"
_SPOOL_DATETIME_TYPE = "datetime"
_SPOOL_TIMING_MARKER_TYPE = "timing_marker"
_SPOOL_JSON_TYPE = "json"


def _sysmon_spool_encode(event: dict[str, Any]) -> str:
    """Encode one detached Sysmon candidate without native deserialization."""

    fields: dict[str, dict[str, Any]] = {}
    for key, value in event.items():
        if isinstance(value, datetime):
            fields[key] = {
                _SPOOL_VALUE_TYPE_KEY: _SPOOL_DATETIME_TYPE,
                _SPOOL_VALUE_KEY: value.isoformat(),
            }
        elif value is _FROZEN_TIMING_MARKER:
            fields[key] = {
                _SPOOL_VALUE_TYPE_KEY: _SPOOL_TIMING_MARKER_TYPE,
                _SPOOL_VALUE_KEY: None,
            }
        else:
            fields[key] = {
                _SPOOL_VALUE_TYPE_KEY: _SPOOL_JSON_TYPE,
                _SPOOL_VALUE_KEY: value,
            }
    return json.dumps({_SPOOL_FIELDS_KEY: fields})


def _sysmon_spool_decode(payload: str) -> dict[str, Any]:
    """Decode one inert JSON Sysmon candidate from the private journal."""

    decoded = json.loads(payload)
    if not isinstance(decoded, dict):
        raise ValueError("Sysmon spool payload must decode to an object")
    fields = decoded.get(_SPOOL_FIELDS_KEY)
    if not isinstance(fields, dict):
        raise ValueError("Sysmon spool payload is missing its fields object")

    event: dict[str, Any] = {}
    for key, wrapped in fields.items():
        if not isinstance(key, str) or not isinstance(wrapped, dict):
            raise ValueError("Sysmon spool field entries must be keyed objects")
        value_type = wrapped.get(_SPOOL_VALUE_TYPE_KEY)
        value = wrapped.get(_SPOOL_VALUE_KEY)
        if value_type == _SPOOL_DATETIME_TYPE:
            if not isinstance(value, str):
                raise ValueError("Sysmon spool datetime value must be a string")
            event[key] = ensure_utc(datetime.fromisoformat(value))
        elif value_type == _SPOOL_TIMING_MARKER_TYPE:
            if value is not None:
                raise ValueError("Sysmon spool timing marker must not retain a value")
            event[key] = _FROZEN_TIMING_MARKER
        elif value_type == _SPOOL_JSON_TYPE:
            event[key] = value
        else:
            raise ValueError(f"unknown Sysmon spool field type: {value_type!r}")
    return event


@dataclass(frozen=True, slots=True)
class SysmonSourceFinalizationCensus:
    """Constant-time candidate, final-row, route, and checkpoint counts."""

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


@dataclass(frozen=True, slots=True)
class SysmonExactCandidateCensus:
    """Constant-time exact candidate receipt and reservation ownership counts."""

    current_rows: int
    current_bytes: int
    current_participants: int
    released_rows: int
    released_bytes: int
    completed_participants: int
    high_water_rows: int
    high_water_bytes: int
    high_water_participants: int


@dataclass(slots=True)
class _SysmonExactCandidateReservation:
    """Owner-private same-process reservation for one exact raw candidate."""

    digest: str
    retained_bytes: int
    charged_bytes: int
    sequence: int
    capacity_charged: bool = False
    admitted: bool = False
    released: bool = False


@dataclass(slots=True)
class _SysmonExactCandidateParticipant:
    """Bounded scalar ownership for one exact candidate participant."""

    next_sequence: int
    reservation_keys: list[ExactPublicationKey] = dataclass_field(default_factory=list)
    reserved_rows: int = 0
    reserved_bytes: int = 0
    admitted_rows: int = 0
    released_rows: int = 0
    released_bytes: int = 0
    render_state_authenticated: bool = False
    render_state_finalized: bool = False
    completed: bool = False
    thread_pools_existed: bool = False
    thread_counters_existed: bool = False
    thread_last_threads_existed: bool = False
    call_trace_counters_existed: bool = False
    sysmon_pids_existed: bool = False
    dns_client_pids_existed: bool = False
    filters_existed: bool = False
    thread_allocation_receipts: dict[str, "_SysmonThreadAllocationReceipt"] = dataclass_field(
        default_factory=dict
    )
    terminal_session_receipts: dict[
        tuple[str, str],
        "_SysmonIntMutationReceipt",
    ] = dataclass_field(default_factory=dict)
    call_trace_receipts: dict[str, "_SysmonCallTraceMutationReceipt"] = dataclass_field(
        default_factory=dict
    )
    sysmon_pid_receipts: dict[str, "_SysmonIntMutationReceipt"] = dataclass_field(
        default_factory=dict
    )
    dns_client_pid_receipts: dict[str, "_SysmonIntMutationReceipt"] = dataclass_field(
        default_factory=dict
    )
    created_filters: dict[str, Any] | None = None


@dataclass(frozen=True, slots=True)
class _SysmonThreadHostState:
    """One immutable per-host view of the sequential Sysmon thread allocator."""

    pool_present: bool
    pool: tuple[int, ...]
    counter_present: bool
    counter: int
    last_thread_present: bool
    last_thread: int


@dataclass(slots=True)
class _SysmonThreadAllocationReceipt:
    """Authenticated before/expected states for one exact-rendered host."""

    original: _SysmonThreadHostState
    expected: _SysmonThreadHostState


@dataclass(frozen=True, slots=True)
class _SysmonIntEntryState:
    """One immutable optional integer mapping entry."""

    present: bool
    value: int


@dataclass(slots=True)
class _SysmonIntMutationReceipt:
    """Authenticated before/expected states for one integer mapping mutation."""

    original: _SysmonIntEntryState
    expected: _SysmonIntEntryState


@dataclass(frozen=True, slots=True)
class _SysmonCallTraceHostState:
    """One immutable per-host call-trace cache and sequence view."""

    cache_present: bool
    cache_digest: str
    counter_present: bool
    counter: int


@dataclass(slots=True)
class _SysmonCallTraceMutationReceipt:
    """Authenticated before/expected states for one call-trace allocation."""

    original: _SysmonCallTraceHostState
    expected: _SysmonCallTraceHostState


@dataclass(frozen=True, slots=True)
class _SysmonAbortExactPendingRow:
    """One bounded final-writer row retained across abort-publication retry."""

    ordinal: int
    key: ExactPublicationKey
    writer: _SingleHostWriter
    digest: str


class _SysmonSourceFinalizationEpoch(SourceFinalizationEpoch):
    """Emitter-owned opaque reference to one sealed Sysmon cohort."""

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
class _SysmonFinalChunk:
    """One bounded page loaded from immutable final-row storage."""

    chunk_id: int
    end_sequence: int
    rows: tuple[ExactSourceRow, ...]


@dataclass(slots=True)
class _SysmonRenderState:
    """Retry-local mutable source state used during one terminal seal."""

    record_id_sequences: dict[str, WindowsRecordIdSequence]
    last_time_created_by_computer: dict[str, datetime]
    time_collision_count_by_computer: dict[str, int]
    final_process_guids: dict[tuple[str, int, str], str]


def _format_sysmon_utc_time(timestamp: datetime) -> str:
    """Return Sysmon EventData UtcTime from the rendered source timestamp."""
    return ensure_utc(timestamp).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]


class SysmonEventEmitter(LogEmitter):
    """Emitter for Windows Sysmon Event Log format (XML).

    Same deferred-rendering architecture as WindowsEventEmitter but outputs
    to a separate file (windows_event_sysmon.xml) with Sysmon Provider/Channel.
    """

    _supported_types: set[str] = {
        "process_create",
        "system_process_create",
        "process_terminate",
        "create_remote_thread",
        "process_access",
        "connection",  # Event 3 (NetworkConnect) + Event 22 (DNSQuery)
        "file_create",  # Event 11 (FileCreate)
        "file_modify",  # Event 11 (FileCreate — overwrites also trigger)
        "registry_modify",  # Events 12/13 (RegistryEvent)
        "image_load",  # Event 7 (ImageLoaded)
    }
    # Per-host boot datetimes for realistic parent ProcessGUID timestamps.
    # Set by emitter_setup after initialization.
    _host_boot_times: dict[str, datetime] = {}

    def _event_rng(self, event: CanonicalOccurrence, salt: str = "") -> random.Random:
        """Return a deterministic renderer-local RNG for incidental Sysmon fields."""
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
        """Return the frozen endpoint phase rendered by one Sysmon row."""

        if event.event_type in {"process_create", "system_process_create"}:
            return "process_create"
        if event.event_type == "process_terminate":
            return "process_terminate"
        if event.event_type == "connection":
            return "dns" if event_id == 22 else "network"
        return "base"

    def _render_times(
        self,
        event: CanonicalOccurrence,
        phase: str | None = None,
    ) -> tuple[datetime, datetime]:
        """Return frozen Sysmon payload/envelope times with direct compatibility."""

        host = event.src_host or event.dst_host
        hostname = host.hostname if host is not None else ""
        effective_phase = phase or self._timing_phase(event)
        finalized = finalized_endpoint_event_times(
            event,
            "windows_event_sysmon",
            hostname,
            effective_phase,
        )
        if finalized is None:
            if event.source_timing is not None and not event.source_timing.compatibility_mode:
                raise RuntimeError(
                    "Sysmon production projection requires frozen endpoint timing: "
                    f"host={hostname} event_type={event.event_type} phase={effective_phase}"
                )
            finalized = compatibility_endpoint_event_times(
                event,
                "windows_event_sysmon",
                hostname,
                effective_phase,
            )
        return finalized

    @staticmethod
    def _apply_finalized_times(
        event_data: dict[str, Any],
        native_time: datetime,
        envelope_time: datetime,
    ) -> None:
        """Attach an upstream-frozen Sysmon payload/envelope pair to one row."""

        event_data["_SysmonNativeTime"] = native_time
        event_data["_SysmonInitialEnvelopeTime"] = envelope_time
        event_data["TimeCreated"] = envelope_time
        if "UtcTime" in event_data:
            event_data["UtcTime"] = _format_sysmon_utc_time(native_time)
        event_data["_TimingFinalized"] = _FROZEN_TIMING_MARKER

    @staticmethod
    def _timing_is_finalized(event_data: dict[str, Any]) -> bool:
        """Return whether a row carries this module's unforgeable timing marker."""

        return event_data.get("_TimingFinalized") is _FROZEN_TIMING_MARKER

    # PE metadata for common Windows binaries (FileVersion, Description, Product, Company, OriginalFileName)
    _PE_METADATA: dict[str, tuple[str, str, str, str, str]] = {
        "cmd.exe": (
            "10.0.19041.1",
            "Windows Command Processor",
            "Microsoft Windows Operating System",
            "Microsoft Corporation",
            "Cmd.Exe",
        ),
        "powershell.exe": (
            "10.0.19041.1",
            "Windows PowerShell",
            "Microsoft Windows Operating System",
            "Microsoft Corporation",
            "PowerShell.EXE",
        ),
        "svchost.exe": (
            "10.0.19041.1",
            "Host Process for Windows Services",
            "Microsoft Windows Operating System",
            "Microsoft Corporation",
            "svchost.exe",
        ),
        "explorer.exe": (
            "10.0.19041.1",
            "Windows Explorer",
            "Microsoft Windows Operating System",
            "Microsoft Corporation",
            "EXPLORER.EXE",
        ),
        "taskhostw.exe": (
            "10.0.19041.1",
            "Host Process for Windows Tasks",
            "Microsoft Windows Operating System",
            "Microsoft Corporation",
            "taskhostw.exe",
        ),
        "usoclient.exe": (
            "10.0.19041.1",
            "Update Session Orchestrator",
            "Microsoft Windows Operating System",
            "Microsoft Corporation",
            "UsoClient.exe",
        ),
        "lsass.exe": (
            "10.0.19041.1",
            "Local Security Authority Process",
            "Microsoft Windows Operating System",
            "Microsoft Corporation",
            "lsass.exe",
        ),
        "services.exe": (
            "10.0.19041.1",
            "Services and Controller app",
            "Microsoft Windows Operating System",
            "Microsoft Corporation",
            "services.exe",
        ),
        "net.exe": (
            "10.0.19041.1",
            "Net Command",
            "Microsoft Windows Operating System",
            "Microsoft Corporation",
            "net.exe",
        ),
        "net1.exe": (
            "10.0.19041.1",
            "Net Command",
            "Microsoft Windows Operating System",
            "Microsoft Corporation",
            "net1.exe",
        ),
        "sc.exe": (
            "10.0.19041.1",
            "Service Control Manager Configuration Tool",
            "Microsoft Windows Operating System",
            "Microsoft Corporation",
            "sc.exe",
        ),
        "schtasks.exe": (
            "10.0.19041.1",
            "Task Scheduler Configuration Tool",
            "Microsoft Windows Operating System",
            "Microsoft Corporation",
            "schtasks.exe",
        ),
        "whoami.exe": (
            "10.0.19041.1",
            "whoami - displays logged on user information",
            "Microsoft Windows Operating System",
            "Microsoft Corporation",
            "whoami.exe",
        ),
        "runas.exe": (
            "10.0.19041.1",
            "RunAs Command",
            "Microsoft Windows Operating System",
            "Microsoft Corporation",
            "runas.exe",
        ),
        "msra.exe": (
            "10.0.19041.1",
            "Windows Remote Assistance",
            "Microsoft Windows Operating System",
            "Microsoft Corporation",
            "msra.exe",
        ),
        "curl.exe": (
            "8.4.0",
            "The curl executable",
            "The curl executable",
            "Microsoft Corporation",
            "curl.exe",
        ),
        "notepad.exe": (
            "10.0.19041.1",
            "Notepad",
            "Microsoft Windows Operating System",
            "Microsoft Corporation",
            "NOTEPAD.EXE",
        ),
        "mstsc.exe": (
            "10.0.19041.1",
            "Remote Desktop Connection",
            "Microsoft Windows Operating System",
            "Microsoft Corporation",
            "mstsc.exe",
        ),
        "wmic.exe": (
            "10.0.19041.1",
            "WMI Commandline Utility",
            "Microsoft Windows Operating System",
            "Microsoft Corporation",
            "wmic.exe",
        ),
        "rundll32.exe": (
            "10.0.19041.1",
            "Windows host process (Rundll32)",
            "Microsoft Windows Operating System",
            "Microsoft Corporation",
            "RUNDLL32.EXE",
        ),
        "conhost.exe": (
            "10.0.19041.1",
            "Console Window Host",
            "Microsoft Windows Operating System",
            "Microsoft Corporation",
            "conhost.exe",
        ),
        # Additional system binaries from system_processes.yaml
        "wmiprvse.exe": (
            "10.0.19041.1",
            "WMI Provider Host",
            "Microsoft Windows Operating System",
            "Microsoft Corporation",
            "WmiPrvSE.exe",
        ),
        "dllhost.exe": (
            "10.0.19041.1",
            "COM Surrogate",
            "Microsoft Windows Operating System",
            "Microsoft Corporation",
            "dllhost.exe",
        ),
        "runtimebroker.exe": (
            "10.0.19041.1",
            "Runtime Broker",
            "Microsoft Windows Operating System",
            "Microsoft Corporation",
            "RuntimeBroker.exe",
        ),
        "spoolsv.exe": (
            "10.0.19041.1",
            "Spooler SubSystem App",
            "Microsoft Windows Operating System",
            "Microsoft Corporation",
            "spoolsv.exe",
        ),
        "sihost.exe": (
            "10.0.19041.1",
            "Shell Infrastructure Host",
            "Microsoft Windows Operating System",
            "Microsoft Corporation",
            "sihost.exe",
        ),
        "tiworker.exe": (
            "10.0.19041.1",
            "Windows Module Installer Worker",
            "Microsoft Windows Operating System",
            "Microsoft Corporation",
            "TiWorker.exe",
        ),
        "backgroundtaskhost.exe": (
            "10.0.19041.1",
            "Background Task Host",
            "Microsoft Windows Operating System",
            "Microsoft Corporation",
            "backgroundTaskHost.exe",
        ),
        "searchhost.exe": (
            "10.0.19041.1",
            "Search application",
            "Microsoft Windows Operating System",
            "Microsoft Corporation",
            "SearchHost.exe",
        ),
        "searchprotocolhost.exe": (
            "10.0.19041.1",
            "Microsoft Windows Search Protocol Host",
            "Microsoft Windows Operating System",
            "Microsoft Corporation",
            "SearchProtocolHost.exe",
        ),
        "searchfilterhost.exe": (
            "10.0.19041.1",
            "Microsoft Windows Search Filter Host",
            "Microsoft Windows Operating System",
            "Microsoft Corporation",
            "SearchFilterHost.exe",
        ),
        "searchindexer.exe": (
            "10.0.19041.1",
            "Microsoft Windows Search Indexer",
            "Microsoft Windows Operating System",
            "Microsoft Corporation",
            "SearchIndexer.exe",
        ),
        "dfsr.exe": (
            "10.0.19041.1",
            "DFS Replication Service",
            "Microsoft Windows Operating System",
            "Microsoft Corporation",
            "dfsr.exe",
        ),
        "dns.exe": (
            "10.0.19041.1",
            "DNS Server Service",
            "Microsoft Windows Operating System",
            "Microsoft Corporation",
            "dns.exe",
        ),
        "ntdsutil.exe": (
            "10.0.19041.1",
            "NT Directory Services Utility",
            "Microsoft Windows Operating System",
            "Microsoft Corporation",
            "ntdsutil.exe",
        ),
        "mpcmdrun.exe": (
            "4.18.2211.5",
            "Microsoft Malware Protection Command Line Utility",
            "Microsoft Antimalware",
            "Microsoft Corporation",
            "MpCmdRun.exe",
        ),
        "msmpeng.exe": (
            "4.18.2211.5",
            "Antimalware Service Executable",
            "Microsoft Antimalware",
            "Microsoft Corporation",
            "MsMpEng.exe",
        ),
        "compattelrunner.exe": (
            "10.0.19041.1",
            "Microsoft Compatibility Appraiser",
            "Microsoft Windows Operating System",
            "Microsoft Corporation",
            "CompatTelRunner.exe",
        ),
        "cleanmgr.exe": (
            "10.0.19041.1",
            "Disk Cleanup",
            "Microsoft Windows Operating System",
            "Microsoft Corporation",
            "cleanmgr.exe",
        ),
        "msdtc.exe": (
            "10.0.19041.1",
            "Microsoft Distributed Transaction Coordinator",
            "Microsoft Windows Operating System",
            "Microsoft Corporation",
            "msdtc.exe",
        ),
        "ismserv.exe": (
            "10.0.19041.1",
            "Intersite Messaging Service",
            "Microsoft Windows Operating System",
            "Microsoft Corporation",
            "ismserv.exe",
        ),
        "wsqmcons.exe": (
            "10.0.19041.1",
            "Windows SQM Consolidator",
            "Microsoft Windows Operating System",
            "Microsoft Corporation",
            "wsqmcons.exe",
        ),
        "consent.exe": (
            "10.0.19041.1",
            "Consent UI for administrative applications",
            "Microsoft Windows Operating System",
            "Microsoft Corporation",
            "consent.exe",
        ),
        "slui.exe": (
            "10.0.19041.1",
            "Windows Activation Client",
            "Microsoft Windows Operating System",
            "Microsoft Corporation",
            "slui.exe",
        ),
        "sppsvc.exe": (
            "10.0.19041.1",
            "Microsoft Software Protection Platform Service",
            "Microsoft Windows Operating System",
            "Microsoft Corporation",
            "sppsvc.exe",
        ),
        "ssh.exe": (
            "8.6.0.1",
            "OpenSSH SSH client",
            "OpenSSH for Windows",
            "Microsoft Corporation",
            "ssh.exe",
        ),
    }

    @classmethod
    def _get_pe_metadata(
        cls, image_path: str, host: Any | None = None
    ) -> tuple[str, str, str, str, str]:
        """Look up PE metadata for a Windows binary by image path or name.

        Checks the built-in OS binary table first, then falls back to the
        application catalog for user-installed apps (Chrome, Firefox, etc.).
        """
        # Handle Windows paths on any OS (backslash is not a separator on Unix)
        basename = image_path.rsplit("\\", 1)[-1].rsplit("/", 1)[-1].lower()
        if basename.endswith((".dll", ".api", ".p5x")):
            from evidenceforge.generation.activity.dll_load_profiles import (
                get_module_pe_metadata,
            )

            result = get_module_pe_metadata(image_path)
            if result != ("-", "-", "-", "-", "-"):
                return result
        result = cls._PE_METADATA.get(basename)
        if result:
            return cls._normalize_os_binary_metadata(image_path, result, host)
        # Fall back to application catalog for user-installed apps
        from evidenceforge.generation.activity.application_catalog import get_pe_metadata

        result = get_pe_metadata(basename)
        return cls._normalize_os_binary_metadata(image_path, result, host)

    @staticmethod
    def _signed_module_metadata(
        image_path: str,
        signature: str,
    ) -> tuple[str, str, str, str, str]:
        """Return plausible version metadata for signed DLLs missing catalog data."""
        basename = image_path.rsplit("\\", 1)[-1].rsplit("/", 1)[-1]
        normalized_path = image_path.replace("/", "\\").lower()
        signature_lower = signature.lower()
        if "\\windows\\" in normalized_path or "microsoft" in signature_lower:
            return (
                "10.0.19041.1",
                f"{basename} system library",
                "Microsoft Windows Operating System",
                "Microsoft Corporation",
                basename,
            )
        if "cisco" in normalized_path or "cisco" in signature_lower:
            return (
                "5.1.8.42",
                f"{basename} module",
                "Cisco Secure Client",
                "Cisco Systems, Inc.",
                basename,
            )
        company = signature.strip() or "Verified Publisher"
        return ("1.0.0.0", f"{basename} module", company, company, basename)

    @classmethod
    def _normalize_os_binary_metadata(
        cls,
        image_path: str,
        metadata: tuple[str, str, str, str, str],
        host: Any | None,
    ) -> tuple[str, str, str, str, str]:
        """Keep Microsoft OS binary file versions consistent for the host OS."""
        fv, desc, prod, company, orig = metadata
        if not host:
            return metadata
        if company != "Microsoft Corporation" or prod not in {
            "Microsoft Windows",
            "Microsoft Windows Operating System",
        }:
            return metadata
        if not cls._is_windows_os_binary_path(image_path):
            return metadata
        component_version = cls._servicing_stack_version_from_path(image_path)
        if component_version and orig.lower() == "tiworker.exe":
            return component_version, desc, prod, company, orig
        return cls._host_windows_file_version(host), desc, prod, company, orig

    @staticmethod
    def _is_windows_os_binary_path(image_path: str) -> bool:
        image_lower = image_path.replace("/", "\\").lower()
        return (
            "\\windows\\system32\\" in image_lower
            or "\\windows\\syswow64\\" in image_lower
            or image_lower.startswith("c:\\windows\\")
        )

    @staticmethod
    def _servicing_stack_version_from_path(image_path: str) -> str:
        image_lower = image_path.replace("/", "\\").lower()
        marker = "microsoft-windows-servicingstack_31bf3856ad364e35_"
        if marker not in image_lower:
            return ""
        tail = image_lower.split(marker, 1)[1]
        version = tail.split("_", 1)[0]
        parts = version.split(".")
        if len(parts) == 4 and all(part.isdigit() for part in parts):
            return version
        return ""

    @staticmethod
    def _host_windows_file_version(host: Any) -> str:
        os_name = str(getattr(host, "os", "") or "").lower()
        system_type = str(getattr(host, "system_type", "") or "").lower()
        if "windows 11" in os_name:
            return "10.0.22621.1"
        if "server" in os_name or system_type in {"server", "domain_controller"}:
            if "2019" in os_name:
                return "10.0.17763.1"
            return "10.0.20348.1"
        return "10.0.19041.1"

    @contextmanager
    def _sysmon_render_state_mutation(
        self,
    ) -> Iterator[_SysmonExactCandidateParticipant | None]:
        """Serialize one mutable renderer helper against exact rollback ownership."""

        exact_attempt = exact_publication_attempt_active()
        if exact_attempt and not register_exact_publication_participant(self):
            raise ExactPublicationError(
                "Sysmon renderer state lost its active exact publication attempt"
            )

        with self._close_condition:
            participant: _SysmonExactCandidateParticipant | None = None
            if exact_attempt:
                if len(self._active_exact_publication_keys) != 1:
                    raise ExactPublicationError(
                        "Sysmon exact renderer state lost its participant fence"
                    )
                participant_key = next(iter(self._active_exact_publication_keys))
                participant = self._exact_candidate_participants.get(participant_key)
                if participant is None or participant.completed:
                    raise ExactPublicationError(
                        "Sysmon exact renderer state lost its participant owner"
                    )
            else:
                while self._active_exact_publication_keys:
                    self._close_condition.wait()
                self._require_accepting_events_locked()

            with self._sysmon_render_state_lock:
                yield participant

    def _sysmon_thread_host_state_unlocked(self, hostname: str) -> _SysmonThreadHostState:
        """Authenticate one host's sequential thread-allocation state."""

        pools = getattr(self, "_sysmon_thread_pools", None)
        counters = getattr(self, "_sysmon_thread_counters", None)
        last_threads = getattr(self, "_sysmon_last_thread_by_host", None)
        for name, mapping in (
            ("pool", pools),
            ("counter", counters),
            ("last-thread", last_threads),
        ):
            if mapping is not None and type(mapping) is not dict:
                raise ExactPublicationError(f"Sysmon thread {name} state is malformed")

        pool_present = pools is not None and hostname in pools
        counter_present = counters is not None and hostname in counters
        last_thread_present = last_threads is not None and hostname in last_threads
        if pool_present != counter_present or (last_thread_present and not pool_present):
            raise ExactPublicationError("Sysmon thread host state is incomplete")

        pool: tuple[int, ...] = ()
        counter = 0
        last_thread = 0
        if pool_present:
            retained_pool = pools[hostname]
            retained_counter = counters[hostname]
            if (
                type(retained_pool) is not list
                or not retained_pool
                or any(type(thread_id) is not int or thread_id <= 0 for thread_id in retained_pool)
                or type(retained_counter) is not int
                or retained_counter < 0
            ):
                raise ExactPublicationError("Sysmon thread host state is malformed")
            pool = tuple(retained_pool)
            counter = retained_counter
        if last_thread_present:
            retained_last_thread = last_threads[hostname]
            if type(retained_last_thread) is not int or retained_last_thread not in pool:
                raise ExactPublicationError("Sysmon thread last-thread state is malformed")
            last_thread = retained_last_thread
        return _SysmonThreadHostState(
            pool_present=pool_present,
            pool=pool,
            counter_present=counter_present,
            counter=counter,
            last_thread_present=last_thread_present,
            last_thread=last_thread,
        )

    def _sysmon_int_entry_state_unlocked(
        self,
        mapping: object,
        key: object,
        *,
        label: str,
    ) -> _SysmonIntEntryState:
        """Authenticate one optional non-negative integer cache entry."""

        retained_mapping = self._validate_sysmon_render_mapping(mapping, label=label)
        if retained_mapping is None or key not in retained_mapping:
            return _SysmonIntEntryState(present=False, value=0)
        value = retained_mapping[key]
        if type(value) is not int or value < 0:
            raise ExactPublicationError(f"Sysmon {label} entry is malformed")
        return _SysmonIntEntryState(present=True, value=value)

    def _sysmon_call_trace_host_state_unlocked(
        self,
        hostname: str,
    ) -> _SysmonCallTraceHostState:
        """Authenticate one host's cached call traces and selection counter."""

        cache = self._validate_sysmon_render_mapping(
            getattr(self, "_call_trace_cache", None),
            label="call-trace cache",
        )
        counters = self._validate_sysmon_render_mapping(
            getattr(self, "_call_trace_counters", None),
            label="call-trace counter",
        )
        cache_present = cache is not None and hostname in cache
        counter_present = counters is not None and hostname in counters
        cache_digest = ""
        retained_counter = 0
        if cache_present:
            value = cache[hostname]
            if (
                type(value) is not list
                or not value
                or any(type(entry) is not str for entry in value)
            ):
                raise ExactPublicationError("Sysmon call-trace cache entry is malformed")
            encoded = json.dumps(
                value,
                ensure_ascii=False,
                separators=(",", ":"),
            ).encode("utf-8")
            cache_digest = hashlib.sha256(encoded).hexdigest()
        if counter_present:
            value = counters[hostname]
            if type(value) is not int or value < 0:
                raise ExactPublicationError("Sysmon call-trace counter entry is malformed")
            retained_counter = value
        return _SysmonCallTraceHostState(
            cache_present=cache_present,
            cache_digest=cache_digest,
            counter_present=counter_present,
            counter=retained_counter,
        )

    def _exact_int_mutation_receipt_unlocked(
        self,
        receipts: (
            dict[str, _SysmonIntMutationReceipt] | dict[tuple[str, str], _SysmonIntMutationReceipt]
        ),
        mapping: object,
        key: str | tuple[str, str],
        *,
        label: str,
    ) -> _SysmonIntMutationReceipt:
        """Create or reauthenticate one lazy exact integer-mutation receipt."""

        current = self._sysmon_int_entry_state_unlocked(mapping, key, label=label)
        receipt = receipts.get(key)
        if receipt is None:
            receipt = _SysmonIntMutationReceipt(original=current, expected=current)
            receipts[key] = receipt
        elif current != receipt.expected:
            raise ExactPublicationError(f"Sysmon exact {label} state changed unexpectedly")
        return receipt

    def _allocate_sysmon_thread_id_unlocked(self, hostname: str) -> int:
        """Advance one host's allocator while the renderer-state lock is held."""

        cache = getattr(self, "_sysmon_thread_pools", None)
        if cache is None:
            cache = self._sysmon_thread_pools = {}
        counters = getattr(self, "_sysmon_thread_counters", None)
        if counters is None:
            counters = self._sysmon_thread_counters = {}
        last_threads = getattr(self, "_sysmon_last_thread_by_host", None)
        if last_threads is None:
            last_threads = self._sysmon_last_thread_by_host = {}
        if hostname not in cache:
            rng = random.Random(_stable_seed(f"sysmon_threads_{hostname}"))
            cache[hostname] = [
                windows_id_randint(rng, 1000, 5000) for _ in range(rng.randint(3, 5))
            ]
            counters[hostname] = 0
        pool = cache[hostname]
        counter = counters.get(hostname, 0)
        counters[hostname] = counter + 1
        rng = random.Random(_stable_seed(f"sysmon_thread_choice:{hostname}:{counter}"))
        previous = last_threads.get(hostname)
        if previous in pool and rng.random() < 0.58:
            return previous
        weights = [max(1, len(pool) * 3 - index * 2) for index, _thread_id in enumerate(pool)]
        thread_id = rng.choices(pool, weights=weights, k=1)[0]
        last_threads[hostname] = thread_id
        return thread_id

    def _get_sysmon_thread_id(self, hostname: str) -> int:
        """Return a reused ThreadID without leaking failed exact-render state.

        Real Sysmon reuses a small thread pool (3-5 threads), not random IDs.
        Exact rendering advances the same sequential allocator as ordinary
        rendering, but retains an authenticated before/expected receipt until
        the exact batch either commits or aborts.
        """

        with self._sysmon_render_state_mutation() as participant:
            receipt: _SysmonThreadAllocationReceipt | None = None
            if participant is not None:
                current = self._sysmon_thread_host_state_unlocked(hostname)
                receipt = participant.thread_allocation_receipts.get(hostname)
                if receipt is None:
                    receipt = _SysmonThreadAllocationReceipt(
                        original=current,
                        expected=current,
                    )
                    participant.thread_allocation_receipts[hostname] = receipt
                elif current != receipt.expected:
                    raise ExactPublicationError(
                        "Sysmon exact thread allocation state changed unexpectedly"
                    )

            try:
                return self._allocate_sysmon_thread_id_unlocked(hostname)
            finally:
                if receipt is not None:
                    receipt.expected = self._sysmon_thread_host_state_unlocked(hostname)

    def _get_sysmon_pid(self, hostname: str) -> int:
        """Return stable Sysmon service PID for a given host.

        The Sysmon driver runs as a single persistent process; its PID
        must be the same across all events from that host.
        """
        with self._sysmon_render_state_mutation() as participant:
            cache = getattr(self, "_sysmon_pids", None)
            if cache is None:
                cache = self._sysmon_pids = {}
            receipt: _SysmonIntMutationReceipt | None = None
            if participant is not None:
                receipt = self._exact_int_mutation_receipt_unlocked(
                    participant.sysmon_pid_receipts,
                    cache,
                    hostname,
                    label="service PID",
                )
            try:
                if hostname not in cache:
                    h = int(
                        hashlib.md5(
                            f"sysmon:{hostname}".encode(),
                            usedforsecurity=False,
                        ).hexdigest(),
                        16,
                    )
                    cache[hostname] = align_windows_id(1800 + (h % 1200))
                return cache[hostname]
            finally:
                if receipt is not None:
                    receipt.expected = self._sysmon_int_entry_state_unlocked(
                        cache,
                        hostname,
                        label="service PID",
                    )

    def _get_call_trace(self, hostname: str) -> str:
        """Return a CallTrace string with per-host stable offsets.

        Loads call chain patterns from calltrace_patterns.yaml, then generates
        concrete offsets per-host using a hostname-seeded RNG. Offsets are fixed
        within a boot session (matching real ASLR behavior) but vary across hosts.
        """
        with self._sysmon_render_state_mutation() as participant:
            receipt: _SysmonCallTraceMutationReceipt | None = None
            if participant is not None:
                current = self._sysmon_call_trace_host_state_unlocked(hostname)
                receipt = participant.call_trace_receipts.get(hostname)
                if receipt is None:
                    receipt = _SysmonCallTraceMutationReceipt(
                        original=current,
                        expected=current,
                    )
                    participant.call_trace_receipts[hostname] = receipt
                elif current != receipt.expected:
                    raise ExactPublicationError(
                        "Sysmon exact call-trace state changed unexpectedly"
                    )
            try:
                if hostname not in self._call_trace_cache:
                    from evidenceforge.generation.activity.calltrace_patterns import (
                        load_calltrace_patterns,
                    )

                    patterns = load_calltrace_patterns()
                    rng = random.Random(_stable_seed(f"calltrace_{hostname}"))
                    rendered = []
                    for pat in patterns:
                        modules = pat["modules"]
                        ranges = pat["offset_ranges"]
                        parts = []
                        for mod in modules:
                            lo, hi = ranges[mod]
                            off = rng.randint(lo, hi)
                            parts.append(f"C:\\Windows\\SYSTEM32\\{mod}+{off:X}")
                        rendered.append("|".join(parts))
                    self._call_trace_cache[hostname] = rendered
                counters = getattr(self, "_call_trace_counters", None)
                if counters is None:
                    counters = self._call_trace_counters = {}
                counter = counters.get(hostname, 0)
                counters[hostname] = counter + 1
                rng = random.Random(_stable_seed(f"calltrace_choice:{hostname}:{counter}"))
                return rng.choice(self._call_trace_cache[hostname])
            finally:
                if receipt is not None:
                    receipt.expected = self._sysmon_call_trace_host_state_unlocked(hostname)

    def _resolve_process_from_pid(self, hostname: str, pid: int) -> tuple[int, str]:
        """Look up process image from StateManager by PID.

        Returns (pid, image_path). Falls back to "-" (Sysmon convention for
        unknown) when the PID is not found, rather than guessing svchost.exe
        which would produce misleading Event 3/11/12 attributions.
        """
        if pid <= 0:
            return (pid, "-")
        sm = getattr(self, "_state_manager", None)
        if sm is None:
            return (pid, "-")
        proc = sm.get_process(hostname, pid)
        if proc is not None:
            return (pid, proc.image)
        return (pid, "-")

    @staticmethod
    def _carrier_owned_process(
        event: CanonicalOccurrence,
        host: HostContext,
    ) -> tuple[int, str, str, datetime] | None:
        """Return process fields whose Sysmon identity was frozen upstream."""

        process = event.process
        if process is not None and process.pid > 0:
            return (
                process.pid,
                process.image,
                process.username,
                process.start_time or event.timestamp,
            )
        actor = event.identity_plan.actor if event.identity_plan is not None else None
        if (
            isinstance(actor, ProcessIdentity)
            and actor.pid > 0
            and actor.hostname.casefold() == host.hostname.casefold()
        ):
            return actor.pid, actor.image or "-", actor.principal, actor.started_at
        return None

    @staticmethod
    def _resolve_destination_hostname(ip: str, dst_port: int = 0) -> str:
        """Resolve destination IP to hostname via REVERSE_DNS.

        Returns FQDN for known internal hosts (scenario systems), "-" for unknown.
        """
        from evidenceforge.generation.activity.network import REVERSE_DNS

        hostname = REVERSE_DNS.get(ip, "-")
        if dst_port == 25 and hostname in {"imap.gmail.com", "pop.gmail.com"}:
            return "smtp.gmail.com"
        return hostname

    def _get_stable_process_guid(
        self,
        hostname: str,
        pid: int,
        fallback_timestamp: datetime,
        *,
        rendered_create_time: datetime | None = None,
    ) -> str:
        """Generate ProcessGuid using the rendered process-create time.

        Sysmon encodes the visible Event 1 time in the ProcessGuid. Use the
        deterministic process-create source offset so Event 1 and all follow-on
        events share the same source-native identifier.
        """
        if rendered_create_time is None:
            ts = fallback_timestamp
            canonical_event = getattr(self._emission_context, "canonical_event", None)
            timing_plan = canonical_event.source_timing if canonical_event is not None else None
            if timing_plan is None or timing_plan.compatibility_mode:
                sm = getattr(self, "_state_manager", None)
                if sm and pid > 0:
                    proc = sm.get_process(hostname, pid)
                    if proc is not None and proc.start_time <= fallback_timestamp:
                        ts = proc.start_time
            if timing_plan is not None:
                rendered_create_time = timing_plan.finalized_times.get(
                    sysmon_process_identity_render_key(hostname, pid, ts)
                ) or timing_plan.finalized_times.get(sysmon_process_pid_render_key(hostname, pid))
                if rendered_create_time is None and not timing_plan.compatibility_mode:
                    raise RuntimeError(
                        "Sysmon ProcessGuid requires a frozen process-create source time: "
                        f"host={hostname} pid={pid} started_at={ensure_utc(ts).isoformat()}"
                    )
            if rendered_create_time is None:
                rendered_create_time = compatibility_process_create_time(
                    ts,
                    format_name="windows_event_sysmon",
                    hostname=hostname,
                    pid=pid,
                )
        base_guid = self._generate_process_guid(hostname, pid, rendered_create_time)
        return self._final_process_guids.get((hostname, pid, base_guid), base_guid)

    @staticmethod
    def _compatibility_parent_process_render_time(
        host: HostContext,
        process: ProcessContext,
        parent_started_at: datetime,
    ) -> datetime:
        """Return the stateless direct-render envelope for an Event 1 parent."""

        parent_event = OccurrenceBuilder(
            timestamp=parent_started_at,
            event_type="process_create",
            src_host=host,
            process=ProcessContext(
                pid=process.parent_pid,
                parent_pid=0,
                image=process.parent_image or "-",
                command_line=process.parent_command_line or "-",
                username="",
                start_time=parent_started_at,
            ),
        )
        _native_time, render_time = compatibility_endpoint_event_times(
            parent_event,
            "windows_event_sysmon",
            host.hostname,
            "process_create",
        )
        return render_time

    def can_handle(self, event: CanonicalOccurrence) -> bool:
        """Sysmon emitter handles supported event types on Windows hosts."""
        if event.event_type not in self._supported_types:
            return False
        if event.src_host is None or event.src_host.os_category != "windows":
            return False
        return True

    def emit(self, event: CanonicalOccurrence) -> None:
        """Dispatch to per-type render method, applying Sysmon filters."""
        self._emission_context.canonical_event = event
        self._emission_context.host_type = (
            event.src_host.system_type if event.src_host is not None else ""
        )
        try:
            if event.event_type in ("process_create", "system_process_create"):
                self._render_sysmon_process_create(event)
            elif event.event_type == "process_terminate":
                self._render_sysmon_process_terminate(event)
            elif event.event_type == "create_remote_thread":
                self._render_sysmon_create_remote_thread(event)
            elif event.event_type == "process_access":
                self._render_sysmon_process_access(event)
            elif event.event_type == "connection":
                # Connection events can produce Event 3 (NetworkConnect) and/or Event 22 (DNSQuery)
                is_application_layer_only = (
                    event.network is not None and event.network.application_layer_only
                )
                production_projection = (
                    event.source_timing is not None and not event.source_timing.compatibility_mode
                )
                event3_eligible = (
                    self._event3_projection_eligible(event)
                    if production_projection
                    else self._passes_event3_filter(event)
                )
                if not is_application_layer_only and event3_eligible:
                    self._render_sysmon_network_connect(event)
                if event.dns and self._passes_event22_filter(event):
                    self._render_sysmon_dns_query(event)
            elif event.event_type in ("file_create", "file_modify"):
                if event.file and self._passes_event11_filter(event):
                    self._render_sysmon_file_create(event)
            elif event.event_type == "registry_modify":
                if event.registry:
                    self._render_sysmon_registry_event(event)
            elif event.event_type == "image_load":
                if event.image_load and self._passes_event7_filter(event):
                    self._render_sysmon_image_loaded(event)
        finally:
            self._emission_context.host_type = ""
            self._emission_context.canonical_event = None

    @staticmethod
    def _format_user(username: str, netbios_domain: str) -> str:
        """Format Sysmon User field with correct domain for well-known accounts.

        Windows always reports SYSTEM, LOCAL SERVICE, and NETWORK SERVICE
        under 'NT AUTHORITY', never under the AD domain name.
        """
        if "\\" in username:
            return username
        domain = _subject_domain(username, netbios_domain)
        return f"{domain}\\{username}"

    @staticmethod
    def _fallback_user_sid(username: str) -> str:
        """Return a deterministic SID when older callers omit AuthContext.user_sid."""
        normalized = username.split("\\")[-1].upper()
        well_known = {
            "SYSTEM": "S-1-5-18",
            "LOCAL SERVICE": "S-1-5-19",
            "NETWORK SERVICE": "S-1-5-20",
        }
        if normalized in well_known:
            return well_known[normalized]
        rid = 1000 + (_stable_seed(f"sysmon_hku_sid:{normalized.lower()}") % 50000)
        return f"S-1-5-21-0-0-0-{rid}"

    def _native_registry_target_object(self, target_object: str, event: CanonicalOccurrence) -> str:
        """Render user-hive aliases as Sysmon-native HKU\\SID paths."""
        if not target_object.startswith("HKCU\\"):
            return target_object
        username = ""
        sid = ""
        if event.auth is not None:
            username = event.auth.username or ""
            sid = event.auth.user_sid or ""
        if not username and event.process is not None:
            username = event.process.username or ""
        if not sid:
            sid = self._fallback_user_sid(username or "user")
        suffix = target_object.removeprefix("HKCU\\")
        return f"HKU\\{sid}\\{suffix}"

    def _generate_process_guid(self, hostname: str, pid: int, timestamp: datetime) -> str:
        """Generate a deterministic Sysmon ProcessGuid from host+pid+time.

        Sysmon ProcessGuid values are source-specific correlation IDs, not RFC
        UUIDs. Public native samples commonly expose a stable machine prefix,
        process creation time as low/high 16-bit Unix-time words, a non-version
        process word, and a zero-heavy token suffix. Keep the value
        deterministic without rendering a UUID-like random tail.
        """
        machine_prefix = hashlib.md5(
            f"sysmon_machine_{hostname}".encode(), usedforsecurity=False
        ).hexdigest()[:8]

        unix_ts = int(timestamp.timestamp())
        boot_time = getattr(self, "_host_boot_times", {}).get(hostname)
        boot_seed = int(boot_time.timestamp()) if boot_time else 0

        time_low = unix_ts & 0xFFFF
        time_high = (unix_ts >> 16) & 0xFFFF

        seed = f"{hostname}:{pid}:{timestamp.isoformat()}:{boot_seed}"
        h = hashlib.md5(seed.encode(), usedforsecurity=False).hexdigest()
        token_word = (int(h[:2], 16) << 8) | (int(h[2:4], 16) & 0x02)
        token_counter = int(h[4:12], 16)
        tail_prefix = "0010" if int(h[12:14], 16) & 1 else "0000"

        return (
            f"{{{machine_prefix}-{time_low:04x}-{time_high:04x}-"
            f"{token_word:04x}-{tail_prefix}{token_counter:08x}}}"
        )

    @classmethod
    def _generate_hashes(
        cls,
        image: str,
        host: Any | str | None = None,
        rendered_identity: tuple[Any, ...] | None = None,
    ) -> str:
        """Generate deterministic fake file hashes from image path.

        Hashes are keyed by rendered file identity, not signature validation
        state. That keeps identical Image/FileVersion/OriginalFileName tuples
        stable across the fleet while still allowing different Windows builds
        or app versions to differ.
        """
        normalized_image = image.replace("/", "\\").lower()
        seed = normalized_image
        if rendered_identity is not None:
            file_identity = rendered_identity[:5]
            seed = f"{normalized_image}:{':'.join(str(part) for part in file_identity)}"
        elif host is not None and not isinstance(host, str):
            fv, _desc, prod, company, orig = cls._get_pe_metadata(image, host)
            seed = f"{normalized_image}:{fv}:{prod}:{company}:{orig}"
        sha1 = hashlib.sha1(seed.encode(), usedforsecurity=False).hexdigest().upper()
        md5 = hashlib.md5(seed.encode(), usedforsecurity=False).hexdigest().upper()
        sha256 = hashlib.sha256(seed.encode(), usedforsecurity=False).hexdigest().upper()
        imphash = hashlib.md5(f"imp:{seed}".encode(), usedforsecurity=False).hexdigest().upper()
        return f"SHA1={sha1},MD5={md5},SHA256={sha256},IMPHASH={imphash}"

    def _resolve_logon_guid(self, hostname: str, logon_id: str, auth: Any | None) -> str:
        """Resolve the canonical Windows LogonGuid for Sysmon process telemetry."""
        if auth is not None and getattr(auth, "logon_guid", ""):
            return auth.logon_guid
        sm = getattr(self, "_state_manager", None)
        if sm is not None and logon_id:
            identity = sm.get_session_identity(logon_id)
            if identity is not None and identity.logon_guid:
                return identity.logon_guid
        return "{00000000-0000-0000-0000-000000000000}"

    def _render_sysmon_process_create(self, event: CanonicalOccurrence) -> None:
        """Render Sysmon Event 1 (ProcessCreate)."""
        proc = event.process
        auth = event.auth
        host = event.src_host
        native_time, render_time = self._render_times(event, "process_create")
        plan = event.source_timing
        utc_time = _format_sysmon_utc_time(native_time)
        process_guid = self._get_stable_process_guid(
            host.hostname,
            proc.pid,
            proc.start_time or event.timestamp,
            rendered_create_time=render_time,
        )
        parent_proc = None
        sm = getattr(self, "_state_manager", None)
        if sm and proc.parent_pid > 0:
            parent_proc = sm.get_process(host.hostname, proc.parent_pid)
        child_start = proc.start_time or event.timestamp
        _parent_ts = (
            proc.parent_start_time
            if proc.parent_start_time is not None
            else parent_proc.start_time
            if parent_proc is not None and parent_proc.start_time <= child_start
            else self._host_boot_times.get(host.hostname, child_start - timedelta(days=7))
        )
        parent_render_time = (
            plan.finalized_times.get(sysmon_parent_process_render_key(host.hostname))
            if plan is not None
            else None
        )
        if parent_render_time is None:
            if plan is not None and not plan.compatibility_mode:
                raise RuntimeError(
                    "Sysmon Event 1 requires a frozen parent process-create source time: "
                    f"host={host.hostname} parent_pid={proc.parent_pid} "
                    f"started_at={ensure_utc(_parent_ts).isoformat()}"
                )
            parent_render_time = self._compatibility_parent_process_render_time(
                host,
                proc,
                _parent_ts,
            )
        parent_guid = self._get_stable_process_guid(
            host.hostname,
            proc.parent_pid,
            _parent_ts,
            rendered_create_time=parent_render_time,
        )

        # Determine user string
        if auth and auth.username:
            user = self._format_user(auth.username, host.netbios_domain)
            logon_id = auth.logon_id if hasattr(auth, "logon_id") and auth.logon_id else "0x3e7"
        else:
            user = "NT AUTHORITY\\SYSTEM"
            logon_id = "0x3e7"
        parent_user = self._sysmon_parent_user(host, parent_proc, proc, user)

        integrity = proc.integrity_level if proc.integrity_level else "Medium"

        event_data = {
            "EventID": 1,
            "TimeCreated": render_time,
            "Computer": host.fqdn,
            "Channel": "Microsoft-Windows-Sysmon/Operational",
            "Level": 4,
            "ExecutionProcessID": self._get_sysmon_pid(host.hostname),
            "ExecutionThreadID": self._get_sysmon_thread_id(host.hostname),
            "UtcTime": utc_time,
            "ProcessGuid": process_guid,
            "ProcessId": proc.pid,
            "Image": proc.image,
            "CommandLine": proc.command_line,
            "User": user,
            "LogonGuid": self._resolve_logon_guid(host.hostname, logon_id, auth),
            "LogonId": logon_id,
            "TerminalSessionId": self._terminal_session_id(host.hostname, auth, logon_id),
            "IntegrityLevel": integrity,
            "Hashes": self._generate_hashes(proc.image, host),
            "ParentProcessGuid": parent_guid,
            "ParentProcessId": proc.parent_pid,
            "ParentImage": proc.parent_image or "-",
            "ParentCommandLine": proc.parent_command_line
            if hasattr(proc, "parent_command_line") and proc.parent_command_line
            else "-",
            "ParentUser": parent_user,
            "CurrentDirectory": proc.current_directory or self._default_current_directory(proc),
        }
        self._apply_finalized_times(event_data, native_time, render_time)
        # Populate PE metadata from known binary lookup
        fv, desc, prod, company, orig = self._get_pe_metadata(proc.image, host)
        event_data["FileVersion"] = fv
        event_data["Description"] = desc
        event_data["Product"] = prod
        event_data["Company"] = company
        event_data["OriginalFileName"] = orig
        self.emit_event(event_data)

    def _sysmon_parent_user(
        self,
        host: HostContext,
        parent_proc: Any | None,
        proc: ProcessContext,
        child_user: str,
    ) -> str:
        """Return Sysmon Event 1 ParentUser for the modeled parent process."""
        parent_username = str(getattr(parent_proc, "username", "") or "")
        if parent_username:
            return self._format_user(parent_username, host.netbios_domain)
        if proc.parent_pid in {0, 4}:
            return "NT AUTHORITY\\SYSTEM"
        parent_image = (proc.parent_image or "").lower()
        if "\\windows\\system32\\services.exe" in parent_image or parent_image.endswith(
            "\\services.exe"
        ):
            return "NT AUTHORITY\\SYSTEM"
        return child_user or "-"

    @staticmethod
    def _default_current_directory(proc: ProcessContext) -> str:
        """Fallback for older ProcessContext callers that do not set a working directory."""
        image = proc.image.replace("/", "\\")
        image_lower = image.lower()
        username = proc.username.split("\\")[-1]
        if username in {"SYSTEM", "LOCAL SERVICE", "NETWORK SERVICE"} or username.endswith("$"):
            return "C:\\Windows\\System32\\"
        if "\\windows\\system32\\" in image_lower or "\\windows\\syswow64\\" in image_lower:
            return "C:\\Windows\\System32\\"
        if "\\" in image:
            return image.rsplit("\\", 1)[0] + "\\"
        return f"C:\\Users\\{username}\\"

    def _render_sysmon_process_terminate(self, event: CanonicalOccurrence) -> None:
        """Render Sysmon Event 5 (ProcessTerminate)."""
        proc = event.process
        auth = event.auth
        host = event.src_host
        native_time, render_time = self._render_times(event, "process_terminate")
        utc_time = _format_sysmon_utc_time(native_time)
        process_guid = self._get_stable_process_guid(
            host.hostname, proc.pid, proc.start_time or event.timestamp
        )

        if auth and auth.username:
            user = self._format_user(auth.username, host.netbios_domain)
        else:
            user = "NT AUTHORITY\\SYSTEM"

        event_data = {
            "EventID": 5,
            "TimeCreated": render_time,
            "Computer": host.fqdn,
            "Channel": "Microsoft-Windows-Sysmon/Operational",
            "Level": 4,
            "ExecutionProcessID": self._get_sysmon_pid(host.hostname),
            "ExecutionThreadID": self._get_sysmon_thread_id(host.hostname),
            "UtcTime": utc_time,
            "ProcessGuid": process_guid,
            "ProcessId": proc.pid,
            "Image": proc.image,
            "User": user,
        }
        self._apply_finalized_times(event_data, native_time, render_time)
        self.emit_event(event_data)

    @staticmethod
    def _resolve_full_image_path(image: str, username: str = "") -> str:
        """Ensure a Windows image path is fully qualified.

        Sysmon always logs full paths. If only a bare filename is provided,
        resolve it via the application catalog (user apps get Program Files,
        system binaries get System32).
        """
        if "\\" not in image and "/" not in image:
            from evidenceforge.generation.activity.application_catalog import (
                resolve_image_path,
            )

            return resolve_image_path(image, "windows", username=username)
        return image

    def _terminal_session_id(self, hostname: str, auth: Any | None, logon_id: str) -> int:
        """Return the canonical TerminalSessionId for Sysmon process creates."""
        if auth is None:
            return 0
        username = (auth.username or "").upper()
        if username in {"SYSTEM", "LOCAL SERVICE", "NETWORK SERVICE", "ANONYMOUS LOGON"}:
            return 0
        key = (hostname, logon_id or username)
        with self._sysmon_render_state_mutation() as participant:
            sessions = self._validate_sysmon_render_mapping(
                getattr(self, "_terminal_session_ids_by_logon", None),
                label="terminal-session",
            )
            if sessions is None:
                raise ExactPublicationError("Sysmon terminal-session mapping disappeared")
            receipt: _SysmonIntMutationReceipt | None = None
            if participant is not None and auth.session_id > 0:
                receipt = self._exact_int_mutation_receipt_unlocked(
                    participant.terminal_session_receipts,
                    sessions,
                    key,
                    label="terminal-session",
                )
            try:
                if auth.session_id > 0:
                    sessions[key] = auth.session_id
                    return auth.session_id
                retained = sessions.get(key, 0)
                if type(retained) is not int or retained < 0:
                    raise ExactPublicationError("Sysmon terminal-session entry is malformed")
                return retained
            finally:
                if receipt is not None:
                    receipt.expected = self._sysmon_int_entry_state_unlocked(
                        sessions,
                        key,
                        label="terminal-session",
                    )

    def _render_sysmon_create_remote_thread(self, event: CanonicalOccurrence) -> None:
        """Render Sysmon Event 8 (CreateRemoteThread)."""
        host = event.src_host
        proc = event.process  # Source process
        auth = event.auth
        remote_thread = event.remote_thread

        utc_time = event.timestamp.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
        source_guid = self._get_stable_process_guid(
            host.hostname, proc.pid, proc.start_time or event.timestamp
        )

        target_pid = (
            remote_thread.target_pid
            if remote_thread is not None
            else int(auth.source_port)
            if auth and auth.source_port
            else 0
        )
        target_username = auth.username if auth else ""
        target_image = self._resolve_full_image_path(
            remote_thread.target_image
            if remote_thread is not None
            else auth.target_server
            if auth and auth.target_server
            else r"C:\Windows\explorer.exe",
            username=target_username,
        )
        target_guid = self._get_stable_process_guid(host.hostname, target_pid, event.timestamp)
        source_user = self._format_user(proc.username or target_username, host.netbios_domain)
        target_identity = event.identity_plan.target if event.identity_plan is not None else None
        target_principal = str(getattr(target_identity, "principal", "") or "")
        target_user = (
            self._format_user(target_principal, host.netbios_domain)
            if target_principal
            else "NT AUTHORITY\\SYSTEM"
        )

        event_data = {
            "EventID": 8,
            "TimeCreated": event.timestamp,
            "Computer": host.fqdn,
            "Channel": "Microsoft-Windows-Sysmon/Operational",
            "Level": 4,
            "ExecutionProcessID": self._get_sysmon_pid(host.hostname),
            "ExecutionThreadID": self._get_sysmon_thread_id(host.hostname),
            "UtcTime": utc_time,
            "SourceProcessGuid": source_guid,
            "SourceProcessId": proc.pid,
            "SourceImage": proc.image,
            "TargetProcessGuid": target_guid,
            "TargetProcessId": target_pid,
            "TargetImage": target_image,
            "NewThreadId": remote_thread.new_thread_id if remote_thread else 0,
            "StartAddress": f"0x{remote_thread.start_address:08X}" if remote_thread else "0x0",
            "StartModule": remote_thread.start_module if remote_thread else "",
            "StartFunction": remote_thread.start_function if remote_thread else "",
            "SourceUser": source_user,
            "TargetUser": target_user,
        }
        self.emit_event(event_data)

    def _render_sysmon_process_access(self, event: CanonicalOccurrence) -> None:
        """Render Sysmon Event 10 (ProcessAccess).

        Primary detection for credential dumping (e.g., mimikatz accessing lsass.exe).
        Source process reads target process memory with specific access rights.
        """
        rng = self._event_rng(event)
        host = event.src_host
        proc = event.process  # Source process
        access = event.process_access

        utc_time = event.timestamp.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
        source_guid = self._get_stable_process_guid(
            host.hostname, proc.pid, proc.start_time or event.timestamp
        )

        target_pid = access.target_pid if access else rng.randint(500, 800)
        target_image = self._resolve_full_image_path(
            access.target_image if access else r"C:\Windows\System32\lsass.exe",
            username=proc.username,
        )
        target_guid = self._get_stable_process_guid(host.hostname, target_pid, event.timestamp)

        # Determine user string
        if event.auth and event.auth.username:
            user = self._format_user(event.auth.username, host.netbios_domain)
        elif proc.username:
            user = self._format_user(proc.username, host.netbios_domain)
        else:
            user = "NT AUTHORITY\\SYSTEM"

        # GrantedAccess values for credential dumping:
        # 0x1010 = PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ
        # 0x1FFFFF = PROCESS_ALL_ACCESS
        # 0x1438 = typical mimikatz access mask
        granted_access = access.granted_access if access else "0x1010"
        target_user = (
            self._format_user(access.target_user, host.netbios_domain)
            if access and access.target_user
            else "NT AUTHORITY\\SYSTEM"
        )
        if access is None or access.source_thread_id < 0:
            raise ValueError("Sysmon ProcessAccess requires a canonical source thread ID")

        event_data = {
            "EventID": 10,
            "TimeCreated": event.timestamp,
            "Computer": host.fqdn,
            "Channel": "Microsoft-Windows-Sysmon/Operational",
            "Level": 4,
            "ExecutionProcessID": self._get_sysmon_pid(host.hostname),
            "ExecutionThreadID": self._get_sysmon_thread_id(host.hostname),
            "UtcTime": utc_time,
            "SourceProcessGUID": source_guid,
            "SourceProcessId": proc.pid,
            "SourceThreadId": access.source_thread_id,
            "SourceImage": proc.image,
            "TargetProcessGUID": target_guid,
            "TargetProcessId": target_pid,
            "TargetImage": target_image,
            "GrantedAccess": granted_access,
            "CallTrace": access.call_trace
            if access and access.call_trace
            else self._get_call_trace(host.hostname),
            "SourceUser": user,
            "TargetUser": target_user,
        }
        self.emit_event(event_data)

    # --- Sysmon filter methods (data-driven from sysmon_filters.yaml) ---

    def _get_filters(self) -> dict:
        """Return the loaded Sysmon filter config (cached)."""
        if exact_publication_attempt_active():
            filters = self.__dict__.get("_filters")
            if filters is None:
                filters = load_sysmon_filters()
            retained = self._validate_sysmon_render_mapping(
                filters,
                label="filter cache",
            )
            if retained is None:
                raise ExactPublicationError("Sysmon filter cache disappeared")
            return retained

        with self._sysmon_render_state_mutation():
            if "_filters" not in self.__dict__:
                loaded = load_sysmon_filters()
                if type(loaded) is not dict:
                    raise ExactPublicationError("Sysmon filter cache is malformed")
                self._filters = loaded
            filters = self._validate_sysmon_render_mapping(
                getattr(self, "_filters", None),
                label="filter cache",
            )
            if filters is None:
                raise ExactPublicationError("Sysmon filter cache disappeared")
            return filters

    @staticmethod
    def _event3_filter_matches(
        event: CanonicalOccurrence,
        cfg: dict[object, object],
        image: str,
    ) -> bool:
        """Evaluate the allocation-free Event 3 policy for one resolved image."""

        if not cfg.get("enabled", True):
            return False
        if not event.network:
            return False

        mode = cfg.get("mode", "include")
        if mode != "include":
            return True  # No filtering

        # Check excluded destination IPs
        dst_ip = event.network.dst_ip or ""
        exclude_ips = cfg.get("exclude_dest_ips", [])
        if dst_ip in exclude_ips:
            return False

        image = image.rsplit("\\", 1)[-1].rsplit("/", 1)[-1].lower()
        include_images = [img.lower() for img in cfg.get("include_images", [])]
        if image in include_images:
            return True

        # Baseline system images: sampled at a lower rate for volume balance
        # Use stable seed for deterministic sampling (same connection → same decision)
        hostname = event.src_host.hostname if event.src_host else ""
        _net = event.network
        _uid = _net.zeek_uid or _net.conn_id or event.timestamp.isoformat()
        _seed_key = f"sysmon3_{hostname}_{image}_{_net.dst_ip}_{_net.dst_port}_{_uid}"
        _sample_float = (_stable_seed(_seed_key) & 0xFFFFFFFF) / 0xFFFFFFFF

        baseline_images = [img.lower() for img in cfg.get("include_baseline_images", [])]
        if image in baseline_images:
            sample_rate = cfg.get("baseline_sample_rate", 0.10)
            if _sample_float < sample_rate:
                return True

        # User application images: low sampling rate for non-zero presence
        user_app_images = [img.lower() for img in cfg.get("include_user_app_images", [])]
        if image in user_app_images:
            rate = cfg.get("user_app_sample_rate", 0.05)
            if _sample_float < rate:
                return True

        dst_port = event.network.dst_port or 0
        include_ports = cfg.get("include_dest_ports", [])
        if dst_port in include_ports:
            # Enforce port-process constraints if defined (e.g., port 22 only from ssh.exe)
            constraints = cfg.get("port_process_constraints", {})
            allowed = constraints.get(dst_port)
            if allowed is not None:
                if not image or image not in [p.lower() for p in allowed]:
                    return False
            return True

        return False

    def _passes_event3_filter(self, event: CanonicalOccurrence) -> bool:
        """Check if a connection event passes the Event 3 (NetworkConnect) filter."""

        cfg = self._get_filters().get("network_connect", {})
        image = ""
        host = event.src_host
        carrier_process = self._carrier_owned_process(event, host) if host is not None else None
        if carrier_process is not None:
            image = carrier_process[1]
        elif event.source_timing is not None and not event.source_timing.compatibility_mode:
            return False
        elif event.network and event.network.initiating_pid > 0 and event.src_host:
            _pid, resolved_image = self._resolve_process_from_pid(
                event.src_host.hostname, event.network.initiating_pid
            )
            image = resolved_image
        return self._event3_filter_matches(event, cfg, image)

    def _event3_projection_eligible(self, event: CanonicalOccurrence) -> bool:
        """Return whether one compiled connection can render a Sysmon Event 3 row.

        The decision reads only canonical carrier identity and an existing or
        locally loaded filter snapshot. It never consults StateManager, allocates
        emitter state, or fabricates process attribution.
        """

        host = event.src_host
        network = event.network
        if (
            event.event_type != "connection"
            or host is None
            or host.os_category != "windows"
            or network is None
            or network.application_layer_only
        ):
            return False
        carrier_process = self._carrier_owned_process(event, host)
        if carrier_process is None:
            return False
        pid, image, _principal, _started_at = carrier_process
        if pid <= 0 or not image or image == "-":
            return False
        owner_state = object.__getattribute__(self, "__dict__")
        filters = dict.get(owner_state, "_filters")
        if filters is None:
            filters = load_sysmon_filters()
        retained = self._validate_sysmon_render_mapping(
            filters,
            label="projection filter",
        )
        if retained is None:
            raise ExactPublicationError("Sysmon projection filter disappeared")
        cfg = retained.get("network_connect", {})
        if type(cfg) is not dict:
            raise ExactPublicationError("Sysmon Event 3 projection filter is malformed")
        return self._event3_filter_matches(event, cfg, image)

    def _passes_event7_filter(self, event: CanonicalOccurrence) -> bool:
        """Check if an image_load event passes the Event 7 (ImageLoaded) filter."""
        cfg = self._get_filters().get("image_loaded", {})
        if not cfg.get("enabled", True):
            return False
        if not event.image_load:
            return False

        mode = cfg.get("mode", "exclude")
        if mode != "exclude":
            return True

        dll_path = event.image_load.image_loaded
        exclude_prefixes = cfg.get("exclude_image_loaded_prefixes", [])
        for prefix in exclude_prefixes:
            if dll_path.lower().startswith(prefix.lower()):
                # Also check signature exclusion for Microsoft-signed DLLs
                exclude_sigs = cfg.get("exclude_signatures", [])
                sig = event.image_load.signature
                if sig and any(s.lower() in sig.lower() for s in exclude_sigs):
                    return False
        return True

    def _passes_event11_filter(self, event: CanonicalOccurrence) -> bool:
        """Check if a file event passes the Event 11 (FileCreate) filter."""
        cfg = self._get_filters().get("file_create", {})
        if not cfg.get("enabled", True):
            return False
        if not event.file:
            return False

        mode = cfg.get("mode", "include")
        if mode != "include":
            return True

        path = event.file.path
        path_lower = path.lower()

        # Check path patterns
        for pattern in cfg.get("include_target_paths", []):
            if pattern.lower() in path_lower:
                return True

        # Check extensions
        for ext in cfg.get("include_extensions", []):
            if path_lower.endswith(ext.lower()):
                return True

        return False

    def _passes_event12_13_filter(self, event: CanonicalOccurrence) -> bool:
        """Check if a registry event passes the Events 12/13 filter."""
        cfg = self._get_filters().get("registry_event", {})
        if not cfg.get("enabled", True):
            return False
        if not event.registry:
            return False

        # Determine if this is Event 12 (create/delete) or 13 (modify/set)
        action = event.registry.action
        if action == "create" and not cfg.get("log_create_key", False):
            return False

        mode = cfg.get("mode", "include")
        if mode != "include":
            return True

        key = event.registry.key
        key_lower = key.lower()
        for pattern in cfg.get("include_key_patterns", []):
            if pattern.lower() in key_lower:
                return True

        return False

    def _passes_event22_filter(self, event: CanonicalOccurrence) -> bool:
        """Check if a DNS event passes the Event 22 (DNSQuery) filter."""
        cfg = self._get_filters().get("dns_query", {})
        if not cfg.get("enabled", True):
            return False
        if not event.dns:
            return False

        exclude_suffixes = cfg.get("exclude_query_suffixes", [])
        query = event.dns.query.lower()
        for suffix in exclude_suffixes:
            if query.endswith(suffix.lower()):
                return False

        return True

    # --- New render methods for Events 3, 7, 11, 12/13, 22 ---

    def _render_sysmon_network_connect(self, event: CanonicalOccurrence) -> None:
        """Render Sysmon Event 3 (NetworkConnect)."""
        host = event.src_host
        net = event.network

        # Process info — use ProcessContext if available, else resolve from
        # initiating_pid via StateManager lookup. Real Sysmon always knows the
        # originating process. Production consumes only a carrier-owned process
        # whose ProcessGuid seed was frozen upstream; StateManager lookup remains
        # a direct-compatibility fallback.
        carrier_process = self._carrier_owned_process(event, host)
        process_username = ""
        if carrier_process is not None:
            pid, image, process_username, process_start_time = carrier_process
        elif event.source_timing is not None and not event.source_timing.compatibility_mode:
            return
        else:
            initiating_pid = net.initiating_pid if net else -1
            pid, image = self._resolve_process_from_pid(host.hostname, initiating_pid)
            process_start_time = event.timestamp
        if pid <= 0 or image == "-":
            return  # Cannot attribute to a process — don't emit phantom Event 3
        native_time, render_time = self._render_times(event, "network")
        utc_time = _format_sysmon_utc_time(native_time)
        process_guid = self._get_stable_process_guid(
            host.hostname,
            pid,
            process_start_time,
        )

        # User — resolve from AuthContext, ProcessContext, or StateManager
        user = ""
        if event.auth and event.auth.username:
            user = self._format_user(event.auth.username, host.netbios_domain)
        elif process_username:
            user = self._format_user(process_username, host.netbios_domain)
        elif pid > 0:
            sm = getattr(self, "_state_manager", None)
            if sm:
                rp = sm.get_process(host.hostname, pid)
                if rp and rp.username:
                    user = self._format_user(rp.username, host.netbios_domain)
        if not user:
            user = "NT AUTHORITY\\SYSTEM"

        src_ip = net.src_ip or host.ip
        dst_ip = net.dst_ip or ""
        src_port = net.src_port or 0
        dst_port = net.dst_port or 0
        proto = (net.protocol or "tcp").lower()

        event_data = {
            "EventID": 3,
            "TimeCreated": render_time,
            "Computer": host.fqdn,
            "Channel": "Microsoft-Windows-Sysmon/Operational",
            "Level": 4,
            "ExecutionProcessID": self._get_sysmon_pid(host.hostname),
            "ExecutionThreadID": self._get_sysmon_thread_id(host.hostname),
            "UtcTime": utc_time,
            "ProcessGuid": process_guid,
            "ProcessId": pid,
            "Image": image,
            "User": user,
            "Protocol": proto,
            "Initiated": "true",
            "SourceIsIpv6": "true" if ":" in src_ip else "false",
            "SourceIp": src_ip,
            "SourceHostname": host.fqdn,
            "SourcePort": src_port,
            "SourcePortName": _PORT_NAMES.get(src_port, "-"),
            "DestinationIsIpv6": "true" if ":" in dst_ip else "false",
            "DestinationIp": dst_ip,
            "DestinationHostname": self._resolve_destination_hostname(dst_ip, dst_port),
            "DestinationPort": dst_port,
            "DestinationPortName": _PORT_NAMES.get(dst_port, "-"),
        }
        self._apply_finalized_times(event_data, native_time, render_time)
        self.emit_event(event_data)

    def _render_sysmon_image_loaded(self, event: CanonicalOccurrence) -> None:
        """Render Sysmon Event 7 (ImageLoaded)."""
        rng = self._event_rng(event)
        host = event.src_host
        proc = event.process
        il = event.image_load

        if (proc is None or proc.pid <= 0) and event.source_timing is not None:
            if not event.source_timing.compatibility_mode:
                return
        pid = proc.pid if proc else rng.randint(1000, 5000)
        image = proc.image if proc else r"C:\Windows\System32\svchost.exe"
        process_start_time = proc.start_time if proc and proc.start_time else event.timestamp
        native_time, render_time = self._render_times(event)
        utc_time = _format_sysmon_utc_time(native_time)
        process_guid = self._get_stable_process_guid(host.hostname, pid, process_start_time)

        # PE metadata for the loaded DLL
        fv, desc, prod, company, orig = self._get_pe_metadata(il.image_loaded, host)
        if il.signed and (fv, desc, prod, company, orig) == ("-", "-", "-", "-", "-"):
            fv, desc, prod, company, orig = self._signed_module_metadata(
                il.image_loaded,
                il.signature,
            )
        signature_status = il.signature_status if il.signed else "Unavailable"
        if event.auth and event.auth.username:
            user = self._format_user(event.auth.username, host.netbios_domain)
        elif proc and proc.username:
            user = self._format_user(proc.username, host.netbios_domain)
        else:
            user = "NT AUTHORITY\\SYSTEM"
        hashes = self._generate_hashes(
            il.image_loaded,
            host,
            rendered_identity=(
                fv,
                desc,
                prod,
                company,
                orig,
            ),
        )

        event_data = {
            "EventID": 7,
            "TimeCreated": render_time,
            "Computer": host.fqdn,
            "Channel": "Microsoft-Windows-Sysmon/Operational",
            "Level": 4,
            "ExecutionProcessID": self._get_sysmon_pid(host.hostname),
            "ExecutionThreadID": self._get_sysmon_thread_id(host.hostname),
            "UtcTime": utc_time,
            "ProcessGuid": process_guid,
            "ProcessId": pid,
            "Image": image,
            "ImageLoaded": il.image_loaded,
            "FileVersion": fv,
            "Description": desc,
            "Product": prod,
            "Company": company,
            "OriginalFileName": orig,
            "Hashes": hashes,
            "Signed": "true" if il.signed else "false",
            "Signature": il.signature if il.signed else "-",
            "SignatureStatus": signature_status,
            "User": user,
        }
        self._apply_finalized_times(event_data, native_time, render_time)
        self.emit_event(event_data)

    def _render_sysmon_file_create(self, event: CanonicalOccurrence) -> None:
        """Render Sysmon Event 11 (FileCreate)."""
        host = event.src_host
        fc = event.file

        carrier_process = self._carrier_owned_process(event, host)
        process_username = ""
        if carrier_process is not None:
            pid, image, process_username, process_start_time = carrier_process
        elif event.source_timing is not None and not event.source_timing.compatibility_mode:
            return
        else:
            file_pid = fc.pid if fc else 0
            pid, image = self._resolve_process_from_pid(host.hostname, file_pid)
            process_start_time = event.timestamp
        native_time, render_time = self._render_times(event, "base")
        utc_time = _format_sysmon_utc_time(native_time)
        process_guid = self._get_stable_process_guid(
            host.hostname,
            pid,
            process_start_time,
        )
        if event.auth and event.auth.username:
            user = self._format_user(event.auth.username, host.netbios_domain)
        elif process_username:
            user = self._format_user(process_username, host.netbios_domain)
        else:
            user = "NT AUTHORITY\\SYSTEM"

        event_data = {
            "EventID": 11,
            "TimeCreated": render_time,
            "Computer": host.fqdn,
            "Channel": "Microsoft-Windows-Sysmon/Operational",
            "Level": 4,
            "ExecutionProcessID": self._get_sysmon_pid(host.hostname),
            "ExecutionThreadID": self._get_sysmon_thread_id(host.hostname),
            "UtcTime": utc_time,
            "ProcessGuid": process_guid,
            "ProcessId": pid,
            "Image": image,
            "TargetFilename": fc.path,
            "CreationUtcTime": utc_time,
            "User": user,
        }
        self._apply_finalized_times(event_data, native_time, render_time)
        self.emit_event(event_data)

    def _render_sysmon_registry_event(self, event: CanonicalOccurrence) -> None:
        """Render Sysmon Event 12 (CreateKey/DeleteKey) or 13 (SetValue)."""
        reg = event.registry
        if not self._passes_event12_13_filter(event):
            return
        host = event.src_host

        carrier_process = self._carrier_owned_process(event, host)
        process_username = ""
        if carrier_process is not None:
            pid, image, process_username, process_start_time = carrier_process
        elif event.source_timing is not None and not event.source_timing.compatibility_mode:
            return
        else:
            reg_pid = reg.pid if reg else 0
            pid, image = self._resolve_process_from_pid(host.hostname, reg_pid)
            process_start_time = event.timestamp
        utc_time = event.timestamp.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
        process_guid = self._get_stable_process_guid(
            host.hostname,
            pid,
            process_start_time,
        )
        if event.auth and event.auth.username:
            user = self._format_user(event.auth.username, host.netbios_domain)
        elif process_username:
            user = self._format_user(process_username, host.netbios_domain)
        else:
            user = "NT AUTHORITY\\SYSTEM"

        # Route value operations to Event 13. Sysmon Event 12 is key create/delete;
        # Event 14 would be value rename, and value deletes are not modeled separately.
        action = reg.action
        if reg.value or action == "modify":
            event_id = 13
            event_type = "SetValue"
        elif action == "delete":
            event_id = 12
            event_type = "DeleteKey"
        elif action == "create":
            event_id = 12
            event_type = "CreateKey"
        else:
            event_id = 13
            event_type = "SetValue"

        event_data = {
            "EventID": event_id,
            "TimeCreated": event.timestamp,
            "Computer": host.fqdn,
            "Channel": "Microsoft-Windows-Sysmon/Operational",
            "Level": 4,
            "ExecutionProcessID": self._get_sysmon_pid(host.hostname),
            "ExecutionThreadID": self._get_sysmon_thread_id(host.hostname),
            "UtcTime": utc_time,
            "ProcessGuid": process_guid,
            "ProcessId": pid,
            "Image": image,
            "EventType": event_type,
            "TargetObject": self._native_registry_target_object(reg.key, event),
        }

        # Event 13 includes the Details field
        if event_id == 13:
            event_data["Details"] = (
                "Binary Data" if reg.value_type == "binary" else reg.value or "-"
            )
        event_data["User"] = user

        self.emit_event(event_data)

    def _render_sysmon_dns_query(self, event: CanonicalOccurrence) -> None:
        """Render Sysmon Event 22 (DNSQuery)."""
        host = event.src_host
        dns = event.dns

        # Sysmon Event 22 attributes the query to the initiating application,
        # while WFP/eCAR may separately identify the DNS Client service that
        # owns UDP/53 transport. Fall back to that service only when the
        # direct compatibility call has no carrier-owned process identity.
        query_process = dns.query_process
        if query_process is not None and query_process.pid > 0:
            dns_client_pid = query_process.pid
            process_start_time = query_process.start_time or event.timestamp
            image = query_process.image
            user = self._format_user(query_process.username, host.netbios_domain)
        elif event.process is not None and event.process.pid > 0:
            dns_client_pid = event.process.pid
            process_start_time = event.process.start_time or event.timestamp
            image = event.process.image
            user = self._format_user(event.process.username, host.netbios_domain)
        else:
            actor = event.identity_plan.actor if event.identity_plan is not None else None
            if isinstance(actor, ProcessIdentity) and (
                actor.pid > 0 and actor.hostname.casefold() == host.hostname.casefold()
            ):
                dns_client_pid = actor.pid
                process_start_time = actor.started_at
                image = actor.image or "-"
                user = (
                    self._format_user(actor.principal, host.netbios_domain)
                    if actor.principal
                    else "NT AUTHORITY\\SYSTEM"
                )
            elif event.source_timing is not None and not event.source_timing.compatibility_mode:
                return
            else:
                sys_pids = getattr(self, "_system_pids", {}).get(host.hostname, {})
                dns_client_pid = sys_pids.get(
                    "svchost_local_svc",
                    sys_pids.get("svchost_netsvcs", self._get_dns_client_pid(host.hostname)),
                )
                process_start_time = event.timestamp
                image = r"C:\Windows\System32\svchost.exe"
                user = "NT AUTHORITY\\LOCAL SERVICE"

        native_time, render_time = self._render_times(event, "dns")
        utc_time = _format_sysmon_utc_time(native_time)
        process_guid = self._get_stable_process_guid(
            host.hostname,
            dns_client_pid,
            process_start_time,
        )

        # Map DNS rcode to Windows QueryStatus
        query_status = _DNS_STATUS_MAP.get(dns.rcode, "0")

        # QueryResults: semicolon-separated IP addresses with trailing semicolon
        if dns.answers:
            query_results = ";".join(dns.answers) + ";"
        else:
            query_results = "-"

        event_data = {
            "EventID": 22,
            "TimeCreated": render_time,
            "Computer": host.fqdn,
            "Channel": "Microsoft-Windows-Sysmon/Operational",
            "Level": 4,
            "ExecutionProcessID": self._get_sysmon_pid(host.hostname),
            "ExecutionThreadID": self._get_sysmon_thread_id(host.hostname),
            "UtcTime": utc_time,
            "ProcessGuid": process_guid,
            "ProcessId": dns_client_pid,
            "QueryName": dns.query,
            "QueryStatus": query_status,
            "QueryResults": query_results,
            "Image": image,
            "User": user,
        }
        self._apply_finalized_times(event_data, native_time, render_time)
        self.emit_event(event_data)

    def _get_dns_client_pid(self, hostname: str) -> int:
        """Return stable DNS Client svchost.exe PID for a given host."""
        with self._sysmon_render_state_mutation() as participant:
            cache = getattr(self, "_dns_client_pids", None)
            if cache is None:
                cache = self._dns_client_pids = {}
            receipt: _SysmonIntMutationReceipt | None = None
            if participant is not None:
                receipt = self._exact_int_mutation_receipt_unlocked(
                    participant.dns_client_pid_receipts,
                    cache,
                    hostname,
                    label="DNS client PID",
                )
            try:
                if hostname not in cache:
                    h = int(
                        hashlib.md5(
                            f"dns_client:{hostname}".encode(),
                            usedforsecurity=False,
                        ).hexdigest(),
                        16,
                    )
                    cache[hostname] = 900 + (h % 400)
                return cache[hostname]
            finally:
                if receipt is not None:
                    receipt.expected = self._sysmon_int_entry_state_unlocked(
                        cache,
                        hostname,
                        label="DNS client PID",
                    )

    # --- Infrastructure (same pattern as WindowsEventEmitter) ---

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
    ) -> None:
        if type(source_finalization) is not bool:
            raise ValueError("Sysmon source_finalization must be one exact bool")
        if source_finalization:
            _require_windows_source_finalization_capabilities()
        for value, label in (
            (finalization_row_capacity, "row"),
            (finalization_byte_capacity, "byte"),
            (finalization_route_capacity, "route"),
        ):
            if type(value) is not int or value <= 0:
                raise ValueError(
                    f"Sysmon finalization {label} capacity must be a positive exact int"
                )
        self._direct_file_mode = output_path.suffix != ""
        self._base_dir = output_path.parent if self._direct_file_mode else output_path
        self._direct_file_path = output_path if self._direct_file_mode else None
        if source_finalization:
            self._preflight_private_spool_root()
        self._host_writers: dict[str, _SingleHostWriter] = {}
        self._snare_writers: dict[str, _SingleHostWriter] = {}
        self._host_writers_lock = Lock()

        super().__init__(format_def, output_path, buffer_size, threaded)
        self._event_dicts: list[dict[str, Any]] = []
        self._record_id_sequences: dict[str, WindowsRecordIdSequence] = {}
        self._emission_context = local()
        self._last_time_created_by_computer: dict[str, datetime] = {}
        self._time_collision_count_by_computer: dict[str, int] = {}
        self._final_process_guids: dict[tuple[str, int, str], str] = {}
        self._terminal_session_ids_by_logon: dict[tuple[str, str], int] = {}
        self._call_trace_cache: dict[str, list[str]] = {}
        self._spool_dir: Path | None = None
        self._owns_spool_dir = False
        self._spool_path: Path | None = None
        self._spool_filename: str | None = None
        self._spool_conn: sqlite3.Connection | None = None
        self._spool_sequence = 0
        self._spooled_count = 0
        self._spool_directory_descriptor: int | None = None
        self._spool_directory_identity: tuple[int, int] | None = None
        self._spool_root_descriptor: int | None = None
        self._spool_root_identity: tuple[int, int] | None = None
        self._spool_directory_name: str | None = None
        self._spool_initialization_pending = False
        self._spool_file_initialization_pending = False
        self._spool_file_identity: tuple[int, int] | None = None
        self._candidate_admitted_rows = 0
        self._candidate_admitted_bytes = 0
        self._candidate_high_water_rows = 0
        self._candidate_high_water_bytes = 0
        self._source_high_water_rows = 0
        self._source_high_water_bytes = 0
        self._source_high_water_routes = 0
        self._exact_candidate_reservations: dict[
            ExactPublicationKey,
            _SysmonExactCandidateReservation,
        ] = {}
        self._exact_candidate_participants: dict[
            ExactPublicationParticipantKey,
            _SysmonExactCandidateParticipant,
        ] = {}
        self._exact_candidate_current_rows = 0
        self._exact_candidate_current_bytes = 0
        self._exact_candidate_current_participants = 0
        self._exact_candidate_released_rows = 0
        self._exact_candidate_released_bytes = 0
        self._exact_candidate_completed_participants = 0
        self._exact_candidate_high_water_rows = 0
        self._exact_candidate_high_water_bytes = 0
        self._exact_candidate_high_water_participants = 0
        self._checkpoint_pruned_exact_sequence = 0
        self._exact_candidate_abort_close_rendering = False
        self._exact_candidate_abort_close_rows_rendered = False
        self._exact_candidate_abort_close_render_complete = False
        self._exact_candidate_abort_participant_key: ExactPublicationParticipantKey | None = None
        self._exact_candidate_abort_registered_writers: dict[int, _SingleHostWriter] = {}
        self._exact_candidate_abort_pending_row: _SysmonAbortExactPendingRow | None = None
        self._sysmon_render_state_lock = Lock()
        self._candidate_admission_lock = Lock()
        self._finalization_row_capacity = finalization_row_capacity
        self._finalization_byte_capacity = finalization_byte_capacity
        self._finalization_route_capacity = finalization_route_capacity
        self._source_finalization_state = "open"
        self._source_finalization_owner: int | None = None
        self._source_finalization_operation_lock = Lock()
        self._source_finalization_epoch: _SysmonSourceFinalizationEpoch | None = None
        self._source_finalization_ordinal = 0
        self._source_finalization_routes: dict[int, _SingleHostWriter] = {}
        self._source_finalization_route_ids: dict[tuple[str, str], int] = {}
        self._source_finalization_bound = source_finalization
        self._source_finalization_output_target: OutputTarget | None = None
        self._source_finalization_header: str | None = None
        self._source_finalization_footer: str | None = None

    def _preflight_private_spool_root(self) -> None:
        """Validate exact-spool trust and output disjointness before generation."""

        configured = os.environ.get("EFORGE_SPOOL_DIR")
        root = Path(
            os.path.realpath(
                os.fspath(Path(configured).expanduser() if configured else tempfile.gettempdir())
            )
        )
        output_root = Path(os.path.realpath(os.fspath(self._base_dir)))
        if root == output_root or root.is_relative_to(output_root):
            raise ExactPublicationError("Sysmon private spool root must be outside public output")
        ancestor = root
        while not ancestor.exists():
            if ancestor == ancestor.parent:
                raise ExactPublicationError("Sysmon private spool has no existing trusted ancestor")
            ancestor = ancestor.parent
        self._validate_private_spool_ancestry(ancestor)

    @staticmethod
    def _open_directory_nofollow(path: Path, *, create: bool = False) -> int:
        """Open every absolute directory component without following symlinks."""

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
                    "Sysmon private spool ancestry is not process controlled"
                )
            permissions = stat.S_IMODE(metadata.st_mode)
            if permissions & 0o022 and not metadata.st_mode & stat.S_ISVTX:
                raise ExactPublicationError(
                    "Sysmon private spool ancestry is externally writable without sticky mode"
                )
            if current == current.parent:
                return
            current = current.parent

    def _validate_spool_directory_unlocked(self) -> None:
        """Revalidate the owner-only private directory and pinned identity."""

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
            raise ExactPublicationError("Sysmon private spool lost its identity")
        retained = os.fstat(descriptor)
        retained_root = os.fstat(root_descriptor)
        reopened = os.stat(directory_name, dir_fd=root_descriptor, follow_symlinks=False)
        effective_user = int(os.geteuid())
        if (
            not stat.S_ISDIR(retained_root.st_mode)
            or (int(retained_root.st_dev), int(retained_root.st_ino)) != root_identity
        ):
            raise ExactPublicationError("Sysmon private spool root identity changed")
        for metadata in (retained, reopened):
            if (
                not stat.S_ISDIR(metadata.st_mode)
                or (int(metadata.st_dev), int(metadata.st_ino)) != identity
                or int(metadata.st_uid) != effective_user
                or stat.S_IMODE(metadata.st_mode) != 0o700
            ):
                raise ExactPublicationError("Sysmon private spool identity or mode changed")

    def _validate_spool_file_unlocked(self) -> None:
        """Revalidate the SQLite main file without following its directory entry."""

        self._validate_spool_directory_unlocked()
        descriptor = self._spool_directory_descriptor
        filename = self._spool_filename
        identity = self._spool_file_identity
        if descriptor is None or filename is None or identity is None:
            raise ExactPublicationError("Sysmon private journal lost its identity")
        metadata = os.stat(filename, dir_fd=descriptor, follow_symlinks=False)
        effective_user = int(os.geteuid())
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_nlink != 1
            or (int(metadata.st_dev), int(metadata.st_ino)) != identity
            or int(metadata.st_uid) != effective_user
            or stat.S_IMODE(metadata.st_mode) != 0o600
        ):
            raise ExactPublicationError("Sysmon private journal identity or mode changed")

    def _get_spool_dir_unlocked(self) -> Path:
        """Return the owner-only local runtime directory for exact journal state."""

        if self._spool_dir is not None:
            if self._spool_initialization_pending:
                self._finish_private_spool_initialization_unlocked()
            self._validate_spool_directory_unlocked()
            return self._spool_dir

        configured = os.environ.get("EFORGE_SPOOL_DIR")
        protected_root = Path(
            os.path.realpath(
                os.fspath(Path(configured).expanduser() if configured else tempfile.gettempdir())
            )
        )
        output_root = Path(os.path.realpath(os.fspath(self._base_dir)))
        if protected_root == output_root or protected_root.is_relative_to(output_root):
            raise ExactPublicationError("Sysmon private spool must be outside public output")
        if configured:
            ancestor = protected_root
            while not ancestor.exists():
                if ancestor == ancestor.parent:
                    raise ExactPublicationError(
                        "Sysmon private spool has no existing trusted ancestor"
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
        self._spool_root_identity = (int(root_metadata.st_dev), int(root_metadata.st_ino))
        for _attempt in range(128):
            directory_name = f"evidenceforge-sysmon-spool-{secrets.token_hex(16)}"
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
            raise ExactPublicationError("Unable to allocate a unique Sysmon private spool")
        self._finish_private_spool_initialization_unlocked()
        self._validate_spool_directory_unlocked()
        return self._spool_dir

    def _adopt_private_spool_create_lost_return_unlocked(self) -> None:
        """Retain an owner-only leaf created before mkdir's return was lost."""

        root_descriptor = self._spool_root_descriptor
        directory_name = self._spool_directory_name
        if root_descriptor is None or directory_name is None:
            raise ExactPublicationError("Sysmon private spool lost its create owner")
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
            raise ExactPublicationError("Sysmon private spool leaf is not owner-only")
        self._spool_directory_identity = (int(metadata.st_dev), int(metadata.st_ino))

    def _finish_private_spool_initialization_unlocked(self) -> None:
        """Retryably pin and durably publish one private spool leaf."""

        root_descriptor = self._spool_root_descriptor
        directory_name = self._spool_directory_name
        if root_descriptor is None or directory_name is None:
            raise ExactPublicationError("Sysmon private spool lost its initialization owner")
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
            raise ExactPublicationError("Sysmon private spool leaf is not owner-only")
        identity = (int(metadata.st_dev), int(metadata.st_ino))
        if self._spool_directory_identity not in {None, identity}:
            raise ExactPublicationError("Sysmon private spool leaf identity changed")
        if self._spool_directory_descriptor is None:
            self._spool_directory_descriptor = os.open(
                directory_name,
                os.O_RDONLY | _DIRECTORY | _NOFOLLOW,
                dir_fd=root_descriptor,
            )
        retained = os.fstat(self._spool_directory_descriptor)
        if (int(retained.st_dev), int(retained.st_ino)) != identity:
            raise ExactPublicationError("Sysmon private spool descriptor changed identity")
        self._spool_directory_identity = identity
        os.fsync(self._spool_directory_descriptor)
        os.fsync(root_descriptor)
        self._spool_initialization_pending = False

    def _get_spool_conn_unlocked(self) -> sqlite3.Connection:
        """Open the exact Sysmon journal while holding `_file_lock`."""

        if self._spool_conn is not None:
            if self._spool_file_initialization_pending:
                self._finish_private_journal_initialization_unlocked()
            return self._spool_conn
        spool_dir = self._get_spool_dir_unlocked()
        directory_descriptor = self._spool_directory_descriptor
        if directory_descriptor is None:
            raise ExactPublicationError("Sysmon private spool lost its directory descriptor")
        if self._spool_filename is None:
            for _attempt in range(128):
                filename = f".sysmon_event_spool_{secrets.token_hex(16)}.sqlite3"
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
                raise ExactPublicationError("Unable to allocate a unique Sysmon journal")
        self._finish_private_journal_initialization_unlocked()
        if self._spool_conn is None:
            raise ExactPublicationError("Sysmon private journal did not open")
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
            raise ExactPublicationError("Sysmon private journal is not an owner file")
        os.fchmod(descriptor, 0o600)
        self._spool_file_identity = (int(metadata.st_dev), int(metadata.st_ino))

    def _adopt_private_journal_create_lost_return_unlocked(self) -> None:
        """Retain a journal created before its exclusive-open return was lost."""

        directory_descriptor = self._spool_directory_descriptor
        filename = self._spool_filename
        if directory_descriptor is None or filename is None:
            raise ExactPublicationError("Sysmon private journal lost its create owner")
        try:
            descriptor = os.open(filename, os.O_RDWR | _NOFOLLOW, dir_fd=directory_descriptor)
        except FileNotFoundError:
            return
        try:
            self._adopt_private_journal_descriptor_unlocked(descriptor)
        finally:
            os.close(descriptor)

    def _finish_private_journal_initialization_unlocked(self) -> None:
        """Retryably initialize and durably publish the retained journal."""

        directory_descriptor = self._spool_directory_descriptor
        filename = self._spool_filename
        path = self._spool_path
        if directory_descriptor is None or filename is None or path is None:
            raise ExactPublicationError("Sysmon private journal lost its initialization owner")
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
                    "Sysmon private journal create ownership is ambiguous"
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
        """Create one bounded journal with memory-only SQLite temporary state."""

        connection.execute("PRAGMA temp_store=MEMORY")
        if connection.execute("PRAGMA temp_store").fetchone() != (2,):
            raise ExactPublicationError("Sysmon journal could not confine SQLite temp storage")
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
            raise ExactPublicationError("Sysmon private journal schema is not immutable")

    def _event_sort_key(self, event: dict[str, Any]) -> str:
        """Return the stable sortable timestamp key for one deferred row."""

        timestamp = event.get("TimeCreated", "")
        if isinstance(timestamp, datetime):
            return ensure_utc(timestamp).isoformat()
        return str(timestamp)

    def _spool_event_dicts_unlocked(self) -> None:
        """Move exact candidate dictionaries to disk and bound emitter memory."""

        if not self._event_dicts:
            return
        connection = self._get_spool_conn_unlocked()
        self._validate_spool_file_unlocked()
        rows: list[tuple[int, str, str, str, int]] = []
        added_bytes = 0
        start_sequence = self._spool_sequence
        for offset, event in enumerate(self._event_dicts):
            payload = _sysmon_spool_encode(event)
            payload_bytes = len(payload.encode("utf-8"))
            if payload_bytes > _FINALIZATION_CHUNK_BYTES:
                raise SourceFinalizationError(
                    "Sysmon candidate row exceeds the finalization chunk byte capacity"
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
        state = connection.execute(
            """SELECT phase, candidate_rows, candidate_bytes
               FROM finalization_state WHERE singleton = ?""",
            (1,),
        ).fetchone()
        if state is None or state[0] != "candidate":
            raise SourceFinalizationError("Sysmon journal rejected a late candidate cohort")
        candidate_rows = int(state[1]) + len(rows)
        candidate_bytes = int(state[2]) + added_bytes
        if candidate_rows > self._finalization_row_capacity:
            raise SourceFinalizationError("Sysmon finalization row capacity is exhausted")
        if candidate_bytes > self._finalization_byte_capacity:
            raise SourceFinalizationError("Sysmon finalization byte capacity is exhausted")
        with self._candidate_admission_lock:
            admitted_rows = self._candidate_admitted_rows
            admitted_bytes = self._candidate_admitted_bytes
            high_water_rows = self._candidate_high_water_rows
            high_water_bytes = self._candidate_high_water_bytes
        if candidate_rows > admitted_rows or candidate_bytes > admitted_bytes:
            raise SourceFinalizationError("Sysmon journal exceeded admitted candidate capacity")
        try:
            connection.executemany(
                """INSERT INTO events
                   (sequence, sort_key, phase, payload, payload_bytes)
                   VALUES (?, ?, ?, ?, ?)""",
                rows,
            )
            connection.execute(
                """UPDATE finalization_state
                   SET candidate_rows = ?, candidate_bytes = ?,
                       high_water_rows = MAX(high_water_rows, ?),
                       high_water_bytes = MAX(high_water_bytes, ?)
                   WHERE singleton = ?""",
                (candidate_rows, candidate_bytes, high_water_rows, high_water_bytes, 1),
            )
            self._commit_journal_unlocked()
        except BaseException:
            retained_rows = connection.execute(
                """SELECT sequence, sort_key, phase, payload, payload_bytes
                   FROM events WHERE sequence >= ? AND sequence < ? ORDER BY sequence""",
                (start_sequence, start_sequence + len(rows)),
            ).fetchall()
            retained_state = connection.execute(
                """SELECT phase, candidate_rows, candidate_bytes
                   FROM finalization_state WHERE singleton = ?""",
                (1,),
            ).fetchone()
            committed = (
                not connection.in_transaction
                and retained_rows == rows
                and retained_state == ("candidate", candidate_rows, candidate_bytes)
            )
            if not committed:
                connection.rollback()
                raise
        self._spool_sequence = start_sequence + len(rows)
        self._spooled_count += len(rows)
        self._event_dicts.clear()

    def _load_candidate_rows_unlocked(
        self,
        *,
        frozen_order: bool = False,
    ) -> list[tuple[int, dict[str, Any]]]:
        """Load the bounded cohort in insertion or frozen chronological order."""

        if self._spool_conn is None:
            return []
        if frozen_order:
            cursor = self._spool_conn.execute(
                """SELECT sequence, payload FROM events
                   WHERE phase = ? ORDER BY sort_key, sequence""",
                ("candidate",),
            )
        else:
            cursor = self._spool_conn.execute(
                """SELECT sequence, payload FROM events
                   WHERE phase = ? ORDER BY sequence""",
                ("candidate",),
            )
        return [(int(sequence), _sysmon_spool_decode(payload)) for sequence, payload in cursor]

    def _persist_candidate_phase_unlocked(
        self,
        candidate_rows: list[tuple[int, dict[str, Any]]],
        *,
        update_sort_key: bool,
        phase_name: str,
    ) -> int:
        """Persist and re-charge one in-transaction candidate transformation."""

        connection = self._spool_conn
        if connection is None or not connection.in_transaction:
            raise SourceFinalizationError(
                "Sysmon candidate transformation lost its sealing transaction"
            )
        payload_updates: list[tuple[Any, ...]] = []
        candidate_bytes = 0
        for sequence, event in candidate_rows:
            payload = _sysmon_spool_encode(event)
            payload_bytes = len(payload.encode("utf-8"))
            if payload_bytes > _FINALIZATION_CHUNK_BYTES:
                raise SourceFinalizationError(
                    f"Sysmon {phase_name} candidate exceeds the chunk byte capacity"
                )
            candidate_bytes += payload_bytes
            if candidate_bytes > self._finalization_byte_capacity:
                raise SourceFinalizationError(
                    f"Sysmon {phase_name} candidate byte capacity is exhausted"
                )
            if update_sort_key:
                payload_updates.append(
                    (
                        self._event_sort_key(event),
                        payload_bytes,
                        payload,
                        sequence,
                        "candidate",
                    )
                )
            else:
                payload_updates.append((payload_bytes, payload, sequence, "candidate"))

        if update_sort_key:
            updated = connection.executemany(
                """UPDATE events SET sort_key = ?, payload_bytes = ?, payload = ?
                   WHERE sequence = ? AND phase = ?""",
                payload_updates,
            )
        else:
            updated = connection.executemany(
                """UPDATE events SET payload_bytes = ?, payload = ?
                   WHERE sequence = ? AND phase = ?""",
                payload_updates,
            )
        if updated.rowcount != len(payload_updates):
            raise SourceFinalizationError(
                f"Sysmon candidate changed during {phase_name} persistence"
            )
        updated_state = connection.execute(
            """UPDATE finalization_state
               SET candidate_bytes = ?, high_water_bytes = MAX(high_water_bytes, ?)
               WHERE singleton = ? AND phase = ? AND candidate_rows = ?""",
            (candidate_bytes, candidate_bytes, 1, "candidate", len(candidate_rows)),
        )
        if updated_state.rowcount != 1:
            raise SourceFinalizationError(
                f"Sysmon source state changed during {phase_name} persistence"
            )
        return candidate_bytes

    def _cleanup_spool_unlocked(self) -> None:
        """Remove the owner-private journal after terminal close or abort."""

        if (
            self._exact_candidate_abort_close_rendering
            and not self._exact_candidate_abort_close_rows_rendered
        ):
            raise ExactPublicationError(
                "Sysmon abort close cannot clear its journal before exact rows render"
            )
        if self._spool_conn is not None:
            self._spool_conn.close()
            self._spool_conn = None
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
                        "Sysmon private journal cleanup found a non-regular entry"
                    )
                if (
                    candidate == filename
                    and (int(metadata.st_dev), int(metadata.st_ino)) != self._spool_file_identity
                ):
                    raise ExactPublicationError(
                        "Sysmon private journal changed before terminal cleanup"
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
                        "Sysmon private spool changed before directory cleanup"
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
        if self._exact_candidate_abort_close_rendering:
            self._exact_candidate_abort_close_render_complete = True

    def configure_output_target(self, target: str | OutputTarget | None) -> None:
        """Reject target mutation after the terminal cohort starts quiescing."""

        with self._close_condition:
            if self._source_finalization_bound and (
                self._source_finalization_state != "open"
                or self._close_state != "open"
                or self._exact_candidate_abort_close_rendering
            ):
                raise SourceFinalizationError(
                    "Sysmon output target cannot change during terminal source ownership"
                )
            super().configure_output_target(target)

    def _get_host_writer(self, host_fqdn: str) -> _SingleHostWriter:
        safe_host = sanitize_path_component(host_fqdn)
        writer_key = "" if self._direct_file_mode else safe_host
        writer = self._host_writers.get(writer_key)
        if writer is not None:
            return writer
        with self._host_writers_lock:
            writer = self._host_writers.get(writer_key)
            if writer is not None:
                return writer
            if safe_host and not self._direct_file_mode:
                path = self._base_dir / safe_host / "windows_event_sysmon.xml"
            elif self._direct_file_path:
                path = self._direct_file_path
            else:
                path = self._base_dir / "windows_event_sysmon.xml"
            writer = _SingleHostWriter(path, self.buffer_size)
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
                path = self._direct_file_path.with_name(WINDOWS_SYSMON_SNARE_FILENAME)
            else:
                path = syslog_family_writer_path(
                    base_dir=self._base_dir,
                    safe_route_key=safe_route_key,
                    log_filename=WINDOWS_SYSMON_SNARE_FILENAME,
                    direct_file_path=None,
                    flat_filename=WINDOWS_SYSMON_SNARE_FILENAME,
                )
            writer = _SingleHostWriter(path, self.buffer_size)
            self._snare_writers[writer_key] = writer
            return writer

    def _buffer_event(self, rendered: str) -> None:
        if not self._direct_file_path:
            return
        self._get_host_writer("").write(rendered)

    def _begin_sysmon_candidate_admission(self) -> None:
        """Serialize ordinary candidate handoff against exact participant ownership."""

        with self._close_condition:
            while self._active_exact_publication_keys:
                self._close_condition.wait()
            self._require_accepting_events_locked()
            if self._exact_candidate_abort_close_rendering:
                raise ExactPublicationError(
                    "Sysmon abort close retry owner rejects new candidate admission"
                )
            self._queue_admissions += 1

    @property
    def supports_exact_candidate_publication(self) -> bool:
        """Return whether this emitter owns the journal required for exact candidates."""

        return self._source_finalization_bound

    @property
    def supports_exact_projection_publication(self) -> bool:
        """Advertise exact projection admission to dispatcher preflight."""

        return self._source_finalization_bound

    @staticmethod
    def _validate_sysmon_render_mapping(
        mapping: object,
        *,
        label: str,
    ) -> dict[object, object] | None:
        """Return one exact allocator mapping after strict shape validation."""

        if mapping is None:
            return None
        if type(mapping) is not dict:
            raise ExactPublicationError(f"Sysmon thread {label} state is malformed")
        return mapping

    def _validate_exact_thread_allocation_receipts_unlocked(
        self,
        participant: _SysmonExactCandidateParticipant,
    ) -> None:
        """Authenticate every exact allocator mutation before commit or rollback."""

        expected_pool_hosts: set[str] = set()
        expected_counter_hosts: set[str] = set()
        expected_last_thread_hosts: set[str] = set()
        for hostname, receipt in participant.thread_allocation_receipts.items():
            if type(hostname) is not str or not hostname:
                raise ExactPublicationError("Sysmon exact thread receipt host is malformed")
            if self._sysmon_thread_host_state_unlocked(hostname) != receipt.expected:
                raise ExactPublicationError(
                    "Sysmon exact thread allocation receipt found conflicting state"
                )
            if receipt.expected.pool_present:
                expected_pool_hosts.add(hostname)
            if receipt.expected.counter_present:
                expected_counter_hosts.add(hostname)
            if receipt.expected.last_thread_present:
                expected_last_thread_hosts.add(hostname)

        mapping_contracts = (
            (
                "pool",
                getattr(self, "_sysmon_thread_pools", None),
                participant.thread_pools_existed,
                expected_pool_hosts,
            ),
            (
                "counter",
                getattr(self, "_sysmon_thread_counters", None),
                participant.thread_counters_existed,
                expected_counter_hosts,
            ),
            (
                "last-thread",
                getattr(self, "_sysmon_last_thread_by_host", None),
                participant.thread_last_threads_existed,
                expected_last_thread_hosts,
            ),
        )
        for label, retained, existed, expected_hosts in mapping_contracts:
            mapping = self._validate_sysmon_render_mapping(retained, label=label)
            if existed:
                if mapping is None:
                    raise ExactPublicationError(f"Sysmon exact thread {label} mapping disappeared")
            elif expected_hosts:
                if mapping is None or set(mapping) != expected_hosts:
                    raise ExactPublicationError(
                        f"Sysmon exact thread {label} mapping gained foreign state"
                    )
            elif mapping is not None:
                raise ExactPublicationError(
                    f"Sysmon exact thread {label} mapping changed unexpectedly"
                )

    def _restore_exact_thread_allocation_receipts_unlocked(
        self,
        participant: _SysmonExactCandidateParticipant,
    ) -> None:
        """Restore authenticated allocator state for a precanonical exact abort."""

        self._validate_exact_thread_allocation_receipts_unlocked(participant)
        pools = self._validate_sysmon_render_mapping(
            getattr(self, "_sysmon_thread_pools", None),
            label="pool",
        )
        counters = self._validate_sysmon_render_mapping(
            getattr(self, "_sysmon_thread_counters", None),
            label="counter",
        )
        last_threads = self._validate_sysmon_render_mapping(
            getattr(self, "_sysmon_last_thread_by_host", None),
            label="last-thread",
        )
        for hostname, receipt in participant.thread_allocation_receipts.items():
            original = receipt.original
            if pools is not None:
                if original.pool_present:
                    pools[hostname] = list(original.pool)
                else:
                    pools.pop(hostname, None)
            if counters is not None:
                if original.counter_present:
                    counters[hostname] = original.counter
                else:
                    counters.pop(hostname, None)
            if last_threads is not None:
                if original.last_thread_present:
                    last_threads[hostname] = original.last_thread
                else:
                    last_threads.pop(hostname, None)

        for attribute, mapping, existed in (
            ("_sysmon_thread_pools", pools, participant.thread_pools_existed),
            ("_sysmon_thread_counters", counters, participant.thread_counters_existed),
            (
                "_sysmon_last_thread_by_host",
                last_threads,
                participant.thread_last_threads_existed,
            ),
        ):
            if not existed and mapping is not None:
                if mapping:
                    raise ExactPublicationError(
                        "Sysmon exact thread rollback retained unexpected allocator state"
                    )
                delattr(self, attribute)
        participant.thread_allocation_receipts.clear()

    def _validate_exact_int_receipts_unlocked(
        self,
        receipts: (
            dict[str, _SysmonIntMutationReceipt] | dict[tuple[str, str], _SysmonIntMutationReceipt]
        ),
        mapping: object,
        *,
        label: str,
    ) -> set[object]:
        """Authenticate lazy integer receipts and return their expected keys."""

        expected_keys: set[object] = set()
        for key, receipt in receipts.items():
            if self._sysmon_int_entry_state_unlocked(mapping, key, label=label) != receipt.expected:
                raise ExactPublicationError(f"Sysmon exact {label} receipt found conflicting state")
            if receipt.expected.present:
                expected_keys.add(key)
        return expected_keys

    def _validate_exact_optional_mapping_unlocked(
        self,
        mapping: object,
        *,
        existed: bool,
        expected_keys: set[object],
        label: str,
    ) -> dict[object, object] | None:
        """Authenticate a lazily created renderer mapping without a full snapshot."""

        retained = self._validate_sysmon_render_mapping(mapping, label=label)
        if existed:
            if retained is None:
                raise ExactPublicationError(f"Sysmon exact {label} mapping disappeared")
        elif expected_keys:
            if retained is None or set(retained) != expected_keys:
                raise ExactPublicationError(f"Sysmon exact {label} mapping gained foreign state")
        elif retained:
            raise ExactPublicationError(f"Sysmon exact {label} mapping changed unexpectedly")
        return retained

    def _validate_exact_render_state_receipts_unlocked(
        self,
        participant: _SysmonExactCandidateParticipant,
    ) -> None:
        """Authenticate every mutable canonical-render receipt as one transaction."""

        self._validate_exact_thread_allocation_receipts_unlocked(participant)

        sessions = self._validate_sysmon_render_mapping(
            getattr(self, "_terminal_session_ids_by_logon", None),
            label="terminal-session",
        )
        if sessions is None:
            raise ExactPublicationError("Sysmon exact terminal-session mapping disappeared")
        self._validate_exact_int_receipts_unlocked(
            participant.terminal_session_receipts,
            sessions,
            label="terminal-session",
        )

        call_trace_cache = self._validate_sysmon_render_mapping(
            getattr(self, "_call_trace_cache", None),
            label="call-trace cache",
        )
        if call_trace_cache is None:
            raise ExactPublicationError("Sysmon exact call-trace cache disappeared")
        expected_call_trace_counters: set[object] = set()
        for hostname, receipt in participant.call_trace_receipts.items():
            if self._sysmon_call_trace_host_state_unlocked(hostname) != receipt.expected:
                raise ExactPublicationError(
                    "Sysmon exact call-trace receipt found conflicting state"
                )
            if receipt.expected.counter_present:
                expected_call_trace_counters.add(hostname)
        self._validate_exact_optional_mapping_unlocked(
            getattr(self, "_call_trace_counters", None),
            existed=participant.call_trace_counters_existed,
            expected_keys=expected_call_trace_counters,
            label="call-trace counter",
        )

        for attribute, existed, receipts, label in (
            (
                "_sysmon_pids",
                participant.sysmon_pids_existed,
                participant.sysmon_pid_receipts,
                "service PID",
            ),
            (
                "_dns_client_pids",
                participant.dns_client_pids_existed,
                participant.dns_client_pid_receipts,
                "DNS client PID",
            ),
        ):
            mapping = getattr(self, attribute, None)
            expected_keys = self._validate_exact_int_receipts_unlocked(
                receipts,
                mapping,
                label=label,
            )
            self._validate_exact_optional_mapping_unlocked(
                mapping,
                existed=existed,
                expected_keys=expected_keys,
                label=label,
            )

        filters = self.__dict__.get("_filters")
        if participant.filters_existed:
            if self._validate_sysmon_render_mapping(filters, label="filter cache") is None:
                raise ExactPublicationError("Sysmon exact filter cache disappeared")
            if participant.created_filters is not None:
                raise ExactPublicationError("Sysmon exact filter receipt is malformed")
        elif participant.created_filters is None:
            if "_filters" in self.__dict__:
                raise ExactPublicationError("Sysmon exact filter cache changed unexpectedly")
        elif filters is not participant.created_filters:
            raise ExactPublicationError("Sysmon exact filter cache changed unexpectedly")

    @staticmethod
    def _restore_exact_int_receipts_unlocked(
        mapping: dict[object, object] | None,
        receipts: (
            dict[str, _SysmonIntMutationReceipt] | dict[tuple[str, str], _SysmonIntMutationReceipt]
        ),
    ) -> None:
        """Restore already-authenticated integer mapping entries."""

        if mapping is None:
            if receipts:
                raise ExactPublicationError("Sysmon exact integer receipt lost its mapping")
            return
        for key, receipt in receipts.items():
            if receipt.original.present:
                mapping[key] = receipt.original.value
            else:
                mapping.pop(key, None)

    def _restore_exact_render_state_receipts_unlocked(
        self,
        participant: _SysmonExactCandidateParticipant,
    ) -> None:
        """Restore all authenticated mutable renderer state after exact abort."""

        self._validate_exact_render_state_receipts_unlocked(participant)
        self._restore_exact_thread_allocation_receipts_unlocked(participant)

        sessions = self._validate_sysmon_render_mapping(
            getattr(self, "_terminal_session_ids_by_logon", None),
            label="terminal-session",
        )
        self._restore_exact_int_receipts_unlocked(
            sessions,
            participant.terminal_session_receipts,
        )

        call_trace_cache = self._validate_sysmon_render_mapping(
            getattr(self, "_call_trace_cache", None),
            label="call-trace cache",
        )
        call_trace_counters = self._validate_sysmon_render_mapping(
            getattr(self, "_call_trace_counters", None),
            label="call-trace counter",
        )
        if call_trace_cache is None:
            raise ExactPublicationError("Sysmon exact call-trace cache disappeared")
        for hostname, receipt in participant.call_trace_receipts.items():
            original = receipt.original
            if not original.cache_present:
                call_trace_cache.pop(hostname, None)
            if call_trace_counters is not None:
                if original.counter_present:
                    call_trace_counters[hostname] = original.counter
                else:
                    call_trace_counters.pop(hostname, None)

        for attribute, mapping, existed, receipts in (
            (
                "_sysmon_pids",
                self._validate_sysmon_render_mapping(
                    getattr(self, "_sysmon_pids", None),
                    label="service PID",
                ),
                participant.sysmon_pids_existed,
                participant.sysmon_pid_receipts,
            ),
            (
                "_dns_client_pids",
                self._validate_sysmon_render_mapping(
                    getattr(self, "_dns_client_pids", None),
                    label="DNS client PID",
                ),
                participant.dns_client_pids_existed,
                participant.dns_client_pid_receipts,
            ),
        ):
            self._restore_exact_int_receipts_unlocked(mapping, receipts)
            if not existed and mapping is not None:
                if mapping:
                    raise ExactPublicationError(
                        "Sysmon exact renderer rollback retained unexpected cache state"
                    )
                delattr(self, attribute)

        if not participant.call_trace_counters_existed and call_trace_counters is not None:
            if call_trace_counters:
                raise ExactPublicationError(
                    "Sysmon exact call-trace rollback retained unexpected counter state"
                )
            delattr(self, "_call_trace_counters")
        if not participant.filters_existed and participant.created_filters is not None:
            delattr(self, "_filters")

        participant.terminal_session_receipts.clear()
        participant.call_trace_receipts.clear()
        participant.sysmon_pid_receipts.clear()
        participant.dns_client_pid_receipts.clear()
        participant.created_filters = None

    def _finalize_exact_render_state_receipts_unlocked(
        self,
        participant: _SysmonExactCandidateParticipant,
    ) -> None:
        """Authenticate and retain every renderer mutation owned by a committed batch."""

        if participant.render_state_finalized:
            return
        self._validate_exact_render_state_receipts_unlocked(participant)
        self._retire_exact_render_state_receipts_unlocked(participant)
        participant.render_state_finalized = True

    @staticmethod
    def _retire_exact_render_state_receipts_unlocked(
        participant: _SysmonExactCandidateParticipant,
    ) -> None:
        """Drop authenticated rollback receipts after their mutations are adopted."""

        participant.thread_allocation_receipts.clear()
        participant.terminal_session_receipts.clear()
        participant.call_trace_receipts.clear()
        participant.sysmon_pid_receipts.clear()
        participant.dns_client_pid_receipts.clear()
        participant.created_filters = None

    def _mark_exact_participant_completed_unlocked(
        self,
        participant: _SysmonExactCandidateParticipant,
    ) -> None:
        """Apply the idempotent scalar completion transition under the owner condition."""

        if participant.completed:
            return
        participant.completed = True
        self._exact_candidate_completed_participants += 1

    def _register_exact_publication_batch(
        self,
        key: ExactPublicationParticipantKey,
    ) -> None:
        """Fence new candidates, then drain every prior threaded FIFO admission."""

        self._validate_exact_candidate_participant_key(key)
        worker_thread = self._thread.ident if self._thread is not None else None
        if worker_thread == get_ident():
            raise ExactPublicationError(
                "Sysmon exact publication cannot register from its emitter worker"
            )
        if not self._source_finalization_bound:
            raise ExactPublicationError(
                "Sysmon exact candidate publication requires source finalization"
            )
        with self._exact_publication_condition:
            if self._exact_candidate_abort_close_rendering:
                raise ExactPublicationError(
                    "Sysmon abort close retry owner rejects exact candidate admission"
                )
            retained_participant = self._exact_candidate_participants.get(key)
            if retained_participant is not None:
                if key not in self._active_exact_publication_keys:
                    raise ExactPublicationError(
                        "Sysmon exact participant receipt is already terminal"
                    )
                return
            foreign = self._active_exact_publication_keys - {key}
            if foreign:
                raise ExactPublicationError(
                    "Sysmon emitter already has an unresolved exact publication"
                )
            if self._close_state != "open" and key not in self._active_exact_publication_keys:
                raise ExactPublicationError(
                    "Sysmon emitter is closing or closed during exact publication"
                )
            while self._queue_admissions:
                self._exact_publication_condition.wait()
            self._active_exact_publication_keys.add(key)

        queue = self._event_queue
        try:
            if queue is not None:
                queue.join()
                self._raise_if_thread_failed()
            with self._file_lock:
                self._spool_event_dicts_unlocked()
            with self._exact_publication_condition:
                if key not in self._active_exact_publication_keys:
                    raise ExactPublicationError("Sysmon exact participant lost its admission fence")
                if key in self._exact_candidate_participants:
                    raise ExactPublicationError(
                        "Sysmon exact participant was registered concurrently"
                    )
                with self._sysmon_render_state_lock:
                    pools = self._validate_sysmon_render_mapping(
                        getattr(self, "_sysmon_thread_pools", None),
                        label="pool",
                    )
                    counters = self._validate_sysmon_render_mapping(
                        getattr(self, "_sysmon_thread_counters", None),
                        label="counter",
                    )
                    last_threads = self._validate_sysmon_render_mapping(
                        getattr(self, "_sysmon_last_thread_by_host", None),
                        label="last-thread",
                    )
                    call_trace_counters = self._validate_sysmon_render_mapping(
                        getattr(self, "_call_trace_counters", None),
                        label="call-trace counter",
                    )
                    sysmon_pids = self._validate_sysmon_render_mapping(
                        getattr(self, "_sysmon_pids", None),
                        label="service PID",
                    )
                    dns_client_pids = self._validate_sysmon_render_mapping(
                        getattr(self, "_dns_client_pids", None),
                        label="DNS client PID",
                    )
                    if (
                        self._validate_sysmon_render_mapping(
                            getattr(self, "_terminal_session_ids_by_logon", None),
                            label="terminal-session",
                        )
                        is None
                    ):
                        raise ExactPublicationError("Sysmon terminal-session mapping disappeared")
                    if (
                        self._validate_sysmon_render_mapping(
                            getattr(self, "_call_trace_cache", None),
                            label="call-trace cache",
                        )
                        is None
                    ):
                        raise ExactPublicationError("Sysmon call-trace cache disappeared")
                    filters_existed = "_filters" in self.__dict__
                    if (
                        filters_existed
                        and self._validate_sysmon_render_mapping(
                            self.__dict__["_filters"],
                            label="filter cache",
                        )
                        is None
                    ):
                        raise ExactPublicationError("Sysmon filter cache disappeared")
                    participant = _SysmonExactCandidateParticipant(
                        next_sequence=self._spool_sequence,
                        thread_pools_existed=pools is not None,
                        thread_counters_existed=counters is not None,
                        thread_last_threads_existed=last_threads is not None,
                        call_trace_counters_existed=call_trace_counters is not None,
                        sysmon_pids_existed=sysmon_pids is not None,
                        dns_client_pids_existed=dns_client_pids is not None,
                        filters_existed=filters_existed,
                    )
                self._exact_candidate_participants[key] = participant
                self._exact_candidate_current_participants += 1
                self._exact_candidate_high_water_participants = max(
                    self._exact_candidate_high_water_participants,
                    self._exact_candidate_current_participants,
                )
        except BaseException:
            with self._exact_publication_condition:
                participant = self._exact_candidate_participants.pop(key, None)
                if participant is not None:
                    self._exact_candidate_current_participants -= 1
                self._active_exact_publication_keys.discard(key)
                self._exact_publication_condition.notify_all()
            raise

    def emit_event(self, event_data: dict[str, Any]) -> None:
        event_data = dict(event_data)
        for field in ("ExecutionProcessID", "ExecutionThreadID"):
            value = event_data.get(field)
            event_data[field] = normalize_windows_id_value(value)
        if "EventID" in event_data:
            event_data["EventID"] = normalize_windows_event_id_value(event_data["EventID"])
        canonical_event = getattr(self._emission_context, "canonical_event", None)
        if canonical_event is not None:
            event_id = coerce_windows_event_id(event_data.get("EventID"))
            phase = self._timing_phase(canonical_event, event_id)
            native_time, envelope_time = self._render_times(canonical_event, phase)
            self._apply_finalized_times(event_data, native_time, envelope_time)
        native_time = event_data.get("TimeCreated")
        if (
            isinstance(native_time, datetime)
            and "UtcTime" in event_data
            and not self._timing_is_finalized(event_data)
        ):
            computer = str(event_data.get("Computer") or "")
            hostname = computer.split(".", 1)[0] if computer else ""
            event_id = coerce_windows_event_id(event_data.get("EventID"))
            identity_parts = (
                event_data.get("ProcessGuid"),
                event_data.get("ProcessId"),
                event_data.get("SourceIp"),
                event_data.get("SourcePort"),
                native_time,
            )
            envelope_time = compatibility_sysmon_envelope_time(
                native_time,
                hostname=hostname,
                event_id=event_id,
                identity_parts=identity_parts,
            )
            event_data["_SysmonNativeTime"] = native_time
            event_data["_SysmonInitialEnvelopeTime"] = envelope_time
            event_data["TimeCreated"] = envelope_time
        host_type = getattr(self._emission_context, "host_type", "")
        if host_type:
            event_data["_host_type"] = host_type
        if exact_publication_attempt_active():
            payload = _sysmon_spool_encode(event_data)
            staged = stage_exact_publication_row(
                self,
                payload,
                publish=self._commit_exact_candidate_row,
                release=self._release_exact_candidate_row,
            )
            if not staged:
                raise ExactPublicationError(
                    "Sysmon exact candidate lost its active publication attempt"
                )
            return
        self._begin_sysmon_candidate_admission()
        handed_off = False
        reserved_bytes = 0
        try:
            with self._candidate_admission_lock:
                event_data, reserved_bytes = self._reserve_candidate_admission_unlocked(event_data)
            if self.threaded:
                if self._event_queue is None:
                    raise RuntimeError("Threaded Sysmon emitter lost its FIFO")
                warned = False
                while True:
                    self._raise_if_thread_failed()
                    try:
                        self._event_queue.put(event_data, timeout=0.1)
                    except Full:
                        if not warned:
                            logger.warning(
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
                            if self._source_finalization_bound:
                                self._spool_event_dicts_unlocked()
                            else:
                                self._flush_unlocked()
                        except BaseException:
                            if self._source_finalization_bound:
                                retained = self._event_dicts.pop()
                                handed_off = False
                                if retained is not event_data:
                                    raise SourceFinalizationError(
                                        "Sysmon candidate rollback lost its current row"
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
        """Charge and detach one exact candidate before memory or FIFO retention."""

        if not self._source_finalization_bound:
            return event_data, 0
        payload = _sysmon_spool_encode(event_data)
        payload_bytes = len(payload.encode("utf-8"))
        self._reserve_candidate_payload_unlocked(payload_bytes)
        return _sysmon_spool_decode(payload), payload_bytes

    def _reserve_candidate_payload_unlocked(self, payload_bytes: int) -> None:
        """Charge one already-frozen candidate payload against terminal capacity."""

        if type(payload_bytes) is not int or payload_bytes < 0:
            raise SourceFinalizationError("Sysmon candidate byte reservation is malformed")
        if not self._source_finalization_bound:
            if payload_bytes != 0:
                raise SourceFinalizationError(
                    "Legacy Sysmon candidate cannot retain finalization capacity"
                )
            return
        if payload_bytes > _FINALIZATION_CHUNK_BYTES:
            raise SourceFinalizationError(
                "Sysmon candidate row exceeds the finalization chunk byte capacity"
            )
        candidate_rows = self._candidate_admitted_rows + 1
        candidate_bytes = self._candidate_admitted_bytes + payload_bytes
        if candidate_rows > self._finalization_row_capacity:
            raise SourceFinalizationError("Sysmon finalization row capacity is exhausted")
        if candidate_bytes > self._finalization_byte_capacity:
            raise SourceFinalizationError("Sysmon finalization byte capacity is exhausted")
        self._candidate_admitted_rows = candidate_rows
        self._candidate_admitted_bytes = candidate_bytes
        self._candidate_high_water_rows = max(self._candidate_high_water_rows, candidate_rows)
        self._candidate_high_water_bytes = max(self._candidate_high_water_bytes, candidate_bytes)
        self._source_high_water_rows = max(self._source_high_water_rows, candidate_rows)
        self._source_high_water_bytes = max(self._source_high_water_bytes, candidate_bytes)

    @staticmethod
    def _validate_exact_candidate_participant_key(
        key: ExactPublicationParticipantKey,
    ) -> None:
        """Reject hostile or malformed exact participant keys before owner lookup."""

        if (
            type(key) is not tuple
            or len(key) != 2
            or type(key[0]) is not str
            or len(key[0]) != 32
            or any(character not in "0123456789abcdef" for character in key[0])
            or type(key[1]) is not int
            or key[1] <= 0
            or key[1] > (2**63 - 1)
        ):
            raise ExactPublicationError("Sysmon exact participant key is malformed")

    @classmethod
    def _validate_exact_candidate_key(cls, key: ExactPublicationKey) -> None:
        """Reject hostile or malformed exact candidate keys before owner lookup."""

        if type(key) is not tuple or len(key) != 3:
            raise ExactPublicationError("Sysmon exact candidate key is malformed")
        cls._validate_exact_candidate_participant_key(key[:2])
        if type(key[2]) is not int or key[2] < 0 or key[2] > (2**63 - 1):
            raise ExactPublicationError("Sysmon exact candidate key is malformed")

    def _reserve_exact_publication_row(
        self,
        key: ExactPublicationKey,
        digest: str,
        retained_bytes: int,
    ) -> None:
        """Reserve one exact raw candidate before canonical State may mutate."""

        self._validate_exact_candidate_key(key)
        if (
            type(digest) is not str
            or len(digest) != 64
            or any(character not in "0123456789abcdef" for character in digest)
            or type(retained_bytes) is not int
            or retained_bytes <= 0
        ):
            raise ExactPublicationError("Sysmon exact candidate reservation is malformed")
        participant_key = key[:2]
        with self._exact_publication_condition:
            if participant_key not in self._active_exact_publication_keys:
                raise ExactPublicationError(
                    "Sysmon exact candidate reservation lost its participant fence"
                )
            retained = self._exact_candidate_reservations.get(key)
            if retained is not None:
                if retained.digest != digest or retained.retained_bytes != retained_bytes:
                    raise ExactPublicationError(
                        "Sysmon exact candidate reservation changed on retry"
                    )
                return
            if not self._source_finalization_bound:
                raise ExactPublicationError(
                    "Sysmon exact candidate reservation requires source finalization"
                )
            participant = self._exact_candidate_participants.get(participant_key)
            if participant is None or participant.completed:
                raise ExactPublicationError(
                    "Sysmon exact candidate reservation lost its participant owner"
                )
            sequence = participant.next_sequence
            if sequence < self._spool_sequence or sequence > (2**63 - 1):
                raise ExactPublicationError(
                    "Sysmon exact candidate sequence exceeds its journal ownership"
                )
            charged_bytes = retained_bytes
            with self._candidate_admission_lock:
                self._reserve_candidate_payload_unlocked(charged_bytes)
            prior_participant = (
                participant.next_sequence,
                participant.reserved_rows,
                participant.reserved_bytes,
            )
            prior_global = (
                self._exact_candidate_current_rows,
                self._exact_candidate_current_bytes,
                self._exact_candidate_high_water_rows,
                self._exact_candidate_high_water_bytes,
            )
            try:
                self._exact_candidate_reservations[key] = _SysmonExactCandidateReservation(
                    digest=digest,
                    retained_bytes=retained_bytes,
                    charged_bytes=charged_bytes,
                    sequence=sequence,
                    capacity_charged=True,
                )
                participant.reservation_keys.append(key)
                participant.next_sequence = sequence + 1
                participant.reserved_rows += 1
                participant.reserved_bytes += retained_bytes
                self._exact_candidate_current_rows += 1
                self._exact_candidate_current_bytes += retained_bytes
                self._exact_candidate_high_water_rows = max(
                    self._exact_candidate_high_water_rows,
                    self._exact_candidate_current_rows,
                )
                self._exact_candidate_high_water_bytes = max(
                    self._exact_candidate_high_water_bytes,
                    self._exact_candidate_current_bytes,
                )
            except BaseException:
                self._exact_candidate_reservations.pop(key, None)
                if participant.reservation_keys and participant.reservation_keys[-1] == key:
                    participant.reservation_keys.pop()
                (
                    participant.next_sequence,
                    participant.reserved_rows,
                    participant.reserved_bytes,
                ) = prior_participant
                (
                    self._exact_candidate_current_rows,
                    self._exact_candidate_current_bytes,
                    self._exact_candidate_high_water_rows,
                    self._exact_candidate_high_water_bytes,
                ) = prior_global
                with self._candidate_admission_lock:
                    self._release_candidate_admission_unlocked(charged_bytes)
                raise

    def _commit_exact_candidate_row(
        self,
        key: ExactPublicationKey,
        digest: str,
        frozen: object,
    ) -> None:
        """Insert or reconcile one durable candidate before its batch cursor advances."""

        self._validate_exact_candidate_key(key)
        if type(frozen) is not str:
            raise ExactPublicationError("Sysmon exact candidate must retain one inert string")
        if type(digest) is not str or len(digest) != 64:
            raise ExactPublicationError("Sysmon exact candidate digest is malformed")
        encoded = frozen.encode("utf-8")
        retained_bytes = len(encoded)
        if hashlib.sha256(encoded).hexdigest() != digest:
            raise ExactPublicationError("Sysmon exact candidate content digest changed")
        event_data = _sysmon_spool_decode(frozen)
        sort_key = self._event_sort_key(event_data)
        participant_key = key[:2]
        route_key = f"{key[0]}:{key[1]}:{key[2]}"
        if len(route_key) > 96:
            raise ExactPublicationError("Sysmon exact candidate route key is oversized")
        with self._exact_publication_condition:
            if participant_key not in self._active_exact_publication_keys:
                raise ExactPublicationError("Sysmon exact candidate lost its emitter fence")
            participant = self._exact_candidate_participants.get(participant_key)
            reservation = self._exact_candidate_reservations.get(key)
            if (
                participant is None
                or participant.completed
                or reservation is None
                or reservation.digest != digest
                or reservation.retained_bytes != retained_bytes
                or not reservation.capacity_charged
                or reservation.released
            ):
                raise ExactPublicationError(
                    "Sysmon exact candidate has no authentic prepared reservation"
                )
            with self._sysmon_render_state_lock:
                self._validate_exact_render_state_receipts_unlocked(participant)
                participant.render_state_authenticated = True
            with self._candidate_admission_lock:
                high_water_rows = self._candidate_high_water_rows
                high_water_bytes = self._candidate_high_water_bytes
            with self._file_lock:
                connection = self._spool_conn
                if connection is None:
                    connection = self._get_spool_conn_unlocked()
                self._validate_spool_file_unlocked()
                expected_row = (
                    reservation.sequence,
                    sort_key,
                    "candidate",
                    frozen,
                    reservation.retained_bytes,
                    None,
                    _EXACT_CANDIDATE_MARKER,
                    route_key,
                    digest,
                )
                retained = connection.execute(
                    """SELECT sequence, sort_key, phase, payload, payload_bytes, ordinal,
                              route_kind, route_key, payload_digest
                       FROM events WHERE sequence = ?""",
                    (reservation.sequence,),
                ).fetchone()
                if retained == expected_row:
                    if not reservation.admitted:
                        participant.admitted_rows += 1
                        reservation.admitted = True
                    return
                if retained is not None:
                    raise ExactPublicationError("Sysmon exact candidate sequence is already owned")
                if reservation.sequence != self._spool_sequence:
                    raise ExactPublicationError(
                        "Sysmon exact candidate sequence is not the current journal tail"
                    )
                state = connection.execute(
                    "SELECT phase, candidate_rows, candidate_bytes "
                    "FROM finalization_state WHERE singleton = ?",
                    (1,),
                ).fetchone()
                if state is None or state[0] != "candidate":
                    raise SourceFinalizationError(
                        "Sysmon journal rejected an exact candidate commit"
                    )
                candidate_rows = int(state[1]) + 1
                candidate_bytes = int(state[2]) + reservation.retained_bytes
                try:
                    connection.execute(
                        """INSERT INTO events
                        (sequence, sort_key, phase, payload, payload_bytes, ordinal,
                         route_kind, route_key, payload_digest)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                        expected_row,
                    )
                    connection.execute(
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
                    self._commit_journal_unlocked()
                except BaseException:
                    reconciled_row = connection.execute(
                        """SELECT sequence, sort_key, phase, payload, payload_bytes, ordinal,
                                  route_kind, route_key, payload_digest
                           FROM events WHERE sequence = ?""",
                        (reservation.sequence,),
                    ).fetchone()
                    reconciled_state = connection.execute(
                        "SELECT phase, candidate_rows, candidate_bytes "
                        "FROM finalization_state WHERE singleton = ?",
                        (1,),
                    ).fetchone()
                    committed = bool(
                        not connection.in_transaction
                        and reconciled_row == expected_row
                        and reconciled_state == ("candidate", candidate_rows, candidate_bytes)
                    )
                    if not committed:
                        connection.rollback()
                        raise
                self._spool_sequence = reservation.sequence + 1
                self._spooled_count += 1
                if not reservation.admitted:
                    participant.admitted_rows += 1
                    reservation.admitted = True

    def _release_exact_candidate_row(self, key: ExactPublicationKey) -> None:
        """Mark one durable candidate released without discarding its retry receipt."""

        self._validate_exact_candidate_key(key)
        participant_key = key[:2]
        with self._exact_publication_condition:
            participant = self._exact_candidate_participants.get(participant_key)
            reservation = self._exact_candidate_reservations.get(key)
            if participant is None or reservation is None:
                raise ExactPublicationError(
                    "Sysmon exact candidate release lost its retained reservation"
                )
            if reservation.released:
                return
            if not reservation.admitted:
                raise ExactPublicationError(
                    "Sysmon exact candidate release lost its committed reservation"
                )
            with self._file_lock:
                connection = self._spool_conn
                if connection is None:
                    raise ExactPublicationError(
                        "Sysmon exact candidate release lost its private journal"
                    )
                route_key = f"{key[0]}:{key[1]}:{key[2]}"
                retained = connection.execute(
                    """SELECT phase, payload, payload_bytes, route_kind, route_key,
                              payload_digest
                       FROM events WHERE sequence = ?""",
                    (reservation.sequence,),
                ).fetchone()
                state = connection.execute(
                    "SELECT phase, candidate_rows, candidate_bytes "
                    "FROM finalization_state WHERE singleton = ?",
                    (1,),
                ).fetchone()
                with self._candidate_admission_lock:
                    expected_state = (
                        "candidate",
                        self._candidate_admitted_rows,
                        self._candidate_admitted_bytes,
                    )
                if retained is None or len(retained) != 6 or type(retained[1]) is not str:
                    raise ExactPublicationError(
                        "Sysmon exact candidate release found malformed journal state"
                    )
                payload = retained[1]
                encoded = payload.encode("utf-8")
                expected_metadata = (
                    "candidate",
                    reservation.retained_bytes,
                    _EXACT_CANDIDATE_MARKER,
                    route_key,
                    reservation.digest,
                )
                retained_metadata = (
                    retained[0],
                    retained[2],
                    retained[3],
                    retained[4],
                    retained[5],
                )
                if (
                    retained_metadata != expected_metadata
                    or len(encoded) != reservation.retained_bytes
                    or hashlib.sha256(encoded).hexdigest() != reservation.digest
                    or state != expected_state
                ):
                    raise ExactPublicationError(
                        "Sysmon exact candidate release found conflicting journal state"
                    )
            if not participant.render_state_finalized:
                if not participant.render_state_authenticated:
                    raise ExactPublicationError(
                        "Sysmon exact candidate release lost renderer authentication"
                    )
                with self._sysmon_render_state_lock:
                    self._finalize_exact_render_state_receipts_unlocked(participant)
            self._mark_exact_participant_completed_unlocked(participant)
            released_rows = participant.released_rows + 1
            released_bytes = participant.released_bytes + reservation.retained_bytes
            if (
                released_rows > participant.reserved_rows
                or released_bytes > participant.reserved_bytes
            ):
                raise ExactPublicationError("Sysmon exact candidate release accounting overflowed")
            reservation.released = True
            participant.released_rows = released_rows
            participant.released_bytes = released_bytes
            self._exact_candidate_released_rows += 1
            self._exact_candidate_released_bytes += reservation.retained_bytes
            if (
                participant.completed
                and participant.released_rows == participant.reserved_rows
                and participant.released_bytes == participant.reserved_bytes
            ):
                self._active_exact_publication_keys.discard(participant_key)
                self._exact_publication_condition.notify_all()

    def _complete_exact_publication_batch(
        self,
        key: ExactPublicationParticipantKey,
    ) -> None:
        """Keep terminal source operations fenced until exact receipts release."""

        with self._exact_publication_condition:
            participant = self._exact_candidate_participants.get(key)
            if participant is None:
                raise ExactPublicationError("Sysmon exact completion lost its participant owner")
            if participant.completed:
                return
            if participant.reserved_rows == 0:
                with self._sysmon_render_state_lock:
                    self._retire_exact_render_state_receipts_unlocked(participant)
                    participant.render_state_finalized = True
                self._mark_exact_participant_completed_unlocked(participant)
                self._exact_candidate_participants.pop(key)
                self._exact_candidate_current_participants -= 1
                self._exact_candidate_completed_participants -= 1
                self._active_exact_publication_keys.discard(key)
                self._exact_publication_condition.notify_all()
                return
            self._mark_exact_participant_completed_unlocked(participant)
            if (
                participant.released_rows == participant.reserved_rows
                and participant.released_bytes == participant.reserved_bytes
            ):
                self._active_exact_publication_keys.discard(key)
                self._exact_publication_condition.notify_all()

    def prune_checkpoint_terminal_receipts(self) -> None:
        """Discard fully released exact receipts at a quiescent checkpoint barrier."""

        with self._exact_publication_condition:
            if self._active_exact_publication_keys or self._queue_admissions:
                raise ExactPublicationError(
                    "Sysmon checkpoint cannot prune active exact publication receipts"
                )
            reserved_rows = 0
            reserved_bytes = 0
            released_rows = 0
            released_bytes = 0
            completed = 0
            for participant_key, participant in self._exact_candidate_participants.items():
                if (
                    not participant.completed
                    or not participant.render_state_finalized
                    or participant.admitted_rows != participant.reserved_rows
                    or participant.released_rows != participant.reserved_rows
                    or participant.released_bytes != participant.reserved_bytes
                ):
                    raise ExactPublicationError(
                        "Sysmon checkpoint found an unterminated exact publication receipt"
                    )
                for candidate_key in participant.reservation_keys:
                    reservation = self._exact_candidate_reservations.get(candidate_key)
                    if (
                        candidate_key[:2] != participant_key
                        or reservation is None
                        or not reservation.capacity_charged
                        or not reservation.admitted
                        or not reservation.released
                    ):
                        raise ExactPublicationError(
                            "Sysmon checkpoint found an inconsistent exact publication receipt"
                        )
                reserved_rows += participant.reserved_rows
                reserved_bytes += participant.reserved_bytes
                released_rows += participant.released_rows
                released_bytes += participant.released_bytes
                completed += 1
            if (
                reserved_rows != self._exact_candidate_current_rows
                or reserved_bytes != self._exact_candidate_current_bytes
                or released_rows != self._exact_candidate_released_rows
                or released_bytes != self._exact_candidate_released_bytes
                or completed != self._exact_candidate_current_participants
                or completed != self._exact_candidate_completed_participants
                or len(self._exact_candidate_reservations) != reserved_rows
            ):
                raise ExactPublicationError(
                    "Sysmon checkpoint exact publication census is inconsistent"
                )
            with self._file_lock:
                if self._spool_conn is not None:
                    self._validate_exact_candidate_receipts_before_seal_unlocked()
            self._checkpoint_pruned_exact_sequence = self._spool_sequence
            self._exact_candidate_reservations.clear()
            self._exact_candidate_participants.clear()
            self._exact_candidate_current_rows = 0
            self._exact_candidate_current_bytes = 0
            self._exact_candidate_current_participants = 0
            self._exact_candidate_released_rows = 0
            self._exact_candidate_released_bytes = 0
            self._exact_candidate_completed_participants = 0

    def _abort_exact_publication_batch(
        self,
        key: ExactPublicationParticipantKey,
    ) -> None:
        """Release every uncommitted exact reservation after precanonical cancel."""

        with self._exact_publication_condition:
            participant = self._exact_candidate_participants.get(key)
            if participant is None:
                self._active_exact_publication_keys.discard(key)
                self._exact_publication_condition.notify_all()
                return
            if participant.admitted_rows:
                raise ExactPublicationError("Sysmon cannot abort an admitted exact candidate batch")
            for candidate_key in participant.reservation_keys:
                reservation = self._exact_candidate_reservations.get(candidate_key)
                if (
                    reservation is None
                    or reservation.admitted
                    or reservation.released
                    or not reservation.capacity_charged
                ):
                    raise ExactPublicationError(
                        "Sysmon exact candidate abort found conflicting ownership"
                    )
            with self._sysmon_render_state_lock:
                self._validate_exact_render_state_receipts_unlocked(participant)
            with self._candidate_admission_lock:
                self._release_candidate_admissions_unlocked(
                    participant.reserved_rows,
                    participant.reserved_bytes,
                )
            with self._sysmon_render_state_lock:
                self._restore_exact_render_state_receipts_unlocked(participant)
            for candidate_key in participant.reservation_keys:
                self._exact_candidate_reservations.pop(candidate_key)
            self._exact_candidate_current_rows -= participant.reserved_rows
            self._exact_candidate_current_bytes -= participant.reserved_bytes
            self._exact_candidate_current_participants -= 1
            self._exact_candidate_participants.pop(key)
            self._active_exact_publication_keys.discard(key)
            self._exact_publication_condition.notify_all()

    def _release_candidate_admission_unlocked(self, payload_bytes: int) -> None:
        """Undo a candidate reservation that never reached memory or the FIFO."""

        if payload_bytes == 0:
            return
        self._release_candidate_admissions_unlocked(1, payload_bytes)

    def _release_candidate_admissions_unlocked(self, rows: int, payload_bytes: int) -> None:
        """Undo bounded candidates that never reached durable journal admission."""

        if type(rows) is not int or rows < 0 or type(payload_bytes) is not int or payload_bytes < 0:
            raise SourceFinalizationError("Sysmon candidate release accounting is malformed")
        if rows == 0 and payload_bytes == 0:
            return
        if (
            rows <= 0
            or self._candidate_admitted_rows < rows
            or self._candidate_admitted_bytes < payload_bytes
        ):
            raise SourceFinalizationError("Sysmon candidate admission accounting underflowed")
        self._candidate_admitted_rows -= rows
        self._candidate_admitted_bytes -= payload_bytes

    def _render_event(self, event_data: dict[str, Any]) -> str:
        from xml.sax.saxutils import escape as xml_escape

        event_data.pop("_TimingFinalized", None)
        if "TimeCreated" in event_data:
            ts = event_data["TimeCreated"]
            if isinstance(ts, datetime):
                event_data["TimeCreated"] = format_windows_system_time(ts, event_data)
        for key, val in event_data.items():
            if isinstance(val, str) and key != "TimeCreated":
                event_data[key] = xml_escape(val)
        return self._template.render(**event_data)

    def _run(self) -> None:
        """Buffer raw Sysmon dicts and fail closed on any worker error."""

        logger.debug("Emitter thread started for %s", self.format_def.name)
        while not self._stop_event.is_set():
            try:
                event_data = self._event_queue.get(timeout=0.1)
                try:
                    if self._handle_flush_request(event_data):
                        continue
                    with self._file_lock:
                        self._event_dicts.append(event_data)
                        if (
                            self._source_finalization_bound
                            and len(self._event_dicts) >= self.buffer_size
                        ):
                            self._spool_event_dicts_unlocked()
                finally:
                    self._event_queue.task_done()
            except Empty:
                continue
            except Exception as error:  # noqa: BLE001
                self._thread_error = error
                logger.exception(
                    "Unhandled exception in %s emitter thread; stopping thread",
                    self.format_def.name,
                )
                self._stop_event.set()
        logger.debug("Emitter thread stopped for %s", self.format_def.name)

    def _flush_at_barrier(self) -> None:
        """Spill exact candidates or preserve the ordinary legacy barrier."""

        with self._file_lock:
            if self._source_finalization_bound:
                self._spool_event_dicts_unlocked()
            elif not self.threaded:
                self._flush_unlocked()

    def _flush_unlocked(self) -> None:
        """Prepare, render, and write one ordinary legacy Sysmon cohort."""

        if self._exact_candidate_abort_close_rendering:
            raise ExactPublicationError(
                "Sysmon exact abort publication cannot use legacy streaming render"
            )
        if not self._event_dicts:
            return

        self._prepare_event_cohort_unlocked()
        for event in self._event_dicts:
            final = self._finalize_event_for_output(event)
            if final is not None:
                final[2].write(final[3])
        self._event_dicts.clear()

    def _prepare_event_cohort_unlocked(self) -> None:
        """Apply the existing global order, IDs, clocks, and GUID synchronization once."""

        all_finalized = self._apply_compatibility_causal_shifts_unlocked()
        self._freeze_event_order_and_assign_ids_unlocked(all_finalized)
        self._synchronize_event_cohort_unlocked(all_finalized)

    def _apply_compatibility_causal_shifts_unlocked(self) -> bool:
        """Apply legacy causal shifts before the terminal chronological order freezes."""

        all_finalized = all(self._timing_is_finalized(event) for event in self._event_dicts)
        if not all_finalized:
            self._shift_process_creates_after_visible_parent()
            self._shift_followons_after_process_create()
            self._shift_terminations_after_followons()
        return all_finalized

    def _freeze_event_order_and_assign_ids_unlocked(self, all_finalized: bool) -> None:
        """Freeze `(TimeCreated, insertion ordinal)` and assign source record IDs."""

        def _sort_key(event: dict) -> Any:
            ts = event.get("TimeCreated", "")
            if isinstance(ts, datetime):
                return ensure_utc(ts)
            return ts

        self._event_dicts.sort(key=_sort_key)

        self._assign_normalized_times_and_record_ids_unlocked(all_finalized)

    def _assign_normalized_times_and_record_ids_unlocked(self, all_finalized: bool) -> None:
        """Normalize clocks and assign IDs without changing the already-frozen order."""

        for sequence, event in enumerate(self._event_dicts):
            if self._timing_is_finalized(event):
                timestamp = event.get("TimeCreated")
                computer = str(event.get("Computer", ""))
                if isinstance(timestamp, datetime):
                    previous = self._last_time_created_by_computer.get(computer)
                    if previous is None or timestamp > previous:
                        self._last_time_created_by_computer[computer] = timestamp
            else:
                _normalize_windows_time_created(
                    event,
                    self._last_time_created_by_computer,
                    self._time_collision_count_by_computer,
                    sequence,
                    "sysmon_time_created",
                    jitter_existing_microseconds=True,
                )
            computer = event.get("Computer", "")
            counter_key = computer.split(".")[0] if "." in computer else computer
            sequence_model = self._record_id_sequences.setdefault(
                counter_key,
                WindowsRecordIdSequence(
                    "sysmon",
                    counter_key,
                    str(event.get("_host_type") or ""),
                ),
            )
            event["EventRecordID"] = sequence_model.next(
                event.get("TimeCreated"),
                coerce_windows_event_id(event.get("EventID")),
            )

    def _synchronize_event_cohort_unlocked(self, all_finalized: bool) -> None:
        """Synchronize UTC payloads and compatibility GUID references over frozen order."""

        self._sync_utc_time_fields()
        if not all_finalized:
            self._shift_followon_utc_times_after_process_create()
            self._sync_process_guids_to_event1_times()

    def _finalize_event_for_output(
        self,
        event: dict[str, Any],
    ) -> tuple[str, str, _SingleHostWriter, str] | None:
        """Resolve the frozen physical route and final source-native string."""

        source_state, _ = self._source_lifecycle_snapshot()
        terminal = self._source_finalization_bound and source_state != "open"
        output_target = self._source_finalization_output_target if terminal else self.output_target
        if output_target is None:
            raise SourceFinalizationError("Sysmon final output target was not frozen")
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
                render_windows_sysmon_snare_syslog(event),
            )
        if output_target in {OutputTarget.DEFAULT, OutputTarget.SPLUNK}:
            route_key = "" if self._direct_file_mode else sanitize_path_component(host_fqdn)
            rendered = self._render_event(event)
            if output_target == OutputTarget.SPLUNK:
                rendered = compact_windows_event_xml(rendered)
            return ("xml", route_key, self._get_host_writer(host_fqdn), rendered)
        return None

    def _shift_process_creates_after_visible_parent(self) -> None:
        """Prevent visible Sysmon Event 1 children from preceding their parent Event 1."""
        process_create_events: dict[tuple[str, str], dict[str, Any]] = {}
        parent_keys: dict[tuple[str, str], tuple[str, str]] = {}

        for event in self._event_dicts:
            if event.get("EventID") != 1:
                continue
            ts = event.get("TimeCreated")
            guid = event.get("ProcessGuid")
            if not isinstance(ts, datetime) or not guid:
                continue
            computer = str(event.get("Computer", ""))
            key = (computer, str(guid))
            process_create_events[key] = event
            parent_guid = event.get("ParentProcessGuid")
            if parent_guid:
                parent_keys[key] = (computer, str(parent_guid))

        if not process_create_events:
            return

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

        max_passes = len(process_create_events)
        for _ in range(max_passes):
            changed = False
            process_create_times: dict[tuple[str, str], datetime] = {}
            for key, event in process_create_events.items():
                ts = event.get("TimeCreated")
                if isinstance(ts, datetime):
                    process_create_times[key] = ts

            for key, event in process_create_events.items():
                if key in cyclic_keys:
                    continue
                if self._timing_is_finalized(event):
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

    def _sync_process_guids_to_event1_times(self) -> None:
        """Rewrite ProcessGuid references after final Event 1 timestamp shifts."""
        replacements: dict[tuple[str, str], str] = {}
        for event in self._event_dicts:
            if event.get("EventID") != 1:
                continue
            ts = event.get("TimeCreated")
            guid = event.get("ProcessGuid")
            pid = event.get("ProcessId")
            computer = str(event.get("Computer", ""))
            if not isinstance(ts, datetime) or not guid:
                continue
            try:
                pid_int = int(pid)
            except (TypeError, ValueError):
                continue
            hostname = computer.split(".", 1)[0] if computer else ""
            new_guid = self._generate_process_guid(hostname, pid_int, ts)
            old_guid = str(guid)
            self._final_process_guids[(hostname, pid_int, old_guid)] = new_guid
            if new_guid != old_guid:
                replacements[(computer, old_guid)] = new_guid
                event["ProcessGuid"] = new_guid

        if not replacements:
            return

        for event in self._event_dicts:
            computer = str(event.get("Computer", ""))
            for field in _PROCESS_GUID_FIELDS:
                guid = event.get(field)
                if not guid:
                    continue
                replacement = replacements.get((computer, str(guid)))
                if replacement is not None:
                    event[field] = replacement

    def _shift_followons_after_process_create(self) -> None:
        """Prevent same-ProcessGuid Sysmon follow-ons from preceding Event 1."""
        process_create_times: dict[tuple[str, str], datetime] = {}
        for event in self._event_dicts:
            if event.get("EventID") != 1:
                continue
            ts = event.get("TimeCreated")
            guid = event.get("ProcessGuid")
            computer = str(event.get("Computer", ""))
            if isinstance(ts, datetime) and guid:
                process_create_times[(computer, str(guid))] = ts

        for event in self._event_dicts:
            event_id = event.get("EventID")
            if event_id == 1 or self._timing_is_finalized(event):
                continue
            ts = event.get("TimeCreated")
            computer = str(event.get("Computer", ""))
            guid = (
                event.get("ProcessGuid")
                or event.get("SourceProcessGuid")
                or event.get("SourceProcessGUID")
            )
            if not isinstance(ts, datetime) or not guid:
                continue
            create_time = process_create_times.get((computer, str(guid)))
            if create_time is not None and ts <= create_time:
                shifted_time = create_time + timedelta(milliseconds=1)
                event["TimeCreated"] = shifted_time
                if event_id == 11:
                    event["CreationUtcTime"] = _format_sysmon_utc_time(shifted_time)

    def _sync_utc_time_fields(self) -> None:
        """Preserve provider-envelope latency through final causal time repairs."""
        for event in self._event_dicts:
            envelope_time = event.get("TimeCreated")
            native_time = event.pop("_SysmonNativeTime", None)
            initial_envelope = event.pop("_SysmonInitialEnvelopeTime", None)
            if (
                "UtcTime" in event
                and isinstance(envelope_time, datetime)
                and isinstance(native_time, datetime)
                and isinstance(initial_envelope, datetime)
            ):
                repair_delta = envelope_time - initial_envelope
                event["UtcTime"] = _format_sysmon_utc_time(native_time + repair_delta)

    def _shift_followon_utc_times_after_process_create(self) -> None:
        """Keep provider-native dependent timestamps after the owning Event 1."""

        create_times: dict[tuple[str, str], str] = {}
        for event in self._event_dicts:
            if event.get("EventID") != 1 or not event.get("ProcessGuid"):
                continue
            utc_time = event.get("UtcTime")
            if isinstance(utc_time, str):
                create_times[(str(event.get("Computer", "")), str(event["ProcessGuid"]))] = utc_time

        for event in self._event_dicts:
            if event.get("EventID") == 1 or self._timing_is_finalized(event):
                continue
            guid = (
                event.get("ProcessGuid")
                or event.get("SourceProcessGuid")
                or event.get("SourceProcessGUID")
            )
            utc_time = event.get("UtcTime")
            if not guid or not isinstance(utc_time, str):
                continue
            create_time = create_times.get((str(event.get("Computer", "")), str(guid)))
            if create_time is None or utc_time > create_time:
                continue
            shifted = datetime.strptime(create_time, "%Y-%m-%d %H:%M:%S.%f").replace(
                tzinfo=UTC
            ) + timedelta(milliseconds=1)
            shifted_text = _format_sysmon_utc_time(shifted)
            event["UtcTime"] = shifted_text
            if event.get("EventID") == 11:
                event["CreationUtcTime"] = shifted_text

    def _shift_terminations_after_followons(self) -> None:
        """Prevent Event 5 from preceding visible same-process follow-on telemetry."""
        latest_followon: dict[tuple[str, str], datetime] = {}
        terminations: list[tuple[tuple[str, str], dict[str, Any]]] = []
        for event in self._event_dicts:
            ts = event.get("TimeCreated")
            guid = event.get("ProcessGuid")
            if not isinstance(ts, datetime) or not guid:
                continue
            key = (str(event.get("Computer", "")), str(guid))
            if event.get("EventID") == 5:
                terminations.append((key, event))
                continue
            if event.get("EventID") == 1:
                parent_guid = event.get("ParentProcessGuid")
                if parent_guid:
                    parent_key = (str(event.get("Computer", "")), str(parent_guid))
                    latest_followon[parent_key] = max(ts, latest_followon.get(parent_key, ts))
                continue
            latest_followon[key] = max(ts, latest_followon.get(key, ts))

        for key, event in terminations:
            if self._timing_is_finalized(event):
                continue
            ts = event.get("TimeCreated")
            latest = latest_followon.get(key)
            if isinstance(ts, datetime) and latest is not None and ts <= latest:
                event["TimeCreated"] = latest + timedelta(milliseconds=1)

    def _snapshot_render_state(self) -> _SysmonRenderState:
        """Copy mutable source-native state so failed sealing cannot advance it."""

        return _SysmonRenderState(
            record_id_sequences=deepcopy(self._record_id_sequences),
            last_time_created_by_computer=dict(self._last_time_created_by_computer),
            time_collision_count_by_computer=dict(self._time_collision_count_by_computer),
            final_process_guids=dict(self._final_process_guids),
        )

    def _adopt_render_state(self, state: _SysmonRenderState) -> None:
        """Install one retry-local source-native state snapshot."""

        self._record_id_sequences = state.record_id_sequences
        self._last_time_created_by_computer = state.last_time_created_by_computer
        self._time_collision_count_by_computer = state.time_collision_count_by_computer
        self._final_process_guids = state.final_process_guids

    def _source_lifecycle_snapshot(self) -> tuple[str, int | None]:
        """Read source state and transient operation owner under the close fence."""

        with self._close_condition:
            return self._source_finalization_state, self._source_finalization_owner

    @contextmanager
    def _source_finalization_operation(self) -> Iterator[None]:
        """Fence one terminal mutation while allowing sequential thread transfer."""

        if not self._source_finalization_operation_lock.acquire(blocking=False):
            raise SourceFinalizationError(
                "Sysmon source finalization already has an active owner operation"
            )
        owner = get_ident()
        try:
            with self._close_condition:
                if self._source_finalization_owner is not None:
                    raise SourceFinalizationError(
                        "Sysmon source finalization retained a stale operation owner"
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
        """Advance source state under the shared close admission lock."""

        with self._close_condition:
            owner = self._source_finalization_owner
            if owner is not None and owner != get_ident():
                raise SourceFinalizationError(
                    "Sysmon source-finalization state has a different owner"
                )
            self._source_finalization_state = state
            self._close_condition.notify_all()

    def _require_source_owner(self, allowed_states: set[str]) -> str:
        """Require the transient operation owner for a terminal mutation."""

        state, owner = self._source_lifecycle_snapshot()
        if state not in allowed_states:
            raise SourceFinalizationError(
                f"Sysmon source-finalization state {state!r} is not mutable here"
            )
        if owner != get_ident():
            raise SourceFinalizationError(
                "Sysmon source-finalization mutation has a different owner"
            )
        return state

    def barrier_flush(self) -> None:
        """Reject external barriers after terminal quiescence begins."""

        current = get_ident()
        with self._close_condition:
            state = self._source_finalization_state
            owner = self._source_finalization_owner
            if state != "open" and current != owner:
                raise SourceFinalizationError(
                    "Sysmon source-finalization rejected a barrier after quiescence"
                )
            if state == "open":
                legacy_close_owner = (
                    self._close_state == "closing" and self._close_thread == current
                )
                if not legacy_close_owner:
                    self._require_accepting_events_locked()
                    if self._exact_candidate_abort_close_rendering:
                        raise SourceFinalizationError(
                            "Sysmon abort close retry owner rejects an external barrier"
                        )
            elif state != "quiescing":
                raise SourceFinalizationError(
                    "Sysmon source-finalization rejected a terminal barrier"
                )
            self._queue_admissions += 1
        try:
            if self.threaded:
                super().barrier_flush()
            else:
                self._wait_for_exact_publication_turn(None)
                self.flush()
        finally:
            self._finish_queue_admission()

    def quiesce_source_finalization(self) -> None:
        """Reject late candidates, drain FIFO work, and spill without output."""

        with self._source_finalization_operation():
            self._quiesce_source_finalization()

    def _quiesce_source_finalization(self) -> None:
        """Run source quiescence under the current operation capability."""

        if not self._source_finalization_bound:
            raise SourceFinalizationError(
                "Direct Sysmon emitters retain legacy close and cannot bind an exact epoch"
            )
        owner = get_ident()
        with self._close_condition:
            state = self._source_finalization_state
            if self._exact_candidate_abort_close_rendering:
                raise SourceFinalizationError(
                    "Sysmon abort close retry owner rejects source quiescence"
                )
            if state in {"quiesced", "sealed", "published", "closed"}:
                return
            if state == "open":
                if self._close_state != "open":
                    raise SourceFinalizationError(
                        "Sysmon emitter close raced source-finalization quiescence"
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
                    "Sysmon source-finalization quiescence has a different owner"
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
                    "Sysmon candidate journal does not match admitted source capacity"
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
            raise SourceFinalizationError("Sysmon source journal lost its singleton state")
        return tuple(row)

    def _commit_journal_unlocked(self) -> None:
        """Commit the journal through one injectable lost-return boundary."""

        if self._spool_conn is None:
            raise SourceFinalizationError("Sysmon source journal is not open")
        self._spool_conn.commit()

    def _rollback_journal_unlocked(self) -> None:
        """Roll back one uncommitted private-journal transaction."""

        if self._spool_conn is not None:
            self._spool_conn.rollback()

    def _validate_exact_candidate_receipts_before_seal_unlocked(self) -> None:
        """Authenticate every retained exact candidate before final metadata replaces it."""

        connection = self._spool_conn
        if connection is None:
            raise SourceFinalizationError("Sysmon source journal is not open")
        if self._active_exact_publication_keys:
            raise ExactPublicationError("Sysmon exact candidate seal found an active publication")
        if (
            self._exact_candidate_current_rows != self._exact_candidate_released_rows
            or self._exact_candidate_current_bytes != self._exact_candidate_released_bytes
            or self._exact_candidate_current_participants
            != self._exact_candidate_completed_participants
            or len(self._exact_candidate_reservations) != self._exact_candidate_current_rows
            or len(self._exact_candidate_participants) != self._exact_candidate_current_participants
        ):
            raise ExactPublicationError(
                "Sysmon exact candidate seal found incomplete receipt ownership"
            )
        checkpoint_watermark = self._checkpoint_pruned_exact_sequence
        if (
            type(checkpoint_watermark) is not int
            or checkpoint_watermark < 0
            or checkpoint_watermark > self._spool_sequence
        ):
            raise ExactPublicationError("Sysmon exact candidate checkpoint watermark is invalid")

        matched_rows = 0
        cursor = connection.execute(
            """SELECT sequence, sort_key, phase, payload, payload_bytes, ordinal,
                      route_kind, route_key, payload_digest
               FROM events WHERE route_kind = ? ORDER BY sequence""",
            (_EXACT_CANDIDATE_MARKER,),
        )
        for row in cursor:
            if (
                len(row) != 9
                or type(row[0]) is not int
                or type(row[1]) is not str
                or row[2] != "candidate"
                or type(row[3]) is not str
                or type(row[4]) is not int
                or row[4] <= 0
                or row[5] is not None
                or row[6] != _EXACT_CANDIDATE_MARKER
                or type(row[7]) is not str
                or len(row[7]) > 96
                or type(row[8]) is not str
            ):
                raise ExactPublicationError(
                    "Sysmon exact candidate seal found malformed journal metadata"
                )
            (
                sequence,
                sort_key,
                _phase,
                payload,
                payload_bytes,
                _ordinal,
                _marker,
                route_key,
                digest,
            ) = row
            route_parts = route_key.split(":")
            if len(route_parts) != 3:
                raise ExactPublicationError(
                    "Sysmon exact candidate seal found a noncanonical journal key"
                )
            try:
                key = (route_parts[0], int(route_parts[1]), int(route_parts[2]))
            except ValueError:
                raise ExactPublicationError(
                    "Sysmon exact candidate seal found a noncanonical journal key"
                ) from None
            self._validate_exact_candidate_key(key)
            if route_key != f"{key[0]}:{key[1]}:{key[2]}":
                raise ExactPublicationError(
                    "Sysmon exact candidate seal found a noncanonical journal key"
                )
            reservation = self._exact_candidate_reservations.get(key)
            checkpoint_sealed = sequence < checkpoint_watermark
            if checkpoint_sealed:
                if reservation is not None:
                    raise ExactPublicationError(
                        "Sysmon exact candidate checkpoint ownership overlaps a live receipt"
                    )
            elif (
                reservation is None
                or not reservation.capacity_charged
                or not reservation.admitted
                or not reservation.released
                or reservation.sequence != sequence
                or reservation.retained_bytes != payload_bytes
                or reservation.digest != digest
            ):
                raise ExactPublicationError(
                    "Sysmon exact candidate seal found foreign or conflicting ownership"
                )
            encoded = payload.encode("utf-8")
            try:
                expected_sort_key = self._event_sort_key(_sysmon_spool_decode(payload))
            except (RecursionError, TypeError, ValueError):
                raise ExactPublicationError(
                    "Sysmon exact candidate seal found a malformed payload"
                ) from None
            if (
                len(encoded) != payload_bytes
                or hashlib.sha256(encoded).hexdigest() != digest
                or sort_key != expected_sort_key
            ):
                raise ExactPublicationError(
                    "Sysmon exact candidate seal found a changed payload or sort key"
                )
            if not checkpoint_sealed:
                matched_rows += 1

        if matched_rows != self._exact_candidate_current_rows:
            raise ExactPublicationError(
                "Sysmon exact candidate seal found a missing or extra journal receipt"
            )

    def _route_id_unlocked(
        self,
        route_kind: str,
        route_key: str,
        writer: _SingleHostWriter,
    ) -> int:
        """Retain one resolved physical writer under the finite route cap."""

        token = (route_kind, route_key)
        route_id = self._source_finalization_route_ids.get(token)
        if route_id is not None:
            if self._source_finalization_routes.get(route_id) is not writer:
                raise SourceFinalizationError(
                    "Sysmon source route changed its physical writer during sealing"
                )
            return route_id
        if len(self._source_finalization_route_ids) >= self._finalization_route_capacity:
            raise SourceFinalizationError("Sysmon finalization route capacity is exhausted")
        route_id = len(self._source_finalization_route_ids)
        self._source_finalization_route_ids[token] = route_id
        self._source_finalization_routes[route_id] = writer
        return route_id

    def _epoch_from_sealed_state_unlocked(
        self,
        epoch_ordinal: int,
    ) -> _SysmonSourceFinalizationEpoch:
        """Return the strongly retained opaque epoch for one durable seal."""

        epoch = self._source_finalization_epoch
        output_target = self._source_finalization_output_target
        header = self._source_finalization_header
        footer = self._source_finalization_footer
        if output_target is None or header is None or footer is None:
            raise SourceFinalizationError("Sysmon epoch lost its frozen output contract")
        if epoch is not None:
            if (
                epoch._owner is not self
                or epoch._ordinal != epoch_ordinal
                or epoch._output_target != output_target
                or epoch._header != header
                or epoch._footer != footer
            ):
                raise SourceFinalizationError("Sysmon source epoch identity changed")
            return epoch
        epoch = _SysmonSourceFinalizationEpoch(
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
        """Stream-validate final rows before adopting a seal lost return."""

        state = self._journal_state_unlocked()
        if str(state[0]) not in {"sealed", "published"} or int(state[7]) != epoch_ordinal:
            raise SourceFinalizationError("Sysmon journal did not retain its sealed epoch")
        final_rows = int(state[3])
        final_bytes = int(state[4])
        routes = int(state[5])
        if expected_rows is not None and final_rows != expected_rows:
            raise SourceFinalizationError("Sysmon sealed row count changed after commit")
        if expected_bytes is not None and final_bytes != expected_bytes:
            raise SourceFinalizationError("Sysmon sealed byte count changed after commit")
        if expected_routes is not None and routes != expected_routes:
            raise SourceFinalizationError("Sysmon sealed route count changed after commit")
        if self._spool_conn is None:
            raise SourceFinalizationError("Sysmon source journal is not open")
        if self._spool_conn.execute(
            "SELECT COUNT(*) FROM events WHERE phase = ?", ("candidate",)
        ).fetchone() != (0,):
            raise SourceFinalizationError("Sysmon sealed journal retained candidate rows")
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
                raise SourceFinalizationError("Sysmon sealed journal lost contiguous ordinals")
            if not all(isinstance(value, str) for value in (route_kind, route_key, rendered)):
                raise SourceFinalizationError("Sysmon sealed journal retained invalid row types")
            encoded = rendered.encode("utf-8")
            if len(encoded) != int(payload_bytes) or hashlib.sha256(encoded).hexdigest() != str(
                payload_digest
            ):
                raise SourceFinalizationError("Sysmon sealed journal row changed after commit")
            route_tokens.add((route_kind, route_key))
            retained_rows += 1
            retained_bytes += len(encoded)
        if (retained_rows, retained_bytes, len(route_tokens)) != (
            final_rows,
            final_bytes,
            routes,
        ):
            raise SourceFinalizationError("Sysmon sealed journal scalar state changed")
        if route_tokens != set(self._source_finalization_route_ids):
            raise SourceFinalizationError("Sysmon sealed journal lost retained route owners")
        return state

    def seal_source_finalization(self) -> SourceFinalizationEpoch:
        """Seal the complete cohort into immutable routed strings exactly once."""

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
                raise SourceFinalizationError("Sysmon source journal has an invalid seal phase")
            connection = self._spool_conn
            if connection is None:
                raise SourceFinalizationError("Sysmon source journal is not open")

            candidate_rows = self._load_candidate_rows_unlocked()
            events = [event for _sequence, event in candidate_rows]
            original_events = self._event_dicts
            original_state = _SysmonRenderState(
                record_id_sequences=self._record_id_sequences,
                last_time_created_by_computer=self._last_time_created_by_computer,
                time_collision_count_by_computer=self._time_collision_count_by_computer,
                final_process_guids=self._final_process_guids,
            )
            working_state = self._snapshot_render_state()
            initial_host_writer_keys = set(self._host_writers)
            initial_snare_writer_keys = set(self._snare_writers)
            self._source_finalization_routes.clear()
            self._source_finalization_route_ids.clear()
            epoch_ordinal = int(state[7]) + 1
            final_rows = 0
            final_bytes = 0
            seal_high_water_bytes = int(state[9])
            sealed = False
            connection.execute("BEGIN IMMEDIATE")
            try:
                self._validate_exact_candidate_receipts_before_seal_unlocked()
                self._event_dicts = events
                self._adopt_render_state(working_state)
                all_finalized = self._apply_compatibility_causal_shifts_unlocked()
                shifted_bytes = self._persist_candidate_phase_unlocked(
                    candidate_rows,
                    update_sort_key=True,
                    phase_name="causal-shift",
                )
                seal_high_water_bytes = max(seal_high_water_bytes, shifted_bytes)

                candidate_rows = []
                self._event_dicts = []
                events = []
                frozen_rows = self._load_candidate_rows_unlocked(frozen_order=True)
                self._event_dicts = [event for _sequence, event in frozen_rows]
                sequence_by_identity = {id(event): sequence for sequence, event in frozen_rows}
                self._assign_normalized_times_and_record_ids_unlocked(all_finalized)
                normalized_bytes = self._persist_candidate_phase_unlocked(
                    frozen_rows,
                    update_sort_key=False,
                    phase_name="normalization",
                )
                seal_high_water_bytes = max(seal_high_water_bytes, normalized_bytes)
                self._synchronize_event_cohort_unlocked(all_finalized)
                synchronized_bytes = self._persist_candidate_phase_unlocked(
                    frozen_rows,
                    update_sort_key=False,
                    phase_name="synchronization",
                )
                seal_high_water_bytes = max(seal_high_water_bytes, synchronized_bytes)
                for event in self._event_dicts:
                    sequence = sequence_by_identity.get(id(event))
                    if sequence is None:
                        raise SourceFinalizationError(
                            "Sysmon terminal sort lost a candidate identity"
                        )
                    final = self._finalize_event_for_output(event)
                    if final is None:
                        connection.execute(
                            "DELETE FROM events WHERE sequence = ? AND phase = ?",
                            (sequence, "candidate"),
                        )
                        continue
                    route_kind, route_key, writer, rendered = final
                    self._route_id_unlocked(route_kind, route_key, writer)
                    encoded = rendered.encode("utf-8")
                    rendered_bytes = len(encoded)
                    if rendered_bytes > _FINALIZATION_CHUNK_BYTES:
                        raise SourceFinalizationError(
                            "Sysmon final row exceeds exact publication byte capacity"
                        )
                    final_rows += 1
                    final_bytes += rendered_bytes
                    if final_rows > self._finalization_row_capacity:
                        raise SourceFinalizationError(
                            "Sysmon finalization row capacity is exhausted"
                        )
                    if final_bytes > self._finalization_byte_capacity:
                        raise SourceFinalizationError(
                            "Sysmon finalization byte capacity is exhausted"
                        )
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
                            hashlib.sha256(encoded).hexdigest(),
                            sequence,
                            "candidate",
                        ),
                    )
                    if updated.rowcount != 1:
                        raise SourceFinalizationError(
                            "Sysmon candidate changed during terminal sealing"
                        )
                working_state = self._snapshot_render_state()
                routes = len(self._source_finalization_route_ids)
                updated_state = connection.execute(
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
                if updated_state.rowcount != 1:
                    raise SourceFinalizationError("Sysmon source state changed during sealing")
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
                self._event_dicts = original_events
                self._adopt_render_state(original_state)

            if not sealed:
                raise SourceFinalizationError("Sysmon terminal source seal was not durable")
            self._spooled_count = 0
            self._candidate_admitted_rows = 0
            self._candidate_admitted_bytes = 0
            self._source_high_water_rows = max(self._source_high_water_rows, final_rows)
            self._source_high_water_bytes = max(
                self._source_high_water_bytes,
                seal_high_water_bytes,
                final_bytes,
            )
            self._source_high_water_routes = max(
                self._source_high_water_routes,
                len(self._source_finalization_route_ids),
            )
            self._adopt_render_state(working_state)
            epoch = self._epoch_from_sealed_state_unlocked(epoch_ordinal)
            self._set_source_lifecycle_state("sealed")
            return epoch

    def _resolve_sealed_writer_unlocked(
        self,
        route_kind: str,
        route_key: str,
    ) -> _SingleHostWriter:
        """Resolve the writer retained when this route was sealed."""

        route_id = self._source_finalization_route_ids.get((route_kind, route_key))
        writer = self._source_finalization_routes.get(route_id) if route_id is not None else None
        if writer is None:
            raise SourceFinalizationError(
                "Sysmon sealed route lost its same-process physical writer"
            )
        return writer

    def _read_final_row_unlocked(self, ordinal: int) -> ExactSourceRow:
        """Load and authenticate one immutable final row by exact ordinal."""

        if type(ordinal) is not int or ordinal < 0:
            raise SourceFinalizationError(
                "Sysmon immutable final row ordinal must be a nonnegative exact int"
            )
        connection = self._spool_conn
        if connection is None:
            raise SourceFinalizationError("Sysmon source journal is not open")
        row = connection.execute(
            """SELECT route_kind, route_key, payload, payload_bytes, payload_digest
               FROM events WHERE phase = ? AND ordinal = ?""",
            ("final", ordinal),
        ).fetchone()
        if row is None:
            raise SourceFinalizationError("Sysmon immutable final row is missing")
        route_kind, route_key, rendered, payload_bytes, payload_digest = row
        if (
            type(route_kind) is not str
            or type(route_key) is not str
            or type(rendered) is not str
            or type(payload_bytes) is not int
            or payload_bytes < 0
            or type(payload_digest) is not str
        ):
            raise SourceFinalizationError("Sysmon immutable final row has invalid types")
        encoded = rendered.encode("utf-8")
        if len(encoded) != payload_bytes or hashlib.sha256(encoded).hexdigest() != payload_digest:
            raise SourceFinalizationError("Sysmon immutable final row failed validation")
        return ExactSourceRow(
            writer=self._resolve_sealed_writer_unlocked(route_kind, route_key),
            content=rendered,
        )

    def _read_final_chunk_unlocked(
        self,
        cursor: int,
        final_rows: int,
    ) -> _SysmonFinalChunk | None:
        """Load one bounded immutable final-string chunk."""

        if cursor >= final_rows:
            return None
        rows: list[ExactSourceRow] = []
        retained_bytes = 0
        route_ids: set[int] = set()
        while len(rows) < _FINALIZATION_CHUNK_ROWS and cursor + len(rows) < final_rows:
            ordinal = cursor + len(rows)
            row = self._read_final_row_unlocked(ordinal)
            encoded = row.content.encode("utf-8")
            next_bytes = retained_bytes + len(encoded)
            next_route_ids = route_ids | {id(row.writer)}
            if rows and (
                next_bytes > _FINALIZATION_CHUNK_BYTES
                or len(next_route_ids) > _FINALIZATION_CHUNK_ROUTES
            ):
                break
            if next_bytes > _FINALIZATION_CHUNK_BYTES:
                raise SourceFinalizationError(
                    "Sysmon immutable row exceeds exact chunk byte capacity"
                )
            retained_bytes = next_bytes
            route_ids = next_route_ids
            rows.append(row)
        if not rows:
            raise SourceFinalizationError("Sysmon source chunk could not make bounded progress")
        return _SysmonFinalChunk(
            chunk_id=cursor,
            end_sequence=cursor + len(rows),
            rows=tuple(rows),
        )

    def _source_checkpoint_at_least_unlocked(self, cursor: int) -> bool:
        state = self._journal_state_unlocked()
        return int(state[6]) >= cursor

    def _checkpoint_source_chunk(self, start: int, end: int) -> None:
        """Durably advance the source cursor after sink commit and before release."""

        self._require_source_owner({"sealed"})
        with self._file_lock:
            state = self._journal_state_unlocked()
            if int(state[6]) >= end:
                return
            if str(state[0]) != "sealed" or int(state[6]) != start:
                raise SourceFinalizationError(
                    "Sysmon source checkpoint does not match the retained child"
                )
            if self._spool_conn is None:
                raise SourceFinalizationError("Sysmon source journal is not open")
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
                raise SourceFinalizationError("Sysmon source checkpoint was not durable")

    def _source_checkpoint_at_least(self, cursor: int) -> bool:
        self._require_source_owner({"sealed"})
        with self._file_lock:
            return self._source_checkpoint_at_least_unlocked(cursor)

    def publish_source_finalization(
        self,
        epoch: SourceFinalizationEpoch,
        publisher: ExactChunkPublisher,
    ) -> None:
        """Publish sealed strings through bounded exact final-writer children."""

        with self._source_finalization_operation():
            self._publish_source_finalization(epoch, publisher)

    def _publish_source_finalization(
        self,
        epoch: SourceFinalizationEpoch,
        publisher: ExactChunkPublisher,
    ) -> None:
        source_state = self._require_source_owner({"sealed", "published"})
        if epoch is not self._source_finalization_epoch or not isinstance(
            epoch, _SysmonSourceFinalizationEpoch
        ):
            raise SourceFinalizationError("Sysmon publication received a foreign epoch")
        if epoch._owner is not self:
            raise SourceFinalizationError("Sysmon publication lost its epoch owner")
        if source_state == "published":
            return

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
                    raise SourceFinalizationError("Sysmon journal left its exact publication phase")
                chunk = self._read_final_chunk_unlocked(cursor, final_rows)
            if chunk is None:
                with self._file_lock:
                    if self._spool_conn is None:
                        raise SourceFinalizationError("Sysmon source journal is not open")
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
                            "Sysmon terminal publication state was not durable"
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

    def exact_candidate_census(self) -> SysmonExactCandidateCensus:
        """Return constant-time same-process exact candidate ownership counts."""

        with self._exact_publication_condition:
            return SysmonExactCandidateCensus(
                current_rows=self._exact_candidate_current_rows,
                current_bytes=self._exact_candidate_current_bytes,
                current_participants=self._exact_candidate_current_participants,
                released_rows=self._exact_candidate_released_rows,
                released_bytes=self._exact_candidate_released_bytes,
                completed_participants=self._exact_candidate_completed_participants,
                high_water_rows=self._exact_candidate_high_water_rows,
                high_water_bytes=self._exact_candidate_high_water_bytes,
                high_water_participants=self._exact_candidate_high_water_participants,
            )

    def source_finalization_census(self) -> SysmonSourceFinalizationCensus:
        """Return bounded journal counts for diagnostics and tests."""

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
                values = (admitted_rows, admitted_bytes, 0, 0, 0, 0)
                high_water = source_high_water
            elif self._spool_conn is None:
                values = (0, 0, 0, 0, 0, 0)
                high_water = source_high_water
            else:
                state = self._journal_state_unlocked()
                values = tuple(int(value) for value in state[1:7])
                high_water = tuple(int(value) for value in state[8:11])
            return SysmonSourceFinalizationCensus(
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

    def flush(self, force: bool = False) -> None:
        """Spill exact candidates or preserve ordinary legacy rendering."""

        current = get_ident()
        with self._close_condition:
            source_state = self._source_finalization_state
            retained_exact_candidates = bool(
                self._active_exact_publication_keys
                or self._exact_candidate_current_rows
                or self._exact_candidate_current_bytes
                or self._exact_candidate_current_participants
                or self._exact_candidate_released_rows
                or self._exact_candidate_released_bytes
                or self._exact_candidate_completed_participants
                or self._exact_candidate_reservations
                or self._exact_candidate_participants
            )
            if self._exact_candidate_abort_close_rendering and self._close_thread != current:
                raise SourceFinalizationError(
                    "Sysmon abort close retry owner rejects an external flush"
                )
            if self._source_finalization_bound and force and retained_exact_candidates:
                raise SourceFinalizationError(
                    "Sysmon released exact candidates require authenticated abort close"
                )
        if self._source_finalization_bound and source_state != "open":
            raise SourceFinalizationError(
                "Sysmon source-finalization rejected legacy flush after quiescence"
            )
        if self._source_finalization_bound:
            with self._file_lock:
                self._spool_event_dicts_unlocked()
        else:
            if not self.threaded:
                force = True
            if not force:
                return
            with self._file_lock:
                self._flush_unlocked()
        with self._host_writers_lock:
            for writer in self._host_writers.values():
                writer.flush()
            for writer in self._snare_writers.values():
                writer.flush()

    def close(self) -> None:
        """Close after exact publication, or retain the direct legacy behavior."""

        if self._source_finalization_bound:
            with self._source_finalization_operation():
                self._close_sysmon_emitter()
            return
        self._close_sysmon_emitter()

    def _finish_exact_candidate_terminal_cleanup(self) -> None:
        """Drop bounded released receipts only after terminal source ownership ends."""

        with self._exact_publication_condition:
            if self._active_exact_publication_keys:
                raise ExactPublicationError(
                    "Sysmon terminal cleanup found an active exact candidate batch"
                )
            if (
                self._exact_candidate_current_participants
                != self._exact_candidate_completed_participants
            ):
                raise ExactPublicationError(
                    "Sysmon terminal cleanup found an incomplete exact participant"
                )
            if (
                self._exact_candidate_current_rows != self._exact_candidate_released_rows
                or self._exact_candidate_current_bytes != self._exact_candidate_released_bytes
            ):
                raise ExactPublicationError(
                    "Sysmon terminal cleanup found an unreleased exact candidate"
                )
            if (
                len(self._exact_candidate_reservations) != self._exact_candidate_current_rows
                or len(self._exact_candidate_participants)
                != self._exact_candidate_current_participants
            ):
                raise ExactPublicationError(
                    "Sysmon terminal cleanup found inconsistent exact candidate ownership"
                )
            if (
                self._exact_candidate_abort_pending_row is not None
                or self._exact_candidate_abort_registered_writers
            ):
                raise ExactPublicationError(
                    "Sysmon terminal cleanup found incomplete exact abort publication"
                )
            self._exact_candidate_reservations.clear()
            self._exact_candidate_participants.clear()
            self._exact_candidate_current_rows = 0
            self._exact_candidate_current_bytes = 0
            self._exact_candidate_current_participants = 0
            self._exact_candidate_released_rows = 0
            self._exact_candidate_released_bytes = 0
            self._exact_candidate_completed_participants = 0
            self._exact_candidate_abort_participant_key = None

    def _validate_exact_candidate_receipts_before_abort_close(self) -> bool:
        """Authenticate released exact candidates before abort may clear or render them."""

        with self._exact_publication_condition:
            retained = bool(
                self._exact_candidate_current_rows
                or self._exact_candidate_current_bytes
                or self._exact_candidate_current_participants
                or self._exact_candidate_released_rows
                or self._exact_candidate_released_bytes
                or self._exact_candidate_completed_participants
                or self._exact_candidate_reservations
                or self._exact_candidate_participants
            )
            if not retained:
                return False
            with self._file_lock:
                self._validate_exact_candidate_receipts_before_seal_unlocked()
            return True

    def _exact_candidate_abort_participant(self) -> ExactPublicationParticipantKey:
        """Retain one authenticated candidate participant for exact abort publication."""

        with self._exact_publication_condition:
            retained = self._exact_candidate_abort_participant_key
            if retained is not None:
                if retained not in self._exact_candidate_participants:
                    raise ExactPublicationError(
                        "Sysmon exact abort publication lost its candidate participant"
                    )
                return retained
            if not self._exact_candidate_participants:
                raise ExactPublicationError(
                    "Sysmon exact abort publication requires a retained participant"
                )
            retained = min(self._exact_candidate_participants)
            self._validate_exact_candidate_participant_key(retained)
            self._exact_candidate_abort_participant_key = retained
            return retained

    def _register_exact_candidate_abort_writer(
        self,
        writer: _SingleHostWriter,
        participant_key: ExactPublicationParticipantKey,
    ) -> None:
        """Fence one final writer under the retained abort participant."""

        writer_id = id(writer)
        retained = self._exact_candidate_abort_registered_writers.get(writer_id)
        if retained is not None:
            if retained is not writer:
                raise ExactPublicationError(
                    "Sysmon exact abort publication changed a retained final writer"
                )
            return
        writer._register_exact_publication_batch(participant_key)
        self._exact_candidate_abort_registered_writers[writer_id] = writer

    def _mark_exact_candidate_abort_published_unlocked(self) -> None:
        """Durably mark a fully checkpointed abort cohort published."""

        connection = self._spool_conn
        if connection is None:
            raise SourceFinalizationError("Sysmon source journal is not open")
        connection.execute(
            """UPDATE finalization_state SET phase = ?
               WHERE singleton = ? AND phase = ? AND published_rows = final_rows""",
            ("published", 1, "sealed"),
        )
        try:
            self._commit_journal_unlocked()
        except BaseException:
            if connection.in_transaction or str(self._journal_state_unlocked()[0]) != "published":
                self._rollback_journal_unlocked()
                raise
        if str(self._journal_state_unlocked()[0]) != "published":
            raise SourceFinalizationError("Sysmon exact abort publication state was not durable")

    def _resume_exact_candidate_abort_rows(self) -> None:
        """Publish sealed abort rows one at a time through exact final-writer receipts."""

        participant_key = self._exact_candidate_abort_participant()
        while True:
            pending = self._exact_candidate_abort_pending_row
            release_pending = False
            publication_complete = False
            rendered = ""
            with self._file_lock:
                state = self._journal_state_unlocked()
                phase = str(state[0])
                final_rows = int(state[3])
                cursor = int(state[6])
                if cursor < 0 or cursor > final_rows:
                    raise SourceFinalizationError(
                        "Sysmon exact abort publication cursor is out of range"
                    )
                if pending is not None and cursor == pending.ordinal + 1:
                    release_pending = True
                elif pending is not None and cursor != pending.ordinal:
                    raise ExactPublicationError(
                        "Sysmon exact abort publication lost its pending row cursor"
                    )
                elif phase == "published":
                    if cursor != final_rows:
                        raise SourceFinalizationError(
                            "Sysmon published abort cohort retained an incomplete cursor"
                        )
                    publication_complete = True
                elif phase != "sealed":
                    raise SourceFinalizationError(
                        "Sysmon exact abort publication requires a sealed journal"
                    )
                elif cursor == final_rows:
                    self._mark_exact_candidate_abort_published_unlocked()
                    publication_complete = True
                else:
                    row = self._read_final_row_unlocked(cursor)
                    rendered = row.content
                    digest = hashlib.sha256(rendered.encode("utf-8")).hexdigest()
                    key = (participant_key[0], participant_key[1], cursor)
                    if pending is None:
                        pending = _SysmonAbortExactPendingRow(
                            ordinal=cursor,
                            key=key,
                            writer=row.writer,
                            digest=digest,
                        )
                        self._exact_candidate_abort_pending_row = pending
                    elif (
                        pending.key != key
                        or pending.writer is not row.writer
                        or pending.digest != digest
                    ):
                        raise ExactPublicationError(
                            "Sysmon exact abort publication changed its pending final row"
                        )

            if release_pending:
                if pending is None:
                    raise ExactPublicationError(
                        "Sysmon exact abort publication lost its release owner"
                    )
                pending.writer._release_exact_row(pending.key)
                self._exact_candidate_abort_pending_row = None
                continue
            if publication_complete:
                break
            if pending is None:
                raise ExactPublicationError("Sysmon exact abort publication lost its pending row")
            self._register_exact_candidate_abort_writer(pending.writer, participant_key)
            pending.writer._commit_exact_row(pending.key, pending.digest, rendered)
            self._checkpoint_source_chunk(pending.ordinal, pending.ordinal + 1)

        for writer in tuple(self._exact_candidate_abort_registered_writers.values()):
            writer._complete_exact_publication_batch(participant_key)
        self._exact_candidate_abort_registered_writers.clear()

    def _resume_exact_candidate_abort_render(self) -> None:
        """Seal, exactly publish, and clean one authenticated abort cohort."""

        with self._close_condition:
            output_target = self._source_finalization_output_target
            header = self._source_finalization_header
            footer = self._source_finalization_footer
            if output_target is None and header is None and footer is None:
                self._source_finalization_output_target = self.output_target
                self._source_finalization_header = self.format_def.output.header_template or ""
                self._source_finalization_footer = self.format_def.output.footer_template or ""
            elif (
                output_target != self.output_target
                or header != (self.format_def.output.header_template or "")
                or footer != (self.format_def.output.footer_template or "")
            ):
                raise ExactPublicationError(
                    "Sysmon exact abort publication changed its frozen output contract"
                )
        self._set_source_lifecycle_state("quiesced")
        try:
            with self._file_lock:
                self._spool_event_dicts_unlocked()
            self._seal_source_finalization()
            self._resume_exact_candidate_abort_rows()
        finally:
            self._set_source_lifecycle_state("open")
        self._exact_candidate_abort_close_rows_rendered = True
        with self._file_lock:
            self._cleanup_spool_unlocked()

    def _prepare_exact_candidate_abort_close_render(self) -> bool:
        """Resume authenticated abort rendering and report whether rows already rendered."""

        if self._exact_candidate_abort_close_render_complete:
            if (
                not self._exact_candidate_abort_close_rendering
                or not self._exact_candidate_abort_close_rows_rendered
            ):
                raise ExactPublicationError(
                    "Sysmon abort close lost its exact render-completion owner"
                )
            return True
        if self._exact_candidate_abort_close_rows_rendered:
            if not self._exact_candidate_abort_close_rendering:
                raise ExactPublicationError(
                    "Sysmon abort close retained rows without an exact render owner"
                )
            with self._file_lock:
                self._cleanup_spool_unlocked()
            if not self._exact_candidate_abort_close_render_complete:
                raise ExactPublicationError(
                    "Sysmon abort close did not retain journal-cleanup completion"
                )
            return True
        if self._exact_candidate_abort_close_rendering:
            self._resume_exact_candidate_abort_render()
            return True
        retained = self._validate_exact_candidate_receipts_before_abort_close()
        if not retained:
            return False
        self._exact_candidate_abort_close_rendering = True
        self._resume_exact_candidate_abort_render()
        return True

    def _close_sysmon_emitter(self) -> None:
        """Run exact or legacy close while the required source owner is held."""

        source_state, source_owner = self._source_lifecycle_snapshot()
        if self._source_finalization_bound and source_state != "open":
            if source_state in {"aborted", "closed"}:
                return
            if source_state != "published":
                raise SourceFinalizationError(
                    "Sysmon source close cannot render an unpublished sealed cohort"
                )
            if source_owner != get_ident():
                raise SourceFinalizationError("Sysmon source close has a different owner")
            footer = self._source_finalization_footer
            output_target = self._source_finalization_output_target
            if footer is None or output_target is None:
                raise SourceFinalizationError("Sysmon source close lost its frozen contract")
            self._finish_exact_candidate_terminal_cleanup()
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
            skip_render = False
            if self._source_finalization_bound:
                skip_render = self._prepare_exact_candidate_abort_close_render()
            if not skip_render and self._source_finalization_bound:
                with self._file_lock:
                    self._spool_event_dicts_unlocked()
                    self._cleanup_spool_unlocked()
            elif not skip_render:
                self.flush(force=True)
            if (
                self._exact_candidate_abort_close_rendering
                and not self._exact_candidate_abort_close_render_complete
            ):
                raise ExactPublicationError(
                    "Sysmon abort close did not complete its authenticated exact render"
                )
            footer = self.format_def.output.footer_template or ""
            for writer in self._host_writers.values():
                if footer and writer.event_count > 0 and self.output_target != OutputTarget.SPLUNK:
                    writer.write_footer(footer)
                else:
                    writer.flush()
            for writer in self._snare_writers.values():
                writer.flush()
            self._source_finalization_routes.clear()
            self._source_finalization_route_ids.clear()
            self._finish_exact_candidate_terminal_cleanup()
        except BaseException:
            self._fail_close()
            raise
        if self._source_finalization_bound:
            self._exact_candidate_abort_close_rendering = False
            self._exact_candidate_abort_close_rows_rendered = False
            self._exact_candidate_abort_close_render_complete = False
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
