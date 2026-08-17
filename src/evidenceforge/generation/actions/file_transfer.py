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

"""File-transfer action bundles and metadata builders."""

from __future__ import annotations

import hashlib
import random
from contextlib import ExitStack
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any, Literal, Protocol
from urllib.parse import urlsplit

from evidenceforge.events.base import OccurrenceBuilder
from evidenceforge.events.content_identity import FileContentIdentity
from evidenceforge.events.contexts import (
    AuthContext,
    FileContext,
    FileTransferContext,
    HttpMultipartEntityContext,
    PeContext,
    ProcessContext,
)
from evidenceforge.events.contracts import (
    EffectOccurrenceKind,
    EffectOccurrenceProvenance,
    OccurrenceRole,
)
from evidenceforge.events.identity import EntityIdentity, EventIdentityPlan, ProcessIdentity
from evidenceforge.generation.actions.base import ActionAnchor
from evidenceforge.generation.actions.command_effects import (
    ChildProcessEffectIntent,
    EffectActorRef,
    EffectExecutionOutcome,
    EffectOutcomeStatus,
    EffectRequirement,
    ExecutionEffectNode,
    ExecutionEffectPlan,
    ExecutionEffectPlanError,
    ExecutionEffectPlanErrorCode,
    ExecutionEffectReconciliation,
    FileEffectAction,
    FileEffectIntent,
    TransferEffectIntent,
)
from evidenceforge.generation.activity.network import _is_private_ip
from evidenceforge.generation.deployment_registry import LocalArtifactPublishToken
from evidenceforge.generation.runtime_content import RuntimeContentIdentityManager
from evidenceforge.generation.state_manager import StateManager
from evidenceforge.generation.timing import TimingRuntime, TimingScope, TriangularDistribution
from evidenceforge.models.scenario import System, User
from evidenceforge.utils.ids import generate_zeek_uid_from_rng
from evidenceforge.utils.rng import _stable_seed, stable_uuid
from evidenceforge.utils.time import ensure_utc

if TYPE_CHECKING:
    from evidenceforge.generation.storage_world import CompiledStorageFile


_HTTP_HASH_ANALYZER_MIME_TYPES = {
    "application/octet-stream",
    "application/vnd.rar",
    "application/vnd.debian.binary-package",
    "application/vnd.ms-cab-compressed",
    "application/x-dosexec",
    "application/x-gzip",
    "application/x-ms-patch",
    "application/x-msi",
    "application/x-msdownload",
    "application/zip",
}
_HTTP_PE_ANALYZER_MIME_TYPES = {
    "application/octet-stream",
    "application/x-dosexec",
    "application/x-msdownload",
}
_HTTP_PE_DEFINITE_MIME_TYPES = {
    "application/x-dosexec",
    "application/x-msdownload",
}
_HTTP_ANALYZER_SHORT_BODY_BYTES = 64 * 1024
_HTTP_BULK_BODY_BYTES = 1_000_000
_HTTP_PARENT_ANALYZER_MARGIN_SECONDS = 0.75
_PE_COMPILE_EARLIEST_TS = int(datetime(2018, 1, 1, tzinfo=UTC).timestamp())
_PE_COMPILE_LATEST_TS = int(datetime(2024, 6, 1, tzinfo=UTC).timestamp())
_PE_COMPILE_OBSERVATION_MARGIN_SECONDS = 30 * 24 * 60 * 60
_PE_SECTION_PROFILES = (
    [".text", ".rdata", ".data", ".pdata", ".rsrc", ".reloc"],
    [".text", ".rdata", ".data", ".rsrc", ".reloc"],
    [".text", ".idata", ".data", ".rsrc", ".reloc"],
    [".text", ".rdata", ".data", ".rsrc"],
)


def _http_transfer_throughput_range(response_body_len: int) -> tuple[int, int] | None:
    """Return source-native HTTP file throughput bounds in bytes/second."""

    if response_body_len <= _HTTP_ANALYZER_SHORT_BODY_BYTES:
        return None
    if response_body_len >= 50 * 1024 * 1024:
        return (18 * 1024 * 1024, 80 * 1024 * 1024)
    if response_body_len >= 10 * 1024 * 1024:
        return (12 * 1024 * 1024, 70 * 1024 * 1024)
    if response_body_len >= _HTTP_BULK_BODY_BYTES:
        return (6 * 1024 * 1024, 55 * 1024 * 1024)
    return (2 * 1024 * 1024, 35 * 1024 * 1024)


def _http_transfer_throughput_floor(response_body_len: int, rng: random.Random) -> float:
    """Return a source-native lower-bound duration for HTTP file payload analysis."""

    throughput_range = _http_transfer_throughput_range(response_body_len)
    if throughput_range is None:
        return 0.0
    bytes_per_second = rng.uniform(*throughput_range)
    return max(0.012, response_body_len / bytes_per_second)


def http_response_transfer_duration_floor(
    response_body_len: int,
    rng: random.Random,
) -> float:
    """Return the minimum plausible parent-connection duration for HTTP files.log."""

    return _http_transfer_throughput_floor(response_body_len, rng)


def http_response_parent_duration_floor(response_body_len: int) -> float:
    """Return a conservative parent-flow duration floor for HTTP file analysis."""

    throughput_range = _http_transfer_throughput_range(response_body_len)
    if throughput_range is None:
        return 0.0
    slowest_bytes_per_second = throughput_range[0]
    return (
        max(0.012, response_body_len / slowest_bytes_per_second)
        + _HTTP_PARENT_ANALYZER_MARGIN_SECONDS
    )


def _http_response_file_duration(
    response_body_len: int,
    parent_duration: float | None,
    rng: random.Random,
) -> float:
    """Return a source-native files.log duration for an HTTP response body."""

    if response_body_len <= _HTTP_ANALYZER_SHORT_BODY_BYTES:
        return rng.uniform(0.0, 0.01)

    duration_floor = _http_transfer_throughput_floor(response_body_len, rng)
    if parent_duration is None or parent_duration <= 0:
        return duration_floor

    if response_body_len >= 10 * 1024 * 1024:
        parent_fraction = rng.uniform(0.55, 0.92)
    elif response_body_len >= _HTTP_BULK_BODY_BYTES:
        parent_fraction = rng.uniform(0.35, 0.85)
    else:
        parent_fraction = rng.uniform(0.08, 0.35)
    candidate = max(duration_floor, parent_duration * parent_fraction)
    if parent_duration > duration_floor + 0.002:
        return min(candidate, parent_duration - 0.002)
    return duration_floor


def _sample_transfer_value(
    timing_runtime: TimingRuntime,
    *,
    relationship_key: str,
    stable_id: str,
    host: str,
    lifecycle_id: str,
    sample_key: str,
    minimum: float,
    mode: float,
    maximum: float,
) -> float:
    """Sample one continuous transfer value through the shared timing runtime."""

    return timing_runtime.sampler.sample_value(
        TriangularDistribution(minimum=minimum, mode=mode, maximum=maximum),
        relationship_key=relationship_key,
        scope=TimingScope(
            stable_id=stable_id,
            host=host,
            source="file_transfer",
            lifecycle_id=lifecycle_id,
        ),
        sample_key=sample_key,
    )


def _sample_transfer_gap(
    timing_runtime: TimingRuntime,
    *,
    relationship_key: str,
    stable_id: str,
    host: str,
    lifecycle_id: str,
    sample_key: str,
    minimum_ms: int,
    mode_ms: int,
    maximum_ms: int,
) -> timedelta:
    """Sample one typed file-effect gap at native microsecond precision."""

    return timing_runtime.sampler.sample_timedelta(
        TriangularDistribution(
            minimum=float(minimum_ms * 1_000),
            mode=float(mode_ms * 1_000),
            maximum=float(maximum_ms * 1_000),
        ),
        relationship_key=relationship_key,
        scope=TimingScope(
            stable_id=stable_id,
            host=host,
            source="file_transfer",
            lifecycle_id=lifecycle_id,
        ),
        sample_key=sample_key,
    )


def file_transfer_hashes(seed_material: str, analyzers: list[str]) -> dict[str, str]:
    """Return deterministic Zeek files.log hashes for requested analyzers."""

    analyzer_names = {analyzer.upper() for analyzer in analyzers}
    hashes: dict[str, str] = {}
    if "MD5" in analyzer_names:
        hashes["md5"] = hashlib.md5(seed_material.encode()).hexdigest()
    if "SHA1" in analyzer_names:
        hashes["sha1"] = hashlib.sha1(seed_material.encode()).hexdigest()
    if "SHA256" in analyzer_names:
        hashes["sha256"] = hashlib.sha256(seed_material.encode()).hexdigest()
    return hashes


def _http_content_seed_material(
    host: str,
    uri: str,
    response_body_len: int,
    mime_type: str,
) -> str:
    """Return the canonical HTTP response-content identity seed."""

    identity_uri = _http_content_identity_uri(host, uri)
    return f"http:{host}:{identity_uri}:{response_body_len}:{mime_type}"


def _http_content_identity_uri(host: str, uri: str) -> str:
    """Normalize absolute-form proxy URLs to the origin-form content identity."""

    if not uri:
        return "/"
    try:
        parsed = urlsplit(uri)
    except ValueError:
        return uri
    if parsed.scheme and parsed.netloc:
        parsed_host = (parsed.hostname or "").rstrip(".").lower()
        expected_host = host.rstrip(".").lower()
        if not expected_host or parsed_host == expected_host:
            path = parsed.path or "/"
            if parsed.query:
                path = f"{path}?{parsed.query}"
            return path
    return uri


def _http_pe_is_64bit(uri: str, content_seed_material: str) -> bool:
    """Return a content-scoped PE architecture decision."""

    normalized_uri = uri.lower()
    if any(token in normalized_uri for token in ("x86_64", "amd64", "x64", "win64")):
        return True
    if any(token in normalized_uri for token in ("i386", "x86", "win32")):
        return False
    return _stable_seed(f"http_pe_arch:{content_seed_material}") % 100 < 70


def _http_pe_compile_ts(content_seed_material: str, observed_at: datetime) -> int:
    """Return a content-scoped PE compile timestamp before the observation."""

    fixed_span = max(1, _PE_COMPILE_LATEST_TS - _PE_COMPILE_EARLIEST_TS)
    compile_ts = _PE_COMPILE_EARLIEST_TS + (
        _stable_seed(f"http_pe_compile_ts:{content_seed_material}") % fixed_span
    )
    latest_allowed = int(observed_at.timestamp()) - _PE_COMPILE_OBSERVATION_MARGIN_SECONDS
    if compile_ts <= latest_allowed:
        return compile_ts

    one_year_seconds = 365 * 24 * 60 * 60
    while compile_ts > latest_allowed and compile_ts - one_year_seconds >= _PE_COMPILE_EARLIEST_TS:
        compile_ts -= one_year_seconds
    return min(compile_ts, latest_allowed)


def _http_pe_analysis_enabled(
    mime_type: str,
    content_seed_material: str,
    body_len: int,
) -> bool:
    """Return whether this content object should produce PE analyzer records."""

    if mime_type not in _HTTP_PE_ANALYZER_MIME_TYPES:
        return False
    if mime_type in _HTTP_PE_DEFINITE_MIME_TYPES:
        return True
    if mime_type == "application/octet-stream" and body_len < _HTTP_ANALYZER_SHORT_BODY_BYTES:
        return False
    return _stable_seed(f"http_pe_enabled:{content_seed_material}") % 100 < 25


@dataclass(frozen=True, slots=True)
class HttpFileTransferRequest:
    """Intent for one request or response entity visible to Zeek file analysis."""

    host: str
    uri: str
    dst_ip: str
    body_len: int
    mime_types: tuple[str, ...]
    timestamp: datetime
    is_orig: bool
    multipart: HttpMultipartEntityContext | None = None
    filename: str = ""
    content_identity: str = ""
    parent_duration: float | None = None
    source: str = "activity_generator"

    @property
    def stable_id(self) -> str:
        """Return a deterministic intent identifier for durable references."""

        seed = _stable_seed(
            "action_bundle:http_file_transfer:"
            f"{self.host}:{self.uri}:{self.dst_ip}:{self.body_len}:"
            f"{','.join(self.mime_types)}:{self.is_orig}:{self.filename}:"
            f"{self.multipart!r}:"
            f"{self.content_identity}:{self.timestamp.isoformat()}:"
            f"{self.parent_duration or ''}:{self.source}"
        )
        return f"http-file-transfer-{seed:016x}"


@dataclass(slots=True)
class HttpFileTransferResult:
    """Expanded HTTP file-analysis metadata."""

    file_transfers: tuple[FileTransferContext, ...]
    pe_analyses: tuple[PeContext, ...] = ()

    @property
    def file_transfer(self) -> FileTransferContext:
        """Return the first transfer for compatibility with ordinary entities."""

        if not self.file_transfers:
            raise ValueError("HTTP file-transfer result has no nonempty leaf")
        return self.file_transfers[0]

    @property
    def pe(self) -> PeContext | None:
        """Return the first PE analysis for compatibility with existing callers."""

        return self.pe_analyses[0] if self.pe_analyses else None


class HttpFileTransferActionBundle:
    """Build coordinated Zeek files.log metadata for an HTTP entity."""

    def __init__(
        self,
        request: HttpFileTransferRequest,
        rng: random.Random,
    ) -> None:
        self._request = request
        self._rng = rng

    @property
    def anchor(self) -> ActionAnchor:
        """Return the stable action anchor."""

        return ActionAnchor(
            family="http_file_transfer",
            stable_id=self._request.stable_id,
            source=self._request.source,
        )

    def execute(self) -> HttpFileTransferResult:
        """Return file-transfer metadata and optional PE analysis."""

        if self._request.multipart is not None:
            return self._execute_multipart(self._request.multipart)
        file_mime_type = self._request.mime_types[0] if self._request.mime_types else ""
        transfer, pe = self._build_transfer(
            body_len=self._request.body_len,
            file_mime_type=file_mime_type,
            filename=self._request.filename,
            content_seed_material=(
                self._request.content_identity
                or _http_content_seed_material(
                    self._request.host,
                    self._request.uri,
                    self._request.body_len,
                    file_mime_type,
                )
            ),
            total_bytes=self._request.body_len,
        )
        return HttpFileTransferResult(
            file_transfers=(transfer,),
            pe_analyses=(pe,) if pe is not None else (),
        )

    def _execute_multipart(self, multipart: HttpMultipartEntityContext) -> HttpFileTransferResult:
        """Return one file object per nonempty decoded multipart leaf."""

        spans = {span.part_path: span for span in multipart.wire_spans if span.kind == "leaf"}
        transfers: list[FileTransferContext] = []
        pe_analyses: list[PeContext] = []
        for part in multipart.leaf_parts():
            if part.decoded_size <= 0:
                continue
            span = spans.get(part.path)
            transfer, pe = self._build_transfer(
                body_len=part.decoded_size,
                file_mime_type=part.detected_mime_type,
                filename=part.wire_filename,
                content_seed_material=part.content_identity,
                total_bytes=part.declared_content_length,
                multipart_part_path=part.path,
                wire_offset=span.offset if span is not None else None,
                wire_length=span.length if span is not None else None,
                entity_body_len=multipart.body_len,
            )
            transfers.append(transfer)
            if pe is not None:
                pe_analyses.append(pe)
        return HttpFileTransferResult(
            file_transfers=tuple(transfers),
            pe_analyses=tuple(pe_analyses),
        )

    def _build_transfer(
        self,
        *,
        body_len: int,
        file_mime_type: str,
        filename: str,
        content_seed_material: str,
        total_bytes: int | None,
        multipart_part_path: tuple[int, ...] = (),
        wire_offset: int | None = None,
        wire_length: int | None = None,
        entity_body_len: int | None = None,
    ) -> tuple[FileTransferContext, PeContext | None]:
        """Build one decoded HTTP leaf and its optional analyzer result."""

        fuid = generate_zeek_uid_from_rng(self._rng, "F")
        analyzers = ["SHA1"] if file_mime_type in _HTTP_HASH_ANALYZER_MIME_TYPES else []
        file_hashes = file_transfer_hashes(content_seed_material, analyzers)
        file_transfer = FileTransferContext(
            fuid=fuid,
            source="HTTP",
            depth=0,
            filename=filename,
            analyzers=analyzers,
            mime_type=file_mime_type,
            duration=_http_response_file_duration(
                body_len,
                self._request.parent_duration,
                self._rng,
            ),
            local_orig=_is_private_ip(self._request.dst_ip),
            is_orig=self._request.is_orig,
            seen_bytes=body_len,
            total_bytes=total_bytes,
            missing_bytes=0,
            overflow_bytes=0,
            timedout=False,
            multipart_part_path=multipart_part_path,
            wire_offset=wire_offset,
            wire_length=wire_length,
            entity_body_len=entity_body_len,
            **file_hashes,
        )
        return (
            file_transfer,
            self._maybe_build_pe_context(
                fuid,
                file_mime_type,
                content_seed_material,
                body_len=body_len,
            ),
        )

    def _maybe_build_pe_context(
        self,
        fuid: str,
        mime_type: str,
        content_seed_material: str,
        *,
        body_len: int | None = None,
    ) -> PeContext | None:
        """Return content-scoped PE analysis for executable file transfers."""

        if not _http_pe_analysis_enabled(
            mime_type,
            content_seed_material,
            self._request.body_len if body_len is None else body_len,
        ):
            return None
        profile_rng = random.Random(_stable_seed(f"http_pe_profile:{content_seed_material}"))
        is_64 = _http_pe_is_64bit(self._request.uri, content_seed_material)
        return PeContext(
            id=fuid,
            machine="AMD64" if is_64 else "I386",
            compile_ts=_http_pe_compile_ts(content_seed_material, self._request.timestamp),
            is_exe=True,
            is_64bit=is_64,
            uses_aslr=profile_rng.random() < 0.88,
            uses_dep=profile_rng.random() < 0.95,
            uses_code_integrity=profile_rng.random() < 0.12,
            has_import_table=True,
            has_export_table=profile_rng.random() < 0.18,
            has_cert_table=profile_rng.random() < 0.72,
            has_debug_data=profile_rng.random() < 0.28,
            section_names=_PE_SECTION_PROFILES[
                _stable_seed(f"http_pe_sections:{content_seed_material}")
                % len(_PE_SECTION_PROFILES)
            ],
        )


@dataclass(frozen=True, slots=True)
class HttpResponseFileTransferRequest:
    """Backward-compatible response-side HTTP file-analysis intent."""

    host: str
    uri: str
    dst_ip: str
    response_body_len: int
    response_mime_types: list[str]
    timestamp: datetime
    multipart: HttpMultipartEntityContext | None = None
    content_identity: str = ""
    parent_duration: float | None = None
    source: str = "activity_generator"


HttpResponseFileTransferResult = HttpFileTransferResult


class HttpResponseFileTransferActionBundle:
    """Compatibility wrapper for callers constructing response transfers."""

    def __init__(self, request: HttpResponseFileTransferRequest, rng: random.Random) -> None:
        self._bundle = HttpFileTransferActionBundle(
            HttpFileTransferRequest(
                host=request.host,
                uri=request.uri,
                dst_ip=request.dst_ip,
                body_len=request.response_body_len,
                mime_types=tuple(request.response_mime_types),
                timestamp=request.timestamp,
                is_orig=False,
                multipart=request.multipart,
                content_identity=request.content_identity,
                parent_duration=request.parent_duration,
                source=request.source,
            ),
            rng,
        )

    @property
    def anchor(self) -> ActionAnchor:
        """Return the stable action anchor."""

        return self._bundle.anchor

    def execute(self) -> HttpFileTransferResult:
        """Return response-side file-transfer metadata."""

        return self._bundle.execute()


@dataclass(frozen=True, slots=True)
class _PlannedFileEffectOccurrence:
    """One immutable endpoint file occurrence owned by an exact process object."""

    node_id: str
    plan_action_id: str
    timestamp: datetime
    event_type: str
    system: System
    actor_username: str
    process_identity: ProcessIdentity
    process_image: str
    process_command_line: str
    process_username: str
    path: str
    action: FileEffectAction
    identity_plan: EventIdentityPlan


@dataclass(frozen=True, slots=True)
class StagedArchiveSmbReadExecutionPlan:
    """Frozen transfer, file, and optional process-close effects for staged SMB reads."""

    effects: ExecutionEffectPlan
    reconciliation: ExecutionEffectReconciliation
    transfer_bytes: int
    duration_seconds: float
    transfer_time: datetime
    ready_time: datetime
    share_ref: str
    relative_path: str
    exact_file: CompiledStorageFile
    source_process: ProcessIdentity | None
    reader_process: ProcessIdentity | None
    local_create: _PlannedFileEffectOccurrence | None
    source_read: _PlannedFileEffectOccurrence | None
    termination_time: datetime | None
    local_create_retention_deadline: datetime | None
    window_end: datetime


@dataclass(frozen=True, slots=True)
class ScpReceiverFileExecutionPlan:
    """Frozen tuple authority and endpoint effects for one modeled SCP upload."""

    effects: ExecutionEffectPlan
    reconciliation: ExecutionEffectReconciliation
    source_process: ProcessIdentity
    receiver_process: ProcessIdentity
    source_read: _PlannedFileEffectOccurrence
    receiver_create: _PlannedFileEffectOccurrence
    ssh_ready_time: datetime
    retention_deadline: datetime
    window_end: datetime


def _file_identity_plan_for_process(
    system: System,
    process: ProcessIdentity,
    path: str,
) -> EventIdentityPlan:
    """Freeze file subject and exact process actor identity during preflight."""

    semantic_key = f"{system.hostname}:{path.casefold()}"
    return EventIdentityPlan(
        subject=EntityIdentity(
            object_id=stable_uuid("file-identity", semantic_key),
            kind="file",
            hostname=system.hostname,
            semantic_key=semantic_key,
        ),
        actor=process,
    )


def _exclusive_effect_window_end(
    executor: FileTransferStorylineExecutor,
    fallback: datetime,
) -> datetime:
    """Return the earliest explicit exclusive output fence visible to the action."""

    candidates = [ensure_utc(fallback)]
    activity_end = getattr(executor.activity_generator, "_scenario_end_time", None)
    if isinstance(activity_end, datetime):
        candidates.append(ensure_utc(activity_end))
    dispatcher_end = getattr(executor.dispatcher, "output_end_time", None)
    if isinstance(dispatcher_end, datetime):
        candidates.append(ensure_utc(dispatcher_end))
    return min(candidates)


def _require_exact_process_identity(
    executor: FileTransferStorylineExecutor,
    *,
    system: System,
    pid: int,
    at_times: tuple[datetime, ...],
    purpose: str,
) -> ProcessIdentity:
    """Resolve one immutable process object and verify its complete activity interval."""

    identity = executor.state_manager.get_process_identity(system.hostname, pid)
    if (
        identity is None
        or identity.pid != pid
        or identity.hostname.casefold() != system.hostname.casefold()
    ):
        raise ExecutionEffectPlanError(
            ExecutionEffectPlanErrorCode.INVALID_ACTOR,
            f"{purpose} requires the exact process object for {system.hostname}:{pid}",
        )
    active_at = getattr(executor.state_manager, "is_process_active_at", None)
    if callable(active_at):
        inactive = next(
            (
                timestamp
                for timestamp in at_times
                if not active_at(system.hostname, pid, ensure_utc(timestamp))
            ),
            None,
        )
        if inactive is not None:
            raise ExecutionEffectPlanError(
                ExecutionEffectPlanErrorCode.INVALID_ACTOR,
                f"{purpose} process {identity.object_id!r} is not active at "
                f"{ensure_utc(inactive).isoformat()}",
            )
    elif any(ensure_utc(timestamp) < ensure_utc(identity.started_at) for timestamp in at_times):
        raise ExecutionEffectPlanError(
            ExecutionEffectPlanErrorCode.INVALID_ACTOR,
            f"{purpose} occurs before exact process {identity.object_id!r} starts",
        )
    return identity


def _file_effect_occurrence(
    *,
    node: ExecutionEffectNode,
    plan_action_id: str,
    timestamp: datetime,
    event_type: str,
    system: System,
    actor_username: str,
    process: ProcessIdentity,
    path: str,
    action: FileEffectAction,
    process_image: str = "",
    process_command_line: str = "",
    process_username: str = "",
) -> _PlannedFileEffectOccurrence:
    """Freeze one source-native file occurrence from its exact process binding."""

    return _PlannedFileEffectOccurrence(
        node_id=node.node_id,
        plan_action_id=plan_action_id,
        timestamp=ensure_utc(timestamp),
        event_type=event_type,
        system=system,
        actor_username=actor_username,
        process_identity=process,
        process_image=process_image or process.image,
        process_command_line=process_command_line or process.command_line or process.image,
        process_username=process_username or process.principal or actor_username,
        path=path,
        action=action,
        identity_plan=_file_identity_plan_for_process(system, process, path),
    )


def _build_file_occurrence(
    executor: FileTransferStorylineExecutor,
    plan: _PlannedFileEffectOccurrence,
    *,
    artifact_publication: LocalArtifactPublishToken | None = None,
) -> OccurrenceBuilder:
    """Build one canonical file occurrence from a fully reconciled immutable plan."""

    process = plan.process_identity
    record = artifact_publication.record if artifact_publication is not None else None
    if record is None:
        manager = getattr(executor.activity_generator, "_runtime_content_manager", None)
        platform = _system_platform(plan.system)
        if isinstance(manager, RuntimeContentIdentityManager) and platform is not None:
            record = manager.resolve_record(
                plan.system.hostname,
                plan.process_username,
                plan.path,
                platform,
            )
    return OccurrenceBuilder(
        timestamp=plan.timestamp,
        event_type=plan.event_type,
        src_host=executor.activity_generator._build_host_context(plan.system),
        auth=AuthContext(username=plan.actor_username),
        process=ProcessContext(
            pid=process.pid,
            parent_pid=process.parent_pid,
            image=plan.process_image,
            command_line=plan.process_command_line,
            username=plan.process_username,
        ),
        file=FileContext(
            path=plan.path,
            action=plan.action.value,
            pid=process.pid,
            artifact_identity=record.artifact if record is not None else None,
            content_identity=record.content if record is not None else None,
        ),
        identity_plan=plan.identity_plan,
        effect_provenance=EffectOccurrenceProvenance.planned(
            kind=EffectOccurrenceKind.FILE,
            root_action_id=plan.plan_action_id,
            plan_action_id=plan.plan_action_id,
            node_id=plan.node_id,
            occurrence_ordinal=0,
        ),
        storyline_origin=True,
    )


def _system_platform(system: System) -> Literal["windows", "linux", "macos"] | None:
    """Return the exact supported runtime-content platform for one scenario host."""

    normalized = system.os.casefold()
    if "windows" in normalized:
        return "windows"
    if any(value in normalized for value in ("macos", "mac os", "darwin")):
        return "macos"
    if any(
        value in normalized
        for value in ("linux", "ubuntu", "debian", "centos", "rhel", "fedora", "suse")
    ):
        return "linux"
    return None


def _prepare_runtime_file_artifact(
    executor: FileTransferStorylineExecutor,
    plan: _PlannedFileEffectOccurrence,
    *,
    root_action_id: str,
    stable_source_id: str,
    canonical_content: FileContentIdentity | None = None,
) -> LocalArtifactPublishToken | None:
    """Prepare one file-transfer placement before endpoint publication mutates state."""

    manager = getattr(executor.activity_generator, "_runtime_content_manager", None)
    platform = _system_platform(plan.system)
    if not isinstance(manager, RuntimeContentIdentityManager) or platform is None:
        return None
    system_principals = {
        "root",
        "system",
        "localsystem",
        "local system",
        "nt authority\\system",
    }
    principal = plan.process_username
    return manager.prepare_effect_publication(
        root_action_id=root_action_id,
        stable_source_id=stable_source_id,
        hostname=plan.system.hostname,
        principal=principal,
        platform=platform,
        architecture=plan.system.architecture,
        native_path=plan.path,
        action=plan.action.value,
        observed_at=plan.timestamp,
        owner_kind="system" if principal.casefold() in system_principals else "user",
        deployment_registry=getattr(executor.dispatcher, "deployment_registry", None),
        actor_image=plan.process_image,
        authored_size_bytes=(
            canonical_content.size_bytes if canonical_content is not None else None
        ),
        authored_mime_type=(canonical_content.mime_type if canonical_content is not None else ""),
        authored_file_object_id=(
            canonical_content.file_object_id if canonical_content is not None else ""
        ),
        authored_content_seed_ref=(
            canonical_content.seed_ref if canonical_content is not None else ""
        ),
        content_version=(canonical_content.version if canonical_content is not None else 1),
    )


def _publish_prepared_file_occurrences(
    executor: FileTransferStorylineExecutor,
    planned: tuple[
        tuple[_PlannedFileEffectOccurrence, LocalArtifactPublishToken | None],
        ...,
    ],
) -> None:
    """Publish prepared file projections, then commit every artifact token last."""

    publication_list: list[LocalArtifactPublishToken] = []
    seen_reservations: set[int] = set()
    for _occurrence, publication in planned:
        if publication is None or id(publication) in seen_reservations:
            continue
        seen_reservations.add(id(publication))
        publication_list.append(publication)
    publications = tuple(publication_list)
    registry = (
        getattr(executor.activity_generator, "_runtime_content_manager", None)
        if publications
        else None
    )
    prepare_builder = getattr(executor.dispatcher, "prepare_builder", None)
    publish_prepared = getattr(executor.dispatcher, "publish_prepared", None)
    if not callable(prepare_builder) or not callable(publish_prepared):
        if publications:
            raise ExecutionEffectPlanError(
                ExecutionEffectPlanErrorCode.INVALID_PLAN,
                "runtime artifact publication requires prepared dispatcher support",
            )
        for occurrence, publication in planned:
            executor.dispatcher.dispatch_builder(
                _build_file_occurrence(
                    executor,
                    occurrence,
                    artifact_publication=publication,
                )
            )
        return
    with ExitStack() as stack:
        commits = (
            tuple(
                stack.enter_context(registry.registry.prepared_publication(publication))
                for publication in publications
            )
            if isinstance(registry, RuntimeContentIdentityManager)
            else ()
        )
        prepared_dispatches = tuple(
            prepare_builder(
                _build_file_occurrence(
                    executor,
                    occurrence,
                    artifact_publication=publication,
                )
            )
            for occurrence, publication in planned
        )
        for prepared in prepared_dispatches:
            publish_prepared(prepared)
        for commit in commits:
            commit.commit()


def _reconcile_exact_effects(
    effects: ExecutionEffectPlan,
    outcomes: tuple[EffectExecutionOutcome, ...],
) -> ExecutionEffectReconciliation:
    """Require exactly one cardinality-complete outcome for every effect node."""

    outcome_by_id = {outcome.node_id: outcome for outcome in outcomes}
    for node in effects.nodes:
        outcome = outcome_by_id.get(node.node_id)
        if outcome is None:
            continue
        if outcome.status in {EffectOutcomeStatus.REALIZED, EffectOutcomeStatus.LINKED} and (
            outcome.canonical_occurrence_count != node.intent.occurrence_cardinality
        ):
            raise ExecutionEffectPlanError(
                ExecutionEffectPlanErrorCode.RECONCILIATION_INCOMPLETE,
                "file-transfer effect outcome must report exact canonical cardinality",
                node_id=node.node_id,
            )
    reconciliation = effects.reconcile(outcomes)
    reconciliation.require_complete()
    return reconciliation


def _record_effect_reconciliation(
    executor: FileTransferStorylineExecutor,
    reconciliation: ExecutionEffectReconciliation,
) -> None:
    """Record count-only effect audit data when the production executor exposes it."""

    audit = getattr(executor.activity_generator, "_execution_effect_audit", None)
    record = getattr(audit, "record", None)
    if callable(record):
        record(reconciliation)


class FileTransferStorylineExecutor(Protocol):
    """Adapter protocol implemented by the storyline engine."""

    activity_generator: Any
    dispatcher: Any
    state_manager: StateManager


@dataclass(frozen=True, slots=True)
class StagedArchiveSmbReadRequest:
    """Intent for one SMB read that moves a staged archive before exfiltration."""

    actor: User
    source_ip: str
    staging_ip: str
    archive_path: str
    smb_filename: str
    staged_at: datetime
    exfil_time: datetime
    upload_bytes: int
    source_system: System | None
    target_system: System
    source_pid: int = -1
    source_process: str = ""
    source_command: str = ""
    source_logon_id: str = ""
    terminate_source_process: bool = False
    reader_pid: int = -1
    reader_process: str = ""
    reader_command: str = ""
    source_file_read_path: str = ""
    source: str = "storyline_staged_archive"

    @property
    def stable_id(self) -> str:
        """Return a deterministic intent identifier for durable references."""

        seed = _stable_seed(
            "action_bundle:staged_archive_smb_read:"
            f"{self.actor.username}:{self.source_ip}:{self.staging_ip}:"
            f"{self.archive_path}:{self.smb_filename}:{self.staged_at.isoformat()}:"
            f"{self.exfil_time.isoformat()}:{self.upload_bytes}:"
            f"{self.source_pid}:{self.reader_pid}:{self.source_file_read_path}:"
            f"{self.source}"
        )
        return f"staged-archive-smb-read-{seed:016x}"


class StagedArchiveSmbReadActionBundle:
    """Emit SMB network file-analysis evidence for a staged archive read."""

    def __init__(
        self,
        executor: FileTransferStorylineExecutor,
        request: StagedArchiveSmbReadRequest,
        rng: random.Random,
    ) -> None:
        self._executor = executor
        self._request = request
        self._rng = rng
        runtime = getattr(getattr(executor, "activity_generator", None), "timing_runtime", None)
        self._timing_runtime = (
            runtime if isinstance(runtime, TimingRuntime) else TimingRuntime.compatibility_default()
        )
        self._planned = False
        self._execution_plan: StagedArchiveSmbReadExecutionPlan | None = None

    @property
    def anchor(self) -> ActionAnchor:
        """Return the stable action anchor."""

        return ActionAnchor(
            family="staged_archive_smb_read",
            stable_id=self._request.stable_id,
            source=self._request.source,
        )

    def _clamp_after_source_process(
        self,
        transfer_time: datetime,
        duration: float,
    ) -> datetime | None:
        """Keep source-visible SMB transfer after the upload process exists."""

        if self._request.source_system is None or self._request.source_pid <= 0:
            return transfer_time
        source_time_getter = getattr(
            self._executor.activity_generator,
            "process_source_create_time",
            None,
        )
        if not callable(source_time_getter):
            return transfer_time
        source_process_time = source_time_getter(
            self._request.source_system.hostname,
            self._request.source_pid,
        )
        if not isinstance(source_process_time, datetime) or transfer_time > source_process_time:
            return transfer_time

        latest = self._request.exfil_time - timedelta(seconds=duration + 5.0)
        candidate = source_process_time + _sample_transfer_gap(
            self._timing_runtime,
            relationship_key="file_transfer.staged_smb.source_process_ready_gap",
            stable_id=self._request.stable_id,
            host=self._request.source_system.hostname,
            lifecycle_id=self.anchor.action_id,
            sample_key="source_process_ready",
            minimum_ms=350,
            mode_ms=620,
            maximum_ms=1400,
        )
        if candidate >= latest:
            return None
        return candidate

    def _source_file_read_path(self) -> str:
        """Return the upload-host path read by the source process."""

        return self._request.source_file_read_path or self._request.smb_filename

    def _reader_pid(self) -> int:
        """Return the process that reads the local staged file for upload."""

        return (
            self._request.reader_pid if self._request.reader_pid > 0 else self._request.source_pid
        )

    def _reader_process(self) -> str:
        """Return the image that reads the local staged file for upload."""

        return self._request.reader_process or self._request.source_process

    def _reader_command(self) -> str:
        """Return the command line that reads the local staged file for upload."""

        return self._request.reader_command or self._request.source_command

    def _transfer_time(self, duration: float) -> datetime | None:
        """Return a transfer time between archive staging and upload."""

        gap_seconds = _sample_transfer_value(
            self._timing_runtime,
            relationship_key="file_transfer.staged_smb.pre_exfil_gap",
            stable_id=self._request.stable_id,
            host=self._request.target_system.hostname,
            lifecycle_id=self.anchor.action_id,
            sample_key="pre_exfil_gap",
            minimum=20.0,
            mode=64.0,
            maximum=180.0,
        )
        transfer_time = self._request.exfil_time - timedelta(seconds=duration + gap_seconds)
        earliest_delay = _sample_transfer_value(
            self._timing_runtime,
            relationship_key="file_transfer.staged_smb.post_stage_gap",
            stable_id=self._request.stable_id,
            host=self._request.target_system.hostname,
            lifecycle_id=self.anchor.action_id,
            sample_key="post_stage_gap",
            minimum=20.0,
            mode=58.0,
            maximum=180.0,
        )
        earliest = self._request.staged_at + timedelta(seconds=earliest_delay)
        if transfer_time >= earliest:
            return transfer_time
        latest = self._request.exfil_time - timedelta(seconds=duration + 5.0)
        if latest <= earliest:
            return None
        span = (latest - earliest).total_seconds()
        offset = _sample_transfer_value(
            self._timing_runtime,
            relationship_key="file_transfer.staged_smb.admissible_interval_offset",
            stable_id=self._request.stable_id,
            host=self._request.target_system.hostname,
            lifecycle_id=self.anchor.action_id,
            sample_key="admissible_interval_offset",
            minimum=0.0,
            mode=span * 0.36,
            maximum=span,
        )
        return earliest + timedelta(seconds=offset)

    def plan_execution(self) -> StagedArchiveSmbReadExecutionPlan | None:
        """Freeze all admitted effects without allocating channel or endpoint state."""

        if not self._planned:
            self._execution_plan = self._build_execution_plan()
            self._planned = True
        return self._execution_plan

    def execute(self) -> bool:
        """Emit one all-or-none staged archive transfer after exact reconciliation."""

        plan = self.plan_execution()
        if plan is None:
            return False

        canonical_content = FileContentIdentity(
            file_object_id=plan.exact_file.file_id,
            version=plan.exact_file.version,
            size_bytes=plan.exact_file.size_bytes,
            mime_type=plan.exact_file.mime_type,
            seed_ref=plan.exact_file.seed_ref or plan.exact_file.file_id,
        )
        local_publication = (
            _prepare_runtime_file_artifact(
                self._executor,
                plan.local_create,
                root_action_id=self.anchor.action_id,
                stable_source_id=canonical_content.file_object_id,
                canonical_content=canonical_content,
            )
            if plan.local_create is not None
            else None
        )

        from evidenceforge.models.scenario import (
            SmbActivityEventSpec,
            SmbClientLocation,
            SmbExternalClient,
            SmbShareLocation,
        )

        external = (
            None
            if self._request.source_system is not None
            else SmbExternalClient(type="external", ip=self._request.source_ip)
        )
        runtime_manager = getattr(
            self._executor.activity_generator,
            "_runtime_content_manager",
            None,
        )
        with ExitStack() as publication_stack:
            artifact_commit = (
                publication_stack.enter_context(
                    runtime_manager.registry.prepared_publication(local_publication)
                )
                if local_publication is not None
                and isinstance(runtime_manager, RuntimeContentIdentityManager)
                else None
            )
            result = self._executor.activity_generator.generate_smb_activity(
                spec=SmbActivityEventSpec(
                    type="smb_activity",
                    client=external,
                    operation="copy",
                    purpose="collection",
                    source=SmbShareLocation(
                        type="share",
                        share=plan.share_ref,
                        path=plan.relative_path,
                    ),
                    destination=SmbClientLocation(
                        type="client",
                        path=self._request.source_file_read_path or None,
                    ),
                ),
                actor=self._request.actor,
                parent_system=self._request.source_system or self._request.target_system,
                time=plan.transfer_time,
                process_pid=self._request.source_pid,
                process_image=self._request.source_process,
                files_override=(plan.exact_file,),
            )
            if not (
                str(getattr(result, "session_id", ""))
                or tuple(getattr(result, "transport_uids", ()))
            ):
                return False

            file_occurrences: list[
                tuple[_PlannedFileEffectOccurrence, LocalArtifactPublishToken | None]
            ] = []
            if plan.local_create is not None:
                file_occurrences.append((plan.local_create, local_publication))
            if plan.source_read is not None:
                file_occurrences.append((plan.source_read, local_publication))
            prepare_builder = getattr(self._executor.dispatcher, "prepare_builder", None)
            publish_prepared = getattr(self._executor.dispatcher, "publish_prepared", None)
            if callable(prepare_builder) and callable(publish_prepared):
                prepared_dispatches = tuple(
                    prepare_builder(
                        _build_file_occurrence(
                            self._executor,
                            occurrence,
                            artifact_publication=publication,
                        )
                    )
                    for occurrence, publication in file_occurrences
                )
                for prepared in prepared_dispatches:
                    publish_prepared(prepared)
            elif local_publication is not None:
                raise ExecutionEffectPlanError(
                    ExecutionEffectPlanErrorCode.INVALID_PLAN,
                    "runtime artifact publication requires prepared dispatcher support",
                )
            else:
                for occurrence, publication in file_occurrences:
                    self._executor.dispatcher.dispatch_builder(
                        _build_file_occurrence(
                            self._executor,
                            occurrence,
                            artifact_publication=publication,
                        )
                    )
            if artifact_commit is not None:
                artifact_commit.commit()
        if plan.termination_time is not None and plan.source_process is not None:
            self._executor.activity_generator.generate_process_termination(
                user=self._request.actor,
                system=self._request.source_system,
                time=plan.termination_time,
                pid=plan.source_process.pid,
                process_name=plan.source_process.image,
                logon_id=self._request.source_logon_id,
                from_storyline=True,
            )
        _record_effect_reconciliation(self._executor, plan.reconciliation)
        return True

    def _build_execution_plan(self) -> StagedArchiveSmbReadExecutionPlan | None:
        """Preflight exact SMB inputs, process bindings, timestamps, and cardinality."""

        if self._request.upload_bytes < 1_000_000:
            return None
        if not self._request.source_ip or not self._request.smb_filename:
            raise ExecutionEffectPlanError(
                ExecutionEffectPlanErrorCode.INVALID_INTENT,
                "staged SMB transfer requires source IP and canonical SMB filename",
            )

        transfer_bytes = max(
            32_768,
            self._request.upload_bytes
            - self._rng.randint(
                4096,
                max(4096, min(self._request.upload_bytes // 180, 2_000_000)),
            ),
        )
        throughput = _sample_transfer_value(
            self._timing_runtime,
            relationship_key="file_transfer.staged_smb.throughput",
            stable_id=self._request.stable_id,
            host=self._request.target_system.hostname,
            lifecycle_id=self.anchor.action_id,
            sample_key="throughput",
            minimum=18_000_000.0,
            mode=42_000_000.0,
            maximum=85_000_000.0,
        )
        transfer_overhead = _sample_transfer_value(
            self._timing_runtime,
            relationship_key="file_transfer.staged_smb.transfer_overhead",
            stable_id=self._request.stable_id,
            host=self._request.target_system.hostname,
            lifecycle_id=self.anchor.action_id,
            sample_key="transfer_overhead",
            minimum=0.5,
            mode=1.8,
            maximum=6.0,
        )
        duration = max(
            3.0,
            min(180.0, transfer_bytes / throughput + transfer_overhead),
        )
        transfer_time = self._transfer_time(duration)
        if transfer_time is None:
            return None
        transfer_time = self._clamp_after_source_process(transfer_time, duration)
        if transfer_time is None:
            return None
        transfer_time = ensure_utc(transfer_time)
        ready_time = transfer_time + timedelta(seconds=duration)
        window_end = _exclusive_effect_window_end(self._executor, self._request.exfil_time)
        if ready_time >= window_end:
            return None

        world = self._executor.activity_generator._storage_world
        server_shares = [
            share
            for share in world.shares
            if share.system.casefold() == self._request.target_system.hostname.casefold()
        ]
        if not server_shares:
            return None
        unc_parts = [
            part for part in self._request.smb_filename.replace("/", "\\").split("\\") if part
        ]
        share_name = unc_parts[1] if len(unc_parts) > 2 else ""
        share = next(
            (
                candidate
                for candidate in server_shares
                if candidate.name.casefold() == share_name.casefold()
            ),
            server_shares[0],
        )
        relative_path = (
            "\\".join(unc_parts[2:]) if len(unc_parts) > 2 else self._request.archive_path
        )
        from evidenceforge.generation.storage_world import CompiledStorageFile

        exact_file = CompiledStorageFile(
            file_id=stable_uuid(
                "staged-archive-file",
                share.ref,
                relative_path,
                self._request.archive_path,
            ),
            share=share.ref,
            path=relative_path,
            size_bytes=transfer_bytes,
            mime_type="application/zip",
            tags=("staged_archive",),
        )

        source_process = self._plan_source_process_identity(transfer_time, ready_time)
        source_path = self._source_file_read_path()
        local_create_time = self._plan_source_local_create_time(
            ready_time,
            source_process,
            source_path,
        )
        termination_time = self._plan_source_termination_time(
            ready_time,
            local_create_time,
            source_process,
        )
        reader_process = self._plan_reader_process_identity(ready_time)
        source_read_time = self._plan_source_read_time(
            ready_time,
            local_create_time,
            reader_process,
            source_path,
        )
        if termination_time is not None and source_read_time is not None:
            termination_time = max(
                termination_time,
                source_read_time + timedelta(milliseconds=1),
            )
        admitted_times = tuple(
            timestamp
            for timestamp in (local_create_time, source_read_time, termination_time)
            if timestamp is not None
        )
        if any(timestamp >= window_end for timestamp in admitted_times):
            return None

        if source_process is not None:
            source_process = _require_exact_process_identity(
                self._executor,
                system=self._request.source_system,
                pid=source_process.pid,
                at_times=(transfer_time, ready_time, *admitted_times),
                purpose="staged SMB source",
            )
        if reader_process is not None:
            reader_process = _require_exact_process_identity(
                self._executor,
                system=self._request.source_system,
                pid=reader_process.pid,
                at_times=tuple(
                    timestamp
                    for timestamp in (ready_time, source_read_time)
                    if timestamp is not None
                ),
                purpose="staged SMB reader",
            )

        effects, local_create, source_read, reconciliation = self._plan_effect_graph(
            source_process=source_process,
            reader_process=reader_process,
            source_path=source_path,
            transfer_time=transfer_time,
            ready_time=ready_time,
            local_create_time=local_create_time,
            source_read_time=source_read_time,
            termination_time=termination_time,
        )
        return StagedArchiveSmbReadExecutionPlan(
            effects=effects,
            reconciliation=reconciliation,
            transfer_bytes=transfer_bytes,
            duration_seconds=duration,
            transfer_time=transfer_time,
            ready_time=ready_time,
            share_ref=share.ref,
            relative_path=relative_path,
            exact_file=exact_file,
            source_process=source_process,
            reader_process=reader_process,
            local_create=local_create,
            source_read=source_read,
            termination_time=termination_time,
            local_create_retention_deadline=(window_end if local_create is not None else None),
            window_end=window_end,
        )

    def _plan_source_process_identity(
        self,
        transfer_time: datetime,
        ready_time: datetime,
    ) -> ProcessIdentity | None:
        """Resolve the exact optional SMB client process without creating one."""

        if (
            self._request.source_system is None
            or self._request.source_pid <= 0
            or not self._request.source_process
        ):
            if self._request.terminate_source_process:
                raise ExecutionEffectPlanError(
                    ExecutionEffectPlanErrorCode.INVALID_ACTOR,
                    "staged SMB process closure requires an exact source process",
                )
            return None
        return _require_exact_process_identity(
            self._executor,
            system=self._request.source_system,
            pid=self._request.source_pid,
            at_times=(transfer_time, ready_time),
            purpose="staged SMB source",
        )

    def _plan_source_local_create_time(
        self,
        ready_time: datetime,
        source_process: ProcessIdentity | None,
        source_path: str,
    ) -> datetime | None:
        """Plan local staging creation without dispatching endpoint state."""

        if source_process is None or not source_path or source_path == self._request.smb_filename:
            return None
        file_time = ready_time + _sample_transfer_gap(
            self._timing_runtime,
            relationship_key="file_transfer.staged_smb.local_create_after_ready",
            stable_id=self._request.stable_id,
            host=self._request.source_system.hostname,
            lifecycle_id=self.anchor.action_id,
            sample_key="local_create",
            minimum_ms=80,
            mode_ms=130,
            maximum_ms=240,
        )
        source_time_getter = getattr(
            self._executor.activity_generator,
            "process_source_create_time",
            None,
        )
        if callable(source_time_getter):
            source_process_time = source_time_getter(
                self._request.source_system.hostname,
                source_process.pid,
            )
            if isinstance(source_process_time, datetime) and file_time <= source_process_time:
                file_time = source_process_time + _sample_transfer_gap(
                    self._timing_runtime,
                    relationship_key="file_transfer.staged_smb.local_create_process_repair",
                    stable_id=self._request.stable_id,
                    host=self._request.source_system.hostname,
                    lifecycle_id=self.anchor.action_id,
                    sample_key="local_create_process_repair",
                    minimum_ms=180,
                    mode_ms=280,
                    maximum_ms=500,
                )
        return ensure_utc(file_time)

    def _plan_source_termination_time(
        self,
        ready_time: datetime,
        not_before: datetime | None,
        source_process: ProcessIdentity | None,
    ) -> datetime | None:
        """Plan the explicit close for a bundle-created staging process."""

        if not self._request.terminate_source_process:
            return None
        if source_process is None or not self._request.source_logon_id:
            raise ExecutionEffectPlanError(
                ExecutionEffectPlanErrorCode.INVALID_ACTOR,
                "staged SMB process closure requires exact process and session identities",
            )
        terminate = getattr(self._executor.activity_generator, "generate_process_termination", None)
        if not callable(terminate):
            raise ExecutionEffectPlanError(
                ExecutionEffectPlanErrorCode.INVALID_PLAN,
                "staged SMB process closure executor is unavailable",
            )
        termination_time = ready_time + _sample_transfer_gap(
            self._timing_runtime,
            relationship_key="file_transfer.staged_smb.termination_after_ready",
            stable_id=self._request.stable_id,
            host=self._request.source_system.hostname,
            lifecycle_id=self.anchor.action_id,
            sample_key="termination",
            minimum_ms=650,
            mode_ms=980,
            maximum_ms=2100,
        )
        if not_before is not None and termination_time <= not_before:
            termination_time = not_before + _sample_transfer_gap(
                self._timing_runtime,
                relationship_key="file_transfer.staged_smb.termination_dependency_repair",
                stable_id=self._request.stable_id,
                host=self._request.source_system.hostname,
                lifecycle_id=self.anchor.action_id,
                sample_key="termination_dependency_repair",
                minimum_ms=300,
                mode_ms=470,
                maximum_ms=900,
            )
        return ensure_utc(termination_time)

    def _plan_reader_process_identity(self, ready_time: datetime) -> ProcessIdentity | None:
        """Resolve the exact process that reads the staged local path."""

        if (
            self._request.source_system is None
            or self._reader_pid() <= 0
            or not self._reader_process()
        ):
            return None
        return _require_exact_process_identity(
            self._executor,
            system=self._request.source_system,
            pid=self._reader_pid(),
            at_times=(ready_time,),
            purpose="staged SMB reader",
        )

    def _plan_source_read_time(
        self,
        ready_time: datetime,
        not_before: datetime | None,
        reader_process: ProcessIdentity | None,
        source_path: str,
    ) -> datetime | None:
        """Plan upload-host FILE/READ timing without partial dispatch."""

        if reader_process is None or not source_path:
            return None
        file_time = ready_time + _sample_transfer_gap(
            self._timing_runtime,
            relationship_key="file_transfer.staged_smb.source_read_after_ready",
            stable_id=self._request.stable_id,
            host=self._request.source_system.hostname,
            lifecycle_id=self.anchor.action_id,
            sample_key="source_read",
            minimum_ms=420,
            mode_ms=690,
            maximum_ms=1400,
        )
        source_time_getter = getattr(
            self._executor.activity_generator,
            "process_source_create_time",
            None,
        )
        if callable(source_time_getter):
            source_process_time = source_time_getter(
                self._request.source_system.hostname,
                reader_process.pid,
            )
            if isinstance(source_process_time, datetime) and file_time <= source_process_time:
                file_time = source_process_time + _sample_transfer_gap(
                    self._timing_runtime,
                    relationship_key="file_transfer.staged_smb.source_read_process_repair",
                    stable_id=self._request.stable_id,
                    host=self._request.source_system.hostname,
                    lifecycle_id=self.anchor.action_id,
                    sample_key="source_read_process_repair",
                    minimum_ms=250,
                    mode_ms=430,
                    maximum_ms=950,
                )
        if not_before is not None and file_time <= not_before:
            file_time = not_before + _sample_transfer_gap(
                self._timing_runtime,
                relationship_key="file_transfer.staged_smb.source_read_dependency_repair",
                stable_id=self._request.stable_id,
                host=self._request.source_system.hostname,
                lifecycle_id=self.anchor.action_id,
                sample_key="source_read_dependency_repair",
                minimum_ms=120,
                mode_ms=260,
                maximum_ms=620,
            )
        return ensure_utc(file_time)

    def _plan_effect_graph(
        self,
        *,
        source_process: ProcessIdentity | None,
        reader_process: ProcessIdentity | None,
        source_path: str,
        transfer_time: datetime,
        ready_time: datetime,
        local_create_time: datetime | None,
        source_read_time: datetime | None,
        termination_time: datetime | None,
    ) -> tuple[
        ExecutionEffectPlan,
        _PlannedFileEffectOccurrence | None,
        _PlannedFileEffectOccurrence | None,
        ExecutionEffectReconciliation,
    ]:
        """Build the immutable effect DAG and exact prepared reconciliation."""

        anchor = self.anchor
        nodes: list[ExecutionEffectNode] = []
        outcomes: list[EffectExecutionOutcome] = []
        process_nodes: dict[str, ExecutionEffectNode] = {}
        for instance_key, process in (
            ("source_process", source_process),
            ("reader_process", reader_process),
        ):
            if process is None or process.object_id in process_nodes:
                continue
            node = ExecutionEffectNode.create(
                anchor,
                ChildProcessEffectIntent(
                    image=process.image,
                    command_line=process.command_line or process.image,
                ),
                role=OccurrenceRole.PREREQUISITE,
                requirement=EffectRequirement.EXTERNALLY_OWNED,
                actor=EffectActorRef.system(),
                instance_key=instance_key,
            )
            process_nodes[process.object_id] = node
            nodes.append(node)
            outcomes.append(
                EffectExecutionOutcome(
                    node_id=node.node_id,
                    status=EffectOutcomeStatus.LINKED,
                    child_action_id=process.object_id,
                    completed_at=transfer_time,
                    canonical_occurrence_count=1,
                )
            )

        source_node = process_nodes.get(source_process.object_id) if source_process else None
        reader_node = process_nodes.get(reader_process.object_id) if reader_process else None
        transfer_node = ExecutionEffectNode.create(
            anchor,
            TransferEffectIntent(
                protocol="smb",
                source_path=self._request.smb_filename,
                destination=self._request.source_ip,
                destination_path=source_path or self._request.smb_filename,
            ),
            actor=(
                EffectActorRef.effect_process(source_node.node_id)
                if source_node is not None
                else EffectActorRef.system()
            ),
            depends_on=tuple(
                sorted(
                    node.node_id
                    for node in (reader_node,)
                    if node is not None and node is not source_node
                )
            ),
            instance_key="smb_transfer",
        )
        nodes.append(transfer_node)
        outcomes.append(
            EffectExecutionOutcome(
                node_id=transfer_node.node_id,
                status=EffectOutcomeStatus.REALIZED,
                completed_at=ready_time,
                canonical_occurrence_count=1,
            )
        )

        local_create: _PlannedFileEffectOccurrence | None = None
        if local_create_time is not None and source_process is not None and source_node is not None:
            local_node = ExecutionEffectNode.create(
                anchor,
                FileEffectIntent(action=FileEffectAction.CREATE, path=source_path),
                actor=EffectActorRef.effect_process(source_node.node_id),
                depends_on=(transfer_node.node_id,),
                instance_key="local_staging_create",
            )
            nodes.append(local_node)
            local_create = _file_effect_occurrence(
                node=local_node,
                plan_action_id=anchor.action_id,
                timestamp=local_create_time,
                event_type="file_create",
                system=self._request.source_system,
                actor_username=self._request.actor.username,
                process=source_process,
                process_image=self._request.source_process,
                process_command_line=(self._request.source_command or self._request.source_process),
                process_username=self._request.actor.username,
                path=source_path,
                action=FileEffectAction.CREATE,
            )
            outcomes.append(
                EffectExecutionOutcome(
                    node_id=local_node.node_id,
                    status=EffectOutcomeStatus.REALIZED,
                    completed_at=local_create_time,
                    canonical_occurrence_count=1,
                )
            )

        source_read: _PlannedFileEffectOccurrence | None = None
        if source_read_time is not None and reader_process is not None and reader_node is not None:
            read_dependencies = [transfer_node.node_id]
            if local_create is not None:
                read_dependencies.append(local_create.node_id)
            read_node = ExecutionEffectNode.create(
                anchor,
                FileEffectIntent(action=FileEffectAction.READ, path=source_path),
                actor=EffectActorRef.effect_process(reader_node.node_id),
                depends_on=tuple(sorted(read_dependencies)),
                instance_key="source_file_read",
            )
            nodes.append(read_node)
            source_read = _file_effect_occurrence(
                node=read_node,
                plan_action_id=anchor.action_id,
                timestamp=source_read_time,
                event_type="file_read",
                system=self._request.source_system,
                actor_username=self._request.actor.username,
                process=reader_process,
                process_image=self._reader_process(),
                process_command_line=self._reader_command() or self._reader_process(),
                process_username=self._request.actor.username,
                path=source_path,
                action=FileEffectAction.READ,
            )
            outcomes.append(
                EffectExecutionOutcome(
                    node_id=read_node.node_id,
                    status=EffectOutcomeStatus.REALIZED,
                    completed_at=source_read_time,
                    canonical_occurrence_count=1,
                )
            )

        if termination_time is not None and source_process is not None and source_node is not None:
            closure_dependencies = [transfer_node.node_id]
            if local_create is not None:
                closure_dependencies.append(local_create.node_id)
            if source_read is not None and reader_process == source_process:
                closure_dependencies.append(source_read.node_id)
            closure_node = ExecutionEffectNode.create(
                anchor,
                ChildProcessEffectIntent(
                    image=source_process.image,
                    command_line=source_process.command_line or source_process.image,
                ),
                role=OccurrenceRole.CLOSURE,
                actor=EffectActorRef.effect_process(source_node.node_id),
                depends_on=tuple(sorted(closure_dependencies)),
                instance_key="source_process_close",
            )
            nodes.append(closure_node)
            outcomes.append(
                EffectExecutionOutcome(
                    node_id=closure_node.node_id,
                    status=EffectOutcomeStatus.REALIZED,
                    completed_at=termination_time,
                    canonical_occurrence_count=1,
                )
            )

        effects = ExecutionEffectPlan(anchor=anchor, nodes=tuple(nodes))
        reconciliation = _reconcile_exact_effects(effects, tuple(outcomes))
        return effects, local_create, source_read, reconciliation


@dataclass(frozen=True, slots=True)
class ScpReceiverFileRequest:
    """Intent for the receiver-side file-system evidence from a modeled SCP transfer."""

    source_system: System
    target_system: System
    actor: User
    source_pid: int
    source_process: str
    source_command: str
    source_path: str
    target_user: str
    target_path: str
    transfer_time: datetime
    source_port: int
    source: str = "storyline_scp_receiver"

    @property
    def stable_id(self) -> str:
        """Return a deterministic intent identifier for durable references."""

        seed = _stable_seed(
            "action_bundle:scp_receiver_file:"
            f"{self.actor.username}:{self.source_system.hostname}:{self.target_system.hostname}:"
            f"{self.source_pid}:{self.source_process}:{self.source_command}:"
            f"{self.source_path}:{self.target_user}:{self.target_path}:{self.transfer_time.isoformat()}:"
            f"{self.source_port}:{self.source}"
        )
        return f"scp-receiver-file-{seed:016x}"


class ScpReceiverFileActionBundle:
    """Emit receiver-side endpoint file evidence for a modeled SCP transfer."""

    def __init__(
        self,
        executor: FileTransferStorylineExecutor,
        request: ScpReceiverFileRequest,
        rng: random.Random,
    ) -> None:
        self._executor = executor
        self._request = request
        self._rng = rng
        runtime = getattr(getattr(executor, "activity_generator", None), "timing_runtime", None)
        self._timing_runtime = (
            runtime if isinstance(runtime, TimingRuntime) else TimingRuntime.compatibility_default()
        )
        self._planned = False
        self._execution_plan: ScpReceiverFileExecutionPlan | None = None

    @property
    def anchor(self) -> ActionAnchor:
        """Return the stable action anchor."""

        return ActionAnchor(
            family="scp_receiver_file",
            stable_id=self._request.stable_id,
            source=self._request.source,
        )

    def plan_execution(self) -> ScpReceiverFileExecutionPlan | None:
        """Freeze exact SSH tuple authority and both endpoint file effects."""

        if not self._planned:
            self._execution_plan = self._build_execution_plan()
            self._planned = True
        return self._execution_plan

    def execute(self) -> bool:
        """Publish both reconciled endpoint artifacts, or publish neither."""

        plan = self.plan_execution()
        if plan is None:
            return False
        manager = getattr(self._executor.activity_generator, "_runtime_content_manager", None)
        source_content: FileContentIdentity | None = None
        source_platform = _system_platform(plan.source_read.system)
        if isinstance(manager, RuntimeContentIdentityManager) and source_platform is not None:
            source_record = manager.resolve_record(
                plan.source_read.system.hostname,
                plan.source_read.process_username,
                plan.source_read.path,
                source_platform,
            )
            source_content = source_record.content if source_record is not None else None
        receiver_publication = _prepare_runtime_file_artifact(
            self._executor,
            plan.receiver_create,
            root_action_id=self.anchor.action_id,
            stable_source_id=stable_uuid(
                "scp-transfer-content",
                plan.source_process.object_id,
                ensure_utc(self._request.transfer_time).isoformat(),
            ),
            canonical_content=source_content,
        )
        _publish_prepared_file_occurrences(
            self._executor,
            (
                (plan.source_read, None),
                (plan.receiver_create, receiver_publication),
            ),
        )
        _record_effect_reconciliation(self._executor, plan.reconciliation)
        return True

    def _build_execution_plan(self) -> ScpReceiverFileExecutionPlan | None:
        """Preflight the complete SCP file-effect graph without allocating state."""

        if (
            not self._request.source_path
            or not self._request.target_path
            or not self._request.target_user
            or not self._request.source_process
            or self._request.source_pid <= 0
            or not 1 <= self._request.source_port <= 65_535
        ):
            raise ExecutionEffectPlanError(
                ExecutionEffectPlanErrorCode.INVALID_INTENT,
                "SCP receiver effects require exact paths, principals, process, PID, and tuple",
            )
        transfer_time = ensure_utc(self._request.transfer_time)
        receiver_pid, ready_time = self._preflight_ssh_tuple()

        source_read_time = transfer_time + _sample_transfer_gap(
            self._timing_runtime,
            relationship_key="file_transfer.scp.source_read_after_transfer",
            stable_id=self._request.stable_id,
            host=self._request.source_system.hostname,
            lifecycle_id=self.anchor.action_id,
            sample_key="source_read",
            minimum_ms=180,
            mode_ms=360,
            maximum_ms=850,
        )
        source_time_getter = getattr(
            self._executor.activity_generator,
            "process_source_create_time",
            None,
        )
        source_process_time: datetime | None = None
        if callable(source_time_getter):
            candidate = source_time_getter(
                self._request.source_system.hostname,
                self._request.source_pid,
            )
            if isinstance(candidate, datetime):
                source_process_time = ensure_utc(candidate)
                if source_read_time <= source_process_time:
                    source_read_time = source_process_time + _sample_transfer_gap(
                        self._timing_runtime,
                        relationship_key="file_transfer.scp.source_read_process_repair",
                        stable_id=self._request.stable_id,
                        host=self._request.source_system.hostname,
                        lifecycle_id=self.anchor.action_id,
                        sample_key="source_read_process_repair",
                        minimum_ms=250,
                        mode_ms=430,
                        maximum_ms=950,
                    )
        if source_read_time <= ready_time:
            source_read_time = ready_time + timedelta(milliseconds=1)

        receiver_create_delay = _sample_transfer_value(
            self._timing_runtime,
            relationship_key="file_transfer.scp.receiver_create_delay",
            stable_id=self._request.stable_id,
            host=self._request.target_system.hostname,
            lifecycle_id=self.anchor.action_id,
            sample_key="receiver_create_delay",
            minimum=1.2,
            mode=1.7,
            maximum=3.0,
        )
        receiver_create_time = transfer_time + timedelta(seconds=receiver_create_delay)
        if source_process_time is not None and receiver_create_time <= source_process_time:
            receiver_create_time = source_process_time + _sample_transfer_gap(
                self._timing_runtime,
                relationship_key="file_transfer.scp.receiver_create_process_repair",
                stable_id=self._request.stable_id,
                host=self._request.target_system.hostname,
                lifecycle_id=self.anchor.action_id,
                sample_key="receiver_create_process_repair",
                minimum_ms=250,
                mode_ms=520,
                maximum_ms=1400,
            )
        if receiver_create_time <= ready_time:
            receiver_create_time = ready_time + _sample_transfer_gap(
                self._timing_runtime,
                relationship_key="file_transfer.scp.receiver_create_session_repair",
                stable_id=self._request.stable_id,
                host=self._request.target_system.hostname,
                lifecycle_id=self.anchor.action_id,
                sample_key="receiver_create_session_repair",
                minimum_ms=120,
                mode_ms=310,
                maximum_ms=900,
            )
        if receiver_create_time <= source_read_time:
            receiver_create_time = source_read_time + timedelta(milliseconds=1)

        window_end = _exclusive_effect_window_end(
            self._executor,
            transfer_time + timedelta(days=1),
        )
        if source_read_time >= window_end or receiver_create_time >= window_end:
            return None

        source_process = _require_exact_process_identity(
            self._executor,
            system=self._request.source_system,
            pid=self._request.source_pid,
            at_times=(transfer_time, source_read_time, receiver_create_time),
            purpose="SCP source",
        )
        receiver_process = _require_exact_process_identity(
            self._executor,
            system=self._request.target_system,
            pid=receiver_pid,
            at_times=(ready_time, receiver_create_time),
            purpose="SCP tuple responder",
        )
        effects, source_read, receiver_create, reconciliation = self._plan_effect_graph(
            source_process=source_process,
            receiver_process=receiver_process,
            source_read_time=source_read_time,
            receiver_create_time=receiver_create_time,
            ready_time=ready_time,
        )
        return ScpReceiverFileExecutionPlan(
            effects=effects,
            reconciliation=reconciliation,
            source_process=source_process,
            receiver_process=receiver_process,
            source_read=source_read,
            receiver_create=receiver_create,
            ssh_ready_time=ready_time,
            retention_deadline=window_end,
            window_end=window_end,
        )

    def _preflight_ssh_tuple(self) -> tuple[int, datetime]:
        """Resolve an existing tuple-bound responder and ready time without fallback creation."""

        responder_getter = getattr(
            self._executor.activity_generator,
            "ssh_responder_pid_for_tuple",
            None,
        )
        ready_getter = getattr(
            self._executor.activity_generator,
            "ssh_session_ready_time_for_tuple",
            None,
        )
        if callable(responder_getter):
            responder_pid = responder_getter(
                self._request.source_system.ip,
                self._request.source_port,
                self._request.target_system.ip,
            )
            if not isinstance(responder_pid, int) or responder_pid <= 0:
                raise ExecutionEffectPlanError(
                    ExecutionEffectPlanErrorCode.INVALID_ACTOR,
                    "SCP endpoint effects require an existing tuple-bound SSH responder",
                )
            ready_time = (
                ready_getter(
                    self._request.source_system.ip,
                    self._request.source_port,
                    self._request.target_system.ip,
                )
                if callable(ready_getter)
                else None
            )
            if not isinstance(ready_time, datetime):
                raise ExecutionEffectPlanError(
                    ExecutionEffectPlanErrorCode.INVALID_PLAN,
                    "SCP endpoint effects require exact SSH session readiness",
                )
            return responder_pid, ensure_utc(ready_time)

        # Focused compatibility executors predate tuple caches.  They still
        # resolve an existing process identity and never allocate a fallback.
        responder_pid = self._executor.activity_generator._get_system_pid(
            self._request.target_system.hostname,
            "sshd",
            0,
        )
        if not isinstance(responder_pid, int) or responder_pid <= 0:
            raise ExecutionEffectPlanError(
                ExecutionEffectPlanErrorCode.INVALID_ACTOR,
                "SCP compatibility executor has no existing sshd process",
            )
        ready_time = (
            ready_getter(
                self._request.source_system.ip,
                self._request.source_port,
                self._request.target_system.ip,
            )
            if callable(ready_getter)
            else None
        )
        return (
            responder_pid,
            ensure_utc(ready_time)
            if isinstance(ready_time, datetime)
            else ensure_utc(self._request.transfer_time),
        )

    def _plan_effect_graph(
        self,
        *,
        source_process: ProcessIdentity,
        receiver_process: ProcessIdentity,
        source_read_time: datetime,
        receiver_create_time: datetime,
        ready_time: datetime,
    ) -> tuple[
        ExecutionEffectPlan,
        _PlannedFileEffectOccurrence,
        _PlannedFileEffectOccurrence,
        ExecutionEffectReconciliation,
    ]:
        """Build the immutable SCP transfer/file DAG and prepared exact outcomes."""

        anchor = self.anchor
        source_node = ExecutionEffectNode.create(
            anchor,
            ChildProcessEffectIntent(
                image=source_process.image,
                command_line=source_process.command_line or source_process.image,
            ),
            role=OccurrenceRole.PREREQUISITE,
            requirement=EffectRequirement.EXTERNALLY_OWNED,
            actor=EffectActorRef.system(),
            instance_key="source_process",
        )
        receiver_node = ExecutionEffectNode.create(
            anchor,
            ChildProcessEffectIntent(
                image=receiver_process.image,
                command_line=receiver_process.command_line or receiver_process.image,
            ),
            role=OccurrenceRole.PREREQUISITE,
            requirement=EffectRequirement.EXTERNALLY_OWNED,
            actor=EffectActorRef.system(),
            instance_key="receiver_process",
        )
        transfer_node = ExecutionEffectNode.create(
            anchor,
            TransferEffectIntent(
                protocol="scp",
                source_path=self._request.source_path,
                destination=self._request.target_system.ip,
                destination_path=self._request.target_path,
            ),
            actor=EffectActorRef.effect_process(source_node.node_id),
            depends_on=(receiver_node.node_id,),
            instance_key="scp_transfer",
        )
        source_read_node = ExecutionEffectNode.create(
            anchor,
            FileEffectIntent(
                action=FileEffectAction.READ,
                path=self._request.source_path,
            ),
            actor=EffectActorRef.effect_process(source_node.node_id),
            depends_on=(transfer_node.node_id,),
            instance_key="source_file_read",
        )
        receiver_create_node = ExecutionEffectNode.create(
            anchor,
            FileEffectIntent(
                action=FileEffectAction.CREATE,
                path=self._request.target_path,
            ),
            actor=EffectActorRef.effect_process(receiver_node.node_id),
            depends_on=(source_read_node.node_id, transfer_node.node_id),
            instance_key="receiver_file_create",
        )
        effects = ExecutionEffectPlan(
            anchor=anchor,
            nodes=(
                source_node,
                receiver_node,
                transfer_node,
                source_read_node,
                receiver_create_node,
            ),
        )
        source_read = _file_effect_occurrence(
            node=source_read_node,
            plan_action_id=anchor.action_id,
            timestamp=source_read_time,
            event_type="file_read",
            system=self._request.source_system,
            actor_username=self._request.actor.username,
            process=source_process,
            process_image=self._request.source_process,
            process_command_line=self._request.source_command,
            process_username=self._request.actor.username,
            path=self._request.source_path,
            action=FileEffectAction.READ,
        )
        receiver_create = _file_effect_occurrence(
            node=receiver_create_node,
            plan_action_id=anchor.action_id,
            timestamp=receiver_create_time,
            event_type="file_create",
            system=self._request.target_system,
            actor_username=self._request.target_user,
            process=receiver_process,
            process_image="/usr/sbin/sshd",
            process_command_line=f"sshd: {self._request.target_user}@notty",
            process_username=self._request.target_user,
            path=self._request.target_path,
            action=FileEffectAction.CREATE,
        )
        outcomes = (
            EffectExecutionOutcome(
                node_id=source_node.node_id,
                status=EffectOutcomeStatus.LINKED,
                child_action_id=source_process.object_id,
                completed_at=ready_time,
                canonical_occurrence_count=1,
            ),
            EffectExecutionOutcome(
                node_id=receiver_node.node_id,
                status=EffectOutcomeStatus.LINKED,
                child_action_id=receiver_process.object_id,
                completed_at=ready_time,
                canonical_occurrence_count=1,
            ),
            EffectExecutionOutcome(
                node_id=transfer_node.node_id,
                status=EffectOutcomeStatus.REALIZED,
                completed_at=receiver_create_time,
                canonical_occurrence_count=1,
            ),
            EffectExecutionOutcome(
                node_id=source_read_node.node_id,
                status=EffectOutcomeStatus.REALIZED,
                completed_at=source_read_time,
                canonical_occurrence_count=1,
            ),
            EffectExecutionOutcome(
                node_id=receiver_create_node.node_id,
                status=EffectOutcomeStatus.REALIZED,
                completed_at=receiver_create_time,
                canonical_occurrence_count=1,
            ),
        )
        reconciliation = _reconcile_exact_effects(effects, outcomes)
        return effects, source_read, receiver_create, reconciliation
