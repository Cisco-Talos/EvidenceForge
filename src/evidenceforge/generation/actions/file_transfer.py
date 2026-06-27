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
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any, Protocol
from urllib.parse import urlsplit

from evidenceforge.events.base import SecurityEvent
from evidenceforge.events.contexts import (
    AuthContext,
    EdrContext,
    FileContext,
    FileTransferContext,
    PeContext,
    ProcessContext,
)
from evidenceforge.generation.actions.base import ActionAnchor
from evidenceforge.generation.activity.network import _is_private_ip
from evidenceforge.generation.activity.smb_file_transfers import (
    load_smb_file_transfers,
    pick_smb_filename,
)
from evidenceforge.generation.state_manager import StateManager
from evidenceforge.models.scenario import System, User
from evidenceforge.utils.ids import generate_zeek_uid
from evidenceforge.utils.rng import _stable_seed, stable_uuid

_HTTP_HASH_ANALYZER_MIME_TYPES = {
    "application/octet-stream",
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
_HTTP_FILE_ANALYSIS_LOSS_MIN_BYTES = 128 * 1024
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


def _file_analysis_missing_bytes(total_bytes: int, rng: random.Random, *, timedout: bool) -> int:
    """Return source-observed bytes lost before file analyzers completed."""

    if total_bytes <= 0:
        return 0
    upper_bound = max(1, min(262_144, total_bytes // (12 if timedout else 35)))
    lower_bound = min(upper_bound, max(1, total_bytes // 600)) if timedout else 1
    return rng.randint(lower_bound, upper_bound)


def _http_file_analysis_loss(
    response_body_len: int,
    rng: random.Random,
) -> tuple[int, bool]:
    """Return low-rate HTTP files.log analyzer loss/timeout texture."""

    if response_body_len < _HTTP_FILE_ANALYSIS_LOSS_MIN_BYTES:
        return 0, False

    if response_body_len >= _HTTP_BULK_BODY_BYTES:
        missing_probability = 0.08
        timeout_probability = 0.012
    else:
        missing_probability = 0.025
        timeout_probability = 0.003

    timedout = rng.random() < timeout_probability
    missing_bytes = (
        _file_analysis_missing_bytes(response_body_len, rng, timedout=timedout)
        if timedout or rng.random() < missing_probability
        else 0
    )
    return missing_bytes, timedout


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


def _http_pe_analysis_enabled(mime_type: str, content_seed_material: str) -> bool:
    """Return whether this content object should produce PE analyzer records."""

    if mime_type not in _HTTP_PE_ANALYZER_MIME_TYPES:
        return False
    if mime_type in _HTTP_PE_DEFINITE_MIME_TYPES:
        return True
    return _stable_seed(f"http_pe_enabled:{content_seed_material}") % 100 < 25


@dataclass(frozen=True, slots=True)
class HttpResponseFileTransferRequest:
    """Intent for one HTTP response body visible to Zeek file analysis."""

    host: str
    uri: str
    dst_ip: str
    response_body_len: int
    response_mime_types: list[str]
    timestamp: datetime
    parent_duration: float | None = None
    source: str = "activity_generator"

    @property
    def stable_id(self) -> str:
        """Return a deterministic intent identifier for durable references."""

        seed = _stable_seed(
            "action_bundle:http_file_transfer:"
            f"{self.host}:{self.uri}:{self.dst_ip}:{self.response_body_len}:"
            f"{','.join(self.response_mime_types)}:{self.timestamp.isoformat()}:"
            f"{self.parent_duration or ''}:{self.source}"
        )
        return f"http-file-transfer-{seed:016x}"


@dataclass(slots=True)
class HttpResponseFileTransferResult:
    """Expanded HTTP file-analysis metadata."""

    file_transfer: FileTransferContext
    pe: PeContext | None = None


class HttpResponseFileTransferActionBundle:
    """Build coordinated Zeek files.log metadata for an HTTP response body."""

    def __init__(
        self,
        request: HttpResponseFileTransferRequest,
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

    def execute(self) -> HttpResponseFileTransferResult:
        """Return file-transfer metadata and optional PE analysis."""

        fuid = generate_zeek_uid("F")
        file_mime_type = self._request.response_mime_types[0]
        analyzers = ["SHA1"] if file_mime_type in _HTTP_HASH_ANALYZER_MIME_TYPES else []
        missing_bytes, timedout = _http_file_analysis_loss(
            self._request.response_body_len,
            self._rng,
        )
        if missing_bytes or timedout:
            analyzers = []
        content_seed_material = _http_content_seed_material(
            self._request.host,
            self._request.uri,
            self._request.response_body_len,
            file_mime_type,
        )
        file_hashes = file_transfer_hashes(content_seed_material, analyzers)
        file_transfer = FileTransferContext(
            fuid=fuid,
            source="HTTP",
            depth=0,
            analyzers=analyzers,
            mime_type=file_mime_type,
            duration=_http_response_file_duration(
                self._request.response_body_len,
                self._request.parent_duration,
                self._rng,
            ),
            local_orig=_is_private_ip(self._request.dst_ip),
            is_orig=False,
            seen_bytes=max(0, self._request.response_body_len - missing_bytes),
            total_bytes=self._request.response_body_len,
            missing_bytes=missing_bytes,
            overflow_bytes=0,
            timedout=timedout,
            **file_hashes,
        )
        return HttpResponseFileTransferResult(
            file_transfer=file_transfer,
            pe=None
            if missing_bytes or timedout
            else self._maybe_build_pe_context(fuid, file_mime_type, content_seed_material),
        )

    def _maybe_build_pe_context(
        self,
        fuid: str,
        mime_type: str,
        content_seed_material: str,
    ) -> PeContext | None:
        """Return content-scoped PE analysis for executable file transfers."""

        if not _http_pe_analysis_enabled(mime_type, content_seed_material):
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
class SmbFileTransferMetadataRequest:
    """Intent for one SMB flow that may be visible to Zeek file analysis."""

    src_ip: str
    dst_ip: str
    transfer_bytes: int
    duration: float
    server: str
    user: str
    is_orig: bool = False
    source: str = "activity_generator"

    @property
    def stable_id(self) -> str:
        """Return a deterministic intent identifier for durable references."""

        seed = _stable_seed(
            "action_bundle:smb_file_transfer_metadata:"
            f"{self.src_ip}:{self.dst_ip}:{self.transfer_bytes}:{self.duration}:"
            f"{self.server}:{self.user}:{self.is_orig}:{self.source}"
        )
        return f"smb-file-transfer-metadata-{seed:016x}"


class SmbFileTransferMetadataActionBundle:
    """Build source-native Zeek files.log metadata for a substantial SMB transfer."""

    def __init__(
        self,
        request: SmbFileTransferMetadataRequest,
        rng: random.Random,
        smb_config: Mapping[str, Any] | None = None,
    ) -> None:
        self._request = request
        self._rng = rng
        self._smb_config = smb_config

    @property
    def anchor(self) -> ActionAnchor:
        """Return the stable action anchor."""

        return ActionAnchor(
            family="smb_file_transfer_metadata",
            stable_id=self._request.stable_id,
            source=self._request.source,
        )

    def execute(self) -> FileTransferContext | None:
        """Return SMB file-transfer metadata when the flow crosses the configured threshold."""

        smb_config = self._smb_config if self._smb_config is not None else load_smb_file_transfers()
        min_transfer_bytes = int(smb_config.get("min_transfer_bytes", 32768))
        if self._request.transfer_bytes < min_transfer_bytes:
            return None

        mime_type = self._pick_mime_type(smb_config)
        analyzers = self._pick_analyzers(smb_config)
        missing_probability = float(smb_config.get("missing_bytes_probability", 0.0))
        timeout_probability = float(smb_config.get("timeout_probability", 0.0))
        timedout = self._rng.random() < timeout_probability
        missing_bytes = (
            _file_analysis_missing_bytes(self._request.transfer_bytes, self._rng, timedout=timedout)
            if timedout or self._rng.random() < missing_probability
            else 0
        )
        if missing_bytes or timedout:
            analyzers = []
        fuid = generate_zeek_uid("F")
        file_hashes = file_transfer_hashes(
            f"smb:{self._request.src_ip}:{self._request.dst_ip}:"
            f"{self._request.transfer_bytes}:{fuid}",
            analyzers,
        )
        filename = pick_smb_filename(
            self._rng,
            smb_config,
            mime_type=mime_type,
            server=self._request.server,
            user=self._request.user,
        )
        return FileTransferContext(
            fuid=fuid,
            source="SMB",
            depth=0,
            filename=filename,
            analyzers=analyzers,
            mime_type=mime_type,
            duration=max(0.0, self._request.duration * self._rng.uniform(0.6, 0.98)),
            local_orig=_is_private_ip(self._request.src_ip),
            is_orig=self._request.is_orig,
            seen_bytes=max(0, self._request.transfer_bytes - missing_bytes),
            total_bytes=self._request.transfer_bytes,
            missing_bytes=missing_bytes,
            overflow_bytes=0,
            timedout=timedout,
            **file_hashes,
        )

    def _pick_mime_type(self, smb_config: Mapping[str, Any]) -> str:
        """Return a configured SMB file MIME type."""

        mime_entries = smb_config.get("mime_types", [])
        if not mime_entries:
            return "application/octet-stream"
        mime_values = [
            str(entry.get("mime_type", "application/octet-stream")) for entry in mime_entries
        ]
        mime_weights = [int(entry.get("weight", 1)) for entry in mime_entries]
        return self._rng.choices(mime_values, weights=mime_weights, k=1)[0]

    def _pick_analyzers(self, smb_config: Mapping[str, Any]) -> list[str]:
        """Return configured Zeek file analyzers for this SMB transfer."""

        analyzer_entries = smb_config.get("analyzer_sets", [])
        if not analyzer_entries:
            return []
        analyzer_values = [entry.get("analyzers", []) for entry in analyzer_entries]
        analyzer_weights = [int(entry.get("weight", 1)) for entry in analyzer_entries]
        return list(self._rng.choices(analyzer_values, weights=analyzer_weights, k=1)[0])


class FileTransferStorylineExecutor(Protocol):
    """Adapter protocol implemented by the storyline engine."""

    activity_generator: Any
    dispatcher: Any
    state_manager: StateManager


class SmbLogonPairEmitter(Protocol):
    """Adapter protocol for SMB companion logon evidence."""

    def __call__(
        self,
        user: User,
        file_server: System,
        source_ip: str,
        time: datetime,
        rng: random.Random,
        *,
        source_port: int | None = None,
        emit_network_evidence: bool = True,
    ) -> object:
        """Emit a file-server logon/logoff pair for an SMB transport."""
        ...


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
            f"{self.source_pid}:{self.source_file_read_path}:{self.source}"
        )
        return f"staged-archive-smb-read-{seed:016x}"


class StagedArchiveSmbReadActionBundle:
    """Emit SMB network file-analysis evidence for a staged archive read."""

    def __init__(
        self,
        executor: FileTransferStorylineExecutor,
        request: StagedArchiveSmbReadRequest,
        rng: random.Random,
        emit_smb_logon_pair: SmbLogonPairEmitter | None = None,
    ) -> None:
        self._executor = executor
        self._request = request
        self._rng = rng
        self._emit_smb_logon_pair = emit_smb_logon_pair

    @property
    def anchor(self) -> ActionAnchor:
        """Return the stable action anchor."""

        return ActionAnchor(
            family="staged_archive_smb_read",
            stable_id=self._request.stable_id,
            source=self._request.source,
        )

    def execute(self) -> bool:
        """Emit the staged archive transfer and return true when evidence was emitted."""

        if self._request.upload_bytes < 1_000_000:
            return False
        transfer_bytes = max(
            32_768,
            self._request.upload_bytes
            - self._rng.randint(
                4096,
                max(4096, min(self._request.upload_bytes // 180, 2_000_000)),
            ),
        )
        throughput = self._rng.uniform(18_000_000, 85_000_000)
        duration = max(3.0, min(180.0, transfer_bytes / throughput + self._rng.uniform(0.5, 6.0)))
        transfer_time = self._transfer_time(duration)
        if transfer_time is None:
            return False
        transfer_time = self._clamp_after_source_process(transfer_time, duration)
        if transfer_time is None:
            return False

        analyzers = ["MD5", "SHA1"]
        fuid = generate_zeek_uid("F")
        hashes = file_transfer_hashes(
            f"smb:{self._request.source_ip}:{self._request.staging_ip}:"
            f"{self._request.archive_path}:{transfer_bytes}",
            analyzers,
        )
        self._executor.activity_generator.generate_connection(
            src_ip=self._request.source_ip,
            dst_ip=self._request.staging_ip,
            time=transfer_time,
            dst_port=445,
            proto="tcp",
            service="smb",
            duration=duration,
            orig_bytes=self._rng.randint(35_000, 180_000),
            resp_bytes=transfer_bytes,
            conn_state="SF",
            emit_dns=False,
            source_system=self._request.source_system,
            pid=self._request.source_pid,
            process_image=self._request.source_process,
            file_transfer=FileTransferContext(
                fuid=fuid,
                source="SMB",
                depth=0,
                filename=self._request.smb_filename,
                analyzers=analyzers,
                mime_type="application/zip",
                duration=max(0.0, duration * self._rng.uniform(0.72, 0.98)),
                local_orig=True,
                is_orig=False,
                seen_bytes=transfer_bytes,
                total_bytes=transfer_bytes,
                missing_bytes=0,
                overflow_bytes=0,
                timedout=False,
                **hashes,
            ),
        )
        self._emit_source_file_read(transfer_time)
        smb_source_port = self._last_smb_connection_source_port()
        if self._target_is_file_server() and self._emit_smb_logon_pair is not None:
            self._emit_smb_logon_pair(
                self._request.actor,
                self._request.target_system,
                self._request.source_ip,
                transfer_time,
                self._rng,
                source_port=smb_source_port,
                emit_network_evidence=smb_source_port is None,
            )
        return True

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
        candidate = source_process_time + timedelta(milliseconds=self._rng.randint(350, 1400))
        if candidate >= latest:
            return None
        return candidate

    def _emit_source_file_read(self, transfer_time: datetime) -> None:
        """Emit upload-host FILE/READ evidence for the staged archive."""

        if (
            self._request.source_system is None
            or self._request.source_pid <= 0
            or not self._request.source_process
        ):
            return
        source_path = self._request.source_file_read_path or self._request.smb_filename
        if not source_path:
            return
        running_source = self._executor.state_manager.get_process(
            self._request.source_system.hostname,
            self._request.source_pid,
        )
        parent_pid = running_source.parent_pid if running_source is not None else 0
        source_actor_id = self._executor.state_manager.get_process_object_id(
            self._request.source_system.hostname,
            self._request.source_pid,
        )
        file_time = transfer_time + timedelta(milliseconds=self._rng.randint(220, 1200))
        source_time_getter = getattr(
            self._executor.activity_generator,
            "process_source_create_time",
            None,
        )
        if callable(source_time_getter):
            source_process_time = source_time_getter(
                self._request.source_system.hostname,
                self._request.source_pid,
            )
            if isinstance(source_process_time, datetime) and file_time <= source_process_time:
                file_time = source_process_time + timedelta(
                    milliseconds=self._rng.randint(250, 950)
                )
        if file_time >= self._request.exfil_time:
            return

        self._executor.dispatcher.dispatch(
            SecurityEvent(
                timestamp=file_time,
                event_type="file_read",
                src_host=self._executor.activity_generator._build_host_context(
                    self._request.source_system
                ),
                auth=AuthContext(username=self._request.actor.username),
                process=ProcessContext(
                    pid=self._request.source_pid,
                    parent_pid=parent_pid,
                    image=self._request.source_process,
                    command_line=self._request.source_command or self._request.source_process,
                    username=self._request.actor.username,
                ),
                file=FileContext(
                    path=source_path,
                    action="read",
                    pid=self._request.source_pid,
                ),
                edr=EdrContext(
                    object_id=stable_uuid(
                        "staged-archive-source-file-read-edr",
                        self._request.source_system.hostname,
                        self._request.source_pid,
                        source_path,
                        self._request.exfil_time.isoformat(),
                    ),
                    actor_id=source_actor_id,
                ),
                storyline_origin=True,
            )
        )

    def _last_smb_connection_source_port(self) -> int | None:
        """Return the just-emitted SMB transfer source port when available."""
        matcher = getattr(
            self._executor.activity_generator,
            "_last_effective_connection_source_port",
            None,
        )
        if matcher is None:
            return None
        return matcher(
            src_ip=self._request.source_ip,
            dst_ip=self._request.staging_ip,
            dst_port=445,
            proto="tcp",
        )

    def _transfer_time(self, duration: float) -> datetime | None:
        """Return a transfer time between archive staging and upload."""

        gap_seconds = self._rng.uniform(20.0, 180.0)
        transfer_time = self._request.exfil_time - timedelta(seconds=duration + gap_seconds)
        earliest = self._request.staged_at + timedelta(seconds=self._rng.uniform(20.0, 180.0))
        if transfer_time >= earliest:
            return transfer_time
        latest = self._request.exfil_time - timedelta(seconds=duration + 5.0)
        if latest <= earliest:
            return None
        span = (latest - earliest).total_seconds()
        return earliest + timedelta(seconds=self._rng.uniform(0.0, span))

    def _target_is_file_server(self) -> bool:
        """Return true when the archive source host should emit SMB logon evidence."""

        return "file_server" in [role.lower() for role in (self._request.target_system.roles or [])]


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

    @property
    def anchor(self) -> ActionAnchor:
        """Return the stable action anchor."""

        return ActionAnchor(
            family="scp_receiver_file",
            stable_id=self._request.stable_id,
            source=self._request.source,
        )

    def execute(self) -> None:
        """Emit target-side file creation after the SSH bundle models transport/session."""

        transfer_time = self._request.transfer_time
        self._executor.state_manager.set_current_time(transfer_time + timedelta(milliseconds=40))
        self._emit_source_file_read()
        sshd_pid = self._ensure_responder_process()
        sshd_actor_id = self._executor.state_manager.get_process_object_id(
            self._request.target_system.hostname,
            sshd_pid,
        )
        parent_pid = self._executor.activity_generator._get_system_pid(
            self._request.target_system.hostname,
            "sshd",
            0,
        )
        file_time = transfer_time + timedelta(seconds=self._rng.uniform(1.2, 3.0))
        source_time_getter = getattr(
            self._executor.activity_generator,
            "process_source_create_time",
            None,
        )
        if callable(source_time_getter):
            source_process_time = source_time_getter(
                self._request.source_system.hostname,
                self._request.source_pid,
            )
            if isinstance(source_process_time, datetime) and file_time <= source_process_time:
                file_time = source_process_time + timedelta(
                    milliseconds=self._rng.randint(250, 1400)
                )
        ready_time_getter = getattr(
            self._executor.activity_generator,
            "ssh_session_ready_time_for_tuple",
            None,
        )
        if callable(ready_time_getter):
            ready_time = ready_time_getter(
                self._request.source_system.ip,
                self._request.source_port,
                self._request.target_system.ip,
            )
            if isinstance(ready_time, datetime) and file_time <= ready_time:
                file_time = ready_time + timedelta(milliseconds=self._rng.randint(120, 900))

        self._executor.dispatcher.dispatch(
            SecurityEvent(
                timestamp=file_time,
                event_type="file_create",
                src_host=self._executor.activity_generator._build_host_context(
                    self._request.target_system
                ),
                auth=AuthContext(username=self._request.target_user),
                process=ProcessContext(
                    pid=sshd_pid,
                    parent_pid=parent_pid if parent_pid > 0 else 0,
                    image="/usr/sbin/sshd",
                    command_line=f"sshd: {self._request.target_user}@notty",
                    username=self._request.target_user,
                ),
                file=FileContext(
                    path=self._request.target_path,
                    action="create",
                    pid=sshd_pid,
                ),
                edr=EdrContext(
                    object_id=stable_uuid(
                        "scp-receiver-file-edr",
                        self._request.target_system.hostname,
                        sshd_pid,
                        self._request.target_path,
                        file_time.isoformat(),
                    ),
                    actor_id=sshd_actor_id,
                ),
                storyline_origin=True,
            )
        )

    def _emit_source_file_read(self) -> None:
        """Emit sender-side file-read evidence owned by the SCP client process."""

        if not self._request.source_path:
            return
        running_source = self._executor.state_manager.get_process(
            self._request.source_system.hostname,
            self._request.source_pid,
        )
        parent_pid = running_source.parent_pid if running_source is not None else 0
        source_actor_id = self._executor.state_manager.get_process_object_id(
            self._request.source_system.hostname,
            self._request.source_pid,
        )
        file_time = self._request.transfer_time + timedelta(
            milliseconds=self._rng.randint(180, 850)
        )
        source_time_getter = getattr(
            self._executor.activity_generator,
            "process_source_create_time",
            None,
        )
        if callable(source_time_getter):
            source_process_time = source_time_getter(
                self._request.source_system.hostname,
                self._request.source_pid,
            )
            if isinstance(source_process_time, datetime) and file_time <= source_process_time:
                file_time = source_process_time + timedelta(
                    milliseconds=self._rng.randint(250, 950)
                )

        self._executor.dispatcher.dispatch(
            SecurityEvent(
                timestamp=file_time,
                event_type="file_read",
                src_host=self._executor.activity_generator._build_host_context(
                    self._request.source_system
                ),
                auth=AuthContext(username=self._request.actor.username),
                process=ProcessContext(
                    pid=self._request.source_pid,
                    parent_pid=parent_pid,
                    image=self._request.source_process,
                    command_line=self._request.source_command,
                    username=self._request.actor.username,
                ),
                file=FileContext(
                    path=self._request.source_path,
                    action="read",
                    pid=self._request.source_pid,
                ),
                edr=EdrContext(
                    object_id=stable_uuid(
                        "scp-source-file-read-edr",
                        self._request.source_system.hostname,
                        self._request.source_pid,
                        self._request.source_path,
                        self._request.transfer_time.isoformat(),
                    ),
                    actor_id=source_actor_id,
                ),
                storyline_origin=True,
            )
        )

    def _ensure_responder_process(self) -> int:
        """Return the destination sshd process that owns receiver-side file evidence."""

        ensure_responder = getattr(
            self._executor.activity_generator,
            "ensure_linux_ssh_responder_process",
            None,
        )
        if callable(ensure_responder):
            return ensure_responder(
                target_system=self._request.target_system,
                time=self._request.transfer_time,
                source_ip=self._request.source_system.ip,
                source_port=self._request.source_port,
                target_user=self._request.target_user,
            )

        parent_pid = self._executor.activity_generator._get_system_pid(
            self._request.target_system.hostname,
            "sshd",
            0,
        )
        return self._executor.state_manager.create_process(
            system=self._request.target_system.hostname,
            parent_pid=parent_pid if parent_pid > 0 else 0,
            image="/usr/sbin/sshd",
            command_line=f"sshd: {self._request.target_user}@notty",
            username=self._request.target_user,
            integrity_level="High" if self._request.target_user == "root" else "Medium",
        )
