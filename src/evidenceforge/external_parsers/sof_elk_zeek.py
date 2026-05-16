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

"""SOF-ELK Zeek parser harness for optional external-parser tests."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import time
import uuid
from collections import Counter
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from evidenceforge.external_parsers.tag_policy import (
    SOF_ELK_ZEEK_VALIDATOR,
    classify_parser_tags,
)

SOF_ELK_REPO_URL = "https://github.com/philhagen/sof-elk.git"
SOF_ELK_COMMIT = "517af9445574cc084cd5f4b80539fc244dab82b0"
FILEBEAT_IMAGE = "docker.elastic.co/beats/filebeat:8.19.0"
LOGSTASH_IMAGE = "docker.elastic.co/logstash/logstash:8.19.0"
HARNESS_CONTAINER_LABEL = "evidenceforge.external_parser=sof-elk-zeek"
HARNESS_RUN_ID_LABEL = "evidenceforge.external_parser.run_id"
FAILURE_REPORT_FILENAME = "sof_elk_parser_failures.json"
FAILURE_DETAIL_LIMIT = 25

SOF_ELK_FILTER_FILES = (
    "1000-preprocess-all.conf",
    "1001-preprocess-json.conf",
    "1200-preprocess-zeek.conf",
    "2051-zeek_conn-netflow.conf",
    "6200-zeek_dns.conf",
    "6201-zeek_http.conf",
    "6202-zeek_files.conf",
    "6203-zeek_ssl.conf",
    "6204-zeek_x509.conf",
    "6276-zeek_weird.conf",
    "8000-postprocess-zeek.conf",
)

JsonObject = dict[str, Any]
LogType = str
ProgressCallback = Callable[[str, dict[str, Any]], None]
ScopeKey = tuple[str, str, str]


def _noop_progress(_event_type: str, _data: dict[str, Any]) -> None:
    """Default progress callback used when callers do not need updates."""
    return


@dataclass(frozen=True)
class ZeekLogSpec:
    """Mapping from generated EvidenceForge Zeek files to SOF-ELK input shape."""

    log_type: LogType
    staged_name: str
    source_names: tuple[str, ...]
    required_paths: tuple[str, ...] = ()
    sof_elk_dedicated_filter: bool = False
    sof_elk_filebeat_input: bool = False


GENERIC_JSON_REQUIRED_PATHS = ("raw.ts",)
ZEEK_LOG_SPECS: tuple[ZeekLogSpec, ...] = (
    ZeekLogSpec(
        log_type="zeek_conn",
        staged_name="conn.log",
        source_names=("conn.json", "zeek_conn.json"),
        required_paths=(
            "zeek.session_id",
            "source.ip",
            "source.port",
            "destination.ip",
            "destination.port",
            "network.transport",
            "zeek.connection.state",
            "source.bytes",
            "destination.bytes",
            "source.packets",
            "destination.packets",
        ),
        sof_elk_dedicated_filter=True,
        sof_elk_filebeat_input=True,
    ),
    ZeekLogSpec(
        log_type="zeek_dns",
        staged_name="dns.log",
        source_names=("dns.json", "zeek_dns.json"),
        required_paths=(
            "zeek.session_id",
            "source.ip",
            "source.port",
            "destination.ip",
            "destination.port",
            "network.transport",
            "dns.question.name",
            "dns.question.type",
            "dns.response.code",
        ),
        sof_elk_dedicated_filter=True,
        sof_elk_filebeat_input=True,
    ),
    ZeekLogSpec(
        log_type="zeek_http",
        staged_name="http.log",
        source_names=("http.json", "zeek_http.json"),
        required_paths=(
            "zeek.session_id",
            "source.ip",
            "source.port",
            "destination.ip",
            "destination.port",
            "http.request.method",
        ),
        sof_elk_dedicated_filter=True,
        sof_elk_filebeat_input=True,
    ),
    ZeekLogSpec(
        log_type="zeek_files",
        staged_name="files.log",
        source_names=("files.json", "zeek_files.json"),
        required_paths=(
            "zeek.files.fuid",
            "zeek.files.source",
            "zeek.files.seen_bytes",
        ),
        sof_elk_dedicated_filter=True,
        sof_elk_filebeat_input=True,
    ),
    ZeekLogSpec(
        log_type="zeek_ssl",
        staged_name="ssl.log",
        source_names=("ssl.json", "zeek_ssl.json"),
        required_paths=(
            "zeek.session_id",
            "source.ip",
            "source.port",
            "destination.ip",
            "destination.port",
            "tls.version",
        ),
        sof_elk_dedicated_filter=True,
        sof_elk_filebeat_input=True,
    ),
    ZeekLogSpec(
        log_type="zeek_x509",
        staged_name="x509.log",
        source_names=("x509.json", "zeek_x509.json"),
        required_paths=(
            "tls.cert_container.x509.hash.sha256",
            "tls.cert_container.x509.version_number",
        ),
        sof_elk_dedicated_filter=True,
        sof_elk_filebeat_input=True,
    ),
    ZeekLogSpec(
        log_type="zeek_weird",
        staged_name="weird.log",
        source_names=("weird.json", "zeek_weird.json"),
        required_paths=("zeek.weird.name",),
        sof_elk_dedicated_filter=True,
        sof_elk_filebeat_input=True,
    ),
    ZeekLogSpec(
        log_type="zeek_dhcp",
        staged_name="dhcp.log",
        source_names=("dhcp.json", "zeek_dhcp.json"),
        required_paths=GENERIC_JSON_REQUIRED_PATHS,
        sof_elk_filebeat_input=True,
    ),
    ZeekLogSpec(
        log_type="zeek_ntp",
        staged_name="ntp.log",
        source_names=("ntp.json", "zeek_ntp.json"),
        required_paths=GENERIC_JSON_REQUIRED_PATHS,
    ),
    ZeekLogSpec(
        log_type="zeek_ocsp",
        staged_name="ocsp.log",
        source_names=("ocsp.json", "zeek_ocsp.json"),
        required_paths=GENERIC_JSON_REQUIRED_PATHS,
    ),
    ZeekLogSpec(
        log_type="zeek_packet_filter",
        staged_name="packet_filter.log",
        source_names=("packet_filter.json", "zeek_packet_filter.json"),
        required_paths=GENERIC_JSON_REQUIRED_PATHS,
    ),
    ZeekLogSpec(
        log_type="zeek_pe",
        staged_name="pe.log",
        source_names=("pe.json", "zeek_pe.json"),
        required_paths=GENERIC_JSON_REQUIRED_PATHS,
    ),
    ZeekLogSpec(
        log_type="zeek_reporter",
        staged_name="reporter.log",
        source_names=("reporter.json", "zeek_reporter.json"),
        required_paths=GENERIC_JSON_REQUIRED_PATHS,
    ),
)
LOG_TYPES: tuple[LogType, ...] = tuple(spec.log_type for spec in ZEEK_LOG_SPECS)
LOG_SPECS_BY_TYPE: dict[LogType, ZeekLogSpec] = {spec.log_type: spec for spec in ZEEK_LOG_SPECS}
SUPPLEMENTAL_FILEBEAT_SPECS = tuple(
    spec for spec in ZEEK_LOG_SPECS if not spec.sof_elk_filebeat_input
)


class SofElkHarnessError(RuntimeError):
    """Raised when the external SOF-ELK harness cannot run."""


class SofElkParserError(AssertionError):
    """Raised when SOF-ELK parses fewer events or produces invalid events."""


@dataclass(frozen=True)
class DnsExpectation:
    """Raw DNS fields that SOF-ELK should preserve when present."""

    answers: bool = False
    ttls: bool = False


@dataclass(frozen=True)
class StagedLog:
    """A generated Zeek file staged under SOF-ELK's watched path layout."""

    source: Path
    staged: Path
    log_type: LogType
    record_count: int


@dataclass(frozen=True)
class ZeekStageManifest:
    """Manifest for staged Zeek logs and the records expected from Logstash."""

    logstash_root: Path
    logs: tuple[StagedLog, ...]
    dns_expectations: dict[tuple[str, str], DnsExpectation] = field(default_factory=dict)

    @property
    def expected_counts(self) -> dict[LogType, int]:
        """Return expected output event counts by SOF-ELK label type."""
        counts: dict[LogType, int] = dict.fromkeys(LOG_TYPES, 0)
        for log in self.logs:
            counts[log.log_type] += log.record_count
        return {log_type: count for log_type, count in counts.items() if count}


@dataclass(frozen=True)
class SofElkZeekResult:
    """Summary returned by a successful SOF-ELK Zeek parser run."""

    manifest: ZeekStageManifest
    output_dir: Path
    pipeline_log_dir: Path
    events_by_type: dict[LogType, list[JsonObject]]
    logstash_config_tested: bool


def default_external_cache_dir() -> Path:
    """Return the cache directory used for runtime-downloaded parser assets."""
    configured_cache = os.environ.get("EFORGE_EXTERNAL_CACHE_DIR")
    if configured_cache:
        return Path(configured_cache).expanduser()

    xdg_cache = os.environ.get("XDG_CACHE_HOME")
    if xdg_cache:
        return Path(xdg_cache).expanduser() / "evidenceforge" / "external-parsers"

    return Path.home() / ".cache" / "evidenceforge" / "external-parsers"


def ensure_sof_elk_checkout(
    cache_dir: Path | None = None,
    *,
    repo_url: str = SOF_ELK_REPO_URL,
    commit: str = SOF_ELK_COMMIT,
) -> Path:
    """Clone and pin SOF-ELK outside the repository if it is not cached.

    Args:
        cache_dir: Optional external cache root.
        repo_url: Git repository URL to clone.
        commit: Exact SOF-ELK commit to check out.

    Returns:
        Path to the pinned SOF-ELK checkout.
    """
    root = (cache_dir or default_external_cache_dir()).expanduser()
    checkout = root / f"sof-elk-{commit[:12]}"

    if checkout.exists():
        existing = _run(
            ["git", "-C", str(checkout), "rev-parse", "HEAD"],
            description="check cached SOF-ELK revision",
        ).stdout.strip()
        if existing != commit:
            message = (
                f"cached SOF-ELK checkout at {checkout} is {existing}, expected {commit}; "
                "remove it or set EFORGE_EXTERNAL_CACHE_DIR to a clean cache"
            )
            raise SofElkHarnessError(message)
        _assert_sof_elk_files_exist(checkout)
        return checkout

    root.mkdir(parents=True, exist_ok=True)
    _run(
        ["git", "clone", "--filter=blob:none", "--no-checkout", repo_url, str(checkout)],
        description="clone SOF-ELK",
        timeout=180,
    )
    _run(
        ["git", "-C", str(checkout), "checkout", commit],
        description="checkout pinned SOF-ELK revision",
        timeout=120,
    )
    _assert_sof_elk_files_exist(checkout)
    return checkout


def find_container_runtime() -> str:
    """Return the available container runtime command, preferring Docker."""
    for runtime in ("docker", "podman"):
        if shutil.which(runtime) and _container_runtime_available(runtime):
            return runtime
    raise SofElkHarnessError(
        "Docker or Podman with an accessible daemon is required for external parser tests"
    )


def stage_zeek_logs(source_root: Path, staging_root: Path) -> ZeekStageManifest:
    """Stage generated Zeek JSON files under SOF-ELK's `/logstash/zeek/**` layout.

    Args:
        source_root: Root containing generated Zeek files.
        staging_root: Temporary directory where the SOF-ELK-style tree is created.

    Returns:
        Manifest describing staged files and expected parsed output counts.
    """
    source_root = source_root.resolve()
    logstash_root = staging_root.resolve() / "logstash"
    zeek_root = logstash_root / "zeek"
    zeek_root.mkdir(parents=True, exist_ok=True)

    logs: list[StagedLog] = []
    dns_expectations: dict[tuple[str, str], DnsExpectation] = {}

    for spec in ZEEK_LOG_SPECS:
        for source_name in spec.source_names:
            for source in sorted(source_root.rglob(source_name)):
                sensor = _sensor_name(source_root, source.parent)
                destination = zeek_root / sensor / spec.staged_name
                destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(source, destination)
                record_count = _count_jsonl_lines(destination)
                logs.append(
                    StagedLog(
                        source=source,
                        staged=destination,
                        log_type=spec.log_type,
                        record_count=record_count,
                    )
                )
                if spec.log_type == "zeek_dns":
                    dns_expectations.update(_dns_expectations(source))

    if not logs:
        expected_names = ", ".join(
            sorted(source_name for spec in ZEEK_LOG_SPECS for source_name in spec.source_names)
        )
        raise SofElkHarnessError(
            f"no supported Zeek JSON files found below generated output {source_root}; "
            f"expected one of: {expected_names}"
        )

    return ZeekStageManifest(
        logstash_root=logstash_root,
        logs=tuple(logs),
        dns_expectations=dns_expectations,
    )


def build_sof_elk_zeek_configs(sof_elk_dir: Path, work_dir: Path) -> tuple[Path, Path]:
    """Create temporary Filebeat and Logstash configs that reuse SOF-ELK assets.

    Args:
        sof_elk_dir: Pinned SOF-ELK checkout.
        work_dir: Temporary directory for generated config files.

    Returns:
        Tuple of `(pipeline_dir, filebeat_config_path)`.
    """
    _assert_sof_elk_files_exist(sof_elk_dir)
    config_root = work_dir.resolve() / "runtime-config"
    pipeline_dir = config_root / "pipeline"
    filebeat_inputs_dir = config_root / "filebeat-inputs"
    pipeline_dir.mkdir(parents=True, exist_ok=True)
    filebeat_inputs_dir.mkdir(parents=True, exist_ok=True)

    (pipeline_dir / "0000-input-beats.conf").write_text(
        """input {
  beats {
    port => 5044
    tags => [ "filebeat" ]
  }
}
""",
        encoding="utf-8",
    )
    for filter_file in SOF_ELK_FILTER_FILES:
        shutil.copyfile(
            sof_elk_dir / "configfiles" / filter_file,
            pipeline_dir / filter_file,
        )
    shutil.copyfile(
        sof_elk_dir / "lib" / "filebeat_inputs" / "zeek.yml",
        filebeat_inputs_dir / "zeek.yml",
    )
    supplemental_inputs = _supplemental_filebeat_inputs()
    if supplemental_inputs:
        (filebeat_inputs_dir / "evidenceforge-zeek.yml").write_text(
            supplemental_inputs,
            encoding="utf-8",
        )
    (pipeline_dir / "9999-output-jsonl.conf").write_text(
        """output {
  file {
    path => "/parsed-output/%{[labels][type]}.jsonl"
    codec => json_lines
  }
}
""",
        encoding="utf-8",
    )

    filebeat_config = config_root / "filebeat.yml"
    filebeat_config.write_text(
        """filebeat.config.inputs:
  enabled: true
  path: /usr/share/filebeat/inputs.d/*.yml
  reload.enabled: false

output.logstash:
  hosts: ["logstash:5044"]

logging.level: info
path.data: /usr/share/filebeat/data
""",
        encoding="utf-8",
    )
    return pipeline_dir, filebeat_config


def _supplemental_filebeat_inputs() -> str:
    """Return Filebeat inputs for EvidenceForge Zeek logs SOF-ELK does not watch yet."""
    blocks: list[str] = []
    for spec in SUPPLEMENTAL_FILEBEAT_SPECS:
        input_id = spec.log_type.replace("_", "-")
        watched_name = spec.staged_name.removesuffix(".log")
        blocks.append(
            f"""- type: filestream
  id: eforge-{input_id}-01
  paths:
    - /logstash/zeek/**/{watched_name}.*
  prospector.scanner.exclude_files: [ '\\.gz$', '\\.bz2$', '\\.zip$' ]
  close.on_state_change.inactive: 5m
  clean_removed: true
  processors:
    - add_labels:
       labels:
         type: {spec.log_type}
  tags: [ 'zeek' ]
"""
        )
    return "\n".join(blocks)


def run_sof_elk_zeek_parser(
    source_root: Path,
    work_dir: Path,
    *,
    cache_dir: Path | None = None,
    timeout_seconds: int = 120,
    runtime: str | None = None,
    progress_callback: ProgressCallback = _noop_progress,
) -> SofElkZeekResult:
    """Run Filebeat and Logstash against staged Zeek logs and validate output.

    Args:
        source_root: Root containing generated EvidenceForge Zeek logs.
        work_dir: Temporary work/output root.
        cache_dir: Optional runtime cache for SOF-ELK.
        timeout_seconds: Polling timeout for containerized parser output.
        runtime: Optional container runtime command, mainly for tests.
        progress_callback: Optional callback for high-level parser stages.

    Returns:
        Successful parse result with parsed events by log type.
    """
    work_dir = work_dir.resolve()
    staging_dir = work_dir / "stage"
    parsed_dir = work_dir / "parsed"
    pipeline_log_dir = work_dir / "pipeline-logs"
    filebeat_data_dir = work_dir / "filebeat-data"
    logstash_data_dir = work_dir / "logstash-data"
    for directory in (
        staging_dir,
        parsed_dir,
        pipeline_log_dir,
        filebeat_data_dir,
        logstash_data_dir,
    ):
        directory.mkdir(parents=True, exist_ok=True)

    progress_callback("validator_step", {"description": "Staging Zeek files"})
    manifest = stage_zeek_logs(source_root, staging_dir)
    progress_callback("validator_step", {"description": "Preparing SOF-ELK checkout"})
    sof_elk_dir = ensure_sof_elk_checkout(cache_dir)
    progress_callback("validator_step", {"description": "Building runtime config"})
    pipeline_dir, filebeat_config = build_sof_elk_zeek_configs(sof_elk_dir, work_dir)
    container_runtime = runtime or find_container_runtime()

    progress_callback("validator_step", {"description": "Validating Logstash config"})
    _validate_logstash_config(container_runtime, pipeline_dir, sof_elk_dir, parsed_dir)
    progress_callback("validator_step", {"description": "Running Filebeat and Logstash"})
    _run_containers(
        container_runtime,
        manifest=manifest,
        sof_elk_dir=sof_elk_dir,
        pipeline_dir=pipeline_dir,
        filebeat_config=filebeat_config,
        parsed_dir=parsed_dir,
        filebeat_data_dir=filebeat_data_dir,
        logstash_data_dir=logstash_data_dir,
        pipeline_log_dir=pipeline_log_dir,
        timeout_seconds=timeout_seconds,
    )
    progress_callback("validator_step", {"description": "Checking parsed output"})
    try:
        events_by_type = validate_parsed_output(
            manifest,
            parsed_dir,
            progress_callback=progress_callback,
        )
    except SofElkParserError:
        progress_callback("validator_done", {"description": "SOF-ELK Zeek failed"})
        raise
    progress_callback("validator_done", {"description": "SOF-ELK Zeek complete"})
    return SofElkZeekResult(
        manifest=manifest,
        output_dir=parsed_dir,
        pipeline_log_dir=pipeline_log_dir,
        events_by_type=events_by_type,
        logstash_config_tested=True,
    )


def validate_parsed_output(
    manifest: ZeekStageManifest,
    parsed_dir: Path,
    progress_callback: ProgressCallback = _noop_progress,
) -> dict[LogType, list[JsonObject]]:
    """Validate SOF-ELK JSONL output against staged input counts and fields.

    Args:
        manifest: Staging manifest describing expected input records.
        parsed_dir: Directory containing SOF-ELK JSONL outputs.
        progress_callback: Optional callback for parsed-record validation progress.

    Returns:
        Parsed events grouped by SOF-ELK label type.

    Raises:
        SofElkParserError: If parsing failed, counts mismatch, or required fields are
            missing.
    """
    failures: list[str] = []
    failure_events: list[JsonObject] = []
    events_by_type: dict[LogType, list[JsonObject]] = {log_type: [] for log_type in LOG_TYPES}
    scope_by_container_path = _scope_by_container_path(manifest)
    fallback_scope_by_log_type = _fallback_scope_by_log_type(manifest)
    expected_by_host, expected_by_logtype, expected_by_subtype = _scope_expected_counts(manifest)
    completed_by_host: Counter[str] = Counter()
    completed_by_logtype: Counter[tuple[str, str]] = Counter()
    completed_by_subtype: Counter[ScopeKey] = Counter()

    for log_type, expected_count in manifest.expected_counts.items():
        output_path = parsed_dir / f"{log_type}.jsonl"
        events = _read_jsonl(output_path) if output_path.exists() else []
        events_by_type[log_type] = events

        if len(events) != expected_count:
            failures.append(
                f"{log_type}: expected {expected_count} parsed events, got {len(events)}"
            )

        for index, event in enumerate(events, start=1):
            scope = _event_scope(
                event, log_type, scope_by_container_path, fallback_scope_by_log_type
            )
            if scope is not None:
                _update_scope_progress(
                    scope=scope,
                    expected_by_host=expected_by_host,
                    expected_by_logtype=expected_by_logtype,
                    expected_by_subtype=expected_by_subtype,
                    completed_by_host=completed_by_host,
                    completed_by_logtype=completed_by_logtype,
                    completed_by_subtype=completed_by_subtype,
                    progress_callback=progress_callback,
                )
            event_failures = _event_failures(log_type, index, event, manifest)
            failures.extend(event_failures)
            if event_failures:
                failure_events.append(
                    _failure_event_summary(log_type, index, event, event_failures)
                )

    if failures:
        report_path = _write_failure_report(
            manifest,
            parsed_dir,
            events_by_type,
            failures,
            failure_events,
        )
        details = "\n- ".join(failures[:FAILURE_DETAIL_LIMIT])
        omitted_count = len(failures) - FAILURE_DETAIL_LIMIT
        omitted = f"\n- ... {omitted_count} additional failure(s)" if omitted_count > 0 else ""
        raise SofElkParserError(
            "SOF-ELK parser validation failed; "
            f"failure report written to {report_path}:\n- {details}{omitted}"
        )

    return events_by_type


def _scope_by_container_path(manifest: ZeekStageManifest) -> dict[str, ScopeKey]:
    return {
        _container_log_path(manifest, log): _scope_for_staged_log(manifest, log)
        for log in manifest.logs
    }


def _fallback_scope_by_log_type(manifest: ZeekStageManifest) -> dict[LogType, ScopeKey]:
    scopes: dict[LogType, ScopeKey] = {}
    for log in manifest.logs:
        scopes.setdefault(log.log_type, _scope_for_staged_log(manifest, log))
    return scopes


def _scope_expected_counts(
    manifest: ZeekStageManifest,
) -> tuple[Counter[str], Counter[tuple[str, str]], Counter[ScopeKey]]:
    expected_by_host: Counter[str] = Counter()
    expected_by_logtype: Counter[tuple[str, str]] = Counter()
    expected_by_subtype: Counter[ScopeKey] = Counter()
    for log in manifest.logs:
        host, logtype, subtype = _scope_for_staged_log(manifest, log)
        expected_by_host[host] += log.record_count
        expected_by_logtype[(host, logtype)] += log.record_count
        expected_by_subtype[(host, logtype, subtype)] += log.record_count
    return expected_by_host, expected_by_logtype, expected_by_subtype


def _scope_for_staged_log(manifest: ZeekStageManifest, log: StagedLog) -> ScopeKey:
    relative = log.staged.relative_to(manifest.logstash_root)
    parts = relative.parts
    host = parts[1] if len(parts) >= 3 and parts[0] == "zeek" else str(relative.parent)
    subtype = Path(parts[-1]).stem
    return host, "zeek", subtype


def _container_log_path(manifest: ZeekStageManifest, log: StagedLog) -> str:
    return f"/logstash/{log.staged.relative_to(manifest.logstash_root).as_posix()}"


def _event_scope(
    event: JsonObject,
    log_type: LogType,
    scope_by_container_path: dict[str, ScopeKey],
    fallback_scope_by_log_type: dict[LogType, ScopeKey],
) -> ScopeKey | None:
    log_file_path = _get_path(event, "log.file.path")
    if isinstance(log_file_path, str) and log_file_path in scope_by_container_path:
        return scope_by_container_path[log_file_path]
    return fallback_scope_by_log_type.get(log_type)


def _update_scope_progress(
    *,
    scope: ScopeKey,
    expected_by_host: Counter[str],
    expected_by_logtype: Counter[tuple[str, str]],
    expected_by_subtype: Counter[ScopeKey],
    completed_by_host: Counter[str],
    completed_by_logtype: Counter[tuple[str, str]],
    completed_by_subtype: Counter[ScopeKey],
    progress_callback: ProgressCallback,
) -> None:
    host, logtype, subtype = scope
    completed_by_host[host] += 1
    completed_by_logtype[(host, logtype)] += 1
    completed_by_subtype[scope] += 1
    progress_callback(
        "validator_scope_progress",
        {
            "host": host,
            "host_completed": completed_by_host[host],
            "host_total": expected_by_host[host],
            "logtype": logtype,
            "logtype_completed": completed_by_logtype[(host, logtype)],
            "logtype_total": expected_by_logtype[(host, logtype)],
            "subtype": subtype,
            "subtype_completed": completed_by_subtype[scope],
            "subtype_total": expected_by_subtype[scope],
        },
    )


def _run_containers(
    runtime: str,
    *,
    manifest: ZeekStageManifest,
    sof_elk_dir: Path,
    pipeline_dir: Path,
    filebeat_config: Path,
    parsed_dir: Path,
    filebeat_data_dir: Path,
    logstash_data_dir: Path,
    pipeline_log_dir: Path,
    timeout_seconds: int,
) -> None:
    run_id = uuid.uuid4().hex[:12]
    network = f"eforge-sof-elk-{run_id}"
    logstash_name = f"eforge-logstash-{run_id}"
    filebeat_name = f"eforge-filebeat-{run_id}"
    created_network = False
    logstash_started = False
    filebeat_started = False

    try:
        _run([runtime, "network", "create", network], description="create parser network")
        created_network = True
        _run(
            [
                runtime,
                "run",
                "-d",
                "--name",
                logstash_name,
                *_container_label_args(run_id),
                "--network",
                network,
                "--network-alias",
                "logstash",
                "-e",
                "LS_JAVA_OPTS=-Xms512m -Xmx512m",
                "-v",
                f"{pipeline_dir}:/usr/share/logstash/pipeline:ro",
                "-v",
                f"{sof_elk_dir}:/usr/local/sof-elk:ro",
                "-v",
                f"{parsed_dir}:/parsed-output",
                "-v",
                f"{logstash_data_dir}:/usr/share/logstash/data",
                "-e",
                "XPACK_MONITORING_ENABLED=false",
                LOGSTASH_IMAGE,
                "-f",
                "/usr/share/logstash/pipeline",
            ],
            description="start Logstash parser",
        )
        logstash_started = True
        _wait_for_logstash(runtime, logstash_name, timeout_seconds)
        _run(
            [
                runtime,
                "run",
                "-d",
                "--name",
                filebeat_name,
                *_container_label_args(run_id),
                "--network",
                network,
                "--user",
                "root",
                "-v",
                f"{manifest.logstash_root}:/logstash:ro",
                "-v",
                f"{sof_elk_dir}:/usr/local/sof-elk:ro",
                "-v",
                f"{filebeat_config}:/usr/share/filebeat/filebeat.yml:ro",
                "-v",
                f"{filebeat_config.parent / 'filebeat-inputs'}:/usr/share/filebeat/inputs.d:ro",
                "-v",
                f"{filebeat_data_dir}:/usr/share/filebeat/data",
                FILEBEAT_IMAGE,
                "-e",
                "--strict.perms=false",
            ],
            description="start Filebeat parser feeder",
        )
        filebeat_started = True
        _wait_for_expected_output(manifest, parsed_dir, timeout_seconds)
    finally:
        if filebeat_started:
            (pipeline_log_dir / "filebeat.log").write_text(
                _container_logs(runtime, filebeat_name),
                encoding="utf-8",
            )
        if logstash_started:
            (pipeline_log_dir / "logstash.log").write_text(
                _container_logs(runtime, logstash_name),
                encoding="utf-8",
            )
        _container_rm_force(runtime, filebeat_name)
        _container_rm_force(runtime, logstash_name)
        if created_network:
            _network_rm(runtime, network)


def _validate_logstash_config(
    runtime: str,
    pipeline_dir: Path,
    sof_elk_dir: Path,
    parsed_dir: Path,
) -> None:
    _run(
        [
            runtime,
            "run",
            "--rm",
            "-e",
            "LS_JAVA_OPTS=-Xms512m -Xmx512m",
            "-v",
            f"{pipeline_dir}:/usr/share/logstash/pipeline:ro",
            "-v",
            f"{sof_elk_dir}:/usr/local/sof-elk:ro",
            "-v",
            f"{parsed_dir}:/parsed-output",
            "-e",
            "XPACK_MONITORING_ENABLED=false",
            LOGSTASH_IMAGE,
            "-f",
            "/usr/share/logstash/pipeline",
            "--config.test_and_exit",
        ],
        description="validate Logstash parser config",
        timeout=600,
    )


def _wait_for_logstash(runtime: str, container_name: str, timeout_seconds: int) -> None:
    deadline = time.monotonic() + timeout_seconds
    ready_markers = (
        "Starting server on port: 5044",
        "Beats inputs: Starting input listener",
        "Pipeline started",
    )
    last_logs = ""
    while time.monotonic() < deadline:
        last_logs = _container_logs(runtime, container_name)
        if any(marker in last_logs for marker in ready_markers):
            return
        time.sleep(1)
    raise SofElkHarnessError(
        "Logstash did not start its Beats listener before timeout. "
        f"Recent logs:\n{last_logs[-4000:]}"
    )


def _wait_for_expected_output(
    manifest: ZeekStageManifest,
    parsed_dir: Path,
    timeout_seconds: int,
) -> None:
    expected = manifest.expected_counts
    deadline = time.monotonic() + timeout_seconds

    while time.monotonic() < deadline:
        if all(
            _count_jsonl_lines(parsed_dir / f"{log_type}.jsonl") >= count
            for log_type, count in expected.items()
        ):
            return
        time.sleep(1)

    observed = {
        log_type: _count_jsonl_lines(parsed_dir / f"{log_type}.jsonl") for log_type in LOG_TYPES
    }
    raise SofElkParserError(
        f"SOF-ELK output timed out after {timeout_seconds}s; expected {expected}, "
        f"observed {observed}"
    )


def _event_failures(
    log_type: LogType,
    index: int,
    event: JsonObject,
    manifest: ZeekStageManifest,
) -> list[str]:
    failures: list[str] = []
    prefix = f"{log_type} event {index}"

    tags = event.get("tags", [])
    if not isinstance(tags, list):
        failures.append(f"{prefix}: tags is not a list")
        tags = []
    failure_tags = _failure_tags(log_type, tags)
    if failure_tags:
        failures.append(f"{prefix}: parser failure tags present: {', '.join(failure_tags)}")

    spec = LOG_SPECS_BY_TYPE[log_type]
    for path in spec.required_paths:
        if _get_path(event, path) in (None, ""):
            failures.append(f"{prefix}: missing required field {path}")

    if log_type == "zeek_dns":
        session_id = _get_path(event, "zeek.session_id")
        question_name = _get_path(event, "dns.question.name")
        expectation = manifest.dns_expectations.get((str(session_id), str(question_name)))
        if (
            expectation
            and expectation.answers
            and _get_path(event, "dns.answers.data") in (None, "")
        ):
            failures.append(f"{prefix}: missing dns.answers.data from raw answers")
        if expectation and expectation.ttls and _get_path(event, "dns.answers.ttl") in (None, ""):
            failures.append(f"{prefix}: missing dns.answers.ttl from raw TTLs")

    return failures


def _write_failure_report(
    manifest: ZeekStageManifest,
    parsed_dir: Path,
    events_by_type: dict[LogType, list[JsonObject]],
    failures: list[str],
    failure_events: list[JsonObject],
) -> Path:
    report_path = parsed_dir / FAILURE_REPORT_FILENAME
    report = {
        "expected_counts": manifest.expected_counts,
        "observed_counts": {
            log_type: len(events_by_type.get(log_type, [])) for log_type in manifest.expected_counts
        },
        "parsed_outputs": {
            log_type: str(parsed_dir / f"{log_type}.jsonl") for log_type in manifest.expected_counts
        },
        "log_support": {
            spec.log_type: {
                "sof_elk_dedicated_filter": spec.sof_elk_dedicated_filter,
                "sof_elk_filebeat_input": spec.sof_elk_filebeat_input,
            }
            for spec in ZEEK_LOG_SPECS
            if spec.log_type in manifest.expected_counts
        },
        "staged_logs": [
            {
                "source": str(log.source),
                "staged": str(log.staged),
                "log_type": log.log_type,
                "record_count": log.record_count,
            }
            for log in manifest.logs
        ],
        "failure_count": len(failures),
        "failure_tag_counts": _failure_tag_counts(
            events_by_type,
            tuple(manifest.expected_counts),
        ),
        "dns_failure_qtype_counts": _dns_failure_qtype_counts(events_by_type),
        "sample_failures": failure_events[:FAILURE_DETAIL_LIMIT],
    }
    report_path.write_text(
        json.dumps(report, indent=2, sort_keys=True),
        encoding="utf-8",
    )
    return report_path


def _failure_event_summary(
    log_type: LogType,
    index: int,
    event: JsonObject,
    failures: list[str],
) -> JsonObject:
    tags = event.get("tags", [])
    summary: JsonObject = {
        "log_type": log_type,
        "event_index": index,
        "failures": failures,
        "tags": _failure_tags(log_type, tags) if isinstance(tags, list) else tags,
        "zeek_session_id": _get_path(event, "zeek.session_id"),
        "source_ip": _get_path(event, "source.ip"),
        "destination_ip": _get_path(event, "destination.ip"),
        "event_original": _get_path(event, "event.original"),
    }
    if log_type == "zeek_dns":
        summary.update(
            {
                "dns_question_name": _get_path(event, "dns.question.name"),
                "dns_question_type": _get_path(event, "dns.question.type"),
                "dns_response_code": _get_path(event, "dns.response.code"),
                "dns_answers_data": _get_path(event, "dns.answers.data"),
            }
        )
    return summary


def _failure_tag_counts(
    events_by_type: dict[LogType, list[JsonObject]],
    log_types: tuple[LogType, ...],
) -> dict[LogType, dict[str, int]]:
    counts_by_type: dict[LogType, dict[str, int]] = {}
    for log_type in log_types:
        counts: Counter[str] = Counter()
        for event in events_by_type.get(log_type, []):
            tags = event.get("tags", [])
            if isinstance(tags, list):
                counts.update(_failure_tags(log_type, tags))
        counts_by_type[log_type] = dict(sorted(counts.items()))
    return counts_by_type


def _dns_failure_qtype_counts(
    events_by_type: dict[LogType, list[JsonObject]],
) -> dict[str, int]:
    counts: Counter[str] = Counter()
    for event in events_by_type.get("zeek_dns", []):
        tags = event.get("tags", [])
        if not isinstance(tags, list) or not _failure_tags("zeek_dns", tags):
            continue
        qtype = _get_path(event, "dns.question.type")
        counts[str(qtype or "unknown")] += 1
    return dict(sorted(counts.items()))


def _failure_tags(log_type: LogType, tags: list[Any]) -> list[str]:
    return list(
        classify_parser_tags(
            validator=SOF_ELK_ZEEK_VALIDATOR,
            log_type=log_type,
            tags=tags,
        ).fatal
    )


def _assert_sof_elk_files_exist(sof_elk_dir: Path) -> None:
    required_paths = [
        sof_elk_dir / "lib" / "filebeat_inputs" / "zeek.yml",
        *(sof_elk_dir / "configfiles" / filename for filename in SOF_ELK_FILTER_FILES),
    ]
    missing = [path for path in required_paths if not path.exists()]
    if missing:
        formatted = ", ".join(str(path) for path in missing)
        raise SofElkHarnessError(f"SOF-ELK checkout is missing required files: {formatted}")


def _run(
    cmd: list[str],
    *,
    description: str,
    timeout: int | None = None,
) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(
            cmd,
            check=True,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired as exc:
        output = _timeout_output(exc)
        detail = f"\nPartial output:\n{output}" if output else ""
        raise SofElkHarnessError(f"{description} timed out after {timeout}s{detail}") from exc
    except subprocess.CalledProcessError as exc:
        stderr = exc.stderr.strip()
        stdout = exc.stdout.strip()
        output = stderr or stdout or f"exit code {exc.returncode}"
        raise SofElkHarnessError(f"failed to {description}: {output}") from exc


def _container_runtime_available(runtime: str) -> bool:
    try:
        completed = subprocess.run(
            [runtime, "info"],
            check=False,
            capture_output=True,
            text=True,
            timeout=10,
        )
    except subprocess.TimeoutExpired:
        return False
    return completed.returncode == 0


def _timeout_output(exc: subprocess.TimeoutExpired) -> str:
    parts: list[str] = []
    for value in (exc.stdout, exc.stderr):
        if not value:
            continue
        if isinstance(value, bytes):
            parts.append(value.decode("utf-8", errors="replace").strip())
        else:
            parts.append(value.strip())
    return "\n".join(part for part in parts if part)


def _container_logs(runtime: str, container_name: str) -> str:
    completed = subprocess.run(
        [runtime, "logs", container_name],
        check=False,
        capture_output=True,
        text=True,
    )
    return completed.stdout + completed.stderr


def _container_label_args(run_id: str) -> list[str]:
    return [
        "--label",
        HARNESS_CONTAINER_LABEL,
        "--label",
        f"{HARNESS_RUN_ID_LABEL}={run_id}",
    ]


def _container_rm_force(runtime: str, container_name: str) -> None:
    subprocess.run(
        [runtime, "rm", "-f", container_name],
        check=False,
        capture_output=True,
        text=True,
    )


def _network_rm(runtime: str, network: str) -> None:
    subprocess.run(
        [runtime, "network", "rm", network],
        check=False,
        capture_output=True,
        text=True,
    )


def _sensor_name(source_root: Path, source_parent: Path) -> str:
    relative = source_parent.relative_to(source_root)
    if relative == Path("."):
        return "default"
    return "__".join(relative.parts)


def _count_jsonl_lines(path: Path) -> int:
    if not path.exists():
        return 0
    with path.open("r", encoding="utf-8") as handle:
        return sum(1 for line in handle if line.strip())


def _read_jsonl(path: Path) -> list[JsonObject]:
    events: list[JsonObject] = []
    with path.open("r", encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, start=1):
            if not line.strip():
                continue
            try:
                parsed = json.loads(line)
            except json.JSONDecodeError as exc:
                raise SofElkParserError(
                    f"parsed output {path} line {line_number} is not valid JSON"
                ) from exc
            if not isinstance(parsed, dict):
                raise SofElkParserError(
                    f"parsed output {path} line {line_number} is not a JSON object"
                )
            events.append(parsed)
    return events


def _dns_expectations(path: Path) -> dict[tuple[str, str], DnsExpectation]:
    expectations: dict[tuple[str, str], DnsExpectation] = {}
    with path.open("r", encoding="utf-8") as handle:
        for line in handle:
            if not line.strip():
                continue
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue
            if not isinstance(event, dict):
                continue
            uid = str(event.get("uid", ""))
            query = str(event.get("query", ""))
            if not uid or not query:
                continue
            expectations[(uid, query)] = DnsExpectation(
                answers=_has_payload(event.get("answers")),
                ttls=_has_payload(event.get("TTLs")),
            )
    return expectations


def _has_payload(value: Any) -> bool:
    if value is None:
        return False
    if isinstance(value, list):
        return any(item not in (None, "", "-") for item in value)
    return value not in ("", "-")


def _get_path(event: JsonObject, dotted_path: str) -> Any:
    value: Any = event
    for part in dotted_path.split("."):
        if not isinstance(value, dict):
            return None
        value = value.get(part)
    return value
