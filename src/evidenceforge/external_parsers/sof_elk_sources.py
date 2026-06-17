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

"""SOF-ELK parser harnesses for non-Zeek generated log sources."""

from __future__ import annotations

import json
import re
import shutil
from collections import Counter
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from evidenceforge.external_parsers.compose_runtime import (
    SofElkGeneratedConfig,
    build_generated_config,
    create_compose_run,
    reset_external_parser_run_directories,
    run_sof_elk_compose,
)
from evidenceforge.external_parsers.sof_elk_zeek import (
    FAILURE_DETAIL_LIMIT,
    FAILURE_REPORT_FILENAME,
    FILEBEAT_IMAGE,
    LOGSTASH_IMAGE,
    SOF_ELK_COMMIT,
    SOF_ELK_REPO_URL,
    SofElkHarnessError,
    SofElkParserError,
    _count_jsonl_lines,
    _get_path,
    _noop_progress,
    _read_jsonl,
)
from evidenceforge.external_parsers.tag_policy import (
    SOF_ELK_CISCO_ASA_VALIDATOR,
    SOF_ELK_SYSLOG_VALIDATOR,
    SOF_ELK_WEB_ACCESS_VALIDATOR,
    SOF_ELK_WINDOWS_SECURITY_SNARE_VALIDATOR,
    SOF_ELK_WINDOWS_SYSMON_SNARE_VALIDATOR,
    classify_parser_tags,
)

JsonObject = dict[str, Any]
ProgressCallback = Callable[[str, dict[str, Any]], None]
ScopeKey = tuple[str, str, str]

EVENTS_OUTPUT_FILENAME = "events.jsonl"


@dataclass(frozen=True)
class SofElkSourceSpec:
    """A non-Zeek EvidenceForge source that can be staged through SOF-ELK."""

    validator: str
    display_name: str
    format_name: str
    logtype: str
    subtype: str
    source_names: tuple[str, ...]
    staged_directory: str
    staged_name: str
    filebeat_input: str
    filter_files: tuple[str, ...]
    output_label_type: str
    required_paths: tuple[str, ...] = ()
    required_tags: tuple[str, ...] = ()


CISCO_ASA_SPEC = SofElkSourceSpec(
    validator=SOF_ELK_CISCO_ASA_VALIDATOR,
    display_name="SOF-ELK Cisco ASA",
    format_name="cisco_asa",
    logtype="firewall",
    subtype="cisco_asa",
    source_names=("cisco_asa.log",),
    staged_directory="syslog",
    staged_name="cisco_asa.log",
    filebeat_input="syslog.yml",
    filter_files=(
        "1000-preprocess-all.conf",
        "1100-preprocess-syslog.conf",
        "6018-cisco_asa.conf",
        "8999-postprocess-all.conf",
    ),
    output_label_type="syslog",
    required_paths=("log.syslog.hostname", "log.syslog.appname"),
    required_tags=("got_cisco", "parse_done"),
)

WEB_ACCESS_SPEC = SofElkSourceSpec(
    validator=SOF_ELK_WEB_ACCESS_VALIDATOR,
    display_name="SOF-ELK Web Access",
    format_name="web_access",
    logtype="web",
    subtype="access",
    source_names=("web_access.log",),
    staged_directory="httpd",
    staged_name="web_access.log",
    filebeat_input="httpdlog.yml",
    filter_files=(
        "1000-preprocess-all.conf",
        "6100-httpd.conf",
        "8060-postprocess-useragent.conf",
        "8110-postprocess-httpd.conf",
        "8999-postprocess-all.conf",
    ),
    output_label_type="httpdlog",
    required_paths=(
        "source.ip",
        "http.request.method",
        "http.response.status_code",
        "url.path",
    ),
    required_tags=("parse_done",),
)

SYSLOG_SPEC = SofElkSourceSpec(
    validator=SOF_ELK_SYSLOG_VALIDATOR,
    display_name="SOF-ELK Syslog",
    format_name="syslog",
    logtype="syslog",
    subtype="linux",
    source_names=("syslog.log",),
    staged_directory="syslog",
    staged_name="syslog.log",
    filebeat_input="syslog.yml",
    filter_files=(
        "1000-preprocess-all.conf",
        "1100-preprocess-syslog.conf",
        "6012-dhcpd.conf",
        "6013-bindquery.conf",
        "6015-sshd.conf",
        "6016-pam.conf",
        "6017-iptables.conf",
        "8100-postprocess-syslog.conf",
        "8999-postprocess-all.conf",
    ),
    output_label_type="syslog",
    required_paths=("log.syslog.hostname", "log.syslog.appname"),
)

WINDOWS_SECURITY_SNARE_SPEC = SofElkSourceSpec(
    validator=SOF_ELK_WINDOWS_SECURITY_SNARE_VALIDATOR,
    display_name="SOF-ELK Windows Security Snare",
    format_name="windows_event_security_snare",
    logtype="windows events",
    subtype="security_snare",
    source_names=("windows_event_security_snare.log",),
    staged_directory="syslog",
    staged_name="windows_event_security_snare.log",
    filebeat_input="syslog.yml",
    filter_files=(
        "1000-preprocess-all.conf",
        "1010-preprocess-snare.conf",
        "1100-preprocess-syslog.conf",
        "6010-snare.conf",
        "8999-postprocess-all.conf",
    ),
    output_label_type="syslog",
    required_paths=(
        "winlog.event_id",
        "winlog.provider_name",
        "winlog.channel",
        "winlog.computer_name",
    ),
    required_tags=("snare_log", "parse_done"),
)

WINDOWS_SYSMON_SNARE_SPEC = SofElkSourceSpec(
    validator=SOF_ELK_WINDOWS_SYSMON_SNARE_VALIDATOR,
    display_name="SOF-ELK Windows Sysmon Snare",
    format_name="windows_event_sysmon_snare",
    logtype="windows events",
    subtype="sysmon_snare",
    source_names=("windows_event_sysmon_snare.log",),
    staged_directory="syslog",
    staged_name="windows_event_sysmon_snare.log",
    filebeat_input="syslog.yml",
    filter_files=WINDOWS_SECURITY_SNARE_SPEC.filter_files,
    output_label_type="syslog",
    required_paths=(
        "winlog.event_id",
        "winlog.provider_name",
        "winlog.channel",
        "winlog.computer_name",
    ),
    required_tags=("snare_log", "parse_done"),
)

SOF_ELK_SOURCE_SPECS: tuple[SofElkSourceSpec, ...] = (
    CISCO_ASA_SPEC,
    WEB_ACCESS_SPEC,
    SYSLOG_SPEC,
    WINDOWS_SECURITY_SNARE_SPEC,
    WINDOWS_SYSMON_SNARE_SPEC,
)
SOF_ELK_SOURCE_SPECS_BY_VALIDATOR: dict[str, SofElkSourceSpec] = {
    spec.validator: spec for spec in SOF_ELK_SOURCE_SPECS
}


@dataclass(frozen=True)
class StagedSourceLog:
    """A generated source file staged under SOF-ELK's watched path layout."""

    source: Path
    staged: Path
    record_count: int
    source_year: int | None = None


@dataclass(frozen=True)
class SofElkSourceManifest:
    """Manifest for a staged non-Zeek SOF-ELK source run."""

    spec: SofElkSourceSpec
    logstash_root: Path
    logs: tuple[StagedSourceLog, ...]

    @property
    def expected_count(self) -> int:
        """Return the total number of records expected from Logstash."""
        return sum(log.record_count for log in self.logs)

    @property
    def expected_counts(self) -> dict[str, int]:
        """Return expected output event counts by EvidenceForge format name."""
        return {self.spec.format_name: self.expected_count}


@dataclass(frozen=True)
class SofElkSourceResult:
    """Summary returned by a successful non-Zeek SOF-ELK parser run."""

    manifest: SofElkSourceManifest
    output_dir: Path
    pipeline_log_dir: Path
    events: list[JsonObject]
    logstash_config_tested: bool

    @property
    def events_by_type(self) -> dict[str, list[JsonObject]]:
        """Return parsed events keyed by EvidenceForge format name."""
        return {self.manifest.spec.format_name: self.events}


def stage_source_logs(
    source_root: Path,
    staging_root: Path,
    spec: SofElkSourceSpec,
) -> SofElkSourceManifest:
    """Stage generated source files under SOF-ELK's watched directory layout."""
    source_root = source_root.resolve()
    logstash_root = staging_root.resolve() / "logstash"
    source_stage_root = logstash_root / spec.staged_directory
    source_stage_root.mkdir(parents=True, exist_ok=True)

    logs: list[StagedSourceLog] = []
    for source_name in spec.source_names:
        for source in sorted(source_root.rglob(source_name)):
            safe_source = _safe_stage_source(source_root, source)
            sensor = _source_name(source_root, source)
            source_year = _source_year(safe_source) if spec.staged_directory == "syslog" else None
            if spec.staged_directory == "syslog" and source_year is not None:
                destination = source_stage_root / str(source_year) / sensor / spec.staged_name
            else:
                destination = source_stage_root / sensor / spec.staged_name
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(safe_source, destination)
            logs.append(
                StagedSourceLog(
                    source=source,
                    staged=destination,
                    record_count=_count_jsonl_lines(destination),
                    source_year=source_year,
                )
            )

    if not logs:
        expected_names = ", ".join(sorted(spec.source_names))
        raise SofElkHarnessError(
            f"no supported {spec.format_name} files found below generated output "
            f"{source_root}; expected one of: {expected_names}"
        )

    return SofElkSourceManifest(spec=spec, logstash_root=logstash_root, logs=tuple(logs))


def build_sof_elk_source_configs(
    work_dir: Path,
    spec: SofElkSourceSpec,
) -> SofElkGeneratedConfig:
    """Create host-side EvidenceForge-owned configs for a non-Zeek SOF-ELK run."""
    return build_generated_config(
        work_dir,
        sof_elk_filter_files=spec.filter_files,
        sof_elk_filebeat_inputs=(spec.filebeat_input,),
        output_path=f"/parsed-output/{EVENTS_OUTPUT_FILENAME}",
    )


def run_sof_elk_source_parser(
    source_root: Path,
    work_dir: Path,
    spec: SofElkSourceSpec,
    *,
    timeout_seconds: int = 120,
    runtime: str | None = None,
    progress_callback: ProgressCallback = _noop_progress,
) -> SofElkSourceResult:
    """Run Filebeat and Logstash against a staged non-Zeek source."""
    work_dir = work_dir.resolve()
    reset_external_parser_run_directories(work_dir)
    staging_dir = work_dir / "stage"
    parsed_dir = work_dir / "parsed"
    pipeline_log_dir = work_dir / "pipeline-logs"
    filebeat_data_dir = work_dir / "filebeat-data"
    logstash_data_dir = work_dir / "logstash-data"

    progress_callback("validator_step", {"description": f"Staging {spec.format_name} files"})
    manifest = stage_source_logs(source_root, staging_dir, spec)
    progress_callback("validator_step", {"description": "Building runtime config"})
    generated_config = build_sof_elk_source_configs(work_dir, spec)
    compose_run = create_compose_run(
        work_dir=work_dir,
        generated_config=generated_config,
        logstash_root=manifest.logstash_root,
        parsed_dir=parsed_dir,
        filebeat_data_dir=filebeat_data_dir,
        logstash_data_dir=logstash_data_dir,
        repo_url=SOF_ELK_REPO_URL,
        commit=SOF_ELK_COMMIT,
        filebeat_image=FILEBEAT_IMAGE,
        logstash_image=LOGSTASH_IMAGE,
        runtime=runtime,
        container_label=f"evidenceforge.external_parser={spec.validator}",
    )
    run_sof_elk_compose(
        compose_run,
        expected_output_counts={"events": manifest.expected_count},
        parsed_dir=parsed_dir,
        pipeline_log_dir=pipeline_log_dir,
        timeout_seconds=timeout_seconds,
        progress_callback=progress_callback,
    )
    progress_callback("validator_step", {"description": "Validating parsed JSONL"})
    try:
        events = validate_source_parsed_output(
            manifest,
            parsed_dir,
            progress_callback=progress_callback,
        )
    except SofElkParserError:
        progress_callback("validator_done", {"description": f"{spec.display_name} failed"})
        raise
    progress_callback("validator_done", {"description": f"{spec.display_name} complete"})
    return SofElkSourceResult(
        manifest=manifest,
        output_dir=parsed_dir,
        pipeline_log_dir=pipeline_log_dir,
        events=events,
        logstash_config_tested=True,
    )


def validate_source_parsed_output(
    manifest: SofElkSourceManifest,
    parsed_dir: Path,
    progress_callback: ProgressCallback = _noop_progress,
) -> list[JsonObject]:
    """Validate SOF-ELK JSONL output for a staged non-Zeek source run."""
    spec = manifest.spec
    output_path = parsed_dir / EVENTS_OUTPUT_FILENAME
    events = _read_jsonl(output_path) if output_path.exists() else []
    failures: list[str] = []
    failure_events: list[JsonObject] = []

    if len(events) != manifest.expected_count:
        failures.append(
            f"{spec.format_name}: expected {manifest.expected_count} parsed events, "
            f"got {len(events)}"
        )

    scope_by_container_path = _scope_by_container_path(manifest)
    fallback_scope = _scope_for_staged_log(manifest, manifest.logs[0])
    expected_by_host, expected_by_logtype, expected_by_subtype = _scope_expected_counts(manifest)
    completed_by_host: Counter[str] = Counter()
    completed_by_logtype: Counter[tuple[str, str]] = Counter()
    completed_by_subtype: Counter[ScopeKey] = Counter()

    for index, event in enumerate(events, start=1):
        scope = _event_scope(event, scope_by_container_path, fallback_scope)
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
        expected_year = _source_year_for_event(manifest, event)
        event_failures = _event_failures(spec, index, event, expected_year)
        failures.extend(event_failures)
        if event_failures:
            failure_events.append(_failure_event_summary(spec, index, event, event_failures))

    if failures:
        report_path = _write_failure_report(manifest, parsed_dir, events, failures, failure_events)
        details = "\n- ".join(failures[:FAILURE_DETAIL_LIMIT])
        omitted_count = len(failures) - FAILURE_DETAIL_LIMIT
        omitted = f"\n- ... {omitted_count} additional failure(s)" if omitted_count > 0 else ""
        raise SofElkParserError(
            "SOF-ELK parser validation failed; "
            f"failure report written to {report_path}:\n- {details}{omitted}"
        )

    return events


def _event_failures(
    spec: SofElkSourceSpec,
    index: int,
    event: JsonObject,
    expected_year: int | None = None,
) -> list[str]:
    failures: list[str] = []
    prefix = f"{spec.format_name} event {index}"

    tags = event.get("tags", [])
    if not isinstance(tags, list):
        failures.append(f"{prefix}: tags is not a list")
        tags = []
    failure_tags = _failure_tags(spec, event, tags)
    if failure_tags:
        failures.append(f"{prefix}: parser failure tags present: {', '.join(failure_tags)}")

    event_tag_set = {str(tag) for tag in tags}
    for tag in spec.required_tags:
        if tag not in event_tag_set:
            failures.append(f"{prefix}: missing required parser tag {tag}")

    for path in spec.required_paths:
        if _get_path(event, path) in (None, ""):
            failures.append(f"{prefix}: missing required field {path}")

    if expected_year is not None:
        timestamp = event.get("@timestamp")
        parsed_year = _event_timestamp_year(timestamp)
        if parsed_year != expected_year:
            failures.append(
                f"{prefix}: parsed @timestamp year {parsed_year} does not match "
                f"source year {expected_year}"
            )

    return failures


def _write_failure_report(
    manifest: SofElkSourceManifest,
    parsed_dir: Path,
    events: list[JsonObject],
    failures: list[str],
    failure_events: list[JsonObject],
) -> Path:
    spec = manifest.spec
    report_path = parsed_dir / FAILURE_REPORT_FILENAME
    report = {
        "expected_counts": manifest.expected_counts,
        "observed_counts": {spec.format_name: len(events)},
        "parsed_outputs": {spec.format_name: str(parsed_dir / EVENTS_OUTPUT_FILENAME)},
        "log_support": {
            spec.format_name: {
                "validator": spec.validator,
                "sof_elk_filebeat_input": spec.filebeat_input,
                "sof_elk_filter_files": list(spec.filter_files),
                "output_label_type": spec.output_label_type,
            }
        },
        "staged_logs": [
            {
                "source": str(log.source),
                "staged": str(log.staged),
                "log_type": spec.format_name,
                "record_count": log.record_count,
                "source_year": log.source_year,
            }
            for log in manifest.logs
        ],
        "failure_count": len(failures),
        "failure_tag_counts": {
            spec.format_name: _failure_tag_counts(spec, events),
        },
        "sample_failures": failure_events[:FAILURE_DETAIL_LIMIT],
    }
    report_path.write_text(
        json.dumps(report, indent=2, sort_keys=True),
        encoding="utf-8",
    )
    return report_path


def _failure_event_summary(
    spec: SofElkSourceSpec,
    index: int,
    event: JsonObject,
    failures: list[str],
) -> JsonObject:
    tags = event.get("tags", [])
    return {
        "log_type": spec.format_name,
        "event_index": index,
        "failures": failures,
        "tags": _failure_tags(spec, event, tags) if isinstance(tags, list) else tags,
        "log_file_path": _get_path(event, "log.file.path"),
        "event_original": _get_path(event, "event.original"),
        "message": event.get("message"),
        "timestamp": event.get("@timestamp"),
        "syslog_hostname": _get_path(event, "log.syslog.hostname"),
        "syslog_appname": _get_path(event, "log.syslog.appname"),
        "source_ip": _get_path(event, "source.ip"),
        "source_port": _get_path(event, "source.port"),
        "destination_ip": _get_path(event, "destination.ip"),
        "destination_port": _get_path(event, "destination.port"),
        "network_transport": _get_path(event, "network.transport"),
        "cisco_asa_action": _get_path(event, "cisco.asa.action"),
        "cisco_asa_connection_id": _get_path(event, "cisco.asa.connection_id"),
        "http_method": _get_path(event, "http.request.method"),
        "http_status_code": _get_path(event, "http.response.status_code"),
        "url_path": _get_path(event, "url.path"),
        "winlog_event_id": _get_path(event, "winlog.event_id"),
        "winlog_provider_name": _get_path(event, "winlog.provider_name"),
        "winlog_channel": _get_path(event, "winlog.channel"),
        "winlog_computer_name": _get_path(event, "winlog.computer_name"),
    }


def _failure_tag_counts(
    spec: SofElkSourceSpec,
    events: list[JsonObject],
) -> dict[str, int]:
    counts: Counter[str] = Counter()
    for event in events:
        tags = event.get("tags", [])
        if isinstance(tags, list):
            counts.update(_failure_tags(spec, event, tags))
    return dict(sorted(counts.items()))


def _failure_tags(spec: SofElkSourceSpec, event: JsonObject, tags: list[Any]) -> list[str]:
    return list(
        classify_parser_tags(
            validator=spec.validator,
            log_type=spec.format_name,
            tags=tags,
            event=event,
        ).fatal
    )


def _scope_by_container_path(manifest: SofElkSourceManifest) -> dict[str, ScopeKey]:
    return {
        _container_log_path(manifest, log): _scope_for_staged_log(manifest, log)
        for log in manifest.logs
    }


def _source_year_by_container_path(manifest: SofElkSourceManifest) -> dict[str, int]:
    return {
        _container_log_path(manifest, log): log.source_year
        for log in manifest.logs
        if log.source_year is not None
    }


def _source_year_for_event(manifest: SofElkSourceManifest, event: JsonObject) -> int | None:
    log_file_path = _get_path(event, "log.file.path")
    if not isinstance(log_file_path, str):
        return None
    return _source_year_by_container_path(manifest).get(log_file_path)


def _scope_expected_counts(
    manifest: SofElkSourceManifest,
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


def _scope_for_staged_log(
    manifest: SofElkSourceManifest,
    log: StagedSourceLog,
) -> ScopeKey:
    relative = log.staged.relative_to(manifest.logstash_root)
    parts = relative.parts
    if (
        manifest.spec.staged_directory == "syslog"
        and len(parts) >= 4
        and parts[0] == "syslog"
        and _is_year_component(parts[1])
    ):
        host = parts[2]
    else:
        host = (
            parts[1]
            if len(parts) >= 3 and parts[0] == manifest.spec.staged_directory
            else str(relative.parent)
        )
    return host, manifest.spec.logtype, manifest.spec.subtype


def _container_log_path(manifest: SofElkSourceManifest, log: StagedSourceLog) -> str:
    return f"/logstash/{log.staged.relative_to(manifest.logstash_root).as_posix()}"


def _event_timestamp_year(value: Any) -> int | None:
    if not isinstance(value, str) or len(value) < 4:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(UTC).year
    except ValueError:
        return None


def _event_scope(
    event: JsonObject,
    scope_by_container_path: dict[str, ScopeKey],
    fallback_scope: ScopeKey,
) -> ScopeKey:
    log_file_path = _get_path(event, "log.file.path")
    if isinstance(log_file_path, str):
        return scope_by_container_path.get(log_file_path, fallback_scope)
    return fallback_scope


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


def _safe_stage_source(source_root: Path, source: Path) -> Path:
    """Return a resolved source path that is safe to copy into parser staging."""
    if source.is_symlink():
        raise SofElkHarnessError(f"refusing to stage symlinked generated log file: {source}")

    resolved = source.resolve(strict=True)
    try:
        resolved.relative_to(source_root)
    except ValueError as exc:
        raise SofElkHarnessError(
            f"refusing to stage generated log file outside generated output root {source_root}: "
            f"{source} -> {resolved}"
        ) from exc
    return resolved


def _source_name(source_root: Path, source: Path) -> str:
    source_parent = source.parent
    if _is_year_component(source_parent.name) and source_parent.parent != source_parent:
        source_parent = source_parent.parent
    relative = source_parent.relative_to(source_root)
    if relative == Path("."):
        return "default"
    return "__".join(relative.parts)


def _source_year(source: Path) -> int | None:
    if _is_year_component(source.parent.name):
        return int(source.parent.name)
    return _infer_year_from_first_record(source)


def _infer_year_from_first_record(source: Path) -> int | None:
    try:
        with source.open(encoding="utf-8") as handle:
            first = next((line.strip() for line in handle if line.strip()), "")
    except OSError:
        return None
    match = re.search(r"\b(?P<year>20\d{2})-\d{2}-\d{2}T", first)
    if match:
        return int(match.group("year"))
    try:
        return datetime.fromtimestamp(source.stat().st_mtime, tz=UTC).year
    except OSError:
        return None


def _is_year_component(value: str) -> bool:
    return re.fullmatch(r"\d{4}", value) is not None
