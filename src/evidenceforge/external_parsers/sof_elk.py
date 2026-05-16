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

"""Combined SOF-ELK parser harness for generated EvidenceForge data."""

from __future__ import annotations

import json
from collections import Counter
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from evidenceforge.external_parsers.compose_runtime import (
    SofElkGeneratedConfig,
    build_generated_config,
    create_compose_run,
    run_sof_elk_compose,
)
from evidenceforge.external_parsers.runner import VALIDATOR_ORDER
from evidenceforge.external_parsers.sof_elk_sources import (
    SOF_ELK_SOURCE_SPECS_BY_VALIDATOR,
    SofElkSourceManifest,
    StagedSourceLog,
    _source_year_for_event,
    stage_source_logs,
)
from evidenceforge.external_parsers.sof_elk_sources import (
    _event_failures as _source_event_failures,
)
from evidenceforge.external_parsers.sof_elk_sources import (
    _failure_event_summary as _source_failure_event_summary,
)
from evidenceforge.external_parsers.sof_elk_sources import (
    _failure_tag_counts as _source_failure_tag_counts,
)
from evidenceforge.external_parsers.sof_elk_zeek import (
    FAILURE_DETAIL_LIMIT,
    FAILURE_REPORT_FILENAME,
    FILEBEAT_IMAGE,
    LOGSTASH_IMAGE,
    SOF_ELK_COMMIT,
    SOF_ELK_FILTER_FILES,
    SOF_ELK_REPO_URL,
    SOF_ELK_ZEEK_VALIDATOR,
    SofElkHarnessError,
    SofElkParserError,
    StagedLog,
    ZeekStageManifest,
    _dns_failure_qtype_counts,
    _get_path,
    _noop_progress,
    _read_jsonl,
    _supplemental_filebeat_inputs,
    stage_zeek_logs,
)
from evidenceforge.external_parsers.sof_elk_zeek import (
    LOG_TYPES as ZEEK_LOG_TYPES,
)
from evidenceforge.external_parsers.sof_elk_zeek import (
    _event_failures as _zeek_event_failures,
)
from evidenceforge.external_parsers.sof_elk_zeek import (
    _failure_event_summary as _zeek_failure_event_summary,
)
from evidenceforge.external_parsers.sof_elk_zeek import (
    _failure_tag_counts as _zeek_failure_tag_counts,
)

JsonObject = dict[str, Any]
ProgressCallback = Callable[[str, dict[str, Any]], None]
ScopeKey = tuple[str, str, str]

COMBINED_VALIDATOR_NAME = "SOF-ELK"
COMBINED_CONTAINER_LABEL = "evidenceforge.external_parser=sof-elk"


@dataclass(frozen=True)
class SofElkCombinedManifest:
    """Manifest for a single SOF-ELK run containing multiple log families."""

    logstash_root: Path
    validators: tuple[str, ...]
    zeek: ZeekStageManifest | None
    sources: tuple[SofElkSourceManifest, ...]

    @property
    def expected_counts(self) -> dict[str, int]:
        """Return expected parsed counts by EvidenceForge format name."""
        counts: dict[str, int] = {}
        if self.zeek is not None:
            counts.update(self.zeek.expected_counts)
        for manifest in self.sources:
            counts.update(manifest.expected_counts)
        return counts

    @property
    def expected_output_counts(self) -> dict[str, int]:
        """Return expected parsed counts by SOF-ELK output label type."""
        counts: Counter[str] = Counter()
        if self.zeek is not None:
            counts.update(self.zeek.expected_counts)
        for manifest in self.sources:
            counts[manifest.spec.output_label_type] += manifest.expected_count
        return dict(sorted(counts.items()))

    @property
    def staged_logs(self) -> tuple[StagedLog | StagedSourceLog, ...]:
        """Return all staged logs in this combined run."""
        logs: list[StagedLog | StagedSourceLog] = []
        if self.zeek is not None:
            logs.extend(self.zeek.logs)
        for manifest in self.sources:
            logs.extend(manifest.logs)
        return tuple(logs)


@dataclass(frozen=True)
class SofElkCombinedResult:
    """Summary returned by a successful combined SOF-ELK parser run."""

    manifest: SofElkCombinedManifest
    output_dir: Path
    pipeline_log_dir: Path
    events_by_type: dict[str, list[JsonObject]]
    logstash_config_tested: bool


def run_sof_elk_parser(
    source_root: Path,
    work_dir: Path,
    *,
    validators: tuple[str, ...],
    timeout_seconds: int = 120,
    runtime: str | None = None,
    progress_callback: ProgressCallback = _noop_progress,
) -> SofElkCombinedResult:
    """Run one Filebeat/Logstash pair for all selected SOF-ELK validators."""
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

    selected_validators = _ordered_validators(validators)
    progress_callback("validator_step", {"description": "Staging files"})
    manifest = stage_sof_elk_logs(source_root, staging_dir, selected_validators)
    progress_callback("validator_step", {"description": "Building runtime config"})
    generated_config = build_sof_elk_configs(work_dir, manifest)
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
        container_label=COMBINED_CONTAINER_LABEL,
    )
    run_sof_elk_compose(
        compose_run,
        expected_output_counts=manifest.expected_output_counts,
        parsed_dir=parsed_dir,
        pipeline_log_dir=pipeline_log_dir,
        timeout_seconds=timeout_seconds,
        progress_callback=progress_callback,
    )
    progress_callback("validator_step", {"description": "Checking parsed output"})
    try:
        events_by_type = validate_sof_elk_output(
            manifest,
            parsed_dir,
            progress_callback=progress_callback,
        )
    except SofElkParserError:
        progress_callback("validator_done", {"description": "SOF-ELK failed"})
        raise
    progress_callback("validator_done", {"description": "SOF-ELK complete"})
    return SofElkCombinedResult(
        manifest=manifest,
        output_dir=parsed_dir,
        pipeline_log_dir=pipeline_log_dir,
        events_by_type=events_by_type,
        logstash_config_tested=True,
    )


def stage_sof_elk_logs(
    source_root: Path,
    staging_root: Path,
    validators: tuple[str, ...],
) -> SofElkCombinedManifest:
    """Stage all selected SOF-ELK-supported logs into one `/logstash` tree."""
    staging_root = staging_root.resolve()
    logstash_root = staging_root / "logstash"
    zeek_manifest: ZeekStageManifest | None = None
    source_manifests: list[SofElkSourceManifest] = []

    if SOF_ELK_ZEEK_VALIDATOR in validators:
        zeek_manifest = stage_zeek_logs(source_root, staging_root)
        logstash_root = zeek_manifest.logstash_root

    for validator in validators:
        spec = SOF_ELK_SOURCE_SPECS_BY_VALIDATOR.get(validator)
        if spec is None:
            continue
        manifest = stage_source_logs(source_root, staging_root, spec)
        logstash_root = manifest.logstash_root
        source_manifests.append(manifest)

    if zeek_manifest is None and not source_manifests:
        raise SofElkHarnessError("no selected SOF-ELK validators can stage this dataset")

    return SofElkCombinedManifest(
        logstash_root=logstash_root,
        validators=validators,
        zeek=zeek_manifest,
        sources=tuple(source_manifests),
    )


def build_sof_elk_configs(
    work_dir: Path,
    manifest: SofElkCombinedManifest,
) -> SofElkGeneratedConfig:
    """Build host-side EvidenceForge-owned config inputs for one SOF-ELK run."""
    filebeat_inputs: list[str] = []
    supplemental_inputs = ""
    if manifest.zeek is not None:
        filebeat_inputs.append("zeek.yml")
        supplemental_inputs = _supplemental_filebeat_inputs()
    for source_manifest in manifest.sources:
        filebeat_inputs.append(source_manifest.spec.filebeat_input)

    return build_generated_config(
        work_dir,
        sof_elk_filter_files=_combined_filter_files(manifest),
        sof_elk_filebeat_inputs=tuple(dict.fromkeys(filebeat_inputs)),
        supplemental_filebeat_inputs=supplemental_inputs,
    )


def validate_sof_elk_output(
    manifest: SofElkCombinedManifest,
    parsed_dir: Path,
    progress_callback: ProgressCallback = _noop_progress,
) -> dict[str, list[JsonObject]]:
    """Validate combined SOF-ELK output and write one failure report if needed."""
    output_events = _read_output_events(manifest, parsed_dir)
    events_by_type: dict[str, list[JsonObject]] = {}
    failures: list[str] = []
    failure_events: list[JsonObject] = []
    progress_state = _ProgressState.from_manifest(manifest)

    if manifest.zeek is not None:
        for log_type, expected_count in manifest.zeek.expected_counts.items():
            events = output_events.get(log_type, [])
            events_by_type[log_type] = events
            if len(events) != expected_count:
                failures.append(
                    f"{log_type}: expected {expected_count} parsed events, got {len(events)}"
                )
            for index, event in enumerate(events, start=1):
                progress_state.update(event, log_type, progress_callback)
                event_failures = _zeek_event_failures(log_type, index, event, manifest.zeek)
                failures.extend(event_failures)
                if event_failures:
                    failure_events.append(
                        _zeek_failure_event_summary(log_type, index, event, event_failures)
                    )

    for source_manifest in manifest.sources:
        spec = source_manifest.spec
        source_events = _source_events_for_manifest(
            output_events.get(spec.output_label_type, []),
            source_manifest,
        )
        events_by_type[spec.format_name] = source_events
        if len(source_events) != source_manifest.expected_count:
            failures.append(
                f"{spec.format_name}: expected {source_manifest.expected_count} parsed events, "
                f"got {len(source_events)}"
            )
        for index, event in enumerate(source_events, start=1):
            progress_state.update(event, spec.format_name, progress_callback)
            expected_year = _source_year_for_event(source_manifest, event)
            event_failures = _source_event_failures(spec, index, event, expected_year)
            failures.extend(event_failures)
            if event_failures:
                failure_events.append(
                    _source_failure_event_summary(spec, index, event, event_failures)
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


@dataclass
class _ProgressState:
    scope_by_container_path: dict[str, ScopeKey]
    fallback_scope_by_format: dict[str, ScopeKey]
    expected_by_host: Counter[str]
    expected_by_logtype: Counter[tuple[str, str]]
    expected_by_subtype: Counter[ScopeKey]
    completed_by_host: Counter[str]
    completed_by_logtype: Counter[tuple[str, str]]
    completed_by_subtype: Counter[ScopeKey]

    @classmethod
    def from_manifest(cls, manifest: SofElkCombinedManifest) -> _ProgressState:
        scope_by_container_path: dict[str, ScopeKey] = {}
        fallback_scope_by_format: dict[str, ScopeKey] = {}
        expected_by_host: Counter[str] = Counter()
        expected_by_logtype: Counter[tuple[str, str]] = Counter()
        expected_by_subtype: Counter[ScopeKey] = Counter()

        if manifest.zeek is not None:
            for log in manifest.zeek.logs:
                scope = _zeek_scope(manifest.zeek, log)
                scope_by_container_path[_container_log_path(manifest.logstash_root, log.staged)] = (
                    scope
                )
                fallback_scope_by_format.setdefault(log.log_type, scope)
                _add_expected_scope(
                    scope,
                    log.record_count,
                    expected_by_host,
                    expected_by_logtype,
                    expected_by_subtype,
                )

        for source_manifest in manifest.sources:
            for log in source_manifest.logs:
                scope = _source_scope(source_manifest, log)
                scope_by_container_path[_container_log_path(manifest.logstash_root, log.staged)] = (
                    scope
                )
                fallback_scope_by_format.setdefault(source_manifest.spec.format_name, scope)
                _add_expected_scope(
                    scope,
                    log.record_count,
                    expected_by_host,
                    expected_by_logtype,
                    expected_by_subtype,
                )

        return cls(
            scope_by_container_path=scope_by_container_path,
            fallback_scope_by_format=fallback_scope_by_format,
            expected_by_host=expected_by_host,
            expected_by_logtype=expected_by_logtype,
            expected_by_subtype=expected_by_subtype,
            completed_by_host=Counter(),
            completed_by_logtype=Counter(),
            completed_by_subtype=Counter(),
        )

    def update(
        self,
        event: JsonObject,
        format_name: str,
        progress_callback: ProgressCallback,
    ) -> None:
        scope = self._event_scope(event, format_name)
        if scope is None:
            return
        host, logtype, subtype = scope
        self.completed_by_host[host] += 1
        self.completed_by_logtype[(host, logtype)] += 1
        self.completed_by_subtype[scope] += 1
        progress_callback(
            "validator_scope_progress",
            {
                "host": host,
                "host_completed": self.completed_by_host[host],
                "host_total": self.expected_by_host[host],
                "logtype": logtype,
                "logtype_completed": self.completed_by_logtype[(host, logtype)],
                "logtype_total": self.expected_by_logtype[(host, logtype)],
                "subtype": subtype,
                "subtype_completed": self.completed_by_subtype[scope],
                "subtype_total": self.expected_by_subtype[scope],
            },
        )

    def _event_scope(self, event: JsonObject, format_name: str) -> ScopeKey | None:
        log_file_path = _get_path(event, "log.file.path")
        if isinstance(log_file_path, str) and log_file_path in self.scope_by_container_path:
            return self.scope_by_container_path[log_file_path]
        return self.fallback_scope_by_format.get(format_name)


def _write_failure_report(
    manifest: SofElkCombinedManifest,
    parsed_dir: Path,
    events_by_type: dict[str, list[JsonObject]],
    failures: list[str],
    failure_events: list[JsonObject],
) -> Path:
    report_path = parsed_dir / FAILURE_REPORT_FILENAME
    report = {
        "expected_counts": manifest.expected_counts,
        "observed_counts": {
            format_name: len(events_by_type.get(format_name, []))
            for format_name in manifest.expected_counts
        },
        "expected_output_counts": manifest.expected_output_counts,
        "parsed_outputs": _parsed_output_paths(manifest, parsed_dir),
        "log_support": _log_support(manifest),
        "staged_logs": _staged_log_report(manifest),
        "failure_count": len(failures),
        "failure_tag_counts": _failure_tag_counts(manifest, events_by_type),
        "dns_failure_qtype_counts": (
            _dns_failure_qtype_counts(events_by_type) if events_by_type.get("zeek_dns") else {}
        ),
        "sample_failures": failure_events[:FAILURE_DETAIL_LIMIT],
    }
    report_path.write_text(
        json.dumps(report, indent=2, sort_keys=True),
        encoding="utf-8",
    )
    return report_path


def _ordered_validators(validators: tuple[str, ...]) -> tuple[str, ...]:
    requested = set(validators)
    return tuple(validator for validator in VALIDATOR_ORDER if validator in requested)


def _combined_filter_files(manifest: SofElkCombinedManifest) -> tuple[str, ...]:
    filters: set[str] = set()
    if manifest.zeek is not None:
        filters.update(SOF_ELK_FILTER_FILES)
    for source_manifest in manifest.sources:
        filters.update(source_manifest.spec.filter_files)
    return tuple(sorted(filters))


def _read_output_events(
    manifest: SofElkCombinedManifest,
    parsed_dir: Path,
) -> dict[str, list[JsonObject]]:
    events_by_output: dict[str, list[JsonObject]] = {}
    for output_type in manifest.expected_output_counts:
        output_path = parsed_dir / f"{output_type}.jsonl"
        events_by_output[output_type] = _read_jsonl(output_path) if output_path.exists() else []
    return events_by_output


def _source_events_for_manifest(
    events: list[JsonObject],
    manifest: SofElkSourceManifest,
) -> list[JsonObject]:
    source_paths = {
        _container_log_path(manifest.logstash_root, log.staged) for log in manifest.logs
    }
    return [
        event
        for event in events
        if isinstance(_get_path(event, "log.file.path"), str)
        and _get_path(event, "log.file.path") in source_paths
    ]


def _add_expected_scope(
    scope: ScopeKey,
    count: int,
    expected_by_host: Counter[str],
    expected_by_logtype: Counter[tuple[str, str]],
    expected_by_subtype: Counter[ScopeKey],
) -> None:
    host, logtype, _subtype = scope
    expected_by_host[host] += count
    expected_by_logtype[(host, logtype)] += count
    expected_by_subtype[scope] += count


def _zeek_scope(manifest: ZeekStageManifest, log: StagedLog) -> ScopeKey:
    relative = log.staged.relative_to(manifest.logstash_root)
    parts = relative.parts
    host = parts[1] if len(parts) >= 3 and parts[0] == "zeek" else str(relative.parent)
    subtype = Path(parts[-1]).stem
    return host, "zeek", subtype


def _source_scope(manifest: SofElkSourceManifest, log: StagedSourceLog) -> ScopeKey:
    relative = log.staged.relative_to(manifest.logstash_root)
    parts = relative.parts
    if (
        manifest.spec.staged_directory == "syslog"
        and len(parts) >= 4
        and parts[0] == "syslog"
        and parts[1].isdigit()
        and len(parts[1]) == 4
    ):
        host = parts[2]
    else:
        host = (
            parts[1]
            if len(parts) >= 3 and parts[0] == manifest.spec.staged_directory
            else str(relative.parent)
        )
    return host, manifest.spec.logtype, manifest.spec.subtype


def _container_log_path(logstash_root: Path, staged: Path) -> str:
    return f"/logstash/{staged.relative_to(logstash_root).as_posix()}"


def _parsed_output_paths(
    manifest: SofElkCombinedManifest,
    parsed_dir: Path,
) -> dict[str, str]:
    paths: dict[str, str] = {}
    if manifest.zeek is not None:
        for log_type in manifest.zeek.expected_counts:
            paths[log_type] = str(parsed_dir / f"{log_type}.jsonl")
    for source_manifest in manifest.sources:
        paths[source_manifest.spec.format_name] = str(
            parsed_dir / f"{source_manifest.spec.output_label_type}.jsonl"
        )
    return paths


def _log_support(manifest: SofElkCombinedManifest) -> dict[str, dict[str, Any]]:
    support: dict[str, dict[str, Any]] = {}
    if manifest.zeek is not None:
        for spec in manifest.zeek.logs:
            if spec.log_type in support:
                continue
            zeek_spec = _zeek_log_spec(spec.log_type)
            support[spec.log_type] = {
                "validator": SOF_ELK_ZEEK_VALIDATOR,
                "sof_elk_dedicated_filter": zeek_spec.sof_elk_dedicated_filter,
                "sof_elk_filebeat_input": zeek_spec.sof_elk_filebeat_input,
            }
    for source_manifest in manifest.sources:
        spec = source_manifest.spec
        support[spec.format_name] = {
            "validator": spec.validator,
            "sof_elk_filebeat_input": spec.filebeat_input,
            "sof_elk_filter_files": list(spec.filter_files),
            "output_label_type": spec.output_label_type,
        }
    return support


def _zeek_log_spec(log_type: str) -> Any:
    from evidenceforge.external_parsers.sof_elk_zeek import LOG_SPECS_BY_TYPE

    return LOG_SPECS_BY_TYPE[log_type]


def _staged_log_report(manifest: SofElkCombinedManifest) -> list[JsonObject]:
    logs: list[JsonObject] = []
    if manifest.zeek is not None:
        logs.extend(
            {
                "source": str(log.source),
                "staged": str(log.staged),
                "log_type": log.log_type,
                "record_count": log.record_count,
            }
            for log in manifest.zeek.logs
        )
    for source_manifest in manifest.sources:
        logs.extend(
            {
                "source": str(log.source),
                "staged": str(log.staged),
                "log_type": source_manifest.spec.format_name,
                "record_count": log.record_count,
                "source_year": log.source_year,
            }
            for log in source_manifest.logs
        )
    return logs


def _failure_tag_counts(
    manifest: SofElkCombinedManifest,
    events_by_type: dict[str, list[JsonObject]],
) -> dict[str, dict[str, int]]:
    counts: dict[str, dict[str, int]] = {}
    if manifest.zeek is not None:
        counts.update(
            _zeek_failure_tag_counts(
                events_by_type,
                tuple(log_type for log_type in ZEEK_LOG_TYPES if log_type in events_by_type),
            )
        )
    for source_manifest in manifest.sources:
        spec = source_manifest.spec
        counts[spec.format_name] = _source_failure_tag_counts(
            spec,
            events_by_type.get(spec.format_name, []),
        )
    return counts
