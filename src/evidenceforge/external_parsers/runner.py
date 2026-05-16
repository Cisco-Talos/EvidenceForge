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

"""Discovery helpers for external parser validation."""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path

from evidenceforge.external_parsers.sof_elk_sources import SOF_ELK_SOURCE_SPECS_BY_VALIDATOR
from evidenceforge.external_parsers.sof_elk_zeek import ZEEK_LOG_SPECS
from evidenceforge.external_parsers.tag_policy import (
    SOF_ELK_CISCO_ASA_VALIDATOR,
    SOF_ELK_WEB_ACCESS_VALIDATOR,
    SOF_ELK_ZEEK_VALIDATOR,
)

VALIDATOR_ORDER = (
    SOF_ELK_ZEEK_VALIDATOR,
    SOF_ELK_CISCO_ASA_VALIDATOR,
    SOF_ELK_WEB_ACCESS_VALIDATOR,
)

_LOG_FILE_SUFFIXES = {".alert", ".bash_history", ".history", ".json", ".log", ".xml"}
_UNSUPPORTED_FILE_PATTERNS: tuple[tuple[str, str, str, str], ...] = (
    ("windows_event_security.xml", "windows events", "security", "windows_event_security"),
    ("windows_event_sysmon.xml", "windows events", "sysmon", "windows_event_sysmon"),
    ("syslog.log", "syslog", "linux", "syslog"),
    ("snort_alert.log", "ids", "snort", "snort_alert"),
    ("proxy_access.log", "proxy", "access", "proxy_access"),
    ("ecar.json", "ecar", "ecar", "ecar"),
)


@dataclass(frozen=True)
class DetectedLog:
    """A generated log file found under a data directory."""

    path: Path
    host: str
    logtype: str
    subtype: str
    format_name: str | None
    validator: str | None

    @property
    def supported(self) -> bool:
        """Return whether an external parser validator exists for this log."""
        return self.validator is not None


@dataclass(frozen=True)
class ExternalParserPlan:
    """Discovered external parser work for a generated data directory."""

    data_dir: Path
    logs: tuple[DetectedLog, ...]
    validators: tuple[str, ...]

    @property
    def supported_logs(self) -> tuple[DetectedLog, ...]:
        """Return logs that have an external parser validator."""
        return tuple(log for log in self.logs if log.supported)

    @property
    def unsupported_logs(self) -> tuple[DetectedLog, ...]:
        """Return logs that do not yet have an external parser validator."""
        return tuple(log for log in self.logs if not log.supported)


ProgressGroups = dict[str, dict[str, dict[str, list[DetectedLog]]]]


def detect_external_parser_plan(data_dir: Path) -> ExternalParserPlan:
    """Detect generated logs and matching external parser validators.

    Args:
        data_dir: Generated EvidenceForge `data/` directory.

    Returns:
        External parser plan with matching validators and unsupported logs.
    """
    data_dir = data_dir.resolve()
    logs_by_path: dict[Path, DetectedLog] = {}

    for spec in ZEEK_LOG_SPECS:
        subtype = spec.staged_name.removesuffix(".log")
        for source_name in spec.source_names:
            for path in sorted(data_dir.rglob(source_name)):
                _add_detected_log(
                    logs_by_path,
                    data_dir=data_dir,
                    path=path,
                    logtype="zeek",
                    subtype=subtype,
                    format_name=spec.log_type,
                    validator=SOF_ELK_ZEEK_VALIDATOR,
                )

    for spec in SOF_ELK_SOURCE_SPECS_BY_VALIDATOR.values():
        for source_name in spec.source_names:
            for path in sorted(data_dir.rglob(source_name)):
                _add_detected_log(
                    logs_by_path,
                    data_dir=data_dir,
                    path=path,
                    logtype=spec.logtype,
                    subtype=spec.subtype,
                    format_name=spec.format_name,
                    validator=spec.validator,
                )

    for filename, logtype, subtype, format_name in _UNSUPPORTED_FILE_PATTERNS:
        for path in sorted(data_dir.rglob(filename)):
            _add_detected_log(
                logs_by_path,
                data_dir=data_dir,
                path=path,
                logtype=logtype,
                subtype=subtype,
                format_name=format_name,
                validator=None,
            )

    for path in sorted(data_dir.rglob("*.bash_history")):
        _add_detected_log(
            logs_by_path,
            data_dir=data_dir,
            path=path,
            logtype="bash history",
            subtype="bash_history",
            format_name="bash_history",
            validator=None,
        )

    for path in _candidate_log_files(data_dir):
        if path not in logs_by_path:
            _add_detected_log(
                logs_by_path,
                data_dir=data_dir,
                path=path,
                logtype="unknown",
                subtype=path.name,
                format_name=None,
                validator=None,
            )

    logs = tuple(
        sorted(
            logs_by_path.values(),
            key=lambda log: (log.host, log.logtype, log.subtype, str(log.path)),
        )
    )
    discovered_validators = {log.validator for log in logs if log.validator is not None}
    validators = tuple(
        validator for validator in VALIDATOR_ORDER if validator in discovered_validators
    )
    return ExternalParserPlan(data_dir=data_dir, logs=logs, validators=validators)


def group_logs_for_progress(logs: tuple[DetectedLog, ...]) -> ProgressGroups:
    """Group detected logs by host, log type, and subtype for progress displays."""
    grouped: ProgressGroups = defaultdict(lambda: defaultdict(lambda: defaultdict(list)))
    for log in logs:
        grouped[log.host][log.logtype][log.subtype].append(log)
    return {
        host: {
            logtype: {subtype: list(files) for subtype, files in sorted(subtypes.items())}
            for logtype, subtypes in sorted(logtypes.items())
        }
        for host, logtypes in sorted(grouped.items())
    }


def unsupported_summary(logs: tuple[DetectedLog, ...]) -> dict[str, list[str]]:
    """Summarize unsupported logs by log type for warning output."""
    summary: dict[str, set[str]] = defaultdict(set)
    for log in logs:
        if not log.supported:
            summary[log.logtype].add(log.subtype)
    return {logtype: sorted(subtypes) for logtype, subtypes in sorted(summary.items())}


def _add_detected_log(
    logs_by_path: dict[Path, DetectedLog],
    *,
    data_dir: Path,
    path: Path,
    logtype: str,
    subtype: str,
    format_name: str | None,
    validator: str | None,
) -> None:
    path = path.resolve()
    logs_by_path[path] = DetectedLog(
        path=path,
        host=_host_for_path(data_dir, path),
        logtype=logtype,
        subtype=subtype,
        format_name=format_name,
        validator=validator,
    )


def _candidate_log_files(data_dir: Path) -> tuple[Path, ...]:
    return tuple(
        sorted(
            path.resolve()
            for path in data_dir.rglob("*")
            if path.is_file() and path.suffix in _LOG_FILE_SUFFIXES
        )
    )


def _host_for_path(data_dir: Path, path: Path) -> str:
    relative = path.relative_to(data_dir)
    if len(relative.parts) == 1:
        return "default"
    if len(relative.parts) >= 3 and relative.parts[-2] == "bash_history":
        return relative.parts[0]
    return str(relative.parent)
