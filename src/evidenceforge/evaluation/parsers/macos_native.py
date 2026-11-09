# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Bounded native Mac export ingestion, independent of generator admission.

Only explicitly named NDJSON exports are discovered. Native IDs, privacy
markers, optional fields and nested event roles remain source-native. A file's
directory supplies source-instance provenance through the evaluation engine;
the native record does not establish a hostname or username.
"""

from collections.abc import Iterator
from datetime import datetime
from pathlib import Path
from typing import Any

from pydantic import ValidationError

from evidenceforge.formats.macos_endpoint_security import decode_endpoint_security_record
from evidenceforge.formats.macos_unified_log import (
    UnifiedLogCompletion,
    decode_unified_log_record,
)

from . import LogParser, ParsedRecord, iter_bounded_text_lines, register_parser
from .json_record import decode_record


def _diagnostic(error: ValueError) -> str:
    """Report bounded structural failures without echoing native record contents."""
    if isinstance(error, ValidationError):
        return "; ".join(
            f"{'.'.join(str(part) for part in item['loc']) or 'record'}: {item['msg']}"
            for item in error.errors(include_input=False, include_context=False)[:8]
        )
    return str(error)


@register_parser
class MacosUnifiedLogParser(LogParser):
    """Read selected logEvent exports and exclude valid completion bookkeeping."""

    format_name = "macos_unified_log"

    def can_parse(self, path: Path) -> bool:
        """Avoid interpreting unrelated JSON or native archive files as exports."""
        return path.name == "macos_unified_log.ndjson"

    def parse_file(self, path: Path) -> Iterator[ParsedRecord]:
        """Yield events or explicit diagnostics, never a successful completion row."""
        completed = False
        for line_number, line in iter_bounded_text_lines(path):
            raw = line.strip()
            if not raw:
                continue
            fields: dict[str, Any] = {}
            timestamp: datetime | None = None
            errors: list[str] = []
            try:
                fields = decode_record(raw)
                if completed:
                    raise ValueError("Record follows Unified Log export completion")
                native = decode_unified_log_record(raw)
                if isinstance(native, UnifiedLogCompletion):
                    completed = True
                    continue
                timestamp = native.event_time
            except ValueError as exc:
                errors.append(_diagnostic(exc))
            yield ParsedRecord(
                source_format=self.format_name,
                raw=raw,
                fields=fields,
                timestamp=timestamp,
                parse_errors=errors,
                line_number=line_number,
                representation="macos_unified_log_logevent",
            )


@register_parser
class MacosEndpointSecurityParser(LogParser):
    """Read only the explicitly implemented eslogger message/event profiles."""

    format_name = "macos_endpoint_security"

    def can_parse(self, path: Path) -> bool:
        """Do not discover arbitrary EDR JSON or substitute it for eslogger."""
        return path.name == "macos_endpoint_security.ndjson"

    def parse_file(self, path: Path) -> Iterator[ParsedRecord]:
        """Retain full native precision in fields and microseconds for evaluation."""
        for line_number, line in iter_bounded_text_lines(path):
            raw = line.strip()
            if not raw:
                continue
            fields: dict[str, Any] = {}
            timestamp: datetime | None = None
            errors: list[str] = []
            representation = "macos_endpoint_security"
            try:
                fields = decode_record(raw)
                native = decode_endpoint_security_record(raw)
                timestamp = datetime.fromisoformat(native.time)
                representation = f"macos_endpoint_security_v{native.version}"
            except ValueError as exc:
                errors.append(_diagnostic(exc))
            yield ParsedRecord(
                source_format=self.format_name,
                raw=raw,
                fields=fields,
                timestamp=timestamp,
                parse_errors=errors,
                line_number=line_number,
                representation=representation,
            )
