# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: MIT

"""Parser for the top-level artifact manifest's email section."""

from __future__ import annotations

import json
from collections.abc import Iterator
from datetime import datetime
from pathlib import Path

from evidenceforge.events.artifacts_manifest import ARTIFACTS_MANIFEST_FILENAME
from evidenceforge.models.exceptions import EvaluationLimitError

from . import MAX_EVALUATION_RECORD_BYTES, LogParser, ParsedRecord, register_parser


@register_parser
class EmailArtifactsParser(LogParser):
    """Parse email artifact manifests into per-message records."""

    format_name = "email_artifacts"
    _filenames = {ARTIFACTS_MANIFEST_FILENAME}

    def can_parse(self, path: Path) -> bool:
        return path.name in self._filenames

    def parse_file(self, path: Path) -> Iterator[ParsedRecord]:
        if path.stat().st_size > MAX_EVALUATION_RECORD_BYTES:
            raise EvaluationLimitError(
                f"Email artifact manifest exceeds {MAX_EVALUATION_RECORD_BYTES} bytes: {path}"
            )
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            yield ParsedRecord(
                source_format=self.format_name,
                raw="",
                fields={},
                parse_errors=[str(exc)],
            )
            return
        if not isinstance(payload, dict):
            yield ParsedRecord(
                source_format=self.format_name,
                raw=json.dumps(payload),
                fields={},
                parse_errors=["Artifact manifest must be an object"],
            )
            return
        email_section = payload.get("email", {})
        if not isinstance(email_section, dict):
            yield ParsedRecord(
                source_format=self.format_name,
                raw=json.dumps(payload, sort_keys=True),
                fields={},
                parse_errors=[f"{ARTIFACTS_MANIFEST_FILENAME} email section must be an object"],
            )
            return
        messages = email_section.get("messages", [])
        if not isinstance(messages, list):
            yield ParsedRecord(
                source_format=self.format_name,
                raw=json.dumps(payload, sort_keys=True),
                fields={},
                parse_errors=[f"{ARTIFACTS_MANIFEST_FILENAME} email.messages must be a list"],
            )
            return
        for index, message in enumerate(messages, start=1):
            if not isinstance(message, dict):
                yield ParsedRecord(
                    source_format=self.format_name,
                    raw=json.dumps(message),
                    fields={},
                    line_number=index,
                    parse_errors=["Email artifact manifest message must be an object"],
                )
                continue
            timestamp = _parse_email_artifact_date(message.get("date"))
            record = ParsedRecord(
                source_format=self.format_name,
                raw=json.dumps(message, sort_keys=True),
                fields=message,
                timestamp=timestamp,
                parse_errors=(
                    ["Email artifact date must be a valid RFC email date"]
                    if message.get("date") not in (None, "") and timestamp is None
                    else []
                ),
                line_number=index,
            )
            from evidenceforge.evaluation.validation_routes import validate_email_artifact

            record.parse_errors.extend(
                f"{'.'.join(finding.fields)}: {finding.message}"
                for finding in validate_email_artifact(record)
            )
            if record.parse_errors:
                # Preserve the raw record and failure count, but do not feed malformed values
                # into specialized cross-source indexes (for example an unhashable Message-ID).
                record.fields = {}
            yield record


def _parse_email_artifact_date(value: object) -> datetime | None:
    if not isinstance(value, str) or not value:
        return None
    from email.utils import parsedate_to_datetime

    try:
        return parsedate_to_datetime(value)
    except (TypeError, ValueError, IndexError):
        return None
