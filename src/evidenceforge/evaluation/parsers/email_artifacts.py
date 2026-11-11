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

from . import LogParser, ParsedRecord, register_parser


@register_parser
class EmailArtifactsParser(LogParser):
    """Parse email artifact manifests into per-message records."""

    format_name = "email_artifacts"
    _filenames = {ARTIFACTS_MANIFEST_FILENAME}

    def can_parse(self, path: Path) -> bool:
        return path.name in self._filenames

    def parse_file(self, path: Path) -> Iterator[ParsedRecord]:
        from evidenceforge.evaluation.json_stream import JsonStreamReader
        from evidenceforge.evaluation.storage import bounded_list

        rows = bounded_list()
        try:
            with path.open(encoding="utf-8") as stream:
                reader = JsonStreamReader(stream)
                if reader.peek() != "{":
                    raise ValueError("Artifact manifest must be an object")
                for key in reader.object_keys():
                    if key != "email":
                        reader.skip()
                        continue
                    if reader.peek() != "{":
                        raise ValueError(
                            f"{ARTIFACTS_MANIFEST_FILENAME} email section must be an object"
                        )
                    rows = bounded_list()
                    for section in reader.object_keys():
                        if section != "messages":
                            reader.skip()
                            continue
                        if reader.peek() != "[":
                            raise ValueError(
                                f"{ARTIFACTS_MANIFEST_FILENAME} email.messages must be a list"
                            )
                        rows = bounded_list()
                        for index, message in enumerate(reader.array_items(), start=1):
                            rows.append(self._message_record(message, index))
                if reader.peek():
                    raise ValueError("Unexpected content after artifact manifest")
        except EvaluationLimitError:
            raise
        except (OSError, UnicodeError, ValueError) as exc:
            yield ParsedRecord(
                source_format=self.format_name, raw="", fields={}, parse_errors=[str(exc)]
            )
            return
        # Publish only after complete JSON validation, matching the original all-or-error parser.
        yield from rows

    def _message_record(self, message: object, index: int) -> ParsedRecord:
        if not isinstance(message, dict):
            return ParsedRecord(
                source_format=self.format_name,
                raw=json.dumps(message),
                fields={},
                line_number=index,
                parse_errors=["Email artifact manifest message must be an object"],
            )
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
            record.fields = {}
        return record


def _parse_email_artifact_date(value: object) -> datetime | None:
    if not isinstance(value, str) or not value:
        return None
    from email.utils import parsedate_to_datetime

    try:
        return parsedate_to_datetime(value)
    except (TypeError, ValueError, IndexError):
        return None
