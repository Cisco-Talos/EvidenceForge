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

from . import LogParser, ParsedRecord, register_parser


@register_parser
class EmailArtifactsParser(LogParser):
    """Parse email artifact manifests into per-message records."""

    format_name = "email_artifacts"
    _filenames = {ARTIFACTS_MANIFEST_FILENAME}

    def can_parse(self, path: Path) -> bool:
        return path.name in self._filenames

    def parse_file(self, path: Path) -> Iterator[ParsedRecord]:
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            yield ParsedRecord(
                source_format=self.format_name,
                raw="",
                fields={},
                parse_errors=[str(exc)],
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
            yield ParsedRecord(
                source_format=self.format_name,
                raw=json.dumps(message, sort_keys=True),
                fields=message,
                timestamp=timestamp,
                line_number=index,
            )


def _parse_email_artifact_date(value: object) -> datetime | None:
    if not isinstance(value, str) or not value:
        return None
    from email.utils import parsedate_to_datetime

    try:
        return parsedate_to_datetime(value)
    except (TypeError, ValueError, IndexError):
        return None
