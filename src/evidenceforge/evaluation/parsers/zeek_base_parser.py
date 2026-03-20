"""Base parser for all Zeek NDJSON log files."""

import json
from collections.abc import Iterator
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from . import LogParser, ParsedRecord


class ZeekNdjsonParser(LogParser):
    """Base parser for Zeek NDJSON files.

    Subclasses set format_name and _filenames (the set of filenames
    this parser can handle, supporting both flat and per-sensor paths).
    """

    _filenames: set[str] = set()  # e.g., {"conn.json", "zeek_conn.json"}

    def can_parse(self, path: Path) -> bool:
        return path.name in self._filenames

    def parse_file(self, path: Path) -> Iterator[ParsedRecord]:
        with path.open(encoding="utf-8") as f:
            for line_num, line in enumerate(f, 1):
                line = line.strip()
                if not line:
                    continue
                yield self._parse_line(line, line_num)

    def _parse_line(self, raw: str, line_num: int) -> ParsedRecord:
        fields: dict[str, Any] = {}
        errors: list[str] = []
        timestamp = None

        try:
            data = json.loads(raw)
            fields = data

            ts = data.get("ts")
            if ts is not None:
                try:
                    epoch = float(ts)
                    timestamp = datetime.fromtimestamp(epoch, tz=timezone.utc)
                except (ValueError, TypeError, OSError):
                    errors.append(f"Invalid timestamp: {ts}")

        except json.JSONDecodeError as e:
            errors.append(f"JSON parse error: {e}")

        return ParsedRecord(
            source_format=self.format_name,
            raw=raw,
            fields=fields,
            timestamp=timestamp,
            parse_errors=errors,
            line_number=line_num,
        )
