"""Parser for Zeek conn.log (NDJSON) files."""

import json
from collections.abc import Iterator
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from . import LogParser, ParsedRecord, register_parser


@register_parser
class ZeekConnParser(LogParser):
    format_name = "zeek_conn"

    def can_parse(self, path: Path) -> bool:
        return path.name == "zeek_conn.json"

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

            # Parse timestamp — Zeek ts can be epoch float or string
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
