"""Parser for Zeek dns.log (NDJSON) files."""

import json
from collections.abc import Iterator
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from . import LogParser, ParsedRecord, register_parser


@register_parser
class ZeekDnsParser(LogParser):
    format_name = "zeek_dns"

    def can_parse(self, path: Path) -> bool:
        return path.name == "zeek_dns.json"

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
            fields = dict(data)

            # Parse ts (epoch float)
            ts_val = data.get("ts")
            if ts_val is not None:
                try:
                    timestamp = datetime.fromtimestamp(
                        float(ts_val), tz=timezone.utc
                    )
                except (ValueError, TypeError, OSError):
                    errors.append(f"Invalid timestamp: {ts_val}")

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
