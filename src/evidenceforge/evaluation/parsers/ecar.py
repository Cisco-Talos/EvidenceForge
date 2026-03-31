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

"""Parser for eCAR (NDJSON) files."""

import json
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from . import LogParser, ParsedRecord, register_parser


@register_parser
class EcarParser(LogParser):
    format_name = "ecar"

    def can_parse(self, path: Path) -> bool:
        return path.name == "ecar.json"

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

            # Flatten properties into top-level fields
            properties = data.pop("properties", {})
            fields = {**data, **properties}

            # Normalize "-" sentinel to absent for IP fields
            for ip_field in ("src_ip", "dst_ip"):
                if fields.get(ip_field) == "-":
                    del fields[ip_field]

            # Parse timestamp_ms (milliseconds since epoch)
            ts_ms = data.get("timestamp_ms")
            if ts_ms is not None:
                try:
                    timestamp = datetime.fromtimestamp(int(ts_ms) / 1000.0, tz=UTC)
                except (ValueError, TypeError, OSError):
                    errors.append(f"Invalid timestamp_ms: {ts_ms}")

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
