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

"""Base parser for all Zeek NDJSON log files."""

import json
from collections.abc import Iterator
from datetime import UTC, datetime
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
                    timestamp = datetime.fromtimestamp(epoch, tz=UTC)
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
