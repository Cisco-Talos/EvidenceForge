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

"""Parser for generated RFC3164 syslog plus legacy syslog eval input."""

import re
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path

from . import LogParser, ParsedRecord, register_parser

RFC5424_PATTERN = re.compile(
    r"^<(?P<pri>\d{1,3})>(?P<version>\d+)\s+"
    r"(?P<timestamp>\S+)\s+"
    r"(?P<hostname>\S+)\s+"
    r"(?P<app_name>\S+)\s+"
    r"(?P<procid>\S+)\s+"
    r"(?P<msgid>\S+)\s+"
    r"(?P<structured_data>-|(?:\[[^\]]*\])+)"
    r"(?:\s(?P<message>.*))?$"
)

# BSD/RFC3164 syslog format: "Mon DD HH:MM:SS hostname app[pid]: message".
RFC3164_SYSLOG_PATTERN = re.compile(
    r"^(?:<(?P<pri>\d{1,3})>)?"
    r"(?P<timestamp>\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+"  # timestamp (BSD)
    r"(\S+)\s+"  # hostname
    r"(\S+?)(?:\[([^\]]*)\])?:\s+"  # app_name[pid]: or app_name:
    r"(.*)$"  # message
)

# Legacy ISO variant: "2026-03-15T10:15:00Z hostname app[pid]: message".
LEGACY_ISO_SYSLOG_PATTERN = re.compile(
    r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\S*)\s+"  # ISO timestamp
    r"(\S+)\s+"  # hostname
    r"(\S+?)(?:\[([^\]]*)\])?:\s+"  # app_name[pid]: or app_name:
    r"(.*)$"  # message
)

# BSD timestamps that are ≥6 months *earlier* than last_ts are treated as a
# year wrap (Dec → Jan crossing), not as a true backwards-time event.
_WRAP_THRESHOLD_SECONDS = 180 * 24 * 3600  # ~6 months


def _path_year(path: Path) -> int | None:
    """Return the immediate parent year from a year-partitioned syslog path."""
    if re.fullmatch(r"\d{4}", path.parent.name):
        return int(path.parent.name)
    return None


def _infer_seed_year(path: Path, scenario: object | None = None) -> int:
    """Return the best-guess year for BSD syslog records in *path*.

    Preference order:
    1. Parent YYYY directory — generated syslog-family layout.
    2. scenario.time_window.start year — fallback for old flat datasets.
    3. File modification time — fallback for use outside the evaluation engine.
    4. Current year — last resort.
    """
    if (year := _path_year(path)) is not None:
        return year
    if scenario is not None:
        try:
            tw = getattr(scenario, "time_window", None)
            start = getattr(tw, "start", None) if tw is not None else None
            if start is not None:
                if isinstance(start, datetime):
                    return start.year
                # String ISO timestamp: "2024-03-18T12:00:00Z"
                return int(str(start)[:4])
        except Exception:
            pass
    try:
        return datetime.fromtimestamp(path.stat().st_mtime, tz=UTC).year
    except OSError:
        return datetime.now(UTC).year


def _resolve_bsd_year(ts_str: str, seed_year: int, last_ts: datetime | None) -> datetime | None:
    """Parse a year-less BSD timestamp, resolving the year robustly.

    If *last_ts* is set and the naive candidate timestamp is more than
    _WRAP_THRESHOLD_SECONDS before it AND the candidate month is January while
    last_ts is December, we increment the year (year-boundary wrap).
    """
    try:
        naive = datetime.strptime(f"{seed_year} {ts_str}", "%Y %b %d %H:%M:%S")
    except ValueError:
        return None

    if last_ts is None:
        return naive

    # Normalise last_ts to naive for comparison
    last_naive = last_ts.replace(tzinfo=None) if last_ts.tzinfo else last_ts
    diff = (last_naive - naive).total_seconds()
    if diff > _WRAP_THRESHOLD_SECONDS and naive.month == 1 and last_naive.month == 12:
        # Year boundary: the new record is in the next year
        try:
            naive = datetime.strptime(f"{seed_year + 1} {ts_str}", "%Y %b %d %H:%M:%S")
        except ValueError:
            pass
    return naive


@register_parser
class SyslogParser(LogParser):
    format_name = "syslog"

    def can_parse(self, path: Path) -> bool:
        return path.name == "syslog.log"

    def parse_file(self, path: Path) -> Iterator[ParsedRecord]:
        seed_year = _infer_seed_year(path, getattr(self, "scenario", None))
        generated_rfc3164 = _path_year(path) is not None
        last_ts: datetime | None = None

        with path.open(encoding="utf-8") as f:
            for line_num, line in enumerate(f, 1):
                line = line.rstrip("\n")
                if not line:
                    continue
                record = self._parse_line(
                    line,
                    line_num,
                    seed_year=seed_year,
                    last_ts=last_ts,
                    generated_rfc3164=generated_rfc3164,
                )
                if record.timestamp is not None:
                    last_ts = record.timestamp
                yield record

    def _parse_line(
        self,
        raw: str,
        line_num: int,
        seed_year: int | None = None,
        last_ts: datetime | None = None,
        generated_rfc3164: bool = False,
    ) -> ParsedRecord:
        fields: dict = {}
        errors: list[str] = []
        timestamp = None

        if seed_year is None:
            seed_year = datetime.now(UTC).year

        match = RFC5424_PATTERN.match(raw)
        if match:
            groups = match.groupdict()
            ts_str = groups["timestamp"]
            try:
                timestamp = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
            except ValueError:
                errors.append(f"Invalid RFC 5424 timestamp: {ts_str}")
            pri = int(groups["pri"])
            fields["pri"] = pri
            fields["version"] = int(groups["version"])
            fields["hostname"] = groups["hostname"]
            fields["app_name"] = groups["app_name"]
            fields["procid"] = groups["procid"]
            fields["msgid"] = groups["msgid"]
            fields["structured_data"] = groups["structured_data"]
            fields["message"] = groups["message"] or ""
            fields["facility"] = pri // 8
            fields["severity"] = pri % 8
            fields["syslog_protocol"] = "rfc5424_legacy"
            pid_str = groups["procid"]
        else:
            match = LEGACY_ISO_SYSLOG_PATTERN.match(raw)
            if match:
                ts_str, hostname, app_name, pid_str, message = match.groups()
                try:
                    timestamp = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
                except ValueError:
                    errors.append(f"Invalid legacy ISO timestamp: {ts_str}")
                fields["hostname"] = hostname
                fields["app_name"] = app_name
                fields["message"] = message
                fields["syslog_protocol"] = "iso_legacy"
            else:
                match = RFC3164_SYSLOG_PATTERN.match(raw)
                if match:
                    groups = match.groupdict()
                    ts_str = groups["timestamp"]
                    hostname, app_name, pid_str, message = match.groups()[2:]
                    timestamp = _resolve_bsd_year(ts_str, seed_year, last_ts)
                    if timestamp is None:
                        errors.append(f"Invalid legacy BSD timestamp: {ts_str}")
                    if groups.get("pri"):
                        pri = int(groups["pri"])
                        fields["pri"] = pri
                        fields["facility"] = pri // 8
                        fields["severity"] = pri % 8
                    fields["hostname"] = hostname
                    fields["app_name"] = app_name
                    fields["message"] = message
                    fields["syslog_protocol"] = "rfc3164" if generated_rfc3164 else "rfc3164_legacy"
                else:
                    errors.append("Line does not match RFC 5424 or legacy syslog format")
                    return ParsedRecord(
                        source_format=self.format_name,
                        raw=raw,
                        fields={},
                        timestamp=None,
                        parse_errors=errors,
                        line_number=line_num,
                    )

        fields["timestamp"] = str(timestamp) if timestamp else ts_str

        if pid_str is not None and pid_str != "-":
            try:
                fields["pid"] = int(pid_str)
            except ValueError:
                fields["pid"] = pid_str

        return ParsedRecord(
            source_format=self.format_name,
            raw=raw,
            fields=fields,
            timestamp=timestamp,
            parse_errors=errors,
            line_number=line_num,
        )
