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

"""Shared RFC3164 rendering and layout helpers for syslog-family emitters."""

from __future__ import annotations

import re
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from evidenceforge.utils.paths import sanitize_path_component

SYSLOG_ROUTE_SEPARATOR = "|"
SYSLOG_FAMILY_YEAR_RE = re.compile(r"^\d{4}$")
_RFC3164_RE = re.compile(
    r"^<(?P<pri>\d{1,3})>"
    r"(?P<month>[A-Z][a-z]{2})\s+"
    r"(?P<day>\d{1,2})\s+"
    r"(?P<hour>\d{2}):(?P<minute>\d{2}):(?P<second>\d{2})\s+"
)
_MONTHS = {
    "Jan": 1,
    "Feb": 2,
    "Mar": 3,
    "Apr": 4,
    "May": 5,
    "Jun": 6,
    "Jul": 7,
    "Aug": 8,
    "Sep": 9,
    "Oct": 10,
    "Nov": 11,
    "Dec": 12,
}


def coerce_syslog_datetime(value: datetime | str) -> datetime:
    """Return a UTC datetime for a syslog-family event timestamp."""
    if isinstance(value, str):
        from evidenceforge.utils.time import parse_iso8601

        value = parse_iso8601(value)
    if not isinstance(value, datetime):
        raise ValueError("syslog-family events require a datetime timestamp")
    if value.tzinfo is None:
        value = value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


def bounded_syslog_int(value: Any, *, default: int, minimum: int, maximum: int) -> int:
    """Return value as an int clamped to a syslog-supported range."""
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        return default
    return max(minimum, min(maximum, parsed))


def syslog_priority(facility: Any, severity: Any) -> int:
    """Return the syslog PRI value for bounded facility and severity inputs."""
    bounded_facility = bounded_syslog_int(facility, default=3, minimum=0, maximum=23)
    bounded_severity = bounded_syslog_int(severity, default=6, minimum=0, maximum=7)
    return bounded_facility * 8 + bounded_severity


def format_rfc3164_timestamp(timestamp: datetime | str) -> str:
    """Format a UTC timestamp as an RFC3164 timestamp without a year."""
    ts = coerce_syslog_datetime(timestamp)
    return f"{ts:%b} {ts.day:2d} {ts:%H:%M:%S}"


def render_rfc3164_syslog(
    *,
    pri: int,
    timestamp: datetime | str,
    hostname: str,
    app_name: str,
    message: str,
    pid: Any = None,
) -> str:
    """Render a BSD/RFC3164-style syslog line."""
    app = _syslog_tag_token(app_name, default="-")
    host = _syslog_header_token(hostname, default="-")
    tag = f"{app}[{pid}]" if pid not in (None, "") else app
    return f"<{pri}>{format_rfc3164_timestamp(timestamp)} {host} {tag}: {message or ''}"


def make_syslog_family_route_key(
    source_name: str,
    timestamp: datetime | str,
    *,
    direct_file_mode: bool,
) -> str:
    """Return an internal writer key carrying source name and event year."""
    if direct_file_mode:
        return source_name
    year = str(coerce_syslog_datetime(timestamp).year)
    return f"{source_name}{SYSLOG_ROUTE_SEPARATOR}{year}"


def sanitize_syslog_family_route_key(route_key: str) -> str:
    """Sanitize an internal syslog-family route key."""
    if SYSLOG_ROUTE_SEPARATOR not in route_key:
        return sanitize_path_component(route_key)
    source, year = route_key.rsplit(SYSLOG_ROUTE_SEPARATOR, 1)
    safe_source = sanitize_path_component(source) or "default"
    safe_year = year if SYSLOG_FAMILY_YEAR_RE.fullmatch(year) else ""
    if not safe_year:
        return safe_source
    return f"{safe_source}{SYSLOG_ROUTE_SEPARATOR}{safe_year}"


def syslog_route_source(route_key: str) -> str:
    """Return the source component from a sanitized syslog-family route key."""
    if SYSLOG_ROUTE_SEPARATOR not in route_key:
        return route_key or "default"
    source, _year = route_key.rsplit(SYSLOG_ROUTE_SEPARATOR, 1)
    return source or "default"


def syslog_route_year(route_key: str) -> str | None:
    """Return the year component from a sanitized syslog-family route key."""
    if SYSLOG_ROUTE_SEPARATOR not in route_key:
        return None
    _source, year = route_key.rsplit(SYSLOG_ROUTE_SEPARATOR, 1)
    return year if SYSLOG_FAMILY_YEAR_RE.fullmatch(year) else None


def syslog_family_writer_path(
    *,
    base_dir: Path,
    safe_route_key: str,
    log_filename: str,
    direct_file_path: Path | None,
    flat_filename: str,
) -> Path:
    """Return the generated output path for a syslog-family writer key."""
    if direct_file_path is not None:
        return direct_file_path
    source = syslog_route_source(safe_route_key)
    year = syslog_route_year(safe_route_key)
    if year is not None:
        return base_dir / source / year / log_filename
    if source:
        return base_dir / source / log_filename
    return base_dir / (flat_filename or log_filename)


def rfc3164_timestamp_sort_key(line: str) -> tuple[int, int, int, int, int]:
    """Return a stable timestamp-only sort key for an RFC3164 syslog line."""
    match = _RFC3164_RE.match(line)
    if match is None:
        return (99, 99, 99, 99, 99)
    return (
        _MONTHS.get(match.group("month"), 99),
        int(match.group("day")),
        int(match.group("hour")),
        int(match.group("minute")),
        int(match.group("second")),
    )


def rfc3164_sort_key(
    line: str, lifecycle_priority: int = 50
) -> tuple[int, int, int, int, int, int, str]:
    """Return a timestamp plus lifecycle sort key for host syslog lines."""
    return (*rfc3164_timestamp_sort_key(line), lifecycle_priority, line)


def _syslog_header_token(value: Any, *, default: str) -> str:
    token = "" if value is None else str(value).strip()
    if not token:
        return default
    return re.sub(r"\s+", "_", token)


def _syslog_tag_token(value: Any, *, default: str) -> str:
    token = _syslog_header_token(value, default=default)
    return token.rstrip(":")
