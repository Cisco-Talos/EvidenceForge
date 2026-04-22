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

"""Time parsing and timezone utilities for EvidenceForge."""

import fnmatch
import re
from datetime import UTC, datetime, timedelta

import pytz

from evidenceforge.models.scenario import Environment, TimeWindow


def parse_duration(duration_str: str) -> timedelta:
    """Parse duration string to timedelta.

    Supports: "10h", "3d", "2h30m", "1d3h45m", "20m30s", "500ms"
    Units: d (days), h (hours), m (minutes), s (seconds), ms (milliseconds)

    Args:
        duration_str: Duration string matching pattern ^(\\d+(ms|[hdms]))+$

    Returns:
        timedelta object

    Raises:
        ValueError: If format is invalid
    """
    if not re.match(r"^(\d+(ms|[hdms]))+$", duration_str):
        raise ValueError(f"Invalid duration format: {duration_str}")

    # Parse all digit-unit pairs (ms must match before single-char m/s)
    pattern = r"(\d+)(ms|[hdms])"
    matches = re.findall(pattern, duration_str)

    total_seconds = 0.0
    for value, unit in matches:
        value = int(value)
        if unit == "d":
            total_seconds += value * 86400
        elif unit == "h":
            total_seconds += value * 3600
        elif unit == "m":
            total_seconds += value * 60
        elif unit == "s":
            total_seconds += value
        elif unit == "ms":
            total_seconds += value * 0.001

    return timedelta(seconds=total_seconds)


def ensure_utc(dt: datetime) -> datetime:
    """Return `dt` with UTC tzinfo. Naive datetimes are assumed to be UTC."""
    if dt.tzinfo is None:
        return dt.replace(tzinfo=UTC)
    return dt.astimezone(UTC)


def parse_iso8601(timestamp_str: str) -> datetime:
    """Parse ISO 8601 timestamp to UTC datetime.

    Examples: "2024-01-15T10:00:00Z", "2024-01-15T10:00:00+00:00"
    If no timezone specified, assumes UTC.

    Args:
        timestamp_str: ISO 8601 formatted timestamp

    Returns:
        datetime object with UTC timezone

    Raises:
        ValueError: If timestamp format is invalid
    """
    try:
        # Try parsing with fromisoformat
        dt = datetime.fromisoformat(timestamp_str.replace("Z", "+00:00"))

        # Ensure UTC timezone
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=UTC)
        else:
            dt = dt.astimezone(UTC)

        return dt
    except ValueError as e:
        raise ValueError(f"Invalid ISO 8601 timestamp: {timestamp_str}") from e


def resolve_time_window(time_window: TimeWindow) -> tuple[datetime, datetime]:
    """Resolve TimeWindow to (start, end) datetimes in UTC.

    Naive datetimes are assumed to be UTC.
    """
    start = ensure_utc(time_window.start)

    if time_window.end:
        end = ensure_utc(time_window.end)
    elif time_window.duration:
        duration = parse_duration(time_window.duration)
        end = start + duration
    else:
        raise ValueError("TimeWindow must have either end or duration")

    return start, end


def get_system_timezone(system_hostname: str, environment: Environment) -> str:
    """Get timezone for a system based on pattern matching.

    Args:
        system_hostname: System hostname (e.g., "WS-NYC-01")
        environment: Environment with timezone configuration

    Returns:
        Timezone name (e.g., "America/New_York")
    """
    # Check pattern overrides
    if environment.timezone.systems:
        for pattern, tz_name in environment.timezone.systems.items():
            if fnmatch.fnmatch(system_hostname, pattern):
                return tz_name

    # Use default
    return environment.timezone.default


def convert_to_output_timezone(
    dt: datetime, system_hostname: str, environment: Environment
) -> datetime:
    """Convert UTC datetime to system's output timezone.

    Args:
        dt: UTC datetime
        system_hostname: System hostname
        environment: Environment with timezone configuration

    Returns:
        datetime in system's timezone
    """
    tz_name = get_system_timezone(system_hostname, environment)
    tz = pytz.timezone(tz_name)
    return dt.astimezone(tz)


def parse_work_hours(work_hours_str: str) -> dict:
    """Parse work hours string into time ranges and distributions.

    Phase 2.4: Supports parsing work hours for temporal activity distribution.

    Supports formats:
    - "9am-5pm" → {start: 9, end: 17, lunch: None}
    - "8:30am-5:30pm" → {start: 8.5, end: 17.5, lunch: None}
    - "9am-5pm (lunch 12pm-1pm)" → {start: 9, end: 17, lunch: (12, 13)}

    Args:
        work_hours_str: Human-readable work hours string

    Returns:
        Dict with:
        - start: Start hour (24-hour format, float for half-hours)
        - end: End hour (24-hour format, float)
        - lunch: Tuple (start, end) if lunch break specified, else None
        - hours: List of active hours (excluding lunch)
        - peak_hours: List of peak hours (mid-morning, mid-afternoon)

    Raises:
        ValueError: If format is invalid

    Examples:
        >>> parse_work_hours("9am-5pm")
        {
            'start': 9,
            'end': 17,
            'lunch': None,
            'hours': [9, 10, 11, 12, 13, 14, 15, 16],
            'peak_hours': [10, 11, 14, 15]
        }

        >>> parse_work_hours("9am-5pm (lunch 12pm-1pm)")
        {
            'start': 9,
            'end': 17,
            'lunch': (12, 13),
            'hours': [9, 10, 11, 13, 14, 15, 16],
            'peak_hours': [10, 11, 14, 15]
        }
    """
    # Extract lunch break if present
    lunch_pattern = r"\(lunch\s+([\d:]+(?:am|pm)?)\s*-\s*([\d:]+(?:am|pm)?)\)"
    lunch_match = re.search(lunch_pattern, work_hours_str, re.IGNORECASE)

    lunch_start = None
    lunch_end = None
    if lunch_match:
        lunch_start_str = lunch_match.group(1)
        lunch_end_str = lunch_match.group(2)
        lunch_start = _parse_time_to_hour(lunch_start_str)
        lunch_end = _parse_time_to_hour(lunch_end_str)
        # Remove lunch portion from main string
        work_hours_str = work_hours_str[: lunch_match.start()] + work_hours_str[lunch_match.end() :]

    # Parse main work hours range
    main_pattern = r"([\d:]+(?:am|pm)?)\s*-\s*([\d:]+(?:am|pm)?)"
    main_match = re.search(main_pattern, work_hours_str, re.IGNORECASE)

    if not main_match:
        raise ValueError(f"Invalid work hours format: {work_hours_str}")

    start_time_str = main_match.group(1)
    end_time_str = main_match.group(2)

    start = _parse_time_to_hour(start_time_str)
    end = _parse_time_to_hour(end_time_str)

    # Generate list of active hours (integer hours only, excluding lunch)
    # If end time has fractional part (e.g., 5:30pm = 17.5), include that hour
    hours = []
    current_hour = int(start)
    end_hour_inclusive = int(end) if end == int(end) else int(end) + 1

    while current_hour < end_hour_inclusive:
        # Exclude lunch hours (use ceiling for lunch_end to exclude partial overlaps)
        if lunch_start is not None and lunch_end is not None:
            lunch_end_ceil = int(lunch_end) if lunch_end == int(lunch_end) else int(lunch_end) + 1
            if not (int(lunch_start) <= current_hour < lunch_end_ceil):
                hours.append(current_hour)
        else:
            hours.append(current_hour)
        current_hour += 1

    # Calculate peak hours (2-3 hours after start, 2-3 hours before end, exclude lunch)
    peak_hours = []

    # Morning peak: 2-3 hours after start
    morning_peak_start = int(start) + 1
    morning_peak_end = int(start) + 3
    for hour in range(morning_peak_start, morning_peak_end):
        if hour in hours:
            peak_hours.append(hour)

    # Afternoon peak: 2-3 hours before end
    afternoon_peak_start = int(end) - 3
    afternoon_peak_end = int(end) - 1
    for hour in range(afternoon_peak_start, afternoon_peak_end):
        if hour in hours and hour not in peak_hours:
            peak_hours.append(hour)

    return {
        "start": start,
        "end": end,
        "lunch": (lunch_start, lunch_end) if lunch_start is not None else None,
        "hours": hours,
        "peak_hours": peak_hours,
    }


def _parse_time_to_hour(time_str: str) -> float:
    """Helper to parse time string to 24-hour float.

    Supports: "9am", "5pm", "8:30am", "12:45pm"

    Args:
        time_str: Time string with optional am/pm

    Returns:
        Hour as float (e.g., 9.0, 17.5, 12.75)

    Raises:
        ValueError: If format is invalid
    """
    time_str = time_str.strip().lower()

    # Check for am/pm
    is_pm = "pm" in time_str
    is_am = "am" in time_str

    # Remove am/pm suffix
    time_str = time_str.replace("am", "").replace("pm", "").strip()

    # Parse hour and optional minutes
    try:
        if ":" in time_str:
            parts = time_str.split(":")
            if len(parts) != 2:
                raise ValueError(f"Invalid time format: {time_str}")
            hour = int(parts[0])
            minutes = int(parts[1])
        else:
            hour = int(time_str)
            minutes = 0
    except ValueError as e:
        raise ValueError(f"Invalid time format: {time_str}") from e

    # Validate ranges
    if hour < 1 or hour > 12:
        raise ValueError(f"Hour must be 1-12, got {hour}")
    if minutes < 0 or minutes > 59:
        raise ValueError(f"Minutes must be 0-59, got {minutes}")

    # Convert to 24-hour format
    if is_pm and hour != 12:
        hour += 12
    elif is_am and hour == 12:
        hour = 0

    # Return as float (hour + fraction for minutes)
    return hour + (minutes / 60.0)
