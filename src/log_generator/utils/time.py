"""Time parsing and timezone utilities for EvidenceForge."""

import fnmatch
import re
from datetime import datetime, timedelta, timezone

import pytz

from log_generator.models.scenario import Environment, TimeWindow


def parse_duration(duration_str: str) -> timedelta:
    """Parse duration string to timedelta.

    Supports: "10h", "3d", "2h30m", "1d3h45m"
    Units: h (hours), d (days), m (minutes)

    Args:
        duration_str: Duration string matching pattern ^(\\d+[hdm])+$

    Returns:
        timedelta object

    Raises:
        ValueError: If format is invalid
    """
    if not re.match(r"^(\d+[hdm])+$", duration_str):
        raise ValueError(f"Invalid duration format: {duration_str}")

    # Parse all digit-unit pairs
    pattern = r"(\d+)([hdm])"
    matches = re.findall(pattern, duration_str)

    total_seconds = 0
    for value, unit in matches:
        value = int(value)
        if unit == "d":
            total_seconds += value * 86400  # days to seconds
        elif unit == "h":
            total_seconds += value * 3600  # hours to seconds
        elif unit == "m":
            total_seconds += value * 60  # minutes to seconds

    return timedelta(seconds=total_seconds)


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
            dt = dt.replace(tzinfo=timezone.utc)
        else:
            dt = dt.astimezone(timezone.utc)

        return dt
    except ValueError as e:
        raise ValueError(f"Invalid ISO 8601 timestamp: {timestamp_str}") from e


def resolve_time_window(time_window: TimeWindow) -> tuple[datetime, datetime]:
    """Resolve TimeWindow to (start, end) datetimes.

    Args:
        time_window: TimeWindow with start + (end XOR duration)

    Returns:
        Tuple of (start_datetime, end_datetime) in UTC
    """
    start = time_window.start

    if time_window.end:
        end = time_window.end
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
