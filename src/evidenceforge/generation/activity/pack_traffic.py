# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Deterministic scheduling helpers for pack-authored persona traffic."""

from __future__ import annotations

import math
import random
from datetime import UTC, date, datetime, time, timedelta, tzinfo
from typing import Any

from evidenceforge.utils.rng import _stable_seed

_DAY_INDEX = {
    "mon": 0,
    "tue": 1,
    "wed": 2,
    "thu": 3,
    "fri": 4,
    "sat": 5,
    "sun": 6,
}
_DEFAULT_DAYS = tuple(_DAY_INDEX)[:5]
_DEFAULT_WINDOWS = ({"start": "07:00", "end": "20:00"},)


def _cadence_days(cadence: dict[str, Any] | None) -> set[int]:
    """Return configured start-day indexes, applying the business-day default."""

    raw_days = (cadence or {}).get("days") or _DEFAULT_DAYS
    return {_DAY_INDEX[str(day)] for day in raw_days}


def _parse_clock(value: str) -> time:
    """Parse the schema-validated HH:MM public clock representation."""

    hour, minute = (int(part) for part in value.split(":"))
    return time(hour=hour, minute=minute)


def _cadence_windows(cadence: dict[str, Any] | None) -> tuple[tuple[time, time], ...]:
    """Return configured wall-clock windows, applying the business-hour default."""

    raw_windows = (cadence or {}).get("windows") or _DEFAULT_WINDOWS
    return tuple(
        (_parse_clock(str(window["start"])), _parse_clock(str(window["end"])))
        for window in raw_windows
    )


def cadence_allows_local_time(
    cadence: dict[str, Any] | None,
    local_datetime: datetime,
) -> bool:
    """Return whether a local timestamp falls in a cadence window.

    Cross-midnight windows belong to their start day. For example, a Friday
    22:00-02:00 window accepts Saturday 01:00 because Friday is selected.
    """

    days = _cadence_days(cadence)
    local_clock = local_datetime.timetz().replace(tzinfo=None)
    for start, end in _cadence_windows(cadence):
        if start < end:
            if local_datetime.weekday() in days and start <= local_clock < end:
                return True
            continue
        if start == end:
            if local_datetime.weekday() in days:
                return True
            continue
        if local_clock >= start and local_datetime.weekday() in days:
            return True
        previous_day = (local_datetime.weekday() - 1) % 7
        if local_clock < end and previous_day in days:
            return True
    return False


def _as_aware(value: datetime) -> datetime:
    """Treat legacy naive generation timestamps as UTC."""

    return value if value.tzinfo is not None else value.replace(tzinfo=UTC)


def cadence_allows_event_time(
    cadence: dict[str, Any] | None,
    event_time: datetime,
    zone: tzinfo,
) -> bool:
    """Check one generation timestamp against the authored scenario-local cadence."""

    return cadence_allows_local_time(cadence, _as_aware(event_time).astimezone(zone))


def _localize(zone: tzinfo, local_value: datetime) -> datetime:
    """Localize a naive wall time for either pytz or stdlib timezone objects."""

    localize = getattr(zone, "localize", None)
    if callable(localize):
        return localize(local_value, is_dst=None)
    return local_value.replace(tzinfo=zone)


def _weighted_times(
    *,
    cadence: dict[str, Any] | None,
    current_hour: datetime,
    zone: tzinfo,
    count: int,
    rng: random.Random,
) -> list[datetime]:
    """Sample weighted traffic with the legacy burst texture inside valid windows."""

    if count <= 0:
        return []
    burst_count = rng.randint(3, 5)
    burst_centers = sorted(rng.sample(range(300, 3300, 60), burst_count))
    event_times: list[datetime] = []
    for _ in range(count):
        for _attempt in range(96):
            if rng.random() < 0.70:
                center = rng.choice(burst_centers)
                offset = max(0.0, min(3599.0, center + rng.gauss(0, 60.0)))
            else:
                offset = rng.uniform(0, 3599)
            candidate = current_hour + timedelta(seconds=offset)
            if cadence_allows_local_time(cadence, _as_aware(candidate).astimezone(zone)):
                event_times.append(candidate)
                break
    return sorted(event_times)


def _periodic_times(
    *,
    cadence: dict[str, Any],
    scenario_start: datetime,
    current_hour: datetime,
    zone: tzinfo,
    schedule_key: str,
) -> list[datetime]:
    """Return stable interval ticks, including bounded per-tick jitter."""

    interval_seconds = int(cadence["interval_minutes"]) * 60
    jitter_seconds = int(cadence.get("jitter_minutes", 0)) * 60
    epoch = _as_aware(scenario_start)
    hour_start = _as_aware(current_hour)
    hour_end = hour_start + timedelta(hours=1)
    anchor_seconds = _stable_seed(f"{schedule_key}:anchor") % interval_seconds
    lower = (hour_start - epoch).total_seconds() - anchor_seconds - jitter_seconds
    upper = (hour_end - epoch).total_seconds() - anchor_seconds + jitter_seconds
    first_index = math.floor(lower / interval_seconds) - 1
    last_index = math.ceil(upper / interval_seconds) + 1
    candidates: set[datetime] = set()
    for index in range(first_index, last_index + 1):
        tick = epoch + timedelta(seconds=anchor_seconds + index * interval_seconds)
        if jitter_seconds:
            tick_rng = random.Random(_stable_seed(f"{schedule_key}:periodic:{index}"))
            tick += timedelta(seconds=tick_rng.uniform(-jitter_seconds, jitter_seconds))
        if not hour_start <= tick < hour_end:
            continue
        if cadence_allows_local_time(cadence, tick.astimezone(zone)):
            candidates.add(tick)
    return [
        value if current_hour.tzinfo is not None else value.replace(tzinfo=None)
        for value in sorted(candidates)
    ]


def _window_instance(
    *,
    zone: tzinfo,
    start_day: date,
    start_clock: time,
    end_clock: time,
) -> tuple[datetime, datetime]:
    """Build one timezone-aware local window tied to its authored start day."""

    start = _localize(zone, datetime.combine(start_day, start_clock))
    end_day = start_day + timedelta(days=1) if end_clock <= start_clock else start_day
    end = _localize(zone, datetime.combine(end_day, end_clock))
    return start, end


def _burst_times(
    *,
    cadence: dict[str, Any],
    current_hour: datetime,
    zone: tzinfo,
    schedule_key: str,
) -> list[datetime]:
    """Return one deterministic clustered burst per eligible local window."""

    hour_start = _as_aware(current_hour)
    hour_end = hour_start + timedelta(hours=1)
    local_hour = hour_start.astimezone(zone)
    start_days = (local_hour.date() - timedelta(days=1), local_hour.date())
    allowed_days = _cadence_days(cadence)
    burst_range = cadence["burst_count"]
    jitter_seconds = int(cadence.get("jitter_minutes", 0)) * 60
    candidates: list[datetime] = []
    for start_day in start_days:
        if start_day.weekday() not in allowed_days:
            continue
        for window_index, (start_clock, end_clock) in enumerate(_cadence_windows(cadence)):
            window_start, window_end = _window_instance(
                zone=zone,
                start_day=start_day,
                start_clock=start_clock,
                end_clock=end_clock,
            )
            duration_seconds = (window_end - window_start).total_seconds()
            if duration_seconds <= 0:
                continue
            window_key = f"{schedule_key}:burst:{start_day.isoformat()}:{window_index}"
            window_rng = random.Random(_stable_seed(window_key))
            count = window_rng.randint(int(burst_range[0]), int(burst_range[1]))
            anchor = window_start + timedelta(
                seconds=duration_seconds * window_rng.uniform(0.25, 0.75)
            )
            spread = jitter_seconds or min(300, max(30, int(duration_seconds * 0.04)))
            for event_index in range(count):
                event_rng = random.Random(_stable_seed(f"{window_key}:event:{event_index}"))
                event_time = anchor + timedelta(seconds=event_rng.uniform(-spread, spread))
                event_time = max(
                    window_start, min(window_end - timedelta(microseconds=1), event_time)
                )
                utc_time = event_time.astimezone(UTC)
                if hour_start.astimezone(UTC) <= utc_time < hour_end.astimezone(UTC):
                    candidates.append(utc_time)
    candidates.sort()
    return [
        value.astimezone(current_hour.tzinfo)
        if current_hour.tzinfo is not None
        else value.replace(tzinfo=None)
        for value in candidates
    ]


def scheduled_pack_event_times(
    *,
    cadence: dict[str, Any] | None,
    scenario_start: datetime,
    current_hour: datetime,
    zone: tzinfo,
    schedule_key: str,
    weighted_count: int,
    rng: random.Random,
) -> list[datetime]:
    """Schedule one pack traffic group for the current generation hour."""

    pattern = str((cadence or {}).get("pattern", "weighted"))
    if pattern == "weighted":
        return _weighted_times(
            cadence=cadence,
            current_hour=current_hour,
            zone=zone,
            count=weighted_count,
            rng=rng,
        )
    if pattern == "periodic":
        assert cadence is not None
        return _periodic_times(
            cadence=cadence,
            scenario_start=scenario_start,
            current_hour=current_hour,
            zone=zone,
            schedule_key=schedule_key,
        )
    if pattern == "burst":
        assert cadence is not None
        return _burst_times(
            cadence=cadence,
            current_hour=current_hour,
            zone=zone,
            schedule_key=schedule_key,
        )
    raise ValueError(f"unsupported pack traffic cadence pattern: {pattern}")
