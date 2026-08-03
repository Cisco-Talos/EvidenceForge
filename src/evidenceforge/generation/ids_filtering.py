# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Deterministic sensor-local IDS alert filtering state machines."""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass
from datetime import datetime

from evidenceforge.events.contexts import IdsAlertPolicyContext


@dataclass(frozen=True, slots=True)
class IdsAlertCandidate:
    """One signature match observed by one IDS sensor."""

    sensor: str
    timestamp: datetime
    gid: int
    sid: int
    src_ip: str
    dst_ip: str
    policy: IdsAlertPolicyContext | None


@dataclass(slots=True)
class _EventWindow:
    start: datetime
    matches: int = 0
    emitted: bool = False


class IdsAlertFilterEngine:
    """Apply Snort-style filters to timestamp-ordered alert candidates."""

    def __init__(self) -> None:
        self._detection_windows: dict[tuple[object, ...], deque[datetime]] = {}
        self._event_windows: dict[tuple[object, ...], _EventWindow] = {}

    @staticmethod
    def _tracked_ip(candidate: IdsAlertCandidate, track: str) -> str:
        return candidate.src_ip if track == "by_src" else candidate.dst_ip

    def admit(self, candidate: IdsAlertCandidate) -> bool:
        """Return whether an observed signature match should be logged."""

        policy = candidate.policy
        if policy is None:
            return True
        detection = policy.detection_filter
        if detection is not None:
            key = (
                candidate.sensor,
                candidate.gid,
                candidate.sid,
                "detection",
                detection.track,
                self._tracked_ip(candidate, detection.track),
            )
            timestamps = self._detection_windows.setdefault(key, deque())
            while (
                timestamps
                and (candidate.timestamp - timestamps[0]).total_seconds() >= detection.seconds
            ):
                timestamps.popleft()
            timestamps.append(candidate.timestamp)
            if len(timestamps) <= detection.count:
                return False

        event_filter = policy.event_filter
        if event_filter is None:
            return True
        key = (
            candidate.sensor,
            candidate.gid,
            candidate.sid,
            "event",
            event_filter.type,
            event_filter.track,
            self._tracked_ip(candidate, event_filter.track),
        )
        window = self._event_windows.get(key)
        if (
            window is None
            or (candidate.timestamp - window.start).total_seconds() >= event_filter.seconds
        ):
            window = _EventWindow(start=candidate.timestamp)
            self._event_windows[key] = window
        window.matches += 1

        if event_filter.type == "limit":
            return window.matches <= event_filter.count
        if event_filter.type == "threshold":
            if window.matches < event_filter.count:
                return False
            self._event_windows.pop(key, None)
            return True
        if window.emitted or window.matches < event_filter.count:
            return False
        window.emitted = True
        return True
