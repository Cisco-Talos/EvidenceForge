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

"""Shared storyline resolution logic used by both Causality and Timing pillars."""

from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any

from evidenceforge.evaluation.parsers import ParsedRecord
from evidenceforge.models.scenario import Scenario, StorylineEvent
from evidenceforge.utils.time import parse_duration, parse_iso8601

# Time tolerance for matching storyline events to log records
TIME_TOLERANCE = timedelta(seconds=120)

# Event types that span a duration (beacons, tunnels, scans). For these we search
# a forward window equal to min(first_interval, 1h) so the first repetition is
# found even if the generator delays its start slightly.
_DURATION_EVENT_TYPES = frozenset({"beacon", "dns_tunnel", "dga_queries", "web_scan"})

# Keyword map for activity-to-event-type matching (mirrors generation/engine.py)
ACTIVITY_KEYWORDS: dict[str, list[str]] = {
    "logon": [
        "logon",
        "log in",
        "login",
        "authenticate",
        "sign in",
        "exploit",
        "ssh",
        "rdp",
        "remote",
        "pivot",
        "credential",
    ],
    "logoff": ["logoff", "log off", "logout", "sign out"],
    "process": [
        "execute",
        "run",
        "launch",
        "start",
        "spawn",
        "powershell",
        "cmd",
        "command",
        "search",
        "read",
        "enumerate",
        "dump",
        "query",
        "list",
        "archive",
        "compress",
        "delete",
        "remove",
        "clean",
    ],
    "connection": [
        "connect",
        "access",
        "download",
        "upload",
        "communicate",
        "c2",
        "exfiltrate",
        "ssh",
        "rdp",
        "remote",
        "pivot",
    ],
}


@dataclass
class ResolvedEvent:
    """A storyline event resolved to an absolute timeline with expected indicators."""

    index: int
    time: datetime
    actor: str
    system: str
    system_ip: str | None
    activity: str
    details: dict[str, Any]
    event_types: list[str]
    sub_details: list[dict[str, Any]] = field(default_factory=list)
    traces: list[ParsedRecord] = field(default_factory=list)
    storyline_id: str = ""


def _parse_event_time(time_str: str, start_time: datetime) -> datetime:
    """Parse a storyline time string to an absolute datetime."""
    if time_str[0].isdigit() and len(time_str) > 10:
        ts = parse_iso8601(time_str)
        if ts.tzinfo is None:
            ts = ts.replace(tzinfo=UTC)
        return ts

    if time_str.startswith("+"):
        offset_str = time_str[1:]
        if offset_str.isdigit():
            offset = timedelta(seconds=int(offset_str))
        else:
            offset = parse_duration(offset_str)
        return start_time + offset

    raise ValueError(f"Invalid storyline time: {time_str}")


def _match_activity(activity: str) -> list[str]:
    """Match activity description to event types via keywords."""
    activity_lower = activity.lower()
    matched = [
        etype
        for etype, keywords in ACTIVITY_KEYWORDS.items()
        if any(kw in activity_lower for kw in keywords)
    ]
    return matched if matched else ["process"]


def resolve_storyline(
    storyline: list[StorylineEvent],
    scenario: Scenario,
) -> list[ResolvedEvent]:
    """Resolve storyline events to absolute datetimes with indicator metadata.

    Does not use any scorer instance state — safe to call from any pillar.
    """
    start_time = scenario.time_window.start
    if start_time.tzinfo is None:
        start_time = start_time.replace(tzinfo=UTC)

    system_ips = {s.hostname: s.ip for s in scenario.environment.systems}
    resolved: list[ResolvedEvent] = []

    for i, event in enumerate(storyline):
        event_time = _parse_event_time(event.time, start_time)
        if event.events:
            event_types = list({spec.type for spec in event.events})
        else:
            event_types = _match_activity(event.activity)

        sub_details: list[dict[str, Any]] = []
        details: dict[str, Any] = {}
        for spec in event.events:
            spec_dict = spec.model_dump(
                exclude_none=True, exclude={"type", "technique", "description", "supplementary"}
            )
            sub_details.append(spec_dict)
            details.update(spec_dict)

        resolved.append(
            ResolvedEvent(
                index=i,
                time=event_time,
                actor=event.actor,
                system=event.system,
                system_ip=system_ips.get(event.system),
                activity=event.activity,
                details=details,
                event_types=event_types,
                sub_details=sub_details,
                storyline_id=event.id,
            )
        )

    return resolved
