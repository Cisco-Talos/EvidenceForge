"""Dimension 5: Signal Integrity scoring.

Sub-scores (0.25 each):
  Event Presence — storyline events produced at least one trace in logs.
  Indicator Accuracy — found traces carry correct IPs, usernames, hostnames, processes.
  Pivot Linkability — consecutive storyline steps share a pivotable indicator.
  Storyline Temporal Integrity — events in correct order at correct times.
"""

import logging
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any

from evidenceforge.evaluation.dimensions import (
    DimensionScorer,
    ProgressCallback,
    _noop_callback,
)
from evidenceforge.evaluation.models import DimensionScore, SubScore
from evidenceforge.evaluation.parsers import ParsedRecord
from evidenceforge.models.scenario import Scenario, StorylineEvent
from evidenceforge.utils.time import parse_duration, parse_iso8601

logger = logging.getLogger(__name__)

# Time tolerance for matching storyline events to log records
TIME_TOLERANCE = timedelta(seconds=120)

# Keyword map for activity-to-event-type matching (mirrors generation/engine.py)
ACTIVITY_KEYWORDS: dict[str, list[str]] = {
    "logon": ["logon", "log in", "login", "authenticate", "sign in", "exploit"],
    "logoff": ["logoff", "log off", "logout", "sign out"],
    "process": [
        "execute", "run", "launch", "start", "spawn",
        "powershell", "cmd", "command",
    ],
    "connection": [
        "connect", "access", "download", "upload",
        "communicate", "c2", "exfiltrate",
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
    traces: list[ParsedRecord] = field(default_factory=list)


class SignalIntegrityScorer(DimensionScorer):
    number = 5
    name = "Signal Integrity"
    weight = 0.20

    def score(
        self,
        records: dict[str, list[ParsedRecord]],
        scenario: Scenario,
        progress: ProgressCallback = _noop_callback,
    ) -> DimensionScore:
        storyline = scenario.storyline or []
        if not storyline:
            return self._empty_score()

        # Step 1: Resolve storyline to absolute timeline
        resolved = self._resolve_storyline(storyline, scenario)

        # Step 2: Find traces for each event
        self._find_traces(resolved, records)

        # Step 3: Score sub-dimensions
        progress("sub_score_start", {"name": "Event Presence", "step": 1, "total": 4})
        event_presence = self._score_event_presence(resolved)
        progress("sub_score_done", {"name": "Event Presence", "score": event_presence.score})

        progress("sub_score_start", {"name": "Indicator Accuracy", "step": 2, "total": 4})
        indicator_accuracy = self._score_indicator_accuracy(resolved)
        progress("sub_score_done", {"name": "Indicator Accuracy", "score": indicator_accuracy.score})

        progress("sub_score_start", {"name": "Pivot Linkability", "step": 3, "total": 4})
        pivot_linkability = self._score_pivot_linkability(resolved)
        progress("sub_score_done", {"name": "Pivot Linkability", "score": pivot_linkability.score})

        progress("sub_score_start", {"name": "Storyline Temporal Integrity", "step": 4, "total": 4})
        temporal_integrity = self._score_temporal_integrity(resolved)
        progress("sub_score_done", {"name": "Storyline Temporal Integrity", "score": temporal_integrity.score})

        sub_scores = [event_presence, indicator_accuracy, pivot_linkability, temporal_integrity]
        dim_score = sum(s.score * s.weight for s in sub_scores if s.score is not None)

        return DimensionScore(
            number=self.number,
            name=self.name,
            weight=self.weight,
            score=dim_score,
            sub_scores=sub_scores,
        )

    def _empty_score(self) -> DimensionScore:
        """Return a perfect score when there's no storyline to check."""
        sub = SubScore(name="N/A", key="no_storyline", weight=1.0, score=100.0,
                       details="No storyline events to evaluate")
        return DimensionScore(
            number=self.number, name=self.name, weight=self.weight,
            score=100.0, sub_scores=[sub],
        )

    # --- Step 1: Resolve storyline ---

    def _resolve_storyline(
        self, storyline: list[StorylineEvent], scenario: Scenario,
    ) -> list[ResolvedEvent]:
        start_time = scenario.time_window.start
        if start_time.tzinfo is None:
            start_time = start_time.replace(tzinfo=timezone.utc)

        system_ips = {s.hostname: s.ip for s in scenario.environment.systems}
        resolved: list[ResolvedEvent] = []

        for i, event in enumerate(storyline):
            event_time = self._parse_event_time(event.time, start_time)
            event_types = self._match_activity(event.activity)

            resolved.append(ResolvedEvent(
                index=i,
                time=event_time,
                actor=event.actor,
                system=event.system,
                system_ip=system_ips.get(event.system),
                activity=event.activity,
                details=event.details or {},
                event_types=event_types,
            ))

        return resolved

    @staticmethod
    def _parse_event_time(time_str: str, start_time: datetime) -> datetime:
        """Parse a storyline time to absolute datetime."""
        if time_str[0].isdigit() and len(time_str) > 10:
            ts = parse_iso8601(time_str)
            if ts.tzinfo is None:
                ts = ts.replace(tzinfo=timezone.utc)
            return ts

        if time_str.startswith("+"):
            offset_str = time_str[1:]
            if offset_str.isdigit():
                offset = timedelta(seconds=int(offset_str))
            else:
                offset = parse_duration(offset_str)
            return start_time + offset

        raise ValueError(f"Invalid storyline time: {time_str}")

    @staticmethod
    def _match_activity(activity: str) -> list[str]:
        """Match activity description to event types via keywords."""
        activity_lower = activity.lower()
        matched = [
            etype for etype, keywords in ACTIVITY_KEYWORDS.items()
            if any(kw in activity_lower for kw in keywords)
        ]
        return matched if matched else ["process"]

    # --- Step 2: Find traces ---

    def _find_traces(
        self,
        resolved: list[ResolvedEvent],
        records: dict[str, list[ParsedRecord]],
    ) -> None:
        """Search parsed records for traces of each storyline event.

        Uses a host-time index for O(1) lookups instead of scanning all records.
        """
        # Build host-time index: (hostname_lower|minute_bucket) -> format -> records
        host_time_index: dict[str, dict[str, list[ParsedRecord]]] = defaultdict(
            lambda: defaultdict(list)
        )
        for format_name, record_list in records.items():
            for rec in record_list:
                if rec.timestamp is None:
                    continue
                # Extract hostname from various field names
                hostname = None
                for field in ("Computer", "hostname"):
                    val = rec.fields.get(field)
                    if val and isinstance(val, str):
                        hostname = val
                        break
                # For zeek/snort, index by originator IP too
                ts = rec.timestamp
                if ts.tzinfo is None:
                    ts = ts.replace(tzinfo=timezone.utc)
                bucket = int(ts.timestamp()) // 60
                if hostname:
                    host_time_index[f"{hostname.lower()}|{bucket}"][format_name].append(rec)
                orig_ip = rec.fields.get("id.orig_h")
                if orig_ip:
                    host_time_index[f"{orig_ip}|{bucket}"][format_name].append(rec)

        for event in resolved:
            for event_type in event.event_types:
                traces = self._search_for_event_indexed(
                    event, event_type, host_time_index
                )
                event.traces.extend(traces)

    def _search_for_event_indexed(
        self,
        event: ResolvedEvent,
        event_type: str,
        host_time_index: dict[str, dict[str, list[ParsedRecord]]],
    ) -> list[ParsedRecord]:
        """Search for event traces using host-time index."""
        found: list[ParsedRecord] = []
        evt_time = event.time
        if evt_time.tzinfo is None:
            evt_time = evt_time.replace(tzinfo=timezone.utc)
        evt_bucket = int(evt_time.timestamp()) // 60

        # Lookup keys: system hostname + system IP
        lookup_keys = [event.system.lower()]
        if event.system_ip:
            lookup_keys.append(event.system_ip)

        seen: set[int] = set()  # Deduplicate records found via multiple keys
        for hostname_key in lookup_keys:
            for b in range(evt_bucket - 2, evt_bucket + 3):
                key = f"{hostname_key}|{b}"
                if key not in host_time_index:
                    continue
                for format_name, recs in host_time_index[key].items():
                    for record in recs:
                        if id(record) in seen:
                            continue
                        ts = record.timestamp
                        if ts is None:
                            continue
                        if ts.tzinfo is None:
                            ts = ts.replace(tzinfo=timezone.utc)
                        if abs((ts - evt_time).total_seconds()) > TIME_TOLERANCE.total_seconds():
                            continue
                        if self._record_matches(record, format_name, event, event_type):
                            found.append(record)
                            seen.add(id(record))

        return found

    def _record_matches(
        self,
        record: ParsedRecord,
        format_name: str,
        event: ResolvedEvent,
        event_type: str,
    ) -> bool:
        """Check if a record is a trace of a storyline event."""
        f = record.fields

        if event_type == "logon":
            if format_name == "windows_event_security":
                return (
                    f.get("EventID") == 4624
                    and self._user_matches(f.get("TargetUserName"), event.actor)
                    and self._host_matches(f.get("Computer"), event.system)
                )
            if format_name == "syslog":
                return (
                    self._host_matches(f.get("hostname"), event.system)
                    and event.actor in f.get("message", "")
                )
            if format_name == "ecar":
                return (
                    f.get("object") == "USER_SESSION"
                    and f.get("action") == "LOGIN"
                    and self._user_matches(f.get("principal"), event.actor)
                    and self._host_matches(f.get("hostname"), event.system)
                )

        elif event_type == "process":
            if format_name == "windows_event_security":
                return (
                    f.get("EventID") == 4688
                    and self._host_matches(f.get("Computer"), event.system)
                    and (
                        self._user_matches(f.get("SubjectUserName"), event.actor)
                        or self._user_matches(f.get("TargetUserName"), event.actor)
                    )
                )
            if format_name == "bash_history":
                return (
                    self._host_matches(f.get("hostname"), event.system)
                    and self._user_matches(f.get("username"), event.actor)
                )
            if format_name == "ecar":
                return (
                    f.get("object") == "PROCESS"
                    and f.get("action") == "CREATE"
                    and self._host_matches(f.get("hostname"), event.system)
                    and self._user_matches(f.get("principal"), event.actor)
                )

        elif event_type == "connection":
            if format_name == "zeek_conn":
                return self._connection_matches_zeek(f, event)
            if format_name == "ecar":
                return (
                    f.get("object") == "FLOW"
                    and f.get("action") == "CONNECT"
                    and self._host_matches(f.get("hostname"), event.system)
                )

        return False

    def _connection_matches_zeek(self, fields: dict, event: ResolvedEvent) -> bool:
        """Check if a Zeek record matches a connection storyline event."""
        orig_h = fields.get("id.orig_h", "")
        resp_h = fields.get("id.resp_h", "")
        details = event.details

        # System IP should be originator
        if event.system_ip and orig_h == event.system_ip:
            # If dst_ip specified, check responder
            if "dst_ip" in details:
                return resp_h == details["dst_ip"]
            return True

        # Or check if dst_ip from details matches
        if "dst_ip" in details and resp_h == details["dst_ip"]:
            return True
        if "source_ip" in details and orig_h == details["source_ip"]:
            return True

        return False

    @staticmethod
    def _user_matches(record_user: Any, expected: str) -> bool:
        if record_user is None:
            return False
        return str(record_user).lower() == expected.lower()

    @staticmethod
    def _host_matches(record_host: Any, expected: str) -> bool:
        if record_host is None:
            return False
        return str(record_host).lower() == expected.lower()

    # --- Step 3: Scoring ---

    def _score_event_presence(self, resolved: list[ResolvedEvent]) -> SubScore:
        total = len(resolved)
        found = sum(1 for e in resolved if e.traces)
        failures = [
            f"Event {e.index}: {e.actor}@{e.system} '{e.activity[:60]}' — no traces"
            for e in resolved if not e.traces
        ]
        score = (100.0 * found / total) if total > 0 else 100.0
        return SubScore(
            name="Event Presence", key="event_presence", weight=0.25,
            score=score,
            details=f"{found}/{total} storyline events have traces in logs",
            sample_failures=failures[:10],
        )

    def _score_indicator_accuracy(self, resolved: list[ResolvedEvent]) -> SubScore:
        total_checks = 0
        correct_checks = 0
        failures: list[str] = []

        for event in resolved:
            if not event.traces:
                continue

            # Check indicators against each trace
            for trace in event.traces:
                checks = self._check_indicators(event, trace)
                for indicator_name, is_correct in checks:
                    total_checks += 1
                    if is_correct:
                        correct_checks += 1
                    elif len(failures) < 10:
                        failures.append(
                            f"Event {event.index}: {indicator_name} mismatch in {trace.source_format}"
                        )

        score = (100.0 * correct_checks / total_checks) if total_checks > 0 else 100.0
        return SubScore(
            name="Indicator Accuracy", key="indicator_accuracy", weight=0.25,
            score=score,
            details=f"{correct_checks}/{total_checks} indicator checks correct",
            sample_failures=failures,
        )

    def _check_indicators(
        self, event: ResolvedEvent, trace: ParsedRecord,
    ) -> list[tuple[str, bool]]:
        """Check expected indicators against a trace record. Returns (name, correct) pairs."""
        checks: list[tuple[str, bool]] = []
        f = trace.fields
        details = event.details

        # Username check
        username_fields = ["TargetUserName", "SubjectUserName", "principal", "username"]
        for uf in username_fields:
            if uf in f and f[uf]:
                checks.append(("username", self._user_matches(f[uf], event.actor)))
                break

        # Hostname check
        hostname_fields = ["Computer", "hostname"]
        for hf in hostname_fields:
            if hf in f and f[hf]:
                checks.append(("hostname", self._host_matches(f[hf], event.system)))
                break

        # Source IP (if specified in details)
        if "source_ip" in details:
            ip_fields = ["IpAddress", "id.orig_h", "src_ip"]
            for ipf in ip_fields:
                if ipf in f and f[ipf] and f[ipf] != "-":
                    checks.append(("source_ip", f[ipf] == details["source_ip"]))
                    break

        # Destination IP (if specified in details)
        if "dst_ip" in details:
            dst_fields = ["id.resp_h", "dst_ip"]
            for df in dst_fields:
                if df in f and f[df]:
                    checks.append(("dst_ip", f[df] == details["dst_ip"]))
                    break

        return checks

    def _score_pivot_linkability(self, resolved: list[ResolvedEvent]) -> SubScore:
        if len(resolved) < 2:
            return SubScore(
                name="Pivot Linkability", key="pivot_linkability", weight=0.25,
                score=100.0, details="Fewer than 2 events — nothing to link",
            )

        total_pairs = len(resolved) - 1
        linkable = 0
        failures: list[str] = []

        for i in range(total_pairs):
            a, b = resolved[i], resolved[i + 1]
            indicators_a = self._extract_indicator_values(a)
            indicators_b = self._extract_indicator_values(b)

            if indicators_a & indicators_b:
                linkable += 1
            elif len(failures) < 10:
                failures.append(
                    f"Events {i}→{i+1}: no shared indicator "
                    f"({a.actor}@{a.system} → {b.actor}@{b.system})"
                )

        score = (100.0 * linkable / total_pairs) if total_pairs > 0 else 100.0
        return SubScore(
            name="Pivot Linkability", key="pivot_linkability", weight=0.25,
            score=score,
            details=f"{linkable}/{total_pairs} consecutive pairs share a pivotable indicator",
            sample_failures=failures,
        )

    def _extract_indicator_values(self, event: ResolvedEvent) -> set[str]:
        """Extract all indicator values from an event's traces and scenario data."""
        values: set[str] = set()
        values.add(event.actor.lower())
        values.add(event.system.lower())
        if event.system_ip:
            values.add(event.system_ip)

        details = event.details
        for key in ("source_ip", "dst_ip"):
            if key in details and details[key]:
                values.add(str(details[key]))

        # Also extract from actual traces
        for trace in event.traces:
            f = trace.fields
            for field_name in ("TargetUserName", "SubjectUserName", "principal",
                               "username", "Computer", "hostname",
                               "IpAddress", "id.orig_h", "id.resp_h",
                               "src_ip", "dst_ip"):
                val = f.get(field_name)
                if val and val != "-":
                    values.add(str(val).lower())

        return values

    def _score_temporal_integrity(self, resolved: list[ResolvedEvent]) -> SubScore:
        total = len(resolved)
        correct = 0
        failures: list[str] = []

        # Check each event's traces are in the right time neighborhood
        # and that events are ordered correctly
        prev_earliest: datetime | None = None

        for event in resolved:
            if not event.traces:
                # No traces = can't verify timing; count as incorrect
                if len(failures) < 10:
                    failures.append(
                        f"Event {event.index}: no traces to verify timing"
                    )
                continue

            # Find earliest trace timestamp for this event
            trace_times = []
            for t in event.traces:
                if t.timestamp:
                    ts = t.timestamp
                    if ts.tzinfo is None:
                        ts = ts.replace(tzinfo=timezone.utc)
                    trace_times.append(ts)

            if not trace_times:
                continue

            earliest = min(trace_times)

            # Check time is within tolerance of expected
            time_ok = abs((earliest - event.time).total_seconds()) <= TIME_TOLERANCE.total_seconds()
            # Check ordering: this event's traces should be after previous event's
            order_ok = prev_earliest is None or earliest >= prev_earliest - timedelta(seconds=5)

            if time_ok and order_ok:
                correct += 1
            elif len(failures) < 10:
                if not time_ok:
                    delta = (earliest - event.time).total_seconds()
                    failures.append(
                        f"Event {event.index}: trace at {delta:+.0f}s from expected (tolerance ±{TIME_TOLERANCE.total_seconds():.0f}s)"
                    )
                if not order_ok:
                    failures.append(
                        f"Event {event.index}: out of order relative to previous event"
                    )

            prev_earliest = earliest

        score = (100.0 * correct / total) if total > 0 else 100.0
        return SubScore(
            name="Storyline Temporal Integrity", key="temporal_integrity", weight=0.25,
            score=score,
            details=f"{correct}/{total} events correctly timed and ordered",
            sample_failures=failures,
        )
