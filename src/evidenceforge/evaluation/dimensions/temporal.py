"""Dimension 4: Temporal Realism scoring.

Sub-scores (0.20 each):
  Work Hour Distribution — user events cluster in persona work hours.
  Human Burstiness — inter-event timing shows burst-and-idle (CV 1-3).
  System Process Regularity — system events show periodic patterns.
  Causal Ordering — known causal pairs correctly sequenced.
  Timing Plausibility — no physically impossible timing.
"""

import logging
import math
import statistics
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from typing import Any
from zoneinfo import ZoneInfo

from evidenceforge.evaluation.dimensions import (
    DimensionScorer,
    ProgressCallback,
    _noop_callback,
)
from evidenceforge.evaluation.models import DimensionScore, SubScore
from evidenceforge.evaluation.parsers import ParsedRecord
from evidenceforge.evaluation.rules import load_rules_file
from evidenceforge.models.scenario import Scenario
from evidenceforge.validation.schema import BUILTIN_ACCOUNTS

logger = logging.getLogger(__name__)

# Formats that carry user attribution
_USER_FIELD_MAP: dict[str, list[str]] = {
    "windows_event_security": ["TargetUserName", "SubjectUserName"],
    "bash_history": ["username"],
    "ecar": ["principal"],
    "web_access": ["username"],
    "syslog": [],  # user extracted from message
}

# Formats that carry hostname
_HOST_FIELD_MAP: dict[str, str] = {
    "windows_event_security": "Computer",
    "bash_history": "hostname",
    "ecar": "hostname",
    "syslog": "hostname",
}


def _extract_username(record: ParsedRecord) -> str | None:
    """Extract username from a parsed record."""
    fmt = record.source_format
    fields = record.fields

    user_fields = _USER_FIELD_MAP.get(fmt, [])
    for uf in user_fields:
        val = fields.get(uf)
        if val and isinstance(val, str) and val != "-":
            return val.lower()

    # Syslog: try to extract from message
    if fmt == "syslog":
        msg = fields.get("message", "")
        # Common patterns: "for <user>", "user=<user>"
        for pattern_prefix in ["for ", "user="]:
            idx = msg.find(pattern_prefix)
            if idx >= 0:
                rest = msg[idx + len(pattern_prefix):]
                user = rest.split()[0].strip("'\"") if rest else None
                if user:
                    return user.lower()

    return None


def _extract_hostname(record: ParsedRecord) -> str | None:
    """Extract hostname from a parsed record, normalizing FQDN to bare hostname."""
    field_name = _HOST_FIELD_MAP.get(record.source_format)
    if field_name:
        val = record.fields.get(field_name)
        if val and isinstance(val, str):
            # Strip domain suffix for FQDN normalization
            hostname = val.lower()
            if not hostname[0].isdigit() and "." in hostname:
                hostname = hostname.split(".")[0]
            return hostname
    return None


def _extract_system_service(record: ParsedRecord) -> str:
    """Identify which system service generated a record."""
    fmt = record.source_format
    f = record.fields
    if fmt == "zeek_conn":
        svc = f.get("service", "")
        if svc:
            return svc
        port = f.get("id.resp_p")
        if port == 53:
            return "dns"
        if port == 123:
            return "ntp"
        if port == 445:
            return "smb"
        proto = f.get("proto", "")
        if proto == "icmp":
            return "icmp"
    if fmt in ("windows_event_security", "ecar"):
        proc = f.get("NewProcessName", "") or f.get("image_path", "")
        proc_lower = proc.lower()
        if "svchost" in proc_lower or "taskhostw" in proc_lower or "usoclient" in proc_lower:
            return "scheduled_task"
    if fmt == "syslog":
        app = f.get("app_name", "")
        if app in ("cron", "anacron", "systemd"):
            return "scheduled_task"
    return "other"


class TemporalRealismScorer(DimensionScorer):
    number = 4
    name = "Temporal Realism"
    weight = 0.15

    def score(
        self,
        records: dict[str, list[ParsedRecord]],
        scenario: Scenario,
        progress: ProgressCallback = _noop_callback,
    ) -> DimensionScore:
        # Pre-compute user→timestamps grouping (used by 3 sub-scores)
        user_events = self._group_by_user(records)

        progress("sub_score_start", {"name": "Work Hour Distribution", "step": 1, "total": 5})
        s1 = self._score_work_hours(user_events, scenario)
        progress("sub_score_done", {"name": "Work Hour Distribution", "score": s1.score})

        progress("sub_score_start", {"name": "Human Burstiness", "step": 2, "total": 5})
        s2 = self._score_burstiness(user_events)
        progress("sub_score_done", {"name": "Human Burstiness", "score": s2.score})

        progress("sub_score_start", {"name": "System Process Regularity", "step": 3, "total": 5})
        s3 = self._score_system_regularity(records)
        progress("sub_score_done", {"name": "System Process Regularity", "score": s3.score})

        progress("sub_score_start", {"name": "Causal Ordering", "step": 4, "total": 5})
        s4 = self._score_causal_ordering(records)
        progress("sub_score_done", {"name": "Causal Ordering", "score": s4.score})

        progress("sub_score_start", {"name": "Timing Plausibility", "step": 5, "total": 5})
        s5 = self._score_timing_plausibility(user_events, records)
        progress("sub_score_done", {"name": "Timing Plausibility", "score": s5.score})

        sub_scores = [s1, s2, s3, s4, s5]
        dim_score = sum(s.score * s.weight for s in sub_scores if s.score is not None)

        return DimensionScore(
            number=self.number, name=self.name, weight=self.weight,
            score=dim_score, sub_scores=sub_scores,
        )

    # --- Sub-score 1: Work Hour Distribution ---

    def _score_work_hours(
        self,
        user_events: dict[str, list[datetime]],
        scenario: Scenario,
    ) -> SubScore:
        # Build user→persona work hours mapping
        persona_map = {}
        if scenario.personas:
            persona_map = {p.name: p for p in scenario.personas}

        user_to_hours: dict[str, list[int]] = {}
        for user in scenario.environment.users:
            if user.persona and user.persona in persona_map:
                persona = persona_map[user.persona]
                if persona.work_hours_parsed:
                    user_to_hours[user.username.lower()] = persona.work_hours_parsed.get("hours", [])

        if not user_to_hours:
            return SubScore(
                name="Work Hour Distribution", key="work_hours", weight=0.20,
                score=100.0, details="No persona work hours defined — skipped",
            )

        # Resolve scenario timezone (work hours are in local time)
        tz_name = "UTC"
        if scenario.environment.timezone and scenario.environment.timezone.default:
            tz_name = scenario.environment.timezone.default
        try:
            scenario_tz = ZoneInfo(tz_name)
        except (KeyError, ValueError):
            scenario_tz = timezone.utc

        # Check work hour adherence using pre-computed user events
        user_scores: list[float] = []
        for username, work_hours in user_to_hours.items():
            if not work_hours:
                continue
            events = user_events.get(username, [])
            if len(events) < 5:
                continue

            in_hours = sum(1 for ts in events if ts.astimezone(scenario_tz).hour in work_hours)
            ratio = in_hours / len(events)

            # Score: 80-95% in work hours = 100, below/above penalized
            if 0.80 <= ratio <= 0.95:
                user_scores.append(100.0)
            elif ratio < 0.80:
                user_scores.append(max(0.0, 100.0 * (ratio / 0.80)))
            else:  # > 0.95 (too perfect)
                user_scores.append(max(0.0, 100.0 * (1.0 - (ratio - 0.95) / 0.05)))

        score = statistics.mean(user_scores) if user_scores else 100.0
        return SubScore(
            name="Work Hour Distribution", key="work_hours", weight=0.20,
            score=score,
            details=f"Scored {len(user_scores)} users with persona work hours",
        )

    # --- Sub-score 2: Human Burstiness ---

    def _score_burstiness(self, user_events: dict[str, list[datetime]]) -> SubScore:
        cv_scores: list[float] = []
        system_accounts_lower = {a.lower() for a in BUILTIN_ACCOUNTS}

        for username, timestamps in user_events.items():
            if username in system_accounts_lower:
                continue
            if len(timestamps) < 10:
                continue

            sorted_ts = sorted(timestamps)

            # Deduplicate: collapse events within 5s into single activity points.
            # Multi-format emission (4624 + 4688 + eCAR at same time) creates many
            # sub-second gaps that dilute the CV. We care about inter-activity CV.
            deduped = [sorted_ts[0]]
            for ts in sorted_ts[1:]:
                if (ts - deduped[-1]).total_seconds() > 5.0:
                    deduped.append(ts)

            if len(deduped) < 10:
                continue

            gaps = [
                (deduped[i + 1] - deduped[i]).total_seconds()
                for i in range(len(deduped) - 1)
            ]
            if len(gaps) < 5:
                continue

            mean_gap = statistics.mean(gaps)
            if mean_gap == 0:
                continue
            std_gap = statistics.stdev(gaps)
            cv = std_gap / mean_gap

            # Score: CV in [1.0, 3.0] → 100. CV < 0.5 → 0. Linear between.
            if 1.0 <= cv <= 3.0:
                cv_scores.append(100.0)
            elif cv < 0.5:
                cv_scores.append(0.0)
            elif cv < 1.0:
                cv_scores.append(100.0 * (cv - 0.5) / 0.5)
            else:  # cv > 3.0
                cv_scores.append(max(0.0, 100.0 * (1.0 - (cv - 3.0) / 3.0)))

        score = statistics.mean(cv_scores) if cv_scores else 100.0
        return SubScore(
            name="Human Burstiness", key="burstiness", weight=0.20,
            score=score,
            details=f"CV scores for {len(cv_scores)} users (target CV 1.0-3.0)",
        )

    # --- Sub-score 3: System Process Regularity ---

    def _score_system_regularity(self, records: dict[str, list[ParsedRecord]]) -> SubScore:
        system_accounts_lower = {a.lower() for a in BUILTIN_ACCOUNTS}

        # Group system events by (hostname, service_type) to preserve per-service periodicity
        service_timestamps: dict[tuple[str, str], list[datetime]] = defaultdict(list)
        total_system_events = 0

        for format_name, record_list in records.items():
            for record in record_list:
                if record.timestamp is None:
                    continue
                user = _extract_username(record)
                if user and user in system_accounts_lower:
                    hostname = _extract_hostname(record)
                    if not hostname:
                        continue
                    service = _extract_system_service(record)
                    ts = record.timestamp
                    if ts.tzinfo is None:
                        ts = ts.replace(tzinfo=timezone.utc)
                    service_timestamps[(hostname, service)].append(ts)
                    total_system_events += 1

        if total_system_events < 20:
            return SubScore(
                name="System Process Regularity", key="system_regularity", weight=0.20,
                score=100.0,
                details=f"Only {total_system_events} system events — insufficient for analysis",
            )

        # Compute per-(host, service) autocorrelation, then average
        autocorrs: list[float] = []
        for key, timestamps in service_timestamps.items():
            sorted_ts = sorted(timestamps)
            intervals = [
                (sorted_ts[i + 1] - sorted_ts[i]).total_seconds()
                for i in range(len(sorted_ts) - 1)
            ]
            intervals = [iv for iv in intervals if iv > 0]
            if len(intervals) >= 10:
                autocorrs.append(self._lag1_autocorrelation(intervals))

        if not autocorrs:
            return SubScore(
                name="System Process Regularity", key="system_regularity", weight=0.20,
                score=100.0, details="Insufficient per-service interval data",
            )

        autocorr = statistics.mean(autocorrs)

        # Score: autocorr > 0.5 → 100, < 0.1 → 0, linear between
        # (relaxed from 0.7/0.2 — real system traffic has inherent jitter)
        if autocorr >= 0.5:
            score = 100.0
        elif autocorr <= 0.1:
            score = 0.0
        else:
            score = 100.0 * (autocorr - 0.1) / 0.4

        return SubScore(
            name="System Process Regularity", key="system_regularity", weight=0.20,
            score=score,
            details=f"Lag-1 autocorrelation: {autocorr:.2f} (avg of {len(autocorrs)} hosts, {total_system_events} events)",
        )

    # --- Sub-score 4: Causal Ordering ---

    def _score_causal_ordering(self, records: dict[str, list[ParsedRecord]]) -> SubScore:
        causal_rules = load_rules_file("causal_pairs.yaml")
        pairs_list = causal_rules.get("pairs", [])
        if not pairs_list:
            return SubScore(
                name="Causal Ordering", key="causal_ordering", weight=0.20,
                score=100.0, details="No causal pair rules defined",
            )

        total_pairs = 0
        correct_pairs = 0
        failures: list[str] = []

        for rule in pairs_list:
            before_fmt = rule["before"]["format"]
            after_fmt = rule["after"]["format"]
            before_cond = rule["before"].get("condition", {})
            after_cond = rule["after"].get("condition", {})
            match_fields = rule.get("match_fields", {})
            before_field = match_fields.get("before")
            after_field = match_fields.get("after")
            extra_match = rule.get("extra_match")

            # Special case: syslog message_contains
            msg_contains = rule.get("before", {}).get("message_contains")

            before_records = records.get(before_fmt, [])
            after_records = records.get(after_fmt, [])

            if not before_records or not after_records:
                continue

            # Build index of "before" records by match field value
            before_index: dict[str, list[ParsedRecord]] = defaultdict(list)
            for rec in before_records:
                if rec.timestamp is None:
                    continue
                if msg_contains:
                    if msg_contains not in rec.fields.get("message", ""):
                        continue
                elif not self._condition_matches(before_cond, rec.fields):
                    continue
                if before_field:
                    key_val = rec.fields.get(before_field)
                    if key_val:
                        idx_key = str(key_val)
                        if extra_match:
                            extra_val = rec.fields.get(extra_match, "")
                            idx_key = f"{idx_key}|{extra_val}"
                        before_index[idx_key].append(rec)

            # Check each "after" record for a matching "before"
            for rec in after_records:
                if rec.timestamp is None:
                    continue
                if not self._condition_matches(after_cond, rec.fields):
                    continue
                if after_field:
                    key_val = rec.fields.get(after_field)
                    if not key_val:
                        continue
                    idx_key = str(key_val)
                    if extra_match:
                        extra_val = rec.fields.get(extra_match, "")
                        idx_key = f"{idx_key}|{extra_val}"

                    matching_befores = before_index.get(idx_key, [])
                    if not matching_befores:
                        continue  # No matching before — not a countable pair

                    total_pairs += 1
                    # Check that at least one before is earlier
                    any_before_earlier = any(
                        b.timestamp <= rec.timestamp
                        for b in matching_befores
                        if b.timestamp is not None
                    )
                    if any_before_earlier:
                        correct_pairs += 1
                    elif len(failures) < 10:
                        failures.append(
                            f"Rule '{rule['name']}': after event at line {rec.line_number} "
                            f"precedes all matching before events"
                        )

        score = (100.0 * correct_pairs / total_pairs) if total_pairs > 0 else 100.0
        return SubScore(
            name="Causal Ordering", key="causal_ordering", weight=0.20,
            score=score,
            details=f"{correct_pairs}/{total_pairs} causal pairs correctly ordered",
            sample_failures=failures,
        )

    # --- Sub-score 5: Timing Plausibility ---

    def _score_timing_plausibility(
        self,
        user_events: dict[str, list[datetime]],
        records: dict[str, list[ParsedRecord]] | None = None,
    ) -> SubScore:
        total_checks = 0
        plausible = 0
        failures: list[str] = []

        # Check 1: Command rate per user per 5-second window
        system_accounts_lower = {a.lower() for a in BUILTIN_ACCOUNTS}

        for username, timestamps in user_events.items():
            if username in system_accounts_lower:
                continue
            if len(timestamps) < 2:
                continue

            sorted_ts = sorted(timestamps)
            # Sliding window: count events in 5-second windows
            window_sec = 5.0
            max_per_window = 20

            i = 0
            while i < len(sorted_ts):
                window_end = sorted_ts[i] + timedelta(seconds=window_sec)
                j = i
                while j < len(sorted_ts) and sorted_ts[j] <= window_end:
                    j += 1
                count = j - i
                total_checks += 1
                if count <= max_per_window:
                    plausible += 1
                elif len(failures) < 10:
                    failures.append(
                        f"User '{username}': {count} events in 5s window at {sorted_ts[i]}"
                    )
                i = j if j > i else i + 1

        # Check 2: Zeek transfer speed
        zeek_records = records.get("zeek_conn", []) if records else []
        for record in zeek_records:
            duration = record.fields.get("duration")
            orig_bytes = record.fields.get("orig_bytes")
            if duration and orig_bytes and isinstance(duration, (int, float)) and duration > 0:
                try:
                    bytes_val = float(orig_bytes)
                    speed_gbps = (bytes_val * 8) / (float(duration) * 1e9)
                    total_checks += 1
                    if speed_gbps <= 10.0:
                        plausible += 1
                    elif len(failures) < 10:
                        failures.append(
                            f"Zeek conn: {speed_gbps:.1f} Gbps transfer (line {record.line_number})"
                        )
                except (ValueError, TypeError):
                    pass

        score = (100.0 * plausible / total_checks) if total_checks > 0 else 100.0
        return SubScore(
            name="Timing Plausibility", key="timing_plausibility", weight=0.20,
            score=score,
            details=f"{plausible}/{total_checks} timing checks plausible",
            sample_failures=failures,
        )

    # --- Helpers ---

    @staticmethod
    def _normalize_ts(ts: datetime) -> datetime:
        """Ensure a datetime is timezone-aware (UTC)."""
        if ts.tzinfo is None:
            return ts.replace(tzinfo=timezone.utc)
        return ts

    @staticmethod
    def _get_user_events(
        records: dict[str, list[ParsedRecord]], username: str,
    ) -> list[datetime]:
        """Get all timestamped events for a specific user."""
        timestamps: list[datetime] = []
        for format_name, record_list in records.items():
            for record in record_list:
                if record.timestamp is None:
                    continue
                user = _extract_username(record)
                if user and user == username:
                    ts = record.timestamp
                    if ts.tzinfo is None:
                        ts = ts.replace(tzinfo=timezone.utc)
                    timestamps.append(ts)
        return timestamps

    @staticmethod
    def _group_by_user(
        records: dict[str, list[ParsedRecord]],
    ) -> dict[str, list[datetime]]:
        """Group record timestamps by extracted username."""
        user_events: dict[str, list[datetime]] = defaultdict(list)
        for format_name, record_list in records.items():
            for record in record_list:
                if record.timestamp is None:
                    continue
                user = _extract_username(record)
                if user:
                    ts = record.timestamp
                    if ts.tzinfo is None:
                        ts = ts.replace(tzinfo=timezone.utc)
                    user_events[user].append(ts)
        return dict(user_events)

    @staticmethod
    def _condition_matches(condition: dict[str, Any], fields: dict[str, Any]) -> bool:
        """Check if record fields match a condition dict."""
        for key, expected in condition.items():
            actual = fields.get(key)
            if actual != expected:
                try:
                    if str(actual) != str(expected):
                        return False
                except (ValueError, TypeError):
                    return False
        return True

    @staticmethod
    def _lag1_autocorrelation(values: list[float]) -> float:
        """Compute lag-1 autocorrelation of a series."""
        n = len(values)
        if n < 3:
            return 0.0

        mean_val = statistics.mean(values)
        var_val = statistics.variance(values)
        if var_val == 0:
            return 1.0  # Constant series = perfectly periodic

        x = values[:-1]
        y = values[1:]
        cov = sum((xi - mean_val) * (yi - mean_val) for xi, yi in zip(x, y)) / (n - 1)
        return cov / var_val
