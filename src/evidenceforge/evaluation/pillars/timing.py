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

"""Pillar 4: Timing scoring.

Sub-scores (weights sum to 1.0):
  attack_chain_timing (0.15): Consecutive storyline transitions within plausible bounds.
  burstiness          (0.20): User inter-event times are bursty (CV 1-3), not metronomic.
  system_regularity   (0.15): System processes show appropriate inter-event regularity.
  diurnal_pattern     (0.20): User events cluster within persona work hours/days (2D JSD).
  volume_adequacy     (0.20): Sufficient background noise relative to attack signal.
  rate_plausibility   (0.10): No impossible event rates.
"""

import logging
import statistics
from collections import defaultdict
from datetime import UTC, datetime, timedelta
from typing import Any
from zoneinfo import ZoneInfo

from evidenceforge.evaluation._shared import (
    _extract_hostname,
    _extract_username,
    _jensen_shannon_2d,
)
from evidenceforge.evaluation.context import EvaluationContext
from evidenceforge.evaluation.dimensions import (
    DimensionScorer,
    ProgressCallback,
    _noop_callback,
    aggregate_sub_scores,
)
from evidenceforge.evaluation.models import PillarScore, SubScore
from evidenceforge.evaluation.parsers import ParsedRecord
from evidenceforge.evaluation.rules import load_rules_file
from evidenceforge.evaluation.storyline import resolve_storyline
from evidenceforge.models.scenario import Scenario
from evidenceforge.validation.schema import BUILTIN_ACCOUNTS

logger = logging.getLogger(__name__)

_VOLUME_TARGETS = {"low": 200, "medium": 2000, "high": 5000}
_RATE_PLAUSIBILITY_WINDOWS_EVENT_IDS = frozenset(
    {
        4624,  # successful logon
        4625,  # failed logon
        4648,  # explicit credentials
        4688,  # process creation
        4720,  # account created
        4723,  # password change
        4724,  # password reset
        4726,  # account deleted
        4728,  # group membership added
        4729,  # group membership removed
        4732,  # local group membership added
        4733,  # local group membership removed
        4738,  # account changed
        4756,  # universal group membership added
        4757,  # universal group membership removed
        4800,  # workstation locked
        4801,  # workstation unlocked
    }
)


class TimingScorer(DimensionScorer):
    number = 4
    name = "Timing"
    weight = 0.20

    def score(
        self,
        records: dict[str, list[ParsedRecord]],
        scenario: Scenario,
        context: EvaluationContext | None = None,
        progress: ProgressCallback = _noop_callback,
    ) -> PillarScore:
        user_events = _group_by_user(records)

        progress("sub_score_start", {"name": "Attack Chain Timing", "step": 1, "total": 6})
        s1 = self._score_attack_chain_timing(scenario)
        progress("sub_score_done", {"name": "Attack Chain Timing", "score": s1.score})

        progress("sub_score_start", {"name": "Human Burstiness", "step": 2, "total": 6})
        s2 = self._score_burstiness(user_events)
        progress("sub_score_done", {"name": "Human Burstiness", "score": s2.score})

        progress("sub_score_start", {"name": "System Process Regularity", "step": 3, "total": 6})
        s3 = self._score_system_regularity(records)
        progress("sub_score_done", {"name": "System Process Regularity", "score": s3.score})

        progress("sub_score_start", {"name": "Diurnal Pattern", "step": 4, "total": 6})
        s4 = self._score_diurnal_pattern(user_events, scenario)
        progress("sub_score_done", {"name": "Diurnal Pattern", "score": s4.score})

        progress("sub_score_start", {"name": "Volume Adequacy", "step": 5, "total": 6})
        s5 = self._score_volume_adequacy(records, scenario)
        progress("sub_score_done", {"name": "Volume Adequacy", "score": s5.score})

        progress("sub_score_start", {"name": "Rate Plausibility", "step": 6, "total": 6})
        s6 = self._score_rate_plausibility(user_events, records)
        progress("sub_score_done", {"name": "Rate Plausibility", "score": s6.score})

        sub_scores = [s1, s2, s3, s4, s5, s6]
        dim_score = aggregate_sub_scores(sub_scores)

        return PillarScore(
            number=self.number,
            name=self.name,
            weight=self.weight,
            score=dim_score,
            sub_scores=sub_scores,
        )

    # --- Sub-score 1: Attack Chain Timing ---

    def _score_attack_chain_timing(self, scenario: Scenario) -> SubScore:
        storyline = scenario.storyline or []
        if len(storyline) < 2:
            return SubScore(
                name="Attack Chain Timing",
                key="attack_chain_timing",
                weight=0.15,
                score=100.0,
                details="No consecutive storyline pairs to evaluate",
            )

        resolved = resolve_storyline(storyline, scenario)
        bounds_config = load_rules_file("timing_bounds.yaml")
        defaults = bounds_config.get("defaults", {})
        default_min = defaults.get("min_seconds", 5)
        default_max = defaults.get("max_seconds", 7200)
        action_overrides = bounds_config.get("action_overrides", {})

        total_pairs = 0
        in_bounds = 0
        failures: list[str] = []

        for i in range(len(resolved) - 1):
            curr = resolved[i]
            nxt = resolved[i + 1]
            elapsed = max(0.0, (nxt.time - curr.time).total_seconds())

            min_sec = default_min
            max_sec = default_max
            activity_lower = nxt.activity.lower()
            for keyword, override in action_overrides.items():
                if keyword.lower() in activity_lower:
                    min_sec = override.get("min_seconds", default_min)
                    max_sec = override.get("max_seconds", default_max)
                    break

            total_pairs += 1
            if min_sec <= elapsed <= max_sec:
                in_bounds += 1
            elif len(failures) < 10:
                if elapsed < min_sec:
                    failures.append(
                        f"Events {i}→{i + 1}: {elapsed:.0f}s < min {min_sec}s "
                        f"('{nxt.activity[:40]}')"
                    )
                else:
                    failures.append(
                        f"Events {i}→{i + 1}: {elapsed:.0f}s > max {max_sec}s "
                        f"('{nxt.activity[:40]}')"
                    )

        score = (100.0 * in_bounds / total_pairs) if total_pairs > 0 else 100.0
        return SubScore(
            name="Attack Chain Timing",
            key="attack_chain_timing",
            weight=0.15,
            score=score,
            details=f"{in_bounds}/{total_pairs} storyline transitions within bounds",
            sample_failures=failures,
        )

    # --- Sub-score 2: Human Burstiness ---

    def _score_burstiness(self, user_events: dict[str, list[datetime]]) -> SubScore:
        system_accounts_lower = {a.lower() for a in BUILTIN_ACCOUNTS}
        cv_scores: list[float] = []

        for username, timestamps in user_events.items():
            if username in system_accounts_lower:
                continue
            if len(timestamps) < 30:
                continue

            sorted_ts = sorted(timestamps)
            deduped = [sorted_ts[0]]
            for ts in sorted_ts[1:]:
                if (ts - deduped[-1]).total_seconds() > 5.0:
                    deduped.append(ts)

            if len(deduped) < 20:
                continue

            gaps = [(deduped[i + 1] - deduped[i]).total_seconds() for i in range(len(deduped) - 1)]
            if len(gaps) < 5:
                continue

            mean_gap = statistics.mean(gaps)
            if mean_gap == 0:
                continue
            cv = statistics.stdev(gaps) / mean_gap

            if 1.0 <= cv <= 3.0:
                cv_scores.append(100.0)
            elif cv < 0.5:
                cv_scores.append(0.0)
            elif cv < 1.0:
                cv_scores.append(100.0 * (cv - 0.5) / 0.5)
            else:
                cv_scores.append(max(0.0, 100.0 * (1.0 - (cv - 3.0) / 3.0)))

        score = statistics.mean(cv_scores) if cv_scores else 100.0
        return SubScore(
            name="Human Burstiness",
            key="burstiness",
            weight=0.20,
            score=score,
            details=f"CV scores for {len(cv_scores)} users (target CV 1.0-3.0)",
        )

    # --- Sub-score 3: System Process Regularity ---

    def _score_system_regularity(self, records: dict[str, list[ParsedRecord]]) -> SubScore:
        system_accounts_lower = {a.lower() for a in BUILTIN_ACCOUNTS}
        service_timestamps: dict[tuple[str, str], list[datetime]] = defaultdict(list)
        total_system_events = 0

        for _fmt, record_list in records.items():
            for record in record_list:
                if record.timestamp is None:
                    continue
                user = _extract_username(record)
                if user and user in system_accounts_lower:
                    hostname = _extract_hostname(record)
                    if not hostname:
                        continue
                    service = _extract_system_service(record)
                    if service == "other":
                        continue
                    ts = record.timestamp
                    if ts.tzinfo is None:
                        ts = ts.replace(tzinfo=UTC)
                    service_timestamps[(hostname, service)].append(ts)
                    total_system_events += 1

        if total_system_events < 20:
            return SubScore(
                name="System Process Regularity",
                key="system_regularity",
                weight=0.15,
                score=100.0,
                details=f"Only {total_system_events} system events — insufficient",
            )

        cv_scores: list[float] = []
        for _key, timestamps in service_timestamps.items():
            sorted_ts = sorted(timestamps)
            intervals = [
                (sorted_ts[i + 1] - sorted_ts[i]).total_seconds() for i in range(len(sorted_ts) - 1)
            ]
            intervals = [iv for iv in intervals if iv > 0]
            if len(intervals) >= 10:
                mean_iv = statistics.mean(intervals)
                if mean_iv > 0:
                    cv = statistics.stdev(intervals) / mean_iv
                    cv_scores.append(cv)

        if not cv_scores:
            return SubScore(
                name="System Process Regularity",
                key="system_regularity",
                weight=0.15,
                score=100.0,
                details="Insufficient per-service interval data",
            )

        avg_cv = statistics.mean(cv_scores)
        if avg_cv < 0.05:
            score = 50.0
        elif avg_cv < 0.15:
            score = 50.0 + 50.0 * (avg_cv - 0.05) / 0.10
        elif avg_cv <= 1.0:
            score = 100.0
        elif avg_cv <= 2.0:
            score = 100.0 * (2.0 - avg_cv)
        else:
            score = 0.0

        return SubScore(
            name="System Process Regularity",
            key="system_regularity",
            weight=0.15,
            score=score,
            details=f"Interval CV: {avg_cv:.3f} ({len(cv_scores)} service groups, {total_system_events} events)",
        )

    # --- Sub-score 4: Diurnal Pattern ---

    def _score_diurnal_pattern(
        self,
        user_events: dict[str, list[datetime]],
        scenario: Scenario,
    ) -> SubScore:
        persona_map = {}
        if scenario.personas:
            persona_map = {p.name: p for p in scenario.personas}

        user_to_persona: dict[str, Any] = {}
        for user in scenario.environment.users:
            if user.persona and user.persona in persona_map:
                user_to_persona[user.username.lower()] = persona_map[user.persona]

        tz_name = "UTC"
        if scenario.environment.timezone and scenario.environment.timezone.default:
            tz_name = scenario.environment.timezone.default
        try:
            scenario_tz = ZoneInfo(tz_name)
        except (KeyError, ValueError):
            scenario_tz = UTC

        # Short-scenario guard: the reference distribution spans Mon-Fri × work hours,
        # so observed data covering <2 weekdays or <24h cannot produce a meaningful
        # JSD. Mark skipped and let the aggregator renormalize remaining sub-scores.
        all_ts = [ts for events in user_events.values() for ts in events]
        if all_ts:
            min_ts = min(all_ts).astimezone(scenario_tz)
            max_ts = max(all_ts).astimezone(scenario_tz)
            span_hours = (max_ts - min_ts).total_seconds() / 3600.0
            distinct_weekdays = {ts.astimezone(scenario_tz).weekday() for ts in all_ts}
            if span_hours < 24.0 or len(distinct_weekdays) < 2:
                return SubScore(
                    name="Diurnal Pattern",
                    key="diurnal_pattern",
                    weight=0.20,
                    score=None,
                    skipped=True,
                    details=(
                        f"Scenario spans {span_hours:.1f}h across "
                        f"{len(distinct_weekdays)} weekday(s) — too short to measure "
                        "diurnal pattern (needs ≥24h and ≥2 weekdays)"
                    ),
                )

        user_scores: list[float] = []
        for username, persona in user_to_persona.items():
            events = user_events.get(username, [])
            if len(events) < 30:
                continue

            observed: dict[tuple[int, int], int] = defaultdict(int)
            for ts in events:
                local_ts = ts.astimezone(scenario_tz)
                observed[(local_ts.weekday(), local_ts.hour)] += 1

            work_hours: list[int] = []
            if persona.work_hours_parsed:
                work_hours = persona.work_hours_parsed.get("hours", [])
            if not work_hours:
                work_hours = list(range(8, 18))

            work_days = list(range(5))
            reference: dict[tuple[int, int], float] = {}
            work_buckets = [(d, h) for d in work_days for h in work_hours]
            if work_buckets:
                weight_per_bucket = 0.85 / len(work_buckets)
                for bucket in work_buckets:
                    reference[bucket] = weight_per_bucket
                off_buckets = [
                    (d, h) for d in range(7) for h in range(24) if (d, h) not in reference
                ]
                if off_buckets:
                    off_weight = 0.15 / len(off_buckets)
                    for bucket in off_buckets:
                        reference[bucket] = off_weight
            else:
                uniform = 1.0 / (7 * 24)
                reference = {(d, h): uniform for d in range(7) for h in range(24)}

            total = sum(observed.values())
            obs_prob = {k: v / total for k, v in observed.items()}
            jsd = _jensen_shannon_2d(obs_prob, reference)

            if jsd < 0.01:
                user_score = max(0.0, 100.0 * (jsd / 0.01))
            elif jsd >= 0.4:
                user_score = 0.0
            else:
                user_score = 100.0 * (1.0 - jsd / 0.4)

            user_scores.append(user_score)

        score = statistics.mean(user_scores) if user_scores else 100.0
        return SubScore(
            name="Diurnal Pattern",
            key="diurnal_pattern",
            weight=0.20,
            score=score,
            details=f"Scored {len(user_scores)} users (hour×weekday 2D JSD)",
        )

    # --- Sub-score 5: Volume Adequacy ---

    def _score_volume_adequacy(
        self,
        records: dict[str, list[ParsedRecord]],
        scenario: Scenario,
    ) -> SubScore:
        storyline = scenario.storyline or []
        if not storyline:
            return SubScore(
                name="Volume Adequacy",
                key="volume_adequacy",
                weight=0.20,
                score=100.0,
                details="No storyline — volume check skipped",
            )

        signal_count = len(storyline)
        total_records = sum(len(recs) for recs in records.values())
        noise_count = max(0, total_records - signal_count)
        ratio = noise_count / max(signal_count, 1)

        target = _VOLUME_TARGETS.get(scenario.baseline_activity.intensity, 5000)
        half_target = target / 2

        if ratio >= target:
            score = 100.0
        elif ratio <= half_target:
            score = 0.0
        else:
            score = 100.0 * (ratio - half_target) / (target - half_target)

        return SubScore(
            name="Volume Adequacy",
            key="volume_adequacy",
            weight=0.20,
            score=score,
            details=f"Noise:signal {ratio:.0f}:1 (target {target}:1 for {scenario.baseline_activity.intensity})",
        )

    # --- Sub-score 6: Rate Plausibility ---

    def _score_rate_plausibility(
        self,
        user_events: dict[str, list[datetime]],
        records: dict[str, list[ParsedRecord]] | None = None,
    ) -> SubScore:
        if records is not None:
            user_events = _group_rate_plausibility_user_events(records)

        total_checks = 0
        plausible = 0
        failures: list[str] = []
        system_accounts_lower = {a.lower() for a in BUILTIN_ACCOUNTS}

        for username, timestamps in user_events.items():
            if username in system_accounts_lower:
                continue
            if len(timestamps) < 2:
                continue

            sorted_ts = sorted(timestamps)
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

        zeek_records = records.get("zeek_conn", []) if records else []
        for record in zeek_records:
            duration = record.fields.get("duration")
            orig_bytes = record.fields.get("orig_bytes")
            if duration and orig_bytes and isinstance(duration, (int, float)) and duration > 0:
                try:
                    speed_gbps = (float(orig_bytes) * 8) / (float(duration) * 1e9)
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
            name="Rate Plausibility",
            key="rate_plausibility",
            weight=0.10,
            score=score,
            details=f"{plausible}/{total_checks} timing checks plausible",
            sample_failures=failures,
        )


# --- Module-level helpers ---


def _group_by_user(records: dict[str, list[ParsedRecord]]) -> dict[str, list[datetime]]:
    user_events: dict[str, list[datetime]] = defaultdict(list)
    for _fmt, record_list in records.items():
        for record in record_list:
            if record.timestamp is None:
                continue
            user = _extract_username(record)
            if user:
                ts = record.timestamp
                if ts.tzinfo is None:
                    ts = ts.replace(tzinfo=UTC)
                user_events[user].append(ts)
    return dict(user_events)


def _group_rate_plausibility_user_events(
    records: dict[str, list[ParsedRecord]],
) -> dict[str, list[datetime]]:
    user_events: dict[str, list[datetime]] = defaultdict(list)
    for _fmt, record_list in records.items():
        for record in record_list:
            if record.timestamp is None or not _is_rate_plausibility_user_event(record):
                continue
            user = _extract_username(record)
            if user:
                ts = record.timestamp
                if ts.tzinfo is None:
                    ts = ts.replace(tzinfo=UTC)
                user_events[user].append(ts)
    return dict(user_events)


def _is_rate_plausibility_user_event(record: ParsedRecord) -> bool:
    fmt = record.source_format
    fields = record.fields

    if fmt == "windows_event_security":
        event_id = fields.get("EventID")
        if event_id is None:
            return True
        return event_id in _RATE_PLAUSIBILITY_WINDOWS_EVENT_IDS

    if fmt == "ecar":
        obj = str(fields.get("object") or "").upper()
        action = str(fields.get("action") or "").upper()
        if obj == "USER_SESSION":
            return action in {"LOGIN", "FAILED_LOGIN"}
        if obj == "PROCESS":
            return action not in {"TERMINATE", "EXIT"}
        return False

    if fmt == "syslog":
        message = str(fields.get("message") or "").lower()
        lifecycle_fragments = (
            "session closed",
            "session close",
            "logged out",
            "connection closed",
        )
        return not any(fragment in message for fragment in lifecycle_fragments)

    return fmt in {"bash_history", "web_access"}


def _extract_system_service(record: ParsedRecord) -> str:
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
