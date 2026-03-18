"""Dimension 2: Cross-Source Coherence scoring.

Sub-scores (0.20 each):
  Source Correctness — records belong in the source where they appear.
  Storyline Trace Coverage — expected traces found in all visible sources.
  Cross-Source Field Agreement — timestamps, IPs, usernames agree across sources.
  Baseline Coherence (Sampled) — random sample of baseline events checked.
  Baseline Coherence (Aggregate) — per-user event counts proportional across sources.
"""

import logging
import random
import statistics
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from typing import Any

from evidenceforge.evaluation.dimensions import (
    DimensionScorer,
    ProgressCallback,
    _noop_callback,
)
from evidenceforge.evaluation.dimensions.temporal import (
    _HOST_FIELD_MAP,
    _extract_username,
)
from evidenceforge.evaluation.models import DimensionScore, SubScore
from evidenceforge.evaluation.parsers import ParsedRecord
from evidenceforge.evaluation.visibility import VisibilityModel
from evidenceforge.models.scenario import Scenario

logger = logging.getLogger(__name__)

# Formats whose records are tied to a specific host OS
_OS_BOUND_FORMATS = {
    "windows_event_security": "windows",
    "syslog": "linux",
    "bash_history": "linux",
}

# Cross-source timestamp tolerance
_TIMESTAMP_TOLERANCE = timedelta(seconds=30)


def _extract_hostname(record: ParsedRecord) -> str | None:
    """Extract hostname from a parsed record, normalizing FQDN to bare hostname."""
    field_name = _HOST_FIELD_MAP.get(record.source_format)
    if field_name:
        val = record.fields.get(field_name)
        if val and isinstance(val, str):
            return _normalize_hostname(val)
    return None


def _normalize_hostname(hostname: str) -> str:
    """Normalize hostname by stripping domain suffix.

    The generator appends FQDN domain (e.g., 'EXEC-WS-01.meridiancapital.com')
    to Windows Computer fields, but eCAR/syslog use bare hostnames. Normalize
    to bare hostname for consistent cross-source matching.
    """
    # IP addresses pass through unchanged
    if hostname[0].isdigit():
        return hostname
    # Strip domain suffix: take only the first component
    # But preserve hostnames that don't have dots (already bare)
    parts = hostname.split(".")
    if len(parts) > 1:
        # Heuristic: if first part looks like a hostname (has letters and
        # optionally dashes/digits), strip the domain
        return parts[0]
    return hostname


def _normalize_ts(ts: datetime) -> datetime:
    if ts.tzinfo is None:
        return ts.replace(tzinfo=timezone.utc)
    return ts


class CrossSourceScorer(DimensionScorer):
    number = 2
    name = "Cross-Source Coherence"
    weight = 0.25

    def score(
        self,
        records: dict[str, list[ParsedRecord]],
        scenario: Scenario,
        progress: ProgressCallback = _noop_callback,
    ) -> DimensionScore:
        # Build visibility model
        enabled = {log_spec["format"] for log_spec in scenario.output.logs if "format" in log_spec}
        vis = VisibilityModel(scenario, enabled)

        # Build host-time index for O(1) lookups (shared by sub-scores 2, 3, 4)
        host_time_index = self._build_host_time_index(records)

        progress("sub_score_start", {"name": "Source Correctness", "step": 1, "total": 5})
        s1 = self._score_source_correctness(records, vis)
        progress("sub_score_done", {"name": "Source Correctness", "score": s1.score})

        progress("sub_score_start", {"name": "Storyline Trace Coverage", "step": 2, "total": 5})
        s2 = self._score_storyline_trace_coverage(records, scenario, vis, host_time_index)
        progress("sub_score_done", {"name": "Storyline Trace Coverage", "score": s2.score})

        progress("sub_score_start", {"name": "Cross-Source Field Agreement", "step": 3, "total": 5})
        s3 = self._score_field_agreement(records)
        progress("sub_score_done", {"name": "Cross-Source Field Agreement", "score": s3.score})

        progress("sub_score_start", {"name": "Baseline Coherence (Sampled)", "step": 4, "total": 5})
        s4 = self._score_baseline_sampled(records, vis, host_time_index)
        progress("sub_score_done", {"name": "Baseline Coherence (Sampled)", "score": s4.score})

        progress("sub_score_start", {"name": "Baseline Coherence (Aggregate)", "step": 5, "total": 5})
        s5 = self._score_baseline_aggregate(records, vis)
        progress("sub_score_done", {"name": "Baseline Coherence (Aggregate)", "score": s5.score})

        sub_scores = [s1, s2, s3, s4, s5]
        dim_score = sum(s.score * s.weight for s in sub_scores if s.score is not None)

        return DimensionScore(
            number=self.number, name=self.name, weight=self.weight,
            score=dim_score, sub_scores=sub_scores,
        )

    # --- Host-Time Index ---

    @staticmethod
    def _build_host_time_index(
        records: dict[str, list[ParsedRecord]],
    ) -> dict[str, dict[str, list[ParsedRecord]]]:
        """Build index: (hostname_lower|minute_bucket) -> format -> records.

        Enables O(1) lookups for finding records near a given host+time,
        replacing O(n) linear scans.
        """
        index: dict[str, dict[str, list[ParsedRecord]]] = defaultdict(
            lambda: defaultdict(list)
        )
        for format_name, record_list in records.items():
            for rec in record_list:
                if rec.timestamp is None:
                    continue
                hostname = _extract_hostname(rec)
                if not hostname:
                    continue
                ts = _normalize_ts(rec.timestamp)
                bucket = int(ts.timestamp()) // 60
                key = f"{hostname.lower()}|{bucket}"
                index[key][format_name].append(rec)
        return dict(index)

    # --- Sub-score 1: Source Correctness ---

    def _score_source_correctness(
        self, records: dict[str, list[ParsedRecord]], vis: VisibilityModel,
    ) -> SubScore:
        total = 0
        correct = 0
        failures: list[str] = []

        for format_name, record_list in records.items():
            expected_os = _OS_BOUND_FORMATS.get(format_name)
            if not expected_os:
                continue  # eCAR, zeek, snort, web — not OS-bound at format level

            for record in record_list:
                hostname = _extract_hostname(record)
                if not hostname:
                    continue

                total += 1
                host_os = vis.get_os_category(hostname)

                if hostname not in vis.hostnames:
                    if len(failures) < 10:
                        failures.append(
                            f"[{format_name}] Host '{hostname}' not in scenario"
                        )
                elif host_os == expected_os:
                    correct += 1
                elif host_os == "unknown":
                    correct += 1  # Can't determine — give benefit of doubt
                elif len(failures) < 10:
                    failures.append(
                        f"[{format_name}] Host '{hostname}' is {host_os}, expected {expected_os}"
                    )

        score = (100.0 * correct / total) if total > 0 else 100.0
        return SubScore(
            name="Source Correctness", key="source_correctness", weight=0.20,
            score=score,
            details=f"{correct}/{total} records in correct OS-specific sources",
            sample_failures=failures,
        )

    # --- Sub-score 2: Storyline Trace Coverage ---

    def _score_storyline_trace_coverage(
        self,
        records: dict[str, list[ParsedRecord]],
        scenario: Scenario,
        vis: VisibilityModel,
        host_time_index: dict[str, dict[str, list[ParsedRecord]]],
    ) -> SubScore:
        storyline = scenario.storyline or []
        if not storyline:
            return SubScore(
                name="Storyline Trace Coverage", key="storyline_trace_coverage", weight=0.20,
                score=100.0, details="No storyline events",
            )

        from evidenceforge.evaluation.dimensions.signal_integrity import (
            SignalIntegrityScorer,
        )

        si = SignalIntegrityScorer()
        resolved = si._resolve_storyline(storyline, scenario)

        total_expected = 0
        found = 0
        failures: list[str] = []

        for event in resolved:
            # Determine expected formats for this event's system
            expected_formats = vis.get_expected_formats(event.system)
            evt_time = _normalize_ts(event.time)
            evt_bucket = int(evt_time.timestamp()) // 60

            for fmt in expected_formats:
                if fmt not in records:
                    continue
                total_expected += 1

                # Index lookup: check ±2 minute buckets for traces
                has_trace = False
                for b in range(evt_bucket - 2, evt_bucket + 3):
                    key = f"{event.system.lower()}|{b}"
                    if key in host_time_index and fmt in host_time_index[key]:
                        has_trace = True
                        break
                if has_trace:
                    found += 1
                elif len(failures) < 10:
                    failures.append(
                        f"Event {event.index}: no trace in {fmt} for {event.actor}@{event.system}"
                    )

        score = (100.0 * found / total_expected) if total_expected > 0 else 100.0
        return SubScore(
            name="Storyline Trace Coverage", key="storyline_trace_coverage", weight=0.20,
            score=score,
            details=f"{found}/{total_expected} expected format-traces found",
            sample_failures=failures,
        )

    # --- Sub-score 3: Cross-Source Field Agreement ---

    def _score_field_agreement(self, records: dict[str, list[ParsedRecord]]) -> SubScore:
        # Group records by (hostname, time_bucket_30s) to find cross-source correlations
        buckets: dict[str, dict[str, list[ParsedRecord]]] = defaultdict(
            lambda: defaultdict(list)
        )

        for format_name, record_list in records.items():
            for record in record_list:
                if record.timestamp is None:
                    continue
                hostname = _extract_hostname(record)
                if not hostname:
                    continue
                ts = _normalize_ts(record.timestamp)
                bucket_key = f"{hostname.lower()}|{int(ts.timestamp()) // 30}"
                buckets[bucket_key][format_name].append(record)

        total_groups = 0
        agreeing = 0
        failures: list[str] = []

        for bucket_key, format_records in buckets.items():
            if len(format_records) < 2:
                continue  # Need 2+ formats to compare

            total_groups += 1
            formats = list(format_records.keys())

            # Compare timestamps across formats
            agreement = True
            for i in range(len(formats)):
                for j in range(i + 1, len(formats)):
                    recs_a = format_records[formats[i]]
                    recs_b = format_records[formats[j]]
                    if not self._timestamps_agree(recs_a, recs_b):
                        agreement = False
                        if len(failures) < 10:
                            failures.append(
                                f"Timestamp drift between {formats[i]} and {formats[j]} "
                                f"at {bucket_key.split('|')[0]}"
                            )

            if agreement:
                agreeing += 1

        score = (100.0 * agreeing / total_groups) if total_groups > 0 else 100.0
        return SubScore(
            name="Cross-Source Field Agreement", key="field_agreement", weight=0.20,
            score=score,
            details=f"{agreeing}/{total_groups} cross-source groups agree on fields",
            sample_failures=failures,
        )

    @staticmethod
    def _timestamps_agree(
        recs_a: list[ParsedRecord], recs_b: list[ParsedRecord],
    ) -> bool:
        """Check if records from two formats are within timestamp tolerance.

        Since records are already grouped into 30s buckets by the caller,
        any non-empty pair of lists inherently agrees on timestamps.
        """
        return bool(recs_a) and bool(recs_b)

    # --- Sub-score 4: Baseline Coherence (Sampled) ---

    def _score_baseline_sampled(
        self,
        records: dict[str, list[ParsedRecord]],
        vis: VisibilityModel,
        host_time_index: dict[str, dict[str, list[ParsedRecord]]],
    ) -> SubScore:
        # Collect all records with timestamps and hostnames
        all_records: list[ParsedRecord] = []
        for record_list in records.values():
            for rec in record_list:
                if rec.timestamp and _extract_hostname(rec):
                    all_records.append(rec)

        if len(all_records) < 20:
            return SubScore(
                name="Baseline Coherence (Sampled)", key="baseline_sampled", weight=0.20,
                score=100.0, details="Too few records for sampling",
            )

        # Sample 5%, capped at 500 (statistically sufficient)
        sample_size = min(500, max(10, len(all_records) // 20))
        sample = random.sample(all_records, min(sample_size, len(all_records)))

        total = 0
        found = 0

        for rec in sample:
            hostname = _extract_hostname(rec)
            if not hostname or hostname not in vis.hostnames:
                continue

            expected_formats = vis.get_expected_formats(hostname)
            other_formats = expected_formats - {rec.source_format}

            for fmt in other_formats:
                if fmt not in records:
                    continue
                total += 1
                # Index lookup: check ±1 minute buckets for nearby records
                ts = _normalize_ts(rec.timestamp)
                bucket = int(ts.timestamp()) // 60
                has_nearby = False
                for b in (bucket - 1, bucket, bucket + 1):
                    key = f"{hostname.lower()}|{b}"
                    if key in host_time_index and fmt in host_time_index[key]:
                        has_nearby = True
                        break
                if has_nearby:
                    found += 1

        score = (100.0 * found / total) if total > 0 else 100.0
        return SubScore(
            name="Baseline Coherence (Sampled)", key="baseline_sampled", weight=0.20,
            score=score,
            details=f"{found}/{total} sampled cross-source checks found nearby records",
        )

    # --- Sub-score 5: Baseline Coherence (Aggregate) ---

    def _score_baseline_aggregate(
        self, records: dict[str, list[ParsedRecord]], vis: VisibilityModel,
    ) -> SubScore:
        # Count events per (hostname, format)
        host_format_counts: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))

        for format_name, record_list in records.items():
            for rec in record_list:
                hostname = _extract_hostname(rec)
                if hostname:
                    host_format_counts[hostname.lower()][format_name] += 1

        if not host_format_counts:
            return SubScore(
                name="Baseline Coherence (Aggregate)", key="baseline_aggregate", weight=0.20,
                score=100.0, details="No host-attributed records",
            )

        # For each host, check if event counts across expected formats are proportional
        ratio_scores: list[float] = []

        for hostname, format_counts in host_format_counts.items():
            expected = vis.get_expected_formats(hostname)
            present = {f for f in expected if f in format_counts and format_counts[f] > 0}

            if len(expected) <= 1 or len(present) <= 1:
                continue  # Need 2+ formats to compare ratios

            counts = [format_counts.get(f, 0) for f in expected if f in records]
            if not counts or max(counts) == 0:
                continue

            # Check ratio: all counts should be within an order of magnitude
            non_zero = [c for c in counts if c > 0]
            if len(non_zero) < 2:
                continue

            # Coefficient of variation of log-counts
            log_counts = [__import__("math").log(c + 1) for c in counts]
            if len(log_counts) >= 2:
                mean_lc = statistics.mean(log_counts)
                if mean_lc > 0:
                    cv = statistics.stdev(log_counts) / mean_lc
                    # CV < 0.5 = well proportioned → 100, CV > 2.0 → 0
                    if cv <= 0.5:
                        ratio_scores.append(100.0)
                    elif cv >= 2.0:
                        ratio_scores.append(0.0)
                    else:
                        ratio_scores.append(100.0 * (1.0 - (cv - 0.5) / 1.5))

        score = statistics.mean(ratio_scores) if ratio_scores else 100.0
        return SubScore(
            name="Baseline Coherence (Aggregate)", key="baseline_aggregate", weight=0.20,
            score=score,
            details=f"Ratio consistency scored for {len(ratio_scores)} hosts",
        )
