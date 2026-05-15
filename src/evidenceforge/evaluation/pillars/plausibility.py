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

"""Pillar 2: Plausibility scoring.

Sub-scores (weights sum to 1.0):
  value_plausibility  (0.25): No impossible field values / OS cross-contamination.
  co_occurrence       (0.20): Field combinations that must/must not co-occur.
  distribution_fit    (0.15): Event-type proportions vs reference profiles.
  field_agreement     (0.15): Cross-source field agreement via pivot-key joins.
  user_diversity      (0.15): Different users behave differently.
  anomaly_rate        (0.10): Realistic 1-5% anomalous-but-benign event rate.
"""

import logging
import math
import random
from collections import Counter, defaultdict
from datetime import UTC, datetime
from typing import Any

from evidenceforge.evaluation._shared import (
    _condition_matches,
    _extract_hostname,
    _extract_username,
    _jensen_shannon_divergence,
)
from evidenceforge.evaluation.anomaly import detect_anomalies
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
from evidenceforge.evaluation.visibility import VisibilityModel
from evidenceforge.models.scenario import Scenario

logger = logging.getLogger(__name__)

# Formats whose records are tied to a specific host OS
_OS_BOUND_FORMATS = {
    "windows_event_security": "windows",
    "syslog": "linux",
    "bash_history": "linux",
}

# Cross-source agreement uses attacker-controlled eval log input. Keep pivot joins bounded so
# a single high-cardinality collision bucket cannot force quadratic CPU work.
_MAX_PIVOT_BUCKET_RECORDS = 256
_MAX_FIELD_AGREEMENT_MATCHES = 100_000


class PlausibilityScorer(DimensionScorer):
    number = 2
    name = "Plausibility"
    weight = 0.25

    def score(
        self,
        records: dict[str, list[ParsedRecord]],
        scenario: Scenario,
        context: EvaluationContext | None = None,
        progress: ProgressCallback = _noop_callback,
    ) -> PillarScore:
        enabled = {log_spec["format"] for log_spec in scenario.output.logs if "format" in log_spec}
        vis = VisibilityModel(scenario, enabled)

        progress("sub_score_start", {"name": "Value & OS Plausibility", "step": 1, "total": 6})
        s1 = self._score_value_plausibility(records, vis)
        progress("sub_score_done", {"name": "Value & OS Plausibility", "score": s1.score})

        progress("sub_score_start", {"name": "Co-occurrence Rules", "step": 2, "total": 6})
        s2 = self._score_co_occurrence(records)
        progress("sub_score_done", {"name": "Co-occurrence Rules", "score": s2.score})

        progress("sub_score_start", {"name": "Distribution Fit", "step": 3, "total": 6})
        s3 = self._score_distribution_fit(records)
        progress("sub_score_done", {"name": "Distribution Fit", "score": s3.score})

        progress("sub_score_start", {"name": "Cross-Source Field Agreement", "step": 4, "total": 6})
        s4 = self._score_field_agreement(records)
        progress("sub_score_done", {"name": "Cross-Source Field Agreement", "score": s4.score})

        progress("sub_score_start", {"name": "User Behavioral Diversity", "step": 5, "total": 6})
        s5 = self._score_user_diversity(records)
        progress("sub_score_done", {"name": "User Behavioral Diversity", "score": s5.score})

        progress("sub_score_start", {"name": "Anomaly Rate", "step": 6, "total": 6})
        s6 = self._score_anomaly_rate(records, scenario)
        progress("sub_score_done", {"name": "Anomaly Rate", "score": s6.score})

        sub_scores = [s1, s2, s3, s4, s5, s6]
        dim_score = aggregate_sub_scores(sub_scores)

        return PillarScore(
            number=self.number,
            name=self.name,
            weight=self.weight,
            score=dim_score,
            sub_scores=sub_scores,
        )

    # --- Sub-score 1: Value & OS Plausibility ---

    def _score_value_plausibility(
        self,
        records: dict[str, list[ParsedRecord]],
        vis: VisibilityModel,
    ) -> SubScore:
        """Merged source_correctness + activity_plausibility.

        Checks:
        1. OS-bound formats appear on correct OS hosts (container check).
        2. Record content is OS-appropriate (content check).
        """
        total = 0
        plausible = 0
        failures: list[str] = []

        for format_name, record_list in records.items():
            expected_os = _OS_BOUND_FORMATS.get(format_name)

            for record in record_list:
                hostname = _extract_hostname(record)

                # Determine whether record is checkable
                if not hostname and not expected_os:
                    content_check = _check_os_plausibility(record, format_name)
                    if content_check is None:
                        continue
                    # No hostname → can't do container check, only content
                    total += 1
                    if content_check:
                        plausible += 1
                    continue

                if not hostname:
                    continue  # OS-bound but no hostname → unverifiable, skip

                # Container check: OS-bound formats on wrong OS
                if expected_os:
                    host_os = vis.get_os_category(hostname)
                    if vis.resolve_hostname(hostname) is None:
                        total += 1
                        if len(failures) < 10:
                            failures.append(f"[{format_name}] Host '{hostname}' not in scenario")
                        continue
                    if host_os != expected_os and host_os != "unknown":
                        total += 1
                        if len(failures) < 10:
                            failures.append(
                                f"[{format_name}] Host '{hostname}' is {host_os}, "
                                f"expected {expected_os}"
                            )
                        continue

                # Content check: OS-implausible field values
                content_check = _check_os_plausibility(record, format_name)
                if content_check is None:
                    if expected_os:
                        # OS-bound format passed container check → count as pass
                        total += 1
                        plausible += 1
                    continue

                total += 1
                if content_check:
                    plausible += 1
                elif len(failures) < 10:
                    failures.append(
                        f"[{format_name}] Implausible content on {hostname} "
                        f"({vis.get_os_category(hostname)})"
                    )

        score = (100.0 * plausible / total) if total > 0 else 100.0
        return SubScore(
            name="Value & OS Plausibility",
            key="value_plausibility",
            weight=0.25,
            score=score,
            details=f"{plausible}/{total} records pass OS/value plausibility checks",
            sample_failures=failures,
        )

    # --- Sub-score 2: Co-occurrence Rules ---

    def _score_co_occurrence(self, records: dict[str, list[ParsedRecord]]) -> SubScore:
        co_rules = load_rules_file("co_occurrence.yaml")
        total_applicable = 0
        passing = 0
        failures: list[str] = []
        max_sample = 2000

        for format_name, record_list in records.items():
            rules = co_rules.get(format_name, [])
            if not rules:
                continue
            valid = [r for r in record_list if not r.parse_errors]
            if len(valid) > max_sample:
                valid = random.sample(valid, max_sample)

            for record in valid:
                for rule in rules:
                    if _condition_matches(rule.get("condition", {}), record.fields):
                        total_applicable += 1
                        checks = rule.get("checks", [])
                        if all(_check_passes(chk, record.fields) for chk in checks):
                            passing += 1
                        elif len(failures) < 10:
                            failures.append(f"[{format_name}] Rule '{rule['name']}' failed")

        score = (100.0 * passing / total_applicable) if total_applicable > 0 else 100.0
        return SubScore(
            name="Co-occurrence Rules",
            key="co_occurrence",
            weight=0.20,
            score=score,
            details=f"{passing}/{total_applicable} co-occurrence checks pass",
            sample_failures=failures,
        )

    # --- Sub-score 3: Distribution Fit ---

    def _score_distribution_fit(self, records: dict[str, list[ParsedRecord]]) -> SubScore:
        dist_profiles = load_rules_file("distributions.yaml")
        divergence_scores: list[float] = []
        details_parts: list[str] = []

        for format_name, record_list in records.items():
            profiles = dist_profiles.get(format_name, [])
            if not profiles:
                continue
            valid = [r for r in record_list if not r.parse_errors]
            if not valid:
                continue

            for profile in profiles:
                field_name = profile["field"]
                reference = profile["reference"]
                tolerance = profile.get("tolerance", 0.25)

                observed_counts: Counter = Counter()
                total = 0
                for record in valid:
                    val = record.fields.get(field_name)
                    if val is not None:
                        key = _coerce_key(val, reference)
                        observed_counts[key] += 1
                        total += 1

                if total == 0:
                    continue

                observed = {k: v / total for k, v in observed_counts.items()}
                jsd = _jensen_shannon_divergence(reference, observed)

                if jsd <= 0:
                    field_score = 100.0
                elif jsd >= tolerance * 2:
                    field_score = 0.0
                else:
                    field_score = max(0.0, 100.0 * (1.0 - jsd / (tolerance * 2)))

                divergence_scores.append(field_score)
                details_parts.append(f"{format_name}.{field_name}: {field_score:.0f}")

        score = sum(divergence_scores) / len(divergence_scores) if divergence_scores else 100.0
        return SubScore(
            name="Distribution Fit",
            key="distribution_fit",
            weight=0.15,
            score=score,
            details="; ".join(details_parts) if details_parts else "No distribution profiles",
        )

    # --- Sub-score 4: Cross-Source Field Agreement ---

    def _score_field_agreement(self, records: dict[str, list[ParsedRecord]]) -> SubScore:
        pairs_config = load_rules_file("cross_source_pairs.yaml").get("pairs", [])
        if not pairs_config:
            return SubScore(
                name="Cross-Source Field Agreement",
                key="field_agreement",
                weight=0.15,
                score=100.0,
                details="No pair definitions loaded",
            )

        total_matched = 0
        total_agreeing = 0
        failures: list[str] = []

        for pair_def in pairs_config:
            fmt_a = pair_def.get("format_a", "")
            fmt_b = pair_def.get("format_b", "")
            recs_a = records.get(fmt_a, [])
            recs_b = records.get(fmt_b, [])
            if not recs_a or not recs_b:
                continue

            cond_a = pair_def.get("condition_a") or {}
            cond_b = pair_def.get("condition_b") or {}
            pivot = pair_def.get("pivot_key", {})
            agree_on = pair_def.get("agree_on", [])

            filtered_a = [r for r in recs_a if _matches_condition(r, cond_a)]
            filtered_b = [r for r in recs_b if _matches_condition(r, cond_b)]
            if not filtered_a or not filtered_b:
                continue

            b_index = _build_pivot_index(filtered_b, pivot)
            m, ag, fails = _score_pair(pair_def["name"], filtered_a, b_index, pivot, agree_on)
            total_matched += m
            total_agreeing += ag
            if len(failures) < 10:
                failures.extend(fails[: 10 - len(failures)])

        score = (100.0 * total_agreeing / total_matched) if total_matched > 0 else 100.0
        return SubScore(
            name="Cross-Source Field Agreement",
            key="field_agreement",
            weight=0.15,
            score=score,
            details=f"{total_agreeing}/{total_matched} matched pivot pairs agree",
            sample_failures=failures,
        )

    # --- Sub-score 5: User Behavioral Diversity ---

    def _score_user_diversity(self, records: dict[str, list[ParsedRecord]]) -> SubScore:
        import itertools

        user_types: dict[str, Counter] = defaultdict(Counter)
        for _fmt, record_list in records.items():
            for record in record_list:
                user = _extract_username(record)
                if not user:
                    continue
                user_types[user][_extract_event_type(record)] += 1

        users_with_data = {u: c for u, c in user_types.items() if sum(c.values()) >= 5}
        if len(users_with_data) < 2:
            return SubScore(
                name="User Behavioral Diversity",
                key="user_diversity",
                weight=0.15,
                score=100.0,
                details="Fewer than 2 users with sufficient data — skipped",
            )

        user_list = list(users_with_data.keys())
        total_pairs = len(user_list) * (len(user_list) - 1) // 2
        max_pairs = 200

        if total_pairs <= max_pairs:
            pairs = list(itertools.combinations(range(len(user_list)), 2))
        else:
            pairs_set: set = set()
            while len(pairs_set) < max_pairs:
                import random as _rng

                i = _rng.randrange(len(user_list))
                j = _rng.randrange(len(user_list))
                if i != j:
                    pairs_set.add((min(i, j), max(i, j)))
            pairs = list(pairs_set)

        similarities: list[float] = []
        for i, j in pairs:
            sim = _cosine_similarity(users_with_data[user_list[i]], users_with_data[user_list[j]])
            similarities.append(sim)

        avg_sim = sum(similarities) / len(similarities) if similarities else 0.0

        if avg_sim <= 0.5:
            score = 100.0
        elif avg_sim >= 0.9:
            score = 0.0
        else:
            score = 100.0 * (0.9 - avg_sim) / 0.4

        return SubScore(
            name="User Behavioral Diversity",
            key="user_diversity",
            weight=0.15,
            score=score,
            details=f"Avg pairwise similarity: {avg_sim:.2f} across {len(user_list)} users",
        )

    # --- Sub-score 6: Anomaly Rate ---

    def _score_anomaly_rate(
        self,
        records: dict[str, list[ParsedRecord]],
        scenario: Scenario,
    ) -> SubScore:
        anomalous, total = detect_anomalies(records, scenario)
        if total == 0:
            return SubScore(
                name="Anomaly Rate",
                key="anomaly_rate",
                weight=0.10,
                score=100.0,
                details="No records to check",
            )

        rate = anomalous / total
        if 0.01 <= rate <= 0.05:
            score = 100.0
        elif rate == 0:
            score = 0.0
        elif rate < 0.01:
            score = 100.0 * (rate / 0.01)
        elif rate <= 0.10:
            score = max(0.0, 100.0 * (1.0 - (rate - 0.05) / 0.05))
        else:
            score = 0.0

        return SubScore(
            name="Anomaly Rate",
            key="anomaly_rate",
            weight=0.10,
            score=score,
            details=f"{anomalous}/{total} events anomalous ({rate:.1%}), target 1-5%",
        )


# --- Module-level helpers ---


def _check_os_plausibility(record: ParsedRecord, fmt: str) -> bool | None:
    """Return True/False for OS-content plausibility, None if not checkable."""
    f = record.fields
    if fmt == "bash_history":
        cmd = f.get("command", "")
        if "C:\\" in cmd or "cmd.exe" in cmd.lower():
            return False
        return True
    if fmt == "windows_event_security":
        proc = f.get("NewProcessName", "")
        if proc and proc.startswith("/"):
            return False
        return True
    return None


def _check_passes(check: dict[str, Any], fields: dict[str, Any]) -> bool:
    field_name = check.get("field", "")
    value = fields.get(field_name)
    if "present" in check:
        return value is not None
    if "not_equal" in check:
        return value is not None and value != check["not_equal"]
    if "equals" in check:
        return value == check["equals"]
    if "min_length" in check:
        return isinstance(value, str) and len(value) >= check["min_length"]
    if "min_value" in check or "max_value" in check:
        try:
            v = int(value) if not isinstance(value, (int, float)) else value
            if "min_value" in check and v < check["min_value"]:
                return False
            if "max_value" in check and v > check["max_value"]:
                return False
            return True
        except (ValueError, TypeError):
            return False
    if "in" in check:
        return value in check["in"]
    if "matches" in check:
        import re

        return bool(re.search(check["matches"], str(value or "")))
    return True


def _coerce_key(value: Any, reference: dict) -> Any:
    sample_key = next(iter(reference), None)
    if sample_key is None:
        return value
    if isinstance(sample_key, int) and not isinstance(value, int):
        try:
            return int(value)
        except (ValueError, TypeError):
            return value
    if isinstance(sample_key, str) and not isinstance(value, str):
        return str(value)
    return value


def _process_category(process_path: str) -> str:
    p = process_path.lower()
    if any(x in p for x in ["chrome", "firefox", "edge", "iexplore", "safari", "opera"]):
        return "browser"
    if any(
        x in p
        for x in [
            "word",
            "excel",
            "outlook",
            "powerpoint",
            "teams",
            "onedrive",
            "acrobat",
            "onenote",
            "libreoffice",
            "thunderbird",
        ]
    ):
        return "office"
    if any(
        x in p
        for x in [
            "code",
            "vim",
            "nvim",
            "emacs",
            "devenv",
            "idea",
            "pycharm",
            "git",
            "node",
            "python",
            "java",
            "dotnet",
            "npm",
            "cargo",
            "make",
            "cmake",
            "gcc",
            "msbuild",
            "pytest",
            "docker",
            "kubectl",
        ]
    ):
        return "dev_tool"
    if any(
        x in p
        for x in [
            "powershell",
            "cmd.exe",
            "regedit",
            "mmc",
            "taskmgr",
            "eventvwr",
            "compmgmt",
            "services.msc",
            "wmic",
            "netstat",
            "ipconfig",
            "ssh",
            "curl",
            "wget",
        ]
    ):
        return "admin_tool"
    if any(
        x in p
        for x in [
            "svchost",
            "lsass",
            "csrss",
            "winlogon",
            "services.exe",
            "smss",
            "wininit",
            "spoolsv",
            "searchindexer",
            "taskhostw",
            "conhost",
            "explorer.exe",
            "systemd",
            "cron",
            "sshd",
            "rsyslog",
        ]
    ):
        return "system"
    return "other"


def _extract_event_type(record: ParsedRecord) -> str:
    fmt = record.source_format
    f = record.fields
    if fmt == "windows_event_security":
        eid = f.get("EventID")
        if eid == 4688:
            return f"win_4688_{_process_category(f.get('NewProcessName', ''))}"
        if eid == 4624:
            return f"win_4624_type{f.get('LogonType', 0)}"
        if eid == 4689:
            return "win_4689_terminate"
        return f"win_{eid}" if eid else "win_unknown"
    if fmt == "windows_event_sysmon":
        eid = f.get("EventID")
        if eid == 1:
            return f"sysmon_1_{_process_category(f.get('Image', ''))}"
        if eid == 5:
            return "sysmon_5_terminate"
        if eid == 8:
            return "sysmon_8_remote_thread"
        if eid == 10:
            return "sysmon_10_process_access"
        return f"sysmon_{eid}" if eid else "sysmon_unknown"
    if fmt == "ecar":
        obj = f.get("object", "?")
        act = f.get("action", "?")
        if obj == "PROCESS" and act == "CREATE":
            return f"ecar_PROCESS_CREATE_{_process_category(f.get('image_path', ''))}"
        if obj == "PROCESS" and act == "TERMINATE":
            return "ecar_PROCESS_TERMINATE"
        if obj == "THREAD" and act == "REMOTE_CREATE":
            return "ecar_THREAD_REMOTE_CREATE"
        if obj == "PROCESS" and act == "OPEN":
            return "ecar_PROCESS_OPEN"
        return f"ecar_{obj}_{act}"
    if fmt == "bash_history":
        cmd = f.get("command", "")
        return f"bash_{cmd.split()[0]}" if cmd else "bash_empty"
    if fmt == "syslog":
        return f"syslog_{f.get('app_name', 'unknown')}"
    if fmt == "web_access":
        method = f.get("method", "GET")
        code = f.get("status_code", 0)
        return f"web_{method}_{code // 100}xx"
    if fmt == "zeek_conn":
        svc = f.get("service", f.get("proto", "unknown"))
        return f"zeek_{svc}"
    return fmt


def _cosine_similarity(a: Counter, b: Counter) -> float:
    all_keys = set(a.keys()) | set(b.keys())
    dot = sum(a.get(k, 0) * b.get(k, 0) for k in all_keys)
    mag_a = math.sqrt(sum(v**2 for v in a.values()))
    mag_b = math.sqrt(sum(v**2 for v in b.values()))
    if mag_a == 0 or mag_b == 0:
        return 0.0
    return dot / (mag_a * mag_b)


# Field-agreement helpers (extracted from cross_source.py)


def _matches_condition(record: ParsedRecord, condition: dict) -> bool:
    for field, expected in condition.items():
        if field == "msg_id_in":
            if record.fields.get("msg_id") not in expected:
                return False
        elif field.endswith("_not"):
            if record.fields.get(field[:-4]) == expected:
                return False
        else:
            if record.fields.get(field) != expected:
                return False
    return True


def _normalize_ts(ts: datetime) -> datetime:
    if ts.tzinfo is None:
        return ts.replace(tzinfo=UTC)
    return ts


def _coerce_value(val: Any, coerce: str | None) -> Any:
    if coerce == "hex_to_int":
        if isinstance(val, str) and val.startswith("0x"):
            try:
                return int(val, 16)
            except ValueError:
                return val
        try:
            return int(val)
        except (TypeError, ValueError):
            return val
    return val


def _get_hostname_for_record(record: ParsedRecord) -> str | None:
    hn = _extract_hostname(record)
    if hn:
        return hn
    return record.fields.get("hostname")


def _get_pivot_key_a(record: ParsedRecord, pivot: dict) -> Any:
    coerce = pivot.get("coerce")
    require_hn = pivot.get("require_hostname_match", False)

    if "a_fields" in pivot:
        parts = []
        for f in pivot["a_fields"]:
            if f == "timestamp_bucket_10s":
                ts = record.timestamp
                if ts is None:
                    return None
                parts.append(int(ts.timestamp()) // 10)
            else:
                v = record.fields.get(f)
                if v is None:
                    return None
                parts.append(v)
        return tuple(parts)
    else:
        a_field = pivot.get("a_field")
        if not a_field:
            return None
        if pivot.get("list_contains"):
            v = record.fields.get(a_field)
            if not isinstance(v, list) or not v:
                return None
            return ("__list__", tuple(_coerce_value(item, coerce) for item in v))
        val = record.fields.get(a_field)
        if val is None:
            return None
        raw_key = _coerce_value(val, coerce)
        if require_hn:
            hn = _get_hostname_for_record(record)
            return (hn.lower() if hn else None, raw_key)
        return raw_key


def _build_pivot_index(
    records: list[ParsedRecord],
    pivot: dict,
    max_bucket_records: int = _MAX_PIVOT_BUCKET_RECORDS,
) -> dict:
    index: dict = defaultdict(list)
    coerce = pivot.get("coerce")
    require_hn = pivot.get("require_hostname_match", False)

    for rec in records:
        key: object | None = None
        if pivot.get("b_fields"):
            parts = []
            for f in pivot["b_fields"]:
                if f == "ts_bucket_10s":
                    ts = rec.timestamp
                    if ts is None:
                        break
                    parts.append(int(ts.timestamp()) // 10)
                else:
                    v = rec.fields.get(f)
                    if v is None:
                        break
                    parts.append(v)
            else:
                key = tuple(parts)
        else:
            b_field = pivot.get("b_field")
            if not b_field:
                continue
            val = rec.fields.get(b_field)
            if val is None:
                continue
            raw_key = _coerce_value(val, coerce)
            if require_hn:
                hn = _get_hostname_for_record(rec)
                key = (hn.lower() if hn else None, raw_key)
            else:
                key = raw_key

        if key is None:
            continue
        bucket = index[key]
        if len(bucket) < max_bucket_records:
            bucket.append(rec)
    return dict(index)


def _normalize_value(val: Any, normalize: str | None) -> Any:
    if val is None:
        return None
    if normalize == "lower":
        return str(val).lower()
    if normalize == "path_basename_ci":
        path_str = str(val)
        basename = path_str.replace("\\", "/").split("/")[-1]
        return basename.lower()
    if normalize == "cn_from_dn":
        s = str(val)
        for part in s.split(","):
            part = part.strip()
            if part.upper().startswith("CN="):
                return part[3:].lower()
        return s.lower()
    return val


def _extract_agree_field(
    record: ParsedRecord, field: str | None, spec: dict, is_b: bool = False
) -> object:
    if not field:
        return None
    val = record.fields.get(field)
    if val is None and is_b and spec.get("b_nested"):
        nested = record.fields.get(spec["b_nested"])
        if isinstance(nested, dict):
            val = nested.get(field)
    return val


def _values_agree(a_val: Any, b_val: Any, spec: dict) -> bool:
    normalize = spec.get("normalize")
    tolerance = spec.get("tolerance")
    b_is_list = spec.get("b_is_list", False)

    if b_is_list:
        if not isinstance(b_val, list):
            return False
        a_norm = _normalize_value(a_val, normalize)
        return any(_normalize_value(v, normalize) == a_norm for v in b_val)

    if tolerance is not None:
        try:
            a_num = float(a_val)
            b_num = float(b_val)
            if b_num == 0:
                return a_num == 0
            return abs(a_num - b_num) / abs(b_num) <= tolerance
        except (TypeError, ValueError):
            pass

    return _normalize_value(a_val, normalize) == _normalize_value(b_val, normalize)


def _score_pair(
    pair_name: str,
    filtered_a: list[ParsedRecord],
    b_index: dict,
    pivot: dict,
    agree_on: list,
    max_matches: int = _MAX_FIELD_AGREEMENT_MATCHES,
) -> tuple[int, int, list[str]]:
    total_matched = 0
    agreeing = 0
    failures: list[str] = []
    time_window = pivot.get("time_window_seconds")

    for rec_a in filtered_a:
        if total_matched >= max_matches:
            break

        key_a = _get_pivot_key_a(rec_a, pivot)
        if key_a is None:
            continue

        if isinstance(key_a, tuple) and key_a and key_a[0] == "__list__":
            matching_b: list = []
            for sub_key in key_a[1]:
                matching_b.extend(b_index.get(sub_key, []))
        else:
            matching_b = b_index.get(key_a, [])

        if not matching_b:
            continue

        if time_window is not None and rec_a.timestamp is not None:
            ts_a = _normalize_ts(rec_a.timestamp)
            matching_b = [
                r
                for r in matching_b
                if r.timestamp is not None
                and abs((_normalize_ts(r.timestamp) - ts_a).total_seconds()) <= time_window
            ]
            if not matching_b:
                continue

        for rec_b in matching_b:
            if total_matched >= max_matches:
                break
            total_matched += 1
            all_agree = True
            for agree_spec in agree_on:
                a_val = _extract_agree_field(rec_a, agree_spec.get("a_field"), agree_spec)
                b_val = _extract_agree_field(
                    rec_b, agree_spec.get("b_field"), agree_spec, is_b=True
                )
                if a_val is None or b_val is None:
                    continue
                if not _values_agree(a_val, b_val, agree_spec):
                    all_agree = False
                    if len(failures) < 5:
                        failures.append(
                            f"[{pair_name}] {agree_spec['a_field']}={a_val!r} vs "
                            f"{agree_spec['b_field']}={b_val!r}"
                        )
                    break
            if all_agree:
                agreeing += 1

    return total_matched, agreeing, failures
