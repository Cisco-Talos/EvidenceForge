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

"""Dimension 3: Background Noise Realism scoring.

Sub-scores (0.25 each):
  Volume Adequacy — noise-to-signal ratio matches declared intensity.
  User Behavioral Diversity — users behave differently, not cookie-cutter.
  Activity Plausibility — activities match persona/system/OS assignments.
  Organic Anomaly Rate — 1-5% of background flagged as anomalous.
"""

import logging
import math
from collections import Counter, defaultdict

from evidenceforge.evaluation.anomaly import detect_anomalies
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

# Target noise-to-signal ratios by baseline intensity.
# Signal count uses storyline entries (not individual records), so each
# entry typically generates 5-10 records across formats. Targets reflect
# the ratio of total records to storyline entry count.
_VOLUME_TARGETS = {"low": 200, "medium": 2000, "high": 5000}


def _process_category(process_path: str) -> str:
    """Categorize a process path for user diversity feature extraction."""
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
    """Extract an event-type key from a record for diversity analysis."""
    fmt = record.source_format
    f = record.fields

    if fmt == "windows_event_security":
        eid = f.get("EventID")
        if eid == 4688:
            proc = f.get("NewProcessName", "")
            return f"win_4688_{_process_category(proc)}"
        if eid == 4624:
            logon_type = f.get("LogonType", 0)
            return f"win_4624_type{logon_type}"
        if eid == 4689:
            return "win_4689_terminate"
        return f"win_{eid}" if eid else "win_unknown"
    if fmt == "windows_event_sysmon":
        eid = f.get("EventID")
        if eid == 1:
            proc = f.get("Image", "")
            return f"sysmon_1_{_process_category(proc)}"
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
            proc = f.get("image_path", "")
            return f"ecar_PROCESS_CREATE_{_process_category(proc)}"
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


def _extract_hostname(record: ParsedRecord) -> str | None:
    """Extract hostname from a record, normalizing FQDN to bare hostname."""
    field_name = _HOST_FIELD_MAP.get(record.source_format)
    if field_name:
        val = record.fields.get(field_name)
        if val and isinstance(val, str):
            return _normalize_hostname(val)
    return None


def _normalize_hostname(hostname: str) -> str:
    """Normalize hostname by stripping domain suffix."""
    if hostname[0].isdigit():
        return hostname
    parts = hostname.split(".")
    if len(parts) > 1:
        return parts[0]
    return hostname


class NoiseRealismScorer(DimensionScorer):
    number = 3
    name = "Background Noise Realism"
    weight = 0.25

    def score(
        self,
        records: dict[str, list[ParsedRecord]],
        scenario: Scenario,
        progress: ProgressCallback = _noop_callback,
    ) -> DimensionScore:
        progress("sub_score_start", {"name": "Volume Adequacy", "step": 1, "total": 4})
        s1 = self._score_volume_adequacy(records, scenario)
        progress("sub_score_done", {"name": "Volume Adequacy", "score": s1.score})

        progress("sub_score_start", {"name": "User Behavioral Diversity", "step": 2, "total": 4})
        s2 = self._score_user_diversity(records)
        progress("sub_score_done", {"name": "User Behavioral Diversity", "score": s2.score})

        progress("sub_score_start", {"name": "Activity Plausibility", "step": 3, "total": 4})
        s3 = self._score_activity_plausibility(records, scenario)
        progress("sub_score_done", {"name": "Activity Plausibility", "score": s3.score})

        progress("sub_score_start", {"name": "Organic Anomaly Rate", "step": 4, "total": 4})
        s4 = self._score_anomaly_rate(records, scenario)
        progress("sub_score_done", {"name": "Organic Anomaly Rate", "score": s4.score})

        sub_scores = [s1, s2, s3, s4]
        dim_score = sum(s.score * s.weight for s in sub_scores if s.score is not None)

        return DimensionScore(
            number=self.number,
            name=self.name,
            weight=self.weight,
            score=dim_score,
            sub_scores=sub_scores,
        )

    # --- Sub-score 1: Volume Adequacy ---

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
                weight=0.25,
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
            weight=0.25,
            score=score,
            details=f"Noise:signal ratio {ratio:.0f}:1 (target {target}:1 for {scenario.baseline_activity.intensity})",
        )

    # --- Sub-score 2: User Behavioral Diversity ---

    def _score_user_diversity(self, records: dict[str, list[ParsedRecord]]) -> SubScore:
        # Build per-user event-type distributions
        user_types: dict[str, Counter] = defaultdict(Counter)

        for _format_name, record_list in records.items():
            for record in record_list:
                user = _extract_username(record)
                if not user:
                    continue
                event_type = _extract_event_type(record)
                user_types[user][event_type] += 1

        # Need at least 2 users to compare diversity
        users_with_data = {u: c for u, c in user_types.items() if sum(c.values()) >= 5}
        if len(users_with_data) < 2:
            return SubScore(
                name="User Behavioral Diversity",
                key="user_diversity",
                weight=0.25,
                score=100.0,
                details="Fewer than 2 users with sufficient data — skipped",
            )

        # Compute pairwise cosine similarity (sample pairs for large user counts)
        import itertools
        import random as _rng

        user_list = list(users_with_data.keys())
        total_pairs = len(user_list) * (len(user_list) - 1) // 2
        max_pairs = 200

        if total_pairs <= max_pairs:
            # Small enough to compute all pairs
            pairs = list(itertools.combinations(range(len(user_list)), 2))
        else:
            # Sample random pairs
            pairs = set()
            while len(pairs) < max_pairs:
                i = _rng.randrange(len(user_list))
                j = _rng.randrange(len(user_list))
                if i != j:
                    pairs.add((min(i, j), max(i, j)))
            pairs = list(pairs)

        similarities: list[float] = []
        for i, j in pairs:
            sim = self._cosine_similarity(
                users_with_data[user_list[i]],
                users_with_data[user_list[j]],
            )
            similarities.append(sim)

        avg_sim = sum(similarities) / len(similarities) if similarities else 0.0

        # Score: low similarity = diverse = good
        if avg_sim <= 0.5:
            score = 100.0
        elif avg_sim >= 0.9:
            score = 0.0
        else:
            score = 100.0 * (0.9 - avg_sim) / 0.4

        return SubScore(
            name="User Behavioral Diversity",
            key="user_diversity",
            weight=0.25,
            score=score,
            details=f"Avg pairwise similarity: {avg_sim:.2f} across {len(user_list)} users",
        )

    @staticmethod
    def _cosine_similarity(a: Counter, b: Counter) -> float:
        """Cosine similarity between two Counter distributions."""
        all_keys = set(a.keys()) | set(b.keys())
        dot = sum(a.get(k, 0) * b.get(k, 0) for k in all_keys)
        mag_a = math.sqrt(sum(v**2 for v in a.values()))
        mag_b = math.sqrt(sum(v**2 for v in b.values()))
        if mag_a == 0 or mag_b == 0:
            return 0.0
        return dot / (mag_a * mag_b)

    # --- Sub-score 3: Activity Plausibility ---

    def _score_activity_plausibility(
        self,
        records: dict[str, list[ParsedRecord]],
        scenario: Scenario,
    ) -> SubScore:
        enabled = {log_spec["format"] for log_spec in scenario.output.logs if "format" in log_spec}
        vis = VisibilityModel(scenario, enabled)

        total = 0
        plausible = 0
        failures: list[str] = []

        for format_name, record_list in records.items():
            for record in record_list:
                hostname = _extract_hostname(record)
                if not hostname:
                    continue

                # Check OS-appropriate content
                check = self._check_os_plausibility(record, format_name, hostname, vis)
                if check is None:
                    continue  # Not checkable

                total += 1
                if check:
                    plausible += 1
                elif len(failures) < 10:
                    failures.append(
                        f"[{format_name}] Implausible content on {hostname} ({vis.get_os_category(hostname)})"
                    )

        score = (100.0 * plausible / total) if total > 0 else 100.0
        return SubScore(
            name="Activity Plausibility",
            key="activity_plausibility",
            weight=0.25,
            score=score,
            details=f"{plausible}/{total} records have OS-plausible content",
            sample_failures=failures,
        )

    @staticmethod
    def _check_os_plausibility(
        record: ParsedRecord,
        fmt: str,
        hostname: str,
        vis: VisibilityModel,
    ) -> bool | None:
        """Check if record content is plausible for the host's OS. Returns None if not checkable."""
        vis.get_os_category(hostname)
        f = record.fields

        if fmt == "bash_history":
            # Bash commands shouldn't have Windows paths
            cmd = f.get("command", "")
            if "C:\\" in cmd or "cmd.exe" in cmd.lower():
                return False
            return True

        if fmt == "windows_event_security":
            # Windows process paths should look like Windows
            proc = f.get("NewProcessName", "")
            if proc and proc.startswith("/"):
                return False
            return True

        return None  # Other formats: not checkable for OS plausibility

    # --- Sub-score 4: Organic Anomaly Rate ---

    def _score_anomaly_rate(
        self,
        records: dict[str, list[ParsedRecord]],
        scenario: Scenario,
    ) -> SubScore:
        anomalous, total = detect_anomalies(records, scenario)

        if total == 0:
            return SubScore(
                name="Organic Anomaly Rate",
                key="anomaly_rate",
                weight=0.25,
                score=100.0,
                details="No records to check",
            )

        rate = anomalous / total

        # Score: 1-5% → 100, 0% → 0, >10% → 0
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
            name="Organic Anomaly Rate",
            key="anomaly_rate",
            weight=0.25,
            score=score,
            details=f"{anomalous}/{total} events flagged anomalous ({rate:.1%}), target 1-5%",
        )
