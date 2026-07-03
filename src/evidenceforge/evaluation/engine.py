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

"""Evaluation engine orchestrator.

Runs all available pillar scorers, computes overall score,
checks acceptance criteria, and assembles the QualityReport.
"""

import logging
from datetime import UTC, datetime
from pathlib import Path

from evidenceforge.evaluation.context import EvaluationContext
from evidenceforge.evaluation.dimensions import DimensionScorer, ProgressCallback, _noop_callback
from evidenceforge.evaluation.models import (
    AcceptanceCriterion,
    PillarScore,
    QualityReport,
)
from evidenceforge.evaluation.parsers import ParsedRecord, discover_log_files, get_parser
from evidenceforge.evaluation.pillars import (
    CausalityScorer,
    ParseabilityScorer,
    PlausibilityScorer,
    TimingScorer,
)
from evidenceforge.evaluation.thresholds import EvalThresholds, load_thresholds
from evidenceforge.events.observation_manifest import load_observation_manifest
from evidenceforge.models.scenario import Scenario
from evidenceforge.output_targets import read_output_target_marker

logger = logging.getLogger(__name__)

# Registered pillar scorers.
DIMENSION_SCORERS: list[DimensionScorer] = [
    ParseabilityScorer(),
    PlausibilityScorer(),
    CausalityScorer(),
    TimingScorer(),
]


def _build_pillar_maps(
    pillars: list[PillarScore],
) -> tuple[dict[str, PillarScore], dict[int, PillarScore]]:
    by_name: dict[str, PillarScore] = {}
    for p in pillars:
        clean = p.name.lower().replace(" ", "_").replace("-", "_")
        by_name[clean] = p
    by_number: dict[int, PillarScore] = {p.number: p for p in pillars}
    return by_name, by_number


def _find_sub_score_for_key(
    key: str,
    by_name: dict[str, PillarScore],
    by_number: dict[int, PillarScore],
):
    """Find a sub-score by key across all pillars."""
    for p in by_name.values():
        sub = next((s for s in p.sub_scores if s.key == key), None)
        if sub is not None:
            return sub
    return None


def _build_acceptance_criteria(
    thresholds: EvalThresholds,
    pillars: list[PillarScore],
) -> list[AcceptanceCriterion]:
    """Build acceptance criteria from threshold config and actual pillar scores."""
    results: list[AcceptanceCriterion] = []
    by_name, by_number = _build_pillar_maps(pillars)

    for pillar_name, pillar_thresh in thresholds.pillars.items():
        for key, ss_thresh in pillar_thresh.sub_scores.items():
            if not ss_thresh.hard_gate:
                continue

            crit = AcceptanceCriterion(
                name=f"{pillar_name}.{key}",
                pillar=pillar_name,
                sub_score_key=key,
                threshold=ss_thresh.minimum,
                aspirational=ss_thresh.aspirational,
                level="hard",
            )

            sub = _find_sub_score_for_key(key, by_name, by_number)
            if sub is not None and sub.score is not None:
                crit.actual = sub.score
                crit.passed = sub.score >= ss_thresh.minimum
                if ss_thresh.aspirational is not None:
                    crit.meets_aspirational = sub.score >= ss_thresh.aspirational

            results.append(crit)

    return results


def _count_aspirational(
    thresholds: EvalThresholds,
    pillars: list[PillarScore],
) -> tuple[int, int]:
    """Return (met, total) aspirational targets across all sub-scores."""
    met = 0
    total = 0
    by_name, by_number = _build_pillar_maps(pillars)

    for pillar_thresh in thresholds.pillars.values():
        for key, ss_thresh in pillar_thresh.sub_scores.items():
            sub = _find_sub_score_for_key(key, by_name, by_number)
            if sub is None or sub.score is None:
                continue
            total += 1
            if sub.score >= ss_thresh.aspirational:
                met += 1

    return met, total


class EvaluationEngine:
    """Orchestrates dataset quality evaluation."""

    def __init__(
        self,
        output_dir: Path,
        scenario: Scenario,
        verbose: bool = False,
        progress_callback: ProgressCallback = _noop_callback,
    ):
        self.output_dir = output_dir
        self.scenario = scenario
        self.verbose = verbose
        self._progress = progress_callback
        self._thresholds = load_thresholds()
        self.output_target = read_output_target_marker(output_dir)

    def _load_spillage_ground_truth(self) -> dict[str, dict]:
        """Load emitted spillage labels from GROUND_TRUTH.json, keyed by storyline id.

        Returns ``{storyline_id: {"values": [rendered, ...], "time": datetime}}``.
        Lets the causality pillar verify a spilled credential landed in the logs
        without re-running synthesis, and anchor matching/timing to the *actual*
        emitted time (bash dwell scheduling can shift it past the storyline time).
        """
        from evidenceforge.events.ground_truth import load_ground_truth_document

        result: dict[str, dict] = {}
        document = load_ground_truth_document(self.output_dir, self.scenario)
        if document is None:
            return result
        for rec in document.events:
            if rec.kind != "spillage" or not rec.emitted:
                continue
            sid = rec.storyline_id
            value = rec.attributes.rendered_value or rec.attributes.value
            if not (sid and value):
                continue
            entry = result.setdefault(sid, {"values": [], "records": [], "time": None})
            entry["values"].append(value)
            entry["records"].append(
                {
                    "value": value,
                    "expected_sources": list(rec.attributes.expected_sources or ()),
                }
            )
            if rec.attributes.target_system and not entry.get("target_system"):
                entry["target_system"] = rec.attributes.target_system
            if entry["time"] is None:
                entry["time"] = rec.time.astimezone(UTC)
        return result

    def _load_adversarial_payload_ground_truth(self) -> dict[str, dict]:
        """Load emitted adversarial-payload labels from GROUND_TRUTH.json, keyed by storyline id.

        Returns ``{storyline_id: {"records": [{"value": rendered, "expected_sources":
        [...]}], "time": datetime, "target_system": fqdn}}``. The causality pillar
        verifies each labeled payload landed in an expected source's text (matched
        against the source's raw lines so a CRLF split still counts), without
        re-running synthesis.
        """
        from evidenceforge.events.ground_truth import load_ground_truth_document

        result: dict[str, dict] = {}
        document = load_ground_truth_document(self.output_dir, self.scenario)
        if document is None:
            return result
        for rec in document.events:
            if rec.kind != "adversarial_payload" or not rec.emitted:
                continue
            sid = rec.storyline_id
            value = rec.attributes.rendered_value or rec.attributes.value
            if not (sid and value):
                continue
            entry = result.setdefault(sid, {"records": [], "time": None})
            entry["records"].append(
                {
                    "value": value,
                    "expected_sources": list(rec.attributes.expected_sources or ()),
                }
            )
            if rec.attributes.target_system and not entry.get("target_system"):
                entry["target_system"] = rec.attributes.target_system
            if entry["time"] is None:
                entry["time"] = rec.time.astimezone(UTC)
        return result

    def _load_email_ground_truth(self) -> dict[str, dict]:
        """Load emitted email identifiers from GROUND_TRUTH.json, keyed by storyline id."""
        from evidenceforge.events.ground_truth import load_ground_truth_document

        result: dict[str, dict] = {}
        document = load_ground_truth_document(self.output_dir, self.scenario)
        if document is None:
            return result
        for rec in document.events:
            if rec.kind != "email_message" or not rec.emitted:
                continue
            sid = rec.storyline_id
            message_id = rec.attributes.message_id
            if not (sid and message_id):
                continue
            result[sid] = {
                "message_id": message_id,
                "artifact_path": rec.attributes.artifact_path,
                "smtp_uids": list(rec.attributes.smtp_uids or ()),
                "subject": rec.attributes.subject,
                "sender": rec.attributes.sender,
                "recipients": list(rec.attributes.recipients or ()),
            }
        return result

    def run(self) -> QualityReport:
        """Execute the full evaluation pipeline."""
        # 1. Discover and parse all log files
        self._progress("phase_start", {"phase": "parsing"})
        records, source_counts = self._parse_all_logs()
        total_records = sum(source_counts.values())
        self._progress(
            "phase_done",
            {
                "phase": "parsing",
                "total_records": total_records,
                "sources": len(source_counts),
            },
        )

        logger.info(f"Parsed {total_records} records across {len(source_counts)} sources")
        observation_manifest = load_observation_manifest(self.output_dir, self.scenario)
        context = EvaluationContext(
            observation_manifest=observation_manifest,
            spillage_ground_truth=self._load_spillage_ground_truth(),
            adversarial_payload_ground_truth=self._load_adversarial_payload_ground_truth(),
            email_ground_truth=self._load_email_ground_truth(),
        )

        # 2. Run each available pillar scorer
        total_pillars = len(DIMENSION_SCORERS)
        self._progress("phase_start", {"phase": "scoring", "total_dimensions": total_pillars})
        pillars: list[PillarScore] = []
        for i, scorer in enumerate(DIMENSION_SCORERS, 1):
            self._progress(
                "dimension_start",
                {
                    "number": scorer.number,
                    "name": scorer.name,
                    "step": i,
                    "total": total_pillars,
                },
            )
            logger.info(f"Scoring Pillar {scorer.number}: {scorer.name}")
            pillar_score: PillarScore
            try:
                pillar_score = scorer.score(
                    records,
                    self.scenario,
                    context=context,
                    progress=self._progress,
                )
                pillars.append(pillar_score)
            except Exception:
                logger.exception(f"Pillar {scorer.number} scoring failed")
                pillar_score = PillarScore(
                    number=scorer.number,
                    name=scorer.name,
                    weight=scorer.weight,
                    score=None,
                )
                pillars.append(pillar_score)
            self._progress(
                "dimension_done",
                {
                    "number": scorer.number,
                    "name": scorer.name,
                    "score": pillar_score.score,
                },
            )

        # 3. Compute overall score (weighted average of available pillars)
        overall = self._compute_overall(pillars)

        # 4. Check acceptance criteria from thresholds.yaml
        acceptance_criteria = _build_acceptance_criteria(self._thresholds, pillars)
        all_hard_pass = all(
            c.passed for c in acceptance_criteria if c.level == "hard" and c.passed is not None
        )

        # 5. Count aspirational targets met
        asp_met, asp_total = _count_aspirational(self._thresholds, pillars)

        # 6. Build flags
        flags = self._build_flags(pillars, acceptance_criteria)

        # 7. Merge pillar-level supplementary data into report supplementary
        supplementary: dict = {}
        supplementary["output_target"] = self.output_target.value
        for pillar in pillars:
            supplementary.update(pillar.supplementary)
        if observation_manifest is not None:
            supplementary["observation_profile"] = {
                "profile": observation_manifest.observation_profile,
                "manifest_present": True,
                "source_summary": observation_manifest.source_summary,
            }
        elif self.scenario.observation_profile != "complete":
            supplementary["observation_profile"] = {
                "profile": self.scenario.observation_profile,
                "manifest_present": False,
                "source_summary": {},
            }

        return QualityReport(
            scenario_name=self.scenario.name,
            evaluated_at=datetime.now(UTC),
            total_records=total_records,
            source_counts=source_counts,
            overall_score=overall,
            pillars=pillars,
            acceptance_passed=all_hard_pass
            if any(c.passed is not None for c in acceptance_criteria if c.level == "hard")
            else None,
            acceptance_criteria=acceptance_criteria,
            aspirational_met=asp_met if asp_total > 0 else None,
            aspirational_total=asp_total if asp_total > 0 else None,
            flags=flags,
            supplementary=supplementary,
        )

    def _parse_all_logs(self) -> tuple[dict[str, list[ParsedRecord]], dict[str, int]]:
        """Discover and parse all log files in the output directory."""
        file_map = discover_log_files(self.output_dir, output_target=self.output_target)
        records: dict[str, list[ParsedRecord]] = {}
        source_counts: dict[str, int] = {}

        total_formats = len(file_map)
        for i, (format_name, paths) in enumerate(file_map.items(), 1):
            self._progress(
                "parsing_format",
                {
                    "format": format_name,
                    "step": i,
                    "total": total_formats,
                },
            )
            parser = get_parser(format_name)
            parser.scenario = self.scenario
            parser.output_target = self.output_target
            format_records: list[ParsedRecord] = []
            for path in paths:
                logger.info(f"Parsing {format_name}: {path.name}")
                format_records.extend(parser.parse_file(path))
            records[format_name] = format_records
            source_counts[format_name] = len(format_records)

        return records, source_counts

    @staticmethod
    def _compute_overall(pillars: list[PillarScore]) -> float | None:
        """Compute weighted overall score from available pillars."""
        scored = [(p.weight, p.score) for p in pillars if p.score is not None]
        if not scored:
            return None

        total_weight = sum(w for w, _ in scored)
        if total_weight == 0:
            return None

        return sum(w * s for w, s in scored) / total_weight

    @staticmethod
    def _build_flags(
        pillars: list[PillarScore],
        criteria: list[AcceptanceCriterion],
    ) -> list[str]:
        """Build human-readable flag messages."""
        flags: list[str] = []

        # Flag any sub-score below 50
        for pillar in pillars:
            for sub in pillar.sub_scores:
                if sub.score is not None and sub.score < 50:
                    flags.append(f"{sub.name}: {sub.score:.0f}/100 ({sub.details})")

        # Flag failed acceptance criteria
        for c in criteria:
            if c.passed is False:
                flags.append(
                    f"[{c.level.upper()}] {c.name}: {c.actual:.1f} < {c.threshold:.1f} threshold"
                )

        return flags
