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
    EvaluationCategoryScore,
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
from evidenceforge.events.ground_truth import load_ground_truth_document
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
            if sub is None:
                crit.applicable = True
                crit.passed = False
            elif sub.skipped:
                crit.applicable = False
            elif sub.score is None:
                crit.applicable = True
                crit.passed = False
            else:
                crit.applicable = True
                crit.actual = sub.score
                crit.passed = sub.score >= ss_thresh.minimum
                if ss_thresh.aspirational is not None:
                    crit.meets_aspirational = sub.score >= ss_thresh.aspirational

            results.append(crit)

    return results


_CATEGORY_DEFINITIONS: tuple[tuple[str, str, tuple[str, ...]], ...] = (
    (
        "source_schema",
        "Parseability & Source Schema",
        ("spec_conformance", "format_constraints"),
    ),
    (
        "canonical_invariants",
        "Canonical Cross-Source Invariants",
        (
            "value_plausibility",
            "co_occurrence",
            "field_agreement",
            "ids_integrity",
            "causal_ordering",
            "rate_plausibility",
        ),
    ),
    (
        "scenario_completeness",
        "Declared Scenario Completeness",
        (
            "intent_reconciliation",
            "event_presence",
            "indicator_accuracy",
            "pivot_linkability",
            "temporal_integrity",
            "storyline_trace_coverage",
        ),
    ),
    (
        "distribution_realism",
        "Distribution & Realism Diagnostics",
        (
            "distribution_fit",
            "user_diversity",
            "anomaly_rate",
            "attack_chain_timing",
            "burstiness",
            "system_regularity",
            "diurnal_pattern",
            "volume_adequacy",
        ),
    ),
)


def _build_category_scores(pillars: list[PillarScore]) -> list[EvaluationCategoryScore]:
    """Build concern-oriented scores while retaining the existing pillar API."""

    by_key = {sub.key: sub for pillar in pillars for sub in pillar.sub_scores}
    categories: list[EvaluationCategoryScore] = []
    for key, name, sub_score_keys in _CATEGORY_DEFINITIONS:
        active = [
            by_key[sub_key]
            for sub_key in sub_score_keys
            if sub_key in by_key
            and by_key[sub_key].score is not None
            and not by_key[sub_key].skipped
        ]
        score = sum(float(sub.score) for sub in active) / len(active) if active else None
        categories.append(
            EvaluationCategoryScore(
                key=key,
                name=name,
                score=score,
                sub_score_keys=[sub.key for sub in active],
                details=(
                    f"{len(active)}/{len(sub_score_keys)} configured measures scored"
                    if active
                    else "No applicable automated measures"
                ),
            )
        )
    categories.append(
        EvaluationCategoryScore(
            key="expert_comparison",
            name="Optional Expert Comparison",
            score=None,
            details="No expert assessment was supplied to this deterministic evaluation run",
        )
    )
    return categories


def _acceptance_verdict(criteria: list[AcceptanceCriterion]) -> bool | None:
    """Return a non-vacuous verdict across all applicable hard requirements."""

    applicable_hard = [
        criterion
        for criterion in criteria
        if criterion.level == "hard" and criterion.applicable is not False
    ]
    if any(criterion.passed is False for criterion in applicable_hard):
        return False
    if applicable_hard and all(criterion.passed is True for criterion in applicable_hard):
        return True
    return None


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
            if rec.kind not in {"email_message", "email_read"} or not rec.emitted:
                continue
            sid = rec.storyline_id
            if not sid:
                continue
            if rec.kind == "email_message":
                message_id = rec.attributes.message_id
                if not message_id:
                    continue
                result[sid] = {
                    "kind": rec.kind,
                    "time": rec.time,
                    "message_id": message_id,
                    "artifact_path": rec.attributes.artifact_path,
                    "smtp_uids": list(rec.attributes.smtp_uids or ()),
                    "subject": rec.attributes.subject,
                    "sender": rec.attributes.sender,
                    "recipients": list(rec.attributes.recipients or ()),
                    "outcome": rec.attributes.outcome,
                }
            else:
                result[sid] = {
                    "kind": rec.kind,
                    "time": rec.time,
                    "uid": rec.attributes.uid,
                    "server": rec.attributes.server,
                    "protocol": rec.attributes.protocol,
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
        ground_truth = load_ground_truth_document(self.output_dir, self.scenario)
        context = EvaluationContext(
            observation_manifest=observation_manifest,
            ground_truth=ground_truth,
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
        all_hard_pass = _acceptance_verdict(acceptance_criteria)

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
            generated_at=ground_truth.generated_at if ground_truth is not None else None,
            evaluated_at=datetime.now(UTC),
            total_records=total_records,
            source_counts=source_counts,
            overall_score=overall,
            pillars=pillars,
            categories=_build_category_scores(pillars),
            acceptance_passed=all_hard_pass,
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
        for i, (format_name, paths) in enumerate(sorted(file_map.items()), 1):
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
            for path in sorted(paths):
                logger.info(f"Parsing {format_name}: {path.name}")
                source_instance = self._source_instance(path)
                parsed = list(parser.parse_file(path))
                for record in parsed:
                    record.source_instance = source_instance
                parsed.sort(key=lambda record: (record.line_number or 0, record.raw))
                format_records.extend(parsed)
            records[format_name] = format_records
            source_counts[format_name] = len(format_records)

        return records, source_counts

    def _source_instance(self, path: Path) -> str:
        """Return the nearest non-year directory identifying a host or sensor."""

        try:
            parts = path.resolve().relative_to(self.output_dir.resolve()).parts[:-1]
        except ValueError:
            return "__artifact__"
        for part in reversed(parts):
            if not (len(part) == 4 and part.isdigit()):
                return part
        return "__direct__"

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
                actual = f"{c.actual:.1f}" if c.actual is not None else "unmeasured"
                flags.append(
                    f"[{c.level.upper()}] {c.name}: {actual} < {c.threshold:.1f} threshold"
                )

        return flags
