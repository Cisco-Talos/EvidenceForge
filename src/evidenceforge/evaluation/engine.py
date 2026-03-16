"""Evaluation engine orchestrator.

Runs all available dimension scorers, computes overall score,
checks acceptance criteria, and assembles the QualityReport.
"""

import logging
from collections.abc import Callable
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from evidenceforge.evaluation.dimensions import DimensionScorer, ProgressCallback, _noop_callback
from evidenceforge.evaluation.dimensions.record_fidelity import RecordFidelityScorer
from evidenceforge.evaluation.dimensions.signal_integrity import SignalIntegrityScorer
from evidenceforge.evaluation.models import (
    AcceptanceCriterion,
    DimensionScore,
    QualityReport,
)
from evidenceforge.evaluation.parsers import ParsedRecord, discover_log_files, get_parser
from evidenceforge.models.scenario import Scenario

logger = logging.getLogger(__name__)

# Registered dimension scorers (add new dimensions here as they're implemented)
DIMENSION_SCORERS: list[DimensionScorer] = [
    RecordFidelityScorer(),
    SignalIntegrityScorer(),
    # Future: TemporalRealismScorer(), CrossSourceScorer(), NoiseRealismScorer()
]

# Acceptance criteria definitions
ACCEPTANCE_CRITERIA: list[AcceptanceCriterion] = [
    AcceptanceCriterion(
        name="Parsability",
        dimension=1,
        sub_score_key="parsability",
        threshold=98.0,
        level="hard",
    ),
    AcceptanceCriterion(
        name="Source Correctness",
        dimension=2,
        sub_score_key="source_correctness",
        threshold=95.0,
        level="hard",
    ),
    AcceptanceCriterion(
        name="Causal Ordering",
        dimension=4,
        sub_score_key="causal_ordering",
        threshold=99.0,
        level="hard",
    ),
    AcceptanceCriterion(
        name="Event Presence",
        dimension=5,
        sub_score_key="event_presence",
        threshold=90.0,
        level="hard",
    ),
]


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

    def run(self) -> QualityReport:
        """Execute the full evaluation pipeline."""
        # 1. Discover and parse all log files
        self._progress("phase_start", {"phase": "parsing"})
        records, source_counts = self._parse_all_logs()
        total_records = sum(source_counts.values())
        self._progress("phase_done", {
            "phase": "parsing",
            "total_records": total_records,
            "sources": len(source_counts),
        })

        logger.info(
            f"Parsed {total_records} records across {len(source_counts)} sources"
        )

        # 2. Run each available dimension scorer
        total_dims = len(DIMENSION_SCORERS)
        self._progress("phase_start", {"phase": "scoring", "total_dimensions": total_dims})
        dimensions: list[DimensionScore] = []
        for i, scorer in enumerate(DIMENSION_SCORERS, 1):
            self._progress("dimension_start", {
                "number": scorer.number,
                "name": scorer.name,
                "step": i,
                "total": total_dims,
            })
            logger.info(f"Scoring Dimension {scorer.number}: {scorer.name}")
            try:
                dim_score = scorer.score(records, self.scenario, progress=self._progress)
                dimensions.append(dim_score)
            except Exception:
                logger.exception(f"Dimension {scorer.number} scoring failed")
                dimensions.append(
                    DimensionScore(
                        number=scorer.number,
                        name=scorer.name,
                        weight=scorer.weight,
                        score=None,
                    )
                )
            self._progress("dimension_done", {
                "number": scorer.number,
                "name": scorer.name,
                "score": dim_score.score if dimensions and dimensions[-1].score is not None else None,
            })

        # 3. Compute overall score (weighted average of available dimensions)
        overall = self._compute_overall(dimensions)

        # 4. Check acceptance criteria
        acceptance_criteria = self._check_acceptance(dimensions)
        all_hard_pass = all(
            c.passed for c in acceptance_criteria
            if c.level == "hard" and c.passed is not None
        )

        # 5. Build flags
        flags = self._build_flags(dimensions, acceptance_criteria)

        return QualityReport(
            scenario_name=self.scenario.name,
            evaluated_at=datetime.now(timezone.utc),
            total_records=total_records,
            source_counts=source_counts,
            overall_score=overall,
            dimensions=dimensions,
            acceptance_passed=all_hard_pass if any(
                c.passed is not None for c in acceptance_criteria if c.level == "hard"
            ) else None,
            acceptance_criteria=acceptance_criteria,
            flags=flags,
        )

    def _parse_all_logs(self) -> tuple[dict[str, list[ParsedRecord]], dict[str, int]]:
        """Discover and parse all log files in the output directory."""
        file_map = discover_log_files(self.output_dir)
        records: dict[str, list[ParsedRecord]] = {}
        source_counts: dict[str, int] = {}

        total_formats = len(file_map)
        for i, (format_name, paths) in enumerate(file_map.items(), 1):
            self._progress("parsing_format", {
                "format": format_name,
                "step": i,
                "total": total_formats,
            })
            parser = get_parser(format_name)
            format_records: list[ParsedRecord] = []
            for path in paths:
                logger.info(f"Parsing {format_name}: {path.name}")
                format_records.extend(parser.parse_file(path))
            records[format_name] = format_records
            source_counts[format_name] = len(format_records)

        return records, source_counts

    @staticmethod
    def _compute_overall(dimensions: list[DimensionScore]) -> float | None:
        """Compute weighted overall score from available dimensions."""
        scored = [(d.weight, d.score) for d in dimensions if d.score is not None]
        if not scored:
            return None

        total_weight = sum(w for w, _ in scored)
        if total_weight == 0:
            return None

        return sum(w * s for w, s in scored) / total_weight

    @staticmethod
    def _check_acceptance(
        dimensions: list[DimensionScore],
    ) -> list[AcceptanceCriterion]:
        """Evaluate acceptance criteria against dimension scores."""
        results: list[AcceptanceCriterion] = []

        for criterion in ACCEPTANCE_CRITERIA:
            result = criterion.model_copy()

            # Find the matching dimension
            dim = next(
                (d for d in dimensions if d.number == criterion.dimension), None
            )
            if dim is None or dim.score is None:
                # Dimension not yet implemented — criterion is indeterminate
                results.append(result)
                continue

            # Find the matching sub-score
            sub = next(
                (s for s in dim.sub_scores if s.key == criterion.sub_score_key), None
            )
            if sub is None or sub.score is None:
                results.append(result)
                continue

            result.actual = sub.score
            result.passed = sub.score >= criterion.threshold
            results.append(result)

        return results

    @staticmethod
    def _build_flags(
        dimensions: list[DimensionScore],
        criteria: list[AcceptanceCriterion],
    ) -> list[str]:
        """Build human-readable flag messages."""
        flags: list[str] = []

        # Flag any sub-score below 50
        for dim in dimensions:
            for sub in dim.sub_scores:
                if sub.score is not None and sub.score < 50:
                    flags.append(
                        f"{sub.name}: {sub.score:.0f}/100 ({sub.details})"
                    )

        # Flag failed acceptance criteria
        for c in criteria:
            if c.passed is False:
                flags.append(
                    f"[{c.level.upper()}] {c.name}: "
                    f"{c.actual:.1f} < {c.threshold:.1f} threshold"
                )

        return flags
