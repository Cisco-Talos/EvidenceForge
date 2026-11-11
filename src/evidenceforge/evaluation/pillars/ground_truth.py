"""Pillar 5: deterministic, equally action-weighted ground-truth agreement."""

from __future__ import annotations

from evidenceforge.evaluation.context import EvaluationContext
from evidenceforge.evaluation.dimensions import DimensionScorer, ProgressCallback, _noop_callback
from evidenceforge.evaluation.ground_truth_agreement import (
    GroundTruthAgreementResult,
    evaluate_ground_truth,
)
from evidenceforge.evaluation.models import PillarScore, SubScore
from evidenceforge.evaluation.parsers import RecordCorpus
from evidenceforge.models import Scenario
from evidenceforge.models.exceptions import EvaluationError


def prepare_ground_truth_agreement(
    context: EvaluationContext, records: RecordCorpus, scenario: Scenario
) -> GroundTruthAgreementResult:
    """Compute once and retain runtime bindings separately from serialized findings."""
    if "result" not in context.ground_truth_agreement:
        if context.ground_truth is None or context.ground_truth_root is None:
            raise EvaluationError("Ground-truth agreement requires a complete schema-v5 bundle")
        result, bindings = evaluate_ground_truth(
            context.ground_truth_root, context.ground_truth, scenario, records
        )
        context.ground_truth_agreement.update(result=result, bindings=bindings)
    return context.ground_truth_agreement["result"]


class GroundTruthAgreementScorer(DimensionScorer):
    """Compare validated source expectations with independently parsed evidence."""

    number = 5
    name = "Ground Truth Agreement"
    weight = 0.20

    def score(
        self,
        records: RecordCorpus,
        scenario: Scenario,
        context: EvaluationContext | None = None,
        progress: ProgressCallback = _noop_callback,
    ) -> PillarScore:
        if context is None:
            raise EvaluationError("Ground-truth agreement requires its captured run context")
        result = prepare_ground_truth_agreement(context, records, scenario)
        zero = sum(a.correct + a.incorrect == 0 for a in result.actions)
        details = (
            f"{result.correct} correct / {result.correct + result.incorrect} applicable source checks across "
            f"{len(result.actions)} equally weighted authored actions; {result.expected_absences} expected absences, "
            f"{result.coverage_gaps} coverage gaps; {zero} zero-check actions score 100%."
        )
        sub = SubScore(
            name=self.name,
            key="ground_truth_agreement",
            weight=1,
            score=result.score,
            details=details,
            sample_failures=[
                f"{finding['intent_id']}: {finding['rule']} in {finding.get('source_instance') or 'canonical truth'}"
                for finding in result.findings[:20]
            ],
            failure_summary={"ground_truth": result.failure_counts},
        )
        progress("sub_score_done", {"name": self.name, "score": result.score})
        return PillarScore(
            number=5,
            name=self.name,
            weight=self.weight,
            score=result.score,
            sub_scores=[sub],
            supplementary={"ground_truth_agreement": result.model_dump(mode="json")},
        )
