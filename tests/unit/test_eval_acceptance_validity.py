# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Known-bad proofs for non-vacuous evaluation acceptance."""

import json
from pathlib import Path
from typing import Any

import pytest

from evidenceforge.evaluation.context import EvaluationContext
from evidenceforge.evaluation.engine import (
    _acceptance_verdict,
    _build_acceptance_criteria,
)
from evidenceforge.evaluation.models import PillarScore, SubScore
from evidenceforge.evaluation.pillars.causality import CausalityScorer
from evidenceforge.evaluation.thresholds import EvalThresholds, load_thresholds
from evidenceforge.events.contracts import OccurrenceRole, SemanticOccurrenceKey
from evidenceforge.events.observation_manifest import ObservationManifest
from evidenceforge.generation.actions.command_effects import ExecutionEffectAuditCounter
from evidenceforge.generation.ground_truth import GroundTruthGenerator
from evidenceforge.generation.intent_ledger import AuthoredIntentLedger, IntentExecutionLedger
from evidenceforge.models.scenario import Scenario
from evidenceforge.utils.files import load_yaml

KNOWN_BAD_CASES_PATH = (
    Path(__file__).parent.parent / "fixtures" / "eval" / "known_bad" / "acceptance_cases.json"
)


def _known_bad_cases() -> list[Any]:
    """Load durable named acceptance failures from the fixture ledger."""

    cases: list[dict[str, Any]] = json.loads(KNOWN_BAD_CASES_PATH.read_text(encoding="utf-8"))
    return [pytest.param(case["sub_score_key"], case["score"], id=case["name"]) for case in cases]


@pytest.fixture
def authored_scenario() -> Scenario:
    """Load a stable typed-storyline scenario for reconciliation proofs."""

    path = Path(__file__).parent.parent / "fixtures" / "scenarios" / "retail-store-ftp-attack.yaml"
    return Scenario(**load_yaml(path))


def _passing_pillars(
    thresholds: EvalThresholds,
    *,
    overrides: dict[str, float] | None = None,
    skipped: set[str] | None = None,
) -> list[PillarScore]:
    overrides = overrides or {}
    skipped = skipped or set()
    pillars = []
    for number, (pillar_name, pillar) in enumerate(thresholds.pillars.items(), start=1):
        sub_scores = []
        for key in pillar.sub_scores:
            is_skipped = key in skipped
            sub_scores.append(
                SubScore(
                    name=key,
                    key=key,
                    weight=0.1,
                    score=None if is_skipped else overrides.get(key, 100.0),
                    skipped=is_skipped,
                )
            )
        pillars.append(
            PillarScore(
                number=number,
                name=pillar_name,
                weight=pillar.weight,
                score=100.0,
                sub_scores=sub_scores,
            )
        )
    return pillars


@pytest.mark.parametrize(
    "key,bad_score",
    [pytest.param("spec_conformance", 94.0, id="unparseable_source"), *_known_bad_cases()],
)
def test_high_impact_mismatch_fails_acceptance(key: str, bad_score: float) -> None:
    """Each high-impact schema, invariant, or scenario mismatch is independently gating."""

    thresholds = load_thresholds()
    criteria = _build_acceptance_criteria(
        thresholds,
        _passing_pillars(thresholds, overrides={key: bad_score}, skipped={"ids_integrity"}),
    )

    target = next(criterion for criterion in criteria if criterion.sub_score_key == key)
    assert target.applicable is True
    assert target.passed is False
    assert _acceptance_verdict(criteria) is False


def test_missing_required_measure_is_not_silently_ignored() -> None:
    """A configured hard gate absent from all scorers makes acceptance fail."""

    thresholds = load_thresholds()
    pillars = _passing_pillars(thresholds, skipped={"ids_integrity"})
    for pillar in pillars:
        pillar.sub_scores = [
            score for score in pillar.sub_scores if score.key != "intent_reconciliation"
        ]

    criteria = _build_acceptance_criteria(thresholds, pillars)
    target = next(
        criterion for criterion in criteria if criterion.sub_score_key == "intent_reconciliation"
    )

    assert target.applicable is True
    assert target.actual is None
    assert target.passed is False
    assert _acceptance_verdict(criteria) is False


def test_explicitly_inapplicable_measure_does_not_create_a_false_failure() -> None:
    """A scorer may explicitly skip a contract that the scenario cannot exercise."""

    thresholds = load_thresholds()
    criteria = _build_acceptance_criteria(
        thresholds,
        _passing_pillars(
            thresholds,
            skipped={"ids_integrity", "pivot_linkability"},
        ),
    )
    pivot = next(
        criterion for criterion in criteria if criterion.sub_score_key == "pivot_linkability"
    )

    assert pivot.applicable is False
    assert pivot.passed is None
    assert _acceptance_verdict(criteria) is True


def test_intent_reconciliation_rejects_metadata_drift(authored_scenario: Scenario) -> None:
    """Stable IDs cannot hide a ground-truth row that contradicts authored intent."""

    authored = AuthoredIntentLedger.from_scenario(authored_scenario)
    execution = IntentExecutionLedger(authored)
    for intent in authored.intents:
        execution.mark_planned(intent.intent_id)
    ground_truth = GroundTruthGenerator(
        authored_scenario,
        [],
        authored_intent_ledger=authored,
        intent_execution_snapshot=execution.snapshot(),
    ).build_document()
    reconciliation = ground_truth.intent_reconciliation
    assert reconciliation is not None
    forged_row = reconciliation.intents[0].model_copy(update={"actor": "forged-actor"})
    forged_reconciliation = reconciliation.model_copy(
        update={"intents": [forged_row, *reconciliation.intents[1:]]}
    )
    forged_ground_truth = ground_truth.model_copy(
        update={"intent_reconciliation": forged_reconciliation}
    )

    score = CausalityScorer._score_intent_reconciliation(
        authored_scenario,
        EvaluationContext(ground_truth=forged_ground_truth),
    )

    assert score.score is not None and score.score < 100.0
    assert any("metadata differs" in failure for failure in score.sample_failures)


def test_intent_reconciliation_rejects_reported_unexpected_intent(
    authored_scenario: Scenario,
) -> None:
    """An unexpected execution ID fails even when it has no authored reconciliation row."""

    authored = AuthoredIntentLedger.from_scenario(authored_scenario)
    execution = IntentExecutionLedger(authored)
    for intent in authored.intents:
        execution.mark_planned(intent.intent_id)
    execution.record_occurrence(
        "unexpected-intent",
        SemanticOccurrenceKey(
            action_id="unexpected-action",
            role=OccurrenceRole.PRIMARY,
            instance_key="unexpected-instance",
        ),
    )
    ground_truth = GroundTruthGenerator(
        authored_scenario,
        [],
        authored_intent_ledger=authored,
        intent_execution_snapshot=execution.snapshot(),
    ).build_document()

    score = CausalityScorer._score_intent_reconciliation(
        authored_scenario,
        EvaluationContext(ground_truth=ground_truth),
    )

    assert score.score is not None and score.score < 100.0
    assert any("unexpected intent" in failure.lower() for failure in score.sample_failures)


def test_effect_reconciliation_is_a_binary_missing_required_guardrail(
    authored_scenario: Scenario,
) -> None:
    """One reported missing required effect forces the zero-weight hard gate to zero."""

    ground_truth = GroundTruthGenerator(
        authored_scenario,
        [],
        execution_effect_audit_snapshot=ExecutionEffectAuditCounter().snapshot(),
    ).build_document()
    reconciliation = ground_truth.effect_reconciliation
    assert reconciliation is not None
    forged = reconciliation.model_copy(
        update={
            "complete": False,
            "plan_count": 1,
            "planned_node_count": 1,
            "required_node_count": 1,
            "missing_node_count": 1,
            "missing_required_node_count": 1,
            "incomplete_reconciliation_count": 1,
        }
    )
    forged_ground_truth = ground_truth.model_copy(update={"effect_reconciliation": forged})

    score = CausalityScorer._score_effect_reconciliation(
        EvaluationContext(ground_truth=forged_ground_truth)
    )

    assert score.weight == 0.0
    assert score.score == 0.0
    assert any("missing_required_node_count=1" in failure for failure in score.sample_failures)


def test_effect_reconciliation_is_a_binary_publication_denominator_guardrail(
    authored_scenario: Scenario,
) -> None:
    """A published effect missing plan reconciliation forces the hard gate to zero."""

    ground_truth = GroundTruthGenerator(
        authored_scenario,
        [],
        execution_effect_audit_snapshot=ExecutionEffectAuditCounter().snapshot(),
    ).build_document()
    reconciliation = ground_truth.effect_reconciliation
    assert reconciliation is not None
    forged = reconciliation.model_copy(
        update={
            "complete": False,
            "published_effect_occurrence_count": 1,
            "effect_publication_mismatch_count": 1,
        }
    )
    forged_ground_truth = ground_truth.model_copy(update={"effect_reconciliation": forged})

    score = CausalityScorer._score_effect_reconciliation(
        EvaluationContext(ground_truth=forged_ground_truth)
    )

    assert score.weight == 0.0
    assert score.score == 0.0
    assert any(
        "effect_publication_mismatch_count=1" in failure for failure in score.sample_failures
    )
    assert any(
        "Published effect occurrences contradict" in failure for failure in score.sample_failures
    )


def test_effect_reconciliation_rejects_legacy_exempt_publication(
    authored_scenario: Scenario,
) -> None:
    """A named exemption remains a defect instead of bypassing the hard gate."""

    ground_truth = GroundTruthGenerator(
        authored_scenario,
        [],
        execution_effect_audit_snapshot=ExecutionEffectAuditCounter().snapshot(),
    ).build_document()
    reconciliation = ground_truth.effect_reconciliation
    assert reconciliation is not None
    forged = reconciliation.model_copy(
        update={
            "complete": False,
            "exempt_effect_occurrence_count": 1,
        }
    )

    score = CausalityScorer._score_effect_reconciliation(
        EvaluationContext(
            ground_truth=ground_truth.model_copy(update={"effect_reconciliation": forged})
        )
    )

    assert score.weight == 0.0
    assert score.score == 0.0
    assert any("exempt_effect_occurrence_count=1" in item for item in score.sample_failures)


def test_mismatched_observation_manifest_does_not_discard_ground_truth(
    authored_scenario: Scenario,
) -> None:
    """Rejecting a stale observation manifest preserves independent reconciliation evidence."""

    authored = AuthoredIntentLedger.from_scenario(authored_scenario)
    execution = IntentExecutionLedger(authored)
    for intent in authored.intents:
        execution.mark_planned(intent.intent_id)
    ground_truth = GroundTruthGenerator(
        authored_scenario,
        [],
        authored_intent_ledger=authored,
        intent_execution_snapshot=execution.snapshot(),
    ).build_document()
    stale_manifest = ObservationManifest(
        scenario_name="different-scenario",
        observation_profile="complete",
        collection_window={"start": None, "end": None},
    )

    pillar = CausalityScorer().score(
        {},
        authored_scenario,
        EvaluationContext(observation_manifest=stale_manifest, ground_truth=ground_truth),
    )
    reconciliation = next(
        score for score in pillar.sub_scores if score.key == "intent_reconciliation"
    )

    assert reconciliation.score == 100.0
