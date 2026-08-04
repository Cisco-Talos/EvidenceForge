# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Exact IDS evaluation contract tests."""

from datetime import UTC, datetime
from pathlib import Path

import pytest
from pydantic import ValidationError

from evidenceforge.evaluation.context import EvaluationContext
from evidenceforge.evaluation.parsers import ParsedRecord
from evidenceforge.evaluation.pillars.plausibility import PlausibilityScorer
from evidenceforge.events.ground_truth import (
    GroundTruthDocument,
    IdsEvaluationSignature,
    IdsEvaluationSummary,
)
from evidenceforge.events.ids_evaluation import new_ids_digest, update_ids_digest
from evidenceforge.models.scenario import Scenario
from evidenceforge.utils.files import load_yaml

SCENARIO_PATH = Path(__file__).parent.parent / "fixtures/scenarios/retail-store-ftp-attack.yaml"
ALERT_TIME = datetime(2025, 2, 3, 12, 34, 56, 123456, tzinfo=UTC)


@pytest.fixture
def scenario() -> Scenario:
    return Scenario(**load_yaml(SCENARIO_PATH))


def _record(*, dst_port: int = 443, sensor: str = "ids-edge") -> ParsedRecord:
    fields = {
        "gid": 1,
        "sid": 2028401,
        "rev": 3,
        "message": "Test correlated alert",
        "classification": "Potentially Bad Traffic",
        "priority": 2,
        "protocol": "TCP",
        "src_ip": "2001:db8::10",
        "src_port": 49152,
        "dst_ip": "198.51.100.20",
        "dst_port": dst_port,
    }
    return ParsedRecord(
        source_format="snort_alert",
        source_instance=sensor,
        raw="alert",
        fields=fields,
        timestamp=ALERT_TIME,
        line_number=1,
    )


def _document(record: ParsedRecord | None) -> GroundTruthDocument:
    sensors: dict[str, dict[str, IdsEvaluationSignature]] = {}
    observation: dict[str, int] = {}
    source_status: dict[str, dict[str, dict[str, int]]] = {}
    if record is not None:
        digest = new_ids_digest()
        update_ids_digest(
            digest,
            record.source_instance or "__direct__",
            record.fields | {"timestamp": record.timestamp},
        )
        sensors[record.source_instance or "__direct__"] = {
            "1:2028401": IdsEvaluationSignature(
                gid=1,
                sid=2028401,
                candidate=1,
                emitted=1,
                policy_filtered=0,
                emitted_visible=1,
                emitted_delayed=0,
                origins={"authored_attachment": 1},
                emitted_sha256=digest.hexdigest(),
            )
        }
        observation = {"visible": 1}
        source_status = {"ids-edge": {"ids": {"visible": 1}}}
    return GroundTruthDocument(
        scenario_name="ids-eval-test",
        scenario_description="IDS contract test",
        generated_at=ALERT_TIME,
        observation_profile="complete",
        collection_window={"start": None, "end": None},
        source_evidence_status=source_status,
        ids_evaluation=IdsEvaluationSummary(observation=observation, sensors=sensors),
    )


def _score(
    scenario: Scenario,
    document: GroundTruthDocument | None,
    records: list[ParsedRecord],
):
    return PlausibilityScorer()._score_ids_integrity(
        {"snort_alert": records},
        scenario,
        EvaluationContext(ground_truth=document),
    )


def test_exact_sensor_tuple_timestamp_and_digest_pass(scenario: Scenario) -> None:
    record = _record()

    score = _score(scenario, _document(record), [record])

    assert score.score == 100.0
    assert not score.sample_failures


@pytest.mark.parametrize(
    ("changed_record", "failure"),
    [
        (_record(dst_port=8443), "digest differs"),
        (_record(sensor="ids-inside"), "Unexpected Snort rows"),
    ],
)
def test_mutated_or_misplaced_alert_fails(
    scenario: Scenario,
    changed_record: ParsedRecord,
    failure: str,
) -> None:
    expected = _record()

    score = _score(scenario, _document(expected), [changed_record])

    assert score.score is not None and score.score < 100.0
    assert any(failure in message for message in score.sample_failures)


def test_extra_alert_fails_count_and_digest(scenario: Scenario) -> None:
    record = _record()

    score = _score(
        scenario, _document(record), [record, record.model_copy(update={"line_number": 2})]
    )

    assert score.score is not None and score.score < 100.0
    assert any("emitted 2 != expected 1" in message for message in score.sample_failures)


def test_zero_candidate_summary_passes_without_snort_rows(scenario: Scenario) -> None:
    assert _score(scenario, _document(None), []).score == 100.0


def test_legacy_summary_is_skipped_without_authored_ids(scenario: Scenario) -> None:
    score = _score(scenario, None, [])

    assert score.skipped
    assert score.score is None
    assert "Legacy dataset" in score.details


def test_missing_summary_fails_when_scenario_authors_ids(scenario: Scenario) -> None:
    first_cluster = scenario.storyline[0]
    first_event = first_cluster.events[0].model_copy(update={"ids_alerts": [{"sid": 2028401}]})
    authored = scenario.model_copy(
        update={
            "storyline": [
                first_cluster.model_copy(update={"events": [first_event]}),
                *scenario.storyline[1:],
            ]
        }
    )

    score = _score(authored, None, [])

    assert score.score == 0.0
    assert not score.skipped


def test_signature_summary_rejects_unauthorized_origin_totals() -> None:
    with pytest.raises(ValidationError, match="origin totals"):
        IdsEvaluationSignature(
            gid=1,
            sid=2028401,
            candidate=1,
            emitted=1,
            policy_filtered=0,
            emitted_visible=1,
            emitted_delayed=0,
            origins={},
            emitted_sha256="0" * 64,
        )
