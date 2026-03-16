"""Tests for evaluation data models."""

import json
from datetime import datetime, timezone

from evidenceforge.evaluation.models import (
    AcceptanceCriterion,
    DimensionScore,
    QualityReport,
    SubScore,
)


class TestSubScore:
    def test_basic_creation(self):
        s = SubScore(name="Test", key="test", weight=0.5, score=85.0)
        assert s.score == 85.0
        assert s.weight == 0.5

    def test_none_score(self):
        s = SubScore(name="Test", key="test", weight=0.5)
        assert s.score is None


class TestDimensionScore:
    def test_basic_creation(self):
        d = DimensionScore(
            number=1,
            name="Record-Level Fidelity",
            weight=0.15,
            score=92.0,
            sub_scores=[
                SubScore(name="Parsability", key="parsability", weight=0.4, score=100.0),
                SubScore(name="Co-occurrence", key="co_occurrence", weight=0.35, score=88.0),
            ],
        )
        assert d.number == 1
        assert len(d.sub_scores) == 2


class TestQualityReport:
    def test_json_serialization(self):
        report = QualityReport(
            scenario_name="test-scenario",
            evaluated_at=datetime(2026, 3, 16, 12, 0, 0, tzinfo=timezone.utc),
            total_records=1000,
            source_counts={"windows_event_security": 500, "zeek_conn": 500},
            overall_score=78.0,
            dimensions=[
                DimensionScore(
                    number=1,
                    name="Record-Level Fidelity",
                    weight=0.15,
                    score=92.0,
                ),
            ],
            acceptance_passed=True,
            acceptance_criteria=[
                AcceptanceCriterion(
                    name="Parsability",
                    dimension=1,
                    sub_score_key="parsability",
                    threshold=98.0,
                    actual=100.0,
                    passed=True,
                    level="hard",
                ),
            ],
        )
        json_str = report.model_dump_json()
        data = json.loads(json_str)
        assert data["scenario_name"] == "test-scenario"
        assert data["overall_score"] == 78.0
        assert len(data["dimensions"]) == 1
        assert data["acceptance_passed"] is True

    def test_empty_report(self):
        report = QualityReport(
            scenario_name="empty",
            evaluated_at=datetime.now(timezone.utc),
        )
        assert report.total_records == 0
        assert report.overall_score is None
        assert report.acceptance_passed is None
