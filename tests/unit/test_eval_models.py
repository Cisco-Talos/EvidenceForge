# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Tests for evaluation data models."""

import json
from datetime import UTC, datetime

from evidenceforge.evaluation.models import (
    AcceptanceCriterion,
    DimensionScore,
    PillarScore,
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


class TestPillarScore:
    def test_basic_creation(self):
        p = PillarScore(
            number=1,
            name="Parseability",
            weight=0.30,
            score=92.0,
            sub_scores=[
                SubScore(name="Spec Conformance", key="spec_conformance", weight=0.5, score=100.0),
                SubScore(
                    name="Format Constraints", key="format_constraints", weight=0.5, score=88.0
                ),
            ],
        )
        assert p.number == 1
        assert len(p.sub_scores) == 2

    def test_dimension_score_alias(self):
        # DimensionScore is a backward-compat alias for PillarScore
        assert DimensionScore is PillarScore
        d = DimensionScore(number=1, name="Record-Level Fidelity", weight=0.15, score=92.0)
        assert isinstance(d, PillarScore)


class TestAcceptanceCriterion:
    def test_basic_creation(self):
        c = AcceptanceCriterion(
            name="parseability.spec_conformance",
            pillar="parseability",
            sub_score_key="spec_conformance",
            threshold=95.0,
            aspirational=99.0,
            actual=97.0,
            passed=True,
            meets_aspirational=False,
            level="hard",
        )
        assert c.passed is True
        assert c.meets_aspirational is False

    def test_indeterminate_state(self):
        c = AcceptanceCriterion(
            name="parseability.spec_conformance",
            pillar="parseability",
            sub_score_key="spec_conformance",
            threshold=95.0,
            level="hard",
        )
        assert c.passed is None
        assert c.actual is None


class TestQualityReport:
    def test_json_serialization(self):
        report = QualityReport(
            scenario_name="test-scenario",
            evaluated_at=datetime(2026, 3, 16, 12, 0, 0, tzinfo=UTC),
            total_records=1000,
            source_counts={"windows_event_security": 500, "zeek_conn": 500},
            overall_score=78.0,
            pillars=[
                PillarScore(
                    number=1,
                    name="Parseability",
                    weight=0.30,
                    score=92.0,
                ),
            ],
            acceptance_passed=True,
            acceptance_criteria=[
                AcceptanceCriterion(
                    name="parseability.spec_conformance",
                    pillar="parseability",
                    sub_score_key="spec_conformance",
                    threshold=95.0,
                    aspirational=99.0,
                    actual=100.0,
                    passed=True,
                    level="hard",
                ),
            ],
            aspirational_met=1,
            aspirational_total=6,
        )
        json_str = report.model_dump_json()
        data = json.loads(json_str)
        assert data["scenario_name"] == "test-scenario"
        assert data["overall_score"] == 78.0
        assert len(data["pillars"]) == 1
        assert data["acceptance_passed"] is True
        assert data["aspirational_met"] == 1
        assert data["aspirational_total"] == 6

    def test_dimensions_property(self):
        """dimensions property is a backward-compat alias for pillars."""
        p = PillarScore(number=1, name="Parseability", weight=0.30, score=92.0)
        report = QualityReport(
            scenario_name="test",
            evaluated_at=datetime.now(UTC),
            pillars=[p],
        )
        assert report.dimensions is report.pillars

    def test_empty_report(self):
        report = QualityReport(
            scenario_name="empty",
            evaluated_at=datetime.now(UTC),
        )
        assert report.total_records == 0
        assert report.overall_score is None
        assert report.acceptance_passed is None
        assert report.aspirational_met is None
