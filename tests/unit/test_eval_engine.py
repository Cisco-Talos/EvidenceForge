# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Tests for the evaluation engine."""

from pathlib import Path

import pytest

from evidenceforge.evaluation.engine import EvaluationEngine
from evidenceforge.evaluation.models import QualityReport
from evidenceforge.models.scenario import Scenario
from evidenceforge.utils.files import load_yaml

GOOD_FIXTURES = Path(__file__).parent.parent / "fixtures" / "eval" / "good"
SCENARIOS_DIR = Path(__file__).parent.parent / "fixtures" / "scenarios"


@pytest.fixture
def retail_scenario() -> Scenario:
    data = load_yaml(SCENARIOS_DIR / "retail-store-ftp-attack.yaml")
    return Scenario(**data)


class TestEvaluationEngine:
    def test_runs_on_fixture_data(self, retail_scenario):
        """Engine should run without errors on the good fixture data."""
        engine = EvaluationEngine(
            output_dir=GOOD_FIXTURES,
            scenario=retail_scenario,
        )
        report = engine.run()

        assert isinstance(report, QualityReport)
        assert report.scenario_name == "retail-store-ftp-attack"
        assert report.total_records > 0
        assert len(report.source_counts) > 0
        assert report.overall_score is not None

    def test_discovers_all_source_formats(self, retail_scenario):
        """Engine should discover all 7 log formats in the good fixtures."""
        engine = EvaluationEngine(
            output_dir=GOOD_FIXTURES,
            scenario=retail_scenario,
        )
        report = engine.run()

        assert len(report.source_counts) == 7

    def test_produces_pillar_scores(self, retail_scenario):
        """Engine should produce at least Pillar 1 scores."""
        engine = EvaluationEngine(
            output_dir=GOOD_FIXTURES,
            scenario=retail_scenario,
        )
        report = engine.run()

        # pillars property holds scored pillars
        assert len(report.pillars) >= 1
        pillar1 = report.pillars[0]
        assert pillar1.number == 1
        assert pillar1.score is not None

        # backward-compat alias
        assert report.dimensions is report.pillars

    def test_acceptance_criteria_from_thresholds(self, retail_scenario):
        """Engine should evaluate hard-gated acceptance criteria from thresholds.yaml."""
        engine = EvaluationEngine(
            output_dir=GOOD_FIXTURES,
            scenario=retail_scenario,
        )
        report = engine.run()

        # thresholds.yaml defines hard gates for spec_conformance and causal_ordering
        hard_criteria = [c for c in report.acceptance_criteria if c.level == "hard"]
        assert len(hard_criteria) > 0
        for c in hard_criteria:
            assert c.actual is not None
            assert c.passed is not None

    def test_aspirational_counts(self, retail_scenario):
        """Engine should compute aspirational_met and aspirational_total."""
        engine = EvaluationEngine(
            output_dir=GOOD_FIXTURES,
            scenario=retail_scenario,
        )
        report = engine.run()

        # These are populated when there are scored sub-scores
        if report.aspirational_total:
            assert report.aspirational_met is not None
            assert 0 <= report.aspirational_met <= report.aspirational_total

    def test_empty_directory(self, retail_scenario, tmp_path):
        """Engine should handle empty output directory gracefully."""
        engine = EvaluationEngine(
            output_dir=tmp_path,
            scenario=retail_scenario,
        )
        report = engine.run()

        assert report.total_records == 0
        assert report.overall_score is not None  # 100 (no failures)
