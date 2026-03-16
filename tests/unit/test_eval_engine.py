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

        # Our fixtures have all 7 formats
        assert len(report.source_counts) == 7

    def test_produces_dimension_scores(self, retail_scenario):
        """Engine should produce at least Dimension 1 scores."""
        engine = EvaluationEngine(
            output_dir=GOOD_FIXTURES,
            scenario=retail_scenario,
        )
        report = engine.run()

        assert len(report.dimensions) >= 1
        dim1 = report.dimensions[0]
        assert dim1.number == 1
        assert dim1.name == "Record-Level Fidelity"
        assert dim1.score is not None

    def test_acceptance_criteria_evaluated(self, retail_scenario):
        """Engine should evaluate acceptance criteria."""
        engine = EvaluationEngine(
            output_dir=GOOD_FIXTURES,
            scenario=retail_scenario,
        )
        report = engine.run()

        # Should have at least the parsability criterion
        parsability = next(
            (c for c in report.acceptance_criteria if c.name == "Parsability"),
            None,
        )
        assert parsability is not None
        assert parsability.actual is not None
        assert parsability.passed is not None

    def test_empty_directory(self, retail_scenario, tmp_path):
        """Engine should handle empty output directory gracefully."""
        engine = EvaluationEngine(
            output_dir=tmp_path,
            scenario=retail_scenario,
        )
        report = engine.run()

        assert report.total_records == 0
        assert report.overall_score is not None  # 100 (no failures)
