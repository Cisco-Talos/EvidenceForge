# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Tests for the evaluation engine."""

from pathlib import Path

import pytest

from evidenceforge.evaluation.engine import EvaluationEngine
from evidenceforge.evaluation.limits import EvaluationLimits
from evidenceforge.evaluation.models import QualityReport
from evidenceforge.models.exceptions import EvaluationLimitError
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
            if c.applicable is False:
                assert c.actual is None
                assert c.passed is None
                continue
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
        assert report.overall_score is not None
        assert report.overall_score < 100
        assert report.acceptance_passed is False

    def test_reports_separate_evaluation_categories(self, retail_scenario):
        """Concern-oriented category scores must be independent of legacy pillar labels."""

        report = EvaluationEngine(output_dir=GOOD_FIXTURES, scenario=retail_scenario).run()

        assert [category.key for category in report.categories] == [
            "source_schema",
            "canonical_invariants",
            "scenario_completeness",
            "distribution_realism",
            "expert_comparison",
        ]
        assert report.categories[0].score is not None
        assert report.categories[-1].score is None

    def test_report_is_repeatable_except_evaluated_at(self, retail_scenario):
        """Stable discovery and sampling produce identical evaluation content."""

        first = EvaluationEngine(output_dir=GOOD_FIXTURES, scenario=retail_scenario).run()
        second = EvaluationEngine(output_dir=GOOD_FIXTURES, scenario=retail_scenario).run()

        assert first.model_dump(exclude={"evaluated_at"}) == second.model_dump(
            exclude={"evaluated_at"}
        )

    def test_rejects_corpus_byte_budget_before_parsing(self, retail_scenario, tmp_path):
        """Corpus bytes are bounded before records are retained in memory."""
        (tmp_path / "ecar.json").write_text("{}\n", encoding="utf-8")
        engine = EvaluationEngine(
            output_dir=tmp_path,
            scenario=retail_scenario,
            limits=EvaluationLimits(max_corpus_bytes=1),
        )

        with pytest.raises(EvaluationLimitError, match="corpus bytes"):
            engine._parse_all_logs()

    def test_rejects_record_budget_during_streaming_parse(self, retail_scenario, tmp_path):
        """The parser stops as soon as the retained-record budget is exceeded."""
        (tmp_path / "ecar.json").write_text("{}\n{}\n", encoding="utf-8")
        engine = EvaluationEngine(
            output_dir=tmp_path,
            scenario=retail_scenario,
            limits=EvaluationLimits(max_records=1),
        )

        with pytest.raises(EvaluationLimitError, match="record count"):
            engine._parse_all_logs()

    def test_explicit_evaluation_override_records_capacity_decision(
        self, retail_scenario, tmp_path
    ):
        """A reviewed large corpus can proceed and records that the limits were overridden."""
        (tmp_path / "ecar.json").write_text("{}\n{}\n", encoding="utf-8")
        engine = EvaluationEngine(
            output_dir=tmp_path,
            scenario=retail_scenario,
            limits=EvaluationLimits(max_corpus_bytes=1, max_records=1),
            allow_large_evaluation=True,
        )

        records, _counts = engine._parse_all_logs()

        assert len(records["ecar"]) == 2
        assert engine.capacity.parsed_records == 2
        assert engine.capacity.limits_overridden is True
