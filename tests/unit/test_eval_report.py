"""Tests for evaluation report formatting."""

from datetime import UTC, datetime
from io import StringIO

from rich.console import Console

from evidenceforge.evaluation.models import (
    AcceptanceCriterion,
    DimensionScore,
    QualityReport,
    SubScore,
)
from evidenceforge.evaluation.report import (
    _score_color,
    format_json_report,
    format_text_report,
)


def _make_console() -> tuple[Console, StringIO]:
    buf = StringIO()
    console = Console(file=buf, force_terminal=False, width=120)
    return console, buf


def _make_report(**overrides) -> QualityReport:
    defaults = dict(
        scenario_name="test-scenario",
        evaluated_at=datetime(2025, 1, 15, 12, 0, 0, tzinfo=UTC),
        total_records=500,
        source_counts={"windows_event_security": 300, "zeek_conn": 200},
        overall_score=85.0,
        dimensions=[
            DimensionScore(
                number=1,
                name="Record Fidelity",
                weight=0.3,
                score=90.0,
                sub_scores=[
                    SubScore(name="Field Accuracy", key="field_accuracy", weight=0.5, score=95.0),
                    SubScore(
                        name="Parse Rate",
                        key="parse_rate",
                        weight=0.5,
                        score=85.0,
                        details="2 parse errors",
                    ),
                ],
            ),
            DimensionScore(
                number=2,
                name="Temporal Consistency",
                weight=0.3,
                score=None,
                sub_scores=[
                    SubScore(name="Ordering", key="ordering", weight=1.0, score=None),
                ],
            ),
        ],
        acceptance_passed=True,
        acceptance_criteria=[
            AcceptanceCriterion(
                name="field_accuracy >= 80",
                dimension=1,
                sub_score_key="field_accuracy",
                threshold=80.0,
                actual=95.0,
                passed=True,
                level="hard",
            ),
        ],
        flags=["Low record count for zeek_conn"],
    )
    defaults.update(overrides)
    return QualityReport(**defaults)


class TestScoreColor:
    def test_green_for_high_scores(self):
        assert _score_color(90.0) == "green"
        assert _score_color(100.0) == "green"

    def test_yellow_for_medium_scores(self):
        assert _score_color(70.0) == "yellow"
        assert _score_color(89.9) == "yellow"

    def test_orange_for_low_scores(self):
        assert _score_color(50.0) == "dark_orange"
        assert _score_color(69.9) == "dark_orange"

    def test_red_for_very_low_scores(self):
        assert _score_color(0.0) == "red"
        assert _score_color(49.9) == "red"


class TestFormatTextReport:
    def test_basic_output_contains_key_sections(self):
        console, buf = _make_console()
        report = _make_report()
        format_text_report(report, console)
        output = buf.getvalue()

        assert "EvidenceForge Data Quality Report" in output
        assert "test-scenario" in output
        assert "500" in output
        assert "85/100" in output
        assert "Record Fidelity" in output
        assert "Acceptance: PASS" in output

    def test_verbose_shows_source_breakdown_and_details(self):
        console, buf = _make_console()
        report = _make_report()
        format_text_report(report, console, verbose=True)
        output = buf.getvalue()

        assert "windows_event_security: 300" in output
        assert "2 parse errors" in output

    def test_none_overall_score(self):
        console, buf = _make_console()
        report = _make_report(overall_score=None)
        format_text_report(report, console)
        output = buf.getvalue()

        assert "N/A" in output

    def test_acceptance_fail(self):
        console, buf = _make_console()
        report = _make_report(acceptance_passed=False)
        format_text_report(report, console)
        output = buf.getvalue()

        assert "FAIL" in output

    def test_acceptance_indeterminate(self):
        console, buf = _make_console()
        report = _make_report(acceptance_passed=None)
        format_text_report(report, console)
        output = buf.getvalue()

        assert "INDETERMINATE" in output

    def test_flags_displayed(self):
        console, buf = _make_console()
        report = _make_report()
        format_text_report(report, console)
        output = buf.getvalue()

        assert "Low record count for zeek_conn" in output

    def test_no_flags_no_crash(self):
        console, buf = _make_console()
        report = _make_report(flags=[])
        format_text_report(report, console)
        # Just verifying no exception

    def test_unscored_dimension_shows_not_implemented(self):
        console, buf = _make_console()
        report = _make_report()
        format_text_report(report, console)
        output = buf.getvalue()

        assert "not implemented" in output

    def test_unscored_subscore_shows_na(self):
        console, buf = _make_console()
        report = _make_report()
        format_text_report(report, console)
        output = buf.getvalue()

        assert "N/A" in output

    def test_acceptance_criteria_tag_in_output(self):
        console, buf = _make_console()
        report = _make_report()
        format_text_report(report, console)
        output = buf.getvalue()

        assert "PASS" in output
        assert ">=80" in output

    def test_failure_summary_displayed(self):
        sub = SubScore(
            name="Parse Rate",
            key="parse_rate",
            weight=1.0,
            score=70.0,
            failure_summary={"windows_event_security": {"parse_error": 3, "missing_field": 1}},
        )
        dim = DimensionScore(number=1, name="Fidelity", weight=1.0, score=70.0, sub_scores=[sub])
        report = _make_report(dimensions=[dim])
        console, buf = _make_console()
        format_text_report(report, console)
        output = buf.getvalue()

        assert "windows_event_security" in output
        assert "parse error" in output

    def test_verbose_sample_failures(self):
        sub = SubScore(
            name="Parse Rate",
            key="parse_rate",
            weight=1.0,
            score=70.0,
            sample_failures=["bad record 1", "bad [record] 2"],
        )
        dim = DimensionScore(number=1, name="Fidelity", weight=1.0, score=70.0, sub_scores=[sub])
        report = _make_report(dimensions=[dim])
        console, buf = _make_console()
        format_text_report(report, console, verbose=True)
        output = buf.getvalue()

        assert "Sample failures" in output
        assert "bad record 1" in output

    def test_verbose_sample_failures_truncation(self):
        sub = SubScore(
            name="Parse Rate",
            key="parse_rate",
            weight=1.0,
            score=70.0,
            sample_failures=[f"failure {i}" for i in range(30)],
        )
        dim = DimensionScore(number=1, name="Fidelity", weight=1.0, score=70.0, sub_scores=[sub])
        report = _make_report(dimensions=[dim])
        console, buf = _make_console()
        format_text_report(report, console, verbose=True)
        output = buf.getvalue()

        assert "... and 10 more" in output


class TestFormatJsonReport:
    def test_valid_json_output(self):
        import json

        report = _make_report()
        result = format_json_report(report)
        data = json.loads(result)

        assert data["scenario_name"] == "test-scenario"
        assert data["total_records"] == 500
        assert data["overall_score"] == 85.0
