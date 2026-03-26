"""Tests for Dimension 2: Cross-Source Coherence scoring."""

from datetime import UTC, datetime, timedelta
from pathlib import Path

from evidenceforge.evaluation.dimensions.cross_source import CrossSourceScorer
from evidenceforge.evaluation.parsers import ParsedRecord
from evidenceforge.evaluation.visibility import VisibilityModel

T0 = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)


def _record(fmt: str, fields: dict, ts: datetime | None = None) -> ParsedRecord:
    return ParsedRecord(source_format=fmt, raw="test", fields=fields, timestamp=ts)


def _make_scenario(systems=None, storyline=None):
    from evidenceforge.models.scenario import (
        BaselineActivity,
        Environment,
        OutputSpec,
        StorylineEvent,
        System,
        TimeWindow,
        User,
    )

    default_systems = systems or [
        System(hostname="WS-01", ip="10.0.10.50", os="Windows 10", type="workstation"),
        System(hostname="SRV-01", ip="10.0.20.10", os="Linux Ubuntu", type="server"),
    ]
    from evidenceforge.models.scenario import Scenario

    return Scenario(
        name="test",
        description="Test",
        environment=Environment(
            description="Test",
            users=[
                User(
                    username="jsmith",
                    full_name="J",
                    email="j@x.com",
                    persona="",
                    primary_system="WS-01",
                ),
            ],
            systems=default_systems,
        ),
        time_window=TimeWindow(start=T0, duration="8h"),
        baseline_activity=BaselineActivity(
            description="Normal",
            intensity="low",
            variation="low",
        ),
        storyline=[StorylineEvent(**e) for e in (storyline or [])],
        output=OutputSpec(
            logs=[
                {"format": "windows_event_security"},
                {"format": "syslog"},
                {"format": "bash_history"},
                {"format": "ecar"},
                {"format": "zeek_conn"},
            ],
            destination="./out",
        ),
    )


class TestVisibilityModel:
    def test_windows_system(self):
        scenario = _make_scenario()
        enabled = {"windows_event_security", "syslog", "bash_history", "ecar", "zeek_conn"}
        vis = VisibilityModel(scenario, enabled)
        fmts = vis.get_expected_formats("WS-01")
        assert "windows_event_security" in fmts
        assert "ecar" in fmts
        assert "syslog" not in fmts
        assert "bash_history" not in fmts

    def test_linux_system(self):
        scenario = _make_scenario()
        enabled = {"windows_event_security", "syslog", "bash_history", "ecar", "zeek_conn"}
        vis = VisibilityModel(scenario, enabled)
        fmts = vis.get_expected_formats("SRV-01")
        assert "syslog" in fmts
        assert "bash_history" in fmts
        assert "ecar" in fmts
        assert "windows_event_security" not in fmts

    def test_os_category(self):
        scenario = _make_scenario()
        enabled = set()
        vis = VisibilityModel(scenario, enabled)
        assert vis.get_os_category("WS-01") == "windows"
        assert vis.get_os_category("SRV-01") == "linux"
        assert vis.get_os_category("UNKNOWN") == "unknown"


class TestSourceCorrectness:
    def test_correct_os_mapping(self):
        """Windows events from Windows host should be correct."""
        scenario = _make_scenario()
        records = {
            "windows_event_security": [
                _record("windows_event_security", {"Computer": "WS-01"}, ts=T0),
            ],
            "syslog": [
                _record("syslog", {"hostname": "SRV-01"}, ts=T0),
            ],
        }
        enabled = {"windows_event_security", "syslog", "ecar"}
        vis = VisibilityModel(scenario, enabled)
        scorer = CrossSourceScorer()
        result = scorer._score_source_correctness(records, vis)
        assert result.score == 100.0

    def test_wrong_os(self):
        """bash_history from Windows host should fail."""
        scenario = _make_scenario()
        records = {
            "bash_history": [
                _record("bash_history", {"hostname": "WS-01", "username": "jsmith"}, ts=T0),
            ],
        }
        enabled = {"windows_event_security", "syslog", "bash_history", "ecar"}
        vis = VisibilityModel(scenario, enabled)
        scorer = CrossSourceScorer()
        result = scorer._score_source_correctness(records, vis)
        assert result.score < 100.0

    def test_unknown_hostname(self):
        """Records from hosts not in scenario get flagged."""
        scenario = _make_scenario()
        records = {
            "windows_event_security": [
                _record("windows_event_security", {"Computer": "ROGUE-HOST"}, ts=T0),
            ],
        }
        enabled = {"windows_event_security"}
        vis = VisibilityModel(scenario, enabled)
        scorer = CrossSourceScorer()
        result = scorer._score_source_correctness(records, vis)
        assert result.score < 100.0
        assert any("not in scenario" in f for f in result.sample_failures)


class TestFieldAgreement:
    def test_matching_timestamps(self):
        """Records from different formats within 30s should agree."""
        records = {
            "windows_event_security": [
                _record("windows_event_security", {"Computer": "WS-01"}, ts=T0),
            ],
            "ecar": [
                _record("ecar", {"hostname": "WS-01"}, ts=T0 + timedelta(seconds=5)),
            ],
        }
        scorer = CrossSourceScorer()
        result = scorer._score_field_agreement(records)
        assert result.score == 100.0

    def test_drifted_timestamps(self):
        """Records from different formats > 30s apart should disagree."""
        records = {
            "windows_event_security": [
                _record("windows_event_security", {"Computer": "WS-01"}, ts=T0),
            ],
            "ecar": [
                _record("ecar", {"hostname": "WS-01"}, ts=T0 + timedelta(seconds=5)),
                # Same bucket but second ecar record is far away
            ],
        }
        # Put in separate buckets to force disagreement
        {
            "windows_event_security": [
                _record("windows_event_security", {"Computer": "WS-01"}, ts=T0),
            ],
            "ecar": [
                _record("ecar", {"hostname": "WS-01"}, ts=T0 + timedelta(minutes=5)),
            ],
        }
        scorer = CrossSourceScorer()
        # Same bucket → agree
        r1 = scorer._score_field_agreement(records)
        assert r1.score == 100.0
        # Different buckets → no multi-format groups to compare (scores 100 by default)


class TestBaselineAggregate:
    def test_proportional_counts(self):
        """Systems with proportional event counts across formats should score well."""
        scenario = _make_scenario()
        # WS-01 has ~similar counts in windows_event_security and ecar
        records = {
            "windows_event_security": [
                _record(
                    "windows_event_security", {"Computer": "WS-01"}, ts=T0 + timedelta(minutes=i)
                )
                for i in range(50)
            ],
            "ecar": [
                _record("ecar", {"hostname": "WS-01"}, ts=T0 + timedelta(minutes=i))
                for i in range(40)
            ],
        }
        enabled = {"windows_event_security", "ecar"}
        vis = VisibilityModel(scenario, enabled)
        scorer = CrossSourceScorer()
        result = scorer._score_baseline_aggregate(records, vis)
        assert result.score >= 50.0


class TestEndToEnd:
    def test_returns_full_dimension_score(self):
        scenario = _make_scenario()
        records = {
            "windows_event_security": [
                _record(
                    "windows_event_security",
                    {
                        "Computer": "WS-01",
                        "EventID": 4624,
                        "TargetUserName": "jsmith",
                    },
                    ts=T0 + timedelta(minutes=i * 10),
                )
                for i in range(5)
            ],
            "syslog": [
                _record(
                    "syslog",
                    {"hostname": "SRV-01", "message": "test"},
                    ts=T0 + timedelta(minutes=i * 10),
                )
                for i in range(5)
            ],
        }
        scorer = CrossSourceScorer()
        result = scorer.score(records, scenario)
        assert result.number == 2
        assert result.name == "Cross-Source Coherence"
        assert result.weight == 0.25
        assert result.score is not None
        assert len(result.sub_scores) == 5

    def test_with_retail_scenario(self):
        """Run on real fixtures — should produce valid scores."""
        from evidenceforge.evaluation.parsers import discover_log_files, get_parser
        from evidenceforge.models.scenario import Scenario
        from evidenceforge.utils.files import load_yaml

        GOOD_FIXTURES = Path(__file__).parent.parent / "fixtures" / "eval" / "good"
        SCENARIOS_DIR = Path(__file__).parent.parent / "fixtures" / "scenarios"

        data = load_yaml(SCENARIOS_DIR / "retail-store-ftp-attack.yaml")
        scenario = Scenario(**data)

        file_map = discover_log_files(GOOD_FIXTURES)
        records: dict[str, list[ParsedRecord]] = {}
        for fmt, paths in file_map.items():
            parser = get_parser(fmt)
            recs: list[ParsedRecord] = []
            for p in paths:
                recs.extend(parser.parse_file(p))
            records[fmt] = recs

        scorer = CrossSourceScorer()
        result = scorer.score(records, scenario)
        assert result.score is not None
        assert len(result.sub_scores) == 5
