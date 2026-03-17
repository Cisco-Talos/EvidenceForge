"""Tests for Dimension 3: Background Noise Realism scoring."""

from collections import Counter
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from evidenceforge.evaluation.anomaly import detect_anomalies
from evidenceforge.evaluation.dimensions.noise_realism import (
    NoiseRealismScorer,
    _extract_event_type,
)
from evidenceforge.evaluation.parsers import ParsedRecord

T0 = datetime(2024, 1, 15, 10, 0, 0, tzinfo=timezone.utc)


def _record(fmt: str, fields: dict, ts: datetime | None = None) -> ParsedRecord:
    return ParsedRecord(source_format=fmt, raw="test", fields=fields, timestamp=ts)


def _make_scenario(intensity="high", storyline_count=5):
    from evidenceforge.models.scenario import (
        BaselineActivity, Environment, OutputSpec,
        StorylineEvent, System, TimeWindow, User,
    )
    from evidenceforge.models.scenario import Scenario

    storyline = [
        StorylineEvent(
            time=f"+{i+1}h", actor="jsmith", system="WS-01",
            activity="Execute command",
        )
        for i in range(storyline_count)
    ]

    return Scenario(
        name="test",
        description="Test",
        environment=Environment(
            description="Test",
            users=[
                User(username="jsmith", full_name="J", email="j@x.com",
                     persona="", primary_system="WS-01"),
                User(username="admin", full_name="A", email="a@x.com",
                     persona="", primary_system="SRV-01"),
            ],
            systems=[
                System(hostname="WS-01", ip="10.0.10.50", os="Windows 10", type="workstation"),
                System(hostname="SRV-01", ip="10.0.20.10", os="Linux Ubuntu", type="server"),
            ],
        ),
        time_window=TimeWindow(start=T0, duration="8h"),
        baseline_activity=BaselineActivity(
            description="Normal", intensity=intensity, variation="low",
        ),
        storyline=storyline if storyline_count > 0 else [],
        output=OutputSpec(
            logs=[{"format": "windows_event_security"}, {"format": "ecar"}],
            destination="./out",
        ),
    )


class TestVolumeAdequacy:
    def test_good_ratio(self):
        """High noise-to-signal ratio should score well."""
        scenario = _make_scenario(intensity="high", storyline_count=2)
        # 2 storyline events, 20000+ noise records → ratio ~10000:1
        records = {"windows_event_security": [
            _record("windows_event_security", {"EventID": 4624}, ts=T0 + timedelta(seconds=i))
            for i in range(20000)
        ]}
        scorer = NoiseRealismScorer()
        result = scorer._score_volume_adequacy(records, scenario)
        assert result.score >= 90.0

    def test_too_little_noise(self):
        """Very low noise-to-signal ratio should score poorly."""
        scenario = _make_scenario(intensity="high", storyline_count=10)
        # 10 storyline + only 50 records → ratio ~4:1 (target 10000:1)
        records = {"windows_event_security": [
            _record("windows_event_security", {"EventID": 4624}, ts=T0 + timedelta(seconds=i))
            for i in range(50)
        ]}
        scorer = NoiseRealismScorer()
        result = scorer._score_volume_adequacy(records, scenario)
        assert result.score < 10.0

    def test_no_storyline(self):
        scenario = _make_scenario(storyline_count=0)
        records = {"windows_event_security": [
            _record("windows_event_security", {"EventID": 4624}, ts=T0)
        ]}
        scorer = NoiseRealismScorer()
        result = scorer._score_volume_adequacy(records, scenario)
        assert result.score == 100.0


class TestUserDiversity:
    def test_diverse_users(self):
        """Users with different event-type distributions should score well."""
        records = {
            "windows_event_security": [
                # jsmith: mostly logons
                _record("windows_event_security", {"TargetUserName": "jsmith", "EventID": 4624}, ts=T0 + timedelta(seconds=i))
                for i in range(20)
            ] + [
                # admin: mostly processes
                _record("windows_event_security", {"TargetUserName": "admin", "EventID": 4688}, ts=T0 + timedelta(seconds=i))
                for i in range(20)
            ],
        }
        scorer = NoiseRealismScorer()
        result = scorer._score_user_diversity(records)
        # Different event types → low similarity → good score
        assert result.score >= 50.0

    def test_identical_users(self):
        """Users with identical event-type distributions should score poorly."""
        records = {
            "windows_event_security": [
                _record("windows_event_security", {"TargetUserName": "jsmith", "EventID": 4624}, ts=T0 + timedelta(seconds=i))
                for i in range(20)
            ] + [
                _record("windows_event_security", {"TargetUserName": "admin", "EventID": 4624}, ts=T0 + timedelta(seconds=i))
                for i in range(20)
            ],
        }
        scorer = NoiseRealismScorer()
        result = scorer._score_user_diversity(records)
        # Same event types → high similarity → low score
        assert result.score < 50.0


class TestActivityPlausibility:
    def test_correct_os_content(self):
        """Windows paths in Windows events should be plausible."""
        scenario = _make_scenario()
        records = {
            "windows_event_security": [
                _record("windows_event_security", {
                    "Computer": "WS-01",
                    "EventID": 4688,
                    "NewProcessName": "C:\\Windows\\System32\\cmd.exe",
                }, ts=T0),
            ],
        }
        scorer = NoiseRealismScorer()
        result = scorer._score_activity_plausibility(records, scenario)
        assert result.score == 100.0

    def test_wrong_os_paths(self):
        """Linux paths in Windows events should be implausible."""
        scenario = _make_scenario()
        records = {
            "windows_event_security": [
                _record("windows_event_security", {
                    "Computer": "WS-01",
                    "EventID": 4688,
                    "NewProcessName": "/usr/bin/python3",
                }, ts=T0),
            ],
        }
        scorer = NoiseRealismScorer()
        result = scorer._score_activity_plausibility(records, scenario)
        assert result.score < 100.0


class TestAnomalyRate:
    def test_target_range(self):
        """3% anomaly rate should score 100 (in 1-5% target)."""
        scenario = _make_scenario()
        # Create records where ~3% have failed operations
        records = {
            "web_access": (
                [_record("web_access", {"status_code": 200}, ts=T0 + timedelta(seconds=i)) for i in range(97)]
                + [_record("web_access", {"status_code": 403}, ts=T0 + timedelta(seconds=i + 97)) for i in range(3)]
            ),
        }
        scorer = NoiseRealismScorer()
        result = scorer._score_anomaly_rate(records, scenario)
        # Rate should be near 3% → in target range
        assert result.score >= 80.0

    def test_too_clean(self):
        """0% anomaly rate (all 200s) should score 0."""
        scenario = _make_scenario()
        records = {
            "web_access": [
                _record("web_access", {"status_code": 200}, ts=T0 + timedelta(seconds=i))
                for i in range(100)
            ],
        }
        scorer = NoiseRealismScorer()
        result = scorer._score_anomaly_rate(records, scenario)
        assert result.score == 0.0


class TestEventTypeExtraction:
    def test_windows(self):
        r = _record("windows_event_security", {"EventID": 4634})
        assert _extract_event_type(r) == "win_4634"

    def test_windows_4624_by_logon_type(self):
        r = _record("windows_event_security", {"EventID": 4624, "LogonType": 3})
        assert _extract_event_type(r) == "win_4624_type3"

    def test_windows_4688_categorized(self):
        r = _record("windows_event_security", {
            "EventID": 4688,
            "NewProcessName": r"C:\Program Files\Google\Chrome\Application\chrome.exe",
        })
        assert _extract_event_type(r) == "win_4688_browser"

    def test_ecar(self):
        r = _record("ecar", {"object": "PROCESS", "action": "CREATE", "image_path": "/usr/bin/git"})
        assert _extract_event_type(r) == "ecar_PROCESS_CREATE_dev_tool"

    def test_ecar_non_process(self):
        r = _record("ecar", {"object": "FILE", "action": "CREATE"})
        assert _extract_event_type(r) == "ecar_FILE_CREATE"

    def test_bash(self):
        r = _record("bash_history", {"command": "ls -la /tmp"})
        assert _extract_event_type(r) == "bash_ls"


class TestEndToEnd:
    def test_returns_full_dimension_score(self):
        scenario = _make_scenario()
        records = {
            "windows_event_security": [
                _record("windows_event_security", {
                    "Computer": "WS-01", "EventID": 4624, "TargetUserName": "jsmith",
                }, ts=T0 + timedelta(minutes=i))
                for i in range(20)
            ],
        }
        scorer = NoiseRealismScorer()
        result = scorer.score(records, scenario)
        assert result.number == 3
        assert result.name == "Background Noise Realism"
        assert result.weight == 0.25
        assert result.score is not None
        assert len(result.sub_scores) == 4
