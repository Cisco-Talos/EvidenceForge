"""Tests for Dimension 4: Temporal Realism scoring."""

from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from evidenceforge.evaluation.dimensions.temporal import (
    TemporalRealismScorer,
    _extract_username,
)
from evidenceforge.evaluation.parsers import ParsedRecord

T0 = datetime(2024, 1, 15, 10, 0, 0, tzinfo=timezone.utc)


def _record(fmt: str, fields: dict, ts: datetime | None = None) -> ParsedRecord:
    return ParsedRecord(source_format=fmt, raw="test", fields=fields, timestamp=ts)


def _make_scenario(
    personas=True, storyline=None, work_hours="9am-5pm",
):
    """Build a minimal Scenario with optional personas."""
    from evidenceforge.models.scenario import (
        BaselineActivity, Environment, OutputSpec, Persona,
        StorylineEvent, System, TimeWindow, User,
    )
    persona_list = []
    if personas:
        persona_list = [Persona(
            name="analyst", description="Analyst",
            typical_activities=["browsing", "email"],
            work_hours=work_hours,
        )]

    return __import__("evidenceforge.models.scenario", fromlist=["Scenario"]).Scenario(
        name="test",
        description="Test",
        environment=Environment(
            description="Test",
            users=[
                User(username="jsmith", full_name="J Smith", email="j@x.com",
                     persona="analyst" if personas else "", primary_system="WS-01"),
            ],
            systems=[
                System(hostname="WS-01", ip="10.0.10.50", os="Windows 10", type="workstation"),
            ],
        ),
        personas=persona_list,
        time_window=TimeWindow(start=T0, duration="8h"),
        baseline_activity=BaselineActivity(
            description="Normal", intensity="low", variation="low",
        ),
        storyline=[StorylineEvent(**e) for e in (storyline or [])],
        output=OutputSpec(logs=[{"format": "windows_event_security"}], destination="./out"),
    )


class TestUsernameExtraction:
    def test_windows(self):
        r = _record("windows_event_security", {"TargetUserName": "jsmith"})
        assert _extract_username(r) == "jsmith"

    def test_bash_history(self):
        r = _record("bash_history", {"username": "admin"})
        assert _extract_username(r) == "admin"

    def test_ecar(self):
        r = _record("ecar", {"principal": "jsmith"})
        assert _extract_username(r) == "jsmith"

    def test_syslog_for_pattern(self):
        r = _record("syslog", {"message": "Accepted password for jsmith from 10.0.10.50"})
        assert _extract_username(r) == "jsmith"

    def test_no_user(self):
        r = _record("zeek_conn", {"proto": "tcp"})
        assert _extract_username(r) is None


class TestWorkHourDistribution:
    def test_events_in_work_hours(self):
        """~90% of events during 9am-5pm should score well (80-95% target)."""
        scenario = _make_scenario(personas=True, work_hours="9am-5pm")
        # 9 events during work hours + 1 outside (3am) = 90% in work hours
        records = {"windows_event_security": [
            _record("windows_event_security", {"TargetUserName": "jsmith"},
                    ts=T0 + timedelta(hours=h))
            for h in range(0, 6)  # 10am-3pm (work hours)
        ] + [
            _record("windows_event_security", {"TargetUserName": "jsmith"},
                    ts=datetime(2024, 1, 15, 3, 0, 0, tzinfo=timezone.utc)),
        ]}
        scorer = TemporalRealismScorer()
        result = scorer._score_work_hours(records, scenario)
        # ~86% in work hours → within 80-95% target
        assert result.score >= 50.0

    def test_events_outside_work_hours(self):
        """Events at 3am should score poorly."""
        scenario = _make_scenario(personas=True, work_hours="9am-5pm")
        # All events at 3am UTC (well outside 9-17 UTC work hours)
        records = {"windows_event_security": [
            _record("windows_event_security", {"TargetUserName": "jsmith"},
                    ts=datetime(2024, 1, 15, 3, i, 0, tzinfo=timezone.utc))
            for i in range(10)
        ]}
        scorer = TemporalRealismScorer()
        result = scorer._score_work_hours(records, scenario)
        assert result.score < 50.0

    def test_no_personas(self):
        """Without personas, work hours check is skipped → score 100."""
        scenario = _make_scenario(personas=False)
        records = {"windows_event_security": [
            _record("windows_event_security", {"TargetUserName": "jsmith"},
                    ts=T0 + timedelta(hours=1))
        ]}
        scorer = TemporalRealismScorer()
        result = scorer._score_work_hours(records, scenario)
        assert result.score == 100.0


class TestHumanBurstiness:
    def test_bursty_events(self):
        """Events with varied inter-event gaps should score well."""
        # Create bursts: cluster of events, then long gap, then cluster
        timestamps = (
            [T0 + timedelta(seconds=i * 2) for i in range(5)]  # burst 1: 5 events in 10s
            + [T0 + timedelta(minutes=30, seconds=i * 3) for i in range(5)]  # burst 2 after 30m
            + [T0 + timedelta(hours=2, seconds=i * 1) for i in range(5)]  # burst 3 after 2h
        )
        records = {"windows_event_security": [
            _record("windows_event_security", {"TargetUserName": "jsmith"}, ts=t)
            for t in timestamps
        ]}
        scorer = TemporalRealismScorer()
        result = scorer._score_burstiness(records)
        # CV should be high (bursty) → good score
        assert result.score > 50.0

    def test_metronomic_events(self):
        """Exactly evenly-spaced events should score poorly (CV near 0)."""
        timestamps = [T0 + timedelta(minutes=i * 5) for i in range(20)]
        records = {"windows_event_security": [
            _record("windows_event_security", {"TargetUserName": "jsmith"}, ts=t)
            for t in timestamps
        ]}
        scorer = TemporalRealismScorer()
        result = scorer._score_burstiness(records)
        # CV near 0 → low score
        assert result.score < 20.0


class TestSystemRegularity:
    def test_periodic_system_events(self):
        """Regular periodic system events should have high autocorrelation."""
        # System events every 60 seconds exactly
        timestamps = [T0 + timedelta(seconds=i * 60) for i in range(30)]
        records = {"windows_event_security": [
            _record("windows_event_security", {"TargetUserName": "SYSTEM"}, ts=t)
            for t in timestamps
        ]}
        scorer = TemporalRealismScorer()
        result = scorer._score_system_regularity(records)
        assert result.score >= 80.0

    def test_too_few_events(self):
        """Fewer than 20 system events → skip, score 100."""
        records = {"windows_event_security": [
            _record("windows_event_security", {"TargetUserName": "SYSTEM"},
                    ts=T0 + timedelta(seconds=i))
            for i in range(5)
        ]}
        scorer = TemporalRealismScorer()
        result = scorer._score_system_regularity(records)
        assert result.score == 100.0


class TestCausalOrdering:
    def test_logon_before_process(self):
        """Logon (4624) before process creation (4688) with matching LogonId → correct."""
        records = {"windows_event_security": [
            _record("windows_event_security", {
                "EventID": 4624, "TargetLogonId": "0x1a2b3c",
            }, ts=T0),
            _record("windows_event_security", {
                "EventID": 4688, "SubjectLogonId": "0x1a2b3c",
            }, ts=T0 + timedelta(minutes=5)),
        ]}
        scorer = TemporalRealismScorer()
        result = scorer._score_causal_ordering(records)
        assert result.score == 100.0

    def test_process_before_logon(self):
        """Process creation before logon with matching LogonId → violation."""
        records = {"windows_event_security": [
            _record("windows_event_security", {
                "EventID": 4688, "SubjectLogonId": "0x1a2b3c",
            }, ts=T0),
            _record("windows_event_security", {
                "EventID": 4624, "TargetLogonId": "0x1a2b3c",
            }, ts=T0 + timedelta(minutes=5)),
        ]}
        scorer = TemporalRealismScorer()
        result = scorer._score_causal_ordering(records)
        assert result.score < 100.0


class TestTimingPlausibility:
    def test_reasonable_rate(self):
        """Reasonable event rate → plausible."""
        timestamps = [T0 + timedelta(seconds=i * 10) for i in range(10)]
        records = {"windows_event_security": [
            _record("windows_event_security", {"TargetUserName": "jsmith"}, ts=t)
            for t in timestamps
        ]}
        scorer = TemporalRealismScorer()
        result = scorer._score_timing_plausibility(records)
        assert result.score == 100.0

    def test_impossible_rate(self):
        """50 events in 1 second → implausible."""
        timestamps = [T0 + timedelta(milliseconds=i * 20) for i in range(50)]
        records = {"windows_event_security": [
            _record("windows_event_security", {"TargetUserName": "jsmith"}, ts=t)
            for t in timestamps
        ]}
        scorer = TemporalRealismScorer()
        result = scorer._score_timing_plausibility(records)
        assert result.score < 100.0


class TestEndToEnd:
    def test_returns_full_dimension_score(self):
        """Full scorer returns DimensionScore with 5 sub-scores."""
        scenario = _make_scenario()
        records = {"windows_event_security": [
            _record("windows_event_security", {"TargetUserName": "jsmith", "EventID": 4624},
                    ts=T0 + timedelta(minutes=i * 10))
            for i in range(10)
        ]}
        scorer = TemporalRealismScorer()
        result = scorer.score(records, scenario)
        assert result.number == 4
        assert result.name == "Temporal Realism"
        assert result.weight == 0.15
        assert result.score is not None
        assert len(result.sub_scores) == 5
