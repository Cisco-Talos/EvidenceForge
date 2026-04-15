# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
#
# SPDX-License-Identifier: MIT

"""Tests for Dimension 4: Temporal Realism scoring."""

from datetime import UTC, datetime, timedelta

from evidenceforge.evaluation.dimensions.temporal import (
    TemporalRealismScorer,
    _extract_username,
)
from evidenceforge.evaluation.parsers import ParsedRecord

T0 = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)


def _record(fmt: str, fields: dict, ts: datetime | None = None) -> ParsedRecord:
    return ParsedRecord(source_format=fmt, raw="test", fields=fields, timestamp=ts)


def _make_scenario(
    personas=True,
    storyline=None,
    work_hours="9am-5pm",
):
    """Build a minimal Scenario with optional personas."""
    from evidenceforge.models.scenario import (
        BaselineActivity,
        Environment,
        OutputSpec,
        Persona,
        StorylineEvent,
        System,
        TimeWindow,
        User,
    )

    persona_list = []
    if personas:
        persona_list = [
            Persona(
                name="analyst",
                description="Analyst",
                typical_activities=["browsing", "email"],
                work_hours=work_hours,
            )
        ]

    return __import__("evidenceforge.models.scenario", fromlist=["Scenario"]).Scenario(
        name="test",
        description="Test",
        environment=Environment(
            description="Test",
            users=[
                User(
                    username="jsmith",
                    full_name="J Smith",
                    email="j@x.com",
                    persona="analyst" if personas else "",
                    primary_system="WS-01",
                ),
            ],
            systems=[
                System(hostname="WS-01", ip="10.0.10.50", os="Windows 10", type="workstation"),
            ],
        ),
        personas=persona_list,
        time_window=TimeWindow(start=T0, duration="8h"),
        baseline_activity=BaselineActivity(
            description="Normal",
            intensity="low",
            variation="low",
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
        records = {
            "windows_event_security": [
                _record(
                    "windows_event_security",
                    {"TargetUserName": "jsmith"},
                    ts=T0 + timedelta(hours=h),
                )
                for h in range(0, 6)  # 10am-3pm (work hours)
            ]
            + [
                _record(
                    "windows_event_security",
                    {"TargetUserName": "jsmith"},
                    ts=datetime(2024, 1, 15, 3, 0, 0, tzinfo=UTC),
                ),
            ]
        }
        scorer = TemporalRealismScorer()
        user_events = scorer._group_by_user(records)
        result = scorer._score_work_hours(user_events, scenario)
        # ~86% in work hours → within 80-95% target
        assert result.score >= 50.0

    def test_events_outside_work_hours(self):
        """Events at 3am should score poorly."""
        scenario = _make_scenario(personas=True, work_hours="9am-5pm")
        # All events at 3am UTC (well outside 9-17 UTC work hours)
        records = {
            "windows_event_security": [
                _record(
                    "windows_event_security",
                    {"TargetUserName": "jsmith"},
                    ts=datetime(2024, 1, 15, 3, i, 0, tzinfo=UTC),
                )
                for i in range(10)
            ]
        }
        scorer = TemporalRealismScorer()
        user_events = scorer._group_by_user(records)
        result = scorer._score_work_hours(user_events, scenario)
        assert result.score < 50.0

    def test_no_personas(self):
        """Without personas, work hours check is skipped → score 100."""
        scenario = _make_scenario(personas=False)
        records = {
            "windows_event_security": [
                _record(
                    "windows_event_security",
                    {"TargetUserName": "jsmith"},
                    ts=T0 + timedelta(hours=1),
                )
            ]
        }
        scorer = TemporalRealismScorer()
        user_events = scorer._group_by_user(records)
        result = scorer._score_work_hours(user_events, scenario)
        assert result.score == 100.0


class TestHumanBurstiness:
    def test_bursty_events(self):
        """Events with varied inter-event gaps should score well."""
        # Create bursts: clusters of events with long gaps between
        timestamps = (
            [T0 + timedelta(seconds=i * 2) for i in range(8)]  # burst 1
            + [T0 + timedelta(minutes=20, seconds=i * 3) for i in range(8)]  # burst 2
            + [T0 + timedelta(hours=1, seconds=i * 2) for i in range(8)]  # burst 3
            + [T0 + timedelta(hours=2, seconds=i * 1) for i in range(8)]  # burst 4
            + [T0 + timedelta(hours=3, seconds=i * 4) for i in range(8)]  # burst 5
        )
        records = {
            "windows_event_security": [
                _record("windows_event_security", {"TargetUserName": "jsmith"}, ts=t)
                for t in timestamps
            ]
        }
        scorer = TemporalRealismScorer()
        user_events = scorer._group_by_user(records)
        result = scorer._score_burstiness(user_events)
        # CV should be high (bursty) → good score
        assert result.score > 50.0

    def test_metronomic_events(self):
        """Exactly evenly-spaced events should score poorly (CV near 0)."""
        timestamps = [T0 + timedelta(minutes=i * 5) for i in range(40)]
        records = {
            "windows_event_security": [
                _record("windows_event_security", {"TargetUserName": "jsmith"}, ts=t)
                for t in timestamps
            ]
        }
        scorer = TemporalRealismScorer()
        user_events = scorer._group_by_user(records)
        result = scorer._score_burstiness(user_events)
        # CV near 0 → low score
        assert result.score < 20.0


class TestSystemRegularity:
    def test_periodic_system_events(self):
        """Regular periodic system events should have high autocorrelation."""
        # System events every 60 seconds exactly
        timestamps = [T0 + timedelta(seconds=i * 60) for i in range(30)]
        records = {
            "windows_event_security": [
                _record("windows_event_security", {"TargetUserName": "SYSTEM"}, ts=t)
                for t in timestamps
            ]
        }
        scorer = TemporalRealismScorer()
        result = scorer._score_system_regularity(records)
        assert result.score >= 80.0

    def test_too_few_events(self):
        """Fewer than 20 system events → skip, score 100."""
        records = {
            "windows_event_security": [
                _record(
                    "windows_event_security",
                    {"TargetUserName": "SYSTEM"},
                    ts=T0 + timedelta(seconds=i),
                )
                for i in range(5)
            ]
        }
        scorer = TemporalRealismScorer()
        result = scorer._score_system_regularity(records)
        assert result.score == 100.0


class TestCausalOrdering:
    # Events must be after grace period (default 30m) to be checked.
    # T0 is scenario start, so use T0+1h for test events.
    _AFTER_GRACE = timedelta(hours=1)

    def test_logon_before_process(self):
        """Logon (4624) before process creation (4688) with matching LogonId → correct."""
        base = T0 + self._AFTER_GRACE
        records = {
            "windows_event_security": [
                _record(
                    "windows_event_security",
                    {
                        "EventID": 4624,
                        "TargetLogonId": "0x1a2b3c",
                    },
                    ts=base,
                ),
                _record(
                    "windows_event_security",
                    {
                        "EventID": 4688,
                        "SubjectLogonId": "0x1a2b3c",
                    },
                    ts=base + timedelta(minutes=5),
                ),
            ]
        }
        scenario = _make_scenario()
        scorer = TemporalRealismScorer()
        result = scorer._score_causal_ordering(records, scenario)
        assert result.score == 100.0

    def test_process_before_logon(self):
        """Process creation before logon with matching LogonId → violation."""
        base = T0 + self._AFTER_GRACE
        records = {
            "windows_event_security": [
                _record(
                    "windows_event_security",
                    {
                        "EventID": 4688,
                        "SubjectLogonId": "0x1a2b3c",
                    },
                    ts=base,
                ),
                _record(
                    "windows_event_security",
                    {
                        "EventID": 4624,
                        "TargetLogonId": "0x1a2b3c",
                    },
                    ts=base + timedelta(minutes=5),
                ),
            ]
        }
        scenario = _make_scenario()
        scorer = TemporalRealismScorer()
        result = scorer._score_causal_ordering(records, scenario)
        assert result.score < 100.0

    def test_grace_period_skips_early_events(self):
        """Events within grace period are not checked for causal ordering."""
        records = {
            "windows_event_security": [
                # Process at T0+5m with no preceding logon — within grace period
                _record(
                    "windows_event_security",
                    {
                        "EventID": 4688,
                        "SubjectLogonId": "0x1a2b3c",
                    },
                    ts=T0 + timedelta(minutes=5),
                ),
            ]
        }
        scenario = _make_scenario()
        scorer = TemporalRealismScorer()
        result = scorer._score_causal_ordering(records, scenario)
        # Within grace period → skipped → no pairs → perfect score
        assert result.score == 100.0

    def test_non_string_principal_does_not_raise(self):
        """Malformed principal values should not crash exclusion checks."""
        base = T0 + self._AFTER_GRACE
        records = {
            "windows_event_security": [
                _record(
                    "windows_event_security",
                    {"EventID": 4624, "TargetLogonId": "0x1a2b3c"},
                    ts=base,
                ),
            ],
            "ecar": [
                _record(
                    "ecar",
                    {"event_type": "PROCESS", "action": "CREATE", "principal": {"name": "bad"}},
                    ts=base + timedelta(seconds=10),
                ),
            ],
        }
        scenario = _make_scenario()
        scorer = TemporalRealismScorer()

        result = scorer._score_causal_ordering(records, scenario)

        assert result.score == 100.0


class TestTimingPlausibility:
    def test_reasonable_rate(self):
        """Reasonable event rate → plausible."""
        timestamps = [T0 + timedelta(seconds=i * 10) for i in range(10)]
        records = {
            "windows_event_security": [
                _record("windows_event_security", {"TargetUserName": "jsmith"}, ts=t)
                for t in timestamps
            ]
        }
        scorer = TemporalRealismScorer()
        user_events = scorer._group_by_user(records)
        result = scorer._score_timing_plausibility(user_events, records)
        assert result.score == 100.0

    def test_impossible_rate(self):
        """50 events in 1 second → implausible."""
        timestamps = [T0 + timedelta(milliseconds=i * 20) for i in range(50)]
        records = {
            "windows_event_security": [
                _record("windows_event_security", {"TargetUserName": "jsmith"}, ts=t)
                for t in timestamps
            ]
        }
        scorer = TemporalRealismScorer()
        user_events = scorer._group_by_user(records)
        result = scorer._score_timing_plausibility(user_events, records)
        assert result.score < 100.0


class TestEndToEnd:
    def test_returns_full_dimension_score(self):
        """Full scorer returns DimensionScore with 5 sub-scores."""
        scenario = _make_scenario()
        records = {
            "windows_event_security": [
                _record(
                    "windows_event_security",
                    {"TargetUserName": "jsmith", "EventID": 4624},
                    ts=T0 + timedelta(minutes=i * 10),
                )
                for i in range(10)
            ]
        }
        scorer = TemporalRealismScorer()
        result = scorer.score(records, scenario)
        assert result.number == 4
        assert result.name == "Temporal Realism"
        assert result.weight == 0.15
        assert result.score is not None
        assert len(result.sub_scores) == 5
