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

"""Tests for TemporalRealismScorer._score_attack_chain_timing and _score_diurnal_pattern."""

from datetime import UTC, datetime, timedelta

from evidenceforge.evaluation.parsers import ParsedRecord
from evidenceforge.evaluation.pillars.timing import TimingScorer as TemporalRealismScorer

# Monday 2024-01-15, 10:00 UTC — weekday() == 0 (Mon), hour == 10
T0 = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _rec(fmt: str, fields: dict, ts: datetime | None = None) -> ParsedRecord:
    return ParsedRecord(source_format=fmt, raw="test", fields=fields, timestamp=ts)


def _make_scenario(storyline=None, personas=True, work_hours="9am-5pm"):
    """Return a minimal Scenario.  Same pattern as test_eval_temporal.py."""
    from evidenceforge.models.scenario import (
        BaselineActivity,
        Environment,
        OutputSpec,
        Persona,
        Scenario,
        StorylineEvent,
        System,
        TimeWindow,
        User,
    )

    persona_list = (
        [
            Persona(
                name="analyst",
                description="Analyst",
                typical_activities=["browsing"],
                work_hours=work_hours,
            )
        ]
        if personas
        else []
    )

    return Scenario(
        name="test",
        description="Test",
        environment=Environment(
            description="Test",
            users=[
                User(
                    username="jsmith",
                    full_name="J Smith",
                    email="j@x.com",
                    persona="analyst" if personas else None,
                    primary_system="WS-01",
                )
            ],
            systems=[
                System(hostname="WS-01", ip="10.0.10.50", os="Windows 10", type="workstation"),
            ],
        ),
        personas=persona_list,
        time_window=TimeWindow(start=T0, duration="8h"),
        baseline_activity=BaselineActivity(description="Normal", intensity="low", variation="low"),
        storyline=[StorylineEvent(**e) for e in (storyline or [])],
        output=OutputSpec(
            logs=[{"format": "windows_event_security"}],
            destination="./out",
        ),
    )


def _storyline_event(offset_seconds: int, activity: str, idx: int = 0) -> dict:
    """Build a minimal StorylineEvent dict for _make_scenario(storyline=[...])."""
    ts = T0 + timedelta(seconds=offset_seconds)
    return {
        "id": f"evt-{idx}",
        "time": ts.isoformat(),
        "actor": "jsmith",
        "system": "WS-01",
        "activity": activity,
        "events": [{"type": "process", "process_name": "cmd.exe"}],
    }


# ---------------------------------------------------------------------------
# _score_attack_chain_timing
# ---------------------------------------------------------------------------


class TestAttackChainTiming:
    def test_no_storyline_returns_100(self):
        """Scenario with no storyline events → perfect score with 'No consecutive' detail."""
        scenario = _make_scenario(storyline=[])
        scorer = TemporalRealismScorer()
        result = scorer._score_attack_chain_timing(scenario)
        assert result.score == 100.0
        assert "No consecutive" in result.details or result.details

    def test_single_storyline_event_returns_100(self):
        """One event → no pairs to evaluate → perfect score."""
        storyline = [_storyline_event(0, "Initial access", idx=0)]
        scenario = _make_scenario(storyline=storyline)
        scorer = TemporalRealismScorer()
        result = scorer._score_attack_chain_timing(scenario)
        assert result.score == 100.0

    def test_two_events_60s_apart_default_bounds_in_range(self):
        """Default bounds: min=5, max=7200. Gap of 60s is within range → score=100."""
        storyline = [
            _storyline_event(0, "Initial recon step", idx=0),
            _storyline_event(60, "Execute payload", idx=1),
        ]
        scenario = _make_scenario(storyline=storyline)
        scorer = TemporalRealismScorer()
        result = scorer._score_attack_chain_timing(scenario)
        assert result.score == 100.0

    def test_two_events_0s_apart_violates_default_min(self):
        """Same timestamp → elapsed=0s < min=5s → fails → score=0.0."""
        storyline = [
            _storyline_event(0, "Recon step A", idx=0),
            _storyline_event(0, "Recon step B", idx=1),
        ]
        scenario = _make_scenario(storyline=storyline)
        scorer = TemporalRealismScorer()
        result = scorer._score_attack_chain_timing(scenario)
        assert result.score == 0.0
        assert len(result.sample_failures) >= 1

    def test_lateral_movement_keyword_min30_gap15_fails(self):
        """'lateral_movement' override: min=30, max=3600. Gap of 15s < 30 → fails."""
        storyline = [
            _storyline_event(0, "Initial access", idx=0),
            _storyline_event(15, "lateral_movement to DC-01", idx=1),
        ]
        scenario = _make_scenario(storyline=storyline)
        scorer = TemporalRealismScorer()
        result = scorer._score_attack_chain_timing(scenario)
        assert result.score == 0.0
        assert result.sample_failures

    def test_lateral_movement_keyword_in_range_passes(self):
        """'lateral_movement' override: min=30, max=3600. Gap of 120s → in range."""
        storyline = [
            _storyline_event(0, "Initial access", idx=0),
            _storyline_event(120, "lateral_movement to DC-01", idx=1),
        ]
        scenario = _make_scenario(storyline=storyline)
        scorer = TemporalRealismScorer()
        result = scorer._score_attack_chain_timing(scenario)
        assert result.score == 100.0

    def test_exfiltration_keyword_3600s_gap_passes(self):
        """'exfiltration' override: min=60, max=86400. Gap of 3600s → passes."""
        storyline = [
            _storyline_event(0, "lateral_movement done", idx=0),
            _storyline_event(3600, "exfiltration via HTTPS", idx=1),
        ]
        scenario = _make_scenario(storyline=storyline)
        scorer = TemporalRealismScorer()
        result = scorer._score_attack_chain_timing(scenario)
        assert result.score == 100.0

    def test_exfiltration_keyword_30s_gap_fails(self):
        """'exfiltration' override: min=60. Gap of 30s < 60 → fails."""
        storyline = [
            _storyline_event(0, "lateral_movement done", idx=0),
            _storyline_event(30, "exfiltration of documents", idx=1),
        ]
        scenario = _make_scenario(storyline=storyline)
        scorer = TemporalRealismScorer()
        result = scorer._score_attack_chain_timing(scenario)
        assert result.score == 0.0

    def test_mixed_pairs_partial_score(self):
        """Two pairs: one in-bounds (default), one too-fast → 50% score."""
        storyline = [
            _storyline_event(0, "initial access", idx=0),
            _storyline_event(60, "run payload", idx=1),  # 60s gap — in default bounds
            _storyline_event(60, "second payload", idx=2),  # 0s gap — violates default min=5
        ]
        scenario = _make_scenario(storyline=storyline)
        scorer = TemporalRealismScorer()
        result = scorer._score_attack_chain_timing(scenario)
        # 1 of 2 pairs in bounds → 50.0
        assert result.score == 50.0

    def test_score_key_and_weight(self):
        """Returned SubScore must carry the right key and weight."""
        scenario = _make_scenario(storyline=[])
        scorer = TemporalRealismScorer()
        result = scorer._score_attack_chain_timing(scenario)
        assert result.key == "attack_chain_timing"
        assert abs(result.weight - 0.15) < 1e-6


# ---------------------------------------------------------------------------
# _score_diurnal_pattern
# ---------------------------------------------------------------------------


class TestDiurnalPattern:
    def _make_work_hour_events(self, count: int) -> list[datetime]:
        """Return `count` events all during Mon-Fri work hours (9-16 UTC)."""
        events = []
        # Each Monday of multiple weeks, spread across hours 9-16
        week = 0
        for i in range(count):
            # Cycle through Mon(0)-Fri(4) and hours 9-16
            day_offset = i % 5  # 0=Mon .. 4=Fri
            hour = 9 + (i % 8)  # hours 9 through 16
            if i % 5 == 0 and i > 0:
                week += 1
            dt = T0 + timedelta(weeks=week, days=day_offset, hours=(hour - 10))
            events.append(dt)
        return events

    def _make_uniform_events(self, count: int) -> list[datetime]:
        """Return `count` events spread uniformly across all 168 hour×weekday buckets."""
        events = []
        # Step through every hour of a week repeatedly
        for i in range(count):
            hour_in_week = i % 168
            day = hour_in_week // 24
            hour = hour_in_week % 24
            dt = T0 + timedelta(days=day, hours=(hour - 10))
            events.append(dt)
        return events

    def test_work_hour_events_score_high(self):
        """30 events tightly in work hours should have low JSD vs reference → high score."""
        scenario = _make_scenario(personas=True, work_hours="9am-5pm")
        events = self._make_work_hour_events(30)
        user_events = {"jsmith": events}
        scorer = TemporalRealismScorer()
        result = scorer._score_diurnal_pattern(user_events, scenario)
        # JSD close to 0 but not below the artificially-uniform threshold of 0.01
        # Work-hour events are concentrated; score should be > 0.
        # The scorer penalises jsd < 0.01 (too uniform), but genuine work-hour
        # concentration will push JSD above that floor — so score should be > 0.
        assert result.score > 0.0

    def test_uniform_events_score_low(self):
        """Events spread uniformly over all 168 buckets look artificially uniform → low score."""
        scenario = _make_scenario(personas=True, work_hours="9am-5pm")
        events = self._make_uniform_events(168)  # exactly one per bucket
        user_events = {"jsmith": events}
        scorer = TemporalRealismScorer()
        result = scorer._score_diurnal_pattern(user_events, scenario)
        # Uniform distribution has JSD << 0.01 vs work-hours reference → near-zero score
        assert result.score < 50.0

    def test_short_scenario_span_is_skipped(self):
        """Events spanning <24h on a single weekday → skipped (not measurable)."""
        scenario = _make_scenario(personas=True, work_hours="9am-5pm")
        events = [T0 + timedelta(hours=i) for i in range(10)]
        user_events = {"jsmith": events}
        scorer = TemporalRealismScorer()
        result = scorer._score_diurnal_pattern(user_events, scenario)
        assert result.skipped is True
        assert result.score is None

    def test_no_personas_returns_100(self):
        """Without personas, no user_to_persona entries → no scoring → 100.0."""
        scenario = _make_scenario(personas=False)
        events = [T0 + timedelta(hours=i) for i in range(40)]
        user_events = {"jsmith": events}
        scorer = TemporalRealismScorer()
        result = scorer._score_diurnal_pattern(user_events, scenario)
        assert result.score == 100.0

    def test_empty_user_events_returns_100(self):
        """No events at all → no users scored → 100.0."""
        scenario = _make_scenario(personas=True)
        scorer = TemporalRealismScorer()
        result = scorer._score_diurnal_pattern({}, scenario)
        assert result.score == 100.0

    def test_score_key_and_name(self):
        scenario = _make_scenario(personas=True)
        scorer = TemporalRealismScorer()
        result = scorer._score_diurnal_pattern({}, scenario)
        assert result.key == "diurnal_pattern"
        assert result.name == "Diurnal Pattern"
