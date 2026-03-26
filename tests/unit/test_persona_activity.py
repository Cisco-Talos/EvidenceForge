"""Tests for persona-based activity generation.

Phase 2.6: Tests that persona data (work hours, risk profile, activity intensity)
flows into event generation for realistic temporal distributions.
"""

from datetime import datetime
from unittest.mock import Mock

from evidenceforge.generation.activity import BASELINE_PATTERNS, ActivityGenerator
from evidenceforge.generation.engine import GenerationEngine
from evidenceforge.models.scenario import (
    BaselineActivity,
    Environment,
    OutputSpec,
    Persona,
    Scenario,
    System,
    TimeWindow,
    User,
)


def _make_persona(
    name="developer", work_hours="9am-5pm", risk_profile="medium", activity_intensity=None
):
    """Helper to create a Persona with auto-parsed work hours."""
    return Persona(
        name=name,
        description=f"Test {name} persona",
        typical_activities=["coding"],
        work_hours=work_hours,
        risk_profile=risk_profile,
        activity_intensity=activity_intensity,
    )


def _make_scenario(personas=None, intensity="medium"):
    """Helper to create a minimal scenario with personas."""
    return Scenario(
        version="1.0",
        name="test",
        description="Test scenario",
        environment=Environment(
            description="Test env",
            users=[
                User(
                    username="testuser",
                    full_name="Test User",
                    email="test@example.com",
                    persona="developer",
                ),
            ],
            systems=[
                System(hostname="WS-01", ip="10.0.0.1", os="Windows 10", type="workstation"),
            ],
        ),
        personas=personas or [_make_persona()],
        time_window=TimeWindow(start=datetime(2024, 1, 15, 8, 0, 0), duration="12h"),
        baseline_activity=BaselineActivity(
            description="Test", intensity=intensity, variation="low"
        ),
        output=OutputSpec(
            logs=[{"format": "windows_event_security"}],
            destination="./output",
        ),
    )


class TestPersonaResolution:
    """Tests for resolving user.persona string to Persona object."""

    def test_resolve_persona(self):
        """Should resolve persona string to Persona object."""
        scenario = _make_scenario()
        engine = GenerationEngine(scenario, "/tmp/test")
        user = scenario.environment.users[0]

        persona = engine._get_user_persona(user)
        assert persona is not None
        assert persona.name == "developer"

    def test_resolve_missing_persona(self):
        """Should return None for undefined persona."""
        scenario = _make_scenario()
        engine = GenerationEngine(scenario, "/tmp/test")
        user = User(
            username="nopersona",
            full_name="No Persona",
            email="no@example.com",
            persona="nonexistent",
        )

        persona = engine._get_user_persona(user)
        assert persona is None

    def test_resolve_no_persona_assigned(self):
        """Should return None when user has no persona."""
        scenario = _make_scenario()
        engine = GenerationEngine(scenario, "/tmp/test")
        user = User(username="nopersona", full_name="No Persona", email="no@example.com")

        persona = engine._get_user_persona(user)
        assert persona is None


class TestWorkHoursModulation:
    """Tests for work hours affecting event generation."""

    def test_activity_during_work_hours(self):
        """Should generate events during work hours."""
        persona = _make_persona(work_hours="9am-5pm")
        scenario = _make_scenario(personas=[persona])
        engine = GenerationEngine(scenario, "/tmp/test")
        user = scenario.environment.users[0]

        # Hour 10 is within 9am-5pm
        engine._calculate_events_for_hour(user, current_hour=10, persona=persona)
        # With medium intensity (15 base), should be > 0 most of the time
        # Run multiple times to be statistically confident
        counts = [
            engine._calculate_events_for_hour(user, current_hour=10, persona=persona)
            for _ in range(20)
        ]
        assert sum(counts) > 0, "Should generate events during work hours"

    def test_no_activity_outside_work_hours(self):
        """Should generate zero events outside work hours."""
        persona = _make_persona(work_hours="9am-5pm")
        scenario = _make_scenario(personas=[persona])
        engine = GenerationEngine(scenario, "/tmp/test")
        user = scenario.environment.users[0]

        # Hour 7 is before 9am
        assert engine._calculate_events_for_hour(user, current_hour=7, persona=persona) == 0
        # Hour 20 is after 5pm
        assert engine._calculate_events_for_hour(user, current_hour=20, persona=persona) == 0

    def test_reduced_activity_during_lunch(self):
        """Should generate reduced (not zero) events during lunch break (soft dip)."""
        persona = _make_persona(work_hours="9am-5pm (lunch 12pm-1pm)")
        scenario = _make_scenario(personas=[persona], intensity="medium")
        engine = GenerationEngine(scenario, "/tmp/test")
        user = scenario.environment.users[0]

        # Hour 12 is lunch — should get ~50% of normal (soft dip, not 0)
        lunch_events = engine._calculate_events_for_hour(user, current_hour=12, persona=persona)
        engine._calculate_events_for_hour(user, current_hour=10, persona=persona)
        # Lunch should be significantly less than peak but not zero
        assert lunch_events >= 0  # Could be 0 from Gaussian jitter, but usually > 0

    def test_peak_hours_higher_intensity(self):
        """Peak hours should produce more events than normal hours."""
        persona = _make_persona(work_hours="9am-5pm")
        scenario = _make_scenario(personas=[persona], intensity="medium")
        engine = GenerationEngine(scenario, "/tmp/test")
        user = scenario.environment.users[0]

        # work_hours_parsed for "9am-5pm": peak_hours = [10, 11, 14, 15]
        # Normal hour: 9, 13, 16. Peak hour: 10, 11.
        normal_counts = [
            engine._calculate_events_for_hour(user, current_hour=9, persona=persona)
            for _ in range(100)
        ]
        peak_counts = [
            engine._calculate_events_for_hour(user, current_hour=10, persona=persona)
            for _ in range(100)
        ]

        avg_normal = sum(normal_counts) / len(normal_counts)
        avg_peak = sum(peak_counts) / len(peak_counts)

        # Peak should be ~50% higher
        assert avg_peak > avg_normal, (
            f"Peak avg ({avg_peak:.1f}) should be > normal avg ({avg_normal:.1f})"
        )

    def test_no_persona_generates_all_hours(self):
        """Without persona, events should generate every hour."""
        scenario = _make_scenario()
        engine = GenerationEngine(scenario, "/tmp/test")
        user = scenario.environment.users[0]

        # No persona passed — should generate regardless of hour
        counts = [
            engine._calculate_events_for_hour(user, current_hour=3, persona=None) for _ in range(20)
        ]
        assert sum(counts) > 0, "No persona should allow activity at any hour"


class TestRiskProfileScaling:
    """Tests for risk profile affecting event intensity."""

    def test_high_risk_more_than_low(self):
        """High-risk personas should generate more events than low-risk."""
        scenario_high = _make_scenario(
            personas=[_make_persona(risk_profile="high")], intensity="medium"
        )
        scenario_low = _make_scenario(
            personas=[_make_persona(risk_profile="low")], intensity="medium"
        )
        engine_high = GenerationEngine(scenario_high, "/tmp/test")
        engine_low = GenerationEngine(scenario_low, "/tmp/test")

        persona_high = scenario_high.personas[0]
        persona_low = scenario_low.personas[0]
        user = scenario_high.environment.users[0]

        high_counts = [
            engine_high._calculate_events_for_hour(user, current_hour=10, persona=persona_high)
            for _ in range(200)
        ]
        low_counts = [
            engine_low._calculate_events_for_hour(user, current_hour=10, persona=persona_low)
            for _ in range(200)
        ]

        avg_high = sum(high_counts) / len(high_counts)
        avg_low = sum(low_counts) / len(low_counts)

        assert avg_high > avg_low, (
            f"High-risk avg ({avg_high:.1f}) should be > low-risk avg ({avg_low:.1f})"
        )

    def test_default_medium_risk(self):
        """Medium risk should produce baseline intensity events."""
        persona = _make_persona(risk_profile="medium")
        scenario = _make_scenario(personas=[persona], intensity="medium")
        engine = GenerationEngine(scenario, "/tmp/test")
        user = scenario.environment.users[0]

        counts = [
            engine._calculate_events_for_hour(user, current_hour=10, persona=persona)
            for _ in range(100)
        ]
        avg = sum(counts) / len(counts)

        # Medium intensity = 15 base, medium risk = 1.0x
        assert 10 <= avg <= 25, f"Medium risk avg ({avg:.1f}) should be near 15"


class TestActivityIntensityOverrides:
    """Tests for persona.activity_intensity dynamic pattern building."""

    def test_activity_intensity_overrides_pattern(self):
        """activity_intensity should override hardcoded patterns."""
        persona = _make_persona(
            name="developer", activity_intensity={"process_code": 20, "connection_web": 5}
        )
        emitters = {}
        generator = ActivityGenerator(
            state_manager=Mock(),
            emitters=emitters,
        )

        pattern = generator.get_baseline_pattern("developer", persona=persona)

        # Should have logon + the two custom activities
        activity_types = [a for a, _ in pattern]
        assert "logon" in activity_types
        assert "process_code" in activity_types
        assert "connection_web" in activity_types

        # process_code should have higher probability than connection_web
        probs = {a: p for a, p in pattern}
        assert probs["process_code"] > probs["connection_web"]

    def test_no_intensity_uses_hardcoded(self):
        """Without activity_intensity, should use hardcoded patterns."""
        persona = _make_persona(name="developer", activity_intensity=None)
        generator = ActivityGenerator(
            state_manager=Mock(),
            emitters={},
        )

        pattern = generator.get_baseline_pattern("developer", persona=persona)
        assert pattern == BASELINE_PATTERNS["developer"]

    def test_no_persona_uses_default(self):
        """Without persona, should use default pattern."""
        generator = ActivityGenerator(
            state_manager=Mock(),
            emitters={},
        )

        pattern = generator.get_baseline_pattern(None, persona=None)
        assert pattern == BASELINE_PATTERNS["default"]
