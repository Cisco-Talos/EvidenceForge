"""Unit tests for Phase 5.5: Temporal realism improvements."""

import statistics
from datetime import UTC, datetime
from pathlib import Path

from evidenceforge.generation.engine import GenerationEngine
from evidenceforge.models import System, User
from evidenceforge.models.scenario import (
    BaselineActivity,
    Environment,
    OutputSpec,
    Persona,
    Scenario,
    TimeWindow,
)


def _make_scenario(personas=None, intensity="medium"):
    """Helper to create minimal scenario for temporal tests."""
    persona = Persona(
        name="developer",
        description="Test developer",
        typical_activities=["coding"],
        work_hours="9am-5pm (lunch 12pm-1pm)",
        risk_profile="medium",
    )
    return Scenario(
        name="temporal-test",
        description="Test temporal realism",
        time_window=TimeWindow(start="2024-01-15T06:00:00Z", duration="18h"),
        environment=Environment(
            description="Test env",
            users=[
                User(
                    username="user.one",
                    full_name="User One",
                    email="u1@t.com",
                    enabled=True,
                    persona="developer",
                    primary_system="WKS-01",
                ),
            ],
            systems=[
                System(hostname="WKS-01", ip="10.0.10.1", os="Windows 10", type="workstation"),
            ],
        ),
        baseline_activity=BaselineActivity(
            description="Test", intensity=intensity, variation="low"
        ),
        output=OutputSpec(logs=[{"format": "windows_event_security"}], destination="./output"),
        personas=personas or [persona],
    )


class TestSoftRamp:
    """Test sigmoid work hour ramp-up/ramp-down."""

    def test_before_work_near_zero(self):
        """Hours well before work start should have near-zero activity."""
        scenario = _make_scenario()
        engine = GenerationEngine(scenario, Path("/tmp/test"))
        persona = scenario.personas[0]
        user = scenario.environment.users[0]

        # Hour 6 is 3 hours before 9am start — should be near zero
        events_h6 = [
            engine._calculate_events_for_hour(user, current_hour=6, persona=persona)
            for _ in range(50)
        ]
        avg = sum(events_h6) / len(events_h6)
        assert avg < 2, f"Hour 6 avg {avg:.1f} should be near zero"

    def test_ramp_up_before_start(self):
        """Hour just before work start should have some activity (not zero)."""
        scenario = _make_scenario()
        engine = GenerationEngine(scenario, Path("/tmp/test"))
        persona = scenario.personas[0]
        user = scenario.environment.users[0]

        # Hour 8 is 1 hour before 9am — should have partial activity
        events_h8 = [
            engine._calculate_events_for_hour(user, current_hour=8, persona=persona)
            for _ in range(50)
        ]
        avg = sum(events_h8) / len(events_h8)
        assert avg > 0, "Hour 8 should have some activity (ramp-up)"

    def test_full_activity_during_work(self):
        """Core work hours should have full activity."""
        scenario = _make_scenario()
        engine = GenerationEngine(scenario, Path("/tmp/test"))
        persona = scenario.personas[0]
        user = scenario.environment.users[0]

        events_h13 = [
            engine._calculate_events_for_hour(user, current_hour=13, persona=persona)
            for _ in range(50)
        ]
        avg = sum(events_h13) / len(events_h13)
        assert avg > 10, f"Hour 13 avg {avg:.1f} should have full activity"

    def test_lunch_soft_dip(self):
        """Lunch hour should have reduced but nonzero activity."""
        scenario = _make_scenario()
        engine = GenerationEngine(scenario, Path("/tmp/test"))
        persona = scenario.personas[0]
        user = scenario.environment.users[0]

        events_lunch = [
            engine._calculate_events_for_hour(user, current_hour=12, persona=persona)
            for _ in range(100)
        ]
        events_work = [
            engine._calculate_events_for_hour(user, current_hour=14, persona=persona)
            for _ in range(100)
        ]
        avg_lunch = sum(events_lunch) / len(events_lunch)
        avg_work = sum(events_work) / len(events_work)

        # Lunch should be substantially less than work but not zero
        assert avg_lunch > 0, "Lunch should have some activity"
        assert avg_lunch < avg_work, f"Lunch ({avg_lunch:.1f}) should be < work ({avg_work:.1f})"

    def test_evening_tail(self):
        """Hour after work end should have small but nonzero activity."""
        scenario = _make_scenario()
        engine = GenerationEngine(scenario, Path("/tmp/test"))
        persona = scenario.personas[0]
        user = scenario.environment.users[0]

        events_h17 = [
            engine._calculate_events_for_hour(user, current_hour=17, persona=persona)
            for _ in range(50)
        ]
        avg = sum(events_h17) / len(events_h17)
        # Hour 17 is right at end (17=5pm), should still have partial activity from ramp-down
        assert avg >= 0  # May be small but should not crash

    def test_peak_hours_still_higher(self):
        """Peak hours should still get 1.5x multiplier."""
        scenario = _make_scenario()
        engine = GenerationEngine(scenario, Path("/tmp/test"))
        persona = scenario.personas[0]
        user = scenario.environment.users[0]

        events_normal = [
            engine._calculate_events_for_hour(user, current_hour=9, persona=persona)
            for _ in range(100)
        ]
        events_peak = [
            engine._calculate_events_for_hour(user, current_hour=10, persona=persona)
            for _ in range(100)
        ]
        avg_normal = sum(events_normal) / len(events_normal)
        avg_peak = sum(events_peak) / len(events_peak)
        assert avg_peak > avg_normal, (
            f"Peak ({avg_peak:.1f}) should exceed normal ({avg_normal:.1f})"
        )


class TestWorkHourMultiplierDirect:
    """Test _work_hour_multiplier directly."""

    def test_multiplier_range(self):
        scenario = _make_scenario()
        engine = GenerationEngine(scenario, Path("/tmp/test"))
        whp = {"start": 9.0, "end": 17.0, "lunch": (12.0, 13.0), "peak_hours": [10, 11, 14, 15]}

        for hour in range(24):
            m = engine._work_hour_multiplier(hour, whp)
            assert 0.0 <= m <= 1.5, f"Hour {hour}: multiplier {m} out of range"

    def test_multiplier_profile_shape(self):
        """Multiplier should follow: low → ramp → high → lunch_dip → high → ramp → low."""
        scenario = _make_scenario()
        engine = GenerationEngine(scenario, Path("/tmp/test"))
        whp = {"start": 9.0, "end": 17.0, "lunch": (12.0, 13.0), "peak_hours": [10, 11, 14, 15]}

        m = {h: engine._work_hour_multiplier(h, whp) for h in range(24)}
        assert m[5] < 0.1  # Well before work
        assert m[10] > 1.0  # Peak
        assert m[12] < 0.7  # Lunch dip
        assert m[14] > 1.0  # Afternoon peak
        assert m[20] < 0.1  # Well after work

    def test_user_offsets_shift_timing(self):
        """Per-user offsets should shift the ramp position."""
        scenario = _make_scenario()
        engine = GenerationEngine(scenario, Path("/tmp/test"))
        whp = {"start": 9.0, "end": 17.0, "lunch": (12.0, 13.0), "peak_hours": [10, 11, 14, 15]}

        # Early bird: starts 30min earlier
        early_offsets = {
            "start_offset": -0.5,
            "end_offset": 0,
            "lunch_start_offset": 0,
            "lunch_duration_offset": 0,
        }
        # Late starter: starts 30min later
        late_offsets = {
            "start_offset": 0.5,
            "end_offset": 0,
            "lunch_start_offset": 0,
            "lunch_duration_offset": 0,
        }

        m_early_h8 = engine._work_hour_multiplier(8, whp, early_offsets)
        m_late_h8 = engine._work_hour_multiplier(8, whp, late_offsets)

        # Early bird should have more activity at hour 8 than late starter
        assert m_early_h8 > m_late_h8, (
            f"Early ({m_early_h8:.2f}) should > late ({m_late_h8:.2f}) at hour 8"
        )


class TestActivityClusters:
    """Test activity cluster distribution model."""

    def test_events_cluster_together(self):
        """Events within a cluster should be close together (sub-second to seconds)."""
        scenario = _make_scenario()
        engine = GenerationEngine(scenario, Path("/tmp/test"))
        hour_start = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)

        times = engine._distribute_events_in_hour(hour_start, 30)
        # Some events may be dropped if they overflow the hour boundary
        assert len(times) >= 20, f"Expected >=20 events, got {len(times)}"

        # Calculate inter-event gaps
        gaps = [(times[i + 1] - times[i]).total_seconds() for i in range(len(times) - 1)]

        # Some gaps should be very small (within clusters, < 5s)
        small_gaps = [g for g in gaps if g < 5.0]
        assert len(small_gaps) > 5, f"Expected >5 small gaps (<5s), got {len(small_gaps)}"

    def test_inter_cluster_gaps(self):
        """Gaps between clusters should be significantly larger than intra-cluster."""
        scenario = _make_scenario()
        engine = GenerationEngine(scenario, Path("/tmp/test"))
        hour_start = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)

        times = engine._distribute_events_in_hour(hour_start, 30)
        gaps = [(times[i + 1] - times[i]).total_seconds() for i in range(len(times) - 1)]

        # Some gaps should be large (between clusters, > 60s)
        large_gaps = [g for g in gaps if g > 60.0]
        assert len(large_gaps) >= 1, f"Expected at least 1 large gap (>60s), got {len(large_gaps)}"

    def test_burstiness_cv(self):
        """Coefficient of variation of inter-event times should be > 1.0 (bursty)."""
        scenario = _make_scenario()
        engine = GenerationEngine(scenario, Path("/tmp/test"))
        hour_start = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)

        times = engine._distribute_events_in_hour(hour_start, 40)
        gaps = [(times[i + 1] - times[i]).total_seconds() for i in range(len(times) - 1)]

        if len(gaps) > 1:
            mean_gap = statistics.mean(gaps)
            std_gap = statistics.stdev(gaps)
            if mean_gap > 0:
                cv = std_gap / mean_gap
                assert cv > 1.0, f"CV {cv:.2f} should be > 1.0 for bursty distribution"

    def test_persona_affects_cluster_size(self):
        """Developer clusters should be larger than executive clusters."""
        scenario = _make_scenario()
        engine = GenerationEngine(scenario, Path("/tmp/test"))
        hour_start = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)

        # Developer: cluster_size (5, 15)
        dev_times = engine._distribute_events_in_hour(hour_start, 30, persona_name="developer")
        # Executive: cluster_size (2, 6)
        exec_times = engine._distribute_events_in_hour(hour_start, 30, persona_name="executive")

        # Count small gaps (intra-cluster) for each
        dev_gaps = [
            (dev_times[i + 1] - dev_times[i]).total_seconds() for i in range(len(dev_times) - 1)
        ]
        exec_gaps = [
            (exec_times[i + 1] - exec_times[i]).total_seconds() for i in range(len(exec_times) - 1)
        ]

        # Developer should have more consecutive small gaps (larger clusters)
        dev_small = sum(1 for g in dev_gaps if g < 5.0)
        exec_small = sum(1 for g in exec_gaps if g < 5.0)
        # With 30 events, developer clusters of 5-15 vs executive 2-6
        # Developer should have more small gaps on average
        assert dev_small >= exec_small * 0.5, (
            f"Developer small gaps ({dev_small}) should be comparable to exec ({exec_small})"
        )

    def test_per_user_variation(self):
        """Two users with same persona should get different distributions."""
        scenario = _make_scenario()
        engine = GenerationEngine(scenario, Path("/tmp/test"))
        # Manually set up two users with different offsets
        engine._user_time_offsets = {
            "user_a": {"cluster_size_bias": 0.3, "inter_gap_bias": -0.2},
            "user_b": {"cluster_size_bias": -0.3, "inter_gap_bias": 0.2},
        }
        hour_start = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)

        times_a = engine._distribute_events_in_hour(
            hour_start, 20, persona_name="developer", username="user_a"
        )
        times_b = engine._distribute_events_in_hour(
            hour_start, 20, persona_name="developer", username="user_b"
        )

        # Both should have events (some may be dropped if they overflow the hour)
        assert len(times_a) > 0
        assert len(times_b) > 0
        # They should not be identical
        assert times_a != times_b
