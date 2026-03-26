"""Integration tests for multi-timezone scenario handling.

Phase 2.4: Tests that timezone configuration works end-to-end
when loading scenarios with multiple timezone overrides.
"""

from datetime import UTC, datetime

from evidenceforge.models.scenario import (
    BaselineActivity,
    Environment,
    OutputSpec,
    Persona,
    Scenario,
    System,
    TimeWindow,
    Timezone,
    User,
)
from evidenceforge.utils.time import convert_to_output_timezone, get_system_timezone


class TestMultiTimezoneScenario:
    """Integration tests for multi-timezone scenario loading and resolution."""

    def _make_multi_tz_scenario(self):
        """Create a scenario with systems in multiple timezones."""
        return Scenario(
            version="1.0",
            name="multi-tz-test",
            description="Multi-timezone integration test",
            environment=Environment(
                description="Global enterprise with US and EU offices",
                timezone=Timezone(
                    default="UTC",
                    systems={
                        "US-*": "America/New_York",
                        "EU-*": "Europe/London",
                        "AP-*": "Asia/Tokyo",
                    },
                ),
                users=[
                    User(
                        username="us_user",
                        full_name="US User",
                        email="us@example.com",
                        persona="developer",
                    ),
                    User(
                        username="eu_user",
                        full_name="EU User",
                        email="eu@example.com",
                        persona="developer",
                    ),
                    User(
                        username="ap_user",
                        full_name="AP User",
                        email="ap@example.com",
                        persona="developer",
                    ),
                ],
                systems=[
                    System(hostname="US-WS-01", ip="10.1.0.1", os="Windows 10", type="workstation"),
                    System(hostname="EU-WS-01", ip="10.2.0.1", os="Windows 10", type="workstation"),
                    System(hostname="AP-WS-01", ip="10.3.0.1", os="Windows 10", type="workstation"),
                    System(
                        hostname="DC-01",
                        ip="10.0.0.1",
                        os="Windows Server 2019",
                        type="domain_controller",
                    ),
                ],
            ),
            personas=[
                Persona(
                    name="developer",
                    description="Software developer",
                    typical_activities=["coding", "browsing"],
                    work_hours="9am-5pm",
                    application_usage=["vscode"],
                    risk_profile="low",
                ),
            ],
            time_window=TimeWindow(
                start=datetime(2024, 1, 15, 10, 0, 0),
                duration="8h",
            ),
            baseline_activity=BaselineActivity(
                description="Normal office activity",
                intensity="medium",
                variation="low",
            ),
            output=OutputSpec(
                logs=[{"format": "windows_event_security"}],
                destination="./output",
            ),
        )

    def test_timezone_resolution_per_system(self):
        """Each system should resolve to its pattern-matched timezone."""
        scenario = self._make_multi_tz_scenario()
        env = scenario.environment

        assert get_system_timezone("US-WS-01", env) == "America/New_York"
        assert get_system_timezone("EU-WS-01", env) == "Europe/London"
        assert get_system_timezone("AP-WS-01", env) == "Asia/Tokyo"
        assert get_system_timezone("DC-01", env) == "UTC"  # No pattern match → default

    def test_same_utc_time_different_local_times(self):
        """Same UTC time should produce different local times per system."""
        scenario = self._make_multi_tz_scenario()
        env = scenario.environment
        utc_time = datetime(2024, 1, 15, 15, 0, 0, tzinfo=UTC)

        us_local = convert_to_output_timezone(utc_time, "US-WS-01", env)
        eu_local = convert_to_output_timezone(utc_time, "EU-WS-01", env)
        ap_local = convert_to_output_timezone(utc_time, "AP-WS-01", env)
        dc_local = convert_to_output_timezone(utc_time, "DC-01", env)

        # January: EST=-5, GMT=0, JST=+9, UTC=0
        assert us_local.hour == 10  # 15:00 UTC - 5 = 10:00 EST
        assert eu_local.hour == 15  # 15:00 UTC + 0 = 15:00 GMT
        assert ap_local.hour == 0  # 15:00 UTC + 9 = 00:00 next day JST
        assert ap_local.day == 16  # Next day in Tokyo
        assert dc_local.hour == 15  # UTC stays UTC

    def test_work_hours_auto_parsed_on_persona_load(self):
        """Persona work_hours_parsed should be auto-populated on load."""
        scenario = self._make_multi_tz_scenario()
        persona = scenario.personas[0]

        assert persona.work_hours == "9am-5pm"
        assert persona.work_hours_parsed is not None
        assert persona.work_hours_parsed["start"] == 9
        assert persona.work_hours_parsed["end"] == 17
        assert persona.work_hours_parsed["lunch"] is None
        assert 9 in persona.work_hours_parsed["hours"]
        assert 16 in persona.work_hours_parsed["hours"]
        assert len(persona.work_hours_parsed["peak_hours"]) > 0

    def test_scenario_loads_without_timezone_overrides(self):
        """Scenario with no timezone overrides should use default for all systems."""
        scenario = Scenario(
            version="1.0",
            name="no-tz-override",
            description="Test without timezone overrides",
            environment=Environment(
                description="Simple env",
                timezone=Timezone(default="America/Chicago"),
                users=[
                    User(username="user1", full_name="User 1", email="u1@example.com"),
                ],
                systems=[
                    System(hostname="WS-01", ip="10.0.0.1", os="Windows 10", type="workstation"),
                    System(
                        hostname="SRV-01", ip="10.0.0.2", os="Windows Server 2019", type="server"
                    ),
                ],
            ),
            time_window=TimeWindow(start=datetime(2024, 1, 15, 10, 0, 0), duration="1h"),
            baseline_activity=BaselineActivity(
                description="Test", intensity="low", variation="low"
            ),
            output=OutputSpec(logs=[{"format": "windows_event_security"}], destination="./output"),
        )

        env = scenario.environment
        assert get_system_timezone("WS-01", env) == "America/Chicago"
        assert get_system_timezone("SRV-01", env) == "America/Chicago"
