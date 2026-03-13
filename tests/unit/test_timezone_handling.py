"""Tests for timezone handling utilities.

Phase 2.4: Tests get_system_timezone() and convert_to_output_timezone()
for correct timezone resolution and conversion.
"""

from datetime import datetime, timezone

import pytest

from evidenceforge.models.scenario import (
    Environment,
    System,
    Timezone,
    User,
)
from evidenceforge.utils.time import convert_to_output_timezone, get_system_timezone


def _make_environment(tz_default="UTC", tz_systems=None):
    """Helper to create an Environment with timezone config."""
    return Environment(
        description="Test environment",
        timezone=Timezone(default=tz_default, systems=tz_systems),
        users=[
            User(
                username="testuser",
                full_name="Test User",
                email="test@example.com",
            )
        ],
        systems=[
            System(hostname="TEST-01", ip="10.0.0.1", os="Windows 10", type="workstation"),
        ],
    )


class TestGetSystemTimezone:
    """Tests for get_system_timezone() function."""

    def test_default_timezone_no_overrides(self):
        """Should return default timezone when no system overrides exist."""
        env = _make_environment(tz_default="America/New_York")
        assert get_system_timezone("TEST-01", env) == "America/New_York"

    def test_default_timezone_no_pattern_match(self):
        """Should return default when hostname doesn't match any pattern."""
        env = _make_environment(
            tz_default="UTC",
            tz_systems={"EU-*": "Europe/London", "US-*": "America/Los_Angeles"},
        )
        assert get_system_timezone("UNKNOWN-HOST", env) == "UTC"

    def test_pattern_match_single(self):
        """Should return overridden timezone when hostname matches pattern."""
        env = _make_environment(
            tz_default="UTC",
            tz_systems={"EU-*": "Europe/London"},
        )
        assert get_system_timezone("EU-SERVER-01", env) == "Europe/London"

    def test_pattern_match_multiple(self):
        """Should match correct pattern among multiple overrides."""
        env = _make_environment(
            tz_default="UTC",
            tz_systems={
                "EU-*": "Europe/London",
                "US-*": "America/Los_Angeles",
                "AP-*": "Asia/Tokyo",
            },
        )
        assert get_system_timezone("EU-WEB-01", env) == "Europe/London"
        assert get_system_timezone("US-DB-02", env) == "America/Los_Angeles"
        assert get_system_timezone("AP-APP-01", env) == "Asia/Tokyo"

    def test_pattern_match_first_wins(self):
        """First matching pattern should win when multiple could match."""
        env = _make_environment(
            tz_default="UTC",
            tz_systems={
                "WS-*": "America/New_York",
                "WS-NYC-*": "America/Chicago",
            },
        )
        # "WS-*" is iterated first, so it should match
        result = get_system_timezone("WS-NYC-01", env)
        assert result == "America/New_York"

    def test_empty_systems_dict(self):
        """Empty systems dict should fall back to default."""
        env = _make_environment(tz_default="Europe/Berlin", tz_systems={})
        # Empty dict means no overrides - should check if environment.timezone.systems is truthy
        assert get_system_timezone("ANY-HOST", env) == "Europe/Berlin"

    def test_none_systems(self):
        """None systems should fall back to default."""
        env = _make_environment(tz_default="Asia/Tokyo", tz_systems=None)
        assert get_system_timezone("ANY-HOST", env) == "Asia/Tokyo"

    def test_fnmatch_question_mark(self):
        """Should support ? wildcard in patterns."""
        env = _make_environment(
            tz_default="UTC",
            tz_systems={"WS-??-01": "America/Denver"},
        )
        assert get_system_timezone("WS-CO-01", env) == "America/Denver"
        assert get_system_timezone("WS-NYC-01", env) == "UTC"  # NYC is 3 chars, ? matches 1


class TestConvertToOutputTimezone:
    """Tests for convert_to_output_timezone() function."""

    def test_utc_to_eastern(self):
        """UTC time should convert to America/New_York correctly."""
        env = _make_environment(tz_default="America/New_York")
        utc_time = datetime(2024, 1, 15, 15, 0, 0, tzinfo=timezone.utc)
        local_time = convert_to_output_timezone(utc_time, "TEST-01", env)
        # January = EST (UTC-5)
        assert local_time.hour == 10
        assert local_time.minute == 0
        assert str(local_time.tzinfo) == "America/New_York"

    def test_utc_to_london(self):
        """UTC time should convert to Europe/London (same in winter)."""
        env = _make_environment(tz_default="Europe/London")
        utc_time = datetime(2024, 1, 15, 12, 0, 0, tzinfo=timezone.utc)
        local_time = convert_to_output_timezone(utc_time, "TEST-01", env)
        # January = GMT (UTC+0)
        assert local_time.hour == 12

    def test_dst_summer(self):
        """Should handle DST correctly in summer."""
        env = _make_environment(tz_default="America/New_York")
        # July = EDT (UTC-4)
        utc_time = datetime(2024, 7, 15, 15, 0, 0, tzinfo=timezone.utc)
        local_time = convert_to_output_timezone(utc_time, "TEST-01", env)
        assert local_time.hour == 11  # EDT is UTC-4

    def test_dst_london_summer(self):
        """Europe/London should be BST (UTC+1) in summer."""
        env = _make_environment(tz_default="Europe/London")
        utc_time = datetime(2024, 7, 15, 12, 0, 0, tzinfo=timezone.utc)
        local_time = convert_to_output_timezone(utc_time, "TEST-01", env)
        assert local_time.hour == 13  # BST is UTC+1

    def test_midnight_boundary(self):
        """Converting UTC midnight should handle date boundary correctly."""
        env = _make_environment(tz_default="America/Los_Angeles")
        utc_time = datetime(2024, 1, 15, 3, 0, 0, tzinfo=timezone.utc)
        local_time = convert_to_output_timezone(utc_time, "TEST-01", env)
        # PST is UTC-8, so 03:00 UTC = 19:00 Jan 14 PST
        assert local_time.hour == 19
        assert local_time.day == 14

    def test_pattern_override_conversion(self):
        """Conversion should use pattern-matched timezone, not default."""
        env = _make_environment(
            tz_default="UTC",
            tz_systems={"EU-*": "Europe/Berlin"},
        )
        utc_time = datetime(2024, 1, 15, 12, 0, 0, tzinfo=timezone.utc)

        # EU host should use Europe/Berlin (CET = UTC+1 in winter)
        local_time = convert_to_output_timezone(utc_time, "EU-SERVER-01", env)
        assert local_time.hour == 13

        # Non-EU host should use UTC
        local_time_utc = convert_to_output_timezone(utc_time, "US-SERVER-01", env)
        assert local_time_utc.hour == 12
