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

"""Unit tests for utility modules."""

import uuid
from datetime import UTC, datetime, timedelta

import pytest

from evidenceforge.models import (
    Environment,
    System,
    TimeWindow,
    Timezone,
    User,
)
from evidenceforge.utils import (
    convert_to_output_timezone,
    ensure_directory,
    get_system_timezone,
    load_yaml,
    parse_duration,
    parse_iso8601,
    redact_secrets,
    resolve_time_window,
    validate_output_path,
    write_yaml,
)
from evidenceforge.utils.rng import stable_uuid


class TestStableUuid:
    """Tests for deterministic source-native UUID helpers."""

    def test_stable_uuid_is_repeatable_uuid4_shape(self):
        """Stable IDs should be deterministic without exposing UUIDv5 morphology."""
        first = stable_uuid("ecar-process", "WS-01", 1234, "cmd.exe")
        second = stable_uuid("ecar-process", "WS-01", 1234, "cmd.exe")

        parsed = uuid.UUID(first)
        assert first == second
        assert parsed.version == 4
        assert parsed.variant == uuid.RFC_4122

    def test_stable_uuid_changes_with_semantic_parts(self):
        """Different semantic inputs should produce different deterministic IDs."""
        first = stable_uuid("ecar-process", "WS-01", 1234, "cmd.exe")
        second = stable_uuid("ecar-process", "WS-01", 1235, "cmd.exe")

        assert first != second


class TestRedactSecrets:
    """Tests for secret redaction utility."""

    def test_redact_secrets(self):
        """Test sensitive data redaction."""
        data = {
            "username": "user",
            "password": "secret123",
            "api_key": "key123",
            "safe_value": "visible",
        }
        redacted = redact_secrets(data)
        assert redacted["password"] == "***REDACTED***"
        assert redacted["api_key"] == "***REDACTED***"
        assert redacted["safe_value"] == "visible"

    def test_redact_secrets_nested(self):
        """Test redaction of nested dicts."""
        data = {"outer": {"password": "secret", "normal": "value"}}
        redacted = redact_secrets(data)
        assert redacted["outer"]["password"] == "***REDACTED***"
        assert redacted["outer"]["normal"] == "value"


class TestTimeUtils:
    """Tests for time parsing utilities."""

    def test_parse_duration_hours(self):
        """Test parsing hours duration."""
        result = parse_duration("8h")
        assert result == timedelta(hours=8)

    def test_parse_duration_days(self):
        """Test parsing days duration."""
        result = parse_duration("3d")
        assert result == timedelta(days=3)

    def test_parse_duration_minutes(self):
        """Test parsing minutes duration."""
        result = parse_duration("30m")
        assert result == timedelta(minutes=30)

    def test_parse_duration_combined(self):
        """Test parsing combined duration."""
        result = parse_duration("2h30m")
        assert result == timedelta(hours=2, minutes=30)

    def test_parse_duration_complex(self):
        """Test parsing complex duration."""
        result = parse_duration("1d3h45m")
        expected = timedelta(days=1, hours=3, minutes=45)
        assert result == expected

    def test_parse_duration_seconds(self):
        """Test parsing seconds duration."""
        result = parse_duration("30s")
        assert result == timedelta(seconds=30)

    def test_parse_duration_minutes_seconds(self):
        """Test parsing combined minutes and seconds."""
        result = parse_duration("2m30s")
        assert result == timedelta(minutes=2, seconds=30)

    def test_parse_duration_hours_minutes_seconds(self):
        """Test parsing combined hours, minutes, and seconds."""
        result = parse_duration("1h30m15s")
        assert result == timedelta(hours=1, minutes=30, seconds=15)

    def test_parse_duration_milliseconds(self):
        """Test parsing milliseconds duration."""
        result = parse_duration("500ms")
        assert result == timedelta(milliseconds=500)

    def test_parse_duration_seconds_milliseconds(self):
        """Test parsing combined seconds and milliseconds."""
        result = parse_duration("2s500ms")
        assert result == timedelta(seconds=2, milliseconds=500)

    def test_parse_duration_invalid(self):
        """Test that invalid duration raises error."""
        with pytest.raises(ValueError, match="Invalid duration format"):
            parse_duration("invalid")

        with pytest.raises(ValueError, match="Invalid duration format"):
            parse_duration("10")

        with pytest.raises(ValueError, match="Invalid duration format"):
            parse_duration("10x")

    def test_parse_iso8601_utc(self):
        """Test parsing ISO 8601 with UTC."""
        result = parse_iso8601("2024-01-15T10:00:00Z")
        assert result.year == 2024
        assert result.month == 1
        assert result.day == 15
        assert result.hour == 10
        assert result.tzinfo == UTC

    def test_parse_iso8601_with_offset(self):
        """Test parsing ISO 8601 with timezone offset."""
        result = parse_iso8601("2024-01-15T10:00:00+00:00")
        assert result.tzinfo == UTC

    def test_resolve_time_window_with_duration(self):
        """Test resolving TimeWindow with duration."""
        tw = TimeWindow(start=datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC), duration="8h")
        start, end = resolve_time_window(tw)
        assert start == datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)
        assert end == start + timedelta(hours=8)

    def test_resolve_time_window_with_end(self):
        """Test resolving TimeWindow with explicit end."""
        tw = TimeWindow(
            start=datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC),
            end=datetime(2024, 1, 15, 18, 0, 0, tzinfo=UTC),
        )
        start, end = resolve_time_window(tw)
        assert start == datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)
        assert end == datetime(2024, 1, 15, 18, 0, 0, tzinfo=UTC)

    def test_get_system_timezone_default(self):
        """Test system timezone with no pattern match."""
        env = Environment(
            description="Test",
            users=[User(username="test", full_name="Test", email="test@example.com")],
            systems=[System(hostname="WS-01", ip="192.168.1.1", os="Windows", type="workstation")],
        )
        tz = get_system_timezone("WS-01", env)
        assert tz == "UTC"

    def test_get_system_timezone_pattern_match(self):
        """Test system timezone with pattern matching."""
        env = Environment(
            description="Test",
            timezone=Timezone(default="UTC", systems={"WS-NYC-*": "America/New_York"}),
            users=[User(username="test", full_name="Test", email="test@example.com")],
            systems=[
                System(hostname="WS-NYC-01", ip="192.168.1.1", os="Windows", type="workstation")
            ],
        )
        tz = get_system_timezone("WS-NYC-01", env)
        assert tz == "America/New_York"

    def test_convert_to_output_timezone(self):
        """Test converting UTC to output timezone."""
        env = Environment(
            description="Test",
            timezone=Timezone(default="UTC", systems={"WS-NYC-*": "America/New_York"}),
            users=[User(username="test", full_name="Test", email="test@example.com")],
            systems=[
                System(hostname="WS-NYC-01", ip="192.168.1.1", os="Windows", type="workstation")
            ],
        )
        utc_time = datetime(2024, 1, 15, 15, 0, 0, tzinfo=UTC)
        ny_time = convert_to_output_timezone(utc_time, "WS-NYC-01", env)
        # Should be 10 AM in New York (EST = UTC-5)
        assert ny_time.hour == 10


class TestFileUtils:
    """Tests for file I/O utilities."""

    def test_load_yaml_valid(self, tmp_path):
        """Test loading valid YAML file."""
        yaml_file = tmp_path / "test.yaml"
        yaml_file.write_text("key: value\nnumber: 42")

        data = load_yaml(yaml_file)
        assert data["key"] == "value"
        assert data["number"] == 42

    def test_load_yaml_not_found(self):
        """Test loading non-existent file raises error."""
        with pytest.raises(FileNotFoundError):
            load_yaml("nonexistent.yaml")

    def test_write_yaml(self, tmp_path):
        """Test writing YAML file."""
        output_file = tmp_path / "output.yaml"
        data = {"key": "value", "number": 42}

        write_yaml(data, output_file)
        assert output_file.exists()

        loaded = load_yaml(output_file)
        assert loaded == data

    def test_write_yaml_creates_parent_dirs(self, tmp_path):
        """Test that write_yaml creates parent directories."""
        output_file = tmp_path / "nested" / "dirs" / "output.yaml"
        data = {"test": "data"}

        write_yaml(data, output_file)
        assert output_file.exists()
        assert output_file.parent.exists()

    def test_ensure_directory(self, tmp_path):
        """Test directory creation."""
        new_dir = tmp_path / "new" / "nested" / "dir"
        result = ensure_directory(new_dir)
        assert result.exists()
        assert result.is_dir()

    def test_ensure_directory_existing(self, tmp_path):
        """Test ensure_directory with existing directory."""
        existing_dir = tmp_path / "existing"
        existing_dir.mkdir()

        result = ensure_directory(existing_dir)
        assert result.exists()
        assert result.is_dir()

    def test_validate_output_path_valid(self, tmp_path):
        """Test validating writable output path."""
        output_path = tmp_path / "output.txt"
        result = validate_output_path(output_path)
        assert result == output_path.resolve()

    def test_validate_output_path_creates_parent(self, tmp_path):
        """Test that validate_output_path creates parent directories."""
        output_path = tmp_path / "new" / "dir" / "output.txt"
        result = validate_output_path(output_path)
        assert result.parent.exists()

    def test_load_yaml_invalid_yaml(self, tmp_path):
        """Test loading invalid YAML raises ConfigurationError."""
        from evidenceforge.models.exceptions import ConfigurationError

        yaml_file = tmp_path / "invalid.yaml"
        yaml_file.write_text("invalid: yaml: [content")

        with pytest.raises(ConfigurationError, match="Invalid YAML"):
            load_yaml(yaml_file)

    def test_load_yaml_empty_file(self, tmp_path):
        """Test loading empty YAML file returns empty dict."""
        yaml_file = tmp_path / "empty.yaml"
        yaml_file.write_text("")

        data = load_yaml(yaml_file)
        assert data == {}

    def test_parse_iso8601_no_timezone(self):
        """Test parsing ISO 8601 without timezone assumes UTC."""
        result = parse_iso8601("2024-01-15T10:00:00")
        assert result.tzinfo == UTC

    def test_parse_iso8601_invalid(self):
        """Test parsing invalid ISO 8601 raises ValueError."""
        with pytest.raises(ValueError, match="Invalid ISO 8601"):
            parse_iso8601("not-a-timestamp")

        with pytest.raises(ValueError, match="Invalid ISO 8601"):
            parse_iso8601("2024-13-45T99:99:99Z")


class TestFileUtilsErrors:
    """Additional tests for file utility error paths."""

    def test_load_yaml_invalid_yaml(self, tmp_path):
        """Test loading invalid YAML raises ConfigurationError."""
        from evidenceforge.models.exceptions import ConfigurationError

        yaml_file = tmp_path / "invalid.yaml"
        yaml_file.write_text("invalid: yaml: [content")

        with pytest.raises(ConfigurationError, match="Invalid YAML"):
            load_yaml(yaml_file)

    def test_load_yaml_empty_file(self, tmp_path):
        """Test loading empty YAML file returns empty dict."""
        yaml_file = tmp_path / "empty.yaml"
        yaml_file.write_text("")

        data = load_yaml(yaml_file)
        assert data == {}
