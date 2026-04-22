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

"""Unit tests for data models."""

from datetime import datetime

import pytest
from pydantic import ValidationError

from evidenceforge.models import (
    ActiveSession,
    BaselineActivity,
    Environment,
    GeneratorState,
    Group,
    OpenConnection,
    OutputSpec,
    Persona,
    RedHerringEvent,
    RunningProcess,
    Scenario,
    StaleAccount,
    StorylineEvent,
    System,
    TimeWindow,
    Timezone,
    User,
)
from evidenceforge.models.exceptions import EvidenceForgeError
from evidenceforge.models.exceptions import ValidationError as VError


class TestExceptions:
    """Tests for exception hierarchy."""

    def test_base_exception(self):
        """Test base EvidenceForgeError."""
        err = EvidenceForgeError("test error")
        assert str(err) == "test error"
        assert isinstance(err, Exception)

    def test_validation_error_inheritance(self):
        """Test ValidationError inherits from EvidenceForgeError."""
        err = VError("validation failed")
        assert isinstance(err, EvidenceForgeError)
        assert isinstance(err, Exception)


class TestTimeWindow:
    """Tests for TimeWindow model."""

    def test_time_window_with_end(self):
        """Test time window with explicit end time."""
        tw = TimeWindow(start=datetime(2024, 1, 15, 10, 0, 0), end=datetime(2024, 1, 15, 18, 0, 0))
        assert tw.start == datetime(2024, 1, 15, 10, 0, 0)
        assert tw.end == datetime(2024, 1, 15, 18, 0, 0)
        assert tw.duration is None

    def test_time_window_with_duration(self):
        """Test time window with duration string."""
        tw = TimeWindow(start=datetime(2024, 1, 15, 10, 0, 0), duration="8h")
        assert tw.start == datetime(2024, 1, 15, 10, 0, 0)
        assert tw.duration == "8h"
        assert tw.end is None

    def test_time_window_requires_end_or_duration(self):
        """Test that either end or duration must be specified."""
        with pytest.raises(ValidationError, match="Either 'end' or 'duration'"):
            TimeWindow(start=datetime(2024, 1, 15, 10, 0, 0))

    def test_time_window_cannot_have_both(self):
        """Test that both end and duration cannot be specified."""
        with pytest.raises(ValidationError, match="Cannot specify both"):
            TimeWindow(
                start=datetime(2024, 1, 15, 10, 0, 0),
                end=datetime(2024, 1, 15, 18, 0, 0),
                duration="8h",
            )

    def test_duration_format_validation(self):
        """Test duration format validation."""
        # Valid formats
        TimeWindow(start=datetime(2024, 1, 15, 10, 0, 0), duration="10h")
        TimeWindow(start=datetime(2024, 1, 15, 10, 0, 0), duration="3d")
        TimeWindow(start=datetime(2024, 1, 15, 10, 0, 0), duration="2h30m")

        # Invalid format
        with pytest.raises(ValidationError, match="Duration must match pattern"):
            TimeWindow(start=datetime(2024, 1, 15, 10, 0, 0), duration="invalid")

    def test_time_window_warmup_default(self):
        """Default warmup is '8h'."""
        tw = TimeWindow(start=datetime(2024, 1, 15, 10, 0, 0), duration="8h")
        assert tw.warmup == "8h"

    def test_time_window_warmup_custom(self):
        """Custom warmup values >= 1h are accepted."""
        tw = TimeWindow(start=datetime(2024, 1, 15, 10, 0, 0), duration="8h", warmup="1h30m")
        assert tw.warmup == "1h30m"

        tw2 = TimeWindow(start=datetime(2024, 1, 15, 10, 0, 0), duration="8h", warmup="2h")
        assert tw2.warmup == "2h"

    def test_time_window_warmup_rejects_zero(self):
        """'0s' is rejected — warm-up cannot be disabled."""
        with pytest.raises(ValidationError, match="at least 1 hour"):
            TimeWindow(start=datetime(2024, 1, 15, 10, 0, 0), duration="8h", warmup="0s")

    def test_time_window_warmup_rejects_sub_hour(self):
        """Sub-hour warmup values are rejected (minimum 1 hour)."""
        with pytest.raises(ValidationError, match="at least 1 hour"):
            TimeWindow(start=datetime(2024, 1, 15, 10, 0, 0), duration="8h", warmup="30m")

    def test_time_window_warmup_none(self):
        """None means use default (engine provides 8h)."""
        tw = TimeWindow(start=datetime(2024, 1, 15, 10, 0, 0), duration="8h", warmup=None)
        assert tw.warmup is None

    def test_time_window_warmup_invalid(self):
        """Invalid warmup format raises ValidationError."""
        with pytest.raises(ValidationError, match="warmup must match pattern"):
            TimeWindow(start=datetime(2024, 1, 15, 10, 0, 0), duration="8h", warmup="invalid")

    def test_time_window_warmup_minimum_1h(self):
        """Exactly 1h is the minimum accepted warmup."""
        tw = TimeWindow(start=datetime(2024, 1, 15, 10, 0, 0), duration="8h", warmup="1h")
        assert tw.warmup == "1h"


class TestUser:
    """Tests for User model."""

    def test_user_valid(self):
        """Test valid user creation."""
        user = User(
            username="jdoe",
            full_name="John Doe",
            email="jdoe@example.com",
            groups=["users", "developers"],
            persona="developer",
        )
        assert user.username == "jdoe"
        assert user.enabled is True
        assert user.persona == "developer"

    def test_user_defaults(self):
        """Test user default values."""
        user = User(username="jdoe", full_name="John Doe", email="jdoe@example.com")
        assert user.groups == []
        assert user.enabled is True
        assert user.persona is None
        assert user.primary_system is None

    def test_user_invalid_username(self):
        """Test that invalid usernames are rejected."""
        with pytest.raises(ValidationError):
            User(
                username="john doe",  # Space not allowed
                full_name="John Doe",
                email="jdoe@example.com",
            )

    def test_user_invalid_email(self):
        """Test that invalid emails are rejected."""
        with pytest.raises(ValidationError, match="Invalid email"):
            User(username="jdoe", full_name="John Doe", email="not-an-email")

    def test_user_allows_machine_account_dollar_sign(self):
        """Machine account usernames/emails containing '$' should validate."""
        user = User(
            username="BACKUP$",
            full_name="BACKUP$",
            email="BACKUP$@system.local",
        )
        assert user.username == "BACKUP$"
        assert user.email == "BACKUP$@system.local"


class TestSystem:
    """Tests for System model."""

    def test_system_valid(self):
        """Test valid system creation."""
        system = System(
            hostname="WS-NYC-01",
            ip="192.168.1.100",
            os="Windows 10",
            type="workstation",
            assigned_user="jdoe",
            services=["RDP", "SMB"],
        )
        assert system.hostname == "WS-NYC-01"
        assert system.type == "workstation"
        assert system.services == ["RDP", "SMB"]

    def test_system_defaults(self):
        """Test system default values."""
        system = System(hostname="SRV-01", ip="192.168.1.1", os="Linux", type="server")
        assert system.assigned_user is None
        assert system.services == []

    def test_system_valid_ipv6(self):
        """Test system with IPv6 address."""
        system = System(hostname="SRV-01", ip="2001:db8::1", os="Linux", type="server")
        assert system.ip == "2001:db8::1"

    def test_system_invalid_ip(self):
        """Test that invalid IPs are rejected."""
        with pytest.raises(ValidationError, match="Invalid IP"):
            System(hostname="WS-01", ip="999.999.999.999", os="Windows 10", type="workstation")

    def test_system_invalid_type(self):
        """Test that invalid types are rejected."""
        with pytest.raises(ValidationError):
            System(
                hostname="WS-01",
                ip="192.168.1.100",
                os="Windows 10",
                type="invalid_type",  # type: ignore
            )


class TestGroup:
    """Tests for Group model."""

    def test_group_valid(self):
        """Test valid group creation."""
        group = Group(
            name="developers",
            description="Development team",
            members=["jdoe", "asmith"],
            permissions=["read", "write"],
        )
        assert group.name == "developers"
        assert len(group.members) == 2

    def test_group_defaults(self):
        """Test group default values."""
        group = Group(name="users")
        assert group.description is None
        assert group.members == []
        assert group.permissions is None


class TestPersona:
    """Tests for Persona model."""

    def test_persona_valid(self):
        """Test valid persona creation."""
        persona = Persona(
            name="developer",
            description="Software developer",
            typical_activities=["coding", "testing", "code review"],
            work_hours="9am-6pm",
            application_usage=["VS Code", "Git", "Browser"],
            risk_profile="medium",
        )
        assert persona.name == "developer"
        assert persona.risk_profile == "medium"

    def test_persona_defaults(self):
        """Test persona default values."""
        persona = Persona(name="test", description="Test persona")
        assert persona.typical_activities == []
        assert persona.work_hours == "9am-5pm"
        assert persona.application_usage == []
        assert persona.risk_profile == "medium"

    def test_persona_invalid_risk_profile(self):
        """Test that invalid risk profiles are rejected."""
        with pytest.raises(ValidationError):
            Persona(
                name="test",
                description="Test",
                risk_profile="invalid",  # type: ignore
            )


class TestTimezone:
    """Tests for Timezone model."""

    def test_timezone_valid(self):
        """Test valid timezone."""
        tz = Timezone(default="America/New_York")
        assert tz.default == "America/New_York"

    def test_timezone_with_systems(self):
        """Test timezone with system overrides."""
        tz = Timezone(
            default="UTC", systems={"WS-NYC-*": "America/New_York", "WS-LON-*": "Europe/London"}
        )
        assert tz.default == "UTC"
        assert tz.systems is not None
        assert tz.systems["WS-NYC-*"] == "America/New_York"

    def test_timezone_invalid(self):
        """Test that invalid timezones are rejected."""
        with pytest.raises(ValidationError, match="Unknown timezone"):
            Timezone(default="Invalid/Timezone")

    def test_timezone_invalid_system_override(self):
        """Test that invalid per-system timezone overrides are rejected."""
        with pytest.raises(ValidationError, match="Unknown timezone override"):
            Timezone(default="UTC", systems={"WS-.*": "Invalid/Timezone"})


class TestEnvironment:
    """Tests for Environment model."""

    def test_environment_valid(self):
        """Test valid environment creation."""
        env = Environment(
            description="Test environment",
            users=[User(username="jdoe", full_name="John Doe", email="jdoe@example.com")],
            systems=[
                System(hostname="WS-01", ip="192.168.1.100", os="Windows", type="workstation")
            ],
        )
        assert len(env.users) == 1
        assert len(env.systems) == 1

    def test_environment_requires_users(self):
        """Test that environment requires at least one user."""
        with pytest.raises(ValidationError, match="at least one user"):
            Environment(
                description="Test",
                users=[],
                systems=[System(hostname="SRV-01", ip="192.168.1.1", os="Linux", type="server")],
            )

    def test_environment_requires_systems(self):
        """Test that environment requires at least one system."""
        with pytest.raises(ValidationError, match="at least one system"):
            Environment(
                description="Test",
                users=[User(username="jdoe", full_name="John", email="j@example.com")],
                systems=[],
            )


class TestBaselineActivity:
    """Tests for BaselineActivity model."""

    def test_baseline_valid(self):
        """Test valid baseline activity."""
        baseline = BaselineActivity(
            description="Normal business activity",
            intensity="medium",
            variation="low",
        )
        assert baseline.intensity == "medium"
        assert baseline.variation == "low"

    def test_baseline_invalid_intensity(self):
        """Test that invalid intensity is rejected."""
        with pytest.raises(ValidationError):
            BaselineActivity(
                description="Test",
                intensity="invalid",
                variation="low",  # type: ignore
            )


class TestStorylineEvent:
    """Tests for StorylineEvent model."""

    def test_storyline_event_valid(self):
        """Test valid storyline event."""
        event = StorylineEvent(
            id="evt-test-1",
            time="2024-01-15T14:30:00Z",
            actor="attacker",
            system="WS-01",
            activity="Execute malicious payload",
            events=[{"type": "process", "process_name": "malware.exe"}],
        )
        assert event.actor == "attacker"
        assert event.events is not None
        assert event.events[0].process_name == "malware.exe"

    def test_storyline_event_with_events_list(self):
        """Test storyline event with events list."""
        event = StorylineEvent(
            id="evt-test-2",
            time="+2h30m",
            actor="jdoe",
            system="WS-01",
            activity="Access file share",
            events=[{"type": "process", "process_name": "cmd.exe"}],
        )
        assert len(event.events) == 1
        assert event.events[0].type == "process"

    def test_storyline_event_with_process_access_event(self):
        """Test storyline event with process_access typed event."""
        event = StorylineEvent(
            id="evt-test-3",
            time="+45m",
            actor="jdoe",
            system="WS-01",
            activity="Access lsass process",
            events=[
                {"type": "process_access", "target_process": "lsass.exe", "access_mask": "0x1010"}
            ],
        )
        assert len(event.events) == 1
        assert event.events[0].type == "process_access"
        assert event.events[0].target_process == "lsass.exe"


class TestOutputSpec:
    """Tests for OutputSpec model."""

    def test_output_spec_valid(self):
        """Test valid output specification."""
        spec = OutputSpec(
            logs=[{"format": "windows_event", "types": ["security"]}],
            destination="./output",
            compression=True,
        )
        assert len(spec.logs) == 1
        assert spec.compression is True

    def test_output_spec_defaults(self):
        """Test output spec default values."""
        spec = OutputSpec(logs=[], destination="./output")
        assert spec.compression is False


class TestScenario:
    """Tests for complete Scenario model."""

    def test_scenario_valid(self):
        """Test valid scenario creation."""
        scenario = Scenario(
            name="test-scenario",
            description="Test scenario",
            environment=Environment(
                description="Test env",
                users=[User(username="jdoe", full_name="John", email="j@example.com")],
                systems=[
                    System(hostname="WS-01", ip="192.168.1.1", os="Windows", type="workstation")
                ],
            ),
            time_window=TimeWindow(start=datetime(2024, 1, 15, 10, 0, 0), duration="8h"),
            baseline_activity=BaselineActivity(
                description="Normal", intensity="medium", variation="low"
            ),
            output=OutputSpec(logs=[], destination="./output"),
        )
        assert scenario.name == "test-scenario"
        assert scenario.version == "1.0"
        assert scenario.personas == []
        assert scenario.storyline == []

    def test_scenario_invalid_name(self):
        """Test that invalid scenario names are rejected."""
        with pytest.raises(ValidationError):
            Scenario(
                name="test scenario",  # Space not allowed
                description="Test",
                environment=Environment(
                    description="Test",
                    users=[User(username="jdoe", full_name="John", email="j@example.com")],
                    systems=[
                        System(hostname="WS-01", ip="192.168.1.1", os="Windows", type="workstation")
                    ],
                ),
                time_window=TimeWindow(start=datetime(2024, 1, 15, 10, 0, 0), duration="8h"),
                baseline_activity=BaselineActivity(
                    description="Normal", intensity="medium", variation="low"
                ),
                output=OutputSpec(logs=[], destination="./output"),
            )


class TestStateModels:
    """Tests for runtime state dataclasses."""

    def test_active_session(self):
        """Test ActiveSession dataclass."""
        session = ActiveSession(
            logon_id="0x3e7",
            username="jdoe",
            system="WS-01",
            logon_type=2,
            start_time=datetime(2024, 1, 15, 9, 0, 0),
            source_ip="192.168.1.50",
        )
        assert session.logon_id == "0x3e7"
        assert session.logon_type == 2

    def test_running_process(self):
        """Test RunningProcess dataclass."""
        process = RunningProcess(
            pid=1234,
            parent_pid=1000,
            image="cmd.exe",
            command_line="cmd.exe /c dir",
            username="jdoe",
            system="WS-01",
            start_time=datetime(2024, 1, 15, 9, 0, 0),
            integrity_level="Medium",
        )
        assert process.pid == 1234
        assert process.integrity_level == "Medium"

    def test_open_connection(self):
        """Test OpenConnection dataclass."""
        conn = OpenConnection(
            conn_id="conn-123",
            zeek_uid="CwDxijH71E9DtkP5aB",
            src_ip="192.168.1.100",
            src_port=50000,
            dst_ip="8.8.8.8",
            dst_port=53,
            protocol="udp",
            state="established",
            start_time=datetime(2024, 1, 15, 9, 0, 0),
        )
        assert conn.protocol == "udp"
        assert conn.bytes_sent == 0  # Default

    def test_generator_state(self):
        """Test GeneratorState dataclass."""
        state = GeneratorState()
        assert state.active_sessions == {}
        assert state.running_processes == {}
        assert state.open_connections == {}
        assert state.dns_cache == {}
        assert state.current_time is None

    def test_generator_state_with_data(self):
        """Test GeneratorState with data."""
        session = ActiveSession(
            logon_id="0x3e7",
            username="jdoe",
            system="WS-01",
            logon_type=2,
            start_time=datetime(2024, 1, 15, 9, 0, 0),
            source_ip="192.168.1.50",
        )
        process = RunningProcess(
            pid=1234,
            parent_pid=1000,
            image="cmd.exe",
            command_line="cmd.exe /c dir",
            username="jdoe",
            system="WS-01",
            start_time=datetime(2024, 1, 15, 9, 0, 0),
            integrity_level="Medium",
        )
        state = GeneratorState(
            active_sessions={"0x3e7": session}, running_processes={("WS-01", 1234): process}
        )
        assert "0x3e7" in state.active_sessions
        assert state.active_sessions["0x3e7"].username == "jdoe"
        assert ("WS-01", 1234) in state.running_processes
        assert state.running_processes[("WS-01", 1234)].pid == 1234


class TestStaleAccount:
    """Tests for StaleAccount model."""

    def test_valid_stale_account(self):
        """Valid stale account should parse correctly."""
        sa = StaleAccount(
            username="svc_bkup_2019", last_active="2024-06-15", reason="Deprecated backup service"
        )
        assert sa.username == "svc_bkup_2019"
        assert sa.last_active == "2024-06-15"
        assert sa.reason == "Deprecated backup service"

    def test_environment_with_stale_accounts(self):
        """Environment should accept stale_accounts."""
        env = Environment(
            description="Test",
            users=[User(username="u1", full_name="U1", email="u1@x.com")],
            systems=[System(hostname="WS-01", ip="10.0.0.1", os="Windows 10", type="workstation")],
            stale_accounts=[
                StaleAccount(
                    username="old_user", last_active="2023-01-01", reason="Former employee"
                ),
            ],
        )
        assert len(env.stale_accounts) == 1
        assert env.stale_accounts[0].username == "old_user"

    def test_stale_accounts_default_empty(self):
        """stale_accounts should default to empty list."""
        env = Environment(
            description="Test",
            users=[User(username="u1", full_name="U1", email="u1@x.com")],
            systems=[System(hostname="WS-01", ip="10.0.0.1", os="Windows 10", type="workstation")],
        )
        assert env.stale_accounts == []

    def test_stale_account_username_pattern(self):
        """Username must match alphanumeric + ._$- pattern."""
        StaleAccount(username="svc$sqlprod", last_active="2024-01-01", reason="test")
        StaleAccount(username="user.name", last_active="2024-01-01", reason="test")
        StaleAccount(username="sa_mon-01", last_active="2024-01-01", reason="test")

        with pytest.raises(ValidationError):
            StaleAccount(username="bad user", last_active="2024-01-01", reason="test")

        with pytest.raises(ValidationError):
            StaleAccount(username="bad@user", last_active="2024-01-01", reason="test")

    def test_stale_account_forbids_extra(self):
        """Extra fields should be rejected."""
        with pytest.raises(ValidationError):
            StaleAccount(
                username="test", last_active="2024-01-01", reason="test", extra_field="bad"
            )


class TestRedHerringEvent:
    """Tests for RedHerringEvent model."""

    def test_valid_red_herring(self):
        """Valid red herring should parse correctly."""
        rh = RedHerringEvent(
            id="rh-admin-ps",
            time="+26h",
            actor="admin.jones",
            system="SRV-DB-01",
            activity="Admin runs PowerShell for maintenance",
            explanation="Scheduled weekly database maintenance",
            events=[{"type": "process", "process_name": "powershell.exe"}],
        )
        assert rh.id == "rh-admin-ps"
        assert rh.explanation == "Scheduled weekly database maintenance"
        assert len(rh.events) == 1

    def test_red_herring_requires_explanation(self):
        """Explanation field should be required."""
        with pytest.raises(ValidationError, match="explanation"):
            RedHerringEvent(
                id="rh-test",
                time="+1h",
                actor="user1",
                system="WS-01",
                activity="Test",
                events=[{"type": "process", "process_name": "cmd.exe"}],
            )

    def test_scenario_with_red_herrings(self):
        """Scenario should accept red_herrings field."""
        scenario = Scenario(
            version="1.0",
            name="test",
            description="Test",
            environment=Environment(
                description="Test",
                users=[User(username="u1", full_name="U1", email="u1@x.com")],
                systems=[
                    System(hostname="WS-01", ip="10.0.0.1", os="Windows 10", type="workstation")
                ],
            ),
            time_window=TimeWindow(start=datetime(2024, 1, 15, 10, 0, 0), duration="2h"),
            baseline_activity=BaselineActivity(
                description="Test", intensity="medium", variation="low"
            ),
            output=OutputSpec(logs=[{"format": "windows"}], destination="./output"),
            red_herrings=[
                RedHerringEvent(
                    id="rh-1",
                    time="+30m",
                    actor="u1",
                    system="WS-01",
                    activity="Test activity",
                    explanation="Benign explanation",
                    events=[{"type": "process", "process_name": "cmd.exe"}],
                ),
            ],
        )
        assert len(scenario.red_herrings) == 1

    def test_red_herrings_default_empty(self):
        """red_herrings should default to empty list."""
        scenario = Scenario(
            version="1.0",
            name="test",
            description="Test",
            environment=Environment(
                description="Test",
                users=[User(username="u1", full_name="U1", email="u1@x.com")],
                systems=[
                    System(hostname="WS-01", ip="10.0.0.1", os="Windows 10", type="workstation")
                ],
            ),
            time_window=TimeWindow(start=datetime(2024, 1, 15, 10, 0, 0), duration="1h"),
            baseline_activity=BaselineActivity(
                description="Test", intensity="low", variation="low"
            ),
            output=OutputSpec(logs=[{"format": "windows"}], destination="./output"),
        )
        assert scenario.red_herrings == []

    def test_red_herring_events_typed(self):
        """Red herring events should use typed EventSpec union."""
        rh = RedHerringEvent(
            id="rh-conn",
            time="+1h",
            actor="user1",
            system="WS-01",
            activity="Test connection",
            explanation="Legitimate backup",
            events=[
                {"type": "process", "process_name": "cmd.exe"},
                {"type": "connection", "dst_ip": "10.0.0.5", "dst_port": 445},
            ],
        )
        assert len(rh.events) == 2


class TestBaselineActivitySuspiciousNoise:
    """Tests for BaselineActivity.suspicious_noise field."""

    def test_suspicious_noise_default_high(self):
        """suspicious_noise should default to 'high'."""
        ba = BaselineActivity(description="Test", intensity="medium", variation="low")
        assert ba.suspicious_noise == "high"

    def test_suspicious_noise_ludicrous(self):
        """'ludicrous' should be accepted."""
        ba = BaselineActivity(
            description="Test", intensity="medium", variation="low", suspicious_noise="ludicrous"
        )
        assert ba.suspicious_noise == "ludicrous"

    def test_suspicious_noise_all_valid_values(self):
        """All valid values should be accepted."""
        for level in ("low", "medium", "high", "ludicrous"):
            ba = BaselineActivity(
                description="Test", intensity="medium", variation="low", suspicious_noise=level
            )
            assert ba.suspicious_noise == level

    def test_suspicious_noise_invalid(self):
        """Invalid values should be rejected."""
        with pytest.raises(ValidationError):
            BaselineActivity(
                description="Test", intensity="medium", variation="low", suspicious_noise="extreme"
            )


class TestBaselineActivityTrafficRates:
    """Tests for BaselineActivity.traffic_rates field."""

    def test_traffic_rates_default_none(self):
        ba = BaselineActivity(description="Test", intensity="medium", variation="low")
        assert ba.traffic_rates is None

    def test_traffic_rates_empty_dict(self):
        ba = BaselineActivity(
            description="Test", intensity="medium", variation="low", traffic_rates={}
        )
        assert ba.traffic_rates == {}

    def test_traffic_rates_int_value(self):
        ba = BaselineActivity(
            description="Test",
            intensity="medium",
            variation="low",
            traffic_rates={"web": 500},
        )
        assert ba.traffic_rates["web"] == 500

    def test_traffic_rates_list_value(self):
        ba = BaselineActivity(
            description="Test",
            intensity="medium",
            variation="low",
            traffic_rates={"web": [1000, 5000]},
        )
        assert ba.traffic_rates["web"] == [1000, 5000]

    def test_traffic_rates_preset_string(self):
        ba = BaselineActivity(
            description="Test",
            intensity="high",
            variation="low",
            traffic_rates={"web": "low", "kerberos": "medium"},
        )
        assert ba.traffic_rates["web"] == "low"
        assert ba.traffic_rates["kerberos"] == "medium"

    def test_traffic_rates_mixed_types(self):
        ba = BaselineActivity(
            description="Test",
            intensity="high",
            variation="low",
            traffic_rates={"web": [1000, 2000], "kerberos": 10, "ldap": "low"},
        )
        assert ba.traffic_rates["web"] == [1000, 2000]
        assert ba.traffic_rates["kerberos"] == 10
        assert ba.traffic_rates["ldap"] == "low"

    def test_traffic_rates_invalid_key(self):
        with pytest.raises(ValidationError, match="Unknown traffic type"):
            BaselineActivity(
                description="Test",
                intensity="medium",
                variation="low",
                traffic_rates={"bogus_key": 100},
            )

    def test_traffic_rates_negative_int(self):
        with pytest.raises(ValidationError, match="must be > 0"):
            BaselineActivity(
                description="Test",
                intensity="medium",
                variation="low",
                traffic_rates={"web": -5},
            )

    def test_traffic_rates_zero_int(self):
        with pytest.raises(ValidationError, match="must be > 0"):
            BaselineActivity(
                description="Test",
                intensity="medium",
                variation="low",
                traffic_rates={"web": 0},
            )

    def test_traffic_rates_list_lo_gt_hi(self):
        with pytest.raises(ValidationError, match="must be <= hi"):
            BaselineActivity(
                description="Test",
                intensity="medium",
                variation="low",
                traffic_rates={"web": [5000, 1000]},
            )

    def test_traffic_rates_list_wrong_length(self):
        with pytest.raises(ValidationError, match="exactly 2 elements"):
            BaselineActivity(
                description="Test",
                intensity="medium",
                variation="low",
                traffic_rates={"web": [100, 200, 300]},
            )

    def test_traffic_rates_int_above_max(self):
        with pytest.raises(ValidationError, match="must be <="):
            BaselineActivity(
                description="Test",
                intensity="medium",
                variation="low",
                traffic_rates={"web": 50001},
            )

    def test_traffic_rates_list_above_max(self):
        with pytest.raises(ValidationError, match="must be <="):
            BaselineActivity(
                description="Test",
                intensity="medium",
                variation="low",
                traffic_rates={"web": [100, 50001]},
            )

    def test_traffic_rates_invalid_preset_string(self):
        with pytest.raises(ValidationError, match="preset must be one of"):
            BaselineActivity(
                description="Test",
                intensity="medium",
                variation="low",
                traffic_rates={"web": "extreme"},
            )
