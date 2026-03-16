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
    RunningProcess,
    Scenario,
    StorylineEvent,
    System,
    TimeWindow,
    Timezone,
    User,
)
from evidenceforge.models.exceptions import EvidenceForgeError, ValidationError as VError


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
        tw = TimeWindow(
            start=datetime(2024, 1, 15, 10, 0, 0), end=datetime(2024, 1, 15, 18, 0, 0)
        )
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
        system = System(
            hostname="SRV-01", ip="192.168.1.1", os="Linux", type="server"
        )
        assert system.assigned_user is None
        assert system.services == []

    def test_system_valid_ipv6(self):
        """Test system with IPv6 address."""
        system = System(
            hostname="SRV-01", ip="2001:db8::1", os="Linux", type="server"
        )
        assert system.ip == "2001:db8::1"

    def test_system_invalid_ip(self):
        """Test that invalid IPs are rejected."""
        with pytest.raises(ValidationError, match="Invalid IP"):
            System(
                hostname="WS-01", ip="999.999.999.999", os="Windows 10", type="workstation"
            )

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


class TestEnvironment:
    """Tests for Environment model."""

    def test_environment_valid(self):
        """Test valid environment creation."""
        env = Environment(
            description="Test environment",
            users=[
                User(username="jdoe", full_name="John Doe", email="jdoe@example.com")
            ],
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
                systems=[
                    System(hostname="SRV-01", ip="192.168.1.1", os="Linux", type="server")
                ],
            )

    def test_environment_requires_systems(self):
        """Test that environment requires at least one system."""
        with pytest.raises(ValidationError, match="at least one system"):
            Environment(
                description="Test",
                users=[
                    User(username="jdoe", full_name="John", email="j@example.com")
                ],
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
                description="Test", intensity="invalid", variation="low"  # type: ignore
            )


class TestStorylineEvent:
    """Tests for StorylineEvent model."""

    def test_storyline_event_valid(self):
        """Test valid storyline event."""
        event = StorylineEvent(
            time="2024-01-15T14:30:00Z",
            actor="attacker",
            system="WS-01",
            activity="Execute malicious payload",
            details={"file": "malware.exe"},
        )
        assert event.actor == "attacker"
        assert event.details is not None
        assert event.details["file"] == "malware.exe"

    def test_storyline_event_defaults(self):
        """Test storyline event default values."""
        event = StorylineEvent(
            time="+2h30m", actor="jdoe", system="WS-01", activity="Access file share"
        )
        assert event.details == {}


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
                users=[
                    User(username="jdoe", full_name="John", email="j@example.com")
                ],
                systems=[
                    System(hostname="WS-01", ip="192.168.1.1", os="Windows", type="workstation")
                ],
            ),
            time_window=TimeWindow(
                start=datetime(2024, 1, 15, 10, 0, 0), duration="8h"
            ),
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
                    users=[
                        User(
                            username="jdoe", full_name="John", email="j@example.com"
                        )
                    ],
                    systems=[
                        System(hostname="WS-01", ip="192.168.1.1", os="Windows", type="workstation")
                    ],
                ),
                time_window=TimeWindow(
                    start=datetime(2024, 1, 15, 10, 0, 0), duration="8h"
                ),
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
            active_sessions={"0x3e7": session},
            running_processes={("WS-01", 1234): process}
        )
        assert "0x3e7" in state.active_sessions
        assert state.active_sessions["0x3e7"].username == "jdoe"
        assert ("WS-01", 1234) in state.running_processes
        assert state.running_processes[("WS-01", 1234)].pid == 1234
