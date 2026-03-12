"""Unit tests for scenario validation."""

from datetime import datetime

import pytest

from log_generator.models import (
    BaselineActivity,
    Environment,
    Group,
    OutputSpec,
    Persona,
    Scenario,
    StorylineEvent,
    System,
    TimeWindow,
    User,
)
from log_generator.utils import load_yaml
from log_generator.validation import ScenarioValidator, ValidationIssue


class TestScenarioValidator:
    """Tests for ScenarioValidator class."""

    def test_valid_scenario_no_issues(self, scenarios_dir):
        """Valid scenario should produce no validation issues."""
        scenario_data = load_yaml(scenarios_dir / "minimal.yaml")
        scenario = Scenario(**scenario_data)
        validator = ScenarioValidator(scenario)
        issues = validator.validate()

        assert len(issues) == 0
        assert not validator.has_errors()

    def test_invalid_persona_reference(self):
        """User referencing non-existent persona should error."""
        scenario = Scenario(
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
                        persona="nonexistent_persona"  # Invalid reference
                    )
                ],
                systems=[
                    System(
                        hostname="TEST-01",
                        ip="10.0.0.1",
                        os="Windows 10",
                        type="workstation"
                    )
                ],
            ),
            personas=[
                Persona(
                    name="developer",
                    description="Developer persona",
                    typical_activities=["coding"],
                    work_hours="9-5",
                    application_usage=["vscode"],
                    risk_profile="low"
                )
            ],
            time_window=TimeWindow(
                start=datetime(2024, 1, 15, 10, 0, 0),
                duration="1h"
            ),
            baseline_activity=BaselineActivity(
                description="Test",
                intensity="medium",
                variation="low"
            ),
            output=OutputSpec(
                logs=[{"format": "windows_event_security"}],
                destination="./output",
                compression=False
            ),
        )

        validator = ScenarioValidator(scenario)
        issues = validator.validate()

        assert len(issues) == 1
        assert issues[0].severity == "error"
        assert issues[0].field_path == "environment.users.0.persona"
        assert "nonexistent_persona" in issues[0].message
        assert "developer" in issues[0].suggestion
        assert validator.has_errors()

    def test_invalid_system_assigned_user(self):
        """System assigned_user referencing non-existent user should error."""
        scenario = Scenario(
            version="1.0",
            name="test",
            description="Test scenario",
            environment=Environment(
                description="Test env",
                users=[
                    User(
                        username="testuser",
                        full_name="Test User",
                        email="test@example.com"
                    )
                ],
                systems=[
                    System(
                        hostname="TEST-01",
                        ip="10.0.0.1",
                        os="Windows 10",
                        type="workstation",
                        assigned_user="nonexistent_user"  # Invalid reference
                    )
                ],
            ),
            time_window=TimeWindow(
                start=datetime(2024, 1, 15, 10, 0, 0),
                duration="1h"
            ),
            baseline_activity=BaselineActivity(
                description="Test",
                intensity="medium",
                variation="low"
            ),
            output=OutputSpec(
                logs=[{"format": "windows_event_security"}],
                destination="./output",
                compression=False
            ),
        )

        validator = ScenarioValidator(scenario)
        issues = validator.validate()

        assert len(issues) == 1
        assert issues[0].severity == "error"
        assert issues[0].field_path == "environment.systems.0.assigned_user"
        assert "nonexistent_user" in issues[0].message
        assert "testuser" in issues[0].suggestion

    def test_invalid_user_primary_system(self):
        """User primary_system referencing non-existent system should error."""
        scenario = Scenario(
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
                        primary_system="NONEXISTENT-01"  # Invalid reference
                    )
                ],
                systems=[
                    System(
                        hostname="TEST-01",
                        ip="10.0.0.1",
                        os="Windows 10",
                        type="workstation"
                    )
                ],
            ),
            time_window=TimeWindow(
                start=datetime(2024, 1, 15, 10, 0, 0),
                duration="1h"
            ),
            baseline_activity=BaselineActivity(
                description="Test",
                intensity="medium",
                variation="low"
            ),
            output=OutputSpec(
                logs=[{"format": "windows_event_security"}],
                destination="./output",
                compression=False
            ),
        )

        validator = ScenarioValidator(scenario)
        issues = validator.validate()

        assert len(issues) == 1
        assert issues[0].severity == "error"
        assert issues[0].field_path == "environment.users.0.primary_system"
        assert "NONEXISTENT-01" in issues[0].message
        assert "TEST-01" in issues[0].suggestion

    def test_invalid_group_member(self):
        """Group member referencing non-existent user should error."""
        scenario = Scenario(
            version="1.0",
            name="test",
            description="Test scenario",
            environment=Environment(
                description="Test env",
                users=[
                    User(
                        username="testuser",
                        full_name="Test User",
                        email="test@example.com"
                    )
                ],
                systems=[
                    System(
                        hostname="TEST-01",
                        ip="10.0.0.1",
                        os="Windows 10",
                        type="workstation"
                    )
                ],
                groups=[
                    Group(
                        name="admins",
                        description="Admin group",
                        members=["testuser", "nonexistent_user"],  # One invalid
                        permissions=["admin"]
                    )
                ],
            ),
            time_window=TimeWindow(
                start=datetime(2024, 1, 15, 10, 0, 0),
                duration="1h"
            ),
            baseline_activity=BaselineActivity(
                description="Test",
                intensity="medium",
                variation="low"
            ),
            output=OutputSpec(
                logs=[{"format": "windows_event_security"}],
                destination="./output",
                compression=False
            ),
        )

        validator = ScenarioValidator(scenario)
        issues = validator.validate()

        assert len(issues) == 1
        assert issues[0].severity == "error"
        assert issues[0].field_path == "environment.groups.0.members.1"
        assert "nonexistent_user" in issues[0].message
        assert "testuser" in issues[0].suggestion

    def test_invalid_storyline_actor(self):
        """Storyline actor not in users and not 'attacker' should error."""
        scenario = Scenario(
            version="1.0",
            name="test",
            description="Test scenario",
            environment=Environment(
                description="Test env",
                users=[
                    User(
                        username="testuser",
                        full_name="Test User",
                        email="test@example.com"
                    )
                ],
                systems=[
                    System(
                        hostname="TEST-01",
                        ip="10.0.0.1",
                        os="Windows 10",
                        type="workstation"
                    )
                ],
            ),
            time_window=TimeWindow(
                start=datetime(2024, 1, 15, 10, 0, 0),
                duration="1h"
            ),
            baseline_activity=BaselineActivity(
                description="Test",
                intensity="medium",
                variation="low"
            ),
            storyline=[
                StorylineEvent(
                    time="2024-01-15T10:30:00Z",
                    actor="nonexistent_actor",  # Invalid
                    system="TEST-01",
                    activity="malicious activity",
                    details={}
                )
            ],
            output=OutputSpec(
                logs=[{"format": "windows_event_security"}],
                destination="./output",
                compression=False
            ),
        )

        validator = ScenarioValidator(scenario)
        issues = validator.validate()

        assert len(issues) == 1
        assert issues[0].severity == "error"
        assert issues[0].field_path == "storyline.0.actor"
        assert "nonexistent_actor" in issues[0].message
        assert "testuser" in issues[0].suggestion
        assert "attacker" in issues[0].suggestion

    def test_valid_attacker_actor(self):
        """Storyline actor 'attacker' should be valid."""
        scenario = Scenario(
            version="1.0",
            name="test",
            description="Test scenario",
            environment=Environment(
                description="Test env",
                users=[
                    User(
                        username="testuser",
                        full_name="Test User",
                        email="test@example.com"
                    )
                ],
                systems=[
                    System(
                        hostname="TEST-01",
                        ip="10.0.0.1",
                        os="Windows 10",
                        type="workstation"
                    )
                ],
            ),
            time_window=TimeWindow(
                start=datetime(2024, 1, 15, 10, 0, 0),
                duration="1h"
            ),
            baseline_activity=BaselineActivity(
                description="Test",
                intensity="medium",
                variation="low"
            ),
            storyline=[
                StorylineEvent(
                    time="2024-01-15T10:30:00Z",
                    actor="attacker",  # Valid special actor
                    system="TEST-01",
                    activity="malicious activity",
                    details={}
                )
            ],
            output=OutputSpec(
                logs=[{"format": "windows_event_security"}],
                destination="./output",
                compression=False
            ),
        )

        validator = ScenarioValidator(scenario)
        issues = validator.validate()

        # Should only have 0 issues (attacker is valid)
        assert len(issues) == 0
        assert not validator.has_errors()

    def test_invalid_storyline_system(self):
        """Storyline system not in systems list should error."""
        scenario = Scenario(
            version="1.0",
            name="test",
            description="Test scenario",
            environment=Environment(
                description="Test env",
                users=[
                    User(
                        username="testuser",
                        full_name="Test User",
                        email="test@example.com"
                    )
                ],
                systems=[
                    System(
                        hostname="TEST-01",
                        ip="10.0.0.1",
                        os="Windows 10",
                        type="workstation"
                    )
                ],
            ),
            time_window=TimeWindow(
                start=datetime(2024, 1, 15, 10, 0, 0),
                duration="1h"
            ),
            baseline_activity=BaselineActivity(
                description="Test",
                intensity="medium",
                variation="low"
            ),
            storyline=[
                StorylineEvent(
                    time="2024-01-15T10:30:00Z",
                    actor="attacker",
                    system="NONEXISTENT-01",  # Invalid
                    activity="malicious activity",
                    details={}
                )
            ],
            output=OutputSpec(
                logs=[{"format": "windows_event_security"}],
                destination="./output",
                compression=False
            ),
        )

        validator = ScenarioValidator(scenario)
        issues = validator.validate()

        assert len(issues) == 1
        assert issues[0].severity == "error"
        assert issues[0].field_path == "storyline.0.system"
        assert "NONEXISTENT-01" in issues[0].message
        assert "TEST-01" in issues[0].suggestion

    def test_duplicate_usernames(self):
        """Duplicate usernames should produce error."""
        scenario = Scenario(
            version="1.0",
            name="test",
            description="Test scenario",
            environment=Environment(
                description="Test env",
                users=[
                    User(
                        username="testuser",  # Duplicate
                        full_name="Test User 1",
                        email="test1@example.com"
                    ),
                    User(
                        username="testuser",  # Duplicate
                        full_name="Test User 2",
                        email="test2@example.com"
                    ),
                ],
                systems=[
                    System(
                        hostname="TEST-01",
                        ip="10.0.0.1",
                        os="Windows 10",
                        type="workstation"
                    )
                ],
            ),
            time_window=TimeWindow(
                start=datetime(2024, 1, 15, 10, 0, 0),
                duration="1h"
            ),
            baseline_activity=BaselineActivity(
                description="Test",
                intensity="medium",
                variation="low"
            ),
            output=OutputSpec(
                logs=[{"format": "windows_event_security"}],
                destination="./output",
                compression=False
            ),
        )

        validator = ScenarioValidator(scenario)
        issues = validator.validate()

        assert len(issues) == 1
        assert issues[0].severity == "error"
        assert issues[0].field_path == "environment.users.1.username"
        assert "Duplicate username" in issues[0].message
        assert "testuser" in issues[0].message

    def test_duplicate_hostnames(self):
        """Duplicate hostnames should produce error."""
        scenario = Scenario(
            version="1.0",
            name="test",
            description="Test scenario",
            environment=Environment(
                description="Test env",
                users=[
                    User(
                        username="testuser",
                        full_name="Test User",
                        email="test@example.com"
                    )
                ],
                systems=[
                    System(
                        hostname="TEST-01",  # Duplicate
                        ip="10.0.0.1",
                        os="Windows 10",
                        type="workstation"
                    ),
                    System(
                        hostname="TEST-01",  # Duplicate
                        ip="10.0.0.2",
                        os="Windows 10",
                        type="workstation"
                    ),
                ],
            ),
            time_window=TimeWindow(
                start=datetime(2024, 1, 15, 10, 0, 0),
                duration="1h"
            ),
            baseline_activity=BaselineActivity(
                description="Test",
                intensity="medium",
                variation="low"
            ),
            output=OutputSpec(
                logs=[{"format": "windows_event_security"}],
                destination="./output",
                compression=False
            ),
        )

        validator = ScenarioValidator(scenario)
        issues = validator.validate()

        assert len(issues) == 1
        assert issues[0].severity == "error"
        assert issues[0].field_path == "environment.systems.1.hostname"
        assert "Duplicate hostname" in issues[0].message
        assert "TEST-01" in issues[0].message

    def test_duplicate_ips(self):
        """Duplicate IP addresses should produce error."""
        scenario = Scenario(
            version="1.0",
            name="test",
            description="Test scenario",
            environment=Environment(
                description="Test env",
                users=[
                    User(
                        username="testuser",
                        full_name="Test User",
                        email="test@example.com"
                    )
                ],
                systems=[
                    System(
                        hostname="TEST-01",
                        ip="10.0.0.1",  # Duplicate
                        os="Windows 10",
                        type="workstation"
                    ),
                    System(
                        hostname="TEST-02",
                        ip="10.0.0.1",  # Duplicate
                        os="Windows 10",
                        type="workstation"
                    ),
                ],
            ),
            time_window=TimeWindow(
                start=datetime(2024, 1, 15, 10, 0, 0),
                duration="1h"
            ),
            baseline_activity=BaselineActivity(
                description="Test",
                intensity="medium",
                variation="low"
            ),
            output=OutputSpec(
                logs=[{"format": "windows_event_security"}],
                destination="./output",
                compression=False
            ),
        )

        validator = ScenarioValidator(scenario)
        issues = validator.validate()

        assert len(issues) == 1
        assert issues[0].severity == "error"
        assert issues[0].field_path == "environment.systems.1.ip"
        assert "Duplicate IP" in issues[0].message
        assert "10.0.0.1" in issues[0].message

    def test_field_path_format(self):
        """Field paths should follow environment.users.0.persona format."""
        scenario = Scenario(
            version="1.0",
            name="test",
            description="Test scenario",
            environment=Environment(
                description="Test env",
                users=[
                    User(
                        username="user1",
                        full_name="User 1",
                        email="user1@example.com",
                        persona="invalid"
                    ),
                    User(
                        username="user2",
                        full_name="User 2",
                        email="user2@example.com",
                        primary_system="INVALID"
                    ),
                ],
                systems=[
                    System(
                        hostname="TEST-01",
                        ip="10.0.0.1",
                        os="Windows 10",
                        type="workstation"
                    )
                ],
            ),
            time_window=TimeWindow(
                start=datetime(2024, 1, 15, 10, 0, 0),
                duration="1h"
            ),
            baseline_activity=BaselineActivity(
                description="Test",
                intensity="medium",
                variation="low"
            ),
            output=OutputSpec(
                logs=[{"format": "windows_event_security"}],
                destination="./output",
                compression=False
            ),
        )

        validator = ScenarioValidator(scenario)
        issues = validator.validate()

        # Verify field path format
        assert any(issue.field_path == "environment.users.0.persona" for issue in issues)
        assert any(issue.field_path == "environment.users.1.primary_system" for issue in issues)

    def test_suggestions_provided(self):
        """Validation issues should include helpful suggestions."""
        scenario = Scenario(
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
                        persona="invalid"
                    )
                ],
                systems=[
                    System(
                        hostname="TEST-01",
                        ip="10.0.0.1",
                        os="Windows 10",
                        type="workstation"
                    )
                ],
            ),
            personas=[
                Persona(
                    name="developer",
                    description="Developer",
                    typical_activities=["coding"],
                    work_hours="9-5",
                    application_usage=["vscode"],
                    risk_profile="low"
                ),
                Persona(
                    name="executive",
                    description="Executive",
                    typical_activities=["email"],
                    work_hours="8-6",
                    application_usage=["outlook"],
                    risk_profile="medium"
                ),
            ],
            time_window=TimeWindow(
                start=datetime(2024, 1, 15, 10, 0, 0),
                duration="1h"
            ),
            baseline_activity=BaselineActivity(
                description="Test",
                intensity="medium",
                variation="low"
            ),
            output=OutputSpec(
                logs=[{"format": "windows_event_security"}],
                destination="./output",
                compression=False
            ),
        )

        validator = ScenarioValidator(scenario)
        issues = validator.validate()

        assert len(issues) == 1
        assert issues[0].suggestion is not None
        assert "developer" in issues[0].suggestion
        assert "executive" in issues[0].suggestion

    def test_multiple_issues_collected(self):
        """Multiple validation issues should all be collected."""
        scenario = Scenario(
            version="1.0",
            name="test",
            description="Test scenario",
            environment=Environment(
                description="Test env",
                users=[
                    User(
                        username="user1",
                        full_name="User 1",
                        email="user1@example.com",
                        persona="invalid_persona",  # Issue 1
                        primary_system="INVALID-SYS"  # Issue 2
                    ),
                    User(
                        username="user1",  # Issue 3: duplicate
                        full_name="User 1 Dup",
                        email="user1dup@example.com"
                    ),
                ],
                systems=[
                    System(
                        hostname="TEST-01",
                        ip="10.0.0.1",
                        os="Windows 10",
                        type="workstation",
                        assigned_user="invalid_user"  # Issue 4
                    )
                ],
            ),
            time_window=TimeWindow(
                start=datetime(2024, 1, 15, 10, 0, 0),
                duration="1h"
            ),
            baseline_activity=BaselineActivity(
                description="Test",
                intensity="medium",
                variation="low"
            ),
            output=OutputSpec(
                logs=[{"format": "windows_event_security"}],
                destination="./output",
                compression=False
            ),
        )

        validator = ScenarioValidator(scenario)
        issues = validator.validate()

        # Should collect all 4 issues
        assert len(issues) == 4
        assert validator.has_errors()

        # Verify each issue type is present
        field_paths = [issue.field_path for issue in issues]
        assert "environment.users.0.persona" in field_paths
        assert "environment.users.0.primary_system" in field_paths
        assert "environment.users.1.username" in field_paths
        assert "environment.systems.0.assigned_user" in field_paths
