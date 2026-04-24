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

"""Unit tests for scenario validation."""

from datetime import datetime

import pytest

from evidenceforge.models import (
    BaselineActivity,
    Environment,
    Group,
    NetworkConfig,
    NetworkSegment,
    NetworkSensor,
    OutputSpec,
    Persona,
    ProxyConfig,
    RedHerringEvent,
    Scenario,
    StaleAccount,
    StorylineEvent,
    System,
    TimeWindow,
    User,
)
from evidenceforge.utils import load_yaml
from evidenceforge.validation import ScenarioValidator
from evidenceforge.validation.schema import BUILTIN_ACCOUNTS


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
                        persona="nonexistent_persona",  # Invalid reference
                        primary_system="TEST-01",
                    )
                ],
                systems=[
                    System(hostname="TEST-01", ip="10.0.0.1", os="Windows 10", type="workstation")
                ],
            ),
            personas=[
                Persona(
                    name="developer",
                    description="Developer persona",
                    typical_activities=["coding"],
                    work_hours="9-5",
                    application_usage=["vscode"],
                    risk_profile="low",
                )
            ],
            time_window=TimeWindow(start=datetime(2024, 1, 15, 10, 0, 0), duration="1h"),
            baseline_activity=BaselineActivity(
                description="Test", intensity="medium", variation="low"
            ),
            output=OutputSpec(
                logs=[{"format": "windows"}], destination="./output", compression=False
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

    def test_storyline_event_outside_time_window_warns(self):
        """Storyline events outside the generation window should warn."""
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
                        primary_system="TEST-01",
                    )
                ],
                systems=[
                    System(hostname="TEST-01", ip="10.0.0.1", os="Windows 10", type="workstation")
                ],
            ),
            time_window=TimeWindow(start=datetime(2024, 1, 15, 10, 0, 0), duration="1h"),
            baseline_activity=BaselineActivity(
                description="Test", intensity="medium", variation="low"
            ),
            storyline=[
                StorylineEvent(
                    id="evt-val-001",
                    time="+2h",
                    actor="testuser",
                    system="TEST-01",
                    activity="malicious activity",
                    events=[{"type": "process", "process_name": "cmd.exe"}],
                )
            ],
            output=OutputSpec(
                logs=[{"format": "windows_event_security"}],
                destination="./output",
                compression=False,
            ),
        )

        issues = ScenarioValidator(scenario).validate()

        assert any(
            issue.severity == "warning"
            and issue.field_path == "storyline.0.time"
            and "outside the configured time_window" in issue.message
            for issue in issues
        )

    def test_invalid_system_assigned_user(self):
        """System assigned_user referencing non-existent user should error."""
        scenario = Scenario(
            version="1.0",
            name="test",
            description="Test scenario",
            environment=Environment(
                description="Test env",
                users=[User(username="testuser", full_name="Test User", email="test@example.com")],
                systems=[
                    System(
                        hostname="TEST-01",
                        ip="10.0.0.1",
                        os="Windows 10",
                        type="workstation",
                        assigned_user="nonexistent_user",  # Invalid reference
                    )
                ],
            ),
            time_window=TimeWindow(start=datetime(2024, 1, 15, 10, 0, 0), duration="1h"),
            baseline_activity=BaselineActivity(
                description="Test", intensity="medium", variation="low"
            ),
            output=OutputSpec(
                logs=[{"format": "windows"}], destination="./output", compression=False
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
                        primary_system="NONEXISTENT-01",  # Invalid reference
                    )
                ],
                systems=[
                    System(hostname="TEST-01", ip="10.0.0.1", os="Windows 10", type="workstation")
                ],
            ),
            time_window=TimeWindow(start=datetime(2024, 1, 15, 10, 0, 0), duration="1h"),
            baseline_activity=BaselineActivity(
                description="Test", intensity="medium", variation="low"
            ),
            output=OutputSpec(
                logs=[{"format": "windows"}], destination="./output", compression=False
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
                users=[User(username="testuser", full_name="Test User", email="test@example.com")],
                systems=[
                    System(hostname="TEST-01", ip="10.0.0.1", os="Windows 10", type="workstation")
                ],
                groups=[
                    Group(
                        name="admins",
                        description="Admin group",
                        members=["testuser", "nonexistent_user"],  # One invalid
                        permissions=["admin"],
                    )
                ],
            ),
            time_window=TimeWindow(start=datetime(2024, 1, 15, 10, 0, 0), duration="1h"),
            baseline_activity=BaselineActivity(
                description="Test", intensity="medium", variation="low"
            ),
            output=OutputSpec(
                logs=[{"format": "windows"}], destination="./output", compression=False
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
        """Storyline actor not in users list should error."""
        scenario = Scenario(
            version="1.0",
            name="test",
            description="Test scenario",
            environment=Environment(
                description="Test env",
                users=[User(username="testuser", full_name="Test User", email="test@example.com")],
                systems=[
                    System(hostname="TEST-01", ip="10.0.0.1", os="Windows 10", type="workstation")
                ],
            ),
            time_window=TimeWindow(start=datetime(2024, 1, 15, 10, 0, 0), duration="1h"),
            baseline_activity=BaselineActivity(
                description="Test", intensity="medium", variation="low"
            ),
            storyline=[
                StorylineEvent(
                    id="evt-val-001",
                    time="2024-01-15T10:30:00Z",
                    actor="nonexistent_actor",  # Invalid
                    system="TEST-01",
                    activity="malicious activity",
                    events=[{"type": "process", "process_name": "cmd.exe"}],
                )
            ],
            output=OutputSpec(
                logs=[{"format": "windows"}], destination="./output", compression=False
            ),
        )

        validator = ScenarioValidator(scenario)
        issues = validator.validate()

        assert len(issues) == 1
        assert issues[0].severity == "error"
        assert issues[0].field_path == "storyline.0.actor"
        assert "nonexistent_actor" in issues[0].message
        assert "testuser" in issues[0].suggestion

    def test_actor_must_be_in_users_list(self):
        """Storyline actor must be a defined user, even if named 'attacker'."""
        scenario = Scenario(
            version="1.0",
            name="test",
            description="Test scenario",
            environment=Environment(
                description="Test env",
                users=[User(username="testuser", full_name="Test User", email="test@example.com")],
                systems=[
                    System(hostname="TEST-01", ip="10.0.0.1", os="Windows 10", type="workstation")
                ],
            ),
            time_window=TimeWindow(start=datetime(2024, 1, 15, 10, 0, 0), duration="1h"),
            baseline_activity=BaselineActivity(
                description="Test", intensity="medium", variation="low"
            ),
            storyline=[
                StorylineEvent(
                    id="evt-val-002",
                    time="2024-01-15T10:30:00Z",
                    actor="attacker",  # Not in users list — should fail
                    system="TEST-01",
                    activity="malicious activity",
                    events=[{"type": "process", "process_name": "cmd.exe"}],
                )
            ],
            output=OutputSpec(
                logs=[{"format": "windows"}], destination="./output", compression=False
            ),
        )

        validator = ScenarioValidator(scenario)
        issues = validator.validate()

        # "attacker" is not in the users list, so it should be flagged
        assert len(issues) == 1
        assert issues[0].severity == "error"
        assert "attacker" in issues[0].message

    def test_invalid_storyline_system(self):
        """Storyline system not in systems list should error."""
        scenario = Scenario(
            version="1.0",
            name="test",
            description="Test scenario",
            environment=Environment(
                description="Test env",
                users=[User(username="testuser", full_name="Test User", email="test@example.com")],
                systems=[
                    System(hostname="TEST-01", ip="10.0.0.1", os="Windows 10", type="workstation")
                ],
            ),
            time_window=TimeWindow(start=datetime(2024, 1, 15, 10, 0, 0), duration="1h"),
            baseline_activity=BaselineActivity(
                description="Test", intensity="medium", variation="low"
            ),
            storyline=[
                StorylineEvent(
                    id="evt-val-003",
                    time="2024-01-15T10:30:00Z",
                    actor="testuser",
                    system="NONEXISTENT-01",  # Invalid
                    activity="malicious activity",
                    events=[{"type": "process", "process_name": "cmd.exe"}],
                )
            ],
            output=OutputSpec(
                logs=[{"format": "windows"}], destination="./output", compression=False
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
                        email="test1@example.com",
                    ),
                    User(
                        username="testuser",  # Duplicate
                        full_name="Test User 2",
                        email="test2@example.com",
                    ),
                ],
                systems=[
                    System(hostname="TEST-01", ip="10.0.0.1", os="Windows 10", type="workstation")
                ],
            ),
            time_window=TimeWindow(start=datetime(2024, 1, 15, 10, 0, 0), duration="1h"),
            baseline_activity=BaselineActivity(
                description="Test", intensity="medium", variation="low"
            ),
            output=OutputSpec(
                logs=[{"format": "windows"}], destination="./output", compression=False
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
                users=[User(username="testuser", full_name="Test User", email="test@example.com")],
                systems=[
                    System(
                        hostname="TEST-01",  # Duplicate
                        ip="10.0.0.1",
                        os="Windows 10",
                        type="workstation",
                    ),
                    System(
                        hostname="TEST-01",  # Duplicate
                        ip="10.0.0.2",
                        os="Windows 10",
                        type="workstation",
                    ),
                ],
            ),
            time_window=TimeWindow(start=datetime(2024, 1, 15, 10, 0, 0), duration="1h"),
            baseline_activity=BaselineActivity(
                description="Test", intensity="medium", variation="low"
            ),
            output=OutputSpec(
                logs=[{"format": "windows"}], destination="./output", compression=False
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
                users=[User(username="testuser", full_name="Test User", email="test@example.com")],
                systems=[
                    System(
                        hostname="TEST-01",
                        ip="10.0.0.1",  # Duplicate
                        os="Windows 10",
                        type="workstation",
                    ),
                    System(
                        hostname="TEST-02",
                        ip="10.0.0.1",  # Duplicate
                        os="Windows 10",
                        type="workstation",
                    ),
                ],
            ),
            time_window=TimeWindow(start=datetime(2024, 1, 15, 10, 0, 0), duration="1h"),
            baseline_activity=BaselineActivity(
                description="Test", intensity="medium", variation="low"
            ),
            output=OutputSpec(
                logs=[{"format": "windows"}], destination="./output", compression=False
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
                        persona="invalid",
                    ),
                    User(
                        username="user2",
                        full_name="User 2",
                        email="user2@example.com",
                        primary_system="INVALID",
                    ),
                ],
                systems=[
                    System(hostname="TEST-01", ip="10.0.0.1", os="Windows 10", type="workstation")
                ],
            ),
            time_window=TimeWindow(start=datetime(2024, 1, 15, 10, 0, 0), duration="1h"),
            baseline_activity=BaselineActivity(
                description="Test", intensity="medium", variation="low"
            ),
            output=OutputSpec(
                logs=[{"format": "windows"}], destination="./output", compression=False
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
                        persona="invalid",
                        primary_system="TEST-01",
                    )
                ],
                systems=[
                    System(hostname="TEST-01", ip="10.0.0.1", os="Windows 10", type="workstation")
                ],
            ),
            personas=[
                Persona(
                    name="developer",
                    description="Developer",
                    typical_activities=["coding"],
                    work_hours="9-5",
                    application_usage=["vscode"],
                    risk_profile="low",
                ),
                Persona(
                    name="executive",
                    description="Executive",
                    typical_activities=["email"],
                    work_hours="8-6",
                    application_usage=["outlook"],
                    risk_profile="medium",
                ),
            ],
            time_window=TimeWindow(start=datetime(2024, 1, 15, 10, 0, 0), duration="1h"),
            baseline_activity=BaselineActivity(
                description="Test", intensity="medium", variation="low"
            ),
            output=OutputSpec(
                logs=[{"format": "windows"}], destination="./output", compression=False
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
                        primary_system="INVALID-SYS",  # Issue 2
                    ),
                    User(
                        username="user1",  # Issue 3: duplicate
                        full_name="User 1 Dup",
                        email="user1dup@example.com",
                    ),
                ],
                systems=[
                    System(
                        hostname="TEST-01",
                        ip="10.0.0.1",
                        os="Windows 10",
                        type="workstation",
                        assigned_user="invalid_user",  # Issue 4
                    )
                ],
            ),
            time_window=TimeWindow(start=datetime(2024, 1, 15, 10, 0, 0), duration="1h"),
            baseline_activity=BaselineActivity(
                description="Test", intensity="medium", variation="low"
            ),
            output=OutputSpec(
                logs=[{"format": "windows"}], destination="./output", compression=False
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

    def test_valid_expanded_activities(self):
        """Valid expanded_activities should produce no issues."""
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
                        persona="dev",
                        primary_system="TEST-01",
                    )
                ],
                systems=[
                    System(hostname="TEST-01", ip="10.0.0.1", os="Windows 10", type="workstation")
                ],
            ),
            personas=[
                Persona(
                    name="dev",
                    description="Developer",
                    typical_activities=["coding"],
                    expanded_activities=[
                        {"activity_type": "process_code", "sequence": [{"action": "open_ide"}]},
                        {"activity_type": "connection_web"},
                    ],
                )
            ],
            time_window=TimeWindow(start=datetime(2024, 1, 15, 10, 0, 0), duration="1h"),
            baseline_activity=BaselineActivity(
                description="Test", intensity="medium", variation="low"
            ),
            output=OutputSpec(logs=[{"format": "windows"}], destination="./output"),
        )

        validator = ScenarioValidator(scenario)
        issues = validator.validate()
        assert len(issues) == 0

    def test_expanded_activities_missing_activity_type(self):
        """expanded_activities item without activity_type should error."""
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
                        persona="dev",
                        primary_system="TEST-01",
                    )
                ],
                systems=[
                    System(hostname="TEST-01", ip="10.0.0.1", os="Windows 10", type="workstation")
                ],
            ),
            personas=[
                Persona(
                    name="dev",
                    description="Developer",
                    typical_activities=["coding"],
                    expanded_activities=[
                        {"sequence": [{"action": "open_ide"}]},  # Missing activity_type
                    ],
                )
            ],
            time_window=TimeWindow(start=datetime(2024, 1, 15, 10, 0, 0), duration="1h"),
            baseline_activity=BaselineActivity(
                description="Test", intensity="medium", variation="low"
            ),
            output=OutputSpec(logs=[{"format": "windows"}], destination="./output"),
        )

        validator = ScenarioValidator(scenario)
        issues = validator.validate()

        assert len(issues) == 1
        assert issues[0].severity == "error"
        assert "expanded_activities" in issues[0].field_path
        assert "activity_type" in issues[0].message

    def test_expanded_activities_invalid_sequence_type(self):
        """expanded_activities with non-list sequence should error."""
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
                        persona="dev",
                        primary_system="TEST-01",
                    )
                ],
                systems=[
                    System(hostname="TEST-01", ip="10.0.0.1", os="Windows 10", type="workstation")
                ],
            ),
            personas=[
                Persona(
                    name="dev",
                    description="Developer",
                    typical_activities=["coding"],
                    expanded_activities=[
                        {"activity_type": "process_code", "sequence": "not_a_list"},
                    ],
                )
            ],
            time_window=TimeWindow(start=datetime(2024, 1, 15, 10, 0, 0), duration="1h"),
            baseline_activity=BaselineActivity(
                description="Test", intensity="medium", variation="low"
            ),
            output=OutputSpec(logs=[{"format": "windows"}], destination="./output"),
        )

        validator = ScenarioValidator(scenario)
        issues = validator.validate()

        assert len(issues) == 1
        assert "sequence" in issues[0].field_path
        assert "must be a list" in issues[0].message

    def test_none_optional_fields_no_issues(self):
        """Personas/events with None optional fields should produce no issues."""
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
                        persona="dev",
                        primary_system="TEST-01",
                    )
                ],
                systems=[
                    System(hostname="TEST-01", ip="10.0.0.1", os="Windows 10", type="workstation")
                ],
            ),
            personas=[
                Persona(
                    name="dev",
                    description="Developer",
                    typical_activities=["coding"],
                    # expanded_activities=None (default)
                )
            ],
            time_window=TimeWindow(start=datetime(2024, 1, 15, 10, 0, 0), duration="1h"),
            baseline_activity=BaselineActivity(
                description="Test", intensity="medium", variation="low"
            ),
            storyline=[
                StorylineEvent(
                    id="evt-val-004",
                    time="2024-01-15T10:00:00Z",
                    actor="testuser",
                    system="TEST-01",
                    activity="logon",
                    events=[{"type": "logon", "logon_type": 2}],
                ),
                StorylineEvent(
                    id="evt-val-005",
                    time="2024-01-15T10:30:00Z",
                    actor="testuser",
                    system="TEST-01",
                    activity="simple attack",
                    events=[{"type": "process", "process_name": "cmd.exe"}],
                ),
            ],
            output=OutputSpec(logs=[{"format": "windows"}], destination="./output"),
        )

        validator = ScenarioValidator(scenario)
        issues = validator.validate()
        assert len(issues) == 0

    @pytest.mark.parametrize(
        "actor_name", ["SYSTEM", "root", "NT AUTHORITY\\SYSTEM", "LOCAL SERVICE"]
    )
    def test_builtin_accounts_valid_as_actors(self, actor_name):
        """Built-in OS accounts should be valid storyline actors without being in users list."""
        scenario = Scenario(
            version="1.0",
            name="test",
            description="Test scenario",
            environment=Environment(
                description="Test env",
                users=[User(username="testuser", full_name="Test User", email="test@example.com")],
                systems=[
                    System(hostname="TEST-01", ip="10.0.0.1", os="Windows 10", type="workstation")
                ],
            ),
            time_window=TimeWindow(start=datetime(2024, 1, 15, 10, 0, 0), duration="1h"),
            baseline_activity=BaselineActivity(
                description="Test", intensity="medium", variation="low"
            ),
            storyline=[
                StorylineEvent(
                    id="evt-val-006",
                    time="2024-01-15T10:30:00Z",
                    actor=actor_name,
                    system="TEST-01",
                    activity="system-level activity",
                    events=[{"type": "process", "process_name": "cmd.exe"}],
                )
            ],
            output=OutputSpec(logs=[{"format": "windows"}], destination="./output"),
        )

        validator = ScenarioValidator(scenario)
        issues = validator.validate()
        actor_issues = [i for i in issues if "actor" in i.field_path]
        assert len(actor_issues) == 0

    def test_custom_service_accounts_valid_as_actors(self):
        """Custom service accounts in environment.service_accounts should be valid actors."""
        scenario = Scenario(
            version="1.0",
            name="test",
            description="Test scenario",
            environment=Environment(
                description="Test env",
                users=[User(username="testuser", full_name="Test User", email="test@example.com")],
                systems=[
                    System(hostname="TEST-01", ip="10.0.0.1", os="Windows 10", type="workstation")
                ],
                service_accounts=["svc_backup", "apache"],
            ),
            time_window=TimeWindow(start=datetime(2024, 1, 15, 10, 0, 0), duration="1h"),
            baseline_activity=BaselineActivity(
                description="Test", intensity="medium", variation="low"
            ),
            storyline=[
                StorylineEvent(
                    id="evt-val-007",
                    time="2024-01-15T10:30:00Z",
                    actor="svc_backup",
                    system="TEST-01",
                    activity="backup service activity",
                    events=[{"type": "process", "process_name": "cmd.exe"}],
                )
            ],
            output=OutputSpec(logs=[{"format": "windows"}], destination="./output"),
        )

        validator = ScenarioValidator(scenario)
        issues = validator.validate()
        actor_issues = [i for i in issues if "actor" in i.field_path]
        assert len(actor_issues) == 0

    def test_unknown_actor_still_rejected(self):
        """Actors not in users, built-in accounts, or service_accounts should still fail."""
        scenario = Scenario(
            version="1.0",
            name="test",
            description="Test scenario",
            environment=Environment(
                description="Test env",
                users=[User(username="testuser", full_name="Test User", email="test@example.com")],
                systems=[
                    System(hostname="TEST-01", ip="10.0.0.1", os="Windows 10", type="workstation")
                ],
                service_accounts=["svc_backup"],
            ),
            time_window=TimeWindow(start=datetime(2024, 1, 15, 10, 0, 0), duration="1h"),
            baseline_activity=BaselineActivity(
                description="Test", intensity="medium", variation="low"
            ),
            storyline=[
                StorylineEvent(
                    id="evt-val-008",
                    time="2024-01-15T10:30:00Z",
                    actor="totally_unknown",
                    system="TEST-01",
                    activity="suspicious activity",
                    events=[{"type": "process", "process_name": "cmd.exe"}],
                )
            ],
            output=OutputSpec(logs=[{"format": "windows"}], destination="./output"),
        )

        validator = ScenarioValidator(scenario)
        issues = validator.validate()
        assert any(i.severity == "error" and "totally_unknown" in i.message for i in issues)

    def test_builtin_accounts_constant_is_nonempty(self):
        """BUILTIN_ACCOUNTS should contain well-known OS accounts."""
        assert len(BUILTIN_ACCOUNTS) > 0
        assert "SYSTEM" in BUILTIN_ACCOUNTS
        assert "root" in BUILTIN_ACCOUNTS


class TestNetworkValidation:
    """Tests for network topology validation."""

    def _make_scenario_with_network(self, network_config):
        """Helper to create a scenario with network config."""
        return Scenario(
            version="1.0",
            name="test",
            description="Test scenario",
            environment=Environment(
                description="Test env",
                users=[User(username="testuser", full_name="Test User", email="test@example.com")],
                systems=[
                    System(hostname="WS-01", ip="10.10.10.1", os="Windows 10", type="workstation"),
                    System(
                        hostname="SRV-01", ip="10.10.30.1", os="Windows Server 2019", type="server"
                    ),
                ],
                network=network_config,
            ),
            time_window=TimeWindow(start=datetime(2024, 1, 15, 10, 0, 0), duration="1h"),
            baseline_activity=BaselineActivity(
                description="Test", intensity="medium", variation="low"
            ),
            output=OutputSpec(logs=[{"format": "windows"}], destination="./output"),
        )

    def test_valid_network_config(self):
        """Valid network config should produce no issues."""
        scenario = self._make_scenario_with_network(
            NetworkConfig(
                segments=[
                    NetworkSegment(
                        name="workstations",
                        cidr="10.10.10.0/24",
                        systems=["WS-01"],
                        exposure="internal",
                    ),
                    NetworkSegment(
                        name="servers",
                        cidr="10.10.30.0/24",
                        systems=["SRV-01"],
                        exposure="internal",
                    ),
                ],
                sensors=[
                    NetworkSensor(
                        type="network",
                        name="tap",
                        monitoring_segments=["workstations", "servers"],
                        log_formats=["zeek"],
                    ),
                ],
            )
        )
        validator = ScenarioValidator(scenario)
        issues = validator.validate()
        assert len(issues) == 0

    def test_segment_references_undefined_system(self):
        """Segment referencing undefined system should error."""
        scenario = self._make_scenario_with_network(
            NetworkConfig(
                segments=[
                    NetworkSegment(
                        name="workstations",
                        cidr="10.10.10.0/24",
                        systems=["WS-01", "NONEXISTENT"],
                        exposure="internal",
                    ),
                ],
                sensors=[
                    NetworkSensor(type="network", name="tap", monitoring_segments=["workstations"]),
                ],
            )
        )
        validator = ScenarioValidator(scenario)
        issues = validator.validate()

        errors = [i for i in issues if i.severity == "error"]
        assert len(errors) == 1
        assert "NONEXISTENT" in errors[0].message
        assert "segments" in errors[0].field_path

    def test_sensor_references_undefined_segment(self):
        """Sensor referencing undefined segment should error."""
        scenario = self._make_scenario_with_network(
            NetworkConfig(
                segments=[
                    NetworkSegment(name="workstations", cidr="10.10.10.0/24", exposure="internal"),
                ],
                sensors=[
                    NetworkSensor(
                        type="network",
                        name="tap",
                        monitoring_segments=["workstations", "nonexistent"],
                    ),
                ],
            )
        )
        validator = ScenarioValidator(scenario)
        issues = validator.validate()

        errors = [i for i in issues if i.severity == "error"]
        assert len(errors) == 1
        assert "nonexistent" in errors[0].message
        assert "sensors" in errors[0].field_path

    def test_system_ip_outside_cidr_warning(self):
        """System IP not matching segment CIDR should produce warning."""
        scenario = self._make_scenario_with_network(
            NetworkConfig(
                segments=[
                    NetworkSegment(
                        name="wrong_subnet",
                        cidr="192.168.1.0/24",
                        systems=["WS-01"],
                        exposure="internal",
                    ),
                ],
                sensors=[
                    NetworkSensor(type="network", name="tap", monitoring_segments=["wrong_subnet"]),
                ],
            )
        )
        validator = ScenarioValidator(scenario)
        issues = validator.validate()

        warnings = [i for i in issues if i.severity == "warning"]
        assert len(warnings) == 1
        assert "10.10.10.1" in warnings[0].message
        assert "192.168.1.0/24" in warnings[0].message

    def test_no_network_config_no_issues(self):
        """Scenario without network config should produce no network-related issues."""
        scenario = self._make_scenario_with_network(None)
        validator = ScenarioValidator(scenario)
        issues = validator.validate()
        assert len(issues) == 0


class TestNetworkSegmentExternalRatio:
    """Tests for NetworkSegment.external_ratio field validation."""

    def test_external_ratio_on_both_segment_ok(self):
        """external_ratio is valid when exposure='both'."""
        seg = NetworkSegment(name="dmz", cidr="10.0.3.0/24", exposure="both", external_ratio=0.9)
        assert seg.external_ratio == 0.9

    def test_external_ratio_none_on_any_exposure_ok(self):
        """external_ratio=None (default) is valid for all exposure values."""
        for exp in ("internal", "external", "both"):
            seg = NetworkSegment(name="seg", cidr="10.0.0.0/24", exposure=exp)
            assert seg.external_ratio is None

    def test_external_ratio_on_internal_segment_raises(self):
        """external_ratio set on exposure='internal' should raise ValidationError."""
        import pytest
        from pydantic import ValidationError

        with pytest.raises(
            ValidationError, match="external_ratio is only valid when exposure='both'"
        ):
            NetworkSegment(name="ws", cidr="10.0.1.0/24", exposure="internal", external_ratio=0.5)

    def test_external_ratio_on_external_segment_raises(self):
        """external_ratio set on exposure='external' should raise ValidationError."""
        import pytest
        from pydantic import ValidationError

        with pytest.raises(
            ValidationError, match="external_ratio is only valid when exposure='both'"
        ):
            NetworkSegment(name="dmz", cidr="10.0.3.0/24", exposure="external", external_ratio=0.5)

    def test_external_ratio_above_1_raises(self):
        """external_ratio > 1.0 should raise ValidationError."""
        import pytest
        from pydantic import ValidationError

        with pytest.raises(ValidationError, match="external_ratio must be between 0.0 and 1.0"):
            NetworkSegment(name="seg", cidr="10.0.0.0/24", exposure="both", external_ratio=1.5)

    def test_external_ratio_below_0_raises(self):
        """external_ratio < 0.0 should raise ValidationError."""
        import pytest
        from pydantic import ValidationError

        with pytest.raises(ValidationError, match="external_ratio must be between 0.0 and 1.0"):
            NetworkSegment(name="seg", cidr="10.0.0.0/24", exposure="both", external_ratio=-0.1)

    def test_external_ratio_boundary_values_ok(self):
        """external_ratio of exactly 0.0 and 1.0 should be valid."""
        seg0 = NetworkSegment(name="seg", cidr="10.0.0.0/24", exposure="both", external_ratio=0.0)
        seg1 = NetworkSegment(name="seg", cidr="10.0.0.0/24", exposure="both", external_ratio=1.0)
        assert seg0.external_ratio == 0.0
        assert seg1.external_ratio == 1.0


class TestFormatOsCompatibility:
    """Tests for _validate_format_os_compatibility."""

    def test_windows_format_no_windows_systems_error(self):
        """Windows format with only Linux systems should error."""
        scenario = Scenario(
            version="1.0",
            name="test",
            description="Test",
            environment=Environment(
                description="Test env",
                users=[User(username="u1", full_name="U", email="u@test.com")],
                systems=[
                    System(
                        hostname="LNX-01", ip="10.0.0.1", os="Linux Ubuntu 22.04", type="server"
                    ),
                ],
            ),
            time_window=TimeWindow(start=datetime(2024, 1, 15, 10, 0, 0), duration="1h"),
            baseline_activity=BaselineActivity(
                description="Test", intensity="medium", variation="low"
            ),
            output=OutputSpec(logs=[{"format": "windows"}], destination="./output"),
        )
        validator = ScenarioValidator(scenario)
        issues = validator.validate()

        errors = [
            i for i in issues if i.severity == "error" and "requires windows" in i.message.lower()
        ]
        assert len(errors) >= 1

    def test_linux_format_no_linux_systems_error(self):
        """Syslog format with only Windows systems should error."""
        scenario = Scenario(
            version="1.0",
            name="test",
            description="Test",
            environment=Environment(
                description="Test env",
                users=[User(username="u1", full_name="U", email="u@test.com")],
                systems=[
                    System(hostname="WS-01", ip="10.0.0.1", os="Windows 10", type="workstation"),
                ],
            ),
            time_window=TimeWindow(start=datetime(2024, 1, 15, 10, 0, 0), duration="1h"),
            baseline_activity=BaselineActivity(
                description="Test", intensity="medium", variation="low"
            ),
            output=OutputSpec(logs=[{"format": "syslog"}], destination="./output"),
        )
        validator = ScenarioValidator(scenario)
        issues = validator.validate()

        errors = [
            i for i in issues if i.severity == "error" and "requires linux" in i.message.lower()
        ]
        assert len(errors) >= 1

    def test_linux_system_no_linux_format_warning(self):
        """Linux system with only Windows formats should warn."""
        scenario = Scenario(
            version="1.0",
            name="test",
            description="Test",
            environment=Environment(
                description="Test env",
                users=[User(username="u1", full_name="U", email="u@test.com")],
                systems=[
                    System(hostname="WS-01", ip="10.0.0.1", os="Windows 10", type="workstation"),
                    System(hostname="LNX-01", ip="10.0.0.2", os="Linux Ubuntu", type="server"),
                ],
            ),
            time_window=TimeWindow(start=datetime(2024, 1, 15, 10, 0, 0), duration="1h"),
            baseline_activity=BaselineActivity(
                description="Test", intensity="medium", variation="low"
            ),
            output=OutputSpec(logs=[{"format": "windows"}], destination="./output"),
        )
        validator = ScenarioValidator(scenario)
        issues = validator.validate()

        warnings = [
            i
            for i in issues
            if i.severity == "warning" and "LNX-01" in i.message and "linux" in i.message.lower()
        ]
        assert len(warnings) >= 1

    def test_matching_os_and_formats_no_issues(self):
        """Systems matching output formats should produce no OS compatibility issues."""
        scenario = Scenario(
            version="1.0",
            name="test",
            description="Test",
            environment=Environment(
                description="Test env",
                users=[User(username="u1", full_name="U", email="u@test.com")],
                systems=[
                    System(hostname="WS-01", ip="10.0.0.1", os="Windows 10", type="workstation"),
                    System(hostname="LNX-01", ip="10.0.0.2", os="Linux Ubuntu", type="server"),
                ],
            ),
            time_window=TimeWindow(start=datetime(2024, 1, 15, 10, 0, 0), duration="1h"),
            baseline_activity=BaselineActivity(
                description="Test", intensity="medium", variation="low"
            ),
            output=OutputSpec(
                logs=[{"format": "windows"}, {"format": "syslog"}, {"format": "bash_history"}],
                destination="./output",
            ),
        )
        validator = ScenarioValidator(scenario)
        issues = validator.validate()

        os_issues = [
            i
            for i in issues
            if "output.logs" == i.field_path and ("requires" in i.message or "no" in i.message)
        ]
        assert len(os_issues) == 0


class TestProxyOutputTopology:
    """Tests for _validate_proxy_output_topology."""

    def test_proxy_access_without_forward_proxy_warns(self):
        """proxy_access output with no forward_proxy system should warn."""
        scenario = Scenario(
            version="1.0",
            name="test",
            description="Test",
            environment=Environment(
                description="Test env",
                users=[User(username="u1", full_name="U", email="u@test.com")],
                systems=[
                    System(
                        hostname="LNX-01",
                        ip="10.0.0.1",
                        os="Linux Ubuntu 22.04",
                        type="server",
                        roles=["web_server"],
                    ),
                ],
            ),
            time_window=TimeWindow(start=datetime(2024, 1, 15, 10, 0, 0), duration="1h"),
            baseline_activity=BaselineActivity(
                description="Test", intensity="medium", variation="low"
            ),
            output=OutputSpec(logs=[{"format": "proxy_access"}], destination="./output"),
        )
        validator = ScenarioValidator(scenario)
        issues = validator.validate()

        warnings = [
            i
            for i in issues
            if i.severity == "warning"
            and i.field_path == "output.logs"
            and "forward_proxy" in i.message
        ]
        assert len(warnings) == 1
        assert "roles: [forward_proxy]" in (warnings[0].suggestion or "")

    def test_proxy_access_with_forward_proxy_no_topology_warning(self):
        """proxy_access output with a forward_proxy system should not warn on missing role."""
        scenario = Scenario(
            version="1.0",
            name="test",
            description="Test",
            environment=Environment(
                description="Test env",
                users=[User(username="u1", full_name="U", email="u@test.com")],
                systems=[
                    System(
                        hostname="PROXY-01",
                        ip="10.0.0.10",
                        os="Linux Ubuntu 22.04",
                        type="server",
                        roles=["forward_proxy"],
                        services=["squid"],
                    ),
                ],
            ),
            time_window=TimeWindow(start=datetime(2024, 1, 15, 10, 0, 0), duration="1h"),
            baseline_activity=BaselineActivity(
                description="Test", intensity="medium", variation="low"
            ),
            output=OutputSpec(logs=[{"format": "proxy_access"}], destination="./output"),
        )
        validator = ScenarioValidator(scenario)
        issues = validator.validate()

        warnings = [
            i for i in issues if i.field_path == "output.logs" and "forward_proxy" in i.message
        ]
        assert len(warnings) == 0

    def test_proxy_access_without_proxy_config_warns_transparent_default(self):
        """proxy_access with no environment.proxy warns that transparent is the default."""
        scenario = Scenario(
            version="1.0",
            name="test",
            description="Test",
            environment=Environment(
                description="Test env",
                users=[User(username="u1", full_name="U", email="u@test.com")],
                systems=[
                    System(
                        hostname="PROXY-01",
                        ip="10.0.0.10",
                        os="Linux Ubuntu 22.04",
                        type="server",
                        roles=["forward_proxy"],
                    ),
                ],
            ),
            time_window=TimeWindow(start=datetime(2024, 1, 15, 10, 0, 0), duration="1h"),
            baseline_activity=BaselineActivity(
                description="Test", intensity="medium", variation="low"
            ),
            output=OutputSpec(logs=[{"format": "proxy_access"}], destination="./output"),
        )
        validator = ScenarioValidator(scenario)
        issues = validator.validate()

        warnings = [
            i
            for i in issues
            if i.severity == "warning"
            and i.field_path == "environment.proxy"
            and "transparent" in i.message
        ]
        assert len(warnings) == 1

    def test_explicit_proxy_without_listener_port_warns_8080_default(self):
        """explicit proxy mode warns when listener_port is omitted."""
        scenario = Scenario(
            version="1.0",
            name="test",
            description="Test",
            environment=Environment(
                description="Test env",
                users=[User(username="u1", full_name="U", email="u@test.com")],
                systems=[
                    System(
                        hostname="PROXY-01",
                        ip="10.0.0.10",
                        os="Linux Ubuntu 22.04",
                        type="server",
                        roles=["forward_proxy"],
                    ),
                ],
                proxy=ProxyConfig(mode="explicit"),
            ),
            time_window=TimeWindow(start=datetime(2024, 1, 15, 10, 0, 0), duration="1h"),
            baseline_activity=BaselineActivity(
                description="Test", intensity="medium", variation="low"
            ),
            output=OutputSpec(logs=[{"format": "proxy_access"}], destination="./output"),
        )
        validator = ScenarioValidator(scenario)
        issues = validator.validate()

        warnings = [
            i
            for i in issues
            if i.severity == "warning"
            and i.field_path == "environment.proxy.listener_port"
            and "8080" in i.message
        ]
        assert len(warnings) == 1


class TestSegmentSensorCoverage:
    """Tests for _validate_segment_sensor_coverage."""

    def test_segment_without_sensor_warning(self):
        """Segment with systems but no sensor monitoring it should warn."""
        scenario = Scenario(
            version="1.0",
            name="test",
            description="Test",
            environment=Environment(
                description="Test env",
                users=[User(username="u1", full_name="U", email="u@test.com")],
                systems=[
                    System(hostname="WS-01", ip="10.0.0.1", os="Windows 10", type="workstation"),
                    System(
                        hostname="SRV-01", ip="10.0.1.1", os="Windows Server 2019", type="server"
                    ),
                ],
                network=NetworkConfig(
                    segments=[
                        NetworkSegment(
                            name="workstations",
                            cidr="10.0.0.0/24",
                            systems=["WS-01"],
                            exposure="internal",
                        ),
                        NetworkSegment(
                            name="servers",
                            cidr="10.0.1.0/24",
                            systems=["SRV-01"],
                            exposure="internal",
                        ),
                    ],
                    sensors=[
                        NetworkSensor(
                            type="network",
                            name="tap",
                            monitoring_segments=["servers"],
                            log_formats=["zeek"],
                        ),
                    ],
                ),
            ),
            time_window=TimeWindow(start=datetime(2024, 1, 15, 10, 0, 0), duration="1h"),
            baseline_activity=BaselineActivity(
                description="Test", intensity="medium", variation="low"
            ),
            output=OutputSpec(logs=[{"format": "windows"}], destination="./output"),
        )
        validator = ScenarioValidator(scenario)
        issues = validator.validate()

        warnings = [
            i for i in issues if i.severity == "warning" and "no sensor" in i.message.lower()
        ]
        assert len(warnings) == 1
        assert "workstations" in warnings[0].message

    def test_segment_with_sensor_no_warning(self):
        """Segment monitored by sensor should produce no coverage warning."""
        scenario = Scenario(
            version="1.0",
            name="test",
            description="Test",
            environment=Environment(
                description="Test env",
                users=[User(username="u1", full_name="U", email="u@test.com")],
                systems=[
                    System(hostname="WS-01", ip="10.0.0.1", os="Windows 10", type="workstation"),
                ],
                network=NetworkConfig(
                    segments=[
                        NetworkSegment(
                            name="workstations",
                            cidr="10.0.0.0/24",
                            systems=["WS-01"],
                            exposure="internal",
                        ),
                    ],
                    sensors=[
                        NetworkSensor(
                            type="network",
                            name="tap",
                            monitoring_segments=["workstations"],
                            log_formats=["zeek"],
                        ),
                    ],
                ),
            ),
            time_window=TimeWindow(start=datetime(2024, 1, 15, 10, 0, 0), duration="1h"),
            baseline_activity=BaselineActivity(
                description="Test", intensity="medium", variation="low"
            ),
            output=OutputSpec(logs=[{"format": "windows"}], destination="./output"),
        )
        validator = ScenarioValidator(scenario)
        issues = validator.validate()

        coverage_warnings = [i for i in issues if "no sensor" in i.message.lower()]
        assert len(coverage_warnings) == 0


class TestServiceAccountCollisions:
    """Tests for _validate_service_account_collisions."""

    def test_collision_warning(self):
        """Service account name matching username should warn."""
        scenario = Scenario(
            version="1.0",
            name="test",
            description="Test",
            environment=Environment(
                description="Test env",
                users=[User(username="svc_backup", full_name="Backup", email="b@test.com")],
                systems=[
                    System(hostname="WS-01", ip="10.0.0.1", os="Windows 10", type="workstation"),
                ],
                service_accounts=["svc_backup", "svc_sql"],
            ),
            time_window=TimeWindow(start=datetime(2024, 1, 15, 10, 0, 0), duration="1h"),
            baseline_activity=BaselineActivity(
                description="Test", intensity="medium", variation="low"
            ),
            output=OutputSpec(logs=[{"format": "windows"}], destination="./output"),
        )
        validator = ScenarioValidator(scenario)
        issues = validator.validate()

        warnings = [i for i in issues if "collides" in i.message.lower()]
        assert len(warnings) == 1
        assert "svc_backup" in warnings[0].message

    def test_no_collision_no_warning(self):
        """Non-overlapping service and user accounts should not warn."""
        scenario = Scenario(
            version="1.0",
            name="test",
            description="Test",
            environment=Environment(
                description="Test env",
                users=[User(username="jdoe", full_name="J Doe", email="j@test.com")],
                systems=[
                    System(hostname="WS-01", ip="10.0.0.1", os="Windows 10", type="workstation"),
                ],
                service_accounts=["svc_sql"],
            ),
            time_window=TimeWindow(start=datetime(2024, 1, 15, 10, 0, 0), duration="1h"),
            baseline_activity=BaselineActivity(
                description="Test", intensity="medium", variation="low"
            ),
            output=OutputSpec(logs=[{"format": "windows"}], destination="./output"),
        )
        validator = ScenarioValidator(scenario)
        issues = validator.validate()

        warnings = [i for i in issues if "collides" in i.message.lower()]
        assert len(warnings) == 0


class TestStorylineActorWorkHours:
    """Tests for _validate_storyline_actor_work_hours."""

    def test_unparseable_work_hours_warning(self):
        """Storyline actor with unparseable work_hours should warn."""
        scenario = Scenario(
            version="1.0",
            name="test",
            description="Test",
            environment=Environment(
                description="Test env",
                users=[User(username="jdoe", full_name="J", email="j@test.com", persona="dev")],
                systems=[
                    System(hostname="WS-01", ip="10.0.0.1", os="Windows 10", type="workstation"),
                ],
            ),
            personas=[
                Persona(
                    name="dev",
                    description="Dev",
                    typical_activities=["coding"],
                    work_hours="whenever I feel like it",
                ),
            ],
            storyline=[
                StorylineEvent(
                    id="evt-val-009",
                    time="2024-01-15T10:00:00Z",
                    actor="jdoe",
                    system="WS-01",
                    activity="logon",
                    events=[{"type": "logon", "logon_type": 2}],
                ),
            ],
            time_window=TimeWindow(start=datetime(2024, 1, 15, 10, 0, 0), duration="1h"),
            baseline_activity=BaselineActivity(
                description="Test", intensity="medium", variation="low"
            ),
            output=OutputSpec(logs=[{"format": "windows"}], destination="./output"),
        )
        validator = ScenarioValidator(scenario)
        issues = validator.validate()

        warnings = [i for i in issues if "work_hours" in i.message.lower()]
        assert len(warnings) >= 1

    def test_valid_work_hours_no_warning(self):
        """Storyline actor with parseable work_hours should not warn."""
        scenario = Scenario(
            version="1.0",
            name="test",
            description="Test",
            environment=Environment(
                description="Test env",
                users=[User(username="jdoe", full_name="J", email="j@test.com", persona="dev")],
                systems=[
                    System(hostname="WS-01", ip="10.0.0.1", os="Windows 10", type="workstation"),
                ],
            ),
            personas=[
                Persona(
                    name="dev",
                    description="Dev",
                    typical_activities=["coding"],
                    work_hours="9am-5pm",
                ),
            ],
            storyline=[
                StorylineEvent(
                    id="evt-val-010",
                    time="2024-01-15T10:00:00Z",
                    actor="jdoe",
                    system="WS-01",
                    activity="logon",
                    events=[{"type": "logon", "logon_type": 2}],
                ),
            ],
            time_window=TimeWindow(start=datetime(2024, 1, 15, 10, 0, 0), duration="1h"),
            baseline_activity=BaselineActivity(
                description="Test", intensity="medium", variation="low"
            ),
            output=OutputSpec(logs=[{"format": "windows"}], destination="./output"),
        )
        validator = ScenarioValidator(scenario)
        issues = validator.validate()

        warnings = [i for i in issues if "work_hours" in i.message.lower()]
        assert len(warnings) == 0


class TestNoiseFeasibility:
    """Tests for _validate_noise_feasibility."""

    def test_low_intensity_many_events_warning(self):
        """Low intensity with 51+ storyline events should warn."""
        events = [
            StorylineEvent(
                id=f"evt-val-011-{i}",
                time=f"2024-01-15T10:{i:02d}:00Z",
                actor="jdoe",
                system="WS-01",
                activity=f"step {i}",
                events=[{"type": "logon", "logon_type": 2}],
            )
            for i in range(51)
        ]
        scenario = Scenario(
            version="1.0",
            name="test",
            description="Test",
            environment=Environment(
                description="Test env",
                users=[User(username="jdoe", full_name="J", email="j@test.com")],
                systems=[
                    System(hostname="WS-01", ip="10.0.0.1", os="Windows 10", type="workstation"),
                ],
            ),
            storyline=events,
            time_window=TimeWindow(start=datetime(2024, 1, 15, 10, 0, 0), duration="2h"),
            baseline_activity=BaselineActivity(
                description="Test", intensity="low", variation="low"
            ),
            output=OutputSpec(logs=[{"format": "windows"}], destination="./output"),
        )
        validator = ScenarioValidator(scenario)
        issues = validator.validate()

        warnings = [i for i in issues if "noise-to-signal" in i.message.lower()]
        assert len(warnings) == 1

    def test_high_intensity_many_events_no_warning(self):
        """High intensity with many events should not warn about noise."""
        events = [
            StorylineEvent(
                id=f"evt-val-012-{i}",
                time=f"2024-01-15T10:{i:02d}:00Z",
                actor="jdoe",
                system="WS-01",
                activity=f"step {i}",
                events=[{"type": "logon", "logon_type": 2}],
            )
            for i in range(51)
        ]
        scenario = Scenario(
            version="1.0",
            name="test",
            description="Test",
            environment=Environment(
                description="Test env",
                users=[User(username="jdoe", full_name="J", email="j@test.com")],
                systems=[
                    System(hostname="WS-01", ip="10.0.0.1", os="Windows 10", type="workstation"),
                ],
            ),
            storyline=events,
            time_window=TimeWindow(start=datetime(2024, 1, 15, 10, 0, 0), duration="2h"),
            baseline_activity=BaselineActivity(
                description="Test", intensity="high", variation="low"
            ),
            output=OutputSpec(logs=[{"format": "windows"}], destination="./output"),
        )
        validator = ScenarioValidator(scenario)
        issues = validator.validate()

        warnings = [i for i in issues if "noise-to-signal" in i.message.lower()]
        assert len(warnings) == 0


class TestStorylineFormatCoverage:
    """Tests for _validate_storyline_format_coverage."""

    def test_linux_system_no_linux_format_warning(self):
        """Storyline Linux system with only Windows formats should warn."""
        scenario = Scenario(
            version="1.0",
            name="test",
            description="Test",
            environment=Environment(
                description="Test env",
                users=[User(username="jdoe", full_name="J", email="j@test.com")],
                systems=[
                    System(hostname="WS-01", ip="10.0.0.1", os="Windows 10", type="workstation"),
                    System(hostname="LNX-01", ip="10.0.0.2", os="Linux Ubuntu", type="server"),
                ],
            ),
            storyline=[
                StorylineEvent(
                    id="evt-val-013",
                    time="2024-01-15T10:00:00Z",
                    actor="jdoe",
                    system="LNX-01",
                    activity="ssh",
                    events=[{"type": "ssh_session"}],
                ),
            ],
            time_window=TimeWindow(start=datetime(2024, 1, 15, 10, 0, 0), duration="1h"),
            baseline_activity=BaselineActivity(
                description="Test", intensity="medium", variation="low"
            ),
            output=OutputSpec(logs=[{"format": "windows"}], destination="./output"),
        )
        validator = ScenarioValidator(scenario)
        issues = validator.validate()

        warnings = [
            i
            for i in issues
            if i.severity == "warning" and "LNX-01" in i.message and "format" in i.message.lower()
        ]
        assert len(warnings) >= 1


class TestStorylineOsPlausibility:
    """Tests for _validate_storyline_os_plausibility."""

    def test_windows_event_on_linux_warning(self):
        """Windows-specific event type on Linux system should warn."""
        scenario = Scenario(
            version="1.0",
            name="test",
            description="Test",
            environment=Environment(
                description="Test env",
                users=[User(username="jdoe", full_name="J", email="j@test.com")],
                systems=[
                    System(hostname="LNX-01", ip="10.0.0.1", os="Linux Ubuntu", type="server"),
                ],
            ),
            storyline=[
                StorylineEvent(
                    id="evt-val-014",
                    time="2024-01-15T10:00:00Z",
                    actor="jdoe",
                    system="LNX-01",
                    activity="install service",
                    events=[
                        {
                            "type": "service_installed",
                            "service_name": "evil",
                            "service_file_name": "C:\\evil.exe",
                        }
                    ],
                ),
            ],
            time_window=TimeWindow(start=datetime(2024, 1, 15, 10, 0, 0), duration="1h"),
            baseline_activity=BaselineActivity(
                description="Test", intensity="medium", variation="low"
            ),
            output=OutputSpec(logs=[{"format": "syslog"}], destination="./output"),
        )
        validator = ScenarioValidator(scenario)
        issues = validator.validate()

        warnings = [i for i in issues if "Windows-specific" in i.message]
        assert len(warnings) >= 1

    def test_ssh_on_windows_warning(self):
        """SSH session on Windows system should warn."""
        scenario = Scenario(
            version="1.0",
            name="test",
            description="Test",
            environment=Environment(
                description="Test env",
                users=[User(username="jdoe", full_name="J", email="j@test.com")],
                systems=[
                    System(hostname="WS-01", ip="10.0.0.1", os="Windows 10", type="workstation"),
                ],
            ),
            storyline=[
                StorylineEvent(
                    id="evt-val-015",
                    time="2024-01-15T10:00:00Z",
                    actor="jdoe",
                    system="WS-01",
                    activity="ssh session",
                    events=[{"type": "ssh_session"}],
                ),
            ],
            time_window=TimeWindow(start=datetime(2024, 1, 15, 10, 0, 0), duration="1h"),
            baseline_activity=BaselineActivity(
                description="Test", intensity="medium", variation="low"
            ),
            output=OutputSpec(logs=[{"format": "windows"}], destination="./output"),
        )
        validator = ScenarioValidator(scenario)
        issues = validator.validate()

        warnings = [i for i in issues if "Linux-specific" in i.message]
        assert len(warnings) >= 1

    def test_powershell_on_linux_warning(self):
        """Process with powershell.exe on Linux should warn."""
        scenario = Scenario(
            version="1.0",
            name="test",
            description="Test",
            environment=Environment(
                description="Test env",
                users=[User(username="jdoe", full_name="J", email="j@test.com")],
                systems=[
                    System(hostname="LNX-01", ip="10.0.0.1", os="Linux Ubuntu", type="server"),
                ],
            ),
            storyline=[
                StorylineEvent(
                    id="evt-val-016",
                    time="2024-01-15T10:00:00Z",
                    actor="jdoe",
                    system="LNX-01",
                    activity="run powershell",
                    events=[
                        {
                            "type": "process",
                            "process_name": "powershell.exe",
                            "command_line": "powershell.exe -enc abc123",
                        }
                    ],
                ),
            ],
            time_window=TimeWindow(start=datetime(2024, 1, 15, 10, 0, 0), duration="1h"),
            baseline_activity=BaselineActivity(
                description="Test", intensity="medium", variation="low"
            ),
            output=OutputSpec(logs=[{"format": "syslog"}], destination="./output"),
        )
        validator = ScenarioValidator(scenario)
        issues = validator.validate()

        warnings = [i for i in issues if "powershell.exe" in i.message]
        assert len(warnings) >= 1

    def test_linux_path_on_windows_warning(self):
        """Process with /usr/ path on Windows should warn."""
        scenario = Scenario(
            version="1.0",
            name="test",
            description="Test",
            environment=Environment(
                description="Test env",
                users=[User(username="jdoe", full_name="J", email="j@test.com")],
                systems=[
                    System(hostname="WS-01", ip="10.0.0.1", os="Windows 10", type="workstation"),
                ],
            ),
            storyline=[
                StorylineEvent(
                    id="evt-val-017",
                    time="2024-01-15T10:00:00Z",
                    actor="jdoe",
                    system="WS-01",
                    activity="run linux binary",
                    events=[{"type": "logon", "logon_type": 2}],
                ),
                StorylineEvent(
                    id="evt-val-018",
                    time="2024-01-15T10:01:00Z",
                    actor="jdoe",
                    system="WS-01",
                    activity="run linux binary",
                    events=[
                        {
                            "type": "process",
                            "process_name": "ncat",
                            "command_line": "/usr/bin/ncat -e /bin/sh",
                        }
                    ],
                ),
            ],
            time_window=TimeWindow(start=datetime(2024, 1, 15, 10, 0, 0), duration="1h"),
            baseline_activity=BaselineActivity(
                description="Test", intensity="medium", variation="low"
            ),
            output=OutputSpec(logs=[{"format": "windows"}], destination="./output"),
        )
        validator = ScenarioValidator(scenario)
        issues = validator.validate()

        warnings = [i for i in issues if "/usr/" in i.message]
        assert len(warnings) >= 1

    def test_correct_os_event_no_warning(self):
        """Windows event on Windows system should not warn."""
        scenario = Scenario(
            version="1.0",
            name="test",
            description="Test",
            environment=Environment(
                description="Test env",
                users=[User(username="jdoe", full_name="J", email="j@test.com")],
                systems=[
                    System(hostname="WS-01", ip="10.0.0.1", os="Windows 10", type="workstation"),
                ],
            ),
            storyline=[
                StorylineEvent(
                    id="evt-val-019",
                    time="2024-01-15T10:00:00Z",
                    actor="jdoe",
                    system="WS-01",
                    activity="logon",
                    events=[{"type": "logon", "logon_type": 2}],
                ),
                StorylineEvent(
                    id="evt-val-020",
                    time="2024-01-15T10:01:00Z",
                    actor="jdoe",
                    system="WS-01",
                    activity="install service",
                    events=[
                        {
                            "type": "service_installed",
                            "service_name": "svc",
                            "service_file_name": "C:\\svc.exe",
                        }
                    ],
                ),
            ],
            time_window=TimeWindow(start=datetime(2024, 1, 15, 10, 0, 0), duration="1h"),
            baseline_activity=BaselineActivity(
                description="Test", intensity="medium", variation="low"
            ),
            output=OutputSpec(logs=[{"format": "windows"}], destination="./output"),
        )
        validator = ScenarioValidator(scenario)
        issues = validator.validate()

        os_warnings = [
            i
            for i in issues
            if "specific" in i.message.lower() and ("Windows" in i.message or "Linux" in i.message)
        ]
        assert len(os_warnings) == 0


class TestStorylineLinkability:
    """Tests for _validate_storyline_linkability."""

    def test_no_shared_indicator_warning(self):
        """Consecutive events with no shared field should warn."""
        scenario = Scenario(
            version="1.0",
            name="test",
            description="Test",
            environment=Environment(
                description="Test env",
                users=[
                    User(username="alice", full_name="A", email="a@test.com"),
                    User(username="bob", full_name="B", email="b@test.com"),
                ],
                systems=[
                    System(hostname="WS-01", ip="10.0.0.1", os="Windows 10", type="workstation"),
                    System(hostname="WS-02", ip="10.0.0.2", os="Windows 10", type="workstation"),
                ],
            ),
            storyline=[
                StorylineEvent(
                    id="evt-val-021",
                    time="2024-01-15T10:00:00Z",
                    actor="alice",
                    system="WS-01",
                    activity="step 1",
                    events=[{"type": "logon", "logon_type": 2}],
                ),
                StorylineEvent(
                    id="evt-val-022",
                    time="2024-01-15T10:01:00Z",
                    actor="bob",
                    system="WS-02",
                    activity="step 2",
                    events=[{"type": "logon", "logon_type": 2}],
                ),
            ],
            time_window=TimeWindow(start=datetime(2024, 1, 15, 10, 0, 0), duration="1h"),
            baseline_activity=BaselineActivity(
                description="Test", intensity="medium", variation="low"
            ),
            output=OutputSpec(logs=[{"format": "windows"}], destination="./output"),
        )
        validator = ScenarioValidator(scenario)
        issues = validator.validate()

        warnings = [i for i in issues if "pivot" in i.message.lower()]
        assert len(warnings) >= 1

    def test_shared_actor_no_warning(self):
        """Consecutive events sharing an actor should not warn about linkability."""
        scenario = Scenario(
            version="1.0",
            name="test",
            description="Test",
            environment=Environment(
                description="Test env",
                users=[User(username="alice", full_name="A", email="a@test.com")],
                systems=[
                    System(hostname="WS-01", ip="10.0.0.1", os="Windows 10", type="workstation"),
                    System(hostname="WS-02", ip="10.0.0.2", os="Windows 10", type="workstation"),
                ],
            ),
            storyline=[
                StorylineEvent(
                    id="evt-val-023",
                    time="2024-01-15T10:00:00Z",
                    actor="alice",
                    system="WS-01",
                    activity="step 1",
                    events=[{"type": "logon", "logon_type": 2}],
                ),
                StorylineEvent(
                    id="evt-val-024",
                    time="2024-01-15T10:01:00Z",
                    actor="alice",
                    system="WS-02",
                    activity="step 2",
                    events=[{"type": "logon", "logon_type": 2}],
                ),
            ],
            time_window=TimeWindow(start=datetime(2024, 1, 15, 10, 0, 0), duration="1h"),
            baseline_activity=BaselineActivity(
                description="Test", intensity="medium", variation="low"
            ),
            output=OutputSpec(logs=[{"format": "windows"}], destination="./output"),
        )
        validator = ScenarioValidator(scenario)
        issues = validator.validate()

        warnings = [i for i in issues if "pivot" in i.message.lower()]
        assert len(warnings) == 0

    def test_shared_ip_no_warning(self):
        """Consecutive events sharing an IP via connection should not warn."""
        scenario = Scenario(
            version="1.0",
            name="test",
            description="Test",
            environment=Environment(
                description="Test env",
                users=[
                    User(username="alice", full_name="A", email="a@test.com"),
                    User(username="bob", full_name="B", email="b@test.com"),
                ],
                systems=[
                    System(hostname="WS-01", ip="10.0.0.1", os="Windows 10", type="workstation"),
                    System(
                        hostname="SRV-01", ip="10.0.0.10", os="Windows Server 2019", type="server"
                    ),
                ],
            ),
            storyline=[
                StorylineEvent(
                    id="evt-val-025",
                    time="2024-01-15T10:00:00Z",
                    actor="alice",
                    system="WS-01",
                    activity="connect",
                    events=[{"type": "connection", "dst_ip": "10.0.0.10", "dst_port": 443}],
                ),
                StorylineEvent(
                    id="evt-val-026",
                    time="2024-01-15T10:01:00Z",
                    actor="bob",
                    system="SRV-01",
                    activity="execute",
                    events=[{"type": "logon", "logon_type": 3}],
                ),
            ],
            time_window=TimeWindow(start=datetime(2024, 1, 15, 10, 0, 0), duration="1h"),
            baseline_activity=BaselineActivity(
                description="Test", intensity="medium", variation="low"
            ),
            output=OutputSpec(logs=[{"format": "windows"}], destination="./output"),
        )
        validator = ScenarioValidator(scenario)
        issues = validator.validate()

        warnings = [i for i in issues if "pivot" in i.message.lower()]
        assert len(warnings) == 0


class TestStorylineCausalOrder:
    """Tests for _validate_storyline_causal_order."""

    def test_process_without_logon_warning(self):
        """Process event with no prior logon should warn (outside grace period)."""
        scenario = Scenario(
            version="1.0",
            name="test",
            description="Test",
            environment=Environment(
                description="Test env",
                users=[User(username="jdoe", full_name="J", email="j@test.com")],
                systems=[
                    System(hostname="WS-01", ip="10.0.0.1", os="Windows 10", type="workstation"),
                ],
            ),
            storyline=[
                StorylineEvent(
                    id="evt-val-027",
                    time="2024-01-15T10:00:00Z",
                    actor="jdoe",
                    system="WS-01",
                    activity="run cmd",
                    events=[{"type": "process", "process_name": "cmd.exe"}],
                ),
            ],
            time_window=TimeWindow(start=datetime(2024, 1, 15, 10, 0, 0), duration="1h"),
            baseline_activity=BaselineActivity(
                description="Test", intensity="medium", variation="low"
            ),
            output=OutputSpec(logs=[{"format": "windows"}], destination="./output"),
            logon_grace_period="0s",
        )
        validator = ScenarioValidator(scenario)
        issues = validator.validate()

        warnings = [i for i in issues if "no prior logon" in i.message.lower()]
        assert len(warnings) >= 1

    def test_logon_then_process_no_warning(self):
        """Process after logon on same system should not warn."""
        scenario = Scenario(
            version="1.0",
            name="test",
            description="Test",
            environment=Environment(
                description="Test env",
                users=[User(username="jdoe", full_name="J", email="j@test.com")],
                systems=[
                    System(hostname="WS-01", ip="10.0.0.1", os="Windows 10", type="workstation"),
                ],
            ),
            storyline=[
                StorylineEvent(
                    id="evt-val-028",
                    time="2024-01-15T10:00:00Z",
                    actor="jdoe",
                    system="WS-01",
                    activity="logon",
                    events=[{"type": "logon", "logon_type": 2}],
                ),
                StorylineEvent(
                    id="evt-val-029",
                    time="2024-01-15T10:01:00Z",
                    actor="jdoe",
                    system="WS-01",
                    activity="run cmd",
                    events=[{"type": "process", "process_name": "cmd.exe"}],
                ),
            ],
            time_window=TimeWindow(start=datetime(2024, 1, 15, 10, 0, 0), duration="1h"),
            baseline_activity=BaselineActivity(
                description="Test", intensity="medium", variation="low"
            ),
            output=OutputSpec(logs=[{"format": "windows"}], destination="./output"),
        )
        validator = ScenarioValidator(scenario)
        issues = validator.validate()

        warnings = [i for i in issues if "no prior logon" in i.message.lower()]
        assert len(warnings) == 0

    def test_builtin_account_process_no_warning(self):
        """SYSTEM process with no prior logon should not warn."""
        scenario = Scenario(
            version="1.0",
            name="test",
            description="Test",
            environment=Environment(
                description="Test env",
                users=[User(username="jdoe", full_name="J", email="j@test.com")],
                systems=[
                    System(hostname="WS-01", ip="10.0.0.1", os="Windows 10", type="workstation"),
                ],
            ),
            storyline=[
                StorylineEvent(
                    id="evt-val-030",
                    time="2024-01-15T10:00:00Z",
                    actor="SYSTEM",
                    system="WS-01",
                    activity="system process",
                    events=[{"type": "process", "process_name": "svchost.exe"}],
                ),
            ],
            time_window=TimeWindow(start=datetime(2024, 1, 15, 10, 0, 0), duration="1h"),
            baseline_activity=BaselineActivity(
                description="Test", intensity="medium", variation="low"
            ),
            output=OutputSpec(logs=[{"format": "windows"}], destination="./output"),
        )
        validator = ScenarioValidator(scenario)
        issues = validator.validate()

        warnings = [i for i in issues if "no prior logon" in i.message.lower()]
        assert len(warnings) == 0

    def test_logoff_without_logon_warning(self):
        """Logoff with no prior logon should warn."""
        scenario = Scenario(
            version="1.0",
            name="test",
            description="Test",
            environment=Environment(
                description="Test env",
                users=[User(username="jdoe", full_name="J", email="j@test.com")],
                systems=[
                    System(hostname="WS-01", ip="10.0.0.1", os="Windows 10", type="workstation"),
                ],
            ),
            storyline=[
                StorylineEvent(
                    id="evt-val-031",
                    time="2024-01-15T10:00:00Z",
                    actor="jdoe",
                    system="WS-01",
                    activity="logoff",
                    events=[{"type": "logoff"}],
                ),
            ],
            time_window=TimeWindow(start=datetime(2024, 1, 15, 10, 0, 0), duration="1h"),
            baseline_activity=BaselineActivity(
                description="Test", intensity="medium", variation="low"
            ),
            output=OutputSpec(logs=[{"format": "windows"}], destination="./output"),
            logon_grace_period="0s",
        )
        validator = ScenarioValidator(scenario)
        issues = validator.validate()

        warnings = [i for i in issues if "no prior logon" in i.message.lower()]
        assert len(warnings) >= 1

    def test_account_deleted_without_created_warning(self):
        """Account deletion without prior creation should warn."""
        scenario = Scenario(
            version="1.0",
            name="test",
            description="Test",
            environment=Environment(
                description="Test env",
                users=[User(username="jdoe", full_name="J", email="j@test.com")],
                systems=[
                    System(
                        hostname="DC-01",
                        ip="10.0.0.1",
                        os="Windows Server 2019",
                        type="domain_controller",
                    ),
                ],
            ),
            storyline=[
                StorylineEvent(
                    id="evt-val-032",
                    time="2024-01-15T10:00:00Z",
                    actor="jdoe",
                    system="DC-01",
                    activity="logon",
                    events=[{"type": "logon", "logon_type": 2}],
                ),
                StorylineEvent(
                    id="evt-val-033",
                    time="2024-01-15T10:01:00Z",
                    actor="jdoe",
                    system="DC-01",
                    activity="delete account",
                    events=[{"type": "account_deleted", "target_username": "ghost_user"}],
                ),
            ],
            time_window=TimeWindow(start=datetime(2024, 1, 15, 10, 0, 0), duration="1h"),
            baseline_activity=BaselineActivity(
                description="Test", intensity="medium", variation="low"
            ),
            output=OutputSpec(logs=[{"format": "windows"}], destination="./output"),
        )
        validator = ScenarioValidator(scenario)
        issues = validator.validate()

        warnings = [i for i in issues if "no prior account_created" in i.message.lower()]
        assert len(warnings) >= 1

    def test_account_created_then_deleted_no_warning(self):
        """Account creation then deletion should not warn."""
        scenario = Scenario(
            version="1.0",
            name="test",
            description="Test",
            environment=Environment(
                description="Test env",
                users=[User(username="jdoe", full_name="J", email="j@test.com")],
                systems=[
                    System(
                        hostname="DC-01",
                        ip="10.0.0.1",
                        os="Windows Server 2019",
                        type="domain_controller",
                    ),
                ],
            ),
            storyline=[
                StorylineEvent(
                    id="evt-val-034",
                    time="2024-01-15T10:00:00Z",
                    actor="jdoe",
                    system="DC-01",
                    activity="logon",
                    events=[{"type": "logon", "logon_type": 2}],
                ),
                StorylineEvent(
                    id="evt-val-035",
                    time="2024-01-15T10:01:00Z",
                    actor="jdoe",
                    system="DC-01",
                    activity="create account",
                    events=[{"type": "account_created", "target_username": "temp_user"}],
                ),
                StorylineEvent(
                    id="evt-val-036",
                    time="2024-01-15T10:02:00Z",
                    actor="jdoe",
                    system="DC-01",
                    activity="delete account",
                    events=[{"type": "account_deleted", "target_username": "temp_user"}],
                ),
            ],
            time_window=TimeWindow(start=datetime(2024, 1, 15, 10, 0, 0), duration="1h"),
            baseline_activity=BaselineActivity(
                description="Test", intensity="medium", variation="low"
            ),
            output=OutputSpec(logs=[{"format": "windows"}], destination="./output"),
        )
        validator = ScenarioValidator(scenario)
        issues = validator.validate()

        warnings = [i for i in issues if "no prior account_created" in i.message.lower()]
        assert len(warnings) == 0


class TestStorylineEventIds:
    """Tests for _validate_storyline_event_ids."""

    def test_duplicate_ids_error(self):
        """Duplicate storyline event IDs should error."""
        scenario = Scenario(
            version="1.0",
            name="test",
            description="Test",
            environment=Environment(
                description="Test env",
                users=[User(username="jdoe", full_name="J", email="j@test.com")],
                systems=[
                    System(hostname="WS-01", ip="10.0.0.1", os="Windows 10", type="workstation"),
                ],
            ),
            storyline=[
                StorylineEvent(
                    id="evt-dup",
                    time="2024-01-15T10:00:00Z",
                    actor="jdoe",
                    system="WS-01",
                    activity="step 1",
                    events=[{"type": "logon", "logon_type": 2}],
                ),
                StorylineEvent(
                    id="evt-dup",
                    time="2024-01-15T10:01:00Z",
                    actor="jdoe",
                    system="WS-01",
                    activity="step 2",
                    events=[{"type": "process", "process_name": "cmd.exe"}],
                ),
            ],
            time_window=TimeWindow(start=datetime(2024, 1, 15, 10, 0, 0), duration="1h"),
            baseline_activity=BaselineActivity(
                description="Test", intensity="medium", variation="low"
            ),
            output=OutputSpec(logs=[{"format": "windows"}], destination="./output"),
        )
        validator = ScenarioValidator(scenario)
        issues = validator.validate()

        errors = [i for i in issues if i.severity == "error" and "Duplicate event ID" in i.message]
        assert len(errors) == 1
        assert "evt-dup" in errors[0].message

    def test_unique_ids_no_error(self):
        """Unique storyline event IDs should not error."""
        scenario = Scenario(
            version="1.0",
            name="test",
            description="Test",
            environment=Environment(
                description="Test env",
                users=[User(username="jdoe", full_name="J", email="j@test.com")],
                systems=[
                    System(hostname="WS-01", ip="10.0.0.1", os="Windows 10", type="workstation"),
                ],
            ),
            storyline=[
                StorylineEvent(
                    id="evt-001",
                    time="2024-01-15T10:00:00Z",
                    actor="jdoe",
                    system="WS-01",
                    activity="step 1",
                    events=[{"type": "logon", "logon_type": 2}],
                ),
                StorylineEvent(
                    id="evt-002",
                    time="2024-01-15T10:01:00Z",
                    actor="jdoe",
                    system="WS-01",
                    activity="step 2",
                    events=[{"type": "process", "process_name": "cmd.exe"}],
                ),
            ],
            time_window=TimeWindow(start=datetime(2024, 1, 15, 10, 0, 0), duration="1h"),
            baseline_activity=BaselineActivity(
                description="Test", intensity="medium", variation="low"
            ),
            output=OutputSpec(logs=[{"format": "windows"}], destination="./output"),
        )
        validator = ScenarioValidator(scenario)
        issues = validator.validate()

        id_errors = [i for i in issues if "Duplicate event ID" in i.message]
        assert len(id_errors) == 0


class TestLogonGracePeriod:
    """Tests for logon grace period in causal order check."""

    def test_process_in_grace_period_no_warning(self):
        """Process event within grace period should not warn about missing logon."""
        scenario = Scenario(
            version="1.0",
            name="test",
            description="Test",
            environment=Environment(
                description="Test env",
                users=[User(username="jdoe", full_name="J", email="j@test.com")],
                systems=[
                    System(hostname="WS-01", ip="10.0.0.1", os="Windows 10", type="workstation"),
                ],
            ),
            storyline=[
                StorylineEvent(
                    id="evt-001",
                    time="+10m",
                    actor="jdoe",
                    system="WS-01",
                    activity="run cmd",
                    events=[{"type": "process", "process_name": "cmd.exe"}],
                ),
            ],
            time_window=TimeWindow(start=datetime(2024, 1, 15, 10, 0, 0), duration="1h"),
            baseline_activity=BaselineActivity(
                description="Test", intensity="medium", variation="low"
            ),
            output=OutputSpec(logs=[{"format": "windows"}], destination="./output"),
            logon_grace_period="30m",
        )
        validator = ScenarioValidator(scenario)
        issues = validator.validate()

        warnings = [i for i in issues if "no prior logon" in i.message.lower()]
        assert len(warnings) == 0

    def test_process_after_grace_period_warning(self):
        """Process event after grace period should warn about missing logon."""
        scenario = Scenario(
            version="1.0",
            name="test",
            description="Test",
            environment=Environment(
                description="Test env",
                users=[User(username="jdoe", full_name="J", email="j@test.com")],
                systems=[
                    System(hostname="WS-01", ip="10.0.0.1", os="Windows 10", type="workstation"),
                ],
            ),
            storyline=[
                StorylineEvent(
                    id="evt-001",
                    time="+2h",
                    actor="jdoe",
                    system="WS-01",
                    activity="run cmd",
                    events=[{"type": "process", "process_name": "cmd.exe"}],
                ),
            ],
            time_window=TimeWindow(start=datetime(2024, 1, 15, 10, 0, 0), duration="4h"),
            baseline_activity=BaselineActivity(
                description="Test", intensity="medium", variation="low"
            ),
            output=OutputSpec(logs=[{"format": "windows"}], destination="./output"),
            logon_grace_period="30m",
        )
        validator = ScenarioValidator(scenario)
        issues = validator.validate()

        warnings = [i for i in issues if "no prior logon" in i.message.lower()]
        assert len(warnings) >= 1


class TestLinkabilityTimeGap:
    """Tests for time-gap heuristic in linkability check."""

    def test_large_time_gap_no_linkability_warning(self):
        """Events with >4h gap should not trigger linkability warning."""
        scenario = Scenario(
            version="1.0",
            name="test",
            description="Test",
            environment=Environment(
                description="Test env",
                users=[
                    User(username="alice", full_name="A", email="a@test.com"),
                    User(username="bob", full_name="B", email="b@test.com"),
                ],
                systems=[
                    System(hostname="WS-01", ip="10.0.0.1", os="Windows 10", type="workstation"),
                    System(hostname="WS-02", ip="10.0.0.2", os="Windows 10", type="workstation"),
                ],
            ),
            storyline=[
                StorylineEvent(
                    id="evt-001",
                    time="+1h",
                    actor="alice",
                    system="WS-01",
                    activity="step 1",
                    events=[{"type": "logon", "logon_type": 2}],
                ),
                StorylineEvent(
                    id="evt-002",
                    time="+27h",
                    actor="bob",
                    system="WS-02",
                    activity="step 2 (next day)",
                    events=[{"type": "logon", "logon_type": 2}],
                ),
            ],
            time_window=TimeWindow(start=datetime(2024, 1, 15, 10, 0, 0), duration="48h"),
            baseline_activity=BaselineActivity(
                description="Test", intensity="medium", variation="low"
            ),
            output=OutputSpec(logs=[{"format": "windows"}], destination="./output"),
        )
        validator = ScenarioValidator(scenario)
        issues = validator.validate()

        link_issues = [i for i in issues if "pivot" in i.message.lower()]
        assert len(link_issues) == 0

    def test_linkability_issues_are_info_severity(self):
        """Linkability issues should be info severity, not warning."""
        scenario = Scenario(
            version="1.0",
            name="test",
            description="Test",
            environment=Environment(
                description="Test env",
                users=[
                    User(username="alice", full_name="A", email="a@test.com"),
                    User(username="bob", full_name="B", email="b@test.com"),
                ],
                systems=[
                    System(hostname="WS-01", ip="10.0.0.1", os="Windows 10", type="workstation"),
                    System(hostname="WS-02", ip="10.0.0.2", os="Windows 10", type="workstation"),
                ],
            ),
            storyline=[
                StorylineEvent(
                    id="evt-001",
                    time="+1h",
                    actor="alice",
                    system="WS-01",
                    activity="step 1",
                    events=[{"type": "logon", "logon_type": 2}],
                ),
                StorylineEvent(
                    id="evt-002",
                    time="+1h30m",
                    actor="bob",
                    system="WS-02",
                    activity="step 2",
                    events=[{"type": "logon", "logon_type": 2}],
                ),
            ],
            time_window=TimeWindow(start=datetime(2024, 1, 15, 10, 0, 0), duration="4h"),
            baseline_activity=BaselineActivity(
                description="Test", intensity="medium", variation="low"
            ),
            output=OutputSpec(logs=[{"format": "windows"}], destination="./output"),
        )
        validator = ScenarioValidator(scenario)
        issues = validator.validate()

        link_issues = [i for i in issues if "pivot" in i.message.lower()]
        assert len(link_issues) >= 1
        assert all(i.severity == "info" for i in link_issues)

    def test_stale_account_username_collision_with_user(self):
        """Stale account colliding with active user should produce error."""
        scenario = Scenario(
            version="1.0",
            name="test",
            description="Test",
            environment=Environment(
                description="Test",
                users=[User(username="jsmith", full_name="John Smith", email="j@x.com")],
                systems=[
                    System(hostname="WS-01", ip="10.0.0.1", os="Windows 10", type="workstation")
                ],
                stale_accounts=[
                    StaleAccount(username="jsmith", last_active="2023-01-01", reason="duplicate"),
                ],
            ),
            time_window=TimeWindow(start=datetime(2024, 1, 15, 10, 0, 0), duration="1h"),
            baseline_activity=BaselineActivity(
                description="Test", intensity="low", variation="low"
            ),
            output=OutputSpec(logs=[{"format": "windows"}], destination="./output"),
        )
        validator = ScenarioValidator(scenario)
        issues = validator.validate()
        stale_issues = [
            i
            for i in issues
            if "stale_accounts" in i.field_path and "collides" in i.message.lower()
        ]
        assert len(stale_issues) == 1
        assert stale_issues[0].severity == "error"
        assert "jsmith" in stale_issues[0].message

    def test_stale_account_username_collision_with_service(self):
        """Stale account colliding with service account should produce error."""
        scenario = Scenario(
            version="1.0",
            name="test",
            description="Test",
            environment=Environment(
                description="Test",
                users=[User(username="u1", full_name="U1", email="u@x.com")],
                systems=[
                    System(hostname="WS-01", ip="10.0.0.1", os="Windows 10", type="workstation")
                ],
                service_accounts=["svc_backup"],
                stale_accounts=[
                    StaleAccount(username="svc_backup", last_active="2023-01-01", reason="dup"),
                ],
            ),
            time_window=TimeWindow(start=datetime(2024, 1, 15, 10, 0, 0), duration="1h"),
            baseline_activity=BaselineActivity(
                description="Test", intensity="low", variation="low"
            ),
            output=OutputSpec(logs=[{"format": "windows"}], destination="./output"),
        )
        validator = ScenarioValidator(scenario)
        issues = validator.validate()
        stale_issues = [
            i
            for i in issues
            if "stale_accounts" in i.field_path and "service account" in i.message.lower()
        ]
        assert len(stale_issues) == 1
        assert stale_issues[0].severity == "error"

    def test_stale_account_no_collision(self):
        """Stale accounts with unique names should produce no collision errors."""
        scenario = Scenario(
            version="1.0",
            name="test",
            description="Test",
            environment=Environment(
                description="Test",
                users=[User(username="active_user", full_name="Active", email="a@x.com")],
                systems=[
                    System(hostname="WS-01", ip="10.0.0.1", os="Windows 10", type="workstation")
                ],
                stale_accounts=[
                    StaleAccount(
                        username="old_user", last_active="2023-01-01", reason="Former employee"
                    ),
                ],
            ),
            time_window=TimeWindow(start=datetime(2024, 1, 15, 10, 0, 0), duration="1h"),
            baseline_activity=BaselineActivity(
                description="Test", intensity="low", variation="low"
            ),
            output=OutputSpec(logs=[{"format": "windows"}], destination="./output"),
        )
        validator = ScenarioValidator(scenario)
        issues = validator.validate()
        stale_issues = [i for i in issues if "stale_accounts" in i.field_path]
        assert len(stale_issues) == 0

    def test_red_herring_actor_not_in_users(self):
        """Red herring with unknown actor should produce error."""
        scenario = Scenario(
            version="1.0",
            name="test",
            description="Test",
            environment=Environment(
                description="Test",
                users=[User(username="u1", full_name="U1", email="u@x.com")],
                systems=[
                    System(hostname="WS-01", ip="10.0.0.1", os="Windows 10", type="workstation")
                ],
            ),
            time_window=TimeWindow(start=datetime(2024, 1, 15, 10, 0, 0), duration="2h"),
            baseline_activity=BaselineActivity(
                description="Test", intensity="low", variation="low"
            ),
            output=OutputSpec(logs=[{"format": "windows"}], destination="./output"),
            red_herrings=[
                RedHerringEvent(
                    id="rh-1",
                    time="+30m",
                    actor="nonexistent_user",
                    system="WS-01",
                    activity="Test",
                    explanation="Test explanation",
                    events=[{"type": "process", "process_name": "cmd.exe"}],
                ),
            ],
        )
        validator = ScenarioValidator(scenario)
        issues = validator.validate()
        rh_issues = [
            i for i in issues if "red_herrings" in i.field_path and "actor" in i.field_path
        ]
        assert len(rh_issues) == 1
        assert rh_issues[0].severity == "error"
        assert "nonexistent_user" in rh_issues[0].message

    def test_red_herring_system_not_in_systems(self):
        """Red herring with unknown system should produce error."""
        scenario = Scenario(
            version="1.0",
            name="test",
            description="Test",
            environment=Environment(
                description="Test",
                users=[User(username="u1", full_name="U1", email="u@x.com")],
                systems=[
                    System(hostname="WS-01", ip="10.0.0.1", os="Windows 10", type="workstation")
                ],
            ),
            time_window=TimeWindow(start=datetime(2024, 1, 15, 10, 0, 0), duration="2h"),
            baseline_activity=BaselineActivity(
                description="Test", intensity="low", variation="low"
            ),
            output=OutputSpec(logs=[{"format": "windows"}], destination="./output"),
            red_herrings=[
                RedHerringEvent(
                    id="rh-1",
                    time="+30m",
                    actor="u1",
                    system="NONEXISTENT-HOST",
                    activity="Test",
                    explanation="Test explanation",
                    events=[{"type": "process", "process_name": "cmd.exe"}],
                ),
            ],
        )
        validator = ScenarioValidator(scenario)
        issues = validator.validate()
        rh_issues = [
            i for i in issues if "red_herrings" in i.field_path and "system" in i.field_path
        ]
        assert len(rh_issues) == 1
        assert rh_issues[0].severity == "error"
        assert "NONEXISTENT-HOST" in rh_issues[0].message

    def test_red_herring_valid_actors_and_systems(self):
        """Red herrings with valid actors and systems should produce no reference errors."""
        scenario = Scenario(
            version="1.0",
            name="test",
            description="Test",
            environment=Environment(
                description="Test",
                users=[User(username="u1", full_name="U1", email="u@x.com")],
                systems=[
                    System(hostname="WS-01", ip="10.0.0.1", os="Windows 10", type="workstation")
                ],
                service_accounts=["svc_backup"],
            ),
            time_window=TimeWindow(start=datetime(2024, 1, 15, 10, 0, 0), duration="2h"),
            baseline_activity=BaselineActivity(
                description="Test", intensity="low", variation="low"
            ),
            output=OutputSpec(logs=[{"format": "windows"}], destination="./output"),
            red_herrings=[
                RedHerringEvent(
                    id="rh-1",
                    time="+30m",
                    actor="u1",
                    system="WS-01",
                    activity="User activity",
                    explanation="Normal usage",
                    events=[{"type": "process", "process_name": "cmd.exe"}],
                ),
                RedHerringEvent(
                    id="rh-2",
                    time="+45m",
                    actor="svc_backup",
                    system="WS-01",
                    activity="Service activity",
                    explanation="Scheduled task",
                    events=[{"type": "process", "process_name": "robocopy.exe"}],
                ),
            ],
        )
        validator = ScenarioValidator(scenario)
        issues = validator.validate()
        rh_issues = [i for i in issues if "red_herrings" in i.field_path]
        assert len(rh_issues) == 0

    def test_expansion_redundancy_dns_with_connection(self):
        """Warn when storyline has manual DNS (port 53) + TCP connection in same step."""
        scenario = Scenario(
            version="1.0",
            name="test",
            description="Test",
            environment=Environment(
                description="Test",
                users=[User(username="attacker", full_name="Attacker", email="a@test.com")],
                systems=[
                    System(hostname="WS-01", ip="10.0.0.5", os="Windows 10", type="workstation"),
                ],
            ),
            personas=[
                Persona(
                    name="developer",
                    description="Dev",
                    typical_activities=["coding"],
                    work_hours="9-5",
                    application_usage=["vscode"],
                    risk_profile="low",
                )
            ],
            time_window=TimeWindow(start=datetime(2024, 1, 15, 10, 0, 0), duration="1h"),
            baseline_activity=BaselineActivity(
                description="Test", intensity="low", variation="low"
            ),
            output=OutputSpec(
                logs=[{"format": "windows"}], destination="./output", compression=False
            ),
            storyline=[
                StorylineEvent(
                    id="step1",
                    time="+1h",
                    actor="attacker",
                    system="WS-01",
                    activity="C2 callback",
                    events=[
                        {"type": "connection", "dst_ip": "10.0.0.1", "dst_port": 53},
                        {"type": "connection", "dst_ip": "203.0.113.50", "dst_port": 443},
                    ],
                ),
            ],
        )
        validator = ScenarioValidator(scenario)
        issues = validator.validate()
        expansion_warnings = [i for i in issues if "causal expansion" in i.message.lower()]
        assert len(expansion_warnings) == 1
        assert expansion_warnings[0].severity == "warning"

    def test_expansion_redundancy_no_warning_for_standalone(self):
        """No warning when storyline has only a TCP connection (no manual DNS)."""
        scenario = Scenario(
            version="1.0",
            name="test",
            description="Test",
            environment=Environment(
                description="Test",
                users=[User(username="attacker", full_name="Attacker", email="a@test.com")],
                systems=[
                    System(hostname="WS-01", ip="10.0.0.5", os="Windows 10", type="workstation"),
                ],
            ),
            personas=[
                Persona(
                    name="developer",
                    description="Dev",
                    typical_activities=["coding"],
                    work_hours="9-5",
                    application_usage=["vscode"],
                    risk_profile="low",
                )
            ],
            time_window=TimeWindow(start=datetime(2024, 1, 15, 10, 0, 0), duration="1h"),
            baseline_activity=BaselineActivity(
                description="Test", intensity="low", variation="low"
            ),
            output=OutputSpec(
                logs=[{"format": "windows"}], destination="./output", compression=False
            ),
            storyline=[
                StorylineEvent(
                    id="step1",
                    time="+1h",
                    actor="attacker",
                    system="WS-01",
                    activity="C2 callback",
                    events=[
                        {"type": "connection", "dst_ip": "203.0.113.50", "dst_port": 443},
                    ],
                ),
            ],
        )
        validator = ScenarioValidator(scenario)
        issues = validator.validate()
        expansion_warnings = [i for i in issues if "causal expansion" in i.message.lower()]
        assert len(expansion_warnings) == 0
