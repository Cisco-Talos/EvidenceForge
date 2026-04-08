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

"""Unit tests for Phase 5.1.1: SID generation and population."""

import re
from datetime import UTC, datetime
from unittest.mock import Mock

import pytest

from evidenceforge.generation.activity import ActivityGenerator
from evidenceforge.generation.state_manager import StateManager
from evidenceforge.models import System, User

# Valid SID pattern: S-1-5-21-{3 sub-authorities}-{RID}
SID_PATTERN = re.compile(r"^S-1-5-21-\d+-\d+-\d+-\d+$")
WELL_KNOWN_SIDS = {
    "SYSTEM": "S-1-5-18",
    "LOCAL SERVICE": "S-1-5-19",
    "NETWORK SERVICE": "S-1-5-20",
}


@pytest.fixture
def state_manager():
    return StateManager()


@pytest.fixture
def mock_emitters():
    return {
        "windows_event_security": Mock(),
        "zeek_conn": Mock(),
    }


@pytest.fixture
def sid_registry():
    """Build a test SID registry."""
    base = "S-1-5-21-1234567890-2345678901-3456789012"
    return {
        "SYSTEM": "S-1-5-18",
        "LOCAL SERVICE": "S-1-5-19",
        "NETWORK SERVICE": "S-1-5-20",
        "alice.smith": f"{base}-1001",
        "bob.jones": f"{base}-1002",
    }


@pytest.fixture
def activity_gen(state_manager, mock_emitters, sid_registry):
    return ActivityGenerator(state_manager, mock_emitters, sid_registry=sid_registry)


@pytest.fixture
def test_user():
    return User(
        username="alice.smith", full_name="Alice Smith", email="alice@corp.com", enabled=True
    )


@pytest.fixture
def test_system():
    return System(hostname="WKS-01", ip="10.0.10.1", os="Windows 10", type="workstation")


@pytest.fixture
def timestamp():
    return datetime(2024, 3, 15, 10, 0, 0, tzinfo=UTC)


class TestSIDRegistry:
    """Tests for SID registry lookup."""

    def test_get_sid_known_user(self, activity_gen):
        assert (
            activity_gen._get_sid("alice.smith") == "S-1-5-21-1234567890-2345678901-3456789012-1001"
        )

    def test_get_sid_system(self, activity_gen):
        assert activity_gen._get_sid("SYSTEM") == "S-1-5-18"

    def test_get_sid_unknown_user_returns_synthetic_domain_sid(self, activity_gen):
        sid = activity_gen._get_sid("unknown.user")
        # Should be a deterministic synthetic domain SID, not Null SID
        assert sid.startswith("S-1-5-21-")
        assert sid.count("-") == 7
        # Should be cached for consistency
        assert activity_gen._get_sid("unknown.user") == sid

    def test_sid_format_valid(self, sid_registry):
        for username, sid in sid_registry.items():
            if username in WELL_KNOWN_SIDS:
                assert sid == WELL_KNOWN_SIDS[username]
            else:
                assert SID_PATTERN.match(sid), f"SID for {username} has invalid format: {sid}"

    def test_sid_registry_consistency(self, activity_gen):
        """Same user always gets same SID."""
        sid1 = activity_gen._get_sid("alice.smith")
        sid2 = activity_gen._get_sid("alice.smith")
        assert sid1 == sid2


class TestSIDInWindowsEvents:
    """Tests that SID fields are populated in emitted Windows events."""

    def test_logon_4624_has_sids(
        self, activity_gen, test_user, test_system, timestamp, state_manager, mock_emitters
    ):
        state_manager.set_current_time(timestamp)
        activity_gen.generate_logon(test_user, test_system, timestamp)

        # Logon now dispatched via SecurityEvent
        event = mock_emitters["windows_event_security"].emit.call_args[0][0]
        assert event.auth.subject_sid == "S-1-5-18"  # SYSTEM
        assert SID_PATTERN.match(event.auth.user_sid)
        assert event.auth.user_sid == activity_gen._get_sid("alice.smith")

    def test_logoff_4634_has_sid(
        self, activity_gen, test_user, test_system, timestamp, state_manager, mock_emitters
    ):
        state_manager.set_current_time(timestamp)
        logon_id = activity_gen.generate_logon(test_user, test_system, timestamp)
        mock_emitters["windows_event_security"].reset_mock()

        activity_gen.generate_logoff(test_user, test_system, timestamp, logon_id)

        # Logoff dispatched via SecurityEvent
        event = mock_emitters["windows_event_security"].emit.call_args[0][0]
        assert event.event_type == "logoff"
        assert SID_PATTERN.match(event.auth.user_sid)
        assert event.auth.user_sid == activity_gen._get_sid("alice.smith")

    def test_process_4688_has_sids(
        self, activity_gen, test_user, test_system, timestamp, state_manager, mock_emitters
    ):
        state_manager.set_current_time(timestamp)
        logon_id = activity_gen.generate_logon(test_user, test_system, timestamp)
        mock_emitters["windows_event_security"].reset_mock()

        activity_gen.generate_process(
            test_user,
            test_system,
            timestamp,
            logon_id,
            "C:\\Windows\\System32\\cmd.exe",
            "cmd.exe /c dir",
        )

        # Process dispatched via SecurityEvent (find process_create among possible file/registry events)
        process_events = [
            call[0][0]
            for call in mock_emitters["windows_event_security"].emit.call_args_list
            if call[0][0].event_type == "process_create"
        ]
        assert len(process_events) >= 1
        event = process_events[0]
        assert SID_PATTERN.match(event.auth.user_sid)
        assert event.auth.user_sid == activity_gen._get_sid("alice.smith")

    def test_no_sid_registry_uses_fallback(self, state_manager, mock_emitters, timestamp):
        """ActivityGenerator without sid_registry still works with fallback SIDs."""
        gen = ActivityGenerator(state_manager, mock_emitters)
        user = User(username="noone", full_name="No One", email="no@one.com", enabled=True)
        system = System(hostname="WKS-02", ip="10.0.10.2", os="Windows 10", type="workstation")
        state_manager.set_current_time(timestamp)

        gen.generate_logon(user, system, timestamp)

        # Logon dispatched via SecurityEvent
        event = mock_emitters["windows_event_security"].emit.call_args[0][0]
        assert event.auth.subject_sid == "S-1-5-18"  # SYSTEM always known
        assert event.auth.user_sid == "S-1-0-0"  # No domain SIDs available, falls back


class TestEngineSIDRegistry:
    """Tests for SID registry creation in the engine."""

    def test_build_sid_registry(self):
        """Engine._build_sid_registry creates valid registry."""
        from pathlib import Path

        from evidenceforge.generation.engine import GenerationEngine
        from evidenceforge.models.scenario import (
            BaselineActivity,
            Environment,
            OutputSpec,
            Scenario,
            TimeWindow,
        )

        scenario = Scenario(
            name="test-sid",
            description="Test SID generation",
            time_window=TimeWindow(start="2024-01-15T08:00:00Z", duration="2h"),
            environment=Environment(
                description="Test env",
                users=[
                    User(
                        username="user.one", full_name="User One", email="u1@test.com", enabled=True
                    ),
                    User(
                        username="user.two", full_name="User Two", email="u2@test.com", enabled=True
                    ),
                ],
                systems=[
                    System(hostname="WKS-01", ip="10.0.10.1", os="Windows 10", type="workstation"),
                ],
                service_accounts=["svc_backup"],
            ),
            baseline_activity=BaselineActivity(
                description="Test baseline", intensity="low", variation="low"
            ),
            output=OutputSpec(logs=[{"format": "windows_event_security"}], destination="./output"),
            personas=[],
        )

        engine = GenerationEngine(scenario, Path("/tmp/test-sid-output"))
        registry = engine._build_sid_registry()

        # Well-known SIDs
        assert registry["SYSTEM"] == "S-1-5-18"
        assert registry["LOCAL SERVICE"] == "S-1-5-19"
        assert registry["NETWORK SERVICE"] == "S-1-5-20"

        # User SIDs with valid format
        assert SID_PATTERN.match(registry["user.one"])
        assert SID_PATTERN.match(registry["user.two"])

        # User RIDs: start at 1001, with random gaps (non-sequential)
        rid_one = int(registry["user.one"].rsplit("-", 1)[1])
        rid_two = int(registry["user.two"].rsplit("-", 1)[1])
        assert rid_one != rid_two
        assert rid_one == 1001  # First user always starts at 1001
        assert rid_two > rid_one  # Second user has higher RID (with gap)

        # Computer account SIDs
        assert "WKS-01$" in registry
        comp_rid = int(registry["WKS-01$"].rsplit("-", 1)[1])
        assert comp_rid >= 1100  # Computer RIDs start at 1100+

        # Service account SID
        assert SID_PATTERN.match(registry["svc_backup"])
        rid_svc = int(registry["svc_backup"].rsplit("-", 1)[1])
        assert rid_svc > comp_rid  # Service accounts after computer accounts

    def test_build_sid_registry_deterministic(self):
        """Same scenario name produces same domain base SID."""
        from pathlib import Path

        from evidenceforge.generation.engine import GenerationEngine
        from evidenceforge.models.scenario import (
            BaselineActivity,
            Environment,
            OutputSpec,
            Scenario,
            TimeWindow,
        )

        def make_engine():
            scenario = Scenario(
                name="deterministic-test",
                description="Test",
                time_window=TimeWindow(start="2024-01-15T08:00:00Z", duration="2h"),
                environment=Environment(
                    description="Test",
                    users=[User(username="u1", full_name="U1", email="u1@t.com", enabled=True)],
                    systems=[
                        System(hostname="S1", ip="10.0.0.1", os="Windows 10", type="workstation")
                    ],
                ),
                baseline_activity=BaselineActivity(
                    description="Test baseline", intensity="low", variation="low"
                ),
                output=OutputSpec(
                    logs=[{"format": "windows_event_security"}], destination="./output"
                ),
                personas=[],
            )
            return GenerationEngine(scenario, Path("/tmp/test"))

        r1 = make_engine()._build_sid_registry()
        r2 = make_engine()._build_sid_registry()
        assert r1["u1"] == r2["u1"]
