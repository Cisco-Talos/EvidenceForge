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

"""Tests for LogonID system scoping — processes use the correct host's session."""

from datetime import UTC, datetime, timedelta
from unittest.mock import Mock

import pytest

from evidenceforge.generation.activity import ActivityGenerator
from evidenceforge.generation.engine.storyline import StorylineMixin
from evidenceforge.generation.state_manager import StateManager
from evidenceforge.models import System, User


@pytest.fixture
def state_manager():
    sm = StateManager()
    sm.set_current_time(datetime(2024, 3, 15, 10, 0, 0, tzinfo=UTC))
    return sm


@pytest.fixture
def mock_emitters():
    return {
        "windows_event_security": Mock(),
        "zeek_conn": Mock(),
        "ecar": Mock(),
        "syslog": Mock(),
    }


@pytest.fixture
def system_a():
    return System(hostname="WKS-A", ip="10.0.10.1", os="Windows 10", type="workstation")


@pytest.fixture
def system_b():
    return System(hostname="SRV-B", ip="10.0.10.2", os="Windows Server 2019", type="server")


@pytest.fixture
def attacker():
    return User(username="attacker", full_name="Attacker", email="a@evil.com", enabled=True)


class TestLogonIdSystemScoping:
    """Verify processes on system B use system B's LogonID, not system A's."""

    def _build_engine(self, state_manager, mock_emitters, systems, users):
        """Build a minimal engine with StorylineMixin."""
        ag = ActivityGenerator(state_manager, mock_emitters)
        engine = type("FakeEngine", (StorylineMixin,), {}).__new__(
            type("FakeEngine", (StorylineMixin,), {})
        )
        engine.state_manager = state_manager
        engine.activity_generator = ag
        engine.dispatcher = ag.dispatcher
        engine.scenario = Mock()
        engine.scenario.environment.systems = systems
        engine.scenario.environment.users = users
        engine.scenario.storyline = []
        engine.malicious_events = []
        engine._system_pids = {}
        engine._created_account_sids = {}
        ag._system_pids = {}
        return engine

    def test_process_uses_target_system_logon_id(
        self, state_manager, mock_emitters, system_a, system_b, attacker
    ):
        """Process on system B should use system B's LogonID, not system A's."""
        engine = self._build_engine(state_manager, mock_emitters, [system_a, system_b], [attacker])

        # Create sessions on both systems with different LogonIDs
        logon_id_a = state_manager.create_session(
            username="attacker",
            system="WKS-A",
            logon_type=2,
            source_ip="10.0.10.1",
        )
        logon_id_b = state_manager.create_session(
            username="attacker",
            system="SRV-B",
            logon_type=10,
            source_ip="10.0.10.1",
        )
        assert logon_id_a != logon_id_b

        # Seed a parent process on system B for the process to use
        state_manager.create_process(
            "SRV-B", 4, r"C:\Windows\explorer.exe", "explorer.exe", "attacker", "Medium"
        )

        # Spy on generate_process to capture the logon_id argument
        original_generate = engine.activity_generator.generate_process
        captured_logon_ids = []

        def spy_generate(*args, **kwargs):
            captured_logon_ids.append(kwargs.get("logon_id"))
            return original_generate(*args, **kwargs)

        engine.activity_generator.generate_process = spy_generate

        spec = Mock()
        spec.type = "process"
        spec.process_name = r"C:\Windows\System32\cmd.exe"
        spec.command_line = "cmd.exe /c whoami"
        spec.supplementary = None

        engine._execute_typed_event(
            spec=spec,
            actor=attacker,
            system=system_b,
            time=datetime(2024, 3, 15, 10, 30, 0, tzinfo=UTC),
            activity="Execute command on server",
            explicit_types={"process"},
        )

        # The process should use system B's LogonID, not system A's
        assert len(captured_logon_ids) == 1
        assert captured_logon_ids[0] == logon_id_b

    def test_process_auto_creates_session_on_new_system(
        self, state_manager, mock_emitters, system_a, system_b, attacker
    ):
        """If no session on target system, auto-create one (type 3)."""
        engine = self._build_engine(state_manager, mock_emitters, [system_a, system_b], [attacker])

        # Only create session on system A
        state_manager.create_session(
            username="attacker",
            system="WKS-A",
            logon_type=2,
            source_ip="10.0.10.1",
        )

        spec = Mock()
        spec.type = "process"
        spec.process_name = r"C:\Windows\System32\cmd.exe"
        spec.command_line = "cmd.exe"
        spec.supplementary = None

        engine._execute_typed_event(
            spec=spec,
            actor=attacker,
            system=system_b,
            time=datetime(2024, 3, 15, 10, 30, 0, tzinfo=UTC),
            activity="Execute command",
            explicit_types={"process"},
        )

        # A new session should have been created on system B
        sessions = state_manager.get_sessions_for_user("attacker")
        b_sessions = [s for s in sessions if s.system == "SRV-B"]
        assert len(b_sessions) == 1
        assert b_sessions[0].logon_type == 3  # Network logon

    def test_logoff_targets_correct_system(
        self, state_manager, mock_emitters, system_a, system_b, attacker
    ):
        """Logoff on system B should end system B's session, not system A's."""
        engine = self._build_engine(state_manager, mock_emitters, [system_a, system_b], [attacker])

        state_manager.create_session(
            username="attacker",
            system="WKS-A",
            logon_type=2,
            source_ip="10.0.10.1",
        )
        state_manager.create_session(
            username="attacker",
            system="SRV-B",
            logon_type=10,
            source_ip="10.0.10.1",
        )

        spec = Mock()
        spec.type = "logoff"

        engine._execute_typed_event(
            spec=spec,
            actor=attacker,
            system=system_b,
            time=datetime(2024, 3, 15, 11, 0, 0, tzinfo=UTC),
            activity="Log off server",
            explicit_types={"logoff"},
        )

        # System A session should still exist
        sessions = state_manager.get_sessions_for_user("attacker")
        remaining_systems = {s.system for s in sessions}
        assert "WKS-A" in remaining_systems

    def test_storyline_process_access_uses_last_process_as_source(
        self, state_manager, mock_emitters, system_a, attacker
    ):
        """Typed process_access should emit Sysmon Event 10 from the prior process."""
        engine = self._build_engine(state_manager, mock_emitters, [system_a], [attacker])
        state_manager.set_current_time(datetime(2024, 3, 15, 10, 29, 0, tzinfo=UTC))
        pid = state_manager.create_process(
            "WKS-A",
            4,
            r"C:\Windows\Temp\procdump64.exe",
            r"C:\Windows\Temp\procdump64.exe -ma lsass.exe",
            attacker.username,
            "High",
            logon_id="0x12345",
        )
        engine._record_last_storyline_process(
            system_a,
            pid,
            r"C:\Windows\Temp\procdump64.exe",
        )
        engine.activity_generator.generate_process_access = Mock()

        spec = Mock()
        spec.type = "process_access"
        spec.target_process = "lsass.exe"
        spec.access_mask = "0x1010"

        engine._execute_typed_event(
            spec=spec,
            actor=attacker,
            system=system_a,
            time=datetime(2024, 3, 15, 10, 30, 0, tzinfo=UTC),
            activity="Dump credentials",
            explicit_types={"process_access"},
        )

        engine.activity_generator.generate_process_access.assert_called_once()
        kwargs = engine.activity_generator.generate_process_access.call_args.kwargs
        assert kwargs["source_pid"] == pid
        assert kwargs["source_image"] == r"C:\Windows\Temp\procdump64.exe"
        assert kwargs["target_image"] == r"C:\Windows\System32\lsass.exe"
        assert kwargs["granted_access"] == "0x1010"

    def test_storyline_create_remote_thread_normalizes_target_image(
        self, state_manager, mock_emitters, system_a, attacker
    ):
        """Typed create_remote_thread should share full target image paths across sources."""
        engine = self._build_engine(state_manager, mock_emitters, [system_a], [attacker])
        state_manager.set_current_time(datetime(2024, 3, 15, 10, 29, 0, tzinfo=UTC))
        pid = state_manager.create_process(
            "WKS-A",
            4,
            r"C:\Windows\Temp\procdump64.exe",
            r"C:\Windows\Temp\procdump64.exe -ma lsass.exe",
            attacker.username,
            "High",
            logon_id="0x12345",
        )
        engine._record_last_storyline_process(
            system_a,
            pid,
            r"C:\Windows\Temp\procdump64.exe",
        )
        engine.activity_generator.generate_create_remote_thread = Mock()
        engine.activity_generator._expand_and_emit = Mock()
        engine.activity_generator._system_pids = {"WKS-A": {"lsass": 620}}

        spec = Mock()
        spec.type = "create_remote_thread"
        spec.target_process = "lsass.exe"

        engine._execute_typed_event(
            spec=spec,
            actor=attacker,
            system=system_a,
            time=datetime(2024, 3, 15, 10, 30, 0, tzinfo=UTC),
            activity="Inject into lsass",
            explicit_types={"create_remote_thread"},
        )

        kwargs = engine.activity_generator.generate_create_remote_thread.call_args.kwargs
        assert kwargs["target_pid"] == 620
        assert kwargs["target_image"] == r"C:\Windows\System32\lsass.exe"
        expand_kwargs = engine.activity_generator._expand_and_emit.call_args.kwargs
        assert expand_kwargs["target_image"] == r"C:\Windows\System32\lsass.exe"

    def test_storyline_process_access_with_stale_source_is_marked_skipped(
        self, state_manager, mock_emitters, system_a, attacker
    ):
        """Typed process_access should not claim evidence when remembered PID is stale."""
        engine = self._build_engine(state_manager, mock_emitters, [system_a], [attacker])
        engine._record_last_storyline_process(
            system_a,
            4242,
            r"C:\Windows\Temp\procdump64.exe",
        )
        engine.activity_generator.generate_process_access = Mock()

        spec = Mock()
        spec.type = "process_access"
        spec.target_process = "lsass.exe"
        spec.access_mask = "0x1010"

        malicious_event = engine._execute_typed_event(
            spec=spec,
            actor=attacker,
            system=system_a,
            time=datetime(2024, 3, 15, 10, 30, 0, tzinfo=UTC),
            activity="Dump credentials",
            explicit_types={"process_access"},
        )

        engine.activity_generator.generate_process_access.assert_not_called()
        assert malicious_event["target_process"] == r"C:\Windows\System32\lsass.exe"
        assert malicious_event["skipped_reason"] == "no_live_source_process"

    def test_storyline_create_remote_thread_with_stale_source_is_marked_skipped(
        self, state_manager, mock_emitters, system_a, attacker
    ):
        """Typed create_remote_thread should not claim evidence when remembered PID is stale."""
        engine = self._build_engine(state_manager, mock_emitters, [system_a], [attacker])
        engine._record_last_storyline_process(
            system_a,
            4242,
            r"C:\Windows\Temp\injector.exe",
        )
        engine.activity_generator.generate_create_remote_thread = Mock()
        engine.activity_generator._expand_and_emit = Mock()

        spec = Mock()
        spec.type = "create_remote_thread"
        spec.target_process = "lsass.exe"

        malicious_event = engine._execute_typed_event(
            spec=spec,
            actor=attacker,
            system=system_a,
            time=datetime(2024, 3, 15, 10, 30, 0, tzinfo=UTC),
            activity="Inject into lsass",
            explicit_types={"create_remote_thread"},
        )

        engine.activity_generator.generate_create_remote_thread.assert_not_called()
        engine.activity_generator._expand_and_emit.assert_not_called()
        assert malicious_event["target_process"] == r"C:\Windows\System32\lsass.exe"
        assert malicious_event["skipped_reason"] == "no_live_source_process"

    def test_storyline_process_termination_is_deferred_until_step_end(
        self, state_manager, mock_emitters, system_a, attacker
    ):
        """Storyline process termination should see same-step dependent activity."""
        engine = self._build_engine(state_manager, mock_emitters, [system_a], [attacker])
        start = datetime(2024, 3, 15, 10, 0, 0, tzinfo=UTC)
        state_manager.set_current_time(start)
        pid = state_manager.create_process(
            "WKS-A",
            4,
            r"C:\Windows\Temp\tool.exe",
            "tool.exe",
            attacker.username,
            "Medium",
            logon_id="0x12345",
        )
        proc = state_manager.get_process("WKS-A", pid)
        assert proc is not None
        proc.last_activity_time = start + timedelta(seconds=20)
        engine.activity_generator.generate_process_termination = Mock()

        engine._queue_story_process_termination(
            actor=attacker,
            system=system_a,
            time=start + timedelta(seconds=5),
            pid=pid,
            process_name=r"C:\Windows\Temp\tool.exe",
            logon_id="0x12345",
        )
        engine._flush_story_process_terminations()

        engine.activity_generator.generate_process_termination.assert_called_once()
        kwargs = engine.activity_generator.generate_process_termination.call_args.kwargs
        assert kwargs["time"] == start + timedelta(seconds=5)
        assert kwargs["from_storyline"] is True


class _FixedRng:
    def uniform(self, a: float, b: float) -> float:
        return 0.0

    def randint(self, a: int, b: int) -> int:
        return max(a, 1000)


def test_execute_storyline_uses_last_intra_step_timestamp_for_monotonic_ordering(
    state_manager, mock_emitters, system_a, attacker, monkeypatch
):
    """Later storyline steps should be scheduled after prior step cadence offsets."""
    ag = ActivityGenerator(state_manager, mock_emitters)
    engine = type("FakeEngine", (StorylineMixin,), {}).__new__(
        type("FakeEngine", (StorylineMixin,), {})
    )
    engine.state_manager = state_manager
    engine.activity_generator = ag
    engine.dispatcher = ag.dispatcher
    engine.malicious_events = []
    engine._created_account_sids = {}
    engine.scenario = Mock()
    engine.scenario.environment.systems = [system_a]
    engine.scenario.environment.users = [attacker]
    engine._system_pids = {}
    ag._system_pids = {}
    engine._report_progress = lambda *args, **kwargs: None
    engine._barrier_flush_all_emitters = lambda: None
    engine._find_actor = lambda actor_name: attacker if actor_name == attacker.username else None
    engine._find_system = lambda hostname: system_a if hostname == system_a.hostname else None

    step_1 = Mock()
    step_1.time = "2024-03-15T10:00:00Z"
    step_1.actor = attacker.username
    step_1.system = system_a.hostname
    step_1.activity = "step one"
    step_1.events = [Mock(type="process"), Mock(type="process")]

    step_2 = Mock()
    step_2.time = "2024-03-15T10:00:05Z"
    step_2.actor = attacker.username
    step_2.system = system_a.hostname
    step_2.activity = "step two"
    step_2.events = [Mock(type="process")]

    engine.scenario.storyline = [step_1, step_2]

    parsed_times = {
        step_1.time: datetime(2024, 3, 15, 10, 0, 0, tzinfo=UTC),
        step_2.time: datetime(2024, 3, 15, 10, 0, 5, tzinfo=UTC),
    }
    monkeypatch.setattr(engine, "_parse_storyline_time", lambda t: parsed_times[t])
    monkeypatch.setattr("evidenceforge.generation.engine.storyline._get_rng", lambda: _FixedRng())

    def fake_typing_cadence(count: int, _rng: _FixedRng) -> list[float]:
        if count == 2:
            return [0.0, 10.0]
        return [0.0]

    monkeypatch.setattr("evidenceforge.utils.timing.typing_cadence", fake_typing_cadence)

    observed_times: list[datetime] = []

    def fake_execute_typed_event(
        *,
        spec,
        actor,
        system,
        time: datetime,
        activity: str,
        explicit_types: set[str],
    ):
        observed_times.append(time)
        return None

    monkeypatch.setattr(engine, "_execute_typed_event", fake_execute_typed_event)

    engine._execute_storyline()

    assert observed_times == sorted(observed_times)
    assert observed_times[1] == observed_times[0] + timedelta(seconds=10)
    assert observed_times[2] > observed_times[1]


def test_log_cleared_storyline_event_inherits_recent_wevtutil_logon_id(
    state_manager, mock_emitters, system_a, attacker, monkeypatch
):
    """Typed log_cleared events should stay attached to the clearing process token."""
    ag = ActivityGenerator(state_manager, mock_emitters)
    engine = type("FakeEngine", (StorylineMixin,), {}).__new__(
        type("FakeEngine", (StorylineMixin,), {})
    )
    engine.state_manager = state_manager
    engine.activity_generator = ag
    engine.dispatcher = ag.dispatcher
    engine.malicious_events = []

    process_time = datetime(2024, 3, 15, 10, 0, 0, tzinfo=UTC)
    state_manager.set_current_time(process_time)
    logon_id = state_manager.create_session(
        username=attacker.username,
        system=system_a.hostname,
        logon_type=2,
        source_ip=system_a.ip,
    )
    pid = state_manager.create_process(
        system_a.hostname,
        4,
        r"C:\Windows\System32\wevtutil.exe",
        "wevtutil cl Security",
        attacker.username,
        "High",
        logon_id=logon_id,
    )
    engine._record_last_storyline_process(system_a, pid, r"C:\Windows\System32\wevtutil.exe")

    captured: dict[str, str | None] = {}

    def fake_generate_log_cleared(*args, **kwargs):
        captured["subject_logon_id"] = kwargs["subject_logon_id"]

    monkeypatch.setattr(ag, "generate_log_cleared", fake_generate_log_cleared)

    engine._execute_typed_event(
        spec=Mock(type="log_cleared"),
        actor=attacker,
        system=system_a,
        time=process_time + timedelta(seconds=2),
        activity="clear security log",
        explicit_types=set(),
    )

    assert captured["subject_logon_id"] == logon_id
