# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

import random
from datetime import timedelta
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from evidenceforge.config.provider import effective_config_scope
from evidenceforge.generation.engine.storyline import StorylineMixin
from evidenceforge.models.scenario import ProcessEventSpec, User
from tests.unit.test_macos_finder_generation import _finder_engine
from tests.unit.test_macos_foundations import _TIME, _system


def test_authored_mac_root_process_does_not_create_windows_service_authentication() -> None:
    generator, state, planner = Mock(), Mock(), Mock()
    runtime = SimpleNamespace(
        world_planner=planner,
        state_manager=state,
        activity_generator=generator,
        scenario=SimpleNamespace(environment=SimpleNamespace(service_accounts=[])),
    )
    actor = User(username="root", full_name="Invented administrator", email="root@example.test")
    assert (
        StorylineMixin._resolve_storyline_process_logon_id(
            runtime, actor, _system(), _TIME, random.Random(7)
        )
        == ""
    )
    assert not generator.mock_calls
    assert not state.mock_calls
    assert not planner.mock_calls


@pytest.mark.parametrize("native", [False, True], ids=["filtered", "native"])
def test_authored_root_shell_uses_preexisting_parent_without_in_window_elevation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, native: bool
) -> None:
    engine = _finder_engine(
        tmp_path, monkeypatch, native=native, complete=False, root_foothold=True
    )
    try:
        with effective_config_scope(engine.compiled_scenario.effective_config):
            engine._initialize()
        system = engine.scenario.environment.systems[0]
        root = User(username="root", full_name="Root", email="root@example.test")
        parent_pid = engine.activity_generator._get_system_pid(
            system.hostname, "preexisting-root-shell", 0
        )
        parent = engine.state_manager.get_process_identity(system.hostname, parent_pid)
        assert parent is not None and parent.image == "/bin/sh"
        assert parent.started_at < engine.start_time and parent.logon_id == ""
        assert parent.credentials.is_unattributed_root
        sessions = engine.state_manager.get_sessions_for_user("root")
        result = engine._execute_typed_event(
            ProcessEventSpec(process_name="/bin/sh", command_line="/bin/sh", supplementary="none"),
            root,
            system,
            engine.start_time + timedelta(minutes=11),
            "Use existing elevated foothold",
            {"process"},
        )
        assert result["native_process_model"] == "fork_exec"
        child = engine.state_manager.get_process_identity(system.hostname, result["pid"])
        assert child.parent_pid == parent.pid and child.execution_ordinal == 1
        assert child.initial_image == "/bin/sh" and child.arguments == ("/bin/sh",)
        assert child.started_at >= engine.start_time and child.logon_id == ""
        assert child.credentials == parent.credentials
        assert engine.state_manager.get_sessions_for_user("root") == sessions
        assert child.image_security is not None
        engine._finalize_macos_process_coverage()
        if native:
            census = engine.dispatcher.macos_es_ingress.coverage.hosts[0].process_census
            assert census.aggregate_births == 0
            assert census.expected_forks == census.expected_execs == 1
            assert census.published_forks == census.published_execs == 1
    finally:
        engine._close_emitters()
