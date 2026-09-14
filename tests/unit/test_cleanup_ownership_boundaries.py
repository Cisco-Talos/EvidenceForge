"""Architectural acceptance gates for the behavior-preserving cleanup."""

from __future__ import annotations

import ast
from datetime import UTC, datetime, timedelta
from pathlib import Path
from unittest.mock import Mock

import pytest

from evidenceforge.generation.actions import network_transaction_planner
from evidenceforge.generation.activity import ActivityGenerator
from evidenceforge.generation.state_manager import StateManager
from evidenceforge.models.scenario import System, User


def test_network_planner_has_no_activity_generator_module_dependency() -> None:
    tree = ast.parse(Path(network_transaction_planner.__file__).read_text())
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            assert all(
                alias.name != "evidenceforge.generation.activity.generator" for alias in node.names
            )
        elif isinstance(node, ast.ImportFrom):
            assert node.module != "evidenceforge.generation.activity.generator"
            if node.module == "evidenceforge.generation.activity":
                assert all(alias.name != "generator" for alias in node.names)
        elif isinstance(node, ast.Name):
            assert node.id != "generator_module"


def test_process_bundles_execute_without_generator_execution_callbacks(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def reject_callback(*args: object, **kwargs: object) -> None:
        raise AssertionError("bundle called generator-owned process execution")

    monkeypatch.setattr(ActivityGenerator, "_execute_process_create_bundle", reject_callback)
    monkeypatch.setattr(ActivityGenerator, "_execute_process_termination_bundle", reject_callback)
    start = datetime(2024, 1, 15, 10, tzinfo=UTC)
    state = StateManager()
    state.set_current_time(start)
    system = System(hostname="WIN-01", ip="10.0.0.10", os="Windows 10", type="workstation")
    user = User(username="alice", full_name="Alice", email="alice@example.test")
    session = state.create_session(
        username=user.username,
        system=system.hostname,
        logon_type=2,
        source_ip="-",
        start_time=start,
    )
    emitter = Mock()
    emitter.can_handle.return_value = True
    generator = ActivityGenerator(state, {"ecar": emitter})
    image = r"C:\Windows\System32\cmd.exe"
    pid = generator.generate_process(user, system, start, session, image, "cmd.exe /c dir")
    generator.generate_process_termination(
        user, system, start + timedelta(minutes=5), pid, image, session
    )
    kinds = {call.args[0].event_type for call in emitter.emit.call_args_list}
    assert {"process_create", "process_terminate"} <= kinds
