# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Process operations use current owners without adding durable service state."""

import ast
from dataclasses import fields
from pathlib import Path

import pytest

from evidenceforge.generation.activity import ActivityGenerator
from evidenceforge.generation.state_manager import StateManager


def test_process_services_rebind_replaced_state_timing_and_cache_owners() -> None:
    generator = ActivityGenerator(StateManager(), {})
    first = generator._process_execution_service()
    original_fields = set(vars(generator))
    replacement = ActivityGenerator(StateManager(), {})
    for name in (
        "state_manager",
        "dispatcher",
        "_lifecycle_authority",
        "_source_timing_planner",
        "_runtime_content_manager",
        "_execution_effect_audit",
        "_process_source_create_times",
        "_process_source_create_bounds",
        "_terminated_process_keys",
        "_terminated_process_times",
        "_foreground_process_finalizers",
        "_foreground_shell_next_time",
        "_preferred_browser_by_session",
        "_last_one_shot_cli_launch_by_command",
    ):
        setattr(generator, name, getattr(replacement, name))

    current = generator._process_execution_service()
    terminal = generator._process_termination_service()
    system = generator._process_system()

    assert current is not first
    assert current.state_manager is replacement.state_manager
    assert terminal.state_manager is replacement.state_manager
    assert system.state_manager is replacement.state_manager
    assert current.lifecycle_authority is replacement._lifecycle_authority
    assert current.sources._source_timing_planner is replacement._source_timing_planner
    assert current.sources._process_source_create_times is replacement._process_source_create_times
    assert current.queries._terminated_process_keys is replacement._terminated_process_keys
    assert terminal.foreground._terminated_process_times is replacement._terminated_process_times
    assert (
        current.foreground._foreground_process_finalizers
        is replacement._foreground_process_finalizers
    )
    assert current.reuse._preferred_browser_by_session is replacement._preferred_browser_by_session
    assert (
        current.scheduling._last_one_shot_cli_launch_by_command
        is replacement._last_one_shot_cli_launch_by_command
    )
    assert set(vars(generator)) == original_fields
    for service in (current, terminal, system):
        assert all(getattr(service, field.name) is not generator for field in fields(service))


def test_process_implementations_do_not_import_or_accept_the_generator() -> None:
    root = Path(__file__).resolve().parents[2] / "src/evidenceforge/generation/actions"
    paths = [root / "process_execution_service.py", *(root / "process_support").glob("*.py")]
    for path in paths:
        tree = ast.parse(path.read_text())
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom):
                assert node.module != "evidenceforge.generation.activity.generator", path
            if isinstance(node, ast.Name):
                assert node.id != "ActivityGenerator", path
            if isinstance(node, ast.Attribute):
                assert not (
                    isinstance(node.value, ast.Name)
                    and node.value.id == "self"
                    and node.attr in {"runtime", "generator", "executor"}
                ), path


@pytest.mark.soak
def test_repeated_process_services_release_bindings_after_watermark_replacement(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Thirty days of create/terminate calls retain no service or obsolete cache binding."""
    import gc
    import weakref
    from datetime import UTC, datetime, timedelta

    from evidenceforge.events.dispatcher import EventDispatcher
    from evidenceforge.generation.actions.process_execution_service import (
        ProcessExecutionService,
        ProcessTerminationService,
    )
    from evidenceforge.models.scenario import System, User

    state = StateManager()
    generator = ActivityGenerator(
        state, {}, dispatcher=EventDispatcher(state_manager=state, emitters={})
    )
    user = User(username="alice", full_name="Alice", email="alice@example.test")
    system = System(hostname="WIN", ip="10.0.0.1", os="Windows 11", type="workstation")
    image = r"C:\Windows\System32\whoami.exe"
    start = datetime(2024, 1, 1, tzinfo=UTC)
    references: list[
        weakref.ReferenceType[ProcessExecutionService | ProcessTerminationService]
    ] = []
    create_binding = generator._process_execution_service
    terminate_binding = generator._process_termination_service

    def bind_create() -> ProcessExecutionService:
        service = create_binding()
        assert (
            service.sources._process_source_create_times is generator._process_source_create_times
        )
        references.append(weakref.ref(service))
        return service

    def bind_terminate() -> ProcessTerminationService:
        service = terminate_binding()
        assert service.foreground._terminated_process_times is generator._terminated_process_times
        references.append(weakref.ref(service))
        return service

    monkeypatch.setattr(generator, "_process_execution_service", bind_create)
    monkeypatch.setattr(generator, "_process_termination_service", bind_terminate)
    for day in range(30):
        for ordinal in range(32):
            timestamp = start + timedelta(days=day, minutes=ordinal * 10)
            pid = generator.generate_process(
                user,
                system,
                timestamp,
                "0x123",
                image,
                "whoami.exe",
                from_storyline=True,
                suppress_command_file_effect=True,
            )
            generator.generate_process_termination(
                user, system, timestamp + timedelta(minutes=2), pid, image, "0x123"
            )
        generator.advance_process_state_watermark(start + timedelta(days=day, hours=12))
        assert not generator._process_source_create_times
        assert not generator._process_source_terminate_times
        assert not generator._terminated_process_keys
        if day in {6, 29}:
            gc.collect()
            assert references and all(reference() is None for reference in references)


def test_unseeded_process_binding_cannot_retain_a_parallel_role_table() -> None:
    from datetime import UTC, datetime

    from evidenceforge.models.scenario import System

    state = StateManager()
    timestamp = datetime(2024, 1, 1, tzinfo=UTC)
    state.set_current_time(timestamp)
    generator = ActivityGenerator(state, {})
    system = System(hostname="LNX", ip="10.0.0.1", os="Ubuntu 24.04", type="server")
    parents = generator._process_parents()

    pid = parents._linux_anchor_pid(system, timestamp)

    assert state.get_process(system.hostname, pid) is not None
    assert not hasattr(generator, "_system_pids")
    assert parents._system_pids is None
    assert generator._process_reuse()._system_pids is None
    generator._system_pids = {system.hostname: {"systemd": pid}}
    assert generator._process_parents()._system_pids is generator._system_pids
    assert generator._process_reuse()._system_pids is generator._system_pids
