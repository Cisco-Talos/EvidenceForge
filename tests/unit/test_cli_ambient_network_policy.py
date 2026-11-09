# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Endpoint-bound CLI tools cannot acquire unrelated ambient network ownership."""

import random
from pathlib import Path
from unittest.mock import Mock

import pytest

from evidenceforge.generation.activity.generator import ActivityGenerator
from evidenceforge.generation.activity.process_network import (
    ambient_network_allowed,
    get_exe_to_service,
    get_service_to_exes,
)
from evidenceforge.generation.state_manager import StateManager
from evidenceforge.models.scenario import System
from tests.unit.test_deployment_assignment_consumers import (
    _ACTIVITY_TIME,
    _service_entry,
    _ServiceAssignmentRegistry,
    _world_planner_harness,
)


@pytest.mark.parametrize("executable", ["git", "npm", "cargo", "docker", "kubectl"])
def test_cli_network_policy_requires_explicit_intent_in_both_indexes(executable: str) -> None:
    assert get_exe_to_service()[executable]["ambient"] is False
    assert not ambient_network_allowed(str(Path("/usr/local/bin") / executable))
    assert not ambient_network_allowed("C:\\Tools\\" + executable + ".exe")
    assert executable not in get_service_to_exes()["ssl"]
    assert ambient_network_allowed("chrome.exe")


@pytest.mark.parametrize(
    "command", ["docker ps", "docker images", "kubectl get pods", "git status"]
)
def test_local_or_configured_cli_queries_cannot_invent_ambient_connections(command: str) -> None:
    state = StateManager()
    generator = ActivityGenerator(state, {})
    generator.generate_connection = Mock(side_effect=AssertionError("Unexpected connection"))
    system = System(hostname="MAC-A", ip="192.0.2.10", os="macOS 26", type="workstation")
    before = state.materialization_digest()
    generator._emit_process_network_correlation(
        system,
        "/usr/local/bin/" + command.split()[0],
        command,
        _ACTIVITY_TIME,
        42,
        random.Random(0),
    )
    assert state.materialization_digest() == before
    generator.generate_connection.assert_not_called()


@pytest.mark.parametrize("explicit_application", [False, True])
def test_world_planner_cannot_select_cli_for_generic_https(explicit_application: bool) -> None:
    registry = _ServiceAssignmentRegistry(
        {"docker": _service_entry("docker", "docker", r"C:\Tools\docker")},
        executable_ids={"docker": ("docker",)},
    )
    planner, session, user, system, generated = _world_planner_harness(registry)
    pid = planner.ensure_connection_process(
        user,
        system,
        session,
        _ACTIVITY_TIME,
        "ssl",
        random.Random(0),
        application_ids=["docker"] if explicit_application else None,
    )
    assert pid == -1 and not generated and not registry.materialize_calls
