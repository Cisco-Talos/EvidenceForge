# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

from dataclasses import replace
from pathlib import Path
from unittest.mock import Mock

import pytest

from evidenceforge.events.process_executable import ProcessExecutableVersion
from evidenceforge.generation.actions.ssh_session import SshSessionActionBundle
from evidenceforge.generation.checkpoints.state_manager_head import _capture_head, _restore_head
from evidenceforge.generation.deployment_compiler import compile_native_deployment_registry
from evidenceforge.generation.deployment_registry import DeploymentContentRegistry
from evidenceforge.generation.engine.emitter_setup import BootFleetSpec, EmitterSetupMixin
from evidenceforge.generation.state_manager import StateManager
from evidenceforge.generation.world_model import WorldModel
from evidenceforge.models.scenario import Scenario, System
from tests.support.macos_ssh import macos_ssh_scenario
from tests.unit.test_macos_ssh_receiver_planning import _mac_fixture
from tests.unit.test_process_execution_state import _START


def _compiled(scenarios_dir: Path, hostname: str) -> DeploymentContentRegistry:
    original = macos_ssh_scenario(scenarios_dir)
    scenario = Scenario.model_validate_json(
        original.model_dump_json().replace('"TEST-01"', f'"{hostname}"')
    )
    return compile_native_deployment_registry(scenario, WorldModel(scenario, "example.test"))


@pytest.mark.parametrize("direct", [False, True])
def test_boot_plan_binds_compiled_images_in_request_state_and_recovery(
    scenarios_dir: Path, direct: bool
) -> None:
    state = StateManager()
    state.set_current_time(_START)
    engine = Mock(spec=EmitterSetupMixin)
    engine.state_manager = state
    engine.deployment_registry = _compiled(scenarios_dir, "MAC-BOOT")
    system = System(hostname="MAC-BOOT", ip="192.0.2.44", os="macOS 26", type="workstation")
    spec = EmitterSetupMixin._build_macos_boot_host_spec(engine, system, _START)
    engine._build_macos_boot_host_spec.return_value = spec
    assert all(member.executable_version is not None for member in spec.processes)
    fleet = BootFleetSpec(_START, (spec,))
    stripped = replace(
        spec, processes=tuple(replace(member, executable_version=None) for member in spec.processes)
    )
    assert (
        EmitterSetupMixin._boot_materialization_request(engine, fleet)[1]
        != EmitterSetupMixin._boot_materialization_request(
            engine, replace(fleet, hosts=(stripped,))
        )[1]
    )
    if direct:
        pids: dict[str, int] = {}
        EmitterSetupMixin._seed_macos_process_tree(engine, system, pids)
    else:
        builder = state.begin_materialization_batch()
        pids = EmitterSetupMixin._plan_boot_host_spec(builder, spec)
        with state.prepared_materialization_batch(builder.seal()) as prepared:
            prepared.apply_provisional()
            prepared.finalize_no_fail()
    restored = StateManager()
    _restore_head(restored, _capture_head(state))
    for member in spec.processes:
        expected = ProcessExecutableVersion.from_binary(
            engine.deployment_registry.resolve_binary(
                system.hostname, member.image, "macos", principal="root"
            )
        )
        for owner in (state, restored):
            assert (
                owner.get_process_identity(system.hostname, pids[member.alias]).executable_version
                == expected
            )


@pytest.mark.parametrize("collect", [False, True])
def test_ssh_wrapper_exec_fork_and_close_retain_exact_deployed_images(
    tmp_path: Path, scenarios_dir: Path, collect: bool
) -> None:
    fixture = _mac_fixture(tmp_path)
    dispatcher = fixture.generator.dispatcher
    registry = _compiled(scenarios_dir, fixture.target.hostname)
    dispatcher.deployment_registry = registry
    if not collect:
        dispatcher.emitters.clear()
    bundle = SshSessionActionBundle(
        replace(fixture.request(), emit_session_close=True), fixture.generator
    )
    transport = bundle._plan_transport(deferred_publication=True)
    prepared = bundle._prepare_deferred_open(transport)
    receiver = prepared.close_continuation.startup_request.receiver
    assert receiver.executable_version == ProcessExecutableVersion.from_binary(
        registry.resolve_binary(receiver.hostname, receiver.image, "macos", principal="root")
    )
    transaction = bundle._open_deferred_transport(transport, prepared)
    continuation = bundle._bind_deferred_close_continuation(prepared, transaction)
    fixture.generator._defer_ssh_session_close(continuation)
    continuation.prepared.drain_receiver_startup(fixture.generator)
    processes = [
        process
        for process in fixture.state.list_running_processes()
        if process.system == fixture.target.hostname and process.pid != 1
    ]
    assert len(processes) == 3
    versions = {}
    for running in processes:
        identity = fixture.state.get_process_identity(running.system, running.pid)
        expected = ProcessExecutableVersion.from_binary(
            registry.resolve_binary(
                identity.hostname, identity.image, "macos", principal=identity.principal
            )
        )
        assert identity.executable_version == expected
        versions[identity.object_id] = expected
    fixture.generator._finalize_exact_ssh_close_continuation(continuation)
    restored = StateManager()
    _restore_head(restored, _capture_head(fixture.state))
    for object_id, expected in versions.items():
        assert restored.get_process_identity_by_object_id(object_id).executable_version == expected
    fixture.close_and_read()
