# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Retained file effects share the executed process's existing atomic publication."""

from dataclasses import replace
from datetime import timedelta
from pathlib import Path

import pytest

from evidenceforge.formats.macos_endpoint_security import decode_endpoint_security_record
from evidenceforge.generation.actions.command_effects import (
    ExecutionEffectNode,
    ExecutionEffectPlan,
    ExecutionEffectPlanError,
    FileEffectAction,
    FileEffectIntent,
    NetworkEffectIntent,
)
from evidenceforge.generation.actions.endpoint_effects import (
    EndpointEffectSpec,
    EndpointStateDisposition,
    PreparedEndpointEffect,
    PreparedFileEffectPayload,
)
from evidenceforge.generation.actions.process_execution import (
    ProcessExecutionActionBundle,
    ProcessExecutionRequest,
)
from evidenceforge.generation.checkpoints.artifact_registry_head import (
    LocalArtifactVersionRegistryParticipant,
)
from evidenceforge.generation.checkpoints.state_manager_head import _capture_head, _restore_head
from evidenceforge.generation.deployment_registry import (
    LocalArtifactPublicationReceipt,
    LocalArtifactVersionRegistry,
    _LocalArtifactPreparedCommitPlan,
    _LocalArtifactPreparedReservation,
)
from evidenceforge.generation.emitters.base import ExactPublicationBatch
from evidenceforge.generation.engine import GenerationEngine
from evidenceforge.generation.state_manager import StateManager
from evidenceforge.models.exceptions import EventContractError, StateError
from tests.unit.test_macos_exec_script import _script
from tests.unit.test_macos_installed_provisioning import _scenario
from tests.unit.test_macos_runtime_es_preparation import _publish
from tests.unit.test_macos_runtime_file_metadata import _manager


@pytest.mark.parametrize(
    "native,collected,action,fault",
    [
        (native, True, action, "none")
        for native in (False, True)
        for action in (FileEffectAction.CREATE, FileEffectAction.MODIFY, FileEffectAction.DELETE)
    ]
    + [
        (True, False, action, "none")
        for action in (FileEffectAction.CREATE, FileEffectAction.MODIFY, FileEffectAction.DELETE)
    ]
    + [
        (True, True, FileEffectAction.CREATE, "artifact"),
        (True, True, FileEffectAction.DELETE, "artifact"),
        (True, True, FileEffectAction.MODIFY, "before"),
        (True, True, FileEffectAction.DELETE, "after"),
        (True, True, FileEffectAction.CREATE, "unowned-root-plan"),
        (True, True, FileEffectAction.CREATE, "placement-time"),
    ],
)
def test_retained_file_effect_has_one_native_exec_and_exact_file_checkpoint(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    native: bool,
    collected: bool,
    action: FileEffectAction,
    fault: str,
) -> None:
    scenario = _scenario()
    scenario.output.logs = ([{"format": "ecar"}] if collected else []) + (
        [{"format": "macos_endpoint_security"}] if native else []
    )
    engine = GenerationEngine(scenario, tmp_path)
    engine._chronological_es_delivery = True
    try:
        engine._initialize()
        generator = engine.activity_generator
        system, user = scenario.environment.systems[0], scenario.environment.users[0]
        at = engine.start_time - timedelta(minutes=5)
        logon = generator.generate_logon(user, system, at, allow_local_session_reuse=False)
        shell = generator.ensure_macos_session_shell(user, system, logon, at + timedelta(minutes=1))
        assert shell is not None
        content = _manager()
        generator._runtime_content_manager = content
        engine.dispatcher.bind_local_artifact_registry(content.registry)
        descriptor, _ = _script(content, system.hostname)
        descriptor = replace(
            descriptor,
            principal=user.username,
            native_path=f"/Users/{user.username}/Documents/invented-owned.txt",
        )
        if action is not FileEffectAction.CREATE:
            _publish(content, descriptor, engine.start_time - timedelta(seconds=1))
        if action is FileEffectAction.MODIFY:
            descriptor = replace(descriptor, artifact_version=2, content_version=2)
        at = engine.start_time + timedelta(minutes=1)
        observed_at = at + timedelta(seconds=1)
        record = content.build_record(descriptor)
        publication = content.registry.prepare_publish_version(
            record, observed_at, withdraw_placement=action is FileEffectAction.DELETE
        )
        effect = PreparedEndpointEffect(
            spec=EndpointEffectSpec(
                intent=FileEffectIntent(action, descriptor.native_path),
                occurrence_times=(
                    observed_at + timedelta(seconds=1)
                    if fault == "placement-time"
                    else observed_at,
                ),
                instance_key="invented-owned-file",
                state_disposition=(
                    EndpointStateDisposition.NONE
                    if action is FileEffectAction.DELETE
                    else EndpointStateDisposition.DURABLE_FINAL
                ),
                retention_deadline=None if action is FileEffectAction.DELETE else engine.end_time,
            ),
            event_type=f"file_{action.value}",
            payload=PreparedFileEffectPayload(descriptor.native_path, action, publication),
        )
        request = ProcessExecutionRequest(
            user,
            system,
            at,
            logon,
            "/bin/zsh",
            "/bin/zsh /Users/alex/invented-writer.sh",
            parent_pid=shell,
            require_exact_parent=True,
            from_storyline=True,
            arguments=("/bin/zsh", "/Users/alex/invented-writer.sh"),
            suppress_command_file_effect=True,
            requested_endpoint_effects=(effect,),
        )
        if fault == "unowned-root-plan":
            anchor = ProcessExecutionActionBundle(generator, request).anchor
            request = replace(
                request,
                effect_plan=ExecutionEffectPlan(
                    anchor=anchor,
                    nodes=(
                        ExecutionEffectNode.create(anchor, NetworkEffectIntent("192.0.2.44", 443)),
                    ),
                ),
            )
            with pytest.raises(ExecutionEffectPlanError, match="reconciliation_incomplete"):
                ProcessExecutionActionBundle(generator, request).execute()
            pid = next(
                process.pid
                for process in engine.state_manager.get_processes_for_session(logon)
                if process.command_line == request.command_line
            )
            assert (
                engine.state_manager.get_process_identity(system.hostname, pid).execution_ordinal
                == 0
            )
            with pytest.raises(StateError, match="Incomplete native macOS process coverage"):
                engine._finalize_macos_process_coverage()
            assert (
                engine.dispatcher.macos_es_ingress.coverage.hosts[0].process_census.aggregate_births
                == 1
            )
            return
        if fault == "placement-time":
            census = engine.state_manager.macos_process_census_snapshot()
            processes = engine.state_manager.get_processes_for_session(logon)
            with pytest.raises(EventContractError, match="lost authenticated"):
                ProcessExecutionActionBundle(generator, request).execute()
            assert engine.state_manager.macos_process_census_snapshot() == census
            assert engine.state_manager.get_processes_for_session(logon) == processes
            assert (
                content.resolve_record(
                    system.hostname, user.username, descriptor.native_path, "macos"
                )
                is None
            )
            assert content.registry.census().prepared_publications == 0
            return
        if fault == "none":
            pid = ProcessExecutionActionBundle(generator, request).execute()
        elif fault == "artifact":
            initial_file = content.resolve_record(
                system.hostname, user.username, descriptor.native_path, "macos"
            )
            census = engine.state_manager.macos_process_census_snapshot()
            processes = engine.state_manager.get_processes_for_session(logon)
            lifecycle = generator._lifecycle_authority.census()
            audit = generator.execution_effect_audit_snapshot()
            commit = LocalArtifactVersionRegistry._commit_prepared_locked

            def fail_after_file_change(
                registry: LocalArtifactVersionRegistry,
                reservation: _LocalArtifactPreparedReservation,
                plan: _LocalArtifactPreparedCommitPlan,
            ) -> LocalArtifactPublicationReceipt:
                receipt = commit(registry, reservation, plan)
                if (
                    reservation.canonical_token.record == publication.record
                    and reservation.canonical_token.observed_at == publication.observed_at
                ):
                    raise RuntimeError("invented retained-file tail failure")
                return receipt

            with monkeypatch.context() as scoped:
                scoped.setattr(
                    LocalArtifactVersionRegistry, "_commit_prepared_locked", fail_after_file_change
                )
                with pytest.raises(RuntimeError, match="retained-file tail"):
                    ProcessExecutionActionBundle(generator, request).execute()
            assert engine.state_manager.macos_process_census_snapshot() == census
            assert engine.state_manager.get_processes_for_session(logon) == processes
            assert generator._lifecycle_authority.census() == lifecycle
            assert generator.execution_effect_audit_snapshot() == audit
            assert (
                content.resolve_record(
                    system.hostname, user.username, descriptor.native_path, "macos"
                )
                == initial_file
            )
            assert content.registry.census().prepared_publications == 0
            return
        else:
            commit = ExactPublicationBatch.commit
            attempted = False

            def fail_once(batch: ExactPublicationBatch) -> None:
                nonlocal attempted
                if not attempted:
                    attempted = True
                    if fault == "after":
                        commit(batch)
                    raise RuntimeError("invented retained-file journal failure")
                commit(batch)

            with monkeypatch.context() as scoped:
                scoped.setattr(ExactPublicationBatch, "commit", fail_once)
                if fault == "after":
                    ProcessExecutionActionBundle(generator, request).execute()
                else:
                    with pytest.raises(RuntimeError, match="retained-file journal") as caught:
                        ProcessExecutionActionBundle(generator, request).execute()
                    census = engine.state_manager.macos_process_census_snapshot()
                    engine.dispatcher.resume_action_cohort_projection(
                        caught.value.action_cohort_receipt
                    )
                    assert engine.state_manager.macos_process_census_snapshot() == census
                    # The processed exception no longer needs its traceback's
                    # live owner capabilities at the checkpoint barrier.
                    caught.value.__traceback__ = None
                    del caught
                assert attempted
            pid = next(
                process.pid
                for process in engine.state_manager.get_processes_for_session(logon)
                if process.command_line == request.command_line
            )
        identity = engine.state_manager.get_process_identity(system.hostname, pid)
        assert identity.execution_ordinal == 1
        current = content.resolve_record(
            system.hostname, user.username, descriptor.native_path, "macos"
        )
        assert current == (None if action is FileEffectAction.DELETE else record)
        restored_state = StateManager()
        _restore_head(restored_state, _capture_head(engine.state_manager))
        assert restored_state.get_process_identity(system.hostname, pid) == identity
        restored_content = _manager()
        checkpoint = LocalArtifactVersionRegistryParticipant(content.registry).prepare_checkpoint(1)
        LocalArtifactVersionRegistryParticipant(restored_content.registry).restore_checkpoint(
            checkpoint.head.payload, ()
        )
        assert (
            restored_content.resolve_record(
                system.hostname, user.username, descriptor.native_path, "macos"
            )
            == current
        )
        engine._finalize_macos_process_coverage()
        summary = engine.dispatcher.macos_es_ingress.coverage.hosts[0].process_census
        assert summary.expected_forks == summary.expected_execs == 1
        assert summary.aggregate_births == 0 and summary.complete is native
    finally:
        engine._close_emitters()
    rows = [
        decode_endpoint_security_record(line)
        for path in tmp_path.rglob("macos_endpoint_security.ndjson")
        for line in path.read_text().splitlines()
    ]
    assert sorted(row.event_type for row in rows) == ([9, 11] if native else [])
