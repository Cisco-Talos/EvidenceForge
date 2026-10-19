# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Shebang-script observations use file placement at the exact exec boundary."""

from datetime import timedelta

import pytest

from evidenceforge.events.contexts import HostContext
from evidenceforge.events.dispatcher import EventDispatcher
from evidenceforge.formats.macos_endpoint_security import decode_endpoint_security_record
from evidenceforge.generation.actions.command_effects import ExecutionEffectAuditCounter
from evidenceforge.generation.actions.posix_process import process_exec_occurrence
from evidenceforge.generation.lifecycle_authority import GeneratorLifecycleAuthority
from evidenceforge.generation.lifecycle_registry import LifecycleRegistry
from evidenceforge.generation.lifecycle_shadow import LifecycleShadow
from evidenceforge.generation.runtime_content import RuntimeContentIdentityManager
from evidenceforge.models.exceptions import EventContractError, StateError
from tests.unit.test_macos_es_exec_preparation import _fixture, _prepare
from tests.unit.test_macos_file_rename import _rename
from tests.unit.test_process_exit_projection import _prepare as prepare_dispatch


@pytest.mark.parametrize("providers", ["rr", "ri", "ir", "ii"])
def test_exec_script_rename_changes_file_view_without_replacing_script_or_interpreter(
    providers: str,
) -> None:
    fixture = _fixture(script=True, providers=providers)
    process = fixture.after.process
    reference = process.exec_script
    source = fixture.artifacts.resolve_version(reference.artifact_version_id)
    manager = RuntimeContentIdentityManager(fixture.artifacts)
    with _rename(
        manager,
        source,
        native_path="/usr/local/lib/renamed-script",
        observed_at=process.execution_started_at - timedelta(seconds=1),
    ) as rename:
        rename.commit()
    before = fixture.owner.state.materialization_digest()
    with _prepare(fixture) as prepared:
        native = decode_endpoint_security_record(prepared.ndjson)
    assert native.event.exec.script.path == "/usr/local/lib/renamed-script"
    assert native.event.exec.target.executable.path == process.image
    assert process.exec_script == reference
    assert source.artifact.native_path == reference.native_path
    assert fixture.owner.state.materialization_digest() == before
    fixture.owner.collectors.cancel(fixture.delivery)


@pytest.mark.parametrize("future", [False, True])
def test_script_removal_is_checked_at_execution_not_preparation_clock(future: bool) -> None:
    fixture = _fixture(script=True)
    process = fixture.after.process
    source = fixture.artifacts.resolve_version(process.exec_script.artifact_version_id)
    at = process.execution_started_at + (timedelta(seconds=1) if future else timedelta(0))
    fixture.artifacts.withdraw_execution_path(source, at)
    if future:
        with _prepare(fixture) as prepared:
            assert (
                decode_endpoint_security_record(prepared.ndjson).event.exec.script.path
                == source.artifact.native_path
            )
    else:
        with pytest.raises(StateError, match="script.*placement"):
            with _prepare(fixture):
                pytest.fail("removed script cannot produce an exec file view")
    assert fixture.owner.collectors.completed_observation(fixture.delivery) is None
    fixture.owner.collectors.cancel(fixture.delivery)


def test_script_change_after_native_binding_rejects_canonical_publication() -> None:
    fixture = _fixture(script=True, born_loaded=True)
    state = fixture.owner.state
    lifecycle = LifecycleRegistry(shard_count=4)
    shadow = LifecycleShadow(state, lifecycle)
    authority = GeneratorLifecycleAuthority(state, shadow, shard_count=4)
    authority.bootstrap_active_state()
    dispatcher = EventDispatcher(
        state, {}, lifecycle_shadow=shadow, enforce_lifecycle_authority=True
    )
    dispatcher.bind_lifecycle_authority(authority)
    dispatcher.bind_execution_effect_audit(ExecutionEffectAuditCounter())
    dispatcher.es_collectors = fixture.owner.collectors
    dispatcher.local_artifact_registry = fixture.artifacts
    target = fixture.after.process
    event = process_exec_occurrence(
        host=HostContext(
            hostname=target.hostname,
            ip="192.0.2.41",
            os="macOS 26",
            os_category="macos",
            system_type="workstation",
        ),
        before=fixture.before.process,
        after=target,
        integrity_level="Medium",
    )
    with _prepare(fixture):
        pass
    batch = prepare_dispatch(
        dispatcher,
        fixture.cohort,
        event,
        exact=True,
        root=fixture.delivery.observation.occurrence_id,
    )
    dispatcher.bind_es_delivery_to_action_cohort(
        batch, delivery=fixture.delivery, collector_process=fixture.collector
    )
    source = fixture.artifacts.resolve_version(target.exec_script.artifact_version_id)
    fixture.artifacts.withdraw_execution_path(source, target.execution_started_at)
    before = state.materialization_digest()
    with pytest.raises(EventContractError, match="script.*placement"):
        dispatcher.publish_prepared_action_cohort_batch(batch)
    assert state.materialization_digest() == before
    assert fixture.owner.collectors.completed_observation(fixture.delivery) is None
    dispatcher.cancel_prepared_action_cohort_batch(batch)
    assert not fixture.artifacts._placement_observation_claims
