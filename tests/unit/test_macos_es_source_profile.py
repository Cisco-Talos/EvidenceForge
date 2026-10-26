# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Independently authored fork policy and canonical collector initialization."""

from dataclasses import replace
from datetime import timedelta
from pathlib import Path

import pytest
from pydantic import ValidationError

from evidenceforge.composition.compiler import build_management_effective_config
from evidenceforge.config.provider import effective_config_scope
from evidenceforge.config.schemas import MacosEndpointSecurityProfile
from evidenceforge.events.dispatcher import EventDispatcher
from evidenceforge.events.es_collector import ESCollectorRegistry
from evidenceforge.events.identity import PosixProcessCredentials
from evidenceforge.events.macos_process_observation import MacosProcessCollectionObservation
from evidenceforge.events.observation import ObservationDecision
from evidenceforge.formats.macos_endpoint_security import decode_endpoint_security_record
from evidenceforge.generation.actions.es_collection import ESCollectionActionOwner, _process
from evidenceforge.generation.activity.macos_endpoint_security_profiles import (
    load_macos_endpoint_security_profile,
)
from evidenceforge.generation.checkpoints.dispatcher_observation_head import (
    DispatcherObservationParticipant,
)
from evidenceforge.generation.checkpoints.packed import dumps, loads
from evidenceforge.generation.checkpoints.state_manager_head import _capture_head, _restore_head
from evidenceforge.generation.macos_es_source import (
    initialize_macos_es_source,
    select_macos_es_profile,
)
from evidenceforge.generation.state_manager import StateManager
from evidenceforge.models.exceptions import StateError
from evidenceforge.models.scenario import System
from tests.unit.test_macos_es_fork_preparation import _fixture


def _system(hostname: str = "invented-mac", **changes: object) -> System:
    return System.model_validate(
        {
            "hostname": hostname,
            "ip": "192.0.2.41",
            "os": "macOS 27",
            "type": "workstation",
            "architecture": "arm64",
            "os_build": "invented-build",
            **changes,
        }
    )


def _setup() -> tuple:
    fixture = _fixture(born_loaded=True)
    fixture.owner.collectors.cancel(fixture.delivery)
    state = fixture.owner.state
    parent = fixture.parent.process
    start = parent.execution_started_at
    state.register_boot_time(parent.hostname, parent.started_at - timedelta(hours=1))
    collector_plan = state.plan_process_materialization(
        system=parent.hostname,
        parent_pid=0,
        image="/usr/bin/eslogger",
        command_line="/usr/bin/eslogger fork exec exit",
        arguments=("/usr/bin/eslogger", "fork", "exec", "exit"),
        username="root",
        integrity_level="System",
        os_category="macos",
        start_time=start,
        credentials=PosixProcessCredentials(0, 0, 0, 0),
    )
    state.materialize_process(collector_plan)
    collector = collector_plan.identity
    owner = ESCollectionActionOwner(state, ESCollectorRegistry())
    system = _system(parent.hostname)
    end = start + timedelta(hours=1)
    source = initialize_macos_es_source(owner, system, collector, known_from=start, known_until=end)
    builder = state.begin_action_cohort_materialization()
    child = builder.fork_process(parent, forked_at=start + timedelta(seconds=1)).identity
    cohort = builder.seal()
    return source, system, collector, parent, child, cohort, fixture.executables


@pytest.mark.parametrize(
    ("changes", "selected"),
    [
        ({}, True),
        ({"os": "macOS 27.1.2"}, True),
        ({"os": "MACOS 27.4"}, True),
        ({"os": "macOS 15"}, False),
        ({"os": "macOS 26"}, False),
        ({"os": "macOS 27 beta"}, False),
        ({"os": "Linux 26"}, False),
        ({"architecture": "x64"}, False),
        ({"architecture": None}, False),
        ({"type": "server"}, False),
    ],
)
def test_source_profile_selects_only_explicit_bounded_host(changes: dict, selected: bool) -> None:
    assert (select_macos_es_profile(_system(**changes)) is not None) == selected


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("message_version", 9),
        ("event_types", [11]),
        ("collector_arguments", ["/usr/bin/eslogger", "exec"]),
        ("action_type", True),
        ("message_version", "10"),
        ("architecture", "x64"),
    ],
)
def test_profile_rejects_decoder_only_admissions_and_coerced_values(
    field: str, value: object
) -> None:
    policy = load_macos_endpoint_security_profile().model_dump(mode="json")
    policy[field] = value
    with pytest.raises(ValidationError):
        MacosEndpointSecurityProfile.model_validate(policy)


def test_initialization_produces_exact_inventory_subscription_clock_and_profile() -> None:
    source, system, collector, parent, child, cohort, _ = _setup()
    connection = source.connection()
    assert connection.process == _process(collector)
    assert connection.next_delivery == connection.next_global_sequence == 0
    assert tuple((item.event_type, item.next_sequence) for item in connection.event_counters) == (
        (9, 0),
        (11, 0),
        (15, 0),
    )
    assert connection.source_profile.os_build == "invented-build"
    assert source.clock.hostname == system.hostname
    assert source.clock.boot_time == source.owner.state.get_boot_time(system.hostname)
    assert (
        source.owner.collectors.known_client_membership(
            system.hostname, _process(collector), child.started_at
        )
        is True
    )
    assert (
        source.owner.collectors.known_client_membership(
            system.hostname, _process(parent), child.started_at
        )
        is False
    )
    assert (
        initialize_macos_es_source(
            source.owner,
            system,
            collector,
            known_from=source.coverage.known_from,
            known_until=source.coverage.known_until,
        )
        == source
    )
    before = source.owner.collectors.snapshot_with_membership()
    token = source.prepare_fork(cohort, child, decision=ObservationDecision("filtered"))
    assert token.observation.event_type == 11
    assert token.observation.seq_num == token.observation.global_seq_num == 0
    source.owner.collectors.cancel(token)
    assert source.owner.collectors.snapshot_with_membership() == before


@pytest.mark.parametrize("status", ["visible", "filtered", "delayed"])
def test_profile_drives_complete_v11_fork_preparation(status: str) -> None:
    source, _, _, parent, child, cohort, executables = _setup()
    delivery = source.prepare_fork(cohort, child, decision=ObservationDecision(status))
    with source.prepared_fork_record(
        executables,
        cohort=cohort,
        delivery=delivery,
        parent=MacosProcessCollectionObservation(parent, child.started_at, False, "absent"),
        child=MacosProcessCollectionObservation(child, child.started_at, False, "absent"),
        thread=parent.primary_thread,
    ) as prepared:
        record = decode_endpoint_security_record(prepared.ndjson)
        assert record.version == 11
        assert record.event_type == 11
        assert record.mach_time == source.clock.ticks_at(child.started_at)
        assert isinstance(record.model_dump(mode="json")["process"]["audit_token"], dict)
    # Frozen preparation is not canonical commit authority.
    assert source.owner.state.get_process(child.hostname, child.pid) is None
    source.owner.collectors.cancel(delivery)


@pytest.mark.parametrize("damage", ["argv", "credentials", "execution", "host"])
def test_bad_collector_initialization_changes_no_registry_state(damage: str) -> None:
    source, system, collector, _, _, _, _ = _setup()
    owner = ESCollectionActionOwner(source.owner.state, ESCollectorRegistry())
    if damage == "argv":
        collector = replace(
            collector,
            arguments=("/usr/bin/eslogger", "exec"),
            command_line="/usr/bin/eslogger exec",
        )
    elif damage == "credentials":
        collector = replace(collector, credentials=PosixProcessCredentials(501, 501, 20, 20))
    elif damage == "execution":
        collector = replace(
            collector,
            execution_ordinal=collector.execution_ordinal + 1,
            executed_at=collector.started_at + timedelta(milliseconds=1),
            lifetime_image=collector.image,
        )
    else:
        system = _system("another-mac")
    with pytest.raises(StateError):
        initialize_macos_es_source(
            owner,
            system,
            collector,
            known_from=source.coverage.known_from,
            known_until=source.coverage.known_until,
        )
    assert owner.collectors.snapshot_with_membership() == ((), ())


def test_ordinary_process_create_cannot_generate_native_fork() -> None:
    source, _, _, parent, _, _, _ = _setup()
    state = source.owner.state
    builder = state.begin_action_cohort_materialization()
    child = builder.plan_process(
        system=parent.hostname,
        parent_pid=parent.pid,
        image=parent.image,
        command_line=parent.command_line,
        username=parent.principal,
        integrity_level="Medium",
        os_category="macos",
        start_time=parent.started_at + timedelta(seconds=2),
    ).identity
    cohort = builder.seal()
    before = source.owner.collectors.snapshot_with_membership()
    with pytest.raises(StateError, match="canonical fork"):
        source.prepare_fork(cohort, child, decision=ObservationDecision("visible"))
    assert source.owner.collectors.snapshot_with_membership() == before


def test_restore_rebinds_profile_and_counter_history_without_reinitializing() -> None:
    source, system, collector, _, child, cohort, _ = _setup()
    token = source.prepare_fork(cohort, child, decision=ObservationDecision("filtered"))
    source.owner.commit(token, collector)
    dispatcher = EventDispatcher(source.owner.state, {})
    dispatcher.es_collectors = source.owner.collectors
    seal = DispatcherObservationParticipant(dispatcher).prepare_checkpoint(1)
    state = StateManager()
    _restore_head(state, _capture_head(source.owner.state))
    restored_dispatcher = EventDispatcher(state, {})
    DispatcherObservationParticipant(restored_dispatcher).restore_checkpoint(seal.head.payload, ())
    owner = ESCollectionActionOwner(state, restored_dispatcher.es_collectors)
    restored = initialize_macos_es_source(
        owner,
        system,
        collector,
        known_from=source.coverage.known_from,
        known_until=source.coverage.known_until,
        restoring=True,
    )
    assert restored.connection() == source.connection()
    assert restored.connection().next_delivery == 1
    with pytest.raises(StateError, match="history"):
        initialize_macos_es_source(
            owner,
            system,
            collector,
            known_from=source.coverage.known_from,
            known_until=source.coverage.known_until,
        )


@pytest.mark.parametrize("change", ["build", "clock", "window", "profile"])
def test_restore_rejects_changed_source_truth_without_resetting_counters(
    change: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    source, system, collector, _, _, _, _ = _setup()
    known_until = source.coverage.known_until
    if change == "build":
        system = system.model_copy(update={"os_build": "another-invented-build"})
    elif change == "clock":
        import evidenceforge.generation.macos_es_source as module

        policy = module.load_macos_unified_log_profiles()
        policy = policy.model_copy(
            update={
                "mach_timebase": policy.mach_timebase.model_copy(
                    update={"numerator": policy.mach_timebase.numerator + 1}
                )
            }
        )
        monkeypatch.setattr(module, "load_macos_unified_log_profiles", lambda: policy)
    elif change == "window":
        known_until += timedelta(seconds=1)
    else:
        current = source.connection()
        snapshot, membership = source.owner.collectors.snapshot_with_membership()
        source.owner.collectors = ESCollectorRegistry()
        source.owner.collectors.restore(
            tuple(
                item.model_copy(update={"source_profile": None}) if item == current else item
                for item in snapshot
            ),
            membership,
        )
    before = source.owner.collectors.snapshot_with_membership()
    with pytest.raises(StateError):
        initialize_macos_es_source(
            source.owner,
            system,
            collector,
            known_from=source.coverage.known_from,
            known_until=known_until,
            restoring=True,
        )
    assert source.owner.collectors.snapshot_with_membership() == before


def test_outside_finite_source_inventory_does_not_consume_a_delivery() -> None:
    source, _, _, parent, _, _, _ = _setup()
    builder = source.owner.state.begin_action_cohort_materialization()
    child = builder.fork_process(parent, forked_at=source.coverage.known_until).identity
    cohort = builder.seal()
    before = source.owner.collectors.snapshot_with_membership()
    assert source.prepare_fork(cohort, child, decision=ObservationDecision("visible")) is None
    assert source.owner.collectors.snapshot_with_membership() == before


def test_direct_counter_preparation_cannot_bypass_native_profile_window() -> None:
    source, _, collector, parent, _, _, executables = _setup()
    builder = source.owner.state.begin_action_cohort_materialization()
    child = builder.fork_process(parent, forked_at=source.coverage.known_until).identity
    cohort = builder.seal()
    connection = source.connection()
    delivery = source.owner.prepare(
        source_instance=source.source_instance,
        process=collector,
        generation=1,
        delivery=0,
        occurrence_id=f"process-fork:{child.object_id}",
        event_type=11,
        observed_at=child.started_at,
        decision=ObservationDecision("visible"),
    )
    with pytest.raises(StateError, match="selected collector"):
        with source.prepared_fork_record(
            executables,
            cohort=cohort,
            delivery=delivery,
            parent=MacosProcessCollectionObservation(parent, child.started_at, False, "absent"),
            child=MacosProcessCollectionObservation(child, child.started_at, False, "absent"),
            thread=parent.primary_thread,
        ):
            pytest.fail("A lower-level counter cannot expand the admitted source window")
    assert source.connection() == connection
    source.owner.collectors.cancel(delivery)


def test_changed_canonical_boot_invalidates_live_source_binding() -> None:
    source, _, _, _, child, _, _ = _setup()
    source.owner.state.register_boot_time(
        child.hostname, source.clock.boot_time - timedelta(seconds=1)
    )
    before = source.owner.collectors.snapshot_with_membership()
    with pytest.raises(StateError, match="frozen source profile"):
        source.connection()
    assert source.owner.collectors.snapshot_with_membership() == before


@pytest.mark.parametrize("change", ["wire_version", "timebase"])
def test_copied_binding_cannot_replace_its_authenticated_source_policy(change: str) -> None:
    from evidenceforge.generation.timing.macos import MachTimebase

    source, _, _, _, _, _, _ = _setup()
    before = source.owner.collectors.snapshot_with_membership()
    if change == "wire_version":
        forged = replace(source, profile=source.profile.model_copy(update={"message_version": 6}))
    else:
        forged = replace(source, clock=replace(source.clock, timebase=MachTimebase(1, 1)))
    with pytest.raises(StateError, match="frozen source profile"):
        forged.connection()
    assert source.owner.collectors.snapshot_with_membership() == before


def test_profile_preserves_unknown_required_metadata() -> None:
    source, _, _, parent, _, _, executables = _setup()
    state = source.owner.state
    builder = state.begin_action_cohort_materialization()
    after = builder.execute_process(
        parent,
        image=parent.image,
        command_line=parent.command_line,
        executed_at=parent.started_at + timedelta(seconds=2),
        executable_version=parent.executable_version,
    )
    state.materialize_action_cohort(builder.seal())
    assert after.image_security is None
    builder = state.begin_action_cohort_materialization()
    child = builder.fork_process(after, forked_at=parent.started_at + timedelta(seconds=3)).identity
    cohort = builder.seal()
    delivery = source.prepare_fork(cohort, child, decision=ObservationDecision("visible"))
    before = source.connection()
    with pytest.raises(StateError):
        with source.prepared_fork_record(
            executables,
            cohort=cohort,
            delivery=delivery,
            parent=MacosProcessCollectionObservation(after, child.started_at, False, "absent"),
            child=MacosProcessCollectionObservation(child, child.started_at, False, "absent"),
            thread=after.primary_thread,
        ):
            pytest.fail("Incomplete required metadata cannot produce native bytes")
    assert source.connection() == before
    source.owner.collectors.cancel(delivery)


def test_engine_initialization_uses_frozen_run_policy_and_rebinds_existing_epoch(
    tmp_path: Path,
) -> None:
    import json

    from evidenceforge.generation.engine import GenerationEngine
    from evidenceforge.models.scenario import Scenario
    from tests.unit.test_macos_installed_provisioning import _scenario

    source, _, collector, _, child, cohort, _ = _setup()
    data = json.dumps(_scenario().model_dump(mode="json")).replace("MAC-01", collector.hostname)
    scenario = Scenario.model_validate_json(data)
    engine = GenerationEngine(scenario, tmp_path)
    with pytest.raises(StateError, match="Initialize engine"):
        engine.initialize_macos_es_source(collector)
    # Supply actual production owners without activating a host service or
    # registering the still-unavailable CLI source.
    engine.state_manager = source.owner.state
    engine.dispatcher = EventDispatcher(engine.state_manager, {})
    engine.start_time = source.coverage.known_from
    engine.end_time = source.coverage.known_until
    engine.warmup_start_time = source.coverage.known_from - timedelta(seconds=1)
    bound = engine.initialize_macos_es_source(collector)
    assert bound.coverage == source.coverage
    token = bound.prepare_fork(cohort, child, decision=ObservationDecision("filtered"))
    bound.owner.commit(token, collector)
    again = engine.initialize_macos_es_source(collector)
    assert again.connection().next_delivery == 1
    assert again.connection() == bound.connection()
    engine.dispatcher.es_collectors.close(bound.connection(), child.started_at)
    assert engine.initialize_macos_es_source(collector).connection().closed_at == child.started_at


@pytest.mark.parametrize("filtered", [False, True])
def test_selected_profile_publishes_canonical_fork_and_restores_native_output(
    tmp_path: Path, filtered: bool
) -> None:
    from evidenceforge.events.contexts import HostContext
    from evidenceforge.generation.actions.command_effects import ExecutionEffectAuditCounter
    from evidenceforge.generation.actions.posix_process import process_fork_occurrence
    from evidenceforge.generation.checkpoints.emitter_spools import EmitterSpoolParticipant
    from evidenceforge.generation.lifecycle_authority import GeneratorLifecycleAuthority
    from evidenceforge.generation.lifecycle_registry import LifecycleRegistry
    from evidenceforge.generation.lifecycle_shadow import LifecycleShadow
    from tests.unit.test_macos_native_output_lifecycle import _output
    from tests.unit.test_macos_native_sink_publication import _prepare

    source, system, collector, parent, child, cohort, executables = _setup()
    state = source.owner.state
    registry = LifecycleRegistry(shard_count=4)
    shadow = LifecycleShadow(state, registry)
    authority = GeneratorLifecycleAuthority(state, shadow, shard_count=4)
    authority.bootstrap_active_state()
    dispatcher = EventDispatcher(
        state, {}, lifecycle_shadow=shadow, enforce_lifecycle_authority=True
    )
    dispatcher.bind_lifecycle_authority(authority)
    dispatcher.bind_execution_effect_audit(ExecutionEffectAuditCounter())
    dispatcher.local_artifact_registry = executables
    dispatcher.es_collectors = source.owner.collectors
    host = HostContext(
        hostname=system.hostname,
        ip=system.ip,
        os=system.os,
        os_category="macos",
        system_type=system.type,
    )
    output = _output(tmp_path / "original", checkpoint=True)
    sink = output.native_sink(host)
    delivery = source.prepare_fork(
        cohort, child, decision=ObservationDecision("filtered" if filtered else "visible")
    )
    with source.prepared_fork_record(
        executables,
        cohort=cohort,
        delivery=delivery,
        parent=MacosProcessCollectionObservation(parent, child.started_at, False, "absent"),
        child=MacosProcessCollectionObservation(child, child.started_at, False, "absent"),
        thread=parent.primary_thread,
    ) as native:
        frozen = native.ndjson
    batch = _prepare(
        dispatcher,
        cohort,
        (process_fork_occurrence(host=host, parent=parent, child=child, integrity_level="Medium"),),
        root=delivery.observation.occurrence_id,
        es_delivery=delivery,
        es_collector_process=collector,
        es_native_sink=sink,
    )
    result = dispatcher.publish_prepared_action_cohort_batch(batch)
    assert dispatcher.authenticates_action_cohort_publication_receipt(result.receipt)
    assert state.get_process_identity(child.hostname, child.pid) == child
    assert source.connection().next_delivery == 1
    assert output.event_count == (0 if filtered else 1)
    output.barrier_flush()
    spool = EmitterSpoolParticipant(
        emitters={"macos_endpoint_security": output}, output_root=tmp_path / "original"
    )
    saved = spool.prepare_checkpoint(1)
    spool.checkpoint_committed(1)
    counter_head = DispatcherObservationParticipant(dispatcher).prepare_checkpoint(1)
    recovered_state = StateManager()
    _restore_head(recovered_state, _capture_head(state))
    recovered_dispatcher = EventDispatcher(recovered_state, {})
    DispatcherObservationParticipant(recovered_dispatcher).restore_checkpoint(
        counter_head.head.payload, ()
    )
    recovered = initialize_macos_es_source(
        ESCollectionActionOwner(recovered_state, recovered_dispatcher.es_collectors),
        system,
        collector,
        known_from=source.coverage.known_from,
        known_until=source.coverage.known_until,
        restoring=True,
    )
    assert recovered.connection() == source.connection()
    recovered_output = _output(tmp_path / "recovered", checkpoint=True)
    EmitterSpoolParticipant(
        emitters={"macos_endpoint_security": recovered_output}, output_root=tmp_path / "recovered"
    ).restore_checkpoint(saved.head.payload, tuple(item.payload for item in saved.segments))
    output.close()
    recovered_output.close()
    files = tuple((tmp_path / "recovered").rglob("*.ndjson"))
    assert (files[0].read_text() if files else "") == ("" if filtered else frozen)


@pytest.mark.parametrize("change", ["wire_version", "mach_time"])
def test_canonical_publication_rechecks_the_retained_native_source_profile(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, change: str
) -> None:
    from evidenceforge.models.exceptions import EventContractError

    if change == "wire_version":
        import evidenceforge.generation.macos_es_source as module

        original = module.prepared_es_fork_record

        def historical(*args: object, **kwargs: object) -> object:
            return original(*args, **(kwargs | {"version": 6}))

        monkeypatch.setattr(module, "prepared_es_fork_record", historical)
    else:
        import json

        from evidenceforge.events.es_collector import PreparedESDeliveryCommit

        original_freeze = PreparedESDeliveryCommit.freeze_native_projection

        def changed_clock(
            handle: PreparedESDeliveryCommit, ndjson: str, *, canonical_token: str
        ) -> str:
            row = json.loads(ndjson)
            row["mach_time"] += 1
            return original_freeze(handle, json.dumps(row) + "\n", canonical_token=canonical_token)

        monkeypatch.setattr(PreparedESDeliveryCommit, "freeze_native_projection", changed_clock)
    with pytest.raises(EventContractError, match="Native source profile"):
        test_selected_profile_publishes_canonical_fork_and_restores_native_output(tmp_path, False)


@pytest.mark.parametrize("old_schema", ["1", "2", "3", "4"])
def test_old_checkpoint_cannot_claim_new_source_profile(old_schema: str) -> None:
    source, _, _, _, _, _, _ = _setup()
    dispatcher = EventDispatcher(source.owner.state, {})
    dispatcher.es_collectors = source.owner.collectors
    seal = DispatcherObservationParticipant(dispatcher).prepare_checkpoint(1)
    head = loads(seal.head.payload)
    head["schema_version"] = old_schema
    restored = EventDispatcher(source.owner.state, {})
    from evidenceforge.generation.checkpoints.errors import CheckpointCorruptionError

    with pytest.raises(CheckpointCorruptionError):
        DispatcherObservationParticipant(restored).restore_checkpoint(dumps(head), ())
    assert restored.es_collectors.snapshot_with_membership() == ((), ())


@pytest.mark.parametrize("old_schema", ["2", "3", "4"])
def test_legacy_checkpoint_keeps_unknown_native_profile(old_schema: str) -> None:
    source, system, collector, _, _, _, _ = _setup()
    dispatcher = EventDispatcher(source.owner.state, {})
    dispatcher.es_collectors = source.owner.collectors
    head = loads(DispatcherObservationParticipant(dispatcher).prepare_checkpoint(1).head.payload)
    head["schema_version"] = old_schema
    import json

    states: list[str] = []
    for encoded in head["es_collectors"]:
        item = json.loads(encoded)
        item.pop("source_profile")
        if old_schema == "2":
            item.pop("process")
            item.pop("closed_at")
        states.append(json.dumps(item))
    head["es_collectors"] = states
    if old_schema != "4":
        head["es_membership"] = []
    restored = EventDispatcher(source.owner.state, {})
    DispatcherObservationParticipant(restored).restore_checkpoint(dumps(head), ())
    assert restored.es_collectors.connection(source.source_instance).source_profile is None
    owner = ESCollectionActionOwner(source.owner.state, restored.es_collectors)
    with pytest.raises(StateError, match="frozen source profile"):
        initialize_macos_es_source(
            owner,
            system,
            collector,
            known_from=source.coverage.known_from,
            known_until=source.coverage.known_until,
            restoring=True,
        )


def test_invalid_profile_overlay_has_actionable_validation_error(tmp_path: Path) -> None:
    from evidenceforge.config.overlay import overlay_project_root_scope
    from evidenceforge.validation.configuration import validate_config

    path = tmp_path / ".eforge/config/activity/macos_endpoint_security_profiles.yaml"
    path.parent.mkdir(parents=True)
    path.write_text("event_type: 9\n")
    effective = build_management_effective_config(tmp_path)
    with overlay_project_root_scope(tmp_path), effective_config_scope(effective):
        result = validate_config()
    assert any("macos_endpoint_security_profiles.yaml" in issue.file for issue in result.errors)


@pytest.mark.parametrize(
    "missing", ["macos_endpoint_security_profiles.yaml", "macos_unified_log_profiles.yaml"]
)
def test_frozen_profile_and_old_inputs_do_not_read_new_ambient_policy(
    tmp_path: Path, missing: str
) -> None:
    effective = build_management_effective_config(tmp_path)
    with effective_config_scope(effective):
        assert load_macos_endpoint_security_profile().message_version == 11
    older = effective.model_copy(
        update={
            "packaged_defaults": {
                key: value
                for key, value in effective.packaged_defaults.items()
                if key != f"activity/{missing}"
            },
        }
    )
    with effective_config_scope(older):
        assert load_macos_endpoint_security_profile() is None
        assert select_macos_es_profile(_system()) is None


@pytest.mark.slow
def test_selected_fork_profile_and_checkpoint_bytes_are_stable_in_fresh_processes(
    tmp_path: Path,
) -> None:
    import json
    import os
    import subprocess
    import sys
    import textwrap

    script = textwrap.dedent("""\
        import hashlib
        import json
        import sys
        from pathlib import Path
        from tests.unit.test_macos_es_source_profile import (
            _setup,
            test_selected_profile_publishes_canonical_fork_and_restores_native_output,
        )
        root = Path(sys.argv[1])
        test_selected_profile_publishes_canonical_fork_and_restores_native_output(root, False)
        path = next((root / "recovered").rglob("*.ndjson"))
        source, *_ = _setup()
        print(json.dumps({
            "profile": source.source_profile.model_dump(mode="json"),
            "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
        }))
    """)
    results: list[dict[str, object]] = []
    for seed in ("29", "953"):
        result = subprocess.run(
            [sys.executable, "-c", script, str(tmp_path / seed)],
            env={**os.environ, "PYTHONHASHSEED": seed},
            check=True,
            capture_output=True,
            text=True,
            timeout=60,
        )
        results.append(json.loads(result.stdout))
    assert results[0] == results[1]
