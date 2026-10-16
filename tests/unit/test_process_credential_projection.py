# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Mac credential observations preserve execution identity and exact mutation ownership."""

import json
from dataclasses import replace
from datetime import timedelta
from pathlib import Path
from typing import Literal
from unittest.mock import MagicMock

import pytest

from evidenceforge.events.base import OccurrenceBuilder
from evidenceforge.events.contexts import FileContext, HostContext
from evidenceforge.events.contracts import shadow_seal
from evidenceforge.events.dispatcher import EventDispatcher, PreparedActionCohortBatch
from evidenceforge.events.identity import EntityIdentity, EventIdentityPlan, ProcessIdentity
from evidenceforge.events.process import process_credential_identities
from evidenceforge.formats.loader import load_format
from evidenceforge.generation.actions.base import ActionAnchor
from evidenceforge.generation.actions.command_effects import (
    ExecutionEffectAuditCohortEntry,
    ExecutionEffectAuditCounter,
    ExecutionEffectPlan,
)
from evidenceforge.generation.actions.posix_process import process_credential_occurrence
from evidenceforge.generation.emitters.ecar import EcarEmitter
from evidenceforge.generation.lifecycle_authority import GeneratorLifecycleAuthority
from evidenceforge.generation.lifecycle_registry import LifecycleRegistry
from evidenceforge.generation.lifecycle_shadow import LifecycleShadow
from evidenceforge.generation.state_manager import ActionCohortMaterializationPlan, StateManager
from evidenceforge.models.exceptions import EventContractError, StateError
from tests.unit.test_macos_audit_sessions import _START
from tests.unit.test_macos_privilege_drop import _child
from tests.unit.test_macos_process_audit_binding import _receiver

Kind = Literal["process_audit_bind", "process_privilege_drop", "process_service_drop"]
KINDS: tuple[Kind, ...] = ("process_audit_bind", "process_privilege_drop", "process_service_drop")


def _environment(kind: Kind) -> tuple[StateManager, EventDispatcher, MagicMock, ProcessIdentity]:
    if kind == "process_service_drop":
        from tests.unit.test_macos_service_drop import _child as service_child

        state, before = service_child(execute=False)
    else:
        state, before = _receiver() if kind == "process_audit_bind" else _child()
    registry = LifecycleRegistry(shard_count=4)
    shadow = LifecycleShadow(state, registry)
    authority = GeneratorLifecycleAuthority(state, shadow, shard_count=4)
    authority.bootstrap_active_state()
    emitter = MagicMock()
    emitter.can_handle.return_value = True
    dispatcher = EventDispatcher(
        state, {"ecar": emitter}, lifecycle_shadow=shadow, enforce_lifecycle_authority=True
    )
    dispatcher.bind_lifecycle_authority(authority)
    dispatcher.bind_execution_effect_audit(ExecutionEffectAuditCounter())
    return state, dispatcher, emitter, before


def _plan(
    state: StateManager,
    before: ProcessIdentity,
    kind: Kind,
) -> tuple[ActionCohortMaterializationPlan, OccurrenceBuilder, ProcessIdentity]:
    builder = state.begin_action_cohort_materialization()
    if kind == "process_audit_bind":
        timestamp = _START + timedelta(seconds=1)
        after = builder.bind_macos_process_audit_origin(before, bound_at=timestamp)
        integrity = "System"
    elif kind == "process_service_drop":
        from tests.unit.test_macos_service_drop import _account

        timestamp = _START + timedelta(seconds=3)
        after = builder.drop_macos_service_child_privileges(
            before,
            service_account=_account(),
            dropped_at=timestamp,
        )
        integrity = "Medium"
    else:
        timestamp = _START + timedelta(seconds=3)
        after = builder.drop_macos_ssh_child_privileges(before, dropped_at=timestamp)
        integrity = "Medium"
    event = process_credential_occurrence(
        host=HostContext(
            hostname="MAC-A",
            ip="192.0.2.20",
            os="macOS 26",
            os_category="macos",
            system_type="workstation",
        ),
        before=before,
        after=after,
        timestamp=timestamp,
        kind=kind,
        integrity_level=integrity,
    )
    return builder.seal(), event, after


def _prepare(
    dispatcher: EventDispatcher,
    plan: ActionCohortMaterializationPlan,
    event: OccurrenceBuilder,
    *,
    exact: bool = False,
    duplicate: bool = False,
) -> PreparedActionCohortBatch:
    with dispatcher.source_timing_planner.prepared_planning() as timing:
        carrier = dispatcher.prepare_action_cohort_projection(
            event, source_timing_preparation=timing
        )
    dispatch = dispatcher.bind_action_cohort_projection(carrier, state_plan=plan)
    root = f"{event.event_type}:{event.identity_plan.subject.execution_id}"
    effects = ExecutionEffectPlan(ActionAnchor("process_execution", root, source="unit_test"), ())
    return dispatcher.prepare_action_cohort_batch(
        root,
        plan,
        (dispatch, dispatch) if duplicate else (dispatch,),
        (ExecutionEffectAuditCohortEntry(effects, effects.reconcile(())),),
        (),
        (),
        exact_projection=exact,
    )


@pytest.mark.parametrize("kind", KINDS)
def test_credential_projection_changes_only_authorized_state(kind: Kind) -> None:
    state, dispatcher, emitter, before = _environment(kind)
    plan, event, after = _plan(state, before, kind)
    batch = _prepare(dispatcher, plan, event)
    assert state.get_process_identity("MAC-A", before.pid) == before
    dispatcher.publish_prepared_action_cohort_batch(batch)
    assert state.get_process_identity("MAC-A", before.pid) == after
    assert (
        before.execution_id == after.execution_id and before.primary_thread == after.primary_thread
    )
    assert process_credential_identities(emitter.emit.call_args.args[0]) == (before, after)
    emitter.emit.assert_called_once()


@pytest.mark.parametrize("kind", KINDS)
def test_credential_cancellation_and_replan_preserve_original_state(kind: Kind) -> None:
    state, dispatcher, emitter, before = _environment(kind)
    plan, event, _ = _plan(state, before, kind)
    batch = _prepare(dispatcher, plan, event)
    assert dispatcher.cancel_prepared_action_cohort_batch(batch)
    assert state.get_process_identity("MAC-A", before.pid) == before
    emitter.emit.assert_not_called()
    plan, event, after = _plan(state, before, kind)
    dispatcher.publish_prepared_action_cohort_batch(_prepare(dispatcher, plan, event))
    assert state.get_process_identity("MAC-A", before.pid) == after


@pytest.mark.parametrize("kind", KINDS)
def test_credential_compatibility_dispatch_cannot_mutate_or_publish(kind: Kind) -> None:
    state, dispatcher, emitter, before = _environment(kind)
    _, event, _ = _plan(state, before, kind)
    with pytest.raises(EventContractError, match="exact State action cohort"):
        dispatcher.dispatch_builder(event)
    assert state.get_process_identity("MAC-A", before.pid) == before
    emitter.emit.assert_not_called()


@pytest.mark.parametrize("kind", KINDS)
@pytest.mark.parametrize(
    "damage", ["pid_version", "execution", "thread", "host", "context", "actor", "time", "origin"]
)
def test_credential_contract_rejects_unrelated_identity_changes(kind: Kind, damage: str) -> None:
    state, _, _, before = _environment(kind)
    _, event, after = _plan(state, before, kind)
    if damage == "pid_version":
        event.identity_plan = replace(
            event.identity_plan, subject=replace(after, audit_pid_version=999)
        )
    elif damage == "execution":
        event.identity_plan = replace(
            event.identity_plan,
            subject=replace(
                after, execution_ordinal=1, executed_at=event.timestamp, lifetime_image=before.image
            ),
        )
    elif damage == "thread":
        event.identity_plan = replace(
            event.identity_plan, subject=replace(after, primary_thread=None)
        )
    elif damage == "host":
        event.src_host.os_category = "linux"
    elif damage == "context":
        event.process.username = "other"
    elif damage == "actor":
        event.identity_plan = replace(event.identity_plan, actor=after)
    elif damage == "time":
        event.timestamp = before.started_at - timedelta(seconds=1)
    else:
        event.identity_plan = replace(
            event.identity_plan,
            subject=replace(after, credentials=replace(after.credentials, real_uid=99)),
        )
    assert not shadow_seal(event).valid


@pytest.mark.parametrize("kind", KINDS)
@pytest.mark.parametrize("damage", ["time", "integrity", "state_platform", "state_credentials"])
def test_credential_projection_binds_exact_state_patch(kind: Kind, damage: str) -> None:
    state, dispatcher, emitter, before = _environment(kind)
    plan, event, after = _plan(state, before, kind)
    if damage == "time":
        event.timestamp += timedelta(microseconds=1)
    elif damage == "integrity":
        event.process.integrity_level = "High"
    elif damage == "state_platform":
        state._pid_os["MAC-A"] = "linux"
    elif kind == "process_audit_bind":
        event.identity_plan = replace(
            event.identity_plan,
            subject=replace(
                after, credentials=replace(after.credentials, audit_session_id=100_999)
            ),
        )
    else:
        event.identity_plan = replace(
            event.identity_plan,
            subject=replace(
                after, credentials=replace(after.credentials, real_gid=99, effective_gid=99)
            ),
        )
    with pytest.raises((EventContractError, StateError, ValueError), match="transition|Mac|State"):
        _prepare(dispatcher, plan, event)
    emitter.emit.assert_not_called()
    assert state.get_process_identity("MAC-A", before.pid) == before


@pytest.mark.parametrize("kind", KINDS)
def test_credential_cohort_rejects_duplicate_members(kind: Kind) -> None:
    state, dispatcher, _, before = _environment(kind)
    plan, event, _ = _plan(state, before, kind)
    with pytest.raises(EventContractError):
        _prepare(dispatcher, plan, event, duplicate=True)


@pytest.mark.parametrize("kind", KINDS)
@pytest.mark.parametrize("threaded", [False, True])
def test_exact_ecar_credential_output_preserves_old_and_new_ids(
    kind: Kind, threaded: bool, tmp_path: Path
) -> None:
    state, dispatcher, _, before = _environment(kind)
    emitter = EcarEmitter(load_format("ecar"), tmp_path, threaded=threaded)
    dispatcher.emitters = {"ecar": emitter}
    plan, event, after = _plan(state, before, kind)
    dispatcher.publish_prepared_action_cohort_batch(_prepare(dispatcher, plan, event, exact=True))
    emitter.close()
    rows = [
        json.loads(line) for p in tmp_path.rglob("ecar.json") for line in p.read_text().splitlines()
    ]
    assert len(rows) == 1
    row = rows[0]
    assert row["object"] == "PROCESS" and row["action"] == "MODIFY"
    props = row["properties"]
    assert props["operation"] == kind.removeprefix("process_")
    assert props["execution_id"] == props["previous_execution_id"] == after.execution_id
    assert props["process_principal"] == after.principal
    assert props["previous_process_principal"] == before.principal
    assert props["previous_effective_uid"] == "0"
    assert props["effective_uid"] == str(after.credentials.effective_uid)
    if kind == "process_service_drop":
        assert all(
            name not in props
            for name in (
                "audit_uid",
                "audit_session_id",
                "previous_audit_uid",
                "previous_audit_session_id",
            )
        )
    else:
        assert props["audit_uid"] == "501"
    if kind == "process_audit_bind":
        assert "previous_audit_uid" not in props
    elif kind == "process_privilege_drop":
        assert props["previous_audit_uid"] == "501"


@pytest.mark.parametrize("kind", KINDS)
def test_exact_credential_omission_still_commits_state(kind: Kind) -> None:
    state, dispatcher, _, before = _environment(kind)
    dispatcher.emitters = {}
    plan, event, after = _plan(state, before, kind)
    dispatcher.publish_prepared_action_cohort_batch(_prepare(dispatcher, plan, event, exact=True))
    assert state.get_process_identity("MAC-A", before.pid) == after


@pytest.mark.parametrize("kind", KINDS)
@pytest.mark.parametrize("restore", [False, True])
def test_new_credential_activity_orders_after_transition(kind: Kind, restore: bool) -> None:
    state, dispatcher, emitter, before = _environment(kind)
    plan, event, after = _plan(state, before, kind)
    batch = _prepare(dispatcher, plan, event)
    dispatcher.publish_prepared_action_cohort_batch(batch)
    observed = emitter.emit.call_args.args[0]
    planner = dispatcher.source_timing_planner
    barrier = planner.admission_time(observed, "ecar")
    if restore:
        from evidenceforge.generation.checkpoints.source_timing_head import (
            SourceTimingPlannerParticipant,
        )
        from evidenceforge.generation.source_timing import SourceTimingPlanner

        del batch
        seal = SourceTimingPlannerParticipant(planner).prepare_checkpoint(0)
        planner = SourceTimingPlanner()
        SourceTimingPlannerParticipant(planner).restore_checkpoint(
            seal.head.payload, tuple(s.payload for s in seal.segments)
        )
    for ordinal in range(8):
        dependent = OccurrenceBuilder(
            timestamp=event.timestamp + timedelta(microseconds=1),
            event_type="file_create",
            src_host=observed.src_host,
            process=observed.process,
            file=FileContext(path=f"/tmp/result-{ordinal}", action="create"),
            identity_plan=EventIdentityPlan(
                actor=after, subject=EntityIdentity(object_id=f"result-{ordinal}", kind="file")
            ),
            lifecycle=observed.lifecycle,
        )
        result = planner.plan_event(dependent, "ecar")
        assert planner.admission_time(result, "ecar") > barrier
    assert (
        planner._runtime_process_credential_times.get(
            planner._process_credential_observation_key("ecar", "ecar:mac-a", after)
        )
        == barrier
    )
    # Same execution with older credentials must not inherit this later barrier.
    assert (
        planner._runtime_process_credential_times.get(
            planner._process_credential_observation_key("ecar", "ecar:mac-a", before)
        )
        is None
    )


@pytest.mark.parametrize("kind", KINDS)
def test_credential_transitions_remain_internal_only(kind: Kind) -> None:
    from pydantic import TypeAdapter, ValidationError

    from evidenceforge.models.scenario import EventSpec

    with pytest.raises(ValidationError, match="union_tag_invalid"):
        TypeAdapter(EventSpec).validate_python({"type": kind})


@pytest.mark.parametrize("kind", KINDS)
def test_credential_sink_lost_return_recovers_one_row(
    kind: Kind,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from evidenceforge.generation.emitters.sorted_writer import ExternalSortedLineWriter

    original = ExternalSortedLineWriter._commit_exact_row
    attempts = 0

    def lose_return(
        writer: ExternalSortedLineWriter, key: tuple[str, int, int], digest: str, frozen: object
    ) -> None:
        nonlocal attempts
        attempts += 1
        original(writer, key, digest, frozen)
        if attempts == 1:
            raise RuntimeError("injected credential commit lost return")

    monkeypatch.setattr(ExternalSortedLineWriter, "_commit_exact_row", lose_return)
    state, dispatcher, _, before = _environment(kind)
    emitter = EcarEmitter(load_format("ecar"), tmp_path, threaded=False)
    dispatcher.emitters = {"ecar": emitter}
    plan, event, after = _plan(state, before, kind)
    batch = _prepare(dispatcher, plan, event, exact=True)
    with pytest.raises(RuntimeError, match="credential commit lost return") as caught:
        dispatcher.publish_prepared_action_cohort_batch(batch)
    assert state.get_process_identity("MAC-A", before.pid) == after
    version = state.materialization_version
    receipt = caught.value.action_cohort_receipt
    assert caught.value.action_cohort_result.projections[0].status == "recoverable"
    assert dispatcher.resume_action_cohort_projection(receipt).projections[0].status == "succeeded"
    assert state.materialization_version == version
    assert state.get_process_identity("MAC-A", before.pid) == after
    dispatcher.assert_exact_projection_recoveries_drained()
    emitter.close()
    rows = [line for path in tmp_path.rglob("ecar.json") for line in path.read_text().splitlines()]
    assert len(rows) == 1 and attempts == 2


@pytest.mark.parametrize("kind", KINDS)
def test_ordinary_dependent_record_cannot_hide_credential_mutation(kind: Kind) -> None:
    state, dispatcher, emitter, before = _environment(kind)
    plan, event, _ = _plan(state, before, kind)
    event.event_type = "file_create"
    event.file = FileContext(path="/tmp/example", action="create")
    event.identity_plan = None
    event.process.username = before.principal
    # The source row is structurally valid but does not describe the credential transition.
    with dispatcher.source_timing_planner.prepared_planning() as timing:
        carrier = dispatcher.prepare_action_cohort_projection(
            event, source_timing_preparation=timing
        )
    dispatch = dispatcher.bind_action_cohort_projection(carrier, state_plan=plan)
    root = "hidden-credential-change"
    effects = ExecutionEffectPlan(ActionAnchor("process_execution", root, source="unit_test"), ())
    with pytest.raises(
        EventContractError, match="credential transitions lack exact source members"
    ):
        dispatcher.prepare_action_cohort_batch(
            root,
            plan,
            (dispatch,),
            (ExecutionEffectAuditCohortEntry(effects, effects.reconcile(())),),
            (),
            (),
        )
    assert state.get_process_identity("MAC-A", before.pid) == before
    emitter.emit.assert_not_called()


@pytest.mark.parametrize("kind", KINDS)
def test_fork_after_credential_transition_keeps_child_create_and_dependents_ordered(
    kind: Kind,
) -> None:
    from evidenceforge.events.contexts import ProcessContext
    from evidenceforge.events.lifecycle import ActionLifecycleContext

    state, dispatcher, emitter, before = _environment(kind)
    plan, event, after = _plan(state, before, kind)
    dispatcher.publish_prepared_action_cohort_batch(_prepare(dispatcher, plan, event))
    observed = emitter.emit.call_args.args[0]
    planner = dispatcher.source_timing_planner
    barrier = planner.admission_time(observed, "ecar")
    builder = state.begin_action_cohort_materialization()
    child = builder.fork_process(after, forked_at=event.timestamp + timedelta(microseconds=1))
    state.materialize_action_cohort(builder.seal())
    identity = child.identity
    created = OccurrenceBuilder(
        timestamp=identity.started_at,
        event_type="process_create",
        src_host=observed.src_host,
        process=ProcessContext(
            pid=identity.pid,
            parent_pid=identity.parent_pid,
            image=identity.image,
            command_line=identity.command_line,
            username=identity.principal,
            logon_id=identity.logon_id,
            start_time=identity.started_at,
        ),
        identity_plan=EventIdentityPlan(actor=after, subject=identity),
        lifecycle=ActionLifecycleContext(
            group_id=identity.lifecycle_group_id,
            canonical_start=identity.started_at,
            phase="start",
            parent_group_id=after.lifecycle_group_id,
        ),
    )
    created = planner.plan_event(created, "ecar")
    child_time = planner.admission_time(created, "ecar")
    assert child_time > barrier
    for ordinal in range(8):
        file = OccurrenceBuilder(
            timestamp=identity.started_at + timedelta(microseconds=1),
            event_type="file_create",
            src_host=observed.src_host,
            process=created.process,
            file=FileContext(path=f"/tmp/child-result-{ordinal}", action="create"),
            identity_plan=EventIdentityPlan(
                actor=identity,
                subject=EntityIdentity(object_id=f"child-result-{ordinal}", kind="file"),
            ),
            lifecycle=replace(created.lifecycle, phase="dependent"),
        )
        assert planner.admission_time(planner.plan_event(file, "ecar"), "ecar") > child_time


@pytest.mark.parametrize("kind", KINDS)
@pytest.mark.parametrize("timestamp", [None, "2026-10-15", _START.replace(tzinfo=None)])
def test_credential_invalid_time_is_a_contract_violation(kind: Kind, timestamp: object) -> None:
    state, _, _, before = _environment(kind)
    _, event, _ = _plan(state, before, kind)
    event.timestamp = timestamp
    seal = shadow_seal(event)
    assert not seal.valid
    assert any("aware canonical timestamp" in item.message for item in seal.violations)


@pytest.mark.parametrize("kind", KINDS)
def test_credential_rejects_unowned_authentication_context(kind: Kind) -> None:
    from evidenceforge.events.contexts import AuthContext

    state, _, _, before = _environment(kind)
    _, event, _ = _plan(state, before, kind)
    event.auth = AuthContext(username="other", logon_id="unrelated")
    assert not shadow_seal(event).valid
