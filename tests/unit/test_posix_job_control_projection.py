# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Membership observations are projections of an authenticated State transition."""

import json
from dataclasses import replace
from datetime import timedelta
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from evidenceforge.events.base import OccurrenceBuilder
from evidenceforge.events.contexts import FileContext, HostContext
from evidenceforge.events.contracts import shadow_seal
from evidenceforge.events.dispatcher import EventDispatcher, PreparedActionCohortBatch
from evidenceforge.events.identity import EntityIdentity, EventIdentityPlan, ProcessIdentity
from evidenceforge.formats.loader import load_format
from evidenceforge.generation.actions.base import ActionAnchor
from evidenceforge.generation.actions.command_effects import (
    ExecutionEffectAuditCohortEntry,
    ExecutionEffectAuditCounter,
    ExecutionEffectPlan,
)
from evidenceforge.generation.actions.posix_process import process_job_control_occurrence
from evidenceforge.generation.checkpoints.source_timing_head import SourceTimingPlannerParticipant
from evidenceforge.generation.emitters.ecar import EcarEmitter
from evidenceforge.generation.lifecycle_authority import GeneratorLifecycleAuthority
from evidenceforge.generation.lifecycle_registry import LifecycleRegistry
from evidenceforge.generation.lifecycle_shadow import LifecycleShadow
from evidenceforge.generation.source_timing import SourceTimingPlanner
from evidenceforge.generation.state_manager import ActionCohortMaterializationPlan, StateManager
from evidenceforge.models.exceptions import EventContractError
from tests.unit.test_posix_job_control import _START, _change, _fork, _root


def _environment() -> tuple[StateManager, EventDispatcher, MagicMock, ProcessIdentity]:
    state, root = _root()
    root = _change(state, root, "bootstrap", 0)
    child = _fork(state, root, 1)
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
    return state, dispatcher, emitter, child


def _plan(
    state: StateManager, before: ProcessIdentity
) -> tuple[ActionCohortMaterializationPlan, OccurrenceBuilder, ProcessIdentity]:
    builder = state.begin_action_cohort_materialization()
    at = _START + timedelta(seconds=2)
    after = builder.change_posix_job_control(before, operation="setsid", changed_at=at)
    event = process_job_control_occurrence(
        host=HostContext(
            hostname=before.hostname,
            ip="192.0.2.20",
            os="macOS 26",
            os_category="macos",
            system_type="workstation",
        ),
        before=before,
        after=after,
        timestamp=at,
        integrity_level="System",
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
    root = f"process-job-control:{event.identity_plan.subject.execution_id}:{event.timestamp.isoformat()}"
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


@pytest.mark.parametrize("threaded", [False, True])
def test_exact_ecar_membership_output_and_replay(threaded: bool, tmp_path: Path) -> None:
    state, dispatcher, _, before = _environment()
    emitter = EcarEmitter(load_format("ecar"), tmp_path, threaded=threaded)
    dispatcher.emitters = {"ecar": emitter}
    plan, event, after = _plan(state, before)
    batch = _prepare(dispatcher, plan, event, exact=True)
    dispatcher.publish_prepared_action_cohort_batch(batch)
    with pytest.raises(EventContractError, match="consumed"):
        dispatcher.publish_prepared_action_cohort_batch(batch)
    emitter.close()
    rows = [
        json.loads(line) for p in tmp_path.rglob("ecar.json") for line in p.read_text().splitlines()
    ]
    assert len(rows) == 1
    props = rows[0]["properties"]
    assert props["operation"] == "job_control"
    assert props["process_group_id"] == props["posix_session_id"] == str(before.pid)
    assert props["previous_process_group_id"] == props["previous_posix_session_id"] == "1"
    assert props["execution_id"] == props["previous_execution_id"] == before.execution_id
    assert state.get_posix_group_members(after.job_control) == (after,)


def test_compatibility_dispatch_and_duplicate_projection_cannot_publish() -> None:
    state, dispatcher, emitter, before = _environment()
    plan, event, _ = _plan(state, before)
    with pytest.raises(EventContractError, match="exact State action cohort"):
        dispatcher.dispatch_builder(event)
    with pytest.raises(EventContractError):
        _prepare(dispatcher, plan, event, duplicate=True)
    assert state.get_process_identity(before.hostname, before.pid) == before
    emitter.emit.assert_not_called()


@pytest.mark.parametrize(
    "damage", ["credentials", "image", "execution", "actor", "time", "windows"]
)
def test_membership_contract_rejects_unrelated_identity_changes(damage: str) -> None:
    state, _, _, before = _environment()
    _, event, after = _plan(state, before)
    if damage == "credentials":
        event.identity_plan = replace(event.identity_plan, subject=replace(after, credentials=None))
    elif damage == "image":
        event.identity_plan = replace(
            event.identity_plan, subject=replace(after, image="/bin/false")
        )
    elif damage == "execution":
        event.identity_plan = replace(
            event.identity_plan,
            subject=replace(
                after, execution_ordinal=1, executed_at=event.timestamp, lifetime_image=before.image
            ),
        )
    elif damage == "actor":
        event.identity_plan = replace(event.identity_plan, target=after)
    elif damage == "time":
        event.timestamp = before.started_at
    else:
        event.src_host.os_category = "windows"
    assert not shadow_seal(event).valid


@pytest.mark.parametrize("restore", [False, True])
def test_dependent_activity_orders_after_membership_observation(restore: bool) -> None:
    state, dispatcher, emitter, before = _environment()
    plan, event, after = _plan(state, before)
    dispatcher.publish_prepared_action_cohort_batch(_prepare(dispatcher, plan, event))
    observed = emitter.emit.call_args.args[0]
    planner = dispatcher.source_timing_planner
    barrier = planner.admission_time(observed, "ecar")
    if restore:
        seal = SourceTimingPlannerParticipant(planner).prepare_checkpoint(0)
        planner = SourceTimingPlanner()
        SourceTimingPlannerParticipant(planner).restore_checkpoint(
            seal.head.payload, tuple(s.payload for s in seal.segments)
        )
    dependent = OccurrenceBuilder(
        timestamp=event.timestamp + timedelta(microseconds=1),
        event_type="file_create",
        src_host=observed.src_host,
        process=observed.process,
        file=FileContext(path="/tmp/invented-result", action="create"),
        identity_plan=EventIdentityPlan(
            actor=after, subject=EntityIdentity(object_id="invented-result", kind="file")
        ),
        lifecycle=observed.lifecycle,
    )
    result = planner.plan_event(dependent, "ecar")
    assert planner.admission_time(result, "ecar") > barrier
    assert (
        planner._runtime_process_credential_times.get(
            planner._process_credential_observation_key("ecar", "ecar:workstation-test", before)
        )
        is None
    )


def test_collection_omission_does_not_change_membership() -> None:
    state, dispatcher, _, before = _environment()
    dispatcher.emitters = {}
    plan, event, after = _plan(state, before)
    dispatcher.publish_prepared_action_cohort_batch(_prepare(dispatcher, plan, event, exact=True))
    assert state.get_process_identity(before.hostname, before.pid) == after


def test_parent_group_change_preserves_actor_and_target_roles_and_frontiers(tmp_path: Path) -> None:
    state, dispatcher, _, before = _environment()
    parent = state.get_process_identity(before.hostname, before.parent_pid)
    builder = state.begin_action_cohort_materialization()
    at = _START + timedelta(seconds=2)
    after = builder.change_posix_job_control(
        before, operation="setpgid", changed_at=at, actor=parent
    )
    event = process_job_control_occurrence(
        host=HostContext(
            hostname=before.hostname,
            ip="192.0.2.20",
            os="macOS 26",
            os_category="macos",
            system_type="workstation",
        ),
        before=before,
        after=after,
        actor=parent,
        timestamp=at,
        integrity_level="System",
    )
    emitter = EcarEmitter(load_format("ecar"), tmp_path, threaded=False)
    dispatcher.emitters = {"ecar": emitter}
    dispatcher.publish_prepared_action_cohort_batch(
        _prepare(dispatcher, builder.seal(), event, exact=True)
    )
    emitter.close()
    row = next(
        json.loads(line) for p in tmp_path.rglob("ecar.json") for line in p.read_text().splitlines()
    )
    assert row["actorID"] == parent.object_id
    assert row["objectID"] == after.object_id
    assert row["properties"]["source_pid"] == str(parent.pid)
    assert row["properties"]["target_pid"] == str(before.pid)
    assert state.get_process(parent.hostname, parent.pid).last_activity_time == at


def test_projection_rejects_a_different_changing_actor() -> None:
    state, dispatcher, emitter, before = _environment()
    parent = state.get_process_identity(before.hostname, before.parent_pid)
    builder = state.begin_action_cohort_materialization()
    at = _START + timedelta(seconds=2)
    after = builder.change_posix_job_control(
        before, operation="setpgid", changed_at=at, actor=parent
    )
    event = process_job_control_occurrence(
        host=HostContext(
            hostname=before.hostname,
            ip="192.0.2.20",
            os="macOS 26",
            os_category="macos",
            system_type="workstation",
        ),
        before=before,
        after=after,
        timestamp=at,
        integrity_level="System",
    )
    with pytest.raises(EventContractError, match="State transition"):
        _prepare(dispatcher, builder.seal(), event)
    emitter.emit.assert_not_called()


def test_membership_source_lost_return_recovers_one_row_without_reapplying_state(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
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
            raise RuntimeError("injected membership commit lost return")

    monkeypatch.setattr(ExternalSortedLineWriter, "_commit_exact_row", lose_return)
    state, dispatcher, _, before = _environment()
    emitter = EcarEmitter(load_format("ecar"), tmp_path, threaded=False)
    dispatcher.emitters = {"ecar": emitter}
    plan, event, after = _plan(state, before)
    with pytest.raises(RuntimeError, match="membership commit lost return") as caught:
        dispatcher.publish_prepared_action_cohort_batch(
            _prepare(dispatcher, plan, event, exact=True)
        )
    version = state.materialization_version
    receipt = caught.value.action_cohort_receipt
    assert dispatcher.resume_action_cohort_projection(receipt).projections[0].status == "succeeded"
    assert state.materialization_version == version
    assert state.get_posix_group_members(after.job_control) == (after,)
    assert len(state.get_process(after.hostname, after.pid).job_control_history) == 1
    dispatcher.assert_exact_projection_recoveries_drained()
    emitter.close()
    rows = [line for path in tmp_path.rglob("ecar.json") for line in path.read_text().splitlines()]
    assert len(rows) == 1 and attempts == 2


@pytest.mark.slow
def test_known_membership_output_is_deterministic_across_fresh_processes(tmp_path: Path) -> None:
    import os
    import subprocess
    import sys

    script = """
from pathlib import Path
import sys
from evidenceforge.formats.loader import load_format
from evidenceforge.generation.emitters.ecar import EcarEmitter
from evidenceforge.utils.rng import generation_seed_scope
from tests.unit.test_posix_job_control_projection import _environment, _plan, _prepare
with generation_seed_scope(217):
    state, dispatcher, _, before = _environment()
    emitter = EcarEmitter(load_format('ecar'), Path(sys.argv[1]), threaded=sys.argv[2]=='yes')
    dispatcher.emitters = {'ecar': emitter}
    plan, event, after = _plan(state, before)
    dispatcher.publish_prepared_action_cohort_batch(_prepare(dispatcher, plan, event, exact=True))
    emitter.close()
"""
    snapshots: list[dict[str, bytes]] = []
    for seed, threaded in (("17", "no"), ("91", "yes")):
        output = tmp_path / seed
        result = subprocess.run(
            [sys.executable, "-c", script, str(output), threaded],
            env=os.environ | {"PYTHONHASHSEED": seed},
            capture_output=True,
            text=True,
            timeout=30,
        )
        assert result.returncode == 0, result.stdout + result.stderr
        snapshots.append(
            {p.relative_to(output).as_posix(): p.read_bytes() for p in output.rglob("ecar.json")}
        )
    assert snapshots[0] and snapshots[0] == snapshots[1]
