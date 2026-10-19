# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Whole terminal cohorts retain one exact source journal and member results."""

import json
from datetime import timedelta
from pathlib import Path

import pytest

from evidenceforge.events.contexts import HostContext
from evidenceforge.events.dispatcher import EventDispatcher
from evidenceforge.formats.loader import load_format
from evidenceforge.generation.actions.base import ActionAnchor
from evidenceforge.generation.actions.command_effects import (
    ExecutionEffectAuditCohortEntry,
    ExecutionEffectAuditCounter,
    ExecutionEffectPlan,
)
from evidenceforge.generation.actions.posix_process import process_exit_occurrence
from evidenceforge.generation.emitters.ecar import EcarEmitter
from evidenceforge.generation.lifecycle_authority import GeneratorLifecycleAuthority
from evidenceforge.generation.lifecycle_registry import LifecycleRegistry
from evidenceforge.generation.lifecycle_shadow import LifecycleShadow
from evidenceforge.generation.state_manager import StateManager
from evidenceforge.models.exceptions import EventContractError
from tests.unit.test_process_exec_projection import _START


def _setup(
    tmp_path: Path,
    *,
    collected: bool = True,
    threaded: bool = False,
    platform: str = "macos",
    count: int = 3,
) -> tuple:
    state = StateManager()
    state.set_current_time(_START)
    members = []
    for index in range(count):
        plan = state.plan_process_materialization(
            system="MAC-01",
            parent_pid=members[-1].pid if members else 0,
            image=f"/usr/local/bin/worker{index}",
            command_line=f"worker{index}",
            username="casey",
            integrity_level="Medium",
            os_category=platform,
            start_time=_START + timedelta(seconds=index),
        )
        state.materialize_process(plan)
        members.append(plan.identity)
    registry = LifecycleRegistry(shard_count=4)
    shadow = LifecycleShadow(state, registry)
    authority = GeneratorLifecycleAuthority(state, shadow, shard_count=4)
    authority.bootstrap_active_state()
    emitter = EcarEmitter(load_format("ecar"), tmp_path, threaded=threaded)
    dispatcher = EventDispatcher(
        state,
        {"ecar": emitter} if collected else {},
        lifecycle_shadow=shadow,
        enforce_lifecycle_authority=True,
    )
    dispatcher.bind_lifecycle_authority(authority)
    dispatcher.bind_execution_effect_audit(ExecutionEffectAuditCounter())
    builder = state.begin_action_cohort_materialization()
    events = []
    for member in reversed(members):
        at = _START + timedelta(seconds=20)
        builder.terminate_process(member, end_time=at)
        events.append(
            process_exit_occurrence(
                host=HostContext(
                    hostname="MAC-01",
                    ip="192.0.2.41",
                    os="macOS 26" if platform == "macos" else "Linux",
                    os_category=platform,
                    system_type="workstation",
                ),
                process=member,
                timestamp=at,
                integrity_level="Medium",
            )
        )
    plan = builder.seal()
    return state, dispatcher, emitter, plan, tuple(events), tuple(members)


def _prepare(
    dispatcher: EventDispatcher,
    plan: object,
    events: tuple,
    *,
    root: str = "process-exit-group:invented",
) -> object:
    with dispatcher.source_timing_planner.prepared_planning() as timing:
        carriers = tuple(
            dispatcher.prepare_action_cohort_projection(event, source_timing_preparation=timing)
            for event in events
        )
    dispatches = tuple(
        dispatcher.bind_action_cohort_projection(carrier, state_plan=plan) for carrier in carriers
    )
    effects = ExecutionEffectPlan(ActionAnchor("process_execution", root, source="unit_test"), ())
    return dispatcher.prepare_action_cohort_batch(
        root,
        plan,
        dispatches,
        (ExecutionEffectAuditCohortEntry(effects, effects.reconcile(())),),
        (),
        (),
        exact_projection=True,
    )


def _rows(tmp_path: Path) -> list[dict]:
    return [
        json.loads(line)
        for path in tmp_path.rglob("ecar.json")
        for line in path.read_text().splitlines()
    ]


@pytest.mark.parametrize("collected", [False, True])
@pytest.mark.parametrize("threaded", [False, True])
def test_whole_mac_group_commits_once_with_one_result_per_member(
    tmp_path: Path, collected: bool, threaded: bool
) -> None:
    state, dispatcher, emitter, plan, events, members = _setup(
        tmp_path, collected=collected, threaded=threaded
    )
    batch = _prepare(dispatcher, plan, events)
    result = dispatcher.publish_prepared_action_cohort_batch(batch)
    assert len(result.projections) == len(members)
    assert all(item.status == "succeeded" for item in result.projections)
    assert dispatcher.authenticates_action_cohort_publication_receipt(result.receipt)
    assert all(state.get_process(item.hostname, item.pid) is None for item in members)
    dispatcher.assert_exact_projection_recoveries_drained()
    emitter.close()
    rows = _rows(tmp_path)
    assert len(rows) == (len(members) if collected else 0)
    assert all(row["action"] == "TERMINATE" for row in rows)


@pytest.mark.parametrize("after_write", [False, True])
@pytest.mark.parametrize("ordinal", [1, 2, 3])
def test_group_sink_failure_resumes_without_repeating_state_or_written_rows(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, after_write: bool, ordinal: int
) -> None:
    from evidenceforge.generation.emitters.sorted_writer import ExternalSortedLineWriter

    original = ExternalSortedLineWriter._commit_exact_row
    attempts = 0

    def fail(writer: object, key: tuple, digest: str, row: object) -> None:
        nonlocal attempts
        attempts += 1
        if attempts == ordinal:
            if after_write:
                original(writer, key, digest, row)
            raise RuntimeError("injected group row failure")
        original(writer, key, digest, row)

    monkeypatch.setattr(ExternalSortedLineWriter, "_commit_exact_row", fail)
    state, dispatcher, emitter, plan, events, members = _setup(tmp_path)
    batch = _prepare(dispatcher, plan, events)
    with pytest.raises(RuntimeError, match="group row failure") as caught:
        dispatcher.publish_prepared_action_cohort_batch(batch)
    assert all(state.get_process(item.hostname, item.pid) is None for item in members)
    version = state.materialization_version
    result = dispatcher.resume_action_cohort_projection(caught.value.action_cohort_receipt)
    assert state.materialization_version == version
    assert all(item.status == "succeeded" for item in result.projections)
    dispatcher.assert_exact_projection_recoveries_drained()
    emitter.close()
    rows = _rows(tmp_path)
    assert len(rows) == 3
    assert len({row["id"] for row in rows}) == 3


def test_cancel_group_preserves_every_live_member_and_releases_source_reservation(
    tmp_path: Path,
) -> None:
    state, dispatcher, emitter, plan, events, members = _setup(tmp_path)
    before = state.materialization_digest()
    batch = _prepare(dispatcher, plan, events)
    assert dispatcher.cancel_prepared_action_cohort_batch(batch)
    assert state.materialization_digest() == before
    assert dispatcher.action_cohort_publication_census().retained_bytes == 0
    emitter.close()
    assert _rows(tmp_path) == []


@pytest.mark.parametrize("damage", ["linux", "root", "missing", "duplicate"])
def test_group_rejects_unrelated_platform_or_incomplete_terminal_members(
    tmp_path: Path, damage: str
) -> None:
    state, dispatcher, emitter, plan, events, members = _setup(
        tmp_path, platform="linux" if damage == "linux" else "macos"
    )
    before = state.materialization_digest()
    if damage == "missing":
        events = events[:-1]
    elif damage == "duplicate":
        events = (events[0], events[0], events[2])
    with pytest.raises(EventContractError):
        _prepare(
            dispatcher,
            plan,
            events,
            root="unrelated" if damage == "root" else "process-exit-group:test",
        )
    assert state.materialization_digest() == before
    emitter.close()
    assert _rows(tmp_path) == []


@pytest.mark.parametrize("after_release", [False, True])
def test_group_release_failure_retains_all_outcomes_or_adopts_completed_release(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, after_release: bool
) -> None:
    from evidenceforge.generation.emitters.base import ExactPublicationBatch

    original = ExactPublicationBatch.release_no_fail
    attempts = 0

    def fail(batch: ExactPublicationBatch) -> None:
        nonlocal attempts
        attempts += 1
        if attempts == 1:
            if after_release:
                original(batch)
            raise RuntimeError("injected group release failure")
        original(batch)

    monkeypatch.setattr(ExactPublicationBatch, "release_no_fail", fail)
    state, dispatcher, emitter, plan, events, _ = _setup(tmp_path)
    batch = _prepare(dispatcher, plan, events)
    if after_release:
        result = dispatcher.publish_prepared_action_cohort_batch(batch)
    else:
        with pytest.raises(RuntimeError, match="group release failure") as caught:
            dispatcher.publish_prepared_action_cohort_batch(batch)
        pending = caught.value.action_cohort_result
        assert all(item.status == "release_pending" for item in pending.projections)
        version = state.materialization_version
        result = dispatcher.resume_action_cohort_projection(caught.value.action_cohort_receipt)
        assert state.materialization_version == version
    assert all(item.status == "succeeded" for item in result.projections)
    dispatcher.assert_exact_projection_recoveries_drained()
    emitter.close()
    assert len(_rows(tmp_path)) == 3


def test_group_provisional_state_failure_leaves_every_member_live(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from evidenceforge.generation.state_manager import PreparedActionCohortMaterialization

    state, dispatcher, emitter, plan, events, _ = _setup(tmp_path)
    before = state.materialization_digest()
    batch = _prepare(dispatcher, plan, events)
    original = PreparedActionCohortMaterialization.apply_provisional

    def fail(owner: PreparedActionCohortMaterialization) -> None:
        original(owner)
        raise RuntimeError("injected group state failure")

    monkeypatch.setattr(PreparedActionCohortMaterialization, "apply_provisional", fail)
    with pytest.raises(RuntimeError, match="group state failure"):
        dispatcher.publish_prepared_action_cohort_batch(batch)
    assert state.materialization_digest() == before
    assert dispatcher.action_cohort_publication_census().retained_bytes == 0
    emitter.close()
    assert _rows(tmp_path) == []


def test_missing_middle_member_row_fails_before_any_canonical_commit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    state, dispatcher, emitter, plan, events, _ = _setup(tmp_path)
    before = state.materialization_digest()
    original = dispatcher._publish_action_cohort_projection
    calls = 0

    def omit(projection: object) -> dict[str, str]:
        nonlocal calls
        calls += 1
        return {} if calls == 2 else original(projection)

    monkeypatch.setattr(dispatcher, "_publish_action_cohort_projection", omit)
    with pytest.raises(EventContractError, match="member's row shape"):
        _prepare(dispatcher, plan, events)
    assert state.materialization_digest() == before
    assert dispatcher.action_cohort_publication_census().retained_bytes == 0
    emitter.close()
    assert _rows(tmp_path) == []


@pytest.mark.slow
def test_group_exact_output_is_identical_in_fresh_processes_and_threaded_writers(
    tmp_path: Path,
) -> None:
    import os
    import subprocess
    import sys

    script = """
from pathlib import Path
import sys
from tests.unit.test_macos_exact_exit_group import _setup, _prepare
state, dispatcher, emitter, plan, events, members = _setup(Path(sys.argv[1]), threaded=sys.argv[2] == 'yes')
dispatcher.publish_prepared_action_cohort_batch(_prepare(dispatcher, plan, events))
dispatcher.assert_exact_projection_recoveries_drained()
emitter.close()
"""
    outputs: list[dict[str, bytes]] = []
    for seed, threaded in (("7", "no"), ("83", "yes")):
        target = tmp_path / seed
        env = dict(os.environ, PYTHONHASHSEED=seed)
        subprocess.run(
            [sys.executable, "-c", script, str(target), threaded],
            env=env,
            check=True,
            capture_output=True,
            text=True,
            timeout=60,
        )
        outputs.append(
            {str(path.relative_to(target)): path.read_bytes() for path in target.rglob("ecar.json")}
        )
    assert outputs[0] and outputs[0] == outputs[1]
