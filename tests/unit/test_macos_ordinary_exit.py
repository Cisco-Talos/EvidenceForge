# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Ordinary Mac exits preserve live descendants and exact lifecycle ownership."""

import json
from dataclasses import replace
from datetime import timedelta
from pathlib import Path

import pytest

from evidenceforge.events.dispatcher import EventDispatcher
from evidenceforge.events.lifecycle import LifecycleHold
from evidenceforge.formats.loader import load_format
from evidenceforge.generation.activity import ActivityGenerator
from evidenceforge.generation.checkpoints.lifecycle_head import _capture, _restore
from evidenceforge.generation.checkpoints.state_manager_head import _capture_head, _restore_head
from evidenceforge.generation.emitters.ecar import EcarEmitter
from evidenceforge.generation.lifecycle_authority import GeneratorLifecycleAuthority
from evidenceforge.generation.lifecycle_registry import LifecycleRegistry
from evidenceforge.generation.lifecycle_shadow import LifecycleShadow
from evidenceforge.generation.state_manager import StateManager
from evidenceforge.models.exceptions import StateError
from evidenceforge.models.scenario import System, User
from tests.unit.test_macos_group_adoption import _family
from tests.unit.test_macos_launch_registration import _START


def _setup(tmp_path: Path, *, collect: bool = True, threaded: bool = False) -> tuple:
    state, registry, authority, _, _, parent, child, descendant, _ = _family()
    emitter = EcarEmitter(load_format("ecar"), tmp_path / "ecar.json", threaded=threaded)
    emitters = {"ecar": emitter} if collect else {}
    dispatcher = EventDispatcher(state, emitters, lifecycle_shadow=authority._shadow)
    generator = ActivityGenerator(
        state, emitters, dispatcher=dispatcher, lifecycle_authority=authority
    )
    system = System(hostname="MAC-A", ip="192.0.2.25", os="macOS 26", type="workstation")
    user = User(
        username="root", full_name="Invented Root", email="root@example.test", persona="developer"
    )
    return (
        generator,
        state,
        registry,
        authority,
        dispatcher,
        emitter,
        system,
        user,
        parent,
        child,
        descendant,
    )


def _close(fixture: tuple, identity: object, seconds: int) -> None:
    generator, _, _, _, _, _, system, user, *_ = fixture
    generator.generate_process_termination(
        user,
        system,
        _START + timedelta(seconds=seconds),
        identity.pid,
        identity.image,
        identity.logon_id,
        from_storyline=True,
    )


@pytest.mark.parametrize("collect", [False, True])
@pytest.mark.parametrize("threaded", [False, True])
def test_ordinary_exit_adopts_child_then_child_can_exit_through_same_owner(
    tmp_path: Path, collect: bool, threaded: bool
) -> None:
    fixture = _setup(tmp_path, collect=collect, threaded=threaded)
    _, state, registry, _, dispatcher, emitter, _, _, parent, child, descendant = fixture
    _close(fixture, child, 5)
    assert state.get_process(child.hostname, child.pid) is None
    assert registry.get_process(child.object_id).closed_at == _START + timedelta(seconds=5)
    adopted = state.get_process_identity_by_object_id(descendant.object_id)
    assert adopted.parentage.original == descendant.parentage.original
    assert adopted.parent_pid == 1
    assert adopted.job_control == descendant.job_control
    assert (
        registry.get_process(descendant.object_id).current_parent_object_id
        == adopted.parentage.current.object_id
    )
    assert state.get_process_identity(parent.hostname, parent.pid) == parent
    _close(fixture, adopted, 7)
    assert registry.get_process(descendant.object_id).closed_at == _START + timedelta(seconds=7)
    dispatcher.assert_exact_projection_recoveries_drained()
    emitter.close()
    rows = (
        [json.loads(line) for line in (tmp_path / "ecar.json").read_text().splitlines()]
        if collect
        else []
    )
    assert len(rows) == (2 if collect else 0)
    assert {row["objectID"] for row in rows} == (
        {child.object_id, descendant.object_id} if collect else set()
    )


def test_adopted_child_remains_valid_after_state_and_lifecycle_checkpoint(tmp_path: Path) -> None:
    fixture = _setup(tmp_path, collect=False)
    _, state, registry, _, _, emitter, _, _, _, child, descendant = fixture
    _close(fixture, child, 5)
    restored_state, restored_registry = StateManager(), LifecycleRegistry()
    _restore_head(restored_state, _capture_head(state))
    registry.prune_action_cohort_receipt_authorities()
    _restore(restored_registry, _capture(registry))
    authority = GeneratorLifecycleAuthority(
        restored_state, LifecycleShadow(restored_state, restored_registry)
    )
    adopted = restored_state.get_process_identity_by_object_id(descendant.object_id)
    builder = restored_state.begin_action_cohort_materialization()
    builder.terminate_process(adopted, end_time=_START + timedelta(seconds=7))
    request = authority.action_cohort_request(builder.seal())
    assert request is not None
    with pytest.raises(StateError, match="parent adoption"):
        authority._action_cohort_registered_process(
            replace(adopted, parentage=descendant.parentage, parent_pid=descendant.parent_pid)
        )
    emitter.close()


@pytest.mark.parametrize("fault", ["admission", "hold"])
def test_exit_preparation_failure_preserves_both_owners_and_releases_timing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fault: str
) -> None:
    fixture = _setup(tmp_path)
    _, state, registry, authority, dispatcher, emitter, _, _, _, child, descendant = fixture
    if fault == "admission":

        def reject(*args: object, **kwargs: object) -> None:
            raise StateError("injected admission failure")

        monkeypatch.setattr(authority, "prepare_action_cohort", reject)
    else:
        registry.add_hold(
            LifecycleHold(
                hold_id="invented-hold",
                subject=registry.get_process(child.object_id).identity.ref,
                acquired_at=_START + timedelta(seconds=4),
                hold_until=_START + timedelta(seconds=10),
                action_id="invented-hold",
                reason="modeled pending work",
            )
        )
    with pytest.raises(StateError):
        _close(fixture, child, 5)
    assert state.get_process_identity(child.hostname, child.pid) == child
    assert state.get_process_identity(descendant.hostname, descendant.pid) == descendant
    assert registry.get_process(child.object_id).closed_at is None
    assert registry.get_process(descendant.object_id).parentage_change is None
    with dispatcher.source_timing_planner.prepared_planning() as timing:
        pass
    timing.cancel()
    monkeypatch.undo()
    _close(fixture, child, 12)
    assert state.get_process(child.hostname, child.pid) is None
    emitter.close()


@pytest.mark.parametrize("after_write", [False, True])
def test_exit_sink_recovery_does_not_repeat_adoption_or_termination(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, after_write: bool
) -> None:
    from evidenceforge.generation.emitters.sorted_writer import ExternalSortedLineWriter

    original = ExternalSortedLineWriter._commit_exact_row
    attempts = 0

    def fail_once(writer: object, key: tuple, digest: str, frozen: object) -> None:
        nonlocal attempts
        attempts += 1
        if attempts == 1:
            if after_write:
                original(writer, key, digest, frozen)
            raise RuntimeError("injected source failure")
        original(writer, key, digest, frozen)

    monkeypatch.setattr(ExternalSortedLineWriter, "_commit_exact_row", fail_once)
    fixture = _setup(tmp_path)
    _, state, registry, _, dispatcher, emitter, _, _, _, child, descendant = fixture
    with pytest.raises(RuntimeError, match="source failure") as caught:
        _close(fixture, child, 5)
    adopted = state.get_process_identity_by_object_id(descendant.object_id)
    assert adopted.parent_pid == 1
    assert state.get_process(child.hostname, child.pid) is None
    version = state.materialization_version
    before = registry.get_process(descendant.object_id)
    dispatcher.resume_action_cohort_projection(caught.value.action_cohort_receipt)
    assert state.materialization_version == version
    assert registry.get_process(descendant.object_id) == before
    dispatcher.assert_exact_projection_recoveries_drained()
    emitter.close()
    assert len((tmp_path / "ecar.json").read_text().splitlines()) == 1
