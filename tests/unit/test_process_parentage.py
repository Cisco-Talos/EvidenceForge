# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Original parent identity survives image changes, parent exit and PID reuse."""

from dataclasses import replace
from datetime import timedelta

import pytest

from evidenceforge.events.parentage import ProcessParentage, ProcessParentReference
from evidenceforge.generation.checkpoints.state_manager_head import _capture_head, _restore_head
from evidenceforge.generation.checkpoints.state_values import decode_state_value, encode_state_value
from evidenceforge.generation.lifecycle_registry import LifecycleRegistry
from evidenceforge.generation.lifecycle_shadow import LifecycleShadow
from evidenceforge.generation.state_manager import StateManager
from evidenceforge.models.exceptions import StateError
from tests.unit.test_posix_job_control import _START, _close, _fork, _root


def test_fork_owns_immediate_parent_reference_and_exec_preserves_it() -> None:
    state, root = _root()
    assert root.parentage == ProcessParentage(None, None)
    assert root.parentage.original_pid == 0
    parent = _fork(state, root, 1)
    child = _fork(state, parent, 2)
    assert (
        child.parentage.original
        == child.parentage.current
        == ProcessParentReference(parent.hostname, parent.object_id, parent.pid, parent.started_at)
    )
    assert child.parentage.original != parent.parentage.original
    builder = state.begin_action_cohort_materialization()
    after = builder.execute_process(
        child,
        image="/bin/echo",
        command_line="echo example",
        executed_at=_START + timedelta(seconds=3),
    )
    state.materialize_action_cohort(builder.seal())
    assert after.parentage == child.parentage
    assert state.get_process_identity(child.hostname, child.pid).parentage == child.parentage
    restored = StateManager()
    _restore_head(restored, _capture_head(state))
    assert restored.get_process_identity(child.hostname, child.pid) == after


def test_parent_reference_survives_parent_exit_and_numeric_pid_reuse() -> None:
    state, root = _root()
    parent = _fork(state, root, 1)
    child = _fork(state, parent, 2)
    _close(state, parent, 3)
    replacement = state.plan_process_materialization(
        system=root.hostname,
        parent_pid=root.pid,
        fixed_pid=parent.pid,
        image="/bin/true",
        command_line="true",
        username="root",
        integrity_level="System",
        os_category="macos",
        start_time=_START + timedelta(seconds=4),
    )
    state.materialize_process(replacement)
    observed = state.get_process_identity(child.hostname, child.pid)
    assert observed.parentage.original.object_id == parent.object_id
    assert observed.parentage.original.object_id != replacement.identity.object_id
    assert observed.parentage.original_pid == replacement.identity.pid
    # This primitive preserves facts; automatic orphan adoption is a separate owner.
    assert observed.parentage.current == observed.parentage.original


@pytest.mark.parametrize("record", ["identity", "process"])
def test_previous_record_restores_unknown_parentage_without_numeric_inference(record: str) -> None:
    state, root = _root()
    child = _fork(state, root, 1)
    value = child if record == "identity" else state.get_process(child.hostname, child.pid)
    encoded = encode_state_value(value)
    assert encoded[1] == ("process-identity-v10" if record == "identity" else "running-process-v15")
    encoded[1] = "process-identity-v7" if record == "identity" else "running-process-v11"
    encoded[2] = encoded[2][: 20 if record == "identity" else 35]
    restored = decode_state_value(encoded)
    assert restored.parentage is None
    assert restored.parent_pid == child.parent_pid


@pytest.mark.parametrize("damage", ["host", "self", "pid", "future"])
def test_invalid_parentage_cannot_be_attached_to_an_identity(damage: str) -> None:
    state, root = _root()
    child = _fork(state, root, 1)
    reference = child.parentage.original
    if damage == "host":
        reference = replace(reference, hostname="other-host")
    elif damage == "self":
        reference = replace(reference, object_id=child.object_id)
    elif damage == "pid":
        reference = replace(reference, pid=reference.pid + 1)
    else:
        reference = replace(reference, started_at=child.started_at + timedelta(seconds=1))
    with pytest.raises(ValueError):
        replace(child, parentage=ProcessParentage(reference, reference))


@pytest.mark.parametrize("pid", [True, False, 0, -1, 2**31])
def test_parent_reference_requires_a_real_positive_pid(pid: object) -> None:
    with pytest.raises(ValueError):
        ProcessParentReference("synthetic-host", "synthetic-parent", pid, _START)


def test_lifecycle_bootstrap_rejects_a_reused_parent_pid() -> None:
    state, root = _root()
    parent = _fork(state, root, 1)
    child = _fork(state, parent, 2)
    _close(state, parent, 3)
    replacement = state.plan_process_materialization(
        system=root.hostname,
        parent_pid=root.pid,
        fixed_pid=parent.pid,
        image="/bin/true",
        command_line="true",
        username="root",
        integrity_level="System",
        os_category="macos",
        start_time=_START + timedelta(seconds=4),
    )
    state.materialize_process(replacement)
    registry = LifecycleRegistry()
    shadow = LifecycleShadow(state, registry)
    with pytest.raises(StateError, match="reused PID"):
        shadow.ensure_process(child, session=None)
    assert registry.get_process(child.object_id) is None
    assert registry.get_process(replacement.identity.object_id) is None


def test_exec_rollback_preserves_parent_reference_and_historical_identity() -> None:
    state, root = _root()
    child = _fork(state, root, 1)
    builder = state.begin_action_cohort_materialization()
    after = builder.execute_process(
        child, image="/bin/true", command_line="true", executed_at=_START + timedelta(seconds=2)
    )
    plan = builder.seal()
    before = state.materialization_digest()
    with state.prepared_action_cohort_materialization(plan) as prepared:
        prepared.certify_composite_commit(prepared.expected_result)
        prepared.apply_provisional()
        assert state.get_process_identity(child.hostname, child.pid).parentage == child.parentage
    assert state.materialization_digest() == before
    assert state.get_process_identity(child.hostname, child.pid) == child
    state.materialize_action_cohort(plan)
    assert state.get_process_identity_at(child.hostname, child.pid, child.started_at) == child
    assert state.get_process_identity(child.hostname, child.pid) == after


def test_checkpoint_rejects_parent_reference_conflicting_with_current_pid() -> None:
    from evidenceforge.generation.checkpoints.errors import CheckpointCorruptionError

    state, root = _root()
    child = _fork(state, root, 1)
    state.get_process(child.hostname, child.pid).parentage = ProcessParentage(None, None)
    restored = StateManager()
    before = restored.materialization_digest()
    with pytest.raises(CheckpointCorruptionError, match="parent"):
        _restore_head(restored, _capture_head(state))
    assert restored.materialization_digest() == before


def test_fork_projection_rejects_another_parent_incarnation() -> None:
    from evidenceforge.events.contexts import HostContext
    from evidenceforge.generation.actions.posix_process import process_fork_occurrence

    state, root = _root()
    child = _fork(state, root, 1)
    other = replace(child.parentage.original, object_id="another-incarnation")
    with pytest.raises(ValueError, match="fork"):
        process_fork_occurrence(
            host=HostContext(
                hostname=root.hostname,
                ip="192.0.2.1",
                os="macOS 26",
                os_category="macos",
                system_type="workstation",
            ),
            parent=root,
            child=replace(child, parentage=ProcessParentage(other, other)),
            integrity_level="System",
        )


def test_parent_reference_uses_bounded_canonical_batch_payload() -> None:
    from evidenceforge.generation.lifecycle_authority import (
        _canonical_materialization_batch_payload_bytes,
        _process_identity_payload,
    )

    state, root = _root()
    child = _fork(state, root, 1)
    payload = _process_identity_payload(child)
    assert (
        "process-parentage-v1",
        (root.hostname, root.object_id, root.pid, root.started_at),
        (root.hostname, root.object_id, root.pid, root.started_at),
    ) in payload
    assert _canonical_materialization_batch_payload_bytes(payload)
    assert _process_identity_payload(replace(child, parentage=None)) != payload


def test_registered_lifecycle_rejects_substituted_original_parent() -> None:
    state, root = _root()
    child = _fork(state, root, 1)
    registry = LifecycleRegistry()
    shadow = LifecycleShadow(state, registry)
    registered = shadow.ensure_process(child, session=None)
    replacement = replace(child.parentage.original, object_id="another-parent")
    forged = replace(child, parentage=ProcessParentage(replacement, replacement))
    with pytest.raises(StateError, match="original parent"):
        shadow.ensure_process(forged, session=None)
    assert registry.get_process(child.object_id).identity == registered
