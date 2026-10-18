# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Source observations freeze exact parent execution rather than mutable PID lookup."""

from dataclasses import replace
from datetime import timedelta

import pytest

from evidenceforge.events.process_observation import ProcessParentObservation
from evidenceforge.generation.checkpoints.state_manager_head import _capture_head, _restore_head
from evidenceforge.generation.state_manager import StateManager
from evidenceforge.models.exceptions import StateError
from tests.unit.test_posix_job_control import _START, _fork, _root


def test_parent_observation_freezes_parent_image_credentials_and_audit_version() -> None:
    state, root = _root()
    parent = _fork(state, root, 1)
    child = _fork(state, parent, 2)
    before = state.observe_process_parent(child, observed_at=_START + timedelta(seconds=3))
    builder = state.begin_action_cohort_materialization()
    after = builder.execute_process(
        parent,
        image="/usr/bin/id",
        command_line="id",
        credentials=replace(parent.credentials, effective_uid=501),
        executed_at=_START + timedelta(seconds=4),
    )
    state.materialize_action_cohort(builder.seal())
    observed = state.observe_process_parent(child, observed_at=_START + timedelta(seconds=5))
    assert before.parent == parent
    assert observed.parent == after
    assert before.parent.credentials.effective_uid == 0
    assert observed.parent.credentials.effective_uid == 501
    assert observed.parent.audit_pid_version != before.parent.audit_pid_version
    assert state.observe_process_parent(child, observed_at=before.observed_at) == before
    restored = StateManager()
    _restore_head(restored, _capture_head(state))
    assert restored.observe_process_parent(child, observed_at=observed.observed_at) == observed
    assert restored.observe_process_parent(child, observed_at=before.observed_at) == before


def test_adoption_observations_keep_original_parent_and_capture_new_parent() -> None:
    state, root = _root()
    parent = _fork(state, root, 1)
    child = _fork(state, parent, 2)
    before = state.observe_process_parent(child, observed_at=_START + timedelta(seconds=2))
    builder = state.begin_action_cohort_materialization()
    after = builder.adopt_process_after_parent_exit(
        child, adopter=root, changed_at=_START + timedelta(seconds=3)
    )
    builder.terminate_process(parent, end_time=_START + timedelta(seconds=3))
    state.materialize_action_cohort(builder.seal())
    observation = state.observe_process_parent(after, observed_at=_START + timedelta(seconds=3))
    assert observation.parent == root
    assert observation.process.parentage.original == before.process.parentage.original
    assert before.parent == parent
    assert state.observe_process_parent(child, observed_at=before.observed_at) == before
    with pytest.raises(StateError, match="stale"):
        state.observe_process_parent(child, observed_at=_START + timedelta(seconds=4))


def test_explicit_root_parent_is_distinct_from_unknown_legacy_parentage() -> None:
    state, root = _root()
    observation = state.observe_process_parent(root, observed_at=root.started_at)
    assert observation.parent is None
    assert observation.process.parentage is not None
    with pytest.raises((StateError, ValueError)):
        state.observe_process_parent(replace(root, parentage=None), observed_at=root.started_at)


@pytest.mark.parametrize(
    "damage", ["other-lifetime", "future-execution", "self", "missing", "naive"]
)
def test_observation_rejects_substituted_or_unavailable_parent_facts(damage: str) -> None:
    state, root = _root()
    child = _fork(state, root, 1)
    at = _START + timedelta(seconds=2)
    parent = root
    if damage == "other-lifetime":
        parent = replace(root, object_id="other-parent", primary_thread=None)
    elif damage == "future-execution":
        parent = state.begin_action_cohort_materialization().execute_process(
            root,
            image=root.image,
            command_line=root.command_line,
            executed_at=at + timedelta(seconds=1),
        )
    elif damage == "self":
        parent = child
    elif damage == "missing":
        parent = None
    else:
        at = at.replace(tzinfo=None)
    with pytest.raises(ValueError):
        ProcessParentObservation(child, parent, at)


def test_parent_observation_rejects_inactive_child_and_parent_without_adoption() -> None:
    state, root = _root()
    parent = _fork(state, root, 1)
    child = _fork(state, parent, 2)
    with pytest.raises(StateError):
        state.observe_process_parent(child, observed_at=_START)
    # The low-level State API cannot be used to infer a missing lifecycle adoption.
    state.end_process(parent.hostname, parent.pid, end_time=_START + timedelta(seconds=3))
    with pytest.raises(StateError, match="parent history"):
        state.observe_process_parent(child, observed_at=_START + timedelta(seconds=4))


def test_reused_parent_pid_never_substitutes_for_exact_parent_history() -> None:
    state, root = _root()
    parent = _fork(state, root, 1)
    child = _fork(state, parent, 2)
    before = state.observe_process_parent(child, observed_at=child.started_at)
    state.end_process(parent.hostname, parent.pid, end_time=_START + timedelta(seconds=3))
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
    assert replacement.identity.object_id != parent.object_id
    assert state.observe_process_parent(child, observed_at=before.observed_at) == before
    with pytest.raises(StateError, match="parent history"):
        state.observe_process_parent(child, observed_at=_START + timedelta(seconds=5))


def test_native_parent_audit_projection_uses_captured_credentials_without_filling_unknowns() -> (
    None
):
    from evidenceforge.formats.macos_endpoint_security import ESAuditToken
    from tests.unit.test_process_credentials import _create

    state, parent = _create()
    child = _fork(state, parent, 1)
    observation = state.observe_process_parent(child, observed_at=child.started_at)
    token = ESAuditToken.from_process_identity(observation.parent)
    builder = state.begin_action_cohort_materialization()
    builder.execute_process(
        parent,
        image="/usr/bin/id",
        command_line="id",
        credentials=replace(parent.credentials, effective_uid=0),
        executed_at=_START + timedelta(seconds=2),
    )
    state.materialize_action_cohort(builder.seal())
    assert ESAuditToken.from_process_identity(observation.parent) == token
    assert token.euid == parent.credentials.effective_uid
    unknown_state, root = _root()
    unknown_child = _fork(unknown_state, root, 1)
    unknown = unknown_state.observe_process_parent(
        unknown_child, observed_at=unknown_child.started_at
    )
    with pytest.raises(ValueError, match="explicit credentials"):
        ESAuditToken.from_process_identity(unknown.parent)
