# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Current execution facts never rewrite process lifetime or resource ownership."""

import gc
from dataclasses import replace
from datetime import timedelta

import pytest

from evidenceforge.events.lifecycle import (
    LifecycleForegroundLease,
    LifecycleSingletonLease,
    LifecycleTransition,
    ProcessGUIAttribution,
    ProcessRuntimeChange,
    ProcessRuntimeView,
    ProcessTokenIdentity,
)
from evidenceforge.generation.checkpoints.errors import CheckpointCorruptionError
from evidenceforge.generation.checkpoints.lifecycle_head import _capture, _restore
from evidenceforge.generation.checkpoints.packed import dumps, loads
from evidenceforge.generation.lifecycle_registry import (
    LifecycleActionCohortRequest,
    LifecycleRegistry,
)
from evidenceforge.models.exceptions import StateError
from tests.unit.test_lifecycle_action_cohort import _START, _process_request, _session_request


def _register_live_tree(registry: LifecycleRegistry) -> None:
    session = _session_request()
    registry.register_session(
        session.identity, action_id=session.action_id, transition_id=session.transition_id
    )
    child = _process_request(
        object_id="child-1", pid=5104, started_at=_START + timedelta(seconds=2), session=session
    )
    registry.register_process(
        child.identity,
        token=replace(child.token, principal="root"),
        membership=child.membership,
        action_id=child.action_id,
        transition_id=child.transition_id,
    )


def _change(
    registry: LifecycleRegistry, *, seconds: int = 3, credentials: bool = False
) -> LifecycleTransition:
    snapshot = registry.get_process("child-1")
    assert snapshot is not None
    before = snapshot.current_view
    after = replace(
        before,
        revision=before.revision + 1,
        changed_at=_START + timedelta(seconds=seconds),
        execution_ordinal=before.execution_ordinal + (not credentials),
        image=before.image if credentials else "/bin/zsh",
        role=before.role if credentials else "shell",
        token=replace(before.token, principal="analyst") if credentials else before.token,
    )
    return LifecycleTransition(
        transition_id=f"change-{after.revision}",
        subject=snapshot.identity.ref,
        kind="dependent",
        canonical_time=after.changed_at,
        action_id=f"action-{after.revision}",
        process_change=ProcessRuntimeChange(
            before, after, "credentials" if credentials else "exec"
        ),
    )


def _request(*changes: LifecycleTransition) -> LifecycleActionCohortRequest:
    return LifecycleActionCohortRequest(
        state_publication_token="state-proof",
        operations=changes,
    )


def _commit(registry: LifecycleRegistry, *changes: LifecycleTransition) -> None:
    request = _request(*changes)
    token = registry.prepare_action_cohort(request)
    with registry.claimed_action_cohort(token) as prepared:
        receipt = prepared.commit_no_fail()
    assert registry.authenticates_action_cohort_receipt(
        receipt, request=request, state_publication_token=request.state_publication_token
    )
    del receipt, prepared, token
    gc.collect()
    registry.prune_action_cohort_receipt_authorities()


def test_exec_then_credentials_preserve_lifetime_and_exact_receipt() -> None:
    registry = LifecycleRegistry()
    _register_live_tree(registry)
    initial = registry.get_process("child-1")
    execute = _change(registry)
    _commit(registry, execute)
    credentials = _change(registry, seconds=4, credentials=True)
    _commit(registry, credentials)
    current = registry.get_process("child-1")
    assert current.identity == initial.identity
    assert current.token == initial.token
    assert current.membership == initial.membership
    assert current.current_view == credentials.process_change.after
    assert current.current_view.execution_ordinal == 1
    assert current.current_view.revision == 2
    assert initial.runtime_view is None
    assert current.transitions[-2:] == (execute, credentials)


def test_preparation_cancel_and_stale_before_view_do_not_mutate_registry() -> None:
    registry = LifecycleRegistry()
    _register_live_tree(registry)
    before = _capture(registry)
    change = _change(registry)
    token = registry.prepare_action_cohort(_request(change))
    assert registry.get_process("child-1").runtime_view is None
    registry.cancel_action_cohort(token)
    del token
    assert _capture(registry) == before
    _commit(registry, change)
    stale = replace(change, action_id="stale", transition_id="stale")
    after = _capture(registry)
    with pytest.raises(StateError, match="exact current view"):
        registry.prepare_action_cohort(_request(stale))
    assert _capture(registry) == after


def test_runtime_transition_rejects_time_before_dependent_frontier() -> None:
    registry = LifecycleRegistry()
    _register_live_tree(registry)
    registry.record_dependent(
        registry.get_process("child-1").identity.ref,
        transition_id="later",
        canonical_time=_START + timedelta(seconds=4),
        action_id="later",
    )
    with pytest.raises(StateError, match="precedes dependent"):
        registry.prepare_action_cohort(_request(_change(registry)))


def _lease(registry: LifecycleRegistry) -> LifecycleForegroundLease:
    snapshot = registry.get_process("child-1")
    return LifecycleForegroundLease(
        lease_id="foreground",
        hostname=snapshot.identity.hostname,
        principal=snapshot.current_view.token.principal,
        session_object_id=snapshot.membership.session_object_id,
        process_object_id=snapshot.identity.object_id,
        acquired_at=_START + timedelta(seconds=5),
        lease_until=_START + timedelta(seconds=10),
        action_id="foreground-action",
    )


def test_foreground_admission_uses_current_shell_and_principal_and_blocks_changes() -> None:
    registry = LifecycleRegistry()
    _register_live_tree(registry)
    _commit(registry, _change(registry))
    _commit(registry, _change(registry, seconds=4, credentials=True))
    lease = _lease(registry)
    with pytest.raises(StateError, match="principal"):
        registry.acquire_foreground_lease(replace(lease, principal="root"))
    registry.acquire_foreground_lease(lease)
    with pytest.raises(StateError, match="lease release"):
        registry.prepare_action_cohort(_request(_change(registry, seconds=6)))
    restored = LifecycleRegistry()
    _restore(restored, _capture(registry))
    assert restored.get_process("child-1") == registry.get_process("child-1")
    assert restored.foreground_lease_for(*lease.resource_key) == lease


def test_reserved_runtime_change_fences_concurrent_lease_admission() -> None:
    registry = LifecycleRegistry()
    _register_live_tree(registry)
    _commit(registry, _change(registry))
    _commit(registry, _change(registry, seconds=4, credentials=True))
    token = registry.prepare_action_cohort(_request(_change(registry, seconds=6)))
    with pytest.raises(StateError):
        registry.acquire_foreground_lease(_lease(registry))
    registry.cancel_action_cohort(token)
    registry.acquire_foreground_lease(_lease(registry))


def test_runtime_frontier_survives_detail_compaction_and_checkpoint() -> None:
    registry = LifecycleRegistry(ledger_detail_retention=timedelta(seconds=1))
    _register_live_tree(registry)
    change = _change(registry)
    _commit(registry, change)
    registry.advance_watermark(_START + timedelta(seconds=10))
    before = registry.get_process("child-1")
    assert change not in before.transitions
    assert before.current_view == change.process_change.after
    restored = LifecycleRegistry()
    _restore(restored, _capture(registry))
    assert restored.get_process("child-1") == before
    _commit(restored, _change(restored, seconds=11, credentials=True))
    assert restored.get_process("child-1").current_view.revision == 2


@pytest.mark.parametrize("damage", [None, "missing", "origin", "time", "revision", "legacy"])
def test_gui_account_frontier_survives_compaction_and_rejects_changed_proof(
    damage: str | None,
) -> None:
    registry = LifecycleRegistry(ledger_detail_retention=timedelta(seconds=1))
    root_token = ProcessTokenIdentity("root", integrity_level="System")
    for object_id, pid, parent in (("boot", 1, ""), ("child-1", 5104, "boot")):
        request = _process_request(
            object_id=object_id, pid=pid, started_at=_START, parent_object_id=parent
        )
        registry.register_process(
            replace(request.identity, image="/sbin/launchd"),
            token=root_token,
            membership=request.membership,
            action_id=request.action_id,
            transition_id=request.transition_id,
        )
    before = registry.get_process("child-1").current_view
    launcher = replace(
        before,
        revision=1,
        execution_ordinal=1,
        changed_at=_START + timedelta(seconds=2),
        image="/usr/libexec/xpcproxy",
    )
    gui_token = ProcessTokenIdentity("analyst", "gui-login", 0, 2, "Medium")
    at = _START + timedelta(seconds=3)
    bound = replace(
        launcher,
        revision=2,
        changed_at=at,
        token=gui_token,
        gui_attribution=ProcessGUIAttribution(root_token, gui_token, at, 2),
    )
    app = replace(
        bound,
        revision=3,
        execution_ordinal=2,
        changed_at=_START + timedelta(seconds=4),
        image="/Applications/Invented.app/Contents/MacOS/Invented",
    )
    for old, new, kind in (
        (before, launcher, "exec"),
        (launcher, bound, "gui_credentials"),
        (bound, app, "exec"),
    ):
        _commit(
            registry,
            LifecycleTransition(
                transition_id=f"gui-{new.revision}",
                subject=registry.get_process("child-1").identity.ref,
                kind="dependent",
                canonical_time=new.changed_at,
                action_id=f"gui-action-{new.revision}",
                process_change=ProcessRuntimeChange(old, new, kind),
            ),
        )
    registry.advance_watermark(_START + timedelta(seconds=10))
    snapshot = registry.get_process("child-1")
    assert not snapshot.transitions and snapshot.current_view == app
    document = loads(_capture(registry))
    runtime = next(
        row[4]
        for partition in document["partitions"]
        for row in partition[0]
        if row[0][1] == "child-1"
    )
    if damage == "legacy":
        document["schema_version"] = "8"
    elif damage == "missing":
        runtime.pop()
    elif damage == "origin":
        runtime[6][0][1] = "foreign-logon"
    elif damage == "time":
        runtime[6][2] = (_START - timedelta(seconds=1)).isoformat()
    elif damage == "revision":
        runtime[6][3] = 5
    restored = LifecycleRegistry()
    if damage is not None:
        with pytest.raises(CheckpointCorruptionError):
            _restore(restored, dumps(document))
        assert restored.get_process("child-1") is None
    else:
        _restore(restored, dumps(document))
        assert restored.get_process("child-1") == snapshot


@pytest.mark.parametrize("field,value", [(0, 0), (0, 500), (1, 500), (2, _START.isoformat())])
def test_corrupt_runtime_frontier_is_rejected_without_mutating_restore_target(
    field: int, value: object
) -> None:
    registry = LifecycleRegistry()
    _register_live_tree(registry)
    _commit(registry, _change(registry))
    document = loads(_capture(registry))
    for partition in document["partitions"]:
        for row in partition[0]:
            if row[0][1] == "child-1":
                row[4][field] = value
    restored = LifecycleRegistry()
    with pytest.raises(CheckpointCorruptionError):
        _restore(restored, dumps(document))
    assert restored.get_process("child-1") is None


@pytest.mark.parametrize(
    "mutation",
    [
        {"revision": 2},
        {"execution_ordinal": 2},
        {"changed_at": _START},
        {"token": "wrong"},
        {"role": ""},
    ],
)
def test_runtime_change_rejects_invalid_views(mutation: dict[str, object]) -> None:
    registry = LifecycleRegistry()
    _register_live_tree(registry)
    change = _change(registry).process_change
    with pytest.raises((ValueError, TypeError)):
        ProcessRuntimeChange(change.before, replace(change.after, **mutation), "exec")


def test_runtime_change_cannot_reassign_authentication_or_hide_exec_as_credentials() -> None:
    registry = LifecycleRegistry()
    _register_live_tree(registry)
    change = _change(registry).process_change
    with pytest.raises(ValueError, match="authentication"):
        ProcessRuntimeChange(
            change.before,
            replace(change.after, token=replace(change.after.token, logon_id="other")),
            "exec",
        )
    with pytest.raises(ValueError, match="preserve execution"):
        ProcessRuntimeChange(change.before, change.after, "credentials")
    with pytest.raises(ValueError):
        replace(_change(registry), canonical_time=_START)
    assert isinstance(change.before, ProcessRuntimeView)


def test_multiple_runtime_changes_in_one_cohort_use_exact_staged_views() -> None:
    registry = LifecycleRegistry()
    _register_live_tree(registry)
    first = _change(registry)
    before = first.process_change.after
    after = replace(
        before,
        revision=2,
        changed_at=_START + timedelta(seconds=4),
        token=replace(before.token, principal="analyst"),
    )
    second = replace(
        first,
        transition_id="second",
        action_id="second",
        canonical_time=after.changed_at,
        process_change=ProcessRuntimeChange(before, after, "credentials"),
    )
    _commit(registry, first, second)
    assert registry.get_process("child-1").current_view == after
    restored = LifecycleRegistry()
    _restore(restored, _capture(registry))
    assert restored.get_process("child-1") == registry.get_process("child-1")


def test_runtime_change_is_bound_to_exact_authenticated_request() -> None:
    registry = LifecycleRegistry()
    _register_live_tree(registry)
    change = _change(registry)
    request = _request(change)
    token = registry.prepare_action_cohort(request)
    altered = replace(
        change,
        process_change=replace(
            change.process_change, after=replace(change.process_change.after, image="/bin/sh")
        ),
    )
    assert not registry.authenticates_action_cohort_admission_token(
        token, request=_request(altered), state_publication_token=request.state_publication_token
    )
    registry.cancel_action_cohort(token)


def test_current_view_cannot_retroactively_own_foreground_activity() -> None:
    registry = LifecycleRegistry()
    _register_live_tree(registry)
    _commit(registry, _change(registry))
    _commit(registry, _change(registry, seconds=4, credentials=True))
    with pytest.raises(StateError, match="precedes the current"):
        registry.acquire_foreground_lease(
            replace(_lease(registry), acquired_at=_START + timedelta(seconds=3))
        )


def test_missing_durable_view_and_altered_retained_history_fail_restore() -> None:
    registry = LifecycleRegistry()
    _register_live_tree(registry)
    _commit(registry, _change(registry))
    for mutation in ("missing", "history"):
        document = loads(_capture(registry))
        for partition in document["partitions"]:
            for row in partition[0]:
                if row[0][1] != "child-1":
                    continue
                if mutation == "missing":
                    row.pop()
                else:
                    row[3][0][-1][7][2][3] = "/bin/different"
        with pytest.raises(CheckpointCorruptionError):
            _restore(LifecycleRegistry(), dumps(document))


def test_process_change_cannot_be_restored_as_session_activity() -> None:
    registry = LifecycleRegistry()
    _register_live_tree(registry)
    _commit(registry, _change(registry))
    document = loads(_capture(registry))
    change = next(
        row[3][0][-1]
        for partition in document["partitions"]
        for row in partition[0]
        if row[0][1] == "child-1"
    )
    session_row = next(row for partition in document["partitions"] for row in partition[1])
    session_row[1][0].append(change)
    session_row[1][5] += 1
    with pytest.raises(CheckpointCorruptionError, match="non-process owner"):
        _restore(LifecycleRegistry(), dumps(document))


def test_singleton_lease_uses_current_image_and_requires_release_before_next_exec() -> None:
    registry = LifecycleRegistry()
    _register_live_tree(registry)
    _commit(registry, _change(registry))
    _commit(registry, _change(registry, seconds=4, credentials=True))
    snapshot = registry.get_process("child-1")
    lease = LifecycleSingletonLease(
        lease_id="singleton",
        hostname=snapshot.identity.hostname,
        principal=snapshot.current_view.token.principal,
        session_object_id=snapshot.membership.session_object_id,
        logon_id=snapshot.token.logon_id,
        canonical_image=snapshot.current_view.image,
        process_object_id=snapshot.identity.object_id,
        acquired_at=_START + timedelta(seconds=5),
        lease_until=_START + timedelta(seconds=10),
        action_id="singleton",
    )
    with pytest.raises(StateError, match="image disagrees"):
        registry.acquire_singleton_lease(replace(lease, canonical_image=snapshot.identity.image))
    registry.acquire_singleton_lease(lease)
    restored = LifecycleRegistry()
    _restore(restored, _capture(registry))
    assert restored.singleton_lease(lease.lease_id) == lease
    with pytest.raises(StateError, match="lease release"):
        restored.prepare_action_cohort(_request(_change(restored, seconds=6)))
    assert restored.release_singleton_lease(
        lease.lease_id, released_at=_START + timedelta(seconds=6), action_id="release"
    )
    _commit(restored, _change(restored, seconds=7))
    assert restored.get_process("child-1").current_view.execution_ordinal == 2
