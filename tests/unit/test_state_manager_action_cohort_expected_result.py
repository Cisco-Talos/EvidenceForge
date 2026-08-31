# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Public expected-result and rollback contracts for StateManager action cohorts."""

import random
from concurrent.futures import ThreadPoolExecutor
from copy import copy
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from threading import Event

import pytest

import evidenceforge.generation.state_manager as state_manager_module
from evidenceforge.events.network import (
    DirectionalTrafficLedger,
    NetworkTrafficLedger,
    NetworkTransactionPlan,
)
from evidenceforge.generation.state_manager import (
    ActionCohortMaterializationPlan,
    ActionCohortMaterializationResult,
    ConnectionCompositeMaterializationPlan,
    ConnectionMaterializationPlan,
    StateManager,
)
from evidenceforge.models.exceptions import StateError

_START = datetime(2026, 8, 17, 16, 0, tzinfo=UTC)


def _closed_cohort(manager: StateManager) -> ActionCohortMaterializationPlan:
    builder = manager.begin_action_cohort_materialization()
    session = builder.plan_session(
        username="analyst",
        system="WS-01",
        logon_type=9,
        source_ip="127.0.0.1",
        session_kind="new_credentials",
        start_time=_START,
        logon_guid_required=True,
    )
    parent = builder.plan_process(
        system="WS-01",
        parent_pid=4,
        image=r"C:\Windows\System32\runas.exe",
        command_line=r"runas.exe /netonly /user:EXAMPLE\admin cmd.exe",
        username="analyst",
        integrity_level="Medium",
        os_category="windows",
        logon_id=session.identity.logon_id,
        start_time=_START + timedelta(seconds=1),
        require_session=True,
        session_plan=session,
    )
    child = builder.plan_process(
        system="WS-01",
        parent_pid=parent.identity.pid,
        image=r"C:\Windows\System32\cmd.exe",
        command_line="cmd.exe /c whoami",
        username="analyst",
        integrity_level="Medium",
        os_category="windows",
        logon_id=session.identity.logon_id,
        start_time=_START + timedelta(seconds=2),
        require_session=True,
        parent_plan=parent,
        session_plan=session,
    )
    builder.patch_process_activity(parent, _START + timedelta(seconds=4))
    builder.patch_session_activity(session, _START + timedelta(seconds=4))
    builder.terminate_process(
        child,
        end_time=_START + timedelta(seconds=3),
        parent_activity_time=_START + timedelta(seconds=3),
    )
    builder.terminate_process(parent, end_time=_START + timedelta(seconds=4))
    builder.terminalize_session(session, end_time=_START + timedelta(seconds=5))
    return builder.seal()


def _manager_and_plan() -> tuple[StateManager, ActionCohortMaterializationPlan]:
    manager = StateManager()
    manager.set_current_time(_START)
    return manager, _closed_cohort(manager)


def _manager_and_live_process_plan() -> tuple[
    StateManager,
    int,
    ActionCohortMaterializationPlan,
]:
    manager = StateManager()
    manager.set_current_time(_START)
    pid = manager.create_process(
        system="WS-01",
        parent_pid=4,
        image=r"C:\Windows\System32\services.exe",
        command_line="services.exe",
        username="SYSTEM",
        integrity_level="System",
    )
    identity = manager.get_process_identity("WS-01", pid)
    assert identity is not None
    builder = manager.begin_action_cohort_materialization()
    builder.patch_process_activity(identity, _START + timedelta(seconds=5))
    return manager, pid, builder.seal()


def _connection_transaction(conn_id: str, zeek_uid: str) -> NetworkTransactionPlan:
    closed_at = _START + timedelta(seconds=1)
    return NetworkTransactionPlan(
        stable_id="lane-regression",
        hostname="example.test",
        outcome="success",
        phase_times=(("transport_start", _START), ("transport_close", closed_at)),
        started_at=_START,
        closed_at=closed_at,
        src_ip="10.0.0.10",
        src_port=50_001,
        dst_ip="10.0.0.20",
        dst_port=443,
        protocol="tcp",
        service="https",
        zeek_uid=zeek_uid,
        conn_id=conn_id,
        duration=1.0,
        conn_state="SF",
        history="ShADadFf",
        traffic=NetworkTrafficLedger(
            orig=DirectionalTrafficLedger(payload_bytes=120, packets=2, ip_bytes=200),
            resp=DirectionalTrafficLedger(payload_bytes=480, packets=3, ip_bytes=600),
        ),
    )


def _connection_plan(
    manager: StateManager,
    owner_rng: random.Random,
) -> tuple[str, ConnectionMaterializationPlan]:
    identity = manager.plan_connection_identity(owner_rng)
    return identity.conn_id, manager.finalize_connection_materialization(
        identity,
        _connection_transaction(identity.conn_id, identity.zeek_uid),
        continuation_rng=identity.continuation_rng(),
    )


def _connection_composite_plan(
    manager: StateManager,
    owner_rng: random.Random,
) -> tuple[str, ConnectionCompositeMaterializationPlan]:
    cursor = manager.begin_connection_planning(owner_rng)
    identity = cursor.reserve_identity()
    return identity.conn_id, manager.finalize_connection_composite_materialization(
        cursor,
        _connection_transaction(identity.conn_id, identity.zeek_uid),
    )


def _assert_exact_result_projection(
    result: ActionCohortMaterializationResult,
    plan: ActionCohortMaterializationPlan,
) -> None:
    assert result.semantic_id == plan.semantic_id
    assert result.prior_version == plan.expected_version
    assert result.committed_version == plan.expected_version + 1
    assert result.started_sessions == tuple(item.identity for item in plan.sessions)
    assert result.started_processes == tuple(item.identity for item in plan.processes)
    assert result.terminated_processes == tuple(item.identity for item in plan.process_terminations)
    assert result.terminalized_sessions == tuple(
        item.identity for item in plan.session_terminalizations
    )


def test_claim_authenticates_and_returns_its_exact_precomputed_result() -> None:
    manager, plan = _manager_and_plan()
    digest = manager.materialization_digest()
    version = manager.materialization_version

    with manager.prepared_action_cohort_materialization(plan) as preparation:
        expected = preparation.expected_result
        token = preparation.expected_result_publication_token
        assert type(token) is str
        assert len(token) == 64
        assert preparation.expected_result_publication_token is token
        _assert_exact_result_projection(expected, plan)
        assert manager.authenticates_expected_action_cohort_result(
            expected,
            preparation=preparation,
        )
        assert manager.materialization_digest() == digest

        preparation.certify_composite_commit(expected)
        result = preparation.commit_no_fail()
        assert result is expected
        assert preparation.expected_result is expected
        assert preparation.committed

    assert manager.materialization_version == version + 1
    assert manager.state.current_time == _START + timedelta(seconds=5)
    with pytest.raises(StateError, match="no longer active"):
        _ = preparation.expected_result_publication_token


def test_provisional_apply_rolls_back_when_a_later_owner_fails() -> None:
    class LaterOwnerAbort(BaseException):
        pass

    manager, plan = _manager_and_plan()
    digest = manager.materialization_digest()
    version = manager.materialization_version

    with pytest.raises(LaterOwnerAbort, match="later owner"):
        with manager.prepared_action_cohort_materialization(plan) as preparation:
            expected = preparation.expected_result
            preparation.certify_composite_commit(expected)
            preparation.apply_provisional()
            assert manager.materialization_version == version + 1
            assert manager.materialization_digest() != digest
            raise LaterOwnerAbort("later owner publication failed")

    assert manager.materialization_digest() == digest
    assert manager.materialization_version == version
    assert manager._active_action_cohort_preparations == {}
    assert not preparation.committed


def test_later_owner_primary_survives_cleanup_observation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class LaterOwnerAbort(BaseException):
        pass

    class CleanupObservation(BaseException):
        pass

    manager, plan = _manager_and_plan()
    digest = manager.materialization_digest()
    original = StateManager._restore_action_cohort_rollback_journal

    def restore_then_observe(target: StateManager, journal: object) -> None:
        original(target, journal)  # type: ignore[arg-type]
        raise CleanupObservation("cleanup observer raised after restoration")

    with pytest.raises(LaterOwnerAbort) as caught:
        with manager.prepared_action_cohort_materialization(plan) as preparation:
            expected = preparation.expected_result
            preparation.certify_composite_commit(expected)
            preparation.apply_provisional()
            monkeypatch.setattr(
                StateManager,
                "_restore_action_cohort_rollback_journal",
                restore_then_observe,
            )
            raise LaterOwnerAbort()

    assert any("CleanupObservation" in note for note in caught.value.__notes__)
    assert manager.materialization_digest() == digest
    assert manager._active_action_cohort_preparations == {}


def test_provisional_finalize_is_identity_return_terminal_only() -> None:
    manager, plan = _manager_and_plan()

    with manager.prepared_action_cohort_materialization(plan) as preparation:
        expected = preparation.expected_result
        with pytest.raises(StateError, match="composite-certified"):
            preparation.apply_provisional()
        preparation.certify_composite_commit(expected)
        with pytest.raises(StateError, match="not provisionally applied"):
            preparation.finalize_no_fail()
        preparation.apply_provisional()
        result = preparation.finalize_no_fail()
        assert result is expected
        assert preparation.committed
        with pytest.raises(StateError, match="already committed"):
            preparation.finalize_no_fail()

    assert manager._active_action_cohort_preparations == {}


def test_expected_result_authenticator_rejects_copies_foreign_and_wrong_thread() -> None:
    manager, plan = _manager_and_plan()
    foreign = StateManager()

    with manager.prepared_action_cohort_materialization(plan) as preparation:
        expected = preparation.expected_result
        copied_preparation = copy(preparation)
        copied_result = replace(expected)
        assert not manager.authenticates_expected_action_cohort_result(
            expected,
            preparation=copied_preparation,
        )
        assert not manager.authenticates_expected_action_cohort_result(
            copied_result,
            preparation=preparation,
        )
        assert not foreign.authenticates_expected_action_cohort_result(
            expected,
            preparation=preparation,
        )

        with ThreadPoolExecutor(max_workers=1) as executor:
            authenticated = executor.submit(
                manager.authenticates_expected_action_cohort_result,
                expected,
                preparation=preparation,
            ).result()
            accessed = executor.submit(lambda: preparation.expected_result)
            certified = executor.submit(preparation.certify_composite_commit, expected)
        assert not authenticated
        with pytest.raises(StateError, match="claiming thread"):
            accessed.result()
        with pytest.raises(StateError, match="claiming thread"):
            certified.result()

        with pytest.raises(StateError, match="authentication"):
            preparation.certify_composite_commit(copied_result)
        preparation.certify_composite_commit(expected)
        with pytest.raises(StateError, match="already composite-certified"):
            preparation.certify_composite_commit(expected)


@pytest.mark.parametrize("certified", (False, True))
def test_shallow_copied_capability_cannot_commit_exact_owner_claim(certified: bool) -> None:
    manager, plan = _manager_and_plan()
    digest = manager.materialization_digest()

    with manager.prepared_action_cohort_materialization(plan) as preparation:
        expected = preparation.expected_result
        if certified:
            preparation.certify_composite_commit(expected)
        copied = copy(preparation)
        with pytest.raises(StateError, match="no longer active"):
            copied.commit_no_fail()
        assert manager.materialization_digest() == digest
        if not certified:
            preparation.certify_composite_commit(expected)
        assert preparation.commit_no_fail() is expected


def test_active_claim_rejects_versioned_process_creation_before_apply() -> None:
    manager, plan = _manager_and_plan()
    digest = manager.materialization_digest()
    version = manager.materialization_version

    with manager.prepared_action_cohort_materialization(plan) as preparation:
        expected = preparation.expected_result
        preparation.certify_composite_commit(expected)
        with pytest.raises(StateError, match="active action-cohort claim"):
            manager.create_process(
                system="WS-01",
                parent_pid=4,
                image=r"C:\Windows\System32\notepad.exe",
                command_line="notepad.exe",
                username="analyst",
                integrity_level="Medium",
            )
        assert manager.materialization_digest() == digest
        assert manager.materialization_version == version
        preparation.apply_provisional()
        preparation.finalize_no_fail()


def test_active_claim_rejects_unversioned_process_activity_update() -> None:
    manager = StateManager()
    manager.set_current_time(_START)
    pid = manager.create_process(
        system="WS-01",
        parent_pid=4,
        image=r"C:\Windows\System32\services.exe",
        command_line="services.exe",
        username="SYSTEM",
        integrity_level="System",
    )
    plan = _closed_cohort(manager)
    before = manager.get_process("WS-01", pid)
    assert before is not None
    assert before.last_activity_time is None

    with manager.prepared_action_cohort_materialization(plan):
        with pytest.raises(StateError, match="active action-cohort claim"):
            manager.update_process_activity_time(
                "WS-01",
                pid,
                _START + timedelta(seconds=10),
            )
        current = manager.get_process("WS-01", pid)
        assert current is before
        assert current.last_activity_time is None


def test_active_claim_promptly_rejects_cross_thread_public_mutations() -> None:
    manager = StateManager()
    manager.set_current_time(_START)
    pid = manager.create_process(
        system="WS-01",
        parent_pid=4,
        image=r"C:\Windows\System32\services.exe",
        command_line="services.exe",
        username="SYSTEM",
        integrity_level="System",
    )
    plan = _closed_cohort(manager)
    process = manager.get_process("WS-01", pid)
    assert process is not None

    executor = ThreadPoolExecutor(max_workers=2)
    try:
        with manager.prepared_action_cohort_materialization(plan):
            created = executor.submit(
                manager.create_process,
                system="WS-01",
                parent_pid=4,
                image=r"C:\Windows\System32\notepad.exe",
                command_line="notepad.exe",
                username="analyst",
                integrity_level="Medium",
            )
            updated = executor.submit(
                manager.update_process_activity_time,
                "WS-01",
                pid,
                _START + timedelta(seconds=10),
            )
            with pytest.raises(StateError, match="active action-cohort claim"):
                created.result(timeout=2)
            with pytest.raises(StateError, match="active action-cohort claim"):
                updated.result(timeout=2)

            assert manager.get_current_time() == _START
            assert manager.get_process("WS-01", pid) is process
            assert process.last_activity_time is None
    finally:
        executor.shutdown(wait=True, cancel_futures=True)


def test_public_mutation_admission_rejects_a_call_that_overlaps_the_claim(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    manager, pid, plan = _manager_and_live_process_plan()
    process = manager.get_process("WS-01", pid)
    assert process is not None
    admitted = Event()
    release = Event()
    original_admit = manager._reject_mutation_during_action_cohort_claim

    def admit_with_barrier(operation: str, *, admitted_at: int | None = None) -> int:
        epoch = original_admit(operation, admitted_at=admitted_at)
        if operation == "update_process_activity_time" and admitted_at is None:
            admitted.set()
            if not release.wait(timeout=2):
                raise AssertionError("mutation admission barrier timed out")
        return epoch

    monkeypatch.setattr(
        manager,
        "_reject_mutation_during_action_cohort_claim",
        admit_with_barrier,
    )
    with ThreadPoolExecutor(max_workers=1) as executor:
        update = executor.submit(
            manager.update_process_activity_time,
            "WS-01",
            pid,
            _START + timedelta(seconds=10),
        )
        assert admitted.wait(timeout=2)
        with manager.prepared_action_cohort_materialization(plan):
            release.set()
            assert not update.done()
        with pytest.raises(StateError, match="active action-cohort claim"):
            update.result(timeout=2)

    assert process.last_activity_time is None


def test_post_apply_public_creation_rejects_and_later_owner_rollback_is_exact() -> None:
    class LaterOwnerAbort(BaseException):
        pass

    manager, plan = _manager_and_plan()
    digest = manager.materialization_digest()
    version = manager.materialization_version

    with pytest.raises(LaterOwnerAbort):
        with manager.prepared_action_cohort_materialization(plan) as preparation:
            expected = preparation.expected_result
            preparation.certify_composite_commit(expected)
            preparation.apply_provisional()
            with pytest.raises(StateError, match="active action-cohort claim"):
                manager.create_process(
                    system="WS-01",
                    parent_pid=4,
                    image=r"C:\Windows\System32\notepad.exe",
                    command_line="notepad.exe",
                    username="analyst",
                    integrity_level="Medium",
                )
            raise LaterOwnerAbort()

    assert manager.materialization_digest() == digest
    assert manager.materialization_version == version
    assert manager.list_running_processes() == []


def test_nested_action_cohort_claim_is_rejected_without_consuming_owner() -> None:
    manager, plan = _manager_and_plan()
    digest = manager.materialization_digest()

    with manager.prepared_action_cohort_materialization(plan) as preparation:
        with pytest.raises(StateError, match="already has an active"):
            with manager.prepared_action_cohort_materialization(plan):
                raise AssertionError("nested claim unexpectedly opened")
        assert manager.materialization_digest() == digest
        expected = preparation.expected_result
        preparation.certify_composite_commit(expected)
        assert preparation.commit_no_fail() is expected


def test_connection_preparation_copy_is_revoked_when_context_closes() -> None:
    manager, action_plan = _manager_and_plan()
    owner_rng = random.Random(17)
    conn_id, connection_plan = _connection_plan(manager, owner_rng)
    digest = manager.materialization_digest()
    version = manager.materialization_version
    rng_state = owner_rng.getstate()

    with manager.prepared_connection_materialization(
        connection_plan,
        owner_rng,
    ) as connection_preparation:
        copied_preparation = copy(connection_preparation)
        assert manager.materialization_digest() == digest

    for preparation in (connection_preparation, copied_preparation):
        with pytest.raises(StateError, match="no longer active"):
            preparation.commit()
    assert manager.materialization_digest() == digest
    assert manager.materialization_version == version
    assert owner_rng.getstate() == rng_state
    assert manager.get_connection(conn_id) is None
    assert manager.authenticates_action_cohort_plan(action_plan)


def test_connection_preparation_copy_cannot_replay_original_commit() -> None:
    manager = StateManager()
    manager.set_current_time(_START)
    owner_rng = random.Random(23)
    conn_id, connection_plan = _connection_plan(manager, owner_rng)

    with manager.prepared_connection_materialization(
        connection_plan,
        owner_rng,
    ) as connection_preparation:
        copied_before_commit = copy(connection_preparation)
        with pytest.raises(StateError, match="no longer active"):
            copied_before_commit.commit()
        result = connection_preparation.commit()
        assert result is manager.get_connection(conn_id)
        copied_after_commit = copy(connection_preparation)
        committed_digest = manager.materialization_digest()
        committed_version = manager.materialization_version
        committed_rng_state = owner_rng.getstate()
        with pytest.raises(StateError, match="no longer active"):
            copied_after_commit.commit()
        with pytest.raises(StateError, match="already committed"):
            connection_preparation.commit()
        assert manager.materialization_digest() == committed_digest
        assert manager.materialization_version == committed_version
        assert owner_rng.getstate() == committed_rng_state

    with pytest.raises(StateError, match="no longer active"):
        copied_after_commit.commit()
    assert manager.materialization_digest() == committed_digest
    assert manager.materialization_version == committed_version
    assert owner_rng.getstate() == committed_rng_state
    assert len(manager.list_open_connections()) == 1


def test_composite_preparation_copy_is_revoked_when_context_closes() -> None:
    manager = StateManager()
    manager.set_current_time(_START)
    owner_rng = random.Random(25)
    conn_id, composite_plan = _connection_composite_plan(manager, owner_rng)
    digest = manager.materialization_digest()
    version = manager.materialization_version
    rng_state = owner_rng.getstate()

    with manager.prepared_connection_composite_materialization(
        composite_plan,
        owner_rng,
    ) as composite_preparation:
        copied_preparation = copy(composite_preparation)

    for preparation in (composite_preparation, copied_preparation):
        with pytest.raises(StateError, match="no longer active"):
            preparation.commit()
    assert manager.materialization_digest() == digest
    assert manager.materialization_version == version
    assert owner_rng.getstate() == rng_state
    assert manager.get_connection(conn_id) is None


def test_composite_preparation_copy_cannot_replay_original_commit() -> None:
    manager = StateManager()
    manager.set_current_time(_START)
    owner_rng = random.Random(27)
    conn_id, composite_plan = _connection_composite_plan(manager, owner_rng)

    with manager.prepared_connection_composite_materialization(
        composite_plan,
        owner_rng,
    ) as composite_preparation:
        copied_before_commit = copy(composite_preparation)
        with pytest.raises(StateError, match="no longer active"):
            copied_before_commit.commit()
        result = composite_preparation.commit()
        assert result.connection is manager.get_connection(conn_id)
        copied_after_commit = copy(composite_preparation)
        committed_digest = manager.materialization_digest()
        committed_version = manager.materialization_version
        committed_rng_state = owner_rng.getstate()
        with pytest.raises(StateError, match="no longer active"):
            copied_after_commit.commit()
        with pytest.raises(StateError, match="already committed"):
            composite_preparation.commit()
        assert manager.materialization_digest() == committed_digest
        assert manager.materialization_version == committed_version
        assert owner_rng.getstate() == committed_rng_state

    with pytest.raises(StateError, match="no longer active"):
        copied_after_commit.commit()
    assert manager.materialization_digest() == committed_digest
    assert manager.materialization_version == committed_version
    assert owner_rng.getstate() == committed_rng_state
    assert len(manager.list_open_connections()) == 1


@pytest.mark.parametrize("composite", (False, True))
def test_connection_preparation_commit_rejects_the_wrong_thread(composite: bool) -> None:
    manager = StateManager()
    manager.set_current_time(_START)
    owner_rng = random.Random(28)
    if composite:
        conn_id, connection_plan = _connection_composite_plan(manager, owner_rng)
    else:
        conn_id, connection_plan = _connection_plan(manager, owner_rng)
    digest = manager.materialization_digest()
    version = manager.materialization_version
    rng_state = owner_rng.getstate()

    context = (
        manager.prepared_connection_composite_materialization(
            connection_plan,  # type: ignore[arg-type]
            owner_rng,
        )
        if composite
        else manager.prepared_connection_materialization(
            connection_plan,  # type: ignore[arg-type]
            owner_rng,
        )
    )
    with context as preparation, ThreadPoolExecutor(max_workers=1) as executor:
        committed = executor.submit(preparation.commit)
        with pytest.raises(StateError, match="claiming thread"):
            committed.result(timeout=2)
        assert manager.materialization_digest() == digest

    assert manager.materialization_digest() == digest
    assert manager.materialization_version == version
    assert owner_rng.getstate() == rng_state
    assert manager.get_connection(conn_id) is None


@pytest.mark.parametrize("composite", (False, True))
def test_closed_connection_copy_cannot_commit_after_a_later_action_owner(
    composite: bool,
) -> None:
    manager, action_plan = _manager_and_plan()
    owner_rng = random.Random(28)
    if composite:
        conn_id, connection_plan = _connection_composite_plan(manager, owner_rng)
    else:
        conn_id, connection_plan = _connection_plan(manager, owner_rng)
    rng_state = owner_rng.getstate()
    context = (
        manager.prepared_connection_composite_materialization(
            connection_plan,  # type: ignore[arg-type]
            owner_rng,
        )
        if composite
        else manager.prepared_connection_materialization(
            connection_plan,  # type: ignore[arg-type]
            owner_rng,
        )
    )
    with context as preparation:
        replayed_preparation = copy(preparation)

    action_result = manager.materialize_action_cohort(action_plan)
    assert action_result.committed_version == action_plan.expected_version + 1
    committed_digest = manager.materialization_digest()
    committed_version = manager.materialization_version
    with pytest.raises(StateError, match="no longer active"):
        replayed_preparation.commit()

    assert manager.materialization_digest() == committed_digest
    assert manager.materialization_version == committed_version
    assert owner_rng.getstate() == rng_state
    assert manager.get_connection(conn_id) is None


def test_action_claim_is_rejected_inside_prepared_connection_without_residue() -> None:
    manager, action_plan = _manager_and_plan()
    owner_rng = random.Random(29)
    conn_id, connection_plan = _connection_plan(manager, owner_rng)
    digest = manager.materialization_digest()
    version = manager.materialization_version
    rng_state = owner_rng.getstate()

    with manager.prepared_connection_materialization(connection_plan, owner_rng):
        with pytest.raises(StateError, match="prepared-State claim"):
            manager.set_current_time(_START + timedelta(seconds=1))
        with pytest.raises(StateError, match="active prepared-State claim"):
            with manager.prepared_action_cohort_materialization(action_plan):
                raise AssertionError("action claim unexpectedly nested inside connection claim")
        assert manager.materialization_digest() == digest

    assert manager.materialization_digest() == digest
    assert manager.materialization_version == version
    assert owner_rng.getstate() == rng_state
    assert manager.get_connection(conn_id) is None


def test_action_claim_is_rejected_inside_prepared_composite_without_residue() -> None:
    manager, action_plan = _manager_and_plan()
    owner_rng = random.Random(31)
    conn_id, composite_plan = _connection_composite_plan(manager, owner_rng)
    digest = manager.materialization_digest()
    version = manager.materialization_version
    rng_state = owner_rng.getstate()

    with manager.prepared_connection_composite_materialization(composite_plan, owner_rng):
        with pytest.raises(StateError, match="active prepared-State claim"):
            with manager.prepared_action_cohort_materialization(action_plan):
                raise AssertionError("action claim unexpectedly nested inside composite claim")
        assert manager.materialization_digest() == digest

    assert manager.materialization_digest() == digest
    assert manager.materialization_version == version
    assert owner_rng.getstate() == rng_state
    assert manager.get_connection(conn_id) is None


@pytest.mark.parametrize("composite", (False, True))
def test_connection_claim_is_rejected_inside_action_claim_without_residue(
    composite: bool,
) -> None:
    manager, action_plan = _manager_and_plan()
    owner_rng = random.Random(37)
    if composite:
        conn_id, connection_plan = _connection_composite_plan(manager, owner_rng)
    else:
        conn_id, connection_plan = _connection_plan(manager, owner_rng)
    digest = manager.materialization_digest()
    version = manager.materialization_version
    rng_state = owner_rng.getstate()

    with manager.prepared_action_cohort_materialization(action_plan):
        with pytest.raises(StateError, match="active action-cohort claim"):
            if composite:
                with manager.prepared_connection_composite_materialization(
                    connection_plan,  # type: ignore[arg-type]
                    owner_rng,
                ):
                    raise AssertionError("composite claim unexpectedly nested inside action claim")
            else:
                with manager.prepared_connection_materialization(
                    connection_plan,  # type: ignore[arg-type]
                    owner_rng,
                ):
                    raise AssertionError("connection claim unexpectedly nested inside action claim")
        assert manager.materialization_digest() == digest

    assert manager.materialization_digest() == digest
    assert manager.materialization_version == version
    assert owner_rng.getstate() == rng_state
    assert manager.get_connection(conn_id) is None


@pytest.mark.parametrize("composite", (False, True))
def test_connection_claim_admission_rejects_overlap_with_action_claim(
    monkeypatch: pytest.MonkeyPatch,
    composite: bool,
) -> None:
    manager, action_plan = _manager_and_plan()
    owner_rng = random.Random(41)
    if composite:
        conn_id, connection_plan = _connection_composite_plan(manager, owner_rng)
        operation = "prepared_connection_composite_materialization"
        context = manager.prepared_connection_composite_materialization(
            connection_plan,
            owner_rng,
        )
    else:
        conn_id, connection_plan = _connection_plan(manager, owner_rng)
        operation = "prepared_connection_materialization"
        context = manager.prepared_connection_materialization(connection_plan, owner_rng)
    version = manager.materialization_version
    rng_state = owner_rng.getstate()
    admitted = Event()
    release = Event()
    original_admit = manager._reject_mutation_during_action_cohort_claim

    def admit_with_barrier(candidate: str, *, admitted_at: int | None = None) -> int:
        epoch = original_admit(candidate, admitted_at=admitted_at)
        if candidate == operation and admitted_at is None:
            admitted.set()
            if not release.wait(timeout=2):
                raise AssertionError("connection claim admission barrier timed out")
        return epoch

    monkeypatch.setattr(
        manager,
        "_reject_mutation_during_action_cohort_claim",
        admit_with_barrier,
    )
    digest = manager.materialization_digest()

    def enter_connection_claim() -> None:
        with context:
            raise AssertionError("overlapping connection claim unexpectedly opened")

    with ThreadPoolExecutor(max_workers=1) as executor:
        entered = executor.submit(enter_connection_claim)
        assert admitted.wait(timeout=2)
        with manager.prepared_action_cohort_materialization(action_plan):
            release.set()
            assert not entered.done()
        with pytest.raises(StateError, match="prepared-State claim"):
            entered.result(timeout=2)

    assert manager.materialization_digest() == digest
    assert manager.materialization_version == version
    assert owner_rng.getstate() == rng_state
    assert manager.get_connection(conn_id) is None


def test_apply_rechecks_state_time_frontier_immediately_before_publication() -> None:
    manager, plan = _manager_and_plan()
    drifted_time = _START + timedelta(microseconds=1)

    with manager.prepared_action_cohort_materialization(plan) as preparation:
        expected = preparation.expected_result
        preparation.certify_composite_commit(expected)
        manager.state.current_time = drifted_time
        with pytest.raises(StateError, match="State time changed before apply"):
            preparation.apply_provisional()

    assert manager.state.current_time == drifted_time
    assert manager.list_running_processes() == []


def test_failed_apply_validation_consumes_claim_and_releases_lane_exactly() -> None:
    manager, plan = _manager_and_plan()
    digest = manager.materialization_digest()
    version = manager.materialization_version

    with manager.prepared_action_cohort_materialization(plan) as preparation:
        expected = preparation.expected_result
        preparation.certify_composite_commit(expected)
        manager.state.current_time = _START + timedelta(microseconds=1)
        with pytest.raises(StateError, match="State time changed before apply"):
            preparation.apply_provisional()

        manager.state.current_time = _START
        with pytest.raises(StateError, match="already failed"):
            preparation.commit_no_fail()
        assert manager.materialization_digest() == digest
        assert manager.materialization_version == version
        assert manager.list_running_processes() == []

    assert manager.materialization_digest() == digest
    assert manager.materialization_version == version
    assert manager._active_action_cohort_preparations == {}
    assert manager._active_action_cohort_claim is None
    assert manager._active_prepared_state_claim is None

    later_result = manager.materialize_action_cohort(plan)
    assert later_result.committed_version == version + 1
    assert manager.materialization_version == version + 1


def test_provisional_claim_rejects_connection_capability_minting_across_aba() -> None:
    class LaterOwnerAbort(BaseException):
        pass

    manager, action_plan = _manager_and_plan()
    simple_rng = random.Random(43)
    composite_rng = random.Random(47)
    prior_identity = manager.plan_connection_identity(simple_rng)
    prior_cursor = manager.begin_connection_planning(composite_rng)
    simple_rng_state = simple_rng.getstate()
    composite_rng_state = composite_rng.getstate()
    digest = manager.materialization_digest()
    version = manager.materialization_version
    connection_counter = manager._connection_id_counter
    minted_identities: list[object] = []
    minted_simple_plans: list[ConnectionMaterializationPlan] = []
    minted_cursors: list[object] = []
    minted_composite_plans: list[ConnectionCompositeMaterializationPlan] = []

    def mint_simple() -> None:
        identity = manager.plan_connection_identity(simple_rng)
        minted_identities.append(identity)
        minted_simple_plans.append(
            manager.finalize_connection_materialization(
                identity,
                _connection_transaction(identity.conn_id, identity.zeek_uid),
                continuation_rng=identity.continuation_rng(),
            )
        )

    def mint_composite() -> None:
        cursor = manager.begin_connection_planning(composite_rng)
        minted_cursors.append(cursor)
        identity = cursor.reserve_identity()
        minted_composite_plans.append(
            manager.finalize_connection_composite_materialization(
                cursor,
                _connection_transaction(identity.conn_id, identity.zeek_uid),
            )
        )

    with pytest.raises(LaterOwnerAbort):
        with manager.prepared_action_cohort_materialization(action_plan) as preparation:
            expected = preparation.expected_result
            preparation.certify_composite_commit(expected)
            preparation.apply_provisional()
            assert manager.materialization_version == version + 1

            with pytest.raises(StateError, match="active action-cohort claim"):
                mint_simple()
            with pytest.raises(StateError, match="active action-cohort claim"):
                manager.finalize_connection_materialization(
                    prior_identity,
                    _connection_transaction(prior_identity.conn_id, prior_identity.zeek_uid),
                    continuation_rng=prior_identity.continuation_rng(),
                )
            with pytest.raises(StateError, match="active action-cohort claim"):
                mint_composite()
            with pytest.raises(StateError, match="active action-cohort claim"):
                manager.finalize_connection_composite_materialization(
                    prior_cursor,
                    _connection_transaction("conn-0", "C-before-claim"),
                )
            raise LaterOwnerAbort()

    assert minted_identities == []
    assert minted_simple_plans == []
    assert minted_cursors == []
    assert minted_composite_plans == []
    assert manager.materialization_digest() == digest
    assert manager.materialization_version == version
    assert manager.state.current_time == _START
    assert manager._connection_id_counter == connection_counter
    assert simple_rng.getstate() == simple_rng_state
    assert composite_rng.getstate() == composite_rng_state
    assert manager.list_open_connections() == []
    with pytest.raises(StateError, match="crossed a prepared-State claim"):
        prior_cursor.reserve_identity()

    manager.allocate_logon_id("ABA-REALIGN", _START + timedelta(seconds=5))
    manager.set_current_time(_START + timedelta(seconds=5))
    assert manager.materialization_version == version + 1
    assert manager.state.current_time == _START + timedelta(seconds=5)
    assert manager._connection_id_counter == connection_counter
    assert manager.list_open_connections() == []


def test_provisional_claim_rejects_all_other_public_capability_minting() -> None:
    class LaterOwnerAbort(BaseException):
        pass

    manager, action_plan = _manager_and_plan()
    logind_rng = random.Random(53)
    logind_rng_state = logind_rng.getstate()
    session_plan = manager.plan_session_materialization(
        username="candidate",
        system="WS-02",
        logon_type=2,
        source_ip="127.0.0.1",
        start_time=_START,
        session_id=0,
    )
    batch_builder = manager.begin_materialization_batch()
    action_builder = manager.begin_action_cohort_materialization()
    digest = manager.materialization_digest()
    version = manager.materialization_version

    with pytest.raises(LaterOwnerAbort):
        with manager.prepared_action_cohort_materialization(action_plan) as preparation:
            expected = preparation.expected_result
            preparation.certify_composite_commit(expected)
            preparation.apply_provisional()

            with pytest.raises(StateError, match="active action-cohort claim"):
                manager.begin_materialization_batch()
            with pytest.raises(StateError, match="active action-cohort claim"):
                manager.begin_action_cohort_materialization()
            with pytest.raises(StateError, match="active action-cohort claim"):
                manager.plan_session_materialization(
                    username="candidate",
                    system="WS-02",
                    logon_type=2,
                    source_ip="127.0.0.1",
                )
            with pytest.raises(StateError, match="active action-cohort claim"):
                manager.plan_linux_logind_session_materialization(
                    session_plan,
                    rng=logind_rng,
                    event_time=_START,
                )
            with pytest.raises(StateError, match="active action-cohort claim"):
                manager.plan_process_materialization(
                    system="WS-02",
                    parent_pid=4,
                    image=r"C:\Windows\System32\cmd.exe",
                    command_line="cmd.exe",
                    username="candidate",
                    integrity_level="Medium",
                    os_category="windows",
                )
            with pytest.raises(StateError, match="active action-cohort claim"):
                manager.plan_process_termination_materialization(
                    system="WS-02",
                    pid=404,
                )
            with pytest.raises(StateError, match="prepared-State claim"):
                batch_builder.plan_session(
                    username="candidate",
                    system="WS-02",
                    logon_type=2,
                    source_ip="127.0.0.1",
                )
            with pytest.raises(StateError, match="prepared-State claim"):
                batch_builder.seal()
            with pytest.raises(StateError, match="prepared-State claim"):
                action_builder.plan_session(
                    username="candidate",
                    system="WS-02",
                    logon_type=2,
                    source_ip="127.0.0.1",
                )
            with pytest.raises(StateError, match="prepared-State claim"):
                action_builder.seal()
            raise LaterOwnerAbort()

    assert manager.materialization_digest() == digest
    assert manager.materialization_version == version
    assert manager.state.current_time == _START
    assert logind_rng.getstate() == logind_rng_state
    with pytest.raises(StateError, match="crossed an active prepared-State claim"):
        batch_builder.plan_session(
            username="candidate",
            system="WS-02",
            logon_type=2,
            source_ip="127.0.0.1",
        )
    with pytest.raises(StateError, match="crossed an active prepared-State claim"):
        action_builder.plan_session(
            username="candidate",
            system="WS-02",
            logon_type=2,
            source_ip="127.0.0.1",
        )


def test_apply_rechecks_the_touched_object_preimage() -> None:
    manager, pid, plan = _manager_and_live_process_plan()
    process = manager.get_process("WS-01", pid)
    assert process is not None

    with manager.prepared_action_cohort_materialization(plan) as preparation:
        expected = preparation.expected_result
        preparation.certify_composite_commit(expected)
        process.last_activity_time = _START + timedelta(seconds=1)
        with pytest.raises(StateError, match="touched State changed before apply"):
            preparation.apply_provisional()

    assert process.last_activity_time == _START + timedelta(seconds=1)


def test_cleanup_refuses_to_overwrite_a_drifted_provisional_postimage() -> None:
    class LaterOwnerAbort(BaseException):
        pass

    manager, pid, plan = _manager_and_live_process_plan()
    process = manager.get_process("WS-01", pid)
    assert process is not None
    drifted = _START + timedelta(seconds=6)

    with pytest.raises(LaterOwnerAbort) as caught:
        with manager.prepared_action_cohort_materialization(plan) as preparation:
            expected = preparation.expected_result
            preparation.certify_composite_commit(expected)
            preparation.apply_provisional()
            process.last_activity_time = drifted
            raise LaterOwnerAbort()

    assert process.last_activity_time == drifted
    assert any("refusing rollback" in note for note in caught.value.__notes__)
    assert manager._active_action_cohort_preparations == {}


def test_later_owner_rollback_restores_bounded_retention_evictions(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class LaterOwnerAbort(BaseException):
        pass

    manager = StateManager()
    manager.set_current_time(_START - timedelta(minutes=10))
    logon_id = manager.create_session(
        username="seed",
        system="WS-01",
        logon_type=2,
        source_ip="127.0.0.1",
    )
    pid = manager.create_process(
        system="WS-01",
        parent_pid=4,
        image=r"C:\Windows\System32\seed.exe",
        command_line="seed.exe",
        username="seed",
        integrity_level="Medium",
        logon_id=logon_id,
    )
    assert manager.end_process("WS-01", pid, _START - timedelta(minutes=9))
    assert manager.end_session(logon_id, _START - timedelta(minutes=8))
    manager.set_current_time(_START)
    plan = _closed_cohort(manager)
    digest = manager.materialization_digest()

    monkeypatch.setattr(state_manager_module, "_MAX_RETAINED_SESSION_IDENTITIES", 1)
    monkeypatch.setattr(state_manager_module, "_MAX_RETAINED_PROCESS_IDENTITIES", 1)
    monkeypatch.setattr(state_manager_module, "_MAX_RETAINED_THREAD_IDENTITIES", 1)

    with pytest.raises(LaterOwnerAbort):
        with manager.prepared_action_cohort_materialization(plan) as preparation:
            expected = preparation.expected_result
            preparation.certify_composite_commit(expected)
            preparation.apply_provisional()
            raise LaterOwnerAbort()

    assert manager.materialization_digest() == digest
    assert manager.get_process_identity("WS-01", pid) is not None
    assert manager.get_session_identity(logon_id) is not None


@pytest.mark.parametrize("fail_after", (False, True))
def test_ordinary_commit_failure_rolls_back_exactly_once(
    monkeypatch: pytest.MonkeyPatch,
    fail_after: bool,
) -> None:
    class CommitAbort(BaseException):
        pass

    manager, plan = _manager_and_plan()
    digest = manager.materialization_digest()
    original = StateManager._commit_prevalidated_action_cohort

    def fail(target: StateManager, commit_plan: object) -> None:
        if fail_after:
            original(target, commit_plan)  # type: ignore[arg-type]
        raise CommitAbort()

    monkeypatch.setattr(StateManager, "_commit_prevalidated_action_cohort", fail)
    with manager.prepared_action_cohort_materialization(plan) as preparation:
        expected = preparation.expected_result
        preparation.certify_composite_commit(expected)
        with pytest.raises(CommitAbort):
            preparation.apply_provisional()
        with pytest.raises(StateError, match="already failed"):
            preparation.apply_provisional()
        assert manager.materialization_digest() == digest

    assert manager.materialization_digest() == digest
