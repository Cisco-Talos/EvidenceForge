# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Authenticated lifecycle-registry action-cohort transaction tests."""

from collections.abc import Callable
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from threading import Barrier, Event, Thread
from weakref import ref

import pytest

import evidenceforge.generation.lifecycle_registry as lifecycle_registry_module
from evidenceforge.events.lifecycle import (
    LifecycleCloseBarrier,
    LifecycleEntityRef,
    LifecycleForegroundLease,
    LifecycleHold,
    LifecycleMembership,
    LifecycleTransition,
    ProcessLifecycleIdentity,
    ProcessTokenIdentity,
    SessionLifecycleIdentity,
)
from evidenceforge.generation.lifecycle_registry import (
    LifecycleActionCohortAdmissionToken,
    LifecycleActionCohortInProgressError,
    LifecycleActionCohortReceipt,
    LifecycleActionCohortRequest,
    LifecycleProcessStartRequest,
    LifecycleRegistry,
    LifecycleSessionStartRequest,
    LifecycleSubjectClosureControl,
)
from evidenceforge.models.exceptions import StateError

_START = datetime(2026, 8, 17, 14, 0, tzinfo=UTC)


def _session_request(
    *,
    hostname: str = "WS-01",
    object_id: str = "session-1",
    logon_id: str = "0x50001",
    started_at: datetime = _START,
) -> LifecycleSessionStartRequest:
    return LifecycleSessionStartRequest(
        identity=SessionLifecycleIdentity(
            hostname=hostname,
            object_id=object_id,
            logon_id=logon_id,
            principal="analyst",
            session_kind="interactive",
            started_at=started_at,
            session_id=4,
        ),
        action_id=f"{object_id}:start-action",
        transition_id=f"{object_id}:started",
    )


def _process_request(
    *,
    hostname: str = "WS-01",
    object_id: str,
    pid: int,
    started_at: datetime,
    parent_object_id: str = "",
    session: LifecycleSessionStartRequest | None = None,
    role: str = "application",
) -> LifecycleProcessStartRequest:
    membership = (
        LifecycleMembership(
            owner_kind="session",
            owner_object_id=session.identity.object_id,
            session_object_id=session.identity.object_id,
        )
        if session is not None
        else LifecycleMembership(
            owner_kind="boot",
            owner_object_id=f"boot:{hostname}",
        )
    )
    return LifecycleProcessStartRequest(
        identity=ProcessLifecycleIdentity(
            hostname=hostname,
            object_id=object_id,
            pid=pid,
            started_at=started_at,
            image="/usr/bin/sh" if hostname.startswith("LINUX") else "cmd.exe",
            parent_object_id=parent_object_id,
            role=role,
        ),
        token=ProcessTokenIdentity(
            principal="analyst",
            logon_id="" if session is None else session.identity.logon_id,
            session_id=None if session is None else session.identity.session_id,
            logon_type=None if session is None else 2,
            integrity_level="Medium",
        ),
        membership=membership,
        action_id=f"{object_id}:start-action",
        transition_id=f"{object_id}:started",
    )


def _closure(
    subject: LifecycleEntityRef,
    *,
    requested_at: datetime,
    suffix: str,
    authority: str = "authoritative",
) -> LifecycleSubjectClosureControl:
    return LifecycleSubjectClosureControl(
        barrier=LifecycleCloseBarrier(
            barrier_id=f"{suffix}:barrier",
            subject=subject,
            requested_at=requested_at,
            authority=authority,  # type: ignore[arg-type]
            action_id=f"{suffix}:close-action",
        ),
        ticket_id=f"{suffix}:ticket",
    )


def _closed_tree_request() -> LifecycleActionCohortRequest:
    session = _session_request()
    parent = _process_request(
        object_id="parent-1",
        pid=5100,
        started_at=_START + timedelta(seconds=1),
        session=session,
    )
    child = _process_request(
        object_id="child-1",
        pid=5104,
        started_at=_START + timedelta(seconds=2),
        parent_object_id=parent.identity.object_id,
        session=session,
    )
    dependent = LifecycleTransition(
        transition_id="child-1:dependent",
        subject=child.identity.ref,
        kind="dependent",
        canonical_time=_START + timedelta(seconds=3),
        action_id="child-1:dependent-action",
        reason="command execution",
    )
    hold = LifecycleHold(
        hold_id="parent-1:hold",
        subject=parent.identity.ref,
        acquired_at=_START + timedelta(seconds=4),
        hold_until=_START + timedelta(seconds=6),
        action_id="parent-1:hold-action",
        reason="retain parent through child execution",
    )
    return LifecycleActionCohortRequest(
        state_publication_token="opaque-state-action-plan",
        operations=(
            session,
            parent,
            child,
            dependent,
            hold,
            _closure(
                child.identity.ref,
                requested_at=_START + timedelta(seconds=5),
                suffix="child-1",
            ),
            _closure(
                parent.identity.ref,
                requested_at=_START + timedelta(seconds=6),
                suffix="parent-1",
            ),
            _closure(
                session.identity.ref,
                requested_at=_START + timedelta(seconds=7),
                suffix="session-1",
            ),
        ),
    )


def _register_live_tree(
    registry: LifecycleRegistry,
    *,
    parent_role: str = "application",
) -> tuple[
    LifecycleSessionStartRequest,
    LifecycleProcessStartRequest,
    LifecycleProcessStartRequest,
]:
    session = _session_request()
    parent = _process_request(
        object_id="parent-1",
        pid=5100,
        started_at=_START + timedelta(seconds=1),
        session=session,
        role=parent_role,
    )
    child = _process_request(
        object_id="child-1",
        pid=5104,
        started_at=_START + timedelta(seconds=2),
        parent_object_id=parent.identity.object_id,
        session=session,
    )
    registry.register_session(
        session.identity,
        action_id=session.action_id,
        transition_id=session.transition_id,
    )
    for request in (parent, child):
        registry.register_process(
            request.identity,
            token=request.token,
            membership=request.membership,
            action_id=request.action_id,
            transition_id=request.transition_id,
        )
    return session, parent, child


def test_action_cohort_ordered_starts_activity_holds_and_closes_are_atomic() -> None:
    registry = LifecycleRegistry()
    request = _closed_tree_request()
    before = registry.census()

    token = registry.prepare_action_cohort(request)

    assert registry.census() == before
    assert registry.authenticates_action_cohort_admission_token(
        token,
        request=request,
        state_publication_token=request.state_publication_token,
    )
    assert registry.action_cohort_preparation_census().reservations == 1
    with registry.claimed_action_cohort(token) as prepared:
        assert registry.get_session("session-1") is None
        assert registry.get_process("parent-1") is None
        receipt = prepared.commit_no_fail()
        with pytest.raises(StateError, match="already committed"):
            prepared.commit_no_fail()

    assert receipt.state_publication_token == request.state_publication_token
    assert registry.authenticates_action_cohort_receipt(
        receipt,
        request=request,
        state_publication_token=request.state_publication_token,
    )
    assert len(receipt.operation_results) == len(request.operations)
    assert [item.identity.object_id for item in receipt.started_sessions] == ["session-1"]
    assert [item.identity.object_id for item in receipt.started_processes] == [
        "parent-1",
        "child-1",
    ]
    assert [item.transition_id for item in receipt.dependents] == ["child-1:dependent"]
    assert [item.hold_id for item in receipt.holds] == ["parent-1:hold"]
    assert [item.identity.object_id for item in receipt.closed_processes] == [
        "child-1",
        "parent-1",
    ]
    assert [item.identity.object_id for item in receipt.closed_sessions] == ["session-1"]
    assert registry.get_process("child-1").closed_at == _START + timedelta(seconds=5)  # type: ignore[union-attr]
    assert registry.get_process("parent-1").closed_at == _START + timedelta(seconds=6)  # type: ignore[union-attr]
    assert registry.get_session("session-1").closed_at == _START + timedelta(seconds=7)  # type: ignore[union-attr]
    assert registry.action_cohort_preparation_census().reservations == 0

    retry_token = registry.prepare_action_cohort(request)
    with registry.claimed_action_cohort(retry_token) as prepared:
        retry = prepared.commit_no_fail()
    assert retry == receipt
    assert registry.authenticates_action_cohort_receipt(retry, request=request)


def test_action_cohort_live_closes_require_child_member_order_and_reject_partial_retry() -> None:
    registry = LifecycleRegistry()
    session, parent, child = _register_live_tree(registry)
    child_close = _closure(
        child.identity.ref,
        requested_at=_START + timedelta(seconds=5),
        suffix="live-child",
    )
    parent_close = _closure(
        parent.identity.ref,
        requested_at=_START + timedelta(seconds=6),
        suffix="live-parent",
    )
    session_close = _closure(
        session.identity.ref,
        requested_at=_START + timedelta(seconds=7),
        suffix="live-session",
    )
    request = LifecycleActionCohortRequest(
        state_publication_token="opaque-live-close-plan",
        operations=(child_close, parent_close, session_close),
    )

    token = registry.prepare_action_cohort(request)
    with registry.claimed_action_cohort(token) as prepared:
        receipt = prepared.commit_no_fail()

    assert [item.identity.object_id for item in receipt.closed_processes] == [
        child.identity.object_id,
        parent.identity.object_id,
    ]
    assert registry.get_session(session.identity.object_id).closed_at is not None  # type: ignore[union-attr]

    partial = LifecycleRegistry()
    partial_session, partial_parent, partial_child = _register_live_tree(partial)
    partial_child_close = _closure(
        partial_child.identity.ref,
        requested_at=_START + timedelta(seconds=5),
        suffix="partial-child",
    )
    ticket = partial.request_close(
        partial_child_close.barrier,
        ticket_id=partial_child_close.ticket_id,
    )
    partial.close(ticket.ticket_id)
    partial_request = LifecycleActionCohortRequest(
        state_publication_token="opaque-partial-plan",
        operations=(
            partial_child_close,
            _closure(
                partial_parent.identity.ref,
                requested_at=_START + timedelta(seconds=6),
                suffix="partial-parent",
            ),
            _closure(
                partial_session.identity.ref,
                requested_at=_START + timedelta(seconds=7),
                suffix="partial-session",
            ),
        ),
    )
    with pytest.raises(StateError, match="Partial lifecycle action-cohort retry"):
        partial.prepare_action_cohort(partial_request)
    assert partial.get_process(partial_parent.identity.object_id).closed_at is None  # type: ignore[union-attr]
    assert partial.action_cohort_preparation_census().reservations == 0


def test_action_cohort_cancel_copy_foreign_tamper_and_stale_leave_zero_residue() -> None:
    registry = LifecycleRegistry()
    foreign = LifecycleRegistry()
    request = LifecycleActionCohortRequest(
        state_publication_token="opaque-single-start",
        operations=(_session_request(object_id="single-session"),),
    )

    cancelled = registry.prepare_action_cohort(request)
    assert not foreign.authenticates_action_cohort_admission_token(cancelled)
    assert registry.action_cohort_preparation_census().reservations == 1
    copied = replace(cancelled)
    assert not registry.authenticates_action_cohort_admission_token(copied)
    assert registry.action_cohort_preparation_census().reservations == 1
    registry.cancel_action_cohort(cancelled)
    assert registry.action_cohort_preparation_census().reservations == 0
    assert registry.get_session("single-session") is None

    tampered = registry.prepare_action_cohort(request)
    object.__setattr__(tampered, "plan_digest", "0" * 64)
    assert not registry.authenticates_action_cohort_admission_token(tampered)
    assert registry.action_cohort_preparation_census().reservations == 0
    assert registry.get_session("single-session") is None

    class Evil:
        def __repr__(self) -> str:
            raise AssertionError("nested repr must not escape the total authenticator")

    nested_tamper = registry.prepare_action_cohort(request)
    object.__setattr__(nested_tamper.request, "state_publication_token", Evil())
    assert not registry.authenticates_action_cohort_admission_token(nested_tamper)
    assert registry.action_cohort_preparation_census().reservations == 0

    stale = registry.prepare_action_cohort(request)
    registry.advance_watermark(_START - timedelta(seconds=1))
    with pytest.raises(StateError, match="stale"):
        with registry.claimed_action_cohort(stale):
            pytest.fail("stale admission must fail before yielding")
    assert registry.action_cohort_preparation_census().reservations == 0
    assert registry.get_session("single-session") is None


def test_claimed_action_cohort_fences_watermark_until_commit() -> None:
    registry = LifecycleRegistry()
    request = LifecycleActionCohortRequest(
        state_publication_token="opaque-watermark-fence",
        operations=(_session_request(object_id="watermark-session"),),
    )
    token = registry.prepare_action_cohort(request)

    with registry.claimed_action_cohort(token) as prepared:
        with pytest.raises(StateError, match="claimed action cohort"):
            registry.advance_watermark(_START - timedelta(seconds=1))
        receipt = prepared.commit_no_fail()

    assert registry.authenticates_action_cohort_receipt(receipt)
    assert registry.census().watermark is None


def test_action_cohort_authenticators_are_total_and_receipts_reject_tamper() -> None:
    registry = LifecycleRegistry()
    request = LifecycleActionCohortRequest(
        state_publication_token="opaque-auth-plan",
        operations=(_session_request(object_id="auth-session"),),
    )
    token = registry.prepare_action_cohort(request)

    class Evil:
        def __repr__(self) -> str:
            raise AssertionError("repr must not execute")

    class TokenSubclass(LifecycleActionCohortAdmissionToken):
        pass

    class ReceiptSubclass(LifecycleActionCohortReceipt):
        pass

    assert not registry.authenticates_action_cohort_admission_token(Evil())
    assert not registry.authenticates_action_cohort_admission_token(object())
    assert not registry.authenticates_action_cohort_admission_token(
        TokenSubclass.__new__(TokenSubclass)
    )
    with registry.claimed_action_cohort(token) as prepared:
        receipt = prepared.commit_no_fail()

    assert not registry.authenticates_action_cohort_receipt(Evil())
    assert not registry.authenticates_action_cohort_receipt(object())
    assert not registry.authenticates_action_cohort_receipt(
        ReceiptSubclass.__new__(ReceiptSubclass)
    )
    assert not registry.authenticates_action_cohort_receipt(
        replace(receipt, committed_digest="0" * 64)
    )
    assert not registry.authenticates_action_cohort_receipt(replace(receipt, operation_results=()))
    assert not LifecycleRegistry().authenticates_action_cohort_receipt(receipt)


def test_action_cohort_claim_exit_and_cross_thread_commit_release_capability() -> None:
    registry = LifecycleRegistry()
    request = LifecycleActionCohortRequest(
        state_publication_token="opaque-thread-plan",
        operations=(_session_request(object_id="thread-session"),),
    )
    token = registry.prepare_action_cohort(request)
    failures: list[BaseException] = []

    with pytest.raises(StateError, match="without commit_no_fail"):
        with registry.claimed_action_cohort(token) as prepared:
            thread = Thread(
                target=lambda: _capture_failure(prepared.commit_no_fail, failures),
                daemon=True,
            )
            thread.start()
            thread.join(timeout=2)
            assert not thread.is_alive()

    assert len(failures) == 1
    assert isinstance(failures[0], StateError)
    assert "claiming thread" in str(failures[0])
    assert registry.action_cohort_preparation_census().reservations == 0
    assert registry.get_session("thread-session") is None

    uncommitted = registry.prepare_action_cohort(request)
    with pytest.raises(StateError, match="without commit_no_fail"):
        with registry.claimed_action_cohort(uncommitted):
            pass
    assert registry.action_cohort_preparation_census().reservations == 0


def _capture_failure(callable_: object, failures: list[BaseException]) -> None:
    try:
        callable_()  # type: ignore[operator]
    except BaseException as exc:  # pragma: no cover - exercised in worker threads
        failures.append(exc)


def test_action_cohort_reserves_descendant_member_and_resource_conflicts() -> None:
    registry = LifecycleRegistry()
    session, parent, child = _register_live_tree(registry, parent_role="shell")
    lease = LifecycleForegroundLease(
        lease_id="foreground-1",
        hostname=parent.identity.hostname,
        principal="analyst",
        session_object_id=session.identity.object_id,
        process_object_id=parent.identity.object_id,
        acquired_at=_START + timedelta(seconds=3),
        lease_until=_START + timedelta(seconds=8),
        action_id="foreground-acquire",
    )
    registry.acquire_foreground_lease(lease)
    request = LifecycleActionCohortRequest(
        state_publication_token="opaque-conflict-plan",
        operations=(
            _closure(
                child.identity.ref,
                requested_at=_START + timedelta(seconds=5),
                suffix="conflict-child",
            ),
            _closure(
                parent.identity.ref,
                requested_at=_START + timedelta(seconds=6),
                suffix="conflict-parent",
                authority="generated",
            ),
            _closure(
                session.identity.ref,
                requested_at=_START + timedelta(seconds=9),
                suffix="conflict-session",
            ),
        ),
    )
    token = registry.prepare_action_cohort(request)

    with pytest.raises(StateError, match="prepared action cohort"):
        registry.record_dependent(
            child.identity.ref,
            transition_id="blocked-dependent",
            canonical_time=_START + timedelta(seconds=4),
            action_id="blocked-action",
        )
    with pytest.raises(StateError, match="prepared action cohort"):
        registry.renew_foreground_lease(
            lease.lease_id,
            expected_lease_until=lease.lease_until,
            lease_until=_START + timedelta(seconds=10),
            canonical_time=_START + timedelta(seconds=4),
            action_id="blocked-renewal",
        )
    with pytest.raises(LifecycleActionCohortInProgressError):
        registry.prepare_action_cohort(request)

    registry.cancel_action_cohort(token)
    assert registry.action_cohort_preparation_census().reservations == 0
    assert registry.transition("blocked-dependent") is None


def test_action_cohort_rejects_order_barrier_ordinal_and_watermark_violations() -> None:
    session = _session_request(object_id="invalid-session")
    with pytest.raises(ValueError, match="time ordered"):
        LifecycleActionCohortRequest(
            state_publication_token="opaque-invalid-order",
            operations=(
                replace(
                    session,
                    identity=replace(
                        session.identity,
                        started_at=_START + timedelta(seconds=2),
                    ),
                ),
                LifecycleTransition(
                    transition_id="invalid:dependent",
                    subject=session.identity.ref,
                    kind="dependent",
                    canonical_time=_START + timedelta(seconds=1),
                    action_id="invalid-action",
                ),
            ),
        )

    duplicate_ordinal = LifecycleTransition(
        transition_id="invalid-session:duplicate-ordinal",
        subject=session.identity.ref,
        kind="dependent",
        canonical_time=_START,
        action_id=session.action_id,
        transition_ordinal=session.transition_ordinal,
    )
    with pytest.raises(ValueError, match="action commit ordinal"):
        LifecycleActionCohortRequest(
            state_publication_token="opaque-invalid-ordinal",
            operations=(session, duplicate_ordinal),
        )

    registry = LifecycleRegistry()
    hold = LifecycleHold(
        hold_id="invalid-session:hold",
        subject=session.identity.ref,
        acquired_at=_START + timedelta(seconds=1),
        hold_until=_START + timedelta(seconds=5),
        action_id="invalid-session:hold-action",
        reason="retained dependent",
    )
    blocked = LifecycleActionCohortRequest(
        state_publication_token="opaque-invalid-close",
        operations=(
            session,
            hold,
            _closure(
                session.identity.ref,
                requested_at=_START + timedelta(seconds=4),
                suffix="invalid-session",
            ),
        ),
    )
    with pytest.raises(StateError, match="hold or lease"):
        registry.prepare_action_cohort(blocked)
    assert registry.get_session(session.identity.object_id) is None
    assert registry.action_cohort_preparation_census().reservations == 0

    registry.advance_watermark(_START)
    behind = LifecycleActionCohortRequest(
        state_publication_token="opaque-watermark-plan",
        operations=(_session_request(object_id="behind-session"),),
    )
    with pytest.raises(StateError, match="watermark"):
        registry.prepare_action_cohort(behind)


def test_action_cohort_preflights_durable_commit_capacity_without_partial_start(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(lifecycle_registry_module, "_MAX_DURABLE_COMMITS_PER_ENTITY", 3)
    session = _session_request(object_id="capacity-session")
    request = LifecycleActionCohortRequest(
        state_publication_token="opaque-capacity-plan",
        operations=(
            session,
            _closure(
                session.identity.ref,
                requested_at=_START + timedelta(seconds=1),
                suffix="capacity-session",
            ),
        ),
    )
    registry = LifecycleRegistry()

    with pytest.raises(StateError, match="durable commit bound"):
        registry.prepare_action_cohort(request)

    assert registry.get_session(session.identity.object_id) is None
    assert registry.action_cohort_preparation_census().reservations == 0


def test_action_cohort_opposite_partition_orders_do_not_deadlock() -> None:
    registry = LifecycleRegistry(shard_count=64)
    first_host = "HOST-000"
    first_partition = registry._partition_id(first_host)
    second_host = next(
        f"HOST-{ordinal:03d}"
        for ordinal in range(1, 100)
        if registry._partition_id(f"HOST-{ordinal:03d}") != first_partition
    )

    def request(prefix: str, hosts: tuple[str, str], pid_base: int) -> LifecycleActionCohortRequest:
        return LifecycleActionCohortRequest(
            state_publication_token=f"opaque-{prefix}-plan",
            operations=tuple(
                _process_request(
                    hostname=hostname,
                    object_id=f"{prefix}-{position}",
                    pid=pid_base + position * 4,
                    started_at=_START,
                )
                for position, hostname in enumerate(hosts)
            ),
        )

    requests = (
        request("forward", (first_host, second_host), 6100),
        request("reverse", (second_host, first_host), 6200),
    )
    tokens = tuple(registry.prepare_action_cohort(item) for item in requests)
    rendezvous = Barrier(2)
    failures: list[BaseException] = []

    def commit(token: LifecycleActionCohortAdmissionToken) -> None:
        try:
            with registry.claimed_action_cohort(token) as prepared:
                rendezvous.wait(timeout=2)
                prepared.commit_no_fail()
        except BaseException as exc:  # pragma: no cover - exercised in worker threads
            failures.append(exc)

    threads = tuple(Thread(target=commit, args=(token,), daemon=True) for token in tokens)
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=4)

    assert not any(thread.is_alive() for thread in threads)
    assert not failures
    assert registry.action_cohort_preparation_census().reservations == 0
    assert all(
        registry.get_process(operation.identity.object_id) is not None
        for item in requests
        for operation in item.operations
    )


def test_action_cohort_retry_provenance_rejects_state_token_laundering_and_eviction() -> None:
    registry = LifecycleRegistry()
    registry._action_cohort_provenance_capacity = 1
    first = LifecycleActionCohortRequest(
        state_publication_token="opaque-first-state-plan",
        operations=(_session_request(object_id="provenance-first"),),
    )
    first_token = registry.prepare_action_cohort(first)
    with registry.claimed_action_cohort(first_token) as prepared:
        first_receipt = prepared.commit_no_fail()

    exact_retry = registry.prepare_action_cohort(first)
    assert registry.action_cohort_preparation_census().committed_provenance == 1

    second = LifecycleActionCohortRequest(
        state_publication_token="opaque-second-state-plan",
        operations=(
            _session_request(
                object_id="provenance-second",
                logon_id="0x50002",
            ),
        ),
    )
    with pytest.raises(StateError, match="exhausted by active exact retries"):
        registry.prepare_action_cohort(second)
    registry.cancel_action_cohort(exact_retry)

    second_token = registry.prepare_action_cohort(second)
    assert registry.action_cohort_preparation_census().pending_provenance_evictions == 1
    with registry.claimed_action_cohort(second_token) as prepared:
        second_receipt = prepared.commit_no_fail()

    assert registry.authenticates_action_cohort_receipt(first_receipt, request=first)
    assert registry.authenticates_action_cohort_receipt(second_receipt, request=second)
    assert registry.action_cohort_preparation_census().committed_provenance == 1
    with pytest.raises(StateError, match="no matching original State/plan provenance"):
        registry.prepare_action_cohort(first)

    laundered = replace(second, state_publication_token="opaque-laundered-state-plan")
    with pytest.raises(StateError, match="cannot rebind existing lifecycle state"):
        registry.prepare_action_cohort(laundered)

    retry_token = registry.prepare_action_cohort(second)
    with registry.claimed_action_cohort(retry_token) as prepared:
        retry_receipt = prepared.commit_no_fail()
    assert retry_receipt == second_receipt
    assert retry_receipt is not second_receipt


def test_action_cohort_committing_fence_blocks_cancel_and_discard(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    registry = LifecycleRegistry()
    request = LifecycleActionCohortRequest(
        state_publication_token="opaque-committing-fence",
        operations=(_session_request(object_id="committing-session"),),
    )
    token = registry.prepare_action_cohort(request)
    entered = Event()
    release = Event()
    failures: list[BaseException] = []
    committing_counts: list[int] = []
    tail_caller_calls: list[str] = []
    original = registry._commit_action_cohort_primitives_locked

    class TailEvil:
        def __deepcopy__(self, memo: dict[int, object]) -> object:
            tail_caller_calls.append("deepcopy")
            raise AssertionError("primitive tail cannot invoke caller deepcopy")

        def __repr__(self) -> str:
            tail_caller_calls.append("repr")
            raise AssertionError("primitive tail cannot invoke caller repr")

        def __eq__(self, other: object) -> bool:
            tail_caller_calls.append("eq")
            raise AssertionError("primitive tail cannot invoke caller equality")

    def blocked_commit(call_plan: object) -> LifecycleActionCohortReceipt:
        entered.set()
        assert release.wait(timeout=2)
        return original(call_plan)  # type: ignore[arg-type]

    monkeypatch.setattr(registry, "_commit_action_cohort_primitives_locked", blocked_commit)

    def race_cancel_and_discard() -> None:
        assert entered.wait(timeout=2)
        committing_counts.append(
            registry.action_cohort_preparation_census().committing_reservations
        )
        _capture_failure(lambda: registry._cancel_claimed_action_cohort(token), failures)
        object.__setattr__(token.request, "state_publication_token", TailEvil())
        registry._discard_action_cohort_reservation_for_token(token)
        release.set()

    with registry.claimed_action_cohort(token) as prepared:
        racer = Thread(target=race_cancel_and_discard, daemon=True)
        racer.start()
        receipt = prepared.commit_no_fail()
        racer.join(timeout=2)

    assert not racer.is_alive()
    assert committing_counts == [1]
    assert len(failures) == 1
    assert isinstance(failures[0], StateError)
    assert "Committing" in str(failures[0])
    assert not tail_caller_calls
    assert registry.authenticates_action_cohort_receipt(receipt, request=request)
    assert registry.get_session("committing-session") is not None
    assert registry.action_cohort_preparation_census().reservations == 0


def test_action_cohort_recursive_closed_value_boundary_invokes_no_caller_code() -> None:
    calls: list[str] = []

    class EvilStr(str):
        def __deepcopy__(self, memo: dict[int, object]) -> str:
            calls.append("deepcopy")
            raise AssertionError("caller deepcopy must not execute")

        def __repr__(self) -> str:
            calls.append("repr")
            raise AssertionError("caller repr must not execute")

        def __eq__(self, other: object) -> bool:
            calls.append("eq")
            raise AssertionError("caller equality must not execute")

    class EvilDateTime(datetime):
        def __repr__(self) -> str:
            calls.append("datetime-repr")
            raise AssertionError("caller datetime repr must not execute")

    def mutate_state_token(request: LifecycleActionCohortRequest) -> None:
        object.__setattr__(request, "state_publication_token", EvilStr("evil-state"))

    def mutate_session_scalar(request: LifecycleActionCohortRequest) -> None:
        operation = request.operations[0]
        assert type(operation) is LifecycleSessionStartRequest
        object.__setattr__(operation.identity, "hostname", EvilStr("evil-host"))

    def mutate_process_integer(request: LifecycleActionCohortRequest) -> None:
        operation = request.operations[1]
        assert type(operation) is LifecycleProcessStartRequest
        object.__setattr__(operation.identity, "pid", True)

    def mutate_token_integer(request: LifecycleActionCohortRequest) -> None:
        operation = request.operations[1]
        assert type(operation) is LifecycleProcessStartRequest
        object.__setattr__(operation.token, "logon_type", True)

    def mutate_membership_scalar(request: LifecycleActionCohortRequest) -> None:
        operation = request.operations[1]
        assert type(operation) is LifecycleProcessStartRequest
        object.__setattr__(operation.membership, "owner_kind", EvilStr("session"))

    def mutate_dependent_time(request: LifecycleActionCohortRequest) -> None:
        operation = request.operations[3]
        assert type(operation) is LifecycleTransition
        evil_time = EvilDateTime(2026, 8, 17, 14, 0, 3, tzinfo=UTC)
        object.__setattr__(operation, "canonical_time", evil_time)

    def mutate_hold_scalar(request: LifecycleActionCohortRequest) -> None:
        operation = request.operations[4]
        assert type(operation) is LifecycleHold
        object.__setattr__(operation, "reason", EvilStr("evil-reason"))

    def mutate_barrier_scalar(request: LifecycleActionCohortRequest) -> None:
        operation = request.operations[5]
        assert type(operation) is LifecycleSubjectClosureControl
        object.__setattr__(operation.barrier.subject, "object_id", EvilStr("evil-child"))

    def mutate_ticket_scalar(request: LifecycleActionCohortRequest) -> None:
        operation = request.operations[5]
        assert type(operation) is LifecycleSubjectClosureControl
        object.__setattr__(operation, "ticket_id", EvilStr("evil-ticket"))

    mutations: tuple[Callable[[LifecycleActionCohortRequest], None], ...] = (
        mutate_state_token,
        mutate_session_scalar,
        mutate_process_integer,
        mutate_token_integer,
        mutate_membership_scalar,
        mutate_dependent_time,
        mutate_hold_scalar,
        mutate_barrier_scalar,
        mutate_ticket_scalar,
    )
    for mutate in mutations:
        registry = LifecycleRegistry()
        request = _closed_tree_request()
        mutate(request)
        before = registry.action_cohort_preparation_census()
        with pytest.raises((TypeError, ValueError)):
            registry.prepare_action_cohort(request)
        assert registry.action_cohort_preparation_census() == before
        assert registry.census().process_entries == 0
        assert registry.census().session_entries == 0
        assert not calls

    registry = LifecycleRegistry()
    authentic_request = LifecycleActionCohortRequest(
        state_publication_token="opaque-closed-receipt",
        operations=(
            _session_request(
                object_id="closed-receipt-session",
                logon_id="0x50009",
            ),
        ),
    )
    authentic_token = registry.prepare_action_cohort(authentic_request)
    with registry.claimed_action_cohort(authentic_token) as prepared:
        caller_receipt = prepared.commit_no_fail()
    session_result = caller_receipt.operation_results[0]
    assert type(session_result) is lifecycle_registry_module.SessionLifecycleSnapshot
    object.__setattr__(session_result.identity, "hostname", EvilStr("evil-receipt-host"))
    assert not registry.authenticates_action_cohort_receipt(caller_receipt)
    assert not calls

    retry_token = registry.prepare_action_cohort(authentic_request)
    with registry.claimed_action_cohort(retry_token) as prepared:
        isolated_retry = prepared.commit_no_fail()
    assert registry.authenticates_action_cohort_receipt(
        isolated_retry,
        request=authentic_request,
    )


def test_action_cohort_finite_caps_and_owner_pruning_are_zero_mutation() -> None:
    request = LifecycleActionCohortRequest(
        state_publication_token="opaque-cap-probe",
        operations=(_session_request(object_id="cap-probe-session"),),
    )
    capacity_cases = (
        ("_action_cohort_operation_capacity", 0, "operation capacity"),
        ("_action_cohort_reserved_key_capacity", 1, "reserved-key capacity"),
        ("_action_cohort_request_byte_capacity", 1, "request-byte capacity"),
        (
            "_action_cohort_provenance_capacity",
            0,
            "committed provenance capacity is zero",
        ),
    )
    for attribute, capacity, message in capacity_cases:
        registry = LifecycleRegistry()
        setattr(registry, attribute, capacity)
        before = registry.action_cohort_preparation_census()
        with pytest.raises(StateError, match=message):
            registry.prepare_action_cohort(request)
        assert registry.action_cohort_preparation_census() == before
        assert registry.get_session("cap-probe-session") is None

    registry = LifecycleRegistry()
    registry._action_cohort_reservation_capacity = 1
    retained = registry.prepare_action_cohort(request)
    retained_census = registry.action_cohort_preparation_census()
    assert retained_census.reservations == 1
    assert retained_census.unclaimed_reservations == 1
    assert retained_census.retained_request_bytes > 0
    with pytest.raises(StateError, match="reservation capacity"):
        registry.prepare_action_cohort(
            LifecycleActionCohortRequest(
                state_publication_token="opaque-cap-second",
                operations=(_session_request(object_id="cap-second-session"),),
            )
        )
    assert registry.action_cohort_preparation_census() == retained_census
    registry.cancel_action_cohort(retained)

    abandoned = registry.prepare_action_cohort(request)
    abandoned_ref = ref(abandoned)
    del abandoned
    assert abandoned_ref() is None
    assert registry.action_cohort_preparation_census().reservations == 1
    assert registry.prune_action_cohort_preparations() == 1
    assert registry.action_cohort_preparation_census().reservations == 0

    implicitly_abandoned = registry.prepare_action_cohort(request)
    implicit_ref = ref(implicitly_abandoned)
    del implicitly_abandoned
    assert implicit_ref() is None
    replacement = registry.prepare_action_cohort(
        LifecycleActionCohortRequest(
            state_publication_token="opaque-cap-replacement",
            operations=(_session_request(object_id="cap-replacement-session"),),
        )
    )
    assert registry.action_cohort_preparation_census().reservations == 1
    registry.advance_watermark(_START - timedelta(seconds=1))
    assert registry.action_cohort_preparation_census().reservations == 0
    assert not registry.authenticates_action_cohort_admission_token(replacement)
