# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Tests for the isolated append-only lifecycle registry foundation."""

from collections.abc import Iterator
from concurrent.futures import ThreadPoolExecutor
from dataclasses import FrozenInstanceError, replace
from datetime import UTC, datetime, timedelta
from threading import Barrier
from time import perf_counter

import pytest

import evidenceforge.generation.lifecycle_registry as lifecycle_registry_module
from evidenceforge.events.lifecycle import (
    LifecycleCloseAuthority,
    LifecycleCloseBarrier,
    LifecycleForegroundLease,
    LifecycleHold,
    LifecycleMembership,
    LifecycleRetentionLease,
    LifecycleSingletonLease,
    LifecycleTransition,
    LogicalServiceIdentity,
    ProcessLifecycleIdentity,
    ProcessTokenIdentity,
    ServiceInstanceLifecycleIdentity,
    ServiceProcessBindingIdentity,
    SessionLifecycleIdentity,
    TransportLifecycleIdentity,
    TransportSessionBindingIdentity,
)
from evidenceforge.events.network import NetworkTuple
from evidenceforge.generation.lifecycle_authority import GeneratorLifecycleAuthority
from evidenceforge.generation.lifecycle_registry import (
    LifecycleProcessStartRequest,
    LifecycleRegistry,
    LifecycleSessionStartRequest,
)
from evidenceforge.generation.lifecycle_shadow import LifecycleShadow
from evidenceforge.generation.state_manager import StateManager
from evidenceforge.models.exceptions import StateError

_START = datetime(2026, 1, 15, 12, 0, tzinfo=UTC)


def _register_session(
    registry: LifecycleRegistry,
    *,
    object_id: str = "session-1",
    logon_id: str = "0x11111",
    started_at: datetime = _START,
    hostname: str = "WS-01",
) -> SessionLifecycleIdentity:
    identity = SessionLifecycleIdentity(
        hostname=hostname,
        object_id=object_id,
        logon_id=logon_id,
        principal="analyst",
        session_kind="interactive",
        started_at=started_at,
        session_id=2,
    )
    registry.register_session(
        identity,
        action_id=f"action-{object_id}",
        transition_id=f"transition-{object_id}-start",
    )
    return identity


def _register_process(
    registry: LifecycleRegistry,
    *,
    object_id: str = "process-1",
    pid: int = 4100,
    started_at: datetime = _START + timedelta(seconds=1),
    session_object_id: str = "session-1",
    parent_object_id: str = "",
    token_logon_id: str = "0x3e7",
    hostname: str = "WS-01",
    role: str = "application",
) -> ProcessLifecycleIdentity:
    identity = ProcessLifecycleIdentity(
        hostname=hostname,
        object_id=object_id,
        pid=pid,
        started_at=started_at,
        image=rf"C:\Windows\System32\{object_id}.exe",
        parent_object_id=parent_object_id,
        role=role,
    )
    membership = (
        LifecycleMembership(
            owner_kind="session",
            owner_object_id=session_object_id,
            session_object_id=session_object_id,
        )
        if session_object_id
        else LifecycleMembership(
            owner_kind="boot",
            owner_object_id=f"boot-{hostname}",
        )
    )
    registry.register_process(
        identity,
        token=ProcessTokenIdentity(
            principal="SYSTEM" if token_logon_id == "0x3e7" else "analyst",
            logon_id=token_logon_id,
            session_id=0 if token_logon_id == "0x3e7" else 2,
            logon_type=5 if token_logon_id == "0x3e7" else 2,
        ),
        membership=membership,
        action_id=f"action-{object_id}",
        transition_id=f"transition-{object_id}-start",
    )
    return identity


def _foreground_lease(
    *,
    lease_id: str = "foreground-1",
    process_object_id: str = "shell-process",
    acquired_at: datetime = _START + timedelta(seconds=2),
    lease_until: datetime = _START + timedelta(minutes=2),
    action_id: str = "foreground-acquire",
    concurrency_group_id: str = "",
) -> LifecycleForegroundLease:
    return LifecycleForegroundLease(
        lease_id=lease_id,
        hostname="WS-01",
        principal="analyst",
        session_object_id="session-1",
        process_object_id=process_object_id,
        acquired_at=acquired_at,
        lease_until=lease_until,
        action_id=action_id,
        concurrency_group_id=concurrency_group_id,
    )


def _singleton_lease(
    *,
    lease_id: str,
    acquired_at: datetime,
    lease_until: datetime,
    process_object_id: str = "",
    action_id: str | None = None,
) -> LifecycleSingletonLease:
    return LifecycleSingletonLease(
        lease_id=lease_id,
        hostname="WS-01",
        principal="analyst",
        session_object_id="session-1",
        logon_id="0x11111",
        canonical_image=r"C:\Windows\System32\singleton-process.exe",
        process_object_id=process_object_id,
        acquired_at=acquired_at,
        lease_until=lease_until,
        action_id=action_id or f"acquire-{lease_id}",
    )


def _request_and_close(
    registry: LifecycleRegistry,
    identity: (
        ProcessLifecycleIdentity
        | SessionLifecycleIdentity
        | ServiceInstanceLifecycleIdentity
        | TransportLifecycleIdentity
    ),
    *,
    requested_at: datetime,
    authority: LifecycleCloseAuthority = "generated",
) -> datetime:
    barrier = LifecycleCloseBarrier(
        barrier_id=f"barrier-{identity.object_id}",
        subject=identity.ref,
        requested_at=requested_at,
        authority=authority,
        action_id=f"close-{identity.object_id}",
    )
    ticket = registry.request_close(barrier, ticket_id=f"ticket-{identity.object_id}")
    registry.close(ticket.ticket_id)
    return ticket.effective_at


def test_process_identity_token_and_membership_are_independently_frozen() -> None:
    registry = LifecycleRegistry()
    session = _register_session(registry)
    process = _register_process(registry)

    snapshot = registry.get_process(process.object_id)

    assert snapshot is not None
    assert snapshot.identity == process
    assert snapshot.token.logon_id == "0x3e7"
    assert snapshot.membership.session_object_id == session.object_id
    assert snapshot.token.logon_id != session.logon_id
    with pytest.raises(FrozenInstanceError):
        snapshot.token.logon_id = session.logon_id
    with pytest.raises(FrozenInstanceError):
        snapshot.membership.session_object_id = "session-2"


def test_prepared_session_registration_is_cancelled_without_commit() -> None:
    registry = LifecycleRegistry()
    identity = SessionLifecycleIdentity(
        hostname="WS-01",
        object_id="prepared-session",
        logon_id="0x20001",
        principal="analyst",
        session_kind="interactive",
        started_at=_START,
        session_id=2,
    )

    with registry.prepare_session_registration(
        identity,
        action_id="prepared-session-action",
        transition_id="prepared-session-transition",
    ) as ticket:
        assert not ticket.committed
        assert registry.get_session(identity.object_id) is None

    assert registry.get_session(identity.object_id) is None
    with pytest.raises(StateError, match="no longer active"):
        ticket.commit()


def test_prepared_process_registration_commits_exactly_once() -> None:
    registry = LifecycleRegistry()
    session = _register_session(registry)
    identity = ProcessLifecycleIdentity(
        hostname="WS-01",
        object_id="prepared-process",
        pid=4200,
        started_at=_START + timedelta(seconds=1),
        image=r"C:\Windows\System32\cmd.exe",
    )
    token = ProcessTokenIdentity(
        principal="analyst",
        logon_id=session.logon_id,
        session_id=session.session_id,
        logon_type=2,
        integrity_level="Medium",
    )
    membership = LifecycleMembership(
        owner_kind="session",
        owner_object_id=session.object_id,
        session_object_id=session.object_id,
    )

    with registry.prepare_process_registration(
        identity,
        token=token,
        membership=membership,
        action_id="prepared-process-action",
        transition_id="prepared-process-transition",
    ) as ticket:
        assert registry.get_process(identity.object_id) is None
        first = ticket.commit()
        second = ticket.commit()

    assert first == second
    assert ticket.committed
    assert registry.get_process(identity.object_id) == first


def test_prepared_start_batch_cancels_session_and_process_when_one_child_is_invalid() -> None:
    registry = LifecycleRegistry()
    session = SessionLifecycleIdentity(
        hostname="WS-01",
        object_id="batch-session",
        logon_id="0x30001",
        principal="analyst",
        session_kind="interactive",
        started_at=_START,
        session_id=3,
    )
    process = ProcessLifecycleIdentity(
        hostname="WS-01",
        object_id="batch-process",
        pid=4300,
        started_at=_START + timedelta(seconds=1),
        image=r"C:\Windows\System32\cmd.exe",
        parent_object_id="missing-parent",
    )

    with pytest.raises(StateError, match="unknown parent"):
        with registry.prepare_start_batch(
            sessions=(
                LifecycleSessionStartRequest(
                    identity=session,
                    action_id="batch-session-action",
                    transition_id="batch-session-transition",
                ),
            ),
            processes=(
                LifecycleProcessStartRequest(
                    identity=process,
                    token=ProcessTokenIdentity(
                        principal="analyst",
                        logon_id=session.logon_id,
                        session_id=session.session_id,
                        logon_type=2,
                        integrity_level="Medium",
                    ),
                    membership=LifecycleMembership(
                        owner_kind="session",
                        owner_object_id=session.object_id,
                        session_object_id=session.object_id,
                    ),
                    action_id="batch-process-action",
                    transition_id="batch-process-transition",
                ),
            ),
        ):
            pytest.fail("invalid batch must fail before yielding a ticket")

    assert registry.get_session(session.object_id) is None
    assert registry.get_process(process.object_id) is None
    assert registry.stats().transitions == 0


def test_prepared_start_batch_valid_cancel_and_idempotent_commit_are_all_or_none() -> None:
    registry = LifecycleRegistry()
    session = SessionLifecycleIdentity(
        hostname="WS-01",
        object_id="valid-batch-session",
        logon_id="0x30002",
        principal="analyst",
        session_kind="interactive",
        started_at=_START,
        session_id=4,
    )
    parent = ProcessLifecycleIdentity(
        hostname="WS-01",
        object_id="valid-batch-parent",
        pid=4400,
        started_at=_START + timedelta(milliseconds=1),
        image=r"C:\Windows\System32\cmd.exe",
    )
    child = ProcessLifecycleIdentity(
        hostname="WS-01",
        object_id="valid-batch-child",
        pid=4404,
        started_at=_START + timedelta(milliseconds=2),
        image=r"C:\Windows\System32\powershell.exe",
        parent_object_id=parent.object_id,
    )
    session_request = LifecycleSessionStartRequest(
        identity=session,
        action_id="valid-batch-session-action",
        transition_id="valid-batch-session-transition",
    )

    def _process_request(
        identity: ProcessLifecycleIdentity,
        suffix: str,
    ) -> LifecycleProcessStartRequest:
        return LifecycleProcessStartRequest(
            identity=identity,
            token=ProcessTokenIdentity(
                principal="analyst",
                logon_id=session.logon_id,
                session_id=session.session_id,
                logon_type=2,
                integrity_level="Medium",
            ),
            membership=LifecycleMembership(
                owner_kind="session",
                owner_object_id=session.object_id,
                session_object_id=session.object_id,
            ),
            action_id=f"valid-batch-{suffix}-action",
            transition_id=f"valid-batch-{suffix}-transition",
        )

    process_requests = (
        _process_request(parent, "parent"),
        _process_request(child, "child"),
    )
    census_before = registry.census()
    with registry.prepare_start_batch(
        sessions=(session_request,),
        processes=process_requests,
    ):
        pass

    assert registry.census() == census_before
    assert registry.get_session(session.object_id) is None
    assert registry.get_process(parent.object_id) is None
    assert registry.get_process(child.object_id) is None

    with registry.prepare_start_batch(
        sessions=(session_request,),
        processes=process_requests,
    ) as ticket:
        first = ticket.commit()
        second = ticket.commit()

    assert first == second
    assert ticket.committed
    assert registry.get_session(session.object_id) == first[0][0]
    assert registry.get_process(parent.object_id) == first[1][0]
    assert registry.get_process(child.object_id) == first[1][1]
    assert first[1][1].identity.parent_object_id == parent.object_id


def test_two_partition_start_batches_acquire_locks_in_one_global_order() -> None:
    registry = LifecycleRegistry(shard_count=64)
    first_host = "HOST-000"
    first_partition = registry._partition_id(first_host)
    second_host = next(
        f"HOST-{ordinal:03d}"
        for ordinal in range(1, 100)
        if registry._partition_id(f"HOST-{ordinal:03d}") != first_partition
    )
    barrier = Barrier(2)

    def _request(hostname: str, suffix: str, pid: int) -> LifecycleProcessStartRequest:
        identity = ProcessLifecycleIdentity(
            hostname=hostname,
            object_id=f"process-{suffix}",
            pid=pid,
            started_at=_START,
            image="bootstrap",
        )
        return LifecycleProcessStartRequest(
            identity=identity,
            token=ProcessTokenIdentity(
                principal="SYSTEM",
                logon_id="0x3e7",
                session_id=0,
                logon_type=5,
                integrity_level="System",
            ),
            membership=LifecycleMembership(
                owner_kind="boot",
                owner_object_id=f"boot-{hostname}",
            ),
            action_id=f"action-{suffix}",
            transition_id=f"transition-{suffix}",
        )

    batches = (
        (
            _request(first_host, "a-first", 4100),
            _request(second_host, "a-second", 4104),
        ),
        (
            _request(second_host, "b-second", 4200),
            _request(first_host, "b-first", 4204),
        ),
    )

    def _commit(requests: tuple[LifecycleProcessStartRequest, ...]) -> None:
        barrier.wait()
        with registry.prepare_start_batch(processes=requests) as ticket:
            ticket.commit()

    with ThreadPoolExecutor(max_workers=2) as executor:
        futures = [executor.submit(_commit, requests) for requests in batches]
        for future in futures:
            future.result(timeout=5)

    assert registry.stats().live_processes == 4


def test_packed_session_snapshot_stays_frozen_when_registry_state_promotes() -> None:
    registry = LifecycleRegistry()
    session = _register_session(registry)
    start_snapshot = registry.get_session(session.object_id)

    assert start_snapshot is not None
    registry.record_dependent(
        session.ref,
        transition_id="transition-session-dependent",
        canonical_time=_START + timedelta(seconds=1),
        action_id="session-dependent",
    )
    registry.register_session(
        session,
        action_id=f"action-{session.object_id}",
        transition_id=f"transition-{session.object_id}-start",
    )
    promoted_snapshot = registry.get_session(session.object_id)

    assert promoted_snapshot is not None
    assert start_snapshot.transition_count == 1
    assert len(start_snapshot.transitions) == 1
    assert promoted_snapshot.transition_count == 2
    assert len(promoted_snapshot.transitions) == 2
    with pytest.raises(FrozenInstanceError):
        start_snapshot.identity = session


def test_future_close_preserves_time_explicit_process_and_session_history() -> None:
    registry = LifecycleRegistry()
    session = _register_session(registry)
    process = _register_process(registry)
    close_at = _START + timedelta(minutes=5)

    _request_and_close(registry, process, requested_at=close_at)
    _request_and_close(registry, session, requested_at=close_at + timedelta(seconds=1))

    assert registry.process_at(process.object_id, close_at - timedelta(microseconds=1)) is not None
    assert registry.process_at(process.object_id, close_at) is None
    assert registry.session_at(session.object_id, close_at) is not None
    assert registry.session_at(session.object_id, close_at + timedelta(seconds=1)) is None
    assert registry.get_process(process.object_id).closed_at == close_at  # type: ignore[union-attr]


def test_pid_reuse_resolves_exact_process_for_canonical_time() -> None:
    registry = LifecycleRegistry()
    _register_session(registry)
    first = _register_process(registry, object_id="process-first", pid=4200)
    first_close = _START + timedelta(minutes=1)
    _request_and_close(registry, first, requested_at=first_close)
    second = _register_process(
        registry,
        object_id="process-second",
        pid=4200,
        started_at=first_close + timedelta(seconds=1),
    )

    early = registry.process_for_pid_at("WS-01", 4200, first.started_at)
    late = registry.process_for_pid_at("WS-01", 4200, second.started_at)

    assert early is not None and early.identity.object_id == first.object_id
    assert late is not None and late.identity.object_id == second.object_id


def test_generated_close_extends_through_latest_hold_and_appends_transitions() -> None:
    registry = LifecycleRegistry()
    _register_session(registry)
    process = _register_process(registry)
    hold_until = _START + timedelta(minutes=3)
    registry.add_hold(
        LifecycleHold(
            hold_id="hold-network",
            subject=process.ref,
            acquired_at=_START + timedelta(seconds=2),
            hold_until=hold_until,
            action_id="network-action",
            reason="transport_close",
        )
    )
    barrier = LifecycleCloseBarrier(
        barrier_id="barrier-process-1",
        subject=process.ref,
        requested_at=_START + timedelta(minutes=1),
        authority="generated",
        action_id="close-process-1",
    )

    ticket = registry.request_close(barrier, ticket_id="ticket-process-1")
    closed = registry.close(ticket.ticket_id)

    assert ticket.effective_at == hold_until
    assert closed.closed_at == hold_until
    assert [transition.kind for transition in closed.transitions] == [
        "started",
        "hold_acquired",
        "close_requested",
        "close_scheduled",
        "closed",
    ]
    assert registry.hold("hold-network") is not None
    assert registry.closure_ticket(ticket.ticket_id) == ticket


def test_authoritative_close_conflict_is_atomic() -> None:
    registry = LifecycleRegistry()
    _register_session(registry)
    process = _register_process(registry)
    registry.add_hold(
        LifecycleHold(
            hold_id="hold-file",
            subject=process.ref,
            acquired_at=_START + timedelta(seconds=2),
            hold_until=_START + timedelta(minutes=2),
            action_id="file-action",
            reason="file_write",
        )
    )
    barrier = LifecycleCloseBarrier(
        barrier_id="barrier-authoritative",
        subject=process.ref,
        requested_at=_START + timedelta(minutes=1),
        authority="authoritative",
        action_id="story-logoff",
    )

    with pytest.raises(StateError, match="conflicts with a hold"):
        registry.request_close(barrier, ticket_id="ticket-authoritative")

    snapshot = registry.get_process(process.object_id)
    assert snapshot is not None
    assert snapshot.close_barrier is None
    assert snapshot.closure_ticket is None
    assert registry.stats().close_barriers == 0
    assert registry.stats().closure_tickets == 0


def test_close_barrier_rejects_new_dependents_and_holds() -> None:
    registry = LifecycleRegistry()
    _register_session(registry)
    process = _register_process(registry)
    barrier_at = _START + timedelta(minutes=1)
    registry.request_close(
        LifecycleCloseBarrier(
            barrier_id="barrier-process-1",
            subject=process.ref,
            requested_at=barrier_at,
            authority="generated",
            action_id="close-process-1",
        ),
        ticket_id="ticket-process-1",
    )

    with pytest.raises(StateError, match="close barrier"):
        registry.record_dependent(
            process.ref,
            transition_id="late-dependent",
            canonical_time=barrier_at,
            action_id="late-action",
        )
    with pytest.raises(StateError, match="already has a close barrier"):
        registry.add_hold(
            LifecycleHold(
                hold_id="late-hold",
                subject=process.ref,
                acquired_at=barrier_at - timedelta(seconds=1),
                hold_until=barrier_at + timedelta(seconds=1),
                action_id="late-action",
                reason="late_transport",
            )
        )


def test_parent_and_session_must_be_active_at_process_start() -> None:
    registry = LifecycleRegistry()
    _register_session(registry)
    parent = _register_process(
        registry,
        object_id="parent",
        pid=4300,
        session_object_id="",
    )
    parent_close = _START + timedelta(minutes=1)
    _request_and_close(registry, parent, requested_at=parent_close)

    with pytest.raises(StateError, match="parent .* is not active"):
        _register_process(
            registry,
            object_id="child",
            pid=4301,
            parent_object_id=parent.object_id,
            started_at=parent_close,
        )


def test_closed_parent_and_session_reject_backdated_membership() -> None:
    registry = LifecycleRegistry()
    session = _register_session(registry)
    parent = _register_process(
        registry,
        object_id="closed-parent",
        pid=4350,
        session_object_id="",
    )
    _request_and_close(
        registry,
        parent,
        requested_at=_START + timedelta(minutes=2),
    )
    _request_and_close(
        registry,
        session,
        requested_at=_START + timedelta(minutes=3),
    )

    with pytest.raises(StateError, match="parent .* is not active"):
        _register_process(
            registry,
            object_id="backdated-child",
            pid=4351,
            parent_object_id=parent.object_id,
            session_object_id="",
            started_at=_START + timedelta(minutes=1),
        )
    with pytest.raises(StateError, match="session .* is not active"):
        _register_process(
            registry,
            object_id="backdated-member",
            pid=4352,
            started_at=_START + timedelta(minutes=1),
        )


def test_retention_leases_bound_eviction_and_stats() -> None:
    registry = LifecycleRegistry(closed_retention=timedelta(hours=1))
    _register_session(registry)
    process = _register_process(registry)
    close_at = _START + timedelta(minutes=1)
    _request_and_close(registry, process, requested_at=close_at)
    lease = LifecycleRetentionLease(
        lease_id="ground-truth-reference",
        subject=process.ref,
        retain_until=close_at + timedelta(hours=2),
        reason="pending_ground_truth",
    )
    registry.add_retention_lease(lease)

    assert registry.advance_watermark(close_at + timedelta(hours=1)) == ()
    retained = registry.stats()
    assert retained.retained_processes == 1
    assert retained.retention_leases == 1
    assert registry.get_process(process.object_id) is not None

    evicted = registry.advance_watermark(lease.retain_until)

    assert evicted == (process.ref,)
    assert registry.get_process(process.object_id) is None
    assert registry.transition("transition-process-1-start") is None
    stats = registry.stats()
    assert stats.process_entries == 0
    assert stats.evicted_processes == 1
    assert stats.retention_leases == 0
    assert stats.high_water_processes == 1


def test_many_retention_leases_use_one_exact_subject_deadline_candidate(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    registry = LifecycleRegistry(shard_count=1, closed_retention=timedelta(minutes=1))
    _register_session(registry)
    process = _register_process(registry, object_id="many-retention-leases")
    lease_count = 5_000
    latest_deadline = _START + timedelta(hours=2, microseconds=lease_count - 1)
    for ordinal in range(lease_count):
        registry.add_retention_lease(
            LifecycleRetentionLease(
                lease_id=f"retention-skew-{ordinal}",
                subject=process.ref,
                retain_until=_START + timedelta(hours=2, microseconds=ordinal),
                reason="single_subject_scale",
            )
        )

    partition = registry._partitions[0]

    def reject_subject_scan(*_args: object, **_kwargs: object) -> Iterator[object]:
        raise AssertionError("retention deadline lookup scanned the lease store")

    monkeypatch.setattr(partition._leases, "find_iter", reject_subject_scan)
    before = registry.census()
    _request_and_close(
        registry,
        process,
        requested_at=_START + timedelta(minutes=1),
    )
    after = registry.census()

    assert registry.retention_deadline(process.ref) == latest_deadline
    assert after.retention_lease_subjects == 1
    assert after.retention_lease_subject_bindings == lease_count
    assert after.retention_lease_max_subject_bindings == lease_count
    assert (
        after.retention_lease_deadline_candidates_inspected
        - before.retention_lease_deadline_candidates_inspected
        == 1
    )
    assert after.lookup_candidates_inspected - before.lookup_candidates_inspected == 1


def test_watermark_is_monotonic() -> None:
    registry = LifecycleRegistry()
    registry.advance_watermark(_START)

    with pytest.raises(StateError, match="cannot move backward"):
        registry.advance_watermark(_START - timedelta(seconds=1))


def test_temporal_queries_use_grouped_compact_handles_and_report_census() -> None:
    registry = LifecycleRegistry()
    session = _register_session(registry)
    process = _register_process(registry)
    for offset in range(20):
        _register_process(
            registry,
            object_id=f"unrelated-{offset}",
            pid=5000 + offset,
            started_at=_START + timedelta(seconds=offset + 2),
        )

    before = registry.census()
    assert registry.get_process(process.object_id) is not None
    assert registry.get_session(session.object_id) is not None
    assert registry.stats().candidates_inspected == before.candidates_inspected

    resolved_process = registry.process_for_pid_at(
        process.hostname,
        process.pid,
        process.started_at + timedelta(seconds=1),
    )
    resolved_session = registry.session_for_logon_at(
        session.hostname,
        session.logon_id,
        session.started_at + timedelta(seconds=1),
    )

    census = registry.census()
    assert resolved_process is not None and resolved_process.identity == process
    assert resolved_session is not None and resolved_session.identity == session
    assert census.candidates_inspected - before.candidates_inspected == 2
    assert census.lookup_candidates_inspected == census.candidates_inspected
    assert census.process_index_backing_entries == census.process_entries
    assert census.session_index_backing_entries == census.session_entries
    assert census.process_temporal_live_entries == census.process_entries
    assert census.session_temporal_live_entries == census.session_entries
    assert census.process_temporal_groups == 21
    assert census.session_temporal_groups == 1
    assert census.temporal_stale_entries == 0
    assert census.estimated_bytes > 0


def test_eviction_compacts_temporal_index_and_reuses_store_handle_safely() -> None:
    registry = LifecycleRegistry(closed_retention=timedelta(seconds=1))
    _register_session(registry)
    first = _register_process(registry, object_id="process-first", pid=6200)
    close_at = _START + timedelta(minutes=1)
    _request_and_close(registry, first, requested_at=close_at)

    assert registry.advance_watermark(close_at + timedelta(seconds=1)) == (first.ref,)
    after_eviction = registry.census()
    assert after_eviction.process_entries == 0
    assert after_eviction.process_temporal_live_entries == 0

    second = _register_process(
        registry,
        object_id="process-second",
        pid=first.pid,
        started_at=close_at + timedelta(seconds=2),
    )
    resolved = registry.process_for_pid_at(
        second.hostname,
        second.pid,
        second.started_at + timedelta(seconds=1),
    )

    assert resolved is not None and resolved.identity == second
    assert registry.get_process(first.object_id) is None
    census = registry.census()
    assert census.process_entries == 1
    assert census.process_index_backing_entries == 1
    assert census.process_temporal_live_entries == 1
    assert census.process_temporal_backing_entries == 1


def test_session_logon_reuse_remains_time_exact_after_handle_reuse() -> None:
    registry = LifecycleRegistry(closed_retention=timedelta(seconds=1))
    first = _register_session(registry, object_id="session-first", logon_id="0x6200")
    close_at = _START + timedelta(minutes=1)
    _request_and_close(registry, first, requested_at=close_at)
    registry.advance_watermark(close_at + timedelta(seconds=1))
    second = _register_session(
        registry,
        object_id="session-second",
        logon_id=first.logon_id,
        started_at=close_at + timedelta(seconds=2),
    )

    resolved = registry.session_for_logon_at(
        second.hostname,
        second.logon_id,
        second.started_at + timedelta(seconds=1),
    )

    assert resolved is not None and resolved.identity == second
    assert registry.get_session(first.object_id) is None
    census = registry.census()
    assert census.session_entries == 1
    assert census.session_index_backing_entries == 1
    assert census.session_temporal_live_entries == 1
    assert census.session_temporal_backing_entries == 1


def test_bulk_retention_eviction_reclaims_empty_temporal_groups() -> None:
    registry = LifecycleRegistry(closed_retention=timedelta(seconds=1))
    _register_session(registry)
    close_at = _START + timedelta(minutes=1)
    processes = [
        _register_process(
            registry,
            object_id=f"ephemeral-{offset}",
            pid=7000 + offset,
        )
        for offset in range(32)
    ]
    for process in processes:
        _request_and_close(registry, process, requested_at=close_at)

    evicted = registry.advance_watermark(close_at + timedelta(seconds=1))

    assert len(evicted) == len(processes)
    census = registry.census()
    assert census.process_entries == 0
    assert census.process_temporal_live_entries == 0
    assert census.process_temporal_backing_entries == 0
    assert census.process_temporal_groups == 0
    assert census.temporal_stale_entries == 0


def test_process_and_session_close_reject_active_descendants() -> None:
    registry = LifecycleRegistry()
    session = _register_session(registry)
    parent = _register_process(
        registry,
        object_id="parent",
        pid=8100,
        session_object_id="",
    )
    child = _register_process(
        registry,
        object_id="child",
        pid=8101,
        parent_object_id=parent.object_id,
    )
    parent_barrier = LifecycleCloseBarrier(
        barrier_id="barrier-parent",
        subject=parent.ref,
        requested_at=_START + timedelta(minutes=5),
        authority="generated",
        action_id="close-parent",
    )
    parent_ticket = registry.request_close(parent_barrier, ticket_id="ticket-parent")
    session_barrier = LifecycleCloseBarrier(
        barrier_id="barrier-session",
        subject=session.ref,
        requested_at=_START + timedelta(minutes=6),
        authority="generated",
        action_id="close-session",
    )
    session_ticket = registry.request_close(session_barrier, ticket_id="ticket-session")

    with pytest.raises(StateError, match="child processes remain active"):
        registry.close(parent_ticket.ticket_id)
    with pytest.raises(StateError, match="session members remain active"):
        registry.close(session_ticket.ticket_id)

    _request_and_close(
        registry,
        child,
        requested_at=_START + timedelta(minutes=4),
    )
    registry.close(parent_ticket.ticket_id)
    registry.close(session_ticket.ticket_id)


def test_parent_close_rejects_child_whose_resolved_close_is_later() -> None:
    registry = LifecycleRegistry()
    _register_session(registry)
    parent = _register_process(
        registry,
        object_id="parent-late-child",
        pid=8200,
        session_object_id="",
    )
    child = _register_process(
        registry,
        object_id="child-closes-late",
        pid=8201,
        parent_object_id=parent.object_id,
    )
    _request_and_close(
        registry,
        child,
        requested_at=_START + timedelta(minutes=6),
    )
    ticket = registry.request_close(
        LifecycleCloseBarrier(
            barrier_id="barrier-parent-late-child",
            subject=parent.ref,
            requested_at=_START + timedelta(minutes=5),
            authority="generated",
            action_id="close-parent-late-child",
        ),
        ticket_id="ticket-parent-late-child",
    )

    with pytest.raises(StateError, match="child processes remain active"):
        registry.close(ticket.ticket_id)


def test_accepted_barriers_reject_later_child_and_member_starts() -> None:
    registry = LifecycleRegistry()
    session = _register_session(registry)
    parent = _register_process(
        registry,
        object_id="barrier-parent",
        pid=8300,
        session_object_id="",
    )
    for subject, prefix in ((parent.ref, "parent"), (session.ref, "session")):
        registry.add_hold(
            LifecycleHold(
                hold_id=f"hold-{prefix}",
                subject=subject,
                acquired_at=_START + timedelta(minutes=1),
                hold_until=_START + timedelta(minutes=10),
                action_id=f"hold-{prefix}",
                reason="foreground_transport",
            )
        )
        ticket = registry.request_close(
            LifecycleCloseBarrier(
                barrier_id=f"barrier-{prefix}",
                subject=subject,
                requested_at=_START + timedelta(minutes=5),
                authority="generated",
                action_id=f"close-{prefix}",
            ),
            ticket_id=f"ticket-{prefix}",
        )
        assert ticket.effective_at == _START + timedelta(minutes=10)

    with pytest.raises(StateError, match="accepted close barrier"):
        _register_process(
            registry,
            object_id="late-child",
            pid=8301,
            parent_object_id=parent.object_id,
            session_object_id="",
            started_at=_START + timedelta(minutes=6),
        )
    with pytest.raises(StateError, match="accepted close barrier"):
        _register_process(
            registry,
            object_id="late-member",
            pid=8302,
            started_at=_START + timedelta(minutes=6),
        )


def test_snapshot_history_is_bounded_sorted_and_aggregates_compacted_holds() -> None:
    registry = LifecycleRegistry(snapshot_history_limit=4)
    _register_session(registry)
    process = _register_process(registry)
    long_hold_until = _START + timedelta(minutes=30)
    registry.add_hold(
        LifecycleHold(
            hold_id="early-long-hold",
            subject=process.ref,
            acquired_at=_START + timedelta(seconds=2),
            hold_until=long_hold_until,
            action_id="hold-000",
            reason="long_transport",
        )
    )
    for ordinal in reversed(range(20)):
        registry.record_dependent(
            process.ref,
            transition_id=f"dependent-{ordinal:02d}",
            canonical_time=_START + timedelta(seconds=ordinal + 3),
            action_id=f"dependent-action-{ordinal:02d}",
        )
        registry.add_hold(
            LifecycleHold(
                hold_id=f"short-hold-{ordinal:02d}",
                subject=process.ref,
                acquired_at=_START + timedelta(seconds=ordinal + 30),
                hold_until=_START + timedelta(minutes=2, seconds=ordinal),
                action_id=f"short-hold-action-{ordinal:02d}",
                reason="short_transport",
            )
        )

    snapshot = registry.get_process(process.object_id)
    assert snapshot is not None
    assert len(snapshot.transitions) == registry.snapshot_history_limit
    assert len(snapshot.holds) == registry.snapshot_history_limit
    assert snapshot.transition_count == 42
    assert snapshot.compacted_transition_count == 38
    assert snapshot.hold_count == 21
    assert snapshot.compacted_hold_count == 17
    assert snapshot.latest_hold_until == long_hold_until
    assert [item.order_key for item in snapshot.transitions] == sorted(
        item.order_key for item in snapshot.transitions
    )
    assert len(snapshot.transition_ledger_digest) == 64
    assert len(snapshot.hold_ledger_digest) == 64

    ticket = registry.request_close(
        LifecycleCloseBarrier(
            barrier_id="bounded-ledger-close",
            subject=process.ref,
            requested_at=_START + timedelta(minutes=3),
            authority="generated",
            action_id="bounded-ledger-close",
        ),
        ticket_id="bounded-ledger-ticket",
    )
    assert ticket.effective_at == long_hold_until


def test_action_commit_identity_rejects_ordinal_reuse() -> None:
    registry = LifecycleRegistry()
    _register_session(registry)
    process = _register_process(registry)
    registry.record_dependent(
        process.ref,
        transition_id="commit-first",
        canonical_time=_START + timedelta(seconds=2),
        action_id="shared-action",
        transition_ordinal=7,
    )

    with pytest.raises(StateError, match="action commit identity"):
        registry.record_dependent(
            process.ref,
            transition_id="commit-second",
            canonical_time=_START + timedelta(seconds=3),
            action_id="shared-action",
            transition_ordinal=7,
        )


def test_reused_pid_and_logon_predecessor_queries_inspect_constant_candidates() -> None:
    registry = LifecycleRegistry(closed_retention=timedelta(days=30))
    session = _register_session(registry)
    pid = 9100
    process_count = 1_000
    last_process: ProcessLifecycleIdentity | None = None
    for ordinal in range(process_count):
        started_at = _START + timedelta(seconds=ordinal * 2 + 1)
        process = _register_process(
            registry,
            object_id=f"reused-process-{ordinal:04d}",
            pid=pid,
            started_at=started_at,
        )
        _request_and_close(
            registry,
            process,
            requested_at=started_at + timedelta(seconds=1),
        )
        last_process = process

    assert last_process is not None
    before_query = registry.census().candidates_inspected
    resolved = registry.process_for_pid_at(
        last_process.hostname,
        pid,
        last_process.started_at,
    )
    assert resolved is not None and resolved.identity == last_process
    assert registry.census().candidates_inspected - before_query == 1

    before_overlap = registry.census().candidates_inspected
    with pytest.raises(StateError, match="PID overlap"):
        _register_process(
            registry,
            object_id="reused-process-backfill",
            pid=pid,
            started_at=_START + timedelta(seconds=500),
        )
    assert registry.census().candidates_inspected - before_overlap <= 2

    _request_and_close(
        registry,
        session,
        requested_at=_START + timedelta(hours=1),
    )
    logon_id = "0x9999"
    last_session: SessionLifecycleIdentity | None = None
    for ordinal in range(process_count):
        started_at = _START + timedelta(hours=2, seconds=ordinal * 2)
        reused_session = _register_session(
            registry,
            object_id=f"reused-session-{ordinal:04d}",
            logon_id=logon_id,
            started_at=started_at,
        )
        _request_and_close(
            registry,
            reused_session,
            requested_at=started_at + timedelta(seconds=1),
        )
        last_session = reused_session

    assert last_session is not None
    before_query = registry.census().candidates_inspected
    resolved_session = registry.session_for_logon_at(
        last_session.hostname,
        logon_id,
        last_session.started_at,
    )
    assert resolved_session is not None and resolved_session.identity == last_session
    assert registry.census().candidates_inspected - before_query == 1

    before_overlap = registry.census().candidates_inspected
    with pytest.raises(StateError, match="LogonID overlap"):
        _register_session(
            registry,
            object_id="reused-session-backfill",
            logon_id=logon_id,
            started_at=_START + timedelta(hours=2, seconds=500),
        )
    assert registry.census().candidates_inspected - before_overlap <= 2


def _run_concurrent_lifecycle_program(
    workers: int,
) -> tuple[tuple[object, ...], float]:
    registry = LifecycleRegistry(snapshot_history_limit=12)
    processes: list[ProcessLifecycleIdentity] = []
    sessions: list[SessionLifecycleIdentity] = []
    host_count = 12
    actions_per_host = 32
    for host_ordinal in range(host_count):
        hostname = f"WS-{host_ordinal:03d}"
        session = _register_session(
            registry,
            object_id=f"session-{host_ordinal:03d}",
            logon_id=f"0x{host_ordinal + 1000:x}",
            hostname=hostname,
        )
        process = _register_process(
            registry,
            object_id=f"process-{host_ordinal:03d}",
            pid=10_000 + host_ordinal,
            session_object_id=session.object_id,
            hostname=hostname,
        )
        sessions.append(session)
        processes.append(process)

    work = [
        (host_ordinal, action_ordinal)
        for action_ordinal in reversed(range(actions_per_host))
        for host_ordinal in reversed(range(host_count))
    ]

    def append_action(item: tuple[int, int]) -> None:
        host_ordinal, action_ordinal = item
        process = processes[host_ordinal]
        registry.record_dependent(
            process.ref,
            transition_id=f"dependent-{host_ordinal:03d}-{action_ordinal:03d}",
            canonical_time=_START + timedelta(seconds=action_ordinal + 2),
            action_id=f"action-{host_ordinal:03d}-{action_ordinal:03d}",
            transition_ordinal=action_ordinal,
        )
        if action_ordinal % 4 == 0:
            registry.add_hold(
                LifecycleHold(
                    hold_id=f"hold-{host_ordinal:03d}-{action_ordinal:03d}",
                    subject=process.ref,
                    acquired_at=_START + timedelta(seconds=action_ordinal + 2),
                    hold_until=_START + timedelta(seconds=action_ordinal + 90),
                    action_id=f"hold-action-{host_ordinal:03d}-{action_ordinal:03d}",
                    reason="foreground_transport",
                    transition_ordinal=action_ordinal,
                )
            )

    started = perf_counter()
    with ThreadPoolExecutor(max_workers=workers) as executor:
        tuple(executor.map(append_action, work))
    elapsed = perf_counter() - started

    for process in processes:
        _request_and_close(
            registry,
            process,
            requested_at=_START + timedelta(minutes=5),
        )
    for session in sessions:
        _request_and_close(
            registry,
            session,
            requested_at=_START + timedelta(minutes=6),
        )

    snapshots: list[object] = []
    for process in processes:
        snapshot = registry.get_process(process.object_id)
        assert snapshot is not None
        snapshots.append(
            (
                snapshot.identity.object_id,
                snapshot.closed_at,
                snapshot.transition_count,
                snapshot.compacted_transition_count,
                snapshot.transition_ledger_digest,
                snapshot.hold_count,
                snapshot.compacted_hold_count,
                snapshot.hold_ledger_digest,
                tuple(
                    (transition.kind, transition.order_key, transition.transition_id)
                    for transition in snapshot.transitions
                ),
                tuple(hold.hold_id for hold in snapshot.holds),
            )
        )
    census = registry.census()
    digest = (
        tuple(snapshots),
        census.process_entries,
        census.session_entries,
        census.transitions,
        census.holds,
        census.close_barriers,
        census.closure_tickets,
    )
    return digest, len(work) / max(elapsed, 1e-9)


def test_worker_count_preserves_lifecycle_digest_without_throughput_collapse() -> None:
    results = {workers: _run_concurrent_lifecycle_program(workers) for workers in (1, 4, 8)}

    assert results[1][0] == results[4][0] == results[8][0]
    baseline_throughput = results[1][1]
    assert baseline_throughput > 0
    assert results[4][1] >= baseline_throughput * 0.05
    assert results[8][1] >= baseline_throughput * 0.05


def test_cross_host_transition_id_claim_is_atomic() -> None:
    registry = LifecycleRegistry()
    processes: list[ProcessLifecycleIdentity] = []
    for ordinal in range(2):
        hostname = f"WS-CLAIM-{ordinal}"
        session = _register_session(
            registry,
            object_id=f"claim-session-{ordinal}",
            logon_id=f"0xclaim{ordinal}",
            hostname=hostname,
        )
        processes.append(
            _register_process(
                registry,
                object_id=f"claim-process-{ordinal}",
                pid=12_000 + ordinal,
                session_object_id=session.object_id,
                hostname=hostname,
            )
        )

    def claim(process: ProcessLifecycleIdentity) -> LifecycleTransition | StateError:
        try:
            return registry.record_dependent(
                process.ref,
                transition_id="shared-global-transition",
                canonical_time=_START + timedelta(seconds=5),
                action_id="shared-action",
                transition_ordinal=1,
            )
        except StateError as exc:
            return exc

    with ThreadPoolExecutor(max_workers=2) as executor:
        outcomes = tuple(executor.map(claim, processes))

    winners = [outcome for outcome in outcomes if not isinstance(outcome, StateError)]
    assert len(winners) == 1
    assert registry.transition("shared-global-transition") == winners[0]
    transition_counts = [
        registry.get_process(process.object_id).transition_count  # type: ignore[union-attr]
        for process in processes
    ]
    assert sorted(transition_counts) == [1, 2]


def test_watermark_and_late_lease_race_has_only_valid_linearizations() -> None:
    registry = LifecycleRegistry(closed_retention=timedelta(seconds=1))
    _register_session(registry)
    process = _register_process(registry)
    close_at = _START + timedelta(minutes=1)
    _request_and_close(registry, process, requested_at=close_at)
    cutoff = close_at + timedelta(seconds=1)
    lease = LifecycleRetentionLease(
        lease_id="watermark-race-lease",
        subject=process.ref,
        retain_until=cutoff + timedelta(minutes=1),
        reason="concurrent_reference",
    )
    start_gate = Barrier(2)

    def add_lease() -> LifecycleRetentionLease | StateError:
        start_gate.wait()
        try:
            return registry.add_retention_lease(lease)
        except StateError as exc:
            return exc

    def sweep() -> tuple[object, ...]:
        start_gate.wait()
        return registry.advance_watermark(cutoff)

    with ThreadPoolExecutor(max_workers=2) as executor:
        add_future = executor.submit(add_lease)
        sweep_future = executor.submit(sweep)
        add_result = add_future.result(timeout=5)
        evicted = sweep_future.result(timeout=5)

    if isinstance(add_result, StateError):
        assert evicted == (process.ref,)
        assert registry.get_process(process.object_id) is None
        assert registry.stats().retention_leases == 0
    else:
        assert add_result == lease
        assert evicted == ()
        assert registry.get_process(process.object_id) is not None
        assert registry.retention_deadline(process.ref) == lease.retain_until
        assert registry.stats().retention_leases == 1


def test_every_canonical_mutation_is_fenced_at_or_behind_watermark() -> None:
    registry = LifecycleRegistry()
    session = _register_session(registry)
    process = _register_process(
        registry,
        object_id="watermark-process",
        pid=13_001,
        session_object_id="",
    )
    cutoff = _START + timedelta(minutes=5)
    registry.advance_watermark(cutoff)

    with pytest.raises(StateError, match="behind watermark"):
        _register_session(
            registry,
            object_id="late-session",
            logon_id="0xlate",
            started_at=cutoff,
        )
    with pytest.raises(StateError, match="behind watermark"):
        _register_process(
            registry,
            object_id="late-process",
            pid=13_002,
            started_at=cutoff,
            session_object_id="",
        )
    with pytest.raises(StateError, match="behind watermark"):
        registry.record_dependent(
            process.ref,
            transition_id="late-dependent-watermark",
            canonical_time=cutoff,
            action_id="late-dependent-watermark",
        )
    with pytest.raises(StateError, match="behind watermark"):
        registry.add_hold(
            LifecycleHold(
                hold_id="late-hold-watermark",
                subject=process.ref,
                acquired_at=cutoff,
                hold_until=cutoff + timedelta(seconds=1),
                action_id="late-hold-watermark",
                reason="late_transport",
            )
        )
    with pytest.raises(StateError, match="behind watermark"):
        registry.request_close(
            LifecycleCloseBarrier(
                barrier_id="late-barrier-watermark",
                subject=process.ref,
                requested_at=cutoff,
                authority="generated",
                action_id="late-barrier-watermark",
            ),
            ticket_id="late-ticket-watermark",
        )
    with pytest.raises(StateError, match="current watermark"):
        registry.add_retention_lease(
            LifecycleRetentionLease(
                lease_id="late-lease-watermark",
                subject=session.ref,
                retain_until=cutoff,
                reason="late_reference",
            )
        )

    barrier_at = cutoff + timedelta(minutes=1)
    ticket = registry.request_close(
        LifecycleCloseBarrier(
            barrier_id="close-after-watermark",
            subject=process.ref,
            requested_at=barrier_at,
            authority="generated",
            action_id="close-after-watermark",
        ),
        ticket_id="ticket-after-watermark",
    )
    registry.advance_watermark(barrier_at)
    with pytest.raises(StateError, match="behind watermark"):
        registry.close(ticket.ticket_id)


def test_long_lived_entity_detail_plateaus_under_streaming_watermarks() -> None:
    registry = LifecycleRegistry(
        ledger_detail_retention=timedelta(seconds=1),
        snapshot_history_limit=8,
        shard_count=8,
    )
    _register_session(registry)
    process = _register_process(registry)
    cycles = 4
    records_per_cycle = 1_200
    first_transition_id = "plateau-dependent-0-0"
    for cycle in range(cycles):
        cycle_start = _START + timedelta(minutes=cycle * 20 + 1)
        for ordinal in range(records_per_cycle):
            at = cycle_start + timedelta(microseconds=ordinal)
            registry.record_dependent(
                process.ref,
                transition_id=f"plateau-dependent-{cycle}-{ordinal}",
                canonical_time=at,
                action_id=f"plateau-dependent-{cycle}-{ordinal}",
            )
            registry.add_hold(
                LifecycleHold(
                    hold_id=f"plateau-hold-{cycle}-{ordinal}",
                    subject=process.ref,
                    acquired_at=at,
                    hold_until=at + timedelta(seconds=1),
                    action_id=f"plateau-hold-{cycle}-{ordinal}",
                    reason="foreground_transport",
                )
            )
        cutoff = cycle_start + timedelta(minutes=10)
        registry.advance_watermark(cutoff)
        while registry.census().ledger_compaction_pending:
            registry.advance_watermark(cutoff)

        census = registry.census()
        assert census.detailed_transition_entries == 2
        assert census.detailed_hold_entries == 0
        assert census.ledger_temporal_backing_entries == 0
        assert census.route_entries == 4

    snapshot = registry.get_process(process.object_id)
    assert snapshot is not None
    assert snapshot.transition_count == 1 + cycles * records_per_cycle * 2
    assert snapshot.hold_count == cycles * records_per_cycle
    assert len(snapshot.transitions) == 0
    assert len(snapshot.holds) == 0
    assert registry.transition(first_transition_id) is None
    census = registry.census()
    assert census.compacted_transition_entries == cycles * records_per_cycle * 2
    assert census.compacted_hold_entries == cycles * records_per_cycle
    assert census.ledger_commit_map_entries == 1
    assert census.ledger_commit_map_backing_bytes < 64_000
    assert census.primary_map_backing_bytes < 512_000


def test_streamed_commits_keep_per_entity_dedupe_constant_inside_hot_horizon() -> None:
    registry = LifecycleRegistry(
        ledger_detail_retention=timedelta(hours=1),
        snapshot_history_limit=8,
        shard_count=8,
    )
    _register_session(registry)
    process = _register_process(registry)
    for ordinal in range(5_000):
        registry.record_dependent(
            process.ref,
            transition_id=f"streamed-commit-{ordinal}",
            canonical_time=_START + timedelta(minutes=1, microseconds=ordinal),
            action_id=f"streamed-action-{ordinal}",
            transition_ordinal=ordinal,
        )

    census = registry.census()
    assert census.detailed_transition_entries == 5_002
    assert census.ledger_commit_map_entries == 1
    assert census.ledger_commit_map_backing_bytes < 1_024
    with pytest.raises(StateError, match="action commit identity"):
        registry.record_dependent(
            process.ref,
            transition_id="streamed-commit-conflict",
            canonical_time=_START + timedelta(minutes=2),
            action_id="streamed-action-4999",
            transition_ordinal=4_999,
        )


def test_fixed_host_shards_bound_lanes_and_allow_disjoint_progress() -> None:
    registry = LifecycleRegistry(shard_count=4)
    host_a = "OVERLAP-A"
    partition_a = registry._partition_id(host_a)
    host_b = next(
        f"OVERLAP-B-{ordinal}"
        for ordinal in range(100)
        if registry._partition_id(f"OVERLAP-B-{ordinal}") != partition_a
    )
    session_a = _register_session(
        registry,
        object_id="overlap-session-a",
        logon_id="0xoverlap-a",
        hostname=host_a,
    )
    session_b = _register_session(
        registry,
        object_id="overlap-session-b",
        logon_id="0xoverlap-b",
        hostname=host_b,
    )
    process_b = _register_process(
        registry,
        object_id="overlap-process-b",
        pid=14_002,
        session_object_id=session_b.object_id,
        hostname=host_b,
    )

    locked_partition = registry._partitions[partition_a]
    with locked_partition._catalog_lock, ThreadPoolExecutor(max_workers=1) as executor:
        future = executor.submit(
            registry.record_dependent,
            process_b.ref,
            transition_id="overlap-disjoint-dependent",
            canonical_time=_START + timedelta(seconds=5),
            action_id="overlap-disjoint-dependent",
        )
        assert future.result(timeout=2).subject == process_b.ref

    assert registry.get_session(session_a.object_id) is not None
    census = registry.census()
    assert census.lifecycle_shard_count == 4
    assert census.lifecycle_shards_allocated == 4
    assert census.maximum_shard_entries <= 2


def test_foreground_lease_is_exact_cas_ordered_and_close_extending() -> None:
    registry = LifecycleRegistry()
    _register_session(registry)
    shell = _register_process(
        registry,
        object_id="shell-process",
        token_logon_id="0x11111",
        role="shell",
    )
    lease = _foreground_lease()

    assert registry.acquire_foreground_lease(lease) is lease
    assert registry.acquire_foreground_lease(lease) == lease
    assert registry.foreground_lease(lease.lease_id) == lease
    assert (
        registry.foreground_lease_for(
            "ws-01",
            "ANALYST",
            "session-1",
            shell.object_id,
        )
        == lease
    )
    with pytest.raises(StateError, match="already leased"):
        registry.acquire_foreground_lease(
            _foreground_lease(
                lease_id="foreground-conflict",
                acquired_at=_START + timedelta(seconds=3),
            )
        )

    renewed_until = _START + timedelta(minutes=3)
    renewed = registry.renew_foreground_lease(
        lease.lease_id,
        expected_lease_until=lease.lease_until,
        lease_until=renewed_until,
        canonical_time=_START + timedelta(seconds=4),
        action_id="foreground-renew",
        transition_ordinal=1,
    )
    assert renewed.lease_until == renewed_until
    assert registry.resource_lease_deadline(shell.ref) == renewed_until
    assert (
        registry.renew_foreground_lease(
            lease.lease_id,
            expected_lease_until=lease.lease_until,
            lease_until=renewed_until,
            canonical_time=_START + timedelta(seconds=4),
            action_id="foreground-renew",
            transition_ordinal=1,
        )
        == renewed
    )
    with pytest.raises(StateError, match="deadline changed"):
        registry.renew_foreground_lease(
            lease.lease_id,
            expected_lease_until=lease.lease_until,
            lease_until=renewed_until + timedelta(seconds=1),
            canonical_time=_START + timedelta(seconds=5),
            action_id="foreground-drift",
        )

    barrier = LifecycleCloseBarrier(
        barrier_id="barrier-shell-resource",
        subject=shell.ref,
        requested_at=_START + timedelta(minutes=1),
        authority="generated",
        action_id="close-shell-resource",
    )
    ticket = registry.request_close(barrier, ticket_id="ticket-shell-resource")
    assert ticket.effective_at == renewed_until


def test_foreground_leases_serialize_one_shell_but_not_sibling_shells() -> None:
    registry = LifecycleRegistry()
    _register_session(registry)
    shell_one = _register_process(
        registry,
        object_id="shell-one",
        pid=4101,
        token_logon_id="0x11111",
        role="shell",
    )
    shell_two = _register_process(
        registry,
        object_id="shell-two",
        pid=4102,
        token_logon_id="0x11111",
        role="shell",
    )
    first = _foreground_lease(process_object_id=shell_one.object_id)
    sibling = _foreground_lease(
        lease_id="foreground-sibling",
        process_object_id=shell_two.object_id,
        action_id="foreground-sibling-acquire",
    )

    assert registry.acquire_foreground_lease(first) == first
    assert registry.acquire_foreground_lease(sibling) == sibling
    assert (
        registry.foreground_lease_for(
            "WS-01",
            "analyst",
            "session-1",
            shell_one.object_id,
        )
        == first
    )
    assert (
        registry.foreground_lease_for(
            "WS-01",
            "analyst",
            "session-1",
            shell_two.object_id,
        )
        == sibling
    )
    with pytest.raises(StateError, match="already leased"):
        registry.acquire_foreground_lease(
            _foreground_lease(
                lease_id="foreground-same-shell-conflict",
                process_object_id=shell_one.object_id,
                acquired_at=_START + timedelta(seconds=3),
                action_id="foreground-same-shell-conflict",
            )
        )


def test_foreground_renewal_revalidates_the_new_deadline_against_close_barriers() -> None:
    registry = LifecycleRegistry()
    _register_session(registry)
    shell = _register_process(
        registry,
        object_id="shell-process",
        token_logon_id="0x11111",
        role="shell",
    )
    lease = registry.acquire_foreground_lease(
        _foreground_lease(lease_until=_START + timedelta(seconds=30))
    )
    barrier_at = _START + timedelta(minutes=1)
    ticket = registry.request_close(
        LifecycleCloseBarrier(
            barrier_id="barrier-shell-renewal",
            subject=shell.ref,
            requested_at=barrier_at,
            authority="generated",
            action_id="close-shell-renewal",
        ),
        ticket_id="ticket-shell-renewal",
    )

    with pytest.raises(StateError, match="extends past process close barrier"):
        registry.renew_foreground_lease(
            lease.lease_id,
            expected_lease_until=lease.lease_until,
            lease_until=barrier_at + timedelta(seconds=1),
            canonical_time=_START + timedelta(seconds=10),
            action_id="foreground-renew-past-barrier",
        )

    assert ticket.effective_at == barrier_at
    assert registry.foreground_lease(lease.lease_id) == lease


def test_foreground_concurrency_group_uses_one_immutable_group_lease() -> None:
    registry = LifecycleRegistry()
    _register_session(registry)
    _register_process(
        registry,
        object_id="shell-process",
        token_logon_id="0x11111",
        role="shell",
    )
    lease = registry.acquire_foreground_lease(_foreground_lease(concurrency_group_id="pipeline-1"))

    assert registry.acquire_foreground_lease(lease) == lease
    with pytest.raises(StateError, match="already leased"):
        registry.acquire_foreground_lease(
            _foreground_lease(
                lease_id="foreground-same-group-stage",
                acquired_at=_START + timedelta(seconds=3),
                concurrency_group_id="pipeline-1",
            )
        )

    renewed = registry.renew_foreground_lease(
        lease.lease_id,
        expected_lease_until=lease.lease_until,
        lease_until=_START + timedelta(minutes=3),
        canonical_time=_START + timedelta(seconds=4),
        action_id="foreground-pipeline-renew",
        concurrency_group_id="pipeline-1",
    )
    with pytest.raises(StateError, match="concurrency group is immutable"):
        registry.renew_foreground_lease(
            lease.lease_id,
            expected_lease_until=renewed.lease_until,
            lease_until=_START + timedelta(minutes=4),
            canonical_time=_START + timedelta(seconds=5),
            action_id="foreground-relabel-group",
            concurrency_group_id="pipeline-2",
        )

    assert registry.foreground_lease(lease.lease_id) == renewed


def test_foreground_lease_release_is_exact_and_census_is_bounded() -> None:
    registry = LifecycleRegistry()
    _register_session(registry)
    _register_process(
        registry,
        object_id="shell-process",
        token_logon_id="0x11111",
        role="shell",
    )
    lease = registry.acquire_foreground_lease(_foreground_lease())

    census = registry.census()
    assert census.foreground_leases == 1
    assert census.singleton_leases == 0
    assert census.resource_lease_deadline_entries == 1
    assert census.resource_lease_subjects == 2
    assert census.resource_lease_subject_bindings == 2
    assert registry.release_foreground_lease(
        lease.lease_id,
        released_at=_START + timedelta(seconds=5),
        action_id="foreground-release",
        transition_ordinal=2,
    )
    assert not registry.release_foreground_lease(
        lease.lease_id,
        released_at=_START + timedelta(seconds=5),
        action_id="foreground-release",
        transition_ordinal=2,
    )
    assert registry.foreground_lease(lease.lease_id) is None
    assert registry.census().foreground_leases == 0
    assert registry.census().resource_lease_subjects == 0
    assert registry.census().resource_lease_subject_bindings == 0


def test_singleton_leases_support_preallocation_binding_and_exact_overlap() -> None:
    registry = LifecycleRegistry()
    _register_session(registry)
    process = _register_process(
        registry,
        object_id="singleton-process",
        token_logon_id="0x11111",
    )
    later = _singleton_lease(
        lease_id="singleton-later",
        acquired_at=_START + timedelta(minutes=4),
        lease_until=_START + timedelta(minutes=5),
    )
    earlier = _singleton_lease(
        lease_id="singleton-earlier",
        acquired_at=_START + timedelta(minutes=1),
        lease_until=_START + timedelta(minutes=2),
    )

    registry.acquire_singleton_lease(later)
    registry.acquire_singleton_lease(earlier)
    assert (
        registry.singleton_lease_for(
            "ws-01",
            "ANALYST",
            "session-1",
            "0X11111",
            r"C:\Windows\System32\singleton-process.exe",
            _START + timedelta(minutes=1, seconds=30),
        )
        == earlier
    )
    with pytest.raises(StateError, match="overlaps"):
        registry.acquire_singleton_lease(
            _singleton_lease(
                lease_id="singleton-overlap",
                acquired_at=_START + timedelta(minutes=1, seconds=30),
                lease_until=_START + timedelta(minutes=4, seconds=30),
            )
        )

    bound = registry.bind_singleton_lease(
        earlier.lease_id,
        process_object_id=process.object_id,
        canonical_time=_START + timedelta(minutes=1, seconds=1),
        action_id="singleton-bind",
        transition_ordinal=1,
    )
    assert bound.process_object_id == process.object_id
    assert registry.census().singleton_leases == 2
    assert registry.census().singleton_lease_temporal_live_entries == 2


def test_singleton_renewal_checks_exact_successor_and_release() -> None:
    registry = LifecycleRegistry()
    _register_session(registry)
    first = registry.acquire_singleton_lease(
        _singleton_lease(
            lease_id="singleton-first",
            acquired_at=_START + timedelta(minutes=1),
            lease_until=_START + timedelta(minutes=2),
        )
    )
    registry.acquire_singleton_lease(
        _singleton_lease(
            lease_id="singleton-next",
            acquired_at=_START + timedelta(minutes=3),
            lease_until=_START + timedelta(minutes=4),
        )
    )

    with pytest.raises(StateError, match="overlaps"):
        registry.renew_singleton_lease(
            first.lease_id,
            expected_lease_until=first.lease_until,
            lease_until=_START + timedelta(minutes=3, seconds=1),
            canonical_time=_START + timedelta(minutes=1, seconds=1),
            action_id="singleton-overlap-renew",
        )
    renewed = registry.renew_singleton_lease(
        first.lease_id,
        expected_lease_until=first.lease_until,
        lease_until=_START + timedelta(minutes=2, seconds=30),
        canonical_time=_START + timedelta(minutes=1, seconds=2),
        action_id="singleton-renew",
    )
    assert renewed.lease_until == _START + timedelta(minutes=2, seconds=30)
    assert registry.release_singleton_lease(
        renewed.lease_id,
        released_at=_START + timedelta(minutes=1, seconds=3),
        action_id="singleton-release",
        transition_ordinal=1,
    )
    assert registry.singleton_lease(renewed.lease_id) is None


def test_resource_lease_watermark_expiry_is_paged(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from evidenceforge.generation import lifecycle_registry as registry_module

    monkeypatch.setattr(registry_module, "_RESOURCE_LEASE_EXPIRY_PAGE", 2)
    registry = LifecycleRegistry(shard_count=1)
    singleton_session = _register_session(registry)
    foreground_leases: list[LifecycleForegroundLease] = []
    foreground_processes: list[ProcessLifecycleIdentity] = []
    for ordinal in range(3):
        session = _register_session(
            registry,
            object_id=f"foreground-page-session-{ordinal}",
            logon_id=f"0x20{ordinal}",
        )
        shell = _register_process(
            registry,
            object_id=f"foreground-page-shell-{ordinal}",
            pid=15_000 + ordinal,
            session_object_id=session.object_id,
            token_logon_id=session.logon_id,
            role="shell",
        )
        lease = LifecycleForegroundLease(
            lease_id=f"foreground-page-{ordinal}",
            hostname=session.hostname,
            principal=session.principal,
            session_object_id=session.object_id,
            process_object_id=shell.object_id,
            acquired_at=_START + timedelta(seconds=ordinal + 1),
            lease_until=_START + timedelta(seconds=ordinal + 2),
            action_id=f"foreground-page-{ordinal}",
            concurrency_group_id=f"pipeline-page-{ordinal}",
        )
        foreground_processes.append(shell)
        foreground_leases.append(registry.acquire_foreground_lease(lease))
    for ordinal in range(3):
        registry.acquire_singleton_lease(
            _singleton_lease(
                lease_id=f"singleton-page-{ordinal}",
                acquired_at=_START + timedelta(seconds=ordinal + 1),
                lease_until=_START + timedelta(seconds=ordinal + 2),
            )
        )

    cutoff = _START + timedelta(minutes=1)
    registry.advance_watermark(cutoff)
    retained = registry.census()
    assert retained.foreground_leases == 1
    assert retained.singleton_leases == 1

    # Bounded reclamation may retain a due backing row for another page, but
    # every authority read must already behave exactly like eager expiry.
    remaining_foreground = foreground_leases[-1]
    assert registry.foreground_lease(remaining_foreground.lease_id) is None
    assert (
        registry.foreground_lease_for(
            remaining_foreground.hostname,
            remaining_foreground.principal,
            remaining_foreground.session_object_id,
            remaining_foreground.process_object_id,
        )
        is None
    )
    assert registry.singleton_lease("singleton-page-2") is None
    assert (
        registry.singleton_lease_for(
            singleton_session.hostname,
            singleton_session.principal,
            singleton_session.object_id,
            singleton_session.logon_id,
            r"C:\Windows\System32\singleton-process.exe",
            _START + timedelta(seconds=3, microseconds=1),
        )
        is None
    )
    with pytest.raises(StateError, match="Unknown lifecycle foreground lease"):
        registry.renew_foreground_lease(
            remaining_foreground.lease_id,
            expected_lease_until=remaining_foreground.lease_until,
            lease_until=cutoff + timedelta(minutes=1),
            canonical_time=cutoff + timedelta(microseconds=1),
            action_id="foreground-page-stale-renew",
        )
    assert not registry.release_foreground_lease(
        remaining_foreground.lease_id,
        released_at=cutoff + timedelta(microseconds=1),
        action_id="foreground-page-stale-release",
    )
    with pytest.raises(StateError, match="Unknown lifecycle singleton lease"):
        registry.renew_singleton_lease(
            "singleton-page-2",
            expected_lease_until=_START + timedelta(seconds=4),
            lease_until=cutoff + timedelta(minutes=1),
            canonical_time=cutoff + timedelta(microseconds=1),
            action_id="singleton-page-stale-renew",
        )
    assert not registry.release_singleton_lease(
        "singleton-page-2",
        released_at=cutoff + timedelta(microseconds=1),
        action_id="singleton-page-stale-release",
    )

    close_at = cutoff + timedelta(seconds=1)
    foreground_ticket = registry.request_close(
        LifecycleCloseBarrier(
            barrier_id="foreground-page-close",
            subject=foreground_processes[-1].ref,
            requested_at=close_at,
            authority="generated",
            action_id="foreground-page-close",
        ),
        ticket_id="foreground-page-close-ticket",
    )
    singleton_ticket = registry.request_close(
        LifecycleCloseBarrier(
            barrier_id="singleton-page-close",
            subject=singleton_session.ref,
            requested_at=close_at,
            authority="generated",
            action_id="singleton-page-close",
        ),
        ticket_id="singleton-page-close-ticket",
    )
    assert foreground_ticket.effective_at == close_at
    assert singleton_ticket.effective_at == close_at

    assert registry.census().singleton_leases == 1
    registry.advance_watermark(cutoff)
    census = registry.census()
    assert census.foreground_leases == 0
    assert census.singleton_leases == 0
    assert census.resource_lease_deadline_entries == 0
    assert census.resource_lease_subjects == 0
    assert census.resource_lease_subject_bindings == 0
    assert census.singleton_lease_temporal_live_entries == 0


def test_many_singleton_leases_keep_session_close_deadline_lookup_flat() -> None:
    registry = LifecycleRegistry(shard_count=1)
    session = _register_session(registry)
    lease_count = 5_000
    latest_deadline = _START + timedelta(minutes=2, microseconds=lease_count - 1)
    for ordinal in range(lease_count):
        registry.acquire_singleton_lease(
            LifecycleSingletonLease(
                lease_id=f"many-singleton-{ordinal}",
                hostname=session.hostname,
                principal=session.principal,
                session_object_id=session.object_id,
                logon_id=session.logon_id,
                canonical_image=rf"C:\Program Files\App-{ordinal}\app.exe",
                process_object_id="",
                acquired_at=_START + timedelta(seconds=1),
                lease_until=_START + timedelta(minutes=2, microseconds=ordinal),
                action_id=f"many-singleton-{ordinal}",
            )
        )

    before = registry.census()
    ticket = registry.request_close(
        LifecycleCloseBarrier(
            barrier_id="many-singleton-session-close",
            subject=session.ref,
            requested_at=_START + timedelta(minutes=1),
            authority="generated",
            action_id="many-singleton-session-close",
        ),
        ticket_id="many-singleton-session-close-ticket",
    )
    after = registry.census()

    assert ticket.effective_at == latest_deadline
    assert after.resource_lease_subjects == 1
    assert after.resource_lease_subject_bindings == lease_count
    assert after.resource_lease_max_subject_bindings == lease_count
    assert (
        after.resource_lease_deadline_candidates_inspected
        - before.resource_lease_deadline_candidates_inspected
        == 1
    )
    assert after.lookup_candidates_inspected - before.lookup_candidates_inspected == 1


def test_session_member_close_deadline_is_exact_and_constant_candidate() -> None:
    registry = LifecycleRegistry(shard_count=1)
    session = _register_session(registry)
    process = _register_process(
        registry,
        object_id="member-close-deadline",
        token_logon_id=session.logon_id,
    )

    before_open = registry.census()
    with pytest.raises(StateError, match="1 unclosed members"):
        registry.session_member_close_deadline(session.object_id)
    after_open = registry.census()
    assert after_open.lookup_candidates_inspected - before_open.lookup_candidates_inspected == 1

    closed_at = _START + timedelta(minutes=3)
    _request_and_close(registry, process, requested_at=closed_at)
    before_closed = registry.census()
    assert registry.session_member_close_deadline(session.object_id) == closed_at
    after_closed = registry.census()
    assert after_closed.lookup_candidates_inspected - before_closed.lookup_candidates_inspected == 1


def test_latest_closed_session_member_is_exact_while_another_member_remains_open() -> None:
    registry = LifecycleRegistry(shard_count=1)
    session = _register_session(registry)
    closed_member = _register_process(
        registry,
        object_id="retained-closed-member",
        pid=4881,
        token_logon_id=session.logon_id,
    )
    _register_process(
        registry,
        object_id="still-open-member",
        pid=4882,
        started_at=_START + timedelta(seconds=2),
        token_logon_id=session.logon_id,
    )
    closed_at = _START + timedelta(minutes=3)
    _request_and_close(registry, closed_member, requested_at=closed_at)

    before = registry.census()
    assert registry.session_latest_closed_member_at(session.object_id) == closed_at
    after = registry.census()

    assert after.lookup_candidates_inspected - before.lookup_candidates_inspected == 1


def test_live_session_member_pages_are_indexed_and_drain_after_close() -> None:
    registry = LifecycleRegistry(shard_count=1)
    session = _register_session(registry)
    members = tuple(
        _register_process(
            registry,
            object_id=f"paged-member-{ordinal}",
            pid=4900 + ordinal,
            started_at=_START + timedelta(seconds=ordinal + 1),
            token_logon_id=session.logon_id,
        )
        for ordinal in range(5)
    )

    before = registry.census()
    first, cursor = registry.live_session_member_process_page(
        session.object_id,
        limit=2,
    )
    after = registry.census()
    assert [item.identity.object_id for item in first] == [
        "paged-member-0",
        "paged-member-1",
    ]
    assert cursor is not None
    assert after.lookup_candidates_inspected - before.lookup_candidates_inspected == 2

    second, cursor = registry.live_session_member_process_page(
        session.object_id,
        after_handle=cursor,
        limit=2,
    )
    assert [item.identity.object_id for item in second] == [
        "paged-member-2",
        "paged-member-3",
    ]
    assert cursor is not None

    for member in first:
        _request_and_close(
            registry,
            member.identity,
            requested_at=_START + timedelta(minutes=2),
        )
    restarted, _cursor = registry.live_session_member_process_page(
        session.object_id,
        limit=2,
    )
    assert [item.identity.object_id for item in restarted] == [
        "paged-member-2",
        "paged-member-3",
    ]

    for ordinal, member in enumerate(members[2:]):
        _request_and_close(
            registry,
            member,
            requested_at=_START + timedelta(minutes=3, microseconds=ordinal),
        )
    assert registry.live_session_member_process_page(session.object_id, limit=1) == ((), None)


def test_live_child_pages_remove_closed_bindings_and_keep_deadline_exact() -> None:
    registry = LifecycleRegistry(shard_count=1)
    _register_session(registry)
    parent = _register_process(
        registry,
        object_id="paged-parent",
        pid=5000,
        token_logon_id="0x11111",
    )
    children = tuple(
        _register_process(
            registry,
            object_id=f"paged-child-{ordinal}",
            pid=5100 + ordinal,
            started_at=_START + timedelta(seconds=2 + ordinal),
            parent_object_id=parent.object_id,
            token_logon_id="0x11111",
        )
        for ordinal in range(5)
    )

    first, cursor = registry.live_child_process_page(parent.object_id, limit=2)
    assert [item.identity.object_id for item in first] == [
        "paged-child-0",
        "paged-child-1",
    ]
    assert cursor is not None
    second, cursor = registry.live_child_process_page(
        parent.object_id,
        after_handle=cursor,
        limit=2,
    )
    assert [item.identity.object_id for item in second] == [
        "paged-child-2",
        "paged-child-3",
    ]
    assert cursor is not None
    third, cursor = registry.live_child_process_page(
        parent.object_id,
        after_handle=cursor,
        limit=2,
    )
    assert [item.identity.object_id for item in third] == ["paged-child-4"]
    assert cursor is None

    with pytest.raises(StateError, match="5 unclosed children"):
        registry.process_child_close_deadline(parent.object_id)
    latest_close = _START
    for ordinal, child in enumerate(children):
        latest_close = _START + timedelta(minutes=2, microseconds=ordinal)
        _request_and_close(registry, child, requested_at=latest_close)
    assert registry.live_child_process_page(parent.object_id, limit=1) == ((), None)
    before = registry.census()
    assert registry.process_child_close_deadline(parent.object_id) == latest_close
    after = registry.census()
    assert after.lookup_candidates_inspected - before.lookup_candidates_inspected == 1


def test_process_parent_rejects_cross_session_ownership_before_registration() -> None:
    """A user-session process cannot become another session's structural child."""

    registry = LifecycleRegistry(shard_count=1)
    first_session = _register_session(
        registry,
        object_id="session-first",
        logon_id="0x11111",
    )
    second_session = _register_session(
        registry,
        object_id="session-second",
        logon_id="0x22222",
    )
    first_shell = _register_process(
        registry,
        object_id="first-shell",
        pid=5_200,
        session_object_id=first_session.object_id,
        token_logon_id=first_session.logon_id,
        role="shell",
    )

    with pytest.raises(StateError, match="parent crosses session ownership"):
        _register_process(
            registry,
            object_id="second-command",
            pid=5_201,
            started_at=_START + timedelta(seconds=2),
            session_object_id=second_session.object_id,
            parent_object_id=first_shell.object_id,
            token_logon_id=second_session.logon_id,
        )

    assert registry.get_process("second-command") is None
    assert registry.live_child_process_page(first_shell.object_id, limit=1) == ((), None)
    assert registry.live_session_member_process_page(second_session.object_id, limit=1) == (
        (),
        None,
    )


def test_bootstrap_handoff_can_cross_session_without_owning_child_lifetime() -> None:
    """The explicit handoff role remains a non-owning cross-session exception."""

    registry = LifecycleRegistry(shard_count=1)
    first_session = _register_session(
        registry,
        object_id="handoff-session",
        logon_id="0x11111",
    )
    second_session = _register_session(
        registry,
        object_id="child-session",
        logon_id="0x22222",
    )
    handoff = _register_process(
        registry,
        object_id="session-handoff",
        pid=5_210,
        session_object_id=first_session.object_id,
        token_logon_id=first_session.logon_id,
        role="bootstrap_handoff",
    )

    child = _register_process(
        registry,
        object_id="handoff-child",
        pid=5_211,
        started_at=_START + timedelta(seconds=2),
        session_object_id=second_session.object_id,
        parent_object_id=handoff.object_id,
        token_logon_id=second_session.logon_id,
    )

    assert registry.get_process(child.object_id) is not None
    assert registry.live_child_process_page(handoff.object_id, limit=1) == ((), None)


@pytest.mark.slow
@pytest.mark.parametrize("descendant_count", (1, 10, 100, 1_000, 4_096))
def test_descendant_postorder_work_is_linear_and_state_neutral(
    descendant_count: int,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Indexed teardown work follows one tree, independent of retained history."""

    state = StateManager()
    state.set_current_time(_START)
    registry = LifecycleRegistry(shard_count=1)
    authority = GeneratorLifecycleAuthority(
        state,
        LifecycleShadow(state, registry),
        shard_count=1,
    )
    session = _register_session(registry)
    root = _register_process(
        registry,
        object_id="linear-root",
        pid=20_000,
        session_object_id=session.object_id,
        token_logon_id=session.logon_id,
        role="receiver",
    )
    parent = root
    for ordinal in range(descendant_count):
        parent = _register_process(
            registry,
            object_id=f"linear-child-{ordinal}",
            pid=20_001 + ordinal,
            started_at=_START + timedelta(seconds=1, microseconds=ordinal + 1),
            session_object_id=session.object_id,
            parent_object_id=parent.object_id,
            token_logon_id=session.logon_id,
        )

    original_page = registry.live_child_process_page
    page_calls = 0
    returned_candidates = 0

    def count_page(*args: object, **kwargs: object):
        nonlocal page_calls, returned_candidates
        page_calls += 1
        page, cursor = original_page(*args, **kwargs)
        returned_candidates += len(page)
        return page, cursor

    monkeypatch.setattr(registry, "live_child_process_page", count_page)
    before = registry.stats()

    descendants = authority.live_process_descendant_postorder(
        root.object_id,
        limit=descendant_count,
    )

    assert len(descendants) == descendant_count
    assert descendants[0].identity.object_id == f"linear-child-{descendant_count - 1}"
    assert descendants[-1].identity.object_id == "linear-child-0"
    assert page_calls == descendant_count + 1
    assert returned_candidates == descendant_count
    assert registry.stats() == before


def test_bootstrap_handoff_parent_does_not_own_shell_child_lifetime() -> None:
    registry = LifecycleRegistry(shard_count=1)
    _register_session(registry)
    handoff = _register_process(
        registry,
        object_id="userinit-handoff",
        pid=5200,
        token_logon_id="0x11111",
        role="bootstrap_handoff",
    )
    shell = _register_process(
        registry,
        object_id="session-explorer",
        pid=5204,
        started_at=_START + timedelta(seconds=2),
        parent_object_id=handoff.object_id,
        token_logon_id="0x11111",
    )

    assert registry.live_child_process_page(handoff.object_id, limit=1) == ((), None)
    handoff_close = _START + timedelta(seconds=5)
    _request_and_close(registry, handoff, requested_at=handoff_close)

    assert registry.get_process(handoff.object_id).closed_at == handoff_close
    assert registry.get_process(shell.object_id).closed_at is None


def test_service_instance_identity_and_process_ownership_are_separate() -> None:
    registry = LifecycleRegistry(shard_count=8, closed_retention=timedelta(hours=1))
    process = _register_process(
        registry,
        object_id="shared-svchost",
        pid=6100,
        hostname="SRV-01",
        session_object_id="",
    )
    logical = LogicalServiceIdentity(
        hostname="SRV-01",
        logical_service_id="windows:lanmanserver",
        canonical_name="LanmanServer",
        service_kind="builtin",
    )
    service = ServiceInstanceLifecycleIdentity(
        hostname="SRV-01",
        object_id="service-lanmanserver-boot-1",
        logical_service_id=logical.logical_service_id,
        boot_id="boot-1",
        instance_id="builtin",
        started_at=_START + timedelta(seconds=1),
    )
    snapshot = registry.register_service_instance(
        logical,
        service,
        action_id="service-start",
        transition_id="service-start-transition",
    )
    assert snapshot.identity == service
    assert (
        registry.service_for_logical_at(
            "SRV-01",
            logical.logical_service_id,
            service.started_at,
        ).identity
        == service
    )
    assert (
        registry.service_for_instance_key(
            "SRV-01",
            "boot-1",
            logical.logical_service_id,
            "builtin",
        ).identity
        == service
    )
    with pytest.raises(StateError, match="instance key"):
        registry.register_service_instance(
            logical,
            ServiceInstanceLifecycleIdentity(
                hostname="SRV-01",
                object_id="service-alias",
                logical_service_id=logical.logical_service_id,
                boot_id="boot-1",
                instance_id="builtin",
                started_at=service.started_at,
            ),
            action_id="alias-start",
            transition_id="alias-start-transition",
        )

    binding = ServiceProcessBindingIdentity(
        binding_id="service-process-binding",
        service_object_id=service.object_id,
        process_object_id=process.object_id,
        bound_at=_START + timedelta(seconds=2),
        role="shared_host_process",
        action_id="bind-service-process",
    )
    assert registry.bind_service_process(binding).identity == binding
    barrier = LifecycleCloseBarrier(
        barrier_id="service-close-barrier",
        subject=service.ref,
        requested_at=_START + timedelta(minutes=5),
        authority="generated",
        action_id="service-close",
    )
    ticket = registry.request_close(barrier, ticket_id="service-close-ticket")
    with pytest.raises(StateError, match="service process bindings remain active"):
        registry.close(ticket.ticket_id)
    with pytest.raises(StateError, match="close barrier"):
        registry.bind_service_process(
            ServiceProcessBindingIdentity(
                binding_id="late-service-process-binding",
                service_object_id=service.object_id,
                process_object_id=process.object_id,
                bound_at=barrier.requested_at,
                role="shared_host_process",
                action_id="late-bind",
            )
        )
    registry.close_service_process_binding(
        binding.binding_id,
        expected_identity=binding,
        closed_at=ticket.effective_at,
        action_id="unbind-service-process",
    )
    assert registry.close(ticket.ticket_id).closed_at == ticket.effective_at
    registry.advance_watermark(_START + timedelta(hours=2))
    assert registry.get_service_instance(service.object_id) is None
    assert registry.service_process_binding(binding.binding_id) is None


def test_service_bulk_eviction_preserves_cumulative_temporal_candidates() -> None:
    registry = LifecycleRegistry(shard_count=1, closed_retention=timedelta(seconds=1))
    logical = LogicalServiceIdentity(
        hostname="SRV-01",
        logical_service_id="windows:eventlog",
        canonical_name="EventLog",
        service_kind="builtin",
    )
    service = ServiceInstanceLifecycleIdentity(
        hostname=logical.hostname,
        object_id="service-eventlog-boot-1",
        logical_service_id=logical.logical_service_id,
        boot_id="boot-1",
        instance_id="builtin",
        started_at=_START + timedelta(seconds=1),
    )
    registry.register_service_instance(
        logical,
        service,
        action_id="service-start",
        transition_id="service-start-transition",
    )
    assert (
        registry.service_for_logical_at(
            logical.hostname,
            logical.logical_service_id,
            service.started_at,
        ).identity
        == service
    )
    _request_and_close(
        registry,
        service,
        requested_at=_START + timedelta(seconds=5),
    )
    before = registry.census()
    assert before.lookup_candidates_inspected >= 1

    registry.advance_watermark(_START + timedelta(hours=1))

    after = registry.census()
    assert after.service_instance_entries == 0
    assert after.lookup_candidates_inspected == before.lookup_candidates_inspected


def test_cross_host_transport_binding_fences_transport_and_session_close() -> None:
    registry = LifecycleRegistry(shard_count=64, closed_retention=timedelta(hours=1))
    session = _register_session(
        registry,
        object_id="target-rdp-session",
        logon_id="0x90001",
        hostname="RDP-TARGET",
    )
    opened_at = _START + timedelta(seconds=1)
    deadline = _START + timedelta(minutes=10)
    transport = TransportLifecycleIdentity(
        hostname="RDP-SOURCE",
        object_id="rdp-transport-object",
        transport_id="network-plan-rdp-1",
        src_hostname="RDP-SOURCE",
        dst_hostname="RDP-TARGET",
        network_tuple=NetworkTuple("10.0.0.10", 50123, "10.0.0.20", 3389, "tcp"),
        opened_at=opened_at,
        close_deadline=deadline,
        zeek_uid="C-rdp-1",
        conn_id="ecar-rdp-1",
    )
    registry.register_transport(
        transport,
        action_id="transport-start",
        transition_id="transport-start-transition",
    )
    assert registry.transport_for_transport_id(transport.transport_id).identity == transport
    assert registry.transport_for_uid(transport.zeek_uid).identity == transport
    assert (
        registry.transport_for_tuple_at(
            transport.hostname,
            transport.tuple_key,
            opened_at,
        ).identity
        == transport
    )
    binding = TransportSessionBindingIdentity(
        binding_id="rdp-session-binding",
        transport_object_id=transport.object_id,
        session_object_id=session.object_id,
        bound_at=opened_at + timedelta(seconds=1),
        role="session",
        action_id="bind-rdp-session",
    )
    assert registry.bind_transport_session(binding).identity == binding
    assert registry.get_transport(transport.object_id).active_binding_count == 1
    transport_page, transport_cursor = registry.transport_binding_page(
        transport.object_id,
        limit=4,
    )
    session_page, session_cursor = registry.session_transport_binding_page(
        session.object_id,
        limit=4,
    )
    assert transport_page == session_page
    assert transport_page[0].identity == binding
    assert transport_cursor is session_cursor is None

    transport_barrier = LifecycleCloseBarrier(
        barrier_id="transport-close-barrier",
        subject=transport.ref,
        requested_at=deadline,
        authority="authoritative",
        action_id="transport-close",
    )
    transport_ticket = registry.request_close(
        transport_barrier,
        ticket_id="transport-close-ticket",
    )
    session_barrier = LifecycleCloseBarrier(
        barrier_id="session-close-barrier",
        subject=session.ref,
        requested_at=deadline + timedelta(seconds=1),
        authority="generated",
        action_id="session-close",
    )
    session_ticket = registry.request_close(session_barrier, ticket_id="session-close-ticket")
    with pytest.raises(StateError, match="session bindings remain active"):
        registry.close(transport_ticket.ticket_id)
    with pytest.raises(StateError, match="transport bindings remain active"):
        registry.close(session_ticket.ticket_id)

    closed_binding = registry.close_transport_session_binding(
        binding.binding_id,
        expected_identity=binding,
        closed_at=deadline,
        action_id="unbind-rdp-session",
    )
    assert closed_binding.closed_at == deadline
    assert registry.get_transport(transport.object_id).active_binding_count == 0
    assert registry.close(transport_ticket.ticket_id).closed_at == deadline
    assert registry.close(session_ticket.ticket_id).closed_at == session_ticket.effective_at
    registry.advance_watermark(_START + timedelta(hours=2))
    assert registry.get_transport(transport.object_id) is None
    assert registry.get_session(session.object_id) is None
    assert registry.transport_session_binding(binding.binding_id) is None
    census = registry.census()
    assert census.transport_evictions == 1
    assert census.binding_evictions == 1


def test_checkpoint_prunes_terminal_transport_from_deadline_queue_without_watermark() -> None:
    registry = LifecycleRegistry(shard_count=8)
    closed_at = _START + timedelta(seconds=10)
    transport = TransportLifecycleIdentity(
        hostname="CHECKPOINT-SOURCE",
        object_id="checkpoint-transport",
        transport_id="checkpoint-plan",
        src_hostname="CHECKPOINT-SOURCE",
        dst_hostname="CHECKPOINT-TARGET",
        network_tuple=NetworkTuple("10.60.0.1", 53000, "10.60.0.2", 443, "tcp"),
        opened_at=_START,
        close_deadline=closed_at,
        zeek_uid="C-checkpoint-transport",
    )
    registry.register_transport(
        transport,
        action_id="checkpoint-transport-start",
        transition_id="checkpoint-transport-start",
    )
    _request_and_close(registry, transport, requested_at=closed_at)

    assert (
        registry.prune_checkpoint_terminal_transports(closed_at - timedelta(microseconds=1)) == ()
    )
    assert registry.get_transport(transport.object_id) is not None
    assert registry.prune_checkpoint_terminal_transports(closed_at) == (transport.ref,)
    assert registry.get_transport(transport.object_id) is None
    assert registry.census().watermark is None

    replacement = replace(
        transport,
        object_id="checkpoint-transport-replacement",
        transport_id="checkpoint-plan-replacement",
        opened_at=closed_at,
        close_deadline=closed_at + timedelta(seconds=10),
        zeek_uid="C-checkpoint-transport-replacement",
    )
    assert (
        registry.register_transport(
            replacement,
            action_id="checkpoint-transport-replacement-start",
            transition_id="checkpoint-transport-replacement-start",
        ).identity
        == replacement
    )


def test_transport_registration_reuses_one_exact_object_route_digest(monkeypatch) -> None:
    """Prepared transport lookup and insertion should share one namespace digest."""
    registry = LifecycleRegistry()
    transport = TransportLifecycleIdentity(
        hostname="ROUTE-SOURCE",
        object_id="prehashed-transport-object",
        transport_id="prehashed-network-plan",
        src_hostname="ROUTE-SOURCE",
        dst_hostname="ROUTE-TARGET",
        network_tuple=NetworkTuple("10.30.0.1", 50123, "10.30.0.2", 443, "tcp"),
        opened_at=_START,
        close_deadline=_START + timedelta(minutes=1),
        zeek_uid="C-prehashed-route",
    )
    original_digest = lifecycle_registry_module.PackedUniqueDigestMap.digest
    object_digest_calls = 0

    def tracked_digest(route, semantic_key):
        nonlocal object_digest_calls
        if route._namespace == b"lc-tr-object" and semantic_key == transport.object_id:
            object_digest_calls += 1
        return original_digest(route, semantic_key)

    monkeypatch.setattr(
        lifecycle_registry_module.PackedUniqueDigestMap,
        "digest",
        tracked_digest,
    )

    registry.register_transport(
        transport,
        action_id="prehashed-route-start",
        transition_id="prehashed-route-transition",
    )
    registration_digest_calls = object_digest_calls

    assert registration_digest_calls == 1
    assert registry.get_transport(transport.object_id).identity == transport


def test_service_and_transport_temporal_reuse_is_exact_and_non_overlapping() -> None:
    registry = LifecycleRegistry(shard_count=8)
    logical = LogicalServiceIdentity(
        hostname="TEMPORAL-SRV",
        logical_service_id="windows:eventlog",
        canonical_name="EventLog",
        service_kind="builtin",
    )
    first_service = ServiceInstanceLifecycleIdentity(
        hostname=logical.hostname,
        object_id="eventlog-boot-a",
        logical_service_id=logical.logical_service_id,
        boot_id="boot-a",
        instance_id="builtin",
        started_at=_START + timedelta(seconds=1),
    )
    registry.register_service_instance(
        logical,
        first_service,
        action_id="start-eventlog-a",
        transition_id="start-eventlog-a",
    )
    _request_and_close(
        registry,
        first_service,
        requested_at=_START + timedelta(seconds=5),
    )
    with pytest.raises(StateError, match="service instance intervals cannot overlap"):
        registry.register_service_instance(
            logical,
            replace(
                first_service,
                object_id="eventlog-backfill",
                boot_id="boot-backfill",
                started_at=_START + timedelta(seconds=3),
            ),
            action_id="start-eventlog-backfill",
            transition_id="start-eventlog-backfill",
        )
    second_service = replace(
        first_service,
        object_id="eventlog-boot-b",
        boot_id="boot-b",
        started_at=_START + timedelta(seconds=5),
    )
    registry.register_service_instance(
        logical,
        second_service,
        action_id="start-eventlog-b",
        transition_id="start-eventlog-b",
    )
    assert (
        registry.service_for_logical_at(
            logical.hostname,
            logical.logical_service_id,
            _START + timedelta(seconds=4),
        ).identity
        == first_service
    )
    assert (
        registry.service_for_logical_at(
            logical.hostname,
            logical.logical_service_id,
            _START + timedelta(seconds=6),
        ).identity
        == second_service
    )

    tuple_value = NetworkTuple("10.10.0.1", 55000, "10.10.0.2", 22, "tcp")
    future = TransportLifecycleIdentity(
        hostname="TEMPORAL-SOURCE",
        object_id="transport-future",
        transport_id="plan-future",
        src_hostname="TEMPORAL-SOURCE",
        dst_hostname="TEMPORAL-TARGET",
        network_tuple=tuple_value,
        opened_at=_START + timedelta(seconds=20),
        close_deadline=_START + timedelta(seconds=30),
        zeek_uid="C-future",
    )
    prior = replace(
        future,
        object_id="transport-prior",
        transport_id="plan-prior",
        opened_at=_START + timedelta(seconds=10),
        close_deadline=_START + timedelta(seconds=20),
        zeek_uid="C-prior",
    )
    registry.register_transport(
        future,
        action_id="start-future",
        transition_id="start-future",
    )
    registry.register_transport(
        prior,
        action_id="start-prior",
        transition_id="start-prior",
    )
    assert (
        registry.transport_for_tuple_at(prior.hostname, prior.tuple_key, prior.opened_at).identity
        == prior
    )
    assert (
        registry.transport_for_tuple_at(
            future.hostname,
            future.tuple_key,
            future.opened_at,
        ).identity
        == future
    )
    with pytest.raises(StateError, match="transport tuple intervals cannot overlap"):
        registry.register_transport(
            replace(
                prior,
                object_id="transport-overlap",
                transport_id="plan-overlap",
                close_deadline=_START + timedelta(seconds=21),
                zeek_uid="C-overlap",
            ),
            action_id="start-overlap",
            transition_id="start-overlap",
        )


def test_relations_cannot_backfill_after_an_accepted_close_barrier() -> None:
    registry = LifecycleRegistry(shard_count=8)
    process = _register_process(
        registry,
        object_id="barrier-service-process",
        pid=6200,
        hostname="BARRIER-SRV",
        session_object_id="",
    )
    logical = LogicalServiceIdentity(
        hostname=process.hostname,
        logical_service_id="windows:schedule",
        canonical_name="Schedule",
        service_kind="builtin",
    )
    service = ServiceInstanceLifecycleIdentity(
        hostname=process.hostname,
        object_id="barrier-schedule-service",
        logical_service_id=logical.logical_service_id,
        boot_id="boot-barrier",
        instance_id="builtin",
        started_at=_START + timedelta(seconds=1),
    )
    registry.register_service_instance(
        logical,
        service,
        action_id="start-schedule",
        transition_id="start-schedule",
    )
    registry.request_close(
        LifecycleCloseBarrier(
            barrier_id="schedule-barrier",
            subject=service.ref,
            requested_at=_START + timedelta(minutes=5),
            authority="generated",
            action_id="close-schedule",
        ),
        ticket_id="schedule-ticket",
    )
    with pytest.raises(StateError, match="already accepted a close barrier"):
        registry.bind_service_process(
            ServiceProcessBindingIdentity(
                binding_id="retroactive-service-binding",
                service_object_id=service.object_id,
                process_object_id=process.object_id,
                bound_at=_START + timedelta(seconds=2),
                role="shared_host_process",
                action_id="retroactive-service-binding",
            )
        )

    session = _register_session(
        registry,
        object_id="barrier-transport-session",
        logon_id="0xbarrier",
        hostname="BARRIER-TARGET",
    )
    deadline = _START + timedelta(minutes=10)
    transport = TransportLifecycleIdentity(
        hostname="BARRIER-SOURCE",
        object_id="barrier-transport",
        transport_id="barrier-network-plan",
        src_hostname="BARRIER-SOURCE",
        dst_hostname=session.hostname,
        network_tuple=NetworkTuple("10.20.0.1", 50100, "10.20.0.2", 3389, "tcp"),
        opened_at=_START + timedelta(seconds=1),
        close_deadline=deadline,
        zeek_uid="C-barrier-transport",
    )
    registry.register_transport(
        transport,
        action_id="start-barrier-transport",
        transition_id="start-barrier-transport",
    )
    registry.request_close(
        LifecycleCloseBarrier(
            barrier_id="transport-barrier",
            subject=transport.ref,
            requested_at=deadline,
            authority="authoritative",
            action_id="close-barrier-transport",
        ),
        ticket_id="transport-ticket",
    )
    with pytest.raises(StateError, match="transport accepted a close barrier"):
        registry.bind_transport_session(
            TransportSessionBindingIdentity(
                binding_id="retroactive-transport-binding",
                transport_object_id=transport.object_id,
                session_object_id=session.object_id,
                bound_at=_START + timedelta(seconds=2),
                role="session",
                action_id="retroactive-transport-binding",
            )
        )
    census = registry.census()
    assert census.active_service_process_bindings == 0
    assert census.active_transport_session_bindings == 0


def test_transport_binding_close_is_aba_fenced_and_failure_is_atomic() -> None:
    registry = LifecycleRegistry(
        shard_count=8,
        closed_retention=timedelta(seconds=1),
    )
    session = _register_session(
        registry,
        object_id="aba-session",
        logon_id="0xaba",
        hostname="ABA-TARGET",
    )
    deadline = _START + timedelta(hours=1)
    transport = TransportLifecycleIdentity(
        hostname="ABA-SOURCE",
        object_id="aba-transport",
        transport_id="aba-plan",
        src_hostname="ABA-SOURCE",
        dst_hostname=session.hostname,
        network_tuple=NetworkTuple("10.30.0.1", 50200, "10.30.0.2", 22, "tcp"),
        opened_at=_START + timedelta(seconds=1),
        close_deadline=deadline,
        zeek_uid="C-aba",
    )
    registry.register_transport(
        transport,
        action_id="start-aba-transport",
        transition_id="start-aba-transport",
    )
    first = TransportSessionBindingIdentity(
        binding_id="reused-binding-id",
        transport_object_id=transport.object_id,
        session_object_id=session.object_id,
        bound_at=_START + timedelta(seconds=2),
        role="session",
        action_id="bind-first",
    )
    registry.bind_transport_session(first)
    with pytest.raises(StateError, match="closes after transport deadline"):
        registry.close_transport_session_binding(
            first.binding_id,
            expected_identity=first,
            closed_at=deadline + timedelta(microseconds=1),
            action_id="invalid-close",
        )
    assert registry.transport_binding_page(transport.object_id, limit=2)[0][0].identity == first
    assert (
        registry.session_transport_binding_page(session.object_id, limit=2)[0][0].identity == first
    )
    assert registry.census().active_transport_session_bindings == 1

    first_closed_at = _START + timedelta(seconds=5)
    registry.close_transport_session_binding(
        first.binding_id,
        expected_identity=first,
        closed_at=first_closed_at,
        action_id="close-first",
    )
    registry.advance_watermark(first_closed_at + timedelta(seconds=1))
    assert registry.transport_session_binding(first.binding_id) is None

    second = replace(
        first,
        bound_at=first_closed_at + timedelta(seconds=2),
        action_id="bind-second",
    )
    registry.bind_transport_session(second)
    with pytest.raises(StateError, match="identity changed before close"):
        registry.close_transport_session_binding(
            first.binding_id,
            expected_identity=first,
            closed_at=second.bound_at + timedelta(seconds=1),
            action_id="stale-close-first",
        )
    assert registry.transport_session_binding(second.binding_id).identity == second
    assert registry.census().active_transport_session_bindings == 1
    registry.close_transport_session_binding(
        second.binding_id,
        expected_identity=second,
        closed_at=second.bound_at + timedelta(seconds=1),
        action_id="close-second",
    )


def _run_cross_partition_binding_program(workers: int) -> tuple[object, ...]:
    registry = LifecycleRegistry(shard_count=8)
    host_a = "LOCK-ORDER-A"
    partition_a = registry._partition_id(host_a)
    host_b = next(
        f"LOCK-ORDER-B-{ordinal}"
        for ordinal in range(100)
        if registry._partition_id(f"LOCK-ORDER-B-{ordinal}") != partition_a
    )
    session_a = _register_session(
        registry,
        object_id="lock-session-a",
        logon_id="0xlocka",
        hostname=host_a,
    )
    session_b = _register_session(
        registry,
        object_id="lock-session-b",
        logon_id="0xlockb",
        hostname=host_b,
    )
    bindings: list[TransportSessionBindingIdentity] = []
    for ordinal in range(32):
        source, target = (host_a, session_b) if ordinal % 2 == 0 else (host_b, session_a)
        transport = TransportLifecycleIdentity(
            hostname=source,
            object_id=f"lock-transport-{ordinal}",
            transport_id=f"lock-plan-{ordinal}",
            src_hostname=source,
            dst_hostname=target.hostname,
            network_tuple=NetworkTuple(
                f"10.40.{ordinal // 250}.{ordinal % 250 + 1}",
                51000 + ordinal,
                f"10.41.{ordinal // 250}.{ordinal % 250 + 1}",
                22,
                "tcp",
            ),
            opened_at=_START + timedelta(seconds=1),
            close_deadline=_START + timedelta(minutes=10),
            zeek_uid=f"C-lock-{ordinal}",
        )
        registry.register_transport(
            transport,
            action_id=f"start-lock-{ordinal}",
            transition_id=f"start-lock-{ordinal}",
        )
        binding = TransportSessionBindingIdentity(
            binding_id=f"lock-binding-{ordinal}",
            transport_object_id=transport.object_id,
            session_object_id=target.object_id,
            bound_at=_START + timedelta(seconds=2),
            role="session",
            action_id=f"bind-lock-{ordinal}",
        )
        registry.bind_transport_session(binding)
        bindings.append(binding)

    def close_binding(binding: TransportSessionBindingIdentity) -> tuple[str, datetime | None]:
        snapshot = registry.close_transport_session_binding(
            binding.binding_id,
            expected_identity=binding,
            closed_at=_START + timedelta(minutes=5),
            action_id=f"close-{binding.binding_id}",
        )
        return (snapshot.identity.binding_id, snapshot.closed_at)

    with ThreadPoolExecutor(max_workers=workers) as executor:
        closed = tuple(executor.map(close_binding, reversed(bindings)))
    census = registry.census()
    assert registry.session_transport_binding_page(session_a.object_id, limit=1) == ((), None)
    assert registry.session_transport_binding_page(session_b.object_id, limit=1) == ((), None)
    return (
        tuple(sorted(closed)),
        census.transport_session_bindings,
        census.active_transport_session_bindings,
        census.binding_index_backing_entries,
    )


def test_cross_partition_binding_lock_order_and_worker_digest_are_stable() -> None:
    results = {workers: _run_cross_partition_binding_program(workers) for workers in (1, 4, 8)}
    assert results[1] == results[4] == results[8]


def test_service_and_transport_controls_are_time_fenced_and_retained() -> None:
    registry = LifecycleRegistry(
        shard_count=8,
        closed_retention=timedelta(seconds=1),
    )
    logical = LogicalServiceIdentity(
        hostname="CONTROL-SRV",
        logical_service_id="windows:taskscheduler",
        canonical_name="Task Scheduler",
        service_kind="builtin",
    )
    service = ServiceInstanceLifecycleIdentity(
        hostname=logical.hostname,
        object_id="control-service",
        logical_service_id=logical.logical_service_id,
        boot_id="control-boot",
        instance_id="builtin",
        started_at=_START,
    )
    registry.register_service_instance(
        logical,
        service,
        action_id="control-service-start",
        transition_id="control-service-start",
    )
    hold_until = _START + timedelta(minutes=3)
    registry.add_hold(
        LifecycleHold(
            hold_id="control-service-hold",
            subject=service.ref,
            acquired_at=_START + timedelta(seconds=1),
            hold_until=hold_until,
            action_id="control-service-hold",
            reason="scheduled_task_child",
        )
    )
    service_barrier = LifecycleCloseBarrier(
        barrier_id="control-service-barrier",
        subject=service.ref,
        requested_at=_START + timedelta(minutes=1),
        authority="generated",
        action_id="control-service-close",
    )
    service_ticket = registry.request_close(
        service_barrier,
        ticket_id="control-service-ticket",
    )
    assert service_ticket.effective_at == hold_until
    assert registry.close(service_ticket.ticket_id).closed_at == hold_until
    lease = LifecycleRetentionLease(
        lease_id="control-service-reference",
        subject=service.ref,
        retain_until=hold_until + timedelta(minutes=5),
        reason="rendered_service_reference",
    )
    registry.add_retention_lease(lease)
    assert registry.advance_watermark(hold_until + timedelta(seconds=1)) == ()
    assert registry.get_service_instance(service.object_id) is not None

    transport_opened_at = hold_until + timedelta(seconds=2)
    transport_deadline = hold_until + timedelta(minutes=10)
    transport = TransportLifecycleIdentity(
        hostname="CONTROL-SOURCE",
        object_id="control-transport",
        transport_id="control-network-plan",
        src_hostname="CONTROL-SOURCE",
        dst_hostname="CONTROL-TARGET",
        network_tuple=NetworkTuple("10.50.0.1", 52000, "10.50.0.2", 3389, "tcp"),
        opened_at=transport_opened_at,
        close_deadline=transport_deadline,
        zeek_uid="C-control-transport",
    )
    registry.register_transport(
        transport,
        action_id="control-transport-start",
        transition_id="control-transport-start",
    )
    before_lookup = registry.census().lookup_candidates_inspected
    assert registry.get_service_instance(service.object_id).identity == service
    assert registry.get_service_instance("missing-service") is None
    assert registry.get_transport(transport.object_id).identity == transport
    assert registry.get_transport("missing-transport") is None
    assert registry.census().lookup_candidates_inspected - before_lookup == 2
    with pytest.raises(StateError, match="beyond its canonical deadline"):
        registry.add_hold(
            LifecycleHold(
                hold_id="control-transport-invalid-hold",
                subject=transport.ref,
                acquired_at=transport.opened_at,
                hold_until=transport_deadline + timedelta(microseconds=1),
                action_id="control-transport-invalid-hold",
                reason="invalid_channel_tail",
            )
        )
    assert registry.get_transport(transport.object_id).hold_count == 0
    with pytest.raises(StateError, match="at or behind watermark"):
        registry.record_dependent(
            transport.ref,
            transition_id="control-transport-late-dependent",
            canonical_time=hold_until,
            action_id="control-transport-late-dependent",
        )


def test_temporal_digest_collisions_fail_before_partial_service_publish(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    registry = LifecycleRegistry(shard_count=1)
    first_logical = LogicalServiceIdentity(
        hostname="COLLISION-SRV",
        logical_service_id="windows:first",
        canonical_name="First",
        service_kind="builtin",
    )
    first = ServiceInstanceLifecycleIdentity(
        hostname=first_logical.hostname,
        object_id="collision-first",
        logical_service_id=first_logical.logical_service_id,
        boot_id="boot-collision",
        instance_id="builtin",
        started_at=_START,
    )
    registry.register_service_instance(
        first_logical,
        first,
        action_id="collision-first",
        transition_id="collision-first",
    )
    original_hash = lifecycle_registry_module._semantic_hash

    def collide_service_groups(namespace: str, *parts: str) -> int:
        if namespace == "lifecycle-service-logical":
            return original_hash(
                namespace,
                first_logical.hostname.casefold(),
                first_logical.logical_service_id.casefold(),
            )
        return original_hash(namespace, *parts)

    monkeypatch.setattr(lifecycle_registry_module, "_semantic_hash", collide_service_groups)
    second_logical = replace(
        first_logical,
        logical_service_id="windows:second",
        canonical_name="Second",
    )
    second = replace(
        first,
        object_id="collision-second",
        logical_service_id=second_logical.logical_service_id,
        started_at=_START + timedelta(seconds=1),
    )
    with pytest.raises(StateError, match="temporal digest collision"):
        registry.register_service_instance(
            second_logical,
            second,
            action_id="collision-second",
            transition_id="collision-second",
        )
    assert registry.get_service_instance(second.object_id) is None
    assert registry.census().service_instance_entries == 1


def test_transport_lifecycle_rejects_ports_that_cannot_be_packed() -> None:
    with pytest.raises(ValueError, match="ports must be between"):
        TransportLifecycleIdentity(
            hostname="PORT-SOURCE",
            object_id="invalid-port-transport",
            transport_id="invalid-port-plan",
            src_hostname="PORT-SOURCE",
            dst_hostname="PORT-TARGET",
            network_tuple=NetworkTuple("10.60.0.1", 65_536, "10.60.0.2", 22, "tcp"),
            opened_at=_START,
            close_deadline=_START + timedelta(seconds=1),
            zeek_uid="C-invalid-port",
        )
