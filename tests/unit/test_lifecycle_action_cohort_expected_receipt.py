# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Claim-time lifecycle action-cohort receipt and primitive-tail contracts."""

import gc
from collections.abc import Callable
from copy import copy
from dataclasses import replace
from datetime import UTC, datetime, timedelta, tzinfo
from threading import Thread, get_ident
from weakref import ref

import pytest

import evidenceforge.generation.lifecycle_registry as lifecycle_registry_module
from evidenceforge.events.lifecycle import (
    LifecycleCloseBarrier,
    LifecycleEntityRef,
    LifecycleHold,
    LifecycleMembership,
    LifecycleTransition,
    ProcessLifecycleIdentity,
    ProcessTokenIdentity,
    SessionLifecycleIdentity,
)
from evidenceforge.generation.lifecycle_registry import (
    LifecycleActionCohortReceipt,
    LifecycleActionCohortRequest,
    LifecycleProcessStartRequest,
    LifecycleRegistry,
    LifecycleSessionStartRequest,
    LifecycleSubjectClosureControl,
)
from evidenceforge.models.exceptions import StateError

_START = datetime(2026, 8, 17, 14, 0, tzinfo=UTC)


def _session_start(*, suffix: str = "expected") -> LifecycleSessionStartRequest:
    return LifecycleSessionStartRequest(
        identity=SessionLifecycleIdentity(
            hostname="LINUX-EXPECTED-01",
            object_id=f"{suffix}-session",
            logon_id="0x51001",
            principal="analyst",
            session_kind="interactive",
            started_at=_START,
            session_id=7,
        ),
        action_id=f"{suffix}-session-start-action",
        transition_id=f"{suffix}-session-started",
    )


def _process_start(session: LifecycleSessionStartRequest) -> LifecycleProcessStartRequest:
    return LifecycleProcessStartRequest(
        identity=ProcessLifecycleIdentity(
            hostname=session.identity.hostname,
            object_id="expected-process",
            pid=5_101,
            started_at=_START + timedelta(seconds=1),
            image="/usr/bin/id",
        ),
        token=ProcessTokenIdentity(
            principal=session.identity.principal,
            logon_id=session.identity.logon_id,
            session_id=session.identity.session_id,
            logon_type=2,
            integrity_level="Medium",
        ),
        membership=LifecycleMembership(
            owner_kind="session",
            owner_object_id=session.identity.object_id,
            session_object_id=session.identity.object_id,
        ),
        action_id="expected-process-start-action",
        transition_id="expected-process-started",
    )


def _closure(
    subject: LifecycleEntityRef,
    *,
    requested_at: datetime,
    suffix: str,
) -> LifecycleSubjectClosureControl:
    return LifecycleSubjectClosureControl(
        barrier=LifecycleCloseBarrier(
            barrier_id=f"{suffix}-barrier",
            subject=subject,
            requested_at=requested_at,
            authority="authoritative",
            action_id=f"{suffix}-close-action",
        ),
        ticket_id=f"{suffix}-ticket",
    )


def _closed_request() -> LifecycleActionCohortRequest:
    session = _session_start()
    process = _process_start(session)
    dependent = LifecycleTransition(
        transition_id="expected-process-dependent",
        subject=process.identity.ref,
        kind="dependent",
        canonical_time=_START + timedelta(seconds=2),
        action_id="expected-process-dependent-action",
        reason="command execution",
    )
    hold = LifecycleHold(
        hold_id="expected-process-hold",
        subject=process.identity.ref,
        acquired_at=_START + timedelta(seconds=3),
        hold_until=_START + timedelta(seconds=4),
        action_id="expected-process-hold-action",
        reason="retain through output collection",
    )
    return LifecycleActionCohortRequest(
        state_publication_token="opaque-expected-state-plan",
        operations=(
            session,
            process,
            dependent,
            hold,
            _closure(
                process.identity.ref,
                requested_at=_START + timedelta(seconds=5),
                suffix="expected-process",
            ),
            _closure(
                session.identity.ref,
                requested_at=_START + timedelta(seconds=6),
                suffix="expected-session",
            ),
        ),
    )


def _capture_failure(call: Callable[[], object], failures: list[BaseException]) -> None:
    try:
        call()
    except BaseException as exc:  # pragma: no cover - exercised in the worker thread
        failures.append(exc)


def _assert_no_transient_claim_state(registry: LifecycleRegistry) -> None:
    census = registry.action_cohort_preparation_census()
    assert census.reservations == 0
    assert census.unclaimed_reservations == 0
    assert census.claimed_reservations == 0
    assert census.committing_reservations == 0
    assert census.reserved_keys == 0
    assert census.capability_locators == 0
    assert census.claimed_capability_locators == 0
    assert census.certified_authorization_locators == 0
    assert census.expected_receipt_authorities == 0
    assert census.retained_request_bytes == 0
    assert census.pending_provenance_insertions == 0
    assert census.pending_provenance_evictions == 0


def test_claim_exposes_authentic_expected_receipt_and_commit_returns_same_identity() -> None:
    registry = LifecycleRegistry(shard_count=4)
    request = _closed_request()
    token = registry.prepare_action_cohort(request)

    with registry.claimed_action_cohort(token) as prepared:
        expected = prepared.expected_receipt
        assert type(expected) is LifecycleActionCohortReceipt
        assert registry.authenticates_expected_action_cohort_receipt(
            expected,
            state_publication_token=request.state_publication_token,
        )
        assert prepared.receipt is None
        assert registry.get_session("expected-session") is None
        assert registry.get_process("expected-process") is None

        receipt = prepared.commit_no_fail()

        assert receipt is expected
        assert prepared.receipt is expected
        assert prepared.expected_receipt is expected

    with pytest.raises(StateError, match="no longer active"):
        _ = prepared.expected_receipt
    assert registry.get_process("expected-process") == expected.operation_results[1]
    assert registry.get_session("expected-session") == expected.operation_results[0]
    assert registry.action_cohort_preparation_census().reservations == 0


def test_expected_and_committed_receipt_authorities_are_exact_and_terminal() -> None:
    registry = LifecycleRegistry()
    request = LifecycleActionCohortRequest(
        state_publication_token="opaque-terminal-receipt-state-plan",
        operations=(_session_start(suffix="terminal-receipt"),),
    )
    token = registry.prepare_action_cohort(request)

    with registry.claimed_action_cohort(token) as prepared:
        expected = prepared.expected_receipt
        copied = replace(expected)
        assert registry.authenticates_expected_action_cohort_receipt(
            expected,
            state_publication_token=request.state_publication_token,
        )
        foreign_request = LifecycleActionCohortRequest(
            state_publication_token=request.state_publication_token,
            operations=(_session_start(suffix="foreign-expected-binding"),),
        )
        with pytest.raises(TypeError, match="unexpected keyword argument"):
            registry.authenticates_expected_action_cohort_receipt(
                expected,
                request=foreign_request,  # type: ignore[call-arg]
            )
        assert not registry.authenticates_expected_action_cohort_receipt(copied)
        assert not registry.authenticates_action_cohort_receipt(expected)
        assert not registry.authenticates_action_cohort_receipt(copied)

        receipt = prepared.commit_no_fail()

        assert receipt is expected
        assert not registry.authenticates_expected_action_cohort_receipt(receipt)
        assert registry.authenticates_action_cohort_receipt(
            receipt,
            request=request,
            state_publication_token=request.state_publication_token,
        )
        assert not registry.authenticates_action_cohort_receipt(replace(receipt))

    census = registry.action_cohort_preparation_census()
    assert census.expected_receipt_authorities == 0
    assert census.committed_receipt_authorities == 1


def test_committed_receipt_authority_is_bounded_and_dead_locators_are_prunable() -> None:
    registry = LifecycleRegistry()
    registry._action_cohort_receipt_authority_capacity = 1
    first_request = LifecycleActionCohortRequest(
        state_publication_token="opaque-terminal-cap-first-state-plan",
        operations=(_session_start(suffix="terminal-cap-first"),),
    )
    first_token = registry.prepare_action_cohort(first_request)
    with registry.claimed_action_cohort(first_token) as prepared:
        first_receipt = prepared.commit_no_fail()

    second_start = _session_start(suffix="terminal-cap-second")
    second_start = replace(
        second_start,
        identity=replace(second_start.identity, logon_id="0x51002", session_id=8),
    )
    second_request = LifecycleActionCohortRequest(
        state_publication_token="opaque-terminal-cap-second-state-plan",
        operations=(second_start,),
    )
    second_token = registry.prepare_action_cohort(second_request)
    with registry.claimed_action_cohort(second_token) as prepared:
        second_receipt = prepared.commit_no_fail()

    assert not registry.authenticates_action_cohort_receipt(first_receipt)
    assert registry.authenticates_action_cohort_receipt(second_receipt)
    census = registry.action_cohort_preparation_census()
    assert census.committed_receipt_authorities == 1
    assert census.receipt_authority_capacity == 1

    receipt_ref = ref(second_receipt)
    del second_receipt
    del prepared
    gc.collect()
    assert receipt_ref() is None
    assert registry.prune_action_cohort_receipt_authorities() == 1
    assert registry.action_cohort_preparation_census().committed_receipt_authorities == 0


def test_final_expected_auth_and_certification_do_not_traverse_hostile_datetime() -> None:
    registry = LifecycleRegistry()
    request = LifecycleActionCohortRequest(
        state_publication_token="opaque-hostile-final-auth-state-plan",
        operations=(_session_start(suffix="hostile-final-auth"),),
    )
    token = registry.prepare_action_cohort(request)
    callbacks: list[str] = []

    class ReentrantHostileTimezone(tzinfo):
        def utcoffset(self, _value: datetime | None) -> timedelta:
            callbacks.append("utcoffset")
            registry.action_cohort_preparation_census()
            raise AssertionError("final authentication traversed caller datetime")

        def dst(self, _value: datetime | None) -> timedelta:
            callbacks.append("dst")
            raise AssertionError("final authentication traversed caller datetime")

        def tzname(self, _value: datetime | None) -> str:
            callbacks.append("tzname")
            raise AssertionError("final authentication traversed caller datetime")

    with registry.claimed_action_cohort(token) as prepared:
        expected = prepared.expected_receipt
        exposed_operation = expected.request.operations[0]
        assert type(exposed_operation) is LifecycleSessionStartRequest
        hostile_time = datetime(2026, 8, 17, 14, tzinfo=ReentrantHostileTimezone())
        object.__setattr__(exposed_operation.identity, "started_at", hostile_time)

        assert registry.authenticates_expected_action_cohort_receipt(
            expected,
            state_publication_token=request.state_publication_token,
        )
        prepared.certify_composite_commit(expected)
        assert prepared.commit_no_fail() is expected

    assert callbacks == []
    committed = registry.get_session("hostile-final-auth-session")
    assert committed is not None
    assert committed.identity.started_at == _START


def test_commit_tail_uses_no_result_receipt_digest_hmac_or_deepcopy_builder(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    registry = LifecycleRegistry(shard_count=4)
    request = _closed_request()
    token = registry.prepare_action_cohort(request)
    forbidden_calls: list[str] = []

    def forbidden(name: str) -> Callable[..., object]:
        def fail(*_args: object, **_kwargs: object) -> object:
            forbidden_calls.append(name)
            raise AssertionError(f"commit tail invoked forbidden {name}")

        return fail

    with registry.claimed_action_cohort(token) as prepared:
        expected = prepared.expected_receipt
        prepared.certify_composite_commit(expected)
        with monkeypatch.context() as tail:
            tail.setattr(
                registry,
                "_active_action_cohort_reservation_locked",
                forbidden("active reservation validation"),
            )
            tail.setattr(
                registry,
                "_validate_action_cohort_token",
                forbidden("token validation"),
            )
            tail.setattr(
                registry,
                "_authorize_action_cohort_commit_locked",
                forbidden("commit authorization"),
            )
            tail.setattr(
                registry,
                "authenticates_action_cohort_receipt",
                forbidden("receipt authentication"),
            )
            tail.setattr(
                registry,
                "authenticates_expected_action_cohort_receipt",
                forbidden("expected receipt authentication"),
            )
            tail.setattr(
                registry,
                "_action_cohort_expected_results_locked",
                forbidden("result projection"),
            )
            tail.setattr(
                registry,
                "_normalize_action_cohort_results",
                forbidden("result normalization"),
            )
            tail.setattr(
                registry,
                "_action_cohort_committed_digest",
                forbidden("committed digest"),
            )
            tail.setattr(
                registry,
                "_action_cohort_receipt_integrity",
                forbidden("receipt HMAC"),
            )
            tail.setattr(
                lifecycle_registry_module,
                "LifecycleActionCohortReceipt",
                forbidden("receipt construction"),
            )
            tail.setattr(
                lifecycle_registry_module,
                "ProcessLifecycleSnapshot",
                forbidden("process result construction"),
            )
            tail.setattr(
                lifecycle_registry_module,
                "SessionLifecycleSnapshot",
                forbidden("session result construction"),
            )
            tail.setattr(
                lifecycle_registry_module,
                "deepcopy",
                forbidden("deepcopy"),
            )

            receipt = prepared.commit_no_fail()

        assert receipt is expected

    assert not forbidden_calls
    assert registry.authenticates_action_cohort_receipt(receipt, request=request)


def test_composite_certification_is_exact_one_shot_and_same_thread() -> None:
    request = LifecycleActionCohortRequest(
        state_publication_token="opaque-certified-state-plan",
        operations=(_session_start(suffix="certified"),),
    )
    foreign = LifecycleRegistry()
    foreign_token = foreign.prepare_action_cohort(request)
    with foreign.claimed_action_cohort(foreign_token) as foreign_prepared:
        foreign_receipt = foreign_prepared.commit_no_fail()

    registry = LifecycleRegistry()
    token = registry.prepare_action_cohort(request)
    failures: list[BaseException] = []
    with registry.claimed_action_cohort(token) as prepared:
        expected = prepared.expected_receipt
        with pytest.raises(StateError, match="exact expected receipt object"):
            prepared.certify_composite_commit(replace(expected))
        with pytest.raises(StateError, match="exact expected receipt object"):
            prepared.certify_composite_commit(foreign_receipt)

        worker = Thread(
            target=lambda: _capture_failure(
                lambda: prepared.certify_composite_commit(expected),
                failures,
            ),
            daemon=True,
        )
        worker.start()
        worker.join(timeout=2)
        assert not worker.is_alive()
        assert len(failures) == 1
        assert isinstance(failures[0], StateError)
        assert "claiming thread" in str(failures[0])
        assert registry.get_session("certified-session") is None

        prepared.certify_composite_commit(expected)
        with pytest.raises(StateError, match="already composite-certified"):
            prepared.certify_composite_commit(expected)
        assert prepared.commit_no_fail() is expected
        assert prepared.receipt is expected


def test_certified_authorization_and_commit_plan_cannot_be_replaced_on_carrier() -> None:
    registry = LifecycleRegistry(shard_count=4)
    request = _closed_request()
    token = registry.prepare_action_cohort(request)

    with registry.claimed_action_cohort(token) as prepared:
        expected = prepared.expected_receipt
        prepared.certify_composite_commit(expected)
        locator = registry._action_cohort_certified_authorizations[id(prepared)]
        authorization = locator.authorization
        forged_plan = replace(authorization.commit_plan, operations=())
        forged_authorization = replace(authorization, commit_plan=forged_plan)

        with pytest.raises(StateError, match="exact registered prepared capability"):
            registry._commit_certified_action_cohort(forged_authorization)  # type: ignore[arg-type]
        with pytest.raises(AttributeError):
            object.__setattr__(prepared, "_certified_commit", forged_authorization)

        assert registry.get_session("expected-session") is None
        assert registry.get_process("expected-process") is None
        assert prepared.commit_no_fail() is expected

    assert registry.get_session("expected-session") == expected.operation_results[0]
    assert registry.get_process("expected-process") == expected.operation_results[1]
    census = registry.action_cohort_preparation_census()
    assert census.reservations == 0
    assert census.certified_authorization_locators == 0


def test_certified_commit_ignores_replaced_carrier_token_and_expected_receipt() -> None:
    registry = LifecycleRegistry()
    request = LifecycleActionCohortRequest(
        state_publication_token="opaque-certified-carrier-isolation-state-plan",
        operations=(_session_start(suffix="certified-carrier-isolation"),),
    )
    token = registry.prepare_action_cohort(request)

    with registry.claimed_action_cohort(token) as prepared:
        expected = prepared.expected_receipt
        prepared.certify_composite_commit(expected)
        locator = registry._action_cohort_certified_authorizations[id(prepared)]
        forged_receipt = replace(expected)
        forged_authorization = replace(
            locator.authorization,
            expected_receipt=forged_receipt,
        )

        with pytest.raises(StateError, match="exact registered prepared capability"):
            registry._commit_certified_action_cohort(forged_authorization)  # type: ignore[arg-type]
        object.__setattr__(prepared, "_token", object())
        object.__setattr__(prepared, "_expected_receipt", forged_receipt)

        receipt = prepared.commit_no_fail()
        assert receipt is expected
        assert receipt is not forged_receipt
        assert registry.authenticates_action_cohort_receipt(receipt, request=request)

    assert registry.get_session("certified-carrier-isolation-session") is not None
    assert registry.action_cohort_preparation_census().certified_authorization_locators == 0


def test_certified_commit_restores_post_cert_receipt_and_nested_mutation() -> None:
    registry = LifecycleRegistry()
    request = LifecycleActionCohortRequest(
        state_publication_token="opaque-certified-receipt-restore-state-plan",
        operations=(_session_start(suffix="certified-receipt-restore"),),
    )
    token = registry.prepare_action_cohort(request)

    with registry.claimed_action_cohort(token) as prepared:
        expected = prepared.expected_receipt
        prepared.certify_composite_commit(expected)
        object.__setattr__(
            expected.request,
            "state_publication_token",
            "forged-after-certification",
        )
        result = expected.operation_results[0]
        object.__setattr__(result.identity, "hostname", "FORGED-AFTER-CERTIFICATION")
        object.__setattr__(expected, "committed_digest", "0" * 64)
        assert not registry.authenticates_expected_action_cohort_receipt(expected)

        receipt = prepared.commit_no_fail()

        assert receipt is expected
        assert receipt.request == request
        assert receipt.operation_results[0].identity.hostname == "LINUX-EXPECTED-01"
        assert registry.authenticates_action_cohort_receipt(receipt, request=request)

    committed = registry.get_session("certified-receipt-restore-session")
    assert committed is not None
    assert committed.identity.hostname == "LINUX-EXPECTED-01"


def test_certified_commit_uses_owner_thread_when_carrier_thread_is_replaced() -> None:
    registry = LifecycleRegistry()
    request = LifecycleActionCohortRequest(
        state_publication_token="opaque-certified-owner-thread-state-plan",
        operations=(_session_start(suffix="certified-owner-thread"),),
    )
    token = registry.prepare_action_cohort(request)
    failures: list[BaseException] = []

    with registry.claimed_action_cohort(token) as prepared:
        expected = prepared.expected_receipt
        prepared.certify_composite_commit(expected)
        owner_thread_id = get_ident()

        def attempt_from_foreign_thread() -> None:
            object.__setattr__(prepared, "_claim_thread_id", get_ident())
            _capture_failure(prepared.commit_no_fail, failures)

        worker = Thread(target=attempt_from_foreign_thread, daemon=True)
        worker.start()
        worker.join(timeout=2)
        assert not worker.is_alive()
        assert len(failures) == 1
        assert isinstance(failures[0], StateError)
        assert "exact registered prepared capability" in str(failures[0])
        assert registry.get_session("certified-owner-thread-session") is None

        object.__setattr__(prepared, "_claim_thread_id", owner_thread_id)
        assert prepared.commit_no_fail() is expected

    assert registry.get_session("certified-owner-thread-session") is not None
    assert registry.action_cohort_preparation_census().certified_authorization_locators == 0


def test_shallow_copy_cannot_commit_uncertified_exact_claim() -> None:
    registry = LifecycleRegistry()
    request = LifecycleActionCohortRequest(
        state_publication_token="opaque-uncertified-copy-state-plan",
        operations=(_session_start(suffix="uncertified-copy"),),
    )
    token = registry.prepare_action_cohort(request)

    with registry.claimed_action_cohort(token) as prepared:
        copied = copy(prepared)
        with pytest.raises(StateError, match="exact registered prepared capability"):
            copied.commit_no_fail()
        assert registry.get_session("uncertified-copy-session") is None
        assert prepared.commit_no_fail() is prepared.expected_receipt

    assert registry.get_session("uncertified-copy-session") is not None
    census = registry.action_cohort_preparation_census()
    assert census.claimed_capability_locators == 0
    assert census.certified_authorization_locators == 0


def test_shallow_copy_cannot_consume_original_composite_certification() -> None:
    registry = LifecycleRegistry()
    request = LifecycleActionCohortRequest(
        state_publication_token="opaque-certified-copy-state-plan",
        operations=(_session_start(suffix="certified-copy"),),
    )
    token = registry.prepare_action_cohort(request)

    with registry.claimed_action_cohort(token) as prepared:
        expected = prepared.expected_receipt
        prepared.certify_composite_commit(expected)
        copied = copy(prepared)

        with pytest.raises(StateError, match="exact registered prepared capability"):
            copied.commit_no_fail()
        assert registry.get_session("certified-copy-session") is None
        assert prepared.commit_no_fail() is expected

    assert registry.get_session("certified-copy-session") is not None
    census = registry.action_cohort_preparation_census()
    assert census.claimed_capability_locators == 0
    assert census.certified_authorization_locators == 0


def test_shallow_copy_committed_tamper_cannot_skip_original_cleanup_and_retry() -> None:
    registry = LifecycleRegistry()
    request = LifecycleActionCohortRequest(
        state_publication_token="opaque-copy-cleanup-state-plan",
        operations=(_session_start(suffix="copy-cleanup"),),
    )
    token = registry.prepare_action_cohort(request)

    with pytest.raises(StateError, match="without commit_no_fail"):
        with registry.claimed_action_cohort(token) as prepared:
            copied = copy(prepared)
            object.__setattr__(copied, "_committed", True)
            assert copied.committed
            assert not prepared.committed

    census = registry.action_cohort_preparation_census()
    assert census.reservations == 0
    assert census.claimed_reservations == 0
    assert census.claimed_capability_locators == 0
    assert census.certified_authorization_locators == 0
    assert registry.get_session("copy-cleanup-session") is None

    retry_token = registry.prepare_action_cohort(request)
    with registry.claimed_action_cohort(retry_token) as prepared:
        retry_expected = prepared.expected_receipt
        assert prepared.commit_no_fail() is retry_expected
    assert registry.get_session("copy-cleanup-session") is not None


def test_normal_claim_exit_uses_registry_truth_when_carrier_claims_commit() -> None:
    registry = LifecycleRegistry()
    request = LifecycleActionCohortRequest(
        state_publication_token="opaque-false-commit-normal-state-plan",
        operations=(_session_start(suffix="false-commit-normal"),),
    )
    token = registry.prepare_action_cohort(request)

    with pytest.raises(StateError, match="without commit_no_fail"):
        with registry.claimed_action_cohort(token) as prepared:
            prepared.certify_composite_commit(prepared.expected_receipt)
            object.__setattr__(prepared, "_committed", True)

    assert registry.get_session("false-commit-normal-session") is None
    census = registry.action_cohort_preparation_census()
    assert census.reservations == 0
    assert census.claimed_reservations == 0
    assert census.reserved_keys == 0
    assert census.capability_locators == 0
    assert census.claimed_capability_locators == 0
    assert census.certified_authorization_locators == 0
    assert census.pending_provenance_insertions == 0


def test_exceptional_claim_exit_uses_registry_truth_when_carrier_claims_commit() -> None:
    registry = LifecycleRegistry()
    request = LifecycleActionCohortRequest(
        state_publication_token="opaque-false-commit-exception-state-plan",
        operations=(_session_start(suffix="false-commit-exception"),),
    )
    token = registry.prepare_action_cohort(request)

    with pytest.raises(RuntimeError, match="abort after carrier tamper"):
        with registry.claimed_action_cohort(token) as prepared:
            prepared.certify_composite_commit(prepared.expected_receipt)
            object.__setattr__(prepared, "_committed", True)
            raise RuntimeError("abort after carrier tamper")

    assert registry.get_session("false-commit-exception-session") is None
    census = registry.action_cohort_preparation_census()
    assert census.reservations == 0
    assert census.claimed_reservations == 0
    assert census.reserved_keys == 0
    assert census.capability_locators == 0
    assert census.claimed_capability_locators == 0
    assert census.certified_authorization_locators == 0
    assert census.pending_provenance_insertions == 0


def test_claim_cleanup_preserves_body_primary_across_first_and_second_faults(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    registry = LifecycleRegistry()
    request = LifecycleActionCohortRequest(
        state_publication_token="opaque-cleanup-two-fault-state-plan",
        operations=(_session_start(suffix="cleanup-two-fault"),),
    )
    token = registry.prepare_action_cohort(request)
    original_state_release = registry._release_action_cohort_reservation_state_locked
    state_attempts = 0

    def fail_ordinary_release(*_args: object, **_kwargs: object) -> bool:
        raise KeyboardInterrupt("first cleanup fault")

    def fail_first_state_release(*args: object, **kwargs: object) -> bool:
        nonlocal state_attempts
        state_attempts += 1
        if state_attempts == 1:
            raise SystemExit("second cleanup fault")
        return original_state_release(*args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(
        registry,
        "_release_action_cohort_reservation_locked",
        fail_ordinary_release,
    )
    monkeypatch.setattr(
        registry,
        "_release_action_cohort_reservation_state_locked",
        fail_first_state_release,
    )
    primary = RuntimeError("body primary")

    with pytest.raises(RuntimeError) as captured:
        with registry.claimed_action_cohort(token):
            raise primary

    assert captured.value is primary
    assert state_attempts == 2
    notes = getattr(captured.value, "__notes__", ())
    assert any("KeyboardInterrupt" in note for note in notes)
    assert any("SystemExit" in note for note in notes)
    _assert_no_transient_claim_state(registry)


def test_claim_cleanup_ignores_discard_and_close_faults_after_post_release_fault(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    registry = LifecycleRegistry()
    request = LifecycleActionCohortRequest(
        state_publication_token="opaque-cleanup-post-release-state-plan",
        operations=(_session_start(suffix="cleanup-post-release"),),
    )
    token = registry.prepare_action_cohort(request)
    original_release = registry._release_action_cohort_reservation_locked
    forbidden_calls: list[str] = []

    def release_then_raise(*args: object, **kwargs: object) -> bool:
        original_release(*args, **kwargs)  # type: ignore[arg-type]
        raise KeyboardInterrupt("post-release cleanup fault")

    def forbidden_discard(*_args: object, **_kwargs: object) -> bool:
        forbidden_calls.append("discard")
        raise AssertionError("context cleanup called token discard")

    def forbidden_close(_prepared: object) -> None:
        forbidden_calls.append("close")
        raise AssertionError("context cleanup called carrier close")

    monkeypatch.setattr(
        registry,
        "_release_action_cohort_reservation_locked",
        release_then_raise,
    )
    monkeypatch.setattr(
        registry,
        "_discard_action_cohort_reservation_for_token",
        forbidden_discard,
    )
    monkeypatch.setattr(
        lifecycle_registry_module.PreparedLifecycleActionCohort,
        "_close",
        forbidden_close,
    )
    primary = RuntimeError("post-release body primary")

    with pytest.raises(RuntimeError) as captured:
        with registry.claimed_action_cohort(token):
            raise primary

    assert captured.value is primary
    assert forbidden_calls == []
    notes = getattr(captured.value, "__notes__", ())
    assert any("KeyboardInterrupt" in note for note in notes)
    _assert_no_transient_claim_state(registry)


def test_normal_uncommitted_exit_preserves_owner_primary_when_cleanup_faults(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    registry = LifecycleRegistry()
    request = LifecycleActionCohortRequest(
        state_publication_token="opaque-normal-cleanup-fault-state-plan",
        operations=(_session_start(suffix="normal-cleanup-fault"),),
    )
    token = registry.prepare_action_cohort(request)

    def fail_ordinary_release(*_args: object, **_kwargs: object) -> bool:
        raise KeyboardInterrupt("normal cleanup fault")

    monkeypatch.setattr(
        registry,
        "_release_action_cohort_reservation_locked",
        fail_ordinary_release,
    )

    with pytest.raises(StateError, match="without commit_no_fail") as captured:
        with registry.claimed_action_cohort(token):
            pass

    notes = getattr(captured.value, "__notes__", ())
    assert any("KeyboardInterrupt" in note for note in notes)
    _assert_no_transient_claim_state(registry)


@pytest.mark.parametrize("cleanup_fault", ("before", "mid", "after"))
def test_pre_yield_plan_failure_preserves_primary_and_reconciles_cleanup_faults(
    monkeypatch: pytest.MonkeyPatch,
    cleanup_fault: str,
) -> None:
    registry = LifecycleRegistry()
    request = LifecycleActionCohortRequest(
        state_publication_token=f"opaque-pre-yield-{cleanup_fault}-state-plan",
        operations=(_session_start(suffix=f"pre-yield-{cleanup_fault}"),),
    )
    token = registry.prepare_action_cohort(request)
    primary = RuntimeError(f"claim plan {cleanup_fault} primary")
    original_release = registry._release_action_cohort_reservation_locked
    original_state_release = registry._release_action_cohort_reservation_state_locked
    state_attempts = 0

    def fail_plan(*_args: object, **_kwargs: object) -> object:
        raise primary

    def fail_before_release(*_args: object, **_kwargs: object) -> bool:
        raise KeyboardInterrupt("pre-yield cleanup before mutation")

    def release_then_fail(*args: object, **kwargs: object) -> bool:
        original_release(*args, **kwargs)  # type: ignore[arg-type]
        raise KeyboardInterrupt("pre-yield cleanup after mutation")

    def fail_mid_state_release(*args: object, **kwargs: object) -> bool:
        nonlocal state_attempts
        state_attempts += 1
        if state_attempts == 1:
            reservation = args[0]
            registry._action_cohort_capability_locators.pop(reservation.token_id, None)
            raise SystemExit("pre-yield cleanup mid-mutation")
        return original_state_release(*args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(registry, "_prepare_action_cohort_commit_locked", fail_plan)
    if cleanup_fault == "after":
        monkeypatch.setattr(
            registry,
            "_release_action_cohort_reservation_locked",
            release_then_fail,
        )
    else:
        monkeypatch.setattr(
            registry,
            "_release_action_cohort_reservation_locked",
            fail_before_release,
        )
    if cleanup_fault == "mid":
        monkeypatch.setattr(
            registry,
            "_release_action_cohort_reservation_state_locked",
            fail_mid_state_release,
        )

    with pytest.raises(RuntimeError) as captured:
        with registry.claimed_action_cohort(token):
            pytest.fail("claim preparation failure must occur before yield")

    assert captured.value is primary
    notes = getattr(captured.value, "__notes__", ())
    assert any("KeyboardInterrupt" in note for note in notes)
    if cleanup_fault == "mid":
        assert state_attempts == 2
        assert any("SystemExit" in note for note in notes)
    _assert_no_transient_claim_state(registry)


@pytest.mark.parametrize("cleanup_fault", ("before", "after"))
def test_pre_yield_stale_watermark_cleanup_preserves_primary(
    monkeypatch: pytest.MonkeyPatch,
    cleanup_fault: str,
) -> None:
    registry = LifecycleRegistry()
    request = LifecycleActionCohortRequest(
        state_publication_token="opaque-pre-yield-stale-state-plan",
        operations=(_session_start(suffix="pre-yield-stale"),),
    )
    token = registry.prepare_action_cohort(request)
    registry._watermark = _START - timedelta(seconds=1)
    original_release = registry._release_action_cohort_reservation_locked

    def fail_before_release(*_args: object, **_kwargs: object) -> bool:
        raise KeyboardInterrupt("stale cleanup before mutation")

    def release_then_fail(*args: object, **kwargs: object) -> bool:
        original_release(*args, **kwargs)  # type: ignore[arg-type]
        raise KeyboardInterrupt("stale cleanup after mutation")

    monkeypatch.setattr(
        registry,
        "_release_action_cohort_reservation_locked",
        fail_before_release if cleanup_fault == "before" else release_then_fail,
    )

    with pytest.raises(StateError, match="stale after watermark advance") as captured:
        with registry.claimed_action_cohort(token):
            pytest.fail("stale claim must fail before yield")

    notes = getattr(captured.value, "__notes__", ())
    assert any("KeyboardInterrupt" in note for note in notes)
    _assert_no_transient_claim_state(registry)


def test_pre_yield_cleanup_exhaustion_preserves_primary_and_token_retry(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    registry = LifecycleRegistry()
    request = LifecycleActionCohortRequest(
        state_publication_token="opaque-pre-yield-exhausted-state-plan",
        operations=(_session_start(suffix="pre-yield-exhausted"),),
    )
    token = registry.prepare_action_cohort(request)
    primary = RuntimeError("claim preparation primary survives cleanup exhaustion")

    def fail_plan(*_args: object, **_kwargs: object) -> object:
        raise primary

    def fail_release(*_args: object, **_kwargs: object) -> bool:
        raise KeyboardInterrupt("pre-yield cleanup exhausted")

    with monkeypatch.context() as faults:
        faults.setattr(registry, "_prepare_action_cohort_commit_locked", fail_plan)
        faults.setattr(
            registry,
            "_release_action_cohort_reservation_locked",
            fail_release,
        )
        faults.setattr(
            registry,
            "_release_action_cohort_reservation_state_locked",
            fail_release,
        )
        with pytest.raises(RuntimeError) as captured:
            with registry.claimed_action_cohort(token):
                pytest.fail("claim preparation failure must occur before yield")

    assert captured.value is primary
    assert len(getattr(captured.value, "__notes__", ())) == 3
    census = registry.action_cohort_preparation_census()
    assert census.reservations == 1
    assert census.unclaimed_reservations == 1
    assert census.claimed_reservations == 0
    assert census.capability_locators == 1
    assert census.claimed_capability_locators == 0
    assert census.expected_receipt_authorities == 0
    assert census.reserved_keys > 0

    registry.cancel_action_cohort(token)
    _assert_no_transient_claim_state(registry)


@pytest.mark.parametrize("cleanup_fault", ("before", "after"))
def test_malformed_token_claim_cleanup_preserves_validation_primary(
    monkeypatch: pytest.MonkeyPatch,
    cleanup_fault: str,
) -> None:
    registry = LifecycleRegistry()
    request = LifecycleActionCohortRequest(
        state_publication_token="opaque-malformed-token-cleanup-state-plan",
        operations=(_session_start(suffix="malformed-token-cleanup"),),
    )
    token = registry.prepare_action_cohort(request)
    object.__setattr__(token, "plan_digest", "0" * 64)
    original_release = registry._release_action_cohort_reservation_locked

    def fail_before_release(*_args: object, **_kwargs: object) -> bool:
        raise KeyboardInterrupt("malformed-token cleanup before mutation")

    def release_then_fail(*args: object, **kwargs: object) -> bool:
        original_release(*args, **kwargs)  # type: ignore[arg-type]
        raise KeyboardInterrupt("malformed-token cleanup after mutation")

    monkeypatch.setattr(
        registry,
        "_release_action_cohort_reservation_locked",
        fail_before_release if cleanup_fault == "before" else release_then_fail,
    )

    with pytest.raises(StateError, match="integrity check failed") as captured:
        with registry.claimed_action_cohort(token):
            pytest.fail("malformed token must fail before yield")

    notes = getattr(captured.value, "__notes__", ())
    assert any("KeyboardInterrupt" in note for note in notes)
    _assert_no_transient_claim_state(registry)


def test_exhausted_claim_cleanup_is_exactly_retryable_after_all_attempts_fault(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    registry = LifecycleRegistry()
    request = LifecycleActionCohortRequest(
        state_publication_token="opaque-retry-cleanup-state-plan",
        operations=(_session_start(suffix="retry-cleanup"),),
    )
    token = registry.prepare_action_cohort(request)
    primary = RuntimeError("retryable cleanup body primary")

    def fail_release(*_args: object, **_kwargs: object) -> bool:
        raise KeyboardInterrupt("retryable cleanup fault")

    with monkeypatch.context() as faults:
        faults.setattr(
            registry,
            "_release_action_cohort_reservation_locked",
            fail_release,
        )
        faults.setattr(
            registry,
            "_release_action_cohort_reservation_state_locked",
            fail_release,
        )
        with pytest.raises(RuntimeError) as captured:
            with registry.claimed_action_cohort(token) as prepared:
                expected = prepared.expected_receipt
                raise primary

    assert captured.value is primary
    assert len(getattr(captured.value, "__notes__", ())) == 3
    census = registry.action_cohort_preparation_census()
    assert census.reservations == 1
    assert census.claimed_reservations == 1
    assert census.claimed_capability_locators == 1
    assert census.expected_receipt_authorities == 1
    assert not registry.authenticates_expected_action_cohort_receipt(expected)

    object.__setattr__(prepared, "_active", True)
    with pytest.raises(StateError, match="exact registered prepared capability"):
        prepared.commit_no_fail()

    registry.retry_claimed_action_cohort_cleanup(prepared)
    _assert_no_transient_claim_state(registry)


def test_composite_certification_rejects_exact_tampered_receipt_without_mutation() -> None:
    request = LifecycleActionCohortRequest(
        state_publication_token="opaque-certified-tamper-state-plan",
        operations=(_session_start(suffix="certified-tamper"),),
    )
    registry = LifecycleRegistry()
    token = registry.prepare_action_cohort(request)

    with pytest.raises(StateError, match="failed authentication"):
        with registry.claimed_action_cohort(token) as prepared:
            expected = prepared.expected_receipt
            object.__setattr__(expected, "_integrity", "0" * 64)
            prepared.certify_composite_commit(expected)

    assert registry.get_session("certified-tamper-session") is None
    assert registry.action_cohort_preparation_census().reservations == 0


def test_certified_tail_never_traverses_caller_exposed_receipt_values() -> None:
    request = LifecycleActionCohortRequest(
        state_publication_token="opaque-certified-isolation-state-plan",
        operations=(_session_start(suffix="certified-isolation"),),
    )
    registry = LifecycleRegistry()
    token = registry.prepare_action_cohort(request)

    with registry.claimed_action_cohort(token) as prepared:
        expected = prepared.expected_receipt
        prepared.certify_composite_commit(expected)
        exposed_start = expected.request.operations[0]
        assert type(exposed_start) is LifecycleSessionStartRequest
        object.__setattr__(exposed_start.identity, "hostname", "CALLER-TAMPERED")
        assert registry.authenticates_expected_action_cohort_receipt(expected)
        assert not registry.authenticates_action_cohort_receipt(expected)

        assert prepared.commit_no_fail() is expected

    committed = registry.get_session("certified-isolation-session")
    assert committed is not None
    assert committed.identity.hostname == "LINUX-EXPECTED-01"
    assert registry.authenticates_action_cohort_receipt(expected, request=request)

    retry_token = registry.prepare_action_cohort(request)
    with registry.claimed_action_cohort(retry_token) as prepared:
        retry_expected = prepared.expected_receipt
        assert registry.authenticates_expected_action_cohort_receipt(
            retry_expected,
        )
        assert prepared.commit_no_fail() is retry_expected


def test_standalone_commit_retains_full_receipt_authentication(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    request = LifecycleActionCohortRequest(
        state_publication_token="opaque-standalone-auth-state-plan",
        operations=(_session_start(suffix="standalone-auth"),),
    )
    registry = LifecycleRegistry()
    token = registry.prepare_action_cohort(request)

    with pytest.raises(StateError, match="failed authentication"):
        with registry.claimed_action_cohort(token) as prepared:
            monkeypatch.setattr(
                registry,
                "authenticates_expected_action_cohort_receipt",
                lambda *_args, **_kwargs: False,
            )
            prepared.commit_no_fail()

    assert registry.get_session("standalone-auth-session") is None
    assert registry.action_cohort_preparation_census().reservations == 0


def test_retry_gets_fresh_claim_local_receipt_without_exposing_private_provenance() -> None:
    registry = LifecycleRegistry(shard_count=4)
    request = _closed_request()
    first_token = registry.prepare_action_cohort(request)
    with registry.claimed_action_cohort(first_token) as prepared:
        first_expected = prepared.expected_receipt
        first_receipt = prepared.commit_no_fail()

    first_session = first_receipt.operation_results[0]
    object.__setattr__(first_session.identity, "hostname", "TAMPERED-HOST")
    assert not registry.authenticates_action_cohort_receipt(first_receipt)

    retry_token = registry.prepare_action_cohort(request)
    with registry.claimed_action_cohort(retry_token) as prepared:
        retry_expected = prepared.expected_receipt
        assert retry_expected is not first_expected
        assert registry.authenticates_expected_action_cohort_receipt(
            retry_expected,
        )
        retry_receipt = prepared.commit_no_fail()
        assert retry_receipt is retry_expected
        assert prepared.receipt is retry_expected

    second_retry_token = registry.prepare_action_cohort(request)
    with registry.claimed_action_cohort(second_retry_token) as prepared:
        second_retry_expected = prepared.expected_receipt
        assert second_retry_expected == retry_receipt
        assert second_retry_expected is not retry_receipt
        assert prepared.commit_no_fail() is second_retry_expected


def test_foreign_tamper_stale_wrong_thread_and_partial_retry_are_neutral() -> None:
    request = LifecycleActionCohortRequest(
        state_publication_token="opaque-neutral-state-plan",
        operations=(_session_start(suffix="neutral"),),
    )

    source = LifecycleRegistry()
    foreign = LifecycleRegistry()
    foreign_token = source.prepare_action_cohort(request)
    with pytest.raises(StateError, match="stale|registry"):
        with foreign.claimed_action_cohort(foreign_token):
            pytest.fail("foreign registry must reject before yielding")
    assert foreign.get_session("neutral-session") is None
    source.cancel_action_cohort(foreign_token)

    tampered = LifecycleRegistry()
    tampered_token = tampered.prepare_action_cohort(request)
    object.__setattr__(tampered_token, "plan_digest", "0" * 64)
    with pytest.raises(StateError, match="mutated|integrity"):
        with tampered.claimed_action_cohort(tampered_token):
            pytest.fail("tampered token must reject before yielding")
    assert tampered.get_session("neutral-session") is None
    assert tampered.action_cohort_preparation_census().reservations == 0

    stale = LifecycleRegistry()
    stale_token = stale.prepare_action_cohort(request)
    stale.advance_watermark(_START - timedelta(microseconds=1))
    with pytest.raises(StateError, match="stale"):
        with stale.claimed_action_cohort(stale_token):
            pytest.fail("stale token must reject before yielding")
    assert stale.get_session("neutral-session") is None
    assert stale.action_cohort_preparation_census().reservations == 0

    wrong_thread = LifecycleRegistry()
    thread_token = wrong_thread.prepare_action_cohort(request)
    failures: list[BaseException] = []
    with pytest.raises(StateError, match="without commit_no_fail"):
        with wrong_thread.claimed_action_cohort(thread_token) as prepared:
            assert wrong_thread.authenticates_expected_action_cohort_receipt(
                prepared.expected_receipt,
            )
            worker = Thread(
                target=lambda: _capture_failure(prepared.commit_no_fail, failures),
                daemon=True,
            )
            worker.start()
            worker.join(timeout=2)
            assert not worker.is_alive()
    assert len(failures) == 1
    assert isinstance(failures[0], StateError)
    assert "claiming thread" in str(failures[0])
    assert wrong_thread.get_session("neutral-session") is None
    assert wrong_thread.action_cohort_preparation_census().reservations == 0

    tampered_receipt = LifecycleRegistry()
    receipt_token = tampered_receipt.prepare_action_cohort(request)
    with pytest.raises(StateError, match="expected receipt changed"):
        with tampered_receipt.claimed_action_cohort(receipt_token) as prepared:
            prepared._expected_receipt = replace(
                prepared.expected_receipt,
                committed_digest="0" * 64,
            )
            prepared.commit_no_fail()
    assert tampered_receipt.get_session("neutral-session") is None
    assert tampered_receipt.action_cohort_preparation_census().reservations == 0

    partial = LifecycleRegistry()
    session = _session_start(suffix="partial")
    partial.register_session(
        session.identity,
        action_id=session.action_id,
        transition_id=session.transition_id,
    )
    prior = partial.get_session(session.identity.object_id)
    partial_request = LifecycleActionCohortRequest(
        state_publication_token="opaque-partial-state-plan",
        operations=(
            session,
            LifecycleTransition(
                transition_id="partial-session-dependent",
                subject=session.identity.ref,
                kind="dependent",
                canonical_time=_START + timedelta(seconds=1),
                action_id="partial-session-dependent-action",
            ),
        ),
    )
    with pytest.raises(StateError, match="Partial lifecycle action-cohort retry"):
        partial.prepare_action_cohort(partial_request)
    assert partial.get_session(session.identity.object_id) == prior
    assert partial.transition("partial-session-dependent") is None
    assert partial.action_cohort_preparation_census().reservations == 0
