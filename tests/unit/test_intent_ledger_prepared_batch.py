# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Focused adversarial tests for prepared intent-execution ledger batches."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from copy import deepcopy
from dataclasses import FrozenInstanceError, replace
from datetime import UTC, datetime, timedelta

import pytest

import evidenceforge.generation.intent_ledger as intent_ledger_module
from evidenceforge.events.contracts import OccurrenceRole, SemanticOccurrenceKey
from evidenceforge.generation.intent_ledger import (
    MAX_INTENT_EXECUTION_BATCH_DELTAS,
    MAX_INTENT_EXECUTION_BATCH_RESERVATIONS,
    MAX_INTENT_EXECUTION_PREPARED_DELTAS,
    MAX_INTENT_EXECUTION_PREPARED_INTENTS,
    AuthoredIntentLedger,
    IntentExecutionBatchConflictError,
    IntentExecutionBatchError,
    IntentExecutionBatchInProgressError,
    IntentExecutionBatchReceipt,
    IntentExecutionBatchRequest,
    IntentExecutionBatchToken,
    IntentExecutionLedger,
    IntentObservationDelta,
    IntentOccurrenceDelta,
)

_TIME = datetime(2026, 8, 17, 12, tzinfo=UTC)


class _LateHashStr(str):
    """String subclass that proves admission never invokes caller behavior."""

    hash_calls: int
    equality_calls: int
    deepcopy_calls: int

    def __new__(cls, value: str) -> _LateHashStr:
        instance = super().__new__(cls, value)
        instance.hash_calls = 0
        instance.equality_calls = 0
        instance.deepcopy_calls = 0
        return instance

    def __hash__(self) -> int:
        self.hash_calls += 1
        raise AssertionError("caller-controlled hash executed")

    def __eq__(self, other: object) -> bool:
        self.equality_calls += 1
        raise AssertionError("caller-controlled equality executed")

    def __deepcopy__(self, memo: dict[int, object]) -> _LateHashStr:
        self.deepcopy_calls += 1
        raise AssertionError("caller-controlled deepcopy executed")


def _ledger() -> IntentExecutionLedger:
    return IntentExecutionLedger(AuthoredIntentLedger("prepared-batch", ()))


def _occurrence(instance_key: str, *, action_id: str = "action-1") -> SemanticOccurrenceKey:
    return SemanticOccurrenceKey(
        action_id=action_id,
        role=OccurrenceRole.DEPENDENT,
        instance_key=instance_key,
    )


def _request(
    intent_id: str = "intent-1",
    *,
    instance_key: str = "occurrence-1",
    timestamp: datetime | None = _TIME,
) -> IntentExecutionBatchRequest:
    return IntentExecutionBatchRequest(
        (
            IntentOccurrenceDelta(intent_id, _occurrence(instance_key), timestamp),
            IntentObservationDelta(intent_id, "windows_security", "visible", timestamp),
        )
    )


def _claim_and_commit(
    ledger: IntentExecutionLedger,
    token: IntentExecutionBatchToken,
) -> IntentExecutionBatchReceipt:
    with ledger.claimed_batch(token) as prepared:
        return prepared.commit_no_fail()


def _assert_empty_batch_census(ledger: IntentExecutionLedger) -> None:
    census = ledger.batch_preparation_census()
    assert (
        census.reservations,
        census.claimed_reservations,
        census.reserved_intents,
        census.capability_locators,
        census.prepared_deltas,
        census.prepared_commit_plans,
        census.mutation_fences,
        census.retained_bytes,
    ) == (0, 0, 0, 0, 0, 0, 0, 0)


def test_prepare_and_cancel_reserve_without_execution_mutation() -> None:
    ledger = _ledger()
    request = _request()
    before_snapshot = ledger.snapshot()
    before_diagnostics = ledger.diagnostics()

    token = ledger.prepare_batch(request)

    assert ledger.authenticates_batch_token(token, request=request)
    assert ledger.snapshot() == before_snapshot
    assert ledger.diagnostics() == before_diagnostics
    assert ledger.batch_preparation_census().reservations == 1
    assert ledger.batch_preparation_census().reserved_intents == 1
    assert ledger.batch_preparation_census().prepared_deltas == 2
    assert ledger.batch_preparation_census().retained_bytes > 0
    assert (
        ledger.batch_preparation_census().reservation_capacity
        == MAX_INTENT_EXECUTION_BATCH_RESERVATIONS
    )
    assert (
        ledger.batch_preparation_census().prepared_intent_capacity
        == MAX_INTENT_EXECUTION_PREPARED_INTENTS
    )
    assert (
        ledger.batch_preparation_census().prepared_delta_capacity
        == MAX_INTENT_EXECUTION_PREPARED_DELTAS
    )

    ledger.cancel_batch(token)

    assert ledger.snapshot() == before_snapshot
    assert ledger.diagnostics() == before_diagnostics
    _assert_empty_batch_census(ledger)
    assert not ledger.authenticates_batch_token(token)


def test_commit_publishes_ordered_occurrences_and_observation_multiset_once() -> None:
    ledger = _ledger()
    request = IntentExecutionBatchRequest(
        (
            IntentOccurrenceDelta("intent-1", _occurrence("first"), _TIME),
            IntentObservationDelta("intent-1", "ecar", "visible"),
            IntentObservationDelta("intent-1", "ecar", "visible"),
            IntentOccurrenceDelta(
                "intent-1",
                _occurrence("second"),
                _TIME + timedelta(seconds=1),
            ),
        )
    )
    token = ledger.prepare_batch(request)

    with ledger.claimed_batch(token) as prepared:
        receipt = prepared.commit_no_fail()
        assert prepared.committed
        assert prepared.receipt is receipt
        with pytest.raises(IntentExecutionBatchError, match="already committed"):
            prepared.commit_no_fail()

    snapshot = ledger.snapshot()[0]
    assert snapshot.intent_id == "intent-1"
    assert snapshot.occurrence_reference_count == 2
    assert snapshot.source_status == {"ecar": {"visible": 2}}
    assert receipt.result.delta_count == 4
    assert receipt.result.occurrence_count == 2
    assert receipt.result.observation_count == 2
    assert receipt.preparation_id == token.preparation_id
    assert receipt.result.preparation_id == token.preparation_id
    assert receipt.expected_watermark is None
    assert receipt.result.expected_watermark is None
    assert receipt.result.prior_watermark is None
    assert receipt.result.committed_watermark == _TIME + timedelta(seconds=1)
    assert receipt.prior_watermark is None
    assert receipt.committed_watermark == _TIME + timedelta(seconds=1)
    assert receipt.result.watermark == _TIME + timedelta(seconds=1)
    assert ledger.authenticates_batch_receipt(receipt, request=request)
    assert ledger.batch_preparation_census().reservations == 0
    assert not ledger.authenticates_batch_token(token)
    with pytest.raises(FrozenInstanceError):
        receipt.result.delta_count = 99
    with pytest.raises(IntentExecutionBatchError, match="stale or consumed"):
        with ledger.claimed_batch(token):
            pytest.fail("a consumed token must not replay")


def test_claim_exit_without_commit_releases_everything_and_mutates_nothing() -> None:
    ledger = _ledger()
    token = ledger.prepare_batch(_request())
    before_snapshot = ledger.snapshot()
    before_diagnostics = ledger.diagnostics()

    with pytest.raises(IntentExecutionBatchError, match="exited without commit_no_fail"):
        with ledger.claimed_batch(token) as prepared:
            census = ledger.batch_preparation_census()
            assert census.claimed_reservations == 1
            assert census.prepared_commit_plans == 1
            assert census.mutation_fences == 1
            assert census.retained_bytes > 0

    assert ledger.snapshot() == before_snapshot
    assert ledger.diagnostics() == before_diagnostics
    _assert_empty_batch_census(ledger)
    with pytest.raises(IntentExecutionBatchError, match="no longer active"):
        prepared.commit_no_fail()

    ledger.advance_watermark(_TIME)
    ledger.record_occurrence("post-cancel", _occurrence("post-cancel"), _TIME)
    ledger.record_observation("post-cancel", "ecar", "visible", _TIME)
    post_cancel = ledger.snapshot()[0]
    assert post_cancel.occurrence_reference_count == 1
    assert post_cancel.source_status == {"ecar": {"visible": 1}}


def test_batch_validation_is_bounded_and_stricter_for_occurrence_identity() -> None:
    occurrence = IntentOccurrenceDelta("intent-1", _occurrence("duplicate"))
    with pytest.raises(ValueError, match="cannot be empty"):
        IntentExecutionBatchRequest(())
    with pytest.raises(ValueError, match="immutable tuple"):
        IntentExecutionBatchRequest([occurrence])  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="repeats exact occurrence identity"):
        IntentExecutionBatchRequest((occurrence, occurrence))
    with pytest.raises(ValueError, match="non-empty intent_id"):
        IntentObservationDelta(" ", "ecar", "visible")

    repeated_observation = IntentObservationDelta("intent-1", "ecar", "visible")
    request = IntentExecutionBatchRequest((repeated_observation, repeated_observation))
    assert len(request.deltas) == 2

    oversized = (repeated_observation,) * (MAX_INTENT_EXECUTION_BATCH_DELTAS + 1)
    with pytest.raises(ValueError, match="Split the action cohort"):
        IntentExecutionBatchRequest(oversized)


def test_prepare_rejects_nonprimitive_strings_before_copy_or_hash() -> None:
    mutation_cases: list[tuple[IntentExecutionBatchRequest, object, str]] = []
    observation_fields = ("intent_id", "source", "status")
    for field_name in observation_fields:
        delta = IntentObservationDelta("intent-1", "ecar", "visible")
        mutation_cases.append((IntentExecutionBatchRequest((delta,)), delta, field_name))
    for field_name in ("action_id", "instance_key"):
        occurrence_key = _occurrence(f"safe-{field_name}")
        delta = IntentOccurrenceDelta("intent-1", occurrence_key)
        mutation_cases.append((IntentExecutionBatchRequest((delta,)), occurrence_key, field_name))

    for index, (request, target, field_name) in enumerate(mutation_cases):
        ledger = _ledger()
        dangerous = _LateHashStr(f"dangerous-{index}")
        object.__setattr__(target, field_name, dangerous)
        with pytest.raises(ValueError, match="exact str"):
            ledger.prepare_batch(request)
        assert (
            dangerous.hash_calls,
            dangerous.equality_calls,
            dangerous.deepcopy_calls,
        ) == (0, 0, 0)
        _assert_empty_batch_census(ledger)

    role_ledger = _ledger()
    role_key = _occurrence("safe-role")
    role_request = IntentExecutionBatchRequest((IntentOccurrenceDelta("intent-1", role_key),))
    dangerous_role = _LateHashStr("dependent")
    object.__setattr__(role_key, "role", dangerous_role)
    with pytest.raises(ValueError, match="exact OccurrenceRole"):
        role_ledger.prepare_batch(role_request)
    assert (
        dangerous_role.hash_calls,
        dangerous_role.equality_calls,
        dangerous_role.deepcopy_calls,
    ) == (0, 0, 0)
    _assert_empty_batch_census(role_ledger)

    ledger = _ledger()
    caller_request = _request(timestamp=None)
    token = ledger.prepare_batch(caller_request)
    late_caller_value = _LateHashStr("mutated-after-prepare")
    object.__setattr__(caller_request.deltas[0].occurrence_key, "action_id", late_caller_value)
    with ledger.claimed_batch(token) as prepared:
        prepared.commit_no_fail()
    assert (
        late_caller_value.hash_calls,
        late_caller_value.equality_calls,
        late_caller_value.deepcopy_calls,
    ) == (0, 0, 0)


def test_batch_capacity_is_named_actionable_and_fully_released(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(intent_ledger_module, "MAX_INTENT_EXECUTION_BATCH_RESERVATIONS", 2)
    monkeypatch.setattr(intent_ledger_module, "MAX_INTENT_EXECUTION_PREPARED_INTENTS", 8)
    monkeypatch.setattr(intent_ledger_module, "MAX_INTENT_EXECUTION_PREPARED_DELTAS", 8)
    reservation_ledger = _ledger()
    first = reservation_ledger.prepare_batch(
        IntentExecutionBatchRequest((IntentObservationDelta("intent-1", "ecar", "visible"),))
    )
    second = reservation_ledger.prepare_batch(
        IntentExecutionBatchRequest((IntentObservationDelta("intent-2", "ecar", "visible"),))
    )
    assert reservation_ledger.batch_preparation_census().reservation_capacity == 2
    with pytest.raises(IntentExecutionBatchError, match="reservation capacity.*Cancel or commit"):
        reservation_ledger.prepare_batch(
            IntentExecutionBatchRequest((IntentObservationDelta("intent-3", "ecar", "visible"),))
        )
    reservation_ledger.cancel_batch(first)
    third = reservation_ledger.prepare_batch(
        IntentExecutionBatchRequest((IntentObservationDelta("intent-3", "ecar", "visible"),))
    )
    reservation_ledger.cancel_batch(second)
    reservation_ledger.cancel_batch(third)
    _assert_empty_batch_census(reservation_ledger)

    monkeypatch.setattr(intent_ledger_module, "MAX_INTENT_EXECUTION_BATCH_RESERVATIONS", 8)
    monkeypatch.setattr(intent_ledger_module, "MAX_INTENT_EXECUTION_PREPARED_INTENTS", 2)
    intent_ledger = _ledger()
    intents = intent_ledger.prepare_batch(
        IntentExecutionBatchRequest(
            (
                IntentObservationDelta("intent-1", "ecar", "visible"),
                IntentObservationDelta("intent-2", "ecar", "visible"),
            )
        )
    )
    with pytest.raises(IntentExecutionBatchError, match="Prepared intent capacity"):
        intent_ledger.prepare_batch(
            IntentExecutionBatchRequest((IntentObservationDelta("intent-3", "ecar", "visible"),))
        )
    intent_ledger.cancel_batch(intents)
    _assert_empty_batch_census(intent_ledger)

    monkeypatch.setattr(intent_ledger_module, "MAX_INTENT_EXECUTION_PREPARED_INTENTS", 8)
    monkeypatch.setattr(intent_ledger_module, "MAX_INTENT_EXECUTION_PREPARED_DELTAS", 2)
    delta_ledger = _ledger()
    repeated = IntentObservationDelta("intent-1", "ecar", "visible")
    deltas = delta_ledger.prepare_batch(IntentExecutionBatchRequest((repeated, repeated)))
    assert delta_ledger.batch_preparation_census().prepared_deltas == 2
    with pytest.raises(IntentExecutionBatchError, match="Prepared intent delta capacity"):
        delta_ledger.prepare_batch(
            IntentExecutionBatchRequest((IntentObservationDelta("intent-2", "ecar", "visible"),))
        )
    delta_ledger.cancel_batch(deltas)
    _assert_empty_batch_census(delta_ledger)


def test_intent_reservations_reject_overlap_but_allow_disjoint_progress() -> None:
    ledger = _ledger()
    request = _request(timestamp=None)
    token = ledger.prepare_batch(request)

    with pytest.raises(IntentExecutionBatchInProgressError, match="already in progress"):
        ledger.prepare_batch(request)
    with pytest.raises(IntentExecutionBatchConflictError, match="already reserved"):
        ledger.prepare_batch(_request(instance_key="other", timestamp=None))
    with pytest.raises(IntentExecutionBatchConflictError, match="prepared execution batch"):
        ledger.record_observation("intent-1", "ecar", "visible")
    with pytest.raises(IntentExecutionBatchConflictError, match="prepared execution batch"):
        ledger.mark_planned("intent-1")

    disjoint = IntentExecutionBatchRequest((IntentObservationDelta("intent-2", "ecar", "visible"),))
    disjoint_token = ledger.prepare_batch(disjoint)
    with ledger.claimed_batch(disjoint_token) as prepared:
        prepared.commit_no_fail()

    ledger.cancel_batch(token)
    ledger.mark_planned("intent-1")
    snapshots = {snapshot.intent_id: snapshot for snapshot in ledger.snapshot()}
    assert snapshots["intent-1"].planned
    assert snapshots["intent-2"].source_status == {"ecar": {"visible": 1}}
    _assert_empty_batch_census(ledger)


def test_claim_retains_no_lock_and_fences_all_execution_mutation() -> None:
    ledger = _ledger()
    token = ledger.prepare_batch(_request(timestamp=None))
    disjoint_token = ledger.prepare_batch(
        IntentExecutionBatchRequest((IntentObservationDelta("intent-2", "ecar", "visible"),))
    )

    with ledger.claimed_batch(token) as prepared:
        with ThreadPoolExecutor(max_workers=8) as executor:
            snapshot_future = executor.submit(ledger.snapshot)
            prepare_future = executor.submit(
                ledger.prepare_batch,
                _request("intent-3", instance_key="prepared-during-claim", timestamp=None),
            )
            watermark_future = executor.submit(ledger.advance_watermark, _TIME)
            occurrence_future = executor.submit(
                ledger.record_occurrence,
                "direct-intent",
                _occurrence("blocked-during-claim"),
                _TIME,
            )
            observation_future = executor.submit(
                ledger.record_observation,
                "direct-intent",
                "ecar",
                "visible",
            )
            planned_future = executor.submit(ledger.mark_planned, "direct-intent")
            second_claim_future = executor.submit(_claim_and_commit, ledger, disjoint_token)
            wrong_thread_future = executor.submit(prepared.commit_no_fail)

            assert snapshot_future.result(timeout=3) == ()
            prepared_during_claim = prepare_future.result(timeout=3)
            for mutation_future in (
                watermark_future,
                occurrence_future,
                observation_future,
                planned_future,
            ):
                with pytest.raises(
                    IntentExecutionBatchInProgressError,
                    match="temporarily fences ledger mutation",
                ):
                    mutation_future.result(timeout=3)
            with pytest.raises(
                IntentExecutionBatchInProgressError,
                match="already claimed",
            ):
                second_claim_future.result(timeout=3)
            with pytest.raises(IntentExecutionBatchError, match="claiming thread"):
                wrong_thread_future.result(timeout=3)

        ledger.cancel_batch(prepared_during_claim)
        receipt = prepared.commit_no_fail()

    assert ledger.authenticates_batch_receipt(receipt)
    disjoint_receipt = _claim_and_commit(ledger, disjoint_token)
    assert ledger.authenticates_batch_receipt(disjoint_receipt)

    ledger.advance_watermark(_TIME + timedelta(seconds=2))
    ledger.record_occurrence(
        "direct-intent",
        _occurrence("allowed-after-commit"),
        _TIME + timedelta(seconds=2),
    )
    ledger.record_observation(
        "direct-intent",
        "ecar",
        "visible",
        _TIME + timedelta(seconds=2),
    )
    ledger.mark_planned("direct-intent")
    assert {snapshot.intent_id for snapshot in ledger.snapshot()} == {
        "direct-intent",
        "intent-1",
        "intent-2",
    }
    assert ledger.batch_preparation_census().reservations == 0
    direct_snapshot = next(
        snapshot for snapshot in ledger.snapshot() if snapshot.intent_id == "direct-intent"
    )
    assert direct_snapshot.planned


def test_foreign_copied_stale_and_double_claim_tokens_reject() -> None:
    ledger = _ledger()
    foreign = _ledger()
    token = ledger.prepare_batch(_request(timestamp=None))
    copied = deepcopy(token)

    assert not foreign.authenticates_batch_token(token)
    assert not ledger.authenticates_batch_token(copied)
    with pytest.raises(IntentExecutionBatchError, match="another ledger"):
        with foreign.claimed_batch(token):
            pytest.fail("foreign token must not claim")
    with pytest.raises(IntentExecutionBatchError, match="stale or consumed"):
        with ledger.claimed_batch(copied):
            pytest.fail("copied token must not claim")

    with ledger.claimed_batch(token) as prepared:
        with pytest.raises(IntentExecutionBatchError, match="already claimed"):
            with ledger.claimed_batch(token):
                pytest.fail("a token must have only one live claim")
        prepared.commit_no_fail()

    unused = ledger.prepare_batch(_request(instance_key="unused", timestamp=None))
    ledger.cancel_batch(unused)
    assert ledger.batch_preparation_census().reservations == 0

    stale = ledger.prepare_batch(_request(instance_key="stale", timestamp=None))
    ledger.advance_watermark(_TIME)
    assert not ledger.authenticates_batch_token(stale)
    _assert_empty_batch_census(ledger)
    with pytest.raises(IntentExecutionBatchError, match="stale or consumed"):
        with ledger.claimed_batch(stale):
            pytest.fail("watermark-stale token must not claim")


def test_receipt_authenticator_requires_exact_owner_issued_identity() -> None:
    ledger = _ledger()
    request = _request()
    token = ledger.prepare_batch(request)
    with ledger.claimed_batch(token) as prepared:
        receipt = prepared.commit_no_fail()

    reordered = IntentExecutionBatchRequest(tuple(reversed(request.deltas)))
    forged_result = replace(receipt.result, observation_count=99)
    assert ledger.authenticates_batch_receipt(receipt)
    assert not ledger.authenticates_batch_receipt(deepcopy(receipt))
    assert not ledger.authenticates_batch_receipt(None)
    assert not ledger.authenticates_batch_receipt(receipt, request=reordered)
    assert not ledger.authenticates_batch_receipt(replace(receipt, result=forged_result))
    assert not ledger.authenticates_batch_receipt(replace(receipt, _integrity="forged"))
    assert not _ledger().authenticates_batch_receipt(receipt)


def test_identical_sequential_batches_have_non_substitutable_receipts() -> None:
    ledger = _ledger()
    request = IntentExecutionBatchRequest(
        (IntentObservationDelta("intent-1", "ecar", "visible", _TIME),)
    )
    first_token = ledger.prepare_batch(request)
    first = _claim_and_commit(ledger, first_token)
    second_token = ledger.prepare_batch(request)
    second = _claim_and_commit(ledger, second_token)

    assert first.request == second.request
    assert first.preparation_id != second.preparation_id
    assert first.result.preparation_id == first.preparation_id
    assert second.result.preparation_id == second.preparation_id
    assert first.expected_watermark is None
    assert first.result.expected_watermark is None
    assert first.result.prior_watermark is None
    assert first.result.committed_watermark == _TIME
    assert second.expected_watermark == _TIME
    assert second.result.expected_watermark == _TIME
    assert second.result.prior_watermark == _TIME
    assert second.result.committed_watermark == _TIME
    assert first.committed_digest != second.committed_digest
    assert first.publication_token != second.publication_token
    assert ledger.authenticates_batch_receipt(first, request=request)
    assert ledger.authenticates_batch_receipt(second, request=request)

    substituted_result = replace(
        second.result,
        preparation_id=first.preparation_id,
    )
    assert not ledger.authenticates_batch_receipt(
        replace(
            second,
            preparation_id=first.preparation_id,
            result=substituted_result,
        )
    )
    assert not ledger.authenticates_batch_receipt(
        replace(second, expected_watermark=first.expected_watermark)
    )
    assert not ledger.authenticates_batch_receipt(
        replace(second, result=replace(second.result, prior_watermark=None))
    )
    assert not ledger.authenticates_batch_receipt(
        replace(
            second,
            result=replace(
                second.result,
                committed_watermark=_TIME + timedelta(microseconds=1),
            ),
        )
    )


def test_pre_epoch_first_timestamp_receipt_matches_legacy_ledger_frontier() -> None:
    ledger = _ledger()
    pre_epoch = datetime(1960, 1, 2, 3, 4, 5, 678901, tzinfo=UTC)
    request = IntentExecutionBatchRequest(
        (IntentOccurrenceDelta("intent-1960", _occurrence("pre-epoch"), pre_epoch),)
    )

    receipt = _claim_and_commit(ledger, ledger.prepare_batch(request))

    assert receipt.expected_watermark is None
    assert receipt.result.expected_watermark is None
    assert receipt.result.prior_watermark is None
    assert receipt.result.committed_watermark == pre_epoch
    assert receipt.result.watermark == pre_epoch
    assert ledger.diagnostics().watermark == pre_epoch
    assert ledger.authenticates_batch_receipt(receipt, request=request)


def test_prepared_occurrence_duplicate_rejects_while_direct_api_keeps_audit_defect() -> None:
    ledger = _ledger()
    occurrence = _occurrence("legacy-duplicate")
    ledger.record_occurrence("intent-1", occurrence, _TIME)
    ledger.record_occurrence("intent-1", occurrence, _TIME + timedelta(seconds=1))

    snapshot = ledger.snapshot()[0]
    assert snapshot.occurrence_reference_count == 2
    assert snapshot.duplicate_occurrence_count == 1

    with pytest.raises(IntentExecutionBatchConflictError, match="exact hot cache"):
        ledger.prepare_batch(
            IntentExecutionBatchRequest((IntentOccurrenceDelta("intent-1", occurrence, _TIME),))
        )
