# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Adversarial expected-receipt coverage for prepared intent batches."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from copy import copy, deepcopy
from datetime import UTC, datetime, timedelta

import pytest

from evidenceforge.events.contracts import OccurrenceRole, SemanticOccurrenceKey
from evidenceforge.generation.intent_ledger import (
    AuthoredIntentLedger,
    IntentExecutionBatchError,
    IntentExecutionBatchRequest,
    IntentExecutionLedger,
    IntentObservationDelta,
    IntentOccurrenceDelta,
)

_TIME = datetime(2026, 8, 17, 16, tzinfo=UTC)


def _ledger() -> IntentExecutionLedger:
    return IntentExecutionLedger(AuthoredIntentLedger("expected-receipt", ()))


def _request(instance_key: str = "expected-receipt") -> IntentExecutionBatchRequest:
    return IntentExecutionBatchRequest(
        (
            IntentOccurrenceDelta(
                "intent-1",
                SemanticOccurrenceKey(
                    action_id="action-1",
                    role=OccurrenceRole.DEPENDENT,
                    instance_key=instance_key,
                ),
                _TIME,
            ),
            IntentObservationDelta("intent-1", "ecar", "visible", _TIME),
        )
    )


def _assert_empty(ledger: IntentExecutionLedger) -> None:
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


def test_expected_receipt_authenticates_before_commit_and_is_returned_by_identity() -> None:
    ledger = _ledger()
    request = _request()
    token = ledger.prepare_batch(request)

    with ledger.claimed_batch(token) as claimed:
        expected = claimed.expected_receipt
        assert claimed.receipt is None
        assert not ledger.authenticates_batch_receipt(expected, request=request)
        assert ledger.authenticates_expected_batch_receipt(
            expected,
            preparation=claimed,
            request=request,
        )
        copied_receipt = deepcopy(expected)
        assert not ledger.authenticates_batch_receipt(copied_receipt, request=request)
        assert not ledger.authenticates_expected_batch_receipt(
            copied_receipt,
            preparation=claimed,
            request=request,
        )
        assert not _ledger().authenticates_expected_batch_receipt(
            expected,
            preparation=claimed,
            request=request,
        )
        with pytest.raises(IntentExecutionBatchError, match="exact expected receipt"):
            claimed.certify_composite_commit(copied_receipt)
        claimed.certify_composite_commit(expected)
        with pytest.raises(IntentExecutionBatchError, match="already composite-certified"):
            claimed.certify_composite_commit(expected)

        receipt = claimed.commit_no_fail()
        assert receipt is expected
        assert claimed.receipt is expected
        with pytest.raises(IntentExecutionBatchError, match="no active expected receipt"):
            _ = claimed.expected_receipt
        with pytest.raises(IntentExecutionBatchError, match="already committed"):
            claimed.commit_no_fail()

    assert not ledger.authenticates_expected_batch_receipt(
        expected,
        preparation=claimed,
        request=request,
    )
    assert ledger.authenticates_batch_receipt(expected, request=request)
    assert not ledger.authenticates_batch_receipt(copied_receipt, request=request)
    assert ledger.authenticates_batch_receipt(deepcopy(expected), request=request)
    _assert_empty(ledger)


def test_expected_receipt_rejects_copied_wrong_thread_and_aborted_capabilities() -> None:
    ledger = _ledger()
    token = ledger.prepare_batch(_request("claim-identity"))
    before_snapshot = ledger.snapshot()
    before_diagnostics = ledger.diagnostics()

    with pytest.raises(IntentExecutionBatchError, match="exited without commit_no_fail"):
        with ledger.claimed_batch(token) as claimed:
            expected = claimed.expected_receipt
            copied = copy(claimed)
            with pytest.raises(IntentExecutionBatchError, match="authentic expected receipt"):
                _ = copied.expected_receipt
            assert not ledger.authenticates_expected_batch_receipt(
                expected,
                preparation=copied,
            )
            with ThreadPoolExecutor(max_workers=1) as executor:
                property_error = executor.submit(lambda: claimed.expected_receipt).exception()
                authenticated = executor.submit(
                    ledger.authenticates_expected_batch_receipt,
                    expected,
                    preparation=claimed,
                ).result()
            assert isinstance(property_error, IntentExecutionBatchError)
            assert "claiming thread" in str(property_error)
            assert not authenticated

    assert ledger.snapshot() == before_snapshot
    assert ledger.diagnostics() == before_diagnostics
    _assert_empty(ledger)
    assert not ledger.authenticates_batch_receipt(expected)
    with pytest.raises(IntentExecutionBatchError, match="no active expected receipt"):
        _ = claimed.expected_receipt


def _seed_equivalent_ledger(ledger: IntentExecutionLedger) -> None:
    ledger.record_occurrence(
        "expired-intent",
        SemanticOccurrenceKey("expired-action", OccurrenceRole.DEPENDENT, "expired"),
        _TIME - timedelta(days=31),
    )
    ledger.record_occurrence(
        "recent-intent",
        SemanticOccurrenceKey("recent-action-1", OccurrenceRole.DEPENDENT, "recent-1"),
        _TIME - timedelta(days=1),
    )
    ledger.record_occurrence(
        "recent-intent",
        SemanticOccurrenceKey("recent-action-2", OccurrenceRole.DEPENDENT, "recent-2"),
        _TIME - timedelta(hours=12),
    )
    ledger.record_observation("recent-intent", "ecar", "visible", _TIME - timedelta(hours=12))


def test_precomputed_replay_matches_ordered_legacy_primitives() -> None:
    prepared = IntentExecutionLedger(
        AuthoredIntentLedger("equivalence", ()),
        hot_identity_capacity=4,
    )
    direct = IntentExecutionLedger(
        AuthoredIntentLedger("equivalence", ()),
        hot_identity_capacity=4,
    )
    _seed_equivalent_ledger(prepared)
    _seed_equivalent_ledger(direct)
    request = IntentExecutionBatchRequest(
        (
            IntentOccurrenceDelta(
                "intent-1",
                SemanticOccurrenceKey("action-1", OccurrenceRole.DEPENDENT, "first"),
                _TIME,
            ),
            IntentObservationDelta("intent-1", "windows_security", "visible", None),
            IntentOccurrenceDelta(
                "intent-2",
                SemanticOccurrenceKey("action-2", OccurrenceRole.DEPENDENT, "second"),
                _TIME + timedelta(seconds=1),
            ),
            IntentOccurrenceDelta(
                "old-intent",
                SemanticOccurrenceKey("old-action", OccurrenceRole.DEPENDENT, "old"),
                _TIME - timedelta(days=20),
            ),
        )
    )

    for delta in request.deltas:
        if type(delta) is IntentOccurrenceDelta:
            direct.record_occurrence(delta.intent_id, delta.occurrence_key, delta.timestamp)
        else:
            direct.record_observation(delta.intent_id, delta.source, delta.status, delta.timestamp)

    token = prepared.prepare_batch(request)
    with prepared.claimed_batch(token) as claimed:
        expected = claimed.expected_receipt
        assert prepared.authenticates_expected_batch_receipt(
            expected,
            preparation=claimed,
            request=request,
        )
        assert claimed.commit_no_fail() is expected

    assert prepared.snapshot() == direct.snapshot()
    assert prepared.diagnostics().watermark == direct.diagnostics().watermark
    assert prepared.diagnostics().hot_identity_count == direct.diagnostics().hot_identity_count
    assert prepared.diagnostics().window_bucket_count == direct.diagnostics().window_bucket_count
    assert (
        prepared.diagnostics().source_aggregate_count == direct.diagnostics().source_aggregate_count
    )
    assert prepared._hot_identities == direct._hot_identities
    assert sorted(prepared._hot_identity_heap) == sorted(direct._hot_identity_heap)
    _assert_empty(prepared)
