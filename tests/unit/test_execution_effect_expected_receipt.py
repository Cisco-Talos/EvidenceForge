# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Adversarial expected-receipt coverage for prepared effect-audit cohorts."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from copy import copy

import pytest

from evidenceforge.generation.actions.base import ActionAnchor
from evidenceforge.generation.actions.command_effects import (
    ExecutionEffectAuditCohortEntry,
    ExecutionEffectAuditCounter,
    ExecutionEffectPlan,
    ExecutionEffectPlanError,
)

_ROOT_ACTION_ID = "expected-receipt-audit-root"


def _preparation(
    counter: ExecutionEffectAuditCounter,
    stable_id: str = "expected-receipt",
) -> tuple[object, ExecutionEffectAuditCohortEntry]:
    plan = ExecutionEffectPlan(
        ActionAnchor(
            family="process_execution",
            stable_id=stable_id,
            source="unit_test",
        )
    )
    entry = ExecutionEffectAuditCohortEntry(plan, plan.reconcile(()))
    return counter.prepare_action_cohort(_ROOT_ACTION_ID, (entry,)), entry


def _assert_empty(counter: ExecutionEffectAuditCounter) -> None:
    census = counter.action_cohort_preparation_census()
    assert (
        census.prepared,
        census.claimed,
        census.prepared_commit_plans,
        census.mutation_fences,
        census.retained_members,
        census.retained_bytes,
    ) == (0, 0, 0, 0, 0, 0)


def test_expected_receipt_authenticates_before_commit_and_is_returned_by_identity() -> None:
    counter = ExecutionEffectAuditCounter()
    preparation, entry = _preparation(counter)

    with pytest.raises(ExecutionEffectPlanError, match="no active expected receipt"):
        _ = preparation.expected_receipt  # type: ignore[attr-defined]

    with counter.claimed_action_cohort(preparation) as claimed:
        expected = claimed.expected_receipt
        assert claimed.receipt is None
        assert counter.authenticates_expected_action_cohort_receipt(
            expected,
            preparation=claimed,
            root_action_id=_ROOT_ACTION_ID,
            entries=(entry,),
            owned_plans=(),
            published_provenances=(),
        )
        assert not counter.authenticates_action_cohort_receipt(
            expected,
            preparation=claimed,
        )
        assert not counter.authenticates_expected_action_cohort_receipt(
            copy(expected),
            preparation=claimed,
        )
        assert not ExecutionEffectAuditCounter().authenticates_expected_action_cohort_receipt(
            expected,
            preparation=claimed,
        )
        with pytest.raises(ExecutionEffectPlanError, match="exact expected receipt"):
            claimed.certify_composite_commit(copy(expected))
        claimed.certify_composite_commit(expected)
        with pytest.raises(ExecutionEffectPlanError, match="already composite-certified"):
            claimed.certify_composite_commit(expected)

        receipt = claimed.commit_no_fail()
        assert receipt is expected
        assert claimed.receipt is expected
        with pytest.raises(ExecutionEffectPlanError, match="no active expected receipt"):
            _ = claimed.expected_receipt

    assert not counter.authenticates_expected_action_cohort_receipt(
        expected,
        preparation=preparation,
    )
    assert counter.authenticates_action_cohort_receipt(
        expected,
        preparation=preparation,
        root_action_id=_ROOT_ACTION_ID,
        entries=(entry,),
    )
    _assert_empty(counter)


def test_expected_receipt_rejects_copied_wrong_thread_and_aborted_capabilities() -> None:
    counter = ExecutionEffectAuditCounter()
    preparation, _entry = _preparation(counter, "claim-identity")
    before = counter.snapshot()

    with pytest.raises(ExecutionEffectPlanError, match="exited without commit_no_fail"):
        with counter.claimed_action_cohort(preparation) as claimed:
            expected = claimed.expected_receipt
            copied = copy(claimed)
            with pytest.raises(ExecutionEffectPlanError, match="no active expected receipt"):
                _ = copied.expected_receipt
            assert not counter.authenticates_expected_action_cohort_receipt(
                expected,
                preparation=copied,
            )
            with ThreadPoolExecutor(max_workers=1) as executor:
                property_error = executor.submit(lambda: claimed.expected_receipt).exception()
                authenticated = executor.submit(
                    counter.authenticates_expected_action_cohort_receipt,
                    expected,
                    preparation=claimed,
                ).result()
            assert isinstance(property_error, ExecutionEffectPlanError)
            assert not authenticated

    assert counter.snapshot() == before
    _assert_empty(counter)
    with pytest.raises(ExecutionEffectPlanError, match="no active expected receipt"):
        _ = preparation.expected_receipt  # type: ignore[attr-defined]


def test_claim_fence_prevents_stale_replacement_and_census_cleans_exactly() -> None:
    counter = ExecutionEffectAuditCounter()
    first, first_entry = _preparation(counter, "fenced-first")
    second, second_entry = _preparation(counter, "fenced-second")

    with counter.claimed_action_cohort(first) as claimed:
        census = counter.action_cohort_preparation_census()
        assert (census.prepared, census.claimed) == (1, 1)
        assert (census.prepared_commit_plans, census.mutation_fences) == (1, 1)
        with pytest.raises(ExecutionEffectPlanError, match="temporarily fences mutation"):
            counter.record(first_entry.reconciliation)
        with pytest.raises(ExecutionEffectPlanError, match="another.*already claimed"):
            with counter.claimed_action_cohort(second):
                pytest.fail("a second audit claim must not invalidate the prepared replacement")
        expected = claimed.expected_receipt
        assert counter.authenticates_expected_action_cohort_receipt(
            expected,
            preparation=claimed,
            root_action_id=_ROOT_ACTION_ID,
            entries=(first_entry,),
        )
        assert claimed.commit_no_fail() is expected

    with counter.claimed_action_cohort(second) as claimed:
        expected = claimed.expected_receipt
        assert counter.authenticates_expected_action_cohort_receipt(
            expected,
            preparation=claimed,
            root_action_id=_ROOT_ACTION_ID,
            entries=(second_entry,),
        )
        assert claimed.commit_no_fail() is expected

    assert counter.snapshot().plan_count == 2
    census = counter.action_cohort_preparation_census()
    assert (
        census.prepared,
        census.claimed,
        census.prepared_commit_plans,
        census.mutation_fences,
        census.retained_members,
        census.retained_bytes,
    ) == (0, 0, 0, 0, 0, 0)
