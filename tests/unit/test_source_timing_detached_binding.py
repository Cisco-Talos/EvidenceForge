# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Tests for exact detached SourceTiming preparation bindings."""

from __future__ import annotations

import copy
import gc
import hashlib
import sys
from dataclasses import replace
from threading import Event, Thread

import pytest

import evidenceforge.generation.source_timing as source_timing_module
from evidenceforge.generation.source_timing import SourceTimingPlanner
from evidenceforge.models.exceptions import StateError


def _digest(label: str) -> str:
    return hashlib.sha256(label.encode("ascii")).hexdigest()


class _CallbackTrap:
    def __init__(self) -> None:
        self.calls = 0

    def _called(self) -> None:
        self.calls += 1
        raise AssertionError("untrusted callback ran")

    def __eq__(self, _other: object) -> bool:
        self._called()

    def __ne__(self, _other: object) -> bool:
        self._called()

    def __hash__(self) -> int:
        self._called()

    def __repr__(self) -> str:
        self._called()

    def __str__(self) -> str:
        self._called()


def test_detached_binding_cross_authenticates_expected_and_committed_receipt() -> None:
    planner = SourceTimingPlanner()
    with planner.prepared_planning() as timing:
        pass
    context = _digest("dispatcher-group-member-capsule")
    binding = planner.detach_preparation_binding(timing, context_digest=context)

    with timing.claimed_commit() as claimed:
        expected = claimed.expected_receipt
        assert planner.authenticates_expected_detached_preparation_binding(
            binding,
            expected,
            context_digest=context,
        )
        assert not planner.authenticates_committed_detached_preparation_binding(
            binding,
            expected,
            context_digest=context,
        )
        receipt = claimed.commit_no_fail()

    assert receipt is expected
    assert not planner.authenticates_expected_detached_preparation_binding(
        binding,
        receipt,
        context_digest=context,
    )
    assert planner.authenticates_committed_detached_preparation_binding(
        binding,
        receipt,
        context_digest=context,
    )


def test_source_timing_planner_copy_and_manual_clone_cannot_own_detached_binding() -> None:
    planner = SourceTimingPlanner()
    with planner.prepared_planning() as timing:
        pass
    context = _digest("exact-owner-copy-gate")
    binding = planner.detach_preparation_binding(timing, context_digest=context)

    with pytest.raises(StateError, match="cannot be copied"):
        copy.copy(planner)
    with pytest.raises(StateError, match="cannot be copied"):
        copy.deepcopy(planner)

    forged = object.__new__(SourceTimingPlanner)
    forged.__dict__ = planner.__dict__.copy()
    assert not forged.authenticates_detached_preparation_binding(
        binding,
        context_digest=context,
    )
    retained = planner._detached_bindings[id(binding)]
    generation = planner._preparation_lane_generation
    assert generation is not None
    semantic_key = (retained.lane_epoch, retained.preparation_id, retained.context_digest)
    with forged._preparation_authority_lock:
        with pytest.raises(StateError, match="belongs to another owner"):
            forged._recover_detached_binding_locked(
                semantic_key,
                generation,
                context,
            )
    with pytest.raises(StateError, match="copied, foreign, tampered, or stale"):
        forged.discard_detached_preparation_binding(binding)
    assert planner.authenticates_detached_preparation_binding(
        binding,
        context_digest=context,
    )
    assert planner.detached_binding_census().retained_bindings == 1
    planner.discard_detached_preparation_binding(binding)


def test_overlay_planner_isolates_authority_and_cannot_revoke_owner_binding() -> None:
    planner = SourceTimingPlanner()
    context = _digest("overlay-owner-isolation")
    with planner.prepared_planning() as timing:
        timing.seal()
        binding = planner.detach_preparation_binding(timing, context_digest=context)
        overlay = object.__getattribute__(timing, "_overlay_planner")

    assert type(overlay) is SourceTimingPlanner
    assert not overlay.authenticates_detached_preparation_binding(
        binding,
        context_digest=context,
    )
    with pytest.raises(StateError, match="copied, foreign, tampered, or stale"):
        overlay.discard_detached_preparation_binding(binding)
    assert planner.authenticates_detached_preparation_binding(
        binding,
        context_digest=context,
    )
    owner_state = planner.__dict__
    overlay_state = overlay.__dict__
    for field_name in (
        "_preparation_lock",
        "_preparation_admission_lock",
        "_preparation_authority_lock",
        "_preparation_claim_records",
        "_committed_preparation_receipts",
        "_detached_bindings",
        "_detached_binding_by_context",
    ):
        assert overlay_state[field_name] is not owner_state[field_name]
    assert overlay_state["_preparation_secret"] != owner_state["_preparation_secret"]
    planner.discard_detached_preparation_binding(binding)


def test_detached_binding_rejects_copy_tamper_foreign_context_and_stale() -> None:
    planner = SourceTimingPlanner()
    foreign = SourceTimingPlanner()
    with planner.prepared_planning() as timing:
        pass
    context = _digest("member-1")
    binding = planner.detach_preparation_binding(timing, context_digest=context)
    copied = replace(binding)
    tampered = replace(binding, overlay_digest=_digest("tampered"))

    assert not planner.authenticates_detached_preparation_binding(
        copied,
        context_digest=context,
    )
    assert not planner.authenticates_detached_preparation_binding(
        tampered,
        context_digest=context,
    )
    assert not foreign.authenticates_detached_preparation_binding(
        binding,
        context_digest=context,
    )
    assert not planner.authenticates_detached_preparation_binding(
        binding,
        context_digest=_digest("member-2"),
    )

    planner.discard_detached_preparation_binding(binding)
    assert not planner.authenticates_detached_preparation_binding(
        binding,
        context_digest=context,
    )


def test_detached_binding_exact_tampered_original_can_reclaim_but_copy_cannot() -> None:
    planner = SourceTimingPlanner()
    with planner.prepared_planning() as timing:
        pass
    context = _digest("member-cleanup")
    binding = planner.detach_preparation_binding(timing, context_digest=context)
    copied = replace(binding)

    with pytest.raises(StateError, match="copied, foreign, tampered, or stale"):
        planner.discard_detached_preparation_binding(copied)

    object.__setattr__(binding, "context_digest", _digest("forced-public-tamper"))
    assert not planner.authenticates_detached_preparation_binding(
        binding,
        context_digest=context,
    )
    planner.discard_detached_preparation_binding(binding)
    assert planner.detached_binding_census().retained_bindings == 0


def test_detached_binding_concurrent_public_tamper_invokes_no_callbacks() -> None:
    planner = SourceTimingPlanner()
    with planner.prepared_planning() as timing:
        pass
    context = _digest("member-concurrent-tamper")
    binding = planner.detach_preparation_binding(timing, context_digest=context)
    original_context = binding.context_digest
    trap = _CallbackTrap()
    started = Event()

    def mutate_public_slot() -> None:
        started.set()
        for _ in range(10_000):
            object.__setattr__(binding, "context_digest", trap)
            object.__setattr__(binding, "context_digest", original_context)

    thread = Thread(target=mutate_public_slot)
    thread.start()
    assert started.wait(timeout=1)
    while thread.is_alive():
        planner.authenticates_detached_preparation_binding(
            binding,
            context_digest=context,
        )
    thread.join(timeout=1)

    assert trap.calls == 0
    planner.discard_detached_preparation_binding(binding)


def test_detach_rejects_hostile_preparation_and_nested_token_slots_without_callbacks() -> None:
    planner = SourceTimingPlanner()
    with planner.prepared_planning() as timing:
        pass
    context = _digest("hostile-sealed-carrier")
    token = timing.binding_token
    original_state = timing._state
    original_token = timing._binding_token
    original_preparation_id = token.preparation_id
    trap = _CallbackTrap()

    object.__setattr__(timing, "_state", trap)
    with pytest.raises(StateError, match="sealed preparation"):
        planner.detach_preparation_binding(timing, context_digest=context)
    object.__setattr__(timing, "_state", original_state)

    object.__setattr__(timing, "_binding_token", trap)
    with pytest.raises(StateError, match="sealed preparation"):
        planner.detach_preparation_binding(timing, context_digest=context)
    object.__setattr__(timing, "_binding_token", original_token)

    object.__setattr__(token, "preparation_id", trap)
    with pytest.raises(StateError, match="sealed preparation"):
        planner.detach_preparation_binding(timing, context_digest=context)
    object.__setattr__(token, "preparation_id", original_preparation_id)

    assert trap.calls == 0
    binding = planner.detach_preparation_binding(timing, context_digest=context)
    planner.discard_detached_preparation_binding(binding)


def test_detach_concurrent_hostile_token_toggles_are_callback_free() -> None:
    planner = SourceTimingPlanner()
    with planner.prepared_planning() as timing:
        pass
    context = _digest("concurrent-sealed-carrier")
    token = timing.binding_token
    original_token = timing._binding_token
    original_preparation_id = token.preparation_id
    trap = _CallbackTrap()
    started = Event()

    def mutate_carrier_and_token() -> None:
        started.set()
        for _ in range(10_000):
            object.__setattr__(timing, "_binding_token", trap)
            object.__setattr__(timing, "_binding_token", original_token)
            object.__setattr__(token, "preparation_id", trap)
            object.__setattr__(token, "preparation_id", original_preparation_id)

    thread = Thread(target=mutate_carrier_and_token)
    thread.start()
    assert started.wait(timeout=1)
    while thread.is_alive():
        try:
            planner.detach_preparation_binding(timing, context_digest=context)
        except StateError:
            pass
    thread.join(timeout=1)
    object.__setattr__(timing, "_binding_token", original_token)
    object.__setattr__(token, "preparation_id", original_preparation_id)

    assert trap.calls == 0
    binding = planner.detach_preparation_binding(timing, context_digest=context)
    planner.discard_detached_preparation_binding(binding)


def test_detached_expected_and_committed_receipt_toggles_are_callback_free() -> None:
    planner = SourceTimingPlanner()
    with planner.prepared_planning() as timing:
        pass
    context = _digest("concurrent-receipt-carrier")
    binding = planner.detach_preparation_binding(timing, context_digest=context)
    trap = _CallbackTrap()

    with timing.claimed_commit() as claimed:
        expected = claimed.expected_receipt
        token = expected.binding_token
        original_receipt_token = expected.binding_token
        original_overlay = expected.overlay_digest
        original_base = token.base_state_digest
        started = Event()

        def mutate_expected_receipt() -> None:
            started.set()
            for _ in range(10_000):
                object.__setattr__(expected, "binding_token", trap)
                object.__setattr__(expected, "binding_token", original_receipt_token)
                object.__setattr__(expected, "overlay_digest", trap)
                object.__setattr__(expected, "overlay_digest", original_overlay)
                object.__setattr__(token, "base_state_digest", trap)
                object.__setattr__(token, "base_state_digest", original_base)

        thread = Thread(target=mutate_expected_receipt)
        thread.start()
        assert started.wait(timeout=1)
        while thread.is_alive():
            planner.authenticates_expected_detached_preparation_binding(
                binding,
                expected,
                context_digest=context,
            )
        thread.join(timeout=1)
        object.__setattr__(expected, "binding_token", original_receipt_token)
        object.__setattr__(expected, "overlay_digest", original_overlay)
        object.__setattr__(token, "base_state_digest", original_base)
        assert planner.authenticates_expected_detached_preparation_binding(
            binding,
            expected,
            context_digest=context,
        )
        receipt = claimed.commit_no_fail()

    original_receipt_token = receipt.binding_token
    original_committed = receipt.committed_state_digest
    original_preparation_id = original_receipt_token.preparation_id
    started = Event()

    def mutate_committed_receipt() -> None:
        started.set()
        for _ in range(10_000):
            object.__setattr__(receipt, "binding_token", trap)
            object.__setattr__(receipt, "binding_token", original_receipt_token)
            object.__setattr__(receipt, "committed_state_digest", trap)
            object.__setattr__(receipt, "committed_state_digest", original_committed)
            object.__setattr__(original_receipt_token, "preparation_id", trap)
            object.__setattr__(
                original_receipt_token,
                "preparation_id",
                original_preparation_id,
            )

    thread = Thread(target=mutate_committed_receipt)
    thread.start()
    assert started.wait(timeout=1)
    while thread.is_alive():
        planner.authenticates_committed_detached_preparation_binding(
            binding,
            receipt,
            context_digest=context,
        )
        planner.authenticates_preparation_receipt(receipt)
    thread.join(timeout=1)
    object.__setattr__(receipt, "binding_token", original_receipt_token)
    object.__setattr__(receipt, "committed_state_digest", original_committed)
    object.__setattr__(original_receipt_token, "preparation_id", original_preparation_id)

    assert trap.calls == 0
    assert planner.authenticates_committed_detached_preparation_binding(
        binding,
        receipt,
        context_digest=context,
    )


def test_detached_binding_capacity_and_exact_same_context_recovery() -> None:
    planner = SourceTimingPlanner(detached_binding_capacity=1)
    with planner.prepared_planning() as timing:
        pass
    context = _digest("member-1")
    binding = planner.detach_preparation_binding(timing, context_digest=context)

    assert planner.detach_preparation_binding(timing, context_digest=context) is binding
    with pytest.raises(StateError, match="capacity"):
        planner.detach_preparation_binding(timing, context_digest=_digest("member-2"))
    census = planner.detached_binding_census()
    assert census.retained_bindings == 1
    assert census.capacity == 1
    assert census.high_water_bindings == 1


def test_detached_binding_rejects_valid_stale_generation_transplant() -> None:
    """A valid old token/seal cannot become the next lane's detached generation."""

    planner = SourceTimingPlanner()
    with planner.prepared_planning() as first:
        pass
    first_context = _digest("first-generation")
    first_binding = planner.detach_preparation_binding(first, context_digest=first_context)
    stale_token = first.binding_token
    stale_overlay = first.overlay_digest
    stale_seal = first._seal_integrity
    first.cancel()

    with planner.prepared_planning() as second:
        pass
    current_token = second.binding_token
    current_overlay = second.overlay_digest
    current_seal = second._seal_integrity
    object.__setattr__(second, "_binding_token", stale_token)
    object.__setattr__(second, "_sealed_overlay_digest", stale_overlay)
    object.__setattr__(second, "_seal_integrity", stale_seal)

    with pytest.raises(StateError, match="sealed preparation"):
        planner.detach_preparation_binding(
            second,
            context_digest=_digest("forged-second-generation"),
        )

    object.__setattr__(second, "_binding_token", current_token)
    object.__setattr__(second, "_sealed_overlay_digest", current_overlay)
    object.__setattr__(second, "_seal_integrity", current_seal)
    with second.claimed_commit() as claimed:
        expected = claimed.expected_receipt
        assert not planner.authenticates_expected_detached_preparation_binding(
            first_binding,
            expected,
            context_digest=first_context,
        )
        committed = claimed.commit_no_fail()
    assert not planner.authenticates_committed_detached_preparation_binding(
        first_binding,
        committed,
        context_digest=first_context,
    )
    planner.discard_detached_preparation_binding(first_binding)


def test_detached_binding_cancel_during_preallocation_leaves_no_authority(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Cancellation in the preallocation gap makes final detached admission stale."""

    planner = SourceTimingPlanner()
    with planner.prepared_planning() as timing:
        pass
    entered = Event()
    release = Event()
    real_token_hex = source_timing_module.secrets.token_hex

    def blocked_token_hex(size: int) -> str:
        entered.set()
        assert release.wait(timeout=2)
        return real_token_hex(size)

    monkeypatch.setattr(source_timing_module.secrets, "token_hex", blocked_token_hex)
    results: list[object] = []

    def detach() -> None:
        try:
            results.append(
                planner.detach_preparation_binding(
                    timing,
                    context_digest=_digest("cancelled-before-detached-insert"),
                )
            )
        except StateError as error:
            results.append(error)

    thread = Thread(target=detach)
    thread.start()
    assert entered.wait(timeout=1)
    timing.cancel()
    release.set()
    thread.join(timeout=2)

    assert len(results) == 1
    assert isinstance(results[0], StateError)
    assert planner.detached_binding_census().retained_bindings == 0


def test_detached_binding_tampered_same_context_retry_fails_closed() -> None:
    """Recovery never returns a retained exact object whose public proof was corrupted."""

    planner = SourceTimingPlanner()
    with planner.prepared_planning() as timing:
        pass
    context = _digest("same-context-tamper")
    binding = planner.detach_preparation_binding(timing, context_digest=context)
    object.__setattr__(binding, "context_digest", _digest("tampered-retry"))

    with pytest.raises(StateError, match="tampered"):
        planner.detach_preparation_binding(timing, context_digest=context)

    assert not planner.authenticates_detached_preparation_binding(
        binding,
        context_digest=context,
    )
    assert planner.detached_binding_census().retained_bindings == 0
    timing.cancel()


def test_detached_binding_requires_sealed_preparation_and_exact_digest() -> None:
    planner = SourceTimingPlanner()
    with planner.prepared_planning() as timing:
        with pytest.raises(StateError, match="sealed preparation"):
            planner.detach_preparation_binding(timing, context_digest=_digest("context"))

    with pytest.raises(StateError, match="SHA-256"):
        planner.detach_preparation_binding(timing, context_digest="not-a-digest")


def test_detached_binding_byte_census_is_explicit_and_planner_composable() -> None:
    planner = SourceTimingPlanner()

    disabled = planner.detached_binding_census()
    assert disabled.binding_semantic_bytes == 0
    assert disabled.generation_semantic_bytes == 0
    assert disabled.claim_semantic_bytes == 0
    assert disabled.receipt_semantic_bytes == 0
    assert disabled.entry_semantic_bytes == 0
    assert disabled.table_backing_bytes == 0
    assert disabled.estimated_bytes == 0

    empty = planner.detached_binding_census(estimate_bytes=True)
    assert empty.binding_semantic_bytes == 0
    assert empty.generation_semantic_bytes == 0
    assert empty.claim_semantic_bytes == 0
    assert empty.receipt_semantic_bytes == 0
    assert empty.entry_semantic_bytes == 0
    assert empty.table_backing_bytes > 0
    assert empty.estimated_bytes == empty.table_backing_bytes

    with planner.prepared_planning() as timing:
        open_generation = planner.detached_binding_census(estimate_bytes=True)
        assert open_generation.generation_semantic_bytes > 0
        assert open_generation.entry_semantic_bytes == open_generation.generation_semantic_bytes
    sealed_generation = planner.detached_binding_census(estimate_bytes=True)
    assert sealed_generation.generation_semantic_bytes > open_generation.generation_semantic_bytes

    context = _digest("byte-census-composition")
    binding = planner.detach_preparation_binding(timing, context_digest=context)
    detached = planner.detached_binding_census(estimate_bytes=True)
    assert detached.binding_semantic_bytes > 0
    assert detached.entry_semantic_bytes == (
        detached.binding_semantic_bytes + detached.generation_semantic_bytes
    )

    with timing.claimed_commit() as claimed:
        expected = claimed.expected_receipt
        claimed_census = planner.detached_binding_census(estimate_bytes=True)
        assert claimed_census.claim_semantic_bytes > 0
        assert claimed_census.receipt_semantic_bytes > 0
        assert claimed_census.entry_semantic_bytes == (
            claimed_census.binding_semantic_bytes
            + claimed_census.generation_semantic_bytes
            + claimed_census.claim_semantic_bytes
            + claimed_census.receipt_semantic_bytes
        )
        receipt = claimed.commit_no_fail()
        assert receipt is expected

    committed = planner.detached_binding_census(estimate_bytes=True)
    assert committed.generation_semantic_bytes == 0
    assert committed.binding_semantic_bytes == detached.binding_semantic_bytes
    assert committed.claim_semantic_bytes == claimed_census.claim_semantic_bytes
    assert committed.receipt_semantic_bytes == claimed_census.receipt_semantic_bytes
    assert committed.estimated_bytes == (
        committed.entry_semantic_bytes + committed.table_backing_bytes
    )

    planner_census = planner.census(estimate_bytes=True)
    composable_total = planner_census.estimated_total_bytes + committed.estimated_bytes
    assert composable_total == (
        sys.getsizeof(planner)
        + planner_census.estimated_index_bytes
        + planner_census.runtime.estimated_bytes
        + committed.estimated_bytes
    )
    planner.discard_detached_preparation_binding(binding)
    del binding, claimed, expected, receipt, timing
    gc.collect()
    reclaimed = planner.detached_binding_census(estimate_bytes=True)
    assert reclaimed.entry_semantic_bytes == 0
    assert reclaimed.table_backing_bytes == empty.table_backing_bytes
    assert reclaimed.estimated_bytes == empty.estimated_bytes


def test_detached_binding_byte_census_full_capacity_gc_and_constant_work(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    planner = SourceTimingPlanner()
    baseline = planner.detached_binding_census(estimate_bytes=True)
    with planner.prepared_planning() as timing:
        pass
    bindings = [
        planner.detach_preparation_binding(
            timing,
            context_digest=_digest(f"full-byte-census-{ordinal}"),
        )
        for ordinal in range(4_096)
    ]
    timing.cancel()

    real_getsizeof = source_timing_module.sys.getsizeof
    measured_objects: list[object] = []

    def counted_getsizeof(value: object) -> int:
        measured_objects.append(value)
        return real_getsizeof(value)

    monkeypatch.setattr(source_timing_module.sys, "getsizeof", counted_getsizeof)
    full = planner.detached_binding_census(estimate_bytes=True)
    monkeypatch.undo()

    assert full.retained_bindings == full.capacity == 4_096
    assert full.binding_semantic_bytes > 0
    assert full.binding_semantic_bytes % 4_096 == 0
    assert full.generation_semantic_bytes == 0
    assert full.claim_semantic_bytes == 0
    assert full.receipt_semantic_bytes == 0
    assert full.entry_semantic_bytes == full.binding_semantic_bytes
    assert full.table_backing_bytes > baseline.table_backing_bytes
    assert full.estimated_bytes == full.entry_semantic_bytes + full.table_backing_bytes
    assert len(measured_objects) == 4
    assert {id(value) for value in measured_objects} == {
        id(planner._preparation_claim_records),
        id(planner._committed_preparation_receipts),
        id(planner._detached_bindings),
        id(planner._detached_binding_by_context),
    }

    bindings.clear()
    gc.collect()
    reclaimed = planner.detached_binding_census(estimate_bytes=True)
    assert reclaimed.retained_bindings == 0
    assert reclaimed.binding_semantic_bytes == 0
    assert reclaimed.entry_semantic_bytes == 0
    assert reclaimed.table_backing_bytes == baseline.table_backing_bytes
    assert reclaimed.estimated_bytes == baseline.estimated_bytes


def test_detached_binding_byte_census_churn_resets_table_backing_plateau() -> None:
    planner = SourceTimingPlanner(detached_binding_capacity=64)
    baseline = planner.detached_binding_census(estimate_bytes=True)
    full_table_sizes: set[int] = set()

    for cycle in range(6):
        with planner.prepared_planning() as timing:
            pass
        bindings = tuple(
            planner.detach_preparation_binding(
                timing,
                context_digest=_digest(f"byte-churn-{cycle}-{ordinal}"),
            )
            for ordinal in range(64)
        )
        timing.cancel()
        full = planner.detached_binding_census(estimate_bytes=True)
        assert full.retained_bindings == 64
        full_table_sizes.add(full.table_backing_bytes)

        del bindings
        gc.collect()
        reclaimed = planner.detached_binding_census(estimate_bytes=True)
        assert reclaimed.retained_bindings == 0
        assert reclaimed.entry_semantic_bytes == 0
        assert reclaimed.table_backing_bytes == baseline.table_backing_bytes

    assert len(full_table_sizes) == 1
