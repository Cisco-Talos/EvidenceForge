# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Finite-capacity atomicity tests for canonical TLS material ownership."""

from __future__ import annotations

import gc
from concurrent.futures import ThreadPoolExecutor
from copy import copy, deepcopy
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from threading import Barrier, Event
from typing import Any, Literal
from weakref import ref

import pytest

import evidenceforge.generation.cryptographic_material as cryptographic_material
from evidenceforge.events.cryptography import CertificateIdentityPlan
from evidenceforge.generation.actions.tls_certificate import TlsCertificatePlanner
from evidenceforge.generation.cryptographic_material import (
    CryptographicMaterialCapacityError,
    CryptographicMaterialPreparation,
    CryptographicMaterialPreparationToken,
    CryptographicMaterialPreparedCommit,
    CryptographicMaterialRegistry,
)
from evidenceforge.models.exceptions import StateError


def _certificate(
    owner: CryptographicMaterialRegistry | CryptographicMaterialPreparation,
    *,
    identity: str = "capacity.example",
    san_dns: tuple[str, ...] | None = None,
) -> CertificateIdentityPlan:
    """Resolve one deterministic two-point key/certificate identity."""

    return owner.resolve_certificate(
        backend_identity=identity,
        subject_name=f"CN={identity}",
        issuer_name="CN=Capacity Test CA, O=Example Corp, C=US",
        not_valid_before=1_700_000_000,
        not_valid_after=1_800_000_000,
        key_type="ecdsa",
        key_size=256,
        signature_algorithm="ecdsa-with-SHA256",
        san_dns=(identity,) if san_dns is None else san_dns,
    )


class _RejectedDoubleCountingRegistry(CryptographicMaterialRegistry):
    """Negative-control owner that charges a live point and its reservation twice."""

    def _commit_claimed_tls_preparation(
        self,
        token: CryptographicMaterialPreparationToken,
        transaction: CryptographicMaterialPreparedCommit,
    ) -> Any:
        capacity = self.tls_material_capacity
        assert capacity is not None
        with self._tls_material_lock:
            capability = self._tls_capability_for_exact_token_locked(token)
            assert capability is not None
            assert (
                self._tls_active_claim_transaction_locked(capability.preparation_id) is transaction
            )
            for patch in capability.trusted_token._patches:
                if (
                    self._tls_live_material_points_locked() + len(self._tls_point_reservations)
                    > capacity
                ):
                    raise CryptographicMaterialCapacityError(
                        "negative control double-counted a published reservation"
                    )
                CryptographicMaterialRegistry._publish_tls_material_locked(
                    self,
                    patch.family,
                    patch.key,
                    patch.value,
                    reservation_id=capability.preparation_id,
                )
        raise AssertionError("negative control unexpectedly published every point")


def test_rejected_double_counting_control_splits_exact_capacity_commit() -> None:
    """The withdrawn live-plus-reservation algorithm reproduces its partial commit."""

    registry = _RejectedDoubleCountingRegistry(tls_material_capacity=2)
    preparation = registry.begin_tls_preparation()
    _certificate(preparation)
    token = preparation.seal()

    with pytest.raises(CryptographicMaterialCapacityError, match="double-counted"):
        with registry.prepared_tls_material(token) as claimed:
            claimed.commit_no_fail()

    census = registry.census()
    assert census.public_keys + census.certificates == 1
    assert (census.public_keys, census.certificates) in {(1, 0), (0, 1)}
    assert census.prepared_overlays == census.claimed_overlays == census.reserved_points == 0


def test_exact_two_point_preparation_transfers_reservation_all_or_none() -> None:
    """An exact-cap key/certificate pair consumes two slots throughout commit."""

    registry = CryptographicMaterialRegistry(tls_material_capacity=2)
    preparation = registry.begin_tls_preparation()
    expected = replace(_certificate(preparation))
    token = preparation.seal()
    sealed = registry.tls_material_point_capacity_census()

    assert (token.public_key_writes, token.certificate_writes) == (1, 1)
    assert sealed.live_material_points == 0
    assert sealed.reserved_new_material_points == sealed.retained_material_points == 2
    assert sealed.reserved_material_bytes > 0
    with registry.prepared_tls_material(token) as claimed:
        receipt = claimed.commit_no_fail()

    committed = registry.tls_material_point_capacity_census()
    assert registry.authenticates_tls_preparation_receipt(receipt, token=token)
    assert _certificate(registry) == expected
    assert committed.live_material_points == committed.retained_material_points == 2
    assert committed.reserved_new_material_points == committed.reserved_material_bytes == 0
    assert committed.retained_material_bytes == sealed.reserved_material_bytes
    assert committed.material_point_high_water == 2
    assert committed.material_byte_high_water == committed.retained_material_bytes


def test_explicit_none_is_semantically_identical_and_capacity_one_is_neutral() -> None:
    """The unlimited escape stays exact while a one-slot compound write is rejected."""

    for invalid in (0, -1, True, 1.5, "2"):
        with pytest.raises(ValueError, match="None or a positive exact integer"):
            CryptographicMaterialRegistry(tls_material_capacity=invalid)  # type: ignore[arg-type]

    default = CryptographicMaterialRegistry()
    assert default.tls_material_capacity == 100_000
    first_unlimited = CryptographicMaterialRegistry(tls_material_capacity=None)
    second_unlimited = CryptographicMaterialRegistry(tls_material_capacity=None)
    assert _certificate(first_unlimited) == _certificate(second_unlimited)
    assert first_unlimited.census() == second_unlimited.census()
    assert first_unlimited.state_digest() == second_unlimited.state_digest()
    assert first_unlimited.tls_material_point_capacity_census().material_point_capacity is None
    assert second_unlimited.tls_material_point_capacity_census().material_point_capacity is None

    bounded = CryptographicMaterialRegistry(tls_material_capacity=1)
    before = (
        bounded.census(),
        bounded.tls_material_point_capacity_census(),
        bounded.state_digest(),
    )
    with pytest.raises(CryptographicMaterialCapacityError, match="retained-key capacity"):
        _certificate(bounded)
    assert before == (
        bounded.census(),
        bounded.tls_material_point_capacity_census(),
        bounded.state_digest(),
    )


def test_direct_compound_failure_and_reserved_prerequisite_publish_nothing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Direct builders and prerequisite reservations fail before their first write."""

    registry = CryptographicMaterialRegistry(tls_material_capacity=2)
    before = (
        registry.census(),
        registry.tls_material_point_capacity_census(),
        registry.state_digest(),
    )

    def reject_certificate(**_arguments: Any) -> CertificateIdentityPlan:
        raise ValueError("injected certificate construction failure")

    monkeypatch.setattr(registry, "_build_certificate_identity", reject_certificate)
    with pytest.raises(ValueError, match="injected certificate construction failure"):
        _certificate(registry)
    assert before == (
        registry.census(),
        registry.tls_material_point_capacity_census(),
        registry.state_digest(),
    )

    monkeypatch.undo()
    reserved = registry.begin_tls_preparation()
    reserved.public_key_spki(
        "certificate:capacity.example:CN=capacity.example",
        key_type="ecdsa",
        key_size=256,
    )
    token = reserved.seal()
    held = (
        registry.census(),
        registry.tls_material_point_capacity_census(),
        registry.state_digest(),
    )
    with pytest.raises(StateError, match="public_key:.* is reserved"):
        _certificate(registry)
    assert held == (
        registry.census(),
        registry.tls_material_point_capacity_census(),
        registry.state_digest(),
    )
    assert registry.cancel_tls_preparation(token)


def test_live_reserved_and_tombstone_replacement_each_count_once() -> None:
    """Live, virgin reservation, and ABA tombstone share one exact slot census."""

    registry = CryptographicMaterialRegistry(tls_material_capacity=2)
    first_identity = "live.example"
    second_identity = "reserved.example"
    registry.public_key_spki(first_identity, key_type="ecdsa", key_size=256)

    preparation = registry.begin_tls_preparation()
    preparation.public_key_spki(second_identity, key_type="ecdsa", key_size=256)
    token = preparation.seal()
    mixed = registry.tls_material_point_capacity_census()
    assert mixed.live_material_points == 1
    assert mixed.reserved_new_material_points == 1
    assert mixed.retained_material_points == 2
    with pytest.raises(CryptographicMaterialCapacityError, match="retained-key capacity"):
        registry.public_key_spki("third.example", key_type="ecdsa", key_size=256)
    with registry.prepared_tls_material(token) as claimed:
        claimed.commit_no_fail()

    key = (first_identity, "ecdsa", 256)
    point = ("public_key", key)
    with registry._tls_material_lock:
        live_generation = registry._tls_point_generations[point]
        assert registry._delete_tls_material_locked("public_key", key)
        tombstone_generation = registry._tls_point_tombstones[point]
    deleted = registry.tls_material_point_capacity_census()
    assert tombstone_generation == live_generation + 1
    assert deleted.live_material_points == 1
    assert deleted.tombstone_material_points == 1
    assert deleted.retained_material_points == 2

    replacement = registry.begin_tls_preparation()
    replacement.public_key_spki(first_identity, key_type="ecdsa", key_size=256)
    replacement_token = replacement.seal()
    sealed = registry.tls_material_point_capacity_census()
    assert sealed.reserved_new_material_points == 0
    assert sealed.retained_material_points == 2
    with registry.prepared_tls_material(replacement_token) as claimed:
        claimed.commit_no_fail()
    final = registry.tls_material_point_capacity_census()
    assert final.live_material_points == final.retained_material_points == 2
    assert final.tombstone_material_points == 0


def test_finite_aba_generations_stop_at_uint64_without_byte_or_slot_growth() -> None:
    """Delete/reinsert ABA history has a fixed generation width and one retained slot."""

    registry = CryptographicMaterialRegistry(tls_material_capacity=1)
    identity = "bounded-aba"
    registry.public_key_spki(identity, key_type="ecdsa", key_size=256)
    initial = registry.tls_material_point_capacity_census()
    point = ("public_key", (identity, "ecdsa", 256))

    for _ in range(128):
        with registry._tls_material_lock:
            assert registry._delete_tls_material_locked("public_key", point[1])
        tombstone = registry.tls_material_point_capacity_census()
        assert tombstone.live_material_points == 0
        assert tombstone.tombstone_material_points == tombstone.retained_material_points == 1
        assert tombstone.retained_material_bytes <= tombstone.material_byte_capacity
        registry.public_key_spki(identity, key_type="ecdsa", key_size=256)

    cycled = registry.tls_material_point_capacity_census()
    assert cycled.live_material_points == cycled.retained_material_points == 1
    assert cycled.tombstone_material_points == 0
    assert cycled.retained_material_bytes == initial.retained_material_bytes
    assert cycled.material_point_generation_high_water == 257
    assert cycled.material_point_generation_capacity == (1 << 64) - 1

    with registry._tls_material_lock:
        registry._tls_point_generations[point] = cycled.material_point_generation_capacity
        registry._tls_material_generation_high_water = cycled.material_point_generation_capacity
    before = (
        registry.census(),
        registry.tls_material_point_capacity_census(),
        registry.state_digest(),
    )
    with registry._tls_material_lock:
        with pytest.raises(CryptographicMaterialCapacityError, match="generation capacity"):
            registry._delete_tls_material_locked("public_key", point[1])
    assert before == (
        registry.census(),
        registry.tls_material_point_capacity_census(),
        registry.state_digest(),
    )


def test_direct_write_and_seal_race_has_exactly_one_capacity_winner() -> None:
    """A direct writer cannot pass the same one-slot boundary as a concurrent seal."""

    for ordinal in range(16):
        registry = CryptographicMaterialRegistry(tls_material_capacity=1)
        preparation = registry.begin_tls_preparation()
        preparation.public_key_spki(f"sealed-{ordinal}", key_type="ecdsa", key_size=256)
        barrier = Barrier(2)

        def seal(
            current_barrier: Barrier = barrier,
            current_preparation: CryptographicMaterialPreparation = preparation,
        ) -> tuple[str, CryptographicMaterialPreparationToken | None]:
            current_barrier.wait(timeout=2.0)
            try:
                return "sealed", current_preparation.seal()
            except CryptographicMaterialCapacityError:
                return "rejected", None

        def write(
            current_barrier: Barrier = barrier,
            current_registry: CryptographicMaterialRegistry = registry,
            current_ordinal: int = ordinal,
        ) -> tuple[str, None]:
            current_barrier.wait(timeout=2.0)
            try:
                current_registry.public_key_spki(
                    f"direct-{current_ordinal}",
                    key_type="ecdsa",
                    key_size=256,
                )
                return "written", None
            except CryptographicMaterialCapacityError:
                return "rejected", None

        with ThreadPoolExecutor(max_workers=2) as pool:
            seal_future = pool.submit(seal)
            write_future = pool.submit(write)
            results = (seal_future.result(), write_future.result())

        outcomes = {result[0] for result in results}
        assert outcomes in ({"sealed", "rejected"}, {"written", "rejected"})
        token = next((result[1] for result in results if result[1] is not None), None)
        if token is not None:
            assert registry.cancel_tls_preparation(token)
            assert preparation.cancel() is False
        else:
            assert preparation.cancel()
        census = registry.tls_material_point_capacity_census()
        assert census.retained_material_points <= 1
        assert census.material_point_high_water <= 1


def test_two_competing_two_point_seals_have_one_atomic_winner() -> None:
    """Two disjoint certificate seals serialize at the exact two-slot cap."""

    registry = CryptographicMaterialRegistry(tls_material_capacity=2)
    preparations = [registry.begin_tls_preparation() for _ in range(2)]
    for ordinal, preparation in enumerate(preparations):
        _certificate(preparation, identity=f"competitor-{ordinal}.example")
    barrier = Barrier(2)

    def seal(
        preparation: CryptographicMaterialPreparation,
    ) -> CryptographicMaterialPreparationToken | None:
        barrier.wait(timeout=2.0)
        try:
            return preparation.seal()
        except CryptographicMaterialCapacityError:
            return None

    with ThreadPoolExecutor(max_workers=2) as pool:
        tokens = tuple(pool.map(seal, preparations))

    winner = next(token for token in tokens if token is not None)
    assert sum(token is not None for token in tokens) == 1
    sealed = registry.tls_material_point_capacity_census()
    assert sealed.reserved_new_material_points == sealed.retained_material_points == 2
    with registry.prepared_tls_material(winner) as claimed:
        claimed.commit_no_fail()
    for preparation, token in zip(preparations, tokens, strict=True):
        if token is None:
            assert preparation.cancel()
    final = registry.tls_material_point_capacity_census()
    assert final.live_material_points == final.retained_material_points == 2
    assert final.reserved_new_material_points == 0


def test_same_preparation_seal_and_cancel_cannot_strand_capacity(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Cancellation waits for an in-flight seal, then releases its exact token."""

    registry = CryptographicMaterialRegistry(tls_material_capacity=1)
    preparation = registry.begin_tls_preparation()
    preparation.public_key_spki("seal-cancel", key_type="ecdsa", key_size=256)
    real_seal = registry._seal_tls_preparation
    entered = Event()
    release = Event()
    cancel_started = Event()

    def paused_seal(patches: tuple[Any, ...]) -> CryptographicMaterialPreparationToken:
        entered.set()
        assert release.wait(timeout=2.0)
        return real_seal(patches)

    def cancel() -> bool:
        cancel_started.set()
        return preparation.cancel()

    monkeypatch.setattr(registry, "_seal_tls_preparation", paused_seal)
    with ThreadPoolExecutor(max_workers=2) as pool:
        seal_future = pool.submit(preparation.seal)
        assert entered.wait(timeout=2.0)
        cancel_future = pool.submit(cancel)
        assert cancel_started.wait(timeout=2.0)
        release.set()
        token = seal_future.result(timeout=2.0)
        assert cancel_future.result(timeout=2.0)

    assert not registry.authenticates_tls_preparation_token(token)
    assert preparation.cancel() is False
    assert registry.census().prepared_overlays == registry.census().reserved_points == 0
    census = registry.tls_material_point_capacity_census()
    assert census.retained_material_points == census.reserved_material_bytes == 0


def test_same_preparation_concurrent_seal_is_idempotent(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Concurrent seals return one exact token and create one reservation."""

    registry = CryptographicMaterialRegistry(tls_material_capacity=1)
    preparation = registry.begin_tls_preparation()
    preparation.public_key_spki("double-seal", key_type="ecdsa", key_size=256)
    real_seal = registry._seal_tls_preparation
    entered = Event()
    release = Event()
    calls = 0

    def paused_seal(patches: tuple[Any, ...]) -> CryptographicMaterialPreparationToken:
        nonlocal calls
        calls += 1
        entered.set()
        assert release.wait(timeout=2.0)
        return real_seal(patches)

    monkeypatch.setattr(registry, "_seal_tls_preparation", paused_seal)
    with ThreadPoolExecutor(max_workers=2) as pool:
        first_future = pool.submit(preparation.seal)
        assert entered.wait(timeout=2.0)
        second_future = pool.submit(preparation.seal)
        release.set()
        first = first_future.result(timeout=2.0)
        second = second_future.result(timeout=2.0)

    assert first is second
    assert calls == 1
    assert registry.census().prepared_overlays == registry.census().reserved_points == 1
    assert preparation.cancel()


def test_real_commit_then_lost_return_has_one_canonical_result(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A lost return cannot retain reservations or duplicate committed capacity."""

    registry = CryptographicMaterialRegistry(tls_material_capacity=2)
    preparation = registry.begin_tls_preparation()
    expected = replace(_certificate(preparation))
    token = preparation.seal()
    real_commit = registry._commit_claimed_tls_preparation

    def commit_then_raise(
        claimed_token: CryptographicMaterialPreparationToken,
        transaction: CryptographicMaterialPreparedCommit,
    ) -> None:
        real_commit(claimed_token, transaction)
        raise RuntimeError("injected lost return")

    monkeypatch.setattr(registry, "_commit_claimed_tls_preparation", commit_then_raise)
    with pytest.raises(RuntimeError, match="injected lost return"):
        with registry.prepared_tls_material(token) as claimed:
            claimed.commit_no_fail()

    census = registry.tls_material_point_capacity_census()
    assert registry.census().prepared_overlays == registry.census().reserved_points == 0
    assert census.live_material_points == census.retained_material_points == 2
    assert census.reserved_new_material_points == census.reserved_material_bytes == 0
    assert _certificate(registry) == expected
    assert registry.cancel_tls_preparation(token) is False

    retry = registry.begin_tls_preparation()
    assert _certificate(retry) == expected
    retry_token = retry.seal()
    assert retry_token.public_key_writes == retry_token.certificate_writes == 0
    monkeypatch.setattr(registry, "_commit_claimed_tls_preparation", real_commit)
    with registry.prepared_tls_material(retry_token) as claimed:
        claimed.commit_no_fail()
    assert registry.tls_material_point_capacity_census().retained_material_points == 2


def test_preparation_and_claim_capabilities_reject_copies_and_forged_commit() -> None:
    """Only the exact context-issued transaction can consume a prepared capability."""

    registry = CryptographicMaterialRegistry(tls_material_capacity=1)
    preparation = registry.begin_tls_preparation()
    preparation.public_key_spki("copy-boundary", key_type="ecdsa", key_size=256)
    for copier in (copy, deepcopy):
        with pytest.raises(StateError, match="preparations cannot be copied"):
            copier(preparation)
    token = preparation.seal()

    with registry.prepared_tls_material(token) as owner:
        for copier in (copy, deepcopy):
            with pytest.raises(StateError, match="commit capabilities cannot be copied"):
                copier(owner)
        forged = CryptographicMaterialPreparedCommit(registry, token)
        held = (
            registry.census(),
            registry.tls_material_point_capacity_census(),
            registry.state_digest(),
        )
        with pytest.raises(StateError, match="not the claim owner"):
            forged.commit_no_fail()
        assert held == (
            registry.census(),
            registry.tls_material_point_capacity_census(),
            registry.state_digest(),
        )
        receipt = owner.commit_no_fail()

    assert owner.committed
    assert owner.receipt == receipt
    assert registry.authenticates_tls_preparation_receipt(receipt, token=token)
    malformed_receipt = replace(receipt)
    object.__setattr__(malformed_receipt, "_registry_token", object())
    assert not registry.authenticates_tls_preparation_receipt(malformed_receipt)
    assert registry.census().prepared_overlays == registry.census().claimed_overlays == 0


def test_claim_cleanup_ignores_caller_tampering_with_transaction_fields() -> None:
    """Caller-mutated status fields cannot suppress registry-owned claim cleanup."""

    registry = CryptographicMaterialRegistry(tls_material_capacity=1)
    preparation = registry.begin_tls_preparation()
    preparation.public_key_spki("tampered-claim", key_type="ecdsa", key_size=256)
    token = preparation.seal()

    with registry.prepared_tls_material(token) as transaction:
        transaction._committed = True
        transaction._active = False
        transaction._receipt = object()  # type: ignore[assignment]

    census = registry.tls_material_point_capacity_census()
    assert registry.census().prepared_overlays == registry.census().claimed_overlays == 0
    assert census.retained_material_points == census.reserved_material_bytes == 0
    registry.public_key_spki("after-tampered-claim", key_type="ecdsa", key_size=256)


def test_abandoned_claim_is_weak_and_reaped_before_direct_publication() -> None:
    """A lost finite claim owner cannot retain its token graph or reserved slot."""

    registry = CryptographicMaterialRegistry(tls_material_capacity=1)
    preparation = registry.begin_tls_preparation()
    preparation.public_key_spki("abandoned-claim", key_type="ecdsa", key_size=256)
    token = preparation.seal()
    transaction = CryptographicMaterialPreparedCommit(registry, token)
    registry._claim_tls_preparation(token, transaction)
    transaction_reference = ref(transaction)
    del transaction
    gc.collect()
    assert transaction_reference() is None

    registry.public_key_spki("after-abandoned-claim", key_type="ecdsa", key_size=256)
    assert not registry.authenticates_tls_preparation_token(token)
    census = registry.tls_material_point_capacity_census()
    assert census.live_material_points == census.retained_material_points == 1
    assert census.reserved_new_material_points == census.reserved_material_bytes == 0


def test_copy_cancel_and_replay_release_only_the_original_reservation() -> None:
    """Equal copied capabilities cannot consume or release finite owner capacity."""

    registry = CryptographicMaterialRegistry(tls_material_capacity=2)
    initial = (registry.census(), registry.state_digest())
    preparation = registry.begin_tls_preparation()
    _certificate(preparation)
    token = preparation.seal()
    copied = deepcopy(token)
    aliased = replace(token)
    sealed = (
        registry.census(),
        registry.tls_material_point_capacity_census(),
        registry.state_digest(),
    )

    for invalid in (copied, aliased):
        assert not registry.authenticates_tls_preparation_token(invalid)
        with pytest.raises(StateError, match="stale or already consumed"):
            with registry.prepared_tls_material(invalid):
                pytest.fail("copied capability entered the claim body")
        assert sealed == (
            registry.census(),
            registry.tls_material_point_capacity_census(),
            registry.state_digest(),
        )

    malformed = replace(token)
    object.__setattr__(malformed, "_registry_token", object())
    assert not registry.authenticates_tls_preparation_token(malformed)
    with pytest.raises(StateError, match="integrity validation failed"):
        with registry.prepared_tls_material(malformed):
            pytest.fail("malformed copied capability entered the claim body")
    assert sealed == (
        registry.census(),
        registry.tls_material_point_capacity_census(),
        registry.state_digest(),
    )

    assert registry.cancel_tls_preparation(token)
    released = registry.tls_material_point_capacity_census()
    assert released.retained_material_points == released.reserved_material_bytes == 0
    assert initial == (registry.census(), registry.state_digest())
    assert registry.cancel_tls_preparation(token) is False
    with pytest.raises(StateError, match="stale or already consumed"):
        with registry.prepared_tls_material(token):
            pytest.fail("cancelled capability replay entered the claim body")


def test_mutated_public_preparation_id_releases_exact_internal_capability() -> None:
    """Cleanup locates the exact live token without trusting its mutable public ID."""

    registry = CryptographicMaterialRegistry(tls_material_capacity=1)
    initial = (registry.census(), registry.state_digest())
    preparation = registry.begin_tls_preparation()
    preparation.public_key_spki("mutated-preparation-id", key_type="ecdsa", key_size=256)
    token = preparation.seal()
    object.__setattr__(token, "preparation_id", token.preparation_id + 10_000)

    assert not registry.authenticates_tls_preparation_token(token)
    with pytest.raises(StateError, match="integrity validation failed"):
        registry.cancel_tls_preparation(token)
    assert initial == (registry.census(), registry.state_digest())
    registry.public_key_spki("after-mutated-preparation-id", key_type="ecdsa", key_size=256)


def test_claim_abort_releases_finite_capacity_and_restores_state_digest() -> None:
    """An uncommitted claim returns every current slot and byte counter."""

    registry = CryptographicMaterialRegistry(tls_material_capacity=2)
    initial = (registry.census(), registry.state_digest())
    preparation = registry.begin_tls_preparation()
    _certificate(preparation)
    token = preparation.seal()

    with registry.prepared_tls_material(token):
        claimed = registry.tls_material_point_capacity_census()
        assert registry.census().claimed_overlays == 1
        assert claimed.retained_material_points == 2

    current = registry.tls_material_point_capacity_census()
    assert initial == (registry.census(), registry.state_digest())
    assert current.retained_material_points == 0
    assert current.reserved_material_bytes == current.retained_material_preparation_bytes == 0
    assert current.material_point_high_water == 2


def test_finite_preparation_identity_watermark_exhausts_without_aba() -> None:
    """Finite owner IDs stop at uint64 instead of growing or recycling capabilities."""

    registry = CryptographicMaterialRegistry(tls_material_capacity=1)
    initial = (registry.census(), registry.state_digest())
    capacity = registry.tls_material_point_capacity_census().material_preparation_id_capacity
    assert capacity == (1 << 64) - 1
    registry._next_tls_preparation_id = capacity
    preparation = registry.begin_tls_preparation()
    preparation.public_key_spki("last-identity", key_type="ecdsa", key_size=256)
    token = preparation.seal()
    assert token.preparation_id == capacity
    assert registry.cancel_tls_preparation(token)
    assert initial == (registry.census(), registry.state_digest())

    exhausted = registry.begin_tls_preparation()
    exhausted.public_key_spki("after-watermark", key_type="ecdsa", key_size=256)
    before = (registry.census(), registry.state_digest())
    with pytest.raises(CryptographicMaterialCapacityError, match="identity capacity"):
        exhausted.seal()
    assert before == (registry.census(), registry.state_digest())
    census = registry.tls_material_point_capacity_census()
    assert (
        census.material_preparation_id_watermark
        == census.material_preparation_id_capacity
        == capacity
    )
    assert exhausted.cancel()


def test_finite_preparation_gc_and_empty_overlay_retention_are_bounded() -> None:
    """Unsealed graphs collect, while live sealed overlays hit a hard owner cap."""

    finalized: list[str] = []

    class Owner:
        def __del__(self) -> None:
            finalized.append("collected")

    registry = CryptographicMaterialRegistry(tls_material_capacity=1)
    owner = Owner()
    preparation = registry.begin_tls_preparation(owner=owner)
    preparation.public_key_spki("unsealed", key_type="ecdsa", key_size=256)
    del preparation
    del owner
    gc.collect()
    assert finalized == ["collected"]
    assert registry.census().prepared_overlays == 0
    assert registry.tls_material_point_capacity_census().retained_material_points == 0

    cached = registry.public_key_spki("cached", key_type="ecdsa", key_size=256)
    first = registry.begin_tls_preparation()
    assert first.public_key_spki("cached", key_type="ecdsa", key_size=256) == cached
    token = first.seal()
    second = registry.begin_tls_preparation()
    second.public_key_spki("cached", key_type="ecdsa", key_size=256)
    with pytest.raises(CryptographicMaterialCapacityError, match="preparation capacity"):
        second.seal()
    assert second.cancel()
    census = registry.tls_material_point_capacity_census()
    assert registry.census().prepared_overlays == 1
    assert census.material_preparation_high_water == 1
    assert census.material_preparation_byte_capacity is not None
    assert census.retained_material_preparation_bytes <= census.material_preparation_byte_capacity
    assert registry.cancel_tls_preparation(token)


@pytest.mark.parametrize("direct_identity", ("abandoned-token", "disjoint-direct"))
def test_abandoned_deep_tampered_token_is_reaped_before_direct_write(
    direct_identity: str,
) -> None:
    """A caller-mutated public token graph is neither retained nor charged after GC."""

    registry = CryptographicMaterialRegistry(tls_material_capacity=1)
    preparation = registry.begin_tls_preparation()
    preparation.public_key_spki("abandoned-token", key_type="ecdsa", key_size=256)
    token = preparation.seal()
    token_reference = ref(token)
    accounted = registry.tls_material_point_capacity_census().retained_material_preparation_bytes
    patch = token._patches[0]
    object.__setattr__(patch, "value", b"x" * 10_000_000)
    assert len(patch.value) > accounted

    del patch
    del token
    del preparation
    gc.collect()
    assert token_reference() is None

    registry.public_key_spki(direct_identity, key_type="ecdsa", key_size=256)
    census = registry.tls_material_point_capacity_census()
    assert registry.census().prepared_overlays == registry.census().reserved_points == 0
    assert census.live_material_points == census.retained_material_points == 1
    assert census.reserved_new_material_points == census.reserved_material_bytes == 0
    assert census.retained_material_preparation_bytes == 0


def test_repeated_point_and_byte_overflow_leave_bounded_high_water() -> None:
    """Rejected slot and oversized-point writes are census/digest neutral."""

    registry = CryptographicMaterialRegistry(tls_material_capacity=1)
    registry.public_key_spki("only", key_type="ecdsa", key_size=256)
    stable = (
        registry.census(),
        registry.tls_material_point_capacity_census(),
        registry.state_digest(),
    )
    for ordinal in range(128):
        with pytest.raises(CryptographicMaterialCapacityError, match="retained-key capacity"):
            registry.public_key_spki(f"overflow-{ordinal}", key_type="ecdsa", key_size=256)
    assert stable == (
        registry.census(),
        registry.tls_material_point_capacity_census(),
        registry.state_digest(),
    )

    oversized = CryptographicMaterialRegistry(tls_material_capacity=1)
    huge_identity = "x" * 300_000
    before = (
        oversized.census(),
        oversized.tls_material_point_capacity_census(),
        oversized.state_digest(),
    )
    with pytest.raises(CryptographicMaterialCapacityError, match="point retained-byte capacity"):
        oversized.public_key_spki(huge_identity, key_type="ecdsa", key_size=256)
    preparation = oversized.begin_tls_preparation()
    with pytest.raises(CryptographicMaterialCapacityError, match="point retained-byte capacity"):
        preparation.public_key_spki(huge_identity, key_type="ecdsa", key_size=256)
    assert not preparation._patches
    assert preparation.cancel()
    assert before == (
        oversized.census(),
        oversized.tls_material_point_capacity_census(),
        oversized.state_digest(),
    )
    bounded = registry.tls_material_point_capacity_census()
    assert bounded.material_point_capacity is not None
    assert bounded.material_byte_capacity is not None
    assert bounded.material_preparation_byte_capacity is not None
    assert bounded.material_point_high_water <= bounded.material_point_capacity
    assert bounded.material_byte_high_water <= bounded.material_byte_capacity
    assert (
        bounded.material_preparation_byte_high_water <= bounded.material_preparation_byte_capacity
    )


def test_aggregate_material_and_preparation_byte_caps_reject_before_owner_mutation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Aggregate byte ceilings reject compound writes and seals before publication."""

    original_material_owner_bytes = cryptographic_material._MAX_TLS_MATERIAL_OWNER_RETAINED_BYTES
    measurement = CryptographicMaterialRegistry(tls_material_capacity=2)
    measurement_preparation = measurement.begin_tls_preparation()
    _certificate(measurement_preparation, identity="byte-measurement.example")
    measurement_token = measurement_preparation.seal()
    exact_two_point_bytes = measurement.tls_material_point_capacity_census().reserved_material_bytes
    assert exact_two_point_bytes > 1
    assert measurement.cancel_tls_preparation(measurement_token)

    monkeypatch.setattr(
        cryptographic_material,
        "_MAX_TLS_MATERIAL_OWNER_RETAINED_BYTES",
        exact_two_point_bytes - 1,
    )
    direct = CryptographicMaterialRegistry(tls_material_capacity=2)
    direct_before = (
        direct.census(),
        direct.tls_material_point_capacity_census(),
        direct.state_digest(),
    )
    with pytest.raises(CryptographicMaterialCapacityError, match="retained-byte capacity"):
        _certificate(direct, identity="direct-byte-overflow.example")
    assert direct_before == (
        direct.census(),
        direct.tls_material_point_capacity_census(),
        direct.state_digest(),
    )

    staged = CryptographicMaterialRegistry(tls_material_capacity=2)
    staged_preparation = staged.begin_tls_preparation()
    with pytest.raises(
        CryptographicMaterialCapacityError,
        match="preparation retained-byte capacity",
    ):
        _certificate(staged_preparation, identity="staged-byte-overflow.example")
    assert not staged_preparation._patches
    assert staged_preparation.cancel()
    assert staged.census().prepared_overlays == 0

    monkeypatch.setattr(
        cryptographic_material,
        "_MAX_TLS_MATERIAL_OWNER_RETAINED_BYTES",
        original_material_owner_bytes,
    )
    monkeypatch.setattr(
        cryptographic_material,
        "_MAX_TLS_PREPARATION_OWNER_RETAINED_BYTES",
        1,
    )
    sealing = CryptographicMaterialRegistry(tls_material_capacity=2)
    sealing_preparation = sealing.begin_tls_preparation()
    _certificate(sealing_preparation, identity="seal-byte-overflow.example")
    sealing_before = (
        sealing.census(),
        sealing.tls_material_point_capacity_census(),
        sealing.state_digest(),
    )
    with pytest.raises(
        CryptographicMaterialCapacityError,
        match="preparation retained-byte capacity",
    ):
        sealing_preparation.seal()
    assert sealing_before == (
        sealing.census(),
        sealing.tls_material_point_capacity_census(),
        sealing.state_digest(),
    )
    assert sealing_preparation.cancel()


@pytest.mark.parametrize(
    "failure_label",
    ("tls-prepared-capability-v1", "tls-point-reservation-v1"),
)
def test_seal_component_failure_preserves_survivor_and_identity_watermark(
    monkeypatch: pytest.MonkeyPatch,
    failure_label: str,
) -> None:
    """Every seal component is derived before IDs, reservations, or XORs mutate."""

    registry = CryptographicMaterialRegistry(tls_material_capacity=2)
    first = registry.begin_tls_preparation()
    first.public_key_spki("seal-survivor", key_type="ecdsa", key_size=256)
    first_token = first.seal()
    stable = (
        registry.census(),
        registry.tls_material_point_capacity_census(),
        registry.state_digest(),
    )
    failed_id = registry._next_tls_preparation_id
    second = registry.begin_tls_preparation()
    second.public_key_spki("seal-fault", key_type="ecdsa", key_size=256)
    real_component = cryptographic_material._tls_material_state_component

    def fail_selected_component(label: str, value: Any) -> int:
        preparation_id = getattr(value, "preparation_id", None)
        if label == "tls-point-reservation-v1":
            preparation_id = value[1]
        if label == failure_label and preparation_id == failed_id:
            raise RuntimeError("injected seal component failure")
        return real_component(label, value)

    with monkeypatch.context() as fault:
        fault.setattr(
            cryptographic_material,
            "_tls_material_state_component",
            fail_selected_component,
        )
        with pytest.raises(RuntimeError, match="injected seal component failure"):
            second.seal()

    assert registry._next_tls_preparation_id == failed_id
    assert stable == (
        registry.census(),
        registry.tls_material_point_capacity_census(),
        registry.state_digest(),
    )
    assert (
        registry._tls_prepared_state_xor
        == registry._tls_prepared_state_components[first_token.preparation_id]
    )
    assert (
        registry._tls_reservation_state_xor
        == registry._tls_reservation_state_components[first_token._patches[0].point]
    )
    assert second.cancel()
    assert registry.cancel_tls_preparation(first_token)


def test_claim_component_failure_reaps_only_failed_token_and_preserves_survivor(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A failed second claim cannot perturb an already claimed preparation."""

    registry = CryptographicMaterialRegistry(tls_material_capacity=2)
    first = registry.begin_tls_preparation()
    first.public_key_spki("claim-survivor", key_type="ecdsa", key_size=256)
    first_token = first.seal()
    first_transaction = CryptographicMaterialPreparedCommit(registry, first_token)
    registry._claim_tls_preparation(first_token, first_transaction)
    stable = (registry.census(), registry.state_digest())

    second = registry.begin_tls_preparation()
    second.public_key_spki("claim-fault", key_type="ecdsa", key_size=256)
    second_token = second.seal()
    second_id = second_token.preparation_id
    second_reference = ref(second_token)
    second_transaction = CryptographicMaterialPreparedCommit(registry, second_token)
    real_component = cryptographic_material._tls_material_state_component

    def fail_selected_component(label: str, value: Any) -> int:
        if label == "tls-claimed-preparation-v1" and value == second_id:
            raise RuntimeError("injected claim component failure")
        return real_component(label, value)

    with monkeypatch.context() as fault:
        fault.setattr(
            cryptographic_material,
            "_tls_material_state_component",
            fail_selected_component,
        )
        with pytest.raises(RuntimeError, match="injected claim component failure"):
            registry._claim_tls_preparation(second_token, second_transaction)

    del second_transaction
    del second_token
    del second
    gc.collect()
    assert second_reference() is None
    assert stable == (registry.census(), registry.state_digest())
    assert (
        registry._tls_claimed_state_xor
        == registry._tls_claimed_state_components[first_token.preparation_id]
    )
    registry._cancel_claimed_tls_preparation(first_token, first_transaction)
    first_transaction._close()


def test_release_uses_stored_components_without_fallible_state_callbacks(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Cancel has a callback-free mutation tail and cannot strand a reservation."""

    registry = CryptographicMaterialRegistry(tls_material_capacity=1)
    initial = (registry.census(), registry.state_digest())
    preparation = registry.begin_tls_preparation()
    preparation.public_key_spki("release-fault", key_type="ecdsa", key_size=256)
    token = preparation.seal()

    def reject_all_components(_label: str, _value: Any) -> int:
        raise RuntimeError("release must not derive state components")

    with monkeypatch.context() as fault:
        fault.setattr(
            cryptographic_material,
            "_tls_material_state_component",
            reject_all_components,
        )
        assert registry.cancel_tls_preparation(token)
    assert initial == (registry.census(), registry.state_digest())
    registry.public_key_spki("after-release-fault", key_type="ecdsa", key_size=256)


def test_canonical_component_failures_precede_direct_and_prepared_batch_mutation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A late plan failure leaves both points of a compound publication absent."""

    real_component = cryptographic_material._tls_material_state_component

    def reject_certificate_live_component(label: str, value: Any) -> int:
        if label == "tls-canonical-point-v1" and value[0][0] == "certificate" and value[2]:
            raise RuntimeError("injected canonical component failure")
        return real_component(label, value)

    direct = CryptographicMaterialRegistry(tls_material_capacity=2)
    direct_initial = (direct.census(), direct.state_digest())
    with monkeypatch.context() as fault:
        fault.setattr(
            cryptographic_material,
            "_tls_material_state_component",
            reject_certificate_live_component,
        )
        with pytest.raises(RuntimeError, match="injected canonical component failure"):
            _certificate(direct, identity="direct-component-fault.example")
    assert direct_initial == (direct.census(), direct.state_digest())

    prepared = CryptographicMaterialRegistry(tls_material_capacity=2)
    prepared_initial = (prepared.census(), prepared.state_digest())
    preparation = prepared.begin_tls_preparation()
    _certificate(preparation, identity="prepared-component-fault.example")
    token = preparation.seal()
    with prepared.prepared_tls_material(token) as transaction:
        with monkeypatch.context() as fault:
            fault.setattr(
                cryptographic_material,
                "_tls_material_state_component",
                reject_certificate_live_component,
            )
            with pytest.raises(RuntimeError, match="injected canonical component failure"):
                transaction.commit_no_fail()
    assert prepared_initial == (prepared.census(), prepared.state_digest())


def test_live_and_tombstone_components_are_derived_before_single_point_mutation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Single publication and deletion faults leave canonical state byte-for-byte stable."""

    registry = CryptographicMaterialRegistry(tls_material_capacity=1)
    initial = (
        registry.census(),
        registry.tls_material_point_capacity_census(),
        registry.state_digest(),
    )
    real_component = cryptographic_material._tls_material_state_component

    def reject_live_component(label: str, value: Any) -> int:
        if label == "tls-canonical-point-v1" and value[2]:
            raise RuntimeError("injected live component failure")
        return real_component(label, value)

    with monkeypatch.context() as fault:
        fault.setattr(
            cryptographic_material,
            "_tls_material_state_component",
            reject_live_component,
        )
        with pytest.raises(RuntimeError, match="injected live component failure"):
            registry.public_key_spki("component-order", key_type="ecdsa", key_size=256)
    assert initial == (
        registry.census(),
        registry.tls_material_point_capacity_census(),
        registry.state_digest(),
    )

    registry.public_key_spki("component-order", key_type="ecdsa", key_size=256)
    live = (
        registry.census(),
        registry.tls_material_point_capacity_census(),
        registry.state_digest(),
    )

    def reject_tombstone_component(label: str, value: Any) -> int:
        if label == "tls-canonical-point-v1" and not value[2]:
            raise RuntimeError("injected tombstone component failure")
        return real_component(label, value)

    with monkeypatch.context() as fault:
        fault.setattr(
            cryptographic_material,
            "_tls_material_state_component",
            reject_tombstone_component,
        )
        with registry._tls_material_lock:
            with pytest.raises(RuntimeError, match="injected tombstone component failure"):
                registry._delete_tls_material_locked(
                    "public_key",
                    ("component-order", "ecdsa", 256),
                )
    assert live == (
        registry.census(),
        registry.tls_material_point_capacity_census(),
        registry.state_digest(),
    )


@pytest.mark.parametrize("family", ("certificate", "authority"))
def test_direct_compounds_bypass_replaceable_per_point_publisher(
    monkeypatch: pytest.MonkeyPatch,
    family: str,
) -> None:
    """Direct two-point writes use one exact atomic publication tail."""

    registry = CryptographicMaterialRegistry(tls_material_capacity=2)
    real_publish = registry._publish_tls_material_locked
    calls = 0

    def publish_then_raise(*arguments: Any, **keywords: Any) -> int:
        nonlocal calls
        calls += 1
        real_publish(*arguments, **keywords)
        raise RuntimeError("replaceable per-point publisher ran")

    monkeypatch.setattr(registry, "_publish_tls_material_locked", publish_then_raise)
    if family == "certificate":
        _certificate(registry, identity="direct-publisher.example")
        assert (registry.census().public_keys, registry.census().certificates) == (1, 1)
    else:
        registry.resolve_authority(
            subject_name="CN=Direct Publisher CA, O=Example Corp, C=US",
            issuer_name="CN=Direct Publisher CA, O=Example Corp, C=US",
            key_type="ecdsa",
            key_size=256,
        )
        assert (registry.census().public_keys, registry.census().authorities) == (1, 1)
    assert calls == 0
    assert registry.tls_material_point_capacity_census().retained_material_points == 2


def test_prepared_commit_bypasses_replaceable_per_point_publisher(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A prepared compound commit cannot split after one real point publication."""

    registry = CryptographicMaterialRegistry(tls_material_capacity=2)
    preparation = registry.begin_tls_preparation()
    _certificate(preparation, identity="prepared-publisher.example")
    token = preparation.seal()
    real_publish = registry._publish_tls_material_locked
    calls = 0

    def publish_then_raise(*arguments: Any, **keywords: Any) -> int:
        nonlocal calls
        calls += 1
        real_publish(*arguments, **keywords)
        raise RuntimeError("replaceable per-point publisher ran")

    monkeypatch.setattr(registry, "_publish_tls_material_locked", publish_then_raise)
    with registry.prepared_tls_material(token) as transaction:
        transaction.commit_no_fail()
    assert calls == 0
    assert (registry.census().public_keys, registry.census().certificates) == (1, 1)
    census = registry.tls_material_point_capacity_census()
    assert census.live_material_points == census.retained_material_points == 2
    assert census.reserved_new_material_points == census.reserved_material_bytes == 0


@pytest.mark.parametrize("capacity", (None, 1))
def test_context_cleanup_bypasses_replaceable_finalizer_and_preserves_primary_error(
    monkeypatch: pytest.MonkeyPatch,
    capacity: int | None,
) -> None:
    """Context cleanup cannot be replaced to mask a body error or strand a claim."""

    registry = CryptographicMaterialRegistry(tls_material_capacity=capacity)
    initial = (registry.census(), registry.state_digest())
    preparation = registry.begin_tls_preparation()
    preparation.public_key_spki("cleanup-dispatch", key_type="ecdsa", key_size=256)
    token = preparation.seal()
    calls = 0

    def reject_cleanup(*_arguments: Any, **_keywords: Any) -> None:
        nonlocal calls
        calls += 1
        raise RuntimeError("replaceable cleanup ran")

    monkeypatch.setattr(registry, "_cancel_claimed_tls_preparation", reject_cleanup)
    with pytest.raises(ValueError, match="primary body failure"):
        with registry.prepared_tls_material(token):
            raise ValueError("primary body failure")
    assert calls == 0
    assert initial == (registry.census(), registry.state_digest())


def test_finite_capacity_scalar_is_uint64_bounded_without_wide_integer_repr() -> None:
    """Finite capacity accepts uint64 max and rejects wider or huge attacker integers."""

    maximum = (1 << 64) - 1
    registry = CryptographicMaterialRegistry(tls_material_capacity=maximum)
    census = registry.tls_material_point_capacity_census()
    assert census.material_point_capacity == maximum
    assert registry.state_digest()
    for invalid in (maximum + 1, 1 << 20_000):
        with pytest.raises(ValueError, match=r"at most 2\^64 - 1"):
            CryptographicMaterialRegistry(tls_material_capacity=invalid)


def test_default_capacity_reference_tls_workload_plateaus_far_below_high_water() -> None:
    """The reviewed 30-day certificate workload stays duration-stable below 100K points."""

    domains = (
        "alpha.example.test",
        "bravo.example.test",
        "charlie.example.test",
        "delta.example.test",
    )
    issuer = {
        "name": "CN=DigiCert Global G2 TLS RSA SHA256 2020 CA1, O=DigiCert Inc, C=US",
        "validity_days": 397,
        "validity_days_min": 397,
        "validity_days_max": 397,
        "not_before_max_days": 300,
    }
    start = datetime(2024, 3, 15, 10, 0, tzinfo=UTC)

    def run(days: int) -> tuple[int, int, int, int]:
        registry = CryptographicMaterialRegistry()
        planner = TlsCertificatePlanner(registry)
        fingerprints: dict[str, str] = {}
        for hour in range(days * 24):
            domain = domains[hour % len(domains)]
            presentation = planner.plan(
                backend_identity=domain,
                cert_name=domain,
                issuer_config=issuer,
                event_time=start + timedelta(hours=hour),
                connection_identity=f"reference-{hour}",
                key_type="rsa",
                key_size=2048,
                san_dns=(domain,),
            )
            prior = fingerprints.setdefault(domain, presentation.leaf.fingerprint)
            assert prior == presentation.leaf.fingerprint
        census = registry.tls_material_point_capacity_census()
        assert census.material_point_capacity == 100_000
        assert census.retained_material_points == census.live_material_points
        assert census.material_point_high_water == census.live_material_points
        assert census.live_material_points < 100
        return (
            census.live_material_points,
            census.material_point_high_water,
            census.retained_material_bytes,
            census.material_byte_high_water,
        )

    assert run(1) == run(7) == run(30)


def test_auxiliary_census_reports_recomputed_ocsp_and_bounded_dkim_retention() -> None:
    """Auxiliary material is either recomputed or covered by an explicit cap."""

    registry = CryptographicMaterialRegistry(tls_material_capacity=2)
    certificate = _certificate(registry, identity="ocsp-residual.example")
    before = registry.tls_material_point_capacity_census()
    digest_before = registry.state_digest()
    assert before.live_material_points == before.material_point_capacity == 2
    assert before.ocsp_status_capacity == before.ocsp_status_byte_capacity == 0
    assert before.retained_ocsp_status_entries == 0
    assert before.retained_ocsp_status_estimated_bytes == 0

    for ordinal in range(1_000):
        registry.resolve_ocsp_status(
            certificate,
            [
                {
                    "name": f"uncapped-ocsp-{ordinal:04d}",
                    "certificate_patterns": ["*"],
                    "status_weights": {"good": 1},
                }
            ],
        )

    after = registry.tls_material_point_capacity_census()
    assert after == before
    assert registry.state_digest() == digest_before

    dkim_registry = CryptographicMaterialRegistry(tls_material_capacity=1)
    dkim_registry.resolve_dkim_key(domain="example.test", selector="mail", key_size=2048)
    dkim = dkim_registry.tls_material_point_capacity_census()
    assert dkim.dkim_key_capacity == 1
    assert dkim.retained_dkim_key_entries == dkim.dkim_key_high_water == 1
    assert dkim.retained_dkim_key_estimated_bytes == dkim.dkim_key_byte_high_water
    assert 0 < dkim.retained_dkim_key_estimated_bytes <= dkim.dkim_key_byte_capacity
    assert dkim.uncapped_dkim_key_entries == dkim.retained_dkim_key_entries
    assert dkim.uncapped_dkim_key_estimated_bytes == dkim.retained_dkim_key_estimated_bytes


@pytest.mark.soak
def test_default_hundred_thousand_point_boundary_rejects_one_over_before_publication(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The reviewed production default counts semantic points, not TLS sessions."""

    registry = CryptographicMaterialRegistry()
    capacity = registry.tls_material_capacity
    assert capacity == 100_000
    spki = CryptographicMaterialRegistry(tls_material_capacity=None).public_key_spki(
        "constant-spki",
        key_type="ecdsa",
        key_size=256,
    )

    def constant_spki(
        _identity: str,
        *,
        normalized_type: Literal["rsa", "ecdsa"],
        normalized_size: int,
    ) -> bytes:
        assert normalized_type == "ecdsa"
        assert normalized_size == 256
        return spki

    monkeypatch.setattr(registry, "_build_public_key_spki", constant_spki)
    for ordinal in range(capacity):
        registry.public_key_spki(
            f"default-capacity-point-{ordinal:06d}",
            key_type="ecdsa",
            key_size=256,
        )

    exact = registry.tls_material_point_capacity_census()
    assert exact.live_material_points == exact.retained_material_points == capacity
    assert exact.material_point_high_water == capacity
    before = (registry.census(), exact, registry.state_digest())
    with pytest.raises(CryptographicMaterialCapacityError, match="retained-key capacity"):
        registry.public_key_spki(
            "default-capacity-point-overflow",
            key_type="ecdsa",
            key_size=256,
        )
    assert before == (
        registry.census(),
        registry.tls_material_point_capacity_census(),
        registry.state_digest(),
    )
