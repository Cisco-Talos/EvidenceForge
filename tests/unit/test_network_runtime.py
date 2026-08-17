# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Focused atomicity tests for generator-local network preparations."""

from __future__ import annotations

import random
from concurrent.futures import ThreadPoolExecutor
from copy import deepcopy
from dataclasses import dataclass, replace
from datetime import UTC, datetime, timedelta, tzinfo
from enum import Enum

import pytest

from evidenceforge.events.network import NetworkTransactionPlan
from evidenceforge.generation.cryptographic_material import CryptographicMaterialRegistry
from evidenceforge.generation.network_runtime import (
    NetworkConnectionCommitResult,
    NetworkPointBatchPreparedCommit,
    NetworkRuntimePointFamily,
    NetworkTransactionPreparation,
    NetworkTransactionRuntime,
    PreparedNetworkTransactionRoot,
)
from evidenceforge.generation.state_manager import (
    ConnectionIdentityPlan,
    ConnectionMaterializationMode,
    StateManager,
)
from evidenceforge.models.exceptions import StateError
from tests.network_factories import network_plan

_START = datetime(2026, 8, 16, 12, 0, tzinfo=UTC)


def _runtime() -> tuple[NetworkTransactionRuntime, StateManager, CryptographicMaterialRegistry]:
    state = StateManager()
    crypto = CryptographicMaterialRegistry()
    runtime = NetworkTransactionRuntime(
        state_manager=state,
        cryptographic_material=crypto,
        window_start=_START,
        window_end=_START + timedelta(days=2),
    )
    return runtime, state, crypto


def _authority_snapshot(
    runtime: NetworkTransactionRuntime,
    state: StateManager,
    crypto: CryptographicMaterialRegistry,
    rng: random.Random,
) -> tuple[object, ...]:
    """Return exact canonical and transient authority state for neutral checks."""

    return (
        runtime.state_digest(),
        runtime.census(),
        runtime.last_result,
        state.materialization_digest(),
        state.materialization_version,
        crypto.state_digest(),
        crypto.census(),
        crypto.tls_preparation_census(),
        rng.getstate(),
    )


def _physical_preparation(
    runtime: NetworkTransactionRuntime,
    rng: random.Random,
    *,
    ordinal: int = 0,
    duration: float = 10.0,
) -> tuple[NetworkTransactionPreparation, object]:
    started_at = _START + timedelta(seconds=ordinal * 20)
    stable_id = f"network-runtime-physical-{ordinal}"
    preparation = runtime.begin(
        owner_rng=rng,
        stable_id=stable_id,
        linearization_time=started_at,
    )
    identity = preparation.reserve_physical_identity()
    transaction = _physical_transaction(
        identity,
        stable_id=stable_id,
        started_at=started_at,
        ordinal=ordinal,
        duration=duration,
    )
    root = preparation.seal(
        transaction=transaction,
        lifecycle_mode="network",
        materialization_mode=ConnectionMaterializationMode.PHYSICAL,
    )
    return preparation, root


def _physical_transaction(
    identity: ConnectionIdentityPlan,
    *,
    stable_id: str,
    started_at: datetime,
    ordinal: int = 0,
    duration: float = 10.0,
) -> NetworkTransactionPlan:
    return replace(
        network_plan(
            src_ip="10.0.0.10",
            src_port=50_000 + ordinal,
            dst_ip="10.0.0.20",
            dst_port=443,
            protocol="tcp",
            service="https",
            zeek_uid=identity.zeek_uid,
            conn_id=identity.conn_id,
            duration=duration,
            source_visible_start_time=started_at,
            conn_state="SF",
            history="ShADadFf",
            orig_bytes=120,
            resp_bytes=480,
        ),
        stable_id=stable_id,
    )


def _commit_runtime(runtime: NetworkTransactionRuntime, root: object) -> object:
    token = root.runtime_token
    with runtime.claimed_preparation(token) as prepared:
        return prepared.commit_no_fail()


def _materialize_parent(
    runtime: NetworkTransactionRuntime,
    state: StateManager,
    rng: random.Random,
) -> object:
    _preparation, root = _physical_preparation(runtime, rng)
    state.materialize_connection_composite(root.state_plan, rng)
    _commit_runtime(runtime, root)
    return root


def _application_child_preparation(
    runtime: NetworkTransactionRuntime,
    rng: random.Random,
    parent: object,
    *,
    ordinal: int,
) -> tuple[NetworkTransactionPreparation, object]:
    parent_transaction = parent.transaction
    started_at = parent_transaction.started_at + timedelta(seconds=ordinal)
    closed_at = started_at + timedelta(milliseconds=250)
    stable_id = f"network-runtime-child-{ordinal}"
    preparation = runtime.begin(
        owner_rng=rng,
        stable_id=stable_id,
        linearization_time=started_at,
    )
    child = replace(
        parent_transaction,
        stable_id=stable_id,
        phase_times=(("application_start", started_at), ("application_close", closed_at)),
        started_at=started_at,
        closed_at=closed_at,
        duration=0.25,
        application_layer_only=True,
    )
    root = preparation.seal(
        transaction=child,
        lifecycle_mode="application_child",
        materialization_mode=ConnectionMaterializationMode.APPLICATION_CHILD,
    )
    return preparation, root


def _application_child_transaction(
    parent: PreparedNetworkTransactionRoot,
    *,
    stable_id: str,
    offset_seconds: int,
) -> NetworkTransactionPlan:
    parent_transaction = parent.transaction
    started_at = parent_transaction.started_at + timedelta(seconds=offset_seconds)
    closed_at = started_at + timedelta(milliseconds=250)
    return replace(
        parent_transaction,
        stable_id=stable_id,
        phase_times=(("application_start", started_at), ("application_close", closed_at)),
        started_at=started_at,
        closed_at=closed_at,
        duration=0.25,
        application_layer_only=True,
    )


def test_open_and_sealed_cancel_restore_exact_state_rng_and_crypto_census() -> None:
    """Cancellation publishes no runtime, State, RNG, or TLS material state."""

    runtime, state, crypto = _runtime()
    rng = random.Random(719)
    runtime_before = runtime.state_digest()
    runtime_census_before = runtime.census()
    state_before = state.materialization_digest()
    rng_before = rng.getstate()
    crypto_before = crypto.tls_preparation_census()
    crypto_digest_before = crypto.state_digest()

    open_preparation = runtime.begin(
        owner_rng=rng,
        stable_id="network-runtime-cancel-open",
        linearization_time=_START,
    )
    open_preparation.rng.random()
    open_preparation.stage_point(
        NetworkRuntimePointFamily.RECENT_TUPLE,
        ("10.0.0.10", 443),
        {"port": 50_000},
    )
    open_preparation.cryptographic_material.public_key_spki(
        "cancelled.example.test",
        key_type="ecdsa",
        key_size=256,
    )
    open_preparation.cancel()

    assert runtime.state_digest() == runtime_before
    assert runtime.census() == runtime_census_before
    assert state.materialization_digest() == state_before
    assert rng.getstate() == rng_before
    assert crypto.tls_preparation_census() == crypto_before
    assert crypto.state_digest() == crypto_digest_before

    _preparation, root = _physical_preparation(runtime, rng)
    assert runtime.cancel_preparation(root.runtime_token) is True
    assert runtime.state_digest() == runtime_before
    assert runtime.census() == runtime_census_before
    assert state.materialization_digest() == state_before
    assert rng.getstate() == rng_before
    assert crypto.tls_preparation_census() == crypto_before
    assert crypto.state_digest() == crypto_digest_before


def test_nested_crypto_view_cannot_publish_outside_the_network_composite() -> None:
    """The caller-facing TLS resolver has no seal/cancel capability to escape."""

    runtime, state, crypto = _runtime()
    before = runtime.census()
    state_before = state.materialization_digest()
    crypto_before = crypto.census()
    crypto_digest_before = crypto.state_digest()
    preparation = runtime.begin(
        owner_rng=random.Random(23),
        stable_id="network-runtime-owned-tls",
        linearization_time=_START,
    )
    view = preparation.cryptographic_material
    view.public_key_spki(
        "owned-network-key",
        key_type="ecdsa",
        key_size=256,
    )

    assert not hasattr(view, "seal")
    assert not hasattr(view, "cancel")
    assert not hasattr(view, "_owner")
    assert not hasattr(preparation, "_crypto")
    assert not hasattr(preparation, "_crypto_owner")
    assert not hasattr(view, "_NetworkCryptographicMaterialPreparation__preparation")
    preparation.cancel()

    assert runtime.census() == before
    assert state.materialization_digest() == state_before
    assert crypto.census() == crypto_before
    assert crypto.state_digest() == crypto_digest_before


def test_outer_claim_never_exposes_the_nested_crypto_commit_authority() -> None:
    """Abandoning an outer claim cannot leave independently committed TLS state."""

    runtime, state, crypto = _runtime()
    state_before = state.materialization_digest()
    crypto_before = crypto.census()
    preparation = runtime.begin(
        owner_rng=random.Random(29),
        stable_id="network-runtime-private-claim",
        linearization_time=_START,
    )
    identity = preparation.reserve_physical_identity()
    preparation.cryptographic_material.public_key_spki(
        "private-claim-key",
        key_type="ecdsa",
        key_size=256,
    )
    root = preparation.seal(
        transaction=_physical_transaction(
            identity,
            stable_id="network-runtime-private-claim",
            started_at=_START,
        ),
        lifecycle_mode="network",
        materialization_mode=ConnectionMaterializationMode.PHYSICAL,
    )

    with runtime.claimed_preparation(root.runtime_token) as prepared:
        assert not hasattr(prepared, "_crypto")
        assert not hasattr(prepared, "_token")

    assert runtime.last_result is None
    assert runtime.census().prepared_transactions == 0
    assert runtime.census().claimed_transactions == 0
    assert state.materialization_digest() == state_before
    assert crypto.census() == crypto_before


def test_prepared_commit_publishes_points_crypto_result_and_signed_receipt_once() -> None:
    """One claim publishes every trusted nested value and a verifiable receipt."""

    runtime, state, crypto = _runtime()
    rng = random.Random(41)
    preparation = runtime.begin(
        owner_rng=rng,
        stable_id="network-runtime-commit",
        linearization_time=_START,
    )
    identity = preparation.reserve_physical_identity()
    mutable_value = {"ports": [443, 8443]}
    preparation.stage_point(
        NetworkRuntimePointFamily.RECENT_TUPLE,
        "client-a",
        mutable_value,
        expires_at=_START + timedelta(hours=1),
    )
    certificate = preparation.cryptographic_material.resolve_certificate(
        backend_identity="backend-a",
        subject_name="CN=api.example.test",
        issuer_name="CN=Example Test CA",
        not_valid_before=1_700_000_000,
        not_valid_after=1_800_000_000,
        key_type="ecdsa",
        key_size=256,
        signature_algorithm="ecdsa-with-SHA256",
        san_dns=("api.example.test",),
    )
    transaction = replace(
        network_plan(
            src_ip="10.0.0.10",
            src_port=50_000,
            dst_ip="10.0.0.20",
            dst_port=443,
            protocol="tcp",
            service="https",
            zeek_uid=identity.zeek_uid,
            conn_id=identity.conn_id,
            duration=1.0,
            source_visible_start_time=_START,
            conn_state="SF",
            history="ShADadFf",
        ),
        stable_id="network-runtime-commit",
    )
    root = preparation.seal(
        transaction=transaction,
        lifecycle_mode="network",
        materialization_mode=ConnectionMaterializationMode.PHYSICAL,
    )
    mutable_value["ports"].append(9443)

    assert runtime.authenticates_preparation_token(
        root.runtime_token,
        expected_transaction_id=transaction.stable_id,
    )
    state_before = state.materialization_digest()
    rng_before = rng.getstate()
    receipt = _commit_runtime(runtime, root)

    assert state.materialization_digest() == state_before
    assert rng.getstate() == rng_before
    assert runtime.get_point(NetworkRuntimePointFamily.RECENT_TUPLE, "client-a") == {
        "ports": [443, 8443]
    }
    assert runtime.last_result is not None
    assert runtime.last_result.transaction == transaction
    assert runtime.authenticates_preparation_token(root.runtime_token) is False
    assert runtime.authenticates_preparation_receipt(receipt, token=root.runtime_token)
    assert receipt.cryptographic_receipt.certificate_writes == 1
    assert (
        crypto.resolve_certificate(
            backend_identity="backend-a",
            subject_name="CN=api.example.test",
            issuer_name="CN=Example Test CA",
            not_valid_before=1_700_000_000,
            not_valid_after=1_800_000_000,
            key_type="ecdsa",
            key_size=256,
            signature_algorithm="ecdsa-with-SHA256",
            san_dns=("api.example.test",),
        )
        == certificate
    )
    with pytest.raises(StateError, match="already consumed"):
        with runtime.claimed_preparation(root.runtime_token):
            pass


def test_preparation_root_authenticates_exact_semantic_replacement_without_mutation() -> None:
    """The root is a value carrier while its exact nested token owns one-shot authority."""

    runtime, state, crypto = _runtime()
    rng = random.Random(43)
    _preparation, root = _physical_preparation(runtime, rng)
    before = _authority_snapshot(runtime, state, crypto, rng)

    assert runtime.authenticates_preparation_root(root)
    assert runtime.authenticates_preparation_root(replace(root))
    assert _authority_snapshot(runtime, state, crypto, rng) == before

    assert runtime.cancel_preparation(root.runtime_token)


def test_preparation_root_rejects_replaced_semantics_and_modes_without_mutation() -> None:
    """Transaction, result, State plan, and mode drift cannot borrow an authentic token."""

    runtime, state, crypto = _runtime()
    rng = random.Random(47)
    _preparation, root = _physical_preparation(runtime, rng)
    changed_transaction = replace(root.transaction, dst_ip="198.51.100.47")
    changed_result = replace(root.result, effective_dst_ip="198.51.100.47")
    changed_plan = replace(root.state_plan, _transaction=changed_transaction)
    changed_mode_plan = replace(
        root.state_plan,
        _mode=ConnectionMaterializationMode.APPLICATION_CHILD,
    )
    changed_lifecycle_result = replace(root.result, lifecycle_mode="application_child")
    before = _authority_snapshot(runtime, state, crypto, rng)

    assert not runtime.authenticates_preparation_root(
        replace(root, transaction=changed_transaction)
    )
    assert not runtime.authenticates_preparation_root(replace(root, result=changed_result))
    assert not runtime.authenticates_preparation_root(replace(root, state_plan=changed_plan))
    assert not runtime.authenticates_preparation_root(replace(root, state_plan=changed_mode_plan))
    assert not runtime.authenticates_preparation_root(
        replace(root, result=changed_lifecycle_result)
    )
    assert runtime.authenticates_preparation_root(root)
    assert _authority_snapshot(runtime, state, crypto, rng) == before

    assert runtime.cancel_preparation(root.runtime_token)


def test_preparation_root_rejects_foreign_and_copied_capabilities_without_mutation() -> None:
    """Root copies cannot replace the exact active token or cross runtime ownership."""

    runtime, state, crypto = _runtime()
    foreign_runtime, foreign_state, foreign_crypto = _runtime()
    rng = random.Random(53)
    foreign_rng = random.Random(59)
    _preparation, root = _physical_preparation(runtime, rng)
    _foreign_preparation, foreign_root = _physical_preparation(
        foreign_runtime,
        foreign_rng,
    )
    copied_token_root = replace(root, runtime_token=replace(root.runtime_token))
    deep_copied_root = deepcopy(root)
    before = _authority_snapshot(runtime, state, crypto, rng)
    foreign_before = _authority_snapshot(
        foreign_runtime,
        foreign_state,
        foreign_crypto,
        foreign_rng,
    )

    assert not runtime.authenticates_preparation_root(copied_token_root)
    assert not runtime.authenticates_preparation_root(deep_copied_root)
    assert not runtime.authenticates_preparation_root(foreign_root)
    assert not foreign_runtime.authenticates_preparation_root(root)
    assert runtime.authenticates_preparation_root(root)
    assert foreign_runtime.authenticates_preparation_root(foreign_root)
    assert _authority_snapshot(runtime, state, crypto, rng) == before
    assert (
        _authority_snapshot(foreign_runtime, foreign_state, foreign_crypto, foreign_rng)
        == foreign_before
    )

    assert runtime.cancel_preparation(root.runtime_token)
    assert foreign_runtime.cancel_preparation(foreign_root.runtime_token)


def test_preparation_root_authentication_is_total_for_malformed_nested_fields() -> None:
    """Malformed nested fields return False without executing caller representation hooks."""

    class EvilStr(str):
        def __repr__(self) -> str:
            raise RuntimeError("caller-controlled root repr must not run")

    runtime, state, crypto = _runtime()
    rng = random.Random(61)
    _preparation, root = _physical_preparation(runtime, rng)
    cyclic_result = replace(root.result)
    object.__setattr__(cyclic_result, "http", cyclic_result)
    malformed_plan = replace(root.state_plan)
    object.__setattr__(malformed_plan, "_integrity_token", object())
    malformed_result = replace(root.result)
    object.__setattr__(malformed_result, "effective_dst_ip", EvilStr("tampered"))
    original_overlay_digest = root.runtime_token.overlay_digest
    before = _authority_snapshot(runtime, state, crypto, rng)

    assert not runtime.authenticates_preparation_root(object())
    assert not runtime.authenticates_preparation_root(replace(root, runtime_token=object()))
    assert not runtime.authenticates_preparation_root(replace(root, state_plan=object()))
    assert not runtime.authenticates_preparation_root(replace(root, result=object()))
    assert not runtime.authenticates_preparation_root(replace(root, result=cyclic_result))
    assert not runtime.authenticates_preparation_root(replace(root, state_plan=malformed_plan))
    assert not runtime.authenticates_preparation_root(replace(root, result=malformed_result))
    object.__setattr__(root.runtime_token, "overlay_digest", EvilStr("tampered"))
    assert not runtime.authenticates_preparation_root(root)
    object.__setattr__(root.runtime_token, "overlay_digest", original_overlay_digest)
    assert runtime.authenticates_preparation_root(root)
    assert _authority_snapshot(runtime, state, crypto, rng) == before

    assert runtime.cancel_preparation(root.runtime_token)


def test_preparation_root_requires_live_state_and_nested_crypto_proofs(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The public root proof composes the exact State plan and nested TLS capability."""

    runtime, state, crypto = _runtime()
    rng = random.Random(67)
    _preparation, root = _physical_preparation(runtime, rng)
    before = _authority_snapshot(runtime, state, crypto, rng)

    with monkeypatch.context() as scoped:
        scoped.setattr(
            StateManager,
            "authenticates_materialization_plan",
            lambda _manager, _plan: False,
        )
        assert not runtime.authenticates_preparation_root(root)
    with monkeypatch.context() as scoped:
        scoped.setattr(
            CryptographicMaterialRegistry,
            "authenticates_tls_preparation_token",
            lambda _registry, _token: False,
        )
        assert not runtime.authenticates_preparation_root(root)
    assert runtime.authenticates_preparation_root(root)
    assert _authority_snapshot(runtime, state, crypto, rng) == before

    assert runtime.cancel_preparation(root.runtime_token)


def test_preparation_root_rejects_cancelled_and_consumed_tokens_without_mutation() -> None:
    """Cancellation and commit permanently retire root authentication authority."""

    runtime, state, crypto = _runtime()
    cancelled_rng = random.Random(71)
    _preparation, cancelled_root = _physical_preparation(runtime, cancelled_rng)
    assert runtime.cancel_preparation(cancelled_root.runtime_token)
    cancelled_before = _authority_snapshot(runtime, state, crypto, cancelled_rng)

    assert not runtime.authenticates_preparation_root(cancelled_root)
    assert _authority_snapshot(runtime, state, crypto, cancelled_rng) == cancelled_before

    consumed_rng = random.Random(73)
    _preparation, consumed_root = _physical_preparation(runtime, consumed_rng, ordinal=1)
    _commit_runtime(runtime, consumed_root)
    consumed_before = _authority_snapshot(runtime, state, crypto, consumed_rng)

    assert not runtime.authenticates_preparation_root(consumed_root)
    assert not runtime.authenticates_preparation_root(replace(consumed_root))
    assert _authority_snapshot(runtime, state, crypto, consumed_rng) == consumed_before


def test_tampered_token_releases_trusted_reservations_without_publishing_preimage() -> None:
    """Object-identity cleanup survives deep token tampering and permits reuse."""

    runtime, state, crypto = _runtime()
    rng = random.Random(91)
    preparation = runtime.begin(
        owner_rng=rng,
        stable_id="network-runtime-tamper",
        linearization_time=_START,
    )
    identity = preparation.reserve_physical_identity()
    preparation.stage_point(NetworkRuntimePointFamily.DNS_OBSERVATION, "api", {"count": 1})
    transaction = replace(
        network_plan(
            src_ip="10.0.0.10",
            src_port=50_001,
            dst_ip="10.0.0.21",
            dst_port=53,
            protocol="udp",
            service="dns",
            zeek_uid=identity.zeek_uid,
            conn_id=identity.conn_id,
            duration=0.1,
            source_visible_start_time=_START,
            conn_state="SF",
        ),
        stable_id="network-runtime-tamper",
    )
    root = preparation.seal(
        transaction=transaction,
        lifecycle_mode="network",
        materialization_mode=ConnectionMaterializationMode.PHYSICAL,
    )
    state_before = state.materialization_digest()
    rng_before = rng.getstate()
    runtime_before = runtime.state_digest()
    object.__setattr__(root.runtime_token, "overlay_digest", "tampered")

    with pytest.raises(StateError, match="integrity"):
        with runtime.claimed_preparation(root.runtime_token):
            pass

    census = runtime.census()
    assert census.prepared_transactions == 0
    assert census.claimed_transactions == 0
    assert census.reserved_points == 0
    assert runtime.state_digest() == runtime_before
    assert state.materialization_digest() == state_before
    assert rng.getstate() == rng_before
    assert crypto.tls_preparation_census().prepared_overlays == 0
    runtime.set_point(NetworkRuntimePointFamily.DNS_OBSERVATION, "api", {"count": 2})
    assert runtime.get_point(NetworkRuntimePointFamily.DNS_OBSERVATION, "api") == {"count": 2}


def test_token_tamper_after_claim_cannot_break_trusted_no_fail_commit() -> None:
    """Post-claim caller mutation cannot invalidate the trusted commit preimage."""

    runtime, _state, _crypto = _runtime()
    _preparation, root = _physical_preparation(runtime, random.Random(101))
    original_transaction_id = root.runtime_token.transaction_id

    with runtime.claimed_preparation(root.runtime_token) as prepared:
        object.__setattr__(root.runtime_token, "transaction_id", "tampered-after-claim")
        receipt = prepared.commit_no_fail()

    assert receipt.transaction_id == original_transaction_id
    assert runtime.authenticates_preparation_receipt(receipt)
    assert runtime.authenticates_preparation_receipt(receipt, token=root.runtime_token) is False
    assert runtime.last_result is not None
    assert runtime.last_result.transaction.stable_id == original_transaction_id


def test_commit_result_is_frozen_before_tls_seal_and_never_revisited_at_commit() -> None:
    """Caller-owned result/State aliases cannot fail after nested crypto commits."""

    @dataclass(frozen=True)
    class UnsupportedHttp:
        value: str = "late-failure"

        def __deepcopy__(self, memo: dict[int, object]) -> UnsupportedHttp:
            return self

    UnsupportedHttp.__module__ = "evidenceforge.events.spoof"

    runtime, state, crypto = _runtime()
    state_before = state.materialization_digest()
    crypto_before = crypto.census()
    runtime_before = runtime.census()
    rejected = runtime.begin(
        owner_rng=random.Random(103),
        stable_id="network-runtime-result-rejected",
        linearization_time=_START,
    )
    rejected_identity = rejected.reserve_physical_identity()
    rejected.cryptographic_material.public_key_spki(
        "rejected-result-key",
        key_type="ecdsa",
        key_size=256,
    )
    rejected_transaction = _physical_transaction(
        rejected_identity,
        stable_id="network-runtime-result-rejected",
        started_at=_START,
    )
    rejected_result = NetworkConnectionCommitResult(
        transaction=rejected_transaction,
        lifecycle_mode="network",
        effective_dst_ip=rejected_transaction.dst_ip,
    )
    object.__setattr__(rejected_result, "http", UnsupportedHttp())

    with pytest.raises(StateError, match="unsupported value"):
        rejected.seal(
            transaction=rejected_transaction,
            lifecycle_mode="network",
            materialization_mode=ConnectionMaterializationMode.PHYSICAL,
            result=rejected_result,
        )

    assert runtime.census() == runtime_before
    assert state.materialization_digest() == state_before
    assert crypto.census() == crypto_before

    accepted = runtime.begin(
        owner_rng=random.Random(107),
        stable_id="network-runtime-result-accepted",
        linearization_time=_START,
    )
    accepted_identity = accepted.reserve_physical_identity()
    accepted.cryptographic_material.public_key_spki(
        "accepted-result-key",
        key_type="ecdsa",
        key_size=256,
    )
    accepted_transaction = _physical_transaction(
        accepted_identity,
        stable_id="network-runtime-result-accepted",
        started_at=_START,
    )
    root = accepted.seal(
        transaction=accepted_transaction,
        lifecycle_mode="network",
        materialization_mode=ConnectionMaterializationMode.PHYSICAL,
    )
    with runtime.claimed_preparation(root.runtime_token) as prepared:
        object.__setattr__(root.state_plan.transaction, "started_at", object())
        object.__setattr__(root.result, "http", UnsupportedHttp())
        receipt = prepared.commit_no_fail()

    assert runtime.authenticates_preparation_receipt(receipt)
    assert crypto.census().public_keys == 1
    retained = runtime.last_result
    assert retained is not None
    assert retained.http is None
    assert retained.transaction.started_at == _START


def test_duplicate_parallel_and_tampered_claims_cannot_revoke_runtime_owner() -> None:
    """Only the first runtime claim may commit or abort its exact nested capability."""

    runtime, _state, crypto = _runtime()
    rng = random.Random(111)
    preparation = runtime.begin(
        owner_rng=rng,
        stable_id="network-runtime-claim-owner",
        linearization_time=_START,
    )
    identity = preparation.reserve_physical_identity()
    preparation.stage_point(
        NetworkRuntimePointFamily.TLS_SERVER_NAME,
        "10.0.0.20",
        "api.example.test",
    )
    preparation.cryptographic_material.public_key_spki(
        "runtime-claim-owner",
        key_type="ecdsa",
        key_size=256,
    )
    transaction = _physical_transaction(
        identity,
        stable_id="network-runtime-claim-owner",
        started_at=_START,
        duration=1.0,
    )
    root = preparation.seal(
        transaction=transaction,
        lifecycle_mode="network",
        materialization_mode=ConnectionMaterializationMode.PHYSICAL,
    )

    def duplicate_claim() -> None:
        with runtime.claimed_preparation(root.runtime_token):
            pytest.fail("duplicate runtime claim must not enter its body")

    with runtime.claimed_preparation(root.runtime_token) as owner:
        with pytest.raises(StateError, match="already claimed"):
            duplicate_claim()
        with ThreadPoolExecutor(max_workers=1) as pool:
            future = pool.submit(duplicate_claim)
            with pytest.raises(StateError, match="already claimed"):
                future.result(timeout=2.0)

        object.__setattr__(root.runtime_token, "materialization_mode", "tampered")
        assert runtime.cancel_preparation(root.runtime_token) is False
        with pytest.raises(StateError, match="already claimed"):
            duplicate_claim()
        census = runtime.census()
        assert census.prepared_transactions == census.claimed_transactions == 1
        receipt = owner.commit_no_fail()

    assert runtime.authenticates_preparation_receipt(receipt)
    assert not runtime.authenticates_preparation_receipt(receipt, token=root.runtime_token)
    assert (
        runtime.get_point(
            NetworkRuntimePointFamily.TLS_SERVER_NAME,
            "10.0.0.20",
        )
        == "api.example.test"
    )
    assert crypto.census().public_keys == 1
    assert runtime.census().prepared_transactions == 0
    assert runtime.census().claimed_transactions == 0


def test_malformed_token_fields_release_unclaimed_capabilities_exactly() -> None:
    """Wrong enum and datetime tampering cannot strand point or TLS reservations."""

    class EvilStr(str):
        def __repr__(self) -> str:
            raise RuntimeError("caller-controlled repr must not run")

    for field_name, malformed in (
        ("materialization_mode", "physical"),
        ("linearization_time", object()),
        ("overlay_digest", EvilStr("tampered")),
    ):
        runtime, state, crypto = _runtime()
        rng = random.Random(127)
        before = runtime.census()
        state_before = state.materialization_digest()
        rng_before = rng.getstate()
        crypto_before = crypto.census()
        preparation, root = _physical_preparation(runtime, rng)
        preparation_id = preparation.preparation_id
        object.__setattr__(root.runtime_token, field_name, malformed)

        assert not runtime.authenticates_preparation_token(root.runtime_token)
        if field_name in {"materialization_mode", "overlay_digest"}:
            with pytest.raises(StateError, match="malformed fields"):
                runtime.cancel_preparation(root.runtime_token)
        else:
            with pytest.raises(StateError, match="malformed fields"):
                with runtime.claimed_preparation(root.runtime_token):
                    pytest.fail("malformed token must not enter its claim body")

        assert preparation_id > 0
        assert runtime.census() == before
        assert state.materialization_digest() == state_before
        assert rng.getstate() == rng_before
        assert crypto.census() == crypto_before


def test_forged_token_cannot_cancel_original_and_reserved_point_blocks_aba() -> None:
    """Copied capabilities are inert while an exact point reservation blocks ABA."""

    runtime, _state, _crypto = _runtime()
    rng = random.Random(121)
    runtime.set_point(NetworkRuntimePointFamily.NTP_ASSOCIATION, "peer-a", 1)
    preparation = runtime.begin(
        owner_rng=rng,
        stable_id="network-runtime-aba",
        linearization_time=_START,
    )
    identity = preparation.reserve_physical_identity()
    assert preparation.read_point(NetworkRuntimePointFamily.NTP_ASSOCIATION, "peer-a") == 1
    preparation.stage_point(NetworkRuntimePointFamily.NTP_ASSOCIATION, "peer-a", 2)
    transaction = replace(
        network_plan(
            src_ip="10.0.0.10",
            src_port=50_002,
            dst_ip="10.0.0.123",
            dst_port=123,
            protocol="udp",
            service="ntp",
            zeek_uid=identity.zeek_uid,
            conn_id=identity.conn_id,
            duration=0.2,
            source_visible_start_time=_START,
            conn_state="SF",
        ),
        stable_id="network-runtime-aba",
    )
    root = preparation.seal(
        transaction=transaction,
        lifecycle_mode="network",
        materialization_mode=ConnectionMaterializationMode.PHYSICAL,
    )
    forged = replace(root.runtime_token)

    assert runtime.authenticates_preparation_token(forged) is False
    assert runtime.cancel_preparation(forged) is False
    assert runtime.authenticates_preparation_token(root.runtime_token) is True
    with pytest.raises(StateError, match="active preparation"):
        runtime.delete_point(NetworkRuntimePointFamily.NTP_ASSOCIATION, "peer-a")
    assert runtime.cancel_preparation(root.runtime_token) is True
    assert runtime.delete_point(NetworkRuntimePointFamily.NTP_ASSOCIATION, "peer-a") is True
    runtime.set_point(NetworkRuntimePointFamily.NTP_ASSOCIATION, "peer-a", 3)
    assert runtime.get_point(NetworkRuntimePointFamily.NTP_ASSOCIATION, "peer-a") == 3


def test_claim_body_retains_no_runtime_lock_and_disjoint_mutation_progresses() -> None:
    """A claimed transaction does not serialize an unrelated exact-key mutation."""

    runtime, _state, _crypto = _runtime()
    rng = random.Random(191)
    preparation, root = _physical_preparation(runtime, rng)
    assert preparation.preparation_id == root.runtime_token.preparation_id

    with runtime.claimed_preparation(root.runtime_token):
        with ThreadPoolExecutor(max_workers=1) as pool:
            future = pool.submit(
                runtime.set_point,
                NetworkRuntimePointFamily.ICMP_OBSERVATION,
                "other-host",
                _START + timedelta(seconds=5),
            )
            assert future.result(timeout=1.0) is None

    assert runtime.get_point(NetworkRuntimePointFamily.ICMP_OBSERVATION, "other-host") == (
        _START + timedelta(seconds=5)
    )
    assert runtime.census().prepared_transactions == 0


def test_begin_never_holds_runtime_lock_while_acquiring_state_cursor(monkeypatch) -> None:
    """State-cursor creation cannot invert the coordinator's State-to-runtime lock order."""

    runtime, state, _crypto = _runtime()
    original = state.begin_connection_planning

    def begin_with_disjoint_runtime_progress(owner_rng: random.Random):
        with ThreadPoolExecutor(max_workers=1) as pool:
            future = pool.submit(
                runtime.set_point,
                NetworkRuntimePointFamily.ICMP_OBSERVATION,
                "lock-order-sentinel",
                1,
            )
            assert future.result(timeout=1.0) is None
        return original(owner_rng)

    monkeypatch.setattr(state, "begin_connection_planning", begin_with_disjoint_runtime_progress)
    preparation = runtime.begin(
        owner_rng=random.Random(197),
        stable_id="network-runtime-lock-order",
        linearization_time=_START,
    )
    preparation.cancel()
    assert (
        runtime.get_point(
            NetworkRuntimePointFamily.ICMP_OBSERVATION,
            "lock-order-sentinel",
        )
        == 1
    )


def test_compatibility_set_canonicalizes_caller_values_outside_runtime_lock() -> None:
    """Caller-controlled copy hooks cannot invert the runtime's own lock."""

    runtime, _state, _crypto = _runtime()
    progressed = False

    class CallbackValue:
        def __deepcopy__(self, memo: dict[int, object]) -> CallbackValue:
            nonlocal progressed
            with ThreadPoolExecutor(max_workers=1) as pool:
                assert pool.submit(runtime.census).result(timeout=1.0) is not None
            progressed = True
            return self

    before = runtime.census()
    with pytest.raises(ValueError, match="deterministic primitives"):
        runtime.set_point(
            NetworkRuntimePointFamily.ICMP_OBSERVATION,
            "callback-value",
            CallbackValue(),
        )

    assert progressed
    assert runtime.census() == before


def test_custom_timezone_and_equality_alias_keys_are_rejected_before_locking() -> None:
    """Retained points cannot invoke tz callbacks or alias bool/int key identities."""

    runtime, _state, _crypto = _runtime()
    callbacks_outside_lock: list[bool] = []

    class CallbackTimezone(tzinfo):
        def utcoffset(self, value: datetime | None) -> timedelta:
            with ThreadPoolExecutor(max_workers=1) as pool:
                progressed = pool.submit(runtime.census).result(timeout=1.0) is not None
            callbacks_outside_lock.append(progressed)
            return timedelta(0)

        def dst(self, value: datetime | None) -> timedelta:
            return timedelta(0)

        def tzname(self, value: datetime | None) -> str:
            return "CALLBACK"

    before = runtime.census()
    digest_before = runtime.state_digest()
    hostile_time = datetime(2026, 8, 16, 12, 0, tzinfo=CallbackTimezone())
    with pytest.raises(ValueError, match="exact UTC"):
        runtime.set_point(
            NetworkRuntimePointFamily.ICMP_OBSERVATION,
            "custom-tz",
            (hostile_time,),
        )
    with pytest.raises(ValueError, match="booleans"):
        runtime.set_point(NetworkRuntimePointFamily.ICMP_OBSERVATION, True, 1)
    with pytest.raises(ValueError, match="floats"):
        runtime.set_point(NetworkRuntimePointFamily.ICMP_OBSERVATION, 1.0, 1)
    assert runtime.census() == before
    assert runtime.state_digest() == digest_before
    assert all(callbacks_outside_lock)

    runtime.set_point(NetworkRuntimePointFamily.ICMP_OBSERVATION, 1, "canonical")
    comparison, _state, _crypto = _runtime()
    comparison.set_point(NetworkRuntimePointFamily.ICMP_OBSERVATION, 1, "canonical")
    assert runtime.state_digest() == comparison.state_digest()


def test_tls_seal_conflict_terminally_cleans_runtime_cursor_and_nested_overlay() -> None:
    """A fallible nested TLS seal cannot strand an open runtime or sealed cursor."""

    runtime, state, crypto = _runtime()
    state_before = state.materialization_digest()
    crypto_before = crypto.census()
    first_rng = random.Random(199)
    second_rng = random.Random(211)
    first_rng_before = first_rng.getstate()
    second_rng_before = second_rng.getstate()

    first = runtime.begin(
        owner_rng=first_rng,
        stable_id="network-runtime-tls-first",
        linearization_time=_START,
    )
    first_identity = first.reserve_physical_identity()
    first.cryptographic_material.public_key_spki(
        "shared-prepared-key",
        key_type="ecdsa",
        key_size=256,
    )
    first_root = first.seal(
        transaction=_physical_transaction(
            first_identity,
            stable_id="network-runtime-tls-first",
            started_at=_START,
        ),
        lifecycle_mode="network",
        materialization_mode=ConnectionMaterializationMode.PHYSICAL,
    )

    second = runtime.begin(
        owner_rng=second_rng,
        stable_id="network-runtime-tls-second",
        linearization_time=_START + timedelta(seconds=1),
    )
    second_identity = second.reserve_physical_identity()
    second.cryptographic_material.public_key_spki(
        "shared-prepared-key",
        key_type="ecdsa",
        key_size=256,
    )
    with pytest.raises(StateError, match="is reserved"):
        second.seal(
            transaction=_physical_transaction(
                second_identity,
                stable_id="network-runtime-tls-second",
                started_at=_START + timedelta(seconds=1),
                ordinal=1,
            ),
            lifecycle_mode="network",
            materialization_mode=ConnectionMaterializationMode.PHYSICAL,
        )

    census = runtime.census()
    assert census.open_preparations == 0
    assert census.prepared_transactions == 1
    assert census.reserved_points == 0
    assert crypto.census().prepared_overlays == 1
    assert crypto.census().reserved_points == 1
    with pytest.raises(StateError, match="cancelled"):
        second.cancel()
    assert state.materialization_digest() == state_before
    assert first_rng.getstate() == first_rng_before
    assert second_rng.getstate() == second_rng_before

    assert runtime.cancel_preparation(first_root.runtime_token)
    assert runtime.census().prepared_transactions == 0
    assert crypto.census() == crypto_before


def test_watermark_is_fenced_then_expires_and_prunes_bounded_tombstone() -> None:
    """Watermark work cannot cross a preparation and preserves bounded ABA history."""

    runtime, _state, _crypto = _runtime()
    runtime.set_point(
        NetworkRuntimePointFamily.DIRECT_DNS_TTL,
        "api.example.test",
        "203.0.113.10",
        expires_at=_START + timedelta(seconds=5),
    )
    preparation = runtime.begin(
        owner_rng=random.Random(211),
        stable_id="network-runtime-watermark",
        linearization_time=_START + timedelta(seconds=10),
    )
    with pytest.raises(StateError, match="fenced"):
        runtime.advance_watermark_page(_START + timedelta(seconds=10))
    preparation.cancel()

    expired = runtime.advance_watermark_page(_START + timedelta(seconds=10), limit=1)
    assert expired.processed == 1
    assert expired.has_more is False
    assert expired.census.live_points == 0
    assert expired.census.tombstone_points == 1
    pruned = runtime.advance_watermark_page(_START + timedelta(days=2), limit=1)
    assert pruned.processed == 1
    assert pruned.has_more is False
    assert pruned.census.tombstone_points == 0


def test_future_delete_retention_anchors_to_publication_and_terminal_drain_is_reachable() -> None:
    """Delete ABA history starts at logical publication and drains by the final window."""

    state = StateManager()
    crypto = CryptographicMaterialRegistry()
    runtime = NetworkTransactionRuntime(
        state_manager=state,
        cryptographic_material=crypto,
        window_start=_START,
        window_end=_START + timedelta(days=4),
    )
    family = NetworkRuntimePointFamily.DIRECT_DNS_TTL
    runtime.set_point(family, "future.example.test", "203.0.113.40")
    preparation = runtime.begin(
        owner_rng=random.Random(219),
        stable_id="network-runtime-future-delete",
        linearization_time=_START + timedelta(hours=30),
    )
    identity = preparation.reserve_physical_identity()
    preparation.delete_point(family, "future.example.test")
    root = preparation.seal(
        transaction=_physical_transaction(
            identity,
            stable_id="network-runtime-future-delete",
            started_at=_START + timedelta(hours=30),
        ),
        lifecycle_mode="network",
        materialization_mode=ConnectionMaterializationMode.PHYSICAL,
    )
    _commit_runtime(runtime, root)

    assert runtime.advance_watermark_page(_START + timedelta(hours=53)).processed == 0
    assert runtime.census().tombstone_points == 1
    assert runtime.advance_watermark_page(_START + timedelta(hours=54)).processed == 1
    assert runtime.census().tombstone_points == 0

    late = NetworkTransactionRuntime(
        state_manager=StateManager(),
        cryptographic_material=CryptographicMaterialRegistry(),
        window_start=_START,
        window_end=_START + timedelta(hours=1),
    )
    late.set_point(
        family,
        "late.example.test",
        "203.0.113.41",
        expires_at=_START + timedelta(hours=1, seconds=-1),
    )
    page = late.advance_watermark_page(_START + timedelta(hours=1), limit=1)
    assert page.has_more
    terminal = late.advance_watermark_page(_START + timedelta(hours=1), limit=1)
    assert not terminal.has_more
    assert terminal.census.live_points == terminal.census.tombstone_points == 0
    assert terminal.census.active_deadlines == terminal.census.expiry_backing == 0


def test_watermark_page_uses_indexed_minima_without_scanning_open_reservations() -> None:
    """One bounded page does not enumerate unrelated preparations or point reservations."""

    class NoScanDict(dict[object, object]):
        def __iter__(self):
            raise AssertionError("watermark must not scan transient dictionaries")

        def items(self):
            raise AssertionError("watermark must not scan transient dictionaries")

        def keys(self):
            raise AssertionError("watermark must not scan transient dictionaries")

        def values(self):
            raise AssertionError("watermark must not scan transient dictionaries")

    runtime, _state, _crypto = _runtime()
    preparations: list[NetworkTransactionPreparation] = []
    for ordinal in range(32):
        preparation = runtime.begin(
            owner_rng=random.Random(500 + ordinal),
            stable_id=f"network-runtime-indexed-fence-{ordinal}",
            linearization_time=_START + timedelta(hours=1, microseconds=ordinal),
        )
        preparation.read_point(
            NetworkRuntimePointFamily.DNS_OBSERVATION,
            f"host-{ordinal}",
        )
        preparations.append(preparation)

    runtime._open_preparations = NoScanDict(runtime._open_preparations)
    runtime._reserved_points = NoScanDict(runtime._reserved_points)
    page = runtime.advance_watermark_page(_START + timedelta(minutes=30), limit=1)
    assert page.processed == 0
    assert not page.has_more
    for preparation in preparations:
        preparation.cancel()


def test_tombstone_retention_requires_an_exact_representable_timedelta() -> None:
    """Malformed retention policy cannot create partial or indigestible tombstones."""

    class RetentionSubclass(timedelta):
        pass

    for retention in (RetentionSubclass(days=1), timedelta.max):
        with pytest.raises(ValueError, match="tombstone retention"):
            NetworkTransactionRuntime(
                state_manager=StateManager(),
                cryptographic_material=CryptographicMaterialRegistry(),
                window_start=_START,
                window_end=_START + timedelta(days=2),
                tombstone_retention=retention,
            )


def test_watermark_cannot_overtake_a_staged_point_expiry() -> None:
    """Seal revalidates trusted deadlines after a lower watermark page advances."""

    runtime, state, crypto = _runtime()
    rng = random.Random(223)
    state_before = state.materialization_digest()
    crypto_before = crypto.census()
    preparation = runtime.begin(
        owner_rng=rng,
        stable_id="network-runtime-expiry-fence",
        linearization_time=_START + timedelta(seconds=10),
    )
    identity = preparation.reserve_physical_identity()
    preparation.stage_point(
        NetworkRuntimePointFamily.DIRECT_DNS_TTL,
        "expiry.example.test",
        "203.0.113.20",
        expires_at=_START + timedelta(seconds=11),
    )
    point_key = (NetworkRuntimePointFamily.DIRECT_DNS_TTL, "expiry.example.test")
    preparation._mutations[point_key] = replace(
        preparation._mutations[point_key],
        expires_at=_START + timedelta(seconds=5),
    )
    page = runtime.advance_watermark_page(_START + timedelta(seconds=9))
    assert page.has_more is False

    with pytest.raises(StateError, match="expiry was overtaken"):
        preparation.seal(
            transaction=_physical_transaction(
                identity,
                stable_id="network-runtime-expiry-fence",
                started_at=_START + timedelta(seconds=10),
            ),
            lifecycle_mode="network",
            materialization_mode=ConnectionMaterializationMode.PHYSICAL,
        )

    assert (
        runtime.get_point(
            NetworkRuntimePointFamily.DIRECT_DNS_TTL,
            "expiry.example.test",
        )
        is None
    )
    assert runtime.census().open_preparations == 0
    assert runtime.census().reserved_points == 0
    assert state.materialization_digest() == state_before
    assert crypto.census() == crypto_before


def test_staged_point_expiry_must_follow_the_final_transaction_start() -> None:
    """An early planner anchor cannot publish a point already expired at occurrence time."""

    runtime, state, crypto = _runtime()
    rng = random.Random(229)
    before = runtime.census()
    state_before = state.materialization_digest()
    crypto_before = crypto.census()
    preparation = runtime.begin(
        owner_rng=rng,
        stable_id="network-runtime-late-transaction",
        linearization_time=_START,
    )
    identity = preparation.reserve_physical_identity()
    preparation.stage_point(
        NetworkRuntimePointFamily.DIRECT_DNS_TTL,
        "late.example.test",
        "203.0.113.30",
        expires_at=_START + timedelta(seconds=5),
    )

    with pytest.raises(StateError, match="expiry was overtaken"):
        preparation.seal(
            transaction=_physical_transaction(
                identity,
                stable_id="network-runtime-late-transaction",
                started_at=_START + timedelta(seconds=10),
            ),
            lifecycle_mode="network",
            materialization_mode=ConnectionMaterializationMode.PHYSICAL,
        )

    assert runtime.census() == before
    assert state.materialization_digest() == state_before
    assert crypto.census() == crypto_before


def test_application_child_reserves_no_identity_or_connection_counter() -> None:
    """Application children stage parent accounting without phantom identity draws."""

    runtime, state, _crypto = _runtime()
    rng = random.Random(271)
    parent = _materialize_parent(runtime, state, rng)
    state_before = state.materialization_digest()
    rng_before = rng.getstate()
    _preparation, child = _application_child_preparation(
        runtime,
        rng,
        parent,
        ordinal=1,
    )

    assert child.state_plan.materializes_connection is False
    assert child.state_plan.physical_transport_id == parent.transaction.stable_id
    assert (
        child.runtime_token.materialization_mode is ConnectionMaterializationMode.APPLICATION_CHILD
    )
    assert child.runtime_token.lifecycle_mode == "application_child"
    assert runtime.authenticates_preparation_root(child)
    assert state.materialization_digest() == state_before
    assert rng.getstate() == rng_before
    assert runtime.cancel_preparation(child.runtime_token) is True
    assert state.materialization_digest() == state_before
    assert rng.getstate() == rng_before


def test_application_child_rejects_runtime_points_and_tls_material_exactly() -> None:
    """Application children may stage parent accounting but no physical-root state."""

    runtime, state, crypto = _runtime()
    rng = random.Random(277)
    parent = _materialize_parent(runtime, state, rng)
    runtime_before = runtime.census()
    runtime_digest_before = runtime.state_digest()
    state_before = state.materialization_digest()
    rng_before = rng.getstate()
    crypto_before = crypto.census()

    point_child = runtime.begin(
        owner_rng=rng,
        stable_id="network-runtime-child-point-delta",
        linearization_time=parent.transaction.started_at + timedelta(seconds=1),
    )
    point_child.stage_point(
        NetworkRuntimePointFamily.RECENT_TUPLE,
        "child-point",
        1,
    )
    with pytest.raises(StateError, match="root-local runtime points"):
        point_child.seal(
            transaction=_application_child_transaction(
                parent,
                stable_id="network-runtime-child-point-delta",
                offset_seconds=1,
            ),
            lifecycle_mode="application_child",
            materialization_mode=ConnectionMaterializationMode.APPLICATION_CHILD,
        )

    tls_child = runtime.begin(
        owner_rng=rng,
        stable_id="network-runtime-child-tls-delta",
        linearization_time=parent.transaction.started_at + timedelta(seconds=2),
    )
    tls_child.cryptographic_material.public_key_spki(
        "application-child-key",
        key_type="ecdsa",
        key_size=256,
    )
    with pytest.raises(StateError, match="root-local TLS material"):
        tls_child.seal(
            transaction=_application_child_transaction(
                parent,
                stable_id="network-runtime-child-tls-delta",
                offset_seconds=2,
            ),
            lifecycle_mode="application_child",
            materialization_mode=ConnectionMaterializationMode.APPLICATION_CHILD,
        )

    assert runtime.census() == runtime_before
    assert runtime.state_digest() == runtime_digest_before
    assert state.materialization_digest() == state_before
    assert rng.getstate() == rng_before
    assert crypto.census() == crypto_before


def test_physical_requires_exactly_one_identity_and_child_forbids_one() -> None:
    """Typed materialization mode enforces one physical identity and zero child identities."""

    runtime, state, _crypto = _runtime()
    rng = random.Random(313)
    parent = _materialize_parent(runtime, state, rng)
    started_at = _START + timedelta(seconds=1)

    missing = runtime.begin(
        owner_rng=rng,
        stable_id="network-runtime-missing-identity",
        linearization_time=started_at,
    )
    missing_transaction = replace(
        parent.transaction,
        stable_id="network-runtime-missing-identity",
        conn_id="conn-missing",
        zeek_uid="Cmissing",
        application_layer_only=False,
    )
    with pytest.raises(StateError, match="requires reserved identity"):
        missing.seal(
            transaction=missing_transaction,
            lifecycle_mode="network",
            materialization_mode=ConnectionMaterializationMode.PHYSICAL,
        )
    with pytest.raises(StateError, match="cancelled"):
        missing.cancel()

    child_preparation = runtime.begin(
        owner_rng=rng,
        stable_id="network-runtime-child-with-identity",
        linearization_time=started_at,
    )
    child_preparation.reserve_physical_identity()
    child_transaction = replace(
        parent.transaction,
        stable_id="network-runtime-child-with-identity",
        phase_times=(
            ("application_start", started_at),
            ("application_close", started_at + timedelta(milliseconds=250)),
        ),
        started_at=started_at,
        closed_at=started_at + timedelta(milliseconds=250),
        duration=0.25,
        application_layer_only=True,
    )
    with pytest.raises(StateError, match="cannot reserve a new identity"):
        child_preparation.seal(
            transaction=child_transaction,
            lifecycle_mode="application_child",
            materialization_mode=ConnectionMaterializationMode.APPLICATION_CHILD,
        )
    with pytest.raises(StateError, match="cancelled"):
        child_preparation.cancel()


def test_committed_digest_is_deterministic_and_last_result_is_copy_isolated() -> None:
    """Random authority proofs never enter committed state digests or retained aliases."""

    runtimes: list[NetworkTransactionRuntime] = []
    receipts: list[object] = []
    for _ordinal in range(2):
        runtime, _state, _crypto = _runtime()
        _preparation, root = _physical_preparation(runtime, random.Random(331))
        receipts.append(_commit_runtime(runtime, root))
        runtimes.append(runtime)

    assert runtimes[0].state_digest() == runtimes[1].state_digest()
    assert receipts[0].receipt_token != receipts[1].receipt_token
    result = runtimes[0].last_result
    assert result is not None
    digest_before = runtimes[0].state_digest()
    object.__setattr__(result, "effective_dst_ip", "198.51.100.250")
    retained = runtimes[0].last_result
    assert retained is not None
    assert retained.effective_dst_ip == "10.0.0.20"
    assert runtimes[0].state_digest() == digest_before


def test_registry_digest_is_independent_of_disjoint_commit_and_expiry_page_order() -> None:
    """Worker scheduling and bounded page size cannot change canonical runtime truth."""

    def committed(order: tuple[int, int]) -> NetworkTransactionRuntime:
        runtime, _state, _crypto = _runtime()
        roots: list[PreparedNetworkTransactionRoot] = []
        for ordinal in range(2):
            _preparation, root = _physical_preparation(
                runtime,
                random.Random(401 + ordinal),
                ordinal=ordinal,
            )
            roots.append(root)
        # The roots themselves have no point mutations, so add disjoint canonical
        # state through the exact compatibility path before opposite-order commits.
        runtime.set_point(NetworkRuntimePointFamily.DNS_OBSERVATION, "a", 1)
        runtime.set_point(NetworkRuntimePointFamily.DNS_OBSERVATION, "b", 2)
        for ordinal in order:
            _commit_runtime(runtime, roots[ordinal])
        return runtime

    forward = committed((0, 1))
    reverse = committed((1, 0))
    assert forward.state_digest() == reverse.state_digest()

    page_one, _state, _crypto = _runtime()
    page_two, _state, _crypto = _runtime()
    for runtime in (page_one, page_two):
        runtime.set_point(
            NetworkRuntimePointFamily.DIRECT_DNS_TTL,
            "a.example.test",
            "203.0.113.1",
            expires_at=_START + timedelta(seconds=1),
        )
        runtime.set_point(
            NetworkRuntimePointFamily.DIRECT_DNS_TTL,
            "b.example.test",
            "203.0.113.2",
            expires_at=_START + timedelta(seconds=1),
        )
    while page_one.advance_watermark_page(_START + timedelta(days=2), limit=1).has_more:
        pass
    assert not page_two.advance_watermark_page(
        _START + timedelta(days=2),
        limit=8,
    ).has_more
    assert page_one.census() == page_two.census()
    assert page_one.state_digest() == page_two.state_digest()


def test_receipt_authentication_is_total_for_malformed_nested_fields() -> None:
    """Malformed caller-owned receipt/token fields return False rather than raising."""

    runtime, _state, _crypto = _runtime()
    _preparation, root = _physical_preparation(runtime, random.Random(337))
    receipt = _commit_runtime(runtime, root)
    malformed_receipt = replace(receipt)
    object.__setattr__(malformed_receipt, "cryptographic_receipt", object())
    assert runtime.authenticates_preparation_receipt(malformed_receipt) is False

    malformed_count = replace(receipt)
    object.__setattr__(malformed_count, "committed_point_mutations", object())
    assert runtime.authenticates_preparation_receipt(malformed_count) is False

    class EvilStr(str):
        def __repr__(self) -> str:
            raise RuntimeError("nested caller-controlled repr must not run")

    malformed_crypto = replace(receipt.cryptographic_receipt)
    object.__setattr__(malformed_crypto, "_integrity_token", EvilStr("tampered"))
    malformed_nested = replace(receipt, cryptographic_receipt=malformed_crypto)
    assert runtime.authenticates_preparation_receipt(malformed_nested) is False

    object.__setattr__(root.runtime_token, "linearization_time", object())
    assert (
        runtime.authenticates_preparation_receipt(
            receipt,
            token=root.runtime_token,
        )
        is False
    )


def test_deadline_backing_is_bounded_for_repeated_point_replacement() -> None:
    """Non-expiring points add no heap rows and finite replacements retain one row."""

    runtime, _state, _crypto = _runtime()
    for ordinal in range(1_000):
        runtime.set_point(NetworkRuntimePointFamily.RECENT_TUPLE, "peer", ordinal)
    census = runtime.census()
    assert census.live_points == 1
    assert census.active_deadlines == 0
    assert census.expiry_backing == 0

    for ordinal in range(1_000):
        runtime.set_point(
            NetworkRuntimePointFamily.RECENT_TUPLE,
            "peer",
            ordinal,
            expires_at=_START + timedelta(hours=1, microseconds=ordinal),
        )
    census = runtime.census()
    assert census.live_points == 1
    assert census.active_deadlines == 1
    assert census.expiry_backing == 1

    expired = runtime.advance_watermark_page(_START + timedelta(hours=2))
    assert expired.processed == 1
    assert expired.census.live_points == 0
    assert expired.census.tombstone_points == 1
    assert expired.census.active_deadlines == 1


def test_unsupported_retained_key_and_value_types_fail_before_mutation() -> None:
    """Address-bearing repr fallbacks cannot enter canonical retained state."""

    class UnsupportedHashable:
        pass

    @dataclass(frozen=True)
    class UnsupportedDataclass:
        generation: int

    runtime, _state, _crypto = _runtime()
    census_before = runtime.census()
    digest_before = runtime.state_digest()

    with pytest.raises(ValueError, match="deterministic primitives"):
        runtime.set_point(
            NetworkRuntimePointFamily.DNS_OBSERVATION,
            UnsupportedHashable(),
            "value",
        )
    with pytest.raises(ValueError, match="deterministic primitives"):
        runtime.set_point(
            NetworkRuntimePointFamily.DNS_OBSERVATION,
            "key",
            UnsupportedHashable(),
        )
    with pytest.raises(ValueError, match="deterministic primitives"):
        runtime.set_point(
            NetworkRuntimePointFamily.DNS_OBSERVATION,
            "dataclass-key",
            UnsupportedDataclass(1),
        )

    preparation = runtime.begin(
        owner_rng=random.Random(997),
        stable_id="network-runtime-unsupported-value",
        linearization_time=_START,
    )
    with pytest.raises(ValueError, match="deterministic primitives"):
        preparation.stage_point(
            NetworkRuntimePointFamily.DNS_OBSERVATION,
            "prepared-key",
            UnsupportedHashable(),
        )
    assert runtime.census().reserved_points == 0
    preparation.cancel()

    assert runtime.census() == census_before
    assert runtime.state_digest() == digest_before


def test_invalid_family_time_and_enum_inputs_are_preflight_neutral() -> None:
    """Malformed point metadata fails before reservations, counters, or digests move."""

    class UnsupportedEnum(Enum):
        VALUE = "value"

    runtime, _state, _crypto = _runtime()
    before = runtime.census()
    digest_before = runtime.state_digest()
    for operation in (
        lambda: runtime.set_point("not-a-family", "key", 1),
        lambda: runtime.get_point("not-a-family", "key"),
        lambda: runtime.delete_point("not-a-family", "key"),
        lambda: runtime.set_point(
            NetworkRuntimePointFamily.DNS_OBSERVATION,
            UnsupportedEnum.VALUE,
            1,
        ),
        lambda: runtime.set_point(
            NetworkRuntimePointFamily.DNS_OBSERVATION,
            "key",
            UnsupportedEnum.VALUE,
        ),
    ):
        with pytest.raises(ValueError):
            operation()
        assert runtime.census() == before
        assert runtime.state_digest() == digest_before

    preparation = runtime.begin(
        owner_rng=random.Random(1009),
        stable_id="network-runtime-invalid-point-metadata",
        linearization_time=_START,
    )
    open_census = runtime.census()
    for operation in (
        lambda: preparation.read_point("not-a-family", "key"),
        lambda: preparation.stage_point("not-a-family", "key", 1),
        lambda: preparation.delete_point("not-a-family", "key"),
        lambda: preparation.read_point(
            NetworkRuntimePointFamily.DNS_OBSERVATION,
            "key",
            at=object(),
        ),
    ):
        with pytest.raises(ValueError):
            operation()
        assert runtime.census() == open_census
    preparation.cancel()

    assert runtime.census() == before
    assert runtime.state_digest() == digest_before


def test_point_batch_open_and_sealed_cancel_restore_every_authority() -> None:
    """Point-only cancellation is neutral to runtime, State, crypto, and caller RNG."""

    runtime, state, crypto = _runtime()
    rng = random.Random(1103)
    before = _authority_snapshot(runtime, state, crypto, rng)

    open_batch = runtime.begin_point_batch(
        stable_id="point-batch-open-cancel",
        linearization_time=_START,
    )
    open_batch.stage_point(
        NetworkRuntimePointFamily.DNS_OBSERVATION,
        "open-a",
        (1, 2),
        expires_at=_START + timedelta(hours=1),
    )
    open_batch.stage_point(
        NetworkRuntimePointFamily.TLS_SERVER_NAME,
        "open-b",
        "api.example.test",
        expires_at=_START + timedelta(hours=1),
    )
    assert runtime.census().open_preparations == 1
    assert runtime.census().reserved_points == 2
    open_batch.cancel()
    assert _authority_snapshot(runtime, state, crypto, rng) == before

    sealed_batch = runtime.begin_point_batch(
        stable_id="point-batch-sealed-cancel",
        linearization_time=_START,
    )
    sealed_batch.stage_point(
        NetworkRuntimePointFamily.DNS_OBSERVATION,
        "sealed-a",
        (3, 4),
        expires_at=_START + timedelta(hours=1),
    )
    token = sealed_batch.seal()
    assert runtime.authenticates_point_batch_token(
        token,
        expected_stable_id="point-batch-sealed-cancel",
    )
    assert runtime.cancel_point_batch(token)
    assert not runtime.cancel_point_batch(token)
    assert _authority_snapshot(runtime, state, crypto, rng) == before


def test_empty_point_batch_seal_fails_without_fence_or_authority_residue() -> None:
    """An empty batch cannot mint a signed no-op publication receipt."""

    runtime, state, crypto = _runtime()
    rng = random.Random(1105)
    before = _authority_snapshot(runtime, state, crypto, rng)
    batch = runtime.begin_point_batch(
        stable_id="point-batch-empty-rejected",
        linearization_time=_START,
    )

    with pytest.raises(StateError, match="at least one mutation"):
        batch.seal()

    assert _authority_snapshot(runtime, state, crypto, rng) == before
    assert runtime.census().preparation_fences == 0


def test_read_only_point_batch_seal_releases_exact_reservation_and_deadline() -> None:
    """A read-only overlay fails closed and releases its live-point reservation."""

    runtime, state, crypto = _runtime()
    rng = random.Random(1107)
    runtime.set_point(
        NetworkRuntimePointFamily.DIRECT_DNS_TTL,
        "read-only.example.test",
        "203.0.113.70",
        expires_at=_START + timedelta(hours=1),
    )
    before = _authority_snapshot(runtime, state, crypto, rng)
    batch = runtime.begin_point_batch(
        stable_id="point-batch-read-only-rejected",
        linearization_time=_START,
    )
    assert (
        batch.read_point(
            NetworkRuntimePointFamily.DIRECT_DNS_TTL,
            "read-only.example.test",
        )
        == "203.0.113.70"
    )
    assert runtime.census().reserved_points == 1
    assert runtime.census().reserved_deadlines == 1

    with pytest.raises(StateError, match="at least one mutation"):
        batch.seal()

    assert _authority_snapshot(runtime, state, crypto, rng) == before
    assert runtime.census().preparation_fences == 0
    assert runtime.census().reserved_points == 0
    assert runtime.census().reserved_deadlines == 0
    runtime.set_point(
        NetworkRuntimePointFamily.DIRECT_DNS_TTL,
        "read-only.example.test",
        "203.0.113.71",
        expires_at=_START + timedelta(hours=1),
    )


def test_point_batch_commit_atomically_publishes_two_points_and_signed_receipt() -> None:
    """One claim publishes the frozen two-point overlay without touching other authorities."""

    runtime, state, crypto = _runtime()
    rng = random.Random(1109)
    state_before = state.materialization_digest()
    state_version_before = state.materialization_version
    crypto_before = (crypto.state_digest(), crypto.census(), crypto.tls_preparation_census())
    rng_before = rng.getstate()
    batch = runtime.begin_point_batch(
        stable_id="point-batch-two-point-commit",
        linearization_time=_START,
    )
    mutable_value = {"ports": [88, 464]}
    batch.stage_point(
        NetworkRuntimePointFamily.DNS_OBSERVATION,
        "dc-a",
        mutable_value,
        expires_at=_START + timedelta(minutes=30),
    )
    batch.stage_point(
        NetworkRuntimePointFamily.TLS_CLIENT_SERVER_PAIR,
        ("client-a", "dc-a"),
        (_START, _START + timedelta(seconds=1)),
        expires_at=_START + timedelta(minutes=30),
    )
    token = batch.seal()
    mutable_value["ports"].append(749)

    assert runtime.get_point(NetworkRuntimePointFamily.DNS_OBSERVATION, "dc-a") is None
    constructed = NetworkPointBatchPreparedCommit(runtime)
    with pytest.raises(StateError, match="stale or foreign"):
        constructed.commit_no_fail()

    with runtime.claimed_point_batch(token) as prepared:
        assert runtime.get_point(NetworkRuntimePointFamily.DNS_OBSERVATION, "dc-a") is None
        with pytest.raises(StateError, match="active preparation"):
            runtime.set_point(NetworkRuntimePointFamily.DNS_OBSERVATION, "dc-a", "conflict")
        with ThreadPoolExecutor(max_workers=1) as pool:
            disjoint = pool.submit(
                runtime.set_point,
                NetworkRuntimePointFamily.NTP_PARSER,
                "server-a",
                "ntp",
            )
            disjoint.result(timeout=2.0)
        receipt = prepared.commit_no_fail()
        with pytest.raises(StateError, match="already committed"):
            prepared.commit_no_fail()

    assert runtime.authenticates_point_batch_receipt(receipt)
    assert runtime.authenticates_point_batch_receipt(receipt, token=token)
    assert receipt.committed_point_mutations == token.point_mutations == 2
    assert runtime.get_point(NetworkRuntimePointFamily.DNS_OBSERVATION, "dc-a") == {
        "ports": [88, 464]
    }
    assert runtime.get_point(
        NetworkRuntimePointFamily.TLS_CLIENT_SERVER_PAIR,
        ("client-a", "dc-a"),
    ) == (_START, _START + timedelta(seconds=1))
    assert runtime.get_point(NetworkRuntimePointFamily.NTP_PARSER, "server-a") == "ntp"
    assert state.materialization_digest() == state_before
    assert state.materialization_version == state_version_before
    assert (
        crypto.state_digest(),
        crypto.census(),
        crypto.tls_preparation_census(),
    ) == crypto_before
    assert rng.getstate() == rng_before
    assert runtime.census().prepared_transactions == 0
    assert runtime.census().claimed_transactions == 0
    assert runtime.census().reserved_points == 0
    with pytest.raises(StateError, match="no longer active"):
        prepared.commit_no_fail()


@pytest.mark.parametrize("claimant_commits", [False, True])
def test_point_batch_commit_is_bound_to_its_claiming_thread(claimant_commits: bool) -> None:
    """A foreign thread cannot publish or consume the claimant's exact capability."""

    runtime, state, crypto = _runtime()
    rng = random.Random(1111)
    before = _authority_snapshot(runtime, state, crypto, rng)
    batch = runtime.begin_point_batch(
        stable_id=f"point-batch-thread-owner-{claimant_commits}",
        linearization_time=_START,
    )
    batch.stage_point(
        NetworkRuntimePointFamily.AD_SRV_DISCOVERY,
        ("10.0.1.50", "corp.example", 496236, "_ldap._tcp.corp.example"),
        _START,
        expires_at=_START + timedelta(hours=1),
    )
    token = batch.seal()

    with runtime.claimed_point_batch(token) as prepared:
        claimed_census = runtime.census()
        with ThreadPoolExecutor(max_workers=1) as pool:
            foreign_commit = pool.submit(prepared.commit_no_fail)
            with pytest.raises(StateError, match="claiming thread"):
                foreign_commit.result(timeout=2.0)

        assert not prepared.committed
        assert runtime.census() == claimed_census
        assert (
            runtime.get_point(
                NetworkRuntimePointFamily.AD_SRV_DISCOVERY,
                ("10.0.1.50", "corp.example", 496236, "_ldap._tcp.corp.example"),
            )
            is None
        )
        if claimant_commits:
            receipt = prepared.commit_no_fail()

    if claimant_commits:
        assert prepared.committed
        assert runtime.authenticates_point_batch_receipt(receipt, token=token)
        assert (
            runtime.get_point(
                NetworkRuntimePointFamily.AD_SRV_DISCOVERY,
                ("10.0.1.50", "corp.example", 496236, "_ldap._tcp.corp.example"),
            )
            == _START
        )
        census = runtime.census()
        assert census.prepared_transactions == 0
        assert census.claimed_transactions == 0
        assert census.reserved_points == 0
        assert census.preparation_fences == 0
        assert census.reserved_deadlines == 0
    else:
        assert _authority_snapshot(runtime, state, crypto, rng) == before


def test_point_batch_abandoned_and_exceptional_claims_cancel_without_publication() -> None:
    """Every uncommitted claim exit releases its token, fence, and reservations."""

    for raise_from_body in (False, True):
        runtime, state, crypto = _runtime()
        rng = random.Random(1117)
        before = _authority_snapshot(runtime, state, crypto, rng)
        batch = runtime.begin_point_batch(
            stable_id=f"point-batch-abandon-{raise_from_body}",
            linearization_time=_START,
        )
        batch.stage_point(
            NetworkRuntimePointFamily.DIRECT_DNS_TTL,
            "abandoned.example.test",
            "203.0.113.40",
            expires_at=_START + timedelta(hours=1),
        )
        token = batch.seal()

        if raise_from_body:
            with pytest.raises(RuntimeError, match="abort occurrence"):
                with runtime.claimed_point_batch(token):
                    raise RuntimeError("abort occurrence")
        else:
            with runtime.claimed_point_batch(token):
                pass

        assert _authority_snapshot(runtime, state, crypto, rng) == before
        assert not runtime.authenticates_point_batch_token(token)
        assert (
            runtime.get_point(
                NetworkRuntimePointFamily.DIRECT_DNS_TTL,
                "abandoned.example.test",
            )
            is None
        )


def test_point_batch_malformed_overlay_and_token_fail_closed_without_partial_state() -> None:
    """One invalid mutation or an original-token tamper releases the entire batch."""

    runtime, state, crypto = _runtime()
    rng = random.Random(1123)
    before = _authority_snapshot(runtime, state, crypto, rng)
    malformed = runtime.begin_point_batch(
        stable_id="point-batch-malformed-overlay",
        linearization_time=_START,
    )
    malformed.stage_point(
        NetworkRuntimePointFamily.DNS_OBSERVATION,
        "valid-before-invalid",
        1,
        expires_at=_START + timedelta(minutes=10),
    )
    malformed.stage_point(
        NetworkRuntimePointFamily.DNS_OBSERVATION,
        "invalid",
        2,
        expires_at=_START + timedelta(minutes=10),
    )
    invalid_mutation = malformed._mutations[(NetworkRuntimePointFamily.DNS_OBSERVATION, "invalid")]
    object.__setattr__(invalid_mutation, "value", object())

    with pytest.raises(ValueError, match="deterministic primitives"):
        malformed.seal()

    assert _authority_snapshot(runtime, state, crypto, rng) == before
    assert (
        runtime.get_point(
            NetworkRuntimePointFamily.DNS_OBSERVATION,
            "valid-before-invalid",
        )
        is None
    )

    tampered = runtime.begin_point_batch(
        stable_id="point-batch-tampered-token",
        linearization_time=_START,
    )
    tampered.stage_point(
        NetworkRuntimePointFamily.DNS_OBSERVATION,
        "tampered",
        3,
        expires_at=_START + timedelta(minutes=10),
    )
    token = tampered.seal()
    object.__setattr__(token, "overlay_digest", object())
    assert not runtime.authenticates_point_batch_token(token)
    with pytest.raises(StateError, match="malformed fields"):
        with runtime.claimed_point_batch(token):
            pytest.fail("a malformed token must not enter its claim body")

    assert _authority_snapshot(runtime, state, crypto, rng) == before
    runtime.set_point(NetworkRuntimePointFamily.DNS_OBSERVATION, "tampered", 4)
    assert runtime.get_point(NetworkRuntimePointFamily.DNS_OBSERVATION, "tampered") == 4


def test_point_batch_duplicate_reserved_and_stale_mutations_reject_neutrally() -> None:
    """Duplicate, conflicting, and overtaken updates never publish a partial overlay."""

    runtime, state, crypto = _runtime()
    rng = random.Random(1129)
    before = _authority_snapshot(runtime, state, crypto, rng)
    duplicate = runtime.begin_point_batch(
        stable_id="point-batch-duplicate",
        linearization_time=_START,
    )
    duplicate.stage_point(
        NetworkRuntimePointFamily.RECENT_TUPLE,
        "tuple-a",
        1,
        expires_at=_START + timedelta(minutes=5),
    )
    with pytest.raises(StateError, match="duplicate mutation"):
        duplicate.stage_point(
            NetworkRuntimePointFamily.RECENT_TUPLE,
            "tuple-a",
            2,
            expires_at=_START + timedelta(minutes=5),
        )
    duplicate.cancel()
    assert _authority_snapshot(runtime, state, crypto, rng) == before

    owner = runtime.begin_point_batch(
        stable_id="point-batch-reservation-owner",
        linearization_time=_START,
    )
    owner.stage_point(
        NetworkRuntimePointFamily.RECENT_TUPLE,
        "tuple-a",
        3,
        expires_at=_START + timedelta(minutes=5),
    )
    contender = runtime.begin_point_batch(
        stable_id="point-batch-reservation-contender",
        linearization_time=_START,
    )
    with pytest.raises(StateError, match="reserved by another preparation"):
        contender.stage_point(
            NetworkRuntimePointFamily.RECENT_TUPLE,
            "tuple-a",
            4,
            expires_at=_START + timedelta(minutes=5),
        )
    contender.cancel()
    owner.cancel()
    assert _authority_snapshot(runtime, state, crypto, rng) == before

    stale = runtime.begin_point_batch(
        stable_id="point-batch-stale-expiry",
        linearization_time=_START + timedelta(minutes=1),
    )
    stale.stage_point(
        NetworkRuntimePointFamily.RECENT_TUPLE,
        "tuple-a",
        5,
        expires_at=_START + timedelta(minutes=2),
    )
    stale_mutation = next(iter(stale._mutations.values()))
    object.__setattr__(stale_mutation, "expires_at", _START + timedelta(seconds=30))
    with pytest.raises(StateError, match="overtaken"):
        stale.seal()
    assert _authority_snapshot(runtime, state, crypto, rng) == before


def test_point_batch_exact_token_identity_and_claim_owner_survive_forgery() -> None:
    """A copied or duplicate token cannot authenticate, cancel, or revoke the owner."""

    runtime, _state, _crypto = _runtime()
    batch = runtime.begin_point_batch(
        stable_id="point-batch-exact-token",
        linearization_time=_START,
    )
    batch.stage_point(
        NetworkRuntimePointFamily.TLS_SERVER_NAME,
        "10.0.0.20",
        "api.example.test",
        expires_at=_START + timedelta(hours=1),
    )
    token = batch.seal()
    forged = replace(token)
    foreign, _foreign_state, _foreign_crypto = _runtime()

    assert not runtime.authenticates_point_batch_token(forged)
    assert not runtime.cancel_point_batch(forged)
    with pytest.raises(StateError, match="stale"):
        with runtime.claimed_point_batch(forged):
            pytest.fail("a copied token must not enter its claim body")
    assert runtime.authenticates_point_batch_token(token)
    assert not foreign.authenticates_point_batch_token(token)
    assert not foreign.cancel_point_batch(token)
    with pytest.raises(StateError, match="another runtime"):
        with foreign.claimed_point_batch(token):
            pytest.fail("a foreign runtime must not enter the claim body")
    assert runtime.authenticates_point_batch_token(token)

    with runtime.claimed_point_batch(token) as owner:
        with pytest.raises(StateError, match="already claimed"):
            with runtime.claimed_point_batch(token):
                pytest.fail("a duplicate claim must not enter its body")
        object.__setattr__(token, "stable_id", "tampered-after-claim")
        receipt = owner.commit_no_fail()

    assert receipt.stable_id == "point-batch-exact-token"
    assert runtime.authenticates_point_batch_receipt(receipt)
    assert not runtime.authenticates_point_batch_receipt(receipt, token=token)
    assert (
        runtime.get_point(
            NetworkRuntimePointFamily.TLS_SERVER_NAME,
            "10.0.0.20",
        )
        == "api.example.test"
    )


def test_point_batch_authenticators_are_total_for_malformed_values() -> None:
    """Public point-batch proof checks return False for every malformed carrier."""

    class EvilEquality:
        def __eq__(self, other: object) -> bool:
            raise RuntimeError("caller equality must not escape")

    runtime, _state, _crypto = _runtime()
    batch = runtime.begin_point_batch(
        stable_id="point-batch-total-authenticator",
        linearization_time=_START,
    )
    batch.stage_point(
        NetworkRuntimePointFamily.DNS_OBSERVATION,
        "total",
        1,
        expires_at=_START + timedelta(hours=1),
    )
    token = batch.seal()
    with runtime.claimed_point_batch(token) as prepared:
        receipt = prepared.commit_no_fail()

    assert not runtime.authenticates_point_batch_token(object())
    assert not runtime.authenticates_point_batch_receipt(object())
    for field_name, malformed in (
        ("stable_id", object()),
        ("committed_point_mutations", -1),
        ("_runtime_token", EvilEquality()),
        ("_integrity_token", object()),
    ):
        candidate = replace(receipt)
        object.__setattr__(candidate, field_name, malformed)
        assert not runtime.authenticates_point_batch_receipt(candidate)
        assert not runtime.authenticates_point_batch_receipt(candidate, token=token)


def test_point_batch_fences_watermark_through_open_sealed_and_claimed_states() -> None:
    """The indexed preparation fence remains authoritative for every batch state."""

    runtime, _state, _crypto = _runtime()
    batch = runtime.begin_point_batch(
        stable_id="point-batch-watermark-fence",
        linearization_time=_START + timedelta(hours=1),
    )
    batch.stage_point(
        NetworkRuntimePointFamily.NTP_ASSOCIATION,
        "client-a",
        "server-a",
        expires_at=_START + timedelta(hours=2),
    )
    page = runtime.advance_watermark_page(_START + timedelta(minutes=30), limit=1)
    assert not page.has_more
    with pytest.raises(StateError, match="fenced by a preparation"):
        runtime.advance_watermark_page(_START + timedelta(hours=1), limit=1)

    token = batch.seal()
    with pytest.raises(StateError, match="fenced by a preparation"):
        runtime.advance_watermark_page(_START + timedelta(hours=1), limit=1)
    with runtime.claimed_point_batch(token):
        with pytest.raises(StateError, match="fenced by a preparation"):
            runtime.advance_watermark_page(_START + timedelta(hours=1), limit=1)

    page = runtime.advance_watermark_page(_START + timedelta(hours=1), limit=1)
    assert not page.has_more
    assert page.census.preparation_fences == 0
    assert page.census.reserved_deadlines == 0


def test_point_batch_overlay_and_commit_digest_are_independent_of_stage_order() -> None:
    """Equivalent point overlays produce the same digest regardless of insertion order."""

    first, first_state, first_crypto = _runtime()
    second, second_state, second_crypto = _runtime()
    entries = (
        (
            NetworkRuntimePointFamily.DNS_OBSERVATION,
            "dns-a",
            ("a.example.test", _START),
        ),
        (
            NetworkRuntimePointFamily.TLS_CLIENT_SERVER_PAIR,
            ("client-a", "server-a"),
            (_START, _START + timedelta(seconds=2)),
        ),
    )

    def prepare(
        runtime: NetworkTransactionRuntime,
        ordered_entries: tuple[tuple[NetworkRuntimePointFamily, object, object], ...],
    ) -> object:
        batch = runtime.begin_point_batch(
            stable_id="point-batch-order-independent",
            linearization_time=_START,
        )
        for family, key, value in ordered_entries:
            batch.stage_point(
                family,
                key,
                value,
                expires_at=_START + timedelta(hours=1),
            )
        return batch.seal()

    first_token = prepare(first, entries)
    second_token = prepare(second, tuple(reversed(entries)))
    assert first_token.overlay_digest == second_token.overlay_digest
    first_state_before = first_state.materialization_digest()
    second_state_before = second_state.materialization_digest()
    first_crypto_before = first_crypto.state_digest()
    second_crypto_before = second_crypto.state_digest()

    with first.claimed_point_batch(first_token) as prepared:
        first_receipt = prepared.commit_no_fail()
    with second.claimed_point_batch(second_token) as prepared:
        second_receipt = prepared.commit_no_fail()

    assert first_receipt.committed_runtime_digest == second_receipt.committed_runtime_digest
    assert first.state_digest() == second.state_digest()
    assert first_state.materialization_digest() == first_state_before
    assert second_state.materialization_digest() == second_state_before
    assert first_crypto.state_digest() == first_crypto_before
    assert second_crypto.state_digest() == second_crypto_before
