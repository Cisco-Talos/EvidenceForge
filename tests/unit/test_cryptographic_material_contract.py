# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Tests for canonical cryptographic material and TLS presentation planning."""

from concurrent.futures import ThreadPoolExecutor
from dataclasses import FrozenInstanceError, replace
from datetime import UTC, datetime
from threading import Event, Thread

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa

from evidenceforge.events.cryptography import CertificateIdentityPlan
from evidenceforge.generation.actions import tls_certificate as tls_certificate_module
from evidenceforge.generation.actions.tls_certificate import TlsCertificatePlanner
from evidenceforge.generation.activity.tls_realism import certificate_authority_profile
from evidenceforge.generation.cryptographic_material import (
    CryptographicMaterialPreparation,
    CryptographicMaterialRegistry,
)
from evidenceforge.models.exceptions import StateError

_EVENT_TIME = datetime(2024, 10, 14, 12, 0, tzinfo=UTC)
_ISSUER_CONFIG = {
    "name": "CN=R3, O=Let's Encrypt, C=US",
    "validity_days_min": 90,
    "validity_days_max": 90,
    "not_before_max_days": 30,
}


def _presentation(
    registry: CryptographicMaterialRegistry,
    *,
    connection: str,
):
    planner = TlsCertificatePlanner(registry)
    return planner, planner.plan(
        backend_identity="www.example.com",
        cert_name="www.example.com",
        issuer_config=_ISSUER_CONFIG,
        event_time=_EVENT_TIME,
        connection_identity=connection,
        key_type="rsa",
        key_size=2048,
        san_dns=("www.example.com",),
    )


def _prepared_certificate(
    preparation: CryptographicMaterialPreparation,
    *,
    backend_identity: str = "prepared.example",
) -> CertificateIdentityPlan:
    return preparation.resolve_certificate(
        backend_identity=backend_identity,
        subject_name=f"CN={backend_identity}",
        issuer_name="CN=Prepared Test CA, O=Example Corp, C=US",
        not_valid_before=1_700_000_000,
        not_valid_after=1_800_000_000,
        key_type="ecdsa",
        key_size=256,
        signature_algorithm="ecdsa-with-SHA256",
        san_dns=(backend_identity,),
    )


def test_registry_material_is_valid_deterministic_and_order_independent() -> None:
    first = CryptographicMaterialRegistry()
    second = CryptographicMaterialRegistry()

    first_rsa = first.public_key_spki("backend:a", key_type="rsa", key_size=2048)
    first_ec = first.public_key_spki("backend:b", key_type="ecdsa", key_size=384)
    second_ec = second.public_key_spki("backend:b", key_type="ecdsa", key_size=384)
    second_rsa = second.public_key_spki("backend:a", key_type="rsa", key_size=2048)

    assert first_rsa == second_rsa
    assert first_ec == second_ec
    rsa_key = serialization.load_der_public_key(first_rsa)
    ec_key = serialization.load_der_public_key(first_ec)
    assert isinstance(rsa_key, rsa.RSAPublicKey)
    assert rsa_key.key_size == 2048
    assert rsa_key.public_numbers().e == 65537
    assert isinstance(ec_key, ec.EllipticCurvePublicKey)
    assert ec_key.key_size == 384
    assert first.census() == second.census()
    assert first.state_digest() == second.state_digest()


def test_tls_presentation_is_stable_but_file_ids_are_connection_scoped() -> None:
    registry = CryptographicMaterialRegistry()
    planner, first = _presentation(registry, connection="CFirst")
    _, second = _presentation(registry, connection="CSecond")

    assert first.certificates == second.certificates
    assert first.certificate_fuids != second.certificate_fuids
    assert all(
        certificate.subject_name != certificate.issuer_name
        for certificate in first.certificates[1:]
    )
    contexts = planner.x509_contexts(first)
    planner.validate_projection(first, contexts)
    with pytest.raises(FrozenInstanceError):
        first.backend_identity = "mutated.example"  # type: ignore[misc]


def test_leaf_issuer_bound_preserves_independent_issuance_seconds() -> None:
    issuer_name = "CN=GlobalSign Atlas R3 DV TLS CA 2024 Q1, O=GlobalSign nv-sa, C=BE"
    profile = certificate_authority_profile(issuer_name)
    assert profile is not None
    issuer_start = int(profile["not_valid_before"])
    issuer_end = int(profile["not_valid_after"])
    event_time = datetime(2024, 3, 18, 12, 0, tzinfo=UTC)
    raw_validity = (issuer_start - 30 * 86400, issuer_end + 30 * 86400)

    first = TlsCertificatePlanner._bound_to_issuer(
        raw_validity,
        issuer_name,
        event_time,
        identity="leaf:first.example",
    )
    repeated = TlsCertificatePlanner._bound_to_issuer(
        raw_validity,
        issuer_name,
        event_time,
        identity="leaf:first.example",
    )
    second = TlsCertificatePlanner._bound_to_issuer(
        raw_validity,
        issuer_name,
        event_time,
        identity="leaf:second.example",
    )

    assert first == repeated
    assert issuer_start < first[0] < int(event_time.timestamp())
    assert first[1] <= issuer_end
    assert second[0] != first[0]


@pytest.mark.parametrize(
    ("issuer_name", "authority_key_type", "authority_key_size"),
    (
        ("CN=Cloudflare Inc ECC CA-3, O=Cloudflare Inc, C=US", "ecdsa", 256),
        ("CN=E1, O=Let's Encrypt, C=US", "ecdsa", 256),
        (
            "CN=GlobalSign Atlas R3 DV TLS CA 2024 Q1, O=GlobalSign nv-sa, C=BE",
            "rsa",
            2048,
        ),
    ),
)
def test_tls_planner_owns_stable_authority_chain_semantics(
    monkeypatch: pytest.MonkeyPatch,
    issuer_name: str,
    authority_key_type: str,
    authority_key_size: int,
) -> None:
    monkeypatch.setattr(
        tls_certificate_module,
        "certificate_chain_config",
        lambda: {
            "include_intermediate_probability": 1.0,
            "include_second_intermediate_probability": 0.0,
            "present_trust_anchor": False,
        },
    )
    registry = CryptographicMaterialRegistry()
    planner = TlsCertificatePlanner(registry)
    issuer_config = {
        "name": issuer_name,
        "validity_days_min": 90,
        "validity_days_max": 90,
        "not_before_max_days": 30,
    }

    first = planner.plan(
        backend_identity="first.example",
        cert_name="first.example",
        issuer_config=issuer_config,
        event_time=_EVENT_TIME,
        connection_identity="CFirstAuthority",
        key_type="rsa",
        key_size=2048,
        san_dns=("first.example",),
    )
    second = planner.plan(
        backend_identity="second.example",
        cert_name="second.example",
        issuer_config=issuer_config,
        event_time=_EVENT_TIME,
        connection_identity="CSecondAuthority",
        key_type="rsa",
        key_size=2048,
        san_dns=("second.example",),
    )

    assert len(first.certificates) == len(second.certificates) == 2
    first_leaf, first_authority = first.certificates
    _second_leaf, second_authority = second.certificates
    assert first_authority == second_authority
    assert first.certificate_fuids[1] != second.certificate_fuids[1]
    assert first_leaf.issuer_name == first_authority.subject_name
    assert first_authority.key_type == authority_key_type
    assert first_authority.key_size == authority_key_size
    assert first_authority.not_valid_before <= first_leaf.not_valid_before
    assert first_leaf.not_valid_after <= first_authority.not_valid_after
    contexts = planner.x509_contexts(first)
    planner.validate_projection(first, contexts)


def test_tls_preparation_cancel_is_exactly_registry_neutral() -> None:
    registry = CryptographicMaterialRegistry()
    before = registry.tls_preparation_census()
    before_digest = registry.state_digest()
    preparation = registry.begin_tls_preparation()

    _prepared_certificate(preparation)
    assert registry.tls_preparation_census() == before
    assert registry.state_digest() == before_digest
    token = preparation.seal()
    prepared = registry.tls_preparation_census()
    assert prepared.prepared_overlays == 1
    assert prepared.reserved_points == 2
    assert registry.state_digest() != before_digest
    assert registry.authenticates_tls_preparation_token(token)

    assert preparation.cancel()
    assert not preparation.cancel()
    assert registry.tls_preparation_census() == before
    assert registry.state_digest() == before_digest
    assert not registry.authenticates_tls_preparation_token(token)
    with pytest.raises(StateError, match="cancelled"):
        preparation.seal()


def test_tls_preparation_commit_is_one_shot_and_returns_signed_receipt() -> None:
    registry = CryptographicMaterialRegistry()
    preparation = registry.begin_tls_preparation()
    expected = replace(_prepared_certificate(preparation))
    token = preparation.seal()
    assert preparation.seal() is token

    with registry.prepared_tls_material(token) as prepared:
        receipt = prepared.commit_no_fail()
        assert prepared.receipt is receipt
        with pytest.raises(StateError, match="already committed"):
            prepared.commit_no_fail()

    assert receipt.publication_token == token.publication_token
    assert receipt.overlay_digest == token.overlay_digest
    assert receipt.public_key_writes == token.public_key_writes == 1
    assert receipt.authority_writes == token.authority_writes == 0
    assert receipt.certificate_writes == token.certificate_writes == 1
    assert receipt.receipt_token
    assert registry.authenticates_tls_preparation_receipt(receipt, token=token)
    assert not registry.authenticates_tls_preparation_token(token)
    assert (
        registry.resolve_certificate(
            backend_identity="prepared.example",
            subject_name="CN=prepared.example",
            issuer_name="CN=Prepared Test CA, O=Example Corp, C=US",
            not_valid_before=1_700_000_000,
            not_valid_after=1_800_000_000,
            key_type="ecdsa",
            key_size=256,
            signature_algorithm="ecdsa-with-SHA256",
            san_dns=("prepared.example",),
        )
        == expected
    )


def test_tls_preparation_commits_authority_material_through_same_receipt() -> None:
    registry = CryptographicMaterialRegistry()
    preparation = registry.begin_tls_preparation()
    expected = preparation.resolve_authority(
        subject_name="CN=Prepared Test CA, O=Example Corp, C=US",
        issuer_name="CN=Prepared Root CA, O=Example Corp, C=US",
        key_type="ecdsa",
        key_size=256,
    )
    token = preparation.seal()
    assert token.public_key_writes == 1
    assert token.authority_writes == 1
    assert token.certificate_writes == 0

    with registry.prepared_tls_material(token) as prepared:
        receipt = prepared.commit_no_fail()
    assert registry.authenticates_tls_preparation_receipt(receipt, token=token)
    assert (
        registry.resolve_authority(
            subject_name="CN=Prepared Test CA, O=Example Corp, C=US",
            issuer_name="CN=Prepared Root CA, O=Example Corp, C=US",
            key_type="ecdsa",
            key_size=256,
        )
        == expected
    )


def test_tls_prepared_claim_body_holds_no_registry_lock_and_abort_is_neutral() -> None:
    registry = CryptographicMaterialRegistry()
    before = registry.census()
    before_digest = registry.state_digest()
    preparation = registry.begin_tls_preparation()
    _prepared_certificate(preparation)
    token = preparation.seal()

    acquired = Event()

    def acquire_registry_lock() -> None:
        with registry._tls_material_lock:
            acquired.set()

    with registry.prepared_tls_material(token) as prepared:
        assert not prepared.committed
        worker = Thread(target=acquire_registry_lock)
        worker.start()
        assert acquired.wait(timeout=2.0)
        worker.join(timeout=2.0)
        claimed = registry.tls_preparation_census()
        assert claimed.claimed_overlays == 1

    assert registry.census() == before
    assert registry.state_digest() == before_digest


def test_tls_preseal_return_alias_tamper_is_rejected_before_any_reservation() -> None:
    """A mutated staged return value cannot become a newly authenticated preimage."""

    registry = CryptographicMaterialRegistry()
    before = registry.census()
    before_digest = registry.state_digest()
    preparation = registry.begin_tls_preparation()
    certificate = _prepared_certificate(preparation)
    object.__setattr__(certificate, "subject_name", "CN=preseal-tampered.example")

    with pytest.raises(StateError, match="staged value changed"):
        preparation.seal()

    assert registry.census() == before
    assert registry.state_digest() == before_digest
    assert preparation.cancel()


def test_tls_duplicate_tampered_points_are_rejected_before_any_publication() -> None:
    """Two trusted-looking patches may never target one canonical point."""

    registry = CryptographicMaterialRegistry()
    before = registry.census()
    before_digest = registry.state_digest()
    preparation = registry.begin_tls_preparation()
    preparation.public_key_spki("duplicate-a", key_type="ecdsa", key_size=256)
    preparation.public_key_spki("duplicate-b", key_type="ecdsa", key_size=256)
    patches = list(preparation._patches.values())
    object.__setattr__(patches[1], "key", patches[0].key)

    with pytest.raises(StateError, match="duplicate point"):
        preparation.seal()

    assert registry.census() == before
    assert registry.state_digest() == before_digest
    assert preparation.cancel()


def test_tls_unique_key_tamper_cannot_rebind_deterministic_material() -> None:
    """A staged value remains bound to the exact semantic key that derived it."""

    registry = CryptographicMaterialRegistry()
    before = registry.census()
    before_digest = registry.state_digest()
    preparation = registry.begin_tls_preparation()
    preparation.public_key_spki("semantic-a", key_type="ecdsa", key_size=256)
    patch = next(iter(preparation._patches.values()))
    object.__setattr__(patch, "key", ("semantic-c", "ecdsa", 256))

    with pytest.raises(StateError, match="semantic point key"):
        preparation.seal()

    assert registry.census() == before
    assert registry.state_digest() == before_digest
    assert preparation.cancel()


def test_tls_cached_values_are_copy_isolated_across_direct_and_prepared_reads() -> None:
    """Frozen dataclass syntax cannot expose mutable canonical object aliases."""

    registry = CryptographicMaterialRegistry()
    certificate = _prepared_certificate(registry)
    expected = replace(certificate)
    digest_before = registry.state_digest()
    object.__setattr__(certificate, "subject_name", "CN=direct-alias-corruption")

    direct = _prepared_certificate(registry)
    assert direct == expected
    preparation = registry.begin_tls_preparation()
    prepared = _prepared_certificate(preparation)
    assert prepared == expected
    object.__setattr__(prepared, "subject_name", "CN=prepared-alias-corruption")
    assert preparation.cancel()

    assert _prepared_certificate(registry) == expected
    assert registry.state_digest() == digest_before


def test_tls_duplicate_claim_attempts_cannot_revoke_claim_owner() -> None:
    """Only the owning claim context may commit or abort an active TLS capability."""

    registry = CryptographicMaterialRegistry()
    preparation = registry.begin_tls_preparation()
    expected = replace(_prepared_certificate(preparation))
    token = preparation.seal()

    def duplicate_claim() -> None:
        with registry.prepared_tls_material(token):
            pytest.fail("duplicate claim must not enter its body")

    with registry.prepared_tls_material(token) as owner:
        with pytest.raises(StateError, match="already claimed"):
            duplicate_claim()
        with ThreadPoolExecutor(max_workers=1) as pool:
            future = pool.submit(duplicate_claim)
            with pytest.raises(StateError, match="already claimed"):
                future.result(timeout=2.0)

        assert registry.cancel_tls_preparation(token) is False
        with pytest.raises(StateError, match="already claimed"):
            duplicate_claim()
        claimed = registry.census()
        assert claimed.prepared_overlays == claimed.claimed_overlays == 1
        receipt = owner.commit_no_fail()

    assert registry.authenticates_tls_preparation_receipt(receipt)
    assert registry.authenticates_tls_preparation_receipt(receipt, token=token)
    assert registry.census().prepared_overlays == 0
    assert (
        registry.resolve_certificate(
            backend_identity="prepared.example",
            subject_name="CN=prepared.example",
            issuer_name="CN=Prepared Test CA, O=Example Corp, C=US",
            not_valid_before=1_700_000_000,
            not_valid_after=1_800_000_000,
            key_type="ecdsa",
            key_size=256,
            signature_algorithm="ecdsa-with-SHA256",
            san_dns=("prepared.example",),
        )
        == expected
    )


def test_tls_preparation_requires_exact_token_object_identity() -> None:
    registry = CryptographicMaterialRegistry()
    preparation = registry.begin_tls_preparation()
    _prepared_certificate(preparation)
    token = preparation.seal()
    alias = replace(token)

    assert not registry.authenticates_tls_preparation_token(alias)
    with pytest.raises(StateError, match="stale or already consumed"):
        with registry.prepared_tls_material(alias):
            pytest.fail("an equal token alias must not be claimable")
    assert registry.authenticates_tls_preparation_token(token)
    assert preparation.cancel()


def test_tls_receipt_rejects_foreign_registry_and_any_public_tamper() -> None:
    registry = CryptographicMaterialRegistry()
    preparation = registry.begin_tls_preparation()
    _prepared_certificate(preparation)
    token = preparation.seal()
    with registry.prepared_tls_material(token) as prepared:
        receipt = prepared.commit_no_fail()

    assert not CryptographicMaterialRegistry().authenticates_tls_preparation_receipt(receipt)
    assert not registry.authenticates_tls_preparation_receipt(
        replace(receipt, committed_digest="0" * 64)
    )
    assert not registry.authenticates_tls_preparation_receipt(
        receipt,
        token=replace(token, overlay_digest="0" * 64),
    )


def test_tls_point_reservation_blocks_same_point_but_not_disjoint_preparation() -> None:
    registry = CryptographicMaterialRegistry()
    first = registry.begin_tls_preparation()
    _prepared_certificate(first, backend_identity="first.example")
    first_token = first.seal()

    conflicting = registry.begin_tls_preparation()
    _prepared_certificate(conflicting, backend_identity="first.example")
    with pytest.raises(StateError, match="is reserved"):
        conflicting.seal()
    with pytest.raises(StateError, match="is reserved"):
        registry.public_key_spki(
            "certificate:first.example:CN=first.example",
            key_type="ecdsa",
            key_size=256,
        )

    disjoint = registry.begin_tls_preparation()
    _prepared_certificate(disjoint, backend_identity="second.example")
    disjoint_token = disjoint.seal()
    assert registry.authenticates_tls_preparation_token(first_token)
    assert registry.authenticates_tls_preparation_token(disjoint_token)
    assert first.cancel()
    assert disjoint.cancel()
    assert conflicting.cancel()


def test_tls_point_tombstone_generation_prevents_absent_point_aba() -> None:
    registry = CryptographicMaterialRegistry()
    identity = "tombstone.example"
    registry.public_key_spki(identity, key_type="ecdsa", key_size=256)
    key = (identity, "ecdsa", 256)
    point = ("public_key", key)

    with registry._tls_material_lock:
        first_generation = registry._tls_point_generations[point]
        assert registry._delete_tls_material_locked("public_key", key)
        tombstone_generation = registry._tls_point_tombstones[point]
    assert tombstone_generation == first_generation + 1

    preparation = registry.begin_tls_preparation()
    preparation.public_key_spki(identity, key_type="ecdsa", key_size=256)
    token = preparation.seal()
    assert token.public_key_writes == 1
    with registry.prepared_tls_material(token) as prepared:
        prepared.commit_no_fail()
    with registry._tls_material_lock:
        assert registry._tls_point_generations[point] == tombstone_generation + 1
        assert point not in registry._tls_point_tombstones


def test_tls_certificate_planner_can_cancel_a_full_private_overlay() -> None:
    registry = CryptographicMaterialRegistry()
    before = registry.tls_preparation_census()
    preparation = registry.begin_tls_preparation()
    planner = TlsCertificatePlanner(preparation)  # type: ignore[arg-type]

    presentation = planner.plan(
        backend_identity="overlay.example",
        cert_name="overlay.example",
        issuer_config=_ISSUER_CONFIG,
        event_time=_EVENT_TIME,
        connection_identity="COverlay",
        key_type="rsa",
        key_size=2048,
        san_dns=("overlay.example",),
    )
    assert presentation.leaf.subject_name == "CN=overlay.example"
    assert registry.tls_preparation_census() == before
    token = preparation.seal()
    assert token.certificate_writes >= 1
    assert preparation.cancel()
    assert registry.tls_preparation_census() == before


def test_tls_preparation_of_existing_material_commits_empty_authenticated_overlay() -> None:
    registry = CryptographicMaterialRegistry()
    expected = registry.public_key_spki("cached.example", key_type="ecdsa", key_size=256)
    before = registry.tls_preparation_census()
    preparation = registry.begin_tls_preparation()
    assert preparation.public_key_spki("cached.example", key_type="ecdsa", key_size=256) == expected
    token = preparation.seal()
    assert token.public_key_writes == token.authority_writes == token.certificate_writes == 0
    with registry.prepared_tls_material(token) as prepared:
        receipt = prepared.commit_no_fail()
    assert registry.authenticates_tls_preparation_receipt(receipt, token=token)
    assert registry.tls_preparation_census() == before
