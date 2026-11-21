# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Mathematical validity and identity isolation of synthetic RSA public evidence."""

from __future__ import annotations

import hashlib
import math
import random
from collections.abc import Iterator
from itertools import combinations

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa

import evidenceforge.generation.rsa_material as rsa_material
from evidenceforge.generation.cryptographic_material import CryptographicMaterialRegistry
from evidenceforge.utils.rng import generation_seed_scope


@pytest.fixture(autouse=True)
def clear_public_modulus_memo() -> Iterator[None]:
    rsa_material._deterministic_rsa_modulus.cache_clear()
    yield
    rsa_material._deterministic_rsa_modulus.cache_clear()


@pytest.mark.parametrize("key_size", [2048, 3072, 4096])
def test_registry_rsa_modulus_passes_independent_native_key_validation(
    monkeypatch: pytest.MonkeyPatch, key_size: int
) -> None:
    factors: list[int] = []
    original = rsa_material._deterministic_rsa_prime

    def capture_prime(identity: str, bits: int) -> int:
        prime = original(identity, bits)
        factors.append(prime)
        return prime

    monkeypatch.setattr(rsa_material, "_deterministic_rsa_prime", capture_prime)
    registry = CryptographicMaterialRegistry()
    spki = registry.public_key_spki("rsa-validity.example", key_type="rsa", key_size=key_size)
    loaded = serialization.load_der_public_key(spki)
    assert isinstance(loaded, rsa.RSAPublicKey)
    numbers = loaded.public_numbers()
    assert loaded.key_size == key_size
    assert numbers.e == 65537
    first, second = factors
    assert first != second and first * second == numbers.n
    private_exponent = pow(numbers.e, -1, math.lcm(first - 1, second - 1))
    private_key = rsa.RSAPrivateNumbers(
        p=first,
        q=second,
        d=private_exponent,
        dmp1=rsa.rsa_crt_dmp1(private_exponent, first),
        dmq1=rsa.rsa_crt_dmq1(private_exponent, second),
        iqmp=rsa.rsa_crt_iqmp(first, second),
        public_numbers=numbers,
    ).private_key()
    assert private_key.public_key().public_numbers() == numbers
    assert (
        registry.public_key_spki("rsa-validity.example", key_type="rsa", key_size=key_size) == spki
    )
    assert len(factors) == 2
    fresh = CryptographicMaterialRegistry()
    assert fresh.public_key_spki("rsa-validity.example", key_type="rsa", key_size=key_size) == spki
    assert len(factors) == 2


def test_selector_and_certificate_siblings_have_distinct_coprime_rsa_material() -> None:
    registry = CryptographicMaterialRegistry()
    selector = registry.resolve_dkim_key("alpha.example", "mail")
    sibling = registry.resolve_dkim_key("alpha.example", "selector2")
    other_domain = registry.resolve_dkim_key("bravo.example", "mail")
    certificate_spki = registry.public_key_spki("ca:alpha.example", key_type="rsa", key_size=2048)
    encoded = [
        selector.public_key_spki_der,
        sibling.public_key_spki_der,
        other_domain.public_key_spki_der,
        certificate_spki,
    ]
    numbers: list[int] = []
    for spki in encoded:
        loaded = serialization.load_der_public_key(spki)
        assert isinstance(loaded, rsa.RSAPublicKey)
        numbers.append(loaded.public_numbers().n)
    assert len(set(numbers)) == 4
    assert all(math.gcd(first, second) == 1 for first, second in combinations(numbers, 2))
    fresh = CryptographicMaterialRegistry()
    assert fresh.resolve_dkim_key("ALPHA.EXAMPLE.", "MAIL.") == selector


@pytest.mark.parametrize("candidate", [0, 1, 4, 561, 1105, 1729, 3215031751, 3825123056546413051])
def test_primality_filter_rejects_composites_and_strong_pseudoprimes(candidate: int) -> None:
    assert not rsa_material._is_probable_prime(candidate, random.Random(21))


def test_rsa_material_change_preserves_valid_ecdsa_public_points() -> None:
    registry = CryptographicMaterialRegistry()
    spki = registry.public_key_spki("ec.example", key_type="ecdsa", key_size=256)
    loaded = serialization.load_der_public_key(spki)
    assert isinstance(loaded, ec.EllipticCurvePublicKey)
    assert loaded.key_size == 256


def test_rsa_factor_identity_survives_forced_32_bit_seed_collision(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(rsa_material, "_stable_seed", lambda _scope: 7)
    first = rsa_material.deterministic_rsa_public_numbers("independent-first", 2048)
    second = rsa_material.deterministic_rsa_public_numbers("independent-second", 2048)
    assert first.n != second.n
    assert math.gcd(first.n, second.n) == 1


def test_rsa_public_seed_scope_is_preserved_across_memo_hits() -> None:
    with generation_seed_scope(10):
        first = rsa_material.deterministic_rsa_public_numbers("same-identity", 2048)
    with generation_seed_scope(11):
        second = rsa_material.deterministic_rsa_public_numbers("same-identity", 2048)
    assert first.n != second.n
    with generation_seed_scope(10):
        repeated = rsa_material.deterministic_rsa_public_numbers("same-identity", 2048)
    assert repeated == first
    assert rsa_material._deterministic_rsa_modulus.cache_info().hits == 1


def test_public_modulus_computation_memo_is_bounded_and_uses_fixed_width_keys(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    scopes: list[str] = []

    def representative_factor(identity: str, bits: int) -> int:
        scopes.append(identity.split(":", 1)[0])
        raw = int.from_bytes(hashlib.shake_256(identity.encode()).digest(bits // 8), "big")
        return raw | (3 << (bits - 2)) | 1

    # Capacity is independent of primality-search cost; native validation above
    # covers actual factors. No fake factor survives this test's memo cleanup.
    monkeypatch.setattr(rsa_material, "_deterministic_rsa_prime", representative_factor)
    for ordinal in range(520):
        rsa_material.deterministic_rsa_public_numbers(f"capacity-{ordinal}", 2048)
    rsa_material.deterministic_rsa_public_numbers("long-identity-" + "x" * 100_000, 2048)
    info = rsa_material._deterministic_rsa_modulus.cache_info()
    assert info.currsize == info.maxsize == 512
    assert scopes and all(len(scope) == 64 for scope in scopes)
