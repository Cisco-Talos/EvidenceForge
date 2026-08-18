# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Bounded-retention gates for DKIM wrappers and deterministic OCSP status."""

from __future__ import annotations

import gc
import json
import os
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from copy import copy, deepcopy
from weakref import ref

import pytest

from evidenceforge.events.cryptography import CertificateIdentityPlan
from evidenceforge.generation.cryptographic_material import (
    CryptographicMaterialCapacityError,
    CryptographicMaterialRegistry,
)


def _certificate(registry: CryptographicMaterialRegistry) -> CertificateIdentityPlan:
    """Create one compact deterministic certificate identity for OCSP probes."""

    return registry.resolve_certificate(
        backend_identity="retention.example",
        subject_name="CN=retention.example",
        issuer_name="CN=Retention CA, O=Example Corp, C=US",
        not_valid_before=1_700_000_000,
        not_valid_after=1_800_000_000,
        key_type="ecdsa",
        key_size=256,
        signature_algorithm="ecdsa-with-SHA256",
        san_dns=("retention.example",),
    )


def _good_profile(name: str) -> dict[str, object]:
    """Return one exact-match deterministic-good OCSP profile."""

    return {
        "name": name,
        "certificate_patterns": ["retention.example"],
        "status_weights": {"good": 1, "unknown": 0, "revoked": 0},
    }


def _constant_rsa_spki() -> bytes:
    """Build one valid RSA SPKI outside the bounded owner under test."""

    return CryptographicMaterialRegistry(tls_material_capacity=None).public_key_spki(
        "auxiliary-retention-constant",
        key_type="rsa",
        key_size=2048,
    )


def test_dkim_wrapper_exact_cap_and_one_over_are_failure_neutral(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The exact wrapper cap is retained and one-over is recomputed without mutation."""

    registry = CryptographicMaterialRegistry(tls_material_capacity=1)
    spki = _constant_rsa_spki()
    monkeypatch.setattr(registry, "public_key_spki", lambda *_args, **_kwargs: spki)

    first = registry.resolve_dkim_key("alpha.example", "mail")
    exact = registry.tls_material_point_capacity_census()
    digest = registry.state_digest()
    second = registry.resolve_dkim_key("bravo.example", "mail")

    assert (first.domain, first.selector) == ("alpha.example", "mail")
    assert (second.domain, second.selector) == ("bravo.example", "mail")
    assert first.public_key_spki_der == second.public_key_spki_der == spki
    assert registry.tls_material_point_capacity_census() == exact
    assert registry.state_digest() == digest
    assert exact.dkim_key_capacity == 1
    assert exact.retained_dkim_key_entries == exact.dkim_key_high_water == 1
    assert exact.retained_dkim_key_estimated_bytes == exact.dkim_key_byte_high_water
    assert exact.retained_dkim_key_estimated_bytes <= exact.dkim_key_byte_capacity


def test_real_dkim_one_over_tls_point_cap_is_neutral() -> None:
    """A new selector over the shared hard point cap publishes neither owner."""

    registry = CryptographicMaterialRegistry(tls_material_capacity=1)
    registry.resolve_dkim_key("alpha.example", "mail")
    before = (
        registry.census(),
        registry.tls_material_point_capacity_census(),
        registry.state_digest(),
    )

    with pytest.raises(CryptographicMaterialCapacityError, match="retained-key capacity"):
        registry.resolve_dkim_key("bravo.example", "mail")
    assert before == (
        registry.census(),
        registry.tls_material_point_capacity_census(),
        registry.state_digest(),
    )


def test_oversized_dkim_wrapper_is_recomputed_without_retention(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A wrapper beyond its byte bound remains usable without owner mutation."""

    registry = CryptographicMaterialRegistry(tls_material_capacity=1)
    spki = _constant_rsa_spki()
    monkeypatch.setattr(registry, "public_key_spki", lambda *_args, **_kwargs: spki)
    before = (
        registry.census(),
        registry.tls_material_point_capacity_census(),
        registry.state_digest(),
    )

    domain = f"{'a' * 300_000}.example"
    result = registry.resolve_dkim_key(domain, "mail")
    assert result.domain == domain
    assert result.public_key_spki_der == spki
    assert before == (
        registry.census(),
        registry.tls_material_point_capacity_census(),
        registry.state_digest(),
    )


def test_explicit_unlimited_mode_retains_legacy_dkim_wrapper_behavior() -> None:
    """The existing ``None`` constructor escape remains explicitly unlimited."""

    registry = CryptographicMaterialRegistry(tls_material_capacity=None)
    first = registry.resolve_dkim_key("alpha.example", "mail")
    second = registry.resolve_dkim_key("bravo.example", "mail")
    census = registry.tls_material_point_capacity_census()

    assert first.domain == "alpha.example"
    assert second.domain == "bravo.example"
    assert registry.dkim_key_capacity is None
    assert census.dkim_key_capacity is None
    assert census.dkim_key_byte_capacity is None
    assert census.retained_dkim_key_entries == 2


def test_dkim_wrapper_cache_owns_a_private_snapshot() -> None:
    """Caller copies and forced frozen-field mutations cannot poison canonical rows."""

    registry = CryptographicMaterialRegistry(tls_material_capacity=4)
    expected = registry.resolve_dkim_key("Example.TEST.", "Mail.")
    shallow = copy(expected)
    deep = deepcopy(expected)

    object.__setattr__(expected, "domain", "mutated.invalid")
    object.__setattr__(shallow, "selector", "mutated")
    object.__setattr__(deep, "public_key_base64", "mutated")
    observed = registry.resolve_dkim_key("example.test", "mail")

    assert observed.domain == "example.test"
    assert observed.selector == "mail"
    assert observed.public_key_base64 != "mutated"
    assert observed is not expected and observed is not shallow and observed is not deep
    census = registry.tls_material_point_capacity_census()
    assert census.retained_dkim_key_entries == 1
    assert census.retained_dkim_key_estimated_bytes > 0

    registry_reference = ref(registry)
    del registry
    gc.collect()
    assert registry_reference() is None


def test_dkim_invalid_identity_fails_before_any_owner_mutation() -> None:
    """Invalid normalized identities cannot strand a TLS point or wrapper row."""

    registry = CryptographicMaterialRegistry(tls_material_capacity=4)
    before = (
        registry.census(),
        registry.tls_material_point_capacity_census(),
        registry.state_digest(),
    )
    with pytest.raises(ValueError, match="non-empty domain and selector"):
        registry.resolve_dkim_key(".", "mail")
    with pytest.raises(ValueError, match="non-empty domain and selector"):
        registry.resolve_dkim_key("example.test", ".")
    assert before == (
        registry.census(),
        registry.tls_material_point_capacity_census(),
        registry.state_digest(),
    )


def test_ocsp_status_recomputation_releases_profile_graph_and_tracks_no_rows() -> None:
    """OCSP profile identities remain pure inputs rather than retained cache keys."""

    class Profile(dict[str, object]):
        """Weak-referenceable profile used to prove terminal release."""

    registry = CryptographicMaterialRegistry(tls_material_capacity=2)
    certificate = _certificate(registry)
    profile = Profile(_good_profile("ephemeral"))
    profile_reference = ref(profile)

    assert registry.resolve_ocsp_status(certificate, [profile]) == ("good", None)
    profile["status_weights"] = {"good": 0, "unknown": 1, "revoked": 0}
    assert registry.resolve_ocsp_status(certificate, [profile]) == ("unknown", None)
    profile["status_weights"] = {"good": 1, "unknown": 0, "revoked": 0}
    assert registry.resolve_ocsp_status(certificate, [profile]) == ("good", None)
    del profile
    gc.collect()

    assert profile_reference() is None
    census = registry.tls_material_point_capacity_census()
    assert census.ocsp_status_capacity == census.ocsp_status_byte_capacity == 0
    assert census.retained_ocsp_status_entries == census.retained_ocsp_status_estimated_bytes == 0
    assert census.uncapped_ocsp_status_entries == census.uncapped_ocsp_status_estimated_bytes == 0


def test_concurrent_dkim_and_ocsp_resolution_publish_one_bounded_wrapper() -> None:
    """Concurrent callers agree while OCSP remains stateless and DKIM publishes once."""

    registry = CryptographicMaterialRegistry(tls_material_capacity=8)
    certificate = _certificate(registry)

    def resolve(ordinal: int) -> tuple[object, tuple[str, str | None]]:
        dkim = registry.resolve_dkim_key("concurrent.example", "mail")
        status = registry.resolve_ocsp_status(certificate, [_good_profile(f"profile-{ordinal}")])
        return dkim, status

    with ThreadPoolExecutor(max_workers=8) as executor:
        results = list(executor.map(resolve, range(128)))

    expected_dkim = results[0][0]
    assert all(dkim == expected_dkim and status == ("good", None) for dkim, status in results)
    assert len({id(dkim) for dkim, _status in results}) == len(results)
    census = registry.tls_material_point_capacity_census()
    assert census.retained_dkim_key_entries == 1
    assert census.retained_ocsp_status_entries == 0


def test_dkim_census_and_digest_are_worker_order_stable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Order-independent accounting agrees across serial and threaded resolution."""

    spki = _constant_rsa_spki()
    identities = [(f"worker-{ordinal}.example", "mail") for ordinal in range(64)]

    def resolve(worker_count: int) -> tuple[object, str]:
        registry = CryptographicMaterialRegistry(tls_material_capacity=128)
        monkeypatch.setattr(registry, "public_key_spki", lambda *_args, **_kwargs: spki)
        if worker_count == 1:
            for domain, selector in identities:
                registry.resolve_dkim_key(domain, selector)
        else:
            with ThreadPoolExecutor(max_workers=worker_count) as executor:
                list(
                    executor.map(
                        lambda identity: registry.resolve_dkim_key(*identity),
                        reversed(identities),
                    )
                )
        return registry.tls_material_point_capacity_census(), registry.state_digest()

    assert resolve(1) == resolve(8)


def test_auxiliary_retention_plateaus_from_seven_to_thirty_days(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Unique hourly wrapper/profile churn is duration-stable after the exact cap."""

    spki = _constant_rsa_spki()

    def run(days: int) -> tuple[int, int, int, int, int]:
        registry = CryptographicMaterialRegistry(tls_material_capacity=32)
        certificate = _certificate(registry)
        monkeypatch.setattr(registry, "public_key_spki", lambda *_args, **_kwargs: spki)
        for hour in range(days * 24):
            registry.resolve_dkim_key(f"domain-{hour}.example", "mail")
            registry.resolve_ocsp_status(certificate, [_good_profile(f"profile-{hour}")])
        census = registry.tls_material_point_capacity_census()
        return (
            census.retained_dkim_key_entries,
            census.retained_dkim_key_estimated_bytes,
            census.dkim_key_high_water,
            census.retained_ocsp_status_entries,
            census.retained_ocsp_status_estimated_bytes,
        )

    one_day = run(1)
    seven_days = run(7)
    thirty_days = run(30)
    assert one_day[0] == 24
    assert seven_days == thirty_days
    assert thirty_days[0] == thirty_days[2] == 32
    assert thirty_days[3:] == (0, 0)


def _hashseed_probe(seed: int) -> dict[str, object]:
    """Run the public auxiliary paths in a fresh hash-seeded interpreter."""

    script = r"""
import json
from evidenceforge.generation.cryptographic_material import CryptographicMaterialRegistry

source = CryptographicMaterialRegistry(tls_material_capacity=None)
spki = source.public_key_spki("hashseed-constant", key_type="rsa", key_size=2048)
certificate = source.resolve_certificate(
    backend_identity="retention.example",
    subject_name="CN=retention.example",
    issuer_name="CN=Retention CA, O=Example Corp, C=US",
    not_valid_before=1_700_000_000,
    not_valid_after=1_800_000_000,
    key_type="ecdsa",
    key_size=256,
    signature_algorithm="ecdsa-with-SHA256",
    san_dns=("retention.example",),
)
registry = CryptographicMaterialRegistry(tls_material_capacity=8)
registry.public_key_spki = lambda *_args, **_kwargs: spki
rows = []
for ordinal in range(16):
    dkim = registry.resolve_dkim_key(f"hash-{ordinal}.example", "mail")
    status = registry.resolve_ocsp_status(
        certificate,
        [{
            "name": f"profile-{ordinal}",
            "certificate_patterns": ["retention.example"],
            "status_weights": {"good": 5, "unknown": 2, "revoked": 0},
        }],
    )
    rows.append((dkim.domain, dkim.public_key_base64, status))
census = registry.tls_material_point_capacity_census()
print(json.dumps({
    "rows": rows,
    "digest": registry.state_digest(),
    "census": [
        census.retained_dkim_key_entries,
        census.retained_dkim_key_estimated_bytes,
        census.retained_ocsp_status_entries,
        census.retained_ocsp_status_estimated_bytes,
    ],
}, sort_keys=True))
"""
    environment = os.environ.copy()
    environment.update(
        {
            "PYTHONDONTWRITEBYTECODE": "1",
            "PYTHONHASHSEED": str(seed),
            "PYTHONPATH": "src",
        }
    )
    completed = subprocess.run(
        [sys.executable, "-c", script],
        check=True,
        capture_output=True,
        text=True,
        env=environment,
    )
    return json.loads(completed.stdout)


def test_auxiliary_outputs_and_census_are_hashseed_stable() -> None:
    """Worker-process hash randomization cannot alter output or retained state."""

    assert _hashseed_probe(1) == _hashseed_probe(999)


@pytest.mark.slow
def test_auxiliary_thirty_day_rss_plateaus_after_seven_days() -> None:
    """Fresh-process RSS and exact census plateau under hourly unique-key churn."""

    script = r"""
import gc
import json
import psutil
from evidenceforge.generation.cryptographic_material import CryptographicMaterialRegistry

source = CryptographicMaterialRegistry(tls_material_capacity=None)
spki = source.public_key_spki("rss-constant", key_type="rsa", key_size=2048)
registry = CryptographicMaterialRegistry(tls_material_capacity=64)
certificate = registry.resolve_certificate(
    backend_identity="retention.example",
    subject_name="CN=retention.example",
    issuer_name="CN=Retention CA, O=Example Corp, C=US",
    not_valid_before=1_700_000_000,
    not_valid_after=1_800_000_000,
    key_type="ecdsa",
    key_size=256,
    signature_algorithm="ecdsa-with-SHA256",
    san_dns=("retention.example",),
)
registry.public_key_spki = lambda *_args, **_kwargs: spki
process = psutil.Process()
samples = {}
for hour in range(30 * 24):
    registry.resolve_dkim_key(f"rss-{hour}.example", "mail")
    registry.resolve_ocsp_status(
        certificate,
        [{
            "name": f"profile-{hour}",
            "certificate_patterns": ["retention.example"],
            "status_weights": {"good": 1},
        }],
    )
    if hour + 1 in {7 * 24, 30 * 24}:
        gc.collect()
        census = registry.tls_material_point_capacity_census()
        samples[str(hour + 1)] = [
            process.memory_info().rss,
            census.retained_dkim_key_entries,
            census.retained_dkim_key_estimated_bytes,
            census.retained_ocsp_status_entries,
            census.retained_ocsp_status_estimated_bytes,
        ]
print(json.dumps(samples, sort_keys=True))
"""
    environment = os.environ.copy()
    environment.update(
        {
            "PYTHONDONTWRITEBYTECODE": "1",
            "PYTHONHASHSEED": "17",
            "PYTHONPATH": "src",
        }
    )
    completed = subprocess.run(
        [sys.executable, "-c", script],
        check=True,
        capture_output=True,
        text=True,
        env=environment,
    )
    samples = json.loads(completed.stdout)
    week = samples[str(7 * 24)]
    month = samples[str(30 * 24)]

    assert week[1:] == month[1:]
    assert month[1] == 64
    assert month[3:] == [0, 0]
    assert month[0] <= int(week[0] * 1.10) + (4 * 1024 * 1024)
