# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Tests for canonical cryptographic material and TLS presentation planning."""

from dataclasses import FrozenInstanceError
from datetime import UTC, datetime

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa

from evidenceforge.generation.actions.tls_certificate import TlsCertificatePlanner
from evidenceforge.generation.cryptographic_material import CryptographicMaterialRegistry

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
