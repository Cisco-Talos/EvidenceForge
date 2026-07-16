# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Tests for canonical standards-valid cryptographic payload planning."""

from __future__ import annotations

import base64
from datetime import UTC, datetime

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from pydantic import ValidationError

from evidenceforge.evaluation.parsers import ParsedRecord
from evidenceforge.evaluation.pillars.plausibility import (
    _score_cryptographic_protocol_consistency,
)
from evidenceforge.events.base import SecurityEvent
from evidenceforge.events.contexts import NetworkContext
from evidenceforge.generation.actions.ocsp_transaction import (
    OcspTransactionPlanner,
    OcspTransactionRequest,
)
from evidenceforge.generation.actions.tls_certificate import TlsCertificatePlanner
from evidenceforge.generation.activity.dns_txt import stable_dns_txt_record
from evidenceforge.generation.cryptographic_material import CryptographicMaterialRegistry
from evidenceforge.models.scenario import DnsQueryEventSpec

_EVENT_TIME = datetime(2024, 10, 14, 12, 0, tzinfo=UTC)
_ISSUER = "CN=R3, O=Let's Encrypt, C=US"
_ISSUER_CONFIG = {
    "name": _ISSUER,
    "validity_days_min": 90,
    "validity_days_max": 90,
    "not_before_max_days": 30,
}


def _presentation(
    registry: CryptographicMaterialRegistry,
    *,
    backend: str = "www.example.com",
    connection: str = "CTestTlsOne",
):
    planner = TlsCertificatePlanner(registry)
    return planner, planner.plan(
        backend_identity=backend,
        cert_name=backend,
        issuer_config=_ISSUER_CONFIG,
        event_time=_EVENT_TIME,
        connection_identity=connection,
        key_type="rsa",
        key_size=2048,
        san_dns=(backend,),
    )


def _tls_event(presentation, *, timestamp: datetime = _EVENT_TIME) -> SecurityEvent:
    return SecurityEvent(
        timestamp=timestamp,
        event_type="connection",
        network=NetworkContext(
            src_ip="10.0.10.25",
            src_port=51000,
            dst_ip="93.184.216.34",
            dst_port=443,
            protocol="tcp",
            service="ssl",
            zeek_uid="CTestTlsOne",
        ),
        tls_presentation=presentation,
    )


def test_generated_dkim_key_is_valid_selector_stable_rsa_spki() -> None:
    first, _ttl = stable_dns_txt_record("selector1._domainkey.sendgrid.net")
    second, _ttl = stable_dns_txt_record("selector1._domainkey.sendgrid.net")
    other, _ttl = stable_dns_txt_record("selector2._domainkey.sendgrid.net")
    encoded = first.split("p=", 1)[1]
    public_key = serialization.load_der_public_key(base64.b64decode(encoded, validate=True))

    assert first == second
    assert first != other
    assert isinstance(public_key, rsa.RSAPublicKey)
    assert public_key.key_size == 2048
    assert public_key.public_numbers().e == 65537


def test_typed_dkim_answer_validation_rejects_invalid_key() -> None:
    with pytest.raises(ValidationError, match="Base64 DER"):
        DnsQueryEventSpec(
            query="selector1._domainkey.example.com",
            qtype="TXT",
            answer="v=DKIM1; k=rsa; p=bm90LWFuLXJzYS1rZXk=",
        )


def test_rendered_cryptographic_evaluator_probe_accepts_valid_family() -> None:
    registry = CryptographicMaterialRegistry()
    tls_planner, presentation = _presentation(registry)
    planner = OcspTransactionPlanner(registry, tls_planner)
    issuer = tls_planner.authority_material(presentation.leaf.issuer_name)
    plan = planner.plan(
        OcspTransactionRequest(
            _tls_event(presentation), presentation.leaf, issuer, "www.example.com"
        )
    )
    dkim, _ttl = stable_dns_txt_record("selector1._domainkey.sendgrid.net")
    records = {
        "zeek_dns": [
            ParsedRecord(
                source_format="zeek_dns",
                raw="",
                fields={
                    "query": "selector1._domainkey.sendgrid.net",
                    "answers": [dkim],
                },
            )
        ],
        "zeek_http": [
            ParsedRecord(
                source_format="zeek_http",
                raw="",
                fields={
                    "uri": plan.request_path,
                    "resp_mime_types": ["application/ocsp-response"],
                    "resp_fuids": [plan.file_id],
                },
            )
        ],
        "zeek_ocsp": [
            ParsedRecord(
                source_format="zeek_ocsp",
                raw="",
                fields={
                    "id": plan.file_id,
                    "hashAlgorithm": plan.hash_algorithm,
                    "issuerNameHash": plan.issuer_name_hash.hex(),
                    "issuerKeyHash": plan.issuer_key_hash.hex(),
                    "serialNumber": plan.certificate.serial_number,
                },
            )
        ],
        "zeek_ssl": [],
        "zeek_x509": [],
    }

    matched, agreeing, failures = _score_cryptographic_protocol_consistency(records)

    assert (matched, agreeing, failures) == (2, 2, [])
