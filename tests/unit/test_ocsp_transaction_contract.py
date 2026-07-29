# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Tests for standards-valid canonical OCSP transaction planning."""

from __future__ import annotations

import base64
from datetime import UTC, datetime, timedelta
from urllib.parse import unquote

import pytest
from cryptography.x509.ocsp import load_der_ocsp_request

from evidenceforge.events.base import SecurityEvent
from evidenceforge.events.contexts import NetworkContext
from evidenceforge.generation.actions.ocsp_transaction import (
    OcspTransactionActionBundle,
    OcspTransactionPlanner,
    OcspTransactionRequest,
)
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
    backend: str = "www.example.com",
):
    planner = TlsCertificatePlanner(registry)
    return planner, planner.plan(
        backend_identity=backend,
        cert_name=backend,
        issuer_config=_ISSUER_CONFIG,
        event_time=_EVENT_TIME,
        connection_identity="CTestTlsOne",
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


def test_ocsp_request_round_trips_exact_certificate_and_issuer_identity() -> None:
    registry = CryptographicMaterialRegistry()
    tls_planner, presentation = _presentation(registry)
    planner = OcspTransactionPlanner(registry, tls_planner)
    issuer = tls_planner.authority_material(presentation.leaf.issuer_name)
    request = OcspTransactionRequest(
        tls_event=_tls_event(presentation),
        certificate=presentation.leaf,
        issuer=issuer,
        cert_name="www.example.com",
    )

    plan = planner.plan(request)
    parsed = load_der_ocsp_request(plan.request_der)
    path_der = base64.b64decode(unquote(plan.request_path.lstrip("/")), validate=True)

    assert path_der == plan.request_der
    assert parsed.serial_number == presentation.leaf.serial_number_int
    assert parsed.issuer_name_hash == plan.issuer_name_hash
    assert parsed.issuer_key_hash == plan.issuer_key_hash
    assert parsed.hash_algorithm.name == plan.hash_algorithm == "sha1"
    assert plan.certificate_status == "good"
    assert plan.revocation_time is None


def test_ocsp_cache_bucket_is_stable_and_certificate_identity_changes_request() -> None:
    registry = CryptographicMaterialRegistry()
    tls_planner, presentation = _presentation(registry)
    planner = OcspTransactionPlanner(registry, tls_planner)
    issuer = tls_planner.authority_material(presentation.leaf.issuer_name)
    first = planner.plan(
        OcspTransactionRequest(
            _tls_event(presentation), presentation.leaf, issuer, "www.example.com"
        )
    )
    second = planner.plan(
        OcspTransactionRequest(
            _tls_event(presentation, timestamp=_EVENT_TIME + timedelta(minutes=5)),
            presentation.leaf,
            issuer,
            "www.example.com",
        )
    )
    _, other_presentation = _presentation(registry, backend="api.example.com")
    other = planner.plan(
        OcspTransactionRequest(
            _tls_event(other_presentation), other_presentation.leaf, issuer, "api.example.com"
        )
    )

    assert first.request_der == second.request_der
    assert (first.this_update, first.next_update) == (second.this_update, second.next_update)
    assert other.request_der != first.request_der


@pytest.mark.parametrize("status", ["unknown", "revoked"])
def test_non_good_ocsp_status_requires_explicit_profile(monkeypatch, status: str) -> None:
    from evidenceforge.generation.actions import ocsp_transaction as ocsp_module

    registry = CryptographicMaterialRegistry()
    tls_planner, presentation = _presentation(registry)
    planner = OcspTransactionPlanner(registry, tls_planner)
    issuer = tls_planner.authority_material(presentation.leaf.issuer_name)
    monkeypatch.setattr(
        ocsp_module,
        "ocsp_config",
        lambda: {
            "request_hash_algorithm": "sha1",
            "cache_bucket_seconds": 14400,
            "this_update_max_skew_seconds": 3600,
            "next_update_min_seconds": 28800,
            "next_update_max_seconds": 604800,
            "certificate_status_profiles": [
                {
                    "name": f"explicit_{status}",
                    "certificate_patterns": ["www.example.com"],
                    "status_weights": {
                        "good": 0,
                        "unknown": 100 if status == "unknown" else 0,
                        "revoked": 100 if status == "revoked" else 0,
                    },
                    "revocation_reasons": ["keyCompromise"],
                }
            ],
        },
    )

    plan = planner.plan(
        OcspTransactionRequest(
            _tls_event(presentation), presentation.leaf, issuer, "www.example.com"
        )
    )

    assert plan.certificate_status == status
    assert (plan.revocation_time is not None) is (status == "revoked")
    assert (plan.revocation_reason is not None) is (status == "revoked")


def test_ocsp_action_bundle_builds_all_contexts_from_one_plan() -> None:
    registry = CryptographicMaterialRegistry()
    tls_planner, presentation = _presentation(registry)
    planner = OcspTransactionPlanner(registry, tls_planner)
    issuer = tls_planner.authority_material(presentation.leaf.issuer_name)

    class Executor:
        _ip_to_system: dict[str, object] = {}

        def __init__(self) -> None:
            self.kwargs = None

        def generate_connection(self, **kwargs):
            self.kwargs = kwargs
            return "COcsp"

    executor = Executor()
    plan = OcspTransactionActionBundle(
        executor,
        planner,
        OcspTransactionRequest(
            _tls_event(presentation), presentation.leaf, issuer, "www.example.com"
        ),
    ).execute()

    assert executor.kwargs is not None
    assert executor.kwargs["http"].uri == plan.request_path
    assert executor.kwargs["http"].resp_fuids == [plan.file_id]
    assert executor.kwargs["file_transfer"].fuid == plan.file_id
    assert executor.kwargs["ocsp"].serial_number == plan.certificate.serial_number
    assert executor.kwargs["ocsp_transaction"] is plan
    assert executor.kwargs.get("proxy_bypass") is None
