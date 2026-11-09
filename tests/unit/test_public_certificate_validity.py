# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Public subscriber issuance policies do not constrain private or CA lifetimes."""

from datetime import UTC, datetime, timedelta

import pytest
from pydantic import ValidationError

from evidenceforge.config.schemas import PublicLeafValidityConfig
from evidenceforge.generation.actions.tls_certificate import TlsCertificatePlanner
from evidenceforge.generation.activity.tls_issuers import load_tls_issuers
from evidenceforge.generation.activity.tls_realism import public_leaf_validity_period
from evidenceforge.generation.cryptographic_material import CryptographicMaterialRegistry


@pytest.mark.parametrize(
    ("date", "days"),
    [
        ("2026-03-14", 397),
        ("2026-03-15", 199),
        ("2027-03-14", 199),
        ("2027-03-15", 99),
        ("2029-03-14", 99),
        ("2029-03-15", 46),
        ("2030-01-01", 46),
    ],
)
def test_public_leaf_issuance_era_bounds_and_private_sibling(date: str, days: int) -> None:
    event = datetime.fromisoformat(date).replace(tzinfo=UTC) + timedelta(hours=12)
    planner = TlsCertificatePlanner(CryptographicMaterialRegistry())
    arguments = {
        "identity": "leaf:policy-example",
        "backend_identity": "example.test",
        "subject_name": "CN=example.test",
        "event_time": event,
        "validity_days_min": 397,
        "validity_days_max": 397,
        "not_before_max_days": 300,
    }
    public = planner._validity_window(**arguments, publicly_trusted_leaf=True)
    private = planner._validity_window(**arguments)
    assert public[1] - public[0] == days * 86400
    assert private[1] - private[0] == 397 * 86400
    assert public[0] < event.timestamp() < public[1]
    assert private[0] < event.timestamp() < private[1]
    # Independent lookup order cannot mutate either certificate interval.
    assert planner._validity_window(**arguments, publicly_trusted_leaf=True) == public
    assert public_leaf_validity_period(event)[1] == days


def test_public_trust_is_explicit_issuer_metadata() -> None:
    issuers = load_tls_issuers()["issuers"]
    assert all(issuer["publicly_trusted"] for issuer in issuers if issuer["weight"] > 0)
    enterprise = next(issuer for issuer in issuers if "Acme Enterprise" in issuer["name"])
    assert enterprise["publicly_trusted"] is False


@pytest.mark.parametrize(
    "periods",
    [
        [],
        [{"effective_date": "2026-03-15", "recommended_days": 199, "maximum_days": 200}],
        [{"effective_date": "1970-01-01", "recommended_days": 201, "maximum_days": 200}],
        [{"effective_date": "1970-01-01", "recommended_days": 0, "maximum_days": 200}],
        [
            {"effective_date": "1970-01-01", "recommended_days": 397, "maximum_days": 398},
            {"effective_date": "1970-01-01", "recommended_days": 199, "maximum_days": 200},
        ],
    ],
)
def test_public_policy_rejects_invalid_eras(periods: list[dict[str, object]]) -> None:
    with pytest.raises(ValidationError):
        PublicLeafValidityConfig.model_validate({"periods": periods})
