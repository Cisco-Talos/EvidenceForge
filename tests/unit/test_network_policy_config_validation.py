# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT
"""Network policy schemas reach their owning CLI validation boundary."""

from copy import deepcopy

import pytest

from evidenceforge.generation.activity import network_params
from evidenceforge.validation.configuration import (
    SchemaCheck,
    ValidationResult,
    _collect_network_parameter_schema_checks,
)


def test_packaged_network_policies_are_validated_without_dispatch_errors() -> None:
    result = ValidationResult()
    checks: list[SchemaCheck] = []
    _collect_network_parameter_schema_checks(result, checks)
    assert not [issue for issue in result.errors if "http_" in issue.file]
    assert checks


@pytest.mark.parametrize(
    "family,patch",
    [
        ("http_request_phase", {"sigma": 0}),
        ("http_transport_floor_slack", {"minimum_ms": 2000}),
    ],
)
def test_invalid_network_timing_policy_is_reported_at_its_own_path(
    monkeypatch: pytest.MonkeyPatch, family: str, patch: dict[str, float]
) -> None:
    config = deepcopy(network_params.load_network_params())
    config[family].update(patch)
    monkeypatch.setattr(network_params, "load_network_params", lambda: config)
    result = ValidationResult()
    _collect_network_parameter_schema_checks(result, [])
    assert any(family in issue.file for issue in result.errors)
