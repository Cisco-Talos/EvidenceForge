# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT
"""RDP traffic support reaches frozen providers, validation and exact old draws."""

import random
from copy import deepcopy
from pathlib import Path

import pytest
from pydantic import ValidationError

from evidenceforge.composition.compiler import build_management_effective_config
from evidenceforge.config.provider import effective_config_scope
from evidenceforge.generation.activity.network_params import (
    merge_network_params,
    rdp_payload_bounds,
    sample_rdp_payload_bytes,
)
from evidenceforge.validation.configuration import (
    ValidationResult,
    _collect_network_parameter_schema_checks,
)


def test_current_and_old_frozen_support_keep_exact_payload_draws(tmp_path: Path) -> None:
    current = build_management_effective_config(tmp_path)
    packaged = deepcopy(current.packaged_defaults)
    packaged["activity/network_params.yaml"].pop("rdp_payload_bounds")
    legacy = current.model_copy(update={"packaged_defaults": packaged})
    for configuration in (current, legacy, current):
        with effective_config_scope(configuration, refresh_legacy_globals=False):
            actual, historical = random.Random(123), random.Random(123)
            assert [sample_rdp_payload_bytes(actual) for _ in range(200)] == [
                (historical.randint(50000, 500000), historical.randint(100000, 2000000))
                for _ in range(200)
            ]
            assert actual.getstate() == historical.getstate()


def test_custom_support_and_partial_overlay_are_shared_and_bounded(tmp_path: Path) -> None:
    current = build_management_effective_config(tmp_path)
    packaged = deepcopy(current.packaged_defaults)
    data = packaged["activity/network_params.yaml"]
    merged = merge_network_params(
        data, {"rdp_payload_bounds": {"responder_maximum_bytes": 3000000}}
    )
    assert merged["rdp_payload_bounds"]["initiator_maximum_bytes"] == 500000
    data["rdp_payload_bounds"] = merged["rdp_payload_bounds"]
    custom = current.model_copy(update={"packaged_defaults": packaged})
    with effective_config_scope(custom, refresh_legacy_globals=False):
        profile = rdp_payload_bounds()
        assert profile.responder_maximum_bytes == 3000000
        rng = random.Random(7)
        samples = [sample_rdp_payload_bytes(rng) for _ in range(100)]
        assert all(50000 <= o <= 500000 and 100000 <= r <= 3000000 for o, r in samples)
        assert max(r for _o, r in samples) > 2000000


@pytest.mark.parametrize("mutation", ["null", "empty", "boolean", "reversed", "extra"])
def test_invalid_rdp_payload_policy_has_named_validator_error(
    tmp_path: Path, mutation: str
) -> None:
    current = build_management_effective_config(tmp_path)
    packaged = deepcopy(current.packaged_defaults)
    data = packaged["activity/network_params.yaml"]
    if mutation == "null":
        data["rdp_payload_bounds"] = None
    elif mutation == "empty":
        data["rdp_payload_bounds"] = {}
    elif mutation == "boolean":
        data["rdp_payload_bounds"]["initiator_minimum_bytes"] = True
    elif mutation == "reversed":
        data["rdp_payload_bounds"]["responder_minimum_bytes"] = 3000000
    else:
        data["rdp_payload_bounds"]["typo"] = 1
    invalid = current.model_copy(update={"packaged_defaults": packaged})
    with effective_config_scope(invalid, refresh_legacy_globals=False):
        with pytest.raises(ValidationError):
            rdp_payload_bounds()
        result = ValidationResult()
        _collect_network_parameter_schema_checks(result, [])
        assert any("rdp_payload_bounds" in issue.file for issue in result.errors)
    assert (
        merge_network_params(
            current.packaged_defaults["activity/network_params.yaml"], {"rdp_payload_bounds": None}
        )["rdp_payload_bounds"]
        is None
    )
