# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT
"""Frozen TLS policy compatibility reaches the real configuration provider and validator."""

from copy import deepcopy
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from unittest.mock import Mock

import pytest
from pydantic import ValidationError

from evidenceforge.composition.compiler import build_management_effective_config
from evidenceforge.config.provider import effective_config_scope
from evidenceforge.events.contexts import SslContext
from evidenceforge.generation.actions import NetworkConnectionRequest
from evidenceforge.generation.actions.network_transaction_planner import NetworkTransactionPlanner
from evidenceforge.generation.activity.network_params import tls_detection_phase_config
from evidenceforge.validation.configuration import (
    ValidationResult,
    _collect_network_parameter_schema_checks,
)


def test_old_frozen_catalog_omits_new_phase_without_sampling_and_restores_current(
    tmp_path: Path,
) -> None:
    current = build_management_effective_config(tmp_path)
    packaged = deepcopy(current.packaged_defaults)
    packaged["activity/network_params.yaml"].pop("tls_detection_phase")
    legacy = current.model_copy(update={"packaged_defaults": packaged})
    sample = Mock(
        side_effect=AssertionError("Legacy configuration must not sample a new TLS phase")
    )
    planner = NetworkTransactionPlanner(
        SimpleNamespace(
            timing_runtime=SimpleNamespace(sampler=SimpleNamespace(sample_timedelta=sample))
        )
    )
    at = datetime(2026, 11, 2, 13, tzinfo=UTC)
    request = NetworkConnectionRequest(
        src_ip="10.0.0.10", dst_ip="10.0.1.20", time=at, dst_port=443, service="ssl"
    )
    event = SimpleNamespace(
        ssl=SslContext(version="TLSv13"),
        x509=None,
        x509_chain=(),
        network=SimpleNamespace(application_layer_only=False),
    )
    with effective_config_scope(legacy, refresh_legacy_globals=False):
        assert tls_detection_phase_config() is None
        assert planner._tls_detection_time(request, event, at, None) is None
        sample.assert_not_called()
    with effective_config_scope(current, refresh_legacy_globals=False):
        profile = tls_detection_phase_config()
        assert profile is not None and profile.median_ms == 119.46


@pytest.mark.parametrize("mutation", ["null", "empty", "boolean", "reversed", "infinite", "extra"])
def test_actual_frozen_tls_policy_is_rejected_at_named_validation_path(
    tmp_path: Path, mutation: str
) -> None:
    current = build_management_effective_config(tmp_path)
    packaged = deepcopy(current.packaged_defaults)
    policy: dict[str, Any] = packaged["activity/network_params.yaml"]["tls_detection_phase"]
    if mutation == "null":
        packaged["activity/network_params.yaml"]["tls_detection_phase"] = None
    elif mutation == "empty":
        packaged["activity/network_params.yaml"]["tls_detection_phase"] = {}
    elif mutation == "boolean":
        policy["minimum_ms"] = True
    elif mutation == "reversed":
        policy["median_ms"] = 1
    elif mutation == "infinite":
        policy["maximum_ms"] = float("inf")
    else:
        policy["extra"] = 1
    invalid = current.model_copy(update={"packaged_defaults": packaged})
    with effective_config_scope(invalid, refresh_legacy_globals=False):
        with pytest.raises(ValidationError):
            tls_detection_phase_config()
        result = ValidationResult()
        _collect_network_parameter_schema_checks(result, [])
        assert any("tls_detection_phase" in issue.file for issue in result.errors)
