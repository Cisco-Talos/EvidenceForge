# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT
"""TLS timing policy overlays preserve defaults and reject invalid declared intent."""

from copy import deepcopy
from typing import Any

import pytest
from pydantic import ValidationError

from evidenceforge.config.schemas import TlsDetectionPhaseConfig
from evidenceforge.generation.activity import network_params

_POLICY = {"minimum_ms": 3, "median_ms": 119.46, "maximum_ms": 650, "sigma": 0.78}


def test_partial_tls_overlay_preserves_other_policy_values(monkeypatch: pytest.MonkeyPatch) -> None:
    default = {"tls_detection_phase": deepcopy(_POLICY)}
    merged = network_params.merge_network_params(
        default, {"tls_detection_phase": {"median_ms": 80}}
    )
    monkeypatch.setattr(network_params, "load_network_params", lambda: merged)
    profile = network_params.tls_detection_phase_config()
    assert profile is not None and profile.median_ms == 80
    assert profile.minimum_ms == 3 and profile.maximum_ms == 650 and profile.sigma == 0.78
    assert default["tls_detection_phase"] == _POLICY


@pytest.mark.parametrize("value", [None, "invalid", []])
def test_invalid_overlay_is_retained_for_typed_rejection(
    monkeypatch: pytest.MonkeyPatch, value: Any
) -> None:
    merged = network_params.merge_network_params(
        {"tls_detection_phase": deepcopy(_POLICY)}, {"tls_detection_phase": value}
    )
    monkeypatch.setattr(network_params, "load_network_params", lambda: merged)
    with pytest.raises(ValidationError):
        network_params.tls_detection_phase_config()


@pytest.mark.parametrize(
    "patch",
    [
        {"minimum_ms": True},
        {"median_ms": 1},
        {"maximum_ms": float("inf")},
        {"minimum_ms": float("nan")},
        {"sigma": 0},
        {"extra": 1},
    ],
)
def test_declared_tls_policy_is_finite_ordered_and_strict(patch: dict[str, Any]) -> None:
    with pytest.raises(ValidationError):
        TlsDetectionPhaseConfig.model_validate({**_POLICY, **patch})
