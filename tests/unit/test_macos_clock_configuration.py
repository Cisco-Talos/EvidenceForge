# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

from copy import deepcopy

import pytest

from evidenceforge.generation.activity import timing_profiles
from evidenceforge.validation.configuration import ValidationResult, _validate_timing_profiles


def _validate(data: dict) -> list[str]:
    result = ValidationResult()
    _validate_timing_profiles(
        dns_domain_set=set(),
        domains=[],
        proxy_domains=set(),
        result=result,
        site_domains=set(),
        site_referenced_hosts=set(),
        timing_profiles_data=data,
    )
    return [issue.message for issue in result.issues if "endpoint_clock" in issue.message]


@pytest.mark.parametrize("platform", ["macos", "windows", "linux"])
@pytest.mark.parametrize(
    "field,minimum,maximum",
    [
        ("host_offset_ms", 5, 4),
        ("host_offset_ms", -300001, 0),
        ("host_offset_ms", 0, 300001),
        ("host_drift_ppm", -501, 0),
        ("host_drift_ppm", 0, 501),
        ("host_drift_ppm", False, True),
        ("host_offset_ms", "0", 1),
    ],
)
def test_endpoint_clock_validation_rejects_bad_values_on_each_supported_platform(
    platform: str, field: str, minimum: object, maximum: object
) -> None:
    data = deepcopy(timing_profiles.load_timing_profiles())
    data["endpoint_clock"]["profiles"]["complete"][platform][field] = {
        "min": minimum,
        "max": maximum,
    }
    messages = _validate(data)
    assert messages and all(f"complete.{platform}.{field}" in message for message in messages)


def test_missing_mac_profile_preserves_legacy_zero_clock_semantics(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    data = deepcopy(timing_profiles.load_timing_profiles())
    for profile in data["endpoint_clock"]["profiles"].values():
        profile.pop("macos", None)
    assert _validate(data) == []
    monkeypatch.setattr(timing_profiles, "load_timing_profiles", lambda: data)
    timing = timing_profiles.endpoint_clock_timing("enterprise_standard", "macos")
    assert timing.host_offset_min_ms == timing.host_offset_max_ms == 0
    assert timing.host_drift_min_ppm == timing.host_drift_max_ppm == 0


@pytest.mark.parametrize("invalid", [None, [], "linux"])
def test_present_mac_profile_cannot_silently_fall_back(invalid: object) -> None:
    data = deepcopy(timing_profiles.load_timing_profiles())
    data["endpoint_clock"]["profiles"]["complete"]["macos"] = invalid
    assert any("complete.macos must be a mapping" in message for message in _validate(data))


def test_packaged_mac_clock_profiles_pass_existing_range_contracts() -> None:
    assert _validate(deepcopy(timing_profiles.load_timing_profiles())) == []
