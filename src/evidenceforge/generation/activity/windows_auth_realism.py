# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Windows authentication realism configuration loader."""

from __future__ import annotations

import math
import random
from typing import Any, Literal

from evidenceforge.config import get_activity_directory
from evidenceforge.config.overlay import deep_merge_dict, load_with_overlay
from evidenceforge.config.schemas import (
    WindowsAnonymousSmbBaselineConfig,
    WindowsRemoteAuthTransportConfig,
)
from evidenceforge.generation.baseline_timing import BaselineTimingPlanner
from evidenceforge.generation.source_timing import SourceTimingPlanner
from evidenceforge.generation.timing import TimingRuntime
from evidenceforge.utils.rng import _stable_seed

_CONFIG_PATH = get_activity_directory() / "windows_auth_realism.yaml"
_CACHED_DATA: dict[str, Any] | None = None
_CACHED_REMOTE_AUTH_TRANSPORT: WindowsRemoteAuthTransportConfig | None = None
_CACHED_ANONYMOUS_SMB_BASELINE: WindowsAnonymousSmbBaselineConfig | None = None
_DEFAULT_MIN_UNLOCK_GAP_SECONDS = 127
_MIN_UNLOCK_GAP_SECONDS = 60
_MAX_UNLOCK_GAP_SECONDS = 86_400
_MACHINE_ACCOUNT_LOGOFF_DELAY_MAX_SECONDS = 30.0
_MACHINE_ACCOUNT_ENDPOINT_FORMATS = ("ecar", "windows_event_security")


def load_windows_auth_realism() -> dict[str, Any]:
    """Load Windows authentication realism config, merged with overlay."""
    global _CACHED_DATA
    if _CACHED_DATA is None:
        _CACHED_DATA = load_with_overlay(
            _CONFIG_PATH,
            "activity/windows_auth_realism.yaml",
            deep_merge_dict,
        )
    return _CACHED_DATA


def reset_windows_auth_realism_cache() -> None:
    """Clear cached Windows auth realism config. Intended for tests."""
    global _CACHED_ANONYMOUS_SMB_BASELINE, _CACHED_DATA, _CACHED_REMOTE_AUTH_TRANSPORT
    _CACHED_DATA = None
    _CACHED_REMOTE_AUTH_TRANSPORT = None
    _CACHED_ANONYMOUS_SMB_BASELINE = None


def workstation_lock_config() -> dict[str, Any]:
    """Return workstation lock/unlock realism settings."""
    config = load_windows_auth_realism().get("workstation_lock", {})
    return config if isinstance(config, dict) else {}


def min_unlock_gap_seconds() -> int:
    """Return the minimum realistic gap between a 4800 lock and 4801 unlock."""
    value = workstation_lock_config().get("min_unlock_gap_seconds", _DEFAULT_MIN_UNLOCK_GAP_SECONDS)
    try:
        seconds = int(value)
    except (TypeError, ValueError):
        return _DEFAULT_MIN_UNLOCK_GAP_SECONDS
    return max(_MIN_UNLOCK_GAP_SECONDS, min(seconds, _MAX_UNLOCK_GAP_SECONDS))


def group_policy_refresh_config() -> dict[str, Any]:
    """Return host-scoped Group Policy refresh scheduling and command profiles."""

    config = load_windows_auth_realism().get("group_policy_refresh", {})
    return config if isinstance(config, dict) else {}


def remote_auth_transport_config() -> WindowsRemoteAuthTransportConfig:
    """Return validated source/outcome-aware remote-auth transport profiles."""

    global _CACHED_REMOTE_AUTH_TRANSPORT
    if _CACHED_REMOTE_AUTH_TRANSPORT is None:
        _CACHED_REMOTE_AUTH_TRANSPORT = WindowsRemoteAuthTransportConfig.model_validate(
            load_windows_auth_realism().get("remote_auth_transport", {})
        )
    return _CACHED_REMOTE_AUTH_TRANSPORT


def remote_auth_transport_max_duration_seconds(
    *,
    source: str,
    outcome: Literal["success", "failure"],
) -> float:
    """Return the configured maximum duration for one remote-auth transport."""

    config = remote_auth_transport_config()
    source_profiles = config.sources.get(source, config.defaults)
    profile_name = source_profiles.success if outcome == "success" else source_profiles.failure
    maximum_seconds = config.profiles[profile_name].maximum_seconds
    # Successful transports are planned around the authentication anchor. If
    # an overlay's configured maximum is shorter than the sampled lead, the
    # owner extends the transport to close at least 250 ms after authentication.
    return max(maximum_seconds, 0.25) if outcome == "success" else maximum_seconds


def machine_account_authentication_close_bound_seconds(
    *,
    endpoint_clock_headroom_seconds: float = 0.0,
    network_sensor_headroom_seconds: float = 0.0,
) -> float:
    """Return the full machine-auth family bound through visible session closure."""

    headrooms = (endpoint_clock_headroom_seconds, network_sensor_headroom_seconds)
    if any(not math.isfinite(headroom) or headroom < 0 for headroom in headrooms):
        raise ValueError("machine-account runtime headrooms must be finite and non-negative")
    endpoint_close_tail = SourceTimingPlanner.max_session_closure_tail(
        _MACHINE_ACCOUNT_ENDPOINT_FORMATS
    ).total_seconds()
    return max(
        remote_auth_transport_max_duration_seconds(
            source="machine_account_logon",
            outcome="success",
        )
        + network_sensor_headroom_seconds,
        _MACHINE_ACCOUNT_LOGOFF_DELAY_MAX_SECONDS
        + endpoint_clock_headroom_seconds
        + endpoint_close_tail,
    )


def sample_remote_auth_transport_duration(
    *,
    source: str,
    outcome: Literal["success", "failure"],
    rng: random.Random,
    timing_runtime: TimingRuntime | None = None,
    stable_id: str = "",
    minimum_seconds: float | None = None,
) -> float:
    """Sample one deterministic, bounded, right-skew remote-auth duration."""

    config = remote_auth_transport_config()
    source_profiles = config.sources.get(source, config.defaults)
    profile_name = source_profiles.success if outcome == "success" else source_profiles.failure
    profile = config.profiles[profile_name]
    scope_id = stable_id or f"compat-{_stable_seed(repr(rng.getstate())):016x}"
    minimum = max(profile.minimum_seconds, minimum_seconds or profile.minimum_seconds)
    return BaselineTimingPlanner(
        timing_runtime or TimingRuntime.compatibility_default(),
        source="windows-remote-auth",
    ).right_skew_seconds(
        relationship_key="windows.remote_auth.transport_duration",
        stable_id=f"{scope_id}:{source}:{outcome}:{profile_name}",
        minimum=minimum,
        median=max(minimum + 0.000001, profile.median_seconds),
        maximum=profile.maximum_seconds,
        sigma=profile.sigma,
        lifecycle_id=scope_id,
        sample_key="duration",
    )


def anonymous_smb_baseline_config() -> WindowsAnonymousSmbBaselineConfig:
    """Return validated sparse anonymous-SMB baseline cadence."""

    global _CACHED_ANONYMOUS_SMB_BASELINE
    if _CACHED_ANONYMOUS_SMB_BASELINE is None:
        _CACHED_ANONYMOUS_SMB_BASELINE = WindowsAnonymousSmbBaselineConfig.model_validate(
            load_windows_auth_realism().get("anonymous_smb_baseline", {})
        )
    return _CACHED_ANONYMOUS_SMB_BASELINE


def failed_logon_config() -> dict[str, Any]:
    """Return failed-logon source-native field profiles."""
    config = load_windows_auth_realism().get("failed_logon", {})
    return config if isinstance(config, dict) else {}


def special_privileges_config() -> dict[str, Any]:
    """Return Windows 4672 privilege profile config."""
    config = load_windows_auth_realism().get("special_privileges", {})
    return config if isinstance(config, dict) else {}
