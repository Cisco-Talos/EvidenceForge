# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Host/persona/role activity profile loader and resolver.

The resolver intentionally works at coarse rate-family granularity. This keeps
baseline realism configurable without making every emitter and event subtype
carry its own profile knobs.
"""

from __future__ import annotations

import base64
import random
from dataclasses import dataclass
from typing import Any

from evidenceforge.config import get_activity_directory
from evidenceforge.config.overlay import deep_merge_dict, load_with_overlay
from evidenceforge.utils.rng import _stable_seed

_PROFILES_PATH = get_activity_directory() / "host_activity_profiles.yaml"
_CACHED_DATA: dict[str, Any] | None = None

RATE_FAMILIES = frozenset(
    {
        "user_activity",
        "web",
        "dns_interval",
        "ntp",
        "smb_interval",
        "kerberos",
        "ldap",
        "persona_connections",
        "role_network",
        "inbound_network",
        "windows_service_process",
        "windows_registry",
        "windows_scheduled_task",
        "windows_remote_thread",
        "windows_process_access",
        "windows_module_load",
        "windows_remote_admin",
        "windows_service_logon",
        "windows_machine_auth",
        "dc_kerberos",
        "linux_syslog",
        "linux_remote_admin",
        "linux_shell",
        "firewall_deny",
        "ids_alert",
        "icmp_monitoring",
    }
)


@dataclass(frozen=True)
class HostActivityProfile:
    """Resolved activity multipliers for one host/persona view."""

    hostname: str
    multipliers: dict[str, float]

    def multiplier(self, family: str) -> float:
        """Return a bounded multiplier for a rate family."""
        return self.multipliers.get(family, 1.0)


def load_host_activity_profiles() -> dict[str, Any]:
    """Load host activity profiles, merged with overlay. Cached after first call."""
    global _CACHED_DATA  # noqa: PLW0603
    if _CACHED_DATA is not None:
        return _CACHED_DATA
    _CACHED_DATA = load_with_overlay(
        _PROFILES_PATH,
        "activity/host_activity_profiles.yaml",
        deep_merge_dict,
    )
    return _CACHED_DATA


def reset_cache() -> None:
    """Clear cached data for tests."""
    global _CACHED_DATA  # noqa: PLW0603
    _CACHED_DATA = None


def _as_float(value: Any, default: float) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def _range_pair(value: Any, default: tuple[float, float]) -> tuple[float, float]:
    if not isinstance(value, list | tuple) or len(value) != 2:
        return default
    lo = _as_float(value[0], default[0])
    hi = _as_float(value[1], default[1])
    if lo <= 0 or hi <= 0:
        return default
    if lo > hi:
        return (hi, lo)
    return (lo, hi)


def _family_multiplier(profile: dict[str, Any] | None, family: str) -> float:
    if not isinstance(profile, dict):
        return 1.0
    families = profile.get("families", {})
    if not isinstance(families, dict):
        return 1.0
    return max(0.0, _as_float(families.get(family), 1.0))


def _bounds_for_family(data: dict[str, Any], family: str) -> tuple[float, float]:
    rate_families = data.get("rate_families", {})
    if not isinstance(rate_families, dict):
        return (0.25, 6.0)
    default_bounds = _range_pair(rate_families.get("default_bounds"), (0.25, 6.0))
    bounds = rate_families.get("bounds", {})
    if isinstance(bounds, dict) and family in bounds:
        return _range_pair(bounds[family], default_bounds)
    return default_bounds


def resolve_host_activity_profile(
    *,
    scenario_name: str,
    system: Any,
    roles: list[str] | None = None,
    persona: str | None = None,
) -> HostActivityProfile:
    """Resolve deterministic activity multipliers for a host/persona combination."""
    data = load_host_activity_profiles()
    host_type = str(getattr(system, "type", "workstation") or "workstation").lower()
    hostname = str(getattr(system, "hostname", "") or "<unknown>")
    normalized_roles = [role.lower() for role in roles or getattr(system, "roles", []) or []]
    if host_type == "domain_controller" and "domain_controller" not in normalized_roles:
        normalized_roles.append("domain_controller")

    host_profiles = data.get("host_types", {}) if isinstance(data, dict) else {}
    role_profiles = data.get("role_profiles", {}) if isinstance(data, dict) else {}
    persona_profiles = data.get("persona_profiles", {}) if isinstance(data, dict) else {}
    host_profile = (
        host_profiles.get(host_type)
        if isinstance(host_profiles, dict) and isinstance(host_profiles.get(host_type), dict)
        else {}
    )
    base_multiplier = max(0.0, _as_float(host_profile.get("base_multiplier"), 1.0))
    variance_min, variance_max = _range_pair(host_profile.get("variance"), (1.0, 1.0))
    persona_profile = (
        persona_profiles.get(str(persona).lower())
        if persona and isinstance(persona_profiles, dict)
        else None
    )

    multipliers: dict[str, float] = {}
    for family in RATE_FAMILIES:
        host_variance_rng = random.Random(
            _stable_seed(f"host_activity:{scenario_name}:{hostname}:{family}")
        )
        multiplier = base_multiplier * host_variance_rng.uniform(variance_min, variance_max)
        multiplier *= _family_multiplier(host_profile, family)
        if isinstance(role_profiles, dict):
            for role in normalized_roles:
                role_profile = role_profiles.get(role)
                multiplier *= _family_multiplier(role_profile, family)
        multiplier *= _family_multiplier(persona_profile, family)

        low, high = _bounds_for_family(data, family)
        multipliers[family] = max(low, min(high, multiplier))

    return HostActivityProfile(hostname=hostname, multipliers=multipliers)


def scale_count_range(lo: int, hi: int, multiplier: float) -> tuple[int, int]:
    """Scale a randint-style count range while preserving a nonzero range."""
    lo = int(lo)
    hi = int(hi)
    if hi < lo:
        lo, hi = hi, lo
    scaled_lo = int(round(lo * multiplier))
    scaled_hi = int(round(hi * multiplier))
    if lo > 0:
        scaled_lo = max(1, scaled_lo)
        scaled_hi = max(scaled_lo, scaled_hi)
    else:
        scaled_lo = max(0, scaled_lo)
        scaled_hi = max(scaled_lo, scaled_hi)
    return scaled_lo, scaled_hi


def scale_interval_range(lo: int, hi: int, multiplier: float) -> tuple[int, int]:
    """Scale seconds-between-events ranges; higher multiplier means shorter intervals."""
    lo = int(lo)
    hi = int(hi)
    if hi < lo:
        lo, hi = hi, lo
    divisor = max(0.01, multiplier)
    scaled_lo = max(1, int(round(lo / divisor)))
    scaled_hi = max(scaled_lo, int(round(hi / divisor)))
    return scaled_lo, scaled_hi


def pick_firewall_deny_offset(
    *,
    rng: random.Random,
    sensor_name: str,
    current_hour_epoch: int,
    generated_index: int,
    multiplier: float,
) -> float | None:
    """Pick a bursty deny-event offset for an ASA/firewall baseline record."""
    data = load_host_activity_profiles()
    config = data.get("firewall_deny", {}) if isinstance(data, dict) else {}
    quiet_probability = _as_float(config.get("quiet_probability"), 0.08)
    if rng.random() < quiet_probability / max(0.5, multiplier):
        return None

    count_lo, count_hi = _range_pair(config.get("burst_window_count"), (2.0, 5.0))
    width_lo, width_hi = _range_pair(config.get("burst_width_seconds"), (20.0, 180.0))
    burst_count = max(1, int(round(rng.randint(int(count_lo), int(count_hi)) * multiplier)))
    burst_index = generated_index % burst_count
    burst_rng = random.Random(
        _stable_seed(f"firewall_deny_burst:{sensor_name}:{current_hour_epoch}:{burst_index}")
    )
    center = burst_rng.uniform(120, 3480)
    width = burst_rng.uniform(width_lo, width_hi)
    return max(0.0, min(3599.0, center + rng.gauss(0, width / 3.0)))


def firewall_deny_hash_values(rng: random.Random) -> tuple[str, str]:
    """Return ASA deny hash values with realistic mostly-zero behavior."""
    data = load_host_activity_profiles()
    config = data.get("firewall_deny", {}) if isinstance(data, dict) else {}
    probability = max(
        0.0, min(1.0, _as_float(config.get("metadata_hash_nonzero_probability"), 0.18))
    )
    if rng.random() >= probability:
        return ("0x0", "0x0")
    return (f"0x{rng.getrandbits(16):04x}", f"0x{rng.getrandbits(16):04x}")


def generate_encoded_powershell_command(
    *,
    rng: random.Random,
    hostname: str,
    username: str,
) -> str:
    """Generate a host-biased UTF-16LE PowerShell EncodedCommand payload."""
    data = load_host_activity_profiles()
    variants = data.get("artifact_variants", {}) if isinstance(data, dict) else {}
    ps_config = variants.get("powershell_encoded", {}) if isinstance(variants, dict) else {}
    templates = ps_config.get("templates", [])
    if not isinstance(templates, list) or not templates:
        templates = ["Get-Service -Name {svc}"]

    preferred_count = max(1, int(ps_config.get("host_preferred_template_count", 3)))
    host_rng = random.Random(_stable_seed(f"ps_encoded_templates:{hostname}:{username}"))
    preferred = list(templates)
    if len(preferred) > preferred_count:
        preferred = host_rng.sample(preferred, preferred_count)
    template = str(rng.choice(preferred))

    params = ps_config.get("params", {})
    if not isinstance(params, dict):
        params = {}
    command = template
    for key, values in params.items():
        placeholder = "{" + str(key) + "}"
        if placeholder not in command:
            continue
        if not isinstance(values, list) or not values:
            continue
        param_rng = random.Random(
            _stable_seed(f"ps_encoded_param:{hostname}:{username}:{key}:{rng.random()}")
        )
        command = command.replace(placeholder, str(param_rng.choice(values)))

    return base64.b64encode(command.encode("utf-16-le")).decode("ascii")
