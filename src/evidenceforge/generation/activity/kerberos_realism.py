# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Kerberos realism configuration loader and pickers."""

from __future__ import annotations

import random
from typing import Any

from evidenceforge.config import get_activity_directory
from evidenceforge.config.overlay import deep_merge_dict, load_with_overlay

_CONFIG_PATH = get_activity_directory() / "kerberos_realism.yaml"
_CACHED_DATA: dict[str, Any] | None = None


def _merge_kerberos_realism(default: dict, overlay: dict) -> dict:
    """Merge Kerberos realism overlay with package defaults."""
    return deep_merge_dict(default, overlay)


def load_kerberos_realism() -> dict[str, Any]:
    """Load Kerberos realism config from YAML, merged with overlay."""
    global _CACHED_DATA
    if _CACHED_DATA is not None:
        return _CACHED_DATA

    _CACHED_DATA = load_with_overlay(
        _CONFIG_PATH,
        "activity/kerberos_realism.yaml",
        _merge_kerberos_realism,
    )
    return _CACHED_DATA


def reset_kerberos_realism_cache() -> None:
    """Clear cached Kerberos realism config. Intended for tests."""
    global _CACHED_DATA
    _CACHED_DATA = None


def pick_tgt_success_fields(rng: random.Random) -> dict[str, Any]:
    """Pick coherent 4768 success fields from Kerberos realism config."""
    cfg = load_kerberos_realism()
    tgt_success = cfg.get("tgt_success", {})
    pre_auth = _pick_weighted_profile(tgt_success.get("pre_auth_types", {}), rng)
    certificate_fields = _certificate_fields(pre_auth, rng)
    return {
        "ticket_options": _pick_weighted_value(tgt_success.get("ticket_options", {}), rng),
        "encryption_type": _pick_weighted_value(tgt_success.get("encryption_types", {}), rng),
        "pre_auth_type": int(pre_auth.get("value", 2)),
        **certificate_fields,
    }


def _pick_weighted_value(profiles: dict[str, dict[str, Any]], rng: random.Random) -> str:
    """Pick a configured weighted profile and return its value."""
    profile = _pick_weighted_profile(profiles, rng)
    return str(profile.get("value", ""))


def _pick_weighted_profile(
    profiles: dict[str, dict[str, Any]], rng: random.Random
) -> dict[str, Any]:
    """Pick one profile from a keyed weighted profile dict."""
    valid_profiles = [
        profile
        for profile in profiles.values()
        if isinstance(profile, dict) and int(profile.get("weight", 0)) > 0
    ]
    if not valid_profiles:
        return {}
    weights = [int(profile.get("weight", 1)) for profile in valid_profiles]
    return rng.choices(valid_profiles, weights=weights, k=1)[0]


def _certificate_fields(pre_auth: dict[str, Any], rng: random.Random) -> dict[str, str]:
    """Return 4768 certificate fields for certificate-based pre-auth."""
    if not pre_auth.get("certificate_required", False):
        return {
            "cert_issuer_name": "",
            "cert_serial_number": "",
            "cert_thumbprint": "",
        }

    cfg = load_kerberos_realism()
    profile_name = str(pre_auth.get("certificate_profile", ""))
    profile = cfg.get("certificate_profiles", {}).get(profile_name, {})
    issuer_names = profile.get("issuer_names", [])
    issuer_name = rng.choice(issuer_names) if issuer_names else ""
    serial_hex_bytes = int(profile.get("serial_hex_bytes", 16))
    thumbprint_hex_chars = int(profile.get("thumbprint_hex_chars", 40))
    serial = "".join(f"{rng.randrange(256):02X}" for _ in range(serial_hex_bytes))
    thumbprint = "".join(rng.choice("0123456789ABCDEF") for _ in range(thumbprint_hex_chars))
    return {
        "cert_issuer_name": issuer_name,
        "cert_serial_number": serial,
        "cert_thumbprint": thumbprint,
    }
