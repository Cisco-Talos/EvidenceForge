# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Kerberos realism configuration loader and pickers."""

from __future__ import annotations

import random
from dataclasses import dataclass
from typing import Any, Literal

from evidenceforge.config import get_activity_directory
from evidenceforge.config.overlay import deep_merge_dict, load_with_overlay
from evidenceforge.utils.rng import _stable_seed

_CONFIG_PATH = get_activity_directory() / "kerberos_realism.yaml"
_CACHED_DATA: dict[str, Any] | None = None
_MAX_SELECTION_WEIGHT = 1_000_000
KerberosPrincipalScope = Literal["user", "machine"]


@dataclass(frozen=True, slots=True)
class KerberosCredentialIdentity:
    """Stable certificate identity owned by one directory principal and credential epoch."""

    issuer_name: str
    serial_number: str
    thumbprint: str


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


def pick_tgt_success_fields(
    rng: random.Random,
    ad_domain: str = "",
    *,
    allow_no_preauth: bool = False,
    principal_sid: str = "",
    principal_scope: KerberosPrincipalScope = "user",
) -> dict[str, Any]:
    """Pick coherent 4768 success fields from Kerberos realism config."""
    cfg = load_kerberos_realism()
    tgt_success = cfg.get("tgt_success", {})
    pre_auth_profiles = tgt_success.get("pre_auth_types", {})
    pre_auth_profiles = {
        name: profile
        for name, profile in pre_auth_profiles.items()
        if not isinstance(profile, dict)
        or _profile_allows_scope(profile, principal_scope, cfg.get("certificate_profiles", {}))
    }
    if not allow_no_preauth:
        pre_auth_profiles = {
            name: profile
            for name, profile in pre_auth_profiles.items()
            if not isinstance(profile, dict) or int(profile.get("value", 2)) != 0
        }
    pre_auth = _pick_weighted_profile(pre_auth_profiles, rng)
    certificate_fields = _certificate_fields(
        pre_auth,
        rng,
        ad_domain,
        principal_sid=principal_sid,
        principal_scope=principal_scope,
    )
    return {
        "ticket_options": _pick_weighted_value(tgt_success.get("ticket_options", {}), rng),
        "encryption_type": _pick_weighted_value(tgt_success.get("encryption_types", {}), rng),
        "pre_auth_type": int(pre_auth.get("value", 2)),
        **certificate_fields,
    }


def pick_tgt_failure_fields(rng: random.Random, status: str = "0x18") -> dict[str, Any]:
    """Pick coherent 4771 failure fields from Kerberos realism config."""
    cfg = load_kerberos_realism()
    failure = cfg.get("tgt_failure", {})
    pre_auth_profiles = failure.get("pre_auth_types", {})
    if _normalize_kerberos_status(status) == 0x18:
        pre_auth_profiles = {
            name: profile
            for name, profile in pre_auth_profiles.items()
            if not isinstance(profile, dict) or int(profile.get("value", 2)) != 0
        }
    return {
        "ticket_options": _pick_weighted_value(failure.get("ticket_options", {}), rng)
        or "0x40810010",
        "pre_auth_type": int(_pick_weighted_profile(pre_auth_profiles, rng).get("value", 2)),
    }


def _normalize_kerberos_status(status: str) -> int | None:
    """Return an integer Kerberos status or None for an unrecognized caller value."""
    try:
        return int(status, 0)
    except (TypeError, ValueError):
        return None


def pick_kerberos_transport(rng: random.Random, profile: str = "default") -> str:
    """Pick TCP or UDP for a Kerberos network exchange."""
    cfg = load_kerberos_realism()
    profiles = cfg.get("transport_profiles", {})
    weights = profiles.get(profile) or profiles.get("default") or {}
    entries: list[tuple[str, int]] = []
    for proto, raw_weight in weights.items():
        if proto not in {"udp", "tcp"}:
            continue
        weight = _coerce_positive_int_weight(raw_weight)
        if weight > 0:
            entries.append((proto, weight))
    if not entries:
        return "tcp"
    protocols = [entry[0] for entry in entries]
    protocol_weights = [entry[1] for entry in entries]
    return rng.choices(protocols, weights=protocol_weights, k=1)[0]


def _coerce_positive_int_weight(value: Any) -> int:
    """Return a finite, bounded positive integer weight or zero for invalid input."""
    try:
        weight = int(value)
    except (TypeError, ValueError, OverflowError):
        return 0
    if weight <= 0:
        return 0
    return min(weight, _MAX_SELECTION_WEIGHT)


def _pick_weighted_value(profiles: dict[str, dict[str, Any]], rng: random.Random) -> str:
    """Pick a configured weighted profile and return its value."""
    profile = _pick_weighted_profile(profiles, rng)
    return str(profile.get("value", ""))


def _pick_weighted_profile(
    profiles: dict[str, dict[str, Any]], rng: random.Random
) -> dict[str, Any]:
    """Pick one profile from a keyed weighted profile dict."""
    weighted_profiles = [
        (profile, weight)
        for profile in profiles.values()
        if isinstance(profile, dict)
        for weight in (_coerce_positive_int_weight(profile.get("weight", 0)),)
        if weight > 0
    ]
    if not weighted_profiles:
        return {}
    valid_profiles = [profile for profile, _weight in weighted_profiles]
    weights = [weight for _profile, weight in weighted_profiles]
    return rng.choices(valid_profiles, weights=weights, k=1)[0]


def _certificate_fields(
    pre_auth: dict[str, Any],
    rng: random.Random,
    ad_domain: str = "",
    *,
    principal_sid: str = "",
    principal_scope: KerberosPrincipalScope = "user",
) -> dict[str, str]:
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
    if principal_sid:
        identity = resolve_kerberos_credential_identity(
            principal_sid=principal_sid,
            principal_scope=principal_scope,
            profile_name=profile_name,
            profile=profile,
            ad_domain=ad_domain,
        )
        issuer_name = identity.issuer_name
        serial = identity.serial_number
        thumbprint = identity.thumbprint
    else:
        # Compatibility for direct callers without a canonical directory identity.
        issuer_names = profile.get("issuer_names", [])
        issuer_name = rng.choice(issuer_names) if issuer_names else ""
        issuer_name = _scenario_certificate_issuer(issuer_name, ad_domain)
        serial_hex_bytes = int(profile.get("serial_hex_bytes", 16))
        thumbprint_hex_chars = int(profile.get("thumbprint_hex_chars", 40))
        serial = "".join(f"{rng.randrange(256):02X}" for _ in range(serial_hex_bytes))
        thumbprint = "".join(rng.choice("0123456789ABCDEF") for _ in range(thumbprint_hex_chars))
    return {
        "cert_issuer_name": issuer_name,
        "cert_serial_number": serial,
        "cert_thumbprint": thumbprint,
    }


def resolve_kerberos_credential_identity(
    *,
    principal_sid: str,
    principal_scope: KerberosPrincipalScope,
    profile_name: str,
    profile: dict[str, Any],
    ad_domain: str = "",
) -> KerberosCredentialIdentity:
    """Resolve one retry- and order-stable PKINIT credential identity.

    This is deliberately a pure SID-keyed derivation rather than a mutable cache. It therefore
    remains stable across domain controllers, checkpoint restores, retries, and generation order
    without introducing retained per-principal state.
    """

    scopes = _normalized_principal_scopes(profile)
    if principal_scope not in scopes:
        raise ValueError(
            f"Kerberos certificate profile {profile_name!r} does not allow {principal_scope!r}"
        )
    credential_epoch = str(profile.get("credential_epoch", "default"))
    credential_rng = random.Random(
        _stable_seed(
            "kerberos_credential:"
            f"{principal_sid.strip().upper()}:{principal_scope}:{profile_name}:{credential_epoch}"
        )
    )
    issuer_names = profile.get("issuer_names", [])
    issuer_name = credential_rng.choice(issuer_names) if issuer_names else ""
    issuer_name = _scenario_certificate_issuer(issuer_name, ad_domain)
    serial_hex_bytes = int(profile.get("serial_hex_bytes", 16))
    thumbprint_hex_chars = int(profile.get("thumbprint_hex_chars", 40))
    serial = "".join(f"{credential_rng.randrange(256):02X}" for _ in range(serial_hex_bytes))
    thumbprint = "".join(
        credential_rng.choice("0123456789ABCDEF") for _ in range(thumbprint_hex_chars)
    )
    return KerberosCredentialIdentity(
        issuer_name=issuer_name,
        serial_number=serial,
        thumbprint=thumbprint,
    )


def _profile_allows_scope(
    pre_auth: dict[str, Any],
    principal_scope: KerberosPrincipalScope,
    certificate_profiles: dict[str, Any],
) -> bool:
    """Return whether a pre-auth entry and its certificate profile allow this scope."""

    if principal_scope not in _normalized_principal_scopes(pre_auth):
        return False
    if not pre_auth.get("certificate_required", False):
        return True
    profile_name = str(pre_auth.get("certificate_profile", ""))
    profile = certificate_profiles.get(profile_name, {})
    return isinstance(profile, dict) and principal_scope in _normalized_principal_scopes(profile)


def _normalized_principal_scopes(profile: dict[str, Any]) -> tuple[str, ...]:
    """Return configured principal scopes with legacy profiles eligible for both scopes."""

    raw_scopes = profile.get("principal_scopes", ("user", "machine"))
    if not isinstance(raw_scopes, (list, tuple)):
        return ()
    return tuple(str(scope) for scope in raw_scopes)


def _scenario_certificate_issuer(issuer_name: str, ad_domain: str) -> str:
    """Replace package placeholder enterprise names with the scenario org stem."""
    if not issuer_name or not ad_domain or "Acme Corp" not in issuer_name:
        return issuer_name
    org_name = _enterprise_org_from_domain(ad_domain)
    return issuer_name.replace("Acme Enterprise", f"{org_name} Enterprise").replace(
        "Acme Corp", org_name
    )


def _enterprise_org_from_domain(ad_domain: str) -> str:
    """Derive a readable organization stem from a DNS domain."""
    generic_labels = {"corp", "local", "internal", "test", "com", "net", "org", "lan"}
    for label in ad_domain.split("."):
        cleaned = label.strip().replace("-", " ").replace("_", " ")
        if cleaned and cleaned.lower() not in generic_labels:
            return cleaned.title()
    return "Enterprise"
