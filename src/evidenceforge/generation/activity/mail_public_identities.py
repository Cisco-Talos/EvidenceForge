# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Public identity pools for external SMTP senders and relays."""

from __future__ import annotations

import random
import re
from typing import Any

from evidenceforge.config import get_activity_directory
from evidenceforge.config.overlay import load_with_overlay, merge_keyed_list
from evidenceforge.utils.rng import _stable_seed

_IDENTITIES_PATH = get_activity_directory() / "mail_public_identities.yaml"
_CACHED_DATA: dict[str, Any] | None = None


def _merge_mail_public_identities(default: dict, overlay: dict) -> dict:
    """Merge mail public identity overlays by provider name."""
    result = dict(default)
    if "providers" in overlay:
        result["providers"] = merge_keyed_list(
            default.get("providers", []),
            overlay["providers"],
            key_field="name",
        )
    for key, value in overlay.items():
        if key != "providers":
            result[key] = value
    return result


def load_mail_public_identities() -> dict[str, Any]:
    """Load mail-specific public identity profiles, merged with local overlay."""
    global _CACHED_DATA
    if _CACHED_DATA is not None:
        return _CACHED_DATA
    _CACHED_DATA = load_with_overlay(
        _IDENTITIES_PATH,
        "activity/mail_public_identities.yaml",
        _merge_mail_public_identities,
    )
    return _CACHED_DATA


def reset_mail_public_identities_cache() -> None:
    """Clear cached mail identity profiles. Intended for tests."""
    global _CACHED_DATA
    _CACHED_DATA = None


def _domain_from_hostname(hostname: str) -> str:
    lowered = hostname.lower().rstrip(".")
    labels = [label for label in lowered.split(".") if label]
    if len(labels) <= 2:
        return lowered or "mail.example"
    if labels[0] in {"mail", "mail1", "mail2", "mx", "mx1", "mx2", "smtp", "smtp1", "smtp2"}:
        return ".".join(labels[1:])
    return ".".join(labels[-2:])


def _provider_for_key(key: str) -> dict[str, Any]:
    providers = load_mail_public_identities().get("providers", [])
    weighted = [provider for provider in providers if int(provider.get("weight", 0)) > 0]
    if not weighted:
        return {}
    rng = random.Random(_stable_seed(f"mail_public_provider:{key.lower()}"))
    weights = [int(provider.get("weight", 0)) for provider in weighted]
    return rng.choices(weighted, weights=weights, k=1)[0]


def _provider_for_ip(ip: str) -> dict[str, Any]:
    try:
        octets = [int(part) for part in ip.split(".")]
    except ValueError:
        return {}
    if len(octets) != 4:
        return {}
    for provider in load_mail_public_identities().get("providers", []):
        for raw_prefix in provider.get("prefixes", []):
            prefix = list(raw_prefix)
            if len(prefix) != 4:
                continue
            if (
                octets[0] == prefix[0]
                and octets[1] == prefix[1]
                and prefix[2] <= octets[2] <= prefix[3]
            ):
                return provider
    return {}


def generate_public_mail_ip(identity_key: str) -> str:
    """Return a stable public IPv4 address from mail-specific provider pools."""
    provider = _provider_for_key(identity_key)
    prefixes = list(provider.get("prefixes", []))
    if not prefixes:
        seed = _stable_seed(f"mail_public_ip:fallback:{identity_key.lower()}")
        return f"64.56.{32 + seed % 96}.{1 + (seed >> 8) % 253}"
    rng = random.Random(_stable_seed(f"mail_public_ip:{identity_key.lower()}"))
    prefix = list(rng.choice(prefixes))
    third = rng.randint(int(prefix[2]), int(prefix[3]))
    fourth = rng.randint(8, 246)
    return f"{int(prefix[0])}.{int(prefix[1])}.{third}.{fourth}"


def public_mail_ptr_name(ip: str, forward_hostname: str | None) -> str:
    """Return a stable mail-style PTR name for mail-specific public IPs."""
    provider = _provider_for_ip(ip)
    if not provider:
        return ""
    octets = ip.split(".")
    domain = _domain_from_hostname(forward_hostname or "")
    if not domain or "." not in domain:
        provider_name = re.sub(r"[^a-z0-9-]+", "-", str(provider.get("name", "mail"))).strip("-")
        domain = f"{provider_name}.mail"
    rng = random.Random(_stable_seed(f"mail_public_ptr:{ip}:{forward_hostname or ''}"))
    templates = list(provider.get("ptr_templates", [])) or ["mx{slot}.{domain}"]
    template = str(rng.choice(templates))
    return template.format(
        domain=domain,
        third=octets[2],
        fourth=octets[3],
        slot=1 + rng.randrange(4),
    )


def is_public_mail_ip(ip: str) -> bool:
    """Return whether an IP belongs to a configured mail public identity pool."""
    return bool(_provider_for_ip(ip))
