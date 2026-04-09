# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""TLS certificate issuer configurations for realistic x509 generation.

Loads issuer parameters from tls_issuers.yaml and provides pick_issuer()
for weighted issuer selection with per-issuer validity and key type parameters.
"""

import random
from typing import Any

import yaml

from evidenceforge.config import get_activity_directory

_ISSUERS_PATH = get_activity_directory() / "tls_issuers.yaml"
_CACHED_ISSUERS: dict[str, Any] | None = None


def load_tls_issuers() -> dict[str, Any]:
    """Load TLS issuer configurations from YAML. Cached after first call."""
    global _CACHED_ISSUERS
    if _CACHED_ISSUERS is not None:
        return _CACHED_ISSUERS

    with open(_ISSUERS_PATH) as f:
        _CACHED_ISSUERS = yaml.safe_load(f)
    return _CACHED_ISSUERS


def pick_issuer(rng: random.Random, server_name: str = "") -> dict[str, Any]:
    """Pick a TLS certificate issuer, respecting domain-to-CA overrides.

    Well-known domains (Google, Microsoft, etc.) always get their real CA.
    Other domains use weighted random selection.

    Returns a dict with keys: name, validity_days, not_before_max_days, key_types.
    """
    import fnmatch

    data = load_tls_issuers()
    issuers = data["issuers"]

    # Check domain-to-CA overrides first
    if server_name:
        overrides = data.get("domain_ca_overrides", {})
        for pattern, ca_name in overrides.items():
            if fnmatch.fnmatch(server_name, pattern) or fnmatch.fnmatch(
                f"*.{server_name}", pattern
            ):
                # Find the matching issuer config
                for issuer in issuers:
                    if issuer["name"] == ca_name:
                        return issuer
                # CA name in overrides but not in issuers list — return minimal config
                return {
                    "name": ca_name,
                    "weight": 0,
                    "validity_days": 397,
                    "not_before_max_days": 300,
                    "key_types": [{"type": "rsa", "length": 2048, "weight": 100}],
                }

    # No override — weighted random selection (exclude weight=0 override-only CAs)
    active_issuers = [i for i in issuers if i.get("weight", 0) > 0]
    weights = [i["weight"] for i in active_issuers]
    return rng.choices(active_issuers, weights=weights, k=1)[0]


def pick_key_type(rng: random.Random, issuer: dict[str, Any]) -> tuple[str, int]:
    """Pick a key type (algorithm, length) from an issuer's key_types.

    Returns (key_type, key_length) tuple, e.g., ("ecdsa", 256) or ("rsa", 2048).
    """
    key_types = issuer.get("key_types", [{"type": "rsa", "length": 2048, "weight": 100}])
    weights = [k["weight"] for k in key_types]
    chosen = rng.choices(key_types, weights=weights, k=1)[0]
    return chosen["type"], chosen["length"]
