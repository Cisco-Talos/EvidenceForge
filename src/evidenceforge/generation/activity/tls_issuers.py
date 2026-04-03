# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""TLS certificate issuer configurations for realistic x509 generation.

Loads issuer parameters from tls_issuers.yaml and provides pick_issuer()
for weighted issuer selection with per-issuer validity and key type parameters.
"""

import random
from pathlib import Path
from typing import Any

import yaml

_ISSUERS_PATH = Path(__file__).parent / "tls_issuers.yaml"
_CACHED_ISSUERS: dict[str, Any] | None = None


def load_tls_issuers() -> dict[str, Any]:
    """Load TLS issuer configurations from YAML. Cached after first call."""
    global _CACHED_ISSUERS
    if _CACHED_ISSUERS is not None:
        return _CACHED_ISSUERS

    with open(_ISSUERS_PATH) as f:
        _CACHED_ISSUERS = yaml.safe_load(f)
    return _CACHED_ISSUERS


def pick_issuer(rng: random.Random) -> dict[str, Any]:
    """Pick a TLS certificate issuer using weighted selection.

    Returns a dict with keys: name, validity_days, not_before_max_days, key_types.
    """
    data = load_tls_issuers()
    issuers = data["issuers"]
    weights = [i["weight"] for i in issuers]
    return rng.choices(issuers, weights=weights, k=1)[0]


def pick_key_type(rng: random.Random, issuer: dict[str, Any]) -> tuple[str, int]:
    """Pick a key type (algorithm, length) from an issuer's key_types.

    Returns (key_type, key_length) tuple, e.g., ("ecdsa", 256) or ("rsa", 2048).
    """
    key_types = issuer.get("key_types", [{"type": "rsa", "length": 2048, "weight": 100}])
    weights = [k["weight"] for k in key_types]
    chosen = rng.choices(key_types, weights=weights, k=1)[0]
    return chosen["type"], chosen["length"]
