# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""TLS realism configuration loader."""

import fnmatch
from typing import Any

from evidenceforge.config import get_activity_directory
from evidenceforge.config.overlay import deep_merge_dict, load_with_overlay

_CONFIG_PATH = get_activity_directory() / "tls_realism.yaml"
_CACHED_DATA: dict[str, Any] | None = None


def _merge_tls_realism(default: dict, overlay: dict) -> dict:
    """Merge TLS realism overlay with package defaults."""
    return deep_merge_dict(default, overlay)


def load_tls_realism() -> dict[str, Any]:
    """Load TLS realism config from YAML, merged with overlay. Cached after first call."""
    global _CACHED_DATA
    if _CACHED_DATA is not None:
        return _CACHED_DATA

    _CACHED_DATA = load_with_overlay(
        _CONFIG_PATH,
        "activity/tls_realism.yaml",
        _merge_tls_realism,
    )
    return _CACHED_DATA


def reset_tls_realism_cache() -> None:
    """Clear cached TLS realism config. Intended for tests."""
    global _CACHED_DATA
    _CACHED_DATA = None


def multi_label_public_suffixes() -> set[str]:
    """Return configured multi-label public suffixes for wildcard SAN generation."""
    data = load_tls_realism()
    suffixes = data.get("san", {}).get("multi_label_public_suffixes", [])
    return {str(suffix).lower() for suffix in suffixes}


def ocsp_config() -> dict[str, Any]:
    """Return OCSP behavior config."""
    return load_tls_realism().get("ocsp", {})


def certificate_chain_config() -> dict[str, Any]:
    """Return TLS certificate chain behavior config."""
    return load_tls_realism().get("certificate_chains", {})


def chain_template_for_issuer(issuer_name: str) -> dict[str, Any]:
    """Return the configured certificate-chain template for an issuer."""
    templates = certificate_chain_config().get("templates", [])
    fallback: dict[str, Any] = {}
    for template in templates:
        if not isinstance(template, dict):
            continue
        patterns = template.get("issuer_patterns", [])
        if "*" in patterns and not fallback:
            fallback = template
        if any(fnmatch.fnmatch(issuer_name, str(pattern)) for pattern in patterns):
            return template
    return fallback
