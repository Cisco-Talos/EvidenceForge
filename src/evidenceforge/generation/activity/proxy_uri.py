# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Domain-aware proxy URI path selection for realistic proxy log generation.

Loads per-domain and per-tag URI templates from proxy_uri_templates.yaml and
provides pick_proxy_uri() for context-appropriate path selection.
"""

import random
import uuid
from typing import Any

import yaml

from evidenceforge.config import get_activity_directory

_TEMPLATES_PATH = get_activity_directory() / "proxy_uri_templates.yaml"
_CACHED_DATA: dict[str, Any] | None = None


def load_proxy_uri_templates() -> dict[str, Any]:
    """Load proxy URI templates from YAML. Cached after first call."""
    global _CACHED_DATA
    if _CACHED_DATA is not None:
        return _CACHED_DATA

    with open(_TEMPLATES_PATH) as f:
        _CACHED_DATA = yaml.safe_load(f)
    return _CACHED_DATA


def _substitute_vars(rng: random.Random, path: str, data: dict[str, Any]) -> str:
    """Replace template variables in a URI path."""
    if "{guid}" in path:
        path = path.replace("{guid}", str(uuid.UUID(int=rng.getrandbits(128))), 1)
        # Handle second {guid} if present
        if "{guid}" in path:
            path = path.replace("{guid}", str(uuid.UUID(int=rng.getrandbits(128))), 1)
    if "{tenant_id}" in path:
        path = path.replace("{tenant_id}", str(uuid.UUID(int=rng.getrandbits(128))))
    if "{hex8}" in path:
        path = path.replace("{hex8}", f"{rng.getrandbits(32):08x}", 1)
        if "{hex8}" in path:
            path = path.replace("{hex8}", f"{rng.getrandbits(32):08x}", 1)
    if "{hex16}" in path:
        path = path.replace("{hex16}", f"{rng.getrandbits(64):016x}", 1)
        if "{hex16}" in path:
            path = path.replace("{hex16}", f"{rng.getrandbits(64):016x}", 1)
    if "{search_term}" in path:
        search_terms = data.get("search_terms", ["enterprise+software"])
        path = path.replace("{search_term}", rng.choice(search_terms))
    if "{brand}" in path:
        path = path.replace("{brand}", f"org-{rng.getrandbits(16):04x}", 1)
        if "{brand}" in path:
            path = path.replace("{brand}", f"repo-{rng.getrandbits(16):04x}", 1)
    return path


def pick_proxy_uri(
    rng: random.Random,
    hostname: str,
    domain_tags: list[str],
) -> tuple[str, str, str]:
    """Pick a URI path, content type, and HTTP method for a proxy log entry.

    Lookup order: exact domain match -> first matching tag -> generic fallback.

    Returns:
        (path, content_type, method) tuple.
    """
    data = load_proxy_uri_templates()

    # 1. Exact domain match
    domains = data.get("domains", {})
    entry = domains.get(hostname)

    # 2. Tag-based fallback
    if entry is None:
        tags = data.get("tags", {})
        for tag in domain_tags:
            if tag in tags:
                entry = tags[tag]
                break

    # 3. Generic fallback
    if entry is None:
        entry = data.get("generic", {})

    paths = entry.get("paths", ["/"])
    content_type = entry.get("content_type", "text/html")
    methods = entry.get("methods", ["GET"])

    idx = rng.randrange(len(paths))
    path = paths[idx]
    method = methods[idx] if idx < len(methods) else methods[-1] if methods else "GET"

    path = _substitute_vars(rng, path, data)

    return path, content_type, method
