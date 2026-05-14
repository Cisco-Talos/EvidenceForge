# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Domain-aware proxy URI path selection for realistic proxy log generation.

Loads per-domain and per-tag URI templates from proxy_uri_templates.yaml and
provides pick_proxy_uri() for context-appropriate path selection.
"""

import random
import re
import uuid
from typing import Any

from evidenceforge.config import get_activity_directory
from evidenceforge.config.overlay import deep_merge_dict, load_with_overlay
from evidenceforge.generation.activity.http_content import normalize_mime_type_for_path

_TEMPLATES_PATH = get_activity_directory() / "proxy_uri_templates.yaml"
_CACHED_DATA: dict[str, Any] | None = None
_NON_BROWSER_DOMAIN_CLASSES = {
    "crl",
    "ocsp",
    "software_update",
    "telemetry",
    "windows_trust_list",
    "windows_update",
}
_SLUGS = [
    "getting-started",
    "best-practices",
    "release-notes",
    "migration-guide",
    "how-to-configure",
    "troubleshooting",
    "changelog",
    "faq",
]


def _merge_proxy_uri_templates(default: dict, overlay: dict) -> dict:
    """Merge proxy URI templates overlay with package defaults."""
    return deep_merge_dict(default, overlay)


def load_proxy_uri_templates() -> dict[str, Any]:
    """Load proxy URI templates from YAML, merged with overlay if present. Cached after first call."""
    global _CACHED_DATA
    if _CACHED_DATA is not None:
        return _CACHED_DATA

    _CACHED_DATA = load_with_overlay(
        _TEMPLATES_PATH,
        "activity/proxy_uri_templates.yaml",
        _merge_proxy_uri_templates,
    )
    return _CACHED_DATA


def reset_proxy_uri_templates_cache() -> None:
    """Clear cached proxy URI templates. Intended for tests."""
    global _CACHED_DATA
    _CACHED_DATA = None


def get_proxy_domain_class(hostname: str) -> str | None:
    """Return the configured proxy behavior class for an exact hostname."""
    entry = load_proxy_uri_templates().get("domains", {}).get(hostname, {})
    if not isinstance(entry, dict):
        return None
    domain_class = entry.get("domain_class")
    return str(domain_class) if domain_class else None


def is_browser_like_proxy_domain(hostname: str) -> bool:
    """Return whether hostname should be eligible for browser-style site visits."""
    domain_class = get_proxy_domain_class(hostname)
    return domain_class not in _NON_BROWSER_DOMAIN_CLASSES


def _template_entry(hostname: str, domain_tags: list[str] | None = None) -> dict[str, Any]:
    """Return the best proxy template entry for a hostname/tags pair."""
    data = load_proxy_uri_templates()
    domains = data.get("domains", {})
    entry = domains.get(hostname)
    if entry is None:
        tags = data.get("tags", {})
        for tag in domain_tags or []:
            if tag in tags:
                entry = tags[tag]
                break
    if entry is None:
        entry = data.get("generic", {})
    return entry if isinstance(entry, dict) else {}


def get_plain_http_response(
    hostname: str,
    domain_tags: list[str] | None = None,
) -> tuple[int, str, str] | None:
    """Return configured source-native plain-HTTP behavior for a host."""
    entry = _template_entry(hostname, domain_tags)
    policy = entry.get("plain_http_policy")
    if policy in {"redirect_https", "hsts_redirect"}:
        status_code = int(entry.get("plain_http_status", 301))
        status_msg = {
            301: "Moved Permanently",
            302: "Found",
            307: "Temporary Redirect",
            308: "Permanent Redirect",
        }.get(status_code, "Moved Permanently")
        return status_code, status_msg, str(entry.get("plain_http_content_type", "text/html"))
    return None


def _substitute_vars(rng: random.Random, path: str, data: dict[str, Any]) -> str:
    """Replace template variables in a URI path."""
    while "{guid}" in path:
        path = path.replace("{guid}", str(uuid.UUID(int=rng.getrandbits(128))), 1)
    if "{tenant_id}" in path:
        path = path.replace("{tenant_id}", str(uuid.UUID(int=rng.getrandbits(128))))
    while "{hex8}" in path:
        path = path.replace("{hex8}", f"{rng.getrandbits(32):08x}", 1)
    while "{hex16}" in path:
        path = path.replace("{hex16}", f"{rng.getrandbits(64):016x}", 1)
    if "{search_term}" in path:
        search_terms = data.get("search_terms", ["enterprise+software"])
        path = path.replace("{search_term}", rng.choice(search_terms))
    while "{slug}" in path:
        path = path.replace("{slug}", rng.choice(_SLUGS), 1)
    while "{brand}" in path:
        path = path.replace("{brand}", f"org-{rng.getrandbits(16):04x}", 1)
    path = re.sub(r"\{[A-Za-z_][A-Za-z0-9_]*\}", "item", path)
    return path


def pick_proxy_uri(
    rng: random.Random,
    hostname: str,
    domain_tags: list[str],
    source_os: str | None = None,
) -> tuple[str, str, str, str | None, str]:
    """Pick URI path, content type, HTTP method, optional UA override, and referrer policy.

    Lookup order: exact domain match -> first matching tag -> generic fallback.
    MIME type is inferred from path extension when possible, overriding the
    domain default.

    Args:
        source_os: OS category of the source host ("windows" or "linux").
            When set, domain-specific user_agent overrides are only returned
            if the entry's ``os`` field matches.  This prevents Windows-only
            UAs (e.g. Windows-Update-Agent) from being applied to Linux hosts.

    Returns:
        (path, content_type, method, user_agent_override, referrer_policy) tuple.
        user_agent_override is None for normal browser traffic.
        referrer_policy is "normal" or "none".
    """
    data = load_proxy_uri_templates()

    entry = _template_entry(hostname, domain_tags)

    paths = entry.get("paths", ["/"])
    content_type = entry.get("content_type", "text/html")
    methods = entry.get("methods", ["GET"])
    user_agent = entry.get("user_agent")
    referrer_policy = entry.get("referrer_policy", "normal")

    # OS-aware UA filtering: suppress OS-specific UA overrides when source
    # OS doesn't match (e.g., don't assign Windows-Update-Agent to Linux hosts)
    entry_os = entry.get("os")
    if user_agent and entry_os and source_os and entry_os != source_os:
        user_agent = None

    # Per-path content_types override (parallel list alongside paths)
    content_types = entry.get("content_types")

    idx = rng.randrange(len(paths))
    path = paths[idx]
    method = methods[idx] if idx < len(methods) else methods[-1] if methods else "GET"

    # Per-path content type (if the YAML provides parallel content_types list)
    if content_types and idx < len(content_types):
        content_type = content_types[idx]

    path = _substitute_vars(rng, path, data)

    content_type = normalize_mime_type_for_path(path, content_type)

    return path, content_type, method, user_agent, referrer_policy
