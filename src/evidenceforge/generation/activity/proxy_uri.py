# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Domain-aware proxy URI path selection for realistic proxy log generation.

Loads per-domain and per-tag URI templates from proxy_uri_templates.yaml and
provides pick_proxy_uri() for context-appropriate path selection.
"""

import random
import re
import uuid
from ipaddress import ip_address
from typing import Any

from evidenceforge.config import get_activity_directory
from evidenceforge.config.overlay import deep_merge_dict, load_with_overlay
from evidenceforge.generation.activity.http_content import (
    is_stable_resource_path,
    normalize_mime_type_for_path,
)
from evidenceforge.utils.rng import _stable_seed

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
_BROWSER_SESSION_TAGS = {
    "email",
    "git",
    "internal",
    "saas",
    "social",
    "web",
}
_NON_BROWSER_INFRA_TAGS = {
    "background",
    "dev",
    "linux",
    "storage",
    "windows",
}
_NON_BROWSER_HOST_PREFIXES = (
    "api.",
    "api-",
    "assets.",
    "cdn.",
    "content.",
    "res.",
    "static.",
)
_NON_BROWSER_HOST_SUFFIXES = (
    "-edge.com",
    ".dropboxapi.com",
    ".githubassets.com",
    ".gstatic.com",
)
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
_INTERNAL_HOST_SUFFIXES = (
    ".corp",
    ".corp.com",
    ".internal",
    ".lan",
    ".local",
)
_NON_NAVIGATION_PATH_MARKERS = (
    "/api/",
    "/oauth",
    "/token",
    "/autodiscover",
    "/ews/",
    "/mapi/",
    "/service/update",
    "/v1/",
    "/v2/",
    "/beta/",
    "/common/discovery",
    "/common/oauth",
    "/2/",
    "/wbxappapi/",
)


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


def get_proxy_domain_http_policy(hostname: str) -> str:
    """Return the configured plaintext HTTP policy for an exact hostname."""
    entry = load_proxy_uri_templates().get("domains", {}).get(hostname, {})
    if not isinstance(entry, dict):
        return ""
    policy = entry.get("http_policy")
    return str(policy).strip().lower() if policy else ""


def proxy_domain_allows_source_system_type(
    hostname: str,
    source_system_type: str | None,
) -> bool:
    """Return whether a domain template is compatible with a source host type."""
    if not source_system_type:
        return True

    entry = load_proxy_uri_templates().get("domains", {}).get(hostname, {})
    if not isinstance(entry, dict):
        return True

    allowed_types = entry.get("source_system_types")
    if not allowed_types:
        return True
    if not isinstance(allowed_types, list):
        return True

    normalized_source_type = source_system_type.strip().lower()
    normalized_allowed = {str(value).strip().lower() for value in allowed_types}
    return normalized_source_type in normalized_allowed


def _is_public_hostname(hostname: str) -> bool:
    """Return whether a hostname should use public-web plaintext defaults."""
    normalized = hostname.strip().lower().rstrip(".")
    if not normalized or "." not in normalized:
        return False
    if normalized.endswith(_INTERNAL_HOST_SUFFIXES):
        return False
    try:
        ip_literal = normalized.strip("[]")
        if ":" in ip_literal and ip_literal.count(":") == 1:
            ip_literal = ip_literal.rsplit(":", 1)[0]
        ip_address(ip_literal)
    except ValueError:
        return True
    return False


def _default_plaintext_http_policy(hostname: str) -> str:
    """Return the configured fallback HTTP policy for public browser-like hosts."""
    default_policy = str(load_proxy_uri_templates().get("default_http_policy", "")).lower()
    if default_policy != "https_redirect_public":
        return ""
    if not is_browser_like_proxy_domain(hostname):
        return ""
    if not _is_public_hostname(hostname):
        return ""
    return "https_redirect"


def plaintext_http_redirect_status(
    hostname: str,
    *,
    port: int,
    path: str = "/",
    dst_ip: str | None = None,
) -> int | None:
    """Return redirect status when plaintext HTTP should not serve content."""
    if port != 80:
        return None
    if dst_ip:
        try:
            if ip_address(dst_ip.strip("[]")).is_private:
                return None
        except ValueError:
            pass
    policy = get_proxy_domain_http_policy(hostname)
    if not policy:
        policy = _default_plaintext_http_policy(hostname)
    if policy not in {"https_redirect", "https_only"}:
        return None
    seed = f"http_plaintext_redirect:{hostname.lower().rstrip('.')}:{path}"
    return 301 if _stable_seed(seed) % 4 else 302


def is_browser_like_proxy_domain(
    hostname: str,
    *,
    domain_tags: list[str] | tuple[str, ...] | set[str] | None = None,
) -> bool:
    """Return whether hostname should be eligible for browser-style site visits."""
    normalized = hostname.strip().lower().rstrip(".")
    domain_class = get_proxy_domain_class(hostname)
    if domain_class in _NON_BROWSER_DOMAIN_CLASSES:
        return False
    if normalized.startswith(_NON_BROWSER_HOST_PREFIXES):
        return False
    if ".cdn." in normalized or normalized.endswith(_NON_BROWSER_HOST_SUFFIXES):
        return False

    normalized_tags = {str(tag).strip().lower() for tag in domain_tags or []}
    if "cdn" in normalized_tags:
        return False
    if (
        normalized_tags
        and normalized_tags.isdisjoint(_BROWSER_SESSION_TAGS)
        and not normalized_tags.isdisjoint(_NON_BROWSER_INFRA_TAGS)
    ):
        return False
    return True


def _inferred_template_tag_for_hostname(hostname: str) -> str:
    """Return a conservative URI-template tag inferred from hostname shape."""
    normalized = hostname.strip().lower().rstrip(".")
    if (
        normalized.startswith(("assets.", "cdn.", "static."))
        or ".cdn." in normalized
        or normalized.endswith(
            (
                "-edge.com",
                ".githubassets.com",
                ".gstatic.com",
            )
        )
    ):
        return "cdn"
    if normalized.endswith(".dropboxapi.com"):
        return "storage"
    if normalized.startswith(("api.", "api-", "collector.", "events.", "metrics.", "telemetry.")):
        return "background"
    return ""


def _entry_matches_source(
    hostname: str,
    entry: Any,
    source_os: str | None,
    source_system_type: str | None,
) -> bool:
    """Return whether a URI template entry is compatible with the source host."""
    if not isinstance(entry, dict):
        return False
    entry_os = entry.get("os")
    if entry_os and source_os:
        if isinstance(entry_os, list):
            if source_os not in {str(value) for value in entry_os}:
                return False
        elif str(entry_os) != source_os:
            return False
    return proxy_domain_allows_source_system_type(
        hostname,
        source_system_type,
    )


def _referrer_policy_for_request(method: str, path: str, content_type: str) -> str:
    """Return a conservative referrer policy for one selected proxy request."""
    normalized_method = method.upper()
    normalized_type = content_type.split(";", 1)[0].strip().lower()
    normalized_path = path.split("?", 1)[0].split("#", 1)[0].lower()

    if normalized_method != "GET":
        return "none"
    if normalized_type != "text/html":
        return "none"
    if any(marker in normalized_path for marker in _NON_NAVIGATION_PATH_MARKERS):
        return "none"
    return "normal"


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
    source_system_type: str | None = None,
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
        source_system_type: Source host type such as "workstation", "server",
            or "domain_controller". Exact templates can restrict themselves
            to compatible source types.

    Returns:
        (path, content_type, method, user_agent_override, referrer_policy) tuple.
        user_agent_override is None for normal browser traffic.
        referrer_policy is "normal" or "none".
    """
    data = load_proxy_uri_templates()

    # 1. Exact domain match
    domains = data.get("domains", {})
    entry = domains.get(hostname)
    if not _entry_matches_source(hostname, entry, source_os, source_system_type):
        entry = None

    # 2. Tag-based fallback
    tags = data.get("tags", {})
    if entry is None:
        for tag in domain_tags:
            candidate = tags.get(tag)
            if _entry_matches_source(hostname, candidate, source_os, source_system_type):
                entry = candidate
                break

    # 3. Hostname-shape fallback for unregistered CDN/API endpoints.
    if entry is None:
        inferred_tag = _inferred_template_tag_for_hostname(hostname)
        if inferred_tag:
            candidate = tags.get(inferred_tag)
            if _entry_matches_source(hostname, candidate, source_os, source_system_type):
                entry = candidate

    # 4. Generic fallback
    if entry is None:
        entry = data.get("generic", {})

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
    if referrer_policy != "none":
        referrer_policy = _referrer_policy_for_request(method, path, content_type)
    if referrer_policy != "none" and is_stable_resource_path(path):
        referrer_policy = "none"

    return path, content_type, method, user_agent, referrer_policy
