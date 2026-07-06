# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Site map loader for browsing session generation.

Loads per-domain and per-tag site maps from site_maps.yaml.
Provides get_site_map() for looking up page structures, subresource
definitions, and CDN domain associations.
"""

from __future__ import annotations

import hashlib
import random
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from evidenceforge.config import get_activity_directory
from evidenceforge.config.overlay import deep_merge_dict, load_with_overlay

_SITE_MAPS_PATH = get_activity_directory() / "site_maps.yaml"
_CACHED_DATA: dict[str, Any] | None = None


def _merge_site_maps(default: dict, overlay: dict) -> dict:
    """Merge site maps overlay with package defaults."""
    return deep_merge_dict(default, overlay)


def load_site_maps() -> dict[str, Any]:
    """Load site map definitions from YAML, merged with overlay if present. Cached after first call."""
    global _CACHED_DATA
    if _CACHED_DATA is not None:
        return _CACHED_DATA
    _CACHED_DATA = load_with_overlay(
        _SITE_MAPS_PATH,
        "activity/site_maps.yaml",
        _merge_site_maps,
    )
    return _CACHED_DATA


@dataclass
class SubresourceDef:
    """A single subresource loaded by a page (CSS, JS, image, API call, etc.)."""

    path: str
    content_type: str
    host: str | None = None  # CDN hostname; None = same as page host
    method: str = "GET"


@dataclass
class PageDef:
    """A page in a site map with navigation targets and subresources."""

    path: str
    content_type: str = "text/html"
    nav_targets: list[str] = field(default_factory=list)
    subresources: list[SubresourceDef] = field(default_factory=list)


@dataclass
class SiteMap:
    """Complete site structure for a domain or synthesized from a tag template."""

    hostname: str
    pages: list[PageDef]
    cdn_domains: list[str] = field(default_factory=list)


_STATIC_ASSET_TYPES = {
    "application/javascript",
    "application/json",
    "image/png",
    "image/svg+xml",
    "image/webp",
    "text/css",
    "font/woff",
    "font/woff2",
}

_DYNAMIC_RESOURCE_MARKERS = (
    "/avatar/",
    "/content/",
    "/comments/",
    "/patient/",
    "/post/",
    "/profile-displayphoto",
    "/thumb/",
    "/u/",
)


def _uses_stable_asset_tokens(path: str, content_type: str | None) -> bool:
    """Return whether template cache-buster tokens should be stable for a host."""
    if "{hex" not in path:
        return False
    if content_type not in _STATIC_ASSET_TYPES:
        return False
    lowered = path.lower()
    if any(marker in lowered for marker in _DYNAMIC_RESOURCE_MARKERS):
        return False
    return (
        "/assets/" in lowered
        or "/static/" in lowered
        or "bundle" in lowered
        or "chunk" in lowered
        or lowered.split("?", 1)[0].endswith((".css", ".js", ".png", ".svg", ".webp", ".woff2"))
    )


def _stable_hex_token(hostname: str, template: str, token: str, occurrence: int) -> str:
    bits = 64 if token == "{hex16}" else 32
    width = bits // 4
    digest = hashlib.sha256(
        f"site_map_asset:{hostname}:{template}:{token}:{occurrence}".encode()
    ).hexdigest()
    return digest[:width]


def _replace_token_occurrences(
    rng: random.Random,
    path: str,
    *,
    token: str,
    bits: int,
    hostname: str,
    template: str,
    stable_asset_tokens: bool,
) -> str:
    """Replace all occurrences of one token with a single linear pass over the path."""
    parts = path.split(token)
    if len(parts) == 1:
        return path

    output = [parts[0]]
    for occurrence, part in enumerate(parts[1:]):
        if stable_asset_tokens:
            replacement = _stable_hex_token(hostname, template, token, occurrence)
        else:
            replacement = f"{rng.getrandbits(bits):0{bits // 4}x}"
        output.extend((replacement, part))
    return "".join(output)


def _replace_hex_tokens(
    rng: random.Random,
    path: str,
    *,
    hostname: str,
    template: str,
    stable_asset_tokens: bool,
) -> str:
    for token, bits in (("{hex8}", 32), ("{hex16}", 64)):
        path = _replace_token_occurrences(
            rng,
            path,
            token=token,
            bits=bits,
            hostname=hostname,
            template=template,
            stable_asset_tokens=stable_asset_tokens,
        )
    return path


def _request_month_start_iso(request_time: datetime | None) -> str:
    """Return a UTC month-start timestamp for browser API path templates."""

    if request_time is None:
        request_time = datetime(2024, 1, 1, tzinfo=UTC)
    elif request_time.tzinfo is None:
        request_time = request_time.replace(tzinfo=UTC)
    else:
        request_time = request_time.astimezone(UTC)
    month_start = request_time.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
    return month_start.strftime("%Y-%m-%dT%H:%M:%SZ")


def _substitute_vars(
    rng: random.Random,
    path: str,
    data: dict[str, Any],
    *,
    hostname: str = "",
    content_type: str | None = None,
    request_time: datetime | None = None,
) -> str:
    """Replace template variables in a URI path."""
    stable_asset_tokens = _uses_stable_asset_tokens(path, content_type)
    template = path
    if "{guid}" in path:
        path = path.replace("{guid}", str(uuid.UUID(int=rng.getrandbits(128))), 1)
        if "{guid}" in path:
            path = path.replace("{guid}", str(uuid.UUID(int=rng.getrandbits(128))), 1)
    path = _replace_hex_tokens(
        rng,
        path,
        hostname=hostname,
        template=template,
        stable_asset_tokens=stable_asset_tokens,
    )
    if "{search_term}" in path:
        search_terms = data.get("search_terms", ["enterprise+software"])
        path = path.replace("{search_term}", rng.choice(search_terms))
    if "{slug}" in path:
        slugs = [
            "getting-started",
            "best-practices",
            "release-notes",
            "migration-guide",
            "how-to-configure",
            "troubleshooting",
            "changelog",
            "faq",
        ]
        path = path.replace("{slug}", rng.choice(slugs), 1)
    if "{n}" in path:
        path = path.replace("{n}", str(rng.randint(1, 20)), 1)
    if "{calendar_time_min}" in path:
        path = path.replace("{calendar_time_min}", _request_month_start_iso(request_time))
    return path


def _build_subresources(
    rng: random.Random,
    raw_list: list[dict[str, str]],
    data: dict[str, Any],
    hostname: str,
    request_time: datetime | None = None,
) -> list[SubresourceDef]:
    """Convert raw YAML subresource dicts to SubresourceDef objects."""
    result = []
    for item in raw_list:
        path = _substitute_vars(
            rng,
            item.get("path", "/"),
            data,
            hostname=item.get("host") or hostname,
            content_type=item.get("type", "application/octet-stream"),
            request_time=request_time,
        )
        result.append(
            SubresourceDef(
                path=path,
                content_type=item.get("type", "application/octet-stream"),
                host=item.get("host"),
                method=item.get("method", "GET"),
            )
        )
    return result


def _build_pages_from_curated(
    rng: random.Random,
    hostname: str,
    domain_entry: dict[str, Any],
    data: dict[str, Any],
    request_time: datetime | None = None,
) -> list[PageDef]:
    """Build PageDef list from a curated domain entry."""
    pages = []
    for page_raw in domain_entry.get("pages", []):
        nav_targets = [
            _substitute_vars(rng, t, data, request_time=request_time)
            for t in page_raw.get("nav_targets", [])
        ]
        subresources = _build_subresources(
            rng,
            page_raw.get("subresources", []),
            data,
            hostname,
            request_time,
        )
        pages.append(
            PageDef(
                path=_substitute_vars(rng, page_raw["path"], data, request_time=request_time),
                content_type=page_raw.get("content_type", "text/html"),
                nav_targets=nav_targets,
                subresources=subresources,
            )
        )
    return pages


def _build_pages_from_tag(
    rng: random.Random,
    hostname: str,
    tag_entry: dict[str, Any],
    data: dict[str, Any],
    request_time: datetime | None = None,
) -> list[PageDef]:
    """Build PageDef list from a tag-based synthesis template."""
    patterns = tag_entry.get("subresource_patterns", {})
    pages = []
    for tmpl in tag_entry.get("page_templates", []):
        pattern_name = tmpl.get("subresource_pattern", "")
        raw_subs = patterns.get(pattern_name, [])
        nav_targets = [
            _substitute_vars(rng, t, data, request_time=request_time)
            for t in tmpl.get("nav_targets", [])
        ]
        subresources = _build_subresources(rng, raw_subs, data, hostname, request_time)
        pages.append(
            PageDef(
                path=_substitute_vars(rng, tmpl["path"], data, request_time=request_time),
                nav_targets=nav_targets,
                subresources=subresources,
            )
        )
    return pages


def get_site_map(
    hostname: str,
    domain_tags: list[str],
    rng: random.Random | None = None,
    request_time: datetime | None = None,
) -> SiteMap:
    """Look up or synthesize a site map for a hostname.

    Lookup order:
    1. Exact domain match in curated domains
    2. First matching tag in tag-based templates
    3. Generic fallback

    Args:
        hostname: Target domain (e.g., "outlook.office365.com")
        domain_tags: Tags from dns_registry (e.g., ["saas", "email"])
        rng: Random instance for template variable substitution.
            If None, a default Random(0) is used.
        request_time: Optional modeled request time for time-relative URI
            template variables.

    Returns:
        SiteMap with pages, subresources, and CDN domains.
    """
    if rng is None:
        rng = random.Random(0)

    data = load_site_maps()

    # Tier 1: Curated domain
    domains = data.get("domains", {})
    if hostname in domains:
        entry = domains[hostname]
        pages = _build_pages_from_curated(rng, hostname, entry, data, request_time)
        cdn = entry.get("cdn_domains", [])
        return SiteMap(hostname=hostname, pages=pages, cdn_domains=cdn)

    # Tier 2: Tag-based synthesis
    tags = data.get("tags", {})
    for tag in domain_tags:
        if tag in tags:
            pages = _build_pages_from_tag(rng, hostname, tags[tag], data, request_time)
            return SiteMap(hostname=hostname, pages=pages)

    # Tier 3: Generic fallback
    generic = data.get("generic", {})
    pages = _build_pages_from_tag(rng, hostname, generic, data, request_time)
    return SiteMap(hostname=hostname, pages=pages)
