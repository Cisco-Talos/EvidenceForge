# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Site map loader for browsing session generation.

Loads per-domain and per-tag site maps from site_maps.yaml.
Provides get_site_map() for looking up page structures, subresource
definitions, and CDN domain associations.
"""

from __future__ import annotations

import random
import uuid
from dataclasses import dataclass, field
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


def _substitute_vars(rng: random.Random, path: str, data: dict[str, Any]) -> str:
    """Replace template variables in a URI path."""
    if "{guid}" in path:
        path = path.replace("{guid}", str(uuid.UUID(int=rng.getrandbits(128))), 1)
        if "{guid}" in path:
            path = path.replace("{guid}", str(uuid.UUID(int=rng.getrandbits(128))), 1)
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
    return path


def _build_subresources(
    rng: random.Random,
    raw_list: list[dict[str, str]],
    data: dict[str, Any],
) -> list[SubresourceDef]:
    """Convert raw YAML subresource dicts to SubresourceDef objects."""
    result = []
    for item in raw_list:
        path = _substitute_vars(rng, item.get("path", "/"), data)
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
    domain_entry: dict[str, Any],
    data: dict[str, Any],
) -> list[PageDef]:
    """Build PageDef list from a curated domain entry."""
    pages = []
    for page_raw in domain_entry.get("pages", []):
        nav_targets = [_substitute_vars(rng, t, data) for t in page_raw.get("nav_targets", [])]
        subresources = _build_subresources(rng, page_raw.get("subresources", []), data)
        pages.append(
            PageDef(
                path=_substitute_vars(rng, page_raw["path"], data),
                content_type=page_raw.get("content_type", "text/html"),
                nav_targets=nav_targets,
                subresources=subresources,
            )
        )
    return pages


def _build_pages_from_tag(
    rng: random.Random,
    tag_entry: dict[str, Any],
    data: dict[str, Any],
) -> list[PageDef]:
    """Build PageDef list from a tag-based synthesis template."""
    patterns = tag_entry.get("subresource_patterns", {})
    pages = []
    for tmpl in tag_entry.get("page_templates", []):
        pattern_name = tmpl.get("subresource_pattern", "")
        raw_subs = patterns.get(pattern_name, [])
        nav_targets = [_substitute_vars(rng, t, data) for t in tmpl.get("nav_targets", [])]
        subresources = _build_subresources(rng, raw_subs, data)
        pages.append(
            PageDef(
                path=_substitute_vars(rng, tmpl["path"], data),
                nav_targets=nav_targets,
                subresources=subresources,
            )
        )
    return pages


def get_site_map(
    hostname: str,
    domain_tags: list[str],
    rng: random.Random | None = None,
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
        pages = _build_pages_from_curated(rng, entry, data)
        cdn = entry.get("cdn_domains", [])
        return SiteMap(hostname=hostname, pages=pages, cdn_domains=cdn)

    # Tier 2: Tag-based synthesis
    tags = data.get("tags", {})
    for tag in domain_tags:
        if tag in tags:
            pages = _build_pages_from_tag(rng, tags[tag], data)
            return SiteMap(hostname=hostname, pages=pages)

    # Tier 3: Generic fallback
    generic = data.get("generic", {})
    pages = _build_pages_from_tag(rng, generic, data)
    return SiteMap(hostname=hostname, pages=pages)
