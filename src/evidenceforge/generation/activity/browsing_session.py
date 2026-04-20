# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Browsing session generator for realistic multi-request site visits.

Generates a list of BrowsingRequest objects representing a complete browsing
session: landing page, subresource cascade (CSS, JS, images, fonts, API calls),
navigation to additional pages, and referrer chains throughout.

This is a pure function with no engine dependencies — fully testable in isolation.
"""

from __future__ import annotations

import random
from dataclasses import dataclass

from evidenceforge.generation.activity.site_maps import (
    PageDef,
    SiteMap,
    SubresourceDef,
    get_site_map,
)


@dataclass
class BrowsingRequest:
    """A single HTTP request within a browsing session."""

    time_offset_ms: int  # Offset from session start in milliseconds
    hostname: str  # Target hostname (may differ from page host for CDN)
    path: str  # URI path
    method: str  # HTTP method (GET, POST)
    content_type: str  # Expected response MIME type
    referrer: str  # Full referrer URL (https://host/path or "")
    trans_depth: int  # HTTP transaction depth within connection
    is_page_load: bool  # True for the page itself, False for subresources
    response_body_len: int  # Estimated response size in bytes
    request_body_len: int  # Estimated request size in bytes


# ── Response size ranges by content type ──────────────────────────────

_RESPONSE_SIZE_RANGES: dict[str, tuple[int, int]] = {
    "text/html": (5_000, 80_000),
    "text/css": (2_000, 50_000),
    "application/javascript": (10_000, 200_000),
    "image/jpeg": (5_000, 500_000),
    "image/png": (2_000, 300_000),
    "image/webp": (5_000, 400_000),
    "image/gif": (500, 50_000),
    "image/svg+xml": (500, 20_000),
    "image/x-icon": (500, 5_000),
    "font/woff2": (20_000, 100_000),
    "font/woff": (20_000, 100_000),
    "application/json": (200, 50_000),
    "application/octet-stream": (1_000, 100_000),
}

# ── Intensity parameters ──────────────────────────────────────────────

_INTENSITY_PARAMS: dict[str, dict[str, tuple[int, int]]] = {
    "light": {
        "pages": (1, 1),
        "subresources_per_page": (3, 6),
        "navigations": (0, 0),
    },
    "normal": {
        "pages": (1, 2),
        "subresources_per_page": (5, 10),
        "navigations": (0, 1),
    },
    "heavy": {
        "pages": (2, 4),
        "subresources_per_page": (8, 15),
        "navigations": (1, 3),
    },
}


def _response_size(rng: random.Random, content_type: str) -> int:
    """Generate a realistic response size for a given content type."""
    lo, hi = _RESPONSE_SIZE_RANGES.get(content_type, (500, 50_000))
    return rng.randint(lo, hi)


def _request_size(rng: random.Random, method: str) -> int:
    """Generate a realistic request size based on HTTP method."""
    if method == "POST":
        return rng.randint(100, 10_000)
    return 0


def _make_referrer(hostname: str, path: str, port: int = 443) -> str:
    """Build a full referrer URL from hostname and path."""
    scheme = "https" if port == 443 else "http"
    return f"{scheme}://{hostname}{path}"


def _pick_subresources(
    rng: random.Random,
    page: PageDef,
    site_map: SiteMap,
    count: int,
) -> list[SubresourceDef]:
    """Select subresources for a page load.

    If the page has enough defined subresources, sample from them.
    If it has fewer than requested, use all of them.
    Always includes favicon.ico if not already present.
    """
    available = list(page.subresources)

    # Ensure favicon is present
    has_favicon = any("/favicon.ico" in s.path for s in available)
    if not has_favicon:
        available.append(SubresourceDef(path="/favicon.ico", content_type="image/x-icon"))

    if len(available) <= count:
        return available

    # Always include favicon, then sample the rest
    favicon = [s for s in available if "/favicon.ico" in s.path]
    others = [s for s in available if "/favicon.ico" not in s.path]
    sampled = rng.sample(others, min(count - len(favicon), len(others)))
    return favicon + sampled


def generate_browsing_session(
    rng: random.Random,
    hostname: str,
    domain_tags: list[str],
    source_os: str = "windows",
    browsing_intensity: str = "normal",
    port: int = 443,
) -> list[BrowsingRequest]:
    """Generate a complete browsing session as a list of HTTP requests.

    Produces a landing page, its subresource cascade, then navigates to
    additional pages with their own subresources. Maintains referrer chains
    throughout.

    Args:
        rng: Random instance for deterministic generation.
        hostname: Target domain (e.g., "outlook.office365.com").
        domain_tags: Tags from dns_registry for tag-based fallback.
        source_os: Source host OS ("windows" or "linux").
        browsing_intensity: "light", "normal", or "heavy".
        port: Destination port (443 for HTTPS, 80 for HTTP).

    Returns:
        List of BrowsingRequest objects sorted by time_offset_ms.
    """
    site_map = get_site_map(hostname, domain_tags, rng)
    params = _INTENSITY_PARAMS.get(browsing_intensity, _INTENSITY_PARAMS["normal"])

    if not site_map.pages:
        return []

    requests: list[BrowsingRequest] = []
    current_ms = 0

    # Landing page referrer: most sessions start from a direct navigation
    # (typed URL, bookmark) with no referrer. ~20% come from a search engine
    # link click, which carries the search page as referrer.
    landing_roll = rng.random()
    if landing_roll < 0.80:
        previous_page_url = ""  # Direct navigation / bookmark
    else:
        # Arrived via search engine link click
        search_engines = [
            "https://www.google.com/search?q=",
            "https://www.bing.com/search?q=",
        ]
        previous_page_url = rng.choice(search_engines) + hostname.replace(".", "+")

    # Determine number of pages to visit
    n_pages_lo, n_pages_hi = params["pages"]
    nav_lo, nav_hi = params["navigations"]
    total_pages = rng.randint(n_pages_lo, n_pages_hi) + rng.randint(nav_lo, nav_hi)
    total_pages = min(total_pages, len(site_map.pages) + 2)  # Don't exceed available
    total_pages = max(1, total_pages)

    # Track visited pages to avoid exact repeats (but allow revisits via nav)
    visited_indices: list[int] = []

    # Landing page selection: 70% start at root/index, 30% land on a
    # deeper page (bookmark, shared link, search result deep link).
    if rng.random() < 0.70 or len(site_map.pages) == 1:
        current_page_idx = 0
    else:
        current_page_idx = rng.randint(0, len(site_map.pages) - 1)

    for page_num in range(total_pages):
        if page_num == 0:
            pass  # Use the landing page index selected above
        else:
            # Navigation: pick from current page's nav_targets or other pages
            current_page = site_map.pages[current_page_idx]
            next_idx = _pick_next_page(rng, site_map, current_page, visited_indices)
            current_page_idx = next_idx

            # Inter-page navigation delay: 3-30 seconds
            current_ms += rng.randint(3_000, 30_000)

        page = site_map.pages[current_page_idx]
        visited_indices.append(current_page_idx)
        page_url = _make_referrer(hostname, page.path, port)

        # Emit the page load request
        requests.append(
            BrowsingRequest(
                time_offset_ms=current_ms,
                hostname=hostname,
                path=page.path,
                method="GET",
                content_type=page.content_type,
                referrer=previous_page_url,
                trans_depth=1,
                is_page_load=True,
                response_body_len=_response_size(rng, page.content_type),
                request_body_len=_request_size(rng, "GET"),
            )
        )

        # Emit subresource requests
        sub_lo, sub_hi = params["subresources_per_page"]
        n_subs = rng.randint(sub_lo, sub_hi)
        subresources = _pick_subresources(rng, page, site_map, n_subs)

        for sub_idx, sub in enumerate(subresources):
            sub_hostname = sub.host or hostname

            # Timing: CSS/JS load early, images later, API calls latest
            if sub.content_type in ("text/css", "application/javascript"):
                delay = rng.randint(50, 200)
            elif sub.content_type.startswith("font/"):
                delay = rng.randint(300, 600)
            elif sub.content_type.startswith("image/"):
                delay = rng.randint(200, 800)
            elif sub.content_type == "application/json":
                delay = rng.randint(500, 2_000)
            else:
                delay = rng.randint(100, 500)

            requests.append(
                BrowsingRequest(
                    time_offset_ms=current_ms + delay,
                    hostname=sub_hostname,
                    path=sub.path,
                    method=sub.method,
                    content_type=sub.content_type,
                    referrer=page_url,
                    trans_depth=sub_idx + 2,  # Page is depth 1, subs start at 2
                    is_page_load=False,
                    response_body_len=_response_size(rng, sub.content_type),
                    request_body_len=_request_size(rng, sub.method),
                )
            )

        # Advance time past subresource loading
        current_ms += rng.randint(800, 2_000)
        previous_page_url = page_url

    # Sort by time offset for chronological emission
    requests.sort(key=lambda r: r.time_offset_ms)
    return requests


def _pick_next_page(
    rng: random.Random,
    site_map: SiteMap,
    current_page: PageDef,
    visited_indices: list[int],
) -> int:
    """Pick the next page to navigate to.

    70% chance: follow a nav_target from the current page
    30% chance: jump to a different page in the site map
    """
    if current_page.nav_targets and rng.random() < 0.70:
        # Follow a navigation target — find matching page in site map
        target_path = rng.choice(current_page.nav_targets)
        for idx, page in enumerate(site_map.pages):
            if page.path == target_path:
                return idx
        # Nav target doesn't match any page exactly (may have template vars);
        # fall through to random page selection

    # Jump to a different page (avoid repeating the most recent)
    candidates = list(range(len(site_map.pages)))
    if visited_indices and len(candidates) > 1:
        last = visited_indices[-1]
        candidates = [i for i in candidates if i != last]
    return rng.choice(candidates) if candidates else 0
