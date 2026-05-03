# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Referer header generation for HTTP events.

Provides pick_referrer() for human-like browsing traffic and
pick_scan_referrer() for scanner traffic, both grounded in real-world
header behavior.
"""

from __future__ import annotations

import random
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    pass

_SEARCH_ENGINES = [
    "https://www.google.com/search?q=",
    "https://www.bing.com/search?q=",
]

_SOCIAL_REFERERS = [
    "https://www.reddit.com/",
    "https://t.co/",
    "https://www.linkedin.com/",
    "https://news.ycombinator.com/",
]


def _allows_search_referrer(hostname: str) -> bool:
    """Return whether a public search referrer is plausible for this host."""
    normalized = hostname.strip().lower()
    if "." not in normalized:
        return False
    if normalized.endswith((".local", ".lan", ".internal", ".corp")):
        return False
    if any(
        part.startswith(("ws-", "dc-", "app-", "db-", "file-", "mail-"))
        for part in normalized.split(".")
    ):
        return False
    return True


def _make_url(hostname: str, path: str, port: int = 443) -> str:
    scheme = "https" if port == 443 else "http"
    return f"{scheme}://{hostname}{path}"


def pick_referrer(
    rng: random.Random,
    hostname: str,
    *,
    site_map: Any = None,
    is_bot: bool = False,
    context: str = "general",
    port: int = 80,
) -> str:
    """Return a realistic Referer value for an HTTP request.

    Args:
        rng: Random number generator.
        hostname: The destination hostname (used for same-origin URLs).
        site_map: Optional SiteMap; enables same-origin referrer generation.
        is_bot: If True, always returns "" (bots don't send Referer).
        context: "general" (browser), "scan" (scanner), or "api" (API call).
        port: Destination port, used to choose http vs https scheme.

    Returns:
        Referer string, or "" for direct navigation / no referer.
    """
    if is_bot:
        return ""
    if context == "scan":
        return ""
    if context == "api":
        roll = rng.random()
        if roll < 0.80:
            return ""
        # 20% same-origin
        if site_map and site_map.pages:
            page = rng.choice(site_map.pages)
            return _make_url(hostname, page.path, port)
        return _make_url(hostname, "/", port)

    # context == "general"
    roll = rng.random()
    if roll < 0.55:
        return ""
    elif roll < 0.75 and _allows_search_referrer(hostname):
        # 20% search engine
        engine = rng.choice(_SEARCH_ENGINES)
        return engine + hostname.replace(".", "+")
    elif roll < 0.95:
        # 20% same-origin
        if site_map and site_map.pages:
            page = rng.choice(site_map.pages)
            return _make_url(hostname, page.path, port)
        return _make_url(hostname, "/", port)
    else:
        # 5% social/news
        return rng.choice(_SOCIAL_REFERERS)


def pick_scan_referrer(
    rng: random.Random,
    hostname: str,
    send_referrer_config: Any,
    *,
    site_map: Any = None,
    port: int = 80,
) -> str:
    """Return a Referer value for a scanner request per preset configuration.

    Args:
        rng: Random number generator.
        hostname: The target hostname.
        send_referrer_config: Value of the preset's ``send_referrer`` field.
            - None / "none" / falsy → always ""
            - "same_origin" → always a same-origin URL
            - dict with keys "mode" and optional "probability" → probabilistic
              same-origin (used for Nikto partial-crawl behavior)
        site_map: Optional SiteMap for same-origin path selection.
        port: Destination port.

    Returns:
        Referer string or "".
    """
    if not send_referrer_config or send_referrer_config == "none":
        return ""

    if send_referrer_config == "same_origin":
        if site_map and site_map.pages:
            page = rng.choice(site_map.pages)
            return _make_url(hostname, page.path, port)
        return _make_url(hostname, "/", port)

    if isinstance(send_referrer_config, dict):
        mode = send_referrer_config.get("mode", "none")
        prob = float(send_referrer_config.get("probability", 1.0))
        if mode == "same_origin" and rng.random() < prob:
            if site_map and site_map.pages:
                page = rng.choice(site_map.pages)
                return _make_url(hostname, page.path, port)
            return _make_url(hostname, "/", port)
        return ""

    return ""
