# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Tests for the pick_referrer() helper in referrer.py."""

import random
from unittest.mock import MagicMock

from evidenceforge.generation.activity.referrer import pick_referrer


def _rng(seed: int = 42) -> random.Random:
    return random.Random(seed)


class TestPickReferrerBot:
    def test_bot_always_empty(self):
        rng = _rng()
        for _ in range(100):
            assert pick_referrer(rng, "example.com", is_bot=True) == ""

    def test_bot_ignores_site_map(self):
        site_map = MagicMock()
        site_map.pages = [MagicMock(path="/about")]
        rng = _rng()
        for _ in range(50):
            assert pick_referrer(rng, "example.com", is_bot=True, site_map=site_map) == ""


class TestPickReferrerScan:
    def test_scan_context_always_empty(self):
        rng = _rng()
        for _ in range(100):
            assert pick_referrer(rng, "target.example.com", context="scan") == ""


class TestPickReferrerApi:
    def test_api_mostly_empty(self):
        rng = _rng()
        results = [pick_referrer(rng, "api.example.com", context="api") for _ in range(1000)]
        empty = sum(1 for r in results if r == "")
        assert empty / len(results) > 0.70  # at least 70% blank

    def test_api_same_origin_uses_hostname(self):
        site_map = MagicMock()
        site_map.pages = [MagicMock(path="/docs")]
        rng = _rng()
        results = [
            pick_referrer(rng, "api.example.com", context="api", site_map=site_map)
            for _ in range(200)
        ]
        non_empty = [r for r in results if r]
        assert all("api.example.com" in r for r in non_empty)


class TestPickReferrerGeneral:
    def test_distribution_approximate(self):
        rng = _rng()
        n = 10000
        results = [pick_referrer(rng, "www.example.com", context="general") for _ in range(n)]
        empty = sum(1 for r in results if r == "")
        search = sum(1 for r in results if "google.com" in r or "bing.com" in r)
        same_origin = sum(1 for r in results if "www.example.com" in r)
        social = sum(
            1
            for r in results
            if any(s in r for s in ("reddit.com", "t.co", "linkedin.com", "ycombinator.com"))
        )
        # Tolerances are ±8% to avoid flaky tests
        assert 0.47 <= empty / n <= 0.63, f"empty fraction {empty / n:.2f} out of range"
        assert 0.12 <= search / n <= 0.28, f"search fraction {search / n:.2f} out of range"
        assert 0.12 <= same_origin / n <= 0.28, (
            f"same_origin fraction {same_origin / n:.2f} out of range"
        )
        assert 0.00 <= social / n <= 0.13, f"social fraction {social / n:.2f} out of range"

    def test_same_origin_without_site_map_uses_root(self):
        # Without a site_map, same-origin referrers should still use the hostname at /
        rng = _rng(seed=7)  # seed chosen to hit the same-origin branch
        results = [pick_referrer(rng, "shop.example.com", context="general") for _ in range(500)]
        same_origin = [r for r in results if "shop.example.com" in r]
        assert all(r.endswith("/") for r in same_origin)

    def test_same_origin_uses_site_map_pages(self):
        site_map = MagicMock()
        site_map.pages = [MagicMock(path="/products"), MagicMock(path="/about")]
        rng = _rng(seed=7)
        results = [
            pick_referrer(rng, "shop.example.com", context="general", site_map=site_map)
            for _ in range(500)
        ]
        same_origin = [r for r in results if "shop.example.com" in r]
        assert all(("/products" in r or "/about" in r) for r in same_origin)
