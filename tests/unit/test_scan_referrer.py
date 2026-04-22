# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Tests for pick_scan_referrer() and per-preset send_referrer behavior."""

import random
from unittest.mock import MagicMock

import pytest

from evidenceforge.generation.activity.referrer import pick_scan_referrer


def _rng(seed: int = 42) -> random.Random:
    return random.Random(seed)


class TestPickScanReferrerNone:
    @pytest.mark.parametrize("config", [None, "none", "", False, 0])
    def test_none_variants_return_empty(self, config):
        rng = _rng()
        for _ in range(50):
            assert pick_scan_referrer(rng, "target.example.com", config) == ""


class TestPickScanReferrerSameOrigin:
    def test_always_returns_url(self):
        rng = _rng()
        for _ in range(50):
            result = pick_scan_referrer(rng, "target.example.com", "same_origin")
            assert "target.example.com" in result

    def test_uses_site_map_pages(self):
        site_map = MagicMock()
        site_map.pages = [MagicMock(path="/search"), MagicMock(path="/login")]
        rng = _rng()
        results = [
            pick_scan_referrer(rng, "target.example.com", "same_origin", site_map=site_map)
            for _ in range(100)
        ]
        assert all(("/search" in r or "/login" in r) for r in results)


class TestPickScanReferrerProbabilistic:
    def test_nikto_partial_crawl_approx(self):
        """Nikto send_referrer config: ~30% same-origin, ~70% blank."""
        config = {"mode": "same_origin", "probability": 0.3}
        rng = _rng()
        results = [pick_scan_referrer(rng, "target.example.com", config) for _ in range(1000)]
        non_empty = sum(1 for r in results if r)
        ratio = non_empty / len(results)
        # Allow ±8% around target 30%
        assert 0.22 <= ratio <= 0.38, f"non-empty ratio {ratio:.2f} out of range"

    def test_non_empty_contains_hostname(self):
        config = {"mode": "same_origin", "probability": 0.5}
        rng = _rng()
        results = [pick_scan_referrer(rng, "target.example.com", config) for _ in range(200)]
        non_empty = [r for r in results if r]
        assert all("target.example.com" in r for r in non_empty)

    def test_unknown_mode_returns_empty(self):
        config = {"mode": "social", "probability": 1.0}
        rng = _rng()
        for _ in range(50):
            assert pick_scan_referrer(rng, "target.example.com", config) == ""


class TestPresetIntegration:
    """Verify presets load correctly with send_referrer configs."""

    def test_nikto_preset_has_send_referrer(self):
        from evidenceforge.config.web_scan_presets import get_preset

        preset = get_preset("nikto")
        assert preset is not None
        assert "send_referrer" in preset
        cfg = preset["send_referrer"]
        assert isinstance(cfg, dict)
        assert cfg.get("mode") == "same_origin"
        assert 0.0 < cfg.get("probability", 0) <= 1.0

    @pytest.mark.parametrize("preset_name", ["gobuster", "sqlmap", "dirb", "nmap_http"])
    def test_non_crawler_presets_have_none(self, preset_name):
        from evidenceforge.config.web_scan_presets import get_preset

        preset = get_preset(preset_name)
        assert preset is not None
        assert preset.get("send_referrer") == "none"

    def test_nikto_ua_contains_testid_token(self):
        from evidenceforge.config.web_scan_presets import get_preset

        preset = get_preset("nikto")
        assert preset is not None
        assert "@NIKTO_TESTID@" in preset.get("user_agent", "")
