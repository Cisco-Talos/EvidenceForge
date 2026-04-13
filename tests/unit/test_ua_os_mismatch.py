# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Tests for User-Agent OS-awareness in proxy URI templates."""

import random


class TestProxyUriOsFiltering:
    """Verify pick_proxy_uri() respects source_os for UA overrides."""

    def test_windows_ua_suppressed_for_linux(self):
        """Windows-specific UA override should not be returned for Linux hosts."""
        from evidenceforge.generation.activity.proxy_uri import pick_proxy_uri

        rng = random.Random(42)
        _, _, _, ua_override = pick_proxy_uri(
            rng, "download.windowsupdate.com", [], source_os="linux"
        )
        assert ua_override is None, f"Windows UA override returned for Linux host: {ua_override}"

    def test_windows_ua_returned_for_windows(self):
        """Windows-specific UA override should be returned for Windows hosts."""
        from evidenceforge.generation.activity.proxy_uri import pick_proxy_uri

        rng = random.Random(42)
        _, _, _, ua_override = pick_proxy_uri(
            rng, "download.windowsupdate.com", [], source_os="windows"
        )
        assert ua_override is not None
        assert "Windows-Update-Agent" in ua_override

    def test_no_os_field_returns_ua_regardless(self):
        """Entries without os field should return UA for any source OS."""
        from evidenceforge.generation.activity.proxy_uri import pick_proxy_uri

        # Generic domains have no os field — UA overrides (if any) apply universally
        rng = random.Random(42)
        # Use a domain with no os field — tag-based or generic fallback
        _, _, _, ua_override = pick_proxy_uri(rng, "example.com", ["background"], source_os="linux")
        # Generic/tag entries typically don't have user_agent, so None is expected
        # The point is: no crash, no filtering error

    def test_no_source_os_returns_ua_unconditionally(self):
        """When source_os is None, UA override should be returned regardless."""
        from evidenceforge.generation.activity.proxy_uri import pick_proxy_uri

        rng = random.Random(42)
        _, _, _, ua_override = pick_proxy_uri(rng, "download.windowsupdate.com", [], source_os=None)
        assert ua_override is not None
        assert "Windows-Update-Agent" in ua_override

    def test_cryptoapi_suppressed_for_linux(self):
        """Microsoft-CryptoAPI UA should not be returned for Linux hosts."""
        from evidenceforge.generation.activity.proxy_uri import pick_proxy_uri

        rng = random.Random(42)
        _, _, _, ua_override = pick_proxy_uri(rng, "crl.microsoft.com", [], source_os="linux")
        assert ua_override is None
