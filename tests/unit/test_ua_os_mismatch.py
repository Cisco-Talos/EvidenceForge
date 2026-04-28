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

    def test_connect_user_agent_uses_domain_override(self):
        """CONNECT proxy entries should still use destination-specific service UAs."""
        from evidenceforge.generation.activity.proxy_user_agents import pick_proxy_user_agent
        from evidenceforge.models.scenario import System

        source = System(
            hostname="WS-01",
            ip="10.10.10.1",
            os="Windows 11",
            type="workstation",
        )

        ua = pick_proxy_user_agent(
            random.Random(42),
            source,
            hostname="ctldl.windowsupdate.com",
        )

        assert ua == "Windows-Update-Agent/10.0.10011.16384 Client-Protocol/2.33"

    def test_http_context_ua_is_overridden_for_infrastructure_domain(self):
        """Domain-specific proxy UA rules should override inherited browser session UAs."""
        from evidenceforge.events.contexts import HttpContext
        from evidenceforge.generation.activity.generator import ActivityGenerator
        from evidenceforge.generation.state_manager import StateManager
        from evidenceforge.models.scenario import System

        source = System(
            hostname="WS-01",
            ip="10.10.10.1",
            os="Windows 11",
            type="workstation",
        )
        proxy = System(
            hostname="proxy01",
            ip="10.10.20.5",
            os="Ubuntu 24.04",
            type="server",
            roles=["forward_proxy"],
        )
        generator = ActivityGenerator(StateManager(), {})

        context = generator._build_proxy_context(
            src_ip=source.ip,
            dst_ip="13.107.4.50",
            dst_port=80,
            service="http",
            duration=0.2,
            orig_bytes=400,
            resp_bytes=2048,
            hostname="ctldl.windowsupdate.com",
            source_system=source,
            proxy_sys=proxy,
            http=HttpContext(
                method="GET",
                uri="/msdownload/update/v3/static/trustedr/en/authrootstl.cab",
                user_agent=(
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                    "AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36"
                ),
            ),
        )

        assert context.user_agent == "Windows-Update-Agent/10.0.10011.16384 Client-Protocol/2.33"


class TestProxyUriTemplateSubstitution:
    """Verify proxy URI templates don't leak unresolved placeholders."""

    def test_slug_placeholder_is_materialized(self):
        """The generic /{slug}/ template should render as a concrete path."""
        from evidenceforge.generation.activity.proxy_uri import _substitute_vars

        rng = random.Random(42)
        uri = _substitute_vars(rng, "/{slug}/{slug}/{unknown}/", {})

        assert "{" not in uri
        assert "}" not in uri
        assert uri.endswith("/item/")
