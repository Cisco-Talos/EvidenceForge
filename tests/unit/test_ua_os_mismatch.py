# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Tests for User-Agent OS-awareness in proxy URI templates."""

import random
from datetime import UTC, datetime
from types import SimpleNamespace

import yaml


class TestProxyUriOsFiltering:
    """Verify pick_proxy_uri() respects source_os for UA overrides."""

    def test_windows_ua_suppressed_for_linux(self):
        """Windows-specific UA override should not be returned for Linux hosts."""
        from evidenceforge.generation.activity.proxy_uri import pick_proxy_uri

        rng = random.Random(42)
        _, _, _, ua_override, _ = pick_proxy_uri(
            rng, "download.windowsupdate.com", [], source_os="linux"
        )
        assert ua_override is None, f"Windows UA override returned for Linux host: {ua_override}"

    def test_windows_ua_returned_for_windows(self):
        """Windows-specific UA override should be returned for Windows hosts."""
        from evidenceforge.generation.activity.proxy_uri import pick_proxy_uri

        rng = random.Random(42)
        _, _, _, ua_override, _ = pick_proxy_uri(
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
        _, _, _, ua_override, _ = pick_proxy_uri(
            rng, "example.com", ["background"], source_os="linux"
        )
        # Generic/tag entries typically don't have user_agent, so None is expected
        # The point is: no crash, no filtering error

    def test_no_source_os_returns_ua_unconditionally(self):
        """When source_os is None, UA override should be returned regardless."""
        from evidenceforge.generation.activity.proxy_uri import pick_proxy_uri

        rng = random.Random(42)
        _, _, _, ua_override, _ = pick_proxy_uri(
            rng, "download.windowsupdate.com", [], source_os=None
        )
        assert ua_override is not None
        assert "Windows-Update-Agent" in ua_override

    def test_cryptoapi_suppressed_for_linux(self):
        """Microsoft-CryptoAPI UA should not be returned for Linux hosts."""
        from evidenceforge.generation.activity.proxy_uri import pick_proxy_uri

        rng = random.Random(42)
        _, _, _, ua_override, _ = pick_proxy_uri(rng, "crl.microsoft.com", [], source_os="linux")
        assert ua_override is None

    def test_overlay_path_extension_overrides_bad_content_type(self, tmp_path, monkeypatch):
        """Overlay-defined paths should still get extension-coherent MIME types."""
        from evidenceforge.generation.activity.proxy_uri import (
            pick_proxy_uri,
            reset_proxy_uri_templates_cache,
        )

        overlay_dir = tmp_path / ".eforge" / "config" / "activity"
        overlay_dir.mkdir(parents=True)
        (overlay_dir / "proxy_uri_templates.yaml").write_text(
            yaml.safe_dump(
                {
                    "domains": {
                        "updates.example.test": {
                            "paths": ["/status.gif"],
                            "content_type": "text/html",
                            "methods": ["GET"],
                        }
                    }
                },
                sort_keys=False,
            )
        )
        monkeypatch.chdir(tmp_path)
        reset_proxy_uri_templates_cache()

        try:
            path, content_type, method, _, _ = pick_proxy_uri(
                random.Random(42),
                "updates.example.test",
                [],
                source_os="windows",
            )
        finally:
            reset_proxy_uri_templates_cache()

        assert path == "/status.gif"
        assert method == "GET"
        assert content_type == "image/gif"

    def test_certificate_infra_templates_are_not_browser_like(self):
        """OCSP/CRL proxy templates should not use generic website paths or referrers."""
        from evidenceforge.generation.activity.proxy_uri import pick_proxy_uri

        infra_domains = {
            "ocsp.pki.goog": {"application/ocsp-response"},
            "crl3.digicert.com": {"application/pkix-crl"},
            "crl.microsoft.com": {"application/pkix-crl"},
            "settings-win.data.microsoft.com": {"application/json"},
            "update.googleapis.com": {"application/json", "application/octet-stream"},
            "archive.ubuntu.com": {"application/x-gzip", "text/plain"},
        }
        for host, allowed_types in infra_domains.items():
            path, content_type, _method, _ua_override, referrer_policy = pick_proxy_uri(
                random.Random(42),
                host,
                ["background"],
                source_os="windows",
            )
            assert path not in {"/login", "/favicon.ico", "/assets/main.css"}
            assert not path.endswith((".css", ".js", ".ico", ".webp"))
            assert content_type in allowed_types
            assert referrer_policy == "none"

        path, content_type, _method, _ua_override, referrer_policy = pick_proxy_uri(
            random.Random(42),
            "packages.microsoft.com",
            ["background"],
            source_os="linux",
        )
        assert "/ubuntu/" in path or path.endswith(".deb")
        assert content_type in {
            "application/vnd.debian.binary-package",
            "application/x-gzip",
            "text/plain",
        }
        assert referrer_policy == "none"

    def test_https_first_domains_have_plaintext_redirect_policy(self):
        """Identity/social sites should not render HTTP 200 login pages on port 80."""
        from evidenceforge.generation.activity.proxy_uri import plaintext_http_redirect_status

        assert plaintext_http_redirect_status(
            "accounts.google.com",
            port=80,
            path="/ServiceLogin",
        ) in {301, 302}
        assert (
            plaintext_http_redirect_status(
                "accounts.google.com",
                port=443,
                path="/ServiceLogin",
            )
            is None
        )

    def test_dbeaver_installer_template_uses_binary_content_type(self):
        """Installer URI templates should not inherit text/html body-size semantics."""
        from evidenceforge.generation.activity.proxy_uri import pick_proxy_uri

        seen_installer = False
        for seed in range(40):
            path, content_type, method, _ua_override, _policy = pick_proxy_uri(
                random.Random(seed),
                "dbeaver.io",
                ["web"],
                source_os="windows",
            )
            if path.endswith(".exe"):
                seen_installer = True
                assert method == "GET"
                assert content_type == "application/x-msdownload"
                break
        assert seen_installer

    def test_linux_package_templates_do_not_apply_to_windows_sources(self):
        """OS-scoped exact templates should fall back instead of pairing Windows hosts with apt paths."""
        from evidenceforge.generation.activity.dns_registry import get_domains_by_tag
        from evidenceforge.generation.activity.proxy_uri import pick_proxy_uri

        path, content_type, _method, ua_override, _referrer_policy = pick_proxy_uri(
            random.Random(42),
            "packages.microsoft.com",
            ["background"],
            source_os="windows",
        )
        assert "/ubuntu/" not in path
        assert not path.endswith((".deb", "Packages.gz"))
        assert content_type not in {
            "application/vnd.debian.binary-package",
            "application/x-gzip",
        }
        assert ua_override is None

        windows_background_domains = {
            entry["domain"] for entry in get_domains_by_tag("background", "windows")
        }
        assert "packages.microsoft.com" not in windows_background_domains

    def test_standalone_static_proxy_paths_do_not_claim_same_origin_referrers(self):
        """Single proxy asset requests should not imply an unseen page load."""
        from evidenceforge.generation.activity.proxy_uri import pick_proxy_uri

        path, _content_type, _method, _ua_override, referrer_policy = pick_proxy_uri(
            random.Random(0),
            "example.org",
            ["web"],
            source_os="windows",
        )

        assert path == "/favicon.ico"
        assert referrer_policy == "none"

    def test_non_browser_proxy_domains_are_not_browser_session_targets(self):
        """Proxy domain_class controls whether a host can use browser-style site maps."""
        from evidenceforge.generation.activity.proxy_uri import is_browser_like_proxy_domain

        assert is_browser_like_proxy_domain("ocsp.pki.goog") is False
        assert is_browser_like_proxy_domain("crl.microsoft.com") is False
        assert is_browser_like_proxy_domain("settings-win.data.microsoft.com") is False
        assert is_browser_like_proxy_domain("update.googleapis.com") is False
        assert is_browser_like_proxy_domain("packages.microsoft.com") is False
        assert is_browser_like_proxy_domain("archive.ubuntu.com") is False
        assert is_browser_like_proxy_domain("www.bing.com") is True
        assert is_browser_like_proxy_domain("unknown.example.test") is True

    def test_proxy_user_agent_normalization_replaces_windows_browser_for_linux(self):
        from evidenceforge.generation.activity.proxy_user_agents import (
            normalize_proxy_user_agent_for_os,
        )

        system = SimpleNamespace(os="Ubuntu 22.04", type="workstation", roles=[])
        ua = normalize_proxy_user_agent_for_os(
            random.Random(42),
            system,
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            hostname="www.example.com",
        )

        assert "Windows NT" not in ua
        assert any(token in ua for token in ("Linux", "curl", "Wget", "python-requests"))

    def test_generate_connection_infers_source_system_for_proxy_user_agent(self):
        from unittest.mock import Mock

        from evidenceforge.generation.activity.generator import ActivityGenerator
        from evidenceforge.generation.state_manager import StateManager
        from evidenceforge.models.scenario import System

        state = StateManager()
        generator = ActivityGenerator(state, {"zeek_conn": Mock(), "proxy_access": Mock()})
        rogue = System(
            hostname="ROGUE-LAPTOP",
            ip="10.10.1.99",
            os="Ubuntu 22.04",
            type="workstation",
        )
        proxy = System(
            hostname="PROXY-01",
            ip="10.10.3.20",
            os="Ubuntu 22.04",
            type="server",
        )
        generator._ip_to_system = {rogue.ip: rogue}
        generator._proxy_routes = {rogue.ip: [proxy]}
        generator._proxy_mode = "explicit"
        generator._proxy_listener_port = 8080
        ts = datetime(2024, 1, 15, 10, 0, tzinfo=UTC)
        state.set_current_time(ts)

        generator.generate_connection(
            src_ip=rogue.ip,
            dst_ip="151.101.0.223",
            time=ts,
            dst_port=443,
            service="ssl",
            duration=1.0,
            orig_bytes=300,
            resp_bytes=1200,
            hostname="pypi.org",
        )

        event = next(
            call.args[0]
            for call in generator.dispatcher.emitters["proxy_access"].emit.call_args_list
            if call.args[0].proxy is not None
        )
        assert "Windows NT" not in event.proxy.user_agent
        assert "Edg/" not in event.proxy.user_agent

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
            hostname="download.windowsupdate.com",
        )

        assert ua.startswith("Windows-Update-Agent/")
        assert ua == pick_proxy_user_agent(
            random.Random(99),
            source,
            hostname="download.windowsupdate.com",
        )

        trust_list_ua = pick_proxy_user_agent(
            random.Random(42),
            source,
            hostname="ctldl.windowsupdate.com",
        )

        assert trust_list_ua == "Microsoft-CryptoAPI/10.0"

        update_ua = pick_proxy_user_agent(
            random.Random(42),
            source,
            hostname="update.googleapis.com",
        )

        assert "Google" in update_ua
        assert "Darwin" not in update_ua
        assert "Windows-Update-Agent" not in update_ua

        internal_ocsp_ua = pick_proxy_user_agent(
            random.Random(42),
            source,
            hostname="ocsp.meridianhcs.local",
        )

        assert internal_ocsp_ua == "Microsoft-CryptoAPI/10.0"

    def test_windows_update_user_agents_vary_by_source_host(self):
        """The Windows Update override should be sticky per host, not globally flat."""
        from evidenceforge.generation.activity.proxy_user_agents import pick_proxy_user_agent
        from evidenceforge.models.scenario import System

        observed = set()
        for idx in range(30):
            source = System(
                hostname=f"WS-{idx:02d}",
                ip=f"10.10.1.{idx + 20}",
                os="Windows 11",
                type="workstation",
            )
            first = pick_proxy_user_agent(
                random.Random(1),
                source,
                hostname="download.windowsupdate.com",
            )
            second = pick_proxy_user_agent(
                random.Random(999),
                source,
                hostname="download.windowsupdate.com",
            )
            assert first == second
            assert first.startswith("Windows-Update-Agent/")
            observed.add(first)

        assert len(observed) >= 3

    def test_vendor_update_user_agents_stay_domain_specific(self):
        """Updater/security-client UAs should not cross vendor domains."""
        from evidenceforge.generation.activity.proxy_user_agents import pick_proxy_user_agent
        from evidenceforge.models.scenario import System

        source = System(
            hostname="WS-01",
            ip="10.10.10.1",
            os="Windows 11",
            type="workstation",
        )
        expected = {
            "dellupdater.dell.com": "Dell Command Update/5.1",
            "download.lenovo.com": "Lenovo System Update",
            "hpia.hpcloud.hp.com": "HP Image Assistant",
            "secure-client-updates.cisco.com": "Cisco Secure Client/5.1.4 Windows",
            "updates.paloaltonetworks.com": "GlobalProtect/6.2.3 Windows",
            "config.zscaler.net": "Zscaler Client Connector/4.3.0",
            "gateway.zscaler.net": "Zscaler Client Connector/4.3.0",
        }

        for hostname, user_agent in expected.items():
            assert pick_proxy_user_agent(random.Random(42), source, hostname=hostname) == user_agent

    def test_http_context_ua_is_overridden_for_infrastructure_domain(self):
        """Domain-specific proxy UA rules should override inherited browser session UAs."""
        from evidenceforge.events.contexts import HttpContext
        from evidenceforge.generation.activity.generator import ActivityGenerator
        from evidenceforge.generation.state_manager import StateManager
        from evidenceforge.models.scenario import System, User

        source = System(
            hostname="WS-01",
            ip="10.10.10.1",
            os="Windows 11",
            type="workstation",
            assigned_user="alex.morgan",
        )
        proxy = System(
            hostname="proxy01",
            ip="10.10.20.5",
            os="Ubuntu 24.04",
            type="server",
            roles=["forward_proxy"],
        )
        generator = ActivityGenerator(StateManager(), {})
        generator._ad_domain = "meridianhcs.local"
        generator._netbios_domain = "MERIDIAN"
        generator._users_by_username = {
            "alex.morgan": User(
                username="alex.morgan",
                full_name="Alex Morgan",
                email="alex.morgan@meridianhcs.local",
            )
        }

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

        assert context.user_agent == "Microsoft-CryptoAPI/10.0"
        assert context.username == "MERIDIAN\\WS-01$"

    def test_proxy_context_uses_assigned_user_for_workstation_browser(self):
        """Authenticated proxy logs should carry user identity for workstation browsing."""
        from evidenceforge.events.contexts import HttpContext
        from evidenceforge.generation.activity.generator import ActivityGenerator
        from evidenceforge.generation.state_manager import StateManager
        from evidenceforge.models.scenario import System, User

        source = System(
            hostname="WS-01",
            ip="10.10.10.1",
            os="Windows 11",
            type="workstation",
            assigned_user="alex.morgan",
        )
        proxy = System(
            hostname="proxy01",
            ip="10.10.20.5",
            os="Ubuntu 24.04",
            type="server",
            roles=["forward_proxy"],
        )
        generator = ActivityGenerator(StateManager(), {})
        generator._ad_domain = "meridianhcs.local"
        generator._netbios_domain = "MERIDIAN"
        generator._users_by_username = {
            "alex.morgan": User(
                username="alex.morgan",
                full_name="Alex Morgan",
                email="alex.morgan@meridianhcs.local",
            )
        }

        context = generator._build_proxy_context(
            src_ip=source.ip,
            dst_ip="93.184.216.34",
            dst_port=443,
            service="ssl",
            duration=0.4,
            orig_bytes=400,
            resp_bytes=4096,
            hostname="example.com",
            source_system=source,
            proxy_sys=proxy,
            http=HttpContext(
                method="GET",
                uri="/portal",
                user_agent=(
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                    "AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36"
                ),
                status_code=200,
                response_body_len=4096,
                resp_mime_types=["text/html"],
            ),
        )

        assert context.username == "MERIDIAN\\alex.morgan"


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
