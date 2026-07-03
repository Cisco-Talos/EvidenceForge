# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Tests for browsing session generator."""

import random
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from unittest.mock import MagicMock

from evidenceforge.generation.actions import BrowserSessionActionBundle, BrowserSessionRequest
from evidenceforge.generation.activity import browsing_session
from evidenceforge.generation.activity.browsing_session import (
    BrowsingRequest,
    generate_browsing_session,
)
from evidenceforge.generation.activity.timing_profiles import reset_timing_profiles_cache


class TestBrowsingSessionBasics:
    """Basic session generation behavior."""

    def test_returns_non_empty_list(self):
        rng = random.Random(42)
        requests = generate_browsing_session(rng, "outlook.office365.com", [])
        assert len(requests) > 0

    def test_returns_browsing_request_objects(self):
        rng = random.Random(42)
        requests = generate_browsing_session(rng, "outlook.office365.com", [])
        for req in requests:
            assert isinstance(req, BrowsingRequest)

    def test_first_request_is_page_load(self):
        rng = random.Random(42)
        requests = generate_browsing_session(rng, "outlook.office365.com", [])
        assert requests[0].is_page_load is True

    def test_first_request_is_get(self):
        rng = random.Random(42)
        requests = generate_browsing_session(rng, "www.google.com", [])
        assert requests[0].method == "GET"

    def test_time_offsets_non_negative(self):
        rng = random.Random(42)
        requests = generate_browsing_session(rng, "github.com", [])
        for req in requests:
            assert req.time_offset_ms >= 0

    def test_sorted_by_time(self):
        rng = random.Random(42)
        requests = generate_browsing_session(rng, "github.com", [])
        offsets = [r.time_offset_ms for r in requests]
        assert offsets == sorted(offsets)

    def test_https_first_domain_redirects_plaintext_http_without_assets(self):
        rng = random.Random(42)
        requests = generate_browsing_session(rng, "accounts.google.com", [], port=80)

        assert len(requests) == 1
        assert requests[0].is_page_load is True
        assert requests[0].status_code in {301, 302}
        assert 120 <= requests[0].response_body_len <= 480

    def test_plaintext_http_landing_pages_do_not_send_https_referrers(self):
        """Browser sessions should not send HTTPS referrers to plaintext HTTP pages."""
        for seed in range(200):
            requests = generate_browsing_session(
                random.Random(seed),
                "www.office.com",
                ["web", "saas"],
                port=80,
            )
            assert not any(req.referrer.startswith("https://") for req in requests)


class TestBrowserSessionActionBundle:
    """Action-bundle expansion behavior."""

    def test_request_has_stable_action_anchor(self):
        source_system = SimpleNamespace(hostname="WKS-01")
        request = BrowserSessionRequest(
            src_ip="10.0.10.50",
            dst_ip="142.250.80.46",
            time=datetime(2024, 1, 15, 10, 0, tzinfo=UTC),
            hostname="www.google.com",
            dst_port=443,
            service="ssl",
            source_system=source_system,
            domain_tags=("web",),
            user_agent="Mozilla/5.0",
        )
        same_request = BrowserSessionRequest(
            src_ip="10.0.10.50",
            dst_ip="142.250.80.46",
            time=datetime(2024, 1, 15, 10, 0, tzinfo=UTC),
            hostname="www.google.com",
            dst_port=443,
            service="ssl",
            source_system=source_system,
            domain_tags=("web",),
            user_agent="Mozilla/5.0",
        )
        bundle = BrowserSessionActionBundle(
            request=request,
            executor=MagicMock(),
            rng=random.Random(7),
        )

        assert request.stable_id == same_request.stable_id
        assert bundle.anchor.family == "browser_session"
        assert bundle.anchor.stable_id == request.stable_id

    def test_bundle_expands_page_and_subresource_to_grouped_http_flows(self, monkeypatch):
        monkeypatch.setattr(
            browsing_session,
            "generate_browsing_session",
            lambda **kwargs: [
                BrowsingRequest(
                    time_offset_ms=0,
                    hostname=kwargs["hostname"],
                    path="/",
                    method="GET",
                    content_type="text/html",
                    referrer="",
                    trans_depth=1,
                    is_page_load=True,
                    response_body_len=4096,
                    request_body_len=0,
                    status_code=200,
                ),
                BrowsingRequest(
                    time_offset_ms=100,
                    hostname=kwargs["hostname"],
                    path="/assets/app.css",
                    method="GET",
                    content_type="text/css",
                    referrer=f"https://{kwargs['hostname']}/",
                    trans_depth=2,
                    is_page_load=False,
                    response_body_len=2048,
                    request_body_len=0,
                    status_code=200,
                ),
            ],
        )
        emitted = []
        executor = MagicMock()
        executor.state_manager = MagicMock()
        executor.generate_connection.side_effect = lambda **kwargs: (
            emitted.append(kwargs) or f"C{len(emitted)}"
        )

        result = BrowserSessionActionBundle(
            request=BrowserSessionRequest(
                src_ip="10.0.10.50",
                dst_ip="142.250.80.46",
                time=datetime(2024, 1, 15, 10, 0, tzinfo=UTC),
                hostname="www.google.com",
                dst_port=443,
                service="ssl",
                source_system=SimpleNamespace(hostname="WKS-01"),
                domain_tags=("web",),
                user_agent="Mozilla/5.0",
            ),
            executor=executor,
            rng=random.Random(11),
        ).execute_with_result()

        assert result.first_uid == "C1"
        assert result.request_count == 2
        assert result.page_load_count == 1
        assert len(emitted) == 2
        assert emitted[0]["http"].trans_depth == 1
        assert emitted[0]["http"].flow_transaction_count == 2
        assert emitted[0]["resp_bytes"] >= 4096 + 2048
        assert emitted[1]["http"].trans_depth == 2
        assert emitted[1]["http"].referrer == "https://www.google.com/"

    def test_bundle_drops_requests_at_session_deadline(self, monkeypatch):
        monkeypatch.setattr(
            browsing_session,
            "generate_browsing_session",
            lambda **kwargs: [
                BrowsingRequest(
                    time_offset_ms=0,
                    hostname=kwargs["hostname"],
                    path="/",
                    method="GET",
                    content_type="text/html",
                    referrer="",
                    trans_depth=1,
                    is_page_load=True,
                    response_body_len=4096,
                    request_body_len=0,
                    status_code=200,
                ),
                BrowsingRequest(
                    time_offset_ms=100,
                    hostname=kwargs["hostname"],
                    path="/assets/app.css",
                    method="GET",
                    content_type="text/css",
                    referrer=f"https://{kwargs['hostname']}/",
                    trans_depth=2,
                    is_page_load=False,
                    response_body_len=2048,
                    request_body_len=0,
                    status_code=200,
                ),
            ],
        )
        emitted = []
        executor = MagicMock()
        executor.state_manager = MagicMock()
        executor.generate_connection.side_effect = lambda **kwargs: (
            emitted.append(kwargs) or f"C{len(emitted)}"
        )
        base_time = datetime(2024, 1, 15, 10, 0, tzinfo=UTC)

        result = BrowserSessionActionBundle(
            request=BrowserSessionRequest(
                src_ip="10.0.10.50",
                dst_ip="142.250.80.46",
                time=base_time,
                latest_request_time=base_time + timedelta(milliseconds=550),
                hostname="www.google.com",
                dst_port=443,
                service="ssl",
                source_system=SimpleNamespace(hostname="WKS-01"),
                domain_tags=("web",),
                user_agent="Mozilla/5.0",
            ),
            executor=executor,
            rng=random.Random(11),
        ).execute_with_result()

        assert result.request_count == 1
        assert result.page_load_count == 1
        assert len(emitted) == 1
        assert emitted[0]["time"] == base_time
        assert emitted[0]["http"].trans_depth == 1
        assert emitted[0]["http"].flow_transaction_count == 1
        assert emitted[0]["resp_bytes"] < 4096 + 2048

    def test_plaintext_http_bundle_drops_https_subresource_referrer(self, monkeypatch):
        monkeypatch.setattr(
            browsing_session,
            "generate_browsing_session",
            lambda **kwargs: [
                BrowsingRequest(
                    time_offset_ms=0,
                    hostname=kwargs["hostname"],
                    path="/assets/app.css",
                    method="GET",
                    content_type="text/css",
                    referrer=f"https://{kwargs['hostname']}/",
                    trans_depth=1,
                    is_page_load=False,
                    response_body_len=2048,
                    request_body_len=0,
                    status_code=200,
                ),
            ],
        )
        emitted = []
        executor = MagicMock()
        executor.state_manager = MagicMock()
        executor.generate_connection.side_effect = lambda **kwargs: emitted.append(kwargs) or "C1"

        BrowserSessionActionBundle(
            request=BrowserSessionRequest(
                src_ip="10.0.10.50",
                dst_ip="13.107.42.14",
                time=datetime(2024, 1, 15, 10, 0, tzinfo=UTC),
                hostname="www.office.com",
                dst_port=80,
                service="http",
                source_system=SimpleNamespace(hostname="WKS-01"),
                domain_tags=("web", "saas"),
                user_agent="Mozilla/5.0",
            ),
            executor=executor,
            rng=random.Random(11),
        ).execute()

        assert emitted[0]["http"].referrer == ""


class TestReferrerChains:
    """Referrer chain correctness."""

    def test_landing_page_empty_referrer(self):
        rng = random.Random(42)
        requests = generate_browsing_session(rng, "www.google.com", [])
        assert requests[0].referrer == ""

    def test_subresources_reference_parent_page(self):
        rng = random.Random(42)
        requests = generate_browsing_session(rng, "outlook.office365.com", [])
        # Find the first page load
        page = requests[0]
        page_url = f"https://{page.hostname}{page.path}"
        # All subresources that come before the next page should ref this page
        for req in requests[1:]:
            if req.is_page_load:
                break
            assert req.referrer == page_url, (
                f"Subresource {req.path} referrer '{req.referrer}' doesn't match page '{page_url}'"
            )

    def test_navigation_references_previous_page(self):
        """Second page load should reference the first page."""
        rng = random.Random(42)
        requests = generate_browsing_session(
            rng, "outlook.office365.com", [], browsing_intensity="heavy"
        )
        page_loads = [r for r in requests if r.is_page_load]
        if len(page_loads) >= 2:
            first_page_url = f"https://{page_loads[0].hostname}{page_loads[0].path}"
            assert page_loads[1].referrer == first_page_url

    def test_referrer_is_full_url(self):
        """Referrer should be a full https://host/path URL."""
        rng = random.Random(42)
        requests = generate_browsing_session(rng, "github.com", [])
        for req in requests:
            if req.referrer:
                assert req.referrer.startswith("https://") or req.referrer.startswith("http://"), (
                    f"Referrer '{req.referrer}' should start with http(s)://"
                )

    def test_some_sessions_have_search_engine_referrer(self):
        """~20% of sessions should start with a search engine referrer."""
        search_ref_count = 0
        for seed in range(50):
            rng = random.Random(seed)
            requests = generate_browsing_session(rng, "github.com", [])
            if requests and requests[0].referrer and "search" in requests[0].referrer:
                search_ref_count += 1
        assert search_ref_count >= 3, (
            f"Expected some sessions with search referrer, got {search_ref_count}/50"
        )

    def test_auth_landing_pages_do_not_use_search_engine_referrers(self):
        """Auth flow entry pages should look direct or app-initiated, not search-landed."""
        for host in (
            "accounts.google.com",
            "api-17.duosecurity.com",
            "identity.getpostman.com",
            "login.microsoftonline.com",
            "login.salesforce.com",
        ):
            for seed in range(60):
                requests = generate_browsing_session(random.Random(seed), host, ["saas"])
                if requests:
                    assert "google.com/search" not in requests[0].referrer
                    assert "bing.com/search" not in requests[0].referrer

    def test_some_sessions_start_deep(self):
        """~30% of sessions should land on a non-root page."""
        deep_start_count = 0
        for seed in range(50):
            rng = random.Random(seed)
            requests = generate_browsing_session(
                rng, "outlook.office365.com", [], browsing_intensity="normal"
            )
            if requests and requests[0].path != "/owa/":
                deep_start_count += 1
        assert deep_start_count >= 3, (
            f"Expected some sessions starting deep, got {deep_start_count}/50"
        )


class TestCdnFanOut:
    """Cross-domain CDN subresource behavior."""

    def test_cdn_subresources_have_different_hostname(self):
        rng = random.Random(42)
        requests = generate_browsing_session(rng, "outlook.office365.com", [])
        hostnames = {r.hostname for r in requests}
        assert len(hostnames) > 1, (
            f"Expected CDN fan-out (multiple hostnames), got only: {hostnames}"
        )

    def test_cdn_subresources_are_not_page_loads(self):
        rng = random.Random(42)
        requests = generate_browsing_session(rng, "outlook.office365.com", [])
        for req in requests:
            if req.hostname != "outlook.office365.com":
                assert req.is_page_load is False


class TestBrowsingIntensity:
    """Intensity levels produce correct session shapes."""

    def test_light_fewer_requests(self):
        rng = random.Random(42)
        light = generate_browsing_session(rng, "www.google.com", [], browsing_intensity="light")
        rng2 = random.Random(42)
        heavy = generate_browsing_session(rng2, "www.google.com", [], browsing_intensity="heavy")
        assert len(light) < len(heavy)

    def test_light_one_page(self):
        rng = random.Random(42)
        requests = generate_browsing_session(rng, "github.com", [], browsing_intensity="light")
        page_loads = [r for r in requests if r.is_page_load]
        assert len(page_loads) == 1

    def test_heavy_multiple_pages(self):
        """Heavy intensity should produce 2+ page loads across many seeds."""
        multi_page_count = 0
        for seed in range(20):
            rng = random.Random(seed)
            requests = generate_browsing_session(
                rng, "outlook.office365.com", [], browsing_intensity="heavy"
            )
            page_loads = [r for r in requests if r.is_page_load]
            if len(page_loads) >= 2:
                multi_page_count += 1
        assert multi_page_count >= 10, (
            f"Heavy intensity produced multi-page sessions only {multi_page_count}/20 times"
        )

    def test_normal_moderate_subresources(self):
        rng = random.Random(42)
        requests = generate_browsing_session(rng, "github.com", [], browsing_intensity="normal")
        subs = [r for r in requests if not r.is_page_load]
        assert 5 <= len(subs) <= 25, f"Normal intensity: {len(subs)} subresources"


class TestFaviconPresence:
    """Favicon should always be included."""

    def test_curated_domain_has_favicon(self):
        rng = random.Random(42)
        requests = generate_browsing_session(rng, "outlook.office365.com", [])
        paths = [r.path for r in requests]
        assert "/favicon.ico" in paths

    def test_tag_domain_has_favicon(self):
        rng = random.Random(42)
        requests = generate_browsing_session(rng, "app.example.com", ["saas"])
        paths = [r.path for r in requests]
        assert "/favicon.ico" in paths

    def test_generic_domain_has_favicon(self):
        rng = random.Random(42)
        requests = generate_browsing_session(rng, "unknown.example.org", [])
        paths = [r.path for r in requests]
        assert "/favicon.ico" in paths


class TestTagAndGenericFallback:
    """Tag-based and generic fallback produce valid sessions."""

    def test_tag_saas_produces_session(self):
        rng = random.Random(42)
        requests = generate_browsing_session(rng, "app.custom-saas.com", ["saas"])
        assert len(requests) > 0
        assert requests[0].is_page_load

    def test_tag_healthcare_produces_session(self):
        rng = random.Random(42)
        requests = generate_browsing_session(rng, "ehr.hospital.org", ["healthcare"])
        assert len(requests) > 0

    def test_generic_fallback_produces_session(self):
        rng = random.Random(42)
        requests = generate_browsing_session(rng, "totally-unknown.test", [])
        assert len(requests) > 0
        assert requests[0].is_page_load

    def test_non_browser_proxy_domain_produces_no_browsing_session(self):
        rng = random.Random(42)
        requests = generate_browsing_session(rng, "ocsp.pki.goog", ["background"])
        assert requests == []

    def test_cdn_and_api_registry_targets_produce_no_browsing_session(self):
        rng = random.Random(42)

        assert generate_browsing_session(rng, "a.slack-edge.com", ["cdn"]) == []
        assert generate_browsing_session(rng, "content.dropboxapi.com", ["storage", "cdn"]) == []
        assert generate_browsing_session(rng, "graph.microsoft.com", ["dev", "outlook"]) == []

    def test_inbound_web_server_can_use_generic_public_hostname(self):
        rng = random.Random(42)
        requests = generate_browsing_session(
            rng,
            "portal.customer.example",
            [],
            port=443,
            require_browser_like_domain=False,
        )
        assert len(requests) > 0
        assert requests[0].hostname == "portal.customer.example"


class TestResponseSizes:
    """Response body lengths should be realistic for content types."""

    def test_page_load_has_reasonable_size(self):
        rng = random.Random(42)
        requests = generate_browsing_session(rng, "github.com", [])
        page = requests[0]
        assert 5_000 <= page.response_body_len <= 80_000

    def test_js_has_reasonable_size(self):
        rng = random.Random(42)
        requests = generate_browsing_session(rng, "github.com", [])
        js_reqs = [r for r in requests if r.content_type == "application/javascript"]
        if js_reqs:
            for r in js_reqs:
                assert 10_000 <= r.response_body_len <= 200_000

    def test_favicon_is_small(self):
        rng = random.Random(42)
        requests = generate_browsing_session(rng, "github.com", [])
        favicons = [r for r in requests if "/favicon.ico" in r.path]
        for f in favicons:
            assert f.response_body_len <= 5_000

    def test_extension_drives_content_type(self):
        rng = random.Random(42)
        requests = generate_browsing_session(rng, "github.com", [])
        for request in requests:
            if request.path.endswith(".gif"):
                assert request.content_type == "image/gif"
                assert 500 <= request.response_body_len <= 50_000
            if request.path.endswith(".ico"):
                assert request.content_type == "image/x-icon"
                assert 500 <= request.response_body_len <= 5_000

    def test_stable_static_asset_size_for_same_host_and_path(self):
        successful_favicons = []
        for seed in range(60):
            requests = generate_browsing_session(
                random.Random(seed),
                "portal.customer.example",
                [],
                require_browser_like_domain=False,
            )
            favicon = next(r for r in requests if r.path == "/favicon.ico")
            if favicon.status_code == 200:
                successful_favicons.append(favicon)
            if len(successful_favicons) >= 2:
                break

        assert len(successful_favicons) >= 2
        assert {r.response_body_len for r in successful_favicons} == {
            successful_favicons[0].response_body_len
        }

    def test_static_asset_transfer_size_is_stable_across_client_variants(self):
        requests_a = generate_browsing_session(
            random.Random(9),
            "portal.customer.example",
            [],
            require_browser_like_domain=False,
            transfer_variant_key="10.10.1.10:chrome",
        )
        requests_a_repeat = generate_browsing_session(
            random.Random(9),
            "portal.customer.example",
            [],
            require_browser_like_domain=False,
            transfer_variant_key="10.10.1.10:chrome",
        )
        requests_b = generate_browsing_session(
            random.Random(9),
            "portal.customer.example",
            [],
            require_browser_like_domain=False,
            transfer_variant_key="10.10.1.11:firefox",
        )

        favicon_a = next(r for r in requests_a if r.path == "/favicon.ico" and r.status_code == 200)
        favicon_a_repeat = next(
            r for r in requests_a_repeat if r.path == "/favicon.ico" and r.status_code == 200
        )
        favicon_b = next(r for r in requests_b if r.path == "/favicon.ico" and r.status_code == 200)

        assert favicon_a.response_body_len == favicon_a_repeat.response_body_len
        assert favicon_a.response_body_len == favicon_b.response_body_len

    def test_page_document_transfer_size_varies_across_session_variants(self):
        requests_a = generate_browsing_session(
            random.Random(9),
            "portal.customer.example",
            [],
            require_browser_like_domain=False,
            transfer_variant_key="10.10.1.10:chrome:2024-03-18T10:00:00Z",
        )
        requests_a_repeat = generate_browsing_session(
            random.Random(9),
            "portal.customer.example",
            [],
            require_browser_like_domain=False,
            transfer_variant_key="10.10.1.10:chrome:2024-03-18T10:00:00Z",
        )
        requests_b = generate_browsing_session(
            random.Random(9),
            "portal.customer.example",
            [],
            require_browser_like_domain=False,
            transfer_variant_key="10.10.1.10:chrome:2024-03-18T11:00:00Z",
        )

        page_a = next(r for r in requests_a if r.is_page_load and r.status_code == 200)
        page_a_repeat = next(
            r for r in requests_a_repeat if r.is_page_load and r.status_code == 200
        )
        page_b = next(r for r in requests_b if r.is_page_load and r.status_code == 200)

        assert page_a.response_body_len == page_a_repeat.response_body_len
        assert page_a.response_body_len != page_b.response_body_len

    def test_sessions_include_non_success_http_outcomes(self):
        statuses = []
        for seed in range(40):
            requests = generate_browsing_session(random.Random(seed), "github.com", [])
            statuses.extend(request.status_code for request in requests)

        assert 200 in statuses
        assert any(status != 200 for status in statuses)

    def test_static_assets_do_not_randomly_turn_into_server_errors(self):
        requests = []
        for seed in range(80):
            requests.extend(
                generate_browsing_session(
                    random.Random(seed),
                    "portal.customer.example",
                    [],
                    require_browser_like_domain=False,
                )
            )

        stable_assets = [
            request
            for request in requests
            if not request.is_page_load
            and request.method == "GET"
            and (
                request.path.endswith((".css", ".js", ".png", ".jpg", ".jpeg", ".webp", ".ico"))
                or "/assets/" in request.path
                or "/static/" in request.path
            )
        ]

        assert stable_assets
        assert {request.status_code for request in stable_assets} <= {200, 206, 304}

    def test_empty_body_statuses_have_zero_response_body(self):
        requests = []
        for seed in range(80):
            requests.extend(generate_browsing_session(random.Random(seed), "github.com", []))

        empty_body = [request for request in requests if request.status_code in {204, 304}]
        assert empty_body
        assert all(request.response_body_len == 0 for request in empty_body)

    def test_subresource_timing_uses_timing_profile_overlay(self, tmp_path, monkeypatch):
        overlay = tmp_path / ".eforge" / "config" / "activity"
        overlay.mkdir(parents=True)
        (overlay / "timing_profiles.yaml").write_text(
            """
relationships:
  web.asset_stylesheet_script_after_page:
    class: burst_fanout
    position: after
    min_ms: 1000
    max_ms: 1000
""".lstrip()
        )
        monkeypatch.chdir(tmp_path)
        reset_timing_profiles_cache()

        requests = generate_browsing_session(random.Random(42), "github.com", [])
        first_page = requests[0]
        first_page_referrer = f"https://{first_page.hostname}{first_page.path}"
        css_js = [
            request
            for request in requests
            if request.referrer == first_page_referrer
            and request.content_type in {"text/css", "application/javascript"}
        ]

        assert css_js
        assert {request.time_offset_ms for request in css_js} == {1000}
        reset_timing_profiles_cache()


class TestDeterminism:
    """Same seed produces identical sessions."""

    def test_same_seed_same_output(self):
        r1 = generate_browsing_session(random.Random(42), "github.com", [])
        r2 = generate_browsing_session(random.Random(42), "github.com", [])
        assert len(r1) == len(r2)
        for a, b in zip(r1, r2, strict=True):
            assert a.hostname == b.hostname
            assert a.path == b.path
            assert a.referrer == b.referrer
            assert a.status_code == b.status_code
            assert a.response_body_len == b.response_body_len
