# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Tests for browsing session generator."""

import random

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

    def test_sessions_include_non_success_http_outcomes(self):
        statuses = []
        for seed in range(40):
            requests = generate_browsing_session(random.Random(seed), "github.com", [])
            statuses.extend(request.status_code for request in requests)

        assert 200 in statuses
        assert any(status != 200 for status in statuses)

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
