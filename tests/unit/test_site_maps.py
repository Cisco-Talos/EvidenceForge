# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Tests for site map loader and data layer."""

import random

from evidenceforge.generation.activity.site_maps import (
    PageDef,
    SiteMap,
    SubresourceDef,
    get_site_map,
    load_site_maps,
)


class TestLoadSiteMaps:
    """Verify site_maps.yaml loads and has expected structure."""

    def test_loads_without_error(self):
        data = load_site_maps()
        assert data is not None
        assert "domains" in data
        assert "tags" in data
        assert "generic" in data

    def test_has_curated_domains(self):
        data = load_site_maps()
        domains = data["domains"]
        expected = [
            "outlook.office365.com",
            "www.google.com",
            "github.com",
            "slack.com",
        ]
        for domain in expected:
            assert domain in domains, f"Missing curated domain: {domain}"

    def test_curated_domains_have_pages(self):
        data = load_site_maps()
        for name, entry in data["domains"].items():
            pages = entry.get("pages", [])
            assert len(pages) >= 1, f"Domain {name} has no pages"
            for page in pages:
                assert "path" in page, f"Page in {name} missing path"

    def test_has_tag_templates(self):
        data = load_site_maps()
        tags = data["tags"]
        expected_tags = ["saas", "healthcare", "web", "internal"]
        for tag in expected_tags:
            assert tag in tags, f"Missing tag template: {tag}"

    def test_tag_templates_have_patterns(self):
        data = load_site_maps()
        for tag_name, tag_entry in data["tags"].items():
            templates = tag_entry.get("page_templates", [])
            assert len(templates) >= 1, f"Tag {tag_name} has no page_templates"
            patterns = tag_entry.get("subresource_patterns", {})
            for tmpl in templates:
                pattern = tmpl.get("subresource_pattern", "")
                if pattern:
                    assert pattern in patterns, (
                        f"Tag {tag_name} page references missing pattern '{pattern}'"
                    )

    def test_generic_fallback_exists(self):
        data = load_site_maps()
        generic = data["generic"]
        assert "page_templates" in generic
        assert "subresource_patterns" in generic
        assert len(generic["page_templates"]) >= 1


class TestGetSiteMap:
    """Verify get_site_map() returns correct SiteMap for each tier."""

    def test_curated_domain_returns_site_map(self):
        rng = random.Random(42)
        sm = get_site_map("outlook.office365.com", [], rng)
        assert isinstance(sm, SiteMap)
        assert sm.hostname == "outlook.office365.com"
        assert len(sm.pages) >= 2
        assert len(sm.cdn_domains) >= 1

    def test_curated_pages_have_subresources(self):
        rng = random.Random(42)
        sm = get_site_map("www.google.com", [], rng)
        for page in sm.pages:
            assert isinstance(page, PageDef)
            assert len(page.subresources) >= 1
            for sub in page.subresources:
                assert isinstance(sub, SubresourceDef)
                assert sub.path
                assert sub.content_type

    def test_curated_pages_have_nav_targets(self):
        rng = random.Random(42)
        sm = get_site_map("github.com", [], rng)
        has_nav = any(len(p.nav_targets) > 0 for p in sm.pages)
        assert has_nav, "No pages have navigation targets"

    def test_cdn_subresources_have_host(self):
        rng = random.Random(42)
        sm = get_site_map("outlook.office365.com", [], rng)
        cdn_subs = [sub for page in sm.pages for sub in page.subresources if sub.host is not None]
        assert len(cdn_subs) >= 1, "No CDN subresources found"
        for sub in cdn_subs:
            assert sub.host in sm.cdn_domains

    def test_tag_fallback(self):
        rng = random.Random(42)
        sm = get_site_map("app.unknown-saas.com", ["saas"], rng)
        assert sm.hostname == "app.unknown-saas.com"
        assert len(sm.pages) >= 1
        assert len(sm.cdn_domains) == 0  # Tag templates don't define CDN

    def test_tag_order_matters(self):
        """First matching tag wins."""
        rng = random.Random(42)
        sm_saas = get_site_map("app.example.com", ["saas", "web"], rng)
        sm_web = get_site_map("app.example.com", ["web", "saas"], rng)
        # Different first tag → different page structures
        assert sm_saas.pages[0].path != sm_web.pages[0].path

    def test_generic_fallback(self):
        rng = random.Random(42)
        sm = get_site_map("totally-unknown.example.org", [], rng)
        assert sm.hostname == "totally-unknown.example.org"
        assert len(sm.pages) >= 1
        # Generic should have basic subresources
        assert any(len(p.subresources) > 0 for p in sm.pages)

    def test_template_variables_substituted(self):
        """Template vars like {hex8} should be replaced, not left literal."""
        rng = random.Random(42)
        sm = get_site_map("outlook.office365.com", [], rng)
        for page in sm.pages:
            assert "{hex8}" not in page.path
            assert "{hex16}" not in page.path
            for sub in page.subresources:
                assert "{hex8}" not in sub.path
                assert "{hex16}" not in sub.path
                assert "{guid}" not in sub.path

    def test_deterministic_with_same_seed(self):
        """Same seed should produce identical site maps."""
        sm1 = get_site_map("github.com", [], random.Random(99))
        sm2 = get_site_map("github.com", [], random.Random(99))
        assert len(sm1.pages) == len(sm2.pages)
        for p1, p2 in zip(sm1.pages, sm2.pages, strict=True):
            assert p1.path == p2.path

    def test_different_seeds_produce_different_vars(self):
        """Different seeds should produce different template substitutions."""
        sm1 = get_site_map("outlook.office365.com", [], random.Random(1))
        sm2 = get_site_map("outlook.office365.com", [], random.Random(999))
        # The page paths are fixed (/owa/, /owa/#/mail, etc.) but subresource
        # paths contain {hex16} which should differ
        subs1 = [s.path for p in sm1.pages for s in p.subresources]
        subs2 = [s.path for p in sm2.pages for s in p.subresources]
        assert subs1 != subs2

    def test_favicon_in_curated_domains(self):
        """Curated domains should include favicon.ico in subresources."""
        rng = random.Random(42)
        for domain in ["outlook.office365.com", "github.com", "www.google.com"]:
            sm = get_site_map(domain, [], rng)
            all_paths = [s.path for p in sm.pages for s in p.subresources]
            assert "/favicon.ico" in all_paths, f"{domain} missing favicon.ico"
