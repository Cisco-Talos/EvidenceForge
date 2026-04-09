# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Tests for Theme 1: unified application catalog (P0-1, P0-3, P1-2, P1-3)."""

import random

from evidenceforge.generation.activity.application_catalog import (
    get_apps_for_persona,
    get_pe_metadata,
    load_catalog,
    pick_app_and_command,
)


class TestCatalogLoading:
    """Tests for YAML catalog loading and structural integrity."""

    def test_catalog_loads(self):
        data = load_catalog()
        assert "applications" in data
        assert len(data["applications"]) > 20

    def test_all_entries_have_fully_qualified_paths(self):
        """P0-1: No bare filenames — all image paths must be fully qualified."""
        data = load_catalog()
        for app in data["applications"]:
            for os_cat, platform in app.get("platforms", {}).items():
                image = platform["image_path"]
                if os_cat == "windows":
                    assert "\\" in image, (
                        f"{app['id']} windows image_path '{image}' is not fully qualified"
                    )
                elif os_cat == "linux":
                    assert image.startswith("/"), (
                        f"{app['id']} linux image_path '{image}' is not fully qualified"
                    )

    def test_all_windows_entries_have_pe_metadata(self):
        """P0-3: Every Windows user-installed app should have PE metadata."""
        data = load_catalog()
        for app in data["applications"]:
            win = app.get("platforms", {}).get("windows", {})
            if win and app["id"] not in ("npm",):  # npm.cmd is a script, not PE
                pe = win.get("pe_metadata")
                assert pe is not None, f"{app['id']} missing pe_metadata"
                assert pe.get("company", "-") != "-", f"{app['id']} has dash company"

    def test_all_entries_have_command_templates(self):
        """P1-3: Every platform entry should have at least one command template."""
        data = load_catalog()
        for app in data["applications"]:
            for os_cat, platform in app.get("platforms", {}).items():
                templates = platform.get("command_templates", [])
                assert len(templates) > 0, f"{app['id']} {os_cat} has no command_templates"


class TestPersonaFiltering:
    """Tests for persona-based application filtering (P1-2)."""

    def test_hr_gets_no_devtools(self):
        """P1-2: HR persona should not have kubectl, cargo, or docker."""
        apps = get_apps_for_persona("hr", "windows", "user_app")
        app_ids = {a["id"] for a in apps}
        assert "kubectl" not in app_ids
        assert "cargo" not in app_ids
        assert "docker" not in app_ids

    def test_hr_gets_no_linux_devtools(self):
        apps = get_apps_for_persona("hr", "linux", "user_app")
        app_ids = {a["id"] for a in apps}
        assert "kubectl" not in app_ids
        assert "docker" not in app_ids

    def test_developer_gets_kubectl(self):
        apps = get_apps_for_persona("developer", "linux", "user_app")
        app_ids = {a["id"] for a in apps}
        assert "kubectl" in app_ids

    def test_developer_gets_docker(self):
        apps = get_apps_for_persona("developer", "windows", "user_app")
        app_ids = {a["id"] for a in apps}
        assert "docker" in app_ids

    def test_sysadmin_gets_kubectl(self):
        apps = get_apps_for_persona("sysadmin", "linux", "user_app")
        app_ids = {a["id"] for a in apps}
        assert "kubectl" in app_ids

    def test_executive_gets_office_apps(self):
        apps = get_apps_for_persona("executive", "windows", "user_app")
        app_ids = {a["id"] for a in apps}
        assert "outlook" in app_ids or "word" in app_ids or "excel" in app_ids

    def test_unknown_persona_falls_to_default(self):
        """Unknown persona should fall back to 'default' persona apps."""
        apps = get_apps_for_persona("mystery_persona", "windows", "user_app")
        assert len(apps) > 0

    def test_default_persona_has_common_apps(self):
        apps = get_apps_for_persona("default", "windows", "user_app")
        app_ids = {a["id"] for a in apps}
        assert "chrome" in app_ids or "firefox" in app_ids


class TestPeMetadataLookup:
    """Tests for PE metadata lookup from catalog."""

    def test_chrome_has_metadata(self):
        fv, desc, prod, company, orig = get_pe_metadata("chrome.exe")
        assert company == "Google LLC"
        assert prod == "Google Chrome"
        assert fv != "-"

    def test_firefox_has_metadata(self):
        fv, desc, prod, company, orig = get_pe_metadata("firefox.exe")
        assert company == "Mozilla Corporation"

    def test_outlook_has_metadata(self):
        fv, desc, prod, company, orig = get_pe_metadata("outlook.exe")
        assert company == "Microsoft Corporation"

    def test_unknown_returns_dashes(self):
        result = get_pe_metadata("totally_unknown.exe")
        assert result == ("-", "-", "-", "-", "-")

    def test_case_insensitive(self):
        upper = get_pe_metadata("CHROME.EXE")
        lower = get_pe_metadata("chrome.exe")
        assert upper == lower


class TestPickAppAndCommand:
    """Tests for pick_app_and_command()."""

    def test_returns_tuple(self):
        rng = random.Random(42)
        result = pick_app_and_command(rng, "developer", "windows", "user_app", username="jdoe")
        assert result is not None
        image_path, command_line = result
        assert "\\" in image_path  # Fully qualified Windows path
        assert len(command_line) > 0

    def test_linux_returns_absolute_path(self):
        rng = random.Random(42)
        result = pick_app_and_command(rng, "developer", "linux", "user_app", username="jdoe")
        assert result is not None
        image_path, _ = result
        assert image_path.startswith("/")

    def test_username_substituted_in_path(self):
        rng = random.Random(1)
        # Teams has {username} in its path; try enough seeds to hit it
        found_username_sub = False
        for seed in range(100):
            rng = random.Random(seed)
            result = pick_app_and_command(
                rng, "default", "windows", "user_app", username="testuser"
            )
            if result and "testuser" in result[0]:
                found_username_sub = True
                break
        assert found_username_sub, "Never saw username substitution in image path"

    def test_no_apps_returns_none(self):
        rng = random.Random(42)
        result = pick_app_and_command(rng, "default", "windows", "nonexistent_category")
        assert result is None

    def test_command_templates_are_not_bare_words(self):
        """P1-3: Command templates should have arguments, not just an exe name."""
        rng = random.Random(42)
        bare_count = 0
        total = 0
        for seed in range(50):
            rng = random.Random(seed)
            result = pick_app_and_command(rng, "default", "windows", "user_app")
            if result:
                total += 1
                _, cmd = result
                # A "bare word" is just an exe name with no spaces/flags
                if " " not in cmd and "\\" not in cmd and "/" not in cmd:
                    bare_count += 1
        # Allow some bare commands (e.g., OneDrive) but most should have args
        assert bare_count / max(total, 1) < 0.5, f"{bare_count}/{total} commands were bare words"
