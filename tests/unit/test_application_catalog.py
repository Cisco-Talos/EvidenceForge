# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Tests for Theme 1: unified application catalog (P0-1, P0-3, P1-2, P1-3)."""

import random
from collections import Counter

from evidenceforge.generation.activity.application_catalog import (
    _USER_BROWSER_AFFINITY,
    get_apps_for_persona,
    get_pe_metadata,
    is_system_type_allowed,
    load_catalog,
    pick_app_and_command,
)
from evidenceforge.generation.activity.helpers import _parameterize_command


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

    def test_gpupdate_uses_workstation_build_metadata(self):
        """Fleet-wide gpupdate metadata should match workstation System32 peers."""
        file_version, _, _, _, _ = get_pe_metadata("gpupdate.exe")

        assert file_version == "10.0.19041.1"

    def test_all_entries_have_command_templates(self):
        """P1-3: Every platform entry should have at least one command template."""
        data = load_catalog()
        for app in data["applications"]:
            for os_cat, platform in app.get("platforms", {}).items():
                templates = platform.get("command_templates", [])
                assert len(templates) > 0, f"{app['id']} {os_cat} has no command_templates"

    def test_browser_entry_commands_are_user_launches_not_renderer_children(self):
        """Browser renderer/content processes belong under children, not app launch commands."""
        data = load_catalog()
        browser_ids = {"chrome", "firefox", "edge"}
        child_markers = ("--type=renderer", "--type=gpu-process", "-contentproc")
        for app in data["applications"]:
            if app["id"] not in browser_ids:
                continue
            windows = app.get("platforms", {}).get("windows", {})
            for template in windows.get("command_templates", []):
                assert not any(marker in template for marker in child_markers)

    def test_docker_go_template_braces_render_source_native(self):
        """Docker Go-template braces should not be escaped into generated telemetry."""
        data = load_catalog()
        docker = next(app for app in data["applications"] if app["id"] == "docker")
        templates = docker["platforms"]["windows"]["command_templates"]
        template = next(t for t in templates if "images --format" in t)

        rendered = _parameterize_command(random.Random(42), template, username="developer")

        assert "{{.Repository}}" in rendered
        assert "{{.Tag}}" in rendered
        assert "{{.Size}}" in rendered
        assert "{{{{" not in rendered
        assert "}}}}" not in rendered


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

    def test_kubectl_and_internal_curl_are_workstation_scoped_on_linux(self):
        assert is_system_type_allowed("kubectl", "linux", "workstation")
        assert not is_system_type_allowed("kubectl", "linux", "server")
        assert is_system_type_allowed("curl", "linux", "workstation")
        assert not is_system_type_allowed("curl", "linux", "server")

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

    def test_dsquery_system_type_restricted_for_generic_selection(self):
        assert not is_system_type_allowed("dsquery.exe", "windows", "workstation")
        assert not is_system_type_allowed("dsquery.exe", "windows", "server")
        assert is_system_type_allowed("dsquery.exe", "windows", "domain_controller")


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

    def test_browser_metadata_matches_configured_user_agent_majors(self):
        """Browser PE versions should not disagree with generated HTTP UA versions."""
        chrome_fv, *_ = get_pe_metadata("chrome.exe")
        firefox_fv, *_ = get_pe_metadata("firefox.exe")
        edge_fv, *_ = get_pe_metadata("msedge.exe")

        assert chrome_fv.startswith("120.")
        assert firefox_fv.startswith("121.")
        assert edge_fv.startswith("120.")

    def test_outlook_has_metadata(self):
        fv, desc, prod, company, orig = get_pe_metadata("outlook.exe")
        assert company == "Microsoft Corporation"

    def test_windows_admin_binaries_have_metadata(self):
        for exe in ("mmc.exe", "wevtutil.exe"):
            fv, desc, prod, company, orig = get_pe_metadata(exe)
            assert company == "Microsoft Corporation"
            assert prod != "-"
            assert fv != "-"
            assert desc != "-"
            assert orig.lower() == exe

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

    def test_selection_weight_biases_catalog_choice(self, monkeypatch):
        """Application entries with lower selection_weight should be rarer."""
        from evidenceforge.generation.activity import application_catalog

        apps = [
            {
                "id": "common",
                "selection_weight": 100,
                "platforms": {
                    "windows": {
                        "image_path": r"C:\Tools\common.exe",
                        "command_templates": ["common.exe"],
                    }
                },
            },
            {
                "id": "rare",
                "selection_weight": 1,
                "platforms": {
                    "windows": {
                        "image_path": r"C:\Tools\rare.exe",
                        "command_templates": ["rare.exe"],
                    }
                },
            },
        ]
        monkeypatch.setattr(
            application_catalog, "get_apps_for_persona", lambda *args, **kwargs: apps
        )

        rng = random.Random(42)
        choices = Counter(
            pick_app_and_command(rng, "sysadmin", "windows", "query")[0].rsplit("\\", 1)[-1]
            for _ in range(400)
        )

        assert choices["common.exe"] > choices["rare.exe"] * 20

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

    def test_user_app_browser_launches_keep_user_affinity(self):
        """Browser affinity applies even when browsers are picked from user_app activity."""
        _USER_BROWSER_AFFINITY.pop("affinity.user", None)
        browser_exes = {"chrome.exe", "firefox.exe", "msedge.exe"}
        seen = []
        for seed in range(300):
            result = pick_app_and_command(
                random.Random(seed),
                "default",
                "windows",
                "user_app",
                username="affinity.user",
            )
            assert result is not None
            image, _ = result
            exe = image.rsplit("\\", 1)[-1].lower()
            if exe in browser_exes:
                seen.append(exe)

        assert len(seen) > 20
        counts = Counter(seen)
        _exe, count = counts.most_common(1)[0]
        assert count / len(seen) >= 0.75
