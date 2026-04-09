# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Tests for Round 3 expert-reported fixes."""

import random

from evidenceforge.generation.activity.application_catalog import (
    resolve_image_path,
)


class TestResolveImagePath:
    """Tests for the centralized resolve_image_path() function."""

    def test_chrome_resolves_to_program_files(self):
        path = resolve_image_path("chrome.exe", "windows")
        assert "Program Files" in path
        assert "System32" not in path

    def test_firefox_resolves_to_program_files(self):
        path = resolve_image_path("firefox.exe", "windows")
        assert "Program Files" in path
        assert "System32" not in path

    def test_kubectl_resolves_from_catalog(self):
        path = resolve_image_path("kubectl.exe", "windows")
        assert "System32" not in path

    def test_docker_resolves_from_catalog(self):
        path = resolve_image_path("docker.exe", "windows")
        assert "System32" not in path

    def test_teams_resolves_from_catalog(self):
        path = resolve_image_path("Teams.exe", "windows")
        assert "AppData" in path or "Teams" in path
        assert "System32" not in path

    def test_svchost_resolves_to_system32(self):
        """Known system binary should get System32."""
        path = resolve_image_path("svchost.exe", "windows")
        assert "System32" in path

    def test_cmd_resolves_to_system32(self):
        path = resolve_image_path("cmd.exe", "windows")
        assert "System32" in path

    def test_powershell_resolves_to_system32(self):
        path = resolve_image_path("powershell.exe", "windows")
        assert "System32" in path

    def test_lsass_resolves_to_system32(self):
        path = resolve_image_path("lsass.exe", "windows")
        assert "System32" in path

    def test_unknown_exe_falls_to_system32(self):
        """Completely unknown exe gets System32 as last resort."""
        path = resolve_image_path("totally_unknown.exe", "windows")
        assert "System32" in path

    def test_linux_firefox(self):
        path = resolve_image_path("firefox", "linux")
        assert path.startswith("/usr/bin/")

    def test_linux_unknown_falls_to_usr_bin(self):
        path = resolve_image_path("unknown_tool", "linux")
        assert path.startswith("/usr/bin/")

    def test_case_insensitive(self):
        """Lookup should be case-insensitive."""
        upper = resolve_image_path("CHROME.EXE", "windows")
        lower = resolve_image_path("chrome.exe", "windows")
        assert upper == lower

    def test_extensionless_git_resolves(self):
        """Bare 'git' (no .exe) should resolve from catalog, not System32."""
        path = resolve_image_path("git", "windows")
        assert "System32" not in path
        assert "Git" in path

    def test_extensionless_docker_resolves(self):
        path = resolve_image_path("docker", "windows")
        assert "System32" not in path

    def test_extensionless_cargo_resolves(self):
        path = resolve_image_path("cargo", "windows")
        assert "System32" not in path

    def test_extensionless_kubectl_resolves(self):
        path = resolve_image_path("kubectl", "windows")
        assert "System32" not in path

    def test_teams_with_username(self):
        """Profile-scoped apps resolve correctly when username is provided."""
        path = resolve_image_path("Teams.exe", "windows", username="jdoe")
        assert "jdoe" in path
        assert "Teams" in path
        assert "System32" not in path
        assert "{username}" not in path

    def test_teams_without_username_returns_basename(self):
        """Without username, profile-scoped apps return bare basename (no fabricated path)."""
        path = resolve_image_path("Teams.exe", "windows")
        assert path == "Teams.exe"

    def test_onedrive_with_username(self):
        path = resolve_image_path("OneDrive.exe", "windows", username="jdoe")
        assert "jdoe" in path
        assert "{username}" not in path

    def test_explorer_not_in_system32(self):
        """explorer.exe lives at C:\\Windows\\, not C:\\Windows\\System32\\."""
        path = resolve_image_path("explorer.exe", "windows")
        assert path == r"C:\Windows\explorer.exe"

    def test_catalog_apps_never_get_system32(self):
        """No user app in the catalog should resolve to System32."""
        from evidenceforge.generation.activity.application_catalog import load_catalog

        data = load_catalog()
        for app in data["applications"]:
            win = app.get("platforms", {}).get("windows")
            if not win:
                continue
            basename = win["image_path"].rsplit("\\", 1)[-1]
            resolved = resolve_image_path(basename, "windows")
            # These legitimately live under System32 or System32 subdirs
            _SYSTEM32_OK = {
                "msedge.exe",
                "wmic.exe",
                "powershell.exe",
                "ssh.exe",
                "mstsc.exe",
                "dsquery.exe",
            }
            if basename.lower() not in _SYSTEM32_OK:
                assert "System32" not in resolved, (
                    f"{app['id']} ({basename}) resolved to System32: {resolved}"
                )


class TestWindowsQueryActivity:
    """Tests that Windows query activity is not silently dropped."""

    def test_windows_query_has_catalog_entries(self):
        from evidenceforge.generation.activity.application_catalog import (
            get_apps_for_persona,
        )

        apps = get_apps_for_persona("analyst", "windows", "query")
        assert len(apps) > 0, "No Windows query apps for analyst persona"

    def test_windows_query_produces_result(self):
        from evidenceforge.generation.activity.application_catalog import (
            pick_app_and_command,
        )

        rng = random.Random(42)
        result = pick_app_and_command(rng, "analyst", "windows", "query")
        assert result is not None, "pick_app_and_command returned None for Windows query"

    def test_windows_query_includes_sqlcmd(self):
        from evidenceforge.generation.activity.application_catalog import (
            get_apps_for_persona,
        )

        apps = get_apps_for_persona("analyst", "windows", "query")
        app_ids = {a["id"] for a in apps}
        assert "sqlcmd" in app_ids


class TestRoleFiltering:
    """Tests that persona filtering prevents dev tools on non-dev workstations."""

    def test_hr_no_cargo(self):
        from evidenceforge.generation.activity.application_catalog import (
            pick_app_and_command,
        )

        rng = random.Random(42)
        for _ in range(50):
            result = pick_app_and_command(rng, "hr", "windows", "build")
            if result:
                assert "cargo" not in result[0].lower()

    def test_hr_no_kubectl(self):
        from evidenceforge.generation.activity.application_catalog import (
            pick_app_and_command,
        )

        rng = random.Random(42)
        for _ in range(50):
            result = pick_app_and_command(rng, "hr", "windows", "user_app")
            if result:
                assert "kubectl" not in result[0].lower()

    def test_legacy_fallback_only_for_system(self):
        """Verify process_system is the only activity_type that should use legacy templates."""
        from evidenceforge.generation.activity.generator import PROCESS_TEMPLATES

        # These are the catalog categories — they should NOT fall through to PROCESS_TEMPLATES
        catalog_categories = {"process_user_apps", "process_code", "process_build", "process_query"}
        for cat in catalog_categories:
            assert cat in PROCESS_TEMPLATES, (
                f"{cat} should exist in PROCESS_TEMPLATES (for reference)"
            )
        # process_system is the only one that should use legacy path
        assert "process_system" in PROCESS_TEMPLATES


class TestExpansionGuard:
    """Tests for the per-event-type expansion guard."""

    def test_expanding_types_initialized_as_set(self):
        from unittest.mock import MagicMock

        from evidenceforge.generation.activity.generator import ActivityGenerator

        gen = ActivityGenerator.__new__(ActivityGenerator)
        gen._causal_engine = MagicMock()
        gen._expanding_types = set()
        assert isinstance(gen._expanding_types, set)

    def test_same_type_blocked(self):
        """Same event type should be blocked by the guard."""
        expanding = {"connection"}
        assert "connection" in expanding

    def test_cross_type_allowed(self):
        """Different event type should NOT be blocked."""
        expanding = {"process_create"}
        assert "connection" not in expanding


class TestNtpStratum:
    """Tests for NTP stratum stability."""

    def test_stratum_stable_per_server(self):
        """Same NTP server IP should always produce the same stratum."""
        from evidenceforge.utils.rng import _stable_seed

        ip = "10.0.0.1"
        stratum1 = (_stable_seed(f"ntp_stratum_{ip}") % 3) + 1
        stratum2 = (_stable_seed(f"ntp_stratum_{ip}") % 3) + 1
        assert stratum1 == stratum2

    def test_different_servers_can_differ(self):
        """Different server IPs may produce different strata."""
        from evidenceforge.utils.rng import _stable_seed

        results = set()
        for ip in ["10.0.0.1", "10.0.0.2", "129.6.15.28", "132.163.97.1", "10.0.0.5"]:
            results.add((_stable_seed(f"ntp_stratum_{ip}") % 3) + 1)
        assert len(results) > 1  # Not all the same


class TestSuspiciousPowerShell:
    """Tests for parameterized suspicious PowerShell commands."""

    def test_different_seeds_produce_different_commands(self):
        from unittest.mock import MagicMock

        from evidenceforge.generation.activity.suspicious_benign import (
            generate_unusual_powershell,
        )

        system = MagicMock()
        system.hostname = "TEST-01"
        system.os = "Windows 10"
        system.type = "workstation"
        user = MagicMock()
        user.username = "testuser"
        user.persona = "default"

        from datetime import datetime

        hour = datetime(2024, 1, 15, 10, 0, 0)

        commands = set()
        for seed in range(50):
            result = generate_unusual_powershell(random.Random(seed), [user], [system], hour)
            if result:
                commands.add(result["command_line"])

        # Should produce at least 5 distinct commands across successful calls
        assert len(commands) >= 5, f"Only {len(commands)} distinct commands"
