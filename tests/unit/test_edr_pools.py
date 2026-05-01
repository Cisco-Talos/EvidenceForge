# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Unit tests for EDR pools YAML loader."""

from evidenceforge.generation.activity.edr_pools import (
    _sanitize_edr_pools,
    get_dll_pool,
    get_file_paths,
    get_registry_keys_hkcu,
    get_registry_keys_hklm,
    load_edr_pools,
    materialize_edr_template,
    select_file_side_effect,
)


class TestLoadEdrPools:
    """Test that the YAML loads correctly with all sections."""

    def test_all_sections_present(self):
        pools = load_edr_pools()
        assert "file_paths_windows" in pools
        assert "file_paths_linux" in pools
        assert "registry_keys_hkcu" in pools
        assert "registry_keys_hklm" in pools
        assert "dll_pool" in pools

    def test_all_sections_non_empty(self):
        pools = load_edr_pools()
        for key in [
            "file_paths_windows",
            "file_paths_linux",
            "registry_keys_hkcu",
            "registry_keys_hklm",
            "dll_pool",
            "file_side_effect_profiles",
        ]:
            assert len(pools[key]) > 0, f"{key} is empty"

    def test_read_only_recon_tool_has_no_file_side_effect(self):
        import random

        effect = select_file_side_effect(
            process_name=r"C:\Windows\System32\dsquery.exe",
            command_line='dsquery.exe group -name "Domain Admins"',
            os_category="windows",
            rng=random.Random(5),
            user="alice",
        )

        assert effect is None

    def test_browser_side_effect_uses_browser_cache_profile(self):
        import random

        effect = select_file_side_effect(
            process_name=r"C:\Program Files\Google\Chrome\Application\chrome.exe",
            command_line="chrome.exe --type=renderer",
            os_category="windows",
            rng=random.Random(5),
            user="alice",
        )

        assert effect is not None
        action, path = effect
        assert action in {"create", "modify"}
        assert "cache" in path.lower()
        assert "Security.evtx" not in path


class TestFilePaths:
    """Test file path pool content."""

    def test_windows_has_templates(self):
        paths = get_file_paths("windows")
        assert any("{user}" in p for p in paths), "No {user} template in Windows paths"
        assert any("{rand}" in p for p in paths), "No {rand} template in Windows paths"

    def test_linux_has_templates(self):
        paths = get_file_paths("linux")
        assert any("{user}" in p for p in paths), "No {user} template in Linux paths"
        assert any("/home/" in p for p in paths), "No /home/ paths in Linux pool"

    def test_windows_paths_have_backslashes(self):
        paths = get_file_paths("windows")
        assert all("\\" in p for p in paths), "Windows paths should use backslashes"

    def test_linux_paths_have_forward_slashes(self):
        paths = get_file_paths("linux")
        assert all("/" in p for p in paths), "Linux paths should use forward slashes"


class TestRegistryKeys:
    """Test registry key pool content."""

    def test_hkcu_returns_3tuples(self):
        keys = get_registry_keys_hkcu()
        assert len(keys) >= 5
        for k, vname, details in keys:
            assert k.startswith("HKCU\\"), f"HKCU key doesn't start with HKCU\\: {k}"
            assert "\\" in k, f"Key missing backslash: {k}"
            assert vname, f"Value name is empty for key {k}"
            assert details, f"Details is empty for key {k}"

    def test_hklm_returns_3tuples(self):
        keys = get_registry_keys_hklm()
        assert len(keys) >= 4
        for k, vname, _details in keys:
            assert k.startswith("HKLM\\"), f"HKLM key doesn't start with HKLM\\: {k}"
            assert vname, f"Value name is empty for key {k}"

    def test_registry_details_are_realistic(self):
        """Details should be DWORD values or strings, not value names."""
        for _k, _vn, details in get_registry_keys_hklm():
            assert details.startswith("DWORD (") or not details.isupper(), (
                f"Details looks like a value name, not data: {details}"
            )


class TestDllPool:
    """Test DLL path pool content."""

    def test_contains_system32_and_application_dlls(self):
        dlls = get_dll_pool()
        assert len(dlls) >= 5
        assert any("System32" in d for d in dlls)
        assert any("Program Files" in d for d in dlls)

    def test_contains_common_dlls(self):
        dlls = get_dll_pool()
        dll_names = [d.rsplit("\\", 1)[-1].lower() for d in dlls]
        assert "ntdll.dll" in dll_names
        assert "kernel32.dll" in dll_names


class TestTemplateMaterialization:
    """Test EDR template placeholder expansion."""

    def test_materializes_registry_and_dll_placeholders(self):
        import random

        rng = random.Random(7)
        value = materialize_edr_template(
            r"HKCU\Software\Test\{guid}\Document {doc}\{hex}\{user}",
            rng,
            "alice",
        )

        assert "{guid}" not in value
        assert "{doc}" not in value
        assert "{hex}" not in value
        assert value.endswith(r"\alice")

    def test_materializes_guid_with_single_registry_braces(self):
        import random

        rng = random.Random(9)
        value = materialize_edr_template(r"Interfaces\{{{guid}}}\DhcpIPAddress", rng)

        assert "{{" not in value
        assert "}}" not in value
        assert value.startswith(r"Interfaces\{")
        assert value.endswith(r"}\DhcpIPAddress")


class TestOverlayValidation:
    """Test fallback behavior for malformed overlay-provided pools."""

    def test_sanitize_empty_string_pools_falls_back_to_defaults(self):
        defaults = {
            "file_paths_windows": [r"C:\\Windows\\Temp\\x.tmp"],
            "file_paths_linux": ["/tmp/x.tmp"],
            "dll_pool": [r"C:\\Windows\\System32\\kernel32.dll"],
            "registry_keys_hkcu": [["HKCU\\Software\\X", "Enabled", "DWORD (0x00000001)"]],
            "registry_keys_hklm": [["HKLM\\Software\\X", "Enabled", "DWORD (0x00000001)"]],
        }
        merged = {**defaults, "file_paths_windows": [], "dll_pool": []}

        sanitized = _sanitize_edr_pools(defaults, merged)

        assert sanitized["file_paths_windows"] == defaults["file_paths_windows"]
        assert sanitized["dll_pool"] == defaults["dll_pool"]

    def test_sanitize_malformed_registry_pool_falls_back_to_defaults(self):
        defaults = {
            "file_paths_windows": [r"C:\\Windows\\Temp\\x.tmp"],
            "file_paths_linux": ["/tmp/x.tmp"],
            "dll_pool": [r"C:\\Windows\\System32\\kernel32.dll"],
            "registry_keys_hkcu": [["HKCU\\Software\\X", "Enabled", "DWORD (0x00000001)"]],
            "registry_keys_hklm": [["HKLM\\Software\\X", "Enabled", "DWORD (0x00000001)"]],
        }
        merged = {**defaults, "registry_keys_hkcu": {"bad": "shape"}}

        sanitized = _sanitize_edr_pools(defaults, merged)

        assert sanitized["registry_keys_hkcu"] == defaults["registry_keys_hkcu"]
