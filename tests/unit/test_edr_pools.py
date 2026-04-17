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
        ]:
            assert len(pools[key]) > 0, f"{key} is empty"


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

    def test_contains_system32_dlls(self):
        dlls = get_dll_pool()
        assert len(dlls) >= 5
        assert all("System32" in d for d in dlls)

    def test_contains_common_dlls(self):
        dlls = get_dll_pool()
        dll_names = [d.rsplit("\\", 1)[-1].lower() for d in dlls]
        assert "ntdll.dll" in dll_names
        assert "kernel32.dll" in dll_names


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
