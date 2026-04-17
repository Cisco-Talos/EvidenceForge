# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Unit tests for DLL load profile loader."""

import logging

from evidenceforge.generation.activity.dll_load_profiles import (
    _apply_defaults,
    _validate_entry,
    get_dlls_for_process,
    load_dll_profiles,
)


class TestLoadProfiles:
    """Test the unified profile loader."""

    def test_common_pool_exists(self):
        profiles = load_dll_profiles()
        common = profiles.get("_common", [])
        assert len(common) > 0, "Common loaded modules must not be empty"
        paths = [d["path"] for d in common]
        assert any("ntdll.dll" in p for p in paths)
        assert any("kernel32.dll" in p for p in paths)

    def test_explorer_has_specific_dlls(self):
        profiles = load_dll_profiles()
        explorer = profiles.get("explorer.exe", [])
        assert len(explorer) > 0
        paths = [d["path"].lower() for d in explorer]
        assert any("shell32.dll" in p for p in paths)
        assert any("uxtheme.dll" in p for p in paths)

    def test_chrome_from_app_catalog(self):
        profiles = load_dll_profiles()
        chrome = profiles.get("chrome.exe", [])
        assert len(chrome) > 0
        paths = [d["path"].lower() for d in chrome]
        assert any("chrome_elf.dll" in p for p in paths)

    def test_lsass_has_auth_dlls(self):
        profiles = load_dll_profiles()
        lsass = profiles.get("lsass.exe", [])
        paths = [d["path"].lower() for d in lsass]
        assert any("kerberos.dll" in p for p in paths)
        assert any("wdigest.dll" in p for p in paths)


class TestGetDllsForProcess:
    """Test the unified lookup function."""

    def test_known_process_gets_common_plus_specific(self):
        dlls = get_dlls_for_process("explorer.exe")
        paths = [d["path"] for d in dlls]
        # Should have common DLLs
        assert any("ntdll.dll" in p for p in paths)
        # Should have explorer-specific DLLs
        assert any("shell32.dll" in p for p in paths)

    def test_unknown_process_gets_common_only(self):
        dlls = get_dlls_for_process("totally_unknown_app.exe")
        profiles = load_dll_profiles()
        common = profiles.get("_common", [])
        assert len(dlls) == len(common)

    def test_case_insensitive_lookup(self):
        lower = get_dlls_for_process("explorer.exe")
        upper = get_dlls_for_process("EXPLORER.EXE")
        mixed = get_dlls_for_process("Explorer.Exe")
        assert len(lower) == len(upper) == len(mixed)

    def test_all_entries_have_required_fields(self):
        dlls = get_dlls_for_process("svchost.exe")
        for dll in dlls:
            assert "path" in dll
            assert "signed" in dll
            assert "signature" in dll
            assert "signature_status" in dll


class TestApplyDefaults:
    """Test default field application."""

    def test_minimal_entry_gets_defaults(self):
        entry = {"path": r"C:\Windows\System32\test.dll"}
        result = _apply_defaults(entry)
        assert result["signed"] is True
        assert result["signature"] == "Microsoft Windows"
        assert result["signature_status"] == "Valid"

    def test_explicit_values_preserved(self):
        entry = {
            "path": r"C:\Program Files\App\plugin.dll",
            "signed": False,
            "signature": "-",
            "signature_status": "Unavailable",
        }
        result = _apply_defaults(entry)
        assert result["signed"] is False
        assert result["signature"] == "-"
        assert result["signature_status"] == "Unavailable"


class TestValidation:
    """Test entry validation."""

    def test_valid_entry_passes(self):
        assert _validate_entry({"path": r"C:\Windows\System32\ntdll.dll"}, "test") is True

    def test_empty_path_fails(self):
        assert _validate_entry({"path": ""}, "test") is False

    def test_non_mapping_entry_fails(self, caplog):
        with caplog.at_level(logging.WARNING):
            result = _validate_entry("not-a-dict", "test")
        assert result is False
        assert "must be a mapping" in caplog.text

    def test_non_string_path_fails(self, caplog):
        with caplog.at_level(logging.WARNING):
            result = _validate_entry({"path": None}, "test")
        assert result is False
        assert "non-string path" in caplog.text

    def test_non_windows_path_fails(self, caplog):
        with caplog.at_level(logging.WARNING):
            result = _validate_entry({"path": "/usr/lib/libfoo.so"}, "test")
        assert result is False
        assert "does not look like a Windows path" in caplog.text

    def test_invalid_signature_status_fails(self, caplog):
        with caplog.at_level(logging.ERROR):
            result = _validate_entry(
                {"path": r"C:\test.dll", "signature_status": "BadValue"},
                "test",
            )
        assert result is False
        assert "invalid signature_status" in caplog.text

    def test_valid_signature_statuses_pass(self):
        for status in ["Valid", "Expired", "Revoked", "Unavailable"]:
            assert (
                _validate_entry({"path": r"C:\test.dll", "signature_status": status}, "test")
                is True
            )
