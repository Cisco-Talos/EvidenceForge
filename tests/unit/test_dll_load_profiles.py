# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Unit tests for DLL load profile loader."""

import logging

from evidenceforge.generation.activity.dll_load_profiles import (
    _apply_defaults,
    _validate_entry,
    get_dlls_for_process,
    get_runtime_dlls_for_process,
    get_startup_dlls_for_process,
    load_dll_profiles,
    module_is_compatible_with_process,
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
            assert dll["load_phase"] in {"startup", "runtime"}

    def test_common_loader_chain_is_startup_only(self):
        startup = get_startup_dlls_for_process("totally_unknown_app.exe")
        runtime = get_runtime_dlls_for_process("totally_unknown_app.exe")

        assert [dll["path"].rsplit("\\", 1)[-1].lower() for dll in startup[:3]] == [
            "ntdll.dll",
            "kernel32.dll",
            "kernelbase.dll",
        ]
        assert runtime == []

    def test_application_modules_default_to_startup(self):
        startup_paths = {dll["path"].lower() for dll in get_startup_dlls_for_process("firefox.exe")}
        runtime_paths = {dll["path"].lower() for dll in get_runtime_dlls_for_process("firefox.exe")}

        assert any(path.endswith("\\mozglue.dll") for path in startup_paths)
        assert not any(path.endswith("\\mozglue.dll") for path in runtime_paths)

    def test_process_specific_lazy_modules_default_to_runtime(self):
        startup_paths = {
            dll["path"].lower() for dll in get_startup_dlls_for_process("explorer.exe")
        }
        runtime_paths = {
            dll["path"].lower() for dll in get_runtime_dlls_for_process("explorer.exe")
        }

        assert not any(path.endswith("\\7-zip.dll") for path in startup_paths)
        assert any(path.endswith("\\7-zip.dll") for path in runtime_paths)

    def test_known_third_party_module_is_owner_restricted(self):
        module = r"C:\Program Files (x86)\Cisco\Cisco AnyConnect Secure Mobility Client\vpnapi.dll"

        assert module_is_compatible_with_process("vpnagent.exe", module)
        assert module_is_compatible_with_process("vpnui.exe", module)
        assert not module_is_compatible_with_process("svchost.exe", module)

    def test_windows_and_unknown_modules_remain_valid_for_explicit_adapters(self):
        assert module_is_compatible_with_process("mmc.exe", r"C:\Windows\System32\dsadmin.dll")
        assert module_is_compatible_with_process(
            "custom.exe", r"C:\Program Files\Custom\extension.dll"
        )


class TestApplyDefaults:
    """Test default field application."""

    def test_minimal_entry_gets_defaults(self):
        entry = {"path": r"C:\Windows\System32\test.dll"}
        result = _apply_defaults(entry)
        assert result["signed"] is True
        assert result["signature"] == "Microsoft Windows"
        assert result["signature_status"] == "Valid"
        assert result["load_phase"] == "runtime"

    def test_source_default_load_phase_is_applied(self):
        entry = {"path": r"C:\Windows\System32\ntdll.dll"}

        result = _apply_defaults(entry, default_load_phase="startup")

        assert result["load_phase"] == "startup"

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

    def test_invalid_load_phase_fails(self, caplog):
        with caplog.at_level(logging.ERROR):
            result = _validate_entry(
                {"path": r"C:\test.dll", "load_phase": "sometimes"},
                "test",
            )
        assert result is False
        assert "invalid load_phase" in caplog.text

    def test_valid_signature_statuses_pass(self):
        for status in ["Valid", "Expired", "Revoked", "Unavailable"]:
            assert (
                _validate_entry({"path": r"C:\test.dll", "signature_status": status}, "test")
                is True
            )
