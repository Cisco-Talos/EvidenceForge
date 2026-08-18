# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Focused tests for OS-native deployment identity publication and rendering."""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

from evidenceforge.config.compatibility import EvidenceForgeDeprecationWarning
from evidenceforge.config.schemas import SystemBinaryEntry
from evidenceforge.generation.activity.edr_pools import normalize_defender_platform_path
from evidenceforge.generation.activity.system_processes import (
    get_native_system_binary_descriptors,
)
from evidenceforge.generation.deployment_compiler import (
    compile_native_deployment_registry,
    resolve_system_build,
)
from evidenceforge.generation.storage_world import (
    CompiledStorageAccess,
    CompiledStorageFile,
    CompiledStorageShare,
    StorageWorldModel,
)
from evidenceforge.generation.world_model import WorldModel
from evidenceforge.models.scenario import Scenario, System

_SCENARIO_PATH = Path(__file__).parents[1] / "fixtures" / "scenarios" / "minimal.yaml"
_IDENTITY_FIELDS = {
    "Hashes",
    "FileVersion",
    "Description",
    "Product",
    "Company",
    "OriginalFileName",
}


def _scenario_with_systems(
    systems: list[dict[str, object]],
    *,
    deployment_overrides: list[dict[str, object]] | None = None,
) -> Scenario:
    payload = yaml.safe_load(_SCENARIO_PATH.read_text(encoding="utf-8"))
    payload["environment"]["systems"] = systems
    payload["environment"]["users"][0]["primary_system"] = systems[0]["hostname"]
    payload["environment"]["network"]["segments"][0]["systems"] = [
        system["hostname"] for system in systems
    ]
    if deployment_overrides is not None:
        payload["environment"]["deployment_overrides"] = deployment_overrides
    return Scenario.model_validate(payload)


def _compile(systems: list[dict[str, object]]):
    scenario = _scenario_with_systems(systems)
    world = WorldModel(scenario, "example.com")
    return scenario, compile_native_deployment_registry(scenario, world)


def _system(
    hostname: str,
    ip_suffix: int,
    *,
    os_name: str = "Windows 11 Enterprise",
    os_build: str | None = None,
    architecture: str | None = None,
) -> dict[str, object]:
    system: dict[str, object] = {
        "hostname": hostname,
        "ip": f"10.0.0.{ip_suffix}",
        "os": os_name,
        "type": "workstation",
    }
    if os_build is not None:
        system["os_build"] = os_build
    if architecture is not None:
        system["architecture"] = architecture
    return system


def test_storage_world_content_compiles_once_without_paths_or_payloads() -> None:
    scenario = _scenario_with_systems([_system("WS-01", 1)])
    world = WorldModel(scenario, "example.com")
    storage_file = CompiledStorageFile(
        file_id="storage-file-quarterly-report",
        share="WS-01.documents",
        path=r"Finance\Quarterly Report.pdf",
        size_bytes=48_512,
        mime_type="application/pdf",
        tags=("finance",),
        seed_ref="quarterly-report-payload",
    )
    storage_world = StorageWorldModel(
        volumes=(),
        shares=(
            CompiledStorageShare(
                ref="WS-01.documents",
                system="WS-01",
                name="Documents",
                volume="data",
                root="Shares",
                preset="collaboration",
                population="tiny",
                activity="standard",
                encryption="off",
                smb_native_filesystem="NTFS",
                audit="standard",
                access=CompiledStorageAccess(
                    read=frozenset({"alice"}),
                    modify=frozenset({"alice"}),
                    admin=frozenset(),
                    deny=frozenset(),
                ),
                files=(storage_file,),
            ),
        ),
        mappings=(),
    )

    registry = compile_native_deployment_registry(
        scenario,
        world,
        storage_world=storage_world,
    )
    content = registry.file_content(storage_file.file_id, storage_file.version)

    assert content is not None
    assert registry.file_content_by_id(content.content_id) is content
    assert content.size_bytes == storage_file.size_bytes
    assert content.mime_type == storage_file.mime_type
    assert content.seed_ref == storage_file.seed_ref
    assert not hasattr(content, "path")
    assert not hasattr(content, "payload")
    assert registry.census().file_versions == 1


def test_enabled_user_profile_compiles_without_application_persona() -> None:
    """A missing persona compiles the OS profile and catalog-default applications."""

    scenario = Scenario.model_validate(yaml.safe_load(_SCENARIO_PATH.read_text(encoding="utf-8")))
    assert scenario.environment.users[0].persona is None
    registry = compile_native_deployment_registry(
        scenario,
        WorldModel(scenario, "example.com"),
    )

    profile = registry.user_profile_for("TEST-01", "test_user", "windows")
    assert profile is not None
    assert profile.profile_root == r"C:\Users\test_user"
    teams = registry.resolve_binary(
        "TEST-01",
        r"C:\Users\test_user\AppData\Local\Microsoft\Teams\current\Teams.exe",
        "windows",
        principal="test_user",
    )
    assert teams is not None
    assignments = registry.user_application_assignments_for_product("TEST-01", "teams")
    assert [(assignment.principal, assignment.persona) for assignment in assignments] == [
        ("test_user", "default")
    ]


def test_authored_process_actor_profile_compiles_on_exact_storyline_host() -> None:
    """An explicitly placed process actor owns a profile on that exact host."""

    attack_path = Path(__file__).parents[1] / "fixtures" / "scenarios" / "attack.yaml"
    scenario = Scenario.model_validate(yaml.safe_load(attack_path.read_text(encoding="utf-8")))
    registry = compile_native_deployment_registry(
        scenario,
        WorldModel(scenario, "corp.example.com"),
    )

    profile = registry.user_profile_for("WS-EXEC-01", "attacker", "windows")
    assert profile is not None
    assert profile.profile_root == r"C:\Users\attacker"


def test_windows_explorer_is_deployed_where_session_shell_generation_is_supported() -> None:
    """Server and domain-controller session shells resolve the exact Explorer release."""

    systems = [
        _system("WS-01", 1),
        {
            "hostname": "DC-01",
            "ip": "10.0.0.2",
            "os": "Windows Server 2019",
            "type": "domain_controller",
        },
    ]
    _scenario, registry = _compile(systems)

    explorer = registry.resolve_binary(
        "DC-01",
        r"C:\Windows\explorer.exe",
        "windows",
    )
    assert explorer is not None
    assert explorer.key.product_id == "windows-explorer"


def test_native_system_binary_catalog_is_typed_and_legacy_compatible() -> None:
    """Every repository binary is typed; old path entries normalize once at the boundary."""

    descriptors = get_native_system_binary_descriptors("windows")

    by_exe = {item.exe: item for item in descriptors}
    assert len(descriptors) == 100
    assert by_exe["winlogon.exe"].has_pe_version_info
    assert by_exe["userinit.exe"].has_pe_version_info
    assert by_exe["eventvwr.exe"].release_policy == "host_build"
    assert by_exe["vpnagent.exe"].release_policy == "unspecified"
    assert all(item.release_policy in {"host_build", "unspecified"} for item in descriptors)
    with pytest.warns(EvidenceForgeDeprecationWarning, match="in a future release"):
        legacy = SystemBinaryEntry.model_validate(
            {"exe": "legacy.exe", "path": r"C:\Windows\legacy.exe"}
        )
    assert legacy.native_release is None
    assert legacy.release_policy == "unspecified"
    with pytest.raises(ValueError, match="must be a filename"):
        SystemBinaryEntry.model_validate(
            {
                "exe": "bad.exe",
                "path": r"C:\Windows\bad.exe",
                "release_policy": "host_build",
                "native_release": {
                    "product_id": "windows",
                    "description": "bad",
                    "product": "Windows",
                    "company": "Microsoft",
                    "original_filename": r"C:\Windows\bad.exe",
                },
            }
        )


def test_explicit_build_and_architecture_override_legacy_inference() -> None:
    """Exact authored System fields own deployment and binary release identity."""

    scenario, registry = _compile(
        [_system("WS-ARM", 10, os_build="10.0.26100.3194", architecture="arm64")]
    )
    system = scenario.environment.systems[0]
    deployment = registry.host_deployment(system.hostname)
    identity = registry.resolve_binary(
        system.hostname,
        r"C:\Windows\System32\winlogon.exe",
        "windows",
    )

    assert deployment is not None
    assert (deployment.os_build, deployment.architecture) == ("10.0.26100.3194", "arm64")
    assert identity is not None
    assert (identity.key.build, identity.key.architecture) == ("10.0.26100.3194", "arm64")
    assert identity.pe_version_info is not None
    assert identity.pe_version_info.file_version == "10.0.26100.3194"


@pytest.mark.parametrize(
    ("os_name", "system_type", "expected"),
    [
        ("Windows 10 Enterprise", "workstation", "10.0.19041.1"),
        ("Windows 11 Enterprise", "workstation", "10.0.22621.1"),
        ("Windows Server 2019", "server", "10.0.17763.1"),
        ("Windows Server 2022", "server", "10.0.20348.1"),
    ],
)
def test_legacy_windows_build_inference_is_preserved(
    os_name: str,
    system_type: str,
    expected: str,
) -> None:
    """Omitted additive build fields retain the established Sysmon mapping."""

    system = System(
        hostname="WS-01",
        ip="10.0.0.1",
        os=os_name,
        type=system_type,
    )
    assert resolve_system_build(system, "windows") == expected


def test_release_identity_is_shared_by_build_and_separated_across_build_arch_and_artifact() -> None:
    """Content identity excludes placement while retaining every binary release dimension."""

    _scenario, registry = _compile(
        [
            _system("WS-A", 1, os_build="10.0.22621.1", architecture="x64"),
            _system("WS-B", 2, os_build="10.0.22621.1", architecture="x64"),
            _system("WS-C", 3, os_build="10.0.26100.1", architecture="x64"),
            _system("WS-D", 4, os_build="10.0.22621.1", architecture="arm64"),
        ]
    )
    winlogon = {
        hostname: registry.resolve_binary(
            hostname,
            r"C:\Windows\System32\winlogon.exe",
            "windows",
        )
        for hostname in ("WS-A", "WS-B", "WS-C", "WS-D")
    }
    userinit = registry.resolve_binary(
        "WS-A",
        r"C:\Windows\System32\userinit.exe",
        "windows",
    )

    assert all(identity is not None for identity in winlogon.values())
    assert winlogon["WS-A"] is winlogon["WS-B"]
    assert winlogon["WS-A"].content_id != winlogon["WS-C"].content_id  # type: ignore[union-attr]
    assert winlogon["WS-A"].content_id != winlogon["WS-D"].content_id  # type: ignore[union-attr]
    assert userinit is not None
    assert userinit.release_id == winlogon["WS-A"].release_id  # type: ignore[union-attr]
    assert userinit.content_id != winlogon["WS-A"].content_id  # type: ignore[union-attr]
    assert (
        registry.resolve_binary("WS-A", "winlogon.exe", "windows") is None
    )  # No basename fallback.
    census = registry.binary_path_index_census()
    assert census.bindings > 400
    assert census.interned_hosts == 4
    assert census.interned_native_paths > 100
    assert census.packed_integer_keys == census.bindings
    assert census.packed_integer_targets == census.bindings
    assert registry.deployment_census().host_deployments == 4


def test_exact_host_service_and_task_overrides_reach_compiled_deployment() -> None:
    """Scenario-layer exact-host replacements win before immutable compilation."""

    system = _system("WS-01", 1)
    system["services"] = ["default-service"]
    scenario = _scenario_with_systems(
        [system],
        deployment_overrides=[
            {
                "system": "WS-01",
                "services": ["scenario-service"],
                "tasks": [r"\Microsoft\Windows\ScenarioTask"],
            }
        ],
    )
    registry = compile_native_deployment_registry(scenario, WorldModel(scenario, "example.com"))
    deployment = registry.host_deployment("WS-01")

    assert deployment is not None
    assert {
        registry.service_identity_by_handle(handle) for handle in deployment.service_handles
    } == {"scenario-service"}
    assert {registry.task_identity_by_handle(handle) for handle in deployment.task_handles} == {
        r"\Microsoft\Windows\ScenarioTask"
    }


def test_default_service_task_and_module_catalogs_compile_to_exact_host_capabilities() -> None:
    """Role placement and module ownership compile once into exact bounded lookups."""

    systems = [_system(f"WS-{index:02d}", index) for index in range(1, 9)]
    domain_controller = _system("DC-01", 20, os_name="Windows Server 2022")
    domain_controller["type"] = "domain_controller"
    systems.append(domain_controller)
    _scenario, registry = _compile(systems)

    assert registry.host_service("WS-01", "wmi-provider") == "wmi-provider"
    assert registry.host_service_handle("WS-01", "wmi-provider") is not None
    assert registry.host_service("WS-01", "dns-server") is None
    assert registry.host_service("DC-01", "dns-server") == "dns-server"
    assert registry.host_task("WS-01", "windows-task-host") == "windows-task-host"
    assert registry.host_task("DC-01", "windows-disk-cleanup") is None

    service_page, service_cursor = registry.page_host_services("WS-01", limit=3)
    task_page, task_cursor = registry.page_host_tasks("WS-01", limit=4)
    assert len(service_page) == 3 and service_cursor is not None
    assert len(task_page) == 4 and task_cursor is not None
    assert registry.count_host_services("WS-01") == len(tuple(registry.iter_host_services("WS-01")))
    assert registry.count_host_tasks("WS-01") == len(tuple(registry.iter_host_tasks("WS-01")))

    ntdll = registry.resolve_binary("WS-01", r"C:\Windows\System32\ntdll.dll", "windows")
    assert ntdll is not None
    assert registry.host_module("WS-01", ntdll.content_id) == ntdll
    assert registry.host_module_handle("WS-01", ntdll.content_id) is not None
    module_page, module_cursor = registry.page_host_modules("WS-01", limit=5)
    assert len(module_page) == 5 and module_cursor is not None
    assert registry.count_host_modules("WS-01") == len(tuple(registry.iter_host_modules("WS-01")))

    remote_service_images = {
        "cisco-secure-client": (
            r"C:\Program Files (x86)\Cisco\Cisco AnyConnect Secure Mobility Client\vpnagent.exe"
        ),
        "globalprotect": r"C:\Program Files\Palo Alto Networks\GlobalProtect\PanGPS.exe",
        "zscaler-service": r"C:\Program Files\Zscaler\ZSAService\ZSAService.exe",
        "zscaler-tunnel": r"C:\Program Files\Zscaler\ZSATunnel\ZSATunnel.exe",
    }
    selected_remote_services = 0
    unselected_remote_services = 0
    for service_id, image_path in remote_service_images.items():
        service_selected = registry.host_service("WS-01", service_id) is not None
        assert (
            registry.resolve_binary("WS-01", image_path, "windows") is not None
        ) is service_selected
        selected_remote_services += int(service_selected)
        unselected_remote_services += int(not service_selected)
    assert selected_remote_services > 0
    assert unselected_remote_services > 0
    zscaler_module = registry.resolve_binary(
        "WS-01",
        r"C:\Program Files\Zscaler\ZSAService\ZSACommon.dll",
        "windows",
    )
    assert (zscaler_module is not None) is (
        registry.host_service("WS-01", "zscaler-service") is not None
    )


def test_rsat_modules_require_an_eligible_admin_population() -> None:
    """RSAT snap-ins exist only where the production planner can place an admin session."""

    developer_scenario = _scenario_with_systems([_system("WS-01", 1)])
    developer_scenario.environment.users[0].persona = "developer"
    developer_registry = compile_native_deployment_registry(
        developer_scenario,
        WorldModel(developer_scenario, "example.com"),
    )
    assert (
        developer_registry.resolve_binary(
            "WS-01",
            r"C:\Windows\System32\dsadmin.dll",
            "windows",
        )
        is None
    )

    admin_scenario = _scenario_with_systems([_system("WS-01", 1)])
    admin_scenario.environment.users[0].persona = "sysadmin"
    admin_registry = compile_native_deployment_registry(
        admin_scenario,
        WorldModel(admin_scenario, "example.com"),
    )
    module = admin_registry.resolve_binary(
        "WS-01",
        r"C:\Windows\System32\dsadmin.dll",
        "windows",
    )
    assert module is not None
    assert admin_registry.host_module("WS-01", module.content_id) is module


def test_resident_service_families_compile_only_on_matching_roles() -> None:
    """Service managers/workers share exact host placement with their role catalog."""

    mail = _system("MAIL-01", 10, os_name="Ubuntu 22.04")
    mail.update({"type": "server", "roles": ["mail_server"], "services": ["postfix"]})
    web = _system("WEB-01", 11, os_name="Windows Server 2022")
    web.update({"type": "server", "roles": ["web_server"], "services": ["iis"]})
    workstation = _system("WS-01", 12, os_name="Windows 11 Enterprise")
    _scenario, registry = _compile([mail, web, workstation])

    assert registry.host_service("MAIL-01", "postfix-resident-workers") is not None
    assert (
        registry.resolve_binary(
            "MAIL-01",
            "/usr/lib/postfix/sbin/smtpd",
            "linux",
        )
        is not None
    )
    assert registry.host_service("WEB-01", "iis-resident-workers") is not None
    assert (
        registry.resolve_binary(
            "WEB-01",
            r"C:\Windows\System32\inetsrv\w3wp.exe",
            "windows",
        )
        is not None
    )
    assert registry.host_service("WS-01", "iis-resident-workers") is None


def test_sql_server_seeded_service_compiles_only_for_exact_host_capability() -> None:
    """The seeded SQL service keeps a typed deployment without broad server placement."""

    sql_server = _system("SQL-01", 18, os_name="Windows Server 2022")
    sql_server.update({"type": "server", "services": ["mssql"]})
    file_server = _system("FILE-01", 19, os_name="Windows Server 2022")
    file_server.update({"type": "server", "roles": ["file_server"], "services": ["smb"]})
    _scenario, registry = _compile([sql_server, file_server])
    image = r"C:\Program Files\Microsoft SQL Server\MSSQL16.MSSQLSERVER\MSSQL\Binn\sqlservr.exe"

    assert (
        registry.host_service("SQL-01", "microsoft-sql-server-engine")
        == "microsoft-sql-server-engine"
    )
    release = registry.resolve_binary("SQL-01", image, "windows")
    assert release is not None
    assert release.key.version == "unspecified"
    assert release.pe_version_info is None
    assert registry.host_service("FILE-01", "microsoft-sql-server-engine") is None
    assert registry.resolve_binary("FILE-01", image, "windows") is None
    assert (
        registry.resolve_binary(
            "WS-01",
            r"C:\Windows\System32\inetsrv\w3wp.exe",
            "windows",
        )
        is None
    )


def test_linux_schedule_catalog_compiles_distro_exact_tasks_and_artifacts() -> None:
    """Linux timer/cron placement respects distro while retaining exact task handles."""

    debian = _system("DEB-01", 21, os_name="Ubuntu 22.04")
    debian.update({"type": "server", "roles": ["web_server"], "services": ["php-fpm"]})
    rhel = _system("RHEL-01", 22, os_name="Rocky Linux 9")
    rhel.update({"type": "server"})
    _scenario, registry = _compile([debian, rhel])

    assert registry.host_task("DEB-01", "linux-apt-daily-timer") is not None
    assert registry.host_task("DEB-01", "linux-dnf-automatic-timer") is None
    assert registry.host_task("RHEL-01", "linux-dnf-automatic-timer") is not None
    assert registry.host_task("RHEL-01", "linux-apt-daily-timer") is None
    assert (
        registry.resolve_binary(
            "DEB-01",
            "/usr/lib/apt/apt.systemd.daily",
            "linux",
        )
        is not None
    )
    assert registry.resolve_binary("RHEL-01", "/usr/bin/dnf-automatic", "linux") is not None
    assert registry.resolve_binary("DEB-01", "/usr/bin/dnf-automatic", "linux") is None
    snapd = registry.resolve_binary("DEB-01", "/usr/lib/snapd/snapd", "linux")
    assert snapd is not None
    assert snapd.key.product_id == "linux-host"
    assert registry.resolve_binary("RHEL-01", "/usr/lib/snapd/snapd", "linux") is None


def test_linux_boot_daemon_catalog_compiles_exact_distro_paths() -> None:
    """Every seeded Linux daemon resolves without cross-distro path fabrication."""

    debian = _system("DEB-01", 23, os_name="Ubuntu 24.04")
    rhel = _system("RHEL-01", 24, os_name="Rocky Linux 9")
    _scenario, registry = _compile([debian, rhel])

    common_paths = (
        "/usr/lib/systemd/systemd",
        "/usr/lib/systemd/systemd-journald",
        "/usr/libexec/gnome-terminal-server",
        "/usr/bin/dbus-daemon",
        "/usr/bin/java",
        "/usr/sbin/sshd",
        "/bin/login",
        "/sbin/agetty",
    )
    for hostname in ("DEB-01", "RHEL-01"):
        assert all(
            registry.resolve_binary(hostname, path, "linux") is not None for path in common_paths
        )

    assert registry.resolve_binary("DEB-01", "/lib/systemd/systemd-udevd", "linux")
    assert registry.resolve_binary("DEB-01", "/usr/sbin/cron", "linux")
    assert registry.resolve_binary("RHEL-01", "/usr/lib/systemd/systemd-udevd", "linux")
    assert registry.resolve_binary("RHEL-01", "/usr/sbin/crond", "linux")
    assert registry.resolve_binary("DEB-01", "/usr/sbin/crond", "linux") is None
    assert registry.resolve_binary("RHEL-01", "/usr/sbin/cron", "linux") is None


def test_linux_baseline_shell_catalog_inventory_has_exact_system_owned_placement() -> None:
    """Baseline shell selectors resolve without fabricating cross-host user profiles."""

    catalog_paths = frozenset(
        {
            "/usr/bin/cat",
            "/usr/bin/cut",
            "/usr/bin/date",
            "/usr/bin/df",
            "/usr/bin/du",
            "/usr/bin/file",
            "/usr/bin/find",
            "/usr/bin/free",
            "/usr/bin/grep",
            "/usr/bin/groups",
            "/usr/bin/head",
            "/usr/bin/hostname",
            "/usr/bin/hostnamectl",
            "/usr/bin/id",
            "/usr/bin/journalctl",
            "/usr/bin/last",
            "/usr/bin/loginctl",
            "/usr/bin/ls",
            "/usr/bin/lsblk",
            "/usr/bin/mount",
            "/usr/bin/nmcli",
            "/usr/bin/ps",
            "/usr/bin/python3",
            "/usr/bin/resolvectl",
            "/usr/bin/stat",
            "/usr/bin/systemctl",
            "/usr/bin/tail",
            "/usr/bin/timedatectl",
            "/usr/bin/top",
            "/usr/bin/uname",
            "/usr/bin/uptime",
            "/usr/bin/users",
            "/usr/bin/vmstat",
            "/usr/bin/w",
            "/usr/bin/wc",
            "/usr/bin/who",
            "/usr/bin/whoami",
            "/usr/sbin/ip",
            "/usr/sbin/ss",
        }
    )
    explicitly_placed_unknown_versions = frozenset(
        {
            "/usr/bin/cut",
            "/usr/bin/date",
            "/usr/bin/du",
            "/usr/bin/file",
            "/usr/bin/groups",
            "/usr/bin/hostnamectl",
            "/usr/bin/last",
            "/usr/bin/loginctl",
            "/usr/bin/lsblk",
            "/usr/bin/mount",
            "/usr/bin/nmcli",
            "/usr/bin/resolvectl",
            "/usr/bin/stat",
            "/usr/bin/timedatectl",
            "/usr/bin/users",
            "/usr/bin/vmstat",
            "/usr/bin/who",
        }
    )
    descriptors_by_path = {
        descriptor.path: descriptor for descriptor in get_native_system_binary_descriptors("linux")
    }
    for path in explicitly_placed_unknown_versions:
        descriptor = descriptors_by_path[path]
        assert descriptor.release_policy == "unspecified"
        assert descriptor.has_explicit_placement
        assert set(descriptor.system_types) == {"workstation", "server", "domain_controller"}
        assert not descriptor.roles_any
        assert not descriptor.services_any

    workstation = _system("WS-01", 25)
    linux_mail = _system("MAIL-01", 26, os_name="Ubuntu 22.04")
    linux_mail.update({"type": "server", "roles": ["mail_server"], "services": ["postfix"]})
    linux_file = _system("FILE-01", 27, os_name="Rocky Linux 9")
    linux_file.update({"type": "server", "roles": ["file_server"], "services": ["samba"]})
    windows_mail = _system("WIN-MAIL-01", 28, os_name="Windows Server 2022")
    windows_mail.update({"type": "server", "roles": ["mail_server"], "services": ["smtp"]})
    _scenario, registry = _compile([workstation, linux_mail, linux_file, windows_mail])

    assert registry.user_profile_for("MAIL-01", "test_user", "linux") is None
    for path in catalog_paths:
        assert registry.resolve_binary("MAIL-01", path, "linux") is not None, path
        assert registry.resolve_binary("FILE-01", path, "linux") is not None, path
    for path in explicitly_placed_unknown_versions:
        ubuntu_release = registry.resolve_binary("MAIL-01", path, "linux")
        rocky_release = registry.resolve_binary("FILE-01", path, "linux")
        assert ubuntu_release is not None
        assert ubuntu_release.key.version == "unspecified"
        assert ubuntu_release.pe_version_info is None
        assert rocky_release is not None
        assert rocky_release.key.version == "unspecified"
        assert registry.resolve_binary("WIN-MAIL-01", path, "linux") is None
    assert all(
        descriptor.path not in explicitly_placed_unknown_versions
        for descriptor in get_native_system_binary_descriptors("windows")
    )


def test_installed_software_catalog_compiles_once_and_projects_by_host_architecture() -> None:
    """Inventory placeholders resolve from path-free releases only on compatible hosts."""

    windows = _system("WS-01", 31)
    linux = _system("LINUX-01", 32, os_name="Ubuntu 22.04")
    _scenario, registry = _compile([windows, linux])

    windows_products = tuple(registry.iter_installed_software_on_host("WS-01"))
    assert windows_products
    assert registry.count_installed_software_on_host("WS-01") == len(windows_products)
    assert registry.count_installed_software_on_host("LINUX-01") == 0
    chrome = registry.installed_software_for_product("WS-01", "google-chrome")
    assert chrome is not None
    assert chrome.name == "Google Chrome"
    assert chrome.publisher == "Google LLC"
    assert chrome.version == "123.0.6312.86"


def test_defender_platform_binaries_compile_at_the_exact_host_version_path() -> None:
    """The host-stable Defender version segment is placement, not emitter inference."""

    _scenario, registry = _compile([_system("WS-01", 31)])
    catalog_path = r"C:\ProgramData\Microsoft\Windows Defender\Platform\MsMpEng.exe"
    materialized = normalize_defender_platform_path(catalog_path, "WS-01")

    identity = registry.resolve_binary("WS-01", materialized, "windows")

    assert identity is not None
    assert identity.key.artifact_name == "msmpeng.exe"
    assert registry.resolve_binary("WS-01", catalog_path, "windows") is None
    module_path = normalize_defender_platform_path(
        r"C:\ProgramData\Microsoft\Windows Defender\Platform\MpClient.dll",
        "WS-01",
    )
    module = registry.resolve_binary("WS-01", module_path, "windows")
    assert module is not None
    assert registry.host_module("WS-01", module.content_id) is module


def test_compilation_is_order_independent() -> None:
    """Host ordering and hash seed cannot affect semantic deployment identities."""

    systems = [
        _system("WS-A", 1, os_build="10.0.22621.1"),
        _system("WS-B", 2, os_build="10.0.26100.1"),
    ]
    first_scenario = _scenario_with_systems(systems)
    second_scenario = _scenario_with_systems(list(reversed(systems)))
    # Reordering the host carrier must not silently move the modeled user; keep
    # both scenarios semantically identical before comparing registry identity.
    second_scenario.environment.users[0].primary_system = first_scenario.environment.users[
        0
    ].primary_system
    first = compile_native_deployment_registry(
        first_scenario,
        WorldModel(first_scenario, "example.com"),
    )
    second = compile_native_deployment_registry(
        second_scenario,
        WorldModel(second_scenario, "example.com"),
    )

    for hostname in ("WS-A", "WS-B"):
        first_deployment = first.host_deployment(hostname)
        second_deployment = second.host_deployment(hostname)
        assert first_deployment is not None and second_deployment is not None
        assert first_deployment.deployment_id == second_deployment.deployment_id
        first_identity = first.resolve_binary(
            hostname,
            r"C:\Windows\System32\winlogon.exe",
            "windows",
        )
        second_identity = second.resolve_binary(
            hostname,
            r"C:\Windows\System32\winlogon.exe",
            "windows",
        )
        assert first_identity is not None and second_identity is not None
        assert first_identity.content_id == second_identity.content_id
        assert first_identity.digests == second_identity.digests


def test_compilation_digest_is_independent_of_python_hash_seed() -> None:
    """Release, deployment, and digest identity are stable across interpreter seeds."""

    script = """
import json
from pathlib import Path
import yaml
from evidenceforge.generation.deployment_compiler import compile_native_deployment_registry
from evidenceforge.generation.world_model import WorldModel
from evidenceforge.models.scenario import Scenario

payload = yaml.safe_load(Path('tests/fixtures/scenarios/minimal.yaml').read_text())
payload['environment']['systems'][0].update(
    {'os_build': '10.0.22621.1', 'architecture': 'x64'}
)
scenario = Scenario.model_validate(payload)
registry = compile_native_deployment_registry(scenario, WorldModel(scenario, 'example.com'))
deployment = registry.host_deployment('TEST-01')
identity = registry.resolve_binary(
    'TEST-01', r'C:\\Windows\\System32\\winlogon.exe', 'windows'
)
print(json.dumps({
    'deployment_id': deployment.deployment_id,
    'content_id': identity.content_id,
    'digests': [identity.digests.md5, identity.digests.sha1, identity.digests.sha256,
                identity.digests.imphash],
}, sort_keys=True))
"""
    outputs = []
    for seed in ("1", "8675309"):
        result = subprocess.run(
            [sys.executable, "-c", script],
            check=True,
            capture_output=True,
            text=True,
            env={**os.environ, "PYTHONHASHSEED": seed},
        )
        outputs.append(result.stdout)

    assert outputs[0] == outputs[1]
