# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Canonical SMB storage topology and authoring tests."""

from copy import deepcopy
from pathlib import Path

import pytest
from pydantic import ValidationError

import evidenceforge.generation.storage_world as storage_world_module
from evidenceforge.generation.activity.smb_profiles import reset_smb_profiles_cache
from evidenceforge.generation.storage_world import CompiledStorageMapping, StorageWorldModel
from evidenceforge.models.scenario import Scenario, SmbActivityEventSpec, StorageMappingConfig
from evidenceforge.utils import load_yaml
from evidenceforge.validation import ScenarioValidator


def _storage_scenario_data(scenarios_dir: Path) -> dict:
    data = load_yaml(scenarios_dir / "minimal.yaml")
    data["environment"]["domain"] = "example.com"
    data["environment"]["systems"].extend(
        [
            {
                "hostname": "FS-01",
                "ip": "10.0.0.20",
                "os": "Windows Server 2022",
                "type": "server",
                "roles": ["file_server"],
            },
            {
                "hostname": "FS-02",
                "ip": "10.0.0.21",
                "os": "Windows Server 2022",
                "type": "server",
                "roles": ["file_server"],
            },
            {
                "hostname": "DC-01",
                "ip": "10.0.0.10",
                "os": "Windows Server 2022",
                "type": "domain_controller",
                "roles": ["domain_controller"],
            },
        ]
    )
    data["environment"]["groups"] = [
        {"name": "Finance-Users", "members": ["test_user"]},
        {"name": "Finance-Readers", "members": []},
    ]
    return data


def _linux_storage_scenario_data(scenarios_dir: Path) -> dict:
    data = load_yaml(scenarios_dir / "minimal.yaml")
    data["environment"]["domain"] = "example.com"
    data["environment"]["systems"][0].update(
        {
            "os": "Ubuntu 24.04",
            "roles": ["workstation"],
            "services": ["cifs-utils", "smbclient"],
        }
    )
    data["environment"]["systems"].append(
        {
            "hostname": "SAMBA-01",
            "ip": "10.0.0.20",
            "os": "Ubuntu Server 24.04",
            "type": "server",
            "roles": ["file_server"],
            "services": ["samba", "smbd"],
        }
    )
    data["environment"]["storage"] = {
        "population": "small",
        "servers": [
            {
                "system": "SAMBA-01",
                "presets": [],
                "volumes": [
                    {
                        "id": "data",
                        "mount": "/srv/samba/data",
                        "filesystem": "xfs",
                    }
                ],
                "shares": [
                    {
                        "id": "team",
                        "name": "Team",
                        "volume": "data",
                        "root": "Departments\\Team",
                        "access": {"modify": ["test_user"]},
                    }
                ],
            }
        ],
        "mappings": [
            {
                "id": "team-mount",
                "share": "SAMBA-01.team",
                "audience": {"users": ["test_user"], "systems": ["TEST-01"]},
                "credential_mode": "fixed",
                "principal": "test_user",
            }
        ],
    }
    return data


def _fixed_cross_server_mapping_data(scenarios_dir: Path) -> dict:
    """Return a cross-server copy whose two legs use distinct fixed credentials."""

    data = load_yaml(scenarios_dir / "smb-linux-matrix.yaml")
    data["environment"]["service_accounts"] = ["svc_source", "svc_destination"]
    data["environment"]["storage"]["mappings"] = [
        {
            "id": "source-fixed",
            "share": "FS-WIN-01.documents",
            "audience": {"users": ["linux_user"], "systems": ["LNX-CLIENT-01"]},
            "mount": "/mnt/source-fixed",
            "credential_mode": "fixed",
            "principal": "svc_source",
            "lifecycle": "persistent",
        },
        {
            "id": "destination-fixed",
            "share": "SAMBA-01.finance",
            "audience": {"users": ["linux_user"], "systems": ["LNX-CLIENT-01"]},
            "mount": "/mnt/destination-fixed",
            "credential_mode": "fixed",
            "principal": "svc_destination",
            "lifecycle": "persistent",
        },
    ]
    samba_share = data["environment"]["storage"]["servers"][0]["shares"][0]
    samba_share["access"] = {"modify": ["svc_destination"]}
    windows_share = data["environment"]["storage"]["servers"][1]["shares"][0]
    windows_share["access"] = {"read": ["svc_source"]}
    data["storyline"] = [
        event for event in data["storyline"] if event["id"] == "windows-to-linux-copy"
    ]
    data["storyline"][0]["events"][0]["mapping"] = "SOURCE-FIXED"
    return data


def test_omitted_storage_compiles_duration_independent_diverse_defaults(
    scenarios_dir: Path,
) -> None:
    data = _storage_scenario_data(scenarios_dir)
    first = StorageWorldModel.compile(Scenario(**data))
    extended = deepcopy(data)
    extended["time_window"] = {"start": "2024-01-15T10:00:00Z", "duration": "31d"}
    second = StorageWorldModel.compile(Scenario(**extended))

    refs = {share.ref for share in first.shares}
    assert {
        "FS-01.collaboration",
        "FS-01.homes",
        "FS-01.c_admin",
        "FS-01.admin",
        "FS-02.software",
        "DC-01.sysvol",
        "DC-01.netlogon",
    } <= refs
    assert any(volume.mount == "D:\\" for volume in first.volumes)
    assert any(volume.mount == "C:\\Mounts\\Data\\" for volume in first.volumes)
    assert first.manifest() == second.manifest()
    assert all("population_resolution" not in share for share in first.manifest()["shares"])
    assert first.share("FS-01.c_admin").files == ()
    assert "DC-01.backup" not in refs


def test_explicit_storage_resolves_mount_access_seed_and_mapping(scenarios_dir: Path) -> None:
    data = _storage_scenario_data(scenarios_dir)
    data["environment"]["storage"] = {
        "population": "small",
        "activity": "low",
        "servers": [
            {
                "system": "FS-01",
                "presets": [],
                "audit": "high",
                "default_volume": "data",
                "volumes": [
                    {"id": "data", "mount": "D:\\", "filesystem": "ntfs"},
                    {
                        "id": "archive",
                        "mount": "C:\\Mounts\\Archive\\",
                        "filesystem": "refs",
                    },
                ],
                "shares": [
                    {
                        "id": "finance",
                        "name": "Finance",
                        "volume": "data",
                        "root": "Departments\\Finance",
                        "preset": "department",
                        "activity": "high",
                        "access": {
                            "read": ["Finance-Readers"],
                            "modify": ["Finance-Users"],
                            "admin": ["Domain Admins"],
                            "deny": ["Contractors"],
                        },
                        "seed_files": [
                            {
                                "ref": "forecast",
                                "path": "Reports\\FY26\\forecast.xlsx",
                                "size_bytes": 1843200,
                                "tags": ["finance", "office"],
                            }
                        ],
                    }
                ],
            }
        ],
        "mappings": [
            {
                "id": "finance-p",
                "share": "FS-01.finance",
                "audience": {
                    "groups": ["Finance-Users"],
                    "systems": ["TEST-01"],
                },
                "drive": "P:",
                "lifecycle": "persistent",
            }
        ],
    }

    world = StorageWorldModel.compile(Scenario(**data))
    share = world.share("FS-01.finance")
    seed = world.select("FS-01.finance", file_ref="forecast")[0]
    mapping = world.mappings_by_id["finance-p"]

    assert world.server_local_path(share, seed.path) == (
        "D:\\Departments\\Finance\\Reports\\FY26\\forecast.xlsx"
    )
    assert world.unc_path(share, seed.path).startswith("\\\\FS-01\\Finance\\")
    assert "test_user" in mapping.users
    assert "Finance-Users" in share.access.modify
    assert "Finance-Users" in share.access.read
    assert share.audit == "high" and share.activity == "high"
    share_manifest = next(
        item for item in world.manifest()["shares"] if item["ref"] == "FS-01.finance"
    )
    mapping_manifest = next(
        item for item in world.manifest()["mappings"] if item["id"] == "finance-p"
    )
    assert {
        "provider": share_manifest["provider"],
        "platform": share_manifest["platform"],
        "network_root": share_manifest["network_root"],
        "server_native_root": share_manifest["server_native_root"],
        "backing_filesystem": share_manifest["backing_filesystem"],
        "advertised_filesystem": share_manifest["advertised_filesystem"],
        "case_policy": share_manifest["case_policy"],
        "audit_profile": share_manifest["audit_profile"],
    } == {
        "provider": "windows",
        "platform": "windows",
        "network_root": "\\\\FS-01\\Finance",
        "server_native_root": "D:\\Departments\\Finance",
        "backing_filesystem": "ntfs",
        "advertised_filesystem": "NTFS",
        "case_policy": "case_insensitive",
        "audit_profile": "high",
    }
    assert mapping_manifest["presentations"] == [
        {"platform": "windows", "type": "drive", "root": "P:"}
    ]


def test_linux_storage_compiles_posix_paths_mounts_and_manifest_v2(
    scenarios_dir: Path,
) -> None:
    world = StorageWorldModel.compile(Scenario(**_linux_storage_scenario_data(scenarios_dir)))
    volume = world.volumes_by_ref["samba-01.data"]
    share = world.share("SAMBA-01.team")
    mapping = world.mappings_by_id["team-mount"]
    manifest = world.manifest()
    share_manifest = next(item for item in manifest["shares"] if item["ref"] == "SAMBA-01.team")
    mapping_manifest = next(item for item in manifest["mappings"] if item["id"] == "team-mount")

    assert (volume.platform, volume.mount, volume.filesystem) == (
        "linux",
        "/srv/samba/data",
        "xfs",
    )
    assert world.server_local_path(share, "Reports\\status.docx") == (
        "/srv/samba/data/Departments/Team/Reports/status.docx"
    )
    assert share.smb_native_filesystem == "NTFS"
    assert {compiled.name for compiled in world.shares}.isdisjoint({"C$", "ADMIN$"})
    assert mapping.drive is None
    assert mapping.mount == "/mnt/team-mount"
    assert (mapping.credential_mode, mapping.principal) == ("fixed", "test_user")
    assert manifest["schema_version"] == 2
    assert manifest["volumes"][0]["platform"] == "linux"
    assert {
        key: share_manifest[key]
        for key in (
            "provider",
            "platform",
            "network_root",
            "server_native_root",
            "backing_filesystem",
            "advertised_filesystem",
            "case_policy",
            "audit_profile",
        )
    } == {
        "provider": "samba",
        "platform": "linux",
        "network_root": "\\\\SAMBA-01\\Team",
        "server_native_root": "/srv/samba/data/Departments/Team",
        "backing_filesystem": "xfs",
        "advertised_filesystem": "NTFS",
        "case_policy": "case_insensitive",
        "audit_profile": "standard",
    }
    assert share_manifest["smb_native_filesystem"] == "NTFS"
    assert mapping_manifest["mount"] == "/mnt/team-mount"
    assert mapping_manifest["audience"] == {
        "users": ["test_user"],
        "systems": ["TEST-01"],
    }
    assert mapping_manifest["presentations"] == [
        {"platform": "linux", "type": "mount", "root": "/mnt/team-mount"}
    ]


def test_manifest_mapping_audience_uses_total_case_insensitive_order() -> None:
    world = StorageWorldModel(
        volumes=(),
        shares=(),
        mappings=(
            CompiledStorageMapping(
                id="defensive-order",
                share="FS-01.shared",
                users=frozenset({"alice", "Alice", "bob"}),
                systems=frozenset({"client-01", "CLIENT-01", "CLIENT-02"}),
                lifecycle="persistent",
            ),
        ),
    )

    mapping = world.manifest()["mappings"][0]

    assert mapping["users"] == ["Alice", "alice", "bob"]
    assert mapping["systems"] == ["CLIENT-01", "client-01", "CLIENT-02"]
    assert mapping["audience"] == {
        "users": ["Alice", "alice", "bob"],
        "systems": ["CLIENT-01", "client-01", "CLIENT-02"],
    }


def test_storage_compiler_uses_overlay_advertised_filesystem_default(
    scenarios_dir: Path,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    overlay_dir = tmp_path / ".eforge" / "config" / "activity"
    overlay_dir.mkdir(parents=True)
    (overlay_dir / "smb_profiles.yaml").write_text(
        """
advertised_filesystem_defaults:
  linux:
    xfs: SAMBA
""",
        encoding="utf-8",
    )
    monkeypatch.chdir(tmp_path)
    reset_smb_profiles_cache()
    try:
        world = StorageWorldModel.compile(Scenario(**_linux_storage_scenario_data(scenarios_dir)))
        assert world.share("SAMBA-01.team").smb_native_filesystem == "SAMBA"
    finally:
        reset_smb_profiles_cache()


def test_linux_file_server_defaults_to_ext4_without_admin_shares(scenarios_dir: Path) -> None:
    data = _linux_storage_scenario_data(scenarios_dir)
    data["environment"]["storage"] = {"population": "small"}

    world = StorageWorldModel.compile(Scenario(**data))

    assert [(volume.mount, volume.filesystem) for volume in world.volumes] == [
        ("/srv/samba", "ext4")
    ]
    assert {share.ref for share in world.shares} == {
        "SAMBA-01.collaboration",
        "SAMBA-01.homes",
    }
    assert all(not share.name.endswith("$") for share in world.shares)


def test_generic_linux_file_server_role_does_not_auto_compile_samba_storage(
    scenarios_dir: Path,
) -> None:
    """Linux NFS/file-server intent must not silently become a Samba topology."""
    data = _linux_storage_scenario_data(scenarios_dir)
    linux_server = data["environment"]["systems"][-1]
    linux_server["services"] = ["nfs"]
    data["environment"]["storage"] = {"population": "small"}

    world = StorageWorldModel.compile(Scenario(**data))

    assert not [volume for volume in world.volumes if volume.system == "SAMBA-01"]
    assert not [share for share in world.shares if share.system == "SAMBA-01"]


@pytest.mark.parametrize("service", ["ksmbd", "samba-ad-dc"])
def test_linux_storage_rejects_unsupported_smb_server_provider(
    service: str,
    scenarios_dir: Path,
) -> None:
    data = _linux_storage_scenario_data(scenarios_dir)
    data["environment"]["systems"][-1]["services"] = [service]
    scenario = Scenario(**data)

    with pytest.raises(ValueError, match=service):
        StorageWorldModel.compile(scenario)

    errors = [
        issue
        for issue in ScenarioValidator(scenario).validate()
        if issue.severity == "error" and issue.field_path == "environment.storage"
    ]
    assert errors
    assert service in errors[0].message


def test_linux_storage_rejects_domain_controller_topology(scenarios_dir: Path) -> None:
    data = _linux_storage_scenario_data(scenarios_dir)
    samba_system = data["environment"]["systems"][-1]
    samba_system.update(
        {
            "type": "domain_controller",
            "roles": ["domain_controller"],
            "services": ["samba", "smbd"],
        }
    )
    scenario = Scenario(**data)

    with pytest.raises(ValueError, match="domain controller"):
        StorageWorldModel.compile(scenario)

    errors = [
        issue
        for issue in ScenarioValidator(scenario).validate()
        if issue.severity == "error" and issue.field_path == "environment.storage"
    ]
    assert errors
    assert "domain controller" in errors[0].message


@pytest.mark.parametrize("share_name", ["C$", "ADMIN$", "SYSVOL", "NETLOGON", "IPC$"])
def test_samba_storage_rejects_reserved_disk_share_names(
    share_name: str,
    scenarios_dir: Path,
) -> None:
    data = _linux_storage_scenario_data(scenarios_dir)
    data["environment"]["storage"]["servers"][0]["shares"][0]["name"] = share_name
    scenario = Scenario(**data)

    with pytest.raises(ValueError, match="IPC\\$|reserved name"):
        StorageWorldModel.compile(scenario)

    errors = [
        issue
        for issue in ScenarioValidator(scenario).validate()
        if issue.severity == "error" and issue.field_path == "environment.storage"
    ]
    assert errors
    assert share_name in errors[0].message


def test_windows_storage_rejects_ipc_named_pipe_as_disk_share(scenarios_dir: Path) -> None:
    data = _storage_scenario_data(scenarios_dir)
    data["environment"]["storage"] = {
        "servers": [
            {
                "system": "FS-01",
                "presets": [],
                "volumes": [{"id": "data", "mount": "D:\\", "filesystem": "ntfs"}],
                "shares": [{"id": "ipc", "name": "IPC$", "volume": "data"}],
            }
        ]
    }
    scenario = Scenario(**data)

    with pytest.raises(ValueError, match="IPC\\$"):
        StorageWorldModel.compile(scenario)

    errors = [
        issue
        for issue in ScenarioValidator(scenario).validate()
        if issue.severity == "error" and issue.field_path == "environment.storage"
    ]
    assert errors
    assert "IPC$" in errors[0].message


def test_manifest_v2_mapping_presentations_are_explicit_for_mixed_audience(
    scenarios_dir: Path,
) -> None:
    data = _linux_storage_scenario_data(scenarios_dir)
    data["environment"]["systems"].append(
        {
            "hostname": "WIN-01",
            "ip": "10.0.0.21",
            "os": "Windows 11",
            "type": "workstation",
        }
    )
    mapping = data["environment"]["storage"]["mappings"][0]
    mapping["audience"]["systems"] = ["TEST-01", "WIN-01"]

    world = StorageWorldModel.compile(Scenario(**data))
    mapping_manifest = world.manifest()["mappings"][0]

    assert mapping_manifest["drive"] is not None
    assert mapping_manifest["mount"] == "/mnt/team-mount"
    assert mapping_manifest["presentations"] == [
        {"platform": "windows", "type": "drive", "root": mapping_manifest["drive"]},
        {"platform": "linux", "type": "mount", "root": "/mnt/team-mount"},
    ]


def test_storage_validator_enforces_server_and_client_platform_rules(
    scenarios_dir: Path,
) -> None:
    data = _linux_storage_scenario_data(scenarios_dir)
    data["environment"]["storage"]["servers"][0]["volumes"][0]["filesystem"] = "ntfs"
    data["storyline"] = [
        {
            "id": "wrong-client-mode",
            "time": "+10m",
            "actor": "test_user",
            "system": "TEST-01",
            "activity": "Use a Windows drive presentation on Linux",
            "events": [
                {
                    "type": "smb_activity",
                    "operation": "read",
                    "target": {"type": "share", "share": "SAMBA-01.team"},
                    "path_style": "mapped",
                    "client_access": "windows_native",
                }
            ],
        }
    ]

    issues = ScenarioValidator(Scenario(**data)).validate()
    errors = [issue for issue in issues if issue.severity == "error"]

    assert any(issue.field_path.endswith(".filesystem") for issue in errors)
    # Compilation fails fast on the invalid backing filesystem, so validate client rules
    # independently with the server repaired.
    data["environment"]["storage"]["servers"][0]["volumes"][0]["filesystem"] = "xfs"
    errors = [
        issue
        for issue in ScenarioValidator(Scenario(**data)).validate()
        if issue.severity == "error"
    ]
    assert any("only valid on Windows clients" in issue.message for issue in errors)
    assert any("requires a Windows client" in issue.message for issue in errors)


def test_storage_validator_requires_mount_mapping_for_explicit_cifs_access(
    scenarios_dir: Path,
) -> None:
    """Explicit CIFS mount semantics require a concrete client mount presentation."""

    data = _linux_storage_scenario_data(scenarios_dir)
    data["environment"]["storage"]["mappings"] = []
    data["storyline"] = [
        {
            "id": "missing-cifs-mount",
            "time": "+10m",
            "actor": "test_user",
            "system": "TEST-01",
            "activity": "Attempt mounted access without a mounted mapping",
            "events": [
                {
                    "type": "smb_activity",
                    "operation": "read",
                    "target": {"type": "share", "share": "SAMBA-01.team"},
                    "client_access": "cifs_mount",
                }
            ],
        }
    ]

    errors = [
        issue
        for issue in ScenarioValidator(Scenario(**data)).validate()
        if issue.severity == "error"
    ]

    assert any(
        issue.field_path.endswith(".client_access")
        and "exactly one active Linux mount mapping" in issue.message
        for issue in errors
    )


def test_storage_validator_resolves_cross_server_fixed_credentials_per_share(
    scenarios_dir: Path,
) -> None:
    """Each transfer leg should use its own mapping, including casefolded explicit IDs."""

    data = _fixed_cross_server_mapping_data(scenarios_dir)

    errors = [
        issue
        for issue in ScenarioValidator(Scenario(**data)).validate()
        if issue.severity == "error"
    ]

    assert errors == []


def test_storage_validator_rejects_cross_server_fixed_credential_acl_mismatch(
    scenarios_dir: Path,
) -> None:
    """A success assertion must be feasible under the destination leg's fixed credential."""

    data = _fixed_cross_server_mapping_data(scenarios_dir)
    samba_share = data["environment"]["storage"]["servers"][0]["shares"][0]
    samba_share["access"] = {"modify": ["linux_user"]}

    errors = [
        issue
        for issue in ScenarioValidator(Scenario(**data)).validate()
        if issue.severity == "error"
    ]

    assert any(
        issue.field_path.endswith(".outcome")
        and "SAMBA-01.finance" in issue.message
        and "svc_destination" in issue.message
        for issue in errors
    )


def test_storage_validator_rejects_principal_conflict_on_auto_resolved_transfer_leg(
    scenarios_dir: Path,
) -> None:
    """An explicit principal cannot override a fixed mapping selected on another leg."""

    data = _fixed_cross_server_mapping_data(scenarios_dir)
    data["storyline"][0]["events"][0]["smb_principal"] = "svc_source"

    errors = [
        issue
        for issue in ScenarioValidator(Scenario(**data)).validate()
        if issue.severity == "error"
    ]

    assert any(
        issue.field_path.endswith(".smb_principal")
        and "destination-fixed" in issue.message
        and "svc_destination" in issue.message
        for issue in errors
    )


def test_storage_validator_rejects_local_builtin_samba_principals(
    scenarios_dir: Path,
) -> None:
    """Domain-member Samba accepts only declared directory-backed identities."""

    data = _linux_storage_scenario_data(scenarios_dir)
    data["environment"]["storage"]["mappings"][0]["principal"] = "root"
    mapping_errors = [
        issue
        for issue in ScenarioValidator(Scenario(**data)).validate()
        if issue.severity == "error"
    ]
    assert any(
        issue.field_path.endswith(".principal") and "not a declared directory user" in issue.message
        for issue in mapping_errors
    )

    data["environment"]["storage"]["mappings"] = []
    data["storyline"] = [
        {
            "id": "local-samba-principal",
            "time": "+10m",
            "actor": "test_user",
            "system": "TEST-01",
            "activity": "Attempt a local Samba identity",
            "events": [
                {
                    "type": "smb_activity",
                    "operation": "read",
                    "target": {"type": "share", "share": "SAMBA-01.team"},
                    "outcome": "access_denied",
                    "client_access": "smbclient",
                    "smb_principal": "root",
                }
            ],
        }
    ]
    event_errors = [
        issue
        for issue in ScenarioValidator(Scenario(**data)).validate()
        if issue.severity == "error"
    ]
    assert any(
        issue.field_path.endswith(".smb_principal")
        and "not a declared directory user" in issue.message
        for issue in event_errors
    )


def test_administrative_shares_use_implicit_ntfs_system_volume(scenarios_dir: Path) -> None:
    data = _storage_scenario_data(scenarios_dir)
    data["environment"]["storage"] = {
        "servers": [
            {
                "system": "FS-01",
                "presets": [],
                "default_volume": "data",
                "volumes": [
                    {
                        "id": "data",
                        "mount": "D:\\",
                        "filesystem": "refs",
                    }
                ],
                "shares": [
                    {
                        "id": "department",
                        "name": "Department",
                        "volume": "data",
                        "root": "Department",
                        "preset": "department",
                    }
                ],
            }
        ]
    }

    world = StorageWorldModel.compile(Scenario(**data))
    c_admin = world.share("FS-01.c_admin")
    admin = world.share("FS-01.admin")
    department = world.share("FS-01.department")
    system_volume = world.volumes_by_ref[f"FS-01.{c_admin.volume}".casefold()]

    assert admin.volume == c_admin.volume
    assert system_volume.mount == "C:\\"
    assert system_volume.filesystem == "ntfs"
    assert world.server_local_path(c_admin, "Windows\\Temp\\sample.txt") == (
        "C:\\Windows\\Temp\\sample.txt"
    )
    assert world.server_local_path(admin, "Temp\\sample.txt") == ("C:\\Windows\\Temp\\sample.txt")
    assert department.volume == "data"
    assert world.volumes_by_ref["fs-01.data"].filesystem == "refs"
    assert department.smb_native_filesystem == "ReFS"


@pytest.mark.parametrize(
    ("population", "requested_count"),
    [("auto", 64), ("medium", 96), ("large", 384)],
)
def test_tiny_storage_vocabulary_caps_population_to_unique_product(
    scenarios_dir: Path,
    monkeypatch: pytest.MonkeyPatch,
    population: str,
    requested_count: int,
) -> None:
    data = _storage_scenario_data(scenarios_dir)
    data["environment"]["systems"] = [
        system
        for system in data["environment"]["systems"]
        if system["hostname"] in {"TEST-01", "FS-01"}
    ]
    data["environment"]["storage"] = {
        "population": population,
        "servers": [
            {
                "system": "FS-01",
                "presets": [],
                "volumes": [{"id": "data", "mount": "D:\\"}],
                "shares": [
                    {
                        "id": "records",
                        "name": "Records",
                        "volume": "data",
                        "preset": "tiny:records",
                    }
                ],
            }
        ],
    }
    monkeypatch.setattr(
        storage_world_module,
        "_load_catalog_config",
        lambda: {
            "population_counts": {
                "small": 24,
                "medium": 96,
                "large": 384,
                "auto": {},
            },
            "profiles": {
                "tiny:records": {
                    "directories": ["Records"],
                    "subjects": ["Case"],
                    "files": [
                        {
                            "extension": ".pdf",
                            "mime": "application/pdf",
                            "weight": 1,
                        }
                    ],
                }
            },
        },
    )

    world = StorageWorldModel.compile(Scenario(**data))
    share = world.share("FS-01.records")
    share_manifest = next(
        item for item in world.manifest()["shares"] if item["ref"] == "FS-01.records"
    )

    assert len(share.files) == 36
    assert len({file.path.casefold() for file in share.files}) == 36
    assert "Records\\Case.pdf" in {file.path for file in share.files}
    assert share_manifest["population_resolution"] == {
        "requested_file_count": requested_count,
        "effective_file_count": 36,
        "realizable_file_count": 36,
        "capped": True,
    }


@pytest.mark.parametrize("drive", ["D:", "F:", "Z:", "d:"])
def test_explicit_storage_mapping_accepts_d_through_z(drive: str) -> None:
    mapping = StorageMappingConfig.model_validate(
        {"id": "department-drive", "share": "FS-01.department", "drive": drive}
    )

    assert mapping.drive == drive.upper()


@pytest.mark.parametrize("drive", ["A:", "B:", "C:", "AA:", "H", "1:"])
def test_storage_mapping_rejects_reserved_system_and_malformed_drives(drive: str) -> None:
    with pytest.raises(ValidationError, match="D: through Z:"):
        StorageMappingConfig.model_validate(
            {"id": "department-drive", "share": "FS-01.department", "drive": drive}
        )


def test_automatic_storage_mapping_remains_h_through_z(scenarios_dir: Path) -> None:
    data = _storage_scenario_data(scenarios_dir)
    data["environment"]["storage"] = {
        "servers": [{"system": "FS-01", "presets": ["collaboration"]}],
        "mappings": [
            {
                "id": "automatic-drive",
                "share": "FS-01.collaboration",
                "audience": {"users": ["test_user"]},
            }
        ],
    }

    mapping = StorageWorldModel.compile(Scenario(**data)).mappings_by_id["automatic-drive"]

    assert "H:" <= mapping.drive <= "Z:"


@pytest.mark.parametrize("global_first", [True, False])
def test_storage_mapping_drive_collision_detects_global_specific_audience_overlap(
    scenarios_dir: Path,
    global_first: bool,
) -> None:
    data = _storage_scenario_data(scenarios_dir)
    global_mapping = {
        "id": "global-drive",
        "share": "FS-01.collaboration",
        "drive": "P:",
    }
    specific_mapping = {
        "id": "specific-drive",
        "share": "FS-01.homes",
        "audience": {"users": ["test_user"], "systems": ["TEST-01"]},
        "drive": "P:",
    }
    data["environment"]["storage"] = {
        "mappings": (
            [global_mapping, specific_mapping]
            if global_first
            else [specific_mapping, global_mapping]
        )
    }

    with pytest.raises(ValueError, match="storage mapping drive collision.*P:"):
        StorageWorldModel.compile(Scenario(**data))


def test_automatic_storage_mapping_avoids_global_drive_overlap(scenarios_dir: Path) -> None:
    probe_data = _storage_scenario_data(scenarios_dir)
    automatic_mapping = {
        "id": "specific-automatic-drive",
        "share": "FS-01.homes",
        "audience": {"users": ["test_user"], "systems": ["TEST-01"]},
    }
    probe_data["environment"]["storage"] = {"mappings": [automatic_mapping]}
    initial_drive = (
        StorageWorldModel.compile(Scenario(**probe_data))
        .mappings_by_id["specific-automatic-drive"]
        .drive
    )
    assert initial_drive is not None

    data = _storage_scenario_data(scenarios_dir)
    data["environment"]["storage"] = {
        "mappings": [
            {
                "id": "global-explicit-drive",
                "share": "FS-01.collaboration",
                "drive": initial_drive,
            },
            automatic_mapping,
        ]
    }

    mapping = StorageWorldModel.compile(Scenario(**data)).mappings_by_id["specific-automatic-drive"]

    assert mapping.drive is not None
    assert mapping.drive != initial_drive


@pytest.mark.parametrize("global_first", [True, False])
def test_storage_mapping_mount_collision_detects_global_specific_audience_overlap(
    scenarios_dir: Path,
    global_first: bool,
) -> None:
    data = _linux_storage_scenario_data(scenarios_dir)
    storage = data["environment"]["storage"]
    storage["servers"][0]["shares"].append(
        {
            "id": "archive",
            "name": "Archive",
            "volume": "data",
            "root": "Archive",
        }
    )
    global_mapping = {
        "id": "global-mount",
        "share": "SAMBA-01.team",
        "mount": "/mnt/shared",
    }
    specific_mapping = {
        "id": "specific-mount",
        "share": "SAMBA-01.archive",
        "audience": {"users": ["test_user"], "systems": ["TEST-01"]},
        "mount": "/mnt/shared",
    }
    storage["mappings"] = (
        [global_mapping, specific_mapping] if global_first else [specific_mapping, global_mapping]
    )

    with pytest.raises(ValueError, match="storage mapping mount collision.*/mnt/shared"):
        StorageWorldModel.compile(Scenario(**data))


@pytest.mark.parametrize(
    "path",
    [
        "..\\secret.txt",
        "C:\\absolute.txt",
        "Reports\\file.txt:stream",
        "CON.txt",
    ],
)
def test_smb_share_paths_reject_unsafe_windows_forms(path: str) -> None:
    with pytest.raises(ValidationError):
        SmbActivityEventSpec.model_validate(
            {
                "type": "smb_activity",
                "operation": "read",
                "target": {"type": "share", "share": "FS-01.finance", "path": path},
            }
        )


def test_smb_validator_checks_external_parent_and_deduplicates_migration_warning(
    scenarios_dir: Path,
) -> None:
    data = _storage_scenario_data(scenarios_dir)
    data["storyline"] = [
        {
            "id": "legacy-and-external",
            "time": "+10m",
            "actor": "test_user",
            "system": "TEST-01",
            "activity": "SMB migration cases",
            "events": [
                {
                    "type": "connection",
                    "dst_ip": "10.0.0.20",
                    "dst_port": 445,
                    "service": "smb",
                    "orig_bytes": 40000,
                },
                {
                    "type": "connection",
                    "dst_ip": "10.0.0.20",
                    "dst_port": 445,
                    "service": "smb",
                    "resp_bytes": 80000,
                },
                {
                    "type": "connection",
                    "dst_ip": "10.0.0.20",
                    "dst_port": 445,
                    "service": "smb",
                    "conn_state": "S0",
                },
                {
                    "type": "smb_activity",
                    "client": {"type": "external", "ip": "203.0.113.42"},
                    "operation": "read",
                    "target": {"type": "share", "share": "FS-01.collaboration"},
                },
            ],
        }
    ]

    issues = ScenarioValidator(Scenario(**data)).validate()
    warnings = [
        issue for issue in issues if issue.severity == "warning" and issue.field_path == "storyline"
    ]
    external_errors = [
        issue
        for issue in issues
        if issue.severity == "error" and issue.field_path.endswith(".client")
    ]

    assert len(warnings) == 1
    assert "2 successful SMB connection event(s)" in warnings[0].message
    assert len(external_errors) == 1
    assert "parent storyline system" in external_errors[0].message
