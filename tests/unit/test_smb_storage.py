# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Canonical SMB storage topology and authoring tests."""

from copy import deepcopy
from pathlib import Path

import pytest
from pydantic import ValidationError

import evidenceforge.generation.storage_world as storage_world_module
from evidenceforge.generation.storage_world import StorageWorldModel
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
