# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT
"""Known Windows policy shares compile purpose-specific automatic file paths."""

from pathlib import Path
from typing import Any
from uuid import UUID

from evidenceforge.generation.storage_world import StorageWorldModel
from evidenceforge.models.scenario import Scenario
from evidenceforge.utils import load_yaml


def policy_scenario(scenarios_dir: Path) -> Scenario:
    data: dict[str, Any] = load_yaml(scenarios_dir / "minimal.yaml")
    data["environment"]["domain"] = "research.example.test"
    for index in range(2):
        hostname = f"DC-{index + 1}"
        data["environment"]["systems"].append(
            {
                "hostname": hostname,
                "ip": f"10.0.0.{20 + index}",
                "os": "Windows Server 2022",
                "type": "domain_controller",
                "roles": ["domain_controller"],
            }
        )
        data["environment"]["network"]["segments"][0]["systems"].append(hostname)
    return Scenario.model_validate(data)


def test_automatic_policy_shares_use_domain_gpo_and_script_repository_roles(
    scenarios_dir: Path,
) -> None:
    world = StorageWorldModel.compile(policy_scenario(scenarios_dir))
    policy = world.share("DC-1.sysvol")
    logon = world.share("DC-1.netlogon")
    assert policy.root.casefold() == "sysvol\\sysvol"
    assert logon.root.casefold() == "sysvol\\sysvol\\research.example.test\\scripts"
    assert policy.files and logon.files
    for file in policy.files:
        domain, directory, policy_id, *relative = file.path.split("\\")
        assert domain == "research.example.test" and directory.casefold() == "policies"
        assert policy_id.startswith("{") and policy_id.endswith("}")
        UUID(policy_id.strip("{}"))
        assert relative
    assert any(file.path.endswith("\\GPT.INI") for file in policy.files)
    assert all(file.extension in {".ps1", ".cmd", ".bat", ".vbs"} for file in logon.files)


def test_replica_paths_and_initial_metadata_are_domain_scoped(scenarios_dir: Path) -> None:
    scenario = policy_scenario(scenarios_dir)
    world = StorageWorldModel.compile(scenario)
    for role in ("sysvol", "netlogon"):
        first, second = world.share(f"DC-1.{role}"), world.share(f"DC-2.{role}")
        assert [(f.path, f.size_bytes, f.mime_type) for f in first.files] == [
            (f.path, f.size_bytes, f.mime_type) for f in second.files
        ]
        # Separate DC filesystem objects remain separate; this is not a DFSR simulator.
        assert {f.file_id for f in first.files}.isdisjoint(f.file_id for f in second.files)
    assert world.manifest() == StorageWorldModel.compile(scenario).manifest()


def test_explicit_root_and_oversized_seed_remain_authoritative(scenarios_dir: Path) -> None:
    data = policy_scenario(scenarios_dir).model_dump()
    data["environment"]["storage"]["servers"] = [
        {
            "system": "DC-1",
            "presets": [],
            "volumes": [{"id": "system", "mount": "C:\\Windows\\", "filesystem": "ntfs"}],
            "shares": [
                {
                    "id": "sysvol",
                    "name": "SYSVOL",
                    "volume": "system",
                    "root": "CustomPolicies",
                    "preset": "dc_policy",
                    "seed_files": [
                        {"ref": "custom", "path": "Custom\\manual.ini", "size_bytes": 16777216}
                    ],
                }
            ],
        }
    ]
    world = StorageWorldModel.compile(Scenario.model_validate(data))
    share = world.share("DC-1.sysvol")
    assert share.root == "CustomPolicies"
    seed = world.select(share.ref, file_ref="custom")
    assert (
        len(seed) == 1 and seed[0].path == "Custom\\manual.ini" and seed[0].size_bytes == 16777216
    )
    assert len({f.path.casefold() for f in share.files}) == len(share.files)


def test_unknown_domain_and_custom_purpose_keep_generic_catalogs(scenarios_dir: Path) -> None:
    data = policy_scenario(scenarios_dir).model_dump()
    data["environment"]["domain"] = None
    legacy = StorageWorldModel.compile(Scenario.model_validate(data))
    assert legacy.share("DC-1.sysvol").root == "SYSVOL"
    assert all("\\Policies\\{" not in f.path for f in legacy.share("DC-1.sysvol").files)
    data = policy_scenario(scenarios_dir).model_dump()
    data["environment"]["storage"]["servers"] = [
        {
            "system": "DC-1",
            "presets": [],
            "volumes": [{"id": "data", "mount": "D:\\"}],
            "shares": [
                {
                    "id": "custom",
                    "name": "Policies",
                    "volume": "data",
                    "root": "Policies",
                    "preset": "dc_policy",
                }
            ],
        }
    ]
    world = StorageWorldModel.compile(Scenario.model_validate(data))
    assert all("\\Policies\\{" not in f.path for f in world.share("DC-1.custom").files)
