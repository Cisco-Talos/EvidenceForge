# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Independently authored Mac client and Windows/Samba server intent."""

from pathlib import Path

from evidenceforge.models.scenario import Scenario
from evidenceforge.utils import load_yaml


def macos_smb_scenario(scenarios_dir: Path, *, server_platform: str = "windows") -> Scenario:
    """Build a bounded mounted read without requiring an external SMB server."""
    data = load_yaml(scenarios_dir / "minimal.yaml")
    data["generation_seed"] = 99
    data["time_window"] = {"start": "2026-10-15T10:00:00Z", "duration": "20m"}
    data["environment"]["users"][0]["primary_system"] = "TEST-01"
    data["environment"]["systems"][0].update(
        {
            "os": "macOS 26",
            "architecture": "arm64",
            "services": ["smb-client"],
            "roles": ["workstation"],
            "assigned_user": "test_user",
        }
    )
    linux_server = server_platform == "linux"
    data["environment"]["systems"].append(
        {
            "hostname": "FS-TEST",
            "ip": "10.0.0.20",
            "os": "Ubuntu Server 24.04" if linux_server else "Windows Server 2022",
            "type": "server",
            "roles": [],
            "services": ["samba", "smbd"] if linux_server else ["smb"],
        }
    )
    data["environment"]["network"]["segments"][0]["systems"].append("FS-TEST")
    data["environment"]["storage"] = {
        "population": "small",
        "servers": [
            {
                "system": "FS-TEST",
                "presets": [],
                "volumes": [
                    {
                        "id": "data",
                        "mount": "/srv/team" if linux_server else "D:\\",
                        "filesystem": "xfs" if linux_server else "ntfs",
                    }
                ],
                "shares": [
                    {
                        "id": "team",
                        "name": "Team",
                        "volume": "data",
                        "root": "Team",
                        "access": {"modify": ["test_user"]},
                        "seed_files": [
                            {"ref": "plan", "path": "Reports\\plan.txt", "size_bytes": 4096}
                        ],
                    }
                ],
            }
        ],
        "mappings": [
            {
                "id": "team",
                "share": "FS-TEST.team",
                "audience": {"users": ["test_user"], "systems": ["TEST-01"]},
                "lifecycle": "persistent",
            }
        ],
    }
    data["storyline"] = [
        {
            "id": "mounted-read",
            "time": "+10m",
            "actor": "test_user",
            "system": "TEST-01",
            "activity": "Read a shared plan using a Mac workstation",
            "events": [
                {
                    "type": "smb_activity",
                    "operation": "read",
                    "target": {"type": "share", "share": "FS-TEST.team", "file_ref": "plan"},
                    "mapping": "team",
                    "path_style": "mounted",
                }
            ],
        }
    ]
    data["output"]["logs"] = [
        {"format": name} for name in ("ecar", "zeek", "syslog" if linux_server else "windows")
    ]
    return Scenario.model_validate(data)
