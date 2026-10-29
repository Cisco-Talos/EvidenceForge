# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Invented Mac workstation and Linux SSH receiver for correlation gates."""

from pathlib import Path

from evidenceforge.models.scenario import Scenario
from evidenceforge.utils import load_yaml

MACOS_NATIVE_QUERY_COMMANDS: tuple[str, ...] = (
    "/usr/bin/id",
    "/usr/bin/sw_vers",
    "/usr/bin/uname -a",
    "/sbin/ifconfig -a",
    "/bin/ps aux",
    "/usr/bin/dscl . -list /Users",
    "/bin/pwd",
    "/bin/ls -la /Users/test_user/Documents",
    "/usr/bin/du -sh /Users/test_user/Documents",
    "/bin/df -h",
    '/usr/bin/find /Users/test_user/Documents -maxdepth 2 -type f -name "*.pdf"',
)


def macos_ssh_scenario(
    scenarios_dir: Path, *, macos_receiver: bool = False, authored_close: bool = False
) -> Scenario:
    """Build existing authored intent without new platform configuration fields."""
    data = load_yaml(scenarios_dir / "minimal.yaml")
    data["generation_seed"] = 99
    # These fixtures qualify individual native phases. Terminal/service aggregate
    # starts remain in the independent census and do not assert total coverage.
    data["macos_process_coverage"] = "partial"
    data["time_window"] = {"start": "2026-10-15T10:00:00Z", "duration": "1h", "warmup": "1h"}
    data["environment"]["users"][0]["primary_system"] = "TEST-01"
    data["environment"]["systems"][0].update(
        os="macOS 27",
        architecture="arm64",
        services=[],
        roles=["workstation"],
        assigned_user="test_user",
    )
    data["environment"]["systems"].append(
        {
            "hostname": "SSH-TEST",
            "ip": "10.0.0.20",
            "os": "Ubuntu 24.04",
            "type": "server",
            "roles": [],
            "services": ["ssh"],
        }
    )
    data["environment"]["network"]["segments"][0]["systems"].append("SSH-TEST")
    data["storyline"] = [
        {
            "id": "mac-login",
            "time": "+1m",
            "actor": "test_user",
            "system": "TEST-01",
            "activity": "Start the local interactive Mac session",
            "events": [{"type": "logon", "logon_type": 2}],
        },
        {
            "id": "remote-session",
            "time": "+10m",
            "actor": "test_user",
            "system": "SSH-TEST",
            "activity": "Connect from the Mac workstation to the Linux receiver",
            "events": [
                {"type": "ssh_session", "source_ip": data["environment"]["systems"][0]["ip"]}
            ],
        },
    ]
    data["output"]["logs"] = [
        {"format": name} for name in ("ecar", "zeek", "syslog", "zsh_history")
    ]
    if macos_receiver:
        data["environment"]["systems"][1].update(
            os="macOS 27", architecture="arm64", type="workstation", assigned_user="test_user"
        )
        data["storyline"][1]["activity"] = "Connect between modeled Mac workstations"
        data["output"]["logs"] = [
            row for row in data["output"]["logs"] if row["format"] != "syslog"
        ]
    if authored_close:
        if not macos_receiver:
            raise ValueError("Authored Mac receiver close requires a Mac receiver")
        data["storyline"].append(
            {
                "id": "remote-close",
                "time": "+30m",
                "actor": "test_user",
                "system": "SSH-TEST",
                "activity": "Close the remote session at its authored deadline",
                "events": [{"type": "logoff"}],
            }
        )
    return Scenario.model_validate(data)
