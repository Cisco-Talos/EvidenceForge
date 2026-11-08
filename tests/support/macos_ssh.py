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
    # Legacy compatibility diagnostics retain partial coverage; public CLI acceptance
    # separately exercises complete client and receiver startup with the current profile.
    # Client-to-Linux acceptance can explicitly request complete Mac coverage.
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


def assert_native_ssh_receiver_lifecycle(
    rows: list[dict], *, closed: bool, sessions: int = 1
) -> None:
    """Require each qualified six-process receiver graph and its exact close set."""
    executions = [row for row in rows if row["event_type"] == 9]
    wrappers = [
        row
        for row in executions
        if row["event"]["exec"]["target"]["executable"]["path"]
        == "/usr/libexec/sshd-keygen-wrapper"
    ]
    assert len(wrappers) == sessions
    forks = [row for row in rows if row["event_type"] == 11]
    checked: set[int] = set()
    for wrapper in wrappers:
        main = wrapper["event"]["exec"]["target"]["audit_token"]["pid"]
        family = {main}
        for _ in range(len(forks)):
            family.update(
                row["event"]["fork"]["child"]["audit_token"]["pid"]
                for row in forks
                if row["process"]["audit_token"]["pid"] in family
            )
        assert not checked.intersection(family)
        checked.update(family)
        births = [
            row for row in forks if row["event"]["fork"]["child"]["audit_token"]["pid"] in family
        ]
        assert len(family) == len(births) == 6
        assert len({row["event"]["fork"]["child"]["audit_token"]["pid"] for row in births}) == 6
        by_image = {
            image: [
                row
                for row in executions
                if row["event"]["exec"]["target"]["executable"]["path"] == image
                and row["event"]["exec"]["target"]["audit_token"]["pid"] in family
            ]
            for image in (
                "/usr/libexec/sshd-keygen-wrapper",
                "/usr/sbin/sshd",
                "/usr/libexec/sshd-session",
                "/usr/libexec/sshd-auth",
                "/bin/zsh",
            )
        }
        assert all(len(matches) == 1 for matches in by_image.values())
        assert all(
            by_image[image][0]["event"]["exec"]["target"]["audit_token"]["pid"] == main
            for image in (
                "/usr/libexec/sshd-keygen-wrapper",
                "/usr/sbin/sshd",
                "/usr/libexec/sshd-session",
            )
        )
        for image in ("/usr/libexec/sshd-auth", "/bin/zsh"):
            execution = by_image[image][0]
            pid = execution["event"]["exec"]["target"]["audit_token"]["pid"]
            birth = next(
                row for row in births if row["event"]["fork"]["child"]["audit_token"]["pid"] == pid
            )
            assert birth["global_seq_num"] < execution["global_seq_num"]
        exits = [
            row
            for row in rows
            if row["event_type"] == 15 and row["process"]["audit_token"]["pid"] in family
        ]
        assert len(exits) == (6 if closed else 3)
        assert len({row["process"]["audit_token"]["pid"] for row in exits}) == len(exits)
        for end in exits:
            pid = end["process"]["audit_token"]["pid"]
            previous = [
                row
                for row in executions
                if row["event"]["exec"]["target"]["audit_token"]["pid"] == pid
            ]
            assert all(row["global_seq_num"] < end["global_seq_num"] for row in previous)
            if previous:
                # Credential transitions may follow exec without replacing its image.
                target = previous[-1]["event"]["exec"]["target"]
                assert (
                    target["audit_token"]["pidversion"]
                    == end["process"]["audit_token"]["pidversion"]
                )
                assert target["executable"] == end["process"]["executable"]
    for event_type in {row["event_type"] for row in rows}:
        sequences = [row["seq_num"] for row in rows if row["event_type"] == event_type]
        assert sequences == list(range(sequences[0], sequences[0] + len(sequences)))
