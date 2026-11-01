# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Complete native client and receiver coverage survives filtering and recovery."""

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

from evidenceforge.formats.macos_endpoint_security import decode_endpoint_security_record
from tests.support.macos_ssh import macos_ssh_scenario


@pytest.mark.slow
@pytest.mark.parametrize("macos_receiver,pty", [(False, False), (True, False), (True, True)])
@pytest.mark.parametrize("terminal_id", ["macos-terminal", "macos-iterm2"])
def test_complete_ssh_client_cli_matches_native_metadata_and_filtered_bytes(
    tmp_path: Path,
    scenarios_dir: Path,
    terminal_id: str,
    macos_receiver: bool,
    pty: bool,
) -> None:
    raw = macos_ssh_scenario(scenarios_dir, macos_receiver=macos_receiver).model_dump(
        mode="json", exclude_none=True
    )
    raw["time_window"]["duration"] = "15m"
    if pty:
        raw["storyline"][1]["events"][0]["pty"] = True
        raw["storyline"].append(
            {
                "id": "pty-query",
                "time": "+12m",
                "actor": "test_user",
                "system": "SSH-TEST",
                "activity": "Run one literal query from the remote PTY shell",
                "events": [
                    {
                        "type": "process",
                        "process_name": "/usr/bin/id",
                        "command_line": "/usr/bin/id",
                        "supplementary": "none",
                    }
                ],
            }
        )
    raw["macos_process_coverage"] = "complete"
    raw["baseline_activity"]["traffic_rates"] = {"user_activity": 1, "persona_connections": 1}
    raw["environment"]["deployment_overrides"] = [
        {
            "system": "TEST-01",
            "user_applications": [{"user": "test_user", "applications": [terminal_id]}],
        }
    ]
    raw["output"]["logs"] = [
        {"format": name} for name in ("ecar", "zeek", "macos_endpoint_security")
    ]
    source = tmp_path / "ssh-client.yaml"
    source.write_text(yaml.safe_dump(raw, sort_keys=False))
    snapshots = []
    for label, seed, formats in (("full", "37", None), ("native", "83", "macos_endpoint_security")):
        output = tmp_path / label
        command = [
            sys.executable,
            "-m",
            "evidenceforge",
            "generate",
            str(source),
            "--output",
            str(output),
            "--seed",
            "366",
            "--checkpoint-hours",
            "0",
            "--project-root",
            str(tmp_path),
        ]
        if formats:
            command.extend(["--formats", formats])
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            env=os.environ | {"PYTHONHASHSEED": seed},
            timeout=120,
            check=False,
        )
        assert result.returncode == 0, result.stdout + result.stderr
        paths = sorted((output / "data").rglob("macos_endpoint_security.ndjson"))
        snapshots.append({str(path.relative_to(output)): path.read_bytes() for path in paths})
        records = [
            decode_endpoint_security_record(line)
            for path in paths
            for line in path.read_text().splitlines()
        ]
        clients = [
            record
            for record in records
            if record.event_type == 9 and record.event.exec.target.executable.path == "/usr/bin/ssh"
        ]
        assert clients
        if pty:
            assert any("-tt" in record.event.exec.args for record in clients)
        for record in clients:
            wire = json.loads(record.to_ndjson())
            payload = wire["event"]["exec"]
            target = payload["target"]
            assert payload["entitlements"] == {
                "keychain-access-groups": ["com.apple.ssh.passphrases"],
                "com.apple.private.amfi.version-restriction": 1,
            }
            assert (
                type(payload["entitlements"]["com.apple.private.amfi.version-restriction"]) is int
            )
            assert target["codesigning_flags"] == 0x26015B11
            assert target["cs_validation_category"] == 1 and target["is_platform_binary"]
            assert payload["image_cpusubtype"] == -2147483646
            assert payload["fds"] == [{"fd": i, "fdtype": 1} for i in range(3)]
            assert target["tty"] is not None
            assert payload["args"][0] == "/usr/bin/ssh"
        truth = json.loads((output / "GROUND_TRUTH.json").read_text())
        hosts = truth["macos_native_coverage"]["hosts"]
        assert len(hosts) == (2 if macos_receiver else 1)
        for host in hosts:
            census = host["process_census"]
            assert census["complete"] and census["aggregate_births"] == 0
            assert census["expected_execs"] == census["published_execs"]
            assert census["expected_forks"] == census["published_forks"]
        if macos_receiver:
            receiver_rows = [
                json.loads(line)
                for path in paths
                if "SSH-TEST." in str(path)
                for line in path.read_text().splitlines()
            ]
            workers = [
                row["event"]["exec"]["target"]
                for row in receiver_rows
                if row["event_type"] == 9
                and row["event"]["exec"]["target"]["executable"]["path"]
                == "/usr/libexec/sshd-session"
                and row["event"]["exec"]["target"]["ppid"] == 1
            ]
            assert workers
            if pty:
                queries = [
                    row["event"]["exec"]
                    for row in receiver_rows
                    if row["event_type"] == 9
                    and row["event"]["exec"]["target"]["executable"]["path"] == "/usr/bin/id"
                ]
                assert queries
                for query in queries:
                    process = query["target"]
                    assert process["group_id"] == process["audit_token"]["pid"]
                    assert process["session_id"] == process["ppid"]
                    assert process["tty"] is not None
                    assert query["fds"] == [{"fd": fd, "fdtype": 1} for fd in range(3)]
            for worker in workers:
                forks = [
                    row
                    for row in receiver_rows
                    if row["event_type"] == 11
                    and row["event"]["fork"]["child"]["audit_token"]["pid"]
                    == worker["audit_token"]["pid"]
                    and row["event"]["fork"]["child"]["start_time"] == worker["start_time"]
                ]
                assert len(forks) == 1
                assert forks[0]["process"]["executable"]["path"] == "/sbin/launchd"
                assert (
                    forks[0]["event"]["fork"]["child"]["executable"]
                    == forks[0]["process"]["executable"]
                )
    assert snapshots[0] == snapshots[1]


@pytest.mark.slow
@pytest.mark.parametrize("macos_receiver,pty", [(False, False), (True, False), (True, True)])
def test_complete_ssh_client_checkpoint_resume_preserves_integer_signatures_and_execs(
    tmp_path: Path,
    scenarios_dir: Path,
    macos_receiver: bool,
    pty: bool,
) -> None:
    from tests.integration.test_checkpoint_smoke import (
        test_short_generation_checkpoint_suspension_and_resume as checkpoint_gate,
    )

    checkpoint_gate(
        tmp_path,
        scenarios_dir,
        "default",
        None,
        True,
        None,
        True,
        macos_receiver,
        False,
        complete_native_ssh=True,
        ssh_pty=pty,
    )
