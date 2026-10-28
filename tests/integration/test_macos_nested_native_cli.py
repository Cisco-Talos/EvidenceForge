# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""A synthetic nested SSH command produces real canonical fork/exec/exit phases."""

import json
import os
import subprocess
import sys
from pathlib import Path
from statistics import median

import pytest
import yaml

from tests.support.macos_ssh import MACOS_NATIVE_QUERY_COMMANDS, macos_ssh_scenario
from tests.support.output_equivalence import deterministic_bundle_files


@pytest.mark.slow
@pytest.mark.parametrize("launch", ["local", "ssh", "occupied_local"])
def test_every_accepted_ordinary_command_exports_native_exec_in_public_cli(
    tmp_path: Path, scenarios_dir: Path, launch: str
) -> None:
    scenario = macos_ssh_scenario(scenarios_dir, macos_receiver=True).model_dump(
        mode="json", exclude_none=True
    )
    scenario["time_window"]["duration"] = "25m"
    scenario["output"]["logs"].append({"format": "macos_endpoint_security"})
    hostname = "SSH-TEST" if launch == "ssh" else "TEST-01"
    if launch == "local":
        # The SSH client occupies this local shell until its remote session closes.
        # Test local commands without simultaneously handing that shell to SSH.
        scenario["storyline"] = [
            event for event in scenario["storyline"] if event["id"] != "remote-session"
        ]
    for ordinal, command in enumerate(MACOS_NATIVE_QUERY_COMMANDS):
        scenario["storyline"].append(
            {
                "id": f"coverage-command-{ordinal}",
                "time": f"+{11 * 60 + ordinal * 20}s",
                "actor": "test_user",
                "system": hostname,
                "activity": f"Invented {launch} external command with complete ES collection",
                "events": [
                    {
                        "type": "process",
                        "process_name": command.split()[0],
                        "command_line": command,
                    }
                ],
            }
        )
    path = tmp_path / "scenario.yaml"
    path.write_text(yaml.safe_dump(scenario))
    output = tmp_path / "complete-commands"
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "evidenceforge",
            "generate",
            str(path),
            "--output",
            str(output),
            "--seed",
            "347",
            "--checkpoint-hours",
            "0",
            "--project-root",
            str(tmp_path),
        ],
        capture_output=True,
        text=True,
        timeout=180,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    truth = json.loads((output / "GROUND_TRUTH.json").read_text())
    accepted = [
        event
        for event in truth["events"]
        if (event.get("storyline_id") or "").startswith("coverage-command-")
    ]
    assert len(accepted) == len(MACOS_NATIVE_QUERY_COMMANDS)
    if launch == "occupied_local":
        assert all(
            not event["emitted"]
            and event["skipped_reason"] == "foreground_shell_unavailable"
            and event["attributes"].get("pid") is None
            for event in accepted
        )
        return
    assert all(event["emitted"] and event["attributes"]["pid"] > 0 for event in accepted)
    native = [
        record["event"]["exec"]
        for path in (output / "data").rglob("macos_endpoint_security.ndjson")
        if any(part == hostname or part.startswith(f"{hostname}.") for part in path.parts)
        for line in path.read_text().splitlines()
        if (record := json.loads(line))["event_type"] == 9
    ]
    for event in accepted:
        matches = [
            execution
            for execution in native
            if execution["target"]["audit_token"]["pid"] == event["attributes"]["pid"]
            and execution["target"]["executable"]["path"] == event["attributes"]["process_name"]
        ]
        assert len(matches) == 1, event["storyline_id"]
    host = next(
        item for item in truth["macos_native_coverage"]["hosts"] if item["hostname"] == hostname
    )
    commands = [
        action
        for action in host["authored_actions"]
        if action["storyline_cluster_id"].startswith("coverage-command-")
    ]
    assert len(commands) == len(accepted)
    assert all(
        sum(
            count["count"]
            for count in action["observations"]
            if count["phase"] == "exec"
            and count["reason"] == "supported"
            and count["status"] in {"visible", "delayed"}
        )
        == 1
        for action in commands
    )


@pytest.mark.slow
def test_nested_native_command_cli_preserves_source_filtering_and_known_exit(
    tmp_path: Path, scenarios_dir: Path
) -> None:
    scenario = macos_ssh_scenario(scenarios_dir, macos_receiver=True).model_dump(
        mode="json", exclude_none=True
    )
    scenario["time_window"]["duration"] = "25m"
    scenario["output"]["logs"].append({"format": "macos_endpoint_security"})
    scenario["storyline"].append(
        dict(
            id="remote-query-before-nesting",
            time="+11m",
            actor="test_user",
            system="SSH-TEST",
            activity="A one-shot query releases the parent shell before nesting",
            events=[
                dict(
                    type="process", process_name="/usr/bin/uname", command_line="/usr/bin/uname -a"
                )
            ],
        )
    )
    for name, when, image, extra in (
        ("nested-shell", "+12m", "/bin/zsh", {"process_ref": "nested"}),
        ("nested-query", "+13m", "/usr/bin/id", {"parent_ref": "nested"}),
    ):
        scenario["storyline"].append(
            dict(
                id=name,
                time=when,
                actor="test_user",
                system="SSH-TEST",
                activity="Invented command chain",
                events=[dict(type="process", process_name=image, command_line=image, **extra)],
            )
        )
    path = tmp_path / "scenario.yaml"
    path.write_text(yaml.safe_dump(scenario))
    outputs = []
    for label, formats in (("all", ""), ("filtered", "ecar")):
        out = tmp_path / label
        args = [
            sys.executable,
            "-m",
            "evidenceforge",
            "generate",
            str(path),
            "--output",
            str(out),
            "--seed",
            "328",
            "--checkpoint-hours",
            "0",
            "--project-root",
            str(tmp_path),
        ]
        if formats:
            args.extend(["--formats", formats])
        result = subprocess.run(
            args,
            capture_output=True,
            text=True,
            timeout=180,
            env=os.environ | {"PYTHONHASHSEED": "61"},
        )
        assert result.returncode == 0, result.stdout + result.stderr
        outputs.append(deterministic_bundle_files(out))
    assert {key: value for key, value in outputs[0].items() if key.endswith("ecar.json")} == {
        key: value for key, value in outputs[1].items() if key.endswith("ecar.json")
    }
    truth = json.loads((tmp_path / "all" / "GROUND_TRUTH.json").read_text())
    query = next(event for event in truth["events"] if event["storyline_id"] == "nested-query")
    assert query["emitted"] is True
    assert query["attributes"]["native_process_model"] == "fork_exec"
    pid = query["attributes"]["pid"]
    records = [
        json.loads(line)
        for name, body in outputs[0].items()
        if name.endswith("macos_endpoint_security.ndjson")
        for line in body.splitlines()
    ]
    executions = [
        row
        for row in records
        if row["event_type"] == 9 and row["event"]["exec"]["target"]["audit_token"]["pid"] == pid
    ]
    exits = [
        row
        for row in records
        if row["event_type"] == 15 and row["process"]["audit_token"]["pid"] == pid
    ]
    assert len(executions) == len(exits) == 1
    assert exits[0]["event"]["exit"]["stat"] == 0


@pytest.mark.slow
def test_current_profile_mixed_benchmark_executes_queries_and_exports_known_lifecycles(
    tmp_path: Path,
) -> None:
    scenario = Path("scenarios/macos27-native-assessment/source/scenario.yaml")
    output = tmp_path / "mixed-native"
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "evidenceforge",
            "generate",
            str(scenario),
            "--output",
            str(output),
            "--checkpoint-hours",
            "0",
            "--project-root",
            str(tmp_path),
        ],
        capture_output=True,
        text=True,
        timeout=180,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    truth = json.loads((output / "GROUND_TRUTH.json").read_text())
    commands = {
        event["storyline_id"]: event
        for event in truth["events"]
        if (event.get("storyline_id") or "").startswith("remote-nested-")
    }
    assert len(commands) == 5
    assert all(
        event["emitted"] and event["attributes"]["native_process_model"] == "fork_exec"
        for event in commands.values()
    )
    records = [
        json.loads(line)
        for path in (output / "data").rglob("macos_endpoint_security.ndjson")
        for line in path.read_text().splitlines()
    ]
    assert records and all(record["version"] == 11 for record in records)
    for name in ("remote-nested-id", "remote-nested-version"):
        pid = commands[name]["attributes"]["pid"]
        births = [
            row
            for row in records
            if row["event_type"] == 11
            and row["event"]["fork"]["child"]["audit_token"]["pid"] == pid
        ]
        execs = [
            row
            for row in records
            if row["event_type"] == 9
            and row["event"]["exec"]["target"]["audit_token"]["pid"] == pid
        ]
        exits = [
            row
            for row in records
            if row["event_type"] == 15 and row["process"]["audit_token"]["pid"] == pid
        ]
        assert len(births) == len(execs) == len(exits) == 1
        assert exits[0]["event"]["exit"]["stat"] == 0
    assert not (output / "data" / ".eforge-es-ingress").exists()
    shell_query_spans: list[float] = []
    for path in (output / "data").rglob("ecar.json"):
        starts: dict[str, dict] = {}
        for line in path.read_text().splitlines():
            row = json.loads(line)
            if row.get("object") != "PROCESS":
                continue
            identity = row["objectID"]
            if row.get("action") == "CREATE":
                starts[identity] = row
            elif (
                row.get("action") == "MODIFY"
                and row.get("properties", {}).get("operation") == "exec"
            ):
                # A fork CREATE still carries the parent's image. Measure the
                # command from its own image activation, not the inherited image.
                starts[identity] = row
            elif row.get("action") == "TERMINATE" and identity in starts:
                start = starts[identity]
                command = start.get("properties", {}).get("command_line", "")
                if command in {
                    "/bin/zsh -c 'id; groups'",
                    "/bin/zsh -c 'ls -la ~/Library/LaunchAgents'",
                }:
                    shell_query_spans.append((row["timestamp_ms"] - start["timestamp_ms"]) / 1000)
    assert len(shell_query_spans) >= 2
    assert 0 < median(shell_query_spans) < 0.5
