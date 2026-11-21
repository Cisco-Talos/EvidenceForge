# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Issue #478's supplied examples through the public generation pipeline."""

import json
import os
import subprocess
import sys
from collections import Counter
from datetime import datetime
from pathlib import Path

import pytest
import yaml

from evidenceforge.formats.macos_endpoint_security import (
    EndpointSecurityRecord,
    decode_endpoint_security_record,
)
from evidenceforge.utils.files import load_yaml

_SHELL_COMMANDS = ("id; groups", "ls -la ~/Library/LaunchAgents")


def _generate_example(project: Path, example: str, *, partial: bool = False) -> Path:
    source = Path(__file__).parents[2] / "scenarios" / example / "scenario.yaml"
    document = load_yaml(source)
    document["output"]["logs"].append({"format": "macos_endpoint_security"})
    if partial:
        document["macos_process_coverage"] = "partial"
    else:
        # Make the reported shell invocations independent of baseline command sampling.
        document["storyline"] = [
            {
                "id": f"shell-command-{index}",
                "time": f"+{index * 10}m",
                "actor": "alex",
                "system": "MAC-01",
                "activity": "Run a short noninteractive shell command",
                "events": [
                    {
                        "type": "process",
                        "process_name": "/bin/zsh",
                        "command_line": f"/bin/zsh -c '{command}'",
                        "supplementary": "none",
                    }
                ],
            }
            for index, command in enumerate(_SHELL_COMMANDS, start=1)
        ]
    scenario = project / "scenario.yaml"
    scenario.write_text(yaml.safe_dump(document, sort_keys=False))
    output = project / "bundle"
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "evidenceforge",
            "generate",
            str(scenario),
            "--output",
            str(output),
            "--seed",
            "42",
            "--project-root",
            str(project),
        ],
        env=os.environ | {"PYTHONHASHSEED": "17"},
        capture_output=True,
        text=True,
        timeout=180,
        check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    return output


@pytest.fixture(scope="module")
def issue478_workstation_bundle(tmp_path_factory: pytest.TempPathFactory) -> Path:
    return _generate_example(
        tmp_path_factory.mktemp("issue478-workstation"), "macos-workstation-example"
    )


def _native_streams(output: Path) -> dict[str, list[EndpointSecurityRecord]]:
    streams = {
        str(path.relative_to(output / "data")): [
            decode_endpoint_security_record(line) for line in path.read_text().splitlines()
        ]
        for path in (output / "data").rglob("macos_endpoint_security.ndjson")
    }
    assert streams and all(streams.values())
    return streams


@pytest.mark.slow
def test_issue478_shell_forks_preserve_fractional_birth_times(
    issue478_workstation_bundle: Path,
) -> None:
    rows = [
        row for stream in _native_streams(issue478_workstation_bundle).values() for row in stream
    ]
    commands = [
        row
        for row in rows
        if row.event_type == 9 and row.event.exec.args == ("/bin/zsh", "-c", "id; groups")
    ]
    assert commands, "The workload must exercise the reported shell command"
    for command in commands:
        forks = [
            row
            for row in rows
            if row.event_type == 11
            and row.event.fork.child.audit_token == command.process.audit_token
            and row.event.fork.child.start_time == command.process.start_time
        ]
        assert len(forks) == 1
        fork = forks[0]
        birth = datetime.fromisoformat(fork.event.fork.child.start_time)
        assert datetime.fromisoformat(fork.time).microsecond != 0
        assert birth.microsecond != 0
        assert birth < datetime.fromisoformat(command.time)


@pytest.mark.slow
def test_issue478_natural_shell_exits_and_source_sequence_accounting(
    issue478_workstation_bundle: Path,
) -> None:
    commands_seen: set[str] = set()
    truth = json.loads((issue478_workstation_bundle / "GROUND_TRUTH.json").read_text())
    hosts = {host["hostname"]: host for host in truth["macos_native_coverage"]["hosts"]}
    phases = {9: "exec", 11: "fork", 15: "exit"}
    for path, rows in _native_streams(issue478_workstation_bundle).items():
        host = hosts[path.split("/", 1)[0].split(".", 1)[0]]
        omissions: Counter[str] = Counter()
        for observation in host["observations"]:
            if observation["status"] not in {"visible", "delayed", "out_of_window"}:
                omissions[observation["phase"]] += observation["count"]
        numbers = [row.global_seq_num for row in rows]
        assert numbers == sorted(set(numbers))
        global_gaps = numbers[-1] - numbers[0] + 1 - len(numbers)
        assert global_gaps <= omissions.total()
        for event_type in {row.event_type for row in rows}:
            sequences = [row.seq_num for row in rows if row.event_type == event_type]
            assert sequences == sorted(set(sequences))
            gaps = sequences[-1] - sequences[0] + 1 - len(sequences)
            assert gaps <= omissions[phases[event_type]]
        for command in rows:
            if command.event_type != 9 or command.event.exec.args not in {
                ("/bin/zsh", "-c", text) for text in _SHELL_COMMANDS
            }:
                continue
            commands_seen.add(command.event.exec.args[-1])
            exits = [
                row
                for row in rows
                if row.event_type == 15
                and row.process.audit_token == command.event.exec.target.audit_token
                and row.process.start_time == command.event.exec.target.start_time
            ]
            assert len(exits) == 1
            assert exits[0].event.exit.stat == 0
            assert datetime.fromisoformat(command.time) < datetime.fromisoformat(exits[0].time)
    assert commands_seen == set(_SHELL_COMMANDS)
    for host in hosts.values():
        census = host["process_census"]
        assert census["exit_accounting_complete"] and census["known_exit_identities_match"]
        assert census["observed_exits"] == census["expected_exits"] > 0
        assert census["known_exits"] == census["published_exits"]


@pytest.mark.slow
def test_issue478_partial_persistence_keeps_unknown_executable_exits_unpublished(
    tmp_path: Path,
) -> None:
    output = _generate_example(tmp_path, "macos-persistence-example", partial=True)
    rows = [row for stream in _native_streams(output).values() for row in stream]
    forks = [row for row in rows if row.event_type == 11]
    assert forks
    assert all(datetime.fromisoformat(row.time).microsecond != 0 for row in forks)
    assert not any(
        row.event_type == 15
        and row.process.executable.path.startswith("/usr/local/libexec/invented-")
        for row in rows
    )
    truth = json.loads((output / "GROUND_TRUTH.json").read_text())
    coverage = truth["macos_native_coverage"]
    assert coverage["policy"] == "partial"
    host = next(host for host in coverage["hosts"] if host["hostname"] == "MAC-01")
    assert any(
        row["phase"] == "exit"
        and row["reason"] == "executable_version_unknown"
        and row["status"] == "filtered"
        and row["count"] > 0
        for row in host["observations"]
    )
    assert host["process_census"]["exit_accounting_complete"]
    assert not host["process_census"]["exit_complete"]
