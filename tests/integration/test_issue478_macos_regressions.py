# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Issue #478's supplied examples through the public generation pipeline."""

import json
import os
import subprocess
import sys
from datetime import datetime
from pathlib import Path

import pytest
import yaml

from evidenceforge.formats.macos_endpoint_security import (
    EndpointSecurityRecord,
    decode_endpoint_security_record,
)
from evidenceforge.utils.files import load_yaml


def _generate_example(project: Path, example: str, *, partial: bool = False) -> Path:
    source = Path(__file__).parents[2] / "scenarios" / example / "scenario.yaml"
    document = load_yaml(source)
    # The contributor's inputs omit native ES. Preserve their workload, duration
    # and warmup, adding only the source and the persistence coverage qualification.
    document["output"]["logs"].append({"format": "macos_endpoint_security"})
    if partial:
        document["macos_process_coverage"] = "partial"
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
def test_issue478_background_shell_forks_preserve_fractional_birth_times(
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
    assert commands, "The supplied workload must exercise the reported background command"
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
def test_issue478_unlisted_natural_shell_exits_leave_no_internal_sequence_gaps(
    issue478_workstation_bundle: Path,
) -> None:
    commands_seen: set[str] = set()
    for rows in _native_streams(issue478_workstation_bundle).values():
        # Warmup legitimately consumes earlier numbers. Check internal continuity,
        # not a zero origin or a particular sampled count/PID/timestamp.
        numbers = [row.global_seq_num for row in rows]
        assert numbers == list(range(numbers[0], numbers[-1] + 1))
        for event_type in {row.event_type for row in rows}:
            sequences = [row.seq_num for row in rows if row.event_type == event_type]
            assert sequences == list(range(sequences[0], sequences[-1] + 1))
        for command in rows:
            if command.event_type != 9 or command.event.exec.args not in {
                ("/bin/zsh", "-c", "id; groups"),
                ("/bin/zsh", "-c", "ls -la ~/Library/LaunchAgents"),
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
    assert commands_seen == {"id; groups", "ls -la ~/Library/LaunchAgents"}
    truth = json.loads((issue478_workstation_bundle / "GROUND_TRUTH.json").read_text())
    for host in truth["macos_native_coverage"]["hosts"]:
        census = host["process_census"]
        assert census["exit_complete"] and census["expected_exits"] > 0
        assert census["expected_exits"] == census["known_exits"] == census["published_exits"]
        assert not any(row["reason"] == "exit_outcome_unknown" for row in host["observations"])


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
