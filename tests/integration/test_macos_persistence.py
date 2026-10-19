# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest


@pytest.mark.slow
def test_authored_job_source_filtering_and_lifecycle(tmp_path: Path) -> None:
    source = Path("scenarios/macos-persistence-example/scenario.yaml").resolve()
    outputs: list[Path] = []
    for name, extra, hash_seed in (("full", [], "3"), ("filtered", ["--formats", "ecar"], "19")):
        output = tmp_path / name
        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "evidenceforge",
                "generate",
                str(source),
                "--output",
                str(output),
                "--seed",
                "123",
                "--checkpoint-hours",
                "0",
                "--project-root",
                str(tmp_path),
                *extra,
            ],
            env=os.environ | {"PYTHONHASHSEED": hash_seed},
            capture_output=True,
            text=True,
            timeout=120,
        )
        assert result.returncode == 0, result.stdout + result.stderr
        outputs.append(output)
    evidence = [
        {
            str(path.relative_to(output)): path.read_bytes()
            for path in (output / "data").rglob("ecar.json")
        }
        for output in outputs
    ]
    assert evidence[0] and evidence[0] == evidence[1]
    rows = [json.loads(line) for content in evidence[0].values() for line in content.splitlines()]
    jobs = [
        row
        for row in rows
        if row["object"] == "PROCESS"
        and row.get("properties", {}).get("image_path") == "/usr/local/libexec/invented-worker"
    ]
    starts = [row for row in jobs if row["action"] == "CREATE"]
    ends = [row for row in jobs if row["action"] == "TERMINATE"]
    assert len(starts) == len(ends) == 2
    assert {row["objectID"] for row in starts} == {row["objectID"] for row in ends}
    assert all(row["ppid"] == 1 and row["principal"] == "root" for row in starts)
    assert all(row["properties"]["parent_image_path"] == "/sbin/launchd" for row in starts)
    files = [
        row
        for row in rows
        if row["object"] == "FILE"
        and row.get("properties", {}).get("file_path")
        == "/Library/LaunchDaemons/org.example.worker.plist"
    ]
    assert {row["action"] for row in files} == {"CREATE", "DELETE"}
    assert len({row["objectID"] for row in files}) == 1
    assert max(row["timestamp_ms"] for row in files) < min(row["timestamp_ms"] for row in starts)
    truth = json.loads((outputs[0] / "GROUND_TRUTH.json").read_text())
    stages = [event for event in truth["events"] if event["kind"] == "macos_launch_item"]
    registered = next(
        event for event in stages if event["attributes"]["launchd_operation"] == "bootstrap"
    )
    assert not registered["emitted"]
    assert registered["skipped_reason"] == "native_job_control_evidence_unavailable"
    assert {
        identity for event in stages for identity in event["attributes"]["process_object_ids"]
    } == {row["objectID"] for row in starts}


@pytest.mark.slow
@pytest.mark.parametrize("natural_exit", [False, True])
def test_authored_job_descendants_close_consistently_across_filtering(
    tmp_path: Path, natural_exit: bool
) -> None:
    import yaml

    source = Path("scenarios/macos-persistence-example/group-cleanup.yaml")
    data = yaml.safe_load(source.read_text())
    if natural_exit:
        for step in data["storyline"]:
            for event in step["events"]:
                if event.get("parent_ref"):
                    event["command_line"] = event["command_line"].replace(" --keep-alive", "")
    source = tmp_path / "scenario.yaml"
    source.write_text(yaml.safe_dump(data, sort_keys=False))
    outputs: list[Path] = []
    for name, extra, hash_seed in (("full", [], "3"), ("filtered", ["--formats", "ecar"], "19")):
        output = tmp_path / name
        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "evidenceforge",
                "generate",
                str(source),
                "--output",
                str(output),
                "--seed",
                "123",
                "--checkpoint-hours",
                "0",
                "--project-root",
                str(tmp_path),
                *extra,
            ],
            env=os.environ | {"PYTHONHASHSEED": hash_seed},
            capture_output=True,
            text=True,
            timeout=120,
        )
        assert result.returncode == 0, result.stdout + result.stderr
        outputs.append(output)
    evidence = [
        {
            str(path.relative_to(output)): path.read_bytes()
            for path in (output / "data").rglob("ecar.json")
        }
        for output in outputs
    ]
    assert evidence[0] and evidence[0] == evidence[1]
    rows = [json.loads(line) for content in evidence[0].values() for line in content.splitlines()]
    family = [
        row
        for row in rows
        if row["object"] == "PROCESS"
        and row.get("properties", {}).get("image_path")
        in {
            "/usr/local/libexec/invented-worker",
            "/usr/local/libexec/invented-helper-1",
            "/usr/local/libexec/invented-helper-2",
        }
    ]
    starts = [row for row in family if row["action"] == "CREATE"]
    ends = [row for row in family if row["action"] == "TERMINATE"]
    assert len(starts) == len(ends) == 3
    assert {row["objectID"] for row in starts} == {row["objectID"] for row in ends}
    truth = json.loads((outputs[0] / "GROUND_TRUTH.json").read_text())
    unload = next(
        event
        for event in truth["events"]
        if event.get("attributes", {}).get("launchd_operation") == "unload"
    )
    if not natural_exit:
        assert set(unload["attributes"]["process_object_ids"]) == {
            row["objectID"] for row in starts
        }
    else:
        assert len(unload["attributes"]["process_object_ids"]) < 3
