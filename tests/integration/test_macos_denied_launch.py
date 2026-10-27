# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

from tests.support.output_equivalence import deterministic_bundle_files


@pytest.mark.slow
@pytest.mark.parametrize("outcome", ["denied", "exec_failed"])
def test_authored_denial_preserves_precursors_suppresses_child_effects_and_is_deterministic(
    tmp_path: Path,
    outcome: str,
) -> None:
    data = yaml.safe_load(Path("scenarios/macos-workstation-example/scenario.yaml").read_text())
    data["time_window"]["duration"] = "20m"
    data["time_window"]["warmup"] = "1h"
    data["storyline"] = [
        dict(
            id="caller",
            time="+1m",
            actor="alex",
            system="MAC-01",
            activity="A caller before a rejected launch",
            events=[dict(type="process", process_name="/bin/zsh", process_ref="caller")],
        ),
        dict(
            id="denied",
            time="+2m",
            actor="alex",
            system="MAC-01",
            activity="Explicit terminal pre-spawn denial",
            events=[
                dict(
                    type="process",
                    process_name="/usr/local/libexec/invented-blocked-helper",
                    command_line="invented-blocked-helper --url https://never-executed.example.test/payload",
                    parent_ref="caller",
                    outcome=outcome,
                )
            ],
        ),
    ]
    scenario = tmp_path / "denied.yaml"
    scenario.write_text(yaml.safe_dump(data))
    outputs = []
    for name, hash_seed, formats in [
        ("first", "11", ""),
        ("second", "97", ""),
        ("filtered", "23", "ecar"),
    ]:
        out = tmp_path / name
        args = [
            sys.executable,
            "-m",
            "evidenceforge",
            "generate",
            str(scenario),
            "--output",
            str(out),
            "--seed",
            "123",
            "--checkpoint-hours",
            "0",
            "--project-root",
            str(tmp_path),
        ]
        if formats:
            args += ["--formats", formats]
        result = subprocess.run(
            args,
            capture_output=True,
            text=True,
            timeout=180,
            env=os.environ | {"PYTHONHASHSEED": hash_seed},
        )
        assert result.returncode == 0, result.stdout + result.stderr
        outputs.append(out)
    first, second, filtered = map(deterministic_bundle_files, outputs)
    assert first == second

    def endpoints(files: dict[str, bytes]) -> dict[str, bytes]:
        return {name: value for name, value in files.items() if name.endswith("/ecar.json")}

    assert endpoints(first) == endpoints(filtered)
    rows = [
        json.loads(line) for content in endpoints(first).values() for line in content.splitlines()
    ]
    assert any(
        row["object"] == "PROCESS"
        and row["action"] == "CREATE"
        and row["properties"]["image_path"] == "/bin/zsh"
        for row in rows
    )
    assert b"invented-blocked-helper" not in b"".join(
        path.read_bytes() for path in (outputs[0] / "data").rglob("*") if path.is_file()
    )
    assert b"never-executed.example.test" not in b"".join(
        path.read_bytes() for path in (outputs[0] / "data").rglob("*") if path.is_file()
    )
    ground_truth = json.loads((outputs[0] / "GROUND_TRUTH.json").read_text())
    denied = next(event for event in ground_truth["events"] if event["storyline_id"] == "denied")
    assert denied["emitted"] is False
    assert denied["attributes"]["outcome"] == outcome
    assert denied["skipped_reason"] == (
        "execution_denied_before_spawn" if outcome == "denied" else "exec_failed_caller_preserved"
    )

    coverage = ground_truth["macos_native_coverage"]
    assert coverage["scope"] == "exact_process_cohorts_and_authored_births"
    host = next(host for host in coverage["hosts"] if host["hostname"] == "MAC-01")
    assert any(item["reason"] == "aggregate_birth_only" for item in host["observations"])
    assert not (outputs[0] / "data" / ".eforge-es-ingress").exists()
