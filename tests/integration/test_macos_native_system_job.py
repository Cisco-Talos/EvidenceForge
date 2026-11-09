# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""A bounded native job runs through ordinary public generation and filtering."""

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from evidenceforge.formats.macos_endpoint_security import decode_endpoint_security_record


@pytest.mark.slow
def test_native_job_public_cli_has_both_execs_and_filter_independent_bytes(tmp_path: Path) -> None:
    source = Path("scenarios/macos-persistence-example/native-system-job.yaml").resolve()
    outputs = []
    for name, formats, hash_seed in (
        ("full", [], "19"),
        ("native", ["--formats", "macos_endpoint_security"], "83"),
    ):
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
                "372",
                "--checkpoint-hours",
                "0",
                "--project-root",
                str(tmp_path),
                *formats,
            ],
            env=os.environ | {"PYTHONHASHSEED": hash_seed},
            capture_output=True,
            text=True,
            timeout=120,
        )
        assert result.returncode == 0, result.stdout + result.stderr
        native = {
            str(path.relative_to(output)): path.read_bytes()
            for path in (output / "data").rglob("macos_endpoint_security.ndjson")
        }
        rows = [
            decode_endpoint_security_record(line.decode())
            for content in native.values()
            for line in content.splitlines()
        ]
        targets = [
            row
            for row in rows
            if row.event_type == 9 and row.event.exec.target.executable.path == "/usr/bin/true"
        ]
        assert len(targets) == 2
        for target in targets:
            pid = target.event.exec.target.audit_token.pid
            selected = [
                row
                for row in rows
                if row.process.audit_token.pid == pid
                or row.event_type == 11
                and row.event.fork.child.audit_token.pid == pid
            ]
            assert [row.event_type for row in selected] == [11, 9, 9, 15]
            assert selected[0].process.executable.path == "/sbin/launchd"
            assert selected[1].event.exec.target.executable.path == "/usr/libexec/xpcproxy"
            assert selected[-1].event.exit.stat == 0
        truth = json.loads((output / "GROUND_TRUTH.json").read_text())
        assert all(
            host["process_census"]["complete"] and host["process_census"]["aggregate_births"] == 0
            for host in truth["macos_native_coverage"]["hosts"]
        )
        outputs.append(native)
    assert outputs[0] and outputs[0] == outputs[1]


@pytest.mark.slow
def test_native_job_public_checkpoint_resume_with_active_job(
    tmp_path: Path, scenarios_dir: Path
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
        False,
        False,
        False,
        native_system_job=True,
    )
