# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Nonempty modeled fork output survives normal CLI filtering and recovery."""

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

from evidenceforge.evaluation.parsers import get_parser
from evidenceforge.evaluation.pillars.parseability import ParseabilityScorer
from evidenceforge.formats.macos_endpoint_security import decode_endpoint_security_record
from tests.integration.test_checkpoint_smoke import (
    test_short_generation_checkpoint_suspension_and_resume as _checkpoint_gate,
)
from tests.support.macos_ssh import macos_ssh_scenario


@pytest.mark.slow
def test_nonempty_native_cli_is_deterministic_filter_independent_and_ingestible(
    tmp_path: Path, scenarios_dir: Path
) -> None:
    data = macos_ssh_scenario(scenarios_dir, macos_receiver=True).model_dump(
        mode="json", exclude_none=True
    )
    for system in data["environment"]["systems"]:
        system["os_build"] = "25A354"
    data["output"]["logs"].append({"format": "macos_endpoint_security"})
    scenario = tmp_path / "invented-native-ssh.yaml"
    scenario.write_text(yaml.safe_dump(data, sort_keys=False))
    snapshots: list[dict[str, bytes]] = []
    for label, hash_seed, formats in (
        ("first", "19", ""),
        ("second", "83", ""),
        ("native", "37", "macos_endpoint_security"),
    ):
        output = tmp_path / label
        arguments = [
            sys.executable,
            "-m",
            "evidenceforge",
            "generate",
            str(scenario),
            "--output",
            str(output),
            "--seed",
            "328",
            "--checkpoint-hours",
            "0",
            "--project-root",
            str(tmp_path),
        ]
        if formats:
            arguments.extend(["--formats", formats])
        result = subprocess.run(
            arguments,
            env=os.environ | {"PYTHONHASHSEED": hash_seed},
            capture_output=True,
            text=True,
            timeout=120,
            check=False,
        )
        assert result.returncode == 0, result.stdout + result.stderr
        paths = sorted((output / "data").rglob("macos_endpoint_security.ndjson"))
        assert len(paths) == 1
        snapshots.append({str(path.relative_to(output)): path.read_bytes() for path in paths})
        records = list(get_parser("macos_endpoint_security").parse_file(paths[0]))
        assert len(records) == 3 and all(not record.parse_errors for record in records)
        schema, constraints = ParseabilityScorer()._score_both({"macos_endpoint_security": records})
        assert schema.score == constraints.score == 100
        for record in records:
            decode_endpoint_security_record(record.raw)
            assert record.fields["event_type"] == 11 and record.fields["version"] == 10
        manifest = json.loads((output / "GENERATION_MANIFEST.json").read_text())
        assert "macos_endpoint_security" in manifest["formats"]
    assert snapshots[0] == snapshots[1] == snapshots[2]


@pytest.mark.slow
def test_nonempty_native_ssh_checkpoint_resume_preserves_exact_output(
    tmp_path: Path, scenarios_dir: Path
) -> None:
    _checkpoint_gate(
        tmp_path,
        scenarios_dir,
        target="default",
        start=None,
        macos=True,
        smb_server=None,
        ssh_client=True,
        macos_receiver=True,
        authored_close=True,
        endpoint_forks=True,
    )
