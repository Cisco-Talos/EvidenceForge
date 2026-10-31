# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""The public CLI cannot accept an incomplete native bundle by default."""

import subprocess
import sys
from pathlib import Path

import pytest
import yaml

from tests.support.macos_ssh import macos_ssh_scenario


@pytest.mark.slow
@pytest.mark.parametrize("filter_native", [False, True])
def test_default_native_completeness_rejects_unresolved_starts_or_removed_source(
    tmp_path: Path, scenarios_dir: Path, filter_native: bool
) -> None:
    raw = macos_ssh_scenario(scenarios_dir, macos_receiver=True).model_dump(
        mode="json", exclude_none=True
    )
    raw.pop("macos_process_coverage")
    raw["time_window"]["duration"] = "15m"
    raw["output"]["logs"].append({"format": "macos_endpoint_security"})
    source = tmp_path / "invented-complete.yaml"
    source.write_text(yaml.safe_dump(raw))
    output = tmp_path / "output"
    command = [
        sys.executable,
        "-m",
        "evidenceforge",
        "generate",
        str(source),
        "--output",
        str(output),
        "--checkpoint-hours",
        "0",
        "--project-root",
        str(tmp_path),
    ]
    if filter_native:
        command.extend(["--formats", "ecar"])
    result = subprocess.run(command, capture_output=True, text=True, timeout=120)
    assert result.returncode != 0
    text = result.stdout + result.stderr
    assert (
        "native macos_endpoint_security output is not selected" in text
        if filter_native
        else "Incomplete native macOS process coverage" in text
    )
    assert not (output / "GROUND_TRUTH.json").exists()
