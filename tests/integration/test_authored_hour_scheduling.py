# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Full lifecycle regression for the non-aligned starts reported in issue #444."""

import json
from pathlib import Path

import pytest

from evidenceforge.generation.checkpoints.models import CheckpointCursor
from evidenceforge.generation.engine import GenerationEngine
from evidenceforge.models.scenario import Scenario
from evidenceforge.utils.files import load_yaml


@pytest.mark.slow
@pytest.mark.parametrize("start", ["2026-10-09T09:59:00Z", "2026-10-06T09:59:00Z"])
def test_branch_office_non_aligned_start_preserves_authored_lifecycle(
    start: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    document = load_yaml(
        Path(__file__).parents[2] / "scenarios/branch-office-example/scenario.yaml"
    )
    document["time_window"]["start"] = start
    scenario = Scenario.model_validate(document)
    engine = GenerationEngine(scenario, tmp_path, output_target="splunk")
    generate_baseline = engine._generate_baseline

    def generate_and_check_interleaving(resume_cursor: CheckpointCursor | None = None) -> None:
        generate_baseline(resume_cursor=resume_cursor)
        # Success must come from timely execution, not a permissive tail replay
        # that bypasses the canonical process/session lifecycle checks.
        assert engine._storyline_executed == set(range(len(scenario.storyline)))
        assert engine._red_herring_executed == set(range(len(scenario.red_herrings)))

    monkeypatch.setattr(engine, "_generate_baseline", generate_and_check_interleaving)
    engine.generate()

    proxy_records = [
        json.loads(line)
        for path in tmp_path.rglob("proxy_access.log")
        for line in path.read_text().splitlines()
        if line.strip()
    ]
    assert any(
        record["server"] == "northlakeportal.com" and record["client"] == "10.44.10.24"
        for record in proxy_records
    )
    assert (tmp_path / "GROUND_TRUTH.json").is_file()
