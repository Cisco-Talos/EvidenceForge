# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

import json
from pathlib import Path

import pytest

from evidenceforge.evaluation.engine import EvaluationEngine
from evidenceforge.generation.engine import GenerationEngine
from evidenceforge.models.scenario import Scenario
from tests.unit.test_macos_history_spillage import _scenario


@pytest.mark.slow
def test_mac_authored_history_is_session_owned_filter_stable_and_evaluated(tmp_path: Path) -> None:
    data = _scenario()
    data["storyline"].insert(
        0,
        {
            "id": "login",
            "time": "+1m",
            "actor": "alex",
            "system": "MAC-01",
            "activity": "Open an invented local session",
            "events": [{"type": "logon", "logon_type": 2}],
        },
    )
    histories: list[dict[str, bytes]] = []
    for formats in [("ecar", "zsh_history"), ("zsh_history",)]:
        data["output"]["logs"] = [{"format": value} for value in formats]
        scenario = Scenario(**data)
        output = tmp_path / str(len(histories))
        GenerationEngine(scenario, output, generation_seed=284).generate()
        rows = [
            record
            for record in json.loads((output / "GROUND_TRUTH.json").read_text())["events"]
            if record["kind"] == "spillage"
        ]
        assert len(rows) == 1 and rows[0]["emitted"]
        assert rows[0]["attributes"]["expected_sources"] == ["zsh_history"]
        files = {
            str(path.relative_to(output)): path.read_bytes()
            for path in output.rglob("*.zsh_history")
        }
        assert files
        assert sum(content.count(b"EvidenceForgeFake_HISTORY") for content in files.values()) == 1
        assert not list(output.rglob("*.bash_history"))
        histories.append(files)
        if "ecar" in formats:
            events = [
                json.loads(line)
                for path in output.rglob("ecar.json")
                for line in path.read_text().splitlines()
            ]
            assert any(
                row["object"] == "PROCESS"
                and row["action"] == "CREATE"
                and row["properties"]["image_path"] == "/bin/zsh"
                for row in events
            )
            report = EvaluationEngine(output_dir=output, scenario=scenario).run()
            presence = next(
                score
                for pillar in report.pillars
                for score in pillar.sub_scores
                if score.key == "event_presence"
            )
            assert presence.score == 100
    assert histories[0] == histories[1]


@pytest.mark.slow
def test_mac_history_example_fresh_process_determinism_and_format_validation(
    tmp_path: Path,
) -> None:
    import os
    import subprocess
    import sys

    from tests.support.output_equivalence import deterministic_bundle_files

    scenario = Path("scenarios/macos-workstation-example/history-exposure.yaml").resolve()
    outputs: list[dict[str, bytes]] = []
    for label, seed in (("first", "17"), ("repeat", "91")):
        output = tmp_path / label
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
                "284",
                "--checkpoint-hours",
                "0",
                "--project-root",
                str(tmp_path),
            ],
            env=os.environ | {"PYTHONHASHSEED": seed},
            capture_output=True,
            text=True,
            timeout=180,
            check=False,
        )
        assert result.returncode == 0, result.stdout + result.stderr
        outputs.append(deterministic_bundle_files(output))
    assert outputs[0] == outputs[1]
    assert b"EvidenceForgeFake_HISTORY_ONLY" in b"".join(
        content for name, content in outputs[0].items() if name.endswith(".zsh_history")
    )
    rejected = subprocess.run(
        [
            sys.executable,
            "-m",
            "evidenceforge",
            "generate",
            str(scenario),
            "--output",
            str(tmp_path / "missing-history"),
            "--formats",
            "ecar",
            "--project-root",
            str(tmp_path),
        ],
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    assert rejected.returncode != 0
    assert "zsh_history" in rejected.stdout + rejected.stderr
