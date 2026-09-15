"""Full realism scenario regression for generation and evaluator integration."""

import hashlib
import json
import subprocess
import sys
from pathlib import Path

import pytest


def _verified_snapshot(root: Path) -> dict[str, bytes]:
    manifest = json.loads((root / "GENERATION_MANIFEST.json").read_text())
    files = {name: (root / name).read_bytes() for name in manifest["files"]}
    for name, content in files.items():
        assert hashlib.sha256(content).hexdigest() == manifest["files"][name]
    assert (
        hashlib.sha256(files["RESOLVED_SCENARIO.yaml"]).hexdigest()
        == manifest["resolved_file_sha256"]
    )
    return files


@pytest.mark.slow
@pytest.mark.parametrize("target", ["default", "sof-elk"])
def test_iteration_fresh_process_bytes_and_complete_evaluation(tmp_path: Path, target: str) -> None:
    root = Path(__file__).parents[2]
    scenario = root / "scenarios/iteration-test/scenario.yaml"
    outputs = [tmp_path / "first", tmp_path / "second"]
    for output in outputs:
        generated = subprocess.run(
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
                "--target",
                target,
            ],
            cwd=root,
            capture_output=True,
            text=True,
            timeout=600,
            check=False,
        )
        assert generated.returncode == 0, generated.stderr
    assert _verified_snapshot(outputs[0]) == _verified_snapshot(outputs[1])
    evaluated = subprocess.run(
        [sys.executable, "-m", "evidenceforge", "eval", str(outputs[0]), "--format", "json"],
        cwd=root,
        capture_output=True,
        text=True,
        timeout=180,
        check=False,
    )
    assert evaluated.returncode == 0, evaluated.stderr
    report = json.loads(evaluated.stdout)
    assert report["source_counts"]["email_artifacts"] > 0
    assert len(report["pillars"]) == 4
    assert all(pillar["score"] is not None for pillar in report["pillars"])
    parseability = next(p for p in report["pillars"] if p["name"] == "Parseability")
    assert all(s["score"] == 100 for s in parseability["sub_scores"])
