"""Ordered public CLI admission diagnostics before generation acquires workspace ownership."""

from pathlib import Path

import pytest
from rich.console import Console
from typer.testing import CliRunner

from evidenceforge.cli import commands


@pytest.mark.parametrize(
    ("arguments", "expected"),
    [
        (
            ["--resume", "--overwrite", "--resume-policy", "unknown"],
            "Error: --resume-policy must be exact, compatible, or attempt\n",
        ),
        (
            ["--resume", "--force"],
            "Error: --resume conflicts with --overwrite/--force\n",
        ),
        (
            ["--force"],
            "Warning: --force/-f is deprecated; use --overwrite.\n"
            "Error: A scenario file is required unless --resume is used\n",
        ),
        ([], "Error: A scenario file is required unless --resume is used\n"),
        (["--resume"], "Error: --output is required for checkpoint-only resume\n"),
    ],
)
def test_public_generation_admission_preserves_first_failure(
    arguments: list[str], expected: str, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(commands, "console", Console(width=240, force_terminal=False))
    monkeypatch.chdir(tmp_path)
    result = CliRunner().invoke(commands.app, ["generate", *arguments])
    assert result.exit_code == commands.EXIT_INPUT_ERROR
    assert result.stdout == expected
    assert list(tmp_path.iterdir()) == []


def test_public_generation_target_failure_precedes_loading(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    scenario = tmp_path / "scenario.yaml"
    scenario.write_text("not a valid scenario")
    monkeypatch.setattr(commands, "console", Console(width=240, force_terminal=False))
    result = CliRunner().invoke(
        commands.app,
        ["generate", str(scenario), "--target", "missing-target"],
    )
    assert result.exit_code == commands.EXIT_INPUT_ERROR
    assert "Loading scenario" not in result.stdout
    assert result.stdout == (
        "Error: invalid output target value; expected one of: default, sof-elk, splunk\n"
    )
    assert sorted(path.name for path in tmp_path.iterdir()) == ["scenario.yaml"]
