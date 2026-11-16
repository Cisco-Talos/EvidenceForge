"""Fresh native CLI configuration scopes through Python, PowerShell and the launcher."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

pytestmark = pytest.mark.skipif(os.name != "nt", reason="Native Windows CLI configuration")
_PACKAGED_PYTHON = os.environ.get("EFORGE_TEST_WINDOWS_PYTHON")
_ENTRY_POINTS = (
    ("python", "powershell", "launcher") if _PACKAGED_PYTHON else ("python", "powershell")
)


@pytest.fixture(scope="module")
def windows_cli_python(tmp_path_factory: pytest.TempPathFactory) -> Path:
    if not _PACKAGED_PYTHON:
        return Path(sys.executable).resolve()
    bootstrap = Path(_PACKAGED_PYTHON).resolve()
    data = tmp_path_factory.mktemp("cli private runtime ü 汉")
    installed = subprocess.run(
        [
            str(bootstrap),
            "-I",
            "-B",
            "-X",
            "utf8",
            "-c",
            "import sys; from pathlib import Path; "
            "from evidenceforge.studio.windows_runtime import install_runtime; "
            "print(install_runtime(Path(sys.argv[1]), Path(sys.argv[2])))",
            str(bootstrap.parents[1]),
            str(data),
        ],
        capture_output=True,
        encoding="utf-8",
        timeout=180,
        check=False,
    )
    assert installed.returncode == 0, installed.stdout + installed.stderr
    python = Path(installed.stdout.strip()) / "python.exe"
    assert python.is_file()
    assert (python.parent / "release.json").is_file()
    return python


@pytest.mark.parametrize("entry_point", _ENTRY_POINTS)
@pytest.mark.parametrize("operation", ["formats", "validate", "environment"])
def test_cli_configuration_from_draft(
    tmp_path: Path, windows_cli_python: Path, entry_point: str, operation: str
) -> None:
    workspace = tmp_path.resolve() / "author's workspace ü 汉"
    draft = workspace / ".eforge/artifacts/drafts/scenario/test/revision/source"
    draft.mkdir(parents=True)
    source = draft / "scenario.yaml"
    fixture = Path(__file__).resolve().parents[1] / "fixtures/scenarios/minimal.yaml"
    shutil.copyfile(fixture, source)
    before = source.read_bytes()
    arguments = {
        "formats": ["info", "formats", "--json"],
        "validate": ["validate", str(source), "--json"],
        "environment": [
            "resolve",
            str(source),
            "--explain-composition",
            "--include-effective-scenario",
            "--include-declaration-sources",
            "--json",
        ],
    }[operation] + ["--project-root", str(workspace)]
    python = windows_cli_python
    command = [str(python), "-I", "-B", "-X", "utf8", "-m", "evidenceforge", *arguments]
    if entry_point == "launcher":
        command = [str(python.parent / "Scripts/eforge.exe"), *arguments]
    elif entry_point == "powershell":
        powershell = (
            Path(os.environ["SystemRoot"]) / "System32/WindowsPowerShell/v1.0/powershell.exe"
        )
        expression = "& " + " ".join(
            "'" + argument.replace("'", "''") + "'" for argument in command
        )
        command = [str(powershell), "-NoProfile", "-NonInteractive", "-Command", expression]
    environment = {
        key: value
        for key, value in os.environ.items()
        if key not in {"PYTHONPATH", "PYTHONHOME", "EFORGE_STUDIO_RUNTIME_ROOT"}
    }
    if _PACKAGED_PYTHON:
        # The private interpreter/launcher must work without development tools.
        environment["PATH"] = str(Path(os.environ["SystemRoot"]) / "System32")
        environment["EFORGE_STUDIO_RUNTIME_ROOT"] = str(python.parent)
    completed = subprocess.run(
        command,
        cwd=draft.parent,
        env=environment,
        capture_output=True,
        encoding="utf-8",
        timeout=120,
        check=False,
    )
    assert completed.returncode == 0, completed.stdout + completed.stderr
    payload = json.loads(completed.stdout)
    if operation == "formats":
        assert "windows_event_security" in payload
    else:
        assert payload["valid"] is True, payload
        if operation == "environment":
            assert payload["effective_scenario"]["environment"]["systems"]
    assert source.read_bytes() == before
