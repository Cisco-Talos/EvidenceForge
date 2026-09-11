"""Policy-shim command and timeout negative controls."""

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from experiments.scenario_agent_acceptance.runner import _run_bounded


def _shim_env(tmp_path: Path, fake_eforge: Path) -> dict[str, str]:
    return {
        **os.environ,
        "EFORGE_ACCEPTANCE_WORKSPACE": str(tmp_path / "workspace"),
        "EFORGE_ACCEPTANCE_ARTIFACTS": str(tmp_path / "artifacts"),
        "EFORGE_ACCEPTANCE_TRACE": str(tmp_path / "trace.jsonl"),
        "EFORGE_ACCEPTANCE_REAL_EFORGE": str(fake_eforge),
    }


def test_shim_rejects_generation_and_records_violation(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    fake = tmp_path / "eforge-real"
    fake.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    fake.chmod(0o755)
    shim = Path(__file__).resolve().parents[1] / "shim.py"

    result = subprocess.run(
        [sys.executable, str(shim), "generate", "scenario.yaml"],
        env=_shim_env(tmp_path, fake),
        capture_output=True,
        check=False,
    )

    assert result.returncode == 64
    event = json.loads((tmp_path / "trace.jsonl").read_text(encoding="utf-8"))
    assert event["allowed"] is False
    assert "outside the read-only policy" in event["policy_reason"]


def test_shim_allows_focused_schema(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    fake = tmp_path / "eforge-real"
    fake.write_text('#!/bin/sh\nprintf \'{"selector":"ok"}\\n\'\n', encoding="utf-8")
    fake.chmod(0o755)
    shim = Path(__file__).resolve().parents[1] / "shim.py"

    result = subprocess.run(
        [sys.executable, str(shim), "schema", "event.email_read", "--json"],
        env=_shim_env(tmp_path, fake),
        capture_output=True,
        check=False,
    )

    assert result.returncode == 0
    assert json.loads(result.stdout)["selector"] == "ok"


def test_timeout_terminates_process_group(tmp_path: Path) -> None:
    script = tmp_path / "wait.py"
    script.write_text("import time\ntime.sleep(30)\n", encoding="utf-8")

    with pytest.raises(TimeoutError):
        _run_bounded(
            [sys.executable, str(script)],
            cwd=tmp_path,
            env=dict(os.environ),
            timeout=1,
        )
