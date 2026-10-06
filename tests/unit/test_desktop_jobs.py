"""Desktop generation survives its launching application process."""

from __future__ import annotations

import os
import subprocess
import sys
import time
from pathlib import Path

import psutil
import pytest

from evidenceforge.desktop import jobs
from evidenceforge.desktop.jobs import process_running, refresh_status
from evidenceforge.desktop.progress import GenerationProgress, parse_progress_line
from evidenceforge.desktop.state import StateStore


def test_detached_generation_can_be_rediscovered_after_launcher_exits(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    scenario = workspace / "scenario.yaml"
    scenario.write_text("version: '1.0'\n", encoding="utf-8")
    executable = tmp_path / "fake-eforge"
    executable.write_text(
        f"#!{sys.executable}\n"
        "import json, pathlib, sys, time\n"
        "progress = pathlib.Path(sys.argv[sys.argv.index('--progress-jsonl') + 1])\n"
        "progress.write_text(json.dumps({'schema_version': 1, 'event': 'hour_progress', "
        "'data': {'hour': 2, 'total_hours': 8, 'completed_simulated_hours': 1, "
        "'total_simulated_hours': 16}}) + '\\n')\n"
        "time.sleep(30)\n",
        encoding="utf-8",
    )
    executable.chmod(0o755)
    state_dir = tmp_path / "state"
    launcher = (
        "import sys\n"
        "from pathlib import Path\n"
        "from evidenceforge.desktop.jobs import start_generation\n"
        "from evidenceforge.desktop.state import DesktopState, StateStore\n"
        "workspace, scenario, state_dir = map(Path, sys.argv[1:])\n"
        "job = start_generation(scenario, workspace, state_dir)\n"
        "StateStore(state_dir).save(DesktopState(workspace=workspace, jobs=[job]))\n"
    )
    environment = os.environ.copy()
    environment["EFORGE_DESKTOP_EFORGE_BIN"] = str(executable)
    subprocess.run(
        [sys.executable, "-c", launcher, str(workspace), str(scenario), str(state_dir)],
        env=environment,
        check=True,
        timeout=10,
    )
    job = StateStore(state_dir).load(workspace).jobs[0]
    try:
        deadline = time.monotonic() + 5
        while not job.progress_file.is_file() and time.monotonic() < deadline:
            time.sleep(0.05)
        assert process_running(job)
        event = parse_progress_line(job.progress_file.read_text(encoding="utf-8").strip())
        assert event is not None
        progress = GenerationProgress()
        progress.apply(event)
        assert (progress.completed_hours, progress.total_hours) == (1, 16)
    finally:
        if process_running(job):
            psutil.Process(job.pid).kill()
    deadline = time.monotonic() + 5
    while process_running(job) and time.monotonic() < deadline:
        time.sleep(0.05)
    assert refresh_status(job)
    assert job.status == "stopped"


def test_generation_uses_selected_output_parent(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    scenario = tmp_path / "scenario.yaml"
    scenario.write_text("version: '1.0'\n", encoding="utf-8")
    destination = tmp_path / "chosen-output"
    commands: list[list[str]] = []

    def fake_start_process(command: list[str], *, cwd: Path, log_file: Path) -> tuple[int, float]:
        commands.append(command)
        return 12345, 12345.0

    monkeypatch.setattr(jobs, "_start_process", fake_start_process)
    job = jobs.start_generation(scenario, tmp_path, tmp_path / "app-state", destination)

    assert job.output_root.parent == destination / "scenario"
    assert commands[0][commands[0].index("--output") + 1] == str(job.output_root)
