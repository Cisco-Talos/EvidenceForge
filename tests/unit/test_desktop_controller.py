"""Headless desktop worker ownership, quit, and checkpoint contracts."""

from __future__ import annotations

import json
import subprocess
import sys
import time
from collections.abc import Callable
from pathlib import Path

import pytest

from evidenceforge.desktop import controller
from evidenceforge.desktop.job_store import ControlIntent, JobStore
from evidenceforge.desktop.jobs import queue_generation
from evidenceforge.desktop.state import AppSettings, EvaluationJob, GenerationJob


def _generation(root: Path, name: str, *, status: str = "queued") -> GenerationJob:
    scenario = root / "scenarios" / name / "scenario.yaml"
    scenario.parent.mkdir(parents=True, exist_ok=True)
    scenario.write_text("version: '1.0'\nname: demo\n", encoding="utf-8")
    bundle = root / "runs" / name / "run-1"
    bundle.mkdir(parents=True, exist_ok=True)
    return GenerationJob(
        id=name,
        scenario=scenario,
        output_root=bundle,
        progress_file=root / f"{name}.jsonl",
        log_file=root / f"{name}.log",
        started_at=time.time(),
        status=status,
        workspace=root,
        command=[sys.executable, "-c", "pass"],
        owned_output=True,
    )


def _evaluation(root: Path, generation_id: str) -> EvaluationJob:
    return EvaluationJob(
        id=f"eval-{generation_id}",
        generation_id=generation_id,
        workspace=root,
        output_root=root / "runs" / generation_id / "run-1",
        result_file=root / f"eval-{generation_id}.json",
        log_file=root / f"eval-{generation_id}.log",
        command=[sys.executable, "-c", "pass"],
        created_at=time.time(),
    )


def test_controller_applies_continue_pause_and_kill_options(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = JobStore(tmp_path / "state")
    running = _generation(tmp_path, "running", status="running")
    running.pid = 42
    running.process_created_at = 42.0
    queued = _generation(tmp_path, "queued")
    evaluation = _evaluation(tmp_path, "running")
    evaluation.status = "running"
    evaluation.pid = 43
    evaluation.process_created_at = 43.0
    for job in (running, queued):
        store.save_generation(job)
    store.save_evaluation(evaluation)
    monkeypatch.setattr(controller, "_running", lambda job: job.pid > 0)
    terminated: list[int] = []
    monkeypatch.setattr(controller, "_terminate_owned", lambda job: terminated.append(job.pid))
    monkeypatch.setattr(
        controller,
        "request_suspension",
        lambda _job, _workspace: subprocess.CompletedProcess([], 0, "", ""),
    )
    settings = AppSettings(continue_queued_generations=False, continue_evaluations="hold")
    controller._worker_tick(store, ControlIntent(action="continue", settings=settings))
    assert next(job for job in store.load_generations() if job.id == "queued").status == "queued"
    assert store.load_evaluations()[0].status == "paused"
    assert terminated == [43]

    settings.pause_evaluations = "restart"
    controller._worker_tick(store, ControlIntent(action="pause", settings=settings))
    generations = {job.id: job for job in store.load_generations()}
    assert generations["running"].status_message == "Pause requested"
    assert generations["queued"].status == "paused"

    settings.kill_incomplete_bundles = "preserve"
    controller._worker_tick(store, ControlIntent(action="kill", settings=settings))
    assert {job.id: job.status for job in store.load_generations()} == {
        "running": "stopped",
        "queued": "cancelled",
    }
    assert 42 in terminated
    assert running.output_root.is_dir()


def test_continue_starts_queued_work_and_manual_evaluation_requires_restart(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = JobStore(tmp_path / "state")
    generation = _generation(tmp_path, "queued")
    evaluation = _evaluation(tmp_path, generation.id)
    store.save_generation(generation)
    store.save_evaluation(evaluation)
    commands: list[list[str]] = []

    def start(command: list[str], *, cwd: Path, log_file: Path) -> tuple[int, float]:
        commands.append(command)
        return 101, 101.0

    monkeypatch.setattr(controller, "_start_process", start)
    controller._worker_tick(
        store,
        ControlIntent(
            action="continue",
            settings=AppSettings(continue_evaluations="manual"),
        ),
    )
    assert store.load_generations()[0].status == "running"
    assert store.load_evaluations()[0].status == "cancelled"
    assert commands == [generation.command]


def test_pause_evaluation_finish_and_restart_policies(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = JobStore(tmp_path / "state")
    active = _evaluation(tmp_path, "active")
    active.status = "running"
    active.pid = 123
    active.process_created_at = 123.0
    queued = _evaluation(tmp_path, "queued")
    store.save_evaluation(active)
    store.save_evaluation(queued)
    monkeypatch.setattr(controller, "_running", lambda job: job.pid == 123)
    stopped: list[int] = []
    monkeypatch.setattr(controller, "_terminate_owned", lambda job: stopped.append(job.pid))

    controller._worker_tick(
        store, ControlIntent(action="pause", settings=AppSettings(pause_evaluations="finish"))
    )
    records = {job.generation_id: job for job in store.load_evaluations()}
    assert records["active"].status == "running"
    assert records["queued"].status == "paused"
    assert stopped == []

    controller._worker_tick(
        store, ControlIntent(action="pause", settings=AppSettings(pause_evaluations="restart"))
    )
    assert {job.status for job in store.load_evaluations()} == {"paused"}
    assert stopped == [123]

    resumed: list[str] = []

    def start_evaluation(job: EvaluationJob) -> None:
        resumed.append(job.generation_id)
        job.status = "running"

    monkeypatch.setattr(controller, "_start_evaluation", start_evaluation)
    controller._worker_tick(store, ControlIntent(action="resume"))
    assert set(resumed) == {"active", "queued"}


def test_resume_one_generation_leaves_other_paused_work_untouched(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = JobStore(tmp_path / "state")
    first = _generation(tmp_path, "first", status="paused")
    second = _generation(tmp_path, "second", status="paused")
    (first.output_root / ".eforge-generation").mkdir()
    (second.output_root / ".eforge-generation").mkdir()
    store.save_generation(first)
    store.save_generation(second)
    evaluation = _evaluation(tmp_path, "first")
    evaluation.status = "paused"
    store.save_evaluation(evaluation)
    resumed: list[str] = []

    def resume(job: GenerationJob, workspace: Path, state_directory: Path) -> None:
        resumed.append(job.id)
        job.status = "running"

    monkeypatch.setattr(controller, "resume_generation", resume)
    controller._worker_tick(store, ControlIntent(action="resume", resume_generation_id="first"))
    assert resumed == ["first"]
    assert {job.id: job.status for job in store.load_generations()} == {
        "first": "running",
        "second": "paused",
    }
    assert store.load_evaluations()[0].status == "paused"


def test_kill_policy_deletes_only_verified_incomplete_bundles(tmp_path: Path) -> None:
    store = JobStore(tmp_path / "state")
    jobs = [_generation(tmp_path, name) for name in ("owned", "complete", "imported")]
    for job in jobs:
        (job.output_root / ".eforge-desktop-job.json").write_text(
            json.dumps({"job_id": job.id}), encoding="utf-8"
        )
        store.save_generation(job)
    (jobs[1].output_root / "GENERATION_MANIFEST.json").write_text("{}", encoding="utf-8")
    jobs[2].owned_output = False
    store.save_generation(jobs[2])
    controller._worker_tick(
        store,
        ControlIntent(action="kill", settings=AppSettings(kill_incomplete_bundles="delete")),
    )
    assert not jobs[0].output_root.exists()
    assert jobs[1].output_root.exists()
    assert jobs[2].output_root.exists()


def test_kill_deletes_only_marked_incomplete_app_bundle(tmp_path: Path) -> None:
    owned = _generation(tmp_path, "owned", status="stopped")
    marker = owned.output_root / ".eforge-desktop-job.json"
    marker.write_text(json.dumps({"job_id": owned.id}), encoding="utf-8")
    complete = _generation(tmp_path, "complete", status="completed")
    (complete.output_root / ".eforge-desktop-job.json").write_text(
        json.dumps({"job_id": complete.id}), encoding="utf-8"
    )
    (complete.output_root / "GENERATION_MANIFEST.json").write_text("{}", encoding="utf-8")
    imported = _generation(tmp_path, "imported", status="stopped")
    imported.owned_output = False
    assert controller._delete_owned_incomplete(owned)
    assert not owned.output_root.exists()
    assert not controller._delete_owned_incomplete(complete)
    assert not controller._delete_owned_incomplete(imported)
    assert complete.output_root.exists() and imported.output_root.exists()


def test_pause_setting_rejects_new_checkpoint_disabled_run(tmp_path: Path) -> None:
    scenario = tmp_path / "scenario.yaml"
    scenario.write_text("version: '1.0'\n", encoding="utf-8")
    with pytest.raises(ValueError, match="requires checkpointing"):
        queue_generation(
            scenario,
            tmp_path,
            tmp_path / "state",
            settings=AppSettings(close_action="pause"),
            checkpoint_hours=0,
        )


def test_queued_generation_marker_and_flags_work_with_real_cli(tmp_path: Path) -> None:
    repository = Path(__file__).resolve().parents[2]
    scenario = repository / "tests" / "fixtures" / "scenarios" / "minimal.yaml"
    job = queue_generation(scenario, repository, tmp_path / "state", tmp_path / "runs")
    job.progress_file.parent.mkdir(parents=True, exist_ok=True)
    completed = subprocess.run(
        job.command,
        cwd=repository,
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )
    assert completed.returncode == 0, completed.stderr[-2000:]
    assert (job.output_root / "GENERATION_MANIFEST.json").is_file()
    assert (job.output_root / ".eforge-desktop-job.json").is_file()
    assert job.progress_file.is_file()


def test_pid_mismatch_does_not_kill_unrelated_process(tmp_path: Path) -> None:
    process = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(30)"])
    try:
        job = _generation(tmp_path, "unrelated", status="running")
        job.pid = process.pid
        job.process_created_at = 1.0
        controller._terminate_owned(job)
        assert process.poll() is None
        actual_start = controller.psutil.Process(process.pid).create_time()
        job.process_created_at = actual_start + 0.5
        controller._terminate_owned(job)
        assert process.poll() is None
        job.process_created_at = actual_start
        controller._terminate_owned(job)
        process.wait(timeout=5)
        assert process.poll() is not None
    finally:
        if process.poll() is None:
            process.kill()
            process.wait(timeout=5)


def test_process_exit_during_group_lookup_does_not_break_quit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    if sys.platform == "win32":
        pytest.skip("POSIX process group lookup")
    process = subprocess.Popen(
        [sys.executable, "-c", "import time; time.sleep(30)"], start_new_session=True
    )
    try:
        job = _generation(tmp_path, "exiting", status="running")
        job.pid = process.pid
        job.process_created_at = controller.psutil.Process(process.pid).create_time()

        def process_exited(_pid: int) -> int:
            raise ProcessLookupError("process exited before group lookup")

        monkeypatch.setattr(controller.os, "getpgid", process_exited)
        controller._terminate_owned(job)
        assert process.poll() is None
    finally:
        process.kill()
        process.wait(timeout=5)


def _fake_cli(tmp_path: Path) -> Path:
    script = tmp_path / "fake_cli.py"
    script.write_text(
        "import json, pathlib, sys, time\n"
        "args = sys.argv[1:]\n"
        "if args[0] == 'checkpoint':\n"
        "    (pathlib.Path(args[-1]) / 'suspend-request').write_text('yes')\n"
        "elif args[0] == 'eval':\n"
        "    time.sleep(.8)\n"
        "    print(json.dumps({'scenario_name': 'demo', "
        "'evaluated_at': '2026-09-29T12:00:00Z', 'overall_score': 91}))\n"
        "elif args[0] == 'generate':\n"
        "    root = pathlib.Path(args[args.index('--output') + 1])\n"
        "    progress = pathlib.Path(args[args.index('--progress-jsonl') + 1])\n"
        "    progress.parent.mkdir(parents=True, exist_ok=True)\n"
        "    (root / '.eforge-generation').mkdir(exist_ok=True)\n"
        "    if '--resume' in args:\n"
        "        (root / 'suspend-request').unlink(missing_ok=True)\n"
        "    for number in range(1, 9):\n"
        "        with progress.open('a') as stream:\n"
        "            stream.write(json.dumps({'schema_version': 1, 'event': 'hour_progress', "
        "'data': {'hour': number, 'total_hours': 8, 'completed_simulated_hours': number, "
        "'total_simulated_hours': 8}}) + '\\n')\n"
        "        if (root / 'suspend-request').exists():\n"
        "            checkpoint = root / '.eforge-generation'\n"
        "            (checkpoint / 'CURRENT.json').write_text(json.dumps({\n"
        "                'recoveries': [{'sequence': 1, 'manifest_sha256': '0' * 64}]}))\n"
        "            (checkpoint / 'suspended.json').write_text(json.dumps({\n"
        "                'kind': 'evidenceforge.generation-suspended', 'schema_version': '1.0',\n"
        "                'request_id': 'fake-request', 'completed_ns': time.time_ns(),\n"
        "                'cursor': {'phase': 'tail', 'completed_simulated_hours': number,\n"
        "                           'next_hour': None}}))\n"
        "            sys.exit(0)\n"
        "        time.sleep(.12)\n"
        "    (root / 'GENERATION_MANIFEST.json').write_text('{}')\n",
        encoding="utf-8",
    )
    return script


def _wait_for(predicate: Callable[[], bool], *, timeout: float = 8) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return
        time.sleep(0.05)
    raise AssertionError("Timed out waiting for desktop job state")


def test_background_controller_checkpoints_after_handoff(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fake_cli = _fake_cli(tmp_path)
    monkeypatch.setattr(
        "evidenceforge.desktop.jobs._eforge_command",
        lambda settings=None: [sys.executable, str(fake_cli)],
    )
    workspace = tmp_path / "workspace"
    scenario = _generation(workspace, "pause-me").scenario
    directory = tmp_path / "state"
    jobs = JobStore(directory)
    generation = queue_generation(scenario, workspace, directory)
    jobs.save_generation(generation)
    jobs.write_control(ControlIntent(action="open"))
    controller.ensure_controller(directory)
    _wait_for(lambda: jobs.load_generations()[0].status == "running")
    intent = ControlIntent(action="pause", settings=AppSettings(close_action="pause"))
    jobs.write_control(intent)
    _wait_for(lambda: jobs.acknowledged(intent.id))
    _wait_for(lambda: jobs.load_generations()[0].status == "paused")
    paused = jobs.load_generations()[0]
    assert paused.progress_file.is_file()
    assert not (paused.output_root / "GENERATION_MANIFEST.json").exists()
    jobs.write_control(ControlIntent(action="resume"))
    controller.ensure_controller(directory)
    _wait_for(lambda: jobs.load_generations()[0].status == "completed")
    assert (paused.output_root / "GENERATION_MANIFEST.json").exists()
