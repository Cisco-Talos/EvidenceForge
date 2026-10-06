"""Real helper exit and background worker preservation in disposable roots."""

from __future__ import annotations

import asyncio
import json
import os
import subprocess
import sys
import urllib.request
from collections.abc import Iterator
from contextlib import closing, contextmanager
from pathlib import Path
from queue import Queue
from threading import Thread

import psutil
import pytest

from evidenceforge.desktop.state import GenerationJob
from evidenceforge.studio.bootstrap import ServiceDescriptor
from evidenceforge.studio.service import StudioService
from evidenceforge.studio.state_upgrade import StateCoordinator
from evidenceforge.studio.store import StudioStore
from tests.support.studio_state import paths


@contextmanager
def helper_process(tmp_path: Path) -> Iterator[tuple[subprocess.Popen[str], ServiceDescriptor]]:
    environment = dict(os.environ)
    environment.pop("EFORGE_STUDIO_RUNTIME_ROOT", None)
    with (tmp_path / "helper.log").open("w") as log:
        process = subprocess.Popen(
            [sys.executable, "-m", "tests.support.studio_helper", str(tmp_path)],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=log,
            text=True,
            env=environment,
        )
        try:
            ready: Queue[str] = Queue()
            assert process.stdout is not None
            Thread(target=lambda: ready.put(process.stdout.readline()), daemon=True).start()
            assert ready.get(timeout=15).strip() == "ready"
            descriptor = ServiceDescriptor.model_validate_json(
                paths(tmp_path / "private").service_file.read_text()
            )
            assert descriptor.pid == process.pid
            yield process, descriptor
        finally:
            # Only this harness's unreaped Popen child is eligible for cleanup.
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=8)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=8)
            process.stdout.close()


@pytest.fixture
def helper(tmp_path: Path) -> Iterator[tuple[subprocess.Popen[str], ServiceDescriptor]]:
    with helper_process(tmp_path) as selected:
        yield selected


def _request(descriptor: ServiceDescriptor, path: str, window: str = "one") -> dict[str, str]:
    request = urllib.request.Request(
        f"{descriptor.url}{path}",
        headers={"X-EForge-Token": descriptor.token, "X-EForge-Session": window},
        data=b"",
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=5) as response:
        return json.loads(response.read())


def test_real_helper_exits_after_last_window_and_releases_state_ownership(
    helper: tuple[subprocess.Popen[str], ServiceDescriptor], tmp_path: Path
) -> None:
    process, descriptor = helper
    _request(descriptor, "/v1/session/open", "one")
    _request(descriptor, "/v1/session/open", "two")
    assert _request(descriptor, "/v1/session/close")["status"] == "window detached"
    assert _request(descriptor, "/v1/session/heartbeat", "two")["status"] == "window alive"
    assert process.poll() is None
    _request(descriptor, "/v1/session/close", "two")
    assert process.wait(timeout=8) == 0
    selected = paths(tmp_path / "private")
    assert not selected.service_file.exists()
    with closing(StateCoordinator(selected)) as coordinator:
        assert coordinator.status.state == "ready"


def test_real_helper_retains_verified_worker_then_exits_when_it_finishes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    selected = paths(tmp_path / "private")
    monkeypatch.setenv("EFORGE_STUDIO_DEFAULT_WORKSPACE", str(tmp_path / "workspace"))
    seeded = StudioService(selected, "seed")
    asyncio.run(seeded.stop())
    # This worker waits for an explicit parent barrier instead of timing its exit.
    worker = subprocess.Popen(
        [sys.executable, "-c", "import sys; print('ready', flush=True); sys.stdin.readline()"],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        text=True,
    )
    try:
        ready: Queue[str] = Queue()
        Thread(target=lambda: ready.put(worker.stdout.readline()), daemon=True).start()
        assert ready.get(timeout=8).strip() == "ready"
        job = GenerationJob(
            id="owned-worker",
            scenario=tmp_path / "workspace/scenario.yaml",
            workspace=tmp_path / "workspace",
            output_root=tmp_path / "workspace/run",
            progress_file=tmp_path / "workspace/progress.jsonl",
            log_file=tmp_path / "workspace/worker.log",
            status="running",
            started_at=1,
            pid=worker.pid,
            process_created_at=psutil.Process(worker.pid).create_time(),
        )
        with closing(StudioStore(selected.database_file)) as store:
            store.save_job(job.id, job.workspace, "generation", job)
        with helper_process(tmp_path) as (process, descriptor):
            _request(descriptor, "/v1/session/open")
            _request(descriptor, "/v1/session/close")
            with pytest.raises(subprocess.TimeoutExpired):
                process.wait(timeout=2.5)
            assert worker.poll() is None
            worker.stdin.write("finish\n")
            worker.stdin.flush()
            assert worker.wait(timeout=8) == 0
            assert process.wait(timeout=8) == 0
            with closing(StudioStore(selected.database_file)) as store:
                assert store.job_payloads()[0]["status"] == "stopped"
            assert not selected.service_file.exists()
    finally:
        if worker.poll() is None:
            worker.terminate()
            worker.wait(timeout=8)
        worker.stdin.close()
        worker.stdout.close()
