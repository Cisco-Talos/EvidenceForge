"""Native same-account attachment and launch locking with production helper commands."""

from __future__ import annotations

import os
import subprocess
import sys
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from queue import Queue
from threading import Barrier, Event, Thread

import psutil
import pytest

from evidenceforge.studio import bootstrap
from evidenceforge.studio.ownership import current_account, process_account
from evidenceforge.studio.state_io import StateLock, StudioStateError
from tests.support.studio_state import paths


@pytest.mark.parametrize("trial", range(3))
def test_native_windows_share_one_verified_helper_and_instance_lock(
    tmp_path: Path, trial: int
) -> None:
    selected = paths(tmp_path / f"private-{trial}")
    environment = dict(os.environ)
    environment.pop("EFORGE_STUDIO_RUNTIME_ROOT", None)
    environment["EFORGE_STUDIO_HOME"] = str(selected.data.parent)
    environment["EFORGE_STUDIO_DEFAULT_WORKSPACE"] = str(tmp_path / "workspace")
    environment["EFORGE_DESKTOP_CODEX_BIN"] = str(tmp_path / "no-codex")
    with (tmp_path / "native-helper.log").open("wb") as log:
        child = subprocess.Popen(
            [sys.executable, "-m", "evidenceforge.studio.bootstrap", "--serve"],
            stdin=subprocess.DEVNULL,
            stdout=log,
            stderr=log,
            env=environment,
        )
        try:
            deadline = time.monotonic() + 15
            ready: bootstrap.ServiceDescriptor | None = None
            pause = Event()
            while time.monotonic() < deadline:
                assert child.poll() is None, "Harness-owned helper exited before readiness"
                candidate = bootstrap._read_descriptor(selected.service_file)
                if candidate is not None and bootstrap._is_live(candidate):
                    ready = candidate
                    break
                pause.wait(0.05)  # Bounded readiness polling, not crash-boundary synchronization.
            assert ready is not None, "Native helper readiness deadline failed"
            assert ready.pid == child.pid
            assert ready.schema_version == 1 and ready.owner == current_account()
            assert process_account(psutil.Process(child.pid)) == current_account()
            assert bootstrap._verified_process(ready) is not None
            start = Barrier(4, timeout=8)

            def attach() -> bootstrap.ServiceDescriptor:
                start.wait()
                return bootstrap.connect_or_start(selected)

            with ThreadPoolExecutor(max_workers=4) as pool:
                descriptors = list(pool.map(lambda _: attach(), range(4)))
            assert all(item == ready for item in descriptors)
            lock = StateLock(selected.state / "service-instance.lock")
            with pytest.raises(StudioStateError, match="Another Studio process"):
                lock.acquire()
            request = urllib.request.Request(
                f"{ready.url}/v1/session/open",
                data=b"",
                method="POST",
                headers={"X-EForge-Token": "wrong", "X-EForge-Session": "spoofed"},
            )
            with pytest.raises(urllib.error.HTTPError) as error:
                urllib.request.urlopen(request, timeout=5)
            assert error.value.code == 401
            error.value.close()
            # Exercises both native owner checks around authenticated replacement.
            bootstrap._replace_idle(ready)
            assert child.wait(timeout=8) == 0
            # Uvicorn may replay SIGTERM after lifespan shutdown, leaving stale discovery.
            # The next launch must reject its exited identity, never attach to a recycled PID.
            assert bootstrap._verified_process(ready) is None
            assert not bootstrap._is_live(ready)
            with StateLock(selected.state / "service-instance.lock"):
                pass
        finally:
            # Only the exact unreaped child created by this harness is signalled.
            if child.poll() is None:
                child.terminate()
                try:
                    child.wait(timeout=8)
                except subprocess.TimeoutExpired:
                    child.kill()
                    child.wait(timeout=8)


def test_native_process_owner_is_distinct_from_a_descriptor_claim(tmp_path: Path) -> None:
    child = subprocess.Popen(
        [sys.executable, "-c", "import sys; print('ready',flush=True); sys.stdin.readline()"],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        text=True,
    )
    try:
        assert child.stdout is not None and child.stdin is not None
        ready: Queue[str] = Queue()
        Thread(target=lambda: ready.put(child.stdout.readline()), daemon=True).start()
        assert ready.get(timeout=8).strip() == "ready"
        actual = psutil.Process(child.pid)
        assert process_account(actual) == current_account()
        descriptor = bootstrap.ServiceDescriptor(
            schema_version=1,
            owner=current_account(),
            pid=child.pid,
            created_at=actual.create_time(),
            executable=actual.exe(),
            port=1234,
            token="unused",
        )
        with pytest.raises(StudioStateError, match="identity changed"):
            bootstrap._verified_process(descriptor)
        assert child.poll() is None
        child.stdin.write("finish\n")
        child.stdin.flush()
        assert child.wait(timeout=8) == 0
    finally:
        if child.poll() is None:
            child.terminate()
            child.wait(timeout=8)
        if child.stdin:
            child.stdin.close()
        if child.stdout:
            child.stdout.close()
