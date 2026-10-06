"""Idle helper shutdown, window ownership, and protected background work."""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator, Iterator
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from threading import Event
from unittest.mock import Mock

import pytest
from fastapi.responses import StreamingResponse
from fastapi.testclient import TestClient

from evidenceforge.desktop.controller import _worker_tick
from evidenceforge.desktop.state import GenerationJob
from evidenceforge.studio.service import StudioService, create_app
from evidenceforge.studio.sessions import WindowSessions
from evidenceforge.studio.state_io import StudioStateError
from evidenceforge.studio.state_upgrade import StateCoordinator
from evidenceforge.studio.store import Conversation
from tests.support.studio_state import inventory, legacy, paths


def test_window_grace_reopen_crash_and_late_heartbeat() -> None:
    now = [0.0]
    windows = WindowSessions(clock=lambda: now[0])
    assert not windows.should_exit(False)
    now[0] = 30
    assert not windows.should_exit(False)  # Allow initial startup/maintenance attachment.
    windows.open("one")
    windows.open("two")
    windows.close("one")
    windows.heartbeat("one")  # A request in flight cannot resurrect a closed window.
    assert windows.has_other_windows("one")
    windows.close("two")
    assert not windows.should_exit(False)
    now[0] += 7
    assert not windows.should_exit(False)
    windows.open("one")
    now[0] += 7
    assert not windows.should_exit(False)
    now[0] += 120  # Process crash: the last window never sends a close request.
    assert not windows.should_exit(False)
    now[0] += 8
    assert windows.should_exit(False)
    assert not windows.should_exit(True)
    assert not windows.should_exit(False)
    now[0] += 8
    assert windows.should_exit(False)


def test_unattached_startup_eventually_exits_without_a_window() -> None:
    now = [0.0]
    windows = WindowSessions(clock=lambda: now[0])
    now[0] = 120
    assert not windows.should_exit(False)
    now[0] = 128
    assert windows.should_exit(False)


@pytest.fixture
def idle_client(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> Iterator[tuple[TestClient, list[float]]]:
    async def quiet_start(self: StudioService) -> None:
        return None

    monkeypatch.setattr(StudioService, "start", quiet_start)
    monkeypatch.setenv("EFORGE_STUDIO_DEFAULT_WORKSPACE", str(tmp_path / "workspace"))
    now = [0.0]
    app = create_app(
        paths(tmp_path / "private"), "secret", sessions=WindowSessions(clock=lambda: now[0])
    )
    with TestClient(app) as client:
        yield client, now


def _headers(window: str = "one") -> dict[str, str]:
    return {"X-EForge-Token": "secret", "X-EForge-Session": window}


def _check(client: TestClient) -> bool:
    assert client.portal is not None
    return client.portal.call(client.app.state.check_idle_shutdown)


def _job(client: TestClient, status: str = "queued") -> GenerationJob:
    studio = client.app.state.studio
    job = GenerationJob(
        id="other-workspace-job",
        scenario=studio.paths.data / "other/scenario.yaml",
        workspace=studio.paths.data / "other",
        output_root=studio.paths.data / "other/run",
        progress_file=studio.paths.data / "other/progress.jsonl",
        log_file=studio.paths.data / "other/job.log",
        started_at=1,
        status=status,
    )
    studio.jobs.save_generation(job)
    return job


def test_only_last_window_applies_quit_policy_and_shutdown_fences_requests(
    idle_client: tuple[TestClient, list[float]],
) -> None:
    client, now = idle_client
    studio = client.app.state.studio
    studio.settings.quit.action = "kill"
    for window in ("one", "two"):
        assert client.post("/v1/session/open", headers=_headers(window)).status_code == 200
    before = studio.intent.id
    assert (
        client.post("/v1/session/close", headers=_headers()).json()["status"] == "window detached"
    )
    assert studio.intent.id == before
    now[0] = 60
    assert not _check(client)
    assert client.post("/v1/session/close", headers=_headers("two")).status_code == 200
    assert studio.intent.action == "kill"
    assert not _check(client)
    now[0] += 8
    assert _check(client)
    assert client.post("/v1/session/open", headers=_headers()).status_code == 503
    assert client.get("/v1/bootstrap", headers=_headers()).status_code == 503


def test_failed_close_keeps_window_attached_and_cancel_reopens_it(
    idle_client: tuple[TestClient, list[float]],
) -> None:
    client, now = idle_client
    studio = client.app.state.studio
    client.post("/v1/session/open", headers=_headers())
    studio.settings.quit.action = "pause"
    job = _job(client, "running")
    job.checkpoint_hours = 0
    studio.jobs.save_generation(job)
    assert client.post("/v1/session/close", headers=_headers()).status_code == 409
    assert "one" in client.app.state.sessions.windows
    job.status = "paused"
    studio.jobs.save_generation(job)
    assert client.post("/v1/session/close", headers=_headers()).status_code == 200
    assert client.post("/v1/session/cancel-close", headers=_headers()).status_code == 200
    now[0] += 10
    assert not _check(client)
    assert "one" in client.app.state.sessions.windows


@pytest.mark.parametrize("status", ["queued", "running"])
def test_background_jobs_across_workspaces_hold_helper_until_reconciled(
    idle_client: tuple[TestClient, list[float]], status: str
) -> None:
    client, now = idle_client
    job = _job(client, status)
    client.post("/v1/session/open", headers=_headers())
    client.post("/v1/session/close", headers=_headers())
    assert not _check(client)
    now[0] += 8
    assert not _check(client)
    job.status = "completed"
    client.app.state.studio.jobs.save_generation(job)
    assert not _check(client)
    now[0] += 8
    assert _check(client)


def test_held_queue_does_not_keep_helper_alive(
    idle_client: tuple[TestClient, list[float]],
) -> None:
    client, now = idle_client
    _job(client)
    client.app.state.studio.settings.quit.continue_queued_generations = False
    client.post("/v1/session/open", headers=_headers())
    client.post("/v1/session/close", headers=_headers())
    assert not _check(client)
    now[0] += 8
    assert _check(client)
    assert client.app.state.studio.jobs.load_generations()[0].status == "queued"


def test_authoring_and_indeterminate_worker_ownership_prevent_idle_exit(
    idle_client: tuple[TestClient, list[float]], monkeypatch: pytest.MonkeyPatch
) -> None:
    client, now = idle_client
    studio = client.app.state.studio
    studio.settings.quit.authoring_turns = "finish"
    chat = Conversation(id="chat", workspace=studio.paths.data / "other", active=True)
    studio.store.save_conversation(chat)
    client.post("/v1/session/open", headers=_headers())
    client.post("/v1/session/close", headers=_headers())
    assert not _check(client)
    now[0] += 8
    assert not _check(client)
    chat.active = False
    studio.store.save_conversation(chat)
    workers = Mock(side_effect=StudioStateError("Ownership unavailable"))
    monkeypatch.setattr("evidenceforge.studio.service.check_workers", workers)
    assert not _check(client)
    now[0] += 8
    assert not _check(client)
    workers.side_effect = None
    assert not _check(client)
    now[0] += 8
    assert _check(client)


@pytest.mark.parametrize("activity", ["request", "prediction", "cycle", "authoring_stop"])
def test_inflight_activity_prevents_shutdown(
    idle_client: tuple[TestClient, list[float]], activity: str
) -> None:
    client, now = idle_client
    studio = client.app.state.studio
    client.post("/v1/session/open", headers=_headers())
    client.post("/v1/session/close", headers=_headers())
    assert not _check(client)
    now[0] += 8

    async def hold() -> None:
        if activity == "request":
            studio.active_requests += 1
        elif activity == "authoring_stop":
            studio.authoring_stop_task = asyncio.create_task(asyncio.Event().wait())
        else:
            await getattr(
                studio, "prediction_lock" if activity == "prediction" else "job_cycle_lock"
            ).acquire()

    async def release() -> None:
        if activity == "request":
            studio.active_requests -= 1
        elif activity == "authoring_stop":
            studio.authoring_stop_task.cancel()
            await asyncio.gather(studio.authoring_stop_task, return_exceptions=True)
        else:
            getattr(
                studio, "prediction_lock" if activity == "prediction" else "job_cycle_lock"
            ).release()

    client.portal.call(hold)
    assert not _check(client)
    client.portal.call(release)
    assert not _check(client)
    now[0] += 8
    assert _check(client)


def test_heartbeat_is_authenticated_and_close_tombstone_survives_renewal(
    idle_client: tuple[TestClient, list[float]],
) -> None:
    client, now = idle_client
    assert client.post("/v1/session/heartbeat").status_code == 401
    assert client.post("/v1/session/detach").status_code == 401
    assert client.post("/v1/session/heartbeat", headers=_headers()).status_code == 200
    now[0] = 100
    client.post("/v1/session/heartbeat", headers=_headers())
    assert not _check(client)
    client.post("/v1/session/close", headers=_headers())
    client.post("/v1/session/heartbeat", headers=_headers())
    assert not _check(client)
    now[0] += 8
    assert _check(client)


def test_maintenance_window_keeps_helper_and_unversioned_state_alive(tmp_path: Path) -> None:
    selected = legacy(tmp_path)
    before = inventory(selected.database_file)
    now = [0.0]
    app = create_app(selected, "secret", sessions=WindowSessions(clock=lambda: now[0]))
    with TestClient(app) as client:
        assert app.state.studio is None
        client.post("/v1/session/heartbeat", headers=_headers())
        now[0] = 100
        client.post("/v1/session/heartbeat", headers=_headers())
        assert not _check(client)
        assert client.get("/v1/bootstrap", headers=_headers()).status_code == 503
        assert client.post("/v1/session/detach", headers=_headers()).status_code == 200
        assert not _check(client)
        now[0] += 8
        assert _check(client)
    assert inventory(selected.database_file) == before


def test_window_arriving_during_worker_recheck_cancels_shutdown(
    idle_client: tuple[TestClient, list[float]], monkeypatch: pytest.MonkeyPatch
) -> None:
    client, now = idle_client
    windows = client.app.state.sessions
    client.post("/v1/session/open", headers=_headers())
    client.post("/v1/session/close", headers=_headers())
    assert not _check(client)
    now[0] += 8
    monkeypatch.setattr(
        "evidenceforge.studio.service.check_workers", lambda database: windows.open("new-window")
    )
    assert not _check(client)
    assert not client.app.state.studio.replacement_ready


def test_newly_queued_work_during_worker_recheck_cancels_shutdown(
    idle_client: tuple[TestClient, list[float]], monkeypatch: pytest.MonkeyPatch
) -> None:
    client, now = idle_client
    client.post("/v1/session/open", headers=_headers())
    client.post("/v1/session/close", headers=_headers())
    assert not _check(client)
    now[0] += 8
    monkeypatch.setattr("evidenceforge.studio.service.check_workers", lambda database: _job(client))
    assert not _check(client)
    assert not client.app.state.studio.replacement_ready


def test_multiple_windows_share_one_generation_concurrency_limit(
    idle_client: tuple[TestClient, list[float]], monkeypatch: pytest.MonkeyPatch
) -> None:
    client, _now = idle_client
    studio = client.app.state.studio
    job = _job(client)
    for number in (2, 3):
        studio.jobs.save_generation(job.model_copy(update={"id": f"queued-{number}"}))
    start = Mock(side_effect=[(101, 1.0), (102, 1.0)])
    monkeypatch.setattr("evidenceforge.desktop.controller._start_process", start)
    monkeypatch.setattr("evidenceforge.desktop.controller._running", lambda job: job.pid > 0)
    for window in ("one", "two"):
        client.post("/v1/session/open", headers=_headers(window))
        _worker_tick(studio.jobs, studio.intent)
    assert start.call_count == 2
    assert sorted(job.status for job in studio.jobs.load_generations()) == [
        "queued",
        "running",
        "running",
    ]


def test_streaming_response_keeps_helper_alive_until_body_finishes(
    idle_client: tuple[TestClient, list[float]],
) -> None:
    client, now = idle_client
    entered, finish = Event(), Event()

    async def response_body() -> AsyncIterator[bytes]:
        yield b"first"
        entered.set()
        assert await asyncio.to_thread(finish.wait, 5)
        yield b"last"

    @client.app.get("/test/stream")
    async def stream() -> StreamingResponse:
        return StreamingResponse(response_body())

    client.post("/v1/session/open", headers=_headers())
    with ThreadPoolExecutor(max_workers=1) as pool:
        response = pool.submit(client.get, "/test/stream", headers=_headers())
        try:
            assert entered.wait(5)
            client.post("/v1/session/close", headers=_headers())
            assert not _check(client)
            now[0] += 8
            assert not _check(client)
            assert client.app.state.studio.active_requests == 1
            assert (
                client.post("/v1/runtime/prepare-replacement", headers=_headers()).status_code
                == 409
            )
        finally:
            finish.set()
        assert response.result(timeout=5).content == b"firstlast"
    assert client.app.state.studio.active_requests == 0
    assert not _check(client)
    now[0] += 8
    assert _check(client)


def test_closing_maintenance_does_not_interrupt_an_upgrade(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    selected = legacy(tmp_path)
    now = [0.0]
    entered, finish = Event(), Event()
    original = StateCoordinator.apply

    def held_apply(self: StateCoordinator, identity: str, restore: bool = False) -> object:
        entered.set()
        assert finish.wait(10)
        return original(self, identity, restore)

    async def quiet_start(self: StudioService) -> None:
        return None

    monkeypatch.setattr(StateCoordinator, "apply", held_apply)
    monkeypatch.setattr(StudioService, "start", quiet_start)
    app = create_app(selected, "secret", sessions=WindowSessions(clock=lambda: now[0]))
    with TestClient(app) as client:
        identity = client.get("/v1/state/status", headers=_headers()).json()["operation_id"]
        client.post("/v1/session/heartbeat", headers=_headers())
        try:
            assert (
                client.post(
                    "/v1/state/upgrade", headers=_headers(), json={"operation_id": identity}
                ).status_code
                == 200
            )
            assert entered.wait(10)
            client.post("/v1/session/detach", headers=_headers())
            assert not _check(client)
            now[0] = 500
            assert not _check(client)
        finally:
            finish.set()
    assert app.state.studio is not None
