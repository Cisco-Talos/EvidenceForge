"""Idle event streams notice peer disconnects without needing a later event."""

import asyncio
import json
from pathlib import Path
from typing import Any

import pytest

from evidenceforge.studio.service import create_app
from tests.unit.test_studio_service import _paths


@pytest.mark.asyncio
async def test_idle_disconnect_releases_subscription_and_keeps_replay_and_delivery(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("EFORGE_STUDIO_DEFAULT_WORKSPACE", str(tmp_path / "workspace"))
    app = create_app(_paths(tmp_path / "private"), "socket-test")
    studio = app.state.studio
    incoming: asyncio.Queue[dict[str, Any]] = asyncio.Queue()
    outgoing: asyncio.Queue[str] = asyncio.Queue()
    accepted = asyncio.Event()

    class Socket:
        query_params = {"token": "socket-test", "after": "0"}

        async def accept(self) -> None:
            accepted.set()

        async def receive(self) -> dict[str, Any]:
            return await incoming.get()

        async def send_text(self, text: str) -> None:
            outgoing.put_nowait(text)

    first = await studio.emit("example", "test.first", {})
    route = next(route for route in app.routes if getattr(route, "path", None) == "/v1/events/ws")
    serving = asyncio.create_task(route.endpoint(Socket()))
    try:
        await asyncio.wait_for(accepted.wait(), timeout=2)
        assert json.loads(await asyncio.wait_for(outgoing.get(), timeout=2))["seq"] == first.seq
        # Client traffic is ignored without losing the event stream.
        incoming.put_nowait({"type": "websocket.receive", "text": "ignored"})
        second = await studio.emit("example", "test.second", {})
        assert json.loads(await asyncio.wait_for(outgoing.get(), timeout=2))["seq"] == second.seq
        assert studio.subscribers
        incoming.put_nowait({"type": "websocket.disconnect", "code": 1000})
        await asyncio.wait_for(serving, timeout=2)
        assert not studio.subscribers
    finally:
        serving.cancel()
        await asyncio.gather(serving, return_exceptions=True)
        await studio.stop()
