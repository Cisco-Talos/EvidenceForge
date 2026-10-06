"""Async JSON-RPC transport for the local Codex app-server."""

from __future__ import annotations

import asyncio
import json
import logging
import sqlite3
from collections.abc import Awaitable, Callable
from pathlib import Path
from typing import Any

from evidenceforge.studio.runtime import command_environment, discover_codex

logger = logging.getLogger(__name__)

MAX_PROTOCOL_LINE_BYTES = 64 * 1024 * 1024

CodexEvent = Callable[[str, dict[str, Any]], Awaitable[None]]
CodexRequest = Callable[[int | str, str, dict[str, Any]], Awaitable[None]]


class CodexUnavailableError(RuntimeError):
    """The configured Codex process is unavailable or rejected a request."""


class CodexTimeoutError(CodexUnavailableError):
    """Codex did not answer a bounded request while its process remained open."""


class CodexThreadNotReadyError(CodexUnavailableError):
    """A newly started Codex thread has not written readable session metadata yet."""


class CodexClient:
    """Keep one app-server process alive across all Studio windows and chats."""

    def __init__(
        self,
        binary: Path | None,
        on_event: CodexEvent,
        on_request: CodexRequest,
    ) -> None:
        self.binary = binary
        self.on_event = on_event
        self.on_request = on_request
        self.process: asyncio.subprocess.Process | None = None
        self.reader_task: asyncio.Task[None] | None = None
        self.stderr_task: asyncio.Task[None] | None = None
        self.dispatch_task: asyncio.Task[None] | None = None
        self.notifications: (
            asyncio.Queue[tuple[str, int | str | None, str, dict[str, Any]]] | None
        ) = None
        self.pending: dict[int, asyncio.Future[dict[str, Any]]] = {}
        self.next_id = 1
        self.write_lock = asyncio.Lock()
        self.start_lock = asyncio.Lock()
        self.stderr_tail = ""

    async def start(self) -> None:
        """Start and initialize Codex lazily, or reuse a healthy connection."""
        async with self.start_lock:
            if (
                self.process is not None
                and self.process.returncode is None
                and self.reader_task is not None
                and not self.reader_task.done()
                and self.dispatch_task is not None
                and not self.dispatch_task.done()
            ):
                return
            await self._stop_transport()
            command = discover_codex(self.binary)
            if not command:
                raise CodexUnavailableError("Codex CLI was not found; set its path in Settings")
            try:
                self.process = await asyncio.create_subprocess_exec(
                    command,
                    "app-server",
                    stdin=asyncio.subprocess.PIPE,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                    limit=MAX_PROTOCOL_LINE_BYTES,
                    env=command_environment(),
                )
            except OSError as error:
                raise CodexUnavailableError(f"Could not start Codex: {error}") from error
            process = self.process
            self.notifications = asyncio.Queue()
            self.dispatch_task = asyncio.create_task(
                self._dispatch_notifications(self.notifications)
            )
            self.reader_task = asyncio.create_task(self._read_stdout(process, self.notifications))
            self.stderr_task = asyncio.create_task(self._read_stderr(process))
            try:
                await self._request(
                    "initialize",
                    {
                        "clientInfo": {
                            "name": "evidenceforge_studio",
                            "title": "EvidenceForge Studio",
                            "version": "0.1.0",
                        }
                    },
                    timeout=15,
                )
                await self._write({"method": "initialized", "params": {}})
                await self.on_event("codex/connected", {})
            except (CodexUnavailableError, OSError):
                await self._stop_transport()
                raise

    async def stop(self) -> None:
        """Close the owned transport during service shutdown."""
        async with self.start_lock:
            await self._stop_transport()

    async def _stop_transport(self) -> None:
        """Stop only the subprocess and tasks owned by this client."""
        process = self.process
        self.process = None
        if process is not None and process.returncode is None:
            process.terminate()
            try:
                await asyncio.wait_for(process.wait(), timeout=2)
            except TimeoutError:
                process.kill()
                await process.wait()
        for task in (self.reader_task, self.stderr_task, self.dispatch_task):
            if task is not None:
                task.cancel()
        await asyncio.gather(
            *(task for task in (self.reader_task, self.stderr_task, self.dispatch_task) if task),
            return_exceptions=True,
        )
        for future in self.pending.values():
            if not future.done():
                future.set_exception(CodexUnavailableError("Codex connection closed"))
        self.reader_task = None
        self.stderr_task = None
        self.dispatch_task = None
        self.notifications = None

    async def reconnect(self) -> None:
        """Replace an unresponsive owned process while retaining saved Codex threads."""
        await self.stop()
        await self.start()

    async def call(
        self, method: str, params: dict[str, Any] | None = None, *, timeout: float = 30
    ) -> dict[str, Any]:
        """Call one Codex RPC method and return its result object."""
        await self.start()
        return await self._request(method, params, timeout=timeout)

    async def respond(self, request_id: int | str, result: dict[str, Any]) -> None:
        """Answer a server-initiated request only after user input."""
        await self._write({"id": request_id, "result": result})

    async def _request(
        self, method: str, params: dict[str, Any] | None, *, timeout: float
    ) -> dict[str, Any]:
        request_id = self.next_id
        self.next_id += 1
        future: asyncio.Future[dict[str, Any]] = asyncio.get_running_loop().create_future()
        self.pending[request_id] = future
        request: dict[str, Any] = {"id": request_id, "method": method, "params": params or {}}

        async def send_and_wait() -> dict[str, Any]:
            await self._write(request)
            return await future

        try:
            message = await asyncio.wait_for(send_and_wait(), timeout=timeout)
        except TimeoutError as error:
            raise CodexTimeoutError(
                f"Codex did not answer {method} within {timeout:g} seconds"
            ) from error
        except OSError as error:
            raise CodexUnavailableError(f"Codex {method} failed: {error}") from error
        finally:
            self.pending.pop(request_id, None)
            if not future.done():
                future.cancel()
        if "error" in message:
            detail = message["error"]
            reason = detail.get("message", str(detail)) if isinstance(detail, dict) else str(detail)
            if (
                method == "thread/read"
                and "failed to read session metadata" in reason
                and "is empty" in reason
            ):
                raise CodexThreadNotReadyError("Codex is still saving this conversation")
            raise CodexUnavailableError(f"Codex {method}: {reason}")
        result = message.get("result", {})
        return result if isinstance(result, dict) else {"value": result}

    async def _write(self, message: dict[str, Any]) -> None:
        process = self.process
        if process is None or process.stdin is None or process.returncode is not None:
            raise CodexUnavailableError("Codex is disconnected")
        async with self.write_lock:
            process.stdin.write((json.dumps(message, separators=(",", ":")) + "\n").encode())
            await process.stdin.drain()

    async def _read_stdout(
        self,
        process: asyncio.subprocess.Process,
        notifications: asyncio.Queue[tuple[str, int | str | None, str, dict[str, Any]]],
    ) -> None:
        assert process.stdout is not None
        disconnect_reason = "Codex disconnected"
        try:
            while line := await process.stdout.readline():
                try:
                    message = json.loads(line)
                    if not isinstance(message, dict):
                        raise ValueError("Expected a JSON object")
                except (UnicodeDecodeError, json.JSONDecodeError, ValueError):
                    logger.warning("Codex sent an invalid protocol message")
                    continue
                if "id" in message and "method" in message:
                    params = message.get("params", {})
                    if isinstance(params, dict):
                        notifications.put_nowait(
                            ("request", message["id"], str(message["method"]), params)
                        )
                elif "id" in message:
                    future = self.pending.get(message["id"])
                    if future is not None and not future.done():
                        future.set_result(message)
                elif "method" in message:
                    params = message.get("params", {})
                    if isinstance(params, dict):
                        notifications.put_nowait(("event", None, str(message["method"]), params))
        except ValueError:
            disconnect_reason = (
                f"Codex response exceeded the {MAX_PROTOCOL_LINE_BYTES // 1024 // 1024} MiB "
                "protocol line limit"
            )
            logger.error("%s", disconnect_reason)
        finally:
            detail = self.stderr_tail[-300:]
            reason = f"{disconnect_reason}: {detail}" if detail else disconnect_reason
            for future in self.pending.values():
                if not future.done():
                    future.set_exception(CodexUnavailableError(reason))
            if self.process is process:
                notifications.put_nowait(("event", None, "codex/disconnected", {}))

    async def _dispatch_notifications(
        self, notifications: asyncio.Queue[tuple[str, int | str | None, str, dict[str, Any]]]
    ) -> None:
        """Process notifications in order without blocking JSON-RPC responses."""
        while True:
            kind, request_id, method, params = await notifications.get()
            try:
                if kind == "request" and request_id is not None:
                    await self.on_request(request_id, method, params)
                else:
                    await self.on_event(method, params)
            except (OSError, ValueError, RuntimeError, KeyError, TypeError, sqlite3.Error) as error:
                logger.error("Codex notification %s failed (%s)", method, type(error).__name__)
                if kind == "request" and request_id is not None:
                    try:
                        await self._write(
                            {
                                "id": request_id,
                                "error": {
                                    "code": -32603,
                                    "message": "Studio could not handle this Codex request",
                                },
                            }
                        )
                    except CodexUnavailableError:
                        pass
            finally:
                notifications.task_done()

    async def _read_stderr(self, process: asyncio.subprocess.Process) -> None:
        assert process.stderr is not None
        while line := await process.stderr.readline():
            self.stderr_tail = (self.stderr_tail + line.decode("utf-8", "replace"))[-2000:]
