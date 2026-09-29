"""Qt transport for a locally spawned Codex app-server."""

from __future__ import annotations

import json
import os
import shutil
from codecs import getincrementaldecoder
from collections.abc import Callable
from typing import Any

from pydantic import BaseModel, ConfigDict, Field
from PySide6.QtCore import QObject, QProcess, Signal

from evidenceforge.desktop.state import AppSettings


class CodexEffort(BaseModel):
    """One reasoning level advertised for a Codex model."""

    model_config = ConfigDict(extra="ignore", populate_by_name=True)

    value: str = Field(alias="reasoningEffort")
    description: str = ""


class CodexModel(BaseModel):
    """A model and its available effort levels from app-server model/list."""

    model_config = ConfigDict(extra="ignore", populate_by_name=True)

    id: str
    display_name: str = Field(alias="displayName")
    default_effort: str | None = Field(default=None, alias="defaultReasoningEffort")
    efforts: list[CodexEffort] = Field(default_factory=list, alias="supportedReasoningEfforts")
    is_default: bool = Field(default=False, alias="isDefault")


class CodexBridge(QObject):
    """Exchange newline-delimited JSON-RPC with one local Codex process."""

    ready = Signal()
    event = Signal(str, object)
    server_request = Signal(object)
    failed = Signal(str)

    def __init__(self, parent: QObject | None = None, settings: AppSettings | None = None) -> None:
        super().__init__(parent)
        self.settings = settings or AppSettings()
        self.process = QProcess(self)
        self.process.started.connect(self._initialize)
        self.process.readyReadStandardOutput.connect(self._read_stdout)
        self.process.readyReadStandardError.connect(self._read_stderr)
        self.process.errorOccurred.connect(self._process_error)
        self.process.finished.connect(self._finished)
        self._buffer = ""
        self._stderr = ""
        self._stdout_decoder = getincrementaldecoder("utf-8")("replace")
        self._stderr_decoder = getincrementaldecoder("utf-8")("replace")
        self._next_id = 1
        self._pending: dict[int, Callable[[dict[str, Any]], None]] = {}
        self.initialized = False

    def start(self) -> None:
        """Start the installed CLI through private standard streams."""
        binary = (
            os.environ.get("EFORGE_DESKTOP_CODEX_BIN")
            or (str(self.settings.codex_path) if self.settings.codex_path else None)
            or shutil.which("codex")
        )
        if not binary:
            self.failed.emit("Codex CLI was not found; set EFORGE_DESKTOP_CODEX_BIN")
            return
        self.process.start(binary, ["app-server"])

    def _initialize(self) -> None:
        self.request(
            "initialize",
            {
                "clientInfo": {
                    "name": "evidenceforge_desktop",
                    "title": "EvidenceForge Desktop",
                    "version": "0.1.0",
                }
            },
            self._initialized_response,
        )

    def _initialized_response(self, message: dict[str, Any]) -> None:
        if "error" in message:
            self.failed.emit(str(message["error"].get("message", "Codex initialization failed")))
            return
        self._write({"method": "initialized", "params": {}})
        self.initialized = True
        self.ready.emit()

    def request(
        self,
        method: str,
        params: dict[str, Any] | None,
        callback: Callable[[dict[str, Any]], None] | None = None,
    ) -> int:
        """Send one client request and optionally route its response."""
        request_id = self._next_id
        self._next_id += 1
        if callback is not None:
            self._pending[request_id] = callback
        message: dict[str, Any] = {"method": method, "id": request_id}
        if params is not None:
            message["params"] = params
        self._write(message)
        return request_id

    def respond(self, request_id: int | str, result: dict[str, Any]) -> None:
        """Answer a server-initiated approval or user-input request."""
        self._write({"id": request_id, "result": result})

    def _write(self, message: dict[str, Any]) -> None:
        payload = (json.dumps(message, separators=(",", ":")) + "\n").encode("utf-8")
        self.process.write(payload)

    def _read_stdout(self) -> None:
        self._buffer += self._stdout_decoder.decode(bytes(self.process.readAllStandardOutput()))
        while "\n" in self._buffer:
            line, self._buffer = self._buffer.split("\n", 1)
            if not line:
                continue
            try:
                message = json.loads(line)
            except json.JSONDecodeError:
                self.failed.emit("Codex sent an invalid protocol message")
                continue
            if "id" in message and "method" in message:
                self.server_request.emit(message)
            elif "id" in message:
                callback = self._pending.pop(message["id"], None)
                if callback is not None:
                    callback(message)
            elif "method" in message:
                self.event.emit(message["method"], message.get("params", {}))

    def _read_stderr(self) -> None:
        self._stderr += self._stderr_decoder.decode(bytes(self.process.readAllStandardError()))
        self._stderr = self._stderr[-2000:]

    def _process_error(self, _error: QProcess.ProcessError) -> None:
        if not self.initialized:
            self.failed.emit(self._stderr.strip() or self.process.errorString())

    def _finished(self, exit_code: int, _status: QProcess.ExitStatus) -> None:
        self.initialized = False
        self.failed.emit(f"Codex app-server exited ({exit_code}): {self._stderr.strip()[-300:]}")

    def close(self) -> None:
        """Stop the local agent process; stored threads remain resumable."""
        if self.process.state() != QProcess.ProcessState.NotRunning:
            self.process.terminate()
            if not self.process.waitForFinished(2000):
                self.process.kill()
                self.process.waitForFinished(1000)
