"""Drive existing NSIS controls; keep inventory/deletion in the unelevated account."""

from __future__ import annotations

import ctypes
import os
import queue
import subprocess
import sys
import threading
import time
from collections.abc import Callable
from ctypes import wintypes as wt
from pathlib import Path
from typing import Protocol
from uuid import uuid4

import psutil

from evidenceforge.models.exceptions import EvidenceForgeError
from evidenceforge.studio.state_io import StudioStateError
from evidenceforge.studio.windows_uninstall import Category
from evidenceforge.studio.windows_uninstall_native import _function, _require, user_locations
from evidenceforge.studio.windows_uninstall_pipe import CleanupPipe
from evidenceforge.studio.windows_uninstall_session import CleanupReply, serve

PREFIX = "EvidenceForge.Cleanup."


def _pid(window: int) -> int:
    result = wt.DWORD()
    _require(
        _function(
            "user32", "GetWindowThreadProcessId", wt.DWORD, [wt.HWND, ctypes.POINTER(wt.DWORD)]
        )(window, ctypes.byref(result))
    )
    return result.value


def _property(window: int, name: str, value: int | None = None) -> int:
    if value is None:
        return (
            _function("user32", "GetPropW", wt.HANDLE, [wt.HWND, wt.LPCWSTR])(window, PREFIX + name)
            or 0
        )
    _require(
        _function("user32", "SetPropW", wt.BOOL, [wt.HWND, wt.LPCWSTR, wt.HANDLE])(
            window, PREFIX + name, value
        )
    )
    return value


class WizardControls:
    """Access only the NSIS page and controls owned by the verified parent process."""

    def __init__(self, wizard: int, page: int, controls: list[int], process: int) -> None:
        if len(controls) != 4 or psutil.Process().ppid() != process:
            raise StudioStateError("Cleanup page is not the controller's parent wizard")
        self.wizard, self.page, self.process = wizard, page, process
        self.checks = dict(zip(("private", "skills", "work"), controls[:3], strict=True))
        self.review = controls[3]
        child = _function("user32", "IsChild", wt.BOOL, [wt.HWND, wt.HWND])
        if _pid(wizard) != process or _pid(page) != process or not child(wizard, page):
            raise StudioStateError("Cleanup page changed its owner")
        for control in controls:
            if _pid(control) != process or not child(page, control):
                raise StudioStateError("Cleanup control is outside the wizard page")
        get = _function("user32", "GetDlgItem", wt.HWND, [wt.HWND, ctypes.c_int])
        self.next, self.cancel = get(wizard, 1), get(wizard, 2)
        _require(self.next)
        _require(self.cancel)
        _property(page, "Pid", os.getpid())

    def alive(self) -> bool:
        is_window = _function("user32", "IsWindow", wt.BOOL, [wt.HWND])
        return bool(is_window(self.page) and is_window(self.wizard))

    def choices(self) -> set[Category]:
        send = _function(
            "user32", "SendMessageW", ctypes.c_ssize_t, [wt.HWND, wt.UINT, wt.WPARAM, wt.LPARAM]
        )
        return {
            category for category, handle in self.checks.items() if send(handle, 0xF0, 0, 0) == 1
        }

    def text(self, text: str) -> None:
        buffer = ctypes.create_unicode_buffer(text.replace("\n", "\r\n"))
        _require(
            _function(
                "user32", "SendMessageW", ctypes.c_ssize_t, [wt.HWND, wt.UINT, wt.WPARAM, wt.LPARAM]
            )(self.review, 0xC, 0, ctypes.addressof(buffer))
        )

    def ready(self, value: bool) -> None:
        _property(self.page, "Ready", int(value))
        _function("user32", "EnableWindow", wt.BOOL, [wt.HWND, wt.BOOL])(self.next, value)

    def busy(self, value: bool) -> None:
        _property(self.page, "Busy", int(value))
        enable = _function("user32", "EnableWindow", wt.BOOL, [wt.HWND, wt.BOOL])
        for control in (*self.checks.values(), self.cancel):
            enable(control, not value)
        self.ready(False)

    def commit_requested(self) -> bool:
        requested = bool(_property(self.page, "Commit"))
        if requested:
            _property(self.page, "Commit", 0)
        return requested

    def finish(self) -> None:
        _property(self.page, "Busy", 0)
        _property(self.page, "Done", 1)
        self.ready(True)
        _require(
            _function("user32", "PostMessageW", wt.BOOL, [wt.HWND, wt.UINT, wt.WPARAM, wt.LPARAM])(
                self.wizard, 0x111, 1, 0
            )
        )


class Channel(Protocol):
    replies: queue.Queue[CleanupReply]
    execution_pending: bool

    def send(
        self, action: str, revision: int, categories: set[Category], plan_id: str | None = None
    ) -> None: ...
    def close(self) -> None: ...

    def check(self) -> None: ...


class AccountChannel:
    """An authenticated local channel to the existing original-token broker."""

    def __init__(self) -> None:
        from evidenceforge.utils.windows_filesystem import process_user_sid

        shell = _function("user32", "GetShellWindow", wt.HWND, [])()
        _require(shell)
        self.account = process_user_sid(_pid(shell))
        identity = uuid4().hex
        self.pipe = CleanupPipe.server(identity, self.account)
        self.replies: queue.Queue[CleanupReply] = queue.Queue()
        self.connected = threading.Event()
        self.closed = threading.Event()
        self.execution_pending = False
        self.started_at = time.monotonic()
        self.connection_failed = False
        self.client: psutil.Process | None = None
        self.process = subprocess.Popen(
            [
                sys.executable,
                "-I",
                "-B",
                "-X",
                "utf8",
                "-m",
                "evidenceforge.studio.windows_uninstall",
                "--broker",
                "--worker-pipe",
                identity,
                "--server-pid",
                str(os.getpid()),
            ],
            creationflags=0x08000000,
        )

        def receive() -> None:
            try:
                self.pipe.accept()
                client = psutil.Process(self.pipe.peer_pid())
                if (
                    client.ppid() != self.process.pid
                    or Path(client.exe()).resolve() != Path(sys.executable).resolve()
                    or process_user_sid(client.pid) != self.account
                ):
                    raise StudioStateError("Cleanup worker identity could not be authenticated")
                self.client = client
                self.connected.set()
                while not self.closed.is_set():
                    reply = CleanupReply.model_validate(self.pipe.receive())
                    if reply.state in {"applied", "error"}:
                        self.execution_pending = False
                    self.replies.put(reply)
            except (OSError, ValueError, EvidenceForgeError, psutil.Error):
                if not self.closed.is_set():
                    self.replies.put(
                        CleanupReply(
                            state="error",
                            revision=0,
                            text="Optional cleanup could not connect to the original account. No cleanup started. Uncheck all categories to uninstall only the application, or cancel.",
                        )
                    )

        threading.Thread(target=receive, daemon=True, name="uninstall-channel").start()

    def check(self) -> None:
        if self.execution_pending and self.process.poll() is not None:
            self.execution_pending = False
            self.replies.put(
                CleanupReply(
                    state="error",
                    revision=0,
                    text="Cleanup exited without a confirmed result. The application has not been uninstalled. Some selected data may have been removed; inspect it before retrying.",
                )
            )
        if (
            not self.connected.is_set()
            and not self.connection_failed
            and (self.process.poll() is not None or time.monotonic() - self.started_at > 15)
        ):
            self.connection_failed = True
            self.replies.put(
                CleanupReply(
                    state="error",
                    revision=0,
                    text="Optional cleanup could not start for the original account. No cleanup started. Uncheck all categories to preserve all data, or cancel and retry.",
                )
            )

    def send(
        self, action: str, revision: int, categories: set[Category], plan_id: str | None = None
    ) -> None:
        if not self.connected.wait(0):
            raise StudioStateError("The original-account cleanup worker is not ready")
        if action == "execute":
            self.execution_pending = True
        self.pipe.send(
            {
                "action": action,
                "revision": revision,
                "categories": sorted(categories),
                "plan_id": plan_id,
            }
        )

    def close(self) -> None:
        self.closed.set()
        if self.connected.is_set():
            try:
                self.send("cancel", 0, set())
            except OSError:
                pass
        self.pipe.close()
        try:
            self.process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            if self.execution_pending:
                # An uncertain acknowledgement is not proof that deletion stopped.
                # Never kill the worker during an approved staging/deletion operation.
                self.process.wait()
                return
            # Called during read-only review or after execution has acknowledged its
            # result, never to interrupt staging/deletion after approval.
            if self.client is not None and self.client.is_running():
                self.client.terminate()
                self.client.wait(timeout=5)
            self.process.terminate()
            self.process.wait(timeout=5)


def run_wizard(ui: WizardControls, channel_factory: Callable[[], Channel] = AccountChannel) -> None:
    """Poll native NSIS controls without blocking its event loop or opening windows."""
    channel: Channel | None = None
    revision = 0
    selected: set[Category] | None = None
    receipt: str | None = None
    connected = False
    submitted = False
    applying = False
    try:
        ui.text(
            "All user data and skills will be preserved.\n\nSelect optional categories to review their exact deletion paths. Nothing is removed until you click Uninstall."
        )
        ui.ready(True)
        while ui.alive() or applying:
            try:
                if ui.alive() and not applying:
                    choices = ui.choices()
                    if choices != selected:
                        selected = choices
                        revision += 1
                        receipt = None
                        submitted = False
                        if not choices and channel is not None:
                            channel.close()
                            channel = None
                            connected = False
                        ui.ready(not choices)
                        ui.text(
                            "Preparing the selected file list… You can change the choices or cancel."
                            if choices
                            else "All user data and skills will be preserved. Only the application will be uninstalled."
                        )
                    if selected and channel is None:
                        channel = channel_factory()
                    if selected and connected and not submitted:
                        channel.send("prepare", revision, selected)
                        submitted = True
                    # NSIS disables Next immediately on every click. Two clicks
                    # between polls can restore the same selection, so restore
                    # eligibility even when no new inventory is needed.
                    ui.ready(not selected or (receipt is not None and submitted))
                    if ui.commit_requested():
                        ui.ready(False)
                        if not selected:
                            if channel is not None:
                                channel.close()
                                channel = None
                            ui.finish()
                            return
                        if receipt is not None and submitted:
                            ui.busy(True)
                            applying = True
                            ui.text(
                                "Removing the reviewed data… Please wait while the selected cleanup finishes."
                            )
                            channel.send("execute", revision, selected, receipt)
                if channel is not None:
                    channel.check()
                    while True:
                        try:
                            reply = channel.replies.get_nowait()
                        except queue.Empty:
                            break
                        if reply.state == "ready":
                            connected = True
                        elif reply.revision in (0, revision):
                            if reply.state == "inspecting":
                                if ui.alive() and selected and not applying:
                                    ui.text(reply.text)
                                continue
                            if reply.state == "applied":
                                applying = False
                                channel.close()
                                channel = None
                                if ui.alive():
                                    ui.finish()
                                return
                            if reply.state == "prepared":
                                receipt = reply.plan_id
                                if selected and ui.alive():
                                    ui.text(
                                        reply.text
                                        + "\n\nClick Uninstall to permanently remove the listed data and the application."
                                    )
                                    ui.ready(True)
                            else:
                                if channel.execution_pending:
                                    if ui.alive():
                                        ui.text(
                                            "Waiting for the selected cleanup to stop. Its acknowledgement was lost; application files will be preserved until its outcome can be checked."
                                        )
                                    continue
                                receipt = None
                                applying = False
                                if ui.alive():
                                    ui.busy(False)
                                    ui.text(reply.text)
                time.sleep(0.05)
            except (OSError, ValueError, EvidenceForgeError, psutil.Error) as error:
                applying = False
                receipt = None
                if ui.alive():
                    ui.busy(False)
                    ui.text(
                        f"Cleanup could not continue: {error}\n\nUncheck all categories to preserve all data, or cancel. Review any reported partial cleanup before retrying."
                    )
                else:
                    break
    finally:
        if channel is not None:
            channel.close()


def worker(identity: str, server_pid: int, expected_account: str) -> int:
    """Run no GUI and accept work only from the verified controller/broker chain."""
    parent = psutil.Process(os.getppid())
    if (
        parent.ppid() != server_pid
        or Path(parent.exe()).resolve() != Path(sys.executable).resolve()
        or Path(psutil.Process(server_pid).exe()).resolve() != Path(sys.executable).resolve()
    ):
        raise StudioStateError("Cleanup worker was not started by the wizard controller")
    locations = user_locations()  # Refuses elevation and environment-selected profiles.
    if locations.account != expected_account:
        raise StudioStateError("Cleanup worker is running as another account")
    connection = CleanupPipe.client(identity, server_pid)
    serve(connection, locations)
    return 0
