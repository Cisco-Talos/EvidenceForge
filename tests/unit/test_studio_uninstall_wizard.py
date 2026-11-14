"""Independent choices, cancellation and reviewed execution for embedded cleanup."""

from __future__ import annotations

import os
import queue
import struct
import threading
import time
from collections.abc import Callable
from concurrent.futures import CancelledError
from pathlib import Path

import pytest

from evidenceforge.studio import windows_uninstall_session as session_module
from evidenceforge.studio.state_io import StudioStateError, private_directory
from evidenceforge.studio.windows_uninstall import CleanupPlan, UserLocations, build_plan
from evidenceforge.studio.windows_uninstall_pipe import CleanupPipe, pipe_name
from evidenceforge.studio.windows_uninstall_session import (
    CleanupCommand,
    CleanupReply,
    ReviewSession,
)
from evidenceforge.studio.windows_uninstall_wizard import run_wizard, worker


def _locations(tmp_path: Path) -> UserLocations:
    root = tmp_path / "account"
    private_directory(root)
    if os.name == "nt":
        from evidenceforge.utils.windows_filesystem import current_user_sid

        account = current_user_sid()
    else:
        account = str(os.getuid())
    return UserLocations(
        profile=root, local=root / "AppData/Local", documents=root / "Documents", account=account
    )


def test_new_selection_cancels_inventory_and_only_latest_receipt_can_execute(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    locations = _locations(tmp_path)
    entered = threading.Event()
    cancelled = threading.Event()
    replies: queue.Queue[CleanupReply] = queue.Queue()
    calls: list[set[str]] = []

    def inspect(
        current: UserLocations, categories: set[str], *, check_cancelled: Callable[[], None]
    ) -> CleanupPlan:
        if categories == {"private"}:
            entered.set()
            while True:
                try:
                    check_cancelled()
                except CancelledError:
                    cancelled.set()
                    raise
                time.sleep(0.01)
        return CleanupPlan(locations=current)

    monkeypatch.setattr(session_module, "build_plan", inspect)
    monkeypatch.setattr(session_module, "execute", lambda plan, selected: calls.append(selected))
    session = ReviewSession(locations, replies.put)
    try:
        session.prepare(CleanupCommand(action="prepare", revision=1, categories={"private"}))
        assert entered.wait(2)
        session.prepare(
            CleanupCommand(action="prepare", revision=2, categories={"private", "work"})
        )
        review = replies.get(timeout=2)
        assert cancelled.is_set() and review.revision == 2
        assert calls == []
        with pytest.raises(StudioStateError, match="changed"):
            session.apply(
                CleanupCommand(
                    action="execute", revision=2, categories={"private"}, plan_id=review.plan_id
                )
            )
        session.apply(
            CleanupCommand(
                action="execute", revision=2, categories={"private", "work"}, plan_id=review.plan_id
            )
        )
        assert calls == [{"private", "work"}]
        with pytest.raises(StudioStateError, match="changed"):
            session.apply(
                CleanupCommand(
                    action="execute",
                    revision=2,
                    categories={"private", "work"},
                    plan_id=review.plan_id,
                )
            )
    finally:
        session.close()


def test_cancelling_real_recursive_inventory_preserves_every_file(tmp_path: Path) -> None:
    locations = _locations(tmp_path)
    private_directory(locations.private)
    for index in range(60):
        (locations.private / f"saved-{index}.txt").write_text("preserve")
    calls = 0

    def cancelled() -> None:
        nonlocal calls
        calls += 1
        if calls == 10:
            raise CancelledError()

    with pytest.raises(CancelledError):
        build_plan(locations, {"private"}, check_cancelled=cancelled)
    assert len(list(locations.private.iterdir())) == 60


def test_channel_rejects_oversize_before_reading_a_payload(monkeypatch: pytest.MonkeyPatch) -> None:
    pipe = CleanupPipe(123)
    sizes: list[int] = []

    def read(count: int) -> bytes:
        sizes.append(count)
        return struct.pack("<I", 4 * 1024 * 1024 + 1)

    monkeypatch.setattr(pipe, "_read", read)
    with pytest.raises(StudioStateError, match="frame"):
        pipe.receive()
    assert sizes == [4]
    with pytest.raises(ValueError):
        pipe_name(r"\\remote\pipe\uninstall")


class LocalChannel:
    execution_pending = False

    def __init__(self, locations: UserLocations) -> None:
        self.replies: queue.Queue[CleanupReply] = queue.Queue()
        self.session = ReviewSession(locations, self.replies.put)
        self.replies.put(CleanupReply(state="ready", revision=0, text="ready"))

    def send(
        self, action: str, revision: int, categories: set[str], plan_id: str | None = None
    ) -> None:
        command = CleanupCommand(
            action=action, revision=revision, categories=categories, plan_id=plan_id
        )
        if action == "prepare":
            self.session.prepare(command)
        elif action == "execute":
            self.session.apply(command)

    def check(self) -> None:
        pass

    def close(self) -> None:
        self.session.close()


class FakePage:
    def __init__(self) -> None:
        self.current: set[str] = set()
        self.open = True
        self.enabled = False
        self.commit = False
        self.finished = False
        self.review = ""

    def alive(self) -> bool:
        return self.open

    def choices(self) -> set[str]:
        return self.current.copy()

    def ready(self, enabled: bool) -> None:
        self.enabled = enabled

    def text(self, text: str) -> None:
        self.review = text

    def busy(self, busy: bool) -> None:
        self.enabled = False

    def commit_requested(self) -> bool:
        value, self.commit = self.commit, False
        return value

    def finish(self) -> None:
        self.finished = True
        self.open = False


def _wait(predicate: Callable[[], bool]) -> None:
    deadline = time.monotonic() + 3
    while not predicate():
        assert time.monotonic() < deadline
        time.sleep(0.01)


def test_all_three_choices_can_be_selected_then_cleared_without_deletion(tmp_path: Path) -> None:
    locations = _locations(tmp_path)
    private_directory(locations.private)
    sentinel = locations.private / "sentinel"
    sentinel.write_text("preserve")
    page = FakePage()
    thread = threading.Thread(target=run_wizard, args=(page, lambda: LocalChannel(locations)))
    thread.start()
    try:
        _wait(lambda: page.enabled)
        page.current = {"private", "skills", "work"}
        _wait(
            lambda: (
                "DELETE: Studio" in page.review
                and "DELETE: EvidenceForge skills" in page.review
                and "DELETE: Authored" in page.review
            )
        )
        page.current = {"private", "work"}
        _wait(
            lambda: (
                "DELETE: Studio" in page.review
                and "DELETE: EvidenceForge skills" not in page.review
            )
        )
        page.current = set()
        _wait(lambda: page.enabled and "Only the application" in page.review)
        page.commit = True
        _wait(lambda: page.finished)
    finally:
        page.open = False
        thread.join(5)
    assert not thread.is_alive() and sentinel.read_text() == "preserve"


def test_worker_rejects_an_unrelated_controller_before_opening_user_state() -> None:
    with pytest.raises(StudioStateError, match="controller"):
        worker("not-a-pipe", -1, "other-account")
