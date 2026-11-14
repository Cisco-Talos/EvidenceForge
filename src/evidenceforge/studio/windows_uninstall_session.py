"""Cancellable read-only review and exact-plan execution for the NSIS wizard."""

from __future__ import annotations

import threading
import time
from collections.abc import Callable
from concurrent.futures import CancelledError, Future, ThreadPoolExecutor
from pathlib import Path
from typing import Any, Literal
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field

from evidenceforge.models.exceptions import EvidenceForgeError
from evidenceforge.studio.state_io import StudioStateError
from evidenceforge.studio.windows_uninstall import (
    LABELS,
    Category,
    CleanupPlan,
    CleanupProgress,
    UserLocations,
    build_plan,
    describe,
    execute,
)


class CleanupCommand(BaseModel):
    """An account-bound request; execution must name the exact reviewed revision."""

    model_config = ConfigDict(extra="forbid", frozen=True)
    action: Literal["prepare", "execute", "cancel"]
    revision: int = Field(ge=0)
    categories: set[Category] = Field(default_factory=set)
    plan_id: str | None = Field(default=None, max_length=64)


class CleanupReply(BaseModel):
    """Only review text and an opaque receipt cross the process boundary."""

    model_config = ConfigDict(extra="forbid", frozen=True)
    state: Literal["ready", "inspecting", "prepared", "removing", "applied", "error"]
    revision: int = Field(ge=0)
    text: str
    plan_id: str | None = None
    progress: CleanupProgress | None = None


class ReviewSession:
    """Inventory off the message reader; never delete on a checkbox change."""

    def __init__(self, locations: UserLocations, emit: Callable[[CleanupReply], None]) -> None:
        self.locations = locations
        self.emit = emit
        self.lock = threading.RLock()
        self.pool = ThreadPoolExecutor(max_workers=1, thread_name_prefix="uninstall-review")
        self.cancelled = threading.Event()
        self.revision = -1
        self.plan: CleanupPlan | None = None
        self.plan_id: str | None = None
        self.categories: set[Category] = set()

    def prepare(self, command: CleanupCommand) -> None:
        """Invalidate the previous receipt immediately, then inventory asynchronously."""
        with self.lock:
            if command.revision <= self.revision:
                raise StudioStateError("Uninstall review revision is obsolete")
            self.cancelled.set()
            self.cancelled = threading.Event()
            cancellation = self.cancelled
            self.revision = command.revision
            self.plan = None
            self.plan_id = None
            self.categories = command.categories.copy()

        last_progress = time.monotonic()
        checks = 0
        current_target: Path | None = None

        def report_target(path: Path) -> None:
            nonlocal current_target
            current_target = path

        def check() -> None:
            nonlocal last_progress, checks
            if cancellation.is_set():
                raise CancelledError()
            checks += 1
            if time.monotonic() - last_progress > 0.5:
                last_progress = time.monotonic()
                self.emit(
                    CleanupReply(
                        state="inspecting",
                        revision=command.revision,
                        text=f"Inspecting selected data… {checks:,} filesystem checks completed.\n"
                        + (f"Folder: {current_target}\n" if current_target else "")
                        + "Includes selected private data, retained runtimes, skills and workspaces.\nYou can change the choices or cancel. No cleanup has started.",
                    )
                )

        def inspect() -> CleanupPlan:
            check()
            return build_plan(
                self.locations,
                command.categories,
                check_cancelled=check,
                report_target=report_target,
                full_cleanup=command.categories == set(LABELS),
            )

        def completed(future: Future[CleanupPlan]) -> None:
            try:
                plan = future.result()
                with self.lock:
                    if cancellation.is_set() or command.revision != self.revision:
                        return
                    self.plan = plan
                    self.plan_id = uuid4().hex
                    self.emit(
                        CleanupReply(
                            state="prepared",
                            revision=command.revision,
                            text=describe(plan, command.categories),
                            plan_id=self.plan_id,
                        )
                    )
            except CancelledError:
                return
            except (OSError, ValueError, EvidenceForgeError) as error:
                with self.lock:
                    if not cancellation.is_set() and command.revision == self.revision:
                        try:
                            self.emit(
                                CleanupReply(
                                    state="error",
                                    revision=command.revision,
                                    text=f"No cleanup has started. {error}\n\nUncheck the affected category to preserve it, or cancel.",
                                )
                            )
                        except OSError:
                            pass

        self.pool.submit(inspect).add_done_callback(completed)

    def apply(self, command: CleanupCommand) -> None:
        """Recheck the receipt and use the existing locked/revalidated cleanup engine."""
        with self.lock:
            if (
                command.revision != self.revision
                or self.plan is None
                or not command.plan_id
                or command.plan_id != self.plan_id
                or command.categories != self.categories
            ):
                raise StudioStateError(
                    "Uninstall choices changed; review them again before deleting"
                )
            plan = self.plan
            self.plan = None  # A receipt is single use, including after a partial failure.
            self.plan_id = None

        def progress(value: CleanupProgress) -> None:
            self.emit(
                CleanupReply(
                    state="removing", revision=command.revision, text=value.message, progress=value
                )
            )

        execute(plan, command.categories, report_progress=progress)
        self.emit(
            CleanupReply(
                state="applied",
                revision=command.revision,
                text="Selected cleanup finished. Uninstalling the application…",
            )
        )

    def close(self) -> None:
        """Cancel inventory promptly; a cancelled review never starts deletion."""
        with self.lock:
            self.cancelled.set()
            self.plan = None
            self.plan_id = None
        self.pool.shutdown(wait=True, cancel_futures=True)


def serve(connection: Any, locations: UserLocations) -> None:
    """Serve only the authenticated original-account channel, without a GUI."""

    def emit(reply: CleanupReply) -> None:
        connection.send(reply.model_dump(mode="json"))

    session = ReviewSession(locations, emit)
    try:
        emit(
            CleanupReply(
                state="ready", revision=0, text=describe(CleanupPlan(locations=locations), set())
            )
        )
        while True:
            command = CleanupCommand.model_validate(connection.receive())
            if command.action == "cancel":
                break
            try:
                if command.action == "prepare":
                    session.prepare(command)
                else:
                    session.apply(command)
            except (OSError, ValueError, EvidenceForgeError) as error:
                emit(
                    CleanupReply(
                        state="error",
                        revision=command.revision,
                        text=f"Cleanup stopped: {error}\n\nThe application has not been uninstalled. If deletion had started, some selected files may be gone. Review before retrying.",
                    )
                )
    except (OSError, ValueError, EvidenceForgeError):
        pass  # A closed/invalid channel authorizes no further work.
    finally:
        session.close()
        connection.close()
