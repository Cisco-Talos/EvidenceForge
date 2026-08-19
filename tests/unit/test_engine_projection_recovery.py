# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
#
# SPDX-License-Identifier: MIT

"""Engine boundaries for retry-stable exact projection recovery."""

from collections.abc import Callable
from pathlib import Path
from threading import Thread

import pytest

from evidenceforge.generation.engine import GenerationEngine
from evidenceforge.models import (
    BaselineActivity,
    Environment,
    OutputSpec,
    Scenario,
    System,
    TimeWindow,
    User,
)


class _RecoveryDispatcher:
    """Small protocol double for the dispatcher-owned recovery carrier."""

    def __init__(
        self,
        calls: list[str],
        *,
        drain_failures: int = 0,
        on_drain: Callable[[], None] | None = None,
    ) -> None:
        self._calls = calls
        self._drain_failures = drain_failures
        self._on_drain = on_drain

    def drain_exact_projection_recoveries(self) -> tuple[object, ...]:
        """Attempt all retained exact projection recovery work."""

        self._calls.append("drain")
        if self._drain_failures:
            self._drain_failures -= 1
            raise OSError("projection recovery failed")
        if self._on_drain is not None:
            self._on_drain()
        return ()

    def assert_exact_projection_recoveries_drained(self) -> None:
        """Assert that no exact projection recovery remains."""

        self._calls.append("assert-drained")


class _RecordingEmitter:
    """Emitter double whose close order is externally observable."""

    def __init__(self, calls: list[str]) -> None:
        self._calls = calls
        self.close_calls = 0

    def close(self) -> None:
        """Record one close."""

        self.close_calls += 1
        self._calls.append("close")


class _PartialRecoveryDispatcher:
    """Malformed dispatcher exposing only one half of the recovery protocol."""

    assert_exact_projection_recoveries_drained = None

    def __init__(self, calls: list[str]) -> None:
        self._calls = calls

    def drain_exact_projection_recoveries(self) -> tuple[object, ...]:
        """Record an invocation that valid preflight must never reach."""

        self._calls.append("partial-drain")
        return ()


class _SourceCoordinator:
    """Source-finalization double for successful EOF ordering."""

    def __init__(self, calls: list[str]) -> None:
        self._calls = calls

    def finalize(self) -> None:
        """Record source finalization."""

        self._calls.append("source-finalize")

    def mark_closed(self) -> None:
        """Record terminal source close acknowledgement."""

        self._calls.append("source-closed")


def _scenario() -> Scenario:
    """Return the smallest valid scenario needed to construct an engine."""

    return Scenario(
        version="1.0",
        name="projection-recovery-engine-test",
        description="Exercise exact projection cleanup ordering",
        environment=Environment(
            description="Test environment",
            users=[
                User(
                    username="testuser",
                    full_name="Test User",
                    email="test@example.com",
                    enabled=True,
                    primary_system="TEST-01",
                )
            ],
            systems=[
                System(
                    hostname="TEST-01",
                    ip="10.0.0.1",
                    os="Windows 11",
                    type="workstation",
                )
            ],
        ),
        time_window=TimeWindow(start="2024-01-15T10:00:00Z", duration="1h"),
        baseline_activity=BaselineActivity(
            description="Test baseline",
            intensity="low",
            variation="low",
        ),
        output=OutputSpec(
            logs=[{"format": "windows_event_security"}],
            destination="./output",
            compression=False,
        ),
        personas=[],
    )


def _engine(
    tmp_path: Path,
    dispatcher: object,
    emitter: _RecordingEmitter,
) -> GenerationEngine:
    """Construct an engine with only the finalization owners under test."""

    engine = GenerationEngine(_scenario(), tmp_path / "output", scenario_root=tmp_path)
    engine.dispatcher = dispatcher
    engine.emitters = {"test": emitter}
    return engine


def test_aborted_finalization_drains_pending_recovery_before_close(tmp_path: Path) -> None:
    """An admitted exact projection must recover before abort can close its sink."""

    calls: list[str] = []
    dispatcher = _RecoveryDispatcher(calls)
    emitter = _RecordingEmitter(calls)
    engine = _engine(tmp_path, dispatcher, emitter)

    engine._finalize(generation_succeeded=False)

    assert calls == ["drain", "assert-drained", "close"]
    assert engine._finalization_aborted
    assert engine._finalization_complete


def test_drain_failure_skips_close_and_aborted_generate_retry_only_cleans_up(
    tmp_path: Path,
) -> None:
    """A failed drain remains retryable and an aborted run never restarts its body."""

    calls: list[str] = []
    dispatcher = _RecoveryDispatcher(calls, drain_failures=1)
    emitter = _RecordingEmitter(calls)
    engine = _engine(tmp_path, dispatcher, emitter)

    with pytest.raises(OSError, match="projection recovery failed"):
        engine._finalize(generation_succeeded=False)

    assert calls == ["drain"]
    assert emitter.close_calls == 0
    assert engine._finalization_aborted
    assert not engine._finalization_complete
    assert engine._exact_projection_recovery_dispatcher is dispatcher

    replacement_calls: list[str] = []
    replacement = _RecoveryDispatcher(replacement_calls)
    engine.dispatcher = replacement
    with pytest.raises(RuntimeError, match="changed identity"):
        engine._finalize(generation_succeeded=False)

    assert replacement_calls == []
    assert emitter.close_calls == 0
    assert not engine._finalization_complete

    engine.dispatcher = dispatcher
    with pytest.raises(RuntimeError, match="Aborted generation cannot be restarted"):
        engine.generate()

    assert calls == ["drain", "drain", "assert-drained", "close"]
    assert emitter.close_calls == 1
    assert engine._finalization_complete


def test_partial_recovery_capability_rejects_without_pinning_or_closing(tmp_path: Path) -> None:
    """A malformed partial protocol cannot become the retained recovery owner."""

    calls: list[str] = []
    partial_calls: list[str] = []
    emitter = _RecordingEmitter(calls)
    engine = _engine(tmp_path, _PartialRecoveryDispatcher(partial_calls), emitter)

    with pytest.raises(RuntimeError, match="incomplete exact projection recovery capability"):
        engine._finalize(generation_succeeded=False)

    assert partial_calls == []
    assert emitter.close_calls == 0
    assert engine._exact_projection_recovery_dispatcher is None
    assert not engine._finalization_complete

    dispatcher = _RecoveryDispatcher(calls)
    engine.dispatcher = dispatcher
    engine._finalize(generation_succeeded=False)

    assert calls == ["drain", "assert-drained", "close"]
    assert engine._exact_projection_recovery_dispatcher is dispatcher
    assert engine._finalization_complete


def test_successful_finalization_noop_drain_preserves_source_close_order(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A no-op recovery check precedes the existing source-finalization sequence."""

    calls: list[str] = []
    dispatcher = _RecoveryDispatcher(calls)
    emitter = _RecordingEmitter(calls)
    coordinator = _SourceCoordinator(calls)
    engine = _engine(tmp_path, dispatcher, emitter)
    engine._ssh_lifecycles_finalized = True
    engine._foreground_lifecycles_finalized = True
    engine._source_finalization_coordinator = coordinator
    engine._ids_alert_summary_applied = True

    def ignore_collection_profile(*args: object, **kwargs: object) -> None:
        return None

    monkeypatch.setattr(
        "evidenceforge.events.collection_profile.write_collection_profile",
        ignore_collection_profile,
    )

    engine._finalize(generation_succeeded=True)

    assert calls == [
        "drain",
        "assert-drained",
        "source-finalize",
        "close",
        "source-closed",
    ]
    assert engine._finalization_complete


def test_hostile_drain_public_reentry_fails_fast_without_deadlock(tmp_path: Path) -> None:
    """Recovery callbacks run outside locks that could block public generate re-entry."""

    calls: list[str] = []
    reentry_errors: list[BaseException] = []
    engine: GenerationEngine

    def reenter_generate() -> None:
        try:
            engine.generate()
        except BaseException as error:
            reentry_errors.append(error)

    dispatcher = _RecoveryDispatcher(calls, on_drain=reenter_generate)
    emitter = _RecordingEmitter(calls)
    engine = _engine(tmp_path, dispatcher, emitter)
    engine._finalization_aborted = True
    outer_errors: list[BaseException] = []

    def run_generate() -> None:
        try:
            engine.generate()
        except BaseException as error:
            outer_errors.append(error)

    worker = Thread(target=run_generate)
    worker.start()
    worker.join(timeout=5)

    assert not worker.is_alive()
    assert calls == ["drain", "assert-drained", "close"]
    assert len(reentry_errors) == 1
    assert "concurrently or re-enter" in str(reentry_errors[0])
    assert len(outer_errors) == 1
    assert "cannot be restarted" in str(outer_errors[0])
