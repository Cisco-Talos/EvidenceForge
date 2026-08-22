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
from datetime import UTC, datetime
from pathlib import Path
from threading import Lock, Thread
from types import SimpleNamespace

import pytest

from evidenceforge.generation.activity.generator import (
    ActivityGenerator,
    TerminalTransientOwnerCensus,
)
from evidenceforge.generation.engine import GenerationEngine
from evidenceforge.models import (
    BaselineActivity,
    Environment,
    OutputSpec,
    Scenario,
    StateError,
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


class _SshLifecycleFinalizer:
    """Record committed SSH close-journal recovery during aborted finalization."""

    def __init__(self, calls: list[str]) -> None:
        self._calls = calls

    def finalize_ssh_session_lifecycles(self, _end_time: object) -> None:
        """Record one SSH journal drain."""

        self._calls.append("ssh-finalize")

    def assert_ssh_session_lifecycles_drained(self) -> None:
        """Record the terminal close-journal assertion."""

        self._calls.append("ssh-assert-drained")


class _FaultingSshLifecycleFinalizer:
    """Three-entry SSH journal with one deterministic injected boundary failure."""

    def __init__(
        self,
        calls: list[str],
        *,
        failure_entry: str,
        failure_mode: str,
    ) -> None:
        self._calls = calls
        self._pending = ["first", "middle", "last"]
        self._failure_entry = failure_entry
        self._failure_mode = failure_mode
        self._injected = False

    @property
    def pending(self) -> tuple[str, ...]:
        """Return the exact remaining close-journal entries."""

        return tuple(self._pending)

    def finalize_ssh_session_lifecycles(self, _end_time: object) -> None:
        """Drain in order, raising once before or after the selected entry."""

        self._calls.append("ssh-finalize")
        while self._pending:
            entry = self._pending[0]
            if entry == self._failure_entry and not self._injected:
                self._injected = True
                if self._failure_mode == "lost-return":
                    self._calls.append(f"ssh-close:{entry}")
                    self._pending.pop(0)
                raise OSError(f"ssh-close {entry} {self._failure_mode}")
            self._calls.append(f"ssh-close:{entry}")
            self._pending.pop(0)

    def assert_ssh_session_lifecycles_drained(self) -> None:
        """Require every close entry to be acknowledged before sink shutdown."""

        self._calls.append("ssh-assert-drained")
        if self._pending:
            raise AssertionError(f"SSH close journal retained {self._pending!r}")

    def write_artifacts_manifest(self) -> None:
        """Satisfy the successful engine finalization adapter surface."""

        return None


class _FaultingLinuxSudoLogoffFinalizer:
    """One retained sudo logoff with a fail-before or lost-return boundary fault."""

    def __init__(self, calls: list[str], *, failure_mode: str) -> None:
        self._calls = calls
        self._pending = True
        self._failure_mode = failure_mode
        self._injected = False

    @property
    def pending(self) -> bool:
        """Return whether the retained logoff still needs execution."""

        return self._pending

    def finalize_linux_sudo_logoffs(self) -> None:
        """Close the retained logoff, raising once before or after its mutation."""

        self._calls.append("sudo-finalize")
        if self._pending and not self._injected:
            self._injected = True
            if self._failure_mode == "lost-return":
                self._calls.append("sudo-close")
                self._pending = False
            raise OSError(f"sudo-close {self._failure_mode}")
        if self._pending:
            self._calls.append("sudo-close")
            self._pending = False

    def assert_linux_sudo_logoffs_drained(self) -> None:
        """Require the retained logoff to be terminal before sink shutdown."""

        self._calls.append("sudo-assert-drained")
        if self._pending:
            raise AssertionError("Linux sudo logoff journal retained one owner")

    def write_artifacts_manifest(self) -> None:
        """Satisfy the successful engine finalization adapter surface."""

        return None


class _TerminalActivityFinalizer:
    """Record the complete shared terminal-drain protocol."""

    def __init__(self, calls: list[str]) -> None:
        self._calls = calls

    def finalize_ssh_session_lifecycles(self, _end_time: object) -> None:
        """Record SSH journal finalization."""

        self._calls.append("ssh-finalize")

    def assert_ssh_session_lifecycles_drained(self) -> None:
        """Record the SSH journal postcondition."""

        self._calls.append("ssh-assert-drained")

    def finalize_rdp_session_lifecycles(self, _end_time: object) -> None:
        """Record RDP journal finalization."""

        self._calls.append("rdp-finalize")

    def assert_rdp_session_lifecycles_drained(self) -> None:
        """Record the RDP journal postcondition."""

        self._calls.append("rdp-assert-drained")

    def finalize_linux_sudo_logoffs(self) -> None:
        """Record local sudo-logoff journal finalization."""

        self._calls.append("sudo-finalize")

    def assert_linux_sudo_logoffs_drained(self) -> None:
        """Record the local sudo-logoff journal postcondition."""

        self._calls.append("sudo-assert-drained")

    def assert_persistent_smb_terminal_state_drained(self) -> None:
        """Record the pre-watermark persistent-SMB postcondition."""

        self._calls.append("smb-terminal-assert")

    def advance_terminal_application_channel_watermark(self, _end_time: object) -> None:
        """Record the one shared application-channel watermark."""

        self._calls.append("application-watermark")

    def finalize_terminal_runtime_state(self, _end_time: object) -> None:
        """Record bounded lifecycle/runtime/timing cleanup."""

        self._calls.append("runtime-cleanup")

    def assert_persistent_smb_projection_state_drained(self) -> None:
        """Record the post-recovery persistent-SMB projection census."""

        self._calls.append("smb-projection-assert")

    def assert_terminal_transient_state_drained(self) -> None:
        """Record the composite transient-owner census."""

        self._calls.append("terminal-census")

    def finalize_foreground_process_lifetimes(self, _end_time: object) -> None:
        """Record the foreground cleanup substage."""

        self._calls.append("foreground-finalize")

    def write_artifacts_manifest(self) -> None:
        """Satisfy successful engine finalization."""

        return None


class _OneShotTerminalStageFault:
    """Inject one fail-before or lost-return terminal-stage failure."""

    def __init__(self, stage: str, mode: str) -> None:
        self.stage = stage
        self.mode = mode
        self.injected = False
        self.completed = False

    def visit(self, stage: str) -> None:
        """Fail once at the selected stage and converge on its retry."""

        if stage != self.stage:
            return
        if self.injected:
            self.completed = True
            return
        self.injected = True
        if self.mode == "lost-return":
            self.completed = True
        raise OSError(f"{stage} {self.mode}")


class _FaultingTerminalActivityFinalizer(_TerminalActivityFinalizer):
    """Terminal activity owner with one selected stage fault."""

    def __init__(self, calls: list[str], fault: _OneShotTerminalStageFault) -> None:
        super().__init__(calls)
        self._fault = fault

    def _record_faultable(self, stage: str) -> None:
        self._calls.append(stage)
        self._fault.visit(stage)

    def assert_persistent_smb_terminal_state_drained(self) -> None:
        """Visit the SMB terminal assertion stage."""

        self._record_faultable("smb-terminal-assert")

    def advance_terminal_application_channel_watermark(self, _end_time: object) -> None:
        """Visit the application-watermark stage."""

        self._record_faultable("application-watermark")

    def finalize_terminal_runtime_state(self, _end_time: object) -> None:
        """Visit the runtime-cleanup stage."""

        self._record_faultable("runtime-cleanup")

    def assert_terminal_transient_state_drained(self) -> None:
        """Visit the terminal-census stage."""

        self._record_faultable("terminal-census")


class _FaultingTerminalDispatcher(_RecoveryDispatcher):
    """Dispatcher double with a faultable exact recovery stage."""

    def __init__(self, calls: list[str], fault: _OneShotTerminalStageFault) -> None:
        super().__init__(calls)
        self._fault = fault

    def drain_exact_projection_recoveries(self) -> tuple[object, ...]:
        """Visit the exact recovery stage."""

        self._calls.append("drain")
        self._fault.visit("drain")
        return ()


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


def _terminal_sequence(generation_succeeded: bool) -> list[str]:
    """Return the exact public sequence for one terminal mode."""

    sequence = [
        "ssh-finalize",
        "ssh-assert-drained",
        "rdp-finalize",
        "rdp-assert-drained",
        "sudo-finalize",
        "sudo-assert-drained",
        "smb-terminal-assert",
        "application-watermark",
    ]
    if generation_succeeded:
        sequence.append("foreground-finalize")
    sequence.extend(
        (
            "runtime-cleanup",
            "drain",
            "assert-drained",
            "smb-projection-assert",
            "terminal-census",
        )
    )
    if generation_succeeded:
        sequence.extend(("source-finalize", "close", "source-closed"))
    else:
        sequence.append("close")
    return sequence


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


def test_aborted_finalization_recovers_ssh_close_journal_between_source_drains(
    tmp_path: Path,
) -> None:
    """A committed SSH open fault cannot close sinks before its owned close runs."""

    calls: list[str] = []
    dispatcher = _RecoveryDispatcher(calls)
    emitter = _RecordingEmitter(calls)
    engine = _engine(tmp_path, dispatcher, emitter)
    engine.activity_generator = _SshLifecycleFinalizer(calls)  # type: ignore[assignment]
    engine.end_time = datetime(2024, 1, 15, 11, tzinfo=UTC)

    engine._finalize(generation_succeeded=False)

    assert calls == [
        "ssh-finalize",
        "ssh-assert-drained",
        "drain",
        "assert-drained",
        "close",
    ]
    assert engine._ssh_lifecycles_finalized
    assert engine._finalization_aborted
    assert engine._finalization_complete


@pytest.mark.parametrize("generation_succeeded", (True, False), ids=("success", "abort"))
@pytest.mark.parametrize("failure_entry", ("first", "middle", "last"))
@pytest.mark.parametrize("failure_mode", ("fail-before", "lost-return"))
def test_ssh_close_failure_recovers_before_retryable_sink_shutdown(
    generation_succeeded: bool,
    failure_entry: str,
    failure_mode: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Every close-journal seam recovers, preserves its error, and keeps sinks retryable."""

    calls: list[str] = []
    dispatcher = _RecoveryDispatcher(calls)
    emitter = _RecordingEmitter(calls)
    coordinator = _SourceCoordinator(calls)
    finalizer = _FaultingSshLifecycleFinalizer(
        calls,
        failure_entry=failure_entry,
        failure_mode=failure_mode,
    )
    engine = _engine(tmp_path, dispatcher, emitter)
    engine.activity_generator = finalizer  # type: ignore[assignment]
    engine.end_time = datetime(2024, 1, 15, 11, tzinfo=UTC)
    if generation_succeeded:
        engine._foreground_lifecycles_finalized = True
        engine._source_finalization_coordinator = coordinator
        engine._ids_alert_summary_applied = True
        monkeypatch.setattr(
            "evidenceforge.events.collection_profile.write_collection_profile",
            lambda *_args, **_kwargs: None,
        )

    expected_message = f"ssh-close {failure_entry} {failure_mode}"
    with pytest.raises(OSError, match=expected_message) as raised:
        engine._finalize(generation_succeeded=generation_succeeded)

    assert str(raised.value) == expected_message
    assert finalizer.pending == ()
    assert engine._ssh_lifecycles_finalized
    assert not engine._finalization_complete
    assert emitter.close_calls == 0
    assert "source-finalize" not in calls
    assert calls.count("ssh-finalize") == 2
    assert calls[-2:] == ["assert-drained", "ssh-assert-drained"]

    engine._finalize(generation_succeeded=generation_succeeded)

    assert emitter.close_calls == 1
    assert engine._finalization_complete
    terminal_assertion = max(
        index
        for index, call in enumerate(calls)
        if call in {"ssh-assert-drained", "assert-drained"}
    )
    assert calls.index("close") > terminal_assertion
    if generation_succeeded:
        assert calls.index("source-finalize") > terminal_assertion
        assert calls.index("source-finalize") < calls.index("close")
        assert calls.index("source-closed") > calls.index("close")
        assert not engine._finalization_aborted
    else:
        assert "source-finalize" not in calls
        assert engine._finalization_aborted


@pytest.mark.parametrize("generation_succeeded", (True, False), ids=("success", "abort"))
@pytest.mark.parametrize("failure_mode", ("fail-before", "lost-return"))
def test_sudo_logoff_failure_recovers_before_retryable_sink_shutdown(
    generation_succeeded: bool,
    failure_mode: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Sudo close failures drain exact rows before source or emitter shutdown."""

    calls: list[str] = []
    dispatcher = _RecoveryDispatcher(calls)
    emitter = _RecordingEmitter(calls)
    coordinator = _SourceCoordinator(calls)
    finalizer = _FaultingLinuxSudoLogoffFinalizer(calls, failure_mode=failure_mode)
    engine = _engine(tmp_path, dispatcher, emitter)
    engine.activity_generator = finalizer  # type: ignore[assignment]
    engine.end_time = datetime(2024, 1, 15, 11, tzinfo=UTC)
    engine._ssh_lifecycles_finalized = True
    engine._rdp_lifecycles_finalized = True
    if generation_succeeded:
        engine._foreground_lifecycles_finalized = True
        engine._source_finalization_coordinator = coordinator
        engine._ids_alert_summary_applied = True
        monkeypatch.setattr(
            "evidenceforge.events.collection_profile.write_collection_profile",
            lambda *_args, **_kwargs: None,
        )

    expected_message = f"sudo-close {failure_mode}"
    with pytest.raises(OSError, match=expected_message) as raised:
        engine._finalize(generation_succeeded=generation_succeeded)

    assert str(raised.value) == expected_message
    assert not finalizer.pending
    assert engine._linux_sudo_logoffs_finalized
    assert not engine._finalization_complete
    assert emitter.close_calls == 0
    assert "source-finalize" not in calls
    assert calls == [
        "sudo-finalize",
        *(["sudo-close"] if failure_mode == "lost-return" else []),
        "drain",
        "assert-drained",
        "sudo-finalize",
        *(["sudo-close"] if failure_mode == "fail-before" else []),
        "sudo-assert-drained",
        "drain",
        "assert-drained",
        "sudo-assert-drained",
    ]

    engine._finalize(generation_succeeded=generation_succeeded)

    terminal_assertion = max(
        index
        for index, call in enumerate(calls)
        if call in {"sudo-assert-drained", "assert-drained"}
    )
    assert emitter.close_calls == 1
    assert calls.index("close") > terminal_assertion
    assert engine._finalization_complete
    if generation_succeeded:
        assert calls.index("source-finalize") > terminal_assertion
        assert calls.index("source-finalize") < calls.index("close")
        assert calls.index("source-closed") > calls.index("close")
        assert not engine._finalization_aborted
    else:
        assert "source-finalize" not in calls
        assert engine._finalization_aborted


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

    assert calls == ["drain", "drain", "assert-drained"]
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


def test_partial_recovery_capability_pins_terminal_owner_but_allows_same_owner_repair(
    tmp_path: Path,
) -> None:
    """A malformed protocol cannot be exchanged after terminal entry, only repaired in place."""

    calls: list[str] = []
    partial_calls: list[str] = []
    emitter = _RecordingEmitter(calls)
    partial = _PartialRecoveryDispatcher(partial_calls)
    engine = _engine(tmp_path, partial, emitter)

    with pytest.raises(RuntimeError, match="incomplete exact projection recovery capability"):
        engine._finalize(generation_succeeded=False)

    assert partial_calls == []
    assert emitter.close_calls == 0
    assert engine._exact_projection_recovery_dispatcher is None
    assert not engine._finalization_complete

    dispatcher = _RecoveryDispatcher(calls)
    engine.dispatcher = dispatcher
    with pytest.raises(RuntimeError, match="changed identity"):
        engine._finalize(generation_succeeded=False)

    assert calls == []
    assert emitter.close_calls == 0

    engine.dispatcher = partial
    partial.assert_exact_projection_recoveries_drained = lambda: partial_calls.append(  # type: ignore[method-assign]
        "partial-assert"
    )
    engine._finalize(generation_succeeded=False)

    assert partial_calls == ["partial-drain", "partial-assert"]
    assert calls == ["close"]
    assert engine._exact_projection_recovery_dispatcher is partial
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


@pytest.mark.parametrize("generation_succeeded", (True, False), ids=("success", "abort"))
def test_shared_terminal_drain_has_one_exact_public_stage_order(
    generation_succeeded: bool,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """All terminal owners drain in one order before source and emitter shutdown."""

    calls: list[str] = []
    dispatcher = _RecoveryDispatcher(calls)
    emitter = _RecordingEmitter(calls)
    coordinator = _SourceCoordinator(calls)
    activity = _TerminalActivityFinalizer(calls)
    engine = _engine(tmp_path, dispatcher, emitter)
    engine.activity_generator = activity  # type: ignore[assignment]
    engine.end_time = datetime(2024, 1, 15, 11, tzinfo=UTC)
    engine._source_finalization_coordinator = coordinator
    engine._ids_alert_summary_applied = True
    monkeypatch.setattr(
        "evidenceforge.events.collection_profile.write_collection_profile",
        lambda *_args, **_kwargs: None,
    )

    engine._finalize(generation_succeeded=generation_succeeded)

    assert calls == _terminal_sequence(generation_succeeded)
    assert engine._finalization_complete


def test_persistent_smb_terminal_residue_blocks_source_and_emitter_close(
    tmp_path: Path,
) -> None:
    """Terminal SMB residue is a fail-closed stage before any sink shutdown."""

    calls: list[str] = []
    dispatcher = _RecoveryDispatcher(calls)
    emitter = _RecordingEmitter(calls)
    coordinator = _SourceCoordinator(calls)
    activity = _TerminalActivityFinalizer(calls)

    def reject_residue() -> None:
        calls.append("smb-terminal-assert")
        raise AssertionError("persistent SMB terminal residue")

    activity.assert_persistent_smb_terminal_state_drained = reject_residue  # type: ignore[method-assign]
    engine = _engine(tmp_path, dispatcher, emitter)
    engine.activity_generator = activity  # type: ignore[assignment]
    engine.end_time = datetime(2024, 1, 15, 11, tzinfo=UTC)
    engine._source_finalization_coordinator = coordinator

    with pytest.raises(AssertionError, match="persistent SMB terminal residue"):
        engine._finalize(generation_succeeded=True)

    assert calls == [
        "ssh-finalize",
        "ssh-assert-drained",
        "rdp-finalize",
        "rdp-assert-drained",
        "sudo-finalize",
        "sudo-assert-drained",
        "smb-terminal-assert",
        "smb-terminal-assert",
    ]
    assert emitter.close_calls == 0
    assert "source-finalize" not in calls
    assert not engine._finalization_complete


def test_terminal_census_allows_bounded_committed_dispatcher_receipt_history() -> None:
    """Committed state-neutral receipts are bounded history, not unresolved recovery work."""

    generator = object.__new__(ActivityGenerator)
    empty_owner = SimpleNamespace(census=lambda: SimpleNamespace())
    registry = SimpleNamespace(
        action_cohort_preparation_census=lambda: SimpleNamespace(),
        closed_transport_preparation_census=lambda: SimpleNamespace(),
        service_preparation_census=lambda: SimpleNamespace(),
    )
    generator._application_channel_registry = empty_owner
    generator._proxy_channel_manager = empty_owner
    generator._http_channel_manager = empty_owner
    generator._ssh_channel_manager = empty_owner
    generator._rdp_session_manager = empty_owner
    generator._smb_channel_manager = empty_owner
    generator._network_transaction_runtime = empty_owner
    generator._lifecycle_authority = SimpleNamespace(
        census=lambda: SimpleNamespace(),
        registry=registry,
    )
    generator._source_timing_planner = SimpleNamespace(
        preparation_authority_census=lambda: SimpleNamespace(),
        detached_binding_census=lambda: SimpleNamespace(),
    )
    generator._linux_sudo_tty_lock = Lock()
    generator._pending_linux_sudo_logoffs = {}
    generator._linux_sudo_logoff_high_water_pending = 0
    generator.dispatcher = SimpleNamespace(
        exact_projection_recovery_census=lambda: SimpleNamespace(
            unresolved_recoveries=0,
            reserved_recoveries=0,
            active_recoveries=0,
            state_neutral_receipts=3,
            authority=SimpleNamespace(),
        ),
        action_cohort_publication_census=lambda: SimpleNamespace(),
    )
    generator.persistent_smb_terminal_state_census = (  # type: ignore[method-assign]
        lambda: TerminalTransientOwnerCensus(counts=())
    )

    def select_exact_unresolved_counts(
        prefix: str,
        census: object,
        fields: tuple[str, ...],
    ) -> tuple[tuple[str, int], ...]:
        if prefix != "dispatcher_exact":
            return ()
        return tuple((f"{prefix}.{field}", getattr(census, field)) for field in fields)

    generator._terminal_census_fields = select_exact_unresolved_counts  # type: ignore[method-assign]

    generator.assert_terminal_transient_state_drained()


def test_terminal_census_allows_bounded_committed_source_timing_history() -> None:
    """Committed SourceTiming preparations and receipts are not transient ownership."""

    generator = object.__new__(ActivityGenerator)
    empty_owner = SimpleNamespace(census=lambda: SimpleNamespace())
    registry = SimpleNamespace(
        action_cohort_preparation_census=lambda: SimpleNamespace(),
        closed_transport_preparation_census=lambda: SimpleNamespace(),
        service_preparation_census=lambda: SimpleNamespace(),
    )
    timing = SimpleNamespace(
        retained_preparations=8,
        active_claims=0,
        terminal_preparations=8,
        retained_receipts=19,
        retained_plan_operations=0,
    )
    detached_timing = SimpleNamespace(retained_bindings=0)
    generator._application_channel_registry = empty_owner
    generator._proxy_channel_manager = empty_owner
    generator._http_channel_manager = empty_owner
    generator._ssh_channel_manager = empty_owner
    generator._rdp_session_manager = empty_owner
    generator._smb_channel_manager = empty_owner
    generator._network_transaction_runtime = empty_owner
    generator._lifecycle_authority = SimpleNamespace(
        census=lambda: SimpleNamespace(),
        registry=registry,
    )
    generator._source_timing_planner = SimpleNamespace(
        preparation_authority_census=lambda: timing,
        detached_binding_census=lambda: detached_timing,
    )
    generator._linux_sudo_tty_lock = Lock()
    generator._pending_linux_sudo_logoffs = {}
    generator._linux_sudo_logoff_high_water_pending = 0
    generator.dispatcher = SimpleNamespace(
        exact_projection_recovery_census=lambda: SimpleNamespace(
            authority=SimpleNamespace(),
        ),
        action_cohort_publication_census=lambda: SimpleNamespace(),
    )
    generator.persistent_smb_terminal_state_census = (  # type: ignore[method-assign]
        lambda: TerminalTransientOwnerCensus(counts=())
    )

    def select_source_timing_counts(
        prefix: str,
        census: object,
        fields: tuple[str, ...],
    ) -> tuple[tuple[str, int], ...]:
        if prefix not in {"source_timing", "source_timing_detached"}:
            return ()
        return tuple((f"{prefix}.{field}", getattr(census, field)) for field in fields)

    generator._terminal_census_fields = select_source_timing_counts  # type: ignore[method-assign]

    generator.assert_terminal_transient_state_drained()

    timing.active_claims = 1
    with pytest.raises(StateError, match="source_timing.active_claims"):
        generator.assert_terminal_transient_state_drained()
    timing.active_claims = 0

    timing.retained_plan_operations = 1
    with pytest.raises(StateError, match="source_timing.retained_plan_operations"):
        generator.assert_terminal_transient_state_drained()
    timing.retained_plan_operations = 0

    detached_timing.retained_bindings = 1
    with pytest.raises(StateError, match="source_timing_detached.retained_bindings"):
        generator.assert_terminal_transient_state_drained()


@pytest.mark.parametrize("generation_succeeded", (True, False), ids=("success", "abort"))
@pytest.mark.parametrize("failure_mode", ("fail-before", "lost-return"))
@pytest.mark.parametrize(
    "failure_stage",
    (
        "smb-terminal-assert",
        "application-watermark",
        "runtime-cleanup",
        "drain",
        "terminal-census",
    ),
)
def test_shared_terminal_stage_fault_retries_in_isolation_then_resumes_exactly_once(
    generation_succeeded: bool,
    failure_mode: str,
    failure_stage: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Each shared stage preserves its first fault and resumes after its postcondition."""

    calls: list[str] = []
    fault = _OneShotTerminalStageFault(failure_stage, failure_mode)
    dispatcher = _FaultingTerminalDispatcher(calls, fault)
    emitter = _RecordingEmitter(calls)
    coordinator = _SourceCoordinator(calls)
    activity = _FaultingTerminalActivityFinalizer(calls, fault)
    engine = _engine(tmp_path, dispatcher, emitter)
    engine.activity_generator = activity  # type: ignore[assignment]
    engine.end_time = datetime(2024, 1, 15, 11, tzinfo=UTC)
    engine._source_finalization_coordinator = coordinator
    engine._ids_alert_summary_applied = True
    monkeypatch.setattr(
        "evidenceforge.events.collection_profile.write_collection_profile",
        lambda *_args, **_kwargs: None,
    )

    with pytest.raises(OSError, match=f"{failure_stage} {failure_mode}") as raised:
        engine._finalize(generation_succeeded=generation_succeeded)

    assert str(raised.value) == f"{failure_stage} {failure_mode}"
    assert fault.completed
    assert calls.count(failure_stage) == 2
    assert emitter.close_calls == 0
    assert "source-finalize" not in calls
    full_sequence = _terminal_sequence(generation_succeeded)
    selected_index = full_sequence.index(failure_stage)
    selected_stage_end = selected_index + (2 if failure_stage == "drain" else 0)
    assert calls == [
        *full_sequence[:selected_index],
        failure_stage,
        *full_sequence[selected_index : selected_stage_end + 1],
    ]

    engine._finalize(generation_succeeded=generation_succeeded)

    expected = full_sequence.copy()
    expected.insert(selected_index, failure_stage)
    assert calls == expected
    assert emitter.close_calls == 1
    assert engine._finalization_complete

    engine._finalize(generation_succeeded=generation_succeeded)

    assert calls == expected
    assert emitter.close_calls == 1


@pytest.mark.parametrize(
    "owner_name",
    ("activity_generator", "dispatcher", "source_coordinator", "emitter"),
)
def test_terminal_entry_identity_snapshot_rejects_owner_substitution(
    owner_name: str,
    tmp_path: Path,
) -> None:
    """No terminal owner may be exchanged after any shutdown mutation begins."""

    calls: list[str] = []
    fault = _OneShotTerminalStageFault("smb-terminal-assert", "fail-before")
    dispatcher = _FaultingTerminalDispatcher(calls, fault)
    emitter = _RecordingEmitter(calls)
    coordinator = _SourceCoordinator(calls)
    activity = _FaultingTerminalActivityFinalizer(calls, fault)
    engine = _engine(tmp_path, dispatcher, emitter)
    engine.activity_generator = activity  # type: ignore[assignment]
    engine.end_time = datetime(2024, 1, 15, 11, tzinfo=UTC)
    engine._source_finalization_coordinator = coordinator

    with pytest.raises(OSError, match="smb-terminal-assert fail-before"):
        engine._finalize(generation_succeeded=True)

    calls_before_substitution = calls.copy()
    if owner_name == "activity_generator":
        engine.activity_generator = _TerminalActivityFinalizer([])  # type: ignore[assignment]
        expected_message = "Activity generator changed identity"
    elif owner_name == "dispatcher":
        engine.dispatcher = _RecoveryDispatcher([])
        expected_message = "Generation dispatcher changed identity"
    elif owner_name == "source_coordinator":
        engine._source_finalization_coordinator = _SourceCoordinator([])
        expected_message = "Source-finalization coordinator changed identity"
    else:
        engine.emitters = {"test": _RecordingEmitter([])}
        expected_message = "Emitter mapping for 'test' changed identity"

    with pytest.raises(RuntimeError, match=expected_message):
        engine._finalize(generation_succeeded=True)

    assert calls == calls_before_substitution
    assert emitter.close_calls == 0


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
