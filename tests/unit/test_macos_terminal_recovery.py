# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Native terminal startup retains exact phases and exec-owned pipe allocations."""

from datetime import timedelta
from pathlib import Path

import pytest

from evidenceforge.events.dispatcher import (
    ActionCohortPublicationResult,
    PreparedActionCohortCapability,
)
from evidenceforge.generation.checkpoints.activity_head import _assert_transient_empty
from evidenceforge.generation.checkpoints.errors import CheckpointError
from evidenceforge.generation.emitters.base import ExactPublicationBatch
from tests.unit.test_macos_terminal_applications import _engine


@pytest.mark.slow
@pytest.mark.parametrize(
    "terminal_id,phase",
    [("macos-terminal", i) for i in range(9)] + [("macos-iterm2", i) for i in range(13)],
)
@pytest.mark.parametrize("fault", ["before-commit", "lost-return", "source-release"])
def test_every_native_terminal_phase_resumes_without_duplicate_state_or_source_records(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, terminal_id: str, phase: int, fault: str
) -> None:
    _exercise_recovery(tmp_path, monkeypatch, terminal_id, phase, fault)


@pytest.mark.parametrize("terminal_id", ["macos-terminal", "macos-iterm2"])
def test_lost_pipe_exec_return_reuses_the_same_allocation_and_finishes_complete_coverage(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, terminal_id: str
) -> None:
    _exercise_recovery(tmp_path, monkeypatch, terminal_id, 5, "lost-return")


def _exercise_recovery(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, terminal_id: str, phase: int, fault: str
) -> None:
    engine = _engine(tmp_path, terminal_id)
    try:
        engine._initialize()
        generator, state = engine.activity_generator, engine.state_manager
        system, user = engine.scenario.environment.systems[0], engine.scenario.environment.users[0]
        logon = generator.generate_logon(
            user, system, engine.start_time - timedelta(minutes=5), allow_local_session_reuse=False
        )
        at = engine.start_time + timedelta(minutes=2)
        injected = False
        original, release = (
            PreparedActionCohortCapability.commit_no_fail,
            ExactPublicationBatch.release_no_fail,
        )

        def selected() -> bool:
            retained = generator._macos_terminal_startups.get(logon)
            return retained is not None and retained.startup._phase == phase

        def interrupted(
            capability: PreparedActionCohortCapability,
        ) -> ActionCohortPublicationResult:
            nonlocal injected
            selected_phase = selected() and not injected
            if selected_phase and fault == "before-commit":
                injected = True
                raise OSError("invented terminal interruption")
            result = original(capability)
            if selected_phase and fault == "lost-return":
                injected = True
                raise OSError("invented terminal interruption")
            return result

        def interrupted_release(batch: ExactPublicationBatch) -> None:
            nonlocal injected
            if selected() and not injected:
                injected = True
                raise OSError("invented terminal interruption")
            release(batch)

        with monkeypatch.context() as scope:
            if fault == "source-release":
                scope.setattr(ExactPublicationBatch, "release_no_fail", interrupted_release)
            else:
                scope.setattr(PreparedActionCohortCapability, "commit_no_fail", interrupted)
            with pytest.raises(OSError, match="invented terminal interruption"):
                generator.ensure_macos_session_shell(user, system, logon, at)
        assert injected and len(generator._macos_terminal_startups) == 1
        assert state.get_session(logon).session_shell_pid is None
        with pytest.raises(CheckpointError, match="_macos_terminal_startups"):
            _assert_transient_empty(generator)
        before = state.materialization_digest()
        engine.dispatcher.drain_exact_projection_recoveries()
        assert state.materialization_digest() == before
        shell = generator.ensure_macos_session_shell(user, system, logon, at)
        assert shell is not None and not generator._macos_terminal_startups
        after = dict(state.macos_process_census_snapshot())[system.hostname]
        assert after.aggregate_births == 0
        assert after.forks.count == (3 if terminal_id == "macos-terminal" else 4)
        assert after.execs.count == (4 if terminal_id == "macos-terminal" else 6)
        first = generator.macos_execution_metadata.profile.first_pipe_id
        assert state._macos_pipe_counters[system.hostname] == (
            first,
            first if terminal_id == "macos-terminal" else first + 1,
        )
        engine.dispatcher.assert_exact_projection_recoveries_drained()
        engine._finalize_macos_process_coverage()
        assert engine.dispatcher.macos_es_ingress.coverage.hosts[0].process_census.complete
    finally:
        engine._close_emitters()
