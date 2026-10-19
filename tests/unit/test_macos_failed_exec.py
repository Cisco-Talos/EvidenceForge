# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

from dataclasses import replace
from datetime import timedelta

import pytest

from evidenceforge.generation.actions.process_policy import record_failed_process_exec
from evidenceforge.generation.checkpoints.state_manager_head import _capture_head, _restore_head
from evidenceforge.generation.state_manager import StateManager
from evidenceforge.models.exceptions import StateError
from tests.unit.test_macos_runtime_es_preparation import _setup
from tests.unit.test_process_execution_state import _process


def test_returning_exec_failure_preserves_image_lifetime_threads_and_runtime_facts() -> None:
    state, _, actor, _ = _setup()
    pid_counters = dict(state._pid_counters)
    tid_counters = dict(state._thread_id_counters)
    audit_versions = dict(state._macos_audit_pid_versions)
    at = actor.execution_started_at + timedelta(seconds=1)
    result = record_failed_process_exec(
        state,
        actor=actor,
        attempted_at=at,
        image="/Applications/Absent.app/Contents/MacOS/Absent",
        command_line="absent 'two words'",
        error_number=2,
        arguments=("absent", "two words"),
        environment=("MODE=attempt-only",),
    )
    assert result.actor == actor and result.error_number == 2
    assert state.get_process_identity(actor.hostname, actor.pid) == actor
    assert state._pid_counters == pid_counters
    assert state._thread_id_counters == tid_counters
    assert state._macos_audit_pid_versions == audit_versions
    running = state.get_process(actor.hostname, actor.pid)
    assert running.last_activity_time == at
    assert running.end_time is None
    assert running.prior_executions[-1].object_id == actor.object_id
    restored = StateManager()
    _restore_head(restored, _capture_head(state))
    assert restored.get_process_identity(actor.hostname, actor.pid) == actor
    assert restored.get_process(actor.hostname, actor.pid).last_activity_time == at
    # A later genuine exec remains a single transition, not the second exec.
    builder = restored.begin_action_cohort_materialization()
    after = builder.execute_process(
        actor,
        image="/usr/bin/true",
        command_line="true",
        executed_at=at + timedelta(seconds=1),
    )
    restored.materialize_action_cohort(builder.seal())
    assert after.execution_ordinal == actor.execution_ordinal + 1


@pytest.mark.parametrize(
    "damage", ["errno_zero", "errno_bool", "argv", "env", "stale", "time", "platform"]
)
def test_failed_exec_rejects_unknown_or_inconsistent_attempts_before_mutation(damage: str) -> None:
    state, actor = _process("linux" if damage == "platform" else "macos")
    arguments = ("missing",) if damage != "argv" else ("another-command",)
    environment = ("NUL=\0",) if damage == "env" else ()
    error = 0 if damage == "errno_zero" else True if damage == "errno_bool" else 2
    if damage == "stale":
        actor = replace(actor, command_line="no-longer-the-live-image")
    before = state.materialization_digest()
    with pytest.raises((ValueError, StateError)):
        record_failed_process_exec(
            state,
            actor=actor,
            attempted_at=actor.execution_started_at
            + timedelta(seconds=-1 if damage == "time" else 1),
            image="/usr/bin/missing",
            command_line="missing",
            error_number=error,
            arguments=arguments,
            environment=environment,
        )
    assert state.materialization_digest() == before
