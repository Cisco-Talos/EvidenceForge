# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Explicit modeled envp snapshots are independent of the generator environment."""

from datetime import timedelta

import pytest
from pydantic import TypeAdapter, ValidationError

from evidenceforge.events.identity import (
    PosixProcessEnvironment,
    ProcessIdentity,
    validate_process_environment,
)
from evidenceforge.generation.checkpoints.state_manager_head import _capture_head, _restore_head
from evidenceforge.generation.checkpoints.state_values import decode_state_value, encode_state_value
from evidenceforge.generation.lifecycle_authority import _process_identity_payload
from evidenceforge.generation.state_manager import StateManager
from evidenceforge.models.exceptions import StateError
from tests.unit.test_process_execution_state import _START


def _create(
    environment: tuple[str, ...] | None, platform: str = "macos"
) -> tuple[StateManager, ProcessIdentity]:
    state = StateManager()
    state.set_current_time(_START)
    builder = state.begin_action_cohort_materialization()
    plan = builder.plan_process(
        system="ENV-TEST",
        parent_pid=0,
        image="/bin/zsh",
        command_line="zsh",
        username="casey",
        integrity_level="Medium",
        os_category=platform,
        environment=environment,
    )
    state.materialize_action_cohort(builder.seal())
    return state, plan.identity


@pytest.mark.parametrize("platform", ["macos", "linux"])
@pytest.mark.parametrize(
    "environment",
    [
        None,
        (),
        (
            "PATH=/invented/bin",
            "DUP=first",
            "DUP=second",
            "EMPTY=",
            "TEXT=café two words",
            "LITERAL=${USER};$(false)",
        ),
    ],
)
def test_ordered_environment_preserves_unknown_empty_duplicates_and_literals(
    platform: str, environment: tuple[str, ...] | None
) -> None:
    state, identity = _create(environment, platform)
    assert identity.environment == environment
    restored = StateManager()
    _restore_head(restored, _capture_head(state))
    assert restored.get_process_identity(identity.hostname, identity.pid) == identity
    assert decode_state_value(encode_state_value(identity)) == identity
    if environment is not None:
        assert ("posix-process-environment-v1", environment) in _process_identity_payload(identity)
    else:
        assert all(
            not isinstance(item, tuple) or item[0] != "posix-process-environment-v1"
            for item in _process_identity_payload(identity)
        )


@pytest.mark.parametrize(
    "environment",
    [["A=1"], {"A": "1"}, (True,), ("A=bad\x00value",), ("A=1",) * 257, ("A=" + "x" * 65536,)],
)
def test_malformed_environment_rejects_before_allocation(environment: object) -> None:
    state = StateManager()
    state.set_current_time(_START)
    before = state.materialization_digest()
    with pytest.raises((ValueError, TypeError, ValidationError)):
        state.plan_process_materialization(
            system="ENV-TEST",
            parent_pid=0,
            image="/bin/zsh",
            command_line="zsh",
            username="casey",
            integrity_level="Medium",
            os_category="macos",
            environment=environment,
        )
    assert state.materialization_digest() == before
    with pytest.raises((ValueError, TypeError, ValidationError)):
        validate_process_environment(environment)


def test_non_posix_environment_and_coerced_entry_types_are_rejected() -> None:
    with pytest.raises(StateError, match="POSIX host"):
        _create((), "windows")
    with pytest.raises(ValidationError):
        TypeAdapter(PosixProcessEnvironment).validate_python(["A=1"])
    with pytest.raises(ValidationError):
        TypeAdapter(PosixProcessEnvironment).validate_python((1,))


def test_fork_inherits_environment_exec_replaces_it_and_omission_stays_unknown() -> None:
    state, parent = _create(("MODE=parent", "LITERAL=${UNEXPANDED}"))
    builder = state.begin_action_cohort_materialization()
    fork = builder.fork_process(parent, forked_at=_START + timedelta(seconds=1))
    state.materialize_action_cohort(builder.seal())
    assert fork.identity.environment == parent.environment
    builder = state.begin_action_cohort_materialization()
    after = builder.execute_process(
        fork.identity,
        image="/usr/bin/true",
        command_line="true",
        executed_at=_START + timedelta(seconds=2),
        environment=(),
    )
    plan = builder.seal()
    before_digest = state.materialization_digest()
    with state.prepared_action_cohort_materialization(plan) as prepared:
        prepared.certify_composite_commit(prepared.expected_result)
        prepared.apply_provisional()
        assert state.get_process_identity(after.hostname, after.pid).environment == ()
    assert state.materialization_digest() == before_digest
    state.materialize_action_cohort(plan)
    assert (
        state.get_process_identity_at(
            after.hostname, after.pid, fork.identity.started_at
        ).environment
        == parent.environment
    )
    builder = state.begin_action_cohort_materialization()
    unknown = builder.execute_process(
        after,
        image="/usr/bin/false",
        command_line="false",
        executed_at=_START + timedelta(seconds=3),
    )
    state.materialize_action_cohort(builder.seal())
    assert unknown.environment is None
    restored = StateManager()
    _restore_head(restored, _capture_head(state))
    assert (
        restored.get_process_identity_at(
            after.hostname, after.pid, _START + timedelta(seconds=2)
        ).environment
        == ()
    )
    assert restored.get_process_identity(after.hostname, after.pid).environment is None


def test_older_identity_and_process_records_recover_unknown_environment() -> None:
    state, identity = _create(("INVENTED=explicit",))
    fields = encode_state_value(identity)[2]
    restored_identity = decode_state_value(["record", "process-identity-v6", fields[:19]])
    assert restored_identity.environment is None
    assert restored_identity.arguments == identity.arguments
    process = state.get_process(identity.hostname, identity.pid)
    fields = encode_state_value(process)[2]
    assert decode_state_value(["record", "running-process-v10", fields[:34]]).environment is None


def test_generator_environment_never_fills_missing_process_environment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("EFORGE_INVENTED_PERSONAL_VALUE", "must-not-be-copied")
    state, identity = _create(None)
    assert identity.environment is None
    assert b"must-not-be-copied" not in _capture_head(state)


def test_environment_is_part_of_fork_and_exec_projection_contracts() -> None:
    from dataclasses import replace

    from evidenceforge.events.contexts import HostContext
    from evidenceforge.generation.actions.posix_process import (
        process_exec_occurrence,
        process_fork_occurrence,
    )

    state, parent = _create(("MODE=parent",))
    host = HostContext(
        hostname=parent.hostname,
        ip="192.0.2.10",
        os="macOS 26",
        os_category="macos",
        system_type="workstation",
    )
    builder = state.begin_action_cohort_materialization()
    fork = builder.fork_process(parent, forked_at=_START + timedelta(seconds=1))
    state.materialize_action_cohort(builder.seal())
    with pytest.raises(ValueError, match="fork"):
        process_fork_occurrence(
            host=host,
            parent=parent,
            child=replace(fork.identity, environment=None),
            integrity_level="Medium",
        )
    builder = state.begin_action_cohort_materialization()
    after = builder.execute_process(
        fork.identity,
        image="/usr/bin/true",
        command_line="true",
        executed_at=_START + timedelta(seconds=2),
        environment=("MODE=child",),
    )
    event = process_exec_occurrence(
        host=host, before=fork.identity, after=after, integrity_level="Medium"
    )
    assert event.identity_plan.actor.environment == parent.environment
    assert event.identity_plan.subject.environment == ("MODE=child",)


def test_checkpoint_rejects_invalid_live_environment_before_state_publication() -> None:
    from evidenceforge.generation.checkpoints.errors import CheckpointCorruptionError

    state, identity = _create(("INVENTED=valid",))
    state.get_process(identity.hostname, identity.pid).environment = ("BAD=embedded\x00NUL",)
    restored = StateManager()
    before = restored.materialization_digest()
    with pytest.raises(CheckpointCorruptionError, match="environment"):
        _restore_head(restored, _capture_head(state))
    assert restored.materialization_digest() == before
