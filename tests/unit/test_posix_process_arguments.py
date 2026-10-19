# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Explicit argv is execution state, never a guess from display command text."""

import shlex
from dataclasses import replace
from datetime import timedelta

import pytest
from pydantic import TypeAdapter, ValidationError

from evidenceforge.events.identity import (
    PosixProcessArguments,
    ProcessIdentity,
    validate_process_arguments,
)
from evidenceforge.generation.checkpoints.state_manager_head import _capture_head, _restore_head
from evidenceforge.generation.checkpoints.state_values import decode_state_value, encode_state_value
from evidenceforge.generation.lifecycle_authority import _process_identity_payload
from evidenceforge.generation.state_manager import StateManager
from evidenceforge.models.exceptions import StateError
from tests.unit.test_process_execution_state import _START


def _create(
    arguments: tuple[str, ...] | None = None, *, platform: str = "macos"
) -> tuple[StateManager, ProcessIdentity]:
    state = StateManager()
    state.set_current_time(_START)
    builder = state.begin_action_cohort_materialization()
    process = builder.plan_process(
        system="MAC-A",
        parent_pid=0,
        image="/bin/zsh",
        command_line=shlex.join(arguments) if arguments else "display text differs",
        username="casey",
        integrity_level="Medium",
        os_category=platform,
        arguments=arguments,
    )
    state.materialize_action_cohort(builder.seal())
    return state, process.identity


@pytest.mark.parametrize("platform", ["macos", "linux"])
def test_explicit_arguments_preserve_empty_whitespace_unicode_and_literal_shell_operators(
    platform: str,
) -> None:
    arguments = ("custom-zero", "", "two words", "café", "$(not-executed)", ";", "*.txt")
    state, identity = _create(arguments, platform=platform)
    assert identity.arguments == arguments
    assert identity.command_line == shlex.join(arguments)
    assert state.get_process_identity(identity.hostname, identity.pid) == identity
    assert encode_state_value(identity)[1] == "process-identity-v11"
    assert decode_state_value(encode_state_value(identity)) == identity
    restored = StateManager()
    _restore_head(restored, _capture_head(state))
    assert restored.get_process_identity(identity.hostname, identity.pid) == identity
    assert ("posix-process-arguments-v1", arguments) in _process_identity_payload(identity)


@pytest.mark.parametrize(
    "arguments",
    [(), ("",), ("zero", "bad\x00value"), ["zero"], (True,), ("a",) * 257, ("a" * 65536,)],
)
def test_malformed_or_oversized_arguments_fail_before_state_allocation(arguments: object) -> None:
    state = StateManager()
    state.set_current_time(_START)
    before = state.materialization_digest()
    with pytest.raises((ValueError, TypeError, ValidationError)):
        state.plan_process_materialization(
            system="MAC-A",
            parent_pid=0,
            image="/bin/zsh",
            command_line="zsh",
            username="casey",
            integrity_level="Medium",
            os_category="macos",
            arguments=arguments,
        )
    assert state.materialization_digest() == before
    with pytest.raises((ValueError, TypeError, ValidationError)):
        validate_process_arguments(arguments)


def test_missing_arguments_remain_unknown_and_legacy_records_upgrade_without_parsing() -> None:
    state, identity = _create()
    assert identity.arguments is None
    encoded = encode_state_value(identity)
    assert decode_state_value(["record", "process-identity-v4", encoded[2][:17]]) == replace(
        identity, parentage=None
    )
    process = state.get_process(identity.hostname, identity.pid)
    row = encode_state_value(process)
    assert row[1] == "running-process-v16"
    assert decode_state_value(["record", "running-process-v8", row[2][:31]]) == replace(
        process, parentage=None
    )
    assert ("macos-audit-pid-version-v1", identity.audit_pid_version) in _process_identity_payload(
        identity
    )


@pytest.mark.parametrize(
    ("tag", "width"),
    [
        ("process-identity", 12),
        ("process-identity-v2", 15),
        ("process-identity-v3", 16),
        ("process-identity-v4", 17),
    ],
)
def test_legacy_identity_widths_preserve_unknown_argv_and_reject_extra_fields(
    tag: str, width: int
) -> None:
    from evidenceforge.generation.checkpoints.errors import CheckpointCorruptionError

    _, identity = _create(("-zsh", "-l"))
    fields = encode_state_value(identity)[2]
    restored = decode_state_value(["record", tag, fields[:width]])
    assert restored.arguments is None
    assert restored.command_line == identity.command_line
    assert restored.object_id == identity.object_id
    assert restored.audit_pid_version == (identity.audit_pid_version if width == 17 else None)
    with pytest.raises(CheckpointCorruptionError):
        decode_state_value(["record", tag, fields[: width + 1]])


@pytest.mark.parametrize("arguments", [["zero"], (1,), ("zero", False)])
def test_checkpoint_argv_type_is_strict(arguments: object) -> None:
    with pytest.raises(ValidationError):
        TypeAdapter(PosixProcessArguments).validate_python(arguments)


def test_fork_inherits_exact_arguments_and_exec_replaces_only_current_execution() -> None:
    state, parent = _create(("-zsh", "-l"))
    builder = state.begin_action_cohort_materialization()
    child = builder.fork_process(parent, forked_at=_START + timedelta(seconds=1))
    state.materialize_action_cohort(builder.seal())
    before = child.identity
    assert before.arguments == parent.arguments
    builder = state.begin_action_cohort_materialization()
    after = builder.execute_process(
        before,
        image="/usr/bin/printf",
        command_line=shlex.join(("printf", "%s", "a b")),
        arguments=("printf", "%s", "a b"),
        executed_at=_START + timedelta(seconds=2),
    )
    state.materialize_action_cohort(builder.seal())
    assert state.get_process_identity(after.hostname, after.pid) == after
    assert after.arguments == ("printf", "%s", "a b")
    assert (
        state.get_process_identity_by_object_id(before.object_id, event_time=before.started_at)
        == before
    )
    assert state.get_process_identity(parent.hostname, parent.pid) == parent
    # A subsequent unmodeled launch does not inherit the previous image's argv.
    builder = state.begin_action_cohort_materialization()
    unknown = builder.execute_process(
        after,
        image="/usr/bin/true",
        command_line="true",
        executed_at=_START + timedelta(seconds=3),
    )
    state.materialize_action_cohort(builder.seal())
    assert unknown.arguments is None
    restored = StateManager()
    _restore_head(restored, _capture_head(state))
    assert restored.get_process_identity(unknown.hostname, unknown.pid) == unknown
    assert (
        restored.get_process_identity_by_object_id(after.object_id, event_time=after.executed_at)
        == after
    )


def test_failed_exec_commit_restores_arguments_with_the_original_image() -> None:
    state, before = _create(("-zsh",))
    builder = state.begin_action_cohort_materialization()
    after = builder.execute_process(
        before,
        image="/usr/bin/printf",
        command_line=shlex.join(("printf", "two words")),
        arguments=("printf", "two words"),
        executed_at=_START + timedelta(seconds=1),
    )
    plan = builder.seal()
    digest = state.materialization_digest()
    with pytest.raises(RuntimeError, match="later owner"):
        with state.prepared_action_cohort_materialization(plan) as prepared:
            prepared.certify_composite_commit(prepared.expected_result)
            prepared.apply_provisional()
            assert state.get_process_identity(after.hostname, after.pid) == after
            raise RuntimeError("later owner")
    assert state.materialization_digest() == digest
    assert state.get_process_identity(before.hostname, before.pid) == before
    state.materialize_action_cohort(plan)
    assert state.get_process_identity(after.hostname, after.pid) == after


def test_loaded_launch_job_requires_exact_argv_and_rejects_missing_or_reparsed_values() -> None:
    from tests.unit.test_macos_launch_activation import _activation, _process, _setup

    state, registry, authority, _, job = _setup()
    process = _process(state, job)
    expected = job.instance_identity.launchd_job.arguments
    assert process.identity.arguments == expected
    _activation(registry, authority, job, process)
    for arguments in (None, ("not-the-loaded-arguments",)):
        changed = _process(
            state,
            job,
            arguments=arguments,
            **({"command_line": shlex.join(arguments)} if arguments is not None else {}),
        )
        with pytest.raises(StateError, match="loaded root job definition"):
            _activation(registry, authority, job, changed)


def test_explicit_argv_does_not_infer_windows_command_line_rules() -> None:
    with pytest.raises(StateError, match="modeled POSIX"):
        _create(("example",), platform="windows")


def test_explicit_exec_arguments_publish_through_existing_lifecycle_authority() -> None:
    from evidenceforge.events.contexts import HostContext
    from evidenceforge.generation.actions.posix_process import process_exec_occurrence
    from tests.unit.test_process_exec_projection import _environment
    from tests.unit.test_process_exit_projection import _prepare

    state, dispatcher, emitter = _environment()
    row = next(iter(state._running_processes.values()))
    before = state.get_process_identity(row.system, row.pid)
    builder = state.begin_action_cohort_materialization()
    after = builder.execute_process(
        before,
        image="/usr/bin/printf",
        command_line=shlex.join(("printf", "%s", "a b")),
        arguments=("printf", "%s", "a b"),
        executed_at=before.started_at + timedelta(seconds=1),
    )
    event = process_exec_occurrence(
        host=HostContext(
            hostname=row.system,
            ip="192.0.2.20",
            os="macOS 26",
            os_category="macos",
            system_type="workstation",
        ),
        before=before,
        after=after,
        integrity_level=row.integrity_level,
    )
    dispatcher.publish_prepared_action_cohort_batch(
        _prepare(dispatcher, builder.seal(), event, root=f"process-exec:{after.execution_id}")
    )
    assert emitter.emit.call_args.args[0].identity_plan.subject.arguments == ("printf", "%s", "a b")
    assert state.get_process_identity(after.hostname, after.pid) == after


def test_checkpoint_rejects_oversized_argv_even_when_record_width_is_valid() -> None:
    from evidenceforge.generation.checkpoints.errors import CheckpointCorruptionError

    state, identity = _create(("zsh",))
    row = state.get_process(identity.hostname, identity.pid)
    row.arguments = ("a" * 40000, "b" * 40000)
    with pytest.raises(CheckpointCorruptionError, match="argv"):
        _restore_head(StateManager(), _capture_head(state))


def test_arguments_cannot_disagree_with_the_shared_display_command() -> None:
    state = StateManager()
    state.set_current_time(_START)
    digest = state.materialization_digest()
    with pytest.raises(ValueError, match="display line"):
        state.plan_process_materialization(
            system="MAC-A",
            parent_pid=0,
            image="/usr/bin/printf",
            command_line="printf safe",
            username="casey",
            integrity_level="Medium",
            os_category="macos",
            arguments=("printf", "different"),
        )
    assert state.materialization_digest() == digest
