# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Invented execution directory observations never read a host filesystem."""

from dataclasses import replace
from datetime import timedelta

import pytest
from pydantic import ValidationError

from evidenceforge.events.contexts import HostContext
from evidenceforge.events.identity import ProcessIdentity
from evidenceforge.events.macos_execution_directory import MacosExecutionDirectory
from evidenceforge.events.macos_file import MacosDirectoryMetadata, MacosFileMetadata
from evidenceforge.formats.macos_file_metadata import es_directory_at_execution
from evidenceforge.generation.actions.posix_process import process_exec_occurrence
from evidenceforge.generation.checkpoints.errors import CheckpointCorruptionError
from evidenceforge.generation.checkpoints.state_manager_head import _capture_head, _restore_head
from evidenceforge.generation.checkpoints.state_values import decode_state_value, encode_state_value
from evidenceforge.generation.lifecycle_authority import _process_identity_payload
from evidenceforge.generation.state_manager import StateManager
from tests.unit.test_macos_runtime_file_metadata import _metadata
from tests.unit.test_process_execution_state import _START


def _directory(*, seconds: int = 0, path: str = "/Users/casey/Work") -> MacosExecutionDirectory:
    facts = _metadata().model_dump() | {
        "file_object_id": "invented-work-directory",
        "mode": 0o040755,
        "size_bytes": 96,
        "link_count": 3,
    }
    return MacosExecutionDirectory(
        "MAC-DIR",
        path,
        _START + timedelta(seconds=seconds),
        MacosDirectoryMetadata.model_validate(facts),
    )


def _create(
    directory: MacosExecutionDirectory | None, *, platform: str = "macos"
) -> tuple[StateManager, ProcessIdentity]:
    state = StateManager()
    state.set_current_time(_START)
    plan = state.plan_process_materialization(
        system="MAC-DIR",
        parent_pid=0,
        image="/bin/zsh",
        command_line="zsh",
        username="casey",
        integrity_level="Medium",
        os_category=platform,
        execution_directory=directory,
    )
    state.materialize_process(plan)
    return state, plan.identity


def test_exact_directory_stat_roundtrips_without_becoming_regular_file_content() -> None:
    state, identity = _create(_directory())
    native = es_directory_at_execution(identity)
    assert native.path == "/Users/casey/Work"
    assert native.stat.st_mode == 0o040755
    assert native.stat.st_size == 96 and native.stat.st_blocks == 0
    assert native.stat.st_nlink == 3 and native.stat.st_ino == 735
    assert native.stat.st_mtimespec.endswith(".123456789Z")
    assert decode_state_value(encode_state_value(identity)) == identity
    restored = StateManager()
    _restore_head(restored, _capture_head(state))
    assert restored.get_process_identity(identity.hostname, identity.pid) == identity
    assert _process_identity_payload(identity) != _process_identity_payload(
        replace(identity, execution_directory=None)
    )
    with pytest.raises(ValidationError, match="regular file"):
        MacosFileMetadata.model_validate(identity.execution_directory.metadata.model_dump())
    with pytest.raises(ValidationError, match="directory"):
        MacosDirectoryMetadata.model_validate(_metadata().model_dump())


def test_fork_does_not_reuse_a_parents_old_launch_directory() -> None:
    state, parent = _create(_directory())
    builder = state.begin_action_cohort_materialization()
    child = builder.fork_process(parent, forked_at=_START + timedelta(seconds=1))
    state.materialize_action_cohort(builder.seal())
    assert child.identity.execution_directory is None
    builder = state.begin_action_cohort_materialization()
    observed = _directory(seconds=2, path="/private/var/empty")
    child = builder.fork_process(
        parent, forked_at=observed.observed_at, execution_directory=observed
    )
    state.materialize_action_cohort(builder.seal())
    assert child.identity.execution_directory == observed
    with pytest.raises(ValueError, match="explicit"):
        es_directory_at_execution(replace(child.identity, execution_directory=None))


def test_exec_directory_is_exact_rollback_safe_retained_and_unknown_on_omission() -> None:
    state, first = _create(_directory())
    builder = state.begin_action_cohort_materialization()
    observation = _directory(seconds=1, path="/private/var/empty")
    second = builder.execute_process(
        first,
        image="/usr/bin/true",
        command_line="true",
        executed_at=observation.observed_at,
        execution_directory=observation,
    )
    plan = builder.seal()
    before = state.materialization_digest()
    with state.prepared_action_cohort_materialization(plan) as prepared:
        prepared.certify_composite_commit(prepared.expected_result)
        prepared.apply_provisional()
        assert (
            state.get_process_identity(second.hostname, second.pid).execution_directory
            == observation
        )
    assert state.materialization_digest() == before
    state.materialize_action_cohort(plan)
    host = HostContext(
        hostname=first.hostname,
        ip="192.0.2.10",
        os="macOS 26",
        os_category="macos",
        system_type="workstation",
    )
    event = process_exec_occurrence(host=host, before=first, after=second, integrity_level="Medium")
    assert event.identity_plan.subject.execution_directory == observation
    builder = state.begin_action_cohort_materialization()
    third = builder.execute_process(
        second,
        image="/usr/bin/false",
        command_line="false",
        executed_at=_START + timedelta(seconds=2),
    )
    state.materialize_action_cohort(builder.seal())
    restored = StateManager()
    _restore_head(restored, _capture_head(state))
    assert third.execution_directory is None
    for identity in (first, second, third):
        assert (
            restored.get_process_identity_at(
                identity.hostname, identity.pid, identity.execution_started_at
            ).execution_directory
            == identity.execution_directory
        )
    assert first.execution_directory.native_path == "/Users/casey/Work"


@pytest.mark.parametrize("kind", ["host", "time", "platform", "type"])
def test_invalid_launch_directory_rejects_before_allocation(kind: str) -> None:
    state = StateManager()
    state.set_current_time(_START)
    directory = _directory()
    platform = "macos"
    if kind == "host":
        directory = replace(directory, hostname="ANOTHER-MAC")
    elif kind == "time":
        directory = replace(directory, observed_at=_START - timedelta(seconds=1))
    elif kind == "platform":
        platform = "linux"
    else:
        directory = {"path": "/invented"}
    before = state.materialization_digest()
    with pytest.raises(ValueError, match="execution directory"):
        state.plan_process_materialization(
            system="MAC-DIR",
            parent_pid=0,
            image="/bin/zsh",
            command_line="zsh",
            username="casey",
            integrity_level="Medium",
            os_category=platform,
            execution_directory=directory,
        )
    assert state.materialization_digest() == before


def test_bad_exec_directory_keeps_ordinal_and_admission_reusable() -> None:
    state, first = _create(_directory())
    before = state.materialization_digest()
    builder = state.begin_action_cohort_materialization()
    with pytest.raises(ValueError, match="execution time"):
        builder.execute_process(
            first,
            image="/bin/true",
            command_line="true",
            executed_at=_START + timedelta(seconds=1),
            execution_directory=first.execution_directory,
        )
    after = builder.execute_process(
        first,
        image="/bin/true",
        command_line="true",
        executed_at=_START + timedelta(seconds=1),
        execution_directory=_directory(seconds=1),
    )
    assert after.execution_ordinal == first.execution_ordinal + 1
    assert state.materialization_digest() == before
    state.materialize_action_cohort(builder.seal())


@pytest.mark.parametrize("path", ["relative/path", "/a/../b", "/bad\0name"])
def test_directory_paths_reject_unresolved_or_invalid_names(path: str) -> None:
    with pytest.raises(ValueError, match="absolute path"):
        _directory(path=path)


def test_old_records_migrate_to_unknown_and_new_fields_cannot_hide_in_old_envelopes() -> None:
    state, identity = _create(_directory())
    for value, old_tag, width in [
        (identity, "process-identity-v10", 23),
        (state.get_process(identity.hostname, identity.pid), "running-process-v15", 39),
    ]:
        fields = encode_state_value(value)[2]
        older = decode_state_value(["record", old_tag, fields[:width]])
        assert older.execution_directory is None
        with pytest.raises(CheckpointCorruptionError):
            decode_state_value(["record", old_tag, fields])


def test_foreign_directory_in_live_or_historical_state_cannot_restore() -> None:
    state, identity = _create(_directory())
    process = state.get_process(identity.hostname, identity.pid)
    process.execution_directory = replace(identity.execution_directory, hostname="FOREIGN")
    restored = StateManager()
    before = restored.materialization_digest()
    with pytest.raises(CheckpointCorruptionError, match="directory"):
        _restore_head(restored, _capture_head(state))
    assert restored.materialization_digest() == before


def test_metadata_coercion_and_corrupt_stat_cannot_cross_codec_boundary() -> None:
    directory = _directory()
    object.__setattr__(directory.metadata, "inode", True)
    with pytest.raises(ValueError, match="primitive"):
        directory.__post_init__()
    with pytest.raises(ValueError, match="primitive"):
        encode_state_value(directory)


def test_absent_directory_does_not_consult_generator_working_directory(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from pathlib import Path

    def forbidden() -> Path:
        raise AssertionError("must not read the real current directory")

    monkeypatch.setattr(Path, "cwd", forbidden)
    state, identity = _create(None)
    assert identity.execution_directory is None
    assert b"invented-work-directory" not in _capture_head(state)


@pytest.mark.parametrize("nested", [False, True])
def test_directory_capability_rejects_shadow_model_methods_without_calling_them(
    nested: bool,
) -> None:
    directory = _directory()
    target = directory.metadata.modified if nested else directory.metadata

    def forbidden() -> str:
        raise AssertionError("must not invoke caller-controlled model methods")

    target.__dict__["canonical_json"] = forbidden
    with pytest.raises(ValueError, match="unsupported model state"):
        _create(directory)


def test_old_native_metadata_preserves_canonical_serialization() -> None:
    facts = _metadata()
    assert facts.canonical_json() == facts.model_dump_json()
