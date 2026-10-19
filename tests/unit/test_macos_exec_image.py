# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Invented image slice facts remain distinct from host and loader assumptions."""

from dataclasses import replace
from datetime import timedelta

import pytest

from evidenceforge.events.contexts import ProcessContext
from evidenceforge.events.identity import ProcessIdentity
from evidenceforge.events.macos_exec_image import ARM64_CPU_TYPE, MacosExecImage
from evidenceforge.events.process_executable import ProcessExecutableVersion
from evidenceforge.formats.macos_exec_image import es_exec_image_fields
from evidenceforge.generation.checkpoints.errors import CheckpointCorruptionError
from evidenceforge.generation.checkpoints.state_manager_head import _capture_head, _restore_head
from evidenceforge.generation.checkpoints.state_values import decode_state_value, encode_state_value
from evidenceforge.generation.lifecycle_authority import _process_identity_payload
from evidenceforge.generation.state_manager import StateManager
from tests.unit.test_macos_runtime_file_metadata import _executable, _manager
from tests.unit.test_process_execution_state import _START


def _create(
    facts: MacosExecImage | None, platform: str = "macos"
) -> tuple[StateManager, ProcessIdentity, ProcessContext]:
    state = StateManager()
    state.set_current_time(_START)
    binary = _manager().build_record(_executable()).binary
    plan = state.plan_process_materialization(
        system="MAC-IMAGE",
        parent_pid=0,
        image="/usr/local/bin/invented-worker",
        command_line="invented-worker",
        username="casey",
        integrity_level="Medium",
        os_category=platform,
        exec_image=facts,
        executable_version=ProcessExecutableVersion.from_binary(binary)
        if platform == "macos"
        else None,
    )
    state.materialize_process(plan)
    identity = plan.identity
    context = ProcessContext(
        identity.pid,
        identity.parent_pid,
        identity.image,
        identity.command_line,
        identity.principal,
        start_time=identity.started_at,
        binary_identity=binary,
    )
    return state, identity, context


def test_launch_fork_exec_history_and_checkpoint_preserve_exact_image_facts() -> None:
    facts = MacosExecImage(2, "./bin/../invented-alias")
    state, first, _ = _create(facts)
    assert first.exec_image == facts
    builder = state.begin_action_cohort_materialization()
    child = builder.fork_process(first, forked_at=_START + timedelta(seconds=1))
    state.materialize_action_cohort(builder.seal())
    assert child.identity.exec_image == facts
    builder = state.begin_action_cohort_materialization()
    second = builder.execute_process(
        child.identity,
        image="/usr/bin/true",
        command_line="true",
        executed_at=_START + timedelta(seconds=2),
        exec_image=MacosExecImage(0, "/usr/bin/true"),
    )
    plan = builder.seal()
    before = state.materialization_digest()
    with state.prepared_action_cohort_materialization(plan) as prepared:
        prepared.certify_composite_commit(prepared.expected_result)
        prepared.apply_provisional()
        assert (
            state.get_process_identity(second.hostname, second.pid).exec_image == second.exec_image
        )
    assert state.materialization_digest() == before
    state.materialize_action_cohort(plan)
    builder = state.begin_action_cohort_materialization()
    third = builder.execute_process(
        second,
        image="/usr/bin/false",
        command_line="false",
        executed_at=_START + timedelta(seconds=3),
    )
    state.materialize_action_cohort(builder.seal())
    assert third.exec_image is None
    restored = StateManager()
    _restore_head(restored, _capture_head(state))
    for identity in (child.identity, second, third):
        assert (
            restored.get_process_identity_at(
                identity.hostname, identity.pid, identity.execution_started_at
            ).exec_image
            == identity.exec_image
        )
    assert _process_identity_payload(first) != _process_identity_payload(
        replace(first, exec_image=None)
    )


@pytest.mark.parametrize("version", [6, 9])
def test_historical_projection_preserves_path_and_never_substitutes_loader(version: int) -> None:
    _, identity, context = _create(MacosExecImage(2, "./unchanged-link/../program"))
    fields = es_exec_image_fields(identity, context, version=version)
    assert fields["image_cputype"] == ARM64_CPU_TYPE
    assert fields["image_cpusubtype"] == 2
    assert ("dyld_exec_path" in fields) == (version == 9)
    if version == 9:
        assert fields["dyld_exec_path"] == "./unchanged-link/../program"
    with pytest.raises(ValueError, match="historical"):
        es_exec_image_fields(identity, context, version=10)
    with pytest.raises(ValueError, match="execution metadata"):
        es_exec_image_fields(replace(identity, exec_image=None), context, version=version)
    with pytest.raises(ValueError, match="exact loaded"):
        es_exec_image_fields(replace(identity, executable_version=None), context, version=version)


def test_unknown_dyld_path_is_not_an_empty_or_normalized_path() -> None:
    _, identity, context = _create(MacosExecImage(0))
    assert "dyld_exec_path" not in es_exec_image_fields(identity, context, version=6)
    with pytest.raises(ValueError, match="pre-resolution"):
        es_exec_image_fields(identity, context, version=9)
    explicit_empty = replace(identity, exec_image=MacosExecImage(0, ""))
    assert es_exec_image_fields(explicit_empty, context, version=9)["dyld_exec_path"] == ""


@pytest.mark.parametrize(
    "subtype,path",
    [(True, None), (2**31, None), (-(2**31) - 1, None), (0, b"path"), (0, "bad\0path")],
)
def test_invalid_image_facts_reject_without_normalization(subtype: object, path: object) -> None:
    with pytest.raises(ValueError):
        MacosExecImage(subtype, path)


def test_foreign_platform_rejects_and_legacy_records_remain_unknown() -> None:
    with pytest.raises(ValueError, match="macOS"):
        _create(MacosExecImage(0), "linux")
    state, identity, _ = _create(MacosExecImage(0))
    for value, tag, width in [
        (identity, "process-identity-v12", 25),
        (state.get_process(identity.hostname, identity.pid), "running-process-v19", 43),
    ]:
        encoded = encode_state_value(value)
        old = decode_state_value(["record", tag, encoded[2][:width]])
        assert old.exec_image is None
        with pytest.raises(CheckpointCorruptionError):
            decode_state_value(["record", tag, encoded[2]])
    encoded = encode_state_value(identity.exec_image)
    encoded[2][0] = True
    with pytest.raises(CheckpointCorruptionError):
        decode_state_value(encoded)


def test_corrupt_foreign_execution_image_cannot_restore() -> None:
    state, identity, _ = _create(None, "linux")
    state.get_process(identity.hostname, identity.pid).exec_image = MacosExecImage(0)
    restored = StateManager()
    before = restored.materialization_digest()
    with pytest.raises(CheckpointCorruptionError, match="execution image"):
        _restore_head(restored, _capture_head(state))
    assert restored.materialization_digest() == before


def test_returning_failure_and_forged_exec_preserve_image_facts() -> None:
    from evidenceforge.generation.actions.process_policy import record_failed_process_exec
    from evidenceforge.models.exceptions import StateError

    state, before, _ = _create(MacosExecImage(2, "./original"))
    record_failed_process_exec(
        state,
        actor=before,
        attempted_at=_START + timedelta(seconds=1),
        image="/usr/bin/missing",
        command_line="missing",
        error_number=2,
    )
    assert state.get_process_identity(before.hostname, before.pid) == before
    builder = state.begin_action_cohort_materialization()
    after = builder.execute_process(
        before,
        image="/usr/bin/true",
        command_line="true",
        executed_at=_START + timedelta(seconds=2),
        exec_image=MacosExecImage(0, "./next"),
    )
    cohort = builder.seal()
    forged = replace(
        cohort,
        _process_executions=(
            replace(
                cohort.process_executions[0], after=replace(after, exec_image=MacosExecImage(1))
            ),
        ),
    )
    digest = state.materialization_digest()
    with pytest.raises(StateError):
        state.materialize_action_cohort(forged)
    assert state.materialization_digest() == digest
    state.materialize_action_cohort(cohort)
    assert state.get_process_identity(after.hostname, after.pid) == after


@pytest.mark.parametrize("field,value", [(0, "2"), (0, True), (1, b"./program")])
def test_image_checkpoint_rejects_scalar_coercion(field: int, value: object) -> None:
    encoded = encode_state_value(MacosExecImage(2, "./program"))
    encoded[2][field] = value
    with pytest.raises(CheckpointCorruptionError):
        decode_state_value(encoded)


@pytest.mark.slow
def test_image_fork_exec_recovery_is_fresh_process_deterministic() -> None:
    import os
    import subprocess
    import sys

    script = """
import json
from datetime import timedelta
from tests.unit.test_macos_exec_image import _create
from tests.unit.test_process_execution_state import _START
from evidenceforge.events.macos_exec_image import MacosExecImage
from evidenceforge.generation.state_manager import StateManager
from evidenceforge.generation.checkpoints.state_manager_head import _capture_head, _restore_head
from evidenceforge.generation.checkpoints.state_values import encode_state_value
state, parent, _ = _create(MacosExecImage(2, './alias/../worker'))
builder = state.begin_action_cohort_materialization()
child = builder.fork_process(parent, forked_at=_START + timedelta(seconds=1))
state.materialize_action_cohort(builder.seal())
restored = StateManager()
_restore_head(restored, _capture_head(state))
results = []
for manager in (state, restored):
    builder = manager.begin_action_cohort_materialization()
    after = builder.execute_process(child.identity, image='/usr/bin/true', command_line='true',
        executed_at=_START + timedelta(seconds=2), exec_image=MacosExecImage(0, './next'))
    manager.materialize_action_cohort(builder.seal())
    results.append(encode_state_value(manager.get_process(after.hostname, after.pid)))
assert results[0] == results[1]
print(json.dumps(results[0], sort_keys=True))
"""
    results: list[str] = []
    for seed in ("17", "983"):
        run = subprocess.run(
            [sys.executable, "-c", script],
            env=os.environ | {"PYTHONHASHSEED": seed},
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        assert run.returncode == 0, run.stdout + run.stderr
        results.append(run.stdout)
    assert results[0] == results[1]
