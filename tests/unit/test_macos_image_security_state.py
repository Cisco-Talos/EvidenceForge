# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

from dataclasses import replace
from datetime import timedelta

import pytest
from pydantic import ValidationError

from evidenceforge.events.identity import ProcessIdentity
from evidenceforge.events.macos_runtime import MacosImageSecurity
from evidenceforge.generation.checkpoints.errors import CheckpointCorruptionError
from evidenceforge.generation.checkpoints.state_manager_head import _capture_head, _restore_head
from evidenceforge.generation.checkpoints.state_values import decode_state_value, encode_state_value
from evidenceforge.generation.lifecycle_authority import _process_identity_payload
from evidenceforge.generation.state_manager import StateManager
from tests.unit.test_process_execution_state import _START


def _create(
    *,
    security: MacosImageSecurity | None = MacosImageSecurity(1, False, 3),
    platform: str = "macos",
) -> tuple[StateManager, ProcessIdentity]:
    state = StateManager()
    state.set_current_time(_START)
    plan = state.plan_process_materialization(
        system="MAC-SEC",
        parent_pid=0,
        image="/usr/local/bin/invented-worker",
        command_line="invented-worker",
        username="casey",
        integrity_level="Medium",
        os_category=platform,
        image_security=security,
    )
    state.materialize_process(plan)
    return state, plan.identity


def test_runtime_security_is_execution_owned_forked_replaced_and_unknown_on_omission() -> None:
    state, first = _create()
    assert first.image_security == MacosImageSecurity(1, False, 3)
    builder = state.begin_action_cohort_materialization()
    fork = builder.fork_process(first, forked_at=_START + timedelta(seconds=1))
    state.materialize_action_cohort(builder.seal())
    assert fork.identity.image_security == first.image_security
    builder = state.begin_action_cohort_materialization()
    second = builder.execute_process(
        fork.identity,
        image="/bin/true",
        command_line="true",
        executed_at=_START + timedelta(seconds=2),
        image_security=MacosImageSecurity(7, True),
    )
    plan = builder.seal()
    before = state.materialization_digest()
    with state.prepared_action_cohort_materialization(plan) as prepared:
        prepared.certify_composite_commit(prepared.expected_result)
        prepared.apply_provisional()
        assert (
            state.get_process_identity(second.hostname, second.pid).image_security
            == second.image_security
        )
    assert state.materialization_digest() == before
    state.materialize_action_cohort(plan)
    builder = state.begin_action_cohort_materialization()
    third = builder.execute_process(
        second, image="/bin/false", command_line="false", executed_at=_START + timedelta(seconds=3)
    )
    state.materialize_action_cohort(builder.seal())
    assert third.image_security is None
    restored = StateManager()
    _restore_head(restored, _capture_head(state))
    assert restored.get_process_identity(third.hostname, third.pid).image_security is None
    assert (
        restored.get_process_identity_at(
            second.hostname, second.pid, _START + timedelta(seconds=2)
        ).image_security
        == second.image_security
    )
    assert (
        restored.get_process_identity_at(first.hostname, first.pid, _START).image_security
        == first.image_security
    )


@pytest.mark.parametrize("platform", ["linux", "windows", "unknown"])
def test_foreign_platform_security_is_rejected_before_allocation(platform: str) -> None:
    with pytest.raises(ValueError, match="macOS"):
        _create(platform=platform)


@pytest.mark.parametrize(
    "security",
    [
        (-1, False, None),
        (2**32, False, 1),
        (True, False, 1),
        (1, 1, 1),
        (1, False, True),
        (1, False, -1),
    ],
)
def test_runtime_flag_fields_reject_coercion_and_out_of_range_values(
    security: tuple[object, ...],
) -> None:
    with pytest.raises((ValueError, ValidationError)):
        MacosImageSecurity(*security)


def test_old_identity_and_process_codecs_preserve_unknown_security() -> None:
    state, identity = _create()
    current = encode_state_value(identity)
    assert current[1] == "process-identity-v11"
    older = decode_state_value(["record", "process-identity-v9", current[2][:22]])
    assert older.image_security is None and older == replace(identity, image_security=None)
    current = encode_state_value(state.get_process(identity.hostname, identity.pid))
    assert current[1] == "running-process-v16"
    assert (
        decode_state_value(["record", "running-process-v14", current[2][:38]]).image_security
        is None
    )
    assert ("macos-image-security-v1", 1, False, 3) in _process_identity_payload(identity)
    assert _process_identity_payload(identity) != _process_identity_payload(older)


def test_restore_rejects_foreign_host_metadata_before_replacing_live_state() -> None:
    state, identity = _create(platform="linux", security=None)
    state.get_process(identity.hostname, identity.pid).image_security = MacosImageSecurity(1, False)
    restored = StateManager()
    before = restored.materialization_digest()
    with pytest.raises(CheckpointCorruptionError, match="image security"):
        _restore_head(restored, _capture_head(state))
    assert restored.materialization_digest() == before


@pytest.mark.parametrize("version", [6, 9, 10])
def test_signing_projection_retains_nullable_signer_and_versioned_category(version: int) -> None:
    from evidenceforge.events.contexts import ProcessContext
    from evidenceforge.formats.macos_image_security import es_image_security_fields
    from tests.unit.test_macos_runtime_file_metadata import _executable, _manager

    _, identity = _create()
    binary = _manager().build_record(_executable()).binary
    context = ProcessContext(
        pid=identity.pid,
        parent_pid=identity.parent_pid,
        image=identity.image,
        command_line=identity.command_line,
        username=identity.principal,
        start_time=identity.started_at,
        binary_identity=binary,
    )
    fields = es_image_security_fields(identity, context, version=version)
    assert fields["signing_id"] == "org.example.invented"
    assert fields["team_id"] is None
    assert fields["codesigning_flags"] == 1
    assert fields["is_platform_binary"] is False
    assert "is_es_client" not in fields
    assert ("cs_validation_category" in fields) == (version == 10)
    with pytest.raises(ValueError, match="runtime signing"):
        es_image_security_fields(replace(identity, image_security=None), context, version=version)
    if version == 10:
        with pytest.raises(ValueError, match="validation category"):
            es_image_security_fields(
                replace(identity, image_security=MacosImageSecurity(1, False)),
                context,
                version=version,
            )
