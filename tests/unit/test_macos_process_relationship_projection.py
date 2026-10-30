# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Invented canonical relationships map without native field-padding defaults."""

from dataclasses import replace
from datetime import timedelta

import pytest

from evidenceforge.events.identity import PosixProcessCredentials, ProcessIdentity
from evidenceforge.events.macos_process_observation import MacosProcessCollectionObservation
from evidenceforge.events.process_observation import ProcessRelationshipObservation
from evidenceforge.events.responsibility import ProcessResponsibility
from evidenceforge.formats.macos_endpoint_security import ESAuditToken
from evidenceforge.formats.macos_process_relationships import ESProcessRelationshipFields
from evidenceforge.generation.checkpoints.state_manager_head import _capture_head, _restore_head
from evidenceforge.generation.state_manager import StateManager
from tests.unit.test_posix_job_control import _START, _change, _close
from tests.unit.test_process_responsibility import _exec, _launch, _reference


@pytest.mark.parametrize("policy", ["all_zero", "default_unattributed_kernel", None])
def test_known_no_parent_boot_observation_never_substitutes_for_unknown_policy(
    policy: str | None,
) -> None:
    from tests.unit.test_macos_gui_exec_adoption import _HOST, _setup

    state, other, _ = _setup()
    boot = state.get_process_identity(_HOST.hostname, 1)
    captured = state.observe_process_relationships(boot, observed_at=boot.started_at)
    if policy is None:
        with pytest.raises(ValueError, match="qualified no-parent audit-token policy"):
            ESProcessRelationshipFields.from_observation(captured, version=11)
        return
    collection = MacosProcessCollectionObservation(boot, boot.started_at, False, "absent", policy)
    fields = ESProcessRelationshipFields.from_observation(
        captured,
        version=11,
        boot_parent_token=collection.boot_parent_token,
    )
    assert fields.ppid == fields.original_ppid == fields.parent_audit_token.pid == 0
    assert fields.parent_audit_token.pidversion == 0
    assert fields.parent_audit_token.auid == (0 if policy == "all_zero" else 2**32 - 1)
    assert fields.group_id == fields.session_id == 1
    with pytest.raises(ValueError, match="boot launchd"):
        MacosProcessCollectionObservation(
            other,
            other.started_at,
            False,
            "absent",
            policy,
        )


def _family() -> tuple[StateManager, ProcessIdentity, ProcessIdentity, ProcessIdentity]:
    state = StateManager()
    state.set_current_time(_START)
    plan = state.plan_process_materialization(
        system="test-mac",
        parent_pid=0,
        fixed_pid=1,
        image="/sbin/launchd",
        command_line="launchd",
        username="root",
        integrity_level="System",
        os_category="macos",
        start_time=_START,
        credentials=PosixProcessCredentials(0, 0, 0, 0, audit_uid=501, audit_session_id=110007),
    )
    state.materialize_process(plan)
    root = _change(state, plan.identity, "bootstrap", 0)
    owner = _launch(state, root, second=2, responsibility=ProcessResponsibility(None))
    parent = _launch(state, root, second=3)
    subject = _launch(state, parent, second=4, responsibility=_reference(owner))
    return state, parent, owner, subject


@pytest.mark.parametrize("version", [6, 9, 10])
def test_native_relationship_fields_freeze_distinct_audit_parent_and_responsibility(
    version: int,
) -> None:
    state, parent, owner, subject = _family()
    captured = state.observe_process_relationships(subject, observed_at=subject.started_at)
    fields = ESProcessRelationshipFields.from_observation(captured, version=version)
    token = ESAuditToken.from_process_identity(subject)
    assert fields.audit_token == (token.as_native_array() if version == 10 else token)
    assert fields.parent_audit_token != fields.responsible_audit_token
    assert fields.ppid == fields.original_ppid == parent.pid
    assert fields.group_id == fields.session_id == 1
    assert fields.session_id != token.asid
    assert fields.start_time == "2026-10-15T12:00:04.000000Z"
    _exec(state, parent, 5)
    _exec(state, owner, 6)
    after = state.observe_process_relationships(subject, observed_at=_START + timedelta(seconds=7))
    assert after.parent.parent.credentials.effective_uid == 501
    assert after.responsibility.responsible.credentials.effective_uid == 501
    assert ESProcessRelationshipFields.from_observation(captured, version=version) == fields
    restored = StateManager()
    _restore_head(restored, _capture_head(state))
    assert (
        restored.observe_process_relationships(subject, observed_at=subject.started_at) == captured
    )


def test_adoption_and_responsible_exit_do_not_replace_original_parent_or_session() -> None:
    state, parent, owner, subject = _family()
    root = state.get_process_identity(subject.hostname, 1)
    builder = state.begin_action_cohort_materialization()
    adopted = builder.adopt_process_after_parent_exit(
        subject, adopter=root, changed_at=_START + timedelta(seconds=5)
    )
    builder.terminate_process(parent, end_time=_START + timedelta(seconds=5))
    state.materialize_action_cohort(builder.seal())
    _close(state, owner, 6)
    observation = state.observe_process_relationships(
        adopted, observed_at=_START + timedelta(seconds=7)
    )
    fields = ESProcessRelationshipFields.from_observation(observation, version=10)
    assert fields.original_ppid == parent.pid and fields.ppid == root.pid
    assert fields.responsible_audit_token == fields.audit_token
    assert fields.session_id == subject.job_control.session.sid


@pytest.mark.parametrize("damage", ["time", "subject"])
def test_relationship_capture_rejects_mixed_occurrences(damage: str) -> None:
    state, _, owner, subject = _family()
    captured = state.observe_process_relationships(subject, observed_at=subject.started_at)
    target = owner if damage == "subject" else subject
    at = subject.started_at if damage == "subject" else subject.started_at + timedelta(seconds=1)
    other = state.observe_process_responsibility(target, observed_at=at)
    with pytest.raises(ValueError, match="same exact subject and event time"):
        ProcessRelationshipObservation(captured.parent, other)


@pytest.mark.parametrize("damage", ["group", "subject_audit", "parent_audit", "responsible_audit"])
def test_native_relationship_projection_rejects_unknown_required_facts(damage: str) -> None:
    state, _, _, subject = _family()
    captured = state.observe_process_relationships(subject, observed_at=subject.started_at)
    if damage in {"group", "subject_audit"}:
        changed = replace(
            subject,
            **({"job_control": None} if damage == "group" else {"audit_pid_version": None}),
        )
        captured = replace(
            captured,
            parent=replace(captured.parent, process=changed),
            responsibility=replace(captured.responsibility, process=changed),
        )
    elif damage == "parent_audit":
        captured = replace(
            captured,
            parent=replace(
                captured.parent, parent=replace(captured.parent.parent, credentials=None)
            ),
        )
    else:
        captured = replace(
            captured,
            responsibility=replace(
                captured.responsibility,
                responsible=replace(captured.responsibility.responsible, credentials=None),
            ),
        )
    with pytest.raises(ValueError, match="requires"):
        ESProcessRelationshipFields.from_observation(captured, version=10)


@pytest.mark.parametrize("version", [True, 7, 10.0, "10"])
def test_native_relationship_projection_rejects_unsupported_version(version: object) -> None:
    state, _, _, subject = _family()
    captured = state.observe_process_relationships(subject, observed_at=subject.started_at)
    with pytest.raises(ValueError, match="wire version"):
        ESProcessRelationshipFields.from_observation(captured, version=version)
