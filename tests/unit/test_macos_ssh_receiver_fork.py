# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""A deferred SSH receiver starts with a genuine inherited fork, not an aggregate wrapper."""

from dataclasses import replace
from datetime import timedelta

import pytest

from evidenceforge.events.contexts import HostContext
from evidenceforge.events.process import macos_service_child_responsibility_matches
from evidenceforge.events.responsibility import ProcessResponsibility, ResponsibleProcessReference
from evidenceforge.generation.actions.posix_process import process_fork_occurrence
from evidenceforge.generation.checkpoints.state_manager_head import _capture_head, _restore_head
from evidenceforge.generation.state_manager import (
    MaterializationBatchBuilder,
    SessionMaterializationPlan,
    StateManager,
)
from evidenceforge.models.exceptions import StateError
from tests.unit.test_macos_metadata_producers import _Fixture
from tests.unit.test_macos_metadata_producers import modeled as modeled


def _session(modeled: _Fixture) -> tuple[MaterializationBatchBuilder, SessionMaterializationPlan]:
    builder = modeled.state.begin_materialization_batch()
    session = builder.plan_session(
        username="alex",
        system="MAC-01",
        logon_type=10,
        source_ip="192.0.2.80",
        source_port=51000,
        session_kind="ssh",
        auth_protocol="ssh",
        effective_uid=501,
        effective_gid=20,
        start_time=modeled.start,
        source_ready_time=modeled.start + timedelta(seconds=20),
        network_close_time=modeled.start + timedelta(minutes=2),
        closure_owned_by_bundle=True,
    )
    session = builder.enrich_macos_audit_session(
        session, audit_uid=501, authenticated_at=modeled.start + timedelta(seconds=10)
    )
    return builder, session


def test_receiver_fork_inherits_boot_execution_without_session_or_image_substitution(
    modeled: _Fixture,
) -> None:
    state, provider = modeled.state, modeled.producer
    state.configure_macos_process_census(
        "MAC-01", modeled.start + timedelta(seconds=1), modeled.end
    )
    builder, session = _session(modeled)
    at = modeled.start + timedelta(seconds=2)
    directory = provider.directory("MAC-01", "/", at)
    digest = state.materialization_digest()
    fork = builder.plan_macos_ssh_receiver_fork(
        modeled.root,
        session=session,
        forked_at=at,
        execution_directory=directory,
        lifecycle_group_id="invented-ssh-root",
    )
    builder.bind_session_processes(session, transport_plan=fork, process_tree_root_plan=fork)
    plan = builder.seal()
    assert state.materialization_digest() == digest
    assert fork.forked and fork.identity.execution_ordinal == 0
    assert fork.identity.initial_image == fork.identity.image == modeled.root.image
    assert fork.identity.credentials == modeled.root.credentials
    assert fork.identity.job_control == modeled.root.job_control
    assert fork.identity.logon_id == session.identity.logon_id != modeled.root.logon_id
    assert fork.identity.parent_pid == modeled.root.pid
    assert fork.identity.arguments == modeled.root.arguments
    assert fork.identity.executable_version == modeled.root.executable_version
    expected = state.process_descriptors_at(modeled.root, event_time=at).inherited_at(at)
    assert fork._payload.initial_descriptors == expected
    host = HostContext(
        hostname="MAC-01",
        ip="192.0.2.81",
        os="macOS 27",
        os_category="macos",
        system_type="workstation",
    )
    event = process_fork_occurrence(
        host=host,
        parent=modeled.root,
        child=fork.identity,
        integrity_level="System",
        session=session.identity,
    )
    assert event.identity_plan.session == session.identity
    with pytest.raises(ValueError, match="inherit"):
        process_fork_occurrence(
            host=host,
            parent=modeled.root,
            child=fork.identity,
            integrity_level="System",
        )
    with state.prepared_materialization_batch(plan) as claim:
        claim.apply_provisional()
        assert state.process_descriptors_at(fork.identity, event_time=at) == expected
    assert state.materialization_digest() == digest
    builder, session = _session(modeled)
    retry = builder.plan_macos_ssh_receiver_fork(
        modeled.root,
        session=session,
        forked_at=at,
        execution_directory=directory,
        lifecycle_group_id="invented-ssh-root",
    )
    assert retry.identity == fork.identity
    builder.bind_session_processes(session, transport_plan=retry, process_tree_root_plan=retry)
    plan = builder.seal()
    with state.prepared_materialization_batch(plan) as claim:
        claim.commit_no_fail()
    restored = StateManager()
    _restore_head(restored, _capture_head(state))
    assert restored.get_process_identity("MAC-01", fork.identity.pid) == fork.identity
    assert restored.process_descriptors_at(fork.identity, event_time=at) == expected
    assert restored.get_session(session.identity.logon_id).transport_pid == fork.identity.pid
    census = dict(state.macos_process_census_snapshot())["MAC-01"]
    assert census.forks.count == 1 and census.execs.count == census.aggregate_births == 0
    assert restored.macos_process_census_snapshot() == state.macos_process_census_snapshot()


@pytest.mark.parametrize(
    "damage", ["parent", "owner", "directory", "observation", "authentication", "naive"]
)
def test_receiver_fork_rejects_changed_parent_session_or_pre_auth_boundary(
    modeled: _Fixture, damage: str
) -> None:
    builder, session = _session(modeled)
    at = modeled.start + timedelta(seconds=2)
    parent = modeled.root
    directory = modeled.producer.directory("MAC-01", "/", at)
    if damage == "parent":
        parent = replace(parent, principal="alex")
    elif damage == "owner":
        _, session = _session(modeled)
    elif damage == "directory":
        directory = modeled.producer.directory("MAC-01", "/Users/alex", at)
    elif damage == "observation":
        directory = replace(directory, observed_at=at + timedelta(microseconds=1))
    elif damage == "authentication":
        at = session.audit_origin.created_at
        directory = modeled.producer.directory("MAC-01", "/", at)
    else:
        at = at.replace(tzinfo=None)
    digest = modeled.state.materialization_digest()
    with pytest.raises(StateError):
        builder.plan_macos_ssh_receiver_fork(
            parent,
            session=session,
            forked_at=at,
            execution_directory=directory,
            lifecycle_group_id="invented-ssh-root",
        )
    assert modeled.state.materialization_digest() == digest


@pytest.mark.parametrize("damage", [None, "unknown", "nonroot", "session", "other_owner"])
def test_explicit_root_service_responsibility_requires_its_exact_parent_lifetime(
    modeled: _Fixture, damage: str | None
) -> None:
    builder, session = _session(modeled)
    at = modeled.start + timedelta(seconds=2)
    fork = builder.plan_macos_ssh_receiver_fork(
        modeled.root,
        session=session,
        forked_at=at,
        execution_directory=modeled.producer.directory("MAC-01", "/", at),
        lifecycle_group_id="invented-ssh-root",
    )
    parent = replace(
        modeled.root, logon_id=session.identity.logon_id, responsibility=ProcessResponsibility(None)
    )
    child = replace(
        fork.identity,
        responsibility=ProcessResponsibility(
            ResponsibleProcessReference(
                parent.hostname, parent.object_id, parent.pid, parent.started_at
            )
        ),
    )
    if damage == "unknown":
        parent = replace(parent, responsibility=None)
    elif damage == "nonroot":
        parent = replace(parent, principal="alex")
    elif damage == "session":
        child = replace(child, logon_id="another-session")
    elif damage == "other_owner":
        child = replace(child, responsibility=ProcessResponsibility(None))
    assert macos_service_child_responsibility_matches(parent, child) == (damage is None)
