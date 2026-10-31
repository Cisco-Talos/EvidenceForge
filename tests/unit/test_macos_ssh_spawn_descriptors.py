# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Invented helper execs exercise measured layouts through canonical State transactions."""

from dataclasses import replace
from datetime import timedelta

import pytest

from evidenceforge.events.macos_descriptors import MacosDescriptorBinding, MacosDescriptorTable
from evidenceforge.events.macos_spawn_io import MacosSpawnIO
from evidenceforge.generation.checkpoints.state_manager_head import _capture_head, _restore_head
from evidenceforge.generation.macos_spawn_descriptors import plan_spawn_descriptors
from evidenceforge.generation.state_manager import StateManager
from evidenceforge.models.exceptions import StateError
from tests.unit.test_macos_metadata_producers import _Fixture
from tests.unit.test_macos_metadata_producers import modeled as modeled


def test_ssh_helper_tables_preserve_open_objects_and_atomic_pipe_allocation(
    modeled: _Fixture,
) -> None:
    state, provider = modeled.state, modeled.producer
    builder = state.begin_action_cohort_materialization()
    birth = provider.plan_fork(
        builder, state, modeled.root, at=modeled.start + timedelta(seconds=1)
    )
    state.materialize_action_cohort(builder.seal())
    before = birth.identity
    previous = state.process_descriptors_at(before, event_time=before.started_at)
    initial_counter = state._macos_pipe_counters.copy()
    for ordinal, (kind, image, arguments) in enumerate(
        (
            ("ssh_inetd", "/usr/libexec/sshd-keygen-wrapper", ("sshd-keygen-wrapper",)),
            ("ssh_session", "/usr/libexec/sshd-session", ("/usr/libexec/sshd-session", "-i")),
            ("ssh_auth", "/usr/libexec/sshd-auth", ("/usr/libexec/sshd-auth",)),
        ),
        start=2,
    ):
        at = modeled.start + timedelta(seconds=ordinal)
        binary = provider._filesystem.deployed_binary(before.hostname, image, "root")
        builder = state.begin_action_cohort_materialization()
        prepared = provider.plan_exec(
            builder,
            state,
            before,
            at=at,
            image=image,
            requested_path=image,
            arguments=arguments,
            binary=binary,
            spawn_io=MacosSpawnIO(
                kind, provider.profile.first_pipe_id if kind == "ssh_auth" else None
            ),
        )
        plan = builder.seal()
        table = plan.process_executions[0].descriptors_after
        assert prepared.descriptors.table == table
        assert table.native_last_fd == (2 if kind == "ssh_inetd" else 4)
        assert [item.kind for item in table.bindings] == {
            "ssh_inetd": ["socket", "socket", "file"],
            "ssh_session": ["socket", "socket", "file", "file", "socket"],
            "ssh_auth": ["socket", "socket", "file", "socket", "pipe"],
        }[kind]
        assert table.bindings[2] == previous.bindings[2]
        if kind == "ssh_inetd":
            assert table.bindings[0].object_id == table.bindings[1].object_id
        else:
            assert table.bindings[:3] == previous.bindings[:3]
        digest = state.materialization_digest()
        with state.prepared_action_cohort_materialization(plan) as claim:
            claim.certify_composite_commit(claim.expected_result)
            claim.apply_provisional()
            assert state.process_descriptors_at(prepared.process, event_time=at) == table
        assert state.materialization_digest() == digest
        assert state._macos_pipe_counters == initial_counter
        state.materialize_action_cohort(plan)
        restored = StateManager()
        _restore_head(restored, _capture_head(state))
        assert restored.process_descriptors_at(prepared.process, event_time=at) == table
        if kind == "ssh_auth":
            expected = (provider.profile.first_pipe_id, provider.profile.first_pipe_id)
            assert state._macos_pipe_counters[before.hostname] == expected
            assert restored._macos_pipe_counters[before.hostname] == expected
            pipe = table.bindings[-1]
            assert pipe.fd == 4 and pipe.native_pipe_id == expected[0]
        else:
            assert state._macos_pipe_counters == initial_counter
        before, previous = prepared.process, table


@pytest.mark.parametrize("kind", ["ssh_inetd", "ssh_session", "ssh_auth"])
@pytest.mark.parametrize("damage", ["unknown", "terminal", "missing", "closed", "wrong_kind"])
def test_ssh_file_actions_reject_unproved_inherited_state(
    modeled: _Fixture, kind: str, damage: str
) -> None:
    at = modeled.start
    process = modeled.root
    standard = tuple(
        MacosDescriptorBinding(
            fd,
            "socket" if kind != "ssh_inetd" and fd < 2 else "file",
            f"invented-open-{fd}",
            False,
        )
        for fd in range(3)
    )
    if damage == "missing":
        standard = standard[1:]
    elif damage == "closed":
        standard = (replace(standard[0], close_on_exec=True),) + standard[1:]
    elif damage == "wrong_kind":
        standard = (
            replace(standard[0], kind="socket" if kind == "ssh_inetd" else "file"),
        ) + standard[1:]
    table = MacosDescriptorTable(process.hostname, at, standard, 2)
    with pytest.raises(StateError):
        plan_spawn_descriptors(
            process,
            MacosSpawnIO(
                kind, modeled.producer.profile.first_pipe_id if kind == "ssh_auth" else None
            ),
            inherited=None if damage == "unknown" else table,
            terminal=None if damage == "terminal" else "absent",
            pipe_counter=None,
        )


@pytest.mark.parametrize(
    "kind,first", [("ssh_auth", None), ("ssh_auth", True), ("ssh_inetd", 1), ("ssh_session", 1)]
)
def test_ssh_file_actions_require_exact_pipe_policy(kind: str, first: int | None) -> None:
    with pytest.raises(ValueError):
        MacosSpawnIO(kind, first)
