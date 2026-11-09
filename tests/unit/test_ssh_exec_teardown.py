# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""SSH closes current executions without rewriting original process lifetime facts."""

from datetime import timedelta
from pathlib import Path

import pytest

from evidenceforge.generation.actions.posix_process import process_exec_occurrence
from evidenceforge.utils.rng import reset_thread_rng
from tests.unit.test_process_exit_projection import _prepare
from tests.unit.test_ssh_deferred_production import (
    _START,
    _assert_no_dispatcher_residue,
    _fixture,
    _open_compatibility_ssh_receiver_descendant_graph,
    _open_exact_ssh_receiver_descendant_graph,
)


@pytest.mark.parametrize("exact", [False, True])
@pytest.mark.parametrize("same_image", [False, True])
def test_ssh_close_preserves_lifetime_and_terminates_replaced_descendant_execution(
    tmp_path: Path, exact: bool, same_image: bool
) -> None:
    reset_thread_rng(42)
    fixture = _fixture(tmp_path)
    graph = (
        _open_exact_ssh_receiver_descendant_graph(fixture)
        if exact
        else _open_compatibility_ssh_receiver_descendant_graph(fixture)
    )
    logon_id, receiver_pid, shell_pid, *children = graph
    pid = children[-1]
    before = fixture.state.get_process_identity(fixture.target.hostname, pid)
    registry = fixture.generator._lifecycle_authority.registry
    lifetime = registry.get_process(before.object_id).identity
    builder = fixture.state.begin_action_cohort_materialization()
    after = builder.execute_process(
        before,
        image=before.image if same_image else "/usr/bin/printf",
        command_line="printf completed",
        executed_at=before.execution_started_at + timedelta(seconds=1),
    )
    event = process_exec_occurrence(
        host=fixture.generator._build_host_context(fixture.target),
        before=before,
        after=after,
        integrity_level="Medium",
    )
    dispatcher = fixture.generator.dispatcher
    dispatcher.publish_prepared_action_cohort_batch(
        _prepare(
            dispatcher, builder.seal(), event, exact=True, root=f"process-exec:{after.execution_id}"
        )
    )
    snapshot = registry.get_process(before.object_id)
    assert snapshot.identity == lifetime
    assert snapshot.current_view.execution_ordinal == 1
    fixture.generator.finalize_ssh_session_lifecycles(_START + timedelta(hours=2))
    assert fixture.state.get_session(logon_id) is None
    closed = registry.get_process(before.object_id)
    assert closed.identity == lifetime
    assert closed.closed_at is not None
    assert closed.current_view.image == after.image
    assert closed.current_view.execution_ordinal == after.execution_ordinal
    _assert_no_dispatcher_residue(dispatcher)
    rows, _ = fixture.close_and_read()
    terminated = [
        row
        for row in rows
        if row.get("action") == "TERMINATE" and row.get("objectID") == after.object_id
    ]
    assert len(terminated) == 1


@pytest.mark.parametrize("exact", [False, True])
@pytest.mark.parametrize("same_image", [False, True])
def test_ssh_close_rejects_execution_not_published_to_lifecycle_owner(
    tmp_path: Path, exact: bool, same_image: bool
) -> None:
    from evidenceforge.models.exceptions import StateError

    reset_thread_rng(42)
    fixture = _fixture(tmp_path)
    graph = (
        _open_exact_ssh_receiver_descendant_graph(fixture)
        if exact
        else _open_compatibility_ssh_receiver_descendant_graph(fixture)
    )
    logon_id, _, _, *children = graph
    before = fixture.state.get_process_identity(fixture.target.hostname, children[-1])
    builder = fixture.state.begin_action_cohort_materialization()
    after = builder.execute_process(
        before,
        image=before.image if same_image else "/usr/bin/printf",
        command_line="printf completed",
        executed_at=before.execution_started_at + timedelta(seconds=1),
    )
    fixture.state.materialize_action_cohort(builder.seal())
    with pytest.raises(StateError, match="descendant"):
        fixture.generator.finalize_ssh_session_lifecycles(_START + timedelta(hours=2))
    assert fixture.state.get_session(logon_id) is not None
    assert fixture.state.get_process_identity(after.hostname, after.pid) == after
    fixture.close_and_read()
