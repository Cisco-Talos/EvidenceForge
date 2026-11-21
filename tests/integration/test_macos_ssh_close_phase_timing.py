# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Exact Mac SSH close planning preserves final anchors without equal subdivisions."""

from pathlib import Path

from tests.unit.test_macos_ssh_close_execution import _close_fixture


def test_exact_mac_ssh_descendant_closes_keep_fixed_receiver_and_vary_transition_shares(
    tmp_path: Path,
) -> None:
    state, _dispatcher, emitter, executor, continuation, roles = _close_fixture(tmp_path)
    try:
        bundle = continuation.materialize_bundle(executor)
        planned = bundle._plan_exact_receiver_descendant_terminations(
            continuation.materialize_state(), continuation.plan.auth_state, continuation
        )
        assert planned == continuation.receiver_descendant_terminations()
        assert [p.identity.object_id for p in planned] == [
            roles.shell.object_id,
            roles.authenticated_child.object_id,
        ]
        times = [p.terminate_at for p in planned] + [continuation.plan.receiver_terminate_time]
        assert continuation.plan.close_time < times[0] < times[1] < times[2]
        assert all(
            state.get_process(p.identity.hostname, p.identity.pid) is not None for p in planned
        )
        first, second = (
            round((b - a).total_seconds() * 1_000_000)
            for a, b in zip(times, times[1:], strict=False)
        )
        assert abs(second - first) > 2, (first, second)
    finally:
        emitter.close()
