# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Narrow correctness checks for sessions whose two transport roles share a host."""

from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest

from evidenceforge.generation.actions.network_transaction_planner import NetworkTransactionPlanner
from evidenceforge.models.exceptions import EventContractError
from evidenceforge.utils.rng import reset_thread_rng
from tests.unit.test_ssh_deferred_production import (
    _assert_no_dispatcher_residue,
    _execute_real_caller,
    _fixture,
)


@pytest.mark.parametrize("threaded", [False, True])
def test_exact_ssh_to_the_source_host_preserves_one_process_endpoint(
    tmp_path: Path, threaded: bool
) -> None:
    reset_thread_rng(42)
    fixture = _fixture(tmp_path, threaded=threaded)
    fixture.source = fixture.target
    fixture.generator._ip_to_system = {fixture.target.ip: fixture.target}
    try:
        _, logon_id = _execute_real_caller(fixture)
        session = fixture.state.get_session(logon_id)
        assert session is not None
        assert session.system == fixture.target.hostname
        assert session.source_ip == fixture.target.ip
        assert fixture.generator._ssh_channel_manager.census().open_sessions == 1
        _assert_no_dispatcher_residue(fixture.generator.dispatcher)
    finally:
        ecar_rows, zeek_rows = fixture.close_and_read()
    # A network sensor cannot observe traffic that stays on the same endpoint.
    assert zeek_rows == []
    assert all(row["hostname"] == fixture.target.hostname for row in ecar_rows)
    assert (
        len(
            [
                row
                for row in ecar_rows
                if row.get("object") == "USER_SESSION" and row.get("action") == "LOGIN"
            ]
        )
        == 1
    )
    receiver_creates = [
        row
        for row in ecar_rows
        if row.get("object") == "PROCESS"
        and row.get("action") == "CREATE"
        and row.get("properties", {}).get("image_path") == "/usr/sbin/sshd"
    ]
    assert len(receiver_creates) == 1


def test_loopback_process_projection_rejects_a_foreign_endpoint_before_state(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fixture = _fixture(tmp_path)
    fixture.source = fixture.target
    fixture.generator._ip_to_system = {fixture.target.ip: fixture.target}
    original = NetworkTransactionPlanner._deferred_session_dependent_builders

    def replace_endpoint(planner: NetworkTransactionPlanner, *args: Any) -> Any:
        builders = original(planner, *args)
        for builder, _ in builders:
            if builder.process is not None:
                assert builder.src_host is not None
                builder.src_host = replace(builder.src_host, ip="10.0.0.99")
        return builders

    monkeypatch.setattr(
        NetworkTransactionPlanner, "_deferred_session_dependent_builders", replace_endpoint
    )
    before = fixture.state.materialization_digest()
    try:
        with pytest.raises(EventContractError, match="exact State target"):
            _execute_real_caller(fixture)
        assert fixture.state.materialization_digest() == before
        _assert_no_dispatcher_residue(fixture.generator.dispatcher)
    finally:
        rows, zeek_rows = fixture.close_and_read()
    assert rows == zeek_rows == []
