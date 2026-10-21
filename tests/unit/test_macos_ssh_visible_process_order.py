# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Actual source clocks preserve the receiver's visible process lifecycles."""

from dataclasses import replace
from pathlib import Path

import pytest

from evidenceforge.generation.actions.ssh_session import SshSessionActionBundle
from tests.unit.test_macos_ssh_receiver_planning import _mac_fixture


@pytest.mark.parametrize("shell", ["/bin/zsh", "/bin/bash"])
def test_receiver_transitions_and_children_follow_final_visible_births(
    tmp_path: Path, shell: str
) -> None:
    fixture = _mac_fixture(tmp_path, shell)
    SshSessionActionBundle(
        replace(fixture.request(), emit_session_close=True), fixture.generator
    )._execute_macos_receiver()
    rows, _flows = fixture.close_and_read()
    processes = [row | row.get("properties", {}) for row in rows if row.get("object") == "PROCESS"]
    births = {row["objectID"]: row for row in processes if row["action"] == "CREATE"}
    closes = {row["objectID"]: row for row in processes if row["action"] == "TERMINATE"}
    transitions = [row for row in processes if row["action"] == "MODIFY"]
    assert {row["operation"] for row in transitions} == {
        "exec",
        "audit_bind",
        "privilege_drop",
        "service_drop",
        "job_control",
    }
    assert sum(row.get("operation") == "fork" for row in births.values()) == 3
    for row in processes:
        born = births.get(row["objectID"])
        if born is not None:
            assert row["timestamp_ms"] >= born["timestamp_ms"], row
        closed = closes.get(row["objectID"])
        if closed is not None:
            assert row["timestamp_ms"] <= closed["timestamp_ms"], row
        if row["action"] == "CREATE" and row.get("parentObjectID") in births:
            assert row["timestamp_ms"] >= births[row["parentObjectID"]]["timestamp_ms"], row
