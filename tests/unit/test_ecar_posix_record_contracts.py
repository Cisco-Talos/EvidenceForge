# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Supported POSIX modifications retain bounded before/after record semantics."""

from dataclasses import replace
from pathlib import Path

import pytest

from evidenceforge.formats.loader import load_format
from evidenceforge.formats.validator import validate_event
from evidenceforge.generation.actions.ssh_session import SshSessionActionBundle
from tests.unit.test_macos_ssh_receiver_planning import _mac_fixture


@pytest.fixture
def transitions(tmp_path: Path) -> dict[str, dict[str, object]]:
    fixture = _mac_fixture(tmp_path)
    SshSessionActionBundle(
        replace(fixture.request(), emit_session_close=True), fixture.generator
    )._execute_macos_receiver()
    rows, _flows = fixture.close_and_read()
    return {
        row["properties"]["operation"]: row | row["properties"]
        for row in rows
        if row.get("object") == "PROCESS" and row.get("action") == "MODIFY"
    }


def test_all_rendered_posix_transition_families_satisfy_record_contract(
    transitions: dict[str, dict[str, object]],
) -> None:
    assert set(transitions) == {
        "exec",
        "audit_bind",
        "privilege_drop",
        "service_drop",
        "job_control",
    }
    for row in transitions.values():
        result = validate_event(load_format("ecar"), row)
        assert result.valid, result


@pytest.mark.parametrize(
    "operation,changes",
    [
        ("exec", {"operation": "unmodeled"}),
        ("exec", {"execution_id": None}),
        ("exec", {"previous_execution_id": None}),
        ("exec", {"previous_image_path": None}),
        ("audit_bind", {"audit_uid": None}),
        ("service_drop", {"previous_effective_uid": None}),
        ("service_drop", {"image_path": "/unmodeled/replacement"}),
        ("service_drop", {"execution_id": "unmodeled-replacement"}),
        ("privilege_drop", {"audit_session_id": "999999"}),
        ("job_control", {"process_group_id": None}),
    ],
)
def test_invalid_posix_modifications_remain_rejected(
    transitions: dict[str, dict[str, object]], operation: str, changes: dict[str, object]
) -> None:
    assert not validate_event(load_format("ecar"), transitions[operation] | changes).valid


def test_exec_cannot_keep_its_previous_execution_identity(
    transitions: dict[str, dict[str, object]],
) -> None:
    row = transitions["exec"].copy()
    row["execution_id"] = row["previous_execution_id"]
    assert not validate_event(load_format("ecar"), row).valid
