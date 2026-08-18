# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Focused contracts for SMB composite timing-runtime ownership."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from evidenceforge.generation.actions.smb_activity import (
    SmbActivityActionBundle,
    SmbActivityRequest,
    SmbActivityResult,
)
from evidenceforge.generation.storage_world import CompiledStorageFile
from evidenceforge.generation.timing import TimingRuntime
from evidenceforge.models.exceptions import StateError
from evidenceforge.models.scenario import (
    SmbActivityEventSpec,
    SmbClientLocation,
    SmbShareLocation,
    System,
    User,
)

_START = datetime(2024, 1, 15, 10, tzinfo=UTC)


def _composite_bundle(
    runtime: TimingRuntime,
    *,
    destination: SmbShareLocation | SmbClientLocation | None = None,
) -> tuple[
    SmbActivityActionBundle,
    list[tuple[str, datetime, datetime]],
    Mock,
]:
    source = SmbShareLocation(share="FS-01.finance", path=r"Reports\forecast.xlsx")
    resolved_destination = destination or SmbShareLocation(
        share="FS-02.archive",
        path=r"Incoming\forecast.xlsx",
    )
    spec = SmbActivityEventSpec(
        operation="move",
        purpose="interactive",
        source=source,
        destination=resolved_destination,
        outcome="success",
    )
    request = SmbActivityRequest(
        spec=spec,
        actor=User(
            username="analyst",
            full_name="Alicia Analyst",
            email="analyst@example.test",
        ),
        parent_system=System(
            hostname="WS-01",
            ip="10.0.0.10",
            os="Windows 11",
            type="workstation",
        ),
        time=_START,
    )
    selected = (
        CompiledStorageFile(
            file_id="forecast-v1",
            share=source.share,
            path=source.path or r"Reports\forecast.xlsx",
            size_bytes=4096,
            mime_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        ),
    )
    calls: list[tuple[str, datetime, datetime]] = []
    select = Mock(return_value=selected)

    bundle = object.__new__(SmbActivityActionBundle)
    bundle.executor = SimpleNamespace(timing_runtime=runtime)
    bundle.request = request
    bundle.anchor = SimpleNamespace(stable_id="smb-composite-timing-runtime")
    bundle._select = select
    bundle._mapping_for_share = lambda _share: None
    bundle._leg_outcome = lambda _location, *, operation: "success"

    def execute_child(
        child_spec: SmbActivityEventSpec,
        _files: tuple[CompiledStorageFile, ...],
        *,
        offset_ms: int,
        execution_time: datetime | None = None,
    ) -> SmbActivityResult:
        started_at = execution_time or request.time + timedelta(milliseconds=offset_ms)
        completed_at = started_at + timedelta(milliseconds=10)
        calls.append((child_spec.operation, started_at, completed_at))
        return SmbActivityResult(
            session_id="smb-session",
            tree_ids=(f"tree-{child_spec.operation}",),
            transport_uids=(f"uid-{child_spec.operation}",),
            operations=({"operation": child_spec.operation, "outcome": "success"},),
            completed_at=completed_at,
        )

    bundle._execute_child = execute_child
    return bundle, calls, select


def test_composite_smb_rejects_missing_engine_runtime_before_any_child() -> None:
    """A missing engine runtime is allocation-free at the composite boundary."""

    bundle, _calls, select = _composite_bundle(TimingRuntime(reference_time=_START))
    execute_child = Mock()
    bundle.executor = SimpleNamespace(timing_runtime=None)
    bundle._execute_child = execute_child

    with pytest.raises(StateError, match="executor-owned TimingRuntime"):
        bundle._execute_composite_transfer()

    select.assert_not_called()
    execute_child.assert_not_called()


def test_composite_smb_delete_gap_uses_one_runtime_with_deterministic_parity() -> None:
    """The read/create/delete sequence is stable and the delete gap stays configured."""

    first_runtime = TimingRuntime(reference_time=_START)
    second_runtime = TimingRuntime(reference_time=_START)
    first, first_calls, _select = _composite_bundle(first_runtime)
    second, second_calls, _select = _composite_bundle(second_runtime)

    first_result = first._execute_composite_transfer()
    second_result = second._execute_composite_transfer()

    assert first_result == second_result
    assert first_calls == second_calls
    assert [operation for operation, _started, _completed in first_calls] == [
        "read",
        "create",
        "delete",
    ]
    destination_completed_at = first_calls[1][2]
    delete_started_at = first_calls[2][1]
    assert timedelta(milliseconds=250) <= delete_started_at - destination_completed_at
    assert delete_started_at - destination_completed_at <= timedelta(milliseconds=1200)
    planner = first._timing_planner()
    assert planner.runtime is first_runtime
    assert planner.source == "smb"
    audit = first_runtime.audit.snapshot()
    assert audit.sample_counts == {
        "smb.cross_server_delete_after_destination": 1,
    }
    assert audit.distribution_counts == {"triangular": 1}


def test_share_to_client_move_uses_the_same_bounded_runtime_delete_gap() -> None:
    """Share-to-client moves retain copy-before-delete ordering and one owner."""

    runtime = TimingRuntime(reference_time=_START)
    bundle, calls, _select = _composite_bundle(
        runtime,
        destination=SmbClientLocation(path=r"C:\Users\analyst\Downloads\forecast.xlsx"),
    )

    result = bundle._execute_composite_transfer()

    assert result is not None
    assert [operation for operation, _started, _completed in calls] == ["copy", "delete"]
    copy_completed_at = calls[0][2]
    delete_started_at = calls[1][1]
    assert timedelta(milliseconds=250) <= delete_started_at - copy_completed_at
    assert delete_started_at - copy_completed_at <= timedelta(milliseconds=1200)
    assert runtime.audit.snapshot().sample_counts == {
        "smb.cross_server_delete_after_destination": 1,
    }
