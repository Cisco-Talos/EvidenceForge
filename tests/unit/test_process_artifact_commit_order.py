# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

from dataclasses import replace

import pytest

from evidenceforge.models.exceptions import StateError
from tests.unit.test_process_service_lifecycle_authority import _authority, _process_plan


@pytest.mark.parametrize("platform", ["windows", "linux", "macos"])
@pytest.mark.parametrize("failure", [False, True])
def test_external_artifact_commit_precedes_allocation_and_timing_tail(
    platform: str, failure: bool
) -> None:
    authority, state, registry, _ = _authority()
    plan = _process_plan(
        state,
        parent_pid=4 if platform == "windows" else 0,
        image=r"C:\Windows\System32\spoolsv.exe"
        if platform == "windows"
        else "/usr/local/bin/invented",
        username="SYSTEM" if platform == "windows" else "root",
        os_category=platform,
    )
    identity = plan.identity
    before = state.materialization_digest()
    observations: list[tuple[str, bool, bool]] = []

    def observe(stage: str) -> None:
        observations.append(
            (
                stage,
                state.get_process(identity.hostname, identity.pid) is not None,
                registry.get_process(identity.object_id) is not None,
            )
        )

    def artifacts() -> None:
        observe("artifacts")
        if failure:
            raise StateError("injected artifact transaction failure")

    def timing() -> None:
        observe("timing")

    if failure:
        with pytest.raises(StateError, match="artifact transaction"):
            authority.materialize_process(
                plan, commit_external_first=artifacts, finalize_external_no_fail=timing
            )
        assert observations == [("artifacts", False, False)]
        assert state.materialization_digest() == before
        assert registry.get_process(identity.object_id) is None
    else:
        process, receipt = authority.materialize_process(
            plan, commit_external_first=artifacts, finalize_external_no_fail=timing
        )
        assert observations == [("artifacts", False, False), ("timing", True, True)]
        assert process.ecar_object_id == identity.object_id
        assert authority.authenticates_materialization_receipt(plan, receipt)


def test_invalid_process_plan_cannot_invoke_external_commit() -> None:
    authority, state, _, _ = _authority()
    plan = _process_plan(state)
    calls: list[bool] = []
    with pytest.raises(StateError):
        authority.materialize_process(
            replace(plan, _expected_version=plan.expected_version + 1),
            commit_external_first=lambda: calls.append(True),
        )
    assert calls == []
