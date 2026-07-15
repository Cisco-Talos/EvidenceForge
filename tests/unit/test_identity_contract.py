# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
#
# SPDX-License-Identifier: MIT

"""Focused tests for immutable event identity roles and compatibility projections."""

from datetime import UTC, datetime

import pytest

from evidenceforge.events.contexts import EdrContext
from evidenceforge.events.identity import EventIdentityPlan, ProcessIdentity, ThreadIdentity


def _process_identity() -> ProcessIdentity:
    started_at = datetime(2024, 3, 18, 12, 0, tzinfo=UTC)
    thread = ThreadIdentity(
        hostname="WS-01",
        process_object_id="process-1",
        pid=4100,
        tid=8124,
        object_id="thread-1",
        started_at=started_at,
        kind="primary",
    )
    return ProcessIdentity(
        hostname="WS-01",
        object_id="process-1",
        pid=4100,
        parent_pid=1200,
        image=r"C:\Windows\System32\cmd.exe",
        command_line="cmd.exe /c whoami",
        principal="analyst",
        logon_id="0x1234",
        started_at=started_at,
        lifecycle_group_id="process-group-1",
        parent_lifecycle_group_id="session-group-1",
        primary_thread=thread,
    )


def test_edr_compatibility_projection_accepts_canonical_identity() -> None:
    process = _process_identity()
    plan = EventIdentityPlan(subject=process)

    EdrContext(
        object_id=process.object_id,
        tid=process.primary_thread.tid,
    ).validate_identity_plan(plan)


@pytest.mark.parametrize(
    ("context", "message"),
    [
        (EdrContext(object_id="wrong"), "object_id"),
        (EdrContext(actor_id="wrong"), "actor_id"),
        (EdrContext(tid=9999), "tid"),
    ],
)
def test_edr_compatibility_projection_rejects_contradictions(
    context: EdrContext,
    message: str,
) -> None:
    process = _process_identity()
    plan = EventIdentityPlan(subject=process, actor=process)

    with pytest.raises(ValueError, match=message):
        context.validate_identity_plan(plan)


def test_dependent_process_plan_has_no_implicit_tid() -> None:
    process = _process_identity()
    plan = EventIdentityPlan(actor=process)

    assert plan.canonical_tid == -1
