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

"""Focused tests for immutable canonical event identity roles."""

from dataclasses import FrozenInstanceError
from datetime import UTC, datetime

import pytest

from evidenceforge.events.identity import (
    EntityIdentity,
    EventIdentityPlan,
    ProcessIdentity,
    ThreadIdentity,
)


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


def test_event_identity_plan_projects_canonical_process_identity() -> None:
    process = _process_identity()
    plan = EventIdentityPlan(subject=process)

    assert plan.object_id == process.object_id
    assert plan.canonical_tid == process.primary_thread.tid


def test_non_process_entity_identity_is_frozen_and_typed() -> None:
    identity = EntityIdentity(
        object_id="file-object",
        kind="file",
        hostname="WS-01",
        semantic_key=r"WS-01:c:\temp\out.txt",
    )

    with pytest.raises(FrozenInstanceError):
        identity.object_id = "wrong"  # type: ignore[misc]


def test_non_process_entity_identity_requires_object_id() -> None:
    with pytest.raises(ValueError, match="object_id"):
        EntityIdentity(object_id="", kind="file")


def test_dependent_process_plan_has_no_implicit_tid() -> None:
    process = _process_identity()
    plan = EventIdentityPlan(actor=process)

    assert plan.canonical_tid == -1
