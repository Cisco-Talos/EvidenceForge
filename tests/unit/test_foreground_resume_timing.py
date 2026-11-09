# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Foreground resumes use one scoped canonical scheduling relationship."""

from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import pytest

from evidenceforge.generation.actions.process_support.foreground import ProcessForegroundLifecycle
from evidenceforge.generation.activity import ActivityGenerator
from evidenceforge.generation.state_manager import StateManager
from evidenceforge.models.exceptions import StateError

T0 = datetime(2026, 11, 2, 13, tzinfo=UTC)


@pytest.mark.parametrize("hostname", ["MAC-01", "LINUX-01"])
def test_resume_gap_is_scoped_varied_and_independent_of_visitation(hostname: str) -> None:
    generator = ActivityGenerator(StateManager(), {})
    owner = generator._process_foreground()

    def resume(child: str) -> datetime:
        return owner.foreground_child_resume_at(
            hostname=hostname,
            logon_id="session",
            parent_pid=42,
            child_object_id=child,
            closed_at=T0,
        )

    first = {str(i): resume(str(i)) for i in range(32)}
    generator._sample_profile_activity_gap(
        "linux.sudo.child_ready", stable_id="unrelated", host="OTHER"
    )
    assert first == {str(i): resume(str(i)) for i in reversed(range(32))}
    assert len(set(first.values())) > 20
    assert all(
        timedelta(milliseconds=1) <= value - T0 <= timedelta(milliseconds=20)
        for value in first.values()
    )
    assert not any(value - T0 == timedelta(milliseconds=1) for value in first.values())


def test_same_release_uses_same_phase_at_both_readiness_callers() -> None:
    generator = ActivityGenerator(StateManager(), {})
    owner = generator._process_foreground()
    kwargs = dict(
        hostname="MAC-01",
        logon_id="session",
        parent_pid=42,
        child_object_id="canonical-child",
        closed_at=T0,
    )
    assert owner.foreground_child_resume_at(
        **kwargs
    ) == generator._process_foreground().foreground_child_resume_at(**kwargs)
    assert owner.foreground_child_resume_at(**kwargs) != owner.foreground_child_resume_at(
        **{**kwargs, "hostname": "MAC-02"}
    )
    assert owner.foreground_child_resume_at(**kwargs) != owner.foreground_child_resume_at(
        **{**kwargs, "logon_id": "other-session"}
    )


@pytest.mark.parametrize("milliseconds", [0, -1])
def test_resume_rejects_nonpositive_policy(milliseconds: int) -> None:
    owner = SimpleNamespace(
        activity_timing=SimpleNamespace(
            sample_profile_gap=lambda *args, **kwargs: timedelta(milliseconds=milliseconds)
        )
    )
    with pytest.raises(StateError, match="positive configured gap"):
        ProcessForegroundLifecycle.foreground_child_resume_at(
            owner,
            hostname="MAC",
            logon_id="session",
            parent_pid=42,
            child_object_id="child",
            closed_at=T0,
        )
