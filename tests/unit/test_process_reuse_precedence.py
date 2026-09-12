# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Preserve process-reuse selection order and preflight's mutation boundary."""

from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from evidenceforge.generation.actions.endpoint_effects import PreparedProcessEffectActor
from evidenceforge.generation.actions.process_execution import ProcessExecutionRequest
from evidenceforge.generation.activity import ActivityGenerator
from evidenceforge.generation.state_manager import StateManager
from evidenceforge.models.scenario import System, User
from evidenceforge.utils.rng import _get_rng


@pytest.mark.parametrize(
    ("single", "service", "application", "storyline", "exact_parent", "late", "expected"),
    [
        (40, 41, 42, False, False, False, 40),
        (None, 41, 42, False, False, False, 41),
        (None, None, 42, False, False, False, 42),
        (None, None, None, False, False, False, None),
        (None, None, 42, True, False, False, None),
        (40, 41, 42, False, True, False, 40),
        (40, 41, 42, False, False, True, 0),
        (0, 41, 42, False, False, False, 0),
    ],
)
def test_bounded_reuse_precedence_and_visibility(
    single: int | None,
    service: int | None,
    application: int | None,
    storyline: bool,
    exact_parent: bool,
    late: bool,
    expected: int | None,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    time = datetime(2024, 3, 18, 13, tzinfo=UTC)
    state = StateManager()
    state.set_current_time(time)
    generator = ActivityGenerator(state, {})
    generator._runtime_content_manager = None
    user = User(username="alice", full_name="Alice", email="alice@example.test")
    system = System(hostname="WIN", ip="10.0.0.1", os="Windows 11", type="workstation")
    request = ProcessExecutionRequest(
        user=user,
        system=system,
        time=time,
        logon_id="session",
        process_name=r"C:\Tools\helper.exe",
        command_line="helper.exe",
        parent_pid=1000,
        from_storyline=storyline,
        require_exact_parent=exact_parent,
        source_visible_by=time + timedelta(seconds=5),
        suppress_command_file_effect=True,
    )
    actor = PreparedProcessEffectActor(
        hostname=system.hostname,
        image=request.process_name,
        command_line=request.command_line,
        username=user.username,
        logon_id=request.logon_id,
        lifecycle_id="process-fixture",
        started_at=time,
        session_deadline=None,
    )
    calls = Mock()
    calls.singleton.return_value = single
    calls.service.return_value = service
    calls.application.return_value = application
    from evidenceforge.generation.actions.process_support.reuse import ProcessReusePolicy
    from evidenceforge.generation.actions.process_support.sources import ProcessSourceTiming

    monkeypatch.setattr(
        ProcessReusePolicy,
        "_existing_windows_singleton_pid",
        lambda self, *args, **kwargs: calls.singleton(*args, **kwargs),
    )
    monkeypatch.setattr(
        ProcessReusePolicy,
        "_existing_windows_singleton_service_pid",
        lambda self, *args, **kwargs: calls.service(*args, **kwargs),
    )
    monkeypatch.setattr(
        ProcessReusePolicy,
        "_existing_persistent_user_app_pid",
        lambda self, *args, **kwargs: calls.application(*args, **kwargs),
    )
    generator.state_manager = calls.state
    parent = SimpleNamespace(image=r"C:\Windows\System32\services.exe")
    running = SimpleNamespace(
        parent_pid=1000,
        image=request.process_name,
        command_line=request.command_line,
        username=user.username,
        logon_id=request.logon_id,
        start_time=time - timedelta(minutes=1),
    )
    calls.state.get_process.side_effect = lambda host, pid: parent if pid == 1000 else running
    calls.state.get_process_identity.return_value = SimpleNamespace(object_id="fixture-object")
    monkeypatch.setattr(
        ProcessSourceTiming,
        "process_source_create_bound",
        lambda self, *args: calls.source_bound(*args),
    )
    calls.source_bound.return_value = time + timedelta(seconds=10 if late else -1)
    rng_before = _get_rng().getstate()

    found, intent = generator._bounded_process_reuse_intent(request=request, actor=actor)

    assert found is (expected is not None)
    assert (intent.pid if intent else 0 if found else None) == expected
    selection = [c[0] for c in calls.mock_calls if c[0] in {"singleton", "service", "application"}]
    expected_selection = ["singleton"]
    if single is None:
        expected_selection.append("service")
        if service is None and not storyline:
            expected_selection.append("application")
    assert selection == expected_selection
    if calls.application.called:
        assert calls.application.call_args.kwargs["update_activity"] is False
    calls.state.update_process_activity_time.assert_not_called()
    assert _get_rng().getstate() == rng_before
