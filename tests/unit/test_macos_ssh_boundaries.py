# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Mac source facts survive Linux-receiver SSH lifecycle planning."""

from datetime import UTC, datetime, timedelta
from pathlib import Path
from unittest.mock import Mock

import pytest

from evidenceforge.events.contexts import HostContext
from evidenceforge.generation.actions.ssh_session import (
    SshSessionActionBundle,
    SshSessionRequest,
    _SshCloseHostFacts,
    ssh_action_deadline_transport_headroom_seconds,
)
from evidenceforge.generation.activity import ActivityGenerator
from evidenceforge.models.exceptions import StateError
from evidenceforge.models.scenario import Scenario, System, User
from evidenceforge.validation.schema import ScenarioValidator
from tests.support.macos_ssh import macos_ssh_scenario


def test_mac_ssh_source_close_facts_preserve_platform_without_linux_substitution() -> None:
    host = HostContext(
        hostname="MAC-SSH-01",
        ip="192.0.2.10",
        os="macOS 26",
        os_category="macos",
        system_type="workstation",
        roles=["workstation"],
    )
    facts = _SshCloseHostFacts.capture(host)
    host.roles.append("changed-after-capture")
    restored = facts.materialize()
    assert restored.os_category == "macos"
    assert restored.os == "macOS 26"
    assert restored.roles == ["workstation"]
    with pytest.raises(ValueError, match="canonical identity"):
        _SshCloseHostFacts.capture(
            HostContext(
                hostname="UNKNOWN",
                ip="192.0.2.11",
                os="unknown",
                os_category="unknown",
                system_type="workstation",
            )
        )


def test_mac_ssh_source_deadline_uses_mac_clock_and_linux_receiver_clock() -> None:
    deadline = datetime(2026, 10, 15, 12, tzinfo=UTC)
    planner = Mock()
    planner.endpoint_clock_positive_headroom.side_effect = lambda _deadline, platform: timedelta(
        seconds=7 if platform == "macos" else 1
    )
    planner.endpoint_clock_negative_headroom.return_value = timedelta(seconds=2)
    mac = ssh_action_deadline_transport_headroom_seconds(
        source_deadline=deadline,
        source_timing_planner=planner,
        source_os_categories=("linux", "macos"),
    )
    assert planner.endpoint_clock_positive_headroom.call_args_list[-1].args == (deadline, "macos")
    planner.endpoint_clock_negative_headroom.assert_called_once_with(deadline, "linux")
    linux = ssh_action_deadline_transport_headroom_seconds(
        source_deadline=deadline,
        source_timing_planner=planner,
        source_os_categories=("linux",),
    )
    assert mac - linux == pytest.approx(6.0)


def test_unqualified_mac_receiver_fails_before_executor_or_linux_shell_access() -> None:
    executor = Mock()
    target = System(hostname="MAC-RECEIVER", ip="192.0.2.20", os="macOS 26", type="workstation")
    user = User(username="casey", full_name="Casey", email="casey@example.test")
    timestamp = datetime(2026, 10, 15, 12, tzinfo=UTC)
    request = SshSessionRequest(
        user=user, target_system=target, time=timestamp, source_ip="198.51.100.10"
    )
    with pytest.raises(StateError, match="explicit arm64 workstation"):
        SshSessionActionBundle(request, executor).execute_with_identity()
    with pytest.raises(StateError, match="Linux SSH shell bootstrap"):
        ActivityGenerator.ensure_linux_ssh_session_shell(
            executor, user, target, "0x1234", timestamp, timestamp
        )
    assert executor.mock_calls == []


@pytest.mark.parametrize("damage", ["architecture", "type", "account", "type10"])
def test_mac_receiver_validation_exposes_bounded_profile(scenarios_dir: Path, damage: str) -> None:
    document = macos_ssh_scenario(scenarios_dir, macos_receiver=True).model_dump(mode="json")
    target = document["environment"]["systems"][1]
    if damage == "architecture":
        target["architecture"] = "x64"
    elif damage == "type":
        target["type"] = "server"
    elif damage == "account":
        target["assigned_user"] = None
    elif damage == "type10":
        document["storyline"][1]["events"][0] = {
            "type": "logon",
            "logon_type": 10,
            "source_ip": "10.0.0.10",
        }
    issues = ScenarioValidator(Scenario.model_validate(document)).validate()
    assert any(issue.severity == "error" and "Mac" in issue.message for issue in issues)


@pytest.mark.parametrize("authored_close", [False, True])
def test_mac_receiver_validation_admits_existing_fields(
    scenarios_dir: Path, authored_close: bool
) -> None:
    issues = ScenarioValidator(
        macos_ssh_scenario(scenarios_dir, macos_receiver=True, authored_close=authored_close)
    ).validate()
    assert not [issue for issue in issues if issue.severity == "error"]


def test_mac_receiver_service_capability_remains_required(scenarios_dir: Path) -> None:
    scenario = macos_ssh_scenario(scenarios_dir, macos_receiver=True)
    scenario.environment.systems[1].services = []
    issues = ScenarioValidator(scenario).validate()
    assert any(issue.severity == "error" and "ssh" in issue.message.lower() for issue in issues)


def test_mac_client_to_linux_receiver_remains_admitted(scenarios_dir: Path) -> None:
    issues = ScenarioValidator(macos_ssh_scenario(scenarios_dir)).validate()
    assert not [issue for issue in issues if "receivers are not implemented" in issue.message]


@pytest.mark.parametrize("source_platform", ["linux", "macos", "windows"])
def test_mac_receiver_deadline_uses_actual_endpoint_clock_bounds(source_platform: str) -> None:
    deadline = datetime(2026, 10, 15, 12, tzinfo=UTC)
    planner = Mock()
    planner.endpoint_clock_positive_headroom.return_value = timedelta(seconds=40)
    planner.endpoint_clock_negative_headroom.side_effect = lambda _deadline, platform: timedelta(
        seconds=8 if platform == "macos" else 2
    )
    categories = ("macos",) if source_platform == "macos" else ("macos", source_platform)
    mac = ssh_action_deadline_transport_headroom_seconds(
        source_deadline=deadline,
        source_timing_planner=planner,
        source_os_categories=categories,
        target_os_category="macos",
    )
    planner.endpoint_clock_negative_headroom.assert_called_once_with(deadline, "macos")
    assert [
        call.args[1] for call in planner.endpoint_clock_positive_headroom.call_args_list
    ] == list(categories)
    linux = ssh_action_deadline_transport_headroom_seconds(
        source_deadline=deadline,
        source_timing_planner=planner,
        source_os_categories=categories,
    )
    assert mac - linux == pytest.approx(6.0)


def test_unsupported_receiver_deadline_platform_fails_before_clock_access() -> None:
    planner = Mock()
    with pytest.raises(ValueError, match="target OS"):
        ssh_action_deadline_transport_headroom_seconds(
            source_deadline=datetime(2026, 10, 15, 12, tzinfo=UTC),
            source_timing_planner=planner,
            target_os_category="windows",
        )
    assert planner.mock_calls == []


@pytest.mark.parametrize(
    "image", ["/usr/bin/id", "/Users/test_user/tools/invented-tool", "invented-tool"]
)
def test_mac_authored_process_path_validation_preserves_explicit_identity(
    scenarios_dir: Path, image: str
) -> None:
    document = macos_ssh_scenario(scenarios_dir, macos_receiver=True).model_dump(mode="json")
    document["storyline"][1]["events"].append(
        {"type": "process", "process_name": image, "command_line": image}
    )
    issues = ScenarioValidator(Scenario.model_validate(document)).validate()
    errors = [issue for issue in issues if issue.severity == "error"]
    if image.startswith("/"):
        assert errors == []
    else:
        assert any("canonical catalog path" in issue.message for issue in errors)
