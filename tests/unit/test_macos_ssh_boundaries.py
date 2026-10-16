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


def test_unimplemented_mac_receiver_fails_before_executor_or_linux_shell_access() -> None:
    executor = Mock()
    target = System(hostname="MAC-RECEIVER", ip="192.0.2.20", os="macOS 26", type="workstation")
    user = User(username="casey", full_name="Casey", email="casey@example.test")
    timestamp = datetime(2026, 10, 15, 12, tzinfo=UTC)
    request = SshSessionRequest(
        user=user, target_system=target, time=timestamp, source_ip="198.51.100.10"
    )
    with pytest.raises(StateError, match="macOS SSH receivers are not implemented"):
        SshSessionActionBundle(request, executor).execute_with_identity()
    with pytest.raises(StateError, match="Linux SSH shell bootstrap"):
        ActivityGenerator.ensure_linux_ssh_session_shell(
            executor, user, target, "0x1234", timestamp, timestamp
        )
    assert executor.mock_calls == []


@pytest.mark.parametrize("event_type", ["ssh_session", "logon"])
@pytest.mark.parametrize("services", [[], ["ssh"]])
def test_mac_remote_receiver_validation_exposes_current_implementation_boundary(
    scenarios_dir: Path, event_type: str, services: list[str]
) -> None:
    document = macos_ssh_scenario(scenarios_dir).model_dump(mode="json")
    document["environment"]["systems"][1].update(
        os="macOS 26", architecture="arm64", type="workstation", services=services
    )
    spec: dict[str, object] = {"type": event_type, "source_ip": "10.0.0.10"}
    if event_type == "logon":
        spec["logon_type"] = 10
    document["storyline"][1]["events"] = [spec]
    issues = ScenarioValidator(Scenario.model_validate(document)).validate()
    errors = [issue for issue in issues if "receivers are not implemented" in issue.message]
    assert len(errors) == 1
    assert errors[0].severity == "error"
    assert errors[0].field_path == "storyline.1.events.0"


def test_mac_client_to_linux_receiver_remains_admitted(scenarios_dir: Path) -> None:
    issues = ScenarioValidator(macos_ssh_scenario(scenarios_dir)).validate()
    assert not [issue for issue in issues if "receivers are not implemented" in issue.message]
