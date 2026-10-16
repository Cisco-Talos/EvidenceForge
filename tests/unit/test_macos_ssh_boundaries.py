# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Mac source facts survive Linux-receiver SSH lifecycle planning."""

from datetime import UTC, datetime, timedelta
from unittest.mock import Mock

import pytest

from evidenceforge.events.contexts import HostContext
from evidenceforge.generation.actions.ssh_session import (
    _SshCloseHostFacts,
    ssh_action_deadline_transport_headroom_seconds,
)


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
