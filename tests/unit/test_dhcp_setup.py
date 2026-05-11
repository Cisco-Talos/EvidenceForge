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

"""Tests for DHCP lease setup behavior."""

from datetime import UTC, datetime, timedelta
from unittest.mock import Mock

from evidenceforge.generation.engine import GenerationEngine
from evidenceforge.models import (
    BaselineActivity,
    Environment,
    OutputSpec,
    Scenario,
    System,
    TimeWindow,
    User,
)
from evidenceforge.models.scenario import StorylineEvent


def _scenario_with_storyline_dhcp() -> Scenario:
    """Build a short scenario whose DHCP setup offset would exceed the output window."""
    return Scenario(
        version="1.0",
        name="short-dhcp-storyline",
        description="Short DHCP storyline scenario",
        environment=Environment(
            description="Test environment",
            users=[
                User(
                    username="attacker",
                    full_name="Attacker",
                    email="attacker@example.com",
                    enabled=True,
                    primary_system="TEST-01",
                )
            ],
            systems=[
                System(hostname="TEST-01", ip="10.0.0.1", os="Windows 10", type="workstation")
            ],
        ),
        time_window=TimeWindow(start="2024-01-15T10:00:00Z", duration="1m"),
        baseline_activity=BaselineActivity(
            description="Test baseline", intensity="low", variation="low"
        ),
        output=OutputSpec(logs=[{"format": "zeek_dhcp"}], destination="./output"),
        storyline=[
            StorylineEvent(
                id="dhcp-storyline",
                time="2024-01-15T10:00:30Z",
                actor="attacker",
                system="TEST-01",
                activity="Rogue host obtains a DHCP lease",
                events=[{"type": "dhcp_lease"}],
            )
        ],
    )


def test_emit_dhcp_leases_keeps_storyline_hosts_in_warmup_state(tmp_path):
    """Storyline DHCP hosts should get setup state without visible out-of-window leases."""
    scenario = _scenario_with_storyline_dhcp()
    engine = GenerationEngine(scenario, tmp_path)
    engine.start_time = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)
    engine.end_time = datetime(2024, 1, 15, 10, 1, 0, tzinfo=UTC)
    engine.warmup_start_time = engine.start_time - timedelta(hours=8)
    engine.emitters = {"zeek_dhcp": Mock()}
    engine.state_manager = Mock()
    engine.activity_generator = Mock()

    engine._emit_dhcp_leases()

    engine.activity_generator.generate_dhcp_lease.assert_called_once()
    kwargs = engine.activity_generator.generate_dhcp_lease.call_args.kwargs
    assert kwargs["system"].hostname == "TEST-01"
    assert kwargs["time"] < engine.start_time
    assert kwargs["time"] < engine.end_time
    assert "msg_types" not in kwargs
    assert engine._dhcp_lease_state["TEST-01"]["last_renewal"] == kwargs["time"].timestamp()
