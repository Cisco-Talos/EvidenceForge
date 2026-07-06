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


def _scenario_with_storyline_dhcp_mac() -> Scenario:
    """Build a scenario whose storyline pins the DHCP client MAC."""
    scenario = _scenario_with_storyline_dhcp()
    scenario.storyline[0].events[0].mac_address = "DC:A6:32:44:91:7B"
    return scenario


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
    assert kwargs["renewal_interval"] > 0
    assert engine._dhcp_lease_state["TEST-01"]["last_renewal"] == kwargs["time"].timestamp()
    assert (
        engine._dhcp_lease_state["TEST-01"]["next_renewal"]
        == kwargs["time"].timestamp() + kwargs["renewal_interval"]
    )


def test_emit_dhcp_leases_uses_storyline_mac_as_host_identity(tmp_path):
    """Setup leases should not disagree with a later explicit storyline MAC."""
    scenario = _scenario_with_storyline_dhcp_mac()
    engine = GenerationEngine(scenario, tmp_path)
    engine.start_time = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)
    engine.end_time = datetime(2024, 1, 15, 10, 1, 0, tzinfo=UTC)
    engine.warmup_start_time = engine.start_time - timedelta(hours=8)
    engine.emitters = {"zeek_dhcp": Mock()}
    engine.state_manager = Mock()
    engine.activity_generator = Mock()

    engine._emit_dhcp_leases()

    kwargs = engine.activity_generator.generate_dhcp_lease.call_args.kwargs
    assert kwargs["mac"] == "dc:a6:32:44:91:7b"
    assert kwargs["renewal_interval"] > 0
    assert engine._dhcp_lease_state["TEST-01"]["mac"] == "dc:a6:32:44:91:7b"
    assert (
        engine._dhcp_lease_state["TEST-01"]["next_renewal"]
        == kwargs["time"].timestamp() + kwargs["renewal_interval"]
    )


def test_emit_dhcp_leases_handles_null_storyline(tmp_path):
    """Schema-valid null storyline should not crash DHCP warm-up setup."""
    base_scenario = _scenario_with_storyline_dhcp()
    scenario = Scenario.model_validate({**base_scenario.model_dump(), "storyline": None})
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
    assert kwargs["renewal_interval"] > 0
    assert engine._dhcp_lease_state["TEST-01"]["mac"] == kwargs["mac"]
    assert (
        engine._dhcp_lease_state["TEST-01"]["next_renewal"]
        == kwargs["time"].timestamp() + kwargs["renewal_interval"]
    )


def test_storyline_dhcp_lease_time_in_hour_finds_authored_event(tmp_path):
    """Baseline DHCP scheduling should be able to defer to an authored DHCP event."""
    scenario = _scenario_with_storyline_dhcp()
    engine = GenerationEngine(scenario, tmp_path)
    engine.start_time = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)

    event_time = engine._storyline_dhcp_lease_time_in_hour("TEST-01", engine.start_time)

    assert event_time == datetime(2024, 1, 15, 10, 0, 30, tzinfo=UTC)
    assert (
        engine._storyline_dhcp_lease_time_in_hour(
            "OTHER-01",
            engine.start_time,
        )
        is None
    )


def test_emit_dhcp_leases_skips_static_infrastructure_servers(tmp_path):
    """Static servers should not get ambient DHCP leases just because Zeek DHCP is enabled."""
    scenario = _scenario_with_storyline_dhcp()
    scenario.environment.systems.append(
        System(
            hostname="DC-01",
            ip="10.0.0.10",
            os="Windows Server 2022",
            type="domain_controller",
            roles=["domain_controller", "dns_server"],
        )
    )
    engine = GenerationEngine(scenario, tmp_path)
    engine.start_time = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)
    engine.end_time = datetime(2024, 1, 15, 10, 1, 0, tzinfo=UTC)
    engine.warmup_start_time = engine.start_time - timedelta(hours=8)
    engine.emitters = {"zeek_dhcp": Mock()}
    engine.state_manager = Mock()
    engine.activity_generator = Mock()

    engine._emit_dhcp_leases()

    leased_hosts = [
        call.kwargs["system"].hostname
        for call in engine.activity_generator.generate_dhcp_lease.call_args_list
    ]
    assert leased_hosts == ["TEST-01"]
    assert "DC-01" not in engine._dhcp_lease_state
