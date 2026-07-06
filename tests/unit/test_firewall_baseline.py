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

"""Tests for firewall deny baseline generation and FirewallRule model."""

import random

import pytest
from pydantic import ValidationError

from evidenceforge.generation.engine.baseline import BaselineMixin
from evidenceforge.models.scenario import FirewallRule, NetworkSensor, System


class TestFirewallRule:
    def test_default_action_is_permit(self):
        rule = FirewallRule(src="external", dst="dmz")
        assert rule.action == "permit"

    def test_explicit_deny(self):
        rule = FirewallRule(src="any", dst="any", action="deny")
        assert rule.action == "deny"

    def test_ports_default_empty(self):
        rule = FirewallRule(src="workstations", dst="external")
        assert rule.ports == []

    def test_ports_with_values(self):
        rule = FirewallRule(src="external", dst="dmz", ports=[80, 443])
        assert rule.ports == [80, 443]

    def test_any_keyword(self):
        rule = FirewallRule(src="any", dst="any", ports=["any"])
        assert rule.src == "any"
        assert rule.dst == "any"

    def test_cidr_notation(self):
        rule = FirewallRule(src="192.168.1.0/24", dst="10.0.0.0/8")
        assert rule.src == "192.168.1.0/24"

    def test_specific_ip(self):
        rule = FirewallRule(src="10.0.20.5", dst="external", ports=[25])
        assert rule.src == "10.0.20.5"


class TestNetworkSensorFirewallFields:
    def test_default_deny(self):
        sensor = NetworkSensor(
            type="firewall",
            name="fw01",
            monitoring_segments=["internal"],
        )
        assert sensor.default_action == "deny"
        assert sensor.deny_ratio == 5.0
        assert sensor.interfaces == {}
        assert sensor.policy == []

    def test_firewall_with_policy(self):
        sensor = NetworkSensor(
            type="firewall",
            name="fw01",
            monitoring_segments=["internal", "dmz"],
            log_formats=["cisco_asa"],
            interfaces={"internal": "inside", "dmz": "dmz"},
            policy=[
                FirewallRule(src="external", dst="dmz", ports=[80, 443]),
                FirewallRule(src="internal", dst="external"),
            ],
            default_action="deny",
            deny_ratio=3.0,
        )
        assert len(sensor.policy) == 2
        assert sensor.policy[0].src == "external"
        assert sensor.policy[0].ports == [80, 443]
        assert sensor.deny_ratio == 3.0

    def test_non_firewall_sensor_ignores_firewall_fields(self):
        sensor = NetworkSensor(
            type="network",
            name="zeek01",
            monitoring_segments=["internal"],
        )
        # Fields exist but are at defaults
        assert sensor.policy == []
        assert sensor.default_action == "deny"

    def test_deny_ratio_rejects_excessive_values(self):
        with pytest.raises(ValidationError):
            NetworkSensor(
                type="firewall",
                name="fw01",
                monitoring_segments=["internal"],
                deny_ratio=100.0,
            )


class TestFirewallDenyProbeTexture:
    def test_internal_probe_sources_are_small_and_stable(self):
        systems = [
            System(hostname="DC-01", ip="10.0.0.10", os="Windows Server 2022", type="server"),
            System(hostname="MAIL-01", ip="10.0.0.20", os="Windows Server 2022", type="server"),
            System(hostname="PROXY-01", ip="10.0.0.30", os="Ubuntu 22.04", type="server"),
            System(hostname="WS-01", ip="10.0.1.11", os="Windows 11", type="workstation"),
            System(hostname="WS-02", ip="10.0.1.12", os="Windows 11", type="workstation"),
            System(hostname="WS-03", ip="10.0.1.13", os="Windows 11", type="workstation"),
            System(hostname="WS-04", ip="10.0.1.14", os="Windows 11", type="workstation"),
            System(hostname="WS-05", ip="10.0.1.15", os="Windows 11", type="workstation"),
            System(hostname="WS-06", ip="10.0.1.16", os="Windows 11", type="workstation"),
        ]

        selected = BaselineMixin._firewall_internal_probe_sources("fw01", systems)
        selected_again = BaselineMixin._firewall_internal_probe_sources("fw01", systems)

        assert selected == selected_again
        assert 1 <= len(selected) <= 2
        assert all(system.type == "workstation" for system in selected)

    def test_internal_probe_sources_prefer_explicit_scanner_roles(self):
        systems = [
            System(hostname="DC-01", ip="10.0.0.10", os="Windows Server 2022", type="server"),
            System(
                hostname="SCAN-01",
                ip="10.0.0.50",
                os="Ubuntu 22.04",
                type="server",
                roles=["vulnerability_scanner"],
            ),
            System(hostname="WS-01", ip="10.0.1.11", os="Windows 11", type="workstation"),
            System(hostname="WS-02", ip="10.0.1.12", os="Windows 11", type="workstation"),
        ]

        selected = BaselineMixin._firewall_internal_probe_sources("fw01", systems)

        assert [system.hostname for system in selected] == ["SCAN-01"]

    def test_internal_blocked_port_profile_is_source_sticky(self):
        first_rng = random.Random(7)
        second_rng = random.Random(7)

        first = [
            BaselineMixin._firewall_blocked_port_for_internal_source("10.0.1.11", first_rng)
            for _ in range(12)
        ]
        second = [
            BaselineMixin._firewall_blocked_port_for_internal_source("10.0.1.11", second_rng)
            for _ in range(12)
        ]

        assert first == second
        assert len(set(first)) <= 4
        assert set(first) <= {
            22,
            23,
            80,
            135,
            445,
            1433,
            2323,
            3306,
            3389,
            5432,
            5900,
            5985,
            6379,
            8080,
        }
