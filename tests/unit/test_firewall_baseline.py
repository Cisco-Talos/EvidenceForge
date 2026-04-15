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

import pytest
from pydantic import ValidationError

from evidenceforge.models.scenario import FirewallRule, NetworkSensor


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
