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

"""Tests for firewall-specific validation in schema validator."""

from evidenceforge.models.scenario import (
    BaselineActivity,
    Environment,
    FirewallRule,
    NetworkConfig,
    NetworkSegment,
    NetworkSensor,
    OutputSpec,
    Scenario,
    System,
    TimeWindow,
    User,
)
from evidenceforge.validation.schema import ScenarioValidator


def _make_scenario(sensors=None) -> Scenario:
    """Create a minimal scenario with optional network sensors."""
    network = NetworkConfig(
        segments=[
            NetworkSegment(name="internal", cidr="10.0.10.0/24"),
            NetworkSegment(name="dmz", cidr="172.16.0.0/24"),
        ],
        sensors=sensors or [],
    )
    return Scenario(
        version="1.0",
        name="test",
        description="Test",
        environment=Environment(
            description="Test",
            users=[
                User(
                    username="jsmith",
                    full_name="J",
                    email="j@test.com",
                    primary_system="WS-01",
                )
            ],
            systems=[
                System(hostname="WS-01", ip="10.0.10.50", os="Windows 10", type="workstation"),
                System(hostname="WEB-01", ip="172.16.0.5", os="Linux Ubuntu", type="server"),
            ],
            network=network,
        ),
        time_window=TimeWindow(start="2024-01-15T10:00:00Z", duration="2h"),
        baseline_activity=BaselineActivity(description="Test", intensity="low", variation="low"),
        output=OutputSpec(
            logs=[{"format": "windows_event_security"}, {"format": "cisco_asa"}],
            destination="./output",
        ),
    )


class TestFirewallValidation:
    def test_valid_firewall_config_no_warnings(self):
        """Well-configured firewall sensor should produce no firewall-specific warnings."""
        scenario = _make_scenario(
            sensors=[
                NetworkSensor(
                    type="firewall",
                    name="fw01",
                    monitoring_segments=["internal", "dmz"],
                    log_formats=["cisco_asa"],
                    interfaces={"internal": "inside", "dmz": "dmz"},
                    policy=[
                        FirewallRule(src="external", dst="dmz", ports=[80, 443]),
                        FirewallRule(src="internal", dst="any"),
                    ],
                )
            ]
        )
        validator = ScenarioValidator(scenario)
        issues = validator.validate()
        fw_issues = [
            issue
            for issue in issues
            if "firewall" in issue.message.lower() or "policy" in issue.message.lower()
        ]
        assert len(fw_issues) == 0

    def test_firewall_without_cisco_asa_warns(self):
        """Firewall sensor without cisco_asa in log_formats should warn."""
        scenario = _make_scenario(
            sensors=[
                NetworkSensor(
                    type="firewall",
                    name="fw01",
                    monitoring_segments=["internal"],
                    log_formats=["zeek"],
                )
            ]
        )
        validator = ScenarioValidator(scenario)
        issues = validator.validate()
        fw_issues = [issue for issue in issues if "cisco_asa" in issue.message]
        assert len(fw_issues) == 1

    def test_non_firewall_with_policy_warns(self):
        """Non-firewall sensor with policy rules should warn."""
        scenario = _make_scenario(
            sensors=[
                NetworkSensor(
                    type="network",
                    name="zeek01",
                    monitoring_segments=["internal"],
                    log_formats=["zeek"],
                    policy=[FirewallRule(src="any", dst="any")],
                )
            ]
        )
        validator = ScenarioValidator(scenario)
        issues = validator.validate()
        policy_issues = [
            issue
            for issue in issues
            if "policy" in issue.message.lower() and "firewall" in issue.message.lower()
        ]
        assert len(policy_issues) == 1

    def test_interface_unknown_segment_warns(self):
        """Interface mapping with unknown segment name should warn."""
        scenario = _make_scenario(
            sensors=[
                NetworkSensor(
                    type="firewall",
                    name="fw01",
                    monitoring_segments=["internal", "dmz"],
                    log_formats=["cisco_asa"],
                    interfaces={"internal": "inside", "nonexistent": "outside"},
                )
            ]
        )
        validator = ScenarioValidator(scenario)
        issues = validator.validate()
        iface_issues = [issue for issue in issues if "nonexistent" in issue.message]
        assert len(iface_issues) == 1

    def test_policy_unknown_segment_warns(self):
        """Policy rule with unknown segment name should warn."""
        scenario = _make_scenario(
            sensors=[
                NetworkSensor(
                    type="firewall",
                    name="fw01",
                    monitoring_segments=["internal", "dmz"],
                    log_formats=["cisco_asa"],
                    policy=[
                        FirewallRule(src="external", dst="nonexistent_segment"),
                    ],
                )
            ]
        )
        validator = ScenarioValidator(scenario)
        issues = validator.validate()
        policy_issues = [issue for issue in issues if "nonexistent_segment" in issue.message]
        assert len(policy_issues) == 1

    def test_policy_accepts_special_keywords(self):
        """Policy rules with 'external', 'any', IPs, and CIDRs should not warn."""
        scenario = _make_scenario(
            sensors=[
                NetworkSensor(
                    type="firewall",
                    name="fw01",
                    monitoring_segments=["internal", "dmz"],
                    log_formats=["cisco_asa"],
                    policy=[
                        FirewallRule(src="external", dst="dmz"),
                        FirewallRule(src="any", dst="any"),
                        FirewallRule(src="10.0.20.5", dst="external"),
                        FirewallRule(src="192.168.1.0/24", dst="internal"),
                    ],
                )
            ]
        )
        validator = ScenarioValidator(scenario)
        issues = validator.validate()
        policy_issues = [
            issue
            for issue in issues
            if "policy" in issue.field_path and "not a known segment" in issue.message
        ]
        assert len(policy_issues) == 0

    def test_interface_default_key_accepted(self):
        """The _default key in interfaces should not warn."""
        scenario = _make_scenario(
            sensors=[
                NetworkSensor(
                    type="firewall",
                    name="fw01",
                    monitoring_segments=["internal"],
                    log_formats=["cisco_asa"],
                    interfaces={"internal": "inside", "_default": "outside"},
                )
            ]
        )
        validator = ScenarioValidator(scenario)
        issues = validator.validate()
        iface_issues = [issue for issue in issues if "_default" in issue.message]
        assert len(iface_issues) == 0
