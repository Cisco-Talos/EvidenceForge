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

"""Tests for firewall storyline event types and source-only deny visibility."""

from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from evidenceforge.generation.ground_truth import GroundTruthGenerator
from evidenceforge.models.scenario import (
    BlockedC2EventSpec,
    NetworkSensor,
    PortScanEventSpec,
)


class TestPortScanEventSpec:
    def test_defaults(self):
        spec = PortScanEventSpec(target_ips=["10.0.10.1"])
        assert spec.type == "port_scan"
        assert spec.ports == [22, 80, 443, 445, 3389]
        assert spec.protocol == "tcp"
        assert spec.scan_rate == 100.0
        assert spec.target_count == 50

    def test_target_segment(self):
        spec = PortScanEventSpec(target_segment="dmz", target_count=20)
        assert spec.target_segment == "dmz"
        assert spec.target_count == 20
        assert spec.target_ips == []

    def test_custom_ports(self):
        spec = PortScanEventSpec(target_ips=["10.0.10.1"], ports=[80, 8080, 8443])
        assert spec.ports == [80, 8080, 8443]

    def test_icmp_protocol(self):
        spec = PortScanEventSpec(target_ips=["10.0.10.1"], protocol="icmp")
        assert spec.protocol == "icmp"

    def test_scan_rate_must_be_positive(self):
        with pytest.raises((ValueError, ValidationError)):
            PortScanEventSpec(target_ips=["10.0.10.1"], scan_rate=0.0)

    def test_target_count_bounds(self):
        with pytest.raises((ValueError, ValidationError)):
            PortScanEventSpec(target_segment="dmz", target_count=0)
        with pytest.raises((ValueError, ValidationError)):
            PortScanEventSpec(target_segment="dmz", target_count=6000)


class TestBlockedC2EventSpec:
    def test_defaults(self):
        spec = BlockedC2EventSpec(dst_ip="198.51.100.30")
        assert spec.type == "blocked_c2"
        assert spec.dst_port == 443
        assert spec.protocol == "tcp"
        assert spec.interval == "30m"
        assert spec.duration == "6h"
        assert spec.jitter == 0.2

    def test_custom_values(self):
        spec = BlockedC2EventSpec(
            dst_ip="198.51.100.30",
            dst_port=8443,
            interval="15m",
            duration="12h",
            jitter=0.1,
        )
        assert spec.dst_port == 8443
        assert spec.interval == "15m"
        assert spec.duration == "12h"
        assert spec.jitter == 0.1

    def test_jitter_bounds(self):
        with pytest.raises((ValueError, ValidationError)):
            BlockedC2EventSpec(dst_ip="198.51.100.30", jitter=-0.1)
        with pytest.raises((ValueError, ValidationError)):
            BlockedC2EventSpec(dst_ip="198.51.100.30", jitter=1.5)


class TestDropMode:
    def test_default_is_drop(self):
        sensor = NetworkSensor(type="firewall", name="fw01", monitoring_segments=["internal"])
        assert sensor.drop_mode == "drop"

    def test_reject_mode(self):
        sensor = NetworkSensor(
            type="firewall",
            name="fw01",
            monitoring_segments=["internal"],
            drop_mode="reject",
        )
        assert sensor.drop_mode == "reject"

    def test_invalid_mode(self):
        with pytest.raises((ValueError, ValidationError)):
            NetworkSensor(
                type="firewall",
                name="fw01",
                monitoring_segments=["internal"],
                drop_mode="block",
            )


class TestGroundTruthPortScan:
    @pytest.fixture
    def minimal_scenario(self):
        from evidenceforge.models import (
            BaselineActivity,
            Environment,
            OutputSpec,
            Scenario,
            System,
            TimeWindow,
            User,
        )

        return Scenario(
            version="1.0",
            name="test",
            description="Test",
            environment=Environment(
                description="Test",
                users=[User(username="attacker", full_name="A", email="a@x.com", enabled=True)],
                systems=[
                    System(hostname="WS-01", ip="10.0.0.1", os="Windows 10", type="workstation")
                ],
            ),
            time_window=TimeWindow(start="2024-01-15T10:00:00Z", duration="2h"),
            baseline_activity=BaselineActivity(
                description="Test", intensity="low", variation="low"
            ),
            output=OutputSpec(
                logs=[{"format": "windows_event_security"}],
                destination="./output",
                compression=False,
            ),
            personas=[],
            storyline=[],
        )

    def test_format_event_details_port_scan(self, minimal_scenario):
        events = [
            {
                "time": datetime(2024, 1, 15, 10, 30, tzinfo=UTC),
                "actor": "attacker",
                "system": "WS-01",
                "type": "port_scan",
                "target_count": 20,
                "ports": [22, 80, 443],
                "total_connections": 60,
                "protocol": "tcp",
            }
        ]
        gen = GroundTruthGenerator(minimal_scenario, events)
        details = gen._format_event_details(events[0])
        assert "Port scan" in details
        assert "20 targets" in details
        assert "60 denied" in details

    def test_format_event_details_blocked_c2(self, minimal_scenario):
        events = [
            {
                "time": datetime(2024, 1, 15, 10, 30, tzinfo=UTC),
                "actor": "attacker",
                "system": "WS-01",
                "type": "blocked_c2",
                "dst_ip": "198.51.100.30",
                "dst_port": 443,
                "interval": "30m",
                "duration": "6h",
                "attempt_count": 12,
            }
        ]
        gen = GroundTruthGenerator(minimal_scenario, events)
        details = gen._format_event_details(events[0])
        assert "Blocked C2" in details
        assert "198.51.100.30:443" in details
        assert "12 attempts" in details

    def test_extract_iocs_port_scan(self, minimal_scenario):
        events = [
            {
                "actor": "attacker",
                "type": "port_scan",
                "ports": [22, 443],
            }
        ]
        gen = GroundTruthGenerator(minimal_scenario, events)
        iocs = gen._extract_iocs()
        assert "network" in iocs
        assert "Port 22 (scan target)" in iocs["network"]
        assert "Port 443 (scan target)" in iocs["network"]

    def test_extract_iocs_blocked_c2(self, minimal_scenario):
        events = [
            {
                "actor": "attacker",
                "type": "blocked_c2",
                "dst_ip": "198.51.100.30",
                "dst_port": 443,
            }
        ]
        gen = GroundTruthGenerator(minimal_scenario, events)
        iocs = gen._extract_iocs()
        assert "network" in iocs
        assert "198.51.100.30:443 (Blocked C2 Server)" in iocs["network"]


class TestSourceOnlyVisibility:
    def test_get_source_side_sensors_internal_ip(self):
        from evidenceforge.generation.network_visibility import NetworkVisibilityEngine
        from evidenceforge.models.scenario import (
            NetworkConfig,
            NetworkSegment,
            NetworkSensor,
            System,
        )

        config = NetworkConfig(
            segments=[
                NetworkSegment(name="internal", cidr="10.0.10.0/24"),
                NetworkSegment(name="dmz", cidr="172.16.0.0/24"),
            ],
            sensors=[
                NetworkSensor(
                    type="network",
                    name="inside-zeek",
                    monitoring_segments=["internal"],
                    log_formats=["zeek"],
                ),
                NetworkSensor(
                    type="network",
                    name="dmz-zeek",
                    monitoring_segments=["dmz"],
                    log_formats=["zeek"],
                ),
            ],
        )
        systems = [
            System(hostname="WS-01", ip="10.0.10.50", os="Windows 10", type="workstation"),
            System(hostname="WEB-01", ip="172.16.0.5", os="Linux Ubuntu", type="server"),
        ]
        engine = NetworkVisibilityEngine(network_config=config, systems=systems)

        # Internal IP: only inside-zeek should see it
        sensors = engine.get_source_side_sensors("10.0.10.50")
        sensor_names = [s.name for s in sensors]
        assert "inside-zeek" in sensor_names
        assert "dmz-zeek" not in sensor_names

    def test_get_source_side_sensors_external_ip(self):
        from evidenceforge.generation.network_visibility import NetworkVisibilityEngine
        from evidenceforge.models.scenario import (
            NetworkConfig,
            NetworkSegment,
            NetworkSensor,
            System,
        )

        config = NetworkConfig(
            segments=[
                NetworkSegment(name="internal", cidr="10.0.10.0/24"),
                NetworkSegment(name="dmz", cidr="172.16.0.0/24"),
            ],
            sensors=[
                NetworkSensor(
                    type="network",
                    name="inside-zeek",
                    monitoring_segments=["internal"],
                    direction="bidirectional",
                    log_formats=["zeek"],
                ),
                NetworkSensor(
                    type="network",
                    name="dmz-zeek",
                    monitoring_segments=["dmz"],
                    direction="inbound",
                    log_formats=["zeek"],
                ),
                NetworkSensor(
                    type="firewall",
                    name="fw01",
                    monitoring_segments=["internal", "dmz"],
                    log_formats=["cisco_asa"],
                ),
            ],
        )
        systems = [
            System(hostname="WS-01", ip="10.0.10.50", os="Windows 10", type="workstation"),
            System(hostname="WEB-01", ip="172.16.0.5", os="Linux Ubuntu", type="server"),
        ]
        engine = NetworkVisibilityEngine(network_config=config, systems=systems)

        # External IP targeting DMZ: boundary segments from fw01 (internal + dmz).
        # dmz-zeek (inbound on dmz) should see external traffic arriving at boundary.
        # inside-zeek (bidirectional on internal) should see it too (boundary includes internal).
        sensors = engine.get_source_side_sensors("203.0.113.45", "172.16.0.5")
        sensor_names = [s.name for s in sensors]
        assert "dmz-zeek" in sensor_names  # inbound on boundary segment
        assert "fw01" in sensor_names  # firewall on boundary
        assert "inside-zeek" in sensor_names  # bidirectional on boundary segment
