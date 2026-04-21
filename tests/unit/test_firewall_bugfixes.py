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

"""Tests for firewall bugfixes from code review."""

import ipaddress
from dataclasses import dataclass, field
from datetime import UTC, datetime

from evidenceforge.evaluation.parsers import ParsedRecord


class TestCiscoAsaFormatFields:
    """Fix 1: cisco_asa.yaml should include all parser-extracted fields."""

    def test_format_definition_includes_parsed_fields(self):
        from evidenceforge.formats import load_format

        fmt = load_format("cisco_asa")
        field_names = {f.name for f in fmt.fields}
        expected = {
            "timestamp",
            "hostname",
            "severity",
            "msg_id",
            "message",
            "pri",
            "connection_id",
            "src_ip",
            "dst_ip",
            "src_port",
            "dst_port",
            "src_interface",
            "dst_interface",
            "duration",
            "bytes",
            "icmp_type",
            "icmp_code",
            "protocol",
            "access_group",
        }
        assert expected.issubset(field_names)


class TestEvalScorerFirewallEvents:
    """Fix 2: _record_matches() should recognize port_scan and beacon."""

    def _make_resolved_event(self, event_type, system_ip, details=None):
        """Create a minimal ResolvedEvent-like object for testing."""

        @dataclass
        class FakeResolvedEvent:
            index: int = 0
            time: datetime = datetime(2024, 6, 15, 14, 0, 0, tzinfo=UTC)
            actor: str = "attacker"
            system: str = "WS-01"
            system_ip: str | None = None
            activity: str = "test"
            details: dict = field(default_factory=dict)
            event_types: list = field(default_factory=list)
            sub_details: list = field(default_factory=list)
            traces: list = field(default_factory=list)

        return FakeResolvedEvent(
            system_ip=system_ip,
            event_types=[event_type],
            details=details or {},
        )

    def test_port_scan_matches_cisco_asa_deny(self):
        from evidenceforge.evaluation.dimensions.signal_integrity import (
            SignalIntegrityScorer,
        )

        scorer = SignalIntegrityScorer()
        event = self._make_resolved_event("port_scan", "10.0.10.50")
        record = ParsedRecord(
            source_format="cisco_asa",
            raw="test",
            fields={"msg_id": 106023, "src_ip": "10.0.10.50"},
        )
        assert scorer._record_matches(record, record.source_format, event, "port_scan") is True

    def test_port_scan_matches_733100_threat_detection(self):
        from evidenceforge.evaluation.dimensions.signal_integrity import (
            SignalIntegrityScorer,
        )

        scorer = SignalIntegrityScorer()
        event = self._make_resolved_event("port_scan", "10.0.10.50")
        record = ParsedRecord(
            source_format="cisco_asa",
            raw="test",
            fields={
                "msg_id": 733100,
                "threat_class": "Scanning",
                "burst_rate": 87,
                "cumulative_count": 2340,
            },
        )
        assert scorer._record_matches(record, record.source_format, event, "port_scan") is True

    def test_port_scan_matches_zeek_rej(self):
        from evidenceforge.evaluation.dimensions.signal_integrity import (
            SignalIntegrityScorer,
        )

        scorer = SignalIntegrityScorer()
        event = self._make_resolved_event("port_scan", "10.0.10.50")
        record = ParsedRecord(
            source_format="zeek_conn",
            raw="test",
            fields={"id.orig_h": "10.0.10.50", "conn_state": "S0"},
        )
        assert scorer._record_matches(record, record.source_format, event, "port_scan") is True

    def test_port_scan_no_match_wrong_ip(self):
        from evidenceforge.evaluation.dimensions.signal_integrity import (
            SignalIntegrityScorer,
        )

        scorer = SignalIntegrityScorer()
        event = self._make_resolved_event("port_scan", "10.0.10.50")
        record = ParsedRecord(
            source_format="cisco_asa",
            raw="test",
            fields={"msg_id": 106023, "src_ip": "10.0.20.1"},
        )
        assert scorer._record_matches(record, record.source_format, event, "port_scan") is False

    def test_beacon_deny_matches_cisco_asa(self):
        from evidenceforge.evaluation.dimensions.signal_integrity import (
            SignalIntegrityScorer,
        )

        scorer = SignalIntegrityScorer()
        event = self._make_resolved_event(
            "beacon", "10.0.10.50", {"dst_ip": "198.51.100.30", "dst_port": 443, "action": "deny"}
        )
        record = ParsedRecord(
            source_format="cisco_asa",
            raw="test",
            fields={"msg_id": 106023, "dst_ip": "198.51.100.30", "dst_port": 443},
        )
        assert scorer._record_matches(record, record.source_format, event, "beacon") is True

    def test_beacon_deny_no_match_wrong_port(self):
        from evidenceforge.evaluation.dimensions.signal_integrity import (
            SignalIntegrityScorer,
        )

        scorer = SignalIntegrityScorer()
        event = self._make_resolved_event(
            "beacon", "10.0.10.50", {"dst_ip": "198.51.100.30", "dst_port": 443, "action": "deny"}
        )
        record = ParsedRecord(
            source_format="cisco_asa",
            raw="test",
            fields={"msg_id": 106023, "dst_ip": "198.51.100.30", "dst_port": 8443},
        )
        assert scorer._record_matches(record, record.source_format, event, "beacon") is False


class TestSourceSideVisibilityDirection:
    """Fix 3: get_source_side_sensors() should respect direction/placement."""

    def test_inbound_sensor_not_returned_for_internal_source(self):
        from evidenceforge.generation.network_visibility import NetworkVisibilityEngine
        from evidenceforge.models.scenario import (
            NetworkConfig,
            NetworkSegment,
            NetworkSensor,
            System,
        )

        config = NetworkConfig(
            segments=[NetworkSegment(name="internal", cidr="10.0.10.0/24", exposure="internal")],
            sensors=[
                NetworkSensor(
                    type="network",
                    name="inbound-only",
                    monitoring_segments=["internal"],
                    direction="inbound",
                    log_formats=["zeek"],
                ),
            ],
        )
        systems = [System(hostname="WS-01", ip="10.0.10.50", os="Windows 10", type="workstation")]
        engine = NetworkVisibilityEngine(network_config=config, systems=systems)

        sensors = engine.get_source_side_sensors("10.0.10.50")
        assert len(sensors) == 0  # inbound-only should NOT see outbound denied traffic

    def test_outbound_sensor_returned_for_internal_source(self):
        from evidenceforge.generation.network_visibility import NetworkVisibilityEngine
        from evidenceforge.models.scenario import (
            NetworkConfig,
            NetworkSegment,
            NetworkSensor,
            System,
        )

        config = NetworkConfig(
            segments=[NetworkSegment(name="internal", cidr="10.0.10.0/24", exposure="internal")],
            sensors=[
                NetworkSensor(
                    type="network",
                    name="outbound-sensor",
                    monitoring_segments=["internal"],
                    direction="outbound",
                    log_formats=["zeek"],
                ),
            ],
        )
        systems = [System(hostname="WS-01", ip="10.0.10.50", os="Windows 10", type="workstation")]
        engine = NetworkVisibilityEngine(network_config=config, systems=systems)

        sensors = engine.get_source_side_sensors("10.0.10.50")
        assert len(sensors) == 1
        assert sensors[0].name == "outbound-sensor"

    def test_external_ip_no_firewall_returns_empty(self):
        from evidenceforge.generation.network_visibility import NetworkVisibilityEngine
        from evidenceforge.models.scenario import (
            NetworkConfig,
            NetworkSegment,
            NetworkSensor,
            System,
        )

        config = NetworkConfig(
            segments=[NetworkSegment(name="internal", cidr="10.0.10.0/24", exposure="internal")],
            sensors=[
                NetworkSensor(
                    type="network",
                    name="inside-zeek",
                    monitoring_segments=["internal"],
                    direction="bidirectional",
                    log_formats=["zeek"],
                ),
            ],
        )
        systems = [System(hostname="WS-01", ip="10.0.10.50", os="Windows 10", type="workstation")]
        engine = NetworkVisibilityEngine(network_config=config, systems=systems)

        # No firewall sensor → no boundary segments → empty result for external IP
        sensors = engine.get_source_side_sensors("203.0.113.45")
        assert len(sensors) == 0


class TestMultiFirewallVisibility:
    """External deny scoped to destination-relevant firewall segments."""

    def test_dmz_deny_not_sent_to_database_only_sensor(self):
        from evidenceforge.generation.network_visibility import NetworkVisibilityEngine
        from evidenceforge.models.scenario import (
            NetworkConfig,
            NetworkSegment,
            NetworkSensor,
            System,
        )

        config = NetworkConfig(
            segments=[
                NetworkSegment(name="dmz", cidr="172.16.0.0/24", exposure="external"),
                NetworkSegment(name="database", cidr="10.0.20.0/24", exposure="internal"),
            ],
            sensors=[
                NetworkSensor(
                    type="firewall",
                    name="fw-external",
                    monitoring_segments=["dmz"],
                    log_formats=["cisco_asa"],
                ),
                NetworkSensor(
                    type="firewall",
                    name="fw-internal",
                    monitoring_segments=["database"],
                    log_formats=["cisco_asa"],
                ),
                NetworkSensor(
                    type="network",
                    name="dmz-zeek",
                    monitoring_segments=["dmz"],
                    direction="inbound",
                    log_formats=["zeek"],
                ),
                NetworkSensor(
                    type="network",
                    name="db-zeek",
                    monitoring_segments=["database"],
                    direction="inbound",
                    log_formats=["zeek"],
                ),
            ],
        )
        systems = [
            System(hostname="WEB-01", ip="172.16.0.5", os="Linux Ubuntu", type="server"),
            System(hostname="DB-01", ip="10.0.20.5", os="Linux Ubuntu", type="server"),
        ]
        engine = NetworkVisibilityEngine(network_config=config, systems=systems)

        # External deny targeting DMZ: only firewall sensors see denied
        # traffic — non-firewall sensors behind the firewall (dmz-zeek)
        # never receive dropped/rejected packets.
        sensors = engine.get_source_side_sensors("203.0.113.45", "172.16.0.5")
        sensor_names = {s.name for s in sensors}
        assert "fw-external" in sensor_names
        assert "dmz-zeek" not in sensor_names  # denied traffic doesn't reach Zeek
        assert "fw-internal" not in sensor_names  # doesn't monitor DMZ
        assert "db-zeek" not in sensor_names  # doesn't monitor DMZ


class TestSingleFirewallSegmentScoping:
    """External deny scoped to destination segment even with single multi-segment firewall."""

    def test_dmz_deny_not_sent_to_internal_sensor(self):
        from evidenceforge.generation.network_visibility import NetworkVisibilityEngine
        from evidenceforge.models.scenario import (
            NetworkConfig,
            NetworkSegment,
            NetworkSensor,
            System,
        )

        config = NetworkConfig(
            segments=[
                NetworkSegment(name="internal", cidr="10.0.10.0/24", exposure="internal"),
                NetworkSegment(name="dmz", cidr="172.16.0.0/24", exposure="external"),
            ],
            sensors=[
                NetworkSensor(
                    type="firewall",
                    name="fw01",
                    monitoring_segments=["internal", "dmz"],
                    log_formats=["cisco_asa"],
                ),
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
            ],
        )
        systems = [
            System(hostname="WS-01", ip="10.0.10.50", os="Windows 10", type="workstation"),
            System(hostname="WEB-01", ip="172.16.0.5", os="Linux Ubuntu", type="server"),
        ]
        engine = NetworkVisibilityEngine(network_config=config, systems=systems)

        # External deny targeting DMZ: only firewall sensors see denied traffic
        sensors = engine.get_source_side_sensors("203.0.113.45", "172.16.0.5")
        sensor_names = {s.name for s in sensors}
        assert "dmz-zeek" not in sensor_names  # denied packets don't reach Zeek
        assert "fw01" in sensor_names  # firewall that denied the traffic
        assert "inside-zeek" not in sensor_names  # packet never reached internal


class TestEvaluateFirewallPolicy:
    """Fix 4: _evaluate_firewall_policy() should correctly evaluate rules."""

    def _make_baseline_mixin(self):
        """Create a minimal object with _evaluate_firewall_policy."""
        from evidenceforge.generation.engine.baseline import BaselineMixin

        class FakeMixin(BaselineMixin):
            pass

        return FakeMixin()

    def _make_sensor(self, policy, default_action="deny"):
        from evidenceforge.models.scenario import FirewallRule, NetworkSensor

        return NetworkSensor(
            type="firewall",
            name="fw01",
            monitoring_segments=["internal", "dmz"],
            log_formats=["cisco_asa"],
            default_action=default_action,
            policy=[FirewallRule(**rule) for rule in policy],
        )

    def _segment_cidrs(self):
        return {
            "internal": ipaddress.ip_network("10.0.10.0/24"),
            "dmz": ipaddress.ip_network("172.16.0.0/24"),
        }

    def test_default_deny_no_rules(self):
        mixin = self._make_baseline_mixin()
        sensor = self._make_sensor(policy=[], default_action="deny")
        result = mixin._evaluate_firewall_policy(
            "203.0.113.1", "10.0.10.50", 80, sensor, self._segment_cidrs()
        )
        assert result == "deny"

    def test_default_permit_no_rules(self):
        mixin = self._make_baseline_mixin()
        sensor = self._make_sensor(policy=[], default_action="permit")
        result = mixin._evaluate_firewall_policy(
            "203.0.113.1", "10.0.10.50", 80, sensor, self._segment_cidrs()
        )
        assert result == "permit"

    def test_permit_rule_matches(self):
        mixin = self._make_baseline_mixin()
        sensor = self._make_sensor(policy=[{"src": "external", "dst": "dmz", "ports": [80, 443]}])
        result = mixin._evaluate_firewall_policy(
            "203.0.113.1", "172.16.0.5", 80, sensor, self._segment_cidrs()
        )
        assert result == "permit"

    def test_permit_rule_wrong_port_falls_to_default(self):
        mixin = self._make_baseline_mixin()
        sensor = self._make_sensor(policy=[{"src": "external", "dst": "dmz", "ports": [80, 443]}])
        result = mixin._evaluate_firewall_policy(
            "203.0.113.1", "172.16.0.5", 445, sensor, self._segment_cidrs()
        )
        assert result == "deny"  # Port 445 not in permit rule, default deny

    def test_any_keyword(self):
        mixin = self._make_baseline_mixin()
        sensor = self._make_sensor(policy=[{"src": "internal", "dst": "any"}])
        result = mixin._evaluate_firewall_policy(
            "10.0.10.50", "203.0.113.1", 443, sensor, self._segment_cidrs()
        )
        assert result == "permit"

    def test_first_match_wins(self):
        mixin = self._make_baseline_mixin()
        sensor = self._make_sensor(
            policy=[
                {"src": "external", "dst": "dmz", "ports": [80], "action": "permit"},
                {"src": "external", "dst": "any", "action": "deny"},
            ]
        )
        # First rule matches: external → dmz:80 = permit
        result = mixin._evaluate_firewall_policy(
            "203.0.113.1", "172.16.0.5", 80, sensor, self._segment_cidrs()
        )
        assert result == "permit"
        # Second rule matches: external → dmz:445 (not port 80) → deny
        result = mixin._evaluate_firewall_policy(
            "203.0.113.1", "172.16.0.5", 445, sensor, self._segment_cidrs()
        )
        assert result == "deny"
