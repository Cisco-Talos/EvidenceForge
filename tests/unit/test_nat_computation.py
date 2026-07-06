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

"""TDD tests for compute_nat() on NetworkVisibilityEngine.

These tests define the planned API for NAT computation. All tests will fail
until the implementation is added.
"""

from datetime import UTC, datetime

import pytest

from evidenceforge.generation.network_visibility import NetworkVisibilityEngine
from evidenceforge.models.scenario import (
    NatRule,
    NetworkConfig,
    NetworkSegment,
    NetworkSensor,
    System,
)

T0 = datetime(2024, 6, 15, 14, 0, 0, tzinfo=UTC)


def _make_segments():
    """Create test network segments."""
    return [
        NetworkSegment(name="workstations", cidr="10.0.10.0/24", exposure="internal"),
        NetworkSegment(name="servers", cidr="10.0.20.0/24", exposure="internal"),
        NetworkSegment(name="dmz", cidr="172.16.0.0/24", exposure="external"),
    ]


def _make_systems():
    """Create test systems across segments."""
    return [
        System(hostname="WS-01", ip="10.0.10.50", os="Windows 10", type="workstation"),
        System(hostname="SRV-01", ip="10.0.20.5", os="Windows Server 2019", type="server"),
        System(hostname="WEB-01", ip="172.16.0.5", os="Linux Ubuntu 22.04", type="server"),
    ]


def _make_nat_rules():
    """Create test NAT rules: one dynamic PAT, one static NAT."""
    return [
        NatRule(
            type="dynamic_pat",
            src=["workstations", "servers"],
            mapped_ip="198.51.100.1",
        ),
        NatRule(
            type="static",
            src="dmz",
            real_ip="172.16.0.5",
            mapped_ip="203.0.113.5",
        ),
    ]


def _make_firewall_sensor(nat_rules=None):
    """Create a firewall sensor with optional NAT rules."""
    return NetworkSensor(
        type="firewall",
        name="fw01",
        hostname="fw01",
        monitoring_segments=["workstations", "servers", "dmz"],
        log_formats=["cisco_asa"],
        nat_rules=nat_rules or [],
    )


def _make_engine(nat_rules=None):
    """Build a NetworkVisibilityEngine with standard test topology and NAT rules."""
    segments = _make_segments()
    sensor = _make_firewall_sensor(nat_rules=nat_rules)
    config = NetworkConfig(segments=segments, sensors=[sensor])
    systems = _make_systems()
    return NetworkVisibilityEngine(config, systems)


@pytest.fixture
def engine():
    """Standard engine with both PAT and static NAT rules."""
    return _make_engine(nat_rules=_make_nat_rules())


@pytest.fixture
def engine_no_nat():
    """Engine with no NAT rules configured."""
    return _make_engine(nat_rules=[])


class TestDynamicPat:
    """Tests for dynamic PAT (many-to-one with port translation)."""

    def test_dynamic_pat_translates_source_ip(self, engine):
        """Workstation IP should be translated to the PAT mapped IP."""
        result = engine.compute_nat("10.0.10.50", "203.0.113.50", 54321, 443)
        assert result is not None
        assert result.mapped_src_ip == "198.51.100.1"

    def test_dynamic_pat_changes_source_port(self, engine):
        """PAT should allocate a new source port different from the original."""
        result = engine.compute_nat("10.0.10.50", "203.0.113.50", 54321, 443)
        assert result is not None
        assert result.mapped_src_port != 54321

    def test_pat_port_allocation_increments(self, engine):
        """Two calls with the same src IP should get different mapped ports."""
        r1 = engine.compute_nat("10.0.10.50", "203.0.113.50", 54321, 443)
        r2 = engine.compute_nat("10.0.10.50", "203.0.113.50", 54322, 443)
        assert r1 is not None and r2 is not None
        assert r1.mapped_src_port != r2.mapped_src_port

    def test_pat_port_allocation_per_rule(self):
        """Two PAT rules should each maintain an independent port counter."""
        rules = [
            NatRule(type="dynamic_pat", src="workstations", mapped_ip="198.51.100.1"),
            NatRule(type="dynamic_pat", src="servers", mapped_ip="198.51.100.2"),
        ]
        eng = _make_engine(nat_rules=rules)
        r_ws = eng.compute_nat("10.0.10.50", "203.0.113.50", 54321, 443)
        r_srv = eng.compute_nat("10.0.20.5", "203.0.113.50", 54321, 443)
        assert r_ws is not None and r_srv is not None
        # Both rules start from independent counters so ports may overlap, but the
        # mapped IPs must come from their respective rules.
        assert r_ws.mapped_src_ip == "198.51.100.1"
        assert r_srv.mapped_src_ip == "198.51.100.2"

    def test_multi_segment_src_matches_any(self, engine):
        """PAT rule with src=[workstations, servers] should match IPs in servers."""
        result = engine.compute_nat("10.0.20.5", "203.0.113.50", 54321, 443)
        assert result is not None
        assert result.mapped_src_ip == "198.51.100.1"

    def test_pat_port_wraps_at_65535(self):
        """PAT port counter must wrap around before exceeding 65535."""
        rules = [NatRule(type="dynamic_pat", src="workstations", mapped_ip="198.51.100.1")]
        eng = _make_engine(nat_rules=rules)
        # Force counter near the ceiling
        key = ("fw01", 0)
        eng._pat_port_counters[key] = 65534
        ports = []
        for _ in range(5):
            r = eng.compute_nat("10.0.10.50", "203.0.113.50", 54321, 443)
            assert r is not None
            assert 1024 <= r.mapped_src_port <= 65535, (
                f"Port {r.mapped_src_port} out of valid range"
            )
            ports.append(r.mapped_src_port)
        assert len(set(ports)) > 1, "Ports should not all be the same after wrap"


class TestStaticNat:
    """Tests for static NAT (one-to-one IP mapping)."""

    def test_static_nat_outbound_translates_source(self, engine):
        """DMZ server going outbound should have its source IP translated."""
        result = engine.compute_nat("172.16.0.5", "203.0.113.99", 443, 80)
        assert result is not None
        assert result.mapped_src_ip == "203.0.113.5"
        # Static NAT preserves ports
        assert result.mapped_src_port == 443

    def test_static_nat_inbound_translates_dest(self, engine):
        """Inbound connection to the public IP should translate the dest to real IP."""
        result = engine.compute_nat("203.0.113.99", "203.0.113.5", 54321, 443)
        assert result is not None
        assert result.mapped_dst_ip == "172.16.0.5"

    def test_static_nat_inbound_real_dest_keeps_public_vip_context(self, engine):
        """External traffic generated to the real host should still carry ASA VIP context."""
        result = engine.compute_nat("203.0.113.99", "172.16.0.5", 54321, 443)
        assert result is not None
        assert result.nat_type == "static"
        assert result.mapped_dst_ip == "172.16.0.5"
        assert result.mapped_dst_port == 443
        assert result.pre_nat_dst_ip == "203.0.113.5"
        assert result.pre_nat_dst_port == 443


class TestNoNat:
    """Tests for scenarios where NAT should not apply."""

    def test_no_nat_for_same_segment(self, engine):
        """Traffic within the same segment should not be NATted."""
        result = engine.compute_nat("10.0.10.50", "10.0.10.100", 54321, 80)
        assert result is None

    def test_no_nat_when_no_rules(self, engine_no_nat):
        """Engine with no NAT rules should always return None."""
        result = engine_no_nat.compute_nat("10.0.10.50", "203.0.113.50", 54321, 443)
        assert result is None

    def test_no_nat_for_external_to_external(self, engine):
        """External-to-external traffic should not be NATted."""
        result = engine.compute_nat("203.0.113.1", "8.8.8.8", 54321, 443)
        assert result is None

    def test_static_nat_internal_to_internal_no_translation(self, engine):
        """DMZ host talking to internal server should NOT have static NAT applied.

        Bug: compute_nat() applied static NAT whenever src_ip == real_ip
        without checking if destination is external. A 172.16.0.5 → 10.0.20.5
        connection incorrectly returned mapped_src_ip=203.0.113.5.
        """
        result = engine.compute_nat("172.16.0.5", "10.0.20.5", 443, 3306)
        assert result is None, (
            f"Static NAT should not apply to internal-to-internal traffic, but got {result}"
        )

    def test_static_nat_outbound_to_external_still_works(self, engine):
        """DMZ host going to external IP should still get static NAT."""
        result = engine.compute_nat("172.16.0.5", "8.8.8.8", 443, 80)
        assert result is not None
        assert result.mapped_src_ip == "203.0.113.5"


class TestRuleOrdering:
    """Tests for rule matching order."""

    def test_first_matching_rule_wins(self):
        """When two rules match the same traffic, the first rule should win."""
        rules = [
            NatRule(type="dynamic_pat", src="workstations", mapped_ip="198.51.100.1"),
            NatRule(type="dynamic_pat", src="workstations", mapped_ip="198.51.100.99"),
        ]
        eng = _make_engine(nat_rules=rules)
        result = eng.compute_nat("10.0.10.50", "203.0.113.50", 54321, 443)
        assert result is not None
        assert result.mapped_src_ip == "198.51.100.1"


class TestMultiFirewallScoping:
    """NAT rules must be scoped to the firewall in the connection path."""

    def test_multi_firewall_nat_scoped_to_path(self):
        """fw-ext PAT rule should NOT apply to connections through fw-int."""
        segments = [
            NetworkSegment(name="workstations", cidr="10.0.10.0/24", exposure="internal"),
            NetworkSegment(name="servers", cidr="10.0.20.0/24", exposure="internal"),
            NetworkSegment(name="database", cidr="10.0.30.0/24", exposure="internal"),
        ]
        systems = [
            System(hostname="WS-01", ip="10.0.10.50", os="Windows 10", type="workstation"),
            System(hostname="SRV-01", ip="10.0.20.5", os="Linux", type="server"),
            System(hostname="DB-01", ip="10.0.30.5", os="Linux", type="server"),
        ]
        fw_ext = NetworkSensor(
            type="firewall",
            name="fw-ext",
            monitoring_segments=["workstations"],
            log_formats=["cisco_asa"],
            nat_rules=[NatRule(type="dynamic_pat", src="workstations", mapped_ip="198.51.100.1")],
        )
        fw_int = NetworkSensor(
            type="firewall",
            name="fw-int",
            monitoring_segments=["servers", "database"],
            log_formats=["cisco_asa"],
            nat_rules=[],  # No NAT on internal firewall
        )
        config = NetworkConfig(segments=segments, sensors=[fw_ext, fw_int])
        engine = NetworkVisibilityEngine(config, systems)

        # Connection from servers -> external: fw-ext's PAT should NOT match
        # because fw-ext only monitors workstations, not servers
        result = engine.compute_nat("10.0.20.5", "203.0.113.50", 54321, 443)
        assert result is None

    def test_nat_rule_from_correct_firewall_used(self):
        """Connection from workstations should match fw-ext's PAT rule."""
        segments = [
            NetworkSegment(name="workstations", cidr="10.0.10.0/24", exposure="internal"),
            NetworkSegment(name="servers", cidr="10.0.20.0/24", exposure="internal"),
        ]
        systems = [
            System(hostname="WS-01", ip="10.0.10.50", os="Windows 10", type="workstation"),
            System(hostname="SRV-01", ip="10.0.20.5", os="Linux", type="server"),
        ]
        fw_ext = NetworkSensor(
            type="firewall",
            name="fw-ext",
            monitoring_segments=["workstations"],
            log_formats=["cisco_asa"],
            nat_rules=[NatRule(type="dynamic_pat", src="workstations", mapped_ip="198.51.100.1")],
        )
        fw_int = NetworkSensor(
            type="firewall",
            name="fw-int",
            monitoring_segments=["servers"],
            log_formats=["cisco_asa"],
            nat_rules=[],
        )
        config = NetworkConfig(segments=segments, sensors=[fw_ext, fw_int])
        engine = NetworkVisibilityEngine(config, systems)

        # Connection from workstations -> external: fw-ext's PAT should match
        result = engine.compute_nat("10.0.10.50", "203.0.113.50", 54321, 443)
        assert result is not None
        assert result.mapped_src_ip == "198.51.100.1"

        # Connection from servers -> servers (through fw-int, no NAT): should return None
        result = engine.compute_nat("10.0.20.5", "10.0.20.10", 54321, 80)
        assert result is None
