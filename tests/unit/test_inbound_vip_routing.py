# Tests for inbound static-NAT VIP routing (public address space).
#
# Verifies:
# - VIP reverse lookup construction from static NAT rules
# - VIP segment registration (VIP inherits real_ip's segments)
# - Public CIDR auto-derivation from VIPs
# - get_inbound_vip() accessor
# - public_cidrs model field and validation

import ipaddress

import pytest

from evidenceforge.models.scenario import (
    FirewallRule,
    NatRule,
    NetworkConfig,
    NetworkSegment,
    NetworkSensor,
    System,
)


def _make_network_config(
    *,
    nat_rules: list[NatRule] | None = None,
    public_cidrs: list[str] | None = None,
) -> tuple[NetworkConfig, list[System]]:
    """Build a minimal network config with DMZ, firewall, and optional NAT/public_cidrs."""
    segments = [
        NetworkSegment(name="corporate", cidr="10.0.1.0/24"),
        NetworkSegment(name="dmz", cidr="172.16.0.0/24", exposure="both"),
    ]
    fw_sensor = NetworkSensor(
        type="firewall",
        name="fw01",
        hostname="fw01",
        monitoring_segments=["corporate", "dmz"],
        log_formats=["cisco_asa"],
        interfaces={"corporate": "inside", "dmz": "dmz"},
        policy=[
            FirewallRule(src="external", dst="dmz", ports=[80, 443]),
            FirewallRule(src="corporate", dst="any"),
        ],
        nat_rules=nat_rules or [],
    )
    zeek_sensor = NetworkSensor(
        type="network",
        name="dmz-zeek",
        hostname="dmz-zeek",
        monitoring_segments=["dmz"],
        direction="bidirectional",
        log_formats=["zeek"],
    )
    config = NetworkConfig(
        segments=segments,
        sensors=[fw_sensor, zeek_sensor],
        public_cidrs=public_cidrs or [],
    )
    systems = [
        System(hostname="WS-01", ip="10.0.1.50", os="Windows 10", type="workstation"),
        System(hostname="WEB-01", ip="172.16.0.5", os="Linux Ubuntu", type="server"),
    ]
    return config, systems


class TestVipReverseLookup:
    """Step 1: VIP lookup tables built from static NAT rules."""

    def test_static_nat_creates_vip_lookup(self):
        from evidenceforge.generation.network_visibility import NetworkVisibilityEngine

        config, systems = _make_network_config(
            nat_rules=[
                NatRule(type="static", src=["dmz"], mapped_ip="203.0.113.5", real_ip="172.16.0.5")
            ]
        )
        engine = NetworkVisibilityEngine(network_config=config, systems=systems)
        assert engine._vip_to_real_ip == {"203.0.113.5": "172.16.0.5"}
        assert engine._real_ip_to_vip == {"172.16.0.5": "203.0.113.5"}

    def test_get_inbound_vip(self):
        from evidenceforge.generation.network_visibility import NetworkVisibilityEngine

        config, systems = _make_network_config(
            nat_rules=[
                NatRule(type="static", src=["dmz"], mapped_ip="203.0.113.5", real_ip="172.16.0.5")
            ]
        )
        engine = NetworkVisibilityEngine(network_config=config, systems=systems)
        assert engine.get_inbound_vip("172.16.0.5") == "203.0.113.5"
        assert engine.get_inbound_vip("10.0.1.50") is None

    def test_dynamic_pat_does_not_create_vip(self):
        from evidenceforge.generation.network_visibility import NetworkVisibilityEngine

        config, systems = _make_network_config(
            nat_rules=[NatRule(type="dynamic_pat", src=["corporate"], mapped_ip="198.51.100.1")]
        )
        engine = NetworkVisibilityEngine(network_config=config, systems=systems)
        assert engine._vip_to_real_ip == {}
        assert engine._real_ip_to_vip == {}

    def test_no_nat_rules_empty_lookups(self):
        from evidenceforge.generation.network_visibility import NetworkVisibilityEngine

        config, systems = _make_network_config()
        engine = NetworkVisibilityEngine(network_config=config, systems=systems)
        assert engine._vip_to_real_ip == {}
        assert engine._real_ip_to_vip == {}


class TestVipSegmentRegistration:
    """Step 1: VIPs inherit real_ip's segment membership."""

    def test_vip_resolves_to_real_ip_segments(self):
        from evidenceforge.generation.network_visibility import NetworkVisibilityEngine

        config, systems = _make_network_config(
            nat_rules=[
                NatRule(type="static", src=["dmz"], mapped_ip="203.0.113.5", real_ip="172.16.0.5")
            ]
        )
        engine = NetworkVisibilityEngine(network_config=config, systems=systems)
        # VIP should be in the same segments as real_ip (dmz)
        vip_segs = engine._resolve_ip_segments("203.0.113.5")
        real_segs = engine._resolve_ip_segments("172.16.0.5")
        assert vip_segs == real_segs
        assert "dmz" in vip_segs


class TestPublicCidrAutoDerivation:
    """Step 4: Auto-derive public CIDRs from VIPs grouped by /24."""

    def test_single_vip_derives_one_slash24(self):
        from evidenceforge.generation.network_visibility import NetworkVisibilityEngine

        config, systems = _make_network_config(
            nat_rules=[
                NatRule(type="static", src=["dmz"], mapped_ip="203.0.113.5", real_ip="172.16.0.5")
            ]
        )
        engine = NetworkVisibilityEngine(network_config=config, systems=systems)
        assert len(engine._public_cidrs) == 1
        assert engine._public_cidrs[0] == ipaddress.ip_network("203.0.113.0/24")

    def test_two_vips_same_slash24(self):
        from evidenceforge.generation.network_visibility import NetworkVisibilityEngine

        config, systems = _make_network_config(
            nat_rules=[
                NatRule(type="static", src=["dmz"], mapped_ip="203.0.113.5", real_ip="172.16.0.5"),
                NatRule(
                    type="static", src=["dmz"], mapped_ip="203.0.113.10", real_ip="172.16.0.10"
                ),
            ]
        )
        # Need a second system for the second NAT rule
        systems.append(
            System(hostname="WEB-02", ip="172.16.0.10", os="Linux Ubuntu", type="server")
        )
        engine = NetworkVisibilityEngine(network_config=config, systems=systems)
        assert len(engine._public_cidrs) == 1

    def test_two_vips_different_slash24s(self):
        from evidenceforge.generation.network_visibility import NetworkVisibilityEngine

        config, systems = _make_network_config(
            nat_rules=[
                NatRule(type="static", src=["dmz"], mapped_ip="203.0.113.5", real_ip="172.16.0.5"),
                NatRule(type="static", src=["dmz"], mapped_ip="45.33.32.10", real_ip="172.16.0.10"),
            ]
        )
        systems.append(
            System(hostname="WEB-02", ip="172.16.0.10", os="Linux Ubuntu", type="server")
        )
        engine = NetworkVisibilityEngine(network_config=config, systems=systems)
        assert len(engine._public_cidrs) == 2
        prefixes = {str(c) for c in engine._public_cidrs}
        assert "203.0.113.0/24" in prefixes
        assert "45.33.32.0/24" in prefixes

    def test_explicit_public_cidrs_override_auto(self):
        from evidenceforge.generation.network_visibility import NetworkVisibilityEngine

        config, systems = _make_network_config(
            nat_rules=[
                NatRule(type="static", src=["dmz"], mapped_ip="203.0.113.5", real_ip="172.16.0.5")
            ],
            public_cidrs=["198.51.100.0/28"],
        )
        engine = NetworkVisibilityEngine(network_config=config, systems=systems)
        assert len(engine._public_cidrs) == 1
        assert engine._public_cidrs[0] == ipaddress.ip_network("198.51.100.0/28")

    def test_no_vips_no_public_cidrs(self):
        from evidenceforge.generation.network_visibility import NetworkVisibilityEngine

        config, systems = _make_network_config()
        engine = NetworkVisibilityEngine(network_config=config, systems=systems)
        assert engine._public_cidrs == []


class TestPublicCidrsModel:
    """Step 4: Model field validation."""

    def test_valid_public_cidrs(self):
        config, _ = _make_network_config(public_cidrs=["203.0.113.0/28", "198.51.100.0/24"])
        assert config.public_cidrs == ["203.0.113.0/28", "198.51.100.0/24"]

    def test_invalid_cidr_rejected(self):
        with pytest.raises(ValueError, match="Invalid public_cidrs"):
            _make_network_config(public_cidrs=["not-a-cidr"])

    def test_empty_public_cidrs_default(self):
        config, _ = _make_network_config()
        assert config.public_cidrs == []
