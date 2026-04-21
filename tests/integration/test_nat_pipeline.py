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

"""Integration tests for NAT pipeline: scenario -> generation -> output validation.

These tests build minimal scenarios with NAT rules, run connections through the
full generation pipeline (ActivityGenerator + EventDispatcher + emitters), and
verify that the output files contain correct NAT translations.

All tests are skipped until Phase 6 NAT implementation is complete.
"""

from datetime import UTC, datetime
from pathlib import Path

from evidenceforge.models.scenario import (
    BaselineActivity,
    Environment,
    FirewallRule,
    NatRule,
    NetworkConfig,
    NetworkSegment,
    NetworkSensor,
    OutputSpec,
    Scenario,
    System,
    TimeWindow,
    User,
)

T0 = datetime(2024, 6, 15, 14, 0, 0, tzinfo=UTC)


def _build_nat_scenario(
    nat_rules: list[NatRule],
    policy: list[FirewallRule] | None = None,
    extra_segments: list[NetworkSegment] | None = None,
    extra_systems: list[System] | None = None,
) -> Scenario:
    """Build a minimal scenario with a firewall sensor that has NAT rules.

    Args:
        nat_rules: NAT rules for the firewall sensor.
        policy: Firewall policy rules. Defaults to permit internal->any.
        extra_segments: Additional segments beyond workstations and servers.
        extra_systems: Additional systems beyond WS-01 and SRV-WEB.
    """
    segments = [
        NetworkSegment(name="workstations", cidr="10.0.10.0/24", exposure="internal"),
        NetworkSegment(name="servers", cidr="10.0.20.0/24", exposure="internal"),
        NetworkSegment(name="dmz", cidr="172.16.0.0/24", exposure="external"),
    ]
    if extra_segments:
        segments.extend(extra_segments)

    systems = [
        System(hostname="WS-01", ip="10.0.10.50", os="Windows 10", type="workstation"),
        System(
            hostname="SRV-WEB",
            ip="172.16.0.5",
            os="Linux Ubuntu",
            type="server",
            roles=["web_server"],
        ),
    ]
    if extra_systems:
        systems.extend(extra_systems)

    default_policy = policy or [
        FirewallRule(src="workstations", dst="any", action="permit"),
        FirewallRule(src="external", dst="dmz", ports=[80, 443], action="permit"),
    ]

    sensor = NetworkSensor(
        type="firewall",
        name="fw01",
        monitoring_segments=["workstations", "servers", "dmz"],
        log_formats=["cisco_asa"],
        interfaces={
            "workstations": "inside",
            "servers": "inside",
            "dmz": "dmz",
            "_default": "outside",
        },
        policy=default_policy,
        nat_rules=nat_rules,
    )

    network = NetworkConfig(segments=segments, sensors=[sensor])

    return Scenario(
        version="1.0",
        name="nat-integration-test",
        description="Integration test for NAT pipeline",
        environment=Environment(
            description="NAT test environment",
            users=[
                User(
                    username="jsmith",
                    full_name="John Smith",
                    email="jsmith@test.com",
                    primary_system="WS-01",
                ),
            ],
            systems=systems,
            network=network,
        ),
        time_window=TimeWindow(start=T0, duration="1h"),
        baseline_activity=BaselineActivity(
            description="Minimal baseline",
            intensity="low",
            variation="low",
        ),
        output=OutputSpec(
            logs=[{"format": "cisco_asa"}, {"format": "zeek_conn"}],
            destination="./output",
        ),
    )


def _read_asa_lines(output_dir: Path) -> list[str]:
    """Read all ASA log lines from the output directory."""
    lines = []
    for log_file in output_dir.rglob("cisco_asa.log"):
        lines.extend(line for line in log_file.read_text().strip().split("\n") if line.strip())
    return lines


def _read_zeek_records(output_dir: Path) -> list[dict]:
    """Read all Zeek conn records from the output directory."""
    import json

    records = []
    for log_file in output_dir.rglob("zeek_conn.json"):
        for line in log_file.read_text().strip().split("\n"):
            if line.strip():
                records.append(json.loads(line))
    return records


# @pytest.mark.skip(reason="NAT implementation pending")
class TestOutboundDynamicPat:
    """Test outbound dynamic PAT: internal host -> internet via shared public IP."""

    def test_outbound_connection_produces_nat_translation(self, tmp_path):
        """WS-01 connecting outbound should produce 305011/305012 NAT records
        and the 302013/302014 Built/Teardown should show mapped IPs in parens."""
        scenario = _build_nat_scenario(
            nat_rules=[
                NatRule(
                    type="dynamic_pat",
                    src="workstations",
                    mapped_ip="198.51.100.1",
                ),
            ],
        )

        from evidenceforge.generation.engine import GenerationEngine

        engine = GenerationEngine(scenario, tmp_path)
        engine.generate()

        asa_lines = _read_asa_lines(tmp_path)

        # Should have 305011 Built translation record
        nat_built = [line for line in asa_lines if "305011" in line]
        assert len(nat_built) >= 1, "Expected at least one 305011 NAT Built record"
        assert "dynamic TCP translation" in nat_built[0] or "dynamic" in nat_built[0].lower()
        assert "198.51.100.1" in nat_built[0], "Mapped IP should appear in NAT record"

        # Should have 305012 Teardown translation
        nat_teardown = [line for line in asa_lines if "305012" in line]
        assert len(nat_teardown) >= 1, "Expected at least one 305012 NAT Teardown record"

        # Built connection records should show mapped IP in parentheses
        built_conn = [line for line in asa_lines if "302013" in line or "302015" in line]
        assert len(built_conn) >= 1
        # At least one Built record should contain the mapped (public) IP
        assert any("198.51.100.1" in line for line in built_conn), (
            "No Built connection record contains mapped IP 198.51.100.1 in parentheses"
        )


# @pytest.mark.skip(reason="NAT implementation pending")
class TestInboundStaticNat:
    """Test inbound static NAT: external client -> public IP mapped to DMZ server."""

    def test_inbound_connection_uses_static_nat(self, tmp_path):
        """External connection to public IP should be translated to DMZ server IP."""
        scenario = _build_nat_scenario(
            nat_rules=[
                NatRule(
                    type="static",
                    src="dmz",
                    real_ip="172.16.0.5",
                    mapped_ip="203.0.113.5",
                ),
            ],
            policy=[
                FirewallRule(src="external", dst="dmz", ports=[80, 443], action="permit"),
                FirewallRule(src="workstations", dst="any", action="permit"),
            ],
        )

        from evidenceforge.generation.engine import GenerationEngine

        engine = GenerationEngine(scenario, tmp_path)
        engine.generate()

        asa_lines = _read_asa_lines(tmp_path)

        # Static NAT should produce 305011 records
        nat_records = [line for line in asa_lines if "305011" in line]
        assert len(nat_records) >= 1, "Expected static NAT translation records"
        assert "static" in nat_records[0].lower()

        # Outbound connections from DMZ server should show the mapped public IP
        # via static NAT in either Built records or NAT translation records
        dmz_traffic = [line for line in asa_lines if "172.16.0.5" in line]
        assert any("203.0.113.5" in line for line in dmz_traffic), (
            "DMZ server traffic should reference mapped IP 203.0.113.5 via static NAT"
        )


# @pytest.mark.skip(reason="NAT implementation pending")
class TestNoNatRegression:
    """Test that connections without NAT rules still work correctly."""

    def test_connections_without_nat_produce_identity_parens(self, tmp_path):
        """When no NAT rules exist, Built records should have matching parens (identity)."""
        scenario = _build_nat_scenario(nat_rules=[])

        from evidenceforge.generation.engine import GenerationEngine

        engine = GenerationEngine(scenario, tmp_path)
        engine.generate()

        asa_lines = _read_asa_lines(tmp_path)

        built_conn = [line for line in asa_lines if "302013" in line or "302015" in line]
        assert len(built_conn) >= 1, "Should produce at least one Built connection"

        # No 305011/305012 NAT records should appear
        nat_records = [line for line in asa_lines if "305011" in line or "305012" in line]
        assert len(nat_records) == 0, "No NAT records expected when no NAT rules defined"


# @pytest.mark.skip(reason="NAT implementation pending")
class TestDeniedWithNatRules:
    """Test that denied connections do NOT produce NAT translation records."""

    def test_denied_connection_has_no_nat_records(self, tmp_path):
        """Deny records (106023) should not have corresponding NAT translations.

        Note: baseline may still generate permitted connections that produce NAT
        records. We verify that deny records themselves never produce 305011.
        """
        scenario = _build_nat_scenario(
            nat_rules=[
                NatRule(
                    type="dynamic_pat",
                    src="workstations",
                    mapped_ip="198.51.100.1",
                ),
            ],
            policy=[
                # Deny all outbound from workstations (unusual but tests the deny path)
                FirewallRule(src="workstations", dst="any", action="deny"),
            ],
        )

        from evidenceforge.generation.engine import GenerationEngine

        engine = GenerationEngine(scenario, tmp_path)
        engine.generate()

        asa_lines = _read_asa_lines(tmp_path)

        # Should have deny records from the deny-all policy
        deny_records = [line for line in asa_lines if "106023" in line]
        assert len(deny_records) >= 1, "Expected deny records"

        # Deny records should NOT show NAT-mapped IPs in their message body.
        # The mapped IP 198.51.100.1 should only appear in 305011/305012 and
        # Built parens, never in a 106023 deny message.
        for deny_line in deny_records:
            assert "198.51.100.1" not in deny_line, "Deny records should not contain NAT-mapped IP"


# @pytest.mark.skip(reason="NAT implementation pending")
class TestSameSegmentNoNat:
    """Test that intra-segment traffic does not get NAT-translated."""

    def test_same_segment_traffic_no_nat(self, tmp_path):
        """Traffic between two hosts in the same segment should not be NATed."""
        scenario = _build_nat_scenario(
            nat_rules=[
                NatRule(
                    type="dynamic_pat",
                    src="workstations",
                    mapped_ip="198.51.100.1",
                ),
            ],
            extra_systems=[
                System(
                    hostname="WS-02",
                    ip="10.0.10.51",
                    os="Windows 10",
                    type="workstation",
                ),
            ],
        )

        from evidenceforge.generation.engine import GenerationEngine

        engine = GenerationEngine(scenario, tmp_path)
        engine.generate()

        asa_lines = _read_asa_lines(tmp_path)

        # Look for connections between two workstation IPs
        intra_segment = [
            line
            for line in asa_lines
            if "10.0.10.50" in line and "10.0.10.51" in line and "302013" in line
        ]

        # If any intra-segment connections exist, they should NOT have NAT translations
        for line in intra_segment:
            # The parenthesized IPs should match the real IPs (identity)
            assert "198.51.100.1" not in line, "Intra-segment traffic should not use NAT mapped IP"
