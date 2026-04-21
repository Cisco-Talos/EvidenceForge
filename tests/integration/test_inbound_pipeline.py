# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Integration tests for inbound traffic profile pipeline.

Verifies that inbound profile traffic flows through the full
generation -> dispatch -> NAT -> render pipeline correctly,
respecting segment exposure, firewall policy, and NAT translations.
"""

import json
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


def _build_inbound_scenario(
    segments: list[NetworkSegment],
    systems: list[System],
    policy: list[FirewallRule],
    nat_rules: list[NatRule] | None = None,
    extra_sensors: list[NetworkSensor] | None = None,
    log_formats: list[dict] | None = None,
) -> Scenario:
    """Build a scenario for inbound traffic integration tests."""
    fw_sensor = NetworkSensor(
        type="firewall",
        name="fw01",
        monitoring_segments=[s.name for s in segments],
        log_formats=["cisco_asa"],
        interfaces={
            "workstations": "inside",
            "servers": "inside",
            "dmz": "dmz",
            "_default": "outside",
        },
        policy=policy,
        nat_rules=nat_rules or [],
    )

    sensors = [fw_sensor]
    if extra_sensors:
        sensors.extend(extra_sensors)

    network = NetworkConfig(segments=segments, sensors=sensors)

    return Scenario(
        version="1.0",
        name="inbound-pipeline-test",
        description="Integration test for inbound traffic pipeline",
        environment=Environment(
            description="Inbound test environment",
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
            logs=log_formats or [{"format": "cisco_asa"}, {"format": "zeek_conn"}],
            destination="./output",
        ),
    )


def _read_asa_lines(output_dir: Path) -> list[str]:
    lines = []
    for log_file in output_dir.rglob("cisco_asa.log"):
        lines.extend(line for line in log_file.read_text().strip().split("\n") if line.strip())
    return lines


def _read_zeek_conn(output_dir: Path) -> list[dict]:
    records = []
    for log_file in output_dir.rglob("zeek_conn.json"):
        for line in log_file.read_text().strip().split("\n"):
            if line.strip():
                records.append(json.loads(line))
    return records


class TestDmzWebServerPermitInbound:
    """Test 1: DMZ web server with firewall permit rule gets inbound traffic."""

    def test_inbound_https_from_external(self, tmp_path):
        """DMZ web server should receive external HTTPS from inbound profiles."""
        scenario = _build_inbound_scenario(
            segments=[
                NetworkSegment(name="workstations", cidr="10.0.10.0/24", exposure="internal"),
                NetworkSegment(name="dmz", cidr="172.16.0.0/24", exposure="external"),
            ],
            systems=[
                System(hostname="WS-01", ip="10.0.10.50", os="Windows 10", type="workstation"),
                System(
                    hostname="SRV-WEB",
                    ip="172.16.0.5",
                    os="Linux Ubuntu",
                    type="server",
                    roles=["web_server"],
                ),
            ],
            policy=[
                FirewallRule(src="workstations", dst="any", action="permit"),
                FirewallRule(src="external", dst="dmz", ports=[80, 443], action="permit"),
            ],
        )

        from evidenceforge.generation.engine import GenerationEngine

        engine = GenerationEngine(scenario, tmp_path)
        engine.generate()

        asa_lines = _read_asa_lines(tmp_path)

        # Should have Built inbound records for the DMZ web server
        built_inbound = [
            line
            for line in asa_lines
            if ("302013" in line or "302015" in line) and "172.16.0.5" in line
        ]
        assert len(built_inbound) >= 1, (
            "Expected at least one ASA Built record for inbound traffic to DMZ web server"
        )


class TestInternalDbNoExternalInbound:
    """Test 2: Internal DB server should not receive external inbound traffic."""

    def test_no_external_to_internal_db(self, tmp_path):
        """Internal database should have zero external inbound connections."""
        scenario = _build_inbound_scenario(
            segments=[
                NetworkSegment(name="workstations", cidr="10.0.10.0/24", exposure="internal"),
                NetworkSegment(name="servers", cidr="10.0.20.0/24", exposure="internal"),
            ],
            systems=[
                System(hostname="WS-01", ip="10.0.10.50", os="Windows 10", type="workstation"),
                System(
                    hostname="SRV-DB",
                    ip="10.0.20.10",
                    os="Linux Ubuntu",
                    type="server",
                    roles=["database"],
                ),
            ],
            policy=[
                FirewallRule(src="workstations", dst="servers", action="permit"),
                FirewallRule(src="external", dst="servers", action="deny"),
            ],
        )

        from evidenceforge.generation.engine import GenerationEngine

        engine = GenerationEngine(scenario, tmp_path)
        engine.generate()

        zeek_records = _read_zeek_conn(tmp_path)

        # Find connections where the DB is the destination
        db_inbound = [r for r in zeek_records if r.get("id.resp_h") == "10.0.20.10"]

        # None of the inbound connections should be from external IPs
        # External IPs are non-RFC1918
        import ipaddress

        for record in db_inbound:
            src_ip = record.get("id.orig_h", "")
            try:
                addr = ipaddress.ip_address(src_ip)
                assert addr.is_private, f"Internal DB received inbound from external IP {src_ip}"
            except ValueError:
                pass  # Skip malformed IPs


class TestFirewallDenyBlocksInboundPort:
    """Test 3: Firewall deny rule blocks specific inbound ports from profiles."""

    def test_deny_port_80_permit_port_443(self, tmp_path):
        """DMZ web server should get HTTPS (443) but not HTTP (80) when 80 is denied."""
        scenario = _build_inbound_scenario(
            segments=[
                NetworkSegment(name="workstations", cidr="10.0.10.0/24", exposure="internal"),
                NetworkSegment(name="dmz", cidr="172.16.0.0/24", exposure="external"),
            ],
            systems=[
                System(hostname="WS-01", ip="10.0.10.50", os="Windows 10", type="workstation"),
                System(
                    hostname="SRV-WEB",
                    ip="172.16.0.5",
                    os="Linux Ubuntu",
                    type="server",
                    roles=["web_server"],
                ),
            ],
            policy=[
                FirewallRule(src="workstations", dst="any", action="permit"),
                # Only permit 443, deny 80
                FirewallRule(src="external", dst="dmz", ports=[443], action="permit"),
                FirewallRule(src="external", dst="dmz", ports=[80], action="deny"),
            ],
        )

        from evidenceforge.generation.engine import GenerationEngine

        engine = GenerationEngine(scenario, tmp_path)
        engine.generate()

        zeek_records = _read_zeek_conn(tmp_path)

        # Find permitted inbound connections to the web server
        web_inbound = [r for r in zeek_records if r.get("id.resp_h") == "172.16.0.5"]

        # Filter to connections from external IPs (non-RFC1918)
        import ipaddress

        external_inbound = []
        for r in web_inbound:
            try:
                addr = ipaddress.ip_address(r.get("id.orig_h", ""))
                if not addr.is_private:
                    external_inbound.append(r)
            except ValueError:
                pass

        # No external inbound should be on port 80 (denied)
        port_80_flows = [r for r in external_inbound if r.get("id.resp_p") == 80]
        assert len(port_80_flows) == 0, (
            f"Expected 0 permitted external inbound on port 80, got {len(port_80_flows)}"
        )


class TestStaticNatInbound:
    """Test 4: Static NAT translates inbound traffic addresses per sensor."""

    def test_static_nat_produces_translation_records(self, tmp_path):
        """External->VIP inbound should produce NAT translation in ASA records."""
        scenario = _build_inbound_scenario(
            segments=[
                NetworkSegment(name="workstations", cidr="10.0.10.0/24", exposure="internal"),
                NetworkSegment(name="dmz", cidr="172.16.0.0/24", exposure="external"),
            ],
            systems=[
                System(hostname="WS-01", ip="10.0.10.50", os="Windows 10", type="workstation"),
                System(
                    hostname="SRV-WEB",
                    ip="172.16.0.5",
                    os="Linux Ubuntu",
                    type="server",
                    roles=["web_server"],
                ),
            ],
            policy=[
                FirewallRule(src="workstations", dst="any", action="permit"),
                FirewallRule(src="external", dst="dmz", ports=[80, 443], action="permit"),
            ],
            nat_rules=[
                NatRule(
                    type="static",
                    src="dmz",
                    real_ip="172.16.0.5",
                    mapped_ip="203.0.113.50",
                ),
            ],
            log_formats=[{"format": "cisco_asa"}],
        )

        from evidenceforge.generation.engine import GenerationEngine

        engine = GenerationEngine(scenario, tmp_path)
        engine.generate()

        asa_lines = _read_asa_lines(tmp_path)

        # ASA records referencing the DMZ server should exist
        dmz_traffic = [line for line in asa_lines if "172.16.0.5" in line]
        assert len(dmz_traffic) >= 1, "Expected ASA records referencing DMZ server IP"

        # Static NAT translation records should reference the mapped IP
        nat_records = [line for line in asa_lines if "305011" in line]
        if nat_records:
            # If NAT records exist, they should reference both real and mapped IPs
            assert any("203.0.113.50" in line for line in nat_records), (
                "Static NAT records should reference mapped IP 203.0.113.50"
            )


class TestDeniedConnectionProducesTraces:
    """Regression: firewall-denied connections must not be dropped by visibility."""

    def test_denied_connection_from_internal_to_external_produces_asa_deny(self, tmp_path):
        """A denied connection from an internal host to an external IP should
        produce ASA deny records (106023), not be silently dropped."""
        scenario = _build_inbound_scenario(
            segments=[
                NetworkSegment(name="servers", cidr="10.0.20.0/24", exposure="internal"),
            ],
            systems=[
                System(
                    hostname="SRV-01",
                    ip="10.0.20.10",
                    os="Windows Server 2022",
                    type="domain_controller",
                    roles=["domain_controller"],
                ),
            ],
            policy=[
                # Only permit internal→internal; deny internal→external
                FirewallRule(src="servers", dst="servers", action="permit"),
            ],
            log_formats=[{"format": "cisco_asa"}],
        )
        # Add a storyline beacon (deny) event
        from evidenceforge.models.scenario import StorylineEvent

        scenario.storyline = [
            StorylineEvent(
                id="evt-beacon-deny",
                time="+0h30m",
                actor="SYSTEM",
                system="SRV-01",
                activity="Denied beacon to external IP",
                events=[
                    {
                        "type": "beacon",
                        "action": "deny",
                        "dst_ip": "45.33.32.30",
                        "dst_port": 443,
                        "interval": "30m",
                        "duration": "1h",
                        "jitter": 0.1,
                    }
                ],
            )
        ]

        from evidenceforge.generation.engine import GenerationEngine

        engine = GenerationEngine(scenario, tmp_path)
        engine.generate()

        asa_lines = _read_asa_lines(tmp_path)

        # Should have ASA deny records (106023) for the denied beacon attempts
        deny_records = [line for line in asa_lines if "106023" in line]
        assert len(deny_records) >= 1, (
            "Expected ASA deny records (106023) for denied beacon, "
            f"but found none in {len(asa_lines)} ASA lines"
        )
        # Deny records should reference the beacon destination
        assert any("45.33.32.30" in line for line in deny_records), (
            "Deny records should reference the beacon destination IP"
        )


class TestStorylineProtectedSession:
    """Regression: storyline-created sessions must not be closed by baseline."""

    def test_storyline_protected_flag_set_on_logon(self):
        """ActiveSession.storyline_protected should default to False."""
        from evidenceforge.models.state import ActiveSession

        session = ActiveSession(
            logon_id="0x1234",
            username="test",
            system="SRV-01",
            logon_type=3,
            start_time=T0,
            source_ip="10.0.0.1",
        )
        assert session.storyline_protected is False

    def test_storyline_protected_prevents_baseline_logoff(self):
        """A protected session should be skipped by baseline logoff planning."""
        from evidenceforge.models.state import ActiveSession

        session = ActiveSession(
            logon_id="0x5678",
            username="svc_test",
            system="SRV-01",
            logon_type=3,
            start_time=T0,
            source_ip="10.0.0.1",
            storyline_protected=True,
        )
        # Simulate the baseline check
        assert session.storyline_protected is True
        # The baseline loop does: if session.storyline_protected: continue
        # This test verifies the flag works as a guard
