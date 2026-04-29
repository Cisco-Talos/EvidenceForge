# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Integration coverage for storyline events routed through explicit proxy."""

import json
from datetime import UTC, datetime
from pathlib import Path

import pytest

from evidenceforge.generation.engine import GenerationEngine
from evidenceforge.models.scenario import (
    BaselineActivity,
    Environment,
    FirewallRule,
    NetworkConfig,
    NetworkSegment,
    NetworkSensor,
    OutputSpec,
    ProxyConfig,
    Scenario,
    StorylineEvent,
    System,
    TimeWindow,
    User,
)


def _read_proxy_lines(output_dir: Path) -> list[str]:
    lines: list[str] = []
    for log_file in output_dir.rglob("proxy_access.log"):
        lines.extend(line for line in log_file.read_text().splitlines() if line.strip())
    return lines


def _read_asa_lines(output_dir: Path) -> list[str]:
    lines: list[str] = []
    for log_file in output_dir.rglob("cisco_asa.log"):
        lines.extend(line for line in log_file.read_text().splitlines() if line.strip())
    return lines


def _read_zeek_conn_records(output_dir: Path) -> list[dict]:
    records: list[dict] = []
    for log_file in output_dir.rglob("conn.json"):
        for line in log_file.read_text().splitlines():
            if line.strip():
                records.append(json.loads(line))
    return records


class TestStorylineBeaconExplicitProxy:
    def test_allowed_http_beacon_to_documentation_ip_appears_in_proxy_access(self, tmp_path):
        """Storyline beacons with external hostnames should route through explicit proxy."""
        scenario = Scenario(
            version="1.0",
            name="beacon-proxy-repro",
            description="Repro for beacon events not appearing in proxy_access.log",
            environment=Environment(
                description="Repro environment",
                proxy=ProxyConfig(mode="explicit", listener_port=8080),
                users=[
                    User(
                        username="jsmith",
                        full_name="Jane Smith",
                        email="j.smith@example.com",
                        persona="analyst",
                        primary_system="ws01",
                    )
                ],
                systems=[
                    System(
                        hostname="proxy01",
                        ip="192.168.1.20",
                        os="Ubuntu 24.04",
                        type="server",
                        roles=["forward_proxy"],
                        services=["forward_proxy"],
                    ),
                    System(
                        hostname="ws01",
                        ip="192.168.2.10",
                        os="Windows 11",
                        type="workstation",
                        assigned_user="jsmith",
                    ),
                ],
                network=NetworkConfig(
                    segments=[
                        NetworkSegment(
                            name="corporate_lan",
                            cidr="192.168.2.0/24",
                            exposure="internal",
                            systems=["ws01"],
                        ),
                        NetworkSegment(
                            name="services",
                            cidr="192.168.1.0/24",
                            exposure="internal",
                            systems=["proxy01"],
                        ),
                    ],
                    sensors=[
                        NetworkSensor(
                            type="network",
                            name="tap01",
                            monitoring_segments=["services", "corporate_lan"],
                            direction="bidirectional",
                            placement="tap",
                            log_formats=["zeek"],
                        )
                    ],
                ),
            ),
            time_window=TimeWindow(start=datetime(2024, 10, 14, 4, 0, tzinfo=UTC), duration="1h"),
            baseline_activity=BaselineActivity(
                description="Normal browsing", intensity="low", variation="low"
            ),
            storyline=[
                StorylineEvent(
                    id="evt-beacon",
                    time="+1m",
                    actor="jsmith",
                    system="ws01",
                    activity="C2 HTTP beacon to dynsync-update.net",
                    events=[
                        {
                            "type": "beacon",
                            "dst_ip": "203.0.113.45",
                            "dst_port": 80,
                            "hostname": "dynsync-update.net",
                            "service": "http",
                            "method": "GET",
                            "uri": "/jquery-3.3.1.min.js",
                            "user_agent": (
                                "Mozilla/5.0 (Windows NT 6.1; Trident/7.0; rv:11.0) like Gecko"
                            ),
                            "status_code": 200,
                            "interval": "60s",
                            "count": 3,
                            "jitter": 0.0,
                            "technique": "T1071.001 - Application Layer Protocol: Web Protocols",
                        }
                    ],
                )
            ],
            output=OutputSpec(logs=[{"format": "proxy_access"}], destination="./output"),
        )

        GenerationEngine(scenario, tmp_path).generate()

        beacon_lines = [
            line for line in _read_proxy_lines(tmp_path) if "dynsync-update.net" in line
        ]
        assert len(beacon_lines) == 3
        assert all("192.168.2.10" in line for line in beacon_lines)
        assert all(
            " GET http://dynsync-update.net/jquery-3.3.1.min.js " in line for line in beacon_lines
        )
        assert all(
            "Mozilla/5.0+(Windows+NT+6.1;+Trident/7.0;+rv:11.0)+like+Gecko" in line
            for line in beacon_lines
        )

    def test_allowed_https_beacon_preserves_user_agent_on_connect(self, tmp_path):
        """HTTPS storyline beacons should write the specified UA to proxy CONNECT rows."""
        custom_ua = "EvilBeacon/4.2 (compatible; legacy-updater)"
        scenario = Scenario(
            version="1.0",
            name="beacon-proxy-https-ua",
            description="HTTPS beacon User-Agent passthrough repro",
            environment=Environment(
                description="Repro environment",
                proxy=ProxyConfig(mode="explicit", listener_port=8080),
                users=[
                    User(
                        username="jsmith",
                        full_name="Jane Smith",
                        email="j.smith@example.com",
                        persona="analyst",
                        primary_system="ws01",
                    )
                ],
                systems=[
                    System(
                        hostname="proxy01",
                        ip="192.168.1.20",
                        os="Ubuntu 24.04",
                        type="server",
                        roles=["forward_proxy"],
                        services=["forward_proxy"],
                    ),
                    System(
                        hostname="ws01",
                        ip="192.168.2.10",
                        os="Windows 11",
                        type="workstation",
                        assigned_user="jsmith",
                    ),
                ],
                network=NetworkConfig(
                    segments=[
                        NetworkSegment(
                            name="corporate_lan",
                            cidr="192.168.2.0/24",
                            exposure="internal",
                            systems=["ws01"],
                        ),
                        NetworkSegment(
                            name="services",
                            cidr="192.168.1.0/24",
                            exposure="internal",
                            systems=["proxy01"],
                        ),
                    ],
                    sensors=[
                        NetworkSensor(
                            type="network",
                            name="tap01",
                            monitoring_segments=["services", "corporate_lan"],
                            direction="bidirectional",
                            placement="tap",
                            log_formats=["zeek"],
                        )
                    ],
                ),
            ),
            time_window=TimeWindow(start=datetime(2024, 10, 14, 4, 0, tzinfo=UTC), duration="1h"),
            baseline_activity=BaselineActivity(
                description="Normal browsing", intensity="low", variation="low"
            ),
            storyline=[
                StorylineEvent(
                    id="evt-beacon",
                    time="+1m",
                    actor="jsmith",
                    system="ws01",
                    activity="C2 HTTPS beacon to dynsync-update.net",
                    events=[
                        {
                            "type": "beacon",
                            "dst_ip": "45.33.49.112",
                            "dst_port": 443,
                            "hostname": "dynsync-update.net",
                            "service": "ssl",
                            "user_agent": custom_ua,
                            "status_code": 200,
                            "interval": "6m",
                            "count": 3,
                            "jitter": 0.0,
                            "technique": "T1071.001 - Application Layer Protocol: Web Protocols",
                        }
                    ],
                )
            ],
            output=OutputSpec(logs=[{"format": "proxy_access"}], destination="./output"),
        )

        GenerationEngine(scenario, tmp_path).generate()

        beacon_lines = [
            line for line in _read_proxy_lines(tmp_path) if "dynsync-update.net" in line
        ]
        connect_lines = [
            line for line in beacon_lines if " CONNECT dynsync-update.net:443 " in line
        ]
        inspected_lines = [
            line for line in beacon_lines if " GET https://dynsync-update.net/ " in line
        ]
        assert len(connect_lines) == 3
        assert len(inspected_lines) == 3
        assert all(custom_ua.replace(" ", "+") in line for line in beacon_lines)

    @pytest.mark.slow
    def test_explicit_proxy_fixture_includes_zeek_proxy_and_firewall_visibility(self, tmp_path):
        """Review fixtures should exercise proxy, Zeek, and ASA correlation together."""
        allowed_host = "telemetry-sync.example.net"
        denied_host = "blocked-c2.example.net"
        scenario = Scenario(
            version="1.0",
            name="explicit-proxy-firewall-review-fixture",
            description="Small explicit-proxy fixture with Zeek and ASA visibility",
            environment=Environment(
                description="Proxy and firewall correlation fixture",
                proxy=ProxyConfig(mode="explicit", listener_port=8080),
                users=[
                    User(
                        username="jsmith",
                        full_name="Jane Smith",
                        email="j.smith@example.com",
                        persona="analyst",
                        primary_system="ws01",
                    )
                ],
                systems=[
                    System(
                        hostname="proxy01",
                        ip="10.0.20.10",
                        os="Ubuntu 24.04",
                        type="server",
                        roles=["forward_proxy"],
                        services=["forward_proxy"],
                    ),
                    System(
                        hostname="ws01",
                        ip="10.0.10.10",
                        os="Windows 11",
                        type="workstation",
                        assigned_user="jsmith",
                    ),
                ],
                network=NetworkConfig(
                    segments=[
                        NetworkSegment(
                            name="workstations",
                            cidr="10.0.10.0/24",
                            exposure="internal",
                            systems=["ws01"],
                        ),
                        NetworkSegment(
                            name="services",
                            cidr="10.0.20.0/24",
                            exposure="internal",
                            systems=["proxy01"],
                        ),
                    ],
                    sensors=[
                        NetworkSensor(
                            type="network",
                            name="client-tap",
                            monitoring_segments=["workstations"],
                            direction="outbound",
                            placement="span",
                            log_formats=["zeek"],
                        ),
                        NetworkSensor(
                            type="network",
                            name="egress-tap",
                            monitoring_segments=["services"],
                            direction="outbound",
                            placement="tap",
                            log_formats=["zeek"],
                        ),
                        NetworkSensor(
                            type="firewall",
                            name="egress-fw",
                            monitoring_segments=["services"],
                            direction="outbound",
                            placement="tap",
                            log_formats=["cisco_asa"],
                            interfaces={"services": "inside", "_default": "outside"},
                            policy=[
                                FirewallRule(src="services", dst="external", action="permit"),
                            ],
                            default_action="deny",
                        ),
                    ],
                ),
            ),
            time_window=TimeWindow(start=datetime(2024, 10, 14, 4, 0, tzinfo=UTC), duration="30m"),
            baseline_activity=BaselineActivity(
                description="Minimal background",
                intensity="low",
                variation="low",
                suspicious_noise="low",
                traffic_rates={
                    "web": 1,
                    "dns_interval": 1,
                    "kerberos": 1,
                    "ldap": 1,
                    "ntp": 1,
                    "persona_connections": 1,
                    "smb_interval": 1,
                    "user_activity": 1,
                },
            ),
            storyline=[
                StorylineEvent(
                    id="evt-allowed",
                    time="+1m",
                    actor="jsmith",
                    system="ws01",
                    activity="Allowed HTTPS beacon through explicit proxy",
                    events=[
                        {
                            "type": "beacon",
                            "dst_ip": "45.33.49.112",
                            "dst_port": 443,
                            "hostname": allowed_host,
                            "service": "ssl",
                            "method": "GET",
                            "uri": "/v1/checkin",
                            "user_agent": "FixtureBeacon/1.0",
                            "status_code": 200,
                            "interval": "5m",
                            "count": 1,
                            "jitter": 0.0,
                        }
                    ],
                ),
                StorylineEvent(
                    id="evt-denied",
                    time="+6m",
                    actor="jsmith",
                    system="ws01",
                    activity="Denied HTTPS beacon blocked at explicit proxy",
                    events=[
                        {
                            "type": "beacon",
                            "dst_ip": "45.33.49.113",
                            "dst_port": 443,
                            "hostname": denied_host,
                            "service": "ssl",
                            "action": "deny",
                            "user_agent": "FixtureBeacon/1.0",
                            "interval": "5m",
                            "count": 1,
                            "jitter": 0.0,
                        }
                    ],
                ),
            ],
            output=OutputSpec(
                logs=[{"format": "proxy_access"}, {"format": "zeek"}, {"format": "cisco_asa"}],
                destination="./output",
            ),
        )

        GenerationEngine(scenario, tmp_path).generate()

        proxy_lines = _read_proxy_lines(tmp_path)
        zeek_conn = _read_zeek_conn_records(tmp_path)
        asa_lines = _read_asa_lines(tmp_path)

        allowed_proxy_lines = [line for line in proxy_lines if allowed_host in line]
        denied_proxy_lines = [line for line in proxy_lines if denied_host in line]
        assert any(" CONNECT " in line and " 200 " in line for line in allowed_proxy_lines)
        assert any(
            f" GET https://{allowed_host}/v1/checkin HTTP/1.1 200 " in line
            for line in allowed_proxy_lines
        )
        assert any(" CONNECT " in line and " 403 " in line for line in denied_proxy_lines)

        assert any(
            record["id.orig_h"] == "10.0.10.10"
            and record["id.resp_h"] == "10.0.20.10"
            and record["id.resp_p"] == 8080
            for record in zeek_conn
        )
        assert any(
            record["id.orig_h"] == "10.0.20.10"
            and record["id.resp_h"] == "45.33.49.112"
            and record["id.resp_p"] == 443
            for record in zeek_conn
        )
        assert not any(
            record["id.orig_h"] == "10.0.20.10"
            and record["id.resp_h"] == "45.33.49.113"
            and record["id.resp_p"] == 443
            for record in zeek_conn
        )

        assert asa_lines
        assert any("45.33.49.112" in line for line in asa_lines)
        assert not any("45.33.49.113" in line for line in asa_lines)
