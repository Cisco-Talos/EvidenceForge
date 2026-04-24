# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Integration coverage for storyline events routed through explicit proxy."""

from datetime import UTC, datetime
from pathlib import Path

from evidenceforge.generation.engine import GenerationEngine
from evidenceforge.models.scenario import (
    BaselineActivity,
    Environment,
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


class TestStorylineBeaconExplicitProxy:
    def test_allowed_http_beacon_to_documentation_ip_appears_in_proxy_access(self, tmp_path):
        """Storyline beacons with external hostnames should route through explicit proxy."""
        scenario = Scenario(
            version="1.0",
            name="beacon-proxy-repro",
            description="Repro for beacon events not appearing in proxy_access.log",
            environment=Environment(
                description="Repro environment",
                proxy=ProxyConfig(mode="explicit", listener_port=3128),
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
                        services=["squid"],
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
