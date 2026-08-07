# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""End-to-end coverage for typed canonical IDS attachments."""

import json
from datetime import UTC, datetime

from evidenceforge.evaluation.engine import EvaluationEngine
from evidenceforge.generation.engine import GenerationEngine
from evidenceforge.models.scenario import (
    BaselineActivity,
    Environment,
    NetworkConfig,
    NetworkSegment,
    NetworkSensor,
    OutputSpec,
    Scenario,
    StorylineEvent,
    System,
    TimeWindow,
    User,
)


def test_beacon_ids_policy_output_and_reporting_are_consistent(tmp_path) -> None:
    scenario = Scenario(
        version="1.0",
        name="ids-beacon-integration",
        description="Canonical IDS beacon attachment",
        environment=Environment(
            description="test",
            users=[
                User(
                    username="alice",
                    full_name="Alice",
                    email="alice@example.test",
                    primary_system="ws01",
                )
            ],
            systems=[System(hostname="ws01", ip="10.0.0.8", os="Windows 11", type="workstation")],
            network=NetworkConfig(
                segments=[
                    NetworkSegment(
                        name="workstations",
                        cidr="10.0.0.0/24",
                        exposure="internal",
                        systems=["ws01"],
                    )
                ],
                sensors=[
                    NetworkSensor(
                        type="ids",
                        name="ids01",
                        hostname="ids01",
                        monitoring_segments=["workstations"],
                        direction="bidirectional",
                        placement="span",
                        log_formats=["snort_alert"],
                    )
                ],
            ),
        ),
        time_window=TimeWindow(start=datetime(2026, 8, 3, tzinfo=UTC), duration="10m"),
        baseline_activity=BaselineActivity(description="minimal", intensity="low", variation="low"),
        storyline=[
            StorylineEvent(
                id="beacon-ids",
                time="+1m",
                actor="alice",
                system="ws01",
                activity="three signature-matching callbacks",
                events=[
                    {
                        "type": "beacon",
                        "dst_ip": "45.83.221.30",
                        "dst_port": 443,
                        "service": "ssl",
                        "interval": "1s",
                        "count": 3,
                        "jitter": 0,
                        "ids_alerts": [
                            {
                                "sid": 2028401,
                                "policy": {
                                    "event_filter": {
                                        "type": "threshold",
                                        "track": "by_src",
                                        "count": 2,
                                        "seconds": 60,
                                    }
                                },
                            }
                        ],
                    }
                ],
            )
        ],
        output=OutputSpec(logs=[{"format": "snort_alert"}], destination="./output"),
    )

    GenerationEngine(scenario, tmp_path).generate()

    alert_lines = [
        line
        for path in tmp_path.rglob("snort_alert.log")
        for line in path.read_text(encoding="utf-8").splitlines()
        if "[1:2028401:1]" in line
    ]
    assert len(alert_lines) == 1

    ground_truth = json.loads((tmp_path / "GROUND_TRUTH.json").read_text(encoding="utf-8"))
    beacon = next(event for event in ground_truth["events"] if event["kind"] == "beacon")
    totals = beacon["attributes"]["ids_alerts"][0]
    assert totals["candidate"] == 3
    assert totals["emitted"] == 1
    assert totals["policy_filtered"] == 2
    assert totals["candidate"] == totals["emitted"] + totals["policy_filtered"]
    ids_evaluation = ground_truth["ids_evaluation"]
    sensor_summary = ids_evaluation["sensors"]["ids01"]["1:2028401"]
    assert sensor_summary["candidate"] == 3
    assert sensor_summary["emitted"] == 1
    assert sensor_summary["policy_filtered"] == 2
    assert sensor_summary["origins"] == {"authored_attachment": 1}
    assert len(sensor_summary["emitted_sha256"]) == 64
    markdown = (tmp_path / "GROUND_TRUTH.md").read_text(encoding="utf-8")
    assert "SID 2028401" in markdown
    assert "candidates=3 emitted=1 filtered=2" in markdown
    assert "## IDS Evaluation Summary" in markdown
    assert sensor_summary["emitted_sha256"][:12] in markdown

    manifest = json.loads((tmp_path / "OBSERVATION_MANIFEST.json").read_text(encoding="utf-8"))
    storyline = next(
        step for step in manifest["storyline_events"] if step["storyline_id"] == "beacon-ids"
    )
    ids_status = storyline["source_status"]["ids"]
    assert ids_status["filtered"] == 2
    assert ids_status.get("visible", 0) + ids_status.get("delayed", 0) == 1

    report = EvaluationEngine(output_dir=tmp_path, scenario=scenario).run()
    ids_score = next(
        score
        for pillar in report.pillars
        for score in pillar.sub_scores
        if score.key == "ids_integrity"
    )
    assert ids_score.score == 100.0
    assert report.generated_at == datetime.fromisoformat(ground_truth["generated_at"])


def test_transport_owner_ids_attachments_emit_and_report_only_owned_transports(tmp_path) -> None:
    systems = [
        System(hostname="ws01", ip="10.0.0.8", os="Windows 11", type="workstation"),
        System(
            hostname="linux01",
            ip="10.0.0.20",
            os="Ubuntu 24.04",
            type="server",
            roles=["application_server"],
            services=["ssh"],
        ),
        System(
            hostname="rdp01",
            ip="10.0.0.30",
            os="Windows Server 2022",
            type="server",
            services=["rdp"],
        ),
        System(
            hostname="dc01",
            ip="10.0.0.65",
            os="Windows Server 2022",
            type="domain_controller",
            roles=["domain_controller", "dns_server", "dhcp_server"],
            services=["dns", "windows-dhcp-server"],
        ),
    ]
    attached = [{"sid": 2002911, "policy": "every"}]
    storyline_specs = [
        ("ssh", "linux01", {"type": "ssh_session", "source_ip": "10.0.0.8"}),
        ("rdp", "rdp01", {"type": "rdp_session", "source_ip": "10.0.0.8"}),
        ("dhcp", "ws01", {"type": "dhcp_lease"}),
        (
            "port-scan",
            "ws01",
            {
                "type": "port_scan",
                "target_ips": ["10.0.0.20"],
                "target_count": 1,
                "ports": [22],
                "scan_rate": 10,
            },
        ),
        (
            "dns",
            "ws01",
            {"type": "dns_query", "query": "missing.example.test", "rcode": "NXDOMAIN"},
        ),
        (
            "web-scan",
            "ws01",
            {
                "type": "web_scan",
                "dst_ip": "10.0.0.20",
                "dst_port": 80,
                "paths": [{"uri": "/admin", "method": "GET", "status": 404}],
                "rate": 1,
                "count": 1,
            },
        ),
        (
            "dga",
            "ws01",
            {
                "type": "dga_queries",
                "interval": "1s",
                "count": 2,
                "rcode_distribution": {"NXDOMAIN": 1.0},
            },
        ),
        (
            "tunnel",
            "ws01",
            {
                "type": "dns_tunnel",
                "base_domain": "tunnel.example.test",
                "payload": "owned transport",
                "interval": "1s",
                "count": 2,
            },
        ),
    ]
    storyline = []
    for minute, (event_id, hostname, event_spec) in enumerate(storyline_specs, start=1):
        storyline.append(
            StorylineEvent(
                id=event_id,
                time=f"+{minute}m",
                actor="alice",
                system=hostname,
                activity=event_id,
                events=[{**event_spec, "ids_alerts": attached}],
            )
        )
    scenario = Scenario(
        version="1.0",
        name="ids-transport-owners",
        description="Canonical IDS transport-owner attachments",
        environment=Environment(
            description="test",
            users=[
                User(
                    username="alice",
                    full_name="Alice",
                    email="alice@example.test",
                    primary_system="ws01",
                )
            ],
            systems=systems,
            network=NetworkConfig(
                segments=[
                    NetworkSegment(
                        name="clients",
                        cidr="10.0.0.0/28",
                        exposure="internal",
                        systems=["ws01"],
                    ),
                    NetworkSegment(
                        name="servers",
                        cidr="10.0.0.16/27",
                        exposure="internal",
                        systems=["linux01", "rdp01"],
                    ),
                    NetworkSegment(
                        name="infra",
                        cidr="10.0.0.64/26",
                        exposure="internal",
                        systems=["dc01"],
                    ),
                ],
                sensors=[
                    NetworkSensor(
                        type="ids",
                        name="ids01",
                        hostname="ids01",
                        monitoring_segments=["clients", "servers", "infra"],
                        direction="bidirectional",
                        placement="span",
                        log_formats=["snort_alert"],
                    )
                ],
            ),
        ),
        time_window=TimeWindow(start=datetime(2026, 8, 3, tzinfo=UTC), duration="1h", warmup=None),
        baseline_activity=BaselineActivity(description="minimal", intensity="low", variation="low"),
        storyline=storyline,
        output=OutputSpec(logs=[{"format": "snort_alert"}], destination="./output"),
        observation_profile="complete",
    )

    GenerationEngine(scenario, tmp_path).generate()

    ground_truth = json.loads((tmp_path / "GROUND_TRUTH.json").read_text(encoding="utf-8"))
    attached_events = {
        event["kind"]: event["attributes"]["ids_alerts"][0]
        for event in ground_truth["events"]
        if event["attributes"].get("ids_alerts")
    }
    expected_kinds = {
        "ssh_session",
        "rdp_session",
        "dhcp_lease",
        "port_scan",
        "dns_query",
        "web_scan",
        "dga_queries",
        "dns_tunnel",
    }
    assert attached_events.keys() == expected_kinds
    incompatible_kinds = {
        "rdp_session",
        "dhcp_lease",
        "dns_query",
        "web_scan",
        "dga_queries",
        "dns_tunnel",
    }
    zero_candidate_kinds = {
        kind for kind, totals in attached_events.items() if totals["candidate"] == 0
    }
    assert zero_candidate_kinds == incompatible_kinds
    assert all(
        totals["candidate"] == totals["emitted"]
        for kind, totals in attached_events.items()
        if kind not in incompatible_kinds
    )
    assert all(totals["policy_filtered"] == 0 for totals in attached_events.values())

    alert_lines = [
        line
        for path in tmp_path.rglob("snort_alert.log")
        for line in path.read_text(encoding="utf-8").splitlines()
        if "[1:2002911:7]" in line
    ]
    assert len(alert_lines) == sum(totals["emitted"] for totals in attached_events.values())
