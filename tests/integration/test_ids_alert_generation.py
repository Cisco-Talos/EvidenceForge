# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""End-to-end coverage for typed canonical IDS attachments."""

import json
from datetime import UTC, datetime

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
                        placement="tap",
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
    markdown = (tmp_path / "GROUND_TRUTH.md").read_text(encoding="utf-8")
    assert "SID 2028401" in markdown
    assert "candidates=3 emitted=1 filtered=2" in markdown

    manifest = json.loads((tmp_path / "OBSERVATION_MANIFEST.json").read_text(encoding="utf-8"))
    storyline = next(
        step for step in manifest["storyline_events"] if step["storyline_id"] == "beacon-ids"
    )
    ids_status = storyline["source_status"]["ids"]
    assert ids_status["filtered"] == 2
    assert ids_status.get("visible", 0) + ids_status.get("delayed", 0) == 1
