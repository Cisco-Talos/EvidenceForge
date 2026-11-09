# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Mixed-fleet authored referrers agree at the server and observed network sensor."""

import json
from pathlib import Path

import pytest
import yaml

from evidenceforge.generation.engine import GenerationEngine
from evidenceforge.models.scenario import Scenario


@pytest.mark.slow
def test_mixed_fleet_referrers_preserve_actor_platform_and_server_source_ownership(
    tmp_path: Path,
) -> None:
    data = yaml.safe_load(Path("scenarios/macos-workstation-example/mixed-fleet.yaml").read_text())
    data["generation_seed"] = 279
    data["time_window"]["duration"] = "1h"
    environment = data["environment"]
    environment["systems"].append(
        {
            "hostname": "WEB-01",
            "ip": "192.0.2.40",
            "os": "Ubuntu 24.04",
            "type": "server",
            "roles": ["web_server"],
            "services": ["http"],
        }
    )
    environment["network"]["segments"][0]["systems"].append("WEB-01")
    data["output"]["logs"] = [{"format": "web_access"}, {"format": "zeek"}]
    actors = [
        ("MAC-01", "alex", "Macintosh"),
        ("WIN-01", "robin", "Windows"),
        ("LINUX-01", "sam", "Linux"),
    ]
    data["storyline"] = []
    for index, (hostname, username, _presentation) in enumerate(actors):
        for offset, kind in enumerate(("spillage", "adversarial_payload")):
            spec = {"type": kind, "surface": "http_referrer", "scheme": "http"}
            if kind == "spillage":
                spec["family"] = "jwt"
            else:
                spec["value"] = f"EFORGE_TEST_referrer_{index}"
            occurrence = f"referrer-{index}-{offset}"
            data["storyline"].append(
                {
                    "id": occurrence,
                    "time": f"+{10 + 5 * index + offset}m",
                    "actor": username,
                    "system": hostname,
                    "activity": "Independently invented HTTP referrer exposure",
                    "events": [spec],
                }
            )
    output = tmp_path / "bundle"
    GenerationEngine(Scenario.model_validate(data), output).generate()
    truth = json.loads((output / "GROUND_TRUTH.json").read_text())
    exposures = [
        entry for entry in truth["events"] if entry["kind"] in {"spillage", "adversarial_payload"}
    ]
    assert len(exposures) == 6
    servers = list(output.rglob("web_access.log"))
    assert servers and all(path.parent.name.startswith("WEB-01.") for path in servers)
    server_lines = [line for path in servers for line in path.read_text().splitlines()]
    wire_paths = list(output.rglob("*http*.json"))
    assert wire_paths and all(path.parent.name == "core-zeek" for path in wire_paths)
    wire = [json.loads(line) for path in wire_paths for line in path.read_text().splitlines()]
    addresses = {item["hostname"]: item["ip"] for item in environment["systems"]}
    for exposure in exposures:
        value = exposure["attributes"]["rendered_value"]
        lines = [line for line in server_lines if value in line]
        records = [row for row in wire if value in row.get("referrer", "")]
        assert len(lines) == len(records) == 1
        user_agent = lines[0].rsplit('"', 2)[1]
        hostname = exposure["system"]
        presentation = next(item[2] for item in actors if item[0] == hostname)
        assert presentation in user_agent
        assert records[0]["user_agent"] == user_agent
        assert records[0]["id.orig_h"] == addresses[hostname]
        assert records[0]["id.resp_h"] == addresses["WEB-01"]
        assert lines[0].startswith(addresses[hostname] + " ")
