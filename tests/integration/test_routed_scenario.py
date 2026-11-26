"""Check routed evidence in the normal generation bundle."""

import json
from pathlib import Path

import pytest
import yaml
from typer.testing import CliRunner

from evidenceforge.cli.commands import app
from evidenceforge.composition.artifacts import verify_generation_bundle

FIXTURE = Path(__file__).resolve().parents[1] / "fixtures/scenarios/routed-two-site.yaml"


def _records(bundle: Path, sensor: str, family: str) -> list[dict]:
    path = bundle / "data" / sensor / f"{family}.json"
    return [json.loads(line) for line in path.read_text().splitlines()] if path.exists() else []


@pytest.mark.slow
def test_legacy_firewall_validation_warns_and_generation_still_emits_asa(tmp_path: Path) -> None:
    data = yaml.safe_load(FIXTURE.read_text())
    network = data["environment"]["network"]
    network.pop("routing")
    network["sensors"] = [sensor for sensor in network["sensors"] if sensor["type"] == "firewall"]
    data["output"]["logs"] = [{"format": "cisco_asa"}]
    storyline = data["storyline"][0]
    storyline["events"] = [
        event for event in storyline["events"] if event.get("uri") == "/internet"
    ]
    scenario = tmp_path / "legacy-firewall.yaml"
    scenario.write_text(yaml.safe_dump(data))
    runner = CliRunner()

    validation = runner.invoke(app, ["validate", str(scenario), "--json", "--no-record"])
    assert validation.exit_code == 0, validation.output
    report = json.loads(validation.stdout)
    assert report["valid"] is True
    assert report["status"] == "valid_with_warnings"
    routing = [
        issue for issue in report["issues"] if issue["field_path"] == "environment.network.routing"
    ]
    assert len(routing) == 1
    assert routing[0]["severity"] == "warning"
    assert "edge-asa" in routing[0]["message"]
    assert "authored routing" in routing[0]["suggestion"]

    bundle = tmp_path / "bundle"
    generation = runner.invoke(
        app, ["generate", str(scenario), "--output", str(bundle), "--seed", "17"]
    )
    assert generation.exit_code == 0, generation.output
    verify_generation_bundle(bundle)
    asa = (bundle / "data/edge/cisco_asa.log").read_text()
    assert any("%ASA-6-302013" in line and "198.51.100.30" in line for line in asa.splitlines())


@pytest.mark.slow
@pytest.mark.parametrize("intersite_kind", [None, "wan", "vpn"], ids=["network", "wan", "vpn"])
def test_routed_bundle_enforces_delivery_and_projects_native_sensor_tuples(
    tmp_path: Path, intersite_kind: str | None
) -> None:
    data = yaml.safe_load(FIXTURE.read_text())
    network = data["environment"]["network"]
    if intersite_kind is not None:
        network["routing"]["links"]["intersite"]["kind"] = intersite_kind
        network["sensors"] = [
            sensor for sensor in network["sensors"] if sensor["name"] != "zeek-wan"
        ]
    data["environment"]["systems"].append(
        {
            "hostname": "HQ-PEER",
            "ip": "10.40.10.11",
            "os": "Ubuntu 24.04",
            "type": "server",
        }
    )
    network["sensors"].extend(
        [
            {
                "type": "network",
                "name": "zeek-users-uplink",
                "placement": "tap",
                "link_tap": {"link": "users"},
            },
            {
                "type": "network",
                "name": "zeek-users-span",
                "placement": "span",
                "monitoring_segments": ["hq-clients"],
            },
            {
                "type": "network",
                "name": "zeek-edge-all",
                "placement": "tap",
                "link_tap": {"link": "edge-core"},
            },
            {
                "type": "network",
                "name": "zeek-plant",
                "placement": "span",
                "monitoring_segments": ["mfg-clients"],
            },
        ]
    )
    data["storyline"][0]["events"].append(
        {
            "type": "connection",
            "dst_ip": "10.40.10.11",
            "dst_port": 80,
            "method": "GET",
            "uri": "/lan-local",
        }
    )
    data["storyline"][0]["events"].append(
        {
            "type": "connection",
            "dst_ip": "192.0.2.2",
            "dst_port": 80,
            "method": "GET",
            "uri": "/internal-vip",
        }
    )
    scenario = tmp_path / "scenario.yaml"
    scenario.write_text(yaml.safe_dump(data))
    bundle = tmp_path / "bundle"
    result = CliRunner().invoke(
        app, ["generate", str(scenario), "--output", str(bundle), "--seed", "17"]
    )
    assert result.exit_code == 0, result.output
    verify_generation_bundle(bundle)

    inside_http = _records(bundle, "zeek-core", "http")
    outside_http = _records(bundle, "zeek-outside", "http")
    intersite_http = _records(
        bundle, "zeek-wan" if intersite_kind is None else "zeek-users-uplink", "http"
    )
    dmz_http = _records(bundle, "zeek-dmz", "http")
    before_nat = _records(bundle, "zeek-edge-all", "http")
    assert (
        next(event for event in before_nat if event["uri"] == "/internal-vip")["id.resp_h"]
        == "192.0.2.2"
    )
    assert (
        next(event for event in dmz_http if event["uri"] == "/internal-vip")["id.resp_h"]
        == "10.40.60.10"
    )
    assert all(event["uri"] != "/internal-vip" for event in inside_http + outside_http)
    uplink_http = {record["uri"] for record in _records(bundle, "zeek-users-uplink", "http")}
    span_http = {record["uri"] for record in _records(bundle, "zeek-users-span", "http")}
    assert {"/lan-local", "/intersite"} <= span_http
    assert "/intersite" in uplink_http
    assert "/lan-local" not in uplink_http
    assert [event["uri"] for event in intersite_http if event["uri"] == "/intersite"] == [
        "/intersite"
    ]
    assert [
        event["uri"]
        for event in _records(bundle, "zeek-plant", "http")
        if event["uri"] == "/intersite"
    ] == ["/intersite"]
    assert {event["uri"] for event in inside_http}.isdisjoint({"/intersite", "/dmz"})
    assert (
        next(event for event in inside_http if event["uri"] == "/internet")["id.orig_h"]
        == "10.40.10.10"
    )
    assert (
        next(event for event in outside_http if event["uri"] == "/internet")["id.orig_h"]
        == "192.0.2.1"
    )
    assert (
        next(event for event in outside_http if event["uri"] == "/dmz")["id.resp_h"] == "192.0.2.2"
    )
    assert next(event for event in dmz_http if event["uri"] == "/dmz")["id.resp_h"] == "10.40.60.10"

    inside = _records(bundle, "zeek-core", "conn")
    outside = _records(bundle, "zeek-outside", "conn")
    with (bundle / "GROUND_TRUTH_EVENTS.jsonl").open() as stream:
        internet_truth = next(
            row
            for row in map(json.loads, stream)
            if row["facts"].get("http", {}).get("uri") == "/internet"
        )
    observed_ports: dict[str, int] = {}
    for sensor, http_rows, connections in (
        ("zeek-core", inside_http, inside),
        ("zeek-outside", outside_http, outside),
    ):
        uid = next(row["uid"] for row in http_rows if row["uri"] == "/internet")
        connection = next(row for row in connections if row["uid"] == uid)
        expectation = next(
            item
            for item in internet_truth["source_expectations"]
            if item["source_host"] == sensor and item["format"] == "zeek_conn"
        )
        required = expectation["requirements"][0]["required"]
        observed_ports[sensor] = connection["id.orig_p"]
        assert (required["id.orig_p"], required["id.resp_p"]) == (
            connection["id.orig_p"],
            connection["id.resp_p"],
        )
    assert observed_ports["zeek-core"] != observed_ports["zeek-outside"]

    for source, dest, crosses, blocked_at in (
        ("10.40.10.10", "198.51.100.30", inside, outside),
        ("198.51.100.30", "10.40.10.10", outside, inside),
    ):

        def match(flow: dict, source: str = source, dest: str = dest) -> bool:
            return (flow["id.orig_h"], flow["id.resp_h"], flow["id.resp_p"]) == (source, dest, 8080)

        assert any(
            match(flow) and flow["conn_state"] == "S0" and flow["resp_pkts"] == 0
            for flow in crosses
        )
        assert not any(match(flow) for flow in blocked_at)
    assert not {"outbound-denied", "inbound-denied"} & {
        event["uri"].removeprefix("/") for event in inside_http + outside_http + dmz_http
    }
    asa = (bundle / "data/edge/cisco_asa.log").read_text()
    assert (
        sum("%ASA-4-106023" in line and "198.51.100.30" in line for line in asa.splitlines()) == 2
    )
