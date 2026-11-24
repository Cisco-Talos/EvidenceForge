"""Authored topology, reachability, and link TAP contracts."""

from pathlib import Path

import pytest
import yaml
from pydantic import ValidationError

from evidenceforge.composition import compile_scenario
from evidenceforge.composition.artifacts import write_resolved_scenario
from evidenceforge.generation.network_visibility import NetworkVisibilityEngine
from evidenceforge.models.routing import RoutingLink
from evidenceforge.models.scenario import NetworkConfig
from evidenceforge.studio.topology import project_topology
from evidenceforge.validation.schema import ScenarioValidator

FIXTURE = Path(__file__).resolve().parents[1] / "fixtures/scenarios/routed-two-site.yaml"
HQ = "10.40.10.10"
MFG = "10.50.10.10"
DMZ = "10.40.60.10"
INTERNET = "198.51.100.30"


def _network() -> dict:
    return yaml.safe_load(FIXTURE.read_text())["environment"]["network"]


def _observers(visibility: NetworkVisibilityEngine, source: str, destination: str) -> set[str]:
    return {sensor.name for sensor in visibility.get_observing_sensors(source, destination, 80)}


@pytest.mark.parametrize("routed", [False, True])
def test_pack_firewall_routing_warning_is_advisory(tmp_path: Path, routed: bool) -> None:
    import json

    from typer.testing import CliRunner

    from evidenceforge.artifacts.properties import check_artifact
    from evidenceforge.cli.commands import app
    from evidenceforge.composition.packs import PackRepository
    from evidenceforge.studio.pack_lifecycle import review_pack

    environment = yaml.safe_load(FIXTURE.read_text())["environment"]
    network = environment["network"]
    if not routed:
        network.pop("routing")
        network["sensors"] = [
            sensor for sensor in network["sensors"] if sensor["type"] == "firewall"
        ]
    pack = PackRepository(tmp_path).create_skeleton(
        "organization",
        "firewall-office",
        "1.0.0",
        publisher="training",
        publisher_display_name="Training",
    )
    (pack / "model/environment.yaml").write_text(yaml.safe_dump({"environment": environment}))
    manifest = pack / "pack.yaml"
    result = CliRunner().invoke(
        app, ["pack", "validate", str(manifest), "--project-root", str(tmp_path), "--json"]
    )
    assert result.exit_code == 0, result.output
    payload = json.loads(result.stdout)
    assert payload["valid"] is True
    warnings = payload["warnings"]
    assert len(warnings) == (0 if routed else 1)
    if not routed:
        assert warnings[0]["severity"] == "warning"
        assert warnings[0]["field_path"] == "environment.network.routing"
        assert "authored routing" in warnings[0]["suggestion"]

    review = review_pack(manifest, tmp_path)
    assert review.valid
    assert review.model_dump(mode="json")["warnings"] == warnings
    checked = check_artifact(manifest, project_root=tmp_path)
    assert checked["valid"]
    assert checked["findings"] == warnings
    assert checked["validated_with"]["warnings"] == len(warnings)


def test_ordinary_link_kind_defaults_and_keeps_its_serialized_shape() -> None:
    payload = _network()["routing"]["links"]["intersite"]
    implicit = RoutingLink.model_validate(payload)
    explicit = RoutingLink.model_validate({**payload, "kind": "network"})
    assert implicit == explicit
    assert implicit.kind == "network"
    assert implicit.model_dump(mode="json") == explicit.model_dump(mode="json")
    assert "kind" not in implicit.model_dump(mode="json")
    with pytest.raises(ValidationError, match="kind"):
        RoutingLink.model_validate({**payload, "kind": "wireless"})


@pytest.mark.parametrize("kind", ["wan", "vpn"])
@pytest.mark.parametrize(
    "placement",
    [
        {"placement": "tap", "link_tap": {"link": "intersite"}},
        {"placement": "tap", "monitoring_segments": ["hq-clients", "site-transit"]},
        {"placement": "span", "monitoring_segments": ["hq-clients", "site-transit"]},
    ],
    ids=["link-tap", "segment-tap", "span"],
)
@pytest.mark.parametrize("sensor_type", ["network", "ids"])
def test_wan_and_vpn_reject_direct_capture(kind: str, placement: dict, sensor_type: str) -> None:
    payload = _network()
    payload["routing"]["links"]["intersite"]["kind"] = kind
    payload["sensors"] = [sensor for sensor in payload["sensors"] if sensor["name"] != "zeek-wan"]
    payload["sensors"].append({"type": sensor_type, "name": "transit-sensor", **placement})

    with pytest.raises(
        ValidationError,
        match=rf"Sensor 'transit-sensor' cannot monitor {kind.upper()} link 'intersite'",
    ):
        NetworkConfig.model_validate(payload)


@pytest.mark.parametrize("kind", ["wan", "vpn"])
def test_wan_and_vpn_keep_capture_on_both_termination_sides(kind: str) -> None:
    systems = compile_scenario(FIXTURE).scenario.environment.systems
    payload = _network()
    payload["routing"]["links"]["intersite"]["kind"] = kind
    firewall = payload["sensors"][0]
    firewall["monitoring_segments"].append("site-transit")
    firewall["interfaces"]["site-transit"] = "wan-scope"
    payload["sensors"] = [sensor for sensor in payload["sensors"] if sensor["name"] != "zeek-wan"]
    payload["sensors"].extend(
        [
            {
                "type": "network",
                "name": "hq-tap",
                "placement": "tap",
                "link_tap": {"link": "users"},
            },
            {
                "type": "network",
                "name": "mfg-span",
                "placement": "span",
                "monitoring_segments": ["mfg-clients"],
            },
        ]
    )
    visibility = NetworkVisibilityEngine(NetworkConfig.model_validate(payload), systems)
    for source, destination in ((HQ, MFG), (MFG, HQ)):
        flow = visibility.routed_connection(source, destination, 80)
        assert flow is not None and flow.reachable
        assert "intersite" in {hop.link for hop in flow.forward.hops}
        assert _observers(visibility, source, destination) == {"hq-tap", "mfg-span"}


@pytest.fixture
def visibility() -> NetworkVisibilityEngine:
    environment = compile_scenario(FIXTURE).scenario.environment
    return NetworkVisibilityEngine(environment.network, environment.systems)


def test_access_uplink_tap_only_sees_unicast_that_crosses_the_attachment() -> None:
    payload = _network()
    payload["routing"]["gateways"].pop("hq-clients")
    payload["sensors"].extend(
        [
            {
                "type": "network",
                "name": "lan-tap",
                "placement": "tap",
                "link_tap": {"link": "users"},
            },
            {
                "type": "network",
                "name": "lan-span",
                "placement": "span",
                "monitoring_segments": ["hq-clients"],
            },
        ]
    )
    systems = compile_scenario(FIXTURE).scenario.environment.systems
    visibility = NetworkVisibilityEngine(NetworkConfig.model_validate(payload), systems)
    peer = "10.40.10.11"
    gateway = "10.40.10.1"

    local = visibility.routed_connection(HQ, peer, 80)
    assert local and local.reachable
    assert not local.forward.hops and not local.reverse.hops
    assert _observers(visibility, HQ, peer) == {"lan-span"}
    assert _observers(visibility, peer, HQ) == {"lan-span"}
    assert {sensor.name for sensor in visibility.get_link_local_sensors(HQ)} == {"lan-span"}

    attached = visibility.routed_connection(HQ, gateway, 80)
    assert attached and attached.reachable
    assert [hop.link for hop in attached.forward.hops] == ["users"]
    assert _observers(visibility, HQ, gateway) == {"lan-tap", "lan-span"}
    assert _observers(visibility, gateway, HQ) == {"lan-tap", "lan-span"}

    unreachable = visibility.routed_connection(HQ, MFG, 80)
    assert unreachable and not unreachable.reachable
    assert unreachable.forward.reason == "segment hq-clients has no gateway"
    assert not unreachable.forward.hops
    assert not _observers(visibility, HQ, MFG)
    assert not _observers(visibility, HQ, HQ)


def test_routing_loop_stops_before_unvisited_links_and_does_not_report_a_deny() -> None:
    payload = _network()
    payload["routing"]["routes"]["MFG-CORE"].append(
        {"destination": f"{MFG}/32", "next_hop": "10.60.0.1"}
    )
    systems = compile_scenario(FIXTURE).scenario.environment.systems
    visibility = NetworkVisibilityEngine(NetworkConfig.model_validate(payload), systems)

    flow = visibility.routed_connection(HQ, MFG, 80)
    assert flow and not flow.reachable and flow.denied_by is None
    assert flow.forward.reason == "routing loop at HQ-CORE"
    assert [(hop.link, hop.forwarder) for hop in flow.forward.hops] == [
        ("users", None),
        ("intersite", "HQ-CORE"),
        ("intersite", "MFG-CORE"),
    ]
    assert not flow.reverse.hops
    assert _observers(visibility, HQ, MFG) == {"zeek-wan"}


@pytest.mark.parametrize("has_boundary", [False, True])
def test_internet_tap_uses_authored_boundary_instead_of_address_appearance(
    has_boundary: bool,
) -> None:
    payload = _network()
    # A public-looking documented LAN address is internal. An off-topology
    # private-looking address is beyond a declared Internet boundary in this model.
    payload["segments"].append(
        {"name": "public-lan", "cidr": "203.0.113.0/24", "exposure": "external"}
    )
    payload["routing"]["links"]["public-lan"] = {
        "segment": "public-lan",
        "interfaces": {"EDGE": {"name": "service", "ip": "203.0.113.1"}},
    }
    payload["routing"]["gateways"]["public-lan"] = "EDGE"
    if not has_boundary:
        del payload["routing"]["links"]["upstream"]
        payload["routing"]["routes"]["EDGE"].pop()
        payload["sensors"] = [
            sensor for sensor in payload["sensors"] if sensor["name"] != "zeek-outside"
        ]
    systems = compile_scenario(FIXTURE).scenario.environment.systems
    visibility = NetworkVisibilityEngine(NetworkConfig.model_validate(payload), systems)

    internal = visibility.routed_connection(HQ, "203.0.113.10", 80)
    assert internal and internal.reachable
    assert [hop.link for hop in internal.forward.hops] == ["users", "edge-core", "public-lan"]
    assert _observers(visibility, HQ, "203.0.113.10") == {"edge-asa"}
    off_topology = visibility.routed_connection(HQ, "172.24.5.10", 80)
    assert off_topology and off_topology.reachable is has_boundary
    assert ("zeek-core" in _observers(visibility, HQ, "172.24.5.10")) is has_boundary
    external_pair = visibility.routed_connection(INTERNET, "192.0.2.42", 80)
    assert external_pair and not external_pair.reachable and not external_pair.forward.hops
    assert not _observers(visibility, INTERNET, "192.0.2.42")


def test_most_specific_segment_drives_routed_span_policy_and_nat() -> None:
    payload = _network()
    payload["segments"].insert(
        0, {"name": "hq-summary", "cidr": "10.40.0.0/16", "exposure": "internal"}
    )
    payload["sensors"].extend(
        [
            {"type": "network", "name": "summary-span", "monitoring_segments": ["hq-summary"]},
            {"type": "network", "name": "client-span", "monitoring_segments": ["hq-clients"]},
        ]
    )
    payload["sensors"][0]["policy"] = [{"src": "hq-clients", "dst": "external", "action": "permit"}]
    systems = compile_scenario(FIXTURE).scenario.environment.systems
    visibility = NetworkVisibilityEngine(NetworkConfig.model_validate(payload), systems)

    assert _observers(visibility, HQ, "10.40.10.11") == {"client-span"}
    assert {sensor.name for sensor in visibility.get_link_local_sensors(HQ)} == {"client-span"}
    outbound = visibility.routed_connection(HQ, INTERNET, 80)
    assert outbound and outbound.reachable
    nat = visibility.compute_nat(HQ, INTERNET, 51000, 80)
    assert nat and nat.mapped_src_ip == "192.0.2.1"


@pytest.mark.parametrize("same_subnet", [False, True])
def test_static_vip_cannot_deliver_by_bypassing_the_translating_firewall(same_subnet: bool) -> None:
    payload = _network()
    real_ip = "10.40.10.11" if same_subnet else "10.40.20.10"
    vip = "192.0.2.3"
    payload["sensors"][0]["nat_rules"].append(
        {"type": "static", "real_ip": real_ip, "mapped_ip": vip}
    )
    payload["sensors"].extend(
        [
            {"type": "network", "name": "lan-span", "monitoring_segments": ["hq-clients"]},
            {
                "type": "network",
                "name": "lan-inbound",
                "monitoring_segments": ["hq-clients"],
                "direction": "inbound",
            },
        ]
    )
    systems = compile_scenario(FIXTURE).scenario.environment.systems
    visibility = NetworkVisibilityEngine(NetworkConfig.model_validate(payload), systems)

    assert visibility.routed_connection(HQ, real_ip, 80).reachable
    attempted = visibility.routed_connection(HQ, vip, 80)
    assert attempted and not attempted.reachable and attempted.denied_by is None
    assert [hop.link for hop in attempted.forward.hops] == ["users", "edge-core"]
    assert _observers(visibility, HQ, vip) == {"lan-span"}
    assert visibility.compute_nat(HQ, vip, 51000, 80) is None
    ingress = visibility.routed_connection(INTERNET, vip, 80)
    assert ingress and ingress.reachable
    nat = visibility.compute_nat(INTERNET, vip, 51000, 80)
    assert nat and nat.mapped_dst_ip == real_ip


@pytest.mark.parametrize("deny_at", ["hq-policy", "edge-asa"])
def test_first_enforcing_firewall_ends_the_observed_path(deny_at: str) -> None:
    payload = _network()
    payload["routing"]["devices"]["HQ-CORE"] = {"kind": "firewall", "firewall": "hq-policy"}
    # Put the upstream firewall last in the declaration order to exercise path order.
    payload["sensors"].append(
        {
            "name": "hq-policy",
            "hostname": "HQ-POLICY",
            "type": "firewall",
            "log_formats": ["cisco_asa"],
            "monitoring_segments": ["hq-clients", "edge-transit"],
            "interfaces": {"hq-clients": "shared-scope", "edge-transit": "shared-scope"},
            "default_action": "deny" if deny_at == "hq-policy" else "permit",
        }
    )
    systems = compile_scenario(FIXTURE).scenario.environment.systems
    visibility = NetworkVisibilityEngine(NetworkConfig.model_validate(payload), systems)

    flow = visibility.routed_connection(HQ, INTERNET, 22)
    assert flow and not flow.reachable and flow.denied_by.name == deny_at
    assert [hop.link for hop in flow.forward.hops] == (
        ["users"] if deny_at == "hq-policy" else ["users", "edge-core"]
    )
    assert {sensor.name for sensor in visibility.get_observing_sensors(HQ, INTERNET, 22)} == (
        {"hq-policy"}
        if deny_at == "hq-policy"
        else {"hq-policy", "edge-asa", "zeek-core", "ids-core"}
    )
    assert visibility.forwarding_interfaces("HQ-POLICY", HQ, INTERNET) == ("clients", "edge")
    assert visibility.compute_nat(HQ, INTERNET, 51000, 22) is None


@pytest.mark.parametrize(
    ("src", "dst", "port", "links", "observers", "reachable", "denied"),
    [
        (HQ, "10.40.20.10", 80, ["users", "servers"], set(), True, None),
        (HQ, MFG, 80, ["users", "intersite", "plant"], {"zeek-wan"}, True, None),
        (MFG, "10.50.90.1", 80, ["plant"], set(), True, None),
        (
            HQ,
            INTERNET,
            80,
            ["users", "edge-core", "upstream"],
            {"edge-asa", "zeek-core", "ids-core", "zeek-outside"},
            True,
            None,
        ),
        (
            HQ,
            INTERNET,
            22,
            ["users", "edge-core"],
            {"edge-asa", "zeek-core", "ids-core"},
            False,
            "edge-asa",
        ),
        (INTERNET, HQ, 22, ["upstream"], {"edge-asa", "zeek-outside"}, False, "edge-asa"),
        (
            INTERNET,
            "192.0.2.2",
            80,
            ["upstream", "dmz-uplink"],
            {"edge-asa", "zeek-dmz", "zeek-outside"},
            True,
            None,
        ),
    ],
)
def test_path_and_capture(
    visibility: NetworkVisibilityEngine,
    src: str,
    dst: str,
    port: int,
    links: list[str],
    observers: set[str],
    reachable: bool,
    denied: str | None,
) -> None:
    flow = visibility.routed_connection(src, dst, port)
    assert flow is not None
    assert flow.reachable is reachable
    assert [hop.link for hop in flow.forward.hops] == links
    assert (flow.denied_by.name if flow.denied_by else None) == denied
    assert {sensor.name for sensor in visibility.get_observing_sensors(src, dst, port)} == observers


def test_nat_is_visible_only_on_the_correct_side(visibility: NetworkVisibilityEngine) -> None:
    core = visibility.get_sensor("zeek-core")
    outside = visibility.get_sensor("zeek-outside")
    dmz = visibility.get_sensor("zeek-dmz")
    assert core and outside and dmz
    pat = visibility.compute_nat(HQ, INTERNET, 12345, 80)
    assert pat and pat.mapped_src_ip == "192.0.2.1"
    dnat = visibility.compute_nat(INTERNET, "192.0.2.2", 12345, 80)
    assert dnat and dnat.mapped_dst_ip == DMZ
    assert not visibility.tap_uses_external_tuple(core, HQ, INTERNET, pat)
    assert visibility.tap_uses_external_tuple(outside, HQ, INTERNET, pat)
    assert not visibility.tap_uses_external_tuple(dmz, INTERNET, "192.0.2.2", dnat)
    assert visibility.tap_uses_external_tuple(outside, INTERNET, "192.0.2.2", dnat)
    assert visibility.compute_nat(HQ, MFG, 12345, 80) is None


def test_internal_client_sees_the_vip_before_translation_on_the_dmz_path(
    visibility: NetworkVisibilityEngine,
) -> None:
    core = visibility.get_sensor("zeek-core")
    dmz = visibility.get_sensor("zeek-dmz")
    assert core and dmz
    vip = "192.0.2.2"
    flow = visibility.routed_connection(HQ, vip, 80)
    assert flow and flow.reachable
    assert [hop.link for hop in flow.forward.hops] == ["users", "edge-core", "dmz-uplink"]
    nat = visibility.compute_nat(HQ, vip, 12345, 80)
    assert nat and nat.mapped_dst_ip == DMZ
    assert visibility.tap_uses_external_tuple(core, HQ, vip, nat)
    assert not visibility.tap_uses_external_tuple(dmz, HQ, vip, nat)
    assert _observers(visibility, HQ, vip) == {"edge-asa", "zeek-dmz"}


@pytest.mark.parametrize("direction", ["forward", "return"])
def test_route_failure_is_a_warning_with_an_observable_prefix(
    tmp_path: Path, direction: str
) -> None:
    document = yaml.safe_load(FIXTURE.read_text())
    routing = document["environment"]["network"]["routing"]
    if direction == "forward":
        routing["routes"]["HQ-CORE"] = []
    else:
        routing["routes"]["MFG-CORE"] = []
    path = tmp_path / "scenario.yaml"
    path.write_text(yaml.safe_dump(document))
    scenario = compile_scenario(path).scenario
    issues = ScenarioValidator(scenario).validate()
    assert not [issue for issue in issues if issue.severity == "error"]
    notes = [issue for issue in issues if "unreachable in the authored topology" in issue.message]
    assert any(
        issue.field_path == "storyline.0.events.0" and issue.severity == "warning"
        for issue in notes
    )
    visibility = NetworkVisibilityEngine(scenario.environment.network, scenario.environment.systems)
    flow = visibility.routed_connection(HQ, MFG, 80)
    assert flow and not flow.reachable and flow.denied_by is None
    assert flow.forward.delivered is (direction == "return")
    assert {sensor.name for sensor in visibility.get_observing_sensors(HQ, MFG, 80)} == (
        {"zeek-wan"} if direction == "return" else set()
    )


@pytest.mark.parametrize(
    ("change", "message"),
    [
        ("link", "unique, known segment"),
        ("gateway", "must have an interface"),
        ("prefix", "ambiguous routes"),
        ("neighbor", "needs a neighbor"),
        ("family", "not on-link"),
        ("tap", "unknown link"),
        ("nonadjacent-next-hop", "not on-link"),
        ("missing-next-hop", "needs exactly one next hop"),
        ("two-next-hops", "needs exactly one next hop"),
        ("duplicate-ip", "duplicate interface"),
        ("duplicate-interface", "duplicate interface"),
        ("address-outside-segment", "outside segment"),
        ("second-internet", "Only one Internet boundary"),
        ("tap-with-span-placement", "requires tap placement and no segments"),
        ("tap-with-segments", "requires tap placement and no segments"),
        ("one-way-tap", "requires bidirectional capture"),
    ],
)
def test_invalid_cross_references_are_reported(change: str, message: str) -> None:
    scenario = compile_scenario(FIXTURE).scenario
    payload = _network()
    routing = payload["routing"]
    if change == "link":
        routing["links"]["intersite"]["segment"] = "missing"
    elif change == "gateway":
        routing["gateways"]["hq-clients"] = "MFG-CORE"
    elif change == "prefix":
        routing["routes"]["EDGE"].append(routing["routes"]["EDGE"][0])
    elif change == "neighbor":
        routing["routes"]["EDGE"][0]["next_hop"] = "10.99.99.1"
    elif change == "family":
        routing["routes"]["EDGE"][0]["destination"] = "::/0"
    elif change == "tap":
        payload["sensors"][2]["link_tap"]["link"] = "missing"
    elif change == "nonadjacent-next-hop":
        routing["routes"]["MFG-CORE"][0]["next_hop"] = "10.40.254.1"
    elif change == "missing-next-hop":
        routing["routes"]["EDGE"][0].pop("next_hop")
    elif change == "two-next-hops":
        routing["routes"]["EDGE"][0]["internet_link"] = "upstream"
    elif change == "duplicate-ip":
        routing["links"]["edge-core"]["interfaces"]["HQ-CORE"]["ip"] = "10.40.254.1"
    elif change == "duplicate-interface":
        routing["links"]["servers"]["interfaces"]["HQ-CORE"]["name"] = "clients"
    elif change == "address-outside-segment":
        routing["links"]["servers"]["interfaces"]["HQ-CORE"]["ip"] = "10.99.99.1"
    elif change == "second-internet":
        routing["links"]["backup-isp"] = {
            "internet": True,
            "interfaces": {"EDGE": {"ip": "192.0.2.42", "name": "backup"}},
        }
    elif change == "tap-with-span-placement":
        payload["sensors"][1]["placement"] = "span"
    elif change == "tap-with-segments":
        payload["sensors"][1]["monitoring_segments"] = ["edge-transit"]
    elif change == "one-way-tap":
        payload["sensors"][1]["direction"] = "outbound"
    scenario.environment.network = NetworkConfig.model_validate(payload)
    assert any(
        issue.field_path == "environment.network.routing"
        and issue.severity == "error"
        and message in issue.message
        for issue in ScenarioValidator(scenario).validate()
    )


def test_ipv6_static_routes_use_the_most_specific_prefix() -> None:
    config = NetworkConfig.model_validate(
        {
            "segments": [
                {"name": "office", "cidr": "fd00:1::/64", "exposure": "internal"},
                {"name": "wan", "cidr": "fd00:2::/64", "exposure": "internal"},
                {"name": "plant", "cidr": "fd00:3::/64", "exposure": "internal"},
            ],
            "sensors": [
                {"type": "network", "name": "v6-span", "monitoring_segments": ["office"]},
                {
                    "type": "network",
                    "name": "v6-uplink",
                    "placement": "tap",
                    "link_tap": {"link": "office"},
                },
                {
                    "type": "network",
                    "name": "v6-edge",
                    "placement": "tap",
                    "link_tap": {"link": "office", "scope": "internet"},
                },
            ],
            "routing": {
                "devices": {"hq": {}, "plant": {}},
                "links": {
                    "office": {
                        "segment": "office",
                        "interfaces": {"hq": {"name": "office", "ip": "fd00:1::1"}},
                    },
                    "wan": {
                        "segment": "wan",
                        "interfaces": {
                            "hq": {"name": "wan", "ip": "fd00:2::1"},
                            "plant": {"name": "wan", "ip": "fd00:2::2"},
                        },
                    },
                    "plant": {
                        "segment": "plant",
                        "interfaces": {"plant": {"name": "plant", "ip": "fd00:3::1"}},
                    },
                    "external": {
                        "internet": True,
                        "interfaces": {"hq": {"name": "external", "ip": "2001:db8::1"}},
                    },
                },
                "gateways": {"office": "hq", "plant": "plant"},
                "routes": {
                    "hq": [
                        {"destination": "::/0", "internet_link": "external"},
                        {"destination": "fd00:3::/64", "next_hop": "fd00:2::2"},
                    ],
                    "plant": [{"destination": "::/0", "next_hop": "fd00:2::1"}],
                },
            },
        }
    )
    visibility = NetworkVisibilityEngine(config, [])
    flow = visibility.routed_connection("fd00:1::10", "fd00:3::10", 80)
    assert flow and flow.reachable
    assert [hop.link for hop in flow.forward.hops] == ["office", "wan", "plant"]
    external = visibility.routed_connection("fd00:1::10", "2001:db8:1::10", 80)
    assert external and external.reachable
    assert [hop.link for hop in external.forward.hops] == ["office", "external"]
    assert _observers(visibility, "fd00:1::10", "fd00:1::11") == {"v6-span"}
    assert _observers(visibility, "fd00:1::10", "fd00:3::10") == {"v6-span", "v6-uplink"}
    assert _observers(visibility, "fd00:1::10", "2001:db8:1::10") == {
        "v6-span",
        "v6-uplink",
        "v6-edge",
    }
    mixed_family = visibility.routed_connection("fd00:1::10", INTERNET, 80)
    assert mixed_family and mixed_family.forward.reason == "address families differ"
    assert not _observers(visibility, "fd00:1::10", INTERNET)


def test_resolved_artifact_and_studio_retain_the_same_declared_links(tmp_path: Path) -> None:
    compiled = compile_scenario(FIXTURE)
    path = write_resolved_scenario(compiled, tmp_path)
    resolved = compile_scenario(path)
    assert compiled.scenario.environment.network == resolved.scenario.environment.network
    graph = project_topology(resolved.scenario.environment.model_dump(mode="json"))
    assert graph.routing is not None
    assert graph.routing.gateways["mfg-management"] == "MFG-CORE"
    assert str(graph.routing.links["management"].interfaces["MFG-CORE"].ip) == "10.50.90.1"
    assert graph.link_taps["device:zeek-core"].scope == "internet"


@pytest.mark.parametrize("missing_return", [False, True])
def test_unreachable_transport_has_no_http_response_or_destination_event(
    missing_return: bool, monkeypatch: pytest.MonkeyPatch
) -> None:
    from datetime import UTC, datetime, timedelta
    from unittest.mock import Mock

    from evidenceforge.events.contexts import HttpContext
    from evidenceforge.events.dispatcher import EventDispatcher
    from evidenceforge.generation.actions.network_connection import NetworkConnectionIdentityCapture
    from evidenceforge.generation.activity import ActivityGenerator
    from evidenceforge.generation.state_manager import StateManager

    environment = compile_scenario(FIXTURE).scenario.environment
    payload = _network()
    routes = payload["routing"]["routes"]
    routes["MFG-CORE" if missing_return else "HQ-CORE"] = []
    # Capture the source's subnet even when the first router cannot forward.
    payload["sensors"].append(
        {
            "name": "source-tap",
            "type": "network",
            "placement": "tap",
            "link_tap": {"link": "users"},
        }
    )
    visibility = NetworkVisibilityEngine(NetworkConfig.model_validate(payload), environment.systems)
    start = datetime(2026, 1, 12, 12, 0, tzinfo=UTC)
    state = StateManager()
    state.set_current_time(start)
    emitters = {name: Mock() for name in ("zeek_conn", "zeek_http", "ecar")}
    dispatcher = EventDispatcher(state, emitters, visibility_engine=visibility)
    routed = Mock(wraps=dispatcher._finalize_network_routing)
    monkeypatch.setattr(dispatcher, "_finalize_network_routing", routed)
    generator = ActivityGenerator(
        state,
        emitters,
        dispatcher=dispatcher,
        generation_window_start=start - timedelta(hours=1),
        generation_window_end=start + timedelta(hours=1),
    )
    source = next(system for system in environment.systems if system.ip == HQ)
    generator._ip_to_system = {system.ip: system for system in environment.systems}
    capture = NetworkConnectionIdentityCapture()
    generator.generate_connection(
        src_ip=HQ,
        dst_ip=MFG,
        dst_port=80,
        time=start,
        service="http",
        conn_state="SF",
        http=HttpContext(method="GET", uri="/must-not-arrive", host=MFG, status_code=200),
        identity_capture=capture,
        source_system=source,
        emit_dns=False,
        suppress_source_pid_inference=True,
    )
    root = capture.require_prepared_root()
    assert root.transaction.conn_state == "S0"
    assert root.transaction.traffic.resp.packets == 0
    assert root.result.http is None
    event = next(
        call.args[0] for call in routed.call_args_list if call.args[0].network.dst_ip == MFG
    )
    assert event.dst_host is None
    assert event.firewall is None


@pytest.mark.parametrize("kind", ["wan", "vpn"])
def test_routing_from_an_organization_pack_survives_composition(tmp_path: Path, kind: str) -> None:
    from evidenceforge.composition.packs import PackError, PackRepository
    from evidenceforge.studio.pack_lifecycle import inspect_pack_topology

    document = yaml.safe_load(FIXTURE.read_text())
    repository = PackRepository(tmp_path)
    pack = repository.create_skeleton(
        "organization",
        "routed-office",
        "1.0.0",
        publisher="training",
        publisher_display_name="Training",
    )
    environment = document.pop("environment")
    pack_model = pack / "model/environment.yaml"
    network = environment["network"]
    network["routing"]["links"]["intersite"]["kind"] = kind
    pack_model.write_text(yaml.safe_dump({"environment": environment}))
    with pytest.raises(PackError, match=f"cannot monitor {kind.upper()} link 'intersite'"):
        inspect_pack_topology(pack / "pack.yaml", tmp_path)
    network["sensors"] = [sensor for sensor in network["sensors"] if sensor["name"] != "zeek-wan"]
    pack_model.write_text(yaml.safe_dump({"environment": environment}))
    document["composition"] = {
        "organization": {
            "source": "project",
            "publisher": "training",
            "name": "routed-office",
            "version": "1.0.0",
        }
    }
    document["environment"] = {
        "network": {
            "routing": {
                "routes": {
                    "MFG-CORE": [{"destination": "0.0.0.0/0", "next_hop": "10.60.0.1"}],
                }
            }
        }
    }
    path = tmp_path / "scenario.yaml"
    path.write_text(yaml.safe_dump(document))

    pack_topology = inspect_pack_topology(pack / "pack.yaml", tmp_path).topology
    composed = compile_scenario(path, project_root=tmp_path)
    graph = project_topology(composed.scenario.environment.model_dump(mode="json"))
    assert graph.routing == pack_topology.routing
    assert graph.routing is not None
    assert graph.routing.links["intersite"].kind == kind
    assert graph.link_taps == pack_topology.link_taps
    assert not [
        issue
        for issue in ScenarioValidator(composed.scenario).validate()
        if issue.severity == "error"
    ]
    resolved = compile_scenario(write_resolved_scenario(composed, tmp_path)).scenario
    assert resolved.environment.network is not None
    assert resolved.environment.network.routing == graph.routing

    document["environment"]["network"]["routing"]["links"] = {"intersite": {"kind": "network"}}
    path.write_text(yaml.safe_dump(document))
    overridden = compile_scenario(path, project_root=tmp_path).scenario.environment.network
    assert overridden is not None and overridden.routing is not None
    assert overridden.routing.links["intersite"].kind == "network"


@pytest.mark.parametrize("return_delivered", [True, False])
def test_asymmetric_taps_only_report_the_packet_direction_they_seen(return_delivered: bool) -> None:
    from dataclasses import replace

    from evidenceforge.events.dispatcher import EventDispatcher
    from evidenceforge.events.network import NetworkTrafficLedger
    from evidenceforge.generation.network_observation import NetworkObservationPlanner
    from evidenceforge.generation.state_manager import StateManager
    from tests.unit.test_network_observation import _network_event

    payload = _network()
    payload["segments"].append(
        {"name": "return-transit", "cidr": "10.61.0.0/30", "exposure": "internal"}
    )
    routing = payload["routing"]
    routing["links"]["return"] = {
        "segment": "return-transit",
        "interfaces": {
            "HQ-CORE": {"name": "wan2", "ip": "10.61.0.1"},
            "MFG-CORE": {"name": "wan2", "ip": "10.61.0.2"},
        },
    }
    routing["routes"]["MFG-CORE"] = [{"destination": "0.0.0.0/0", "next_hop": "10.61.0.1"}]
    if not return_delivered:
        routing["routes"]["HQ-CORE"].append({"destination": f"{HQ}/32", "next_hop": "10.61.0.2"})
    payload["sensors"].append(
        {
            "name": "reverse-tap",
            "type": "network",
            "placement": "tap",
            "link_tap": {"link": "return"},
        }
    )
    systems = compile_scenario(FIXTURE).scenario.environment.systems
    visibility = NetworkVisibilityEngine(NetworkConfig.model_validate(payload), systems)
    flow = visibility.routed_connection(HQ, MFG, 53)
    assert flow and flow.reachable is return_delivered
    assert flow.forward.delivered
    assert [hop.link for hop in flow.reverse.hops][:2] == ["plant", "return"]
    sensors = visibility.get_observing_sensors(HQ, MFG, 53)
    if not return_delivered:
        assert flow.reverse.reason == "routing loop at MFG-CORE"
        assert {sensor.name for sensor in sensors} == {"zeek-wan"}
        return
    event = _network_event(protocol="tcp")
    event.network = replace(event.network, src_ip=HQ, dst_ip=MFG)
    formats = {"zeek_conn", "zeek_dns"}
    assert {sensor.name for sensor in sensors} == {"zeek-wan", "reverse-tap"}
    event._sensor_hostnames_by_format = {
        name: [sensor.name for sensor in sensors] for name in formats
    }
    observations = {
        item.sensor_identity: item
        for item in NetworkObservationPlanner(visibility).plan(event, formats)
    }
    assert 0 < observations["zeek-wan"].traffic.orig.packets <= 12
    assert observations["zeek-wan"].traffic.resp.packets == 0
    assert observations["reverse-tap"].traffic.orig.packets == 0
    assert 0 < observations["reverse-tap"].traffic.resp.packets <= 24
    assert all(
        observation.visible_formats == {"zeek_conn"} for observation in observations.values()
    )

    # A configured return route can exist even when the endpoint never replies.
    event.network = replace(
        event.network,
        conn_state="S0",
        history="S",
        traffic=NetworkTrafficLedger(orig=event.network.traffic.orig),
    )
    dispatcher = EventDispatcher(StateManager(), {}, visibility_engine=visibility)
    dispatcher._finalize_network_routing(event)
    assert event._sensor_hostnames_by_format["zeek_conn"] == ["zeek-wan"]
    only_attempt = NetworkObservationPlanner(visibility).plan(event, {"zeek_conn"})
    assert tuple(item.sensor_identity for item in only_attempt) == ("zeek-wan",)
    assert only_attempt[0].traffic.resp.packets == 0


@pytest.mark.parametrize("kind", ["ssh", "rdp"])
def test_unreachable_world_bootstrap_keeps_the_attempt_and_omits_the_session(kind: str) -> None:
    import random
    from datetime import UTC, datetime, timedelta
    from unittest.mock import Mock

    from evidenceforge.events.dispatcher import EventDispatcher
    from evidenceforge.generation.activity import ActivityGenerator
    from evidenceforge.generation.state_manager import StateManager
    from evidenceforge.generation.world_model import WorldModel, WorldPlanner

    scenario = compile_scenario(FIXTURE).scenario
    payload = _network()
    payload["routing"]["routes"]["MFG-CORE"] = []
    scenario.environment.network = NetworkConfig.model_validate(payload)
    environment = scenario.environment
    source = next(system for system in environment.systems if system.ip == HQ)
    target = next(system for system in environment.systems if system.ip == MFG)
    if kind == "rdp":
        source.os = "Windows 11"
        target.os = "Windows Server 2022"
    visibility = NetworkVisibilityEngine(environment.network, environment.systems)
    start = datetime(2026, 1, 12, 12, 0, tzinfo=UTC)
    state = StateManager()
    state.set_current_time(start)
    emitters = {"zeek_conn": Mock()}
    dispatcher = EventDispatcher(state, emitters, visibility_engine=visibility)
    generator = ActivityGenerator(
        state,
        emitters,
        dispatcher=dispatcher,
        generation_window_start=start - timedelta(hours=1),
        generation_window_end=start + timedelta(hours=1),
    )
    generator._ip_to_system = {system.ip: system for system in environment.systems}
    planner = WorldPlanner(WorldModel(scenario, "example.test"), state, generator)
    user = environment.users[0]
    result = planner.bootstrap_user_session(
        user=user,
        target_system=target,
        time=start,
        rng=random.Random(7),
        session_kind=kind,
        source_system=source,
        allow_existing=False,
    )
    assert result.network_uid
    assert result.session is None
    assert not state.get_sessions_for_user(user.username)


def test_routed_ids_uses_the_tuple_on_its_own_link(tmp_path: Path) -> None:
    from dataclasses import replace

    from evidenceforge.events.contexts import IdsAlertPlan
    from evidenceforge.events.dispatcher import EventDispatcher
    from evidenceforge.formats import load_format
    from evidenceforge.generation.emitters.snort import SnortEmitter
    from evidenceforge.generation.state_manager import StateManager
    from tests.unit.test_network_observation import _network_event

    systems = compile_scenario(FIXTURE).scenario.environment.systems
    payload = _network()
    payload["sensors"].append(
        {
            "name": "ids-outside",
            "type": "ids",
            "placement": "tap",
            "link_tap": {"link": "upstream"},
            "log_formats": ["snort_alert"],
        }
    )
    visibility = NetworkVisibilityEngine(NetworkConfig.model_validate(payload), systems)
    emitter = SnortEmitter(
        load_format("snort_alert"), tmp_path, sensor_hostnames=["ids-core", "ids-outside"]
    )
    dispatcher = EventDispatcher(
        StateManager(), {"snort_alert": emitter}, visibility_engine=visibility
    )
    event = _network_event(protocol="tcp")
    event.network = replace(event.network, src_ip=HQ, dst_ip=INTERNET)
    event.ids_alerts = (
        IdsAlertPlan(sid=2_000_001, message="Test observation", classification="Misc activity"),
    )

    dispatcher.dispatch_builder(event)
    emitter.close()

    inside = (tmp_path / "ids-core/snort_alert.log").read_text()
    outside = (tmp_path / "ids-outside/snort_alert.log").read_text()
    assert f"{HQ}:51000 -> {INTERNET}:53" in inside
    assert "192.0.2.1:" in outside and f"-> {INTERNET}:53" in outside
