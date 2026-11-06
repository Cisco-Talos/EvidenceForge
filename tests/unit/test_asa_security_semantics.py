# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""ASA wire roles and reset sides stay independent of the initiating endpoint."""

from dataclasses import replace
from datetime import timedelta
from pathlib import Path

import pytest

from evidenceforge.evaluation.parsers.cisco_asa import CiscoAsaParser
from evidenceforge.events.contexts import NatContext
from evidenceforge.generation.asa_semantics import asa_tcp_close_reason
from evidenceforge.generation.emitters.cisco_asa import CiscoAsaEmitter
from evidenceforge.generation.network_observation import NetworkObservationPlanner
from evidenceforge.generation.network_visibility import NetworkVisibilityEngine
from evidenceforge.models.scenario import NetworkConfig, NetworkSegment, NetworkSensor
from tests.unit.test_cisco_asa_emitter import T0, _make_connection_event
from tests.unit.test_cisco_asa_emitter import asa_emitter as asa_emitter


@pytest.mark.parametrize(
    ("state", "history", "source", "destination", "levels", "expected"),
    [
        ("RSTO", "R", "inside", "outside", {}, "TCP Reset-I"),
        ("RSTOS0", "SR", "inside", "outside", {}, "TCP Reset-I"),
        ("RSTRH", "hr", "inside", "outside", {}, "TCP Reset-O"),
        ("RSTO", "R", "outside", "inside", {}, "TCP Reset-O"),
        ("RSTR", "r", "inside", "outside", {}, "TCP Reset-O"),
        ("REJ", "Sr", "outside", "inside", {}, "TCP Reset-I"),
        ("RSTO", "R", "dmz", "outside", {}, "TCP Reset-I"),
        ("RSTR", "r", "dmz", "inside", {}, "TCP Reset-I"),
        ("RSTO", "R", "trusted", "public", {"trusted": 75, "public": 10}, "TCP Reset-I"),
        ("RSTO", "R", "inside", "inside", {}, "Unknown"),
        ("RSTO", "R", "a", "b", {"a": 50, "b": 50}, "Unknown"),
        ("RSTR", "r", "unqualified", "outside", {}, "Unknown"),
        ("OTH", "Cc", "dmz", "outside", {}, "Unknown"),
        ("OTH", "AR", "inside", "outside", {}, "TCP Reset-I"),
        ("OTH", "Rr", "inside", "outside", {}, "Unknown"),
    ],
)
def test_reset_side_uses_security_relationship(
    state: str, history: str, source: str, destination: str, levels: dict[str, int], expected: str
) -> None:
    assert asa_tcp_close_reason(state, history, source, destination, levels) == expected


def _visibility() -> NetworkVisibilityEngine:
    config = NetworkConfig(
        segments=[NetworkSegment(name="clients", cidr="10.0.10.0/24", exposure="both")],
        sensors=[
            NetworkSensor(
                type="firewall",
                name="fw01",
                monitoring_segments=["clients"],
                log_formats=["cisco_asa"],
                interfaces={"clients": "inside", "_default": "outside"},
            )
        ],
    )
    return NetworkVisibilityEngine(config, systems=[])


@pytest.mark.parametrize("inbound", [False, True])
@pytest.mark.parametrize("state", ["RSTO", "RSTR"])
def test_observation_owns_reset_side_before_rendering(inbound: bool, state: str) -> None:
    source, destination = (
        ("198.51.100.25", "10.0.10.50") if inbound else ("10.0.10.50", "203.0.113.50")
    )
    event = _make_connection_event(src_ip=source, dst_ip=destination, conn_state=state)
    event.network = replace(
        event.network,
        zeek_uid="CAsaSecurity1",
        started_at=T0,
        closed_at=T0 + timedelta(seconds=83.5),
        phase_times=(("transport_start", T0), ("transport_close", T0 + timedelta(seconds=83.5))),
    )
    observation = NetworkObservationPlanner(_visibility()).plan(event, {"cisco_asa"})[0]
    inside_sender = (state == "RSTO") != inbound
    assert observation.firewall_teardown_reason == (
        "TCP Reset-I" if inside_sender else "TCP Reset-O"
    )
    assert observation.observed_close_time < observation.firewall_teardown_time


@pytest.mark.parametrize("inbound", [False, True])
@pytest.mark.parametrize("protocol", ["tcp", "udp"])
@pytest.mark.parametrize("translated", [False, True])
@pytest.mark.parametrize("custom_interfaces", [False, True])
def test_native_endpoint_order_preserves_nat_and_parser_roles(
    asa_emitter: CiscoAsaEmitter,
    tmp_path: Path,
    inbound: bool,
    protocol: str,
    translated: bool,
    custom_interfaces: bool,
) -> None:
    if custom_interfaces:
        asa_emitter._sensor_interfaces["fw01"].update(
            {"workstations": "trusted-link", "_default": "public-net"}
        )
        asa_emitter._sensor_security_levels["fw01"] = {"trusted-link": 100, "public-net": 0}
    source, destination = (
        ("198.51.100.25", "10.0.10.50") if inbound else ("10.0.10.50", "203.0.113.50")
    )
    nat = None
    if translated:
        nat = NatContext(
            nat_type="static" if inbound else "dynamic_pat",
            mapped_src_ip=source if inbound else "198.51.100.1",
            mapped_src_port=54321 if inbound else 12345,
            mapped_dst_ip=destination,
            mapped_dst_port=443,
            pre_nat_dst_ip="203.0.113.5" if inbound else "",
            pre_nat_dst_port=443 if inbound else 0,
        )
    event = _make_connection_event(src_ip=source, dst_ip=destination, protocol=protocol, nat=nat)
    asa_emitter.emit(event)
    asa_emitter.close()
    path = tmp_path / "fw01/2024/cisco_asa.log"
    rows = list(CiscoAsaParser().parse_file(path))
    built = next(row for row in rows if row.fields["msg_id"] in (302013, 302015))
    closed = next(row for row in rows if row.fields["msg_id"] in (302014, 302016))
    for row in (built, closed):
        assert not row.parse_errors
        assert row.fields["src_ip"] == source
        assert row.fields["dst_ip"] == destination
        assert row.fields["foreign_ip"] == (source if inbound else destination)
        assert row.fields["local_ip"] == (destination if inbound else source)
        assert ("for public-net:" if custom_interfaces else "for outside:") in row.fields["message"]
        assert row.fields["connection_id"] == built.fields["connection_id"]
    if translated:
        key = "mapped_dst_ip" if inbound else "mapped_src_ip"
        assert built.fields[key] == ("203.0.113.5" if inbound else "198.51.100.1")


@pytest.mark.parametrize("mismatch", ["hostname", "endpoint", "protocol"])
def test_unmatched_teardown_does_not_invent_an_initiator(tmp_path: Path, mismatch: str) -> None:
    built = "<166>Jun 15 14:23:05 fw01 %ASA-6-302013: Built outbound TCP connection 7 for outside:203.0.113.50/443 (203.0.113.50/443) to inside:10.0.10.50/54321 (10.0.10.50/54321)"
    closed = "<166>Jun 15 14:24:28 fw01 %ASA-6-302014: Teardown TCP connection 7 for outside:203.0.113.50/443 to inside:10.0.10.50/54321 duration 0:01:23 bytes 10 TCP FINs"
    if mismatch == "hostname":
        closed = closed.replace("fw01", "fw02")
    elif mismatch == "endpoint":
        closed = closed.replace("10.0.10.50", "10.0.10.51")
    else:
        closed = closed.replace("302014", "302016").replace("TCP", "UDP")
    path = tmp_path / "cisco_asa.log"
    path.write_text(built + "\n" + closed + "\n")
    record = list(CiscoAsaParser().parse_file(path))[-1]
    assert not record.parse_errors
    assert record.fields["foreign_ip"] == "203.0.113.50"
    assert "src_ip" not in record.fields
    assert "direction" not in record.fields
