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

"""ASA ground-truth projections agree with the firewall's own route and NAT view."""

from pathlib import Path

from evidenceforge.evaluation.ground_truth_agreement import _fields_match, _firewall_forwards
from evidenceforge.evaluation.parsers.cisco_asa import CiscoAsaParser
from evidenceforge.events.evidence_projection import native_requirements
from evidenceforge.generation.network_visibility import NetworkVisibilityEngine
from evidenceforge.models.scenario import (
    NatRule,
    NetworkConfig,
    NetworkSegment,
    NetworkSensor,
    System,
)

_TEARDOWN = "2026-11-02T13:12:21.445625+00:00"


def _matches(path: Path, requirements: list) -> list[bool]:
    records = list(CiscoAsaParser().parse_file(path))
    return [
        any(
            _fields_match(record, requirement.selector)
            and _fields_match(record, requirement.required)
            for record in records
        )
        for requirement in requirements
    ]


def _view(nat: dict | None = None) -> dict:
    return {
        "firewall_teardown_time": _TEARDOWN,
        "firewall_teardown_observed": True,
        "nat": nat,
    }


def test_native_requirements_destination_nat_match_rendered_asa_rows(tmp_path: Path) -> None:
    log = tmp_path / "cisco_asa.log"
    log.write_text(
        "<166>Nov  2 13:12:18 fw-perimeter %ASA-6-302013: Built inbound TCP connection 1681733 "
        "for outside:185.58.85.86/58787 (185.58.85.86/58787) to inside:10.10.2.25/25 "
        "(203.14.220.11/25)\n"
        "<166>Nov  2 13:12:21 fw-perimeter %ASA-6-302014: Teardown TCP connection 1681733 "
        "for outside:185.58.85.86/58787 to inside:10.10.2.25/25 duration 0:00:03 bytes 5824 "
        "TCP FINs\n"
    )
    facts = {
        "network": {
            "protocol": "tcp",
            "src_ip": "185.58.85.86",
            "src_port": 58787,
            "dst_ip": "203.14.220.11",
            "dst_port": 25,
        }
    }
    nat = {
        "nat_type": "static",
        "direction": "destination",
        "local_ip": "10.10.2.25",
        "local_port": 25,
        "global_ip": "203.14.220.11",
        "global_port": 25,
    }

    requirements = native_requirements(
        "cisco_asa", "connection", facts, {}, "sensor", source_view=_view(nat)
    )

    assert [item.selector["msg_id"] for item in requirements] == [302013, 302014]
    assert requirements[0].required["mapped_dst_ip"] == "203.14.220.11"
    assert "mapped_dst_ip" not in requirements[1].required
    assert _matches(log, requirements) == [True, True]


def test_native_requirements_without_nat_view_keep_canonical_tuple() -> None:
    facts = {
        "network": {
            "protocol": "tcp",
            "src_ip": "10.10.1.20",
            "src_port": 50000,
            "dst_ip": "10.10.3.10",
            "dst_port": 443,
        }
    }

    built, teardown = native_requirements(
        "cisco_asa", "connection", facts, {}, "sensor", source_view=_view()
    )

    assert (
        built.required
        == teardown.required
        == {
            "src_ip": "10.10.1.20",
            "src_port": 50000,
            "dst_ip": "10.10.3.10",
            "dst_port": 443,
        }
    )


def test_native_requirements_icmp_use_icmp_lifecycle_rows(tmp_path: Path) -> None:
    log = tmp_path / "cisco_asa.log"
    log.write_text(
        "<166>Nov  2 14:40:01 fw-perimeter %ASA-6-302020: Built inbound ICMP connection for "
        "faddr 10.10.3.10/8 gaddr 10.10.2.1/0 laddr 10.10.2.1/0\n"
        "<166>Nov  2 14:40:03 fw-perimeter %ASA-6-302021: Teardown ICMP connection for "
        "faddr 10.10.3.10/8 gaddr 10.10.2.1/0 laddr 10.10.2.1/0\n"
    )
    facts = {
        "network": {
            "protocol": "icmp",
            "src_ip": "10.10.3.10",
            "src_port": 0,
            "dst_ip": "10.10.2.1",
            "dst_port": 0,
        }
    }

    requirements = native_requirements(
        "cisco_asa", "connection", facts, {}, "sensor", source_view=_view()
    )

    assert [item.selector["msg_id"] for item in requirements] == [302020, 302021]
    assert all("dst_port" not in item.required for item in requirements)
    assert _matches(log, requirements) == [True, True]


def _shared_inside_config() -> NetworkConfig:
    return NetworkConfig(
        segments=[
            NetworkSegment(name="corporate_lan", cidr="10.10.1.0/24", exposure="internal"),
            NetworkSegment(name="server_vlan", cidr="10.10.2.0/24", exposure="internal"),
            NetworkSegment(name="dmz", cidr="10.10.3.0/24", exposure="both"),
        ],
        sensors=[
            NetworkSensor(
                type="firewall",
                name="fw-perimeter",
                placement="tap",
                monitoring_segments=["corporate_lan", "server_vlan", "dmz"],
                direction="bidirectional",
                log_formats=["cisco_asa"],
                interfaces={"corporate_lan": "inside", "server_vlan": "inside", "dmz": "dmz"},
                nat_rules=[
                    NatRule(
                        type="static",
                        src="server_vlan",
                        real_ip="10.10.2.25",
                        mapped_ip="203.14.220.11",
                    )
                ],
            ),
            NetworkSensor(
                type="network",
                name="zeek-core",
                placement="span",
                monitoring_segments=["corporate_lan", "server_vlan"],
                direction="bidirectional",
                log_formats=["zeek"],
            ),
        ],
    )


def _systems() -> list[System]:
    return [
        System(hostname="WS-01", ip="10.10.1.35", os="Windows 11", type="workstation"),
        System(hostname="DC-01", ip="10.10.2.11", os="Windows Server 2022", type="server"),
        System(hostname="MAIL-01", ip="10.10.2.25", os="Linux Ubuntu 22.04", type="server"),
        System(hostname="WEB-01", ip="10.10.3.10", os="Linux Ubuntu 22.04", type="server"),
    ]


def test_visibility_firewall_skips_traffic_between_segments_on_one_interface() -> None:
    engine = NetworkVisibilityEngine(_shared_inside_config(), _systems())

    names = {sensor.name for sensor in engine.get_observing_sensors("10.10.1.35", "10.10.2.11")}
    denied = {sensor.name for sensor in engine.get_source_side_sensors("10.10.1.35", "10.10.2.11")}

    assert names == {"zeek-core"}
    assert "fw-perimeter" not in denied


def test_visibility_firewall_sees_cross_interface_and_hairpin_vip_traffic() -> None:
    engine = NetworkVisibilityEngine(_shared_inside_config(), _systems())

    dmz = {sensor.name for sensor in engine.get_observing_sensors("10.10.3.10", "10.10.2.11")}
    hairpin = {
        sensor.name for sensor in engine.get_observing_sensors("10.10.1.35", "203.14.220.11")
    }
    inbound = {
        sensor.name for sensor in engine.get_observing_sensors("185.58.85.86", "203.14.220.11")
    }

    assert "fw-perimeter" in dmz
    assert "fw-perimeter" in hairpin
    assert "fw-perimeter" in inbound


def test_evaluator_firewall_path_check_mirrors_declared_interfaces() -> None:
    config = _shared_inside_config()
    firewall = config.sensors[0]

    def forwards(src: str, dst: str) -> bool:
        return _firewall_forwards(config, firewall, {"src_ip": src, "dst_ip": dst})

    assert not forwards("10.10.1.35", "10.10.2.11")
    assert forwards("10.10.3.10", "10.10.2.11")
    assert forwards("10.10.1.35", "203.14.220.11")
    assert forwards("185.58.85.86", "203.14.220.11")
