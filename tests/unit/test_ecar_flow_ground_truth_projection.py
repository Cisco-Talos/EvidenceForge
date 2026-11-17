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

"""eCAR FLOW ground-truth projections use the endpoint-local view the emitter renders."""

from evidenceforge.evaluation.ground_truth_agreement import _fields_match
from evidenceforge.evaluation.parsers import ParsedRecord
from evidenceforge.events.evidence_projection import native_requirements


def _flow(properties: dict, direction: str) -> ParsedRecord:
    return ParsedRecord(
        source_format="ecar",
        raw="",
        fields={"object": "FLOW", "action": "CONNECT", **properties, "direction": direction},
    )


def test_inbound_flow_requirement_uses_destination_host_real_address() -> None:
    facts = {
        "network": {
            "protocol": "tcp",
            "src_ip": "185.70.41.45",
            "src_port": 53419,
            "dst_ip": "203.14.220.10",
            "dst_port": 443,
        },
        "nat": {"nat_type": "static", "mapped_dst_ip": "10.10.3.10", "mapped_dst_port": 443},
    }
    (requirement,) = native_requirements("ecar", "connection", facts, {}, "destination_endpoint")
    row = _flow(
        {
            "src_ip": "185.70.41.45",
            "src_port": "53419",
            "dst_ip": "10.10.3.10",
            "dst_port": "443",
            "protocol": "tcp",
        },
        "INBOUND",
    )

    assert requirement.required["dst_ip"] == "10.10.3.10"
    assert _fields_match(row, requirement.selector)
    assert _fields_match(row, requirement.required)


def test_outbound_flow_requirement_keeps_addressed_destination() -> None:
    facts = {
        "network": {
            "protocol": "tcp",
            "src_ip": "10.10.1.35",
            "src_port": 49543,
            "dst_ip": "203.14.220.11",
            "dst_port": 993,
        },
        "nat": {"nat_type": "static", "mapped_dst_ip": "10.10.2.25", "mapped_dst_port": 993},
    }
    (requirement,) = native_requirements("ecar", "connection", facts, {}, "source_endpoint")

    assert requirement.required["dst_ip"] == "203.14.220.11"


def test_icmp_flow_requirement_has_no_transport_ports() -> None:
    facts = {
        "network": {
            "protocol": "icmp",
            "src_ip": "10.10.3.10",
            "src_port": 0,
            "dst_ip": "10.10.2.1",
            "dst_port": 0,
        }
    }
    (requirement,) = native_requirements("ecar", "connection", facts, {}, "source_endpoint")
    row = _flow(
        {
            "src_ip": "10.10.3.10",
            "dst_ip": "10.10.2.1",
            "protocol": "icmp",
            "icmp_type": 8,
            "icmp_code": 0,
        },
        "OUTBOUND",
    )

    assert "src_port" not in requirement.required
    assert _fields_match(row, requirement.selector)
    assert _fields_match(row, requirement.required)
