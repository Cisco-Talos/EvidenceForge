# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

import pytest

from evidenceforge.events.contexts import DnsContext
from evidenceforge.generation.activity.network_dns import _dns_payload_accounting


@pytest.mark.parametrize(
    ("query_type", "answers"),
    [("A", ["10.0.0.1"]), ("AAAA", ["2001:db8::1"]), ("TXT", ["policy text"])],
)
def test_tcp_dns_adds_one_prefix_per_present_message(query_type: str, answers: list[str]) -> None:
    context = DnsContext(
        query="server.example.test", query_type=query_type, answers=answers, rtt=0.02
    )
    kwargs = {"dns": context, "duration": 1.0, "orig_bytes": None, "resp_bytes": None}
    udp = _dns_payload_accounting(**kwargs, proto="udp")
    tcp = _dns_payload_accounting(**kwargs, proto="tcp")
    assert tcp == (udp[0], udp[1] + 2, udp[2] + 2)


def test_tcp_unanswered_dns_does_not_invent_response_prefix() -> None:
    context = DnsContext(query="unanswered.example.test", query_type="A", rcode="-", rcode_num=None)
    result = _dns_payload_accounting(
        dns=context, duration=0.4, orig_bytes=None, resp_bytes=None, proto="tcp"
    )
    assert result[2] == 0


def test_tcp_dns_keeps_full_large_response_above_udp_ceiling() -> None:
    context = DnsContext(
        query="large.example.test", query_type="TXT", answers=["x" * 1600], rtt=0.02
    )
    result = _dns_payload_accounting(
        dns=context, duration=0.4, orig_bytes=None, resp_bytes=None, proto="tcp"
    )
    assert result[2] > 1600
