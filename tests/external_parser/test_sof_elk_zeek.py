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

"""External parser tests for SOF-ELK Zeek ingestion."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest

from evidenceforge.events.base import SecurityEvent
from evidenceforge.events.contexts import DnsContext, HostContext, NetworkContext
from evidenceforge.external_parsers.sof_elk_zeek import (
    SofElkHarnessError,
    SofElkParserError,
    find_container_runtime,
    run_sof_elk_zeek_parser,
)
from evidenceforge.formats import load_format
from evidenceforge.generation.emitters.zeek import ZeekEmitter
from evidenceforge.generation.emitters.zeek_dns import ZeekDnsEmitter

pytestmark = pytest.mark.external_parser


def test_sof_elk_parses_generated_zeek_conn_and_dns(tmp_path: Path) -> None:
    runtime = _runtime_or_skip()
    data_dir = _generate_zeek_sample(tmp_path / "generated")

    result = run_sof_elk_zeek_parser(
        data_dir,
        tmp_path / "harness",
        runtime=runtime,
    )

    assert result.logstash_config_tested
    assert result.manifest.expected_counts["zeek_conn"] > 0
    assert result.manifest.expected_counts["zeek_dns"] > 0
    assert len(result.events_by_type["zeek_conn"]) == result.manifest.expected_counts["zeek_conn"]
    assert len(result.events_by_type["zeek_dns"]) == result.manifest.expected_counts["zeek_dns"]


def test_sof_elk_reports_corrupted_zeek_json(tmp_path: Path) -> None:
    runtime = _runtime_or_skip()
    source_dir = tmp_path / "source" / "sensor-a"
    source_dir.mkdir(parents=True)
    (source_dir / "conn.json").write_text(
        '{"ts":"1742036100.000000","uid":"BROKEN",\n',
        encoding="utf-8",
    )

    with pytest.raises(SofElkParserError, match="SOF-ELK parser validation failed"):
        run_sof_elk_zeek_parser(
            tmp_path / "source",
            tmp_path / "work",
            runtime=runtime,
        )


def _runtime_or_skip() -> str:
    try:
        return find_container_runtime()
    except SofElkHarnessError as exc:
        pytest.skip(str(exc))


def _generate_zeek_sample(output_dir: Path) -> Path:
    conn_emitter = ZeekEmitter(
        load_format("zeek_conn"),
        output_dir,
        sensor_hostnames=["core-zeek"],
    )
    dns_emitter = ZeekDnsEmitter(
        load_format("zeek_dns"),
        output_dir,
        sensor_hostnames=["core-zeek"],
    )

    host = HostContext(
        hostname="WS-01",
        ip="10.0.1.10",
        os="Windows 11",
        os_category="windows",
        system_type="workstation",
    )
    conn_event = SecurityEvent(
        timestamp=datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC),
        event_type="connection",
        src_host=host,
        network=NetworkContext(
            src_ip="10.0.1.10",
            src_port=54321,
            dst_ip="198.51.100.10",
            dst_port=443,
            protocol="tcp",
            service="ssl",
            zeek_uid="CConnParserSample1",
            conn_state="SF",
            history="ShADadfF",
            duration=2.5,
            orig_bytes=1024,
            resp_bytes=4096,
            orig_pkts=10,
            resp_pkts=8,
            orig_ip_bytes=1500,
            resp_ip_bytes=4500,
            ip_proto=6,
        ),
        _sensor_hostnames_by_format={"zeek_conn": ["core-zeek"]},
    )
    dns_event = SecurityEvent(
        timestamp=datetime(2024, 1, 15, 10, 0, 3, tzinfo=UTC),
        event_type="connection",
        src_host=host,
        network=NetworkContext(
            src_ip="10.0.1.10",
            src_port=53533,
            dst_ip="10.0.0.1",
            dst_port=53,
            protocol="udp",
            service="dns",
            zeek_uid="CDnsParserSample1",
            conn_state="SF",
            duration=0.012,
            orig_bytes=64,
            resp_bytes=128,
            orig_pkts=1,
            resp_pkts=1,
            orig_ip_bytes=92,
            resp_ip_bytes=156,
            ip_proto=17,
        ),
        dns=DnsContext(
            query="updates.corp.example.test",
            trans_id=1234,
            qtype=1,
            query_type="A",
            rcode="NOERROR",
            rcode_num=0,
            answers=["198.51.100.10"],
            TTLs=[300.0],
            rtt=0.012,
        ),
        _sensor_hostnames_by_format={"zeek_dns": ["core-zeek"]},
    )

    conn_emitter.emit(conn_event)
    dns_emitter.emit(dns_event)
    conn_emitter.close()
    dns_emitter.close()

    data_dir = output_dir
    assert (data_dir / "core-zeek" / "conn.json").exists()
    assert (data_dir / "core-zeek" / "dns.json").exists()
    return data_dir
