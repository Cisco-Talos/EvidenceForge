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

from pathlib import Path

import pytest

from evidenceforge.external_parsers.sof_elk_zeek import (
    ZEEK_LOG_SPECS,
    SofElkHarnessError,
    SofElkParserError,
    find_container_runtime,
    run_sof_elk_zeek_parser,
)
from evidenceforge.formats import load_format
from evidenceforge.generation.engine.emitter_setup import _build_emitter_classes

pytestmark = pytest.mark.external_parser


def test_sof_elk_parses_every_generated_zeek_type(tmp_path: Path) -> None:
    runtime = _runtime_or_skip()
    data_dir = _generate_all_type_zeek_sample(tmp_path / "generated")

    result = run_sof_elk_zeek_parser(
        data_dir,
        tmp_path / "harness",
        runtime=runtime,
    )

    assert result.logstash_config_tested
    assert result.manifest.expected_counts == {spec.log_type: 1 for spec in ZEEK_LOG_SPECS}
    for spec in ZEEK_LOG_SPECS:
        assert len(result.events_by_type[spec.log_type]) == 1


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


def _generate_all_type_zeek_sample(output_dir: Path) -> Path:
    samples = _all_type_zeek_records()
    expected_names = {spec.source_names[0] for spec in ZEEK_LOG_SPECS}
    assert set(samples) == expected_names
    emitter_classes = _build_emitter_classes()

    for spec in ZEEK_LOG_SPECS:
        emitter_class = emitter_classes[spec.log_type]
        emitter = emitter_class(
            load_format(spec.log_type),
            output_dir,
            sensor_hostnames=["core-zeek"],
        )
        emitter.emit_event(samples[spec.source_names[0]])
        emitter.close()

    return output_dir


def _all_type_zeek_records() -> dict[str, dict[str, object]]:
    return {
        "conn.json": {
            "ts": 1705312800.0,
            "uid": "CConnParserSample1",
            "id.orig_h": "10.0.1.10",
            "id.orig_p": 54321,
            "id.resp_h": "198.51.100.10",
            "id.resp_p": 443,
            "proto": "tcp",
            "service": "ssl",
            "duration": 2.5,
            "orig_bytes": 1024,
            "resp_bytes": 4096,
            "conn_state": "SF",
            "missed_bytes": 0,
            "history": "ShADadfF",
            "orig_pkts": 10,
            "orig_ip_bytes": 1500,
            "resp_pkts": 8,
            "resp_ip_bytes": 4500,
            "ip_proto": 6,
        },
        "dns.json": {
            "ts": 1705312803.0,
            "uid": "CDnsParserSample1",
            "id.orig_h": "10.0.1.10",
            "id.orig_p": 53533,
            "id.resp_h": "10.0.0.1",
            "id.resp_p": 53,
            "proto": "udp",
            "trans_id": 1234,
            "rtt": 0.012,
            "query": "updates.corp.example.test",
            "qclass": 1,
            "qclass_name": "C_INTERNET",
            "qtype": 1,
            "qtype_name": "A",
            "rcode": 0,
            "rcode_name": "NOERROR",
            "AA": False,
            "TC": False,
            "RD": True,
            "RA": True,
            "Z": 0,
            "answers": ["198.51.100.10"],
            "TTLs": [300.0],
            "rejected": False,
            "opcode": 0,
            "opcode_name": "QUERY",
        },
        "http.json": {
            "ts": 1705312804.0,
            "uid": "CHttpParserSample1",
            "id.orig_h": "10.0.1.10",
            "id.orig_p": 54322,
            "id.resp_h": "198.51.100.20",
            "id.resp_p": 80,
            "trans_depth": 1,
            "method": "GET",
            "host": "www.example.com",
            "uri": "/index.html",
            "version": "1.1",
            "user_agent": "Mozilla/5.0",
            "request_body_len": 0,
            "response_body_len": 2048,
            "status_code": 200,
            "status_msg": "OK",
            "resp_fuids": ["FHttpParserSample1"],
            "resp_mime_types": ["text/html"],
        },
        "files.json": {
            "ts": 1705312804.05,
            "fuid": "FHttpParserSample1",
            "tx_hosts": ["198.51.100.20"],
            "rx_hosts": ["10.0.1.10"],
            "conn_uids": ["CHttpParserSample1"],
            "source": "HTTP",
            "depth": 0,
            "filename": "index.html",
            "analyzers": ["MD5", "SHA1"],
            "mime_type": "text/html",
            "duration": 0.05,
            "local_orig": False,
            "is_orig": False,
            "seen_bytes": 2048,
            "total_bytes": 2048,
            "missing_bytes": 0,
            "overflow_bytes": 0,
            "timedout": False,
            "md5": "5d41402abc4b2a76b9719d911017c592",
            "sha1": "2aae6c35c94fcfb415dbe95f408b9ce91ee846ed",
        },
        "ssl.json": {
            "ts": 1705312805.0,
            "uid": "CSslParserSample1",
            "id.orig_h": "10.0.1.10",
            "id.orig_p": 54323,
            "id.resp_h": "198.51.100.30",
            "id.resp_p": 443,
            "version": "TLSv12",
            "cipher": "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
            "server_name": "assets.example.com",
            "resumed": False,
            "established": True,
            "ssl_history": "Csxk",
            "cert_chain_fuids": ["FCertParserSample1"],
        },
        "x509.json": {
            "ts": 1705312805.1,
            "id": "FCertParserSample1",
            "fingerprint": "0123456789abcdef0123456789abcdef01234567",
            "certificate.version": 3,
            "certificate.serial": "01",
            "certificate.subject": "CN=assets.example.com",
            "certificate.issuer": "CN=Example Issuing CA",
            "certificate.not_valid_before": 1704067200.0,
            "certificate.not_valid_after": 1735689600.0,
            "certificate.key_alg": "rsaEncryption",
            "certificate.sig_alg": "sha256WithRSAEncryption",
            "certificate.key_type": "rsa",
            "certificate.key_length": 2048,
            "certificate.exponent": "65537",
            "san_dns": ["assets.example.com"],
            "basic_constraints_ca": False,
            "host_cert": False,
            "client_cert": False,
        },
        "weird.json": {
            "ts": 1705312806.0,
            "uid": "CWeirdParserSample1",
            "id.orig_h": "10.0.1.10",
            "id.orig_p": 54324,
            "id.resp_h": "198.51.100.40",
            "id.resp_p": 443,
            "name": "bad_TCP_checksum",
            "notice": False,
            "peer": "zeek",
            "source": "NETWORK",
        },
        "dhcp.json": {
            "ts": 1705312807.0,
            "uids": ["CDhcpParserSample1"],
            "client_addr": "10.0.1.10",
            "server_addr": "10.0.0.1",
            "assigned_addr": "10.0.1.10",
            "mac": "00:11:22:33:44:55",
            "host_name": "WS-01",
            "domain": "corp.example.test",
            "msg_types": ["REQUEST", "ACK"],
            "lease_time": 86400,
            "duration": 0.04,
        },
        "ntp.json": {
            "ts": 1705312808.0,
            "uid": "CNtpParserSample1",
            "id.orig_h": "10.0.1.10",
            "id.orig_p": 55123,
            "id.resp_h": "10.0.0.123",
            "id.resp_p": 123,
            "version": 4,
            "mode": 4,
            "stratum": 2,
            "poll": 6,
            "precision": -20,
            "root_delay": 0.015,
            "root_disp": 0.023,
            "ref_id": "GPS",
            "ref_time": 1705312790.0,
            "org_time": 1705312807.95,
            "rec_time": 1705312808.0,
            "xmt_time": 1705312808.01,
            "num_exts": 0,
        },
        "ocsp.json": {
            "ts": 1705312809.0,
            "id": "FOcspParserSample1",
            "hashAlgorithm": "sha1",
            "issuerNameHash": "0123456789abcdef0123456789abcdef01234567",
            "issuerKeyHash": "89abcdef0123456789abcdef0123456789abcdef",
            "serialNumber": "02",
            "certStatus": "good",
            "thisUpdate": 1705312800.0,
            "nextUpdate": 1705399200.0,
            "revoketime": None,
            "revokereason": None,
        },
        "packet_filter.json": {
            "ts": 1705312810.0,
            "node": "core-zeek",
            "filter": "ip or not ip",
            "init": True,
            "success": True,
        },
        "pe.json": {
            "ts": 1705312811.0,
            "id": "FPeParserSample1",
            "machine": "AMD64",
            "compile_ts": 1700000000.0,
            "os": "Windows 10",
            "subsystem": "WINDOWS_GUI",
            "is_exe": True,
            "is_64bit": True,
            "uses_aslr": True,
            "uses_dep": True,
            "uses_code_integrity": False,
            "uses_seh": True,
            "has_import_table": True,
            "has_export_table": False,
            "has_cert_table": True,
            "has_debug_data": False,
            "section_names": [".text", ".rdata", ".data"],
        },
        "reporter.json": {
            "ts": 1705312812.0,
            "level": "Reporter::INFO",
            "message": "zeek_init() called",
            "location": "frameworks/reporter/main.zeek, line 42",
        },
    }
