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

"""Purpose-built sample data for external parser container tests."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

from evidenceforge.external_parsers.sof_elk_zeek import ZEEK_LOG_SPECS
from evidenceforge.formats import load_format
from evidenceforge.generation.emitters.sysmon import SysmonEventEmitter
from evidenceforge.generation.emitters.windows import WindowsEventEmitter
from evidenceforge.generation.engine.emitter_setup import _build_emitter_classes


def write_splunk_multifamily_dataset(data_dir: Path) -> Path:
    """Write one compact record for every Splunk-supported EvidenceForge family."""
    write_all_type_zeek_sample(
        data_dir,
        sensor_hostname="core-zeek",
        output_target="splunk",
    )
    _write_windows_xml_streams(data_dir)
    _write_host_text_samples(data_dir)
    return data_dir


def write_all_type_zeek_sample(
    output_dir: Path,
    *,
    sensor_hostname: str = "core-zeek",
    output_target: str | None = None,
) -> Path:
    """Write one realistic emitter-rendered record for every Zeek source type."""
    samples = all_type_zeek_records()
    expected_names = {spec.source_names[0] for spec in ZEEK_LOG_SPECS}
    assert set(samples) == expected_names
    emitter_classes = _build_emitter_classes()

    for spec in ZEEK_LOG_SPECS:
        emitter_class = emitter_classes[spec.log_type]
        emitter = emitter_class(
            load_format(spec.log_type),
            output_dir,
            sensor_hostnames=[sensor_hostname],
        )
        if output_target is not None:
            emitter.configure_output_target(output_target)
        emitter.emit_event(samples[spec.source_names[0]])
        emitter.close()

    return output_dir


def all_type_zeek_records() -> dict[str, dict[str, object]]:
    """Return one parser-friendly record for every generated Zeek log file."""
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


def _write_windows_xml_streams(data_dir: Path) -> None:
    security_emitter = WindowsEventEmitter(
        load_format("windows_event_security"),
        data_dir,
        buffer_size=10,
    )
    security_emitter.configure_output_target("splunk")
    security_emitter.emit_event(_security_event())
    security_emitter.close()

    sysmon_emitter = SysmonEventEmitter(
        load_format("windows_event_sysmon"),
        data_dir,
        buffer_size=10,
    )
    sysmon_emitter.configure_output_target("splunk")
    sysmon_emitter.emit_event(_sysmon_event())
    sysmon_emitter.close()


def _write_host_text_samples(data_dir: Path) -> None:
    (data_dir / "linux01.example.test").mkdir(parents=True, exist_ok=True)
    (data_dir / "linux01.example.test" / "syslog.log").write_text(
        "<86>1 2026-06-15T14:23:05.000000Z linux01 sshd 1234 - - Accepted password "
        "for alice from 198.51.100.25 port 54321 ssh2\n",
        encoding="utf-8",
    )
    (data_dir / "fw01").mkdir(parents=True, exist_ok=True)
    (data_dir / "fw01" / "cisco_asa.log").write_text(
        "<166>Jun 15 14:23:05 fw01 %ASA-6-302013: Built outbound TCP connection 7 "
        "for inside:10.0.10.5/54321 (10.0.10.5/54321) to "
        "outside:198.51.100.10/443 (198.51.100.10/443)\n",
        encoding="utf-8",
    )
    (data_dir / "web01.example.test").mkdir(parents=True, exist_ok=True)
    (data_dir / "web01.example.test" / "web_access.log").write_text(
        json.dumps(
            {
                "timestamp": "2026-06-15T14:23:05.000000Z",
                "client": "198.51.100.25",
                "server": "www.example.test",
                "dest_port": 80,
                "ident": "-",
                "user": "alice",
                "http_method": "GET",
                "uri_path": "/index.html",
                "uri_query": "",
                "http_version": "HTTP/1.1",
                "status": 200,
                "http_referrer": "https://example.test/",
                "http_user_agent": "Mozilla/5.0",
                "bytes_in": 0,
                "bytes_out": 512,
                "response_time_microseconds": 23000,
                "http_content_type": "text/html",
            },
            sort_keys=True,
            separators=(",", ":"),
        )
        + "\n",
        encoding="utf-8",
    )
    (data_dir / "proxy01.example.test").mkdir(parents=True, exist_ok=True)
    (data_dir / "proxy01.example.test" / "proxy_access.log").write_text(
        json.dumps(
            {
                "timestamp": "2026-06-15T14:23:05.000000Z",
                "client": "10.0.0.5",
                "server": "example.test",
                "dest_port": 80,
                "ident": "-",
                "user": "alice",
                "http_method": "GET",
                "uri_path": "/",
                "uri_query": "",
                "http_version": "HTTP/1.1",
                "status": 200,
                "http_referrer": "",
                "http_user_agent": "Mozilla/5.0",
                "bytes_in": 128,
                "bytes_out": 512,
                "response_time_microseconds": 10000,
                "http_content_type": "text/html",
                "cache_result": "MISS",
                "proxy_action": "forward",
                "url_category": "Business/Economy",
            },
            sort_keys=True,
            separators=(",", ":"),
        )
        + "\n",
        encoding="utf-8",
    )
    (data_dir / "endpoint01.example.test").mkdir(parents=True, exist_ok=True)
    (data_dir / "endpoint01.example.test" / "ecar.json").write_text(
        '{"timestamp_ms": 1781533385000, "event_type": "PROCESS", "action": "CREATE", '
        '"hostname": "endpoint01.example.test", "pid": 4242}\n',
        encoding="utf-8",
    )


def _security_event() -> dict[str, object]:
    return {
        "EventID": 4624,
        "TimeCreated": datetime(2026, 6, 15, 14, 23, 5, tzinfo=UTC),
        "Computer": "win01.example.test",
        "Channel": "Security",
        "Level": 0,
        "EventRecordID": 101,
        "ExecutionProcessID": 704,
        "ExecutionThreadID": 812,
        "SubjectUserSid": "S-1-5-18",
        "SubjectUserName": "SYSTEM",
        "SubjectDomainName": "NT AUTHORITY",
        "SubjectLogonId": "0x3e7",
        "TargetUserSid": "S-1-5-21-1000-1001",
        "TargetUserName": "alice",
        "TargetDomainName": "CORP",
        "TargetLogonId": "0x46a3f",
        "LogonType": 3,
        "ProcessId": "0x3e4",
        "ProcessName": r"C:\Windows\System32\lsass.exe",
        "IpAddress": "10.0.10.25",
        "IpPort": 54321,
    }


def _sysmon_event() -> dict[str, object]:
    return {
        "EventID": 1,
        "TimeCreated": datetime(2026, 6, 15, 14, 23, 6, tzinfo=UTC),
        "Computer": "win01.example.test",
        "Channel": "Microsoft-Windows-Sysmon/Operational",
        "Level": 4,
        "EventRecordID": 100001,
        "ExecutionProcessID": 4020,
        "ExecutionThreadID": 4024,
        "RuleName": "-",
        "UtcTime": "2026-06-15 14:23:06.000",
        "ProcessGuid": "{11111111-1111-1111-1111-111111111111}",
        "ProcessId": 4321,
        "Image": r"C:\Windows\System32\cmd.exe",
        "CommandLine": "cmd.exe /c whoami",
        "User": r"CORP\alice",
        "Hashes": "MD5=0123456789abcdef0123456789abcdef",
        "ParentProcessGuid": "{33333333-3333-3333-3333-333333333333}",
        "ParentProcessId": 4000,
        "ParentImage": r"C:\Windows\explorer.exe",
        "ParentCommandLine": r"C:\Windows\explorer.exe",
    }
