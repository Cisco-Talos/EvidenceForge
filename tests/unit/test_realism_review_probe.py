# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Regression coverage for the durable rendered-output review probe."""

from pathlib import Path

from scripts.realism_review_probe import (
    Finding,
    _check_cisco_asa_contracts,
    _check_cross_source_contracts,
    _check_zeek_sensor,
)


def _asa_findings(tmp_path: Path, lines: list[str]) -> list[Finding]:
    path = tmp_path / "cisco_asa.log"
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    findings: list[Finding] = []
    _check_cisco_asa_contracts(path, findings)
    return findings


def test_probe_detects_pat_teardown_before_connection(tmp_path: Path) -> None:
    findings = _asa_findings(
        tmp_path,
        [
            "%ASA-6-302013: Built outbound TCP connection 42 for inside:10.0.0.8/51000 "
            "(203.0.113.8/32000) to outside:198.51.100.20/443 (198.51.100.20/443)",
            "%ASA-6-305011: Built dynamic TCP translation from inside:10.0.0.8/51000 "
            "to outside:203.0.113.8/32000",
            "%ASA-6-305012: Teardown dynamic TCP translation from inside:10.0.0.8/51000 "
            "to outside:203.0.113.8/32000 duration 0:00:00",
            "%ASA-6-302014: Teardown TCP connection 42 for inside:10.0.0.8/51000 "
            "to outside:198.51.100.20/443 duration 0:00:30 bytes 0 SYN Timeout",
        ],
    )

    assert [finding.check for finding in findings] == ["asa_pat_lifetime"]


def test_probe_accepts_connection_contained_pat_lifetime(tmp_path: Path) -> None:
    findings = _asa_findings(
        tmp_path,
        [
            "%ASA-6-302013: Built outbound TCP connection 42 for inside:10.0.0.8/51000 "
            "(203.0.113.8/32000) to outside:198.51.100.20/443 (198.51.100.20/443)",
            "%ASA-6-305011: Built dynamic TCP translation from inside:10.0.0.8/51000 "
            "to outside:203.0.113.8/32000",
            "%ASA-6-302014: Teardown TCP connection 42 for inside:10.0.0.8/51000 "
            "to outside:198.51.100.20/443 duration 0:00:30 bytes 0 SYN Timeout",
            "%ASA-6-305012: Teardown dynamic TCP translation from inside:10.0.0.8/51000 "
            "to outside:203.0.113.8/32000 duration 0:00:30",
        ],
    )

    assert not findings


def test_probe_detects_inbound_icmp_static_nat_role_error(tmp_path: Path) -> None:
    findings = _asa_findings(
        tmp_path,
        [
            "%ASA-6-302013: Built inbound TCP connection 7 for outside:198.51.100.20/51000 "
            "(198.51.100.20/51000) to dmz:10.0.0.20/443 (203.0.113.20/443)",
            "%ASA-6-302020: Built inbound ICMP connection for faddr 198.51.100.20/8 "
            "gaddr 203.0.113.20/0 laddr 203.0.113.20/0",
        ],
    )

    assert [finding.check for finding in findings] == ["asa_inbound_icmp_nat"]


def test_probe_rejects_service_without_analyzer_payload(tmp_path: Path) -> None:
    findings: list[Finding] = []
    _check_zeek_sensor(
        tmp_path,
        {
            "conn": [
                {
                    "ts": 1.0,
                    "uid": "CpayloadFree",
                    "id.orig_h": "10.0.0.8",
                    "id.orig_p": 51000,
                    "id.resp_h": "198.51.100.20",
                    "id.resp_p": 443,
                    "proto": "tcp",
                    "service": "ssl",
                    "orig_bytes": 0,
                    "resp_bytes": 0,
                    "orig_ip_bytes": 40,
                    "resp_ip_bytes": 0,
                    "orig_pkts": 1,
                    "resp_pkts": 0,
                    "conn_state": "OTH",
                }
            ]
        },
        findings,
    )

    assert [finding.check for finding in findings] == ["zeek_unconfirmed_service"]


def test_probe_rejects_head_body_larger_than_transport(tmp_path: Path) -> None:
    findings: list[Finding] = []
    _check_zeek_sensor(
        tmp_path,
        {
            "conn": [
                {
                    "ts": 1.0,
                    "uid": "CheadBody",
                    "id.orig_h": "198.51.100.8",
                    "id.orig_p": 51000,
                    "id.resp_h": "10.0.0.20",
                    "id.resp_p": 80,
                    "proto": "tcp",
                    "service": "http",
                    "orig_bytes": 300,
                    "resp_bytes": 220,
                    "orig_ip_bytes": 500,
                    "resp_ip_bytes": 420,
                    "orig_pkts": 4,
                    "resp_pkts": 4,
                    "conn_state": "SF",
                    "duration": 1.0,
                }
            ],
            "http": [
                {
                    "ts": 1.1,
                    "uid": "CheadBody",
                    "id.orig_h": "198.51.100.8",
                    "id.orig_p": 51000,
                    "id.resp_h": "10.0.0.20",
                    "id.resp_p": 80,
                    "method": "HEAD",
                    "response_body_len": 478,
                }
            ],
        },
        findings,
    )

    assert [finding.check for finding in findings] == [
        "zeek_http_head_body",
        "zeek_http_transport_accounting",
    ]


def test_probe_rejects_file_gap_without_transport_gap(tmp_path: Path) -> None:
    findings: list[Finding] = []
    _check_zeek_sensor(
        tmp_path,
        {
            "conn": [
                {
                    "ts": 1.0,
                    "uid": "CfileGap",
                    "id.orig_h": "10.0.0.8",
                    "id.orig_p": 51000,
                    "id.resp_h": "198.51.100.20",
                    "id.resp_p": 80,
                    "proto": "tcp",
                    "service": "http",
                    "orig_bytes": 300,
                    "resp_bytes": 10_500,
                    "orig_ip_bytes": 500,
                    "resp_ip_bytes": 11_000,
                    "orig_pkts": 4,
                    "resp_pkts": 10,
                    "conn_state": "SF",
                    "duration": 1.0,
                    "missed_bytes": 0,
                    "history": "ShADadfF",
                }
            ],
            "files": [
                {
                    "ts": 1.1,
                    "fuid": "FfileGap",
                    "conn_uids": ["CfileGap"],
                    "source": "HTTP",
                    "is_orig": False,
                    "seen_bytes": 9_500,
                    "total_bytes": 10_000,
                    "missing_bytes": 500,
                    "duration": 0.5,
                }
            ],
        },
        findings,
    )

    assert [finding.check for finding in findings] == ["zeek_file_capture_loss"]


def test_probe_detects_ocsp_http_without_response_companion(tmp_path: Path) -> None:
    findings: list[Finding] = []
    _check_zeek_sensor(
        tmp_path,
        {
            "conn": [
                {
                    "ts": 1.0,
                    "uid": "CocspMissing",
                    "id.orig_h": "10.0.0.8",
                    "id.orig_p": 51000,
                    "id.resp_h": "198.51.100.20",
                    "id.resp_p": 80,
                    "proto": "tcp",
                    "service": "http",
                    "orig_bytes": 500,
                    "resp_bytes": 1000,
                    "orig_ip_bytes": 700,
                    "resp_ip_bytes": 1200,
                    "orig_pkts": 5,
                    "resp_pkts": 6,
                    "conn_state": "SF",
                    "duration": 1.0,
                }
            ],
            "http": [
                {
                    "ts": 1.0,
                    "uid": "CocspMissing",
                    "id.orig_h": "10.0.0.8",
                    "id.orig_p": 51000,
                    "id.resp_h": "198.51.100.20",
                    "id.resp_p": 80,
                    "resp_fuids": ["FocspMissing"],
                    "resp_mime_types": ["application/ocsp-response"],
                }
            ],
            "files": [
                {
                    "ts": 1.1,
                    "fuid": "FocspMissing",
                    "source": "HTTP",
                    "mime_type": "application/ocsp-response",
                }
            ],
        },
        findings,
    )

    assert [finding.check for finding in findings] == ["zeek_ocsp_companion_reference"]


def test_probe_detects_one_client_using_unrelated_public_dns_operators(tmp_path: Path) -> None:
    findings: list[Finding] = []
    _check_zeek_sensor(
        tmp_path,
        {
            "conn": [
                {
                    "ts": 1.0,
                    "uid": "CdnsCloudflare",
                    "id.orig_h": "10.0.0.8",
                    "id.orig_p": 51000,
                    "id.resp_h": "1.1.1.1",
                    "id.resp_p": 53,
                    "proto": "udp",
                    "service": "dns",
                    "orig_bytes": 50,
                    "resp_bytes": 100,
                    "orig_ip_bytes": 78,
                    "resp_ip_bytes": 128,
                    "orig_pkts": 1,
                    "resp_pkts": 1,
                    "conn_state": "SF",
                },
                {
                    "ts": 2.0,
                    "uid": "CdnsGoogle",
                    "id.orig_h": "10.0.0.8",
                    "id.orig_p": 51001,
                    "id.resp_h": "8.8.8.8",
                    "id.resp_p": 53,
                    "proto": "udp",
                    "service": "dns",
                    "orig_bytes": 50,
                    "resp_bytes": 100,
                    "orig_ip_bytes": 78,
                    "resp_ip_bytes": 128,
                    "orig_pkts": 1,
                    "resp_pkts": 1,
                    "conn_state": "SF",
                },
            ],
            "dns": [
                {
                    "ts": 1.0,
                    "uid": "CdnsCloudflare",
                    "id.orig_h": "10.0.0.8",
                    "id.orig_p": 51000,
                    "id.resp_h": "1.1.1.1",
                    "id.resp_p": 53,
                },
                {
                    "ts": 2.0,
                    "uid": "CdnsGoogle",
                    "id.orig_h": "10.0.0.8",
                    "id.orig_p": 51001,
                    "id.resp_h": "8.8.8.8",
                    "id.resp_p": 53,
                },
            ],
        },
        findings,
    )

    assert [finding.check for finding in findings] == ["dns_public_resolver_operator_coherence"]


def test_probe_rejects_ssh_client_termination_long_after_transport_close(tmp_path: Path) -> None:
    findings: list[Finding] = []
    host_path = tmp_path / "HOST" / "ecar.json"
    zeek_path = tmp_path / "ZEEK" / "conn.json"
    _check_cross_source_contracts(
        tmp_path,
        {
            host_path: [
                {
                    "timestamp_ms": 1_000,
                    "id": "process-create",
                    "object": "PROCESS",
                    "action": "CREATE",
                    "objectID": "ssh-process",
                    "properties": {"image_path": r"C:\Windows\System32\OpenSSH\ssh.exe"},
                },
                {
                    "timestamp_ms": 2_000,
                    "id": "ssh-flow",
                    "object": "FLOW",
                    "action": "CONNECT",
                    "actorID": "ssh-process",
                    "properties": {
                        "src_ip": "10.0.0.8",
                        "src_port": "51000",
                        "dst_ip": "10.0.0.20",
                        "dst_port": "22",
                    },
                },
                {
                    "timestamp_ms": 100_000,
                    "id": "process-terminate",
                    "object": "PROCESS",
                    "action": "TERMINATE",
                    "objectID": "ssh-process",
                    "properties": {"image_path": r"C:\Windows\System32\OpenSSH\ssh.exe"},
                },
            ],
            zeek_path: [
                {
                    "ts": 2.0,
                    "duration": 10.0,
                    "id.orig_h": "10.0.0.8",
                    "id.orig_p": 51000,
                    "id.resp_h": "10.0.0.20",
                    "id.resp_p": 22,
                }
            ],
        },
        findings,
    )

    assert [finding.check for finding in findings] == [
        "ecar_ssh_client_terminates_after_transport_close"
    ]


def test_probe_rejects_ssh_shell_without_termination_before_logout(tmp_path: Path) -> None:
    findings: list[Finding] = []
    host_path = tmp_path / "HOST" / "ecar.json"
    _check_cross_source_contracts(
        tmp_path,
        {
            host_path: [
                {
                    "timestamp_ms": 1_000,
                    "id": "shell-create",
                    "object": "PROCESS",
                    "action": "CREATE",
                    "objectID": "ssh-shell",
                    "pid": 42001,
                    "properties": {
                        "image_path": "/bin/bash",
                        "logon_id": "0x1234",
                    },
                },
                {
                    "timestamp_ms": 20_000,
                    "id": "session-logout",
                    "object": "USER_SESSION",
                    "action": "LOGOUT",
                    "properties": {
                        "session_type": "ssh",
                        "logon_id": "0x1234",
                    },
                },
            ]
        },
        findings,
    )

    assert [finding.check for finding in findings] == [
        "ecar_ssh_shell_terminates_before_session_logout"
    ]
