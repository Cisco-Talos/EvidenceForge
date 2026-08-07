# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Regression coverage for the durable rendered-output review probe."""

from pathlib import Path

from scripts.realism_review_probe import Finding, _check_cisco_asa_contracts, _check_zeek_sensor


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
