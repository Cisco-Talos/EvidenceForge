#!/usr/bin/env python3
# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Derive the temporary all-source profiling workload from the historical fixture."""

from __future__ import annotations

import argparse
from pathlib import Path
from typing import Any

import yaml

from evidenceforge.composition import compile_scenario

SOURCE_FIXTURE = Path("tests/fixtures/performance/network_warmup_profile.yaml")
CONCRETE_FORMATS = (
    "bash_history",
    "cisco_asa",
    "ecar",
    "proxy_access",
    "snort_alert",
    "syslog",
    "web_access",
    "windows_event_security",
    "windows_event_sysmon",
    "zeek_conn",
    "zeek_dhcp",
    "zeek_dns",
    "zeek_files",
    "zeek_http",
    "zeek_ntp",
    "zeek_ocsp",
    "zeek_packet_filter",
    "zeek_pe",
    "zeek_reporter",
    "zeek_smb_files",
    "zeek_smb_mapping",
    "zeek_smtp",
    "zeek_ssl",
    "zeek_weird",
    "zeek_x509",
)


def _coverage_anchors() -> list[dict[str, Any]]:
    """Return bounded authored anchors for families not guaranteed by baseline probability."""

    return [
        {
            "id": "profile-windows-endpoint",
            "time": "+5m",
            "actor": "user055",
            "system": "admin-client-a",
            "activity": "Deterministic Windows authentication and process coverage",
            "events": [
                {"type": "logon", "logon_type": 2},
                {
                    "type": "process",
                    "process_name": (
                        "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
                    ),
                    "command_line": "powershell.exe -Command Get-Process",
                },
            ],
        },
        {
            "id": "profile-linux-ssh",
            "time": "+12m",
            "actor": "user055",
            "system": "archive-service",
            "activity": "Deterministic SSH and Linux command coverage",
            "events": [
                {"type": "ssh_session", "source_ip": "192.168.3.11"},
                {
                    "type": "process",
                    "process_name": "/usr/bin/find",
                    "command_line": "find /var/log -maxdepth 2 -type f",
                },
            ],
        },
        {
            "id": "profile-http-file",
            "time": "+20m",
            "actor": "user010",
            "system": "client-005",
            "activity": "Deterministic HTTP and file-transfer coverage",
            "events": [
                {
                    "type": "connection",
                    "dst_ip": "192.168.101.10",
                    "dst_port": 80,
                    "hostname": "perimeter-web-a.example.org",
                    "service": "http",
                    "method": "GET",
                    "uri": "/downloads/profile-guide.pdf",
                    "status_code": 200,
                    "response_body_len": 131072,
                }
            ],
        },
        {
            "id": "profile-explicit-proxy",
            "time": "+25m",
            "actor": "user010",
            "system": "client-005",
            "activity": "Deterministic explicit forward-proxy coverage",
            "events": [
                {
                    "type": "connection",
                    "dst_ip": "203.0.113.10",
                    "dst_port": 443,
                    "hostname": "metrics-api.example.net",
                    "service": "ssl",
                    "method": "GET",
                    "uri": "/v1/health",
                }
            ],
        },
        {
            "id": "profile-web-and-ids",
            "time": "+30m",
            "actor": "user061",
            "system": "soc-client-a",
            "activity": "Deterministic web-server and IDS coverage",
            "events": [
                {
                    "type": "web_scan",
                    "dst_ip": "192.168.1.51",
                    "dst_port": 80,
                    "hostname": "internal-portal.example.org",
                    "preset": "nmap_http",
                    "rate": 2.0,
                    "count": 12,
                    "ids_alerts": [{"sid": 2002910, "policy": "every"}],
                }
            ],
        },
        {
            "id": "profile-firewall",
            "time": "+40m",
            "actor": "user061",
            "system": "soc-client-a",
            "activity": "Deterministic firewall permit and deny coverage",
            "events": [
                {
                    "type": "port_scan",
                    "target_segment": "infrastructure",
                    "target_count": 8,
                    "ports": [22, 80, 443, 445, 3389],
                    "protocol": "tcp",
                    "scan_rate": 10.0,
                }
            ],
        },
        {
            "id": "profile-dns",
            "time": "+50m",
            "actor": "user062",
            "system": "soc-client-b",
            "activity": "Deterministic DNS coverage",
            "events": [
                {
                    "type": "dns_query",
                    "query": "metrics-api.example.net",
                    "qtype": "A",
                    "rcode": "NOERROR",
                    "answer": "203.0.113.10",
                    "ttl": 300,
                }
            ],
        },
        {
            "id": "profile-smtp",
            "time": "+1h10m",
            "actor": "user020",
            "system": "client-015",
            "activity": "Deterministic SMTP and attachment coverage",
            "events": [
                {
                    "type": "email_message",
                    "to": ["user055@example.org"],
                    "subject": "Profiling fixture status",
                    "body": "The bounded all-source profiling workload is ready.",
                    "attachments": [
                        {
                            "filename": "profile-results.csv",
                            "content_type": "text/csv",
                            "size": 8192,
                        }
                    ],
                }
            ],
        },
    ]


def build_workload(source: Path, destination: Path) -> None:
    """Derive, write, and validate one deterministic all-source workload."""

    document = yaml.safe_load(source.read_text(encoding="utf-8"))
    if not isinstance(document, dict):
        raise TypeError(f"Expected a scenario mapping in {source}")
    environment = document["environment"]
    if len(environment["users"]) != 63 or len(environment["systems"]) != 78:
        raise ValueError("Historical profiling topology no longer has 63 users and 78 systems")

    document["name"] = "all-source-generation-performance-profile"
    document["description"] = (
        "A temporary deterministic all-source workload derived from the anonymized historical "
        "network profiling fixture."
    )
    document["generation_seed"] = 42
    document["time_window"] = {
        "start": "2026-03-02T13:00:00Z",
        "duration": "2h",
        "warmup": "1h",
    }
    baseline = document["baseline_activity"]
    baseline["intensity"] = "high"
    baseline["variation"] = "medium"
    baseline["suspicious_noise"] = "high"
    baseline["traffic_rates"] = {"web": [1500, 3000]}

    environment["proxy"] = {"mode": "explicit", "listener_port": 8080}
    environment["email"] = {
        "accepted_domains": ["example.org"],
        "mail_servers": [
            {
                "name": "profile-mail",
                "hostname": "mail.example.org",
                "system": "mail-gateway",
                "platform": "exchange",
                "allow_inbound_starttls": True,
                "attempt_outbound_starttls": True,
            }
        ],
        "default_mailbox_servers": ["profile-mail"],
        "outbound_routes": [{"name": "default", "servers": ["profile-mail"]}],
        "inbound_route": ["profile-mail"],
        "artifacts": {"mode": "storyline", "selected_ids": []},
        "background_messages_per_user_per_day": 0.0,
    }
    proxy = next(system for system in environment["systems"] if system["hostname"] == "edge-proxy")
    proxy["roles"] = sorted({*proxy.get("roles", []), "forward_proxy"})
    proxy["services"] = sorted({*proxy.get("services", []), "squid"})

    network = environment["network"]
    segment_names = [segment["name"] for segment in network["segments"]]
    for sensor in network["sensors"]:
        sensor["log_formats"] = ["zeek"]
        sensor["placement"] = "span"
    network["sensors"].extend(
        [
            {
                "type": "ids",
                "name": "profile-ids",
                "hostname": "profile-ids",
                "monitoring_segments": segment_names,
                "direction": "bidirectional",
                "placement": "span",
                "log_formats": ["snort_alert"],
            },
            {
                "type": "firewall",
                "name": "profile-firewall",
                "hostname": "profile-firewall",
                "monitoring_segments": segment_names,
                "direction": "bidirectional",
                "placement": "tap",
                "log_formats": ["cisco_asa"],
                "interfaces": {
                    "perimeter": "dmz",
                    "infrastructure": "inside",
                    "operations": "management",
                    "clients": "clients",
                },
                "default_action": "permit",
                "deny_ratio": 5.0,
                "threat_detection_rate": 10,
            },
        ]
    )
    document["storyline"] = _coverage_anchors()
    document["output"] = {
        "logs": [{"format": format_name} for format_name in CONCRETE_FORMATS],
        "destination": ".",
        "compression": False,
    }

    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(
        yaml.safe_dump(document, sort_keys=False, width=100),
        encoding="utf-8",
        newline="\n",
    )
    compiled = compile_scenario(destination)
    actual_formats = tuple(sorted(log["format"] for log in compiled.scenario.output.logs))
    if actual_formats != CONCRETE_FORMATS:
        raise RuntimeError("Derived workload did not retain all concrete output formats")


def main() -> None:
    """Build a validated temporary workload from command-line paths."""

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("destination", type=Path)
    parser.add_argument("--source", type=Path, default=SOURCE_FIXTURE)
    args = parser.parse_args()
    build_workload(args.source.resolve(), args.destination.resolve())


if __name__ == "__main__":
    main()
