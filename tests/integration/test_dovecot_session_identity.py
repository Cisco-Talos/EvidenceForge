# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT
"""Native Dovecot identities retain the committed IMAPS transport tuple."""

import base64
import ipaddress
import json
import re
from pathlib import Path
from typing import Any

import pytest

from evidenceforge.generation.activity.generator import ActivityGenerator
from evidenceforge.generation.engine import GenerationEngine
from evidenceforge.models.scenario import Scenario


def _scenario(protocol: str) -> Scenario:
    return Scenario.model_validate(
        {
            "version": "1.0",
            "name": "dovecot-native-id",
            "description": "Focused mailbox access",
            "environment": {
                "description": "Mailbox client and Linux mail server",
                "domain": "corp.example",
                "users": [
                    {
                        "username": "bob",
                        "full_name": "Bob Brown",
                        "email": "bob@corp.example",
                        "primary_system": "CLIENT",
                    }
                ],
                "systems": [
                    {
                        "hostname": "CLIENT",
                        "ip": "10.0.0.10",
                        "os": "Windows 11",
                        "type": "workstation",
                        "assigned_user": "bob",
                    },
                    {
                        "hostname": "MAIL",
                        "ip": "10.0.0.20",
                        "os": "Ubuntu 22.04",
                        "type": "server",
                        "roles": ["mail_server"],
                        "services": ["smtp", "imaps"],
                    },
                ],
                "network": {
                    "segments": [
                        {
                            "name": "corp",
                            "cidr": "10.0.0.0/24",
                            "exposure": "internal",
                            "systems": ["CLIENT", "MAIL"],
                        }
                    ],
                    "sensors": [
                        {
                            "type": "network",
                            "name": "mail-sensor",
                            "hostname": "zeek-mail",
                            "monitoring_segments": ["corp"],
                            "log_formats": ["zeek"],
                            "capture_profile": "well_synced",
                        }
                    ],
                },
                "email": {
                    "accepted_domains": ["corp.example"],
                    "mail_servers": [
                        {"name": "mail", "hostname": "mail.corp.example", "system": "MAIL"}
                    ],
                    "default_mailbox_servers": ["mail"],
                },
            },
            "time_window": {"start": "2026-11-02T13:00:00Z", "duration": "4m", "warmup": None},
            "baseline_activity": {
                "description": "Short baseline",
                "intensity": "low",
                "variation": "low",
            },
            "observation_profile": "complete",
            "storyline": [
                {
                    "id": f"read-{n}",
                    "time": f"+{n}m",
                    "actor": "bob",
                    "system": "CLIENT",
                    "activity": "Read mailbox",
                    "events": [
                        {
                            "type": "email_read",
                            "server": "mail",
                            "protocol": protocol,
                            "duration": 20.0,
                        }
                    ],
                }
                for n in (1, 2)
            ],
            "output": {"logs": [{"format": "zeek"}, {"format": "syslog"}], "destination": "./data"},
        }
    )


@pytest.mark.slow
@pytest.mark.parametrize(
    "protocol, network_visible, static_nat",
    [("imaps", True, False), ("owa", True, False), ("imaps", False, False), ("imaps", True, True)],
)
def test_mail_session_identity_matches_native_tuple_and_reuses_token(
    tmp_path: Path,
    protocol: str,
    network_visible: bool,
    static_nat: bool,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    scenario = _scenario(protocol)
    observed_destinations: list[str] = []
    if static_nat:
        data = scenario.model_dump()
        data["environment"]["network_identities"] = [
            {
                "id": "public-mail",
                "hosts": ["mail.corp.example"],
                "ips": ["203.0.113.20"],
                "dns": True,
            }
        ]
        data["environment"]["network"]["sensors"].append(
            {
                "type": "firewall",
                "name": "mail-gateway",
                "monitoring_segments": ["corp"],
                "log_formats": ["cisco_asa"],
                "default_action": "permit",
                "nat_rules": [
                    {
                        "type": "static",
                        "src": ["corp"],
                        "real_ip": "10.0.0.20",
                        "mapped_ip": "203.0.113.20",
                    }
                ],
            }
        )
        scenario = Scenario.model_validate(data)
        original = ActivityGenerator._emit_dovecot_imap_syslog

        def observe_destination(self: ActivityGenerator, **kwargs: Any) -> None:
            observed_destinations.append(kwargs["transport"].dst_ip)
            original(self, **kwargs)

        monkeypatch.setattr(ActivityGenerator, "_emit_dovecot_imap_syslog", observe_destination)
    if not network_visible:
        scenario.output.logs = [{"format": "syslog"}]
    GenerationEngine(scenario, tmp_path / "data", ground_truth_dir=tmp_path).generate()
    if static_nat:
        assert "203.0.113.20" in observed_destinations
    connections = [
        json.loads(line)
        for p in (tmp_path / "data").glob("*/conn.json")
        for line in p.read_text().splitlines()
        if line
    ]
    text = "\n".join(p.read_text() for p in (tmp_path / "data").glob("*/syslog.log"))
    logins = re.findall(r"imap-login: Login: user=<bob>.*?rip=([^, ]+).*?session=<([^>]+)>", text)
    if protocol == "owa":
        assert not logins
        assert any(
            row["id.resp_p"] == 443
            and row["id.orig_h"] == "10.0.0.10"
            and row["id.resp_h"] == "10.0.0.20"
            for row in connections
        )
        return
    assert len(logins) >= 2
    summaries = re.findall(r"Disconnected: Logged out [^\n]*", text)
    assert summaries
    for summary in summaries:
        fields = {name: int(value) for name, value in re.findall(r"(\w+)=(\d+)", summary)}
        for prefix in ("hdr", "body"):
            assert fields[prefix + "_count"] > 0 or fields[prefix + "_bytes"] == 0
        assert fields["hdr_bytes"] + fields["body_bytes"] <= fields["out"]
    tokens = []
    for rip, token in logins:
        raw = base64.b64decode(token, validate=True)
        assert len(raw) == 12
        assert str(ipaddress.ip_address(raw[8:])) == rip
        remote_port = int.from_bytes(raw[6:8], "little")
        matches = [
            row
            for row in connections
            if row["id.orig_h"] == rip
            and row["id.orig_p"] == remote_port
            and row["id.resp_h"] == "10.0.0.20"
            and row["id.resp_p"] == 993
        ]
        if not network_visible:
            assert not connections
            assert re.search(r"imap\(bob\)<\d+><" + re.escape(token) + r">: Disconnected:", text)
            tokens.append(token)
            continue
        assert len(matches) == 1
        transport = matches[0]
        start_us = round(transport["ts"] * 1_000_000) % (1 << 48)
        elapsed_us = (int.from_bytes(raw[:6], "little") - start_us) % (1 << 48)
        assert 0 < elapsed_us < (transport["duration"] + 0.25) * 1_000_000
        assert re.search(r"imap\(bob\)<\d+><" + re.escape(token) + r">: Disconnected:", text)
        tokens.append(token)
    assert len(set(tokens)) == len(tokens)
