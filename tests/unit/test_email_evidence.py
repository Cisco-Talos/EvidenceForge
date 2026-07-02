# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: MIT

"""Tests for explicit email evidence modeling."""

from __future__ import annotations

import json
from pathlib import Path

from evidenceforge.evaluation.parsers import discover_log_files
from evidenceforge.events.dispatcher import FORMAT_GROUPS, expand_formats
from evidenceforge.generation.engine.core import GenerationEngine
from evidenceforge.models.scenario import (
    BaselineActivity,
    EmailArtifactsConfig,
    EmailConfig,
    EmailDistributionGroup,
    EmailMailboxOverride,
    EmailMessageEventSpec,
    EmailRouteConfig,
    EmailServerConfig,
    Environment,
    Group,
    NetworkConfig,
    NetworkSegment,
    NetworkSensor,
    OutputSpec,
    Scenario,
    StorylineEvent,
    System,
    TimeWindow,
    User,
)
from evidenceforge.validation.schema import ScenarioValidator


def _read_ndjson(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line]


def _email_scenario(*, include_email_config: bool = True) -> Scenario:
    users = [
        User(
            username="alice",
            full_name="Alice Adams",
            email="alice@corp.example",
            groups=["engineering"],
            primary_system="WS-ALICE",
        ),
        User(
            username="bob",
            full_name="Bob Brown",
            email="bob@corp.example",
            groups=["finance"],
            primary_system="WS-BOB",
        ),
    ]
    systems = [
        System(
            hostname="WS-ALICE",
            ip="10.10.1.10",
            os="Windows 11",
            type="workstation",
            assigned_user="alice",
        ),
        System(
            hostname="WS-BOB",
            ip="10.10.1.11",
            os="Windows 11",
            type="workstation",
            assigned_user="bob",
        ),
        System(
            hostname="DC-01",
            ip="10.10.0.10",
            os="Windows Server 2022",
            type="domain_controller",
            roles=["dns_server"],
        ),
        System(
            hostname="MAIL-ENG",
            ip="10.10.2.25",
            os="Windows Server 2022",
            type="server",
            roles=["mail_server"],
            services=["smtp"],
        ),
        System(
            hostname="MAIL-FIN",
            ip="10.10.2.26",
            os="Windows Server 2022",
            type="server",
            roles=["mail_server"],
            services=["smtp"],
        ),
    ]
    email = None
    if include_email_config:
        email = EmailConfig(
            accepted_domains=["corp.example"],
            mail_servers=[
                EmailServerConfig(
                    name="eng",
                    hostname="mail-eng.corp.example",
                    system="MAIL-ENG",
                    attempt_outbound_starttls=True,
                ),
                EmailServerConfig(
                    name="fin",
                    hostname="mail-fin.corp.example",
                    system="MAIL-FIN",
                    allow_inbound_starttls=True,
                ),
            ],
            default_mailbox_servers=["eng"],
            mailbox_overrides=[EmailMailboxOverride(group="finance", server="fin")],
            outbound_routes=[EmailRouteConfig(name="default", servers=["eng"])],
            artifacts=EmailArtifactsConfig(mode="storyline"),
        )
    return Scenario(
        version="1.0",
        name="email-evidence",
        description="Email evidence test scenario",
        environment=Environment(
            description="Small on-prem email environment",
            domain="corp.example",
            users=users,
            systems=systems,
            groups=[
                Group(name="engineering", members=["alice"]),
                Group(name="finance", members=["bob"]),
            ],
            network=NetworkConfig(
                segments=[
                    NetworkSegment(
                        name="corp",
                        cidr="10.10.0.0/16",
                        exposure="internal",
                        systems=[system.hostname for system in systems],
                    )
                ],
                sensors=[
                    NetworkSensor(
                        type="network",
                        name="core-zeek",
                        hostname="zeek-core",
                        monitoring_segments=["corp"],
                        log_formats=["zeek"],
                    )
                ],
            ),
            email=email,
        ),
        time_window=TimeWindow(start="2026-01-05T14:00:00Z", duration="1h", warmup="1h"),
        baseline_activity=BaselineActivity(
            description="Minimal baseline",
            intensity="low",
            variation="low",
            traffic_rates={"user_activity": 1},
        ),
        storyline=[
            StorylineEvent(
                id="phish-email",
                time="+10m",
                actor="alice",
                system="WS-ALICE",
                activity="Alice sends a suspicious finance email",
                events=[
                    EmailMessageEventSpec(
                        to=["bob@corp.example"],
                        subject="Quarterly forecast review",
                        body="Bob,\n\nPlease review the attached forecast notes.\n",
                        verdict="suspicious",
                        attachments=[
                            {
                                "filename": "forecast.txt",
                                "content_type": "text/plain",
                                "content": "Synthetic attachment\n",
                            }
                        ],
                    )
                ],
            )
        ],
        output=OutputSpec(logs=[{"format": "zeek"}], destination="./data"),
    )


def _with_email_storyline(scenario: Scenario, spec: EmailMessageEventSpec) -> Scenario:
    """Return a copy of the fixture scenario with one email storyline event."""
    return scenario.model_copy(
        update={
            "storyline": [
                StorylineEvent(
                    id="email-step",
                    time="+10m",
                    actor="alice",
                    system="WS-ALICE",
                    activity="Email test step",
                    events=[spec],
                )
            ]
        }
    )


def test_zeek_group_includes_smtp() -> None:
    assert "zeek_smtp" in FORMAT_GROUPS["zeek"]
    assert "zeek_smtp" in expand_formats({"zeek"})


def test_email_message_requires_explicit_email_config() -> None:
    scenario = _email_scenario(include_email_config=False)

    issues = ScenarioValidator(scenario).validate()

    assert any(
        issue.severity == "error"
        and issue.field_path == "storyline.0.events.0"
        and "environment.email" in issue.message
        for issue in issues
    )


def test_email_generation_writes_smtp_artifacts_and_ground_truth(tmp_path: Path) -> None:
    scenario = _email_scenario()
    engine = GenerationEngine(
        scenario,
        output_dir=tmp_path / "data",
        ground_truth_dir=tmp_path,
        artifact_dir=tmp_path / "artifacts",
    )

    engine.generate()

    smtp_path = tmp_path / "data" / "zeek-core" / "smtp.json"
    dns_path = tmp_path / "data" / "zeek-core" / "dns.json"
    conn_path = tmp_path / "data" / "zeek-core" / "conn.json"
    manifest_path = tmp_path / "artifacts" / "email" / "EMAIL_ARTIFACTS.json"

    smtp_records = _read_ndjson(smtp_path)
    dns_records = _read_ndjson(dns_path)
    conn_records = _read_ndjson(conn_path)
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    ground_truth = json.loads((tmp_path / "GROUND_TRUTH.json").read_text(encoding="utf-8"))

    assert len(smtp_records) == 2
    assert smtp_records[0]["id.orig_h"] == "10.10.1.10"
    assert smtp_records[0]["id.resp_p"] == 587
    assert smtp_records[0]["subject"] == "Quarterly forecast review"
    assert smtp_records[1]["id.orig_h"] == "10.10.2.25"
    assert smtp_records[1]["id.resp_h"] == "10.10.2.26"
    assert smtp_records[1]["tls"] is True
    assert "subject" not in smtp_records[1]
    assert any(record["qtype_name"] == "A" for record in dns_records)
    assert {record["uid"] for record in smtp_records} <= {record["uid"] for record in conn_records}

    assert manifest["messages"][0]["storyline_id"] == "phish-email"
    assert manifest["messages"][0]["bcc"] == []
    assert manifest["messages"][0]["artifact_path"].endswith(".eml")
    materialized = tmp_path / manifest["messages"][0]["artifact_path"]
    assert materialized.exists()
    assert "Bcc:" not in materialized.read_text(encoding="utf-8")
    eml_text = materialized.read_text(encoding="utf-8")
    assert "Received:" in eml_text
    assert "for <bob@corp.example>" in eml_text
    assert "for <alice@corp.example>" not in eml_text
    assert ground_truth["events"][0]["kind"] == "email_message"
    assert ground_truth["events"][0]["attributes"]["artifact_path"].endswith(".eml")

    discovered = discover_log_files(tmp_path / "data")
    assert smtp_path in discovered["zeek_smtp"]


def test_distribution_group_expands_once_and_bcc_stays_out_of_headers(tmp_path: Path) -> None:
    scenario = _email_scenario()
    assert scenario.environment.email is not None
    scenario.environment.email.distribution_groups = [
        EmailDistributionGroup(
            address="team@corp.example",
            members=["alice@corp.example", "bob@corp.example"],
        )
    ]
    scenario = _with_email_storyline(
        scenario,
        EmailMessageEventSpec(
            to=["team@corp.example"],
            bcc=["bob@corp.example"],
            subject="Distro test",
            body="Testing distribution group expansion.\n",
        ),
    )
    engine = GenerationEngine(
        scenario,
        output_dir=tmp_path / "data",
        ground_truth_dir=tmp_path,
        artifact_dir=tmp_path / "artifacts",
    )

    engine.generate()

    smtp_records = _read_ndjson(tmp_path / "data" / "zeek-core" / "smtp.json")
    manifest = json.loads(
        (tmp_path / "artifacts" / "email" / "EMAIL_ARTIFACTS.json").read_text(encoding="utf-8")
    )
    materialized = tmp_path / manifest["messages"][0]["artifact_path"]
    eml_text = materialized.read_text(encoding="utf-8")

    assert sorted(smtp_records[0]["rcptto"]) == ["alice@corp.example", "bob@corp.example"]
    assert smtp_records[0]["to"] == ["<team@corp.example>"]
    assert manifest["messages"][0]["bcc"] == ["bob@corp.example"]
    assert "Bcc:" not in eml_text
    assert "To: <team@corp.example>" in eml_text


def test_outbound_route_group_override_and_global_isp_relay(tmp_path: Path) -> None:
    scenario = _email_scenario()
    assert scenario.environment.email is not None
    scenario.environment.email.outbound_routes = [
        EmailRouteConfig(name="default", servers=["eng"]),
        EmailRouteConfig(name="engineering-egress", sender_groups=["engineering"], servers=["fin"]),
    ]
    scenario.environment.email.isp_relays = ["smtp.isp.example"]
    scenario = _with_email_storyline(
        scenario,
        EmailMessageEventSpec(
            to=["analyst@example.net"],
            subject="Outbound ISP test",
            body="This message should route through the ISP relay.\n",
        ),
    )
    engine = GenerationEngine(
        scenario,
        output_dir=tmp_path / "data",
        ground_truth_dir=tmp_path,
        artifact_dir=tmp_path / "artifacts",
    )

    engine.generate()

    smtp_records = _read_ndjson(tmp_path / "data" / "zeek-core" / "smtp.json")
    dns_records = _read_ndjson(tmp_path / "data" / "zeek-core" / "dns.json")

    assert [(row["id.orig_h"], row["id.resp_h"], row["id.resp_p"]) for row in smtp_records] == [
        ("10.10.1.10", "10.10.2.25", 587),
        ("10.10.2.25", "10.10.2.26", 25),
        ("10.10.2.26", smtp_records[2]["id.resp_h"], 25),
    ]
    assert smtp_records[1]["tls"] is True
    assert smtp_records[2]["tls"] is False
    assert any(
        row["query"] == "smtp.isp.example" and row["qtype_name"] == "A" for row in dns_records
    )
    assert not any(
        row["qtype_name"] == "MX" and row["query"] == "example.net" for row in dns_records
    )


def test_inbound_route_uses_configured_entry_server(tmp_path: Path) -> None:
    scenario = _email_scenario()
    assert scenario.environment.email is not None
    scenario.environment.email.inbound_route = ["fin"]
    scenario = _with_email_storyline(
        scenario,
        EmailMessageEventSpec(
            sender="news@example.net",
            to=["alice@corp.example"],
            subject="Inbound routing test",
            body="External sender to an internal mailbox.\n",
        ),
    )
    engine = GenerationEngine(
        scenario,
        output_dir=tmp_path / "data",
        ground_truth_dir=tmp_path,
        artifact_dir=tmp_path / "artifacts",
    )

    engine.generate()

    smtp_records = _read_ndjson(tmp_path / "data" / "zeek-core" / "smtp.json")

    assert len(smtp_records) == 2
    assert smtp_records[0]["id.orig_h"].startswith("198.51.100.")
    assert smtp_records[0]["id.resp_h"] == "10.10.2.26"
    assert smtp_records[0]["id.resp_p"] == 25
    assert smtp_records[1]["id.orig_h"] == "10.10.2.26"
    assert smtp_records[1]["id.resp_h"] == "10.10.2.25"


def test_email_validator_reports_actionable_topology_errors() -> None:
    scenario = _email_scenario()
    assert scenario.environment.email is not None
    scenario.environment.email.mail_servers.append(
        EmailServerConfig(name="eng", hostname="mail-dup.corp.example", system="NOPE")
    )
    scenario.environment.email.default_mailbox_servers = ["missing"]
    scenario.environment.email.outbound_routes = [
        EmailRouteConfig(name="bad-route", servers=["missing"], sender_groups=["missing-group"])
    ]
    scenario.environment.email.inbound_route = ["missing"]
    scenario.environment.email.distribution_groups = [
        EmailDistributionGroup(address="team@corp.example", members=["nested@corp.example"]),
        EmailDistributionGroup(address="nested@corp.example", members=["alice@corp.example"]),
    ]
    scenario = _with_email_storyline(
        scenario,
        EmailMessageEventSpec(
            sender="relay@example.net",
            to=["other@example.org"],
            subject="Bad relay",
            body="External to external is unsupported.\n",
        ),
    )

    issues = ScenarioValidator(scenario).validate()
    messages = "\n".join(issue.message for issue in issues)

    assert "Duplicate email mail_server names" in messages
    assert "references unknown system" in messages
    assert "Unknown default mailbox server" in messages
    assert "Outbound route references unknown group" in messages
    assert "Outbound route references unknown server" in messages
    assert "Inbound route references unknown server" in messages
    assert "Nested distribution groups are not supported" in messages
    assert "external-to-external SMTP relay is out of scope" in messages
