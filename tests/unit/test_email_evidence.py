# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: MIT

"""Tests for explicit email evidence modeling."""

from __future__ import annotations

import ipaddress
import json
import re
from datetime import UTC, datetime
from email import policy
from email.parser import BytesParser
from email.utils import parsedate_to_datetime
from hashlib import md5, sha1, sha256
from pathlib import Path

from evidenceforge.evaluation.context import EvaluationContext
from evidenceforge.evaluation.parsers import ParsedRecord, discover_log_files, get_parser
from evidenceforge.evaluation.pillars.causality import CausalityScorer
from evidenceforge.events.contexts import SslContext
from evidenceforge.events.dispatcher import FORMAT_GROUPS, expand_formats
from evidenceforge.events.ground_truth import load_ground_truth_document
from evidenceforge.generation.activity.mail_public_identities import (
    is_public_mail_ip,
    public_mail_ptr_name,
    public_safe_mail_hostname,
)
from evidenceforge.generation.engine.baseline import BaselineMixin
from evidenceforge.generation.engine.core import GenerationEngine
from evidenceforge.models.scenario import (
    BaselineActivity,
    EmailArtifactsConfig,
    EmailAttachmentSpec,
    EmailConfig,
    EmailDistributionGroup,
    EmailMailboxOverride,
    EmailMessageEventSpec,
    EmailReadEventSpec,
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


def _header_names(message_text: str) -> list[str]:
    names: list[str] = []
    for line in message_text.splitlines():
        if not line:
            break
        if line[0].isspace():
            continue
        names.append(line.split(":", 1)[0])
    return names


def _received_header_datetimes(message_text: str) -> list[str]:
    return [
        line.rsplit(";", 1)[-1].strip()
        for line in message_text.splitlines()
        if line.startswith("Received:")
    ]


def _email_ground_truth(output_dir: Path, scenario: Scenario) -> dict[str, dict]:
    document = load_ground_truth_document(output_dir, scenario)
    assert document is not None
    result: dict[str, dict] = {}
    for rec in document.events:
        if rec.kind != "email_message" or not rec.emitted:
            continue
        assert rec.attributes.message_id
        result[rec.storyline_id] = {
            "message_id": rec.attributes.message_id,
            "artifact_path": rec.attributes.artifact_path,
            "smtp_uids": list(rec.attributes.smtp_uids or ()),
            "subject": rec.attributes.subject,
            "sender": rec.attributes.sender,
            "recipients": list(rec.attributes.recipients or ()),
        }
    return result


def _parse_eval_records(data_dir: Path) -> dict[str, list]:
    discovered = discover_log_files(data_dir)
    records: dict[str, list] = {}
    for format_name, paths in discovered.items():
        parser = get_parser(format_name)
        records[format_name] = [
            record
            for path in paths
            for record in parser.parse_file(path)
            if not record.parse_errors
        ]
    return records


def _parse_syslog_records(data_dir: Path) -> list[ParsedRecord]:
    records: list[ParsedRecord] = []
    for path in data_dir.rglob("syslog.log"):
        parser = get_parser("syslog")
        records.extend(record for record in parser.parse_file(path) if not record.parse_errors)
    return records


def _is_global_non_test_net(ip: str) -> bool:
    parsed = ipaddress.ip_address(ip)
    return parsed.is_global and not (
        ip.startswith("192.0.2.") or ip.startswith("198.51.100.") or ip.startswith("203.0.113.")
    )


def test_explicit_email_topology_suppresses_generic_mail_profile_connections() -> None:
    """Explicit topology owns baseline SMTP and mailbox-access evidence."""
    assert BaselineMixin._is_profile_email_connection(
        {"port": 25, "service": "smtp", "description": "Outbound mail relay"}
    )
    assert BaselineMixin._is_profile_email_connection(
        {"port": 993, "service": "ssl", "description": "IMAPS client access"}
    )
    assert BaselineMixin._is_profile_email_connection(
        {"port": 443, "service": "ssl", "description": "OWA/webmail access"}
    )
    assert not BaselineMixin._is_profile_email_connection(
        {"port": 443, "service": "ssl", "description": "Anti-spam/update checks"}
    )


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


def _with_email_storyline(scenario: Scenario, spec: object) -> Scenario:
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
    ssl_path = tmp_path / "data" / "zeek-core" / "ssl.json"
    manifest_path = tmp_path / "artifacts" / "email" / "EMAIL_ARTIFACTS.json"

    smtp_records = _read_ndjson(smtp_path)
    dns_records = _read_ndjson(dns_path)
    conn_records = _read_ndjson(conn_path)
    ssl_records = _read_ndjson(ssl_path)
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    ground_truth = json.loads((tmp_path / "GROUND_TRUTH.json").read_text(encoding="utf-8"))

    assert len(smtp_records) == 2
    assert smtp_records[0]["id.orig_h"] == "10.10.1.10"
    assert smtp_records[0]["id.resp_p"] == 587
    assert smtp_records[0]["tls"] is True
    assert smtp_records[0]["mailfrom"] == ""
    assert smtp_records[0]["rcptto"] == []
    assert smtp_records[0]["last_reply"].startswith("220 2.0.0")
    assert smtp_records[0]["path"] == []
    assert smtp_records[0]["subject"] == ""
    assert smtp_records[0]["cc"] == []
    assert smtp_records[0]["fuids"] == []
    assert smtp_records[0]["user_agent"] == ""
    assert smtp_records[1]["id.orig_h"] == "10.10.2.25"
    assert smtp_records[1]["id.resp_h"] == "10.10.2.26"
    assert smtp_records[1]["tls"] is True
    assert smtp_records[1]["mailfrom"] == ""
    assert smtp_records[1]["rcptto"] == []
    assert smtp_records[1]["last_reply"].startswith("220 2.0.0")
    assert smtp_records[1]["path"] == []
    assert smtp_records[1]["subject"] == ""
    assert smtp_records[1]["cc"] == []
    assert any(record["qtype_name"] == "A" for record in dns_records)
    assert {record["uid"] for record in smtp_records} <= {record["uid"] for record in conn_records}
    assert {record["uid"] for record in smtp_records} <= {record["uid"] for record in ssl_records}
    assert all("TLS" in record["last_reply"].upper() for record in smtp_records if record["tls"])

    assert "storyline_id" not in manifest["messages"][0]
    assert "artifact_id" not in manifest["messages"][0]
    assert "artifact_path" not in manifest["messages"][0]
    assert "verdict" not in manifest["messages"][0]
    blind_facing_transport_fields = {
        "delivery_action",
        "expanded_rcptto",
        "outcome",
        "received_headers",
        "route",
    }
    assert not (blind_facing_transport_fields & set(manifest["messages"][0]))
    assert manifest["messages"][0]["bcc"] == []
    assert manifest["messages"][0]["eml_path"].endswith(".eml")
    assert manifest["messages"][0]["artifact_export_status"] == "materialized"
    assert manifest["messages"][0]["artifact_export_reason"] == "selected_by_artifact_policy"
    materialized = tmp_path / "artifacts" / "email" / manifest["messages"][0]["eml_path"]
    assert materialized.exists()
    assert "Bcc:" not in materialized.read_text(encoding="utf-8")
    eml_text = materialized.read_text(encoding="utf-8")
    assert "Received:" in eml_text
    assert "for <bob@corp.example>" in eml_text
    assert "for <alice@corp.example>" not in eml_text
    received_lines = [line for line in eml_text.splitlines() if line.startswith("Received:")]
    assert any(
        "with ESMTPSA id " in line or "with Microsoft SMTP Server id " in line
        for line in received_lines
    )
    assert any(
        "with ESMTPS id " in line or "with Microsoft SMTP Server id " in line
        for line in received_lines
    )
    assert not any("with ESMTP id " in line for line in received_lines)
    exchange_versions = [
        match.group(1)
        for line in received_lines
        if (match := re.search(r"Microsoft SMTP Server id ([0-9.]+)", line))
    ]
    assert exchange_versions
    assert all(re.fullmatch(r"15\.(?:1|2)\.\d+\.\d+", version) for version in exchange_versions)
    received_dates = _received_header_datetimes(eml_text)
    assert received_dates
    if len(received_dates) > 1:
        parsed_received = sorted(parsedate_to_datetime(date) for date in received_dates)
        received_gaps = [
            (parsed_received[index + 1] - parsed_received[index]).total_seconds()
            for index in range(len(parsed_received) - 1)
        ]
        assert any(gap != 4.0 for gap in received_gaps)
    assert ground_truth["events"][0]["kind"] == "email_message"
    assert ground_truth["events"][0]["attributes"]["artifact_path"].endswith(".eml")
    rendered_smtp_uids = {record["uid"] for record in smtp_records}
    assert set(ground_truth["events"][0]["attributes"]["smtp_uids"]) <= rendered_smtp_uids

    discovered = discover_log_files(tmp_path / "data")
    assert smtp_path in discovered["zeek_smtp"]
    assert manifest_path in discovered["email_artifacts"]
    artifact_records = list(get_parser("email_artifacts").parse_file(manifest_path))
    assert artifact_records[0].fields["message_id"] == manifest["messages"][0]["message_id"]


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
    materialized = tmp_path / "artifacts" / "email" / manifest["messages"][0]["eml_path"]
    eml_text = materialized.read_text(encoding="utf-8")

    assert smtp_records[0]["id.resp_p"] == 587
    assert smtp_records[0]["tls"] is True
    assert smtp_records[0]["rcptto"] == []
    assert smtp_records[0]["to"] == []
    assert smtp_records[0]["cc"] == []
    assert smtp_records[0]["mailfrom"] == ""
    assert smtp_records[0]["subject"] == ""
    assert smtp_records[1]["tls"] is True
    assert smtp_records[1]["rcptto"] == []
    assert manifest["messages"][0]["bcc"] == ["bob@corp.example"]
    assert "Bcc:" not in eml_text
    assert "To: <team@corp.example>" in eml_text


def test_linux_mail_server_emits_postfix_syslog_lifecycle(tmp_path: Path) -> None:
    scenario = _email_scenario()
    systems = [
        system.model_copy(update={"os": "Ubuntu 22.04"})
        if system.hostname == "MAIL-ENG"
        else system
        for system in scenario.environment.systems
    ]
    scenario = scenario.model_copy(
        update={
            "environment": scenario.environment.model_copy(update={"systems": systems}),
            "output": OutputSpec(
                logs=[{"format": "zeek"}, {"format": "syslog"}, {"format": "ecar"}],
                destination="./data",
            ),
        }
    )
    engine = GenerationEngine(
        scenario,
        output_dir=tmp_path / "data",
        ground_truth_dir=tmp_path,
        artifact_dir=tmp_path / "artifacts",
    )

    engine.generate()

    syslog_text = "\n".join(
        path.read_text(encoding="utf-8") for path in (tmp_path / "data").rglob("syslog.log")
    )
    conn_records = _read_ndjson(tmp_path / "data" / "zeek-core" / "conn.json")
    smtp_records = _read_ndjson(tmp_path / "data" / "zeek-core" / "smtp.json")
    client_match = re.search(
        r"postfix/smtpd \d+ - - ([A-F0-9]{9,11}): "
        r"client=WS-ALICE\.corp\.example\[10\.10\.1\.10\], "
        r"sasl_method=LOGIN, sasl_username=alice",
        syslog_text,
    )
    assert client_match is not None
    queue_id = client_match.group(1)
    assert "postfix/cleanup" in syslog_text
    assert f"{queue_id}: message-id=<" in syslog_text
    assert f"{queue_id}: from=<alice@corp.example>" in syslog_text
    size_match = re.search(rf"{queue_id}: from=<alice@corp\.example>, size=(\d+),", syslog_text)
    assert size_match is not None
    queue_size = int(size_match.group(1))
    conn_by_uid = {row["uid"]: row for row in conn_records}
    assert queue_size != conn_by_uid[smtp_records[0]["uid"]]["orig_bytes"]
    assert queue_size != conn_by_uid[smtp_records[1]["uid"]]["orig_bytes"]
    assert (
        f"{queue_id}: to=<bob@corp.example>, relay=mail-fin.corp.example[10.10.2.26]:25"
    ) in syslog_text
    assert f"{queue_id}: removed" in syslog_text
    assert syslog_text.index(f"{queue_id}: client=") < syslog_text.index(f"{queue_id}: message-id=")
    assert syslog_text.index(f"{queue_id}: message-id=") < syslog_text.index(
        f"{queue_id}: from=<alice@corp.example>"
    )

    syslog_records = _parse_syslog_records(tmp_path / "data")
    active_record = next(
        record
        for record in syslog_records
        if record.fields.get("message", "").startswith(f"{queue_id}: from=<alice@corp.example>")
    )
    delivery_record = next(
        record
        for record in syslog_records
        if record.fields.get("message", "").startswith(f"{queue_id}: to=<bob@corp.example>")
    )
    delay_match = re.search(r"\bdelay=([0-9.]+)", delivery_record.fields["message"])
    assert delay_match is not None
    assert active_record.timestamp is not None
    assert delivery_record.timestamp is not None
    assert (
        float(delay_match.group(1))
        >= (delivery_record.timestamp - active_record.timestamp).total_seconds()
    )

    smtp_pid = delivery_record.fields["pid"]
    ecar_records = [
        row for path in (tmp_path / "data").rglob("ecar.json") for row in _read_ndjson(path)
    ]
    outbound_flow = next(
        row
        for row in ecar_records
        if row.get("object") == "FLOW"
        and row.get("action") == "CONNECT"
        and row.get("properties", {}).get("src_ip") == "10.10.2.25"
        and row.get("properties", {}).get("dst_ip") == "10.10.2.26"
        and row.get("properties", {}).get("dst_port") == "25"
        and row.get("properties", {}).get("direction") == "OUTBOUND"
    )
    assert outbound_flow["pid"] == smtp_pid
    assert outbound_flow["properties"]["image_path"] == "/usr/lib/postfix/sbin/smtp"


def test_outbound_route_group_override_and_global_isp_relay(tmp_path: Path, monkeypatch) -> None:
    def _tls12_starttls(self, *, dst_system, **_kwargs) -> SslContext:
        return SslContext(
            version="TLSv12",
            cipher="TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
            server_name=self._email_server_fqdn(dst_system.hostname),
            resumed=False,
            established=True,
            ssl_history="Csxk",
        )

    monkeypatch.setattr(
        "evidenceforge.generation.activity.generator.ActivityGenerator._smtp_starttls_ssl_context",
        _tls12_starttls,
    )
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
    conn_records = _read_ndjson(tmp_path / "data" / "zeek-core" / "conn.json")
    dns_records = _read_ndjson(tmp_path / "data" / "zeek-core" / "dns.json")
    file_records = _read_ndjson(tmp_path / "data" / "zeek-core" / "files.json")
    ssl_records = _read_ndjson(tmp_path / "data" / "zeek-core" / "ssl.json")
    x509_records = _read_ndjson(tmp_path / "data" / "zeek-core" / "x509.json")

    assert [(row["id.orig_h"], row["id.resp_h"], row["id.resp_p"]) for row in smtp_records] == [
        ("10.10.1.10", "10.10.2.25", 587),
        ("10.10.2.25", "10.10.2.26", 25),
        ("10.10.2.26", smtp_records[2]["id.resp_h"], 25),
    ]
    assert smtp_records[1]["tls"] is True
    assert smtp_records[1]["mailfrom"] == ""
    assert smtp_records[1]["rcptto"] == []
    assert smtp_records[1]["last_reply"].startswith("220 2.0.0")
    assert smtp_records[1]["path"] == []
    assert smtp_records[1]["fuids"] == []
    assert smtp_records[2]["tls"] is False
    assert smtp_records[2]["path"] != [smtp_records[2]["id.resp_h"], smtp_records[2]["id.orig_h"]]
    starttls_uids = {row["uid"] for row in smtp_records if row["tls"]}
    assert starttls_uids
    assert starttls_uids <= {row["uid"] for row in ssl_records}
    starttls_ports = {row["id.resp_p"] for row in ssl_records if row["uid"] in starttls_uids}
    assert starttls_ports <= {25, 587}
    assert starttls_ports >= {25, 587}
    starttls_tls12 = [
        row for row in ssl_records if row["uid"] in starttls_uids and row["version"] == "TLSv12"
    ]
    assert starttls_tls12
    cert_fuids = [fuid for row in starttls_tls12 for fuid in (row.get("cert_chain_fuids") or [])]
    assert cert_fuids
    assert set(cert_fuids) <= {row["fuid"] for row in file_records}
    assert set(cert_fuids) <= {row["id"] for row in x509_records}
    conn_by_uid = {row["uid"]: row for row in conn_records}
    assert all(conn_by_uid[uid]["orig_bytes"] > 1000 for uid in starttls_uids)
    safe_isp_relay = public_safe_mail_hostname("smtp.isp.example")
    assert safe_isp_relay != "smtp.isp.example.net"
    assert any(row["query"] == safe_isp_relay and row["qtype_name"] == "A" for row in dns_records)
    assert not any(
        row["query"] == safe_isp_relay and row["qtype_name"] == "MX" for row in dns_records
    )
    assert all(row["trans_id"] > 0 for row in dns_records if safe_isp_relay == row["query"])
    assert not any(
        row["qtype_name"] == "MX" and row["query"] == "example.net" for row in dns_records
    )
    plaintext_fuid_sets = [tuple(row.get("fuids", [])) for row in smtp_records if not row["tls"]]
    plaintext_fuids = [fuid for fuids in plaintext_fuid_sets for fuid in fuids]
    assert len(plaintext_fuids) == len(set(plaintext_fuids))
    assert {row["fuid"] for row in file_records} >= set(plaintext_fuids)


def test_mixed_internal_external_outbound_hops_scope_recipients(tmp_path: Path) -> None:
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
            cc=["bob@corp.example"],
            subject="Mixed recipient route",
            body="This message has both internal and external recipients.\n",
        ),
    )
    systems = [
        system.model_copy(update={"os": "Ubuntu 22.04"})
        if system.hostname == "MAIL-ENG"
        else system
        for system in scenario.environment.systems
    ]
    scenario = scenario.model_copy(
        update={
            "environment": scenario.environment.model_copy(update={"systems": systems}),
            "output": OutputSpec(
                logs=[{"format": "zeek"}, {"format": "syslog"}],
                destination="./data",
            ),
        }
    )
    engine = GenerationEngine(
        scenario,
        output_dir=tmp_path / "data",
        ground_truth_dir=tmp_path,
        artifact_dir=tmp_path / "artifacts",
    )

    engine.generate()

    smtp_records = _read_ndjson(tmp_path / "data" / "zeek-core" / "smtp.json")

    assert [(row["id.orig_h"], row["id.resp_h"], row["id.resp_p"]) for row in smtp_records] == [
        ("10.10.1.10", "10.10.2.25", 587),
        ("10.10.2.25", "10.10.2.26", 25),
        ("10.10.2.25", "10.10.2.26", 25),
        ("10.10.2.26", smtp_records[3]["id.resp_h"], 25),
    ]
    assert smtp_records[0]["tls"] is True
    assert smtp_records[0]["mailfrom"] == ""
    assert smtp_records[0]["rcptto"] == []
    assert smtp_records[0]["subject"] == ""
    assert smtp_records[1]["tls"] is True
    assert smtp_records[1]["rcptto"] == []
    assert smtp_records[2]["tls"] is True
    assert smtp_records[2]["rcptto"] == []
    assert smtp_records[3]["rcptto"] == ["analyst@example.net"]

    syslog_records = _parse_syslog_records(tmp_path / "data")
    client_record = next(
        record
        for record in syslog_records
        if record.fields.get("app_name") == "postfix/smtpd"
        and "client=WS-ALICE.corp.example[10.10.1.10]" in record.fields.get("message", "")
    )
    queue_match = re.search(r"([A-F0-9]{9,11}): client=", client_record.fields["message"])
    assert queue_match is not None
    queue_id = queue_match.group(1)
    active_record = next(
        record
        for record in syslog_records
        if record.fields.get("message", "").startswith(f"{queue_id}: from=<alice@corp.example>")
    )
    assert "nrcpt=2 (queue active)" in active_record.fields["message"]
    delivery_records = [
        record
        for record in syslog_records
        if record.fields.get("message", "").startswith(f"{queue_id}: to=<")
    ]
    delivery_messages = [record.fields["message"] for record in delivery_records]
    assert len(delivery_records) == 2
    assert any("to=<bob@corp.example>" in message for message in delivery_messages)
    assert any("to=<analyst@example.net>" in message for message in delivery_messages)
    removed_record = next(
        record
        for record in syslog_records
        if record.fields.get("message") == f"{queue_id}: removed"
    )
    assert removed_record.timestamp is not None
    assert all(
        record.timestamp is not None and record.timestamp <= removed_record.timestamp
        for record in delivery_records
    )


def test_outbound_direct_mx_groups_external_recipients_by_domain(tmp_path: Path) -> None:
    scenario = _email_scenario()
    assert scenario.environment.email is not None
    scenario.environment.email.isp_relays = []
    scenario = _with_email_storyline(
        scenario,
        EmailMessageEventSpec(
            to=["analyst@example.net", "reviewer@vendor.example.org"],
            subject="External delivery split",
            body="This message should produce one external SMTP route per recipient domain.\n",
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
    assert [(row["id.orig_h"], row["id.resp_p"]) for row in smtp_records] == [
        ("10.10.1.10", 587),
        ("10.10.2.25", 25),
        ("10.10.2.25", 25),
    ]
    external_hops = [row for row in smtp_records if row["id.resp_p"] == 25]
    assert [row["rcptto"] for row in external_hops] == [[], []]
    assert len({row["id.resp_h"] for row in external_hops}) == 2

    mx_queries = {
        row["query"]: row["answers"]
        for row in dns_records
        if row["qtype_name"] == "MX" and row["query"] in {"example.net", "vendor.example.org"}
    }
    assert set(mx_queries) == {"example.net", "vendor.example.org"}
    mx_hosts = {domain: answers[0].split(maxsplit=1)[1] for domain, answers in mx_queries.items()}
    a_queries = {
        row["query"]: tuple(row["answers"])
        for row in dns_records
        if row["qtype_name"] == "A" and row["query"] in set(mx_hosts.values())
    }
    assert set(a_queries) == set(mx_hosts.values())
    mx_answer_ips = {answers[0] for answers in a_queries.values()}
    assert {row["id.resp_h"] for row in external_hops} == mx_answer_ips


def test_email_dns_uses_configured_mail_server_identity(tmp_path: Path) -> None:
    scenario = _email_scenario()
    assert scenario.environment.email is not None
    scenario.environment.email.accepted_domains = ["corp-mail.example"]
    scenario.environment.email.mail_servers[0].hostname = "mail.corp-mail.example"
    scenario.environment.email.mail_servers[1].hostname = "mail-fin.corp-mail.example"
    scenario.environment.users[0].email = "alice@corp-mail.example"
    scenario.environment.users[1].email = "bob@corp-mail.example"
    scenario.storyline[0].events = [
        EmailMessageEventSpec(
            to=["bob@corp-mail.example"],
            subject="Mail DNS identity",
            body="Mail DNS should use the configured mail server system IP.\n",
        )
    ]
    engine = GenerationEngine(
        scenario,
        output_dir=tmp_path / "data",
        ground_truth_dir=tmp_path,
        artifact_dir=tmp_path / "artifacts",
    )

    engine.generate()

    dns_records = _read_ndjson(tmp_path / "data" / "zeek-core" / "dns.json")
    mail_answers = [
        answer
        for row in dns_records
        if row["query"] == "mail.corp-mail.example" and row["qtype_name"] in {"A", "AAAA"}
        for answer in row.get("answers", [])
    ]
    assert mail_answers
    assert set(mail_answers) <= {"10.10.2.25", "fd00:3714:0019::1"}


def test_inbound_route_uses_configured_entry_server(tmp_path: Path, monkeypatch) -> None:
    def _no_external_starttls(self, **_kwargs) -> bool:
        return False

    monkeypatch.setattr(
        "evidenceforge.generation.activity.generator.ActivityGenerator._external_sender_attempts_starttls",
        _no_external_starttls,
    )
    scenario = _email_scenario()
    assert scenario.environment.email is not None
    scenario.environment.email.inbound_route = ["fin"]
    scenario = _with_email_storyline(
        scenario,
        EmailMessageEventSpec(
            sender="news@example.net",
            to=["alice@corp.example"],
            cc=["bob@corp.example"],
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
    dns_records = _read_ndjson(tmp_path / "data" / "zeek-core" / "dns.json")
    conn_records = _read_ndjson(tmp_path / "data" / "zeek-core" / "conn.json")

    assert len(smtp_records) == 2
    assert _is_global_non_test_net(smtp_records[0]["id.orig_h"])
    assert smtp_records[0]["id.resp_h"] == "10.10.2.26"
    assert smtp_records[0]["id.resp_p"] == 25
    assert smtp_records[0]["tls"] is False
    assert smtp_records[0]["to"] == ["<alice@corp.example>"]
    assert smtp_records[0]["cc"] == ["<bob@corp.example>"]
    assert smtp_records[0]["path"]
    assert all(_is_global_non_test_net(ip) for ip in smtp_records[0]["path"])
    assert smtp_records[1]["id.orig_h"] == "10.10.2.26"
    assert smtp_records[1]["id.resp_h"] == "10.10.2.25"
    inbound_conn = next(row for row in conn_records if row["uid"] == smtp_records[0]["uid"])
    assert inbound_conn["local_orig"] is False
    assert inbound_conn["local_resp"] is True
    assert not any(
        row["id.orig_h"] == smtp_records[0]["id.orig_h"] and row["id.resp_h"] == "10.10.0.10"
        for row in dns_records
    )
    assert not any(
        row["id.orig_h"] == smtp_records[0]["id.orig_h"] and row["qtype_name"] == "SRV"
        for row in dns_records
    )


def test_external_inbound_sender_can_use_starttls(tmp_path: Path, monkeypatch) -> None:
    def _always_external_starttls(self, **_kwargs) -> bool:
        return True

    monkeypatch.setattr(
        "evidenceforge.generation.activity.generator.ActivityGenerator._external_sender_attempts_starttls",
        _always_external_starttls,
    )
    scenario = _email_scenario()
    assert scenario.environment.email is not None
    scenario.environment.email.inbound_route = ["fin"]
    scenario = _with_email_storyline(
        scenario,
        EmailMessageEventSpec(
            sender="alerts@vendorpost.net",
            to=["alice@corp.example"],
            subject="Inbound STARTTLS policy test",
            body="External sender should negotiate inbound STARTTLS.\n",
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
    ssl_records = _read_ndjson(tmp_path / "data" / "zeek-core" / "ssl.json")
    inbound_smtp = next(
        row for row in smtp_records if row["id.resp_h"] == "10.10.2.26" and row["id.resp_p"] == 25
    )

    assert inbound_smtp["tls"] is True
    assert inbound_smtp["uid"] in {row["uid"] for row in ssl_records}
    assert inbound_smtp["mailfrom"] == ""
    assert inbound_smtp["rcptto"] == []
    assert inbound_smtp["subject"] == ""
    assert inbound_smtp["cc"] == []
    assert inbound_smtp["fuids"] == []


def test_smtp_starttls_tls12_cipher_matches_certificate_key(tmp_path: Path) -> None:
    scenario = _email_scenario()
    engine = GenerationEngine(
        scenario,
        output_dir=tmp_path / "data",
        ground_truth_dir=tmp_path,
        artifact_dir=tmp_path / "artifacts",
    )

    engine.generate()

    generator = engine.activity_generator
    assert generator is not None
    systems = {system.hostname: system for system in scenario.environment.systems}
    checked = False
    for index in range(200):
        ssl_ctx = generator._smtp_starttls_ssl_context(
            src_system=systems["WS-ALICE"],
            dst_system=systems["MAIL-ENG"],
            message_id=f"<probe-{index}@corp.example>",
            hop_index=index,
            event_time=datetime(2026, 1, 5, 14, 0, tzinfo=UTC),
        )
        if ssl_ctx.version != "TLSv12" or ssl_ctx.resumed:
            continue
        cert_chain = generator._smtp_starttls_certificate_chain(
            ssl=ssl_ctx,
            dst_system=systems["MAIL-ENG"],
            message_id=f"<probe-{index}@corp.example>",
            hop_index=index,
            event_time=datetime(2026, 1, 5, 14, 0, tzinfo=UTC),
        )
        if not cert_chain:
            continue
        assert ("_ECDSA_" in ssl_ctx.cipher) == (cert_chain[0].certificate_key_type == "ecdsa")
        checked = True
        break
    assert checked


def test_smtp_starttls_replies_are_server_family_textured(tmp_path: Path) -> None:
    scenario = _email_scenario()
    engine = GenerationEngine(
        scenario,
        output_dir=tmp_path / "data",
        ground_truth_dir=tmp_path,
        artifact_dir=tmp_path / "artifacts",
    )

    engine.generate()

    generator = engine.activity_generator
    assert generator is not None
    systems = {system.hostname: system for system in scenario.environment.systems}
    linux_mail = systems["MAIL-ENG"].model_copy(update={"os": "Ubuntu 22.04"})
    external_mail = System(
        hostname="MX-EDGE",
        ip="198.51.100.44",
        os="Ubuntu 22.04",
        type="server",
        roles=["external_mail_server"],
        services=["smtp"],
    )
    old_global_pool = {
        "220 2.0.0 Ready to start TLS",
        "220 2.0.0 Begin TLS negotiation now",
        "220 2.0.0 Go ahead with STARTTLS",
        "220 2.0.0 STARTTLS accepted; proceed",
    }

    replies_by_server = {
        dst.hostname: {
            generator._smtp_starttls_reply(
                src_system=systems["WS-ALICE"],
                dst_system=dst,
                message_id=f"<probe-{index}@corp.example>",
                hop_index=index,
            )
            for index in range(80)
        }
        for dst in (systems["MAIL-ENG"], linux_mail, external_mail)
    }
    all_replies = {reply for replies in replies_by_server.values() for reply in replies}

    assert all("TLS" in reply.upper() for reply in all_replies)
    assert len(all_replies) > len(old_global_pool)
    assert len(all_replies - old_global_pool) >= 4
    assert all(len(replies) >= 3 for replies in replies_by_server.values())


def test_smtp_starttls_sni_policy_varies_for_server_to_server(tmp_path: Path) -> None:
    scenario = _email_scenario()
    engine = GenerationEngine(
        scenario,
        output_dir=tmp_path / "data",
        ground_truth_dir=tmp_path,
        artifact_dir=tmp_path / "artifacts",
    )

    engine.generate()

    generator = engine.activity_generator
    assert generator is not None
    systems = {system.hostname: system for system in scenario.environment.systems}
    external_mail = System(
        hostname="mx.partner.example",
        ip="198.51.100.44",
        os="Internet SMTP Server",
        type="server",
        roles=["external_mail_server"],
        services=["smtp"],
    )

    submission_names = {
        generator._smtp_starttls_server_name(
            src_system=systems["WS-ALICE"],
            dst_system=systems["MAIL-ENG"],
            message_id=f"<submit-{index}@corp.example>",
            hop_index=index,
            submission=True,
            server_to_server=False,
        )
        for index in range(25)
    }
    internal_relay_names = {
        generator._smtp_starttls_server_name(
            src_system=systems["MAIL-ENG"],
            dst_system=systems["MAIL-FIN"],
            message_id=f"<relay-{index}@corp.example>",
            hop_index=index,
            submission=False,
            server_to_server=True,
        )
        for index in range(80)
    }
    external_relay_names = {
        generator._smtp_starttls_server_name(
            src_system=systems["MAIL-ENG"],
            dst_system=external_mail,
            message_id=f"<external-{index}@corp.example>",
            hop_index=index,
            submission=False,
            server_to_server=True,
        )
        for index in range(80)
    }

    assert submission_names == {"mail-eng.corp.example"}
    assert "" in internal_relay_names
    assert "mail-fin.corp.example" in internal_relay_names
    assert "" in external_relay_names
    assert "mx.partner.example" in external_relay_names


def test_external_sender_received_headers_share_public_hop_model(tmp_path: Path) -> None:
    scenario = _email_scenario()
    engine = GenerationEngine(
        scenario,
        output_dir=tmp_path / "data",
        ground_truth_dir=tmp_path,
        artifact_dir=tmp_path / "artifacts",
    )

    engine.generate()

    generator = engine.activity_generator
    assert generator is not None
    systems = {system.hostname: system for system in scenario.environment.systems}
    sender = "support@example.net"
    message_id = "<external-hop-model@example.net>"
    route = [
        {
            "src_system": generator._external_source_mail_system(sender),
            "dst_system": systems["MAIL-FIN"],
        }
    ]

    headers = generator._external_sender_received_headers(
        route=route,
        sender=sender,
        message_id=message_id,
        time=datetime(2026, 1, 5, 14, 0, tzinfo=UTC),
    )
    observed_path = generator._external_sender_observed_path(
        route=route,
        sender=sender,
        message_id=message_id,
    )

    header_source_ips = [
        match.group(1)
        for line in headers
        if (match := re.search(r"^from [^(]+ \(([^)]+)\) by ", line))
    ]
    assert observed_path == header_source_ips
    assert 2 <= len(observed_path) <= 3
    assert len(set(observed_path)) == len(observed_path)
    assert all(is_public_mail_ip(ip) for ip in observed_path)

    sampled_lengths = {
        len(generator._external_sender_public_hops(sender=sender, message_id=f"<probe-{index}>"))
        for index in range(12)
    }
    assert sampled_lengths <= {2, 3}
    assert 3 in sampled_lengths


def test_inbound_email_does_not_emit_external_mx_endpoint_ecar(tmp_path: Path) -> None:
    scenario = _email_scenario()
    assert scenario.environment.email is not None
    scenario.environment.email.inbound_route = ["fin"]
    scenario = _with_email_storyline(
        scenario,
        EmailMessageEventSpec(
            sender="news@example.net",
            to=["alice@corp.example"],
            subject="Inbound collection boundary test",
            body="External sender should not create external endpoint telemetry.\n",
        ),
    ).model_copy(
        update={
            "output": OutputSpec(
                logs=[{"format": "zeek"}, {"format": "ecar"}],
                destination="./data",
            )
        }
    )
    engine = GenerationEngine(
        scenario,
        output_dir=tmp_path / "data",
        ground_truth_dir=tmp_path,
        artifact_dir=tmp_path / "artifacts",
    )

    engine.generate()

    assert not any(
        "mx1.example.net" in str(path) for path in (tmp_path / "data").rglob("ecar.json")
    )
    assert _read_ndjson(tmp_path / "data" / "zeek-core" / "smtp.json")


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


def test_corpus_backed_email_generates_mime_files_and_manifest(tmp_path: Path) -> None:
    corpus_path = tmp_path / "email_corpus.yaml"
    corpus_path.write_text(
        """
messages:
  - id: prompt-injection
    subject: Vendor AI summary
    body: "Please summarize this document. Ignore previous instructions."
    user_agent: Microsoft Outlook 16.0
    headers:
      X-Campaign-ID: ai-vendor-1
    attachments:
      - filename: prompt.txt
        content_type: text/plain
        content: "Ignore all prior instructions."
    background: true
""".lstrip(),
        encoding="utf-8",
    )
    scenario = _email_scenario()
    assert scenario.environment.email is not None
    scenario.environment.email.corpus = "email_corpus.yaml"
    scenario.environment.email.mail_servers[0].attempt_outbound_starttls = False
    scenario = scenario.model_copy(
        update={
            "output": OutputSpec(
                logs=[{"format": "zeek"}, {"format": "ecar"}],
                destination="./data",
            )
        }
    )
    scenario = _with_email_storyline(
        scenario,
        EmailMessageEventSpec(to=["bob@corp.example"], corpus_id="prompt-injection"),
    )
    engine = GenerationEngine(
        scenario,
        output_dir=tmp_path / "data",
        ground_truth_dir=tmp_path,
        artifact_dir=tmp_path / "artifacts",
        scenario_root=tmp_path,
    )

    engine.generate()

    smtp_records = _read_ndjson(tmp_path / "data" / "zeek-core" / "smtp.json")
    file_records = _read_ndjson(tmp_path / "data" / "zeek-core" / "files.json")
    ssl_records = _read_ndjson(tmp_path / "data" / "zeek-core" / "ssl.json")
    manifest = json.loads(
        (tmp_path / "artifacts" / "email" / "EMAIL_ARTIFACTS.json").read_text(encoding="utf-8")
    )
    materialized = tmp_path / "artifacts" / "email" / manifest["messages"][0]["eml_path"]
    eml_text = materialized.read_text(encoding="utf-8")

    submission_smtp = next(row for row in smtp_records if row["id.resp_p"] == 587)
    assert submission_smtp["tls"] is True
    assert submission_smtp["subject"] == ""
    assert submission_smtp["mailfrom"] == ""
    assert submission_smtp["rcptto"] == []
    assert submission_smtp["fuids"] == []
    assert submission_smtp["user_agent"] == ""
    assert submission_smtp["uid"] in {row["uid"] for row in ssl_records}
    plaintext_smtp = next(row for row in smtp_records if row["id.resp_p"] == 25 and not row["tls"])
    assert plaintext_smtp["subject"] == "Vendor AI summary"
    assert not plaintext_smtp["msg_id"].startswith("<00000000")
    assert "prompt-injection" not in plaintext_smtp["msg_id"]
    assert len(plaintext_smtp["fuids"]) == 2
    assert {row["fuid"] for row in file_records} >= set(plaintext_smtp["fuids"])
    assert [row["source"] for row in file_records if row["fuid"] in plaintext_smtp["fuids"]] == [
        "SMTP",
        "SMTP",
    ]
    assert {row["mime_type"] for row in file_records if row["fuid"] in plaintext_smtp["fuids"]} == {
        "text/plain"
    }
    file_by_fuid = {row["fuid"]: row for row in file_records}
    fuid_file_times = [file_by_fuid[fuid]["ts"] for fuid in plaintext_smtp["fuids"]]
    assert fuid_file_times == sorted(fuid_file_times)
    assert "X-Campaign-ID: ai-vendor-1" in eml_text
    assert "prompt.txt" in eml_text
    headers = _header_names(eml_text)
    assert headers[0] == "Received"
    assert headers.index("Return-Path") < headers.index("Date") < headers.index("From")
    assert headers.index("Subject") < headers.index("Thread-Topic")
    assert headers.index("X-Mailer") < headers.index("X-Campaign-ID")
    assert headers.index("X-Campaign-ID") < headers.index("Message-ID")
    assert headers.index("X-Campaign-ID") < headers.index("MIME-Version")
    assert 'boundary="===============' not in eml_text
    assert not re.fullmatch(
        r"<[0-9a-f]{16}@[0-9A-F]{8}\.corp\.example>",
        plaintext_smtp["msg_id"],
    )
    assert re.fullmatch(
        r"<[A-Z0-9.-]+@(?:[a-z0-9-]+\.)?corp\.example>",
        plaintext_smtp["msg_id"],
    )
    parsed_email = BytesParser(policy=policy.default).parsebytes(materialized.read_bytes())
    attachment_parts = {
        part.get_filename(): part.get_payload(decode=True)
        for part in parsed_email.walk()
        if part.get_filename()
    }
    prompt_payload = attachment_parts["prompt.txt"]
    prompt_file_row = next(row for row in file_records if row.get("filename") == "prompt.txt")
    assert prompt_file_row["seen_bytes"] == len(prompt_payload)
    assert prompt_file_row["md5"] == md5(prompt_payload, usedforsecurity=False).hexdigest()
    assert prompt_file_row["sha1"] == sha1(prompt_payload, usedforsecurity=False).hexdigest()
    assert prompt_file_row["sha256"] == sha256(prompt_payload).hexdigest()
    ecar_records = [
        row for path in (tmp_path / "data").rglob("ecar.json") for row in _read_ndjson(path)
    ]
    assert any(
        row.get("object") == "FILE"
        and row.get("action") == "READ"
        and row.get("principal") == "alice"
        and str(row.get("properties", {}).get("file_path", "")).endswith("prompt.txt")
        for row in ecar_records
    )


def test_office_email_attachment_payload_is_openxml_container(tmp_path: Path) -> None:
    scenario = _email_scenario()
    assert scenario.environment.email is not None
    scenario.environment.email.mail_servers[0].attempt_outbound_starttls = False
    scenario.environment.email.mail_servers[1].allow_inbound_starttls = False
    scenario = _with_email_storyline(
        scenario,
        EmailMessageEventSpec(
            to=["bob@corp.example"],
            subject="Invoice workbook",
            body="Please review the attached workbook.\n",
            attachments=[
                EmailAttachmentSpec(
                    filename="invoice_77821.xlsm",
                    content_type="application/vnd.ms-excel.sheet.macroEnabled.12",
                    size=32768,
                )
            ],
        ),
    )
    engine = GenerationEngine(
        scenario,
        output_dir=tmp_path / "data",
        ground_truth_dir=tmp_path,
        artifact_dir=tmp_path / "artifacts",
    )

    engine.generate()

    manifest = json.loads(
        (tmp_path / "artifacts" / "email" / "EMAIL_ARTIFACTS.json").read_text(encoding="utf-8")
    )
    materialized = tmp_path / "artifacts" / "email" / manifest["messages"][0]["eml_path"]
    message = BytesParser(policy=policy.default).parsebytes(materialized.read_bytes())
    attachment = next(message.iter_attachments())
    payload = attachment.get_payload(decode=True)
    assert payload.startswith(b"PK\x03\x04")
    assert b"email-attachment:" not in payload
    assert attachment.get_filename() == "invoice_77821.xlsm"


def test_rejected_email_stops_before_mime_artifacts_and_downstream_hops(tmp_path: Path) -> None:
    scenario = _email_scenario()
    assert scenario.environment.email is not None
    scenario.environment.email.artifacts = EmailArtifactsConfig(mode="all")
    scenario.environment.email.mail_servers[1].allow_inbound_starttls = False
    scenario = _with_email_storyline(
        scenario,
        EmailMessageEventSpec(
            sender="billing@vendorpost.net",
            to=["bob@corp.example"],
            subject="Rejected invoice",
            body="Invoice attached.\n",
            verdict="malware",
            mail_action="reject",
            outcome="rejected",
            attachments=[
                EmailAttachmentSpec(
                    filename="invoice_77821.xlsm",
                    content_type="application/vnd.ms-excel.sheet.macroEnabled.12",
                    size=32768,
                )
            ],
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
    assert len(smtp_records) == 1
    assert smtp_records[0]["last_reply"].startswith(("550", "554"))
    assert smtp_records[0]["fuids"] == []
    assert smtp_records[0]["id.resp_h"] == "10.10.2.26"
    files_path = tmp_path / "data" / "zeek-core" / "files.json"
    file_records = _read_ndjson(files_path) if files_path.exists() else []
    assert not any(row.get("source") == "SMTP" for row in file_records)
    assert not any(row.get("filename") == "invoice_77821.xlsm" for row in file_records)
    email_dir = tmp_path / "artifacts" / "email"
    assert not list(email_dir.glob("*.eml"))
    manifest = json.loads((email_dir / "EMAIL_ARTIFACTS.json").read_text(encoding="utf-8"))
    assert manifest["messages"][0]["eml_path"] == ""
    assert manifest["messages"][0]["artifact_export_status"] == "metadata_only"
    assert manifest["messages"][0]["artifact_export_reason"] == "transport_not_completed"


def test_service_email_artifact_uses_service_header_profile(tmp_path: Path) -> None:
    corpus_path = tmp_path / "email_corpus.yaml"
    corpus_path.write_text(
        """
messages:
  - id: docflow-notice
    subject: DocFlow generated package
    body: "The package is ready for review."
    user_agent: Microsoft Outlook 16.0
    headers:
      X-DocFlow-Workspace: contracts-2026
    attachments:
      - filename: notice.txt
        content_type: text/plain
        content: "Generated by DocFlow."
""".lstrip(),
        encoding="utf-8",
    )
    scenario = _email_scenario()
    assert scenario.environment.email is not None
    scenario.environment.email.corpus = "email_corpus.yaml"
    scenario = _with_email_storyline(
        scenario,
        EmailMessageEventSpec(
            sender="workspace@docflow-service.example",
            to=["bob@corp.example"],
            corpus_id="docflow-notice",
        ),
    )
    engine = GenerationEngine(
        scenario,
        output_dir=tmp_path / "data",
        ground_truth_dir=tmp_path,
        artifact_dir=tmp_path / "artifacts",
        scenario_root=tmp_path,
    )

    engine.generate()

    manifest = json.loads(
        (tmp_path / "artifacts" / "email" / "EMAIL_ARTIFACTS.json").read_text(encoding="utf-8")
    )
    materialized = tmp_path / "artifacts" / "email" / manifest["messages"][0]["eml_path"]
    eml_text = materialized.read_text(encoding="utf-8")
    headers = _header_names(eml_text)
    parsed_email = BytesParser(policy=policy.default).parsebytes(materialized.read_bytes())

    assert headers[0] == "Received"
    assert eml_text.count("Received:") >= 3
    assert "mail.example.net" not in eml_text
    assert public_safe_mail_hostname("docflow-service.example") in eml_text
    assert headers.index("Date") < headers.index("From")
    assert headers.index("Subject") < headers.index("Auto-Submitted")
    assert headers.index("X-DocFlow-Workspace") < headers.index("MIME-Version")
    assert headers.index("Auto-Submitted") < headers.index("X-Mailer")
    assert headers.index("X-DocFlow-Workspace") < headers.index("Message-ID")
    assert 'boundary="----=_Part_' in eml_text
    assert "X-Mailer: Workspace Mailer " in eml_text
    assert "Microsoft Outlook 16.0" not in eml_text
    assert "User-Agent:" not in eml_text
    assert re.fullmatch(
        r"<workspace-[0-9a-f]{8}-[0-9]{7}@docflow-service\.example>",
        parsed_email["Message-ID"],
    )
    assert parsed_email["X-DocFlow-Workspace"] == "contracts-2026"
    assert {
        part.get_filename(): part.get_payload(decode=True)
        for part in parsed_email.walk()
        if part.get_filename()
    } == {"notice.txt": b"Generated by DocFlow."}


def test_background_corpus_subjects_are_contextualized(tmp_path: Path) -> None:
    corpus_path = tmp_path / "email_corpus.yaml"
    corpus_path.write_text(
        """
messages:
  - id: recurring-parking
    subject: "Reminder: office parking renewals"
    body: "Parking renewals are due next week."
    user_agent: Microsoft Outlook 16.0
    background: true
    storyline: false
""".lstrip(),
        encoding="utf-8",
    )
    scenario = _email_scenario()
    assert scenario.environment.email is not None
    scenario.environment.email.corpus = "email_corpus.yaml"
    scenario.environment.email.background_messages_per_user_per_day = 24.0
    scenario = scenario.model_copy(
        update={
            "storyline": [],
            "time_window": TimeWindow(
                start="2026-01-05T14:00:00Z",
                duration="8h",
                warmup="1h",
            ),
        }
    )
    engine = GenerationEngine(
        scenario,
        output_dir=tmp_path / "data",
        ground_truth_dir=tmp_path,
        artifact_dir=tmp_path / "artifacts",
        scenario_root=tmp_path,
    )

    engine.generate()

    smtp_records = _read_ndjson(tmp_path / "data" / "zeek-core" / "smtp.json")
    corpus_subjects = [
        row["subject"]
        for row in smtp_records
        if row.get("subject") and "parking renewals" in row["subject"]
    ]
    assert len(corpus_subjects) >= 2
    assert "Reminder: office parking renewals" not in corpus_subjects
    assert len(set(corpus_subjects)) >= min(len(corpus_subjects), 2)


def test_email_read_event_generates_opaque_tls_access(tmp_path: Path) -> None:
    scenario = _email_scenario()
    assert scenario.environment.email is not None
    scenario.environment.email.mail_servers[1] = scenario.environment.email.mail_servers[
        1
    ].model_copy(update={"platform": "exchange"})
    scenario = scenario.model_copy(
        update={
            "storyline": [
                StorylineEvent(
                    id="read-email",
                    time="+15m",
                    actor="bob",
                    system="WS-BOB",
                    activity="Bob reads a mailbox message",
                    events=[
                        EmailReadEventSpec(
                            mailbox="bob@corp.example",
                            protocol="owa",
                            message_ids=["<message@example>"],
                            count=3,
                            duration=44.0,
                        )
                    ],
                )
            ]
        }
    )
    engine = GenerationEngine(
        scenario,
        output_dir=tmp_path / "data",
        ground_truth_dir=tmp_path,
        artifact_dir=tmp_path / "artifacts",
    )

    engine.generate()

    conn_records = _read_ndjson(tmp_path / "data" / "zeek-core" / "conn.json")
    smtp_path = tmp_path / "data" / "zeek-core" / "smtp.json"
    ground_truth = json.loads((tmp_path / "GROUND_TRUTH.json").read_text(encoding="utf-8"))

    assert any(
        row["id.orig_h"] == "10.10.1.11"
        and row["id.resp_h"] == "10.10.2.26"
        and row["id.resp_p"] == 443
        and row["service"] == "ssl"
        for row in conn_records
    )
    assert not smtp_path.exists()
    assert ground_truth["events"][0]["kind"] == "email_read"
    assert ground_truth["events"][0]["attributes"]["protocol"] == "owa"


def test_linux_imaps_read_emits_dovecot_session_syslog(tmp_path: Path) -> None:
    scenario = _email_scenario()
    assert scenario.environment.email is not None
    systems = [
        system.model_copy(update={"os": "Ubuntu 22.04"})
        if system.hostname == "MAIL-FIN"
        else system
        for system in scenario.environment.systems
    ]
    scenario = scenario.model_copy(
        update={
            "environment": scenario.environment.model_copy(update={"systems": systems}),
            "output": OutputSpec(
                logs=[{"format": "zeek"}, {"format": "syslog"}, {"format": "ecar"}],
                destination="./data",
            ),
            "storyline": [
                StorylineEvent(
                    id="read-imaps",
                    time="+15m",
                    actor="bob",
                    system="WS-BOB",
                    activity="Bob reads a mailbox message over IMAPS",
                    events=[
                        EmailReadEventSpec(
                            mailbox="bob@corp.example",
                            server="fin",
                            protocol="imaps",
                            message_ids=["<message@example>"],
                            count=2,
                            duration=38.0,
                        )
                    ],
                )
            ],
        }
    )
    engine = GenerationEngine(
        scenario,
        output_dir=tmp_path / "data",
        ground_truth_dir=tmp_path,
        artifact_dir=tmp_path / "artifacts",
    )

    engine.generate()

    conn_records = _read_ndjson(tmp_path / "data" / "zeek-core" / "conn.json")
    syslog_text = "\n".join(
        path.read_text(encoding="utf-8") for path in (tmp_path / "data").rglob("syslog.log")
    )

    assert any(
        row["id.orig_h"] == "10.10.1.11"
        and row["id.resp_h"] == "10.10.2.26"
        and row["id.resp_p"] == 993
        and row["service"] == "ssl"
        for row in conn_records
    )
    assert "dovecot" in syslog_text
    assert "imap-login: Login: user=<bob>, method=PLAIN" in syslog_text
    assert "rip=10.10.1.11, lip=10.10.2.26" in syslog_text
    assert "TLS, session=<" in syslog_text
    assert "imap(bob)<" in syslog_text
    assert "Disconnected: Logged out in=" in syslog_text
    assert syslog_text.index("imap-login: Login") < syslog_text.index("Disconnected: Logged out")


def test_email_storyline_events_count_as_causality_traces(tmp_path: Path) -> None:
    scenario = _email_scenario()
    assert scenario.environment.email is not None
    scenario.environment.email.mail_servers[1] = scenario.environment.email.mail_servers[
        1
    ].model_copy(update={"platform": "exchange"})
    scenario = scenario.model_copy(
        update={
            "storyline": [
                StorylineEvent(
                    id="email-step",
                    time="+10m",
                    actor="alice",
                    system="WS-ALICE",
                    activity="Alice sends Bob a message",
                    events=[
                        EmailMessageEventSpec(
                            to=["bob@corp.example"],
                            subject="Trace me",
                            body="This should count as a causality trace.\n",
                        )
                    ],
                ),
                StorylineEvent(
                    id="read-step",
                    time="+15m",
                    actor="bob",
                    system="WS-BOB",
                    activity="Bob reads his mailbox",
                    events=[
                        EmailReadEventSpec(
                            mailbox="bob@corp.example",
                            server="fin",
                            protocol="owa",
                            message_ids=["email-step"],
                            duration=30.0,
                        )
                    ],
                ),
            ]
        }
    )
    engine = GenerationEngine(
        scenario,
        output_dir=tmp_path / "data",
        ground_truth_dir=tmp_path,
        artifact_dir=tmp_path / "artifacts",
    )

    engine.generate()
    result = CausalityScorer().score(
        _parse_eval_records(tmp_path / "data"),
        scenario,
        EvaluationContext(email_ground_truth=_email_ground_truth(tmp_path / "data", scenario)),
    )

    event_presence = next(score for score in result.sub_scores if score.key == "event_presence")
    temporal_integrity = next(
        score for score in result.sub_scores if score.key == "temporal_integrity"
    )
    assert event_presence.score == 100.0
    assert event_presence.details.startswith("2/2 expected-visible storyline events")
    assert temporal_integrity.score == 100.0


def test_email_validator_reports_corpus_and_read_errors(tmp_path: Path) -> None:
    corpus_path = tmp_path / "email_corpus.yaml"
    corpus_path.write_text(
        """
messages:
  - id: duplicate
    subject: A
    body: B
  - id: duplicate
    subject: C
    body: D
""".lstrip(),
        encoding="utf-8",
    )
    scenario = _email_scenario()
    assert scenario.environment.email is not None
    scenario.environment.email.corpus = "email_corpus.yaml"
    scenario = scenario.model_copy(
        update={
            "storyline": [
                StorylineEvent(
                    id="bad-email",
                    time="+10m",
                    actor="alice",
                    system="WS-ALICE",
                    activity="Invalid email inputs",
                    events=[
                        EmailMessageEventSpec(
                            to=["bob@corp.example"],
                            corpus_id="missing",
                        ),
                        EmailReadEventSpec(
                            mailbox="nobody@corp.example",
                            server="missing",
                        ),
                    ],
                )
            ]
        }
    )

    issues = ScenarioValidator(scenario, scenario_root=tmp_path).validate()
    messages = "\n".join(issue.message for issue in issues)

    assert "Duplicate email corpus id 'duplicate'" in messages
    assert "references unknown corpus_id 'missing'" in messages
    assert "mailbox 'nobody@corp.example' is not a known user email" in messages


def test_background_email_generates_inbound_outbound_and_reads(tmp_path: Path) -> None:
    scenario = _email_scenario()
    assert scenario.environment.email is not None
    scenario.environment.email.background_messages_per_user_per_day = 24.0
    scenario = scenario.model_copy(
        update={
            "storyline": [],
            "time_window": TimeWindow(
                start="2026-01-05T14:00:00Z",
                duration="2h",
                warmup="1h",
            ),
        }
    )
    engine = GenerationEngine(
        scenario,
        output_dir=tmp_path / "data",
        ground_truth_dir=tmp_path,
        artifact_dir=tmp_path / "artifacts",
    )

    engine.generate()

    smtp_records = _read_ndjson(tmp_path / "data" / "zeek-core" / "smtp.json")
    conn_records = _read_ndjson(tmp_path / "data" / "zeek-core" / "conn.json")
    file_records = _read_ndjson(tmp_path / "data" / "zeek-core" / "files.json")
    manifest = json.loads(
        (tmp_path / "artifacts" / "email" / "EMAIL_ARTIFACTS.json").read_text(encoding="utf-8")
    )

    inbound_external_ips = [
        row["id.orig_h"]
        for row in smtp_records
        if row["id.resp_h"] in {"10.10.2.25", "10.10.2.26"}
        and not row["id.orig_h"].startswith("10.10.")
    ]
    outbound_external_ips = [
        row["id.resp_h"]
        for row in smtp_records
        if row["id.orig_h"] in {"10.10.2.25", "10.10.2.26"}
        and not row["id.resp_h"].startswith("10.10.")
    ]
    assert inbound_external_ips
    assert outbound_external_ips
    assert all(_is_global_non_test_net(ip) for ip in inbound_external_ips)
    assert all(_is_global_non_test_net(ip) for ip in outbound_external_ips)
    assert all(is_public_mail_ip(ip) for ip in inbound_external_ips)
    assert all(is_public_mail_ip(ip) for ip in outbound_external_ips)
    safe_hostname = public_safe_mail_hostname("smtp.isp.example")
    assert safe_hostname.startswith("smtp.isp.")
    assert not safe_hostname.endswith((".example", ".example.net", ".example.com", ".example.org"))
    assert "example.net" not in public_safe_mail_hostname("docflow-service.example.net")
    ptr_name = public_mail_ptr_name(outbound_external_ips[0], "smtp.isp.example")
    assert ptr_name
    assert not ptr_name.endswith(".example")
    assert any(row["id.resp_p"] in {443, 993} and row["service"] == "ssl" for row in conn_records)
    mail_conn_uids = {row["uid"] for row in conn_records if row.get("id.resp_p") in {25, 587}}
    smtp_uids = {row["uid"] for row in smtp_records}
    assert mail_conn_uids <= smtp_uids
    submission_rows = [row for row in smtp_records if row.get("id.resp_p") == 587]
    assert submission_rows
    assert all(row["tls"] is True for row in submission_rows)
    assert all(row["mailfrom"] == "" for row in submission_rows)
    assert all(row["user_agent"] == "" for row in submission_rows)
    leaked_fields = {"storyline_id", "artifact_id", "artifact_path", "verdict"}
    assert all(not (leaked_fields & set(message)) for message in manifest["messages"])
    visible_subjects = [row["subject"] for row in smtp_records if row.get("subject")]
    assert len(set(visible_subjects)) >= min(len(visible_subjects), 2)
    assert all(
        row.get("path") != [row["id.resp_h"], row["id.orig_h"]]
        for row in smtp_records
        if row.get("path")
    )
    msg_id_by_uid = {row["uid"]: row.get("msg_id", "") for row in smtp_records if row.get("msg_id")}
    body_hash_messages: dict[str, set[str]] = {}
    for row in file_records:
        if row.get("source") != "SMTP" or row.get("depth") != 0 or row.get("md5") is None:
            continue
        for uid in row.get("conn_uids", []):
            msg_id = msg_id_by_uid.get(uid)
            if msg_id:
                body_hash_messages.setdefault(row["md5"], set()).add(msg_id)
    assert all(len(message_ids) == 1 for message_ids in body_hash_messages.values())
    delivered_replies = [
        row["last_reply"]
        for row in smtp_records
        if str(row.get("last_reply", "")).startswith("250")
    ]
    assert delivered_replies
    assert len(set(delivered_replies)) >= min(len(delivered_replies), 2)
