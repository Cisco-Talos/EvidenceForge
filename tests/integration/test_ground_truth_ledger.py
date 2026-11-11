"""Journal reconciliation, DNS selection, and exact incremental recovery contracts."""

from __future__ import annotations

import json
from dataclasses import replace
from datetime import timedelta
from pathlib import Path

import pytest

from evidenceforge.events.base import OccurrenceBuilder
from evidenceforge.events.contexts import DnsContext, EmailContext, NatContext, SmtpContext
from evidenceforge.events.dispatcher import EventDispatcher
from evidenceforge.generation.checkpoints.sqlite_spool import SQLiteSpoolParticipant
from evidenceforge.generation.ground_truth_ledger import GroundTruthLedger
from evidenceforge.generation.intent_ledger import AuthoredIntentLedger, IntentExecutionLedger
from evidenceforge.generation.state_manager import StateManager
from evidenceforge.models.exceptions import StateError
from tests.integration.test_ground_truth_reconciliation import _download, _scenario
from tests.network_factories import network_plan


def _journal(root: Path) -> tuple[GroundTruthLedger, EventDispatcher, str]:
    authored = AuthoredIntentLedger.from_scenario(_scenario(root, [_download()]))
    execution = IntentExecutionLedger(authored)
    journal = GroundTruthLedger(authored)
    execution.ground_truth = journal
    dispatcher = EventDispatcher(StateManager(), {}, intent_execution_ledger=execution)
    intent_id = authored.intents[0].intent_id
    dispatcher.authored_intent_id = intent_id
    return journal, dispatcher, intent_id


def test_dns_keeps_all_answers_and_marks_used_subset_with_cache_reuse(tmp_path: Path) -> None:
    journal, dispatcher, _intent_id = _journal(tmp_path)
    try:
        dns_plan = network_plan(
            src_ip="10.0.10.10",
            src_port=53000,
            protocol="udp",
            dst_ip="9.9.9.9",
            dst_port=53,
            service="dns",
            zeek_uid="CdnsProbe",
            conn_state="SF",
        )
        dispatcher.dispatch_builder(
            OccurrenceBuilder(
                timestamp=dns_plan.started_at,
                event_type="connection",
                network=dns_plan,
                dns=DnsContext(
                    query="download-regression.example.net",
                    answers=["93.184.216.34", "93.184.216.35"],
                    TTLs=[300.0, 300.0],
                ),
            )
        )
        for index in (1, 2):
            plan = network_plan(
                src_ip="10.0.10.10",
                dst_ip="93.184.216.34",
                dst_port=8080,
                src_port=53000 + index,
                protocol="tcp",
                zeek_uid=f"Cconnection{index}",
                source_visible_start_time=dns_plan.started_at + timedelta(seconds=index),
            )
            plan = replace(plan, hostname="download-regression.example.net")
            journal.note_dns_resolution(
                client=plan.src_ip,
                domain=plan.hostname,
                selected_ip=plan.dst_ip,
                at=plan.started_at,
                resolver="9.9.9.9",
                cached=index == 2,
            )
            dispatcher.dispatch_builder(
                OccurrenceBuilder(timestamp=plan.started_at, event_type="connection", network=plan)
            )
        extra = network_plan(
            src_ip="10.0.10.10",
            src_port=53003,
            protocol="tcp",
            dst_ip="93.184.216.34",
            dst_port=8080,
            zeek_uid="Cstatic",
            source_visible_start_time=dns_plan.started_at + timedelta(seconds=3),
        )
        extra = replace(extra, hostname="download-regression.example.net")
        dispatcher.dispatch_builder(
            OccurrenceBuilder(timestamp=extra.started_at, event_type="connection", network=extra)
        )
        rows = list(journal.rows())
        dns = next(row for row in rows if row.facts.get("dns"))
        answers = next(item for item in dns.relationships if item.kind == "dns_answer_set")
        assert answers.facts == {
            "answers": ["93.184.216.34", "93.184.216.35"],
            "used_answer_ips": ["93.184.216.34"],
        }
        uses = [
            relation
            for row in rows
            for relation in row.relationships
            if relation.kind == "dns_answer_use"
        ]
        assert len(uses) == 2
        assert {item.facts["resolution_mode"] for item in uses} == {"lookup", "cache_hit"}
        assert all(item.facts["occurrence_id"] == dns.occurrence_id for item in uses)
    finally:
        journal.close()


def test_nat_preserves_public_destination_and_translated_tuple(tmp_path: Path) -> None:
    journal, dispatcher, _intent_id = _journal(tmp_path)
    try:
        plan = network_plan(
            src_ip="198.51.100.10",
            src_port=53000,
            dst_ip="10.0.20.10",
            dst_port=8080,
            protocol="tcp",
            zeek_uid="Cnat",
        )
        dispatcher.dispatch_builder(
            OccurrenceBuilder(
                timestamp=plan.started_at,
                event_type="connection",
                network=plan,
                nat=NatContext(
                    nat_type="static",
                    mapped_src_ip=plan.src_ip,
                    mapped_src_port=plan.src_port,
                    mapped_dst_ip=plan.dst_ip,
                    mapped_dst_port=plan.dst_port,
                    pre_nat_dst_ip="198.51.100.20",
                    pre_nat_dst_port=80,
                ),
            )
        )
        row = next(journal.rows())
        translation = next(item for item in row.relationships if item.kind == "address_translation")
        assert translation.facts["original"]["dst_ip"] == "198.51.100.20"
        assert translation.facts["original"]["dst_port"] == 80
        assert translation.facts["translated"]["dst_ip"] == "10.0.20.10"
        assert translation.facts["translated"]["dst_port"] == 8080
    finally:
        journal.close()


@pytest.mark.parametrize(
    "action,outcome,reply,result",
    [
        ("deliver", "delivered", "250 OK", "completed"),
        ("reject", "rejected", "550 Rejected", "prevented"),
        ("strip_attachment", "delivered", "250 OK", "partial"),
        ("deliver", "bounced", "550 No such recipient", "failed"),
    ],
)
def test_recipient_candidates_remain_distinct_from_actual_delivery_attempts(
    tmp_path: Path,
    action: str,
    outcome: str,
    reply: str,
    result: str,
) -> None:
    journal, dispatcher, _intent_id = _journal(tmp_path)
    try:
        plan = network_plan(
            src_ip="10.0.10.10",
            src_port=53000,
            dst_ip="10.0.20.10",
            dst_port=25,
            protocol="tcp",
            service="smtp",
            zeek_uid="Cmail",
        )
        dispatcher.dispatch_builder(
            OccurrenceBuilder(
                timestamp=plan.started_at,
                event_type="connection",
                network=plan,
                email=EmailContext(
                    message_id="<recipient-test@example.net>",
                    artifact_id="mail-test",
                    envelope_from="sender@example.net",
                    header_from="sender@example.net",
                    to=["group@example.net"],
                    expanded_rcptto=["one@example.net", "two@example.net"],
                    mail_action=action,
                    outcome=outcome,
                ),
                smtp=SmtpContext(
                    helo="sender.example.net",
                    mailfrom="sender@example.net",
                    rcptto=["one@example.net"],
                    date="Mon, 02 Nov 2026 10:00:00 +0000",
                    from_header="sender@example.net",
                    to_header=["group@example.net"],
                    msg_id="<recipient-test@example.net>",
                    subject="Test",
                    last_reply=reply,
                ),
            )
        )
        row = next(journal.rows())
        assert row.outcome.result == result
        delivery = next(item for item in row.relationships if item.kind == "recipient_delivery")
        assert delivery.facts["requested"]["to"] == ["group@example.net"]
        assert delivery.facts["expanded_recipients"] == ["one@example.net", "two@example.net"]
        assert delivery.facts["attempted_recipients"] == ["one@example.net"]
        assert delivery.facts["smtp_reply"] == reply
        assert delivery.facts["message_outcome"] == outcome
    finally:
        journal.close()


@pytest.mark.parametrize(
    "reason", ["no_live_parent_ref", "no_live_source_process", "no_matching_session", "not_emitted"]
)
def test_unexpected_unexecuted_intent_is_retained_and_fails(tmp_path: Path, reason: str) -> None:
    journal, _dispatcher, intent_id = _journal(tmp_path)
    try:
        with pytest.raises(StateError, match="could not execute"):
            journal.finish_intent(intent_id, {"skipped_reason": reason}, "process")
        assert journal.intent_results()[intent_id]["status"] == "not_executed"
        journal.write_failure_diagnostics(tmp_path)
        diagnostic = json.loads((tmp_path / "GROUND_TRUTH_DIAGNOSTICS.json").read_text())
        assert diagnostic["status"] == "failed"
        assert diagnostic["intent_outcomes"][intent_id]["reason"] == reason
        assert not (tmp_path / "GENERATION_MANIFEST.json").exists()
    finally:
        journal.close()


@pytest.mark.parametrize("outcome, expected", [("denied", "prevented"), ("exec_failed", "failed")])
def test_modeled_launch_attempt_does_not_invent_process_creation(
    tmp_path: Path, outcome: str, expected: str
) -> None:
    journal, _dispatcher, intent_id = _journal(tmp_path)
    try:
        plan = network_plan(
            src_ip="10.0.10.10",
            src_port=53000,
            protocol="tcp",
            dst_ip="93.184.216.34",
            dst_port=8080,
            zeek_uid="Cprobe",
        )
        journal.finish_intent(
            intent_id,
            {
                "time": plan.started_at,
                "outcome": outcome,
                "process_name": "/usr/bin/tool",
                "skipped_reason": "execution_denied_before_spawn"
                if outcome == "denied"
                else "exec_failed_caller_preserved",
            },
            "process",
        )
        (row,) = journal.rows()
        assert row.kind == "process_attempt"
        assert row.outcome.result == expected
        assert not row.source_expectations  # No process creation or native notification occurred.
        assert "process" not in row.facts
    finally:
        journal.close()


def test_legitimate_noop_has_no_fabricated_occurrence(tmp_path: Path) -> None:
    journal, _dispatcher, intent_id = _journal(tmp_path)
    try:
        journal.finish_intent(
            intent_id, {"skipped_reason": "workstation_already_locked"}, "workstation_lock"
        )
        journal.assert_complete()
        assert journal.intent_results()[intent_id]["status"] == "no_op"
        assert list(journal.rows()) == []
    finally:
        journal.close()


def test_source_staging_does_not_publish_canonical_ground_truth(tmp_path: Path) -> None:
    journal, dispatcher, _intent_id = _journal(tmp_path)
    try:
        plan = network_plan(
            src_ip="10.0.10.10",
            src_port=53000,
            protocol="tcp",
            dst_ip="93.184.216.34",
            dst_port=8080,
            zeek_uid="Cstage",
        )
        prepared = dispatcher.prepare_builder(
            OccurrenceBuilder(timestamp=plan.started_at, event_type="connection", network=plan)
        )
        dispatcher._publish_action_cohort_projection(prepared._projection)
        assert list(journal.rows()) == []
        dispatcher.publish_prepared(prepared)
        assert len(list(journal.rows())) == 1
    finally:
        journal.close()


def test_metadata_failure_cannot_be_hidden_by_later_source_recovery(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    journal, dispatcher, _intent_id = _journal(tmp_path)
    try:

        def unavailable(*args: object, **kwargs: object) -> None:
            raise OSError("injected journal write failure")

        monkeypatch.setattr(journal, "observe", unavailable)
        plan = network_plan(
            src_ip="10.0.10.10",
            src_port=53000,
            protocol="tcp",
            dst_ip="93.184.216.34",
            dst_port=8080,
            zeek_uid="Cfailure",
        )
        with pytest.raises(OSError, match="injected"):
            dispatcher.dispatch_builder(
                OccurrenceBuilder(timestamp=plan.started_at, event_type="connection", network=plan)
            )
        with pytest.raises(StateError, match="capture failed"):
            journal.assert_complete()
        with pytest.raises(StateError, match="Cannot checkpoint"):
            journal.checkpoint_connection()
    finally:
        journal.close()


def test_occurrence_journal_restores_and_continues_byte_identically(tmp_path: Path) -> None:
    source, dispatcher, _intent_id = _journal(tmp_path)
    restored, restored_dispatcher, _restored_id = _journal(tmp_path)
    try:
        participant = SQLiteSpoolParticipant(
            owner="ground-truth-occurrences",
            connection=source.checkpoint_connection,
            tables=source.tables,
        )
        plan = network_plan(
            src_ip="10.0.10.10",
            src_port=53000,
            protocol="tcp",
            dst_ip="93.184.216.34",
            dst_port=8080,
            zeek_uid="Cprobe",
        )
        dispatcher.dispatch_builder(
            OccurrenceBuilder(timestamp=plan.started_at, event_type="connection", network=plan)
        )
        sealed = participant.prepare_checkpoint(0)
        participant.checkpoint_committed(0)
        recovery = SQLiteSpoolParticipant(
            owner="ground-truth-occurrences",
            connection=restored.checkpoint_connection,
            tables=restored.tables,
            initialize_tracking=False,
        )
        recovery.restore_checkpoint(
            sealed.head.payload, tuple(item.payload for item in sealed.segments)
        )
        for current in (dispatcher, restored_dispatcher):
            later = replace(plan, stable_id=plan.stable_id + "-next", zeek_uid=plan.zeek_uid + "x")
            current.dispatch_builder(
                OccurrenceBuilder(
                    timestamp=later.started_at, event_type="connection", network=later
                )
            )
        source.export(tmp_path / "control")
        restored.export(tmp_path / "resumed")
        assert (tmp_path / "control/GROUND_TRUTH_EVENTS.jsonl").read_bytes() == (
            tmp_path / "resumed/GROUND_TRUTH_EVENTS.jsonl"
        ).read_bytes()
    finally:
        source.close()
        restored.close()


@pytest.mark.parametrize("inspected_https", [False, True])
def test_proxy_prevention_retains_leg_and_connect_semantics(
    tmp_path: Path, inspected_https: bool
) -> None:
    from datetime import UTC, datetime
    from unittest.mock import Mock

    from evidenceforge.events.contexts import HttpContext, ProxyContext
    from evidenceforge.models.scenario import NetworkSensor
    from tests.unit.test_explicit_proxy import _generator

    journal, dispatcher, intent_id = _journal(tmp_path)
    try:
        generator, emitters = _generator(
            [
                NetworkSensor(
                    type="network",
                    name="both-sides",
                    monitoring_segments=["workstations", "dmz"],
                    log_formats=["zeek"],
                )
            ]
        )
        generator.dispatcher.intent_execution_ledger = dispatcher.intent_execution_ledger
        generator.dispatcher.authored_intent_id = intent_id
        generator._build_proxy_context = Mock(
            return_value=ProxyContext(
                client_ip="10.0.1.10",
                method="GET",
                url=("https" if inspected_https else "http") + "://example.com/payload.exe",
                host="example.com",
                status_code=403,
                tunnel_status_code=200 if inspected_https else None,
                sc_bytes=1200,
                cs_bytes=420,
                time_taken=250,
                user_agent="Mozilla/5.0",
                content_type="text/html",
                cache_result="DENIED",
                referrer="-",
                proxy_fqdn="PROXY-01.example.org",
            )
        )
        generator.generate_connection(
            src_ip="10.0.1.10",
            dst_ip="93.184.216.34",
            time=datetime(2024, 1, 15, 10, tzinfo=UTC),
            dst_port=443 if inspected_https else 80,
            service="ssl" if inspected_https else "http",
            source_system=generator._ip_to_system["10.0.1.10"],
            hostname="example.com",
            http=HttpContext(method="GET", host="example.com", uri="/payload.exe", status_code=200),
            preserve_http_outcome=True,
        )
        rows = list(journal.rows())
        denial = next(row for row in rows if row.facts.get("proxy"))
        assert denial.outcome.result == "prevented"
        assert denial.outcome.mechanism == "proxy_policy"
        assert not any(
            row.facts.get("network", {}).get("src_ip") == "10.0.3.10"
            and row.facts.get("network", {}).get("dst_ip") == "93.184.216.34"
            for row in rows
        )
        rendered = emitters["zeek_http"].emit.call_args.args[0].protocol.http
        if inspected_https:
            assert rendered.method == "CONNECT" and rendered.status_code == 200
            assert denial.outcome.stage == "inspected_request"
        else:
            assert rendered.method == "GET" and rendered.status_code == 403
    finally:
        journal.close()
