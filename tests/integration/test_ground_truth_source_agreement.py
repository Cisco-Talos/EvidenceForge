"""Fault injection across authored intent, source expectations and native evidence."""

from __future__ import annotations

import hashlib
from copy import deepcopy
from pathlib import Path

import pytest

from evidenceforge.evaluation.engine import EvaluationEngine
from evidenceforge.evaluation.ground_truth_agreement import evaluate_ground_truth
from evidenceforge.events.ground_truth import GroundTruthDocument
from evidenceforge.events.ground_truth_occurrence import GroundTruthEventStream
from evidenceforge.generation.engine import GenerationEngine
from evidenceforge.models.scenario import NetworkSensor
from tests.integration.test_ground_truth_reconciliation import _download, _scenario, _truth


@pytest.fixture(scope="module")
def source_bundle(tmp_path_factory: pytest.TempPathFactory) -> tuple:
    root = tmp_path_factory.mktemp("source-agreement")
    events = [
        {**_download(), "status_code": 403},
        {
            **_download(),
            "type": "beacon",
            "count": 3,
            "interval": "5s",
            "jitter": 0,
            "uri": "/beacon",
            "status_code": 200,
        },
        {
            "type": "process",
            "process_name": r"C:\Windows\System32\cmd.exe",
            "command_line": "cmd.exe /c echo diagnostic",
        },
        {"type": "failed_logon", "source_ip": "10.0.10.99"},
        {
            "type": "dns_query",
            "query": "multi.example.net",
            "answer": ["93.184.216.34", "93.184.216.35"],
            "ttl": 300,
        },
    ]
    scenario = _scenario(
        root, events, formats=["zeek", "ecar", "windows_event_security", "windows_event_sysmon"]
    )
    scenario.environment.network.sensors.append(
        NetworkSensor(
            type="network", name="second-tap", monitoring_segments=["clients"], log_formats=["zeek"]
        )
    )
    GenerationEngine(scenario, root).generate()
    document, rows = _truth(root)
    records, _ = EvaluationEngine(root, scenario)._parse_all_logs()
    return root, scenario, document, rows, records


def _audit(
    bundle: tuple,
    root: Path,
    *,
    rows: list | None = None,
    records: dict | None = None,
    document: GroundTruthDocument | None = None,
):
    _original, scenario, original_document, original_rows, original_records = bundle
    selected = rows if rows is not None else original_rows
    root.mkdir(exist_ok=True)
    payload = b"".join((row.model_dump_json() + "\n").encode() for row in selected)
    (root / "GROUND_TRUTH_EVENTS.jsonl").write_bytes(payload)
    reference = GroundTruthEventStream(
        count=len(selected), sha256=hashlib.sha256(payload).hexdigest()
    )
    doc = (document or original_document).model_copy(update={"event_stream": reference})
    return evaluate_ground_truth(
        root, doc, scenario, original_records if records is None else records
    )[0]


def test_all_sources_and_instances_agree(source_bundle: tuple, tmp_path: Path) -> None:
    result = _audit(source_bundle, tmp_path)
    assert result.score == 100, result.findings
    assert result.correct > 20
    root, scenario, _, _, _ = source_bundle
    report = EvaluationEngine(root, scenario).run()
    assert len(report.pillars) == 5
    assert [pillar.weight for pillar in report.pillars] == [0.2] * 5
    assert report.supplementary["ground_truth_agreement"]["score"] == 100


@pytest.mark.parametrize("sources", [["client-tap"], ["client-tap", "second-tap"]])
def test_each_missing_source_is_its_own_check(
    source_bundle: tuple, tmp_path: Path, sources: list[str]
) -> None:
    records = deepcopy(source_bundle[4])
    records["zeek_http"] = [
        record
        for record in records["zeek_http"]
        if (record.source_host or record.source_instance) not in sources
    ]
    result = _audit(source_bundle, tmp_path, records=records)
    assert result.score < 100
    missing = {
        item["source_instance"] for item in result.findings if item["rule"] == "missing_evidence"
    }
    assert {"zeek:" + source for source in sources} <= missing
    assert all(action.score == 100 for action in result.actions[2:])


def test_optional_fields_do_not_dilute_required_fact_disagreement(
    source_bundle: tuple, tmp_path: Path
) -> None:
    records = deepcopy(source_bundle[4])
    record = next(
        record for record in records["zeek_http"] if record.fields["uri"] == "/payload.exe"
    )
    record.fields["status_code"] = 599
    record.fields.update({f"optional_{index}": "correct" for index in range(100)})
    result = _audit(source_bundle, tmp_path, records=records)
    assert result.incorrect == 1
    assert result.failure_counts["factual_disagreement"] == 1
    assert any(item["details"]["evidence"][0]["line"] for item in result.findings)


def test_omitted_expectation_and_its_log_cannot_hide_a_defect(
    source_bundle: tuple, tmp_path: Path
) -> None:
    rows = list(source_bundle[3])
    index = next(i for i, row in enumerate(rows) if row.facts.get("http"))
    row = rows[index]
    missing = next(item for item in row.source_expectations if item.format == "zeek_http")
    rows[index] = row.model_copy(
        update={
            "source_expectations": [item for item in row.source_expectations if item != missing]
        }
    )
    records = deepcopy(source_bundle[4])
    records["zeek_http"] = [
        record
        for record in records["zeek_http"]
        if record.fields.get("uid") != missing.identifiers["zeek_uid"]
    ]
    result = _audit(source_bundle, tmp_path, rows=rows, records=records)
    assert result.failure_counts["missing_source_expectation"] == 1


def test_false_loss_reason_is_independently_rejected(source_bundle: tuple, tmp_path: Path) -> None:
    rows = deepcopy(source_bundle[3])
    index = next(i for i, row in enumerate(rows) if row.facts.get("http"))
    row = rows[index]
    expectation = next(item for item in row.source_expectations if item.format == "zeek_http")
    conditions = [
        item.model_copy(update={"state": "excluded", "reason": "modeled_collection_loss"})
        if item.stage == "loss"
        else item
        for item in expectation.conditions
    ]
    loss = dict(expectation.provenance["loss"], probability=1.0, dropped=True)
    changed = expectation.model_copy(
        update={
            "expected": "absent",
            "reason": "modeled_collection_loss",
            "conditions": conditions,
            "provenance": {"contract_version": 1, "loss": loss},
        }
    )
    rows[index] = row.model_copy(
        update={
            "source_expectations": [
                changed if item == expectation else item for item in row.source_expectations
            ]
        }
    )
    records = deepcopy(source_bundle[4])
    records["zeek_http"] = [
        record
        for record in records["zeek_http"]
        if record.fields.get("uid") != expectation.identifiers["zeek_uid"]
    ]
    result = _audit(source_bundle, tmp_path, rows=rows, records=records)
    assert result.failure_counts["loss_probability_policy_disagreement"] == 1


def test_consistent_ground_truth_and_logs_cannot_override_authored_status(
    source_bundle: tuple, tmp_path: Path
) -> None:
    rows = deepcopy(source_bundle[3])
    records = deepcopy(source_bundle[4])
    for index, row in enumerate(rows):
        if (row.facts.get("http") or {}).get("uri") != "/payload.exe":
            continue
        facts = deepcopy(row.facts)
        facts["http"]["status_code"] = 599
        expectations = []
        for item in row.source_expectations:
            requirements = deepcopy(item.requirements)
            for requirement in requirements:
                if "status_code" in requirement["required"]:
                    requirement["required"]["status_code"] = 599
            expectations.append(item.model_copy(update={"requirements": requirements}))
        rows[index] = row.model_copy(update={"facts": facts, "source_expectations": expectations})
    for record in records["zeek_http"]:
        if record.fields.get("uri") == "/payload.exe":
            record.fields["status_code"] = 599
    result = _audit(source_bundle, tmp_path, rows=rows, records=records)
    assert result.failure_counts["authored_http_status_disagreement"]


def test_missing_contract_is_not_a_zero_check_success(source_bundle: tuple, tmp_path: Path) -> None:
    document = source_bundle[2].model_copy(update={"expectation_contract": None})
    result = _audit(source_bundle, tmp_path, document=document)
    assert result.score < 100
    assert result.failure_counts["missing_or_invalid_expectation_contract"] == len(result.actions)


def test_schema_v4_uses_legacy_weights_without_fabricating_agreement(
    source_bundle: tuple, tmp_path: Path
) -> None:
    # Legacy readers are exercised separately from the authoritative v5 bundle.
    from evidenceforge.evaluation.context import EvaluationContext
    from evidenceforge.evaluation.pillars.causality import CausalityScorer

    document = source_bundle[2].model_copy(
        update={"schema_version": 4, "event_stream": None, "expectation_contract": None}
    )
    assert EvaluationContext(ground_truth=document).ground_truth.schema_version == 4
    score = CausalityScorer._score_intent_reconciliation(
        source_bundle[1], EvaluationContext(ground_truth=document, ground_truth_root=tmp_path)
    )
    assert score.score is not None


def test_actions_have_equal_weight_despite_sequence_size(
    source_bundle: tuple, tmp_path: Path
) -> None:
    records = deepcopy(source_bundle[4])
    record = next(item for item in records["zeek_http"] if item.fields["uri"] == "/payload.exe")
    record.fields["status_code"] = 599
    result = _audit(source_bundle, tmp_path, records=records)
    assert len({action.correct + action.incorrect for action in result.actions}) > 1
    assert result.score == pytest.approx(
        sum(action.score for action in result.actions) / len(result.actions)
    )
    assert result.score != pytest.approx(100 * result.correct / (result.correct + result.incorrect))


def test_duplicate_matching_record_is_one_failed_projection(
    source_bundle: tuple, tmp_path: Path
) -> None:
    records = deepcopy(source_bundle[4])
    records["zeek_http"].append(deepcopy(records["zeek_http"][0]))
    result = _audit(source_bundle, tmp_path, records=records)
    assert result.incorrect == 1
    assert result.failure_counts["missing_or_duplicate_evidence"] == 1


def test_expected_absence_in_one_source_does_not_excuse_another(tmp_path: Path) -> None:
    from evidenceforge.models.scenario import SourceObservationOverride

    scenario = _scenario(tmp_path, [_download()], formats=["zeek", "ecar"])
    scenario.version = "2.0"
    scenario.environment.network.sensors.append(
        NetworkSensor(
            type="network", name="lost-tap", monitoring_segments=["clients"], log_formats=["zeek"]
        )
    )
    scenario.environment.observation_overrides = [
        SourceObservationOverride(source_instance="zeek:lost-tap", missingness=1)
    ]
    GenerationEngine(scenario, tmp_path).generate()
    document, rows = _truth(tmp_path)
    records, _ = EvaluationEngine(tmp_path, scenario)._parse_all_logs()
    result, _ = evaluate_ground_truth(tmp_path, document, scenario, records)
    assert result.score == 100, result.findings
    assert result.expected_absences
    assert all(
        item.expected == "absent"
        for row in rows
        for item in row.source_expectations
        if item.source_instance == "zeek:lost-tap"
    )
    excluded = next(
        item
        for row in rows
        for item in row.source_expectations
        if item.source_instance == "zeek:lost-tap" and item.format == "zeek_http"
    )
    unexpected = records["zeek_http"][0].model_copy(deep=True)
    unexpected.source_instance = "lost-tap"
    unexpected.source_host = None
    unexpected.fields["uid"] = excluded.identifiers["zeek_uid"]
    unexpected.fields["status_code"] = 599
    records["zeek_http"].append(unexpected)
    result, _ = evaluate_ground_truth(tmp_path, document, scenario, records)
    assert result.incorrect == 1
    assert result.failure_counts["unexpected_evidence"] == 1
    records["zeek_http"].pop()
    records["ecar"] = []
    result, _ = evaluate_ground_truth(tmp_path, document, scenario, records)
    assert result.incorrect
    assert any(finding["source_instance"] == "ecar:ws01" for finding in result.findings)


@pytest.mark.parametrize("kind", ["no_authored_actions", "no_sensor"])
def test_legitimate_zero_checks_score_100_with_scope(tmp_path: Path, kind: str) -> None:
    scenario = _scenario(tmp_path, [_download()], formats=["zeek_conn"])
    if kind == "no_authored_actions":
        scenario.storyline = []
    else:
        scenario.environment.network.sensors = []
    GenerationEngine(scenario, tmp_path).generate()
    document, _ = _truth(tmp_path)
    records, _ = EvaluationEngine(tmp_path, scenario)._parse_all_logs()
    result, _ = evaluate_ground_truth(tmp_path, document, scenario, records)
    assert result.score == 100, result.findings
    assert result.correct == result.incorrect == 0
    if kind == "no_sensor":
        assert result.actions[0].zero_check_reason == "no_configured_source"
        assert result.coverage_gaps
    else:
        assert result.actions == []


def test_95_percent_threshold_and_immediately_below(tmp_path: Path) -> None:
    from evidenceforge.evaluation.engine import _build_acceptance_criteria
    from evidenceforge.evaluation.models import PillarScore, SubScore
    from evidenceforge.evaluation.thresholds import load_thresholds
    from evidenceforge.generation.ground_truth_expectations import scenario_contract_digest
    from evidenceforge.generation.intent_ledger import AuthoredIntentLedger

    root = tmp_path / "bundle"
    events = [
        {
            "type": "connection",
            "dst_ip": "93.184.216.34",
            "dst_port": 4000 + index,
            "service": "tcp",
        }
        for index in range(20)
    ]
    scenario = _scenario(root, events, formats=["zeek_conn"])
    GenerationEngine(scenario, root).generate()
    document, rows = _truth(root)
    records, _ = EvaluationEngine(root, scenario)._parse_all_logs()
    baseline, bindings = evaluate_ground_truth(root, document, scenario, records)
    assert baseline.score == 100, baseline.findings
    broken_id = baseline.actions[0].intent_id
    removed = {id(record) for record in bindings[broken_id]}
    damaged = {
        fmt: [record for record in items if id(record) not in removed]
        for fmt, items in records.items()
    }
    result, _ = evaluate_ground_truth(root, document, scenario, damaged)
    assert result.score == 95
    trimmed = scenario.model_copy(deep=True)
    trimmed.storyline[0].events.pop()
    retained = AuthoredIntentLedger.from_scenario(trimmed).intent_ids
    filtered = [row for row in rows if row.intent_id in retained]
    contract = document.expectation_contract.model_copy(
        update={"scenario_sha256": scenario_contract_digest(trimmed)}
    )
    trimmed_doc = document.model_copy(update={"expectation_contract": contract})
    second = _audit((root, trimmed, trimmed_doc, filtered, damaged), tmp_path / "nineteen")
    assert second.score == pytest.approx(100 * 18 / 19)
    for score, passed in [(result.score, True), (second.score, False)]:
        pillar = PillarScore(
            number=5,
            name="Ground Truth Agreement",
            weight=0.2,
            score=score,
            sub_scores=[
                SubScore(
                    name="Ground Truth Agreement",
                    key="ground_truth_agreement",
                    weight=1,
                    score=score,
                )
            ],
        )
        criterion = next(
            item
            for item in _build_acceptance_criteria(load_thresholds(), [pillar])
            if item.sub_score_key == "ground_truth_agreement"
        )
        assert criterion.passed is passed


def test_legacy_report_keeps_original_four_weights(
    source_bundle: tuple, monkeypatch: pytest.MonkeyPatch
) -> None:
    import evidenceforge.evaluation.engine as module

    root, scenario, document, _, _ = source_bundle
    legacy = document.model_copy(
        update={"schema_version": 3, "event_stream": None, "expectation_contract": None}
    )
    monkeypatch.setattr(module, "load_ground_truth_document", lambda *args: legacy)
    report = EvaluationEngine(root, scenario).run()
    assert [pillar.weight for pillar in report.pillars] == [0.30, 0.25, 0.25, 0.20]
    assert "ground_truth_agreement" not in report.supplementary
    assert "limitation" in report.supplementary["ground_truth_coverage"]


def test_relationship_corruption_is_reported_even_when_logs_match(
    source_bundle: tuple, tmp_path: Path
) -> None:
    rows = deepcopy(source_bundle[3])
    index = next(i for i, row in enumerate(rows) if row.facts.get("dns"))
    row = rows[index]
    links = [
        link.model_copy(update={"facts": {**link.facts, "used_answer_ips": ["203.0.113.99"]}})
        if link.kind == "dns_answer_set"
        else link
        for link in row.relationships
    ]
    rows[index] = row.model_copy(update={"relationships": links})
    result = _audit(source_bundle, tmp_path, rows=rows)
    assert result.failure_counts["canonical_relationship_disagreement"] == 1


@pytest.mark.parametrize("inspected", [False, True])
def test_proxy_denial_reconciles_connect_request_and_prevents_origin(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, inspected: bool
) -> None:
    from dataclasses import replace

    from evidenceforge.generation.activity.generator import ActivityGenerator
    from evidenceforge.models.scenario import NetworkSegment, ProxyConfig, System

    host = "proxy-denial.example.net"
    event = {
        **_download(),
        "hostname": host,
        "dst_port": 443 if inspected else 80,
        "service": "ssl" if inspected else "http",
        "status_code": 200,
    }
    scenario = _scenario(tmp_path, [event], formats=["zeek", "proxy_access", "ecar"])
    scenario.environment.proxy = ProxyConfig(mode="explicit")
    scenario.environment.systems.append(
        System(
            hostname="PROXY",
            ip="10.0.20.10",
            os="Ubuntu 24.04",
            type="server",
            roles=["forward_proxy"],
        )
    )
    scenario.environment.network.segments.extend(
        [
            NetworkSegment(
                name="proxy", cidr="10.0.20.0/24", exposure="internal", systems=["PROXY"]
            ),
            NetworkSegment(name="origin", cidr="93.184.216.0/24", exposure="external"),
        ]
    )
    scenario.environment.network.sensors.append(
        NetworkSensor(
            type="network", name="origin-tap", monitoring_segments=["origin"], log_formats=["zeek"]
        )
    )
    original = ActivityGenerator._build_proxy_context

    def deny(self, *args, **kwargs):
        context = original(self, *args, **kwargs)
        if context is not None and context.host == host:
            return replace(
                context,
                status_code=403,
                tunnel_status_code=200 if inspected else None,
                cache_result="DENIED",
            )
        return context

    monkeypatch.setattr(ActivityGenerator, "_build_proxy_context", deny)
    GenerationEngine(scenario, tmp_path).generate()
    document, rows = _truth(tmp_path)
    records, _ = EvaluationEngine(tmp_path, scenario)._parse_all_logs()
    denial = next(row for row in rows if (row.facts.get("proxy") or {}).get("host") == host)
    assert denial.outcome.result == "prevented"
    assert not any(
        (row.facts.get("network") or {}).get("src_ip") == "10.0.20.10"
        and (row.facts.get("network") or {}).get("dst_ip") == event["dst_ip"]
        for row in rows
    )
    if inspected:
        assert any(
            record.fields.get("method") == "CONNECT" and record.fields.get("status_code") == 200
            for record in records["proxy_access"]
        )
        assert any(
            record.fields.get("method") == "GET" and record.fields.get("status_code") == 403
            for record in records["proxy_access"]
        )
    result, _ = evaluate_ground_truth(tmp_path, document, scenario, records)
    assert result.score == 100, result.findings


def test_simultaneous_restrictions_remain_separate_and_exact(tmp_path: Path) -> None:
    from evidenceforge.models.scenario import NetworkSegment, SourceObservationOverride

    scenario = _scenario(tmp_path, [_download()], formats=["ecar"])
    scenario.version = "2.0"
    scenario.environment.network.segments.append(
        NetworkSegment(name="remote", cidr="10.0.99.0/24", exposure="internal")
    )
    scenario.environment.network.sensors.append(
        NetworkSensor(
            type="network",
            name="excluded-tap",
            monitoring_segments=["remote"],
            log_formats=["zeek"],
        )
    )
    scenario.environment.observation_overrides = [
        SourceObservationOverride(
            source_instance="zeek:excluded-tap",
            enabled=False,
            capabilities=[],
            windows=[],
            missingness=1,
        )
    ]
    GenerationEngine(scenario, tmp_path).generate()
    document, rows = _truth(tmp_path)
    http = next(row for row in rows if row.facts.get("http"))
    expectation = next(
        item
        for item in http.source_expectations
        if item.source_instance == "zeek:excluded-tap" and item.format == "zeek_http"
    )
    assert expectation.expected == "absent" and expectation.reason == "source_disabled"
    excluded = {
        condition.stage for condition in expectation.conditions if condition.state == "excluded"
    }
    assert {"deployment", "placement", "capability", "window", "export"} <= excluded
    assert (
        next(condition for condition in expectation.conditions if condition.stage == "loss").state
        == "unknown"
    )
    records, _ = EvaluationEngine(tmp_path, scenario)._parse_all_logs()
    result, _ = evaluate_ground_truth(tmp_path, document, scenario, records)
    assert result.score == 100, result.findings


def test_packet_capture_receipts_cannot_excuse_invented_loss(
    source_bundle: tuple, tmp_path: Path
) -> None:
    rows = deepcopy(source_bundle[3])
    index = next(i for i, row in enumerate(rows) if row.source_views and row.facts.get("http"))
    row = rows[index]
    source_id = next(iter(row.source_views))
    views = deepcopy(row.source_views)
    view = views[source_id]
    traffic = deepcopy(view.traffic)
    traffic["missed_resp_bytes"] += 1
    views[source_id] = view.model_copy(update={"traffic": traffic})
    rows[index] = row.model_copy(update={"source_views": views})
    result = _audit(source_bundle, tmp_path, rows=rows)
    assert result.failure_counts["invalid_packet_loss_receipt"]


def test_firewall_build_and_close_are_one_projection_check(tmp_path: Path) -> None:
    scenario = _scenario(
        tmp_path,
        [
            {
                "type": "beacon",
                "dst_ip": "93.184.216.34",
                "dst_port": 4444,
                "action": "allow",
                "interval": "5s",
                "count": 1,
            }
        ],
        formats=["zeek", "cisco_asa"],
    )
    scenario.environment.network.sensors.append(
        NetworkSensor(
            type="firewall",
            name="edge",
            monitoring_segments=["clients"],
            log_formats=["cisco_asa"],
            default_action="permit",
            deny_ratio=0,
        )
    )
    GenerationEngine(scenario, tmp_path).generate()
    document, _ = _truth(tmp_path)
    records, _ = EvaluationEngine(tmp_path, scenario)._parse_all_logs()
    result, _ = evaluate_ground_truth(tmp_path, document, scenario, records)
    assert result.score == 100, result.findings
    assert any(record.fields.get("msg_id") == 302014 for record in records["cisco_asa"])
    records["cisco_asa"] = [
        record for record in records["cisco_asa"] if record.fields.get("msg_id") != 302014
    ]
    result, _ = evaluate_ground_truth(tmp_path, document, scenario, records)
    assert result.incorrect == 1


def test_same_host_connection_has_one_endpoint_projection(tmp_path: Path) -> None:
    scenario = _scenario(
        tmp_path,
        [{"type": "connection", "dst_ip": "10.0.10.10", "dst_port": 4444, "service": "tcp"}],
        formats=["ecar"],
    )
    GenerationEngine(scenario, tmp_path).generate()
    document, rows = _truth(tmp_path)
    records, _ = EvaluationEngine(tmp_path, scenario)._parse_all_logs()
    flow = next(row for row in rows if row.kind == "connection")
    assert {item.role for item in flow.source_expectations if item.format == "ecar"} == {
        "source_endpoint",
    }
    result, _ = evaluate_ground_truth(tmp_path, document, scenario, records)
    assert result.score == 100, result.findings


def test_raw_source_local_receipt_and_false_loss_explanation(tmp_path: Path) -> None:
    scenario = _scenario(
        tmp_path,
        [
            {
                "type": "raw",
                "target_format": "syslog",
                "fields": {
                    "app_name": "diagnostic",
                    "message": "raw contract probe",
                    "facility": 3,
                    "severity": 6,
                },
            }
        ],
        formats=["syslog"],
    )
    GenerationEngine(scenario, tmp_path).generate()
    document, _ = _truth(tmp_path)
    records, _ = EvaluationEngine(tmp_path, scenario)._parse_all_logs()
    result, _ = evaluate_ground_truth(tmp_path, document, scenario, records)
    assert result.score == 100, result.findings
    assert result.correct == 1
    document = document.model_copy(deep=True)
    outcome = next(iter(document.intent_outcomes.values()))
    outcome["raw_expectation"]["status"] = "dropped"
    result, _ = evaluate_ground_truth(tmp_path, document, scenario, {})
    assert result.incorrect == 1
    assert result.score == 0


def test_registered_account_and_service_facts_reconcile(tmp_path: Path) -> None:
    scenario = _scenario(
        tmp_path,
        [
            {"type": "account_created", "target_username": "temporary.user"},
            {"type": "account_deleted", "target_username": "temporary.user"},
            {
                "type": "group_member_added",
                "group_name": "Administrators",
                "member_name": "alice",
                "scope": "local",
            },
            {
                "type": "service_installed",
                "service_name": "DiagnosticService",
                "service_file_name": r"C:\Windows\System32\cmd.exe",
            },
            {"type": "scheduled_task_created", "task_name": r"\DiagnosticTask"},
        ],
        formats=["windows_event_security", "windows_event_sysmon", "ecar"],
    )
    GenerationEngine(scenario, tmp_path).generate()
    document, _ = _truth(tmp_path)
    records, _ = EvaluationEngine(tmp_path, scenario)._parse_all_logs()
    result, _ = evaluate_ground_truth(tmp_path, document, scenario, records)
    assert result.score == 100, result.findings
    assert len(result.actions) == 5


def test_no_sensor_does_not_excuse_wrong_canonical_authored_status(tmp_path: Path) -> None:
    scenario = _scenario(tmp_path, [{**_download(), "status_code": 403}], formats=["zeek"])
    scenario.environment.network.sensors = []
    GenerationEngine(scenario, tmp_path).generate()
    document, rows = _truth(tmp_path)
    for row in rows:
        if row.facts.get("http"):
            row.facts["http"]["status_code"] = 200
    result = _audit((tmp_path, scenario, document, rows, {}), tmp_path / "mutated")
    assert result.incorrect > 0
    assert "authored_http_status_disagreement" in result.failure_counts


def test_adjacent_native_dns_queries_and_empty_answers_have_distinct_checks(tmp_path: Path) -> None:
    scenario = _scenario(
        tmp_path,
        [
            {**_download(), "hostname": "www.google.com", "dst_port": 80, "status_code": 403},
            {"type": "dns_query", "query": "missing.example.net", "rcode": "NXDOMAIN"},
        ],
        formats=["zeek", "windows_event_sysmon"],
    )
    scenario.generation_seed = 42
    GenerationEngine(scenario, tmp_path).generate()
    document, _ = _truth(tmp_path)
    records, _ = EvaluationEngine(tmp_path, scenario)._parse_all_logs()
    result, _ = evaluate_ground_truth(tmp_path, document, scenario, records)
    assert result.score == 100, result.findings
    query = next(
        record
        for record in records["windows_event_sysmon"]
        if record.fields.get("QueryName") == "missing.example.net"
    )
    assert query.fields["QueryResults"] == "-"
    records["windows_event_sysmon"].append(query.model_copy(deep=True))
    result, _ = evaluate_ground_truth(tmp_path, document, scenario, records)
    assert result.incorrect == 1
    records["windows_event_sysmon"].pop()
    query.fields["QueryStatus"] = "0"
    result, _ = evaluate_ground_truth(tmp_path, document, scenario, records)
    assert result.incorrect == 1
    assert "factual_disagreement" in result.failure_counts


@pytest.mark.slow
@pytest.mark.parametrize(
    "mail_action,outcome",
    [("deliver", "delivered"), ("reject", "rejected"), ("strip_attachment", "delivered")],
)
def test_email_delivery_prevention_and_partial_outcomes_reconcile(
    tmp_path: Path, mail_action: str, outcome: str
) -> None:
    from evidenceforge.models.scenario import EmailMessageEventSpec, OutputSpec
    from tests.unit.test_email_evidence import _email_scenario

    scenario = _email_scenario()
    scenario.time_window.duration = "2m"
    scenario.storyline[0].time = "+10s"
    scenario.storyline[0].events = [
        EmailMessageEventSpec(
            sender="billing@vendorpost.net",
            to=["bob@corp.example"],
            subject="Diagnostic mail",
            body="Synthetic message",
            mail_action=mail_action,
            outcome=outcome,
            attachments=[
                {
                    "filename": "probe.txt",
                    "content_type": "text/plain",
                    "content": "Synthetic attachment",
                }
            ],
        )
    ]
    scenario.output = OutputSpec(
        logs=[{"format": "zeek"}, {"format": "ecar"}, {"format": "windows"}],
        destination=str(tmp_path),
        compression=False,
    )
    GenerationEngine(scenario, tmp_path).generate()
    document, _ = _truth(tmp_path)
    records, _ = EvaluationEngine(tmp_path, scenario)._parse_all_logs()
    result, _ = evaluate_ground_truth(tmp_path, document, scenario, records)
    assert result.score == 100, result.findings


@pytest.mark.slow
@pytest.mark.parametrize("outcome", ["success", "access_denied", "high_audit"])
def test_storage_operation_and_authorization_reconcile(
    tmp_path: Path, scenarios_dir: Path, outcome: str
) -> None:
    from evidenceforge.models.scenario import Scenario
    from tests.integration.test_smb_generation import _base_scenario

    data = _base_scenario(scenarios_dir)
    data["time_window"]["duration"] = "2m"
    data["storyline"] = [
        {
            "id": "storage",
            "time": "+10s",
            "actor": "test_user",
            "system": "TEST-01",
            "activity": "Storage contract",
            "events": [
                {
                    "type": "smb_activity",
                    "operation": "read",
                    "target": {"type": "share", "share": "FS-01.finance", "file_ref": "forecast"},
                    "outcome": "success" if outcome == "high_audit" else outcome,
                }
            ],
        }
    ]
    if outcome == "high_audit":
        data["environment"]["storage"]["servers"][0]["audit"] = "high"
    if outcome == "access_denied":
        data["environment"]["storage"]["servers"][0]["shares"][0]["access"] = {
            "deny": ["test_user"]
        }
    data["output"]["compression"] = False
    scenario = Scenario.model_validate(data)
    GenerationEngine(scenario, tmp_path).generate()
    document, rows = _truth(tmp_path)
    records, _ = EvaluationEngine(tmp_path, scenario)._parse_all_logs()
    result, _ = evaluate_ground_truth(tmp_path, document, scenario, records)
    assert result.score == 100, result.findings

    if outcome == "success":
        result = _audit(
            (tmp_path, scenario, document, rows, records),
            tmp_path / "missing-read",
            rows=[row for row in rows if row.kind != "smb_file_read"],
        )
        assert "missing_required_storage_consequence" in result.failure_counts


@pytest.mark.parametrize("name", ["ground-truth-regression", "registry-consequences"])
def test_registry_consequences_reconcile_and_reject_factual_corruption(
    tmp_path: Path, name: str
) -> None:
    scenario = _scenario(
        tmp_path,
        [
            {
                "type": "process",
                "process_name": r"C:\Windows\System32\reg.exe",
                "command_line": f"reg.exe query HKCU\\Software\\Probe{i}",
            }
            for i in range(5)
        ],
        formats=["ecar", "windows_event_sysmon"],
    )
    scenario.name = name
    scenario.generation_seed = 42
    GenerationEngine(scenario, tmp_path).generate()
    document, rows = _truth(tmp_path)
    assert any(row.kind == "registry_modify" for row in rows)
    records, _ = EvaluationEngine(tmp_path, scenario)._parse_all_logs()
    result, _ = evaluate_ground_truth(tmp_path, document, scenario, records)
    assert result.score == 100, result.findings
    record = next(record for record in records["ecar"] if record.fields.get("object") == "REGISTRY")
    record.fields["registry_key"] = r"HKLM\Software\Incorrect"
    result, _ = evaluate_ground_truth(tmp_path, document, scenario, records)
    assert result.incorrect > 0
