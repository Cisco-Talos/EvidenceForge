"""Controls for defects exposed by the full shipping-example evaluations."""

from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from evidenceforge.evaluation.ground_truth_agreement import (
    _equal,
    _fields_match,
    _operation_selector,
    _RecordIndex,
)
from evidenceforge.evaluation.parsers import ParsedRecord
from evidenceforge.evaluation.pillars.plausibility import _coerce_key
from evidenceforge.events.evidence_projection import candidate_formats, native_requirements
from evidenceforge.events.ground_truth_occurrence import (
    GroundTruthOccurrence,
    GroundTruthSourceExpectation,
)
from tests.integration.test_ground_truth_reconciliation import _scenario


@pytest.mark.parametrize(
    ("actual", "expected", "matches"),
    [
        (True, True, True),
        (False, False, True),
        (False, True, False),
        (1, True, False),
        (0, False, False),
        ("T", True, True),
        ("false", False, True),
        (None, False, False),
    ],
)
def test_protocol_boolean_is_not_parsed_as_an_integer(
    actual: object, expected: bool, matches: bool
) -> None:
    assert _equal(actual, expected, "tls") is matches


@pytest.mark.parametrize("frozen", [False, True])
def test_distribution_boolean_keys_survive_configuration_capture(frozen: bool) -> None:
    reference = {"true": 0.9, "false": 0.1} if frozen else {True: 0.9, False: 0.1}
    assert reference[_coerce_key(True, reference)] == 0.9
    assert reference[_coerce_key(False, reference)] == 0.1
    assert _coerce_key("unknown", reference) not in reference


@pytest.mark.parametrize("actual", ["TXT 3 AbC", "AbC"])
def test_dns_txt_presentation_preserves_the_payload(actual: str) -> None:
    row = ParsedRecord(
        source_format="zeek_dns", raw="", fields={"qtype_name": "TXT", "answers": [actual]}
    )
    assert _fields_match(row, {"answers": ["AbC"]})
    assert not _fields_match(row, {"answers": ["abc"]})
    row.fields["qtype_name"] = "A"
    assert _fields_match(row, {"answers": [actual]})


def test_smb_audit_cardinality_is_scoped_to_the_file() -> None:
    requirements = native_requirements(
        "windows_event_security",
        "smb_file_open",
        {
            "smb": {
                "server_path": r"D:\Reviews\one.xlsx",
                "share_path": "one.xlsx",
                "result": "success",
                "audit": "high",
            },
            "auth": {"logon_id": "0x123", "username": "alice"},
        },
        {},
        "host",
        seed=42,
    )
    requirement = next(r for r in requirements if r.selector["EventID"] == 5145)
    selector = _operation_selector(
        requirement.selector, requirement.required, "windows_event_security"
    )
    rows = [
        ParsedRecord(
            source_format="windows_event_security",
            raw="",
            fields={
                "EventID": 5145,
                "SubjectLogonId": "0x123",
                "RelativeTargetName": path,
                "SubjectUserName": "alice",
            },
        )
        for path in ("one.xlsx", "two.xlsx", "three.xlsx")
    ]
    assert sum(_fields_match(r, selector) for r in rows) == 1
    rows.append(rows[0].model_copy(deep=True))
    assert sum(_fields_match(r, selector) for r in rows) == 2


def test_samba_logoff_matches_the_native_close_without_a_username() -> None:
    facts = {
        "dst_host": {"os_category": "linux"},
        "auth": {"session_kind": "smb", "username": "alice"},
        "smb": {"share_name": "Reviews"},
        "network": {"responding_pid": 1234},
    }
    (requirement,) = native_requirements("syslog", "logoff", facts, {}, "host")
    assert requirement.selector == {"app_name": "smbd", "pid": 1234}
    assert requirement.required == {"message": "closed connection to service Reviews"}
    del facts["smb"]
    del facts["network"]
    assert "syslog" in candidate_formats("logoff", facts)
    (legacy,) = native_requirements("syslog", "logoff", facts, {}, "host")
    assert legacy.selector == {"app_name": "smbd"}
    assert legacy.contains == ["closed connection to service "]


def test_web_request_identity_distinguishes_clients_in_the_same_second() -> None:
    facts = {
        "http": {"method": "GET", "uri": "/login", "status_code": 301},
        "network": {"src_ip": "192.0.2.3"},
    }
    (requirement,) = native_requirements("web_access", "connection", facts, {}, "host")
    records = [
        ParsedRecord(
            source_format="web_access",
            raw="",
            fields={"method": "GET", "path": "/login", "client_ip": ip},
        )
        for ip in ("192.0.2.2", "192.0.2.3")
    ]
    assert [_fields_match(row, requirement.selector) for row in records] == [False, True]


def test_history_identity_uses_the_native_second(tmp_path: Path) -> None:
    at = datetime(2026, 11, 9, 15, 0, 0, 700000, tzinfo=UTC)
    rows = [
        ParsedRecord(
            source_format="zsh_history",
            raw="id",
            timestamp=at.replace(microsecond=0) + timedelta(seconds=i),
            source_host="WS01",
            fields={"command": "id"},
        )
        for i in (0, 1, 2)
    ]
    index = _RecordIndex({"zsh_history": rows}, _scenario(tmp_path, []))
    occurrence = GroundTruthOccurrence(
        occurrence_id="one",
        action_id="action",
        intent_id="intent",
        storyline_id="story",
        section="storyline",
        kind="process_create",
        time=at,
        facts={},
    )
    expectation = GroundTruthSourceExpectation(
        expectation_id="e",
        source_instance="zsh_history:ws01",
        source_host="WS01",
        family="history",
        format="zsh_history",
        role="host",
        phase="process_create",
        expected="present",
        expected_time=at,
    )
    assert list(index.candidates(occurrence, expectation, {"command": "id"}, "point")) == [rows[0]]


def test_http_status_is_checked_after_a_unique_transaction_match() -> None:
    from evidenceforge.evaluation.pillars.plausibility import _build_pivot_index, _score_pair

    at = datetime(2026, 11, 9, tzinfo=UTC)
    pivot = {
        "a_fields": ["client_ip", "method", "path", "timestamp_bucket_10s"],
        "b_fields": ["id.orig_h", "method", "uri", "ts_bucket_10s"],
        "time_window_seconds": 2,
        "matching": "one_to_one",
    }
    left = [
        ParsedRecord(
            source_format="web_access",
            raw="",
            timestamp=at + timedelta(seconds=s),
            fields={"client_ip": "10.0.0.1", "method": "GET", "path": "/", "status_code": code},
        )
        for s, code in [(0, 200), (8, 404)]
    ]
    right = [
        ParsedRecord(
            source_format="zeek_http",
            raw="",
            timestamp=at + timedelta(seconds=s + 0.1),
            fields={"id.orig_h": "10.0.0.1", "method": "GET", "uri": "/", "status_code": code},
        )
        for s, code in [(0, 200), (8, 404)]
    ]
    fields = [{"a_field": "status_code", "b_field": "status_code"}]
    assert _score_pair("web", left, _build_pivot_index(right, pivot), pivot, fields)[:2] == (2, 2)
    right[1].fields["status_code"] = 200
    assert _score_pair("web", left, _build_pivot_index(right, pivot), pivot, fields)[:2] == (2, 1)
    right.append(right[0].model_copy(deep=True))
    diagnostics: dict[str, int] = {}
    _score_pair(
        "web", left, _build_pivot_index(right, pivot), pivot, fields, diagnostics=diagnostics
    )
    assert diagnostics["ambiguous"] == 1


@pytest.mark.parametrize("missing_bytes,expected", [(3, 0), (0, 1)])
def test_incomplete_ocsp_capture_is_not_a_cryptographic_identity_failure(
    missing_bytes: int, expected: int
) -> None:
    from evidenceforge.evaluation.pillars.plausibility import (
        _score_cryptographic_protocol_consistency,
    )

    records = {
        "zeek_http": [
            ParsedRecord(
                source_format="zeek_http",
                raw="",
                fields={
                    "resp_mime_types": ["application/ocsp-response"],
                    "resp_fuids": ["F1"],
                    "uri": "/invalid",
                },
            )
        ],
        "zeek_files": [
            ParsedRecord(
                source_format="zeek_files",
                raw="",
                fields={
                    "fuid": "F1",
                    "seen_bytes": 100 - missing_bytes,
                    "total_bytes": 100,
                    "missing_bytes": missing_bytes,
                },
            )
        ],
    }
    diagnostics: dict[str, int] = {}
    checks, agreeing, failures = _score_cryptographic_protocol_consistency(
        records, diagnostics=diagnostics
    )
    assert checks == expected
    assert agreeing == 0
    assert bool(failures) == bool(expected)
    assert diagnostics.get("partial_ocsp", 0) == int(missing_bytes > 0)


def test_suppressed_ids_candidates_require_the_exact_admitted_stream() -> None:
    from evidenceforge.evaluation.ids_policy import verified_filtered_signatures
    from tests.unit.test_eval_ids_integrity import _document, _record

    record = _record()
    doc = _document(record)
    signature = doc.ids_evaluation.sensors["ids-edge"]["1:2028401"]
    signature.candidate = 3
    signature.policy_filtered = 2
    assert verified_filtered_signatures(doc, {"snort_alert": [record]}) == {
        ("ids-edge", 1, 2028401)
    }
    assert not verified_filtered_signatures(doc, {"snort_alert": []})
    changed = record.model_copy(update={"fields": record.fields | {"dst_port": 8443}})
    assert not verified_filtered_signatures(doc, {"snort_alert": [changed]})


def test_mounted_read_does_not_advance_a_phantom_delete_clock() -> None:
    from evidenceforge.events.evidence_source_rules import ecar_smb_projection_phases

    source = {"hostname": "LINUX", "os_category": "linux"}
    destination = {"hostname": "SERVER"}
    smb = {
        "operation": "read",
        "phase": "read",
        "client_access": "cifs_mount",
        "client_path": "/mnt/reviews/one",
    }
    assert ecar_smb_projection_phases(
        "smb_file_read", smb, source, destination, {"pid": 42}, "LINUX"
    ) == ("client_file",)
    assert ecar_smb_projection_phases(
        "smb_file_read", smb, source, destination, {"pid": 42}, "SERVER"
    ) == ("base",)
    assert (
        ecar_smb_projection_phases("smb_file_read", smb, source, destination, {"pid": 42}, "OTHER")
        == ()
    )


def test_linux_client_has_no_windows_server_samba_projection() -> None:
    from evidenceforge.events.evidence_source_rules import semantic_source_admission

    facts = {
        "src_host": {"os_category": "linux"},
        "dst_host": {"os_category": "windows"},
        "smb": {"provider": "windows", "server_platform": "windows"},
        "network": {"protocol": "tcp"},
    }
    assert not semantic_source_admission("syslog", "smb_tree_connect", facts)
    assert not semantic_source_admission("cisco_asa", "smb_tree_connect", facts)
    assert semantic_source_admission("cisco_asa", "connection", facts)
    facts["network"]["application_layer_only"] = True
    assert not semantic_source_admission("cisco_asa", "connection", facts)


def test_dns_txt_chunks_are_concatenated_only_when_each_length_is_valid() -> None:
    row = ParsedRecord(source_format="zeek_dns", raw="", fields={"qtype_name": "TXT"})
    row.fields["answers"] = ["TXT 3 AbC TXT 3 dEf"]
    assert _fields_match(row, {"answers": ["AbCdEf"]})
    assert not _fields_match(row, {"answers": ["abcdef"]})
    row.fields["answers"] = ["TXT 4 AbC TXT 3 dEf"]
    assert not _fields_match(row, {"answers": ["AbCdEf"]})


def test_all_filtered_ids_signature_proves_an_empty_stream(tmp_path: Path) -> None:
    from evidenceforge.evaluation.context import EvaluationContext
    from evidenceforge.evaluation.ids_policy import verified_filtered_signatures
    from evidenceforge.evaluation.pillars.plausibility import PlausibilityScorer
    from evidenceforge.events.ids_evaluation import new_ids_digest
    from tests.unit.test_eval_ids_integrity import _document, _record

    document = _document(_record())
    signature = document.ids_evaluation.sensors["ids-edge"]["1:2028401"]
    signature.emitted = signature.emitted_visible = 0
    signature.policy_filtered = 1
    signature.emitted_sha256 = new_ids_digest().hexdigest()
    document.ids_evaluation.observation = {"filtered": 1}
    document.source_evidence_status = {"ids-edge": {"ids": {"filtered": 1}}}
    scenario = _scenario(tmp_path, [])
    scorer = PlausibilityScorer()
    context = EvaluationContext(ground_truth=document)
    assert scorer._score_ids_integrity({}, scenario, context).score == 100
    assert verified_filtered_signatures(document, {}) == {("ids-edge", 1, 2028401)}
    assert scorer._score_ids_integrity({"snort_alert": [_record()]}, scenario, context).score < 100


@pytest.mark.parametrize("spill", [False, True])
def test_anomaly_population_excludes_injections_and_unsupported_native_rows(
    tmp_path: Path, spill: bool
) -> None:
    from evidenceforge.evaluation.anomaly import detect_anomalies
    from evidenceforge.evaluation.storage import (
        EvaluationWorkspace,
        evaluation_workspace,
        record_identity,
    )

    scenario = _scenario(tmp_path, [])
    process = ParsedRecord(
        source_format="windows_event_sysmon",
        raw="background",
        source_host="WS01",
        timestamp=datetime(2026, 11, 9, 14, tzinfo=UTC),
        fields={"EventID": 1, "User": "alice", "Image": r"C:\Windows\explorer.exe"},
    )
    attack = process.model_copy(update={"raw": "authored", "line_number": 2})
    unsupported = ParsedRecord(source_format="macos_endpoint_security", raw="native", fields={})
    rows = {
        "windows_event_sysmon": [attack, process],
        "macos_endpoint_security": [unsupported] * 20,
    }
    workspace = EvaluationWorkspace(1 if spill else 256 * 1024 * 1024, tmp_path)
    try:
        with evaluation_workspace(workspace):
            diagnostics: dict[str, int] = {}
            assert (
                detect_anomalies(
                    rows,
                    scenario,
                    excluded_record_ids={record_identity(attack)},
                    diagnostics=diagnostics,
                )[1]
                == 1
            )
            assert diagnostics["eligible"] == 1
            assert detect_anomalies({"macos_endpoint_security": [unsupported]}, scenario) == (0, 0)
    finally:
        workspace.close()


def test_platform_reference_does_not_compare_linux_with_windows_mix(tmp_path: Path) -> None:
    from evidenceforge.evaluation.pillars.plausibility import distribution_profile_applies

    scenario = _scenario(tmp_path, [])
    row = ParsedRecord(source_format="ecar", raw="", source_host="WS01", fields={})
    assert distribution_profile_applies(row, {"platforms": ["windows"]}, scenario)
    scenario.environment.systems[0].os = "Ubuntu 24.04"
    assert not distribution_profile_applies(row, {"platforms": ["windows"]}, scenario)
    assert distribution_profile_applies(row, {"platforms": ["linux"]}, scenario)


def test_anomaly_hours_use_the_observed_hosts_timezone(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from evidenceforge.evaluation import anomaly
    from evidenceforge.models.scenario import Timezone

    scenario = _scenario(tmp_path, [])
    scenario.environment.timezone = Timezone(default="UTC", systems={"WS01": "Asia/Tokyo"})
    monkeypatch.setattr(anomaly, "_build_persona_hours", lambda _: {"alice": list(range(9, 18))})
    row = ParsedRecord(
        source_format="windows_event_sysmon",
        source_host="ws01.example.org",
        raw="",
        timestamp=datetime(2026, 11, 9, 17, tzinfo=UTC),
        fields={"EventID": 1, "User": r"EXAMPLE\alice", "Image": "editor.exe"},
    )
    rows = [row, row.model_copy(update={"raw": "second", "line_number": 2})]
    assert anomaly.detect_anomalies({"windows_event_sysmon": rows}, scenario) == (2, 2)
    scenario.environment.timezone = Timezone(default="UTC")
    assert anomaly.detect_anomalies({"windows_event_sysmon": rows}, scenario) == (0, 2)


def test_unrelated_tasks_cannot_supply_each_others_repetitions() -> None:
    from evidenceforge.evaluation.pillars.timing import TimingScorer

    at = datetime(2026, 11, 9, tzinfo=UTC)
    rows = [
        ParsedRecord(
            source_format="syslog",
            source_host="LINUX",
            raw="",
            timestamp=at + timedelta(minutes=i),
            fields={"app_name": "cron", "message": f"(root) CMD (/usr/local/bin/job-{i % 2})"},
        )
        for i in range(12)
    ]
    assert TimingScorer()._score_system_regularity({"syslog": rows}).skipped
    for row in rows:
        row.fields["message"] = "(root) CMD (/usr/local/bin/job-1)"
    score = TimingScorer()._score_system_regularity({"syslog": rows})
    assert score.score == 100
    rows[-1].timestamp = at + timedelta(days=100)
    assert TimingScorer()._score_system_regularity({"syslog": rows}).score < 100


def test_http_join_requires_the_correct_server_or_its_static_nat_alias(tmp_path: Path) -> None:
    from evidenceforge.evaluation.pillars.plausibility import (
        _http_server_addresses,
        _http_server_matches,
    )
    from evidenceforge.models.scenario import NatRule

    scenario = _scenario(tmp_path, [])
    scenario.environment.network.sensors[0].nat_rules = [
        NatRule(type="static", real_ip="10.0.10.10", mapped_ip="203.0.113.10")
    ]
    source = ParsedRecord(
        source_format="web_access", raw="", source_host="WS01.example.org", fields={}
    )
    matching = ParsedRecord(source_format="zeek_http", raw="", fields={"id.resp_h": "203.0.113.10"})
    addresses = _http_server_addresses(scenario)
    assert _http_server_matches(source, matching, addresses)
    matching.fields["id.resp_h"] = "203.0.113.20"
    assert not _http_server_matches(source, matching, addresses)


def test_smb_source_admission_names_only_phases_observed_on_that_endpoint() -> None:
    from evidenceforge.events.evidence_source_rules import semantic_source_admission

    facts = {
        "src_host": {"hostname": "LINUX", "os_category": "linux"},
        "dst_host": {"hostname": "SERVER", "os_category": "windows"},
        "process": {"pid": 42},
        "smb": {
            "phase": "read",
            "operation": "read",
            "result": "success",
            "client_path": "/mnt/reviews/one",
            "client_access": "cifs_mount",
        },
        "network": {"application_layer_only": True},
    }
    assert semantic_source_admission("ecar", "smb_file_read", facts, "linux")
    assert semantic_source_admission("ecar", "smb_file_read", facts, "server")
    assert not semantic_source_admission("ecar", "connection", facts, "linux")
    facts["smb"]["client_access"] = "windows_unc"
    assert not semantic_source_admission("ecar", "smb_file_read", facts, "linux")
    assert semantic_source_admission("ecar", "smb_file_read", facts, "server")
    facts["firewall"] = {"action": "deny"}
    assert not semantic_source_admission("ecar", "smb_file_read", facts, "server")


def test_ecar_file_cardinality_distinguishes_simultaneous_files() -> None:
    selector = _operation_selector(
        {"object": "FILE", "action": "READ"}, {"file_path": "/reviews/one"}, "ecar"
    )
    rows = [
        ParsedRecord(
            source_format="ecar",
            raw="",
            fields={"object": "FILE", "action": "READ", "file_path": f"/reviews/{name}"},
        )
        for name in ("one", "two", "three")
    ]
    assert sum(_fields_match(row, selector) for row in rows) == 1
    rows.append(rows[0].model_copy(deep=True))
    assert sum(_fields_match(row, selector) for row in rows) == 2


def test_frozen_generation_defaults_do_not_restore_an_obsolete_evaluator(tmp_path: Path) -> None:
    from evidenceforge.composition.models import EffectiveConfig
    from evidenceforge.config.provider import effective_config_scope
    from evidenceforge.evaluation.rules import load_rules_file

    installed = load_rules_file("distributions.yaml")
    captured = EffectiveConfig(
        project_root=str(tmp_path),
        packaged_defaults={"evaluation/distributions.yaml": {"obsolete": True}},
    )
    with effective_config_scope(captured, refresh_legacy_globals=False):
        assert load_rules_file("distributions.yaml") == installed
    assert load_rules_file("distributions.yaml") == installed


def test_authored_process_source_cannot_displace_background_process_coverage(
    tmp_path: Path,
) -> None:
    from evidenceforge.evaluation.anomaly import detect_anomalies
    from evidenceforge.evaluation.storage import record_identity

    injected = ParsedRecord(
        source_format="windows_event_sysmon",
        source_host="WS01",
        raw="attack",
        fields={"EventID": 1, "Image": "payload.exe"},
    )
    background = ParsedRecord(
        source_format="ecar",
        source_host="WS01",
        raw="background",
        fields={"object": "PROCESS", "action": "CREATE", "image_path": "editor.exe"},
    )
    records = {"windows_event_sysmon": [injected], "ecar": [background]}
    assert (
        detect_anomalies(
            records, _scenario(tmp_path, []), excluded_record_ids={record_identity(injected)}
        )[1]
        == 1
    )


def test_smb_overwrites_at_one_path_keep_distinct_retained_file_identities() -> None:
    facts = {"smb": {"file_id": "remote-file", "local_file_id": "local-first"}}
    selector = _operation_selector(
        {"object": "FILE", "action": "CREATE"},
        {"file_path": r"C:\Reports\care-plan.docx"},
        "ecar",
        facts,
        role="source_endpoint",
    )
    rows = [
        ParsedRecord(
            source_format="ecar",
            raw="",
            fields={
                "object": "FILE",
                "action": "CREATE",
                "file_path": r"C:\Reports\care-plan.docx",
                "objectID": identity,
            },
        )
        for identity in ("local-first", "local-second")
    ]
    assert sum(_fields_match(row, selector) for row in rows) == 1
    rows.append(rows[0].model_copy(deep=True))
    assert sum(_fields_match(row, selector) for row in rows) == 2


def test_dkim_cryptographic_check_uses_the_shared_chunked_txt_decoder() -> None:
    from evidenceforge.evaluation.pillars.plausibility import (
        _score_cryptographic_protocol_consistency,
    )
    from evidenceforge.generation.activity.dns_txt import stable_dns_txt_record

    text, _ttl = stable_dns_txt_record("selector._domainkey.example.org")
    wire = " ".join(
        f"TXT {len(text[i : i + 255])} {text[i : i + 255]}" for i in range(0, len(text), 255)
    )
    record = ParsedRecord(
        source_format="zeek_dns",
        raw="",
        fields={
            "query": "selector._domainkey.example.org",
            "qtype_name": "TXT",
            "answers": [wire],
        },
    )
    assert _score_cryptographic_protocol_consistency({"zeek_dns": [record]}) == (1, 1, [])
    record.fields["answers"] = [wire.replace("p=", "p=!")]
    assert _score_cryptographic_protocol_consistency({"zeek_dns": [record]})[1] == 0


def test_trace_coverage_excludes_only_proven_unrendered_ids_candidates(tmp_path: Path) -> None:
    from evidenceforge.evaluation.context import EvaluationContext
    from evidenceforge.evaluation.ground_truth_agreement import (
        ActionAgreement,
        GroundTruthAgreementResult,
    )
    from evidenceforge.evaluation.pillars.causality import CausalityScorer
    from evidenceforge.evaluation.visibility import VisibilityModel

    action = ActionAgreement(
        intent_id="intent", storyline_id="story", fact_checks=3, found=1, policy_only_checks=2
    )
    scorer = CausalityScorer()
    scorer._canonical_agreement = GroundTruthAgreementResult(score=100, actions=[action])
    visibility = VisibilityModel(_scenario(tmp_path, []), set())
    assert (
        scorer._score_storyline_trace_coverage([], visibility, {}, EvaluationContext()).score == 100
    )
    action.found = 0
    assert (
        scorer._score_storyline_trace_coverage([], visibility, {}, EvaluationContext()).score == 0
    )
    action.fact_checks = action.policy_only_checks
    unmeasured = scorer._score_storyline_trace_coverage([], visibility, {}, EvaluationContext())
    assert unmeasured.score is None and unmeasured.skipped
