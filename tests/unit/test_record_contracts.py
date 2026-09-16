# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Regression proofs for schema, predicate, parser, and scoring boundaries."""

import json
from pathlib import Path
from unittest.mock import patch

import pytest
from pydantic import ValidationError

from evidenceforge.evaluation.parsers import ParsedRecord, get_parser
from evidenceforge.evaluation.pillars.parseability import ParseabilityScorer, _get_variant
from evidenceforge.formats.format_def import FieldConstraint, FieldDefinition, FieldType
from evidenceforge.formats.loader import load_all_formats, load_format
from evidenceforge.formats.rules import RecordRule, evaluate_rule
from evidenceforge.formats.validator import validate_event, validate_field
from evidenceforge.models.exceptions import ConfigurationError


def dns_record() -> dict:
    return {
        "ts": 1750000000.0,
        "uid": "C12345678901234567",
        "id.orig_h": "10.0.0.1",
        "id.orig_p": 12345,
        "id.resp_h": "10.0.0.2",
        "id.resp_p": 53,
        "proto": "udp",
        "trans_id": 1,
        "query": "example.com",
        "qtype": 1,
        "qtype_name": "A",
        "rcode": 0,
        "rcode_name": "NOERROR",
        "AA": False,
        "TC": False,
        "RD": True,
        "RA": True,
        "Z": 0,
        "answers": ["10.0.0.3"],
        "TTLs": [60.0],
        "rejected": False,
        "opcode": 0,
        "opcode_name": "query",
        "rtt": 0.02,
    }


@pytest.mark.parametrize(
    "change",
    [
        {"qtype_name": "AAAA"},
        {"rcode_name": "NXDOMAIN"},
        {"TTLs": []},
        {"TTLs": ["sixty"]},
        {"answers": [42]},
        {"rtt": "bad"},
        {"rtt": -1.0},
    ],
)
def test_corrupted_dns_fails_through_parser_and_scoring(change: dict) -> None:
    scorer = ParseabilityScorer()
    parser = get_parser("zeek_dns")
    good = parser._parse_line(json.dumps(dns_record()), 1)
    bad = parser._parse_line(json.dumps(dns_record() | change), 2)
    assert scorer._score_spec_conformance({"zeek_dns": [good]}).score == 100
    assert scorer._score_format_constraints({"zeek_dns": [good]}).score == 100
    scores = [
        scorer._score_spec_conformance({"zeek_dns": [bad]}),
        scorer._score_format_constraints({"zeek_dns": [bad]}),
    ]
    assert any(score.score < 100 for score in scores)


@pytest.mark.parametrize("value", [True, "1", None, float("nan"), float("inf"), []])
def test_float_rejects_nonfinite_or_nonnumeric(value: object) -> None:
    field = FieldDefinition(name="duration", type=FieldType.FLOAT)
    assert not validate_field(field, value).valid


def test_float_bounds_apply_and_zero_is_valid() -> None:
    field = FieldDefinition(
        name="duration", type=FieldType.FLOAT, constraints=FieldConstraint(min_value=0)
    )
    assert validate_field(field, 0.0).valid
    assert not validate_field(field, -0.1).valid


@pytest.mark.parametrize("format_name", sorted(load_all_formats()))
def test_every_format_loads_and_rejects_missing_required_fields(format_name: str) -> None:
    definition = load_format(format_name)
    assert not validate_event(definition, {}).valid
    assert len({r.id for r in definition.validators or []}) == len(definition.validators or [])


@pytest.mark.parametrize(
    "check",
    [
        {"op": "typo", "field": "x"},
        {"op": "presence", "field": "x", "minimum": 0},
        {"op": "compare", "field": "x", "relation": "eq"},
        {"op": "compare", "field": "x", "relation": "eq", "value": 1, "other_field": "y"},
        {"op": "bounds", "field": "x", "minimum": 5, "maximum": 1},
        {"op": "pattern", "field": "x", "pattern": "["},
    ],
)
def test_malformed_predicates_fail_loading(check: dict) -> None:
    with pytest.raises(ValidationError):
        RecordRule(id="test", message="test", checks=[check])


@pytest.mark.parametrize(
    "check,good,bad",
    [
        ({"op": "presence", "field": "x"}, {"x": 0}, {}),
        ({"op": "presence", "field": "x", "present": False}, {}, {"x": 0}),
        (
            {"op": "compare", "field": "x", "relation": "lt", "other_field": "y"},
            {"x": 1, "y": 2},
            {"x": 2, "y": 1},
        ),
        (
            {"op": "compare", "field": "id.orig_h", "relation": "eq", "value": "10.0.0.1"},
            {"id.orig_h": "10.0.0.1"},
            {"id": {"orig_h": "10.0.0.1"}},
        ),
        (
            {"op": "membership", "field": "x", "values": ["tcp", "udp"]},
            {"x": "tcp"},
            {"x": "other"},
        ),
        ({"op": "bounds", "field": "x", "minimum": 0}, {"x": 0.0}, {"x": -0.1}),
        ({"op": "length", "field": "x", "minimum": 1}, {"x": "a"}, {"x": ""}),
        ({"op": "pattern", "field": "x", "pattern": "^a$"}, {"x": "a"}, {"x": "ab"}),
        (
            {"op": "same_length", "field": "x", "other_field": "y"},
            {"x": [1], "y": [2]},
            {"x": [1], "y": []},
        ),
        (
            {"op": "combination", "field": "x", "other_field": "y", "pairs": [["FILE", "RENAME"]]},
            {"x": "FILE", "y": "RENAME"},
            {"x": "FILE", "y": "LOGIN"},
        ),
        (
            {"op": "address_family", "field": "x", "other_field": "y"},
            {"x": "::1", "y": "true"},
            {"x": "127.0.0.1", "y": "true"},
        ),
    ],
)
def test_predicate_positive_negative_and_applicability(check: dict, good: dict, bad: dict) -> None:
    rule = RecordRule(id="test", message="test", checks=[check])
    assert evaluate_rule(rule, good, "test", None).outcome == "pass"
    assert evaluate_rule(rule, bad, "test", None).outcome == "fail"
    conditional = rule.model_copy(
        update={
            "when": (
                RecordRule(
                    id="condition",
                    message="condition",
                    checks=[{"op": "presence", "field": "enabled"}],
                ).checks[0],
            )
        }
    )
    assert evaluate_rule(conditional, good, "test", None).outcome == "not_applicable"


def test_bad_schema_is_not_a_perfect_score() -> None:
    record = ParsedRecord(source_format="zeek_dns", raw="{}", fields={})
    with patch(
        "evidenceforge.evaluation.pillars.parseability.load_format",
        side_effect=ConfigurationError("broken schema"),
    ):
        with pytest.raises(ConfigurationError):
            ParseabilityScorer()._score_spec_conformance({"zeek_dns": [record]})


@pytest.mark.parametrize(
    "format_name,raw",
    [
        ("zeek_dns", "[]"),
        ("zeek_dns", '{"ts":Infinity}'),
        ("zeek_dns", '{"ts":1,"ts":2}'),
        ("ecar", "[]"),
        ("ecar", '{"properties":[]}'),
        ("ecar", '{"object":"FILE","properties":{"object":"PROCESS"}}'),
    ],
)
def test_json_shape_errors_are_counted(format_name: str, raw: str) -> None:
    record = get_parser(format_name)._parse_line(raw, 1)
    assert record.parse_errors
    assert ParseabilityScorer()._score_spec_conformance({format_name: [record]}).score == 0


@pytest.mark.parametrize("raw", ["<Event><System/>", "not XML"])
def test_windows_truncated_and_nonxml_input_is_counted(tmp_path: Path, raw: str) -> None:
    path = tmp_path / "windows_event_security.xml"
    path.write_text(raw)
    records = list(get_parser("windows_event_security").parse_file(path))
    assert len(records) == 1 and records[0].parse_errors


@pytest.mark.parametrize("event_id", [4778, 4779, 4699, 4700, 4701])
def test_previously_unmapped_windows_events_require_variant_fields(event_id: int) -> None:
    record = ParsedRecord(
        source_format="windows_event_security", raw="", fields={"EventID": event_id}
    )
    variant = _get_variant(record.source_format, record)
    assert variant is not None
    assert not validate_event(load_format(record.source_format), record.fields, variant).valid


def test_rdp_port_is_parsed_as_integer() -> None:
    raw = '<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><EventID>4778</EventID></System><EventData><Data Name="ClientPort">3389</Data></EventData></Event>'
    assert get_parser("windows_event_security")._parse_event(raw, 1).fields["ClientPort"] == 3389


RULE_CASES = json.loads(
    (Path(__file__).parents[1] / "fixtures/record_validation/rule_cases.json").read_text()
)


@pytest.mark.parametrize("case", RULE_CASES, ids=lambda case: case["rule"])
def test_every_bundled_rule_witness(case: dict) -> None:
    from evidenceforge.formats.rules import rule_fields

    matches = [
        (definition, rule)
        for definition in load_all_formats().values()
        for rule in definition.validators or []
        if rule.id == case["rule"]
    ]
    assert len(matches) == 1
    definition, rule = matches[0]
    assert evaluate_rule(rule, case["pass"], definition.name, None).outcome == "pass"
    assert evaluate_rule(rule, case["fail"], definition.name, None).outcome == "fail"
    assert (
        evaluate_rule(rule, case["pass"], definition.name, None, set(rule_fields(rule))).outcome
        == "not_applicable"
    )
    if rule.when:
        assert evaluate_rule(rule, {}, definition.name, None).outcome == "not_applicable"
    for check in rule.checks:
        if check.op == "presence":
            null = case["pass"] | {check.field: None}
            assert evaluate_rule(rule, null, definition.name, None).outcome == "fail"


def test_bundled_rule_witness_inventory_is_complete() -> None:
    ids = [
        rule.id
        for definition in load_all_formats().values()
        for rule in definition.validators or []
    ]
    assert len(ids) == len(set(ids))
    assert set(ids) == {case["rule"] for case in RULE_CASES}


def test_source_native_sentinel_and_explicit_exclusion() -> None:
    rule = load_format("windows_event_security").validators[0]
    good = {"EventID": 4624, "LogonType": 3, "TargetUserName": "alice"}
    for address in (None, "", "-"):
        assert evaluate_rule(rule, good | {"IpAddress": address}, rule.id, None).outcome == "fail"
    unusual = good | {"IpAddress": "-", "TargetUserName": "ANONYMOUS LOGON"}
    assert evaluate_rule(rule, unusual, rule.id, None).outcome == "not_applicable"


def test_rule_execution_error_never_becomes_a_warning() -> None:
    rule = RecordRule.model_validate(
        {
            "id": "test.error",
            "severity": "warning",
            "message": "Cannot compare",
            "checks": [{"op": "compare", "field": "a", "other_field": "b", "relation": "lt"}],
        }
    )
    finding = evaluate_rule(rule, {"a": [], "b": 1}, "test", None)
    assert finding.outcome == "evaluation_error"
    assert finding.severity == "error"


def test_format_field_plan_is_cached_per_variant() -> None:
    definition = load_format("windows_event_security")
    assert definition.validation_fields("logon") is definition.validation_fields("logon")
    assert definition.validation_fields(
        "scheduled_task_deleted"
    ) is not definition.validation_fields(None)


def test_partial_dns_observation_and_unknown_codes_remain_supported() -> None:
    """Zeek DNS::Info permits unanswered and partially observed protocol messages."""
    fields = dns_record()
    for name in ("rcode", "rcode_name", "AA", "RA", "answers", "TTLs"):
        fields.pop(name)
    assert validate_event(load_format("zeek_dns"), fields).valid
    fields.update(qtype=65534, qtype_name="unknown-65534", rcode=1, rcode_name="FORMERR")
    assert validate_event(load_format("zeek_dns"), fields).valid


def test_null_comparison_distinguishes_missing_from_explicit_null() -> None:
    rule = RecordRule.model_validate(
        {
            "id": "test.null",
            "message": "Explicit null",
            "checks": [{"op": "compare", "field": "a", "relation": "eq", "value": None}],
        }
    )
    assert evaluate_rule(rule, {"a": None}, "test", None).outcome == "pass"
    for fields in ({}, {"a": ""}, {"a": "-"}, {"a": 0}):
        assert evaluate_rule(rule, fields, "test", None).outcome == "fail"


def test_one_violation_among_many_fails_exact_acceptance() -> None:
    from evidenceforge.evaluation.engine import _build_acceptance_criteria
    from evidenceforge.evaluation.models import PillarScore
    from evidenceforge.evaluation.thresholds import load_thresholds

    parser = get_parser("zeek_dns")
    good = parser._parse_line(json.dumps(dns_record()), 1)
    bad = parser._parse_line(json.dumps(dns_record() | {"qtype_name": "AAAA"}), 1001)
    sub = ParseabilityScorer()._score_format_constraints({"zeek_dns": [good] * 1000 + [bad]})
    assert 99 < sub.score < 100
    criteria = _build_acceptance_criteria(
        load_thresholds(),
        [
            PillarScore(
                number=1, name="Parseability", weight=0.3, score=sub.score, sub_scores=[sub]
            ),
        ],
    )
    assert (
        next(item for item in criteria if item.sub_score_key == "format_constraints").passed
        is False
    )


@pytest.mark.parametrize("command", ["validate", "resolve", "validate-config"])
def test_commands_report_broken_package_contract_in_json(command: str) -> None:
    from typer.testing import CliRunner

    from evidenceforge.cli.commands import app

    arguments = [command]
    if command != "validate-config":
        arguments.append(str(Path(__file__).parents[1] / "fixtures/scenarios/minimal.yaml"))
    arguments.append("--json")
    if command == "resolve":
        arguments.append("--explain-composition")
    with patch(
        "evidenceforge.formats.loader.validate_packaged_contracts",
        side_effect=ConfigurationError(
            "Invalid format definition in /package/formats/zeek_dns.yaml: unknown operation"
        ),
    ):
        result = CliRunner().invoke(app, arguments)
    assert result.exit_code != 0
    payload = json.loads(result.stdout)
    assert "zeek_dns.yaml" in json.dumps(payload)
    assert "unknown operation" in json.dumps(payload)


WINDOWS_CASES = json.loads(
    (Path(__file__).parents[1] / "fixtures/record_validation/windows_variants.json").read_text()
)


@pytest.mark.parametrize("case", WINDOWS_CASES, ids=lambda case: case["variant"])
def test_every_windows_variant_selects_and_validates(case: dict) -> None:
    definition = load_format(case["format"])
    record = ParsedRecord(source_format=case["format"], raw="", fields=case["fields"])
    selected = _get_variant(case["format"], record)
    assert selected == case["variant"]
    result = validate_event(definition, record.fields, selected)
    assert result.valid, result.errors
    for field in definition.validation_fields(selected).values():
        if not field.required:
            continue
        incomplete = {name: value for name, value in record.fields.items() if name != field.name}
        assert not validate_event(definition, incomplete, selected).valid


def test_windows_variant_positive_fixture_inventory() -> None:
    expected = {
        (name, variant.name)
        for name in ("windows_event_security", "windows_event_sysmon")
        for variant in load_format(name).variants
    }
    assert expected == {(case["format"], case["variant"]) for case in WINDOWS_CASES}


FORMAT_CASES = json.loads(
    (Path(__file__).parents[1] / "fixtures/record_validation/formats.json").read_text()
)


@pytest.mark.parametrize("case", FORMAT_CASES, ids=lambda case: case["format"])
def test_every_nonvariant_format_has_positive_and_mutation_witness(case: dict) -> None:
    definition = load_format(case["format"])
    result = validate_event(definition, case["fields"])
    assert result.valid, result.errors
    for field in definition.fields:
        if field.required:
            incomplete = {
                name: value for name, value in case["fields"].items() if name != field.name
            }
            assert not validate_event(definition, incomplete).valid


def test_all_formats_have_positive_witnesses() -> None:
    assert set(load_all_formats()) == {c["format"] for c in FORMAT_CASES + WINDOWS_CASES}


@pytest.mark.parametrize("name", ["packet_filter", "reporter", "weird"])
def test_standalone_native_zeek_fixtures(name: str) -> None:
    format_name = f"zeek_{name}"
    path = Path(__file__).parents[1] / f"fixtures/record_validation/native/{name}.json"
    records = list(get_parser(format_name).parse_file(path))
    assert len(records) == 1
    assert not records[0].parse_errors
    assert validate_event(load_format(format_name), records[0].fields).valid


def test_windows_protocol_conversion_is_source_specific() -> None:
    sysmon = get_parser("windows_event_sysmon")
    security = get_parser("windows_event_security")
    assert sysmon._coerce_event_data_field("Protocol", "tcp") == "tcp"
    assert security._coerce_event_data_field("Protocol", "6") == 6
    with pytest.raises(ValueError, match="Protocol"):
        security._coerce_event_data_field("Protocol", "tcp")


@pytest.mark.parametrize("raw", ["<Events>\n", "</Events>\n", "<Events broken>\n</Events>\n"])
def test_malformed_windows_wrapper_does_not_disappear(tmp_path: Path, raw: str) -> None:
    path = tmp_path / "windows_event_security.xml"
    path.write_text(raw)
    records = list(get_parser("windows_event_security").parse_file(path))
    assert records
    assert all(record.parse_errors for record in records)


def test_empty_complete_windows_wrapper_has_no_records(tmp_path: Path) -> None:
    path = tmp_path / "windows_event_security.xml"
    path.write_text("<Events>\n</Events>\n")
    assert list(get_parser("windows_event_security").parse_file(path)) == []


@pytest.mark.parametrize("status", [199, 200, 201, 299, 300, 407, 500])
def test_connect_body_rule_uses_the_entire_successful_status_class(status: int) -> None:
    rule = load_format("zeek_http").validators[0]
    fields = {"method": "CONNECT", "status_code": status, "response_body_len": 1}
    expected = "fail" if 200 <= status <= 299 else "not_applicable"
    assert evaluate_rule(rule, fields, "zeek_http", None).outcome == expected
    fields["response_body_len"] = 0
    expected = "pass" if 200 <= status <= 299 else "not_applicable"
    assert evaluate_rule(rule, fields, "zeek_http", None).outcome == expected
