# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Single-property corruption across native parsing and exact acceptance gates."""

import json
import re
import xml.etree.ElementTree as ET
from pathlib import Path

import pytest

from evidenceforge.evaluation.engine import _build_acceptance_criteria
from evidenceforge.evaluation.models import PillarScore
from evidenceforge.evaluation.parsers import get_parser
from evidenceforge.evaluation.pillars.parseability import ParseabilityScorer
from evidenceforge.evaluation.thresholds import load_thresholds
from evidenceforge.formats.loader import load_format
from tests.support.native_records import render_record

ROOT = Path(__file__).parents[1] / "fixtures/record_validation"
CASES = json.loads((ROOT / "formats.json").read_text()) + json.loads(
    (ROOT / "windows_variants.json").read_text()
)
MUTATIONS = []
for case in CASES:
    definition = load_format(case["format"])
    if definition.output.format not in ("json", "xml"):
        continue
    for field in definition.validation_fields(case.get("variant")).values():
        if not field.required:
            continue
        for mode in ("missing", "empty", "wrong_type", "null"):
            if mode == "null" and (definition.output.format == "xml" or field.nullable):
                continue
            if mode == "empty" and field.type.value in ("string", "list"):
                continue  # Empty text/lists are legal unless a separate rule constrains them.
            if (
                mode == "wrong_type"
                and definition.output.format == "xml"
                and field.type.value in ("string", "enum")
            ):
                continue  # XML attributes/text have no independent object-valued representation.
            MUTATIONS.append((case, field.name, mode))


def mutate_native(raw: str, name: str, field: str, mode: str) -> str:
    if name.startswith("windows_"):
        ET.register_namespace("", "http://schemas.microsoft.com/win/2004/08/events/event")
        root = ET.fromstring(raw)
        if field in {"ExecutionProcessID", "ExecutionThreadID"}:
            target = next(e for e in root.iter() if e.tag.endswith("}Execution"))
            attribute = field.removeprefix("Execution")
            if mode == "missing":
                del target.attrib[attribute]
            else:
                target.set(attribute, "" if mode == "empty" else "invalid-value")
            return ET.tostring(root, encoding="unicode")
        target = next(
            (
                e
                for e in root.iter()
                if e.attrib.get("Name") == field or e.tag.rsplit("}", 1)[-1] == field
            ),
            None,
        )
        assert target is not None, field
        if mode == "missing":
            parent = next(p for p in root.iter() if target in list(p))
            parent.remove(target)
        elif field == "TimeCreated":
            target.set("SystemTime", "" if mode == "empty" else "invalid-time")
        else:
            target.text = "" if mode == "empty" else "invalid-value"
        return ET.tostring(root, encoding="unicode")
    obj = json.loads(raw)
    container = obj.get("properties", {}) if field in obj.get("properties", {}) else obj
    assert field in container, field
    if mode == "missing":
        del container[field]
    elif mode == "empty":
        container[field] = ""
    elif mode == "null":
        container[field] = None
    else:
        container[field] = {"invalid": "type"}
    return json.dumps(obj)


@pytest.mark.parametrize(
    "case,field,mode",
    MUTATIONS,
    ids=[f"{c.get('variant', c['format'])}:{f}:{m}" for c, f, m in MUTATIONS],
)
def test_corrupt_required_field_cannot_pass_acceptance(
    tmp_path: Path, case: dict, field: str, mode: str
) -> None:
    raw = render_record(tmp_path, case)
    path = tmp_path / "mutated.log"
    path.write_text(mutate_native(raw, case["format"], field, mode) + "\n")
    records = list(get_parser(case["format"]).parse_file(path))
    assert len(records) == 1
    scores = ParseabilityScorer()._score_both({case["format"]: records})
    assert any(s.score < 100 for s in scores), (field, mode, scores)
    assert any(s.sample_findings for s in scores)
    pillar = PillarScore(
        number=1, name="Parseability", weight=0.3, score=0, sub_scores=list(scores)
    )
    gates = _build_acceptance_criteria(load_thresholds(), [pillar])
    assert any(g.pillar == "parseability" and g.passed is False for g in gates)


@pytest.mark.parametrize(
    "name", ["bash_history", "syslog", "cisco_asa", "snort_alert", "web_access", "proxy_access"]
)
def test_text_source_malformed_timestamp_is_counted(tmp_path: Path, name: str) -> None:

    case = next(c for c in CASES if c["format"] == name)
    raw = render_record(tmp_path, case)
    if name == "bash_history":
        raw = re.sub(r"^#[0-9]+", "#" + "9" * 40, raw)
    elif name in {"web_access", "proxy_access"}:
        raw = re.sub(r"\[[^]]+\]", "[invalid-time]", raw, count=1)
    elif name == "snort_alert":
        raw = "99/99-99:99:99.000000" + raw[raw.index(" ") :]
    elif name == "syslog":
        raw = re.sub(r"2024-01-15T[^ ]+", "2024-99-99T99:99:99Z", raw)
    else:
        raw = raw.replace("Jan 15 10:01:21", "Jan 99 99:99:99")
    path = tmp_path / "bad.log"
    path.write_text(raw + "\n")
    records = list(get_parser(name).parse_file(path))
    assert records
    scores = ParseabilityScorer()._score_both({name: records})
    assert scores[0].score < 100
    assert scores[0].sample_findings


def test_malformed_native_records_complete_all_pillars(tmp_path: Path) -> None:
    from typer.testing import CliRunner

    from evidenceforge.cli.commands import app

    expected = {}
    rendered = {
        (c["format"], c.get("variant")): render_record(tmp_path / "render", c) for c in CASES
    }
    for case, field, mode in MUTATIONS:
        name = case["format"]
        raw = rendered[(name, case.get("variant"))]
        path = tmp_path / (name + (".xml" if name.startswith("windows_") else ".json"))
        with path.open("a") as stream:
            stream.write(mutate_native(raw, name, field, mode) + "\n")
        expected[name] = expected.get(name, 0) + 1
    for case, field in JSON_FIELD_CASES:
        name = case["format"]
        obj = json.loads(rendered[(name, case.get("variant"))])
        container = obj["properties"] if name == "ecar" and field.name not in obj else obj
        container[field.name] = {"wrong": "type"}
        with (tmp_path / (name + ".json")).open("a") as stream:
            stream.write(json.dumps(obj) + "\n")
        expected[name] = expected.get(name, 0) + 1
    for name in (
        "bash_history",
        "syslog",
        "snort_alert",
        "cisco_asa",
        "web_access",
        "proxy_access",
    ):
        path = tmp_path / ("bash_history/user.history" if name == "bash_history" else name + ".log")
        path.parent.mkdir(exist_ok=True)
        raw = (
            "#" + "9" * 40 + "\nls"
            if name == "bash_history"
            else "invalid-header " + rendered[(name, None)]
        )
        path.write_text(raw + "\n")
        expected[name] = len(list(get_parser(name).parse_file(path)))
    assert len(expected) == 25
    result = CliRunner().invoke(
        app,
        [
            "eval",
            str(tmp_path),
            "--scenario",
            str(ROOT.parent / "scenarios/retail-store-ftp-attack.yaml"),
            "--format",
            "json",
        ],
    )
    assert result.exit_code == 0, result.stderr
    report = json.loads(result.stdout)
    assert report["acceptance_passed"] is False
    for name, count in expected.items():
        assert report["source_counts"][name] == count
    assert all(p["score"] is not None for p in report["pillars"])


RULE_CASES = json.loads((ROOT / "rule_cases.json").read_text())


@pytest.mark.parametrize("witness", RULE_CASES, ids=lambda c: c["rule"])
@pytest.mark.parametrize("outcome", ["pass", "fail"])
def test_rule_witness_through_native_parser(tmp_path: Path, witness: dict, outcome: str) -> None:
    from evidenceforge.evaluation.pillars.parseability import (
        _get_variant,
        _normalize_for_validation,
    )
    from evidenceforge.formats.loader import load_all_formats
    from evidenceforge.formats.validator import validate_event

    definition, rule = next(
        (d, r)
        for d in load_all_formats().values()
        for r in d.validators or []
        if r.id == witness["rule"]
    )
    fields = dict(witness[outcome])
    if definition.name == "ecar" and "target_pid" in fields:
        fields["target_pid"] = str(fields["target_pid"])
    candidates = [c for c in CASES if c["format"] == definition.name]
    case = next(
        (c for c in candidates if c["fields"].get("EventID") == fields.get("EventID")),
        candidates[0],
    )
    raw = render_record(tmp_path, case)
    if definition.output.format == "xml":
        ET.register_namespace("", "http://schemas.microsoft.com/win/2004/08/events/event")
        root = ET.fromstring(raw)
        event_data = next(e for e in root.iter() if e.tag.endswith("}EventData"))
        for key in set(witness["pass"]) | set(witness["fail"]):
            target = next(
                (
                    e
                    for e in root.iter()
                    if e.attrib.get("Name") == key or e.tag.endswith("}" + key)
                ),
                None,
            )
            if key not in fields:
                if target is not None:
                    next(p for p in root.iter() if target in list(p)).remove(target)
            else:
                if target is None:
                    target = ET.SubElement(
                        event_data,
                        "{http://schemas.microsoft.com/win/2004/08/events/event}Data",
                        Name=key,
                    )
                target.text = str(fields[key])
        raw = ET.tostring(root, encoding="unicode")
    elif definition.output.format == "text":
        if definition.name == "web_access":
            raw = f'10.0.0.1 - - [15/Jun/2025:15:06:40 +0000] "{fields.get("method", "GET")} / HTTP/1.1" {fields.get("status_code", 200)} 1 "-" "-"'
        elif definition.name == "syslog":
            raw = f"<30>1 2024-01-15T10:00:00Z {fields.get('hostname', 'ws01')} sshd 1 - - {fields.get('message', 'accepted')}"
        elif definition.name == "snort_alert":
            raw = f"06/15-15:06:40.000000 [**] [1:1:1] test [**] [Classification: test] [Priority: {fields.get('priority', 1)}] {{TCP}} {fields.get('src_ip', '10.0.0.1') if witness['rule'].endswith('-1') else fields.get('src_ip', '')} -> {fields.get('dst_ip', '10.0.0.2')}"
        else:
            assert definition.name == "bash_history"
            if witness["rule"] == "bash_history.legacy-2" and outcome == "fail":
                pytest.skip(
                    "Username is derived from a nonempty filename; empty username has no native representation"
                )
            raw = "#1750000000\n" + fields.get("command", "ls")
    else:
        assert definition.output.format == "json", definition.name
        obj = json.loads(raw)
        for key in set(witness["pass"]) | set(witness["fail"]):
            container = obj["properties"] if definition.name == "ecar" and key not in obj else obj
            if key in fields:
                container[key] = fields[key]
            else:
                container.pop(key, None)
        raw = json.dumps(obj)
    path = tmp_path / "witness.log"
    path.write_text(raw + "\n")
    records = list(get_parser(definition.name).parse_file(path))
    assert len(records) == 1
    record = records[0]
    result = validate_event(
        definition,
        _normalize_for_validation(definition.name, record.fields, record.timestamp),
        _get_variant(definition.name, record),
    )
    finding = next(f for f in result.findings if f.rule_id == rule.id)
    if outcome == "pass":
        assert finding.outcome == outcome, result.findings
    else:
        assert (
            finding.outcome == "fail"
            or record.parse_errors
            or any(
                f.category in {"schema", "constraint"}
                and f.outcome == "fail"
                and set(f.fields) & set(finding.fields)
                for f in result.findings
            )
        ), result.findings
    scores = ParseabilityScorer()._score_both({definition.name: records})
    if outcome == "fail" and rule.severity == "error":
        assert scores[1].score < 100 or scores[0].score < 100


JSON_FIELD_CASES = [
    (case, field)
    for case in CASES
    if load_format(case["format"]).output.format == "json"
    for field in load_format(case["format"]).validation_fields(case.get("variant")).values()
]


@pytest.mark.parametrize(
    "case,field", JSON_FIELD_CASES, ids=[f"{c['format']}:{f.name}" for c, f in JSON_FIELD_CASES]
)
def test_json_scalar_edges_and_native_sentinels(tmp_path: Path, case: dict, field) -> None:
    from evidenceforge.evaluation.pillars.parseability import _normalize_for_validation
    from evidenceforge.formats.validator import validate_event, validate_field

    raw = json.loads(render_record(tmp_path, case))
    candidates = [None, "", "-", {"wrong": "type"}]
    if field.type.value == "list":
        candidates.extend([[], [None], ["wrong-element"]])
    bounds = field.constraints
    if bounds:
        for bound in (bounds.min_value, bounds.max_value):
            if bound is not None:
                candidates.extend([int(bound) - 1, int(bound), int(bound) + 1])
    if field.type.value in {"float", "integer"}:
        candidates.extend([float("inf"), float("nan")])
    for value in candidates:
        obj = json.loads(json.dumps(raw))
        container = obj["properties"] if case["format"] == "ecar" and field.name not in obj else obj
        container[field.name] = value
        path = tmp_path / "edge.log"
        path.write_text(json.dumps(obj) + "\n")
        records = list(get_parser(case["format"]).parse_file(path))
        assert len(records) == 1
        record = records[0]
        normalized = _normalize_for_validation(case["format"], record.fields, record.timestamp)
        result = validate_event(load_format(case["format"]), normalized)
        assert all(f.outcome != "evaluation_error" for f in result.findings)
        scores = ParseabilityScorer()._score_both({case["format"]: records})
        if record.parse_errors or not validate_field(field, normalized.get(field.name)).valid:
            assert any(s.score < 100 for s in scores), (field.name, value)


@pytest.mark.parametrize("digits", [40, 5000])
def test_bash_oversized_epoch_is_evidence_failure(tmp_path: Path, digits: int) -> None:
    path = tmp_path / "user.history"
    path.write_text("#" + "9" * digits + "\nls\n")
    records = list(get_parser("bash_history").parse_file(path))
    assert len(records) == 1 and records[0].parse_errors
    assert ParseabilityScorer()._score_both({"bash_history": records})[0].score == 0
