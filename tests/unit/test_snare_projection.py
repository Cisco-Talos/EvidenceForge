# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Snare preserves canonical facts and keeps historical omissions explicit."""

import json
from datetime import datetime
from pathlib import Path

import pytest
from typer.testing import CliRunner

from evidenceforge.cli.commands import app
from evidenceforge.evaluation.parsers import get_parser
from evidenceforge.evaluation.pillars.parseability import ParseabilityScorer
from evidenceforge.formats.snare import load_snare_projections
from evidenceforge.generation.emitters.windows_snare import (
    render_windows_security_snare_syslog,
    render_windows_sysmon_snare_syslog,
)

CASES = json.loads(
    (Path(__file__).parents[1] / "fixtures/record_validation/windows_variants.json").read_text()
)
FULL_CASES = json.loads(
    (Path(__file__).parents[1] / "fixtures/record_validation/snare_full_variants.json").read_text()
)


def render_case(case: dict) -> str:
    fields = dict(case["fields"])
    fields["TimeCreated"] = datetime.fromisoformat(fields["TimeCreated"].replace("Z", "+00:00"))
    renderer = (
        render_windows_security_snare_syslog
        if case["format"].endswith("security")
        else render_windows_sysmon_snare_syslog
    )
    return renderer(fields)


@pytest.mark.parametrize("case", CASES + FULL_CASES, ids=lambda c: c["format"] + ":" + c["variant"])
def test_snare_variant_preserves_canonical_fields(tmp_path: Path, case: dict) -> None:
    path = tmp_path / (case["format"] + "_snare.log")
    path.write_text(render_case(case) + "\n")
    (record,) = get_parser(case["format"]).parse_file(path)
    assert not record.parse_errors
    assert record.representation == "windows_snare"
    for name, value in case["fields"].items():
        if name in {"TimeCreated", "Channel", "Provider", "UtcTime"}:
            continue
        assert record.fields.get(name) == value, (name, record.fields.get(name), value)
    scores = ParseabilityScorer()._score_both({case["format"]: [record]})
    assert all(score.score == 100 for score in scores), [s.sample_findings for s in scores]
    assert scores[0].unavailable_check_count == 0


def test_projection_inventory_is_exhaustive() -> None:
    assert len(load_snare_projections().events) == len(CASES) == 43


@pytest.mark.parametrize("mutation", ["missing", "numeric", "alias", "computer", "timestamp"])
def test_snare_corruption_remains_counted(tmp_path: Path, mutation: str) -> None:
    case = next(c for c in CASES if c["fields"]["EventID"] == 4624)
    raw = render_case(case)
    if mutation == "missing":
        raw = raw.replace("ExecutionProcessID: 1  ", "")
    elif mutation == "numeric":
        raw = raw.replace("ExecutionProcessID: 1", "ExecutionProcessID: invalid")
    elif mutation == "alias":
        raw = raw.replace("Account Name: example", "Account Name: conflicting")
    elif mutation == "computer":
        raw = raw.replace("\tMSWinEventLog", "-changed\tMSWinEventLog", 1)
    else:
        raw = raw.replace("TimeCreated: 2026-09-15T12:00:00", "TimeCreated: 2026-09-16T12:00:00")
    path = tmp_path / "windows_event_security_snare.log"
    path.write_text(raw + "\n")
    records = list(get_parser(case["format"]).parse_file(path))
    assert len(records) == 1
    scores = ParseabilityScorer()._score_both({case["format"]: records})
    assert scores[0].score == 0
    assert scores[0].sample_findings
    result = CliRunner().invoke(
        app,
        [
            "eval",
            str(tmp_path),
            "--scenario",
            str(Path(__file__).parents[1] / "fixtures/scenarios/retail-store-ftp-attack.yaml"),
            "--format",
            "json",
        ],
    )
    assert result.exit_code == 0, result.stderr
    report = json.loads(result.stdout)
    assert report["source_counts"][case["format"]] == 1
    assert report["acceptance_passed"] is False


@pytest.mark.parametrize("case", CASES, ids=lambda c: c["variant"])
def test_snare_missing_system_metadata_is_invalid_in_current_projection(
    tmp_path: Path, case: dict
) -> None:
    raw = render_case(case)
    raw = raw.replace(f"Level: {case['fields']['Level']}  ", "")
    path = tmp_path / (case["format"] + "_snare.log")
    path.write_text(raw + "\n")
    (record,) = get_parser(case["format"]).parse_file(path)
    schema, _ = ParseabilityScorer()._score_both({case["format"]: [record]})
    assert schema.score == 0
    assert any(f.rule_id == "Level" for f in schema.sample_findings)


def test_scoped_logon_ids_do_not_feed_generic_upstream_pattern() -> None:
    case = next(c for c in CASES if c["fields"]["EventID"] == 4624)
    raw = render_case(case)
    assert "Canonical[SubjectLogonId]: 0x1" in raw
    assert "Canonical[TargetLogonId]: 0x1" in raw
    assert "SubjectLogonId: " not in raw


def test_unsupported_event_is_a_record_failure(tmp_path: Path) -> None:
    case = CASES[0]
    raw = render_case(case).replace(f"\t{case['fields']['EventID']}\t", "\t99999\t")
    path = tmp_path / (case["format"] + "_snare.log")
    path.write_text(raw + "\n")
    (record,) = get_parser(case["format"]).parse_file(path)
    assert "Unsupported Snare EventID: 99999" in record.parse_errors


def test_generic_identity_labels_never_mix_subject_and_target() -> None:
    for projection in load_snare_projections().events:
        owners = {
            owner.removesuffix("UserSid")
            .removesuffix("UserName")
            .removesuffix("DomainName")
            .removesuffix("LogonId")
            for label, owner in projection.aliases.items()
            if label in {"Security ID", "Account Name", "Account Domain", "Logon ID"}
        }
        assert len(owners) <= 1, projection


def test_native_port_sentinel_is_preserved(tmp_path: Path) -> None:
    case = next(c for c in CASES if c["fields"]["EventID"] == 4624)
    case = case | {"fields": case["fields"] | {"IpPort": "-"}}
    path = tmp_path / "windows_event_security_snare.log"
    path.write_text(render_case(case) + "\n")
    (record,) = get_parser(case["format"]).parse_file(path)
    assert not record.parse_errors
    assert record.fields["IpPort"] == "-"
    schema, _ = ParseabilityScorer()._score_both({case["format"]: [record]})
    assert schema.score == 100


def test_empty_certificate_fields_do_not_attach_to_previous_port(tmp_path: Path) -> None:
    case = next(c for c in CASES if c["fields"]["EventID"] == 4768)
    case = case | {
        "fields": case["fields"]
        | {"IpPort": 50000, "CertIssuerName": "", "CertSerialNumber": "", "CertThumbprint": ""}
    }
    path = tmp_path / "windows_event_security_snare.log"
    path.write_text(render_case(case) + "\n")
    (record,) = get_parser(case["format"]).parse_file(path)
    assert not record.parse_errors
    assert record.fields["IpPort"] == 50000
    assert record.fields["CertIssuerName"] == ""
    assert record.fields["CertSerialNumber"] == ""
    assert record.fields["CertThumbprint"] == ""
    schema, _ = ParseabilityScorer()._score_both({case["format"]: [record]})
    assert schema.score == 100


@pytest.mark.parametrize(
    "mutation",
    ["unknown", "duplicate", "missing", "reference", "label", "decimal", "fallback", "bool_id"],
)
def test_malformed_projection_definitions_fail_at_load(mutation: str) -> None:
    from pydantic import ValidationError

    from evidenceforge.formats.snare import SnareProjections

    document = load_snare_projections().model_dump(mode="json")
    event = document["events"][0]
    if mutation == "unknown":
        event["unexpected"] = True
    elif mutation == "duplicate":
        document["events"].append(event.copy())
    elif mutation == "missing":
        document["events"].pop()
    elif mutation == "reference":
        event["aliases"]["Bad field"] = "Nonexistent"
    elif mutation == "label":
        event["aliases"]["Injected: field"] = "SubjectUserName"
    elif mutation == "decimal":
        event["decimal_aliases"]["Number"] = "SubjectUserName"
    elif mutation == "fallback":
        event["fallback_aliases"] = {"Process ID": "SubjectLogonId"}
    else:
        event["event_id"] = True
    with pytest.raises(ValidationError):
        SnareProjections.model_validate(document)


@pytest.mark.parametrize("source", ["windows_event_security", "windows_event_sysmon"])
def test_committed_iteration_snare_fixture(source: str) -> None:
    path = (
        Path(__file__).parents[1]
        / "fixtures/record_validation/targets/snare_v1"
        / (source + "_snare.log")
    )
    (record,) = get_parser(source).parse_file(path)
    assert not record.parse_errors
    assert record.fields["ProjectionVersion"] == "1"
    assert record.fields["ExecutionProcessID"] >= 0
    assert all(s.score == 100 for s in ParseabilityScorer()._score_both({source: [record]}))


def test_snare_counter_and_windows_record_id_are_distinct(tmp_path: Path) -> None:
    case = CASES[0]
    raw = render_case(case).replace("EventRecordID: 1  ", "EventRecordID: 100  ")
    path = tmp_path / (case["format"] + "_snare.log")
    path.write_text(raw + "\n")
    (record,) = get_parser(case["format"]).parse_file(path)
    assert not record.parse_errors
    assert record.fields["SnareCounter"] == 1
    assert record.fields["EventRecordID"] == 100
    assert all(s.score == 100 for s in ParseabilityScorer()._score_both({case["format"]: [record]}))


def test_supplied_sysmon_utc_time_is_not_replaced(tmp_path: Path) -> None:
    case = next(c for c in CASES if c["format"].endswith("sysmon"))
    case = case | {"fields": case["fields"] | {"UtcTime": "2026-09-15 11:59:59.987"}}
    path = tmp_path / "windows_event_sysmon_snare.log"
    path.write_text(render_case(case) + "\n")
    (record,) = get_parser(case["format"]).parse_file(path)
    assert not record.parse_errors
    assert record.fields["UtcTime"] == case["fields"]["UtcTime"]
