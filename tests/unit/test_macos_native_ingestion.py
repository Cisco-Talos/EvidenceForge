# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Native ingestion contracts using independently authored structural records."""

import json
from datetime import UTC, datetime
from pathlib import Path

import pytest
from typer.testing import CliRunner

from evidenceforge.cli.commands import app
from evidenceforge.evaluation.parsers import ParsedRecord, discover_log_files, get_parser
from evidenceforge.evaluation.pillars.parseability import ParseabilityScorer
from evidenceforge.evaluation.validation_routes import (
    get_validation_route,
    validate_route_inventory,
)
from evidenceforge.models.exceptions import EvaluationLimitError
from tests.unit.test_macos_endpoint_security_contracts import _record
from tests.unit.test_macos_native_contracts import _log_record, _persona_metadata


def _write(tmp_path: Path, source: str, rows: list[object]) -> Path:
    path = tmp_path / f"{source}.ndjson"
    path.write_text("\n".join(json.dumps(row) for row in rows) + "\n", encoding="utf-8")
    return path


def test_unified_log_completion_is_not_an_event_and_optional_fields_remain_native(
    tmp_path: Path,
) -> None:
    source = "macos_unified_log"
    fields = _log_record()
    path = _write(tmp_path, source, [fields, {"count": 1, "finished": 1}])
    records = list(get_parser(source).parse_file(path))
    assert len(records) == 1
    record = records[0]
    assert record.fields == fields
    assert record.fields["eventMessage"] == "Example value: <private>"
    assert "source" not in record.fields
    assert record.timestamp == datetime(2026, 10, 19, 14, 0, 0, 123456, tzinfo=UTC)
    assert record.line_number == 1 and record.source_host is None
    assert record.parse_errors == []
    schema, constraints = ParseabilityScorer()._score_both({source: records})
    assert schema.score == constraints.score == 100
    assert (
        list(get_parser(source).parse_file(_write(tmp_path, source, [{"count": 0, "finished": 1}])))
        == []
    )


def test_unified_log_ingestion_accepts_persona_metadata_without_normalizing_to_user_id(
    tmp_path: Path,
) -> None:
    source = "macos_unified_log"
    fields = _log_record() | _persona_metadata()
    record = next(get_parser(source).parse_file(_write(tmp_path, source, [fields])))
    assert record.fields == fields and not record.parse_errors
    assert record.fields["userID"] != record.fields["personaID"]
    schema, constraints = ParseabilityScorer()._score_both({source: [record]})
    assert schema.score == constraints.score == 100


@pytest.mark.parametrize("version,family", [(6, "exec"), (9, "exit"), (10, "fork")])
def test_endpoint_ingestion_preserves_version_roles_and_nanosecond_text(
    tmp_path: Path, version: int, family: str
) -> None:
    source = "macos_endpoint_security"
    fields = _record(version, family)
    records = list(get_parser(source).parse_file(_write(tmp_path, source, [fields])))
    assert len(records) == 1
    record = records[0]
    assert record.fields == fields
    assert record.timestamp == datetime(2026, 10, 19, 12, 30, 0, 123456, tzinfo=UTC)
    assert record.fields["time"].endswith("123456789Z")
    assert record.representation == f"macos_endpoint_security_v{version}"
    assert record.source_host is None and record.parse_errors == []
    schema, constraints = ParseabilityScorer()._score_both({source: records})
    assert schema.score == constraints.score == 100


@pytest.mark.parametrize("source", ["macos_unified_log", "macos_endpoint_security"])
@pytest.mark.parametrize("mutation", ["duplicate", "boolean", "nonfinite", "future", "array"])
def test_malformed_native_records_are_counted_as_failures(
    tmp_path: Path, source: str, mutation: str
) -> None:
    fields = _log_record() if source == "macos_unified_log" else _record()
    key = "processID" if source == "macos_unified_log" else "version"
    if mutation == "boolean":
        fields[key] = True
    elif mutation == "nonfinite":
        fields[key] = float("nan")
    elif mutation == "future":
        if source == "macos_unified_log":
            fields["eventType"] = "signpostEvent"
        else:
            fields["version"] = 11
    raw = json.dumps([] if mutation == "array" else fields)
    if mutation == "duplicate":
        raw = '{"' + key + '":999,' + raw[1:]
    path = tmp_path / f"{source}.ndjson"
    path.write_text(raw + "\n", encoding="utf-8")
    records = list(get_parser(source).parse_file(path))
    assert len(records) == 1 and records[0].parse_errors
    schema, _ = ParseabilityScorer()._score_both({source: records})
    assert schema.score == 0 and schema.sample_findings


@pytest.mark.parametrize("trailing", [_log_record(), {"count": 0, "finished": 1}])
def test_records_after_export_completion_are_not_silently_accepted(
    tmp_path: Path, trailing: dict[str, object]
) -> None:
    source = "macos_unified_log"
    path = _write(tmp_path, source, [{"count": 0, "finished": 1}, trailing])
    records = list(get_parser(source).parse_file(path))
    assert len(records) == 1 and records[0].line_number == 2
    assert "follows" in records[0].parse_errors[0]


def test_native_validation_does_not_trust_mutated_fields_or_completion_rows(tmp_path: Path) -> None:
    source = "macos_unified_log"
    record = next(get_parser(source).parse_file(_write(tmp_path, source, [_log_record()])))
    record.fields["processID"] = False
    schema, _ = ParseabilityScorer()._score_both({source: [record]})
    assert schema.score == 0
    completion = ParsedRecord(source_format=source, raw="", fields={"count": 0, "finished": 1})
    schema, _ = ParseabilityScorer()._score_both({source: [completion]})
    assert schema.score == 0


@pytest.mark.parametrize("source", ["macos_unified_log", "macos_endpoint_security"])
def test_native_ingestion_uses_existing_record_size_and_utf8_limits(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, source: str
) -> None:
    from evidenceforge.evaluation.parsers import iter_bounded_text_lines

    monkeypatch.setattr(
        "evidenceforge.evaluation.parsers.macos_native.iter_bounded_text_lines",
        lambda path: iter_bounded_text_lines(path, max_record_bytes=32),
    )
    path = tmp_path / f"{source}.ndjson"
    for data in (b"{" + b"a" * 32, b"\xff\n"):
        path.write_bytes(data)
        with pytest.raises(EvaluationLimitError):
            list(get_parser(source).parse_file(path))


def test_native_discovery_retains_explicit_codecs_for_registered_sources(tmp_path: Path) -> None:
    from evidenceforge.generation.engine.emitter_setup import _build_emitter_classes

    folder = tmp_path / "invented-mac.example"
    folder.mkdir()
    path = _write(folder, "macos_unified_log", [_log_record()])
    (folder / "other.json").write_text(json.dumps(_log_record()))
    assert discover_log_files(tmp_path) == {"macos_unified_log": [path]}
    validate_route_inventory()
    for source in ("macos_unified_log", "macos_endpoint_security"):
        assert get_validation_route(source).kind == "native_codec"
        assert source in _build_emitter_classes()
        assert not get_parser(source).can_parse(Path("arbitrary.json"))


def test_native_codec_route_must_resolve_an_explicit_validator(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from evidenceforge.evaluation import validation_routes
    from evidenceforge.models.exceptions import ConfigurationError

    monkeypatch.setattr(
        validation_routes,
        "VALIDATION_ROUTES",
        tuple(
            route.model_copy(update={"validator": "missing"})
            if route.kind == "native_codec"
            else route
            for route in validation_routes.VALIDATION_ROUTES
        ),
    )
    with pytest.raises(ConfigurationError, match="Unknown native codec validator"):
        validate_route_inventory()


def test_native_only_cli_evaluation_counts_events_and_keeps_ingestion_boundary(
    tmp_path: Path,
) -> None:
    _write(tmp_path, "macos_unified_log", [_log_record(), {"count": 1, "finished": 1}])
    _write(tmp_path, "macos_endpoint_security", [_record()])
    scenario = Path(__file__).parents[1] / "fixtures/scenarios/retail-store-ftp-attack.yaml"
    result = CliRunner().invoke(
        app, ["eval", str(tmp_path), "--scenario", str(scenario), "--format", "json"]
    )
    assert result.exit_code == 0, result.stderr
    report = json.loads(result.stdout)
    assert report["source_counts"] == {"macos_endpoint_security": 1, "macos_unified_log": 1}
    assert report["acceptance_passed"] is False
    from evidenceforge.evaluation.pillars.plausibility import PlausibilityScorer

    records = list(
        get_parser("macos_unified_log").parse_file(tmp_path / "macos_unified_log.ndjson")
    )
    co_occurrence = PlausibilityScorer()._score_co_occurrence({"macos_unified_log": records})
    assert co_occurrence.skipped and co_occurrence.score is None
