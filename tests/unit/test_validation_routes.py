"""Parser ownership and evaluator boundary regressions."""

import json
import logging
from pathlib import Path

import pytest
from jinja2 import Environment
from typer.testing import CliRunner

from evidenceforge.cli.commands import app
from evidenceforge.evaluation import validation_routes as routes
from evidenceforge.evaluation.engine import DIMENSION_SCORERS
from evidenceforge.evaluation.parsers import get_parser
from evidenceforge.evaluation.pillars.parseability import ParseabilityScorer
from evidenceforge.evaluation.pillars.plausibility import PlausibilityScorer
from evidenceforge.formats.loader import load_all_formats
from evidenceforge.generation.engine.emitter_setup import _build_emitter_classes
from evidenceforge.models.exceptions import ConfigurationError

FIXTURES = Path(__file__).parents[1] / "fixtures"


def test_every_parser_schema_and_emitter_has_an_owner() -> None:
    routes.validate_route_inventory()
    native = {r.validator for r in routes.VALIDATION_ROUTES if r.kind == "native"}
    assert native == set(load_all_formats()) == set(_build_emitter_classes())
    for definition in load_all_formats().values():
        for template in (
            definition.output.template,
            definition.output.header_template,
            definition.output.footer_template,
        ):
            if template is not None:
                Environment().parse(template)


@pytest.mark.parametrize("mutation", ["missing", "duplicate", "stale", "artifact", "schema"])
def test_broken_route_inventory_is_an_execution_error(monkeypatch, mutation: str) -> None:
    entries = list(routes.VALIDATION_ROUTES)
    if mutation == "missing":
        entries.pop()
    elif mutation == "duplicate":
        entries.append(entries[0])
    elif mutation == "stale":
        entries.append(routes.ValidationRoute(source="future", kind="native", validator="future"))
    elif mutation == "artifact":
        entries[-1] = entries[-1].model_copy(update={"validator": "missing"})
    else:
        entries[0] = entries[0].model_copy(update={"validator": "missing"})
    monkeypatch.setattr(routes, "VALIDATION_ROUTES", tuple(entries))
    with pytest.raises(ConfigurationError):
        routes.validate_route_inventory()


@pytest.mark.parametrize(
    "payload",
    [
        [],
        None,
        {"email": []},
        {"email": {"messages": {}}},
        {"email": {"messages": [42]}},
        {"email": {"messages": [{"date": "invalid"}]}},
        {"email": {"messages": [{"to": "not-a-list"}]}},
    ],
)
def test_malformed_email_artifacts_count_as_failures(tmp_path: Path, payload: object) -> None:
    path = tmp_path / "ARTIFACTS_MANIFEST.json"
    path.write_text(json.dumps(payload))
    records = list(get_parser("email_artifacts").parse_file(path))
    assert len(records) == 1
    schema, _ = ParseabilityScorer()._score_both({"email_artifacts": records})
    assert schema.score == 0
    assert schema.sample_findings


@pytest.mark.parametrize("payload", [{}, {"email": {}}, {"email": {"messages": []}}])
def test_empty_artifact_sections_are_legitimate(tmp_path: Path, payload: dict) -> None:
    path = tmp_path / "ARTIFACTS_MANIFEST.json"
    path.write_text(json.dumps(payload))
    assert list(get_parser("email_artifacts").parse_file(path)) == []


def test_sparse_email_metadata_and_extensions_remain_supported(tmp_path: Path) -> None:
    path = tmp_path / "ARTIFACTS_MANIFEST.json"
    path.write_text(
        json.dumps({"email": {"messages": [{"message_id": "<m@host>", "extension": 1}]}})
    )
    records = {"email_artifacts": list(get_parser("email_artifacts").parse_file(path))}
    schema, constraints = ParseabilityScorer()._score_both(records)
    assert schema.score == constraints.score == 100
    PlausibilityScorer()._score_co_occurrence(records)


@pytest.mark.parametrize("failure", [False, True])
def test_json_cli_is_clean_across_repeated_calls(monkeypatch, failure: bool) -> None:
    scorer = DIMENSION_SCORERS[0]
    original = scorer.score

    def scoring(*args, **kwargs):
        logging.getLogger("evidenceforge.routing_test").warning("routing-test-warning")
        if failure:
            raise RuntimeError("injected pillar failure")
        return original(*args, **kwargs)

    monkeypatch.setattr(scorer, "score", scoring)
    runner = CliRunner()
    for verbose in (False, True):
        args = [
            "eval",
            str(FIXTURES / "eval/good"),
            "--scenario",
            str(FIXTURES / "scenarios/retail-store-ftp-attack.yaml"),
            "--format",
            "json",
        ]
        if verbose:
            args.append("--verbose")
        result = runner.invoke(app, args)
        assert "routing-test-warning" in result.stderr
        if failure:
            assert result.exit_code == 22
            assert result.stdout == ""
            assert "Pillar 1 (Parseability)" in result.stderr
            if not verbose:
                assert "Traceback" not in result.stderr
        else:
            assert result.exit_code == 0, result.stderr
            report = json.loads(result.stdout)
            assert len(report["pillars"]) == 4
            assert report["acceptance_passed"] is False


RECORD_CASES = sum(
    (
        json.loads((FIXTURES / "record_validation" / name).read_text())
        for name in ("formats.json", "windows_variants.json")
    ),
    [],
)


@pytest.mark.parametrize("case", RECORD_CASES, ids=lambda c: c.get("variant", c["format"]))
def test_native_render_parse_validate_roundtrip(tmp_path: Path, case: dict) -> None:
    from datetime import UTC, datetime

    from evidenceforge.formats.loader import load_format

    name = case["format"]
    definition = load_format(name)
    fields = dict(case["fields"])
    for key in ("timestamp", "TimeCreated", "ts"):
        if isinstance(fields.get(key), str):
            fields[key] = datetime.fromisoformat(fields[key].replace("Z", "+00:00"))
    if name == "ecar":
        fields["timestamp"] = fields.pop("timestamp_ms") / 1000
    if name in {"snort_alert", "proxy_access", "web_access", "bash_history"}:
        if isinstance(fields.get("timestamp"), (int, float)):
            fields["timestamp"] = datetime.fromtimestamp(fields["timestamp"], UTC)
    if name == "proxy_access":
        fields.update(method="GET", url="http://example/", protocol="HTTP/1.1", sc_bytes=1)
    if name == "zeek_smb_files":
        for key in ("size", "prev_name", "fuid"):
            fields.setdefault(key, None)
    if case.get("variant") == "process_creation":
        fields.setdefault("TargetUserSid", "S-1-0-0")
    path = tmp_path / (name + definition.output.file_extension)
    emitter = _build_emitter_classes()[name](definition, path, threaded=False)
    try:
        raw = (
            emitter._prepare_event(fields)["rendered"]
            if name == "bash_history"
            else emitter._render_alert(fields)
            if name == "snort_alert"
            else emitter._render_event(fields)
        )
        path.write_text(raw + "\n")
        records = list(get_parser(name).parse_file(path))
        assert len(records) == 1
        schema, constraints = ParseabilityScorer()._score_both({name: records})
        assert schema.score == constraints.score == 100, (schema, constraints, raw)
    finally:
        emitter.close()


def test_mixed_native_email_bundle_retains_cross_source_checks() -> None:
    from evidenceforge.evaluation.pillars.plausibility import _score_email_evidence_consistency

    root = FIXTURES / "record_validation/email"
    records = {
        name: list(get_parser(name).parse_file(root / filename))
        for name, filename in (
            ("email_artifacts", "ARTIFACTS_MANIFEST.json"),
            ("zeek_smtp", "smtp.json"),
            ("zeek_conn", "conn.json"),
        )
    }
    schema, constraints = ParseabilityScorer()._score_both(records)
    assert schema.score == constraints.score == 100
    matched, agreeing, failures = _score_email_evidence_consistency(records)
    assert matched == agreeing == 2
    assert failures == []
    records["email_artifacts"][0].fields["subject"] = "Conflicting subject"
    matched, agreeing, failures = _score_email_evidence_consistency(records)
    assert matched == 2 and agreeing == 1
    assert failures


def test_duplicate_parser_registration_is_rejected() -> None:
    from evidenceforge.evaluation.parsers import LogParser, register_parser

    class DuplicateParser(LogParser):
        format_name = "email_artifacts"

    with pytest.raises(ValueError, match="Duplicate parser"):
        register_parser(DuplicateParser)


def test_missing_native_schema_cli_exits_22_without_report(monkeypatch) -> None:
    def missing_schema(name: str):
        raise ConfigurationError(f"Missing schema: {name}")

    monkeypatch.setattr(routes, "load_format", missing_schema)
    result = CliRunner().invoke(
        app,
        [
            "eval",
            str(FIXTURES / "eval/good"),
            "--scenario",
            str(FIXTURES / "scenarios/retail-store-ftp-attack.yaml"),
            "--format",
            "json",
        ],
    )
    assert result.exit_code == 22, result.stderr
    assert result.stdout == ""
    assert "Missing schema" in result.stderr


@pytest.mark.parametrize("message", [{"message_id": []}, {"to": 42}, {"date": "bad-date"}])
def test_malformed_artifact_completes_failed_evaluation(tmp_path: Path, message: dict) -> None:
    import shutil

    for source in (FIXTURES / "record_validation/email").iterdir():
        shutil.copyfile(source, tmp_path / source.name)
    (tmp_path / "ARTIFACTS_MANIFEST.json").write_text(
        json.dumps({"email": {"messages": [message]}})
    )
    result = CliRunner().invoke(
        app,
        [
            "eval",
            str(tmp_path),
            "--scenario",
            str(FIXTURES / "scenarios/retail-store-ftp-attack.yaml"),
            "--format",
            "json",
        ],
    )
    assert result.exit_code == 0, result.stderr
    report = json.loads(result.stdout)
    assert report["source_counts"]["email_artifacts"] == 1
    assert report["acceptance_passed"] is False
    assert all(p["score"] is not None for p in report["pillars"])
    spec = next(s for s in report["pillars"][0]["sub_scores"] if s["key"] == "spec_conformance")
    assert spec["score"] < 100
