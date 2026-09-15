# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Supported Splunk web/proxy JSON uses the same exact evidence gates."""

import json
from datetime import UTC, datetime
from pathlib import Path

import pytest
from typer.testing import CliRunner

from evidenceforge.cli.commands import app
from evidenceforge.evaluation.parsers import get_parser
from evidenceforge.evaluation.pillars.causality import CausalityScorer
from evidenceforge.evaluation.pillars.parseability import ParseabilityScorer
from evidenceforge.evaluation.storyline import ResolvedEvent

ROOT = Path(__file__).parents[1] / "fixtures/record_validation/targets"


@pytest.mark.parametrize("source", ["web_access", "proxy_access"])
@pytest.mark.parametrize("username", ["-", "alice", "bob", "CORP\\alice", "HOST$"])
def test_apache_json_user_indicator_semantics(source: str, username: str) -> None:
    document = json.loads((ROOT / (source + ".log")).read_text())
    document["user"] = username
    record = get_parser(source)._parse_line(json.dumps(document), 1)
    assert not record.parse_errors
    if username == "-":
        assert "username" not in record.fields
    else:
        assert record.fields["username"] == username
    event = ResolvedEvent(
        index=0,
        time=datetime(2024, 3, 18, tzinfo=UTC),
        actor="alice",
        system="WEB-01",
        system_ip=None,
        activity="HTTP request",
        details={},
        event_types=["connection"],
    )
    checks = CausalityScorer()._check_indicators(event, record)
    if username == "-":
        assert not any(name == "username" for name, _ in checks)
    elif username in {"alice", "bob"}:
        assert ("username", username == "alice") in checks


@pytest.mark.parametrize("source", ["web_access", "proxy_access"])
@pytest.mark.parametrize("reverse", [False, True])
def test_anonymous_user_does_not_hide_conflicting_alias(source: str, reverse: bool) -> None:
    document = json.loads((ROOT / (source + ".log")).read_text())
    document.update(user="-", username="alice")
    if reverse:
        document = dict(reversed(document.items()))
    record = get_parser(source)._parse_line(json.dumps(document), 1)
    assert "Conflicting JSON field: username" in record.parse_errors


@pytest.mark.parametrize("source", ["web_access", "proxy_access"])
@pytest.mark.parametrize(
    "mutation",
    [
        None,
        "timestamp",
        "uri_path",
        "bytes_out",
        "bytes_in",
        "dest_port",
        "response_time_microseconds",
        "client",
        "conflict",
        "username_conflict",
        "shape",
    ],
)
def test_apache_json_records_stay_counted(
    tmp_path: Path, source: str, mutation: str | None
) -> None:
    document = json.loads((ROOT / (source + ".log")).read_text())
    if mutation == "shape":
        document = []
    elif mutation == "conflict":
        document["client_ip"] = "192.0.2.99"
    elif mutation == "username_conflict":
        document.update(user="-", username="alice")
    elif mutation:
        document[mutation] = {"invalid": "value"}
    path = tmp_path / (source + ".log")
    path.write_text(json.dumps(document) + "\n")
    records = list(get_parser(source).parse_file(path))
    assert len(records) == 1
    scores = ParseabilityScorer()._score_both({source: records})
    if mutation is None:
        assert all(s.score == 100 for s in scores)
    else:
        assert any(s.score < 100 for s in scores)
    result = CliRunner().invoke(
        app,
        [
            "eval",
            str(tmp_path),
            "--scenario",
            str(ROOT.parents[1] / "scenarios/retail-store-ftp-attack.yaml"),
            "--format",
            "json",
        ],
    )
    assert result.exit_code == 0, result.stderr
    report = json.loads(result.stdout)
    assert report["source_counts"][source] == 1
    if mutation is not None:
        assert report["acceptance_passed"] is False


def test_snare_projection_gap_remains_visible() -> None:
    """Do not silently waive missing XML metadata or invent ambiguous account fields."""
    records = list(
        get_parser("windows_event_security").parse_file(ROOT / "windows_event_security_snare.log")
    )
    assert len(records) == 1
    schema, _ = ParseabilityScorer()._score_both({"windows_event_security": records})
    assert schema.score == 0
    assert "Level" in {f.rule_id for f in schema.sample_findings}
