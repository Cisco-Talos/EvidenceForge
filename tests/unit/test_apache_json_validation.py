# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Supported Splunk web/proxy JSON uses the same exact evidence gates."""

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from evidenceforge.cli.commands import app
from evidenceforge.evaluation.parsers import get_parser
from evidenceforge.evaluation.pillars.parseability import ParseabilityScorer

ROOT = Path(__file__).parents[1] / "fixtures/record_validation/targets"


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
