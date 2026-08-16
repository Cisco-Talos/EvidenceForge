# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Tests for the dual-signal SnortML + signature + Splunk-notable triage corpus."""

from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest
from scripts.validate_dual_signal_triage_corpus import load_and_validate, validate_corpus

REPO_ROOT = Path(__file__).resolve().parents[2]
CORPUS_PATH = (
    REPO_ROOT / "scenarios" / "dual-signal-triage-corpus" / "corpus" / "labeled_events.json"
)
SCHEMA_PATH = REPO_ROOT / "scenarios" / "dual-signal-triage-corpus" / "corpus" / "schema.json"


@pytest.fixture
def corpus() -> dict:
    return json.loads(CORPUS_PATH.read_text(encoding="utf-8"))


def test_shipped_corpus_validates():
    errors = load_and_validate(CORPUS_PATH)
    assert errors == [], errors


def test_schema_file_present():
    assert SCHEMA_PATH.is_file()
    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    assert schema["properties"]["never_equate_ml_to_signature"]["const"] is True


def test_required_cases_present(corpus: dict):
    cases = {event["case"] for event in corpus["events"]}
    assert "snortml_gid411_high_ml_only" in cases
    assert "signature_only_high" in cases
    assert "signature_plus_ml_corroboration" in cases
    assert "snortml_low" in cases
    assert "splunk_notable_high_risk" in cases
    assert "splunk_notable_low" in cases


def test_ml_only_high_cannot_be_fix_now(corpus: dict):
    bad = copy.deepcopy(corpus)
    for event in bad["events"]:
        if event["case"] == "snortml_gid411_high_ml_only":
            event["label_disposition"] = "fix_now"
            break
    errors = validate_corpus(bad)
    assert any("ml_only" in e and "fix_now" in e for e in errors), errors


def test_ml_only_high_cannot_be_auto_contain(corpus: dict):
    bad = copy.deepcopy(corpus)
    for event in bad["events"]:
        if event["case"] == "snortml_gid411_high_ml_only":
            event["label_disposition"] = "auto_contain"
            break
    errors = validate_corpus(bad)
    assert any("auto_contain" in e or "forbidden" in e for e in errors), errors


def test_missing_flag_fails(corpus: dict):
    bad = copy.deepcopy(corpus)
    bad["never_equate_ml_to_signature"] = False
    errors = validate_corpus(bad)
    assert any("never_equate_ml_to_signature" in e for e in errors)


def test_cli_main_ok(capsys):
    from scripts.validate_dual_signal_triage_corpus import main

    assert main([str(CORPUS_PATH)]) == 0
    assert "OK:" in capsys.readouterr().out
