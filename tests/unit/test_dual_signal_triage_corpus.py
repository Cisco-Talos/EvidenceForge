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
SCENARIO_ROOT = REPO_ROOT / "scenarios" / "dual-signal-triage-corpus"
EVIDENCE_GENERATED = (SCENARIO_ROOT / "evidence" / "GROUND_TRUTH.json").is_file()


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


def test_every_event_declares_evidence(corpus: dict):
    for event in corpus["events"]:
        evidence = event["evidence"]
        assert evidence["ground_truth_record_id"]
        assert evidence["sources"], event["event_id"]


@pytest.mark.skipif(
    not EVIDENCE_GENERATED,
    reason="evidence/ not generated (run: uv run eforge generate "
    "scenarios/dual-signal-triage-corpus/evidence-scenario.yaml --seed 1234 "
    "-o scenarios/dual-signal-triage-corpus/evidence)",
)
def test_evidence_sources_exist_and_match_on_disk():
    """Every evidence.sources[].match string is a real, literal substring of a
    real, generated file -- this is the check that stops the corpus from
    drifting back into asserted-but-unsupported labels."""
    errors = load_and_validate(CORPUS_PATH)
    assert errors == [], errors


@pytest.mark.skipif(not EVIDENCE_GENERATED, reason="evidence/ not generated")
def test_ml_only_events_have_no_fired_signature_in_ground_truth(corpus: dict):
    gt = json.loads((SCENARIO_ROOT / "evidence" / "GROUND_TRUTH.json").read_text())
    fired = {e["record_id"] for e in gt["events"] if "ids_alert" in e.get("attributes", {})}
    for event in corpus["events"]:
        if event["signal_class"] == "ml_only":
            record_id = event["evidence"]["ground_truth_record_id"]
            assert record_id not in fired, (
                f"{event['event_id']} is labeled ml_only but its evidence "
                f"({record_id}) actually fired a signature -- it should be "
                "signature_only or signature_plus_ml instead"
            )


@pytest.mark.skipif(not EVIDENCE_GENERATED, reason="evidence/ not generated")
def test_signature_events_have_fired_signature_in_ground_truth(corpus: dict):
    gt = json.loads((SCENARIO_ROOT / "evidence" / "GROUND_TRUTH.json").read_text())
    fired = {e["record_id"] for e in gt["events"] if "ids_alert" in e.get("attributes", {})}
    for event in corpus["events"]:
        if event["signal_class"] in ("signature_only", "signature_plus_ml"):
            record_id = event["evidence"]["ground_truth_record_id"]
            assert record_id in fired, (
                f"{event['event_id']} claims a fired signature but its evidence "
                f"({record_id}) has no ids_alert in GROUND_TRUTH.json"
            )


def test_tampered_evidence_reference_is_rejected(corpus: dict, tmp_path: Path):
    """A corpus claiming ml_only evidence for a request that actually fired
    the signature must fail validation, not silently pass."""
    bad = copy.deepcopy(corpus)
    for event in bad["events"]:
        if event["case"] == "snortml_gid411_high_ml_only":
            event["evidence"]["ground_truth_record_id"] = "evt-sqli-a#0"  # a fired-signature record
            break
    bad_path = tmp_path / "labeled_events.json"
    bad_path.write_text(json.dumps(bad), encoding="utf-8")
    errors = load_and_validate(bad_path, check_evidence=False)
    assert errors == [], "sanity: schema-only check should still pass"

    if not EVIDENCE_GENERATED:
        pytest.skip("evidence/ not generated; cannot exercise the cross-check itself")
    # Point the tmp corpus at the real scenario_root by validating in place.
    real_bad_path = SCENARIO_ROOT / "corpus" / "_tmp_tampered_for_test.json"
    real_bad_path.write_text(json.dumps(bad), encoding="utf-8")
    try:
        errors = load_and_validate(real_bad_path)
    finally:
        real_bad_path.unlink()
    assert any("has an ids_alert" in e for e in errors), errors
