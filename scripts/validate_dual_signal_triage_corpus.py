#!/usr/bin/env python3
# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Validate the dual-signal SnortML + signature + Splunk-notable triage corpus.

Enforces the SnortML hard rule: ML probability must never be treated as a
signature true positive (no auto-contain / fix_now on ML-only highs).
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

REQUIRED_TOP = ("version", "never_equate_ml_to_signature", "events")
REQUIRED_EVENT = (
    "event_id",
    "case",
    "signal_class",
    "label_disposition",
    "tier_hint",
    "msg",
    "evidence",
)

# Cases whose signal_class implies a signature must (or must not) have actually
# fired in the referenced evidence. Cross-checked against ids_alert presence in
# ../evidence/GROUND_TRUTH.json so a label can't silently drift from what the
# generator actually produced.
SIGNATURE_MUST_FIRE = frozenset({"signature_only", "signature_plus_ml"})
SIGNATURE_MUST_NOT_FIRE = frozenset({"ml_only"})

ALLOWED_CASES = frozenset(
    {
        "signature_only_high",
        "snortml_gid411_high_ml_only",
        "signature_plus_ml_corroboration",
        "snortml_low",
        "splunk_notable_high_risk",
        "splunk_notable_low",
    }
)
ALLOWED_SIGNAL = frozenset({"signature_only", "ml_only", "signature_plus_ml", "splunk_notable"})
ALLOWED_DISPOSITION = frozenset(
    {
        "fix_now",
        "escalate",
        "accept",
        "suppress_fp",
        "triage_t1",
        "triage_t2",
    }
)
FORBIDDEN_DISPOSITIONS = frozenset({"auto_contain", "contain", "block"})
HIGH_ML_THRESHOLD = 0.8

CASE_EXPECTATIONS: dict[str, dict[str, Any]] = {
    "signature_only_high": {
        "signal_class": "signature_only",
        "label_disposition": "fix_now",
    },
    "snortml_gid411_high_ml_only": {
        "signal_class": "ml_only",
        "label_disposition": "escalate",
        "gid": 411,
        "min_ml": HIGH_ML_THRESHOLD,
    },
    "signature_plus_ml_corroboration": {
        "signal_class": "signature_plus_ml",
        "label_disposition": "fix_now",
        "min_ml": HIGH_ML_THRESHOLD,
    },
    "snortml_low": {
        "signal_class": "ml_only",
        "label_disposition": "accept",
        "gid": 411,
        "max_ml": HIGH_ML_THRESHOLD,
    },
    "splunk_notable_high_risk": {
        "signal_class": "splunk_notable",
        "label_disposition": "triage_t2",
    },
    "splunk_notable_low": {
        "signal_class": "splunk_notable",
        "label_disposition": "triage_t1",
    },
}


def _err(errors: list[str], message: str) -> None:
    errors.append(message)


def _load_ground_truth_record_ids_with_alert(scenario_root: Path) -> set[str] | None:
    """record_ids in evidence/GROUND_TRUTH.json that carry an ids_alert.

    Returns None if the ground truth file isn't present (e.g. running the
    validator standalone without having generated evidence/ yet) so callers
    can skip the cross-check rather than fail on a missing optional file.
    """
    gt_path = scenario_root / "evidence" / "GROUND_TRUTH.json"
    if not gt_path.is_file():
        return None
    try:
        gt = json.loads(gt_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    fired: set[str] = set()
    for event in gt.get("events", []):
        if "ids_alert" in event.get("attributes", {}):
            fired.add(event["record_id"])
    return fired


def _validate_evidence(
    errors: list[str],
    prefix: str,
    event: dict[str, Any],
    signal: str | None,
    scenario_root: Path,
    fired_record_ids: set[str] | None,
) -> None:
    """Verify `evidence` points at real, on-disk, content-matching artifacts.

    This is the check that makes the corpus a labeled-with-support dataset
    rather than assertions alone: every source path must exist, every `match`
    string must be a literal substring actually present in that file (with
    optional min_count/max_count), and for signature-bearing signal classes
    the ids_alert presence in GROUND_TRUTH.json must agree with signal_class.
    """
    evidence = event.get("evidence")
    if not isinstance(evidence, dict):
        _err(errors, f"{prefix}: evidence must be an object")
        return

    record_id = evidence.get("ground_truth_record_id")
    if not isinstance(record_id, str) or not record_id:
        _err(errors, f"{prefix}: evidence.ground_truth_record_id must be a non-empty string")

    sources = evidence.get("sources")
    if not isinstance(sources, list) or not sources:
        _err(errors, f"{prefix}: evidence.sources must be a non-empty list")
        return

    for src_idx, source in enumerate(sources):
        src_prefix = f"{prefix}.evidence.sources[{src_idx}]"
        if not isinstance(source, dict):
            _err(errors, f"{src_prefix}: must be an object")
            continue
        rel_path = source.get("path")
        match = source.get("match")
        if not isinstance(rel_path, str) or not rel_path:
            _err(errors, f"{src_prefix}: path must be a non-empty string")
            continue
        if not isinstance(match, str) or not match:
            _err(errors, f"{src_prefix}: match must be a non-empty string")
            continue

        full_path = scenario_root / rel_path
        if not full_path.is_file():
            _err(errors, f"{src_prefix}: evidence file does not exist: {full_path}")
            continue

        try:
            content = full_path.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            _err(errors, f"{src_prefix}: could not read {full_path}: {exc}")
            continue

        count = content.count(match)
        if count == 0:
            _err(errors, f"{src_prefix}: match string not found in {rel_path}: {match!r}")
            continue

        min_count = source.get("min_count")
        if isinstance(min_count, int) and count < min_count:
            _err(
                errors,
                f"{src_prefix}: match occurs {count} time(s) in {rel_path}, "
                f"expected at least {min_count}",
            )
        max_count = source.get("max_count")
        if isinstance(max_count, int) and count > max_count:
            _err(
                errors,
                f"{src_prefix}: match occurs {count} time(s) in {rel_path}, "
                f"expected at most {max_count}",
            )

    # Cross-check: does GROUND_TRUTH.json agree that a signature fired (or
    # didn't) for this record, matching what signal_class claims?
    if fired_record_ids is not None and isinstance(record_id, str) and record_id:
        actually_fired = record_id in fired_record_ids
        if signal in SIGNATURE_MUST_FIRE and not actually_fired:
            _err(
                errors,
                f"{prefix}: signal_class {signal!r} requires a fired signature, but "
                f"GROUND_TRUTH.json record {record_id!r} has no ids_alert "
                "(the seed may have picked a different adversarial_payload variant -- "
                "re-check evidence_seed / regenerate)",
            )
        if signal in SIGNATURE_MUST_NOT_FIRE and actually_fired:
            _err(
                errors,
                f"{prefix}: signal_class {signal!r} requires no fired signature, but "
                f"GROUND_TRUTH.json record {record_id!r} has an ids_alert "
                "(this event would actually be signature-detected, not ML-only)",
            )


def validate_corpus(data: dict[str, Any], scenario_root: Path | None = None) -> list[str]:
    """Return a list of validation error strings (empty means OK)."""
    errors: list[str] = []
    fired_record_ids = (
        _load_ground_truth_record_ids_with_alert(scenario_root) if scenario_root else None
    )

    for key in REQUIRED_TOP:
        if key not in data:
            _err(errors, f"missing top-level field: {key}")
    if errors:
        return errors

    if data.get("version") != "1.0":
        _err(errors, f"version must be '1.0', got {data.get('version')!r}")

    if data.get("never_equate_ml_to_signature") is not True:
        _err(errors, "never_equate_ml_to_signature must be true")

    events = data.get("events")
    if not isinstance(events, list) or not events:
        _err(errors, "events must be a non-empty list")
        return errors

    seen_ids: set[str] = set()
    seen_cases: set[str] = set()

    for idx, event in enumerate(events):
        prefix = f"events[{idx}]"
        if not isinstance(event, dict):
            _err(errors, f"{prefix}: must be an object")
            continue

        for key in REQUIRED_EVENT:
            if key not in event or event[key] in (None, ""):
                _err(errors, f"{prefix}: missing required field {key}")

        event_id = event.get("event_id")
        if isinstance(event_id, str):
            if event_id in seen_ids:
                _err(errors, f"{prefix}: duplicate event_id {event_id!r}")
            seen_ids.add(event_id)

        case = event.get("case")
        if case not in ALLOWED_CASES:
            _err(errors, f"{prefix}: unknown case {case!r}")
        else:
            seen_cases.add(case)

        signal = event.get("signal_class")
        if signal not in ALLOWED_SIGNAL:
            _err(errors, f"{prefix}: unknown signal_class {signal!r}")

        disposition = event.get("label_disposition")
        if disposition in FORBIDDEN_DISPOSITIONS:
            _err(
                errors,
                f"{prefix}: forbidden disposition {disposition!r} "
                "(auto-contain is not a valid ground-truth label)",
            )
        elif disposition not in ALLOWED_DISPOSITION:
            _err(errors, f"{prefix}: unknown label_disposition {disposition!r}")

        # Hard rule: ML-only must never be treated as signature TP / auto action.
        ml_score = event.get("ml_score")
        if signal == "ml_only":
            if disposition in {"fix_now", *FORBIDDEN_DISPOSITIONS}:
                _err(
                    errors,
                    f"{prefix}: ml_only event {event_id!r} labeled {disposition!r}; "
                    "ML probability must not be equated to signature TP "
                    "(use escalate/accept/suppress_fp)",
                )
            if (
                isinstance(ml_score, (int, float))
                and ml_score >= HIGH_ML_THRESHOLD
                and disposition != "escalate"
            ):
                _err(
                    errors,
                    f"{prefix}: high ml_only score ({ml_score}) must label escalate, "
                    f"got {disposition!r}",
                )
            if event.get("gid") not in (411, None) and case in {
                "snortml_gid411_high_ml_only",
                "snortml_low",
            }:
                _err(errors, f"{prefix}: SnortML cases expect gid 411, got {event.get('gid')!r}")

        expectation = CASE_EXPECTATIONS.get(case) if isinstance(case, str) else None
        if expectation:
            if signal != expectation["signal_class"]:
                _err(
                    errors,
                    f"{prefix}: case {case} expects signal_class "
                    f"{expectation['signal_class']!r}, got {signal!r}",
                )
            if disposition != expectation["label_disposition"]:
                _err(
                    errors,
                    f"{prefix}: case {case} expects label_disposition "
                    f"{expectation['label_disposition']!r}, got {disposition!r}",
                )
            if "gid" in expectation and event.get("gid") != expectation["gid"]:
                _err(
                    errors,
                    f"{prefix}: case {case} expects gid {expectation['gid']}, "
                    f"got {event.get('gid')!r}",
                )
            if "min_ml" in expectation:
                if not isinstance(ml_score, (int, float)) or ml_score < expectation["min_ml"]:
                    _err(
                        errors,
                        f"{prefix}: case {case} expects ml_score >= "
                        f"{expectation['min_ml']}, got {ml_score!r}",
                    )
            if "max_ml" in expectation:
                if not isinstance(ml_score, (int, float)) or ml_score >= expectation["max_ml"]:
                    _err(
                        errors,
                        f"{prefix}: case {case} expects ml_score < "
                        f"{expectation['max_ml']}, got {ml_score!r}",
                    )

        if scenario_root is not None and isinstance(event.get("evidence"), dict):
            _validate_evidence(errors, prefix, event, signal, scenario_root, fired_record_ids)

    missing_cases = ALLOWED_CASES - seen_cases
    if missing_cases:
        _err(errors, f"corpus missing required cases: {sorted(missing_cases)}")

    return errors


def load_and_validate(path: Path, *, check_evidence: bool = True) -> list[str]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return [f"failed to load {path}: {exc}"]
    if not isinstance(data, dict):
        return ["corpus root must be a JSON object"]
    # corpus/labeled_events.json -> corpus/ -> scenario root (where
    # evidence-scenario.yaml and evidence/ live). Evidence source paths in
    # the corpus are relative to that root.
    scenario_root = path.resolve().parent.parent if check_evidence else None
    return validate_corpus(data, scenario_root=scenario_root)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "corpus",
        nargs="?",
        type=Path,
        default=Path("scenarios/dual-signal-triage-corpus/corpus/labeled_events.json"),
        help="Path to labeled_events.json",
    )
    parser.add_argument(
        "--no-evidence-check",
        action="store_true",
        help="Skip verifying evidence.sources against on-disk files (schema/policy checks only)",
    )
    args = parser.parse_args(argv)
    errors = load_and_validate(args.corpus, check_evidence=not args.no_evidence_check)
    if errors:
        print(f"FAIL: {args.corpus} ({len(errors)} error(s))", file=sys.stderr)
        for message in errors:
            print(f"  - {message}", file=sys.stderr)
        return 1
    print(f"OK: {args.corpus}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
