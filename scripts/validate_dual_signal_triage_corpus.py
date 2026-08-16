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
)

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


def validate_corpus(data: dict[str, Any]) -> list[str]:
    """Return a list of validation error strings (empty means OK)."""
    errors: list[str] = []

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

    missing_cases = ALLOWED_CASES - seen_cases
    if missing_cases:
        _err(errors, f"corpus missing required cases: {sorted(missing_cases)}")

    return errors


def load_and_validate(path: Path) -> list[str]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return [f"failed to load {path}: {exc}"]
    if not isinstance(data, dict):
        return ["corpus root must be a JSON object"]
    return validate_corpus(data)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "corpus",
        nargs="?",
        type=Path,
        default=Path("scenarios/dual-signal-triage-corpus/corpus/labeled_events.json"),
        help="Path to labeled_events.json",
    )
    args = parser.parse_args(argv)
    errors = load_and_validate(args.corpus)
    if errors:
        print(f"FAIL: {args.corpus} ({len(errors)} error(s))", file=sys.stderr)
        for message in errors:
            print(f"  - {message}", file=sys.stderr)
        return 1
    print(f"OK: {args.corpus}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
