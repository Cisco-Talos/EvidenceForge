# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
#
# SPDX-License-Identifier: MIT

"""Pillar 1: Parseability scoring.

Sub-scores:
  spec_conformance (0.55): Records parse cleanly under strict-mode rules.
  format_constraints (0.45): Records satisfy per-field constraint rules.
"""

import logging
from typing import Any

from evidenceforge.evaluation.dimensions import (
    DimensionScorer,
    ProgressCallback,
    _noop_callback,
    aggregate_sub_scores,
)
from evidenceforge.evaluation.models import PillarScore, SubScore
from evidenceforge.evaluation.parsers import ParsedRecord
from evidenceforge.formats.format_def import FormatDefinition
from evidenceforge.formats.loader import load_format
from evidenceforge.formats.validator import STRICT_FORMATS, validate_event, validate_strict
from evidenceforge.models.scenario import Scenario

logger = logging.getLogger(__name__)

# EventID → variant name mapping for Windows Event Security
WINDOWS_VARIANT_MAP = {
    1102: "log_cleared",
    4624: "logon",
    4625: "failed_logon",
    4634: "logoff",
    4648: "explicit_credentials",
    4672: "special_privileges",
    4688: "process_creation",
    4689: "process_termination",
    4697: "service_installed",
    4698: "scheduled_task",
    4800: "workstation_locked",
    4801: "workstation_unlocked",
    4720: "account_created",
    4723: "password_change",
    4724: "password_reset",
    4726: "account_deleted",
    4728: "group_membership_change",
    4729: "group_membership_change",
    4732: "group_membership_change",
    4733: "group_membership_change",
    4738: "account_changed",
    4756: "group_membership_change",
    4757: "group_membership_change",
    4768: "kerberos_tgt",
    4769: "kerberos_service_ticket",
    4770: "kerberos_service_ticket",
    4771: "kerberos_preauth_failed",
    4776: "ntlm_validation",
    5156: "wfp_connection",
}

# Error category constants
_SPEC_CATEGORIES = {"parse_error", "missing_field", "strict_validation"}
_CONSTRAINT_CATEGORIES = {"constraint_violation", "validation_error"}


class ParseabilityScorer(DimensionScorer):
    number = 1
    name = "Parseability"
    weight = 0.30

    def score(
        self,
        records: dict[str, list[ParsedRecord]],
        scenario: Scenario,
        progress: ProgressCallback = _noop_callback,
    ) -> PillarScore:
        progress("sub_score_start", {"name": "Spec Conformance", "step": 1, "total": 2})
        spec = self._score_spec_conformance(records)
        progress("sub_score_done", {"name": "Spec Conformance", "score": spec.score})

        progress("sub_score_start", {"name": "Format Constraints", "step": 2, "total": 2})
        constraints = self._score_format_constraints(records)
        progress("sub_score_done", {"name": "Format Constraints", "score": constraints.score})

        sub_scores = [spec, constraints]
        dim_score = aggregate_sub_scores(sub_scores)

        return PillarScore(
            number=self.number,
            name=self.name,
            weight=self.weight,
            score=dim_score,
            sub_scores=sub_scores,
        )

    def _score_spec_conformance(self, records: dict[str, list[ParsedRecord]]) -> SubScore:
        """Spec conformance: parse errors + strict-mode validation failures.

        Counts records where the parser returned errors OR the strict validator
        (RFC5424 syslog, Zeek typed columns, eCAR schema, Windows XML) rejected
        the record. These failures indicate a downstream parser would reject the
        record entirely.
        """
        total = 0
        passing = 0
        failures: list[str] = []
        failure_counts: dict[str, dict[str, int]] = {}

        def _track(fmt: str, category: str, detail: str) -> None:
            failure_counts.setdefault(fmt, {})
            failure_counts[fmt][category] = failure_counts[fmt].get(category, 0) + 1
            if len(failures) < 20:
                failures.append(detail)

        for format_name, record_list in records.items():
            fmt_def = _load_format_def(format_name)
            for record in record_list:
                total += 1

                if record.parse_errors:
                    ctx = _build_event_context(format_name, record, None)
                    ctx_label = f" ({ctx})" if ctx else ""
                    line_info = f" (line {record.line_number})" if record.line_number else ""
                    for err in record.parse_errors:
                        _track(
                            format_name,
                            "parse_error",
                            f"[{format_name}{ctx_label}]{line_info} Parse error: {err}",
                        )
                    continue

                if fmt_def is not None:
                    variant = _get_variant(format_name, record)
                    ctx = _build_event_context(format_name, record, variant)
                    ctx_label = f" ({ctx})" if ctx else ""
                    normalized = _normalize_for_validation(
                        format_name, record.fields, record.timestamp
                    )
                    result = validate_event(fmt_def, normalized, variant, event_context=ctx)

                    # Strict-mode: required field & type checks count as spec failures
                    spec_errors = (
                        [
                            e
                            for e in result.errors
                            if "required field missing" in e.lower()
                            or "invalid" in e.lower()
                            or "expected" in e.lower()
                        ]
                        if not result.valid
                        else []
                    )

                    # Strict parser check (format-level byte validation)
                    strict_failed = False
                    if format_name in STRICT_FORMATS and record.raw:
                        strict_result = validate_strict(format_name, record.raw, record.fields)
                        if not strict_result.valid:
                            for err in strict_result.errors:
                                _track(
                                    format_name,
                                    "strict_validation",
                                    f"[{format_name}{ctx_label}] Strict: {err}",
                                )
                            strict_failed = True

                    if spec_errors or strict_failed:
                        line_info = f" (line {record.line_number})" if record.line_number else ""
                        for err in spec_errors:
                            _track(
                                format_name,
                                _categorize_error(err),
                                f"[{format_name}{ctx_label}]{line_info} {err}",
                            )
                    else:
                        passing += 1
                else:
                    passing += 1

        score = (100.0 * passing / total) if total > 0 else 100.0
        return SubScore(
            name="Spec Conformance",
            key="spec_conformance",
            weight=0.55,
            score=score,
            details=f"{passing}/{total} records pass strict spec validation",
            sample_failures=failures,
            failure_summary=failure_counts,
        )

    def _score_format_constraints(self, records: dict[str, list[ParsedRecord]]) -> SubScore:
        """Format constraints: per-field enum/range/regex violations.

        Counts records with constraint violations (enum out-of-range, regex mismatch,
        invalid type coercion). These don't fail the strict parser but do violate
        the format's declared field contracts.
        """
        total = 0
        passing = 0
        failures: list[str] = []
        failure_counts: dict[str, dict[str, int]] = {}

        def _track(fmt: str, category: str, detail: str) -> None:
            failure_counts.setdefault(fmt, {})
            failure_counts[fmt][category] = failure_counts[fmt].get(category, 0) + 1
            if len(failures) < 20:
                failures.append(detail)

        for format_name, record_list in records.items():
            fmt_def = _load_format_def(format_name)
            for record in record_list:
                if record.parse_errors:
                    continue  # Excluded from constraint scoring (already in spec_conformance)

                if fmt_def is not None:
                    variant = _get_variant(format_name, record)
                    ctx = _build_event_context(format_name, record, variant)
                    ctx_label = f" ({ctx})" if ctx else ""
                    normalized = _normalize_for_validation(
                        format_name, record.fields, record.timestamp
                    )
                    result = validate_event(fmt_def, normalized, variant, event_context=ctx)

                    # Only count constraint errors (not missing-field / strict errors)
                    constraint_errors = (
                        [
                            e
                            for e in result.errors
                            if "required field missing" not in e.lower()
                            and "invalid" not in e.lower()
                            and "expected" not in e.lower()
                        ]
                        if not result.valid
                        else []
                    )

                    # Also check strict parser for constraint-style issues
                    if format_name in STRICT_FORMATS and record.raw:
                        strict_result = validate_strict(format_name, record.raw, record.fields)
                        # Only strict non-spec errors (e.g. malformed value)
                        constraint_strict = [
                            e for e in strict_result.errors if "required" not in e.lower()
                        ]
                        constraint_errors.extend(constraint_strict)

                    total += 1
                    if not constraint_errors:
                        passing += 1
                    else:
                        line_info = f" (line {record.line_number})" if record.line_number else ""
                        for err in constraint_errors:
                            _track(
                                format_name,
                                "constraint_violation",
                                f"[{format_name}{ctx_label}]{line_info} {err}",
                            )
                else:
                    total += 1
                    passing += 1

        score = (100.0 * passing / total) if total > 0 else 100.0
        return SubScore(
            name="Format Constraints",
            key="format_constraints",
            weight=0.45,
            score=score,
            details=f"{passing}/{total} records pass format constraint checks",
            sample_failures=failures,
            failure_summary=failure_counts,
        )


# --- Module-level helpers ---


def _load_format_def(format_name: str) -> FormatDefinition | None:
    try:
        return load_format(format_name)
    except Exception:
        return None


def _get_variant(format_name: str, record: ParsedRecord) -> str | None:
    if format_name == "windows_event_security":
        event_id = record.fields.get("EventID")
        if isinstance(event_id, int):
            return WINDOWS_VARIANT_MAP.get(event_id)
    return None


def _build_event_context(format_name: str, record: ParsedRecord, variant: str | None) -> str:
    if format_name in ("windows_event_security", "windows_event_sysmon"):
        eid = record.fields.get("EventID", "?")
        parts = [f"EventID {eid}"]
        if variant:
            parts.append(variant)
        return ", ".join(parts)
    if format_name.startswith("zeek_"):
        return format_name.replace("zeek_", "") + ".log"
    if format_name == "ecar":
        obj = record.fields.get("object", "?")
        action = record.fields.get("action", "?")
        return f"{obj}/{action}"
    if format_name == "syslog":
        return f"app={record.fields.get('app_name', '?')}"
    if format_name == "snort_alert":
        return f"SID {record.fields.get('sid', '?')}"
    return ""


def _normalize_for_validation(
    format_name: str,
    fields: dict[str, Any],
    parsed_timestamp: Any | None,
) -> dict[str, Any]:
    normalized = dict(fields)
    if format_name.startswith("zeek_") and "ts" in normalized:
        ts = normalized["ts"]
        if parsed_timestamp is not None:
            normalized["ts"] = parsed_timestamp
        elif isinstance(ts, (int, float)):
            normalized["ts"] = ts
        elif isinstance(ts, str):
            try:
                normalized["ts"] = float(ts)
            except ValueError:
                pass
    if format_name in ("web_access", "syslog", "snort_alert", "bash_history"):
        if parsed_timestamp is not None:
            normalized["timestamp"] = parsed_timestamp
    return normalized


def _categorize_error(error_msg: str) -> str:
    lower = error_msg.lower()
    if "required field missing" in lower:
        return "missing_field"
    if "invalid" in lower or "expected" in lower:
        return "constraint_violation"
    return "validation_error"
