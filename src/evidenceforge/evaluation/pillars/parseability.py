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

from evidenceforge.evaluation.context import EvaluationContext
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
from evidenceforge.formats.rules import Finding
from evidenceforge.formats.validator import STRICT_FORMATS, validate_event, validate_strict
from evidenceforge.models.scenario import Scenario

logger = logging.getLogger(__name__)


def _variant_map(format_name: str) -> dict[int, str]:
    """Derive source event selectors from the packaged schema."""
    return {
        event_id: variant.name
        for variant in load_format(format_name).variants or []
        for event_id in variant.event_ids or ([int(variant.event_id)] if variant.event_id else [])
    }


WINDOWS_VARIANT_MAP = _variant_map("windows_event_security")
SYSMON_VARIANT_MAP = _variant_map("windows_event_sysmon")


class ParseabilityScorer(DimensionScorer):
    number = 1
    name = "Parseability"
    weight = 0.30

    def score(
        self,
        records: dict[str, list[ParsedRecord]],
        scenario: Scenario,
        context: EvaluationContext | None = None,
        progress: ProgressCallback = _noop_callback,
    ) -> PillarScore:
        progress("sub_score_start", {"name": "Spec Conformance", "step": 1, "total": 2})
        spec, constraints = self._score_both(records)
        progress("sub_score_done", {"name": "Spec Conformance", "score": spec.score})

        progress("sub_score_start", {"name": "Format Constraints", "step": 2, "total": 2})
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
        return self._score_both(records)[0]

    def _score_format_constraints(self, records: dict[str, list[ParsedRecord]]) -> SubScore:
        return self._score_both(records)[1]

    def _score_both(self, records: dict[str, list[ParsedRecord]]) -> tuple[SubScore, SubScore]:
        """Validate each record once and aggregate bounded diagnostics by category."""
        totals = {"schema": 0, "constraint": 0}
        passing = {"schema": 0, "constraint": 0}
        failures: dict[str, list[str]] = {"schema": [], "constraint": []}
        counts: dict[str, dict[str, dict[str, int]]] = {"schema": {}, "constraint": {}}
        findings: dict[str, list[Finding]] = {"schema": [], "constraint": []}
        for name, items in records.items():
            definition = _load_format_def(name)
            for record in items:
                selected: dict[str, list[Finding]] = {"schema": [], "constraint": []}
                if record.parse_errors:
                    selected["schema"] = [
                        Finding(
                            rule_id="parser.record",
                            format=name,
                            category="parse",
                            message=message,
                        )
                        for message in record.parse_errors
                    ]
                else:
                    variant = _get_variant(name, record)
                    normalized = _normalize_for_validation(name, record.fields, record.timestamp)
                    result = validate_event(
                        definition, normalized, variant, include_diagnostics=False
                    )
                    for finding in result.findings:
                        if finding.severity != "error" or finding.outcome not in {
                            "fail",
                            "evaluation_error",
                        }:
                            continue
                        category = (
                            "schema" if finding.category in {"schema", "parse"} else "constraint"
                        )
                        selected[category].append(finding)
                    if name in STRICT_FORMATS and record.raw:
                        selected["schema"].extend(
                            Finding(
                                rule_id="parser.structure",
                                format=name,
                                variant=variant,
                                category="parse",
                                message=message,
                            )
                            for message in validate_strict(name, record.raw, record.fields).errors
                        )
                for category in totals:
                    if record.parse_errors and category == "constraint":
                        continue
                    totals[category] += 1
                    errors = selected[category]
                    if not errors:
                        passing[category] += 1
                        continue
                    counts[category].setdefault(name, {}).setdefault(category, 0)
                    counts[category][name][category] += 1
                    for finding in errors:
                        if len(failures[category]) < 20:
                            failures[category].append(
                                f"[{name}] line {record.line_number}: {finding.message}"
                            )
                            findings[category].append(finding)

        def subscore(category: str) -> SubScore:
            schema = category == "schema"
            total = totals[category]
            return SubScore(
                name="Spec Conformance" if schema else "Format Constraints",
                key="spec_conformance" if schema else "format_constraints",
                weight=0.55 if schema else 0.45,
                score=100.0 * passing[category] / total if total else 0.0,
                details=f"{passing[category]}/{total} records pass {category} validation",
                sample_failures=failures[category],
                failure_summary=counts[category],
                sample_findings=findings[category],
            )

        return subscore("schema"), subscore("constraint")


# --- Module-level helpers ---


def _load_format_def(format_name: str) -> FormatDefinition:
    """A missing or broken schema is an evaluation error, never a passing record."""
    return load_format(format_name)


def _get_variant(format_name: str, record: ParsedRecord) -> str | None:
    if format_name in ("windows_event_security", "windows_event_sysmon"):
        event_id = record.fields.get("EventID")
        if isinstance(event_id, int):
            if format_name == "windows_event_security":
                return WINDOWS_VARIANT_MAP.get(event_id)
            return SYSMON_VARIANT_MAP.get(event_id)
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
    if format_name in ("web_access", "proxy_access", "syslog", "snort_alert", "bash_history"):
        if parsed_timestamp is not None:
            normalized["timestamp"] = parsed_timestamp
    if format_name == "windows_event_security":
        for port_field in ("IpPort", "NetworkPort"):
            if normalized.get(port_field) == "-":
                normalized[port_field] = 0
        restricted_sid_count = normalized.get("RestrictedSidCount")
        if isinstance(restricted_sid_count, str) and restricted_sid_count.isdigit():
            normalized["RestrictedSidCount"] = int(restricted_sid_count)
    return normalized
