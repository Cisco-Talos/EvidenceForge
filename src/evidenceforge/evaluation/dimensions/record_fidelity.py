"""Dimension 1: Record-Level Fidelity scoring.

Sub-scores:
  Tier A (0.40): Parsability & Structure — records parse, required fields, valid types.
  Tier B (0.35): Co-occurrence Rules — field combinations that must co-occur.
  Tier C (0.25): Population Statistics — aggregate distributions match reference profiles.
"""

import logging
import math
from collections import Counter
from typing import Any

from evidenceforge.evaluation.dimensions import (
    DimensionScorer,
    ProgressCallback,
    _noop_callback,
)
from evidenceforge.evaluation.models import DimensionScore, SubScore
from evidenceforge.evaluation.parsers import ParsedRecord
from evidenceforge.evaluation.rules import load_rules_file
from evidenceforge.formats.format_def import FormatDefinition
from evidenceforge.formats.loader import load_format
from evidenceforge.formats.validator import validate_event
from evidenceforge.models.scenario import Scenario

logger = logging.getLogger(__name__)

# EventID -> variant name mapping for Windows Event Security
WINDOWS_VARIANT_MAP = {
    4624: "logon",
    4625: "failed_logon",
    4634: "logoff",
    4672: "special_privileges",
    4688: "process_creation",
    4689: "process_termination",
}


class RecordFidelityScorer(DimensionScorer):
    number = 1
    name = "Record-Level Fidelity"
    weight = 0.15

    def score(
        self,
        records: dict[str, list[ParsedRecord]],
        scenario: Scenario,
        progress: ProgressCallback = _noop_callback,
    ) -> DimensionScore:
        progress("sub_score_start", {"name": "Parsability & Structure", "step": 1, "total": 3})
        tier_a = self._score_tier_a(records)
        progress("sub_score_done", {"name": "Parsability & Structure", "score": tier_a.score})

        progress("sub_score_start", {"name": "Co-occurrence Rules", "step": 2, "total": 3})
        tier_b = self._score_tier_b(records)
        progress("sub_score_done", {"name": "Co-occurrence Rules", "score": tier_b.score})

        progress("sub_score_start", {"name": "Population Statistics", "step": 3, "total": 3})
        tier_c = self._score_tier_c(records)
        progress("sub_score_done", {"name": "Population Statistics", "score": tier_c.score})

        sub_scores = [tier_a, tier_b, tier_c]
        dim_score = sum(s.score * s.weight for s in sub_scores if s.score is not None)

        return DimensionScore(
            number=self.number,
            name=self.name,
            weight=self.weight,
            score=dim_score,
            sub_scores=sub_scores,
        )

    def _score_tier_a(self, records: dict[str, list[ParsedRecord]]) -> SubScore:
        """Tier A: Parsability & Structure.

        Validates each record against its format definition for required fields,
        types, and constraints.
        """
        total = 0
        passing = 0
        failures: list[str] = []

        for format_name, record_list in records.items():
            fmt_def = self._load_format_def(format_name)
            for record in record_list:
                total += 1

                # If the record had parse errors, it fails Tier A
                if record.parse_errors:
                    if len(failures) < 10:
                        failures.append(
                            f"[{format_name}] Parse error: {record.parse_errors[0]}"
                        )
                    continue

                # Validate against format definition if available
                if fmt_def is not None:
                    variant = self._get_variant(format_name, record)
                    # Normalize fields for validation (e.g., epoch timestamps)
                    normalized = self._normalize_for_validation(
                        format_name, record.fields, record.timestamp
                    )
                    result = validate_event(fmt_def, normalized, variant)
                    if result.valid:
                        passing += 1
                    elif len(failures) < 10:
                        failures.append(
                            f"[{format_name}] {result.errors[0]}"
                        )
                else:
                    # No format def — count as passing if parsed successfully
                    passing += 1

        score = (100.0 * passing / total) if total > 0 else 100.0
        return SubScore(
            name="Parsability & Structure",
            key="parsability",
            weight=0.40,
            score=score,
            details=f"{passing}/{total} records pass structure validation",
            sample_failures=failures,
        )

    def _score_tier_b(self, records: dict[str, list[ParsedRecord]]) -> SubScore:
        """Tier B: Co-occurrence Rules.

        Checks field combinations that must co-occur or have specific values.
        """
        co_occurrence_rules = load_rules_file("co_occurrence.yaml")
        total_applicable = 0
        passing = 0
        failures: list[str] = []

        for format_name, record_list in records.items():
            rules = co_occurrence_rules.get(format_name, [])
            if not rules:
                continue

            for record in record_list:
                if record.parse_errors:
                    continue

                for rule in rules:
                    if self._condition_matches(rule.get("condition", {}), record.fields):
                        total_applicable += 1
                        checks = rule.get("checks", [])
                        all_pass = all(
                            self._check_passes(check, record.fields)
                            for check in checks
                        )
                        if all_pass:
                            passing += 1
                        elif len(failures) < 10:
                            failures.append(
                                f"[{format_name}] Rule '{rule['name']}' failed"
                            )

        score = (100.0 * passing / total_applicable) if total_applicable > 0 else 100.0
        return SubScore(
            name="Co-occurrence Rules",
            key="co_occurrence",
            weight=0.35,
            score=score,
            details=f"{passing}/{total_applicable} applicable rule checks pass",
            sample_failures=failures,
        )

    def _score_tier_c(self, records: dict[str, list[ParsedRecord]]) -> SubScore:
        """Tier C: Population Statistics.

        Compares observed field distributions against reference profiles.
        """
        dist_profiles = load_rules_file("distributions.yaml")
        divergence_scores: list[float] = []
        details_parts: list[str] = []

        for format_name, record_list in records.items():
            profiles = dist_profiles.get(format_name, [])
            if not profiles:
                continue

            valid_records = [r for r in record_list if not r.parse_errors]
            if not valid_records:
                continue

            for profile in profiles:
                field = profile["field"]
                reference = profile["reference"]
                tolerance = profile.get("tolerance", 0.25)

                # Build observed distribution
                observed_counts = Counter()
                total = 0
                for record in valid_records:
                    val = record.fields.get(field)
                    if val is not None:
                        # Coerce to the reference key type
                        key = self._coerce_key(val, reference)
                        observed_counts[key] += 1
                        total += 1

                if total == 0:
                    continue

                observed = {k: v / total for k, v in observed_counts.items()}

                # Calculate Jensen-Shannon divergence
                jsd = self._jensen_shannon_divergence(reference, observed)
                # Convert to a 0-100 score: 0 divergence = 100, tolerance divergence = 50
                if jsd <= 0:
                    field_score = 100.0
                elif jsd >= tolerance * 2:
                    field_score = 0.0
                else:
                    field_score = max(0.0, 100.0 * (1.0 - jsd / (tolerance * 2)))

                divergence_scores.append(field_score)
                details_parts.append(f"{format_name}.{field}: {field_score:.0f}")

        score = (
            sum(divergence_scores) / len(divergence_scores)
            if divergence_scores
            else 100.0
        )
        return SubScore(
            name="Population Statistics",
            key="distributions",
            weight=0.25,
            score=score,
            details="; ".join(details_parts) if details_parts else "No distribution profiles applicable",
            sample_failures=[],
        )

    # --- Helpers ---

    @staticmethod
    def _normalize_for_validation(
        format_name: str,
        fields: dict[str, Any],
        parsed_timestamp: Any | None,
    ) -> dict[str, Any]:
        """Normalize field values for format validation.

        Handles cases where parsers produce different representations than
        what the format validator expects (e.g., epoch timestamps vs ISO 8601).
        """
        normalized = dict(fields)

        # Zeek ts field: epoch float string -> datetime (validator expects timestamp type)
        if format_name == "zeek_conn" and "ts" in normalized:
            ts = normalized["ts"]
            if parsed_timestamp is not None:
                normalized["ts"] = parsed_timestamp
            elif isinstance(ts, str):
                try:
                    normalized["ts"] = float(ts)
                except ValueError:
                    pass

        # eCAR timestamp_ms: already an int, validator handles it

        return normalized

    @staticmethod
    def _load_format_def(format_name: str) -> FormatDefinition | None:
        try:
            return load_format(format_name)
        except Exception:
            return None

    @staticmethod
    def _get_variant(format_name: str, record: ParsedRecord) -> str | None:
        if format_name == "windows_event_security":
            event_id = record.fields.get("EventID")
            if isinstance(event_id, int):
                return WINDOWS_VARIANT_MAP.get(event_id)
        return None

    @staticmethod
    def _condition_matches(condition: dict[str, Any], fields: dict[str, Any]) -> bool:
        """Check if a record's fields match a rule's condition."""
        if not condition:
            return True
        for key, expected in condition.items():
            actual = fields.get(key)
            if actual != expected:
                # Try string/int coercion
                try:
                    if str(actual) != str(expected):
                        return False
                except (ValueError, TypeError):
                    return False
        return True

    @staticmethod
    def _check_passes(check: dict[str, Any], fields: dict[str, Any]) -> bool:
        """Evaluate a single co-occurrence check against record fields."""
        field_name = check.get("field", "")
        value = fields.get(field_name)

        if "present" in check:
            return value is not None

        if "not_equal" in check:
            return value is not None and value != check["not_equal"]

        if "min_length" in check:
            return isinstance(value, str) and len(value) >= check["min_length"]

        if "min_value" in check and "max_value" in check:
            try:
                v = int(value) if not isinstance(value, (int, float)) else value
                return check["min_value"] <= v <= check["max_value"]
            except (ValueError, TypeError):
                return False

        if "in" in check:
            return value in check["in"]

        return True

    @staticmethod
    def _coerce_key(value: Any, reference: dict) -> Any:
        """Coerce a value to match reference key types."""
        sample_key = next(iter(reference), None)
        if sample_key is None:
            return value
        if isinstance(sample_key, int) and not isinstance(value, int):
            try:
                return int(value)
            except (ValueError, TypeError):
                return value
        if isinstance(sample_key, str) and not isinstance(value, str):
            return str(value)
        return value

    @staticmethod
    def _jensen_shannon_divergence(p: dict, q: dict) -> float:
        """Calculate Jensen-Shannon divergence between two distributions.

        Both p and q are dicts mapping keys to probabilities.
        Returns a value in [0, ln(2)] ≈ [0, 0.693].
        """
        all_keys = set(p.keys()) | set(q.keys())
        jsd = 0.0
        for key in all_keys:
            p_val = p.get(key, 0.0)
            q_val = q.get(key, 0.0)
            m_val = (p_val + q_val) / 2.0

            if p_val > 0 and m_val > 0:
                jsd += 0.5 * p_val * math.log(p_val / m_val)
            if q_val > 0 and m_val > 0:
                jsd += 0.5 * q_val * math.log(q_val / m_val)

        return max(0.0, jsd)
