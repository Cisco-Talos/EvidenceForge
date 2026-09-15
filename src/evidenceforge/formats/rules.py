# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Bounded, typed predicates for developer-owned record contracts."""

from __future__ import annotations

import ipaddress
import math
import re
from typing import Annotated, Any, Literal

from pydantic import BaseModel, ConfigDict, Field, PrivateAttr, model_validator

Scalar = str | int | float | bool | None


class Predicate(BaseModel):
    """Common strict predicate configuration."""

    model_config = ConfigDict(extra="forbid", frozen=True)
    field: str


class Presence(Predicate):
    """Test non-null presence; empty strings and zero remain present."""

    op: Literal["presence"]
    present: bool = Field(default=True, strict=True)


class Compare(Predicate):
    """Compare a field with one literal or another literal field name."""

    op: Literal["compare"]
    relation: Literal["eq", "ne", "lt", "le", "gt", "ge"]
    value: Scalar = None
    other_field: str | None = None

    @model_validator(mode="after")
    def check_operand(self) -> Compare:
        """Require exactly one explicit comparison operand."""
        if ("value" in self.model_fields_set) == (self.other_field is not None):
            raise ValueError("compare requires exactly one of value or other_field")
        return self


class Membership(Predicate):
    """Test membership in a finite literal pool."""

    op: Literal["membership"]
    values: tuple[Scalar, ...] = Field(min_length=1)


class Bounds(Predicate):
    """Require finite numeric bounds."""

    op: Literal["bounds"]
    minimum: float | None = Field(default=None, strict=True)
    maximum: float | None = Field(default=None, strict=True)

    @model_validator(mode="after")
    def check_bounds(self) -> Bounds:
        """Reject empty, inverted, or nonfinite bounds."""
        if self.minimum is None and self.maximum is None:
            raise ValueError("bounds requires minimum or maximum")
        if any(v is not None and not math.isfinite(v) for v in (self.minimum, self.maximum)):
            raise ValueError("bounds must be finite")
        if self.minimum is not None and self.maximum is not None and self.minimum > self.maximum:
            raise ValueError("minimum must not exceed maximum")
        return self


class Length(Predicate):
    """Require a string or list length."""

    op: Literal["length"]
    minimum: int = Field(default=0, ge=0, strict=True)
    maximum: int | None = Field(default=None, ge=0, strict=True)

    @model_validator(mode="after")
    def check_bounds(self) -> Length:
        """Reject inverted length bounds."""
        if self.maximum is not None and self.minimum > self.maximum:
            raise ValueError("minimum must not exceed maximum")
        return self


class Pattern(Predicate):
    """Require a compiled regular expression match."""

    op: Literal["pattern"]
    pattern: str

    @model_validator(mode="after")
    def check_pattern(self) -> Pattern:
        """Reject invalid expressions at definition load time."""
        try:
            re.compile(self.pattern)
        except re.error as exc:
            raise ValueError(f"Invalid pattern: {exc}") from exc
        return self


class SameLength(Predicate):
    """Require equal lengths of two present lists."""

    op: Literal["same_length"]
    other_field: str


class Combination(Predicate):
    """Require a supported pair of field values."""

    op: Literal["combination"]
    other_field: str
    pairs: tuple[tuple[Scalar, Scalar], ...] = Field(min_length=1)


class AddressFamily(Predicate):
    """Compare an IP address with a source-native IPv6 flag."""

    op: Literal["address_family"]
    other_field: str


Check = Annotated[
    Presence
    | Compare
    | Membership
    | Bounds
    | Length
    | Pattern
    | SameLength
    | Combination
    | AddressFamily,
    Field(discriminator="op"),
]


class RecordRule(BaseModel):
    """One conjunction of checks with explicit applicability and exclusions."""

    model_config = ConfigDict(extra="forbid", frozen=True)
    id: str = Field(pattern=r"^[a-z0-9][a-z0-9_.-]*$")
    message: str = Field(min_length=1)
    severity: Literal["error", "warning"] = "error"
    when: tuple[Check, ...] = ()
    exclude: tuple[Check, ...] = ()
    checks: tuple[Check, ...] = Field(min_length=1)
    _references: tuple[str, ...] = PrivateAttr(default=())

    @model_validator(mode="after")
    def compile_references(self) -> RecordRule:
        """Compile literal field references once when loading the rule."""
        self._references = tuple(
            dict.fromkeys(
                name
                for check in (*self.when, *self.exclude, *self.checks)
                for name in predicate_fields(check)
            )
        )
        return self


class Finding(BaseModel):
    """Machine-readable source validation outcome."""

    model_config = ConfigDict(extra="forbid", frozen=True)
    rule_id: str
    format: str = ""
    variant: str | None = None
    fields: tuple[str, ...] = ()
    category: Literal["schema", "constraint", "parse", "evaluation"] = "constraint"
    severity: Literal["error", "warning"] = "error"
    outcome: Literal["pass", "fail", "not_applicable", "evaluation_error"] = "fail"
    message: str


def predicate_fields(check: Check) -> tuple[str, ...]:
    """Return literal field references used by a predicate."""
    other = getattr(check, "other_field", None)
    return (check.field, other) if other is not None else (check.field,)


def scalar_equal(value: Any, other: Any) -> bool:
    """Compare numeric values without conflating booleans with numbers."""
    numeric = (int, float)
    compatible = type(value) is type(other) or (
        isinstance(value, numeric)
        and not isinstance(value, bool)
        and isinstance(other, numeric)
        and not isinstance(other, bool)
    )
    return compatible and value == other


def predicate_passes(check: Check, fields: dict[str, Any]) -> bool:
    """Execute one bounded predicate without coercing observed values."""
    value = fields.get(check.field)
    if isinstance(check, Presence):
        return (value is not None) == check.present
    if value is None:
        return (
            check.field in fields
            and isinstance(check, Compare)
            and check.other_field is None
            and check.value is None
            and check.relation == "eq"
        )
    if isinstance(check, Compare):
        other = fields.get(check.other_field) if check.other_field is not None else check.value
        if check.relation == "eq":
            return scalar_equal(value, other)
        if check.relation == "ne":
            return not (scalar_equal(value, other))
        if other is None:
            return False
        if check.relation == "lt":
            return value < other
        if check.relation == "le":
            return value <= other
        if check.relation == "gt":
            return value > other
        return value >= other
    if isinstance(check, Membership):
        return any(scalar_equal(value, item) for item in check.values)
    if isinstance(check, Bounds):
        return (
            isinstance(value, (int, float))
            and not isinstance(value, bool)
            and math.isfinite(value)
            and (check.minimum is None or value >= check.minimum)
            and (check.maximum is None or value <= check.maximum)
        )
    if isinstance(check, Length):
        return (
            isinstance(value, (str, list))
            and len(value) >= check.minimum
            and (check.maximum is None or len(value) <= check.maximum)
        )
    if isinstance(check, Pattern):
        return isinstance(value, str) and re.search(check.pattern, value) is not None
    other = fields.get(check.other_field)
    if isinstance(check, SameLength):
        return (
            isinstance(value, (str, list))
            and type(value) is type(other)
            and len(value) == len(other)
        )
    if isinstance(check, Combination):
        return any(scalar_equal(value, a) and scalar_equal(other, b) for a, b in check.pairs)
    if isinstance(check, AddressFamily):
        try:
            version = ipaddress.ip_address(value).version
        except ValueError:
            return False
        return other in ("true", "false") and (version == 6) == (other == "true")
    raise TypeError(f"Unsupported predicate {type(check).__name__}")


def rule_fields(rule: RecordRule) -> tuple[str, ...]:
    """Return the compiled literal references for an immutable predicate plan."""
    return rule._references


def evaluate_rule(
    rule: RecordRule,
    fields: dict[str, Any],
    format_name: str,
    variant: str | None,
    invalid_fields: set[str] | None = None,
) -> Finding:
    """Evaluate a rule, preserving non-applicability and execution failures."""
    references = rule_fields(rule)
    outcome: Literal["pass", "fail", "not_applicable", "evaluation_error"]
    try:
        if invalid_fields and invalid_fields.intersection(references):
            outcome = "not_applicable"
        elif not all(predicate_passes(check, fields) for check in rule.when):
            outcome = "not_applicable"
        elif rule.exclude and all(predicate_passes(check, fields) for check in rule.exclude):
            outcome = "not_applicable"
        else:
            outcome = "pass" if all(predicate_passes(c, fields) for c in rule.checks) else "fail"
    except (TypeError, ValueError, OverflowError):
        outcome = "evaluation_error"
    return Finding(
        rule_id=rule.id,
        format=format_name,
        variant=variant,
        fields=references,
        category="evaluation" if outcome == "evaluation_error" else "constraint",
        severity="error" if outcome == "evaluation_error" else rule.severity,
        outcome=outcome,
        message=rule.message,
    )
