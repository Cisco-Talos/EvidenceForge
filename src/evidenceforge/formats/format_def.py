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

"""Format definition models for EvidenceForge.

This module defines Pydantic models for log format definitions loaded from YAML.
Format definitions describe field schemas, validation rules, and output templates.
"""

import math
import re
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, PrivateAttr, field_validator, model_validator

from .rules import (
    AddressFamily,
    Bounds,
    Combination,
    Compare,
    Length,
    Membership,
    Pattern,
    RecordRule,
    SameLength,
    predicate_fields,
)


class FieldType(StrEnum):
    """Supported field types for log formats."""

    STRING = "string"
    INTEGER = "integer"
    FLOAT = "float"  # Floating point number
    BOOLEAN = "boolean"
    TIMESTAMP = "timestamp"  # ISO 8601 datetime
    IP_ADDRESS = "ip_address"  # IPv4 or IPv6
    PORT = "port"  # 1-65535
    HEX_STRING = "hex_string"  # "0xABCD1234"
    SID = "sid"  # Windows SID
    ENUM = "enum"  # One of allowed_values
    LIST = "list"  # JSON array (e.g., Zeek answers, TTLs)


def _literal_compatible(value: Any, field_type: FieldType) -> bool:
    """Check predicate literal types without coercing developer-authored operands."""
    if value is None:
        return True
    if field_type in {FieldType.INTEGER, FieldType.FLOAT, FieldType.PORT, FieldType.TIMESTAMP}:
        return (
            isinstance(value, (int, float)) and not isinstance(value, bool) and math.isfinite(value)
        )
    if field_type == FieldType.BOOLEAN:
        return isinstance(value, bool)
    if field_type in {
        FieldType.STRING,
        FieldType.IP_ADDRESS,
        FieldType.HEX_STRING,
        FieldType.SID,
        FieldType.ENUM,
    }:
        return isinstance(value, str)
    return False


class FieldConstraint(BaseModel):
    """Constraints for field validation.

    Attributes:
        pattern: Regex pattern (for string types)
        min_value: Minimum value (for integer/port types)
        max_value: Maximum value (for integer/port types)
        min_length: Minimum string length
        max_length: Maximum string length
        allowed_values: List of allowed values (for enum type)
    """

    pattern: str | None = None
    min_value: float | None = None
    max_value: float | None = None
    min_length: int | None = None
    max_length: int | None = None
    allowed_values: list[str | int] | None = None

    @model_validator(mode="after")
    def validate_constraints(self) -> "FieldConstraint":
        """Reject malformed scalar constraints before processing records."""
        if self.pattern is not None:
            try:
                re.compile(self.pattern)
            except re.error as exc:
                raise ValueError(f"Invalid pattern: {exc}") from exc
        for low, high in ((self.min_value, self.max_value), (self.min_length, self.max_length)):
            if any(v is not None and not math.isfinite(v) for v in (low, high)):
                raise ValueError("Constraint bounds must be finite")
            if low is not None and high is not None and low > high:
                raise ValueError("Minimum constraint must not exceed maximum")
        if any(v is not None and v < 0 for v in (self.min_length, self.max_length)):
            raise ValueError("Length constraints must be nonnegative")
        return self

    model_config = ConfigDict(extra="forbid")


class FieldDefinition(BaseModel):
    """Definition of a single field in a log format.

    Attributes:
        name: Field name (e.g., "EventID", "TargetUserName")
        type: Field type from FieldType enum
        required: Whether field must be present
        description: Human-readable field description
        constraints: Optional validation constraints
        default: Default value if not provided
    """

    name: str
    type: FieldType
    required: bool = True
    description: str = ""
    constraints: FieldConstraint | None = None
    default: Any = None
    item_type: FieldType | None = None
    nullable: bool = False

    @field_validator("name")
    @classmethod
    def validate_name(cls, v: str) -> str:
        """Validate field name is alphanumeric with underscores/dots."""
        if not v.replace("_", "").replace(".", "").replace("-", "").isalnum():
            raise ValueError(f"Field name must be alphanumeric with _/./- : {v}")
        return v

    model_config = ConfigDict(extra="forbid")


class EventVariant(BaseModel):
    """Variant of a log format (e.g., Windows EventID 4624 vs 4634).

    Some formats have multiple event types with different field sets.
    For example, Windows Event Log has EventID 4624 (logon), 4634 (logoff), etc.

    Attributes:
        name: Variant name (e.g., "logon", "logoff", "process_creation")
        event_id: Optional event type identifier (e.g., "4624" for Windows)
        description: Human-readable variant description
        fields: List of fields specific to this variant (extends base fields)
    """

    name: str
    event_id: str | None = None
    event_ids: list[int] = Field(default_factory=list)
    description: str = ""
    fields: list[FieldDefinition] = Field(default_factory=list)

    model_config = ConfigDict(extra="forbid")


class OutputTemplate(BaseModel):
    """Output rendering configuration.

    Attributes:
        format: Output format type (xml|json|tsv|csv|text)
        template: Jinja2 template string for rendering
        file_extension: File extension for output (e.g., ".xml", ".log")
        header_template: Optional header template (for TSV/CSV formats)
        footer_template: Optional footer template (for XML root element closing)
        encoding: Output encoding (default: utf-8)
    """

    format: str = Field(..., pattern="^(xml|json|tsv|csv|text)$")
    template: str = Field(..., description="Jinja2 template for rendering")
    file_extension: str = Field(..., pattern=r"^\.[a-z0-9]+$")
    header_template: str | None = Field(None, description="Optional header template")
    footer_template: str | None = Field(None, description="Optional footer template")
    encoding: str = Field(default="utf-8")

    model_config = ConfigDict(extra="forbid")


class FormatDefinition(BaseModel):
    """Complete log format definition.

    Attributes:
        name: Format name (e.g., "windows_event", "zeek")
        version: Format definition version
        description: Human-readable format description
        category: Format category (host|network|application|cloud)
        fields: List of base fields (common to all variants)
        variants: Optional list of event variants
        output: Output template configuration
        validators: Optional list of typed record validators
    """

    name: str = Field(..., pattern="^[a-z0-9_]+$")
    version: str = Field(default="1.0")
    description: str
    category: str = Field(..., pattern="^(host|network|application|cloud)$")
    fields: list[FieldDefinition]
    variants: list[EventVariant] | None = Field(default_factory=list)
    output: OutputTemplate
    validators: list[RecordRule] | None = Field(None, description="Typed record validators")

    _field_plans: dict[str | None, dict[str, FieldDefinition]] = PrivateAttr(default_factory=dict)

    def validation_fields(self, variant: str | None) -> dict[str, FieldDefinition] | None:
        """Return the cached literal-key field plan for this definition and variant."""
        return self._field_plans.get(variant)

    @model_validator(mode="after")
    def validate_contract(self) -> "FormatDefinition":
        """Compile references and variant identities against declared fields."""
        fields = {f.name: f for f in self.fields}
        variant_names: set[str] = set()
        event_ids: set[int] = set()
        for variant in self.variants or []:
            if variant.name in variant_names:
                raise ValueError(f"Duplicate variant {variant.name}")
            variant_names.add(variant.name)
            names = [f.name for f in variant.fields]
            if len(names) != len(set(names)) or set(names).intersection(
                f.name for f in self.fields
            ):
                raise ValueError(f"Duplicate fields in variant {variant.name}")
            for event_id in variant.event_ids or (
                [int(variant.event_id)] if variant.event_id else []
            ):
                if event_id in event_ids:
                    raise ValueError(f"Duplicate variant event ID {event_id}")
                event_ids.add(event_id)
            fields.update({f.name: f for f in variant.fields})
        self._field_plans = {None: {field.name: field for field in self.fields}}
        for variant in self.variants or []:
            self._field_plans[variant.name] = {
                **self._field_plans[None],
                **{field.name: field for field in variant.fields},
            }
        ids: set[str] = set()
        for rule in self.validators or []:
            if rule.id in ids:
                raise ValueError(f"Duplicate rule ID {rule.id}")
            ids.add(rule.id)
            for check in (*rule.when, *rule.exclude, *rule.checks):
                for name in predicate_fields(check):
                    if name not in fields:
                        raise ValueError(f"Rule {rule.id} references unknown field {name}")
                kind = fields[check.field].type
                literals = []
                if isinstance(check, Compare) and check.other_field is None:
                    literals.append((check.value, kind))
                if isinstance(check, Membership):
                    literals.extend((value, kind) for value in check.values)
                if isinstance(check, Combination):
                    for left, right in check.pairs:
                        literals.extend(((left, kind), (right, fields[check.other_field].type)))
                if any(
                    not _literal_compatible(value, field_type) for value, field_type in literals
                ):
                    raise ValueError(f"Rule {rule.id} has incompatible literal operand")
                if isinstance(check, AddressFamily) and (
                    kind not in {FieldType.IP_ADDRESS, FieldType.STRING}
                    or fields[check.other_field].type != FieldType.STRING
                ):
                    raise ValueError(
                        f"Rule {rule.id} address_family requires address and string flag"
                    )
                if isinstance(check, Bounds) and kind not in {
                    FieldType.INTEGER,
                    FieldType.FLOAT,
                    FieldType.PORT,
                }:
                    raise ValueError(f"Rule {rule.id} requires numeric field {check.field}")
                if isinstance(check, (Length, SameLength)) and kind not in {
                    FieldType.STRING,
                    FieldType.LIST,
                }:
                    raise ValueError(f"Rule {rule.id} requires string/list field {check.field}")
                if isinstance(check, Pattern) and kind != FieldType.STRING:
                    raise ValueError(f"Rule {rule.id} requires string field {check.field}")
                if isinstance(check, SameLength) and fields[check.other_field].type != kind:
                    raise ValueError(f"Rule {rule.id} has incompatible collection fields")
                if isinstance(check, Compare) and check.other_field:
                    other_kind = fields[check.other_field].type
                    numeric_kinds = {
                        FieldType.INTEGER,
                        FieldType.FLOAT,
                        FieldType.PORT,
                        FieldType.TIMESTAMP,
                    }
                    text_kinds = {
                        FieldType.STRING,
                        FieldType.ENUM,
                        FieldType.IP_ADDRESS,
                        FieldType.HEX_STRING,
                        FieldType.SID,
                    }
                    if kind != other_kind and not (
                        {kind, other_kind} <= numeric_kinds or {kind, other_kind} <= text_kinds
                    ):
                        raise ValueError(f"Rule {rule.id} has incompatible field operands")
                if isinstance(check, Compare) and check.relation not in {"eq", "ne"}:
                    numeric = {FieldType.INTEGER, FieldType.FLOAT, FieldType.PORT}
                    if kind not in numeric:
                        raise ValueError(f"Rule {rule.id} ordering requires numeric operands")
                    if check.other_field and fields[check.other_field].type not in numeric:
                        raise ValueError(f"Rule {rule.id} has incompatible ordering operands")
                    if not check.other_field and (
                        isinstance(check.value, bool) or not isinstance(check.value, (int, float))
                    ):
                        raise ValueError(f"Rule {rule.id} ordering requires numeric literal")
        return self

    @field_validator("validators", mode="before")
    @classmethod
    def reject_legacy_rules(cls, value: Any) -> Any:
        """Explain how to migrate the former internal expression syntax."""
        if isinstance(value, list) and any(
            isinstance(rule, dict) and "id" not in rule for rule in value
        ):
            raise ValueError(
                "Legacy JSON Logic validators are unsupported; use typed rules with id, message, and checks"
            )
        return value

    @field_validator("fields")
    @classmethod
    def validate_unique_field_names(cls, v: list[FieldDefinition]) -> list[FieldDefinition]:
        """Ensure field names are unique."""
        names = [f.name for f in v]
        if len(names) != len(set(names)):
            duplicates = [n for n in names if names.count(n) > 1]
            raise ValueError(f"Duplicate field names: {set(duplicates)}")
        return v

    model_config = ConfigDict(extra="forbid")
