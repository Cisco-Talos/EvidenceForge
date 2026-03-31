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

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator


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


class FieldConstraint(BaseModel):
    """Constraints for field validation.

    Attributes:
        pattern: Regex pattern (for string types)
        min_value: Minimum value (for integer/port types)
        max_value: Maximum value (for integer/port types)
        min_length: Minimum string length
        max_length: Maximum string length
        allowed_values: List of allowed values (for enum type)
        json_logic: JSON Logic rule for complex validation
    """

    pattern: str | None = None
    min_value: int | None = None
    max_value: int | None = None
    min_length: int | None = None
    max_length: int | None = None
    allowed_values: list[str | int] | None = None
    json_logic: dict[str, Any] | None = Field(None, description="JSON Logic rule for validation")

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
        validators: Optional list of cross-field JSON Logic validators
    """

    name: str = Field(..., pattern="^[a-z0-9_]+$")
    version: str = Field(default="1.0")
    description: str
    category: str = Field(..., pattern="^(host|network|application|cloud)$")
    fields: list[FieldDefinition]
    variants: list[EventVariant] | None = Field(default_factory=list)
    output: OutputTemplate
    validators: list[dict[str, Any]] | None = Field(
        None, description="Cross-field JSON Logic validators"
    )

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
