"""Format validation for EvidenceForge.

This module provides validation functions for log fields based on format definitions.
Uses json-logic-py for complex validation rules.
"""

import ipaddress
import logging
import re
from datetime import datetime
from typing import Any

from json_logic import jsonLogic

from .format_def import FieldConstraint, FieldDefinition, FieldType, FormatDefinition

logger = logging.getLogger(__name__)


class ValidationResult:
    """Result of field validation.

    Attributes:
        valid: Whether validation passed
        errors: List of error messages (field path + message)
    """

    def __init__(self):
        self.valid = True
        self.errors: list[str] = []

    def add_error(self, field_path: str, message: str) -> None:
        """Add a validation error."""
        self.valid = False
        self.errors.append(f"{field_path}: {message}")

    def merge(self, other: "ValidationResult") -> None:
        """Merge another validation result into this one."""
        if not other.valid:
            self.valid = False
            self.errors.extend(other.errors)


def validate_field_type(
    field_name: str, field_value: Any, field_type: FieldType
) -> ValidationResult:
    """Validate a field value matches its type.

    Args:
        field_name: Field name (for error messages)
        field_value: Value to validate
        field_type: Expected field type

    Returns:
        ValidationResult with errors if type mismatch
    """
    result = ValidationResult()

    if field_type == FieldType.STRING:
        if not isinstance(field_value, str):
            result.add_error(
                field_name, f"Expected string, got {type(field_value).__name__}"
            )

    elif field_type == FieldType.INTEGER:
        if not isinstance(field_value, int) or isinstance(field_value, bool):
            result.add_error(
                field_name, f"Expected integer, got {type(field_value).__name__}"
            )

    elif field_type == FieldType.BOOLEAN:
        if not isinstance(field_value, bool):
            result.add_error(
                field_name, f"Expected boolean, got {type(field_value).__name__}"
            )

    elif field_type == FieldType.TIMESTAMP:
        # Accept datetime objects or ISO 8601 strings
        if isinstance(field_value, str):
            try:
                datetime.fromisoformat(field_value.replace("Z", "+00:00"))
            except ValueError:
                result.add_error(field_name, "Invalid ISO 8601 timestamp")
        elif not isinstance(field_value, datetime):
            result.add_error(
                field_name, f"Expected timestamp, got {type(field_value).__name__}"
            )

    elif field_type == FieldType.IP_ADDRESS:
        if not isinstance(field_value, str):
            result.add_error(field_name, "IP address must be string")
        else:
            try:
                ipaddress.ip_address(field_value)
            except ValueError:
                result.add_error(field_name, f"Invalid IP address: {field_value}")

    elif field_type == FieldType.PORT:
        if not isinstance(field_value, int) or isinstance(field_value, bool):
            result.add_error(field_name, "Port must be integer")
        elif not (1 <= field_value <= 65535):
            result.add_error(field_name, f"Port must be 1-65535, got {field_value}")

    elif field_type == FieldType.HEX_STRING:
        if not isinstance(field_value, str):
            result.add_error(field_name, "Hex string must be string")
        elif not re.match(r"^0x[0-9a-fA-F]+$", field_value):
            result.add_error(field_name, f"Invalid hex string format: {field_value}")

    elif field_type == FieldType.SID:
        if not isinstance(field_value, str):
            result.add_error(field_name, "SID must be string")
        elif not re.match(r"^S-\d+-\d+(-\d+)*$", field_value):
            result.add_error(field_name, f"Invalid SID format: {field_value}")

    elif field_type == FieldType.ENUM:
        # Enum validation requires constraints.allowed_values
        # (handled in validate_field_constraints)
        pass

    return result


def validate_field_constraints(
    field_name: str, field_value: Any, constraints: FieldConstraint
) -> ValidationResult:
    """Validate field value against constraints.

    Args:
        field_name: Field name (for error messages)
        field_value: Value to validate
        constraints: Field constraints

    Returns:
        ValidationResult with errors if constraints violated
    """
    result = ValidationResult()

    # Pattern matching (for strings)
    if constraints.pattern and isinstance(field_value, str):
        if not re.match(constraints.pattern, field_value):
            result.add_error(
                field_name,
                f"Value does not match pattern {constraints.pattern}: {field_value}",
            )

    # Min/max value (for integers)
    if isinstance(field_value, int) and not isinstance(field_value, bool):
        if constraints.min_value is not None and field_value < constraints.min_value:
            result.add_error(
                field_name,
                f"Value {field_value} less than minimum {constraints.min_value}",
            )
        if constraints.max_value is not None and field_value > constraints.max_value:
            result.add_error(
                field_name,
                f"Value {field_value} greater than maximum {constraints.max_value}",
            )

    # Min/max length (for strings)
    if isinstance(field_value, str):
        if (
            constraints.min_length is not None
            and len(field_value) < constraints.min_length
        ):
            result.add_error(
                field_name,
                f"Length {len(field_value)} less than minimum {constraints.min_length}",
            )
        if (
            constraints.max_length is not None
            and len(field_value) > constraints.max_length
        ):
            result.add_error(
                field_name,
                f"Length {len(field_value)} greater than maximum {constraints.max_length}",
            )

    # Allowed values (for enums)
    if constraints.allowed_values:
        if field_value not in constraints.allowed_values:
            result.add_error(
                field_name,
                f"Value must be one of {constraints.allowed_values}, got {field_value}",
            )

    # JSON Logic validation
    if constraints.json_logic:
        try:
            # JSON Logic rule has access to the field value as {"value": ...}
            logic_result = jsonLogic(constraints.json_logic, {"value": field_value})
            if not logic_result:
                result.add_error(
                    field_name, f"Failed JSON Logic validation: {constraints.json_logic}"
                )
        except Exception as e:
            result.add_error(field_name, f"JSON Logic error: {e}")

    return result


def validate_field(field_def: FieldDefinition, field_value: Any) -> ValidationResult:
    """Validate a field value against its definition.

    Args:
        field_def: Field definition
        field_value: Value to validate

    Returns:
        ValidationResult with any validation errors
    """
    result = ValidationResult()

    # Type validation
    type_result = validate_field_type(field_def.name, field_value, field_def.type)
    result.merge(type_result)

    # Constraint validation
    if field_def.constraints:
        constraint_result = validate_field_constraints(
            field_def.name, field_value, field_def.constraints
        )
        result.merge(constraint_result)

    return result


def validate_event(
    format_def: FormatDefinition,
    event_data: dict[str, Any],
    variant_name: str | None = None,
) -> ValidationResult:
    """Validate an event against a format definition.

    Args:
        format_def: Format definition
        event_data: Event data dict (field name -> value)
        variant_name: Optional variant name (for formats with variants)

    Returns:
        ValidationResult with all validation errors
    """
    result = ValidationResult()

    # Build combined field list (base + variant)
    fields = list(format_def.fields)
    if variant_name and format_def.variants:
        variant = next((v for v in format_def.variants if v.name == variant_name), None)
        if variant:
            fields.extend(variant.fields)
        else:
            result.add_error("_variant", f"Unknown variant: {variant_name}")
            return result

    # Check required fields
    for field_def in fields:
        if field_def.required and field_def.name not in event_data:
            result.add_error(field_def.name, "Required field missing")

    # Validate present fields
    for field_name, field_value in event_data.items():
        # Find field definition
        field_def = next((f for f in fields if f.name == field_name), None)
        if not field_def:
            # Unknown field (warning, not error)
            logger.warning(f"Unknown field in {format_def.name}: {field_name}")
            continue

        # Validate field
        field_result = validate_field(field_def, field_value)
        result.merge(field_result)

    # Cross-field validators (JSON Logic)
    if format_def.validators:
        for i, validator in enumerate(format_def.validators):
            try:
                logic_result = jsonLogic(validator, event_data)
                if not logic_result:
                    result.add_error(
                        "_cross_field", f"Failed cross-field validation #{i}: {validator}"
                    )
            except Exception as e:
                result.add_error("_cross_field", f"Cross-field validator error: {e}")

    return result
