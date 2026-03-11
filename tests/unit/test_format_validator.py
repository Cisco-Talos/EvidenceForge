"""Unit tests for format validator."""

from datetime import datetime

import pytest

from log_generator.formats.format_def import (
    FieldConstraint,
    FieldDefinition,
    FieldType,
    FormatDefinition,
    EventVariant,
    OutputTemplate,
)
from log_generator.formats.validator import (
    ValidationResult,
    validate_event,
    validate_field,
    validate_field_constraints,
    validate_field_type,
)


class TestValidationResult:
    """Tests for ValidationResult class."""

    def test_init_valid(self):
        """Test that new ValidationResult is valid."""
        result = ValidationResult()
        assert result.valid is True
        assert result.errors == []

    def test_add_error_sets_invalid(self):
        """Test that adding error sets valid to False."""
        result = ValidationResult()
        result.add_error("field1", "Error message")
        assert result.valid is False
        assert len(result.errors) == 1
        assert "field1: Error message" in result.errors

    def test_multiple_errors(self):
        """Test accumulating multiple errors."""
        result = ValidationResult()
        result.add_error("field1", "Error 1")
        result.add_error("field2", "Error 2")
        assert result.valid is False
        assert len(result.errors) == 2

    def test_merge_valid_results(self):
        """Test merging two valid results."""
        result1 = ValidationResult()
        result2 = ValidationResult()
        result1.merge(result2)
        assert result1.valid is True
        assert result1.errors == []

    def test_merge_invalid_result(self):
        """Test merging invalid result."""
        result1 = ValidationResult()
        result2 = ValidationResult()
        result2.add_error("field", "Error")

        result1.merge(result2)
        assert result1.valid is False
        assert len(result1.errors) == 1


class TestValidateFieldType:
    """Tests for validate_field_type function."""

    def test_string_valid(self):
        """Test valid string type."""
        result = validate_field_type("field", "test", FieldType.STRING)
        assert result.valid is True

    def test_string_invalid(self):
        """Test invalid string type."""
        result = validate_field_type("field", 123, FieldType.STRING)
        assert result.valid is False
        assert "Expected string" in result.errors[0]

    def test_integer_valid(self):
        """Test valid integer type."""
        result = validate_field_type("field", 42, FieldType.INTEGER)
        assert result.valid is True

    def test_integer_invalid_type(self):
        """Test invalid integer type."""
        result = validate_field_type("field", "42", FieldType.INTEGER)
        assert result.valid is False
        assert "Expected integer" in result.errors[0]

    def test_integer_rejects_boolean(self):
        """Test that boolean is rejected as integer."""
        result = validate_field_type("field", True, FieldType.INTEGER)
        assert result.valid is False

    def test_boolean_valid(self):
        """Test valid boolean type."""
        result = validate_field_type("field", True, FieldType.BOOLEAN)
        assert result.valid is True

    def test_boolean_invalid(self):
        """Test invalid boolean type."""
        result = validate_field_type("field", 1, FieldType.BOOLEAN)
        assert result.valid is False

    def test_timestamp_datetime_valid(self):
        """Test valid datetime object for timestamp."""
        result = validate_field_type("field", datetime(2024, 1, 15), FieldType.TIMESTAMP)
        assert result.valid is True

    def test_timestamp_iso8601_valid(self):
        """Test valid ISO 8601 string for timestamp."""
        result = validate_field_type("field", "2024-01-15T10:00:00Z", FieldType.TIMESTAMP)
        assert result.valid is True

    def test_timestamp_iso8601_with_timezone(self):
        """Test ISO 8601 string with timezone."""
        result = validate_field_type(
            "field", "2024-01-15T10:00:00+05:00", FieldType.TIMESTAMP
        )
        assert result.valid is True

    def test_timestamp_invalid_format(self):
        """Test invalid timestamp format."""
        result = validate_field_type("field", "not a timestamp", FieldType.TIMESTAMP)
        assert result.valid is False
        assert "Invalid ISO 8601" in result.errors[0]

    def test_ip_address_ipv4_valid(self):
        """Test valid IPv4 address."""
        result = validate_field_type("field", "192.168.1.100", FieldType.IP_ADDRESS)
        assert result.valid is True

    def test_ip_address_ipv6_valid(self):
        """Test valid IPv6 address."""
        result = validate_field_type("field", "2001:db8::1", FieldType.IP_ADDRESS)
        assert result.valid is True

    def test_ip_address_invalid(self):
        """Test invalid IP address."""
        result = validate_field_type("field", "999.999.999.999", FieldType.IP_ADDRESS)
        assert result.valid is False
        assert "Invalid IP address" in result.errors[0]

    def test_ip_address_not_string(self):
        """Test IP address must be string."""
        result = validate_field_type("field", 192168, FieldType.IP_ADDRESS)
        assert result.valid is False

    def test_port_valid(self):
        """Test valid port number."""
        result = validate_field_type("field", 8080, FieldType.PORT)
        assert result.valid is True

    def test_port_min_boundary(self):
        """Test port minimum boundary."""
        result = validate_field_type("field", 1, FieldType.PORT)
        assert result.valid is True

    def test_port_max_boundary(self):
        """Test port maximum boundary."""
        result = validate_field_type("field", 65535, FieldType.PORT)
        assert result.valid is True

    def test_port_below_min(self):
        """Test port below minimum."""
        result = validate_field_type("field", 0, FieldType.PORT)
        assert result.valid is False
        assert "1-65535" in result.errors[0]

    def test_port_above_max(self):
        """Test port above maximum."""
        result = validate_field_type("field", 65536, FieldType.PORT)
        assert result.valid is False

    def test_port_not_integer(self):
        """Test port must be integer."""
        result = validate_field_type("field", "8080", FieldType.PORT)
        assert result.valid is False

    def test_hex_string_valid(self):
        """Test valid hex string."""
        result = validate_field_type("field", "0x3e7", FieldType.HEX_STRING)
        assert result.valid is True

    def test_hex_string_uppercase_valid(self):
        """Test hex string with uppercase letters."""
        result = validate_field_type("field", "0xABCD1234", FieldType.HEX_STRING)
        assert result.valid is True

    def test_hex_string_no_prefix(self):
        """Test hex string without 0x prefix is invalid."""
        result = validate_field_type("field", "3e7", FieldType.HEX_STRING)
        assert result.valid is False
        assert "Invalid hex string" in result.errors[0]

    def test_hex_string_invalid_chars(self):
        """Test hex string with invalid characters."""
        result = validate_field_type("field", "0xGHIJ", FieldType.HEX_STRING)
        assert result.valid is False

    def test_sid_valid(self):
        """Test valid Windows SID."""
        result = validate_field_type("field", "S-1-5-18", FieldType.SID)
        assert result.valid is True

    def test_sid_complex_valid(self):
        """Test complex valid SID."""
        result = validate_field_type(
            "field", "S-1-5-21-1234567890-1234567890-1234567890-1001", FieldType.SID
        )
        assert result.valid is True

    def test_sid_invalid_format(self):
        """Test invalid SID format."""
        result = validate_field_type("field", "S-1", FieldType.SID)
        assert result.valid is False
        assert "Invalid SID format" in result.errors[0]

    def test_sid_no_prefix(self):
        """Test SID without S- prefix."""
        result = validate_field_type("field", "1-5-18", FieldType.SID)
        assert result.valid is False

    def test_enum_type(self):
        """Test enum type (validated by constraints)."""
        result = validate_field_type("field", "tcp", FieldType.ENUM)
        assert result.valid is True  # Enum validation in constraints


class TestValidateFieldConstraints:
    """Tests for validate_field_constraints function."""

    def test_pattern_match(self):
        """Test pattern constraint matches."""
        constraints = FieldConstraint(pattern=r"^\d{4}$")
        result = validate_field_constraints("field", "1234", constraints)
        assert result.valid is True

    def test_pattern_no_match(self):
        """Test pattern constraint doesn't match."""
        constraints = FieldConstraint(pattern=r"^\d{4}$")
        result = validate_field_constraints("field", "abc", constraints)
        assert result.valid is False
        assert "does not match pattern" in result.errors[0]

    def test_min_value_valid(self):
        """Test min_value constraint passes."""
        constraints = FieldConstraint(min_value=10)
        result = validate_field_constraints("field", 15, constraints)
        assert result.valid is True

    def test_min_value_invalid(self):
        """Test min_value constraint fails."""
        constraints = FieldConstraint(min_value=10)
        result = validate_field_constraints("field", 5, constraints)
        assert result.valid is False
        assert "less than minimum" in result.errors[0]

    def test_max_value_valid(self):
        """Test max_value constraint passes."""
        constraints = FieldConstraint(max_value=100)
        result = validate_field_constraints("field", 50, constraints)
        assert result.valid is True

    def test_max_value_invalid(self):
        """Test max_value constraint fails."""
        constraints = FieldConstraint(max_value=100)
        result = validate_field_constraints("field", 150, constraints)
        assert result.valid is False
        assert "greater than maximum" in result.errors[0]

    def test_min_length_valid(self):
        """Test min_length constraint passes."""
        constraints = FieldConstraint(min_length=3)
        result = validate_field_constraints("field", "abcd", constraints)
        assert result.valid is True

    def test_min_length_invalid(self):
        """Test min_length constraint fails."""
        constraints = FieldConstraint(min_length=5)
        result = validate_field_constraints("field", "ab", constraints)
        assert result.valid is False
        assert "less than minimum" in result.errors[0]

    def test_max_length_valid(self):
        """Test max_length constraint passes."""
        constraints = FieldConstraint(max_length=10)
        result = validate_field_constraints("field", "short", constraints)
        assert result.valid is True

    def test_max_length_invalid(self):
        """Test max_length constraint fails."""
        constraints = FieldConstraint(max_length=5)
        result = validate_field_constraints("field", "toolongstring", constraints)
        assert result.valid is False
        assert "greater than maximum" in result.errors[0]

    def test_allowed_values_valid(self):
        """Test allowed_values constraint passes."""
        constraints = FieldConstraint(allowed_values=["tcp", "udp", "icmp"])
        result = validate_field_constraints("field", "tcp", constraints)
        assert result.valid is True

    def test_allowed_values_invalid(self):
        """Test allowed_values constraint fails."""
        constraints = FieldConstraint(allowed_values=["tcp", "udp"])
        result = validate_field_constraints("field", "http", constraints)
        assert result.valid is False
        assert "must be one of" in result.errors[0]

    def test_json_logic_simple_valid(self):
        """Test simple JSON Logic rule passes."""
        constraints = FieldConstraint(json_logic={"==": [{"var": "value"}, 42]})
        result = validate_field_constraints("field", 42, constraints)
        assert result.valid is True

    def test_json_logic_simple_invalid(self):
        """Test simple JSON Logic rule fails."""
        constraints = FieldConstraint(json_logic={"==": [{"var": "value"}, 42]})
        result = validate_field_constraints("field", 99, constraints)
        assert result.valid is False
        assert "Failed JSON Logic" in result.errors[0]

    def test_multiple_constraints(self):
        """Test multiple constraints together."""
        constraints = FieldConstraint(min_value=1, max_value=100, allowed_values=[10, 20, 30])
        result = validate_field_constraints("field", 20, constraints)
        assert result.valid is True

    def test_multiple_constraints_fail(self):
        """Test multiple constraints with failure."""
        constraints = FieldConstraint(min_value=1, max_value=100)
        result = validate_field_constraints("field", 150, constraints)
        assert result.valid is False


class TestValidateField:
    """Tests for validate_field function."""

    def test_valid_field(self):
        """Test validating a valid field."""
        field_def = FieldDefinition(name="test_field", type=FieldType.STRING)
        result = validate_field(field_def, "test value")
        assert result.valid is True

    def test_invalid_type(self):
        """Test validating field with wrong type."""
        field_def = FieldDefinition(name="test_field", type=FieldType.INTEGER)
        result = validate_field(field_def, "not an integer")
        assert result.valid is False

    def test_with_constraints(self):
        """Test validating field with constraints."""
        field_def = FieldDefinition(
            name="test_field",
            type=FieldType.STRING,
            constraints=FieldConstraint(min_length=5, max_length=10),
        )
        result = validate_field(field_def, "valid")
        assert result.valid is True

    def test_constraint_violation(self):
        """Test validating field with constraint violation."""
        field_def = FieldDefinition(
            name="test_field",
            type=FieldType.STRING,
            constraints=FieldConstraint(pattern=r"^\d+$"),
        )
        result = validate_field(field_def, "abc")
        assert result.valid is False

    def test_both_type_and_constraint_errors(self):
        """Test field with both type and constraint errors."""
        field_def = FieldDefinition(
            name="test_field",
            type=FieldType.INTEGER,
            constraints=FieldConstraint(min_value=10),
        )
        result = validate_field(field_def, "not an int")
        assert result.valid is False
        # Should have type error
        assert len(result.errors) >= 1


class TestValidateEvent:
    """Tests for validate_event function."""

    def test_minimal_valid_event(self):
        """Test validating minimal valid event."""
        format_def = FormatDefinition(
            name="test",
            description="Test",
            category="host",
            fields=[FieldDefinition(name="field1", type=FieldType.STRING)],
            output=OutputTemplate(format="text", template="t", file_extension=".txt"),
        )
        event_data = {"field1": "value1"}
        result = validate_event(format_def, event_data)
        assert result.valid is True

    def test_missing_required_field(self):
        """Test event missing required field."""
        format_def = FormatDefinition(
            name="test",
            description="Test",
            category="host",
            fields=[
                FieldDefinition(name="field1", type=FieldType.STRING, required=True)
            ],
            output=OutputTemplate(format="text", template="t", file_extension=".txt"),
        )
        event_data = {}
        result = validate_event(format_def, event_data)
        assert result.valid is False
        assert "Required field missing" in result.errors[0]

    def test_optional_field_missing(self):
        """Test event with optional field missing."""
        format_def = FormatDefinition(
            name="test",
            description="Test",
            category="host",
            fields=[
                FieldDefinition(name="field1", type=FieldType.STRING, required=False)
            ],
            output=OutputTemplate(format="text", template="t", file_extension=".txt"),
        )
        event_data = {}
        result = validate_event(format_def, event_data)
        assert result.valid is True

    def test_unknown_field_warning(self):
        """Test event with unknown field generates warning."""
        format_def = FormatDefinition(
            name="test",
            description="Test",
            category="host",
            fields=[FieldDefinition(name="field1", type=FieldType.STRING)],
            output=OutputTemplate(format="text", template="t", file_extension=".txt"),
        )
        event_data = {"field1": "value1", "unknown_field": "value2"}
        result = validate_event(format_def, event_data)
        # Unknown fields don't fail validation, just warning
        assert result.valid is True

    def test_invalid_field_value(self):
        """Test event with invalid field value."""
        format_def = FormatDefinition(
            name="test",
            description="Test",
            category="host",
            fields=[FieldDefinition(name="field1", type=FieldType.INTEGER)],
            output=OutputTemplate(format="text", template="t", file_extension=".txt"),
        )
        event_data = {"field1": "not an integer"}
        result = validate_event(format_def, event_data)
        assert result.valid is False

    def test_with_variant(self):
        """Test validating event with variant."""
        format_def = FormatDefinition(
            name="test",
            description="Test",
            category="host",
            fields=[FieldDefinition(name="base_field", type=FieldType.STRING)],
            variants=[
                EventVariant(
                    name="variant1",
                    fields=[
                        FieldDefinition(name="variant_field", type=FieldType.INTEGER)
                    ],
                )
            ],
            output=OutputTemplate(format="text", template="t", file_extension=".txt"),
        )
        event_data = {"base_field": "value", "variant_field": 42}
        result = validate_event(format_def, event_data, variant_name="variant1")
        assert result.valid is True

    def test_variant_required_field(self):
        """Test variant required field validation."""
        format_def = FormatDefinition(
            name="test",
            description="Test",
            category="host",
            fields=[],
            variants=[
                EventVariant(
                    name="variant1",
                    fields=[
                        FieldDefinition(
                            name="variant_field", type=FieldType.STRING, required=True
                        )
                    ],
                )
            ],
            output=OutputTemplate(format="text", template="t", file_extension=".txt"),
        )
        event_data = {}
        result = validate_event(format_def, event_data, variant_name="variant1")
        assert result.valid is False
        assert "variant_field" in result.errors[0]

    def test_unknown_variant(self):
        """Test with unknown variant name."""
        format_def = FormatDefinition(
            name="test",
            description="Test",
            category="host",
            fields=[],
            variants=[EventVariant(name="variant1", fields=[])],
            output=OutputTemplate(format="text", template="t", file_extension=".txt"),
        )
        event_data = {}
        result = validate_event(format_def, event_data, variant_name="unknown")
        assert result.valid is False
        assert "Unknown variant" in result.errors[0]

    def test_cross_field_validator_pass(self):
        """Test cross-field validator passes."""
        format_def = FormatDefinition(
            name="test",
            description="Test",
            category="host",
            fields=[
                FieldDefinition(name="field1", type=FieldType.INTEGER),
                FieldDefinition(name="field2", type=FieldType.INTEGER),
            ],
            output=OutputTemplate(format="text", template="t", file_extension=".txt"),
            validators=[{"<": [{"var": "field1"}, {"var": "field2"}]}],
        )
        event_data = {"field1": 10, "field2": 20}
        result = validate_event(format_def, event_data)
        assert result.valid is True

    def test_cross_field_validator_fail(self):
        """Test cross-field validator fails."""
        format_def = FormatDefinition(
            name="test",
            description="Test",
            category="host",
            fields=[
                FieldDefinition(name="field1", type=FieldType.INTEGER),
                FieldDefinition(name="field2", type=FieldType.INTEGER),
            ],
            output=OutputTemplate(format="text", template="t", file_extension=".txt"),
            validators=[{"<": [{"var": "field1"}, {"var": "field2"}]}],
        )
        event_data = {"field1": 30, "field2": 20}
        result = validate_event(format_def, event_data)
        assert result.valid is False
        assert "_cross_field" in result.errors[0]

    def test_multiple_validation_errors(self):
        """Test accumulating multiple validation errors."""
        format_def = FormatDefinition(
            name="test",
            description="Test",
            category="host",
            fields=[
                FieldDefinition(name="field1", type=FieldType.INTEGER, required=True),
                FieldDefinition(name="field2", type=FieldType.STRING, required=True),
            ],
            output=OutputTemplate(format="text", template="t", file_extension=".txt"),
        )
        event_data = {}
        result = validate_event(format_def, event_data)
        assert result.valid is False
        assert len(result.errors) == 2
