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

"""Unit tests for format definition models."""

import pytest
from pydantic import ValidationError

from evidenceforge.formats.format_def import (
    EventVariant,
    FieldConstraint,
    FieldDefinition,
    FieldType,
    FormatDefinition,
    OutputTemplate,
)


class TestFieldType:
    """Tests for FieldType enum."""

    def test_all_field_types_defined(self):
        """Test that all expected field types are defined."""
        expected_types = {
            "string",
            "integer",
            "float",
            "boolean",
            "timestamp",
            "ip_address",
            "port",
            "hex_string",
            "sid",
            "enum",
            "list",
        }
        actual_types = {ft.value for ft in FieldType}
        assert actual_types == expected_types


class TestFieldConstraint:
    """Tests for FieldConstraint model."""

    def test_empty_constraint(self):
        """Test creating an empty constraint."""
        constraint = FieldConstraint()
        assert constraint.pattern is None
        assert constraint.min_value is None
        assert constraint.max_value is None
        assert constraint.allowed_values is None
        assert constraint.json_logic is None

    def test_pattern_constraint(self):
        """Test constraint with pattern."""
        constraint = FieldConstraint(pattern=r"^\d{4}$")
        assert constraint.pattern == r"^\d{4}$"

    def test_range_constraint(self):
        """Test constraint with min/max values."""
        constraint = FieldConstraint(min_value=1, max_value=100)
        assert constraint.min_value == 1
        assert constraint.max_value == 100

    def test_length_constraint(self):
        """Test constraint with min/max length."""
        constraint = FieldConstraint(min_length=5, max_length=20)
        assert constraint.min_length == 5
        assert constraint.max_length == 20

    def test_enum_constraint(self):
        """Test constraint with allowed values."""
        constraint = FieldConstraint(allowed_values=["tcp", "udp", "icmp"])
        assert constraint.allowed_values == ["tcp", "udp", "icmp"]

    def test_enum_constraint_with_integers(self):
        """Test constraint with integer allowed values."""
        constraint = FieldConstraint(allowed_values=[2, 3, 10])
        assert constraint.allowed_values == [2, 3, 10]

    def test_json_logic_constraint(self):
        """Test constraint with JSON Logic rule."""
        rule = {"==": [{"var": "LogonType"}, 3]}
        constraint = FieldConstraint(json_logic=rule)
        assert constraint.json_logic == rule

    def test_extra_fields_rejected(self):
        """Test that extra fields are rejected."""
        with pytest.raises(ValidationError):
            FieldConstraint(unknown_field="value")  # type: ignore


class TestFieldDefinition:
    """Tests for FieldDefinition model."""

    def test_minimal_field(self):
        """Test creating a minimal field definition."""
        field = FieldDefinition(name="test_field", type=FieldType.STRING)
        assert field.name == "test_field"
        assert field.type == FieldType.STRING
        assert field.required is True
        assert field.description == ""
        assert field.constraints is None
        assert field.default is None

    def test_full_field(self):
        """Test creating a complete field definition."""
        constraint = FieldConstraint(pattern=r"^\d+$")
        field = FieldDefinition(
            name="event_id",
            type=FieldType.INTEGER,
            required=True,
            description="Event identifier",
            constraints=constraint,
            default=0,
        )
        assert field.name == "event_id"
        assert field.type == FieldType.INTEGER
        assert field.required is True
        assert field.description == "Event identifier"
        assert field.constraints == constraint
        assert field.default == 0

    def test_optional_field(self):
        """Test creating an optional field."""
        field = FieldDefinition(
            name="optional_field", type=FieldType.STRING, required=False, default="-"
        )
        assert field.required is False
        assert field.default == "-"

    def test_field_name_with_underscore(self):
        """Test field name with underscore."""
        field = FieldDefinition(name="field_name", type=FieldType.STRING)
        assert field.name == "field_name"

    def test_field_name_with_dot(self):
        """Test field name with dot (for Zeek fields like id.orig_h)."""
        field = FieldDefinition(name="id.orig_h", type=FieldType.IP_ADDRESS)
        assert field.name == "id.orig_h"

    def test_field_name_with_hyphen(self):
        """Test field name with hyphen."""
        field = FieldDefinition(name="field-name", type=FieldType.STRING)
        assert field.name == "field-name"

    def test_invalid_field_name_with_space(self):
        """Test that field names with spaces are rejected."""
        with pytest.raises(ValidationError, match="alphanumeric"):
            FieldDefinition(name="field name", type=FieldType.STRING)

    def test_invalid_field_name_with_special_chars(self):
        """Test that field names with invalid special characters are rejected."""
        with pytest.raises(ValidationError, match="alphanumeric"):
            FieldDefinition(name="field@name", type=FieldType.STRING)

    def test_extra_fields_rejected(self):
        """Test that extra fields are rejected."""
        with pytest.raises(ValidationError):
            FieldDefinition(
                name="test",
                type=FieldType.STRING,
                unknown_field="value",  # type: ignore
            )


class TestEventVariant:
    """Tests for EventVariant model."""

    def test_minimal_variant(self):
        """Test creating a minimal event variant."""
        variant = EventVariant(name="logon")
        assert variant.name == "logon"
        assert variant.event_id is None
        assert variant.description == ""
        assert variant.fields == []

    def test_full_variant(self):
        """Test creating a complete event variant."""
        fields = [
            FieldDefinition(name="field1", type=FieldType.STRING),
            FieldDefinition(name="field2", type=FieldType.INTEGER),
        ]
        variant = EventVariant(
            name="logon",
            event_id="4624",
            description="Successful logon",
            fields=fields,
        )
        assert variant.name == "logon"
        assert variant.event_id == "4624"
        assert variant.description == "Successful logon"
        assert len(variant.fields) == 2

    def test_extra_fields_rejected(self):
        """Test that extra fields are rejected."""
        with pytest.raises(ValidationError):
            EventVariant(name="test", unknown_field="value")  # type: ignore


class TestOutputTemplate:
    """Tests for OutputTemplate model."""

    def test_xml_template(self):
        """Test creating an XML output template."""
        template = OutputTemplate(
            format="xml",
            template="<Event>{{ EventID }}</Event>",
            file_extension=".xml",
        )
        assert template.format == "xml"
        assert template.template == "<Event>{{ EventID }}</Event>"
        assert template.file_extension == ".xml"
        assert template.encoding == "utf-8"

    def test_json_template(self):
        """Test creating a JSON output template."""
        template = OutputTemplate(
            format="json", template='{"event": "{{ EventID }}"}', file_extension=".json"
        )
        assert template.format == "json"

    def test_tsv_template(self):
        """Test creating a TSV output template."""
        template = OutputTemplate(
            format="tsv",
            template="{{ field1 }}\t{{ field2 }}",
            file_extension=".log",
            header_template="#fields\tfield1\tfield2",
        )
        assert template.format == "tsv"
        assert template.header_template == "#fields\tfield1\tfield2"

    def test_csv_template(self):
        """Test creating a CSV output template."""
        template = OutputTemplate(
            format="csv", template="{{ field1 }},{{ field2 }}", file_extension=".csv"
        )
        assert template.format == "csv"

    def test_text_template(self):
        """Test creating a text output template."""
        template = OutputTemplate(
            format="text", template="Event: {{ EventID }}", file_extension=".txt"
        )
        assert template.format == "text"

    def test_custom_encoding(self):
        """Test template with custom encoding."""
        template = OutputTemplate(
            format="xml",
            template="<Event></Event>",
            file_extension=".xml",
            encoding="utf-16",
        )
        assert template.encoding == "utf-16"

    def test_invalid_format(self):
        """Test that invalid format types are rejected."""
        with pytest.raises(ValidationError, match="pattern"):
            OutputTemplate(
                format="invalid",  # type: ignore
                template="test",
                file_extension=".log",
            )

    def test_invalid_file_extension_no_dot(self):
        """Test that file extensions without dot are rejected."""
        with pytest.raises(ValidationError, match="pattern"):
            OutputTemplate(format="xml", template="test", file_extension="xml")

    def test_invalid_file_extension_uppercase(self):
        """Test that uppercase file extensions are rejected."""
        with pytest.raises(ValidationError, match="pattern"):
            OutputTemplate(format="xml", template="test", file_extension=".XML")

    def test_extra_fields_rejected(self):
        """Test that extra fields are rejected."""
        with pytest.raises(ValidationError):
            OutputTemplate(
                format="xml",
                template="test",
                file_extension=".xml",
                unknown_field="value",  # type: ignore
            )


class TestFormatDefinition:
    """Tests for FormatDefinition model."""

    def test_minimal_format(self):
        """Test creating a minimal format definition."""
        fmt = FormatDefinition(
            name="test_format",
            description="Test format",
            category="host",
            fields=[FieldDefinition(name="field1", type=FieldType.STRING)],
            output=OutputTemplate(format="text", template="test", file_extension=".txt"),
        )
        assert fmt.name == "test_format"
        assert fmt.version == "1.0"
        assert fmt.description == "Test format"
        assert fmt.category == "host"
        assert len(fmt.fields) == 1
        assert fmt.variants == []
        assert fmt.validators is None

    def test_full_format(self):
        """Test creating a complete format definition."""
        fields = [
            FieldDefinition(name="field1", type=FieldType.STRING),
            FieldDefinition(name="field2", type=FieldType.INTEGER),
        ]
        variants = [
            EventVariant(
                name="variant1",
                event_id="1",
                fields=[FieldDefinition(name="v1_field", type=FieldType.STRING)],
            )
        ]
        output = OutputTemplate(format="xml", template="<test/>", file_extension=".xml")
        validators = [{"==": [{"var": "field1"}, "value"]}]

        fmt = FormatDefinition(
            name="test_format",
            version="2.0",
            description="Test format",
            category="network",
            fields=fields,
            variants=variants,
            output=output,
            validators=validators,
        )
        assert fmt.name == "test_format"
        assert fmt.version == "2.0"
        assert fmt.category == "network"
        assert len(fmt.fields) == 2
        assert len(fmt.variants) == 1
        assert fmt.validators == validators

    def test_all_categories_valid(self):
        """Test that all valid categories work."""
        for category in ["host", "network", "application", "cloud"]:
            fmt = FormatDefinition(
                name="test",
                description="Test",
                category=category,
                fields=[FieldDefinition(name="f", type=FieldType.STRING)],
                output=OutputTemplate(format="text", template="t", file_extension=".txt"),
            )
            assert fmt.category == category

    def test_invalid_category(self):
        """Test that invalid categories are rejected."""
        with pytest.raises(ValidationError, match="pattern"):
            FormatDefinition(
                name="test",
                description="Test",
                category="invalid",  # type: ignore
                fields=[FieldDefinition(name="f", type=FieldType.STRING)],
                output=OutputTemplate(format="text", template="t", file_extension=".txt"),
            )

    def test_invalid_name_with_uppercase(self):
        """Test that format names with uppercase are rejected."""
        with pytest.raises(ValidationError, match="pattern"):
            FormatDefinition(
                name="TestFormat",
                description="Test",
                category="host",
                fields=[FieldDefinition(name="f", type=FieldType.STRING)],
                output=OutputTemplate(format="text", template="t", file_extension=".txt"),
            )

    def test_invalid_name_with_hyphen(self):
        """Test that format names with hyphens are rejected."""
        with pytest.raises(ValidationError, match="pattern"):
            FormatDefinition(
                name="test-format",
                description="Test",
                category="host",
                fields=[FieldDefinition(name="f", type=FieldType.STRING)],
                output=OutputTemplate(format="text", template="t", file_extension=".txt"),
            )

    def test_duplicate_field_names_rejected(self):
        """Test that duplicate field names are rejected."""
        fields = [
            FieldDefinition(name="duplicate", type=FieldType.STRING),
            FieldDefinition(name="duplicate", type=FieldType.INTEGER),
        ]
        with pytest.raises(ValidationError, match="Duplicate field names"):
            FormatDefinition(
                name="test",
                description="Test",
                category="host",
                fields=fields,
                output=OutputTemplate(format="text", template="t", file_extension=".txt"),
            )

    def test_empty_fields_allowed(self):
        """Test that empty field list is allowed (variants provide fields)."""
        fmt = FormatDefinition(
            name="test",
            description="Test",
            category="host",
            fields=[],
            variants=[
                EventVariant(
                    name="v1",
                    fields=[FieldDefinition(name="f", type=FieldType.STRING)],
                )
            ],
            output=OutputTemplate(format="text", template="t", file_extension=".txt"),
        )
        assert len(fmt.fields) == 0
        assert len(fmt.variants) == 1

    def test_extra_fields_rejected(self):
        """Test that extra fields are rejected."""
        with pytest.raises(ValidationError):
            FormatDefinition(
                name="test",
                description="Test",
                category="host",
                fields=[FieldDefinition(name="f", type=FieldType.STRING)],
                output=OutputTemplate(format="text", template="t", file_extension=".txt"),
                unknown_field="value",  # type: ignore
            )
