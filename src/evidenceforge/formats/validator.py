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

"""Format validation for EvidenceForge.

This module provides validation functions for log fields based on format definitions.
Uses json-logic-py for complex validation rules.
"""

import ipaddress
import json
import logging
import re
import xml.etree.ElementTree as ET
from datetime import datetime
from typing import Any

from json_logic import jsonLogic

from .format_def import FieldConstraint, FieldDefinition, FieldType, FormatDefinition

# Deduplicate unknown field warnings: only warn once per (format, field) pair
_warned_unknown_fields: set[tuple[str, str]] = set()

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
            result.add_error(field_name, f"Expected string, got {type(field_value).__name__}")

    elif field_type == FieldType.INTEGER:
        if not isinstance(field_value, int) or isinstance(field_value, bool):
            result.add_error(field_name, f"Expected integer, got {type(field_value).__name__}")

    elif field_type == FieldType.BOOLEAN:
        if not isinstance(field_value, bool):
            result.add_error(field_name, f"Expected boolean, got {type(field_value).__name__}")

    elif field_type == FieldType.TIMESTAMP:
        # Accept datetime objects, ISO 8601 strings, or epoch floats/ints (Zeek)
        if isinstance(field_value, (int, float)) and not isinstance(field_value, bool):
            pass  # Epoch timestamp — valid
        elif isinstance(field_value, str):
            try:
                datetime.fromisoformat(field_value.replace("Z", "+00:00"))
            except ValueError:
                result.add_error(field_name, "Invalid ISO 8601 timestamp")
        elif not isinstance(field_value, datetime):
            result.add_error(field_name, f"Expected timestamp, got {type(field_value).__name__}")

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
        elif not (0 <= field_value <= 65535):
            result.add_error(field_name, f"Port must be 0-65535, got {field_value}")

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

    elif field_type == FieldType.LIST:
        if not isinstance(field_value, list):
            result.add_error(field_name, f"Expected list, got {type(field_value).__name__}")

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
        if constraints.min_length is not None and len(field_value) < constraints.min_length:
            result.add_error(
                field_name,
                f"Length {len(field_value)} less than minimum {constraints.min_length}",
            )
        if constraints.max_length is not None and len(field_value) > constraints.max_length:
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
            data = {"value": field_value}
            logic_result = jsonLogic(constraints.json_logic, data)
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


# ---------------------------------------------------------------------------
# Strict-mode validators — format-specific raw-content checks
# ---------------------------------------------------------------------------

# RFC3164 syslog header: <PRI>MMM DD HH:MM:SS HOSTNAME APP[PID]:
_RFC3164_RE = re.compile(
    r"^<(?P<pri>\d{1,3})>"
    r"(?P<timestamp>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+"
    r"(?P<hostname>\S+)\s+"
    r"(?P<app_name>\S+?)(?:\[[^\]]+\])?:\s+"
    r".*$"
)

# RFC 5424 syslog header: <PRI>VERSION TIMESTAMP HOSTNAME APP-NAME PROCID MSGID STRUCTURED-DATA
_RFC5424_RE = re.compile(
    r"^<(?P<pri>\d{1,3})>(?P<version>\d+)\s+"
    r"(?P<timestamp>\S+)\s+"
    r"(?P<hostname>\S+)\s+"
    r"(?P<app_name>\S+)\s+"
    r"(?P<procid>\S+)\s+"
    r"(?P<msgid>\S+)\s+"
    r"(?P<structured_data>-|(?:\[[^\]]*\])+)"
    r"(?:\s(?P<message>.*))?$"
)
_RFC5424_PRIORITY_MAX = 191  # 23 facilities × 8 severities - 1
_LEGACY_BSD_SYSLOG_RE = re.compile(r"^[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+\S+\s+\S+")
_LEGACY_ISO_SYSLOG_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\S*\s+\S+\s+\S+")

# eCAR valid object/action combos
_ECAR_VALID_OBJECTS = frozenset(
    {"PROCESS", "FILE", "FLOW", "REGISTRY", "MODULE", "THREAD", "USER_SESSION", "SERVICE"}
)
_ECAR_VALID_ACTIONS = frozenset(
    {
        "CREATE",
        "DELETE",
        "MODIFY",
        "READ",
        "WRITE",
        "OPEN",
        "CLOSE",
        "EXECUTE",
        "TERMINATE",
        "LOGIN",
        "LOGOUT",
        "START",
        "STOP",
        "LOAD",
        "UNLOAD",
        "CONNECT",
        "DISCONNECT",
        "REMOTE_CREATE",
    }
)

# Formats that support strict-mode validation
STRICT_FORMATS: frozenset[str] = frozenset(
    {
        "syslog",
        "zeek_files",
        "zeek_conn",
        "zeek_http",
        "zeek_ssl",
        "zeek_dns",
        "zeek_x509",
        "zeek_dhcp",
        "zeek_ntp",
        "zeek_pe",
        "zeek_weird",
        "zeek_ocsp",
        "zeek_reporter",
        "zeek_packet_filter",
        "windows_event_security",
        "windows_event_sysmon",
        "ecar",
    }
)


def validate_strict(format_name: str, raw: str, fields: dict[str, Any]) -> ValidationResult:
    """Perform strict format-specific validation on a raw log line.

    This supplements the lenient schema validator with format-specific
    invariants that are well-defined by spec.

    Args:
        format_name: The format identifier (e.g., "syslog", "zeek_conn").
        raw: The original raw log line string.
        fields: Already-parsed fields dict from the normal parser.

    Returns:
        ValidationResult — valid=True if strict checks pass.
    """
    result = ValidationResult()

    if format_name == "syslog":
        _validate_strict_syslog(raw, fields, result)
    elif format_name.startswith("zeek_"):
        _validate_strict_zeek_json(raw, result)
    elif format_name in ("windows_event_security", "windows_event_sysmon"):
        _validate_strict_windows_xml(raw, result)
    elif format_name == "ecar":
        _validate_strict_ecar(raw, fields, result)

    return result


def _validate_strict_syslog(raw: str, fields: dict[str, Any], result: ValidationResult) -> None:
    """Validate generated RFC5424/RFC3164 syslog and parser-marked legacy input."""
    if not raw.strip():
        return

    protocol = fields.get("syslog_protocol")
    if protocol in (None, "", "rfc3164"):
        match = _RFC3164_RE.match(raw)
        if match is None:
            result.add_error("syslog", "Syslog line does not match BSD/RFC3164")
            return
        pri = int(match.group("pri"))
        if pri > _RFC5424_PRIORITY_MAX:
            result.add_error("syslog_pri", f"PRI {pri} exceeds maximum {_RFC5424_PRIORITY_MAX}")
        return
    if protocol == "rfc3164_legacy":
        if not _LEGACY_BSD_SYSLOG_RE.match(raw):
            result.add_error("syslog", "Legacy syslog marker does not match BSD/RFC3164 input")
        return
    if protocol == "iso_legacy":
        if not _LEGACY_ISO_SYSLOG_RE.match(raw):
            result.add_error("syslog", "Legacy syslog marker does not match ISO-style input")
        return
    if protocol not in ("rfc5424", "rfc5424_legacy"):
        result.add_error("syslog", f"Unknown syslog protocol marker: {protocol}")
        return

    match = _RFC5424_RE.match(raw)
    if match is None:
        result.add_error("syslog", "Legacy syslog marker does not match RFC 5424")
        return

    pri = int(match.group("pri"))
    if pri > _RFC5424_PRIORITY_MAX:
        result.add_error("syslog_pri", f"PRI {pri} exceeds maximum {_RFC5424_PRIORITY_MAX}")

    if match.group("version") != "1":
        result.add_error("syslog_version", "RFC 5424 VERSION must be 1")

    timestamp = match.group("timestamp")
    if timestamp == "-":
        result.add_error("syslog_timestamp", "Generated syslog requires a timestamp")
        return
    try:
        datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
    except ValueError:
        result.add_error("syslog_timestamp", f"Invalid RFC 5424 timestamp: {timestamp}")


def _validate_strict_zeek_json(raw: str, result: ValidationResult) -> None:
    """Zeek JSON Lines: each line must be valid JSON and a top-level object."""
    raw = raw.strip()
    if not raw:
        return
    try:
        obj = json.loads(raw)
    except json.JSONDecodeError as e:
        result.add_error("zeek_json", f"Invalid JSON: {e}")
        return
    if not isinstance(obj, dict):
        result.add_error("zeek_json", f"Expected JSON object, got {type(obj).__name__}")


def _validate_strict_windows_xml(raw: str, result: ValidationResult) -> None:
    """Windows event XML: must be well-formed with <Event><System> structure."""
    raw = raw.strip()
    if not raw:
        return
    try:
        root = ET.fromstring(raw)
    except ET.ParseError as e:
        result.add_error("windows_xml", f"XML parse error: {e}")
        return
    # Accept any namespace variant of Event/System
    tag = root.tag
    local = tag.split("}")[-1] if "}" in tag else tag
    if local != "Event":
        result.add_error("windows_xml", f"Root element must be 'Event', got '{local}'")
        return
    # Check for System child
    system_child = None
    for child in root:
        ctag = child.tag.split("}")[-1] if "}" in child.tag else child.tag
        if ctag == "System":
            system_child = child
            break
    if system_child is None:
        result.add_error("windows_xml", "Missing <System> child element")


def _validate_strict_ecar(raw: str, fields: dict[str, Any], result: ValidationResult) -> None:
    """eCAR: valid JSON, valid object/action enum values."""
    raw = raw.strip()
    if not raw:
        return
    try:
        obj = json.loads(raw)
    except json.JSONDecodeError as e:
        result.add_error("ecar_json", f"Invalid JSON: {e}")
        return
    if not isinstance(obj, dict):
        result.add_error("ecar_json", f"Expected JSON object, got {type(obj).__name__}")
        return
    obj_type = obj.get("object")
    action = obj.get("action")
    if obj_type is not None and obj_type not in _ECAR_VALID_OBJECTS:
        result.add_error("ecar_object", f"Unknown object type: {obj_type!r}")
    if action is not None and action not in _ECAR_VALID_ACTIONS:
        result.add_error("ecar_action", f"Unknown action: {action!r}")


def validate_event(
    format_def: FormatDefinition,
    event_data: dict[str, Any],
    variant_name: str | None = None,
    event_context: str | None = None,
) -> ValidationResult:
    """Validate an event against a format definition.

    Args:
        format_def: Format definition
        event_data: Event data dict (field name -> value)
        variant_name: Optional variant name (for formats with variants)
        event_context: Optional context string for better messages
            (e.g., "EventID 4720, account_created" or "dns.log")

    Returns:
        ValidationResult with all validation errors
    """
    result = ValidationResult()
    ctx_suffix = f" ({event_context})" if event_context else ""

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
            result.add_error(field_def.name, f"Required field missing{ctx_suffix}")

    # Validate present fields
    for field_name, field_value in event_data.items():
        # Find field definition
        field_def = next((f for f in fields if f.name == field_name), None)
        if not field_def:
            # Unknown field (warning, not error) — deduplicate per context
            key = (format_def.name, field_name, event_context or "")
            if key not in _warned_unknown_fields:
                _warned_unknown_fields.add(key)
                logger.warning(f"Unknown field in {format_def.name}{ctx_suffix}: {field_name}")
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
