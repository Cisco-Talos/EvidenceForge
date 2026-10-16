# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Evaluation ownership for versioned native exports with nested wire schemas."""

import json
from collections.abc import Callable

from pydantic import ValidationError

from evidenceforge.evaluation.parsers import ParsedRecord
from evidenceforge.evaluation.parsers.json_record import decode_record
from evidenceforge.formats.macos_endpoint_security import decode_endpoint_security_record
from evidenceforge.formats.macos_unified_log import (
    UnifiedLogCompletion,
    decode_unified_log_record,
)
from evidenceforge.formats.rules import Finding


def _validate(record: ParsedRecord, decoder: Callable[[str], object]) -> list[Finding]:
    try:
        if record.raw:
            if decode_record(record.raw) != record.fields:
                raise ValueError("Native parsed fields disagree with the original record")
            raw = record.raw
        else:
            raw = json.dumps(record.fields, allow_nan=False)
        native = decoder(raw)
        if isinstance(native, UnifiedLogCompletion):
            raise ValueError("Unified Log completion is export bookkeeping, not an event")
    except ValidationError as exc:
        return [
            Finding(
                rule_id=f"native.{record.source_format}.structure",
                format=record.source_format,
                category="schema",
                fields=tuple(str(part) for part in error["loc"]),
                message=error["msg"],
            )
            for error in exc.errors(include_input=False, include_context=False)[:8]
        ]
    except (TypeError, ValueError) as exc:
        return [
            Finding(
                rule_id=f"native.{record.source_format}.structure",
                format=record.source_format,
                category="schema",
                message=str(exc),
            )
        ]
    return []


def validate_unified_log(record: ParsedRecord) -> list[Finding]:
    """Validate the native logEvent schema without treating markers as evidence."""
    return _validate(record, decode_unified_log_record)


def validate_endpoint_security(record: ParsedRecord) -> list[Finding]:
    """Validate an admitted version/family pair; this does not certify fidelity."""
    return _validate(record, decode_endpoint_security_record)


NATIVE_CODEC_VALIDATORS: dict[str, Callable[[ParsedRecord], list[Finding]]] = {
    "macos_unified_log": validate_unified_log,
    "macos_endpoint_security": validate_endpoint_security,
}
