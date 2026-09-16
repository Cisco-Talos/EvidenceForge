# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Strict JSON object decoding shared by record parsers."""

import json
from typing import Any


def _object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for name, value in pairs:
        if name in result:
            raise ValueError(f"Duplicate JSON field: {name}")
        result[name] = value
    return result


def _constant(value: str) -> None:
    raise ValueError(f"Nonfinite JSON number: {value}")


def decode_record(raw: str) -> dict[str, Any]:
    """Decode a finite JSON object without silently replacing duplicate keys."""
    value = json.loads(raw, object_pairs_hook=_object, parse_constant=_constant)
    if not isinstance(value, dict):
        raise ValueError("Expected JSON object")
    return value
