# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""IDS signature configuration loader and helpers."""

from __future__ import annotations

import random
import string
from string import Formatter
from typing import Any

from evidenceforge.config import get_activity_directory
from evidenceforge.config.overlay import extend_list, load_with_overlay

_CONFIG_PATH = get_activity_directory() / "ids_signatures.yaml"
_CACHED_DATA: dict[str, Any] | None = None
_MAX_DNS_TEMPLATE_LENGTH = 253
_MAX_TOKEN_WIDTH = 64


def _merge_ids_signatures(default: dict[str, Any], overlay: dict[str, Any]) -> dict[str, Any]:
    """Merge IDS signature overlay with package defaults."""
    result = dict(default)
    if "signatures" in overlay:
        result["signatures"] = extend_list(default.get("signatures", []), overlay["signatures"])
    return result


def load_ids_signatures() -> dict[str, Any]:
    """Load IDS signature config, merged with any project-local overlay."""
    global _CACHED_DATA
    if _CACHED_DATA is None:
        _CACHED_DATA = load_with_overlay(
            _CONFIG_PATH,
            "activity/ids_signatures.yaml",
            _merge_ids_signatures,
        )
    return _CACHED_DATA


def reset_ids_signatures_cache() -> None:
    """Clear cached IDS signature config. Intended for tests."""
    global _CACHED_DATA
    _CACHED_DATA = None


def signature_by_sid(sid: int) -> dict[str, Any] | None:
    """Return the curated signature dict for ``sid`` (merged with overlay), or None.

    Used to attach a known on-wire IDS signature to canonical network evidence — e.g.
    an adversarial_payload family maps to the ET rule a sensor should fire on when the
    payload rides a cleartext HTTP request.
    """
    for signature in load_ids_signatures().get("signatures", []):
        if signature.get("sid") == sid:
            return dict(signature)
    return None


def validate_dns_query_template(template: str) -> str | None:
    """Validate IDS DNS template safety; return error message or None."""
    if not template:
        return "must be a non-empty string containing {token}"
    if len(template) > _MAX_DNS_TEMPLATE_LENGTH:
        return f"must be <= {_MAX_DNS_TEMPLATE_LENGTH} characters"
    formatter = Formatter()
    saw_token = False
    try:
        for _, field_name, format_spec, conversion in formatter.parse(template):
            if field_name is None:
                continue
            if field_name != "token":
                return "may only reference {token}"
            saw_token = True
            if conversion is not None:
                return "must not use ! conversions"
            if "{" in format_spec or "}" in format_spec:
                return "must not use nested format specifiers"
            if format_spec:
                if not format_spec.isdigit():
                    return "must use numeric width only"
                if int(format_spec) > _MAX_TOKEN_WIDTH:
                    return f"must use token width <= {_MAX_TOKEN_WIDTH}"
    except ValueError:
        return "contains invalid format syntax"
    if not saw_token:
        return "must contain {token}"
    return None


def render_dns_query_template(signature: dict[str, Any], rng: random.Random) -> str | None:
    """Render a DNS query template associated with an IDS DNS signature."""
    templates = signature.get("dns_query_templates") or []
    if not isinstance(templates, list) or not templates:
        return None
    candidates = [
        template
        for template in templates
        if isinstance(template, str) and validate_dns_query_template(template) is None
    ]
    if not candidates:
        return None
    token = "".join(rng.choice(string.ascii_lowercase + string.digits) for _ in range(8))
    return rng.choice(candidates).format(token=token)
