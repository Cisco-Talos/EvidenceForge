# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Safe public DNS answer template validation and rendering."""

from __future__ import annotations

from string import Formatter

_ALLOWED_PUBLIC_DNS_FIELDS = frozenset({"domain", "domain_hyphen"})
_FORMATTER = Formatter()


def validate_public_dns_answer_template(template: str) -> str:
    """Validate a public DNS answer template uses only safe placeholders.

    Public DNS profile data may come from project-local overlays. Keep the
    supported mini-language intentionally tiny: literal text plus the exact
    ``{domain}`` and ``{domain_hyphen}`` placeholders. Python format specs,
    conversions, attribute access, indexing, and unknown fields are rejected so
    untrusted overlays cannot trigger KeyError crashes or large allocations via
    width/precision specifiers.
    """
    try:
        parsed = list(_FORMATTER.parse(template))
    except ValueError as exc:
        raise ValueError(f"invalid public DNS answer template: {exc}") from exc

    for _literal_text, field_name, format_spec, conversion in parsed:
        if field_name is None:
            continue
        if field_name not in _ALLOWED_PUBLIC_DNS_FIELDS:
            allowed = ", ".join(f"{{{field}}}" for field in sorted(_ALLOWED_PUBLIC_DNS_FIELDS))
            raise ValueError(
                "public DNS answer templates may only use "
                f"{allowed} placeholders; found {{{field_name}}}"
            )
        if conversion is not None:
            raise ValueError("public DNS answer templates must not use conversion flags")
        if format_spec:
            raise ValueError("public DNS answer templates must not use format specifiers")
    return template


def render_public_dns_answer_template(template: str, domain: str) -> str:
    """Render a validated public DNS answer template without Python format specs."""
    validate_public_dns_answer_template(template)
    values = {
        "domain": domain,
        "domain_hyphen": domain.replace(".", "-"),
    }
    rendered: list[str] = []
    for literal_text, field_name, _format_spec, _conversion in _FORMATTER.parse(template):
        rendered.append(literal_text)
        if field_name is not None:
            rendered.append(values[field_name])
    return "".join(rendered)
