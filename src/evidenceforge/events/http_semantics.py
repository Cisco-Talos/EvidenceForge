# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Canonical HTTP request metadata, before source-specific rendering."""

from urllib.parse import urlsplit


def http_wire_target(reference: str) -> str:
    """Remove the client fragment without changing URI form or encoded content."""
    return reference.partition("#")[0]


def http_wire_referrer(reference: str) -> str:
    """Remove fragment/userinfo from a transmitted Referer URI reference."""
    value = http_wire_target(reference)
    try:
        parsed = urlsplit(value)
    except ValueError:
        return ""
    if "@" not in parsed.netloc:
        return value
    # Replace only the authority's userinfo, preserving spelling, query and
    # empty delimiters rather than reserializing the whole URI.
    authority_start = value.find("//") + 2
    userinfo_end = parsed.netloc.rfind("@") + 1
    return value[:authority_start] + value[authority_start + userinfo_end :]
