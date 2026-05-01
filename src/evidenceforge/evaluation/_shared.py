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

"""Shared helpers used across multiple pillar scorers."""

import math
from datetime import UTC, datetime
from typing import Any

from evidenceforge.evaluation.parsers import ParsedRecord

# Formats that carry user attribution
_USER_FIELD_MAP: dict[str, list[str]] = {
    "windows_event_security": ["TargetUserName", "SubjectUserName"],
    "bash_history": ["username"],
    "ecar": ["principal"],
    "web_access": ["username"],
    "syslog": [],  # user extracted from message
}

# Formats that carry hostname
_HOST_FIELD_MAP: dict[str, str] = {
    "windows_event_security": "Computer",
    "bash_history": "hostname",
    "ecar": "hostname",
    "syslog": "hostname",
}


def _extract_username(record: ParsedRecord) -> str | None:
    """Extract username from a parsed record."""
    fmt = record.source_format
    fields = record.fields

    user_fields = _USER_FIELD_MAP.get(fmt, [])
    for uf in user_fields:
        val = fields.get(uf)
        if val and isinstance(val, str) and val != "-":
            return val.lower()

    # Syslog: try to extract from message
    if fmt == "syslog":
        msg = fields.get("message", "")
        for pattern_prefix in ["for ", "user="]:
            idx = msg.find(pattern_prefix)
            if idx >= 0:
                rest = msg[idx + len(pattern_prefix) :]
                user = rest.split()[0].strip("'\"") if rest else None
                if user:
                    return user.lower()

    return None


def _extract_hostname(record: ParsedRecord) -> str | None:
    """Extract hostname from a parsed record, normalizing FQDN to bare hostname."""
    field_name = _HOST_FIELD_MAP.get(record.source_format)
    if field_name:
        val = record.fields.get(field_name)
        if val and isinstance(val, str):
            return _normalize_hostname(val)
    # Fall back to source_host set by the parser from the file's directory name
    if record.source_host:
        return _normalize_hostname(record.source_host)
    return None


def _normalize_hostname(hostname: str) -> str:
    """Normalize hostname by stripping domain suffix."""
    if not hostname:
        return hostname
    # IP addresses pass through unchanged
    if hostname[0].isdigit():
        return hostname
    # Strip domain suffix: take only the first component
    parts = hostname.split(".")
    if len(parts) > 1:
        return parts[0]
    return hostname


def _normalize_ts(ts: datetime) -> datetime:
    """Ensure a datetime is timezone-aware (UTC)."""
    if ts.tzinfo is None:
        return ts.replace(tzinfo=UTC)
    return ts


def _condition_matches(condition: dict[str, Any], fields: dict[str, Any]) -> bool:
    """Check if a record's fields match a rule's condition dict.

    Handles optional 'exclude' key for exclusion criteria.
    """
    if not condition:
        return True
    for key, expected in condition.items():
        if key == "exclude":
            for ex_key, ex_val in expected.items():
                actual = fields.get(ex_key)
                if actual == ex_val or str(actual) == str(ex_val):
                    return False
            continue
        actual = fields.get(key)
        if actual != expected:
            try:
                if str(actual) != str(expected):
                    return False
            except (ValueError, TypeError):
                return False
    return True


def _jensen_shannon_divergence(p: dict, q: dict) -> float:
    """Jensen-Shannon divergence between two distributions (uses natural log).

    Returns a value in [0, ln(2)] ≈ [0, 0.693].
    """
    all_keys = set(p.keys()) | set(q.keys())
    jsd = 0.0
    for key in all_keys:
        p_val = p.get(key, 0.0)
        q_val = q.get(key, 0.0)
        m_val = (p_val + q_val) / 2.0
        if p_val > 0 and m_val > 0:
            jsd += 0.5 * p_val * math.log(p_val / m_val)
        if q_val > 0 and m_val > 0:
            jsd += 0.5 * q_val * math.log(q_val / m_val)
    return max(0.0, jsd)


def _jensen_shannon_2d(p: dict, q: dict) -> float:
    """Jensen-Shannon divergence (in bits, range 0–1) between two 2D distributions."""
    all_keys = set(p.keys()) | set(q.keys())
    jsd = 0.0
    for key in all_keys:
        p_val = p.get(key, 0.0)
        q_val = q.get(key, 0.0)
        m_val = (p_val + q_val) / 2.0
        if p_val > 0 and m_val > 0:
            jsd += 0.5 * p_val * math.log2(p_val / m_val)
        if q_val > 0 and m_val > 0:
            jsd += 0.5 * q_val * math.log2(q_val / m_val)
    return jsd
