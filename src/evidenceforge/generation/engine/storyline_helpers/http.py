# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Storyline HTTP helpers without coordinator dependencies."""

import random
from typing import Any

from evidenceforge.generation.activity.http_content import response_size_for_status
from evidenceforge.models.scenario import MAX_HTTP_RESPONSE_BODY_LEN


def _is_exfil_connection_spec(spec: Any) -> bool:
    """Return True when a storyline connection describes exfiltration."""
    desc = (spec.description or "").lower()
    tech = (spec.technique or "").lower()
    return "exfil" in desc or "t1041" in tech or "t1048" in tech


def _is_c2_http_request(
    *,
    description: str | None,
    technique: str | None,
    uri: str | None,
    activity: str | None = None,
) -> bool:
    """Return True when a storyline HTTP request should look like C2/tasking."""
    uri_l = (uri or "").lower()
    text = f"{description or ''} {technique or ''} {activity or ''} {uri_l}".lower()
    text_markers = (
        "c2",
        "beacon",
        "callback",
        "checkin",
        "tasking",
        "command and control",
        "t1041",
        "t1071",
    )
    path_markers = (
        "/v2/",
        "/callback",
        "/checkin",
        "/beacon",
        "/task",
        "/cmd",
        "/gate",
    )
    return any(marker in text for marker in text_markers) or any(
        marker in uri_l for marker in path_markers
    )


def _c2_http_response_size(rng: random.Random, *, method: str, uri: str) -> int:
    """Return varied source-native response body sizes for C2-like HTTP requests."""
    method_u = method.upper()
    uri_l = uri.lower()
    if method_u == "POST":
        return rng.randint(160, 2600)
    if any(marker in uri_l for marker in ("/status", "/check", "/heartbeat", "/ping")):
        band = rng.choices(["ack", "config", "task"], weights=[55, 34, 11], k=1)[0]
        if band == "ack":
            return rng.randint(90, 1800)
        if band == "config":
            return rng.randint(2400, 14500)
        return rng.randint(18_000, 86_000)
    if any(marker in uri_l for marker in ("/client", "/stage", "/update", "/loader")):
        return rng.randint(8_000, 94_000)
    return rng.randint(220, 11_000)


def _is_round_transfer_size(value: int) -> bool:
    """Return True for large human-authored round byte counts."""
    if value < 1_000_000:
        return False
    binary_mib = 1024 * 1024
    decimal_mb = 1000 * 1000
    return value % binary_mib == 0 or value % decimal_mb == 0 or value & (value - 1) == 0


def _deround_storyline_transfer_size(value: int, rng: random.Random) -> int:
    """Add archive/package variance so exfil sizes do not land on exact MB boundaries."""
    delta_min = max(32_768, value // 250)
    delta_max = max(delta_min + 1, value // 25)
    delta = rng.randint(delta_min, delta_max) + rng.randint(137, 8191)
    if value - delta > 1_000_000 and rng.random() < 0.35:
        adjusted = value - delta
    else:
        adjusted = value + delta
    if _is_round_transfer_size(adjusted):
        adjusted += rng.randint(139, 8191)
    return adjusted


def _size_storyline_connection(
    spec: Any,
    rng: random.Random,
) -> tuple[int, int]:
    """Determine orig_bytes/resp_bytes for a storyline connection.

    Priority:
    1. Explicit spec values (author override)
    2. Heuristic sizing based on technique/description keywords
    3. Default bidirectional range
    """
    ob = spec.orig_bytes
    rb = spec.resp_bytes

    desc = (spec.description or "").lower()
    tech = (spec.technique or "").lower()

    is_exfil = _is_exfil_connection_spec(spec)
    is_c2 = "c2" in desc or "callback" in desc or "beacon" in desc or "t1071" in tech
    is_download = "download" in desc or "stage" in desc or "t1105" in tech

    if ob is not None and is_exfil and _is_round_transfer_size(ob):
        ob = _deround_storyline_transfer_size(ob, rng)

    if ob is None:
        if is_exfil:
            ob = rng.randint(1_000_000, 50_000_000)  # 1-50 MB
        elif is_c2:
            ob = rng.randint(500, 5_000)
        elif is_download:
            ob = rng.randint(200, 2_000)
        else:
            ob = rng.randint(1_000, 10_000)

    if rb is None:
        if is_exfil:
            rb = rng.randint(200, 5_000)  # small ACK/response
        elif is_c2:
            rb = rng.randint(1_000, 10_000)  # tasking payload
        elif is_download:
            rb = rng.randint(50_000, 5_000_000)  # 50KB-5MB payload
        else:
            rb = rng.randint(5_000, 50_000)

    return ob, rb


def _storyline_http_response_body_len(
    *,
    spec: Any,
    rng: random.Random,
    method: str,
    uri: str,
    host: str,
    is_c2_http: bool,
    use_connection_path_hints: bool,
) -> int:
    """Return the body size rendered by web/proxy access logs for authored HTTP."""
    method_upper = method.upper()
    status_code = spec.status_code or 200
    uri_lower = uri.lower()

    if method_upper == "HEAD":
        return 0
    if spec.response_body_len is not None:
        return min(max(0, spec.response_body_len), MAX_HTTP_RESPONSE_BODY_LEN)
    if spec.resp_bytes is not None:
        return min(max(0, spec.resp_bytes), MAX_HTTP_RESPONSE_BODY_LEN)
    if status_code >= 300 or status_code in {204, 304}:
        return response_size_for_status(status_code, host, uri)
    if (
        use_connection_path_hints
        and method_upper == "POST"
        and any(kw in uri_lower for kw in ("/upload", "/submit", "/api", "/beacon"))
    ):
        return rng.randint(200, 2000)
    if (
        use_connection_path_hints
        and method_upper == "GET"
        and any(kw in uri_lower for kw in ("/callback", "/task", "/cmd", "/beacon", "/gate"))
    ):
        return rng.randint(500, 5000)
    if is_c2_http:
        return _c2_http_response_size(rng, method=method, uri=uri)
    if method_upper == "POST":
        return rng.randint(200, 5000) if use_connection_path_hints else rng.randint(200, 2000)
    return response_size_for_status(status_code, host, uri)
