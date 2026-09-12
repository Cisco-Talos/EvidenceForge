# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Shared proxy protocol planning helpers."""

from __future__ import annotations

import logging
import random

from evidenceforge.generation.timing import (
    TimingRuntime,
)

from .network_common import _activity_timing_planner, _activity_timing_stable_id

logger = logging.getLogger(__name__)

_PROXY_CS_OVERHEAD = (80, 350)  # Via, X-Forwarded-For, etc.

_PROXY_SC_OVERHEAD = (50, 250)  # Via, X-Cache, Age, etc.


def _proxy_request_allows_cache_hit(
    *,
    method: str,
    url: str,
    content_type: str,
    domain_tags: list[str] | tuple[str, ...],
) -> bool:
    """Return whether a proxy request can plausibly be served from cache."""
    if method.upper() not in {"GET", "HEAD"}:
        return False
    url_l = url.lower()
    content_l = content_type.lower()
    if any(tag in {"c2", "malware", "beacon", "command-control"} for tag in domain_tags):
        return False
    if any(marker in url_l for marker in ("/api/", "/checkin", "/beacon", "/task", "/gate")):
        return False
    if content_l in {"application/json", "application/octet-stream"}:
        return False
    return content_l.startswith(("image/", "font/")) or content_l in {
        "application/javascript",
        "text/css",
    }


def _proxy_time_taken_ms(
    duration: float | None,
    rng: random.Random,
    *,
    method: str,
    status_code: int,
    cache_result: str = "",
    minimum_ms: int = 1,
    timing_runtime: TimingRuntime | None = None,
    stable_id: str = "",
) -> int:
    """Return proxy-side service time without mirroring wire duration exactly."""
    base_ms = max(1, int((duration or 0.0) * 1000))
    method_upper = method.upper()
    cache_upper = cache_result.upper()
    planner = _activity_timing_planner(timing_runtime)
    timing_id = stable_id or _activity_timing_stable_id(
        "proxy-time",
        base_ms,
        method_upper,
        status_code,
        cache_upper,
        rng=rng,
    )

    if status_code >= 400:
        minimum, median, maximum = (
            (20.0, 140.0, 1500.0) if method_upper == "CONNECT" else (35.0, 210.0, 2400.0)
        )
        sampled_ms = round(
            planner.right_skew_seconds(
                relationship_key="activity.proxy.error_service_time_ms",
                stable_id=timing_id,
                minimum=minimum,
                median=median,
                maximum=maximum,
                sample_key="milliseconds",
            )
        )
    elif cache_upper == "HIT":
        ratio = planner.right_skew_seconds(
            relationship_key="activity.proxy.cache_hit_ratio",
            stable_id=timing_id,
            minimum=0.08,
            median=0.16,
            maximum=0.42,
            sample_key="ratio",
        )
        overhead_ms = planner.right_skew_seconds(
            relationship_key="activity.proxy.cache_hit_overhead_ms",
            stable_id=timing_id,
            minimum=3.0,
            median=12.0,
            maximum=95.0,
            sample_key="overhead",
        )
        sampled_ms = round(max(8.0, base_ms * ratio) + overhead_ms)
    elif method_upper == "CONNECT":
        overhead_ms = planner.right_skew_seconds(
            relationship_key="activity.proxy.connect_overhead_ms",
            stable_id=timing_id,
            minimum=19.0,
            median=72.0,
            maximum=420.0,
            sample_key="overhead",
        )
        if base_ms > 10_000:
            overhead_ms += planner.right_skew_seconds(
                relationship_key="activity.proxy.connect_long_tail_ms",
                stable_id=timing_id,
                minimum=1.0,
                median=60.0,
                maximum=950.0,
                sample_key="tail",
            )
        jitter_ms = planner.centered_seconds(
            relationship_key="activity.proxy.connect_jitter_ms",
            stable_id=timing_id,
            mean=8.0,
            standard_deviation=15.0,
            minimum=-11.0,
            maximum=47.0,
            sample_key="jitter",
        )
        sampled_ms = round(base_ms + overhead_ms + jitter_ms)
    else:
        overhead_ms = planner.right_skew_seconds(
            relationship_key="activity.proxy.request_overhead_ms",
            stable_id=timing_id,
            minimum=7.0,
            median=34.0,
            maximum=180.0,
            sample_key="overhead",
        )
        if base_ms > 5000:
            overhead_ms += planner.right_skew_seconds(
                relationship_key="activity.proxy.request_long_tail_ms",
                stable_id=timing_id,
                minimum=1.0,
                median=28.0,
                maximum=500.0,
                sample_key="tail",
            )
        jitter_ms = planner.centered_seconds(
            relationship_key="activity.proxy.request_jitter_ms",
            stable_id=timing_id,
            mean=6.0,
            standard_deviation=12.0,
            minimum=-9.0,
            maximum=35.0,
            sample_key="jitter",
        )
        sampled_ms = round(base_ms + overhead_ms + jitter_ms)

    sampled_ms = max(minimum_ms, sampled_ms)
    if duration is not None and sampled_ms == base_ms:
        sampled_ms += 11
    return max(minimum_ms, sampled_ms)


def _proxy_action_for_context(
    *,
    method: str,
    url: str,
    status_code: int,
    cache_result: str,
    dst_port: int | None = None,
    explicit_mode: bool = False,
) -> str:
    """Return a source-native proxy policy/action hint for proxy events."""
    normalized_cache = (cache_result or "").upper()
    if normalized_cache == "DENIED":
        return "deny"
    if normalized_cache == "AUTH_REQUIRED":
        return "auth-required"
    if normalized_cache == "GATEWAY_ERROR":
        return "gateway-error"
    normalized_method = method.upper()
    normalized_url = url.lower()
    if normalized_method == "CONNECT":
        return "tunnel"
    if dst_port == 443 or normalized_url.startswith("https://"):
        return "ssl-inspect"
    return "forward"
