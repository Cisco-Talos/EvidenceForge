# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Data-driven explicit-proxy phase timing profiles."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from evidenceforge.config import get_activity_directory
from evidenceforge.config.overlay import deep_merge_dict, load_with_overlay

_CONFIG_PATH = get_activity_directory() / "proxy_phase_profiles.yaml"
_CACHED_DATA: dict[str, Any] | None = None
_MAX_PHASE_MS = 60_000


@dataclass(frozen=True, slots=True)
class MillisecondRange:
    """Validated inclusive millisecond range."""

    minimum: int
    maximum: int


@dataclass(frozen=True, slots=True)
class ProxyResolverProfile:
    """One weighted resolver path through the proxy phase graph."""

    name: str
    weight: float
    dns_completion_after_request_ms: MillisecondRange | None
    origin_after_request_ms: MillisecondRange | None
    origin_after_dns_ms: MillisecondRange | None


@dataclass(frozen=True, slots=True)
class ProxyPhaseTiming:
    """Timing ranges shared by explicit-proxy phase planners."""

    request_after_connect_ms: MillisecondRange
    inspected_request_after_connect_setup_ms: MillisecondRange
    policy_decision_after_request_ms: MillisecondRange
    tls_after_origin_connect_ms: MillisecondRange
    origin_service_ms: MillisecondRange
    client_flush_after_response_ms: MillisecondRange
    terminal_response_after_decision_ms: MillisecondRange
    close_after_flush_ms: MillisecondRange
    gateway_attempt_ms: MillisecondRange


def load_proxy_phase_profiles() -> dict[str, Any]:
    """Load proxy phase profiles with project-local overlay support."""

    global _CACHED_DATA
    if _CACHED_DATA is None:
        _CACHED_DATA = load_with_overlay(
            _CONFIG_PATH,
            "activity/proxy_phase_profiles.yaml",
            deep_merge_dict,
        )
    return _CACHED_DATA


def reset_proxy_phase_profiles_cache() -> None:
    """Clear cached profile data for focused tests."""

    global _CACHED_DATA
    _CACHED_DATA = None


def _range(value: Any, fallback: tuple[int, int]) -> MillisecondRange:
    """Return a bounded range or the supplied safe fallback."""

    if not isinstance(value, dict):
        return MillisecondRange(*fallback)
    try:
        minimum = int(value.get("min", fallback[0]))
        maximum = int(value.get("max", fallback[1]))
    except (TypeError, ValueError):
        return MillisecondRange(*fallback)
    if minimum < 0 or maximum < minimum or maximum > _MAX_PHASE_MS:
        return MillisecondRange(*fallback)
    return MillisecondRange(minimum, maximum)


def proxy_resolver_profiles() -> tuple[ProxyResolverProfile, ...]:
    """Return the configured weighted resolver mixture."""

    configured = load_proxy_phase_profiles().get("resolver_mixture", [])
    profiles: list[ProxyResolverProfile] = []
    if isinstance(configured, list):
        for entry in configured:
            if not isinstance(entry, dict):
                continue
            name = str(entry.get("name", ""))
            if name not in {"resolver_cache_hit", "ordinary_lookup", "retry_queue"}:
                continue
            try:
                weight = float(entry.get("weight", 0))
            except (TypeError, ValueError):
                continue
            if weight <= 0:
                continue
            profiles.append(
                ProxyResolverProfile(
                    name=name,
                    weight=weight,
                    dns_completion_after_request_ms=(
                        _range(entry.get("dns_completion_after_request_ms"), (8, 120))
                        if name != "resolver_cache_hit"
                        else None
                    ),
                    origin_after_request_ms=(
                        _range(entry.get("origin_after_request_ms"), (5, 75))
                        if name == "resolver_cache_hit"
                        else None
                    ),
                    origin_after_dns_ms=(
                        _range(entry.get("origin_after_dns_ms"), (2, 35))
                        if name != "resolver_cache_hit"
                        else None
                    ),
                )
            )
    if profiles:
        return tuple(profiles)
    return (
        ProxyResolverProfile(
            "resolver_cache_hit",
            65.0,
            None,
            MillisecondRange(5, 75),
            None,
        ),
        ProxyResolverProfile(
            "ordinary_lookup",
            32.0,
            MillisecondRange(8, 120),
            None,
            MillisecondRange(2, 35),
        ),
        ProxyResolverProfile(
            "retry_queue",
            3.0,
            MillisecondRange(350, 2500),
            None,
            MillisecondRange(5, 80),
        ),
    )


def proxy_phase_timing() -> ProxyPhaseTiming:
    """Return validated shared phase timing ranges."""

    timing = load_proxy_phase_profiles().get("phase_timing", {})
    if not isinstance(timing, dict):
        timing = {}
    return ProxyPhaseTiming(
        request_after_connect_ms=_range(timing.get("request_after_connect_ms"), (1, 18)),
        inspected_request_after_connect_setup_ms=_range(
            timing.get("inspected_request_after_connect_setup_ms"),
            (10, 80),
        ),
        policy_decision_after_request_ms=_range(
            timing.get("policy_decision_after_request_ms"),
            (0, 4),
        ),
        tls_after_origin_connect_ms=_range(
            timing.get("tls_after_origin_connect_ms"),
            (18, 180),
        ),
        origin_service_ms=_range(timing.get("origin_service_ms"), (35, 650)),
        client_flush_after_response_ms=_range(
            timing.get("client_flush_after_response_ms"),
            (2, 80),
        ),
        terminal_response_after_decision_ms=_range(
            timing.get("terminal_response_after_decision_ms"),
            (5, 280),
        ),
        close_after_flush_ms=_range(timing.get("close_after_flush_ms"), (2, 120)),
        gateway_attempt_ms=_range(timing.get("gateway_attempt_ms"), (80, 1800)),
    )
