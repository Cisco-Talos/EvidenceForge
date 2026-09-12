# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Shared common protocol planning helpers."""

from __future__ import annotations

import ipaddress
import logging
import random
import shlex
from datetime import datetime
from typing import Any

from evidenceforge.generation.activity.timing_profiles import (
    get_timing_window as _activity_get_timing_window,
)
from evidenceforge.generation.baseline_timing import BaselineTimingPlanner
from evidenceforge.generation.source_timing import (
    SourceTimingPlanningRuntime,
)
from evidenceforge.generation.timing import (
    TimingRuntime,
)
from evidenceforge.utils.rng import _stable_seed

from .network import (
    _get_http_status as _network_get_http_status,
)
from .network import (
    _is_invalid_network_connection as _network_is_invalid_connection,
)
from .network import (
    _is_private_ip,
)

logger = logging.getLogger(__name__)

get_timing_window = _activity_get_timing_window

_get_http_status = _network_get_http_status

_is_invalid_network_connection = _network_is_invalid_connection


def _is_modeled_local_ip(executor: Any, ip: str) -> bool:
    """Return whether an IP belongs to the modeled organization/network."""
    if hasattr(executor, "_ip_to_system") and ip in executor._ip_to_system:
        return True
    environment = getattr(executor, "_scenario_environment", None)
    network = getattr(environment, "network", None)
    try:
        address = ipaddress.ip_address(ip)
    except ValueError:
        return False
    if network is not None:
        for segment in getattr(network, "segments", []) or []:
            if getattr(segment, "exposure", "internal") not in {"internal", "both"}:
                continue
            try:
                if address in ipaddress.ip_network(segment.cidr, strict=False):
                    return True
            except ValueError:
                continue
        for rule in getattr(network, "nat_rules", []) or []:
            if ip in {
                str(getattr(rule, "mapped_ip", "") or ""),
                str(getattr(rule, "real_ip", "") or ""),
            }:
                return True
    dispatcher = getattr(executor, "dispatcher", None)
    visibility = getattr(dispatcher, "visibility_engine", None)
    if visibility is not None:
        resolve_segments = getattr(visibility, "_resolve_ip_segments", None)
        if callable(resolve_segments) and resolve_segments(ip):
            return True
        vip_to_real = getattr(visibility, "_vip_to_real_ip", {})
        if ip in vip_to_real or ip in set(vip_to_real.values()):
            return True
    if network is None and visibility is None:
        return _is_private_ip(ip)
    return False


def _command_tokens(command_line: str) -> list[str]:
    """Split a process command line enough to recover network target arguments."""
    try:
        tokens = shlex.split(command_line, posix=False)
    except ValueError:
        tokens = command_line.split()
    return [token.strip().strip("'\"") for token in tokens if token.strip().strip("'\"")]


def _extract_ssh_attempted_username(command_line: str) -> str | None:
    """Extract the username a source-native SSH client command attempted."""

    tokens = _command_tokens(command_line)
    if not tokens:
        return None
    option_args = {
        "-b",
        "-c",
        "-e",
        "-f",
        "-i",
        "-j",
        "-l",
        "-m",
        "-o",
        "-p",
        "-s",
        "-w",
    }
    skip_next = False
    for idx, token in enumerate(tokens[1:], start=1):
        lower = token.lower()
        if skip_next:
            skip_next = False
            continue
        if lower == "-l" and idx + 1 < len(tokens):
            candidate = tokens[idx + 1].strip()
            return candidate or None
        if lower.startswith("-l") and len(token) > 2:
            candidate = token[2:].strip()
            return candidate or None
        if lower in option_args:
            skip_next = True
            continue
        if lower.startswith("-"):
            continue
        if "@" not in token:
            continue
        candidate = token.rsplit("@", 1)[0].rsplit("\\", 1)[-1].strip()
        return candidate or None
    return None


def _zeek_conn_observation_time(
    base_time: datetime,
    src_ip: str,
    src_port: int,
    dst_ip: str,
    dst_port: int,
    proto: str,
    service: str,
    *,
    timing_runtime: TimingRuntime | SourceTimingPlanningRuntime | None = None,
) -> datetime:
    """Return runtime-owned canonical spacing for one exact transport tuple."""

    relationship_key = "network.connection_start_jitter"
    window = _activity_get_timing_window(
        relationship_key,
        default_min_ms=0,
        default_max_ms=0,
        default_position="after",
    )
    stable_id = (
        f"network-connection-start:{src_ip}:{src_port}:{dst_ip}:{dst_port}:"
        f"{proto}:{service}:{base_time.isoformat()}"
    )
    runtime = timing_runtime or TimingRuntime.compatibility_default()
    planner = BaselineTimingPlanner(runtime, source="network")
    return base_time + planner.packet_observation_delta(
        relationship_key=relationship_key,
        stable_id=stable_id,
        minimum_ms=window.min_ms,
        maximum_ms=window.max_ms,
        host=src_ip,
        lifecycle_id=stable_id,
        sample_key="transport_open",
    )


def _activity_timing_planner(timing_runtime: TimingRuntime | None) -> BaselineTimingPlanner:
    """Return the engine planner or an isolated direct-helper adapter."""

    runtime = timing_runtime if isinstance(timing_runtime, TimingRuntime) else None
    return BaselineTimingPlanner(
        runtime or TimingRuntime.compatibility_default(),
        source="activity",
    )


def _activity_timing_stable_id(
    family: str,
    *parts: object,
    rng: random.Random | None = None,
) -> str:
    """Return a stable compatibility scope without continuous RNG timing draws."""

    state_token = ""
    if rng is not None:
        state = rng.getstate()[1]
        adapter_ordinal = int(getattr(rng, "_eforge_activity_timing_ordinal", 0))
        rng._eforge_activity_timing_ordinal = adapter_ordinal + 1  # type: ignore[attr-defined]
        state_token = (
            f"{_stable_seed(':'.join(str(value) for value in state[:8]))}:{adapter_ordinal}"
        )
    return ":".join((family, *(str(part) for part in parts), state_token))
