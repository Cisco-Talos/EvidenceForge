# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Shared ntp protocol planning helpers."""

from __future__ import annotations

import logging
import random
from datetime import datetime

from evidenceforge.generation.timing import (
    TimingRuntime,
)
from evidenceforge.utils.rng import _stable_seed

from .network import (
    _is_private_ip,
)
from .network_common import _activity_timing_planner

logger = logging.getLogger(__name__)

_NTP_STRATUM_TIMING = {
    1: (2.0, 0.5),  # GPS-connected
    2: (10.0, 0.7),  # synced to stratum 1
    3: (30.0, 0.8),  # synced to stratum 2
}


def _ntp_stratum_and_ref_id(dst_ip: str) -> tuple[int, str]:
    """Return stable NTP server metadata for a destination."""
    from evidenceforge.generation.activity.network_params import public_ntp_servers

    for server in public_ntp_servers():
        if server.get("ip") == dst_ip:
            stratum = int(server.get("stratum", 2))
            ref_id = str(server.get("ref_id", ".GPS."))
            return stratum, ref_id

    rng = random.Random(_stable_seed(f"ntp_server_profile:{dst_ip}"))
    if _is_private_ip(dst_ip):
        return rng.choice([2, 2, 3, 3, 4]), rng.choice(
            [
                server.get("ip")
                for server in public_ntp_servers()
                if isinstance(server.get("ip"), str) and server.get("ip") != dst_ip
            ]
            or ["129.6.15.28", "132.163.97.1", "132.163.96.1", "192.5.41.40"]
        )
    return rng.choice([1, 1, 2]), rng.choice([".GPS.", ".PPS.", ".GOES.", ".ACTS."])


def _ntp_parser_min_gap_seconds(poll_seconds: float) -> float:
    """Return the minimum plausible gap between successful parser observations."""
    return max(300.0, poll_seconds * 0.40)


def _ntp_payload_accounting(
    *,
    src_ip: str,
    dst_ip: str,
    time: datetime,
    conn_state: str | None,
    history: str | None,
    orig_bytes: int | None,
    resp_bytes: int | None,
    duration: float | None,
) -> tuple[int | None, int | None, float | None]:
    """Return source-native NTP UDP payload sizes for conn.log accounting."""
    rng = random.Random(
        _stable_seed(
            "ntp_payload_accounting:"
            f"{src_ip}:{dst_ip}:{time.isoformat()}:{conn_state or ''}:{history or ''}"
        )
    )
    request_datagrams = max(1, (history or "").count("D"))
    response_datagrams = (history or "").count("d") if (resp_bytes or 0) > 0 else 0

    def sample_payload_size() -> int:
        return int(
            rng.choices(
                (48, 48, 56, 64, 68, 76, 88, 96, 112, 120),
                weights=(34, 20, 14, 9, 7, 5, 4, 3, 2, 2),
                k=1,
            )[0]
        )

    normalized_orig = sum(sample_payload_size() for _ in range(request_datagrams))
    normalized_resp = (
        sum(sample_payload_size() for _ in range(response_datagrams))
        if conn_state not in {"S0", "REJ"} and response_datagrams > 0
        else 0
    )
    normalized_duration = duration
    if normalized_resp > 0 and (normalized_duration is None or normalized_duration > 0.25):
        normalized_duration = rng.uniform(0.003, 0.12)
    return normalized_orig, normalized_resp, normalized_duration


def _ntp_observed_response_fields(
    server_response: dict[str, float],
    *,
    dst_ip: str,
    event_time: datetime,
    timing_runtime: TimingRuntime | None = None,
) -> dict[str, float]:
    """Return NTP response fields with stable server traits and per-poll texture."""
    root_delay = float(server_response["root_delay"])
    root_disp = float(server_response["root_disp"])
    timing = _activity_timing_planner(timing_runtime)
    stable_id = f"ntp-response:{dst_ip}:{event_time.isoformat()}"
    observed_delay = timing.centered_seconds(
        relationship_key="activity.ntp.observed_root_delay",
        stable_id=stable_id,
        mean=root_delay,
        standard_deviation=max(0.00001, root_delay * 0.06),
        minimum=max(0.000001, root_delay * 0.91 - 0.00025),
        maximum=max(0.000003, root_delay * 1.12 + 0.00035),
        sample_key="root_delay",
    )
    observed_disp = timing.mixture_seconds(
        relationship_key="activity.ntp.observed_root_dispersion",
        stable_id=stable_id,
        components=(
            (
                0.82,
                max(0.000001, root_disp * 0.88 - 0.00015),
                max(0.000002, root_disp),
                max(0.000003, root_disp * 1.16 + 0.0004),
            ),
            (
                0.18,
                max(0.000001, root_disp * 0.95 + 0.00035),
                max(0.000002, root_disp * 1.08 + 0.0007),
                max(0.000003, root_disp * 1.20 + 0.0018),
            ),
        ),
        sample_key="root_dispersion",
    )
    return {
        "precision": float(server_response["precision"]),
        "root_delay": round(max(0.00025, observed_delay), 6),
        "root_disp": round(max(0.00025, observed_disp), 6),
    }


def _select_public_ntp_ip(src_ip: str, dst_ip: str, time: datetime) -> str | None:
    """Return a configured public NTP server IP for inferred public NTP traffic."""
    from evidenceforge.generation.activity.network_params import public_ntp_servers

    servers = [
        server
        for server in public_ntp_servers()
        if isinstance(server.get("ip"), str) and server["ip"]
    ]
    if not servers:
        return None
    rng = random.Random(
        _stable_seed(
            "public_ntp_destination:"
            f"{src_ip}:{dst_ip}:{time.replace(minute=0, second=0, microsecond=0).isoformat()}"
        )
    )
    weights = [
        max(0.1, float(server.get("weight", 1.0)))
        if isinstance(server.get("weight", 1.0), int | float)
        else 1.0
        for server in servers
    ]
    return str(rng.choices([server["ip"] for server in servers], weights=weights, k=1)[0])
