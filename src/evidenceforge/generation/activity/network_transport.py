# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Shared transport protocol planning helpers."""

from __future__ import annotations

import logging
import random

from evidenceforge.events.contexts import (
    NetworkTransactionDraft,
)
from evidenceforge.generation.baseline_timing import BaselineTimingPlanner
from evidenceforge.generation.source_timing import (
    SourceTimingPlanningRuntime,
)
from evidenceforge.generation.timing import (
    TimingRuntime,
)
from evidenceforge.models.exceptions import StateError

logger = logging.getLogger(__name__)

TCP_CONN_STATE_DISTRIBUTION = [
    # Normal completions (SF) — ~62% total (real: 55-75%)
    ("SF", 21, "ShADadfF"),  # Standard: SYN→SYN-ACK→data→FIN
    ("SF", 11, "ShADaDadfF"),  # Multiple data exchanges before FIN
    ("SF", 6, "ShADadTtFf"),  # Normal with retransmissions (T=orig retx, t=resp retx)
    ("SF", 5, "ShADadfFa"),  # FIN-ACK with trailing ACK
    ("SF", 5, "ShADaDaDadfF"),  # Bulk transfer (many data rounds)
    ("SF", 4, "ShADadFf"),  # Originator FIN first (client closes)
    ("SF", 4, "ShADaDadfFa"),  # Multi-exchange with trailing ACK
    ("SF", 3, "ShADadTFf"),  # Retransmit then FIN
    ("SF", 2, "ShADaDadFf"),  # Multi data then client closes
    ("SF", 1, "ShADaDaTtdfF"),  # Multi data with retransmissions
    # Connection attempts (S0) — ~14% (timeouts, unreachable hosts, scanning)
    ("S0", 9, "S"),  # Single SYN, no reply
    ("S0", 5, "S"),  # SYN retransmit (Zeek deduplicates to single 'S')
    # Partial handshakes (S1) — ~3%
    ("S1", 2, "Sh"),  # SYN-ACK seen, no termination observed
    ("S1", 1, "Sh"),  # SYN-ACK seen, no further data
    # Rejected connections (REJ) — ~5% (refused ports, firewall rejects)
    ("REJ", 3, "Sr"),  # RST from responder immediately
    ("REJ", 2, "Srr"),  # Multiple RSTs from responder
    # Reset by originator (RSTO) — ~8% (client aborts, load balancer health checks)
    ("RSTO", 4, "ShADaR"),  # Data exchange then originator RST
    ("RSTO", 2, "ShADadTR"),  # Data + retransmit then RST
    ("RSTO", 2, "ShAR"),  # Quick RST after handshake
    # Reset by responder (RSTR) — ~5% (server resets, IDS/WAF termination)
    ("RSTR", 3, "ShADadr"),  # Data exchange then responder RST
    ("RSTR", 2, "ShAdr"),  # Partial data then responder RST
    # Half-closed states — ~2% (one side closed, other didn't respond)
    ("S2", 1, "ShADadF"),  # Orig sent FIN, responder never replied
    ("S3", 1, "ShADadf"),  # Resp sent FIN, originator never replied
    # Midstream (OTH) — ~1% (partial captures, asymmetric routing, NAT state loss)
    ("OTH", 1, "DAd"),  # Midstream bidirectional data/ACK (handshake not observed)
]

UDP_CONN_STATE_DISTRIBUTION = [
    ("SF", 55, "Dd"),  # Normal bidirectional exchange (query + response)
    ("SF", 8, "DdDd"),  # Multi-packet exchange
    ("SF", 5, "DdDdDd"),  # Extended multi-packet exchange
    ("SF", 4, "DDd"),  # Retransmitted query before response
    ("S0", 12, "D"),  # Originator only, no response (timeout)
    ("S0", 6, "DD"),  # Retransmitted datagram, no response
    ("OTH", 6, "Dd"),  # Midstream UDP exchange
    ("OTH", 4, "DdDd"),  # Midstream multi-packet exchange
]

_TCP_CONN_ENTRIES = TCP_CONN_STATE_DISTRIBUTION

_TCP_CONN_WEIGHTS = [s[1] for s in TCP_CONN_STATE_DISTRIBUTION]

_TCP_SUCCESS_HISTORY_ENTRIES = [
    (history, weight) for conn_state, weight, history in _TCP_CONN_ENTRIES if conn_state == "SF"
]

_TCP_SUCCESS_HISTORY_WEIGHTS = [weight for _history, weight in _TCP_SUCCESS_HISTORY_ENTRIES]

_UDP_CONN_ENTRIES = UDP_CONN_STATE_DISTRIBUTION

_UDP_CONN_WEIGHTS = [s[1] for s in UDP_CONN_STATE_DISTRIBUTION]


def _tcp_success_history(rng: random.Random) -> str:
    """Choose a plausible Zeek history string for a completed TCP connection."""
    return rng.choices(
        [history for history, _weight in _TCP_SUCCESS_HISTORY_ENTRIES],
        weights=_TCP_SUCCESS_HISTORY_WEIGHTS,
        k=1,
    )[0]


_UDP_OVERHEAD_VALUES = (28, 32, 52, 60, 68)

_UDP_OVERHEAD_WEIGHTS = (93, 5, 1, 0.5, 0.5)

_TCP_OVERHEAD_VALUES = (40, 52, 60, 64)

_TCP_OVERHEAD_WEIGHTS = (10, 75, 10, 5)

_TCP_MSS_BYTES = 1460

_TCP_MSS_VALUES = (1200, 1320, 1360, 1448, 1460)

_TCP_MSS_WEIGHTS = (2, 4, 10, 22, 62)

_TCP_ACK_FLOOR_PAYLOAD_BYTES = 64 * 1024

_CLIENT_FIRST_TCP_PAYLOAD_SERVICES = frozenset(
    {
        "dce_rpc",
        "dns",
        "http",
        "https",
        "kerberos",
        "ldap",
        "ldaps",
        "mssql",
        "mysql",
        "postgresql",
        "rdp",
        "smb",
        "ssl",
        "tds",
        "winrm",
    }
)

_CLIENT_FIRST_TCP_PAYLOAD_PORTS = frozenset(
    {
        53,
        80,
        88,
        135,
        389,
        443,
        445,
        464,
        636,
        1433,
        3268,
        3269,
        3306,
        3389,
        5432,
        5985,
        5986,
        8080,
        8443,
    }
)


def _tcp_effective_mss_bytes(rng: random.Random) -> int:
    """Return a plausible effective TCP MSS for source packet accounting."""
    return rng.choices(_TCP_MSS_VALUES, weights=_TCP_MSS_WEIGHTS, k=1)[0]


def _tcp_payload_segment_count(
    payload_bytes: int | None,
    mss_bytes: int = _TCP_MSS_BYTES,
) -> int:
    """Return the minimum TCP payload segment count for Zeek packet accounting."""
    if payload_bytes is None or payload_bytes <= 0:
        return 0
    effective_mss = max(1, mss_bytes)
    return max(1, (payload_bytes + effective_mss - 1) // effective_mss)


def _tcp_payload_packet_count(payload_bytes: int | None, rng: random.Random) -> int:
    """Return source-visible TCP data packets with MSS and segmentation texture."""
    segments = _tcp_payload_segment_count(payload_bytes, _tcp_effective_mss_bytes(rng))
    if segments <= 0:
        return 0
    if segments >= 8:
        extra_fraction = rng.choices(
            (0.0, 0.001, 0.0025, 0.005, 0.01),
            weights=(35, 20, 20, 15, 10),
            k=1,
        )[0]
        if extra_fraction > 0:
            segments += max(1, int(round(segments * extra_fraction)))
        elif rng.random() < 0.35:
            segments += 1
    return segments


def _tcp_history_packet_counts(history: str | None) -> tuple[int, int, int, int]:
    """Return total and non-data packet markers by Zeek history side."""
    text = history or ""
    orig_total = sum(1 for char in text if char.isupper())
    resp_total = sum(1 for char in text if char.islower())
    orig_control = sum(1 for char in text if char.isupper() and char != "D")
    resp_control = sum(1 for char in text if char.islower() and char != "d")
    return orig_total, resp_total, orig_control, resp_control


def _tcp_packet_counts_from_payload_and_history(
    orig_bytes: int | None,
    resp_bytes: int | None,
    history: str | None,
    rng: random.Random,
) -> tuple[int, int]:
    """Return TCP packet counts including payload segments and visible control packets."""
    orig_total, resp_total, orig_control, resp_control = _tcp_history_packet_counts(history)
    orig_data = _tcp_payload_packet_count(orig_bytes, rng)
    resp_data = _tcp_payload_packet_count(resp_bytes, rng)

    orig_pkts = max(orig_total, orig_data + orig_control) if orig_data else orig_total
    resp_pkts = max(resp_total, resp_data + resp_control) if resp_data else resp_total
    return _apply_tcp_ack_packet_floors(orig_pkts, resp_pkts, orig_bytes, resp_bytes, rng)


def _tcp_payload_bytes_consistent_with_history(
    orig_bytes: int | None,
    resp_bytes: int | None,
    history: str | None,
) -> tuple[int | None, int | None]:
    """Return TCP payload byte counts that agree with Zeek history data markers."""
    if not history or history == "-":
        return orig_bytes, resp_bytes

    normalized_orig = orig_bytes
    normalized_resp = resp_bytes
    if (orig_bytes or 0) > 0 and "D" not in history:
        normalized_orig = 0
    if (resp_bytes or 0) > 0 and "d" not in history:
        normalized_resp = 0
    return normalized_orig, normalized_resp


def _tcp_service_requires_client_payload_first(service: str | None, dst_port: int) -> bool:
    """Return whether responder payload requires prior originator payload."""
    normalized_service = (service or "").strip().lower()
    return (
        normalized_service in _CLIENT_FIRST_TCP_PAYLOAD_SERVICES
        or dst_port in _CLIENT_FIRST_TCP_PAYLOAD_PORTS
    )


def _insert_originator_payload_before_responder_payload(history: str) -> str:
    """Add a Zeek originator data marker before the first responder data marker."""
    if "D" in history or "d" not in history:
        return history
    resp_index = history.index("d")
    if resp_index > 0 and history[resp_index - 1] == "A":
        return f"{history[:resp_index]}Da{history[resp_index:]}"
    return f"{history[:resp_index]}D{history[resp_index:]}"


def _client_first_originator_payload_floor(
    service: str | None,
    dst_port: int,
    rng: random.Random,
) -> int:
    """Return a plausible minimum request/client-hello payload for client-first TCP."""
    normalized_service = (service or "").strip().lower()
    if normalized_service in {"ssl", "https"} or dst_port in {443, 8443}:
        return rng.randint(180, 900)
    if normalized_service == "http" or dst_port in {80, 8080}:
        return rng.randint(120, 620)
    if normalized_service in {"smb", "ldap", "ldaps", "kerberos", "dce_rpc", "rdp", "winrm"}:
        return rng.randint(72, 420)
    if normalized_service in {"mssql", "mysql", "postgresql", "tds"} or dst_port in {
        1433,
        3306,
        5432,
    }:
        return rng.randint(64, 360)
    if normalized_service == "dns" or dst_port == 53:
        return rng.randint(40, 220)
    return rng.randint(72, 480)


def _enforce_client_first_tcp_payload_order(
    net: NetworkTransactionDraft, rng: random.Random
) -> bool:
    """Ensure client-first TCP responses have visible originator application payload."""
    if (
        net.protocol != "tcp"
        or net.conn_state in {"S0", "REJ", "S1", "SH", "SHR", "OTH"}
        or not _tcp_service_requires_client_payload_first(net.service, net.dst_port)
        or (net.resp_bytes or 0) <= 0
        or "d" not in (net.history or "")
    ):
        return False

    changed = False
    history = net.history or ""
    normalized_history = _insert_originator_payload_before_responder_payload(history)
    if normalized_history != history:
        net.history = normalized_history
        changed = True

    if (net.orig_bytes or 0) <= 0:
        net.orig_bytes = _client_first_originator_payload_floor(net.service, net.dst_port, rng)
        changed = True

    return changed


def _align_tcp_network_payload_with_history(
    net: NetworkTransactionDraft,
    rng: random.Random,
) -> bool:
    """Align TCP payload, packet, and IP-byte fields with Zeek history markers."""
    if net.protocol != "tcp":
        return False
    changed = _enforce_client_first_tcp_payload_order(net, rng)
    orig_bytes, resp_bytes = _tcp_payload_bytes_consistent_with_history(
        net.orig_bytes,
        net.resp_bytes,
        net.history,
    )
    if not changed and orig_bytes == net.orig_bytes and resp_bytes == net.resp_bytes:
        return False

    net.orig_bytes = orig_bytes
    net.resp_bytes = resp_bytes
    net.orig_pkts, net.resp_pkts = _tcp_packet_counts_from_payload_and_history(
        net.orig_bytes,
        net.resp_bytes,
        net.history,
        rng,
    )
    net.orig_ip_bytes = _tcp_ip_byte_count(net.orig_bytes, net.orig_pkts, rng)
    net.resp_ip_bytes = _tcp_ip_byte_count(net.resp_bytes, net.resp_pkts, rng)
    return True


def _preserve_explicit_tcp_payload_overrides(
    net: NetworkTransactionDraft,
    *,
    explicit_orig_bytes: int | None,
    explicit_resp_bytes: int | None,
    rng: random.Random,
) -> bool:
    """Re-apply explicit author payload intent after protocol shaping."""
    if net.protocol != "tcp" or net.conn_state != "SF":
        return False

    changed = False
    if explicit_orig_bytes is not None and explicit_orig_bytes > (net.orig_bytes or 0):
        net.orig_bytes = explicit_orig_bytes
        changed = True
    if explicit_resp_bytes is not None and explicit_resp_bytes > (net.resp_bytes or 0):
        net.resp_bytes = explicit_resp_bytes
        changed = True
    if not changed:
        return False

    net.orig_pkts, net.resp_pkts = _tcp_packet_counts_from_payload_and_history(
        net.orig_bytes,
        net.resp_bytes,
        net.history,
        rng,
    )
    net.orig_ip_bytes = _tcp_ip_byte_count(net.orig_bytes, net.orig_pkts, rng)
    net.resp_ip_bytes = _tcp_ip_byte_count(net.resp_bytes, net.resp_pkts, rng)
    return True


def _tcp_ip_byte_count(
    payload_bytes: int | None,
    packet_count: int,
    rng: random.Random,
    *,
    overhead_override: int | None = None,
) -> int:
    """Return MTU-bounded TCP IP-byte accounting with header texture."""
    if packet_count <= 0:
        return 0
    payload = payload_bytes or 0
    mtu_ceiling = packet_count * 1500
    if overhead_override is not None:
        return min(payload + packet_count * overhead_override, mtu_ceiling)
    overhead = rng.choices(_TCP_OVERHEAD_VALUES, weights=_TCP_OVERHEAD_WEIGHTS, k=1)[0]
    option_extra = 0
    if packet_count > 1:
        textured_packets = min(
            packet_count,
            8192,
            max(1, int(round(packet_count * rng.uniform(0.001, 0.018)))),
        )
        max_option_extra = packet_count * (max(_TCP_OVERHEAD_VALUES) - overhead)
        option_extra = min(max_option_extra, textured_packets * rng.choice((4, 8, 12)))
    return min(payload + packet_count * overhead + option_extra, mtu_ceiling)


def _tcp_ack_packet_floor(peer_payload_bytes: int | None, rng: random.Random) -> int:
    """Return a plausible ACK-only packet floor for a peer's large TCP payload."""
    segments = _tcp_payload_segment_count(peer_payload_bytes)
    if segments == 0 or (peer_payload_bytes or 0) < _TCP_ACK_FLOOR_PAYLOAD_BYTES:
        return 0
    ack_every_segments = rng.choices((2, 3, 4), weights=(70, 20, 10), k=1)[0]
    return max(16, (segments + ack_every_segments - 1) // ack_every_segments)


def _apply_tcp_ack_packet_floors(
    orig_pkts: int,
    resp_pkts: int,
    orig_bytes: int | None,
    resp_bytes: int | None,
    rng: random.Random,
) -> tuple[int, int]:
    """Ensure large one-way TCP transfers include plausible reverse ACK packets."""
    orig_ack_floor = _tcp_ack_packet_floor(resp_bytes, rng)
    resp_ack_floor = _tcp_ack_packet_floor(orig_bytes, rng)
    return max(orig_pkts, orig_ack_floor), max(resp_pkts, resp_ack_floor)


_AUTO_WEIRD_ENABLED = False  # weird.log realism is deferred; explicit contexts still render.


def _ephemeral_port(rng: random.Random, os_category: str = "windows") -> int:
    """Generate a random ephemeral port appropriate for the OS.

    Linux uses 32768-60999 (net.ipv4.ip_local_port_range default).
    Windows uses 49152-65535 (IANA dynamic port range).
    """
    if os_category == "linux":
        return rng.randint(32768, 60999)
    return rng.randint(49152, 65535)


def _icmp_echo_payload_size(rng: random.Random, requested: int | None) -> int:
    """Return a varied but source-native ICMP echo payload size."""
    common_sizes = [32, 48, 56, 64, 84, 120, 256, 512, 1024, 1200, 1472]
    weights = [8, 10, 18, 18, 10, 8, 7, 7, 5, 4, 5]
    if requested is not None and 32 <= requested <= 1472:
        return requested
    return rng.choices(common_sizes, weights=weights, k=1)[0]


def _icmp_echo_duration(
    rng: random.Random,
    requested: float | None,
    *,
    timing_runtime: TimingRuntime | SourceTimingPlanningRuntime | None = None,
    stable_id: str = "",
) -> float:
    """Return one runtime-owned ICMP RTT with the legacy mixture support."""
    del rng
    if type(timing_runtime) not in {TimingRuntime, SourceTimingPlanningRuntime}:
        raise StateError("ICMP echo duration requires an injected TimingRuntime")
    if type(stable_id) is not str or not stable_id:
        raise StateError("ICMP echo duration requires a stable connection identity")

    components: tuple[tuple[float, float, float, float], ...] = (
        (0.85, 0.001, 0.012, 0.045),
        (0.15, 0.045, 0.072, 0.145),
    )
    if requested is not None and 0.001 <= requested <= 0.15:
        components = (
            (0.65, requested, requested, requested),
            (0.35 * 0.85, 0.001, 0.012, 0.045),
            (0.35 * 0.15, 0.045, 0.072, 0.145),
        )
    return BaselineTimingPlanner(timing_runtime, source="activity").mixture_seconds(
        relationship_key="activity.icmp.echo_rtt",
        stable_id=stable_id,
        components=components,
        lifecycle_id=stable_id,
        sample_key="rtt",
    )
