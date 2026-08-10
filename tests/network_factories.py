"""Canonical network-plan factories for focused unit tests."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from evidenceforge.events.network import (
    DirectionalTrafficLedger,
    NetworkTrafficLedger,
    NetworkTransactionPlan,
)
from evidenceforge.utils.rng import stable_uuid

_DEFAULT_START = datetime(2024, 1, 1, tzinfo=UTC)


def network_plan(
    *,
    src_ip: str,
    src_port: int,
    dst_ip: str,
    dst_port: int,
    protocol: str,
    service: str = "",
    zeek_uid: str = "",
    conn_id: str = "",
    duration: float | None = None,
    source_visible_start_time: datetime | None = None,
    source_visible_close_time: datetime | None = None,
    orig_bytes: int | None = None,
    resp_bytes: int | None = None,
    orig_pkts: int = 0,
    resp_pkts: int = 0,
    orig_ip_bytes: int | None = None,
    resp_ip_bytes: int | None = None,
    conn_state: str = "",
    history: str = "",
    local_orig: bool = True,
    local_resp: bool = False,
    ip_proto: int | None = None,
    missed_bytes: int = 0,
    initiating_pid: int = -1,
    responding_pid: int = -1,
    link_local: bool = False,
    application_layer_only: bool = False,
) -> NetworkTransactionPlan:
    """Build immutable canonical network truth without a mutable compatibility context."""

    started_at = source_visible_start_time or _DEFAULT_START
    closed_at = source_visible_close_time
    if duration is None and closed_at is not None:
        duration = max(0.0, (closed_at - started_at).total_seconds())
    elif duration is not None and closed_at is None:
        closed_at = started_at + timedelta(seconds=max(0.0, duration))

    orig_payload = max(0, orig_bytes or 0)
    resp_payload = max(0, resp_bytes or 0)
    orig_ip_total = max(orig_payload, orig_ip_bytes or 0)
    resp_ip_total = max(resp_payload, resp_ip_bytes or 0)
    if protocol.lower() in {"tcp", "udp"}:
        orig_pkts = max(orig_pkts, (orig_ip_total + 1499) // 1500)
        resp_pkts = max(resp_pkts, (resp_ip_total + 1499) // 1500)
    else:
        if orig_ip_total and orig_pkts == 0:
            orig_pkts = 1
        if resp_ip_total and resp_pkts == 0:
            resp_pkts = 1
    traffic = NetworkTrafficLedger(
        orig=DirectionalTrafficLedger(orig_payload, max(0, orig_pkts), orig_ip_total),
        resp=DirectionalTrafficLedger(resp_payload, max(0, resp_pkts), resp_ip_total),
        missed_orig_bytes=max(0, missed_bytes),
    )
    phase_times = [("transport_start", started_at)]
    if closed_at is not None:
        phase_times.append(("transport_close", closed_at))
    outcome = "success" if conn_state in {"SF", "S1", "S2", "S3", "OTH", ""} else "failure"
    stable_id = stable_uuid(
        "test-network-transaction",
        src_ip,
        src_port,
        dst_ip,
        dst_port,
        protocol,
        zeek_uid,
        conn_id,
        started_at.isoformat(),
    )
    return NetworkTransactionPlan(
        stable_id=stable_id,
        hostname=dst_ip,
        outcome=outcome,
        phase_times=tuple(phase_times),
        started_at=started_at,
        closed_at=closed_at,
        src_ip=src_ip,
        src_port=src_port,
        dst_ip=dst_ip,
        dst_port=dst_port,
        protocol=protocol,
        service=service,
        zeek_uid=zeek_uid,
        conn_id=conn_id,
        duration=duration,
        conn_state=conn_state,
        history=history,
        traffic=traffic,
        initiating_pid=initiating_pid,
        responding_pid=responding_pid,
        local_orig=local_orig,
        local_resp=local_resp,
        ip_proto=(
            ip_proto
            if ip_proto is not None
            else 6
            if protocol.lower() == "tcp"
            else 17
            if protocol.lower() == "udp"
            else 1
        ),
        link_local=link_local,
        application_layer_only=application_layer_only,
    )
