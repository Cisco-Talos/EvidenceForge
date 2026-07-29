# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Immutable canonical explicit-proxy transaction types."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Literal

ProxyResolverMode = Literal["resolver_cache_hit", "ordinary_lookup", "retry_queue"]
ProxyTerminalOutcome = Literal[
    "success",
    "cache_hit",
    "denied",
    "authentication_required",
    "gateway_failure",
]


@dataclass(frozen=True, slots=True)
class ProxyTransactionPlan:
    """Final phase and outcome truth for one explicit-proxy transaction."""

    stable_id: str
    terminal_outcome: ProxyTerminalOutcome
    resolver_mode: ProxyResolverMode | None
    client_connect_at: datetime
    tunnel_request_at: datetime | None
    request_at: datetime
    decision_at: datetime
    dns_query_at: datetime | None
    dns_response_at: datetime | None
    origin_connect_at: datetime | None
    tls_complete_at: datetime | None
    origin_request_at: datetime | None
    origin_response_at: datetime | None
    origin_close_at: datetime | None
    client_flush_at: datetime
    close_at: datetime
    origin_conn_state: str | None
    reused_transport: bool = False
    tunnel_setup_cs_bytes: int = 0
    tunnel_setup_sc_bytes: int = 0
    tunnel_setup_time_taken_ms: int = 0

    def __post_init__(self) -> None:
        """Validate conditional phase ordering and terminal semantics."""

        if not self.stable_id:
            raise ValueError("Proxy transaction stable_id cannot be empty")
        if self.request_at < self.client_connect_at:
            raise ValueError("Proxy request cannot precede the client connection")
        if self.tunnel_request_at is not None and not (
            self.client_connect_at <= self.tunnel_request_at <= self.request_at
        ):
            raise ValueError("Proxy tunnel request must fall between connect and request")
        if self.decision_at < self.request_at:
            raise ValueError("Proxy policy decision cannot precede the request")
        if self.client_flush_at < self.decision_at or self.close_at < self.client_flush_at:
            raise ValueError("Proxy response/close phases are out of order")
        dns_phases = (self.dns_query_at, self.dns_response_at)
        if (dns_phases[0] is None) != (dns_phases[1] is None):
            raise ValueError("Proxy DNS query and response phases must be paired")
        if self.dns_query_at is not None and not (
            self.decision_at <= self.dns_query_at <= self.dns_response_at
        ):
            raise ValueError("Proxy DNS phases are out of order")
        if self.resolver_mode == "resolver_cache_hit" and self.dns_query_at is not None:
            raise ValueError("Resolver cache hits cannot emit DNS phases")
        if self.resolver_mode in {"ordinary_lookup", "retry_queue"} and self.dns_query_at is None:
            raise ValueError("Resolver lookup paths require DNS phases")
        origin_phases = (
            self.origin_connect_at,
            self.origin_close_at,
            self.origin_conn_state,
        )
        if any(value is None for value in origin_phases) and any(
            value is not None for value in origin_phases
        ):
            raise ValueError("Proxy origin transport phases must be complete")
        if self.origin_connect_at is not None:
            origin_floor = self.dns_response_at or self.decision_at
            if self.origin_connect_at < origin_floor:
                raise ValueError("Proxy origin connection cannot precede resolution/decision")
            if self.origin_close_at is None or self.origin_close_at < self.origin_connect_at:
                raise ValueError("Proxy origin close cannot precede its connection")
        for phase in (self.tls_complete_at, self.origin_request_at, self.origin_response_at):
            if phase is not None and self.origin_connect_at is None:
                raise ValueError("Origin-dependent phases require an origin connection")
        ordered_origin = [
            phase
            for phase in (
                self.origin_connect_at,
                self.tls_complete_at,
                self.origin_request_at,
                self.origin_response_at,
                self.origin_close_at,
            )
            if phase is not None
        ]
        if any(
            later < earlier
            for earlier, later in zip(ordered_origin, ordered_origin[1:], strict=False)
        ):
            raise ValueError("Proxy origin phases are out of order")
        if self.terminal_outcome in {"cache_hit", "denied", "authentication_required"}:
            if self.resolver_mode is not None or self.origin_connect_at is not None:
                raise ValueError("Terminal proxy-only outcomes cannot contain origin activity")
        if self.reused_transport and (
            self.terminal_outcome != "success"
            or self.resolver_mode is not None
            or self.origin_connect_at is not None
        ):
            raise ValueError("Reused proxy transports cannot open another origin transport")
        if self.terminal_outcome == "gateway_failure" and self.origin_response_at is not None:
            raise ValueError("Gateway failures cannot claim an origin response")
        if (
            min(
                self.tunnel_setup_cs_bytes,
                self.tunnel_setup_sc_bytes,
                self.tunnel_setup_time_taken_ms,
            )
            < 0
        ):
            raise ValueError("Proxy tunnel setup accounting must be non-negative")

    @property
    def time_taken_ms(self) -> int:
        """Return proxy service time from request through client flush."""

        return max(1, round((self.client_flush_at - self.request_at).total_seconds() * 1000))

    @property
    def client_duration_seconds(self) -> float:
        """Return the complete client-to-proxy transport lifetime."""

        return max(0.000001, (self.close_at - self.client_connect_at).total_seconds())

    @property
    def origin_duration_seconds(self) -> float | None:
        """Return the attempted origin transport lifetime when present."""

        if self.origin_connect_at is None or self.origin_close_at is None:
            return None
        return max(0.000001, (self.origin_close_at - self.origin_connect_at).total_seconds())

    @property
    def dns_rtt_seconds(self) -> float | None:
        """Return the planned resolver RTT when DNS phases are present."""

        if self.dns_query_at is None or self.dns_response_at is None:
            return None
        return max(0.000001, (self.dns_response_at - self.dns_query_at).total_seconds())
