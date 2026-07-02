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

"""Network connection action bundle."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Protocol

from evidenceforge.events.contexts import (
    DnsContext,
    EmailContext,
    FileTransferContext,
    FirewallContext,
    HttpContext,
    IdsContext,
    OcspContext,
    PeContext,
    ProxyContext,
    SmtpContext,
    SslContext,
    X509Context,
)
from evidenceforge.generation.actions.base import ActionAnchor
from evidenceforge.models.scenario import System
from evidenceforge.utils.rng import _stable_seed


def _context_fingerprint(value: object) -> str:
    """Return a compact deterministic fingerprint for optional context objects."""

    if value is None:
        return ""
    parts = []
    for name in (
        "query",
        "query_type",
        "signature_id",
        "signature",
        "method",
        "host",
        "uri",
        "fuid",
        "url",
        "action",
        "rule_id",
    ):
        if hasattr(value, name):
            parts.append(f"{name}={getattr(value, name)}")
    return "|".join(parts) if parts else value.__class__.__name__


@dataclass(frozen=True, slots=True)
class NetworkConnectionRequest:
    """Intent for one canonical network connection occurrence."""

    src_ip: str
    dst_ip: str
    time: datetime
    dst_port: int = 443
    proto: str = "tcp"
    service: str | None = None
    duration: float | None = None
    orig_bytes: int | None = None
    resp_bytes: int | None = None
    src_port: int | None = None
    emit_dns: bool = False
    pid: int = -1
    source_system: System | None = None
    conn_state: str | None = None
    dns: DnsContext | None = None
    email: EmailContext | None = None
    smtp: SmtpContext | None = None
    ssl: SslContext | None = None
    x509: X509Context | None = None
    x509_chain: list[X509Context] = field(default_factory=list)
    ids: IdsContext | None = None
    http: HttpContext | None = None
    file_transfer: FileTransferContext | None = None
    file_transfers: list[FileTransferContext] = field(default_factory=list)
    pe: PeContext | None = None
    ocsp: OcspContext | None = None
    proxy: ProxyContext | None = None
    firewall: FirewallContext | None = None
    hostname: str | None = None
    proxy_bypass: bool = False
    process_image: str | None = None
    preserve_dst_ip: bool = False
    preserve_http_outcome: bool = False
    suppress_application_side_effects: bool = False
    preserve_explicit_payload: bool = False
    packet_overhead_bytes: int | None = None
    responding_pid: int = -1
    source: str = "activity_generator"

    @property
    def stable_id(self) -> str:
        """Return a deterministic intent identifier for durable references."""

        source_hostname = self.source_system.hostname if self.source_system is not None else ""
        seed = _stable_seed(
            "action_bundle:network_connection:"
            f"{self.src_ip}:{self.dst_ip}:{self.time.isoformat()}:{self.dst_port}:"
            f"{self.proto}:{self.service or ''}:{self.duration or ''}:"
            f"{self.orig_bytes or ''}:{self.resp_bytes or ''}:{self.src_port or ''}:"
            f"{self.emit_dns}:{self.pid}:{source_hostname}:{self.conn_state or ''}:"
            f"{_context_fingerprint(self.dns)}:{_context_fingerprint(self.ssl)}:"
            f"{_context_fingerprint(self.ids)}:"
            f"{_context_fingerprint(self.http)}:{_context_fingerprint(self.file_transfer)}:"
            f"{_context_fingerprint(self.file_transfers)}:"
            f"{_context_fingerprint(self.pe)}:{_context_fingerprint(self.ocsp)}:"
            f"{_context_fingerprint(self.proxy)}:"
            f"{_context_fingerprint(self.firewall)}:{self.hostname or ''}:"
            f"{self.proxy_bypass}:{self.process_image or ''}:{self.preserve_dst_ip}:"
            f"{self.preserve_http_outcome}:{self.suppress_application_side_effects}:"
            f"{self.preserve_explicit_payload}:{self.packet_overhead_bytes or ''}:"
            f"{self.responding_pid}:{self.source}"
        )
        return f"network-connection-{seed:016x}"


class NetworkConnectionExecutor(Protocol):
    """Adapter protocol implemented by the current activity generator."""

    def _execute_network_connection_bundle(self, request: NetworkConnectionRequest) -> str:
        """Expand one network connection request into canonical evidence."""
        ...


class NetworkConnectionActionBundle:
    """Expand one network connection into cross-source connection evidence."""

    def __init__(
        self,
        executor: NetworkConnectionExecutor,
        request: NetworkConnectionRequest,
    ) -> None:
        self._executor = executor
        self._request = request

    @property
    def anchor(self) -> ActionAnchor:
        """Return the stable action anchor."""

        return ActionAnchor(
            family="network_connection",
            stable_id=self._request.stable_id,
            source=self._request.source,
        )

    def execute(self) -> str:
        """Emit network, source endpoint, proxy, DNS/TLS/HTTP, and firewall evidence."""

        return self._executor._execute_network_connection_bundle(self._request)
