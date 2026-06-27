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

"""Explicit forward-proxy transaction action bundle."""

from __future__ import annotations

import random
from dataclasses import dataclass, replace
from datetime import datetime, timedelta
from typing import Protocol

from evidenceforge.events.contexts import (
    DnsContext,
    FileTransferContext,
    FirewallContext,
    HttpContext,
    IdsContext,
    OcspContext,
    PeContext,
    ProxyContext,
)
from evidenceforge.generation.actions.base import ActionAnchor
from evidenceforge.generation.actions.file_transfer import (
    HttpResponseFileTransferActionBundle,
    HttpResponseFileTransferRequest,
)
from evidenceforge.generation.activity.helpers import _get_rng
from evidenceforge.generation.activity.network_params import proxy_connect_status_message
from evidenceforge.generation.activity.timing_profiles import get_timing_window
from evidenceforge.generation.state_manager import StateManager
from evidenceforge.generation.timing import TemporalConstraintGraph
from evidenceforge.models.scenario import System
from evidenceforge.utils.rng import _stable_seed

_PROXY_HTTP_FILE_TRANSFER_MIME_TYPES = frozenset(
    {
        "application/octet-stream",
        "application/pdf",
        "application/vnd.debian.binary-package",
        "application/vnd.ms-cab-compressed",
        "application/x-gzip",
        "application/x-ms-patch",
        "application/x-msi",
        "application/x-msdownload",
        "application/zip",
    }
)
_PROXY_HTTP_FILE_TRANSFER_BODY_THRESHOLD = 64 * 1024
_PROXY_HTTP_FILE_TRANSFER_LARGE_BODY_THRESHOLD = 1_000_000


@dataclass(frozen=True, slots=True)
class ProxyTransactionRequest:
    """Intent for one explicit forward-proxy transaction."""

    src_ip: str
    dst_ip: str
    time: datetime
    dst_port: int
    proto: str
    service: str | None
    duration: float | None
    orig_bytes: int | None
    resp_bytes: int | None
    src_port: int | None
    pid: int
    source_system: System | None
    conn_state: str | None
    dns: DnsContext | None
    ids: IdsContext | None
    http: HttpContext | None
    file_transfer: FileTransferContext | None
    ocsp: OcspContext | None
    proxy: ProxyContext | None
    firewall: FirewallContext | None
    hostname: str | None
    process_image: str | None
    proxy_chain: list[System]
    preserve_explicit_proxy_dst_ip: bool
    caller_provided_conn_state: bool
    ad_domain: str
    source: str = "activity_generator"

    @property
    def stable_id(self) -> str:
        """Return a deterministic intent identifier for durable references."""

        proxy_host = self.proxy_chain[0].hostname if self.proxy_chain else ""
        seed = _stable_seed(
            "action_bundle:proxy_transaction:"
            f"{self.src_ip}:{self.src_port or ''}:{proxy_host}:"
            f"{self.dst_ip}:{self.dst_port}:{self.proto}:{self.service or ''}:"
            f"{self.hostname or ''}:{self.pid}:{self.duration or ''}:"
            f"{self.orig_bytes or ''}:{self.resp_bytes or ''}:"
            f"{self.conn_state or ''}:{self.time.isoformat()}:{self.source}"
        )
        return f"proxy-transaction-{seed:016x}"


class ProxyTransactionExecutor(Protocol):
    """Runtime hooks supplied by the current activity generator."""

    state_manager: StateManager
    _explicit_proxy_tunnels: dict[tuple[str, str, str, str, int, str], tuple[datetime, str]]

    def _build_proxy_context(
        self,
        *,
        src_ip: str,
        dst_ip: str,
        dst_port: int,
        service: str | None,
        duration: float | None,
        orig_bytes: int | None,
        resp_bytes: int | None,
        hostname: str | None,
        source_system: System | None,
        proxy_sys: System,
        http: HttpContext | None,
        explicit_mode: bool = False,
    ) -> ProxyContext:
        """Build proxy context for a logical origin request."""
        ...

    def _proxy_fqdn(self, proxy_sys: System) -> str:
        """Return the FQDN used for proxy access logs."""
        ...

    def _caller_explicit_proxy_process_image(
        self,
        *,
        source_system: System | None,
        pid: int,
        process_image: str | None,
        time: datetime,
        proxy_context: ProxyContext,
        proxy_sys: System,
        dst_port: int,
    ) -> str | None:
        """Return a caller process image when valid proxy client telemetry owns it."""
        ...

    def _ensure_explicit_proxy_client_process(
        self,
        *,
        source_system: System | None,
        time: datetime,
        proxy_context: ProxyContext,
        proxy_sys: System,
        dst_port: int,
    ) -> tuple[int, str]:
        """Create or reuse a source-native proxy client process."""
        ...

    def _allocate_ephemeral_port(
        self,
        src_ip: str,
        dst_ip: str,
        dst_port: int,
        proto: str,
        time: datetime,
        os_category: str,
    ) -> int:
        """Allocate a source port for a connection tuple."""
        ...

    def _os_for_ip(self, ip: str) -> str:
        """Return an OS category for a source IP."""
        ...

    def _clamp_after_visible_process_create(
        self,
        source_system: System,
        pid: int,
        event_time: datetime,
        source_key: str,
    ) -> datetime:
        """Move an event after the visible process-create timestamp when needed."""
        ...

    def _emit_dns_lookup(
        self,
        src_ip: str,
        dst_ip: str,
        time: datetime,
        *,
        hostname: str | None = None,
        force_address: bool = False,
        bypass_cache: bool = False,
    ) -> None:
        """Emit correlated DNS evidence."""
        ...

    def generate_connection(
        self,
        *,
        src_ip: str,
        dst_ip: str,
        time: datetime,
        dst_port: int = 443,
        proto: str = "tcp",
        service: str | None = None,
        duration: float | None = None,
        orig_bytes: int | None = None,
        resp_bytes: int | None = None,
        src_port: int | None = None,
        emit_dns: bool = False,
        pid: int = -1,
        source_system: System | None = None,
        conn_state: str | None = None,
        dns: DnsContext | None = None,
        ids: IdsContext | None = None,
        http: HttpContext | None = None,
        file_transfer: FileTransferContext | None = None,
        pe: PeContext | None = None,
        ocsp: OcspContext | None = None,
        proxy: ProxyContext | None = None,
        firewall: FirewallContext | None = None,
        hostname: str | None = None,
        proxy_bypass: bool = False,
        preserve_http_outcome: bool = False,
        process_image: str | None = None,
    ) -> str:
        """Generate a canonical connection event."""
        ...


@dataclass(frozen=True, slots=True)
class ProxyTransactionActionBundle:
    """Action bundle for one explicit forward-proxy transaction."""

    request: ProxyTransactionRequest
    executor: ProxyTransactionExecutor

    @property
    def anchor(self) -> ActionAnchor:
        """Return the stable action anchor for this proxy transaction."""

        return ActionAnchor(
            family="proxy_transaction",
            stable_id=self.request.stable_id,
            source=self.request.source,
        )

    def execute(self) -> str:
        """Expand and dispatch explicit proxy client and origin evidence."""

        # Import lazily to avoid a module-load cycle with ActivityGenerator.
        from evidenceforge.generation.activity import generator as generator_utils
        from evidenceforge.generation.activity.dns_registry import resolve_domain_ip

        request = self.request
        executor = self.executor
        proxy_sys = request.proxy_chain[0]
        listener_port = int(getattr(executor, "_proxy_listener_port", 8080))
        dst_ip = request.dst_ip
        src_port = request.src_port

        proxy_context = request.proxy or executor._build_proxy_context(
            src_ip=request.src_ip,
            dst_ip=dst_ip,
            dst_port=request.dst_port,
            service=request.service,
            duration=request.duration,
            orig_bytes=request.orig_bytes,
            resp_bytes=request.resp_bytes,
            hostname=request.hostname,
            source_system=request.source_system,
            proxy_sys=proxy_sys,
            http=request.http,
            explicit_mode=True,
        )
        tunnel_key = (
            request.src_ip,
            proxy_sys.ip,
            proxy_context.host,
            dst_ip,
            request.dst_port,
            " ".join((proxy_context.user_agent or "").lower().split()),
        )
        reuse_safe = (
            request.dst_port == 443
            and request.http is not None
            and request.dns is None
            and request.ids is None
            and request.firewall is None
            and request.proxy is None
            and proxy_context.status_code < 400
        )
        if reuse_safe:
            active_tunnel = executor._explicit_proxy_tunnels.get(tunnel_key)
            if active_tunnel is not None:
                last_activity, cached_uid = active_tunnel
                elapsed = (request.time - last_activity).total_seconds()
                if 0 <= elapsed < generator_utils._EXPLICIT_PROXY_TUNNEL_TIMEOUT_S:
                    executor._explicit_proxy_tunnels[tunnel_key] = (request.time, cached_uid)
                    return cached_uid

        client_http = self._build_client_http(proxy_context)
        if proxy_context.method == "CONNECT" and proxy_context.status_code >= 400:
            self._shape_failed_connect(proxy_context, client_http)
        if proxy_context.status_code < 400 and client_http.response_body_len > 0:
            proxy_context.sc_bytes = max(
                proxy_context.sc_bytes,
                client_http.response_body_len + generator_utils._PROXY_SC_OVERHEAD[0],
            )

        if (
            proxy_context.host
            and "." in proxy_context.host
            and not generator_utils._is_ip_literal(proxy_context.host)
            and not proxy_context.host.endswith(f".{request.ad_domain}")
            and not proxy_context.host.endswith(".local")
            and not request.preserve_explicit_proxy_dst_ip
        ):
            resolver = getattr(executor, "_network_resolver", None)
            if resolver is not None:
                resolved = resolver.resolve_host(proxy_context.host, src_host=proxy_sys.hostname)
                dst_ip = resolved.ip or dst_ip
            else:
                dst_ip = resolve_domain_ip(proxy_context.host, src_host=proxy_sys.hostname)

        client_orig_bytes = max(1, proxy_context.cs_bytes or request.orig_bytes or 1)
        client_resp_bytes = max(0, proxy_context.sc_bytes or 0)
        will_emit_egress = proxy_context.status_code < 400 and proxy_context.cache_result != "HIT"
        egress_delay = (
            self._egress_delay(dst_ip, proxy_context=proxy_context)
            if will_emit_egress
            else timedelta(0)
        )
        client_pid, client_process_image = self._resolve_client_process(proxy_context, proxy_sys)

        if src_port is None:
            src_port = executor._allocate_ephemeral_port(
                request.src_ip,
                proxy_sys.ip,
                listener_port,
                "tcp",
                request.time,
                executor._os_for_ip(request.src_ip),
            )

        client_time = request.time
        if client_pid > 0 and request.source_system is not None:
            client_time = executor._clamp_after_visible_process_create(
                request.source_system,
                client_pid,
                client_time,
                "source.windows_wfp_connection",
            )

        egress_time = self._resolve_egress_time(
            client_time=client_time,
            src_port=src_port,
            proxy_sys=proxy_sys,
            listener_port=listener_port,
            egress_delay=egress_delay,
            will_emit_egress=will_emit_egress,
            generator_utils=generator_utils,
        )

        (
            client_duration,
            egress_duration,
            client_orig_bytes,
            client_resp_bytes,
        ) = self._resolve_durations_and_sizes(
            dst_ip=dst_ip,
            proxy_context=proxy_context,
            client_orig_bytes=client_orig_bytes,
            client_resp_bytes=client_resp_bytes,
            client_time=client_time,
            egress_time=egress_time,
            will_emit_egress=will_emit_egress,
            generator_utils=generator_utils,
        )

        proxy_terminal_failures = {"DENIED", "AUTH_REQUIRED", "GATEWAY_ERROR"}
        will_emit_origin_transaction = (
            proxy_context.cache_result not in proxy_terminal_failures
            and proxy_context.cache_result != "HIT"
        )
        egress_http = (
            self._build_egress_http(proxy_context, client_http)
            if will_emit_origin_transaction
            else None
        )
        client_file_transfer: FileTransferContext | None = None
        client_pe: PeContext | None = None
        egress_file_transfer = request.file_transfer
        egress_pe: PeContext | None = None
        if egress_http is not None and request.file_transfer is None:
            (
                client_file_transfer,
                client_pe,
                egress_file_transfer,
                egress_pe,
                client_duration,
                egress_duration,
            ) = self._build_proxied_http_file_transfer_pair(
                client_http=client_http,
                egress_http=egress_http,
                client_time=client_time,
                egress_time=egress_time,
                client_duration=client_duration,
                egress_duration=egress_duration,
                client_dst_ip=proxy_sys.ip,
                egress_dst_ip=dst_ip,
                proxy_context=proxy_context,
                generator_utils=generator_utils,
            )

        client_uid = executor.generate_connection(
            src_ip=request.src_ip,
            dst_ip=proxy_sys.ip,
            time=client_time,
            dst_port=listener_port,
            proto="tcp",
            service="http",
            duration=client_duration,
            orig_bytes=client_orig_bytes,
            resp_bytes=client_resp_bytes,
            src_port=src_port,
            emit_dns=False,
            pid=client_pid,
            source_system=request.source_system,
            conn_state=request.conn_state or "SF",
            http=client_http,
            file_transfer=client_file_transfer,
            pe=client_pe,
            proxy=proxy_context,
            hostname=executor._proxy_fqdn(proxy_sys),
            proxy_bypass=True,
            preserve_http_outcome=True,
            process_image=client_process_image,
        )

        if (
            proxy_context.cache_result in proxy_terminal_failures
            or proxy_context.cache_result == "HIT"
        ):
            return client_uid

        egress_resp_bytes = request.resp_bytes
        if egress_http is not None:
            egress_resp_bytes = max(request.resp_bytes or 0, egress_http.response_body_len)
        if (
            request.dst_port == 443
            and request.http is not None
            and proxy_context.cache_result == "MISS"
        ):
            egress_resp_bytes = max(request.resp_bytes or 0, request.http.response_body_len)
        if proxy_context.host:
            executor._emit_dns_lookup(
                proxy_sys.ip,
                dst_ip,
                egress_time,
                hostname=proxy_context.host,
                force_address=True,
            )

        egress_conn_state = request.conn_state
        if not request.caller_provided_conn_state and proxy_context.status_code < 400:
            egress_conn_state = "SF"
        executor.generate_connection(
            src_ip=proxy_sys.ip,
            dst_ip=dst_ip,
            time=egress_time,
            dst_port=request.dst_port,
            proto=request.proto,
            service=request.service,
            duration=egress_duration,
            orig_bytes=request.orig_bytes,
            resp_bytes=egress_resp_bytes,
            emit_dns=False,
            pid=-1,
            source_system=proxy_sys,
            conn_state=egress_conn_state,
            dns=request.dns,
            ids=request.ids,
            http=egress_http,
            file_transfer=egress_file_transfer,
            pe=egress_pe,
            ocsp=request.ocsp,
            firewall=request.firewall,
            hostname=proxy_context.host,
            proxy_bypass=True,
            preserve_http_outcome=True,
        )
        if request.dst_port == 443:
            executor._explicit_proxy_tunnels[tunnel_key] = (client_time, client_uid)
        return client_uid

    def _build_client_http(self, proxy_context: ProxyContext) -> HttpContext:
        """Build the client-to-proxy HTTP context."""

        from evidenceforge.generation.activity import generator as generator_utils

        request = self.request
        if request.dst_port == 443:
            tunnel_status_code = proxy_context.tunnel_status_code
            if tunnel_status_code is None:
                tunnel_status_code = proxy_context.status_code
            return HttpContext(
                method="CONNECT",
                host=proxy_context.host,
                uri=f"{proxy_context.host}:443",
                version="1.1",
                user_agent=proxy_context.user_agent,
                request_body_len=0,
                response_body_len=0,
                status_code=tunnel_status_code,
                status_msg=proxy_connect_status_message(
                    tunnel_status_code,
                    proxy_context.host,
                    proxy_context.user_agent,
                    request.time,
                ),
                tags=[],
            )

        if request.http is not None:
            from evidenceforge.generation.activity.http_content import (
                response_mime_types_for_status,
            )

            status_messages = {
                200: "OK",
                301: "Moved Permanently",
                302: "Found",
                304: "Not Modified",
                403: "Forbidden",
                407: "Proxy Authentication Required",
                500: "Internal Server Error",
                502: "Bad Gateway",
                503: "Service Unavailable",
                504: "Gateway Timeout",
            }
            response_body_len = generator_utils._proxy_http_response_body_len(
                proxy_context,
                resp_bytes=request.resp_bytes,
                http=request.http,
            )
            return HttpContext(
                method=request.http.method,
                host=proxy_context.host,
                uri=proxy_context.url,
                version=request.http.version,
                user_agent=request.http.user_agent,
                request_body_len=request.http.request_body_len,
                response_body_len=response_body_len,
                flow_request_body_len=request.http.flow_request_body_len,
                flow_response_body_len=request.http.flow_response_body_len,
                flow_transaction_count=request.http.flow_transaction_count,
                status_code=proxy_context.status_code,
                status_msg=status_messages.get(proxy_context.status_code, request.http.status_msg),
                referrer=request.http.referrer,
                trans_depth=request.http.trans_depth,
                tags=list(request.http.tags),
                resp_mime_types=response_mime_types_for_status(
                    proxy_context.status_code,
                    proxy_context.content_type
                    or (request.http.resp_mime_types[0] if request.http.resp_mime_types else ""),
                    response_body_len,
                    method=request.http.method,
                ),
            )

        request_body_len = 0
        if proxy_context.method not in ("GET", "HEAD", "CONNECT", "OPTIONS"):
            request_body_len = proxy_context.cs_bytes
        return HttpContext(
            method=proxy_context.method,
            host=proxy_context.host,
            uri=proxy_context.url,
            version="1.1",
            user_agent=proxy_context.user_agent,
            request_body_len=request_body_len,
            response_body_len=generator_utils._proxy_http_response_body_len(
                proxy_context,
                resp_bytes=request.resp_bytes,
            ),
            status_code=proxy_context.status_code,
            status_msg="OK" if proxy_context.status_code == 200 else "Forbidden",
            referrer=proxy_context.referrer,
            tags=[],
            resp_mime_types=[proxy_context.content_type] if proxy_context.content_type else [],
        )

    def _shape_failed_connect(
        self,
        proxy_context: ProxyContext,
        client_http: HttpContext,
    ) -> None:
        """Apply source-native byte/status shape for failed CONNECT requests."""

        rng = _get_rng()
        host_len = len(proxy_context.host or "")
        proxy_context.cs_bytes = rng.randint(180 + host_len, 520 + host_len)
        proxy_context.sc_bytes = rng.randint(250, 2000)
        proxy_context.time_taken = rng.randint(20, 1500)
        proxy_context.tunnel_status_code = proxy_context.status_code
        client_http.status_code = proxy_context.status_code
        client_http.status_msg = proxy_connect_status_message(
            proxy_context.status_code,
            proxy_context.host,
            proxy_context.user_agent,
            self.request.time,
        )
        from evidenceforge.generation.activity import generator as generator_utils

        client_http.response_body_len = generator_utils._proxy_http_response_body_len(
            proxy_context,
            resp_bytes=self.request.resp_bytes,
        )
        client_http.resp_mime_types = (
            [proxy_context.content_type] if proxy_context.content_type else []
        )

    def _egress_delay(self, dst_ip: str, *, proxy_context: ProxyContext) -> timedelta:
        """Return the deterministic delay between client proxy request and egress."""

        request = self.request
        proxy_delay_window = get_timing_window(
            "network.proxy_upstream_after_client",
            default_min_ms=950,
            default_max_ms=1800,
            default_position="after",
            default_class="causal_prerequisite",
        )
        rng = random.Random(
            _stable_seed(
                "proxy_egress_delay:"
                f"{request.src_ip}:{dst_ip}:{request.dst_port}:{proxy_context.host}:"
                f"{request.time.timestamp()}:{proxy_context.cache_result}"
            )
        )
        base_ms = rng.randint(proxy_delay_window.min_ms, proxy_delay_window.max_ms)
        if proxy_context.cache_result in {"MISS", "REVALIDATED", "NONE"}:
            dns_component_ms = rng.randint(150, 2400)
            tcp_tls_component_ms = rng.randint(80, 2600 if request.dst_port == 443 else 900)
            retry_component_ms = rng.choice([0, 0, 0, 0, rng.randint(1200, 8500)])
            base_ms += dns_component_ms + tcp_tls_component_ms + retry_component_ms
        return timedelta(milliseconds=base_ms)

    def _resolve_client_process(
        self,
        proxy_context: ProxyContext,
        proxy_sys: System,
    ) -> tuple[int, str | None]:
        """Resolve or materialize the client-side process that owns the proxy socket."""

        request = self.request
        executor = self.executor
        client_pid = request.pid
        client_process_image = request.process_image
        caller_process_image = executor._caller_explicit_proxy_process_image(
            source_system=request.source_system,
            pid=request.pid,
            process_image=request.process_image,
            time=request.time,
            proxy_context=proxy_context,
            proxy_sys=proxy_sys,
            dst_port=request.dst_port,
        )
        if caller_process_image is not None:
            client_process_image = caller_process_image
            if request.source_system is not None:
                executor.state_manager.update_process_activity_time(
                    request.source_system.hostname,
                    request.pid,
                    request.time,
                )
        else:
            client_pid = -1
            client_process_image = None
            owned_client_pid, owned_process_image = executor._ensure_explicit_proxy_client_process(
                source_system=request.source_system,
                time=request.time,
                proxy_context=proxy_context,
                proxy_sys=proxy_sys,
                dst_port=request.dst_port,
            )
            if owned_client_pid > 0:
                client_pid = owned_client_pid
                client_process_image = owned_process_image
        return client_pid, client_process_image

    def _resolve_egress_time(
        self,
        *,
        client_time: datetime,
        src_port: int,
        proxy_sys: System,
        listener_port: int,
        egress_delay: timedelta,
        will_emit_egress: bool,
        generator_utils: object,
    ) -> datetime:
        """Resolve proxy-origin egress time through the temporal graph."""

        request = self.request
        egress_time = request.time + egress_delay
        if not will_emit_egress:
            return egress_time

        client_observed_time = generator_utils._zeek_conn_observation_time(
            client_time,
            request.src_ip,
            src_port,
            proxy_sys.ip,
            listener_port,
            "tcp",
            "http",
        )
        connect_window = get_timing_window(
            "source.zeek_http_request",
            default_min_ms=1,
            default_max_ms=450,
            default_position="after",
            default_class="same_observation",
        )
        client_connect_visible_by = client_observed_time + timedelta(
            milliseconds=connect_window.max_ms + 1
        )
        proxy_graph = TemporalConstraintGraph()
        proxy_graph.add_node("client_connection", client_time)
        proxy_graph.add_node("client_proxy_request_visible", client_connect_visible_by)
        proxy_graph.add_node("origin_egress", egress_time)
        proxy_graph.constrain_after(
            "client_proxy_request_visible",
            "client_connection",
            min_gap=timedelta(milliseconds=connect_window.max_ms + 1),
        )
        proxy_graph.constrain_after(
            "origin_egress",
            "client_proxy_request_visible",
            min_gap=egress_delay,
        )
        return proxy_graph.resolved_time("origin_egress")

    def _resolve_durations_and_sizes(
        self,
        *,
        dst_ip: str,
        proxy_context: ProxyContext,
        client_orig_bytes: int,
        client_resp_bytes: int,
        client_time: datetime,
        egress_time: datetime,
        will_emit_egress: bool,
        generator_utils: object,
    ) -> tuple[float | None, float | None, int, int]:
        """Resolve client duration, egress duration, and proxy accounting fields."""

        request = self.request
        proxy_sys = request.proxy_chain[0]
        proxy_client_cap = random.Random(
            _stable_seed(
                "proxy_client_duration_cap:"
                f"{request.src_ip}:{proxy_sys.ip}:{dst_ip}:{request.dst_port}:"
                f"{request.time.timestamp()}"
            )
        ).uniform(1.72, 2.36)
        flow_transaction_count = (
            request.http.flow_transaction_count
            if request.http is not None and request.http.flow_transaction_count is not None
            else 1
        )
        if request.duration is not None and flow_transaction_count > 1:
            client_duration = request.duration
        else:
            client_duration = min(
                request.duration if request.duration is not None else 0.2,
                proxy_client_cap,
            )
        if request.duration is None:
            client_duration = generator_utils._jitter_default_connection_duration(
                client_duration,
                caller_provided_duration=False,
                seed_parts=(
                    request.src_ip,
                    proxy_sys.ip,
                    dst_ip,
                    request.dst_port,
                    request.time,
                    "proxy_client",
                ),
            )
        if request.dst_port == 443 and proxy_context.status_code < 400:
            client_duration = request.duration or _get_rng().uniform(0.5, 10.0)
            if proxy_context.method == "CONNECT":
                rng = _get_rng()
                client_orig_bytes += max(request.orig_bytes or 0, rng.randint(180, 900))
                client_resp_bytes += max(request.resp_bytes or 0, rng.randint(900, 4500))
            else:
                framing_rng = random.Random(
                    _stable_seed(
                        "proxy_client_tls_framing:"
                        f"{request.src_ip}:{proxy_sys.ip}:{proxy_context.host}:"
                        f"{request.time.timestamp()}:{proxy_context.method}"
                    )
                )
                client_orig_bytes += framing_rng.randint(160, 900)
                client_resp_bytes += framing_rng.randint(180, 2400)

        egress_duration = request.duration
        if will_emit_egress:
            egress_duration = (
                request.duration
                or generator_utils._jitter_default_connection_duration(
                    0.1,
                    caller_provided_duration=False,
                    seed_parts=(
                        proxy_sys.ip,
                        dst_ip,
                        request.dst_port,
                        request.time,
                        "proxy_egress",
                    ),
                )
            )
            response_flush = random.Random(
                _stable_seed(
                    f"proxy_response_flush:{request.src_ip}:{dst_ip}:{request.time.timestamp()}"
                )
            ).uniform(0.02, 0.25)
            egress_start_after_client = max(0.0, (egress_time - client_time).total_seconds())
            client_duration = max(
                client_duration,
                egress_start_after_client + egress_duration + response_flush,
            )
            proxy_context.time_taken = max(
                proxy_context.time_taken,
                generator_utils._proxy_time_taken_ms(
                    client_duration,
                    random.Random(
                        _stable_seed(
                            "proxy_context_total_time:"
                            f"{request.src_ip}:{proxy_sys.ip}:{proxy_context.host}:"
                            f"{request.dst_port}:{request.time.timestamp()}"
                        )
                    ),
                    method=proxy_context.method,
                    status_code=proxy_context.status_code,
                    cache_result=proxy_context.cache_result,
                ),
            )

        return client_duration, egress_duration, client_orig_bytes, client_resp_bytes

    def _build_proxied_http_file_transfer_pair(
        self,
        *,
        client_http: HttpContext,
        egress_http: HttpContext,
        client_time: datetime,
        egress_time: datetime,
        client_duration: float | None,
        egress_duration: float | None,
        client_dst_ip: str,
        egress_dst_ip: str,
        proxy_context: ProxyContext,
        generator_utils: object,
    ) -> tuple[
        FileTransferContext | None,
        PeContext | None,
        FileTransferContext | None,
        PeContext | None,
        float | None,
        float | None,
    ]:
        """Build paired file metadata for a proxied HTTP MISS response body."""

        if not self._http_file_transfer_required(client_http, egress_http):
            return None, None, None, None, client_duration, egress_duration

        request = self.request
        proxy_sys = request.proxy_chain[0]
        egress_result = HttpResponseFileTransferActionBundle(
            HttpResponseFileTransferRequest(
                host=egress_http.host,
                uri=egress_http.uri,
                dst_ip=egress_dst_ip,
                response_body_len=egress_http.response_body_len,
                response_mime_types=list(egress_http.resp_mime_types),
                timestamp=egress_time,
                parent_duration=egress_duration,
                source="proxy_transaction",
            ),
            random.Random(
                _stable_seed(
                    "proxy_egress_file_transfer:"
                    f"{request.src_ip}:{proxy_sys.ip}:{egress_http.host}:{egress_http.uri}:"
                    f"{egress_http.response_body_len}:{egress_time.isoformat()}"
                )
            ),
        ).execute()
        client_result = HttpResponseFileTransferActionBundle(
            HttpResponseFileTransferRequest(
                host=client_http.host,
                uri=client_http.uri,
                dst_ip=client_dst_ip,
                response_body_len=client_http.response_body_len,
                response_mime_types=list(client_http.resp_mime_types),
                timestamp=client_time,
                parent_duration=client_duration,
                source="proxy_transaction",
            ),
            random.Random(
                _stable_seed(
                    "proxy_client_file_transfer:"
                    f"{request.src_ip}:{proxy_sys.ip}:{client_http.host}:{client_http.uri}:"
                    f"{client_http.response_body_len}:{client_time.isoformat()}"
                )
            ),
        ).execute()

        egress_duration = max(
            egress_duration or 0.0,
            egress_result.file_transfer.duration + 0.002,
        )
        client_not_before = egress_time + timedelta(
            milliseconds=1100
            + (
                _stable_seed(
                    "proxy_client_file_not_before:"
                    f"{request.src_ip}:{proxy_sys.ip}:{client_http.host}:"
                    f"{client_http.uri}:{client_time.isoformat()}"
                )
                % 900
            )
        )
        client_result.file_transfer.observation_not_before = client_not_before
        client_result.file_transfer.duration = max(
            client_result.file_transfer.duration,
            egress_result.file_transfer.duration
            + random.Random(
                _stable_seed(
                    "proxy_client_file_tail_gap:"
                    f"{request.src_ip}:{proxy_sys.ip}:{client_http.host}:"
                    f"{client_http.uri}:{client_time.isoformat()}"
                )
            ).uniform(0.02, 0.18),
        )
        client_file_floor = (
            max(0.0, (client_not_before - client_time).total_seconds())
            + client_result.file_transfer.duration
            + 0.002
        )
        client_duration = max(client_duration or 0.0, client_file_floor)

        client_http.resp_fuids = [client_result.file_transfer.fuid]
        client_http.resp_mime_types = [client_result.file_transfer.mime_type]
        egress_http.resp_fuids = [egress_result.file_transfer.fuid]
        egress_http.resp_mime_types = [egress_result.file_transfer.mime_type]

        proxy_context.time_taken = max(
            proxy_context.time_taken,
            generator_utils._proxy_time_taken_ms(
                client_duration,
                random.Random(
                    _stable_seed(
                        "proxy_context_file_transfer_time:"
                        f"{request.src_ip}:{proxy_sys.ip}:{client_http.host}:"
                        f"{client_http.uri}:{client_time.isoformat()}"
                    )
                ),
                method=proxy_context.method,
                status_code=proxy_context.status_code,
                cache_result=proxy_context.cache_result,
            ),
        )

        return (
            client_result.file_transfer,
            client_result.pe,
            egress_result.file_transfer,
            egress_result.pe,
            client_duration,
            egress_duration,
        )

    @staticmethod
    def _http_file_transfer_required(client_http: HttpContext, egress_http: HttpContext) -> bool:
        """Return whether this proxied HTTP body should produce files.log rows."""

        method = (egress_http.method or "GET").upper()
        if (
            method in {"CONNECT", "HEAD"}
            or not (200 <= egress_http.status_code < 300)
            or egress_http.response_body_len <= 100
            or not egress_http.resp_mime_types
            or client_http.response_body_len != egress_http.response_body_len
        ):
            return False
        mime_type = egress_http.resp_mime_types[0]
        return egress_http.response_body_len >= _PROXY_HTTP_FILE_TRANSFER_LARGE_BODY_THRESHOLD or (
            egress_http.response_body_len >= _PROXY_HTTP_FILE_TRANSFER_BODY_THRESHOLD
            and mime_type in _PROXY_HTTP_FILE_TRANSFER_MIME_TYPES
        )

    def _build_egress_http(
        self,
        proxy_context: ProxyContext,
        client_http: HttpContext,
    ) -> HttpContext | None:
        """Build the proxy-to-origin HTTP context when the origin leg is HTTP."""

        from evidenceforge.generation.activity import generator as generator_utils

        request = self.request
        egress_http = (
            request.http
            if request.http is not None and proxy_context.cache_result in {"MISS", "REVALIDATED"}
            else None
        )
        if egress_http is not None:
            egress_http = replace(
                egress_http,
                user_agent=proxy_context.user_agent,
                referrer=proxy_context.referrer,
            )
        if (
            egress_http is not None
            or request.dst_port != 80
            or proxy_context.cache_result not in {"MISS", "REVALIDATED"}
        ):
            return egress_http

        status_messages = {
            200: "OK",
            301: "Moved Permanently",
            302: "Found",
            304: "Not Modified",
            403: "Forbidden",
            407: "Proxy Authentication Required",
            500: "Internal Server Error",
            502: "Bad Gateway",
            503: "Service Unavailable",
            504: "Gateway Timeout",
        }
        response_body_len = generator_utils._proxy_http_response_body_len(
            proxy_context,
            resp_bytes=request.resp_bytes,
        )
        request_body_len = 0
        if proxy_context.method not in {"GET", "HEAD", "CONNECT", "OPTIONS"}:
            request_body_len = max(request.orig_bytes or 0, proxy_context.cs_bytes)
        return HttpContext(
            method=proxy_context.method,
            host=proxy_context.host,
            uri=generator_utils._origin_form_uri_from_proxy_url(proxy_context.url),
            version="1.1",
            user_agent=proxy_context.user_agent,
            request_body_len=request_body_len,
            response_body_len=response_body_len,
            status_code=proxy_context.status_code,
            status_msg=status_messages.get(proxy_context.status_code, "OK"),
            referrer=proxy_context.referrer,
            trans_depth=client_http.trans_depth,
            tags=[],
            resp_mime_types=[proxy_context.content_type]
            if proxy_context.content_type
            and response_body_len > 0
            and proxy_context.status_code not in {204, 304}
            and proxy_context.status_code < 400
            else [],
        )
