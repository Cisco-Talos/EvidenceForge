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

"""Canonical network-connection action planner."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta
from types import ModuleType
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from evidenceforge.events.base import SecurityEvent
    from evidenceforge.generation.actions.network_connection import NetworkConnectionRequest
    from evidenceforge.generation.activity.generator import ActivityGenerator


@dataclass(slots=True)
class _NetworkOccurrenceDraft:
    """Mutable planning surface used before the canonical event is constructed.

    Protocol and source metadata sometimes need to repair the initial transport
    estimates. Keeping those mutations on an action-owned draft prevents an
    incompletely planned ``SecurityEvent`` from escaping into state or renderers.
    """

    timestamp: datetime
    src_host: Any = None
    dst_host: Any = None
    local_only: bool = False
    process: Any = None
    network: Any = None
    edr: Any = None
    dns: Any = None
    email: Any = None
    smtp: Any = None
    ids: Any = None
    ssl: Any = None
    http: Any = None
    file_transfer: Any = None
    file_transfers: list[Any] = field(default_factory=list)
    x509: Any = None
    x509_chain: list[Any] = field(default_factory=list)
    ntp: Any = None
    ocsp: Any = None
    pe: Any = None
    proxy: Any = None
    firewall: Any = None
    parent_action_group_id: str | None = None

    def build_event(self, generator_module: ModuleType) -> SecurityEvent:
        """Construct the canonical event only after the transaction is frozen."""

        if self.network is None or self.network.transaction is None:
            raise ValueError("Cannot construct a network event before transaction finalization")
        from evidenceforge.events.lifecycle import ActionLifecycleContext

        transaction = self.network.transaction
        return generator_module.SecurityEvent(
            timestamp=self.timestamp,
            event_type="connection",
            src_host=self.src_host,
            dst_host=self.dst_host,
            local_only=self.local_only,
            process=self.process,
            network=self.network,
            edr=self.edr,
            dns=self.dns,
            email=self.email,
            smtp=self.smtp,
            ids=self.ids,
            ssl=self.ssl,
            http=self.http,
            file_transfer=self.file_transfer,
            file_transfers=self.file_transfers,
            x509=self.x509,
            x509_chain=self.x509_chain,
            ntp=self.ntp,
            ocsp=self.ocsp,
            pe=self.pe,
            proxy=self.proxy,
            firewall=self.firewall,
            lifecycle=ActionLifecycleContext(
                group_id=transaction.stable_id,
                canonical_start=transaction.started_at,
                phase="start",
                parent_group_id=(
                    self.parent_action_group_id
                    or (transaction.conn_id if self.network.application_layer_only else None)
                ),
            ),
        )


class NetworkTransactionPlanner:
    """Expand one network intent into a finalized canonical transaction."""

    def __init__(self, executor: ActivityGenerator) -> None:
        self._executor = executor

    def execute(self, request: NetworkConnectionRequest) -> str:
        """Expand one network connection request into canonical evidence."""
        from evidenceforge.generation.actions.file_transfer import (
            SmbFileTransferMetadataActionBundle,
            SmbFileTransferMetadataRequest,
        )
        from evidenceforge.generation.actions.proxy_transaction import (
            ProxyTransactionActionBundle,
            ProxyTransactionRequest,
        )
        from evidenceforge.generation.activity import generator as generator_module

        executor = self._executor
        src_ip = request.src_ip
        dst_ip = request.dst_ip
        time = request.time
        dst_port = request.dst_port
        proto = request.proto
        service = request.service
        duration = request.duration
        orig_bytes = request.orig_bytes
        resp_bytes = request.resp_bytes
        explicit_orig_bytes = request.orig_bytes
        explicit_resp_bytes = request.resp_bytes
        src_port = request.src_port
        emit_dns = request.emit_dns
        pid = request.pid
        source_system = request.source_system
        conn_state = request.conn_state
        dns = request.dns
        email = request.email
        smtp = request.smtp
        x509 = request.x509
        x509_chain = request.x509_chain
        ids = request.ids
        http = request.http
        caller_supplied_http = http is not None
        file_transfer = request.file_transfer
        file_transfers = request.file_transfers
        pe = request.pe
        ocsp = request.ocsp
        proxy = request.proxy
        firewall = request.firewall
        hostname = request.hostname
        proxy_bypass = request.proxy_bypass
        process_image = request.process_image
        preserve_dst_ip = request.preserve_dst_ip
        preserve_http_outcome = request.preserve_http_outcome
        suppress_application_side_effects = request.suppress_application_side_effects
        suppress_source_pid_inference = request.suppress_source_pid_inference
        preserve_explicit_payload = request.preserve_explicit_payload
        suppress_prereq_dns = request.suppress_prereq_dns
        packet_overhead_bytes = request.packet_overhead_bytes
        responding_pid = request.responding_pid
        ssh_attempted_username = request.ssh_attempted_username
        parent_action_group_id = request.parent_action_group_id
        preserve_start_time = request.preserve_start_time
        caller_supplied_pid = pid > 0

        from evidenceforge.events.contexts import NetworkContext

        executor._last_connection_effective_tuple = None
        executor._last_connection_effective_time = None

        if http is not None:
            http = generator_module._normalize_http_context_for_source_native_response(http)

        caller_provided_duration = duration is not None
        caller_provided_conn_state = conn_state is not None
        caller_provided_payload = (
            service is not None
            and duration is not None
            and (orig_bytes or 0) > 0
            and (resp_bytes or 0) > 0
        )
        if http is not None and proto == "tcp" and conn_state is None:
            conn_state = "SF"
        process_exe = (process_image or "").rsplit("\\", 1)[-1].rsplit("/", 1)[-1].lower()
        is_tcp_probe = process_exe in {"nmap", "nmap.exe"}
        if source_system is None and hasattr(executor, "_ip_to_system"):
            source_system = executor._ip_to_system.get(src_ip)
        if service == "kerberos" and dst_port == 88 and proto == "tcp":
            from evidenceforge.generation.activity.kerberos_realism import (
                pick_kerberos_transport,
            )

            proto = pick_kerberos_transport(
                generator_module.random.Random(
                    generator_module._stable_seed(
                        "kerberos_transport:"
                        f"{src_ip}:{dst_ip}:{time.isoformat()}:{src_port or ''}:{pid}"
                    )
                )
            )
        if service == "kerberos" and dst_port == 88 and proto == "udp":
            udp_kerberos_rng = generator_module.random.Random(
                generator_module._stable_seed(
                    "kerberos_udp_shape:"
                    f"{src_ip}:{dst_ip}:{time.isoformat()}:{src_port or ''}:{pid}"
                )
            )
            duration = min(
                duration if duration is not None else udp_kerberos_rng.uniform(0.003, 0.075),
                udp_kerberos_rng.uniform(0.035, 0.16),
            )
            orig_bytes = min(
                max(orig_bytes or udp_kerberos_rng.randint(180, 900), 160),
                udp_kerberos_rng.randint(700, 1300),
            )
            resp_bytes = min(
                max(resp_bytes or udp_kerberos_rng.randint(120, 1200), 80),
                udp_kerberos_rng.randint(600, 1400),
            )
            if conn_state not in {None, "SF", "S0", "REJ", "OTH"}:
                conn_state = "SF" if resp_bytes else "S0"

        if (
            http is None
            and pid > 0
            and source_system is not None
            and proto == "tcp"
            and (dst_port in {80, 443, 8080} or service is None or service in {"http", "ssl"})
        ):
            proc = executor.state_manager.get_process(source_system.hostname, pid)
            if proc is not None:
                command_http = generator_module._http_context_from_process_command(
                    proc.image,
                    proc.command_line,
                    response_body_len=resp_bytes or generator_module._get_rng().randint(500, 50000),
                )
                if command_http is not None:
                    command_http_context, command_host, command_port, command_service = command_http
                    command_target = executor._system_for_hostname(command_host)
                    host_lower = command_host.lower().rstrip(".")
                    ad_domain_for_command = (
                        str(
                            getattr(executor, "_ad_domain", "") or "",
                        )
                        .lower()
                        .rstrip(".")
                    )
                    command_is_unknown_internal = command_target is None and (
                        host_lower.endswith(".local")
                        or (
                            ad_domain_for_command
                            and host_lower.endswith(f".{ad_domain_for_command}")
                        )
                    )
                    if not command_is_unknown_internal:
                        http = command_http_context
                        hostname = command_host
                        dst_port = command_port
                        service = command_service
                        if command_target is not None:
                            dst_ip = command_target.ip
                            emit_dns = True

        # Resolve hostname ONCE for DNS/proxy consistency.
        # All downstream uses (causal DNS expansion, proxy hostname)
        # share this single resolved value instead of doing independent lookups.
        #
        # hostname semantics (preserved through all downstream builders):
        #   None  → auto-resolve from REVERSE_DNS or generate random
        #   ""    → suppress resolution (raw-IP C2, exposed hosts w/o public_hostnames)
        #   "x.y" → use this hostname explicitly
        hostname_was_explicit = hostname not in (None, "")
        hostname_from_reverse_dns = False
        if hostname is None:
            reverse_hostname = generator_module.REVERSE_DNS.get(dst_ip)
            if reverse_hostname is not None:
                hostname = reverse_hostname
                hostname_from_reverse_dns = True
            elif (
                emit_dns
                and proto == "tcp"
                and dst_port not in (53,)
                and generator_module._is_private_ip(dst_ip)
            ):
                hostname = generator_module._generate_internal_hostname(
                    generator_module._get_rng(),
                    dst_ip,
                    getattr(executor, "_ad_domain", "corp.local"),
                )
            else:
                hostname = None
        if hostname is None and emit_dns and proto == "tcp" and dst_port not in (53,):
            if not generator_module._is_private_ip(dst_ip):
                hostname = generator_module._generate_random_hostname(
                    generator_module._get_rng(), dst_ip
                )

        proxy_routes = getattr(executor, "_proxy_routes", {})
        proxy_chain = proxy_routes.get(src_ip)
        preserve_explicit_proxy_dst_ip = (
            preserve_dst_ip
            and hostname_was_explicit
            and not proxy_bypass
            and getattr(executor, "_proxy_mode", "transparent") == "explicit"
            and bool(proxy_chain)
            and proto == "tcp"
            and dst_port in (80, 443)
        )

        if (
            hostname
            and hostname_was_explicit
            and not preserve_dst_ip
            and not preserve_explicit_proxy_dst_ip
            and not (service == "dns" and proto in ("udp", "tcp") and dst_port == 53)
        ):
            from evidenceforge.generation.activity.dns_registry import get_domain_ips

            src_host = source_system.hostname if source_system else src_ip
            resolver = getattr(executor, "_network_resolver", None)
            resolved = resolver.resolve_host(hostname, src_host=src_host) if resolver else None
            if (
                resolved is not None
                and resolved.source == "scenario_identity"
                and resolved.ip
                and dst_ip != resolved.ip
            ):
                dst_ip = resolved.ip
            elif resolved is not None and resolved.source == "stable_fallback":
                pass
            else:
                from evidenceforge.generation.activity.dns_registry import resolve_domain_ip

                domain_ips = get_domain_ips(hostname)
                if domain_ips and dst_ip not in domain_ips:
                    dst_ip = resolve_domain_ip(hostname, src_host=src_host)
                elif not domain_ips and emit_dns and not generator_module._is_private_ip(dst_ip):
                    dst_ip = resolve_domain_ip(hostname, src_host=src_host)

        ad_domain = getattr(executor, "_ad_domain", "corp.local")
        hostname_is_external = (
            bool(hostname)
            and "." in hostname
            and not hostname.endswith(f".{ad_domain}")
            and not hostname.endswith(".local")
        )
        proxyable_external_destination = (
            hostname_is_external or not generator_module._is_private_ip(dst_ip)
        )
        dns_server_ips = set(getattr(executor, "_dns_server_ips", []))
        if (
            proto == "tcp"
            and dst_port in (80, 443)
            and hostname_is_external
            and dst_ip in dns_server_ips
        ):
            src_host = source_system.hostname if source_system else src_ip
            resolver = getattr(executor, "_network_resolver", None)
            resolved = resolver.resolve_host(hostname, src_host=src_host) if resolver else None
            if resolved is not None and resolved.ip:
                dst_ip = resolved.ip
            else:
                from evidenceforge.generation.activity.dns_registry import resolve_domain_ip

                dst_ip = resolve_domain_ip(hostname, src_host=src_host)

        # Infer common payload service from destination port before proxy
        # routing and DNS expansion. Some callers provide only port/protocol or
        # source-common aliases (for example "https"); explicit proxy semantics
        # still need to catch 80/443 before a client-side origin DNS lookup is
        # emitted. Keep the empty-string raw-TCP sentinel unchanged.
        if proto == "tcp" and dst_port in (80, 443) and service != "" and not is_tcp_probe:
            service = "http" if dst_port == 80 else "ssl"
        if proto == "udp" and dst_port == 123 and (service != "" or (resp_bytes or 0) > 0):
            service = "ntp"
            if not generator_module._is_private_ip(dst_ip):
                from evidenceforge.generation.activity.network_params import public_ntp_ips

                configured_ntp_ips = set(public_ntp_ips())
                if configured_ntp_ips and dst_ip not in configured_ntp_ips:
                    selected_ntp_ip = generator_module._select_public_ntp_ip(src_ip, dst_ip, time)
                    if selected_ntp_ip:
                        dst_ip = selected_ntp_ip

        if (
            proto == "tcp"
            and service == "ssl"
            and dst_port == 443
            and emit_dns
            and dns is None
            and http is None
            and not hostname_was_explicit
            and generator_module._is_private_ip(src_ip)
            and not generator_module._is_private_ip(dst_ip)
        ):
            hostname, dst_ip = executor._pick_profiled_tls_destination(
                rng=generator_module._get_rng(),
                src_ip=src_ip,
                source_system=source_system,
                purpose_tags=("web", "saas", "background"),
            )

        executor._last_connection_effective_dst_ip = dst_ip

        tls_hostname = hostname
        if hostname_from_reverse_dns and not emit_dns and dns is None and http is None:
            # A PTR/reverse-DNS-style fallback is useful for proxy URL rendering
            # but should not become TLS SNI unless the client actually resolved
            # or was explicitly configured to use that hostname.
            tls_hostname = ""

        will_route_explicit_proxy = (
            not proxy_bypass
            and getattr(executor, "_proxy_mode", "transparent") == "explicit"
            and bool(proxy_chain)
            and proto == "tcp"
            and service in ("ssl", "http")
            and dst_port in (80, 443)
            and proxyable_external_destination
            and conn_state not in ("S0", "REJ", "S1", "SH", "SHR", "RSTO", "RSTR")
        )

        if http is not None and not preserve_http_outcome and not will_route_explicit_proxy:
            http = generator_module._apply_plaintext_http_policy(
                http,
                hostname=hostname,
                dst_ip=dst_ip,
                dst_port=dst_port,
            )

        explicit_proxy = will_route_explicit_proxy
        if explicit_proxy:
            proxy_request = ProxyTransactionRequest(
                src_ip=src_ip,
                dst_ip=dst_ip,
                time=time,
                dst_port=dst_port,
                proto=proto,
                service=service,
                duration=duration,
                orig_bytes=orig_bytes,
                resp_bytes=resp_bytes,
                src_port=src_port,
                pid=pid,
                source_system=source_system,
                conn_state=conn_state,
                dns=dns,
                ids=ids,
                http=http,
                file_transfer=file_transfer,
                ocsp=ocsp,
                proxy=proxy,
                firewall=firewall,
                hostname=hostname,
                process_image=process_image,
                proxy_chain=list(proxy_chain),
                preserve_explicit_proxy_dst_ip=preserve_explicit_proxy_dst_ip,
                caller_provided_conn_state=caller_provided_conn_state,
                ad_domain=ad_domain,
                parent_action_group_id=parent_action_group_id,
            )
            return ProxyTransactionActionBundle(
                request=proxy_request,
                executor=executor,
            ).execute()

        # Emit DNS lookup before connection via causal expansion.
        # The DnsBeforeConnection rule handles caching, SERVFAIL, multi-answer, etc.
        # Only internal hosts generate DNS lookups — external source IPs (e.g.,
        # attacker IPs in storylines) don't query the victim's internal resolver.
        src_ip_is_local = generator_module._is_modeled_local_ip(executor, src_ip)
        dst_ip_is_local = generator_module._is_modeled_local_ip(executor, dst_ip)
        force_visible_prereq_dns = (
            source_system is not None
            and "forward_proxy" in (source_system.roles or [])
            and hostname_is_external
            and proto == "tcp"
            and dst_port in (80, 443)
            and src_ip_is_local
            and not suppress_prereq_dns
        )
        # Same-host connections are valid for host-based logs (eCAR FLOW)
        # but invisible to network sensors (Zeek/Snort)
        local_only = src_ip == dst_ip

        # Validate connection is not fundamentally invalid (localhost, link-local, multicast)
        is_invalid, reason = generator_module._is_invalid_network_connection(src_ip, dst_ip)
        if is_invalid:
            generator_module.logger.warning(
                "Skipping invalid network connection: %s:%s -> %s:%s proto=%s. "
                "Reason: %s. Check that all systems have routable IPs in the scenario.",
                src_ip,
                src_port or "?",
                dst_ip,
                dst_port,
                proto,
                reason,
            )
            return ""

        is_fw_deny = firewall is not None and firewall.action == "deny"

        resolved_source_system = source_system
        if (
            resolved_source_system is None
            and hasattr(executor, "_ip_to_system")
            and src_ip in executor._ip_to_system
        ):
            resolved_source_system = executor._ip_to_system[src_ip]

        http_application_layer_only = False
        reused_http_uid = ""
        reused_http_conn_id = ""
        http_persistent_key: tuple[str, str, int, str, str] | None = None
        if http is not None and proto == "tcp" and service == "http" and dst_port > 0:
            http_host_key = (http.host or hostname or dst_ip).lower().rstrip(".")
            http_user_agent_key = (http.user_agent or "").lower()
            http_persistent_key = (
                src_ip,
                dst_ip,
                dst_port,
                http_host_key,
                http_user_agent_key,
            )
            if http.trans_depth > 1:
                cached = executor._http_persistent_connections.get(http_persistent_key)
                if cached is not None:
                    reuse_deadline = (
                        cached.close_deadline - generator_module._HTTP_PERSISTENT_REUSE_GUARD
                    )
                    elapsed = (time - reuse_deadline).total_seconds()
                    request_body = http.request_body_len or 0
                    response_body = http.response_body_len or 0
                    fits_parent_flow = (
                        cached.used_orig + request_body <= cached.orig_budget
                        and cached.used_resp + response_body <= cached.resp_budget
                    )
                    if elapsed <= 0 and fits_parent_flow:
                        src_port = cached.src_port
                        reused_http_uid = cached.uid
                        reused_http_conn_id = cached.conn_id
                        http_application_layer_only = True
                        http = generator_module.replace(http, trans_depth=cached.next_trans_depth)
                        cached.next_trans_depth += 1
                        cached.used_orig += request_body
                        cached.used_resp += response_body
                    else:
                        executor._http_persistent_connections.pop(http_persistent_key, None)
                if not http_application_layer_only:
                    http = generator_module.replace(http, trans_depth=1)

        kerberos_dc_hostname = None
        if proto in {"tcp", "udp"} and dst_port == 88:
            kerberos_dc = executor._dc_system_for_ip(dst_ip)
            if kerberos_dc is not None:
                kerberos_dc_hostname = str(getattr(kerberos_dc, "hostname", "") or "")

        if proto == "icmp":
            src_port = 0
            dst_port = 0
        elif src_port is None:
            if kerberos_dc_hostname:
                src_port = executor._find_reserved_kerberos_source_port(
                    src_ip,
                    kerberos_dc_hostname,
                    time,
                    dst_ip=dst_ip,
                )
                if src_port is not None:
                    executor._remember_connection_tuple(
                        src_ip, src_port, dst_ip, dst_port, proto, time
                    )
            if src_port is None:
                # Determine source OS for correct ephemeral port range
                _src_os = "windows"
                if resolved_source_system:
                    _src_os = generator_module._get_os_category(resolved_source_system.os)
                src_port = executor._allocate_ephemeral_port(
                    src_ip, dst_ip, dst_port, proto, time, _src_os
                )
        else:
            executor._remember_connection_tuple(src_ip, src_port, dst_ip, dst_port, proto, time)
        if kerberos_dc_hostname and src_port is not None and src_port > 0:
            executor._reserve_kerberos_source_port(src_ip, kerberos_dc_hostname, time, src_port)

        if service == "dns" and proto in ("udp", "tcp") and dst_port == 53:
            dns_pid = executor._infer_connection_pid(
                resolved_source_system, service, dst_port, proto
            )
            if dns_pid > 0:
                pid = dns_pid
        elif pid <= 0 and not suppress_source_pid_inference:
            pid = executor._infer_connection_pid(resolved_source_system, service, dst_port, proto)

        resolved_process = None
        if service == "dns" and proto in ("udp", "tcp") and dst_port == 53:
            query_len = len(dns.query) if dns is not None and dns.query else 12
            query_type = (dns.query_type if dns is not None else "").upper()
            min_query_payload = max(40, query_len + 16)
            if query_type in {"TXT", "NULL"}:
                min_query_payload += 18
            elif query_type == "SRV":
                min_query_payload += 10
            if orig_bytes is None or orig_bytes < min_query_payload:
                orig_bytes = min_query_payload
            if dns is not None and dns.rtt is not None:
                duration = max(duration or 0.001, dns.rtt)

        if pid > 0 and resolved_source_system:
            resolved_process = executor.state_manager.get_process(
                resolved_source_system.hostname, pid
            )
            drop_explicit_pid_without_inference = False
            if (
                resolved_process
                and resolved_process.start_time
                and time < resolved_process.start_time
            ):
                generator_module.logger.debug(
                    "Dropping future connection PID attribution: "
                    "host=%s pid=%s process_start=%s connection_time=%s dst=%s:%s",
                    resolved_source_system.hostname,
                    pid,
                    resolved_process.start_time,
                    time,
                    dst_ip,
                    dst_port,
                )
                pid = -1
                resolved_process = None
                drop_explicit_pid_without_inference = caller_supplied_pid
            elif executor._process_termination_recorded(
                resolved_source_system.hostname,
                pid,
                resolved_process.start_time if resolved_process is not None else None,
            ):
                generator_module.logger.debug(
                    "Dropping terminated process connection attribution: host=%s pid=%s dst=%s:%s",
                    resolved_source_system.hostname,
                    pid,
                    dst_ip,
                    dst_port,
                )
                pid = -1
                resolved_process = None
                drop_explicit_pid_without_inference = caller_supplied_pid
            elif (
                resolved_process
                and resolved_process.start_time
                and executor._foreground_process_expired_for_attribution(
                    resolved_source_system,
                    resolved_process,
                    time,
                )
            ):
                generator_module.logger.debug(
                    "Dropping expired foreground process attribution: "
                    "host=%s pid=%s image=%s dst=%s:%s",
                    resolved_source_system.hostname,
                    pid,
                    resolved_process.image,
                    dst_ip,
                    dst_port,
                )
                pid = -1
                resolved_process = None
                drop_explicit_pid_without_inference = caller_supplied_pid
            elif resolved_process is None and pid != 4:
                generator_module.logger.debug(
                    "Dropping stale connection PID attribution: host=%s pid=%s dst=%s:%s",
                    resolved_source_system.hostname,
                    pid,
                    dst_ip,
                    dst_port,
                )
                pid = -1
                drop_explicit_pid_without_inference = caller_supplied_pid
            if drop_explicit_pid_without_inference:
                suppress_source_pid_inference = True

        if pid <= 0 and resolved_source_system is not None and not suppress_source_pid_inference:
            pid, process_image = executor._ensure_high_confidence_connection_owner(
                source_system=resolved_source_system,
                time=time,
                service=service,
                dst_port=dst_port,
                proto=proto,
                hostname=hostname,
                http=http,
                ssh_attempted_username=ssh_attempted_username,
            )
            if pid > 0:
                resolved_process = executor.state_manager.get_process(
                    resolved_source_system.hostname,
                    pid,
                )

        if (
            ssh_attempted_username is None
            and proto == "tcp"
            and dst_port == 22
            and resolved_process is not None
        ):
            ssh_attempted_username = generator_module._extract_ssh_attempted_username(
                resolved_process.command_line
            )

        if pid > 0 and resolved_source_system is not None and resolved_process is not None:
            adjusted_time = executor._clamp_after_visible_process_create(
                resolved_source_system,
                pid,
                time,
                "source.windows_wfp_connection",
            )
            if preserve_start_time and adjusted_time > time:
                # Higher-level action bundles already own this transport's phase
                # anchor. A late endpoint process observation must not move the
                # canonical connection behind a dependent sibling; retain the
                # transport and omit unsafe process attribution instead.
                pid = -1
                resolved_process = None
                process_image = None
                suppress_source_pid_inference = True
            else:
                time = adjusted_time

        # Preserve the initiating application on the canonical DNS occurrence
        # after connection ownership has been resolved. The DNS bundle still
        # assigns resolver-service ownership to its separate UDP/53 transport.
        if force_visible_prereq_dns:
            executor._emit_dns_lookup(
                src_ip,
                dst_ip,
                time - generator_module.timedelta(seconds=2),
                hostname=hostname,
                force_address=True,
                bypass_cache=True,
                source_system=resolved_source_system,
                source_pid=pid,
                source_process_image=process_image or "",
            )
        elif (
            (emit_dns or (hostname and not hostname_from_reverse_dns and not suppress_prereq_dns))
            and proto == "tcp"
            and dst_port not in (53,)
            and src_ip_is_local
        ):
            executor._expand_and_emit(
                "connection",
                time,
                src_ip=src_ip,
                dst_ip=dst_ip,
                dst_port=dst_port,
                proto=proto,
                service=service,
                hostname=hostname,
                source_system=resolved_source_system,
                source_pid=pid,
                source_image=process_image or "",
            )

        if service == "dns" and proto in ("udp", "tcp") and dst_port == 53 and dns is not None:
            ad_domain = getattr(executor, "_ad_domain", "corp.local")
            dns.AA = generator_module._dns_is_internal_name(dns.query or "", ad_domain)
            if not is_fw_deny:
                duration, orig_bytes, resp_bytes = generator_module._dns_payload_accounting(
                    dns=dns,
                    duration=duration,
                    orig_bytes=orig_bytes,
                    resp_bytes=resp_bytes,
                )
        elif service == "dns" and proto in ("udp", "tcp") and dst_port == 53:
            if hostname and resp_bytes is not None and resp_bytes > 0:
                dns_query = (
                    hostname
                    or generator_module.REVERSE_DNS.get(dst_ip)
                    or f"host-{dst_ip.replace('.', '-')}"
                )
                fallback_dns = generator_module.DnsContext(
                    query=dns_query,
                    trans_id=0,
                    qtype=1,
                    query_type="A",
                    rcode="NOERROR",
                    rcode_num=0,
                    answers=[dst_ip],
                    rtt=duration,
                )
                duration, orig_bytes, resp_bytes = generator_module._dns_payload_accounting(
                    dns=fallback_dns,
                    duration=duration,
                    orig_bytes=orig_bytes,
                    resp_bytes=resp_bytes,
                )
            else:
                duration = min(
                    duration
                    or generator_module._jitter_default_connection_duration(
                        0.02,
                        caller_provided_duration=False,
                        seed_parts=(src_ip, dst_ip, dst_port, time, "dns_default"),
                    ),
                    0.08,
                )
                orig_bytes = min(max(orig_bytes or 40, 40), 260)
                if resp_bytes is None:
                    resp_bytes = 120
                elif resp_bytes <= 0:
                    resp_bytes = 0
                else:
                    resp_bytes = min(max(resp_bytes, 70), 512)

        if (
            service == "dns"
            and proto in ("udp", "tcp")
            and dst_port == 53
            and dns is None
            and hostname
        ):
            ad_domain = getattr(executor, "_ad_domain", "corp.local")
            dns_cache_key = (src_ip, dst_ip, hostname, "A")
            ts_epoch = time.timestamp()
            cache_ttl = generator_module._dns_base_ttl(
                hostname, generator_module._dns_is_internal_name(hostname, ad_domain)
            )
            cached_at, cached_until = generator_module._dns_cache_window(
                executor._dns_cache.get(dns_cache_key)
            )
            if cached_at <= ts_epoch < cached_until:
                executor._last_connection_effective_dst_ip = dst_ip
                return ""
            executor._dns_cache[dns_cache_key] = (ts_epoch, ts_epoch + cache_ttl)

        state_source_system = resolved_source_system.hostname if resolved_source_system else ""
        state_source_hostname = ""
        if resolved_source_system:
            state_source_hostname = executor._build_host_context(resolved_source_system).fqdn
        close_time = (
            time + generator_module.timedelta(seconds=duration) if duration is not None else None
        )

        executor._last_connection_effective_dst_ip = dst_ip

        # Phase 1: Allocate IDs from StateManager
        if reused_http_conn_id:
            executor.state_manager.reserve_connection_identity()
            conn_id = reused_http_conn_id
            uid = reused_http_uid
        else:
            conn_id = executor.state_manager.open_connection(
                src_ip=src_ip,
                src_port=src_port,
                dst_ip=dst_ip,
                dst_port=dst_port,
                protocol=proto,
                source_system=state_source_system,
                source_hostname=state_source_hostname,
                hostname=hostname or "",
                initiating_pid=pid,
                close_time=close_time,
            )
            uid = executor.state_manager.get_zeek_uid(conn_id)
        if orig_bytes is not None and resp_bytes is not None:
            executor.state_manager.update_connection_bytes(conn_id, orig_bytes, resp_bytes)

        # Protocol-aware connection state selection
        rng = generator_module._get_rng()

        dns_has_response = (
            proto == "udp"
            and service == "dns"
            and dns is not None
            and (
                dns.rtt is not None
                or bool(dns.answers)
                or dns.rcode.upper() in {"NOERROR", "NXDOMAIN", "SERVFAIL", "REFUSED"}
            )
        )

        # ICMP is connectionless — always OTH regardless of what the caller passed
        if proto == "icmp":
            conn_state = "OTH"
            history = "-"
            src_port = 0  # ICMP has no ports; Zeek emits 0
            dst_port = 0
            if resp_bytes and resp_bytes > 0:
                request_size = generator_module._icmp_echo_payload_size(rng, orig_bytes)
                response_size = request_size
                orig_bytes = request_size
                resp_bytes = response_size
                duration = generator_module._icmp_echo_duration(rng, duration)
            else:
                orig_bytes = generator_module._icmp_echo_payload_size(rng, orig_bytes)
                resp_bytes = 0
                duration = generator_module._icmp_echo_duration(rng, duration)
        elif dns_has_response:
            conn_state = "SF"
            history = "Dd"
            orig_bytes = max(orig_bytes or 0, 28)
            resp_bytes = max(resp_bytes or 0, 40)
            if dns.rtt is not None and (duration is None or duration < dns.rtt):
                duration = dns.rtt
        elif conn_state is not None:
            # Explicit conn_state for TCP/UDP (e.g., UFW BLOCK → REJ)
            if proto == "udp":
                history = {
                    "SF": "Dd" if resp_bytes else "D",
                    "S0": "D",
                    "REJ": "D",
                    "OTH": "D",
                }.get(conn_state, "Dd" if resp_bytes else "D")
            else:
                if conn_state == "SF":
                    history = generator_module._tcp_success_history(rng)
                else:
                    history = {
                        "REJ": "Sr",
                        "S0": "S",
                        "OTH": "Cc",
                        "S2": "ShADadF",
                        "S3": "ShADadf",
                        "RSTO": "ShADaR",
                        "RSTR": "ShADadR",
                        "S1": "ShR",
                    }.get(conn_state, generator_module._tcp_success_history(rng))
            if conn_state in ("S0", "REJ"):
                duration = None
                resp_bytes = 0
                if service == "dns" and proto == "udp" and dst_port == 53:
                    orig_bytes = max(orig_bytes or 0, 40)
                else:
                    orig_bytes = 0
            elif conn_state in ("S2", "S3"):
                if duration is not None:
                    duration = duration * rng.uniform(0.3, 0.8)
                if resp_bytes:
                    resp_bytes = int(resp_bytes * rng.uniform(0.2, 0.7))
            elif conn_state in ("RSTO", "RSTR"):
                if duration is not None:
                    duration = duration * rng.uniform(0.1, 0.5)
                if resp_bytes:
                    resp_bytes = int(resp_bytes * rng.uniform(0.1, 0.5))
        elif proto == "udp":
            # DNS connections with responses must not be S0 (no-response)
            if service == "kerberos" and resp_bytes and resp_bytes > 0:
                conn_state, history = "SF", "Dd"
            elif service == "dns" and resp_bytes and resp_bytes > 0:
                # ~5% retransmissions, ~2% multi-packet responses (large TXT/DNSSEC)
                dns_roll = rng.random()
                if dns_roll < 0.05:
                    conn_state, history = "SF", "DDd"  # Retransmitted query
                elif dns_roll < 0.07:
                    conn_state, history = "SF", "Ddd"  # Multi-packet response
                else:
                    conn_state, history = "SF", "Dd"
            elif service == "ntp" and resp_bytes and resp_bytes > 0:
                conn_state, history = "SF", "Dd"
            else:
                entry = rng.choices(
                    generator_module._UDP_CONN_ENTRIES,
                    weights=generator_module._UDP_CONN_WEIGHTS,
                    k=1,
                )[0]
                conn_state, _, history = entry
            if conn_state == "S0":
                duration = None
                resp_bytes = 0
        else:
            if duration is not None:
                tcp_entries = generator_module._TCP_CONN_ENTRIES
                tcp_weights = generator_module._TCP_CONN_WEIGHTS
                if caller_provided_payload:
                    candidates = [
                        entry
                        for entry in generator_module._TCP_CONN_ENTRIES
                        if entry[0] not in {"S0", "S1", "SH", "SHR", "REJ"}
                    ]
                    if candidates:
                        tcp_entries = candidates
                        tcp_weights = [entry[1] for entry in candidates]
                entry = rng.choices(tcp_entries, weights=tcp_weights, k=1)[0]
                conn_state, _, history = entry
            else:
                conn_state = "S0"
                history = "S"
            if conn_state in ("S0", "REJ"):
                duration = None
                resp_bytes = 0
                # S0/REJ: Zeek orig_bytes/resp_bytes are payload (application
                # data), not packet overhead.  No handshake completed → zero payload.
                orig_bytes = 0
            elif conn_state in ("S1", "SH", "SHR"):
                # S1/SH/SHR = partial handshake, no application data transferred.
                # Zeek orig_bytes/resp_bytes are payload bytes (always 0 for
                # handshake-only states); IP-byte totals are computed from packet
                # counts + header overhead downstream.
                orig_bytes = 0
                resp_bytes = 0
                if duration is not None:
                    duration = rng.uniform(0.0, 0.5)
            elif conn_state in ("S2", "S3"):
                # S2/S3 = half-closed: connection established, one side sent FIN
                # but the other never replied. Some data transferred before close.
                if duration is not None:
                    duration = duration * rng.uniform(0.3, 0.8)
                if resp_bytes:
                    resp_bytes = int(resp_bytes * rng.uniform(0.2, 0.7))
            elif conn_state in ("RSTO", "RSTR"):
                if duration is not None:
                    duration = duration * rng.uniform(0.1, 0.5)
                if resp_bytes:
                    resp_bytes = int(resp_bytes * rng.uniform(0.1, 0.5))
            elif conn_state == "OTH":
                # OTH/Cc = midstream capture fragment — minimal data visible
                orig_bytes = rng.randint(0, 200)
                resp_bytes = rng.randint(0, 200)
                if duration is not None:
                    duration = rng.uniform(0.001, 0.5)

        if (
            not suppress_application_side_effects
            and proto == "tcp"
            and dst_port == 443
            and conn_state == "SF"
        ):
            # A completed TLS session with ssl.log/SNI evidence must include
            # at least a ClientHello and server handshake payload at conn.log
            # accounting level, even when the logical request body is empty.
            if http is not None:
                request_body_len = generator_module._http_context_flow_body_len(http, "request")
                response_body_len = generator_module._http_context_flow_body_len(http, "response")
                request_records = max(1, (request_body_len + 16_383) // 16_384)
                response_records = max(1, (response_body_len + 16_383) // 16_384)
                orig_bytes = (
                    request_body_len + rng.randint(350, 950) + request_records * rng.randint(22, 38)
                )
                resp_bytes = (
                    response_body_len
                    + rng.randint(1200, 5200)
                    + response_records * rng.randint(22, 38)
                )
            else:
                orig_bytes = max(orig_bytes or 0, rng.randint(180, 900))
                resp_bytes = max(resp_bytes or 0, rng.randint(900, 4500))
            tls_min_window = generator_module.get_timing_window(
                "network.tls_completed_min_duration",
                default_min_ms=800,
                default_max_ms=2500,
                default_position="after",
                default_class="same_observation",
            )
            tls_min_duration = tls_min_window.min_ms / 1000
            if duration is None or duration < tls_min_duration:
                max_extra = max(
                    0.016, min(0.65, (tls_min_window.max_ms - tls_min_window.min_ms) / 1000)
                )
                duration = tls_min_duration + rng.uniform(0.015, max_extra)
            else:
                duration += rng.expovariate(1.0 / 0.35)
                if rng.random() < 0.08:
                    duration += rng.uniform(1.5, 8.0)

        if not suppress_application_side_effects and http is not None and conn_state == "SF":
            http_timing = generator_module.get_timing_window(
                "source.zeek_http_request",
                default_min_ms=1,
                default_max_ms=35,
                default_position="after",
                default_class="same_observation",
            )
            http_min_duration = (http_timing.max_ms + 5) / 1000
            if duration is None or duration < http_min_duration:
                duration = http_min_duration + rng.uniform(0.0, 0.025)

        kerberos_has_response = conn_state not in {"S0", "S1", "SH", "SHR", "REJ", "OTH"} and (
            (resp_bytes or 0) > 0 or conn_state == "SF"
        )
        if kerberos_has_response and not suppress_application_side_effects:
            executor._emit_dc_audit_for_kerberos_connection(
                src_ip=src_ip,
                src_port=src_port,
                dst_ip=dst_ip,
                time=time,
                dst_port=dst_port,
                proto=proto,
                conn_state=conn_state,
                service=service or "",
                source_system=resolved_source_system,
            )

        duration_locked_to_dns_rtt = (
            service == "dns"
            and proto in ("udp", "tcp")
            and dst_port == 53
            and dns is not None
            and dns.rtt is not None
            and duration is not None
            and generator_module.math.isclose(duration, dns.rtt, rel_tol=0.0, abs_tol=1e-9)
        )
        duration = generator_module._jitter_default_connection_duration(
            duration,
            caller_provided_duration=caller_provided_duration or duration_locked_to_dns_rtt,
            seed_parts=(src_ip, src_port, dst_ip, dst_port, proto, service or "", time),
        )
        kerberos_audit_count = 0
        if (
            not suppress_application_side_effects
            and service == "kerberos"
            and dst_port == 88
            and proto in {"tcp", "udp"}
            and kerberos_dc_hostname
            and src_port is not None
            and src_port > 0
            and not (proto == "tcp" and conn_state in {"S0", "S1", "SH", "SHR", "REJ", "OTH"})
        ):
            kerberos_audit_count = executor._kerberos_audit_count_for_connection(
                src_ip,
                kerberos_dc_hostname,
                src_port,
                time,
            )
            if kerberos_audit_count > 0:
                conn_state = "SF"
                min_orig_bytes = kerberos_audit_count * rng.randint(260, 520)
                min_resp_bytes = kerberos_audit_count * rng.randint(320, 760)
                orig_bytes = max(orig_bytes or 0, min_orig_bytes)
                resp_bytes = max(resp_bytes or 0, min_resp_bytes)
                min_duration = kerberos_audit_count * rng.uniform(0.006, 0.022)
                duration = max(duration or 0.0, min_duration)
                if proto == "udp":
                    history = "Dd" * kerberos_audit_count
                else:
                    history = generator_module._tcp_success_history(rng)

        if proto == "tcp":
            orig_bytes, resp_bytes = generator_module._tcp_payload_bytes_consistent_with_history(
                orig_bytes,
                resp_bytes,
                history,
            )
            executor.state_manager.update_connection_bytes(
                conn_id,
                orig_bytes or 0,
                resp_bytes or 0,
            )

        # Calculate packet counts — enforce consistency with history
        if proto == "udp" and history:
            orig_pkts = max(
                history.count("D"), generator_module.math.ceil((orig_bytes or 0) / 1232)
            )
            resp_pkts = max(
                history.count("d"), generator_module.math.ceil((resp_bytes or 0) / 1232)
            )
            if orig_pkts > 0 and orig_bytes:
                orig_bytes = max(orig_bytes, orig_pkts * 28)
            if resp_pkts > 0 and resp_bytes:
                resp_bytes = max(resp_bytes, resp_pkts * 28)
            elif resp_pkts == 0:
                resp_bytes = 0
        elif proto == "tcp" and history and history != "-":
            orig_pkts, resp_pkts = generator_module._tcp_packet_counts_from_payload_and_history(
                orig_bytes,
                resp_bytes,
                history,
                rng,
            )
            if dst_port == 443 and conn_state == "SF":
                orig_pkts += rng.choices([0, 1, 2, 3, 5], weights=[45, 25, 15, 10, 5], k=1)[0]
                resp_pkts += rng.choices([0, 1, 2, 4, 8], weights=[35, 25, 20, 15, 5], k=1)[0]
        elif proto == "icmp":
            orig_pkts = 1
            resp_pkts = 1 if resp_bytes and resp_bytes > 0 else 0
        else:
            orig_pkts = max(1, (orig_bytes // 1500)) if orig_bytes else 1
            resp_pkts = max(1, (resp_bytes // 1500)) if resp_bytes else 0
        if kerberos_audit_count > 0:
            orig_pkts = max(orig_pkts, kerberos_audit_count)
            resp_pkts = max(resp_pkts, kerberos_audit_count)

        if proto == "udp" and dst_port == 123:
            orig_bytes, resp_bytes, duration = generator_module._ntp_payload_accounting(
                src_ip=src_ip,
                dst_ip=dst_ip,
                time=time,
                conn_state=conn_state,
                history=history,
                orig_bytes=orig_bytes,
                resp_bytes=resp_bytes,
                duration=duration,
            )
            orig_pkts = max(1, (history or "").count("D"))
            resp_pkts = (history or "").count("d") if (resp_bytes or 0) > 0 else 0

        if packet_overhead_bytes is not None:
            overhead = packet_overhead_bytes
        elif proto == "udp":
            overhead = rng.choices(
                generator_module._UDP_OVERHEAD_VALUES,
                weights=generator_module._UDP_OVERHEAD_WEIGHTS,
                k=1,
            )[0]
        elif proto == "icmp":
            overhead = 28
        else:
            overhead = rng.choices(
                generator_module._TCP_OVERHEAD_VALUES,
                weights=generator_module._TCP_OVERHEAD_WEIGHTS,
                k=1,
            )[0]
        # Zeek count fields are source-observed IP payload totals. TCP gets
        # per-side header/control texture; UDP/ICMP keeps protocol-specific
        # fixed accounting for source-native packet sizes.
        if proto == "tcp":
            orig_ip_bytes = generator_module._tcp_ip_byte_count(
                orig_bytes,
                orig_pkts,
                rng,
                overhead_override=packet_overhead_bytes,
            )
            resp_ip_bytes = generator_module._tcp_ip_byte_count(
                resp_bytes,
                resp_pkts,
                rng,
                overhead_override=packet_overhead_bytes,
            )
        else:
            orig_ip_bytes = (orig_bytes or 0) + orig_pkts * overhead
            resp_ip_bytes = (resp_bytes or 0) + resp_pkts * overhead

        ip_proto = 6 if proto == "tcp" else 17 if proto == "udp" else 1

        # Probabilistic missed_bytes for long TCP connections (~3% chance, more for bulk transfers)
        missed_bytes = 0
        if proto == "tcp" and duration and duration > 10.0 and rng.random() < 0.03:
            missed_bytes = rng.randint(500, 50000)

        if not preserve_start_time:
            time = generator_module._zeek_conn_observation_time(
                time,
                src_ip,
                src_port,
                dst_ip,
                dst_port,
                proto,
                service or "",
            )
        if proto == "icmp":
            time = executor._disambiguate_icmp_observation_time(
                src_ip,
                src_port,
                dst_ip,
                dst_port,
                time,
            )
        else:
            executor._remember_connection_tuple(
                src_ip,
                src_port,
                dst_ip,
                dst_port,
                proto,
                time,
                duration=duration,
            )
        if (
            dns is None
            and resolved_source_system is not None
            and "forward_proxy" in (resolved_source_system.roles or [])
            and hostname_is_external
            and proto == "tcp"
            and dst_port in (80, 443)
            and src_ip_is_local
            and not suppress_prereq_dns
        ):
            executor._emit_dns_lookup(
                src_ip,
                dst_ip,
                time - generator_module.timedelta(seconds=2),
                hostname=hostname,
                force_address=True,
                bypass_cache=True,
            )
        executor.state_manager.update_connection_interval(
            conn_id,
            time,
            time + generator_module.timedelta(seconds=duration) if duration is not None else None,
        )

        if pid > 0 and resolved_source_system:
            close_time = (
                time + generator_module.timedelta(seconds=max(0.0, duration))
                if duration is not None
                else None
            )
            if close_time is None:
                executor.state_manager.update_process_activity_time(
                    resolved_source_system.hostname,
                    pid,
                    time,
                )
            else:
                executor._remember_process_connection_hold(
                    system=resolved_source_system,
                    pid=pid,
                    close_time=close_time,
                )

        # Port-based service correction (Zeek detects service from payload, not scenario labels)
        _PORT_SERVICE = {
            80: "http",
            443: "ssl",
            22: "ssh",
            53: "dns",
            25: "smtp",
            587: "smtp",
            88: "kerberos",
            389: "ldap",
            445: "smb",
        }
        if (
            service
            and dst_port in _PORT_SERVICE
            and service != _PORT_SERVICE[dst_port]
            and not is_tcp_probe
        ):
            service = _PORT_SERVICE[dst_port]
        if (
            proto == "tcp"
            and conn_state in {"S0", "REJ", "S1", "SH", "SHR"}
            and service != "dns"
            and http is None
        ):
            service = ""
        if (
            proto == "udp"
            and conn_state in {"S0", "REJ", "OTH"}
            and (orig_bytes or 0) == 0
            and (resp_bytes or 0) == 0
            and service != "dns"
        ):
            service = ""

        # Phase 2: Resolve event-side ownership into an action-owned draft. The
        # canonical SecurityEvent is constructed only after the transaction is
        # finalized below.
        # Resolve source system for src_host (needed by eCAR emitter for hostname/routing)
        src_host_ctx = None
        if resolved_source_system:
            src_host_ctx = executor._build_host_context(resolved_source_system)

        # Resolve destination system for dst_host
        dst_host_ctx = None
        if hasattr(executor, "_ip_to_system") and dst_ip in executor._ip_to_system:
            dst_host_ctx = executor._build_host_context(executor._ip_to_system[dst_ip])
        elif executor.dispatcher and executor.dispatcher.visibility_engine:
            real_dst_ip = executor.dispatcher.visibility_engine._vip_to_real_ip.get(dst_ip)
            if real_dst_ip and real_dst_ip in executor._ip_to_system:
                dst_host_ctx = executor._build_host_context(executor._ip_to_system[real_dst_ip])

        # Resolve eCAR actor_id from initiating process (if pid is known)
        conn_actor_id = ""
        process_ctx = None
        if pid > 0 and resolved_source_system:
            conn_actor_id = executor.state_manager.get_process_object_id(
                resolved_source_system.hostname, pid
            )
            running = resolved_process or executor.state_manager.get_process(
                resolved_source_system.hostname, pid
            )
            if running is not None:
                process_ctx = generator_module.ProcessContext(
                    pid=pid,
                    parent_pid=running.parent_pid,
                    image=running.image,
                    command_line=running.command_line,
                    username=running.username,
                    logon_id=running.logon_id,
                    start_time=running.start_time,
                    parent_start_time=executor._lookup_parent_start_time(
                        resolved_source_system.hostname, running.parent_pid
                    ),
                )
            elif process_image:
                process_ctx = generator_module.ProcessContext(
                    pid=pid,
                    parent_pid=0,
                    image=process_image,
                    command_line="",
                    username="",
                )

        target_system = None
        if dst_host_ctx is not None and hasattr(executor, "_ip_to_system"):
            target_system = executor._ip_to_system.get(dst_host_ctx.ip)
        target_has_ssh = target_system is not None and "ssh" in {
            str(service_name).lower() for service_name in (target_system.services or [])
        }
        generic_ssh_preauth_pid: int | None = None
        if (
            target_system is not None
            and dst_host_ctx is not None
            and dst_host_ctx.os_category == "windows"
            and responding_pid <= 0
        ):
            responding_pid = executor._resolve_windows_inbound_service_pid(
                target_system,
                dst_port,
                time,
            )
        if (
            dst_host_ctx is not None
            and dst_host_ctx.os_category == "linux"
            and target_system is not None
            and proto == "tcp"
            and dst_port == 22
            and conn_state == "SF"
            and (service in {"", "ssh"} or target_has_ssh)
        ):
            if responding_pid <= 0:
                responding_pid = executor.ensure_linux_ssh_responder_process(
                    target_system=target_system,
                    time=time,
                    source_ip=src_ip,
                    source_port=src_port,
                    target_user=ssh_attempted_username,
                )
                generic_ssh_preauth_pid = responding_pid
            else:
                executor._remember_ssh_responder_pid(
                    src_ip, src_port, target_system.ip, responding_pid
                )

        event = _NetworkOccurrenceDraft(
            timestamp=time,
            parent_action_group_id=parent_action_group_id,
            src_host=src_host_ctx,
            dst_host=dst_host_ctx,
            local_only=local_only,
            process=process_ctx,
            network=NetworkContext(
                src_ip=src_ip,
                src_port=src_port,
                dst_ip=dst_ip,
                dst_port=dst_port,
                protocol=proto,
                service=service or "",
                zeek_uid=uid,
                conn_id=conn_id,
                duration=duration,
                orig_bytes=orig_bytes,
                resp_bytes=resp_bytes,
                orig_pkts=orig_pkts,
                resp_pkts=resp_pkts,
                orig_ip_bytes=orig_ip_bytes,
                resp_ip_bytes=resp_ip_bytes,
                conn_state=conn_state,
                history=history,
                local_orig=src_ip_is_local,
                local_resp=dst_ip_is_local,
                ip_proto=ip_proto,
                missed_bytes=missed_bytes,
                initiating_pid=pid,
                responding_pid=responding_pid,
                application_layer_only=http_application_layer_only,
            ),
            edr=generator_module.EdrContext(
                object_id=generator_module.stable_uuid(
                    "connection-edr",
                    src_ip,
                    src_port,
                    dst_ip,
                    dst_port,
                    proto,
                    time.isoformat(),
                ),
                actor_id=conn_actor_id,
            ),
        )

        # Caller-provided context overrides
        if ids is not None:
            event.ids = ids
        if email is not None:
            event.email = email
        if smtp is not None:
            event.smtp = smtp
        if request.ssl is not None:
            event.ssl = request.ssl
        if x509 is not None:
            event.x509 = x509
        if x509_chain:
            event.x509_chain = list(x509_chain)
        if http is not None:
            event.http = http
        if file_transfer is not None:
            event.file_transfer = file_transfer
        if file_transfers:
            event.file_transfers = list(file_transfers)
        if pe is not None:
            event.pe = pe
        if ocsp is not None:
            event.ocsp = ocsp
        if proxy is not None:
            event.proxy = proxy
        if firewall is not None:
            event.firewall = firewall

        # DNS context for Zeek dns.log fan-out
        if dns is not None:
            event.dns = dns
            if (
                event.firewall is not None
                and event.firewall.action == "deny"
                and proto in ("udp", "tcp")
                and dst_port == 53
            ):
                event.dns.rcode = "NOERROR"
                event.dns.rcode_num = 0
                event.dns.answers = []
                event.dns.TTLs = []
                event.dns.rtt = None
                event.network.conn_state = "S0"
                event.network.history = "D" if proto == "udp" else "S"
                event.network.duration = None
                event.network.resp_bytes = 0
                event.network.resp_pkts = 0
                event.network.resp_ip_bytes = None
            else:
                executor._normalize_dns_context_for_resolver(
                    event.dns,
                    resolver_ip=dst_ip,
                    time=time,
                )
                if executor._dns_observation_cache_hit_or_store(
                    src_ip=src_ip,
                    resolver_ip=dst_ip,
                    dns=event.dns,
                    time=time,
                ):
                    executor._last_connection_effective_dst_ip = dst_ip
                    return ""
        elif (
            service == "dns"
            and proto in ("udp", "tcp")
            and dst_port == 53
            and hostname
            and (hostname_was_explicit or dst_ip in dns_server_ips)
            and not is_fw_deny
        ):
            dns_query = (
                hostname
                or generator_module.REVERSE_DNS.get(dst_ip)
                or f"host-{dst_ip.replace('.', '-')}"
            )
            dns_is_internal = generator_module._dns_is_internal_name(
                dns_query,
                getattr(executor, "_ad_domain", ""),
            )
            dns_answers = [dst_ip] if resp_bytes else []
            event.dns = generator_module.DnsContext(
                query=dns_query,
                trans_id=rng.randint(1, 65535),
                qtype=1,
                query_type="A",
                rcode="NOERROR" if resp_bytes else "SERVFAIL",
                rcode_num=0 if resp_bytes else 2,
                answers=dns_answers,
                TTLs=executor._dns_observed_ttls(
                    resolver_ip=dst_ip,
                    query=dns_query,
                    qtype_name="A",
                    answers=dns_answers,
                    is_internal=dns_is_internal,
                    base_ttl=generator_module._dns_base_ttl(dns_query, dns_is_internal),
                    time=time,
                ),
                rtt=generator_module._dns_rtt(rng, dst_ip) if resp_bytes else None,
                AA=dns_is_internal,
            )
            if executor._dns_observation_cache_hit_or_store(
                src_ip=src_ip,
                resolver_ip=dst_ip,
                dns=event.dns,
                time=time,
            ):
                executor._last_connection_effective_dst_ip = dst_ip
                return ""
            if not resp_bytes:
                event.network.conn_state = "SF"
                event.network.history = "Dd"
                event.network.duration = rng.uniform(0.001, 0.03)
                event.network.resp_bytes = rng.randint(80, 220)
                if proto == "udp":
                    event.network.orig_pkts = event.network.history.count("D")
                    event.network.resp_pkts = event.network.history.count("d")
                    event.network.orig_bytes = max(
                        event.network.orig_bytes or 0,
                        event.network.orig_pkts * 28,
                    )
                    event.network.orig_ip_bytes = (
                        event.network.orig_bytes + event.network.orig_pkts * overhead
                    )
                    event.network.resp_ip_bytes = (
                        event.network.resp_bytes + event.network.resp_pkts * overhead
                    )
                else:
                    event.network.resp_pkts = max(event.network.resp_pkts or 0, 1)
                    event.network.resp_ip_bytes = event.network.resp_bytes + overhead
                executor.state_manager.update_connection_bytes(
                    event.network.conn_id,
                    event.network.orig_bytes or 0,
                    event.network.resp_bytes or 0,
                )
            if event.dns.rtt is not None:
                event.network.duration = event.dns.rtt

        # Proxy context: attach only for established outbound internet traffic.
        # Forward proxies only see egress that completes (not blocked/denied flows).
        if (
            not local_only
            and service in ("ssl", "http")
            and dst_port in (80, 443)
            and event.proxy is None
            and not generator_module._is_private_ip(dst_ip)
            and conn_state not in ("S0", "REJ", "S1", "SH", "SHR", "RSTO", "RSTR")
        ):
            proxy_routes = getattr(executor, "_proxy_routes", {})
            chain = proxy_routes.get(src_ip)
            if chain:
                from evidenceforge.events.contexts import ProxyContext

                proxy_sys = chain[0]
                proxy_fqdn = getattr(proxy_sys, "hostname", "")
                # Build proxy FQDN from hostname + domain
                ad_domain = getattr(executor, "_ad_domain", "")
                if ad_domain and "." not in proxy_fqdn:
                    proxy_fqdn = f"{proxy_fqdn}.{ad_domain}"
                # Hostname was resolved once at the top of generate_connection().
                proxy_hostname = hostname
                if proxy_hostname is None and dns is not None and dns.query:
                    proxy_hostname = dns.query
                if proxy_hostname is None:
                    proxy_hostname = generator_module.REVERSE_DNS.get(dst_ip)
                if proxy_hostname is None:
                    proxy_hostname = generator_module._generate_random_hostname(
                        generator_module._get_rng(), dst_ip
                    )
                # Suppressed hostname → use raw IP for proxy logging
                if proxy_hostname == "":
                    proxy_hostname = dst_ip
                from evidenceforge.generation.activity.dns_registry import get_domain_tags
                from evidenceforge.generation.activity.proxy_uri import pick_proxy_uri

                domain_tags = get_domain_tags(proxy_hostname)
                user_agent = ""

                # When a pre-built HttpContext exists (from browsing session
                # generator), derive proxy fields from it.  The proxy emitter
                # handles CONNECT tunnel deduplication automatically.
                if event.http is not None:
                    from evidenceforge.generation.activity.http_content import (
                        normalize_mime_type_for_path,
                    )

                    scheme = "https" if dst_port == 443 else "http"
                    proxy_method = event.http.method
                    url = f"{scheme}://{proxy_hostname}{event.http.uri}"
                    if event.http.resp_mime_types or event.http.status_code == 304:
                        proxy_content_type = normalize_mime_type_for_path(
                            event.http.uri,
                            (
                                event.http.resp_mime_types[0]
                                if event.http.resp_mime_types
                                else "text/html"
                            ),
                        )
                    else:
                        proxy_content_type = "text/html"
                    proxy_ua_override = None  # session UA is already on HttpContext
                    user_agent = event.http.user_agent
                    proxy_referrer = event.http.referrer
                elif dst_port == 443:
                    # Legacy single-connection HTTPS path
                    _src_os = (
                        generator_module._get_os_category(source_system.os)
                        if source_system
                        else None
                    )
                    (
                        path,
                        proxy_content_type,
                        proxy_method,
                        proxy_ua_override,
                        referrer_policy,
                    ) = pick_proxy_uri(
                        generator_module._get_rng(),
                        proxy_hostname,
                        domain_tags,
                        source_os=_src_os,
                        source_system_type=getattr(source_system, "type", None),
                    )
                    url = f"https://{proxy_hostname}{path}"
                    from evidenceforge.generation.activity.referrer import pick_referrer

                    proxy_referrer = (
                        ""
                        if referrer_policy == "none"
                        else pick_referrer(rng, proxy_hostname, context="general", port=443)
                    )
                else:
                    _src_os = (
                        generator_module._get_os_category(source_system.os)
                        if source_system
                        else None
                    )
                    (
                        path,
                        proxy_content_type,
                        proxy_method,
                        proxy_ua_override,
                        referrer_policy,
                    ) = pick_proxy_uri(
                        generator_module._get_rng(),
                        proxy_hostname,
                        domain_tags,
                        source_os=_src_os,
                        source_system_type=getattr(source_system, "type", None),
                    )
                    url = f"http://{proxy_hostname}{path}"
                    from evidenceforge.generation.activity.referrer import pick_referrer

                    proxy_referrer = (
                        ""
                        if referrer_policy == "none"
                        else pick_referrer(rng, proxy_hostname, context="general", port=80)
                    )
                from evidenceforge.generation.activity.proxy_uri import is_browser_like_proxy_domain

                apply_domain_user_agent = event.http is None or (
                    not generator_module._is_tool_http_user_agent(event.http.user_agent)
                    and not is_browser_like_proxy_domain(proxy_hostname, domain_tags=domain_tags)
                )
                user_agent = executor._proxy_user_agent_for_context(
                    rng,
                    source_system,
                    hostname=proxy_hostname,
                    domain_tags=domain_tags,
                    existing_user_agent=user_agent,
                    override_user_agent=proxy_ua_override,
                    apply_domain_override=apply_domain_user_agent,
                )
                proxy_referrer = generator_module._source_native_http_referrer(
                    user_agent,
                    proxy_referrer,
                    request_scheme="https" if dst_port == 443 else "http",
                    request_port=dst_port,
                )
                cache_roll = rng.random()
                proxy_cacheable = generator_module._proxy_request_allows_cache_hit(
                    method=proxy_method,
                    url=url,
                    content_type=proxy_content_type,
                    domain_tags=domain_tags,
                )
                if event.http is not None:
                    if event.http.status_code == 304:
                        cache_result = "REVALIDATED"
                    elif proxy_cacheable and cache_roll < 0.30 and event.http.status_code < 400:
                        cache_result = "HIT"
                    else:
                        cache_result = "MISS"
                elif proxy_cacheable and cache_roll < 0.30:
                    cache_result = "HIT"
                elif cache_roll < 0.91:
                    cache_result = "MISS"
                elif cache_roll < 0.945:
                    cache_result = "DENIED"
                elif cache_roll < 0.975:
                    cache_result = "AUTH_REQUIRED"
                else:
                    cache_result = "GATEWAY_ERROR"
                # Proxy sc_bytes/cs_bytes are source-side accounting fields:
                # payload plus HTTP/proxy headers for allowed responses,
                # or proxy-generated error pages for failures.
                _cs = (orig_bytes or 0) + rng.randint(*generator_module._PROXY_CS_OVERHEAD)
                _response_bytes = (
                    event.http.response_body_len if event.http is not None else (resp_bytes or 0)
                )
                if cache_result == "DENIED":
                    _sc = rng.randint(500, 2000)  # proxy error page
                elif cache_result == "AUTH_REQUIRED":
                    _sc = rng.randint(300, 1200)
                elif cache_result == "GATEWAY_ERROR":
                    _sc = rng.randint(250, 1800)
                elif cache_result == "HIT":
                    _sc = _response_bytes + rng.randint(*generator_module._PROXY_SC_OVERHEAD)
                else:
                    _sc = _response_bytes + rng.randint(*generator_module._PROXY_SC_OVERHEAD)
                proxy_status_code = (
                    event.http.status_code
                    if event.http is not None
                    else {
                        "DENIED": 403,
                        "AUTH_REQUIRED": 407,
                        "GATEWAY_ERROR": rng.choice([502, 503, 504]),
                    }.get(cache_result, 200)
                )
                event.proxy = ProxyContext(
                    client_ip=src_ip,
                    username=executor._proxy_username_for_source(
                        source_system=source_system,
                        user_agent=user_agent,
                        cache_result=cache_result,
                        hostname=proxy_hostname,
                        time=event.timestamp,
                    ),
                    method=proxy_method,
                    url=url,
                    host=proxy_hostname,
                    status_code=proxy_status_code,
                    sc_bytes=_sc,
                    cs_bytes=_cs,
                    time_taken=generator_module._proxy_time_taken_ms(
                        duration,
                        rng,
                        method=proxy_method,
                        status_code=proxy_status_code,
                        cache_result=cache_result,
                    ),
                    user_agent=user_agent,
                    content_type=proxy_content_type,
                    cache_result=cache_result,
                    referrer=proxy_referrer,
                    proxy_fqdn=proxy_fqdn,
                    proxy_action=generator_module._proxy_action_for_context(
                        method=proxy_method,
                        url=url,
                        status_code=proxy_status_code,
                        cache_result=cache_result,
                        dst_port=dst_port,
                    ),
                )

        # Zeek protocol-layer contexts: populate SSL/HTTP/files for fan-out
        # Skip for local-only events (no network sensor will see them)
        rng = generator_module._get_rng()
        if (
            not suppress_application_side_effects
            and not local_only
            and service == "ssl"
            and proto == "tcp"
            and conn_state == "SF"
        ):
            executor._attach_ssl_context(
                event,
                hostname=tls_hostname,
                dns=dns,
                dst_ip=dst_ip,
                rng=rng,
                allow_failure=not caller_provided_conn_state,
            )
        if (
            proto == "tcp"
            and event.network.conn_state in {"S0", "REJ", "SH", "SHR"}
            and event.network.service in {"http", "ssl"}
            and event.http is None
            and event.ssl is None
        ):
            event.network.service = ""

        elif (
            not local_only
            and not suppress_application_side_effects
            and service == "http"
            and proto == "tcp"
            and conn_state == "SF"
            and event.http is None  # Skip auto-generation if caller provided HttpContext
        ):
            _USER_AGENTS_WINDOWS = [
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0",
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) Gecko/20100101 Firefox/120.0",
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 OPR/106.0.0.0",
            ]
            _USER_AGENTS_LINUX = [
                "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
                "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0",
                "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
                "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0",
                "curl/7.88.1",
                "python-requests/2.31.0",
                "Wget/1.21.3",
            ]
            if source_system and generator_module._get_os_category(source_system.os) == "linux":
                ua = rng.choice(_USER_AGENTS_LINUX)
            else:
                ua = rng.choice(_USER_AGENTS_WINDOWS)
            # Use the already-resolved hostname for HTTP Host header and URI templates.
            # Honor hostname="" (suppressed) — use raw IP instead of REVERSE_DNS.
            host = (
                hostname
                if hostname is not None
                else generator_module.REVERSE_DNS.get(dst_ip, dst_ip)
            )
            if host == "":
                host = dst_ip
            if dst_port not in (80, 443):
                host = f"{host}:{dst_port}"
            from evidenceforge.generation.activity.dns_registry import get_domain_tags
            from evidenceforge.generation.activity.http_content import (
                apply_transfer_size_variance,
                coerce_response_size_for_mime,
                http_status_message,
                is_stable_resource_path,
                response_mime_types_for_status,
                response_size_for_status,
            )
            from evidenceforge.generation.activity.proxy_uri import (
                pick_proxy_uri,
                plaintext_http_redirect_status,
            )

            web_host = (
                hostname
                if hostname is not None
                else generator_module.REVERSE_DNS.get(dst_ip, dst_ip)
            )
            if web_host == "":
                web_host = dst_ip
            web_domain_tags = get_domain_tags(web_host)
            _src_os_http = (
                generator_module._get_os_category(source_system.os) if source_system else None
            )
            uri, mime_type, http_method, http_ua_override, http_referrer_policy = pick_proxy_uri(
                rng,
                web_host,
                web_domain_tags,
                source_os=_src_os_http,
                source_system_type=getattr(source_system, "type", None),
            )
            ua = executor._proxy_user_agent_for_context(
                rng,
                source_system,
                hostname=web_host,
                domain_tags=web_domain_tags,
                existing_user_agent="",
                override_user_agent=http_ua_override,
                apply_domain_override=True,
            )
            redirect_status = plaintext_http_redirect_status(
                web_host,
                port=dst_port,
                path=uri,
                dst_ip=dst_ip,
            )
            if redirect_status is not None:
                status_code = redirect_status
                status_msg = http_status_message(status_code)
            else:
                status_code, status_msg = generator_module._get_http_status(dst_ip, uri)

            if status_code in {204, 304}:
                resp_body_len = 0
            else:
                if status_code >= 300 or is_stable_resource_path(uri):
                    resp_body_len = apply_transfer_size_variance(
                        response_size_for_status(status_code, host, uri),
                        status_code=status_code,
                        host=host,
                        uri=uri,
                        content_type=mime_type,
                        variant_key=f"{src_ip}:{ua}",
                    )
                else:
                    resp_body_len = coerce_response_size_for_mime(rng, mime_type, resp_bytes)
            if event.network.conn_state == "SF" and resp_body_len > (event.network.resp_bytes or 0):
                event.network.resp_bytes = resp_body_len
                min_resp_pkts = max(1, generator_module.math.ceil(resp_body_len / 1460))
                event.network.resp_pkts = max(event.network.resp_pkts or 0, min_resp_pkts)
                min_resp_ip_bytes = resp_body_len + event.network.resp_pkts * 40
                event.network.resp_ip_bytes = max(
                    event.network.resp_ip_bytes or 0,
                    min_resp_ip_bytes,
                )
            from evidenceforge.generation.activity.referrer import pick_referrer

            _http_referer = (
                ""
                if http_referrer_policy == "none"
                else pick_referrer(rng, host, context="general", port=dst_port)
            )
            _http_referer = generator_module._source_native_http_referrer(
                ua,
                _http_referer,
                request_scheme="https" if dst_port == 443 else "http",
                request_port=dst_port,
            )
            event.http = generator_module.HttpContext(
                method=http_method,
                host=host,
                uri=uri,
                version="1.1",
                user_agent=ua,
                request_body_len=rng.randint(50, 2000) if http_method == "POST" else 0,
                response_body_len=resp_body_len,
                status_code=status_code,
                status_msg=status_msg,
                referrer=_http_referer,
                resp_mime_types=response_mime_types_for_status(
                    status_code,
                    mime_type,
                    resp_body_len,
                    method=http_method,
                ),
                tags=[],
            )

        if not suppress_application_side_effects:
            generator_module._attach_http_response_file_transfer(
                event,
                dst_ip=dst_ip,
                rng=rng,
                probabilistic_file_analysis=not caller_supplied_http,
            )

        if (
            not suppress_application_side_effects
            and event.file_transfer is None
            and service == "smb"
            and proto == "tcp"
            and dst_port == 445
            and event.network.conn_state == "SF"
        ):
            transfer_bytes = max(event.network.orig_bytes or 0, event.network.resp_bytes or 0)
            smb_server = ""
            if event.dst_host is not None:
                smb_server = event.dst_host.hostname or event.dst_host.fqdn
            if not smb_server:
                smb_server = generator_module.REVERSE_DNS.get(
                    event.network.dst_ip, event.network.dst_ip
                )
            smb_user = getattr(resolved_source_system, "assigned_user", "") or "Public"
            event.file_transfer = SmbFileTransferMetadataActionBundle(
                SmbFileTransferMetadataRequest(
                    src_ip=event.network.src_ip,
                    dst_ip=event.network.dst_ip,
                    transfer_bytes=transfer_bytes,
                    duration=event.network.duration or 0.0,
                    server=smb_server,
                    user=smb_user,
                    is_orig=(event.network.orig_bytes or 0) >= (event.network.resp_bytes or 0),
                ),
                rng,
            ).execute()

        # NTP context for Zeek ntp.log fan-out. Zeek ntp.log records server response
        # fields, so only attach the context when the matching conn.log row has a
        # responder payload.
        if (
            not local_only
            and service == "ntp"
            and proto == "udp"
            and event.network.conn_state == "SF"
            and (event.network.resp_pkts or 0) > 0
            and (event.network.resp_bytes or 0) > 0
        ):
            from evidenceforge.events.contexts import NtpContext

            ntp_rng = generator_module._get_rng()
            ntp_epoch = time.timestamp()
            # Stratum-aware timing via log-normal distribution
            stratum, ref_id = generator_module._ntp_stratum_and_ref_id(dst_ip)
            association = executor._ntp_association_profile(event.network.src_ip, dst_ip)
            poll_seconds = float(association["poll"])
            last_parser_time = executor._ntp_last_parser_times.get((event.network.src_ip, dst_ip))
            parser_gap = (
                None
                if last_parser_time is None
                else (event.timestamp - last_parser_time).total_seconds()
            )
            if parser_gap is None or parser_gap >= generator_module._ntp_parser_min_gap_seconds(
                poll_seconds
            ):
                executor._ntp_last_parser_times[(event.network.src_ip, dst_ip)] = event.timestamp
                server_response = executor._ntp_server_response_profile(dst_ip)
                observed_response = generator_module._ntp_observed_response_fields(
                    server_response,
                    dst_ip=dst_ip,
                    event_time=event.timestamp,
                )
                _ntp_mean_ms, _ntp_sigma = generator_module._NTP_STRATUM_TIMING.get(
                    stratum, (10.0, 0.7)
                )
                _ntp_mu = generator_module.math.log(_ntp_mean_ms) - (_ntp_sigma**2) / 2
                rtt_sec = ntp_rng.lognormvariate(_ntp_mu, _ntp_sigma) / 1000.0
                proc_sec = (
                    ntp_rng.lognormvariate(generator_module.math.log(0.5) - 0.3**2 / 2, 0.3)
                    / 1000.0
                )
                ntp_jitter = ntp_rng.uniform(-0.005, 0.005)
                ntp_duration = max(0.001, rtt_sec + proc_sec + ntp_rng.uniform(0.001, 0.008))
                if event.network.duration is None or event.network.duration < ntp_duration:
                    event.network.duration = ntp_duration
                event.ntp = NtpContext(
                    version=int(association["version"]),
                    mode=4,  # server response
                    stratum=stratum,
                    poll=poll_seconds,
                    precision=observed_response["precision"],
                    root_delay=observed_response["root_delay"],
                    root_disp=observed_response["root_disp"],
                    ref_id=ref_id,
                    ref_ts=round(ntp_epoch - ntp_rng.uniform(30, 300), 6),
                    org_ts=round(ntp_epoch + ntp_jitter, 6),
                    rec_ts=round(ntp_epoch + ntp_jitter + rtt_sec, 6),
                    xmt_ts=round(ntp_epoch + ntp_jitter + rtt_sec + proc_sec, 6),
                )
            else:
                event.network.service = ""

        # Enforce conn_state/HTTP consistency: if HTTP context exists,
        # the connection must have completed successfully (SF). A connection
        # with a handshake-only, reset, or half-close state cannot have served
        # a Zeek HTTP transaction with request/response body accounting.
        if (
            event.http is not None
            and event.network.protocol == "tcp"
            and event.network.conn_state != "SF"
        ):
            event.network.conn_state = "SF"
            event.network.history = generator_module._tcp_success_history(rng)
            if event.network.duration is None:
                event.network.duration = rng.uniform(0.01, 2.0)

        if (
            event.http is not None
            and event.network.protocol == "tcp"
            and event.network.conn_state == "SF"
        ):
            http_timing = generator_module.get_timing_window(
                "source.zeek_http_request",
                default_min_ms=1,
                default_max_ms=35,
                default_position="after",
                default_class="same_observation",
            )
            http_min_duration = (http_timing.max_ms + 5) / 1000
            if event.network.duration is None or event.network.duration < http_min_duration:
                event.network.duration = http_min_duration + rng.uniform(0.0, 0.025)

        if event.network.protocol == "tcp" and event.network.conn_state == "SF":
            if event.http is not None:
                method = (event.http.method or "GET").upper()
                if event.network.service == "http" and method != "CONNECT":
                    event.network.orig_bytes, event.network.resp_bytes = (
                        generator_module._http_flow_payload_bytes(event.http)
                    )
                else:
                    request_body_len = generator_module._http_context_flow_body_len(
                        event.http, "request"
                    )
                    response_body_len = generator_module._http_context_flow_body_len(
                        event.http, "response"
                    )
                    request_overhead = rng.randint(180, 620)
                    response_overhead = rng.randint(180, 900)
                    if event.http.status_code in {204, 304} or method == "HEAD":
                        response_overhead = rng.randint(90, 360)
                    event.network.orig_bytes = max(
                        event.network.orig_bytes or 0,
                        request_body_len + request_overhead,
                        rng.randint(180, 520),
                    )
                    event.network.resp_bytes = max(
                        event.network.resp_bytes or 0,
                        response_body_len + response_overhead,
                        rng.randint(90, 450),
                    )
            if event.network.service == "ssl" and not suppress_application_side_effects:
                event.network.orig_bytes = max(event.network.orig_bytes or 0, rng.randint(180, 900))
                event.network.resp_bytes = max(
                    event.network.resp_bytes or 0, rng.randint(900, 4500)
                )
            event.network.orig_pkts, event.network.resp_pkts = (
                generator_module._tcp_packet_counts_from_payload_and_history(
                    event.network.orig_bytes,
                    event.network.resp_bytes,
                    event.network.history,
                    rng,
                )
            )
            if event.network.service == "ssl" and not suppress_application_side_effects:
                event.network.orig_pkts += rng.choices(
                    [0, 1, 2, 3, 5],
                    weights=[45, 25, 15, 10, 5],
                    k=1,
                )[0]
                event.network.resp_pkts += rng.choices(
                    [0, 1, 2, 4, 8],
                    weights=[35, 25, 20, 15, 5],
                    k=1,
                )[0]
            event.network.orig_ip_bytes = generator_module._tcp_ip_byte_count(
                event.network.orig_bytes,
                event.network.orig_pkts,
                rng,
            )
            event.network.resp_ip_bytes = generator_module._tcp_ip_byte_count(
                event.network.resp_bytes,
                event.network.resp_pkts,
                rng,
            )
            executor.state_manager.update_connection_bytes(
                event.network.conn_id,
                event.network.orig_bytes or 0,
                event.network.resp_bytes or 0,
            )

        if (
            not suppress_application_side_effects
            and not local_only
            and event.network.service == "ssl"
            and event.network.conn_state == "SF"
            and event.ssl is None
        ):
            executor._attach_ssl_context(
                event,
                hostname=tls_hostname,
                dns=dns,
                dst_ip=dst_ip,
                rng=rng,
                allow_failure=False,
            )

        if generator_module._align_tcp_network_payload_with_history(event.network, rng):
            executor.state_manager.update_connection_bytes(
                event.network.conn_id,
                event.network.orig_bytes or 0,
                event.network.resp_bytes or 0,
            )
        if preserve_explicit_payload and generator_module._preserve_explicit_tcp_payload_overrides(
            event.network,
            explicit_orig_bytes=explicit_orig_bytes,
            explicit_resp_bytes=explicit_resp_bytes,
            rng=rng,
        ):
            executor.state_manager.update_connection_bytes(
                event.network.conn_id,
                event.network.orig_bytes or 0,
                event.network.resp_bytes or 0,
            )
        if executor._ensure_tls_conn_covers_certificate_bytes(event):
            close_time = (
                event.timestamp
                + generator_module.timedelta(seconds=max(0.0, event.network.duration or 0.0))
                if event.network.duration is not None
                else None
            )
            executor.state_manager.update_connection_interval(
                event.network.conn_id,
                event.timestamp,
                close_time,
            )
            executor.state_manager.update_connection_bytes(
                event.network.conn_id,
                event.network.orig_bytes or 0,
                event.network.resp_bytes or 0,
            )
            if pid > 0 and resolved_source_system is not None:
                executor._remember_process_connection_hold(
                    system=resolved_source_system,
                    pid=pid,
                    close_time=close_time,
                )

        executor._repair_explicit_proxy_listener_process_attribution(
            event,
            source_system=resolved_source_system,
            time=time,
        )
        executor._repair_browser_http_process_attribution(
            event,
            source_system=resolved_source_system,
            time=time,
        )
        pid = event.network.initiating_pid
        process_ctx = event.process
        if pid > 0 and resolved_source_system is not None and process_ctx is not None:
            adjusted_time = executor._clamp_after_visible_process_create(
                resolved_source_system,
                pid,
                event.timestamp,
                "source.windows_wfp_connection",
            )
            if adjusted_time > event.timestamp:
                if preserve_start_time:
                    executor._set_connection_process_context(
                        event,
                        source_system=resolved_source_system,
                        pid=-1,
                    )
                    pid = -1
                    process_ctx = None
                else:
                    event.timestamp = adjusted_time
                    time = adjusted_time

        # Finalize the canonical source-visible interval only after every protocol,
        # payload, and process-visibility adjustment has settled. Dispatch creates
        # source-local event copies with collection delay, so the immutable interval
        # must live on NetworkContext rather than be re-derived from those copies.
        event.network.source_visible_start_time = event.timestamp
        event.network.source_visible_close_time = (
            event.timestamp + generator_module.timedelta(seconds=max(0.0, event.network.duration))
            if event.network.duration is not None
            else None
        )
        executor.state_manager.update_connection_interval(
            event.network.conn_id,
            event.network.source_visible_start_time,
            event.network.source_visible_close_time,
        )
        canonical_start = event.network.source_visible_start_time
        canonical_close = event.network.source_visible_close_time
        phase_times: list[tuple[str, datetime]] = [("transport_start", canonical_start)]
        if any((event.dns, event.http, event.ssl, event.smtp, event.proxy)):
            phase_times.append(("application_request", canonical_start))
        if (
            canonical_close is not None
            and (event.network.resp_bytes or 0) > 0
            and canonical_close > canonical_start
        ):
            response_time = canonical_start + timedelta(
                seconds=(canonical_close - canonical_start).total_seconds() * 0.75
            )
            phase_times.append(("application_response", response_time))
        if canonical_close is not None:
            phase_times.append(("transport_close", canonical_close))
        if event.firewall is not None and event.firewall.action == "deny":
            transaction_outcome = "denied"
        elif event.network.conn_state in {"SF", "S1", "S2", "S3", "OTH"}:
            transaction_outcome = "success"
        else:
            transaction_outcome = "failure"
        event.network.finalize_transaction(
            request.stable_id,
            hostname=hostname or event.network.dst_ip,
            outcome=transaction_outcome,
            phase_times=tuple(phase_times),
        )
        event = event.build_event(generator_module)

        # Automatic weird.log synthesis is intentionally disabled for now. The
        # Zeek weird type space is broad and state-sensitive; poorly matched
        # weird rows are more damaging than sparse weird.log output. Explicit
        # WeirdContext events still render through ZeekWeirdEmitter. Keep one
        # RNG draw to avoid reshaping unrelated deterministic traffic choices.
        if not generator_module._AUTO_WEIRD_ENABLED:
            rng.random()

        if (
            http_persistent_key is not None
            and event.http is not None
            and event.network.conn_state == "SF"
            and not event.network.application_layer_only
            and event.network.duration is not None
        ):
            executor._http_persistent_connections[http_persistent_key] = (
                generator_module._HttpPersistentConnection(
                    close_deadline=event.timestamp
                    + generator_module.timedelta(seconds=event.network.duration),
                    uid=uid,
                    conn_id=event.network.conn_id,
                    src_port=src_port,
                    next_trans_depth=max(2, event.http.trans_depth + 1),
                    orig_budget=max(
                        event.network.orig_bytes or 0, event.http.request_body_len or 0
                    ),
                    resp_budget=max(
                        event.network.resp_bytes or 0, event.http.response_body_len or 0
                    ),
                    used_orig=event.http.request_body_len or 0,
                    used_resp=event.http.response_body_len or 0,
                )
            )

        # Phase 3: Dispatch to matching emitters (visibility handled by dispatcher)
        if not event.network.application_layer_only and event.network.src_port > 0:
            executor._last_connection_effective_tuple = (
                event.network.src_ip,
                event.network.src_port,
                event.network.dst_ip,
                event.network.dst_port,
                event.network.protocol,
            )
            executor._last_connection_effective_time = event.timestamp
        executor.dispatcher.dispatch(event)
        if generic_ssh_preauth_pid is not None and target_system is not None:
            executor._emit_generic_ssh_preauth_failure_syslog(
                target_system=target_system,
                target_host=dst_host_ctx,
                time=event.timestamp,
                source_ip=src_ip,
                source_port=src_port,
                sshd_pid=generic_ssh_preauth_pid,
                attempted_username=ssh_attempted_username,
                duration=event.network.duration,
            )
        generator_module.logger.debug(
            f"Generated connection: {src_ip} -> {dst_ip}:{dst_port} (UID: {uid})"
        )

        # Emit 5156 (WFP connection) on Windows source hosts when process ownership is known.
        # Unknown ownership is not PID 4 by default; rendering it as System makes ordinary
        # user/proxy flows look kernel-originated.
        wfp_system = resolved_source_system or source_system
        wfp_application = event.process.image if event.process is not None else None
        if (
            wfp_system
            and generator_module._get_os_category(wfp_system.os) == "windows"
            and (pid > 0 or wfp_application is not None)
            and not event.network.application_layer_only
        ):
            executor.generate_wfp_connection(
                system=wfp_system,
                time=time,
                src_ip=src_ip,
                src_port=src_port,
                dst_ip=dst_ip,
                dst_port=dst_port,
                protocol=proto,
                pid=pid,
                application=wfp_application,
            )

        if (
            target_system is not None
            and dst_host_ctx is not None
            and dst_host_ctx.os_category == "windows"
            and not event.network.application_layer_only
            and executor._should_emit_windows_inbound_wfp(event, target_system)
        ):
            inbound_pid = event.network.responding_pid
            inbound_application = executor._lookup_process_name(
                target_system.hostname,
                inbound_pid,
                "windows",
            )
            executor.generate_wfp_connection(
                system=target_system,
                time=time,
                src_ip=src_ip,
                src_port=src_port,
                dst_ip=target_system.ip,
                dst_port=dst_port,
                protocol=proto,
                pid=inbound_pid,
                application=inbound_application,
            )

        if pid > 0 and resolved_source_system is not None and process_ctx is not None:
            running = executor.state_manager.get_process(resolved_source_system.hostname, pid)
            if executor._process_termination_recorded(
                resolved_source_system.hostname,
                pid,
                running.start_time if running is not None else None,
            ):
                return uid
            lifetime = (
                executor._foreground_process_lifetime_for_attribution(
                    resolved_source_system, running
                )
                if running is not None
                else None
            )
            if lifetime is not None and generator_module.re.match(
                r"^[a-zA-Z0-9._$-]+$", running.username
            ):
                known_users = getattr(executor, "_users_by_username", {})
                process_user = known_users.get(running.username) or generator_module.User(
                    username=running.username,
                    full_name=running.username,
                    email=f"{running.username}@example.local",
                )
                term_rng = generator_module.random.Random(
                    generator_module._stable_seed(
                        "connection_owned_foreground_termination:"
                        f"{resolved_source_system.hostname}:{pid}:{time.isoformat()}"
                    )
                )
                min_delay = min(max(lifetime[0], 0.5), 4.0)
                max_delay = max(min_delay + 0.5, min(lifetime[1] + 8.0, 45.0))
                executor.generate_process_termination(
                    user=process_user,
                    system=resolved_source_system,
                    time=time
                    + generator_module.timedelta(seconds=term_rng.uniform(min_delay, max_delay)),
                    pid=pid,
                    process_name=running.image,
                    logon_id=running.logon_id,
                )

        return uid
