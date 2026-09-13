# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Typed storyline periodic handlers."""

from __future__ import annotations

import itertools
import random
from dataclasses import replace
from datetime import timedelta
from typing import TYPE_CHECKING, Any

from evidenceforge.generation.activity.http_content import (
    normalize_mime_type_for_path,
)
from evidenceforge.generation.activity.network_params import activity_dns_resolver_ips
from evidenceforge.models.scenario import (
    BeaconEventSpec,
    BeaconHttpSequenceEntry,
    DgaQueriesEventSpec,
    DnsQueryEventSpec,
    DnsTunnelEventSpec,
)
from evidenceforge.utils.rng import _stable_seed
from evidenceforge.utils.time import ensure_utc, parse_duration

from .context import TypedEventContext

if TYPE_CHECKING:
    from evidenceforge.generation.engine.storyline import StorylineMixin


def handle_beacon(
    self: StorylineMixin, spec: BeaconEventSpec, context: TypedEventContext
) -> dict[str, Any] | None:
    """Execute the beacon evidence path using the existing runtime owners."""
    from evidenceforge.generation.engine.storyline_helpers.http import (
        _c2_http_response_size,
        _is_c2_http_request,
        _size_storyline_connection,
        _storyline_http_response_body_len,
    )
    from evidenceforge.generation.engine.storyline_helpers.ids import (
        _build_ids_alert_contexts,
        _ids_attachment_ground_truth,
    )
    from evidenceforge.generation.engine.storyline_helpers.periodic import (
        _entry_value,
        _iter_periodic_ticks,
        _range_or_value,
        _render_beacon_template,
        _weighted_profile_entry,
    )

    actor = context.actor
    system = context.system
    time = context.time
    activity = context.activity
    rng = context.rng
    malicious_event = context.malicious_event
    start = self._parse_storyline_time(spec.start_time) if spec.start_time else time
    interval_sec = parse_duration(spec.interval).total_seconds()
    duration_sec = None
    count = spec.count
    if spec.duration is not None:
        duration_sec = parse_duration(spec.duration).total_seconds()
    elif spec.end_time is not None:
        end_dt = self._parse_storyline_time(spec.end_time)
        duration_sec = (end_dt - start).total_seconds()

    beacon_profile: dict[str, Any] | None = None
    profile_http_sequence: list[dict[str, Any]] = []
    profile_user_agents: list[str] = []
    profile_dns_resolution = None
    if spec.profile:
        from evidenceforge.config.beacon_profiles import get_profile

        beacon_profile = get_profile(spec.profile)
        if beacon_profile is None:
            raise ValueError(f"Unknown beacon profile: {spec.profile}")
        raw_profile_sequence = beacon_profile.get("http_sequence", [])
        if isinstance(raw_profile_sequence, list):
            profile_http_sequence = [
                entry for entry in raw_profile_sequence if isinstance(entry, dict)
            ]
        raw_profile_user_agents = beacon_profile.get("user_agents", [])
        if isinstance(raw_profile_user_agents, list):
            profile_user_agents = [str(value) for value in raw_profile_user_agents if value]
        profile_dns_resolution = beacon_profile.get("dns_resolution")
    explicit_http_sequence: list[BeaconHttpSequenceEntry] = list(spec.http_sequence)

    beacon_src_ip = spec.source_ip or system.ip
    beacon_dst_ip = spec.dst_ip
    if spec.hostname and not beacon_dst_ip:
        resolved_beacon_ip = self._resolve_scenario_network_host(
            spec.hostname,
            src_host=system.hostname,
        )
        if resolved_beacon_ip:
            beacon_dst_ip = resolved_beacon_ip

    # Deny mode: firewall context
    fw_ctx = None
    deny_conn_state = None
    if spec.action == "deny":
        from evidenceforge.events.contexts import FirewallContext

        deny_conn_state = self._get_firewall_deny_conn_state()
        src_iface = self._resolve_firewall_interface(beacon_src_ip)
        dst_iface = self._resolve_firewall_interface(beacon_dst_ip)
        fw_ctx = FirewallContext(
            action="deny",
            msg_id=106023,
            connection_id=0,
            src_interface=src_iface,
            dst_interface=dst_iface,
            access_group=f"{src_iface}_access_in",
        )

    # Allow mode: resolve service, http context, hostname, byte sizing
    service = spec.service
    http_ctx = None
    http_is_c2 = False
    http_method = ""
    http_uri = ""
    conn_hostname = None
    emit_dns = False
    s_ob, s_rb = _size_storyline_connection(spec, rng)
    s_conn_state = spec.conn_state or "SF"

    if spec.action == "allow":
        service = service or (
            "ssl" if spec.dst_port == 443 else "http" if spec.dst_port == 80 else "ssl"
        )
        # Build HttpContext if HTTP/proxy-visible request metadata is provided.
        # HTTPS CONNECT beacons still need this for proxy User-Agent fidelity
        # even though no origin-side Zeek http.log is emitted for TLS.
        first_sequence_entry: BeaconHttpSequenceEntry | dict[str, Any] | None = None
        if explicit_http_sequence:
            first_sequence_entry = explicit_http_sequence[0]
        elif profile_http_sequence:
            first_sequence_entry = profile_http_sequence[0]
        profile_user_agent = profile_user_agents[0] if profile_user_agents else None

        if (
            spec.method
            or spec.uri
            or spec.user_agent
            or getattr(spec, "request_body_len", None) is not None
            or spec.request_multipart is not None
            or spec.response_multipart is not None
            or profile_user_agent is not None
            or first_sequence_entry is not None
        ):
            from evidenceforge.events.contexts import HttpContext

            _method = _entry_value(first_sequence_entry, "method") or spec.method or "GET"
            _uri_template = _entry_value(first_sequence_entry, "uri") or spec.uri or "/"
            _uri_raw = _render_beacon_template(
                str(_uri_template),
                spec=spec,
                system=system,
                tick_index=0,
            )
            _user_agent = (
                _entry_value(first_sequence_entry, "user_agent")
                or spec.user_agent
                or profile_user_agent
                or "Mozilla/5.0"
            )
            http_method = _method
            http_uri = _uri_raw
            _mime_type = normalize_mime_type_for_path(_uri_raw, "text/html")
            _is_c2_http = _is_c2_http_request(
                description=spec.description,
                technique=spec.technique,
                uri=_uri_raw,
                activity=activity,
            )
            http_is_c2 = _is_c2_http
            if _is_c2_http and _mime_type == "text/html":
                _mime_type = rng.choices(
                    ["application/json", "text/plain", "application/octet-stream"],
                    weights=[65, 25, 10],
                    k=1,
                )[0]
            from evidenceforge.generation.activity.referrer import pick_referrer

            _http_host2 = spec.hostname or spec.dst_ip
            response_override = _range_or_value(
                _entry_value(first_sequence_entry, "response_body_len"),
                rng,
            )
            resp_bytes = (
                response_override
                if response_override is not None
                else _storyline_http_response_body_len(
                    spec=spec,
                    rng=rng,
                    method=_method,
                    uri=_uri_raw,
                    host=_http_host2,
                    is_c2_http=_is_c2_http,
                    use_connection_path_hints=False,
                )
            )
            request_override = _range_or_value(
                _entry_value(first_sequence_entry, "request_body_len"), rng
            )
            request_body_len = (
                request_override
                if request_override is not None
                else getattr(spec, "request_body_len", None)
                if getattr(spec, "request_body_len", None) is not None
                else max(0, s_ob or 0)
                if _method not in {"GET", "HEAD", "CONNECT", "OPTIONS"}
                else 0
            )
            if request_body_len == 0 and _method == "POST":
                request_body_len = rng.randint(100, 10000)
            _status_code = (
                _entry_value(first_sequence_entry, "status_code") or spec.status_code or 200
            )
            http_ctx = HttpContext(
                method=_method,
                host=_http_host2,
                uri=_uri_raw,
                version="1.1",
                user_agent=str(_user_agent),
                request_body_len=request_body_len,
                response_body_len=resp_bytes,
                status_code=_status_code,
                status_msg={
                    200: "OK",
                    301: "Moved Permanently",
                    302: "Found",
                    403: "Forbidden",
                    404: "Not Found",
                    500: "Internal Server Error",
                }.get(_status_code, "OK"),
                referrer=spec.referrer
                if spec.referrer is not None
                else ""
                if _is_c2_http and rng.random() < 0.75
                else pick_referrer(rng, _http_host2, context="general"),
                resp_mime_types=[_mime_type] if _status_code == 200 else [],
                tags=[],
            )
            first_request_multipart = (
                _entry_value(first_sequence_entry, "request_multipart") or spec.request_multipart
            )
            first_response_multipart = (
                _entry_value(first_sequence_entry, "response_multipart") or spec.response_multipart
            )
            if first_request_multipart is not None or first_response_multipart is not None:
                from evidenceforge.generation.activity.http_multipart import (
                    apply_http_multipart_specs,
                )

                http_ctx = apply_http_multipart_specs(
                    http_ctx,
                    stable_key=(
                        f"beacon:{system.hostname}:{beacon_src_ip}:{beacon_dst_ip}:"
                        f"{start.isoformat()}:0:{_uri_raw}"
                    ),
                    request_spec=first_request_multipart,
                    response_spec=first_response_multipart,
                    request_body_assertion=request_override,
                    response_body_assertion=response_override,
                )

        # Hostname / DNS resolution (same logic as connection handler)
        from evidenceforge.generation.activity.network import REVERSE_DNS

        if spec.hostname:
            conn_hostname = spec.hostname
            emit_dns = True
        elif spec.dst_ip in REVERSE_DNS:
            conn_hostname = None
            emit_dns = True
        else:
            conn_hostname = ""
            emit_dns = False

    # Resolve source system
    src_sys = None
    ip_map = getattr(self.activity_generator, "_ip_to_system", {})
    if beacon_src_ip in ip_map:
        src_sys = ip_map[beacon_src_ip]
    elif beacon_src_ip == system.ip:
        src_sys = system
    story_pid, story_image = self._last_storyline_process_for_system(src_sys)

    attempt_count = 0
    for tick_time in _iter_periodic_ticks(
        start,
        interval_sec,
        duration_sec,
        count,
        spec.jitter,
        rng,
        exclusive_end_time=getattr(self, "end_time", None),
    ):
        self.state_manager.set_current_time(tick_time)
        tick_sequence_entry: BeaconHttpSequenceEntry | dict[str, Any] | None = None
        if explicit_http_sequence:
            tick_sequence_entry = explicit_http_sequence[
                attempt_count % len(explicit_http_sequence)
            ]
        elif profile_http_sequence:
            tick_sequence_entry = _weighted_profile_entry(
                profile_http_sequence,
                tick_index=attempt_count,
                spec=spec,
                system=system,
            )
        tick_method = _entry_value(tick_sequence_entry, "method") or spec.method or "GET"
        tick_uri_template = _entry_value(tick_sequence_entry, "uri") or spec.uri or "/"
        tick_uri = _render_beacon_template(
            str(tick_uri_template),
            spec=spec,
            system=system,
            tick_index=attempt_count,
        )
        tick_user_agent = (
            _entry_value(tick_sequence_entry, "user_agent")
            or spec.user_agent
            or (
                profile_user_agents[
                    _stable_seed(f"beacon-ua:{system.hostname}:{spec.profile}:{attempt_count}")
                    % len(profile_user_agents)
                ]
                if profile_user_agents
                else None
            )
            or "Mozilla/5.0"
        )
        tick_status_code = (
            _entry_value(tick_sequence_entry, "status_code") or spec.status_code or 200
        )
        tick_response_override = _range_or_value(
            _entry_value(tick_sequence_entry, "response_body_len"),
            rng,
        )
        tick_request_override = _range_or_value(
            _entry_value(tick_sequence_entry, "request_body_len"), rng
        )
        tick_orig_bytes = (
            _range_or_value(_entry_value(tick_sequence_entry, "orig_bytes"), rng)
            if tick_sequence_entry is not None
            else None
        )
        if tick_orig_bytes is None:
            tick_orig_bytes = s_ob
        tick_resp_bytes = (
            _range_or_value(_entry_value(tick_sequence_entry, "resp_bytes"), rng)
            if tick_sequence_entry is not None
            else None
        )
        if tick_resp_bytes is None:
            tick_resp_bytes = s_rb
        tick_emit_dns = emit_dns and (
            spec.dns_resolution == "each_tick"
            or (profile_dns_resolution == "each_tick" and spec.dns_resolution == "cached")
            or attempt_count == 0
        )
        tick_http_ctx = http_ctx
        if tick_http_ctx is not None and (
            tick_sequence_entry is not None
            or spec.request_multipart is not None
            or spec.response_multipart is not None
        ):
            tick_mime_type = normalize_mime_type_for_path(tick_uri, "text/html")
            tick_request_body_len = (
                tick_request_override
                if tick_request_override is not None
                else getattr(spec, "request_body_len", None)
                if getattr(spec, "request_body_len", None) is not None
                else max(0, tick_orig_bytes)
                if str(tick_method).upper() not in {"GET", "HEAD", "CONNECT", "OPTIONS"}
                else 0
            )
            tick_response_body_len = (
                tick_response_override
                if tick_response_override is not None
                else tick_http_ctx.response_body_len
            )
            tick_http_ctx = replace(
                tick_http_ctx,
                method=str(tick_method),
                uri=tick_uri,
                user_agent=str(tick_user_agent),
                status_code=int(tick_status_code),
                status_msg={
                    200: "OK",
                    301: "Moved Permanently",
                    302: "Found",
                    403: "Forbidden",
                    404: "Not Found",
                    500: "Internal Server Error",
                }.get(int(tick_status_code), "OK"),
                response_body_len=tick_response_body_len,
                response_multipart=None,
                request_body_len=tick_request_body_len,
                request_entity=None,
                request_multipart=None,
                referrer=_entry_value(tick_sequence_entry, "referrer")
                if tick_sequence_entry is not None
                and _entry_value(tick_sequence_entry, "referrer") is not None
                else tick_http_ctx.referrer,
                tags=list(tick_http_ctx.tags),
                resp_fuids=list(tick_http_ctx.resp_fuids),
                resp_mime_types=[tick_mime_type] if int(tick_status_code) == 200 else [],
            )
            tick_request_multipart = (
                _entry_value(tick_sequence_entry, "request_multipart") or spec.request_multipart
            )
            tick_response_multipart = (
                _entry_value(tick_sequence_entry, "response_multipart") or spec.response_multipart
            )
            if tick_request_multipart is not None or tick_response_multipart is not None:
                from evidenceforge.generation.activity.http_multipart import (
                    apply_http_multipart_specs,
                )

                tick_http_ctx = apply_http_multipart_specs(
                    tick_http_ctx,
                    stable_key=(
                        f"beacon:{system.hostname}:{beacon_src_ip}:{beacon_dst_ip}:"
                        f"{tick_time.isoformat()}:{attempt_count}:{tick_uri}"
                    ),
                    request_spec=tick_request_multipart,
                    response_spec=tick_response_multipart,
                    request_body_assertion=tick_request_override,
                    response_body_assertion=tick_response_override,
                )
            if tick_response_override is not None:
                tick_resp_bytes = max(
                    tick_resp_bytes,
                    tick_response_override + rng.randint(300, 5000),
                )
        if (
            http_ctx is not None
            and http_is_c2
            and spec.response_body_len is None
            and tick_response_override is None
            and (tick_http_ctx or http_ctx).response_multipart is None
        ):
            tick_http_body_len = _c2_http_response_size(
                rng,
                method=str(tick_method or http_method or http_ctx.method),
                uri=tick_uri or http_uri or http_ctx.uri,
            )
            tick_http_ctx = replace(
                tick_http_ctx or http_ctx,
                response_body_len=tick_http_body_len,
                tags=list((tick_http_ctx or http_ctx).tags),
                resp_fuids=list((tick_http_ctx or http_ctx).resp_fuids),
                resp_mime_types=list((tick_http_ctx or http_ctx).resp_mime_types),
            )
            tick_resp_bytes = max(
                tick_resp_bytes,
                tick_http_body_len + rng.randint(300, 5000),
            )
        if story_pid <= 0:
            story_pid, story_image = self._ensure_storyline_service_process_for_beacon(
                actor,
                src_sys,
                tick_time,
            )
        if tick_http_ctx is not None and tick_http_ctx.request_multipart is not None:
            running_beacon = (
                self.state_manager.get_process(src_sys.hostname, story_pid)
                if src_sys is not None and story_pid > 0
                else None
            )
            self._emit_http_multipart_file_reads(
                actor=actor,
                system=src_sys,
                pid=story_pid,
                process_image=story_image,
                command_line=(running_beacon.command_line if running_beacon is not None else ""),
                multipart=tick_http_ctx.request_multipart,
                connection_time=tick_time,
            )
            tick_http_ctx = replace(
                tick_http_ctx,
                request_multipart=replace(
                    tick_http_ctx.request_multipart,
                    local_reads_emitted=True,
                ),
            )
        tick_ids_alerts = _build_ids_alert_contexts(
            getattr(spec, "ids_alerts", []),
            time=tick_time,
            src_ip=beacon_src_ip,
            dst_ip=beacon_dst_ip,
            dst_port=spec.dst_port,
            proto=spec.protocol,
            rng=rng,
            source="storyline_beacon",
        )
        if spec.action == "deny":
            proxy_chain = getattr(self.activity_generator, "_proxy_routes", {}).get(beacon_src_ip)
            explicit_proxy = (
                getattr(self.activity_generator, "_proxy_mode", "transparent") == "explicit"
                and proxy_chain
                and spec.protocol == "tcp"
                and spec.dst_port in (80, 443)
            )
            if explicit_proxy:
                from evidenceforge.events.contexts import ProxyContext

                proxy_sys = proxy_chain[0]
                beacon_host = spec.hostname or spec.dst_ip
                proxy_method = "CONNECT" if spec.dst_port == 443 else str(tick_method)
                proxy_url = (
                    f"{beacon_host}:443"
                    if proxy_method == "CONNECT"
                    else f"http://{beacon_host}{tick_uri}"
                )
                proxy_user_agent = str(tick_user_agent)
                proxy_source_system = getattr(
                    self.activity_generator,
                    "_ip_to_system",
                    {},
                ).get(beacon_src_ip)
                proxy_ctx = ProxyContext(
                    client_ip=beacon_src_ip,
                    username=self.activity_generator._proxy_username_for_source(
                        source_system=proxy_source_system,
                        user_agent=proxy_user_agent,
                        cache_result="DENIED",
                        hostname=beacon_host,
                        time=tick_time,
                    ),
                    method=proxy_method,
                    url=proxy_url,
                    host=beacon_host,
                    status_code=403,
                    sc_bytes=rng.randint(500, 2000),
                    cs_bytes=rng.randint(180, 520),
                    time_taken=rng.randint(20, 1500),
                    user_agent=proxy_user_agent,
                    content_type="text/html",
                    cache_result="DENIED",
                    referrer=spec.referrer or "",
                    proxy_fqdn=self.activity_generator._proxy_fqdn(proxy_sys),
                    proxy_action="deny",
                )
                self.activity_generator.generate_connection(
                    src_ip=beacon_src_ip,
                    dst_ip=beacon_dst_ip,
                    time=tick_time,
                    dst_port=spec.dst_port,
                    proto=spec.protocol,
                    service="ssl" if spec.dst_port == 443 else "http",
                    duration=rng.uniform(0.05, 2.0),
                    orig_bytes=tick_orig_bytes,
                    resp_bytes=tick_resp_bytes,
                    conn_state="SF",
                    emit_dns=tick_emit_dns,
                    source_system=src_sys,
                    http=tick_http_ctx,
                    ids_alerts=tick_ids_alerts,
                    proxy=proxy_ctx,
                    hostname=conn_hostname if conn_hostname is not None else spec.hostname,
                    pid=story_pid,
                    process_image=story_image,
                    preserve_dst_ip=bool(spec.hostname),
                    preserve_explicit_payload=(
                        spec.orig_bytes is not None
                        or spec.resp_bytes is not None
                        or tick_sequence_entry is not None
                    ),
                )
            else:
                self.activity_generator.generate_connection(
                    src_ip=beacon_src_ip,
                    dst_ip=beacon_dst_ip,
                    time=tick_time,
                    dst_port=spec.dst_port,
                    proto=spec.protocol,
                    conn_state=deny_conn_state,
                    firewall=fw_ctx,
                    ids_alerts=tick_ids_alerts,
                    emit_dns=False,
                )
        else:
            # Allow DNS only on the first tick; cache handles the rest
            self.activity_generator.generate_connection(
                src_ip=beacon_src_ip,
                dst_ip=beacon_dst_ip,
                time=tick_time,
                dst_port=spec.dst_port,
                proto=spec.protocol,
                service=service,
                duration=rng.uniform(0.5, 10.0),
                orig_bytes=tick_orig_bytes,
                resp_bytes=tick_resp_bytes,
                conn_state=s_conn_state,
                emit_dns=tick_emit_dns,
                source_system=src_sys,
                http=tick_http_ctx,
                ids_alerts=tick_ids_alerts,
                hostname=conn_hostname,
                pid=story_pid,
                process_image=story_image,
                preserve_dst_ip=bool(spec.hostname),
                preserve_explicit_payload=(
                    spec.orig_bytes is not None
                    or spec.resp_bytes is not None
                    or tick_sequence_entry is not None
                ),
            )
        attempt_count += 1

    malicious_event["dst_ip"] = beacon_dst_ip
    malicious_event["dst_port"] = spec.dst_port
    malicious_event["interval"] = spec.interval
    malicious_event["action"] = spec.action
    term = spec.duration or spec.end_time or f"count={spec.count}"
    malicious_event["termination"] = term
    malicious_event["attempt_count"] = attempt_count
    if getattr(spec, "ids_alerts", []):
        malicious_event["ids_alerts"] = _ids_attachment_ground_truth(spec.ids_alerts)

    return context.malicious_event


def handle_dns_query(
    self: StorylineMixin, spec: DnsQueryEventSpec, context: TypedEventContext
) -> dict[str, Any] | None:
    """Execute the dns_query evidence path using the existing runtime owners."""
    from evidenceforge.generation.engine.storyline_helpers.ids import (
        _build_ids_alert_contexts,
        _ids_attachment_ground_truth,
    )

    system = context.system
    time = context.time
    rng = context.rng
    malicious_event = context.malicious_event
    _QTYPE_MAP = {
        "A": 1,
        "AAAA": 28,
        "TXT": 16,
        "CNAME": 5,
        "MX": 15,
        "NULL": 10,
        "SRV": 33,
        "PTR": 12,
    }
    _RCODE_MAP = {"NOERROR": 0, "NXDOMAIN": 3, "SERVFAIL": 2, "REFUSED": 5}

    from evidenceforge.events.contexts import DnsContext

    qtype_num = _QTYPE_MAP.get(spec.qtype, 1)
    rcode_num = _RCODE_MAP.get(spec.rcode, 0)

    # Build answers list
    answers = []
    ttls = []
    if spec.answer is not None:
        answers = [spec.answer] if isinstance(spec.answer, str) else list(spec.answer)
        ttl_val = float(spec.ttl) if spec.ttl is not None else float(rng.randint(60, 3600))
        ttls = [ttl_val] * len(answers)
    elif spec.rcode == "NOERROR" and spec.qtype in {"A", "AAAA"}:
        resolver = getattr(self, "network_resolver", None)
        if resolver is not None:
            resolved_query = resolver.resolve_host(spec.query, src_host=system.hostname)
            if resolved_query.ip:
                answers = [resolved_query.ip]
                ttl_val = float(spec.ttl) if spec.ttl is not None else float(rng.randint(60, 3600))
                ttls = [ttl_val]

    # Resolve DNS server IP before choosing source-native DNS RTT so
    # local resolvers do not get impossible multi-second timings.
    query_src_ip = spec.source_ip or system.ip
    dns_server_ips = activity_dns_resolver_ips(
        self.activity_generator,
        query_src_ip,
    )
    dns_server_ip = rng.choice(dns_server_ips)
    from evidenceforge.generation.activity.generator import _dns_rtt

    dns_ctx = DnsContext(
        query=spec.query,
        query_type=spec.qtype,
        qtype=qtype_num,
        rcode=spec.rcode,
        rcode_num=rcode_num,
        answers=answers,
        TTLs=ttls,
        preserve_ttls=spec.ttl is not None,
        trans_id=rng.randint(1, 65535),
        AA=False,
        RD=True,
        RA=True,
        rejected=spec.rcode == "REFUSED",
        rtt=_dns_rtt(rng, dns_server_ip),
    )
    authored_ids_alerts = _build_ids_alert_contexts(
        getattr(spec, "ids_alerts", []),
        time=time,
        src_ip=query_src_ip,
        dst_ip=dns_server_ip,
        dst_port=53,
        proto="udp",
        rng=rng,
        source="storyline_dns_query",
    )

    self.activity_generator.generate_connection(
        src_ip=query_src_ip,
        dst_ip=dns_server_ip,
        time=time,
        dst_port=53,
        proto="udp",
        service="dns",
        dns=dns_ctx,
        emit_dns=False,
        orig_bytes=rng.randint(40, 100),
        resp_bytes=rng.randint(80, 400) if spec.rcode == "NOERROR" else rng.randint(40, 80),
        conn_state="SF",
        duration=rng.uniform(0.001, 0.05),
        ids_alerts=authored_ids_alerts,
    )

    malicious_event["query"] = spec.query
    malicious_event["qtype"] = spec.qtype
    malicious_event["rcode"] = spec.rcode
    if getattr(spec, "ids_alerts", []):
        malicious_event["ids_alerts"] = _ids_attachment_ground_truth(spec.ids_alerts)

    return context.malicious_event


def handle_dga_queries(
    self: StorylineMixin, spec: DgaQueriesEventSpec, context: TypedEventContext
) -> dict[str, Any] | None:
    """Execute the dga_queries evidence path using the existing runtime owners."""
    from evidenceforge.generation.engine.storyline_helpers.ids import (
        _build_ids_alert_contexts,
        _ids_attachment_ground_truth,
    )
    from evidenceforge.generation.engine.storyline_helpers.periodic import _iter_periodic_ticks

    system = context.system
    time = context.time
    rng = context.rng
    malicious_event = context.malicious_event
    import random as _random

    from evidenceforge.events.contexts import DnsContext

    # Timing
    start = self._parse_storyline_time(spec.start_time) if spec.start_time else time
    interval_sec = parse_duration(spec.interval).total_seconds()
    duration_sec = None
    count = spec.count
    if spec.duration is not None:
        duration_sec = parse_duration(spec.duration).total_seconds()
    elif spec.end_time is not None:
        end_dt = self._parse_storyline_time(spec.end_time)
        duration_sec = (end_dt - start).total_seconds()

    # DGA RNG — separate from main rng for reproducibility
    dga_seed = spec.seed if spec.seed is not None else rng.randint(0, 2**31)
    dga_rng = _random.Random(dga_seed)

    # Rcode distribution
    rcode_dist = spec.rcode_distribution or {"NXDOMAIN": 0.95, "NOERROR": 0.05}
    rcode_names = list(rcode_dist.keys())
    rcode_weights = list(rcode_dist.values())

    _RCODE_MAP = {"NOERROR": 0, "NXDOMAIN": 3, "SERVFAIL": 2, "REFUSED": 5}
    _QTYPE_MAP = {"A": 1, "AAAA": 28, "TXT": 16, "CNAME": 5}

    query_src_ip = spec.source_ip or system.ip
    dns_server_ips = activity_dns_resolver_ips(
        self.activity_generator,
        query_src_ip,
    )

    query_count = 0
    nxdomain_count = 0
    domain_sample = []
    for tick_time in _iter_periodic_ticks(
        start,
        interval_sec,
        duration_sec,
        count,
        spec.jitter,
        rng,
        exclusive_end_time=getattr(self, "end_time", None),
    ):
        self.state_manager.set_current_time(tick_time)

        # Generate random domain
        label_len = dga_rng.randint(*spec.length_range)
        label = "".join(dga_rng.choices(spec.charset, k=label_len))
        domain = f"{label}{spec.tld}"

        # Select rcode
        rcode_name = dga_rng.choices(rcode_names, weights=rcode_weights, k=1)[0]
        rcode_num = _RCODE_MAP.get(rcode_name, 3)

        answers = []
        ttls = []
        if rcode_name == "NOERROR" and spec.answer_ip:
            answers = [spec.answer_ip]
            ttls = [float(dga_rng.randint(60, 3600))]
        if rcode_name == "NXDOMAIN":
            nxdomain_count += 1

        dns_server_ip = rng.choice(dns_server_ips)
        from evidenceforge.generation.activity.generator import _dns_rtt

        dns_ctx = DnsContext(
            query=domain,
            query_type="A",
            qtype=1,
            rcode=rcode_name,
            rcode_num=rcode_num,
            answers=answers,
            TTLs=ttls,
            trans_id=rng.randint(1, 65535),
            AA=False,
            RD=True,
            RA=True,
            rejected=False,
            rtt=_dns_rtt(rng, dns_server_ip),
        )
        authored_ids_alerts = _build_ids_alert_contexts(
            getattr(spec, "ids_alerts", []),
            time=tick_time,
            src_ip=query_src_ip,
            dst_ip=dns_server_ip,
            dst_port=53,
            proto="udp",
            rng=rng,
            source="storyline_dga_queries",
        )

        self.activity_generator.generate_connection(
            src_ip=query_src_ip,
            dst_ip=dns_server_ip,
            time=tick_time,
            dst_port=53,
            proto="udp",
            service="dns",
            dns=dns_ctx,
            emit_dns=False,
            orig_bytes=rng.randint(40, 100),
            resp_bytes=rng.randint(80, 400) if rcode_name == "NOERROR" else rng.randint(40, 80),
            conn_state="SF",
            duration=rng.uniform(0.001, 0.05),
            ids_alerts=authored_ids_alerts,
        )
        query_count += 1
        if query_count % 500 == 0:
            self.state_manager.sweep_closed_connections()
        if len(domain_sample) < 5:
            domain_sample.append(domain)

    malicious_event["total_queries"] = query_count
    malicious_event["nxdomain_count"] = nxdomain_count
    malicious_event["domain_sample"] = domain_sample
    malicious_event["tld"] = spec.tld
    if getattr(spec, "ids_alerts", []):
        malicious_event["ids_alerts"] = _ids_attachment_ground_truth(spec.ids_alerts)

    return context.malicious_event


def handle_dns_tunnel(
    self: StorylineMixin, spec: DnsTunnelEventSpec, context: TypedEventContext
) -> dict[str, Any] | None:
    """Execute the dns_tunnel evidence path using the existing runtime owners."""
    from evidenceforge.generation.engine.storyline_helpers.ids import (
        _build_ids_alert_contexts,
        _ids_attachment_ground_truth,
    )
    from evidenceforge.generation.engine.storyline_helpers.periodic import (
        _choose_dns_tunnel_campaign_ttl,
        _choose_dns_tunnel_response_template,
        _choose_dns_tunnel_response_ttl,
        _dns_periodic_exclusive_start_fence,
        _dns_tunnel_background_txt_record,
        _dns_tunnel_extra_labels,
        _iter_dns_tunnel_ticks,
        _render_dns_tunnel_response_template,
    )

    system = context.system
    time = context.time
    rng = context.rng
    malicious_event = context.malicious_event
    import base64 as _b64

    from evidenceforge.events.contexts import DnsContext
    from evidenceforge.generation.activity.network_params import (
        dns_tunnel_rcode_weights,
        dns_tunnel_response_templates,
        dns_tunnel_rtt_range,
        dns_tunnel_ttl_choices,
    )

    _QTYPE_MAP = {"TXT": 16, "NULL": 10, "CNAME": 5}
    _RCODE_MAP = {"NOERROR": 0, "NXDOMAIN": 3, "SERVFAIL": 2, "REFUSED": 5}

    # Timing
    start = self._parse_storyline_time(spec.start_time) if spec.start_time else time
    interval_sec = parse_duration(spec.interval).total_seconds()
    duration_sec = None
    count = spec.count
    if spec.duration is not None:
        duration_sec = parse_duration(spec.duration).total_seconds()
    elif spec.end_time is not None:
        end_dt = self._parse_storyline_time(spec.end_time)
        duration_sec = (end_dt - start).total_seconds()

    exclusive_end_time = getattr(self, "end_time", None)
    min_rtt, max_rtt = dns_tunnel_rtt_range()
    scenario_start_time = getattr(self, "start_time", None)
    dns_window_start = (
        max(ensure_utc(start), ensure_utc(scenario_start_time))
        if scenario_start_time is not None
        else ensure_utc(start)
    )
    dns_start_fence = _dns_periodic_exclusive_start_fence(
        self.activity_generator,
        window_start=dns_window_start,
        exclusive_end_time=exclusive_end_time,
        maximum_rtt_seconds=max_rtt,
    )
    tunnel_ticks = _iter_dns_tunnel_ticks(
        start,
        interval_sec,
        duration_sec,
        count,
        spec.jitter,
        rng,
        exclusive_end_time=dns_start_fence,
    )
    # Freeze one real cadence tick before any background publication. This
    # intentionally moves cadence RNG ahead of payload/background RNG so the
    # owner cannot emit cover traffic for a campaign with no admitted query.
    first_tick = next(tunnel_ticks, None)
    if first_tick is None:
        malicious_event["base_domain"] = spec.base_domain
        malicious_event["encoding"] = spec.encoding
        malicious_event["qtype"] = spec.qtype
        malicious_event["total_queries"] = 0
        malicious_event["bytes_exfiltrated"] = 0
        if getattr(spec, "ids_alerts", []):
            malicious_event["ids_alerts"] = _ids_attachment_ground_truth(spec.ids_alerts)
        return malicious_event

    query_src_ip = spec.source_ip or system.ip
    dns_server_ips = activity_dns_resolver_ips(
        self.activity_generator,
        query_src_ip,
    )

    # Generate or use payload
    if spec.payload:
        payload_bytes = spec.payload.encode("utf-8")
    else:
        payload_bytes = rng.randbytes(spec.payload_size)

    # Calculate raw bytes that can fit in the visible label for each encoding.
    if spec.encoding == "hex":
        bytes_per_label = spec.label_length // 2
    elif spec.encoding == "base32":
        bytes_per_label = (spec.label_length * 5) // 8
    else:  # base64
        bytes_per_label = (spec.label_length * 3) // 4
    bytes_per_label = max(1, bytes_per_label)

    # Reserve visible label capacity for tunnel metadata before chunking the payload.
    # Otherwise full-sized chunks would be encoded with metadata and truncated, causing
    # GROUND_TRUTH.md to count bytes that never appeared in the emitted DNS label.
    visible_nonce_len = 2
    sequence_len = 4
    payload_bytes_per_label = max(0, bytes_per_label - visible_nonce_len - sequence_len)

    # Chunk only the bytes that can actually be emitted in the label. Very small labels
    # still generate DNS traffic but carry no visible payload, so ground truth reports 0.
    chunks: list[bytes]
    if payload_bytes_per_label > 0:
        chunks = [
            payload_bytes[i : i + payload_bytes_per_label]
            for i in range(0, len(payload_bytes), payload_bytes_per_label)
        ]
    else:
        chunks = [b""]

    qtype_num = _QTYPE_MAP.get(spec.qtype, 16)
    response_templates = dns_tunnel_response_templates() or ["status={token}"]
    response_primary_template = rng.choice(response_templates)
    response_secondary_templates = [
        template
        for template in rng.sample(
            response_templates,
            k=min(len(response_templates), rng.randint(3, 6)),
        )
        if template != response_primary_template
    ]
    ttl_choices = dns_tunnel_ttl_choices()
    campaign_ttl = _choose_dns_tunnel_campaign_ttl(ttl_choices, rng)
    rcode_weights = dns_tunnel_rcode_weights()
    rcode_names = list(rcode_weights)
    rcode_values = [rcode_weights[name] for name in rcode_names]
    total_bytes = 0
    query_count = 0
    chunk_idx = 0
    tunnel_salt = rng.randbytes(4)

    scenario = getattr(self, "scenario", None)
    environment = getattr(scenario, "environment", None)
    background_systems = [
        candidate
        for candidate in getattr(environment, "systems", [])
        if getattr(candidate, "ip", "") and getattr(candidate, "ip", "") != query_src_ip
    ]
    background_window_sec = (
        duration_sec
        if duration_sec is not None
        else interval_sec * float(count if count is not None else 120)
    )
    background_earliest = start - timedelta(seconds=240.0)
    background_latest = start + timedelta(seconds=background_window_sec + 240.0)
    if scenario_start_time is not None:
        background_earliest = max(
            ensure_utc(background_earliest),
            ensure_utc(scenario_start_time),
        )
    if dns_start_fence is not None:
        # Sample once from the valid intersection instead of retrying
        # post-fence candidates and drifting the owner RNG.
        background_latest = min(
            ensure_utc(background_latest),
            dns_start_fence - timedelta(microseconds=1),
        )
    background_span_sec = max(
        0.0,
        (ensure_utc(background_latest) - ensure_utc(background_earliest)).total_seconds(),
    )
    if (
        background_systems
        and background_window_sec > 0
        and ensure_utc(background_earliest) <= ensure_utc(background_latest)
    ):
        background_count = min(36, max(12, len(background_systems) * 2 + rng.randint(3, 9)))
        for _ in range(background_count):
            bg_system = rng.choice(background_systems)
            bg_query, bg_answer, bg_ttl = _dns_tunnel_background_txt_record(rng)
            bg_rtt = rng.uniform(min_rtt, max_rtt)
            bg_dns = DnsContext(
                query=bg_query,
                query_type="TXT",
                qtype=16,
                rcode="NOERROR",
                rcode_num=0,
                answers=[bg_answer],
                TTLs=[float(bg_ttl)],
                trans_id=rng.randint(1, 65535),
                AA=False,
                RD=True,
                RA=True,
                rejected=False,
                rtt=bg_rtt,
            )
            bg_time = background_earliest + timedelta(seconds=rng.uniform(0.0, background_span_sec))
            self.activity_generator.generate_connection(
                src_ip=bg_system.ip,
                dst_ip=rng.choice(dns_server_ips),
                time=bg_time,
                dst_port=53,
                proto="udp",
                service="dns",
                dns=bg_dns,
                emit_dns=False,
                resp_bytes=max(90, len(bg_query) + len(bg_answer) + rng.randint(35, 120)),
                duration=bg_rtt,
                source_system=bg_system,
            )

    for tick_time in itertools.chain((first_tick,), tunnel_ticks):
        self.state_manager.set_current_time(tick_time)

        if spec.label_length >= 24:
            min_label_length = max(14, int(spec.label_length * 0.45))
            label_length = int(
                rng.triangular(min_label_length, spec.label_length, spec.label_length - 4)
            )
        elif spec.label_length >= 20:
            label_length = rng.randint(max(16, spec.label_length - 8), spec.label_length)
        else:
            label_length = spec.label_length
        if spec.encoding == "hex":
            effective_bytes_per_label = label_length // 2
        elif spec.encoding == "base32":
            effective_bytes_per_label = (label_length * 5) // 8
        else:  # base64
            effective_bytes_per_label = (label_length * 3) // 4
        effective_bytes_per_label = max(1, effective_bytes_per_label)

        chunk = chunks[chunk_idx % len(chunks)]
        chunk_idx += 1
        sequence_mask = random.Random(
            _stable_seed(f"dns_tunnel_seq:{spec.base_domain}:{tunnel_salt.hex()}:{query_count}")
        ).getrandbits(32)
        sequence = (query_count ^ sequence_mask).to_bytes(4, "big", signed=False)
        visible_nonce = rng.randbytes(visible_nonce_len)
        effective_payload_capacity = max(
            0,
            effective_bytes_per_label - visible_nonce_len - sequence_len,
        )
        visible_payload = chunk[: min(payload_bytes_per_label, effective_payload_capacity)]
        pad_len = max(
            0,
            effective_bytes_per_label - len(visible_nonce) - len(visible_payload) - len(sequence),
        )
        padded_chunk = visible_nonce + visible_payload + rng.randbytes(pad_len) + sequence

        # Encode chunk
        if spec.encoding == "hex":
            encoded = padded_chunk.hex()
        elif spec.encoding == "base32":
            encoded = _b64.b32encode(padded_chunk).decode("ascii").rstrip("=").lower()
        else:  # base64
            encoded = _b64.urlsafe_b64encode(padded_chunk).decode("ascii").rstrip("=").lower()

        # Truncate to label_length
        encoded = encoded[:label_length]
        query_labels = [
            encoded,
            *_dns_tunnel_extra_labels(
                query_count,
                random.Random(
                    _stable_seed(
                        "dns_tunnel_extra_labels:"
                        f"{spec.base_domain}:{tunnel_salt.hex()}:{query_count}"
                    )
                ),
            ),
        ]
        tunnel_query = ".".join([*query_labels, spec.base_domain])

        rcode_name = rng.choices(rcode_names, weights=rcode_values, k=1)[0]
        rcode_num = _RCODE_MAP.get(rcode_name, 0)
        answers: list[str] = []
        ttls: list[float] = []
        if rcode_name == "NOERROR":
            # TXT responses carry data back; CNAME/NULL are smaller.
            if spec.qtype == "TXT":
                resp_bytes = rng.randint(140, 2400)
            else:
                resp_bytes = rng.randint(50, 240)
            token_rng = random.Random(
                _stable_seed(
                    f"dns_tunnel_response:{spec.base_domain}:{query_count}:{tunnel_salt.hex()}"
                )
            )
            token_bytes = token_rng.randbytes(token_rng.randint(3, 10))
            token_style = token_rng.choice(["hex", "base32", "base64url"])
            if token_style == "base32":
                response_token = _b64.b32encode(token_bytes).decode("ascii").rstrip("=")
            elif token_style == "base64url":
                response_token = _b64.urlsafe_b64encode(token_bytes).decode("ascii").rstrip("=")
            else:
                response_token = token_bytes.hex()
            response_ttl = _choose_dns_tunnel_response_ttl(
                ttl_choices,
                campaign_ttl,
                rng,
            )
            response_template = _choose_dns_tunnel_response_template(
                response_templates,
                response_primary_template,
                response_secondary_templates,
                rng,
            )
            answers = [
                _render_dns_tunnel_response_template(
                    response_template,
                    token=response_token,
                    query_count=query_count,
                    ttl=response_ttl,
                    rng=rng,
                )
            ]
            ttls = [response_ttl]
        else:
            resp_bytes = rng.randint(55, 180)

        dns_ctx = DnsContext(
            query=tunnel_query,
            query_type=spec.qtype,
            qtype=qtype_num,
            rcode=rcode_name,
            rcode_num=rcode_num,
            answers=answers,
            TTLs=ttls,
            trans_id=rng.randint(1, 65535),
            AA=False,
            RD=True,
            RA=True,
            rejected=False,
            rtt=rng.uniform(min_rtt, max_rtt),
        )

        dns_server_ip = rng.choice(dns_server_ips)
        authored_ids_alerts = _build_ids_alert_contexts(
            getattr(spec, "ids_alerts", []),
            time=tick_time,
            src_ip=query_src_ip,
            dst_ip=dns_server_ip,
            dst_port=53,
            proto="udp",
            rng=rng,
            source="storyline_dns_tunnel",
        )
        self.activity_generator.generate_connection(
            src_ip=query_src_ip,
            dst_ip=dns_server_ip,
            time=tick_time,
            dst_port=53,
            proto="udp",
            service="dns",
            dns=dns_ctx,
            emit_dns=False,
            resp_bytes=resp_bytes,
            duration=dns_ctx.rtt,
            ids_alerts=authored_ids_alerts,
        )
        total_bytes += len(visible_payload)
        query_count += 1

    malicious_event["base_domain"] = spec.base_domain
    malicious_event["encoding"] = spec.encoding
    malicious_event["qtype"] = spec.qtype
    malicious_event["total_queries"] = query_count
    malicious_event["bytes_exfiltrated"] = total_bytes
    if getattr(spec, "ids_alerts", []):
        malicious_event["ids_alerts"] = _ids_attachment_ground_truth(spec.ids_alerts)

    return context.malicious_event
