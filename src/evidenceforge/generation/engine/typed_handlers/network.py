# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Typed storyline network handlers."""

from __future__ import annotations

import random
from dataclasses import replace
from typing import TYPE_CHECKING, Any

from evidenceforge.generation.actions import (
    PortScanActionBundle,
    PortScanRequest,
    WebScanActionBundle,
    WebScanRequest,
    dhcp_renewal_interval_seconds,
)
from evidenceforge.generation.activity.http_content import (
    infer_mime_type_from_path,
    normalize_mime_type_for_path,
)
from evidenceforge.generation.activity.network import _is_private_ip
from evidenceforge.models.exceptions import StateError
from evidenceforge.models.scenario import (
    ConnectionEventSpec,
    DhcpLeaseEventSpec,
    PortScanEventSpec,
    WebScanEventSpec,
)
from evidenceforge.utils.rng import _stable_seed

from .context import TypedEventContext

if TYPE_CHECKING:
    from evidenceforge.generation.engine.storyline import StorylineMixin


def handle_connection(
    self: StorylineMixin, spec: ConnectionEventSpec, context: TypedEventContext
) -> dict[str, Any] | None:
    """Execute the connection evidence path using the existing runtime owners."""
    from evidenceforge.generation.engine.storyline import (
        _build_ids_alert_contexts,
        _ids_attachment_ground_truth,
        _is_c2_http_request,
        _is_exfil_connection_spec,
        _size_storyline_connection,
        _storyline_http_response_body_len,
    )

    actor = context.actor
    system = context.system
    time = context.time
    activity = context.activity
    rng = context.rng
    malicious_event = context.malicious_event
    _ground_truth_uid = context._ground_truth_uid
    source_ip = spec.source_ip or system.ip
    dst_ip = spec.dst_ip
    effective_dst_ip = dst_ip
    if spec.hostname and not effective_dst_ip:
        resolved_dst_ip = self._resolve_scenario_network_host(
            spec.hostname,
            src_host=system.hostname,
        )
        if resolved_dst_ip:
            effective_dst_ip = resolved_dst_ip
    if not effective_dst_ip:
        effective_dst_ip = self.public_identity_registry.bind(
            "c2",
            f"storyline-connection:{system.hostname}:{time.isoformat()}:{spec.dst_port}",
            forward_hostname=spec.hostname,
        ).ip
    if (
        not _is_private_ip(source_ip)
        and hasattr(self, "dispatcher")
        and self.dispatcher.visibility_engine
    ):
        effective_dst_ip = self.dispatcher.visibility_engine._real_ip_to_vip.get(dst_ip, dst_ip)
    dst_port = spec.dst_port
    service = spec.service or ("ssl" if dst_port == 443 else "http" if dst_port == 80 else "ssl")
    s_ob, s_rb = _size_storyline_connection(spec, rng)
    # Build HttpContext if HTTP fields are provided
    http_ctx = None
    authored_request_body_len = getattr(spec, "request_body_len", None)
    authored_request_multipart = getattr(spec, "request_multipart", None)
    authored_response_multipart = getattr(spec, "response_multipart", None)
    if (
        spec.method
        or spec.uri
        or authored_request_body_len is not None
        or authored_request_multipart is not None
        or authored_response_multipart is not None
    ):
        from evidenceforge.events.contexts import HttpContext

        # Context-aware response sizing (or author-specified override)
        _method = spec.method or (
            "POST" if authored_request_body_len or authored_request_multipart else "GET"
        )
        _uri_raw = spec.uri or "/"
        _mime_type = normalize_mime_type_for_path(_uri_raw, "text/html")
        _is_c2_http = _is_c2_http_request(
            description=spec.description,
            technique=spec.technique,
            uri=_uri_raw,
            activity=activity,
        )
        if _is_c2_http and _mime_type == "text/html":
            _mime_type = rng.choices(
                ["application/json", "text/plain", "application/octet-stream"],
                weights=[55, 25, 20],
                k=1,
            )[0]
        from evidenceforge.generation.activity.referrer import pick_referrer

        _http_host = spec.hostname or effective_dst_ip
        resp_bytes = _storyline_http_response_body_len(
            spec=spec,
            rng=rng,
            method=_method,
            uri=_uri_raw,
            host=_http_host,
            is_c2_http=_is_c2_http,
            use_connection_path_hints=True,
        )
        request_body_len = (
            authored_request_body_len
            if authored_request_body_len is not None
            else max(0, s_ob or 0)
            if _method not in {"GET", "HEAD", "CONNECT", "OPTIONS"}
            else 0
        )
        if request_body_len == 0 and _method == "POST":
            request_body_len = rng.randint(100, 10000)
        http_ctx = HttpContext(
            method=_method,
            host=_http_host,
            uri=_uri_raw,
            version="1.1",
            user_agent=spec.user_agent or "Mozilla/5.0",
            request_body_len=request_body_len,
            response_body_len=resp_bytes,
            status_code=spec.status_code or 200,
            status_msg={
                200: "OK",
                301: "Moved Permanently",
                302: "Found",
                403: "Forbidden",
                404: "Not Found",
                500: "Internal Server Error",
            }.get(spec.status_code or 200, "OK"),
            referrer=spec.referrer
            if spec.referrer is not None
            else ""
            if _is_c2_http and rng.random() < 0.8
            else pick_referrer(rng, _http_host, context="general"),
            resp_mime_types=[_mime_type] if (spec.status_code or 200) == 200 else [],
            tags=[],
        )
        if authored_request_multipart is not None or authored_response_multipart is not None:
            from evidenceforge.generation.activity.http_multipart import (
                apply_http_multipart_specs,
            )

            http_ctx = apply_http_multipart_specs(
                http_ctx,
                stable_key=(
                    f"storyline:{system.hostname}:{source_ip}:{effective_dst_ip}:"
                    f"{time.isoformat()}:{_uri_raw}"
                ),
                request_spec=authored_request_multipart,
                response_spec=authored_response_multipart,
                request_body_assertion=authored_request_body_len,
                response_body_assertion=spec.response_body_len,
            )

    # Resolve source system from source_ip (not storyline system, which may be the target)
    src_sys = None
    ip_map = getattr(self.activity_generator, "_ip_to_system", {})
    if source_ip in ip_map:
        src_sys = ip_map[source_ip]
    elif source_ip == system.ip:
        src_sys = system
    story_pid, story_image = self._last_storyline_process_for_system(src_sys)
    story_proc = (
        self.state_manager.get_process(src_sys.hostname, story_pid)
        if story_pid > 0 and src_sys is not None
        else None
    )
    story_command = story_proc.command_line if story_proc is not None else ""
    if src_sys is not None and not story_command:
        recorded_process = getattr(self, "_last_storyline_process_command_by_system", {}).get(
            src_sys.hostname
        )
        if recorded_process is not None:
            recorded_pid, recorded_image, recorded_command = recorded_process
            target_url = f"{spec.hostname or effective_dst_ip}{spec.uri or '/'}"
            if target_url in recorded_command:
                story_pid = recorded_pid
                story_image = recorded_image
                story_command = recorded_command
    upload_read_emitted = False
    if http_ctx is not None and http_ctx.request_body_len > 0:
        if http_ctx.request_multipart is not None:
            command_multipart = self._http_request_multipart_from_command(
                story_command,
                http_ctx.request_body_len,
                stable_key=(
                    f"storyline-curl-validation:{source_ip}:{effective_dst_ip}:"
                    f"{time.isoformat()}:{http_ctx.uri}"
                ),
            )
            if command_multipart is not None:
                self._validate_multipart_command_agreement(
                    http_ctx.request_multipart,
                    command_multipart,
                )
        request_multipart = (
            None
            if http_ctx.request_multipart is not None
            else self._http_request_multipart_from_command(
                story_command,
                http_ctx.request_body_len,
                stable_key=(
                    f"storyline-curl:{source_ip}:{effective_dst_ip}:"
                    f"{time.isoformat()}:{http_ctx.uri}"
                ),
            )
        )
        request_entity = (
            None
            if request_multipart is not None or http_ctx.request_multipart is not None
            else self._http_request_entity_from_command(story_command, http_ctx.request_body_len)
        )
        if request_multipart is not None:
            http_ctx = replace(
                http_ctx,
                request_content_type=(
                    f"{request_multipart.media_type}; boundary={request_multipart.boundary}"
                ),
                request_multipart=request_multipart,
            )
        elif request_entity is not None:
            http_ctx = replace(
                http_ctx,
                request_content_type=request_entity.mime_type,
                request_entity=request_entity,
            )
            if not _is_exfil_connection_spec(spec):
                self._emit_http_upload_file_read(
                    actor=actor,
                    system=src_sys,
                    pid=story_pid,
                    process_image=story_image,
                    command_line=story_command,
                    entity=request_entity,
                    connection_time=time,
                )
                upload_read_emitted = True
    if story_pid > 0 and src_sys is not None and service in {"ssl", "https"}:
        if self._command_contains_raw_tcp_endpoint(
            story_command,
            effective_dst_ip,
            dst_port,
        ):
            service = ""
    # Only use explicit hostname from scenario.  Do NOT fall back to
    # Hostname resolution for storyline connections:
    # - Explicit hostname → use it, emit DNS
    # - No hostname but IP in REVERSE_DNS → use known hostname, emit DNS
    # - No hostname, unknown IP → suppress (raw-IP C2/exfil), no DNS
    from evidenceforge.generation.activity.network import REVERSE_DNS

    if spec.hostname:
        conn_hostname = spec.hostname
        emit_dns = True
    elif effective_dst_ip in REVERSE_DNS:
        conn_hostname = None  # let generate_connection resolve via REVERSE_DNS
        emit_dns = True
    else:
        conn_hostname = ""  # suppress — raw IP
        emit_dns = False
    s_conn_state = spec.conn_state or "SF"
    story_command = story_command or story_image or ""
    if _is_exfil_connection_spec(spec):
        story_pid, story_image, story_command = self._ensure_storyline_upload_process_for_exfil(
            actor=actor,
            system=src_sys,
            time=time,
            spec=spec,
            current_pid=story_pid,
            current_image=story_image,
            rng=rng,
        )
        if http_ctx is not None:
            upload_user_agent = self._storyline_http_user_agent_for_process(
                system=src_sys,
                process_image=story_image,
                command_line=story_command,
                rng=rng,
            )
            if upload_user_agent and (
                not (spec.user_agent or "").strip()
                or (http_ctx.user_agent or "").strip().lower() == "mozilla/5.0"
            ):
                http_ctx = replace(http_ctx, user_agent=upload_user_agent)
            if (
                http_ctx.request_entity is None
                and http_ctx.request_multipart is None
                and http_ctx.request_body_len > 0
            ):
                request_multipart = self._http_request_multipart_from_command(
                    story_command,
                    http_ctx.request_body_len,
                    stable_key=(
                        f"storyline-exfil-curl:{source_ip}:{effective_dst_ip}:"
                        f"{time.isoformat()}:{http_ctx.uri}"
                    ),
                )
                request_entity = (
                    None
                    if request_multipart is not None
                    else self._http_request_entity_from_command(
                        story_command, http_ctx.request_body_len
                    )
                )
                if request_multipart is not None:
                    http_ctx = replace(
                        http_ctx,
                        request_content_type=(
                            f"{request_multipart.media_type}; boundary={request_multipart.boundary}"
                        ),
                        request_multipart=request_multipart,
                    )
                elif request_entity is not None:
                    http_ctx = replace(
                        http_ctx,
                        request_content_type=request_entity.mime_type,
                        request_entity=request_entity,
                    )
            staged_archive = self._matching_storyline_staged_archive_for_exfil(
                source_ip=source_ip,
                exfil_time=time,
            )
            if (
                http_ctx.request_entity is None
                and http_ctx.request_multipart is None
                and http_ctx.request_body_len > 0
                and staged_archive is not None
                and src_sys is not None
            ):
                from evidenceforge.events.contexts import HttpRequestEntityContext

                local_path = self._local_staging_path_for_archive(
                    actor,
                    src_sys,
                    staged_archive.archive_path,
                )
                mime_type = infer_mime_type_from_path(
                    local_path,
                    "application/octet-stream",
                )
                request_entity = HttpRequestEntityContext(
                    size=http_ctx.request_body_len,
                    mime_type=mime_type,
                    content_identity=(
                        f"staged-upload:{src_sys.hostname}:{local_path}:{http_ctx.request_body_len}"
                    ),
                    local_source_path=local_path,
                    local_source_filename=(local_path.replace("\\", "/").rsplit("/", 1)[-1]),
                )
                http_ctx = replace(
                    http_ctx,
                    request_content_type=mime_type,
                    request_entity=request_entity,
                )
            if (
                not upload_read_emitted
                and http_ctx.request_entity is not None
                and staged_archive is None
            ):
                self._emit_http_upload_file_read(
                    actor=actor,
                    system=src_sys,
                    pid=story_pid,
                    process_image=story_image,
                    command_line=story_command,
                    entity=http_ctx.request_entity,
                    connection_time=time,
                )
                upload_read_emitted = True
        self._emit_storyline_archive_transfer_before_exfil(
            actor=actor,
            source_ip=source_ip,
            exfil_time=time,
            upload_bytes=s_ob,
            source_pid=story_pid,
            source_process=story_image or "",
            source_command=story_command,
            rng=rng,
        )
    connection_time = self._clamp_after_storyline_process_source_create(
        system=src_sys,
        pid=story_pid,
        network_time=time,
        rng=rng,
    )
    if http_ctx is not None and http_ctx.request_multipart is not None:
        self._emit_http_multipart_file_reads(
            actor=actor,
            system=src_sys,
            pid=story_pid,
            process_image=story_image,
            command_line=story_command,
            multipart=http_ctx.request_multipart,
            connection_time=connection_time,
        )
        http_ctx = replace(
            http_ctx,
            request_multipart=replace(
                http_ctx.request_multipart,
                local_reads_emitted=True,
            ),
        )
    ids_alerts = _build_ids_alert_contexts(
        getattr(spec, "ids_alerts", []),
        time=connection_time,
        src_ip=source_ip,
        dst_ip=effective_dst_ip,
        dst_port=dst_port,
        proto="tcp",
        rng=rng,
        source="storyline_connection",
    )
    uid = self.activity_generator.generate_connection(
        src_ip=source_ip,
        dst_ip=effective_dst_ip,
        time=connection_time,
        dst_port=dst_port,
        service=service,
        duration=rng.uniform(1.0, 30.0),
        orig_bytes=s_ob,
        resp_bytes=s_rb,
        conn_state=s_conn_state,
        emit_dns=emit_dns,
        source_system=src_sys,
        http=http_ctx,
        ids_alerts=ids_alerts,
        pid=story_pid,
        process_image=story_image,
        hostname=conn_hostname,
        preserve_dst_ip=bool(spec.hostname),
        preserve_explicit_payload=(spec.orig_bytes is not None or spec.resp_bytes is not None),
    )
    logged_dst_ip = getattr(
        self.activity_generator,
        "_last_connection_effective_dst_ip",
        effective_dst_ip,
    )
    malicious_event["dst_ip"] = logged_dst_ip
    malicious_event["dst_port"] = dst_port
    malicious_event["uid"] = _ground_truth_uid(uid, source_ip, logged_dst_ip)
    if http_ctx is not None and http_ctx.request_entity is not None:
        malicious_event["http_upload"] = {
            "request_body_len": http_ctx.request_body_len,
            "mime_type": http_ctx.request_entity.mime_type,
            "local_source_path": http_ctx.request_entity.local_source_path,
            "local_source_filename": http_ctx.request_entity.local_source_filename,
            "wire_filename": http_ctx.request_entity.wire_filename or None,
        }
    if http_ctx is not None and (
        http_ctx.request_multipart is not None or http_ctx.response_multipart is not None
    ):
        last_transfers = getattr(
            self.activity_generator,
            "_last_connection_file_transfers",
            (),
        )
        multipart_fuids: dict[tuple[int, ...], list[str]] = {}
        response_multipart_fuids: dict[tuple[int, ...], list[str]] = {}
        for transfer in last_transfers:
            if not transfer.multipart_part_path:
                continue
            target = multipart_fuids if transfer.is_orig else response_multipart_fuids
            target.setdefault(transfer.multipart_part_path, []).append(transfer.fuid)

        def _multipart_truth(entity: Any, *, response: bool) -> dict[str, Any]:
            fuid_map = response_multipart_fuids if response else multipart_fuids
            return {
                "body_len": entity.body_len,
                "media_type": entity.media_type,
                "boundary": entity.boundary,
                "parts": [
                    {
                        "path": list(part.path),
                        "name": part.name,
                        "decoded_size": part.decoded_size,
                        "encoded_size": part.encoded_size,
                        "local_source_path": part.local_source_path or None,
                        "local_source_filename": part.local_source_filename or None,
                        "wire_filename": part.wire_filename or None,
                        "declared_mime_type": part.declared_content_type or None,
                        "detected_mime_type": part.detected_mime_type or None,
                        "transfer_encoding": part.transfer_encoding,
                        "endpoint_read_owner_pid": (
                            story_pid
                            if not response and part.local_source_path and story_pid > 0
                            else None
                        ),
                        "fuids": fuid_map.get(part.path, []),
                    }
                    for part in entity.leaf_parts()
                ],
            }

        malicious_event["http_multipart"] = {
            "request": (
                _multipart_truth(http_ctx.request_multipart, response=False)
                if http_ctx.request_multipart is not None
                else None
            ),
            "response": (
                _multipart_truth(http_ctx.response_multipart, response=True)
                if http_ctx.response_multipart is not None
                else None
            ),
        }
    if getattr(spec, "ids_alerts", []):
        malicious_event["ids_alerts"] = _ids_attachment_ground_truth(
            getattr(spec, "ids_alerts", [])
        )

    return context.malicious_event


def handle_dhcp_lease(
    self: StorylineMixin, spec: DhcpLeaseEventSpec, context: TypedEventContext
) -> dict[str, Any] | None:
    """Execute the dhcp_lease evidence path using the existing runtime owners."""
    from evidenceforge.generation.engine.storyline import (
        _build_ids_alert_contexts,
        _ids_attachment_ground_truth,
    )

    system = context.system
    time = context.time
    rng = context.rng
    malicious_event = context.malicious_event
    existing_lease = getattr(self, "_dhcp_lease_state", {}).get(system.hostname)
    if spec.mac_address:
        mac = spec.mac_address
    elif existing_lease:
        mac = existing_lease["mac"]
    else:
        ip_hash = _stable_seed(f"mac_{spec.requested_ip or system.ip}")
        mac = (
            f"00:50:56:{(ip_hash >> 16) & 0xFF:02x}"
            f":{(ip_hash >> 8) & 0xFF:02x}:{ip_hash & 0xFF:02x}"
        )
    from evidenceforge.generation.world_model import HostCapability
    from evidenceforge.utils.ids import generate_zeek_uid

    dhcp_servers = self.world_model.systems_with_capability(
        HostCapability.DHCP_SERVER,
        distinct_from=system,
    )
    if not dhcp_servers:
        raise StateError(
            f"DHCP lease for {system.hostname} requires a distinct modeled DHCP server"
        )
    dhcp_server = dhcp_servers[
        _stable_seed(
            "storyline_dhcp_server:"
            f"{getattr(self, '_current_storyline_spec_id', '')}:{system.hostname}"
        )
        % len(dhcp_servers)
    ].ip
    lease_time = (
        float(existing_lease["lease_time"])
        if existing_lease
        else float(rng.choice([3600, 7200, 14400, 86400]))
    )
    if existing_lease:
        legacy_timer_state = "renewal_rng" not in existing_lease
        renewal_sequence = int(existing_lease.get("renewal_sequence", 0))
        renewal_rng = existing_lease.get("renewal_rng")
        if renewal_rng is None:
            renewal_rng = random.Random(_stable_seed(f"dhcp_renewal_timer:{system.hostname}:{mac}"))
        if "timer_granularity" in existing_lease:
            timer_granularity = float(existing_lease["timer_granularity"])
        else:
            timer_granularity = renewal_rng.choice([0.25, 1.0, 1.0, 5.0])
    else:
        legacy_timer_state = False
        renewal_sequence = 0
        renewal_rng = random.Random(_stable_seed(f"dhcp_renewal_timer:{system.hostname}:{mac}"))
        timer_granularity = renewal_rng.choice([0.25, 1.0, 1.0, 5.0])
    if legacy_timer_state:
        renewal_interval = float(existing_lease["renewal_interval"])
    else:
        renewal_interval = dhcp_renewal_interval_seconds(
            lease_time,
            timing_runtime=self.timing_runtime,
            stable_id=f"{system.hostname}|{mac}",
            host=system.hostname,
            renewal_sequence=renewal_sequence,
            timer_granularity=timer_granularity,
        )
        renewal_sequence += 1
    msg_types = ["REQUEST", "ACK"] if existing_lease else None
    authored_ids_alerts = _build_ids_alert_contexts(
        getattr(spec, "ids_alerts", []),
        time=time,
        src_ip=system.ip,
        dst_ip=dhcp_server,
        dst_port=67,
        proto="udp",
        rng=rng,
        source="storyline_dhcp_lease",
    )
    self.activity_generator.generate_dhcp_lease(
        system=system,
        time=time,
        mac=mac,
        server_addr=dhcp_server,
        lease_time=lease_time,
        uid=generate_zeek_uid("C"),
        msg_types=msg_types,
        renewal_interval=renewal_interval,
        ids_alerts=authored_ids_alerts,
    )
    if hasattr(self, "_dhcp_lease_state"):
        self._dhcp_lease_state[system.hostname] = {
            "mac": mac,
            "lease_time": lease_time,
            "last_renewal": time.timestamp(),
            "next_renewal": time.timestamp() + renewal_interval,
            "renewal_interval": renewal_interval,
            "renewal_rng": renewal_rng,
            "renewal_sequence": renewal_sequence,
            "timer_granularity": timer_granularity,
            "server_addr": dhcp_server,
            "system": system,
        }
    malicious_event["mac_address"] = mac
    if getattr(spec, "ids_alerts", []):
        malicious_event["ids_alerts"] = _ids_attachment_ground_truth(spec.ids_alerts)

    return context.malicious_event


def handle_port_scan(
    self: StorylineMixin, spec: PortScanEventSpec, context: TypedEventContext
) -> dict[str, Any] | None:
    """Execute the port_scan evidence path using the existing runtime owners."""
    actor = context.actor
    system = context.system
    time = context.time
    rng = context.rng
    malicious_event = context.malicious_event
    malicious_event = PortScanActionBundle(
        executor=self,
        request=PortScanRequest(
            spec=spec,
            actor=actor,
            system=system,
            time=time,
            rng=rng,
            malicious_event=malicious_event,
        ),
    ).execute()

    return context.malicious_event


def handle_web_scan(
    self: StorylineMixin, spec: WebScanEventSpec, context: TypedEventContext
) -> dict[str, Any] | None:
    """Execute the web_scan evidence path using the existing runtime owners."""
    actor = context.actor
    system = context.system
    time = context.time
    rng = context.rng
    malicious_event = context.malicious_event
    malicious_event = WebScanActionBundle(
        executor=self,
        request=WebScanRequest(
            spec=spec,
            actor=actor,
            system=system,
            time=time,
            rng=rng,
            malicious_event=malicious_event,
        ),
    ).execute()

    return context.malicious_event
