# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Shared http protocol planning helpers."""

from __future__ import annotations

import logging
import random
import re
from dataclasses import replace
from urllib.parse import urlsplit

from evidenceforge.events.base import OccurrenceBuilder
from evidenceforge.events.contexts import (
    HttpContext,
)
from evidenceforge.generation.actions import (
    HttpFileTransferActionBundle,
    HttpFileTransferRequest,
    HttpResponseFileTransferActionBundle,
    HttpResponseFileTransferRequest,
    http_response_parent_duration_floor,
)
from evidenceforge.generation.deployment_registry import (
    DeploymentContentRegistry,
)
from evidenceforge.generation.source_timing import (
    SourceTimingPlanningRuntime,
)
from evidenceforge.generation.timing import (
    TimingRuntime,
    TimingScope,
    TruncatedLognormalDistribution,
)
from evidenceforge.models.exceptions import StateError
from evidenceforge.utils.rng import _stable_seed

from .network_proxy import _proxy_time_taken_ms

logger = logging.getLogger(__name__)


def _extract_http_url_from_command(command_line: str) -> str | None:
    """Return the first valid HTTP(S) URL embedded in a process command line."""
    for match in re.finditer(r"https?://[^\s'\"<>]+", command_line):
        candidate = match.group(0).rstrip(").,;]")
        try:
            parsed = urlsplit(candidate)
            _ = parsed.port
        except ValueError:
            continue
        if parsed.scheme in {"http", "https"} and parsed.hostname:
            return candidate
    return None


def _http_user_agent_for_process(process_name: str, command_line: str) -> str:
    """Return a source-native HTTP User-Agent for command-line HTTP clients."""
    exe = process_name.rsplit("\\", 1)[-1].rsplit("/", 1)[-1].lower()
    command = command_line.lower()
    if exe in {"curl", "curl.exe"} or command.startswith("curl "):
        return "curl/7.88.1"
    if exe in {"wget", "wget.exe"} or command.startswith("wget "):
        return "Wget/1.21.3"
    if "python" in exe and "requests" in command:
        return "python-requests/2.31.0"
    return ""


def _is_tool_http_user_agent(user_agent: str) -> bool:
    """Return true when the UA identifies a command-line/library HTTP client."""
    ua = user_agent.strip().lower()
    return ua.startswith(
        (
            "curl/",
            "wget/",
            "python-requests/",
            "go-http-client/",
            "apache-httpclient/",
            "powershell/",
        )
    )


def _source_native_http_referrer(
    user_agent: str,
    referrer: str,
    *,
    request_scheme: str | None = None,
    request_port: int | None = None,
) -> str:
    """Return a referrer that agrees with the HTTP client family."""
    if not referrer:
        return ""
    if _is_tool_http_user_agent(user_agent):
        return ""
    target_is_plaintext = request_scheme == "http" or request_port == 80
    if target_is_plaintext:
        try:
            if urlsplit(referrer).scheme == "https":
                return ""
        except ValueError:
            return ""
    return referrer


def _http_method_for_process_command(command_line: str) -> str:
    """Infer the HTTP method visible for a simple CLI HTTP command."""
    lowered = f" {command_line.lower()} "
    if " -i " in lowered or " --head " in lowered or " --head" in lowered:
        return "HEAD"
    method_match = re.search(r"(?:\s-X\s+|\s--request\s+)([A-Za-z]+)", command_line)
    if method_match:
        return method_match.group(1).upper()
    return "GET"


def _http_context_from_process_command(
    process_name: str,
    command_line: str,
    *,
    response_body_len: int,
) -> tuple[HttpContext, str, int, str] | None:
    """Build canonical HTTP request metadata from a process command URL.

    Returns ``(context, host, port, service)`` so the owning process, proxy, and
    Zeek records agree on host, path, method, and User-Agent for the same flow.
    """
    http_url = _extract_http_url_from_command(command_line)
    if not http_url:
        return None
    try:
        parsed = urlsplit(http_url)
        host = parsed.hostname or ""
        if not host:
            return None
        service = "ssl" if parsed.scheme == "https" else "http"
        port = parsed.port or (443 if service == "ssl" else 80)
    except ValueError:
        return None
    path = parsed.path or "/"
    if parsed.query:
        path = f"{path}?{parsed.query}"
    user_agent = _http_user_agent_for_process(process_name, command_line)
    if not user_agent:
        return None

    from evidenceforge.generation.activity.http_content import (
        infer_mime_type_from_path,
        is_stable_resource_path,
        response_mime_types_for_status,
        response_size_for_status,
    )

    mime_type = infer_mime_type_from_path(path)
    method = _http_method_for_process_command(command_line)
    body_len = 0 if method == "HEAD" else response_body_len
    if method != "HEAD" and is_stable_resource_path(path):
        body_len = response_size_for_status(200, host, path)
    context = HttpContext(
        method=method,
        host=host if port in (80, 443) else f"{host}:{port}",
        uri=path,
        version="1.1",
        user_agent=user_agent,
        request_body_len=0,
        response_body_len=body_len,
        status_code=200,
        status_msg="OK",
        referrer="",
        resp_mime_types=response_mime_types_for_status(
            200,
            mime_type,
            body_len,
            method=method,
        ),
        tags=[],
    )
    return context, host, port, service


def _normalize_http_context_for_source_native_response(http: HttpContext) -> HttpContext:
    """Keep caller-provided HTTP metadata source-native before cross-source fan-out."""
    from evidenceforge.generation.activity.http_content import (
        coerce_response_size_for_mime,
        http_response_body_is_prohibited,
        http_status_message,
        is_download_scale_mime,
        is_stable_resource_path,
        normalize_mime_type_for_path,
        response_mime_types_for_status,
    )

    method = (http.method or "GET").upper()
    status_code = http.status_code
    response_body_len = max(0, http.response_body_len)
    status_msg = http.status_msg
    bodyless_status = http_response_body_is_prohibited(method, status_code)

    if bodyless_status:
        response_body_len = 0
    elif (
        status_code == 200
        and response_body_len == 0
        and method not in {"CONNECT", "HEAD"}
        and is_stable_resource_path(http.uri)
    ):
        status_code = 304
        status_msg = http_status_message(status_code)
    elif method != "CONNECT":
        status_msg = http_status_message(status_code)

    resp_mime_types = list(http.resp_mime_types)
    if 200 <= status_code < 300 and not bodyless_status:
        mime_type = (
            resp_mime_types[0]
            if resp_mime_types
            else normalize_mime_type_for_path(
                http.uri,
                "text/html",
            )
        )
        if is_download_scale_mime(mime_type):
            response_body_len = coerce_response_size_for_mime(
                random.Random(
                    _stable_seed(
                        "http_context_body_size:"
                        f"{http.host}:{http.uri}:{mime_type}:{response_body_len}"
                    )
                ),
                mime_type,
                response_body_len,
            )
    if not resp_mime_types or response_body_len <= 0 or bodyless_status or status_code >= 400:
        mime_type = resp_mime_types[0] if resp_mime_types else ""
        if not mime_type and response_body_len > 0 and status_code < 300:
            mime_type = normalize_mime_type_for_path(
                http.uri,
                "application/octet-stream",
            )
        resp_mime_types = response_mime_types_for_status(
            status_code,
            mime_type,
            response_body_len,
            method=method,
        )

    if (
        status_code == http.status_code
        and status_msg == http.status_msg
        and response_body_len == http.response_body_len
        and resp_mime_types == list(http.resp_mime_types)
    ):
        return http
    return replace(
        http,
        response_body_len=response_body_len,
        status_code=status_code,
        status_msg=status_msg,
        resp_mime_types=resp_mime_types,
    )


def _apply_plaintext_http_policy(
    http: HttpContext,
    *,
    hostname: str | None,
    dst_ip: str,
    dst_port: int,
) -> HttpContext:
    """Apply public-domain plaintext HTTP policy to caller-provided HTTP context."""
    if not hostname or dst_port != 80:
        return http

    from evidenceforge.generation.activity.http_content import (
        http_status_message,
        response_mime_types_for_status,
        response_size_for_status,
    )
    from evidenceforge.generation.activity.proxy_uri import plaintext_http_redirect_status

    redirect_status = plaintext_http_redirect_status(
        hostname,
        port=dst_port,
        path=http.uri,
        dst_ip=dst_ip,
    )
    if redirect_status is None or http.status_code in {301, 302}:
        return http

    response_body_len = (
        0
        if (http.method or "GET").upper() == "HEAD"
        else response_size_for_status(redirect_status, hostname, http.uri)
    )
    resp_mime_types = response_mime_types_for_status(
        redirect_status,
        "text/html",
        response_body_len,
        method=http.method,
    )
    return replace(
        http,
        response_body_len=response_body_len,
        flow_response_body_len=response_body_len
        if http.flow_response_body_len is not None
        else None,
        status_code=redirect_status,
        status_msg=http_status_message(redirect_status),
        resp_mime_types=resp_mime_types,
    )


def _attach_http_file_transfers(
    event: OccurrenceBuilder,
    *,
    dst_ip: str,
    rng: random.Random,
    timing_runtime: TimingRuntime | SourceTimingPlanningRuntime | None = None,
    timing_scope: TimingScope | None = None,
    deployment_registry: DeploymentContentRegistry | None = None,
) -> None:
    """Attach source-native Zeek files.log metadata for visible HTTP entities."""

    if event.network is None or event.http is None:
        return
    if event.network.service != "http" or event.network.conn_state != "SF":
        return
    http = event.http
    method = (http.method or "GET").upper()
    runtime = (
        timing_runtime if timing_runtime is not None else TimingRuntime.compatibility_default()
    )
    if type(runtime) not in {TimingRuntime, SourceTimingPlanningRuntime}:
        raise StateError("HTTP file-transfer timing requires an exact engine TimingRuntime")
    scope = timing_scope or TimingScope(
        stable_id=(
            f"http-files:{event.network.src_ip}:{event.network.src_port}:"
            f"{event.network.dst_ip}:{event.network.dst_port}:{http.host}:{http.uri}:"
            f"{event.timestamp.isoformat()}"
        ),
        source="network",
        lifecycle_id=event.network.conn_id or event.network.zeek_uid,
    )

    def parent_duration_slack(sample_key: str) -> float:
        """Return right-skew transfer slack without a fixed floor or ceiling atom."""

        return runtime.sampler.sample_timedelta(
            TruncatedLognormalDistribution(
                median=145_000.0,
                sigma=0.72,
                minimum=50_000.0,
                maximum=550_001.0,
            ),
            relationship_key="network.http.file_parent_duration_slack",
            scope=scope,
            sample_key=sample_key,
        ).total_seconds()

    existing = [
        transfer
        for transfer in (event.file_transfer, *event.file_transfers)
        if transfer is not None
    ]
    has_request_transfer = any(transfer.is_orig for transfer in existing)
    has_response_transfer = any(not transfer.is_orig for transfer in existing)

    if http.request_body_len > 0 and not has_request_transfer:
        from evidenceforge.generation.activity.http_file_profiles import (
            request_content_type_for_activity,
        )

        request_entity = http.request_entity
        request_mime = http.request_content_type or (
            request_entity.mime_type if request_entity is not None else ""
        )
        if not request_mime:
            request_mime = request_content_type_for_activity(
                method,
                http.uri,
                http.user_agent,
                local_source_path=(request_entity.local_source_path if request_entity else ""),
            )
        request_duration_floor = http_response_parent_duration_floor(http.request_body_len)
        if request_duration_floor > 0:
            event.network.duration = max(
                event.network.duration or 0.0,
                request_duration_floor + parent_duration_slack("request"),
            )
            if event.proxy is not None:
                event.proxy = replace(
                    event.proxy,
                    time_taken=_proxy_time_taken_ms(
                        event.network.duration,
                        rng,
                        method=event.proxy.method,
                        status_code=event.proxy.status_code,
                        cache_result=event.proxy.cache_result,
                        stable_id=f"{scope.stable_id}:proxy-request-duration",
                    ),
                )
        content_identity = (
            request_entity.content_identity
            if request_entity is not None
            else (
                f"http-request:{http.host}:{http.uri}:{method}:"
                f"{http.request_body_len}:{request_mime}"
            )
        )
        request_result = HttpFileTransferActionBundle(
            HttpFileTransferRequest(
                host=http.host,
                uri=http.uri,
                dst_ip=dst_ip,
                body_len=http.request_body_len,
                mime_types=(request_mime,),
                timestamp=event.timestamp,
                is_orig=True,
                multipart=http.request_multipart,
                filename=request_entity.wire_filename if request_entity else "",
                content_identity=content_identity,
                parent_duration=event.network.duration,
            ),
            rng,
            timing_runtime=runtime,
        ).execute()
        event.file_transfers.extend(request_result.file_transfers)
        request_transfers = request_result.file_transfers
        from evidenceforge.generation.activity.http_file_profiles import load_http_file_profiles

        max_files_orig = int(load_http_file_profiles()["multipart"]["max_files_orig"])
        request_referenced = request_transfers[:max_files_orig]
        event.http = replace(
            event.http,
            request_content_type=request_mime,
            orig_fuids=tuple(transfer.fuid for transfer in request_referenced),
            orig_filenames=tuple(
                transfer.filename for transfer in request_referenced if transfer.filename
            ),
            orig_mime_types=tuple(
                transfer.mime_type for transfer in request_transfers if transfer.mime_type
            )[:max_files_orig],
        )
        event.pe_analyses.extend(request_result.pe_analyses)

    http = event.http
    from evidenceforge.generation.activity.http_content import http_response_has_entity_body

    if has_response_transfer or not http_response_has_entity_body(
        method,
        http.status_code,
        http.response_body_len,
    ):
        return

    duration_floor = http_response_parent_duration_floor(http.response_body_len)
    if duration_floor > 0:
        min_http_file_duration = duration_floor + parent_duration_slack("response")
        event.network.duration = max(event.network.duration or 0.0, min_http_file_duration)
        if event.proxy is not None:
            event.proxy = replace(
                event.proxy,
                time_taken=_proxy_time_taken_ms(
                    event.network.duration,
                    rng,
                    method=event.proxy.method,
                    status_code=event.proxy.status_code,
                    cache_result=event.proxy.cache_result,
                    stable_id=f"{scope.stable_id}:proxy-response-duration",
                ),
            )

    file_result = HttpResponseFileTransferActionBundle(
        HttpResponseFileTransferRequest(
            host=http.host,
            uri=http.uri,
            dst_ip=dst_ip,
            response_body_len=http.response_body_len,
            response_mime_types=list(http.resp_mime_types),
            timestamp=event.timestamp,
            multipart=http.response_multipart,
            content_identity=http.response_content_identity,
            parent_duration=event.network.duration,
        ),
        rng,
        timing_runtime=runtime,
    ).execute()
    if file_result.file_transfers and event.file_transfer is None:
        event.file_transfer = file_result.file_transfers[0]
        event.file_transfers.extend(file_result.file_transfers[1:])
    else:
        event.file_transfers.extend(file_result.file_transfers)
    from evidenceforge.generation.activity.http_file_profiles import load_http_file_profiles

    max_files_resp = int(load_http_file_profiles()["multipart"]["max_files_resp"])
    response_referenced = file_result.file_transfers[:max_files_resp]
    event.http = replace(
        event.http,
        resp_fuids=tuple(transfer.fuid for transfer in response_referenced),
        resp_filenames=tuple(
            transfer.filename for transfer in response_referenced if transfer.filename
        ),
        resp_mime_types=tuple(
            transfer.mime_type for transfer in file_result.file_transfers if transfer.mime_type
        )[:max_files_resp],
    )
    event.pe_analyses.extend(file_result.pe_analyses)


def _http_context_flow_body_len(http: HttpContext, side: str) -> int:
    """Return the HTTP body bytes represented by the parent TCP flow."""
    if side == "request":
        value = http.flow_request_body_len
        fallback = http.request_body_len
    else:
        value = http.flow_response_body_len
        fallback = http.response_body_len
    if value is None:
        value = fallback
    return max(0, value or 0)


def _http_context_flow_transaction_count(http: HttpContext) -> int:
    """Return the number of HTTP transactions represented by the parent TCP flow."""
    return max(1, http.flow_transaction_count or 1)


def _http_request_header_len(http: HttpContext, transaction_count: int) -> int:
    """Approximate source-native HTTP request header bytes for conn.log payload accounting."""
    method = (http.method or "GET").upper()
    version = http.version or "1.1"
    uri = http.uri or "/"
    host = http.host or "-"
    user_agent = http.user_agent or ""
    body_len = _http_context_flow_body_len(http, "request")
    seed = _stable_seed(
        f"http_request_headers:{method}:{host}:{uri}:{user_agent}:{transaction_count}:{body_len}"
    )
    accept = "*/*" if not user_agent else "text/html,application/xhtml+xml,*/*;q=0.8"
    header_lines = [
        f"{method} {uri} HTTP/{version}",
        f"Host: {host}",
        f"Accept: {accept}",
        "Accept-Encoding: gzip, deflate, br",
        "Connection: keep-alive" if transaction_count > 1 else "Connection: close",
    ]
    if user_agent:
        header_lines.append(f"User-Agent: {user_agent}")
    if http.referrer:
        header_lines.append(f"Referer: {http.referrer}")
    if http.status_code == 304:
        header_lines.append(f'If-None-Match: W/"{seed & 0xFFFFFFFF:x}"')
    if body_len > 0:
        header_lines.append(f"Content-Length: {body_len}")
        header_lines.append(
            f"Content-Type: {http.request_content_type or 'application/octet-stream'}"
        )
    base_len = sum(len(line.encode("utf-8")) + 2 for line in header_lines) + 2
    per_transaction_extra = 24 + (seed % 97)
    return (base_len + per_transaction_extra) * transaction_count


def _http_response_header_len(http: HttpContext, transaction_count: int) -> int:
    """Approximate source-native HTTP response header bytes for conn.log payload accounting."""
    method = (http.method or "GET").upper()
    status_code = int(http.status_code or 0)
    status_msg = http.status_msg or "OK"
    host = http.host or "-"
    uri = http.uri or "/"
    body_len = _http_context_flow_body_len(http, "response")
    seed = _stable_seed(
        f"http_response_headers:{method}:{status_code}:{status_msg}:{host}:{uri}:"
        f"{transaction_count}:{body_len}"
    )
    content_type = http.resp_mime_types[0] if http.resp_mime_types else "text/html"
    header_lines = [
        f"HTTP/{http.version or '1.1'} {status_code} {status_msg}",
        "Server: nginx",
        f"Content-Length: {0 if method == 'HEAD' else body_len}",
        "Connection: keep-alive" if transaction_count > 1 else "Connection: close",
    ]
    if method != "HEAD" and status_code not in {204, 304}:
        header_lines.append(f"Content-Type: {content_type}")
    if status_code in {301, 302}:
        header_lines.append(f"Location: https://{host}{uri if uri.startswith('/') else '/'}")
    if status_code == 304:
        header_lines.append(f'ETag: W/"{seed & 0xFFFFFFFF:x}"')
        header_lines.append("Cache-Control: max-age=300")
    if 200 <= status_code < 300:
        header_lines.append(f"Date: {seed % 28 + 1:02d} May 2026 12:00:00 GMT")
    base_len = sum(len(line.encode("utf-8")) + 2 for line in header_lines) + 2
    per_transaction_extra = 16 + (seed % 83)
    return (base_len + per_transaction_extra) * transaction_count


def _http_flow_payload_bytes(http: HttpContext) -> tuple[int, int]:
    """Return TCP payload byte counts implied by source-native HTTP metadata."""
    transaction_count = _http_context_flow_transaction_count(http)
    request_bytes = _http_context_flow_body_len(http, "request") + _http_request_header_len(
        http,
        transaction_count,
    )
    response_body_len = _http_context_flow_body_len(http, "response")
    response_header_len = _http_response_header_len(http, transaction_count)
    response_bytes = response_header_len
    if (http.method or "GET").upper() != "HEAD":
        response_bytes += response_body_len
    return request_bytes, response_bytes
