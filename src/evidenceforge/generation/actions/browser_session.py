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

"""Browser-session action bundle."""

from __future__ import annotations

import random
import re
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any, Protocol
from urllib.parse import urlsplit

from evidenceforge.events.contexts import HttpContext, HttpRequestEntityContext
from evidenceforge.generation.actions.base import ActionAnchor
from evidenceforge.generation.activity import browsing_session
from evidenceforge.generation.activity.http_content import (
    http_status_message,
    is_stable_resource_path,
    response_mime_types_for_status,
)
from evidenceforge.generation.baseline_timing import BaselineTimingPlanner
from evidenceforge.generation.state_manager import StateManager
from evidenceforge.generation.timing import TimingRuntime
from evidenceforge.utils.rng import _stable_seed
from evidenceforge.utils.time import ensure_utc

_HttpGroupKey = tuple[str, int]
_HttpPlanValue = tuple[_HttpGroupKey, int, bool, int]


@dataclass(frozen=True, slots=True)
class BrowserSessionRequest:
    """Intent for one modeled browser page-load session."""

    src_ip: str
    dst_ip: str
    time: datetime
    hostname: str
    dst_port: int
    proto: str = "tcp"
    service: str | None = None
    source_system: Any | None = None
    pid: int = -1
    domain_tags: tuple[str, ...] = ()
    source_os: str = "windows"
    browsing_intensity: str = "normal"
    require_browser_like_domain: bool = True
    transfer_variant_key: str | None = None
    user_agent: str | None = None
    route_profile: Any | None = None
    same_host_only: bool = False
    page_load_budget: int | None = None
    latest_request_time: datetime | None = None
    request_body_floor: int = 0
    secondary_duration_min: float = 0.05
    emit_dns_on_page_load: bool = True
    include_flow_context: bool = True
    set_current_time: bool = True
    source: str = "activity_generator"

    @property
    def stable_id(self) -> str:
        """Return a deterministic intent identifier for durable references."""

        source_host = getattr(self.source_system, "hostname", "") if self.source_system else ""
        seed = _stable_seed(
            "action_bundle:browser_session:"
            f"{self.src_ip}:{source_host}:{self.dst_ip}:{self.dst_port}:"
            f"{self.hostname}:{self.proto}:{self.service or ''}:"
            f"{self.pid}:{self.source_os}:{self.browsing_intensity}:"
            f"{self.require_browser_like_domain}:{self.transfer_variant_key or ''}:"
            f"{self.user_agent or ''}:{bool(self.route_profile)}:"
            f"{self.same_host_only}:{self.page_load_budget or ''}:"
            f"{ensure_utc(self.latest_request_time).isoformat() if self.latest_request_time else ''}:"
            f"{self.request_body_floor}:{self.time.isoformat()}:{self.source}:"
            f"{','.join(self.domain_tags)}"
        )
        return f"browser-session-{seed:016x}"


@dataclass(frozen=True, slots=True)
class BrowserSessionResult:
    """Summary of browser-session expansion."""

    first_uid: str = ""
    request_count: int = 0
    page_load_count: int = 0


class BrowserSessionExecutor(Protocol):
    """Runtime hooks supplied by the activity generator."""

    state_manager: StateManager

    def generate_connection(self, **kwargs: Any) -> str:
        """Generate a canonical connection event."""
        ...


@dataclass(frozen=True, slots=True)
class BrowserSessionActionBundle:
    """Action bundle for one browser-like multi-request web session."""

    request: BrowserSessionRequest
    executor: BrowserSessionExecutor
    rng: random.Random
    static_cache_seen: dict[tuple[str, str, str], int] | None = None
    timing_runtime: TimingRuntime | None = None

    @property
    def resolved_timing_runtime(self) -> TimingRuntime | None:
        """Return a real injected runtime without accepting mock-like adapters."""

        if isinstance(self.timing_runtime, TimingRuntime):
            return self.timing_runtime
        candidate = getattr(self.executor, "timing_runtime", None)
        return candidate if isinstance(candidate, TimingRuntime) else None

    @property
    def timing(self) -> BaselineTimingPlanner:
        """Return the engine timing runtime or an isolated direct-call adapter."""

        runtime = self.resolved_timing_runtime
        if runtime is not None:
            return BaselineTimingPlanner(runtime)
        return BaselineTimingPlanner.compatibility(self.request.time)

    @property
    def anchor(self) -> ActionAnchor:
        """Return the stable action anchor for this browser session."""

        return ActionAnchor(
            family="browser_session",
            stable_id=self.request.stable_id,
            source=self.request.source,
        )

    def execute(self) -> str:
        """Expand and dispatch browser-session evidence."""

        return self.execute_with_result().first_uid

    def execute_with_result(self) -> BrowserSessionResult:
        """Expand and dispatch browser-session evidence with summary counts."""

        request = self.request
        if request.route_profile is not None:
            session_requests = self._generate_route_profile_session()
        else:
            session_requests = browsing_session.generate_browsing_session(
                rng=self.rng,
                hostname=request.hostname,
                domain_tags=list(request.domain_tags),
                source_os=request.source_os,
                browsing_intensity=request.browsing_intensity,
                port=request.dst_port,
                require_browser_like_domain=request.require_browser_like_domain,
                transfer_variant_key=request.transfer_variant_key,
                request_time=request.time,
                timing_runtime=self.resolved_timing_runtime,
                timing_stable_id=request.stable_id,
            )
        visible_requests, page_load_count = self._visible_requests(session_requests)
        visible_requests = self._requests_before_deadline(visible_requests)
        page_load_count = sum(1 for req in visible_requests if req.is_page_load)
        if not visible_requests:
            return BrowserSessionResult()

        request_plan, request_groups = _plan_http_request_groups(
            visible_requests,
            request_body_floor=request.request_body_floor,
        )
        planned_requests = sorted(
            enumerate(visible_requests),
            key=lambda item: (request_plan[item[0]][3], item[0]),
        )

        first_uid = ""
        request_count = 0
        for req_index, req in planned_requests:
            group_key, trans_depth, first_in_group, emit_offset_us = request_plan[req_index]
            group = request_groups[group_key]
            uid = self._emit_request(
                req=req,
                group=group,
                trans_depth=trans_depth,
                first_in_group=first_in_group,
                emit_offset_us=emit_offset_us,
            )
            if uid and not first_uid:
                first_uid = uid
            request_count += 1

        return BrowserSessionResult(
            first_uid=first_uid,
            request_count=request_count,
            page_load_count=page_load_count,
        )

    def _requests_before_deadline(
        self,
        requests: list[browsing_session.BrowsingRequest],
    ) -> list[browsing_session.BrowsingRequest]:
        """Drop browser requests that would render after a visible session close."""

        if self.request.latest_request_time is None or not requests:
            return requests

        request_plan, _request_groups = _plan_http_request_groups(
            requests,
            request_body_floor=self.request.request_body_floor,
        )
        base_time = ensure_utc(self.request.time)
        deadline = ensure_utc(self.request.latest_request_time)
        visible: list[browsing_session.BrowsingRequest] = []
        current_page_allowed = False
        for index, req in enumerate(requests):
            _group_key, _trans_depth, _first_in_group, emit_offset_us = request_plan[index]
            req_ts = base_time + timedelta(microseconds=emit_offset_us)
            if req_ts >= deadline:
                if req.is_page_load:
                    current_page_allowed = False
                continue
            if req.is_page_load:
                current_page_allowed = True
            elif not current_page_allowed:
                continue
            visible.append(req)
        return visible

    def _generate_route_profile_session(self) -> list[browsing_session.BrowsingRequest]:
        """Generate route-owned HTTP requests for an authored web affinity."""

        routes = list(getattr(self.request.route_profile, "routes", []) or [])
        if not routes:
            return browsing_session.generate_browsing_session(
                rng=self.rng,
                hostname=self.request.hostname,
                domain_tags=list(self.request.domain_tags),
                source_os=self.request.source_os,
                browsing_intensity=self.request.browsing_intensity,
                port=self.request.dst_port,
                require_browser_like_domain=self.request.require_browser_like_domain,
                transfer_variant_key=self.request.transfer_variant_key,
                request_time=self.request.time,
                timing_runtime=self.resolved_timing_runtime,
                timing_stable_id=self.request.stable_id,
            )

        page_bounds = {
            "light": (1, 1),
            "normal": (1, 2),
            "heavy": (2, 4),
        }.get(self.request.browsing_intensity, (1, 2))
        request_count = self.rng.randint(*page_bounds)
        route_weights = [float(getattr(route, "weight", 1.0)) for route in routes]
        requests: list[browsing_session.BrowsingRequest] = []
        elapsed_us = 0
        referrer = ""
        for index in range(request_count):
            route = self.rng.choices(routes, weights=route_weights, k=1)[0]
            method_profiles = getattr(route, "methods", {}) or {}
            method_names = list(method_profiles)
            method = self.rng.choice(method_names) if method_names else "GET"
            profile = method_profiles.get(method)
            status_weights = getattr(profile, "statuses", {"200": 1.0}) if profile else {"200": 1.0}
            status = int(
                self.rng.choices(
                    list(status_weights),
                    weights=[float(weight) for weight in status_weights.values()],
                    k=1,
                )[0]
            )
            path = self._render_route_path(str(getattr(route, "path", "/")))
            content_type = (
                str(getattr(profile, "content_type", "text/html")) if profile else "text/html"
            )
            request_content_type = (
                str(getattr(profile, "request_content_type", "") or "") if profile else ""
            )
            request_wire_filename = (
                str(getattr(profile, "request_wire_filename", "") or "") if profile else ""
            )
            request_multipart_spec = (
                getattr(profile, "request_multipart", None) if profile else None
            )
            response_multipart_spec = (
                getattr(profile, "response_multipart", None) if profile else None
            )
            req_range = getattr(profile, "request_body_bytes", None) if profile else None
            resp_range = getattr(profile, "response_body_bytes", None) if profile else None
            request_body_len = (
                self.rng.randint(int(req_range[0]), int(req_range[1]))
                if req_range
                else (self.rng.randint(100, 4000) if method not in {"GET", "HEAD"} else 0)
            )
            response_body_len = (
                self.rng.randint(int(resp_range[0]), int(resp_range[1]))
                if resp_range
                else browsing_session._response_size_for_status_code(  # noqa: SLF001
                    self.rng,
                    self.request.hostname,
                    path,
                    content_type,
                    status,
                    transfer_variant_key=self.request.transfer_variant_key,
                )
            )
            request_multipart = None
            response_multipart = None
            legacy_wire_filename = bool(request_wire_filename and request_multipart_spec is None)
            if legacy_wire_filename:
                from evidenceforge.models.http import HttpMultipartEntitySpec

                request_multipart_spec = HttpMultipartEntitySpec.model_validate(
                    {
                        "media_type": "multipart/form-data",
                        "parts": [
                            {
                                "name": "file",
                                "body_len": 0,
                                "filename": request_wire_filename,
                                "content_type": request_content_type or "application/octet-stream",
                            }
                        ],
                    }
                )
            if request_multipart_spec is not None or response_multipart_spec is not None:
                from evidenceforge.generation.activity.http_multipart import (
                    build_http_multipart_context,
                )

                stable_key = f"{self.request.stable_id}:route:{index}:{method}:{path}"
                if request_multipart_spec is not None:
                    if legacy_wire_filename:
                        envelope = build_http_multipart_context(
                            request_multipart_spec,
                            stable_key=f"{stable_key}:request",
                            user_agent=self.request.user_agent or "Mozilla/5.0",
                        )
                        if request_body_len > envelope.body_len:
                            request_multipart_spec = request_multipart_spec.model_copy(
                                update={
                                    "parts": [
                                        request_multipart_spec.parts[0].model_copy(
                                            update={
                                                "body_len": request_body_len - envelope.body_len
                                            }
                                        )
                                    ]
                                }
                            )
                        else:
                            request_multipart_spec = None
                    if request_multipart_spec is not None:
                        request_multipart = build_http_multipart_context(
                            request_multipart_spec,
                            stable_key=f"{stable_key}:request",
                            user_agent=self.request.user_agent or "Mozilla/5.0",
                        )
                        request_body_len = request_multipart.body_len
                        request_content_type = (
                            f"{request_multipart.media_type}; boundary={request_multipart.boundary}"
                        )
                if response_multipart_spec is not None:
                    response_multipart = build_http_multipart_context(
                        response_multipart_spec,
                        stable_key=f"{stable_key}:response",
                        client_family="generic",
                    )
                    response_body_len = response_multipart.body_len
            if index:
                elapsed_us += round(
                    self.timing.right_skew_seconds(
                        relationship_key="browser.route.request_gap",
                        stable_id=self.request.stable_id,
                        minimum=0.250,
                        median=0.680,
                        maximum=2.400,
                        sigma=0.78,
                        host=getattr(self.request.source_system, "hostname", ""),
                        lifecycle_id=self.request.stable_id,
                        ordinal=index,
                    )
                    * 1_000_000
                )
            requests.append(
                browsing_session.BrowsingRequest(
                    time_offset_ms=elapsed_us // 1_000,
                    time_offset_remainder_us=elapsed_us % 1_000,
                    hostname=self.request.hostname,
                    path=path,
                    method=method,
                    content_type=content_type,
                    referrer=referrer,
                    trans_depth=index + 1,
                    is_page_load=True,
                    response_body_len=response_body_len,
                    request_body_len=request_body_len,
                    status_code=status,
                    request_content_type=request_content_type,
                    request_wire_filename=request_wire_filename,
                    request_multipart=request_multipart,
                    response_multipart=response_multipart,
                )
            )
            referrer = browsing_session._make_referrer(  # noqa: SLF001
                self.request.hostname,
                path,
                self.request.dst_port,
            )
        return requests

    def _render_route_path(self, path: str) -> str:
        """Render common route placeholders with deterministic per-session values."""

        def _replace(match: re.Match[str]) -> str:
            token = match.group(1)
            if token in {"id", "n"}:
                return str(self.rng.randint(1, 9999))
            if token == "hex8":
                return f"{self.rng.getrandbits(32):08x}"
            if token == "hex16":
                return f"{self.rng.getrandbits(64):016x}"
            return token

        return re.sub(r"\{([A-Za-z0-9_]+)\}", _replace, path)

    def _visible_requests(
        self,
        session_requests: list[browsing_session.BrowsingRequest],
    ) -> tuple[list[browsing_session.BrowsingRequest], int]:
        """Return requests visible for this session intent."""

        request = self.request
        visible_requests: list[browsing_session.BrowsingRequest] = []
        page_load_count = 0
        current_page_allowed = request.page_load_budget is None

        for req in session_requests:
            if req.is_page_load:
                if (
                    request.page_load_budget is not None
                    and page_load_count >= request.page_load_budget
                ):
                    break
                page_load_count += 1
                current_page_allowed = True
            elif not current_page_allowed:
                continue

            if request.same_host_only and req.hostname != request.hostname:
                continue

            if self._is_cached_static_asset(req):
                continue

            visible_requests.append(req)

        return visible_requests, page_load_count

    def _is_cached_static_asset(self, req: browsing_session.BrowsingRequest) -> bool:
        """Return whether a repeated browser asset should be hidden by client cache."""

        if self.static_cache_seen is None or req.is_page_load:
            return False
        if not is_stable_resource_path(req.path):
            return False
        cache_key = (self.request.src_ip, self.request.hostname, req.path)
        if cache_key in self.static_cache_seen:
            self.static_cache_seen[cache_key] += 1
            return True
        self.static_cache_seen[cache_key] = 1
        return False

    def _emit_request(
        self,
        *,
        req: browsing_session.BrowsingRequest,
        group: dict[str, int],
        trans_depth: int,
        first_in_group: bool,
        emit_offset_us: int,
    ) -> str:
        """Emit one browser request as canonical connection/HTTP evidence."""

        request = self.request
        req_ts = request.time + timedelta(microseconds=emit_offset_us)
        if request.set_current_time:
            self.executor.state_manager.set_current_time(req_ts)

        req_hostname, req_dst_ip = self._resolve_destination(req)
        conn_duration = self._connection_duration(
            group=group,
            first_in_group=first_in_group,
            emit_offset_us=emit_offset_us,
        )
        conn_orig_bytes = self._connection_orig_bytes(
            req=req,
            group=group,
            first_in_group=first_in_group,
        )
        conn_resp_bytes = self._connection_resp_bytes(
            req=req,
            group=group,
            first_in_group=first_in_group,
        )
        emit_dns = (request.emit_dns_on_page_load and req.is_page_load) or (
            req_hostname != request.hostname
        )
        http_context = self._http_context(
            req=req,
            req_hostname=req_hostname,
            group=group,
            trans_depth=trans_depth,
            first_in_group=first_in_group,
        )

        generate_kwargs: dict[str, Any] = {
            "src_ip": request.src_ip,
            "dst_ip": req_dst_ip,
            "time": req_ts,
            "dst_port": request.dst_port,
            "proto": request.proto,
            "service": request.service,
            "duration": conn_duration,
            "orig_bytes": conn_orig_bytes,
            "resp_bytes": conn_resp_bytes,
            "emit_dns": emit_dns,
            "suppress_prereq_dns": not emit_dns,
            "source_system": request.source_system,
            "hostname": req_hostname,
            "http": http_context,
        }
        if request.pid != -1:
            generate_kwargs["pid"] = request.pid
        return self.executor.generate_connection(**generate_kwargs) or ""

    def _resolve_destination(
        self,
        req: browsing_session.BrowsingRequest,
    ) -> tuple[str, str]:
        """Return the hostname/IP pair for a request, preserving app CDN coherence."""

        if req.hostname == self.request.hostname:
            return self.request.hostname, self.request.dst_ip

        from evidenceforge.generation.activity.dns_registry import (
            pick_domain_and_ip,
            resolve_domain_ip,
        )

        app_specific_tags = [
            tag for tag in ("outlook", "teams", "onedrive") if tag in self.request.domain_tags
        ]
        source_host = (
            getattr(self.request.source_system, "hostname", None)
            if self.request.source_system is not None
            else None
        )
        resolver = getattr(self.executor, "_network_resolver", None)
        if app_specific_tags:
            return pick_domain_and_ip(
                self.rng,
                self.rng.choice(app_specific_tags),
                src_host=source_host,
            )
        if resolver is not None:
            resolved = resolver.resolve_host(req.hostname, src_host=source_host or "")
            if resolved.ip:
                return req.hostname, resolved.ip
        return req.hostname, resolve_domain_ip(req.hostname, src_host=source_host)

    def _connection_duration(
        self,
        *,
        group: dict[str, int],
        first_in_group: bool,
        emit_offset_us: int,
    ) -> float:
        """Return a source-native duration for the parent TCP flow."""

        host = getattr(self.request.source_system, "hostname", "")
        stable_id = f"{self.request.stable_id}:{emit_offset_us}"

        if first_in_group:
            remaining_us = max(0, group["last_offset_us"] - emit_offset_us)
            return (remaining_us / 1_000_000) + self.timing.right_skew_seconds(
                relationship_key="browser.connection.primary_tail",
                stable_id=stable_id,
                minimum=1.250,
                median=1.620,
                maximum=3.000,
                sigma=0.48,
                host=host,
                lifecycle_id=self.request.stable_id,
            )
        minimum = max(0.000001, self.request.secondary_duration_min)
        return self.timing.right_skew_seconds(
            relationship_key="browser.connection.secondary_duration",
            stable_id=stable_id,
            minimum=minimum,
            median=min(2.0, max(minimum + 0.000001, minimum * 2.6)),
            maximum=max(2.0, minimum + 0.000002),
            sigma=0.72,
            host=host,
            lifecycle_id=self.request.stable_id,
        )

    def _connection_orig_bytes(
        self,
        *,
        req: browsing_session.BrowsingRequest,
        group: dict[str, int],
        first_in_group: bool,
    ) -> int:
        """Return originator TCP payload bytes for this emitted flow."""

        if not first_in_group:
            return max(self.request.request_body_floor, req.request_body_len)
        request_overhead = 120 * group["request_count"]
        group_bytes = group["request_body_len"] + request_overhead
        if self.request.request_body_floor:
            return group_bytes
        return max(req.request_body_len, group_bytes)

    def _connection_resp_bytes(
        self,
        *,
        req: browsing_session.BrowsingRequest,
        group: dict[str, int],
        first_in_group: bool,
    ) -> int:
        """Return responder TCP payload bytes for this emitted flow."""

        if not first_in_group:
            return req.response_body_len
        response_overhead = 160 * group["request_count"]
        return max(req.response_body_len, group["response_body_len"] + response_overhead)

    def _http_context(
        self,
        *,
        req: browsing_session.BrowsingRequest,
        req_hostname: str,
        group: dict[str, int],
        trans_depth: int,
        first_in_group: bool,
    ) -> HttpContext:
        """Build source-native HTTP context for a browser request."""

        request = self.request
        referrer = req.referrer
        if request.dst_port == 80:
            try:
                if urlsplit(referrer).scheme == "https":
                    referrer = ""
            except ValueError:
                referrer = ""
        request_entity = None
        if (
            req.request_multipart is None
            and req.request_body_len > 0
            and (req.request_content_type or req.request_wire_filename)
        ):
            request_mime = req.request_content_type or "application/octet-stream"
            request_entity = HttpRequestEntityContext(
                size=req.request_body_len,
                mime_type=request_mime,
                content_identity=(
                    f"application-request:{req_hostname}:{req.path}:{req.method}:"
                    f"{req.request_body_len}:{request_mime}:{req.request_wire_filename}"
                ),
                encoding="multipart" if req.request_wire_filename else "raw",
                wire_filename=req.request_wire_filename,
            )
        return HttpContext(
            method=req.method,
            host=req_hostname,
            uri=req.path,
            version="1.1",
            user_agent=request.user_agent or "",
            request_body_len=req.request_body_len,
            request_content_type=req.request_content_type,
            request_entity=request_entity,
            request_multipart=req.request_multipart,
            response_body_len=req.response_body_len,
            response_multipart=req.response_multipart,
            flow_request_body_len=(
                group["request_body_len"]
                if request.include_flow_context and first_in_group
                else None
            ),
            flow_response_body_len=(
                group["response_body_len"]
                if request.include_flow_context and first_in_group
                else None
            ),
            flow_transaction_count=(
                group["request_count"] if request.include_flow_context and first_in_group else 1
            ),
            status_code=req.status_code,
            status_msg=http_status_message(req.status_code),
            referrer=referrer,
            trans_depth=trans_depth,
            resp_mime_types=response_mime_types_for_status(
                req.status_code,
                req.content_type,
                req.response_body_len,
                method=req.method,
            ),
            tags=[],
        )


def _plan_http_request_groups(
    requests: list[browsing_session.BrowsingRequest],
    *,
    request_body_floor: int = 0,
) -> tuple[dict[int, _HttpPlanValue], dict[_HttpGroupKey, dict[str, int]]]:
    """Plan source-native HTTP transaction depth and parent flow accounting."""

    group_counters: dict[str, int] = {}
    active_group: dict[str, _HttpGroupKey] = {}
    depths: dict[_HttpGroupKey, int] = {}
    last_emit_offset: dict[_HttpGroupKey, int] = {}
    plan: dict[int, _HttpPlanValue] = {}
    groups: dict[_HttpGroupKey, dict[str, int]] = {}

    for index, req in enumerate(requests):
        hostname = str(req.hostname)
        if req.is_page_load or hostname not in active_group:
            group_counters[hostname] = group_counters.get(hostname, 0) + 1
            active_group[hostname] = (hostname, group_counters[hostname])
            depths[active_group[hostname]] = 0

        group_key = active_group[hostname]
        depths[group_key] += 1
        trans_depth = depths[group_key]
        emit_offset_us = (req.time_offset_ms * 1_000) + req.time_offset_remainder_us
        if group_key in last_emit_offset:
            emit_offset_us = max(emit_offset_us, last_emit_offset[group_key] + 600_000)
        last_emit_offset[group_key] = emit_offset_us
        plan[index] = (group_key, trans_depth, trans_depth == 1, emit_offset_us)

        group = groups.setdefault(
            group_key,
            {
                "first_offset_us": emit_offset_us,
                "last_offset_us": emit_offset_us,
                "request_body_len": 0,
                "response_body_len": 0,
                "request_count": 0,
            },
        )
        group["first_offset_us"] = min(group["first_offset_us"], emit_offset_us)
        group["last_offset_us"] = max(group["last_offset_us"], emit_offset_us)
        group["request_body_len"] += max(request_body_floor, req.request_body_len)
        group["response_body_len"] += req.response_body_len
        group["request_count"] += 1

    return plan, groups
