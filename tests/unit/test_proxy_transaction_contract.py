# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Contract tests for explicit-proxy phase and byte ownership."""

from __future__ import annotations

from dataclasses import FrozenInstanceError
from datetime import UTC, datetime, timedelta
from unittest.mock import Mock

import pytest

from evidenceforge.events.base import SecurityEvent
from evidenceforge.events.contexts import HttpContext, NetworkContext, ProxyContext
from evidenceforge.events.dispatcher import EventDispatcher
from evidenceforge.events.lifecycle import ActionLifecycleContext
from evidenceforge.generation.actions.proxy_phase_planner import ProxyPhasePlanner
from evidenceforge.generation.actions.proxy_transaction import ProxyTransactionRequest
from evidenceforge.generation.activity.generator import ActivityGenerator
from evidenceforge.generation.activity.proxy_phase_profiles import proxy_resolver_profiles
from evidenceforge.generation.state_manager import StateManager
from evidenceforge.models.scenario import System

_BASE_TIME = datetime(2024, 1, 15, 10, 0, tzinfo=UTC)


def _systems() -> tuple[System, System]:
    workstation = System(
        hostname="WKS-01",
        ip="10.0.1.10",
        os="Windows 11",
        type="workstation",
    )
    proxy = System(
        hostname="PROXY-01",
        ip="10.0.3.10",
        os="Ubuntu 22.04",
        type="server",
        roles=["forward_proxy"],
    )
    return workstation, proxy


def _request(index: int = 0, *, duration: float | None = 1.0) -> ProxyTransactionRequest:
    workstation, proxy = _systems()
    return ProxyTransactionRequest(
        src_ip=workstation.ip,
        dst_ip="93.184.216.34",
        time=_BASE_TIME + timedelta(milliseconds=index * 17),
        dst_port=80,
        proto="tcp",
        service="http",
        duration=duration,
        orig_bytes=4600,
        resp_bytes=18_000,
        src_port=None,
        pid=-1,
        source_system=workstation,
        conn_state="SF",
        dns=None,
        ids=None,
        http=HttpContext(
            method="POST",
            host="example.com",
            uri="/api/v1/data",
            request_body_len=4096,
            response_body_len=16_384,
        ),
        file_transfer=None,
        ocsp=None,
        proxy=None,
        firewall=None,
        hostname="example.com",
        process_image=None,
        proxy_chain=[proxy],
        preserve_explicit_proxy_dst_ip=False,
        caller_provided_conn_state=True,
        ad_domain="example.org",
    )


def _proxy_context(
    *,
    cache_result: str = "MISS",
    status_code: int = 200,
) -> ProxyContext:
    return ProxyContext(
        client_ip="10.0.1.10",
        method="POST",
        url="http://example.com/api/v1/data",
        host="example.com",
        status_code=status_code,
        sc_bytes=16_620,
        cs_bytes=4_310,
        request_body_bytes=4096,
        response_body_bytes=16_384,
        cache_result=cache_result,
        proxy_fqdn="PROXY-01.example.org",
    )


def test_proxy_phase_plan_is_deterministic_ordered_and_immutable() -> None:
    request = _request(7)
    proxy = _proxy_context()
    planner = ProxyPhasePlanner()

    first = planner.plan(request, proxy, request.time)
    second = planner.plan(request, proxy, request.time)

    assert first == second
    assert first.client_connect_at <= first.request_at <= first.decision_at
    assert first.origin_connect_at is not None
    assert first.origin_close_at is not None
    assert first.decision_at < first.origin_connect_at < first.origin_close_at <= first.close_at
    assert first.time_taken_ms == round(
        (first.client_flush_at - first.request_at).total_seconds() * 1000
    )
    with pytest.raises(FrozenInstanceError):
        first.request_at = request.time  # type: ignore[misc]


@pytest.mark.parametrize(
    ("cache_result", "status_code", "expected_outcome"),
    [
        ("HIT", 200, "cache_hit"),
        ("DENIED", 403, "denied"),
        ("AUTH_REQUIRED", 407, "authentication_required"),
    ],
)
def test_proxy_terminal_policy_paths_stop_before_dns_and_origin(
    cache_result: str,
    status_code: int,
    expected_outcome: str,
) -> None:
    request = _request(status_code)
    plan = ProxyPhasePlanner().plan(
        request,
        _proxy_context(cache_result=cache_result, status_code=status_code),
        request.time,
    )

    assert plan.terminal_outcome == expected_outcome
    assert plan.resolver_mode is None
    assert plan.dns_query_at is None
    assert plan.origin_connect_at is None


def test_gateway_failure_keeps_attempted_origin_without_success_phases() -> None:
    request = _request(504)
    plan = ProxyPhasePlanner().plan(
        request,
        _proxy_context(cache_result="GATEWAY_ERROR", status_code=504),
        request.time,
    )

    assert plan.terminal_outcome == "gateway_failure"
    assert plan.origin_connect_at is not None
    assert plan.origin_close_at is not None
    assert plan.origin_conn_state == "S0"
    assert plan.origin_response_at is None
    assert plan.tls_complete_at is None


def test_resolver_mixture_matches_configured_contract_and_has_retry_tail() -> None:
    profiles = proxy_resolver_profiles()
    assert {profile.name: profile.weight for profile in profiles} == {
        "resolver_cache_hit": 65.0,
        "ordinary_lookup": 32.0,
        "retry_queue": 3.0,
    }

    planner = ProxyPhasePlanner()
    counts = {profile.name: 0 for profile in profiles}
    lookup_to_connect_gaps_ms: list[float] = []
    for index in range(1200):
        request = _request(index, duration=0.2)
        plan = planner.plan(request, _proxy_context(), request.time)
        assert plan.resolver_mode is not None
        counts[plan.resolver_mode] += 1
        if plan.resolver_mode == "resolver_cache_hit":
            assert plan.dns_query_at is None
            assert plan.origin_connect_at is not None
            gap_ms = (plan.origin_connect_at - plan.request_at).total_seconds() * 1000
            assert 5 <= gap_ms <= 75
            continue
        assert plan.dns_query_at is not None
        assert plan.dns_response_at is not None
        assert plan.origin_connect_at is not None
        completion_ms = (plan.dns_response_at - plan.request_at).total_seconds() * 1000
        origin_after_dns_ms = (plan.origin_connect_at - plan.dns_response_at).total_seconds() * 1000
        lookup_to_connect_gaps_ms.append(
            (plan.origin_connect_at - plan.dns_query_at).total_seconds() * 1000
        )
        if plan.resolver_mode == "ordinary_lookup":
            assert 8 <= completion_ms <= 120
            assert 2 <= origin_after_dns_ms <= 35
        else:
            assert 350 <= completion_ms <= 2500
            assert 5 <= origin_after_dns_ms <= 80

    assert 0.60 <= counts["resolver_cache_hit"] / 1200 <= 0.70
    assert 0.27 <= counts["ordinary_lookup"] / 1200 <= 0.37
    assert 0.01 <= counts["retry_queue"] / 1200 <= 0.05
    assert (
        sum(gap < 250 for gap in lookup_to_connect_gaps_ms) / len(lookup_to_connect_gaps_ms) >= 0.75
    )
    assert any(gap > 500 for gap in lookup_to_connect_gaps_ms)
    assert any(gap < 1000 for gap in lookup_to_connect_gaps_ms)


def test_proxy_context_separates_body_sizes_from_transfer_totals() -> None:
    workstation, proxy = _systems()
    generator = ActivityGenerator(StateManager(), {})
    context = generator._build_proxy_context(
        src_ip=workstation.ip,
        dst_ip="93.184.216.34",
        dst_port=80,
        service="http",
        duration=1.0,
        orig_bytes=4600,
        resp_bytes=18_000,
        hostname="example.com",
        source_system=workstation,
        proxy_sys=proxy,
        http=HttpContext(
            method="POST",
            host="example.com",
            uri="/api/v1/data",
            request_body_len=4096,
            response_body_len=16_384,
        ),
        explicit_mode=True,
        time=_BASE_TIME,
    )

    assert context.request_body_bytes == 4096
    assert context.response_body_bytes == 16_384
    assert context.cs_bytes > context.request_body_bytes
    assert context.sc_bytes > context.response_body_bytes


def test_output_window_admits_transport_but_suppresses_late_proxy_request() -> None:
    request = _request(33)
    proxy = _proxy_context(cache_result="HIT")
    plan = ProxyPhasePlanner().plan(request, proxy, request.time)
    proxy.transaction = plan
    connection_emitter = Mock()
    connection_emitter.can_handle.return_value = True
    proxy_emitter = Mock()
    proxy_emitter.can_handle.return_value = True
    dispatcher = EventDispatcher(
        StateManager(),
        {"zeek_conn": connection_emitter, "proxy_access": proxy_emitter},
        output_end_time=plan.request_at,
    )
    event = SecurityEvent(
        timestamp=plan.client_connect_at,
        event_type="connection",
        network=NetworkContext(
            src_ip="10.0.1.10",
            src_port=52000,
            dst_ip="10.0.3.10",
            dst_port=8080,
            protocol="tcp",
            service="http",
            duration=plan.client_duration_seconds,
            conn_state="SF",
            zeek_uid="CProxyWindowTest01",
        ),
        proxy=proxy,
        lifecycle=ActionLifecycleContext(
            group_id="proxy-client-transport",
            canonical_start=plan.client_connect_at,
            phase="start",
            parent_group_id=plan.stable_id,
        ),
    )

    dispatcher.dispatch(event)

    connection_emitter.emit.assert_called_once()
    proxy_emitter.emit.assert_not_called()
