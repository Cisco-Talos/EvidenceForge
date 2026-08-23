# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Owner-level close-bound contracts for explicit-proxy transactions."""

from __future__ import annotations

import math
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from typing import Any

import pytest

import evidenceforge.generation.actions as actions
from evidenceforge.events.contexts import HttpContext, ProxyContext
from evidenceforge.generation.actions.network_connection import NetworkConnectionRequest
from evidenceforge.generation.actions.network_transaction_planner import (
    NetworkTransactionPlanner,
    tls_completed_transport_close_bound_seconds,
)
from evidenceforge.generation.actions.proxy_phase_planner import (
    ProxyPhasePlanner,
    proxy_transaction_close_bound_seconds,
)
from evidenceforge.generation.actions.proxy_transaction import ProxyTransactionRequest
from evidenceforge.generation.activity import proxy_phase_profiles, timing_profiles
from evidenceforge.generation.timing import TimingRuntime
from evidenceforge.models.scenario import System

_BASE_TIME = datetime(2024, 3, 18, 10, tzinfo=UTC)
_PHASE_KEYS = (
    "request_after_connect_ms",
    "inspected_request_after_connect_setup_ms",
    "policy_decision_after_request_ms",
    "dns_query_after_decision_ms",
    "tls_after_origin_connect_ms",
    "origin_service_ms",
    "client_flush_after_response_ms",
    "terminal_response_after_decision_ms",
    "close_after_flush_ms",
    "gateway_attempt_ms",
)


def _install_zero_phase_profile(monkeypatch: pytest.MonkeyPatch) -> None:
    """Make the successful origin path, rather than another branch, own the bound."""

    profile: dict[str, Any] = {
        "phase_timing": {key: {"min": 0, "max": 0} for key in _PHASE_KEYS},
        "resolver_mixture": [
            {
                "name": "resolver_cache_hit",
                "weight": 1,
                "origin_after_request_ms": {"min": 0, "max": 0},
            }
        ],
    }
    monkeypatch.setattr(proxy_phase_profiles, "load_proxy_phase_profiles", lambda: profile)


class _MaximumTimingSampler:
    """Resolve supported timing distributions at their configured maximum."""

    @staticmethod
    def sample_timedelta(distribution: Any, **_kwargs: Any) -> timedelta:
        components = getattr(distribution, "components", ())
        if components:
            maximum_us = max(component.distribution.maximum for component in components)
        elif hasattr(distribution, "maximum"):
            maximum_us = distribution.maximum
        else:
            maximum_us = distribution.value
        return timedelta(microseconds=maximum_us)


def _maximum_network_planner() -> NetworkTransactionPlanner:
    """Return a physical network planner whose sampler selects every maximum."""

    runtime = SimpleNamespace(sampler=_MaximumTimingSampler())
    return NetworkTransactionPlanner(SimpleNamespace(timing_runtime=runtime))


def _request(dst_port: int) -> tuple[ProxyTransactionRequest, ProxyContext]:
    """Return one successful request whose body does not add a transfer floor."""

    workstation = System(
        hostname="WKS-01",
        ip="10.0.1.10",
        os="Windows 11",
        type="workstation",
    )
    proxy_system = System(
        hostname="PROXY-01",
        ip="10.0.3.10",
        os="Ubuntu 22.04",
        type="server",
        roles=["forward_proxy"],
    )
    service = "ssl" if dst_port == 443 else "http"
    scheme = "https" if dst_port == 443 else "http"
    http = HttpContext(
        method="POST",
        host="origin.example.test",
        uri="/api/data",
        request_body_len=512,
        response_body_len=16_384,
    )
    request = ProxyTransactionRequest(
        src_ip=workstation.ip,
        dst_ip="198.51.100.25",
        time=_BASE_TIME,
        dst_port=dst_port,
        proto="tcp",
        service=service,
        duration=0.0,
        orig_bytes=1024,
        resp_bytes=16_384,
        src_port=None,
        pid=-1,
        source_system=workstation,
        conn_state="SF",
        dns=None,
        http=http,
        file_transfer=None,
        ocsp=None,
        proxy=None,
        firewall=None,
        hostname="origin.example.test",
        process_image=None,
        proxy_chain=[proxy_system],
        preserve_explicit_proxy_dst_ip=False,
        caller_provided_conn_state=True,
        ad_domain="corp.test",
    )
    proxy = ProxyContext(
        client_ip=workstation.ip,
        method="POST",
        url=f"{scheme}://origin.example.test/api/data",
        host="origin.example.test",
        status_code=200,
        sc_bytes=16_620,
        cs_bytes=1024,
        request_body_bytes=512,
        response_body_bytes=16_384,
        cache_result="MISS",
        proxy_fqdn="proxy-01.corp.test",
    )
    return request, proxy


def _maximum_physical_close_seconds(
    request: ProxyTransactionRequest,
    plan: Any,
) -> float:
    """Return the latest client/origin physical close under maximum sampling."""

    planner = _maximum_network_planner()
    client_duration = planner._completed_http_duration_seconds(
        NetworkConnectionRequest(
            src_ip=request.src_ip,
            dst_ip=request.proxy_chain[0].ip,
            time=plan.client_connect_at,
            dst_port=8080,
            proto="tcp",
            service="http",
            duration=plan.client_duration_seconds,
            conn_state="SF",
        ),
        plan.client_duration_seconds,
    )
    latest_close_seconds = client_duration
    if plan.origin_connect_at is None or plan.origin_duration_seconds is None:
        return latest_close_seconds
    origin_request = NetworkConnectionRequest(
        src_ip=request.proxy_chain[0].ip,
        dst_ip=request.dst_ip,
        time=plan.origin_connect_at,
        dst_port=request.dst_port,
        proto="tcp",
        service=request.service,
        duration=plan.origin_duration_seconds,
        conn_state="SF",
    )
    origin_duration = plan.origin_duration_seconds
    if request.dst_port == 443:
        origin_duration = planner._completed_tls_duration_seconds(
            origin_request,
            origin_duration,
        )
    origin_duration = planner._completed_http_duration_seconds(
        origin_request,
        origin_duration,
    )
    origin_start_seconds = (plan.origin_connect_at - plan.client_connect_at).total_seconds()
    return max(latest_close_seconds, origin_start_seconds + origin_duration)


@pytest.mark.parametrize(
    ("dst_port", "runtime_floor_seconds"),
    [(80, 0.04), (443, 0.85)],
)
def test_proxy_close_bound_covers_real_runtime_origin_floor(
    monkeypatch: pytest.MonkeyPatch,
    dst_port: int,
    runtime_floor_seconds: float,
) -> None:
    """The public bound mirrors the same 40 ms/850 ms floor as a real plan."""

    _install_zero_phase_profile(monkeypatch)
    request, proxy = _request(dst_port)
    plan = ProxyPhasePlanner(
        TimingRuntime(reference_time=_BASE_TIME, namespace=f"proxy-bound-{dst_port}")
    ).plan(request, proxy, request.time)
    bound = proxy_transaction_close_bound_seconds(
        origin_duration_max_seconds=0.0,
        origin_close_extension_seconds=0.0,
        dst_port=dst_port,
    )

    assert plan.origin_connect_at is not None
    assert plan.origin_close_at is not None
    assert (plan.origin_close_at - plan.origin_connect_at).total_seconds() == runtime_floor_seconds
    assert (plan.close_at - plan.client_connect_at).total_seconds() <= bound
    physical_close_seconds = _maximum_physical_close_seconds(request, plan)
    expected = math.ceil(physical_close_seconds * 1_000_000) / 1_000_000
    assert bound == expected


@pytest.mark.parametrize(
    ("dst_port", "expected_bound"),
    [(80, 86_400.031002), (443, 86_404.532002)],
)
def test_proxy_close_bound_covers_extreme_http_overlay_on_physical_legs(
    monkeypatch: pytest.MonkeyPatch,
    dst_port: int,
    expected_bound: float,
) -> None:
    """The client and origin NetworkTransactionPlanners cannot escape proxy admission."""

    _install_zero_phase_profile(monkeypatch)
    maximum_ms = 86_400_000
    monkeypatch.setattr(
        timing_profiles,
        "load_timing_profiles",
        lambda: {
            "relationships": {
                "source.zeek_http_request": {
                    "min_ms": maximum_ms,
                    "max_ms": maximum_ms,
                    "position": "after",
                    "class": "same_observation",
                }
            }
        },
    )
    request, proxy = _request(dst_port)
    plan = ProxyPhasePlanner(
        TimingRuntime(reference_time=_BASE_TIME, namespace=f"proxy-http-overlay-{dst_port}")
    ).plan(request, proxy, request.time)
    bound = proxy_transaction_close_bound_seconds(
        origin_duration_max_seconds=0.0,
        origin_close_extension_seconds=0.0,
        dst_port=dst_port,
    )

    physical_close_seconds = _maximum_physical_close_seconds(request, plan)

    assert physical_close_seconds == pytest.approx(
        86_400.031001,
        abs=1e-9,
    )
    assert bound == expected_bound
    assert physical_close_seconds <= bound


def test_proxy_tls_close_bound_uses_network_owner_overlay_floor(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A valid TLS duration overlay remains part of the proxy-origin close bound."""

    _install_zero_phase_profile(monkeypatch)
    monkeypatch.setattr(
        timing_profiles,
        "load_timing_profiles",
        lambda: {
            "relationships": {
                "network.tls_completed_min_duration": {
                    "min_ms": 20_000,
                    "max_ms": 20_100,
                    "position": "after",
                    "class": "same_observation",
                }
            }
        },
    )
    request, proxy = _request(443)
    plan = ProxyPhasePlanner(
        TimingRuntime(reference_time=_BASE_TIME, namespace="proxy-bound-tls-overlay")
    ).plan(request, proxy, request.time)
    tls_bound = tls_completed_transport_close_bound_seconds(
        caller_duration_maximum=0.85,
    )
    bound = proxy_transaction_close_bound_seconds(
        origin_duration_max_seconds=0.0,
        origin_close_extension_seconds=0.0,
        dst_port=443,
    )

    assert tls_bound == 20.1
    expected = math.ceil((0.001 + tls_bound) * 1_000_000) / 1_000_000
    assert bound == expected
    assert (plan.close_at - plan.client_connect_at).total_seconds() <= bound


def test_action_package_exports_terminal_close_bound_helpers() -> None:
    """Package export metadata includes every public terminal-bound helper."""

    expected = {
        "dns_transport_close_headroom_seconds",
        "http_completed_transport_close_bound_seconds",
        "linux_sudo_intrinsic_close_headroom",
        "ntp_transport_close_headroom_seconds",
        "proxy_transaction_close_bound_seconds",
        "tls_completed_extension_headroom_seconds",
        "tls_completed_transport_close_bound_seconds",
        "tls_generated_family_close_bound_seconds",
    }

    assert expected <= set(actions.__all__)
    assert all(callable(getattr(actions, name)) for name in expected)
