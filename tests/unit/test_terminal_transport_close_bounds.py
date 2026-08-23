# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Focused terminal-window bounds for DNS, TLS, and explicit-proxy transports."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

import evidenceforge.generation.actions.ocsp_transaction as ocsp_transaction_module
import evidenceforge.generation.activity.tls_realism as tls_realism_module
import evidenceforge.generation.engine.baseline as baseline_module
from evidenceforge.config.schemas import TlsOcspResponseConfig
from evidenceforge.events.contexts import HttpContext, ProxyContext, SslContext, X509Context
from evidenceforge.formats.loader import load_format
from evidenceforge.generation.actions import (
    dns_transport_close_headroom_seconds,
    http_completed_transport_close_bound_seconds,
    proxy_transaction_close_bound_seconds,
    tls_completed_extension_headroom_seconds,
    tls_generated_family_close_bound_seconds,
)
from evidenceforge.generation.actions.network_connection import (
    NetworkConnectionIdentityCapture,
    NetworkConnectionRequest,
)
from evidenceforge.generation.actions.network_transaction_planner import (
    NetworkTransactionPlanner,
    tls_completed_transport_close_bound_seconds,
)
from evidenceforge.generation.actions.proxy_phase_planner import ProxyPhasePlanner
from evidenceforge.generation.actions.proxy_transaction import ProxyTransactionRequest
from evidenceforge.generation.activity import (
    ActivityGenerator,
    proxy_phase_profiles,
    timing_profiles,
)
from evidenceforge.generation.activity.tls_realism import certificate_analyzer_delay_ms
from evidenceforge.generation.emitters.zeek import ZeekEmitter
from evidenceforge.generation.emitters.zeek_files import ZeekFilesEmitter
from evidenceforge.generation.emitters.zeek_http import ZeekHttpEmitter
from evidenceforge.generation.emitters.zeek_ocsp import ZeekOcspEmitter
from evidenceforge.generation.emitters.zeek_ssl import ZeekSslEmitter
from evidenceforge.generation.emitters.zeek_x509 import ZeekX509Emitter
from evidenceforge.generation.engine.baseline import BaselineMixin
from evidenceforge.generation.state_manager import StateManager
from evidenceforge.generation.timing import TimingRuntime
from evidenceforge.models import System, User

_WINDOW_START = datetime(2024, 3, 18, 10, tzinfo=UTC)
_WINDOW_END = _WINDOW_START + timedelta(minutes=10)
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


def _fixed_range(milliseconds: int) -> dict[str, int]:
    """Return one valid fixed phase range."""

    return {"min": milliseconds, "max": milliseconds}


def _proxy_profiles(
    *,
    phase_maxima: dict[str, int],
    resolver: dict[str, Any],
) -> dict[str, Any]:
    """Return a complete synthetic proxy timing overlay for bound tests."""

    phase_timing = {key: _fixed_range(phase_maxima.get(key, 0)) for key in _PHASE_KEYS}
    return {
        "phase_timing": phase_timing,
        "resolver_mixture": [resolver],
    }


def _install_proxy_profiles(
    monkeypatch: pytest.MonkeyPatch,
    *,
    phase_maxima: dict[str, int],
    resolver: dict[str, Any],
) -> None:
    """Install one in-memory project-overlay equivalent."""

    profiles = _proxy_profiles(phase_maxima=phase_maxima, resolver=resolver)
    monkeypatch.setattr(
        proxy_phase_profiles,
        "load_proxy_phase_profiles",
        lambda: profiles,
    )


def _install_extreme_ocsp_config(monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
    """Install one schema-valid response profile whose transfer tail dominates TLS."""

    response = TlsOcspResponseConfig(
        size_bytes_min=1_000_000,
        size_bytes_max=1_000_000,
        latency_ms_min=60_000,
        latency_ms_max=60_000,
        throughput_bytes_per_second_min=1_000,
        throughput_bytes_per_second_max=1_000,
        file_duration_floor_ms=3,
    ).model_dump()
    settings = {
        "query_probability": 1.0,
        "request_hash_algorithm": "sha1",
        "response": response,
    }
    monkeypatch.setattr(ocsp_transaction_module, "ocsp_config", lambda: settings)
    monkeypatch.setattr(tls_realism_module, "ocsp_config", lambda: settings)
    return settings


def _install_exact_ocsp_bound_timing(monkeypatch: pytest.MonkeyPatch) -> None:
    """Fix child open jitter and remove unrelated proxy phase variability."""

    monkeypatch.setattr(
        timing_profiles,
        "load_timing_profiles",
        lambda: {
            "relationships": {
                "network.connection_start_jitter": {
                    "class": "same_observation",
                    "position": "after",
                    "min_ms": 850,
                    "max_ms": 850,
                }
            }
        },
    )
    _install_proxy_profiles(
        monkeypatch,
        phase_maxima={},
        resolver=_cache_resolver(),
    )


def _cache_resolver(milliseconds: int = 0) -> dict[str, Any]:
    """Return a valid fixed cache-hit resolver profile."""

    return {
        "name": "resolver_cache_hit",
        "weight": 1,
        "origin_after_request_ms": _fixed_range(milliseconds),
    }


def _lookup_resolver(
    *,
    dns_completion_ms: int = 0,
    origin_after_dns_ms: int = 0,
) -> dict[str, Any]:
    """Return a valid fixed ordinary-lookup resolver profile."""

    return {
        "name": "ordinary_lookup",
        "weight": 1,
        "dns_completion_after_request_ms": _fixed_range(dns_completion_ms),
        "origin_after_dns_ms": _fixed_range(origin_after_dns_ms),
    }


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


def _maximum_timing_planner() -> NetworkTransactionPlanner:
    """Return an actual network planner whose sampler selects every maximum."""

    runtime = SimpleNamespace(sampler=_MaximumTimingSampler())
    return NetworkTransactionPlanner(SimpleNamespace(timing_runtime=runtime))


def _tls_request(*, duration: float) -> NetworkConnectionRequest:
    """Return one completed-TLS request for direct owner-duration planning."""

    return NetworkConnectionRequest(
        src_ip="10.0.0.25",
        dst_ip="198.51.100.25",
        time=_WINDOW_START,
        dst_port=443,
        proto="tcp",
        service="ssl",
        duration=duration,
        conn_state="SF",
    )


def _http_request(*, duration: float) -> NetworkConnectionRequest:
    """Return one completed-HTTP request for direct owner-duration planning."""

    return NetworkConnectionRequest(
        src_ip="10.0.0.25",
        dst_ip="198.51.100.25",
        time=_WINDOW_START,
        dst_port=80,
        proto="tcp",
        service="http",
        duration=duration,
        conn_state="SF",
    )


def _render_physical_transport(
    output_dir: Path,
    *,
    dst_port: int,
    service: str,
    duration: float,
    http: HttpContext,
    start_time: datetime = _WINDOW_START,
    ssl: SslContext | None = None,
    x509_chain: tuple[X509Context, ...] = (),
    tls_presentation: Any = None,
    source_system: System | None = None,
    generated_tls_identity: str = "",
) -> tuple[Any, list[dict[str, Any]]]:
    """Execute one physical owner and return its plan plus rendered Zeek rows."""

    output_dir.mkdir(parents=True, exist_ok=True)
    outputs = {
        "zeek_conn": output_dir / "conn.json",
        "zeek_http": output_dir / "http.json",
        "zeek_ssl": output_dir / "ssl.json",
        "zeek_x509": output_dir / "x509.json",
        "zeek_files": output_dir / "files.json",
        "zeek_ocsp": output_dir / "ocsp.json",
    }
    emitters = {
        "zeek_conn": ZeekEmitter(load_format("zeek_conn"), outputs["zeek_conn"], threaded=False),
        "zeek_http": ZeekHttpEmitter(load_format("zeek_http"), outputs["zeek_http"]),
        "zeek_ssl": ZeekSslEmitter(load_format("zeek_ssl"), outputs["zeek_ssl"]),
        "zeek_x509": ZeekX509Emitter(load_format("zeek_x509"), outputs["zeek_x509"]),
        "zeek_files": ZeekFilesEmitter(load_format("zeek_files"), outputs["zeek_files"]),
        "zeek_ocsp": ZeekOcspEmitter(load_format("zeek_ocsp"), outputs["zeek_ocsp"]),
    }
    state = StateManager()
    state.set_current_time(start_time)
    generator = ActivityGenerator(
        state,
        emitters,
        generation_window_start=_WINDOW_START,
        generation_window_end=_WINDOW_START + timedelta(days=3),
    )
    if source_system is not None:
        generator._ip_to_system[source_system.ip] = source_system
    if generated_tls_identity:
        tls_presentation = generator._tls_certificate_planner.plan(
            backend_identity=generated_tls_identity,
            cert_name=generated_tls_identity,
            issuer_config={
                "name": "CN=R3, O=Let's Encrypt, C=US",
                "validity_days_min": 90,
                "validity_days_max": 90,
                "not_before_max_days": 30,
            },
            event_time=start_time,
            connection_identity="COcspTerminalBound",
            key_type="rsa",
            key_size=2_048,
            san_dns=(generated_tls_identity,),
        )
        x509_chain = tuple(generator._tls_certificate_planner.x509_contexts(tls_presentation))
        ssl = SslContext(
            version="TLSv12",
            cipher="TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
            server_name=generated_tls_identity,
            established=True,
            cert_chain_fuids=tuple(certificate.fuid for certificate in x509_chain),
        )
    capture = NetworkConnectionIdentityCapture()
    request = NetworkConnectionRequest(
        src_ip="10.0.0.25",
        src_port=50_025,
        dst_ip="198.51.100.25",
        time=start_time,
        dst_port=dst_port,
        proto="tcp",
        service=service,
        duration=duration,
        orig_bytes=512,
        resp_bytes=16_384,
        conn_state="SF",
        source_system=source_system,
        http=http,
        ssl=ssl,
        x509=x509_chain[0] if x509_chain else None,
        x509_chain=x509_chain,
        tls_presentation=tls_presentation,
        hostname="origin.example.test",
        proxy_bypass=True,
        suppress_prereq_dns=True,
        suppress_source_pid_inference=True,
        preserve_start_time=True,
        identity_capture=capture,
    )
    try:
        NetworkTransactionPlanner(generator).execute(request)
    finally:
        for emitter in emitters.values():
            emitter.close()

    rows: list[dict[str, Any]] = []
    for output in outputs.values():
        if output.exists():
            rows.extend(json.loads(line) for line in output.read_text().splitlines() if line)
    return capture.require(), rows


def _successful_proxy_request() -> tuple[ProxyTransactionRequest, ProxyContext]:
    """Return one HTTPS proxy request whose phase graph owns both physical legs."""

    workstation = System(
        hostname="WKS-01",
        ip="10.0.0.25",
        os="Windows 11",
        type="workstation",
    )
    proxy_system = System(
        hostname="PROXY-01",
        ip="10.0.0.50",
        os="Ubuntu 22.04",
        type="server",
        roles=["forward_proxy"],
    )
    http = HttpContext(
        method="POST",
        host="origin.example.test",
        uri="/api/data",
        request_body_len=512,
        response_body_len=16_384,
    )
    return (
        ProxyTransactionRequest(
            src_ip=workstation.ip,
            dst_ip="198.51.100.25",
            time=_WINDOW_START,
            dst_port=443,
            proto="tcp",
            service="ssl",
            duration=0.0,
            orig_bytes=1_024,
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
            ad_domain="example.test",
        ),
        ProxyContext(
            client_ip=workstation.ip,
            method="POST",
            url="https://origin.example.test/api/data",
            host="origin.example.test",
            status_code=200,
            sc_bytes=16_620,
            cs_bytes=1_024,
            request_body_bytes=512,
            response_body_bytes=16_384,
            cache_result="MISS",
            proxy_fqdn="proxy-01.example.test",
        ),
    )


def _maximum_rendered_timestamp(rows: list[dict[str, Any]]) -> float:
    """Return the latest rendered row timestamp or explicit row close."""

    candidates: list[float] = []
    for row in rows:
        if "ts" not in row:
            continue
        timestamp = float(row["ts"])
        candidates.append(timestamp)
        duration = row.get("duration")
        if isinstance(duration, int | float):
            candidates.append(timestamp + float(duration))
    return max(candidates)


def test_network_owner_exports_exact_dns_and_tls_close_headroom() -> None:
    """Public helpers stay aligned with the planner's microsecond maxima."""

    assert dns_transport_close_headroom_seconds(caller_rtt_maximum=0.35) == 0.363
    assert dns_transport_close_headroom_seconds(caller_rtt_maximum=0.3509994) == 0.364
    assert tls_completed_extension_headroom_seconds() == 8.0


def test_tls_family_bound_exactly_reserves_extreme_valid_ocsp_child(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A schema-valid responder extreme has one finite allocation-free family bound."""

    _install_extreme_ocsp_config(monkeypatch)
    _install_exact_ocsp_bound_timing(monkeypatch)

    # 60 s latency + 1,000,000 B / (1,000 B/s * 0.78) rounds up to
    # 1,342.051283 s. The direct child then owns 850.997 ms of transport-open
    # headroom and starts at most 4.5 s after its TLS parent.
    assert tls_generated_family_close_bound_seconds(caller_duration_maximum=0.1) == 1_347.402280


def test_extreme_ocsp_child_output_stays_inside_tls_family_bound(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """A real OCSP HTTP/files/ocsp child cannot render past its parent's bound."""

    _install_extreme_ocsp_config(monkeypatch)
    _install_exact_ocsp_bound_timing(monkeypatch)
    workstation = System(
        hostname="WS-OCSP-01",
        ip="10.0.0.25",
        os="Windows 11",
        type="workstation",
    )
    _transaction, rows = _render_physical_transport(
        tmp_path,
        dst_port=443,
        service="ssl",
        duration=0.1,
        http=HttpContext(
            method="GET",
            host="origin.example.test",
            uri="/status",
            status_code=200,
            response_body_len=256,
        ),
        source_system=workstation,
        generated_tls_identity="origin.example.test",
    )
    bound = tls_generated_family_close_bound_seconds(caller_duration_maximum=0.1)

    assert any(row.get("hashAlgorithm") == "sha1" for row in rows)
    assert any(row.get("host") == "ocsp.digicert.com" for row in rows)
    assert any(row.get("id.resp_p") == 80 for row in rows)
    assert _maximum_rendered_timestamp(rows) <= _WINDOW_START.timestamp() + bound


def test_tls_absolute_close_bound_matches_default_planner_extension_maximum() -> None:
    """The public bound covers the planner's default caller-duration branch exactly."""

    caller_duration = 10.0
    request = _tls_request(duration=caller_duration)
    planned_duration = _maximum_timing_planner()._completed_tls_duration_seconds(
        request,
        caller_duration,
    )

    assert planned_duration == 18.0
    assert (
        tls_completed_transport_close_bound_seconds(
            caller_duration_maximum=caller_duration,
        )
        == planned_duration
    )


def test_tls_absolute_close_bound_matches_extreme_valid_overlay_floor(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The largest valid configured TLS floor cannot escape the public bound."""

    minimum_ms = 86_399_350
    maximum_ms = 86_400_000
    monkeypatch.setattr(
        timing_profiles,
        "load_timing_profiles",
        lambda: {
            "relationships": {
                "network.tls_completed_min_duration": {
                    "class": "same_observation",
                    "position": "after",
                    "min_ms": minimum_ms,
                    "max_ms": maximum_ms,
                }
            }
        },
    )
    caller_duration = 0.0
    request = _tls_request(duration=caller_duration)
    planned_duration = _maximum_timing_planner()._completed_tls_duration_seconds(
        request,
        caller_duration,
    )

    assert planned_duration == 86_400.0
    assert (
        tls_completed_transport_close_bound_seconds(
            caller_duration_maximum=caller_duration,
        )
        == planned_duration
    )


def test_http_absolute_close_bound_matches_shipped_planner_floor() -> None:
    """The public HTTP bound covers the physical planner's shipped floor."""

    caller_duration = 0.0
    request = _http_request(duration=caller_duration)
    planned_duration = _maximum_timing_planner()._completed_http_duration_seconds(
        request,
        caller_duration,
    )

    assert planned_duration == 0.480001
    assert (
        http_completed_transport_close_bound_seconds(
            caller_duration_maximum=caller_duration,
        )
        == planned_duration
    )


def test_http_absolute_close_bound_matches_extreme_valid_overlay_floor(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The largest valid HTTP analyzer overlay cannot escape physical admission."""

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
    caller_duration = 0.0
    request = _http_request(duration=caller_duration)
    planned_duration = _maximum_timing_planner()._completed_http_duration_seconds(
        request,
        caller_duration,
    )

    assert planned_duration == 86_400.030001
    assert (
        http_completed_transport_close_bound_seconds(
            caller_duration_maximum=caller_duration,
        )
        == planned_duration
    )


def test_http_absolute_close_bound_covers_physical_rendered_leg(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """An extreme analyzer overlay stays inside the rendered physical close bound."""

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
    transaction, rows = _render_physical_transport(
        tmp_path,
        dst_port=80,
        service="http",
        duration=0.1,
        http=HttpContext(
            method="GET",
            host="origin.example.test",
            uri="/status",
            status_code=200,
            response_body_len=256,
        ),
    )
    bound = http_completed_transport_close_bound_seconds(caller_duration_maximum=0.1)

    assert transaction.duration is not None
    assert transaction.closed_at is not None
    assert (transaction.closed_at - transaction.started_at).total_seconds() == pytest.approx(
        transaction.duration
    )
    assert transaction.duration >= maximum_ms / 1_000 + 0.005
    assert transaction.duration <= bound
    assert rows
    rendered_maximum = _maximum_rendered_timestamp(rows)
    assert rendered_maximum >= _WINDOW_START.timestamp() + maximum_ms / 1_000
    assert rendered_maximum <= _WINDOW_START.timestamp() + bound


def test_tls_absolute_close_bound_covers_extreme_certificate_analyzer_overlay(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Generated-chain analyzer timing cannot extend the TLS transport past its bound."""

    maximum_ms = 86_400_000
    monkeypatch.setattr(
        timing_profiles,
        "load_timing_profiles",
        lambda: {
            "relationships": {
                key: {
                    "min_ms": maximum_ms,
                    "max_ms": maximum_ms,
                    "position": "after",
                    "class": "same_observation",
                }
                for key in ("source.zeek_ssl_analyzer", "source.zeek_x509_analyzer")
            }
        },
    )
    timing_runtime = TimingRuntime(
        reference_time=_WINDOW_START,
        namespace="tls-certificate-close-bound",
    )
    timing_runtime.sampler = _MaximumTimingSampler()
    planner_duration = (
        certificate_analyzer_delay_ms(
            zeek_uid="Cbound",
            event_timestamp=_WINDOW_START,
            fuid="Fleaf",
            position=2,
            timing_runtime=timing_runtime,
        )
        / 1_000
        + 0.005
    )

    bound = tls_completed_transport_close_bound_seconds(caller_duration_maximum=0.0)

    assert planner_duration == 172_800.095
    assert bound == planner_duration


def test_tls_absolute_close_bound_covers_physical_rendered_certificate_leg(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """Analyzer-delayed SSL/X.509/files rows stay inside the absolute TLS bound."""

    maximum_ms = 20_000
    monkeypatch.setattr(
        timing_profiles,
        "load_timing_profiles",
        lambda: {
            "relationships": {
                key: {
                    "min_ms": maximum_ms,
                    "max_ms": maximum_ms,
                    "position": "after",
                    "class": "same_observation",
                }
                for key in ("source.zeek_ssl_analyzer", "source.zeek_x509_analyzer")
            }
        },
    )
    chain = (
        X509Context(
            fuid="Fleaf",
            fingerprint="a" * 40,
            certificate_subject="CN=origin.example.test",
            certificate_issuer="CN=Intermediate",
        ),
        X509Context(
            fuid="Fintermediate",
            fingerprint="b" * 40,
            certificate_subject="CN=Intermediate",
            certificate_issuer="CN=Root",
            host_cert=False,
            basic_constraints_ca=True,
        ),
        X509Context(
            fuid="Froot",
            fingerprint="c" * 40,
            certificate_subject="CN=Root",
            certificate_issuer="CN=Root",
            host_cert=False,
            basic_constraints_ca=True,
        ),
    )
    transaction, rows = _render_physical_transport(
        tmp_path,
        dst_port=443,
        service="ssl",
        duration=0.1,
        http=HttpContext(
            method="GET",
            host="origin.example.test",
            uri="/status",
            status_code=200,
            response_body_len=256,
        ),
        ssl=SslContext(
            version="TLSv12",
            cipher="TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
            server_name="origin.example.test",
            established=True,
            cert_chain_fuids=tuple(certificate.fuid for certificate in chain),
        ),
        x509_chain=chain,
    )
    bound = tls_completed_transport_close_bound_seconds(caller_duration_maximum=0.1)

    assert transaction.duration is not None
    assert transaction.closed_at is not None
    assert (transaction.closed_at - transaction.started_at).total_seconds() == pytest.approx(
        transaction.duration
    )
    assert transaction.duration > 2 * maximum_ms / 1_000
    assert transaction.duration <= bound
    assert rows
    rendered_maximum = _maximum_rendered_timestamp(rows)
    assert rendered_maximum > _WINDOW_START.timestamp() + 2 * maximum_ms / 1_000
    assert rendered_maximum <= _WINDOW_START.timestamp() + bound


def test_proxy_absolute_close_bound_covers_rendered_physical_legs(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """The proxy bound contains both rendered legs under analyzer overlays."""

    _install_proxy_profiles(
        monkeypatch,
        phase_maxima={},
        resolver=_cache_resolver(),
    )
    maximum_ms = 20_000
    monkeypatch.setattr(
        timing_profiles,
        "load_timing_profiles",
        lambda: {
            "relationships": {
                key: {
                    "min_ms": maximum_ms,
                    "max_ms": maximum_ms,
                    "position": "after",
                    "class": "same_observation",
                }
                for key in ("source.zeek_ssl_analyzer", "source.zeek_x509_analyzer")
            }
        },
    )
    request, proxy = _successful_proxy_request()
    phase_plan = ProxyPhasePlanner(
        TimingRuntime(reference_time=_WINDOW_START, namespace="rendered-proxy-close-bound")
    ).plan(request, proxy, request.time)
    assert phase_plan.origin_connect_at is not None
    assert phase_plan.origin_duration_seconds is not None

    chain = (
        X509Context(
            fuid="Fproxy-leaf",
            fingerprint="d" * 40,
            certificate_subject="CN=origin.example.test",
            certificate_issuer="CN=Intermediate",
        ),
        X509Context(
            fuid="Fproxy-intermediate",
            fingerprint="e" * 40,
            certificate_subject="CN=Intermediate",
            certificate_issuer="CN=Root",
            host_cert=False,
            basic_constraints_ca=True,
        ),
        X509Context(
            fuid="Fproxy-root",
            fingerprint="f" * 40,
            certificate_subject="CN=Root",
            certificate_issuer="CN=Root",
            host_cert=False,
            basic_constraints_ca=True,
        ),
    )
    _client_transaction, client_rows = _render_physical_transport(
        tmp_path / "client",
        dst_port=8080,
        service="http",
        duration=phase_plan.client_duration_seconds,
        http=request.http,
        start_time=phase_plan.client_connect_at,
    )
    _origin_transaction, origin_rows = _render_physical_transport(
        tmp_path / "origin",
        dst_port=443,
        service="ssl",
        duration=phase_plan.origin_duration_seconds,
        http=request.http,
        start_time=phase_plan.origin_connect_at,
        ssl=SslContext(
            version="TLSv12",
            cipher="TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
            server_name="origin.example.test",
            established=True,
            cert_chain_fuids=tuple(certificate.fuid for certificate in chain),
        ),
        x509_chain=chain,
    )
    bound = proxy_transaction_close_bound_seconds(
        origin_duration_max_seconds=0.0,
        origin_close_extension_seconds=0.0,
        dst_port=443,
    )

    assert phase_plan.close_at <= phase_plan.client_connect_at + timedelta(seconds=bound)
    rendered_maximum = _maximum_rendered_timestamp(client_rows + origin_rows)
    assert rendered_maximum > _WINDOW_START.timestamp() + 2 * maximum_ms / 1_000
    assert rendered_maximum <= _WINDOW_START.timestamp() + bound


def test_proxy_owner_default_inspected_tls_close_bound_is_exact() -> None:
    """The shipped retry-resolver and TLS tails produce one stable maximum."""

    assert (
        proxy_transaction_close_bound_seconds(
            origin_duration_max_seconds=5.0,
            origin_close_extension_seconds=8.0,
            dst_port=443,
        )
        == 15.88
    )


def test_proxy_owner_includes_overlay_dominant_terminal_tail(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A terminal policy response can outlive every origin-bearing path."""

    _install_proxy_profiles(
        monkeypatch,
        phase_maxima={
            "policy_decision_after_request_ms": 60_000,
            "terminal_response_after_decision_ms": 60_000,
            "close_after_flush_ms": 60_000,
        },
        resolver=_cache_resolver(),
    )

    assert (
        proxy_transaction_close_bound_seconds(
            origin_duration_max_seconds=0.04,
            origin_close_extension_seconds=0.0,
            dst_port=80,
        )
        == 180.0
    )


def test_proxy_owner_includes_overlay_dominant_tls_ocsp_family_tail(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A valid proxy overlay reserves the later TLS-owned OCSP child transaction."""

    _install_proxy_profiles(
        monkeypatch,
        phase_maxima={
            "request_after_connect_ms": 60_000,
            "inspected_request_after_connect_setup_ms": 60_000,
            "policy_decision_after_request_ms": 60_000,
            "dns_query_after_decision_ms": 60_000,
            "origin_service_ms": 60_000,
            "client_flush_after_response_ms": 60_000,
            "terminal_response_after_decision_ms": 60_000,
            "close_after_flush_ms": 60_000,
            "gateway_attempt_ms": 60_000,
        },
        resolver=_lookup_resolver(
            dns_completion_ms=60_000,
            origin_after_dns_ms=60_000,
        ),
    )

    assert (
        proxy_transaction_close_bound_seconds(
            origin_duration_max_seconds=5.0,
            origin_close_extension_seconds=0.0,
            dst_port=443,
        )
        == 844.5
    )


def test_proxy_owner_includes_overlay_dominant_dns_family_tail(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A proxy lookup reserves companion and MX-address DNS teardown headroom."""

    _install_proxy_profiles(
        monkeypatch,
        phase_maxima={},
        resolver=_lookup_resolver(),
    )
    monkeypatch.setattr(
        timing_profiles,
        "load_timing_profiles",
        lambda: {
            "relationships": {
                "source.zeek_http_request": {
                    "min_ms": 0,
                    "max_ms": 0,
                    "position": "after",
                    "class": "same_observation",
                }
            }
        },
    )

    assert (
        proxy_transaction_close_bound_seconds(
            origin_duration_max_seconds=0.04,
            origin_close_extension_seconds=0.0,
            dst_port=80,
        )
        == 0.438
    )


@pytest.mark.parametrize("service", [None, "https"])
def test_baseline_normalizes_https_alias_to_exact_explicit_proxy_bound(
    service: str | None,
) -> None:
    """Baseline admission uses the same alias normalization as runtime routing."""

    source_ip = "10.0.0.25"
    baseline = BaselineMixin()
    baseline.activity_generator = SimpleNamespace(
        _proxy_mode="explicit",
        _proxy_routes={source_ip: [object()]},
    )

    assert (
        baseline._baseline_network_close_bound_seconds(
            src_ip=source_ip,
            dst_ip="198.51.100.25",
            proto="tcp",
            dst_port=443,
            service=service,
            requested_duration_max=10.0,
        )
        == 20.88
    )


@pytest.mark.parametrize(
    ("microseconds_inside_frontier", "expected_calls"),
    [(1, 1), (0, 0)],
)
def test_suspicious_dns_uses_exact_transport_close_headroom(
    monkeypatch: pytest.MonkeyPatch,
    microseconds_inside_frontier: int,
    expected_calls: int,
) -> None:
    """Suspicious DNS rejects the rendered frontier and admits one microsecond inside."""

    user = User(
        username="analyst",
        full_name="Security Analyst",
        email="analyst@example.test",
        persona="security_analyst",
    )
    system = System(
        hostname="WS-ANALYST-01",
        ip="10.0.0.25",
        os="Windows 11",
        type="workstation",
    )
    generated: list[dict[str, object]] = []
    state_times: list[datetime] = []
    activity = SimpleNamespace(
        _dns_server_ips=("10.0.0.53",),
        timing_runtime=object(),
        generate_connection=lambda **kwargs: generated.append(kwargs),
    )
    baseline = BaselineMixin()
    baseline.start_time = _WINDOW_START
    baseline.end_time = _WINDOW_END
    baseline.activity_generator = activity
    baseline.state_manager = SimpleNamespace(set_current_time=state_times.append)
    baseline.scenario = SimpleNamespace(
        baseline_activity=SimpleNamespace(suspicious_noise="high"),
        environment=SimpleNamespace(
            users=[user],
            systems=[system],
            domain="example.test",
        ),
        personas=[],
    )
    transport_open_window = baseline_module.get_timing_window(
        "network.connection_start_jitter",
        default_min_ms=0,
        default_max_ms=0,
        default_position="after",
    )
    remaining_seconds = (
        dns_transport_close_headroom_seconds(caller_rtt_maximum=0.35)
        + (transport_open_window.max_ms / 1000)
        + 0.000997
        + (microseconds_inside_frontier / 1_000_000)
    )
    monkeypatch.setattr(baseline_module, "get_suspicious_event_count", lambda *_args: 1)
    monkeypatch.setattr(
        baseline_module,
        "pick_suspicious_pattern",
        lambda *_args: {"type": "suspicious_dns"},
    )
    monkeypatch.setattr(
        baseline_module,
        "generate_suspicious_dns",
        lambda *_args: {
            "system": system,
            "time": _WINDOW_END - timedelta(seconds=remaining_seconds),
            "hostname": "telemetry-example.test",
        },
    )

    baseline._generate_suspicious_noise(_WINDOW_START)

    assert len(generated) == expected_calls
    assert len(state_times) == expected_calls


@pytest.mark.parametrize("service", [None, "https"])
def test_unusual_outbound_alias_reserves_explicit_proxy_tls_close(
    monkeypatch: pytest.MonkeyPatch,
    service: str | None,
) -> None:
    """Runtime-normalized HTTPS aliases cannot enter without proxy close headroom."""

    user = User(
        username="analyst",
        full_name="Security Analyst",
        email="analyst@example.test",
        persona="security_analyst",
    )
    system = System(
        hostname="WS-ANALYST-01",
        ip="10.0.0.25",
        os="Windows 11",
        type="workstation",
    )

    class RejectingActivity:
        _proxy_mode = "explicit"
        _proxy_routes = {system.ip: [object()]}
        timing_runtime = object()

        @staticmethod
        def generate_connection(**_kwargs: object) -> None:
            raise AssertionError("an explicit-proxy transaction would cross the window end")

    class RejectingState:
        @staticmethod
        def set_current_time(_time: datetime) -> None:
            raise AssertionError("rejected work must not advance canonical state")

    baseline = BaselineMixin()
    baseline.start_time = _WINDOW_START
    baseline.end_time = _WINDOW_END
    baseline.activity_generator = RejectingActivity()
    baseline.state_manager = RejectingState()
    baseline.scenario = SimpleNamespace(
        baseline_activity=SimpleNamespace(suspicious_noise="high"),
        environment=SimpleNamespace(
            users=[user],
            systems=[system],
            domain="example.test",
        ),
        personas=[],
    )
    monkeypatch.setattr(baseline_module, "get_suspicious_event_count", lambda *_args: 1)
    monkeypatch.setattr(
        baseline_module,
        "pick_suspicious_pattern",
        lambda *_args: {"type": "unusual_outbound"},
    )
    monkeypatch.setattr(
        baseline_module,
        "generate_unusual_outbound",
        lambda *_args: {
            "system": system,
            "time": _WINDOW_END - timedelta(seconds=19),
            "dst_ip": "198.51.100.25",
            "dst_port": 443,
            "service": service,
            "hostname": "updates.example.test",
            "large_transfer": False,
        },
    )

    baseline._generate_suspicious_noise(_WINDOW_START)


def test_unusual_outbound_rejects_one_microsecond_short_of_extreme_ocsp_family(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Terminal TLS admission rejects the OCSP child family before state mutation."""

    _install_extreme_ocsp_config(monkeypatch)
    _install_exact_ocsp_bound_timing(monkeypatch)
    terminal_end = _WINDOW_START + timedelta(hours=1)
    user = User(
        username="analyst",
        full_name="Security Analyst",
        email="analyst@example.test",
        persona="security_analyst",
    )
    system = System(
        hostname="WS-ANALYST-01",
        ip="10.0.0.25",
        os="Windows 11",
        type="workstation",
    )

    class RejectingActivity:
        _proxy_mode = "transparent"
        _proxy_routes: dict[str, list[object]] = {}
        timing_runtime = object()

        @staticmethod
        def generate_connection(**_kwargs: object) -> None:
            raise AssertionError("rejected TLS/OCSP work must not allocate a connection")

    class RejectingState:
        @staticmethod
        def set_current_time(_time: datetime) -> None:
            raise AssertionError("rejected TLS/OCSP work must not advance canonical state")

    sensor_facts: list[dict[str, object]] = []

    class SensorPlanner:
        @staticmethod
        def network_sensor_close_positive_headroom(
            _canonical_time: datetime,
            **facts: object,
        ) -> timedelta:
            sensor_facts.append(facts)
            return timedelta(seconds=1)

    baseline = BaselineMixin()
    baseline.start_time = _WINDOW_START
    baseline.end_time = terminal_end
    baseline.activity_generator = RejectingActivity()
    baseline.dispatcher = SimpleNamespace(network_observation_planner=SensorPlanner())
    baseline.state_manager = RejectingState()
    baseline.scenario = SimpleNamespace(
        baseline_activity=SimpleNamespace(suspicious_noise="high"),
        environment=SimpleNamespace(
            users=[user],
            systems=[system],
            domain="example.test",
        ),
        personas=[],
    )
    rendered_bound = baseline._baseline_network_close_bound_seconds(
        src_ip=system.ip,
        dst_ip="198.51.100.25",
        proto="tcp",
        dst_port=443,
        service="ssl",
        requested_duration_max=10.0,
        direct_extension_seconds=tls_completed_extension_headroom_seconds(),
        current_hour=_WINDOW_START,
        start=_WINDOW_START,
    )
    event_time = terminal_end - timedelta(seconds=rendered_bound) + timedelta(microseconds=1)
    assert baseline._baseline_pass_admits(
        _WINDOW_START,
        start=event_time,
        end=event_time + timedelta(seconds=rendered_bound) - timedelta(microseconds=1),
    )
    monkeypatch.setattr(baseline_module, "get_suspicious_event_count", lambda *_args: 1)
    monkeypatch.setattr(
        baseline_module,
        "pick_suspicious_pattern",
        lambda *_args: {"type": "unusual_outbound"},
    )
    monkeypatch.setattr(
        baseline_module,
        "generate_unusual_outbound",
        lambda *_args: {
            "system": system,
            "time": event_time,
            "dst_ip": "198.51.100.25",
            "dst_port": 443,
            "service": "ssl",
            "hostname": "updates.example.test",
            "large_transfer": False,
        },
    )

    baseline._generate_suspicious_noise(_WINDOW_START)

    assert sensor_facts
    assert all(
        facts
        == {
            "src_ip": "",
            "dst_ip": "",
            "protocol": "tcp",
            "conn_state": "",
            "payload_bytes": None,
        }
        for facts in sensor_facts
    )
