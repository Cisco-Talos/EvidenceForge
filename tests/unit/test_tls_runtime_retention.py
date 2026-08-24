# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Focused TLS resumption ownership and bounded-retention tests."""

from __future__ import annotations

import inspect
from datetime import UTC, datetime, timedelta
from types import MethodType, SimpleNamespace
from unittest.mock import Mock

import pytest

from evidenceforge.generation.activity import ActivityGenerator
from evidenceforge.generation.activity import generator as generator_module
from evidenceforge.generation.engine.baseline import BaselineMixin
from evidenceforge.generation.network_runtime import NetworkRuntimePointFamily
from evidenceforge.generation.process_runtime_cache import (
    ACTIVITY_GENERATOR_MUTABLE_RETENTION_POLICIES,
    REMOVED_DEAD_ACTIVITY_GENERATOR_MUTABLE_FIELDS,
    discover_activity_generator_mutable_fields,
)
from evidenceforge.generation.state_manager import StateManager
from evidenceforge.models.exceptions import StateError

_START = datetime(2024, 3, 15, 10, 0, tzinfo=UTC)
_SOURCE_IP = "10.0.1.50"
_DESTINATION_IP = "203.0.113.20"
_SERVER_NAME = "assets.example.test"
_PAIR_KEY = (_SOURCE_IP, _DESTINATION_IP, 443, _SERVER_NAME)


def _generator(*, window_days: int = 10) -> tuple[ActivityGenerator, StateManager, Mock]:
    state = StateManager()
    state.set_current_time(_START)
    emitter = Mock()
    emitter.can_handle.return_value = True
    generator = ActivityGenerator(
        state,
        {"zeek_conn": emitter},
        generation_window_start=_START - timedelta(hours=1),
        generation_window_end=_START + timedelta(days=window_days),
    )
    return generator, state, emitter


def _generate_tls(
    generator: ActivityGenerator,
    *,
    at: datetime,
    source_port: int,
    conn_state: str | None = "SF",
) -> str:
    return generator.generate_connection(
        src_ip=_SOURCE_IP,
        src_port=source_port,
        dst_ip=_DESTINATION_IP,
        time=at,
        dst_port=443,
        proto="tcp",
        service="ssl",
        duration=2.0,
        orig_bytes=512,
        resp_bytes=2048,
        conn_state=conn_state,
        hostname=_SERVER_NAME,
        suppress_prereq_dns=True,
        suppress_source_pid_inference=True,
        preserve_start_time=True,
    )


def test_failed_tls_handshake_does_not_publish_resumption_points(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    generator, _state, emitter = _generator()
    crypto = generator._cryptographic_material_registry
    crypto_before = crypto.state_digest()
    crypto_census_before = crypto.census()
    monkeypatch.setattr(generator_module, "_SSL_FAILURE_RATE", 1.0)
    monkeypatch.setattr(generator_module, "_TCP_CONN_ENTRIES", (("SF", 1, "ShADadf"),))
    monkeypatch.setattr(generator_module, "_TCP_CONN_WEIGHTS", (1,))

    _generate_tls(generator, at=_START, source_port=50_001, conn_state=None)

    event = emitter.emit.call_args.args[0]
    assert event.protocol.ssl is not None
    assert event.protocol.ssl.established is False
    runtime = generator._network_transaction_runtime
    assert runtime.get_point(NetworkRuntimePointFamily.TLS_SERVER_NAME, _SERVER_NAME) is None
    assert runtime.get_point(NetworkRuntimePointFamily.TLS_CLIENT_SERVER_PAIR, _PAIR_KEY) is None
    assert crypto.state_digest() == crypto_before
    assert crypto.census() == crypto_census_before
    census = runtime.census()
    assert census.open_preparations == 0
    assert census.prepared_transactions == 0
    assert census.claimed_transactions == 0
    assert census.reserved_points == 0
    assert census.preparation_fences == 0
    assert census.reserved_deadlines == 0


def test_tls_last_precommit_rejection_cancels_points_and_retry_is_exact() -> None:
    generator, state, emitter = _generator()
    runtime = generator._network_transaction_runtime
    owner_rng = generator_module._get_rng()
    state_before = state.materialization_digest()
    runtime_before = runtime.state_digest()
    runtime_census_before = runtime.census()
    crypto_before = generator._cryptographic_material_registry.state_digest()
    crypto_census_before = generator._cryptographic_material_registry.census()
    rng_before = owner_rng.getstate()

    def reject() -> None:
        raise StateError("injected TLS last-precommit rejection")

    generator._lifecycle_authority._materialization_precommit_hook = reject
    with pytest.raises(StateError, match="injected TLS last-precommit rejection"):
        _generate_tls(generator, at=_START, source_port=50_002)

    assert state.materialization_digest() == state_before
    assert runtime.state_digest() == runtime_before
    assert runtime.census() == runtime_census_before
    assert generator._cryptographic_material_registry.state_digest() == crypto_before
    assert generator._cryptographic_material_registry.census() == crypto_census_before
    assert owner_rng.getstate() == rng_before
    emitter.emit.assert_not_called()

    generator._lifecycle_authority._materialization_precommit_hook = None
    _generate_tls(generator, at=_START, source_port=50_002)
    assert runtime.get_point(NetworkRuntimePointFamily.TLS_SERVER_NAME, _SERVER_NAME) is True
    assert runtime.get_point(NetworkRuntimePointFamily.TLS_CLIENT_SERVER_PAIR, _PAIR_KEY) is True


@pytest.mark.parametrize("window_days", (10, 0))
def test_tls_resumption_expiry_is_24_hours_and_clamped_to_runtime_window(
    window_days: int,
) -> None:
    window_end = _START + timedelta(days=window_days, hours=12)
    state = StateManager()
    state.set_current_time(_START)
    emitter = Mock()
    emitter.can_handle.return_value = True
    generator = ActivityGenerator(
        state,
        {"zeek_conn": emitter},
        generation_window_start=_START - timedelta(hours=1),
        generation_window_end=window_end,
    )

    _generate_tls(generator, at=_START, source_port=50_003)

    runtime = generator._network_transaction_runtime
    expiry = min(
        runtime.window_end,
        _START + generator_module._TLS_RESUMPTION_STATE_HORIZON,
    )
    before_expiry = expiry - timedelta(microseconds=1)
    assert (
        runtime.get_point(
            NetworkRuntimePointFamily.TLS_SERVER_NAME,
            _SERVER_NAME,
            at=before_expiry,
        )
        is True
    )
    assert (
        runtime.get_point(
            NetworkRuntimePointFamily.TLS_CLIENT_SERVER_PAIR,
            _PAIR_KEY,
            at=before_expiry,
        )
        is True
    )
    assert (
        runtime.get_point(
            NetworkRuntimePointFamily.TLS_SERVER_NAME,
            _SERVER_NAME,
            at=expiry,
        )
        is None
    )
    assert (
        runtime.get_point(
            NetworkRuntimePointFamily.TLS_CLIENT_SERVER_PAIR,
            _PAIR_KEY,
            at=expiry,
        )
        is None
    )
    if expiry < runtime.window_end:
        emitter.reset_mock()
        _generate_tls(generator, at=expiry, source_port=50_004)
        retry_event = emitter.emit.call_args.args[0]
        assert retry_event.protocol.ssl is not None
        assert retry_event.protocol.ssl.resumed is False
        refreshed_expiry = expiry + generator_module._TLS_RESUMPTION_STATE_HORIZON
        assert (
            runtime.get_point(
                NetworkRuntimePointFamily.TLS_SERVER_NAME,
                _SERVER_NAME,
                at=refreshed_expiry - timedelta(microseconds=1),
            )
            is True
        )
        assert (
            runtime.get_point(
                NetworkRuntimePointFamily.TLS_SERVER_NAME,
                _SERVER_NAME,
                at=refreshed_expiry,
            )
            is None
        )


def test_tls_runtime_backing_plateaus_under_real_hourly_baseline_watermarks() -> None:
    def run_duration(days: int) -> tuple[int, int, int, int]:
        generator, _generator_state, _emitter = _generator(window_days=days + 2)
        runtime = generator._network_transaction_runtime
        state_manager = Mock()
        engine = SimpleNamespace(
            scenario=SimpleNamespace(environment=SimpleNamespace(users=[])),
            warmup_duration=timedelta(0),
            warmup_start_time=_START,
            start_time=_START,
            end_time=_START + timedelta(days=days),
            state_manager=state_manager,
            activity_generator=generator,
            _emit_dhcp_leases=Mock(),
            _emit_sensor_startup=Mock(),
            _report_progress=Mock(),
        )
        engine._baseline_pass_end = MethodType(BaselineMixin._baseline_pass_end, engine)

        def generate_hour(
            current: datetime,
            _users: list[object],
            **_kwargs: object,
        ) -> None:
            ordinal = int((current - _START).total_seconds() // 3600)
            observed_at = current + timedelta(minutes=30)
            expires_at = observed_at + generator_module._TLS_RESUMPTION_STATE_HORIZON
            runtime.set_point(
                NetworkRuntimePointFamily.TLS_SERVER_NAME,
                f"server-{ordinal}.example.test",
                True,
                expires_at=expires_at,
            )
            runtime.set_point(
                NetworkRuntimePointFamily.TLS_CLIENT_SERVER_PAIR,
                (_SOURCE_IP, _DESTINATION_IP, 443, f"server-{ordinal}.example.test"),
                True,
                expires_at=expires_at,
            )

        engine._generate_hour = generate_hour
        BaselineMixin._generate_baseline(engine)
        census = runtime.census()
        assert state_manager.advance_pid_allocation_watermark.call_count == days * 24
        return (
            census.live_points,
            census.tombstone_points,
            census.active_deadlines,
            census.expiry_backing,
        )

    four_day_shape = run_duration(4)
    eight_day_shape = run_duration(8)
    assert four_day_shape == eight_day_shape
    assert eight_day_shape == (96, 48, 144, 144)


def test_dead_tls_caches_and_chain_helper_cannot_reenter_generator_retention() -> None:
    retired = {
        "_tls_seen_server_names",
        "_tls_seen_client_server_pairs",
        "_tls_cert_validity",
        "_tls_intermediate_profiles",
        "_tls_ocsp_response_sizes",
        "_tls_ocsp_windows",
    }
    discovered = {
        row.field_name
        for row in discover_activity_generator_mutable_fields(inspect.getsource(ActivityGenerator))
    }
    policy_fields = {policy.field_name for policy in ACTIVITY_GENERATOR_MUTABLE_RETENTION_POLICIES}
    generator, _state, _emitter = _generator()

    assert retired.isdisjoint(discovered)
    assert retired.isdisjoint(policy_fields)
    assert retired <= set(REMOVED_DEAD_ACTIVITY_GENERATOR_MUTABLE_FIELDS)
    assert all(not hasattr(generator, field_name) for field_name in retired)
    assert not hasattr(ActivityGenerator, "_build_tls_certificate_chain")
