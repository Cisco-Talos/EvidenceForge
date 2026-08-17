# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Atomicity and retention tests for auth-owned failed-logon cadence state."""

from dataclasses import FrozenInstanceError, replace
from datetime import UTC, datetime, timedelta
from unittest.mock import Mock

import pytest

from evidenceforge.generation.activity import ActivityGenerator
from evidenceforge.generation.activity import generator as generator_mod
from evidenceforge.generation.process_runtime_cache import (
    ACTIVITY_GENERATOR_MUTABLE_RETENTION_POLICIES,
    ActivityGeneratorRetentionDisposition,
    BoundedRuntimeCache,
)
from evidenceforge.generation.state_manager import StateManager
from evidenceforge.models import System, User
from evidenceforge.models.exceptions import StateError

_START = datetime(2024, 1, 1, tzinfo=UTC)
_FAILED_KEY = ("wks-01", "alice", 2, "-")


def _generator(*, days: int = 31) -> tuple[ActivityGenerator, dict[str, Mock]]:
    emitters = {
        "windows_event_security": Mock(),
        "ecar": Mock(),
        "zeek_conn": Mock(),
        "syslog": Mock(),
    }
    generator = ActivityGenerator(
        StateManager(),
        emitters,
        generation_window_start=_START,
        generation_window_end=_START + timedelta(days=days),
    )
    return generator, emitters


def _user(username: str = "alice") -> User:
    return User(
        username=username,
        full_name=username.title(),
        email=f"{username}@example.test",
        enabled=True,
    )


def _workstation() -> System:
    return System(
        hostname="WKS-01",
        ip="10.0.10.10",
        os="Windows 11",
        type="workstation",
    )


def _failed_events(emitters: dict[str, Mock]) -> list[object]:
    return [
        call.args[0]
        for call in emitters["windows_event_security"].emit.call_args_list
        if call.args[0].event_type == "failed_logon"
    ]


def _assert_no_pending_residue(generator: ActivityGenerator) -> None:
    assert generator._failed_logon_attempt_pending == {}


def test_successful_primary_commits_exact_auth_owned_cadence() -> None:
    generator, emitters = _generator()

    generator.generate_failed_logon(
        _user(),
        _workstation(),
        _START,
        logon_type=2,
    )

    assert generator._failed_logon_attempt_times.get(_FAILED_KEY) == (_START,)
    assert generator._failed_logon_attempt_times.metrics().live_entries == 1
    assert len(_failed_events(emitters)) == 1
    _assert_no_pending_residue(generator)


def test_pre_primary_failure_cancels_reservation_without_cadence(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    generator, emitters = _generator()
    monkeypatch.setattr(
        generator,
        "_failed_logon_profile",
        Mock(side_effect=StateError("profile rejected")),
    )

    with pytest.raises(StateError, match="profile rejected"):
        generator.generate_failed_logon(_user(), _workstation(), _START, logon_type=2)

    assert generator._failed_logon_attempt_times.get(_FAILED_KEY) is None
    assert generator._failed_logon_attempt_times.metrics().live_entries == 0
    assert _failed_events(emitters) == []
    _assert_no_pending_residue(generator)


def test_primary_dispatch_rejection_cancels_and_exact_retry_can_publish(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    generator, emitters = _generator()
    original_dispatch = generator.dispatcher.dispatch_builder

    def reject_primary(event: object) -> None:
        if getattr(event, "event_type", "") == "failed_logon":
            raise StateError("primary rejected")
        original_dispatch(event)  # type: ignore[arg-type]

    monkeypatch.setattr(generator.dispatcher, "dispatch_builder", reject_primary)
    with pytest.raises(StateError, match="primary rejected"):
        generator.generate_failed_logon(_user(), _workstation(), _START, logon_type=2)

    assert generator._failed_logon_attempt_times.get(_FAILED_KEY) is None
    _assert_no_pending_residue(generator)

    monkeypatch.setattr(generator.dispatcher, "dispatch_builder", original_dispatch)
    generator.generate_failed_logon(_user(), _workstation(), _START, logon_type=2)

    assert generator._failed_logon_attempt_times.get(_FAILED_KEY) == (_START,)
    assert len(_failed_events(emitters)) == 1
    _assert_no_pending_residue(generator)


def test_dc_companion_failure_retains_committed_primary_truth(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    generator, emitters = _generator()
    workstation = _workstation()
    dc = System(
        hostname="DC-01",
        ip="10.0.20.10",
        os="Windows Server 2022",
        type="domain_controller",
    )
    source_ip = "203.0.113.25"
    key = ("wks-01", "alice", 3, source_ip)
    monkeypatch.setattr(
        generator_mod,
        "failed_logon_config",
        lambda: {
            "network": {
                "validation_path_weights": {
                    "ntlm_only": {"emit_4776": True, "emit_4771": False, "weight": 1}
                },
                "logon_process_weights": {
                    "ntlm": {
                        "logon_process_name": "NtLmSsp",
                        "authentication_package_name": "NTLM",
                        "lm_package_name": "NTLM V2",
                        "weight": 1,
                    }
                },
                "emit_network_connection_probability": 0.0,
                "network_ports": {"smb": {"port": 445, "weight": 1}},
            }
        },
    )
    monkeypatch.setattr(
        generator,
        "generate_ntlm_validation",
        Mock(side_effect=StateError("DC companion rejected")),
    )

    with pytest.raises(StateError, match="DC companion rejected"):
        generator.generate_failed_logon(
            _user(),
            workstation,
            _START,
            logon_type=3,
            source_ip=source_ip,
            dc_system=dc,
        )

    assert generator._failed_logon_attempt_times.get(key) == (_START,)
    assert len(_failed_events(emitters)) == 1
    _assert_no_pending_residue(generator)

    generator.generate_failed_logon(
        _user(),
        workstation,
        _START + timedelta(milliseconds=350),
        logon_type=3,
        source_ip=source_ip,
        dc_system=dc,
    )
    assert len(_failed_events(emitters)) == 1


def test_pending_key_rejects_competitor_and_exact_claim_identity() -> None:
    generator, _emitters = _generator()
    prepared = generator._prepare_failed_logon_attempt_time(
        hostname="WKS-01",
        username="alice",
        logon_type=2,
        source_ip="-",
        requested_time=_START,
    )
    assert prepared is not None
    _normalized, reservation = prepared
    forged = replace(reservation)

    with pytest.raises(StateError, match="stale or foreign"):
        with generator._claimed_failed_logon_attempt(forged):
            pytest.fail("a copied reservation must not enter its claim body")
    with pytest.raises(StateError, match="active primary publication"):
        generator._prepare_failed_logon_attempt_time(
            hostname="wks-01.",
            username="ALICE",
            logon_type=2,
            source_ip="-",
            requested_time=_START + timedelta(seconds=1),
        )
    with pytest.raises(FrozenInstanceError):
        reservation.expires_at = _START + timedelta(days=30)  # type: ignore[misc]

    assert generator._failed_logon_attempt_pending[_FAILED_KEY].reservation is reservation
    with generator._claimed_failed_logon_attempt(reservation):
        pass
    assert generator._failed_logon_attempt_times.get(_FAILED_KEY) is None
    _assert_no_pending_residue(generator)


def test_malformed_cadence_value_fails_closed_without_new_reservation() -> None:
    generator, emitters = _generator()
    generator._failed_logon_attempt_times.set(
        _FAILED_KEY,
        ("not-a-timestamp",),  # type: ignore[arg-type]
        deadline=_START + timedelta(seconds=2),
    )
    before = generator._failed_logon_attempt_times.metrics()

    with pytest.raises(StateError, match="malformed timestamps"):
        generator.generate_failed_logon(_user(), _workstation(), _START, logon_type=2)

    after = generator._failed_logon_attempt_times.metrics()
    assert (after.live_entries, after.backing_entries, after.stale_entries) == (
        before.live_entries,
        before.backing_entries,
        before.stale_entries,
    )
    assert after.lookup_candidates_inspected == before.lookup_candidates_inspected + 1
    assert _failed_events(emitters) == []
    _assert_no_pending_residue(generator)


def test_cadence_value_is_sorted_capped_and_expires_after_semantic_horizon() -> None:
    generator, _emitters = _generator()
    key = ("wks-01", "alice", 3, "203.0.113.25")
    for ordinal in range(40):
        current = _START + timedelta(seconds=ordinal)
        prepared = generator._prepare_failed_logon_attempt_time(
            hostname="WKS-01.",
            username="ALICE",
            logon_type=3,
            source_ip="::ffff:203.0.113.25",
            requested_time=current,
        )
        assert prepared is not None
        _normalized, reservation = prepared
        with generator._claimed_failed_logon_attempt(reservation) as claim:
            claim.commit_no_fail()
        generator.advance_process_state_watermark(current)

    retained = generator._failed_logon_attempt_times.get(key)
    assert retained == tuple(_START + timedelta(seconds=ordinal) for ordinal in range(8, 40))
    metrics = generator._failed_logon_attempt_times.metrics()
    assert metrics.live_entries == 1
    assert metrics.backing_entries <= 3
    assert metrics.stale_entries <= 2

    generator._failed_logon_attempt_times.advance_watermark(
        _START + timedelta(seconds=41, microseconds=1),
        limit=4_096,
    )
    assert generator._failed_logon_attempt_times.get(key) is None
    assert generator._failed_logon_attempt_times.metrics().live_entries == 0


def test_pending_reservation_fences_auth_cache_watermark() -> None:
    generator, _emitters = _generator()
    prepared = generator._prepare_failed_logon_attempt_time(
        hostname="WKS-01",
        username="alice",
        logon_type=2,
        source_ip="-",
        requested_time=_START,
    )
    assert prepared is not None
    _normalized, reservation = prepared

    with pytest.raises(StateError, match="fenced by an active primary"):
        generator.advance_process_state_watermark(_START + timedelta(seconds=1))

    assert generator._failed_logon_attempt_pending[_FAILED_KEY].reservation is reservation
    generator._cancel_failed_logon_attempt(reservation)
    generator.advance_process_state_watermark(_START + timedelta(seconds=1))
    _assert_no_pending_residue(generator)


def test_attempt_behind_watermark_rejects_neutrally_and_equality_is_admitted() -> None:
    generator, emitters = _generator()
    watermark = _START + timedelta(seconds=10)
    generator.advance_process_state_watermark(watermark)

    with pytest.raises(StateError, match="starts behind the watermark"):
        generator.generate_failed_logon(_user(), _workstation(), _START, logon_type=2)

    assert _failed_events(emitters) == []
    assert generator._failed_logon_attempt_times.get(_FAILED_KEY) is None
    _assert_no_pending_residue(generator)

    generator.generate_failed_logon(_user(), _workstation(), watermark, logon_type=2)
    assert generator._failed_logon_attempt_times.get(_FAILED_KEY) == (watermark,)
    assert len(_failed_events(emitters)) == 1


def _duration_census(hours: int) -> tuple[int, int, int]:
    generator, _emitters = _generator()
    for hour in range(hours):
        current = _START + timedelta(hours=hour)
        prepared = generator._prepare_failed_logon_attempt_time(
            hostname="WKS-01",
            username=f"user-{hour}",
            logon_type=3,
            source_ip="203.0.113.25",
            requested_time=current,
        )
        assert prepared is not None
        _normalized, reservation = prepared
        with generator._claimed_failed_logon_attempt(reservation) as claim:
            claim.commit_no_fail()
        generator.advance_process_state_watermark(current)
    metrics = generator._failed_logon_attempt_times.metrics()
    return metrics.live_entries, metrics.backing_entries, metrics.stale_entries


def test_unique_failed_logon_key_universe_plateaus_from_seven_to_thirty_days() -> None:
    seven_day = _duration_census(24 * 7)
    thirty_day = _duration_census(24 * 30)

    assert seven_day == (1, 1, 0)
    assert thirty_day == seven_day


def test_failed_logon_cache_and_pending_reservation_have_closed_retention_policies() -> None:
    generator, _emitters = _generator()
    policies = {
        policy.field_name: policy for policy in ACTIVITY_GENERATOR_MUTABLE_RETENTION_POLICIES
    }

    assert isinstance(generator._failed_logon_attempt_times, BoundedRuntimeCache)
    assert policies["_failed_logon_attempt_times"].disposition is (
        ActivityGeneratorRetentionDisposition.BOUNDED
    )
    assert policies["_failed_logon_attempt_pending"].disposition is (
        ActivityGeneratorRetentionDisposition.TRANSIENT
    )
