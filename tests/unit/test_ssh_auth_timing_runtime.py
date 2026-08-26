# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Runtime-ownership contracts for the complete SSH authentication timing plan."""

from __future__ import annotations

import ast
import hashlib
import inspect
import json
import math
import os
import random
import subprocess
import sys
import textwrap
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from evidenceforge.events.base import OccurrenceBuilder
from evidenceforge.events.contexts import HostContext
from evidenceforge.generation.actions import ssh_session as ssh_session_module
from evidenceforge.generation.actions.base import ActionAnchor
from evidenceforge.generation.actions.ssh_session import (
    SshSessionActionBundle,
    SshSessionRequest,
)
from evidenceforge.generation.activity import ActivityGenerator
from evidenceforge.generation.activity import generator as generator_module
from evidenceforge.generation.activity import timing_profiles as timing_profiles_module
from evidenceforge.generation.activity.timing_profiles import (
    SshAuthenticationTimingPlan,
    plan_ssh_authentication_timing,
    ssh_authentication_timing_support,
)
from evidenceforge.generation.source_timing import SourceTimingPlanner
from evidenceforge.generation.timing import (
    ConstantDistribution,
    DistributionSpec,
    MixtureDistribution,
    TemporalConstraintError,
    TimingDistributionError,
    TimingRuntime,
    TimingSampler,
    TimingScope,
    TriangularDistribution,
)
from evidenceforge.models.exceptions import StateError
from evidenceforge.models.scenario import System, User

pytestmark = pytest.mark.slow

_START = datetime(2024, 1, 15, 10, tzinfo=UTC)
_GENERATION_ROOT = Path(timing_profiles_module.__file__).parents[1]
_PUBLIC_KEY_RELATIONSHIPS = {
    "ssh.authentication.connection_after_transport": 1,
    "ssh.authentication.phase": 1,
    "ssh.authentication.cache_delay": 1,
    "ssh.authentication.route_delay": 1,
    "ssh.authentication.receiver_delay": 1,
    "ssh.authentication.key_penalty": 1,
    "ssh.authentication.pam_after_accepted": 1,
    "ssh.authentication.logind_after_pam": 1,
}


class _Executor:
    """Minimal executor surface for allocation-free authentication planning."""

    def __init__(self, runtime: TimingRuntime | None) -> None:
        self.timing_runtime = runtime
        self._ip_to_system: dict[str, System] = {}
        self.dispatcher = SimpleNamespace(observation_policy=None)

    @staticmethod
    def _clamp_after_visible_linux_process_create_with_runtime(
        _system: System,
        _pid: int,
        requested_time: datetime,
        _relationship_key: str = "",
        **_kwargs: Any,
    ) -> datetime:
        """Leave the requested timestamp unchanged in direct timing tests."""

        return requested_time


class _RecordingTimingSampler:
    """Capture top-level SSH distributions while delegating real sampling."""

    def __init__(self, delegate: TimingSampler) -> None:
        self.delegate = delegate
        self.distributions: dict[str, DistributionSpec] = {}

    def sample_microseconds(
        self,
        distribution: DistributionSpec,
        *,
        relationship_key: str,
        scope: TimingScope,
        sample_key: str = "value",
    ) -> int:
        """Record and sample one distribution through the real sampler."""

        self.distributions[relationship_key] = distribution
        return self.delegate.sample_microseconds(
            distribution,
            relationship_key=relationship_key,
            scope=scope,
            sample_key=sample_key,
        )


def _assert_open_half_step_quantization_support(distribution: DistributionSpec) -> None:
    """Prove every continuous leaf accepts both intended outer integer bins."""

    if isinstance(distribution, ConstantDistribution):
        return
    if isinstance(distribution, MixtureDistribution):
        for component in distribution.components:
            _assert_open_half_step_quantization_support(component.distribution)
        return
    assert isinstance(distribution, TriangularDistribution)
    lower_bin = math.ceil(distribution.minimum)
    upper_bin = math.floor(distribution.maximum)
    assert distribution.minimum == lower_bin - 0.5
    assert distribution.maximum == upper_bin + 0.5
    rounded_lower = round(math.nextafter(distribution.minimum, distribution.maximum))
    rounded_upper = round(math.nextafter(distribution.maximum, distribution.minimum))
    assert (rounded_lower, rounded_upper) == (lower_bin, upper_bin)
    assert distribution.minimum < rounded_lower < distribution.maximum
    assert distribution.minimum < rounded_upper < distribution.maximum


def _request(
    *,
    auth_method: str = "publickey",
    public_key_type: str = "ED25519",
    linux: bool = True,
) -> SshSessionRequest:
    source = System(
        hostname="WS-01",
        ip="10.0.0.10",
        os="Windows 11",
        type="workstation",
    )
    target = System(
        hostname="LNX-01" if linux else "WIN-01",
        ip="10.0.0.20",
        os="Ubuntu 24.04" if linux else "Windows Server 2022",
        type="server",
        services=["ssh"] if linux else [],
    )
    return SshSessionRequest(
        user=User(
            username="analyst",
            full_name="Alicia Analyst",
            email="analyst@example.test",
        ),
        target_system=target,
        time=_START,
        source_ip=source.ip,
        source_system=source,
        source_port=51111,
        duration=60.0,
        orig_bytes=2048,
        resp_bytes=8192,
        auth_method=auth_method,
        public_key_type=public_key_type,
        source="ssh_auth_timing_test",
    )


def _bundle_state(
    runtime: TimingRuntime | None,
    *,
    auth_method: str = "publickey",
    public_key_type: str = "ED25519",
    linux: bool = True,
) -> tuple[SshSessionActionBundle, Any]:
    request = _request(
        auth_method=auth_method,
        public_key_type=public_key_type,
        linux=linux,
    )
    bundle = SshSessionActionBundle(
        request=request,
        executor=_Executor(runtime),  # type: ignore[arg-type]
    )
    execution_id = request.execution_stable_id(51111)
    state = ssh_session_module._SshTransportState(
        rng=random.Random(8675309),
        source_port=51111,
        duration=60.0,
        close_time=_START + timedelta(seconds=60),
        orig_bytes=2048,
        resp_bytes=8192,
        network_visible=True,
        dst_host=HostContext(
            hostname=request.target_system.hostname,
            ip=request.target_system.ip,
            os=request.target_system.os,
            os_category="linux" if linux else "windows",
            system_type="server",
        ),
        session_obj_id="session-object",
        open_time=_START,
        execution_anchor=ActionAnchor(
            family="ssh_session",
            stable_id=execution_id,
            source=request.source,
        ),
    )
    return bundle, state


def _scope(stable_id: str) -> TimingScope:
    return TimingScope(
        stable_id=stable_id,
        host="LNX-01",
        source="ssh",
        lifecycle_id=stable_id,
    )


def _four_gaps(plan: SshAuthenticationTimingPlan) -> tuple[float, float, float, float]:
    return (
        plan.connection_gap_ms,
        plan.accepted_gap_ms,
        plan.pam_gap_ms,
        plan.logind_gap_ms,
    )


def _audit_payload(runtime: TimingRuntime) -> dict[str, dict[str, int]]:
    summary = runtime.audit.snapshot()
    return {
        "samples": dict(summary.sample_counts),
        "distributions": dict(summary.distribution_counts),
        "repairs": dict(summary.repair_counts),
        "saturations": dict(summary.saturation_counts),
        "fallbacks": dict(summary.fallback_counts),
    }


def _audit_digest(runtime: TimingRuntime) -> str:
    payload = json.dumps(_audit_payload(runtime), sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _forced_lifecycle_repair(
    timing_runtime: Any,
) -> dict[str, datetime]:
    """Resolve one deliberately collapsed accepted phase through graph repair."""

    bundle, state = _bundle_state(timing_runtime)
    scope = _scope("ssh-forced-lifecycle-repair")
    plan = plan_ssh_authentication_timing(
        "publickey",
        public_key_type="ED25519",
        route_class="private",
        timing_runtime=timing_runtime,
        scope=scope,
    )
    forced = replace(
        plan,
        # Stay above the configured eCAR visibility floor so the deliberately
        # collapsed accepted phase must be repaired relative to connection.
        connection_gap_ms=10_000,
        accepted=replace(
            plan.accepted,
            phase_ms=0,
            cache_delay_ms=0,
            route_delay_ms=0,
            receiver_delay_ms=0,
            key_penalty_ms=0,
        ),
    )
    return bundle._resolve_linux_auth_lifecycle(
        event=OccurrenceBuilder(
            timestamp=_START,
            event_type="ssh_session",
            dst_host=state.dst_host,
        ),
        responder_pid=4242,
        conn_delay_ms=forced.connection_gap_ms,
        accepted_gap_ms=forced.accepted_gap_ms,
        pam_gap_ms=forced.pam_gap_ms,
        logind_gap_ms=forced.logind_gap_ms,
        transport_open_time=_START,
        timing_runtime=timing_runtime,
        timing_scope=scope,
    )


def _runtime_owned_linux_visibility_clamp(
    timing_runtime: Any,
    *,
    requested_time: datetime = _START,
    timing_scope: TimingScope | None = None,
) -> datetime:
    """Invoke the generator's strict Linux visibility clamp without full construction."""

    generator = object.__new__(ActivityGenerator)
    generator.process_source_create_bound = lambda _system, _pid: _START
    return generator._clamp_after_visible_linux_process_create_with_runtime(
        _request().target_system,
        4242,
        requested_time,
        timing_runtime=timing_runtime,
        timing_scope=timing_scope or _scope("ssh-visible-process-clamp"),
    )


@pytest.mark.parametrize(
    ("auth_method", "route_class", "key_type", "expected_total"),
    [
        ("publickey", "private", "", (27, 7005)),
        ("publickey", "private", "ED25519", (27, 7040)),
        ("publickey", "private", "ECDSA", (32, 7080)),
        ("publickey", "private", "RSA", (47, 7245)),
        ("publickey", "public", "", (50, 7270)),
        ("publickey", "public", "ED25519", (50, 7305)),
        ("publickey", "public", "ECDSA", (55, 7345)),
        ("publickey", "public", "RSA", (70, 7510)),
        ("password", "private", "", (182, 12505)),
        ("password", "public", "", (205, 12770)),
    ],
)
def test_former_component_and_total_supports_are_exact(
    auth_method: str,
    route_class: str,
    key_type: str,
    expected_total: tuple[int, int],
) -> None:
    """Typed support metadata preserves every former inclusive integer endpoint."""

    support = ssh_authentication_timing_support(
        auth_method,
        public_key_type=key_type,
        route_class=route_class,
    )

    assert support.connection_gap_ms.intervals == ((35, 160),)
    assert support.pam_gap_ms.intervals == ((45, 180),)
    assert support.logind_gap_ms.intervals == ((420, 760),)
    assert support.accepted_gap_ms.bounds == expected_total
    assert support.lifecycle_gap_ms.bounds == (
        expected_total[0] + 35 + 45 + 420,
        expected_total[1] + 160 + 180 + 760,
    )
    if auth_method == "publickey":
        assert support.accepted.phase_ms.intervals == ((25, 4800),)
        assert support.accepted.cache_delay_ms.intervals == ((0, 0), (120, 1500))
    else:
        assert support.accepted.phase_ms.intervals == ((180, 9000),)
        assert support.accepted.cache_delay_ms.intervals == ((0, 0), (250, 2800))
    assert support.accepted.route_delay_ms.intervals == (
        ((2, 55),) if route_class == "private" else ((25, 320),)
    )
    assert support.accepted.receiver_delay_ms.intervals == ((0, 650),)
    expected_key_support = {
        "": ((0, 0),),
        "ED25519": ((0, 35),),
        "ECDSA": ((5, 75),),
        "RSA": ((20, 240),),
    }[key_type]
    assert support.accepted.key_penalty_ms.intervals == expected_key_support


@pytest.mark.parametrize(
    ("auth_method", "phase_weights", "cache_weights"),
    [
        (
            "publickey",
            (0.12, 0.22, 1.0 - 0.12 - 0.22),
            (1.0 - 0.18, 0.18),
        ),
        (
            "password",
            (0.18, 0.08, 1.0 - 0.18 - 0.08),
            (1.0 - 0.32, 0.32),
        ),
    ],
)
def test_half_step_bounds_preserve_exact_configured_mixture_weights(
    auth_method: str,
    phase_weights: tuple[float, ...],
    cache_weights: tuple[float, ...],
) -> None:
    """Open half-step leaves cannot reject an outer bin and reselect a mixture."""

    delegate = TimingRuntime(
        reference_time=_START,
        namespace=f"ssh-half-step-{auth_method}",
    )
    recorder = _RecordingTimingSampler(delegate.sampler)
    plan_ssh_authentication_timing(
        auth_method,
        public_key_type="",
        route_class="private",
        timing_runtime=SimpleNamespace(sampler=recorder),
        scope=_scope(f"ssh-half-step-{auth_method}"),
    )

    expected_relationships = set(_PUBLIC_KEY_RELATIONSHIPS)
    expected_relationships.remove("ssh.authentication.key_penalty")
    assert set(recorder.distributions) == expected_relationships
    phase = recorder.distributions["ssh.authentication.phase"]
    cache = recorder.distributions["ssh.authentication.cache_delay"]
    assert isinstance(phase, MixtureDistribution)
    assert isinstance(cache, MixtureDistribution)
    assert tuple(component.weight for component in phase.components) == phase_weights
    assert tuple(component.weight for component in cache.components) == cache_weights
    assert math.fsum(component.weight for component in phase.components) == 1.0
    assert math.fsum(component.weight for component in cache.components) == 1.0
    for distribution in recorder.distributions.values():
        _assert_open_half_step_quantization_support(distribution)


@pytest.mark.parametrize(
    ("auth_method", "key_type", "expected_samples"),
    [("publickey", "ED25519", 8), ("password", "", 7)],
)
def test_production_plan_uses_one_exact_runtime_without_shared_rng(
    monkeypatch: pytest.MonkeyPatch,
    auth_method: str,
    key_type: str,
    expected_samples: int,
) -> None:
    """Linux planning audits only real phases and leaves the shared RNG untouched."""

    runtime = TimingRuntime(
        reference_time=_START,
        namespace=f"ssh-production-{auth_method}",
    )
    bundle, state = _bundle_state(
        runtime,
        auth_method=auth_method,
        public_key_type=key_type,
    )
    monkeypatch.setattr(
        SshSessionActionBundle,
        "_resolve_responder_pid",
        lambda _bundle, _state, _gap: 4242,
    )
    before_rng = state.rng.getstate()

    plan = bundle._prepare_linux_auth_plan(state)

    assert plan is not None
    assert state.rng.getstate() == before_rng
    support = ssh_authentication_timing_support(
        auth_method,
        public_key_type=key_type,
        route_class="private",
    )
    assert plan.conn_delay_ms in support.connection_gap_ms
    assert plan.accepted_gap_ms in support.accepted_gap_ms
    assert plan.pam_gap_ms in support.pam_gap_ms
    assert plan.logind_gap_ms in support.logind_gap_ms
    accepted = plan.timing.accepted
    component_pairs = (
        (accepted.phase_ms, support.accepted.phase_ms),
        (accepted.cache_delay_ms, support.accepted.cache_delay_ms),
        (accepted.route_delay_ms, support.accepted.route_delay_ms),
        (accepted.receiver_delay_ms, support.accepted.receiver_delay_ms),
        (accepted.key_penalty_ms, support.accepted.key_penalty_ms),
    )
    assert all(value in component_support for value, component_support in component_pairs)
    sampled_values = (
        plan.conn_delay_ms,
        *(value for value, _component_support in component_pairs),
        plan.pam_gap_ms,
        plan.logind_gap_ms,
    )
    assert all(abs(value * 1_000 - round(value * 1_000)) < 1e-9 for value in sampled_values)
    assert any(not value.is_integer() for value in sampled_values if value)
    audit = runtime.audit.snapshot()
    assert audit.total_samples == expected_samples
    expected_relationships = dict(_PUBLIC_KEY_RELATIONSHIPS)
    if not key_type:
        expected_relationships.pop("ssh.authentication.key_penalty")
    assert audit.sample_counts == expected_relationships
    assert audit.repair_counts == {}
    assert audit.saturation_counts == {}
    assert audit.fallback_counts == {}


def test_direct_and_prepared_planning_have_all_four_gap_and_full_audit_parity() -> None:
    """A staged timing view commits the same four gaps and complete audit as direct planning."""

    direct_runtime = TimingRuntime(
        reference_time=_START,
        namespace="ssh-direct-prepared-parity",
    )
    direct = plan_ssh_authentication_timing(
        "publickey",
        public_key_type="ED25519",
        route_class="private",
        timing_runtime=direct_runtime,
        scope=_scope("ssh-parity"),
    )

    staged_runtime = TimingRuntime(
        reference_time=_START,
        namespace="ssh-direct-prepared-parity",
    )
    timing_owner = SourceTimingPlanner(timing_runtime=staged_runtime)
    with timing_owner.prepared_planning() as preparation:
        staged = plan_ssh_authentication_timing(
            "publickey",
            public_key_type="ED25519",
            route_class="private",
            timing_runtime=preparation.planning_runtime,
            scope=_scope("ssh-parity"),
        )
        assert preparation.staged_audit_operations == 8
        assert staged_runtime.audit.snapshot().total_samples == 0

    with preparation.claimed_commit():
        preparation.commit_no_fail()

    assert _four_gaps(staged) == _four_gaps(direct)
    assert staged == direct
    assert staged_runtime.audit.snapshot() == direct_runtime.audit.snapshot()
    assert _audit_digest(staged_runtime) == _audit_digest(direct_runtime)


def test_non_linux_and_missing_runtime_paths_create_no_phantom_samples(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Inapplicable targets sample nothing; applicable production paths require the runtime."""

    runtime = TimingRuntime(reference_time=_START, namespace="ssh-no-phantom")
    non_linux_bundle, non_linux_state = _bundle_state(runtime, linux=False)
    before_rng = non_linux_state.rng.getstate()
    responder_calls = 0

    def count_responder(*_args: Any, **_kwargs: Any) -> int:
        nonlocal responder_calls
        responder_calls += 1
        return 4242

    monkeypatch.setattr(SshSessionActionBundle, "_resolve_responder_pid", count_responder)

    assert non_linux_bundle._prepare_linux_auth_plan(non_linux_state) is None
    assert non_linux_state.rng.getstate() == before_rng
    assert runtime.audit.snapshot().total_samples == 0
    assert responder_calls == 0

    linux_bundle, linux_state = _bundle_state(None)
    before_linux_rng = linux_state.rng.getstate()
    with pytest.raises(StateError, match="executor TimingRuntime"):
        linux_bundle._prepare_linux_auth_plan(linux_state)
    assert linux_state.rng.getstate() == before_linux_rng
    assert responder_calls == 0


def test_lifecycle_and_visibility_clamp_reject_missing_injection_before_reads(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Strict lifecycle paths reject missing capabilities before compatibility or state reads."""

    runtime = TimingRuntime(reference_time=_START, namespace="ssh-strict-admission")
    bundle, state = _bundle_state(runtime)
    scope = _scope("ssh-strict-admission")

    def fail_compatibility_default(_cls: type[TimingRuntime]) -> TimingRuntime:
        raise AssertionError("compatibility timing runtime must not be constructed")

    monkeypatch.setattr(
        TimingRuntime,
        "compatibility_default",
        classmethod(fail_compatibility_default),
    )
    lifecycle_kwargs = {
        "event": OccurrenceBuilder(
            timestamp=_START,
            event_type="ssh_session",
            dst_host=state.dst_host,
        ),
        "responder_pid": 4242,
        "conn_delay_ms": 50,
        "accepted_gap_ms": 100,
        "pam_gap_ms": 50,
        "logind_gap_ms": 500,
        "transport_open_time": _START,
    }
    with pytest.raises(StateError, match="exact injected timing runtime"):
        bundle._resolve_linux_auth_lifecycle(
            **lifecycle_kwargs,
            timing_runtime=None,
            timing_scope=scope,
        )
    with pytest.raises(StateError, match="exact TimingScope"):
        bundle._resolve_linux_auth_lifecycle(
            **lifecycle_kwargs,
            timing_runtime=runtime,
            timing_scope=None,
        )

    generator = object.__new__(ActivityGenerator)

    def fail_process_read(_hostname: str, _pid: int) -> datetime | None:
        raise AssertionError("visibility state must not be read before admission")

    generator.process_source_create_time = fail_process_read
    with pytest.raises(StateError, match="exact timing runtime"):
        generator._clamp_after_visible_linux_process_create_with_runtime(
            _request().target_system,
            4242,
            _START,
            timing_runtime=None,
            timing_scope=scope,
        )
    with pytest.raises(StateError, match="exact TimingScope"):
        generator._clamp_after_visible_linux_process_create_with_runtime(
            _request().target_system,
            4242,
            _START,
            timing_runtime=runtime,
            timing_scope=None,
        )
    assert runtime.audit.snapshot().total_samples == 0


def test_planned_auth_reuse_and_lifecycle_resolution_do_not_resample(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Prepared live reuse and exact-base lifecycle consumption preserve the full audit."""

    runtime = TimingRuntime(reference_time=_START, namespace="ssh-prepared-reuse")
    bundle, state = _bundle_state(runtime)
    monkeypatch.setattr(
        SshSessionActionBundle,
        "_resolve_responder_pid",
        lambda _bundle, _state, _gap: 4242,
    )
    plan = bundle._prepare_linux_auth_plan(state)
    assert plan is not None
    assert plan.timing_runtime is runtime
    replacement_runtime = TimingRuntime(reference_time=_START, namespace="ssh-runtime-swap")
    bundle.executor.timing_runtime = replacement_runtime
    event = OccurrenceBuilder(
        timestamp=_START,
        event_type="ssh_session",
        dst_host=state.dst_host,
    )
    before = runtime.audit.snapshot()
    before_digest = _audit_digest(runtime)

    parameters = inspect.signature(bundle._plan_linux_auth).parameters
    if "planned_auth_state" in parameters:
        planned_state = ssh_session_module._SshLinuxAuthState(
            sshd_pid=4242,
            logind_session_id=17,
            syslog_seed=plan.syslog_seed,
            connection_time=_START + timedelta(milliseconds=plan.conn_delay_ms),
            accepted_time=_START
            + timedelta(milliseconds=plan.conn_delay_ms + plan.accepted_gap_ms),
            pam_time=_START
            + timedelta(milliseconds=plan.conn_delay_ms + plan.accepted_gap_ms + plan.pam_gap_ms),
            logind_time=_START + timedelta(milliseconds=plan.timing.lifecycle_gap_ms),
        )
        reused = bundle._plan_linux_auth(
            state,
            event,
            plan,
            planned_auth_state=planned_state,
        )
        assert reused is planned_state
    else:
        bundle._resolve_linux_auth_lifecycle(
            event=event,
            responder_pid=4242,
            conn_delay_ms=plan.conn_delay_ms,
            accepted_gap_ms=plan.accepted_gap_ms,
            pam_gap_ms=plan.pam_gap_ms,
            logind_gap_ms=plan.logind_gap_ms,
            transport_open_time=_START,
            timing_runtime=plan.timing_runtime,
            timing_scope=plan.timing_scope,
        )
    assert runtime.audit.snapshot() == before
    assert _audit_digest(runtime) == before_digest
    assert replacement_runtime.audit.snapshot().total_samples == 0


def test_runtime_gaps_enforce_strict_transport_to_logind_order(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The four sampled gaps preserve the canonical SSH authentication causal chain."""

    runtime = TimingRuntime(reference_time=_START, namespace="ssh-causal-order")
    bundle, state = _bundle_state(runtime)
    monkeypatch.setattr(
        SshSessionActionBundle,
        "_resolve_responder_pid",
        lambda _bundle, _state, _gap: 4242,
    )
    plan = bundle._prepare_linux_auth_plan(state)
    assert plan is not None
    monkeypatch.setattr(
        ssh_session_module,
        "get_timing_window",
        lambda *_args, **_kwargs: SimpleNamespace(max_ms=0),
    )
    monkeypatch.setattr(
        ssh_session_module,
        "source_observation_delay_difference",
        lambda *_args, **_kwargs: timedelta(0),
    )
    resolved = bundle._resolve_linux_auth_lifecycle(
        event=OccurrenceBuilder(
            timestamp=_START,
            event_type="ssh_session",
            dst_host=state.dst_host,
        ),
        responder_pid=4242,
        conn_delay_ms=plan.conn_delay_ms,
        accepted_gap_ms=plan.accepted_gap_ms,
        pam_gap_ms=plan.pam_gap_ms,
        logind_gap_ms=plan.logind_gap_ms,
        transport_open_time=_START,
        timing_runtime=runtime,
        timing_scope=plan.timing_scope,
    )

    expected_connection = _START + timedelta(milliseconds=plan.conn_delay_ms)
    expected_accepted = expected_connection + timedelta(milliseconds=plan.accepted_gap_ms)
    expected_pam = expected_accepted + timedelta(milliseconds=plan.pam_gap_ms)
    expected_logind = expected_pam + timedelta(milliseconds=plan.logind_gap_ms)
    assert resolved == {
        "transport_open": _START,
        "connection": expected_connection,
        "accepted": expected_accepted,
        "pam": expected_pam,
        "logind": expected_logind,
    }


def test_lifecycle_repair_uses_injected_runtime_with_prepared_audit_parity() -> None:
    """Constraint repair is stable and audited by the same direct or staged runtime."""

    direct_runtime = TimingRuntime(
        reference_time=_START,
        namespace="ssh-lifecycle-repair-parity",
    )
    direct = _forced_lifecycle_repair(direct_runtime)
    direct_audit = direct_runtime.audit.snapshot()
    assert direct_audit.total_samples == 11
    assert direct_audit.sample_counts["ssh.authentication.lifecycle_repair"] == 3
    assert direct_audit.repair_counts == {"ssh.authentication.lifecycle_repair": 3}
    assert direct_audit.saturation_counts == {}
    assert direct_audit.fallback_counts == {}

    staged_runtime = TimingRuntime(
        reference_time=_START,
        namespace="ssh-lifecycle-repair-parity",
    )
    timing_owner = SourceTimingPlanner(timing_runtime=staged_runtime)
    with timing_owner.prepared_planning() as preparation:
        staged = _forced_lifecycle_repair(preparation.planning_runtime)
        assert staged_runtime.audit.snapshot().total_samples == 0

    with preparation.claimed_commit():
        preparation.commit_no_fail()

    assert staged == direct
    assert staged_runtime.audit.snapshot() == direct_audit
    assert _audit_digest(staged_runtime) == _audit_digest(direct_runtime)


def test_lifecycle_repair_fault_is_audited_by_injected_runtime(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A repair sampling fault saturates the injected audit without compatibility fallback."""

    runtime = TimingRuntime(
        reference_time=_START,
        namespace="ssh-lifecycle-repair-fault",
    )

    def fail_repair(
        _sampler: TimingSampler,
        _distribution: DistributionSpec,
        *,
        relationship_key: str,
        scope: TimingScope,
        sample_key: str = "value",
    ) -> timedelta:
        del scope, sample_key
        assert relationship_key == "ssh.authentication.lifecycle_repair"
        raise TimingDistributionError("forced SSH lifecycle repair fault")

    monkeypatch.setattr(TimingSampler, "sample_timedelta", fail_repair)
    with pytest.raises(TemporalConstraintError, match="no sampleable interior repair"):
        _forced_lifecycle_repair(runtime)

    audit = runtime.audit.snapshot()
    assert audit.total_samples == 8
    assert audit.repair_counts == {}
    assert audit.saturation_counts == {"ssh.authentication.lifecycle_repair": 1}
    assert audit.fallback_counts == {}


def test_linux_visibility_clamp_uses_injected_runtime_with_no_phantom_samples() -> None:
    """The reachable SSH process floor has direct/staged parity and skips absent clamps."""

    direct_runtime = TimingRuntime(
        reference_time=_START,
        namespace="ssh-visible-clamp-parity",
    )
    direct = _runtime_owned_linux_visibility_clamp(direct_runtime)
    direct_audit = direct_runtime.audit.snapshot()
    assert _START + timedelta(milliseconds=1) <= direct <= _START + timedelta(milliseconds=35)
    assert direct_audit.total_samples == 1
    assert direct_audit.sample_counts == {
        "source.ecar_dependent_after_process_create": 1,
    }
    assert direct_audit.repair_counts == {}
    assert direct_audit.saturation_counts == {}
    assert direct_audit.fallback_counts == {}

    staged_runtime = TimingRuntime(
        reference_time=_START,
        namespace="ssh-visible-clamp-parity",
    )
    timing_owner = SourceTimingPlanner(timing_runtime=staged_runtime)
    with timing_owner.prepared_planning() as preparation:
        staged = _runtime_owned_linux_visibility_clamp(preparation.planning_runtime)
        assert staged_runtime.audit.snapshot().total_samples == 0

    with preparation.claimed_commit():
        preparation.commit_no_fail()

    assert staged == direct
    assert staged_runtime.audit.snapshot() == direct_audit
    assert _audit_digest(staged_runtime) == _audit_digest(direct_runtime)

    no_clamp_runtime = TimingRuntime(
        reference_time=_START,
        namespace="ssh-visible-clamp-noop",
    )
    unchanged = _runtime_owned_linux_visibility_clamp(
        no_clamp_runtime,
        requested_time=_START + timedelta(seconds=1),
    )
    assert unchanged == _START + timedelta(seconds=1)
    assert no_clamp_runtime.audit.snapshot().total_samples == 0


def test_linux_visibility_clamp_fault_uses_exact_runtime_and_scope(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Clamp faults propagate from the exact sampler without compatibility fallback."""

    runtime = TimingRuntime(
        reference_time=_START,
        namespace="ssh-visible-clamp-fault",
    )
    timing_scope = _scope("ssh-visible-clamp-fault")

    def fail_sample(
        sampler: TimingSampler,
        _distribution: DistributionSpec,
        *,
        relationship_key: str,
        scope: TimingScope,
        sample_key: str = "value",
    ) -> timedelta:
        assert sampler is runtime.sampler
        assert relationship_key == "source.ecar_dependent_after_process_create"
        assert scope is timing_scope
        assert sample_key == "visible_process_create_gap"
        raise TimingDistributionError("forced SSH visibility-clamp fault")

    def fail_legacy(*_args: Any, **_kwargs: Any) -> timedelta:
        raise AssertionError("legacy timing helper must not be called")

    def fail_compatibility_default(_cls: type[TimingRuntime]) -> TimingRuntime:
        raise AssertionError("compatibility timing runtime must not be constructed")

    monkeypatch.setattr(TimingSampler, "sample_timedelta", fail_sample)
    monkeypatch.setattr(generator_module, "sample_timing_delta", fail_legacy, raising=False)
    monkeypatch.setattr(
        TimingRuntime,
        "compatibility_default",
        classmethod(fail_compatibility_default),
    )

    with pytest.raises(TimingDistributionError, match="visibility-clamp fault"):
        _runtime_owned_linux_visibility_clamp(runtime, timing_scope=timing_scope)

    audit = runtime.audit.snapshot()
    assert audit.total_samples == 0
    assert audit.repair_counts == {}
    assert audit.saturation_counts == {}
    assert audit.fallback_counts == {}


def _worker_population(
    worker_count: int,
) -> tuple[tuple[tuple[float, float, float, float], ...], str]:
    runtime = TimingRuntime(reference_time=_START, namespace="ssh-worker-determinism")

    def sample(index: int) -> tuple[float, float, float, float]:
        plan = plan_ssh_authentication_timing(
            "publickey",
            public_key_type="ED25519",
            route_class="private",
            timing_runtime=runtime,
            scope=_scope(f"ssh-worker-{index}"),
        )
        return _four_gaps(plan)

    with ThreadPoolExecutor(max_workers=worker_count) as pool:
        values = tuple(pool.map(sample, range(64)))
    return values, _audit_digest(runtime)


def test_all_four_gaps_and_full_audit_are_worker_deterministic() -> None:
    """Worker topology cannot change any phase gap or the complete audit digest."""

    assert _worker_population(1) == _worker_population(8)


def test_all_four_gaps_and_full_audit_ignore_pythonhashseed() -> None:
    """The typed timing scope has no dependency on Python hash randomization."""

    script = textwrap.dedent(
        """
        import hashlib
        import json
        from concurrent.futures import ThreadPoolExecutor
        from datetime import UTC, datetime

        from evidenceforge.generation.activity.timing_profiles import (
            plan_ssh_authentication_timing,
        )
        from evidenceforge.generation.timing import TimingRuntime, TimingScope

        start = datetime(2024, 1, 15, 10, tzinfo=UTC)
        runtime = TimingRuntime(reference_time=start, namespace="ssh-hash-determinism")

        def sample(index):
            stable_id = f"ssh-hash-{index}"
            plan = plan_ssh_authentication_timing(
                "publickey",
                public_key_type="ED25519",
                route_class="private",
                timing_runtime=runtime,
                scope=TimingScope(
                    stable_id=stable_id,
                    host="LNX-01",
                    source="ssh",
                    lifecycle_id=stable_id,
                ),
            )
            return (
                plan.connection_gap_ms,
                plan.accepted_gap_ms,
                plan.pam_gap_ms,
                plan.logind_gap_ms,
            )

        with ThreadPoolExecutor(max_workers=8) as pool:
            values = tuple(pool.map(sample, range(64)))
        audit = runtime.audit.snapshot()
        audit_payload = {
            "samples": dict(audit.sample_counts),
            "distributions": dict(audit.distribution_counts),
            "repairs": dict(audit.repair_counts),
            "saturations": dict(audit.saturation_counts),
            "fallbacks": dict(audit.fallback_counts),
        }
        audit_bytes = json.dumps(
            audit_payload,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        print(json.dumps({
            "values": values,
            "audit": hashlib.sha256(audit_bytes).hexdigest(),
        }, sort_keys=True, separators=(",", ":")))
        """
    )
    project_root = Path(__file__).parents[2]
    outputs: list[str] = []
    for hash_seed in ("1", "987654"):
        environment = dict(os.environ)
        environment["PYTHONHASHSEED"] = hash_seed
        environment["PYTHONPATH"] = str(project_root / "src")
        result = subprocess.run(
            [sys.executable, "-c", script],
            cwd=project_root,
            env=environment,
            check=True,
            capture_output=True,
            text=True,
        )
        outputs.append(result.stdout.strip())

    assert outputs[0] == outputs[1]
    assert len(json.loads(outputs[0])["values"]) == 64


def _function(tree: ast.Module, name: str) -> ast.FunctionDef:
    matches = [
        node for node in ast.walk(tree) if isinstance(node, ast.FunctionDef) and node.name == name
    ]
    assert len(matches) == 1
    return matches[0]


def _called_name(call: ast.Call) -> str:
    if isinstance(call.func, ast.Name):
        return call.func.id
    if isinstance(call.func, ast.Attribute):
        return call.func.attr
    return ""


def test_ast_policy_rejects_legacy_signature_private_rng_and_production_fallback() -> None:
    """Production has one strict runtime call and compatibility is a direct-only adapter."""

    timing_path = Path(timing_profiles_module.__file__)
    timing_tree = ast.parse(timing_path.read_text(encoding="utf-8"), filename=str(timing_path))
    ssh_path = Path(ssh_session_module.__file__)
    ssh_tree = ast.parse(ssh_path.read_text(encoding="utf-8"), filename=str(ssh_path))
    generator_path = Path(generator_module.__file__)
    generator_tree = ast.parse(
        generator_path.read_text(encoding="utf-8"),
        filename=str(generator_path),
    )

    assert not any(
        isinstance(node, ast.FunctionDef) and node.name == "sample_ssh_authentication_phase_ms"
        for node in ast.walk(timing_tree)
    )
    strict = _function(timing_tree, "plan_ssh_authentication_timing")
    strict_keywords = {
        argument.arg: default
        for argument, default in zip(
            strict.args.kwonlyargs,
            strict.args.kw_defaults,
            strict=True,
        )
    }
    assert strict_keywords["timing_runtime"] is None
    assert strict_keywords["scope"] is None
    assert "seed_parts" not in strict_keywords

    relevant_functions = (
        strict,
        _function(timing_tree, "_plan_ssh_accepted_authentication_timing"),
        _function(timing_tree, "_sample_ssh_milliseconds"),
        _function(timing_tree, "sample_ssh_authentication_phase_ms_compatibility"),
    )
    for function in relevant_functions:
        calls = [node for node in ast.walk(function) if isinstance(node, ast.Call)]
        assert not any(_called_name(call) == "Random" for call in calls)
        assert not any(_called_name(call) == "_stable_seed" for call in calls)

    for tree in (ssh_tree, generator_tree):
        assert not any(
            isinstance(node, ast.FunctionDef) and node.name == "_ssh_syslog_time"
            for node in ast.walk(tree)
        )
        assert not any(
            isinstance(node, ast.Name) and node.id == "_SSH_SYSLOG_MICRO_JITTER_BANDS"
            for node in ast.walk(tree)
        )
    production = _function(ssh_tree, "_prepare_linux_auth_plan")
    production_calls = {
        _called_name(node) for node in ast.walk(production) if isinstance(node, ast.Call)
    }
    assert "plan_ssh_authentication_timing" in production_calls
    assert "sample_ssh_authentication_phase_ms_compatibility" not in production_calls
    assert "compatibility_default" not in production_calls
    assert "_timing_planner" not in production_calls
    assert "randint" not in production_calls
    assert "randrange" not in production_calls
    assert "Random" not in production_calls
    assert "_stable_seed" not in production_calls

    lifecycle = _function(ssh_tree, "_resolve_linux_auth_lifecycle")
    assert "syslog_seed" not in {
        argument.arg for argument in (*lifecycle.args.args, *lifecycle.args.kwonlyargs)
    }
    private_temporal_calls = {
        "Random",
        "_stable_seed",
        "randint",
        "randrange",
        "random",
        "sample_timing_delta",
        "triangular",
        "uniform",
        "_ssh_syslog_time",
        "_clamp_after_visible_linux_process_create",
    }
    for function in (
        production,
        _function(ssh_tree, "_ensure_session_identity"),
        _function(ssh_tree, "_plan_linux_auth"),
        lifecycle,
    ):
        calls = {_called_name(node) for node in ast.walk(function) if isinstance(node, ast.Call)}
        assert private_temporal_calls.isdisjoint(calls)
        assert not any(
            isinstance(node, ast.BinOp) and isinstance(node.op, ast.Mod)
            for node in ast.walk(function)
        )

    lifecycle_callers = [
        node
        for node in ast.walk(ssh_tree)
        if isinstance(node, ast.Call) and _called_name(node) == "_resolve_linux_auth_lifecycle"
    ]
    assert lifecycle_callers
    for call in lifecycle_callers:
        keywords = {keyword.arg: keyword.value for keyword in call.keywords}
        assert isinstance(keywords["timing_runtime"], ast.Attribute)
        assert keywords["timing_runtime"].attr == "timing_runtime"
        assert isinstance(keywords["timing_runtime"].value, ast.Name)
        assert keywords["timing_runtime"].value.id in {"plan", "auth_plan"}
        assert isinstance(keywords["timing_scope"], ast.Attribute)
        assert keywords["timing_scope"].attr == "timing_scope"
        assert isinstance(keywords["timing_scope"].value, ast.Name)
        assert keywords["timing_scope"].value.id in {"plan", "auth_plan"}

    graph_calls = [
        node
        for node in ast.walk(lifecycle)
        if isinstance(node, ast.Call) and _called_name(node) == "TemporalConstraintGraph"
    ]
    assert len(graph_calls) == 1
    graph_keywords = {keyword.arg: keyword.value for keyword in graph_calls[0].keywords}
    assert set(graph_keywords) == {"timing_runtime", "scope", "relationship_key"}
    assert isinstance(graph_keywords["timing_runtime"], ast.Name)
    assert graph_keywords["timing_runtime"].id == "timing_runtime"
    assert isinstance(graph_keywords["scope"], ast.Name)
    assert graph_keywords["scope"].id == "timing_scope"
    clamp_calls = [
        node
        for node in ast.walk(lifecycle)
        if isinstance(node, ast.Call)
        and _called_name(node) == "_clamp_after_visible_linux_process_create_with_runtime"
    ]
    assert len(clamp_calls) == 1
    clamp_keywords = {keyword.arg: keyword.value for keyword in clamp_calls[0].keywords}
    assert {"timing_runtime", "timing_scope"} <= clamp_keywords.keys()
    assert isinstance(clamp_keywords["timing_runtime"], ast.Name)
    assert clamp_keywords["timing_runtime"].id == "timing_runtime"
    assert isinstance(clamp_keywords["timing_scope"], ast.Name)
    assert clamp_keywords["timing_scope"].id == "timing_scope"

    strict_clamp = _function(
        generator_tree,
        "_clamp_after_visible_linux_process_create_with_runtime",
    )
    strict_clamp_keywords = {
        argument.arg: default
        for argument, default in zip(
            strict_clamp.args.kwonlyargs,
            strict_clamp.args.kw_defaults,
            strict=True,
        )
    }
    assert strict_clamp_keywords["timing_runtime"] is None
    assert strict_clamp_keywords["timing_scope"] is None
    strict_clamp_calls = {
        _called_name(node) for node in ast.walk(strict_clamp) if isinstance(node, ast.Call)
    }
    assert "_sample_profile_activity_gap" in strict_clamp_calls
    assert private_temporal_calls.isdisjoint(strict_clamp_calls)
    assert "compatibility_default" not in strict_clamp_calls
    profile_gap_calls = [
        node
        for node in ast.walk(strict_clamp)
        if isinstance(node, ast.Call) and _called_name(node) == "_sample_profile_activity_gap"
    ]
    assert len(profile_gap_calls) == 1
    profile_gap_keywords = {keyword.arg: keyword.value for keyword in profile_gap_calls[0].keywords}
    assert isinstance(profile_gap_keywords["timing_runtime"], ast.Name)
    assert profile_gap_keywords["timing_runtime"].id == "timing_runtime"
    assert isinstance(profile_gap_keywords["timing_scope"], ast.Name)
    assert profile_gap_keywords["timing_scope"].id == "timing_scope"

    compatibility_callers: set[tuple[str, str]] = set()
    for path in sorted(_GENERATION_ROOT.rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        parents = {
            child: parent for parent in ast.walk(tree) for child in ast.iter_child_nodes(parent)
        }
        for call in (node for node in ast.walk(tree) if isinstance(node, ast.Call)):
            if _called_name(call) != "sample_ssh_authentication_phase_ms_compatibility":
                continue
            current: ast.AST = call
            while current in parents and not isinstance(current, ast.FunctionDef):
                current = parents[current]
            owner = current.name if isinstance(current, ast.FunctionDef) else "<module>"
            compatibility_callers.add((path.relative_to(_GENERATION_ROOT).as_posix(), owner))
    assert compatibility_callers == set()
