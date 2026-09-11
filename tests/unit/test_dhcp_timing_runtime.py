# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Focused contracts for runtime-owned DHCP renewal timing."""

from __future__ import annotations

import ast
import inspect
import json
import os
import subprocess
import sys
import textwrap
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace

import pytest

from evidenceforge.generation.actions.dhcp_lease import dhcp_renewal_interval_seconds
from evidenceforge.generation.engine.baseline import BaselineMixin, _dhcp_renewal_epochs_for_hour
from evidenceforge.generation.engine.emitter_setup import EmitterSetupMixin
from evidenceforge.generation.engine.storyline import StorylineMixin
from evidenceforge.generation.source_timing import SourceTimingPlanner
from evidenceforge.generation.timing import TimingRuntime
from evidenceforge.models.exceptions import StateError
from evidenceforge.models.scenario import DhcpLeaseEventSpec, System, User

_START = datetime(2024, 3, 15, 12, tzinfo=UTC)
_RELATIONSHIPS = {
    "dhcp.lease.renewal.scheduling_drift_seconds",
    "dhcp.lease.renewal.wakeup_backoff_seconds",
    "dhcp.lease.renewal.scheduler_latency_seconds",
    "dhcp.lease.renewal.timer_quantization_jitter_seconds",
}
_PROJECT_ROOT = Path(__file__).parents[2]


def _sample(
    runtime: TimingRuntime,
    sequence: int,
    *,
    lease_time: float = 3600.0,
    timer_granularity: float = 1.0,
) -> float:
    """Sample one semantic lease renewal without a private RNG authority."""

    return dhcp_renewal_interval_seconds(
        lease_time,
        timing_runtime=runtime,
        stable_id="WS-DHCP-01|00:50:56:ab:cd:ef",
        host="WS-DHCP-01",
        renewal_sequence=sequence,
        timer_granularity=timer_granularity,
    )


def _emitter_setup_interval(runtime: TimingRuntime) -> tuple[float, dict[str, object]]:
    """Run the production initial-lease caller with a minimal exact owner graph."""

    client = System(
        hostname="WS-DHCP-01",
        ip="10.0.10.25",
        os="Windows 11",
        type="workstation",
    )
    server = System(
        hostname="DHCP-01",
        ip="10.0.0.10",
        os="Windows Server 2022",
        type="server",
    )

    class World:
        dhcp_servers = (server,)

        @staticmethod
        def systems_with_capability(*_args: object, **_kwargs: object) -> list[System]:
            return [server]

    class Activity:
        def __init__(self) -> None:
            self.timing_runtime = runtime
            self.calls: list[dict[str, object]] = []

        def generate_dhcp_lease(self, **kwargs: object) -> None:
            self.calls.append(kwargs)

    harness = EmitterSetupMixin()
    harness.scenario = SimpleNamespace(
        environment=SimpleNamespace(systems=[client]),
        storyline=[],
    )
    harness.world_model = World()
    harness.start_time = _START
    harness.warmup_start_time = _START
    harness.timing_runtime = runtime
    harness.state_manager = SimpleNamespace(set_current_time=lambda _time: None)
    harness.activity_generator = Activity()

    harness._emit_dhcp_leases()

    state = harness._dhcp_lease_state[client.hostname]
    return float(state["renewal_interval"]), state


def test_initial_caller_direct_and_prepared_timing_commit_are_identical() -> None:
    """The production caller stages four samples and commits exact direct parity."""

    direct_runtime = TimingRuntime(reference_time=_START, namespace="dhcp-caller-parity")
    direct_interval, direct_state = _emitter_setup_interval(direct_runtime)

    staged_runtime = TimingRuntime(reference_time=_START, namespace="dhcp-caller-parity")
    timing_owner = SourceTimingPlanner(timing_runtime=staged_runtime)
    before_digest = staged_runtime.state_digest()
    with timing_owner.prepared_planning() as preparation:
        staged_interval, staged_state = _emitter_setup_interval(staged_runtime)
        assert preparation.staged_audit_operations == 4
        assert staged_runtime.state_digest() == before_digest

    with preparation.claimed_commit():
        preparation.commit_no_fail()

    assert staged_interval == direct_interval
    assert staged_state["lease_time"] == direct_state["lease_time"]
    assert staged_state["timer_granularity"] == direct_state["timer_granularity"]
    assert staged_state["renewal_sequence"] == direct_state["renewal_sequence"] == 1
    assert staged_runtime.audit.snapshot() == direct_runtime.audit.snapshot()
    assert staged_runtime.audit.snapshot().sample_counts == {
        relationship: 1 for relationship in _RELATIONSHIPS
    }


def test_dhcp_reject_and_cancel_leave_zero_audit_residue() -> None:
    """Malformed identities and a rejected preparation cannot publish timing audit state."""

    runtime = TimingRuntime(reference_time=_START, namespace="dhcp-cancel-neutral")
    before_digest = runtime.state_digest()
    with pytest.raises(StateError, match="stable lease identity"):
        dhcp_renewal_interval_seconds(
            3600.0,
            timing_runtime=runtime,
            stable_id="",
            host="WS-DHCP-01",
            renewal_sequence=0,
        )
    assert runtime.state_digest() == before_digest

    class ForeignRuntime:
        sampler = runtime.sampler

    with pytest.raises(StateError, match="exact engine TimingRuntime"):
        dhcp_renewal_interval_seconds(
            3600.0,
            timing_runtime=ForeignRuntime(),  # type: ignore[arg-type]
            stable_id="WS-DHCP-01|00:50:56:ab:cd:ef",
            host="WS-DHCP-01",
            renewal_sequence=0,
        )
    assert runtime.state_digest() == before_digest

    timing_owner = SourceTimingPlanner(timing_runtime=runtime)
    with pytest.raises(RuntimeError, match="reject DHCP interval"):
        with timing_owner.prepared_planning() as preparation:
            _sample(runtime, 0)
            assert preparation.staged_audit_operations == 4
            raise RuntimeError("reject DHCP interval")

    assert runtime.state_digest() == before_digest
    assert runtime.audit.snapshot().sample_counts == {}


def test_dhcp_lost_return_retry_replays_one_canonical_sample_set() -> None:
    """A cancelled lost return retries the same values with one canonical audit set."""

    runtime = TimingRuntime(reference_time=_START, namespace="dhcp-lost-return")
    timing_owner = SourceTimingPlanner(timing_runtime=runtime)
    lost_return = 0.0
    with pytest.raises(RuntimeError, match="lose DHCP return"):
        with timing_owner.prepared_planning():
            lost_return = _sample(runtime, 17)
            raise RuntimeError("lose DHCP return")

    with timing_owner.prepared_planning() as retry_preparation:
        retry = _sample(runtime, 17)
    with retry_preparation.claimed_commit():
        retry_preparation.commit_no_fail()

    assert retry == lost_return
    assert runtime.audit.snapshot().sample_counts == {
        relationship: 1 for relationship in _RELATIONSHIPS
    }


def test_dhcp_renewal_values_keep_schedule_bounds_and_order() -> None:
    """Every sampled client timer remains ordered near T1 across catch-up cycles."""

    runtime = TimingRuntime(reference_time=_START, namespace="dhcp-schedule-bounds")
    intervals = tuple(_sample(runtime, index, timer_granularity=5.0) for index in range(16))

    assert all(1745.0 <= interval < 2186.0 for interval in intervals)
    assert len({round(interval, 6) for interval in intervals}) >= 12
    interval_iter = iter(intervals[1:])
    current_hour = datetime(2024, 3, 15, 13, tzinfo=UTC)
    due, _updated_last, pending_next = _dhcp_renewal_epochs_for_hour(
        last_renewal=datetime(2024, 3, 15, 12, 40, tzinfo=UTC).timestamp(),
        renewal_interval=intervals[0],
        current_hour=current_hour,
        renewal_interval_factory=lambda: next(interval_iter),
    )
    epochs = [epoch for epoch, _interval in due]
    assert epochs == sorted(epochs)
    assert all(current_hour.timestamp() <= epoch for epoch in epochs)
    assert all(epoch < (current_hour + timedelta(hours=1)).timestamp() for epoch in epochs)
    assert pending_next is not None
    assert pending_next >= (current_hour + timedelta(hours=1)).timestamp()


def _worker_population(
    workers: int,
    *,
    reverse: bool,
) -> tuple[dict[int, float], dict[str, int]]:
    """Return one renewal population under a selected worker topology."""

    runtime = TimingRuntime(reference_time=_START, namespace="dhcp-worker-parity")
    sequences = tuple(range(64))
    submitted = tuple(reversed(sequences)) if reverse else sequences

    def sample(sequence: int) -> tuple[int, float]:
        return sequence, _sample(runtime, sequence, timer_granularity=5.0)

    if workers == 1:
        values = map(sample, submitted)
    else:
        with ThreadPoolExecutor(max_workers=workers) as executor:
            values = executor.map(sample, submitted)
    return dict(values), dict(runtime.audit.snapshot().sample_counts)


def test_dhcp_timing_is_order_and_worker_deterministic() -> None:
    """Stable renewal ordinals make timing independent of worker arrival order."""

    single = _worker_population(1, reverse=False)
    parallel = _worker_population(8, reverse=True)
    assert single == parallel
    assert single[1] == {relationship: 64 for relationship in _RELATIONSHIPS}


def test_dhcp_timing_is_pythonhashseed_deterministic() -> None:
    """Renewal timing cannot inherit interpreter hash randomization."""

    script = textwrap.dedent(
        """
        import json
        from tests.unit.test_dhcp_timing_runtime import _worker_population

        values, audit = _worker_population(8, reverse=True)
        print(json.dumps([values, audit], sort_keys=True, separators=(",", ":")))
        """
    )
    outputs: list[str] = []
    for hash_seed in ("1", "8675309"):
        environment = dict(os.environ)
        environment["PYTHONHASHSEED"] = hash_seed
        environment["PYTHONPATH"] = str(_PROJECT_ROOT / "src")
        result = subprocess.run(
            [sys.executable, "-c", script],
            cwd=_PROJECT_ROOT,
            env=environment,
            check=True,
            capture_output=True,
            text=True,
        )
        outputs.append(result.stdout.strip())

    assert outputs[0] == outputs[1]
    values, audit = json.loads(outputs[0])
    assert len(values) == 64
    assert set(audit) == _RELATIONSHIPS


def test_three_production_callers_never_enter_compatibility_runtime(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Every initialized engine caller supplies its exact runtime owner."""

    def reject_compatibility(_cls: type[TimingRuntime]) -> TimingRuntime:
        raise AssertionError("production caller entered DHCP compatibility timing")

    monkeypatch.setattr(
        TimingRuntime,
        "compatibility_default",
        classmethod(reject_compatibility),
    )

    emitter_runtime = TimingRuntime(reference_time=_START, namespace="dhcp-emitter-owner")
    _emitter_setup_interval(emitter_runtime)
    assert emitter_runtime.audit.snapshot().total_samples == 4

    client = System(
        hostname="WS-DHCP-01",
        ip="10.0.10.25",
        os="Windows 11",
        type="workstation",
    )
    current_hour = _START + timedelta(hours=1)

    class BaselineActivity:
        @staticmethod
        def generate_dhcp_lease(**_kwargs: object) -> None:
            raise RuntimeError("baseline DHCP caller reached publication")

    baseline = BaselineMixin()
    baseline.timing_runtime = TimingRuntime(
        reference_time=_START,
        namespace="dhcp-baseline-owner",
    )
    baseline.scenario = SimpleNamespace(environment=SimpleNamespace(systems=[client]))
    baseline._uses_linux_smb_prepass = lambda: False
    baseline._infra_ips = {"dns": [], "ntp": []}
    baseline._system_service_defaults = {client.hostname: []}
    baseline._system_pids = {client.hostname: {}}
    baseline._generation_epoch = _START
    baseline._storyline_dhcp_lease_time_in_hour = lambda _hostname, _hour: None
    baseline._dhcp_lease_state = {
        client.hostname: {
            "mac": "00:50:56:ab:cd:ef",
            "lease_time": 3600.0,
            "last_renewal": (_START + timedelta(minutes=50)).timestamp(),
            "next_renewal": (_START + timedelta(hours=1, minutes=20)).timestamp(),
            "renewal_interval": 1800.0,
            "renewal_sequence": 1,
            "timer_granularity": 1.0,
            "server_addr": "10.0.0.10",
            "system": client,
        }
    }
    baseline.state_manager = SimpleNamespace(set_current_time=lambda _time: None)
    baseline.activity_generator = BaselineActivity()
    with pytest.raises(RuntimeError, match="baseline DHCP caller reached publication"):
        baseline._generate_system_traffic(current_hour)
    assert baseline.timing_runtime.audit.snapshot().total_samples >= 4

    server = System(
        hostname="DHCP-01",
        ip="10.0.0.10",
        os="Windows Server 2022",
        type="server",
    )

    class StorylineActivity:
        def __init__(self) -> None:
            self.calls: list[dict[str, object]] = []

        def generate_dhcp_lease(self, **kwargs: object) -> None:
            self.calls.append(kwargs)

    storyline = StorylineMixin()
    storyline.timing_runtime = TimingRuntime(
        reference_time=_START,
        namespace="dhcp-storyline-owner",
    )
    storyline.world_model = SimpleNamespace(
        systems_with_capability=lambda _capability, distinct_from: (
            [server] if distinct_from is client else []
        )
    )
    storyline.activity_generator = StorylineActivity()
    storyline.dispatcher = SimpleNamespace(visibility_engine=None)
    storyline._dhcp_lease_state = {}
    storyline._execute_typed_event(
        spec=DhcpLeaseEventSpec(),
        actor=User(
            username="analyst",
            full_name="Security Analyst",
            email="analyst@example.com",
        ),
        system=client,
        time=current_hour,
        activity="acquire lease",
        explicit_types={"dhcp_lease"},
    )
    assert len(storyline.activity_generator.calls) == 1
    assert storyline.timing_runtime.audit.snapshot().total_samples == 4


def test_dhcp_helper_and_three_callers_have_exact_runtime_wiring() -> None:
    """The helper has no RNG seam and every production caller supplies semantic ownership."""

    signature = inspect.signature(dhcp_renewal_interval_seconds)
    assert "rng" not in signature.parameters
    helper = ast.parse(inspect.getsource(dhcp_renewal_interval_seconds))
    helper_calls = {
        call.func.attr
        for call in ast.walk(helper)
        if isinstance(call, ast.Call) and isinstance(call.func, ast.Attribute)
    }
    assert not helper_calls.intersection({"random", "triangular", "uniform"})

    generation_root = _PROJECT_ROOT / "src" / "evidenceforge" / "generation"
    expected = {
        "engine/emitter_setup.py": 1,
        "engine/baseline.py": 1,
        "engine/storyline.py": 1,
    }
    for relative, count in expected.items():
        tree = ast.parse((generation_root / relative).read_text(encoding="utf-8"))
        calls = [
            call
            for call in ast.walk(tree)
            if isinstance(call, ast.Call)
            and isinstance(call.func, ast.Name)
            and call.func.id == "dhcp_renewal_interval_seconds"
        ]
        assert len(calls) == count
        for call in calls:
            assert {keyword.arg for keyword in call.keywords} >= {
                "timing_runtime",
                "stable_id",
                "host",
                "renewal_sequence",
            }
