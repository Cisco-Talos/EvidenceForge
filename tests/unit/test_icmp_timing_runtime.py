# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Focused contracts for runtime-owned ICMP RTT planning."""

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
from unittest.mock import MagicMock

import pytest

from evidenceforge.events.base import OccurrenceBuilder
from evidenceforge.events.dispatcher import EventDispatcher
from evidenceforge.generation.activity import generator as generator_module
from evidenceforge.generation.activity.generator import ActivityGenerator, _icmp_echo_duration
from evidenceforge.generation.source_timing import SourceTimingPlanner
from evidenceforge.generation.state_manager import StateManager
from evidenceforge.generation.timing import TimingRuntime
from evidenceforge.models.exceptions import StateError

_START = datetime(2024, 1, 15, 10, tzinfo=UTC)
_RELATIONSHIP = "activity.icmp.echo_rtt"


def _sample(
    runtime: object,
    stable_id: str,
    requested: float | None = None,
) -> float:
    """Sample without providing any usable private RNG authority."""

    return _icmp_echo_duration(  # type: ignore[arg-type]
        object(),
        requested,
        timing_runtime=runtime,  # type: ignore[arg-type]
        stable_id=stable_id,
    )


def _activity_generator(
    runtime: TimingRuntime,
) -> tuple[ActivityGenerator, list[OccurrenceBuilder]]:
    """Return a real planner entrypoint with captured canonical occurrences."""

    state_manager = StateManager()
    state_manager.set_current_time(_START)
    emitter = MagicMock()
    emitter.can_handle.side_effect = lambda event: (
        event.event_type == "connection" and event.network is not None
    )
    emitters = {"zeek_conn": emitter}
    dispatcher = EventDispatcher(
        state_manager,
        emitters,
        timing_runtime=runtime,
    )
    captured: list[OccurrenceBuilder] = []
    publish_prepared = dispatcher.publish_prepared

    def capture(prepared: object, *args: object, **kwargs: object) -> object:
        result = publish_prepared(prepared, *args, **kwargs)
        captured.append(prepared._occurrence)  # type: ignore[attr-defined]
        return result

    dispatcher.publish_prepared = capture  # type: ignore[method-assign]
    return (
        ActivityGenerator(
            state_manager,
            emitters,
            dispatcher=dispatcher,
            timing_runtime=runtime,
        ),
        captured,
    )


def test_icmp_rtt_direct_and_prepared_runtime_commit_are_identical() -> None:
    """A prepared RTT stages one audit entry and commits exactly like direct sampling."""

    direct_runtime = TimingRuntime(reference_time=_START, namespace="icmp-prepared-parity")
    direct = _sample(direct_runtime, "icmp-connection-17", requested=0.05)

    staged_runtime = TimingRuntime(reference_time=_START, namespace="icmp-prepared-parity")
    timing_owner = SourceTimingPlanner(timing_runtime=staged_runtime)
    before_digest = staged_runtime.state_digest()
    with timing_owner.prepared_planning() as preparation:
        staged = _sample(
            preparation.planning_runtime,
            "icmp-connection-17",
            requested=0.05,
        )
        assert preparation.staged_audit_operations == 1
        assert staged_runtime.state_digest() == before_digest

    with preparation.claimed_commit():
        preparation.commit_no_fail()

    assert staged == direct
    assert staged_runtime.audit.snapshot() == direct_runtime.audit.snapshot()
    assert staged_runtime.audit.snapshot().sample_counts == {_RELATIONSHIP: 1}
    assert staged_runtime.audit.snapshot().distribution_counts == {"mixture": 1}


def test_icmp_rtt_rejected_preparation_leaves_zero_audit_residue() -> None:
    """A cancelled prepared RTT cannot leak a logical timing sample."""

    runtime = TimingRuntime(reference_time=_START, namespace="icmp-prepared-cancel")
    timing_owner = SourceTimingPlanner(timing_runtime=runtime)
    before_digest = runtime.state_digest()

    with pytest.raises(RuntimeError, match="reject ICMP plan"):
        with timing_owner.prepared_planning() as preparation:
            _sample(preparation.planning_runtime, "icmp-cancelled")
            assert preparation.staged_audit_operations == 1
            raise RuntimeError("reject ICMP plan")

    assert runtime.state_digest() == before_digest
    assert runtime.audit.snapshot().sample_counts == {}


@pytest.mark.parametrize(
    ("requested", "minimum", "maximum", "must_retain"),
    (
        (None, 0.001, 0.145, None),
        (0.0009, 0.001, 0.145, None),
        (0.1501, 0.001, 0.145, None),
        (0.001, 0.001, 0.145, 0.001),
        (0.05, 0.001, 0.145, 0.05),
        (0.15, 0.001, 0.15, 0.15),
    ),
)
def test_icmp_rtt_preserves_legacy_mixture_and_requested_support(
    requested: float | None,
    minimum: float,
    maximum: float,
    must_retain: float | None,
) -> None:
    """The runtime distribution preserves fast/slow support and valid requested RTTs."""

    runtime = TimingRuntime(reference_time=_START, namespace=f"icmp-support:{requested}")
    values = tuple(
        _sample(runtime, f"icmp-support-{index}", requested=requested) for index in range(512)
    )

    assert all(minimum <= value <= maximum for value in values)
    if must_retain is None:
        assert all(minimum < value < maximum for value in values)
    else:
        assert must_retain in values
        assert any(value != must_retain for value in values)
    assert any(value < 0.045 for value in values)
    assert any(value > 0.045 for value in values)
    audit = runtime.audit.snapshot()
    assert audit.sample_counts == {_RELATIONSHIP: len(values)}
    assert audit.distribution_counts == {"mixture": len(values)}


def _worker_population(
    workers: int,
    *,
    reverse: bool,
) -> tuple[dict[str, float], dict[str, int]]:
    runtime = TimingRuntime(reference_time=_START, namespace="icmp-worker-parity")
    stable_ids = tuple(f"icmp-worker-{index}" for index in range(128))
    submitted = tuple(reversed(stable_ids)) if reverse else stable_ids

    def sample(stable_id: str) -> tuple[str, float]:
        ordinal = int(stable_id.rpartition("-")[2])
        requested = 0.05 if ordinal % 2 else None
        return stable_id, _sample(runtime, stable_id, requested=requested)

    if workers == 1:
        values = map(sample, submitted)
    else:
        with ThreadPoolExecutor(max_workers=workers) as executor:
            values = executor.map(sample, submitted)
    return dict(values), dict(runtime.audit.snapshot().sample_counts)


def test_icmp_rtt_is_order_and_worker_deterministic() -> None:
    """Stable scopes make RTT values independent of arrival and worker topology."""

    assert _worker_population(1, reverse=False) == _worker_population(8, reverse=True)


def test_icmp_rtt_is_pythonhashseed_deterministic() -> None:
    """RTT sampling does not inherit Python hash randomization."""

    script = textwrap.dedent(
        """
        import json
        from concurrent.futures import ThreadPoolExecutor
        from datetime import UTC, datetime

        from evidenceforge.generation.activity.generator import _icmp_echo_duration
        from evidenceforge.generation.timing import TimingRuntime

        start = datetime(2024, 1, 15, 10, tzinfo=UTC)
        runtime = TimingRuntime(reference_time=start, namespace="icmp-hash-parity")

        def sample(index):
            return _icmp_echo_duration(
                object(),
                0.05 if index % 2 else None,
                timing_runtime=runtime,
                stable_id=f"icmp-hash-{index}",
            )

        with ThreadPoolExecutor(max_workers=8) as executor:
            values = tuple(executor.map(sample, range(64)))
        print(json.dumps(values, separators=(",", ":")))
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
    assert len(json.loads(outputs[0])) == 64


def test_real_network_planner_commits_rtt_audit_and_nonoverlapping_intervals() -> None:
    """The prepared planner commits one RTT per accepted nonoverlapping ICMP root."""

    runtime = TimingRuntime(reference_time=_START, namespace="icmp-network-planner")
    generator, events = _activity_generator(runtime)
    for requested_size in range(64, 72):
        generator.generate_connection(
            src_ip="10.10.4.10",
            dst_ip="10.10.3.20",
            time=_START,
            proto="icmp",
            service="icmp",
            duration=None,
            orig_bytes=requested_size,
            resp_bytes=requested_size,
        )

    icmp_events = tuple(
        event for event in events if event.network is not None and event.network.protocol == "icmp"
    )
    assert len(icmp_events) == 8
    intervals = tuple(
        sorted(
            (
                event.timestamp,
                event.timestamp + timedelta(seconds=event.network.duration or 0.0),
            )
            for event in icmp_events
        )
    )
    assert all(
        previous_end < current_start
        for (_previous_start, previous_end), (current_start, _current_end) in zip(
            intervals[:-1],
            intervals[1:],
            strict=True,
        )
    )
    assert len({event.network.conn_id for event in icmp_events}) == len(icmp_events)
    audit = runtime.audit.snapshot()
    assert audit.sample_counts[_RELATIONSHIP] == len(icmp_events)


def test_icmp_rtt_requires_exact_runtime_and_stable_identity() -> None:
    """Production cannot fall back to a helper-local timing authority or RNG identity."""

    runtime = TimingRuntime(reference_time=_START, namespace="icmp-required-owner")
    with pytest.raises(StateError, match="injected TimingRuntime"):
        _icmp_echo_duration(object(), None, stable_id="icmp-owner")  # type: ignore[arg-type]
    with pytest.raises(StateError, match="stable connection identity"):
        _icmp_echo_duration(  # type: ignore[arg-type]
            object(),
            None,
            timing_runtime=runtime,
        )
    assert runtime.audit.snapshot().sample_counts == {}


def test_icmp_rtt_rejects_foreign_runtime_carriers_before_sampler_dispatch() -> None:
    """Only exact engine runtime owners may reach timing sampler dispatch."""

    owner = TimingRuntime(reference_time=_START, namespace="icmp-foreign-owner")

    class ForeignRuntimeWrapper:
        def __init__(self, wrapped: TimingRuntime) -> None:
            self.sampler = wrapped.sampler

    class HostileSamplerCarrier:
        @property
        def sampler(self) -> object:
            raise AssertionError("foreign sampler descriptor must not be resolved")

    class TimingRuntimeSubclass(TimingRuntime):
        pass

    foreign_runtimes = (
        ForeignRuntimeWrapper(owner),
        HostileSamplerCarrier(),
        TimingRuntimeSubclass(reference_time=_START, namespace="icmp-runtime-subclass"),
    )
    for foreign_runtime in foreign_runtimes:
        with pytest.raises(StateError, match="injected TimingRuntime"):
            _sample(foreign_runtime, "icmp-foreign-runtime")

    assert owner.audit.snapshot().sample_counts == {}


def test_icmp_rtt_rejects_noncanonical_identity_before_dynamic_coercion() -> None:
    """Stable connection identity must be an exact nonempty string."""

    runtime = TimingRuntime(reference_time=_START, namespace="icmp-invalid-identity")

    class HostileIdentity:
        def __bool__(self) -> bool:
            raise AssertionError("foreign identity truthiness must not be evaluated")

        def __str__(self) -> str:
            raise AssertionError("foreign identity coercion must not be evaluated")

    class StringSubclass(str):
        pass

    invalid_identities = (None, 7, b"icmp", HostileIdentity(), StringSubclass("icmp"), "")
    for invalid_identity in invalid_identities:
        with pytest.raises(StateError, match="stable connection identity"):
            _icmp_echo_duration(  # type: ignore[arg-type]
                object(),
                None,
                timing_runtime=runtime,
                stable_id=invalid_identity,
            )

    assert runtime.audit.snapshot().sample_counts == {}


def test_icmp_rtt_helper_and_planner_have_no_private_rng_or_identity_fallback() -> None:
    """AST ownership prevents a forwarding-only seam from masking private RNG timing."""

    helper_tree = ast.parse(textwrap.dedent(inspect.getsource(_icmp_echo_duration)))
    forbidden_rng_methods = {
        "choice",
        "choices",
        "random",
        "randint",
        "randrange",
        "triangular",
        "uniform",
    }
    assert not any(
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and isinstance(node.func.value, ast.Name)
        and node.func.value.id == "rng"
        and node.func.attr in forbidden_rng_methods
        for node in ast.walk(helper_tree)
    )

    planner_path = Path(inspect.getsourcefile(generator_module) or "").parents[1]
    planner_path /= "actions/network_transaction_planner.py"
    planner_tree = ast.parse(planner_path.read_text(encoding="utf-8"), filename=str(planner_path))
    calls = [
        node
        for node in ast.walk(planner_tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "_icmp_echo_duration"
    ]
    assert len(calls) == 2
    for call in calls:
        keywords = {keyword.arg: ast.unparse(keyword.value) for keyword in call.keywords}
        assert keywords["timing_runtime"] == "self._timing_runtime"
        assert "stable_id" in keywords["stable_id"]
        assert "request.stable_id" not in keywords["stable_id"]
        assert "conn_id" in keywords["stable_id"]
