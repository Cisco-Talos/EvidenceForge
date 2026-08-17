# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Runtime timing contracts for WorldPlanner RDP source-process placement."""

from __future__ import annotations

import ast
import json
import os
import random
import subprocess
import sys
import textwrap
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from evidenceforge.generation.timing import TimingRuntime
from evidenceforge.generation.world_model import SessionPlan, WorldPlanner
from evidenceforge.models.scenario import System, User

_LOGON_TIME = datetime(2024, 1, 15, 10, tzinfo=UTC)
_RELATIONSHIP = "world.rdp.source_process_create_lead"


def _user() -> User:
    return User(username="analyst", full_name="Alicia Analyst", email="a@example.test")


def _windows(hostname: str, ip: str, *, system_type: str = "workstation") -> System:
    return System(hostname=hostname, ip=ip, os="Windows 11", type=system_type)


def _plan(*, with_source: bool = True) -> SessionPlan:
    return SessionPlan(
        target_system=_windows("APP-01", "10.0.0.30", system_type="server"),
        source_system=_windows("WS-01", "10.0.0.10") if with_source else None,
        source_ip="10.0.0.10" if with_source else "198.51.100.14",
        logon_type=10,
        session_kind="rdp",
        requires_transport=True,
    )


class _StateFixture:
    """Minimal state surface used by the real RDP bootstrap method."""

    def __init__(self) -> None:
        self.session = SimpleNamespace(last_activity_time=None)

    def get_session(self, logon_id: str) -> SimpleNamespace | None:
        return self.session if logon_id == "rdp-logon" else None

    @staticmethod
    def get_sessions_for_user(_username: str) -> list[Any]:
        return []


class _ActivityFixture:
    """Record the canonical bundle request while exposing one engine runtime."""

    def __init__(self, runtime: TimingRuntime) -> None:
        self.timing_runtime = runtime
        self.requests: list[dict[str, Any]] = []

    def _execute_rdp_session_bundle(self, **kwargs: Any) -> tuple[str, str]:
        self.requests.append(kwargs)
        return "rdp-uid", "rdp-logon"


def _planner(runtime: TimingRuntime) -> tuple[WorldPlanner, _StateFixture, _ActivityFixture]:
    state = _StateFixture()
    activity = _ActivityFixture(runtime)
    planner = WorldPlanner(
        SimpleNamespace(hosts={}),  # type: ignore[arg-type]
        state,  # type: ignore[arg-type]
        activity,  # type: ignore[arg-type]
    )
    return planner, state, activity


def test_rdp_source_process_placement_uses_engine_runtime_and_preserves_bounds() -> None:
    """The source process precedes target logon within the former inclusive support."""

    runtime = TimingRuntime(reference_time=_LOGON_TIME, namespace="rdp-source-placement")
    planner, state, activity = _planner(runtime)
    rng = random.Random(19)
    rng_state = rng.getstate()

    result = planner._bootstrap_rdp_session(
        _user(),
        _plan(),
        _LOGON_TIME,
        _LOGON_TIME + timedelta(seconds=8),
        rng,
    )

    request = activity.requests[0]
    source_process_time = request["source_process_time"]
    assert planner._timing_planner("rdp-bootstrap").runtime is runtime
    assert isinstance(source_process_time, datetime)
    assert _LOGON_TIME - timedelta(seconds=3.2) <= source_process_time
    assert source_process_time <= _LOGON_TIME - timedelta(seconds=1.8)
    assert source_process_time < request["time"]
    assert result.session is state.session
    assert state.session.last_activity_time == _LOGON_TIME + timedelta(seconds=8)
    assert rng.getstate() == rng_state
    audit = runtime.audit.snapshot()
    assert audit.sample_counts == {_RELATIONSHIP: 1}
    assert audit.distribution_counts == {"triangular": 1}


def test_unmodeled_rdp_source_has_no_timing_planner_or_audit_phantom(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """External RDP sources do not invent source process placement work."""

    runtime = TimingRuntime(reference_time=_LOGON_TIME, namespace="rdp-no-source")
    planner, _state, activity = _planner(runtime)

    def reject_planner(_source: str = "world-planner") -> Any:
        raise AssertionError("unmodeled RDP source constructed a timing planner")

    monkeypatch.setattr(planner, "_timing_planner", reject_planner)
    rng = random.Random(23)
    rng_state = rng.getstate()
    planner._bootstrap_rdp_session(
        _user(),
        _plan(with_source=False),
        _LOGON_TIME,
        _LOGON_TIME + timedelta(seconds=8),
        rng,
    )

    assert activity.requests[0]["source_process_time"] is None
    assert rng.getstate() == rng_state
    assert runtime.audit.snapshot().total_samples == 0


def _worker_population(workers: int, reverse: bool) -> tuple[dict[int, str], dict[str, int]]:
    runtime = TimingRuntime(reference_time=_LOGON_TIME, namespace="rdp-source-workers")
    planner, _state, _activity = _planner(runtime)
    plan = _plan()
    indices = list(range(128))
    if reverse:
        indices.reverse()

    def sample(index: int) -> tuple[int, str]:
        logon_time = _LOGON_TIME + timedelta(microseconds=index * 101)
        result = planner._rdp_source_process_time(
            user=_user(),
            plan=plan,
            logon_time=logon_time,
        )
        assert result is not None
        return index, result.isoformat()

    if workers == 1:
        values = tuple(sample(index) for index in indices)
    else:
        with ThreadPoolExecutor(max_workers=workers) as executor:
            values = tuple(executor.map(sample, indices))
    return dict(values), dict(runtime.audit.snapshot().sample_counts)


def test_rdp_source_process_placement_is_order_and_worker_deterministic() -> None:
    """Stable scopes produce identical placement under reordered parallel work."""

    assert _worker_population(1, False) == _worker_population(8, True)


def test_rdp_source_process_placement_is_pythonhashseed_deterministic() -> None:
    """The production WorldPlanner path does not inherit Python hash randomization."""

    script = textwrap.dedent(
        """
        import json
        from concurrent.futures import ThreadPoolExecutor
        from datetime import UTC, datetime, timedelta
        from types import SimpleNamespace

        from evidenceforge.generation.timing import TimingRuntime
        from evidenceforge.generation.world_model import SessionPlan, WorldPlanner
        from evidenceforge.models.scenario import System, User

        start = datetime(2024, 1, 15, 10, tzinfo=UTC)
        runtime = TimingRuntime(reference_time=start, namespace="rdp-source-hash-seed")
        planner = WorldPlanner(
            SimpleNamespace(),
            SimpleNamespace(),
            SimpleNamespace(timing_runtime=runtime),
        )
        user = User(username="analyst", full_name="Alicia Analyst", email="a@example.test")
        source = System(hostname="WS-01", ip="10.0.0.10", os="Windows 11", type="workstation")
        target = System(hostname="APP-01", ip="10.0.0.30", os="Windows 11", type="server")
        plan = SessionPlan(
            target_system=target,
            source_system=source,
            source_ip=source.ip,
            logon_type=10,
            session_kind="rdp",
            requires_transport=True,
        )

        def sample(index):
            value = planner._rdp_source_process_time(
                user=user,
                plan=plan,
                logon_time=start + timedelta(microseconds=index * 101),
            )
            return index, value.isoformat()

        with ThreadPoolExecutor(max_workers=8) as executor:
            values = dict(executor.map(sample, reversed(range(64))))
        print(json.dumps(values, sort_keys=True, separators=(",", ":")))
        """
    )
    project_root = Path(__file__).resolve().parents[2]
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


def test_rdp_bootstrap_has_no_legacy_temporal_rng_draw() -> None:
    """The exact residual randint is absent from the RDP bootstrap source."""

    module_path = Path(sys.modules[WorldPlanner.__module__].__file__ or "")
    tree = ast.parse(module_path.read_text(encoding="utf-8"))
    bootstrap = next(
        node
        for node in ast.walk(tree)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        and node.name == "_bootstrap_rdp_session"
    )
    assert not any(
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "randint"
        for node in ast.walk(bootstrap)
    )
