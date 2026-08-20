# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Focused contracts for runtime-owned Linux pipeline stage timing."""

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
from unittest.mock import Mock

import pytest

from evidenceforge.generation.actions.linux_shell_command import (
    plan_linux_pipeline_stage_times,
)
from evidenceforge.generation.activity.generator import ActivityGenerator
from evidenceforge.generation.source_timing import SourceTimingPlanner
from evidenceforge.generation.timing import TimingRuntime
from evidenceforge.models import System, User
from evidenceforge.models.exceptions import StateError

_START = datetime(2024, 3, 15, 12, tzinfo=UTC)
_RELATIONSHIP = "linux.pipeline_stage_start"
_PROJECT_ROOT = Path(__file__).parents[2]


def _plan(
    runtime: object,
    ordinal: int,
    *,
    stage_count: int = 4,
    active_process_count: int = 8,
) -> tuple[datetime, ...]:
    """Plan one semantically distinct pipeline through an injected runtime."""

    return plan_linux_pipeline_stage_times(
        _START,
        stage_count=stage_count,
        scope_parts=(
            f"LNX-{ordinal:03d}",
            "alice",
            "0xabc",
            f"pipeline-{ordinal}",
        ),
        active_process_count=active_process_count,
        timing_runtime=runtime,  # type: ignore[arg-type]
    )


class _PipelineState:
    """Minimal public-caller state view for one shell pipeline."""

    def __init__(self, session: SimpleNamespace) -> None:
        self._session = session
        self._processes: dict[tuple[str, int], SimpleNamespace] = {}

    def get_sessions_for_user(self, _username: str) -> list[SimpleNamespace]:
        """Return the exact modeled shell session."""

        return [self._session]

    def get_processes_on_system(self, hostname: str) -> list[SimpleNamespace]:
        """Return a stable host-load cohort plus newly created children."""

        placeholders = [SimpleNamespace(pid=index) for index in range(8)]
        created = [
            process
            for (process_hostname, _pid), process in self._processes.items()
            if process_hostname == hostname
        ]
        return [*placeholders, *created]

    def get_process(self, hostname: str, pid: int) -> SimpleNamespace | None:
        """Return one newly created child process."""

        return self._processes.get((hostname, pid))

    def remember_process(self, hostname: str, pid: int, started_at: datetime) -> None:
        """Retain the public start time consumed by the caller."""

        self._processes[(hostname, pid)] = SimpleNamespace(start_time=started_at)


def _public_pipeline_signature(runtime: TimingRuntime) -> tuple[object, ...]:
    """Execute the public shell-command caller and return its canonical payload signature."""

    user = User(
        username="alice",
        full_name="Alice Example",
        email="alice@example.test",
    )
    system = System(
        hostname="LNX-PIPE-01",
        ip="10.0.0.25",
        os="Ubuntu 22.04",
        type="server",
    )
    session = SimpleNamespace(
        system=system.hostname,
        start_time=_START - timedelta(minutes=5),
        logon_id="0xabc",
        session_shell_pid=101,
        network_close_time=None,
    )
    state = _PipelineState(session)
    generator = ActivityGenerator.__new__(ActivityGenerator)
    generator.timing_runtime = runtime
    generator.state_manager = state
    generator._resolve_bash_command = Mock(side_effect=lambda _user, _system, command: command)
    generator._should_skip_bash_history = Mock(return_value=False)
    generator._prepare_bash_history_command = Mock(side_effect=lambda _system, command: command)
    generator._schedule_bash_history_time = Mock(
        side_effect=lambda _user, _system, requested_at, _command: requested_at
    )
    generator._is_within_scenario_window = Mock(return_value=True)
    generator._prepare_bash_process_session = Mock()
    generator._emit_bash_command_event = Mock()
    generator._is_pid_active_at = Mock(return_value=True)
    generator._reserve_foreground_shell_time = Mock(
        side_effect=lambda **kwargs: kwargs["requested_time"]
    )
    generator._record_user_process = Mock()
    generator._generate_bounded_foreground_process_termination = Mock(
        side_effect=lambda **kwargs: kwargs["start_time"] + timedelta(milliseconds=250)
    )
    generator._remember_foreground_shell_available = Mock()

    next_pid = iter((201, 202))

    def generate_process(**kwargs: object) -> int:
        pid = next(next_pid)
        started_at = kwargs["time"]
        assert isinstance(started_at, datetime)
        state.remember_process(system.hostname, pid, started_at)
        return pid

    generator.generate_process = Mock(side_effect=generate_process)

    scheduled_at = generator.generate_bash_command(
        user,
        system,
        _START,
        "cat /etc/passwd | head -5",
    )
    process_payload = tuple(
        (
            call.kwargs["process_name"],
            call.kwargs["command_line"],
            call.kwargs["time"].isoformat(),
            call.kwargs["parent_pid"],
            call.kwargs["concurrency_group_id"],
        )
        for call in generator.generate_process.call_args_list
    )
    history_call = generator._emit_bash_command_event.call_args
    return (
        scheduled_at.isoformat() if scheduled_at is not None else None,
        history_call.args[2].isoformat(),
        history_call.args[3],
        process_payload,
    )


def test_public_pipeline_direct_and_prepared_commit_are_identical() -> None:
    """The public caller uses the active staged runtime and preserves complete payload parity."""

    direct_runtime = TimingRuntime(reference_time=_START, namespace="linux-pipeline-parity")
    direct_signature = _public_pipeline_signature(direct_runtime)

    staged_runtime = TimingRuntime(reference_time=_START, namespace="linux-pipeline-parity")
    owner = SourceTimingPlanner(timing_runtime=staged_runtime)
    before_digest = staged_runtime.state_digest()
    with owner.prepared_planning() as preparation:
        staged_signature = _public_pipeline_signature(staged_runtime)
        assert preparation.staged_audit_operations == 1
        assert staged_runtime.state_digest() == before_digest

    with preparation.claimed_commit():
        preparation.commit_no_fail()

    assert staged_signature == direct_signature
    assert direct_signature[:3] == (
        "2024-03-15T12:00:00+00:00",
        "2024-03-15T12:00:00+00:00",
        "cat /etc/passwd | head -5",
    )
    process_payload = direct_signature[3]
    assert isinstance(process_payload, tuple)
    assert tuple(
        (image, command_line, parent_pid, concurrency_group_id)
        for image, command_line, _timestamp, parent_pid, concurrency_group_id in process_payload
    ) == (
        (
            "/usr/bin/cat",
            "cat /etc/passwd",
            101,
            "bash-history:00000000ec19af4c",
        ),
        (
            "/usr/bin/head",
            "head -5",
            101,
            "bash-history:00000000ec19af4c",
        ),
    )
    assert process_payload[0][2] == "2024-03-15T12:00:00.058000+00:00"
    assert staged_runtime.audit.snapshot() == direct_runtime.audit.snapshot()
    assert staged_runtime.audit.snapshot().sample_counts == {_RELATIONSHIP: 1}


def test_pipeline_reject_cancel_and_lost_return_retry_are_neutral() -> None:
    """Rejected inputs and a lost prepared return leave one exact retry sample set."""

    runtime = TimingRuntime(reference_time=_START, namespace="linux-pipeline-retry")
    before_digest = runtime.state_digest()

    class ForeignRuntime:
        sampler = runtime.sampler

    with pytest.raises(StateError, match="exact engine TimingRuntime"):
        _plan(ForeignRuntime(), 1)
    with pytest.raises(StateError, match="at most four stages"):
        _plan(runtime, 1, stage_count=5)
    assert runtime.state_digest() == before_digest

    owner = SourceTimingPlanner(timing_runtime=runtime)
    lost_return: tuple[datetime, ...] = ()
    with pytest.raises(RuntimeError, match="lose pipeline return"):
        with owner.prepared_planning() as preparation:
            lost_return = _plan(runtime, 17)
            assert preparation.staged_audit_operations == 3
            raise RuntimeError("lose pipeline return")

    assert runtime.state_digest() == before_digest
    with owner.prepared_planning() as retry_preparation:
        retry = _plan(runtime, 17)
    with retry_preparation.claimed_commit():
        retry_preparation.commit_no_fail()

    assert retry == lost_return
    assert runtime.audit.snapshot().sample_counts == {_RELATIONSHIP: 3}


def test_pipeline_stage_timing_is_bounded_varied_and_load_sensitive() -> None:
    """Runtime sampling retains ordered microsecond texture and load-sensitive support."""

    runtime = TimingRuntime(reference_time=_START, namespace="linux-pipeline-distribution")
    gaps = []
    for ordinal in range(128):
        times = _plan(
            runtime,
            ordinal,
            stage_count=2,
            active_process_count=ordinal % 32,
        )
        gaps.append(times[1] - times[0])

    assert min(gaps) >= timedelta(milliseconds=6)
    assert max(gaps) <= timedelta(milliseconds=115)
    assert len(set(gaps)) > 110
    rounded_ms = [round(gap.total_seconds() * 1_000) for gap in gaps]
    assert max(rounded_ms.count(value) for value in set(rounded_ms)) < 8

    idle_runtime = TimingRuntime(reference_time=_START, namespace="linux-pipeline-pressure")
    busy_runtime = TimingRuntime(reference_time=_START, namespace="linux-pipeline-pressure")
    idle = _plan(idle_runtime, 999, stage_count=2, active_process_count=0)
    busy = _plan(busy_runtime, 999, stage_count=2, active_process_count=96)
    assert busy[1] - busy[0] > idle[1] - idle[0]


def test_pipeline_fixed_window_uses_one_audited_constant_per_gap(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An equal configured window remains valid without restoring a private sampler."""

    monkeypatch.setattr(
        "evidenceforge.generation.actions.linux_shell_command.get_timing_window",
        lambda *_args, **_kwargs: SimpleNamespace(min_ms=17, max_ms=17),
    )
    runtime = TimingRuntime(reference_time=_START, namespace="linux-pipeline-fixed-window")

    planned = _plan(runtime, 7)

    assert [
        current - previous for previous, current in zip(planned, planned[1:], strict=False)
    ] == [timedelta(milliseconds=17)] * 3
    audit = runtime.audit.snapshot()
    assert audit.sample_counts == {_RELATIONSHIP: 3}
    assert audit.distribution_counts == {"constant": 3}


def test_pipeline_audit_cardinality_stays_bounded_by_one_relationship() -> None:
    """Many semantic pipelines retain one bounded audit slot and no per-scope cache."""

    runtime = TimingRuntime(reference_time=_START, namespace="linux-pipeline-bounded-audit")
    for ordinal in range(512):
        _plan(runtime, ordinal)

    census = runtime.census(estimate_bytes=True)
    assert census.audit.relationship_slots_live == 1
    assert census.audit.distribution_keys_live == 1
    assert census.audit.sample_count == 512 * 3
    assert census.clocks.live_entries == 0


def _worker_population(
    workers: int,
    *,
    reverse: bool,
) -> tuple[dict[int, tuple[str, ...]], dict[str, int]]:
    """Return one pipeline population under a selected worker topology."""

    runtime = TimingRuntime(reference_time=_START, namespace="linux-pipeline-workers")
    ordinals = tuple(range(64))
    submitted = tuple(reversed(ordinals)) if reverse else ordinals

    def sample(ordinal: int) -> tuple[int, tuple[str, ...]]:
        return ordinal, tuple(value.isoformat() for value in _plan(runtime, ordinal))

    if workers == 1:
        values = map(sample, submitted)
    else:
        with ThreadPoolExecutor(max_workers=workers) as executor:
            values = executor.map(sample, submitted)
    return dict(values), dict(runtime.audit.snapshot().sample_counts)


def test_pipeline_timing_is_order_and_worker_deterministic() -> None:
    """Stable stage ordinals make values independent of worker arrival order."""

    single = _worker_population(1, reverse=False)
    parallel = _worker_population(8, reverse=True)
    assert single == parallel
    assert single[1] == {_RELATIONSHIP: 64 * 3}


def test_pipeline_timing_is_pythonhashseed_deterministic() -> None:
    """Pipeline timing cannot inherit interpreter hash randomization."""

    script = textwrap.dedent(
        """
        import json
        from tests.unit.test_linux_shell_timing_runtime import _worker_population

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
    assert audit == {_RELATIONSHIP: 64 * 3}


def test_pipeline_helper_and_two_callers_have_exact_runtime_wiring() -> None:
    """The helper has no RNG seam and both production callers pass the engine owner."""

    signature = inspect.signature(plan_linux_pipeline_stage_times)
    assert signature.parameters["timing_runtime"].default is inspect.Parameter.empty
    helper = ast.parse(inspect.getsource(plan_linux_pipeline_stage_times))
    called_names = {
        call.func.id
        for call in ast.walk(helper)
        if isinstance(call, ast.Call) and isinstance(call.func, ast.Name)
    }
    called_methods = {
        call.func.attr
        for call in ast.walk(helper)
        if isinstance(call, ast.Call) and isinstance(call.func, ast.Attribute)
    }
    assert not called_names.intersection(
        {"Random", "TimingSampler", "TimingRuntimePreparation", "_stable_seed"}
    )
    assert not called_methods.intersection(
        {"commit_no_fail", "prepared", "random", "triangular", "uniform"}
    )
    assert "_pipeline_timing_runtime" in called_names

    action_path = (
        _PROJECT_ROOT
        / "src"
        / "evidenceforge"
        / "generation"
        / "actions"
        / "linux_shell_command.py"
    )
    action_tree = ast.parse(action_path.read_text(encoding="utf-8"), filename=str(action_path))
    action_called_names = {
        call.func.id
        for call in ast.walk(action_tree)
        if isinstance(call, ast.Call) and isinstance(call.func, ast.Name)
    }
    assert "active_source_timing_planning_runtime" in action_called_names

    generator_path = (
        _PROJECT_ROOT / "src" / "evidenceforge" / "generation" / "activity" / "generator.py"
    )
    tree = ast.parse(generator_path.read_text(encoding="utf-8"), filename=str(generator_path))
    calls = [
        call
        for call in ast.walk(tree)
        if isinstance(call, ast.Call)
        and isinstance(call.func, ast.Name)
        and call.func.id == "plan_linux_pipeline_stage_times"
    ]
    assert len(calls) == 2
    for call in calls:
        runtime_keyword = next(
            keyword for keyword in call.keywords if keyword.arg == "timing_runtime"
        )
        assert ast.unparse(runtime_keyword.value) == "self.timing_runtime"
