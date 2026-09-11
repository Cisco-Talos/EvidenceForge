# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Runtime timing contracts for direct baseline RDP outer placement."""

from __future__ import annotations

import ast
import inspect
import json
import os
import random
import subprocess
import sys
import textwrap
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from pathlib import Path
from unittest.mock import Mock

import pytest

from evidenceforge.generation.activity import generator as generator_module
from evidenceforge.generation.activity.generator import (
    ActivityGenerator,
    _rdp_inclusive_millisecond_distribution,
)
from evidenceforge.generation.source_timing import SourceTimingPlanner
from evidenceforge.generation.timing import TimingRuntime, TimingScope
from evidenceforge.models import System, User
from evidenceforge.models.exceptions import StateError

_ACTIVITY_TIME = datetime(2026, 2, 3, 14, 15, 16, 170_000, tzinfo=UTC)
_SESSION_RELATIONSHIP = "activity.rdp.session_before_baseline_logon"
_PROCESS_RELATIONSHIP = "activity.rdp.source_process_before_session"


def _user() -> User:
    return User(
        username="analyst",
        full_name="Alicia Analyst",
        email="analyst@example.test",
    )


def _source() -> System:
    return System(
        hostname="WS-01",
        ip="10.0.0.10",
        os="Windows 11",
        type="workstation",
        assigned_user="analyst",
    )


def _target() -> System:
    return System(
        hostname="APP-01",
        ip="10.0.0.30",
        os="Windows Server 2022",
        type="server",
        services=["rdp"],
    )


def _selection_rng() -> Mock:
    rng = Mock(spec=random.Random)
    rng.random.return_value = 0.5
    rng.choices.return_value = [10]
    rng.choice.side_effect = lambda values: values[0]
    return rng


def _generator(
    runtime: object,
    *,
    source_system: System | None,
    remote_ip: str | None = None,
) -> ActivityGenerator:
    generator = ActivityGenerator.__new__(ActivityGenerator)
    generator.timing_runtime = runtime  # type: ignore[assignment]
    source_ip = remote_ip or (source_system.ip if source_system is not None else "198.51.100.24")
    generator._all_system_ips = [_target().ip, source_ip]
    generator._ip_to_system = (
        {source_system.ip: source_system, _target().ip: _target()}
        if source_system is not None
        else {_target().ip: _target()}
    )
    generator._resolve_direct_rdp_source_system = Mock(return_value=source_system)
    generator._direct_rdp_source_process_factory = Mock(return_value=object())
    generator.generate_rdp_session = Mock()
    generator.generate_logon = Mock(return_value="0x100")
    generator.generate_failed_logon = Mock()
    return generator


def _execute_rdp(
    runtime: object,
    monkeypatch: pytest.MonkeyPatch,
    *,
    source_system: System | None,
    remote_ip: str | None = None,
) -> tuple[ActivityGenerator, dict[str, object]]:
    generator = _generator(runtime, source_system=source_system, remote_ip=remote_ip)
    rng = _selection_rng()
    monkeypatch.setattr(generator_module, "_get_rng", lambda: rng)
    generator.execute_baseline_activity(_user(), _target(), _ACTIVITY_TIME, "logon")
    assert generator.generate_rdp_session.call_count == 1
    return generator, generator.generate_rdp_session.call_args.kwargs


def test_rdp_outer_timing_uses_exact_scope_support_and_audit() -> None:
    """One direct draw matches the exact semantic scope and inclusive support."""

    runtime = TimingRuntime(reference_time=_ACTIVITY_TIME, namespace="rdp-outer-exact-scope")
    generator = ActivityGenerator.__new__(ActivityGenerator)
    generator.timing_runtime = runtime
    actual = generator._sample_rdp_outer_timing_milliseconds(
        relationship_key=_SESSION_RELATIONSHIP,
        stable_id="baseline-rdp:analyst:10.0.0.10:APP-01:2026-02-03T14:15:16.170000+00:00",
        host="APP-01",
        lifecycle_id="baseline-rdp-lifecycle",
        sample_key="session_lead_ms",
        minimum_ms=80,
        maximum_ms=400,
        ordinal=7,
    )

    expected_runtime = TimingRuntime(
        reference_time=_ACTIVITY_TIME,
        namespace="rdp-outer-exact-scope",
    )
    expected = expected_runtime.sampler.sample_value(
        _rdp_inclusive_millisecond_distribution(80, 400),
        relationship_key=_SESSION_RELATIONSHIP,
        scope=TimingScope(
            stable_id=("baseline-rdp:analyst:10.0.0.10:APP-01:2026-02-03T14:15:16.170000+00:00"),
            host="APP-01",
            source="activity.rdp",
            lifecycle_id="baseline-rdp-lifecycle",
            ordinal=7,
        ),
        sample_key="session_lead_ms",
    )

    assert actual == int(expected + 0.5)
    assert 80 <= actual <= 400
    audit = runtime.audit.snapshot()
    assert audit.sample_counts == {_SESSION_RELATIONSHIP: 1}
    assert audit.distribution_counts == {"mixture": 1}


def test_rdp_outer_direct_and_prepared_commit_are_identical(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Prepared placement stages two samples and commits exactly like direct execution."""

    direct_runtime = TimingRuntime(reference_time=_ACTIVITY_TIME, namespace="rdp-outer-prepared")
    _direct_generator, direct_request = _execute_rdp(
        direct_runtime,
        monkeypatch,
        source_system=_source(),
    )
    direct_audit = direct_runtime.audit.snapshot()

    staged_runtime = TimingRuntime(reference_time=_ACTIVITY_TIME, namespace="rdp-outer-prepared")
    timing_owner = SourceTimingPlanner(
        "enterprise_standard",
        timing_runtime=staged_runtime,
    )
    before_digest = staged_runtime.state_digest()
    with timing_owner.prepared_planning() as preparation:
        _staged_generator, staged_request = _execute_rdp(
            preparation.planning_runtime,
            monkeypatch,
            source_system=_source(),
        )
        assert preparation.staged_audit_operations == 2
        assert staged_runtime.state_digest() == before_digest

    with preparation.claimed_commit():
        preparation.commit_no_fail()

    assert staged_request["time"] == direct_request["time"]
    assert staged_request["source_process_time"] == direct_request["source_process_time"]
    assert staged_runtime.audit.snapshot() == direct_audit
    assert direct_audit.sample_counts == {
        _PROCESS_RELATIONSHIP: 1,
        _SESSION_RELATIONSHIP: 1,
    }
    assert direct_audit.distribution_counts == {"mixture": 2}


def test_rdp_outer_order_and_bounds_are_preserved(monkeypatch: pytest.MonkeyPatch) -> None:
    """Source process, session request, and baseline activity retain causal ordering."""

    runtime = TimingRuntime(reference_time=_ACTIVITY_TIME, namespace="rdp-outer-order")
    _generator_instance, request = _execute_rdp(runtime, monkeypatch, source_system=_source())
    session_time = request["time"]
    source_process_time = request["source_process_time"]
    assert isinstance(session_time, datetime)
    assert isinstance(source_process_time, datetime)
    assert _ACTIVITY_TIME - timedelta(milliseconds=400) <= session_time
    assert session_time <= _ACTIVITY_TIME - timedelta(milliseconds=80)
    assert session_time - timedelta(milliseconds=3200) <= source_process_time
    assert source_process_time <= session_time - timedelta(milliseconds=1800)
    assert source_process_time < session_time < _ACTIVITY_TIME


def test_rdp_outer_skips_conditional_and_inadmissible_samples(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """External sources skip process placement and self-sourced logons skip both draws."""

    external_runtime = TimingRuntime(reference_time=_ACTIVITY_TIME, namespace="rdp-outer-external")
    _external_generator, external_request = _execute_rdp(
        external_runtime,
        monkeypatch,
        source_system=None,
    )
    assert external_request["source_process_time"] is None
    assert external_request["source_process_factory"] is None
    assert external_runtime.audit.snapshot().sample_counts == {_SESSION_RELATIONSHIP: 1}

    self_runtime = TimingRuntime(reference_time=_ACTIVITY_TIME, namespace="rdp-outer-self")
    self_generator = _generator(
        self_runtime,
        source_system=None,
        remote_ip=_target().ip,
    )
    self_generator._all_system_ips = [_target().ip]
    rng = _selection_rng()
    monkeypatch.setattr(generator_module, "_get_rng", lambda: rng)
    self_generator.execute_baseline_activity(_user(), _target(), _ACTIVITY_TIME, "logon")
    assert self_generator.generate_rdp_session.call_count == 0
    assert self_generator.generate_logon.call_count == 1
    assert self_runtime.audit.snapshot().total_samples == 0


def test_rdp_outer_cancelled_preparation_leaves_zero_audit_residue(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Rejecting a prepared baseline RDP request discards both staged timing samples."""

    runtime = TimingRuntime(reference_time=_ACTIVITY_TIME, namespace="rdp-outer-cancel")
    timing_owner = SourceTimingPlanner("enterprise_standard", timing_runtime=runtime)
    before_digest = runtime.state_digest()

    with pytest.raises(RuntimeError, match="reject baseline RDP"):
        with timing_owner.prepared_planning() as preparation:
            _execute_rdp(
                preparation.planning_runtime,
                monkeypatch,
                source_system=_source(),
            )
            assert preparation.staged_audit_operations == 2
            raise RuntimeError("reject baseline RDP")

    assert runtime.state_digest() == before_digest
    assert runtime.audit.snapshot().total_samples == 0


def test_rdp_outer_rejects_foreign_authority_before_descriptor_dispatch() -> None:
    """Raw preparations, subclasses, and hostile carriers cannot become timing owners."""

    callbacks: list[str] = []

    class ForeignRuntime:
        @property
        def sampler(self) -> object:
            callbacks.append("sampler")
            raise AssertionError("foreign sampler descriptor reached")

    class RuntimeSubclass(TimingRuntime):
        pass

    class HostileIdentity:
        def __bool__(self) -> bool:
            callbacks.append("identity-bool")
            raise AssertionError("foreign identity truthiness reached")

    owner = TimingRuntime(reference_time=_ACTIVITY_TIME, namespace="rdp-outer-authority")
    invalid_runtimes: tuple[object, ...] = (
        ForeignRuntime(),
        RuntimeSubclass(reference_time=_ACTIVITY_TIME, namespace="rdp-outer-subclass"),
        owner.prepared(),
    )
    for invalid_runtime in invalid_runtimes:
        generator = ActivityGenerator.__new__(ActivityGenerator)
        generator.timing_runtime = invalid_runtime  # type: ignore[assignment]
        with pytest.raises(StateError, match="exact engine-owned runtime"):
            generator._sample_rdp_outer_timing_milliseconds(
                relationship_key=_SESSION_RELATIONSHIP,
                stable_id="baseline-rdp-authority",
                host="APP-01",
                lifecycle_id="baseline-rdp-lifecycle",
                sample_key="session_lead_ms",
                minimum_ms=80,
                maximum_ms=400,
            )

    generator = ActivityGenerator.__new__(ActivityGenerator)
    generator.timing_runtime = owner
    with pytest.raises(StateError, match="exact built-in values"):
        generator._sample_rdp_outer_timing_milliseconds(
            relationship_key=_SESSION_RELATIONSHIP,
            stable_id=HostileIdentity(),  # type: ignore[arg-type]
            host="APP-01",
            lifecycle_id="baseline-rdp-lifecycle",
            sample_key="session_lead_ms",
            minimum_ms=80,
            maximum_ms=400,
        )
    assert callbacks == []
    assert owner.audit.snapshot().total_samples == 0


def test_rdp_outer_distribution_preserves_inclusive_uniform_pmf() -> None:
    """The edge-triangle mixture retains the former inclusive randint endpoint mass."""

    distribution = _rdp_inclusive_millisecond_distribution(80, 400)
    triangles = tuple(component.distribution for component in distribution.components)
    assert all(triangle.minimum == 79.5 for triangle in triangles)
    assert all(triangle.maximum == 400.5 for triangle in triangles)

    runtime = TimingRuntime(reference_time=_ACTIVITY_TIME, namespace="rdp-outer-pmf")
    generator = ActivityGenerator.__new__(ActivityGenerator)
    generator.timing_runtime = runtime
    counts = Counter(
        generator._sample_rdp_outer_timing_milliseconds(
            relationship_key="activity.rdp.pmf",
            stable_id=f"baseline-rdp-pmf-{index}",
            host="APP-01",
            lifecycle_id="baseline-rdp-pmf",
            sample_key="gap_ms",
            minimum_ms=0,
            maximum_ms=3,
            ordinal=index,
        )
        for index in range(40_000)
    )
    assert set(counts) == {0, 1, 2, 3}
    expected = 10_000
    chi_squared = sum((count - expected) ** 2 / expected for count in counts.values())
    assert chi_squared < 12.0


def _worker_population(
    workers: int, reverse: bool
) -> tuple[dict[int, tuple[int, int]], dict[str, int]]:
    runtime = TimingRuntime(reference_time=_ACTIVITY_TIME, namespace="rdp-outer-workers")
    generator = ActivityGenerator.__new__(ActivityGenerator)
    generator.timing_runtime = runtime
    indices = tuple(reversed(range(128))) if reverse else tuple(range(128))

    def sample(index: int) -> tuple[int, tuple[int, int]]:
        lifecycle_id = f"baseline-rdp-worker-{index}"
        session_lead = generator._sample_rdp_outer_timing_milliseconds(
            relationship_key=_SESSION_RELATIONSHIP,
            stable_id=lifecycle_id,
            host="APP-01",
            lifecycle_id=lifecycle_id,
            sample_key="session_lead_ms",
            minimum_ms=80,
            maximum_ms=400,
            ordinal=index,
        )
        process_lead = generator._sample_rdp_outer_timing_milliseconds(
            relationship_key=_PROCESS_RELATIONSHIP,
            stable_id=lifecycle_id,
            host="WS-01",
            lifecycle_id=lifecycle_id,
            sample_key="source_process_lead_ms",
            minimum_ms=1800,
            maximum_ms=3200,
            ordinal=index,
        )
        return index, (session_lead, process_lead)

    if workers == 1:
        values = map(sample, indices)
    else:
        with ThreadPoolExecutor(max_workers=workers) as executor:
            values = executor.map(sample, indices)
    return dict(values), dict(runtime.audit.snapshot().sample_counts)


def test_rdp_outer_is_order_and_worker_deterministic() -> None:
    """Stable RDP scopes make both placement populations independent of scheduling."""

    assert _worker_population(1, False) == _worker_population(8, True)


def test_rdp_outer_is_pythonhashseed_deterministic() -> None:
    """RDP outer placement does not depend on Python's randomized hash seed."""

    script = textwrap.dedent(
        """
        import json
        from concurrent.futures import ThreadPoolExecutor
        from datetime import UTC, datetime

        from evidenceforge.generation.activity.generator import ActivityGenerator
        from evidenceforge.generation.timing import TimingRuntime

        start = datetime(2026, 2, 3, 14, tzinfo=UTC)
        generator = ActivityGenerator.__new__(ActivityGenerator)
        generator.timing_runtime = TimingRuntime(
            reference_time=start,
            namespace="rdp-outer-hashseed",
        )

        def sample(index):
            lifecycle_id = f"baseline-rdp-hashseed-{index}"
            return index, (
                generator._sample_rdp_outer_timing_milliseconds(
                    relationship_key="activity.rdp.session_before_baseline_logon",
                    stable_id=lifecycle_id,
                    host="APP-01",
                    lifecycle_id=lifecycle_id,
                    sample_key="session_lead_ms",
                    minimum_ms=80,
                    maximum_ms=400,
                    ordinal=index,
                ),
                generator._sample_rdp_outer_timing_milliseconds(
                    relationship_key="activity.rdp.source_process_before_session",
                    stable_id=lifecycle_id,
                    host="WS-01",
                    lifecycle_id=lifecycle_id,
                    sample_key="source_process_lead_ms",
                    minimum_ms=1800,
                    maximum_ms=3200,
                    ordinal=index,
                ),
            )

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
        completed = subprocess.run(
            [sys.executable, "-c", script],
            cwd=project_root,
            env=environment,
            check=True,
            capture_output=True,
            text=True,
        )
        outputs.append(completed.stdout.strip())

    assert outputs[0] == outputs[1]
    assert len(json.loads(outputs[0])) == 64


def test_rdp_outer_production_branch_has_no_direct_temporal_rng() -> None:
    """Both former randint supports route through the exact runtime helper."""

    source = textwrap.dedent(inspect.getsource(ActivityGenerator.execute_baseline_activity))
    tree = ast.parse(source)
    forbidden_supports = {(80, 400), (1800, 3200)}
    direct_supports = {
        (node.args[0].value, node.args[1].value)
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "randint"
        and len(node.args) == 2
        and all(isinstance(argument, ast.Constant) for argument in node.args)
    }
    assert direct_supports.isdisjoint(forbidden_supports)

    sample_calls = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "_sample_rdp_outer_timing_milliseconds"
    ]
    assert len(sample_calls) == 2
    actual = {
        next(
            keyword.value.value
            for keyword in call.keywords
            if keyword.arg == "relationship_key" and isinstance(keyword.value, ast.Constant)
        ): (
            next(
                keyword.value.value
                for keyword in call.keywords
                if keyword.arg == "minimum_ms" and isinstance(keyword.value, ast.Constant)
            ),
            next(
                keyword.value.value
                for keyword in call.keywords
                if keyword.arg == "maximum_ms" and isinstance(keyword.value, ast.Constant)
            ),
        )
        for call in sample_calls
    }
    assert actual == {
        _SESSION_RELATIONSHIP: (80, 400),
        _PROCESS_RELATIONSHIP: (1800, 3200),
    }

    helper_source = inspect.getsource(ActivityGenerator._sample_rdp_outer_timing_milliseconds)
    assert "compatibility_default" not in helper_source
    assert "_get_rng" not in helper_source
    assert "random." not in helper_source
