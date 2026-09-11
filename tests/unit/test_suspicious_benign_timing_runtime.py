# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Engine-owned timing contracts for suspicious-but-benign hourly placement."""

from __future__ import annotations

import ast
import inspect
import json
import os
import random
import subprocess
import sys
import textwrap
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import evidenceforge.generation.activity.suspicious_benign as suspicious_benign
from evidenceforge.generation.activity.suspicious_benign import (
    _HOURLY_PLACEMENT_MAX_SECONDS,
    _inclusive_integer_distribution,
    _sample_hourly_placement_seconds,
)
from evidenceforge.generation.engine.baseline import BaselineMixin
from evidenceforge.generation.timing import TimingRuntime, TriangularDistribution
from evidenceforge.models.scenario import System, User

_PATTERNS = tuple(_HOURLY_PLACEMENT_MAX_SECONDS)
_HOUR = datetime(2026, 2, 3, 14, tzinfo=UTC)


def _environment() -> tuple[list[User], list[System]]:
    users = [
        User(
            username="svc_admin",
            full_name="Service Admin",
            email="svc_admin@example.test",
            persona="sysadmin",
            primary_system="WS-01",
        )
    ]
    systems = [
        System(
            hostname="WS-01",
            ip="10.0.0.10",
            os="Windows 11",
            type="workstation",
            assigned_user="svc_admin",
        ),
        System(
            hostname="SRV-01",
            ip="10.0.0.20",
            os="Windows Server 2022",
            type="server",
        ),
        System(
            hostname="SRV-02",
            ip="10.0.0.21",
            os="Ubuntu 24.04",
            type="server",
        ),
    ]
    return users, systems


def _placement_population(
    order: tuple[int, ...],
    *,
    workers: int,
) -> tuple[dict[str, int], dict[str, int]]:
    runtime = TimingRuntime(
        reference_time=_HOUR,
        namespace="suspicious-benign-placement-parity",
    )
    users, systems = _environment()

    def generate(index: int) -> tuple[str, int]:
        pattern = _PATTERNS[index]
        generator = getattr(suspicious_benign, f"generate_{pattern}")
        args: list[Any] = [
            random.Random(1100 + index),
            users,
            systems,
            _HOUR,
        ]
        if pattern in {"suspicious_cli", "unusual_powershell"}:
            args.append("example.test")
        result = generator(
            *args,
            runtime,
            100 + index,
        )
        assert result is not None
        return pattern, int((result["time"] - _HOUR).total_seconds())

    with ThreadPoolExecutor(max_workers=workers) as executor:
        placements = dict(executor.map(generate, order))
    return placements, dict(runtime.audit.snapshot().sample_counts)


def test_all_nine_placements_are_owner_audited_and_order_independent() -> None:
    """Every family uses one stable host/hour/ordinal scope regardless of worker order."""

    forward = _placement_population(tuple(range(len(_PATTERNS))), workers=1)
    reverse = _placement_population(tuple(reversed(range(len(_PATTERNS)))), workers=6)

    assert forward == reverse
    placements, sample_counts = forward
    assert set(placements) == set(_PATTERNS)
    assert all(
        0 <= placements[name] <= maximum for name, maximum in _HOURLY_PLACEMENT_MAX_SECONDS.items()
    )
    assert sample_counts == {
        f"suspicious_benign.{pattern}.hourly_placement": 1 for pattern in _PATTERNS
    }


class _EdgeSampler:
    def __init__(self, *, upper: bool) -> None:
        self._upper = upper
        self.requests: list[tuple[str, Any, str]] = []

    def sample_value(
        self,
        distribution: Any,
        *,
        relationship_key: str,
        scope: Any,
        sample_key: str,
    ) -> float:
        self.requests.append((relationship_key, scope, sample_key))
        components = distribution.components
        triangles = tuple(component.distribution for component in components)
        assert all(isinstance(item, TriangularDistribution) for item in triangles)
        if self._upper:
            return max(item.maximum for item in triangles) - 0.000001
        return min(item.minimum for item in triangles) + 0.000001


def test_prior_inclusive_support_and_scope_axes_are_exact() -> None:
    """The migrated distributions retain both legacy support edges and all identity axes."""

    for pattern, maximum in _HOURLY_PLACEMENT_MAX_SECONDS.items():
        distribution = _inclusive_integer_distribution(0, maximum)
        triangles = tuple(component.distribution for component in distribution.components)
        assert all(item.minimum == -0.5 for item in triangles)
        assert all(item.maximum == maximum + 0.5 for item in triangles)
        lower_sampler = _EdgeSampler(upper=False)
        upper_sampler = _EdgeSampler(upper=True)
        common = {
            "pattern": pattern,
            "hostname": "HOST-01",
            "current_hour": _HOUR,
            "timing_ordinal": 17,
        }
        assert (
            _sample_hourly_placement_seconds(
                timing_runtime=SimpleNamespace(sampler=lower_sampler),
                **common,
            )
            == 0
        )
        assert (
            _sample_hourly_placement_seconds(
                timing_runtime=SimpleNamespace(sampler=upper_sampler),
                **common,
            )
            == maximum
        )
        relationship, scope, sample_key = upper_sampler.requests[0]
        assert relationship == f"suspicious_benign.{pattern}.hourly_placement"
        assert scope.seed_parts() == (
            pattern,
            "HOST-01",
            "suspicious_benign",
            _HOUR.isoformat(),
            17,
        )
        assert sample_key == "offset_seconds"


def test_production_seam_injects_exact_runtime_without_temporal_rng_fallback() -> None:
    """Baseline has one explicit owner seam and all nine helpers have no legacy offset randint."""

    baseline_source = textwrap.dedent(inspect.getsource(BaselineMixin._generate_suspicious_noise))
    baseline_tree = ast.parse(baseline_source)
    runtime_references = [
        ast.unparse(node)
        for node in ast.walk(baseline_tree)
        if isinstance(node, ast.Attribute)
        and ast.unparse(node) == "self.activity_generator.timing_runtime"
    ]
    assert len(runtime_references) == len(_PATTERNS)
    production_source = ast.unparse(baseline_tree)
    assert production_source.count("event_ordinal") >= len(_PATTERNS) + 1
    assert "compatibility_default" not in baseline_source

    module_tree = ast.parse(inspect.getsource(suspicious_benign))
    timed_functions = {
        f"generate_{pattern}" if pattern != "after_hours_admin" else "generate_after_hours_admin"
        for pattern in _PATTERNS
    }
    definitions = {
        node.name: node
        for node in module_tree.body
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
    }
    assert timed_functions <= definitions.keys()
    for function_name in timed_functions:
        function = definitions[function_name]
        placement_calls = [
            node
            for node in ast.walk(function)
            if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id == "_sample_hourly_placement_seconds"
        ]
        assert len(placement_calls) == 1
        legacy_offset_draws = [
            node
            for node in ast.walk(function)
            if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and isinstance(node.func.value, ast.Name)
            and node.func.value.id == "rng"
            and node.func.attr == "randint"
            and len(node.args) == 2
            and isinstance(node.args[1], ast.Constant)
            and node.args[1].value in {3500, 3599}
        ]
        assert legacy_offset_draws == []


def test_placements_are_pythonhashseed_deterministic() -> None:
    """Stable semantic scopes do not depend on Python's randomized hash seed."""

    script = textwrap.dedent(
        """
        import json
        import random
        from datetime import UTC, datetime

        from evidenceforge.generation.activity.suspicious_benign import (
            _HOURLY_PLACEMENT_MAX_SECONDS,
        )
        import evidenceforge.generation.activity.suspicious_benign as suspicious_benign
        from evidenceforge.generation.timing import TimingRuntime
        from evidenceforge.models.scenario import System, User

        hour = datetime(2026, 2, 3, 14, tzinfo=UTC)
        users = [User(username="svc_admin", full_name="Service Admin",
                      email="svc_admin@example.test", persona="sysadmin",
                      primary_system="WS-01")]
        systems = [
            System(hostname="WS-01", ip="10.0.0.10", os="Windows 11",
                   type="workstation", assigned_user="svc_admin"),
            System(hostname="SRV-01", ip="10.0.0.20", os="Windows Server 2022",
                   type="server"),
            System(hostname="SRV-02", ip="10.0.0.21", os="Ubuntu 24.04", type="server"),
        ]
        runtime = TimingRuntime(reference_time=hour, namespace="suspicious-hashseed")
        result = {}
        for index, pattern in enumerate(_HOURLY_PLACEMENT_MAX_SECONDS):
            generator = getattr(suspicious_benign, f"generate_{pattern}")
            args = [random.Random(1100 + index), users, systems, hour]
            if pattern in {"suspicious_cli", "unusual_powershell"}:
                args.append("example.test")
            event = generator(*args, runtime, 100 + index)
            result[pattern] = int((event["time"] - hour).total_seconds())
        print(json.dumps(result, sort_keys=True))
        """
    )
    outputs = []
    for hash_seed in ("1", "8675309"):
        environment = os.environ.copy()
        environment["PYTHONHASHSEED"] = hash_seed
        completed = subprocess.run(
            [sys.executable, "-c", script],
            check=True,
            cwd=Path(__file__).parents[2],
            env=environment,
            capture_output=True,
            text=True,
        )
        outputs.append(json.loads(completed.stdout))
    assert outputs[0] == outputs[1]
