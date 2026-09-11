# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Adversarial timing-runtime coverage for browser-session activity."""

from __future__ import annotations

import ast
import json
import os
import random
import statistics
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from typing import Any

from evidenceforge.generation.actions import browser_session as browser_action_module
from evidenceforge.generation.actions.browser_session import (
    BrowserSessionActionBundle,
    BrowserSessionRequest,
)
from evidenceforge.generation.activity import browsing_session as browsing_module
from evidenceforge.generation.activity.browsing_session import (
    BrowsingRequest,
    generate_browsing_session,
)
from evidenceforge.generation.timing import TimingRuntime

T0 = datetime(2026, 8, 16, 12, 0, tzinfo=UTC)


class _StateSink:
    """Record browser event-time advances without owning canonical state."""

    def __init__(self) -> None:
        self.times: list[datetime] = []

    def set_current_time(self, timestamp: datetime) -> None:
        """Record one requested canonical time."""

        self.times.append(timestamp)


class _BrowserExecutor:
    """Minimal browser executor with one injected timing runtime."""

    def __init__(self, timing_runtime: TimingRuntime) -> None:
        self.timing_runtime = timing_runtime
        self.state_manager = _StateSink()
        self.connections: list[dict[str, Any]] = []

    def generate_connection(self, **kwargs: Any) -> str:
        """Record one canonical connection request."""

        self.connections.append(kwargs)
        return f"C{len(self.connections)}"


class _NoLegacyTimingRandom(random.Random):
    """Fail if a migrated route/duration site returns to direct RNG timing."""

    def randint(self, a: int, b: int) -> int:
        """Allow content/count draws while rejecting the former route gap."""

        if (a, b) == (250, 2_400):
            raise AssertionError("route request gaps must use TimingRuntime")
        return super().randint(a, b)

    def uniform(self, a: float, b: float) -> float:
        """Reject both former browser connection-duration draws."""

        raise AssertionError(f"browser duration must not use rng.uniform({a}, {b})")


def _request(*, route_profile: object | None = None) -> BrowserSessionRequest:
    """Return one stable browser action request."""

    return BrowserSessionRequest(
        src_ip="10.0.10.50",
        dst_ip="203.0.113.20",
        time=T0,
        hostname="portal.example.com",
        dst_port=443,
        service="ssl",
        source_system=SimpleNamespace(hostname="WS-01"),
        domain_tags=("web", "saas"),
        browsing_intensity="heavy",
        require_browser_like_domain=False,
        user_agent="Mozilla/5.0",
        route_profile=route_profile,
    )


def _route_profile() -> SimpleNamespace:
    """Return one deterministic authored route whose only variation is timing."""

    method = SimpleNamespace(
        statuses={"200": 1.0},
        content_type="text/html",
        request_content_type="",
        request_wire_filename="",
        request_multipart=None,
        response_multipart=None,
        request_body_bytes=(0, 0),
        response_body_bytes=(4_096, 4_096),
    )
    route = SimpleNamespace(weight=1.0, path="/dashboard", methods={"GET": method})
    return SimpleNamespace(routes=[route])


def _offset_population(
    *,
    cache_size: int,
    workers: int,
    reverse: bool,
) -> dict[int, tuple[tuple[int, int], ...]]:
    """Generate browser timing under varied ordering, workers, and clock capacity."""

    runtime = TimingRuntime(
        reference_time=T0,
        namespace="browser-order-worker-cache",
        max_clock_cache_entries=cache_size,
    )
    ordinals = list(range(96))
    if reverse:
        ordinals.reverse()

    def sample(ordinal: int) -> tuple[int, tuple[tuple[int, int], ...]]:
        requests = generate_browsing_session(
            random.Random(ordinal),
            "github.com",
            [],
            request_time=T0,
            timing_runtime=runtime,
            timing_stable_id=f"browser-worker:{ordinal}",
        )
        return ordinal, tuple(
            (request.time_offset_ms, request.time_offset_remainder_us) for request in requests
        )

    if workers == 1:
        values = tuple(sample(ordinal) for ordinal in ordinals)
    else:
        with ThreadPoolExecutor(max_workers=workers) as executor:
            values = tuple(executor.map(sample, ordinals))
    assert runtime.clocks.cache_size <= cache_size
    return dict(values)


def test_browser_offsets_are_order_worker_and_cache_independent() -> None:
    """Browser timing must depend on semantic scope, not scheduling or cache shape."""

    expected = _offset_population(cache_size=0, workers=1, reverse=False)
    assert _offset_population(cache_size=1, workers=4, reverse=True) == expected
    assert _offset_population(cache_size=17, workers=8, reverse=False) == expected


def test_browser_offsets_are_python_hash_seed_independent() -> None:
    """Browser timing identities must not depend on Python hash randomization."""

    script = """
import json
import random
from datetime import UTC, datetime
from evidenceforge.generation.activity.browsing_session import generate_browsing_session
from evidenceforge.generation.timing import TimingRuntime

t0 = datetime(2026, 8, 16, 12, tzinfo=UTC)
runtime = TimingRuntime(reference_time=t0, namespace='browser-hash-seed')
values = {}
for ordinal in reversed(range(48)):
    requests = generate_browsing_session(
        random.Random(ordinal),
        'github.com',
        [],
        request_time=t0,
        timing_runtime=runtime,
        timing_stable_id=f'browser-hash:{ordinal}',
    )
    values[str(ordinal)] = [
        [request.time_offset_ms, request.time_offset_remainder_us]
        for request in requests
    ]
print(json.dumps(values, sort_keys=True))
"""
    outputs = []
    for seed in ("1", "8675309"):
        result = subprocess.run(
            [sys.executable, "-c", script],
            check=True,
            capture_output=True,
            text=True,
            env={**os.environ, "PYTHONHASHSEED": seed},
        )
        outputs.append(json.loads(result.stdout))
    assert outputs[0] == outputs[1]


def test_browser_offsets_preserve_interior_microsecond_texture() -> None:
    """The millisecond compatibility field must retain a separate microsecond residue."""

    runtime = TimingRuntime(reference_time=T0, namespace="browser-offset-shape")
    offsets: list[int] = []
    for ordinal in range(256):
        requests = generate_browsing_session(
            random.Random(ordinal),
            "github.com",
            [],
            request_time=T0,
            timing_runtime=runtime,
            timing_stable_id=f"browser-shape:{ordinal}",
        )
        exact_offsets = [
            (request.time_offset_ms * 1_000) + request.time_offset_remainder_us
            for request in requests
        ]
        assert all(0 <= request.time_offset_remainder_us < 1_000 for request in requests)
        assert exact_offsets == sorted(exact_offsets)
        offsets.extend(offset for offset in exact_offsets if offset)

    assert offsets
    assert sum(offset % 1_000 == 0 for offset in offsets) / len(offsets) < 0.005
    audit = runtime.audit.snapshot()
    assert audit.total_samples > 2_000
    assert audit.total_saturations / audit.total_samples < 0.005
    assert {
        "web.asset_image_after_page",
        "web.asset_stylesheet_script_after_page",
        "web.page.subresource_settle",
        "web.session_navigation",
    } <= set(audit.sample_counts)


def test_microsecond_remainder_survives_deadline_and_dispatch(monkeypatch: Any) -> None:
    """Deadline filtering and dispatch must consume the full split offset."""

    def session(**kwargs: Any) -> list[BrowsingRequest]:
        return [
            BrowsingRequest(
                time_offset_ms=100,
                time_offset_remainder_us=321,
                hostname=kwargs["hostname"],
                path="/",
                method="GET",
                content_type="text/html",
                referrer="",
                trans_depth=1,
                is_page_load=True,
                response_body_len=4_096,
                request_body_len=0,
            )
        ]

    monkeypatch.setattr(browsing_module, "generate_browsing_session", session)
    runtime = TimingRuntime(reference_time=T0, namespace="browser-offset-dispatch")
    executor = _BrowserExecutor(runtime)
    request = _request()
    result = BrowserSessionActionBundle(
        request=request,
        executor=executor,
        rng=random.Random(9),
    ).execute_with_result()

    assert result.request_count == 1
    assert executor.connections[0]["time"] == T0 + timedelta(microseconds=100_321)
    assert executor.state_manager.times == [T0 + timedelta(microseconds=100_321)]

    rejected_executor = _BrowserExecutor(runtime)
    rejected_request = replace(
        request,
        latest_request_time=T0 + timedelta(microseconds=100_320),
    )
    rejected = BrowserSessionActionBundle(
        request=rejected_request,
        executor=rejected_executor,
        rng=random.Random(9),
    ).execute_with_result()
    assert rejected.request_count == 0
    assert rejected_executor.connections == []


def test_route_gaps_and_connection_durations_use_semantic_runtime_samples() -> None:
    """Former route/duration RNG sites must be runtime-owned and repeatable."""

    runtime = TimingRuntime(reference_time=T0, namespace="browser-route-duration")
    executor = _BrowserExecutor(runtime)
    request = _request(route_profile=_route_profile())
    left = BrowserSessionActionBundle(
        request=request,
        executor=executor,
        rng=_NoLegacyTimingRandom(7),
    )
    right = BrowserSessionActionBundle(
        request=request,
        executor=executor,
        rng=_NoLegacyTimingRandom(901),
    )

    left_routes = left._generate_route_profile_session()  # noqa: SLF001
    right_routes = right._generate_route_profile_session()  # noqa: SLF001
    left_offsets = [
        (route.time_offset_ms * 1_000) + route.time_offset_remainder_us for route in left_routes
    ]
    right_offsets = [
        (route.time_offset_ms * 1_000) + route.time_offset_remainder_us for route in right_routes
    ]
    assert len(left_offsets) >= 2
    assert left_offsets == right_offsets
    assert all(offset % 1_000 for offset in left_offsets[1:])

    group = {"last_offset_us": 4_000_000}
    primary_left = left._connection_duration(  # noqa: SLF001
        group=group,
        first_in_group=True,
        emit_offset_us=1_000_123,
    )
    primary_right = right._connection_duration(  # noqa: SLF001
        group=group,
        first_in_group=True,
        emit_offset_us=1_000_123,
    )
    secondary_left = left._connection_duration(  # noqa: SLF001
        group=group,
        first_in_group=False,
        emit_offset_us=1_600_321,
    )
    secondary_right = right._connection_duration(  # noqa: SLF001
        group=group,
        first_in_group=False,
        emit_offset_us=1_600_321,
    )
    assert primary_left == primary_right
    assert secondary_left == secondary_right
    assert 4.249877 < primary_left < 5.999877
    assert request.secondary_duration_min < secondary_left < 2.0

    samples = runtime.audit.snapshot().sample_counts
    assert samples["browser.route.request_gap"] >= 2
    assert samples["browser.connection.primary_tail"] == 2
    assert samples["browser.connection.secondary_duration"] == 2


def test_browser_transport_duration_shapes_are_interior_and_non_lattice() -> None:
    """Primary tails and secondary transports must avoid bounds and ms atoms."""

    runtime = TimingRuntime(reference_time=T0, namespace="browser-duration-shape")
    bundle = BrowserSessionActionBundle(
        request=_request(),
        executor=_BrowserExecutor(runtime),
        rng=_NoLegacyTimingRandom(11),
    )
    primary_tails: list[float] = []
    secondary: list[float] = []
    for ordinal in range(2_048):
        emit_offset_us = 1_000_000 + ordinal
        remaining = (5_000_000 - emit_offset_us) / 1_000_000
        primary = bundle._connection_duration(  # noqa: SLF001
            group={"last_offset_us": 5_000_000},
            first_in_group=True,
            emit_offset_us=emit_offset_us,
        )
        primary_tails.append(primary - remaining)
        secondary.append(
            bundle._connection_duration(  # noqa: SLF001
                group={"last_offset_us": 5_000_000},
                first_in_group=False,
                emit_offset_us=emit_offset_us,
            )
        )

    assert min(primary_tails) > 1.25
    assert max(primary_tails) < 3.0
    assert statistics.mean(primary_tails) > statistics.median(primary_tails)
    assert min(secondary) > bundle.request.secondary_duration_min
    assert max(secondary) < 2.0
    assert statistics.mean(secondary) > statistics.median(secondary)
    for values in (primary_tails, secondary):
        exact_ms = sum(round(value * 1_000_000) % 1_000 == 0 for value in values)
        assert exact_ms / len(values) < 0.005


def test_browser_migrated_functions_have_no_direct_rng_timing() -> None:
    """Freeze the remaining continuous RNG as response-size texture only."""

    action_path = Path(browser_action_module.__file__)
    browsing_path = Path(browsing_module.__file__)
    continuous_methods = {
        "betavariate",
        "expovariate",
        "gammavariate",
        "gauss",
        "lognormvariate",
        "normalvariate",
        "paretovariate",
        "triangular",
        "uniform",
        "vonmisesvariate",
        "weibullvariate",
    }
    observed: list[tuple[Path, str, str]] = []
    for path in (action_path, browsing_path):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        parents = {
            child: parent for parent in ast.walk(tree) for child in ast.iter_child_nodes(parent)
        }
        for call in (node for node in ast.walk(tree) if isinstance(node, ast.Call)):
            if not isinstance(call.func, ast.Attribute) or call.func.attr not in continuous_methods:
                continue
            receiver = call.func.value
            direct_rng = isinstance(receiver, ast.Name) and receiver.id.endswith("rng")
            direct_rng = direct_rng or (
                isinstance(receiver, ast.Attribute)
                and isinstance(receiver.value, ast.Name)
                and receiver.value.id == "self"
                and receiver.attr == "rng"
            )
            if not direct_rng:
                continue
            ancestor: ast.AST | None = call
            while ancestor is not None and not isinstance(ancestor, ast.FunctionDef):
                ancestor = parents.get(ancestor)
            function = ancestor.name if isinstance(ancestor, ast.FunctionDef) else "<module>"
            observed.append((path, function, call.func.attr))

    assert observed == [(browsing_path, "_response_size_for_status_code", "uniform")]
