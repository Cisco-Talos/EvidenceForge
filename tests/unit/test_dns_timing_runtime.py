# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Engine-owned timing contracts for automatic DNS resolver evidence."""

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

from evidenceforge.generation.activity import ActivityGenerator
from evidenceforge.generation.activity.generator import (
    _dns_inclusive_millisecond_distribution,
)
from evidenceforge.generation.source_timing import SourceTimingPlanner
from evidenceforge.generation.state_manager import StateManager
from evidenceforge.generation.timing import TimingRuntime, TimingScope
from evidenceforge.models import System
from evidenceforge.models.exceptions import StateError

_START = datetime(2026, 2, 3, 14, tzinfo=UTC)
_SOURCE_IP = "10.0.1.50"
_DESTINATION_IP = "203.0.113.40"
_DNS_SERVER_IP = "10.0.0.10"


def _generator() -> ActivityGenerator:
    state = StateManager()
    state.set_current_time(_START)
    emitters = {
        "windows_event_security": Mock(),
        "windows_event_sysmon": Mock(),
        "zeek_conn": Mock(),
        "zeek_dns": Mock(),
        "zeek_ssl": Mock(),
        "zeek_x509": Mock(),
        "ecar": Mock(),
        "syslog": Mock(),
        "proxy_access": Mock(),
    }
    return ActivityGenerator(
        state,
        emitters,
        generation_window_start=_START - timedelta(hours=1),
        generation_window_end=_START + timedelta(days=2),
    )


def test_dns_integer_millisecond_support_and_scope_are_exact() -> None:
    """Every former randint support retains both endpoints without a private RNG."""

    for minimum, maximum in ((1, 10), (1, 30), (2, 45), (35, 95), (180, 420), (900, 1400)):
        distribution = _dns_inclusive_millisecond_distribution(minimum, maximum)
        triangles = tuple(component.distribution for component in distribution.components)
        assert all(item.minimum == minimum - 0.5 for item in triangles)
        assert all(item.maximum == maximum + 0.5 for item in triangles)

        generator = _generator()
        actual = generator._sample_dns_timing_milliseconds(
            relationship_key="activity.dns.test_gap",
            stable_id="dns-test-stable-id",
            host="WS-01",
            lifecycle_id="dns-test-lifecycle",
            sample_key="gap_ms",
            minimum_ms=minimum,
            maximum_ms=maximum,
            ordinal=7,
        )
        expected_runtime = _generator().timing_runtime
        expected = expected_runtime.sampler.sample_value(
            distribution,
            relationship_key="activity.dns.test_gap",
            scope=TimingScope(
                stable_id="dns-test-stable-id",
                host="WS-01",
                source="dns_lookup",
                lifecycle_id="dns-test-lifecycle",
                ordinal=7,
            ),
            sample_key="gap_ms",
        )
        assert actual == int(expected + 0.5)
        assert minimum <= actual <= maximum
        assert dict(generator.timing_runtime.audit.snapshot().sample_counts) == {
            "activity.dns.test_gap": 1
        }


def test_dns_timing_rejects_foreign_runtime_before_descriptor_dispatch() -> None:
    """Duck-typed and malformed authority cannot intercept the timing owner seam."""

    callbacks: list[str] = []

    class ForeignRuntime:
        @property
        def sampler(self) -> object:
            callbacks.append("sampler")
            raise RuntimeError("foreign sampler reached")

    class HostileIdentity:
        def __bool__(self) -> bool:
            callbacks.append("identity-bool")
            raise RuntimeError("identity bool reached")

    generator = _generator()
    generator.timing_runtime = ForeignRuntime()
    with pytest.raises(StateError, match="exact engine-owned runtime"):
        generator._sample_dns_timing_milliseconds(
            relationship_key="activity.dns.test_gap",
            stable_id="dns-test-stable-id",
            host="WS-01",
            lifecycle_id="dns-test-lifecycle",
            sample_key="gap_ms",
            minimum_ms=1,
            maximum_ms=10,
        )
    assert callbacks == []

    generator = _generator()
    with pytest.raises(StateError, match="exact built-in values"):
        generator._sample_dns_timing_milliseconds(
            relationship_key="activity.dns.test_gap",
            stable_id=HostileIdentity(),  # type: ignore[arg-type]
            host="WS-01",
            lifecycle_id="dns-test-lifecycle",
            sample_key="gap_ms",
            minimum_ms=1,
            maximum_ms=10,
        )
    assert callbacks == []


def test_dns_timing_direct_and_prepared_runtime_are_exact_and_cancel_neutral() -> None:
    """The source-timing planning view samples identically without mutating its owner early."""

    owner = SourceTimingPlanner(
        "enterprise_standard",
        timing_runtime=TimingRuntime(
            reference_time=_START - timedelta(hours=1),
            namespace="dns-direct-prepared-parity",
        ),
    )
    direct = _generator()
    direct.timing_runtime = owner.timing_runtime
    common = {
        "relationship_key": "activity.dns.direct_prepared_gap",
        "stable_id": "dns-direct-prepared",
        "host": "WS-01",
        "lifecycle_id": "dns-direct-prepared-lifecycle",
        "sample_key": "gap_ms",
        "minimum_ms": 1,
        "maximum_ms": 30,
        "ordinal": 4,
    }
    direct_value = direct._sample_dns_timing_milliseconds(**common)
    direct_audit = owner.timing_runtime.audit.snapshot()

    with owner.prepared_planning() as preparation:
        staged = _generator()
        staged.timing_runtime = preparation.planning_runtime
        assert staged._sample_dns_timing_milliseconds(**common) == direct_value
        assert preparation.staged_audit_operations == 1
        assert owner.timing_runtime.audit.snapshot() == direct_audit

    preparation.cancel()
    assert owner.timing_runtime.audit.snapshot() == direct_audit


def test_unplanned_query_uses_one_runtime_sample_and_planned_query_uses_none() -> None:
    """A caller-owned query timestamp bypasses the query-lead sampler without phantom audit."""

    unplanned = _generator()
    unplanned._emit_dns_lookup(
        src_ip=_SOURCE_IP,
        dst_ip=_DESTINATION_IP,
        time=_START,
        hostname="updates.example.test",
        force_address=True,
        bypass_cache=True,
    )
    unplanned_counts = dict(unplanned.timing_runtime.audit.snapshot().sample_counts)
    assert unplanned_counts["activity.dns.query_before_request"] == 1

    planned = _generator()
    planned_query_time = _START - timedelta(milliseconds=1111)
    planned._emit_dns_lookup(
        src_ip=_SOURCE_IP,
        dst_ip=_DESTINATION_IP,
        time=_START,
        hostname="updates.example.test",
        force_address=True,
        bypass_cache=True,
        planned_query_time=planned_query_time,
    )
    planned_counts = dict(planned.timing_runtime.audit.snapshot().sample_counts)
    assert "activity.dns.query_before_request" not in planned_counts


def test_ad_srv_duplicate_consumes_no_additional_timing_sample() -> None:
    """Only an admitted second SRV query samples spacing; duplicate buckets are neutral."""

    generator = _generator()
    generator._dc_systems = [
        System(
            hostname="DC-01",
            ip=_DNS_SERVER_IP,
            os="Windows Server 2022",
            type="domain_controller",
        )
    ]
    generator._allocate_ephemeral_port = Mock(return_value=53_000)
    generator.generate_connection = Mock(return_value="CAdSrvTiming1")
    rng = random.Random(117)
    common = {
        "src_ip": _SOURCE_IP,
        "dns_server_ip": _DNS_SERVER_IP,
        "src_os": "windows",
        "domain": "corp.example",
        "rng": rng,
        "query_process": None,
    }

    generator._emit_ad_srv_discovery(time=_START, **common)
    first_audit = generator.timing_runtime.audit.snapshot()
    assert generator.generate_connection.call_count == 2
    assert dict(first_audit.sample_counts)["activity.dns.ad_srv_query_spacing"] == 1

    generator._emit_ad_srv_discovery(time=_START + timedelta(minutes=5), **common)
    assert generator.generate_connection.call_count == 2
    assert generator.timing_runtime.audit.snapshot() == first_audit


def test_dns_timing_is_worker_and_order_independent() -> None:
    """Stable resolver scopes produce the same population under concurrent reversal."""

    def population(order: tuple[int, ...], workers: int) -> dict[int, int]:
        generator = _generator()

        def sample(index: int) -> tuple[int, int]:
            return (
                index,
                generator._sample_dns_timing_milliseconds(
                    relationship_key="activity.dns.worker_gap",
                    stable_id=f"dns-worker-{index}",
                    host=f"WS-{index % 3:02d}",
                    lifecycle_id=f"dns-lifecycle-{index // 3}",
                    sample_key="gap_ms",
                    minimum_ms=1,
                    maximum_ms=30,
                    ordinal=index,
                ),
            )

        with ThreadPoolExecutor(max_workers=workers) as executor:
            result = dict(executor.map(sample, order))
        assert dict(generator.timing_runtime.audit.snapshot().sample_counts) == {
            "activity.dns.worker_gap": len(order)
        }
        return result

    forward = population(tuple(range(32)), 1)
    reverse = population(tuple(reversed(range(32))), 8)
    assert forward == reverse


def test_dns_integer_distribution_preserves_uniform_endpoint_mass() -> None:
    """The edge-triangle mixture retains the former inclusive randint PMF."""

    generator = _generator()
    counts = Counter(
        generator._sample_dns_timing_milliseconds(
            relationship_key="activity.dns.pmf_gap",
            stable_id=f"dns-pmf-{index}",
            host="WS-01",
            lifecycle_id="dns-pmf-lifecycle",
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


def test_dns_timing_is_pythonhashseed_independent() -> None:
    """Resolver timing scopes do not depend on Python's randomized hash seed."""

    source_root = Path(__file__).resolve().parents[2] / "src"
    script = """
import json
from datetime import UTC, datetime
from evidenceforge.generation.activity import ActivityGenerator
from evidenceforge.generation.timing import TimingRuntime

generator = ActivityGenerator.__new__(ActivityGenerator)
generator.timing_runtime = TimingRuntime(
    reference_time=datetime(2026, 2, 3, 14, tzinfo=UTC),
    namespace="dns-hashseed",
)
print(json.dumps([
    generator._sample_dns_timing_milliseconds(
        relationship_key="activity.dns.hashseed_gap",
        stable_id=f"dns-hashseed-{index}",
        host="WS-01",
        lifecycle_id="dns-hashseed-lifecycle",
        sample_key="gap_ms",
        minimum_ms=1,
        maximum_ms=30,
        ordinal=index,
    )
    for index in range(24)
]))
"""
    outputs = []
    for seed in ("1", "987654"):
        environment = os.environ.copy()
        environment["PYTHONHASHSEED"] = seed
        environment["PYTHONPATH"] = str(source_root)
        completed = subprocess.run(
            [sys.executable, "-c", script],
            check=True,
            capture_output=True,
            text=True,
            env=environment,
        )
        outputs.append(json.loads(completed.stdout))
    assert outputs[0] == outputs[1]


def test_dns_production_paths_have_no_direct_temporal_randint() -> None:
    """All six resolver schedule gaps route through the engine-owned sampler."""

    forbidden_supports = {
        (1, 10),
        (1, 30),
        (2, 45),
        (35, 95),
        (180, 420),
        (900, 1400),
    }
    for function in (
        ActivityGenerator._execute_dns_lookup_bundle,
        ActivityGenerator._emit_ad_srv_discovery,
    ):
        tree = ast.parse(textwrap.dedent(inspect.getsource(function)))
        forbidden = []
        for node in ast.walk(tree):
            if not (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute)
                and isinstance(node.func.value, ast.Name)
                and node.func.value.id == "rng"
                and node.func.attr == "randint"
                and len(node.args) == 2
                and all(isinstance(argument, ast.Constant) for argument in node.args)
            ):
                continue
            support = (node.args[0].value, node.args[1].value)
            if support in forbidden_supports:
                forbidden.append(support)
        assert forbidden == []

    source = textwrap.dedent(inspect.getsource(ActivityGenerator._execute_dns_lookup_bundle))
    for relationship in (
        "activity.dns.query_before_request",
        "activity.dns.ad_srv_discovery_before_address",
        "activity.dns.companion_after_query",
        "activity.dns.mx_address_after_mx",
        "activity.dns.nxdomain_before_query",
    ):
        assert relationship in source
    assert "activity.dns.ad_srv_query_spacing" in inspect.getsource(
        ActivityGenerator._emit_ad_srv_discovery
    )
