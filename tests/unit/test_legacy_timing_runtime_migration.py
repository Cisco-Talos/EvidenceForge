# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Contracts for the final production legacy timing-helper migration."""

from __future__ import annotations

import ast
import json
import os
import subprocess
import sys
import textwrap
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from unittest.mock import Mock

from evidenceforge.events.contexts import HostContext
from evidenceforge.generation.actions.rdp_session import (
    RdpSessionActionBundle,
    RdpSessionRequest,
)
from evidenceforge.generation.actions.ssh_session import (
    SshSessionActionBundle,
    SshSessionRequest,
)
from evidenceforge.generation.activity import timing_profiles as timing_profiles_module
from evidenceforge.generation.activity.generator import (
    ActivityGenerator,
    _zeek_conn_observation_time,
)
from evidenceforge.generation.activity.timing_profiles import sample_packet_timing_delta
from evidenceforge.generation.baseline_timing import BaselineTimingPlanner
from evidenceforge.generation.state_manager import StateManager
from evidenceforge.generation.timing import TimingRuntime
from evidenceforge.models.scenario import System, User

_START = datetime(2024, 1, 15, 10, tzinfo=UTC)
_GENERATION_ROOT = Path(timing_profiles_module.__file__).parents[1]


class _SshPlanExecutor:
    """Minimal direct fixture for the allocation-free SSH transport planner."""

    def __init__(self, runtime: TimingRuntime) -> None:
        self.timing_runtime = runtime
        self._ip_to_system: dict[str, System] = {}
        self._network_visibility = None
        self.dispatcher = SimpleNamespace(visibility_engine=None)

    def reserve_ssh_source_port(
        self,
        _src_ip: str,
        _dst_ip: str,
        requested_port: int | None,
        _rng: Any,
        _os_category: str,
        *,
        time: datetime,
    ) -> int:
        """Return the fixture's explicit source port without additional state."""

        assert time == _START
        assert requested_port is not None
        return requested_port

    @staticmethod
    def _build_host_context(system: System) -> HostContext:
        """Build the exact host context needed by transport preflight."""

        return HostContext(
            hostname=system.hostname,
            ip=system.ip,
            os=system.os,
            os_category="windows" if "windows" in system.os.casefold() else "linux",
            system_type=system.type,
        )


def _user() -> User:
    return User(username="analyst", full_name="Alicia Analyst", email="a@example.test")


def _windows(hostname: str, ip: str) -> System:
    return System(hostname=hostname, ip=ip, os="Windows 11", type="workstation")


def _ssh_bundle(runtime: TimingRuntime) -> SshSessionActionBundle:
    source = _windows("WS-01", "10.0.0.10")
    target = System(
        hostname="LNX-01",
        ip="10.0.0.20",
        os="Ubuntu 24.04",
        type="server",
        services=["ssh"],
    )
    return SshSessionActionBundle(
        executor=_SshPlanExecutor(runtime),  # type: ignore[arg-type]
        request=SshSessionRequest(
            user=_user(),
            target_system=target,
            time=_START,
            source_ip=source.ip,
            source_system=source,
            source_port=51111,
            duration=60.0,
            orig_bytes=2048,
            resp_bytes=8192,
            source="timing_runtime_test",
        ),
    )


def test_packet_observation_distribution_preserves_bounds_and_runtime_scope() -> None:
    """The typed replacement is bounded, non-lattice, audited, and order independent."""

    forward_runtime = TimingRuntime(reference_time=_START, namespace="packet-family")
    reverse_runtime = TimingRuntime(reference_time=_START, namespace="packet-family")
    forward = BaselineTimingPlanner(forward_runtime, source="network")
    reverse = BaselineTimingPlanner(reverse_runtime, source="network")
    stable_ids = tuple(f"flow-{index}" for index in range(128))

    def samples(planner: BaselineTimingPlanner, values: tuple[str, ...]) -> dict[str, timedelta]:
        return {
            stable_id: planner.packet_observation_delta(
                relationship_key="network.connection_start_jitter",
                stable_id=stable_id,
                minimum_ms=0,
                maximum_ms=850,
                host="10.0.0.10",
                lifecycle_id=stable_id,
                sample_key="transport_open",
            )
            for stable_id in values
        }

    forward_samples = samples(forward, stable_ids)
    reverse_samples = samples(reverse, tuple(reversed(stable_ids)))

    assert forward_samples == reverse_samples
    assert all(
        timedelta(microseconds=37) <= value <= timedelta(microseconds=850_997)
        for value in forward_samples.values()
    )
    assert all(value.microseconds % 1_000 for value in forward_samples.values())
    audit = forward_runtime.audit.snapshot()
    assert audit.sample_counts == {"network.connection_start_jitter": len(stable_ids)}
    assert audit.distribution_counts == {"triangular": len(stable_ids)}


def test_legacy_packet_helper_is_stateless_and_does_not_compose_legacy_delta(
    monkeypatch: Any,
) -> None:
    """The direct compatibility helper uses the typed distribution in isolation."""

    def reject_legacy_delta(*_args: Any, **_kwargs: Any) -> timedelta:
        raise AssertionError("sample_packet_timing_delta composed sample_timing_delta")

    monkeypatch.setattr(timing_profiles_module, "sample_timing_delta", reject_legacy_delta)
    seed_parts = ("10.0.0.10", 51111, "10.0.0.20", 22, "tcp", "ssh", _START)
    first = sample_packet_timing_delta(
        "network.connection_start_jitter",
        seed_parts=seed_parts,
    )
    second = sample_packet_timing_delta(
        "network.connection_start_jitter",
        seed_parts=seed_parts,
    )

    assert first == second
    assert timedelta(microseconds=37) <= first <= timedelta(microseconds=850_997)
    assert first.microseconds % 1_000


def test_rdp_target_logon_uses_one_engine_runtime_scope() -> None:
    """RDP target authentication is repeatable and bounded after canonical transport."""

    runtime = TimingRuntime(reference_time=_START, namespace="rdp-target-logon")
    target = System(
        hostname="APP-01",
        ip="10.0.0.30",
        os="Windows Server 2022",
        type="server",
    )
    bundle = RdpSessionActionBundle(
        executor=SimpleNamespace(timing_runtime=runtime),  # type: ignore[arg-type]
        request=RdpSessionRequest(
            user=_user(),
            target_system=target,
            time=_START,
            source_ip="10.0.0.10",
        ),
    )

    first = bundle._target_logon_time(
        source_ip="10.0.0.10",
        src_port=52875,
        transport_start_time=_START,
    )
    second = bundle._target_logon_time(
        source_ip="10.0.0.10",
        src_port=52875,
        transport_start_time=_START,
    )

    assert first == second
    assert _START + timedelta(milliseconds=900) <= first
    assert first <= _START + timedelta(milliseconds=1600)
    audit = runtime.audit.snapshot()
    assert audit.sample_counts == {"rdp.target_logon_after_transport": 2}
    assert audit.distribution_counts == {"triangular": 2}


def test_ssh_transport_plan_computes_one_runtime_owned_open_anchor() -> None:
    """SSH planning and responder prediction share one exact sampled transport time."""

    first_runtime = TimingRuntime(reference_time=_START, namespace="ssh-transport-open")
    second_runtime = TimingRuntime(reference_time=_START, namespace="ssh-transport-open")
    first_bundle = _ssh_bundle(first_runtime)
    second_bundle = _ssh_bundle(second_runtime)

    first_state = first_bundle._plan_transport()
    second_state = second_bundle._plan_transport()

    assert first_state.open_time == second_state.open_time
    assert isinstance(first_state.open_time, datetime)
    assert _START + timedelta(microseconds=37) <= first_state.open_time
    assert first_state.open_time <= _START + timedelta(microseconds=850_997)
    before_prediction = first_runtime.audit.snapshot()
    assert first_bundle._predicted_transport_open_time(first_state) == first_state.open_time
    assert first_bundle._predicted_transport_open_time(first_state) == first_state.open_time
    assert first_runtime.audit.snapshot() == before_prediction
    assert before_prediction.sample_counts == {"network.connection_start_jitter": 1}
    assert before_prediction.distribution_counts == {"triangular": 1}


def test_network_transaction_caller_commits_the_engine_runtime_sample() -> None:
    """The real planner sibling commits connection spacing to its injected runtime."""

    runtime = TimingRuntime(reference_time=_START, namespace="network-transaction-caller")
    state = StateManager()
    state.set_current_time(_START)
    emitter = Mock()
    emitter.can_handle.return_value = True
    generator = ActivityGenerator(
        state,
        {"zeek_conn": emitter},
        timing_runtime=runtime,
    )

    generator.generate_connection(
        src_ip="10.0.0.10",
        dst_ip="10.0.0.20",
        time=_START,
        src_port=51111,
        dst_port=443,
        proto="tcp",
        service="ssl",
        duration=1.0,
        orig_bytes=512,
        resp_bytes=2048,
    )

    event = next(
        call.args[0]
        for call in emitter.emit.call_args_list
        if call.args[0].event_type == "connection"
    )
    assert _START + timedelta(microseconds=37) <= event.timestamp
    assert event.timestamp <= _START + timedelta(microseconds=850_997)
    audit = runtime.audit.snapshot()
    assert audit.sample_counts["network.connection_start_jitter"] == 1
    assert audit.distribution_counts["triangular"] >= 1


def _worker_samples(worker_count: int) -> tuple[tuple[str, ...], dict[str, int]]:
    runtime = TimingRuntime(reference_time=_START, namespace="network-worker-determinism")

    def sample(index: int) -> str:
        return _zeek_conn_observation_time(
            _START + timedelta(microseconds=index * 101),
            "10.0.0.10",
            40000 + index,
            "10.0.0.20",
            443,
            "tcp",
            "ssl",
            timing_runtime=runtime,
        ).isoformat()

    with ThreadPoolExecutor(max_workers=worker_count) as pool:
        values = tuple(pool.map(sample, range(64)))
    return values, dict(runtime.audit.snapshot().sample_counts)


def test_network_timing_family_is_worker_deterministic() -> None:
    """The migrated tuple scope is independent of worker arrival order."""

    assert _worker_samples(1) == _worker_samples(8)


def test_network_timing_family_is_pythonhashseed_deterministic() -> None:
    """The production helper does not inherit Python hash randomization."""

    script = textwrap.dedent(
        """
        import json
        from concurrent.futures import ThreadPoolExecutor
        from datetime import UTC, datetime, timedelta

        from evidenceforge.generation.activity.generator import _zeek_conn_observation_time
        from evidenceforge.generation.timing import TimingRuntime

        start = datetime(2024, 1, 15, 10, tzinfo=UTC)
        runtime = TimingRuntime(reference_time=start, namespace="network-hash-determinism")

        def sample(index):
            return _zeek_conn_observation_time(
                start + timedelta(microseconds=index * 101),
                "10.0.0.10",
                40000 + index,
                "10.0.0.20",
                443,
                "tcp",
                "ssl",
                timing_runtime=runtime,
            ).isoformat()

        with ThreadPoolExecutor(max_workers=8) as pool:
            values = tuple(pool.map(sample, range(64)))
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


def test_migrated_timing_sibling_callers_are_exact_and_runtime_wired() -> None:
    """Every owned helper has only its intended production and compatibility siblings."""

    targets = {
        "_target_logon_time",
        "_plan_transport",
        "_predicted_transport_open_time",
        "_zeek_conn_observation_time",
        "packet_observation_delta",
    }
    owned_functions = {
        ("actions/rdp_session.py", "_target_logon_time"),
        ("actions/ssh_session.py", "_plan_transport"),
        ("actions/ssh_session.py", "_predicted_transport_open_time"),
        ("actions/ssh_session.py", "_transport_open_time"),
        ("activity/generator.py", "_zeek_conn_observation_time"),
    }
    observed: set[tuple[str, str, str]] = set()
    owned_legacy_calls: set[tuple[str, str, str]] = set()
    production_packet_helper_calls: set[tuple[str, str]] = set()
    zeek_call: ast.Call | None = None
    for path in sorted(_GENERATION_ROOT.rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        parents = {
            child: parent for parent in ast.walk(tree) for child in ast.iter_child_nodes(parent)
        }
        relative = path.relative_to(_GENERATION_ROOT).as_posix()
        for call in (node for node in ast.walk(tree) if isinstance(node, ast.Call)):
            called = ""
            if isinstance(call.func, ast.Name):
                called = call.func.id
            elif isinstance(call.func, ast.Attribute):
                called = call.func.attr
            if called not in targets | {
                "sample_packet_timing_delta",
                "sample_timing_delta",
            }:
                continue
            current: ast.AST = call
            while current in parents and not isinstance(current, ast.FunctionDef):
                current = parents[current]
            if not isinstance(current, ast.FunctionDef):
                continue
            if called in targets:
                observed.add((relative, current.name, called))
            if called == "sample_packet_timing_delta":
                production_packet_helper_calls.add((relative, current.name))
            if (relative, current.name) in owned_functions and called in {
                "sample_packet_timing_delta",
                "sample_timing_delta",
            }:
                owned_legacy_calls.add((relative, current.name, called))
            if relative == "actions/network_transaction_planner.py" and called == (
                "_zeek_conn_observation_time"
            ):
                zeek_call = call

    assert owned_legacy_calls == set()
    assert production_packet_helper_calls == set()
    assert observed == {
        ("actions/network_transaction_planner.py", "_execute", "_zeek_conn_observation_time"),
        ("actions/rdp_session.py", "execute", "_target_logon_time"),
        ("actions/ssh_session.py", "_resolve_responder_pid", "_predicted_transport_open_time"),
        ("actions/ssh_session.py", "_transport_open_time", "packet_observation_delta"),
        ("actions/ssh_session.py", "execute_with_identity", "_plan_transport"),
        ("activity/generator.py", "_zeek_conn_observation_time", "packet_observation_delta"),
        ("activity/timing_profiles.py", "sample_packet_timing_delta", "packet_observation_delta"),
    }
    assert zeek_call is not None
    timing_keyword = next(
        (keyword.value for keyword in zeek_call.keywords if keyword.arg == "timing_runtime"),
        None,
    )
    assert isinstance(timing_keyword, ast.Attribute)
    assert timing_keyword.attr == "_timing_runtime"
