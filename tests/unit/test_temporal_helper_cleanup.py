# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Focused contracts for the final compatibility timing-helper cleanup."""

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
from unittest.mock import Mock

import pytest

from evidenceforge.generation.actions.auth_session import LogonRequest
from evidenceforge.generation.actions.scanner_probe import NmapCommandProbeRequest
from evidenceforge.generation.actions.ssh_session import (
    SshSessionActionBundle,
    SshSessionRequest,
)
from evidenceforge.generation.activity import generator as generator_module
from evidenceforge.generation.activity.generator import ActivityGenerator
from evidenceforge.generation.source_timing import SourceTimingPlanner
from evidenceforge.generation.state_manager import StateManager
from evidenceforge.generation.timing import TimingRuntime, TimingSampler
from evidenceforge.models.scenario import System, User

_START = datetime(2024, 3, 18, 10, tzinfo=UTC)
_READY_RELATIONSHIP = "windows.remote_logon_source_ready"
_PROCESS_RELATIONSHIP = "source.ecar_dependent_after_process_create"
_SSH_RELATIONSHIP = "source.ecar_ssh_session_after_accept"


def _user() -> User:
    return User(username="analyst", full_name="Alicia Analyst", email="a@example.test")


def _windows() -> System:
    return System(hostname="WS-01", ip="10.0.0.10", os="Windows 11", type="workstation")


def _linux() -> System:
    return System(hostname="LNX-01", ip="10.0.0.20", os="Ubuntu 24.04", type="server")


def _generator(runtime: TimingRuntime) -> ActivityGenerator:
    emitters = {name: Mock() for name in ("windows_event_security", "ecar", "syslog", "zeek_conn")}
    return ActivityGenerator(StateManager(), emitters, timing_runtime=runtime)


def _called_name(call: ast.Call) -> str:
    if isinstance(call.func, ast.Name):
        return call.func.id
    if isinstance(call.func, ast.Attribute):
        return call.func.attr
    return ""


def _function(tree: ast.Module, name: str) -> ast.FunctionDef:
    return next(
        node for node in ast.walk(tree) if isinstance(node, ast.FunctionDef) and node.name == name
    )


def _sample_keys(function: ast.FunctionDef, called_name: str) -> tuple[str, ...]:
    calls: list[tuple[int, str]] = []
    for call in (node for node in ast.walk(function) if isinstance(node, ast.Call)):
        if _called_name(call) != called_name:
            continue
        sample_key = next(
            (keyword.value for keyword in call.keywords if keyword.arg == "sample_key"),
            None,
        )
        assert isinstance(sample_key, ast.Constant) and isinstance(sample_key.value, str)
        calls.append((call.lineno, sample_key.value))
    return tuple(value for _line, value in sorted(calls))


def test_nine_migrated_sites_freeze_exact_sample_keys_before_compatibility_mutation() -> None:
    """The compatibility adapters freeze all nine semantic draws exactly once."""

    generation_root = Path(generator_module.__file__).parents[1]
    generator_path = Path(generator_module.__file__)
    ssh_path = generation_root / "actions" / "ssh_session.py"
    generator_tree = ast.parse(generator_path.read_text(encoding="utf-8"))
    ssh_tree = ast.parse(ssh_path.read_text(encoding="utf-8"))
    expected = {
        "_execute_logon_bundle": ("remote_source_ready",),
        "_execute_logoff_bundle": (
            "ssh_transport_close_gap",
            "last_activity_gap",
            "rendered_dependents_gap",
            "ecar_logout_gap",
            "windows_security_logout_gap",
        ),
        "_clamp_after_visible_linux_process_create": ("visible_create_gap",),
        "_nmap_probe_anchor_after_visible_process_create": ("probe_readiness_gap",),
    }
    assert {
        name: _sample_keys(_function(generator_tree, name), "_freeze_profile_activity_gap")
        for name in expected
    } == expected
    assert _sample_keys(
        _function(ssh_tree, "_freeze_linux_ecar_readiness"),
        "sample_timedelta",
    ) == ("ecar_session_ready",)

    logon = _function(generator_tree, "_execute_logon_bundle")
    assert min(
        call.lineno
        for call in ast.walk(logon)
        if isinstance(call, ast.Call) and _called_name(call) == "_freeze_profile_activity_gap"
    ) < min(
        call.lineno
        for call in ast.walk(logon)
        if isinstance(call, ast.Call) and _called_name(call) == "set_current_time"
    )
    logoff = _function(generator_tree, "_execute_logoff_bundle")
    assert max(
        call.lineno
        for call in ast.walk(logoff)
        if isinstance(call, ast.Call) and _called_name(call) == "_freeze_profile_activity_gap"
    ) < min(
        call.lineno
        for call in ast.walk(logoff)
        if isinstance(call, ast.Call) and _called_name(call) == "plan_session_end"
    )
    execute_ssh = _function(ssh_tree, "execute_with_identity")
    freeze_lines = [
        call.lineno
        for call in ast.walk(execute_ssh)
        if isinstance(call, ast.Call) and _called_name(call) == "_freeze_linux_ecar_readiness"
    ]
    transport_lines = [
        call.lineno
        for call in ast.walk(execute_ssh)
        if isinstance(call, ast.Call) and _called_name(call) == "_plan_transport"
    ]
    assert len(freeze_lines) == 1
    assert any(freeze_lines[0] < line for line in transport_lines)


@pytest.mark.parametrize("failure_mode", ("fail-before", "lost-return"))
def test_remote_logon_freeze_faults_before_state_or_audit_mutation(
    monkeypatch: pytest.MonkeyPatch,
    failure_mode: str,
) -> None:
    """A sampler failure, including lost return, cannot reach compatibility State."""

    runtime = TimingRuntime(reference_time=_START, namespace=f"logon-{failure_mode}")
    generator = object.__new__(ActivityGenerator)
    generator.timing_runtime = runtime
    generator.state_manager = Mock()
    original = TimingSampler.sample_timedelta

    def fail(
        sampler: TimingSampler,
        distribution: object,
        *,
        relationship_key: str,
        scope: object,
        sample_key: str = "value",
    ) -> timedelta:
        if relationship_key == _READY_RELATIONSHIP:
            if failure_mode == "lost-return":
                original(
                    sampler,
                    distribution,  # type: ignore[arg-type]
                    relationship_key=relationship_key,
                    scope=scope,  # type: ignore[arg-type]
                    sample_key=sample_key,
                )
            raise RuntimeError(f"timing {failure_mode}")
        return original(
            sampler,
            distribution,  # type: ignore[arg-type]
            relationship_key=relationship_key,
            scope=scope,  # type: ignore[arg-type]
            sample_key=sample_key,
        )

    monkeypatch.setattr(TimingSampler, "sample_timedelta", fail)
    with pytest.raises(RuntimeError, match=failure_mode):
        generator._execute_logon_bundle(
            LogonRequest(
                user=_user(),
                system=_windows(),
                time=_START,
                logon_type=3,
                source_ip="10.0.0.30",
            )
        )

    assert generator.state_manager.mock_calls == []
    assert runtime.audit.snapshot().total_samples == 0


def test_remote_logon_samples_once_and_rejection_leaves_no_target_audit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Success publishes one draw; a later compatibility rejection publishes none."""

    original = TimingSampler.sample_timedelta
    calls = 0

    def count(
        sampler: TimingSampler,
        distribution: object,
        *,
        relationship_key: str,
        scope: object,
        sample_key: str = "value",
    ) -> timedelta:
        nonlocal calls
        if relationship_key == _READY_RELATIONSHIP:
            calls += 1
        return original(
            sampler,
            distribution,  # type: ignore[arg-type]
            relationship_key=relationship_key,
            scope=scope,  # type: ignore[arg-type]
            sample_key=sample_key,
        )

    monkeypatch.setattr(TimingSampler, "sample_timedelta", count)
    success_runtime = TimingRuntime(reference_time=_START, namespace="logon-success")
    success = _generator(success_runtime)
    success.generate_logon(
        _user(),
        _windows(),
        _START,
        logon_type=3,
        source_ip="10.0.0.30",
        emit_network_evidence=False,
    )
    assert calls == 1
    assert success_runtime.audit.snapshot().sample_counts[_READY_RELATIONSHIP] == 1

    rejected_runtime = TimingRuntime(reference_time=_START, namespace="logon-rejected")
    rejected = _generator(rejected_runtime)
    original_dispatch = rejected.dispatcher.dispatch_builder

    def reject_logon(event: object) -> dict[str, str]:
        if getattr(event, "event_type", "") == "logon":
            raise RuntimeError("logon publication rejected")
        return original_dispatch(event)  # type: ignore[arg-type]

    rejected.dispatcher.dispatch_builder = reject_logon  # type: ignore[method-assign]
    with pytest.raises(RuntimeError, match="publication rejected"):
        rejected.generate_logon(
            _user(),
            _windows(),
            _START,
            logon_type=3,
            source_ip="10.0.0.30",
            emit_network_evidence=False,
        )
    assert _READY_RELATIONSHIP not in rejected_runtime.audit.snapshot().sample_counts


@pytest.mark.parametrize("reject", (False, True))
def test_logoff_publishes_frozen_gap_only_after_compatibility_success(
    monkeypatch: pytest.MonkeyPatch,
    reject: bool,
) -> None:
    """A rejected public logoff leaves no audit claim for its frozen gap."""

    runtime = TimingRuntime(reference_time=_START, namespace=f"logoff-{reject}")
    generator = _generator(runtime)
    system = _windows()
    user = _user()
    generator.state_manager.set_current_time(_START)
    logon_id = generator.state_manager.create_session(
        username=user.username,
        system=system.hostname,
        logon_type=2,
        source_ip="-",
        start_time=_START,
    )
    session = generator.state_manager.get_session(logon_id)
    assert session is not None
    session.last_activity_time = _START + timedelta(minutes=5)

    if reject:
        original_dispatch = generator.dispatcher.dispatch_builder

        def reject_logoff(event: object) -> dict[str, str]:
            if getattr(event, "event_type", "") == "logoff":
                raise RuntimeError("logoff publication rejected")
            return original_dispatch(event)  # type: ignore[arg-type]

        monkeypatch.setattr(generator.dispatcher, "dispatch_builder", reject_logoff)
        with pytest.raises(RuntimeError, match="publication rejected"):
            generator.generate_logoff(
                user,
                system,
                _START + timedelta(minutes=5),
                logon_id,
            )
    else:
        generator.generate_logoff(
            user,
            system,
            _START + timedelta(minutes=5),
            logon_id,
        )

    count = runtime.audit.snapshot().sample_counts.get("windows.logoff_after_last_activity", 0)
    assert count == (0 if reject else 1)


def test_linux_visibility_delta_is_source_timing_cancel_neutral() -> None:
    """A staged helper publication disappears when its existing owner cancels."""

    runtime = TimingRuntime(reference_time=_START, namespace="linux-visibility-cancel")
    owner = SourceTimingPlanner("enterprise_standard", timing_runtime=runtime)
    generator = object.__new__(ActivityGenerator)
    generator.timing_runtime = runtime
    generator._process_source_create_times = {(_linux().hostname, 4242): _START}
    generator._process_source_create_latest = {}
    before = runtime.audit.snapshot()

    with owner.prepared_planning() as preparation:
        result = generator._clamp_after_visible_linux_process_create(
            _linux(),
            4242,
            _START,
        )
        assert result > _START
        assert preparation.staged_audit_operations == 1
        assert runtime.audit.snapshot() == before
    preparation.cancel()
    assert runtime.audit.snapshot() == before


@pytest.mark.parametrize("reject", (False, True))
def test_nmap_anchor_publishes_once_only_after_probe_success(reject: bool) -> None:
    """The scanner adapter retains or discards its one frozen anchor with the action."""

    runtime = TimingRuntime(reference_time=_START, namespace=f"nmap-{reject}")
    generator = object.__new__(ActivityGenerator)
    generator.timing_runtime = runtime
    generator._ip_to_system = {}
    generator._process_source_create_times = {(_linux().hostname, 4242): _START}
    generator._process_source_create_latest = {}
    generator._emit_nmap_discovery_probes = Mock(
        side_effect=RuntimeError("probe publication rejected") if reject else None
    )
    request = NmapCommandProbeRequest(
        user=_user(),
        system=_linux(),
        time=_START,
        pid=4242,
        process_name="/usr/bin/nmap",
        command_line="nmap -sn 10.0.0.30",
    )

    if reject:
        with pytest.raises(RuntimeError, match="publication rejected"):
            generator._execute_nmap_command_probe_bundle(request)
        assert _PROCESS_RELATIONSHIP not in runtime.audit.snapshot().sample_counts
    else:
        assert generator._execute_nmap_command_probe_bundle(request) == 1
        assert runtime.audit.snapshot().sample_counts[_PROCESS_RELATIONSHIP] == 1


@pytest.mark.parametrize("failure_mode", ("fail-before", "lost-return"))
def test_ssh_readiness_faults_before_transport_planning(
    monkeypatch: pytest.MonkeyPatch,
    failure_mode: str,
) -> None:
    """Compatibility SSH freezes readiness before reserving its transport tuple."""

    runtime = TimingRuntime(reference_time=_START, namespace=f"ssh-{failure_mode}")
    executor = SimpleNamespace(timing_runtime=runtime, dispatcher=SimpleNamespace(emitters={}))
    bundle = SshSessionActionBundle(
        executor=executor,  # type: ignore[arg-type]
        request=SshSessionRequest(
            user=_user(),
            target_system=_linux(),
            time=_START,
            source_ip="10.0.0.30",
        ),
    )
    transport = Mock(side_effect=AssertionError("transport planning ran"))

    def plan_transport(_bundle: SshSessionActionBundle) -> object:
        return transport()

    monkeypatch.setattr(SshSessionActionBundle, "_plan_transport", plan_transport)
    original = TimingSampler.sample_timedelta

    def fail(
        sampler: TimingSampler,
        distribution: object,
        *,
        relationship_key: str,
        scope: object,
        sample_key: str = "value",
    ) -> timedelta:
        if relationship_key == _SSH_RELATIONSHIP:
            if failure_mode == "lost-return":
                original(
                    sampler,
                    distribution,  # type: ignore[arg-type]
                    relationship_key=relationship_key,
                    scope=scope,  # type: ignore[arg-type]
                    sample_key=sample_key,
                )
            raise RuntimeError(f"ssh timing {failure_mode}")
        return original(
            sampler,
            distribution,  # type: ignore[arg-type]
            relationship_key=relationship_key,
            scope=scope,  # type: ignore[arg-type]
            sample_key=sample_key,
        )

    monkeypatch.setattr(TimingSampler, "sample_timedelta", fail)
    with pytest.raises(RuntimeError, match=failure_mode):
        bundle.execute_with_identity()
    transport.assert_not_called()
    assert runtime.audit.snapshot().total_samples == 0


def _worker_values(worker_count: int) -> tuple[tuple[str, ...], int, int]:
    runtime = TimingRuntime(reference_time=_START, namespace="helper-worker-order")
    generator = object.__new__(ActivityGenerator)
    generator.timing_runtime = runtime

    def sample(index: int) -> str:
        delta = generator._freeze_profile_activity_gap(
            _PROCESS_RELATIONSHIP,
            stable_id=f"process-{index}",
            host="LNX-01",
            source="ecar",
            lifecycle_id=str(index),
            sample_key="visible_create_gap",
        )
        delta.publish()
        return str(delta.value.total_seconds())

    with ThreadPoolExecutor(max_workers=worker_count) as pool:
        values = tuple(pool.map(sample, range(64)))
    census = runtime.census().audit
    return values, census.relationship_slots_live, census.sample_count


def test_frozen_helper_samples_are_worker_deterministic_and_census_bounded() -> None:
    """Arrival order does not alter values or exceed one bounded relationship slot."""

    serial = _worker_values(1)
    parallel = _worker_values(8)
    assert serial == parallel
    assert serial[1:] == (1, 64)


def test_frozen_helper_samples_are_pythonhashseed_deterministic() -> None:
    """Semantic SHA-256 scopes ignore interpreter hash randomization."""

    script = textwrap.dedent(
        """
        import json
        from datetime import UTC, datetime

        from evidenceforge.generation.activity.generator import ActivityGenerator
        from evidenceforge.generation.timing import TimingRuntime

        start = datetime(2024, 3, 18, 10, tzinfo=UTC)
        runtime = TimingRuntime(reference_time=start, namespace="helper-hash-seed")
        generator = object.__new__(ActivityGenerator)
        generator.timing_runtime = runtime
        values = []
        for index in range(32):
            delta = generator._freeze_profile_activity_gap(
                "source.ecar_dependent_after_process_create",
                stable_id=f"process-{index}",
                host="LNX-01",
                source="ecar",
                lifecycle_id=str(index),
                sample_key="visible_create_gap",
            )
            values.append(delta.value.total_seconds())
            delta.publish()
        print(json.dumps((values, dict(runtime.audit.snapshot().sample_counts))))
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
    values, counts = json.loads(outputs[0])
    assert len(set(values)) > 1
    assert counts == {_PROCESS_RELATIONSHIP: 32}
