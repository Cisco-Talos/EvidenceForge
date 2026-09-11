# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Engine-owned timing contracts for outbound email MTA process placement."""

from __future__ import annotations

import ast
import inspect
import json
import os
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
    _email_mta_outbound_process_lead_distribution,
)
from evidenceforge.generation.source_timing import SourceTimingPlanner
from evidenceforge.generation.state_manager import StateManager
from evidenceforge.generation.timing import TimingRuntime
from evidenceforge.models import System
from evidenceforge.models.exceptions import StateError

_START = datetime(2026, 2, 3, 14, tzinfo=UTC)


def _generator() -> ActivityGenerator:
    state = StateManager()
    state.set_current_time(_START - timedelta(hours=1))
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


def _sampler(runtime: object) -> ActivityGenerator:
    generator = ActivityGenerator.__new__(ActivityGenerator)
    generator.timing_runtime = runtime
    return generator


def _linux_mail_system() -> System:
    return System(
        hostname="MAIL-EDGE-01",
        ip="10.10.2.25",
        os="Ubuntu 22.04",
        type="server",
        services=["smtp", "postfix"],
        roles=["mail_server"],
    )


def _register_systemd(generator: ActivityGenerator, system: System) -> None:
    generator.state_manager.register_process(
        system=system.hostname,
        pid=1,
        parent_pid=0,
        image="/usr/lib/systemd/systemd",
        command_line="/usr/lib/systemd/systemd --system",
        username="root",
        integrity_level="System",
        os_category="linux",
    )
    generator._system_pids = {system.hostname: {"systemd": 1}}


def test_email_mta_distribution_preserves_exact_inclusive_uniform_support() -> None:
    """The edge mixture rounds to the former uniform integer range without endpoint loss."""

    distribution = _email_mta_outbound_process_lead_distribution()
    assert tuple(component.weight for component in distribution.components) == (1.0, 1.0)
    left, right = (component.distribution for component in distribution.components)
    assert (left.minimum, left.mode, left.maximum) == (179.5, 179.5, 850.5)
    assert (right.minimum, right.mode, right.maximum) == (179.5, 850.5, 850.5)

    generator = _sampler(TimingRuntime(reference_time=_START, namespace="email-mta-pmf"))
    counts = Counter(
        generator._sample_email_mta_outbound_process_lead_milliseconds(
            hostname="MAIL-EDGE-01",
            image="/usr/lib/postfix/sbin/smtp",
            activity_time=_START + timedelta(microseconds=index),
        )
        for index in range(40_000)
    )
    assert set(counts) == set(range(180, 851))
    expected = 40_000 / 671
    chi_squared = sum((count - expected) ** 2 / expected for count in counts.values())
    assert chi_squared < 780.0


def test_email_mta_timing_rejects_foreign_authority_before_callbacks() -> None:
    """Duck runtimes and hostile scope values cannot intercept the owner seam."""

    callbacks: list[str] = []

    class ForeignRuntime:
        @property
        def sampler(self) -> object:
            callbacks.append("sampler")
            raise RuntimeError("foreign sampler reached")

    class HostileString(str):
        def __bool__(self) -> bool:
            callbacks.append("string-bool")
            raise RuntimeError("hostile string reached")

    class RuntimeSubclass(TimingRuntime):
        pass

    common = {
        "hostname": "MAIL-EDGE-01",
        "image": "/usr/lib/postfix/sbin/smtp",
        "activity_time": _START,
    }
    with pytest.raises(StateError, match="exact engine-owned runtime"):
        _sampler(ForeignRuntime())._sample_email_mta_outbound_process_lead_milliseconds(**common)
    with pytest.raises(StateError, match="exact engine-owned runtime"):
        _sampler(
            RuntimeSubclass(reference_time=_START, namespace="email-mta-subclass")
        )._sample_email_mta_outbound_process_lead_milliseconds(**common)
    with pytest.raises(StateError, match="exact built-in values"):
        _sampler(
            TimingRuntime(reference_time=_START, namespace="email-mta-hostile-scope")
        )._sample_email_mta_outbound_process_lead_milliseconds(
            **{**common, "hostname": HostileString("MAIL-EDGE-01")}
        )
    assert callbacks == []


def test_email_mta_direct_and_prepared_sampling_match_and_cancel_is_neutral() -> None:
    """Prepared sampling retains exact value/audit parity without early owner mutation."""

    direct_runtime = TimingRuntime(
        reference_time=_START - timedelta(hours=1),
        namespace="email-mta-direct-prepared",
    )
    staged_runtime = TimingRuntime(
        reference_time=_START - timedelta(hours=1),
        namespace="email-mta-direct-prepared",
    )
    owner = SourceTimingPlanner(
        "enterprise_standard",
        timing_runtime=staged_runtime,
    )
    common = {
        "hostname": "MAIL-EDGE-01",
        "image": "/usr/lib/postfix/sbin/smtp",
        "activity_time": _START,
    }
    direct = _sampler(direct_runtime)
    direct_value = direct._sample_email_mta_outbound_process_lead_milliseconds(**common)
    direct_audit = direct_runtime.audit.snapshot()
    before_staged_audit = staged_runtime.audit.snapshot()

    with owner.prepared_planning() as preparation:
        staged = _sampler(preparation.planning_runtime)
        assert staged._sample_email_mta_outbound_process_lead_milliseconds(**common) == direct_value
        assert preparation.staged_audit_operations == 1
        assert staged_runtime.audit.snapshot() == before_staged_audit

    with preparation.claimed_commit():
        preparation.commit_no_fail()
    assert preparation.receipt is not None
    assert owner.authenticates_preparation_receipt(preparation.receipt)
    assert staged_runtime.audit.snapshot() == direct_audit

    cancel_runtime = TimingRuntime(
        reference_time=_START - timedelta(hours=1),
        namespace="email-mta-cancel",
    )
    cancel_owner = SourceTimingPlanner("enterprise_standard", timing_runtime=cancel_runtime)
    cancel_before = cancel_runtime.audit.snapshot()
    with cancel_owner.prepared_planning() as cancelled:
        _sampler(cancelled.planning_runtime)._sample_email_mta_outbound_process_lead_milliseconds(
            **common
        )
        assert cancelled.staged_audit_operations == 1
    cancelled.cancel()
    assert cancel_runtime.audit.snapshot() == cancel_before


def test_email_mta_worker_creation_samples_once_and_reuse_is_audit_neutral() -> None:
    """Only a newly materialized Postfix SMTP worker consumes process-lead timing."""

    generator = _generator()
    system = _linux_mail_system()
    _register_systemd(generator, system)

    first_pid = generator._ensure_email_mta_outbound_process(system, time=_START)
    first_process = generator.state_manager.get_process(system.hostname, first_pid)
    assert first_process is not None
    lead = _START - first_process.start_time
    assert timedelta(milliseconds=180) <= lead <= timedelta(milliseconds=850)
    first_audit = generator.timing_runtime.audit.snapshot()
    assert dict(first_audit.sample_counts)["activity.email.mta_outbound_process_lead"] == 1

    second_pid = generator._ensure_email_mta_outbound_process(
        system,
        time=_START + timedelta(minutes=2),
    )
    assert second_pid == first_pid
    assert generator.timing_runtime.audit.snapshot() == first_audit


def test_email_mta_prepared_worker_failure_leaves_no_timing_or_process_residue() -> None:
    """A rejected worker materialization cannot publish its staged timing sample."""

    runtime = TimingRuntime(reference_time=_START, namespace="email-mta-worker-fault")
    owner = SourceTimingPlanner("enterprise_standard", timing_runtime=runtime)
    generator = _generator()
    system = _linux_mail_system()
    _register_systemd(generator, system)
    before_audit = runtime.audit.snapshot()
    generator._ensure_profiled_service_worker = Mock(
        side_effect=RuntimeError("reject outbound MTA worker")
    )

    with pytest.raises(RuntimeError, match="reject outbound MTA worker"):
        with owner.prepared_planning() as preparation:
            generator.timing_runtime = preparation.planning_runtime
            generator._ensure_email_mta_outbound_process(system, time=_START)

    assert runtime.audit.snapshot() == before_audit
    assert all(
        process.image != "/usr/lib/postfix/sbin/smtp"
        for process in generator.state_manager.get_processes_on_system(system.hostname)
    )


def test_email_mta_windows_delegation_consumes_no_outbound_worker_sample() -> None:
    """Windows mail ownership stays with the server process path without a phantom draw."""

    generator = _generator()
    system = System(
        hostname="MAIL-WIN-01",
        ip="10.10.2.27",
        os="Windows Server 2022",
        type="server",
        services=["smtp", "exchange"],
        roles=["mail_server"],
    )
    generator._ensure_email_server_process = Mock(return_value=4242)
    before = generator.timing_runtime.audit.snapshot()

    assert generator._ensure_email_mta_outbound_process(system, time=_START) == 4242
    assert generator.timing_runtime.audit.snapshot() == before


def test_email_mta_timing_is_worker_order_and_hashseed_independent() -> None:
    """Stable MTA scopes produce the same samples across worker order and hash seeds."""

    def population(order: tuple[int, ...], workers: int) -> dict[int, int]:
        generator = _sampler(TimingRuntime(reference_time=_START, namespace="email-mta-workers"))

        def sample(index: int) -> tuple[int, int]:
            return (
                index,
                generator._sample_email_mta_outbound_process_lead_milliseconds(
                    hostname=f"MAIL-{index % 4:02d}",
                    image="/usr/lib/postfix/sbin/smtp",
                    activity_time=_START + timedelta(seconds=index),
                ),
            )

        with ThreadPoolExecutor(max_workers=workers) as executor:
            return dict(executor.map(sample, order))

    assert population(tuple(range(48)), 1) == population(tuple(reversed(range(48))), 8)

    source_root = Path(__file__).resolve().parents[2] / "src"
    script = """
import json
from datetime import UTC, datetime, timedelta
from evidenceforge.generation.activity import ActivityGenerator
from evidenceforge.generation.timing import TimingRuntime

start = datetime(2026, 2, 3, 14, tzinfo=UTC)
generator = ActivityGenerator.__new__(ActivityGenerator)
generator.timing_runtime = TimingRuntime(reference_time=start, namespace="email-mta-hashseed")
print(json.dumps([
    generator._sample_email_mta_outbound_process_lead_milliseconds(
        hostname=f"MAIL-{index % 4:02d}",
        image="/usr/lib/postfix/sbin/smtp",
        activity_time=start + timedelta(seconds=index),
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


def test_email_mta_production_path_has_no_private_temporal_rng() -> None:
    """Outbound MTA placement routes both former draws through the owned sampler."""

    source = textwrap.dedent(
        inspect.getsource(ActivityGenerator._ensure_email_mta_outbound_process)
    )
    tree = ast.parse(source)
    called_names = [
        node.func.attr
        for node in ast.walk(tree)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
    ]
    assert "randint" not in called_names
    assert "randrange" not in called_names
    assert source.count("_sample_email_mta_outbound_process_lead_milliseconds(") == 2
    assert "_stable_seed" not in source
    assert "random.Random" not in source
