# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Focused contracts for runtime-owned HTTP file-transfer timing."""

from __future__ import annotations

import ast
import json
import os
import random
import subprocess
import sys
import textwrap
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime
from pathlib import Path

import pytest

import evidenceforge.generation.actions.file_transfer as file_transfer_module
from evidenceforge.events.base import OccurrenceBuilder
from evidenceforge.events.contexts import HttpContext
from evidenceforge.generation.actions.file_transfer import (
    HttpResponseFileTransferActionBundle,
    HttpResponseFileTransferRequest,
)
from evidenceforge.generation.activity.generator import _attach_http_file_transfers
from evidenceforge.generation.source_timing import SourceTimingPlanner
from evidenceforge.generation.timing import TimingRuntime, TimingScope
from evidenceforge.models.exceptions import StateError
from evidenceforge.utils.ids import generate_zeek_uid_from_rng
from tests.network_factories import network_plan

_EVENT_TIME = datetime(2024, 10, 14, 12, tzinfo=UTC)
_PROJECT_ROOT = Path(__file__).parents[2]
_RELATIONSHIPS = {
    "file_transfer.http.analyzed_parent_fraction",
    "file_transfer.http.bulk_parent_fraction",
    "file_transfer.http.large_parent_fraction",
    "file_transfer.http.short_duration_seconds",
    "file_transfer.http.throughput_bytes_per_second",
}
_SIZES = (4_096, 100_000, 2_000_000, 12_000_000)


def _request(size: int, *, ordinal: int = 0) -> HttpResponseFileTransferRequest:
    """Return one stable response intent in a selected duration family."""

    return HttpResponseFileTransferRequest(
        host="downloads.example.test",
        uri=f"/artifact-{size}-{ordinal}.bin",
        dst_ip="93.184.216.34",
        response_body_len=size,
        response_mime_types=["application/octet-stream"],
        timestamp=_EVENT_TIME,
        parent_duration=10.0,
        source="file_transfer_timing_test",
    )


def _duration(
    runtime: TimingRuntime,
    size: int,
    *,
    ordinal: int = 0,
    rng_seed: int = 7,
) -> float:
    """Return one response-file duration through an injected runtime."""

    result = HttpResponseFileTransferActionBundle(
        _request(size, ordinal=ordinal),
        random.Random(rng_seed),
        timing_runtime=runtime,
    ).execute()
    return result.file_transfer.duration


def _four_family_durations(runtime: TimingRuntime) -> tuple[float, ...]:
    """Sample each former direct-RNG call family once."""

    return tuple(_duration(runtime, size, ordinal=index) for index, size in enumerate(_SIZES))


def test_http_transfer_direct_and_prepared_timing_commit_are_identical() -> None:
    """An active SourceTiming overlay stages all five relationships with direct parity."""

    direct_runtime = TimingRuntime(reference_time=_EVENT_TIME, namespace="file-direct-parity")
    direct = _four_family_durations(direct_runtime)

    staged_runtime = TimingRuntime(reference_time=_EVENT_TIME, namespace="file-direct-parity")
    timing_owner = SourceTimingPlanner(timing_runtime=staged_runtime)
    before_digest = staged_runtime.state_digest()
    with timing_owner.prepared_planning() as preparation:
        staged = _four_family_durations(staged_runtime)
        assert preparation.staged_audit_operations == 7
        assert staged_runtime.state_digest() == before_digest

    with preparation.claimed_commit():
        preparation.commit_no_fail()

    assert staged == direct
    assert 0.0 < direct[0] < 0.01
    assert 0.8 < direct[1] < 3.5
    assert 3.5 < direct[2] < 8.5
    assert 5.5 < direct[3] < 9.2
    assert staged_runtime.audit.snapshot() == direct_runtime.audit.snapshot()
    assert staged_runtime.audit.snapshot().sample_counts == {
        "file_transfer.http.analyzed_parent_fraction": 1,
        "file_transfer.http.bulk_parent_fraction": 1,
        "file_transfer.http.large_parent_fraction": 1,
        "file_transfer.http.short_duration_seconds": 1,
        "file_transfer.http.throughput_bytes_per_second": 3,
    }


def test_http_transfer_cancel_lost_return_retry_is_neutral_and_stable() -> None:
    """A rejected staged result retries identically with one committed sample set."""

    runtime = TimingRuntime(reference_time=_EVENT_TIME, namespace="file-cancel-retry")
    timing_owner = SourceTimingPlanner(timing_runtime=runtime)
    before_digest = runtime.state_digest()
    lost_return = 0.0

    with pytest.raises(RuntimeError, match="lose transfer return"):
        with timing_owner.prepared_planning() as preparation:
            lost_return = _duration(runtime, 2_000_000, ordinal=19)
            assert preparation.staged_audit_operations == 2
            raise RuntimeError("lose transfer return")

    assert runtime.state_digest() == before_digest
    assert runtime.audit.snapshot().sample_counts == {}

    with timing_owner.prepared_planning() as retry_preparation:
        retry = _duration(runtime, 2_000_000, ordinal=19)
    with retry_preparation.claimed_commit():
        retry_preparation.commit_no_fail()

    assert retry == lost_return
    assert runtime.audit.snapshot().sample_counts == {
        "file_transfer.http.bulk_parent_fraction": 1,
        "file_transfer.http.throughput_bytes_per_second": 1,
    }


def test_http_transfer_rejects_foreign_runtime_before_content_rng_mutation() -> None:
    """A duck-typed timing owner cannot consume FUID or profile randomness."""

    rng = random.Random(8675309)
    before_state = rng.getstate()

    class ForeignRuntime:
        sampler = TimingRuntime(reference_time=_EVENT_TIME).sampler

    with pytest.raises(StateError, match="exact engine TimingRuntime"):
        HttpResponseFileTransferActionBundle(
            _request(2_000_000),
            rng,
            timing_runtime=ForeignRuntime(),  # type: ignore[arg-type]
        )

    assert rng.getstate() == before_state


def test_http_transfer_timing_does_not_resample_from_content_rng() -> None:
    """FUID texture may differ while one semantic transfer keeps its exact duration."""

    runtime = TimingRuntime(reference_time=_EVENT_TIME, namespace="file-content-neutral")
    request = _request(12_000_000, ordinal=41)
    first_rng = random.Random(1)
    second_rng = random.Random(99)
    first = HttpResponseFileTransferActionBundle(
        request,
        first_rng,
        timing_runtime=runtime,
    ).execute()
    second = HttpResponseFileTransferActionBundle(
        request,
        second_rng,
        timing_runtime=runtime,
    ).execute()

    expected_first_rng = random.Random(1)
    expected_second_rng = random.Random(99)
    generate_zeek_uid_from_rng(expected_first_rng, "F")
    generate_zeek_uid_from_rng(expected_second_rng, "F")

    assert first.file_transfer.fuid != second.file_transfer.fuid
    assert first.file_transfer.duration == second.file_transfer.duration
    assert first_rng.getstate() == expected_first_rng.getstate()
    assert second_rng.getstate() == expected_second_rng.getstate()
    assert runtime.audit.snapshot().sample_counts == {
        "file_transfer.http.large_parent_fraction": 2,
        "file_transfer.http.throughput_bytes_per_second": 2,
    }


def _worker_population(
    workers: int,
    *,
    reverse: bool,
) -> tuple[dict[int, float], dict[str, int]]:
    """Return one mixed transfer population under a selected worker topology."""

    runtime = TimingRuntime(reference_time=_EVENT_TIME, namespace="file-worker-parity")
    ordinals = tuple(range(64))
    submitted = tuple(reversed(ordinals)) if reverse else ordinals

    def sample(ordinal: int) -> tuple[int, float]:
        return ordinal, _duration(runtime, _SIZES[ordinal % len(_SIZES)], ordinal=ordinal)

    if workers == 1:
        values = map(sample, submitted)
    else:
        with ThreadPoolExecutor(max_workers=workers) as executor:
            values = executor.map(sample, submitted)
    return dict(values), dict(runtime.audit.snapshot().sample_counts)


def test_http_transfer_timing_is_order_and_worker_deterministic() -> None:
    """Stable transfer identities make timing independent of 1/4/8-worker arrival."""

    single = _worker_population(1, reverse=False)
    four = _worker_population(4, reverse=True)
    eight = _worker_population(8, reverse=True)

    assert single == four == eight
    assert single[1] == {
        "file_transfer.http.analyzed_parent_fraction": 16,
        "file_transfer.http.bulk_parent_fraction": 16,
        "file_transfer.http.large_parent_fraction": 16,
        "file_transfer.http.short_duration_seconds": 16,
        "file_transfer.http.throughput_bytes_per_second": 48,
    }


def test_http_transfer_timing_is_pythonhashseed_deterministic() -> None:
    """Transfer timing cannot inherit interpreter hash randomization."""

    script = textwrap.dedent(
        """
        import json
        from tests.unit.test_file_transfer_timing_runtime import _worker_population

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
    assert set(audit) == _RELATIONSHIPS


def test_http_transfer_audit_cardinality_is_relationship_bounded() -> None:
    """Distinct transfer identities cannot grow the fixed relationship universe."""

    runtime = TimingRuntime(
        reference_time=_EVENT_TIME,
        namespace="file-audit-bound",
        max_audit_relationship_keys=64,
    )
    for ordinal in range(256):
        _duration(runtime, _SIZES[ordinal % len(_SIZES)], ordinal=ordinal)

    census = runtime.audit.census()
    assert census.relationship_slots_capacity == 256
    assert census.relationship_slots_live <= len(_RELATIONSHIPS)
    assert census.sample_count == 448
    assert set(runtime.audit.snapshot().sample_counts) == _RELATIONSHIPS


def _constructor_calls(path: Path) -> list[ast.Call]:
    """Return HTTP file-transfer constructor calls in one production module."""

    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    calls: list[ast.Call] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        called = ""
        if isinstance(node.func, ast.Name):
            called = node.func.id
        elif isinstance(node.func, ast.Attribute):
            called = node.func.attr
        if called in {
            "HttpFileTransferActionBundle",
            "HttpResponseFileTransferActionBundle",
        }:
            calls.append(node)
    return calls


def test_http_transfer_callers_inject_timing_and_direct_rng_inventory_is_zero() -> None:
    """All production callers inject timing and the five direct temporal draws stay gone."""

    generation_root = Path(file_transfer_module.__file__).parents[1]
    caller_counts = {
        generation_root / "activity" / "generator.py": 2,
        generation_root / "actions" / "proxy_transaction.py": 2,
    }
    for path, expected_count in caller_counts.items():
        calls = _constructor_calls(path)
        assert len(calls) == expected_count
        assert all("timing_runtime" in {keyword.arg for keyword in call.keywords} for call in calls)

    path = Path(file_transfer_module.__file__)
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    temporal_helpers = {
        "_http_response_file_duration",
        "_http_transfer_throughput_floor",
        "http_response_transfer_duration_floor",
    }
    direct_calls: list[tuple[int, str]] = []
    for function in (
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.FunctionDef) and node.name in temporal_helpers
    ):
        for call in (node for node in ast.walk(function) if isinstance(node, ast.Call)):
            if isinstance(call.func, ast.Attribute) and call.func.attr in {
                "betavariate",
                "expovariate",
                "gauss",
                "lognormvariate",
                "randint",
                "randrange",
                "triangular",
                "uniform",
            }:
                direct_calls.append((call.lineno, call.func.attr))

    relationship_literals = {
        node.value
        for node in ast.walk(tree)
        if isinstance(node, ast.Constant)
        and isinstance(node.value, str)
        and node.value.startswith("file_transfer.http.")
    }
    assert direct_calls == []
    assert relationship_literals == _RELATIONSHIPS


def test_activity_http_transfer_path_never_enters_compatibility_runtime(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The real generator helper passes its injected owner through both transfer directions."""

    def reject_compatibility(_cls: type[TimingRuntime]) -> TimingRuntime:
        raise AssertionError("production HTTP transfer entered compatibility timing")

    monkeypatch.setattr(
        TimingRuntime,
        "compatibility_default",
        classmethod(reject_compatibility),
    )
    runtime = TimingRuntime(reference_time=_EVENT_TIME, namespace="file-caller-owner")
    event = OccurrenceBuilder(
        timestamp=_EVENT_TIME,
        event_type="connection",
        network=network_plan(
            src_ip="10.0.0.5",
            src_port=49152,
            dst_ip="93.184.216.34",
            dst_port=80,
            protocol="tcp",
            service="http",
            conn_state="SF",
            duration=10.0,
            orig_bytes=5_000,
            resp_bytes=5_000,
            zeek_uid="CFileTimingCaller",
        ),
        http=HttpContext(
            method="POST",
            host="downloads.example.test",
            uri="/round-trip",
            request_body_len=4_096,
            request_content_type="application/octet-stream",
            response_body_len=4_096,
            resp_mime_types=("application/octet-stream",),
        ),
    )

    _attach_http_file_transfers(
        event,
        dst_ip="93.184.216.34",
        rng=random.Random(17),
        timing_runtime=runtime,
        timing_scope=TimingScope(
            stable_id="file-caller-owner",
            host="downloads.example.test",
            source="network",
            lifecycle_id="CFileTimingCaller",
        ),
    )

    assert len(event.protocol.file_transfers) == 2
    assert _RELATIONSHIPS.intersection(runtime.audit.snapshot().sample_counts)
