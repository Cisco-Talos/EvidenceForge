# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Contracts for reusable, opt-in generation profiling."""

from __future__ import annotations

import hashlib
import inspect
import json
import signal
from datetime import UTC, datetime
from pathlib import Path
from threading import Thread

import pytest
import yaml
from scripts.build_all_source_profile_workload import CONCRETE_FORMATS, build_workload

from evidenceforge.composition import compile_scenario
from evidenceforge.composition.artifacts import (
    verify_generation_bundle,
    write_generation_manifest,
    write_resolved_scenario,
)
from evidenceforge.composition.sidecars import SIDECAR_REGISTRY
from evidenceforge.generation.engine.core import GenerationEngine
from evidenceforge.generation.profiling import (
    GENERATION_PROFILE_FILENAME,
    GenerationProfileDocument,
    GenerationProfiler,
    ProfileMetricProvider,
)
from evidenceforge.generation.state_manager import StateManager
from evidenceforge.models.exceptions import SchemaValidationError
from evidenceforge.output_targets import OUTPUT_TARGET_FILENAME

_MINIMAL = Path("tests/fixtures/scenarios/minimal.yaml")
_PROFILE_SOURCE = Path("tests/fixtures/performance/network_warmup_profile.yaml")


def _finished_profiler(tmp_path: Path, *, max_unique_stacks: int = 10) -> GenerationProfiler:
    profiler = GenerationProfiler(
        scenario="profile-test",
        generation_seed=42,
        output_target="default",
        selected_formats=("ecar", "windows_event_security"),
        source_root=Path.cwd(),
        max_unique_stacks=max_unique_stacks,
    )
    profiler._install_sampler = lambda: None  # type: ignore[method-assign]
    profiler.start(starting_cursor={"phase": "collection", "completed_simulated_hours": 2})
    profiler.begin_phase("collection")
    profiler.begin_hour(
        phase="collection",
        simulated_time=datetime(2026, 3, 2, 13, tzinfo=UTC),
    )
    frame = inspect.currentframe()
    assert frame is not None
    profiler._sample(0, frame)
    with profiler.span("baseline.user_activity"):
        pass
    profiler.record_emitter_barrier(
        format_name="ecar",
        elapsed_seconds=0.25,
        queue_depth_before=7,
    )
    profiler.end_hour(
        emitter_snapshots={
            "ecar": {
                "rendered_rows": 12,
                "queue_depth": 0,
                "worker_cpu_ns": 2_000_000_000,
            },
            "windows_event_security": {
                "rendered_rows": 4,
                "queue_depth": 0,
                "worker_cpu_ns": None,
            },
        },
        state_metrics={"active_sessions": 3, "pid_candidate_probes": 11},
    )
    profiler.record_final_emitters(
        {
            "ecar": {
                "rendered_rows": 15,
                "queue_depth": 0,
                "worker_cpu_ns": 3_000_000_000,
            },
            "windows_event_security": {
                "rendered_rows": 8,
                "queue_depth": 0,
                "worker_cpu_ns": None,
            },
        }
    )
    profiler.end_phase("collection")
    profiler.finish("completed")
    return profiler


def _write_required_bundle(root: Path, *, profile: str | None = None) -> None:
    (root / "data").mkdir(parents=True)
    (root / "data/events.log").write_text("event\n", encoding="utf-8")
    for name in (
        "GROUND_TRUTH.md",
        "GROUND_TRUTH.json",
        "OBSERVATION_MANIFEST.json",
        OUTPUT_TARGET_FILENAME,
        "RESOLVED_SCENARIO.yaml",
        "GENERATION_MANIFEST.json",
    ):
        (root / name).write_text("{}\n", encoding="utf-8")
    if profile is not None:
        (root / GENERATION_PROFILE_FILENAME).write_text(profile, encoding="utf-8")


def test_profile_document_records_samples_hours_rows_and_resume_cursor(tmp_path: Path) -> None:
    profiler = _finished_profiler(tmp_path)

    document = profiler.document()

    assert GenerationProfileDocument.model_validate(document.model_dump()) == document
    assert document.starting_cursor == {"phase": "collection", "completed_simulated_hours": 2}
    assert document.generation_status == "completed"
    assert document.total_samples == 1
    assert document.phases["collection"] >= 0.0
    assert document.stages["baseline.user_activity"] >= 0.0
    assert len(document.hours) == 1
    hour = document.hours[0]
    assert hour.emitters["ecar"].rendered_rows == 12
    assert hour.emitters["ecar"].barrier_seconds == 0.25
    assert hour.emitters["ecar"].worker_cpu_seconds == 2.0
    assert hour.emitters["ecar"].queue_depth_before_barrier == 7
    assert hour.emitters["windows_event_security"].worker_cpu_seconds is None
    assert hour.state_metrics["pid_candidate_probes"] == 11
    assert document.emitters["ecar"].rendered_rows == 15
    assert document.emitters["ecar"].worker_cpu_seconds == 3.0
    assert document.emitters["windows_event_security"].rendered_rows == 8
    assert all(str(Path.cwd()) not in sample.location for sample in document.functions)


def test_profile_stack_storage_is_bounded(tmp_path: Path) -> None:
    profiler = GenerationProfiler(
        scenario="bounded",
        generation_seed=42,
        output_target="default",
        selected_formats=(),
        source_root=tmp_path,
        max_unique_stacks=1,
    )
    profiler._install_sampler = lambda: None  # type: ignore[method-assign]
    profiler.start()
    frame = inspect.currentframe()
    assert frame is not None
    profiler._sample(0, frame)

    def collect_distinct_stack() -> None:
        nested = inspect.currentframe()
        assert nested is not None
        profiler._sample(0, nested)

    collect_distinct_stack()
    profiler.finish("completed")

    assert len(profiler.document().stacks) == 1
    assert profiler.document().dropped_samples == 1


def test_sampler_restores_prior_signal_handler_and_timer(monkeypatch: pytest.MonkeyPatch) -> None:
    prior_handler = object()
    calls: list[tuple[object, ...]] = []
    monkeypatch.setattr(signal, "getsignal", lambda _signal: prior_handler)
    monkeypatch.setattr(signal, "getitimer", lambda _timer: (0.25, 0.5))
    monkeypatch.setattr(signal, "signal", lambda *args: calls.append(("signal", *args)))
    monkeypatch.setattr(signal, "setitimer", lambda *args: calls.append(("timer", *args)))
    profiler = GenerationProfiler(
        scenario="signals",
        generation_seed=42,
        output_target="default",
        selected_formats=(),
    )

    profiler.start()
    profiler.finish("completed")

    assert profiler.document().sampler == "itimer-prof"
    assert ("timer", signal.ITIMER_PROF, 0.0, 0.0) in calls
    assert ("signal", signal.SIGPROF, prior_handler) in calls
    assert ("timer", signal.ITIMER_PROF, 0.25, 0.5) in calls


def test_sampler_unavailability_degrades_to_coarse_metrics_off_main_thread() -> None:
    documents: list[GenerationProfileDocument] = []

    def collect() -> None:
        profiler = GenerationProfiler(
            scenario="coarse",
            generation_seed=42,
            output_target="default",
            selected_formats=(),
        )
        profiler.start()
        profiler.finish("completed")
        documents.append(profiler.document())

    worker = Thread(target=collect)
    worker.start()
    worker.join()

    assert len(documents) == 1
    assert documents[0].sampler == "unavailable"
    assert documents[0].degraded
    assert "coarse metrics remain enabled" in documents[0].warnings[0]


def test_state_profile_metrics_use_constant_time_index_counters() -> None:
    provider: ProfileMetricProvider = StateManager()
    metrics = provider.profiling_metrics()

    assert metrics["active_sessions"] == 0
    assert metrics["running_processes"] == 0
    assert metrics["open_connections"] == 0
    assert metrics["pid_allocations"] == 0


def test_partial_engine_reports_progress_without_profiler_state() -> None:
    """Failure cleanup remains usable for test and recovery harnesses built without init."""

    engine = object.__new__(GenerationEngine)
    observed: list[tuple[str, dict[str, object]]] = []
    engine.progress_callback = lambda event_type, data: observed.append((event_type, data))

    engine._report_progress("phase_start", {"phase": "finalization"})

    assert observed == [("phase_start", {"phase": "finalization"})]


def test_profile_write_is_atomic_and_rejects_symlink(tmp_path: Path) -> None:
    profiler = _finished_profiler(tmp_path)
    destination = profiler.write(tmp_path)

    assert destination == tmp_path / GENERATION_PROFILE_FILENAME
    assert not tuple(tmp_path.glob(f".{GENERATION_PROFILE_FILENAME}.pending-*"))
    GenerationProfileDocument.model_validate_json(destination.read_text(encoding="utf-8"))

    destination.unlink()
    target = tmp_path / "outside.json"
    target.write_text("unchanged\n", encoding="utf-8")
    destination.symlink_to(target)

    assert profiler.write(tmp_path) is None
    assert target.read_text(encoding="utf-8") == "unchanged\n"


def test_profile_sidecar_is_replaced_and_removed_transactionally(tmp_path: Path) -> None:
    destination = tmp_path / "destination"
    staged = tmp_path / "staged"
    _write_required_bundle(destination, profile="old\n")
    _write_required_bundle(staged, profile="new\n")

    SIDECAR_REGISTRY.replace(staged, destination)

    assert (destination / GENERATION_PROFILE_FILENAME).read_text(encoding="utf-8") == "new\n"

    staged_without_profile = tmp_path / "staged-without-profile"
    _write_required_bundle(staged_without_profile)
    SIDECAR_REGISTRY.replace(staged_without_profile, destination)

    assert not (destination / GENERATION_PROFILE_FILENAME).exists()


def test_generation_manifest_hashes_and_verifies_profile_sidecar(tmp_path: Path) -> None:
    compiled = compile_scenario(_MINIMAL)
    (tmp_path / "data").mkdir()
    (tmp_path / "data/events.log").write_text("event\n", encoding="utf-8")
    profile = _finished_profiler(tmp_path)
    profile.write(tmp_path)
    write_resolved_scenario(compiled, tmp_path)
    write_generation_manifest(compiled, tmp_path, output_target="default", formats=[])

    manifest = verify_generation_bundle(tmp_path)

    assert GENERATION_PROFILE_FILENAME in manifest["files"]
    (tmp_path / GENERATION_PROFILE_FILENAME).write_text("{}\n", encoding="utf-8")
    with pytest.raises(SchemaValidationError, match="hash verification failed"):
        verify_generation_bundle(tmp_path)


def test_derived_all_source_workload_is_valid_and_leaves_source_unchanged(tmp_path: Path) -> None:
    source_digest = hashlib.sha256(_PROFILE_SOURCE.read_bytes()).hexdigest()
    destination = tmp_path / "all-source.yaml"

    build_workload(_PROFILE_SOURCE.resolve(), destination)

    document = yaml.safe_load(destination.read_text(encoding="utf-8"))
    compiled = compile_scenario(destination)
    assert hashlib.sha256(_PROFILE_SOURCE.read_bytes()).hexdigest() == source_digest
    assert len(compiled.scenario.environment.users) == 63
    assert len(compiled.scenario.environment.systems) == 78
    assert len(compiled.scenario.environment.network.segments) == 4
    assert compiled.scenario.generation_seed == 42
    assert document["time_window"] == {
        "start": "2026-03-02T13:00:00Z",
        "duration": "2h",
        "warmup": "1h",
    }
    assert tuple(sorted(log["format"] for log in document["output"]["logs"])) == CONCRETE_FORMATS


def test_registered_profile_sidecar_rejects_destination_symlink(tmp_path: Path) -> None:
    destination = tmp_path / "destination"
    staged = tmp_path / "staged"
    _write_required_bundle(destination)
    _write_required_bundle(staged, profile=json.dumps({"new": True}))
    target = tmp_path / "outside-profile.json"
    target.write_text("outside\n", encoding="utf-8")
    (destination / GENERATION_PROFILE_FILENAME).symlink_to(target)

    with pytest.raises(PermissionError, match="GENERATION_PROFILE.json"):
        SIDECAR_REGISTRY.replace(staged, destination)

    assert target.read_text(encoding="utf-8") == "outside\n"
