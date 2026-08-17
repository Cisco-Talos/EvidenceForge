# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Smoke contracts for the V2 foundation-registry release workload probe."""

from __future__ import annotations

import json
import subprocess
import sys
from argparse import Namespace
from datetime import timedelta
from pathlib import Path

import pytest
from scripts.foundation_scale_workload import (
    _AUTHORITATIVE_RELEASE_CASE_COUNT,
    _DURATION_REGISTRIES,
    _IMPLEMENTATION_FILES,
    _IMPLEMENTED_PROTOCOLS,
    _ONE_MICROSECOND,
    _REGISTRIES,
    _RELEASE_CHURN_ENTRIES,
    _RELEASE_DURATIONS,
    _RELEASE_GROUP_MODES,
    _RELEASE_HASH_SEEDS,
    _RELEASE_MIXED_ENTRIES,
    _RELEASE_QUERIES,
    _RELEASE_RATE_PER_HOUR,
    _RELEASE_SIDECAR_ENTRIES,
    _RELEASE_SIZES,
    _RELEASE_WORKERS,
    _RELEASE_WRITE_MODES,
    _START,
    CaseSpec,
    DurationResult,
    RegistryName,
    RepositorySnapshot,
    ScaleResult,
    WorkloadMetrics,
    _authoritative_release_preflight_errors,
    _authoritative_release_requested,
    _build_duration_specs,
    _build_scale_specs,
    _build_sidecar_specs,
    _canonical_release_configuration,
    _final_plateau_hour,
    _implementation_files,
    _load_mixed_timing_runtime,
    _release_provenance_gates,
    _result_gates,
    _run_lifecycle_duration,
)

from evidenceforge.generation.lifecycle_registry import LifecycleRegistry
from evidenceforge.generation.workload import RETAINED_STATE_FAMILIES


def test_release_digest_covers_shared_integration_owners() -> None:
    """A moving caller or authority file must invalidate the same-revision release gate."""

    assert {
        "pyproject.toml",
        "uv.lock",
        "src/evidenceforge/events/dispatcher.py",
        "src/evidenceforge/events/base.py",
        "src/evidenceforge/events/rdp.py",
        "src/evidenceforge/events/source_catalog.py",
        "src/evidenceforge/config/schemas.py",
        "src/evidenceforge/config/provider.py",
        "src/evidenceforge/generation/actions/endpoint_effects.py",
        "src/evidenceforge/generation/actions/file_transfer.py",
        "src/evidenceforge/generation/actions/process_execution.py",
        "src/evidenceforge/generation/activity/generator.py",
        "src/evidenceforge/generation/activity/application_catalog.py",
        "src/evidenceforge/generation/activity/system_processes.py",
        "src/evidenceforge/generation/baseline_timing.py",
        "src/evidenceforge/generation/engine/baseline.py",
        "src/evidenceforge/generation/engine/storyline.py",
        "src/evidenceforge/generation/lifecycle_authority.py",
        "src/evidenceforge/generation/lifecycle_production_adapters.py",
        "src/evidenceforge/generation/network_observation.py",
        "src/evidenceforge/generation/network_runtime.py",
        "src/evidenceforge/generation/runtime_content.py",
        "src/evidenceforge/generation/source_deployment_compiler.py",
        "src/evidenceforge/generation/state_manager.py",
        "src/evidenceforge/generation/storyline_timing.py",
    } <= set(_IMPLEMENTATION_FILES)
    assert len(_IMPLEMENTATION_FILES) == len(set(_IMPLEMENTATION_FILES))
    repository_root = Path(__file__).resolve().parents[2]
    tracked = subprocess.run(
        ["git", "ls-files", "-z", "--", "src/evidenceforge"],
        cwd=repository_root,
        check=False,
        capture_output=True,
    )
    if tracked.returncode == 0:
        package_files = {
            relative_name.decode() for relative_name in tracked.stdout.split(b"\0") if relative_name
        }
    else:
        package_files = {
            path.relative_to(repository_root).as_posix()
            for path in (repository_root / "src" / "evidenceforge").rglob("*")
            if path.is_file()
            and "__pycache__" not in path.parts
            and path.suffix not in {".pyc", ".pyo"}
        }
    assert package_files <= set(_IMPLEMENTATION_FILES)
    assert _implementation_files() == _IMPLEMENTATION_FILES
    assert all(
        (repository_root / relative_name).is_file() for relative_name in _IMPLEMENTATION_FILES
    )


def _canonical_release_config() -> dict[str, object]:
    return {
        "registries": _REGISTRIES,
        "sizes": _RELEASE_SIZES,
        "group_modes": _RELEASE_GROUP_MODES,
        "write_modes": _RELEASE_WRITE_MODES,
        "workers": _RELEASE_WORKERS,
        "hash_seeds": _RELEASE_HASH_SEEDS,
        "durations": _RELEASE_DURATIONS,
        "queries": _RELEASE_QUERIES,
        "rate_per_hour": _RELEASE_RATE_PER_HOUR,
        "churn_entries": _RELEASE_CHURN_ENTRIES,
        "mixed_entries": _RELEASE_MIXED_ENTRIES,
        "sidecar_protocols": _IMPLEMENTED_PROTOCOLS,
        "sidecar_entries": _RELEASE_SIDECAR_ENTRIES,
    }


def test_release_matrix_preserves_exact_161_case_contract() -> None:
    """The static release plan must not silently lose or add a measured case."""

    scale = _build_scale_specs(
        profile="release",
        registries=_REGISTRIES,
        sizes=_RELEASE_SIZES,
        group_modes=_RELEASE_GROUP_MODES,
        write_modes=_RELEASE_WRITE_MODES,
        workers=_RELEASE_WORKERS,
        hash_seeds=_RELEASE_HASH_SEEDS,
        queries=_RELEASE_QUERIES,
        churn_entries=_RELEASE_CHURN_ENTRIES,
    )
    duration = _build_duration_specs(
        profile="release",
        registries=_DURATION_REGISTRIES,
        durations=_RELEASE_DURATIONS,
        workers=_RELEASE_WORKERS,
        hash_seeds=_RELEASE_HASH_SEEDS,
        rate_per_hour=_RELEASE_RATE_PER_HOUR,
        group_modes=_RELEASE_GROUP_MODES,
    )
    sidecars = _build_sidecar_specs(
        profile="release",
        protocols=_IMPLEMENTED_PROTOCOLS,
        entries=_RELEASE_SIDECAR_ENTRIES,
        workers=_RELEASE_WORKERS,
        hash_seeds=_RELEASE_HASH_SEEDS,
        queries=_RELEASE_QUERIES,
    )

    assert (len(scale), len(duration), len(sidecars), 1) == (93, 32, 35, 1)
    assert len(scale) + len(duration) + len(sidecars) + 1 == _AUTHORITATIVE_RELEASE_CASE_COUNT
    assert _canonical_release_configuration(_canonical_release_config()) is True


def test_authoritative_release_requires_all_three_existing_flags() -> None:
    """Focused and exploratory profiles must not inherit clean-tree release authority."""

    assert _authoritative_release_requested(
        Namespace(profile="release", enforce=True, require_complete=True)
    )
    assert not _authoritative_release_requested(
        Namespace(profile="release", enforce=True, require_complete=False)
    )
    assert not _authoritative_release_requested(
        Namespace(profile="smoke", enforce=True, require_complete=True)
    )


def test_authoritative_release_preflight_rejects_dirty_or_noncanonical_start() -> None:
    """An invalid final run must fail before launching any expensive child case."""

    config = _canonical_release_config()
    specs = [CaseSpec(kind="mixed", registry="mixed")] * _AUTHORITATIVE_RELEASE_CASE_COUNT
    clean = RepositorySnapshot(git_sha="a" * 40, dirty=False, status_digest="e" * 64)
    dirty = RepositorySnapshot(git_sha="a" * 40, dirty=True, status_digest="d" * 64)

    assert _authoritative_release_preflight_errors(config, specs, clean) == ()
    assert any(
        "worktree must be clean" in error
        for error in _authoritative_release_preflight_errors(config, specs, dirty)
    )
    changed = dict(config)
    changed["queries"] = _RELEASE_QUERIES - 1
    assert any(
        "canonical 161-case" in error
        for error in _authoritative_release_preflight_errors(changed, specs, clean)
    )


def test_release_result_binds_clean_stable_sha_and_implementation_digest() -> None:
    """Final authority requires one clean Git revision and one implementation digest."""

    start = RepositorySnapshot(git_sha="a" * 40, dirty=False, status_digest="e" * 64)
    clean_end = RepositorySnapshot(git_sha="a" * 40, dirty=False, status_digest="e" * 64)
    dirty_end = RepositorySnapshot(git_sha="a" * 40, dirty=True, status_digest="d" * 64)
    changed_end = RepositorySnapshot(git_sha="b" * 40, dirty=False, status_digest="e" * 64)

    green = _release_provenance_gates(
        authoritative=True,
        case_count=_AUTHORITATIVE_RELEASE_CASE_COUNT,
        implementation_revision_gate=True,
        start=start,
        end=clean_end,
    )
    assert all(value is True for value in green.values())
    assert (
        _release_provenance_gates(
            authoritative=True,
            case_count=_AUTHORITATIVE_RELEASE_CASE_COUNT,
            implementation_revision_gate=True,
            start=start,
            end=dirty_end,
        )["release_result_revision_bound"]
        is False
    )
    assert (
        _release_provenance_gates(
            authoritative=True,
            case_count=_AUTHORITATIVE_RELEASE_CASE_COUNT,
            implementation_revision_gate=True,
            start=start,
            end=changed_end,
        )["release_result_revision_bound"]
        is False
    )
    development = _release_provenance_gates(
        authoritative=False,
        case_count=1,
        implementation_revision_gate=True,
        start=dirty_end,
        end=dirty_end,
    )
    assert development["implementation_manifest_complete"] is True
    assert development["release_result_revision_bound"] is None


def test_final_plateau_hour_rejects_a_never_flat_footprint() -> None:
    """A final sample is not a plateau when retained/backing state never stabilizes."""

    assert _final_plateau_hour([(hour, hour * 2) for hour in range(168)]) is None


def test_lifecycle_duration_keeps_next_hour_boundary_ahead_of_watermark() -> None:
    """Adjacent duration buckets must not publish on an already-sealed frontier."""

    spec = CaseSpec(
        kind="duration",
        registry="lifecycle",
        duration_hours=2,
        rate_per_hour=1,
    )

    registry, _metrics, _lookups, _late_hour, mutations, _state, _notes = _run_lifecycle_duration(
        spec
    )

    assert isinstance(registry, LifecycleRegistry)
    assert mutations == 2
    assert registry.census().watermark == _START + timedelta(hours=2) - _ONE_MICROSECOND
    first = registry.get_session("duration-session-000000000000")
    second = registry.get_session("duration-session-000000000001")
    assert first is not None and first.closed_at is not None
    assert second is not None and second.closed_at is not None


def test_final_plateau_hour_requires_an_exact_full_day_suffix() -> None:
    """Retained counts and backing capacity must both stay exact for 24 hours."""

    samples = [(hour, hour) for hour in range(144)] + [(7, 11)] * 24
    assert _final_plateau_hour(samples) == 145
    assert _final_plateau_hour(samples[:-1] + [(7, 12)]) is None
    assert _final_plateau_hour([(7, 11)] * 23) is None


def test_final_plateau_hour_rejects_invalid_minimum_suffix() -> None:
    """Callers cannot accidentally disable the meaningful-suffix contract."""

    with pytest.raises(ValueError, match="must be positive"):
        _final_plateau_hour([(1, 1)], minimum_suffix_hours=0)


def _synthetic_week_result(registry: RegistryName, plateau_hour: int | None) -> DurationResult:
    metrics = WorkloadMetrics(
        logical_entries=1,
        live_entries=1,
        retained_entries=1,
        stale_entries=0,
        leased_entries=0,
        backing_entries=1,
        estimated_bytes=1,
        maximum_bucket_size=1,
        lookup_candidates_inspected=1,
        heap_segment_amplification=1.0,
        compaction_work=0,
        compaction_seconds=0.0,
        high_water_mark=1,
        estimated_index_bytes=1,
    )
    return DurationResult(
        kind="duration",
        registry=registry,
        duration_hours=168,
        rate_per_hour=1,
        group_mode="uniform",
        workers=1,
        hash_seed=0,
        mutations=168,
        total_seconds=1.0,
        late_hour_seconds=0.01,
        lookup_p95_us=1.0,
        plateau_hour=plateau_hour,
        rss_delta_bytes=1,
        peak_rss_delta_bytes=1,
        metrics=metrics,
        registry_digest="d" * 64,
        implementation_digest_start="i" * 64,
        implementation_digest_end="i" * 64,
        notes=(),
    )


@pytest.mark.parametrize(("plateau_hour", "expected"), [(None, False), (145, True)])
def test_week_plateau_gate_fails_for_complete_never_flat_coverage(
    plateau_hour: int | None,
    expected: bool,
) -> None:
    """Full seven-day coverage cannot pass without a meaningful stable suffix."""

    registries = ("lifecycle", "channels", "artifacts", "collection")
    gates, _ratios = _result_gates(
        [],
        [_synthetic_week_result(registry, plateau_hour) for registry in registries],
        [],
        [],
        [],
        expected_registries=registries,
        expected_sizes=(),
        expected_group_modes=(),
        expected_write_modes=(),
        expected_workers=(1,),
        expected_hash_seeds=(0,),
        expected_durations=(168,),
        expected_protocols=(),
        expected_sidecar_entries=0,
        reference_host=False,
    )
    assert gates["retained_counts_plateau_by_seven_days"] is expected


def test_deployment_actual_million_memory_and_index_fail_independently() -> None:
    """A small mixed share cannot hide a red standalone deployment million point."""

    metrics = WorkloadMetrics(
        logical_entries=1_000_000,
        live_entries=1_000_000,
        retained_entries=1_000_000,
        stale_entries=0,
        leased_entries=0,
        backing_entries=1_727_272,
        estimated_bytes=966_000_000,
        maximum_bucket_size=90_909,
        lookup_candidates_inspected=1,
        heap_segment_amplification=None,
        compaction_work=0,
        compaction_seconds=0.0,
        high_water_mark=1_000_000,
        estimated_index_bytes=313_150_000,
    )
    result = ScaleResult(
        kind="scale",
        registry="deployment",
        entries=1_000_000,
        queries=1,
        group_mode="skewed",
        write_mode="monotonic",
        workers=1,
        hash_seed=0,
        load_seconds=39.154,
        primary_cold_lookup_p95_us=1.0,
        primary_lookup_p95_us=1.0,
        secondary_cold_lookup_p95_us=1.0,
        secondary_lookup_p95_us=1.0,
        page_lookup_p95_us=1.0,
        churn_entries=0,
        churn_seconds=0.0,
        operation_seconds=None,
        close_prepare_seconds=None,
        close_seconds=None,
        expiry_entries=0,
        expiry_seconds=0.0,
        rss_delta_bytes=1_657_000_000,
        peak_rss_delta_bytes=2_079_000_000,
        bytes_per_requested_entry=1_657.0,
        metrics=metrics,
        registry_digest="d" * 64,
        implementation_digest_start="i" * 64,
        implementation_digest_end="i" * 64,
        notes=(),
    )
    gates, _ratios = _result_gates(
        [result],
        [],
        [],
        [],
        [],
        expected_registries=("deployment",),
        expected_sizes=(1_000_000,),
        expected_group_modes=("skewed",),
        expected_write_modes=("monotonic",),
        expected_workers=(1,),
        expected_hash_seeds=(0,),
        expected_durations=(),
        expected_protocols=(),
        expected_sidecar_entries=0,
        reference_host=False,
    )

    assert gates["deployment_content_actual_million_covered"] is True
    assert gates["deployment_content_million_load_lte_60_seconds"] is True
    assert gates["deployment_content_million_rss_lte_512_mib"] is False
    assert gates["deployment_content_index_overhead_lte_256_bytes_per_physical_record"] is False


def test_release_matrix_keeps_every_deployment_million_shape() -> None:
    """Uniform/skewed and monotonic/late deployment million points are actual cases."""

    specs = _build_scale_specs(
        profile="release",
        registries=("deployment",),
        sizes=(1_000, 100_000, 1_000_000, 2_000_000),
        group_modes=("uniform", "skewed"),
        write_modes=("monotonic", "out-of-order"),
        workers=(1, 4, 8),
        hash_seeds=(0, 17),
        queries=10,
        churn_entries=100_000,
    )
    million_shapes = {
        (spec.group_mode, spec.write_mode) for spec in specs if spec.entries == 1_000_000
    }

    assert million_shapes == {
        ("uniform", "monotonic"),
        ("uniform", "out-of-order"),
        ("skewed", "monotonic"),
        ("skewed", "out-of-order"),
    }


def test_mixed_timing_family_loads_planner_indexes_and_shared_runtime() -> None:
    """Every retained timing-planner family contributes through its public census."""

    planner, family, semantic = _load_mixed_timing_runtime(18)
    census = planner.census(estimate_bytes=True)

    assert census.index_count == len(semantic["planner_families"])
    assert census.index_count >= 16
    assert all(index.live_entries >= 1 for index in census.indexes)
    assert census.runtime.clocks.live_entries >= 1
    assert census.runtime.audit.relationship_slots_live >= 1
    assert semantic["planner_families"] == tuple(index.name for index in census.indexes)
    assert family.physical_records == (
        census.live_entries
        + census.runtime.clocks.live_entries
        + census.runtime.audit.relationship_slots_live
        + census.runtime.audit.distribution_keys_live
    )
    assert family.estimated_index_bytes == (
        census.estimated_index_bytes + census.runtime.estimated_index_bytes
    )


def _run_probe(tmp_path: Path, *arguments: str) -> tuple[subprocess.CompletedProcess[str], dict]:
    output = tmp_path / "foundation-scale.json"
    result = subprocess.run(
        [
            sys.executable,
            "scripts/foundation_scale_workload.py",
            *arguments,
            "--json-output",
            str(output),
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    payload = json.loads(output.read_text(encoding="utf-8")) if output.exists() else {}
    return result, payload


def test_foundation_probe_smoke_covers_all_public_registry_censuses(tmp_path: Path) -> None:
    """A tiny invocation should exercise every scale and duration adapter."""

    result, payload = _run_probe(
        tmp_path,
        "--sizes",
        "10",
        "--queries",
        "5",
        "--churn-entries",
        "2",
        "--duration-hours",
        "1",
        "--rate-per-hour",
        "1",
        "--enforce",
    )

    assert result.returncode == 0, result.stderr
    assert payload["schema_version"] == 1
    assert payload["release_authority"]["requested"] is False
    assert payload["release_authority"]["canonical_case_count"] == 161
    assert payload["repository"]["git_sha_start"] == payload["repository"]["git_sha_end"]
    assert payload["repository"]["snapshot_boundary"] == "before_json_output"
    assert payload["case_count"] == 9
    assert payload["errors"] == []
    assert payload["gates"]["all_isolated_cases_completed"] is True
    assert payload["gates"]["single_implementation_revision"] is True
    assert payload["gates"]["implementation_manifest_complete"] is True
    assert payload["gates"]["repository_revision_stable"] is None
    assert payload["gates"]["repository_worktree_clean"] is None
    assert payload["gates"]["release_result_revision_bound"] is None
    assert payload["gates"]["requested_size_ladder_covered"] is True
    assert payload["gates"]["requested_durations_covered"] is True
    assert payload["gates"]["million_mixed_rss_lte_512_mib"] is None
    assert payload["gates"]["all_registry_index_overhead_lte_256_bytes_per_physical_record"] is None
    assert "primary_cold_1m_over_1k_lte_2" not in payload["gates"]
    assert "secondary_cold_1m_over_1k_lte_3" not in payload["gates"]
    assert {item["registry"] for item in payload["results"]} == {
        "lifecycle",
        "channels",
        "artifacts",
        "collection",
        "deployment",
    }
    for item in payload["results"]:
        metrics = item["metrics"]
        assert metrics["logical_entries"] >= 0
        assert metrics["backing_entries"] >= 0
        assert metrics["high_water_mark"] is not None
        assert "lookup_candidates_inspected" in metrics
        assert "heap_segment_amplification" in metrics
        assert "estimated_index_bytes" in metrics
        if item["kind"] == "scale":
            assert item["primary_cold_lookup_p95_us"] >= 0
            assert item["secondary_cold_lookup_p95_us"] >= 0
            if item["registry"] == "channels":
                assert item["operation_seconds"] is not None
                assert item["close_prepare_seconds"] is not None
                assert item["close_seconds"] is not None
        if item["kind"] == "duration":
            assert item["plateau_hour"] is None
        assert len(item["registry_digest"]) == 64
        assert len(item["implementation_digest_start"]) == 64
        assert item["implementation_digest_start"] == item["implementation_digest_end"]
    assert len(payload["summary"]["implementation_digests"]) == 1
    assert payload["gates"]["retained_counts_plateau_by_seven_days"] is None
    assert payload["gates"]["seven_to_thirty_day_plateau_index_bytes_within_10_percent"] is None


def test_foundation_probe_release_mode_fails_closed_for_missing_cases(tmp_path: Path) -> None:
    """A partial foundation smoke cannot be reported as release-complete."""

    result, payload = _run_probe(
        tmp_path,
        "--registries",
        "channels",
        "--sizes",
        "10",
        "--queries",
        "2",
        "--churn-entries",
        "0",
        "--skip-duration",
        "--skip-sidecars",
        "--enforce",
        "--require-complete",
    )

    assert result.returncode == 1
    assert payload["failed_gates"] == []
    assert {
        "all_registry_index_overhead_lte_256_bytes_per_physical_record",
        "deployment_content_actual_million_covered",
        "deployment_content_index_overhead_lte_256_bytes_per_physical_record",
        "deployment_content_million_rss_lte_512_mib",
        "million_mixed_rss_lte_512_mib",
        "million_load_lte_60_seconds",
        "primary_1m_over_1k_lte_2",
        "secondary_1m_over_1k_lte_3",
    }.issubset(payload["open_gates"])


def test_foundation_probe_compares_workers_and_real_hash_seeds(tmp_path: Path) -> None:
    """Identical semantic channel work must digest equally across scheduling and hash seeds."""

    result, payload = _run_probe(
        tmp_path,
        "--profile",
        "exhaustive",
        "--registries",
        "channels",
        "--sizes",
        "20",
        "--group-modes",
        "skewed",
        "--write-modes",
        "out-of-order",
        "--workers",
        "1,2",
        "--hash-seeds",
        "0,17",
        "--queries",
        "10",
        "--churn-entries",
        "5",
        "--skip-duration",
        "--skip-sidecars",
        "--enforce",
    )

    assert result.returncode == 0, result.stderr
    assert payload["case_count"] == 4
    assert payload["errors"] == []
    assert payload["gates"]["deterministic_across_workers"] is True
    assert payload["gates"]["deterministic_across_pythonhashseed"] is True
    assert payload["gates"]["deterministic_across_workers_and_pythonhashseed"] is True
    assert len({item["registry_digest"] for item in payload["results"]}) == 1


def test_foundation_probe_measures_a_true_mixed_process_when_explicit(
    tmp_path: Path,
) -> None:
    """The mixed adapter retains every implemented family without common-row duplication."""

    result, payload = _run_probe(
        tmp_path,
        "--registries",
        "channels",
        "--sizes",
        "4",
        "--queries",
        "2",
        "--churn-entries",
        "0",
        "--mixed-entries",
        "40",
        "--skip-duration",
        "--enforce",
    )

    assert result.returncode == 0, result.stderr
    mixed = next(item for item in payload["results"] if item["kind"] == "mixed")
    assert mixed["entries"] == 40
    assert mixed["live_entries"] == mixed["physical_hot_records"] >= 40
    expected_families = set(RETAINED_STATE_FAMILIES)
    assert set(mixed["per_family_requested_entries"]) == expected_families
    assert set(mixed["family_censuses"]) == expected_families
    assert mixed["family_coverage_complete"] is True
    assert mixed["physical_hot_records"] == sum(
        family["physical_records"] for family in mixed["family_censuses"].values()
    )
    assert mixed["family_censuses"]["process_runtime"]["requested_logical"] >= 17
    assert mixed["family_censuses"]["deployment_content"]["requested_logical"] >= 11
    assert mixed["family_censuses"]["timing_runtime"]["requested_logical"] >= 18
    assert (
        "bounded production source-timing" in mixed["family_censuses"]["timing_runtime"]["notes"][0]
    )
    assert all(
        family["estimated_bytes"] is not None and family["estimated_index_bytes"] is not None
        for family in mixed["family_censuses"].values()
    )
    assert mixed["rss_delta_bytes"] >= 0
    assert mixed["rss_bytes_per_physical_record"] >= 0
    assert mixed["estimated_index_bytes"] is not None
    assert mixed["estimated_index_bytes_per_physical_record"] is not None
    assert payload["gates"]["mixed_retained_state_families_complete"] is True
    assert payload["gates"]["mixed_physical_denominator_at_least_requested"] is True
    assert payload["gates"]["million_mixed_rss_lte_512_mib"] is None


def test_foundation_probe_measures_protocol_sidecars_against_one_shared_registry(
    tmp_path: Path,
) -> None:
    """Tiny explicit sidecar cases expose common and incremental manager costs."""

    result, payload = _run_probe(
        tmp_path,
        "--sidecar-protocols",
        "http,proxy,smb,rdp,ssh",
        "--sidecar-entries",
        "3",
        "--queries",
        "2",
        "--skip-scale",
        "--skip-duration",
        "--enforce",
    )

    assert result.returncode == 0, result.stderr
    assert payload["case_count"] == 5
    assert payload["errors"] == []
    assert payload["gates"]["required_protocol_managers_available"] is True
    assert payload["gates"]["protocol_sidecar_actual_or_structural_scale_covered"] is True
    assert payload["gates"]["protocol_sidecar_common_and_incremental_bytes_exposed"] is True
    sidecars = [item for item in payload["results"] if item["kind"] == "sidecar"]
    assert {item["registry"] for item in sidecars} == {"http", "proxy", "smb", "rdp", "ssh"}
    for item in sidecars:
        assert item["representation"] == "actual_manager"
        assert item["common_live_entries"] == 3
        assert item["sidecar_live_entries"] == 3
        assert item["common_estimated_bytes"] > 0
        assert item["common_estimated_index_bytes"] > 0
        assert item["sidecar_estimated_bytes"] > 0
        assert item["sidecar_estimated_index_bytes"] > 0
        assert item["lookup_p95_us"] >= 0
        assert item["physical_hot_records"] >= item["entries"] * 2
        assert item["rss_bytes_per_physical_record"] >= 0
        assert item["load_seconds_per_million_physical_records"] >= 0
