"""Resource gates reject incomplete evaluation and both forms of memory growth."""

import pytest
from scripts.check_evaluation_memory import (
    MIB,
    Limits,
    Measurement,
    Profile,
    WorkerResult,
    check_measurements,
)


def matrix() -> tuple[list[Measurement], Profile, Limits]:
    limits = Limits(peak_mib=256, growth_mib=32)
    profile = Profile(version=1, memory_budget_mib=16, records=[24, 72, 216], limits={})
    rows = []
    for workload in ("processes", "correlated"):
        for count in profile.records:
            sources = (
                {"ecar": count}
                if workload == "processes"
                else {
                    "ecar": count // 2,
                    **{f"zeek_{kind}": count // 8 for kind in ("conn", "dns", "ssl", "files")},
                }
            )
            rows.append(
                Measurement(
                    workload=workload,
                    records=count,
                    baseline_rss_bytes=100 * MIB,
                    peak_rss_bytes=120 * MIB,
                    startup_lifetime_peak_bytes=900 * MIB,
                    samples=10,
                    evaluation_seconds=1,
                    input_sha256="0" * 64,
                    result=WorkerResult(
                        records=count,
                        source_counts=sources,
                        spec_conformance=100,
                        resources={"spilled": True, "working_memory_bytes": 16 * MIB},
                        final_rss_bytes=110 * MIB,
                        lifetime_peak_bytes=900 * MIB,
                        scratch_clean=True,
                    ),
                )
            )
    return rows, profile, limits


def test_lifetime_high_water_history_does_not_change_evaluator_memory_gate() -> None:
    rows, profile, limits = matrix()
    assert check_measurements(rows, profile, limits) == []


@pytest.mark.parametrize("peaks", [(120, 140, 165), (120, 165, 120)])
def test_growth_gate_detects_sustained_or_intermediate_growth_below_absolute_limit(
    peaks: tuple[int, int, int],
) -> None:
    rows, profile, limits = matrix()
    for index, peak in enumerate(peaks):
        rows[index] = rows[index].model_copy(update={"peak_rss_bytes": peak * MIB})
    assert check_measurements(rows, profile, limits) == [
        "processes: RSS growth 47185920 exceeds 32 MiB"
    ]


def test_absolute_gate_detects_large_constant_overhead_with_no_growth() -> None:
    rows, profile, limits = matrix()
    rows = [row.model_copy(update={"peak_rss_bytes": 300 * MIB}) for row in rows]
    failures = check_measurements(rows, profile, limits)
    assert len(failures) == 6
    assert all("exceeds 256 MiB" in failure for failure in failures)


@pytest.mark.parametrize(
    "change,expected",
    [
        ({"records": 8}, "incomplete evaluation"),
        ({"source_counts": {"ecar": 24}}, "incomplete evaluation"),
        ({"spec_conformance": 99}, "fixture has schema failures"),
        ({"scratch_clean": False}, "scratch cleanup or RSS sampling failed"),
        (
            {"resources": {"spilled": False, "working_memory_bytes": 16 * MIB}},
            "workload did not exercise spill",
        ),
        (
            {"resources": {"spilled": True, "working_memory_bytes": 32 * MIB}},
            "wrong working-state budget",
        ),
    ],
)
def test_resource_gate_cannot_pass_with_incomplete_or_changed_workload(
    change: dict,
    expected: str,
) -> None:
    rows, profile, limits = matrix()
    rows[3] = rows[3].model_copy(update={"result": rows[3].result.model_copy(update=change)})
    assert check_measurements(rows, profile, limits) == [f"correlated/24: {expected}"]


def test_missing_or_duplicate_scaling_size_fails_the_gate() -> None:
    rows, profile, limits = matrix()
    assert check_measurements(rows[:-1], profile, limits) == [
        "correlated: incomplete or duplicate scaling matrix"
    ]
    assert check_measurements([*rows, rows[-1]], profile, limits) == [
        "correlated: incomplete or duplicate scaling matrix"
    ]
