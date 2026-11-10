"""Contracts for complete, balanced CI selection and retained execution reports."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest
from scripts.ci_shards import (
    ShardReport,
    TimingDatabase,
    TimingHistory,
    json_report,
    plan_shards,
    update_timings,
    validate_reports,
)


def reports() -> list[ShardReport]:
    return [
        ShardReport(
            tier="routine",
            index=index,
            count=2,
            inventory=["a", "b"],
            selected=[node],
            outcomes={node: "passed"},
            exit_code=0,
        )
        for index, node in enumerate(("a", "b"))
    ]


def test_balancing_is_complete_disjoint_and_independent_of_collection_order() -> None:
    nodes = [f"tests/test_{index % 3}.py::test_{index}" for index in range(100)]
    history = TimingHistory(cases={nodes[0]: 100, nodes[1]: 80})
    first = plan_shards(nodes, 8, history)
    assert first == plan_shards(list(reversed(nodes)), 8, history)
    assert len(set().union(*(set(shard) for shard in first))) == len(nodes)
    assert sum(map(len, first)) == len(nodes)
    assert any(nodes[0] in shard and nodes[1] not in shard for shard in first)


def test_shared_fixture_module_is_not_repeated_across_shards() -> None:
    nodes = [f"tests/test_shared.py::test_{index}" for index in range(20)]
    nodes += [f"tests/test_other.py::test_{index}" for index in range(20)]
    shards = plan_shards(nodes, 4, TimingHistory(keep_modules=["tests/test_shared.py"]))
    assert sum(any("test_shared.py" in node for node in shard) for shard in shards) == 1


@pytest.mark.parametrize("count", [0, -1, 65])
def test_invalid_shard_counts_fail(count: int) -> None:
    with pytest.raises(ValueError, match="between"):
        plan_shards(["one"], count, TimingHistory())


def test_duplicate_collection_cannot_hide_missing_cases() -> None:
    with pytest.raises(ValueError, match="duplicate"):
        plan_shards(["one", "one"], 2, TimingHistory())


@pytest.mark.parametrize(
    "damage",
    ["missing", "duplicate", "omitted", "overlap", "failed", "outcome", "inventory", "all-skipped"],
)
def test_incomplete_or_unsuccessful_shards_fail_the_gate(damage: str) -> None:
    selected = reports()
    if damage == "missing":
        selected.pop()
    elif damage == "duplicate":
        selected[1].index = 0
    elif damage == "omitted":
        selected[1].selected = []
    elif damage == "overlap":
        selected[1].selected = ["a"]
        selected[1].outcomes = {"a": "passed"}
    elif damage == "failed":
        selected[1].exit_code = 1
    elif damage == "outcome":
        selected[1].outcomes = {}
    elif damage == "inventory":
        selected[1].inventory = ["a", "b", "c"]
    else:
        selected[1].outcomes = {"b": "skipped"}
    with pytest.raises(ValueError):
        validate_reports(selected)


def test_complete_shard_reports_pass() -> None:
    validate_reports(reports())


def test_real_pytest_hook_records_every_case_once(tmp_path: Path) -> None:
    result = []
    for index in range(2):
        path = tmp_path / f"shard-{index}.json"
        subprocess.run(
            [
                sys.executable,
                "-m",
                "pytest",
                "--no-cov",
                "-q",
                "tests/unit/test_test_tier_policy.py",
                "--ci-tier",
                "routine",
                "--ci-shard-count",
                "2",
                "--ci-shard-index",
                str(index),
                "--ci-report",
                str(path),
            ],
            check=True,
            capture_output=True,
            text=True,
            timeout=60,
        )
        result.append(json_report(path))
    validate_reports(result)
    assert all(report.durations for report in result)


def test_additional_filters_cannot_silently_reduce_ci_selection(tmp_path: Path) -> None:
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "pytest",
            "--no-cov",
            "-q",
            "tests/unit/test_test_tier_policy.py",
            "--ci-tier",
            "routine",
            "-k",
            "distinct",
            "--ci-report",
            str(tmp_path / "shard.json"),
        ],
        check=False,
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert result.returncode != 0
    assert "without additional filters" in result.stderr + result.stdout


def test_timing_refresh_requires_complete_executed_reports(tmp_path: Path) -> None:
    database = tmp_path / "timings.json"
    database.write_text(
        TimingDatabase(profiles={"routine-linux": TimingHistory()}).model_dump_json()
    )
    paths = []
    for report in reports():
        report.durations = {node: 1.5 + report.index for node in report.selected}
        path = tmp_path / f"report-{report.index}.json"
        path.write_text(json.dumps({"shard": report.model_dump()}))
        paths.append(path)
    with pytest.raises(ValueError, match="missing"):
        update_timings("routine-linux", paths[:1], database)
    update_timings("routine-linux", paths, database)
    refreshed = TimingDatabase.model_validate_json(database.read_bytes())
    assert refreshed.profiles["routine-linux"].cases == {"a": 1.5, "b": 2.5}


def test_coverage_from_different_runner_roots_combines_all_branches(tmp_path: Path) -> None:
    data_files = []
    for index in range(2):
        runner = tmp_path / f"runner-{index}"
        runner.mkdir()
        (runner / "sample.py").write_text(
            "def choose(value):\n    if value:\n        return 1\n    return 2\n"
        )
        (runner / "test_sample.py").write_text(
            f"from sample import choose\ndef test_choice():\n    assert choose({bool(index)}) == {2 - index}\n"
        )
        (runner / ".coveragerc").write_text(
            "[run]\nsource = sample\nrelative_files = True\nbranch = True\n"
        )
        destination = tmp_path / f".coverage.shard-{index}"
        subprocess.run(
            [
                sys.executable,
                "-m",
                "pytest",
                "-q",
                "--cov=sample",
                "--cov-report=",
                "test_sample.py",
            ],
            cwd=runner,
            env={**os.environ, "COVERAGE_FILE": str(destination)},
            check=True,
            capture_output=True,
            timeout=60,
        )
        data_files.append(str(destination))
    combined = tmp_path / ".coverage"
    environment = {**os.environ, "COVERAGE_FILE": str(combined)}
    subprocess.run(
        [sys.executable, "-m", "coverage", "combine", *data_files],
        cwd=tmp_path,
        env=environment,
        check=True,
        capture_output=True,
        timeout=30,
    )
    from coverage import CoverageData

    data = CoverageData(basename=str(combined))
    data.read()
    assert data.measured_files() == {"sample.py"}
    assert {(2, 3), (2, 4)} <= set(data.arcs("sample.py") or [])
