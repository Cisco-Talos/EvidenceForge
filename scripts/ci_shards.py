"""Plan complete, deterministic CI shards and retain their execution inventories."""

from __future__ import annotations

import argparse
import json
import math
import sys
from collections import defaultdict
from pathlib import Path
from typing import Literal

import pytest
from pydantic import BaseModel, ConfigDict, Field, field_validator

ROOT = Path(__file__).resolve().parents[1]
TIMINGS = ROOT / ".github" / "ci" / "timings.json"


class TimingHistory(BaseModel):
    """Measured per-case costs; unknown cases use a bounded scheduling estimate."""

    model_config = ConfigDict(extra="forbid", frozen=True)
    schema_version: Literal[1] = 1
    default_seconds: float = Field(default=1.0, gt=0, le=3600)
    cases: dict[str, float] = Field(default_factory=dict)
    keep_modules: list[str] = Field(default_factory=list)

    @field_validator("cases")
    @classmethod
    def finite_costs(cls, values: dict[str, float]) -> dict[str, float]:
        """Reject invalid weights without ever changing which cases are selected."""
        if any(
            not math.isfinite(value) or value <= 0 or value > 86400 for value in values.values()
        ):
            raise ValueError("CI timing costs must be finite positive seconds, at most one day")
        return values


class ShardReport(BaseModel):
    """The complete collection, assignment and outcomes for one executed shard."""

    model_config = ConfigDict(extra="forbid")
    schema_version: Literal[1] = 1
    tier: Literal["routine", "slow"]
    index: int = Field(ge=0)
    count: int = Field(ge=1, le=64)
    inventory: list[str]
    selected: list[str]
    durations: dict[str, float] = Field(default_factory=dict)
    outcomes: dict[str, str] = Field(default_factory=dict)
    exit_code: int

    @field_validator("durations")
    @classmethod
    def valid_durations(cls, values: dict[str, float]) -> dict[str, float]:
        """Reject malformed timing data before it can seed later allocations."""
        if any(not math.isfinite(value) or value < 0 or value > 86400 for value in values.values()):
            raise ValueError("CI durations must be finite nonnegative seconds, at most one day")
        return values


class TimingDatabase(BaseModel):
    """Independent measured costs for routine platforms and the Linux slow tier."""

    model_config = ConfigDict(extra="forbid", frozen=True)
    schema_version: Literal[1] = 1
    profiles: dict[str, TimingHistory]


def load_timings(path: Path = TIMINGS, *, tier: str = "routine") -> TimingHistory:
    """Load a checked-in timing seed independently of the tested case inventory."""
    database = TimingDatabase.model_validate_json(path.read_text(encoding="utf-8"))
    operating_system = "windows" if sys.platform == "win32" else "linux"
    return database.profiles[f"{tier}-{operating_system}"]


def plan_shards(nodeids: list[str], count: int, history: TimingHistory) -> list[list[str]]:
    """Balance measured case costs, keeping configured shared-fixture modules together.

    Every collected case is assigned exactly once. Sorting provides a stable
    fallback for new cases and deterministic tie breaking across processes.
    """
    if not 1 <= count <= 64:
        raise ValueError("CI shard count must be between 1 and 64")
    if len(set(nodeids)) != len(nodeids):
        raise ValueError("CI collection contains duplicate node IDs")
    groups: dict[str, list[str]] = defaultdict(list)
    for nodeid in sorted(nodeids):
        module = nodeid.split("::", 1)[0]
        groups[module if module in history.keep_modules else nodeid].append(nodeid)
    weights = {
        name: sum(history.cases.get(nodeid, history.default_seconds) for nodeid in cases)
        for name, cases in groups.items()
    }
    shards: list[list[str]] = [[] for _ in range(count)]
    totals = [0.0] * count
    for name in sorted(groups, key=lambda name: (-weights[name], name)):
        index = min(range(count), key=lambda index: (totals[index], index))
        shards[index].extend(groups[name])
        totals[index] += weights[name]
    return [sorted(shard) for shard in shards]


def validate_reports(reports: list[ShardReport]) -> None:
    """Require all shards, the exact collection union and successful case outcomes."""
    if not reports:
        raise ValueError("No CI shard reports were supplied")
    first = reports[0]
    if len(reports) != first.count or {report.index for report in reports} != set(
        range(first.count)
    ):
        raise ValueError("CI shard reports are missing, duplicated or have invalid indices")
    expected = set(first.inventory)
    if not expected or len(expected) != len(first.inventory):
        raise ValueError("CI collection must be nonempty and unique")
    selected: list[str] = []
    for report in reports:
        if (
            report.count != first.count
            or report.tier != first.tier
            or report.inventory != first.inventory
        ):
            raise ValueError("CI shards disagree about their complete test inventory")
        if report.exit_code != 0 or not report.selected:
            raise ValueError("CI shard did not execute a successful nonempty selection")
        if set(report.outcomes) != set(report.selected):
            raise ValueError("CI shard is missing recorded test outcomes")
        if any(outcome not in {"passed", "skipped"} for outcome in report.outcomes.values()):
            raise ValueError("CI shard has failed or incomplete test outcomes")
        if "passed" not in report.outcomes.values():
            raise ValueError("CI shard contains no passing tests")
        selected.extend(report.selected)
    if len(selected) != len(set(selected)) or set(selected) != expected:
        raise ValueError("CI shard selections overlap or omit collected tests")


class ShardRecorder:
    """Pytest report hooks installed only for an explicitly requested CI shard."""

    def __init__(self, report: ShardReport, destination: Path) -> None:
        self.report = report
        self.destination = destination

    def pytest_runtest_logreport(self, report: pytest.TestReport) -> None:
        """Record each case's setup, call and teardown cost and terminal outcome."""
        nodeid = report.nodeid
        duration = report.duration
        self.report.durations[nodeid] = self.report.durations.get(nodeid, 0.0) + duration
        if report.failed:
            self.report.outcomes[nodeid] = "failed"
        elif self.report.outcomes.get(nodeid) != "failed":
            if report.skipped:
                self.report.outcomes[nodeid] = "skipped"
            elif report.when == "call":
                self.report.outcomes[nodeid] = "passed"

    def pytest_sessionfinish(self, exitstatus: int) -> None:
        """Persist the report even after a failed or interrupted test execution."""
        self.report.exit_code = int(exitstatus)
        self.destination.parent.mkdir(parents=True, exist_ok=True)
        self.destination.write_text(self.report.model_dump_json(indent=2) + "\n", encoding="utf-8")


def json_report(path: Path) -> ShardReport:
    """Read a bounded CI report from an explicitly selected local path."""
    if path.stat().st_size > 16 * 1024 * 1024:
        raise ValueError("CI shard report exceeds the 16 MiB size limit")
    return ShardReport.model_validate(json.loads(path.read_text(encoding="utf-8")))


def update_timings(profile: str, paths: list[Path], database_path: Path = TIMINGS) -> None:
    """Refresh a profile from a complete successful run without rerunning its tests."""
    database = TimingDatabase.model_validate_json(database_path.read_bytes())
    if profile not in database.profiles:
        raise ValueError("Unknown timing profile")
    reports: list[ShardReport] = []
    for path in paths:
        if path.stat().st_size > 16 * 1024 * 1024:
            raise ValueError("CI timing report exceeds the 16 MiB size limit")
        raw = json.loads(path.read_text(encoding="utf-8"))
        reports.append(ShardReport.model_validate(raw.get("shard", raw)))
    validate_reports(reports)
    if any(report.tier != profile.split("-", 1)[0] for report in reports):
        raise ValueError("CI timing profile and test tier differ")
    costs: dict[str, float] = {}
    for report in reports:
        if set(report.durations) != set(report.selected):
            raise ValueError("CI timing report omits selected case durations")
        costs.update({node: max(duration, 0.001) for node, duration in report.durations.items()})
    profiles = dict(database.profiles)
    profiles[profile] = database.profiles[profile].model_copy(update={"cases": costs})
    database_path.write_text(
        json.dumps(
            database.model_copy(update={"profiles": profiles}).model_dump(),
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )


def main() -> None:
    """Update checked-in timing seeds from downloaded successful shard evidence."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--profile", required=True)
    parser.add_argument("--reports", nargs="+", required=True, type=Path)
    parser.add_argument("--database", type=Path, default=TIMINGS)
    args = parser.parse_args()
    update_timings(args.profile, args.reports, args.database)


if __name__ == "__main__":
    main()
