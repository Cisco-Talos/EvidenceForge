"""Exact spill, ordering, identity and ownership contracts for evaluation."""

from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

from evidenceforge.evaluation.engine import EvaluationEngine
from evidenceforge.evaluation.indexes import HostTimeIndex
from evidenceforge.evaluation.parsers import ParsedRecord
from evidenceforge.evaluation.storage import (
    EvaluationWorkspace,
    PayloadSearch,
    bounded_counter,
    bounded_groups,
    bounded_list,
    bounded_map,
    bounded_nsmallest,
    bounded_set,
    bounded_sorted,
    evaluation_workspace,
    record_identity,
)
from evidenceforge.models.scenario import Scenario
from evidenceforge.utils.files import load_yaml


@pytest.mark.parametrize("budget", [1, 10_000_000])
def test_exact_collections_and_stable_record_identity(tmp_path: Path, budget: int) -> None:
    workspace = EvaluationWorkspace(budget, tmp_path)
    try:
        with evaluation_workspace(workspace):
            records = bounded_list()
            groups = bounded_groups()
            values = bounded_map()
            seen = bounded_set()
            for number in range(30):
                record = workspace.add_record(
                    ParsedRecord(source_format="ecar", raw=str(number), line_number=number)
                )
                records.append(record)
                groups[number % 3].append(record)
                values[number % 3] = record
                seen.add(record_identity(record))
            assert len(records) == 30
            assert len(seen) == 30
            assert list(groups) == [0, 1, 2]
            assert [r.raw for r in groups[0]] == [str(n) for n in range(0, 30, 3)]
            assert values[0].raw == "27"
            assert [record_identity(r) for r in records] == list(range(1, 31))
            assert [r.raw for r in bounded_sorted(records, key=lambda r: -r.line_number)][:3] == [
                "29",
                "28",
                "27",
            ]
            top = bounded_nsmallest(3, records, key=lambda r: -r.line_number)
            assert [r.raw for r in top] == ["29", "28", "27"]
    finally:
        workspace.close()
    assert list(tmp_path.iterdir()) == []


@pytest.mark.parametrize("budget", [1, 10_000_000])
def test_counter_get_keeps_missing_key_semantics(tmp_path: Path, budget: int) -> None:
    workspace = EvaluationWorkspace(budget, tmp_path)
    try:
        with evaluation_workspace(workspace):
            counts = bounded_counter()
            assert counts["missing"] == 0
            assert counts.get("missing") is None
            assert counts.get("missing", 17) == 17
            assert "missing" not in counts
            counts["present"] += 1
            assert counts.get("present") == 1
    finally:
        workspace.close()


@pytest.mark.parametrize("budget", [1, 10_000_000])
def test_ordered_group_range_and_lazy_slices(tmp_path: Path, budget: int) -> None:
    workspace = EvaluationWorkspace(budget, tmp_path)
    try:
        with evaluation_workspace(workspace):
            values = bounded_sorted([9.0, -2.0, 5.0, 0.0, 5.0])
            assert list(values) == [-2.0, 0.0, 5.0, 5.0, 9.0]
            assert list(values.in_range(0.0, 5.0)) == [0.0, 5.0, 5.0]
            assert list(values.in_range(0.0, 5.0, exclusive_upper=True)) == [0.0]
            assert list(values[1:4]) == [0.0, 5.0, 5.0]
            assert list(values[::-1]) == [9.0, 5.0, 5.0, 0.0, -2.0]
            base = datetime(2024, 1, 1, tzinfo=UTC)
            times = bounded_sorted([base, base - timedelta(seconds=1)])
            assert list(times) == [base - timedelta(seconds=1), base]
    finally:
        workspace.close()


@pytest.mark.parametrize("budget", [1, 3000, 10_000_000])
def test_host_candidates_preserve_source_insertion_order(tmp_path: Path, budget: int) -> None:
    workspace = EvaluationWorkspace(budget, tmp_path)
    try:
        with evaluation_workspace(workspace):
            index = HostTimeIndex(workspace)
            for source in ("syslog", "ecar"):
                for number in range(8):
                    record = workspace.add_record(
                        ParsedRecord(source_format=source, raw=f"{source}-{number}")
                    )
                    index.append("host", source, record)
                    index.append("alias", source, record)
            expected = [
                f"{source}-{number}" for source in ("syslog", "ecar") for number in range(8)
            ]
            assert [record.raw for _, record in index.candidates(["host", "alias"])] == expected
            assert list(index["host"]) == ["syslog", "ecar"]
            assert [record.raw for record in index["host"]["syslog"][::-1]] == expected[:8][::-1]
    finally:
        workspace.close()


@pytest.mark.parametrize(
    "parts,pattern",
    [
        (["abc", "def"], "bc\nde"),
        (["abc\r", "def"], "bc\nde"),
        (["a\rb", "c\r\nd"], "a\nb\nc\nd"),
        (["abc\r"], "bc\n"),
    ],
)
def test_payload_search_preserves_joined_newline_semantics(parts: list[str], pattern: str) -> None:
    normalized = "\n".join(parts).replace("\r\n", "\n").replace("\r", "\n")
    patterns = {pattern, "missing", "a", ""}
    index = PayloadSearch(parts, patterns)
    for value in patterns:
        assert (value in index) == (value in normalized)


def test_fixture_evaluation_equivalent_with_forced_spill(tmp_path: Path) -> None:

    root = Path(__file__).parents[1] / "fixtures"
    scenario = Scenario(**load_yaml(root / "scenarios/retail-store-ftp-attack.yaml"))
    reports = []
    for budget in [1, 256 * 1024 * 1024]:
        report = EvaluationEngine(
            root / "eval/good", scenario, memory_budget_bytes=budget, scratch_dir=tmp_path
        ).run()
        content = report.model_dump(exclude={"evaluated_at"})
        content["supplementary"].pop("evaluation_resources")
        reports.append(content)
    assert reports[0] == reports[1]
    assert list(tmp_path.iterdir()) == []


@pytest.mark.parametrize("budget", [1, 256 * 1024 * 1024])
def test_report_matches_pre_change_dev_snapshot(tmp_path: Path, budget: int) -> None:
    """The oracle was produced by untouched dev f93a25bf, not another new-engine path."""
    import json

    root = Path(__file__).parents[1] / "fixtures"
    scenario = Scenario(**load_yaml(root / "scenarios/retail-store-ftp-attack.yaml"))
    expected = json.loads((root / "eval/reference-f93a25bf.json").read_text())
    actual = (
        EvaluationEngine(
            root / "eval/good", scenario, memory_budget_bytes=budget, scratch_dir=tmp_path
        )
        .run()
        .model_dump(mode="json", exclude={"evaluated_at"})
    )
    actual["supplementary"].pop("evaluation_resources")
    assert actual == expected


@pytest.mark.parametrize("budget", [1, 10_000_000])
def test_mapping_keys_keep_python_numeric_and_clock_equality(tmp_path: Path, budget: int) -> None:
    from datetime import timezone

    workspace = EvaluationWorkspace(budget, tmp_path)
    try:
        with evaluation_workspace(workspace):
            values = bounded_map()
            values[True] = "first"
            values[1.0] = "second"
            assert len(values) == 1
            assert values[1] == "second"
            values[(datetime(2024, 1, 1, tzinfo=UTC), 2)] = "clock"
            assert (
                values[(datetime(2024, 1, 1, 1, tzinfo=timezone(timedelta(hours=1))), 2.0)]
                == "clock"
            )
    finally:
        workspace.close()


def test_ground_truth_index_handles_missing_source_buckets(tmp_path: Path) -> None:

    from evidenceforge.evaluation.ground_truth_agreement import _RecordIndex
    from evidenceforge.events.ground_truth_occurrence import (
        GroundTruthOccurrence,
        GroundTruthSourceExpectation,
    )

    root = Path(__file__).parents[1] / "fixtures"
    scenario = Scenario(**load_yaml(root / "scenarios/retail-store-ftp-attack.yaml"))
    at = datetime(2024, 1, 1, tzinfo=UTC)
    row = GroundTruthOccurrence(
        occurrence_id="o",
        action_id="a",
        intent_id="i",
        storyline_id="s",
        section="storyline",
        kind="process_create",
        time=at,
    )
    expectation = GroundTruthSourceExpectation(
        expectation_id="e",
        source_instance="host",
        source_host="host",
        family="edr",
        format="ecar",
        role="target",
        phase="create",
        expected="present",
        expected_time=at,
    )
    workspace = EvaluationWorkspace(1, tmp_path)
    try:
        with evaluation_workspace(workspace):
            index = _RecordIndex({}, scenario)
            assert list(index.candidates(row, expectation, {}, "point")) == []
    finally:
        workspace.close()


def test_interrupt_releases_only_owned_scratch(tmp_path: Path) -> None:

    root = Path(__file__).parents[1] / "fixtures"
    scenario = Scenario(**load_yaml(root / "scenarios/retail-store-ftp-attack.yaml"))
    unrelated = tmp_path / "keep-me"
    unrelated.write_text("unchanged")

    def interrupt(event: str, payload: dict[str, Any]) -> None:
        if event == "phase_done" and payload["phase"] == "parsing":
            assert any(tmp_path.glob("eforge-eval-*"))
            raise KeyboardInterrupt

    with pytest.raises(KeyboardInterrupt):
        EvaluationEngine(
            root / "eval/good",
            scenario,
            memory_budget_bytes=1,
            scratch_dir=tmp_path,
            progress_callback=interrupt,
        ).run()
    assert list(tmp_path.iterdir()) == [unrelated]
    assert unrelated.read_text() == "unchanged"


def test_sql_failure_has_no_report_and_releases_scratch(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import sqlite3

    from evidenceforge.models.exceptions import EvaluationError

    root = Path(__file__).parents[1] / "fixtures"
    scenario = Scenario(**load_yaml(root / "scenarios/retail-store-ftp-attack.yaml"))

    def fail_decode(self: EvaluationWorkspace, rid: int | None, payload: bytes | None) -> None:
        raise sqlite3.OperationalError("disk full")

    monkeypatch.setattr(EvaluationWorkspace, "decode", fail_decode)
    with pytest.raises(EvaluationError, match="scratch storage failed"):
        EvaluationEngine(
            root / "eval/good", scenario, memory_budget_bytes=1, scratch_dir=tmp_path
        ).run()
    assert list(tmp_path.iterdir()) == []


@pytest.mark.parametrize("budget", [1, 10_000_000])
def test_time_range_queries_preserve_insertion_order(tmp_path: Path, budget: int) -> None:
    from evidenceforge.evaluation.storage import append_group

    workspace = EvaluationWorkspace(budget, tmp_path)
    try:
        with evaluation_workspace(workspace):
            groups = bounded_groups()
            for value in [3.0, 1.0, 2.0]:
                append_group(groups, "host", value, sort=value)
            assert list(groups["host"].in_range(1.0, 2.0)) == [1.0, 2.0]
            assert list(groups["host"]) == [3.0, 1.0, 2.0]
            append_group(groups, "host", 0.0, sort=0.0)
            assert groups["host"].latest_before(1.0) == 1.0
            assert groups["host"].latest_before(1.0, strict=True) == 0.0
            assert list(groups["host"]) == [3.0, 1.0, 2.0, 0.0]
    finally:
        workspace.close()


@pytest.mark.slow
def test_full_evaluation_exceeds_old_record_cap_and_detects_last_failure(tmp_path: Path) -> None:
    import json

    root = Path(__file__).parents[1] / "fixtures"
    scenario = Scenario(**load_yaml(root / "scenarios/minimal.yaml"))
    scenario.output.logs = [{"format": "ecar"}]
    data = tmp_path / "data"
    host = data / "TEST-01"
    host.mkdir(parents=True)
    count = 500_001
    with (host / "ecar.json").open("w") as stream:
        for number in range(count):
            identity = f"00000000-0000-4000-8000-{number:012x}"
            stream.write(
                json.dumps(
                    {
                        "timestamp_ms": 1705312800000 + number % 86400 * 1000,
                        "id": identity,
                        "hostname": "TEST-01",
                        "object": "PROCESS",
                        "action": "CREATE",
                        "objectID": identity,
                        "pid": number + 10,
                        "tid": number + 10,
                        "ppid": 0,
                        "principal": "test_user",
                        "properties": {
                            "command_line": "cmd.exe /c ver",
                            "image_path": r"C:\Windows\System32\cmd.exe",
                        },
                    }
                )
                + "\n"
            )
        stream.write("not-json\n")
    scratch = tmp_path / "scratch"
    scratch.mkdir()
    import subprocess
    import sys

    code = """
import json,sys
from pathlib import Path
from evidenceforge.evaluation.engine import EvaluationEngine
from evidenceforge.models.scenario import Scenario
from evidenceforge.utils.files import load_yaml
scenario = Scenario(**load_yaml(Path(sys.argv[2])))
scenario.output.logs = [{"format": "ecar"}]
report = EvaluationEngine(Path(sys.argv[1]), scenario, memory_budget_bytes=16*1024*1024, scratch_dir=Path(sys.argv[3])).run()
try:
    import resource
    peak = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    if sys.platform != "darwin": peak *= 1024
except ImportError:
    peak = None
print(json.dumps({"report":report.model_dump(mode="json"),"peak_rss_bytes":peak}))
"""
    result = subprocess.run(
        [sys.executable, "-c", code, str(data), str(root / "scenarios/minimal.yaml"), str(scratch)],
        check=True,
        capture_output=True,
        text=True,
        timeout=600,
    )
    measured = json.loads(result.stdout)
    report = measured["report"]
    assert report["total_records"] == count + 1
    assert report["source_counts"]["ecar"] == count + 1
    schema = next(
        score
        for pillar in report["pillars"]
        for score in pillar["sub_scores"]
        if score["key"] == "spec_conformance"
    )
    assert schema["score"] == 100.0 * count / (count + 1)
    assert "500002" in " ".join(schema["sample_failures"])
    assert report["acceptance_passed"] is False
    assert report["supplementary"]["evaluation_resources"]["spilled"] is True
    if measured["peak_rss_bytes"] is not None:
        assert measured["peak_rss_bytes"] < 512 * 1024 * 1024
    (tmp_path / "resource-measurement.json").write_text(
        json.dumps(
            {
                "records": report["total_records"],
                "peak_rss_bytes": measured["peak_rss_bytes"],
                "resources": report["supplementary"]["evaluation_resources"],
            }
        )
    )
    assert list(scratch.iterdir()) == []
