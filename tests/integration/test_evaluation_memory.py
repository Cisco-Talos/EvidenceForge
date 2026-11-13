"""Small real workers verify resource-fixture validity and the observation boundary."""

from pathlib import Path

import pytest
from scripts.check_evaluation_memory import Workload, measure


@pytest.mark.parametrize("workload,sources", [("processes", 1), ("correlated", 5)])
def test_ready_worker_evaluates_valid_fixture_and_cleans_spilled_state(
    tmp_path: Path,
    workload: Workload,
    sources: int,
) -> None:
    result = measure(workload, 240, 1, tmp_path / workload)
    assert result.result.records == 240
    assert len(result.result.source_counts) == sources
    assert result.result.spec_conformance == 100
    assert result.result.resources["spilled"]
    assert result.result.scratch_clean
    assert result.samples >= 2
    assert result.peak_rss_bytes >= result.baseline_rss_bytes > 0
