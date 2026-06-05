# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
#
# SPDX-License-Identifier: MIT

"""Integration tests for medium-scale dataset generation.

Phase 2.8: Validates that the generation engine handles 100 users x 8 hours
without errors, within reasonable time and output bounds.

These tests are marked @pytest.mark.slow and skipped in normal test runs.
Run explicitly with: pytest -m slow
"""

import json
import tempfile
import tracemalloc
from datetime import datetime
from pathlib import Path

import pytest

from evidenceforge.generation.engine import GenerationEngine
from evidenceforge.models.scenario import Scenario
from evidenceforge.utils.files import load_yaml


@pytest.fixture(scope="module")
def medium_scenario():
    """Load and parse the medium-dataset scenario."""
    scenario_path = Path(__file__).parent.parent / "fixtures" / "scenarios" / "medium-dataset.yaml"
    data = load_yaml(scenario_path)
    return Scenario(**data)


@pytest.fixture(scope="module")
def generated_output(medium_scenario):
    """Generate medium dataset once, share across all tests in this module."""
    with tempfile.TemporaryDirectory() as tmpdir:
        engine = GenerationEngine(medium_scenario, Path(tmpdir))

        start = datetime.now()
        engine.generate()
        duration = (datetime.now() - start).total_seconds()

        # Collect output info (scan recursively for per-host/per-sensor subdirs)
        # Aggregate sizes for same-named files across subdirectories
        output_dir = Path(tmpdir)
        files = {}
        for f in output_dir.rglob("*"):
            if f.is_file():
                if f.name in files:
                    # Aggregate: keep the larger file (or sum sizes)
                    files[f.name]["size"] += f.stat().st_size
                else:
                    files[f.name] = {
                        "path": f,
                        "size": f.stat().st_size,
                        "content": f.read_text() if f.stat().st_size < 100_000_000 else None,
                    }

        yield {
            "dir": output_dir,
            "files": files,
            "duration": duration,
            "scenario": medium_scenario,
        }


def _generated_file(generated_output: dict, *names: str) -> dict | None:
    """Return the first aggregated generated file matching one of the names."""
    for name in names:
        file_info = generated_output["files"].get(name)
        if file_info is not None:
            return file_info
    return None


@pytest.mark.slow
class TestMediumDatasetGeneration:
    """Tests for 100-user 8-hour dataset generation."""

    def test_generates_without_errors(self, generated_output):
        """100 users x 8 hours should complete without exceptions."""
        assert generated_output["duration"] > 0
        assert len(generated_output["files"]) > 0

    def test_completes_in_reasonable_time(self, generated_output):
        """Generation should complete in under 5 minutes."""
        duration = generated_output["duration"]
        assert duration < 300, f"Generation took {duration:.1f}s (limit: 300s)"

    def test_produces_expected_output_files(self, generated_output):
        """Should produce at least Windows Event, Zeek, eCAR, and syslog files."""
        filenames = set(generated_output["files"].keys())
        assert "windows_event_security.xml" in filenames
        assert "conn.json" in filenames
        assert "ecar.json" in filenames
        assert "syslog.log" in filenames

    def test_windows_events_substantial(self, generated_output):
        """Should produce substantial Windows Event output (>1MB)."""
        win_file = generated_output["files"].get("windows_event_security.xml")
        assert win_file is not None
        assert win_file["size"] > 1_000_000, f"Windows events too small: {win_file['size']} bytes"

    def test_zeek_events_substantial(self, generated_output):
        """Should produce substantial Zeek output (>100KB)."""
        zeek_file = _generated_file(generated_output, "conn.json", "zeek_conn.json")
        assert zeek_file is not None
        assert zeek_file["size"] > 100_000, f"Zeek output too small: {zeek_file['size']} bytes"

    def test_zeek_events_valid_json(self, generated_output):
        """All Zeek events should be valid JSON (NDJSON)."""
        zeek_file = _generated_file(generated_output, "conn.json", "zeek_conn.json")
        if zeek_file is None or zeek_file["content"] is None:
            pytest.skip("Zeek file too large or missing")

        line_count = 0
        for line in zeek_file["content"].splitlines():
            if line.strip():
                json.loads(line)  # Will raise if invalid
                line_count += 1

        assert line_count > 100, f"Only {line_count} Zeek events generated"

    def test_ecar_events_valid_json(self, generated_output):
        """All eCAR events should be valid JSON (NDJSON)."""
        ecar_file = generated_output["files"].get("ecar.json")
        if ecar_file is None or ecar_file["content"] is None:
            pytest.skip("eCAR file too large or missing")

        line_count = 0
        for line in ecar_file["content"].splitlines():
            if line.strip():
                json.loads(line)
                line_count += 1

        assert line_count > 100, f"Only {line_count} eCAR events generated"


@pytest.mark.slow
class TestMediumDatasetMemory:
    """Memory usage tests for medium dataset generation."""

    @pytest.mark.skip(reason="500MB ceiling is not a release gate; retained as reference only")
    def test_peak_memory_under_500mb(self, medium_scenario):
        """Peak memory during generation should stay under 500MB."""
        tracemalloc.start()

        with tempfile.TemporaryDirectory() as tmpdir:
            engine = GenerationEngine(medium_scenario, Path(tmpdir))
            engine.generate()

        _, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()

        peak_mb = peak / (1024 * 1024)
        assert peak_mb < 500, f"Peak memory {peak_mb:.1f}MB exceeds 500MB limit"
