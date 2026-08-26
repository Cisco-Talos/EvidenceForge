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

"""MetroLink release and opt-in soak generation workloads."""

import json
import tempfile
from datetime import datetime
from pathlib import Path
from typing import Any

import pytest

from evidenceforge.composition import compile_scenario
from evidenceforge.generation.engine import GenerationEngine
from evidenceforge.models.scenario import Scenario
from evidenceforge.utils.files import load_yaml


@pytest.fixture(scope="module")
def metrolink_consumer():
    """Resolve the fixed-seed MetroLink consumer and retain exact release provenance."""

    scenario_path = (
        Path(__file__).parent.parent
        / "fixtures"
        / "scenarios"
        / "metrolink-specialty-care-pack.yaml"
    )
    return compile_scenario(scenario_path)


@pytest.fixture(scope="module")
def generated_output(metrolink_consumer):
    """Generate MetroLink once, sharing the bounded release workload across assertions."""
    with tempfile.TemporaryDirectory() as tmpdir:
        output_dir = Path(tmpdir).resolve()
        engine = GenerationEngine(
            metrolink_consumer.scenario,
            output_dir,
            compiled_scenario=metrolink_consumer,
            scenario_root=Path(__file__).parent.parent,
        )

        start = datetime.now()
        engine.generate()
        duration = (datetime.now() - start).total_seconds()

        # Collect output info (scan recursively for per-host/per-sensor subdirs)
        # Aggregate sizes for same-named files across subdirectories
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
            "compiled": metrolink_consumer,
            "scenario": metrolink_consumer.scenario,
        }


def _generated_file(generated_output: dict, *names: str) -> dict | None:
    """Return the first aggregated generated file matching one of the names."""
    for name in names:
        file_info = generated_output["files"].get(name)
        if file_info is not None:
            return file_info
    return None


def _json_records(output: Path, filename: str) -> list[dict[str, Any]]:
    """Return all NDJSON records with one source-native filename from a generated bundle."""

    records: list[dict[str, Any]] = []
    for path in output.rglob(filename):
        for line in path.read_text(encoding="utf-8").splitlines():
            if line.strip():
                records.append(json.loads(line))
    return records


@pytest.mark.slow
class TestMediumDatasetGeneration:
    """Tests over one shared MetroLink release generation."""

    def test_generates_without_errors(self, generated_output):
        """The representative multi-office consumer completes without exceptions."""
        assert generated_output["duration"] > 0
        assert len(generated_output["files"]) > 0

    def test_produces_expected_output_files(self, generated_output):
        """Should produce at least Windows Event, Zeek, eCAR, and syslog files."""
        filenames = set(generated_output["files"].keys())
        assert "windows_event_security.xml" in filenames
        assert "conn.json" in filenames
        assert "ecar.json" in filenames
        assert "syslog.log" in filenames

    def test_resolves_exact_locked_healthcare_release(self, generated_output):
        """The consumer preserves its tested organization and industry release bytes."""

        selected = {
            (pack.type, pack.name, pack.version): pack.digest
            for pack in generated_output["compiled"].selected_packs
        }
        assert selected == {
            (
                "industry",
                "healthcare",
                "1.0.0",
            ): "91f369c55113c940a9a907282b53fcc5629c54d3b91b79a869814cbcb7b82220",
            (
                "organization",
                "metrolink-specialty-care",
                "1.0.0",
            ): "78064394ad268bc8b5210b8e06b52fbdf1575652d170f7242a4560766555eecd",
        }

    def test_proves_email_storage_endpoint_and_network_evidence(self, generated_output):
        """MetroLink's owned services render the representative evidence its release claims."""

        output = generated_output["dir"]
        storage = json.loads((output / "STORAGE_MANIFEST.json").read_text(encoding="utf-8"))
        share = next(
            item for item in storage["shares"] if item["ref"] == "MLSC-FILE-01.care_operations"
        )
        assert share["preset"] == "healthcare:clinical-department"
        assert share["file_count"] > 0

        syslog = "\n".join(path.read_text(encoding="utf-8") for path in output.rglob("syslog.log"))
        assert "from=<ana.ross@metrolinkcare.lab>" in syslog

        endpoint_records = _json_records(output, "ecar.json")
        assert any(
            record.get("hostname") == "MLSC-CARD-01"
            and record.get("object") == "FLOW"
            and record.get("principal") == "ana.ross"
            and record.get("properties", {}).get("dst_port") == "587"
            for record in endpoint_records
        )
        assert any(
            record.get("hostname") == "MLSC-FILE-01"
            and record.get("object") == "FILE"
            and record.get("action") == "READ"
            and str(record.get("properties", {}).get("file_path", "")).endswith(
                "Care Coordination\\Referral Status.pdf"
            )
            for record in endpoint_records
        )

        smb_records = _json_records(output, "smb_files.json")
        assert any(
            record.get("action") == "SMB::FILE_READ"
            and record.get("id.orig_h") == "10.61.10.21"
            and record.get("id.resp_h") == "10.61.60.20"
            and record.get("name") == "Care Coordination\\Referral Status.pdf"
            for record in smb_records
        )

    def test_windows_events_substantial(self, generated_output):
        """Should produce non-trivial Windows Event output."""
        win_file = generated_output["files"].get("windows_event_security.xml")
        assert win_file is not None
        assert win_file["size"] > 50_000, f"Windows events too small: {win_file['size']} bytes"

    def test_zeek_events_substantial(self, generated_output):
        """Should produce non-trivial Zeek output."""
        zeek_file = _generated_file(generated_output, "conn.json", "zeek_conn.json")
        assert zeek_file is not None
        assert zeek_file["size"] > 5_000, f"Zeek output too small: {zeek_file['size']} bytes"

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

        assert line_count > 50, f"Only {line_count} eCAR events generated"


@pytest.mark.soak
def test_full_hundred_user_eight_hour_fixture_generates() -> None:
    """The historical 800-user-hour workload remains an explicit diagnostic."""

    scenario_path = Path(__file__).parent.parent / "fixtures" / "scenarios" / "medium-dataset.yaml"
    scenario = Scenario(**load_yaml(scenario_path))
    with tempfile.TemporaryDirectory() as tmpdir:
        output = Path(tmpdir).resolve()
        GenerationEngine(scenario, output).generate()
        assert (output / "GENERATION_MANIFEST.json").exists()
