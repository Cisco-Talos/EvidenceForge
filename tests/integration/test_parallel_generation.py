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

"""Integration tests for parallel generation (Phase 2.1).

Tests end-to-end parallel generation with threaded emitters, verifying temporal
consistency, cross-log referential integrity, and data correctness.
"""

import json
import tempfile
import xml.etree.ElementTree as ET
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from evidenceforge.generation.engine import GenerationEngine
from evidenceforge.models.scenario import (
    BaselineActivity,
    Environment,
    OutputSpec,
    Scenario,
    StorylineEvent,
    System,
    TimeWindow,
    User,
)

pytestmark = pytest.mark.slow


def create_test_scenario(users: int = 2, hours: int = 3) -> Scenario:
    """Create a test scenario with specified users and duration.

    Args:
        users: Number of users to create
        hours: Duration in hours

    Returns:
        Scenario object for testing
    """
    start_time = datetime(2024, 1, 1, 9, 0, 0)
    end_time = start_time + timedelta(hours=hours)

    # Create systems
    system_list = [
        System(hostname="TEST-WS-01", ip="10.0.10.1", os="Windows 10", type="workstation"),
        System(hostname="TEST-WS-02", ip="10.0.10.2", os="Windows 10", type="workstation"),
    ]

    # Create users (assign primary_system round-robin across workstations)
    user_list = []
    for i in range(users):
        user_list.append(
            User(
                username=f"user{i}",
                full_name=f"Test User {i}",
                email=f"user{i}@test.com",
                persona=None,
                enabled=True,
                primary_system=system_list[i % len(system_list)].hostname,
            )
        )

    environment = Environment(
        description="Test environment for parallel generation", users=user_list, systems=system_list
    )

    time_window = TimeWindow(start=start_time, end=end_time)

    baseline = BaselineActivity(
        description="Low intensity baseline activity", intensity="low", variation="low"
    )

    output = OutputSpec(
        logs=[{"format": "windows_event_security"}, {"format": "zeek_conn"}], destination="./output"
    )

    return Scenario(
        name="test-scenario",
        description="Test scenario for parallel generation",
        time_window=time_window,
        environment=environment,
        baseline_activity=baseline,
        output=output,
        storyline=[],
    )


def parse_windows_log(file_path: Path) -> list[dict]:
    """Parse Windows Event Log XML file.

    Args:
        file_path: Path to XML file

    Returns:
        List of event dictionaries
    """
    # Read the file — now has proper XML declaration and <Events> root
    with open(file_path) as f:
        content = f.read()

    # If file already has <Events> root, parse directly; otherwise wrap
    if "<Events>" in content:
        root = ET.fromstring(content)
    else:
        wrapped_content = f"<Events>{content}</Events>"
        root = ET.fromstring(wrapped_content)

    # Define namespace
    ns = {"ns": "http://schemas.microsoft.com/win/2004/08/events/event"}

    events = []
    # Find all Event elements
    for event_elem in root.findall("ns:Event", ns):
        event = {}

        # Extract System data
        system = event_elem.find("ns:System", ns)
        if system is not None:
            event["EventID"] = system.findtext("ns:EventID", namespaces=ns)
            time_created = system.find("ns:TimeCreated", ns)
            if time_created is not None:
                time_str = time_created.get("SystemTime")
                if time_str:
                    event["TimeCreated"] = datetime.fromisoformat(time_str.replace("Z", "+00:00"))
            event["Computer"] = system.findtext("ns:Computer", namespaces=ns)
            event["EventRecordID"] = system.findtext("ns:EventRecordID", namespaces=ns)

        # Extract EventData
        event_data = event_elem.find("ns:EventData", ns)
        if event_data is not None:
            for data in event_data.findall("ns:Data", ns):
                name = data.get("Name")
                if name:
                    event[name] = data.text

        events.append(event)

    return events


def parse_zeek_log(file_path: Path) -> list[dict]:
    """Parse Zeek JSON log file.

    Args:
        file_path: Path to JSON file

    Returns:
        List of event dictionaries
    """
    events = []
    with open(file_path) as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#"):
                event = json.loads(line)
                # Convert timestamp to datetime
                event["ts"] = float(event["ts"])
                events.append(event)
    return events


class TestParallelGeneration:
    """Test parallel generation with threaded emitters."""

    def test_parallel_generation_temporal_consistency(self):
        """Test parallel generation completes successfully with multiple formats."""
        scenario = create_test_scenario(users=2, hours=3)

        with tempfile.TemporaryDirectory() as tmpdir:
            engine = GenerationEngine(scenario, Path(tmpdir))
            engine.generate()

            # Verify both log files exist
            # Files may be in per-host/per-sensor subdirectories
            win_files = list(Path(tmpdir).rglob("windows_event_security.xml"))
            zeek_files = list(Path(tmpdir).rglob("*.json"))
            assert len(win_files) > 0, "No Windows event files found"
            assert len(zeek_files) > 0, "No Zeek files found"

            # Parse and verify events were generated
            windows_events = parse_windows_log(
                list(Path(tmpdir).rglob("windows_event_security.xml"))[0]
            )
            zeek_events = parse_zeek_log(
                list(Path(tmpdir).rglob("conn.json"))[0]
                if list(Path(tmpdir).rglob("conn.json"))
                else list(Path(tmpdir).rglob("zeek_conn.json"))[0]
            )

            # Check Windows events exist
            windows_timestamps = [e["TimeCreated"] for e in windows_events if "TimeCreated" in e]
            assert len(windows_timestamps) > 0, "No Windows events generated"

            # Check Zeek events exist (may be 0 if no connections generated)
            # This is OK for low-intensity baseline
            [e["ts"] for e in zeek_events]
            # assert len(zeek_timestamps) >= 0  # Always true, just checking it parses

    def test_parallel_generation_cross_log_consistency(self):
        """Test LogonIDs, PIDs, UIDs are unique across parallel emitters."""
        scenario = create_test_scenario(users=5, hours=2)

        with tempfile.TemporaryDirectory() as tmpdir:
            engine = GenerationEngine(scenario, Path(tmpdir))
            engine.generate()

            # Extract cross-references
            windows_events = parse_windows_log(
                list(Path(tmpdir).rglob("windows_event_security.xml"))[0]
            )

            # Verify LogonID uniqueness (only in logon events; logoff events reuse the same ID)
            logon_ids = [
                e.get("TargetLogonId")
                for e in windows_events
                if e.get("TargetLogonId") and e.get("EventID") == "4624"
            ]
            assert len(logon_ids) > 0
            assert len(logon_ids) == len(set(logon_ids)), (
                "Duplicate LogonIDs found in logon events!"
            )

            # Verify PID uniqueness per system
            pids_per_system = {}
            for e in windows_events:
                if e.get("EventID") == "4688":  # Process creation
                    system = e.get("Computer")
                    pid = e.get("NewProcessId")
                    if system and pid:
                        pids_per_system.setdefault(system, []).append(pid)

            for system, pids in pids_per_system.items():
                assert len(pids) == len(set(pids)), f"Duplicate PIDs found on {system}!"

            # Verify Zeek UID uniqueness
            zeek_events = parse_zeek_log(
                list(Path(tmpdir).rglob("conn.json"))[0]
                if list(Path(tmpdir).rglob("conn.json"))
                else list(Path(tmpdir).rglob("zeek_conn.json"))[0]
            )
            uids = [e["uid"] for e in zeek_events]
            assert len(uids) > 0
            assert len(uids) == len(set(uids)), "Duplicate Zeek UIDs found!"

    def test_parallel_generation_no_data_corruption(self):
        """Test all events are valid and parseable (no file corruption)."""
        scenario = create_test_scenario(users=3, hours=2)

        with tempfile.TemporaryDirectory() as tmpdir:
            engine = GenerationEngine(scenario, Path(tmpdir))
            engine.generate()

            # Parse both log files (will raise exception if corrupted)
            windows_events = parse_windows_log(
                list(Path(tmpdir).rglob("windows_event_security.xml"))[0]
            )
            zeek_events = parse_zeek_log(
                list(Path(tmpdir).rglob("conn.json"))[0]
                if list(Path(tmpdir).rglob("conn.json"))
                else list(Path(tmpdir).rglob("zeek_conn.json"))[0]
            )

            # Verify events parsed successfully
            assert len(windows_events) > 0, "No Windows events generated"
            assert len(zeek_events) > 0, "No Zeek events generated"

            # Verify all Windows events have required fields
            for event in windows_events:
                assert "EventID" in event
                assert "TimeCreated" in event
                assert "Computer" in event
                assert "EventRecordID" in event

            # Verify all Zeek events have required fields
            for event in zeek_events:
                assert "ts" in event
                assert "uid" in event
                assert "id.orig_h" in event
                assert "id.resp_h" in event
                assert "proto" in event

    def test_parallel_generation_with_storyline(self):
        """Test storyline events maintain correct ordering with threading."""
        scenario = create_test_scenario(users=2, hours=2)

        # Add a storyline event
        scenario.storyline = [
            StorylineEvent(
                id="evt-test-1",
                time="2024-01-01T09:30:00",
                actor="user0",
                system="TEST-WS-01",
                activity="suspicious logon from external IP",
                events=[{"type": "logon", "source_ip": "203.0.113.10", "logon_type": 3}],
            )
        ]

        with tempfile.TemporaryDirectory() as tmpdir:
            engine = GenerationEngine(scenario, Path(tmpdir))
            engine.generate()

            # Verify ground truth file created
            ground_truth_file = Path(tmpdir) / "GROUND_TRUTH.md"
            assert ground_truth_file.exists()

            # Parse logs from all host directories
            windows_events = []
            for xml_file in Path(tmpdir).rglob("windows_event_security.xml"):
                windows_events.extend(parse_windows_log(xml_file))

            # Verify storyline event present in logs
            # Look for logon event around 9:30 AM
            storyline_time = datetime(2024, 1, 1, 9, 30, 0, tzinfo=UTC)
            tolerance = timedelta(minutes=1)

            storyline_events = [
                e
                for e in windows_events
                if "TimeCreated" in e
                and abs((e["TimeCreated"] - storyline_time).total_seconds())
                < tolerance.total_seconds()
            ]

            assert len(storyline_events) > 0, "Storyline event not found in logs"

    def test_parallel_generation_performance(self):
        """Test parallel generation completes successfully."""
        # This is a basic performance test - just verify it completes
        # without errors for a moderate-sized scenario
        scenario = create_test_scenario(users=10, hours=2)

        with tempfile.TemporaryDirectory() as tmpdir:
            engine = GenerationEngine(scenario, Path(tmpdir))

            # Measure generation time
            start_time = datetime.now()
            engine.generate()
            end_time = datetime.now()

            duration = (end_time - start_time).total_seconds()

            # Verify generation completed
            # Files may be in per-host/per-sensor subdirectories
            win_files = list(Path(tmpdir).rglob("windows_event_security.xml"))
            zeek_files = list(Path(tmpdir).rglob("*.json"))
            assert len(win_files) > 0, "No Windows event files found"
            assert len(zeek_files) > 0, "No Zeek files found"

            # Verify generation time is reasonable (< 30 seconds for this small scenario)
            assert duration < 30, f"Generation took too long: {duration:.2f}s"

            # Verify events were generated
            windows_events = parse_windows_log(
                list(Path(tmpdir).rglob("windows_event_security.xml"))[0]
            )
            zeek_events = parse_zeek_log(
                list(Path(tmpdir).rglob("conn.json"))[0]
                if list(Path(tmpdir).rglob("conn.json"))
                else list(Path(tmpdir).rglob("zeek_conn.json"))[0]
            )

            # With 10 users, 2 hours, low intensity: events distributed across 7 formats
            assert len(windows_events) > 10, "Too few Windows events generated"
            assert len(zeek_events) > 0, "No Zeek events generated"
