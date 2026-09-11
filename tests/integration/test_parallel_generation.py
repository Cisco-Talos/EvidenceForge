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
import xml.etree.ElementTree as ET
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from evidenceforge.generation.engine import GenerationEngine
from evidenceforge.models.scenario import (
    BaselineActivity,
    Environment,
    NetworkConfig,
    NetworkSegment,
    NetworkSensor,
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
        description="Test environment for parallel generation",
        users=user_list,
        systems=system_list,
        network=NetworkConfig(
            segments=[
                NetworkSegment(
                    name="workstations",
                    cidr="10.0.10.0/24",
                    exposure="internal",
                )
            ],
            sensors=[
                NetworkSensor(
                    name="zeek-workstations",
                    type="network",
                    placement="span",
                    monitoring_segments=["workstations"],
                    direction="bidirectional",
                    log_formats=["zeek"],
                )
            ],
        ),
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


def first_zeek_conn_file(output_dir: Path) -> Path:
    """Return the first generated Zeek conn log in sensor or direct-file mode."""
    conn_files = list(output_dir.rglob("conn.json"))
    if conn_files:
        return conn_files[0]
    legacy_conn_files = list(output_dir.rglob("zeek_conn.json"))
    if legacy_conn_files:
        return legacy_conn_files[0]
    raise AssertionError("No Zeek conn log found")


class TestParallelGeneration:
    """Test parallel generation with threaded emitters."""

    def test_parallel_generation_integrity(self, tmp_path: Path) -> None:
        """One shared run proves parsing, identity, timing, and storyline integrity."""

        scenario = create_test_scenario(users=5, hours=1)
        scenario.storyline = [
            StorylineEvent(
                id="evt-test-1",
                time="2024-01-01T09:15:00",
                actor="user0",
                system="TEST-WS-01",
                activity="suspicious logon from external IP",
                events=[{"type": "logon", "source_ip": "203.0.113.10", "logon_type": 3}],
            )
        ]
        GenerationEngine(scenario, tmp_path).generate()

        win_files = list(tmp_path.rglob("windows_event_security.xml"))
        zeek_files = list(tmp_path.rglob("conn.json"))
        assert win_files and zeek_files
        assert (tmp_path / "GROUND_TRUTH.md").exists()

        windows_events = [event for path in win_files for event in parse_windows_log(path)]
        zeek_events = parse_zeek_log(first_zeek_conn_file(tmp_path))
        assert windows_events and zeek_events
        for event in windows_events:
            assert {"EventID", "TimeCreated", "Computer", "EventRecordID"} <= event.keys()
        for event in zeek_events:
            assert {"ts", "uid", "id.orig_h", "id.resp_h", "proto"} <= event.keys()

        well_known_service_ids = {
            "SYSTEM": "0x3e7",
            "LOCAL SERVICE": "0x3e5",
            "NETWORK SERVICE": "0x3e4",
        }
        dynamic_logon_ids_by_host: dict[str, list[str]] = {}
        session_logons = [
            event
            for event in windows_events
            if event.get("TargetLogonId")
            and event.get("EventID") == "4624"
            and str(event.get("LogonType")) != "7"
        ]
        assert session_logons
        for event in session_logons:
            hostname = str(event["Computer"])
            username = str(event.get("TargetUserName") or "").upper()
            logon_id = str(event["TargetLogonId"]).lower()
            expected = well_known_service_ids.get(username)
            if expected is not None:
                assert str(event.get("LogonType")) == "5"
                assert logon_id == expected
            else:
                assert logon_id not in well_known_service_ids.values()
                dynamic_logon_ids_by_host.setdefault(hostname, []).append(logon_id)
        for logon_ids in dynamic_logon_ids_by_host.values():
            assert len(logon_ids) == len(set(logon_ids))

        active_pids: dict[str, set[str]] = {}
        for event in sorted(
            windows_events,
            key=lambda item: item.get("TimeCreated", datetime.min.replace(tzinfo=UTC)),
        ):
            hostname = str(event.get("Computer") or "")
            if event.get("EventID") == "4688" and event.get("NewProcessId"):
                pid = str(event["NewProcessId"])
                assert pid not in active_pids.setdefault(hostname, set())
                active_pids[hostname].add(pid)
            elif event.get("EventID") == "4689" and event.get("ProcessId"):
                active_pids.setdefault(hostname, set()).discard(str(event["ProcessId"]))

        uids = [event["uid"] for event in zeek_events]
        assert len(uids) == len(set(uids))
        storyline_time = datetime(2024, 1, 1, 9, 15, tzinfo=UTC)
        assert any(
            abs((event["TimeCreated"] - storyline_time).total_seconds()) < 60
            for event in windows_events
            if "TimeCreated" in event
        )
