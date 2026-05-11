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

"""Unit tests for ground truth generation."""

from datetime import UTC, datetime

import pytest

from evidenceforge.generation.ground_truth import GroundTruthGenerator
from evidenceforge.models import (
    BaselineActivity,
    Environment,
    OutputSpec,
    Scenario,
    StorylineEvent,
    System,
    TimeWindow,
    User,
)


class TestGroundTruthGenerator:
    """Tests for GroundTruthGenerator class."""

    @pytest.fixture
    def minimal_scenario(self):
        """Create minimal scenario with storyline."""
        return Scenario(
            version="1.0",
            name="test-attack",
            description="Test attack scenario",
            environment=Environment(
                description="Test environment",
                users=[
                    User(
                        username="attacker",
                        full_name="Attacker",
                        email="attacker@evil.com",
                        enabled=True,
                    ),
                    User(
                        username="victim",
                        full_name="Victim User",
                        email="victim@example.com",
                        enabled=True,
                    ),
                ],
                systems=[
                    System(hostname="TEST-01", ip="10.0.0.1", os="Windows 10", type="workstation")
                ],
            ),
            time_window=TimeWindow(start="2024-01-15T10:00:00Z", duration="2h"),
            baseline_activity=BaselineActivity(
                description="Test", intensity="low", variation="low"
            ),
            output=OutputSpec(
                logs=[{"format": "windows_event_security"}],
                destination="./output",
                compression=False,
            ),
            personas=[],
            storyline=[
                StorylineEvent(
                    id="evt-test-1",
                    time="2024-01-15T10:30:00Z",
                    actor="attacker",
                    system="TEST-01",
                    activity="Execute malicious PowerShell command",
                    events=[{"type": "process", "process_name": "cmd.exe"}],
                ),
                StorylineEvent(
                    id="evt-test-2",
                    time="2024-01-15T10:35:00Z",
                    actor="attacker",
                    system="TEST-01",
                    activity="Connect to C2 server",
                    events=[{"type": "process", "process_name": "cmd.exe"}],
                ),
            ],
        )

    @pytest.fixture
    def malicious_events(self):
        """Create sample malicious events."""
        return [
            {
                "time": datetime(2024, 1, 15, 10, 30, 0, tzinfo=UTC),
                "actor": "attacker",
                "system": "TEST-01",
                "activity": "Execute malicious PowerShell command",
                "type": "process",
                "process_name": "powershell.exe",
                "command_line": "powershell.exe -enc <base64_encoded_command>",
                "pid": 1234,
            },
            {
                "time": datetime(2024, 1, 15, 10, 35, 0, tzinfo=UTC),
                "actor": "attacker",
                "system": "TEST-01",
                "activity": "Connect to C2 server",
                "type": "connection",
                "dst_ip": "159.65.43.201",
                "dst_port": 443,
                "uid": "C12345",
            },
        ]

    def test_generate_creates_file(self, minimal_scenario, malicious_events, tmp_path):
        """generate() should create GROUND_TRUTH.md file."""
        output_path = tmp_path / "GROUND_TRUTH.md"
        generator = GroundTruthGenerator(minimal_scenario, malicious_events)

        generator.generate(output_path)

        assert output_path.exists()
        assert output_path.stat().st_size > 0

    def test_generate_includes_header(self, minimal_scenario, malicious_events, tmp_path):
        """Generated file should include header with scenario name and description."""
        output_path = tmp_path / "GROUND_TRUTH.md"
        generator = GroundTruthGenerator(minimal_scenario, malicious_events)

        generator.generate(output_path)
        content = output_path.read_text()

        assert "# Ground Truth: test-attack" in content
        assert "**Scenario:** Test attack scenario" in content
        assert "**Generated:**" in content

    def test_create_narrative_with_storyline(self, minimal_scenario, malicious_events):
        """_create_narrative() should extract narrative from storyline."""
        generator = GroundTruthGenerator(minimal_scenario, malicious_events)

        narrative = generator._create_narrative()

        assert "This scenario simulates the following attack sequence:" in narrative
        assert "1. **attacker** on **TEST-01**: Execute malicious PowerShell command" in narrative
        assert "2. **attacker** on **TEST-01**: Connect to C2 server" in narrative

    def test_create_narrative_without_storyline(self, minimal_scenario, malicious_events):
        """_create_narrative() should handle empty storyline."""
        minimal_scenario.storyline = []
        generator = GroundTruthGenerator(minimal_scenario, malicious_events)

        narrative = generator._create_narrative()

        assert "No malicious activities" in narrative

    def test_create_timeline_with_events(self, minimal_scenario, malicious_events):
        """_create_timeline() should create Markdown table with events."""
        generator = GroundTruthGenerator(minimal_scenario, malicious_events)

        timeline = generator._create_timeline()

        assert "| Timestamp | Actor | System | Event Type | Details |" in timeline
        assert "|-----------|" in timeline
        assert "| 2024-01-15 10:30:00 UTC | attacker | TEST-01 | Process |" in timeline
        assert "| 2024-01-15 10:35:00 UTC | attacker | TEST-01 | Connection |" in timeline

    def test_create_timeline_sorted_by_time(self, minimal_scenario):
        """_create_timeline() should sort events chronologically."""
        # Create events out of order
        events = [
            {
                "time": datetime(2024, 1, 15, 10, 35, 0, tzinfo=UTC),
                "actor": "attacker",
                "system": "TEST-01",
                "type": "connection",
                "dst_ip": "159.65.43.201",
                "dst_port": 443,
            },
            {
                "time": datetime(2024, 1, 15, 10, 30, 0, tzinfo=UTC),
                "actor": "attacker",
                "system": "TEST-01",
                "type": "process",
                "process_name": "cmd.exe",
            },
        ]
        generator = GroundTruthGenerator(minimal_scenario, events)

        timeline = generator._create_timeline()
        lines = timeline.split("\n")

        # First event in table (after headers) should be 10:30, then 10:35
        assert "10:30:00" in lines[2]  # First data row
        assert "10:35:00" in lines[3]  # Second data row

    def test_create_timeline_without_events(self, minimal_scenario):
        """_create_timeline() should handle empty events list."""
        generator = GroundTruthGenerator(minimal_scenario, [])

        timeline = generator._create_timeline()

        assert "No malicious events" in timeline

    def test_format_event_details_logon(self, minimal_scenario, malicious_events):
        """_format_event_details() should format logon events."""
        event = {"type": "logon", "source_ip": "203.0.113.50", "logon_id": "0x12345"}
        generator = GroundTruthGenerator(minimal_scenario, malicious_events)

        details = generator._format_event_details(event)

        assert "Network logon from 203.0.113.50" in details
        assert "LogonID: 0x12345" in details

    def test_format_event_details_process(self, minimal_scenario, malicious_events):
        """_format_event_details() should format process events."""
        event = {
            "type": "process",
            "process_name": "powershell.exe",
            "pid": 1234,
            "command_line": "powershell.exe -Command Get-Process",
        }
        generator = GroundTruthGenerator(minimal_scenario, malicious_events)

        details = generator._format_event_details(event)

        assert "Process: powershell.exe" in details
        assert "PID: 1234" in details
        assert "powershell.exe -Command Get-Process" in details

    def test_format_event_details_process_truncates_long_cmdline(
        self, minimal_scenario, malicious_events
    ):
        """_format_event_details() should truncate long command lines."""
        long_cmdline = "x" * 100
        event = {
            "type": "process",
            "process_name": "cmd.exe",
            "pid": 5678,
            "command_line": long_cmdline,
        }
        generator = GroundTruthGenerator(minimal_scenario, malicious_events)

        details = generator._format_event_details(event)

        assert len(details) < len(long_cmdline) + 50  # Should be truncated
        assert "..." in details  # Should have ellipsis

    def test_format_event_details_connection(self, minimal_scenario, malicious_events):
        """_format_event_details() should format connection events."""
        event = {"type": "connection", "dst_ip": "159.65.43.201", "dst_port": 443, "uid": "C12345"}
        generator = GroundTruthGenerator(minimal_scenario, malicious_events)

        details = generator._format_event_details(event)

        assert "Connection to 159.65.43.201:443" in details
        assert "UID: C12345" in details

    def test_format_event_details_rdp_session(self, minimal_scenario, malicious_events):
        """_format_event_details() should include UID for RDP sessions."""
        event = {"type": "rdp_session", "dst_ip": "10.0.10.5", "uid": "Cabcd1234"}
        generator = GroundTruthGenerator(minimal_scenario, malicious_events)
        details = generator._format_event_details(event)
        assert "RDP session to 10.0.10.5:3389" in details
        assert "UID: Cabcd1234" in details

    def test_format_event_details_ssh_session(self, minimal_scenario, malicious_events):
        """_format_event_details() should include UID for SSH sessions."""
        event = {"type": "ssh_session", "dst_ip": "10.0.20.3", "uid": "Cxyz9876"}
        generator = GroundTruthGenerator(minimal_scenario, malicious_events)
        details = generator._format_event_details(event)
        assert "SSH session to 10.0.20.3:22" in details
        assert "UID: Cxyz9876" in details

    def test_extract_iocs_rdp_session_uid(self, minimal_scenario):
        """_extract_iocs() should include RDP session UIDs in network IOCs."""
        events = [
            {
                "time": datetime(2024, 1, 15, 10, 30, 0, tzinfo=UTC),
                "actor": "attacker",
                "system": "TEST-01",
                "type": "rdp_session",
                "dst_ip": "10.0.10.5",
                "dst_port": 3389,
                "uid": "Cabcd1234",
            }
        ]
        generator = GroundTruthGenerator(minimal_scenario, events)
        iocs = generator._extract_iocs()
        network_iocs = iocs.get("network", set())
        assert "Zeek UID: Cabcd1234" in network_iocs
        assert "10.0.10.5:3389 (Lateral Movement)" in network_iocs

    def test_extract_iocs_filtered_uid_excluded(self, minimal_scenario):
        """_extract_iocs() should NOT include filtered UIDs."""
        events = [
            {
                "time": datetime(2024, 1, 15, 10, 30, 0, tzinfo=UTC),
                "actor": "attacker",
                "system": "TEST-01",
                "type": "ssh_session",
                "dst_ip": "10.0.20.3",
                "dst_port": 22,
                "uid": "(filtered by sensor placement)",
            }
        ]
        generator = GroundTruthGenerator(minimal_scenario, events)
        iocs = generator._extract_iocs()
        network_iocs = iocs.get("network", set())
        assert not any("Zeek UID" in ioc for ioc in network_iocs)

    def test_format_event_details_unknown_type(self, minimal_scenario, malicious_events):
        """_format_event_details() should handle unknown event types."""
        event = {"type": "unknown", "activity": "Some activity"}
        generator = GroundTruthGenerator(minimal_scenario, malicious_events)

        details = generator._format_event_details(event)

        assert "Some activity" in details

    def test_extract_iocs_network(self, minimal_scenario):
        """_extract_iocs() should extract network IOCs."""
        events = [
            {"actor": "attacker", "type": "logon", "source_ip": "203.0.113.50"},
            {"actor": "attacker", "type": "connection", "dst_ip": "159.65.43.201", "dst_port": 443},
        ]
        generator = GroundTruthGenerator(minimal_scenario, events)

        iocs = generator._extract_iocs()

        assert "network" in iocs
        assert "203.0.113.50 (Attacker IP)" in iocs["network"]
        assert "159.65.43.201:443 (C2 Server)" in iocs["network"]

    def test_extract_iocs_processes(self, minimal_scenario):
        """_extract_iocs() should extract process IOCs."""
        events = [
            {
                "actor": "attacker",
                "type": "process",
                "process_name": "powershell.exe",
                "command_line": "powershell.exe -enc PAYLOAD",
            }
        ]
        generator = GroundTruthGenerator(minimal_scenario, events)

        iocs = generator._extract_iocs()

        assert "processes" in iocs
        assert "powershell.exe" in iocs["processes"]
        assert "`powershell.exe -enc PAYLOAD`" in iocs["processes"]

    def test_extract_iocs_users(self, minimal_scenario):
        """_extract_iocs() should extract user IOCs."""
        events = [
            {"actor": "attacker", "type": "logon"},
            {"actor": "victim", "type": "process", "process_name": "cmd.exe"},
        ]
        generator = GroundTruthGenerator(minimal_scenario, events)

        iocs = generator._extract_iocs()

        assert "users" in iocs
        assert "attacker" in iocs["users"]
        assert "victim" in iocs["users"]

    def test_extract_iocs_deduplicates(self, minimal_scenario):
        """_extract_iocs() should deduplicate IOCs."""
        events = [
            {"actor": "attacker", "type": "process", "process_name": "powershell.exe"},
            {"actor": "attacker", "type": "process", "process_name": "powershell.exe"},
        ]
        generator = GroundTruthGenerator(minimal_scenario, events)

        iocs = generator._extract_iocs()

        # Should only appear once
        assert len(iocs["users"]) == 1
        assert len([p for p in iocs["processes"] if p == "powershell.exe"]) == 1

    def test_extract_iocs_removes_empty_categories(self, minimal_scenario):
        """_extract_iocs() should remove empty IOC categories."""
        events = [{"actor": "attacker", "type": "process", "process_name": "cmd.exe"}]
        generator = GroundTruthGenerator(minimal_scenario, events)

        iocs = generator._extract_iocs()

        # Should have users and processes, but not network or files
        assert "users" in iocs
        assert "processes" in iocs
        assert "network" not in iocs
        assert "files" not in iocs

    def test_format_iocs_network_section(self, minimal_scenario, malicious_events):
        """_format_iocs() should format network IOC section."""
        iocs = {"network": {"159.65.43.201:443 (C2 Server)", "203.0.113.50 (Attacker IP)"}}
        generator = GroundTruthGenerator(minimal_scenario, malicious_events)

        formatted = generator._format_iocs(iocs)

        assert "### Network IOCs" in formatted
        assert "- 159.65.43.201:443 (C2 Server)" in formatted
        assert "- 203.0.113.50 (Attacker IP)" in formatted

    def test_format_iocs_process_section(self, minimal_scenario, malicious_events):
        """_format_iocs() should format process IOC section."""
        iocs = {"processes": {"powershell.exe", "`powershell.exe -enc PAYLOAD`"}}
        generator = GroundTruthGenerator(minimal_scenario, malicious_events)

        formatted = generator._format_iocs(iocs)

        assert "### Process IOCs" in formatted
        assert "- powershell.exe" in formatted
        assert "- `powershell.exe -enc PAYLOAD`" in formatted

    def test_format_iocs_user_section(self, minimal_scenario, malicious_events):
        """_format_iocs() should format user IOC section."""
        iocs = {"users": {"attacker", "victim"}}
        generator = GroundTruthGenerator(minimal_scenario, malicious_events)

        formatted = generator._format_iocs(iocs)

        assert "### User IOCs" in formatted
        assert "- attacker (compromised account)" in formatted
        assert "- victim (compromised account)" in formatted

    def test_format_iocs_empty(self, minimal_scenario, malicious_events):
        """_format_iocs() should handle empty IOCs."""
        generator = GroundTruthGenerator(minimal_scenario, malicious_events)

        formatted = generator._format_iocs({})

        assert "No IOCs extracted" in formatted

    def test_format_iocs_sorted(self, minimal_scenario, malicious_events):
        """_format_iocs() should sort IOCs alphabetically."""
        iocs = {"users": {"zebra", "alpha", "beta"}}
        generator = GroundTruthGenerator(minimal_scenario, malicious_events)

        formatted = generator._format_iocs(iocs)
        lines = formatted.split("\n")

        # Find lines with IOCs
        ioc_lines = [line for line in lines if line.startswith("- ")]

        # Should be in alphabetical order
        assert "- alpha" in ioc_lines[0]
        assert "- beta" in ioc_lines[1]
        assert "- zebra" in ioc_lines[2]

    def test_generate_includes_all_sections(self, minimal_scenario, malicious_events, tmp_path):
        """generate() should include all sections in output."""
        output_path = tmp_path / "GROUND_TRUTH.md"
        generator = GroundTruthGenerator(minimal_scenario, malicious_events)

        generator.generate(output_path)
        content = output_path.read_text()

        # Verify all major sections present
        assert "# Ground Truth:" in content
        assert "## Attack Summary" in content
        assert "## Timeline" in content
        assert "## Indicators of Compromise (IOCs)" in content

    def test_extract_iocs_connection_without_port(self, minimal_scenario):
        """_extract_iocs() should handle connections without port."""
        events = [
            {
                "actor": "attacker",
                "type": "connection",
                "dst_ip": "159.65.43.201",
                # No dst_port
            }
        ]
        generator = GroundTruthGenerator(minimal_scenario, events)

        iocs = generator._extract_iocs()

        assert "network" in iocs
        assert "159.65.43.201 (C2 Server)" in iocs["network"]

    def test_format_event_details_missing_fields(self, minimal_scenario, malicious_events):
        """_format_event_details() should handle missing optional fields."""
        # Logon without optional fields
        event_logon = {"type": "logon"}
        generator = GroundTruthGenerator(minimal_scenario, malicious_events)
        details = generator._format_event_details(event_logon)
        assert "N/A" in details

        # Process without optional fields
        event_process = {"type": "process"}
        details = generator._format_event_details(event_process)
        assert "N/A" in details

        # Connection without optional fields
        event_conn = {"type": "connection"}
        details = generator._format_event_details(event_conn)
        assert "N/A" in details

    def test_red_herring_section_in_output(self, minimal_scenario, malicious_events, tmp_path):
        """GROUND_TRUTH.md should include Red Herrings section when red herrings exist."""
        red_herrings = [
            {
                "time": datetime(2024, 1, 15, 10, 45, 0, tzinfo=UTC),
                "actor": "admin.jones",
                "system": "SRV-DB-01",
                "activity": "PowerShell maintenance script",
                "explanation": "Scheduled weekly database maintenance",
            },
        ]
        output_path = tmp_path / "GROUND_TRUTH.md"
        generator = GroundTruthGenerator(
            minimal_scenario, malicious_events, red_herring_events=red_herrings
        )
        generator.generate(output_path)
        content = output_path.read_text()

        assert "## Red Herrings" in content
        assert "appear suspicious but are benign" in content

    def test_red_herring_explanations_included(self, minimal_scenario, malicious_events, tmp_path):
        """Each red herring's explanation text should appear in the output."""
        red_herrings = [
            {
                "time": datetime(2024, 1, 15, 10, 45, 0, tzinfo=UTC),
                "actor": "admin.jones",
                "system": "SRV-DB-01",
                "activity": "PowerShell maintenance script",
                "explanation": "Scheduled weekly database maintenance",
            },
            {
                "time": datetime(2024, 1, 15, 11, 0, 0, tzinfo=UTC),
                "actor": "svc_backup",
                "system": "SRV-FILE-01",
                "activity": "Large file transfer to cloud",
                "explanation": "Nightly backup to Azure Blob",
            },
        ]
        output_path = tmp_path / "GROUND_TRUTH.md"
        generator = GroundTruthGenerator(
            minimal_scenario, malicious_events, red_herring_events=red_herrings
        )
        generator.generate(output_path)
        content = output_path.read_text()

        assert "Scheduled weekly database maintenance" in content
        assert "Nightly backup to Azure Blob" in content
        assert "admin.jones" in content
        assert "svc_backup" in content

    def test_no_red_herrings_no_section(self, minimal_scenario, malicious_events, tmp_path):
        """Red Herrings section should be omitted when no red herrings exist."""
        output_path = tmp_path / "GROUND_TRUTH.md"
        generator = GroundTruthGenerator(minimal_scenario, malicious_events)
        generator.generate(output_path)
        content = output_path.read_text()

        assert "## Red Herrings" not in content

    def test_red_herring_table_format(self, minimal_scenario, malicious_events, tmp_path):
        """Red herring section should use table format with correct columns."""
        red_herrings = [
            {
                "time": datetime(2024, 1, 15, 10, 45, 0, tzinfo=UTC),
                "actor": "admin.jones",
                "system": "SRV-DB-01",
                "activity": "Admin PowerShell",
                "explanation": "Maintenance",
            },
        ]
        output_path = tmp_path / "GROUND_TRUTH.md"
        generator = GroundTruthGenerator(
            minimal_scenario, malicious_events, red_herring_events=red_herrings
        )
        generator.generate(output_path)
        content = output_path.read_text()

        assert "| Timestamp | Actor | System | Activity | Why It's Benign |" in content
        assert "| 2024-01-15 10:45:00 UTC | admin.jones | SRV-DB-01 |" in content

    # --- Tests for new event type IOC extraction ---

    def test_extract_iocs_service_installed(self, minimal_scenario):
        """_extract_iocs() should extract file and process IOCs from service_installed."""
        events = [
            {
                "actor": "attacker",
                "type": "service_installed",
                "service_name": "EvilSvc",
                "service_file_name": "C:\\Windows\\Temp\\payload.exe",
            }
        ]
        generator = GroundTruthGenerator(minimal_scenario, events)
        iocs = generator._extract_iocs()
        assert "C:\\Windows\\Temp\\payload.exe" in iocs["files"]
        assert "Service: EvilSvc" in iocs["processes"]

    def test_extract_iocs_scheduled_task_created(self, minimal_scenario):
        """_extract_iocs() should extract task name and command from scheduled_task_created."""
        task_xml = (
            '<?xml version="1.0"?>\n'
            "<Task><Actions><Exec>"
            "<Command>C:\\Windows\\System32\\cmd.exe</Command>"
            "</Exec></Actions></Task>"
        )
        events = [
            {
                "actor": "attacker",
                "type": "scheduled_task_created",
                "task_name": "Updater",
                "task_content": task_xml,
            }
        ]
        generator = GroundTruthGenerator(minimal_scenario, events)
        iocs = generator._extract_iocs()
        assert "Scheduled Task: Updater" in iocs["processes"]
        assert "C:\\Windows\\System32\\cmd.exe" in iocs["files"]

    def test_extract_iocs_create_remote_thread(self, minimal_scenario):
        """_extract_iocs() should extract target process from create_remote_thread."""
        events = [
            {
                "actor": "attacker",
                "type": "create_remote_thread",
                "target_process": "C:\\Windows\\System32\\lsass.exe",
            }
        ]
        generator = GroundTruthGenerator(minimal_scenario, events)
        iocs = generator._extract_iocs()
        assert "Injection Target: C:\\Windows\\System32\\lsass.exe" in iocs["processes"]

    def test_extract_iocs_skips_unemitted_events(self, minimal_scenario):
        """_extract_iocs() should not list indicators for skipped evidence."""
        events = [
            {
                "actor": "attacker",
                "type": "create_remote_thread",
                "target_process": "C:\\Windows\\System32\\lsass.exe",
                "skipped_reason": "no_live_source_process",
            }
        ]
        generator = GroundTruthGenerator(minimal_scenario, events)
        iocs = generator._extract_iocs()
        assert "Injection Target: C:\\Windows\\System32\\lsass.exe" not in iocs.get(
            "processes", set()
        )

    def test_extract_iocs_account_created(self, minimal_scenario):
        """_extract_iocs() should extract target username from account_created."""
        events = [
            {
                "actor": "attacker",
                "type": "account_created",
                "target_username": "backdoor_admin",
            }
        ]
        generator = GroundTruthGenerator(minimal_scenario, events)
        iocs = generator._extract_iocs()
        assert "backdoor_admin" in iocs["users"]

    def test_extract_iocs_account_deleted(self, minimal_scenario):
        """_extract_iocs() should extract target username from account_deleted."""
        events = [
            {
                "actor": "attacker",
                "type": "account_deleted",
                "target_username": "backdoor_admin",
            }
        ]
        generator = GroundTruthGenerator(minimal_scenario, events)
        iocs = generator._extract_iocs()
        assert "backdoor_admin" in iocs["users"]

    def test_extract_iocs_group_member_added(self, minimal_scenario):
        """_extract_iocs() should extract member and group from group_member_added."""
        events = [
            {
                "actor": "attacker",
                "type": "group_member_added",
                "member_name": "backdoor_admin",
                "group_name": "Domain Admins",
            }
        ]
        generator = GroundTruthGenerator(minimal_scenario, events)
        iocs = generator._extract_iocs()
        assert "backdoor_admin" in iocs["users"]
        assert "Group: Domain Admins" in iocs["users"]

    # --- Tests for new event type formatting ---

    def test_format_event_details_service_installed(self, minimal_scenario, malicious_events):
        """_format_event_details() should format service_installed events."""
        event = {
            "type": "service_installed",
            "service_name": "EvilSvc",
            "service_file_name": "C:\\Windows\\Temp\\payload.exe",
        }
        generator = GroundTruthGenerator(minimal_scenario, malicious_events)
        details = generator._format_event_details(event)
        assert "Service installed: EvilSvc" in details
        assert "C:\\Windows\\Temp\\payload.exe" in details

    def test_format_event_details_scheduled_task_created(self, minimal_scenario, malicious_events):
        """_format_event_details() should format scheduled_task_created events."""
        event = {"type": "scheduled_task_created", "task_name": "Updater"}
        generator = GroundTruthGenerator(minimal_scenario, malicious_events)
        details = generator._format_event_details(event)
        assert "Scheduled task created: Updater" in details

    def test_format_event_details_create_remote_thread(self, minimal_scenario, malicious_events):
        """_format_event_details() should format create_remote_thread events."""
        event = {
            "type": "create_remote_thread",
            "target_process": "C:\\Windows\\System32\\lsass.exe",
        }
        generator = GroundTruthGenerator(minimal_scenario, malicious_events)
        details = generator._format_event_details(event)
        assert "Remote thread injection into C:\\Windows\\System32\\lsass.exe" in details

    def test_format_event_details_skipped_event(self, minimal_scenario, malicious_events):
        """_format_event_details() should identify skipped evidence without claiming success."""
        event = {
            "type": "create_remote_thread",
            "target_process": "C:\\Windows\\System32\\lsass.exe",
            "skipped_reason": "no_live_source_process",
        }
        generator = GroundTruthGenerator(minimal_scenario, malicious_events)
        details = generator._format_event_details(event)
        assert details == (
            "Skipped (no live source process); "
            "no evidence emitted for target C:\\Windows\\System32\\lsass.exe"
        )

    def test_format_event_details_account_created(self, minimal_scenario, malicious_events):
        """_format_event_details() should format account_created events."""
        event = {"type": "account_created", "target_username": "backdoor_admin"}
        generator = GroundTruthGenerator(minimal_scenario, malicious_events)
        details = generator._format_event_details(event)
        assert "Account created: backdoor_admin" in details

    def test_format_event_details_account_deleted(self, minimal_scenario, malicious_events):
        """_format_event_details() should format account_deleted events."""
        event = {"type": "account_deleted", "target_username": "backdoor_admin"}
        generator = GroundTruthGenerator(minimal_scenario, malicious_events)
        details = generator._format_event_details(event)
        assert "Account deleted: backdoor_admin" in details

    def test_format_event_details_group_member_added(self, minimal_scenario, malicious_events):
        """_format_event_details() should format group_member_added events."""
        event = {
            "type": "group_member_added",
            "member_name": "backdoor_admin",
            "group_name": "Domain Admins",
        }
        generator = GroundTruthGenerator(minimal_scenario, malicious_events)
        details = generator._format_event_details(event)
        assert "Added backdoor_admin to group Domain Admins" in details
