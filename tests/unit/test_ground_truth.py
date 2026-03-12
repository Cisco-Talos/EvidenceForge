"""Unit tests for ground truth generation."""

import pytest
from datetime import datetime, timezone
from pathlib import Path

from log_generator.generation.ground_truth import GroundTruthGenerator
from log_generator.models import (
    Scenario, Environment, User, System, TimeWindow,
    BaselineActivity, OutputSpec, StorylineEvent
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
                    User(username="attacker", full_name="Attacker", email="attacker@evil.com", enabled=True),
                    User(username="victim", full_name="Victim User", email="victim@example.com", enabled=True)
                ],
                systems=[
                    System(hostname="TEST-01", ip="10.0.0.1", os="Windows 10", type="workstation")
                ]
            ),
            time_window=TimeWindow(start="2024-01-15T10:00:00Z", duration="2h"),
            baseline_activity=BaselineActivity(description="Test", intensity="low", variation="low"),
            output=OutputSpec(logs=[{"format": "windows_event_security"}], destination="./output", compression=False),
            personas=[],
            storyline=[
                StorylineEvent(
                    time="2024-01-15T10:30:00Z",
                    actor="attacker",
                    system="TEST-01",
                    activity="Execute malicious PowerShell command",
                    details={}
                ),
                StorylineEvent(
                    time="2024-01-15T10:35:00Z",
                    actor="attacker",
                    system="TEST-01",
                    activity="Connect to C2 server",
                    details={}
                )
            ]
        )

    @pytest.fixture
    def malicious_events(self):
        """Create sample malicious events."""
        return [
            {
                'time': datetime(2024, 1, 15, 10, 30, 0, tzinfo=timezone.utc),
                'actor': 'attacker',
                'system': 'TEST-01',
                'activity': 'Execute malicious PowerShell command',
                'type': 'process',
                'process_name': 'powershell.exe',
                'command_line': 'powershell.exe -enc <base64_encoded_command>',
                'pid': 1234
            },
            {
                'time': datetime(2024, 1, 15, 10, 35, 0, tzinfo=timezone.utc),
                'actor': 'attacker',
                'system': 'TEST-01',
                'activity': 'Connect to C2 server',
                'type': 'connection',
                'dst_ip': '198.51.100.10',
                'dst_port': 443,
                'uid': 'C12345'
            }
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
                'time': datetime(2024, 1, 15, 10, 35, 0, tzinfo=timezone.utc),
                'actor': 'attacker',
                'system': 'TEST-01',
                'type': 'connection',
                'dst_ip': '198.51.100.10',
                'dst_port': 443
            },
            {
                'time': datetime(2024, 1, 15, 10, 30, 0, tzinfo=timezone.utc),
                'actor': 'attacker',
                'system': 'TEST-01',
                'type': 'process',
                'process_name': 'cmd.exe'
            }
        ]
        generator = GroundTruthGenerator(minimal_scenario, events)

        timeline = generator._create_timeline()
        lines = timeline.split('\n')

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
        event = {
            'type': 'logon',
            'source_ip': '203.0.113.50',
            'logon_id': '0x12345'
        }
        generator = GroundTruthGenerator(minimal_scenario, malicious_events)

        details = generator._format_event_details(event)

        assert "Network logon from 203.0.113.50" in details
        assert "LogonID: 0x12345" in details

    def test_format_event_details_process(self, minimal_scenario, malicious_events):
        """_format_event_details() should format process events."""
        event = {
            'type': 'process',
            'process_name': 'powershell.exe',
            'pid': 1234,
            'command_line': 'powershell.exe -Command Get-Process'
        }
        generator = GroundTruthGenerator(minimal_scenario, malicious_events)

        details = generator._format_event_details(event)

        assert "Process: powershell.exe" in details
        assert "PID: 1234" in details
        assert "powershell.exe -Command Get-Process" in details

    def test_format_event_details_process_truncates_long_cmdline(self, minimal_scenario, malicious_events):
        """_format_event_details() should truncate long command lines."""
        long_cmdline = "x" * 100
        event = {
            'type': 'process',
            'process_name': 'cmd.exe',
            'pid': 5678,
            'command_line': long_cmdline
        }
        generator = GroundTruthGenerator(minimal_scenario, malicious_events)

        details = generator._format_event_details(event)

        assert len(details) < len(long_cmdline) + 50  # Should be truncated
        assert "..." in details  # Should have ellipsis

    def test_format_event_details_connection(self, minimal_scenario, malicious_events):
        """_format_event_details() should format connection events."""
        event = {
            'type': 'connection',
            'dst_ip': '198.51.100.10',
            'dst_port': 443,
            'uid': 'C12345'
        }
        generator = GroundTruthGenerator(minimal_scenario, malicious_events)

        details = generator._format_event_details(event)

        assert "Connection to 198.51.100.10:443" in details
        assert "UID: C12345" in details

    def test_format_event_details_unknown_type(self, minimal_scenario, malicious_events):
        """_format_event_details() should handle unknown event types."""
        event = {
            'type': 'unknown',
            'activity': 'Some activity'
        }
        generator = GroundTruthGenerator(minimal_scenario, malicious_events)

        details = generator._format_event_details(event)

        assert "Some activity" in details

    def test_extract_iocs_network(self, minimal_scenario):
        """_extract_iocs() should extract network IOCs."""
        events = [
            {
                'actor': 'attacker',
                'type': 'logon',
                'source_ip': '203.0.113.50'
            },
            {
                'actor': 'attacker',
                'type': 'connection',
                'dst_ip': '198.51.100.10',
                'dst_port': 443
            }
        ]
        generator = GroundTruthGenerator(minimal_scenario, events)

        iocs = generator._extract_iocs()

        assert 'network' in iocs
        assert '203.0.113.50 (Attacker IP)' in iocs['network']
        assert '198.51.100.10:443 (C2 Server)' in iocs['network']

    def test_extract_iocs_processes(self, minimal_scenario):
        """_extract_iocs() should extract process IOCs."""
        events = [
            {
                'actor': 'attacker',
                'type': 'process',
                'process_name': 'powershell.exe',
                'command_line': 'powershell.exe -enc PAYLOAD'
            }
        ]
        generator = GroundTruthGenerator(minimal_scenario, events)

        iocs = generator._extract_iocs()

        assert 'processes' in iocs
        assert 'powershell.exe' in iocs['processes']
        assert '`powershell.exe -enc PAYLOAD`' in iocs['processes']

    def test_extract_iocs_users(self, minimal_scenario):
        """_extract_iocs() should extract user IOCs."""
        events = [
            {
                'actor': 'attacker',
                'type': 'logon'
            },
            {
                'actor': 'victim',
                'type': 'process',
                'process_name': 'cmd.exe'
            }
        ]
        generator = GroundTruthGenerator(minimal_scenario, events)

        iocs = generator._extract_iocs()

        assert 'users' in iocs
        assert 'attacker' in iocs['users']
        assert 'victim' in iocs['users']

    def test_extract_iocs_deduplicates(self, minimal_scenario):
        """_extract_iocs() should deduplicate IOCs."""
        events = [
            {
                'actor': 'attacker',
                'type': 'process',
                'process_name': 'powershell.exe'
            },
            {
                'actor': 'attacker',
                'type': 'process',
                'process_name': 'powershell.exe'
            }
        ]
        generator = GroundTruthGenerator(minimal_scenario, events)

        iocs = generator._extract_iocs()

        # Should only appear once
        assert len(iocs['users']) == 1
        assert len([p for p in iocs['processes'] if p == 'powershell.exe']) == 1

    def test_extract_iocs_removes_empty_categories(self, minimal_scenario):
        """_extract_iocs() should remove empty IOC categories."""
        events = [
            {
                'actor': 'attacker',
                'type': 'process',
                'process_name': 'cmd.exe'
            }
        ]
        generator = GroundTruthGenerator(minimal_scenario, events)

        iocs = generator._extract_iocs()

        # Should have users and processes, but not network or files
        assert 'users' in iocs
        assert 'processes' in iocs
        assert 'network' not in iocs
        assert 'files' not in iocs

    def test_format_iocs_network_section(self, minimal_scenario, malicious_events):
        """_format_iocs() should format network IOC section."""
        iocs = {
            'network': {'198.51.100.10:443 (C2 Server)', '203.0.113.50 (Attacker IP)'}
        }
        generator = GroundTruthGenerator(minimal_scenario, malicious_events)

        formatted = generator._format_iocs(iocs)

        assert "### Network IOCs" in formatted
        assert "- 198.51.100.10:443 (C2 Server)" in formatted
        assert "- 203.0.113.50 (Attacker IP)" in formatted

    def test_format_iocs_process_section(self, minimal_scenario, malicious_events):
        """_format_iocs() should format process IOC section."""
        iocs = {
            'processes': {'powershell.exe', '`powershell.exe -enc PAYLOAD`'}
        }
        generator = GroundTruthGenerator(minimal_scenario, malicious_events)

        formatted = generator._format_iocs(iocs)

        assert "### Process IOCs" in formatted
        assert "- powershell.exe" in formatted
        assert "- `powershell.exe -enc PAYLOAD`" in formatted

    def test_format_iocs_user_section(self, minimal_scenario, malicious_events):
        """_format_iocs() should format user IOC section."""
        iocs = {
            'users': {'attacker', 'victim'}
        }
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
        iocs = {
            'users': {'zebra', 'alpha', 'beta'}
        }
        generator = GroundTruthGenerator(minimal_scenario, malicious_events)

        formatted = generator._format_iocs(iocs)
        lines = formatted.split('\n')

        # Find lines with IOCs
        ioc_lines = [l for l in lines if l.startswith('- ')]

        # Should be in alphabetical order
        assert '- alpha' in ioc_lines[0]
        assert '- beta' in ioc_lines[1]
        assert '- zebra' in ioc_lines[2]

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
                'actor': 'attacker',
                'type': 'connection',
                'dst_ip': '198.51.100.10'
                # No dst_port
            }
        ]
        generator = GroundTruthGenerator(minimal_scenario, events)

        iocs = generator._extract_iocs()

        assert 'network' in iocs
        assert '198.51.100.10 (C2 Server)' in iocs['network']

    def test_format_event_details_missing_fields(self, minimal_scenario, malicious_events):
        """_format_event_details() should handle missing optional fields."""
        # Logon without optional fields
        event_logon = {'type': 'logon'}
        generator = GroundTruthGenerator(minimal_scenario, malicious_events)
        details = generator._format_event_details(event_logon)
        assert "N/A" in details

        # Process without optional fields
        event_process = {'type': 'process'}
        details = generator._format_event_details(event_process)
        assert "N/A" in details

        # Connection without optional fields
        event_conn = {'type': 'connection'}
        details = generator._format_event_details(event_conn)
        assert "N/A" in details
