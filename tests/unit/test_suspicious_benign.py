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

"""Unit tests for suspicious-but-benign ambient noise generator."""

import random
from datetime import datetime

import pytest

from evidenceforge.generation.activity.suspicious_benign import (
    SUSPICIOUS_NOISE_INTENSITY,
    _generate_encoded_command,
    _get_os_category,
    generate_after_hours_admin,
    generate_failed_logon_burst,
    generate_service_account_anomaly,
    generate_suspicious_cli,
    generate_unusual_powershell,
    get_suspicious_event_count,
    pick_suspicious_pattern,
)
from evidenceforge.models.scenario import Persona, System, User


@pytest.fixture
def rng():
    return random.Random(42)


@pytest.fixture
def users():
    return [
        User(
            username="jsmith",
            full_name="John Smith",
            email="jsmith@example.com",
            persona="developer",
        ),
        User(
            username="admin.jones",
            full_name="Admin Jones",
            email="ajones@example.com",
            persona="sysadmin",
        ),
        User(
            username="analyst.lee",
            full_name="Analyst Lee",
            email="alee@example.com",
            persona="security_analyst",
        ),
    ]


@pytest.fixture
def systems():
    return [
        System(
            hostname="WS-DEV-01",
            ip="10.0.1.10",
            os="Windows 10",
            type="workstation",
            assigned_user="jsmith",
        ),
        System(
            hostname="SRV-DC-01", ip="10.0.0.1", os="Windows Server 2019", type="domain_controller"
        ),
        System(hostname="SRV-APP-01", ip="10.0.0.10", os="Ubuntu 22.04", type="server"),
    ]


@pytest.fixture
def personas():
    return [
        Persona(
            name="developer",
            description="Developer",
            typical_activities=["coding"],
            work_hours="9-17",
            application_usage=["vscode"],
            risk_profile="low",
        ),
        Persona(
            name="sysadmin",
            description="Sysadmin",
            typical_activities=["admin"],
            work_hours="9-17",
            application_usage=["powershell"],
            risk_profile="medium",
        ),
    ]


@pytest.fixture
def current_hour():
    return datetime(2024, 6, 15, 14, 0, 0)


class TestSuspiciousEventCount:
    """Tests for get_suspicious_event_count."""

    def test_returns_integer(self, rng):
        count = get_suspicious_event_count("high", rng)
        assert isinstance(count, int)

    def test_scales_with_level(self):
        """Higher levels produce more events on average."""
        samples = 500
        for level_a, level_b in [("low", "medium"), ("medium", "high"), ("high", "ludicrous")]:
            avg_a = (
                sum(get_suspicious_event_count(level_a, random.Random(i)) for i in range(samples))
                / samples
            )
            avg_b = (
                sum(get_suspicious_event_count(level_b, random.Random(i)) for i in range(samples))
                / samples
            )
            assert avg_b > avg_a, (
                f"{level_b} should average more than {level_a}: {avg_b} <= {avg_a}"
            )

    def test_averages_near_intensity(self):
        """Average count should be close to the declared mean."""
        for level, expected_mean in SUSPICIOUS_NOISE_INTENSITY.items():
            samples = 1000
            avg = (
                sum(get_suspicious_event_count(level, random.Random(i)) for i in range(samples))
                / samples
            )
            assert abs(avg - expected_mean) < 0.5, (
                f"{level}: avg {avg} not close to {expected_mean}"
            )

    def test_unknown_level_uses_default(self, rng):
        """Unknown level falls back to 3.0 (high)."""
        count = get_suspicious_event_count("unknown_level", rng)
        assert isinstance(count, int)


class TestPickSuspiciousPattern:
    """Tests for pick_suspicious_pattern."""

    def test_returns_dict(self, rng, users, systems, personas, current_hour):
        result = pick_suspicious_pattern(rng, users, systems, personas, current_hour)
        assert result is not None
        assert "type" in result

    def test_returns_none_with_no_users(self, rng, systems, personas, current_hour):
        result = pick_suspicious_pattern(rng, [], systems, personas, current_hour)
        assert result is None

    def test_returns_none_with_no_systems(self, rng, users, personas, current_hour):
        result = pick_suspicious_pattern(rng, users, [], personas, current_hour)
        assert result is None

    def test_valid_pattern_types(self, rng, users, systems, personas, current_hour):
        """All returned patterns should be one of the known types."""
        valid_types = {
            "after_hours_admin",
            "suspicious_cli",
            "failed_logon_burst",
            "service_account_anomaly",
            "suspicious_dns",
            "unusual_outbound",
            "scheduled_scan_overlap",
            "temp_dir_execution",
            "unusual_powershell",
        }
        for seed in range(50):
            result = pick_suspicious_pattern(
                random.Random(seed), users, systems, personas, current_hour
            )
            if result:
                assert result["type"] in valid_types

    def test_persona_aware_weighting(self, rng, systems, current_hour):
        """Sysadmin users should weight after_hours_admin higher."""
        sysadmin_users = [
            User(username="admin1", full_name="Admin", email="a@x.com", persona="sysadmin")
        ]
        counts: dict[str, int] = {}
        for seed in range(200):
            result = pick_suspicious_pattern(
                random.Random(seed), sysadmin_users, systems, None, current_hour
            )
            if result:
                counts[result["type"]] = counts.get(result["type"], 0) + 1
        # With sysadmin users, after_hours_admin should have weight 3 (vs 1 for suspicious_cli without devs)
        assert counts.get("after_hours_admin", 0) > counts.get("suspicious_cli", 0)


class TestGenerateAfterHoursAdmin:
    """Tests for generate_after_hours_admin."""

    def test_returns_pattern_info(self, rng, users, systems, current_hour):
        result = generate_after_hours_admin(rng, users, systems, current_hour)
        assert result is not None
        assert result["pattern"] == "after_hours_admin"
        assert "user" in result
        assert "system" in result
        assert "time" in result
        assert "logon_type" in result

    def test_prefers_admin_users(self, rng, users, systems, current_hour):
        """Should prefer sysadmin/help_desk/security_analyst personas."""
        admin_usernames = {"admin.jones", "analyst.lee"}
        results = [
            generate_after_hours_admin(random.Random(i), users, systems, current_hour)
            for i in range(50)
        ]
        admin_picks = sum(1 for r in results if r and r["user"].username in admin_usernames)
        assert admin_picks > 25, "Should prefer admin-like users"

    def test_prefers_servers(self, rng, users, systems, current_hour):
        """Should prefer server/DC targets."""
        server_hostnames = {"SRV-DC-01", "SRV-APP-01"}
        results = [
            generate_after_hours_admin(random.Random(i), users, systems, current_hour)
            for i in range(50)
        ]
        server_picks = sum(1 for r in results if r and r["system"].hostname in server_hostnames)
        assert server_picks == 50, "Should always pick server/DC targets when available"

    def test_time_within_hour(self, rng, users, systems, current_hour):
        result = generate_after_hours_admin(rng, users, systems, current_hour)
        assert result["time"] >= current_hour
        from datetime import timedelta

        assert result["time"] < current_hour + timedelta(hours=1)


class TestGenerateSuspiciousCli:
    """Tests for generate_suspicious_cli."""

    def test_returns_pattern_info(self, rng, users, systems, current_hour):
        result = generate_suspicious_cli(rng, users, systems, current_hour)
        assert result is not None
        assert result["pattern"] == "suspicious_cli"
        assert "process_name" in result
        assert "command_line" in result

    def test_windows_system_gets_windows_commands(self, rng, current_hour):
        """Windows systems should get PowerShell or cmd commands."""
        win_users = [User(username="u1", full_name="U", email="u@x.com")]
        win_systems = [
            System(
                hostname="WS-01",
                ip="10.0.0.1",
                os="Windows 10",
                type="workstation",
                assigned_user="u1",
            )
        ]
        for seed in range(20):
            result = generate_suspicious_cli(
                random.Random(seed), win_users, win_systems, current_hour
            )
            assert (
                "powershell" in result["process_name"].lower()
                or "cmd" in result["process_name"].lower()
            )

    def test_domain_dn_is_scenario_specific(self, current_hour):
        win_users = [User(username="u1", full_name="U", email="u@x.com")]
        win_systems = [
            System(
                hostname="WS-01",
                ip="10.0.0.1",
                os="Windows 10",
                type="workstation",
                assigned_user="u1",
            )
        ]
        commands = {
            generate_suspicious_cli(
                random.Random(seed),
                win_users,
                win_systems,
                current_hour,
                ad_domain="meridianhcs.local",
            )["command_line"]
            for seed in range(100)
        }
        assert any("DC=meridianhcs,DC=local" in command for command in commands)
        assert not any("DC=corp,DC=local" in command for command in commands)

    def test_linux_system_gets_linux_commands(self, rng, current_hour):
        """Linux systems should get Linux commands."""
        lin_users = [User(username="u1", full_name="U", email="u@x.com")]
        lin_systems = [
            System(
                hostname="srv-01",
                ip="10.0.0.1",
                os="Ubuntu 22.04",
                type="server",
                assigned_user="u1",
            )
        ]
        for seed in range(20):
            result = generate_suspicious_cli(
                random.Random(seed), lin_users, lin_systems, current_hour
            )
            assert "Windows" not in result["process_name"]


class TestGenerateFailedLogonBurst:
    """Tests for generate_failed_logon_burst."""

    def test_returns_pattern_info(self, rng, users, systems, current_hour):
        result = generate_failed_logon_burst(rng, users, systems, current_hour)
        assert result is not None
        assert result["pattern"] == "failed_logon_burst"
        assert "num_failures" in result

    def test_failure_count_range(self, rng, users, systems, current_hour):
        """Number of failures should be 2-5."""
        for seed in range(50):
            result = generate_failed_logon_burst(random.Random(seed), users, systems, current_hour)
            assert 2 <= result["num_failures"] <= 5


class TestGenerateServiceAccountAnomaly:
    """Tests for generate_service_account_anomaly."""

    def test_returns_pattern_info(self, rng, users, systems, current_hour):
        result = generate_service_account_anomaly(rng, users, systems, current_hour)
        assert result is not None
        assert result["pattern"] == "service_account_anomaly"
        assert result["logon_type"] == 3

    def test_prefers_service_users(self, current_hour):
        """Should prefer users with service-like prefixes."""
        svc_users = [
            User(username="svc_backup", full_name="Backup Service", email="svc@x.com"),
            User(username="sa_monitor", full_name="Monitor", email="sa@x.com"),
            User(username="regular_user", full_name="Regular", email="r@x.com"),
        ]
        systems = [System(hostname="SRV-01", ip="10.0.0.1", os="Windows Server", type="server")]
        svc_picks = 0
        for seed in range(100):
            result = generate_service_account_anomaly(
                random.Random(seed), svc_users, systems, current_hour
            )
            if result and result["user"].username.startswith(("svc", "sa_")):
                svc_picks += 1
        assert svc_picks == 100, "Should always pick service-like users when available"


class TestGetOsCategory:
    """Tests for _get_os_category."""

    def test_windows(self):
        sys = System(
            hostname="WS-01", ip="10.0.0.1", os="Windows 10 Enterprise", type="workstation"
        )
        assert _get_os_category(sys) == "windows"

    def test_linux(self):
        sys = System(hostname="srv-01", ip="10.0.0.1", os="Ubuntu 22.04", type="server")
        assert _get_os_category(sys) == "linux"

    def test_windows_server(self):
        sys = System(hostname="SRV-01", ip="10.0.0.1", os="Windows Server 2019", type="server")
        assert _get_os_category(sys) == "windows"


class TestEncodedPowershell:
    """Fix 2: Encoded PowerShell commands should vary across invocations."""

    def test_encoded_commands_vary(self):
        """Different RNG seeds produce different encoded commands."""
        payloads = set()
        for seed in range(50):
            rng = random.Random(seed)
            payloads.add(_generate_encoded_command(rng))
        # With 7 templates × multiple params, we should get high diversity
        assert len(payloads) > 10, f"Only {len(payloads)} unique payloads from 50 seeds"

    def test_encoded_command_is_valid_base64(self):
        """Encoded command should decode to readable PowerShell."""
        import base64

        rng = random.Random(99)
        encoded = _generate_encoded_command(rng)
        decoded = base64.b64decode(encoded).decode("utf-16-le")
        # Should contain a recognizable PowerShell cmdlet
        ps_cmdlets = [
            "Get-Service",
            "Get-EventLog",
            "Test-NetConnection",
            "Get-Process",
            "Get-ChildItem",
            "Get-WmiObject",
            "Get-HotFix",
        ]
        assert any(c in decoded for c in ps_cmdlets), f"Decoded command lacks PS cmdlet: {decoded}"

    def test_unusual_powershell_has_varied_encoded(self, rng, users):
        """generate_unusual_powershell produces varied EncodedCommand payloads."""
        systems = [
            System(
                hostname="WS-01",
                ip="10.0.0.1",
                os="Windows 10 Enterprise",
                type="workstation",
            )
        ]
        encoded_payloads = set()
        for seed in range(100):
            rng_local = random.Random(seed)
            result = generate_unusual_powershell(
                rng_local, users, systems, datetime(2024, 1, 15, 10, 0)
            )
            if result and "-EncodedCommand" in result["command_line"]:
                payload = result["command_line"].split("-EncodedCommand ")[1]
                encoded_payloads.add(payload)
        # Should get multiple distinct base64 payloads
        assert len(encoded_payloads) > 3, f"Only {len(encoded_payloads)} unique encoded payloads"

    def test_unusual_powershell_api_domain_is_scenario_specific(self, users):
        systems = [
            System(
                hostname="WS-01",
                ip="10.0.0.1",
                os="Windows 10 Enterprise",
                type="workstation",
            )
        ]
        commands = {
            generate_unusual_powershell(
                random.Random(seed),
                users,
                systems,
                datetime(2024, 1, 15, 10, 0),
                ad_domain="meridianhcs.local",
            )["command_line"]
            for seed in range(100)
        }
        assert any("internal-api.meridianhcs.local" in command for command in commands)
        assert not any("internal-api.corp.local" in command for command in commands)
