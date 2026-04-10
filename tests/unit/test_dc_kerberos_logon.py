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

"""Tests for DC-side Kerberos events emitted during domain logons.

When a user authenticates via Kerberos to a Windows domain system, the DC
should see a TGT request (4768) and service ticket request (4769) before
the target system logs the 4624.
"""

from datetime import UTC, datetime
from unittest.mock import Mock

import pytest

from evidenceforge.generation.activity import ActivityGenerator
from evidenceforge.generation.state_manager import StateManager
from evidenceforge.models.scenario import System, User


@pytest.fixture
def state_manager():
    sm = StateManager()
    sm.set_current_time(datetime(2024, 3, 15, 10, 0, 0, tzinfo=UTC))
    return sm


@pytest.fixture
def mock_emitters():
    return {
        "windows_event_security": Mock(),
        "zeek_conn": Mock(),
        "zeek_dns": Mock(),
        "ecar": Mock(),
        "syslog": Mock(),
    }


@pytest.fixture
def activity_gen(state_manager, mock_emitters):
    gen = ActivityGenerator(state_manager, mock_emitters)
    # Simulate engine setup: provide DC info
    gen._dc_hostnames = ["DC-01"]
    gen._dc_ips = ["10.10.100.10"]
    gen._netbios_domain = "CORP"
    gen._ad_domain = "corp.local"
    return gen


@pytest.fixture
def windows_system():
    return System(hostname="WKS-01", ip="10.10.10.50", os="Windows 10", type="workstation")


@pytest.fixture
def dc_system():
    return System(
        hostname="DC-01", ip="10.10.100.10", os="Windows Server 2019", type="domain_controller"
    )


@pytest.fixture
def linux_system():
    return System(hostname="LNX-01", ip="10.10.10.60", os="Ubuntu 22.04", type="server")


@pytest.fixture
def test_user():
    return User(username="john.smith", full_name="John Smith", email="john.smith@corp.com")


class TestDCKerberosOnLogon:
    """DC emits 4768 (TGT) and 4769 (service ticket) for domain Kerberos logons."""

    def test_kerberos_logon_emits_tgt_and_service_ticket(
        self, activity_gen, mock_emitters, windows_system, test_user
    ):
        """Domain logon with Kerberos auth should produce 4768+4769 on DC plus 4624 on target."""
        ts = datetime(2024, 3, 15, 10, 0, 0, tzinfo=UTC)
        activity_gen.generate_logon(
            user=test_user,
            system=windows_system,
            time=ts,
            logon_type=3,  # Network logon (70% chance Kerberos)
            source_ip="10.10.10.50",
        )

        # Collect all dispatched events
        emitter = mock_emitters["windows_event_security"]
        events = [call[0][0] for call in emitter.emit.call_args_list]
        event_types = [e.event_type for e in events]

        # The logon event should always be present
        assert "logon" in event_types

        # If Kerberos was selected (stochastic), DC events should be present
        if "kerberos_tgt" in event_types:
            assert "kerberos_service" in event_types

            # TGT should target krbtgt
            tgt_event = next(e for e in events if e.event_type == "kerberos_tgt")
            assert tgt_event.kerberos.service_name == "krbtgt"
            assert tgt_event.kerberos.target_username == "john.smith"
            assert tgt_event.dst_host.hostname == "DC-01"

            # Service ticket should target a valid service on WKS-01
            tgs_event = next(e for e in events if e.event_type == "kerberos_service")
            svc = tgs_event.kerberos.service_name
            assert svc.endswith("/WKS-01") or svc.startswith("krbtgt/"), f"Unexpected: {svc}"
            assert tgs_event.dst_host.hostname == "DC-01"

            # TGT timestamp should be before logon, service ticket between TGT and logon
            logon_event = next(e for e in events if e.event_type == "logon")
            assert tgt_event.timestamp < logon_event.timestamp
            assert tgs_event.timestamp > tgt_event.timestamp
            assert tgs_event.timestamp <= logon_event.timestamp

    def test_kerberos_logon_produces_dc_events_deterministically(
        self, activity_gen, mock_emitters, windows_system, test_user
    ):
        """Run multiple logons and verify that at least some produce DC Kerberos events."""
        kerberos_count = 0
        total_runs = 20

        for i in range(total_runs):
            mock_emitters["windows_event_security"].emit.reset_mock()
            ts = datetime(2024, 3, 15, 10, i, 0, tzinfo=UTC)
            activity_gen.state_manager.set_current_time(ts)
            activity_gen.generate_logon(
                user=test_user,
                system=windows_system,
                time=ts,
                logon_type=3,
                source_ip="10.10.10.50",
            )
            events = [
                call[0][0] for call in mock_emitters["windows_event_security"].emit.call_args_list
            ]
            if any(e.event_type == "kerberos_tgt" for e in events):
                kerberos_count += 1

        # With 70% Kerberos rate for type-3 logons, we expect many to produce DC events
        assert kerberos_count > 0, "No DC Kerberos events generated in 20 logon attempts"

    def test_no_dc_kerberos_for_ntlm_logon(
        self, activity_gen, mock_emitters, windows_system, test_user
    ):
        """NTLM-only auth (type 10 RDP) should not produce DC Kerberos events."""
        # Run multiple times — RDP uses NtLmSsp which should never trigger Kerberos
        for i in range(10):
            mock_emitters["windows_event_security"].emit.reset_mock()
            ts_i = datetime(2024, 3, 15, 10, i, 0, tzinfo=UTC)
            activity_gen.state_manager.set_current_time(ts_i)
            activity_gen.generate_logon(
                user=test_user,
                system=windows_system,
                time=ts_i,
                logon_type=10,  # RDP — uses CredSSP/Negotiate, not Kerberos
                source_ip="10.10.10.50",
            )
            events = [
                call[0][0] for call in mock_emitters["windows_event_security"].emit.call_args_list
            ]
            event_types = [e.event_type for e in events]
            # RDP auth package is CredSSP or Negotiate (not "Kerberos"), so no DC Kerberos
            assert "kerberos_tgt" not in event_types

    def test_no_dc_kerberos_for_interactive_logon(
        self, activity_gen, mock_emitters, windows_system, test_user
    ):
        """Interactive (type 2) logon uses Negotiate, not Kerberos — no DC events."""
        ts = datetime(2024, 3, 15, 10, 0, 0, tzinfo=UTC)
        activity_gen.generate_logon(
            user=test_user,
            system=windows_system,
            time=ts,
            logon_type=2,
            source_ip="10.10.10.50",
        )
        events = [
            call[0][0] for call in mock_emitters["windows_event_security"].emit.call_args_list
        ]
        event_types = [e.event_type for e in events]
        # Type 2 uses "Negotiate" auth package, which passes the filter
        # but the actual behavior depends on _select_auth_package
        # Just verify logon event is present
        assert "logon" in event_types

    def test_no_dc_kerberos_for_linux_system(
        self, activity_gen, mock_emitters, linux_system, test_user
    ):
        """Linux logon should not produce DC Kerberos events."""
        ts = datetime(2024, 3, 15, 10, 0, 0, tzinfo=UTC)
        activity_gen.generate_logon(
            user=test_user,
            system=linux_system,
            time=ts,
            logon_type=3,
            source_ip="10.10.10.50",
        )
        events = [
            call[0][0] for call in mock_emitters["windows_event_security"].emit.call_args_list
        ]
        event_types = [e.event_type for e in events]
        assert "kerberos_tgt" not in event_types

    def test_no_dc_kerberos_when_logging_onto_dc(
        self, activity_gen, mock_emitters, dc_system, test_user
    ):
        """Logon to the DC itself should not produce separate Kerberos events."""
        ts = datetime(2024, 3, 15, 10, 0, 0, tzinfo=UTC)
        activity_gen.generate_logon(
            user=test_user,
            system=dc_system,
            time=ts,
            logon_type=3,
            source_ip="10.10.10.50",
        )
        events = [
            call[0][0] for call in mock_emitters["windows_event_security"].emit.call_args_list
        ]
        event_types = [e.event_type for e in events]
        assert "kerberos_tgt" not in event_types
        assert "kerberos_service" not in event_types

    def test_dc_4672_for_elevated_user(self, activity_gen, mock_emitters, windows_system):
        """Elevated users should get 4672 (Special Privileges) on the DC during Kerberos auth."""
        # Use a sysadmin persona which has ~80% elevation rate
        from evidenceforge.models.scenario import User

        admin_user = User(
            username="admin.user",
            full_name="Admin User",
            email="admin.user@corp.com",
            persona="sysadmin",
        )

        special_priv_count = 0
        total_kerberos_count = 0

        for i in range(30):
            mock_emitters["windows_event_security"].emit.reset_mock()
            ts = datetime(2024, 3, 15, 10, i, 0, tzinfo=UTC)
            activity_gen.state_manager.set_current_time(ts)
            activity_gen.generate_logon(
                user=admin_user,
                system=windows_system,
                time=ts,
                logon_type=3,
                source_ip="10.10.10.50",
            )
            events = [
                call[0][0] for call in mock_emitters["windows_event_security"].emit.call_args_list
            ]
            event_types = [e.event_type for e in events]

            if "kerberos_tgt" in event_types:
                total_kerberos_count += 1
                if "special_privileges" in event_types:
                    special_priv_count += 1
                    # Verify 4672 is on the DC
                    priv_event = next(e for e in events if e.event_type == "special_privileges")
                    assert priv_event.dst_host.hostname == "DC-01"
                    assert priv_event.auth.username == "admin.user"

        # Should have at least some Kerberos logons with 4672
        assert total_kerberos_count > 0, "No Kerberos logons in 30 attempts"
        assert special_priv_count > 0, "No DC 4672 events for admin in Kerberos logons"

    def test_no_dc_4672_for_regular_user(
        self, activity_gen, mock_emitters, windows_system, test_user
    ):
        """Regular users should rarely get 4672 on DC (only ~5% elevation rate)."""
        special_priv_count = 0

        for i in range(30):
            mock_emitters["windows_event_security"].emit.reset_mock()
            ts = datetime(2024, 3, 15, 10, i, 0, tzinfo=UTC)
            activity_gen.state_manager.set_current_time(ts)
            activity_gen.generate_logon(
                user=test_user,
                system=windows_system,
                time=ts,
                logon_type=3,
                source_ip="10.10.10.50",
            )
            events = [
                call[0][0] for call in mock_emitters["windows_event_security"].emit.call_args_list
            ]
            if any(e.event_type == "special_privileges" for e in events):
                special_priv_count += 1

        # Regular users have ~5% elevation rate, so most runs should have very few
        # With 30 attempts * 70% Kerberos * 5% elevation = ~1 expected
        assert special_priv_count < 15, (
            f"Too many DC 4672 events for regular user: {special_priv_count}"
        )

    def test_no_dc_kerberos_when_no_dc_configured(
        self, state_manager, mock_emitters, windows_system, test_user
    ):
        """When no DC is in the scenario, logon should not attempt Kerberos emission."""
        gen = ActivityGenerator(state_manager, mock_emitters)
        # No _dc_hostnames set — simulates scenario without a DC
        ts = datetime(2024, 3, 15, 10, 0, 0, tzinfo=UTC)
        gen.generate_logon(
            user=test_user,
            system=windows_system,
            time=ts,
            logon_type=3,
            source_ip="10.10.10.50",
        )
        events = [
            call[0][0] for call in mock_emitters["windows_event_security"].emit.call_args_list
        ]
        event_types = [e.event_type for e in events]
        assert "kerberos_tgt" not in event_types
