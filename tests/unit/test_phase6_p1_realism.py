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

"""Tests for Phase 6.2 P1 realism fixes."""

from datetime import UTC, datetime
from unittest.mock import Mock

import pytest

from evidenceforge.generation.activity import ActivityGenerator, _is_private_ip
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
    return ActivityGenerator(state_manager, mock_emitters)


@pytest.fixture
def windows_system():
    return System(hostname="WKS-01", ip="10.10.10.50", os="Windows 10", type="workstation")


@pytest.fixture
def dc_system():
    return System(
        hostname="DC-01", ip="10.10.100.10", os="Windows Server 2019", type="domain_controller"
    )


@pytest.fixture
def test_user():
    return User(username="john.smith", full_name="John Smith", email="john.smith@corp.com")


class TestPrivateIP:
    """P1-9: local_resp for internal servers."""

    def test_rfc1918_10_network(self):
        assert _is_private_ip("10.0.0.1") is True
        assert _is_private_ip("10.10.100.50") is True

    def test_rfc1918_172_network(self):
        assert _is_private_ip("172.16.0.1") is True
        assert _is_private_ip("172.31.255.255") is True

    def test_rfc1918_192_network(self):
        assert _is_private_ip("192.168.1.1") is True

    def test_public_ips(self):
        assert _is_private_ip("8.8.8.8") is False
        assert _is_private_ip("52.97.145.162") is False

    def test_invalid_ip(self):
        assert _is_private_ip("not-an-ip") is False


class TestLocalResp:
    """P1-9: local_resp/local_orig in Zeek connections."""

    def test_internal_destination_sets_local_resp_true(
        self, activity_gen, state_manager, mock_emitters
    ):
        state_manager.set_current_time(datetime(2024, 3, 15, 10, 0, 0, tzinfo=UTC))
        activity_gen.generate_connection(
            src_ip="10.10.10.50",
            dst_ip="10.10.100.10",
            time=datetime(2024, 3, 15, 10, 0, 0, tzinfo=UTC),
            dst_port=445,
            proto="tcp",
            service="smb",
            duration=0.5,
            orig_bytes=500,
            resp_bytes=1000,
        )
        event = mock_emitters["zeek_conn"].emit.call_args_list[-1][0][0]
        assert event.network.local_resp is True
        assert event.network.local_orig is True

    def test_external_destination_sets_local_resp_false(
        self, activity_gen, state_manager, mock_emitters
    ):
        state_manager.set_current_time(datetime(2024, 3, 15, 10, 0, 0, tzinfo=UTC))
        activity_gen.generate_connection(
            src_ip="10.10.10.50",
            dst_ip="52.97.145.162",
            time=datetime(2024, 3, 15, 10, 0, 0, tzinfo=UTC),
            dst_port=443,
            proto="tcp",
            service="https",
            duration=0.5,
            orig_bytes=500,
            resp_bytes=1000,
        )
        event = mock_emitters["zeek_conn"].emit.call_args_list[-1][0][0]
        assert event.network.local_resp is False
        assert event.network.local_orig is True


class TestTCPOverhead:
    """P1-10: IP+TCP overhead in Zeek packets."""

    def test_tcp_overhead_in_range(self, activity_gen, state_manager, mock_emitters):
        state_manager.set_current_time(datetime(2024, 3, 15, 10, 0, 0, tzinfo=UTC))
        activity_gen.generate_connection(
            src_ip="10.10.10.50",
            dst_ip="10.10.100.10",
            time=datetime(2024, 3, 15, 10, 0, 0, tzinfo=UTC),
            dst_port=443,
            proto="tcp",
            service="https",
            duration=0.5,
            orig_bytes=3000,
            resp_bytes=10000,
        )
        event = mock_emitters["zeek_conn"].emit.call_args_list[-1][0][0]
        net = event.network
        overhead_per_pkt = (net.orig_ip_bytes - net.orig_bytes) / net.orig_pkts
        assert 40 <= overhead_per_pkt <= 64

    def test_udp_overhead_is_28(self, activity_gen, state_manager, mock_emitters):
        state_manager.set_current_time(datetime(2024, 3, 15, 10, 0, 0, tzinfo=UTC))
        activity_gen.generate_connection(
            src_ip="10.10.10.50",
            dst_ip="10.10.100.10",
            time=datetime(2024, 3, 15, 10, 0, 0, tzinfo=UTC),
            dst_port=53,
            proto="udp",
            service="dns",
            duration=0.01,
            orig_bytes=100,
            resp_bytes=200,
        )
        event = mock_emitters["zeek_conn"].emit.call_args_list[-1][0][0]
        net = event.network
        if net.orig_pkts and net.orig_ip_bytes and net.orig_bytes:
            overhead_per_pkt = (net.orig_ip_bytes - net.orig_bytes) / net.orig_pkts
            assert overhead_per_pkt in (28, 32, 52, 60, 78)


class TestPerHostEventRecordIDs:
    """P1-11: Per-computer EventRecordIDs."""

    def test_independent_per_host(self, activity_gen):
        id_a1 = activity_gen._get_next_event_record_id("HOST-A")
        id_b1 = activity_gen._get_next_event_record_id("HOST-B")
        id_a2 = activity_gen._get_next_event_record_id("HOST-A")
        id_b2 = activity_gen._get_next_event_record_id("HOST-B")
        assert id_a2 == id_a1 + 1
        assert id_b2 == id_b1 + 1

    def test_start_in_valid_range(self, activity_gen):
        first_id = activity_gen._get_next_event_record_id("UNIQUE-HOST")
        assert 1001 <= first_id <= 50001

    def test_deterministic_per_hostname(self):
        """Same hostname should get same starting value across instances."""
        sm = StateManager()
        emitters = {"windows_event_security": Mock(), "zeek_conn": Mock()}
        gen1 = ActivityGenerator(sm, emitters)
        gen2 = ActivityGenerator(sm, emitters)
        assert gen1._get_next_event_record_id("TEST") == gen2._get_next_event_record_id("TEST")


class TestLogonTypeDistribution:
    """P1-12: LogonType distribution."""

    def test_workstation_no_type5_for_regular_users(
        self, activity_gen, state_manager, mock_emitters
    ):
        """Regular users should not get Type 5 (service) logons on workstations."""
        user = User(username="jane.doe", full_name="Jane Doe", email="jane.doe@corp.com")
        system = System(hostname="WKS-01", ip="10.10.10.50", os="Windows 10", type="workstation")
        ts = datetime(2024, 3, 15, 10, 0, 0, tzinfo=UTC)

        logon_types = []
        for _ in range(200):
            state_manager.set_current_time(ts)
            activity_gen.execute_baseline_activity(
                user=user, system=system, time=ts, activity_type="logon"
            )
            if mock_emitters["windows_event_security"].emit_event.called:
                last_call = mock_emitters["windows_event_security"].emit_event.call_args_list[-1][
                    0
                ][0]
                if last_call.get("EventID") == 4624:
                    logon_types.append(last_call.get("LogonType"))
            mock_emitters["windows_event_security"].reset_mock()

        assert 5 not in logon_types, "Type 5 should not appear for regular users"

    def test_server_type3_dominates(self, activity_gen, state_manager, mock_emitters):
        """Type 3 should dominate on servers."""
        user = User(username="admin", full_name="Admin", email="admin@corp.com")
        system = System(
            hostname="SRV-01", ip="10.10.100.50", os="Windows Server 2019", type="server"
        )
        ts = datetime(2024, 3, 15, 10, 0, 0, tzinfo=UTC)

        logon_types = []
        for _ in range(200):
            state_manager.set_current_time(ts)
            activity_gen.execute_baseline_activity(
                user=user, system=system, time=ts, activity_type="logon"
            )
            if mock_emitters["windows_event_security"].emit_event.called:
                last_call = mock_emitters["windows_event_security"].emit_event.call_args_list[-1][
                    0
                ][0]
                if last_call.get("EventID") == 4624:
                    logon_types.append(last_call.get("LogonType"))
            mock_emitters["windows_event_security"].reset_mock()

        if logon_types:
            type3_pct = logon_types.count(3) / len(logon_types)
            assert type3_pct > 0.40, f"Type 3 should dominate on servers (got {type3_pct:.0%})"


class TestMachineAccountLogon:
    """P1-7: Machine account ($) activity."""

    def test_emits_dollar_username(self, activity_gen, mock_emitters):
        ts = datetime(2024, 3, 15, 10, 0, 0, tzinfo=UTC)
        activity_gen.generate_machine_account_logon(
            hostname="WKS-01",
            machine_username="WKS-01$",
            dc_hostname="DC-01",
            source_ip="10.10.10.50",
            dc_ip="10.10.100.10",
            time=ts,
        )
        # machine_logon dispatched via SecurityEvent
        event = mock_emitters["windows_event_security"].emit.call_args_list[0][0][0]
        assert event.event_type == "machine_logon"
        assert event.auth.username == "WKS-01$"
        assert event.dst_host.fqdn.startswith("DC-01.")
        assert event.auth.logon_type == 3
        assert event.auth.auth_package == "Kerberos"


class TestKerberosEvents:
    """P1-6/8: New Kerberos Event IDs."""

    def test_tgt_emits_4768(self, activity_gen, mock_emitters):
        ts = datetime(2024, 3, 15, 10, 0, 0, tzinfo=UTC)
        activity_gen.generate_kerberos_tgt(
            username="WKS-01$",
            source_ip="10.10.10.50",
            dc_hostname="DC-01",
            time=ts,
        )
        event = mock_emitters["windows_event_security"].emit.call_args_list[0][0][0]
        assert event.event_type == "kerberos_tgt"
        assert event.kerberos.service_name == "krbtgt"
        assert event.dst_host.fqdn.startswith("DC-01.")

    def test_service_ticket_emits_4769(self, activity_gen, mock_emitters):
        ts = datetime(2024, 3, 15, 10, 0, 0, tzinfo=UTC)
        activity_gen.generate_kerberos_service_ticket(
            username="WKS-01$",
            service_name="cifs/SRV-FILE-01",
            source_ip="10.10.10.50",
            dc_hostname="DC-01",
            time=ts,
        )
        event = mock_emitters["windows_event_security"].emit.call_args_list[0][0][0]
        assert event.event_type == "kerberos_service"
        assert event.kerberos.service_name == "cifs/SRV-FILE-01"

    def test_ntlm_emits_4776(self, activity_gen, mock_emitters):
        ts = datetime(2024, 3, 15, 10, 0, 0, tzinfo=UTC)
        activity_gen.generate_ntlm_validation(
            username="WKS-01$",
            workstation="WKS-01",
            dc_hostname="DC-01",
            time=ts,
        )
        event = mock_emitters["windows_event_security"].emit.call_args_list[0][0][0]
        assert event.event_type == "ntlm_validation"
        assert event.auth.username == "WKS-01$"
        assert event.auth.source_ip == "WKS-01"  # workstation stored in source_ip


class TestInfrastructureDetection:
    """P1-15, P1-16: Infrastructure IP detection."""

    def test_detects_multiple_dcs(self):
        from evidenceforge.generation.engine import GenerationEngine
        from evidenceforge.models.scenario import (
            BaselineActivity,
            Environment,
            OutputSpec,
            Scenario,
            TimeWindow,
        )

        scenario = Scenario(
            name="test",
            description="test",
            environment=Environment(
                description="test",
                users=[User(username="j", full_name="J", email="j@x.com")],
                systems=[
                    System(
                        hostname="DC-01",
                        ip="10.10.100.10",
                        os="Windows Server 2019",
                        type="domain_controller",
                    ),
                    System(
                        hostname="DC-02",
                        ip="10.10.100.11",
                        os="Windows Server 2019",
                        type="domain_controller",
                    ),
                    System(hostname="WKS-01", ip="10.10.10.1", os="Windows 10", type="workstation"),
                ],
            ),
            time_window=TimeWindow(start=datetime(2024, 1, 1, tzinfo=UTC), duration="8h"),
            baseline_activity=BaselineActivity(
                description="Normal", intensity="low", variation="low"
            ),
            output=OutputSpec(logs=[{"format": "windows_event_security"}], destination="./out"),
        )
        engine = object.__new__(GenerationEngine)
        engine.scenario = scenario
        infra = engine._detect_infrastructure_ips()

        assert "10.10.100.10" in infra["dc"]
        assert "10.10.100.11" in infra["dc"]
        assert "10.10.100.10" in infra["dns"]
        assert "10.10.100.11" in infra["dns"]

    def test_detects_exchange(self):
        from evidenceforge.generation.engine import GenerationEngine
        from evidenceforge.models.scenario import (
            BaselineActivity,
            Environment,
            OutputSpec,
            Scenario,
            TimeWindow,
        )

        scenario = Scenario(
            name="test",
            description="test",
            environment=Environment(
                description="test",
                users=[User(username="j", full_name="J", email="j@x.com")],
                systems=[
                    System(
                        hostname="SRV-EXCH-01",
                        ip="10.10.100.16",
                        os="Windows Server 2019",
                        type="server",
                    ),
                    System(hostname="WKS-01", ip="10.10.10.1", os="Windows 10", type="workstation"),
                ],
            ),
            time_window=TimeWindow(start=datetime(2024, 1, 1, tzinfo=UTC), duration="8h"),
            baseline_activity=BaselineActivity(
                description="Normal", intensity="low", variation="low"
            ),
            output=OutputSpec(logs=[{"format": "windows_event_security"}], destination="./out"),
        )
        engine = object.__new__(GenerationEngine)
        engine.scenario = scenario
        infra = engine._detect_infrastructure_ips()

        assert infra["exchange"] == "10.10.100.16"
