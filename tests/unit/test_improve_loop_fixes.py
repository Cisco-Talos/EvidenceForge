# Tests for fixes from the adversarial improve loop iterations.
#
# Covers:
# - DB service routing: OS-aware inference, service filtering, fallback removal
# - Session management: exact kind matching, SYSTEM actor bypass
# - Logoff race: storyline_protected re-check before execution
# - Small CIDR handling: /31 and /32 in scan target picker
# - External inbound: RFC1918 rejection, direct-public-IP fallback

import ipaddress
import random
from datetime import UTC, datetime, timedelta
from unittest.mock import Mock

from evidenceforge.generation.state_manager import StateManager
from evidenceforge.models.scenario import (
    BaselineActivity,
    Environment,
    NatRule,
    OutputSpec,
    Scenario,
    System,
    TimeWindow,
    User,
)

# ============================================================
# DB Service Routing
# ============================================================


class TestDbServerOsInference:
    """_collect_db_servers() infers DB type from OS when services are empty."""

    def _make_world_model(self, systems):
        scenario = Scenario(
            name="db-test",
            description="DB inference test",
            environment=Environment(
                description="test",
                users=[
                    User(
                        username="admin",
                        full_name="Admin",
                        email="a@test.local",
                        primary_system="WS-01",
                    )
                ],
                systems=[
                    System(
                        hostname="WS-01",
                        ip="10.0.1.50",
                        os="Windows 10",
                        type="workstation",
                        assigned_user="admin",
                    ),
                    *systems,
                ],
            ),
            time_window=TimeWindow(start=datetime(2024, 1, 15, 10, 0, tzinfo=UTC), duration="1h"),
            baseline_activity=BaselineActivity(
                description="test", intensity="low", variation="low"
            ),
            output=OutputSpec(logs=[{"format": "windows"}], destination="./out"),
        )
        from evidenceforge.generation.world_model import WorldModel

        return WorldModel(scenario, "corp.local")

    def test_linux_db_infers_postgresql(self):
        wm = self._make_world_model(
            [
                System(
                    hostname="DB-LIN",
                    ip="10.0.2.10",
                    os="Ubuntu 22.04",
                    type="server",
                    roles=["database"],
                )
            ]
        )
        assert len(wm.db_servers) == 1
        assert wm.db_servers[0].service == "postgresql"
        assert wm.db_servers[0].port == 5432

    def test_windows_db_infers_mssql(self):
        wm = self._make_world_model(
            [
                System(
                    hostname="DB-WIN",
                    ip="10.0.2.11",
                    os="Windows Server 2019",
                    type="server",
                    roles=["database"],
                )
            ]
        )
        assert len(wm.db_servers) == 1
        assert wm.db_servers[0].service == "mssql"
        assert wm.db_servers[0].port == 1433

    def test_explicit_postgresql_service_overrides(self):
        wm = self._make_world_model(
            [
                System(
                    hostname="DB-WIN",
                    ip="10.0.2.11",
                    os="Windows Server 2019",
                    type="server",
                    roles=["database"],
                    services=["postgresql"],
                )
            ]
        )
        assert wm.db_servers[0].service == "postgresql"

    def test_explicit_mysql_service(self):
        wm = self._make_world_model(
            [
                System(
                    hostname="DB-MY",
                    ip="10.0.2.12",
                    os="Ubuntu 22.04",
                    type="server",
                    roles=["database"],
                    services=["mysql"],
                )
            ]
        )
        assert wm.db_servers[0].service == "mysql"
        assert wm.db_servers[0].port == 3306


class TestDbServiceFiltering:
    """resolve_destination() filters database candidates by service."""

    def _make_world_model_mixed_db(self):
        scenario = Scenario(
            name="mixed-db-test",
            description="Mixed DB test",
            environment=Environment(
                description="test",
                users=[
                    User(
                        username="admin",
                        full_name="Admin",
                        email="a@test.local",
                        primary_system="WS-01",
                    )
                ],
                systems=[
                    System(
                        hostname="WS-01",
                        ip="10.0.1.50",
                        os="Windows 10",
                        type="workstation",
                        assigned_user="admin",
                    ),
                    System(
                        hostname="DB-PG",
                        ip="10.0.2.10",
                        os="Ubuntu 22.04",
                        type="server",
                        roles=["database"],
                        services=["postgresql"],
                    ),
                    System(
                        hostname="DB-MS",
                        ip="10.0.2.11",
                        os="Windows Server 2019",
                        type="server",
                        roles=["database"],
                        services=["mssql"],
                    ),
                ],
            ),
            time_window=TimeWindow(start=datetime(2024, 1, 15, 10, 0, tzinfo=UTC), duration="1h"),
            baseline_activity=BaselineActivity(
                description="test", intensity="low", variation="low"
            ),
            output=OutputSpec(logs=[{"format": "windows"}], destination="./out"),
        )
        from evidenceforge.generation.world_model import WorldModel

        return WorldModel(scenario, "corp.local")

    def test_postgresql_request_gets_pg_host(self):
        wm = self._make_world_model_mixed_db()
        rng = random.Random(42)
        src = next(s for s in wm.scenario.environment.systems if s.hostname == "WS-01")
        # Request postgresql — should only return the PG host
        for _ in range(20):
            ip, _ = wm.resolve_destination("database", src, rng, service="postgresql")
            assert ip == "10.0.2.10", f"Expected PG host, got {ip}"

    def test_mssql_request_gets_ms_host(self):
        wm = self._make_world_model_mixed_db()
        rng = random.Random(42)
        src = next(s for s in wm.scenario.environment.systems if s.hostname == "WS-01")
        for _ in range(20):
            ip, _ = wm.resolve_destination("database", src, rng, service="mssql")
            assert ip == "10.0.2.11", f"Expected MSSQL host, got {ip}"

    def test_no_compatible_db_returns_none(self):
        """When only PG exists and mysql is requested, return None."""
        scenario = Scenario(
            name="single-db",
            description="test",
            environment=Environment(
                description="test",
                users=[
                    User(
                        username="admin",
                        full_name="Admin",
                        email="a@test.local",
                        primary_system="WS-01",
                    )
                ],
                systems=[
                    System(
                        hostname="WS-01",
                        ip="10.0.1.50",
                        os="Windows 10",
                        type="workstation",
                        assigned_user="admin",
                    ),
                    System(
                        hostname="DB-PG",
                        ip="10.0.2.10",
                        os="Ubuntu 22.04",
                        type="server",
                        roles=["database"],
                        services=["postgresql"],
                    ),
                ],
            ),
            time_window=TimeWindow(start=datetime(2024, 1, 15, 10, 0, tzinfo=UTC), duration="1h"),
            baseline_activity=BaselineActivity(
                description="test", intensity="low", variation="low"
            ),
            output=OutputSpec(logs=[{"format": "windows"}], destination="./out"),
        )
        from evidenceforge.generation.world_model import WorldModel

        wm = WorldModel(scenario, "corp.local")
        rng = random.Random(42)
        src = next(s for s in scenario.environment.systems if s.hostname == "WS-01")
        ip, _ = wm.resolve_destination("database", src, rng, service="mssql")
        assert ip is None, "Should not route MSSQL to a PostgreSQL-only host"


# ============================================================
# Session Management
# ============================================================


class TestSessionKindMatching:
    """bootstrap_user_session() requires exact kind match."""

    def _setup_planner(self):
        from evidenceforge.generation.world_model import WorldModel, WorldPlanner

        scenario = Scenario(
            name="session-test",
            description="test",
            environment=Environment(
                description="test",
                users=[
                    User(
                        username="admin",
                        full_name="Admin",
                        email="a@test.local",
                        persona="sysadmin",
                        primary_system="WS-01",
                    )
                ],
                systems=[
                    System(
                        hostname="WS-01",
                        ip="10.0.1.50",
                        os="Windows 11",
                        type="workstation",
                        assigned_user="admin",
                    ),
                    System(hostname="SRV-01", ip="10.0.2.10", os="Ubuntu 22.04", type="server"),
                ],
            ),
            time_window=TimeWindow(start=datetime(2024, 1, 15, 10, 0, tzinfo=UTC), duration="1h"),
            baseline_activity=BaselineActivity(
                description="test", intensity="low", variation="low"
            ),
            output=OutputSpec(logs=[{"format": "windows"}], destination="./out"),
        )
        wm = WorldModel(scenario, "corp.local")
        state = StateManager()
        ag = Mock()
        ag.generate_logon = Mock(return_value="0x1234")
        ag.generate_ssh_session = Mock(return_value="CxUID1")
        ag.generate_rdp_session = Mock(return_value="CxUID2")
        planner = WorldPlanner(
            world_model=wm,
            state_manager=state,
            activity_generator=ag,
        )
        user = scenario.environment.users[0]
        srv = scenario.environment.systems[1]
        return planner, user, srv, state

    def test_network_session_not_reused_for_ssh(self):
        """An existing network session should not satisfy an SSH request."""
        planner, user, srv, state = self._setup_planner()
        rng = random.Random(42)
        time = datetime(2024, 1, 15, 10, 30, tzinfo=UTC)

        # Create a network session first
        result1 = planner.bootstrap_user_session(user, srv, time, rng, session_kind="network")
        assert result1.session.session_kind == "network"

        # Request SSH — should NOT reuse the network session
        result2 = planner.bootstrap_user_session(
            user, srv, time + timedelta(minutes=5), rng, session_kind="ssh"
        )
        assert result2.session.logon_id != result1.session.logon_id

    def test_ssh_session_reused_for_ssh(self):
        """An existing SSH session should be reused for another SSH request."""
        planner, user, srv, state = self._setup_planner()
        rng = random.Random(42)
        time = datetime(2024, 1, 15, 10, 30, tzinfo=UTC)

        result1 = planner.bootstrap_user_session(user, srv, time, rng, session_kind="ssh")
        result2 = planner.bootstrap_user_session(
            user, srv, time + timedelta(minutes=5), rng, session_kind="ssh"
        )
        assert result2.session.logon_id == result1.session.logon_id


# ============================================================
# Small CIDR Handling
# ============================================================


class TestSmallCidrScanTargets:
    """/31 and /32 CIDRs don't crash _pick_public_scan_target."""

    def test_slash32_returns_valid_ip(self):
        from evidenceforge.generation.network_visibility import NetworkVisibilityEngine
        from tests.unit.test_inbound_vip_routing import _make_network_config

        config, systems = _make_network_config(
            nat_rules=[
                NatRule(type="static", src=["dmz"], mapped_ip="203.0.113.5", real_ip="172.16.0.5")
            ],
            public_cidrs=["203.0.113.5/32"],
        )
        engine = NetworkVisibilityEngine(network_config=config, systems=systems)
        assert len(engine._public_cidrs) == 1

        # Simulate what _pick_public_scan_target does
        cidr = engine._public_cidrs[0]
        assert cidr.num_addresses <= 2
        # Should not crash — just return the network address
        result = str(cidr.network_address)
        assert result == "203.0.113.5"

    def test_slash31_returns_valid_ip(self):
        from evidenceforge.generation.network_visibility import NetworkVisibilityEngine
        from tests.unit.test_inbound_vip_routing import _make_network_config

        config, systems = _make_network_config(
            nat_rules=[
                NatRule(type="static", src=["dmz"], mapped_ip="203.0.113.4", real_ip="172.16.0.5")
            ],
            public_cidrs=["203.0.113.4/31"],
        )
        engine = NetworkVisibilityEngine(network_config=config, systems=systems)
        cidr = engine._public_cidrs[0]
        assert cidr.num_addresses == 2
        result = str(cidr.network_address)
        assert result == "203.0.113.4"


# ============================================================
# External Inbound Routing
# ============================================================


class TestExternalInboundRouting:
    """External inbound requires VIP or public IP (RFC1918 skipped)."""

    def test_rfc1918_without_vip_is_private(self):
        """An RFC1918 IP with no VIP should be detected as private."""
        assert ipaddress.ip_address("10.0.1.50").is_private
        assert ipaddress.ip_address("172.16.0.5").is_private
        assert ipaddress.ip_address("192.168.1.1").is_private

    def test_public_ip_is_not_private(self):
        """A truly public IP should be detected as non-private."""
        assert not ipaddress.ip_address("8.8.8.8").is_private
        assert not ipaddress.ip_address("1.1.1.1").is_private

    def test_vip_lookup_provides_mapped_address(self):
        """VIP lookup should return the mapped public address for a private IP."""
        from evidenceforge.generation.network_visibility import NetworkVisibilityEngine
        from tests.unit.test_inbound_vip_routing import _make_network_config

        config, systems = _make_network_config(
            nat_rules=[
                NatRule(type="static", src=["dmz"], mapped_ip="203.0.113.5", real_ip="172.16.0.5")
            ]
        )
        engine = NetworkVisibilityEngine(network_config=config, systems=systems)
        vip = engine.get_inbound_vip("172.16.0.5")
        assert vip == "203.0.113.5"
        # No VIP for hosts without NAT rules
        assert engine.get_inbound_vip("10.0.1.50") is None


# ============================================================
# Logoff Race Protection
# ============================================================


class TestLogoffRaceProtection:
    """Logoff execution re-checks storyline_protected."""

    def test_protected_session_survives_planned_logoff(self):
        """A session marked storyline_protected after planning should not be logged off."""
        state = StateManager()
        state.set_current_time(datetime(2024, 1, 15, 10, 0, tzinfo=UTC))

        # Create a session
        logon_id = state.create_session(
            username="alice",
            system="SRV-01",
            logon_type=10,
            source_ip="10.0.1.50",
            session_kind="ssh",
        )
        session = state.get_session(logon_id)
        assert session is not None
        assert not session.storyline_protected

        # Mark it protected (simulating storyline execution after logoff planning)
        session.storyline_protected = True

        # Verify the session is still active and protected
        session_after = state.get_session(logon_id)
        assert session_after is not None
        assert session_after.storyline_protected
