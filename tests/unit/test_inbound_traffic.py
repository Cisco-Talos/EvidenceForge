# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Tests for inbound traffic profile generation."""

from datetime import UTC, datetime
from random import Random
from types import SimpleNamespace

from evidenceforge.generation.activity.traffic_profiles import (
    get_persona_connections,
    get_role_connections,
    get_role_inbound_connections,
    load_traffic_profiles,
)
from evidenceforge.generation.engine.baseline import (
    BaselineMixin,
    _baseline_database_service_supported,
)
from evidenceforge.models.scenario import System


class TestTrafficProfileSchema:
    """Tests for the renamed outbound/inbound schema."""

    def test_role_outbound_loads(self):
        """Outbound role connections should load from 'outbound' key."""
        conns = get_role_connections(["web_server"], "linux")
        assert len(conns) > 0

    def test_role_inbound_loads(self):
        """Inbound role connections should load from 'inbound' key."""
        conns = get_role_inbound_connections(["web_server"], "linux")
        assert len(conns) > 0

    def test_persona_outbound_loads(self):
        """Persona connections should load from 'outbound' key."""
        conns = get_persona_connections("developer", "windows")
        assert len(conns) > 0

    def test_default_fallback_works(self):
        """Unknown roles should fall back to _default."""
        conns = get_role_connections(["nonexistent_role"], "windows")
        assert len(conns) > 0

    def test_no_old_connections_key(self):
        """The YAML should not have 'connections' key (renamed to 'outbound')."""
        data = load_traffic_profiles()
        for role_name, profile in data.get("role_traffic", {}).items():
            assert "connections" not in profile, (
                f"Role '{role_name}' still has 'connections' key; should be 'outbound'"
            )
        for persona_name, profile in data.get("persona_traffic", {}).items():
            assert "connections" not in profile, (
                f"Persona '{persona_name}' still has 'connections' key; should be 'outbound'"
            )

    def test_no_old_dest_role_field(self):
        """Connection entries should use 'role', not 'dest_role'."""
        data = load_traffic_profiles()
        for section in ("role_traffic", "persona_traffic"):
            for name, profile in data.get(section, {}).items():
                for direction in ("outbound", "inbound"):
                    for conn in profile.get(direction, []):
                        assert "dest_role" not in conn, (
                            f"{section}.{name}.{direction} has 'dest_role'; should be 'role'"
                        )


class TestInboundProfiles:
    """Tests for inbound traffic profile content."""

    def test_web_server_has_external_inbound(self):
        conns = get_role_inbound_connections(["web_server"], "linux")
        roles = {c["role"] for c in conns}
        assert "_external" in roles, "web_server should have _external inbound"

    def test_database_has_web_server_inbound(self):
        conns = get_role_inbound_connections(["database"], "linux")
        roles = {c["role"] for c in conns}
        assert "web_server" in roles, "database should have web_server inbound"

    def test_domain_controller_has_any_inbound(self):
        conns = get_role_inbound_connections(["domain_controller"], "windows")
        roles = {c["role"] for c in conns}
        assert "_any" in roles, "domain_controller should have _any inbound for Kerberos/LDAP"

    def test_workstation_has_no_inbound(self):
        conns = get_role_inbound_connections(["workstation"], "windows")
        assert len(conns) == 0, "workstations should not have inbound traffic profiles"

    def test_inbound_entries_have_required_fields(self):
        data = load_traffic_profiles()
        for role_name, profile in data.get("role_traffic", {}).items():
            for conn in profile.get("inbound", []):
                assert "role" in conn, f"{role_name} inbound entry missing 'role'"
                assert "port" in conn, f"{role_name} inbound entry missing 'port'"

    def test_multiple_roles_merge_inbound(self):
        """Multiple roles should merge their inbound profiles."""
        conns = get_role_inbound_connections(["web_server", "database"], "linux")
        roles = {c["role"] for c in conns}
        assert "_external" in roles  # from web_server
        assert "web_server" in roles  # from database

    def test_database_inbound_entries_filter_to_declared_engine(self):
        """A MySQL-only database host should not receive MSSQL/PostgreSQL profile rows."""
        mysql_db = System(
            hostname="DB-MY-01",
            ip="10.0.20.10",
            os="CentOS 8",
            type="server",
            services=["mysql"],
            roles=["database"],
        )

        conns = [
            conn
            for conn in get_role_inbound_connections(["database"], "linux")
            if _baseline_database_service_supported(mysql_db, conn.get("service"))
        ]

        assert {conn["port"] for conn in conns} == {3306}


class TestEnsureConnectionProcessCommandLine:
    """Regression: ensure_connection_process should emit catalog command templates."""

    def test_catalog_has_apps_with_command_templates(self):
        """Catalog should have apps with parameterized command templates."""
        from evidenceforge.generation.activity.application_catalog import load_catalog

        catalog = load_catalog()
        apps_with_templates = 0
        for app in catalog.get("applications", []):
            for os_cat in ("windows", "linux"):
                plat = app.get("platforms", {}).get(os_cat)
                if plat and plat.get("command_templates"):
                    templates = plat["command_templates"]
                    # At least one template should have arguments or placeholders
                    has_parameterized = any(" " in t or "{" in t for t in templates)
                    if has_parameterized:
                        apps_with_templates += 1
        assert apps_with_templates > 10, (
            f"Expected >10 apps with parameterized templates, got {apps_with_templates}"
        )

    def test_catalog_key_is_applications(self):
        """Regression: catalog uses 'applications' key, not 'apps'."""
        from evidenceforge.generation.activity.application_catalog import load_catalog

        catalog = load_catalog()
        assert "applications" in catalog, "Catalog should have 'applications' key"
        assert "apps" not in catalog, "Catalog should NOT have 'apps' key"
        assert len(catalog["applications"]) > 0


class TestInboundGenerationRegression:
    """Regression tests for inbound generation edge cases."""

    def test_inbound_only_profile_does_not_raise_when_outbound_is_empty(self, monkeypatch):
        """Inbound generation should not depend on outbound profile count."""

        class _FakeActivityGenerator:
            def __init__(self) -> None:
                self._ip_to_system = {}
                self.calls = 0

            def generate_connection(self, **kwargs) -> None:
                self.calls += 1

        class _FakeStateManager:
            def set_current_time(self, _time) -> None:
                return None

            def get_sessions_on_system(self, _hostname):
                return []

        class _FakeBaseline(BaselineMixin):
            def _resolve_role(self, *args, **kwargs):
                return ("198.51.100.20", "external-client.example")

            def _get_system_exposure(self, _system):
                return "external"

        monkeypatch.setattr(
            "evidenceforge.generation.activity.traffic_profiles.get_role_connections",
            lambda _roles, _os_cat: [],
        )
        monkeypatch.setattr(
            "evidenceforge.generation.activity.traffic_profiles.get_role_inbound_connections",
            lambda _roles, _os_cat: [{"role": "workstation", "port": 443, "proto": "tcp"}],
        )
        monkeypatch.setattr(
            "evidenceforge.generation.activity.traffic_profiles.get_persona_connections",
            lambda _persona, _os_cat: [],
        )

        engine = object.__new__(_FakeBaseline)
        engine.activity_generator = _FakeActivityGenerator()
        engine.state_manager = _FakeStateManager()
        engine.scenario = SimpleNamespace(
            environment=SimpleNamespace(users=[], network=None),
        )

        system = SimpleNamespace(
            hostname="WEB-01",
            ip="172.16.0.10",
            roles=["web_server"],
            type="server",
            public_hostnames=["www.example.com"],
            assigned_user=None,
        )

        engine._generate_profile_traffic(
            current_hour=datetime(2026, 4, 13, 13, tzinfo=UTC),
            system=system,
            rng=Random(7),
            os_cat="linux",
            local_dt=datetime(2026, 4, 13, 13, tzinfo=UTC),
        )

        assert engine.activity_generator.calls > 0
