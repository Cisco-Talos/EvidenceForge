# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Tests for inbound traffic profile generation."""

from evidenceforge.generation.activity.traffic_profiles import (
    get_persona_connections,
    get_role_connections,
    get_role_inbound_connections,
    load_traffic_profiles,
)


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


class TestEnsureConnectionProcessCommandLine:
    """Regression: ensure_connection_process should emit catalog command templates."""

    def test_catalog_backed_command_not_bare_exe(self):
        """When the catalog has a template, command_line should not be a bare exe."""
        from evidenceforge.generation.activity.application_catalog import load_catalog

        catalog = load_catalog()
        # Find an app with command templates
        for app in catalog.get("apps", []):
            for os_cat in ("windows", "linux"):
                plat = app.get("platforms", {}).get(os_cat)
                if plat and plat.get("command_templates"):
                    templates = plat["command_templates"]
                    # All templates should have more than just a bare exe name
                    for t in templates:
                        # Templates have spaces (arguments) or placeholders
                        assert " " in t or "{" in t, (
                            f"Template '{t}' for {app['id']}/{os_cat} looks like a bare exe"
                        )
