# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Tests for deferred items: server-admin profiles, catalog gaps, public hostnames."""

from datetime import datetime

from evidenceforge.generation.activity.process_network import get_service_to_exes
from evidenceforge.generation.activity.traffic_profiles import get_persona_connections
from evidenceforge.models.scenario import System

# ---------------------------------------------------------------------------
# Item #2: Server-admin traffic profiles
# ---------------------------------------------------------------------------


class TestServerAdminProfile:
    """Tests for the _server_admin persona traffic profile."""

    def _services(self, os_cat):
        conns = get_persona_connections("_server_admin", os_cat)
        return {c.get("service") for c in conns if c.get("service")}

    def test_server_admin_windows_has_ldap(self):
        assert "ldap" in self._services("windows")

    def test_server_admin_windows_has_smb(self):
        assert "smb" in self._services("windows")

    def test_server_admin_windows_no_ssh(self):
        assert "ssh" not in self._services("windows")

    def test_server_admin_linux_has_ssh(self):
        assert "ssh" in self._services("linux")

    def test_server_admin_linux_no_ldap(self):
        assert "ldap" not in self._services("linux")

    def test_server_admin_linux_no_smb(self):
        assert "smb" not in self._services("linux")

    def test_server_admin_cross_platform_log_access(self):
        """Both OSes should have log server access."""
        for os_cat in ("windows", "linux"):
            conns = get_persona_connections("_server_admin", os_cat)
            roles = {c["role"] for c in conns}
            assert "log_server" in roles, f"Missing log_server for {os_cat}"


# ---------------------------------------------------------------------------
# Item #3: Catalog gaps
# ---------------------------------------------------------------------------


class TestCatalogGapsFilled:
    """Tests for process_network_map and catalog persona gap fixes."""

    def test_smb_has_exe_mapping(self):
        mapping = get_service_to_exes()
        assert "smb" in mapping, "SMB service should have exe mappings"
        assert "explorer.exe" in mapping["smb"]

    def test_rdp_has_exe_mapping(self):
        mapping = get_service_to_exes()
        assert "rdp" in mapping, "RDP service should have exe mappings"
        assert "mstsc.exe" in mapping["rdp"]

    def test_ldap_has_exe_mapping(self):
        mapping = get_service_to_exes()
        assert "ldap" in mapping, "LDAP service should have exe mappings"
        exes = mapping["ldap"]
        assert "dsquery.exe" in exes
        assert "ldapsearch" in exes

    def test_data_analyst_allowed_for_sqlcmd(self):
        from evidenceforge.generation.activity.application_catalog import is_persona_allowed

        assert is_persona_allowed("sqlcmd.exe", "windows", "data_analyst")

    def test_accountant_allowed_for_sqlcmd(self):
        from evidenceforge.generation.activity.application_catalog import is_persona_allowed

        assert is_persona_allowed("sqlcmd.exe", "windows", "accountant")

    def test_data_analyst_allowed_for_psql(self):
        from evidenceforge.generation.activity.application_catalog import is_persona_allowed

        assert is_persona_allowed("psql", "linux", "data_analyst")

    def test_sysadmin_allowed_for_mstsc(self):
        from evidenceforge.generation.activity.application_catalog import is_persona_allowed

        assert is_persona_allowed("mstsc.exe", "windows", "sysadmin")

    def test_sysadmin_allowed_for_dsquery(self):
        from evidenceforge.generation.activity.application_catalog import is_persona_allowed

        assert is_persona_allowed("dsquery.exe", "windows", "sysadmin")

    def test_sysadmin_allowed_for_ldapsearch(self):
        from evidenceforge.generation.activity.application_catalog import is_persona_allowed

        assert is_persona_allowed("ldapsearch", "linux", "sysadmin")


# ---------------------------------------------------------------------------
# Item #1: Public hostnames
# ---------------------------------------------------------------------------


class TestPublicHostnames:
    """Tests for the public_hostnames field on System."""

    def test_system_accepts_public_hostnames(self):
        system = System(
            hostname="SRV-WEB",
            ip="10.0.0.1",
            os="Linux Ubuntu",
            type="server",
            public_hostnames=["portal.example.com", "api.example.com"],
        )
        assert system.public_hostnames == ["portal.example.com", "api.example.com"]

    def test_system_default_empty_public_hostnames(self):
        system = System(
            hostname="SRV-WEB",
            ip="10.0.0.1",
            os="Linux Ubuntu",
            type="server",
        )
        assert system.public_hostnames == []

    def test_validation_warns_exposed_server_without_public_hostnames(self):
        from evidenceforge.models import (
            BaselineActivity,
            Environment,
            OutputSpec,
            Scenario,
            TimeWindow,
            User,
        )
        from evidenceforge.models.scenario import (
            NetworkConfig,
            NetworkSegment,
            NetworkSensor,
        )
        from evidenceforge.validation import ScenarioValidator

        scenario = Scenario(
            version="1.0",
            name="test",
            description="test",
            environment=Environment(
                description="test",
                users=[User(username="u", full_name="U", email="u@e.com")],
                systems=[
                    System(
                        hostname="WEB-01",
                        ip="172.16.0.5",
                        os="Linux",
                        type="server",
                        roles=["web_server"],
                        # No public_hostnames
                    ),
                ],
                network=NetworkConfig(
                    segments=[
                        NetworkSegment(
                            name="dmz",
                            cidr="172.16.0.0/24",
                            exposure="external",
                            systems=["WEB-01"],
                        ),
                    ],
                    sensors=[
                        NetworkSensor(
                            type="network",
                            name="zeek",
                            monitoring_segments=["dmz"],
                            log_formats=["zeek"],
                        ),
                    ],
                ),
            ),
            time_window=TimeWindow(start=datetime(2024, 1, 1), duration="1h"),
            baseline_activity=BaselineActivity(
                description="test", intensity="low", variation="low"
            ),
            output=OutputSpec(logs=[{"format": "zeek"}], destination="./out", compression=False),
        )
        validator = ScenarioValidator(scenario)
        issues = validator.validate()
        info_issues = [
            i for i in issues if "public_hostnames" in i.message and i.severity == "info"
        ]
        assert len(info_issues) == 1
        assert "WEB-01" in info_issues[0].message
