"""Tests for RDP background noise in baseline generation."""

import tempfile
from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import patch

from evidenceforge.generation.engine import GenerationEngine
from evidenceforge.models.scenario import (
    BaselineActivity,
    Environment,
    OutputSpec,
    Scenario,
    System,
    TimeWindow,
    User,
)


def _make_scenario(systems):
    """Create a minimal test scenario with given systems."""
    return Scenario(
        name="rdp-test",
        description="Test RDP baseline noise",
        environment=Environment(
            description="Test environment",
            users=[
                User(
                    username="admin.user",
                    full_name="Admin User",
                    email="admin@corp.com",
                    persona="sysadmin",
                ),
            ],
            systems=systems,
        ),
        time_window=TimeWindow(start=datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC), duration="2h"),
        baseline_activity=BaselineActivity(description="Normal", intensity="low", variation="low"),
        output=OutputSpec(logs=[{"format": "windows"}], destination="./out"),
    )


class TestRDPBaselineNoise:
    """Verify that baseline generates RDP admin connections to Windows servers."""

    def test_rdp_connections_generated_for_windows_servers(self):
        """Windows servers should receive baseline RDP admin connections."""
        systems = [
            System(hostname="WKS-01", ip="10.10.10.50", os="Windows 10", type="workstation"),
            System(hostname="SRV-01", ip="10.10.20.10", os="Windows Server 2019", type="server"),
            System(
                hostname="DC-01",
                ip="10.10.100.10",
                os="Windows Server 2019",
                type="domain_controller",
            ),
        ]
        scenario = _make_scenario(systems)

        with tempfile.TemporaryDirectory() as tmpdir:
            engine = GenerationEngine(scenario, Path(tmpdir))
            engine._initialize()

            rdp_connections = []
            original = engine.activity_generator.generate_connection

            def tracking(*args, **kwargs):
                if kwargs.get("dst_port") == 3389:
                    rdp_connections.append(kwargs)
                return original(*args, **kwargs)

            with patch.object(
                engine.activity_generator, "generate_connection", side_effect=tracking
            ):
                # Generate multiple hours for determinism
                for h in range(4):
                    hour = datetime(2024, 1, 15, 10 + h, 0, 0, tzinfo=UTC)
                    engine._generate_system_traffic(hour)

            assert len(rdp_connections) > 0, "No RDP baseline connections in 4 hours of generation"
            for conn in rdp_connections:
                assert conn["dst_port"] == 3389
                assert conn["proto"] == "tcp"
                assert conn["service"] == "rdp"

    def test_no_rdp_noise_for_workstations_only(self):
        """Environment with only workstations should not get RDP admin connections."""
        systems = [
            System(hostname="WKS-01", ip="10.10.10.50", os="Windows 10", type="workstation"),
            System(hostname="WKS-02", ip="10.10.10.51", os="Windows 10", type="workstation"),
        ]
        scenario = _make_scenario(systems)

        with tempfile.TemporaryDirectory() as tmpdir:
            engine = GenerationEngine(scenario, Path(tmpdir))
            engine._initialize()

            rdp_connections = []
            original = engine.activity_generator.generate_connection

            def tracking(*args, **kwargs):
                if kwargs.get("dst_port") == 3389:
                    rdp_connections.append(kwargs)
                return original(*args, **kwargs)

            with patch.object(
                engine.activity_generator, "generate_connection", side_effect=tracking
            ):
                hour = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)
                engine._generate_system_traffic(hour)

            assert len(rdp_connections) == 0, (
                f"Got RDP connections to workstations: {rdp_connections}"
            )
