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

"""Tests for RDP background noise in baseline generation."""

import random
import tempfile
from datetime import UTC, datetime, timedelta
from pathlib import Path
from unittest.mock import patch

from evidenceforge.generation.engine import GenerationEngine
from evidenceforge.generation.engine.baseline import (
    _baseline_success_port_for_target,
    _baseline_success_target_for_guarded_port,
)
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

    def test_generic_successful_rdp_remaps_from_linux_without_xrdp(self):
        """Generic baseline noise should not imply successful RDP to Linux-only services."""
        app_server = System(
            hostname="APP-01",
            ip="10.10.20.30",
            os="Ubuntu 22.04",
            type="server",
            services=["ssh", "gunicorn", "systemd-resolved"],
            roles=["app_server"],
        )

        effective = _baseline_success_port_for_target(
            app_server,
            3389,
            None,
            random.Random(7),
        )

        assert effective is not None
        assert effective[0] != 3389
        assert effective[1] in {"ssh", "http", "ssl"}

    def test_generic_successful_rdp_allows_explicit_xrdp_service(self):
        """Linux RDP is plausible only when visible receiver service inventory says so."""
        xrdp_server = System(
            hostname="JUMP-01",
            ip="10.10.20.31",
            os="Ubuntu 22.04",
            type="server",
            services=["ssh", "xrdp"],
            roles=["jump_host"],
        )

        assert _baseline_success_port_for_target(
            xrdp_server,
            3389,
            "rdp",
            random.Random(7),
        ) == (3389, "rdp")

    def test_generic_successful_smb_requires_windows_or_samba(self):
        """Generic baseline noise should not imply SMB to Linux hosts without Samba."""
        app_server = System(
            hostname="APP-01",
            ip="10.10.20.30",
            os="Ubuntu 22.04",
            type="server",
            services=["ssh", "gunicorn"],
            roles=["app_server"],
        )
        samba_server = System(
            hostname="FS-LNX-01",
            ip="10.10.20.32",
            os="Ubuntu 22.04",
            type="server",
            services=["ssh", "samba"],
            roles=["file_server"],
        )
        windows_server = System(
            hostname="FILE-01",
            ip="10.10.20.20",
            os="Windows Server 2019",
            type="server",
            services=["smb", "dns-client"],
            roles=["file_server"],
        )

        remapped = _baseline_success_port_for_target(app_server, 445, "smb", random.Random(9))

        assert remapped is not None
        assert remapped[0] != 445
        assert _baseline_success_port_for_target(
            samba_server,
            445,
            "smb",
            random.Random(9),
        ) == (445, "smb")
        assert _baseline_success_port_for_target(
            windows_server,
            445,
            "smb",
            random.Random(9),
        ) == (445, "smb")

    def test_guarded_profile_smb_retargets_from_linux_app_to_file_server(self):
        """Profile SMB traffic should keep SMB semantics but choose an SMB-capable receiver."""
        workstation = System(
            hostname="WKS-01",
            ip="10.10.10.50",
            os="Windows 11",
            type="workstation",
        )
        app_server = System(
            hostname="APP-01",
            ip="10.10.20.30",
            os="Ubuntu 22.04",
            type="server",
            services=["ssh", "gunicorn"],
            roles=["app_server"],
        )
        file_server = System(
            hostname="FILE-01",
            ip="10.10.20.20",
            os="Windows Server 2019",
            type="server",
            services=["smb"],
            roles=["file_server"],
        )

        effective_target = _baseline_success_target_for_guarded_port(
            [workstation, app_server, file_server],
            workstation,
            app_server,
            445,
            random.Random(9),
        )

        assert effective_target == file_server

    def test_guarded_profile_smb_skips_without_compatible_receiver(self):
        """Profile SMB should not invent a success target when no receiver exposes SMB."""
        workstation = System(
            hostname="WKS-01",
            ip="10.10.10.50",
            os="Windows 11",
            type="workstation",
        )
        app_server = System(
            hostname="APP-01",
            ip="10.10.20.30",
            os="Ubuntu 22.04",
            type="server",
            services=["ssh", "gunicorn"],
            roles=["app_server"],
        )

        assert (
            _baseline_success_target_for_guarded_port(
                [workstation, app_server],
                workstation,
                app_server,
                445,
                random.Random(9),
            )
            is None
        )

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

    def test_domain_controller_rdp_noise_is_capped_per_hour(self):
        """DC baseline RDP should not request several new sessions in one hour."""
        systems = [
            System(hostname="WKS-01", ip="10.10.10.50", os="Windows 10", type="workstation"),
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

            with patch.object(engine, "_scaled_randint", return_value=3):
                assert engine._baseline_rdp_hourly_count(random.Random(11), systems[1]) == 1

    def test_rdp_cooldown_rejects_dense_same_tuple_sessions(self):
        """The same source/user/target should not open clustered baseline RDP sessions."""
        systems = [
            System(hostname="WKS-01", ip="10.10.10.50", os="Windows 10", type="workstation"),
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
            first = datetime(2024, 1, 15, 14, 23, tzinfo=UTC)

            assert engine._baseline_rdp_cooldown_allows(
                target_hostname="DC-01",
                source_hostname="WKS-01",
                username="admin.user",
                planned_time=first,
            )
            engine._remember_baseline_rdp_session(
                target_hostname="DC-01",
                source_hostname="WKS-01",
                username="admin.user",
                session_time=first,
            )

            assert not engine._baseline_rdp_cooldown_allows(
                target_hostname="DC-01",
                source_hostname="WKS-01",
                username="admin.user",
                planned_time=first + timedelta(minutes=1),
            )
            assert engine._baseline_rdp_cooldown_allows(
                target_hostname="DC-01",
                source_hostname="WKS-01",
                username="admin.user",
                planned_time=first + timedelta(minutes=46),
            )
