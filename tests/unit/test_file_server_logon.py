# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Tests for file server SMB logon event generation."""

from datetime import UTC, datetime
from unittest.mock import MagicMock


class TestEmitSmbLogonPair:
    """Test _emit_smb_logon_pair helper method."""

    def test_emits_logon_and_logoff(self):
        """Should call generate_logon(type=3) then generate_logoff(type=3)."""
        import random

        from evidenceforge.generation.engine.baseline import BaselineMixin

        obj = MagicMock()
        obj.activity_generator = MagicMock()
        obj.activity_generator.generate_logon.return_value = "0x12345"
        method = BaselineMixin._emit_smb_logon_pair.__get__(obj)

        user = MagicMock()
        file_server = MagicMock()
        file_server.os = "Windows Server 2019"
        ts = datetime(2024, 3, 15, 10, 0, 0, tzinfo=UTC)
        rng = random.Random(42)

        logon_id = method(user, file_server, "10.10.10.50", ts, rng)

        assert logon_id == "0x12345"
        obj.activity_generator.generate_logon.assert_called_once_with(
            user=user,
            system=file_server,
            time=ts,
            logon_type=3,
            source_ip="10.10.10.50",
        )
        obj.activity_generator.generate_logoff.assert_called_once()
        logoff_args = obj.activity_generator.generate_logoff.call_args
        assert logoff_args.kwargs["logon_type"] == 3
        assert logoff_args.kwargs["logon_id"] == "0x12345"
        # Logoff should be 5-60s after logon
        logoff_time = logoff_args.kwargs["time"]
        delay = (logoff_time - ts).total_seconds()
        assert 5.0 <= delay <= 60.0, f"Logoff delay {delay}s outside [5, 60] range"

    def test_skips_linux_file_servers(self):
        """Linux file servers don't get Windows 4624 logon events."""
        import random

        from evidenceforge.generation.engine.baseline import BaselineMixin

        obj = MagicMock()
        method = BaselineMixin._emit_smb_logon_pair.__get__(obj)

        file_server = MagicMock()
        file_server.os = "Ubuntu 22.04"
        rng = random.Random(42)
        ts = datetime(2024, 3, 15, 10, 0, 0, tzinfo=UTC)

        result = method(MagicMock(), file_server, "10.10.10.50", ts, rng)

        assert result is None
        obj.activity_generator.generate_logon.assert_not_called()


class TestSmbBrowsingIncludesFileServers:
    """Verify SMB browsing target pool includes file servers."""

    def test_file_server_ips_in_smb_targets(self):
        """When file servers exist, SMB target pool includes their IPs alongside DCs."""
        from types import SimpleNamespace

        # Create mock systems
        dc = SimpleNamespace(
            hostname="DC-01",
            ip="10.10.10.1",
            os="Windows Server 2019",
            type="domain_controller",
            roles=["domain_controller"],
            public_hostnames=[],
            services=[],
        )
        fs = SimpleNamespace(
            hostname="FS-01",
            ip="10.10.10.5",
            os="Windows Server 2019",
            type="server",
            roles=["file_server"],
            public_hostnames=[],
            services=[],
        )
        ws = SimpleNamespace(
            hostname="WS-01",
            ip="10.10.20.10",
            os="Windows 11",
            type="workstation",
            roles=["workstation"],
            public_hostnames=[],
            services=[],
        )

        # File servers should be discoverable as SMB targets
        all_systems = [dc, fs, ws]
        fs_targets = [
            s
            for s in all_systems
            if s.ip != ws.ip and s.roles and "file_server" in [r.lower() for r in s.roles]
        ]
        smb_targets = [dc.ip]
        for fst in fs_targets:
            if fst.ip not in smb_targets:
                smb_targets.append(fst.ip)

        assert dc.ip in smb_targets
        assert fs.ip in smb_targets
        assert len(smb_targets) == 2

    def test_file_server_only_environment_still_has_smb_targets(self):
        """File servers should drive SMB noise even when no DC target exists."""
        from types import SimpleNamespace

        from evidenceforge.generation.engine.baseline import BaselineMixin

        fs = SimpleNamespace(
            hostname="FS-01",
            ip="10.10.10.5",
            os="Windows Server 2019",
            type="server",
            roles=["file_server"],
            public_hostnames=[],
            services=[],
        )
        ws = SimpleNamespace(
            hostname="WS-01",
            ip="10.10.20.10",
            os="Windows 11",
            type="workstation",
            roles=["workstation"],
            public_hostnames=[],
            services=[],
        )
        obj = MagicMock()
        obj.scenario.environment.systems = [fs, ws]
        method = BaselineMixin._build_smb_targets.__get__(obj)

        targets, fs_targets = method(ws, [])

        assert targets == [fs.ip, fs.ip, fs.ip]
        assert fs_targets == [fs]

    def test_file_servers_are_weighted_above_domain_controllers(self):
        """File server targets should be weighted higher than SYSVOL/DC traffic."""
        from types import SimpleNamespace

        from evidenceforge.generation.engine.baseline import BaselineMixin

        dc = SimpleNamespace(
            hostname="DC-01",
            ip="10.10.10.1",
            os="Windows Server 2019",
            type="domain_controller",
            roles=["domain_controller"],
            public_hostnames=[],
            services=[],
        )
        fs = SimpleNamespace(
            hostname="FS-01",
            ip="10.10.10.5",
            os="Windows Server 2019",
            type="server",
            roles=["file_server"],
            public_hostnames=[],
            services=[],
        )
        ws = SimpleNamespace(
            hostname="WS-01",
            ip="10.10.20.10",
            os="Windows 11",
            type="workstation",
            roles=["workstation"],
            public_hostnames=[],
            services=[],
        )
        obj = MagicMock()
        obj.scenario.environment.systems = [dc, fs, ws]
        method = BaselineMixin._build_smb_targets.__get__(obj)

        targets, _ = method(ws, [dc.ip])

        assert targets.count(dc.ip) == 1
        assert targets.count(fs.ip) == 3
