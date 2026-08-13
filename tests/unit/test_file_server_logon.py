# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Tests for file server SMB logon event generation."""

from types import SimpleNamespace
from unittest.mock import MagicMock


def test_legacy_smb_baseline_helpers_are_removed() -> None:
    """The direct cutover must not retain a second inferred SMB truth path."""

    from evidenceforge.generation.engine.baseline import BaselineMixin

    assert not hasattr(BaselineMixin, "_smb_logon_transport_conn_state")
    assert not hasattr(BaselineMixin, "_emit_smb_logon_pair")
    assert not hasattr(BaselineMixin, "_emit_smb_file_operations")


class TestSmbBrowsingIncludesFileServers:
    """Verify SMB browsing target pool includes file servers."""

    def test_file_server_ips_in_smb_targets(self):
        """When file servers exist, SMB target pool includes their IPs alongside DCs."""
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
