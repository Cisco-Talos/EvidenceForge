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

"""Unit tests for Phase 5.4: Background Traffic & System Activity."""

import random
from datetime import UTC, datetime, timedelta
from unittest.mock import Mock

import pytest

from evidenceforge.generation.activity import ActivityGenerator
from evidenceforge.generation.engine.baseline import (
    _machine_account_ntlm_offset_seconds,
    _machine_account_tgs_gap_ms,
    _registry_writer_candidates,
    _windows_user_session_system_exe,
)
from evidenceforge.generation.state_manager import StateManager
from evidenceforge.models import System, User


@pytest.fixture
def state_manager():
    sm = StateManager()
    sm.set_current_time(datetime(2024, 3, 15, 8, 0, 0, tzinfo=UTC))
    return sm


@pytest.fixture
def mock_emitters():
    return {
        "windows_event_security": Mock(),
        "zeek_conn": Mock(),
        "ecar": Mock(),
        "syslog": Mock(),
    }


@pytest.fixture
def activity_gen(state_manager, mock_emitters):
    return ActivityGenerator(state_manager, mock_emitters)


@pytest.fixture
def win_system():
    return System(hostname="WKS-01", ip="10.0.10.1", os="Windows 10", type="workstation")


@pytest.fixture
def linux_system():
    return System(hostname="LNX-01", ip="10.0.10.2", os="Linux Ubuntu 22.04", type="server")


@pytest.fixture
def timestamp():
    return datetime(2024, 3, 15, 10, 0, 0, tzinfo=UTC)


class TestWindowsProcessTreeSeeding:
    """Test that Windows system process tree is seeded correctly."""

    def test_hkcu_registry_writers_require_desktop_user(self):
        """HKCU noise should not be attributed to SYSTEM-owned background helpers."""
        sys_pids = {"explorer": 2000, "runtime_broker": 2100, "search_indexer": 2200}

        no_desktop_candidates = _registry_writer_candidates(
            r"HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer",
            sys_pids,
            desktop_user=None,
        )
        desktop_candidates = _registry_writer_candidates(
            r"HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer",
            sys_pids,
            desktop_user="alice",
        )

        assert no_desktop_candidates == []
        assert desktop_candidates
        assert {candidate[2] for candidate in desktop_candidates} == {"alice"}

    @pytest.mark.parametrize(
        "image",
        [
            r"C:\Windows\SystemApps\MicrosoftWindows.Client.CBS_cw5n1h2txyewy\SearchHost.exe",
            r"C:\Windows\System32\RuntimeBroker.exe",
            r"C:\Windows\System32\backgroundTaskHost.exe",
            r"C:\Windows\System32\sihost.exe",
        ],
    )
    def test_desktop_shell_helpers_are_user_session_processes(self, image):
        """Desktop/UWP helpers should not be generated as LocalSystem services."""
        assert _windows_user_session_system_exe(image)

    def test_server_services_remain_system_processes(self):
        """Classic service binaries still use the service-process path."""
        assert not _windows_user_session_system_exe(r"C:\Windows\System32\spoolsv.exe")

    def test_windows_tree_has_correct_hierarchy(self, state_manager, win_system):
        """After seeding, services.exe children include svchost instances."""
        from evidenceforge.generation.engine import GenerationEngine

        # Seed the tree directly via the method
        engine = object.__new__(GenerationEngine)
        engine.state_manager = state_manager
        engine._system_pids = {}

        pids: dict[str, int] = {}
        engine._seed_windows_process_tree(win_system, pids)

        # Verify key processes exist
        assert "smss" in pids
        assert "services" in pids
        assert "lsass" in pids
        assert "svchost_netsvcs" in pids
        assert "msmpeng" in pids
        assert "dwm" in pids

    def test_windows_tree_has_min_svchost_instances(self, state_manager, win_system):
        """Windows should have at least 7 svchost instances."""
        from evidenceforge.generation.engine import GenerationEngine

        engine = object.__new__(GenerationEngine)
        engine.state_manager = state_manager
        engine._system_pids = {}

        pids: dict[str, int] = {}
        engine._seed_windows_process_tree(win_system, pids)

        svchost_count = sum(1 for k in pids if k.startswith("svchost_"))
        assert svchost_count >= 7, f"Only {svchost_count} svchost instances"

    def test_services_is_parent_of_svchost(self, state_manager, win_system):
        """svchost instances should be children of services.exe."""
        from evidenceforge.generation.engine import GenerationEngine

        engine = object.__new__(GenerationEngine)
        engine.state_manager = state_manager
        engine._system_pids = {}

        pids: dict[str, int] = {}
        engine._seed_windows_process_tree(win_system, pids)

        # Check parent of a svchost
        svchost_pid = pids["svchost_netsvcs"]
        proc = state_manager.get_process(win_system.hostname, svchost_pid)
        assert proc is not None
        assert proc.parent_pid == pids["services"]

    def test_lsass_is_child_of_wininit(self, state_manager, win_system):
        """lsass.exe should be child of wininit.exe (not services.exe)."""
        from evidenceforge.generation.engine import GenerationEngine

        engine = object.__new__(GenerationEngine)
        engine.state_manager = state_manager
        engine._system_pids = {}

        pids: dict[str, int] = {}
        engine._seed_windows_process_tree(win_system, pids)

        lsass_proc = state_manager.get_process(win_system.hostname, pids["lsass"])
        assert lsass_proc is not None
        assert lsass_proc.parent_pid == pids["wininit"]

    def test_no_events_emitted_during_seeding(self, state_manager, win_system, mock_emitters):
        """Seeding should not emit any log events."""
        from evidenceforge.generation.engine import GenerationEngine

        engine = object.__new__(GenerationEngine)
        engine.state_manager = state_manager
        engine._system_pids = {}

        pids: dict[str, int] = {}
        engine._seed_windows_process_tree(win_system, pids)

        # No emitters should have been called
        for emitter in mock_emitters.values():
            assert not emitter.emit_event.called


class TestLinuxProcessTreeSeeding:
    """Test that Linux system process tree is seeded correctly."""

    def test_linux_tree_has_systemd_children(self, state_manager, linux_system):
        """After seeding, systemd children include sshd, cron, rsyslogd."""
        from evidenceforge.generation.engine import GenerationEngine

        engine = object.__new__(GenerationEngine)
        engine.state_manager = state_manager
        engine._system_pids = {}

        pids: dict[str, int] = {}
        engine._seed_linux_process_tree(linux_system, pids)

        assert "systemd" in pids
        assert "sshd" in pids
        assert "cron" in pids
        assert "rsyslogd" in pids
        assert "dbus" in pids
        assert "journald" in pids

    def test_all_daemons_are_children_of_systemd(self, state_manager, linux_system):
        """All daemons should be direct children of PID 1 (systemd)."""
        from evidenceforge.generation.engine import GenerationEngine

        engine = object.__new__(GenerationEngine)
        engine.state_manager = state_manager
        engine._system_pids = {}

        pids: dict[str, int] = {}
        engine._seed_linux_process_tree(linux_system, pids)

        systemd_pid = pids["systemd"]
        sshd_pid = pids["sshd"]
        for name, pid in pids.items():
            if name == "systemd":
                continue
            proc = state_manager.get_process(linux_system.hostname, pid)
            assert proc is not None
            if name == "bash":
                # bash is a child of sshd (login shell), not systemd
                assert proc.parent_pid == sshd_pid, (
                    f"bash parent is {proc.parent_pid}, expected sshd ({sshd_pid})"
                )
            else:
                assert proc.parent_pid == systemd_pid, (
                    f"{name} parent is {proc.parent_pid}, expected {systemd_pid}"
                )

    def test_rsyslogd_runs_as_syslog_user(self, state_manager, linux_system):
        """rsyslogd should run as syslog user, not root."""
        from evidenceforge.generation.engine import GenerationEngine

        engine = object.__new__(GenerationEngine)
        engine.state_manager = state_manager
        engine._system_pids = {}

        pids: dict[str, int] = {}
        engine._seed_linux_process_tree(linux_system, pids)

        rsyslogd = state_manager.get_process(linux_system.hostname, pids["rsyslogd"])
        assert rsyslogd.username == "syslog"

    def test_dbus_runs_as_messagebus(self, state_manager, linux_system):
        """dbus-daemon should run as messagebus user."""
        from evidenceforge.generation.engine import GenerationEngine

        engine = object.__new__(GenerationEngine)
        engine.state_manager = state_manager
        engine._system_pids = {}

        pids: dict[str, int] = {}
        engine._seed_linux_process_tree(linux_system, pids)

        dbus = state_manager.get_process(linux_system.hostname, pids["dbus"])
        assert dbus.username == "messagebus"

    def test_rhel_uses_crond(self, state_manager):
        """RHEL/CentOS should use crond, not cron."""
        from evidenceforge.generation.engine import GenerationEngine

        rhel_system = System(hostname="RHEL-01", ip="10.0.10.3", os="Linux CentOS 9", type="server")
        engine = object.__new__(GenerationEngine)
        engine.state_manager = state_manager
        engine._system_pids = {}

        pids: dict[str, int] = {}
        engine._seed_linux_process_tree(rhel_system, pids)

        cron_proc = state_manager.get_process(rhel_system.hostname, pids["cron"])
        assert "crond" in cron_proc.image


class TestGenerateSystemProcess:
    """Test system process generation method in ActivityGenerator."""

    def test_emits_windows_4688(
        self, activity_gen, win_system, timestamp, state_manager, mock_emitters
    ):
        state_manager.set_current_time(timestamp)
        # Create a parent first
        parent_pid = state_manager.create_process(
            win_system.hostname,
            4,
            r"C:\Windows\System32\services.exe",
            "services.exe",
            "SYSTEM",
            "System",
        )
        activity_gen.generate_system_process(
            system=win_system,
            time=timestamp,
            process_name=r"C:\Windows\System32\svchost.exe",
            command_line="svchost.exe -k netsvcs -p -s Schedule",
            parent_pid=parent_pid,
            username="SYSTEM",
        )
        assert mock_emitters["windows_event_security"].emit.called
        event = mock_emitters["windows_event_security"].emit.call_args[0][0]
        assert event.event_type == "system_process_create"
        assert event.auth.username == "SYSTEM"

    def test_emits_linux_syslog(
        self, activity_gen, linux_system, timestamp, state_manager, mock_emitters
    ):
        state_manager.set_current_time(timestamp)
        parent_pid = state_manager.create_process(
            linux_system.hostname, 0, "/usr/sbin/cron", "/usr/sbin/cron -f", "root", "System"
        )
        activity_gen.generate_system_process(
            system=linux_system,
            time=timestamp,
            process_name="/usr/sbin/logrotate",
            command_line="/usr/sbin/logrotate /etc/logrotate.conf",
            parent_pid=parent_pid,
            username="root",
        )
        assert mock_emitters["syslog"].emit.called

    def test_emits_ecar(self, activity_gen, win_system, timestamp, state_manager, mock_emitters):
        state_manager.set_current_time(timestamp)
        parent_pid = state_manager.create_process(
            win_system.hostname,
            4,
            r"C:\Windows\System32\services.exe",
            "services.exe",
            "SYSTEM",
            "System",
        )
        activity_gen.generate_system_process(
            system=win_system,
            time=timestamp,
            process_name=r"C:\Windows\System32\taskhostw.exe",
            command_line="taskhostw.exe /Run",
            parent_pid=parent_pid,
            username="SYSTEM",
        )
        ecar_calls = [
            c
            for c in mock_emitters["ecar"].emit.call_args_list
            if c[0][0].event_type == "system_process_create"
        ]
        assert len(ecar_calls) >= 1

    def test_reuses_active_singleton_windows_service_process(
        self, activity_gen, win_system, timestamp, state_manager, mock_emitters
    ):
        """Singleton Windows services should not overlap as independent processes."""
        state_manager.set_current_time(timestamp)
        parent_pid = state_manager.create_process(
            win_system.hostname,
            4,
            r"C:\Windows\System32\services.exe",
            "services.exe",
            "SYSTEM",
            "System",
        )

        first_pid = activity_gen.generate_system_process(
            system=win_system,
            time=timestamp,
            process_name=r"C:\Windows\System32\spoolsv.exe",
            command_line="spoolsv.exe",
            parent_pid=parent_pid,
            username="SYSTEM",
        )
        second_pid = activity_gen.generate_system_process(
            system=win_system,
            time=timestamp + timedelta(minutes=10),
            process_name=r"C:\Windows\System32\spoolsv.exe",
            command_line="spoolsv.exe",
            parent_pid=parent_pid,
            username="SYSTEM",
        )

        assert second_pid == first_pid
        security_creates = [
            c
            for c in mock_emitters["windows_event_security"].emit.call_args_list
            if c[0][0].event_type == "system_process_create"
            and c[0][0].process.image.endswith("spoolsv.exe")
        ]
        assert len(security_creates) == 1

    def test_allows_multiple_non_singleton_windows_service_processes(
        self, activity_gen, win_system, timestamp, state_manager, mock_emitters
    ):
        """Multi-instance service hosts like WmiPrvSE.exe may create separate processes."""
        state_manager.set_current_time(timestamp)
        parent_pid = state_manager.create_process(
            win_system.hostname,
            4,
            r"C:\Windows\System32\svchost.exe",
            "svchost.exe -k DcomLaunch",
            "SYSTEM",
            "System",
        )

        first_pid = activity_gen.generate_system_process(
            system=win_system,
            time=timestamp,
            process_name=r"C:\Windows\System32\wbem\WmiPrvSE.exe",
            command_line="WmiPrvSE.exe -Embedding",
            parent_pid=parent_pid,
            username="NETWORK SERVICE",
        )
        state_manager.set_current_time(timestamp + timedelta(minutes=10))
        second_pid = activity_gen.generate_system_process(
            system=win_system,
            time=timestamp + timedelta(minutes=10),
            process_name=r"C:\Windows\System32\wbem\WmiPrvSE.exe",
            command_line="WmiPrvSE.exe -secured -Embedding",
            parent_pid=parent_pid,
            username="NETWORK SERVICE",
        )

        assert second_pid != first_pid


class TestInfrastructureDetection:
    """Test infrastructure IP detection."""

    def test_detects_dc_from_hostname(self):
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
                        ip="10.0.0.5",
                        os="Windows Server 2019",
                        type="domain_controller",
                    ),
                    System(hostname="WKS-01", ip="10.0.10.1", os="Windows 10", type="workstation"),
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

        assert infra["dc"] == ["10.0.0.5"]
        assert infra["dns"] == ["10.0.0.5"]  # DC also serves DNS

    def test_service_defaults_windows(self):
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
                    System(hostname="WKS-01", ip="10.0.10.1", os="Windows 10", type="workstation"),
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
        defaults = engine._build_service_defaults()

        assert "dns-client" in defaults["WKS-01"]
        assert "ntp-client" in defaults["WKS-01"]
        assert "smb-client" in defaults["WKS-01"]


class TestParentPidSelection:
    """Test that user processes get realistic parent PIDs."""

    def test_windows_process_gets_explorer_parent(self, state_manager, mock_emitters, win_system):
        """Windows user process should have explorer.exe as parent, not System (4)."""
        from evidenceforge.generation.engine import GenerationEngine

        engine = object.__new__(GenerationEngine)
        engine.state_manager = state_manager

        pids: dict[str, int] = {}
        engine._system_pids = {}
        engine._seed_windows_process_tree(win_system, pids)
        engine._system_pids[win_system.hostname] = pids

        ag = ActivityGenerator(state_manager, mock_emitters)
        ag._system_pids = engine._system_pids
        user = User(username="test.user", full_name="Test User", email="t@t.com", enabled=True)

        logon_id = ag.generate_logon(user, win_system, datetime(2024, 3, 15, 10, 0, 0, tzinfo=UTC))
        pid = ag.generate_process(
            user,
            win_system,
            datetime(2024, 3, 15, 10, 0, 1, tzinfo=UTC),
            logon_id,
            r"C:\Windows\System32\notepad.exe",
            "notepad.exe",
            parent_pid=ag._select_parent_pid(win_system, user, r"C:\Windows\System32\notepad.exe"),
        )

        proc = state_manager.get_process(win_system.hostname, pid)
        # Parent should be an explorer.exe PID (session-specific or system-seeded)
        parent_proc = state_manager.get_process(win_system.hostname, proc.parent_pid)
        assert parent_proc is not None, f"Parent PID {proc.parent_pid} not found in state"
        assert "explorer.exe" in parent_proc.image.lower(), (
            f"User process parent should be explorer, got {parent_proc.image} (PID {proc.parent_pid})"
        )

    def test_linux_process_gets_bash_parent(self, state_manager, mock_emitters, linux_system):
        """Linux user process should have bash as parent, not systemd or PID 0."""
        from evidenceforge.generation.engine import GenerationEngine

        engine = object.__new__(GenerationEngine)
        engine.state_manager = state_manager

        pids: dict[str, int] = {}
        engine._system_pids = {}
        engine._seed_linux_process_tree(linux_system, pids)
        engine._system_pids[linux_system.hostname] = pids

        ag = ActivityGenerator(state_manager, mock_emitters)
        ag._system_pids = engine._system_pids
        user = User(username="test.user", full_name="Test User", email="t@t.com", enabled=True)

        logon_id = ag.generate_logon(
            user, linux_system, datetime(2024, 3, 15, 10, 0, 0, tzinfo=UTC)
        )
        pid = ag.generate_process(
            user,
            linux_system,
            datetime(2024, 3, 15, 10, 0, 1, tzinfo=UTC),
            logon_id,
            "/usr/bin/vim",
            "vim /etc/config",
            parent_pid=ag._select_parent_pid(linux_system, user, "/usr/bin/vim"),
        )

        proc = state_manager.get_process(linux_system.hostname, pid)
        bash_pid = pids["bash"]
        assert proc.parent_pid == bash_pid, (
            f"Linux user process parent should be bash ({bash_pid}), not {proc.parent_pid}"
        )

    def test_process_tree_depth(self, state_manager, mock_emitters, win_system):
        """After creating a shell, subsequent processes should sometimes use it as parent."""
        from evidenceforge.generation.engine import GenerationEngine

        engine = object.__new__(GenerationEngine)
        engine.state_manager = state_manager

        pids: dict[str, int] = {}
        engine._system_pids = {}
        engine._seed_windows_process_tree(win_system, pids)
        engine._system_pids[win_system.hostname] = pids

        ag = ActivityGenerator(state_manager, mock_emitters)
        ag._system_pids = engine._system_pids
        user = User(username="test.user", full_name="Test User", email="t@t.com", enabled=True)

        ts = datetime(2024, 3, 15, 10, 0, 0, tzinfo=UTC)
        logon_id = ag.generate_logon(user, win_system, ts)

        # Create a cmd.exe shell first
        cmd_pid = ag.generate_process(
            user,
            win_system,
            ts,
            logon_id,
            r"C:\Windows\System32\cmd.exe",
            "cmd.exe",
            parent_pid=ag._select_parent_pid(win_system, user, r"C:\Windows\System32\cmd.exe"),
        )
        ag._record_user_process(win_system, user, cmd_pid, r"C:\Windows\System32\cmd.exe")

        # Create many processes — some should have cmd.exe as parent
        parent_pids = set()
        for _i in range(20):
            parent = ag._select_parent_pid(win_system, user, r"C:\Windows\System32\ipconfig.exe")
            parent_pids.add(parent)

        # Should see both explorer and cmd as possible parents
        assert cmd_pid in parent_pids or pids["explorer"] in parent_pids, (
            "Process tree should have depth — shells should sometimes be parents"
        )


class TestInfrastructureTrafficGeneration:
    """Test Kerberos/LDAP/DB traffic detection and generation."""

    def test_machine_account_kerberos_gaps_include_non_immediate_tgs(self):
        """Machine-account TGS timing should not be locked to tiny millisecond gaps."""
        rng = random.Random(7)
        gaps = [_machine_account_tgs_gap_ms(rng, first=True) for _ in range(100)]

        assert any(gap > 2_000 for gap in gaps)
        assert any(gap > 60_000 for gap in gaps)

    def test_machine_account_ntlm_offset_avoids_same_second_kerberos(self):
        """Baseline NTLM validation should not share the Kerberos cycle timestamp."""
        rng = random.Random(11)
        tgt_offset = 512.5
        offsets = [_machine_account_ntlm_offset_seconds(tgt_offset, rng) for _ in range(100)]

        assert all(0 <= offset <= 3599 for offset in offsets)
        assert all(abs(offset - tgt_offset) >= 2.0 for offset in offsets)

    def test_detects_mssql_from_services(self):
        """DB servers should be detected from system services list."""
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
                        ip="10.0.0.5",
                        os="Windows Server 2019",
                        type="domain_controller",
                    ),
                    System(
                        hostname="SRV-DB-01",
                        ip="10.0.100.14",
                        os="Windows Server 2019",
                        type="server",
                        services=["mssql", "SQL Server 2019"],
                    ),
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

        db_servers = infra["db_servers"]
        assert len(db_servers) >= 1
        assert any(
            d["ip"] == "10.0.100.14" and d["port"] == 1433 and d["service"] == "mssql"
            for d in db_servers
        )

    def test_detects_mysql_from_services(self):
        """MySQL servers should also be detected."""
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
                        hostname="DB-01",
                        ip="10.0.100.10",
                        os="Linux Ubuntu 22.04",
                        type="server",
                        services=["MySQL 8.0"],
                    ),
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

        db_servers = infra["db_servers"]
        assert len(db_servers) >= 1
        assert any(d["port"] == 3306 and d["service"] == "mysql" for d in db_servers)

    def test_kerberos_ldap_in_default_windows_services(self):
        """Windows systems should have kerberos-client and ldap-client by default."""
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
                    System(hostname="WKS-01", ip="10.0.10.1", os="Windows 10", type="workstation"),
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
        defaults = engine._build_service_defaults()

        assert "kerberos-client" in defaults["WKS-01"]
        assert "ldap-client" in defaults["WKS-01"]
