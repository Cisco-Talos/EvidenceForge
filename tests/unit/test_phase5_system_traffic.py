"""Unit tests for Phase 5.4: Background Traffic & System Activity."""

import pytest
from datetime import datetime, timezone
from unittest.mock import Mock, patch

from evidenceforge.generation.activity import ActivityGenerator, _get_os_category
from evidenceforge.generation.state_manager import StateManager
from evidenceforge.models import User, System


@pytest.fixture
def state_manager():
    sm = StateManager()
    sm.set_current_time(datetime(2024, 3, 15, 8, 0, 0, tzinfo=timezone.utc))
    return sm


@pytest.fixture
def mock_emitters():
    return {
        'windows_event_security': Mock(),
        'zeek_conn': Mock(),
        'ecar': Mock(),
        'syslog': Mock(),
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
    return datetime(2024, 3, 15, 10, 0, 0, tzinfo=timezone.utc)


class TestWindowsProcessTreeSeeding:
    """Test that Windows system process tree is seeded correctly."""

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
        assert 'smss' in pids
        assert 'services' in pids
        assert 'lsass' in pids
        assert 'svchost_netsvcs' in pids
        assert 'msmpeng' in pids
        assert 'dwm' in pids

    def test_windows_tree_has_min_svchost_instances(self, state_manager, win_system):
        """Windows should have at least 7 svchost instances."""
        from evidenceforge.generation.engine import GenerationEngine

        engine = object.__new__(GenerationEngine)
        engine.state_manager = state_manager
        engine._system_pids = {}

        pids: dict[str, int] = {}
        engine._seed_windows_process_tree(win_system, pids)

        svchost_count = sum(1 for k in pids if k.startswith('svchost_'))
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
        svchost_pid = pids['svchost_netsvcs']
        proc = state_manager.get_process(win_system.hostname, svchost_pid)
        assert proc is not None
        assert proc.parent_pid == pids['services']

    def test_lsass_is_child_of_wininit(self, state_manager, win_system):
        """lsass.exe should be child of wininit.exe (not services.exe)."""
        from evidenceforge.generation.engine import GenerationEngine

        engine = object.__new__(GenerationEngine)
        engine.state_manager = state_manager
        engine._system_pids = {}

        pids: dict[str, int] = {}
        engine._seed_windows_process_tree(win_system, pids)

        lsass_proc = state_manager.get_process(win_system.hostname, pids['lsass'])
        assert lsass_proc is not None
        assert lsass_proc.parent_pid == pids['wininit']

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

        assert 'systemd' in pids
        assert 'sshd' in pids
        assert 'cron' in pids
        assert 'rsyslogd' in pids
        assert 'dbus' in pids
        assert 'journald' in pids

    def test_all_daemons_are_children_of_systemd(self, state_manager, linux_system):
        """All daemons should be direct children of PID 1 (systemd)."""
        from evidenceforge.generation.engine import GenerationEngine

        engine = object.__new__(GenerationEngine)
        engine.state_manager = state_manager
        engine._system_pids = {}

        pids: dict[str, int] = {}
        engine._seed_linux_process_tree(linux_system, pids)

        systemd_pid = pids['systemd']
        for name, pid in pids.items():
            if name == 'systemd':
                continue
            proc = state_manager.get_process(linux_system.hostname, pid)
            assert proc is not None
            assert proc.parent_pid == systemd_pid, f"{name} parent is {proc.parent_pid}, expected {systemd_pid}"

    def test_rsyslogd_runs_as_syslog_user(self, state_manager, linux_system):
        """rsyslogd should run as syslog user, not root."""
        from evidenceforge.generation.engine import GenerationEngine

        engine = object.__new__(GenerationEngine)
        engine.state_manager = state_manager
        engine._system_pids = {}

        pids: dict[str, int] = {}
        engine._seed_linux_process_tree(linux_system, pids)

        rsyslogd = state_manager.get_process(linux_system.hostname, pids['rsyslogd'])
        assert rsyslogd.username == 'syslog'

    def test_dbus_runs_as_messagebus(self, state_manager, linux_system):
        """dbus-daemon should run as messagebus user."""
        from evidenceforge.generation.engine import GenerationEngine

        engine = object.__new__(GenerationEngine)
        engine.state_manager = state_manager
        engine._system_pids = {}

        pids: dict[str, int] = {}
        engine._seed_linux_process_tree(linux_system, pids)

        dbus = state_manager.get_process(linux_system.hostname, pids['dbus'])
        assert dbus.username == 'messagebus'

    def test_rhel_uses_crond(self, state_manager):
        """RHEL/CentOS should use crond, not cron."""
        from evidenceforge.generation.engine import GenerationEngine

        rhel_system = System(hostname="RHEL-01", ip="10.0.10.3", os="Linux CentOS 9", type="server")
        engine = object.__new__(GenerationEngine)
        engine.state_manager = state_manager
        engine._system_pids = {}

        pids: dict[str, int] = {}
        engine._seed_linux_process_tree(rhel_system, pids)

        cron_proc = state_manager.get_process(rhel_system.hostname, pids['cron'])
        assert 'crond' in cron_proc.image


class TestGenerateSystemProcess:
    """Test system process generation method in ActivityGenerator."""

    def test_emits_windows_4688(self, activity_gen, win_system, timestamp, state_manager, mock_emitters):
        state_manager.set_current_time(timestamp)
        # Create a parent first
        parent_pid = state_manager.create_process(
            win_system.hostname, 4, r'C:\Windows\System32\services.exe', 'services.exe', 'SYSTEM', 'System'
        )
        activity_gen.generate_system_process(
            system=win_system, time=timestamp,
            process_name=r'C:\Windows\System32\svchost.exe',
            command_line='svchost.exe -k netsvcs -p -s Schedule',
            parent_pid=parent_pid, username='SYSTEM',
        )
        assert mock_emitters['windows_event_security'].emit_event.called
        event = mock_emitters['windows_event_security'].emit_event.call_args[0][0]
        assert event['EventID'] == 4688
        assert event['SubjectUserName'] == 'SYSTEM'

    def test_emits_linux_syslog(self, activity_gen, linux_system, timestamp, state_manager, mock_emitters):
        state_manager.set_current_time(timestamp)
        parent_pid = state_manager.create_process(
            linux_system.hostname, 0, '/usr/sbin/cron', '/usr/sbin/cron -f', 'root', 'System'
        )
        activity_gen.generate_system_process(
            system=linux_system, time=timestamp,
            process_name='/usr/sbin/logrotate',
            command_line='/usr/sbin/logrotate /etc/logrotate.conf',
            parent_pid=parent_pid, username='root',
        )
        assert mock_emitters['syslog'].emit_event.called

    def test_emits_ecar(self, activity_gen, win_system, timestamp, state_manager, mock_emitters):
        state_manager.set_current_time(timestamp)
        parent_pid = state_manager.create_process(
            win_system.hostname, 4, r'C:\Windows\System32\services.exe', 'services.exe', 'SYSTEM', 'System'
        )
        activity_gen.generate_system_process(
            system=win_system, time=timestamp,
            process_name=r'C:\Windows\System32\taskhostw.exe',
            command_line='taskhostw.exe /Run',
            parent_pid=parent_pid, username='SYSTEM',
        )
        ecar_calls = [c for c in mock_emitters['ecar'].emit_event.call_args_list
                      if c[0][0].get('object') == 'PROCESS']
        assert len(ecar_calls) >= 1


class TestInfrastructureDetection:
    """Test infrastructure IP detection."""

    def test_detects_dc_from_hostname(self):
        from evidenceforge.generation.engine import GenerationEngine
        from evidenceforge.models.scenario import (
            BaselineActivity, Environment, OutputSpec, Scenario, TimeWindow,
        )
        scenario = Scenario(
            name="test", description="test",
            environment=Environment(
                description="test",
                users=[User(username="j", full_name="J", email="j@x.com")],
                systems=[
                    System(hostname="DC-01", ip="10.0.0.5", os="Windows Server 2019", type="domain_controller"),
                    System(hostname="WKS-01", ip="10.0.10.1", os="Windows 10", type="workstation"),
                ],
            ),
            time_window=TimeWindow(start=datetime(2024, 1, 1, tzinfo=timezone.utc), duration="8h"),
            baseline_activity=BaselineActivity(description="Normal", intensity="low", variation="low"),
            output=OutputSpec(logs=[{"format": "windows_event_security"}], destination="./out"),
        )

        engine = object.__new__(GenerationEngine)
        engine.scenario = scenario
        infra = engine._detect_infrastructure_ips()

        assert infra['dc'] == '10.0.0.5'
        assert infra['dns'] == '10.0.0.5'  # DC also serves DNS

    def test_service_defaults_windows(self):
        from evidenceforge.generation.engine import GenerationEngine
        from evidenceforge.models.scenario import (
            BaselineActivity, Environment, OutputSpec, Scenario, TimeWindow,
        )
        scenario = Scenario(
            name="test", description="test",
            environment=Environment(
                description="test",
                users=[User(username="j", full_name="J", email="j@x.com")],
                systems=[
                    System(hostname="WKS-01", ip="10.0.10.1", os="Windows 10", type="workstation"),
                ],
            ),
            time_window=TimeWindow(start=datetime(2024, 1, 1, tzinfo=timezone.utc), duration="8h"),
            baseline_activity=BaselineActivity(description="Normal", intensity="low", variation="low"),
            output=OutputSpec(logs=[{"format": "windows_event_security"}], destination="./out"),
        )

        engine = object.__new__(GenerationEngine)
        engine.scenario = scenario
        defaults = engine._build_service_defaults()

        assert 'dns-client' in defaults['WKS-01']
        assert 'ntp-client' in defaults['WKS-01']
        assert 'smb-client' in defaults['WKS-01']
