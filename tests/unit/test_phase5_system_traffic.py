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
import re
from datetime import UTC, datetime, timedelta
from unittest.mock import Mock

import pytest

from evidenceforge.generation.activity import ActivityGenerator
from evidenceforge.generation.activity.system_processes import load_system_processes
from evidenceforge.generation.engine.baseline import (
    BaselineMixin,
    _cron_shell_command_line,
    _dc_kerberos_cycle_range,
    _dc_kerberos_tgs_range,
    _is_kerberos_member_server,
    _kernel_uptime_stamp,
    _machine_account_ntlm_offset_seconds,
    _machine_account_tgs_gap_ms,
    _networkmanager_message_timestamp,
    _pick_dc_kerberos_service,
    _pick_dc_kerberos_target,
    _registry_writer_candidates,
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


def test_kernel_uptime_stamp_tracks_event_timestamp_fraction():
    """Kernel bracket timestamps should be monotonic within a host boot stream."""
    scenario_start = datetime(2024, 3, 18, 12, 0, 0, tzinfo=UTC)
    first = scenario_start + timedelta(seconds=387.345076)
    second = scenario_start + timedelta(seconds=387.997014)

    first_stamp = _kernel_uptime_stamp(2332800.0, scenario_start, first)
    second_stamp = _kernel_uptime_stamp(2332800.0, scenario_start, second)

    assert first_stamp == "2333187.345076"
    assert second_stamp == "2333187.997014"
    assert float(second_stamp) > float(first_stamp)


def test_networkmanager_message_timestamp_uses_epoch_time():
    """NetworkManager bracket timestamps should be epoch-style source timestamps."""
    ts = datetime(2024, 3, 18, 12, 8, 39, 757990, tzinfo=UTC)

    assert _networkmanager_message_timestamp(ts) == "1710763719.7580"


def test_rsyslog_fd_state_stays_process_local(linux_system):
    """Rsyslog file descriptors should look like small per-process integers."""
    engine = type("FakeEngine", (BaselineMixin,), {})()
    rng = random.Random(7)

    fds = [engine._next_rsyslog_fd(linux_system.hostname, rng) for _ in range(12)]

    assert min(fds) >= 4
    assert max(fds) <= 64
    assert fds == sorted(fds)


def test_polkit_messages_use_low_session_and_bus_values(linux_system, state_manager):
    """Polkit payloads should not contain random six-digit sessions or bus IDs."""
    from evidenceforge.generation.activity.extra_syslog import load_extra_syslog_messages

    engine = type("FakeEngine", (BaselineMixin,), {})()
    engine.state_manager = state_manager
    entry = next(item for item in load_extra_syslog_messages() if item["app"] == "polkitd")
    rng = random.Random(11)
    timestamp = datetime(2024, 3, 18, 12, 0, 0, tzinfo=UTC)

    messages = [
        engine._render_polkit_syslog_message(
            entry,
            rng,
            system=linux_system,
            timestamp=timestamp + timedelta(seconds=i),
        )
        for i in range(20)
    ]

    session_ids = [
        int(match.group(1))
        for message in messages
        if (match := re.search(r"unix-session:(\d+)", message))
    ]
    bus_ids = [
        int(match.group(1)) for message in messages if (match := re.search(r":1\.(\d+)", message))
    ]
    process_ids = [
        int(match.group(1))
        for message in messages
        if (match := re.search(r"unix-process:(\d+):", message))
    ]

    assert session_ids
    assert max(session_ids) < 1000
    assert bus_ids
    assert max(bus_ids) < 1000
    assert len(set(bus_ids)) > 4
    assert process_ids
    assert min(process_ids) >= 300


def test_polkit_action_messages_pair_action_with_source_native_program(linux_system, state_manager):
    """Polkit authorization rows should not mix unrelated actions and binaries."""
    from evidenceforge.generation.activity.extra_syslog import load_extra_syslog_messages

    engine = type("FakeEngine", (BaselineMixin,), {})()
    engine.state_manager = state_manager
    entry = next(item for item in load_extra_syslog_messages() if item["app"] == "polkitd")
    rng = random.Random(19)
    timestamp = datetime(2024, 3, 18, 12, 0, 0, tzinfo=UTC)
    allowed_paths = {
        "org.freedesktop.systemd1.manage-units": {
            "/usr/bin/systemctl",
            "/usr/bin/loginctl",
        },
        "org.freedesktop.login1.reboot": {
            "/usr/bin/systemctl",
            "/usr/bin/loginctl",
        },
        "org.freedesktop.packagekit.system-update": {
            "/usr/lib/packagekit/packagekitd",
            "/usr/bin/pkcon",
        },
        "org.freedesktop.NetworkManager.settings.modify.system": {
            "/usr/bin/nmcli",
            "/usr/sbin/NetworkManager",
        },
        "org.freedesktop.timedate1.set-timezone": {
            "/usr/bin/timedatectl",
        },
    }

    messages = [
        engine._render_polkit_syslog_message(
            {**entry, "messages": [message]},
            rng,
            system=linux_system,
            timestamp=timestamp + timedelta(seconds=idx),
        )
        for idx, message in enumerate(entry["messages"])
        if "action {action_id}" in message
    ]

    assert messages
    for message in messages:
        action = re.search(r"action ([^ ]+)", message).group(1)
        path = re.search(r"\[([^]]+)\]", message)
        if path is not None:
            assert path.group(1) in allowed_paths[action]


def test_dbus_bus_state_stays_source_native(linux_system):
    """D-Bus bus suffixes should stay in a realistic low integer regime."""
    engine = type("FakeEngine", (BaselineMixin,), {})()
    rng = random.Random(13)

    bus_ids = [engine._next_dbus_bus_id(linux_system.hostname, rng) for _ in range(20)]

    assert min(bus_ids) >= 12
    assert max(bus_ids) < 1000
    assert bus_ids == sorted(bus_ids)


def test_anacron_lifecycle_emits_once_per_host_day(linux_system):
    """Anacron syslog should be a coherent daily run, not random repeated fragments."""
    engine = type("FakeEngine", (object,), {})()
    engine.activity_generator = Mock()
    engine.start_time = datetime(2024, 3, 18, 12, 0, 0, tzinfo=UTC)
    engine.end_time = datetime(2024, 3, 18, 18, 0, 0, tzinfo=UTC)
    engine._scenario_tz = None
    engine._emit_anacron_lifecycle = BaselineMixin._emit_anacron_lifecycle.__get__(
        engine,
        type(engine),
    )
    ts = datetime(2024, 3, 18, 12, 16, 58, tzinfo=UTC)

    engine._emit_anacron_lifecycle(
        linux_system,
        ts - timedelta(hours=2),
        random.Random(5),
        {"anacron": 13517},
    )
    engine._emit_anacron_lifecycle(linux_system, ts, random.Random(7), {"anacron": 13517})
    engine._emit_anacron_lifecycle(
        linux_system,
        ts + timedelta(hours=1),
        random.Random(9),
        {"anacron": 13517},
    )

    calls = engine.activity_generator.generate_syslog_event.call_args_list
    messages = [call.kwargs["message"] for call in calls]
    times = [call.kwargs["time"] for call in calls]

    assert len(messages) == 5
    assert messages[0] == "Anacron 2.3 started on 2024-03-18"
    assert all("cron.weekly" not in message for message in messages)
    assert messages[-1] == "Normal exit (1 job run)"
    assert times == sorted(times)


def test_cron_schedule_emits_shell_and_workload_process_tree(linux_system):
    """Cron schedules should not render shell syntax as the cron daemon image."""
    engine = type("FakeEngine", (object,), {})()
    engine.state_manager = Mock()
    engine.activity_generator = Mock()
    engine.activity_generator.generate_system_process.side_effect = [41200, 41201]
    engine._emit_scheduled_event = BaselineMixin._emit_scheduled_event.__get__(
        engine,
        type(engine),
    )
    ts = datetime(2024, 3, 18, 12, 0, 0, tzinfo=UTC)
    sched = {
        "service": "debian-sa1",
        "type": "cron",
        "cron_user": "sysstat",
        "cron_commands": {
            "debian": "command -v debian-sa1 > /dev/null && debian-sa1 1 1",
        },
    }

    engine._emit_scheduled_event(
        sched,
        linux_system,
        ts,
        random.Random(3),
        {"cron": 1337},
        False,
    )

    process_calls = engine.activity_generator.generate_system_process.call_args_list
    assert process_calls[0].kwargs["process_name"] == "/bin/sh"
    assert process_calls[0].kwargs["command_line"] == _cron_shell_command_line(
        "command -v debian-sa1 > /dev/null && debian-sa1 1 1"
    )
    assert process_calls[0].kwargs["parent_pid"] == 1337
    assert process_calls[0].kwargs["username"] == "sysstat"
    assert process_calls[0].kwargs["emit_linux_syslog"] is False
    assert process_calls[1].kwargs["process_name"] == "/usr/lib/sysstat/debian-sa1"
    assert process_calls[1].kwargs["command_line"] == "debian-sa1 1 1"
    assert process_calls[1].kwargs["parent_pid"] == 41200
    assert process_calls[1].kwargs["emit_linux_syslog"] is False
    syslog_call = engine.activity_generator.generate_syslog_event.call_args
    assert syslog_call.kwargs["app_name"] == "CRON"
    assert syslog_call.kwargs["pid"] == 41200
    assert syslog_call.kwargs["message"] == (
        "(sysstat) CMD (command -v debian-sa1 > /dev/null && debian-sa1 1 1)"
    )
    term_calls = engine.activity_generator.generate_system_process_termination.call_args_list
    assert [call.kwargs["pid"] for call in term_calls] == [41201, 41200]


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

    def test_singleton_windows_service_reuse_ignores_noncanonical_future_process(
        self, activity_gen, win_system, timestamp, state_manager, mock_emitters
    ):
        """Singleton service reuse should not select attacker-like future user processes."""
        state_manager.set_current_time(timestamp)
        parent_pid = state_manager.create_process(
            win_system.hostname,
            4,
            r"C:\Windows\System32\services.exe",
            "services.exe",
            "SYSTEM",
            "System",
        )
        state_manager.set_current_time(timestamp + timedelta(hours=1))
        rogue_pid = state_manager.create_process(
            win_system.hostname,
            4,
            r"C:\Users\Public\spoolsv.exe",
            r"C:\Users\Public\spoolsv.exe",
            "bob",
            "Medium",
        )
        mock_emitters["windows_event_security"].reset_mock()

        returned_pid = activity_gen.generate_system_process(
            system=win_system,
            time=timestamp + timedelta(minutes=10),
            process_name=r"C:\Windows\System32\spoolsv.exe",
            command_line="spoolsv.exe",
            parent_pid=parent_pid,
            username="SYSTEM",
        )

        assert returned_pid != rogue_pid
        returned_proc = state_manager.get_process(win_system.hostname, returned_pid)
        assert returned_proc is not None
        assert returned_proc.image == r"C:\Windows\System32\spoolsv.exe"
        assert returned_proc.username == "SYSTEM"
        assert returned_proc.start_time == timestamp + timedelta(minutes=10)
        security_creates = [
            c[0][0]
            for c in mock_emitters["windows_event_security"].emit.call_args_list
            if c[0][0].event_type == "system_process_create"
            and c[0][0].process.image == r"C:\Windows\System32\spoolsv.exe"
        ]
        assert len(security_creates) == 1
        assert security_creates[0].process.pid == returned_pid

    def test_singleton_windows_service_reuse_ignores_canonical_future_process(
        self, activity_gen, win_system, timestamp, state_manager, mock_emitters
    ):
        """Singleton service reuse should not select processes that start after event time."""
        state_manager.set_current_time(timestamp)
        parent_pid = state_manager.create_process(
            win_system.hostname,
            4,
            r"C:\Windows\System32\services.exe",
            "services.exe",
            "SYSTEM",
            "System",
        )
        state_manager.set_current_time(timestamp + timedelta(hours=1))
        future_pid = state_manager.create_process(
            win_system.hostname,
            parent_pid,
            r"C:\Windows\System32\spoolsv.exe",
            "spoolsv.exe",
            "SYSTEM",
            "System",
        )
        mock_emitters["windows_event_security"].reset_mock()

        returned_pid = activity_gen.generate_system_process(
            system=win_system,
            time=timestamp + timedelta(minutes=10),
            process_name=r"C:\Windows\System32\spoolsv.exe",
            command_line="spoolsv.exe",
            parent_pid=parent_pid,
            username="SYSTEM",
        )

        assert returned_pid != future_pid
        returned_proc = state_manager.get_process(win_system.hostname, returned_pid)
        assert returned_proc is not None
        assert returned_proc.start_time == timestamp + timedelta(minutes=10)

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


class TestSystemProcessSessionOwnership:
    """Test source-native ownership for system-pool Windows process candidates."""

    def test_shell_uwp_processes_use_active_interactive_session(self, state_manager, mock_emitters):
        """Shell/UWP processes selected by system traffic should not run as SYSTEM/session 0."""
        from evidenceforge.generation.engine import GenerationEngine

        system = System(
            hostname="WKS-01",
            ip="10.0.10.1",
            os="Windows 10",
            type="workstation",
            assigned_user="alice",
        )
        user = User(username="alice", full_name="Alice", email="alice@example.com")
        engine = object.__new__(GenerationEngine)
        engine.state_manager = state_manager
        engine._system_pids = {}
        pids: dict[str, int] = {}
        engine._seed_windows_process_tree(system, pids)

        ag = ActivityGenerator(state_manager, mock_emitters)
        ag._system_pids = {system.hostname: pids}
        ag._users_by_username = {user.username: user}
        timestamp = datetime(2024, 3, 15, 10, 0, 0, tzinfo=UTC)
        logon_id = ag.generate_logon(user, system, timestamp, logon_type=2)
        mock_emitters["windows_event_security"].reset_mock()

        pid = ag.generate_system_process(
            system,
            timestamp + timedelta(seconds=3),
            r"C:\Windows\System32\sihost.exe",
            "sihost.exe",
            parent_pid=pids["svchost_netsvcs"],
            username="SYSTEM",
        )

        assert pid != 0
        proc = state_manager.get_process(system.hostname, pid)
        assert proc is not None
        assert proc.username == user.username
        assert proc.logon_id == logon_id
        emitted = [
            call.args[0] for call in mock_emitters["windows_event_security"].emit.call_args_list
        ]
        process_event = next(
            event
            for event in emitted
            if event.event_type == "process_create" and event.process.pid == pid
        )
        assert process_event.auth.username == user.username
        assert process_event.auth.logon_id == logon_id
        assert process_event.auth.logon_type == 2
        assert process_event.process.integrity_level == "Medium"
        assert all(
            event.event_type != "system_process_create" or event.process.pid != pid
            for event in emitted
        )

    def test_shell_uwp_processes_skip_without_interactive_session(
        self, activity_gen, state_manager, mock_emitters
    ):
        """Desktop-only shell helpers should not appear on hosts without a desktop session."""
        system = System(hostname="DC-01", ip="10.0.0.10", os="Windows Server 2022", type="server")
        state_manager.set_current_time(datetime(2024, 3, 15, 10, 0, 0, tzinfo=UTC))

        pid = activity_gen.generate_system_process(
            system,
            datetime(2024, 3, 15, 10, 0, 1, tzinfo=UTC),
            r"C:\Windows\System32\RuntimeBroker.exe",
            "RuntimeBroker.exe -Embedding",
            parent_pid=4,
            username="SYSTEM",
        )

        assert pid == 0
        emitted = [
            call.args[0] for call in mock_emitters["windows_event_security"].emit.call_args_list
        ]
        assert all(
            "runtimebroker.exe" not in (event.process.image or "").lower()
            for event in emitted
            if event.process is not None
        )

    def test_system_service_pools_exclude_desktop_shell_helpers(self):
        """System service config should not list user-session shell/UWP processes."""
        service_pools = load_system_processes()["system_services"]
        pool_images = {
            image.rsplit("\\", 1)[-1].lower()
            for pool_name in ("all", "workstation")
            for entry in service_pools[pool_name]
            for image in [entry["image"]]
        }

        assert "sihost.exe" not in pool_images
        assert "runtimebroker.exe" not in pool_images
        assert "backgroundtaskhost.exe" not in pool_images
        assert "searchhost.exe" not in pool_images


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

    def test_dc_kerberos_counts_are_capped_for_high_activity_dcs(self):
        """DC activity multipliers should not explode machine-account TGS volume."""
        assert _dc_kerberos_cycle_range(8.0) == (2, 8)
        assert _dc_kerberos_tgs_range(8.0) == (2, 3)

    def test_dc_kerberos_service_distribution_is_skewed(self):
        """Baseline service-ticket classes should not be uniform buckets."""
        from collections import Counter

        member_rng = random.Random(21)
        dc_rng = random.Random(22)
        member_counts = Counter(
            _pick_dc_kerberos_service(member_rng, target_is_dc=False) for _ in range(500)
        )
        dc_counts = Counter(
            _pick_dc_kerberos_service(dc_rng, target_is_dc=True) for _ in range(500)
        )

        assert member_counts["cifs"] > member_counts["http"] > member_counts["termsrv"]
        assert dc_counts["ldap"] > dc_counts["cifs"] > dc_counts["http"]

    def test_dc_kerberos_targets_prefer_member_servers_when_available(self):
        rng = random.Random(23)
        picks = [_pick_dc_kerberos_target(rng, ["FILE-01", "APP-01"], "DC-01") for _ in range(200)]

        member_count = sum(1 for _target, is_dc in picks if not is_dc)
        assert member_count > 140

    def test_kerberos_member_server_detector_handles_roles_and_source_native_services(self):
        file_server = System(
            hostname="FILE-SRV-01",
            ip="10.0.0.20",
            os="Windows Server 2019",
            type="server",
            services=["SMB", "Windows Search"],
            roles=["file_server"],
        )
        ordinary_workstation = System(
            hostname="WS-01",
            ip="10.0.0.30",
            os="Windows 11",
            type="workstation",
            services=["dns-client"],
        )

        assert _is_kerberos_member_server(file_server)
        assert not _is_kerberos_member_server(ordinary_workstation)

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
