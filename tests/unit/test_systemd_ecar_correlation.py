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

"""Tests for systemd↔eCAR PROCESS cross-source correlation.

Verifies that systemd service start/stop generates paired eCAR
PROCESS/CREATE and PROCESS/TERMINATE events alongside syslog messages.
"""

from datetime import UTC, datetime, timedelta
from unittest.mock import Mock

import pytest

from evidenceforge.generation.activity import ActivityGenerator
from evidenceforge.generation.emitters.syslog import SyslogEmitter, _syslog_sort_key
from evidenceforge.generation.state_manager import StateManager
from evidenceforge.models import System


@pytest.fixture
def state_manager():
    return StateManager()


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
def linux_system():
    return System(hostname="SRV-WEB-01", ip="10.0.20.1", os="Ubuntu 22.04", type="server")


@pytest.fixture
def timestamp():
    return datetime(2024, 3, 15, 10, 0, 0, tzinfo=UTC)


class TestSystemdProcessLifecycle:
    def test_generate_system_process_with_syslog_message(
        self, activity_gen, linux_system, timestamp, state_manager, mock_emitters
    ):
        """generate_system_process with syslog_message should emit both eCAR and syslog."""
        state_manager.set_current_time(timestamp)
        # Seed systemd as parent
        systemd_pid = state_manager.create_process(
            "SRV-WEB-01", 0, "/usr/lib/systemd/systemd", "systemd", "root", "System"
        )

        pid = activity_gen.generate_system_process(
            system=linux_system,
            time=timestamp,
            process_name="/usr/lib/systemd/logrotate",
            command_line="/usr/lib/systemd/logrotate",
            parent_pid=systemd_pid,
            username="root",
            syslog_message="Starting logrotate.service - Logrotate.",
        )

        # eCAR should get a PROCESS/CREATE event
        ecar_calls = [
            c[0][0]
            for c in mock_emitters["ecar"].emit.call_args_list
            if c[0][0].event_type == "system_process_create"
        ]
        assert len(ecar_calls) == 1
        event = ecar_calls[0]
        assert event.process.pid == pid

        # The same event should have SyslogContext with custom message
        assert event.syslog is not None
        assert event.syslog.message == "Starting logrotate.service - Logrotate."
        assert event.syslog.app_name == "systemd"

    def test_generate_system_process_termination_with_syslog(
        self, activity_gen, linux_system, timestamp, state_manager, mock_emitters
    ):
        """generate_system_process_termination should emit eCAR PROCESS/TERMINATE + syslog."""
        state_manager.set_current_time(timestamp)
        systemd_pid = state_manager.create_process(
            "SRV-WEB-01", 0, "/usr/lib/systemd/systemd", "systemd", "root", "System"
        )
        svc_pid = state_manager.create_process(
            "SRV-WEB-01",
            systemd_pid,
            "/usr/lib/systemd/logrotate",
            "/usr/lib/systemd/logrotate",
            "root",
            "System",
        )

        activity_gen.generate_system_process_termination(
            system=linux_system,
            time=timestamp,
            pid=svc_pid,
            process_name="/usr/lib/systemd/logrotate",
            parent_pid=systemd_pid,
            username="root",
            syslog_message="Finished logrotate.service - Logrotate.",
        )

        # eCAR should get a PROCESS/TERMINATE event
        ecar_calls = [
            c[0][0]
            for c in mock_emitters["ecar"].emit.call_args_list
            if c[0][0].event_type == "process_terminate"
        ]
        assert len(ecar_calls) == 1
        event = ecar_calls[0]
        assert event.process.pid == svc_pid

        # Should also have syslog
        assert event.syslog is not None
        assert event.syslog.message == "Finished logrotate.service - Logrotate."

    def test_paired_lifecycle_shares_object_id(
        self, activity_gen, linux_system, timestamp, state_manager, mock_emitters
    ):
        """Starting and Finished events for same service should share eCAR objectID."""
        state_manager.set_current_time(timestamp)
        systemd_pid = state_manager.create_process(
            "SRV-WEB-01", 0, "/usr/lib/systemd/systemd", "systemd", "root", "System"
        )

        # Starting
        svc_pid = activity_gen.generate_system_process(
            system=linux_system,
            time=timestamp,
            process_name="/usr/lib/systemd/logrotate",
            command_line="/usr/lib/systemd/logrotate",
            parent_pid=systemd_pid,
            username="root",
            syslog_message="Starting logrotate.service - Logrotate.",
        )

        create_event = [
            c[0][0]
            for c in mock_emitters["ecar"].emit.call_args_list
            if c[0][0].event_type == "system_process_create"
        ][-1]
        create_obj_id = create_event.edr.object_id

        # Finished
        activity_gen.generate_system_process_termination(
            system=linux_system,
            time=timestamp,
            pid=svc_pid,
            process_name="/usr/lib/systemd/logrotate",
            parent_pid=systemd_pid,
            username="root",
            syslog_message="Finished logrotate.service - Logrotate.",
        )

        terminate_event = [
            c[0][0]
            for c in mock_emitters["ecar"].emit.call_args_list
            if c[0][0].event_type == "process_terminate"
        ][-1]
        assert terminate_event.edr.object_id == create_obj_id
        assert create_obj_id != ""

    def test_syslog_message_override_does_not_affect_cron(
        self, activity_gen, linux_system, timestamp, state_manager, mock_emitters
    ):
        """CRON processes without syslog_message should still get CRON-format syslog."""
        state_manager.set_current_time(timestamp)
        cron_pid = state_manager.create_process(
            "SRV-WEB-01", 0, "/usr/sbin/cron", "cron", "root", "System"
        )

        activity_gen.generate_system_process(
            system=linux_system,
            time=timestamp,
            process_name="/usr/sbin/cron",
            command_line="test -x /usr/sbin/anacron",
            parent_pid=cron_pid,
            username="root",
            # No syslog_message — should fall through to CRON format
        )

        event = mock_emitters["ecar"].emit.call_args_list[-1][0][0]
        assert event.syslog is not None
        assert event.syslog.app_name == "CRON"
        assert "(root) CMD (test -x /usr/sbin/anacron)" in event.syslog.message

    def test_system_parent_termination_follows_foreground_child_termination(
        self, activity_gen, linux_system, timestamp, state_manager, mock_emitters
    ):
        """Foreground cron shells should not terminate before visible child workloads."""
        state_manager.set_current_time(timestamp)
        cron_pid = state_manager.create_process(
            "SRV-WEB-01", 0, "/usr/sbin/cron", "cron", "root", "System"
        )

        shell_pid = activity_gen.generate_system_process(
            system=linux_system,
            time=timestamp,
            process_name="/bin/sh",
            command_line="/bin/sh -c 'command -v debian-sa1 > /dev/null && debian-sa1 1 1'",
            parent_pid=cron_pid,
            username="sysstat",
            emit_linux_syslog=False,
        )
        child_time = timestamp + timedelta(milliseconds=80)
        child_pid = activity_gen.generate_system_process(
            system=linux_system,
            time=child_time,
            process_name="/usr/lib/sysstat/debian-sa1",
            command_line="debian-sa1 1 1",
            parent_pid=shell_pid,
            username="sysstat",
            emit_linux_syslog=False,
        )
        child_end = child_time + timedelta(milliseconds=120)
        activity_gen.generate_system_process_termination(
            system=linux_system,
            time=child_end,
            pid=child_pid,
            process_name="/usr/lib/sysstat/debian-sa1",
            parent_pid=shell_pid,
            username="sysstat",
        )
        activity_gen.generate_system_process_termination(
            system=linux_system,
            time=timestamp + timedelta(milliseconds=90),
            pid=shell_pid,
            process_name="/bin/sh",
            parent_pid=cron_pid,
            username="sysstat",
        )

        terminate_events = [
            c.args[0]
            for c in mock_emitters["ecar"].emit.call_args_list
            if c.args[0].event_type == "process_terminate"
        ]
        shell_terminate = next(
            event for event in terminate_events if event.process and event.process.pid == shell_pid
        )
        child_terminate = next(
            event for event in terminate_events if event.process and event.process.pid == child_pid
        )

        assert shell_terminate.timestamp > child_terminate.timestamp


def test_syslog_sort_orders_same_second_systemd_start_before_finish():
    """Second-precision syslog sorting should preserve systemd unit lifecycle order."""
    lines = [
        "<30>1 2024-03-18T12:04:02.000000Z WEB-EXT-01 systemd 1 - - Finished phpsessionclean.service - Clean PHP session files.",
        "<30>1 2024-03-18T12:04:02.000000Z WEB-EXT-01 systemd 1 - - Starting phpsessionclean.service - Clean PHP session files.",
    ]

    assert sorted(lines, key=_syslog_sort_key)[0].endswith(
        "Starting phpsessionclean.service - Clean PHP session files."
    )


def test_syslog_sudo_lifecycle_normalizer_orders_same_pid_pam_session():
    """Sudo COMMAND rows should stay between same-PID PAM open and close rows."""
    lines = [
        "<85>1 2024-03-18T12:00:00.100000Z WEB-EXT-01 sudo 701258 - - "
        "deploy : TTY=pts/1 ; PWD=/srv/app ; USER=root ; COMMAND=/usr/bin/id",
        "<86>1 2024-03-18T12:00:00.140000Z WEB-EXT-01 sudo 701258 - - "
        "pam_unix(sudo:session): session opened for user root(uid=0) by deploy(uid=1002)",
        "<86>1 2024-03-18T12:00:00.450000Z WEB-EXT-01 sudo 701258 - - "
        "pam_unix(sudo:session): session closed for user root",
    ]

    normalized = SyslogEmitter._normalize_sudo_session_lifecycles_for_lines(lines)

    assert "session opened" in normalized[0]
    assert "COMMAND=/usr/bin/id" in normalized[1]
    assert "session closed" in normalized[2]
    assert "2024-03-18T12:00:00.099000Z" in normalized[0]
