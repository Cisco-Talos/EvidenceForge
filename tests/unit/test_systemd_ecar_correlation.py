"""Tests for systemd↔eCAR PROCESS cross-source correlation.

Verifies that systemd service start/stop generates paired eCAR
PROCESS/CREATE and PROCESS/TERMINATE events alongside syslog messages.
"""

from datetime import UTC, datetime
from unittest.mock import Mock

import pytest

from evidenceforge.generation.activity import ActivityGenerator
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
