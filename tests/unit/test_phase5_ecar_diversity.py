"""Unit tests for Phase 5.2.4: eCAR object type diversity."""

import pytest
from datetime import datetime, timezone
from unittest.mock import Mock

from evidenceforge.generation.activity import ActivityGenerator
from evidenceforge.generation.state_manager import StateManager
from evidenceforge.models import User, System


@pytest.fixture
def state_manager():
    return StateManager()


@pytest.fixture
def mock_emitters():
    return {
        'windows_event_security': Mock(),
        'zeek_conn': Mock(),
        'ecar': Mock(),
    }


@pytest.fixture
def activity_gen(state_manager, mock_emitters):
    return ActivityGenerator(state_manager, mock_emitters)


@pytest.fixture
def test_user():
    return User(username="alice.smith", full_name="Alice Smith", email="a@t.com", enabled=True)


@pytest.fixture
def win_system():
    return System(hostname="WKS-01", ip="10.0.10.1", os="Windows 10", type="workstation")


@pytest.fixture
def timestamp():
    return datetime(2024, 3, 15, 10, 0, 0, tzinfo=timezone.utc)


class TestEcarFileEvent:
    def test_emits_file_event(self, activity_gen, win_system, timestamp, mock_emitters):
        activity_gen._emit_ecar_file_event(win_system, timestamp, 1234, 'CREATE', 'alice.smith')

        assert mock_emitters['ecar'].emit_event.called
        event_data = mock_emitters['ecar'].emit_event.call_args[0][0]
        assert event_data['object'] == 'FILE'
        assert event_data['action'] == 'CREATE'
        assert event_data['pid'] == 1234
        assert 'file_path' in event_data
        assert '{user}' not in event_data['file_path']  # placeholder replaced

    def test_no_emit_without_ecar(self, state_manager):
        emitters = {'windows_event_security': Mock(), 'zeek_conn': Mock()}
        gen = ActivityGenerator(state_manager, emitters)
        system = System(hostname="W1", ip="10.0.0.1", os="Windows 10", type="workstation")
        gen._emit_ecar_file_event(system, datetime.now(timezone.utc), 1, 'CREATE', 'user')
        # Should not raise


class TestEcarRegistryEvent:
    def test_emits_registry_event(self, activity_gen, win_system, timestamp, mock_emitters):
        activity_gen._emit_ecar_registry_event(win_system, timestamp, 1234, 'alice.smith')

        assert mock_emitters['ecar'].emit_event.called
        event_data = mock_emitters['ecar'].emit_event.call_args[0][0]
        assert event_data['object'] == 'REGISTRY'
        assert event_data['action'] == 'MODIFY'
        assert 'registry_key' in event_data
        assert 'registry_value' in event_data


class TestEcarFlowEvent:
    def test_emits_flow_event(self, activity_gen, timestamp, mock_emitters):
        activity_gen._emit_ecar_flow_event(
            '10.0.10.1', '93.184.216.34', 443,
            timestamp, 'WKS-01', pid=1234
        )

        assert mock_emitters['ecar'].emit_event.called
        event_data = mock_emitters['ecar'].emit_event.call_args[0][0]
        assert event_data['object'] == 'FLOW'
        assert event_data['action'] == 'CONNECT'
        assert event_data['src_ip'] == '10.0.10.1'
        assert event_data['dst_ip'] == '93.184.216.34'
        assert event_data['dst_port'] == 443


class TestEcarModuleEvent:
    def test_emits_module_event(self, activity_gen, win_system, timestamp, mock_emitters):
        activity_gen._emit_ecar_module_event(win_system, timestamp, 1234, 'alice.smith')

        assert mock_emitters['ecar'].emit_event.called
        event_data = mock_emitters['ecar'].emit_event.call_args[0][0]
        assert event_data['object'] == 'MODULE'
        assert event_data['action'] == 'LOAD'
        assert 'file_path' in event_data
        assert event_data['file_path'].endswith('.dll')


class TestEcarDiversityInProcessCreation:
    """Test that process creation triggers diverse eCAR events."""

    def test_multiple_object_types_from_processes(self, activity_gen, test_user, win_system, timestamp, state_manager, mock_emitters):
        """Generating many processes should produce multiple eCAR object types."""
        state_manager.set_current_time(timestamp)
        logon_id = activity_gen.generate_logon(test_user, win_system, timestamp)

        # Generate many processes to trigger probabilistic eCAR events
        for i in range(50):
            activity_gen.generate_process(
                test_user, win_system, timestamp, logon_id,
                'C:\\Windows\\System32\\cmd.exe', f'cmd.exe /c echo {i}'
            )

        # Collect all unique eCAR object types
        object_types = set()
        for call in mock_emitters['ecar'].emit_event.call_args_list:
            event_data = call[0][0]
            object_types.add(event_data.get('object'))

        # Should have at least PROCESS + some of FILE, MODULE, REGISTRY
        assert 'PROCESS' in object_types
        assert 'USER_SESSION' in object_types  # From logon
        # With 50 processes at 40% file + 30% module + 20% registry, should see at least 2 more
        assert len(object_types) >= 3, f"Only {len(object_types)} object types: {object_types}"


class TestEcarFlowFromConnection:
    """Test that connections emit FLOW/CONNECT eCAR events."""

    def test_connection_emits_flow(self, activity_gen, timestamp, state_manager, mock_emitters):
        state_manager.set_current_time(timestamp)

        activity_gen.generate_connection(
            '10.0.10.1', '93.184.216.34', timestamp,
            dst_port=443, duration=1.0, orig_bytes=500, resp_bytes=1000,
        )

        # Check for FLOW/CONNECT in eCAR calls
        flow_calls = [
            c for c in mock_emitters['ecar'].emit_event.call_args_list
            if c[0][0].get('object') == 'FLOW'
        ]
        assert len(flow_calls) >= 1
        event_data = flow_calls[0][0][0]
        assert event_data['action'] == 'CONNECT'
        assert event_data['dst_ip'] == '93.184.216.34'
