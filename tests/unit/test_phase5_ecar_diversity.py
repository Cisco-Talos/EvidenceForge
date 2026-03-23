"""Unit tests for Phase 5.2: eCAR object type diversity."""

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

        # Now dispatched via dispatch_raw → emit_raw
        assert mock_emitters['ecar'].emit_raw.called
        event_data = mock_emitters['ecar'].emit_raw.call_args[0][0]
        assert event_data['object'] == 'FILE'
        assert event_data['action'] == 'CREATE'
        assert event_data['pid'] == 1234
        assert 'file_path' in event_data
        assert '{user}' not in event_data['file_path']

    def test_no_emit_without_ecar(self, state_manager):
        emitters = {'windows_event_security': Mock(), 'zeek_conn': Mock()}
        gen = ActivityGenerator(state_manager, emitters)
        system = System(hostname="W1", ip="10.0.0.1", os="Windows 10", type="workstation")
        gen._emit_ecar_file_event(system, datetime.now(timezone.utc), 1, 'CREATE', 'user')
        # Should not raise


class TestEcarRegistryEvent:
    def test_emits_registry_event(self, activity_gen, win_system, timestamp, mock_emitters):
        activity_gen._emit_ecar_registry_event(win_system, timestamp, 1234, 'alice.smith')

        assert mock_emitters['ecar'].emit_raw.called
        event_data = mock_emitters['ecar'].emit_raw.call_args[0][0]
        assert event_data['object'] == 'REGISTRY'
        assert event_data['action'] == 'MODIFY'
        assert 'registry_key' in event_data
        assert 'registry_value' in event_data


class TestEcarFlowEvent:
    def test_ecar_receives_connection_events(self, activity_gen, state_manager, timestamp, mock_emitters):
        """eCAR FLOW events are now dispatched via SecurityEvent canonical path (Phase 8.1)."""
        state_manager.set_current_time(timestamp)
        # generate_connection dispatches SecurityEvent with event_type="connection"
        # EcarEmitter.can_handle() returns True for "connection" and renders FLOW
        activity_gen.generate_connection(
            src_ip='10.0.10.1', dst_ip='93.184.216.34',
            time=timestamp, dst_port=443, proto='tcp', service='ssl',
            duration=1.0, orig_bytes=500, resp_bytes=1000,
        )

        # eCAR emitter should have received the event via emit() (canonical path)
        assert mock_emitters['ecar'].emit.called
        event = mock_emitters['ecar'].emit.call_args[0][0]
        assert event.event_type == 'connection'
        assert event.network.src_ip == '10.0.10.1'
        assert event.network.dst_ip == '93.184.216.34'
        assert event.network.dst_port == 443


class TestEcarModuleEvent:
    def test_emits_module_event(self, activity_gen, win_system, timestamp, mock_emitters):
        activity_gen._emit_ecar_module_event(win_system, timestamp, 1234, 'alice.smith')

        assert mock_emitters['ecar'].emit_raw.called
        event_data = mock_emitters['ecar'].emit_raw.call_args[0][0]
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

        # Collect eCAR object types from:
        # - emit_raw (diversity helpers: FILE, REGISTRY, MODULE)
        # - emit (canonical dispatch: PROCESS, USER_SESSION)
        object_types = set()
        for call in mock_emitters['ecar'].emit_raw.call_args_list:
            event_data = call[0][0]
            object_types.add(event_data.get('object'))
        _TYPE_MAP = {"logon": "USER_SESSION", "process_create": "PROCESS", "process_terminate": "PROCESS"}
        for call in mock_emitters['ecar'].emit.call_args_list:
            event = call[0][0]
            if event.event_type in _TYPE_MAP:
                object_types.add(_TYPE_MAP[event.event_type])

        # Should have at least PROCESS + USER_SESSION + some of FILE, MODULE, REGISTRY
        assert 'PROCESS' in object_types
        assert 'USER_SESSION' in object_types
        assert len(object_types) >= 3, f"Only {len(object_types)} object types: {object_types}"


class TestEcarRegistryBackslashEscaping:
    """Test that REGISTRY events with Windows paths produce valid NDJSON."""

    def test_registry_key_has_valid_backslashes(self, activity_gen, win_system, timestamp, mock_emitters):
        activity_gen._emit_ecar_registry_event(win_system, timestamp, 1234, 'alice.smith')

        event_data = mock_emitters['ecar'].emit_raw.call_args[0][0]
        key = event_data['registry_key']
        # Keys should contain backslashes (not forward slashes)
        assert '\\' in key
