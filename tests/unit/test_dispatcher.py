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

"""Tests for EventDispatcher routing, visibility filtering, and StateManager.apply()."""

from datetime import UTC, datetime, timedelta
from unittest.mock import MagicMock

import pytest

from evidenceforge.events import (
    AuthContext,
    HostContext,
    NetworkContext,
    ProcessContext,
    RawLogEntry,
    SecurityEvent,
)
from evidenceforge.events.contexts import SyslogContext
from evidenceforge.events.dispatcher import FORMAT_GROUPS, EventDispatcher
from evidenceforge.events.observation import (
    SOURCE_FAMILIES,
    ObservationPolicy,
    source_family_for_format,
)
from evidenceforge.generation.state_manager import StateManager


def _make_ts():
    return datetime(2026, 3, 19, 10, 0, 0, tzinfo=UTC)


def _make_mock_emitter(name: str, handles: bool = False):
    """Create a mock emitter with can_handle() returning the given value."""
    emitter = MagicMock()
    emitter.can_handle.return_value = handles
    return emitter


class TestDispatchRouting:
    """Tests for EventDispatcher event routing."""

    def test_dispatch_calls_apply_and_emitters(self):
        """dispatch() calls StateManager.apply() and emit() on matching emitters."""
        sm = MagicMock(spec=StateManager)
        emitter = _make_mock_emitter("windows", handles=True)
        dispatcher = EventDispatcher(state_manager=sm, emitters={"windows": emitter})

        event = SecurityEvent(timestamp=_make_ts(), event_type="logon")
        dispatcher.dispatch(event)

        sm.apply.assert_called_once_with(event)
        emitter.emit.assert_called_once_with(event)

    def test_dispatch_skips_non_matching_emitters(self):
        """dispatch() skips emitters where can_handle() returns False."""
        sm = MagicMock(spec=StateManager)
        matching = _make_mock_emitter("windows", handles=True)
        non_matching = _make_mock_emitter("zeek", handles=False)
        dispatcher = EventDispatcher(
            state_manager=sm,
            emitters={"windows": matching, "zeek_conn": non_matching},
        )

        event = SecurityEvent(timestamp=_make_ts(), event_type="logon")
        dispatcher.dispatch(event)

        matching.emit.assert_called_once_with(event)
        non_matching.emit.assert_not_called()

    def test_dispatch_no_matching_emitters(self):
        """dispatch() still calls apply() even if no emitters match."""
        sm = MagicMock(spec=StateManager)
        emitter = _make_mock_emitter("windows", handles=False)
        dispatcher = EventDispatcher(state_manager=sm, emitters={"windows": emitter})

        event = SecurityEvent(timestamp=_make_ts(), event_type="logon")
        dispatcher.dispatch(event)

        sm.apply.assert_called_once_with(event)
        emitter.emit.assert_not_called()

    def test_dispatch_applies_storyline_cluster_provenance_only(self):
        """storyline_cluster_id marks context provenance without changing origin flag."""
        sm = MagicMock(spec=StateManager)
        emitter = _make_mock_emitter("windows", handles=True)
        dispatcher = EventDispatcher(state_manager=sm, emitters={"windows": emitter})
        dispatcher.storyline_cluster_id = "story-001"

        event = SecurityEvent(timestamp=_make_ts(), event_type="process_create")
        dispatcher.dispatch(event)

        assert event.storyline_cluster_id == "story-001"
        assert event.storyline_origin is False


class TestObservationProfiles:
    """Tests for optional source-observation policy in dispatcher."""

    def test_complete_profile_preserves_visible_emission(self):
        """The default complete profile keeps current perfect-coverage behavior."""
        sm = MagicMock(spec=StateManager)
        emitter = _make_mock_emitter("sysmon", handles=True)
        dispatcher = EventDispatcher(
            state_manager=sm,
            emitters={"windows_event_sysmon": emitter},
        )
        dispatcher.storyline_cluster_id = "story-001"

        event = SecurityEvent(timestamp=_make_ts(), event_type="process_create")
        dispatcher.dispatch(event)

        emitter.emit.assert_called_once_with(event)
        assert dispatcher.source_evidence_status["story-001"]["sysmon"] == {"visible": 1}

    def test_source_missingness_drops_rendering_without_skipping_state(self, monkeypatch):
        """Non-complete profiles can drop source rows without corrupting canonical state."""
        monkeypatch.setattr(
            "evidenceforge.events.observation.get_observation_profile",
            lambda _name: {
                "default": {
                    "missingness": 0.0,
                    "delay_ms": {"min_ms": 0, "max_ms": 0},
                    "host_missingness_multiplier": {"min": 1.0, "max": 1.0},
                },
                "sources": {
                    "sysmon": {
                        "missingness": 1.0,
                        "delay_ms": {"min_ms": 0, "max_ms": 0},
                    }
                },
            },
        )
        sm = MagicMock(spec=StateManager)
        emitter = _make_mock_emitter("sysmon", handles=True)
        dispatcher = EventDispatcher(
            state_manager=sm,
            emitters={"windows_event_sysmon": emitter},
            observation_policy=ObservationPolicy("messy_test"),
        )
        dispatcher.storyline_cluster_id = "story-001"

        event = SecurityEvent(timestamp=_make_ts(), event_type="process_create")
        dispatcher.dispatch(event)

        sm.apply.assert_called_once_with(event)
        emitter.emit.assert_not_called()
        assert dispatcher.source_evidence_status["story-001"]["sysmon"] == {"dropped": 1}

    def test_source_delay_uses_copy_and_preserves_canonical_state(self, monkeypatch):
        """Source delays render a timestamp-adjusted copy while state sees canonical time."""
        monkeypatch.setattr(
            "evidenceforge.events.observation.get_observation_profile",
            lambda _name: {
                "default": {
                    "missingness": 0.0,
                    "delay_ms": {"min_ms": 0, "max_ms": 0},
                    "host_missingness_multiplier": {"min": 1.0, "max": 1.0},
                },
                "sources": {
                    "sysmon": {
                        "missingness": 0.0,
                        "delay_ms": {"min_ms": 17, "max_ms": 17},
                    }
                },
            },
        )
        sm = MagicMock(spec=StateManager)
        emitter = _make_mock_emitter("sysmon", handles=True)
        dispatcher = EventDispatcher(
            state_manager=sm,
            emitters={"windows_event_sysmon": emitter},
            observation_policy=ObservationPolicy("delay_test"),
        )
        dispatcher.storyline_cluster_id = "story-001"

        event = SecurityEvent(timestamp=_make_ts(), event_type="process_create")
        dispatcher.dispatch(event)

        sm.apply.assert_called_once_with(event)
        emitted_event = emitter.emit.call_args.args[0]
        assert emitted_event is not event
        assert emitted_event.timestamp == event.timestamp + timedelta(milliseconds=17)
        assert event.timestamp == _make_ts()
        assert dispatcher.source_evidence_status["story-001"]["sysmon"] == {"delayed": 1}

    def test_zeek_observation_delay_is_coherent_per_uid(self, monkeypatch):
        """Zeek protocol rows for one UID should share source collection delay."""
        monkeypatch.setattr(
            "evidenceforge.events.observation.get_observation_profile",
            lambda _name: {
                "default": {
                    "missingness": 0.0,
                    "delay_ms": {"min_ms": 0, "max_ms": 0},
                    "host_missingness_multiplier": {"min": 1.0, "max": 1.0},
                },
                "sources": {
                    "zeek": {
                        "missingness": 0.0,
                        "delay_ms": {"min_ms": 5, "max_ms": 1000},
                    }
                },
            },
        )
        sm = MagicMock(spec=StateManager)
        conn = _make_mock_emitter("zeek_conn", handles=True)
        http = _make_mock_emitter("zeek_http", handles=True)
        dispatcher = EventDispatcher(
            state_manager=sm,
            emitters={"zeek_conn": conn, "zeek_http": http},
            observation_policy=ObservationPolicy("zeek_delay_test"),
        )

        event = SecurityEvent(
            timestamp=_make_ts(),
            event_type="connection",
            network=NetworkContext(
                src_ip="10.0.1.10",
                src_port=51111,
                dst_ip="10.0.2.20",
                dst_port=443,
                protocol="tcp",
                zeek_uid="CUID123456789",
            ),
        )
        dispatcher.dispatch(event)

        conn_event = conn.emit.call_args.args[0]
        http_event = http.emit.call_args.args[0]
        assert conn_event.timestamp == http_event.timestamp
        assert conn_event.timestamp > event.timestamp

    def test_syslog_ssh_lifecycle_delay_preserves_session_order(self, monkeypatch):
        """SSH lifecycle syslog rows with one sshd PID should share collection delay."""
        monkeypatch.setattr(
            "evidenceforge.events.observation.get_observation_profile",
            lambda _name: {
                "default": {
                    "missingness": 0.0,
                    "delay_ms": {"min_ms": 0, "max_ms": 0},
                    "host_missingness_multiplier": {"min": 1.0, "max": 1.0},
                },
                "sources": {
                    "syslog": {
                        "missingness": 0.0,
                        "delay_ms": {"min_ms": 5, "max_ms": 1000},
                    }
                },
            },
        )
        policy = ObservationPolicy("syslog_delay_test")
        host = HostContext(
            hostname="APP-01",
            ip="10.0.3.10",
            os="Ubuntu 22.04",
            os_category="linux",
            system_type="server",
        )
        connection = SecurityEvent(
            timestamp=_make_ts(),
            event_type="syslog",
            src_host=host,
            syslog=SyslogContext(
                app_name="sshd",
                pid=5158,
                message='Connection from 10.0.1.10 port 52713 on 10.0.3.10 port 22 rdomain ""',
            ),
        )
        accepted = SecurityEvent(
            timestamp=_make_ts() + timedelta(milliseconds=120),
            event_type="ssh_session",
            dst_host=host,
            syslog=SyslogContext(
                app_name="sshd",
                pid=5158,
                message="Accepted publickey for admin from 10.0.1.10 port 52713 ssh2",
            ),
        )

        delay = policy.decide("syslog", connection).delay
        assert delay == policy.decide("syslog", accepted).delay
        assert connection.timestamp + delay < accepted.timestamp + delay

    def test_network_visibility_records_filtered_source_status(self):
        """Network visibility filtering is reflected in source evidence status."""
        sm = MagicMock(spec=StateManager)
        zeek = _make_mock_emitter("zeek_conn", handles=True)
        dispatcher = EventDispatcher(state_manager=sm, emitters={"zeek_conn": zeek})
        dispatcher.storyline_cluster_id = "story-001"

        event = SecurityEvent(
            timestamp=_make_ts(),
            event_type="connection",
            network=NetworkContext(
                src_ip="10.0.1.50",
                src_port=54321,
                dst_ip="10.0.1.50",
                dst_port=443,
                protocol="tcp",
            ),
            local_only=True,
        )
        dispatcher.dispatch(event)

        zeek.emit.assert_not_called()
        assert dispatcher.source_evidence_status["story-001"]["zeek"] == {"filtered": 1}

    def test_pre_dispatch_network_skip_records_filtered_source_status(self):
        """Pre-dispatch unobservable storyline connections are reflected in manifests."""
        sm = MagicMock(spec=StateManager)
        zeek = _make_mock_emitter("zeek_conn", handles=True)
        ecar = _make_mock_emitter("ecar", handles=True)
        dispatcher = EventDispatcher(state_manager=sm, emitters={"zeek_conn": zeek, "ecar": ecar})
        dispatcher.storyline_cluster_id = "story-001"

        dispatcher.record_filtered_network_observation()

        assert dispatcher.source_evidence_status["story-001"]["zeek"] == {"filtered": 1}
        assert "ecar" not in dispatcher.source_evidence_status["story-001"]

    def test_all_emitter_formats_map_to_source_families(self):
        """Every current emitter belongs to a source-observation family."""
        from evidenceforge.generation.engine.emitter_setup import _build_emitter_classes

        for format_name in _build_emitter_classes():
            assert source_family_for_format(format_name) in SOURCE_FAMILIES


class TestNetworkVisibilityFiltering:
    """Tests for network visibility integration in dispatcher."""

    def test_network_event_filtered_by_visibility(self):
        """Network emitters are filtered by visibility engine."""
        sm = MagicMock(spec=StateManager)
        zeek = _make_mock_emitter("zeek_conn", handles=True)
        snort = _make_mock_emitter("snort_alert", handles=True)

        visibility = MagicMock()
        # Only zeek formats are visible, not snort_alert
        visibility.get_log_formats_for_connection.return_value = FORMAT_GROUPS["zeek"]

        dispatcher = EventDispatcher(
            state_manager=sm,
            emitters={"zeek_conn": zeek, "snort_alert": snort},
            visibility_engine=visibility,
        )

        event = SecurityEvent(
            timestamp=_make_ts(),
            event_type="connection",
            network=NetworkContext(
                src_ip="10.0.1.50",
                src_port=54321,
                dst_ip="10.0.1.100",
                dst_port=443,
                protocol="tcp",
            ),
        )
        dispatcher.dispatch(event)

        zeek.emit.assert_called_once_with(event)
        snort.emit.assert_not_called()

    def test_host_event_bypasses_visibility(self):
        """Host events (no network context) skip visibility checks entirely."""
        sm = MagicMock(spec=StateManager)
        windows = _make_mock_emitter("windows", handles=True)

        visibility = MagicMock()

        dispatcher = EventDispatcher(
            state_manager=sm,
            emitters={"windows_event_security": windows},
            visibility_engine=visibility,
        )

        event = SecurityEvent(
            timestamp=_make_ts(),
            event_type="logon",
            dst_host=HostContext(
                hostname="WS-01",
                ip="10.0.1.50",
                os="Windows 10",
                os_category="windows",
                system_type="workstation",
            ),
        )
        dispatcher.dispatch(event)

        # Visibility engine should NOT be called for host events
        visibility.get_log_formats_for_connection.assert_not_called()
        windows.emit.assert_called_once_with(event)

    def test_no_visibility_engine_skips_filtering(self):
        """Without a visibility engine, all matching emitters receive events."""
        sm = MagicMock(spec=StateManager)
        zeek = _make_mock_emitter("zeek_conn", handles=True)

        dispatcher = EventDispatcher(
            state_manager=sm,
            emitters={"zeek_conn": zeek},
            visibility_engine=None,
        )

        event = SecurityEvent(
            timestamp=_make_ts(),
            event_type="connection",
            network=NetworkContext(
                src_ip="10.0.1.50",
                src_port=54321,
                dst_ip="10.0.1.100",
                dst_port=443,
                protocol="tcp",
            ),
        )
        dispatcher.dispatch(event)

        zeek.emit.assert_called_once_with(event)


class TestDispatchRaw:
    """Tests for RawLogEntry escape hatch."""

    def test_dispatch_raw_routes_to_named_emitter(self):
        """dispatch_raw() calls emit_raw() on the named emitter."""
        sm = MagicMock(spec=StateManager)
        syslog = _make_mock_emitter("syslog")
        dispatcher = EventDispatcher(
            state_manager=sm,
            emitters={"syslog": syslog},
        )

        entry = RawLogEntry(
            timestamp=_make_ts(),
            target_emitter="syslog",
            data={"message": "test"},
        )
        dispatcher.dispatch_raw(entry)

        syslog.emit_raw.assert_called_once_with({"message": "test"})

    def test_dispatch_raw_unknown_emitter_raises(self):
        """dispatch_raw() raises KeyError for unknown emitter names."""
        sm = MagicMock(spec=StateManager)
        dispatcher = EventDispatcher(state_manager=sm, emitters={})

        entry = RawLogEntry(
            timestamp=_make_ts(),
            target_emitter="nonexistent",
            data={},
        )
        with pytest.raises(KeyError, match="nonexistent"):
            dispatcher.dispatch_raw(entry)


class TestStateManagerApply:
    """Tests for StateManager.apply() with real StateManager."""

    def test_apply_logoff_ends_session(self):
        """apply() with logoff event ends the corresponding session."""
        sm = StateManager()
        sm.set_current_time(_make_ts())
        logon_id = sm.create_session(
            username="alice",
            system="WS-01",
            logon_type=2,
            source_ip="10.0.1.50",
        )

        # Session should exist
        assert sm.get_session(logon_id) is not None

        # Dispatch logoff event
        event = SecurityEvent(
            timestamp=_make_ts(),
            event_type="logoff",
            auth=AuthContext(username="alice", logon_id=logon_id),
        )
        sm.apply(event)

        # Session should be ended
        assert sm.get_session(logon_id) is None

    def test_apply_process_terminate_ends_process(self):
        """apply() with process_terminate event ends the process."""
        sm = StateManager()
        sm.set_current_time(_make_ts())
        pid = sm.create_process(
            system="WS-01",
            parent_pid=4,
            image="cmd.exe",
            command_line="cmd.exe",
            username="alice",
            integrity_level="Medium",
        )

        # Process should exist
        assert sm.get_process("WS-01", pid) is not None

        # Dispatch terminate event
        event = SecurityEvent(
            timestamp=_make_ts(),
            event_type="process_terminate",
            src_host=HostContext(
                hostname="WS-01",
                ip="10.0.1.50",
                os="Windows 10",
                os_category="windows",
                system_type="workstation",
            ),
            process=ProcessContext(
                pid=pid,
                parent_pid=4,
                image="cmd.exe",
                command_line="cmd.exe",
                username="alice",
            ),
        )
        sm.apply(event)

        # Process should be ended
        assert sm.get_process("WS-01", pid) is None

    def test_apply_logon_is_noop(self):
        """apply() with logon event is a no-op (IDs allocated before dispatch)."""
        sm = StateManager()
        event = SecurityEvent(
            timestamp=_make_ts(),
            event_type="logon",
            auth=AuthContext(username="alice", logon_id="0x12345"),
        )
        # Should not raise
        sm.apply(event)

    def test_apply_connection_updates_bytes(self):
        """apply() with connection event updates bytes if conn_id is present."""
        sm = StateManager()
        sm.set_current_time(_make_ts())
        conn_id = sm.open_connection(
            src_ip="10.0.1.50",
            src_port=54321,
            dst_ip="10.0.1.100",
            dst_port=443,
            protocol="tcp",
        )

        event = SecurityEvent(
            timestamp=_make_ts(),
            event_type="connection",
            network=NetworkContext(
                src_ip="10.0.1.50",
                src_port=54321,
                dst_ip="10.0.1.100",
                dst_port=443,
                protocol="tcp",
                conn_id=conn_id,
                orig_bytes=1024,
                resp_bytes=2048,
            ),
        )
        sm.apply(event)

        conn = sm.get_connection(conn_id)
        assert conn is not None
        assert conn.bytes_sent == 1024
        assert conn.bytes_received == 2048


class TestCanHandleDefault:
    """Tests for base LogEmitter.can_handle() default behavior."""

    def test_base_can_handle_returns_false(self):
        """Base LogEmitter.can_handle() returns False for any event."""

        event = SecurityEvent(timestamp=_make_ts(), event_type="logon")

        # Can't instantiate ABC directly, but we can test via a concrete subclass
        # All current subclasses inherit the default can_handle() which returns False
        # Let's test via a real emitter
        import tempfile
        from pathlib import Path

        from evidenceforge.formats import load_format
        from evidenceforge.generation.emitters.syslog import SyslogEmitter

        format_def = load_format("syslog")
        with tempfile.NamedTemporaryFile(suffix=".log") as f:
            emitter = SyslogEmitter(format_def, Path(f.name))
            assert emitter.can_handle(event) is False

    def test_all_emitters_have_supported_types(self):
        """All emitter subclasses have _supported_types attribute."""
        from evidenceforge.generation.emitters import (
            BashHistoryEmitter,
            EcarEmitter,
            SnortEmitter,
            SyslogEmitter,
            WebEmitter,
            WindowsEventEmitter,
            ZeekDnsEmitter,
            ZeekEmitter,
        )

        emitter_classes = [
            WindowsEventEmitter,
            ZeekEmitter,
            ZeekDnsEmitter,
            EcarEmitter,
            SyslogEmitter,
            BashHistoryEmitter,
            SnortEmitter,
            WebEmitter,
        ]
        for cls in emitter_classes:
            assert hasattr(cls, "_supported_types"), f"{cls.__name__} missing _supported_types"
            assert isinstance(cls._supported_types, set), (
                f"{cls.__name__}._supported_types is not a set"
            )

    def test_emit_raises_not_implemented(self):
        """emit() raises NotImplementedError for unsupported event types."""
        import tempfile
        from pathlib import Path

        from evidenceforge.formats import load_format
        from evidenceforge.generation.emitters.syslog import SyslogEmitter

        format_def = load_format("syslog")
        with tempfile.NamedTemporaryFile(suffix=".log") as f:
            emitter = SyslogEmitter(format_def, Path(f.name))
            event = SecurityEvent(timestamp=_make_ts(), event_type="unsupported_type")
            with pytest.raises(NotImplementedError, match="SyslogEmitter"):
                emitter.emit(event)

    def test_emit_raw_delegates_to_emit_event(self):
        """emit_raw() delegates to emit_event()."""
        import tempfile
        from pathlib import Path

        from evidenceforge.formats import load_format
        from evidenceforge.generation.emitters.syslog import SyslogEmitter

        format_def = load_format("syslog")
        with tempfile.NamedTemporaryFile(suffix=".log") as f:
            emitter = SyslogEmitter(format_def, Path(f.name))
            # Mock emit_event to verify delegation
            from unittest.mock import patch as mock_patch

            with mock_patch.object(emitter, "emit_event") as mock_emit:
                data = {"message": "test", "hostname": "srv-01"}
                emitter.emit_raw(data)
                mock_emit.assert_called_once_with(data)

    def test_syslog_sorts_full_file_on_close(self, tmp_path):
        """Syslog should be chronologically sorted across buffered flush boundaries."""
        from datetime import UTC, datetime

        from evidenceforge.formats import load_format
        from evidenceforge.generation.emitters.syslog import SyslogEmitter

        format_def = load_format("syslog")
        output_path = tmp_path / "syslog.log"
        emitter = SyslogEmitter(format_def, output_path, buffer_size=1)
        emitter.emit_raw(
            {
                "timestamp": datetime(2024, 10, 14, 20, 1, 25, tzinfo=UTC),
                "hostname": "linux01",
                "app_name": "systemd-logind",
                "pid": 500,
                "facility": 10,
                "severity": 6,
                "message": "Removed session 170.",
            }
        )
        emitter.emit_raw(
            {
                "timestamp": datetime(2024, 10, 14, 19, 0, 53, tzinfo=UTC),
                "hostname": "linux01",
                "app_name": "systemd-logind",
                "pid": 500,
                "facility": 10,
                "severity": 6,
                "message": "New session 176 of user jsmith.",
            }
        )
        emitter.close()

        lines = output_path.read_text(encoding="utf-8").splitlines()
        assert lines[0].startswith("<86>1 2024-10-14T19:00:53.000000Z")
        assert lines[1].startswith("<86>1 2024-10-14T20:01:25.000000Z")

    def test_syslog_normalizes_logind_session_ids_in_rendered_order(self, tmp_path):
        """Rendered New-session IDs should not move backward after final syslog sort."""
        from datetime import UTC, datetime

        from evidenceforge.formats import load_format
        from evidenceforge.generation.emitters.syslog import SyslogEmitter

        format_def = load_format("syslog")
        output_path = tmp_path / "syslog.log"
        emitter = SyslogEmitter(format_def, output_path, buffer_size=10)
        for timestamp, message in [
            (
                datetime(2024, 3, 18, 12, 10, 9, tzinfo=UTC),
                "New session 7608 of user admin.",
            ),
            (
                datetime(2024, 3, 18, 12, 4, 40, tzinfo=UTC),
                "New session 7616 of user root.",
            ),
            (
                datetime(2024, 3, 18, 12, 12, 0, tzinfo=UTC),
                "Removed session 7616.",
            ),
        ]:
            emitter.emit_raw(
                {
                    "timestamp": timestamp,
                    "hostname": "linux01",
                    "app_name": "systemd-logind",
                    "pid": 22523,
                    "facility": 10,
                    "severity": 6,
                    "message": message,
                }
            )
        emitter.close()

        lines = output_path.read_text(encoding="utf-8").splitlines()
        new_sessions = [
            int(line.split("New session ", 1)[1].split(" ", 1)[0])
            for line in lines
            if "New session" in line
        ]
        removed_session = int(lines[2].split("Removed session ", 1)[1].rstrip("."))
        assert new_sessions == sorted(new_sessions)
        assert removed_session == new_sessions[0]

    def test_syslog_rewrites_prewindow_logind_removals_below_visible_news(self, tmp_path):
        """Pre-window removes should not reuse a later visible New-session ID."""
        from datetime import UTC, datetime

        from evidenceforge.formats import load_format
        from evidenceforge.generation.emitters.syslog import SyslogEmitter

        format_def = load_format("syslog")
        output_path = tmp_path / "syslog.log"
        emitter = SyslogEmitter(format_def, output_path, buffer_size=10)
        for timestamp, message in [
            (
                datetime(2024, 3, 18, 12, 1, 55, tzinfo=UTC),
                "Removed session 12945.",
            ),
            (
                datetime(2024, 3, 18, 12, 8, 13, tzinfo=UTC),
                "New session 12945 of user root.",
            ),
            (
                datetime(2024, 3, 18, 12, 11, 12, tzinfo=UTC),
                "Removed session 12945.",
            ),
        ]:
            emitter.emit_raw(
                {
                    "timestamp": timestamp,
                    "hostname": "linux01",
                    "app_name": "systemd-logind",
                    "pid": 24094,
                    "facility": 10,
                    "severity": 6,
                    "message": message,
                }
            )
        emitter.close()

        lines = output_path.read_text(encoding="utf-8").splitlines()
        first_removed = int(lines[0].split("Removed session ", 1)[1].rstrip("."))
        new_session = int(lines[1].split("New session ", 1)[1].split(" ", 1)[0])
        later_removed = int(lines[2].split("Removed session ", 1)[1].rstrip("."))

        assert first_removed < new_session
        assert later_removed == new_session

    def test_syslog_sorts_same_second_ssh_lifecycle(self, tmp_path):
        """Same-second SSH syslog groups should keep lifecycle order."""
        from datetime import UTC, datetime

        from evidenceforge.formats import load_format
        from evidenceforge.generation.emitters.syslog import SyslogEmitter

        format_def = load_format("syslog")
        output_path = tmp_path / "syslog.log"
        emitter = SyslogEmitter(format_def, output_path, buffer_size=10)
        timestamp = datetime(2024, 10, 14, 19, 0, 53, tzinfo=UTC)
        for message in [
            "Accepted password for admin from 10.0.10.50 port 51111 ssh2",
            'Connection from 10.0.10.50 port 51111 on 10.0.20.10 port 22 rdomain ""',
            "pam_unix(sshd:session): session opened for user admin(uid=1001) by (uid=0)",
        ]:
            emitter.emit_raw(
                {
                    "timestamp": timestamp,
                    "hostname": "linux01",
                    "app_name": "sshd",
                    "pid": 6505,
                    "facility": 10,
                    "severity": 6,
                    "message": message,
                }
            )
        emitter.close()

        lines = output_path.read_text(encoding="utf-8").splitlines()
        assert "Connection from" in lines[0]
        assert "Accepted password" in lines[1]
        assert "pam_unix(sshd:session): session opened" in lines[2]

    def test_syslog_sorts_same_second_dhclient_lifecycle(self, tmp_path):
        """Same-second DHCP syslog groups should keep lease transaction order."""
        from datetime import UTC, datetime

        from evidenceforge.formats import load_format
        from evidenceforge.generation.emitters.syslog import SyslogEmitter

        format_def = load_format("syslog")
        output_path = tmp_path / "syslog.log"
        emitter = SyslogEmitter(format_def, output_path, buffer_size=10)
        timestamp = datetime(2024, 3, 18, 12, 11, 6, tzinfo=UTC)
        for message in [
            "DHCPACK of 10.10.1.99 from 10.10.2.10",
            "bound to 10.10.1.99 -- renewal in 7200 seconds.",
            "DHCPREQUEST for 10.10.1.99 on eth0 to 10.10.2.10 port 67",
        ]:
            emitter.emit_raw(
                {
                    "timestamp": timestamp,
                    "hostname": "ROGUE-LAPTOP",
                    "app_name": "dhclient",
                    "pid": 32883,
                    "facility": 3,
                    "severity": 6,
                    "message": message,
                }
            )
        emitter.close()

        lines = output_path.read_text(encoding="utf-8").splitlines()
        assert "DHCPREQUEST" in lines[0]
        assert "DHCPACK" in lines[1]
        assert "bound to" in lines[2]

    def test_syslog_ssh_session_routes_to_target_host_when_both_hosts_are_linux(self):
        """SSH auth syslog belongs to the server, not the Linux client host."""
        from evidenceforge.generation.emitters.syslog import SyslogEmitter

        src_host = HostContext(
            hostname="APP-INT-01",
            ip="10.10.2.30",
            os="Ubuntu 22.04",
            os_category="linux",
            system_type="server",
        )
        dst_host = HostContext(
            hostname="DB-PROD-01",
            ip="10.10.4.10",
            os="Ubuntu 22.04",
            os_category="linux",
            system_type="server",
        )
        event = SecurityEvent(
            timestamp=_make_ts(),
            event_type="ssh_session",
            src_host=src_host,
            dst_host=dst_host,
            syslog=SyslogContext(app_name="sshd", pid=1729, message="Accepted password"),
        )

        assert SyslogEmitter._linux_host(event) is dst_host


class TestBuildHostContext:
    """Tests for ActivityGenerator._build_host_context()."""

    def test_build_host_context(self):
        """_build_host_context() creates a HostContext from a System model."""
        from unittest.mock import MagicMock

        from evidenceforge.events.contexts import HostContext
        from evidenceforge.generation.activity import ActivityGenerator
        from evidenceforge.generation.state_manager import StateManager

        sm = StateManager()
        gen = ActivityGenerator(state_manager=sm, emitters={})

        system = MagicMock()
        system.hostname = "WS-01"
        system.ip = "10.0.1.50"
        system.os = "Windows 10 Enterprise"
        system.type = "workstation"

        ctx = gen._build_host_context(system)

        assert isinstance(ctx, HostContext)
        assert ctx.hostname == "WS-01"
        assert ctx.ip == "10.0.1.50"
        assert ctx.os == "Windows 10 Enterprise"
        assert ctx.os_category == "windows"
        assert ctx.system_type == "workstation"
        # No _ad_domain set → fqdn is bare hostname, netbios is default
        assert ctx.fqdn == "WS-01"
        assert ctx.netbios_domain == "CORP"

    def test_build_host_context_with_domain(self):
        """_build_host_context() precomputes FQDN and NetBIOS when domain is set."""
        from unittest.mock import MagicMock

        from evidenceforge.generation.activity import ActivityGenerator
        from evidenceforge.generation.state_manager import StateManager

        sm = StateManager()
        gen = ActivityGenerator(state_manager=sm, emitters={})
        gen._ad_domain = "corp.local"

        system = MagicMock()
        system.hostname = "WS-01"
        system.ip = "10.0.1.50"
        system.os = "Windows 10 Enterprise"
        system.type = "workstation"

        ctx = gen._build_host_context(system)

        assert ctx.domain == "corp.local"
        assert ctx.fqdn == "WS-01.corp.local"
        assert ctx.netbios_domain == "CORP"

    def test_build_host_context_linux(self):
        """_build_host_context() correctly detects Linux OS."""
        from unittest.mock import MagicMock

        from evidenceforge.generation.activity import ActivityGenerator
        from evidenceforge.generation.state_manager import StateManager

        sm = StateManager()
        gen = ActivityGenerator(state_manager=sm, emitters={})

        system = MagicMock()
        system.hostname = "srv-01"
        system.ip = "10.0.1.100"
        system.os = "Ubuntu 22.04"
        system.type = "server"

        ctx = gen._build_host_context(system)

        assert ctx.os_category == "linux"
        assert ctx.system_type == "server"

    def test_build_dc_host_context(self):
        """_build_dc_host_context() builds HostContext for DC from raw hostname."""
        from evidenceforge.generation.activity import ActivityGenerator
        from evidenceforge.generation.state_manager import StateManager

        sm = StateManager()
        gen = ActivityGenerator(state_manager=sm, emitters={})
        gen._ad_domain = "corp.local"

        ctx = gen._build_dc_host_context("DC-01")

        assert ctx.hostname == "DC-01"
        assert ctx.fqdn == "DC-01.corp.local"
        assert ctx.netbios_domain == "CORP"
        assert ctx.os_category == "windows"
        assert ctx.system_type == "domain_controller"
        assert ctx.ip == ""  # DC IP not needed for event rendering


class TestWarmUpSuppression:
    """Tests for warm-up period emission suppression."""

    def _make_dispatcher(self, output_start_time=None):
        sm = MagicMock(spec=StateManager)
        emitter = _make_mock_emitter("windows", handles=True)
        dispatcher = EventDispatcher(
            state_manager=sm,
            emitters={"windows_event_security": emitter},
            output_start_time=output_start_time,
        )
        return dispatcher, sm, emitter

    def test_dispatch_suppresses_emission_before_output_start(self):
        """Events before output_start_time update state but don't reach emitters."""
        output_start = datetime(2026, 3, 19, 10, 0, 0, tzinfo=UTC)
        dispatcher, sm, emitter = self._make_dispatcher(output_start_time=output_start)

        # Event 1 hour before output start
        event = SecurityEvent(
            timestamp=datetime(2026, 3, 19, 9, 0, 0, tzinfo=UTC),
            event_type="logon",
        )
        dispatcher.dispatch(event)

        sm.apply.assert_called_once_with(event)
        emitter.emit.assert_not_called()

    def test_dispatch_emits_at_output_start(self):
        """Events exactly at output_start_time are emitted normally."""
        output_start = datetime(2026, 3, 19, 10, 0, 0, tzinfo=UTC)
        dispatcher, sm, emitter = self._make_dispatcher(output_start_time=output_start)

        event = SecurityEvent(
            timestamp=datetime(2026, 3, 19, 10, 0, 0, tzinfo=UTC),
            event_type="logon",
        )
        dispatcher.dispatch(event)

        sm.apply.assert_called_once_with(event)
        emitter.emit.assert_called_once_with(event)

    def test_dispatch_emits_after_output_start(self):
        """Events after output_start_time are emitted normally."""
        output_start = datetime(2026, 3, 19, 10, 0, 0, tzinfo=UTC)
        dispatcher, sm, emitter = self._make_dispatcher(output_start_time=output_start)

        event = SecurityEvent(
            timestamp=datetime(2026, 3, 19, 11, 0, 0, tzinfo=UTC),
            event_type="logon",
        )
        dispatcher.dispatch(event)

        sm.apply.assert_called_once_with(event)
        emitter.emit.assert_called_once_with(event)

    def test_dispatch_no_suppression_when_output_start_none(self):
        """Without output_start_time, all events are emitted (default behavior)."""
        dispatcher, sm, emitter = self._make_dispatcher(output_start_time=None)

        event = SecurityEvent(
            timestamp=datetime(2026, 3, 19, 9, 0, 0, tzinfo=UTC),
            event_type="logon",
        )
        dispatcher.dispatch(event)

        sm.apply.assert_called_once_with(event)
        emitter.emit.assert_called_once_with(event)

    def test_dispatch_raw_suppressed_before_output_start(self):
        """dispatch_raw() skips emission for pre-window raw entries."""
        output_start = datetime(2026, 3, 19, 10, 0, 0, tzinfo=UTC)
        sm = MagicMock(spec=StateManager)
        syslog = _make_mock_emitter("syslog")
        dispatcher = EventDispatcher(
            state_manager=sm,
            emitters={"syslog": syslog},
            output_start_time=output_start,
        )

        entry = RawLogEntry(
            timestamp=datetime(2026, 3, 19, 9, 0, 0, tzinfo=UTC),
            target_emitter="syslog",
            data={"message": "test"},
        )
        dispatcher.dispatch_raw(entry)

        syslog.emit_raw.assert_not_called()

    def test_dispatch_raw_emitted_at_output_start(self):
        """dispatch_raw() emits normally at output_start_time."""
        output_start = datetime(2026, 3, 19, 10, 0, 0, tzinfo=UTC)
        sm = MagicMock(spec=StateManager)
        syslog = _make_mock_emitter("syslog")
        dispatcher = EventDispatcher(
            state_manager=sm,
            emitters={"syslog": syslog},
            output_start_time=output_start,
        )

        entry = RawLogEntry(
            timestamp=datetime(2026, 3, 19, 10, 0, 0, tzinfo=UTC),
            target_emitter="syslog",
            data={"message": "test"},
        )
        dispatcher.dispatch_raw(entry)

        syslog.emit_raw.assert_called_once_with({"message": "test"})
