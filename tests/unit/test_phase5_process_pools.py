"""Unit tests for Phase 5.1.4: Expanded process template pools."""

import pytest
from datetime import datetime, timezone
from unittest.mock import Mock

from evidenceforge.generation.activity import (
    ActivityGenerator,
    PROCESS_TEMPLATES,
    PROCESS_TEMPLATES_LINUX,
    BASELINE_PATTERNS,
    PERSONA_PROCESS_WEIGHTS,
)
from evidenceforge.generation.state_manager import StateManager
from evidenceforge.models import User, System


class TestProcessPoolSize:
    """Verify process template pools have sufficient variety."""

    def test_windows_process_pool_over_25(self):
        """Windows process templates should have >25 unique paths."""
        paths = set()
        for category, templates in PROCESS_TEMPLATES.items():
            for process_name, _ in templates:
                paths.add(process_name)
        assert len(paths) > 25, f"Only {len(paths)} unique Windows process paths"

    def test_linux_process_pool_over_15(self):
        """Linux process templates should have >15 unique paths."""
        paths = set()
        for category, templates in PROCESS_TEMPLATES_LINUX.items():
            for process_name, _ in templates:
                paths.add(process_name)
        assert len(paths) > 15, f"Only {len(paths)} unique Linux process paths"

    def test_system_processes_present(self):
        """System backbone processes should be in templates."""
        assert 'process_system' in PROCESS_TEMPLATES
        system_paths = [p for p, _ in PROCESS_TEMPLATES['process_system']]
        # Should have svchost, explorer, and other system processes
        assert any('svchost' in p for p in system_paths)
        assert any('explorer' in p for p in system_paths)

    def test_user_apps_present(self):
        """User application processes should be in templates."""
        assert 'process_user_apps' in PROCESS_TEMPLATES
        app_paths = [p for p, _ in PROCESS_TEMPLATES['process_user_apps']]
        assert any('chrome' in p.lower() for p in app_paths)
        assert any('outlook' in p.lower() or 'OUTLOOK' in p for p in app_paths)

    def test_linux_system_processes_present(self):
        assert 'process_system' in PROCESS_TEMPLATES_LINUX
        system_paths = [p for p, _ in PROCESS_TEMPLATES_LINUX['process_system']]
        assert any('systemd' in p for p in system_paths)
        assert any('cron' in p for p in system_paths)


class TestBaselinePatterns:
    """Verify baseline patterns include new activity types."""

    def test_developer_has_user_apps(self):
        activities = [a for a, _ in BASELINE_PATTERNS['developer']]
        assert 'process_user_apps' in activities

    def test_executive_has_user_apps(self):
        activities = [a for a, _ in BASELINE_PATTERNS['executive']]
        assert 'process_user_apps' in activities

    def test_default_has_user_apps(self):
        activities = [a for a, _ in BASELINE_PATTERNS['default']]
        assert 'process_user_apps' in activities

    def test_sysadmin_pattern_exists(self):
        assert 'sysadmin' in BASELINE_PATTERNS
        activities = [a for a, _ in BASELINE_PATTERNS['sysadmin']]
        assert 'process_system' in activities


class TestPersonaProcessWeights:
    """Verify persona-specific process weights."""

    def test_developer_weights_favor_code(self):
        w = PERSONA_PROCESS_WEIGHTS['developer']
        assert w['process_code'] > w['process_user_apps']

    def test_executive_weights_favor_user_apps(self):
        w = PERSONA_PROCESS_WEIGHTS['executive']
        assert w['process_user_apps'] > w['process_code']

    def test_all_personas_have_weights(self):
        for persona in ['developer', 'executive', 'analyst', 'default']:
            assert persona in PERSONA_PROCESS_WEIGHTS


class TestUsernameSubstitution:
    """Verify {username} placeholder is substituted in process paths."""

    def test_username_substituted_in_process_name(self):
        state_manager = StateManager()
        mock_emitters = {'windows_event_security': Mock(), 'zeek_conn': Mock()}
        gen = ActivityGenerator(state_manager, mock_emitters)
        user = User(username="alice.smith", full_name="Alice Smith", email="a@t.com", enabled=True)
        system = System(hostname="W1", ip="10.0.0.1", os="Windows 10", type="workstation")
        timestamp = datetime(2024, 3, 15, 10, 0, 0, tzinfo=timezone.utc)
        state_manager.set_current_time(timestamp)

        # Create a session first
        logon_id = gen.generate_logon(user, system, timestamp)
        mock_emitters['windows_event_security'].reset_mock()

        # Execute user_apps activity multiple times to hit a {username} template
        for _ in range(50):
            gen.execute_baseline_activity(user, system, timestamp, 'process_user_apps')

        # Check all emitted events for un-substituted {username}
        for call in mock_emitters['windows_event_security'].emit_event.call_args_list:
            event_data = call[0][0]
            if 'NewProcessName' in event_data:
                assert '{username}' not in event_data['NewProcessName'], \
                    f"Unsubstituted placeholder in: {event_data['NewProcessName']}"
            if 'CommandLine' in event_data:
                assert '{username}' not in event_data['CommandLine'], \
                    f"Unsubstituted placeholder in: {event_data['CommandLine']}"
