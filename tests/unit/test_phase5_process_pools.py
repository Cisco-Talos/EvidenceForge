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

"""Unit tests for Phase 5.1.4: Expanded process template pools."""

import random
from datetime import UTC, datetime
from types import SimpleNamespace
from unittest.mock import Mock

from evidenceforge.generation.activity import (
    BASELINE_PATTERNS,
    PERSONA_PROCESS_WEIGHTS,
    PROCESS_TEMPLATES,
    PROCESS_TEMPLATES_LINUX,
    ActivityGenerator,
)
from evidenceforge.generation.activity.system_processes import (
    _resolve_host_placeholders,
    load_system_processes,
    pick_system_service_process,
)
from evidenceforge.generation.state_manager import StateManager
from evidenceforge.models import System, User


class TestProcessPoolSize:
    """Verify process template pools have sufficient variety."""

    def test_windows_process_pool_over_25(self):
        """Windows process templates should have >25 unique paths."""
        paths = set()
        for _category, templates in PROCESS_TEMPLATES.items():
            for process_name, _ in templates:
                paths.add(process_name)
        assert len(paths) > 25, f"Only {len(paths)} unique Windows process paths"

    def test_linux_process_pool_over_15(self):
        """Linux process templates should have >15 unique paths."""
        paths = set()
        for _category, templates in PROCESS_TEMPLATES_LINUX.items():
            for process_name, _ in templates:
                paths.add(process_name)
        assert len(paths) > 15, f"Only {len(paths)} unique Linux process paths"

    def test_system_processes_present(self):
        """System backbone processes should be in templates."""
        assert "process_system" in PROCESS_TEMPLATES
        system_paths = [p for p, _ in PROCESS_TEMPLATES["process_system"]]
        # Should have svchost, explorer, and other system processes
        assert any("svchost" in p for p in system_paths)
        assert any("explorer" in p for p in system_paths)

    def test_user_apps_present(self):
        """User application processes should be in templates."""
        assert "process_user_apps" in PROCESS_TEMPLATES
        app_paths = [p for p, _ in PROCESS_TEMPLATES["process_user_apps"]]
        assert any("chrome" in p.lower() for p in app_paths)
        assert any("outlook" in p.lower() or "OUTLOOK" in p for p in app_paths)

    def test_linux_system_processes_present(self):
        assert "process_system" in PROCESS_TEMPLATES_LINUX
        system_paths = [p for p, _ in PROCESS_TEMPLATES_LINUX["process_system"]]
        assert any("systemd" in p for p in system_paths)
        assert any("cron" in p for p in system_paths)

    def test_windows_search_helpers_are_parented_to_search_indexer(self):
        """Search helper processes should render under SearchIndexer, not svchost."""
        data = load_system_processes()
        workstation_services = data["system_services"]["workstation"]
        search_helpers = {
            entry["image"].rsplit("\\", 1)[-1]: entry["parent"]
            for entry in workstation_services
            if entry["image"].endswith(("SearchProtocolHost.exe", "SearchFilterHost.exe"))
        }

        assert search_helpers == {
            "SearchProtocolHost.exe": "search_indexer",
            "SearchFilterHost.exe": "search_indexer",
        }

    def test_system_process_templates_avoid_windows_internal_path_artifacts(self):
        """Windows internal maintenance paths and pipe args should look source-native."""
        data = load_system_processes()
        tiworker_entries = [
            entry for entry in data["scheduled_tasks"] if entry["image"].endswith("TiWorker.exe")
        ]
        search_protocol_entries = [
            entry
            for entry in data["system_services"]["workstation"]
            if entry["image"].endswith("SearchProtocolHost.exe")
        ]

        assert tiworker_entries
        assert search_protocol_entries
        assert all("servicingstack_\\" not in entry["image"] for entry in tiworker_entries)

        command = search_protocol_entries[0]["command_templates"][0]
        params = search_protocol_entries[0]["params"]["search_pipe_args"]
        assert "SearchProtocolHost.exe {search_pipe_args}" == command
        assert all("S-1-5-21 1" not in arg for arg in params)
        assert all("UsGthrCtrlFltPipeMssGthrPipe" in arg for arg in params)

    def test_tiworker_servicing_stack_placeholder_resolves_by_host_build(self):
        """TiWorker WinSxS component paths should follow the host OS family."""
        template = (
            r"C:\Windows\WinSxS\amd64_microsoft-windows-servicingstack_31bf3856ad364e35_"
            r"{servicing_stack_version}_none_7c91d6e7c9f7f1f5\TiWorker.exe"
        )

        workstation = SimpleNamespace(os="Windows 10 Enterprise", type="workstation")
        server = SimpleNamespace(os="Windows Server 2022", type="server")

        assert "10.0.19041.3636" in _resolve_host_placeholders(template, workstation)
        assert "10.0.20348.2322" in _resolve_host_placeholders(template, server)

    def test_ntdsutil_not_generic_domain_controller_service_texture(self):
        """NTDS utility should appear via explicit admin context, not service noise."""
        data = load_system_processes()
        dc_services = data["system_services"]["domain_controller"]

        assert all("ntdsutil.exe" not in entry["image"].lower() for entry in dc_services)

        host = SimpleNamespace(os="Windows Server 2022", type="domain_controller")
        picks = [
            pick_system_service_process(random.Random(seed), "domain_controller", host)[0].lower()
            for seed in range(100)
        ]
        assert all("ntdsutil.exe" not in image for image in picks)


class TestBaselinePatterns:
    """Verify baseline patterns include new activity types."""

    def test_developer_has_user_apps(self):
        activities = [a for a, _ in BASELINE_PATTERNS["developer"]]
        assert "process_user_apps" in activities

    def test_executive_has_user_apps(self):
        activities = [a for a, _ in BASELINE_PATTERNS["executive"]]
        assert "process_user_apps" in activities

    def test_default_has_user_apps(self):
        activities = [a for a, _ in BASELINE_PATTERNS["default"]]
        assert "process_user_apps" in activities

    def test_sysadmin_pattern_exists(self):
        assert "sysadmin" in BASELINE_PATTERNS
        activities = [a for a, _ in BASELINE_PATTERNS["sysadmin"]]
        assert "process_system" in activities


class TestPersonaProcessWeights:
    """Verify persona-specific process weights."""

    def test_developer_weights_favor_code(self):
        w = PERSONA_PROCESS_WEIGHTS["developer"]
        assert w["process_code"] > w["process_user_apps"]

    def test_executive_weights_favor_user_apps(self):
        w = PERSONA_PROCESS_WEIGHTS["executive"]
        assert w["process_user_apps"] > w["process_code"]

    def test_all_personas_have_weights(self):
        for persona in ["developer", "executive", "analyst", "default"]:
            assert persona in PERSONA_PROCESS_WEIGHTS


class TestUsernameSubstitution:
    """Verify {username} placeholder is substituted in process paths."""

    def test_username_substituted_in_process_name(self):
        state_manager = StateManager()
        mock_emitters = {"windows_event_security": Mock(), "zeek_conn": Mock()}
        gen = ActivityGenerator(state_manager, mock_emitters)
        user = User(username="alice.smith", full_name="Alice Smith", email="a@t.com", enabled=True)
        system = System(hostname="W1", ip="10.0.0.1", os="Windows 10", type="workstation")
        timestamp = datetime(2024, 3, 15, 10, 0, 0, tzinfo=UTC)
        state_manager.set_current_time(timestamp)

        # Create a session first
        gen.generate_logon(user, system, timestamp)
        mock_emitters["windows_event_security"].reset_mock()

        # Execute user_apps activity multiple times to hit a {username} template
        for _ in range(50):
            gen.execute_baseline_activity(user, system, timestamp, "process_user_apps")

        # Check all emitted events for un-substituted {username}
        for call in mock_emitters["windows_event_security"].emit_event.call_args_list:
            event_data = call[0][0]
            if "NewProcessName" in event_data:
                assert "{username}" not in event_data["NewProcessName"], (
                    f"Unsubstituted placeholder in: {event_data['NewProcessName']}"
                )
            if "CommandLine" in event_data:
                assert "{username}" not in event_data["CommandLine"], (
                    f"Unsubstituted placeholder in: {event_data['CommandLine']}"
                )
