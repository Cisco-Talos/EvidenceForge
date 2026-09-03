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

"""Unit tests for generation engine."""

import json
import random
from datetime import UTC, datetime, timedelta
from unittest.mock import Mock, patch

import pytest

from evidenceforge.events.collection_profile import COLLECTION_PROFILE_FILENAME
from evidenceforge.events.observation_manifest import OBSERVATION_MANIFEST_FILENAME
from evidenceforge.generation.checkpoints import (
    GenerationEngineParticipant,
    IncrementalCheckpointStore,
)
from evidenceforge.generation.checkpoints.runtime import IncrementalCheckpointController
from evidenceforge.generation.engine import GenerationEngine
from evidenceforge.generation.engine.storyline import _estimate_process_lifetime
from evidenceforge.models import (
    BaselineActivity,
    Environment,
    NetworkConfig,
    OutputSpec,
    Scenario,
    SourceObservationOverride,
    StorylineEvent,
    System,
    TimeWindow,
    User,
)
from evidenceforge.models.scenario import ConnectionEventSpec
from evidenceforge.output_targets import OUTPUT_TARGET_FILENAME
from evidenceforge.utils.timing import HawkesState


def _mock_activity_generator_factory(mock_instance: Mock):
    """Bind mocked generation to the bundle-owned session postcondition."""

    mock_instance.timing_runtime = None

    def factory(**kwargs):
        state_manager = kwargs["state_manager"]

        def generate_logon(**request):
            state_manager.set_current_time(request["time"])
            return state_manager.create_session(
                username=request["user"].username,
                system=request["system"].hostname,
                logon_type=request.get("logon_type", 2),
                source_ip=request.get("source_ip") or "-",
                start_time=request["time"],
                session_kind="interactive",
                lifecycle_group_id="mock-logon-bundle",
            )

        mock_instance.generate_logon.side_effect = generate_logon
        return mock_instance

    return factory


def test_service_wrapper_storyline_process_lifetimes_are_source_native():
    """Remote service wrappers should use the lifecycle of the modeled tool."""
    assert _estimate_process_lifetime(
        r"C:\Windows\System32\PSEXESVC.exe",
        "PSEXESVC.exe -accepteula",
    ) == (8.0, 45.0)
    assert (
        _estimate_process_lifetime(
            r"C:\Windows\System32\HealthMonitorSvc.exe",
            r"C:\Windows\System32\HealthMonitorSvc.exe",
        )
        is None
    )


@pytest.mark.slow
class TestGenerationEngine:
    def test_incremental_controller_commits_real_production_participants(
        self,
        minimal_scenario,
        tmp_path,
    ):
        """A real cadence barrier should publish every initialized mutable owner."""

        controller = IncrementalCheckpointController(
            store=IncrementalCheckpointStore(tmp_path),
            fingerprint="a" * 64,
            checkpoint_hours=1,
            resolved_scenario=b"resolved\n",
        )
        engine = GenerationEngine(
            minimal_scenario,
            tmp_path / "data",
            ground_truth_dir=tmp_path,
            artifact_dir=tmp_path / "artifacts",
            checkpoint_hours=1,
            checkpoint_controller=controller,
        )

        engine.generate()

        recovery = controller.store.recover(expected_fingerprint="a" * 64)
        expected_hours = int((engine.end_time - engine.warmup_start_time).total_seconds() // 3600)
        assert recovery.manifest.cursor.phase == "tail"
        assert recovery.manifest.cursor.completed_simulated_hours == expected_hours
        assert {head.owner for head in recovery.manifest.participant_heads} == {
            participant.checkpoint_owner for participant in engine._checkpoint_participants
        }
        assert (
            engine.lifecycle_registry.action_cohort_preparation_census().committed_receipt_authorities
            == 0
        )

    def test_checkpoint_hour_hook_is_cadence_only_and_uses_post_boundary_phase(
        self,
        minimal_scenario,
        tmp_path,
        monkeypatch,
    ):
        """Checkpoint hooks should run only at exact continuous-hour multiples."""

        observed: list[tuple[int, datetime, str]] = []
        engine = GenerationEngine(
            minimal_scenario,
            tmp_path,
            checkpoint_hour_callback=lambda hour, next_hour, phase: observed.append(
                (hour, next_hour, phase)
            ),
            checkpoint_hours=6,
        )
        start = datetime(2026, 1, 2, tzinfo=UTC)
        end = start + timedelta(hours=6)
        engine.start_time = start
        engine.end_time = end
        barrier = Mock()
        monkeypatch.setattr(engine, "_barrier_flush_all_emitters", barrier)

        engine._checkpoint_after_completed_hour(
            completed_simulated_hours=5,
            next_hour=start - timedelta(hours=1),
        )
        engine._checkpoint_after_completed_hour(
            completed_simulated_hours=6,
            next_hour=start,
        )
        engine._checkpoint_after_completed_hour(
            completed_simulated_hours=12,
            next_hour=end,
        )

        assert observed == [(6, start, "collection"), (12, end, "tail")]
        assert barrier.call_count == 2

    def test_checkpoint_hour_hook_requires_a_nonnegative_exact_cadence(
        self,
        minimal_scenario,
        tmp_path,
    ):
        """Internal engine cadence should reject disabled callbacks and invalid values."""

        with pytest.raises(ValueError, match="requires a positive"):
            GenerationEngine(
                minimal_scenario,
                tmp_path,
                checkpoint_hour_callback=lambda *_args: None,
            )
        with pytest.raises(ValueError, match="non-negative integer"):
            GenerationEngine(minimal_scenario, tmp_path, checkpoint_hours=-1)

    def test_generation_engine_checkpoint_head_round_trips_bounded_progress(
        self,
        minimal_scenario,
        tmp_path,
    ):
        """Engine progress and DHCP RNG state should restore without runtime identities."""

        engine = GenerationEngine(minimal_scenario, tmp_path / "source")
        system = engine.scenario.environment.systems[0]
        moment = datetime(2024, 1, 15, 11, tzinfo=UTC)
        renewal_rng = random.Random(91)
        renewal_rng.random()
        expected_rng = random.Random()
        expected_rng.setstate(renewal_rng.getstate())
        engine._ambient_registry_state = {"TEST-01": {"Run": "agent.exe"}}
        engine._audit_serials = {"TEST-01": 1032}
        engine._baseline_startup_next_age_seconds = {("TEST-01", "0x1"): 93.5}
        engine._dhcp_lease_state = {
            "TEST-01": {
                "system": system,
                "renewal_rng": renewal_rng,
                "next_renewal": moment,
                "renewal_sequence": 2,
            }
        }
        engine._extra_syslog_sudo_command_counts = {"testuser": 2}
        engine._extra_syslog_sudo_command_host_counts = {("TEST-01", "testuser"): 1}
        engine._hawkes_states = {"testuser": HawkesState(12.5, 0.75)}
        engine._last_tgt_time = {"testuser": moment}
        engine._machine_ids = {"TEST-01": "a" * 32}
        engine._ntp_schedule_state = {"TEST-01": (3, moment)}
        engine._pending_unlocks = {"testuser": (moment, "0x1")}
        engine._red_herring_executed = {1}
        engine._storyline_executed = {0, 2}
        engine._windows_scheduled_task_counts = {"TEST-01": 4}
        engine._windows_scheduled_task_last_seen = {"TEST-01": moment}
        engine.malicious_events = [{"event": "process", "time": moment}]
        engine.red_herring_events = [{"event": "dns", "time": moment}]

        seal = GenerationEngineParticipant(engine).prepare_checkpoint(0)
        assert not seal.segments

        restored_scenario = Scenario.model_validate(minimal_scenario.model_dump(mode="python"))
        restored = GenerationEngine(restored_scenario, tmp_path / "restored")
        GenerationEngineParticipant(restored).restore_checkpoint(seal.head.payload, ())

        assert restored._ambient_registry_state == engine._ambient_registry_state
        assert restored._hawkes_states == engine._hawkes_states
        assert restored._pending_unlocks == engine._pending_unlocks
        assert restored._storyline_executed == engine._storyline_executed
        assert restored.malicious_events == engine.malicious_events
        restored_lease = restored._dhcp_lease_state["TEST-01"]
        assert restored_lease["system"] is restored.scenario.environment.systems[0]
        assert restored_lease["system"] is not system
        assert restored_lease["renewal_rng"].random() == expected_rng.random()

    def test_warmup_boundary_checkpoint_contains_post_transition_state(self):
        """A cadence point at collection start should follow reset and sensor startup."""

        engine = object.__new__(GenerationEngine)
        start = datetime(2026, 1, 2, tzinfo=UTC)
        engine.start_time = start
        engine.end_time = start + timedelta(hours=1)
        engine.warmup_start_time = start - timedelta(hours=1)
        engine.warmup_duration = timedelta(hours=1)
        engine.scenario = Mock(environment=Mock(users=[]))
        engine.state_manager = Mock()
        engine.activity_generator = Mock()
        engine._report_progress = Mock()
        engine._emit_dhcp_leases = Mock()
        engine._generate_hour = Mock()
        order: list[str] = []
        engine._emit_sensor_startup = lambda: order.append("sensor-startup")
        engine._checkpoint_after_completed_hour = lambda **_kwargs: order.append("checkpoint")

        engine._generate_baseline()

        assert order[:2] == ["sensor-startup", "checkpoint"]

    """Tests for GenerationEngine class."""

    @pytest.fixture(autouse=True)
    def mock_new_emitters(self):
        """Mock emitter classes outside the original Phase 1 test surface.

        Tests were written for Phase 1 (2 emitters). The engine now creates many
        emitters, so this fixture keeps tests that patch only WindowsEventEmitter
        and ZeekEmitter focused on engine behavior.
        """
        with (
            patch("evidenceforge.generation.engine.emitter_setup.EcarEmitter") as m1,
            patch("evidenceforge.generation.engine.emitter_setup.SyslogEmitter") as m2,
            patch("evidenceforge.generation.engine.emitter_setup.BashHistoryEmitter") as m3,
            patch("evidenceforge.generation.engine.emitter_setup.SnortEmitter") as m4,
            patch("evidenceforge.generation.engine.emitter_setup.WebEmitter") as m5,
            patch("evidenceforge.generation.engine.emitter_setup.ZeekSmtpEmitter") as m6,
            patch("evidenceforge.generation.engine.emitter_setup.ZeekSmbFilesEmitter") as m7,
            patch("evidenceforge.generation.engine.emitter_setup.ZeekSmbMappingEmitter") as m8,
        ):
            yield m1, m2, m3, m4, m5, m6, m7, m8

    @pytest.fixture
    def minimal_scenario(self):
        """Create minimal valid scenario for testing."""
        return Scenario(
            version="1.0",
            name="test-scenario",
            description="Test scenario",
            environment=Environment(
                description="Test environment",
                users=[
                    User(
                        username="testuser",
                        full_name="Test User",
                        email="test@example.com",
                        enabled=True,
                        primary_system="TEST-01",
                    )
                ],
                systems=[
                    System(hostname="TEST-01", ip="10.0.0.1", os="Windows 10", type="workstation")
                ],
            ),
            time_window=TimeWindow(start="2024-01-15T10:00:00Z", duration="2h"),
            baseline_activity=BaselineActivity(
                description="Test baseline", intensity="medium", variation="low"
            ),
            output=OutputSpec(
                logs=[{"format": "windows"}, {"format": "zeek"}],
                destination="./output",
                compression=False,
            ),
            personas=[],
        )

    def test_system_seeding_does_not_mutate_packaged_reverse_dns(self, minimal_scenario, tmp_path):
        """Scenario identities must remain local to their generation engine."""
        from evidenceforge.generation.activity.network import REVERSE_DNS

        scenario_ip = "10.255.254.253"
        scenario_system = System(
            hostname="SCENARIO-ONLY",
            ip=scenario_ip,
            os="Windows 11",
            type="workstation",
        )
        scenario = minimal_scenario.model_copy(
            update={
                "environment": minimal_scenario.environment.model_copy(
                    update={"systems": [scenario_system]}
                )
            }
        )
        engine = GenerationEngine(scenario, tmp_path)
        engine.start_time = None
        engine._kernel_boot_uptimes = {}
        engine._system_pids = {}
        engine._infra_ips = {"db_servers": [], "dns": [], "dc_hostnames": [], "dc": []}
        engine.activity_generator = Mock()

        prior = REVERSE_DNS.pop(scenario_ip, None)
        try:
            with (
                patch.object(engine, "_seed_windows_process_tree"),
                patch.object(engine, "_generate_external_client_ip", return_value="198.51.100.10"),
            ):
                engine._seed_system_process_trees()
            assert scenario_ip not in REVERSE_DNS
        finally:
            if prior is not None:
                REVERSE_DNS[scenario_ip] = prior

    @pytest.fixture
    def scenario_with_storyline(self):
        """Create scenario with storyline events."""
        return Scenario(
            version="1.0",
            name="attack-scenario",
            description="Attack scenario",
            environment=Environment(
                description="Test environment",
                users=[
                    User(
                        username="testuser",
                        full_name="Test User",
                        email="test@example.com",
                        enabled=True,
                        primary_system="TEST-01",
                    ),
                    User(
                        username="attacker",
                        full_name="Attacker",
                        email="attacker@evil.com",
                        enabled=True,
                    ),
                ],
                systems=[
                    System(hostname="TEST-01", ip="10.0.0.1", os="Windows 10", type="workstation")
                ],
            ),
            time_window=TimeWindow(start="2024-01-15T10:00:00Z", duration="2h"),
            baseline_activity=BaselineActivity(
                description="Test baseline", intensity="low", variation="low"
            ),
            output=OutputSpec(
                logs=[{"format": "windows"}, {"format": "zeek"}],
                destination="./output",
                compression=False,
            ),
            personas=[],
            storyline=[
                StorylineEvent(
                    id="evt-test-1",
                    time="2024-01-15T10:30:00Z",
                    actor="attacker",
                    system="TEST-01",
                    activity="Execute malicious PowerShell command",
                    events=[{"type": "process", "process_name": "powershell.exe"}],
                )
            ],
        )

    @patch("evidenceforge.generation.engine.core.ActivityGenerator")
    @patch("evidenceforge.generation.engine.emitter_setup.ZeekReporterEmitter")
    @patch("evidenceforge.generation.engine.emitter_setup.ZeekPacketFilterEmitter")
    @patch("evidenceforge.generation.engine.emitter_setup.ZeekPeEmitter")
    @patch("evidenceforge.generation.engine.emitter_setup.ZeekOcspEmitter")
    @patch("evidenceforge.generation.engine.emitter_setup.ZeekX509Emitter")
    @patch("evidenceforge.generation.engine.emitter_setup.ZeekWeirdEmitter")
    @patch("evidenceforge.generation.engine.emitter_setup.ZeekNtpEmitter")
    @patch("evidenceforge.generation.engine.emitter_setup.ZeekDhcpEmitter")
    @patch("evidenceforge.generation.engine.emitter_setup.ZeekFilesEmitter")
    @patch("evidenceforge.generation.engine.emitter_setup.ZeekSslEmitter")
    @patch("evidenceforge.generation.engine.emitter_setup.ZeekHttpEmitter")
    @patch("evidenceforge.generation.engine.emitter_setup.ZeekDnsEmitter")
    @patch("evidenceforge.generation.engine.emitter_setup.ZeekEmitter")
    @patch("evidenceforge.generation.engine.emitter_setup.SysmonEventEmitter")
    @patch("evidenceforge.generation.engine.emitter_setup.WindowsEventEmitter")
    @patch("evidenceforge.generation.engine.emitter_setup.load_format")
    def test_initialize_creates_emitters(
        self,
        mock_load_format,
        mock_windows,
        mock_sysmon,
        mock_zeek,
        mock_zeek_dns,
        mock_zeek_http,
        mock_zeek_ssl,
        mock_zeek_files,
        mock_zeek_dhcp,
        mock_zeek_ntp,
        mock_zeek_weird,
        mock_zeek_x509,
        mock_zeek_ocsp,
        mock_zeek_pe,
        mock_zeek_pf,
        mock_zeek_reporter,
        mock_activity_gen,
        minimal_scenario,
        tmp_path,
    ):
        """Engine initialization should create emitters for each format."""
        # Mock format definitions
        mock_format_def = Mock()
        mock_format_def.output.file_extension = ".log"
        mock_load_format.return_value = mock_format_def

        minimal_scenario.environment.network = NetworkConfig.model_validate(
            {
                "segments": [
                    {
                        "name": "workstations",
                        "cidr": "10.0.0.0/24",
                        "exposure": "internal",
                        "systems": ["TEST-01"],
                    }
                ],
                "sensors": [],
            }
        )

        engine = GenerationEngine(minimal_scenario, tmp_path)
        engine._initialize()

        # Verify emitters created: windows (2: security + sysmon) + zeek (16) = 18
        assert mock_windows.called
        assert mock_zeek.called
        assert len(engine.emitters) == 18
        assert "windows_event_security" in engine.emitters
        assert "zeek_conn" in engine.emitters
        assert "zeek_http" in engine.emitters
        assert "zeek_ssl" in engine.emitters
        assert "zeek_files" in engine.emitters
        assert "zeek_smb_mapping" in engine.emitters
        assert "zeek_smb_files" in engine.emitters
        assert engine.source_deployment_compilation.census.sensor_sources == 0
        assert engine.source_deployment_compilation.source_instances == (
            "sysmon:test-01",
            "windows_security:test-01",
        )
        assert (
            engine.dispatcher.collection_deployment
            is engine.source_deployment_compilation.deployment
        )

    @patch("evidenceforge.generation.engine.core.ActivityGenerator")
    def test_initialize_compiles_and_injects_sensor_deployment(
        self,
        mock_activity_gen,
        minimal_scenario,
        tmp_path,
    ):
        """Engine should retain and inject the exact sensor-backed compilation."""
        scenario_data = minimal_scenario.model_dump(mode="json")
        scenario_data["environment"]["network"] = {
            "segments": [
                {
                    "name": "workstations",
                    "cidr": "10.0.0.0/24",
                    "exposure": "internal",
                    "systems": ["TEST-01"],
                }
            ],
            "sensors": [
                {
                    "type": "network",
                    "name": "core-zeek",
                    "monitoring_segments": ["workstations"],
                    "log_formats": ["zeek_conn"],
                }
            ],
        }
        scenario = Scenario.model_validate(scenario_data)
        engine = GenerationEngine(scenario, tmp_path)

        def initialize_fake_emitter() -> None:
            engine.emitters = {"zeek_conn": Mock()}

        with patch.object(engine, "_init_emitters", side_effect=initialize_fake_emitter):
            engine._initialize()

        compilation = engine.source_deployment_compilation
        assert compilation.census.sensor_sources == 1
        assert compilation.source_instances == ("zeek:core-zeek",)
        assert engine.dispatcher.collection_deployment is compilation.deployment
        assert len(compilation.digest) == 64
        assert mock_activity_gen.called

    @patch("evidenceforge.generation.engine.core.ActivityGenerator")
    @patch("evidenceforge.generation.engine.emitter_setup.ZeekReporterEmitter")
    @patch("evidenceforge.generation.engine.emitter_setup.ZeekPacketFilterEmitter")
    @patch("evidenceforge.generation.engine.emitter_setup.ZeekPeEmitter")
    @patch("evidenceforge.generation.engine.emitter_setup.ZeekOcspEmitter")
    @patch("evidenceforge.generation.engine.emitter_setup.ZeekX509Emitter")
    @patch("evidenceforge.generation.engine.emitter_setup.ZeekWeirdEmitter")
    @patch("evidenceforge.generation.engine.emitter_setup.ZeekNtpEmitter")
    @patch("evidenceforge.generation.engine.emitter_setup.ZeekDhcpEmitter")
    @patch("evidenceforge.generation.engine.emitter_setup.ZeekFilesEmitter")
    @patch("evidenceforge.generation.engine.emitter_setup.ZeekSslEmitter")
    @patch("evidenceforge.generation.engine.emitter_setup.ZeekHttpEmitter")
    @patch("evidenceforge.generation.engine.emitter_setup.ZeekDnsEmitter")
    @patch("evidenceforge.generation.engine.emitter_setup.ZeekEmitter")
    @patch("evidenceforge.generation.engine.emitter_setup.WindowsEventEmitter")
    @patch("evidenceforge.generation.engine.emitter_setup.SysmonEventEmitter")
    @patch("evidenceforge.generation.engine.emitter_setup.load_format")
    def test_initialize_resolves_time_window(
        self,
        mock_load_format,
        mock_sysmon,
        mock_windows,
        mock_zeek,
        mock_zeek_dns,
        mock_zeek_http,
        mock_zeek_ssl,
        mock_zeek_files,
        mock_zeek_dhcp,
        mock_zeek_ntp,
        mock_zeek_weird,
        mock_zeek_x509,
        mock_zeek_ocsp,
        mock_zeek_pe,
        mock_zeek_pf,
        mock_zeek_reporter,
        mock_activity_gen,
        minimal_scenario,
        tmp_path,
    ):
        """Engine should correctly resolve time window from duration."""
        mock_format_def = Mock()
        mock_format_def.output.file_extension = ".log"
        mock_load_format.return_value = mock_format_def

        engine = GenerationEngine(minimal_scenario, tmp_path)
        engine._initialize()

        # Verify time window calculated correctly
        assert engine.start_time == datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)
        assert engine.end_time == datetime(2024, 1, 15, 12, 0, 0, tzinfo=UTC)

    @patch("evidenceforge.generation.engine.core.ActivityGenerator")
    @patch("evidenceforge.generation.engine.emitter_setup.ZeekReporterEmitter")
    @patch("evidenceforge.generation.engine.emitter_setup.ZeekPacketFilterEmitter")
    @patch("evidenceforge.generation.engine.emitter_setup.ZeekPeEmitter")
    @patch("evidenceforge.generation.engine.emitter_setup.ZeekOcspEmitter")
    @patch("evidenceforge.generation.engine.emitter_setup.ZeekX509Emitter")
    @patch("evidenceforge.generation.engine.emitter_setup.ZeekWeirdEmitter")
    @patch("evidenceforge.generation.engine.emitter_setup.ZeekNtpEmitter")
    @patch("evidenceforge.generation.engine.emitter_setup.ZeekDhcpEmitter")
    @patch("evidenceforge.generation.engine.emitter_setup.ZeekFilesEmitter")
    @patch("evidenceforge.generation.engine.emitter_setup.ZeekSslEmitter")
    @patch("evidenceforge.generation.engine.emitter_setup.ZeekHttpEmitter")
    @patch("evidenceforge.generation.engine.emitter_setup.ZeekDnsEmitter")
    @patch("evidenceforge.generation.engine.emitter_setup.ZeekEmitter")
    @patch("evidenceforge.generation.engine.emitter_setup.WindowsEventEmitter")
    @patch("evidenceforge.generation.engine.emitter_setup.SysmonEventEmitter")
    @patch("evidenceforge.generation.engine.emitter_setup.load_format")
    def test_initialize_creates_output_directory(
        self,
        mock_load_format,
        mock_sysmon,
        mock_windows,
        mock_zeek,
        mock_zeek_dns,
        mock_zeek_http,
        mock_zeek_ssl,
        mock_zeek_files,
        mock_zeek_dhcp,
        mock_zeek_ntp,
        mock_zeek_weird,
        mock_zeek_x509,
        mock_zeek_ocsp,
        mock_zeek_pe,
        mock_zeek_pf,
        mock_zeek_reporter,
        mock_activity_gen,
        minimal_scenario,
        tmp_path,
    ):
        """Engine should create output directory if it doesn't exist."""
        mock_format_def = Mock()
        mock_format_def.output.file_extension = ".log"
        mock_load_format.return_value = mock_format_def

        output_dir = tmp_path / "nonexistent"
        engine = GenerationEngine(minimal_scenario, output_dir)
        engine._initialize()

        assert output_dir.exists()

    @patch("evidenceforge.generation.engine.core.ActivityGenerator")
    @patch("evidenceforge.generation.engine.emitter_setup.ZeekReporterEmitter")
    @patch("evidenceforge.generation.engine.emitter_setup.ZeekPacketFilterEmitter")
    @patch("evidenceforge.generation.engine.emitter_setup.ZeekPeEmitter")
    @patch("evidenceforge.generation.engine.emitter_setup.ZeekOcspEmitter")
    @patch("evidenceforge.generation.engine.emitter_setup.ZeekX509Emitter")
    @patch("evidenceforge.generation.engine.emitter_setup.ZeekWeirdEmitter")
    @patch("evidenceforge.generation.engine.emitter_setup.ZeekNtpEmitter")
    @patch("evidenceforge.generation.engine.emitter_setup.ZeekDhcpEmitter")
    @patch("evidenceforge.generation.engine.emitter_setup.ZeekFilesEmitter")
    @patch("evidenceforge.generation.engine.emitter_setup.ZeekSslEmitter")
    @patch("evidenceforge.generation.engine.emitter_setup.ZeekHttpEmitter")
    @patch("evidenceforge.generation.engine.emitter_setup.ZeekDnsEmitter")
    @patch("evidenceforge.generation.engine.emitter_setup.ZeekEmitter")
    @patch("evidenceforge.generation.engine.emitter_setup.WindowsEventEmitter")
    @patch("evidenceforge.generation.engine.emitter_setup.SysmonEventEmitter")
    @patch("evidenceforge.generation.engine.emitter_setup.load_format")
    def test_initialize_sets_state_manager_time(
        self,
        mock_load_format,
        mock_sysmon,
        mock_windows,
        mock_zeek,
        mock_zeek_dns,
        mock_zeek_http,
        mock_zeek_ssl,
        mock_zeek_files,
        mock_zeek_dhcp,
        mock_zeek_ntp,
        mock_zeek_weird,
        mock_zeek_x509,
        mock_zeek_ocsp,
        mock_zeek_pe,
        mock_zeek_pf,
        mock_zeek_reporter,
        mock_activity_gen,
        minimal_scenario,
        tmp_path,
    ):
        """Engine should set StateManager initial time to warm-up start."""
        mock_format_def = Mock()
        mock_format_def.output.file_extension = ".log"
        mock_load_format.return_value = mock_format_def

        engine = GenerationEngine(minimal_scenario, tmp_path)
        engine._initialize()

        # Verify state manager time set to warm-up start (before scenario start)
        assert engine.state_manager.get_current_time() == engine.warmup_start_time

    @patch("evidenceforge.generation.engine.core.ActivityGenerator")
    @patch("evidenceforge.generation.engine.emitter_setup.ZeekReporterEmitter")
    @patch("evidenceforge.generation.engine.emitter_setup.ZeekPacketFilterEmitter")
    @patch("evidenceforge.generation.engine.emitter_setup.ZeekPeEmitter")
    @patch("evidenceforge.generation.engine.emitter_setup.ZeekOcspEmitter")
    @patch("evidenceforge.generation.engine.emitter_setup.ZeekX509Emitter")
    @patch("evidenceforge.generation.engine.emitter_setup.ZeekWeirdEmitter")
    @patch("evidenceforge.generation.engine.emitter_setup.ZeekNtpEmitter")
    @patch("evidenceforge.generation.engine.emitter_setup.ZeekDhcpEmitter")
    @patch("evidenceforge.generation.engine.emitter_setup.ZeekFilesEmitter")
    @patch("evidenceforge.generation.engine.emitter_setup.ZeekSslEmitter")
    @patch("evidenceforge.generation.engine.emitter_setup.ZeekHttpEmitter")
    @patch("evidenceforge.generation.engine.emitter_setup.ZeekDnsEmitter")
    @patch("evidenceforge.generation.engine.emitter_setup.ZeekEmitter")
    @patch("evidenceforge.generation.engine.emitter_setup.WindowsEventEmitter")
    @patch("evidenceforge.generation.engine.emitter_setup.SysmonEventEmitter")
    @patch("evidenceforge.generation.engine.emitter_setup.load_format")
    def test_warmup_snaps_to_whole_hours(
        self,
        mock_load_format,
        mock_sysmon,
        mock_windows,
        mock_zeek,
        mock_zeek_dns,
        mock_zeek_http,
        mock_zeek_ssl,
        mock_zeek_files,
        mock_zeek_dhcp,
        mock_zeek_ntp,
        mock_zeek_weird,
        mock_zeek_x509,
        mock_zeek_ocsp,
        mock_zeek_pe,
        mock_zeek_pf,
        mock_zeek_reporter,
        mock_activity_gen,
        tmp_path,
    ):
        """Sub-hour warmup values snap up to whole hours to prevent overlap."""
        mock_format_def = Mock()
        mock_format_def.output.file_extension = ".log"
        mock_load_format.return_value = mock_format_def

        scenario = Scenario(
            version="1.0",
            name="test-warmup-snap",
            description="Test warmup snapping",
            environment=Environment(
                description="Test",
                users=[
                    User(
                        username="testuser",
                        full_name="Test User",
                        email="test@example.com",
                        enabled=True,
                        primary_system="TEST-01",
                    )
                ],
                systems=[
                    System(hostname="TEST-01", ip="10.0.0.1", os="Windows 10", type="workstation")
                ],
            ),
            time_window=TimeWindow(start="2024-01-15T10:00:00Z", duration="2h", warmup="1h30m"),
            baseline_activity=BaselineActivity(
                description="Test baseline", intensity="medium", variation="low"
            ),
            output=OutputSpec(
                logs=[{"format": "windows"}],
                destination="./output",
                compression=False,
            ),
            personas=[],
        )

        engine = GenerationEngine(scenario, tmp_path)
        engine._initialize()

        # 1h30m snaps up to 2h: warmup_start = 10:00 - 2h = 08:00
        assert engine.warmup_start_time == datetime(2024, 1, 15, 8, 0, 0, tzinfo=UTC)
        assert engine.warmup_duration == timedelta(hours=2)
        # generation_epoch matches warmup_start_time
        assert engine._generation_epoch == engine.warmup_start_time

    def test_parse_storyline_time_iso8601(self, minimal_scenario, tmp_path):
        """Should parse ISO 8601 absolute time strings."""
        engine = GenerationEngine(minimal_scenario, tmp_path)
        engine.start_time = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)

        result = engine._parse_storyline_time("2024-01-15T10:30:00Z")

        assert result == datetime(2024, 1, 15, 10, 30, 0, tzinfo=UTC)

    def test_parse_storyline_time_relative_duration(self, minimal_scenario, tmp_path):
        """Should parse relative duration strings like '+2h30m'."""
        engine = GenerationEngine(minimal_scenario, tmp_path)
        engine.start_time = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)

        result = engine._parse_storyline_time("+2h30m")

        assert result == datetime(2024, 1, 15, 12, 30, 0, tzinfo=UTC)

    def test_parse_storyline_time_relative_with_seconds(self, minimal_scenario, tmp_path):
        """Should parse relative duration with seconds like '+20m30s'."""
        engine = GenerationEngine(minimal_scenario, tmp_path)
        engine.start_time = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)

        result = engine._parse_storyline_time("+20m30s")

        assert result == datetime(2024, 1, 15, 10, 20, 30, tzinfo=UTC)

    def test_parse_storyline_time_relative_seconds(self, minimal_scenario, tmp_path):
        """Should parse relative seconds like '+7200'."""
        engine = GenerationEngine(minimal_scenario, tmp_path)
        engine.start_time = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)

        result = engine._parse_storyline_time("+7200")

        assert result == datetime(2024, 1, 15, 12, 0, 0, tzinfo=UTC)

    def test_parse_storyline_time_invalid_format(self, minimal_scenario, tmp_path):
        """Should raise ValueError for invalid time format."""
        engine = GenerationEngine(minimal_scenario, tmp_path)
        engine.start_time = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)

        with pytest.raises(ValueError, match="Invalid storyline time format"):
            engine._parse_storyline_time("invalid-time")

    def test_calculate_events_for_hour_intensity_medium(self, minimal_scenario, tmp_path):
        """Should calculate appropriate event count for medium intensity."""
        engine = GenerationEngine(minimal_scenario, tmp_path)
        user = minimal_scenario.environment.users[0]

        # Run multiple times to verify randomness but reasonable range
        counts = [engine._calculate_events_for_hour(user) for _ in range(10)]

        # Medium intensity base is 15, so expect range around 10-20 with low variation
        assert all(5 <= c <= 25 for c in counts), f"Unexpected counts: {counts}"

    def test_calculate_events_for_hour_intensity_low(self, minimal_scenario, tmp_path):
        """Should calculate lower event count for low intensity."""
        minimal_scenario.baseline_activity.intensity = "low"
        engine = GenerationEngine(minimal_scenario, tmp_path)
        user = minimal_scenario.environment.users[0]

        counts = [engine._calculate_events_for_hour(user) for _ in range(10)]

        # Low intensity base is 5, expect range around 3-7 with low variation
        assert all(0 <= c <= 10 for c in counts), f"Unexpected counts: {counts}"

    def test_calculate_events_for_hour_intensity_high(self, minimal_scenario, tmp_path):
        """Should calculate higher event count for high intensity."""
        minimal_scenario.baseline_activity.intensity = "high"
        engine = GenerationEngine(minimal_scenario, tmp_path)
        user = minimal_scenario.environment.users[0]

        counts = [engine._calculate_events_for_hour(user) for _ in range(10)]

        # High intensity base is 40, expect range around 30-50 with low variation
        assert all(25 <= c <= 55 for c in counts), f"Unexpected counts: {counts}"

    def test_distribute_events_in_hour_sorted(self, minimal_scenario, tmp_path):
        """Distributed events should be sorted chronologically."""
        engine = GenerationEngine(minimal_scenario, tmp_path)
        hour_start = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)

        times = engine._distribute_events_in_hour(hour_start, 5)

        assert times == sorted(times)

    def test_distribute_events_in_hour_within_bounds(self, minimal_scenario, tmp_path):
        """Distributed events should all be within the hour."""
        engine = GenerationEngine(minimal_scenario, tmp_path)
        hour_start = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)
        hour_end = hour_start + timedelta(hours=1)

        times = engine._distribute_events_in_hour(hour_start, 10)

        assert all(hour_start <= t < hour_end for t in times)

    def test_distribute_events_in_hour_zero_events(self, minimal_scenario, tmp_path):
        """Should return empty list for zero events."""
        engine = GenerationEngine(minimal_scenario, tmp_path)
        hour_start = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)

        times = engine._distribute_events_in_hour(hour_start, 0)

        assert times == []

    @patch("evidenceforge.generation.engine.core.ActivityGenerator")
    @patch("evidenceforge.generation.engine.emitter_setup.ZeekReporterEmitter")
    @patch("evidenceforge.generation.engine.emitter_setup.ZeekPacketFilterEmitter")
    @patch("evidenceforge.generation.engine.emitter_setup.ZeekPeEmitter")
    @patch("evidenceforge.generation.engine.emitter_setup.ZeekOcspEmitter")
    @patch("evidenceforge.generation.engine.emitter_setup.ZeekX509Emitter")
    @patch("evidenceforge.generation.engine.emitter_setup.ZeekWeirdEmitter")
    @patch("evidenceforge.generation.engine.emitter_setup.ZeekNtpEmitter")
    @patch("evidenceforge.generation.engine.emitter_setup.ZeekDhcpEmitter")
    @patch("evidenceforge.generation.engine.emitter_setup.ZeekFilesEmitter")
    @patch("evidenceforge.generation.engine.emitter_setup.ZeekSslEmitter")
    @patch("evidenceforge.generation.engine.emitter_setup.ZeekHttpEmitter")
    @patch("evidenceforge.generation.engine.emitter_setup.ZeekDnsEmitter")
    @patch("evidenceforge.generation.engine.emitter_setup.ZeekEmitter")
    @patch("evidenceforge.generation.engine.emitter_setup.WindowsEventEmitter")
    @patch("evidenceforge.generation.engine.emitter_setup.SysmonEventEmitter")
    @patch("evidenceforge.generation.engine.emitter_setup.load_format")
    def test_generate_baseline_filters_enabled_users(
        self,
        mock_load_format,
        mock_sysmon,
        mock_windows,
        mock_zeek,
        mock_zeek_dns,
        mock_zeek_http,
        mock_zeek_ssl,
        mock_zeek_files,
        mock_zeek_dhcp,
        mock_zeek_ntp,
        mock_zeek_weird,
        mock_zeek_x509,
        mock_zeek_ocsp,
        mock_zeek_pe,
        mock_zeek_pf,
        mock_zeek_reporter,
        mock_activity_gen,
        minimal_scenario,
        tmp_path,
    ):
        """Baseline generation should only process enabled users."""
        # Add disabled user
        minimal_scenario.environment.users.append(
            User(
                username="disabled_user",
                full_name="Disabled User",
                email="disabled@example.com",
                enabled=False,
            )
        )

        mock_format_def = Mock()
        mock_format_def.output.file_extension = ".log"
        mock_load_format.return_value = mock_format_def

        mock_activity_instance = Mock()
        mock_activity_instance.get_baseline_pattern.return_value = []
        mock_activity_gen.side_effect = _mock_activity_generator_factory(mock_activity_instance)

        engine = GenerationEngine(minimal_scenario, tmp_path)
        engine._initialize()
        engine._generate_baseline()

        # Only 1 enabled user, so baseline pattern should be requested once per event
        # (or possibly zero times if no events generated due to randomness)
        assert mock_activity_instance.get_baseline_pattern.called

    @patch("evidenceforge.generation.engine.core.ActivityGenerator")
    @patch("evidenceforge.generation.engine.emitter_setup.ZeekReporterEmitter")
    @patch("evidenceforge.generation.engine.emitter_setup.ZeekPacketFilterEmitter")
    @patch("evidenceforge.generation.engine.emitter_setup.ZeekPeEmitter")
    @patch("evidenceforge.generation.engine.emitter_setup.ZeekOcspEmitter")
    @patch("evidenceforge.generation.engine.emitter_setup.ZeekX509Emitter")
    @patch("evidenceforge.generation.engine.emitter_setup.ZeekWeirdEmitter")
    @patch("evidenceforge.generation.engine.emitter_setup.ZeekNtpEmitter")
    @patch("evidenceforge.generation.engine.emitter_setup.ZeekDhcpEmitter")
    @patch("evidenceforge.generation.engine.emitter_setup.ZeekFilesEmitter")
    @patch("evidenceforge.generation.engine.emitter_setup.ZeekSslEmitter")
    @patch("evidenceforge.generation.engine.emitter_setup.ZeekHttpEmitter")
    @patch("evidenceforge.generation.engine.emitter_setup.ZeekDnsEmitter")
    @patch("evidenceforge.generation.engine.emitter_setup.ZeekEmitter")
    @patch("evidenceforge.generation.engine.emitter_setup.WindowsEventEmitter")
    @patch("evidenceforge.generation.engine.emitter_setup.SysmonEventEmitter")
    @patch("evidenceforge.generation.engine.emitter_setup.load_format")
    def test_generate_baseline_hour_by_hour(
        self,
        mock_load_format,
        mock_sysmon,
        mock_windows,
        mock_zeek,
        mock_zeek_dns,
        mock_zeek_http,
        mock_zeek_ssl,
        mock_zeek_files,
        mock_zeek_dhcp,
        mock_zeek_ntp,
        mock_zeek_weird,
        mock_zeek_x509,
        mock_zeek_ocsp,
        mock_zeek_pe,
        mock_zeek_pf,
        mock_zeek_reporter,
        mock_activity_gen,
        minimal_scenario,
        tmp_path,
    ):
        """Baseline generation should iterate hour-by-hour."""
        mock_format_def = Mock()
        mock_format_def.output.file_extension = ".log"
        mock_load_format.return_value = mock_format_def

        mock_activity_instance = Mock()
        mock_activity_instance.get_baseline_pattern.return_value = []
        mock_activity_gen.side_effect = _mock_activity_generator_factory(mock_activity_instance)

        engine = GenerationEngine(minimal_scenario, tmp_path)
        engine._initialize()

        # Track state manager time updates
        time_updates = []
        original_set_time = engine.state_manager.set_current_time

        def track_time(t):
            time_updates.append(t)
            original_set_time(t)

        engine.state_manager.set_current_time = track_time

        engine._generate_baseline()

        # Should have updates for each hour (2 hours in minimal_scenario)
        hour_updates = [t for t in time_updates if t.minute == 0]
        assert len(hour_updates) >= 2  # At least start of each hour

    def test_find_user_exists(self, minimal_scenario, tmp_path):
        """Should find user by username."""
        engine = GenerationEngine(minimal_scenario, tmp_path)

        user = engine._find_user("testuser")

        assert user is not None
        assert user.username == "testuser"

    def test_find_user_not_exists(self, minimal_scenario, tmp_path):
        """Should return None for non-existent user."""
        engine = GenerationEngine(minimal_scenario, tmp_path)

        user = engine._find_user("nonexistent")

        assert user is None

    def test_find_system_exists(self, minimal_scenario, tmp_path):
        """Should find system by hostname."""
        engine = GenerationEngine(minimal_scenario, tmp_path)

        system = engine._find_system("TEST-01")

        assert system is not None
        assert system.hostname == "TEST-01"

    def test_find_system_not_exists(self, minimal_scenario, tmp_path):
        """Should return None for non-existent system."""
        engine = GenerationEngine(minimal_scenario, tmp_path)

        system = engine._find_system("NONEXISTENT")

        assert system is None

    # test_match_activity_to_events_* deleted in Phase 8.4
    # Keyword matching replaced by typed event declarations in scenario YAML

    @patch("evidenceforge.generation.engine.core.GroundTruthGenerator")
    @patch("evidenceforge.generation.engine.core.ActivityGenerator")
    @patch("evidenceforge.generation.engine.emitter_setup.ZeekReporterEmitter")
    @patch("evidenceforge.generation.engine.emitter_setup.ZeekPacketFilterEmitter")
    @patch("evidenceforge.generation.engine.emitter_setup.ZeekPeEmitter")
    @patch("evidenceforge.generation.engine.emitter_setup.ZeekOcspEmitter")
    @patch("evidenceforge.generation.engine.emitter_setup.ZeekX509Emitter")
    @patch("evidenceforge.generation.engine.emitter_setup.ZeekWeirdEmitter")
    @patch("evidenceforge.generation.engine.emitter_setup.ZeekNtpEmitter")
    @patch("evidenceforge.generation.engine.emitter_setup.ZeekDhcpEmitter")
    @patch("evidenceforge.generation.engine.emitter_setup.ZeekFilesEmitter")
    @patch("evidenceforge.generation.engine.emitter_setup.ZeekSslEmitter")
    @patch("evidenceforge.generation.engine.emitter_setup.ZeekHttpEmitter")
    @patch("evidenceforge.generation.engine.emitter_setup.ZeekDnsEmitter")
    @patch("evidenceforge.generation.engine.emitter_setup.ZeekEmitter")
    @patch("evidenceforge.generation.engine.emitter_setup.WindowsEventEmitter")
    @patch("evidenceforge.generation.engine.emitter_setup.SysmonEventEmitter")
    @patch("evidenceforge.generation.engine.emitter_setup.load_format")
    def test_execute_storyline_tracks_malicious_events(
        self,
        mock_load_format,
        mock_sysmon,
        mock_windows,
        mock_zeek,
        mock_zeek_dns,
        mock_zeek_http,
        mock_zeek_ssl,
        mock_zeek_files,
        mock_zeek_dhcp,
        mock_zeek_ntp,
        mock_zeek_weird,
        mock_zeek_x509,
        mock_zeek_ocsp,
        mock_zeek_pe,
        mock_zeek_pf,
        mock_zeek_reporter,
        mock_activity_gen,
        mock_gt_gen,
        scenario_with_storyline,
        tmp_path,
    ):
        """Storyline execution should track malicious events."""
        mock_format_def = Mock()
        mock_format_def.output.file_extension = ".log"
        mock_load_format.return_value = mock_format_def

        mock_activity_instance = Mock()
        mock_activity_instance.get_baseline_pattern.return_value = []
        mock_activity_instance.generate_process.return_value = 1234
        mock_activity_instance.generate_logon.return_value = "0x12345"
        mock_activity_gen.side_effect = _mock_activity_generator_factory(mock_activity_instance)

        engine = GenerationEngine(scenario_with_storyline, tmp_path)
        engine._initialize()
        engine._execute_storyline()

        # Should have tracked malicious events
        assert len(engine.malicious_events) > 0
        assert engine.malicious_events[0]["actor"] == "attacker"
        assert engine.malicious_events[0]["system"] == "TEST-01"

    @patch("evidenceforge.generation.engine.core.GroundTruthGenerator")
    @patch("evidenceforge.generation.engine.core.ActivityGenerator")
    @patch("evidenceforge.generation.engine.emitter_setup.ZeekReporterEmitter")
    @patch("evidenceforge.generation.engine.emitter_setup.ZeekPacketFilterEmitter")
    @patch("evidenceforge.generation.engine.emitter_setup.ZeekPeEmitter")
    @patch("evidenceforge.generation.engine.emitter_setup.ZeekOcspEmitter")
    @patch("evidenceforge.generation.engine.emitter_setup.ZeekX509Emitter")
    @patch("evidenceforge.generation.engine.emitter_setup.ZeekWeirdEmitter")
    @patch("evidenceforge.generation.engine.emitter_setup.ZeekNtpEmitter")
    @patch("evidenceforge.generation.engine.emitter_setup.ZeekDhcpEmitter")
    @patch("evidenceforge.generation.engine.emitter_setup.ZeekFilesEmitter")
    @patch("evidenceforge.generation.engine.emitter_setup.ZeekSslEmitter")
    @patch("evidenceforge.generation.engine.emitter_setup.ZeekHttpEmitter")
    @patch("evidenceforge.generation.engine.emitter_setup.ZeekDnsEmitter")
    @patch("evidenceforge.generation.engine.emitter_setup.ZeekEmitter")
    @patch("evidenceforge.generation.engine.emitter_setup.WindowsEventEmitter")
    @patch("evidenceforge.generation.engine.emitter_setup.SysmonEventEmitter")
    @patch("evidenceforge.generation.engine.emitter_setup.load_format")
    def test_generate_calls_ground_truth_when_malicious_events(
        self,
        mock_load_format,
        mock_sysmon,
        mock_windows,
        mock_zeek,
        mock_zeek_dns,
        mock_zeek_http,
        mock_zeek_ssl,
        mock_zeek_files,
        mock_zeek_dhcp,
        mock_zeek_ntp,
        mock_zeek_weird,
        mock_zeek_x509,
        mock_zeek_ocsp,
        mock_zeek_pe,
        mock_zeek_pf,
        mock_zeek_reporter,
        mock_activity_gen,
        mock_gt_gen,
        scenario_with_storyline,
        tmp_path,
    ):
        """Should generate ground truth when malicious events exist."""
        mock_format_def = Mock()
        mock_format_def.output.file_extension = ".log"
        mock_load_format.return_value = mock_format_def

        mock_activity_instance = Mock()
        mock_activity_instance.get_baseline_pattern.return_value = []
        mock_activity_instance.generate_process.return_value = 1234
        mock_activity_instance.generate_logon.return_value = "0x12345"
        mock_activity_gen.side_effect = _mock_activity_generator_factory(mock_activity_instance)

        mock_gt_instance = Mock()
        mock_gt_gen.return_value = mock_gt_instance

        engine = GenerationEngine(scenario_with_storyline, tmp_path)
        engine.generate()

        # Verify ground truth generator called
        assert mock_gt_gen.called
        assert mock_gt_instance.generate.called

    @patch("evidenceforge.generation.engine.core.GroundTruthGenerator")
    @patch("evidenceforge.generation.engine.core.ActivityGenerator")
    @patch("evidenceforge.generation.engine.emitter_setup.ZeekReporterEmitter")
    @patch("evidenceforge.generation.engine.emitter_setup.ZeekPacketFilterEmitter")
    @patch("evidenceforge.generation.engine.emitter_setup.ZeekPeEmitter")
    @patch("evidenceforge.generation.engine.emitter_setup.ZeekOcspEmitter")
    @patch("evidenceforge.generation.engine.emitter_setup.ZeekX509Emitter")
    @patch("evidenceforge.generation.engine.emitter_setup.ZeekWeirdEmitter")
    @patch("evidenceforge.generation.engine.emitter_setup.ZeekNtpEmitter")
    @patch("evidenceforge.generation.engine.emitter_setup.ZeekDhcpEmitter")
    @patch("evidenceforge.generation.engine.emitter_setup.ZeekFilesEmitter")
    @patch("evidenceforge.generation.engine.emitter_setup.ZeekSslEmitter")
    @patch("evidenceforge.generation.engine.emitter_setup.ZeekHttpEmitter")
    @patch("evidenceforge.generation.engine.emitter_setup.ZeekDnsEmitter")
    @patch("evidenceforge.generation.engine.emitter_setup.ZeekEmitter")
    @patch("evidenceforge.generation.engine.emitter_setup.WindowsEventEmitter")
    @patch("evidenceforge.generation.engine.emitter_setup.SysmonEventEmitter")
    @patch("evidenceforge.generation.engine.emitter_setup.load_format")
    def test_generate_calls_ground_truth_without_malicious_events(
        self,
        mock_load_format,
        mock_sysmon,
        mock_windows,
        mock_zeek,
        mock_zeek_dns,
        mock_zeek_http,
        mock_zeek_ssl,
        mock_zeek_files,
        mock_zeek_dhcp,
        mock_zeek_ntp,
        mock_zeek_weird,
        mock_zeek_x509,
        mock_zeek_ocsp,
        mock_zeek_pe,
        mock_zeek_pf,
        mock_zeek_reporter,
        mock_activity_gen,
        mock_gt_gen,
        minimal_scenario,
        tmp_path,
    ):
        """Baseline-only scenarios should still generate the matched report set."""
        mock_format_def = Mock()
        mock_format_def.output.file_extension = ".log"
        mock_load_format.return_value = mock_format_def

        mock_activity_instance = Mock()
        mock_activity_instance.get_baseline_pattern.return_value = []
        mock_activity_gen.side_effect = _mock_activity_generator_factory(mock_activity_instance)

        mock_gt_instance = Mock()
        mock_gt_gen.return_value = mock_gt_instance

        engine = GenerationEngine(minimal_scenario, tmp_path)
        engine.generate()

        assert mock_gt_gen.called
        assert mock_gt_gen.call_args.kwargs["malicious_events"] == []
        assert mock_gt_gen.call_args.kwargs["red_herring_events"] == []
        assert mock_gt_instance.generate.called
        assert (tmp_path / OBSERVATION_MANIFEST_FILENAME).exists()
        payload = json.loads((tmp_path / OBSERVATION_MANIFEST_FILENAME).read_text(encoding="utf-8"))
        assert "source_deployment_digest" not in payload

    @patch("evidenceforge.generation.engine.core.ActivityGenerator")
    @patch("evidenceforge.generation.engine.emitter_setup.ZeekReporterEmitter")
    @patch("evidenceforge.generation.engine.emitter_setup.ZeekPacketFilterEmitter")
    @patch("evidenceforge.generation.engine.emitter_setup.ZeekPeEmitter")
    @patch("evidenceforge.generation.engine.emitter_setup.ZeekOcspEmitter")
    @patch("evidenceforge.generation.engine.emitter_setup.ZeekX509Emitter")
    @patch("evidenceforge.generation.engine.emitter_setup.ZeekWeirdEmitter")
    @patch("evidenceforge.generation.engine.emitter_setup.ZeekNtpEmitter")
    @patch("evidenceforge.generation.engine.emitter_setup.ZeekDhcpEmitter")
    @patch("evidenceforge.generation.engine.emitter_setup.ZeekFilesEmitter")
    @patch("evidenceforge.generation.engine.emitter_setup.ZeekSslEmitter")
    @patch("evidenceforge.generation.engine.emitter_setup.ZeekHttpEmitter")
    @patch("evidenceforge.generation.engine.emitter_setup.ZeekDnsEmitter")
    @patch("evidenceforge.generation.engine.emitter_setup.ZeekEmitter")
    @patch("evidenceforge.generation.engine.emitter_setup.WindowsEventEmitter")
    @patch("evidenceforge.generation.engine.emitter_setup.SysmonEventEmitter")
    @patch("evidenceforge.generation.engine.emitter_setup.load_format")
    def test_generate_baseline_only_writes_ground_truth_and_manifest(
        self,
        mock_load_format,
        mock_sysmon,
        mock_windows,
        mock_zeek,
        mock_zeek_dns,
        mock_zeek_http,
        mock_zeek_ssl,
        mock_zeek_files,
        mock_zeek_dhcp,
        mock_zeek_ntp,
        mock_zeek_weird,
        mock_zeek_x509,
        mock_zeek_ocsp,
        mock_zeek_pe,
        mock_zeek_pf,
        mock_zeek_reporter,
        mock_activity_gen,
        minimal_scenario,
        tmp_path,
    ):
        """A successful baseline-only generation writes the complete report set."""
        mock_format_def = Mock()
        mock_format_def.output.file_extension = ".log"
        mock_load_format.return_value = mock_format_def

        mock_activity_instance = Mock()
        mock_activity_instance.get_baseline_pattern.return_value = []
        mock_activity_gen.side_effect = _mock_activity_generator_factory(mock_activity_instance)

        minimal_scenario.environment.observation_overrides = [
            SourceObservationOverride(
                source_instance="windows_security:test-01",
                enabled=False,
            )
        ]

        data_dir = tmp_path / "data"
        engine = GenerationEngine(
            minimal_scenario,
            data_dir,
            ground_truth_dir=tmp_path,
        )
        engine.generate()

        ground_truth = tmp_path / "GROUND_TRUTH.md"
        manifest = tmp_path / OBSERVATION_MANIFEST_FILENAME
        collection_profile = tmp_path / COLLECTION_PROFILE_FILENAME
        target_marker = tmp_path / OUTPUT_TARGET_FILENAME
        assert ground_truth.exists()
        assert manifest.exists()
        assert collection_profile.exists()
        assert not (data_dir / COLLECTION_PROFILE_FILENAME).exists()
        assert target_marker.read_text(encoding="utf-8") == "default\n"
        assert "No malicious activities" in ground_truth.read_text()
        assert "No malicious events were generated" in ground_truth.read_text()
        profile = json.loads(collection_profile.read_text(encoding="utf-8"))
        assert "storyline_events" not in profile
        assert "red_herring_events" not in profile
        profile_text = json.dumps(profile)
        assert "stable replay" not in profile_text
        assert "storyline" not in profile_text.lower()
        assert "verdict" not in profile_text.lower()
        assert profile["output_target"] == "default"
        observation = json.loads(manifest.read_text(encoding="utf-8"))
        assert (
            observation["source_deployment_digest"] == engine.source_deployment_compilation.digest
        )
        endpoint_family = next(
            family
            for family in profile["source_families"]
            if family["family"] == "endpoint_telemetry"
        )
        assert "still active at the end remains open" in endpoint_family["tail_policy"]

    @patch("evidenceforge.generation.engine.core.ActivityGenerator")
    @patch("evidenceforge.generation.engine.emitter_setup.ZeekReporterEmitter")
    @patch("evidenceforge.generation.engine.emitter_setup.ZeekPacketFilterEmitter")
    @patch("evidenceforge.generation.engine.emitter_setup.ZeekPeEmitter")
    @patch("evidenceforge.generation.engine.emitter_setup.ZeekOcspEmitter")
    @patch("evidenceforge.generation.engine.emitter_setup.ZeekX509Emitter")
    @patch("evidenceforge.generation.engine.emitter_setup.ZeekWeirdEmitter")
    @patch("evidenceforge.generation.engine.emitter_setup.ZeekNtpEmitter")
    @patch("evidenceforge.generation.engine.emitter_setup.ZeekDhcpEmitter")
    @patch("evidenceforge.generation.engine.emitter_setup.ZeekFilesEmitter")
    @patch("evidenceforge.generation.engine.emitter_setup.ZeekSslEmitter")
    @patch("evidenceforge.generation.engine.emitter_setup.ZeekHttpEmitter")
    @patch("evidenceforge.generation.engine.emitter_setup.ZeekDnsEmitter")
    @patch("evidenceforge.generation.engine.emitter_setup.ZeekEmitter")
    @patch("evidenceforge.generation.engine.emitter_setup.WindowsEventEmitter")
    @patch("evidenceforge.generation.engine.emitter_setup.SysmonEventEmitter")
    @patch("evidenceforge.generation.engine.emitter_setup.load_format")
    def test_finalize_closes_emitters(
        self,
        mock_load_format,
        mock_sysmon,
        mock_windows,
        mock_zeek,
        mock_zeek_dns,
        mock_zeek_http,
        mock_zeek_ssl,
        mock_zeek_files,
        mock_zeek_dhcp,
        mock_zeek_ntp,
        mock_zeek_weird,
        mock_zeek_x509,
        mock_zeek_ocsp,
        mock_zeek_pe,
        mock_zeek_pf,
        mock_zeek_reporter,
        mock_activity_gen,
        minimal_scenario,
        tmp_path,
    ):
        """Finalize should close all emitters."""
        mock_format_def = Mock()
        mock_format_def.output.file_extension = ".log"
        mock_load_format.return_value = mock_format_def

        mock_windows_instance = Mock()
        mock_zeek_instance = Mock()
        mock_windows.return_value = mock_windows_instance
        mock_zeek.return_value = mock_zeek_instance

        engine = GenerationEngine(minimal_scenario, tmp_path)
        engine._initialize()
        engine._finalize()

        # Emitters are created with threaded=True, so _finalize calls close()
        assert mock_windows_instance.close.called
        assert mock_zeek_instance.close.called

    @patch("evidenceforge.generation.engine.core.ActivityGenerator")
    @patch("evidenceforge.generation.engine.emitter_setup.ZeekReporterEmitter")
    @patch("evidenceforge.generation.engine.emitter_setup.ZeekPacketFilterEmitter")
    @patch("evidenceforge.generation.engine.emitter_setup.ZeekPeEmitter")
    @patch("evidenceforge.generation.engine.emitter_setup.ZeekOcspEmitter")
    @patch("evidenceforge.generation.engine.emitter_setup.ZeekX509Emitter")
    @patch("evidenceforge.generation.engine.emitter_setup.ZeekWeirdEmitter")
    @patch("evidenceforge.generation.engine.emitter_setup.ZeekNtpEmitter")
    @patch("evidenceforge.generation.engine.emitter_setup.ZeekDhcpEmitter")
    @patch("evidenceforge.generation.engine.emitter_setup.ZeekFilesEmitter")
    @patch("evidenceforge.generation.engine.emitter_setup.ZeekSslEmitter")
    @patch("evidenceforge.generation.engine.emitter_setup.ZeekHttpEmitter")
    @patch("evidenceforge.generation.engine.emitter_setup.ZeekDnsEmitter")
    @patch("evidenceforge.generation.engine.emitter_setup.ZeekEmitter")
    @patch("evidenceforge.generation.engine.emitter_setup.WindowsEventEmitter")
    @patch("evidenceforge.generation.engine.emitter_setup.SysmonEventEmitter")
    @patch("evidenceforge.generation.engine.emitter_setup.load_format")
    def test_progress_callback_invoked(
        self,
        mock_load_format,
        mock_sysmon,
        mock_windows,
        mock_zeek,
        mock_zeek_dns,
        mock_zeek_http,
        mock_zeek_ssl,
        mock_zeek_files,
        mock_zeek_dhcp,
        mock_zeek_ntp,
        mock_zeek_weird,
        mock_zeek_x509,
        mock_zeek_ocsp,
        mock_zeek_pe,
        mock_zeek_pf,
        mock_zeek_reporter,
        mock_activity_gen,
        minimal_scenario,
        tmp_path,
    ):
        """Progress callback should be invoked during generation."""
        mock_format_def = Mock()
        mock_format_def.output.file_extension = ".log"
        mock_load_format.return_value = mock_format_def

        mock_activity_instance = Mock()
        mock_activity_instance.get_baseline_pattern.return_value = []
        mock_activity_gen.side_effect = _mock_activity_generator_factory(mock_activity_instance)

        callback = Mock()
        engine = GenerationEngine(minimal_scenario, tmp_path, progress_callback=callback)
        engine.generate()

        # Verify callback invoked for various phases
        assert callback.called

        # Check for phase_start and phase_end calls
        phase_starts = [call for call in callback.call_args_list if call[0][0] == "phase_start"]
        phase_ends = [call for call in callback.call_args_list if call[0][0] == "phase_end"]

        assert len(phase_starts) > 0
        assert len(phase_ends) > 0

    @patch("evidenceforge.generation.engine.core.ActivityGenerator")
    @patch("evidenceforge.generation.engine.emitter_setup.ZeekReporterEmitter")
    @patch("evidenceforge.generation.engine.emitter_setup.ZeekPacketFilterEmitter")
    @patch("evidenceforge.generation.engine.emitter_setup.ZeekPeEmitter")
    @patch("evidenceforge.generation.engine.emitter_setup.ZeekOcspEmitter")
    @patch("evidenceforge.generation.engine.emitter_setup.ZeekX509Emitter")
    @patch("evidenceforge.generation.engine.emitter_setup.ZeekWeirdEmitter")
    @patch("evidenceforge.generation.engine.emitter_setup.ZeekNtpEmitter")
    @patch("evidenceforge.generation.engine.emitter_setup.ZeekDhcpEmitter")
    @patch("evidenceforge.generation.engine.emitter_setup.ZeekFilesEmitter")
    @patch("evidenceforge.generation.engine.emitter_setup.ZeekSslEmitter")
    @patch("evidenceforge.generation.engine.emitter_setup.ZeekHttpEmitter")
    @patch("evidenceforge.generation.engine.emitter_setup.ZeekDnsEmitter")
    @patch("evidenceforge.generation.engine.emitter_setup.ZeekEmitter")
    @patch("evidenceforge.generation.engine.emitter_setup.WindowsEventEmitter")
    @patch("evidenceforge.generation.engine.emitter_setup.SysmonEventEmitter")
    @patch("evidenceforge.generation.engine.emitter_setup.load_format")
    def test_progress_callback_not_required(
        self,
        mock_load_format,
        mock_sysmon,
        mock_windows,
        mock_zeek,
        mock_zeek_dns,
        mock_zeek_http,
        mock_zeek_ssl,
        mock_zeek_files,
        mock_zeek_dhcp,
        mock_zeek_ntp,
        mock_zeek_weird,
        mock_zeek_x509,
        mock_zeek_ocsp,
        mock_zeek_pe,
        mock_zeek_pf,
        mock_zeek_reporter,
        mock_activity_gen,
        minimal_scenario,
        tmp_path,
    ):
        """Generation should work without progress callback."""
        mock_format_def = Mock()
        mock_format_def.output.file_extension = ".log"
        mock_load_format.return_value = mock_format_def

        mock_activity_instance = Mock()
        mock_activity_instance.get_baseline_pattern.return_value = []
        mock_activity_gen.side_effect = _mock_activity_generator_factory(mock_activity_instance)

        # No progress_callback provided
        engine = GenerationEngine(minimal_scenario, tmp_path)

        # Should not raise exception
        engine.generate()

    @patch("evidenceforge.generation.engine.core.ActivityGenerator")
    @patch("evidenceforge.generation.engine.emitter_setup.ZeekReporterEmitter")
    @patch("evidenceforge.generation.engine.emitter_setup.ZeekPacketFilterEmitter")
    @patch("evidenceforge.generation.engine.emitter_setup.ZeekPeEmitter")
    @patch("evidenceforge.generation.engine.emitter_setup.ZeekOcspEmitter")
    @patch("evidenceforge.generation.engine.emitter_setup.ZeekX509Emitter")
    @patch("evidenceforge.generation.engine.emitter_setup.ZeekWeirdEmitter")
    @patch("evidenceforge.generation.engine.emitter_setup.ZeekNtpEmitter")
    @patch("evidenceforge.generation.engine.emitter_setup.ZeekDhcpEmitter")
    @patch("evidenceforge.generation.engine.emitter_setup.ZeekFilesEmitter")
    @patch("evidenceforge.generation.engine.emitter_setup.ZeekSslEmitter")
    @patch("evidenceforge.generation.engine.emitter_setup.ZeekHttpEmitter")
    @patch("evidenceforge.generation.engine.emitter_setup.ZeekDnsEmitter")
    @patch("evidenceforge.generation.engine.emitter_setup.ZeekEmitter")
    @patch("evidenceforge.generation.engine.emitter_setup.WindowsEventEmitter")
    @patch("evidenceforge.generation.engine.emitter_setup.SysmonEventEmitter")
    @patch("evidenceforge.generation.engine.emitter_setup.load_format")
    def test_execute_storyline_event_logon_type(
        self,
        mock_load_format,
        mock_sysmon,
        mock_windows,
        mock_zeek,
        mock_zeek_dns,
        mock_zeek_http,
        mock_zeek_ssl,
        mock_zeek_files,
        mock_zeek_dhcp,
        mock_zeek_ntp,
        mock_zeek_weird,
        mock_zeek_x509,
        mock_zeek_ocsp,
        mock_zeek_pe,
        mock_zeek_pf,
        mock_zeek_reporter,
        mock_activity_gen,
        scenario_with_storyline,
        tmp_path,
    ):
        """Storyline logon events should use network logon type."""
        mock_format_def = Mock()
        mock_format_def.output.file_extension = ".log"
        mock_load_format.return_value = mock_format_def

        mock_activity_instance = Mock()
        mock_activity_instance.generate_logon.return_value = "0x12345"
        mock_activity_gen.side_effect = _mock_activity_generator_factory(mock_activity_instance)

        engine = GenerationEngine(scenario_with_storyline, tmp_path)
        engine._initialize()

        # Modify storyline to have logon event
        engine.scenario.storyline[0].activity = "User attempts to log in"

        engine._execute_storyline()

        # Verify generate_logon called (planner chooses appropriate logon type)
        assert mock_activity_instance.generate_logon.called
        call_args = mock_activity_instance.generate_logon.call_args
        # logon_type depends on user/host relationship:
        # type 2 = interactive (own workstation), type 3 = network, type 10 = remote
        assert call_args[1]["logon_type"] in (2, 3, 10)

    @patch("evidenceforge.generation.engine.core.ActivityGenerator")
    @patch("evidenceforge.generation.engine.emitter_setup.ZeekReporterEmitter")
    @patch("evidenceforge.generation.engine.emitter_setup.ZeekPacketFilterEmitter")
    @patch("evidenceforge.generation.engine.emitter_setup.ZeekPeEmitter")
    @patch("evidenceforge.generation.engine.emitter_setup.ZeekOcspEmitter")
    @patch("evidenceforge.generation.engine.emitter_setup.ZeekX509Emitter")
    @patch("evidenceforge.generation.engine.emitter_setup.ZeekWeirdEmitter")
    @patch("evidenceforge.generation.engine.emitter_setup.ZeekNtpEmitter")
    @patch("evidenceforge.generation.engine.emitter_setup.ZeekDhcpEmitter")
    @patch("evidenceforge.generation.engine.emitter_setup.ZeekFilesEmitter")
    @patch("evidenceforge.generation.engine.emitter_setup.ZeekSslEmitter")
    @patch("evidenceforge.generation.engine.emitter_setup.ZeekHttpEmitter")
    @patch("evidenceforge.generation.engine.emitter_setup.ZeekDnsEmitter")
    @patch("evidenceforge.generation.engine.emitter_setup.ZeekEmitter")
    @patch("evidenceforge.generation.engine.emitter_setup.WindowsEventEmitter")
    @patch("evidenceforge.generation.engine.emitter_setup.SysmonEventEmitter")
    @patch("evidenceforge.generation.engine.emitter_setup.load_format")
    def test_execute_storyline_event_connection_validation(
        self,
        mock_load_format,
        mock_sysmon,
        mock_windows,
        mock_zeek,
        mock_zeek_dns,
        mock_zeek_http,
        mock_zeek_ssl,
        mock_zeek_files,
        mock_zeek_dhcp,
        mock_zeek_ntp,
        mock_zeek_weird,
        mock_zeek_x509,
        mock_zeek_ocsp,
        mock_zeek_pe,
        mock_zeek_pf,
        mock_zeek_reporter,
        mock_activity_gen,
        scenario_with_storyline,
        tmp_path,
    ):
        """Storyline connections should validate dst_ip != src_ip."""
        mock_format_def = Mock()
        mock_format_def.output.file_extension = ".log"
        mock_load_format.return_value = mock_format_def

        mock_activity_instance = Mock()
        mock_activity_instance.generate_connection.return_value = "UID123"
        mock_activity_instance.generate_logon.return_value = "0x12345"
        mock_activity_gen.side_effect = _mock_activity_generator_factory(mock_activity_instance)

        engine = GenerationEngine(scenario_with_storyline, tmp_path)
        engine._initialize()

        # Modify storyline to have connection event
        engine.scenario.storyline[0].activity = "Connect to external server"
        engine.scenario.storyline[0].events = [
            ConnectionEventSpec(
                dst_ip="159.65.43.201",
                dst_port=443,
                hostname="cdn-assets-update.com",
            )
        ]

        engine._execute_storyline()

        # Phase 8.4: engine uses dst_ip from the typed EventSpec directly
        assert mock_activity_instance.generate_connection.called
        call_args = mock_activity_instance.generate_connection.call_args
        assert call_args[1]["dst_ip"] == "159.65.43.201"
        assert call_args[1]["hostname"] == "cdn-assets-update.com"
        assert call_args[1]["preserve_dst_ip"] is True

    @patch("evidenceforge.generation.engine.core.ActivityGenerator")
    @patch("evidenceforge.generation.engine.emitter_setup.ZeekReporterEmitter")
    @patch("evidenceforge.generation.engine.emitter_setup.ZeekPacketFilterEmitter")
    @patch("evidenceforge.generation.engine.emitter_setup.ZeekPeEmitter")
    @patch("evidenceforge.generation.engine.emitter_setup.ZeekOcspEmitter")
    @patch("evidenceforge.generation.engine.emitter_setup.ZeekX509Emitter")
    @patch("evidenceforge.generation.engine.emitter_setup.ZeekWeirdEmitter")
    @patch("evidenceforge.generation.engine.emitter_setup.ZeekNtpEmitter")
    @patch("evidenceforge.generation.engine.emitter_setup.ZeekDhcpEmitter")
    @patch("evidenceforge.generation.engine.emitter_setup.ZeekFilesEmitter")
    @patch("evidenceforge.generation.engine.emitter_setup.ZeekSslEmitter")
    @patch("evidenceforge.generation.engine.emitter_setup.ZeekHttpEmitter")
    @patch("evidenceforge.generation.engine.emitter_setup.ZeekDnsEmitter")
    @patch("evidenceforge.generation.engine.emitter_setup.ZeekEmitter")
    @patch("evidenceforge.generation.engine.emitter_setup.WindowsEventEmitter")
    @patch("evidenceforge.generation.engine.emitter_setup.SysmonEventEmitter")
    @patch("evidenceforge.generation.engine.emitter_setup.load_format")
    def test_generate_user_activity_uses_primary_system(
        self,
        mock_load_format,
        mock_sysmon,
        mock_windows,
        mock_zeek,
        mock_zeek_dns,
        mock_zeek_http,
        mock_zeek_ssl,
        mock_zeek_files,
        mock_zeek_dhcp,
        mock_zeek_ntp,
        mock_zeek_weird,
        mock_zeek_x509,
        mock_zeek_ocsp,
        mock_zeek_pe,
        mock_zeek_pf,
        mock_zeek_reporter,
        mock_activity_gen,
        minimal_scenario,
        tmp_path,
    ):
        """User activity should prefer primary_system if set."""
        mock_format_def = Mock()
        mock_format_def.output.file_extension = ".log"
        mock_load_format.return_value = mock_format_def

        mock_activity_instance = Mock()
        mock_activity_instance.get_baseline_pattern.return_value = [("logon", 1.0)]
        mock_activity_instance.execute_baseline_activity.return_value = None
        mock_activity_gen.side_effect = _mock_activity_generator_factory(mock_activity_instance)

        engine = GenerationEngine(minimal_scenario, tmp_path)
        engine._initialize()

        user = minimal_scenario.environment.users[0]
        event_time = datetime(2024, 1, 15, 10, 30, 0, tzinfo=UTC)

        # Try multiple times to account for 15% idle period randomization
        for attempt_time in [
            event_time,
            event_time + timedelta(minutes=1),
            event_time + timedelta(minutes=2),
        ]:
            mock_activity_instance.reset_mock()
            engine._generate_user_activity(user, attempt_time)
            if mock_activity_instance.execute_baseline_activity.called:
                break

        # Verify executed on primary system (at least one attempt should succeed)
        assert mock_activity_instance.execute_baseline_activity.called
        call_args = mock_activity_instance.execute_baseline_activity.call_args
        assert call_args[1]["system"].hostname == "TEST-01"

    @patch("evidenceforge.generation.engine.core.ActivityGenerator")
    @patch("evidenceforge.generation.engine.emitter_setup.ZeekReporterEmitter")
    @patch("evidenceforge.generation.engine.emitter_setup.ZeekPacketFilterEmitter")
    @patch("evidenceforge.generation.engine.emitter_setup.ZeekPeEmitter")
    @patch("evidenceforge.generation.engine.emitter_setup.ZeekOcspEmitter")
    @patch("evidenceforge.generation.engine.emitter_setup.ZeekX509Emitter")
    @patch("evidenceforge.generation.engine.emitter_setup.ZeekWeirdEmitter")
    @patch("evidenceforge.generation.engine.emitter_setup.ZeekNtpEmitter")
    @patch("evidenceforge.generation.engine.emitter_setup.ZeekDhcpEmitter")
    @patch("evidenceforge.generation.engine.emitter_setup.ZeekFilesEmitter")
    @patch("evidenceforge.generation.engine.emitter_setup.ZeekSslEmitter")
    @patch("evidenceforge.generation.engine.emitter_setup.ZeekHttpEmitter")
    @patch("evidenceforge.generation.engine.emitter_setup.ZeekDnsEmitter")
    @patch("evidenceforge.generation.engine.emitter_setup.ZeekEmitter")
    @patch("evidenceforge.generation.engine.emitter_setup.WindowsEventEmitter")
    @patch("evidenceforge.generation.engine.emitter_setup.SysmonEventEmitter")
    @patch("evidenceforge.generation.engine.emitter_setup.load_format")
    def test_execute_storyline_skips_missing_actor(
        self,
        mock_load_format,
        mock_sysmon,
        mock_windows,
        mock_zeek,
        mock_zeek_dns,
        mock_zeek_http,
        mock_zeek_ssl,
        mock_zeek_files,
        mock_zeek_dhcp,
        mock_zeek_ntp,
        mock_zeek_weird,
        mock_zeek_x509,
        mock_zeek_ocsp,
        mock_zeek_pe,
        mock_zeek_pf,
        mock_zeek_reporter,
        mock_activity_gen,
        scenario_with_storyline,
        tmp_path,
    ):
        """Storyline should skip events with missing actor."""
        mock_format_def = Mock()
        mock_format_def.output.file_extension = ".log"
        mock_load_format.return_value = mock_format_def

        mock_activity_instance = Mock()
        mock_activity_gen.side_effect = _mock_activity_generator_factory(mock_activity_instance)

        engine = GenerationEngine(scenario_with_storyline, tmp_path)
        engine._initialize()

        # Set invalid actor
        engine.scenario.storyline[0].actor = "nonexistent_user"

        engine._execute_storyline()

        # Should not track any malicious events
        assert len(engine.malicious_events) == 0
