"""Unit tests for generation engine."""

import pytest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import Mock, patch, call, MagicMock

from evidenceforge.generation.engine import GenerationEngine
from evidenceforge.models import (
    Scenario, Environment, User, System, TimeWindow,
    BaselineActivity, OutputSpec, StorylineEvent
)


class TestGenerationEngine:
    """Tests for GenerationEngine class."""

    @pytest.fixture(autouse=True)
    def mock_new_emitters(self):
        """Mock the 5 emitter classes added in Phase 2.2.

        Tests were written for Phase 1 (2 emitters). The engine now creates
        7 emitters. This fixture mocks the 5 new ones so existing tests
        that only patch WindowsEventEmitter and ZeekEmitter still work.
        """
        with patch('evidenceforge.generation.engine.EcarEmitter') as m1, \
             patch('evidenceforge.generation.engine.SyslogEmitter') as m2, \
             patch('evidenceforge.generation.engine.BashHistoryEmitter') as m3, \
             patch('evidenceforge.generation.engine.SnortEmitter') as m4, \
             patch('evidenceforge.generation.engine.WebEmitter') as m5:
            yield m1, m2, m3, m4, m5

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
                        primary_system="TEST-01"
                    )
                ],
                systems=[
                    System(
                        hostname="TEST-01",
                        ip="10.0.0.1",
                        os="Windows 10",
                        type="workstation"
                    )
                ]
            ),
            time_window=TimeWindow(
                start="2024-01-15T10:00:00Z",
                duration="2h"
            ),
            baseline_activity=BaselineActivity(
                description="Test baseline",
                intensity="medium",
                variation="low"
            ),
            output=OutputSpec(
                logs=[
                    {"format": "windows_event_security"},
                    {"format": "zeek_conn"}
                ],
                destination="./output",
                compression=False
            ),
            personas=[]
        )

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
                        primary_system="TEST-01"
                    ),
                    User(
                        username="attacker",
                        full_name="Attacker",
                        email="attacker@evil.com",
                        enabled=True
                    )
                ],
                systems=[
                    System(
                        hostname="TEST-01",
                        ip="10.0.0.1",
                        os="Windows 10",
                        type="workstation"
                    )
                ]
            ),
            time_window=TimeWindow(
                start="2024-01-15T10:00:00Z",
                duration="2h"
            ),
            baseline_activity=BaselineActivity(
                description="Test baseline",
                intensity="low",
                variation="low"
            ),
            output=OutputSpec(
                logs=[
                    {"format": "windows_event_security"},
                    {"format": "zeek_conn"}
                ],
                destination="./output",
                compression=False
            ),
            personas=[],
            storyline=[
                StorylineEvent(
                    time="2024-01-15T10:30:00Z",
                    actor="attacker",
                    system="TEST-01",
                    activity="Execute malicious PowerShell command",
                    details={"process_name": "powershell.exe"}
                )
            ]
        )

    @patch('evidenceforge.generation.engine.ActivityGenerator')
    @patch('evidenceforge.generation.engine.ZeekEmitter')
    @patch('evidenceforge.generation.engine.WindowsEventEmitter')
    @patch('evidenceforge.generation.engine.load_format')
    def test_initialize_creates_emitters(
        self, mock_load_format, mock_windows, mock_zeek, mock_activity_gen,
        minimal_scenario, tmp_path
    ):
        """Engine initialization should create emitters for each format."""
        # Mock format definitions
        mock_format_def = Mock()
        mock_format_def.output.file_extension = ".log"
        mock_load_format.return_value = mock_format_def

        engine = GenerationEngine(minimal_scenario, tmp_path)
        engine._initialize()

        # Verify emitters created (7 total: 2 Phase 1 + 5 Phase 2.2)
        assert mock_windows.called
        assert mock_zeek.called
        assert len(engine.emitters) == 7
        assert 'windows_event_security' in engine.emitters
        assert 'zeek_conn' in engine.emitters

    @patch('evidenceforge.generation.engine.ActivityGenerator')
    @patch('evidenceforge.generation.engine.ZeekEmitter')
    @patch('evidenceforge.generation.engine.WindowsEventEmitter')
    @patch('evidenceforge.generation.engine.load_format')
    def test_initialize_resolves_time_window(
        self, mock_load_format, mock_windows, mock_zeek, mock_activity_gen,
        minimal_scenario, tmp_path
    ):
        """Engine should correctly resolve time window from duration."""
        mock_format_def = Mock()
        mock_format_def.output.file_extension = ".log"
        mock_load_format.return_value = mock_format_def

        engine = GenerationEngine(minimal_scenario, tmp_path)
        engine._initialize()

        # Verify time window calculated correctly
        assert engine.start_time == datetime(2024, 1, 15, 10, 0, 0, tzinfo=timezone.utc)
        assert engine.end_time == datetime(2024, 1, 15, 12, 0, 0, tzinfo=timezone.utc)

    @patch('evidenceforge.generation.engine.ActivityGenerator')
    @patch('evidenceforge.generation.engine.ZeekEmitter')
    @patch('evidenceforge.generation.engine.WindowsEventEmitter')
    @patch('evidenceforge.generation.engine.load_format')
    def test_initialize_creates_output_directory(
        self, mock_load_format, mock_windows, mock_zeek, mock_activity_gen,
        minimal_scenario, tmp_path
    ):
        """Engine should create output directory if it doesn't exist."""
        mock_format_def = Mock()
        mock_format_def.output.file_extension = ".log"
        mock_load_format.return_value = mock_format_def

        output_dir = tmp_path / "nonexistent"
        engine = GenerationEngine(minimal_scenario, output_dir)
        engine._initialize()

        assert output_dir.exists()

    @patch('evidenceforge.generation.engine.ActivityGenerator')
    @patch('evidenceforge.generation.engine.ZeekEmitter')
    @patch('evidenceforge.generation.engine.WindowsEventEmitter')
    @patch('evidenceforge.generation.engine.load_format')
    def test_initialize_sets_state_manager_time(
        self, mock_load_format, mock_windows, mock_zeek, mock_activity_gen,
        minimal_scenario, tmp_path
    ):
        """Engine should set StateManager initial time to scenario start."""
        mock_format_def = Mock()
        mock_format_def.output.file_extension = ".log"
        mock_load_format.return_value = mock_format_def

        engine = GenerationEngine(minimal_scenario, tmp_path)
        engine._initialize()

        # Verify state manager time set
        assert engine.state_manager.get_current_time() == engine.start_time

    def test_parse_storyline_time_iso8601(self, minimal_scenario, tmp_path):
        """Should parse ISO 8601 absolute time strings."""
        engine = GenerationEngine(minimal_scenario, tmp_path)
        engine.start_time = datetime(2024, 1, 15, 10, 0, 0, tzinfo=timezone.utc)

        result = engine._parse_storyline_time("2024-01-15T10:30:00Z")

        assert result == datetime(2024, 1, 15, 10, 30, 0, tzinfo=timezone.utc)

    def test_parse_storyline_time_relative_duration(self, minimal_scenario, tmp_path):
        """Should parse relative duration strings like '+2h30m'."""
        engine = GenerationEngine(minimal_scenario, tmp_path)
        engine.start_time = datetime(2024, 1, 15, 10, 0, 0, tzinfo=timezone.utc)

        result = engine._parse_storyline_time("+2h30m")

        assert result == datetime(2024, 1, 15, 12, 30, 0, tzinfo=timezone.utc)

    def test_parse_storyline_time_relative_seconds(self, minimal_scenario, tmp_path):
        """Should parse relative seconds like '+7200'."""
        engine = GenerationEngine(minimal_scenario, tmp_path)
        engine.start_time = datetime(2024, 1, 15, 10, 0, 0, tzinfo=timezone.utc)

        result = engine._parse_storyline_time("+7200")

        assert result == datetime(2024, 1, 15, 12, 0, 0, tzinfo=timezone.utc)

    def test_parse_storyline_time_invalid_format(self, minimal_scenario, tmp_path):
        """Should raise ValueError for invalid time format."""
        engine = GenerationEngine(minimal_scenario, tmp_path)
        engine.start_time = datetime(2024, 1, 15, 10, 0, 0, tzinfo=timezone.utc)

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
        hour_start = datetime(2024, 1, 15, 10, 0, 0, tzinfo=timezone.utc)

        times = engine._distribute_events_in_hour(hour_start, 5)

        assert times == sorted(times)

    def test_distribute_events_in_hour_within_bounds(self, minimal_scenario, tmp_path):
        """Distributed events should all be within the hour."""
        engine = GenerationEngine(minimal_scenario, tmp_path)
        hour_start = datetime(2024, 1, 15, 10, 0, 0, tzinfo=timezone.utc)
        hour_end = hour_start + timedelta(hours=1)

        times = engine._distribute_events_in_hour(hour_start, 10)

        assert all(hour_start <= t < hour_end for t in times)

    def test_distribute_events_in_hour_zero_events(self, minimal_scenario, tmp_path):
        """Should return empty list for zero events."""
        engine = GenerationEngine(minimal_scenario, tmp_path)
        hour_start = datetime(2024, 1, 15, 10, 0, 0, tzinfo=timezone.utc)

        times = engine._distribute_events_in_hour(hour_start, 0)

        assert times == []

    @patch('evidenceforge.generation.engine.ActivityGenerator')
    @patch('evidenceforge.generation.engine.ZeekEmitter')
    @patch('evidenceforge.generation.engine.WindowsEventEmitter')
    @patch('evidenceforge.generation.engine.load_format')
    def test_generate_baseline_filters_enabled_users(
        self, mock_load_format, mock_windows, mock_zeek, mock_activity_gen,
        minimal_scenario, tmp_path
    ):
        """Baseline generation should only process enabled users."""
        # Add disabled user
        minimal_scenario.environment.users.append(
            User(
                username="disabled_user",
                full_name="Disabled User",
                email="disabled@example.com",
                enabled=False
            )
        )

        mock_format_def = Mock()
        mock_format_def.output.file_extension = ".log"
        mock_load_format.return_value = mock_format_def

        mock_activity_instance = Mock()
        mock_activity_instance.get_baseline_pattern.return_value = []
        mock_activity_gen.return_value = mock_activity_instance

        engine = GenerationEngine(minimal_scenario, tmp_path)
        engine._initialize()
        engine._generate_baseline()

        # Only 1 enabled user, so baseline pattern should be requested once per event
        # (or possibly zero times if no events generated due to randomness)
        assert mock_activity_instance.get_baseline_pattern.called

    @patch('evidenceforge.generation.engine.ActivityGenerator')
    @patch('evidenceforge.generation.engine.ZeekEmitter')
    @patch('evidenceforge.generation.engine.WindowsEventEmitter')
    @patch('evidenceforge.generation.engine.load_format')
    def test_generate_baseline_hour_by_hour(
        self, mock_load_format, mock_windows, mock_zeek, mock_activity_gen,
        minimal_scenario, tmp_path
    ):
        """Baseline generation should iterate hour-by-hour."""
        mock_format_def = Mock()
        mock_format_def.output.file_extension = ".log"
        mock_load_format.return_value = mock_format_def

        mock_activity_instance = Mock()
        mock_activity_instance.get_baseline_pattern.return_value = []
        mock_activity_gen.return_value = mock_activity_instance

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

    def test_match_activity_to_events_logon(self, minimal_scenario, tmp_path):
        """Should match logon keywords to logon event type."""
        engine = GenerationEngine(minimal_scenario, tmp_path)

        events = engine._match_activity_to_events("User attempts to log in to the system")

        assert 'logon' in events

    def test_match_activity_to_events_process(self, minimal_scenario, tmp_path):
        """Should match process keywords to process event type."""
        engine = GenerationEngine(minimal_scenario, tmp_path)

        events = engine._match_activity_to_events("Execute PowerShell command")

        assert 'process' in events

    def test_match_activity_to_events_connection(self, minimal_scenario, tmp_path):
        """Should match connection keywords to connection event type."""
        engine = GenerationEngine(minimal_scenario, tmp_path)

        events = engine._match_activity_to_events("Connect to C2 server")

        assert 'connection' in events

    def test_match_activity_to_events_default(self, minimal_scenario, tmp_path):
        """Should default to process if no match."""
        engine = GenerationEngine(minimal_scenario, tmp_path)

        events = engine._match_activity_to_events("Some unrecognized activity")

        assert events == ['process']

    @patch('evidenceforge.generation.engine.GroundTruthGenerator')
    @patch('evidenceforge.generation.engine.ActivityGenerator')
    @patch('evidenceforge.generation.engine.ZeekEmitter')
    @patch('evidenceforge.generation.engine.WindowsEventEmitter')
    @patch('evidenceforge.generation.engine.load_format')
    def test_execute_storyline_tracks_malicious_events(
        self, mock_load_format, mock_windows, mock_zeek,
        mock_activity_gen, mock_gt_gen, scenario_with_storyline, tmp_path
    ):
        """Storyline execution should track malicious events."""
        mock_format_def = Mock()
        mock_format_def.output.file_extension = ".log"
        mock_load_format.return_value = mock_format_def

        mock_activity_instance = Mock()
        mock_activity_instance.get_baseline_pattern.return_value = []
        mock_activity_instance.generate_process.return_value = 1234
        mock_activity_instance.generate_logon.return_value = "0x12345"
        mock_activity_gen.return_value = mock_activity_instance

        engine = GenerationEngine(scenario_with_storyline, tmp_path)
        engine._initialize()
        engine._execute_storyline()

        # Should have tracked malicious events
        assert len(engine.malicious_events) > 0
        assert engine.malicious_events[0]['actor'] == 'attacker'
        assert engine.malicious_events[0]['system'] == 'TEST-01'

    @patch('evidenceforge.generation.engine.GroundTruthGenerator')
    @patch('evidenceforge.generation.engine.ActivityGenerator')
    @patch('evidenceforge.generation.engine.ZeekEmitter')
    @patch('evidenceforge.generation.engine.WindowsEventEmitter')
    @patch('evidenceforge.generation.engine.load_format')
    def test_generate_calls_ground_truth_when_malicious_events(
        self, mock_load_format, mock_windows, mock_zeek,
        mock_activity_gen, mock_gt_gen, scenario_with_storyline, tmp_path
    ):
        """Should generate ground truth when malicious events exist."""
        mock_format_def = Mock()
        mock_format_def.output.file_extension = ".log"
        mock_load_format.return_value = mock_format_def

        mock_activity_instance = Mock()
        mock_activity_instance.get_baseline_pattern.return_value = []
        mock_activity_instance.generate_process.return_value = 1234
        mock_activity_instance.generate_logon.return_value = "0x12345"
        mock_activity_gen.return_value = mock_activity_instance

        mock_gt_instance = Mock()
        mock_gt_gen.return_value = mock_gt_instance

        engine = GenerationEngine(scenario_with_storyline, tmp_path)
        engine.generate()

        # Verify ground truth generator called
        assert mock_gt_gen.called
        assert mock_gt_instance.generate.called

    @patch('evidenceforge.generation.engine.GroundTruthGenerator')
    @patch('evidenceforge.generation.engine.ActivityGenerator')
    @patch('evidenceforge.generation.engine.ZeekEmitter')
    @patch('evidenceforge.generation.engine.WindowsEventEmitter')
    @patch('evidenceforge.generation.engine.load_format')
    def test_generate_skips_ground_truth_without_malicious_events(
        self, mock_load_format, mock_windows, mock_zeek,
        mock_activity_gen, mock_gt_gen, minimal_scenario, tmp_path
    ):
        """Should NOT generate ground truth for baseline-only scenarios."""
        mock_format_def = Mock()
        mock_format_def.output.file_extension = ".log"
        mock_load_format.return_value = mock_format_def

        mock_activity_instance = Mock()
        mock_activity_instance.get_baseline_pattern.return_value = []
        mock_activity_gen.return_value = mock_activity_instance

        engine = GenerationEngine(minimal_scenario, tmp_path)
        engine.generate()

        # Ground truth generator should NOT be called
        assert not mock_gt_gen.called

    @patch('evidenceforge.generation.engine.ActivityGenerator')
    @patch('evidenceforge.generation.engine.ZeekEmitter')
    @patch('evidenceforge.generation.engine.WindowsEventEmitter')
    @patch('evidenceforge.generation.engine.load_format')
    def test_finalize_closes_emitters(
        self, mock_load_format, mock_windows, mock_zeek, mock_activity_gen,
        minimal_scenario, tmp_path
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

        # Emitters are created with threaded=True, so _finalize calls stop_thread()
        assert mock_windows_instance.stop_thread.called
        assert mock_zeek_instance.stop_thread.called

    @patch('evidenceforge.generation.engine.ActivityGenerator')
    @patch('evidenceforge.generation.engine.ZeekEmitter')
    @patch('evidenceforge.generation.engine.WindowsEventEmitter')
    @patch('evidenceforge.generation.engine.load_format')
    def test_progress_callback_invoked(
        self, mock_load_format, mock_windows, mock_zeek, mock_activity_gen,
        minimal_scenario, tmp_path
    ):
        """Progress callback should be invoked during generation."""
        mock_format_def = Mock()
        mock_format_def.output.file_extension = ".log"
        mock_load_format.return_value = mock_format_def

        mock_activity_instance = Mock()
        mock_activity_instance.get_baseline_pattern.return_value = []
        mock_activity_gen.return_value = mock_activity_instance

        callback = Mock()
        engine = GenerationEngine(minimal_scenario, tmp_path, progress_callback=callback)
        engine.generate()

        # Verify callback invoked for various phases
        assert callback.called

        # Check for phase_start and phase_end calls
        phase_starts = [call for call in callback.call_args_list
                       if call[0][0] == "phase_start"]
        phase_ends = [call for call in callback.call_args_list
                     if call[0][0] == "phase_end"]

        assert len(phase_starts) > 0
        assert len(phase_ends) > 0

    @patch('evidenceforge.generation.engine.ActivityGenerator')
    @patch('evidenceforge.generation.engine.ZeekEmitter')
    @patch('evidenceforge.generation.engine.WindowsEventEmitter')
    @patch('evidenceforge.generation.engine.load_format')
    def test_progress_callback_not_required(
        self, mock_load_format, mock_windows, mock_zeek, mock_activity_gen,
        minimal_scenario, tmp_path
    ):
        """Generation should work without progress callback."""
        mock_format_def = Mock()
        mock_format_def.output.file_extension = ".log"
        mock_load_format.return_value = mock_format_def

        mock_activity_instance = Mock()
        mock_activity_instance.get_baseline_pattern.return_value = []
        mock_activity_gen.return_value = mock_activity_instance

        # No progress_callback provided
        engine = GenerationEngine(minimal_scenario, tmp_path)

        # Should not raise exception
        engine.generate()

    def test_get_next_event_record_id_increments(self, minimal_scenario, tmp_path):
        """Event record IDs should increment sequentially."""
        engine = GenerationEngine(minimal_scenario, tmp_path)

        id1 = engine._get_next_event_record_id()
        id2 = engine._get_next_event_record_id()
        id3 = engine._get_next_event_record_id()

        assert id2 == id1 + 1
        assert id3 == id2 + 1

    @patch('evidenceforge.generation.engine.ActivityGenerator')
    @patch('evidenceforge.generation.engine.ZeekEmitter')
    @patch('evidenceforge.generation.engine.WindowsEventEmitter')
    @patch('evidenceforge.generation.engine.load_format')
    def test_execute_storyline_event_logon_type(
        self, mock_load_format, mock_windows, mock_zeek, mock_activity_gen,
        scenario_with_storyline, tmp_path
    ):
        """Storyline logon events should use network logon type."""
        mock_format_def = Mock()
        mock_format_def.output.file_extension = ".log"
        mock_load_format.return_value = mock_format_def

        mock_activity_instance = Mock()
        mock_activity_instance.generate_logon.return_value = "0x12345"
        mock_activity_gen.return_value = mock_activity_instance

        engine = GenerationEngine(scenario_with_storyline, tmp_path)
        engine._initialize()

        # Modify storyline to have logon event
        engine.scenario.storyline[0].activity = "User attempts to log in"

        engine._execute_storyline()

        # Verify generate_logon called with logon_type=3 (network)
        assert mock_activity_instance.generate_logon.called
        call_args = mock_activity_instance.generate_logon.call_args
        assert call_args[1]['logon_type'] == 3

    @patch('evidenceforge.generation.engine.ActivityGenerator')
    @patch('evidenceforge.generation.engine.ZeekEmitter')
    @patch('evidenceforge.generation.engine.WindowsEventEmitter')
    @patch('evidenceforge.generation.engine.load_format')
    def test_execute_storyline_event_connection_validation(
        self, mock_load_format, mock_windows, mock_zeek, mock_activity_gen,
        scenario_with_storyline, tmp_path
    ):
        """Storyline connections should validate dst_ip != src_ip."""
        mock_format_def = Mock()
        mock_format_def.output.file_extension = ".log"
        mock_load_format.return_value = mock_format_def

        mock_activity_instance = Mock()
        mock_activity_instance.generate_connection.return_value = "UID123"
        mock_activity_instance.generate_logon.return_value = "0x12345"
        mock_activity_gen.return_value = mock_activity_instance

        engine = GenerationEngine(scenario_with_storyline, tmp_path)
        engine._initialize()

        # Modify storyline to have connection with same IP
        engine.scenario.storyline[0].activity = "Connect to external server"
        engine.scenario.storyline[0].details = {"dst_ip": "10.0.0.1"}  # Same as system IP

        engine._execute_storyline()

        # Should adjust to external IP (198.51.100.10)
        assert mock_activity_instance.generate_connection.called
        call_args = mock_activity_instance.generate_connection.call_args
        assert call_args[1]['dst_ip'] == "198.51.100.10"

    @patch('evidenceforge.generation.engine.ActivityGenerator')
    @patch('evidenceforge.generation.engine.ZeekEmitter')
    @patch('evidenceforge.generation.engine.WindowsEventEmitter')
    @patch('evidenceforge.generation.engine.load_format')
    def test_generate_user_activity_uses_primary_system(
        self, mock_load_format, mock_windows, mock_zeek, mock_activity_gen,
        minimal_scenario, tmp_path
    ):
        """User activity should prefer primary_system if set."""
        mock_format_def = Mock()
        mock_format_def.output.file_extension = ".log"
        mock_load_format.return_value = mock_format_def

        mock_activity_instance = Mock()
        mock_activity_instance.get_baseline_pattern.return_value = [('logon', 1.0)]
        mock_activity_instance.execute_baseline_activity.return_value = None
        mock_activity_gen.return_value = mock_activity_instance

        engine = GenerationEngine(minimal_scenario, tmp_path)
        engine._initialize()

        user = minimal_scenario.environment.users[0]
        event_time = datetime(2024, 1, 15, 10, 30, 0, tzinfo=timezone.utc)

        engine._generate_user_activity(user, event_time)

        # Verify executed on primary system
        assert mock_activity_instance.execute_baseline_activity.called
        call_args = mock_activity_instance.execute_baseline_activity.call_args
        assert call_args[1]['system'].hostname == "TEST-01"

    @patch('evidenceforge.generation.engine.ActivityGenerator')
    @patch('evidenceforge.generation.engine.ZeekEmitter')
    @patch('evidenceforge.generation.engine.WindowsEventEmitter')
    @patch('evidenceforge.generation.engine.load_format')
    def test_execute_storyline_skips_missing_actor(
        self, mock_load_format, mock_windows, mock_zeek, mock_activity_gen,
        scenario_with_storyline, tmp_path
    ):
        """Storyline should skip events with missing actor."""
        mock_format_def = Mock()
        mock_format_def.output.file_extension = ".log"
        mock_load_format.return_value = mock_format_def

        mock_activity_instance = Mock()
        mock_activity_gen.return_value = mock_activity_instance

        engine = GenerationEngine(scenario_with_storyline, tmp_path)
        engine._initialize()

        # Set invalid actor
        engine.scenario.storyline[0].actor = "nonexistent_user"

        engine._execute_storyline()

        # Should not track any malicious events
        assert len(engine.malicious_events) == 0
