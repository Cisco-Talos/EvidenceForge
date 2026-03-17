"""Generation engine for coordinated log production.

This module provides the main orchestrator for Phase 1 log generation.
It coordinates StateManager, emitters, and activity generation to produce
consistent synthetic security logs across multiple formats.
"""

import logging
import math
import random
from datetime import datetime, timedelta
from pathlib import Path
from typing import Callable, Optional

from evidenceforge.formats import load_format
from evidenceforge.generation.activity import ActivityGenerator
from evidenceforge.generation.emitters import (
    WindowsEventEmitter,
    ZeekEmitter,
    EcarEmitter,
    SyslogEmitter,
    BashHistoryEmitter,
    SnortEmitter,
    WebEmitter,
)
from evidenceforge.generation.ground_truth import GroundTruthGenerator
from evidenceforge.generation.state_manager import StateManager
from evidenceforge.models.scenario import Persona, Scenario, User, System
from evidenceforge.utils.time import parse_duration, parse_iso8601, resolve_time_window
from evidenceforge.validation.schema import BUILTIN_ACCOUNTS

logger = logging.getLogger(__name__)


class GenerationEngine:
    """Single-threaded log generation orchestrator for Phase 1.

    Coordinates StateManager, emitters, and activity generation to produce
    temporally consistent logs across multiple formats (Windows Event Logs,
    Zeek conn.log) with proper cross-references (LogonIDs, PIDs, timestamps).

    Phase 1 Constraints:
    - Single-threaded execution
    - Small datasets (<10K events)
    - Fixed baseline patterns (no LLM expansion)
    - Simple storyline keyword matching
    - Hour-by-hour time iteration

    Attributes:
        scenario: Validated Scenario object with environment, baseline, storyline
        output_dir: Directory for generated logs and documentation
        state_manager: StateManager instance for cross-log consistency
        emitters: Dict mapping format name to emitter instance
        start_time: Scenario start datetime (UTC)
        end_time: Scenario end datetime (UTC)
        malicious_events: List of malicious events for GROUND_TRUTH.md
    """

    def __init__(
        self,
        scenario: Scenario,
        output_dir: Path,
        progress_callback: Optional[Callable[[str, dict], None]] = None,
        ground_truth_dir: Optional[Path] = None,
    ):
        """Initialize generation engine.

        Args:
            scenario: Validated scenario object
            output_dir: Output directory path for generated log files
            progress_callback: Optional callback for progress reporting.
                Called with (event_type: str, data: dict) at key milestones.
            ground_truth_dir: Directory for GROUND_TRUTH.md. Defaults to output_dir.
        """
        self.scenario = scenario
        self.output_dir = output_dir
        self.ground_truth_dir = ground_truth_dir or output_dir
        self.progress_callback = progress_callback
        self.state_manager = StateManager()
        self.emitters: dict[str, WindowsEventEmitter | ZeekEmitter | EcarEmitter | SyslogEmitter | BashHistoryEmitter | SnortEmitter | WebEmitter] = {}
        self.activity_generator: Optional[ActivityGenerator] = None
        self.start_time: Optional[datetime] = None
        self.end_time: Optional[datetime] = None
        self.malicious_events: list[dict] = []  # Track for GROUND_TRUTH.md

        # Event counter for record IDs
        self.event_record_counter = 10000

    def _report_progress(self, event_type: str, data: dict) -> None:
        """Report progress to callback if registered.

        Args:
            event_type: Type of progress event (e.g., "phase_start", "hour_progress")
            data: Event-specific data payload
        """
        if self.progress_callback:
            self.progress_callback(event_type, data)

    def generate(self) -> None:
        """Main generation flow.

        Orchestrates the complete log generation process:
        1. Initialize state manager and emitters
        2. Generate baseline activity (hour-by-hour iteration)
        3. Execute storyline events (if present)
        4. Finalize and close emitters
        5. Generate GROUND_TRUTH.md (if malicious activity present)
        """
        logger.info(f"Starting generation for scenario: {self.scenario.name}")

        # Phase 1: Initialize
        self._report_progress("phase_start", {"phase": "initialize", "description": "Initializing generation engine"})
        self._initialize()
        self._report_progress("phase_end", {"phase": "initialize"})

        # Phase 2: Generate baseline activity
        self._report_progress("phase_start", {"phase": "baseline", "description": "Generating baseline activity"})
        self._generate_baseline()
        self._report_progress("phase_end", {"phase": "baseline"})

        # Phase 3: Execute storyline events (if present)
        if self.scenario.storyline:
            logger.info(f"Executing {len(self.scenario.storyline)} storyline events")
            self._report_progress("phase_start", {
                "phase": "storyline",
                "description": f"Executing {len(self.scenario.storyline)} storyline events"
            })
            self._execute_storyline()
            self._report_progress("phase_end", {"phase": "storyline"})

        # Phase 4: Finalize and close emitters
        self._report_progress("phase_start", {"phase": "finalize", "description": "Finalizing generation"})
        self._finalize()
        self._report_progress("phase_end", {"phase": "finalize"})

        # Phase 5: Generate ground truth (if malicious activity present)
        if self.malicious_events:
            logger.info(f"Generating GROUND_TRUTH.md with {len(self.malicious_events)} malicious events")
            self._report_progress("phase_start", {"phase": "ground_truth", "description": "Generating ground truth documentation"})
            self._generate_ground_truth()
            self._report_progress("phase_end", {"phase": "ground_truth"})

        logger.info("Generation complete")

    def _initialize(self) -> None:
        """Initialize state manager, emitters, and validate scenario.

        - Resolves time window (start/end datetimes)
        - Creates output directory
        - Loads format definitions
        - Initializes emitters for each format
        - Sets initial StateManager time
        """
        logger.info("Initializing generation engine")

        # Resolve time window
        self.start_time, self.end_time = resolve_time_window(self.scenario.time_window)
        logger.info(f"Time window: {self.start_time} to {self.end_time}")

        # Create output directory
        self.output_dir.mkdir(parents=True, exist_ok=True)
        logger.info(f"Output directory: {self.output_dir}")

        # Load format definitions and create emitters
        # Phase 2.2: Added new formats (eCAR, syslog, bash_history, snort, web)
        # Note: windows_event_security kept temporarily until Phase 2.10 when activity.py
        # is updated to emit to eCAR instead
        formats_to_generate = [
            'windows_event_security',  # Phase 1 - Temporary (activity.py still uses this)
            'zeek_conn',               # Phase 1 - Network visibility
            'ecar',                    # Phase 2.2 - Primary host EDR/XDR (NEW)
            'syslog',                  # Phase 2.2 - Linux native logs (NEW)
            'bash_history',            # Phase 2.2 - Command history (NEW)
            'snort_alert',             # Phase 2.2 - IDS alerts (NEW)
            'web_access'               # Phase 2.2 - Web logs (NEW)
        ]

        # Map format names to emitter classes
        emitter_classes = {
            'windows_event_security': WindowsEventEmitter,
            'zeek_conn': ZeekEmitter,
            'ecar': EcarEmitter,
            'syslog': SyslogEmitter,
            'bash_history': BashHistoryEmitter,
            'snort_alert': SnortEmitter,
            'web_access': WebEmitter,
        }

        for format_name in formats_to_generate:
            format_def = load_format(format_name)

            # bash_history uses a directory (per-user-per-host files), not a single file
            if format_name == 'bash_history':
                output_path = self.output_dir / "bash_history"
            else:
                output_path = self.output_dir / f"{format_name}{format_def.output.file_extension}"

            emitter_class = emitter_classes[format_name]
            emitter = emitter_class(format_def, output_path, threaded=True)

            self.emitters[format_name] = emitter
            logger.info(f"Initialized {format_name} emitter (threaded) -> {output_path}")

        # Initialize network visibility engine (Phase 2.5)
        from evidenceforge.generation.network_visibility import NetworkVisibilityEngine
        visibility_engine = NetworkVisibilityEngine(
            network_config=self.scenario.environment.network,
            systems=self.scenario.environment.systems,
        )

        # Phase 5.1: Generate domain SID and per-user SID registry
        sid_registry = self._build_sid_registry()

        # Phase 5.5: Generate per-user timing and behavioral offsets
        rng = random.Random(hash(self.scenario.name + "_offsets"))
        self._user_time_offsets: dict[str, dict[str, float]] = {}
        for user in self.scenario.environment.users:
            self._user_time_offsets[user.username] = {
                'start_offset': rng.gauss(0, 0.25),        # ~±15min work start
                'end_offset': rng.gauss(0, 0.25),          # ~±15min work end
                'lunch_start_offset': rng.gauss(0, 0.17),  # ~±10min lunch start
                'lunch_duration_offset': rng.gauss(0, 0.12),  # ~±7min lunch length
                'intensity_bias': rng.uniform(0.8, 1.2),    # ±20% event intensity
                'cluster_size_bias': rng.gauss(0, 0.2),     # ±20% cluster size
                'inter_gap_bias': rng.gauss(0, 0.15),       # ±15% gap timing
            }

        # Initialize activity generator
        self.activity_generator = ActivityGenerator(
            state_manager=self.state_manager,
            emitters=self.emitters,
            event_record_counter=self.event_record_counter,
            network_visibility=visibility_engine,
            sid_registry=sid_registry,
        )
        logger.info("Initialized activity generator")

        # Set initial state manager time
        self.state_manager.set_current_time(self.start_time)
        logger.info("Initialization complete")

    def _generate_baseline(self) -> None:
        """Generate baseline activity for all enabled users.

        Iterates hour-by-hour through the time window, generating activity
        for each enabled user based on their persona, intensity, and variation.

        Phase 1 Implementation:
        - Simple hour-by-hour iteration
        - Fixed activity patterns (no LLM)
        - Uniform distribution with jitter within each hour
        """
        logger.info("Starting baseline activity generation")

        # Get enabled users only
        enabled_users = [u for u in self.scenario.environment.users if u.enabled]
        logger.info(f"Generating baseline for {len(enabled_users)} enabled users")

        # Calculate total hours for progress tracking
        total_hours = int((self.end_time - self.start_time).total_seconds() / 3600)

        # Hour-by-hour iteration
        current_hour = self.start_time
        hour_count = 0

        while current_hour < self.end_time:
            hour_count += 1
            logger.debug(f"Processing hour {hour_count}: {current_hour}")
            self.state_manager.set_current_time(current_hour)

            # Report hour progress
            self._report_progress("hour_progress", {
                "hour": hour_count,
                "total_hours": total_hours,
                "current_time": current_hour
            })

            # Generate events for each user this hour
            for user in enabled_users:
                # Resolve persona for work hours and risk modulation
                persona = self._get_user_persona(user)
                user_offsets = self._user_time_offsets.get(user.username)

                # Calculate events for this user this hour
                num_events = self._calculate_events_for_hour(
                    user, current_hour=current_hour.hour, persona=persona,
                    user_offsets=user_offsets,
                )

                if num_events > 0:
                    # Distribute events across the hour (clustered)
                    persona_name = user.persona if user.persona else None
                    event_times = self._distribute_events_in_hour(
                        current_hour, num_events,
                        persona_name=persona_name,
                        username=user.username,
                    )

                    # Generate user activity at each time
                    for event_time in event_times:
                        self._generate_user_activity(user, event_time)

            # Phase 5.2: Terminate stale processes
            self._terminate_stale_processes(current_hour)

            # Phase 5.1: Generate logoffs for sessions that should end this hour
            self._generate_logoffs_for_hour(enabled_users, current_hour)

            # Barrier flush - ensure all events for this hour are written
            # before proceeding to next hour (temporal consistency)
            self._barrier_flush_all_emitters()

            # Move to next hour
            current_hour += timedelta(hours=1)

        logger.info(f"Baseline generation complete: processed {hour_count} hours")

    def _terminate_stale_processes(self, current_hour: datetime) -> None:
        """Terminate processes that have exceeded their expected lifetime.

        Called per-hour. Process lifetime depends on type:
        - System processes (svchost, lsass, csrss, services, explorer): never
        - Browsers/editors (chrome, firefox, outlook, code): 1-4 hours
        - Build tools (msbuild, gcc, npm): 5-30 minutes
        - Other: 30min-2 hours

        Args:
            current_hour: Start of the current hour
        """
        # Patterns for processes that should never be terminated
        system_patterns = ('svchost', 'lsass', 'csrss', 'services.exe', 'explorer.exe',
                           'smss', 'wininit', 'winlogon', 'fontdrvhost', 'systemd',
                           'cron', 'sshd', 'rsyslogd', 'NetworkManager', 'dbus-daemon')

        # Patterns for short-lived processes (5-30 min)
        short_lived = ('msbuild', 'gcc', 'npm', 'make', 'dotnet', 'cargo', 'node.exe')

        for system in self.scenario.environment.systems:
            processes = self.state_manager.get_processes_on_system(system.hostname)
            for proc in list(processes):
                proc_age_hours = (current_hour - proc.start_time).total_seconds() / 3600
                image_lower = proc.image.lower()

                # System processes: never terminate
                if any(p in image_lower for p in system_patterns):
                    continue

                # Determine max lifetime
                if any(p in image_lower for p in short_lived):
                    max_hours = random.uniform(0.08, 0.5)  # 5-30 min
                elif any(p in image_lower for p in ('chrome', 'firefox', 'edge', 'outlook', 'teams', 'code')):
                    max_hours = random.uniform(1.0, 4.0)
                else:
                    max_hours = random.uniform(0.5, 2.0)

                if proc_age_hours > max_hours and random.random() < 0.5:
                    # Find user and generate termination
                    actor = self._find_actor(proc.username)
                    if not actor:
                        continue

                    # Get logon_id from active sessions
                    sessions = self.state_manager.get_sessions_for_user(proc.username)
                    logon_id = sessions[0].logon_id if sessions else '0x0'

                    term_offset = random.uniform(0, 3599)
                    term_time = current_hour + timedelta(seconds=term_offset)
                    self.state_manager.set_current_time(term_time)
                    self.activity_generator.generate_process_termination(
                        user=actor,
                        system=system,
                        time=term_time,
                        pid=proc.pid,
                        process_name=proc.image,
                        logon_id=logon_id,
                    )

    def _generate_logoffs_for_hour(
        self,
        users: list[User],
        current_hour: datetime,
    ) -> None:
        """Generate logoff events for sessions that should end this hour.

        For each user with active sessions, probabilistically end sessions:
        - 30% chance per session if session age > 1 hour
        - 60% chance if current hour is outside user's work hours

        Args:
            users: List of enabled users
            current_hour: Start of the current hour
        """
        for user in users:
            sessions = self.state_manager.get_sessions_for_user(user.username)
            if not sessions:
                continue

            persona = self._get_user_persona(user)
            is_outside_work_hours = False
            if persona and persona.work_hours_parsed:
                is_outside_work_hours = current_hour.hour not in persona.work_hours_parsed.get('hours', range(24))

            # Find the system for this user (for logoff emission)
            system = None
            if user.primary_system:
                systems = [s for s in self.scenario.environment.systems if s.hostname == user.primary_system]
                if systems:
                    system = systems[0]
            if not system:
                assigned = [s for s in self.scenario.environment.systems if s.assigned_user == user.username]
                system = assigned[0] if assigned else self.scenario.environment.systems[0]

            for session in list(sessions):  # Copy list since we modify during iteration
                session_age_hours = (current_hour - session.start_time).total_seconds() / 3600
                if session_age_hours < 0.5:
                    continue  # Too new to logoff

                logoff_probability = 0.6 if is_outside_work_hours else 0.3 if session_age_hours > 1 else 0.1
                if random.random() < logoff_probability:
                    # Generate logoff at a random time within the hour
                    logoff_offset = random.uniform(0, 3599)
                    logoff_time = current_hour + timedelta(seconds=logoff_offset)
                    self.state_manager.set_current_time(logoff_time)
                    self.activity_generator.generate_logoff(
                        user=user,
                        system=system,
                        time=logoff_time,
                        logon_id=session.logon_id,
                        logon_type=session.logon_type,
                    )

    def _barrier_flush_all_emitters(self) -> None:
        """Flush all emitters and wait for completion (hour-level barrier).

        Ensures temporal consistency: all events for hour N are written
        before hour N+1 begins.
        """
        logger.debug("Barrier flush: waiting for all emitters to complete")
        for format_name, emitter in self.emitters.items():
            emitter.barrier_flush()
        logger.debug("Barrier flush: all emitters complete")

    def _get_user_persona(self, user: User) -> Optional[Persona]:
        """Resolve user.persona string to Persona object.

        Args:
            user: User whose persona to resolve

        Returns:
            Persona object or None if not found
        """
        if not user.persona or not self.scenario.personas:
            return None
        for persona in self.scenario.personas:
            if persona.name == user.persona:
                return persona
        return None

    @staticmethod
    def _sigmoid(x: float) -> float:
        """Sigmoid function for smooth temporal transitions."""
        return 1.0 / (1.0 + math.exp(-6.0 * x))

    def _work_hour_multiplier(
        self,
        hour: int,
        whp: dict,
        user_offsets: Optional[dict] = None,
    ) -> float:
        """Calculate activity multiplier based on work hours with smooth transitions.

        Returns 0.0–1.5 multiplier. Uses sigmoid ramps for gradual transitions
        at work start/end and lunch, instead of binary on/off.

        Args:
            hour: Integer hour of day (0-23)
            whp: work_hours_parsed dict with start, end, lunch, peak_hours
            user_offsets: Optional per-user timing offsets

        Returns:
            Activity multiplier (0.02–1.5)
        """
        start = whp['start']
        end = whp['end']
        lunch = whp.get('lunch')  # (start_hour, end_hour) or None
        peak_hours = whp.get('peak_hours') or []

        # Apply per-user offsets if provided
        if user_offsets:
            start += user_offsets.get('start_offset', 0)
            end += user_offsets.get('end_offset', 0)
            if lunch:
                lunch_start = lunch[0] + user_offsets.get('lunch_start_offset', 0)
                lunch_dur_offset = user_offsets.get('lunch_duration_offset', 0)
                lunch_end = lunch[1] + user_offsets.get('lunch_start_offset', 0) + lunch_dur_offset
                lunch = (lunch_start, lunch_end)

        h = float(hour) + 0.5  # Use mid-hour for smoother curve

        # Morning ramp-up: sigmoid from start-1.5 to start
        if h < start - 1.5:
            return 0.02  # Near-zero early morning
        if h < start + 0.5:
            t = (h - (start - 1.0)) / 1.5  # 0 to 1 over transition
            return 0.02 + 0.98 * self._sigmoid(t * 2 - 1)

        # Evening ramp-down: sigmoid from end to end+1.5
        if h > end + 1.5:
            return 0.02  # Near-zero late evening
        if h > end - 0.5:
            t = (h - (end - 0.5)) / 1.5  # 0 to 1 over transition
            return 0.02 + 0.98 * (1.0 - self._sigmoid(t * 2 - 1))

        # Lunch dip (soft, 50% not 0%)
        if lunch:
            lunch_start, lunch_end = lunch
            lunch_mid = (lunch_start + lunch_end) / 2.0
            lunch_half = (lunch_end - lunch_start) / 2.0
            if lunch_start - 0.5 < h < lunch_end + 0.5:
                # Smooth dip centered on lunch mid-point
                dist_from_mid = abs(h - lunch_mid)
                if dist_from_mid < lunch_half:
                    return 0.5  # Core lunch: 50%
                else:
                    # Transition zone (0.5h on each side)
                    t = (dist_from_mid - lunch_half) / 0.5
                    return 0.5 + 0.5 * min(1.0, t)  # Ramp 0.5 → 1.0

        # Peak hours: 1.5x
        if hour in peak_hours:
            return 1.5

        # Normal work hours
        return 1.0

    def _calculate_events_for_hour(
        self,
        user: User,
        current_hour: Optional[int] = None,
        persona: Optional[Persona] = None,
        user_offsets: Optional[dict] = None,
    ) -> int:
        """Calculate number of events for user this hour.

        Applies intensity + variation + persona risk profile + sigmoid work hours
        to determine how many events to generate for this user during this hour.

        Args:
            user: User to calculate events for
            current_hour: Hour of day (0-23) for work hours modulation
            persona: Resolved Persona object for risk/work-hours modulation
            user_offsets: Optional per-user timing offsets

        Returns:
            Number of events to generate (>= 0)
        """
        # Base intensity from scenario
        intensity_map = {'low': 5, 'medium': 15, 'high': 40}
        base_events = intensity_map[self.scenario.baseline_activity.intensity]

        # Risk profile multiplier
        if persona and persona.risk_profile:
            risk_mult = {'low': 0.7, 'medium': 1.0, 'high': 1.3}
            base_events = int(base_events * risk_mult.get(persona.risk_profile, 1.0))

        # Phase 5.5: Sigmoid work hours modulation (replaces binary on/off)
        if persona and persona.work_hours_parsed and current_hour is not None:
            multiplier = self._work_hour_multiplier(
                current_hour, persona.work_hours_parsed, user_offsets
            )
            base_events = int(base_events * multiplier)

        # Phase 5.5: Per-user intensity bias (so two same-persona users differ)
        if user_offsets and 'intensity_bias' in user_offsets:
            base_events = int(base_events * user_offsets['intensity_bias'])

        # Apply variation (random jitter)
        variation_map = {'low': 0.10, 'medium': 0.25, 'high': 0.50}
        stddev = base_events * variation_map[self.scenario.baseline_activity.variation]
        num_events = max(0, int(random.gauss(base_events, stddev)))

        return num_events

    # Phase 5.5: Per-persona cluster configuration
    PERSONA_CLUSTER_CONFIG = {
        'developer': {'cluster_size': (5, 15), 'inter_gap_mean': 600},
        'executive': {'cluster_size': (2, 6), 'inter_gap_mean': 300},
        'analyst': {'cluster_size': (4, 10), 'inter_gap_mean': 480},
        'sysadmin': {'cluster_size': (3, 8), 'inter_gap_mean': 360},
        'default': {'cluster_size': (3, 10), 'inter_gap_mean': 420},
    }

    def _distribute_events_in_hour_uniform(self, hour_start: datetime, num_events: int) -> list[datetime]:
        """Distribute events uniformly (legacy fallback).

        Args:
            hour_start: Start of the hour
            num_events: Number of events to distribute

        Returns:
            List of event times sorted chronologically
        """
        if num_events == 0:
            return []

        interval = 3600 / num_events
        times = []
        for i in range(num_events):
            offset = interval * i + random.uniform(-interval * 0.25, interval * 0.25)
            offset = max(0, min(3599, offset))
            times.append(hour_start + timedelta(seconds=offset))
        return sorted(times)

    def _distribute_events_in_hour(
        self,
        hour_start: datetime,
        num_events: int,
        persona_name: Optional[str] = None,
        username: Optional[str] = None,
    ) -> list[datetime]:
        """Distribute events in activity clusters within an hour.

        Phase 5.5: Replaces uniform spacing with realistic bursty clusters.
        Events within a cluster are spaced 0.5-3 seconds apart.
        Inter-cluster gaps follow exponential distribution.

        Args:
            hour_start: Start of the hour
            num_events: Number of events to distribute
            persona_name: Optional persona for cluster config
            username: Optional username for per-user variation

        Returns:
            List of event times sorted chronologically
        """
        if num_events == 0:
            return []

        # Get persona-specific cluster config
        config = self.PERSONA_CLUSTER_CONFIG.get(
            (persona_name or '').lower(),
            self.PERSONA_CLUSTER_CONFIG['default']
        )
        cluster_min, cluster_max = config['cluster_size']
        inter_gap_mean = config['inter_gap_mean']

        # Apply per-user variation
        if username and hasattr(self, '_user_time_offsets'):
            offsets = self._user_time_offsets.get(username, {})
            size_bias = 1.0 + offsets.get('cluster_size_bias', 0)
            cluster_min = max(2, int(cluster_min * size_bias))
            cluster_max = max(cluster_min + 1, int(cluster_max * size_bias))
            gap_bias = 1.0 + offsets.get('inter_gap_bias', 0)
            inter_gap_mean = max(60, inter_gap_mean * gap_bias)

        times = []
        remaining = num_events
        t = random.expovariate(1.0 / 60)  # First cluster offset (mean ~1min)

        while remaining > 0:
            cluster_size = min(remaining, random.randint(cluster_min, cluster_max))
            for i in range(cluster_size):
                event_t = t + random.uniform(0.5, 3.0) * i
                times.append(hour_start + timedelta(seconds=min(event_t, 3599)))
            remaining -= cluster_size
            # Inter-cluster gap: exponential distribution
            t += cluster_size * 2.0 + random.expovariate(1.0 / inter_gap_mean)

        return sorted(times)

    def _generate_user_activity(self, user: User, event_time: datetime) -> None:
        """Generate activity for user at specified time.

        Uses ActivityGenerator to execute baseline activity patterns based on
        the user's persona (or default pattern if no persona assigned).

        Args:
            user: User to generate activity for
            event_time: Time of the activity
        """
        # Get user's system (prioritize primary_system, then assigned systems, then random)
        if user.primary_system:
            # Use user's primary system
            systems = [s for s in self.scenario.environment.systems if s.hostname == user.primary_system]
            system = systems[0] if systems else random.choice(self.scenario.environment.systems)
        else:
            # Find systems assigned to this user
            assigned_systems = [s for s in self.scenario.environment.systems if s.assigned_user == user.username]
            if assigned_systems:
                system = random.choice(assigned_systems)
            else:
                system = random.choice(self.scenario.environment.systems)

        # Get baseline pattern for user's persona
        persona = self._get_user_persona(user)
        persona_name = user.persona if user.persona else None
        pattern = self.activity_generator.get_baseline_pattern(persona_name, persona=persona)

        # Execute activities based on probabilities
        for activity_type, probability in pattern:
            if random.random() < probability:
                self.state_manager.set_current_time(event_time)
                self.activity_generator.execute_baseline_activity(
                    user=user,
                    system=system,
                    time=event_time,
                    activity_type=activity_type
                )

    def _execute_storyline(self) -> None:
        """Execute storyline events (malicious/suspicious activities).

        Parses storyline events, executes them at specified times, and tracks
        them for GROUND_TRUTH.md generation. Implements baseline suppression
        (±5 min window) to avoid conflicts with baseline activity.

        Phase 1 Implementation:
        - Simple keyword matching for activity types
        - Basic event generation based on activity description
        - Tracking of malicious events for ground truth
        """
        total_events = len(self.scenario.storyline)

        for event_num, storyline_event in enumerate(self.scenario.storyline, start=1):
            # Parse event time
            event_time = self._parse_storyline_time(storyline_event.time)

            # Find actor and system
            actor = self._find_actor(storyline_event.actor)
            system = self._find_system(storyline_event.system)

            if not actor or not system:
                logger.warning(
                    f"Skipping storyline event: actor={storyline_event.actor}, "
                    f"system={storyline_event.system} not found"
                )
                continue

            logger.info(
                f"Executing storyline event: {storyline_event.actor} on "
                f"{storyline_event.system} at {event_time}"
            )

            # Report storyline progress
            self._report_progress("storyline_progress", {
                "event_num": event_num,
                "total_events": total_events,
                "actor": actor.username,
                "system": system.hostname
            })

            # Match activity to event types (simple keyword matching)
            event_types = self._match_activity_to_events(storyline_event.activity)

            # Execute each matched event type
            self.state_manager.set_current_time(event_time)

            for event_type in event_types:
                malicious_event = self._execute_storyline_event(
                    actor=actor,
                    system=system,
                    time=event_time,
                    event_type=event_type,
                    activity=storyline_event.activity,
                    details=storyline_event.details
                )

                if malicious_event:
                    self.malicious_events.append(malicious_event)

            # Barrier flush after each storyline event (ensures event written before proceeding)
            self._barrier_flush_all_emitters()

    def _parse_storyline_time(self, time_str: str) -> datetime:
        """Parse storyline event time to absolute datetime.

        Supports:
        - ISO 8601 absolute time: "2024-01-15T10:30:00Z"
        - Relative offset (duration): "+2h30m"
        - Relative offset (seconds): "+7200"

        Args:
            time_str: Time string to parse

        Returns:
            Absolute datetime (UTC)

        Raises:
            ValueError: If time format is invalid
        """
        # ISO 8601 absolute time (starts with year)
        if time_str[0].isdigit() and len(time_str) > 10:
            return parse_iso8601(time_str)

        # Relative offset
        if time_str.startswith('+'):
            offset_str = time_str[1:]

            # Try seconds first (all digits)
            if offset_str.isdigit():
                offset = timedelta(seconds=int(offset_str))
            else:
                # Parse duration string (e.g., "2h30m")
                offset = parse_duration(offset_str)

            return self.start_time + offset

        raise ValueError(f"Invalid storyline time format: {time_str}")

    def _match_activity_to_events(self, activity: str) -> list[str]:
        """Match activity description to event types using keyword matching.

        Phase 1: Simple keyword-based matching.

        Args:
            activity: Activity description string

        Returns:
            List of event types to generate
        """
        # Keyword mapping for Phase 1
        keywords = {
            'logon': ['logon', 'log in', 'login', 'authenticate', 'sign in'],
            'logoff': ['logoff', 'log off', 'logout', 'sign out'],
            'process': ['execute', 'run', 'launch', 'start', 'spawn', 'powershell', 'cmd', 'command'],
            'connection': ['connect', 'access', 'download', 'upload', 'communicate', 'c2', 'exfiltrate'],
        }

        activity_lower = activity.lower()
        matched = []

        for event_type, kws in keywords.items():
            if any(kw in activity_lower for kw in kws):
                matched.append(event_type)

        # Default to process if no match
        return matched if matched else ['process']

    def _execute_storyline_event(
        self,
        actor: User,
        system: System,
        time: datetime,
        event_type: str,
        activity: str,
        details: Optional[dict]
    ) -> Optional[dict]:
        """Execute a single storyline event of a specific type.

        Args:
            actor: User performing the activity
            system: System where activity occurs
            time: Event timestamp
            event_type: Type of event (logon, process, connection, etc.)
            activity: Activity description
            details: Optional activity-specific details

        Returns:
            Malicious event dict for GROUND_TRUTH.md, or None if not tracked
        """
        details = details or {}
        malicious_event = {
            'time': time,
            'actor': actor.username,
            'system': system.hostname,
            'activity': activity,
            'type': event_type,
        }

        if event_type == 'logon':
            source_ip = details.get('source_ip', '203.0.113.50')  # Default attacker IP
            logon_id = self.activity_generator.generate_logon(
                user=actor,
                system=system,
                time=time,
                logon_type=3,  # Network logon for attacks
                source_ip=source_ip
            )
            malicious_event['logon_id'] = logon_id
            malicious_event['source_ip'] = source_ip

        elif event_type == 'process':
            # Get or create session for this user
            sessions = self.state_manager.get_sessions_for_user(actor.username)
            if not sessions:
                # Create session first
                logon_id = self.activity_generator.generate_logon(actor, system, time, logon_type=3)
            else:
                logon_id = sessions[0].logon_id  # Use first active session

            # Use details or create malicious-looking process
            process_name = details.get('process_name', 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe')
            command_line = details.get('command_line', 'powershell.exe -enc <base64_encoded_command>')

            pid = self.activity_generator.generate_process(
                user=actor,
                system=system,
                time=time,
                logon_id=logon_id,
                process_name=process_name,
                command_line=command_line
            )

            malicious_event['process_name'] = process_name
            malicious_event['command_line'] = command_line
            malicious_event['pid'] = pid

        elif event_type == 'connection':
            dst_ip = details.get('dst_ip', '198.51.100.10')  # Default C2 server IP
            dst_port = details.get('dst_port', 443)
            service = details.get('service', 'https')

            # Validate destination is different from source
            if dst_ip == system.ip:
                logger.warning(
                    f"Skipping storyline connection: dst_ip {dst_ip} matches system IP {system.ip}. "
                    f"Adjusting to external IP."
                )
                dst_ip = '198.51.100.10'  # Force to external IP

            uid = self.activity_generator.generate_connection(
                src_ip=system.ip,
                dst_ip=dst_ip,
                time=time,
                dst_port=dst_port,
                service=service,
                duration=random.uniform(1.0, 30.0),
                orig_bytes=random.randint(1000, 10000),
                resp_bytes=random.randint(5000, 50000)
            )

            malicious_event['dst_ip'] = dst_ip
            malicious_event['dst_port'] = dst_port
            malicious_event['uid'] = uid

        return malicious_event

    def _find_user(self, username: str) -> Optional[User]:
        """Find user by username.

        Args:
            username: Username to search for

        Returns:
            User object or None if not found
        """
        for user in self.scenario.environment.users:
            if user.username == username:
                return user
        return None

    def _find_actor(self, actor_name: str) -> Optional[User]:
        """Find actor by name, checking users first then service/built-in accounts.

        For service and built-in accounts, returns a synthetic User object
        with the account name as the username.

        Args:
            actor_name: Actor name to resolve

        Returns:
            User object or None if not found
        """
        user = self._find_user(actor_name)
        if user:
            return user

        service_accounts = set(self.scenario.environment.service_accounts)
        if actor_name in BUILTIN_ACCOUNTS or actor_name in service_accounts:
            return User(
                username=actor_name,
                full_name=actor_name,
                email=f"{actor_name.lower().replace(' ', '.')}@system.local",
                enabled=True,
            )

        return None

    def _find_system(self, hostname: str) -> Optional[System]:
        """Find system by hostname.

        Args:
            hostname: Hostname to search for

        Returns:
            System object or None if not found
        """
        for system in self.scenario.environment.systems:
            if system.hostname == hostname:
                return system
        return None

    def _finalize(self) -> None:
        """Finalize generation and close all emitters.

        Flushes remaining buffered events and closes emitter files.
        Phase 2.1: Gracefully stops emitter threads before closing.
        """
        logger.info("Finalizing generation")

        # Stop emitter threads gracefully (they flush on stop)
        for format_name, emitter in self.emitters.items():
            if emitter.threaded:
                logger.info(f"Stopping {format_name} emitter thread")
                emitter.stop_thread()
            else:
                logger.info(f"Closing {format_name} emitter")
                emitter.close()

        logger.info("All emitters closed")

    def _generate_ground_truth(self) -> None:
        """Generate GROUND_TRUTH.md documentation.

        Creates comprehensive attack documentation including narrative,
        timeline, and IOCs for threat hunting training.
        """
        self.ground_truth_dir.mkdir(parents=True, exist_ok=True)
        output_path = self.ground_truth_dir / "GROUND_TRUTH.md"

        generator = GroundTruthGenerator(
            scenario=self.scenario,
            malicious_events=self.malicious_events
        )

        generator.generate(output_path)
        logger.info(f"Ground truth documentation generated: {output_path}")

    def _build_sid_registry(self) -> dict[str, str]:
        """Build a SID registry mapping usernames to Windows SIDs.

        Generates a domain base SID (S-1-5-21-{3 sub-authorities}) and assigns
        each user a unique RID starting at 1001. Well-known SIDs are included
        for system accounts.

        Returns:
            Dict mapping username to full SID string
        """
        # Generate domain base SID with 3 random sub-authority values
        rng = random.Random(hash(self.scenario.name))  # Deterministic per scenario
        base_sid = (
            f"S-1-5-21-{rng.randint(1000000000, 3999999999)}"
            f"-{rng.randint(1000000000, 3999999999)}"
            f"-{rng.randint(1000000000, 3999999999)}"
        )

        registry: dict[str, str] = {
            # Well-known SIDs
            'SYSTEM': 'S-1-5-18',
            'LOCAL SERVICE': 'S-1-5-19',
            'NETWORK SERVICE': 'S-1-5-20',
        }

        # Assign per-user RIDs starting at 1001
        for i, user in enumerate(self.scenario.environment.users):
            registry[user.username] = f"{base_sid}-{1001 + i}"

        # Also assign SIDs for service accounts
        for j, svc in enumerate(self.scenario.environment.service_accounts):
            if svc not in registry:
                registry[svc] = f"{base_sid}-{2001 + j}"

        logger.info(f"Built SID registry: {len(registry)} entries (domain: {base_sid})")
        return registry

    def _get_next_event_record_id(self) -> int:
        """Get next EventRecordID for Windows events.

        Returns:
            Next sequential EventRecordID
        """
        self.event_record_counter += 1
        return self.event_record_counter
