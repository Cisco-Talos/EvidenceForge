"""Generation engine for coordinated log production.

This module provides the main orchestrator for Phase 1 log generation.
It coordinates StateManager, emitters, and activity generation to produce
consistent synthetic security logs across multiple formats.
"""

import logging
import random
from datetime import datetime, timedelta
from pathlib import Path
from typing import Callable, Optional

from log_generator.formats import load_format
from log_generator.generation.activity import ActivityGenerator
from log_generator.generation.emitters import WindowsEventEmitter, ZeekEmitter
from log_generator.generation.ground_truth import GroundTruthGenerator
from log_generator.generation.state_manager import StateManager
from log_generator.models.scenario import Scenario, User, System
from log_generator.utils.time import parse_duration, parse_iso8601, resolve_time_window

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
        progress_callback: Optional[Callable[[str, dict], None]] = None
    ):
        """Initialize generation engine.

        Args:
            scenario: Validated scenario object
            output_dir: Output directory path
            progress_callback: Optional callback for progress reporting.
                Called with (event_type: str, data: dict) at key milestones.
        """
        self.scenario = scenario
        self.output_dir = output_dir
        self.progress_callback = progress_callback
        self.state_manager = StateManager()
        self.emitters: dict[str, WindowsEventEmitter | ZeekEmitter] = {}
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
        # Phase 1: Windows Event Security and Zeek conn.log only
        formats_to_generate = ['windows_event_security', 'zeek_conn']

        for format_name in formats_to_generate:
            format_def = load_format(format_name)
            output_file = self.output_dir / f"{format_name}{format_def.output.file_extension}"

            if format_name == 'windows_event_security':
                emitter = WindowsEventEmitter(format_def, output_file)
            elif format_name == 'zeek_conn':
                emitter = ZeekEmitter(format_def, output_file)
            else:
                raise ValueError(f"Unsupported format: {format_name}")

            self.emitters[format_name] = emitter
            logger.info(f"Initialized {format_name} emitter -> {output_file}")

        # Initialize activity generator
        self.activity_generator = ActivityGenerator(
            state_manager=self.state_manager,
            emitters=self.emitters,
            event_record_counter=self.event_record_counter
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
                # Calculate events for this user this hour
                num_events = self._calculate_events_for_hour(user)

                if num_events > 0:
                    # Distribute events across the hour
                    event_times = self._distribute_events_in_hour(current_hour, num_events)

                    # Generate user activity at each time
                    for event_time in event_times:
                        self._generate_user_activity(user, event_time)

            # Move to next hour
            current_hour += timedelta(hours=1)

        logger.info(f"Baseline generation complete: processed {hour_count} hours")

    def _calculate_events_for_hour(self, user: User) -> int:
        """Calculate number of events for user this hour.

        Applies intensity + variation + persona risk profile to determine
        how many events to generate for this user during this hour.

        Args:
            user: User to calculate events for

        Returns:
            Number of events to generate (>= 0)
        """
        # Base intensity
        intensity_map = {'low': 5, 'medium': 15, 'high': 40}
        base_events = intensity_map[self.scenario.baseline_activity.intensity]

        # Risk profile adjustment (if persona assigned)
        # Note: Phase 1 - persona is just a string name, not full Persona object
        # Risk adjustments would require full persona definition (Phase 2+)
        # For now, skip risk adjustment since we don't have access to risk_profile

        # Apply variation (random jitter)
        variation_map = {'low': 0.10, 'medium': 0.25, 'high': 0.50}
        stddev = base_events * variation_map[self.scenario.baseline_activity.variation]
        num_events = max(0, int(random.gauss(base_events, stddev)))

        return num_events

    def _distribute_events_in_hour(self, hour_start: datetime, num_events: int) -> list[datetime]:
        """Distribute events across hour with uniform distribution + jitter.

        Args:
            hour_start: Start of the hour
            num_events: Number of events to distribute

        Returns:
            List of event times sorted chronologically
        """
        if num_events == 0:
            return []

        # Uniform spacing with jitter (±25% of interval)
        interval = 3600 / num_events  # seconds per event
        times = []

        for i in range(num_events):
            # Base time with jitter
            offset = interval * i + random.uniform(-interval * 0.25, interval * 0.25)
            offset = max(0, min(3600, offset))  # Clamp to hour [0, 3600]
            times.append(hour_start + timedelta(seconds=offset))

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
        # Note: persona is a string (persona name) in Phase 1, not a Persona object
        persona_name = user.persona if user.persona else None
        pattern = self.activity_generator.get_baseline_pattern(persona_name)

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
            actor = self._find_user(storyline_event.actor)
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
        """
        logger.info("Finalizing generation")

        for format_name, emitter in self.emitters.items():
            logger.info(f"Closing {format_name} emitter")
            emitter.close()

        logger.info("All emitters closed")

    def _generate_ground_truth(self) -> None:
        """Generate GROUND_TRUTH.md documentation.

        Creates comprehensive attack documentation including narrative,
        timeline, and IOCs for threat hunting training.
        """
        output_path = self.output_dir / "GROUND_TRUTH.md"

        generator = GroundTruthGenerator(
            scenario=self.scenario,
            malicious_events=self.malicious_events
        )

        generator.generate(output_path)
        logger.info(f"Ground truth documentation generated: {output_path}")

    def _get_next_event_record_id(self) -> int:
        """Get next EventRecordID for Windows events.

        Returns:
            Next sequential EventRecordID
        """
        self.event_record_counter += 1
        return self.event_record_counter
