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

"""Generation engine for coordinated log production.

This module provides the main orchestrator for Phase 1 log generation.
It coordinates StateManager, emitters, and activity generation to produce
consistent synthetic security logs across multiple formats.
"""

import logging
import math
import random
from collections.abc import Callable
from datetime import datetime, timedelta
from pathlib import Path

from evidenceforge.events.dispatcher import EventDispatcher
from evidenceforge.events.ground_truth import GROUND_TRUTH_JSON_FILENAME
from evidenceforge.generation.activity import ActivityGenerator
from evidenceforge.generation.engine.baseline import BaselineMixin
from evidenceforge.generation.engine.emitter_setup import EmitterSetupMixin
from evidenceforge.generation.engine.storyline import StorylineMixin
from evidenceforge.generation.ground_truth import GroundTruthGenerator
from evidenceforge.generation.network_identities import ScenarioNetworkResolver
from evidenceforge.generation.state_manager import StateManager
from evidenceforge.generation.world_model import WorldModel, WorldPlanner
from evidenceforge.models.scenario import Scenario, System, User
from evidenceforge.output_targets import (
    OutputTarget,
    normalize_output_target,
    write_output_target_marker,
)
from evidenceforge.utils.rng import _stable_seed, reset_thread_rng
from evidenceforge.utils.time import parse_duration, resolve_time_window
from evidenceforge.validation.schema import BUILTIN_ACCOUNTS

logger = logging.getLogger(__name__)


class GenerationEngine(EmitterSetupMixin, BaselineMixin, StorylineMixin):
    """Log generation orchestrator.

    Coordinates StateManager, emitters, and activity generation to produce
    temporally consistent logs across multiple formats with proper
    cross-references (LogonIDs, PIDs, timestamps, Zeek UIDs).

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
        progress_callback: Callable[[str, dict], None] | None = None,
        ground_truth_dir: Path | None = None,
        output_target: str | OutputTarget | None = None,
        oob_hosts: tuple[str, ...] = (),
    ):
        """Initialize generation engine.

        Args:
            scenario: Validated scenario object
            output_dir: Output directory path for generated log files
            progress_callback: Optional callback for progress reporting.
                Called with (event_type: str, data: dict) at key milestones.
            ground_truth_dir: Directory for GROUND_TRUTH.md. Defaults to output_dir.
            output_target: Render/layout target for generated output.
            oob_hosts: Operator-registered live-callback host(s) for adversarial_payload
                out-of-band testing (off by default). When set, an adversarial payload's
                {canary} resolves to the first and all are host-allowlisted.
        """
        reset_thread_rng()
        self.scenario = scenario
        self.output_dir = output_dir
        self.ground_truth_dir = ground_truth_dir or output_dir
        self.output_target = normalize_output_target(output_target)
        self.oob_hosts = tuple(oob_hosts)
        self.progress_callback = progress_callback
        self.state_manager = StateManager()
        self.emitters: dict = {}
        self.activity_generator: ActivityGenerator | None = None
        self.start_time: datetime | None = None
        self.end_time: datetime | None = None
        self.malicious_events: list[dict] = []  # Track for GROUND_TRUTH.md
        self.red_herring_events: list[dict] = []  # Track for Red Herrings section
        self.network_resolver = ScenarioNetworkResolver.from_scenario(scenario)

        # Event counter for record IDs
        self.event_record_counter = 10000

        # Hawkes process state per user for cross-hour continuity
        self._hawkes_states: dict = {}

        from evidenceforge.generation.activity.bash_commands import reset_bash_command_memory

        reset_bash_command_memory()

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
        5. Generate ground-truth reports and the observation manifest
        """
        logger.info(f"Starting generation for scenario: {self.scenario.name}")

        # Phase 1: Initialize
        self._report_progress(
            "phase_start", {"phase": "initialize", "description": "Initializing generation engine"}
        )
        self._initialize()
        self._report_progress("phase_end", {"phase": "initialize"})

        try:
            # Phase 2: Generate baseline activity
            self._report_progress(
                "phase_start", {"phase": "baseline", "description": "Generating baseline activity"}
            )
            self._generate_baseline()
            self._report_progress("phase_end", {"phase": "baseline"})

            # Phase 6.3: Execute remaining storyline events not covered by baseline hours
            if self.scenario.storyline:
                remaining = [
                    i
                    for i in range(len(self.scenario.storyline))
                    if i not in self._storyline_executed
                ]
                if remaining:
                    logger.info(
                        f"Executing {len(remaining)} remaining storyline events (outside baseline window)"
                    )
                    self._report_progress(
                        "phase_start",
                        {
                            "phase": "storyline",
                            "description": f"Executing {len(remaining)} remaining storyline events",
                        },
                    )
                    for idx in remaining:
                        self._execute_single_storyline_event(idx)
                        self._storyline_executed.add(idx)
                    self._barrier_flush_all_emitters()
                    self._report_progress("phase_end", {"phase": "storyline"})

            # Execute remaining red herring events not covered by baseline hours
            if self.scenario.red_herrings:
                remaining_rh = [
                    i
                    for i in range(len(self.scenario.red_herrings))
                    if i not in self._red_herring_executed
                ]
                if remaining_rh:
                    logger.info(
                        f"Executing {len(remaining_rh)} remaining red herring events (outside baseline window)"
                    )
                    for idx in remaining_rh:
                        self._execute_single_red_herring_event(idx)
                        self._red_herring_executed.add(idx)
                    self._barrier_flush_all_emitters()
        finally:
            # Phase 4: Finalize and close emitters (always, even on error)
            self._report_progress(
                "phase_start", {"phase": "finalize", "description": "Finalizing generation"}
            )
            self._finalize()
            self._report_progress("phase_end", {"phase": "finalize"})

        # Phase 5: Generate ground-truth reports for every successful run. Baseline-only
        # datasets still need an empty GROUND_TRUTH.md so CLI overwrite swaps
        # can keep data and metadata as a matched pair.
        logger.info(
            "Generating GROUND_TRUTH.md with %d malicious events and %d red herrings",
            len(self.malicious_events),
            len(self.red_herring_events),
        )
        self._report_progress(
            "phase_start",
            {"phase": "ground_truth", "description": "Generating ground truth documentation"},
        )
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

        # Compute warm-up period (snapped to whole hours so _generate_hour()
        # never produces events that overlap with the real baseline loop)
        warmup_str = self.scenario.time_window.warmup
        if warmup_str:
            raw_duration = parse_duration(warmup_str)
            warmup_hours = max(1, math.ceil(raw_duration.total_seconds() / 3600))
            self.warmup_duration = timedelta(hours=warmup_hours)
        else:
            # Default: 8 hours if not specified (warmup is always on)
            self.warmup_duration = timedelta(hours=8)
        self.warmup_start_time = self.start_time - self.warmup_duration
        # Epoch for periodic schedules (DNS, SMB) — covers warm-up + real window
        self._generation_epoch = self.warmup_start_time
        if self.warmup_duration.total_seconds() > 0:
            logger.info(
                f"Warm-up period: {self.warmup_start_time} to {self.start_time} "
                f"({warmup_str} → {int(self.warmup_duration.total_seconds() / 3600)}h)"
            )

        # Create output directory
        self.output_dir.mkdir(parents=True, exist_ok=True)
        logger.info(f"Output directory: {self.output_dir}")

        # Initialize emitters (from EmitterSetupMixin)
        self._init_emitters()

        # Initialize network visibility engine (Phase 2.5)
        from evidenceforge.generation.network_visibility import NetworkVisibilityEngine

        visibility_engine = NetworkVisibilityEngine(
            network_config=self.scenario.environment.network,
            systems=self.scenario.environment.systems,
        )

        # Resolve logical people and platform accounts once, then expose the
        # legacy SID registry view for older Windows callers during migration.
        identity_directory = self._build_identity_directory()
        sid_registry = identity_directory.sid_registry

        # Phase 5.5: Generate per-user timing and behavioral offsets
        rng = random.Random(_stable_seed(self.scenario.name + "_offsets"))
        self._user_time_offsets: dict[str, dict[str, float]] = {}
        for user in self.scenario.environment.users:
            self._user_time_offsets[user.username] = {
                "start_offset": rng.gauss(0, 0.25),  # ~+/-15min work start
                "end_offset": rng.gauss(0, 0.25),  # ~+/-15min work end
                "lunch_start_offset": rng.gauss(0, 0.17),  # ~+/-10min lunch start
                "lunch_duration_offset": rng.gauss(0, 0.12),  # ~+/-7min lunch length
                "intensity_bias": rng.uniform(0.8, 1.2),  # +/-20% event intensity
                "cluster_size_bias": rng.gauss(0, 0.12),  # +/-12% cluster size
                "inter_gap_bias": rng.gauss(0, 0.10),  # +/-10% gap timing
            }

        # Initialize event dispatcher and activity generator
        from evidenceforge.events.observation import ObservationPolicy

        self.dispatcher = EventDispatcher(
            state_manager=self.state_manager,
            emitters=self.emitters,
            visibility_engine=visibility_engine,
            output_start_time=self.start_time,
            observation_policy=ObservationPolicy(self.scenario.observation_profile),
        )
        self.activity_generator = ActivityGenerator(
            state_manager=self.state_manager,
            emitters=self.emitters,
            event_record_counter=self.event_record_counter,
            network_visibility=visibility_engine,
            sid_registry=sid_registry,
            identity_directory=identity_directory,
            source_timing_profile=self.scenario.observation_profile,
            dispatcher=self.dispatcher,
        )
        self.activity_generator._network_resolver = self.network_resolver
        # Live-callback OOB host(s) for adversarial_payload (off by default).
        self.activity_generator._oob_hosts = self.oob_hosts
        # Build IP->System lookup for HostContext resolution on connection events
        self.activity_generator._ip_to_system = {s.ip: s for s in self.scenario.environment.systems}
        # Set scenario start time for pre-existing process chain logic
        self.activity_generator._scenario_start_time = self.start_time
        self.activity_generator._scenario_end_time = self.end_time
        logger.info("Initialized activity generator")

        # Set initial state manager time (warm-up start if applicable)
        self.state_manager.set_current_time(self.warmup_start_time)

        # Resolve scenario timezone for work-hours modulation
        self._scenario_tz = None
        if self.scenario.environment.timezone and self.scenario.environment.timezone.default:
            try:
                from zoneinfo import ZoneInfo

                self._scenario_tz = ZoneInfo(self.scenario.environment.timezone.default)
            except (KeyError, ValueError):
                pass

        # Phase 6.3: Resolve AD domain for FQDNs and domain name fields
        self._ad_domain = self._resolve_ad_domain()
        self._netbios_domain = self._ad_domain.split(".")[0].upper() if self._ad_domain else "CORP"
        self.activity_generator._ad_domain = self._ad_domain
        self.activity_generator._netbios_domain = self._netbios_domain
        self.activity_generator._users_by_username = {
            user.username: user for user in self.scenario.environment.users
        }
        self.world_model = WorldModel(self.scenario, self._ad_domain)
        self.activity_generator._world_model = self.world_model
        self.activity_generator._ip_to_system = dict(self.world_model.systems_by_ip)

        # Cache org CIDR networks for external IP exclusion
        import ipaddress as _ipa_core

        self._org_cidr_networks: list = []
        if self.scenario.environment.network:
            for seg in self.scenario.environment.network.segments:
                try:
                    self._org_cidr_networks.append(_ipa_core.ip_network(seg.cidr, strict=False))
                except ValueError:
                    pass
            for cidr in self.scenario.environment.network.public_cidrs or []:
                try:
                    self._org_cidr_networks.append(_ipa_core.ip_network(cidr, strict=False))
                except ValueError:
                    pass

        # Register VIPs in IP-to-system so host context resolves for VIP-addressed connections
        ve = self.dispatcher.visibility_engine
        if ve:
            for real_ip, vip in ve._real_ip_to_vip.items():
                system = self.activity_generator._ip_to_system.get(real_ip)
                if system:
                    self.activity_generator._ip_to_system[vip] = system

        # Per-host kernel boot uptime: deterministic offset (seconds since boot at scenario start)
        self._kernel_boot_uptimes: dict[str, float] = {}
        self._audit_serials: dict[str, int] = {}  # per-host monotonic audit serial
        for system in self.scenario.environment.systems:
            boot_days = (_stable_seed(f"boot_days_{system.hostname}") % 28) + 3  # 3-30 days
            self._kernel_boot_uptimes[system.hostname] = boot_days * 86400.0
            self._audit_serials[system.hostname] = (
                _stable_seed(f"audit_serial_{system.hostname}") % 5000
            ) + 1000

        # Phase 5.4: Pre-seed system process trees and detect infrastructure IPs
        self._infra_ips = self._detect_infrastructure_ips()
        self._system_service_defaults = self._build_service_defaults()
        self._system_pids: dict[str, dict[str, int]] = {}  # hostname -> {role: pid}
        self._seed_system_process_trees()

        # Pass per-host boot datetimes to Sysmon emitter for ProcessGUID realism
        if "windows_event_sysmon" in self.emitters:
            _boot_times = {
                hostname: self.start_time - timedelta(seconds=uptime)
                for hostname, uptime in self._kernel_boot_uptimes.items()
            }
            _sysmon = self.emitters["windows_event_sysmon"]
            _sysmon._host_boot_times = _boot_times
            _sysmon._state_manager = self.state_manager
            _sysmon._system_pids = self._system_pids
        if "windows_event_security" in self.emitters:
            self.emitters["windows_event_security"]._state_manager = self.state_manager
            self.emitters["windows_event_security"]._system_pids = self._system_pids
        if "ecar" in self.emitters:
            self.emitters["ecar"]._state_manager = self.state_manager
            self.emitters["ecar"]._system_pids = self._system_pids

        # Phase 6.3: Pre-parse storyline event times for interleaved generation
        self._storyline_by_hour: dict[int, list] = {}  # hour_epoch -> list of (time, event_idx)
        if self.scenario.storyline:
            for idx, event in enumerate(self.scenario.storyline):
                event_time = self._parse_storyline_time(event.time)
                hour_key = int(event_time.replace(minute=0, second=0, microsecond=0).timestamp())
                self._storyline_by_hour.setdefault(hour_key, []).append((event_time, idx))
            for key in self._storyline_by_hour:
                self._storyline_by_hour[key].sort()
            logger.info(
                f"Pre-parsed {len(self.scenario.storyline)} storyline events across {len(self._storyline_by_hour)} hours"
            )

        self._storyline_executed: set[int] = set()

        # Pre-parse red herring event times for interleaved generation
        self._red_herring_by_hour: dict[int, list] = {}
        if self.scenario.red_herrings:
            for idx, event in enumerate(self.scenario.red_herrings):
                event_time = self._parse_storyline_time(event.time)
                hour_key = int(event_time.replace(minute=0, second=0, microsecond=0).timestamp())
                self._red_herring_by_hour.setdefault(hour_key, []).append((event_time, idx))
            for key in self._red_herring_by_hour:
                self._red_herring_by_hour[key].sort()
            logger.info(
                f"Pre-parsed {len(self.scenario.red_herrings)} red herring events across {len(self._red_herring_by_hour)} hours"
            )
        self._red_herring_executed: set[int] = set()

        # Build proxy routing table
        self._proxy_routes: dict[str, list] = {}
        self._build_proxy_routes()
        self.activity_generator._proxy_routes = self._proxy_routes
        self.activity_generator._proxy_mode = self.scenario.environment.proxy.mode
        self.activity_generator._proxy_listener_port = self.scenario.environment.proxy.listener_port
        self.activity_generator._proxy_auth_policy = self.scenario.environment.proxy.auth_policy
        self.activity_generator._proxy_service_accounts = self.scenario.environment.service_accounts
        self.world_planner = WorldPlanner(
            world_model=self.world_model,
            state_manager=self.state_manager,
            activity_generator=self.activity_generator,
        )

        logger.info("Initialization complete")

    def _find_user(self, username: str) -> User | None:
        """Find user by username."""
        for user in self.scenario.environment.users:
            if user.username == username:
                return user
        return None

    def _find_actor(self, actor_name: str) -> User | None:
        """Find actor by name, checking users first then service/built-in accounts.

        For service and built-in accounts, returns a synthetic User object
        with the account name as the username.
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

    def _find_system(self, hostname: str) -> System | None:
        """Find system by hostname."""
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

        if self.activity_generator is not None and self.end_time is not None:
            self.activity_generator.finalize_foreground_process_lifetimes(self.end_time)

        for format_name, emitter in self.emitters.items():
            logger.info(f"Stopping {format_name} emitter thread")
            emitter.close()

        logger.info("All emitters closed")

    def _generate_ground_truth(self) -> None:
        """Generate GROUND_TRUTH.json, derived GROUND_TRUTH.md, and the observation manifest."""
        from evidenceforge.events.observation_manifest import (
            OBSERVATION_MANIFEST_FILENAME,
            write_observation_manifest,
        )

        self.ground_truth_dir.mkdir(parents=True, exist_ok=True)
        output_path = self.ground_truth_dir / "GROUND_TRUTH.md"
        source_evidence_status = self.dispatcher.source_evidence_status

        generator = GroundTruthGenerator(
            scenario=self.scenario,
            malicious_events=self.malicious_events,
            red_herring_events=self.red_herring_events,
            source_evidence_status=source_evidence_status,
        )

        document = generator.build_document()
        generator.write_json(self.ground_truth_dir / GROUND_TRUTH_JSON_FILENAME, document)
        generator.generate(output_path, document)
        write_observation_manifest(
            self.ground_truth_dir / OBSERVATION_MANIFEST_FILENAME,
            self.scenario,
            source_evidence_status,
        )
        write_output_target_marker(self.ground_truth_dir, self.output_target)
        logger.info(f"Ground truth documentation generated: {output_path}")

    def _get_next_event_record_id(self) -> int:
        """Get next EventRecordID for Windows events."""
        self.event_record_counter += 1
        return self.event_record_counter
