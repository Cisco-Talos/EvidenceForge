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

from __future__ import annotations

import logging
import math
import random
import time
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path
from threading import Lock
from typing import TYPE_CHECKING

from evidenceforge.composition.models import CompiledScenario
from evidenceforge.events.artifacts_manifest import ARTIFACTS_MANIFEST_FILENAME
from evidenceforge.events.dispatcher import EventDispatcher
from evidenceforge.events.ground_truth import GROUND_TRUTH_JSON_FILENAME
from evidenceforge.generation.activity import ActivityGenerator
from evidenceforge.generation.application_channels import ApplicationChannelRegistry
from evidenceforge.generation.emitters.base import ExactPublicationAuthority
from evidenceforge.generation.engine.baseline import BaselineMixin
from evidenceforge.generation.engine.emitter_setup import EmitterSetupMixin
from evidenceforge.generation.engine.storyline import StorylineMixin
from evidenceforge.generation.ground_truth import GroundTruthGenerator
from evidenceforge.generation.intent_ledger import AuthoredIntentLedger, IntentExecutionLedger
from evidenceforge.generation.lifecycle_authority import GeneratorLifecycleAuthority
from evidenceforge.generation.lifecycle_registry import LifecycleRegistry
from evidenceforge.generation.lifecycle_shadow import LifecycleShadow
from evidenceforge.generation.network_identities import ScenarioNetworkResolver
from evidenceforge.generation.rdp_sessions import RdpReconnectStateManager
from evidenceforge.generation.resource_forecast import ResourceForecast, build_resource_forecast
from evidenceforge.generation.source_finalization import (
    SourceFinalizationCoordinator,
    SourceFinalizationParticipant,
)
from evidenceforge.generation.source_timing import SourceTimingPlanner
from evidenceforge.generation.state_manager import StateManager
from evidenceforge.generation.timing import TimingRuntime
from evidenceforge.generation.workload import WorkloadLimits, estimate_workload
from evidenceforge.generation.world_model import WorldModel, WorldPlanner
from evidenceforge.models.scenario import Scenario, System, User
from evidenceforge.output_targets import (
    OutputTarget,
    normalize_output_target,
    write_output_target_marker,
)
from evidenceforge.utils.rng import (
    MAX_GENERATION_SEED,
    _stable_seed,
    generation_seed_scope,
    reset_thread_rng,
)
from evidenceforge.utils.time import parse_duration, resolve_time_window
from evidenceforge.validation.schema import BUILTIN_ACCOUNTS

logger = logging.getLogger(__name__)

if TYPE_CHECKING:
    from evidenceforge.generation.checkpoints.models import CheckpointCursor, CheckpointRecovery
    from evidenceforge.generation.checkpoints.participants import (
        IncrementalCheckpointParticipant,
    )
    from evidenceforge.generation.checkpoints.runtime import IncrementalCheckpointController

_ENGINE_TIMING_NAMESPACE = "shared-timing-v1"


@dataclass(frozen=True, slots=True)
class _TerminalOwnerSnapshot:
    """Exact engine owners pinned before any terminal mutation begins."""

    activity_generator: object | None
    dispatcher: object | None
    source_coordinator: object | None
    emitters: tuple[tuple[str, object], ...]


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
        artifact_dir: Path | None = None,
        scenario_root: Path | None = None,
        output_target: str | OutputTarget | None = None,
        oob_hosts: tuple[str, ...] = (),
        generation_seed: int | None = None,
        allow_large_workload: bool = False,
        workload_limits: WorkloadLimits | None = None,
        resource_forecast: ResourceForecast | None = None,
        compiled_scenario: CompiledScenario | None = None,
        checkpoint_hour_callback: Callable[[int, datetime, str], None] | None = None,
        checkpoint_hours: int = 0,
        checkpoint_controller: IncrementalCheckpointController | None = None,
        checkpoint_recovery: CheckpointRecovery | None = None,
        checkpoint_synchronization_hook: Callable[[CheckpointCursor], None] | None = None,
    ):
        """Initialize generation engine.

        Args:
            scenario: Validated scenario object
            output_dir: Output directory path for generated log files
            progress_callback: Optional callback for progress reporting.
                Called with (event_type: str, data: dict) at key milestones.
            ground_truth_dir: Directory for GROUND_TRUTH.md. Defaults to output_dir.
            scenario_root: Directory used to resolve scenario-relative sidecar inputs.
            output_target: Render/layout target for generated output.
            oob_hosts: Operator-registered live-callback host(s) for adversarial_payload
                out-of-band testing (off by default). When set, an adversarial payload's
                {canary} resolves to the first and all are host-allowlisted.
            checkpoint_hour_callback: Optional internal cadence hook invoked after each
                scheduled, completely swept simulated hour at an emitter barrier. The phase
                names the post-boundary cursor and is one of warmup, collection, or tail.
            checkpoint_hours: Internal positive cadence for checkpoint_hour_callback. Zero
                disables the hook.
            checkpoint_controller: Optional incremental checkpoint publisher. Its cadence must
                match checkpoint_hours and it cannot be combined with the legacy test hook.
            checkpoint_recovery: Optional validated recovery selected from the controller's store.
            checkpoint_synchronization_hook: Internal post-publication test barrier. Production CLI
                wiring exposes it only through the guarded pytest environment seam.
        """
        self.generation_seed = (
            scenario.generation_seed if generation_seed is None else generation_seed
        )
        if not 0 <= self.generation_seed <= MAX_GENERATION_SEED:
            raise ValueError(f"generation_seed must be between 0 and {MAX_GENERATION_SEED}")
        self.scenario = scenario.model_copy(update={"generation_seed": self.generation_seed})
        from evidenceforge.composition.artifacts import minimal_compiled_scenario
        from evidenceforge.composition.compiler import with_runtime_scenario

        if compiled_scenario is not None and not isinstance(compiled_scenario, CompiledScenario):
            raise TypeError("compiled_scenario must be a CompiledScenario")
        base_compiled = compiled_scenario or minimal_compiled_scenario(self.scenario)
        self.compiled_scenario = with_runtime_scenario(base_compiled, self.scenario)
        self.output_dir = Path(output_dir)
        self.scenario_root = Path(scenario_root) if scenario_root is not None else Path.cwd()
        self.allow_large_workload = allow_large_workload
        from evidenceforge.config.overlay import retired_overlay_errors
        from evidenceforge.config.provider import effective_config_scope
        from evidenceforge.models.exceptions import ConfigurationError

        with effective_config_scope(self.compiled_scenario.effective_config):
            retired = retired_overlay_errors()
            if retired:
                path, message = retired[0]
                raise ConfigurationError(f"overlay/{path}: {message}")
            self.workload_estimate = estimate_workload(
                self.scenario,
                scenario_root=self.scenario_root,
                limits=workload_limits,
            )
            self.resource_forecast = resource_forecast or build_resource_forecast(
                self.scenario,
                self.workload_estimate,
                self.output_dir,
            )
        self.ground_truth_dir = (
            Path(ground_truth_dir) if ground_truth_dir is not None else self.output_dir
        )
        self.artifact_dir = (
            Path(artifact_dir) if artifact_dir is not None else self.ground_truth_dir / "artifacts"
        )
        self.output_target = normalize_output_target(output_target)
        self.oob_hosts = tuple(oob_hosts)
        self.progress_callback = progress_callback
        if type(checkpoint_hours) is not int or checkpoint_hours < 0:
            raise ValueError("checkpoint_hours must be a non-negative integer")
        if checkpoint_hour_callback is not None and checkpoint_hours == 0:
            raise ValueError("checkpoint_hour_callback requires a positive checkpoint_hours")
        if checkpoint_controller is not None and checkpoint_hour_callback is not None:
            raise ValueError("checkpoint controller and checkpoint callback are mutually exclusive")
        if checkpoint_controller is not None and checkpoint_controller.cadence.hours != (
            checkpoint_hours
        ):
            raise ValueError("checkpoint controller cadence must match checkpoint_hours")
        if checkpoint_recovery is not None and checkpoint_controller is None:
            raise ValueError("checkpoint recovery requires an incremental checkpoint controller")
        if checkpoint_synchronization_hook is not None and checkpoint_controller is None:
            raise ValueError("checkpoint synchronization requires an incremental controller")
        self.checkpoint_hour_callback = checkpoint_hour_callback
        self.checkpoint_hours = checkpoint_hours
        self._checkpoint_controller = checkpoint_controller
        self._checkpoint_recovery = checkpoint_recovery
        self._checkpoint_synchronization_hook = checkpoint_synchronization_hook
        self._checkpoint_participants: tuple[IncrementalCheckpointParticipant, ...] = ()
        self.state_manager = StateManager()
        self.emitters: dict = {}
        self.activity_generator: ActivityGenerator | None = None
        self.timing_runtime: TimingRuntime | None = None
        self.source_timing_planner: SourceTimingPlanner | None = None
        self.start_time: datetime | None = None
        self.end_time: datetime | None = None
        self.malicious_events: list[dict] = []  # Track for GROUND_TRUTH.md
        self.red_herring_events: list[dict] = []  # Track for Red Herrings section
        # Independent pre-planning oracle plus execution-side reconciliation evidence. Rendered
        # source data remains unchanged; canonical ground truth receives the additive projection.
        self.authored_intent_ledger = AuthoredIntentLedger.from_scenario(scenario)
        self.intent_execution_ledger = IntentExecutionLedger(self.authored_intent_ledger)
        self.network_resolver = ScenarioNetworkResolver.from_scenario(scenario)
        self._source_finalization_authority: ExactPublicationAuthority | None = None
        self._source_finalization_coordinator: SourceFinalizationCoordinator | None = None
        self._ssh_lifecycles_finalized = False
        self._rdp_lifecycles_finalized = False
        self._linux_sudo_logoffs_finalized = False
        self._foreground_lifecycles_finalized = False
        self._persistent_smb_terminal_asserted = False
        self._application_channels_finalized = False
        self._terminal_runtime_cleanup_finalized = False
        self._exact_projection_recoveries_finalized = False
        self._terminal_transient_census_asserted = False
        self._finalization_complete = False
        self._finalization_aborted = False
        self._initialization_complete = False
        self._generation_body_completed = False
        self._generation_complete = False
        self._ids_alert_summary_applied = False
        self._generate_owner = Lock()
        self._expected_close_emitters: dict[str, object] | None = None
        self._closed_emitter_names: set[str] = set()
        self._source_coordinator_closed = False
        self._exact_projection_recovery_dispatcher: object | None = None
        self._terminal_owner_snapshot: _TerminalOwnerSnapshot | None = None

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

    def _checkpoint_after_completed_hour(
        self,
        *,
        completed_simulated_hours: int,
        next_hour: datetime,
    ) -> None:
        """Invoke the optional cadence hook with an exact post-hour cursor."""

        callback = self.checkpoint_hour_callback
        controller = self._checkpoint_controller
        if (callback is None and controller is None) or (
            self.checkpoint_hours == 0 or completed_simulated_hours % self.checkpoint_hours != 0
        ):
            return
        if self.start_time is None or self.end_time is None:
            raise RuntimeError("checkpoint cadence hook requires initialized generation bounds")
        checkpoint_started = time.perf_counter()
        quiesce_started = time.perf_counter()
        self._barrier_flush_all_emitters()
        emitter_quiesce_seconds = time.perf_counter() - quiesce_started
        barrier_prepare_seconds = 0.0
        if controller is not None:
            barrier_prepare_started = time.perf_counter()
            self._prepare_incremental_checkpoint_barrier(next_hour)
            barrier_prepare_seconds = time.perf_counter() - barrier_prepare_started
        if next_hour < self.start_time:
            phase = "warmup"
        elif next_hour < self.end_time:
            phase = "collection"
        else:
            phase = "tail"
        if controller is not None:
            from evidenceforge.generation.checkpoints.models import CheckpointCursor

            cursor = CheckpointCursor(
                phase=phase,
                completed_simulated_hours=completed_simulated_hours,
                next_hour=None if phase == "tail" else next_hour.isoformat(),
            )
            controller.commit(
                cursor=cursor,
                participants=self._checkpoint_participants,
                emitter_quiesce_seconds=emitter_quiesce_seconds,
                barrier_prepare_seconds=barrier_prepare_seconds,
            )
            logger.debug(
                "Incremental checkpoint foreground pause completed in %.6f seconds",
                time.perf_counter() - checkpoint_started,
            )
            if self._checkpoint_synchronization_hook is not None:
                self._checkpoint_synchronization_hook(cursor)
        else:
            assert callback is not None
            callback(completed_simulated_hours, next_hour, phase)

    def _prepare_incremental_checkpoint_barrier(self, cutoff: datetime) -> None:
        """Retire terminal authorities at the sealed post-hour frontier."""

        self.lifecycle_registry.prune_action_cohort_receipt_authorities()
        self.lifecycle_registry.prune_checkpoint_terminal_transports(cutoff)
        self.activity_generator.prune_checkpoint_terminal_network_state(cutoff)

    def generate(self) -> None:
        """Generate one run inside its public deterministic seed namespace."""

        from evidenceforge.config.provider import effective_config_scope

        if not self._generate_owner.acquire(blocking=False):
            raise RuntimeError("Generation cannot run concurrently or re-enter on one engine")
        try:
            with effective_config_scope(self.compiled_scenario.effective_config):
                with generation_seed_scope(self.generation_seed):
                    reset_thread_rng()
                    self._generate_scoped()
        finally:
            self._generate_owner.release()

    def _generate_scoped(self) -> None:
        """Main generation flow.

        Orchestrates the complete log generation process:
        1. Initialize state manager and emitters
        2. Generate baseline activity (hour-by-hour iteration)
        3. Execute storyline events (if present)
        4. Finalize and close emitters
        5. Generate ground-truth reports and the observation manifest
        """
        logger.info(f"Starting generation for scenario: {self.scenario.name}")

        if self._finalization_aborted:
            self._retry_aborted_cleanup()
            raise RuntimeError("Aborted generation cannot be restarted")
        if self._generation_body_completed:
            if not self._finalization_complete:
                self._finalize_successfully_with_progress(
                    description="Retrying generation finalization"
                )
            self._complete_generation_outputs()
            return
        if self._initialization_complete:
            raise RuntimeError("Generation body cannot be restarted after an incomplete run")

        # Phase 1: Initialize a fresh runtime, then hydrate semantic state when resuming.
        try:
            self._report_progress(
                "phase_start",
                {"phase": "initialize", "description": "Initializing generation engine"},
            )
            self._initialize()
            recovery = self._checkpoint_recovery
            if recovery is not None:
                controller = self._checkpoint_controller
                if controller is None:  # pragma: no cover - constructor invariant
                    raise RuntimeError("checkpoint recovery lost its controller")
                controller.restore_participants(
                    recovery=recovery,
                    participants=self._checkpoint_participants,
                )
            self._initialization_complete = True
            self._report_progress("phase_end", {"phase": "initialize"})
        except BaseException as primary:
            self._abort_failed_generation(primary)
            raise

        try:
            # Phase 2: Generate baseline activity
            self._report_progress(
                "phase_start", {"phase": "baseline", "description": "Generating baseline activity"}
            )
            self._generate_baseline(
                resume_cursor=(
                    None
                    if self._checkpoint_recovery is None
                    else self._checkpoint_recovery.manifest.cursor
                )
            )
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
            self._generation_body_completed = True
        except BaseException as primary:
            self._abort_failed_generation(primary)
            raise
        else:
            self._finalize_successfully_with_progress(description="Finalizing generation")

        self._complete_generation_outputs()

    def _abort_failed_generation(self, primary: BaseException) -> None:
        """Close every initialized emitter without allowing progress errors to skip cleanup."""

        self._finalization_aborted = True
        secondary_errors: list[tuple[str, BaseException]] = []
        try:
            self._report_progress(
                "phase_start",
                {"phase": "finalize", "description": "Finalizing generation"},
            )
        except BaseException as progress_error:
            secondary_errors.append(("Generation failure progress callback", progress_error))
        try:
            self._finalize(generation_succeeded=False)
        except BaseException as cleanup_error:
            secondary_errors.append(("Generation failure cleanup", cleanup_error))
        try:
            self._report_progress("phase_end", {"phase": "finalize"})
        except BaseException as progress_error:
            secondary_errors.append(("Generation failure progress callback", progress_error))
        for label, error in secondary_errors:
            try:
                BaseException.add_note(primary, f"{label} also failed: {error!r}")
            except BaseException:
                logger.debug("Unable to annotate the primary generation failure")

    def _retry_aborted_cleanup(self) -> None:
        """Resume only legacy terminal cleanup after an already-aborted run."""

        if self._finalization_complete:
            return
        progress_error: BaseException | None = None
        try:
            self._report_progress(
                "phase_start",
                {"phase": "finalize", "description": "Retrying aborted generation cleanup"},
            )
        except BaseException as error:
            progress_error = error
        try:
            self._finalize(generation_succeeded=False)
        except BaseException as cleanup_error:
            if progress_error is not None:
                cleanup_error.add_note(
                    f"Aborted cleanup progress callback also failed: {progress_error!r}"
                )
            raise
        try:
            self._report_progress("phase_end", {"phase": "finalize"})
        except BaseException:
            if progress_error is None:
                raise
        if progress_error is not None:
            raise progress_error

    def _finalize_successfully_with_progress(self, *, description: str) -> None:
        """Run retryable EOF finalization even when its progress callback fails."""

        progress_error: BaseException | None = None
        try:
            self._report_progress(
                "phase_start",
                {"phase": "finalize", "description": description},
            )
        except BaseException as error:
            progress_error = error
        try:
            self._finalize(generation_succeeded=True)
        except BaseException as finalization_error:
            if progress_error is not None:
                finalization_error.add_note(
                    f"Finalization progress callback also failed: {progress_error!r}"
                )
            raise
        try:
            self._report_progress("phase_end", {"phase": "finalize"})
        except BaseException as error:
            if progress_error is None:
                progress_error = error
        if progress_error is not None:
            raise progress_error

    def _complete_generation_outputs(self) -> None:
        """Write successful-run metadata once after retryable terminal source close."""

        if self._generation_complete:
            return
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
        from evidenceforge.composition.artifacts import (
            write_generation_manifest,
            write_resolved_scenario,
        )

        write_resolved_scenario(self.compiled_scenario, self.ground_truth_dir)
        write_generation_manifest(
            self.compiled_scenario,
            self.ground_truth_dir,
            output_target=self.output_target.value,
            formats=[
                str(log["format"])
                for log in self.scenario.output.logs
                if isinstance(log, dict) and "format" in log
            ],
            oob_hosts=self.oob_hosts,
        )
        self._report_progress("phase_end", {"phase": "ground_truth"})

        self._generation_complete = True
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
        self.timing_runtime = TimingRuntime(
            reference_time=self.warmup_start_time,
            namespace=_ENGINE_TIMING_NAMESPACE,
            generation_seed=self.generation_seed,
        )
        self.source_timing_planner = SourceTimingPlanner(
            clock_profile_name=self.scenario.observation_profile,
            timing_runtime=self.timing_runtime,
        )
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
        self._source_finalization_authority = ExactPublicationAuthority(
            capacity=1,
            row_capacity=512,
            byte_capacity=20 * 1024 * 1024,
        )
        participants = tuple(
            emitter
            for emitter in self.emitters.values()
            if isinstance(emitter, SourceFinalizationParticipant)
        )
        self._source_finalization_coordinator = SourceFinalizationCoordinator(
            participants,
            self._source_finalization_authority,
        )

        # Initialize network visibility engine (Phase 2.5)
        from evidenceforge.generation.network_visibility import NetworkVisibilityEngine

        visibility_engine = NetworkVisibilityEngine(
            network_config=self.scenario.environment.network,
            systems=self.scenario.environment.systems,
        )
        from evidenceforge.events.source_catalog import DEFAULT_SOURCE_CATALOG, SourceOwnerKind
        from evidenceforge.generation.source_deployment_compiler import (
            compile_scenario_source_deployment,
        )

        # Compile one immutable source deployment after concrete emitters and
        # topology are known. Sensor-backed formats retain their legacy
        # no-output behavior when no sensor is configured.
        network = self.scenario.environment.network
        has_network_sensors = network is not None and bool(network.sensors)
        deployment_formats = tuple(
            format_name
            for format_name in self.emitters
            if has_network_sensors
            or DEFAULT_SOURCE_CATALOG.descriptor(format_name).owner is SourceOwnerKind.HOST
        )
        self.source_deployment_compilation = compile_scenario_source_deployment(
            self.scenario,
            emitter_formats=deployment_formats,
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

        # Establish the canonical State frontier before constructing any runtime owner that
        # can publish lifecycle identity. Production owns exactly one registry/shadow/authority
        # graph; boot processes enter State and lifecycle through its fleet transaction below.
        self.state_manager.set_current_time(self.warmup_start_time)
        self.lifecycle_registry = LifecycleRegistry()
        self.lifecycle_shadow = LifecycleShadow(self.state_manager, self.lifecycle_registry)
        self.lifecycle_authority = GeneratorLifecycleAuthority(
            self.state_manager,
            self.lifecycle_shadow,
        )
        self.application_channel_registry = ApplicationChannelRegistry(
            window_start=self.warmup_start_time,
            window_end=self.end_time,
        )
        self.rdp_session_manager = RdpReconnectStateManager(
            application_registry=self.application_channel_registry,
            window_start=self.warmup_start_time,
            window_end=self.end_time,
        )

        # Initialize event dispatcher and activity generator
        from evidenceforge.events.observation import ObservationPolicy

        self.dispatcher = EventDispatcher(
            state_manager=self.state_manager,
            emitters=self.emitters,
            visibility_engine=visibility_engine,
            output_start_time=self.start_time,
            output_end_time=self.end_time,
            observation_policy=ObservationPolicy(self.scenario.observation_profile),
            intent_execution_ledger=self.intent_execution_ledger,
            timing_runtime=self.timing_runtime,
            source_timing_planner=self.source_timing_planner,
            lifecycle_shadow=self.lifecycle_shadow,
            collection_deployment=self.source_deployment_compilation.deployment,
        )
        self.activity_generator = ActivityGenerator(
            state_manager=self.state_manager,
            emitters=self.emitters,
            network_visibility=visibility_engine,
            sid_registry=sid_registry,
            identity_directory=identity_directory,
            source_timing_profile=self.scenario.observation_profile,
            dispatcher=self.dispatcher,
            timing_runtime=self.timing_runtime,
            source_timing_planner=self.source_timing_planner,
            lifecycle_shadow=self.lifecycle_shadow,
            lifecycle_authority=self.lifecycle_authority,
            application_channel_registry=self.application_channel_registry,
            rdp_session_manager=self.rdp_session_manager,
            generation_window_start=self.warmup_start_time,
            generation_window_end=self.end_time,
        )
        self.activity_generator._network_resolver = self.network_resolver
        self.activity_generator._scenario_environment = self.scenario.environment
        self.activity_generator._software_deployment_key = self.scenario.environment.domain
        self.activity_generator._scenario_root = self.scenario_root
        self.activity_generator._email_artifact_dir = self.artifact_dir / "email"
        self.activity_generator._artifacts_manifest_path = (
            self.ground_truth_dir / ARTIFACTS_MANIFEST_FILENAME
        )
        # Live-callback OOB host(s) for adversarial_payload (off by default).
        self.activity_generator._oob_hosts = self.oob_hosts
        # Build IP->System lookup for HostContext resolution on connection events
        self.activity_generator._ip_to_system = {s.ip: s for s in self.scenario.environment.systems}
        # Set scenario start time for pre-existing process chain logic
        self.activity_generator._scenario_start_time = self.start_time
        self.activity_generator._scenario_end_time = self.end_time
        logger.info("Initialized activity generator")

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
        from evidenceforge.generation.storage_world import StorageWorldModel

        self.storage_world = StorageWorldModel.compile(self.scenario)
        self.activity_generator._storage_world = self.storage_world

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
        self.activity_generator._world_planner = self.world_planner

        if self._checkpoint_controller is not None:
            from evidenceforge.generation.checkpoints.participant_set import (
                production_checkpoint_participants,
            )

            self._checkpoint_participants = production_checkpoint_participants(self)

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

    @staticmethod
    def _emitter_identity_snapshot(emitters: dict) -> tuple[tuple[str, object], ...]:
        """Return a deterministic identity-only snapshot of an emitter mapping."""

        return tuple(sorted(emitters.items(), key=lambda item: item[0]))

    def _pin_terminal_owners(self) -> _TerminalOwnerSnapshot:
        """Pin every public owner before the first terminal stage mutates state."""

        current = _TerminalOwnerSnapshot(
            activity_generator=getattr(self, "activity_generator", None),
            dispatcher=getattr(self, "dispatcher", None),
            source_coordinator=getattr(self, "_source_finalization_coordinator", None),
            emitters=self._emitter_identity_snapshot(getattr(self, "emitters", {})),
        )
        expected = getattr(self, "_terminal_owner_snapshot", None)
        if expected is None:
            self._terminal_owner_snapshot = current
            return current
        if current.activity_generator is not expected.activity_generator:
            raise RuntimeError("Activity generator changed identity after terminal ownership")
        if current.dispatcher is not expected.dispatcher:
            raise RuntimeError("Generation dispatcher changed identity after terminal ownership")
        if current.source_coordinator is not expected.source_coordinator:
            raise RuntimeError(
                "Source-finalization coordinator changed identity after terminal ownership"
            )
        if len(current.emitters) != len(expected.emitters):
            raise RuntimeError("Emitter mapping keys changed after terminal ownership")
        for (current_name, current_emitter), (expected_name, expected_emitter) in zip(
            current.emitters,
            expected.emitters,
            strict=True,
        ):
            if current_name != expected_name:
                raise RuntimeError("Emitter mapping keys changed after terminal ownership")
            if current_emitter is not expected_emitter:
                raise RuntimeError(
                    f"Emitter mapping for {current_name!r} changed identity "
                    "after terminal ownership"
                )
        return expected

    def _run_bounded_terminal_stage(
        self,
        *,
        completed_attribute: str,
        description: str,
        operation: Callable[[], None],
    ) -> None:
        """Run one restartable stage twice at most while preserving its first error."""

        if getattr(self, completed_attribute, False):
            return
        primary: BaseException | None = None
        for attempt in range(2):
            try:
                operation()
            except BaseException as error:
                if primary is None:
                    primary = error
                else:
                    primary.add_note(f"{description} retry also failed: {error!r}")
                if attempt == 1:
                    raise primary from None
                continue

            setattr(self, completed_attribute, True)
            if primary is None:
                return
            raise primary

    def _activity_terminal_capability(
        self,
        name: str,
        *,
        owner_attributes: tuple[str, ...],
        missing_message: str,
    ) -> Callable[..., object] | None:
        """Resolve a terminal API while retaining compatibility-only test adapters."""

        activity_generator = getattr(self, "activity_generator", None)
        if activity_generator is None:
            return None
        capability = getattr(activity_generator, name, None)
        if callable(capability):
            return capability
        owner_state = vars(activity_generator)
        if any(attribute in owner_state for attribute in owner_attributes):
            raise RuntimeError(missing_message)
        return None

    def _drain_exact_projection_recoveries_before_close(self) -> None:
        """Finish dispatcher-owned exact projection recovery before sink shutdown.

        The dispatcher is installed partway through initialization, and legacy
        dispatchers cannot own exact projection recovery.  Treat a dispatcher
        with neither capability as a no-op, but reject a partial or malformed
        capability so emitter close cannot strand admitted source rows.
        """

        dispatcher = getattr(self, "dispatcher", None)
        recovery_dispatcher = self._exact_projection_recovery_dispatcher
        if recovery_dispatcher is not None and dispatcher is not recovery_dispatcher:
            raise RuntimeError(
                "Generation dispatcher changed identity after exact projection recovery ownership"
            )
        if dispatcher is None:
            return
        drain = getattr(dispatcher, "drain_exact_projection_recoveries", None)
        assert_drained = getattr(
            dispatcher,
            "assert_exact_projection_recoveries_drained",
            None,
        )
        if drain is None and assert_drained is None:
            return
        if not callable(drain) or not callable(assert_drained):
            raise RuntimeError(
                "Generation dispatcher has an incomplete exact projection recovery capability"
            )
        if recovery_dispatcher is None:
            if self.dispatcher is not dispatcher:
                raise RuntimeError(
                    "Generation dispatcher changed identity during exact projection recovery setup"
                )
            self._exact_projection_recovery_dispatcher = dispatcher
        drain()
        assert_drained()

    def _assert_ssh_session_lifecycles_drained_before_close(self) -> None:
        """Require the activity owner's close journal to be terminal before sink close."""

        activity_generator = getattr(self, "activity_generator", None)
        if activity_generator is None:
            return
        assert_drained = getattr(
            activity_generator,
            "assert_ssh_session_lifecycles_drained",
            None,
        )
        if not callable(assert_drained):
            # Compatibility adapters that predate action-owned SSH journals
            # have nothing to assert. A real owner exposing journal storage may
            # never silently omit the matching terminal capability.
            owner_state = vars(activity_generator)
            if (
                "_pending_ssh_session_closures" in owner_state
                or "_prepared_ssh_close_continuations" in owner_state
            ):
                raise RuntimeError("Activity generator has no SSH close-journal terminal assertion")
            return
        assert_drained()

    def _assert_rdp_session_lifecycles_drained_before_close(self) -> None:
        """Require the RDP lifecycle journal to be terminal before sink close."""

        activity_generator = getattr(self, "activity_generator", None)
        if activity_generator is None:
            return
        assert_drained = getattr(
            activity_generator,
            "assert_rdp_session_lifecycles_drained",
            None,
        )
        if not callable(assert_drained):
            owner_state = vars(activity_generator)
            if (
                "_pending_rdp_lifecycle_continuations" in owner_state
                or "_prepared_rdp_lifecycle_continuations" in owner_state
            ):
                raise RuntimeError("Activity generator has no RDP lifecycle terminal assertion")
            return
        assert_drained()

    def _finalize_linux_sudo_logoffs_before_close(self) -> None:
        """Drain sudo-logoff work with one recovery retry, preserving its first failure."""

        if self._linux_sudo_logoffs_finalized:
            return
        activity_generator = getattr(self, "activity_generator", None)
        if activity_generator is None:
            self._linux_sudo_logoffs_finalized = True
            return

        owner_state = vars(activity_generator)
        activity_type = type(activity_generator)
        owns_journal = (
            "_pending_linux_sudo_logoffs" in owner_state
            or "finalize_linux_sudo_logoffs" in owner_state
            or "assert_linux_sudo_logoffs_drained" in owner_state
            or getattr(activity_type, "finalize_linux_sudo_logoffs", None) is not None
            or getattr(activity_type, "assert_linux_sudo_logoffs_drained", None) is not None
        )
        if not owns_journal:
            self._linux_sudo_logoffs_finalized = True
            return
        finalizer = getattr(activity_generator, "finalize_linux_sudo_logoffs", None)
        assert_drained = getattr(activity_generator, "assert_linux_sudo_logoffs_drained", None)
        if not callable(finalizer):
            raise RuntimeError("Activity generator has no Linux sudo logoff finalizer")
        if not callable(assert_drained):
            raise RuntimeError("Activity generator has no Linux sudo logoff terminal assertion")

        primary: BaseException | None = None
        for attempt in range(2):
            try:
                finalizer()
                assert_drained()
            except BaseException as error:
                if primary is None:
                    primary = error
                else:
                    primary.add_note(f"Linux sudo logoff journal retry also failed: {error!r}")
                try:
                    self._drain_exact_projection_recoveries_before_close()
                except BaseException as recovery_error:
                    primary.add_note(
                        "Exact projection recovery after Linux sudo logoff failure also failed: "
                        f"{recovery_error!r}"
                    )
                    raise primary from recovery_error
                if attempt == 1:
                    raise primary from None
                continue

            if primary is None:
                self._linux_sudo_logoffs_finalized = True
                return
            try:
                # A recovered retry may admit the terminal eCAR row after its
                # canonical state was already committed. Authenticate both
                # owners again before remembering the stage as complete.
                self._drain_exact_projection_recoveries_before_close()
                assert_drained()
            except BaseException as recovery_error:
                primary.add_note(
                    "Terminal recovery after Linux sudo logoff retry also failed: "
                    f"{recovery_error!r}"
                )
                raise primary from recovery_error
            self._linux_sudo_logoffs_finalized = True
            raise primary

    def _finalize_rdp_session_lifecycles_before_close(self) -> None:
        """Drain RDP terminal work with one exact-projection recovery retry."""

        if getattr(self, "_rdp_lifecycles_finalized", False):
            return
        activity_generator = getattr(self, "activity_generator", None)
        if activity_generator is None:
            self._rdp_lifecycles_finalized = True
            return
        finalizer = getattr(activity_generator, "finalize_rdp_session_lifecycles", None)
        if not callable(finalizer):
            owner_state = vars(activity_generator)
            if (
                "_pending_rdp_lifecycle_continuations" in owner_state
                or "_prepared_rdp_lifecycle_continuations" in owner_state
            ):
                raise RuntimeError("Activity generator has no RDP lifecycle-journal finalizer")
            self._rdp_lifecycles_finalized = True
            return

        primary: BaseException | None = None
        for attempt in range(2):
            try:
                if self.end_time is not None:
                    finalizer(self.end_time)
                self._assert_rdp_session_lifecycles_drained_before_close()
            except BaseException as error:
                if primary is None:
                    primary = error
                else:
                    primary.add_note(f"RDP lifecycle-journal retry also failed: {error!r}")
                try:
                    self._drain_exact_projection_recoveries_before_close()
                except BaseException as recovery_error:
                    primary.add_note(
                        "Exact projection recovery after RDP lifecycle failure also failed: "
                        f"{recovery_error!r}"
                    )
                    raise primary from recovery_error
                if attempt == 1:
                    raise primary from None
                continue

            self._rdp_lifecycles_finalized = True
            if primary is None:
                return
            try:
                self._drain_exact_projection_recoveries_before_close()
                self._assert_rdp_session_lifecycles_drained_before_close()
            except BaseException as recovery_error:
                primary.add_note(
                    f"Terminal recovery after RDP lifecycle retry also failed: {recovery_error!r}"
                )
            raise primary

    def _finalize_ssh_session_lifecycles_before_close(self) -> None:
        """Drain SSH close work with one recovery retry, preserving its first failure."""

        if getattr(self, "_ssh_lifecycles_finalized", False):
            return
        activity_generator = getattr(self, "activity_generator", None)
        if activity_generator is None:
            self._ssh_lifecycles_finalized = True
            return
        finalizer = getattr(activity_generator, "finalize_ssh_session_lifecycles", None)
        if not callable(finalizer):
            raise RuntimeError("Activity generator has no SSH close-journal finalizer")

        primary: BaseException | None = None
        for attempt in range(2):
            try:
                if self.end_time is not None:
                    finalizer(self.end_time)
                self._assert_ssh_session_lifecycles_drained_before_close()
            except BaseException as error:
                if primary is None:
                    primary = error
                else:
                    primary.add_note(f"SSH close-journal retry also failed: {error!r}")
                try:
                    self._drain_exact_projection_recoveries_before_close()
                except BaseException as recovery_error:
                    primary.add_note(
                        "Exact projection recovery after SSH close failure also failed: "
                        f"{recovery_error!r}"
                    )
                    raise primary from recovery_error
                if attempt == 1:
                    raise primary from None
                continue

            self._ssh_lifecycles_finalized = True
            if primary is None:
                return
            try:
                # The recovered retry may itself have admitted terminal source
                # rows. Finish those while sinks remain open, but preserve the
                # caller-visible first failure.
                self._drain_exact_projection_recoveries_before_close()
                self._assert_ssh_session_lifecycles_drained_before_close()
            except BaseException as recovery_error:
                primary.add_note(
                    f"Terminal recovery after SSH close retry also failed: {recovery_error!r}"
                )
            raise primary

    def _assert_persistent_smb_terminal_state_before_close(self) -> None:
        """Reject synchronous SMB action residue before shared watermarks advance."""

        def assert_drained() -> None:
            capability = self._activity_terminal_capability(
                "assert_persistent_smb_terminal_state_drained",
                owner_attributes=(
                    "_persistent_smb_terminal_continuations",
                    "_smb_channel_manager",
                ),
                missing_message=(
                    "Activity generator has no persistent-SMB terminal-state assertion"
                ),
            )
            if capability is not None:
                capability()

        self._run_bounded_terminal_stage(
            completed_attribute="_persistent_smb_terminal_asserted",
            description="Persistent-SMB terminal assertion",
            operation=assert_drained,
        )

    def _finalize_application_channels_before_close(self) -> None:
        """Advance the one shared terminal application/network watermark."""

        def advance() -> None:
            capability = self._activity_terminal_capability(
                "advance_terminal_application_channel_watermark",
                owner_attributes=(
                    "_application_channel_registry",
                    "_network_transaction_runtime",
                ),
                missing_message=(
                    "Activity generator has no shared terminal application-channel watermark"
                ),
            )
            end_time = getattr(self, "end_time", None)
            if capability is not None:
                if end_time is None:
                    raise RuntimeError(
                        "Generation engine lost its terminal application-channel watermark"
                    )
                capability(end_time)

        self._run_bounded_terminal_stage(
            completed_attribute="_application_channels_finalized",
            description="Shared application-channel watermark",
            operation=advance,
        )

    def _finalize_foreground_lifecycles_before_close(self) -> None:
        """Finalize foreground process lifetimes as a restartable cleanup substage."""

        def finalize() -> None:
            capability = self._activity_terminal_capability(
                "finalize_foreground_process_lifetimes",
                owner_attributes=("_foreground_process_finalizers",),
                missing_message=("Activity generator has no foreground-process terminal finalizer"),
            )
            end_time = getattr(self, "end_time", None)
            if capability is not None:
                if end_time is None:
                    raise RuntimeError("Generation engine lost its foreground-process frontier")
                capability(end_time)

        self._run_bounded_terminal_stage(
            completed_attribute="_foreground_lifecycles_finalized",
            description="Foreground lifecycle finalization",
            operation=finalize,
        )

    def _finalize_terminal_runtime_cleanup_before_close(self) -> None:
        """Advance bounded process, lifecycle, network, and timing retention."""

        def finalize() -> None:
            capability = self._activity_terminal_capability(
                "finalize_terminal_runtime_state",
                owner_attributes=(
                    "_lifecycle_authority",
                    "_source_timing_planner",
                    "_network_transaction_runtime",
                ),
                missing_message="Activity generator has no terminal runtime cleanup",
            )
            end_time = getattr(self, "end_time", None)
            if capability is not None:
                if end_time is None:
                    raise RuntimeError("Generation engine lost its terminal runtime frontier")
                capability(end_time)

        self._run_bounded_terminal_stage(
            completed_attribute="_terminal_runtime_cleanup_finalized",
            description="Terminal runtime cleanup",
            operation=finalize,
        )

    def _finalize_exact_projection_recoveries_before_close(self) -> None:
        """Drain exact rows, then reassert persistent-SMB group/source ownership."""

        def finalize() -> None:
            self._drain_exact_projection_recoveries_before_close()
            capability = self._activity_terminal_capability(
                "assert_persistent_smb_projection_state_drained",
                owner_attributes=("_persistent_smb_terminal_continuations",),
                missing_message=(
                    "Activity generator has no persistent-SMB projection-state assertion"
                ),
            )
            if capability is not None:
                capability()

        self._run_bounded_terminal_stage(
            completed_attribute="_exact_projection_recoveries_finalized",
            description="Exact projection recovery",
            operation=finalize,
        )

    def _assert_terminal_transient_state_before_close(self) -> None:
        """Require the composite transient-owner census to be empty before shutdown."""

        def assert_drained() -> None:
            capability = self._activity_terminal_capability(
                "assert_terminal_transient_state_drained",
                owner_attributes=(
                    "_application_channel_registry",
                    "_lifecycle_authority",
                    "_source_timing_planner",
                ),
                missing_message="Activity generator has no composite terminal-state assertion",
            )
            if capability is not None:
                capability()

        self._run_bounded_terminal_stage(
            completed_attribute="_terminal_transient_census_asserted",
            description="Composite terminal transient assertion",
            operation=assert_drained,
        )

    def _drain_terminal_stages_before_close(self, *, include_foreground: bool) -> None:
        """Run every shared terminal stage in its single public shutdown order."""

        self._finalize_ssh_session_lifecycles_before_close()
        self._finalize_rdp_session_lifecycles_before_close()
        self._finalize_linux_sudo_logoffs_before_close()
        self._assert_persistent_smb_terminal_state_before_close()
        self._finalize_application_channels_before_close()
        if include_foreground:
            self._finalize_foreground_lifecycles_before_close()
        self._finalize_terminal_runtime_cleanup_before_close()
        self._finalize_exact_projection_recoveries_before_close()
        self._assert_terminal_transient_state_before_close()

    def _close_emitters(self, *, primary: BaseException | None = None) -> None:
        """Close every emitter, retaining a supplied lifecycle failure as primary."""

        failures: list[BaseException] = []
        snapshot = self._pin_terminal_owners()
        expected_emitters = dict(snapshot.emitters)
        self._expected_close_emitters = expected_emitters

        for format_name, emitter in expected_emitters.items():
            logger.info("Stopping %s emitter thread", format_name)
            if format_name in self._closed_emitter_names:
                continue
            try:
                emitter.close()
            except BaseException as error:
                failures.append(error)
            else:
                self._closed_emitter_names.add(format_name)
        if primary is not None:
            for failure in failures:
                primary.add_note(f"Emitter cleanup also failed: {failure!r}")
            return
        if failures:
            first, *additional = failures
            for failure in additional:
                first.add_note(f"Additional emitter cleanup failure: {failure!r}")
            raise first

    def _finalize(self, *, generation_succeeded: bool = True) -> None:
        """Finalize generation and close all emitters.

        Flushes remaining buffered events and closes emitter files.
        Phase 2.1: Gracefully stops emitter threads before closing.
        """
        if getattr(self, "_finalization_complete", False):
            return
        logger.info("Finalizing generation")

        if not generation_succeeded:
            self._finalization_aborted = True
            self._pin_terminal_owners()
            self._drain_terminal_stages_before_close(include_foreground=False)
            self._close_emitters()
            self._finalization_complete = True
            return
        if getattr(self, "_finalization_aborted", False):
            raise RuntimeError("Aborted generation cannot resume exact source finalization")

        snapshot = self._pin_terminal_owners()
        self._drain_terminal_stages_before_close(include_foreground=True)
        coordinator = snapshot.source_coordinator
        if coordinator is None:
            raise RuntimeError("Generation engine lost its source-finalization coordinator")
        coordinator.finalize()
        self._close_emitters()
        if not getattr(self, "_source_coordinator_closed", False):
            coordinator.mark_closed()
            self._source_coordinator_closed = True

        if not getattr(self, "_ids_alert_summary_applied", False):
            snort_emitter = self.emitters.get("snort_alert")
            ids_summary = getattr(snort_emitter, "ids_alert_summary", {})
            if ids_summary:
                self._apply_ids_alert_summary(ids_summary)
            self._ids_evaluation_summary = getattr(snort_emitter, "ids_evaluation_summary", None)
            self._ids_alert_summary_applied = True

        if self.activity_generator is not None:
            self.activity_generator.write_artifacts_manifest()

        from evidenceforge.events.collection_profile import write_collection_profile

        write_collection_profile(
            self.ground_truth_dir,
            self.scenario,
            self.output_target,
            workload_estimate=self.workload_estimate,
        )

        self._finalization_complete = True
        logger.info("All emitters closed")

    def _apply_ids_alert_summary(
        self,
        summary: dict[str, dict[int, dict[str, object]]],
    ) -> None:
        """Attach finalized sensor totals to ground truth and observation accounting."""
        for cluster_id, sid_totals in summary.items():
            filtered = sum(int(totals.get("policy_filtered", 0)) for totals in sid_totals.values())
            emitted_visible = sum(
                int(totals.get("emitted_visible", 0)) for totals in sid_totals.values()
            )
            emitted_delayed = sum(
                int(totals.get("emitted_delayed", 0)) for totals in sid_totals.values()
            )
            self.dispatcher.reconcile_ids_policy_filtering(
                cluster_id,
                emitted_visible=emitted_visible,
                emitted_delayed=emitted_delayed,
                policy_filtered=filtered,
            )
            for event in (*self.malicious_events, *self.red_herring_events):
                if event.get("storyline_cluster_id") != cluster_id:
                    continue
                attachments = event.get("ids_alerts")
                if not isinstance(attachments, list):
                    continue
                for attachment in attachments:
                    if not isinstance(attachment, dict):
                        continue
                    totals = sid_totals.get(attachment.get("sid"))
                    if totals is not None:
                        attachment.update(
                            {
                                key: totals[key]
                                for key in (
                                    "sid",
                                    "effective_policy",
                                    "candidate",
                                    "emitted",
                                    "policy_filtered",
                                )
                            }
                        )

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
            ids_evaluation_summary=getattr(self, "_ids_evaluation_summary", None),
            authored_intent_ledger=self.authored_intent_ledger,
            intent_execution_snapshot=self.intent_execution_ledger.snapshot(),
        )

        document = generator.build_document()
        generator.write_json(self.ground_truth_dir / GROUND_TRUTH_JSON_FILENAME, document)
        generator.generate(output_path, document)
        from evidenceforge.generation.storage_world import write_storage_manifest

        resolved_storage_targets = [
            {
                "section": section,
                "actor": event.get("actor"),
                "system": event.get("system"),
                "activity": event.get("activity"),
                "operations": event.get("operations", []),
                "batch_summary": event.get("batch_summary", {}),
            }
            for section, events in (
                ("storyline", self.malicious_events),
                ("red_herring", self.red_herring_events),
            )
            for event in events
            if event.get("type") == "smb_activity"
        ]
        write_storage_manifest(
            self.ground_truth_dir / "STORAGE_MANIFEST.json",
            self.storage_world,
            resolved_targets=resolved_storage_targets,
        )
        write_observation_manifest(
            self.ground_truth_dir / OBSERVATION_MANIFEST_FILENAME,
            self.scenario,
            source_evidence_status,
            source_deployment_digest=(
                self.source_deployment_compilation.digest
                if self.scenario.environment.observation_overrides
                else None
            ),
        )
        write_output_target_marker(self.ground_truth_dir, self.output_target)
        logger.info(f"Ground truth documentation generated: {output_path}")
