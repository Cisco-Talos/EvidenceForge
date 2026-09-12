# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Bundle-owned process creation and termination over existing runtime owners."""

from __future__ import annotations

import logging
import ntpath
import random
from contextlib import ExitStack
from dataclasses import dataclass, replace
from datetime import datetime, timedelta
from typing import TYPE_CHECKING

from evidenceforge.events.base import OccurrenceBuilder
from evidenceforge.events.contexts import (
    AuthContext,
    ProcessContext,
)
from evidenceforge.events.dispatcher import (
    ActionCohortEffectMemberBinding,
    EventDispatcher,
    PreparedDispatchStateIntent,
)
from evidenceforge.events.identity import (
    EventIdentityPlan,
)
from evidenceforge.events.lifecycle import (
    ActionLifecycleContext,
)
from evidenceforge.generation.actions import (
    EffectRequirement,
    ExecutionEffectPlanError,
    ExecutionEffectPlanErrorCode,
    ProcessExecutionRequest,
    ProcessTerminationRequest,
)
from evidenceforge.generation.activity.helpers import (
    _get_os_category,
    _get_rng,
)
from evidenceforge.generation.activity.process_helpers import (
    _PROCESS_ENDPOINT_ACTION_COHORT_MEMBER_LIMIT,
    _SYSTEM_ACCOUNT_LOGON_IDS,
    _SYSTEM_ACCOUNTS,
    _is_bare_windows_explorer_launch,
    _linux_foreground_lifetime,
    _linux_shell_process_reserves_foreground,
    _process_termination_delay_after_activity_seconds,
    _windows_service_process_account,
    normalize_process_command,
)
from evidenceforge.generation.activity.service_process_profiles import (
    matching_service_worker,
)
from evidenceforge.generation.deployment_registry import (
    LocalArtifactPublishToken,
)
from evidenceforge.generation.lifecycle_authority import (
    GeneratorLifecycleAuthority,
)
from evidenceforge.generation.runtime_content import (
    RuntimeContentIdentityManager,
)
from evidenceforge.generation.state_manager import (
    StateManager,
)
from evidenceforge.generation.windows_tokens import (
    windows_process_token_profile as _windows_token_profile,
)
from evidenceforge.models.exceptions import StateError
from evidenceforge.utils.rng import _stable_seed
from evidenceforge.utils.time import ensure_utc

if TYPE_CHECKING:
    from evidenceforge.generation.activity.generator import ActivityGenerator

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class ProcessExecutionService:
    """Ephemeral dependency binding; all durable state remains on existing owners."""

    runtime: ActivityGenerator
    state_manager: StateManager
    dispatcher: EventDispatcher
    lifecycle_authority: GeneratorLifecycleAuthority
    runtime_content_manager: RuntimeContentIdentityManager

    @classmethod
    def from_runtime(cls, runtime: ActivityGenerator) -> ProcessExecutionService:
        """Bind the existing state, dispatch, lifecycle, and content owners."""
        return cls(
            runtime,
            runtime.state_manager,
            runtime.dispatcher,
            runtime._lifecycle_authority,
            runtime._runtime_content_manager,
        )

    def create(self, request: ProcessExecutionRequest) -> int:
        """Execute the canonical process create path."""
        runtime = self.runtime

        prepared_effects = request.prepared_effects
        prepared_endpoint = prepared_effects.endpoint if prepared_effects is not None else None
        prepared_actor = prepared_effects.actor if prepared_effects is not None else None
        # Scanner transports still publish through the established post-process network path.
        # Keep their process/dependent rows on that same legacy boundary until one bounded
        # scanner transport collector can admit the complete probe group atomically.
        if prepared_endpoint is not None and prepared_actor is None:
            raise ExecutionEffectPlanError(
                ExecutionEffectPlanErrorCode.INVALID_PLAN,
                "prepared process endpoint effects lost their allocation-free actor",
            )
        uses_action_cohort = bool(
            prepared_endpoint is not None
            and prepared_actor is not None
            and runtime._process_endpoint_uses_action_cohort(
                actor=prepared_actor,
                admitted_effects=prepared_endpoint.admitted_effects,
                effect_plan=request.effect_plan,
            )
        )
        if uses_action_cohort:
            admitted_occurrence_count = sum(
                len(effect.spec.occurrence_times) for effect in prepared_endpoint.admitted_effects
            )
            if 1 + admitted_occurrence_count > _PROCESS_ENDPOINT_ACTION_COHORT_MEMBER_LIMIT:
                raise ExecutionEffectPlanError(
                    ExecutionEffectPlanErrorCode.INVALID_PLAN,
                    "process endpoint action cohort exceeds its root/occurrence member limit",
                )
        prepared_requires_new_root = bool(
            prepared_effects is not None
            and (
                prepared_effects.process_binary_publication is not None
                or (
                    prepared_effects.endpoint is not None
                    and any(
                        spec.requirement != EffectRequirement.OPTIONAL
                        for spec in prepared_effects.endpoint.specs
                    )
                )
            )
        )
        if prepared_actor is not None:
            expected_actor = runtime._prepare_process_effect_actor(
                replace(request, prepared_effects=None)
            )
            if expected_actor != prepared_actor:
                raise ExecutionEffectPlanError(
                    ExecutionEffectPlanErrorCode.INVALID_ACTOR,
                    "prepared process actor drifted before root allocation",
                )

        user = request.user
        system = request.system
        time = prepared_actor.started_at if prepared_actor is not None else request.time
        logon_id = prepared_actor.logon_id if prepared_actor is not None else request.logon_id
        process_name = prepared_actor.image if prepared_actor is not None else request.process_name
        command_line = (
            prepared_actor.command_line if prepared_actor is not None else request.command_line
        )
        parent_pid = request.parent_pid
        from_storyline = request.from_storyline
        allow_existing_browser_reuse = request.allow_existing_browser_reuse
        allow_browser_launch_spacing = request.allow_browser_launch_spacing
        concurrency_group_id = request.concurrency_group_id
        source_visible_by = request.source_visible_by

        if request.reuse_intent is not None:
            return runtime._execute_bounded_process_reuse(
                request=request,
                actor=(
                    prepared_actor
                    if prepared_actor is not None
                    else runtime._prepare_process_effect_actor(request)
                ),
            )

        profiled_worker = matching_service_worker(
            os_category=_get_os_category(system.os),
            image=process_name,
            command_line=command_line,
            username=user.username,
        )
        if profiled_worker is not None and not request.require_exact_parent:
            family_name, worker_name, _family = profiled_worker
            return runtime._ensure_profiled_service_worker(
                system=system,
                worker_time=time,
                activity_time=time,
                family_name=family_name,
                worker_name=worker_name,
                source_visible_by=source_visible_by,
            )

        session_end_plan = self.state_manager.get_session_end_plan(logon_id)
        if (
            session_end_plan is not None
            and session_end_plan.is_hard_deadline
            and ensure_utc(time) >= ensure_utc(session_end_plan.canonical_end)
        ):
            raise StateError(
                "Process activity cannot begin at or after its authoritative session end: "
                f"{system.hostname} logon_id={logon_id} time={ensure_utc(time).isoformat()}"
            )
        process_name, command_line, _exe_lower = normalize_process_command(
            process_name,
            command_line,
            os_category=_get_os_category(system.os),
            hostname=system.hostname,
        )

        # Determine integrity level per UAC model:
        # - SYSTEM processes: "System" (handled in generate_system_process)
        # - Explicitly elevated (admin tools, installers): "High"
        # - Everything else (including admin users under UAC): "Medium"
        _HIGH_INTEGRITY_EXES = {
            "msiexec.exe",
            "regedit.exe",
            "mmc.exe",
            "dism.exe",
            "pkgmgr.exe",
            "setup.exe",
            "install.exe",
            "procdump64.exe",
            "procdump.exe",
            "mimikatz.exe",
            "psexec.exe",
            "psexesvc.exe",
        }

        if _exe_lower in _HIGH_INTEGRITY_EXES:
            _integrity = "High"
        elif _get_os_category(system.os) == "windows" and any(
            marker in command_line.lower()
            for marker in ("sekurlsa::", "privilege::debug", "lsadump::", "token::elevate")
        ):
            _integrity = "High"
        else:
            _integrity = "Medium"
            # Browser child processes (renderers) run at Low integrity.
            # ~65% of browser children are sandboxed renderers (Low),
            # ~35% are GPU/utility processes (Medium).
            _BROWSER_EXES = {"chrome.exe", "msedge.exe", "firefox.exe"}
            if _exe_lower in _BROWSER_EXES:
                _parent_image = (
                    runtime._lookup_process_name(
                        system.hostname, parent_pid, _get_os_category(system.os)
                    )
                    or ""
                )
                _parent_exe = _parent_image.rsplit("\\", 1)[-1].rsplit("/", 1)[-1].lower()
                if _parent_exe in _BROWSER_EXES:
                    rng = _get_rng()
                    _integrity = "Low" if rng.random() < 0.65 else "Medium"

        if prepared_actor is not None:
            process_username = prepared_actor.username
            process_logon_id = prepared_actor.logon_id
        else:
            process_username, process_logon_id = runtime._resolve_process_identity(
                system=system,
                username=user.username,
                logon_id=logon_id,
                process_name=process_name,
                time=time,
            )
        service_process_account = _windows_service_process_account(process_name, command_line)
        if (
            prepared_actor is None
            and _get_os_category(system.os) == "windows"
            and service_process_account is not None
        ):
            process_username = service_process_account
            process_logon_id = _SYSTEM_ACCOUNT_LOGON_IDS[service_process_account]
            _integrity = "System"
        if (
            prepared_actor is not None
            and _get_os_category(system.os) == "linux"
            and process_logon_id == "0x3e7"
            and request.logon_id != "0x3e7"
            and runtime._linux_process_is_system_background_helper(process_name, command_line)
        ):
            _integrity = "System"
            parent_pid = runtime._linux_system_parent_fallback(system, time)
        linux_session_end_time = (
            self.state_manager.get_session_end_time(process_logon_id)
            if _get_os_category(system.os) == "linux" and process_logon_id
            else None
        )
        if (
            prepared_actor is None
            and linux_session_end_time is not None
            and ensure_utc(time) >= ensure_utc(linux_session_end_time)
            and runtime._linux_process_is_system_background_helper(process_name, command_line)
        ):
            process_username = runtime._linux_background_helper_username(
                process_name,
                command_line,
            )
            process_logon_id = "0x3e7"
            _integrity = "System"
            parent_pid = runtime._linux_system_parent_fallback(system, time)
        if prepared_actor is not None and (
            process_name != prepared_actor.image
            or command_line != prepared_actor.command_line
            or process_username != prepared_actor.username
            or process_logon_id != prepared_actor.logon_id
        ):
            raise ExecutionEffectPlanError(
                ExecutionEffectPlanErrorCode.INVALID_ACTOR,
                "resolved process identity drifted from its allocation-free prepared actor",
            )
        session_end_time = self.state_manager.get_session_end_time(process_logon_id)
        if (
            prepared_actor is None
            and session_end_time is not None
            and time >= session_end_time
            and process_logon_id not in _SYSTEM_ACCOUNT_LOGON_IDS.values()
        ):
            time = session_end_time - runtime._sample_profile_activity_gap(
                "windows.process_create_before_logoff",
                stable_id=request.stable_id,
                host=system.hostname,
                source="endpoint_process",
                lifecycle_id=process_logon_id,
                sample_key="before_logoff_gap",
            )
        session = self.state_manager.get_session(process_logon_id)
        process_logon_type = session.logon_type if session is not None else 2
        if prepared_actor is None and session is not None and time <= session.start_time:
            logon_gap = runtime._sample_activity_gap(
                relationship_key="activity.process.start_after_logon",
                stable_id=request.stable_id,
                minimum_ms=100,
                maximum_ms=1499,
                host=system.hostname,
                source="endpoint_process",
                lifecycle_id=process_logon_id,
                sample_key="after_logon_gap",
            )
            time = session.start_time + logon_gap
        explicit_parent = self.state_manager.get_process(system.hostname, parent_pid)
        if (
            prepared_actor is None
            and explicit_parent is not None
            and time <= explicit_parent.start_time
        ):
            parent_gap = runtime._sample_activity_gap(
                relationship_key="activity.process.start_after_parent",
                stable_id=request.stable_id,
                minimum_ms=50,
                maximum_ms=499,
                host=system.hostname,
                source="endpoint_process",
                lifecycle_id=process_logon_id,
                sample_key="after_parent_gap",
            )
            time = explicit_parent.start_time + parent_gap
        # A caller-supplied source deadline means this process owns an already
        # anchored causal occurrence (for example an SSH socket). Optional
        # human-spacing must not move the canonical start beyond that anchor.
        if prepared_actor is None and not from_storyline and source_visible_by is None:
            spaced_time = runtime._space_one_shot_cli_launch(
                system=system,
                username=process_username,
                logon_id=process_logon_id,
                process_name=process_name,
                command_line=command_line,
                time=time,
                source_visible_by=source_visible_by,
            )
            if spaced_time != time:
                time = spaced_time
            if allow_browser_launch_spacing:
                spaced_time = runtime._space_browser_launch(
                    system=system,
                    username=process_username,
                    logon_id=process_logon_id,
                    process_name=process_name,
                    command_line=command_line,
                    time=time,
                )
                if spaced_time != time:
                    time = spaced_time
        if (
            process_username != user.username
            and process_username not in _SYSTEM_ACCOUNTS
            and not (
                _get_os_category(system.os) == "linux"
                and process_logon_id == "0x3e7"
                and process_username in {"root", "www-data", "proxy", "postfix"}
            )
        ):
            _integrity = "Medium"
        if _get_os_category(system.os) == "windows" and process_logon_type == 5:
            _integrity = "High" if _integrity == "Medium" else _integrity
        if _get_os_category(system.os) == "windows":
            _integrity, _token_elevation, _mandatory_label = _windows_token_profile(
                process_username,
                _integrity,
            )
        else:
            _token_elevation = "%%1938"
            _mandatory_label = "S-1-16-8192"

        if (
            not prepared_requires_new_root
            and not from_storyline
            and source_visible_by is None
            and _get_os_category(system.os) == "windows"
            and _exe_lower == "explorer.exe"
            and _is_bare_windows_explorer_launch(process_name, command_line)
            and process_logon_id not in _SYSTEM_ACCOUNT_LOGON_IDS.values()
        ):
            explorer_pid = runtime._ensure_session_explorer_pid(
                system,
                runtime._user_model_for_username(process_username),
                time,
                process_logon_id,
            )
            if explorer_pid is not None:
                runtime._record_reused_process_optional_effects(prepared_effects)
                self.state_manager.update_process_activity_time(
                    system.hostname,
                    explorer_pid,
                    time,
                )
                return explorer_pid

        singleton_pid = (
            runtime._existing_windows_singleton_pid(system, process_name, time)
            if not prepared_requires_new_root and not request.require_exact_parent
            else None
        )
        if singleton_pid is not None:
            if not runtime._process_source_visible_by(
                system=system,
                pid=singleton_pid,
                deadline=source_visible_by,
            ):
                return 0
            runtime._record_reused_process_optional_effects(prepared_effects)
            self.state_manager.update_process_activity_time(
                system.hostname,
                singleton_pid,
                time,
            )
            return singleton_pid

        if (
            not prepared_requires_new_root
            and _get_os_category(system.os) == "windows"
            and explicit_parent is not None
            and ntpath.basename(explicit_parent.image).lower() == "services.exe"
        ):
            singleton_service_pid = runtime._existing_windows_singleton_service_pid(
                system=system,
                process_name=process_name,
                time=time,
                username=process_username,
                command_line=command_line,
            )
            if singleton_service_pid is not None:
                if not runtime._process_source_visible_by(
                    system=system,
                    pid=singleton_service_pid,
                    deadline=source_visible_by,
                ):
                    return 0
                runtime._record_reused_process_optional_effects(prepared_effects)
                running_proc = self.state_manager.get_process(
                    system.hostname, singleton_service_pid
                )
                if running_proc is not None:
                    self.state_manager.update_process_activity_time(
                        system.hostname,
                        singleton_service_pid,
                        time,
                    )
                return singleton_service_pid

        if not prepared_requires_new_root and not from_storyline:
            persistent_app_pid = runtime._existing_persistent_user_app_pid(
                system=system,
                username=process_username,
                logon_id=process_logon_id,
                process_name=process_name,
                command_line=command_line,
                time=time,
                source_visible_by=source_visible_by,
            )
            if persistent_app_pid is not None:
                if not runtime._process_source_visible_by(
                    system=system,
                    pid=persistent_app_pid,
                    deadline=source_visible_by,
                ):
                    return 0
                runtime._record_reused_process_optional_effects(prepared_effects)
                return persistent_app_pid

        if (
            not prepared_requires_new_root
            and not from_storyline
            and allow_existing_browser_reuse
            and source_visible_by is None
        ):
            browser_pid = runtime._existing_user_browser_pid(
                system=system,
                username=process_username,
                logon_id=process_logon_id,
                process_name=process_name,
                command_line=command_line,
                time=time,
                source_visible_by=source_visible_by,
            )
            if browser_pid is not None:
                if not runtime._process_source_visible_by(
                    system=system,
                    pid=browser_pid,
                    deadline=source_visible_by,
                ):
                    return 0
                runtime._record_reused_process_optional_effects(prepared_effects)
                return browser_pid

        if request.require_exact_parent:
            if not runtime._is_valid_process_parent_at(
                system=system,
                parent_pid=parent_pid,
                time=time,
            ) or not runtime._parent_process_matches_logon(
                hostname=system.hostname,
                parent_pid=parent_pid,
                logon_id=process_logon_id,
                os_category=_get_os_category(system.os),
            ):
                raise StateError(
                    "Exact authored process parent is not live in the child session: "
                    f"host={system.hostname} parent_pid={parent_pid} "
                    f"child={process_name!r}"
                )
        elif prepared_requires_new_root:
            parent_pid = runtime._resolve_existing_prepared_process_parent(
                system=system,
                user=user,
                time=time,
                logon_id=process_logon_id,
                parent_pid=parent_pid,
                process_username=process_username,
            )
        else:
            parent_pid = runtime._sanitize_user_parent_pid(
                system=system,
                user=user,
                time=time,
                logon_id=process_logon_id,
                process_name=process_name,
                command_line=command_line,
                parent_pid=parent_pid,
                process_username=process_username,
            )
            parent_pid = runtime._materialize_visible_linux_shell_parent_for_child(
                system=system,
                time=time,
                logon_id=process_logon_id,
                parent_pid=parent_pid,
                process_username=process_username,
            )
            parent_pid = runtime._repair_process_parent_pid(
                system=system,
                time=time,
                logon_id=process_logon_id,
                process_name=process_name,
                command_line=command_line,
                parent_pid=parent_pid,
                process_username=process_username,
            )
        if prepared_actor is not None and not runtime._is_valid_process_parent_at(
            system=system,
            parent_pid=parent_pid,
            time=time,
        ):
            # Legacy repair may select a future shell because non-prepared callers
            # can move the child after it. A prepared actor's start is immutable.
            parent_pid = runtime._resolve_existing_prepared_process_parent(
                system=system,
                user=user,
                time=time,
                logon_id=process_logon_id,
                parent_pid=parent_pid,
                process_username=process_username,
            )
        repaired_parent = self.state_manager.get_process(system.hostname, parent_pid)
        if (
            prepared_actor is None
            and repaired_parent is not None
            and time <= repaired_parent.start_time
        ):
            time = repaired_parent.start_time + timedelta(milliseconds=50)
        if (
            prepared_actor is None
            and _get_os_category(system.os) == "linux"
            and source_visible_by is None
            and _linux_shell_process_reserves_foreground(process_name, command_line)
            and _linux_foreground_lifetime(process_name, command_line) is not None
        ):
            time = runtime._reserve_foreground_shell_time(
                system=system,
                username=process_username,
                logon_id=process_logon_id,
                parent_pid=parent_pid,
                requested_time=ensure_utc(time),
                seed_text=command_line,
                concurrency_group_id=concurrency_group_id,
            )
            if time is None:
                return 0
            if (
                session_end_plan is not None
                and session_end_plan.is_hard_deadline
                and time >= ensure_utc(session_end_plan.canonical_end)
            ):
                raise StateError(
                    "Foreground process cannot begin after its owning shell session ends: "
                    f"{system.hostname} logon_id={process_logon_id} "
                    f"time={time.isoformat()}"
                )
        if not from_storyline:
            if source_visible_by is None:
                if prepared_actor is None:
                    spaced_time = runtime._space_interactive_shell_child_launch(
                        system=system,
                        process_name=process_name,
                        parent_pid=parent_pid,
                        time=time,
                    )
                    if spaced_time != time:
                        time = spaced_time

        # Drain independently committed due closes before freezing the root State and
        # source-timing fences. Running this after a timing overlay is sealed or claimed
        # would either stale that overlay or re-enter its locked canonical indexes.
        runtime._finalize_due_process_lifetimes(time, exhaust=False)

        # Phase 1: Freeze the exact PID/thread identity without consuming any allocator.
        process_session_id = runtime._session_id_for_logon(process_logon_id)
        process_session_identity = self.state_manager.get_session_identity(process_logon_id)
        action_cohort_builder = (
            self.state_manager.begin_action_cohort_materialization() if uses_action_cohort else None
        )
        if action_cohort_builder is not None:
            process_plan = action_cohort_builder.plan_process(
                system=system.hostname,
                parent_pid=parent_pid,
                image=process_name,
                command_line=command_line,
                username=process_username,
                integrity_level=_integrity,
                logon_id=process_logon_id,
                lifecycle_group_id=request.lifecycle_group_id or request.stable_id,
                concurrency_group_id=concurrency_group_id,
                os_category=_get_os_category(system.os),
                start_time=ensure_utc(time),
                parent_activity_time=(ensure_utc(time) if parent_pid not in {0, 4} else None),
                auth_session_id=process_session_id,
                auth_logon_type=process_logon_type,
            )
            endpoint_activity_frontier = max(
                ensure_utc(time),
                prepared_endpoint.latest_admitted_occurrence or ensure_utc(time),
            )
            action_cohort_builder.patch_process_activity(
                process_plan,
                endpoint_activity_frontier,
            )
            live_session = self.state_manager.get_session(process_logon_id)
            if live_session is not None and process_session_identity is not None:
                action_cohort_builder.patch_session_activity(
                    process_session_identity,
                    endpoint_activity_frontier,
                )
            action_cohort_state_plan = action_cohort_builder.seal()
        else:
            process_plan = self.state_manager.plan_process_materialization(
                system=system.hostname,
                parent_pid=parent_pid,
                image=process_name,
                command_line=command_line,
                username=process_username,
                integrity_level=_integrity,
                logon_id=process_logon_id,
                lifecycle_group_id=request.lifecycle_group_id or request.stable_id,
                concurrency_group_id=concurrency_group_id,
                os_category=_get_os_category(system.os),
                start_time=ensure_utc(time),
                parent_activity_time=ensure_utc(time),
            )
            action_cohort_state_plan = None
        process_identity = process_plan.identity
        pid = process_identity.pid
        parent_identity = self.state_manager.get_process_identity(
            system.hostname,
            process_identity.parent_pid,
        )

        # Phase 2: Build and validate the complete root/dependent publication batch.
        provisional_process_termination = (
            prepared_effects.provisional_termination if prepared_effects is not None else None
        )
        if (
            not uses_action_cohort
            and provisional_process_termination is None
            and _get_os_category(system.os) == "linux"
            and _linux_shell_process_reserves_foreground(process_name, command_line)
            and runtime._foreground_shell_key(
                system=system,
                username=process_identity.principal,
                logon_id=process_identity.logon_id,
                parent_pid=process_identity.parent_pid,
            )
            is not None
        ):
            provisional_lifetime = _linux_foreground_lifetime(process_name, command_line)
            if provisional_lifetime is not None:
                provisional_rng = random.Random(
                    _stable_seed(
                        "canonical-linux-foreground-lifetime:"
                        f"{system.hostname}:{pid}:{process_identity.started_at.isoformat()}:"
                        f"{command_line}"
                    )
                )
                provisional_process_termination = ensure_utc(
                    process_identity.started_at
                ) + timedelta(seconds=provisional_rng.uniform(*provisional_lifetime))
                session_deadline = self.state_manager.get_session_end_time(
                    process_identity.logon_id
                )
                if session_deadline is not None:
                    provisional_process_termination = min(
                        provisional_process_termination,
                        ensure_utc(session_deadline) - timedelta(milliseconds=25),
                    )
                provisional_process_termination = max(
                    provisional_process_termination,
                    ensure_utc(process_identity.started_at) + timedelta(milliseconds=25),
                )
        if (
            uses_action_cohort
            and provisional_process_termination is None
            and _get_os_category(system.os) == "linux"
            and _linux_shell_process_reserves_foreground(process_name, command_line)
            and runtime._foreground_shell_key(
                system=system,
                username=process_identity.principal,
                logon_id=process_identity.logon_id,
                parent_pid=process_identity.parent_pid,
            )
            is not None
        ):
            provisional_lifetime = _linux_foreground_lifetime(process_name, command_line)
            if provisional_lifetime is not None:
                raise ExecutionEffectPlanError(
                    ExecutionEffectPlanErrorCode.INVALID_PLAN,
                    "Linux foreground process reached allocation without a frozen close time",
                )
        process_binary_publication = (
            prepared_effects.process_binary_publication if prepared_effects is not None else None
        )
        event = OccurrenceBuilder(
            timestamp=time,
            event_type="process_create",
            src_host=runtime._build_host_context(system),
            auth=AuthContext(
                username=process_username,
                user_sid=runtime._get_sid(process_username),
                logon_id=process_logon_id,
                session_id=process_session_id,
                logon_type=process_logon_type,
                elevated=_integrity in {"High", "System"},
            ),
            process=ProcessContext(
                pid=pid,
                parent_pid=parent_pid,
                image=process_name,
                command_line=command_line,
                username=process_username,
                integrity_level=_integrity,
                logon_id=process_logon_id,
                parent_image=runtime._lookup_process_name(
                    system.hostname, parent_pid, _get_os_category(system.os)
                ),
                parent_command_line=runtime._lookup_parent_command_line(
                    system.hostname, parent_pid
                ),
                parent_start_time=runtime._lookup_parent_start_time(system.hostname, parent_pid),
                token_elevation=_token_elevation,
                mandatory_label=_mandatory_label,
                start_time=process_identity.started_at,
                current_directory=runtime._derive_current_directory(
                    system=system,
                    username=process_username,
                    process_name=process_name,
                    command_line=command_line,
                    parent_pid=parent_pid,
                    logon_type=process_logon_type,
                ),
                concurrency_group_id=concurrency_group_id,
                binary_identity=(
                    process_binary_publication.record.binary
                    if process_binary_publication is not None
                    else None
                ),
            ),
            storyline_origin=from_storyline,
            identity_plan=EventIdentityPlan(
                subject=process_identity,
                actor=parent_identity,
                session=(
                    process_session_identity if action_cohort_state_plan is not None else None
                ),
            ),
            lifecycle=ActionLifecycleContext(
                group_id=process_identity.lifecycle_group_id,
                canonical_start=process_identity.started_at,
                phase="start",
                parent_group_id=process_identity.parent_lifecycle_group_id or None,
            ),
        )

        endpoint_source_deadline = (
            prepared_endpoint.earliest_admitted_occurrence - timedelta(microseconds=1)
            if prepared_endpoint is not None
            and prepared_endpoint.earliest_admitted_occurrence is not None
            else None
        )
        effective_source_visible_by = (
            min(
                value
                for value in (source_visible_by, endpoint_source_deadline)
                if value is not None
            )
            if source_visible_by is not None or endpoint_source_deadline is not None
            else None
        )
        if (
            provisional_process_termination is not None
            and prepared_endpoint is not None
            and prepared_endpoint.latest_admitted_occurrence is not None
        ):
            provisional_process_termination = max(
                provisional_process_termination,
                prepared_endpoint.latest_admitted_occurrence + timedelta(milliseconds=25),
            )

        def dependent_artifact_publications(
            publication: LocalArtifactPublishToken | None,
        ) -> tuple[LocalArtifactPublishToken, ...]:
            """Bind the root binary plus a distinct dependent file publication."""

            publications: list[LocalArtifactPublishToken] = []
            if process_binary_publication is not None:
                publications.append(process_binary_publication)
            if publication is not None and publication is not process_binary_publication:
                publications.append(publication)
            return tuple(publications)

        with self.dispatcher.source_timing_planner.prepared_planning() as timing_preparation:
            if (
                prepared_effects is not None
                and prepared_effects.provisional_termination is not None
                and prepared_effects.lifetime_plan is not None
            ):
                lifetime_distribution, lifetime_relationship, _scope, _sample_key = (
                    runtime._process_provisional_termination_timing_request(
                        request,
                        prepared_effects.actor,
                        prepared_effects.lifetime_plan,
                    )
                )
                timing_preparation.planning_runtime.sampler.record_logical_sample(
                    lifetime_distribution,
                    relationship_key=lifetime_relationship,
                )
            runtime._plan_process_source_create_times(
                event,
                not_after=effective_source_visible_by,
            )

            endpoint_reconciliation = None
            endpoint_builders: tuple[
                tuple[OccurrenceBuilder, LocalArtifactPublishToken | None], ...
            ] = ()
            if prepared_endpoint is not None:
                endpoint_reconciliation, endpoint_builders = (
                    runtime._prepare_process_owned_endpoint_effects_for_publication(
                        system=system,
                        process_identity=process_identity,
                        process_closes_at=provisional_process_termination,
                        prepared=prepared_endpoint,
                        storyline_origin=from_storyline,
                        action_cohort_owned=action_cohort_state_plan is not None,
                    )
                )

            root_dispatch = self.dispatcher.prepare_builder(
                event,
                state_intent=(
                    PreparedDispatchStateIntent.EXTERNAL_ACTION_COHORT
                    if action_cohort_state_plan is not None
                    else PreparedDispatchStateIntent.EXTERNAL_MATERIALIZED_START
                ),
                lifecycle_ticket=(
                    action_cohort_state_plan
                    if action_cohort_state_plan is not None
                    else process_plan
                ),
                artifact_publications=(
                    (process_binary_publication,) if process_binary_publication is not None else ()
                ),
                source_timing_preparation=timing_preparation,
            )
            dependent_dispatches = tuple(
                self.dispatcher.prepare_builder(
                    builder,
                    state_intent=(
                        PreparedDispatchStateIntent.EXTERNAL_ACTION_COHORT
                        if action_cohort_state_plan is not None
                        else PreparedDispatchStateIntent.EXTERNAL_DEPENDENT
                    ),
                    lifecycle_ticket=(
                        action_cohort_state_plan
                        if action_cohort_state_plan is not None
                        else process_plan
                    ),
                    artifact_publications=dependent_artifact_publications(publication),
                    source_timing_preparation=timing_preparation,
                )
                for builder, publication in endpoint_builders
            )
        self.dispatcher.validate_prepared(root_dispatch)
        for dependent_dispatch in dependent_dispatches:
            self.dispatcher.validate_prepared(dependent_dispatch)

        artifact_publications = (
            prepared_effects.artifact_publications if prepared_effects is not None else ()
        )
        if artifact_publications and self.runtime_content_manager is None:
            raise ExecutionEffectPlanError(
                ExecutionEffectPlanErrorCode.INVALID_PLAN,
                "prepared process artifacts require the engine-owned runtime content manager",
            )
        reservation_ids = tuple(
            getattr(publication, "_reservation_id", 0) for publication in artifact_publications
        )
        if len(reservation_ids) != len(set(reservation_ids)):
            raise ExecutionEffectPlanError(
                ExecutionEffectPlanErrorCode.INVALID_PLAN,
                "prepared process artifacts contain a duplicate publication token",
            )

        if action_cohort_state_plan is not None:
            from evidenceforge.generation.actions.command_effects import (
                ExecutionEffectAuditCohortEntry,
            )

            if endpoint_reconciliation is None or prepared_endpoint is None:
                raise ExecutionEffectPlanError(
                    ExecutionEffectPlanErrorCode.INVALID_PLAN,
                    "process endpoint action cohort lost its exact reconciliation",
                )
            endpoint_effect_plan = prepared_endpoint.execution_plan
            if endpoint_effect_plan is None:
                raise ExecutionEffectPlanError(
                    ExecutionEffectPlanErrorCode.INVALID_PLAN,
                    "process endpoint action cohort lost its execution-effect plan",
                )
            effect_member_bindings = tuple(
                ActionCohortEffectMemberBinding(
                    entry_ordinal=0,
                    node_id=builder.effect_provenance.node_id,
                    occurrence_ordinal=builder.effect_provenance.occurrence_ordinal,
                    member=dependent_dispatch,
                )
                for (builder, _publication), dependent_dispatch in zip(
                    endpoint_builders,
                    dependent_dispatches,
                    strict=True,
                )
                if builder.effect_provenance is not None
            )
            try:
                action_cohort_batch = self.dispatcher.prepare_action_cohort_batch(
                    prepared_endpoint.root_anchor.action_id,
                    action_cohort_state_plan,
                    (root_dispatch, *dependent_dispatches),
                    (
                        ExecutionEffectAuditCohortEntry(
                            endpoint_effect_plan,
                            endpoint_reconciliation,
                        ),
                    ),
                    effect_member_bindings,
                    (),
                )
            except BaseException as primary:
                if not timing_preparation.committed:
                    runtime._reconcile_generator_cleanup(
                        primary,
                        "process action-cohort source timing",
                        timing_preparation.cancel,
                    )
                raise
            self.dispatcher.publish_prepared_action_cohort_batch(action_cohort_batch)
            running_proc = self.state_manager.get_process(system.hostname, pid)
            if running_proc is None:  # pragma: no cover - authenticated State result invariant
                raise StateError("Committed process action cohort did not publish its root")
        else:
            with timing_preparation.claimed_commit():
                with ExitStack() as artifact_stack:
                    artifact_commits = tuple(
                        artifact_stack.enter_context(
                            self.runtime_content_manager.registry.prepared_publication(publication)
                        )
                        for publication in artifact_publications
                    )

                    def finalize_prepared_capabilities() -> None:
                        for artifact_commit in artifact_commits:
                            artifact_commit.commit()
                        timing_preparation.commit_no_fail()

                    running_proc, materialization_receipt = (
                        self.lifecycle_authority.materialize_process(
                            process_plan,
                            finalize_external_no_fail=finalize_prepared_capabilities,
                        )
                    )

            self.dispatcher.publish_prepared(
                root_dispatch,
                materialization_receipt=materialization_receipt,
            )
            for dependent_dispatch in dependent_dispatches:
                self.dispatcher.publish_prepared(
                    dependent_dispatch,
                    materialization_receipt=materialization_receipt,
                )
            if endpoint_reconciliation is not None:
                runtime._execution_effect_audit.record(endpoint_reconciliation)

        if not from_storyline:
            runtime._remember_one_shot_cli_launch(
                system=system,
                username=process_username,
                logon_id=process_logon_id,
                process_name=process_name,
                command_line=command_line,
                time=time,
            )
        if running_proc.logon_id and action_cohort_state_plan is None:
            session = self.state_manager.get_session(running_proc.logon_id)
            if session is not None:
                session.last_activity_time = time
        runtime._record_process_source_create_time(
            system.hostname,
            pid,
            event,
            not_after=effective_source_visible_by,
        )
        if provisional_process_termination is not None:
            runtime._remember_foreground_process_finalizer(
                system=system,
                user=user,
                pid=pid,
                process_name=process_name,
                logon_id=running_proc.logon_id,
                termination_time=provisional_process_termination,
            )
        if _get_os_category(system.os) == "windows":
            runtime._emit_windows_process_startup_modules(
                user=user,
                system=system,
                time=time,
                pid=pid,
                process_name=process_name,
                from_storyline=from_storyline,
            )
        runtime._emit_process_command_network_effects(
            user=user,
            system=system,
            time=time,
            pid=pid,
            process_name=process_name,
            command_line=command_line,
            effect_plan=request.effect_plan,
        )

        runtime_image_load = (
            prepared_effects.runtime_image_load if prepared_effects is not None else None
        )
        if runtime_image_load is not None:
            runtime.generate_image_load(
                user=user,
                system=system,
                time=runtime_image_load.timestamp,
                pid=pid,
                image=process_name,
                dll_path=runtime_image_load.path,
                signed=runtime_image_load.signed,
                signature=runtime_image_load.signature,
                signature_status=runtime_image_load.signature_status,
                load_phase="runtime",
                from_storyline=from_storyline,
            )
        logger.debug(f"Generated process: {process_name} (PID: {pid}) on {system.hostname}")
        return pid


@dataclass(frozen=True)
class ProcessTerminationService:
    """Bind only the owners needed for termination, without new durable state."""

    runtime: ActivityGenerator
    state_manager: StateManager
    dispatcher: EventDispatcher

    @classmethod
    def from_runtime(cls, runtime: ActivityGenerator) -> ProcessTerminationService:
        """Bind existing process/session state and event dispatch."""
        return cls(runtime, runtime.state_manager, runtime.dispatcher)

    def terminate(self, request: ProcessTerminationRequest) -> None:
        """Execute the canonical process terminate path."""
        runtime = self.runtime

        user = request.user
        system = request.system
        time = request.time
        pid = request.pid
        process_name = request.process_name
        logon_id = request.logon_id
        from_storyline = request.from_storyline
        authoritative_end_plan = request.session_end_plan
        authoritative_latest_allowed: datetime | None = None

        running_proc = self.state_manager.get_process(system.hostname, pid)
        frozen_generic_close = runtime._frozen_generic_logoff_process_close(request, running_proc)
        frozen_generic_close_time = (
            frozen_generic_close.end_time if frozen_generic_close is not None else None
        )
        if frozen_generic_close_time is not None:
            time = frozen_generic_close_time
        if runtime._process_termination_recorded(
            system.hostname,
            pid,
            running_proc.start_time if running_proc is not None else None,
        ):
            return

        if (
            running_proc is not None
            and frozen_generic_close_time is None
            and running_proc.last_activity_time is not None
            and time <= running_proc.last_activity_time
        ):
            if authoritative_end_plan is not None and authoritative_end_plan.is_authoritative:
                time = ensure_utc(running_proc.last_activity_time) + timedelta(milliseconds=25)
            else:
                time = running_proc.last_activity_time + timedelta(
                    seconds=_process_termination_delay_after_activity_seconds(
                        hostname=system.hostname,
                        pid=pid,
                        last_activity_time=running_proc.last_activity_time,
                    )
                )
        if running_proc is not None:
            process_name = running_proc.image
        process_username = running_proc.username if running_proc is not None else user.username
        process_membership_logon_id = (
            running_proc.logon_id if running_proc is not None else logon_id
        )
        process_logon_id = (
            running_proc.token_logon_id or process_membership_logon_id
            if running_proc is not None
            else logon_id
        )
        owning_session = self.state_manager.get_session(process_membership_logon_id)
        lifecycle_session = self.state_manager.get_session(logon_id)
        if (
            lifecycle_session is not None
            and lifecycle_session.system == system.hostname
            and lifecycle_session.session_winlogon_pid == pid
        ):
            # winlogon keeps its SYSTEM token/LUID while remaining a member of
            # the interactive terminal session it bootstraps.  Use that
            # explicit relationship only for terminal-session metadata and
            # teardown timing, never to rewrite the process authentication ID.
            owning_session = lifecycle_session
        token_session = self.state_manager.get_session(process_logon_id)
        session_logon_type = (
            running_proc.auth_logon_type
            if running_proc is not None and running_proc.auth_logon_type is not None
            else token_session.logon_type
            if token_session is not None
            else 0
        )
        session_end_time = (
            self.state_manager.get_session_end_time(owning_session.logon_id)
            if owning_session is not None
            else None
        )
        if (
            owning_session is not None
            and owning_session.session_kind == "ssh"
            and owning_session.network_close_time is not None
            and owning_session.transport_pid != pid
        ):
            ssh_transport_end = ensure_utc(owning_session.network_close_time)
            session_end_time = (
                ssh_transport_end
                if session_end_time is None
                else min(ensure_utc(session_end_time), ssh_transport_end)
            )
        if (
            frozen_generic_close_time is None
            and session_end_time is not None
            and time >= session_end_time
        ):
            end_margin_ms = 150 + (
                _stable_seed(
                    f"process_terminate_before_logoff:{system.hostname}:{pid}:{process_logon_id}"
                )
                % 850
            )
            latest_allowed = session_end_time - timedelta(milliseconds=end_margin_ms)
            if running_proc is not None and running_proc.start_time >= latest_allowed:
                latest_allowed = running_proc.start_time + timedelta(milliseconds=100)
            if latest_allowed < session_end_time:
                time = min(time, latest_allowed)
        if authoritative_end_plan is not None and authoritative_end_plan.is_authoritative:
            deadline = ensure_utc(authoritative_end_plan.canonical_end)
            hold_until = runtime._process_connection_hold_until.get(
                runtime._process_instance_key(system.hostname, pid)
            )
            if hold_until is not None and ensure_utc(hold_until) >= deadline:
                raise StateError(
                    "Process connection hold extends beyond authoritative session end: "
                    f"{system.hostname} pid={pid} hold={ensure_utc(hold_until).isoformat()} "
                    f"end={deadline.isoformat()}"
                )
            if frozen_generic_close_time is not None:
                if frozen_generic_close_time >= deadline:
                    raise StateError(
                        "Generic logoff process close is not before its authoritative end"
                    )
            else:
                end_margin_ms = 25 + (
                    _stable_seed(
                        "process_terminate_before_authoritative_logoff:"
                        f"{system.hostname}:{pid}:{process_logon_id}:{deadline.isoformat()}"
                    )
                    % 176
                )
                authoritative_latest_allowed = deadline - timedelta(milliseconds=end_margin_ms)
                time = min(ensure_utc(time), authoritative_latest_allowed)
        else:
            time = runtime._held_process_termination_time(
                system=system,
                pid=pid,
                requested_time=time,
            )
        if not process_logon_id:
            if process_username in _SYSTEM_ACCOUNTS:
                process_logon_id = "0x3e7"
            else:
                resolved_username, resolved_logon_id = runtime._resolve_process_identity(
                    system=system,
                    username=process_username,
                    logon_id=logon_id,
                    process_name=process_name,
                    time=time,
                )
                process_username = resolved_username
                process_logon_id = resolved_logon_id or logon_id
        if authoritative_latest_allowed is None and frozen_generic_close_time is None:
            time = runtime._clamp_after_visible_process_create(
                system,
                pid,
                time,
                "windows.process_exit_after_visible_create",
            )
        elif authoritative_latest_allowed is not None:
            # Source-native ordering is planned below. It must not move the
            # canonical process lifecycle outside its authoritative session.
            time = min(ensure_utc(time), authoritative_latest_allowed)
        self.state_manager.get_process_object_id(system.hostname, pid)
        process_session_id = (
            running_proc.auth_session_id
            if running_proc is not None and running_proc.auth_session_id is not None
            else token_session.session_id
            if token_session is not None
            else 0
        )
        event = OccurrenceBuilder(
            timestamp=time,
            event_type="process_terminate",
            src_host=runtime._build_host_context(system),
            auth=AuthContext(
                username=process_username,
                user_sid=runtime._get_sid(process_username),
                logon_id=process_logon_id,
                session_id=process_session_id,
                logon_type=session_logon_type or 0,
            ),
            process=ProcessContext(
                pid=pid,
                parent_pid=0,
                image=process_name,
                command_line="",
                username=process_username,
                logon_id=process_logon_id,
                start_time=running_proc.start_time if running_proc is not None else None,
                concurrency_group_id=(
                    running_proc.concurrency_group_id if running_proc is not None else ""
                ),
            ),
            storyline_origin=from_storyline,
        )

        runtime._record_process_source_terminate_time(system.hostname, pid, event)
        if (
            running_proc is not None
            and _get_os_category(system.os) == "linux"
            and _linux_shell_process_reserves_foreground(
                running_proc.image,
                running_proc.command_line,
            )
            and runtime._foreground_shell_key(
                system=system,
                username=running_proc.username,
                logon_id=running_proc.logon_id,
                parent_pid=running_proc.parent_pid,
            )
            is not None
        ):
            runtime._discard_superseded_foreground_reservation(
                system=system, process=running_proc, termination_time=ensure_utc(event.timestamp)
            )
            runtime._remember_foreground_shell_available(
                system=system,
                username=running_proc.username,
                logon_id=running_proc.logon_id,
                parent_pid=running_proc.parent_pid,
                termination_time=ensure_utc(event.timestamp),
                seed_text=running_proc.command_line,
                concurrency_group_id=running_proc.concurrency_group_id,
            )
        self.dispatcher.dispatch_builder(event)
        termination_start_time = event.process.start_time if event.process is not None else None
        termination_key = (system.hostname, pid, termination_start_time)
        runtime._terminated_process_keys.add(termination_key)
        runtime._terminated_process_times[termination_key] = ensure_utc(event.timestamp)
        runtime._terminate_completed_one_shot_shell_parent(
            user=user,
            system=system,
            child=running_proc,
            child_termination_time=event.timestamp,
            from_storyline=from_storyline,
            session_end_plan=authoritative_end_plan,
        )

        logger.debug(
            f"Generated process termination: {process_name} (PID: {pid}) on {system.hostname}"
        )
