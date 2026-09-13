# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Resolve process actors and allocation-free preflight identity."""

from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import datetime, timedelta

from evidenceforge.generation.actions import (
    ExecutionEffectPlan,
    ExecutionEffectPlanError,
    ExecutionEffectPlanErrorCode,
    ProcessExecutionRequest,
    ScannerEffectIntent,
)
from evidenceforge.generation.actions.endpoint_effects import (
    PreparedEndpointEffect,
    PreparedProcessEffectActor,
)
from evidenceforge.generation.activity.helpers import _get_os_category
from evidenceforge.generation.activity.process_helpers import (
    _SYSTEM_ACCOUNT_LOGON_IDS as _SYSTEM_ACCOUNT_LOGON_IDS,
)
from evidenceforge.generation.activity.process_helpers import _SYSTEM_ACCOUNTS as _SYSTEM_ACCOUNTS
from evidenceforge.generation.activity.process_helpers import (
    _linux_foreground_lifetime as _linux_foreground_lifetime,
)
from evidenceforge.generation.activity.process_helpers import (
    _linux_shell_process_reserves_foreground as _linux_shell_process_reserves_foreground,
)
from evidenceforge.generation.activity.process_helpers import (
    _windows_service_process_account as _windows_service_process_account,
)
from evidenceforge.generation.activity.process_helpers import normalize_process_command
from evidenceforge.generation.lifecycle_authority import GeneratorLifecycleAuthority
from evidenceforge.generation.lifecycle_shadow import LifecycleShadow
from evidenceforge.generation.state_manager import StateManager
from evidenceforge.models.scenario import System, User
from evidenceforge.models.state import ActiveSession
from evidenceforge.utils.rng import _stable_seed
from evidenceforge.utils.time import ensure_utc

from . import policy
from .capabilities import ProcessIdentityCapabilities, WorkstationLogonLockedAtCapability
from .foreground import ProcessForegroundLifecycle
from .policy import (
    _WINDOWS_INTERACTIVE_SESSION_LOGON_TYPES,
    _WINDOWS_USER_SESSION_PROCESSES,
    _session_source_ready_time,
    _session_started_by,
)
from .queries import ProcessStateQueries
from .scheduling import ProcessLaunchScheduler

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class ProcessActorResolver:
    """Ephemeral operations; injected maps and managers remain on their existing owners."""

    _lifecycle_authority: GeneratorLifecycleAuthority
    _scenario_start_time: datetime | None
    _workstation_logon_locked_at: WorkstationLogonLockedAtCapability
    state_manager: StateManager
    scheduling: ProcessLaunchScheduler
    foreground: ProcessForegroundLifecycle
    queries: ProcessStateQueries
    identity: ProcessIdentityCapabilities

    def _prepare_process_effect_actor(
        self,
        request: ProcessExecutionRequest,
    ) -> PreparedProcessEffectActor:
        """Resolve the root actor and start fence without mutating runtime state."""

        system = request.system
        process_name, command_line, exe_lower = normalize_process_command(
            request.process_name,
            request.command_line,
            os_category=_get_os_category(system.os),
            hostname=system.hostname,
        )

        started_at = ensure_utc(request.time)
        process_username, process_logon_id = self._resolve_process_identity(
            system=system,
            username=request.user.username,
            logon_id=request.logon_id,
            process_name=process_name,
            time=started_at,
        )
        service_account = _windows_service_process_account(process_name, command_line)
        if _get_os_category(system.os) == "windows" and service_account is not None:
            process_username = service_account
            process_logon_id = _SYSTEM_ACCOUNT_LOGON_IDS[service_account]
        if (
            _get_os_category(system.os) == "linux"
            and process_logon_id
            and (session_end := self.state_manager.get_session_end_time(process_logon_id))
            is not None
            and started_at >= ensure_utc(session_end)
            and policy._linux_process_is_system_background_helper(process_name, command_line)
        ):
            process_username = policy._linux_background_helper_username(process_name, command_line)
            process_logon_id = "0x3e7"

        session = self.state_manager.get_session(process_logon_id)
        session_end_plan = self.state_manager.get_session_end_plan(process_logon_id)
        session_deadline = self.state_manager.get_session_end_time(process_logon_id)
        if (
            session is not None
            and session.session_kind.casefold() == "ssh"
            and session.network_close_time is not None
        ):
            network_close_deadline = ensure_utc(session.network_close_time)
            session_deadline = (
                network_close_deadline
                if session_deadline is None
                else min(ensure_utc(session_deadline), network_close_deadline)
            )
        if session_end_plan is not None and session_end_plan.is_hard_deadline:
            planned_deadline = ensure_utc(session_end_plan.canonical_end)
            session_deadline = (
                planned_deadline
                if session_deadline is None
                else min(ensure_utc(session_deadline), planned_deadline)
            )
        if (
            session_end_plan is not None
            and session_end_plan.is_hard_deadline
            and started_at >= ensure_utc(session_end_plan.canonical_end)
        ):
            deadline = ensure_utc(session_end_plan.canonical_end)
            raise ExecutionEffectPlanError(
                ExecutionEffectPlanErrorCode.INVALID_ACTOR,
                "prepared process actor begins at or after its authoritative session end: "
                f"host={system.hostname} logon_id={process_logon_id} image={process_name!r} "
                f"started_at={started_at.isoformat()} deadline={deadline.isoformat()}",
            )
        if session_deadline is not None and started_at >= ensure_utc(session_deadline):
            deadline = ensure_utc(session_deadline)
            raise ExecutionEffectPlanError(
                ExecutionEffectPlanErrorCode.INVALID_ACTOR,
                "prepared process actor begins at or after its session deadline: "
                f"host={system.hostname} logon_id={process_logon_id} image={process_name!r} "
                f"started_at={started_at.isoformat()} deadline={deadline.isoformat()}",
            )
        if session is not None and started_at <= ensure_utc(session.start_time):
            offset_ms = 100 + (
                _stable_seed(
                    f"process_after_logon:{system.hostname}:{process_logon_id}:{process_name}"
                )
                % 1400
            )
            started_at = ensure_utc(session.start_time) + timedelta(milliseconds=offset_ms)
        is_linux_login_shell = (
            _get_os_category(system.os) == "linux"
            and exe_lower in {"bash", "sh", "zsh"}
            and command_line.strip() == f"-{exe_lower}"
        )
        if (
            _get_os_category(system.os) == "linux"
            and session is not None
            and session.session_kind.casefold() == "ssh"
            and not is_linux_login_shell
        ):
            shell_ready = self._linux_ssh_process_shell_ready_time(
                system=system,
                session=session,
                username=process_username,
                parent_pid=request.parent_pid,
                activity_time=started_at,
            )
            if started_at <= shell_ready:
                started_at = shell_ready + timedelta(milliseconds=50)
        parent = self.state_manager.get_process(system.hostname, request.parent_pid)
        if parent is not None and started_at <= ensure_utc(parent.start_time):
            offset_ms = 50 + (
                _stable_seed(
                    f"process_after_parent:{system.hostname}:{request.parent_pid}:{process_name}:"
                    f"{command_line}"
                )
                % 450
            )
            started_at = ensure_utc(parent.start_time) + timedelta(milliseconds=offset_ms)

        if not request.from_storyline and request.source_visible_by is None:
            started_at = self.scheduling._preview_one_shot_cli_launch(
                system=system,
                username=process_username,
                logon_id=process_logon_id,
                process_name=process_name,
                command_line=command_line,
                time=started_at,
            )
            if request.allow_browser_launch_spacing:
                started_at = self.scheduling._preview_browser_launch(
                    system=system,
                    username=process_username,
                    logon_id=process_logon_id,
                    process_name=process_name,
                    command_line=command_line,
                    time=started_at,
                )
        if (
            _get_os_category(system.os) == "linux"
            and request.source_visible_by is None
            and not request.from_storyline
            and _linux_shell_process_reserves_foreground(process_name, command_line)
            and _linux_foreground_lifetime(process_name, command_line) is not None
        ):
            started_at = self.foreground._reserve_foreground_shell_time(
                system=system,
                username=process_username,
                logon_id=process_logon_id,
                parent_pid=request.parent_pid,
                requested_time=started_at,
                seed_text=command_line,
                concurrency_group_id=request.concurrency_group_id,
            )
            if started_at is None:
                raise ExecutionEffectPlanError(
                    ExecutionEffectPlanErrorCode.INVALID_ACTOR,
                    "process parent shell has a foreground command without a modeled release",
                )
        if not request.from_storyline and request.source_visible_by is None:
            started_at = self.scheduling._space_interactive_shell_child_launch(
                system=system,
                process_name=process_name,
                parent_pid=request.parent_pid,
                time=started_at,
            )
        effective_deadline = ensure_utc(session_deadline) if session_deadline is not None else None
        if effective_deadline is not None and started_at >= effective_deadline:
            raise ExecutionEffectPlanError(
                ExecutionEffectPlanErrorCode.INVALID_ACTOR,
                "prepared process actor leaves no session interval after launch spacing: "
                f"host={system.hostname} logon_id={process_logon_id} image={process_name!r} "
                f"started_at={started_at.isoformat()} deadline={effective_deadline.isoformat()}",
            )
        return PreparedProcessEffectActor(
            hostname=system.hostname,
            image=process_name,
            command_line=command_line,
            username=process_username,
            logon_id=process_logon_id,
            lifecycle_id=request.lifecycle_group_id or request.stable_id,
            started_at=started_at,
            session_deadline=effective_deadline,
        )

    def _resolve_process_identity(
        self,
        *,
        system: System,
        username: str,
        logon_id: str,
        process_name: str,
        time: datetime,
    ) -> tuple[str, str]:
        """Resolve process owner/logon before emitters render cross-source evidence."""
        if _get_os_category(system.os) != "windows":
            return username, logon_id

        exe_name = process_name.rsplit("\\", 1)[-1].rsplit("/", 1)[-1].lower()
        normalized_username = username.upper().split("\\")[-1]
        if (
            normalized_username in _SYSTEM_ACCOUNT_LOGON_IDS
            and exe_name not in _WINDOWS_USER_SESSION_PROCESSES
        ):
            return normalized_username, _SYSTEM_ACCOUNT_LOGON_IDS[normalized_username]
        if (
            exe_name not in _WINDOWS_USER_SESSION_PROCESSES
            or normalized_username not in _SYSTEM_ACCOUNTS
        ):
            return username, logon_id

        session = self._active_interactive_windows_session(system, time)
        if session is None:
            return username, logon_id
        return session.username, session.logon_id

    def _active_interactive_windows_session(
        self,
        system: System,
        time: datetime,
    ) -> ActiveSession | None:
        """Return the newest user-owned interactive Windows session on a host."""
        if _get_os_category(system.os) != "windows":
            return None

        candidates = [
            session
            for session in self.state_manager.get_active_sessions_on_system_at(
                system.hostname,
                time,
            )
            if (
                session.username not in _SYSTEM_ACCOUNTS
                and not session.username.endswith("$")
                and session.logon_type in _WINDOWS_INTERACTIVE_SESSION_LOGON_TYPES
                and session.session_kind not in {"network", "service"}
                and _session_started_by(session, time)
                and not self._workstation_logon_locked_at(
                    system,
                    session.username,
                    session.logon_id,
                    time,
                )
            )
        ]
        if not candidates:
            return None

        assigned_user = getattr(system, "assigned_user", None)
        if assigned_user:
            assigned_candidates = [
                session for session in candidates if session.username == assigned_user
            ]
            if assigned_candidates:
                candidates = assigned_candidates
        return max(candidates, key=lambda session: session.start_time)

    def _linux_ssh_process_shell_ready_time(
        self,
        *,
        system: System,
        session: ActiveSession,
        username: str,
        parent_pid: int,
        activity_time: datetime,
    ) -> datetime:
        """Return the actual or deterministically planned SSH shell readiness."""

        explicit_parent = self.state_manager.get_process(system.hostname, parent_pid)
        if (
            explicit_parent is not None
            and explicit_parent.logon_id == session.logon_id
            and explicit_parent.image.rsplit("/", 1)[-1].casefold() in {"bash", "sh", "zsh"}
        ):
            return ensure_utc(explicit_parent.start_time)

        session_shell = (
            self.state_manager.get_process(system.hostname, session.session_shell_pid)
            if session.session_shell_pid is not None
            else None
        )
        if (
            session_shell is not None
            and session_shell.logon_id == session.logon_id
            and session_shell.image.rsplit("/", 1)[-1].casefold() in {"bash", "sh", "zsh"}
        ):
            return ensure_utc(session_shell.start_time)

        _, shell_ready = self._linux_ssh_session_shell_times(
            user=self.identity.user_for_username(username),
            target_system=system,
            session=session,
            logon_time=session.start_time,
            activity_time=activity_time,
        )
        return shell_ready

    def _derive_current_directory(
        self,
        system: System,
        username: str,
        process_name: str,
        command_line: str,
        parent_pid: int,
        logon_type: int = 2,
    ) -> str:
        """Derive a source-native process working directory for Sysmon Event 1."""
        if _get_os_category(system.os) != "windows":
            account = username.split("\\")[-1]
            return (
                "/root" if account in _SYSTEM_ACCOUNTS or account == "root" else f"/home/{account}"
            )

        image = process_name.replace("/", "\\")
        image_lower = image.lower()
        exe = image_lower.rsplit("\\", 1)[-1]
        profile_dir = policy._user_profile_directory(username)
        system_dir = r"C:\Windows\System32"

        if username in _SYSTEM_ACCOUNTS or username.endswith("$"):
            return system_dir + "\\"
        if logon_type == 5:
            return system_dir + "\\"

        parent_image = (
            self.queries._lookup_process_name(
                system.hostname, parent_pid, _get_os_category(system.os)
            )
            or ""
        ).lower()
        parent_dir = parent_image.rsplit("\\", 1)[0] if "\\" in parent_image else ""

        if exe in {"winword.exe", "excel.exe", "powerpnt.exe", "acrord32.exe", "acrobat.exe"}:
            if '"' in command_line:
                for candidate in command_line.split('"')[1::2]:
                    if "\\" in candidate:
                        return candidate.rsplit("\\", 1)[0] + "\\"
            return profile_dir + "\\Documents\\"

        if exe in {"onedrive.exe", "teams.exe", "outlook.exe"}:
            return profile_dir + "\\"

        if exe in {
            "cargo.exe",
            "docker.exe",
            "git.exe",
            "kubectl.exe",
            "node.exe",
            "npm.cmd",
            "npm.exe",
            "ssh.exe",
        }:
            if exe == "ssh.exe":
                return profile_dir + "\\"
            repo_names = (
                "clinical-portal",
                "integration-api",
                "ops-automation",
                "platform-services",
                "security-tools",
            )
            repo = repo_names[
                _stable_seed(
                    f"windows_project_cwd:{system.hostname}:{username}:{process_name}:"
                    f"{command_line}"
                )
                % len(repo_names)
            ]
            return profile_dir + f"\\source\\repos\\{repo}\\"

        if exe in {"chrome.exe", "msedge.exe", "firefox.exe"}:
            install_dir = image.rsplit("\\", 1)[0] if "\\" in image else ""
            if parent_dir and parent_dir == install_dir.lower():
                return install_dir + "\\"
            return profile_dir + "\\"

        if exe in {"cmd.exe", "powershell.exe", "pwsh.exe"}:
            if parent_dir and "windows\\system32" not in parent_dir:
                return parent_dir + "\\"
            return profile_dir + "\\"

        if "\\windows\\system32\\" in image_lower or "\\windows\\syswow64\\" in image_lower:
            return system_dir + "\\"

        if "\\" in image:
            return image.rsplit("\\", 1)[0] + "\\"

        return profile_dir + "\\"

    def _process_endpoint_uses_action_cohort(
        self,
        *,
        actor: PreparedProcessEffectActor,
        admitted_effects: tuple[PreparedEndpointEffect, ...],
        effect_plan: ExecutionEffectPlan | None,
    ) -> bool:
        """Select the exact endpoint publication boundary without mutating an owner."""

        from evidenceforge.generation.actions.command_effects import (
            FileEffectIntent,
            RegistryEffectIntent,
        )

        has_scanner_effect_intent = effect_plan is not None and any(
            isinstance(node.intent, ScannerEffectIntent) for node in effect_plan.nodes
        )
        has_non_single_endpoint_effect = any(
            isinstance(effect.spec.intent, (FileEffectIntent, RegistryEffectIntent))
            and effect.spec.intent.occurrence_cardinality != 1
            for effect in admitted_effects
        )
        state_session = self.state_manager.get_session(actor.logon_id) if actor.logon_id else None
        state_session_identity = (
            self.state_manager.get_session_identity(actor.logon_id)
            if state_session is not None
            else None
        )
        lifecycle_session_snapshot = (
            self._lifecycle_authority.registry.get_session(state_session_identity.object_id)
            if state_session_identity is not None
            else None
        )
        session_requires_legacy_endpoint_path = state_session is not None and (
            state_session_identity is None
            or lifecycle_session_snapshot is None
            or lifecycle_session_snapshot.identity
            != LifecycleShadow.project_session_start(state_session_identity)
        )
        if has_scanner_effect_intent and has_non_single_endpoint_effect:
            raise ExecutionEffectPlanError(
                ExecutionEffectPlanErrorCode.INVALID_PLAN,
                "scanner process endpoint effects require exactly one occurrence on the "
                "legacy publication path",
            )
        if session_requires_legacy_endpoint_path and has_non_single_endpoint_effect:
            raise ExecutionEffectPlanError(
                ExecutionEffectPlanErrorCode.INVALID_PLAN,
                "process endpoint effects require exactly one occurrence when the owning "
                "State session lacks exact lifecycle-registry identity",
            )
        return not has_scanner_effect_intent and not session_requires_legacy_endpoint_path

    def _linux_ssh_session_shell_times(
        self,
        *,
        user: User,
        target_system: System,
        session: ActiveSession,
        logon_time: datetime,
        activity_time: datetime,
    ) -> tuple[datetime, datetime]:
        """Preview the deterministic receiver and login-shell canonical times."""

        logon_time = ensure_utc(logon_time)
        activity_time = ensure_utc(activity_time)
        scenario_start = getattr(self, "_scenario_start_time", None)
        if scenario_start is not None:
            scenario_start = ensure_utc(scenario_start)
        shell_seed = _stable_seed(
            "linux_ssh_session_shell:"
            f"{target_system.hostname}:{user.username}:{session.logon_id}:"
            f"{logon_time.isoformat()}"
        )
        source_ready_time = _session_source_ready_time(session)
        source_floor = logon_time + timedelta(milliseconds=150)
        if source_ready_time is not None:
            source_floor = max(source_floor, source_ready_time + timedelta(milliseconds=50))
        sshd_delay_ms = 900 + (shell_seed % 1400)
        sshd_time = max(logon_time + timedelta(milliseconds=sshd_delay_ms), source_floor)
        if (
            scenario_start is not None
            and activity_time >= scenario_start
            and sshd_time < scenario_start
        ):
            pre_command_gap = timedelta(seconds=5 + (shell_seed % 95))
            scenario_floor = scenario_start + timedelta(milliseconds=500 + (shell_seed % 3000))
            sshd_time = max(scenario_floor, activity_time - pre_command_gap)
        effective_activity_time = max(activity_time, sshd_time + timedelta(milliseconds=700))
        latest_parent_time = effective_activity_time - timedelta(milliseconds=500)
        if sshd_time > latest_parent_time and latest_parent_time >= source_floor:
            sshd_time = max(logon_time + timedelta(milliseconds=150), latest_parent_time)

        bash_time = sshd_time + timedelta(milliseconds=120 + (shell_seed % 180))
        effective_activity_time = max(activity_time, bash_time + timedelta(milliseconds=260))
        latest_bash_time = effective_activity_time - timedelta(milliseconds=120)
        if bash_time > latest_bash_time and latest_bash_time >= sshd_time + timedelta(
            milliseconds=20
        ):
            bash_time = max(sshd_time + timedelta(milliseconds=20), latest_bash_time)
        return sshd_time, bash_time
