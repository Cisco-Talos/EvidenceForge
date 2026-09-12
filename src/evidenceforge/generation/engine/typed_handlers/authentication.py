# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Typed storyline authentication handlers."""

from __future__ import annotations

from types import SimpleNamespace
from typing import TYPE_CHECKING, Any

from evidenceforge.generation.activity.helpers import _get_os_category
from evidenceforge.models.exceptions import StateError
from evidenceforge.models.scenario import (
    CredentialSprayEventSpec,
    ExplicitCredentialsEventSpec,
    FailedLogonEventSpec,
    LogoffEventSpec,
    LogonEventSpec,
    RdpSessionEventSpec,
    SshSessionEventSpec,
    WorkstationLockEventSpec,
    WorkstationUnlockEventSpec,
)
from evidenceforge.utils.rng import _stable_seed
from evidenceforge.utils.time import parse_duration

from .context import TypedEventContext

if TYPE_CHECKING:
    from evidenceforge.generation.engine.storyline import StorylineMixin


def handle_logon(
    self: StorylineMixin, spec: LogonEventSpec, context: TypedEventContext
) -> dict[str, Any] | None:
    """Execute the logon evidence path using the existing runtime owners."""
    actor = context.actor
    system = context.system
    time = context.time
    rng = context.rng
    malicious_event = context.malicious_event
    session_end_plan = self._session_end_plan_for_current_start()
    if (
        spec.logon_type == 10
        and _get_os_category(system.os) == "windows"
        and spec.source_ip not in {"-", system.ip}
    ):
        session_end_plan = self._authored_rdp_session_end_plan()
    if spec.logon_type == 9:
        caller, caller_logon_id = self._storyline_new_credentials_caller(
            actor,
            system,
            time,
        )
        outbound_domain = self.activity_generator._explicit_credentials_target_domain(
            actor.username,
            system.hostname,
            system,
        )
        logon_id = self.activity_generator._emit_new_credentials_logon(
            user=caller,
            system=system,
            time=time,
            caller_logon_id=caller_logon_id,
            outbound_username=actor.username,
            outbound_domain=outbound_domain,
            lifecycle_group_id=(
                f"storyline:{getattr(self, '_current_storyline_spec_id', 'logon')}"
            ),
        )
        source_ip = "-"
    else:
        source_ip = (
            spec.source_ip
            or self.public_identity_registry.bind(
                "external_logon",
                f"storyline-logon:{actor.username}:{system.hostname}:{time.isoformat()}",
            ).ip
        )
        logon_id = self.activity_generator.generate_logon(
            user=actor,
            system=system,
            time=time,
            logon_type=spec.logon_type,
            source_ip=source_ip,
            session_end_plan=session_end_plan,
        )
    # Protect storyline-created sessions from baseline logoff
    session = self.state_manager.get_session(logon_id)
    if session:
        session.storyline_protected = True
        if getattr(session, "session_kind", "") in {"rdp", "ssh"}:
            self._record_storyline_session_ready(
                system=system,
                actor=actor,
                session=session,
                rng=rng,
            )
    malicious_event["logon_id"] = logon_id
    malicious_event["source_ip"] = source_ip
    self._record_storyline_logon(actor, system, logon_id, source_ip=source_ip)

    return context.malicious_event


def handle_failed_logon(
    self: StorylineMixin, spec: FailedLogonEventSpec, context: TypedEventContext
) -> dict[str, Any] | None:
    """Execute the failed_logon evidence path using the existing runtime owners."""
    actor = context.actor
    system = context.system
    time = context.time
    malicious_event = context.malicious_event
    source_ip = (
        spec.source_ip
        or self.public_identity_registry.bind(
            "failed_logon",
            f"storyline-failed-logon:{actor.username}:{system.hostname}:{time.isoformat()}",
        ).ip
    )
    dc = next(
        (s for s in self.scenario.environment.systems if s.type == "domain_controller"),
        None,
    )
    self.activity_generator.generate_failed_logon(
        user=actor,
        system=system,
        time=time,
        logon_type=spec.logon_type,
        source_ip=source_ip,
        target_username=getattr(spec, "target_username", None),
        dc_system=dc,
    )
    malicious_event["source_ip"] = source_ip

    return context.malicious_event


def handle_logoff(
    self: StorylineMixin, spec: LogoffEventSpec, context: TypedEventContext
) -> dict[str, Any] | None:
    """Execute the logoff evidence path using the existing runtime owners."""
    actor = context.actor
    system = context.system
    time = context.time
    paired_close = self._session_end_plan_for_current_logoff()
    if paired_close is not None:
        logon_id, session_end_plan = paired_close
        target_session = self.state_manager.get_session(logon_id)
        if target_session is None or target_session.system != system.hostname:
            raise StateError(
                f"Explicit storyline logoff {session_end_plan.storyline_event_id} "
                f"lost its paired session {logon_id} on {system.hostname}"
            )
        self.activity_generator.generate_logoff(
            actor,
            system,
            session_end_plan.canonical_end,
            logon_id,
            from_storyline=True,
            session_end_plan=session_end_plan,
        )
    else:
        logon_id = self._last_storyline_logon_for_actor_system(
            actor,
            system,
            at_time=time,
        )
        if logon_id is not None:
            self.activity_generator.generate_logoff(
                actor,
                system,
                time,
                logon_id,
                from_storyline=True,
            )

    return context.malicious_event


def handle_ssh_session(
    self: StorylineMixin, spec: SshSessionEventSpec, context: TypedEventContext
) -> dict[str, Any] | None:
    """Execute the ssh_session evidence path using the existing runtime owners."""
    from evidenceforge.generation.engine.storyline_helpers.ids import (
        _build_ids_alert_contexts,
        _ids_attachment_ground_truth,
    )

    actor = context.actor
    system = context.system
    time = context.time
    session_required_until = context.session_required_until
    rng = context.rng
    malicious_event = context.malicious_event
    _ground_truth_uid = context._ground_truth_uid
    target = next((s for s in self.scenario.environment.systems if s.ip == system.ip), system)
    authored_ids_alerts = _build_ids_alert_contexts(
        getattr(spec, "ids_alerts", []),
        time=time,
        src_ip=spec.source_ip or system.ip,
        dst_ip=target.ip,
        dst_port=22,
        proto="tcp",
        rng=rng,
        source="storyline_ssh_session",
    )
    session_end_plan = self._session_end_plan_for_current_start()
    if hasattr(self, "world_planner"):
        source_system = (
            self.world_model.system_for_ip(spec.source_ip)
            if spec.source_ip and hasattr(self, "world_model")
            else None
        )
        result = self.world_planner.bootstrap_user_session(
            user=actor,
            target_system=target,
            time=time,
            rng=rng,
            session_kind="ssh",
            source_system=source_system,
            allow_existing=False,
            source_ip_override=spec.source_ip,
            storyline_protected=True,
            required_until=session_required_until,
            session_end_plan=session_end_plan,
            ids_alerts=authored_ids_alerts,
        )
    else:
        source_ip = spec.source_ip or system.ip
        uid = self.activity_generator.generate_ssh_session(
            user=actor,
            target_system=target,
            time=time,
            source_ip=source_ip,
            min_duration=(
                max(
                    30.0,
                    (session_required_until - time).total_seconds() + 30.0,
                )
                if session_required_until is not None
                else None
            ),
            emit_session_close=True,
            session_end_plan=session_end_plan,
            ids_alerts=authored_ids_alerts,
        )
        result = SimpleNamespace(network_uid=uid)
    if getattr(result, "session", None) is not None:
        self._record_storyline_logon(
            actor,
            target,
            result.session.logon_id,
            source_ip=result.session.source_ip,
        )
        self._record_storyline_session_ready(
            system=target,
            actor=actor,
            session=result.session,
            rng=rng,
        )
    malicious_event["dst_ip"] = system.ip
    malicious_event["dst_port"] = 22
    result_source_ip = (
        result.session.source_ip
        if getattr(result, "session", None) is not None
        else spec.source_ip or system.ip
    )
    malicious_event["uid"] = _ground_truth_uid(
        result.network_uid or "",
        result_source_ip,
        target.ip,
    )
    if getattr(spec, "ids_alerts", []):
        malicious_event["ids_alerts"] = _ids_attachment_ground_truth(spec.ids_alerts)

    return context.malicious_event


def handle_rdp_session(
    self: StorylineMixin, spec: RdpSessionEventSpec, context: TypedEventContext
) -> dict[str, Any] | None:
    """Execute the rdp_session evidence path using the existing runtime owners."""
    from evidenceforge.generation.engine.storyline_helpers.ids import (
        _build_ids_alert_contexts,
        _ids_attachment_ground_truth,
    )

    actor = context.actor
    system = context.system
    time = context.time
    rng = context.rng
    malicious_event = context.malicious_event
    _ground_truth_uid = context._ground_truth_uid
    target = next((s for s in self.scenario.environment.systems if s.ip == system.ip), system)
    authored_ids_alerts = _build_ids_alert_contexts(
        getattr(spec, "ids_alerts", []),
        time=time,
        src_ip=spec.source_ip or system.ip,
        dst_ip=target.ip,
        dst_port=3389,
        proto="tcp",
        rng=rng,
        source="storyline_rdp_session",
    )
    if hasattr(self, "world_planner"):
        source_system = (
            self.world_model.system_for_ip(spec.source_ip)
            if spec.source_ip and hasattr(self, "world_model")
            else None
        )
        result = self.world_planner.bootstrap_user_session(
            user=actor,
            target_system=target,
            time=time,
            rng=rng,
            session_kind="rdp",
            source_system=source_system,
            allow_existing=False,
            source_ip_override=spec.source_ip,
            storyline_protected=True,
            session_end_plan=self._authored_rdp_session_end_plan(),
            ids_alerts=authored_ids_alerts,
        )
    else:
        source_ip = spec.source_ip or system.ip
        uid = self.activity_generator.generate_rdp_session(
            user=actor,
            target_system=target,
            time=time,
            source_ip=source_ip,
            session_end_plan=self._authored_rdp_session_end_plan(),
            ids_alerts=authored_ids_alerts,
        )
        result = SimpleNamespace(network_uid=uid)
    if getattr(result, "session", None) is not None:
        malicious_event["actor"] = result.session.username
        self._record_storyline_logon(
            actor,
            target,
            result.session.logon_id,
            source_ip=result.session.source_ip,
        )
        self._record_storyline_session_ready(
            system=target,
            actor=actor,
            session=result.session,
            rng=rng,
        )
    malicious_event["dst_ip"] = system.ip
    malicious_event["dst_port"] = 3389
    result_source_ip = (
        result.session.source_ip
        if getattr(result, "session", None) is not None
        else spec.source_ip or system.ip
    )
    malicious_event["uid"] = _ground_truth_uid(
        result.network_uid or "",
        result_source_ip,
        target.ip,
    )
    if getattr(spec, "ids_alerts", []):
        malicious_event["ids_alerts"] = _ids_attachment_ground_truth(spec.ids_alerts)

    return context.malicious_event


def handle_credential_spray(
    self: StorylineMixin, spec: CredentialSprayEventSpec, context: TypedEventContext
) -> dict[str, Any] | None:
    """Execute the credential_spray evidence path using the existing runtime owners."""
    from evidenceforge.generation.engine.storyline_helpers.periodic import _iter_periodic_ticks

    actor = context.actor
    system = context.system
    time = context.time
    authored_time_shift = context.authored_time_shift
    rng = context.rng
    malicious_event = context.malicious_event
    start = (
        self._parse_storyline_time(spec.start_time) + authored_time_shift
        if spec.start_time
        else time
    )
    interval_sec = parse_duration(spec.interval).total_seconds()
    duration_sec = None
    count = spec.count
    if spec.duration is not None:
        duration_sec = parse_duration(spec.duration).total_seconds()
    elif spec.end_time is not None:
        end_dt = self._parse_storyline_time(spec.end_time) + authored_time_shift
        duration_sec = (end_dt - start).total_seconds()

    spray_src_ip = spec.source_ip or system.ip
    accounts = spec.target_accounts
    success_spec = spec.success
    success_account = success_spec.get("account") if success_spec else None
    success_after = success_spec.get("after", 0) if success_spec else 0
    success_session_end_plan = (
        self._authored_rdp_session_end_plan()
        if success_account
        and spec.logon_type == 10
        and _get_os_category(system.os) == "windows"
        and spray_src_ip not in {"-", system.ip}
        else None
    )

    # Resolve target accounts — include service accounts as synthetic User
    # objects so credential_spray targets resolve for both failed and success logons
    from evidenceforge.models.scenario import User as _User

    scenario_users = {u.username: u for u in self.scenario.environment.users}
    ad_domain = self.scenario.environment.domain or "corp.local"
    for svc_name in self.scenario.environment.service_accounts:
        if svc_name not in scenario_users:
            scenario_users[svc_name] = _User(
                username=svc_name,
                full_name=svc_name,
                email=f"{svc_name}@{ad_domain}",
            )

    # Only attach DC for Windows domain-account sprays — Linux SSH brute
    # force or local-account attacks should not produce DC-side 4625/4776
    dc_system = None
    is_windows_target = "windows" in system.os.lower()
    has_domain_account = any(acct in scenario_users for acct in accounts)
    if is_windows_target and has_domain_account:
        dcs = [s for s in self.scenario.environment.systems if s.type == "domain_controller"]
        if dcs:
            # Deterministic DC per source IP (mimics AD DC Locator caching)
            dc_idx = _stable_seed(f"preferred_dc_{spray_src_ip}") % len(dcs)
            dc_system = dcs[dc_idx]

    attempt_count = 0
    for tick_time in _iter_periodic_ticks(
        start,
        interval_sec,
        duration_sec,
        count,
        spec.jitter,
        rng,
        exclusive_end_time=getattr(self, "end_time", None),
    ):
        self.state_manager.set_current_time(tick_time)

        # Success fires at exactly the requested attempt count,
        # regardless of which account the pattern would have selected
        if success_account and attempt_count == success_after:
            target_user = scenario_users.get(success_account, actor)
            self.activity_generator.generate_logon(
                user=target_user,
                system=system,
                time=tick_time,
                logon_type=spec.logon_type,
                source_ip=spray_src_ip,
                session_end_plan=success_session_end_plan,
            )
            attempt_count += 1
            malicious_event["success_account"] = success_account
            malicious_event["success_at_attempt"] = attempt_count
            break

        # Select target account based on pattern
        if spec.pattern == "spray":
            target_account = accounts[attempt_count % len(accounts)]
        elif spec.pattern == "brute_force":
            target_account = accounts[
                min(
                    attempt_count // max(1, (spec.count or 100) // len(accounts)),
                    len(accounts) - 1,
                )
            ]
        else:  # stuffing
            target_account = accounts[attempt_count % len(accounts)]

        target_user = scenario_users.get(target_account, actor)

        self.activity_generator.generate_failed_logon(
            user=target_user,
            system=system,
            time=tick_time,
            logon_type=spec.logon_type,
            source_ip=spray_src_ip,
            target_username=target_account,
            dc_system=dc_system,
        )
        attempt_count += 1

    malicious_event["pattern"] = spec.pattern
    malicious_event["target_accounts"] = accounts
    malicious_event["attempt_count"] = attempt_count

    return context.malicious_event


def handle_explicit_credentials(
    self: StorylineMixin, spec: ExplicitCredentialsEventSpec, context: TypedEventContext
) -> dict[str, Any] | None:
    """Execute the explicit_credentials evidence path using the existing runtime owners."""
    actor = context.actor
    system = context.system
    time = context.time
    malicious_event = context.malicious_event
    story_pid, _story_image = self._last_storyline_process_for_system(system)
    self.activity_generator.generate_explicit_credentials(
        user=actor,
        system=system,
        time=time,
        target_username=spec.target_username,
        target_server=spec.target_server or system.hostname,
        process_name=spec.process_name or r"C:\Windows\System32\runas.exe",
        process_pid=story_pid if story_pid > 0 else 0,
        source_ip=spec.source_ip or "",
    )
    malicious_event["target_username"] = spec.target_username
    malicious_event["target_server"] = spec.target_server

    return context.malicious_event


def handle_workstation_lock(
    self: StorylineMixin, spec: WorkstationLockEventSpec, context: TypedEventContext
) -> dict[str, Any] | None:
    """Execute the workstation_lock evidence path using the existing runtime owners."""
    actor = context.actor
    system = context.system
    time = context.time
    malicious_event = context.malicious_event
    sessions = self.state_manager.get_sessions_for_user(actor.username)
    session = max(
        (
            s
            for s in sessions
            if s.system == system.hostname
            and s.logon_type in (2, 11)
            and s.session_kind not in {"network", "service", "rdp", "ssh"}
            and s.start_time <= time
        ),
        key=lambda s: s.start_time,
        default=None,
    )
    logon_id = session.logon_id if session else "0x0"
    result = self.activity_generator.generate_workstation_lock(
        user=actor,
        system=system,
        time=time,
        logon_id=logon_id,
    )
    if not result.emitted:
        malicious_event["skipped_reason"] = result.skipped_reason or "workstation_lock_not_emitted"

    return context.malicious_event


def handle_workstation_unlock(
    self: StorylineMixin, spec: WorkstationUnlockEventSpec, context: TypedEventContext
) -> dict[str, Any] | None:
    """Execute the workstation_unlock evidence path using the existing runtime owners."""
    actor = context.actor
    system = context.system
    time = context.time
    sessions = self.state_manager.get_sessions_for_user(actor.username)
    session = max(
        (
            s
            for s in sessions
            if s.system == system.hostname
            and s.logon_type in (2, 11)
            and s.session_kind not in {"network", "service", "rdp", "ssh"}
            and s.start_time <= time
        ),
        key=lambda s: s.start_time,
        default=None,
    )
    logon_id = session.logon_id if session else "0x0"
    self.activity_generator.generate_workstation_unlock(
        user=actor,
        system=system,
        time=time,
        logon_id=logon_id,
    )

    return context.malicious_event
