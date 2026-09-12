# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Typed storyline administration handlers."""

from __future__ import annotations

from datetime import timedelta
from typing import TYPE_CHECKING, Any

from evidenceforge.models.scenario import (
    AccountCreatedEventSpec,
    AccountDeletedEventSpec,
    GroupMemberAddedEventSpec,
    LogClearedEventSpec,
    ScheduledTaskCreatedEventSpec,
    ServiceInstalledEventSpec,
)

from .context import TypedEventContext

if TYPE_CHECKING:
    from evidenceforge.generation.engine.storyline import StorylineMixin


def handle_account_created(
    self: StorylineMixin, spec: AccountCreatedEventSpec, context: TypedEventContext
) -> dict[str, Any] | None:
    """Execute the account_created evidence path using the existing runtime owners."""
    actor = context.actor
    system = context.system
    time = context.time
    rng = context.rng
    malicious_event = context.malicious_event
    dc = next(
        (s for s in self.scenario.environment.systems if s.type == "domain_controller"),
        system,
    )
    target_sid = spec.target_sid or self._make_domain_sid()
    effect_time = self._clamp_after_recent_storyline_process_source_create(
        system=system,
        event_time=time,
        rng=rng,
    )
    self.activity_generator.generate_account_created(
        actor=actor,
        system=dc,
        time=effect_time,
        target_username=spec.target_username,
        target_sid=target_sid,
    )
    # Store SID for later reuse by group_member_added, account_deleted,
    # and any _get_sid() lookups (Windows event rendering).
    self._created_account_sids[spec.target_username] = target_sid
    self._created_account_effect_times[
        self._account_create_lookup_key(dc, spec.target_username)
    ] = effect_time
    self._record_storyline_host_available_after(
        system=dc,
        actor=actor,
        time=effect_time,
        rng=rng,
    )
    if self._recent_storyline_account_create_command(dc, spec.target_username):
        self._emit_storyline_account_password_followups(
            actor=actor,
            system=dc,
            time=effect_time,
            target_username=spec.target_username,
            target_sid=target_sid,
        )
    malicious_event["target_username"] = spec.target_username

    return context.malicious_event


def handle_account_deleted(
    self: StorylineMixin, spec: AccountDeletedEventSpec, context: TypedEventContext
) -> dict[str, Any] | None:
    """Execute the account_deleted evidence path using the existing runtime owners."""
    actor = context.actor
    system = context.system
    time = context.time
    rng = context.rng
    malicious_event = context.malicious_event
    dc = next(
        (s for s in self.scenario.environment.systems if s.type == "domain_controller"),
        system,
    )
    target_sid = (
        spec.target_sid
        or self._created_account_sids.get(spec.target_username)
        or self._make_domain_sid()
    )
    effect_time = self._clamp_after_recent_storyline_process_source_create(
        system=system,
        event_time=time,
        rng=rng,
    )
    self.activity_generator.generate_account_deleted(
        actor=actor,
        system=dc,
        time=effect_time,
        target_username=spec.target_username,
        target_sid=target_sid,
        from_storyline=True,
    )
    malicious_event["target_username"] = spec.target_username

    return context.malicious_event


def handle_group_member_added(
    self: StorylineMixin, spec: GroupMemberAddedEventSpec, context: TypedEventContext
) -> dict[str, Any] | None:
    """Execute the group_member_added evidence path using the existing runtime owners."""
    actor = context.actor
    system = context.system
    time = context.time
    rng = context.rng
    malicious_event = context.malicious_event
    dc = next(
        (s for s in self.scenario.environment.systems if s.type == "domain_controller"),
        system,
    )
    group_rid = 512 if "admin" in spec.group_name.lower() else rng.randint(1100, 9999)
    group_sid = self._make_domain_sid(group_rid)
    # Reuse SID from earlier account_created event, or generate new
    member_sid = (
        self._created_account_sids.get(spec.member_name)
        or self.activity_generator.sid_registry.get(spec.member_name)
        or self._make_domain_sid()
    )
    effect_time = self._clamp_after_recent_storyline_process_source_create(
        system=dc,
        event_time=time,
        rng=rng,
    )
    account_created_at = self._created_account_effect_times.get(
        self._account_create_lookup_key(dc, spec.member_name)
    )
    if account_created_at is not None and effect_time <= account_created_at:
        effect_time = account_created_at + timedelta(milliseconds=rng.randint(180, 950))
    self.activity_generator.generate_group_membership_change(
        actor=actor,
        system=dc,
        time=effect_time,
        action="add",
        scope=spec.scope,
        group_name=spec.group_name,
        group_sid=group_sid,
        member_username=spec.member_name,
        member_sid=member_sid,
    )
    self._record_storyline_host_available_after(
        system=dc,
        actor=actor,
        time=effect_time,
        rng=rng,
    )
    malicious_event["group_name"] = spec.group_name
    malicious_event["member_name"] = spec.member_name

    return context.malicious_event


def handle_service_installed(
    self: StorylineMixin, spec: ServiceInstalledEventSpec, context: TypedEventContext
) -> dict[str, Any] | None:
    """Execute the service_installed evidence path using the existing runtime owners."""
    actor = context.actor
    system = context.system
    time = context.time
    rng = context.rng
    malicious_event = context.malicious_event
    effect_time = self._clamp_after_recent_storyline_process_source_create(
        system=system,
        event_time=time,
        rng=rng,
    )
    source_ip = getattr(spec, "source_ip", None)
    remote_source_system = self.world_model.system_for_ip(source_ip) if source_ip else None
    service_lifecycle_group_id = self._storyline_remote_service_lifecycle_id(
        system,
        spec.service_name,
    )
    self.activity_generator.generate_service_installed(
        user=actor,
        system=system,
        time=effect_time,
        service_name=spec.service_name,
        service_file_name=spec.service_file_name,
        service_start_type=self._recent_storyline_service_start_type(
            system,
            spec.service_name,
        ),
        service_account=spec.service_account,
        lifecycle_group_id=service_lifecycle_group_id,
        remote_source_system=remote_source_system,
    )
    self._record_storyline_service_install(
        system=system,
        service_name=spec.service_name,
        service_file_name=spec.service_file_name,
        service_account=spec.service_account,
        time=effect_time,
        lifecycle_group_id=service_lifecycle_group_id,
    )
    malicious_event["service_name"] = spec.service_name
    if spec.service_file_name:
        malicious_event["service_file_name"] = spec.service_file_name

    return context.malicious_event


def handle_scheduled_task_created(
    self: StorylineMixin, spec: ScheduledTaskCreatedEventSpec, context: TypedEventContext
) -> dict[str, Any] | None:
    """Execute the scheduled_task_created evidence path using the existing runtime owners."""
    actor = context.actor
    system = context.system
    time = context.time
    rng = context.rng
    malicious_event = context.malicious_event
    task_content = spec.task_content
    source_command_line = self._recent_storyline_scheduled_task_command(
        system,
        spec.task_name,
    )
    if not task_content:
        task_content = (
            f'<?xml version="1.0" encoding="UTF-16"?>\n'
            f'<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">\n'
            f'  <Actions Context="Author">\n'
            f"    <Exec>\n"
            f"      <Command>C:\\Windows\\System32\\cmd.exe</Command>\n"
            f'      <Arguments>/c "{spec.task_name}"</Arguments>\n'
            f"    </Exec>\n"
            f"  </Actions>\n"
            f"</Task>"
        )
    elif not task_content.lstrip().startswith(("<?xml", "<Task")):
        task_content = (
            f'<?xml version="1.0" encoding="UTF-16"?>\n'
            f'<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">\n'
            f'  <Actions Context="Author">\n'
            f"    <Exec>\n"
            f"      <Command>{task_content}</Command>\n"
            f"    </Exec>\n"
            f"  </Actions>\n"
            f"</Task>"
        )
    effect_time = self._clamp_after_recent_storyline_process_source_create(
        system=system,
        event_time=time,
        rng=rng,
    )
    self.activity_generator.generate_scheduled_task(
        user=actor,
        system=system,
        time=effect_time,
        task_name=spec.task_name,
        action="created",
        task_content=task_content,
        source_command_line=source_command_line,
    )
    malicious_event["task_name"] = spec.task_name
    malicious_event["task_content"] = task_content

    return context.malicious_event


def handle_log_cleared(
    self: StorylineMixin, spec: LogClearedEventSpec, context: TypedEventContext
) -> dict[str, Any] | None:
    """Execute the log_cleared evidence path using the existing runtime owners."""
    actor = context.actor
    system = context.system
    time = context.time
    rng = context.rng
    effect_time = self._clamp_after_recent_storyline_process_source_create(
        system=system,
        event_time=time,
        rng=rng,
    )
    subject_logon_id = self._recent_storyline_process_logon_id(
        actor,
        system,
        effect_time,
        executable="wevtutil.exe",
    )
    self.activity_generator.generate_log_cleared(
        user=actor,
        system=system,
        time=effect_time,
        from_storyline=True,
        subject_logon_id=subject_logon_id,
    )

    return context.malicious_event
