# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Typed storyline process handlers."""

from __future__ import annotations

import random
from datetime import datetime, timedelta
from typing import TYPE_CHECKING, Any

from evidenceforge.events.content_identity import FileContentIdentity
from evidenceforge.generation.activity.helpers import _get_os_category
from evidenceforge.generation.activity.http_content import (
    apply_transfer_size_variance,
    is_stable_resource_path,
    normalize_mime_type_for_path,
    response_size_for_mime,
    response_size_for_status,
)
from evidenceforge.generation.activity.network import _is_private_ip
from evidenceforge.models.scenario import (
    CreateRemoteThreadEventSpec,
    ProcessAccessEventSpec,
    ProcessEventSpec,
)
from evidenceforge.utils.rng import _stable_seed, stable_uuid
from evidenceforge.utils.time import ensure_utc

from .context import TypedEventContext

if TYPE_CHECKING:
    from evidenceforge.generation.engine.storyline import StorylineMixin


def handle_process(
    self: StorylineMixin, spec: ProcessEventSpec, context: TypedEventContext
) -> dict[str, Any] | None:
    """Execute the process evidence path using the existing runtime owners."""
    from evidenceforge.generation.engine.storyline import (
        _IPV4_LITERAL_RE,
        _estimate_process_lifetime,
        _extract_schtasks_option,
        _linux_shell_process_command_line,
        _normalize_storyline_process_image,
    )

    actor = context.actor
    system = context.system
    time = context.time
    explicit_types = context.explicit_types
    future_specs = context.future_specs
    rng = context.rng
    malicious_event = context.malicious_event
    os_category = _get_os_category(system.os)
    if hasattr(self, "world_planner"):
        # Built-in/service accounts (SYSTEM, LOCAL SERVICE, etc.) run
        # locally — don't fabricate remote logon evidence for them.
        from evidenceforge.validation.schema import BUILTIN_ACCOUNTS

        service_accounts = set(self.scenario.environment.service_accounts)
        is_local_account = actor.username in BUILTIN_ACCOUNTS or actor.username in service_accounts
        is_interactive_linux_root = os_category == "linux" and actor.username == "root"
        if is_local_account and not is_interactive_linux_root:
            linux_daemon_users = {"apache", "www-data", "nginx", "httpd", "tomcat"}
            if os_category == "linux" and actor.username.lower() in linux_daemon_users:
                logon_id = ""
            else:
                # Use existing system session or create a service logon.
                sessions = self.state_manager.get_sessions_for_user_at(
                    actor.username,
                    time,
                )
                target_session = max(
                    (s for s in sessions if s.system == system.hostname),
                    key=lambda session: session.start_time,
                    default=None,
                )
                if target_session:
                    logon_id = target_session.logon_id
                else:
                    logon_time = time - timedelta(seconds=rng.uniform(0.5, 2.0))
                    logon_id = self.activity_generator.generate_service_logon(
                        system=system,
                        time=logon_time,
                        service_account=actor.username,
                    )
        else:
            logon_id = self._last_storyline_logon_for_actor_system(
                actor,
                system,
                at_time=time,
            )
            if logon_id is None:
                required_until = self._next_storyline_logoff_time_for_actor_system(
                    actor,
                    system,
                    time,
                )
                session_kind = self._storyline_non_session_kind(actor, system, rng)
                target_session = self.world_planner.ensure_user_session(
                    actor,
                    system,
                    time,
                    rng,
                    session_kind=session_kind,
                    storyline_protected=True,
                    required_until=required_until,
                )
                logon_id = target_session.logon_id
                self._record_storyline_logon(actor, system, logon_id)
    else:
        sessions = self.state_manager.get_sessions_for_user(actor.username)
        target_session = max(
            (s for s in sessions if s.system == system.hostname),
            key=lambda session: session.start_time,
            default=None,
        )
        if not target_session:
            logon_time = time - timedelta(seconds=rng.uniform(0.5, 2.0))
            logon_id = self.activity_generator.generate_logon(
                actor, system, logon_time, logon_type=3
            )
            self._record_storyline_logon(actor, system, logon_id)
        else:
            logon_id = target_session.logon_id

    process_actor = self._linux_native_service_user_for_storyline_actor(
        actor,
        system,
        time,
    )
    process_actor = self._storyline_local_process_actor_for_logon(
        process_actor,
        system,
        logon_id,
    )
    process_name = _normalize_storyline_process_image(
        spec.process_name,
        os_category,
        username=process_actor.username,
    )
    command_line = spec.command_line or process_name
    shell_key = (system.hostname, process_actor.username)

    if os_category == "linux":
        if not hasattr(self, "_storyline_shell_available_at"):
            self._storyline_shell_available_at: dict[tuple[str, str], datetime] = {}
        available_times = [
            ts
            for key in {shell_key, (system.hostname, actor.username)}
            if (ts := self._storyline_shell_available_at.get(key)) is not None
        ]
        available_at = max(available_times) if available_times else None
        if available_at is not None and time < available_at:
            time = available_at + timedelta(seconds=rng.uniform(0.3, 2.0))

    if "<base64_encoded_command>" in command_line:
        command_line = command_line.replace(
            "<base64_encoded_command>",
            self._generate_encoded_powershell(
                _stable_seed(f"storyline_ps_{time.isoformat()}_{actor.username}")
            ),
        )

    process_command_line = command_line
    if os_category == "linux":
        from evidenceforge.generation.activity.generator import (
            _linux_command_process_from_shell,
        )

        inferred_process = _linux_command_process_from_shell(
            command_line,
            username=process_actor.username,
        )
        if inferred_process is not None:
            inferred_image, inferred_command_line = inferred_process
            if inferred_image.rsplit("/", 1)[-1] == process_name.rsplit("/", 1)[-1]:
                process_command_line = inferred_command_line
        shell_command_line = _linux_shell_process_command_line(
            process_name,
            process_command_line,
        )
        if shell_command_line is not None:
            process_command_line = shell_command_line

    output_file = self._extract_output_file(command_line, os_category)
    process_logon_id = logon_id
    service_lifecycle_group_id = ""
    service_process_identity = self._storyline_service_process_identity(
        system=system,
        time=time,
        process_name=process_name,
        future_specs=future_specs,
    )
    parent_ref = getattr(spec, "parent_ref", None)
    if not isinstance(parent_ref, str) or not parent_ref:
        parent_ref = None
    explicit_parent = self._storyline_process_ref_for_parent(
        actor=process_actor,
        system=system,
        parent_ref=parent_ref,
    )
    if parent_ref is not None and explicit_parent is None:
        malicious_event["process_name"] = process_name
        malicious_event["command_line"] = command_line
        malicious_event["skipped_reason"] = "no_live_parent_ref"
        return malicious_event
    if explicit_parent is not None:
        parent_pid, _parent_image = explicit_parent
    elif service_process_identity is not None:
        process_actor, _service_name, service_lifecycle_group_id = service_process_identity
        process_logon_id = {
            "SYSTEM": "0x3e7",
            "LOCAL SERVICE": "0x3e5",
            "NETWORK SERVICE": "0x3e4",
        }[process_actor.username]
        parent_pid = self.activity_generator._get_system_pid(
            system.hostname,
            "services",
            0x1F4,
        )
    else:
        service_context = self._storyline_service_context_for_process(
            actor=process_actor,
            system=system,
            time=time,
            process_name=process_name,
        )
        if service_context is not None:
            (
                process_actor,
                process_logon_id,
                parent_pid,
                service_lifecycle_group_id,
            ) = service_context
        else:
            parent_pid = self.activity_generator._resolve_parent(
                system,
                process_actor,
                time,
                process_logon_id,
                process_name,
                process_command_line,
            )
    if os_category == "linux":
        self._emit_linux_storyline_shell_friction(
            actor=process_actor,
            system=system,
            time=time,
            process_name=process_name,
            command_line=command_line,
            output_file=output_file,
            rng=rng,
        )
        reserved_start_time = self.activity_generator.reserve_linux_foreground_process_start(
            system=system,
            username=process_actor.username,
            logon_id=process_logon_id,
            parent_pid=parent_pid,
            requested_time=time,
            process_name=process_name,
            command_line=process_command_line,
            authoritative_time=True,
        )
        if isinstance(reserved_start_time, datetime):
            time = reserved_start_time
        prepared_shell_command = self.activity_generator._prepare_bash_history_command(
            system,
            command_line,
        )
        self.activity_generator._emit_bash_command_event(
            process_actor,
            system,
            time,
            prepared_shell_command,
        )
        malicious_event["time"] = time
    exe_name = process_name.rsplit("\\", 1)[-1].rsplit("/", 1)[-1].lower()
    service_backed_process = service_process_identity is not None or (
        "service_installed" in explicit_types
        and exe_name in {"psexesvc.exe", "healthmonitorsvc.exe"}
    )
    if service_backed_process and not service_lifecycle_group_id:
        matching_service_spec = next(
            (
                candidate
                for candidate in future_specs
                if getattr(candidate, "type", "") == "service_installed"
                and self._normalize_storyline_service_file_name(
                    str(getattr(candidate, "service_file_name", "") or "")
                )
                .rsplit("\\", 1)[-1]
                .casefold()
                == exe_name
            ),
            None,
        )
        if matching_service_spec is not None:
            service_name = str(getattr(matching_service_spec, "service_name", "") or exe_name)
        else:
            service_name = exe_name.removesuffix(".exe")
        service_lifecycle_group_id = self._storyline_remote_service_lifecycle_id(
            system,
            service_name,
        )
    if not service_lifecycle_group_id and exe_name in {
        "psexesvc.exe",
        "healthmonitorsvc.exe",
    }:
        recent_service = getattr(self, "_last_storyline_service_by_system", {}).get(
            system.hostname,
            {},
        )
        installed_image = self._normalize_storyline_service_file_name(
            str(recent_service.get("service_file_name") or "")
        )
        installed_at = recent_service.get("installed_at")
        if (
            installed_image.rsplit("\\", 1)[-1].casefold() == exe_name
            and isinstance(installed_at, datetime)
            and installed_at <= time
            and time - installed_at
            <= (timedelta(minutes=2) if exe_name == "psexesvc.exe" else timedelta(minutes=30))
        ):
            service_lifecycle_group_id = str(recent_service.get("lifecycle_group_id") or "")
    pid = self.activity_generator.generate_process(
        user=process_actor,
        system=system,
        time=time,
        logon_id=process_logon_id,
        process_name=process_name,
        command_line=process_command_line,
        parent_pid=parent_pid,
        require_exact_parent=explicit_parent is not None,
        ensure_file_event=not service_backed_process,
        from_storyline=True,
        suppress_command_file_effect=output_file is not None,
        lifecycle_group_id=service_lifecycle_group_id,
    )
    running_process = self.state_manager.get_process(system.hostname, pid)
    if running_process is not None:
        time = max(ensure_utc(time), ensure_utc(running_process.start_time))
        malicious_event["time"] = time
    self.activity_generator._record_user_process(system, process_actor, pid, process_name)
    self._record_last_storyline_process(system, pid, process_name, process_command_line)
    process_ref = getattr(spec, "process_ref", None)
    if not isinstance(process_ref, str) or not process_ref:
        process_ref = None
    if process_ref is not None:
        self._record_storyline_process_ref(
            actor=process_actor,
            system=system,
            process_ref=process_ref,
            pid=pid,
            image=process_name,
        )
    malicious_event["process_name"] = process_name
    malicious_event["command_line"] = command_line
    malicious_event["pid"] = pid
    archive_destination = self._extract_compress_archive_destination(command_line)
    if archive_destination:
        staging_source_ip = self._last_storyline_logon_source_for_actor_system(
            actor,
            system,
            at_time=time,
        )
        if staging_source_ip and staging_source_ip != system.ip:
            self._record_storyline_staged_archive(
                actor=process_actor,
                system=system,
                archive_path=archive_destination,
                source_ip=staging_source_ip,
                staged_at=time,
            )
            malicious_event["staged_archive"] = archive_destination
    task_name = _extract_schtasks_option(command_line, "tn")
    if task_name and "/create" in command_line.lower():
        self._record_storyline_scheduled_task_command(system, task_name, command_line)
    self._record_storyline_service_create_command(system, command_line)
    self._record_storyline_account_create_command(system, command_line)

    if output_file:
        if os_category == "linux" and output_file.startswith("~/"):
            home = (
                "/root" if process_actor.username == "root" else f"/home/{process_actor.username}"
            )
            output_file = f"{home}/{output_file[2:]}"
        file_time = time + timedelta(seconds=rng.uniform(0.5, 3.0))
        from evidenceforge.events.base import OccurrenceBuilder
        from evidenceforge.events.contexts import (
            AuthContext,
            FileContext,
            ProcessContext,
        )

        host_ctx = self.activity_generator._build_host_context(system)
        running_proc = self.state_manager.get_process(system.hostname, pid)
        self.dispatcher.dispatch_builder(
            OccurrenceBuilder(
                timestamp=file_time,
                event_type="file_create",
                src_host=host_ctx,
                auth=AuthContext(username=process_actor.username),
                process=ProcessContext(
                    pid=pid,
                    parent_pid=parent_pid,
                    image=process_name,
                    command_line=process_command_line,
                    username=process_actor.username,
                    logon_id=process_logon_id,
                    start_time=running_proc.start_time if running_proc is not None else None,
                ),
                file=FileContext(path=output_file, action="create", pid=pid),
                storyline_origin=True,
            )
        )
        malicious_event["output_file"] = output_file

    http_url = self._extract_http_url(command_line)
    if http_url is not None:
        parsed_target = self._parse_http_url_target(http_url)
        if parsed_target is not None:
            from urllib.parse import urlparse

            from evidenceforge.events.contexts import HttpContext

            hostname, dst_port = parsed_target
            parsed_url = urlparse(http_url)
            uri = parsed_url.path or "/"
            if parsed_url.query:
                uri = f"{uri}?{parsed_url.query}"
            mime_type = normalize_mime_type_for_path(uri, "text/plain")
            response_body_len = (
                apply_transfer_size_variance(
                    response_size_for_status(200, hostname, uri),
                    status_code=200,
                    host=hostname,
                    uri=uri,
                    content_type=mime_type,
                    variant_key=f"{system.ip}:{process_name}:{pid}",
                )
                if is_stable_resource_path(uri)
                else response_size_for_mime(rng, mime_type)
            )
            preserve_url_dst_ip = False
            dst_ip = self._resolve_storyline_network_target(hostname)
            if dst_ip is None:
                authored_dst_ip = self._storyline_authored_ip_for_hostname(hostname)
                if authored_dst_ip is not None:
                    dst_ip = authored_dst_ip
                    preserve_url_dst_ip = True
            if dst_ip is None:
                dst_ip = self._resolve_scenario_network_host(
                    hostname,
                    src_host=system.hostname,
                )
            service = "ssl" if dst_port == 443 else "http"
            network_time = self._clamp_after_storyline_process_source_create(
                system=system,
                pid=pid,
                network_time=time + timedelta(milliseconds=rng.randint(250, 900)),
                rng=rng,
            )
            http_user_agent, http_user_agent_known_absent = (
                self._storyline_http_user_agent_metadata_for_command(
                    system=system,
                    process_image=process_name,
                    command_line=command_line,
                    rng=rng,
                )
            )
            self.activity_generator.generate_connection(
                src_ip=system.ip,
                dst_ip=dst_ip,
                time=network_time,
                dst_port=dst_port,
                proto="tcp",
                service=service,
                duration=rng.uniform(0.8, 6.0),
                orig_bytes=rng.randint(300, 1400),
                resp_bytes=response_body_len,
                conn_state="SF",
                emit_dns=not _is_private_ip(dst_ip),
                source_system=system,
                pid=pid,
                hostname=hostname,
                process_image=process_name,
                preserve_dst_ip=preserve_url_dst_ip,
                http=HttpContext(
                    method="GET",
                    host=hostname,
                    uri=uri,
                    version="1.1",
                    user_agent=http_user_agent,
                    user_agent_known_absent=http_user_agent_known_absent,
                    request_body_len=0,
                    response_body_len=response_body_len,
                    status_code=200,
                    status_msg="OK",
                    resp_mime_types=[mime_type],
                    tags=[],
                ),
            )
            malicious_event["network_url"] = http_url

    remote_db_target = self._extract_database_client_target(command_line, os_category)
    if remote_db_target is not None:
        target_host, dst_port, service = remote_db_target
        target_ip = self._resolve_storyline_network_target(target_host)
        target_hostname = None if _IPV4_LITERAL_RE.fullmatch(target_host) else target_host
        unresolved_single_label_fallback = False
        if target_ip is None and target_hostname is not None:
            ad_domain = getattr(self, "_ad_domain", "")
            target_lower = target_hostname.rstrip(".").lower()
            unresolved_single_label = "." not in target_lower
            looks_internal = target_lower.endswith(".local") or (
                bool(ad_domain) and target_lower.endswith(f".{ad_domain.lower()}")
            )
            if unresolved_single_label:
                if self._is_local_database_instance_target(target_hostname):
                    target_hostname = None
                else:
                    target_ip = self._unresolved_database_target_ip(target_hostname)
                    unresolved_single_label_fallback = target_ip is not None
                    if ad_domain:
                        target_hostname = f"{target_hostname}.{ad_domain}"
            elif not looks_internal:
                target_ip = self._resolve_scenario_network_host(
                    target_hostname,
                    src_host=system.hostname,
                )
        if target_ip is not None:
            target_system = self._system_for_ip(target_ip)
            failed_private_attempt = unresolved_single_label_fallback or (
                target_system is None and _is_private_ip(target_ip)
            )
            firewall_ctx = None
            conn_state = "SF"
            duration = rng.uniform(0.6, 8.0)
            orig_bytes = rng.randint(180, 900)
            resp_bytes = rng.randint(800, 6000)
            rendered_service = service
            if failed_private_attempt:
                from evidenceforge.events.contexts import FirewallContext

                src_iface = self._resolve_firewall_interface(system.ip)
                dst_iface = self._resolve_firewall_interface(target_ip)
                firewall_ctx = FirewallContext(
                    action="deny",
                    msg_id=106023,
                    connection_id=0,
                    src_interface=src_iface,
                    dst_interface=dst_iface,
                    access_group=f"{src_iface}_access_in",
                )
                conn_state = self._get_firewall_deny_conn_state()
                duration = rng.uniform(0.02, 0.45)
                orig_bytes = 0
                resp_bytes = 0
                rendered_service = None
            connection_time = self._clamp_after_storyline_process_source_create(
                system=system,
                pid=pid,
                network_time=time + timedelta(milliseconds=rng.randint(250, 900)),
                rng=rng,
            )
            self.activity_generator.generate_connection(
                src_ip=system.ip,
                dst_ip=target_ip,
                time=connection_time,
                dst_port=dst_port,
                proto="tcp",
                service=rendered_service,
                duration=duration,
                orig_bytes=orig_bytes,
                resp_bytes=resp_bytes,
                conn_state=conn_state,
                emit_dns=target_hostname is not None,
                source_system=system,
                pid=pid,
                hostname=target_hostname,
                process_image=process_name,
                firewall=firewall_ctx,
            )
            malicious_event["network_target"] = target_host
            malicious_event["network_target_ip"] = target_ip
            malicious_event["network_target_port"] = dst_port

    scp_destination = self._extract_scp_destination(command_line, os_category)
    scp_target = scp_destination[0] if scp_destination is not None else None
    if scp_target is not None:
        dst_ip = self._resolve_storyline_network_target(scp_target)
        if dst_ip:
            transfer_time = self._clamp_after_storyline_process_source_create(
                system=system,
                pid=pid,
                network_time=time + timedelta(milliseconds=rng.randint(250, 900)),
                rng=rng,
            )
            target_system = self._system_for_ip(dst_ip)
            modeled_linux_receiver = bool(
                target_system is not None and _get_os_category(target_system.os) == "linux"
            )
            source_port = (
                self.activity_generator.preview_ssh_source_port(
                    system.ip,
                    dst_ip,
                    None,
                    rng,
                    _get_os_category(system.os),
                    transfer_time,
                )
                if modeled_linux_receiver
                else self.activity_generator.reserve_ssh_source_port(
                    system.ip,
                    dst_ip,
                    None,
                    rng,
                    _get_os_category(system.os),
                    time=transfer_time,
                )
            )
            transfer_duration = (
                # Leave a real authentication window before exact SCP close.
                rng.uniform(12.0, 40.0) if modeled_linux_receiver else rng.uniform(2.0, 30.0)
            )
            source_path = self._extract_scp_source_path(command_line, os_category) or ""
            source_content = None
            runtime_manager = getattr(
                self.activity_generator,
                "_runtime_content_manager",
                None,
            )
            if runtime_manager is not None and source_path:
                source_record = runtime_manager.resolve_record(
                    system.hostname,
                    process_actor.username,
                    source_path,
                    "linux",
                )
                if source_record is not None:
                    source_content = source_record.content
            if source_content is None and source_path:
                content_rng = random.Random(
                    _stable_seed(
                        "storyline_scp_source_content:"
                        f"{system.hostname}:{source_path}:{transfer_time.isoformat()}"
                    )
                )
                source_content = FileContentIdentity(
                    file_object_id=stable_uuid(
                        "file-identity",
                        f"{system.hostname}:{source_path.casefold()}",
                    ),
                    version=1,
                    size_bytes=content_rng.randint(600_000, 1_800_000),
                    mime_type=(
                        "application/gzip"
                        if source_path.casefold().endswith((".gz", ".tgz"))
                        else "application/octet-stream"
                    ),
                    seed_ref=stable_uuid(
                        "storyline-scp-content",
                        system.hostname,
                        source_path,
                    ),
                )
            orig_bytes = (
                source_content.size_bytes + rng.randint(8_192, 32_768)
                if source_content is not None
                else rng.randint(20_000, 250_000)
            )
            resp_bytes = rng.randint(4_000, 40_000)
            if modeled_linux_receiver and target_system is not None and scp_destination is not None:
                target_user = self._resolve_scp_target_user(
                    extracted_username=scp_destination[2],
                    fallback_username=process_actor.username,
                )
                transport_uid = self.activity_generator.generate_ssh_session(
                    user=self.activity_generator._user_model_for_username(target_user),
                    target_system=target_system,
                    time=transfer_time,
                    source_ip=system.ip,
                    source_system=system,
                    source_port=source_port,
                    source_pid=pid,
                    source_process_image=process_name,
                    duration=transfer_duration,
                    orig_bytes=orig_bytes,
                    resp_bytes=resp_bytes,
                    auth_method="publickey",
                    emit_session_close=True,
                    defer_session_close=True,
                    source="storyline_scp",
                )
                network_plan_getter = getattr(
                    self.dispatcher,
                    "network_plan_for",
                    None,
                )
                transport_plan = (
                    network_plan_getter(transport_uid) if callable(network_plan_getter) else None
                )
                transfer_completed_at = (
                    transport_plan.closed_at
                    if transport_plan is not None
                    else transfer_time + timedelta(seconds=transfer_duration)
                )
                self._emit_scp_receiver_artifacts(
                    source_system=system,
                    target_system=target_system,
                    actor=process_actor,
                    source_pid=pid,
                    source_process=process_name,
                    source_command=command_line,
                    source_path=source_path,
                    target_user=target_user,
                    target_path=scp_destination[1],
                    transfer_time=transfer_time,
                    source_port=source_port,
                    transfer_completed_at=transfer_completed_at,
                    source_content=source_content,
                    rng=rng,
                )
            else:
                self.activity_generator.generate_connection(
                    src_ip=system.ip,
                    dst_ip=dst_ip,
                    time=transfer_time,
                    dst_port=22,
                    proto="tcp",
                    service="ssh",
                    duration=transfer_duration,
                    orig_bytes=orig_bytes,
                    resp_bytes=resp_bytes,
                    conn_state="SF",
                    emit_dns=not _is_private_ip(dst_ip),
                    source_system=system,
                    pid=pid,
                    process_image=process_name,
                    src_port=source_port,
                )

    _EXPLICIT_CRED_TOOLS = {"psexec", "wmic", "runas", "schtasks"}
    proc_basename = (
        process_name.rsplit("\\", 1)[-1].lower() if "\\" in process_name else process_name.lower()
    )
    command_lower = command_line.lower()
    uses_explicit_creds = proc_basename in _EXPLICIT_CRED_TOOLS or (
        proc_basename in {"net.exe", "net1.exe"}
        and any(token in command_lower for token in ("/user:", " /u:", " /user "))
    )
    if uses_explicit_creds and os_category == "windows":
        cred_time = time - timedelta(milliseconds=rng.randint(5, 50))
        self.activity_generator.generate_explicit_credentials(
            user=process_actor,
            system=system,
            time=cred_time,
            target_username=process_actor.username,
            target_server="localhost",
            process_name=process_name,
            process_pid=pid,
        )

    if os_category == "windows" and getattr(spec, "supplementary", "auto") != "none":
        self.activity_generator._expand_and_emit(
            "process_create",
            time,
            actor=process_actor,
            target_system=system,
            command_line=command_line,
            os_category=os_category,
            source_pid=pid,
            logon_id=process_logon_id,
            skip_types=explicit_types,
        )

    # Mark as story process and schedule termination
    self.state_manager.mark_story_process(system.hostname, pid)
    lifetime = _estimate_process_lifetime(process_name, process_command_line)
    if lifetime is not None:
        term_delay = rng.uniform(lifetime[0], lifetime[1])
        term_time = time + timedelta(seconds=term_delay)
        shell_release_time = term_time
        terminate_immediately = False
        if os_category == "linux":
            from evidenceforge.generation.activity.generator import (
                _linux_foreground_lifetime,
            )

            terminate_immediately = (
                _linux_foreground_lifetime(process_name, process_command_line) is not None
            )
            if process_ref is not None:
                terminate_immediately = False
            if terminate_immediately and self._process_has_following_same_host_connection(
                system,
                future_specs,
            ):
                terminate_immediately = False
        if terminate_immediately:
            self.activity_generator.generate_process_termination(
                user=process_actor,
                system=system,
                time=term_time,
                pid=pid,
                process_name=process_name,
                logon_id=process_logon_id,
                from_storyline=True,
            )
        else:
            release_storyline_index = (
                self._storyline_process_ref_release_index(
                    actor=process_actor,
                    system=system,
                    process_ref=process_ref,
                )
                if process_ref is not None
                else None
            )
            self._queue_story_process_termination(
                actor=process_actor,
                system=system,
                time=term_time,
                pid=pid,
                process_name=process_name,
                logon_id=process_logon_id,
                release_storyline_index=release_storyline_index,
            )
        if os_category == "linux":
            self.activity_generator.remember_linux_foreground_process_completion(
                system=system,
                username=process_actor.username,
                logon_id=process_logon_id,
                parent_pid=parent_pid,
                termination_time=shell_release_time,
                process_name=process_name,
                command_line=process_command_line,
            )
            self._storyline_shell_available_at[shell_key] = shell_release_time
            process_shell_key = (system.hostname, process_actor.username)
            self._storyline_shell_available_at[process_shell_key] = shell_release_time

    return context.malicious_event


def handle_create_remote_thread(
    self: StorylineMixin, spec: CreateRemoteThreadEventSpec, context: TypedEventContext
) -> dict[str, Any] | None:
    """Execute the create_remote_thread evidence path using the existing runtime owners."""
    from evidenceforge.generation.engine.storyline import _normalize_storyline_process_image

    actor = context.actor
    system = context.system
    time = context.time
    rng = context.rng
    malicious_event = context.malicious_event
    source_pid, source_image = self._last_storyline_process_for_system(
        system,
        actor=actor,
    )
    # Use a realistic target PID — look up the process name from
    # system PIDs or use a plausible default (not 4 = System kernel)
    target_image = _normalize_storyline_process_image(
        spec.target_process,
        _get_os_category(system.os),
        username=actor.username,
    )
    target_name = target_image.rsplit("\\", 1)[-1].rsplit("/", 1)[-1].lower()
    if source_pid <= 0:
        # Without a live source process, there is no realistic Sysmon
        # Event 8 relationship to render. Keep the storyline record,
        # but mark it skipped instead of claiming generated evidence.
        malicious_event["target_process"] = target_image
        malicious_event["skipped_reason"] = "no_live_source_process"
    else:
        effect_time = self._clamp_after_storyline_process_source_create(
            system=system,
            pid=source_pid,
            network_time=time,
            rng=rng,
        )
        target_pid = self.activity_generator._get_system_pid(
            system.hostname,
            target_name.replace(".exe", ""),
            0x27C,  # 636 default
        )
        evidence_emitted = self.activity_generator.generate_create_remote_thread(
            user=actor,
            system=system,
            time=effect_time,
            source_pid=source_pid,
            source_image=source_image,
            target_pid=target_pid,
            target_image=target_image,
        )
        malicious_event["target_process"] = target_image
        if not evidence_emitted:
            malicious_event["skipped_reason"] = "no_live_target_process"

    return context.malicious_event


def handle_process_access(
    self: StorylineMixin, spec: ProcessAccessEventSpec, context: TypedEventContext
) -> dict[str, Any] | None:
    """Execute the process_access evidence path using the existing runtime owners."""
    from evidenceforge.generation.engine.storyline import _normalize_storyline_process_image

    actor = context.actor
    system = context.system
    time = context.time
    rng = context.rng
    malicious_event = context.malicious_event
    source_pid, source_image = self._last_storyline_process_for_system(
        system,
        actor=actor,
    )
    os_category = _get_os_category(system.os)
    target_image = _normalize_storyline_process_image(
        spec.target_process,
        os_category,
        username=actor.username,
    )
    if source_pid <= 0:
        # Without a live source process, there is no realistic Sysmon
        # Event 10 relationship to render. Keep the storyline record,
        # but mark it skipped instead of claiming generated evidence.
        malicious_event["target_process"] = target_image
        malicious_event["skipped_reason"] = "no_live_source_process"
    else:
        target_name = target_image.rsplit("\\", 1)[-1].rsplit("/", 1)[-1].lower()
        target_pid = self.activity_generator._get_system_pid(
            system.hostname,
            target_name.replace(".exe", ""),
            0x27C,
        )
        evidence_emitted = self.activity_generator.generate_process_access(
            user=actor,
            system=system,
            time=self._clamp_after_storyline_process_source_create(
                system=system,
                pid=source_pid,
                network_time=time,
                rng=rng,
            ),
            source_pid=source_pid,
            source_image=source_image,
            target_pid=target_pid,
            target_image=target_image,
            granted_access=spec.access_mask,
        )
        malicious_event["target_process"] = target_image
        if not evidence_emitted:
            malicious_event["skipped_reason"] = "no_live_target_process"

    return context.malicious_event
