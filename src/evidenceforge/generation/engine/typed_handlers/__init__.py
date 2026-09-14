# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Explicit typed storyline dispatch; family modules own execution bodies."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from evidenceforge.models.scenario import EventSpec

from . import administration, authentication, content, network, periodic, process
from .context import TypedEventContext

if TYPE_CHECKING:
    from evidenceforge.generation.engine.storyline import StorylineMixin

_HANDLERS = {
    "logon": authentication.handle_logon,
    "failed_logon": authentication.handle_failed_logon,
    "logoff": authentication.handle_logoff,
    "email_message": content.handle_email_message,
    "email_read": content.handle_email_read,
    "process": process.handle_process,
    "smb_activity": content.handle_smb_activity,
    "connection": network.handle_connection,
    "ssh_session": authentication.handle_ssh_session,
    "rdp_session": authentication.handle_rdp_session,
    "account_created": administration.handle_account_created,
    "account_deleted": administration.handle_account_deleted,
    "group_member_added": administration.handle_group_member_added,
    "service_installed": administration.handle_service_installed,
    "scheduled_task_created": administration.handle_scheduled_task_created,
    "log_cleared": administration.handle_log_cleared,
    "create_remote_thread": process.handle_create_remote_thread,
    "process_access": process.handle_process_access,
    "dhcp_lease": network.handle_dhcp_lease,
    "port_scan": network.handle_port_scan,
    "beacon": periodic.handle_beacon,
    "dns_query": periodic.handle_dns_query,
    "web_scan": network.handle_web_scan,
    "credential_spray": authentication.handle_credential_spray,
    "dga_queries": periodic.handle_dga_queries,
    "dns_tunnel": periodic.handle_dns_tunnel,
    "explicit_credentials": authentication.handle_explicit_credentials,
    "workstation_lock": authentication.handle_workstation_lock,
    "workstation_unlock": authentication.handle_workstation_unlock,
    "spillage": content.handle_spillage,
    "adversarial_payload": content.handle_adversarial_payload,
    "raw": content.handle_raw,
}


def execute_typed_handler(
    runtime: StorylineMixin, spec: EventSpec, context: TypedEventContext
) -> dict[str, Any] | None:
    """Select exactly one handler, preserving the legacy unknown-type fallback."""
    handler = _HANDLERS.get(spec.type)
    if handler is None:
        return context.malicious_event
    return handler(runtime, spec, context)
