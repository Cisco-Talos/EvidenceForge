# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Prepare creator and new-process token facts for ordinary modeled Windows launches."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import replace

from evidenceforge.events.base import OccurrenceBuilder
from evidenceforge.events.contexts import ProcessTargetSecurityContext
from evidenceforge.events.identity import ProcessIdentity
from evidenceforge.generation.activity.process_helpers import (
    _SYSTEM_ACCOUNT_LOGON_IDS,
    _SYSTEM_ACCOUNTS,
)
from evidenceforge.models.exceptions import StateError


def prepare_windows_process_creation_security(
    event: OccurrenceBuilder,
    *,
    creator: ProcessIdentity | None,
    sid_for: Callable[[str], str],
) -> None:
    """Resolve ordinary creation from its explicit canonical actor before source preparation.

    The process action declares its requesting actor. This is not an inference
    that every real parent uses its primary token: separately supplied target
    contexts and unknown actors remain untouched. SID resolution stays with the
    injected identity owner; this policy owns no State, cache or identifier pool.
    """
    host = event.src_host or event.dst_host
    auth, process = event.auth, event.process
    if (
        host is None
        or host.os_category != "windows"
        or event.event_type not in {"process_create", "system_process_create"}
        or auth is None
        or process is None
        or not isinstance(creator, ProcessIdentity)
        or process.target_security_context is not None
        or auth.username.casefold() != process.username.casefold()
    ):
        return
    if creator.hostname.casefold() != host.hostname.casefold() or creator.pid != process.parent_pid:
        raise StateError("Windows process creator disagrees with the canonical host/parent")
    if process.start_time is not None and creator.started_at > process.start_time:
        raise StateError("Windows process creator starts after its child")
    if (
        auth.logon_id
        and process.logon_id
        and auth.logon_id.casefold() != process.logon_id.casefold()
    ):
        raise StateError("Windows new-process authentication and process logons disagree")
    child_logon_id = process.logon_id or auth.logon_id
    creator_name = creator.principal
    creator_builtin = creator_name.upper() in _SYSTEM_ACCOUNTS
    creator_logon_id = creator.logon_id or _SYSTEM_ACCOUNT_LOGON_IDS.get(creator_name.upper(), "")
    if not child_logon_id or not creator_logon_id:
        return
    creator_sid = (
        auth.user_sid
        if creator_name.casefold() == auth.username.casefold()
        else sid_for(creator_name.upper() if creator_builtin else creator_name)
    )
    if (
        not isinstance(creator_sid, str)
        or not isinstance(auth.user_sid, str)
        or creator_sid in {"", "S-1-0-0"}
        or auth.user_sid in {"", "S-1-0-0"}
    ):
        return
    target = None
    if creator_sid != auth.user_sid or creator_logon_id.casefold() != child_logon_id.casefold():
        target = ProcessTargetSecurityContext(
            user_sid=auth.user_sid,
            username=process.username,
            domain="NT AUTHORITY"
            if process.username.upper() in _SYSTEM_ACCOUNTS
            else host.netbios_domain,
            logon_id=child_logon_id,
        )
    event.auth = replace(
        auth,
        subject_sid=creator_sid,
        subject_username=creator_name,
        subject_domain="NT AUTHORITY" if creator_builtin else host.netbios_domain,
        subject_logon_id=creator_logon_id,
    )
    event.process = replace(process, target_security_context=target)
