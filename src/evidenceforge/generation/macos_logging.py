# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Read-only native logging preparation against canonical State and deployment."""

import re
from datetime import datetime

from evidenceforge.events.identity import ProcessIdentity, SessionIdentity
from evidenceforge.events.macos_logging import (
    KernelLogCallsite,
    MacosKernelLogObservation,
    MacosPolicyRefusal,
    MacosSshAuthentication,
    MacosUnifiedLogObservation,
    MacosWorkspaceRequest,
    UnifiedLogCallsite,
    kernel_writer_identity,
)
from evidenceforge.generation.activity.macos_unified_log_profiles import (
    load_macos_unified_log_profiles,
    workspace_request_callsite,
)
from evidenceforge.generation.deployment_registry import DeploymentContentRegistry
from evidenceforge.generation.state_manager import MacosPolicyRefusalAllocation, StateManager
from evidenceforge.generation.timing.macos import MachTimebase
from evidenceforge.models.exceptions import StateError


def prepare_unified_log_observation(
    state: StateManager,
    deployment: DeploymentContentRegistry,
    *,
    writer: ProcessIdentity,
    canonical_time: datetime,
    timebase: MachTimebase,
    callsite: UnifiedLogCallsite,
    message: str,
    backtrace_offsets: tuple[int, ...] = (),
) -> MacosUnifiedLogObservation:
    """Freeze the exact live writer, primary thread, build image and boot clock.

    This boundary deliberately requires the intended process object, not just a
    PID. It prepares observations at execution time; delayed rendering consumes
    the returned snapshot and must not query a subsequently reused PID or changed
    deployment. Missing facts reject this native projection without mutating the
    action, State, deployment or any collection owner.
    """
    if type(writer) is not ProcessIdentity:
        raise StateError("Unified Log preparation requires its canonical writer identity")
    if type(canonical_time) is not datetime or canonical_time.utcoffset() is None:
        raise StateError("Unified Log preparation requires an aware canonical time")
    current = state.get_process_identity_at(writer.hostname, writer.pid, canonical_time)
    if current != writer:
        raise StateError("Unified Log writer is not the exact active execution at occurrence time")
    thread = writer.primary_thread
    if thread is None or state.get_thread(writer.hostname, writer.object_id, thread.tid) != thread:
        raise StateError("Unified Log writer requires its active canonical primary thread")
    clock = state.get_macos_boot_clock(writer.hostname, timebase=timebase)
    if writer.started_at < clock.boot_time:
        raise StateError("Unified Log writer lifetime precedes its owning boot")
    binary = deployment.resolve_binary(
        writer.hostname, writer.image, "macos", principal=writer.principal
    )
    if binary is None or binary.mach_o_image is None:
        raise StateError("Unified Log writer has no exact deployed native image metadata")
    try:
        return MacosUnifiedLogObservation(
            canonical_time=canonical_time,
            writer=writer,
            thread=thread,
            binary=binary,
            boot_uuid=clock.boot_uuid,
            mach_timestamp=clock.ticks_at(canonical_time),
            callsite=callsite,
            message=message,
            backtrace_offsets=backtrace_offsets,
        )
    except ValueError as error:
        raise StateError(f"Invalid Unified Log writer facts: {error}") from error


def prepare_ssh_authentication(
    state: StateManager,
    deployment: DeploymentContentRegistry | None,
    *,
    session: SessionIdentity,
    writer: ProcessIdentity,
    authenticated_at: datetime,
    os_name: str,
    source_ip: str,
    source_port: int,
) -> MacosSshAuthentication:
    """Snapshot the root receiver's PAM success at the SSH owner's auth phase."""
    live = state.get_session(session.logon_id)
    if (
        state.get_session_identity(session.logon_id) != session
        or live is None
        or live.source_ip != source_ip
        or live.source_port != source_port
        or live.transport_pid != writer.pid
    ):
        raise StateError("SSH authentication lost its canonical peer/session/receiver ownership")
    profiles = load_macos_unified_log_profiles()
    profile = profiles.ssh_authentication
    native = None
    if (
        workspace_request_profile_available(os_name)
        and profile is not None
        and deployment is not None
    ):
        if writer.image != profile.writer_path:
            raise StateError("SSH authentication requires its exact deployed session-worker image")
        native = prepare_unified_log_observation(
            state,
            deployment,
            writer=writer,
            canonical_time=authenticated_at,
            timebase=MachTimebase(
                profiles.mach_timebase.numerator, profiles.mach_timebase.denominator
            ),
            callsite=UnifiedLogCallsite(
                message_type=profile.message_type,
                subsystem="",
                category="",
                format_string=profile.format_string,
                format_string_offset=profile.format_string_offset,
                program_counter=profile.program_counter,
                has_private_data=profile.has_private_data,
            ),
            message=profile.message.format(
                username=session.principal, source_ip=source_ip, source_port=source_port
            ),
            backtrace_offsets=profile.backtrace_offsets,
        )
    return MacosSshAuthentication(session, authenticated_at, writer, source_ip, source_port, native)


def workspace_request_profile_available(os_name: str) -> bool:
    """Return whether the OS label has the bounded native workspace profile."""
    return (
        re.fullmatch(
            r"macos\s+27(?:\.\d+){0,2}",
            os_name.strip().casefold(),
        )
        is not None
    )


def prepare_policy_refusal(
    state: StateManager,
    deployment: DeploymentContentRegistry | None,
    *,
    initiator: ProcessIdentity,
    allocation: MacosPolicyRefusalAllocation,
    os_name: str,
) -> MacosPolicyRefusal:
    """Freeze a kernel observation without claiming a target execution lifetime.

    Called against a pure cohort allocation before commit. State authenticates
    the receipt when the resulting occurrence is published. Source selection
    never controls allocation or native fact preparation.
    """
    target = allocation.target
    profiles = load_macos_unified_log_profiles()
    profile = profiles.policy_refusal
    if not workspace_request_profile_available(os_name) or profile is None:
        return MacosPolicyRefusal(target, initiator, None, "profile_unavailable")
    kernel = (
        deployment.resolve_binary(target.hostname, profile.kernel_path, "macos")
        if deployment
        else None
    )
    sender = (
        deployment.resolve_binary(target.hostname, profile.sender_path, "macos")
        if deployment
        else None
    )
    if (
        kernel is None
        or sender is None
        or kernel.mach_o_image is None
        or sender.mach_o_image is None
    ):
        return MacosPolicyRefusal(target, initiator, None, "native_image_unavailable")
    timebase = MachTimebase(profiles.mach_timebase.numerator, profiles.mach_timebase.denominator)
    clock = state.get_macos_boot_clock(target.hostname, timebase=timebase)
    writer = kernel_writer_identity(target.hostname, clock.boot_uuid, profile.kernel_export_path)
    native = MacosKernelLogObservation(
        canonical_time=target.refused_at,
        writer=writer,
        boot_time=clock.boot_time,
        boot_uuid=clock.boot_uuid,
        kernel_path=profile.kernel_export_path,
        kernel_binary=kernel,
        sender_path=profile.sender_path,
        sender_binary=sender,
        thread_id=allocation.kernel_thread_id,
        mach_timestamp=clock.ticks_at(target.refused_at),
        callsite=KernelLogCallsite(
            profile.format_string, profile.format_string_offset, profile.program_counter
        ),
        message=profile.format_string % (target.pid, target.image),
    )
    return MacosPolicyRefusal(target, initiator, native)


def prepare_workspace_request(
    state: StateManager,
    deployment: DeploymentContentRegistry | None,
    *,
    session: SessionIdentity,
    writer_pid: int,
    requested_at: datetime,
    os_name: str,
) -> MacosWorkspaceRequest:
    """Prepare a GUI request independently of source selection and collection."""
    if (
        state.get_session_identity(session.logon_id) != session
        or state.get_session_at(session.logon_id, requested_at) is None
    ):
        raise StateError("Workspace request requires its exact active session")
    writer = state.get_process_identity_at(session.hostname, writer_pid, requested_at)
    if not workspace_request_profile_available(os_name):
        return MacosWorkspaceRequest(session, requested_at, writer, None, "profile_unavailable")
    if writer is None:
        return MacosWorkspaceRequest(session, requested_at, None, None, "writer_unavailable")
    binary = (
        deployment.resolve_binary(
            writer.hostname, writer.image, "macos", principal=writer.principal
        )
        if deployment is not None
        else None
    )
    if binary is None or binary.mach_o_image is None:
        return MacosWorkspaceRequest(
            session, requested_at, writer, None, "native_image_unavailable"
        )
    profile = load_macos_unified_log_profiles()
    native = prepare_unified_log_observation(
        state,
        deployment,
        writer=writer,
        canonical_time=requested_at,
        timebase=MachTimebase(profile.mach_timebase.numerator, profile.mach_timebase.denominator),
        callsite=workspace_request_callsite(),
        message=profile.workspace_request.message,
    )
    return MacosWorkspaceRequest(session, requested_at, writer, native)
