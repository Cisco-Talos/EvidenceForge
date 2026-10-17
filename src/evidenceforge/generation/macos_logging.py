# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Read-only native logging preparation against canonical State and deployment."""

from datetime import datetime

from evidenceforge.events.identity import ProcessIdentity
from evidenceforge.events.macos_logging import MacosUnifiedLogObservation, UnifiedLogCallsite
from evidenceforge.generation.deployment_registry import DeploymentContentRegistry
from evidenceforge.generation.state_manager import StateManager
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
        )
    except ValueError as error:
        raise StateError(f"Invalid Unified Log writer facts: {error}") from error
