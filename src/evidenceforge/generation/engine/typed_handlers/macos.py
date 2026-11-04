# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Translate explicit authored system-job stages into the shared action owner."""

from __future__ import annotations

from datetime import timedelta
from typing import TYPE_CHECKING, Any

from evidenceforge.events.macos_launchd_spec import LaunchdSystemJobSpec
from evidenceforge.generation.actions.macos_persistence import (
    MacosPersistenceActionBundle,
    MacosPersistenceRequest,
)
from evidenceforge.generation.runtime_content import RuntimeContentIdentityManager
from evidenceforge.generation.storyline_timing import STORYLINE_EVENT_JITTER_SECONDS
from evidenceforge.models.exceptions import StateError
from evidenceforge.models.scenario import MacosLaunchItemEventSpec
from evidenceforge.utils.rng import stable_uuid

from .context import TypedEventContext

if TYPE_CHECKING:
    from evidenceforge.generation.engine.storyline import StorylineMixin


def handle_launch_item(
    runtime: StorylineMixin, spec: MacosLaunchItemEventSpec, context: TypedEventContext
) -> dict[str, Any]:
    """Bind a real earlier caller; never use a control marker as activation proof."""
    reference = getattr(runtime, "_storyline_process_refs", {}).get(
        (context.system.hostname, context.actor.username, spec.caller_ref)
    )
    if reference is None or len(reference) != 3:
        raise StateError("Launch-item stage requires an earlier exact caller_ref lifetime")
    caller = runtime.state_manager.get_process_identity(context.system.hostname, reference[0])
    if caller is None or (caller.image, caller.object_id) != (reference[1], reference[2]):
        raise StateError("Launch-item caller_ref no longer names its original live process")
    generator = runtime.activity_generator
    dispatcher = runtime.dispatcher
    if (
        dispatcher is None
        or dispatcher.deployment_registry is None
        or dispatcher.local_artifact_registry is None
    ):
        raise StateError("Launch-item stages require compiled deployment and publication owners")
    definition = None
    if spec.operation == "write":
        definition = LaunchdSystemJobSpec(
            label=spec.label,
            program=spec.program,
            arguments=tuple(spec.arguments),
            principal="root",
            run_at_load=spec.run_at_load,
            launch_profile=spec.launch_profile,
        )
    bundle = MacosPersistenceActionBundle(
        state=runtime.state_manager,
        lifecycle=runtime.lifecycle_registry,
        authority=runtime.lifecycle_authority,
        dispatcher=dispatcher,
        deployments=dispatcher.deployment_registry,
        content=RuntimeContentIdentityManager(dispatcher.local_artifact_registry),
        metadata_provider=generator.macos_execution_metadata,
        native_startups=generator._macos_finder_startups,
    )
    at = (
        bundle.plan_exit_time(
            hostname=context.system.hostname,
            label=spec.label,
            requested_at=context.time,
            exit_code=spec.exit_code,
            latest_at=context.authored_nominal_time
            + timedelta(seconds=STORYLINE_EVENT_JITTER_SECONDS, microseconds=999999)
            if context.authored_nominal_time is not None
            else None,
        )
        if spec.operation == "exit"
        else context.time
    )
    runtime.state_manager.set_current_time(at)
    request = MacosPersistenceRequest(
        caller=caller,
        host=generator._build_host_context(context.system),
        timestamp=at,
        action_id=stable_uuid(
            "authored-macos-launch-item",
            context.system.hostname,
            dispatcher.authored_intent_id,
            at.isoformat(),
            spec.operation,
            spec.label,
        ),
        operation=spec.operation,
        label=spec.label,
        path=spec.path,
        definition=definition,
        version=spec.version,
        size_bytes=spec.size_bytes,
        exit_code=spec.exit_code,
    )
    completed = bundle.execute(request)
    process = completed.process
    result = context.malicious_event
    result["time"] = at
    result.update(launchd_operation=spec.operation, launchd_label=spec.label, outcome="success")
    result["process_object_ids"] = [process.object_id for process in completed.terminated] + (
        [process.object_id] if process is not None else []
    )
    if completed.file_action is not None:
        result["action"] = completed.file_action
        result["actor_object_id"] = caller.object_id
    if spec.path is not None:
        result["file_path"] = spec.path
    if process is not None:
        if process.execution_ordinal == 2 and spec.operation == "activate":
            result["native_process_model"] = "launchd_exec"
        result.update(
            pid=process.pid, process_name=process.image, command_line=process.command_line
        )
        if spec.process_ref is not None:
            runtime._record_storyline_process_ref(
                actor=context.actor,
                system=context.system,
                process_ref=spec.process_ref,
                pid=process.pid,
                image=process.image,
            )
    if not completed.observable:
        result.update(skipped_reason="native_job_control_evidence_unavailable", expected_sources=[])
    return result
