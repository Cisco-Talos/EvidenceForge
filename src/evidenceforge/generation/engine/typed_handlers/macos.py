# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Translate explicit authored system-job stages into the shared action owner."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from evidenceforge.events.macos_launchd_spec import LaunchdSystemJobSpec
from evidenceforge.generation.actions.macos_persistence import (
    MacosPersistenceActionBundle,
    MacosPersistenceRequest,
)
from evidenceforge.generation.runtime_content import RuntimeContentIdentityManager
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
        )
    request = MacosPersistenceRequest(
        caller=caller,
        host=generator._build_host_context(context.system),
        timestamp=context.time,
        action_id=stable_uuid(
            "authored-macos-launch-item",
            context.system.hostname,
            dispatcher.authored_intent_id,
            context.time.isoformat(),
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
    bundle = MacosPersistenceActionBundle(
        state=runtime.state_manager,
        lifecycle=runtime.lifecycle_registry,
        authority=runtime.lifecycle_authority,
        dispatcher=dispatcher,
        deployments=dispatcher.deployment_registry,
        content=RuntimeContentIdentityManager(dispatcher.local_artifact_registry),
        metadata_provider=generator.macos_execution_metadata,
    )
    completed = bundle.execute(request)
    process = completed.process
    result = context.malicious_event
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
