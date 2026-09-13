# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Typed storyline content handlers."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from evidenceforge.models.scenario import (
    AdversarialPayloadEventSpec,
    EmailMessageEventSpec,
    EmailReadEventSpec,
    RawEventSpec,
    SmbActivityEventSpec,
    SpillageEventSpec,
)

from .context import TypedEventContext

if TYPE_CHECKING:
    from evidenceforge.generation.engine.storyline import StorylineMixin


def handle_email_message(
    self: StorylineMixin, spec: EmailMessageEventSpec, context: TypedEventContext
) -> dict[str, Any] | None:
    """Execute the email_message evidence path using the existing runtime owners."""
    actor = context.actor
    system = context.system
    time = context.time
    activity = context.activity
    dispatcher = context.dispatcher
    malicious_event = context.malicious_event
    result = self.activity_generator.generate_email_message(
        spec=spec,
        actor=actor,
        system=system,
        time=time,
        activity=activity,
        storyline_id=getattr(dispatcher, "storyline_cluster_id", "") or "",
    )
    malicious_event.update(
        {
            "artifact_id": result.artifact_id,
            "message_id": result.message_id,
            "sender": result.sender,
            "recipients": result.recipients,
            "subject": result.subject,
            "outcome": result.outcome,
            "artifact_path": result.artifact_path,
            "smtp_uids": result.smtp_uids,
            "route": result.route,
        }
    )

    return context.malicious_event


def handle_email_read(
    self: StorylineMixin, spec: EmailReadEventSpec, context: TypedEventContext
) -> dict[str, Any] | None:
    """Execute the email_read evidence path using the existing runtime owners."""
    actor = context.actor
    system = context.system
    time = context.time
    activity = context.activity
    dispatcher = context.dispatcher
    malicious_event = context.malicious_event
    result = self.activity_generator.generate_email_read(
        spec=spec,
        actor=actor,
        system=system,
        time=time,
        activity=activity,
        storyline_id=getattr(dispatcher, "storyline_cluster_id", "") or "",
    )
    malicious_event.update(result)

    return context.malicious_event


def handle_smb_activity(
    self: StorylineMixin, spec: SmbActivityEventSpec, context: TypedEventContext
) -> dict[str, Any] | None:
    """Execute the smb_activity evidence path using the existing runtime owners."""
    actor = context.actor
    system = context.system
    time = context.time
    rng = context.rng
    malicious_event = context.malicious_event
    time = self._storyline_smb_file_ready_time(
        system=system,
        spec=spec,
        requested_at=time,
        rng=rng,
    )
    malicious_event["time"] = time
    smb_actor, smb_spec = self._storyline_smb_actor_and_spec(
        actor,
        system,
        time,
        spec,
    )
    result = self.activity_generator.generate_smb_activity(
        spec=smb_spec,
        actor=smb_actor,
        parent_system=system,
        time=time,
        client_source_override=self._storyline_smb_source_override(
            system=system,
            spec=smb_spec,
        ),
    )
    malicious_event.update(
        {
            "session_id": result.session_id,
            "tree_ids": list(result.tree_ids),
            "transport_uids": list(result.transport_uids),
            "operations": list(result.operations),
            "batch_summary": {
                "selected": len(result.operations),
                "outcomes": sorted({operation["outcome"] for operation in result.operations}),
            },
        }
    )

    return context.malicious_event


def handle_spillage(
    self: StorylineMixin, spec: SpillageEventSpec, context: TypedEventContext
) -> dict[str, Any] | None:
    """Execute the spillage evidence path using the existing runtime owners."""
    actor = context.actor
    system = context.system
    time = context.time
    rng = context.rng
    malicious_event = context.malicious_event
    from evidenceforge.generation.spillage import HTTP_SURFACES

    cluster_id = malicious_event["storyline_cluster_id"]
    # Monotonic per-generation sequence makes every spillage value unique
    # (deterministic order); eval reads the emitted value from ground truth.
    seq = getattr(self, "_spillage_seq", 0)
    self._spillage_seq = seq + 1
    spill_logon_id = None
    spill_target = None
    spill_scheme = spec.scheme
    # process_command_line spills run as a standalone process-execution
    # record with a durable unique PID, using local carriers only (no
    # implied outbound network). We deliberately do NOT attach the spill to
    # an interactive shell session: a foreground bash child competes for
    # that shell's serialized command timeline and, under heavy baseline,
    # can be shifted and dropped during eCAR post-flush normalization —
    # leaving a labeled-but-unwritten credential (a phantom). A standalone
    # process keeps a stable, unique identity and always lands.
    if spec.surface == "process_command_line":
        spill_logon_id = self._resolve_storyline_process_spill_logon_id(
            actor,
            system,
            time,
            rng,
        )
    if spec.surface in HTTP_SURFACES:
        # The credential leaks into a web server's access log; pick the
        # destination web server (the validator requires one to exist).
        spill_target, spill_scheme = self._select_web_server_for_spillage(system, spec.scheme)
    info = self.activity_generator.generate_spillage(
        user=actor,
        system=system,
        time=time,
        surface=spec.surface,
        family=spec.family,
        value=spec.value,
        scheme=spill_scheme,
        seed_key=f"spillage:{cluster_id}:{seq}:{spec.surface}:{spec.family or 'literal'}",
        logon_id=spill_logon_id,
        target_system=spill_target,
    )
    malicious_event["surface"] = info["surface"]
    malicious_event["family"] = info["family"]
    if info.get("skipped_reason"):
        # Credential was not emitted (e.g. dwell-shifted past the window);
        # mark it so no phantom ground-truth record is written.
        malicious_event["skipped_reason"] = info["skipped_reason"]
    else:
        malicious_event["value"] = info["value"]
        malicious_event["rendered_value"] = info["rendered_value"]
        malicious_event["expected_sources"] = info["expected_sources"]
        # Reflect the actual emitted time (bash dwell scheduling may shift it).
        malicious_event["time"] = info["time"]
        if info.get("target_system"):
            # http_* surfaces land on the destination web server's access
            # log; record its FQDN (as the generator names the access-log
            # directory) so ground truth and eval can locate the trace.
            malicious_event["target_system"] = info["target_system"]
        if info.get("scheme"):
            malicious_event["scheme"] = info["scheme"]

    return context.malicious_event


def handle_adversarial_payload(
    self: StorylineMixin, spec: AdversarialPayloadEventSpec, context: TypedEventContext
) -> dict[str, Any] | None:
    """Execute the adversarial_payload evidence path using the existing runtime owners."""
    actor = context.actor
    system = context.system
    time = context.time
    rng = context.rng
    malicious_event = context.malicious_event
    from evidenceforge.generation.adversarial_payload import HTTP_SURFACES

    cluster_id = malicious_event["storyline_cluster_id"]
    # Monotonic per-generation sequence makes every synthesized payload
    # unique (deterministic order); eval reads the emitted value from
    # ground truth.
    seq = getattr(self, "_adversarial_payload_seq", 0)
    self._adversarial_payload_seq = seq + 1
    payload_logon_id = None
    payload_target = None
    payload_scheme = None
    # A process_command_line payload runs as a standalone process-execution
    # record; resolve canonical session ownership (same as a spillage process
    # spill) so it gets a non-shell parent and a stable, unique identity.
    if spec.surface == "process_command_line":
        payload_logon_id = self._resolve_storyline_process_spill_logon_id(
            actor,
            system,
            time,
            rng,
        )
    if spec.surface in HTTP_SURFACES:
        # The payload rides to a web server's access log; pick the destination.
        # An authored `scheme:` (http/https) forces the transport; otherwise the
        # server's supported scheme decides (https preferred, else http).
        payload_target, payload_scheme = self._select_web_server_for_spillage(system, spec.scheme)
    info = self.activity_generator.generate_adversarial_payload(
        user=actor,
        system=system,
        time=time,
        surface=spec.surface,
        family=spec.family,
        value=spec.value,
        scheme=payload_scheme,
        seed_key=f"adversarial_payload:{cluster_id}:{seq}:{spec.surface}:{spec.family or 'literal'}",
        logon_id=payload_logon_id,
        target_system=payload_target,
    )
    malicious_event["surface"] = info["surface"]
    malicious_event["family"] = info["family"]
    if info.get("skipped_reason"):
        malicious_event["skipped_reason"] = info["skipped_reason"]
    else:
        malicious_event["value"] = info["value"]
        malicious_event["rendered_value"] = info["rendered_value"]
        malicious_event["expected_sources"] = info["expected_sources"]
        malicious_event["encoding"] = info["encoding"]
        malicious_event["time"] = info["time"]
        if info.get("target_system"):
            malicious_event["target_system"] = info["target_system"]
        if info.get("scheme"):
            malicious_event["scheme"] = info["scheme"]
        if info.get("callback_host"):
            malicious_event["callback_host"] = info["callback_host"]
        if info.get("weakness_class"):
            malicious_event["weakness_class"] = info["weakness_class"]
        if info.get("expected_defender_signal"):
            malicious_event["expected_defender_signal"] = info["expected_defender_signal"]
        if info.get("ids_alert"):
            malicious_event["ids_alert"] = info["ids_alert"]
        # Pivot anchors to the exact evidence row (dst tuple for http, pid for
        # process) so an analyst can jump from the payload record to the source.
        for pivot_key in ("dst_ip", "dst_port", "pid"):
            if info.get(pivot_key) is not None:
                malicious_event[pivot_key] = info[pivot_key]

    return context.malicious_event


def handle_raw(
    self: StorylineMixin, spec: RawEventSpec, context: TypedEventContext
) -> dict[str, Any] | None:
    """Execute the raw evidence path using the existing runtime owners."""
    system = context.system
    time = context.time
    malicious_event = context.malicious_event
    self.activity_generator.generate_raw(
        time=time,
        target_format=spec.target_format,
        fields=spec.fields,
        system=system,
    )
    malicious_event["target_format"] = spec.target_format

    return context.malicious_event
