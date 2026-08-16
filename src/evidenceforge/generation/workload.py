# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Allocation-free workload estimation and supported generation limits."""

from __future__ import annotations

import math
import re
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from evidenceforge.events.dispatcher import expand_formats
from evidenceforge.models.scenario import Scenario

_DURATION_PART = re.compile(r"(\d+)(ms|[dhms])")


class WorkloadLimits(BaseModel):
    """Documented default supported envelope for one generation run."""

    max_primary_duration_seconds: int = Field(default=31 * 86_400, gt=0)
    max_warmup_seconds: int = Field(default=7 * 86_400, gt=0)
    max_periodic_event_occurrences: int = Field(default=1_000_000, gt=0)
    max_explicit_occurrences: int = Field(default=5_000_000, gt=0)
    max_canonical_occurrences: int = Field(default=20_000_000, gt=0)
    max_rendered_records: int = Field(default=200_000_000, gt=0)
    max_attachment_bytes: int = Field(default=25 * 1024 * 1024, gt=0)
    max_message_attachment_bytes: int = Field(default=35 * 1024 * 1024, gt=0)
    max_email_payload_bytes: int = Field(default=256 * 1024 * 1024, gt=0)

    model_config = ConfigDict(frozen=True, extra="forbid")


class WorkloadEstimate(BaseModel):
    """Conservative pre-allocation estimate for one validated scenario."""

    primary_duration_seconds: int
    warmup_seconds: int
    baseline_occurrences: int
    explicit_occurrences: int
    periodic_event_max: int
    canonical_occurrences: int
    rendered_records: int
    attachment_payload_bytes: int
    email_artifact_bytes: int
    enabled_formats: int
    smb_activity_events: int = 0
    smb_catalog_files: int = 0
    smb_selector_candidates: int = 0
    smb_batch_operations: int = 0
    smb_retained_mutations: int = 0
    limit_violations: tuple[str, ...] = ()

    model_config = ConfigDict(frozen=True, extra="forbid")


def _duration_milliseconds(value: str | None) -> int:
    """Parse an already schema-validated duration without ``timedelta`` overflow."""

    if not value:
        return 0
    multipliers = {
        "d": 86_400_000,
        "h": 3_600_000,
        "m": 60_000,
        "s": 1_000,
        "ms": 1,
    }
    return sum(int(number) * multipliers[unit] for number, unit in _DURATION_PART.findall(value))


def _primary_duration_seconds(scenario: Scenario) -> int:
    window = scenario.time_window
    if window.duration is not None:
        return math.ceil(_duration_milliseconds(window.duration) / 1000)
    if window.end is None:
        return 0
    return max(0, math.ceil((window.end - window.start).total_seconds()))


def _periodic_occurrences(spec: Any, *, primary_duration_seconds: int) -> int | None:
    """Return a conservative tick count for periodic event-shaped specs."""

    if not hasattr(spec, "interval") and not hasattr(spec, "rate"):
        return None
    count = getattr(spec, "count", None)
    if count is not None:
        return int(count)
    duration = getattr(spec, "duration", None)
    duration_ms = (
        _duration_milliseconds(duration)
        if duration is not None
        else primary_duration_seconds * 1000
    )
    interval = getattr(spec, "interval", None)
    if interval is not None:
        interval_ms = _duration_milliseconds(interval)
        return math.ceil(duration_ms / max(1, interval_ms))
    rate = getattr(spec, "rate", None)
    if rate is not None:
        return math.ceil((duration_ms / 1000) * float(rate))
    return None


def _attachment_size(attachment: Any) -> int:
    content = getattr(attachment, "content", None)
    content_bytes = len(str(content).encode("utf-8")) if content is not None else 0
    return max(content_bytes, int(getattr(attachment, "size", 0) or 0))


def _raw_attachment_size(attachment: Any) -> int:
    if not isinstance(attachment, dict):
        return 0
    content = attachment.get("content")
    content_bytes = len(str(content).encode("utf-8")) if content is not None else 0
    try:
        declared = int(attachment.get("size") or 0)
    except (TypeError, ValueError):
        declared = 0
    return max(0, content_bytes, declared)


def _email_corpus_attachment_groups(
    scenario: Scenario,
    scenario_root: Path | None,
) -> dict[str, tuple[list[int], bool]]:
    email = scenario.environment.email
    if email is None or not email.corpus or scenario_root is None:
        return {}
    from evidenceforge.utils.assets import load_email_corpus_yaml

    raw = load_email_corpus_yaml(scenario_root, email.corpus) or {}
    messages = raw.get("messages", raw if isinstance(raw, list) else [])
    if not isinstance(messages, list):
        return {}
    groups: dict[str, tuple[list[int], bool]] = {}
    for index, message in enumerate(messages):
        if not isinstance(message, dict):
            continue
        attachments = message.get("attachments") or []
        if not isinstance(attachments, list):
            continue
        label = str(message.get("id") or f"corpus message {index}")
        groups[label] = (
            [_raw_attachment_size(item) for item in attachments],
            bool(message.get("background", False)),
        )
    return groups


def estimate_workload(
    scenario: Scenario,
    *,
    scenario_root: Path | None = None,
    limits: WorkloadLimits | None = None,
) -> WorkloadEstimate:
    """Estimate generation work and report every exceeded supported limit."""

    effective_limits = limits or WorkloadLimits()
    primary_seconds = _primary_duration_seconds(scenario)
    warmup_seconds = math.ceil(_duration_milliseconds(scenario.time_window.warmup) / 1000)
    generation_hours = math.ceil((primary_seconds + warmup_seconds) / 3600)
    baseline_entities = max(
        len(scenario.environment.systems),
        len([user for user in scenario.environment.users if user.enabled]),
    )
    baseline_occurrences = generation_hours * baseline_entities * 250

    explicit_occurrences = 0
    explicit_canonical_occurrences = 0
    periodic_max = 0
    attachment_groups: list[tuple[str, list[int]]] = []
    corpus_groups = _email_corpus_attachment_groups(scenario, scenario_root)
    try:
        from evidenceforge.generation.storage_world import StorageWorldModel
        from evidenceforge.models.scenario import SmbShareLocation

        storage_world = StorageWorldModel.compile(scenario)
    except (KeyError, TypeError, ValueError):
        storage_world = None
    smb_selector_candidates = 0
    smb_activity_events = 0
    smb_catalog_files = (
        sum(len(share.files) for share in storage_world.shares) if storage_world is not None else 0
    )
    smb_batch_operations = 0
    smb_retained_mutations = 0
    for authored in [*(scenario.storyline or []), *scenario.red_herrings]:
        for spec in authored.events:
            periodic = _periodic_occurrences(spec, primary_duration_seconds=primary_seconds)
            if periodic is not None:
                occurrences = periodic
                periodic_max = max(periodic_max, periodic)
            elif getattr(spec, "type", "") == "port_scan":
                target_ips = getattr(spec, "target_ips", []) or []
                target_count = len(target_ips) or int(getattr(spec, "target_count", 0) or 0)
                occurrences = target_count * len(getattr(spec, "ports", []) or [])
            elif getattr(spec, "type", "") == "process":
                from evidenceforge.generation.actions.scanner_probe import (
                    estimate_nmap_command_probe_occurrences,
                )
                from evidenceforge.generation.activity.network_params import (
                    nmap_command_probe_config,
                )

                probe_occurrences = estimate_nmap_command_probe_occurrences(
                    str(getattr(spec, "command_line", "") or ""),
                    nmap_command_probe_config(),
                )
                occurrences = max(1, probe_occurrences)
            elif getattr(spec, "type", "") == "smb_activity" and storage_world is not None:
                location = spec.target or spec.source
                if isinstance(location, SmbShareLocation):
                    candidates = storage_world.select(
                        location.share,
                        file_ref=location.file_ref,
                        path=location.path,
                        selector=location.selector,
                    )
                    smb_selector_candidates += len(candidates)
                    if spec.batch is None:
                        occurrences = 1
                    elif spec.batch.count is not None:
                        occurrences = spec.batch.count
                    elif spec.batch.fraction is not None:
                        occurrences = max(1, math.ceil(len(candidates) * spec.batch.fraction))
                    else:
                        occurrences = len(candidates)
                    smb_batch_operations += occurrences
                    if spec.operation in {"create", "update", "copy", "move", "delete"}:
                        smb_retained_mutations += occurrences
                else:
                    occurrences = 1
            else:
                occurrences = 1
            explicit_occurrences += occurrences
            if getattr(spec, "type", "") == "smb_activity":
                smb_activity_events += 1
                explicit_canonical_occurrences += 5 + occurrences * 3
            else:
                explicit_canonical_occurrences += occurrences * (
                    8 + len(getattr(spec, "ids_alerts", []) or [])
                )
            if getattr(spec, "type", "") == "email_message":
                corpus_id = getattr(spec, "corpus_id", None)
                sizes = (
                    corpus_groups.get(corpus_id, ([], False))[0]
                    if corpus_id
                    else [_attachment_size(item) for item in getattr(spec, "attachments", [])]
                )
                attachment_groups.append((f"storyline event {authored.id}", sizes))

    email_config = scenario.environment.email
    background_groups = [
        (f"background corpus message {entry_id}", sizes)
        for entry_id, (sizes, background) in corpus_groups.items()
        if background
    ]
    background_attachment_payload = 0
    if (
        email_config is not None
        and email_config.background_messages_per_user_per_day > 0
        and background_groups
    ):
        attachment_groups.extend(background_groups)
        primary_hours = math.ceil(primary_seconds / 3600)
        eligible_users = sum(
            1 for user in scenario.environment.users if user.enabled and user.email
        )
        background_email_occurrences = primary_hours * eligible_users
        background_attachment_payload = background_email_occurrences * max(
            sum(sizes) for _label, sizes in background_groups
        )

    authored_attachment_payload = sum(
        sum(sizes)
        for label, sizes in attachment_groups
        if not label.startswith("background corpus message ")
    )
    attachment_payload_bytes = authored_attachment_payload + background_attachment_payload
    email_artifact_bytes = math.ceil(attachment_payload_bytes * 4 / 3)
    enabled_formats = len(
        expand_formats({entry["format"] for entry in scenario.output.logs if "format" in entry})
    )
    canonical_occurrences = baseline_occurrences + explicit_canonical_occurrences
    rendered_records = canonical_occurrences * max(1, enabled_formats)

    violations: list[str] = []
    if primary_seconds > effective_limits.max_primary_duration_seconds:
        violations.append(
            "primary duration "
            f"{primary_seconds}s exceeds {effective_limits.max_primary_duration_seconds}s"
        )
    if warmup_seconds > effective_limits.max_warmup_seconds:
        violations.append(
            f"warmup {warmup_seconds}s exceeds {effective_limits.max_warmup_seconds}s"
        )
    if periodic_max > effective_limits.max_periodic_event_occurrences:
        violations.append(
            "one periodic event projects "
            f"{periodic_max} occurrences; limit is "
            f"{effective_limits.max_periodic_event_occurrences}"
        )
    if explicit_occurrences > effective_limits.max_explicit_occurrences:
        violations.append(
            f"explicit occurrences {explicit_occurrences} exceed "
            f"{effective_limits.max_explicit_occurrences}"
        )
    if canonical_occurrences > effective_limits.max_canonical_occurrences:
        violations.append(
            f"estimated canonical occurrences {canonical_occurrences} exceed "
            f"{effective_limits.max_canonical_occurrences}"
        )
    if rendered_records > effective_limits.max_rendered_records:
        violations.append(
            f"estimated rendered records {rendered_records} exceed "
            f"{effective_limits.max_rendered_records}"
        )
    for label, sizes in attachment_groups:
        for size in sizes:
            if size > effective_limits.max_attachment_bytes:
                violations.append(
                    f"{label} attachment {size} bytes exceeds "
                    f"{effective_limits.max_attachment_bytes}"
                )
        total = sum(sizes)
        if total > effective_limits.max_message_attachment_bytes:
            violations.append(
                f"{label} attachments total {total} bytes exceeds "
                f"{effective_limits.max_message_attachment_bytes}"
            )
    if email_artifact_bytes > effective_limits.max_email_payload_bytes:
        violations.append(
            f"estimated email artifact expansion {email_artifact_bytes} bytes exceeds "
            f"{effective_limits.max_email_payload_bytes}"
        )

    return WorkloadEstimate(
        primary_duration_seconds=primary_seconds,
        warmup_seconds=warmup_seconds,
        baseline_occurrences=baseline_occurrences,
        explicit_occurrences=explicit_occurrences,
        periodic_event_max=periodic_max,
        canonical_occurrences=canonical_occurrences,
        rendered_records=rendered_records,
        attachment_payload_bytes=attachment_payload_bytes,
        email_artifact_bytes=email_artifact_bytes,
        enabled_formats=enabled_formats,
        smb_activity_events=smb_activity_events,
        smb_catalog_files=smb_catalog_files,
        smb_selector_candidates=smb_selector_candidates,
        smb_batch_operations=smb_batch_operations,
        smb_retained_mutations=smb_retained_mutations,
        limit_violations=tuple(violations),
    )


def enforce_workload_limits(
    scenario: Scenario,
    *,
    scenario_root: Path | None = None,
    limits: WorkloadLimits | None = None,
    allow_large_workload: bool = False,
) -> WorkloadEstimate:
    """Return an estimate without rejecting large workloads.

    ``allow_large_workload`` remains as a compatibility-only library argument. Resource
    projections and live machine capacity now inform non-fatal CLI warnings.
    """
    _ = allow_large_workload
    return estimate_workload(scenario, scenario_root=scenario_root, limits=limits)
