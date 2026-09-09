# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Source-instance-aware evidence reachability analysis for resolved scenarios."""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass

from evidenceforge.events.evidence_requirements import (
    AUTHORED_EVENT_EVIDENCE_CONTRACTS,
    PERSISTENT_WINDOWS_SMB_EVIDENCE,
    BehaviorEvidenceContract,
    EvidenceProjectionAlternative,
    EvidenceSourceScope,
)
from evidenceforge.events.source_catalog import DEFAULT_SOURCE_CATALOG, SourceOwnerKind
from evidenceforge.generation.collection_deployment import (
    CompiledCollectionDeployment,
    SourceInstanceDeployment,
)
from evidenceforge.generation.source_deployment_compiler import (
    SourceDeploymentCompilationError,
    compile_scenario_source_deployment,
)
from evidenceforge.generation.storage_world import StorageWorldModel
from evidenceforge.generation.world_model import WorldModel
from evidenceforge.models import Scenario
from evidenceforge.utils.time import resolve_time_window


@dataclass(frozen=True, slots=True)
class EvidenceReachabilityFinding:
    """One configured behavior with no possible effective evidence projection."""

    behavior_id: str
    severity: str
    field_path: str
    message: str
    suggestion: str


@dataclass(frozen=True, slots=True)
class _BehaviorActivation:
    contract: BehaviorEvidenceContract
    field_path: str
    participant_hosts: frozenset[str]
    detail: str


def _source_window_overlaps_scenario(source: SourceInstanceDeployment, scenario: Scenario) -> bool:
    start, end = resolve_time_window(scenario.time_window)
    return any(
        (window.end is None or start < window.end) and (window.start is None or window.start < end)
        for window in source.policy.windows
    )


def _source_in_scope(
    source: SourceInstanceDeployment,
    *,
    source_format: str,
    activation: _BehaviorActivation,
) -> bool:
    scope = activation.contract.source_scope
    if scope is EvidenceSourceScope.ANY:
        return True
    descriptor = DEFAULT_SOURCE_CATALOG.descriptor(source_format)
    hostname = source.identity.hostname.casefold()
    if scope is EvidenceSourceScope.TARGET_HOST:
        return descriptor.owner is SourceOwnerKind.HOST and hostname in activation.participant_hosts
    return descriptor.owner is SourceOwnerKind.SENSOR or hostname in activation.participant_hosts


def _alternative_is_reachable(
    alternative: EvidenceProjectionAlternative,
    *,
    activation: _BehaviorActivation,
    deployment: CompiledCollectionDeployment,
    scenario: Scenario,
) -> bool:
    for source_format in sorted(alternative.formats):
        for source in deployment.iter_format(source_format):
            if not source.policy.enabled:
                continue
            if not source.policy.capabilities.covers(alternative.capabilities):
                continue
            if source.policy.missingness_for(source_format) >= 1.0:
                continue
            if not _source_window_overlaps_scenario(source, scenario):
                continue
            if _source_in_scope(
                source,
                source_format=source_format,
                activation=activation,
            ):
                return True
    return False


def _activation_is_reachable(
    activation: _BehaviorActivation,
    *,
    deployment: CompiledCollectionDeployment,
    scenario: Scenario,
) -> bool:
    return any(
        _alternative_is_reachable(
            alternative,
            activation=activation,
            deployment=deployment,
            scenario=scenario,
        )
        for alternative in activation.contract.alternatives
    )


def _authored_event_activations(scenario: Scenario) -> tuple[_BehaviorActivation, ...]:
    grouped: dict[tuple[str, str], list[tuple[str, str]]] = {}
    known_hosts = {system.hostname.casefold() for system in scenario.environment.systems}
    for section_name, events in (
        ("storyline", scenario.storyline or ()),
        ("red_herrings", scenario.red_herrings or ()),
    ):
        for event_index, event in enumerate(events):
            hostname = event.system.casefold()
            if hostname not in known_hosts:
                continue
            for spec_index, spec in enumerate(event.events):
                contract = AUTHORED_EVENT_EVIDENCE_CONTRACTS.get(spec.type)
                if contract is None:
                    continue
                field_path = f"{section_name}.{event_index}.events.{spec_index}"
                grouped.setdefault(
                    (contract.behavior_id, hostname),
                    [],
                ).append((field_path, event.id))

    activations: list[_BehaviorActivation] = []
    contracts_by_id = {
        contract.behavior_id: contract for contract in AUTHORED_EVENT_EVIDENCE_CONTRACTS.values()
    }
    for (behavior_id, hostname), occurrences in sorted(grouped.items()):
        contract = contracts_by_id[behavior_id]
        event_ids = tuple(dict.fromkeys(event_id for _path, event_id in occurrences))
        shown_ids = ", ".join(repr(event_id) for event_id in event_ids[:3])
        if len(event_ids) > 3:
            shown_ids += f", and {len(event_ids) - 3} more"
        activations.append(
            _BehaviorActivation(
                contract=contract,
                field_path=occurrences[0][0],
                participant_hosts=frozenset({hostname}),
                detail=f"target host {hostname!r} in event(s) {shown_ids}",
            )
        )
    return tuple(activations)


def _persistent_windows_smb_activation(scenario: Scenario) -> _BehaviorActivation | None:
    try:
        storage = StorageWorldModel.compile(scenario)
    except (KeyError, TypeError, ValueError):
        return None

    systems = {system.hostname.casefold(): system for system in scenario.environment.systems}
    server_hosts = frozenset(
        share.system.casefold()
        for share in storage.shares
        if share.files
        and (system := systems.get(share.system.casefold())) is not None
        and "windows" in system.os.casefold()
    )
    if not server_hosts:
        return None

    world = WorldModel(scenario, scenario.environment.domain or "corp.local")
    client_hosts = frozenset(
        system.hostname.casefold()
        for system in world.smb_clients
        if any(system.hostname.casefold() != server for server in server_hosts)
    )
    explicit_event_ids = tuple(
        event.id
        for events in (scenario.storyline or (), scenario.red_herrings or ())
        for event in events
        if any(spec.type == "smb_activity" for spec in event.events)
    )
    if not client_hosts and not explicit_event_ids:
        return None

    servers = ", ".join(sorted(server_hosts))
    detail = f"Windows SMB server(s) {servers}"
    if explicit_event_ids:
        detail += " and authored SMB event(s) " + ", ".join(
            repr(event_id) for event_id in explicit_event_ids[:3]
        )
    else:
        detail += " with baseline-capable SMB clients"
    return _BehaviorActivation(
        contract=PERSISTENT_WINDOWS_SMB_EVIDENCE,
        field_path="output.logs",
        participant_hosts=server_hosts | client_hosts,
        detail=detail,
    )


def _observable_source_formats(
    deployment: CompiledCollectionDeployment,
    scenario: Scenario,
) -> tuple[str, ...]:
    """Return formats with at least one source that can observe part of the scenario."""

    return tuple(
        sorted(
            {
                source_format
                for source in deployment
                if source.policy.enabled and _source_window_overlaps_scenario(source, scenario)
                for source_format in source.formats
                if source.policy.missingness_for(source_format) < 1.0
            }
        )
    )


def analyze_evidence_reachability(
    scenario: Scenario,
    *,
    emitter_formats: Iterable[str] | None = None,
) -> tuple[EvidenceReachabilityFinding, ...]:
    """Return configured behaviors that no effective source can ever express."""

    try:
        compilation = compile_scenario_source_deployment(
            scenario,
            emitter_formats=emitter_formats,
        )
    except SourceDeploymentCompilationError:
        # Existing format, sensor, profile, and observation validation owns malformed
        # deployments. Reachability only reasons about a successfully compiled deployment.
        return ()

    activations = list(_authored_event_activations(scenario))
    smb_activation = _persistent_windows_smb_activation(scenario)
    if smb_activation is not None:
        activations.append(smb_activation)

    observable_formats = _observable_source_formats(compilation.deployment, scenario)
    observable_text = ", ".join(observable_formats) if observable_formats else "none"
    findings: list[EvidenceReachabilityFinding] = []
    for activation in activations:
        if _activation_is_reachable(
            activation,
            deployment=compilation.deployment,
            scenario=scenario,
        ):
            continue
        contract = activation.contract
        findings.append(
            EvidenceReachabilityFinding(
                behavior_id=contract.behavior_id,
                severity=contract.unreachable_severity.value,
                field_path=activation.field_path,
                message=(
                    f"Configured {contract.label} has no possible evidence projection for "
                    f"{activation.detail}. Potentially observable source formats: "
                    f"{observable_text}."
                ),
                suggestion=contract.suggestion,
            )
        )
    return tuple(
        sorted(
            findings,
            key=lambda finding: (
                finding.severity != "error",
                finding.field_path,
                finding.behavior_id,
            ),
        )
    )


__all__ = ["EvidenceReachabilityFinding", "analyze_evidence_reachability"]
