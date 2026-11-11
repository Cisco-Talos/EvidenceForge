"""Preflight typed-fact coverage on planned hosts and paths, without execution."""

from __future__ import annotations

import re
from datetime import datetime
from typing import TYPE_CHECKING
from urllib.parse import urlsplit

from evidenceforge.events.collection_policy import CollectionCapability
from evidenceforge.events.evidence_projection import source_event_contracts
from evidenceforge.events.evidence_requirements import (
    BehaviorEvidenceContract,
    EvidenceProjectionAlternative,
    EvidenceReachabilitySeverity,
    EvidenceSourceScope,
)
from evidenceforge.events.source_catalog import DEFAULT_SOURCE_CATALOG, SourceOwnerKind
from evidenceforge.generation.collection_deployment import CompiledCollectionDeployment
from evidenceforge.generation.network_visibility import NetworkVisibilityEngine
from evidenceforge.models import Scenario
from evidenceforge.utils.time import parse_duration, resolve_time_window

if TYPE_CHECKING:
    from evidenceforge.validation.evidence_reachability import EvidenceReachabilityFinding


def _fact_contract(name: str) -> BehaviorEvidenceContract:
    rule = source_event_contracts()["typed_facts"][name]
    return BehaviorEvidenceContract(
        behavior_id="typed_fact_" + name,
        label=name.replace("_", " "),
        alternatives=(
            EvidenceProjectionAlternative(
                formats=frozenset(rule["formats"]),
                capabilities=CollectionCapability[rule["capability"]],
            ),
        ),
        source_scope=EvidenceSourceScope.PARTICIPANT_OR_SENSOR,
        unreachable_severity=EvidenceReachabilitySeverity.WARNING,
        suggestion="Enable a capable source on the relevant host or transport leg, and export its format.",
    )


def analyze_typed_fact_visibility(
    scenario: Scenario, deployment: CompiledCollectionDeployment
) -> list[EvidenceReachabilityFinding]:
    """Check important authored facts and report conditional or optional source risks."""
    from evidenceforge.validation.evidence_reachability import EvidenceReachabilityFinding

    findings: list[EvidenceReachabilityFinding] = []
    start, end = resolve_time_window(scenario.time_window)
    hosts = {system.hostname.casefold(): system for system in scenario.environment.systems}
    visibility = NetworkVisibilityEngine(scenario.environment.network, scenario.environment.systems)
    for section, steps in (
        ("storyline", scenario.storyline),
        ("red_herrings", scenario.red_herrings),
    ):
        for step_index, step in enumerate(steps or []):
            source = hosts.get(step.system.casefold())
            if source is None:
                continue
            anchor: datetime | None = None
            try:
                anchor = (
                    start + parse_duration(step.time[1:])
                    if step.time.startswith("+")
                    else datetime.fromisoformat(step.time.replace("Z", "+00:00"))
                )
            except ValueError:
                pass
            for spec_index, spec in enumerate(step.events):
                facts: list[str] = []
                destination = getattr(spec, "dst_ip", None)
                service = getattr(spec, "service", None)
                conditional = spec.type in {
                    "beacon",
                    "web_scan",
                    "port_scan",
                    "dns_tunnel",
                    "dga_queries",
                    "credential_spray",
                }
                if spec.type in {"connection", "beacon", "port_scan", "web_scan"}:
                    facts.append("transport")
                if getattr(spec, "status_code", None) is not None or any(
                    item.status_code is not None for item in getattr(spec, "http_sequence", [])
                ):
                    facts.append("http_result")
                if spec.type == "dhcp_lease":
                    facts.append("dhcp_lease")
                    destination = "255.255.255.255"
                if spec.type in {"dns_query", "dns_tunnel", "dga_queries"}:
                    facts.append("dns_answer")
                    destination = destination or "9.9.9.9"
                    conditional = conditional or spec.type != "dns_query"
                if spec.type in {"logon", "failed_logon", "rdp_session", "credential_spray"}:
                    facts.append("authentication")
                if spec.type == "email_message":
                    facts.append("smtp_result")
                    conditional = True
                if spec.type == "process" and spec.outcome == "success":
                    match = re.search(r"https?://[^\s'\"<>]+", spec.command_line or "")
                    if match:
                        try:
                            parsed = urlsplit(match.group(0).rstrip(").,;]"))
                            parsed_host = parsed.hostname
                        except ValueError:
                            parsed = urlsplit("")
                            parsed_host = None
                        destination = next(
                            (
                                host.ip
                                for host in hosts.values()
                                if host.hostname.casefold() == str(parsed_host).casefold()
                            ),
                            None,
                        )
                        service = "ssl" if parsed.scheme == "https" else "http"
                        facts.append("transport")
                        conditional = destination is None
                if not facts:
                    continue
                path = f"{section}.{step_index}.events.{spec_index}"
                for fact in facts:
                    contract = _fact_contract(fact)
                    exclusions: list[str] = []
                    reachable = False
                    for alternative in contract.alternatives:
                        for fmt in sorted(alternative.formats):
                            descriptor = DEFAULT_SOURCE_CATALOG.descriptor(fmt)
                            candidates = list(deployment.iter_format(fmt))
                            if not candidates:
                                exclusions.append(f"{fmt}: source not deployed or not exported")
                            for candidate in candidates:
                                reasons: list[str] = []
                                if descriptor.owner is SourceOwnerKind.HOST:
                                    expected_host = source.hostname.casefold()
                                    if fmt in {"proxy_access", "web_access"}:
                                        # Server-side coverage is conditional until routing selects the leg.
                                        if fmt == "web_access" and destination:
                                            target = next(
                                                (
                                                    host
                                                    for host in hosts.values()
                                                    if host.ip == destination
                                                ),
                                                None,
                                            )
                                            if (
                                                target is None
                                                or candidate.identity.hostname
                                                != target.hostname.casefold()
                                            ):
                                                continue
                                        conditional = True
                                    elif candidate.identity.hostname != expected_host:
                                        continue
                                elif destination:
                                    observing = (
                                        visibility.get_link_local_sensors(source.ip)
                                        if fact == "dhcp_lease"
                                        else visibility.get_source_side_sensors(
                                            source.ip, destination
                                        )
                                        if getattr(spec, "action", None) == "deny"
                                        else visibility.get_observing_sensors(
                                            source.ip, destination
                                        )
                                    )
                                    if candidate.identity.hostname not in {
                                        str(sensor.hostname or sensor.name).casefold()
                                        for sensor in observing
                                    }:
                                        reasons.append("topology exclusion")
                                else:
                                    # An unresolved destination cannot establish a precise path.
                                    conditional = True
                                if (
                                    fact == "transport"
                                    and fmt == "ecar"
                                    and getattr(spec, "action", None) == "deny"
                                ):
                                    reasons.append(
                                        "endpoint flow cannot establish a firewall-denied attempt"
                                    )
                                if not candidate.policy.enabled:
                                    reasons.append("source disabled")
                                if not candidate.policy.capabilities.covers(
                                    alternative.capabilities
                                ):
                                    reasons.append("missing capability")
                                if (
                                    fact == "http_result"
                                    and fmt == "zeek_http"
                                    and service == "ssl"
                                ):
                                    reasons.append("encrypted application")
                                missingness = candidate.policy.missingness_for(fmt)
                                if missingness >= 1:
                                    reasons.append("modeled collection loss (100%)")
                                point = anchor if not conditional else None
                                if not any(
                                    (window.end is None or start < window.end)
                                    and (window.start is None or window.start < end)
                                    for window in candidate.policy.windows
                                ):
                                    reasons.append("collection window exclusion")
                                elif point and not any(
                                    window.contains(point) for window in candidate.policy.windows
                                ):
                                    reasons.append("collection window exclusion")
                                if point and not start <= point < end:
                                    reasons.append("outside collection window")
                                if reasons:
                                    exclusions.append(
                                        f"{candidate.identity.source_instance}/{fmt}: {', '.join(reasons)}"
                                    )
                                else:
                                    reachable = True
                                    if missingness > 0:
                                        exclusions.append(
                                            f"{candidate.identity.source_instance}/{fmt}: probabilistic collection loss {missingness:.0%}"
                                        )
                    if not reachable:
                        findings.append(
                            EvidenceReachabilityFinding(
                                behavior_id=contract.behavior_id,
                                severity="warning",
                                field_path=path,
                                message=f"Action {step.id!r} cannot record important typed fact {contract.label!r}. "
                                + "; ".join(exclusions),
                                suggestion=contract.suggestion
                                + (
                                    " Runtime routing/timing is conditional."
                                    if conditional
                                    else " Intentional collection settings still make this fact unobservable."
                                ),
                            )
                        )
                    elif exclusions or conditional:
                        findings.append(
                            EvidenceReachabilityFinding(
                                behavior_id=contract.behavior_id,
                                severity="info",
                                field_path=path,
                                message=f"Action {step.id!r}, {contract.label}: alternative evidence is available; optional gaps/risks: "
                                + (
                                    "; ".join(exclusions)
                                    or "coverage depends on runtime routing/timing"
                                )
                                + (
                                    " Coverage is conditional on runtime routing/timing."
                                    if conditional
                                    else ""
                                ),
                                suggestion="Review conditional coverage after generation; modeled loss remains an expected absence.",
                            )
                        )
    return findings
