"""Capture immutable source expectations before filtering can erase source identity."""

from __future__ import annotations

import hashlib
import json
import random
from typing import TYPE_CHECKING

from evidenceforge.events.evidence_projection import (
    candidate_formats,
    host_routes,
    native_requirements,
    projection_phase,
    required_capabilities,
)
from evidenceforge.events.ground_truth_occurrence import (
    GroundTruthCondition,
    GroundTruthCoverageGap,
    GroundTruthExpectationContract,
    GroundTruthSensorView,
    GroundTruthSourceExpectation,
)
from evidenceforge.events.source_catalog import DEFAULT_SOURCE_CATALOG, SourceOwnerKind
from evidenceforge.generation.source_deployment_compiler import compile_scenario_source_deployment
from evidenceforge.utils.rng import _stable_seed, current_generation_seed, stable_uuid
from evidenceforge.utils.time import resolve_time_window

if TYPE_CHECKING:
    from evidenceforge.events.base import CanonicalOccurrence
    from evidenceforge.events.dispatcher import EventDispatcher, _PreparedProjection
    from evidenceforge.events.observation import ObservationPolicy
    from evidenceforge.generation.collection_deployment import CompiledCollectionDeployment
    from evidenceforge.models import Scenario


def scenario_contract_digest(scenario: Scenario) -> str:
    """Bind semantic input while excluding the destination's machine-local pathname."""
    data = scenario.model_dump(mode="json")
    data["output"].pop("destination", None)
    return hashlib.sha256(
        json.dumps(data, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


class GroundTruthExpectationPlanner:
    """Retain source candidates and the committed owner's actual collection decisions."""

    def __init__(
        self,
        scenario: Scenario,
        deployment: CompiledCollectionDeployment,
        policy: ObservationPolicy,
    ) -> None:
        from evidenceforge.config.sysmon_filters import load_sysmon_filters
        from evidenceforge.generation.activity.timing_profiles import load_timing_profiles

        self.source_rules = load_sysmon_filters()
        self.capture_rules = load_timing_profiles().get("network_sensor_observation", {})
        self.scenario = scenario
        self.deployment = deployment
        self.policy = policy
        self.formats = set(
            DEFAULT_SOURCE_CATALOG.expand(item["format"] for item in scenario.output.logs)
        )
        inventory_formats = set(self.formats)
        sensors = scenario.environment.network.sensors if scenario.environment.network else []
        # Include explicitly configured sensors even if their formats are not exported.
        inventory_formats = {
            fmt
            for fmt in inventory_formats
            if DEFAULT_SOURCE_CATALOG.descriptor(fmt).owner is SourceOwnerKind.HOST
        }
        for sensor in sensors:
            inventory_formats.update(DEFAULT_SOURCE_CATALOG.expand(sensor.log_formats))
        inventory = compile_scenario_source_deployment(
            scenario, emitter_formats=inventory_formats
        ).deployment
        self.sources = {source.identity.source_instance: source for source in inventory}
        self.by_format: dict[str, list] = {}
        for source in inventory:
            for fmt in source.formats:
                self.by_format.setdefault(fmt, []).append(source)
        self.sensors = {
            str(sensor.hostname or sensor.name).casefold(): sensor for sensor in sensors
        }
        self.start, self.end = resolve_time_window(scenario.time_window)
        self.contract = GroundTruthExpectationContract(
            scenario_sha256=scenario_contract_digest(scenario),
            profile=policy.profile_name,
            profile_settings=policy.profile,
            sources={
                identity: {
                    "hostname": source.identity.hostname,
                    "family": source.identity.family,
                    "formats": list(source.formats),
                    "enabled": source.policy.enabled,
                    "capabilities": int(source.policy.capabilities),
                    "missingness": source.policy.missingness,
                    "format_missingness": dict(source.policy.format_missingness),
                    "optional_fields": sorted(source.policy.optional_fields),
                    "windows": [
                        {
                            "start": w.start.isoformat() if w.start else None,
                            "end": w.end.isoformat() if w.end else None,
                        }
                        for w in source.policy.windows
                    ],
                }
                for identity, source in self.sources.items()
            },
            source_rules=json.loads(
                json.dumps(
                    {
                        "windows_event_sysmon": self.source_rules,
                        "network_sensor_observation": self.capture_rules,
                        "process_timing": {
                            key: dict(load_timing_profiles().get("relationships", {}).get(key, {}))
                            for key in (
                                "source.ecar_process_create",
                                "source.ecar_process_terminate",
                                "source.ecar_dependent_after_process_create",
                            )
                        },
                    }
                )
            ),
        )

    def capture(
        self,
        event: CanonicalOccurrence,
        projection: _PreparedProjection,
        facts: dict,
        dispatcher: EventDispatcher,
    ) -> tuple[
        list[GroundTruthSourceExpectation],
        list[GroundTruthCoverageGap],
        dict[str, GroundTruthSensorView],
    ]:
        """Capture expectations for every relevant source, including excluded candidates."""
        actual = {}
        views: dict[str, GroundTruthSensorView] = {}
        for source_id, source in self.sources.items():
            for view in event.network_observations:
                if source.identity.hostname.casefold() == view.sensor_identity.casefold():
                    views[source_id] = GroundTruthSensorView(
                        sensor_identity=view.sensor_identity,
                        profile=view.capture_profile,
                        path_role=view.path_role,
                        traffic={
                            **{
                                direction: {
                                    key: getattr(getattr(view.traffic, direction), key)
                                    for key in ("payload_bytes", "packets", "ip_bytes")
                                }
                                for direction in ("orig", "resp")
                            },
                            "missed_orig_bytes": view.traffic.missed_orig_bytes,
                            "missed_resp_bytes": view.traffic.missed_resp_bytes,
                        },
                        files=[
                            {
                                "canonical_id": item.canonical_id,
                                "seen_bytes": item.seen_bytes,
                                "total_bytes": item.total_bytes,
                                "missing_bytes": item.missing_bytes,
                                "analyzers_visible": item.analyzers_visible,
                            }
                            for item in view.file_observations
                        ],
                        source_times=dict(view.source_times),
                        visible_formats=sorted(view.visible_formats),
                        start_time=view.observed_start_time,
                        close_time=view.observed_close_time,
                        firewall_teardown_time=view.firewall_teardown_time,
                        firewall_teardown_observed=view.firewall_teardown_observed,
                    )
        for target in projection.compiled_targets:
            envelope = target.envelope
            actual[(envelope.source.source_instance, target.format_name, target.role.value)] = (
                target
            )
        formats = candidate_formats(str(event.event_type), facts) | {
            target.format_name for target in projection.compiled_targets
        }
        expectations: list[GroundTruthSourceExpectation] = []
        gaps: list[GroundTruthCoverageGap] = []
        visibility = dispatcher.visibility_engine
        network = event.network
        ordinary = set()
        observed_path = set()
        if network is not None and visibility is not None:
            ordinary = {
                str(s.hostname or s.name).casefold()
                for s in visibility.get_observing_sensors(network.src_ip, network.dst_ip)
            }
            eligible = (
                visibility.get_link_local_sensors(network.src_ip)
                if network.link_local
                else (
                    visibility.get_source_side_sensors(network.src_ip, network.dst_ip)
                    if event.firewall is not None and event.firewall.action == "deny"
                    else visibility.get_observing_sensors(network.src_ip, network.dst_ip)
                )
            )
            observed_path = {str(s.hostname or s.name).casefold() for s in eligible}
        for fmt in sorted(formats):
            descriptor = DEFAULT_SOURCE_CATALOG.descriptor(fmt)
            routes: dict[str, list[str]] = {}
            for host, role in host_routes(fmt, str(event.event_type), facts):
                routes.setdefault(host.casefold(), []).append(role)
            candidates = [
                source
                for source in self.by_format.get(fmt, [])
                if descriptor.owner is SourceOwnerKind.SENSOR
                or source.identity.hostname.casefold() in routes
            ]
            if not candidates:
                gaps.append(
                    GroundTruthCoverageGap(
                        family=descriptor.family,
                        format=fmt,
                        location=next(
                            iter(routes),
                            str(
                                (facts.get("src_host") or facts.get("dst_host") or {}).get(
                                    "hostname"
                                )
                                or "network"
                            ),
                        ),
                        reason="source_not_deployed"
                        if descriptor.owner is SourceOwnerKind.SENSOR
                        and self.scenario.environment.network is not None
                        else "deployment_unknown",
                        restrictions=["output_filtering"] if fmt not in self.formats else [],
                    )
                )
                continue
            for source in candidates:
                source_id = source.identity.source_instance
                host = source.identity.hostname
                for role in routes.get(host.casefold(), ["sensor"]):
                    target = actual.get((source_id, fmt, role))
                    timing_plan = (
                        target.source_timing if target is not None else event.source_timing
                    )
                    conditions = []

                    def condition(
                        stage: str, allowed: bool, reason: str, entries: list = conditions
                    ) -> None:
                        entries.append(
                            GroundTruthCondition(
                                stage=stage,
                                state="eligible" if allowed else "excluded",
                                reason=None if allowed else reason,
                            )
                        )

                    condition("deployment", source.policy.enabled, "source_disabled")
                    path_visible = (
                        descriptor.owner is SourceOwnerKind.HOST or host.casefold() in observed_path
                    )
                    path_reason = (
                        "prevented_upstream"
                        if host.casefold() in ordinary
                        and not path_visible
                        and event.firewall is not None
                        else "topology_exclusion"
                    )
                    if event.local_only and descriptor.owner is SourceOwnerKind.SENSOR:
                        path_visible = False
                        path_reason = "host_local_activity"
                    condition("placement", path_visible, path_reason)
                    capable = source.policy.capabilities.covers(
                        required_capabilities(fmt, str(event.event_type), facts, role)
                    )
                    capability_reason = "missing_capability"
                    if fmt == "zeek_http" and network is not None and network.service == "ssl":
                        capable = False
                        capability_reason = "encrypted_application"
                    if fmt in {"ecar", "cisco_asa"} and (
                        (
                            fmt == "ecar"
                            and event.firewall is not None
                            and event.firewall.action == "deny"
                        )
                        or (network is not None and network.application_layer_only)
                    ):
                        capable = False
                    if target is not None:
                        capable = capable and source.policy.capabilities.covers(
                            target.required_capabilities
                        )
                    elif fmt in dispatcher.emitters and not (
                        fmt in {"zeek_smb_files", "zeek_smb_mapping"}
                        or fmt == "windows_event_security"
                        and str(event.event_type).startswith("smb_")
                    ):
                        capable = capable and dispatcher.emitters[fmt].can_handle(event)
                    from evidenceforge.events.evidence_source_rules import (
                        native_projection_applicable,
                    )

                    condition("capability", capable, capability_reason)
                    if fmt in {"zeek_pe", "zeek_x509"} and source_id in views:
                        ids = {
                            item.get("id") or item.get("fuid")
                            for item in facts.get(
                                "pe_analyses" if fmt == "zeek_pe" else "x509_chain", []
                            )
                        }
                        visible = any(
                            item["analyzers_visible"]
                            for item in views[source_id].files
                            if item["canonical_id"] in ids
                        )
                        if not visible:
                            conditions[-1] = GroundTruthCondition(
                                stage="capability",
                                state="excluded",
                                reason="incomplete_payload_visibility",
                            )
                    source_time = (
                        target.envelope.observed_time if target is not None else None
                    ) or event.timestamp
                    admission_time = source_time
                    source_delay = (
                        target.decision.delay.total_seconds()
                        if target is not None and target.decision is not None
                        else 0.0
                    )
                    if fmt != "zeek_conn" and source_id in views:
                        from datetime import timedelta

                        admission_time = max(
                            [
                                source_time,
                                *[
                                    value + timedelta(seconds=source_delay)
                                    for key, value in views[source_id].source_times.items()
                                    if key == fmt or key.startswith(fmt + ":")
                                ],
                            ]
                        )
                    if fmt == "zeek_conn":
                        window_views = (
                            (target.network_observations or event.network_observations)
                            if target is not None
                            else event.network_observations
                        )
                        close_times = [
                            view.observed_close_time
                            for view in window_views
                            if view.sensor_identity.casefold() == host.casefold()
                            and view.observed_close_time is not None
                        ]
                        admission_time = max(
                            close_times,
                            default=network.closed_at
                            if network is not None and network.closed_at is not None
                            else source_time,
                        )
                    lifecycle_start = source_time
                    if event.lifecycle is not None:
                        lifecycle_start += event.lifecycle.canonical_start - event.timestamp
                    active = [
                        window
                        for window in source.policy.windows
                        if window.contains(event.timestamp)
                    ]
                    in_window = (
                        bool(active)
                        and self.start <= source_time
                        and admission_time < self.end
                        and lifecycle_start < self.end
                    )
                    if active and active[0].end is not None:
                        in_window = (
                            in_window
                            and admission_time < active[0].end
                            and lifecycle_start < active[0].end
                        )
                    window_receipt = {
                        "source_time": source_time.isoformat(),
                        "admission_time": admission_time.isoformat(),
                        "lifecycle_start": lifecycle_start.isoformat(),
                        "source_delay_seconds": source_delay,
                    }
                    condition("window", in_window, "collection_window_exclusion")
                    if fmt == "windows_event_sysmon":
                        from evidenceforge.events.evidence_source_rules import sysmon_event_ids

                        condition(
                            "source_filter",
                            bool(
                                sysmon_event_ids(
                                    str(event.event_type),
                                    facts,
                                    self.source_rules,
                                    current_generation_seed(),
                                )
                            ),
                            "source_rule_filtering",
                        )
                    if (
                        fmt in {"zeek_smb_files", "zeek_smb_mapping"}
                        or fmt == "windows_event_security"
                        and str(event.event_type).startswith("smb_")
                    ):
                        condition(
                            "source_filter",
                            native_projection_applicable(
                                fmt, str(event.event_type), facts, current_generation_seed()
                            ),
                            "source_rule_filtering",
                        )
                    loss = {}
                    if target is not None and target.decision is not None:
                        base = source.policy.missingness_for(fmt)
                        settings = self.policy._settings_for_source(descriptor.family)
                        probability = self.policy._projection_missingness(
                            descriptor.family, event, host, base, settings
                        )
                        identity = self.policy._event_identity(
                            descriptor.family,
                            fmt,
                            event,
                            force_format_specific=fmt in source.policy.format_missingness,
                        )
                        sample_key = (
                            f"observation.drop|{self.policy.profile_name}|{source_id}|{identity}"
                        )
                        sample = random.Random(_stable_seed(sample_key)).random()
                        loss = {
                            "identity": identity,
                            "probability": probability,
                            "base_probability": base,
                            "sample": sample,
                            "seed": current_generation_seed(),
                            "dropped": target.decision.status == "dropped",
                        }
                        condition(
                            "loss", target.decision.status != "dropped", "modeled_collection_loss"
                        )
                    else:
                        conditions.append(
                            GroundTruthCondition(
                                stage="loss",
                                state="unknown",
                                reason="not_sampled_for_excluded_projection",
                            )
                        )
                    condition("export", fmt in self.formats, "output_filtering")
                    exclusion = next(
                        (item.reason for item in conditions if item.state == "excluded"), None
                    )
                    identifiers = {}
                    if network is not None:
                        identifiers = {
                            "zeek_uid": network.zeek_uid,
                            "src_ip": network.src_ip,
                            "dst_ip": network.dst_ip,
                        }
                        if descriptor.owner is SourceOwnerKind.SENSOR:
                            from evidenceforge.generation.network_observation import (
                                derive_sensor_identifier,
                            )

                            sensor = self.sensors.get(host.casefold())
                            identity = (
                                str(sensor.hostname or sensor.name) if sensor is not None else host
                            )
                            identifiers["zeek_uid"] = derive_sensor_identifier(
                                network.zeek_uid, identity
                            )
                            for item in [
                                *facts.get("file_transfers", []),
                                *facts.get("x509_chain", []),
                                *facts.get("pe_analyses", []),
                            ]:
                                canonical = item.get("fuid") or item.get("id")
                                if canonical:
                                    identifiers["file:" + canonical] = derive_sensor_identifier(
                                        canonical, identity
                                    )
                        for view in (
                            (target.network_observations or event.network_observations)
                            if target is not None
                            else event.network_observations
                        ):
                            if view.sensor_identity.casefold() == host.casefold():
                                identifiers.update(
                                    zeek_uid=view.connection_uid,
                                    src_ip=view.tuple_view.src_ip,
                                    dst_ip=view.tuple_view.dst_ip,
                                )
                                identifiers.update(
                                    {
                                        "file:" + canonical: observed
                                        for canonical, observed in view.file_ids
                                    }
                                )
                                break
                    if fmt == "windows_event_sysmon" and facts.get("dns"):
                        timing = (
                            target.source_timing if target is not None else None
                        ) or event.source_timing
                        query_host = (facts.get("src_host") or {}).get("hostname", host)
                        if timing is not None:
                            native_key = f"sysmon.event.dns.render.{query_host}"
                            if native_key in timing.finalized_times:
                                identifiers["sysmon_dns_render_time"] = timing.finalized_times[
                                    native_key
                                ].isoformat()
                    expected_time = (
                        target.envelope.observed_time if target is not None else event.timestamp
                    )
                    try:
                        requirements = [
                            item.model_dump(mode="json")
                            for item in native_requirements(
                                fmt,
                                str(event.event_type),
                                facts,
                                identifiers,
                                role,
                                self.source_rules,
                                current_generation_seed(),
                                source_view=views[source_id].model_dump(mode="json")
                                if source_id in views
                                else None,
                            )
                        ]
                    except (ValueError, KeyError) as exc:
                        requirements = [{"unsupported": str(exc)}]
                    expectations.append(
                        GroundTruthSourceExpectation(
                            expectation_id=stable_uuid(
                                "source-expectation", event.occurrence_id, source_id, fmt, role
                            ),
                            source_instance=source_id,
                            source_host=host,
                            family=descriptor.family,
                            format=fmt,
                            role=role,
                            phase=str(event.event_type),
                            connection_leg=projection_phase(fmt, str(event.event_type), facts)[0],
                            transaction_phase=projection_phase(fmt, str(event.event_type), facts)[
                                1
                            ],
                            expected="absent" if exclusion else "present",
                            reason=exclusion,
                            conditions=conditions,
                            identifiers=identifiers,
                            requirements=requirements,
                            expected_time=expected_time,
                            provenance={
                                "contract_version": 1,
                                "loss": loss,
                                "window": window_receipt,
                                "timing": timing_plan.validation_receipts.get(source_id, {})
                                if timing_plan is not None
                                else {},
                            },
                        )
                    )
        return expectations, gaps, views
