# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
#
# SPDX-License-Identifier: MIT

"""EventDispatcher routes SecurityEvents to StateManager and emitters.

Two-layer filtering for emitter selection:
1. Format eligibility: emitter.can_handle(event)
2. Network visibility: for network events, check NetworkVisibilityEngine
"""

from __future__ import annotations

import logging
from dataclasses import replace
from datetime import datetime, timedelta
from typing import TYPE_CHECKING

from evidenceforge.events.base import RawLogEntry, SecurityEvent
from evidenceforge.events.network import NetworkSensorObservation
from evidenceforge.events.observation import (
    ObservationDecision,
    ObservationPolicy,
    ObservationStatus,
    ObservationSummary,
    source_family_for_format,
)

if TYPE_CHECKING:
    from evidenceforge.generation.emitters.base import LogEmitter
    from evidenceforge.generation.network_visibility import NetworkVisibilityEngine
    from evidenceforge.generation.state_manager import StateManager

logger = logging.getLogger(__name__)

# Format groups: a single name that expands to multiple emitter-level formats.
# Sensors and output.logs declare groups; the engine expands to individual emitters.
FORMAT_GROUPS: dict[str, set[str]] = {
    "zeek": {
        "zeek_conn",
        "zeek_dns",
        "zeek_http",
        "zeek_smtp",
        "zeek_ssl",
        "zeek_files",
        "zeek_x509",
        "zeek_dhcp",
        "zeek_ntp",
        "zeek_weird",
        "zeek_ocsp",
        "zeek_pe",
        "zeek_packet_filter",
        "zeek_reporter",
    },
    "windows": {
        "windows_event_security",
        "windows_event_sysmon",
    },
}

# Formats subject to network visibility filtering (expanded emitter names)
_NETWORK_FORMATS = FORMAT_GROUPS["zeek"] | {"snort_alert", "cisco_asa"}
_ZEEK_CONN_DEPENDENTS = FORMAT_GROUPS["zeek"] - {"zeek_conn"}
_ZEEK_FILES_DEPENDENTS = {"zeek_x509", "zeek_ocsp", "zeek_pe"}


def expand_formats(formats: list[str] | set[str]) -> set[str]:
    """Expand format group names (e.g., 'zeek') to individual emitter names."""
    expanded: set[str] = set()
    for fmt in formats:
        if fmt in FORMAT_GROUPS:
            expanded.update(FORMAT_GROUPS[fmt])
        else:
            expanded.add(fmt)
    return expanded


def _is_successful_remote_interactive_transport(event: SecurityEvent) -> bool:
    """Return whether a network event is an established SSH/RDP session transport."""

    network = event.network
    if network is None:
        return False
    if str(network.protocol or "").lower() != "tcp" or network.dst_port not in {22, 3389}:
        return False
    state = str(network.conn_state or "").upper()
    if state and state != "SF":
        return False
    if event.firewall is not None and event.firewall.action == "deny":
        return False
    service = str(network.service or "").lower()
    if service and service not in {"ssh", "rdp"}:
        return False
    return True


class EventDispatcher:
    """Routes SecurityEvents to StateManager and matching emitters."""

    def __init__(
        self,
        state_manager: StateManager,
        emitters: dict[str, LogEmitter],
        visibility_engine: NetworkVisibilityEngine | None = None,
        output_start_time: datetime | None = None,
        output_end_time: datetime | None = None,
        observation_policy: ObservationPolicy | None = None,
    ) -> None:
        self.state_manager = state_manager
        self.emitters = emitters
        self.visibility_engine = visibility_engine
        self.output_start_time = output_start_time
        self.output_end_time = output_end_time
        self.observation_policy = observation_policy or ObservationPolicy("complete")
        self._source_evidence_status: dict[str, dict[str, ObservationSummary]] = {}
        self._network_identifiers_by_format: dict[tuple[str, str], str] = {}
        self.storyline_cluster_id: str | None = None
        from evidenceforge.generation.source_timing import SourceTimingPlanner

        self.source_timing_planner = SourceTimingPlanner(
            clock_profile_name=self.observation_policy.profile_name
        )
        from evidenceforge.generation.network_observation import NetworkObservationPlanner

        self.network_observation_planner = NetworkObservationPlanner(visibility_engine)
        from evidenceforge.generation.identity_lifecycle import IdentityLifecyclePlanner

        self.identity_lifecycle_planner = IdentityLifecyclePlanner(state_manager)

    @property
    def source_evidence_status(self) -> dict[str, dict[str, dict[str, int]]]:
        """Return source evidence status summaries for ground truth generation."""
        return {
            cluster_id: {
                source: summary.as_dict()
                for source, summary in sorted(source_summaries.items())
                if summary.as_dict()
            }
            for cluster_id, source_summaries in sorted(self._source_evidence_status.items())
        }

    def network_identifier_for_format(
        self,
        canonical_uid: str,
        format_name: str,
    ) -> str | None:
        """Return a planned sensor-local UID, blank if suppressed, or None if unplanned."""

        return self._network_identifiers_by_format.get((canonical_uid, format_name))

    def record_filtered_network_observation(self) -> None:
        """Record that a storyline network event was filtered before emitter dispatch.

        Some caller paths skip unobservable network connections before building a
        full SecurityEvent. The manifest still needs a source-status entry so
        eval can distinguish expected sensor-placement loss from missing evidence.
        """
        for format_name in self.emitters:
            if format_name in _NETWORK_FORMATS:
                self._record_cluster_observation(format_name, "filtered")

    def _is_suppressed(self, timestamp: datetime) -> bool:
        """Return True if the event falls before the output window (warm-up period)."""
        if self.output_start_time is None:
            return False
        # Normalize tz-awareness to avoid naive/aware comparison errors
        ts = timestamp
        gate = self.output_start_time
        if ts.tzinfo is not None and gate.tzinfo is None:
            ts = ts.replace(tzinfo=None)
        elif ts.tzinfo is None and gate.tzinfo is not None:
            gate = gate.replace(tzinfo=None)
        return ts < gate

    def dispatch(self, event: SecurityEvent) -> None:
        """Route a structured event to StateManager + matching emitters.

        State is always updated (even during warm-up). Emission to log files
        is suppressed for events before output_start_time.
        """
        if self.storyline_cluster_id and event.storyline_cluster_id is None:
            event.storyline_cluster_id = self.storyline_cluster_id
        if event.network is not None:
            event.network.validate_finalized_transaction()
        self.identity_lifecycle_planner.plan(event)
        self.state_manager.apply(event)
        if self._is_suppressed(event.timestamp):
            self._record_observation(event, "all", "out_of_window")
            return
        matching_emitters = self._get_matching_emitters(event)
        decisions = {
            format_name: self.observation_policy.decide(format_name, event)
            for format_name, _emitter in matching_emitters
        }
        self._enforce_source_observation_contracts(event, decisions)
        observed_formats = {
            format_name
            for format_name, decision in decisions.items()
            if decision.status != "dropped"
        }
        event._observed_formats = observed_formats
        if event.network is not None:
            planned_observations = self.network_observation_planner.plan(
                event,
                observed_formats,
            )
            event.network_observations = planned_observations
            event.network_observations_planned = bool(planned_observations)
            event.network_observations = self._admit_network_sensor_observations(event)
            self._initialize_network_identifiers(event, matching_emitters)
        for format_name, emitter in matching_emitters:
            decision = decisions[format_name]
            if decision.status == "dropped":
                self._record_observation(event, format_name, "dropped")
                continue
            event_to_emit = event
            status: ObservationStatus = "visible"
            if decision.delay.total_seconds() > 0:
                event_to_emit = replace(event, timestamp=event.timestamp + decision.delay)
                status = "delayed"
            event_to_emit._observed_formats = observed_formats
            event_to_emit = self.source_timing_planner.plan_event(event_to_emit)
            if not self._admit_source_event(event_to_emit, format_name):
                self._record_observation(event, format_name, "out_of_window")
                continue
            self._record_admitted_network_identifier(event_to_emit, format_name)
            if (
                event_to_emit.event_type != "process_terminate"
                and event_to_emit.process is not None
                and event_to_emit.src_host is not None
            ):
                self.state_manager.update_process_activity_time(
                    event_to_emit.src_host.hostname,
                    event_to_emit.process.pid,
                    event_to_emit.timestamp,
                )
            self._record_observation(event, format_name, status)
            if event.raw is not None:
                emitter.emit_raw(event_to_emit.raw.fields)
            else:
                emitter.emit(event_to_emit)

    def _initialize_network_identifiers(
        self,
        event: SecurityEvent,
        matching_emitters: list[tuple[str, LogEmitter]],
    ) -> None:
        """Mark planned network formats suppressed until source admission succeeds."""

        network = event.network
        if network is None or not event.network_observations_planned:
            return
        for format_name, _emitter in matching_emitters:
            if format_name not in _NETWORK_FORMATS:
                continue
            self._network_identifiers_by_format[(network.zeek_uid, format_name)] = ""

    def _record_admitted_network_identifier(
        self,
        event: SecurityEvent,
        format_name: str,
    ) -> None:
        """Publish the observation-owned identifier after final source admission."""

        network = event.network
        if network is None or format_name not in _NETWORK_FORMATS:
            return
        identifier = next(
            (
                observation.connection_uid
                for observation in event.network_observations
                if format_name in observation.visible_formats
            ),
            None,
        )
        if identifier is not None:
            self._network_identifiers_by_format[(network.zeek_uid, format_name)] = identifier

    def _admit_network_sensor_observations(
        self,
        event: SecurityEvent,
    ) -> tuple[NetworkSensorObservation, ...]:
        """Apply half-open end admission independently to sensor observations."""

        if self.output_end_time is None or event.lifecycle is None:
            return event.network_observations
        if event.lifecycle.phase == "closure":
            return event.network_observations
        return tuple(
            observation
            for observation in event.network_observations
            if self._is_before(observation.observed_start_time, self.output_end_time)
        )

    def _admit_source_event(self, event: SecurityEvent, format_name: str) -> bool:
        """Return whether final source-visible timing admits this rendered event."""

        if (
            event.network_observations_planned
            and format_name in _NETWORK_FORMATS
            and not any(
                format_name in observation.visible_formats
                for observation in event.network_observations
            )
        ):
            return False
        visible_time = self.source_timing_planner.admission_time(event, format_name)
        lifecycle = event.lifecycle
        if lifecycle is None:
            return self.output_end_time is None or self._is_before(
                visible_time,
                self.output_end_time,
            )

        source_start = visible_time + self._timestamp_delta(
            lifecycle.canonical_start,
            event.timestamp,
        )
        if self.output_end_time is not None and not self._is_before(
            source_start,
            self.output_end_time,
        ):
            return False
        if lifecycle.phase == "closure":
            return True
        if self.output_start_time is not None and self._is_before(
            visible_time,
            self.output_start_time,
        ):
            return False
        return self.output_end_time is None or self._is_before(
            visible_time,
            self.output_end_time,
        )

    @staticmethod
    def _is_before(timestamp: datetime, gate: datetime) -> bool:
        """Compare timestamps after normalizing timezone awareness."""

        ts = timestamp
        normalized_gate = gate
        if ts.tzinfo is not None and normalized_gate.tzinfo is None:
            ts = ts.replace(tzinfo=None)
        elif ts.tzinfo is None and normalized_gate.tzinfo is not None:
            normalized_gate = normalized_gate.replace(tzinfo=None)
        return ts < normalized_gate

    @staticmethod
    def _timestamp_delta(later: datetime, earlier: datetime) -> timedelta:
        """Return a delta after aligning naive/aware canonical timestamps."""

        normalized_later = later
        normalized_earlier = earlier
        if normalized_later.tzinfo is not None and normalized_earlier.tzinfo is None:
            normalized_earlier = normalized_earlier.replace(tzinfo=normalized_later.tzinfo)
        elif normalized_later.tzinfo is None and normalized_earlier.tzinfo is not None:
            normalized_later = normalized_later.replace(tzinfo=normalized_earlier.tzinfo)
        return normalized_later - normalized_earlier

    def _enforce_source_observation_contracts(
        self,
        event: SecurityEvent,
        decisions: dict[str, ObservationDecision],
    ) -> None:
        """Preserve source-local parent rows when child observations survive."""
        self._promote_zeek_parent(decisions, "zeek_conn", _ZEEK_CONN_DEPENDENTS)
        self._promote_zeek_parent(decisions, "zeek_files", _ZEEK_FILES_DEPENDENTS)
        self._promote_zeek_parent(decisions, "zeek_conn", {"zeek_files"})
        self._preserve_zeek_tls_certificate_companions(event, decisions)
        self._preserve_remote_interactive_transport_companions(event, decisions)

    @staticmethod
    def _preserve_remote_interactive_transport_companions(
        event: SecurityEvent,
        decisions: dict[str, ObservationDecision],
    ) -> None:
        """Keep successful SSH/RDP network rows when endpoint transport telemetry survives."""

        if not _is_successful_remote_interactive_transport(event):
            return
        endpoint_decision = decisions.get("ecar")
        if endpoint_decision is None or endpoint_decision.status == "dropped":
            return
        for format_name in ("zeek_conn", "cisco_asa"):
            decision = decisions.get(format_name)
            if decision is not None and decision.status == "dropped":
                decisions[format_name] = ObservationDecision(status="visible")

    @staticmethod
    def _preserve_zeek_tls_certificate_companions(
        event: SecurityEvent,
        decisions: dict[str, ObservationDecision],
    ) -> None:
        """Keep TLS certificate files/x509/ssl rows source-local coherent."""
        if event.ssl is None or (event.x509 is None and not event.x509_chain):
            return
        certificate_formats = ("zeek_files", "zeek_x509")
        anchor = next(
            (
                decisions[format_name]
                for format_name in certificate_formats
                if format_name in decisions and decisions[format_name].status != "dropped"
            ),
            None,
        )
        if anchor is None:
            return
        for format_name in ("zeek_ssl", *certificate_formats):
            decision = decisions.get(format_name)
            if decision is not None and decision.status == "dropped":
                decisions[format_name] = ObservationDecision(
                    status=anchor.status,
                    delay=anchor.delay,
                )

    @staticmethod
    def _promote_zeek_parent(
        decisions: dict[str, ObservationDecision],
        parent_format: str,
        child_formats: set[str],
    ) -> None:
        parent_decision = decisions.get(parent_format)
        if parent_decision is None or parent_decision.status != "dropped":
            return
        for child_format in child_formats:
            child_decision = decisions.get(child_format)
            if child_decision is None or child_decision.status == "dropped":
                continue
            decisions[parent_format] = ObservationDecision(
                status=child_decision.status,
                delay=child_decision.delay,
            )
            return

    def dispatch_raw(self, entry: RawLogEntry) -> None:
        """Route a raw log entry directly to a specific emitter (escape hatch).

        target_emitter must match a key in self.emitters dict.
        """
        if self._is_suppressed(entry.timestamp):
            return
        if self.output_end_time is not None and not self._is_before(
            entry.timestamp,
            self.output_end_time,
        ):
            return
        emitter = self.emitters.get(entry.target_emitter)
        if emitter is None:
            raise KeyError(f"Unknown emitter: {entry.target_emitter!r}")
        decision = self.observation_policy.decide_raw(entry)
        if decision.status == "dropped":
            return
        emitter.emit_raw(entry.data)

    def _get_matching_emitters(self, event: SecurityEvent) -> list[tuple[str, LogEmitter]]:
        """Two-layer filtering: format eligibility + network visibility."""
        # Raw event routing: target a single specific emitter
        if event.raw is not None:
            emitter = self.emitters.get(event.raw.target_format)
            if emitter is None:
                logger.warning(f"Raw event targets unknown emitter: {event.raw.target_format!r}")
                return []
            if event.local_only and event.raw.target_format in _NETWORK_FORMATS:
                self._record_observation(event, event.raw.target_format, "filtered")
                return []
            return [(event.raw.target_format, emitter)]

        # For network events, determine which formats can see this traffic
        # and annotate the event with observing sensor hostnames
        visible_formats: set[str] | None = None
        if event.network and self.visibility_engine:
            is_link_local = event.network.link_local
            if is_link_local:
                visible_formats = self.visibility_engine.get_log_formats_for_link_local(
                    event.network.src_ip
                )
                sensors = self.visibility_engine.get_link_local_sensors(event.network.src_ip)
            else:
                # Denied connections only visible from the source side (packets
                # never reach the destination — firewall blocks them)
                is_fw_deny = event.firewall is not None and event.firewall.action == "deny"
            if not is_link_local and is_fw_deny:
                visible_formats = self.visibility_engine.get_log_formats_for_source_only(
                    event.network.src_ip, event.network.dst_ip
                )
                sensors = self.visibility_engine.get_source_side_sensors(
                    event.network.src_ip, event.network.dst_ip
                )
            elif not is_link_local:
                visible_formats = self.visibility_engine.get_log_formats_for_connection(
                    event.network.src_ip, event.network.dst_ip
                )
                sensors = self.visibility_engine.get_observing_sensors(
                    event.network.src_ip, event.network.dst_ip
                )
            format_to_sensors: dict[str, list[str]] = {}
            for sensor in sensors:
                hostname = sensor.hostname or sensor.name
                # Expand group names to individual emitter names
                for fmt in expand_formats(sensor.log_formats):
                    format_to_sensors.setdefault(fmt, []).append(hostname)
            event._sensor_hostnames_by_format = format_to_sensors

            # NAT computation: translate addresses for permitted connections
            if not is_link_local and not is_fw_deny and event.nat is None:
                nat_ctx = self.visibility_engine.compute_nat(
                    event.network.src_ip,
                    event.network.dst_ip,
                    event.network.src_port,
                    event.network.dst_port,
                )
                if nat_ctx:
                    event.nat = nat_ctx
                    src_segments = self.visibility_engine._resolve_ip_segments(event.network.src_ip)
                    # Detect NAT direction: inbound static NAT translates
                    # dst from VIP to real_ip; outbound PAT translates src.
                    is_inbound_nat = (
                        nat_ctx.nat_type == "static"
                        and nat_ctx.mapped_dst_ip
                        and nat_ctx.mapped_dst_ip != event.network.dst_ip
                    )
                    nat_swaps: dict[str, dict[str, str | int]] = {}
                    for sensor in sensors:
                        if sensor.type == "firewall":
                            continue  # ASA handles NAT via NatContext directly
                        sensor_segs = set(sensor.monitoring_segments)
                        hostname = sensor.hostname or sensor.name
                        swaps: dict[str, str | int] = {}

                        if is_inbound_nat:
                            # Inbound NAT: inside sensors (monitoring the
                            # real_ip's segment) see the translated real_ip;
                            # outside sensors keep the VIP (no swap).
                            real_ip_segs = self.visibility_engine._resolve_ip_segments(
                                nat_ctx.mapped_dst_ip
                            )
                            if sensor_segs & real_ip_segs:
                                swaps["dst_ip"] = nat_ctx.mapped_dst_ip
                                swaps["dst_port"] = nat_ctx.mapped_dst_port
                                swaps["local_resp"] = True
                        else:
                            # Outbound NAT: outside sensors (NOT on source
                            # segment) see post-NAT translated IPs.
                            if not (sensor_segs & src_segments):
                                if nat_ctx.mapped_src_ip != event.network.src_ip:
                                    swaps["src_ip"] = nat_ctx.mapped_src_ip
                                    swaps["src_port"] = nat_ctx.mapped_src_port
                                if nat_ctx.mapped_dst_ip != event.network.dst_ip:
                                    swaps["dst_ip"] = nat_ctx.mapped_dst_ip
                                    swaps["dst_port"] = nat_ctx.mapped_dst_port

                        if swaps:
                            nat_swaps[hostname] = swaps
                    if nat_swaps:
                        event._nat_swaps_by_sensor = nat_swaps

        matched = []
        for format_name, emitter in self.emitters.items():
            if not emitter.can_handle(event):
                continue
            # Host-local events (same src/dst IP) are invisible to network sensors
            if event.local_only and format_name in _NETWORK_FORMATS:
                self._record_observation(event, format_name, "filtered")
                continue
            # Network visibility filter: only applies to network-format emitters
            if visible_formats is not None and format_name in _NETWORK_FORMATS:
                if format_name not in visible_formats:
                    self._record_observation(event, format_name, "filtered")
                    continue
            matched.append((format_name, emitter))
        return matched

    def _record_observation(
        self,
        event: SecurityEvent,
        format_name: str,
        status: ObservationStatus,
    ) -> None:
        """Record source evidence status for storyline/red-herring ground truth."""
        cluster_id = event.storyline_cluster_id
        if not cluster_id:
            return
        self._record_cluster_observation(format_name, status, cluster_id=cluster_id)

    def _record_cluster_observation(
        self,
        format_name: str,
        status: ObservationStatus,
        *,
        cluster_id: str | None = None,
    ) -> None:
        """Record source evidence status for the active or supplied cluster."""
        cluster_id = cluster_id or self.storyline_cluster_id
        if not cluster_id:
            return
        source = source_family_for_format(format_name)
        cluster = self._source_evidence_status.setdefault(cluster_id, {})
        source_counts = cluster.setdefault(source, ObservationSummary())
        source_counts.record(status)
