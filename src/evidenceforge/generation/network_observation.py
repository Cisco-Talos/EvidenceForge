# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Plan frozen per-sensor observations from canonical network transactions."""

from __future__ import annotations

import hashlib
import random
import string
from collections.abc import Collection, Mapping
from datetime import datetime, timedelta
from typing import TYPE_CHECKING

from evidenceforge.events.network import (
    DirectionalTrafficLedger,
    FileSensorObservation,
    NatSensorObservation,
    NetworkSensorObservation,
    NetworkTrafficLedger,
    NetworkTuple,
)
from evidenceforge.generation.activity.timing_profiles import (
    FirewallObservationTiming,
    NetworkSensorObservationTiming,
    firewall_observation_timing,
    get_timing_window,
    network_sensor_observation_timing,
)
from evidenceforge.generation.activity.tls_realism import certificate_file_size
from evidenceforge.generation.timing import (
    ClockWanderSpec,
    ConstantDistribution,
    SourceClockKey,
    SourceClockSpec,
    TimingDistributionError,
    TimingRuntime,
    TimingScope,
    TriangularDistribution,
    TruncatedLognormalDistribution,
)
from evidenceforge.utils.ids import _has_synthetic_marker
from evidenceforge.utils.rng import _stable_seed
from evidenceforge.utils.time import ensure_utc

if TYPE_CHECKING:
    from evidenceforge.events.base import CanonicalOccurrence
    from evidenceforge.generation.network_visibility import NetworkVisibilityEngine
    from evidenceforge.models.scenario import NetworkSensor


def derive_sensor_identifier(canonical_id: str, sensor_identity: str) -> str:
    """Return a stable source-local Zeek-style identifier."""

    if not canonical_id:
        return canonical_id
    base62 = string.ascii_uppercase + string.ascii_lowercase + string.digits
    prefix = canonical_id[0]
    target_len = max(0, len(canonical_id) - 1)
    candidate = canonical_id
    for counter in range(16):
        suffix = "" if counter == 0 else f":{counter}"
        digest = hashlib.sha256(f"{canonical_id}:{sensor_identity}{suffix}".encode()).digest()
        candidate = prefix + "".join(base62[byte % 62] for byte in digest[:target_len])
        if not _has_synthetic_marker(candidate):
            return candidate
    return candidate


def network_source_timing_key(format_name: str, object_id: str = "") -> str:
    """Return the immutable key for one sensor-native network row."""

    return format_name if not object_id else f"{format_name}:{object_id}"


class NetworkObservationPlanner:
    """Project canonical network truth through configured sensor behavior."""

    def __init__(
        self,
        visibility_engine: NetworkVisibilityEngine | None,
        output_end_time: datetime | None = None,
        timing_runtime: TimingRuntime | None = None,
    ) -> None:
        self.visibility_engine = visibility_engine
        self.output_end_time = output_end_time
        self._runtime_injected = timing_runtime is not None
        self.timing_runtime = timing_runtime or TimingRuntime.compatibility_default()

    def plan(
        self,
        event: CanonicalOccurrence,
        visible_formats: set[str],
        *,
        sensor_formats: Mapping[str, Collection[str]] | None = None,
    ) -> tuple[NetworkSensorObservation, ...]:
        """Return deterministic observations for every visible network sensor."""

        network = event.network
        if network is None:
            return ()
        transaction = network
        planned_sensor_formats = (
            {
                sensor_identity: set(formats) & visible_formats
                for sensor_identity, formats in sensor_formats.items()
                if set(formats) & visible_formats
            }
            if sensor_formats is not None
            else self._sensor_formats(event, visible_formats)
        )
        canonical_file_ids = self._canonical_file_ids(event)
        canonical_connection_ids = self._canonical_connection_ids(event)
        runtime = self._runtime_for_event(transaction.started_at)
        observations: list[NetworkSensorObservation] = []
        for sensor_identity, formats in sorted(planned_sensor_formats.items()):
            sensor = (
                self.visibility_engine.get_sensor(sensor_identity)
                if self.visibility_engine is not None
                else None
            )
            requested_profile = sensor.capture_profile if sensor is not None else ""
            timing = network_sensor_observation_timing(requested_profile or None)
            path_role = (
                self.visibility_engine.infer_sensor_path_role(
                    sensor_identity,
                    transaction.src_ip,
                    transaction.dst_ip,
                    link_local=network.link_local,
                )
                if self.visibility_engine is not None
                else "unspecified"
            )
            tuple_view, local_orig, local_resp = self._sensor_view(event, sensor)
            observed_start, observed_close = self._observed_interval(
                transaction.started_at,
                transaction.closed_at,
                timing,
                sensor_identity,
                path_role,
                transaction.conn_id or transaction.zeek_uid or transaction.stable_id,
                runtime,
            )
            observation_scope = TimingScope(
                stable_id=transaction.stable_id or transaction.zeek_uid,
                source=sensor_identity.casefold(),
                lifecycle_id=path_role,
            )
            firewall_reason, firewall_teardown = self._firewall_teardown_plan(
                event,
                formats,
                sensor_identity,
                observed_start,
                observed_close,
                scope=observation_scope,
                runtime=runtime,
            )
            firewall_teardown_observed = self._before_output_end(firewall_teardown)
            observed_traffic = self._observed_traffic(
                transaction.traffic,
                timing,
                sensor_identity,
                transaction.stable_id,
                transaction.protocol,
            )
            history, file_observations, request_body_len, response_body_len = (
                self._observed_protocol(event, observed_traffic)
            )
            source_times, source_durations = self._source_native_protocol_timing(
                event,
                canonical_start=ensure_utc(transaction.started_at),
                observed_start=observed_start,
                observed_close=observed_close,
                sensor_identity=sensor_identity,
                path_role=path_role,
                visible_formats=formats,
                timing=timing,
                runtime=runtime,
            )
            admitted_formats = self._admitted_source_formats(
                formats,
                source_times=source_times,
                observed_start=observed_start,
            )
            observations.append(
                NetworkSensorObservation(
                    sensor_identity=sensor_identity,
                    path_role=path_role,
                    capture_profile=timing.profile_name,
                    tuple_view=tuple_view,
                    connection_uid=derive_sensor_identifier(
                        transaction.zeek_uid,
                        sensor_identity,
                    ),
                    connection_ids=tuple(
                        (connection_id, derive_sensor_identifier(connection_id, sensor_identity))
                        for connection_id in canonical_connection_ids
                    ),
                    file_ids=tuple(
                        (file_id, derive_sensor_identifier(file_id, sensor_identity))
                        for file_id in canonical_file_ids
                    ),
                    local_orig=local_orig,
                    local_resp=local_resp,
                    observed_start_time=observed_start,
                    observed_close_time=observed_close,
                    traffic=observed_traffic,
                    visible_formats=frozenset(admitted_formats),
                    history=history,
                    file_observations=file_observations,
                    http_request_body_len=request_body_len,
                    http_response_body_len=response_body_len,
                    firewall_teardown_reason=firewall_reason,
                    firewall_teardown_time=firewall_teardown,
                    firewall_teardown_observed=firewall_teardown_observed,
                    nat=self._nat_observation(
                        event,
                        observed_start,
                        observed_close,
                        firewall_teardown,
                    ),
                    source_times=source_times,
                    source_durations=source_durations,
                )
            )
        return tuple(observations)

    def _admitted_source_formats(
        self,
        formats: set[str],
        *,
        source_times: tuple[tuple[str, datetime], ...],
        observed_start: datetime,
    ) -> set[str]:
        """Apply the half-open output window to every frozen row in a format."""

        if self.output_end_time is None:
            return set(formats)
        admitted: set[str] = set()
        for format_name in formats:
            prefix = f"{format_name}:"
            row_times = [
                timestamp
                for key, timestamp in source_times
                if key == format_name or key.startswith(prefix)
            ]
            final_time = max(row_times) if row_times else observed_start
            if self._before_output_end(final_time):
                admitted.add(format_name)
        return admitted

    def _before_output_end(self, timestamp: datetime | None) -> bool:
        """Return whether a source-local fan-out row is inside the export window."""

        if timestamp is None or self.output_end_time is None:
            return True
        candidate = timestamp
        gate = self.output_end_time
        if candidate.tzinfo is not None and gate.tzinfo is None:
            candidate = candidate.replace(tzinfo=None)
        elif candidate.tzinfo is None and gate.tzinfo is not None:
            gate = gate.replace(tzinfo=None)
        return candidate < gate

    @classmethod
    def _observed_protocol(
        cls,
        event: CanonicalOccurrence,
        traffic: NetworkTrafficLedger,
    ) -> tuple[str, tuple[FileSensorObservation, ...], int | None, int | None]:
        """Freeze application completeness implied by one sensor's traffic ledger."""

        network = event.network
        if network is None:
            return "", (), None, None

        history = network.history
        if network.protocol.lower() == "tcp":
            if traffic.missed_orig_bytes > 0 and "G" not in history:
                history += "G"
            if traffic.missed_resp_bytes > 0 and "g" not in history:
                history += "g"

        orig_ratio = cls._payload_observation_ratio(
            network.traffic.orig.payload_bytes,
            traffic.orig.payload_bytes,
        )
        resp_ratio = cls._payload_observation_ratio(
            network.traffic.resp.payload_bytes,
            traffic.resp.payload_bytes,
        )
        files: list[FileSensorObservation] = []
        for transfer in event.protocol.file_transfers:
            ratio = orig_ratio if transfer.is_orig else resp_ratio
            total = transfer.total_bytes
            if (
                transfer.entity_body_len is not None
                and transfer.wire_offset is not None
                and transfer.wire_length is not None
            ):
                seen, missing = cls._observed_multipart_leaf(
                    event,
                    transfer,
                    ratio,
                )
            else:
                accounted_total = (
                    total if total is not None else transfer.seen_bytes + transfer.missing_bytes
                )
                seen = min(transfer.seen_bytes, int(transfer.seen_bytes * ratio))
                missing = max(transfer.missing_bytes, accounted_total - seen)
            files.append(
                FileSensorObservation(
                    canonical_id=transfer.fuid,
                    seen_bytes=seen,
                    total_bytes=total,
                    missing_bytes=missing,
                    analyzers_visible=missing == 0 and not transfer.timedout,
                )
            )

        for certificate in event.protocol.x509_chain:
            total = certificate_file_size(certificate)
            seen = int(total * resp_ratio)
            files.append(
                FileSensorObservation(
                    canonical_id=certificate.fuid,
                    seen_bytes=seen,
                    total_bytes=total,
                    missing_bytes=total - seen,
                    analyzers_visible=seen == total,
                )
            )

        request_body_len = None
        response_body_len = None
        http = event.protocol.http
        if http is not None:
            canonical_request = max(
                0,
                http.flow_request_body_len
                if http.flow_request_body_len is not None
                else http.request_body_len,
            )
            canonical_response = max(
                0,
                http.flow_response_body_len
                if http.flow_response_body_len is not None
                else http.response_body_len,
            )
            request_body_len = min(http.request_body_len, int(canonical_request * orig_ratio))
            response_body_len = min(http.response_body_len, int(canonical_response * resp_ratio))

        return history, tuple(files), request_body_len, response_body_len

    @staticmethod
    def _observed_multipart_leaf(
        event: CanonicalOccurrence,
        transfer: object,
        ratio: float,
    ) -> tuple[int, int]:
        """Allocate one stable directional capture gap across multipart wire spans."""

        entity_len = max(0, int(getattr(transfer, "entity_body_len", 0) or 0))
        wire_offset = max(0, int(getattr(transfer, "wire_offset", 0) or 0))
        wire_length = max(0, int(getattr(transfer, "wire_length", 0) or 0))
        decoded_size = max(0, int(getattr(transfer, "seen_bytes", 0) or 0))
        canonical_missing = max(0, int(getattr(transfer, "missing_bytes", 0) or 0))
        if entity_len <= 0 or wire_length <= 0 or ratio >= 1.0:
            return decoded_size, canonical_missing

        missing_wire = min(entity_len, entity_len - int(entity_len * ratio))
        if missing_wire <= 0:
            return decoded_size, canonical_missing
        available_starts = entity_len - missing_wire + 1
        network = event.network
        gap_start = (
            _stable_seed(
                "http-multipart-observation-gap:"
                f"{getattr(network, 'zeek_uid', '')}:"
                f"{getattr(transfer, 'is_orig', False)}:{entity_len}"
            )
            % available_starts
        )
        gap_end = gap_start + missing_wire
        leaf_end = wire_offset + wire_length
        overlap = max(0, min(gap_end, leaf_end) - max(gap_start, wire_offset))
        if overlap <= 0:
            return decoded_size, canonical_missing
        decoded_missing = min(
            decoded_size,
            (decoded_size * overlap + wire_length - 1) // wire_length,
        )
        missing = max(canonical_missing, decoded_missing)
        return max(0, decoded_size - missing), missing

    @staticmethod
    def _payload_observation_ratio(canonical_bytes: int, observed_bytes: int) -> float:
        """Return the bounded fraction of canonical payload visible at one sensor."""

        if canonical_bytes <= 0:
            return 1.0
        return min(1.0, max(0.0, observed_bytes / canonical_bytes))

    @staticmethod
    def _nat_observation(
        event: CanonicalOccurrence,
        observed_start: datetime,
        observed_close: datetime | None,
        firewall_teardown: datetime | None,
    ) -> NatSensorObservation | None:
        """Freeze local/global address roles and translation lifetime for one sensor."""

        nat = event.nat
        network = event.network
        if nat is None or network is None:
            return None
        transaction = network
        teardown_time = None
        if nat.nat_type == "dynamic_pat":
            teardown_time = firewall_teardown or observed_close
        if nat.mapped_src_ip != transaction.src_ip or nat.mapped_src_port != transaction.src_port:
            return NatSensorObservation(
                nat_type=nat.nat_type,
                direction="source",
                local_ip=transaction.src_ip,
                local_port=transaction.src_port,
                global_ip=nat.mapped_src_ip,
                global_port=nat.mapped_src_port,
                built_time=observed_start,
                teardown_time=teardown_time,
            )
        public_dst_ip = nat.pre_nat_dst_ip or transaction.dst_ip
        public_dst_port = nat.pre_nat_dst_port or transaction.dst_port
        if nat.mapped_dst_ip != public_dst_ip or nat.mapped_dst_port != public_dst_port:
            return NatSensorObservation(
                nat_type=nat.nat_type,
                direction="destination",
                local_ip=nat.mapped_dst_ip,
                local_port=nat.mapped_dst_port,
                global_ip=public_dst_ip,
                global_port=public_dst_port,
                built_time=observed_start,
                teardown_time=teardown_time,
            )
        if nat.pre_nat_dst_ip:
            return NatSensorObservation(
                nat_type=nat.nat_type,
                direction="destination",
                local_ip=transaction.dst_ip,
                local_port=transaction.dst_port,
                global_ip=nat.pre_nat_dst_ip,
                global_port=public_dst_port,
                built_time=observed_start,
                teardown_time=teardown_time,
            )
        return None

    @classmethod
    def _firewall_teardown_plan(
        cls,
        event: CanonicalOccurrence,
        formats: set[str],
        sensor_identity: str,
        observed_start: datetime,
        observed_close: datetime | None,
        *,
        scope: TimingScope,
        runtime: TimingRuntime,
    ) -> tuple[str, datetime | None]:
        """Plan source-native ASA teardown time from canonical state and policy."""

        if "cisco_asa" not in formats:
            return "", None
        network = event.network
        if network is None:
            return "", None
        if network.protocol != "tcp":
            anchor = observed_close or observed_start
            return (
                "",
                runtime.sampler.after(
                    anchor,
                    cls._right_skew_distribution(83, 8_500),
                    relationship_key="source.firewall.datagram_teardown",
                    scope=scope,
                    sample_key="datagram",
                ),
            )
        timing: FirewallObservationTiming = firewall_observation_timing(sensor_identity)
        state = network.conn_state
        traffic = network.traffic
        payload_bytes = traffic.orig.payload_bytes + traffic.resp.payload_bytes
        if state in {"S0", "S1", "SH", "SHR"} and payload_bytes == 0:
            timeout_anchor = observed_start + timedelta(
                seconds=timing.tcp_embryonic_timeout_seconds
            )
            return (
                "SYN Timeout",
                runtime.sampler.after(
                    timeout_anchor,
                    cls._right_skew_distribution(137, 18_500),
                    relationship_key="source.firewall.syn_timeout_processing",
                    scope=scope,
                    sample_key="syn-timeout",
                ),
            )
        reason = {
            "REJ": "TCP Reset-O",
            "RSTO": "TCP Reset-O",
            "RSTR": "TCP Reset-I",
            "OTH": "TCP Reset-O",
        }.get(state, "TCP FINs")
        if observed_close is not None:
            anchor = observed_close
            minimum_us, maximum_us = (91, 12_500)
        else:
            anchor = observed_start
            minimum_us, maximum_us = (1_500, 280_000)
        return (
            reason,
            runtime.sampler.after(
                anchor,
                cls._right_skew_distribution(minimum_us, maximum_us),
                relationship_key="source.firewall.connection_teardown",
                scope=scope,
                sample_key=f"teardown:{state or 'unknown'}",
            ),
        )

    @staticmethod
    def _sensor_formats(
        event: CanonicalOccurrence,
        visible_formats: set[str],
    ) -> dict[str, set[str]]:
        sensor_formats: dict[str, set[str]] = {}
        for format_name, sensor_identities in event._sensor_hostnames_by_format.items():
            if format_name not in visible_formats:
                continue
            for sensor_identity in sensor_identities:
                sensor_formats.setdefault(sensor_identity, set()).add(format_name)
        return sensor_formats

    def _sensor_view(
        self,
        event: CanonicalOccurrence,
        sensor: NetworkSensor | None,
    ) -> tuple[NetworkTuple, bool, bool]:
        """Derive one sensor's tuple and locality directly from topology and NAT truth."""

        network = event.network
        transaction = network
        tuple_view = NetworkTuple(
            src_ip=network.src_ip,
            src_port=network.src_port,
            dst_ip=network.dst_ip,
            dst_port=network.dst_port,
            protocol=network.protocol,
        )
        local_orig = network.local_orig
        local_resp = network.local_resp
        nat = event.nat
        if (
            nat is None
            or sensor is None
            or sensor.type == "firewall"
            or self.visibility_engine is None
        ):
            return tuple_view, local_orig, local_resp

        sensor_segments = set(sensor.monitoring_segments)
        inbound = nat.nat_type == "static" and bool(
            nat.pre_nat_dst_ip or (nat.mapped_dst_ip and nat.mapped_dst_ip != transaction.dst_ip)
        )
        if inbound:
            local_dst_ip = nat.mapped_dst_ip or transaction.dst_ip
            local_dst_port = nat.mapped_dst_port or transaction.dst_port
            global_dst_ip = nat.pre_nat_dst_ip or transaction.dst_ip
            global_dst_port = nat.pre_nat_dst_port or transaction.dst_port
            local_segments = self.visibility_engine._resolve_ip_segments(local_dst_ip)
            inside = bool(sensor_segments & local_segments)
            tuple_view = NetworkTuple(
                src_ip=transaction.src_ip,
                src_port=transaction.src_port,
                dst_ip=local_dst_ip if inside else global_dst_ip,
                dst_port=local_dst_port if inside else global_dst_port,
                protocol=transaction.protocol,
            )
            return tuple_view, local_orig, local_resp or inside

        source_segments = self.visibility_engine._resolve_ip_segments(transaction.src_ip)
        if sensor_segments & source_segments:
            return tuple_view, local_orig, local_resp
        tuple_view = NetworkTuple(
            src_ip=nat.mapped_src_ip or transaction.src_ip,
            src_port=nat.mapped_src_port or transaction.src_port,
            dst_ip=nat.mapped_dst_ip or transaction.dst_ip,
            dst_port=nat.mapped_dst_port or transaction.dst_port,
            protocol=transaction.protocol,
        )
        return tuple_view, local_orig, local_resp

    @staticmethod
    def _canonical_file_ids(event: CanonicalOccurrence) -> tuple[str, ...]:
        values: list[str] = []

        def add(candidate: object) -> None:
            if isinstance(candidate, str) and candidate and candidate not in values:
                values.append(candidate)

        if event.protocol.primary_file_transfer is not None:
            add(event.protocol.primary_file_transfer.fuid)
        for transfer in event.protocol.file_transfers:
            add(transfer.fuid)
        if event.protocol.ssl is not None:
            for value in event.protocol.ssl.cert_chain_fuids:
                add(value)
        if event.protocol.http is not None:
            for value in event.protocol.http.orig_fuids:
                add(value)
            for value in event.protocol.http.resp_fuids:
                add(value)
        if event.smtp is not None:
            for value in event.smtp.fuids:
                add(value)
        if event.protocol.leaf_certificate is not None:
            add(event.protocol.leaf_certificate.fuid)
        for certificate in event.protocol.x509_chain:
            add(certificate.fuid)
        if event.protocol.ocsp is not None:
            add(event.protocol.ocsp.id)
        for pe in event.protocol.pe_analyses:
            add(pe.id)
        return tuple(values)

    @staticmethod
    def _canonical_connection_ids(event: CanonicalOccurrence) -> tuple[str, ...]:
        values = [event.network.zeek_uid]
        if event.dhcp is not None:
            values.extend(uid for uid in event.dhcp.uids if uid and uid not in values)
        return tuple(values)

    def _runtime_for_event(self, canonical_time: datetime) -> TimingRuntime:
        """Return the injected runtime or a deterministic direct-caller adapter."""

        if self._runtime_injected:
            return self.timing_runtime
        # Low-level callers historically constructed this planner directly. A
        # day-local adapter avoids applying decades of compatibility-epoch drift
        # while production always uses the engine-owned scenario runtime.
        reference = ensure_utc(canonical_time).replace(hour=0, minute=0, second=0, microsecond=0)
        return TimingRuntime(reference_time=reference)

    @classmethod
    def _observed_interval(
        cls,
        canonical_start: datetime,
        canonical_close: datetime | None,
        timing: NetworkSensorObservationTiming,
        sensor_identity: str,
        path_role: str,
        transaction_id: str,
        runtime: TimingRuntime,
    ) -> tuple[datetime, datetime | None]:
        """Project one canonical interval through a physical sensor clock and route."""

        clock_key = cls._sensor_clock_key(sensor_identity, timing.profile_name)
        clock_spec = cls._sensor_clock_spec(timing)
        scope = TimingScope(
            stable_id=transaction_id,
            source=sensor_identity.casefold(),
            lifecycle_id=path_role,
        )
        route_delay = runtime.sampler.sample_timedelta(
            cls._right_skew_distribution(
                timing.route_delay_min_us,
                timing.route_delay_max_us,
            ),
            relationship_key="network.sensor.route_delay",
            scope=scope,
            sample_key="route",
        )
        observed_start = (
            runtime.clocks.project(
                ensure_utc(canonical_start),
                key=clock_key,
                spec=clock_spec,
            )
            + route_delay
        )
        if canonical_close is None:
            return observed_start, None
        observed_close = (
            runtime.clocks.project(
                ensure_utc(canonical_close),
                key=clock_key,
                spec=clock_spec,
            )
            + route_delay
        )
        observed_close += runtime.sampler.sample_timedelta(
            cls._right_skew_distribution(73, 1_800),
            relationship_key="network.sensor.close_processing",
            scope=scope,
            sample_key="close",
        )
        if observed_close < observed_start:
            runtime.audit.record_saturation("network.sensor.clock_interval")
            raise TimingDistributionError(
                "sensor clock projection inverted a canonical network interval: "
                f"sensor={sensor_identity!r} transaction={transaction_id!r}"
            )
        return observed_start, observed_close

    @staticmethod
    def _sensor_clock_key(sensor_identity: str, profile_name: str) -> SourceClockKey:
        return SourceClockKey(
            kind="network_sensor",
            identity=sensor_identity.casefold(),
            profile=profile_name,
        )

    @classmethod
    def _sensor_clock_spec(
        cls,
        timing: NetworkSensorObservationTiming,
    ) -> SourceClockSpec:
        return SourceClockSpec(
            offset_microseconds=cls._clock_distribution(
                timing.clock_offset_min_us,
                timing.clock_offset_max_us,
            ),
            drift_ppm=cls._clock_distribution(
                timing.clock_drift_min_ppm,
                timing.clock_drift_max_ppm,
            ),
            wander=ClockWanderSpec(
                knot_distribution_microseconds=cls._clock_distribution(
                    timing.event_jitter_min_us,
                    timing.event_jitter_max_us,
                ),
                knot_interval=timedelta(minutes=5),
            ),
        )

    @staticmethod
    def _clock_distribution(
        minimum: int, maximum: int
    ) -> ConstantDistribution | TriangularDistribution:
        if maximum <= minimum:
            return ConstantDistribution(float(minimum))
        mode = min(float(maximum), max(float(minimum), 0.0))
        return TriangularDistribution(float(minimum), mode, float(maximum))

    @staticmethod
    def _right_skew_distribution(
        minimum_us: int,
        maximum_us: int,
    ) -> ConstantDistribution | TruncatedLognormalDistribution:
        if maximum_us <= minimum_us + 2:
            return ConstantDistribution(float(max(minimum_us, maximum_us)))
        span = maximum_us - minimum_us
        median = max(1.0, minimum_us + span * 0.18)
        return TruncatedLognormalDistribution(
            median=median,
            sigma=0.78,
            minimum=float(minimum_us),
            maximum=float(maximum_us),
        )

    @classmethod
    def _source_native_protocol_timing(
        cls,
        event: CanonicalOccurrence,
        *,
        canonical_start: datetime,
        observed_start: datetime,
        observed_close: datetime | None,
        sensor_identity: str,
        path_role: str,
        visible_formats: set[str],
        timing: NetworkSensorObservationTiming,
        runtime: TimingRuntime,
    ) -> tuple[tuple[tuple[str, datetime], ...], tuple[tuple[str, float], ...]]:
        """Freeze Zeek connection, analyzer, and file timing before rendering."""

        network = event.network
        if network is None:
            return (), ()
        source_times: dict[str, datetime] = {}
        source_durations: dict[str, float] = {}
        scope = TimingScope(
            stable_id=network.stable_id or network.zeek_uid,
            source=sensor_identity.casefold(),
            lifecycle_id=path_role,
        )
        if "zeek_conn" in visible_formats:
            conn_key = network_source_timing_key("zeek_conn")
            source_times[conn_key] = observed_start
            if observed_close is not None:
                source_durations[conn_key] = (observed_close - observed_start).total_seconds()

        for format_name in ("zeek_smb_files", "zeek_smb_mapping", "zeek_weird"):
            if format_name in visible_formats:
                source_times[network_source_timing_key(format_name)] = observed_start

        dns = event.dns
        if dns is not None and "zeek_dns" in visible_formats:
            dns_key = network_source_timing_key("zeek_dns")
            source_rtt_us = max(0, round(float(dns.rtt or 0.0) * 1_000_000))
            dns_upper = observed_close
            if observed_close is not None and source_rtt_us > 0:
                observed_duration_us = round(
                    (observed_close - observed_start).total_seconds() * 1_000_000
                )
                if observed_duration_us <= 8:
                    runtime.audit.record_saturation("source.zeek_dns.admissible_window")
                    raise TimingDistributionError(
                        "source.zeek_dns has no microsecond interior inside its transport"
                    )
                query_reserve_us = (
                    min(
                        observed_duration_us - 4,
                        max(1_004, min(10_000, observed_duration_us // 8)),
                    )
                    if observed_duration_us > 1_008
                    else max(4, observed_duration_us // 3)
                )
                maximum_rtt_us = observed_duration_us - query_reserve_us - 1
                if source_rtt_us > maximum_rtt_us:
                    minimum_rtt_us = max(0, min(maximum_rtt_us - 2, round(maximum_rtt_us * 0.72)))
                    source_rtt_us = runtime.sampler.sample_microseconds(
                        cls._right_skew_distribution(minimum_rtt_us, maximum_rtt_us + 1),
                        relationship_key="source.zeek_dns.rtt_projection",
                        scope=scope,
                        sample_key=f"rtt:{observed_duration_us}",
                    )
                dns_upper = observed_close - timedelta(microseconds=source_rtt_us + 1)
            dns_window = get_timing_window(
                "source.zeek_dns_query",
                default_min_ms=1,
                default_max_ms=95,
                default_position="after",
                default_class="same_observation",
            )
            dns_time = cls._sample_after_within(
                observed_start,
                dns_upper,
                minimum_us=dns_window.min_ms * 1_000,
                maximum_us=dns_window.max_ms * 1_000,
                relationship_key="source.zeek_dns_query",
                scope=scope,
                sample_key=f"dns:{dns.trans_id}:{dns.query}",
                runtime=runtime,
            )
            source_times[dns_key] = dns_time
            if source_rtt_us > 0:
                response_time = dns_time + timedelta(microseconds=source_rtt_us)
                source_times[network_source_timing_key("zeek_dns", "response")] = response_time
                source_durations[dns_key] = source_rtt_us / 1_000_000

        if event.dhcp is not None and "zeek_dhcp" in visible_formats:
            dhcp_key = network_source_timing_key("zeek_dhcp")
            source_times[dhcp_key] = observed_start
            if observed_close is not None:
                dhcp_duration = (observed_close - observed_start).total_seconds()
                source_times[network_source_timing_key("zeek_dhcp", "close")] = observed_close
                source_durations[dhcp_key] = dhcp_duration

        if event.smtp is not None and "zeek_smtp" in visible_formats:
            smtp_key = network_source_timing_key("zeek_smtp")
            source_times[smtp_key] = cls._sample_after_within(
                observed_start,
                observed_close,
                minimum_us=1_300,
                maximum_us=180_000,
                relationship_key="source.zeek_smtp_transaction",
                scope=scope,
                sample_key=f"smtp:{event.smtp.trans_depth}:{event.smtp.msg_id}",
                runtime=runtime,
            )

        if event.ntp is not None and "zeek_ntp" in visible_formats:
            ntp_key = network_source_timing_key("zeek_ntp")
            ntp_time = cls._sample_after_within(
                observed_start,
                observed_close,
                minimum_us=100,
                maximum_us=120_000,
                relationship_key="source.zeek_ntp_response",
                scope=scope,
                sample_key=f"ntp:{event.ntp.stratum}:{event.ntp.xmt_ts}",
                runtime=runtime,
            )
            source_times[ntp_key] = ntp_time

        ssl_time: datetime | None = None
        needs_tls_timing = bool(
            event.protocol.ssl is not None
            or event.protocol.x509_chain
            or event.protocol.leaf_certificate is not None
        )
        if needs_tls_timing:
            ssl_window = get_timing_window(
                "source.zeek_ssl_analyzer",
                default_min_ms=3,
                default_max_ms=650,
                default_position="after",
                default_class="same_observation",
            )
            ssl_time = cls._sample_after_within(
                observed_start,
                observed_close,
                minimum_us=ssl_window.min_ms * 1_000,
                maximum_us=ssl_window.max_ms * 1_000,
                relationship_key="source.zeek_ssl_analyzer",
                scope=scope,
                sample_key="ssl",
                runtime=runtime,
            )
            if "zeek_ssl" in visible_formats and event.protocol.ssl is not None:
                source_times[network_source_timing_key("zeek_ssl")] = ssl_time

        file_window = get_timing_window(
            "source.zeek_file_analyzer",
            default_min_ms=25,
            default_max_ms=250,
            default_position="after",
            default_class="same_observation",
        )
        ocsp = event.protocol.ocsp
        ocsp_transfer = (
            next(
                (
                    transfer
                    for transfer in event.protocol.file_transfers
                    if ocsp is not None and transfer.fuid == ocsp.id
                ),
                None,
            )
            if ocsp is not None
            else None
        )
        ocsp_duration_floor_us = (
            max(4, round(max(0.0, ocsp_transfer.duration) * 0.55 * 1_000_000))
            if ocsp_transfer is not None
            else 0
        )
        http_time: datetime | None = None
        http = event.protocol.http
        if http is not None:
            canonical_request = http.canonical_request_time
            request_anchor = (
                max(observed_start, ssl_time) if ssl_time is not None else observed_start
            )
            if canonical_request is not None:
                request_anchor = max(
                    request_anchor,
                    cls._project_phase_time(
                        ensure_utc(canonical_request),
                        canonical_start=canonical_start,
                        observed_start=observed_start,
                        sensor_identity=sensor_identity,
                        timing=timing,
                        runtime=runtime,
                    ),
                )
            http_window = get_timing_window(
                "source.zeek_http_request",
                default_min_ms=1,
                default_max_ms=450,
                default_position="after",
                default_class="same_observation",
            )
            http_upper = observed_close
            if observed_close is not None and ocsp_duration_floor_us:
                downstream_reserve_us = file_window.min_ms * 1_000 + ocsp_duration_floor_us + 3
                http_upper = observed_close - timedelta(microseconds=downstream_reserve_us)
            http_time = cls._sample_after_within(
                request_anchor,
                http_upper,
                minimum_us=http_window.min_ms * 1_000,
                maximum_us=http_window.max_ms * 1_000,
                relationship_key="source.zeek_http_request",
                scope=scope,
                sample_key=f"http:{http.trans_depth}",
                runtime=runtime,
            )
            if "zeek_http" in visible_formats:
                source_times[network_source_timing_key("zeek_http")] = http_time

        file_times: dict[str, datetime] = {}
        file_durations: dict[str, float] = {}
        previous_file_time: datetime | None = None
        transfers = sorted(event.protocol.file_transfers, key=lambda transfer: not transfer.is_orig)
        for ordinal, transfer in enumerate(transfers):
            anchor = observed_start
            if http_time is not None and transfer.fuid in (*http.orig_fuids, *http.resp_fuids):
                anchor = http_time
            elif ssl_time is not None and transfer.source.upper() == "SSL":
                anchor = ssl_time
            if transfer.observation_not_before is not None:
                projected_not_before = cls._project_phase_time(
                    ensure_utc(transfer.observation_not_before),
                    canonical_start=canonical_start,
                    observed_start=observed_start,
                    sensor_identity=sensor_identity,
                    timing=timing,
                    runtime=runtime,
                )
                if observed_close is None or projected_not_before < observed_close:
                    anchor = max(anchor, projected_not_before)
                else:
                    runtime.audit.record_saturation(
                        "source.zeek_file.observation_not_before_window"
                    )
            file_upper = observed_close
            if (
                observed_close is not None
                and ocsp is not None
                and transfer.fuid == ocsp.id
                and ocsp_duration_floor_us
            ):
                file_upper = observed_close - timedelta(microseconds=ocsp_duration_floor_us)
            if previous_file_time is not None:
                anchor = cls._sample_after_within(
                    max(anchor, previous_file_time),
                    file_upper,
                    minimum_us=113,
                    maximum_us=8_500,
                    relationship_key="source.zeek_file.inter_row_gap",
                    scope=scope,
                    sample_key=f"file-gap:{ordinal}:{transfer.fuid}",
                    runtime=runtime,
                )
                minimum_us = 0
            else:
                minimum_us = file_window.min_ms * 1_000
            file_time = cls._sample_after_within(
                anchor,
                file_upper,
                minimum_us=minimum_us,
                maximum_us=file_window.max_ms * 1_000,
                relationship_key="source.zeek_file_analyzer",
                scope=scope,
                sample_key=f"file:{ordinal}:{transfer.fuid}",
                runtime=runtime,
            )
            duration = cls._sample_file_duration(
                transfer.duration,
                source=transfer.source,
                start=file_time,
                close=observed_close,
                scope=scope,
                sample_key=f"duration:{ordinal}:{transfer.fuid}",
                runtime=runtime,
            )
            file_times[transfer.fuid] = file_time
            file_durations[transfer.fuid] = duration
            previous_file_time = file_time
            if "zeek_files" in visible_formats:
                key = network_source_timing_key("zeek_files", transfer.fuid)
                source_times[key] = file_time
                source_durations[key] = duration

        certificates = event.protocol.x509_chain or (
            (event.protocol.leaf_certificate,)
            if event.protocol.leaf_certificate is not None
            else ()
        )
        previous_certificate_file: datetime | None = None
        previous_x509: datetime | None = None
        for position, certificate in enumerate(certificates):
            anchor = ssl_time or observed_start
            if previous_certificate_file is not None:
                anchor = max(anchor, previous_certificate_file)
            certificate_file_time = cls._sample_after_within(
                anchor,
                observed_close,
                minimum_us=2_103,
                maximum_us=24_853,
                relationship_key="source.zeek_tls_certificate_file",
                scope=scope,
                sample_key=f"cert-file:{position}:{certificate.fuid}",
                runtime=runtime,
            )
            file_times[certificate.fuid] = certificate_file_time
            previous_certificate_file = certificate_file_time
            if "zeek_files" in visible_formats:
                source_times[network_source_timing_key("zeek_files", certificate.fuid)] = (
                    certificate_file_time
                )

            x509_anchor = certificate_file_time
            if previous_x509 is not None:
                x509_anchor = max(x509_anchor, previous_x509)
            x509_time = cls._sample_after_within(
                x509_anchor,
                observed_close,
                minimum_us=2_137,
                maximum_us=24_919,
                relationship_key="source.zeek_x509_analyzer",
                scope=scope,
                sample_key=f"x509:{position}:{certificate.fuid}",
                runtime=runtime,
            )
            previous_x509 = x509_time
            if "zeek_x509" in visible_formats:
                source_times[network_source_timing_key("zeek_x509", certificate.fuid)] = x509_time

        if ocsp is not None and "zeek_ocsp" in visible_formats:
            anchor = file_times.get(ocsp.id, ssl_time or observed_start)
            file_duration = file_durations.get(ocsp.id, 0.0)
            ocsp_close = (
                anchor + timedelta(seconds=file_duration) if file_duration > 0 else observed_close
            )
            source_times[network_source_timing_key("zeek_ocsp", ocsp.id)] = (
                cls._sample_after_within(
                    anchor,
                    ocsp_close,
                    minimum_us=37,
                    maximum_us=250_000,
                    relationship_key="source.zeek_ocsp_analyzer",
                    scope=scope,
                    sample_key=f"ocsp:{ocsp.id}",
                    runtime=runtime,
                )
            )

        if "zeek_pe" in visible_formats:
            for ordinal, pe in enumerate(event.protocol.pe_analyses):
                anchor = file_times.get(pe.id, observed_start)
                file_duration = file_durations.get(pe.id, 0.0)
                pe_close = (
                    anchor + timedelta(seconds=file_duration)
                    if file_duration > 0
                    else observed_close
                )
                source_times[network_source_timing_key("zeek_pe", pe.id)] = (
                    cls._sample_after_within(
                        anchor,
                        pe_close,
                        minimum_us=43,
                        maximum_us=250_000,
                        relationship_key="source.zeek_pe_analyzer",
                        scope=scope,
                        sample_key=f"pe:{ordinal}:{pe.id}",
                        runtime=runtime,
                    )
                )

        return tuple(sorted(source_times.items())), tuple(sorted(source_durations.items()))

    @classmethod
    def _project_phase_time(
        cls,
        canonical_time: datetime,
        *,
        canonical_start: datetime,
        observed_start: datetime,
        sensor_identity: str,
        timing: NetworkSensorObservationTiming,
        runtime: TimingRuntime,
    ) -> datetime:
        """Project a canonical child phase through the owning sensor clock."""

        key = cls._sensor_clock_key(sensor_identity, timing.profile_name)
        spec = cls._sensor_clock_spec(timing)
        projected_start = runtime.clocks.project(canonical_start, key=key, spec=spec)
        route_delay = observed_start - projected_start
        return runtime.clocks.project(canonical_time, key=key, spec=spec) + route_delay

    @classmethod
    def _sample_after_within(
        cls,
        anchor: datetime,
        upper_bound: datetime | None,
        *,
        minimum_us: int,
        maximum_us: int,
        relationship_key: str,
        scope: TimingScope,
        sample_key: str,
        runtime: TimingRuntime,
    ) -> datetime:
        """Sample right-skew analyzer slack inside the available interval."""

        minimum_us = max(0, minimum_us)
        maximum_us = max(minimum_us + 3, maximum_us)
        if upper_bound is None:
            return runtime.sampler.after(
                anchor,
                cls._right_skew_distribution(minimum_us, maximum_us),
                relationship_key=relationship_key,
                scope=scope,
                sample_key=sample_key,
            )
        available_us = round((upper_bound - anchor).total_seconds() * 1_000_000)
        if available_us <= 2:
            runtime.audit.record_saturation(f"{relationship_key}.admissible_window")
            raise TimingDistributionError(
                f"{relationship_key} has no microsecond interior before its owning close: "
                f"anchor={anchor.isoformat()} close={upper_bound.isoformat()} "
                f"available_us={available_us}"
            )
        sampled_maximum = min(maximum_us, available_us)
        sampled_minimum = min(minimum_us, max(0, sampled_maximum - 3))
        if sampled_maximum <= sampled_minimum + 2:
            sampled_minimum = 0
        try:
            return runtime.sampler.after(
                anchor,
                cls._right_skew_distribution(sampled_minimum, sampled_maximum),
                relationship_key=relationship_key,
                scope=scope,
                sample_key=f"{sample_key}:{available_us}",
            )
        except TimingDistributionError:
            runtime.audit.record_saturation(f"{relationship_key}.admissible_window")
            raise

    @classmethod
    def _sample_file_duration(
        cls,
        canonical_duration: float,
        *,
        source: str,
        start: datetime,
        close: datetime | None,
        scope: TimingScope,
        sample_key: str,
        runtime: TimingRuntime,
    ) -> float:
        """Sample a file-analysis duration with interior transport-close slack."""

        if canonical_duration <= 0:
            return 0.0
        canonical_us = max(1, round(canonical_duration * 1_000_000))
        if close is None:
            maximum_us = max(canonical_us + 3, round(canonical_us * 1.45))
        else:
            available_us = round((close - start).total_seconds() * 1_000_000)
            if available_us <= 3:
                runtime.audit.record_saturation("source.zeek_file.duration_window")
                return 0.0
            cap_us = {
                "HTTP": 120_000,
                "SMB": 160_000,
                "SMTP": 280_000,
            }.get(source.upper(), 100_000)
            margin_maximum = min(cap_us, max(3, available_us // 3))
            margin = runtime.sampler.sample_microseconds(
                cls._right_skew_distribution(1, margin_maximum),
                relationship_key="source.zeek_file.close_slack",
                scope=scope,
                sample_key=f"{sample_key}:close",
            )
            maximum_us = available_us - margin
            if maximum_us <= 2:
                runtime.audit.record_saturation("source.zeek_file.duration_window")
                return 0.0
        lower_us = max(0, min(maximum_us - 2, round(canonical_us * 0.55)))
        preferred_us = min(canonical_us, max(1, round(maximum_us * 0.82)))
        upper_us = min(maximum_us, max(preferred_us + 3, round(canonical_us * 1.55)))
        if upper_us <= lower_us + 2:
            lower_us = 0
            upper_us = maximum_us
        try:
            duration_us = runtime.sampler.sample_microseconds(
                TruncatedLognormalDistribution(
                    median=float(max(1, preferred_us)),
                    sigma=0.42,
                    minimum=float(lower_us),
                    maximum=float(upper_us),
                ),
                relationship_key="source.zeek_file.duration",
                scope=scope,
                sample_key=sample_key,
            )
        except TimingDistributionError:
            runtime.audit.record_saturation("source.zeek_file.duration_window")
            duration_us = max(1, maximum_us // 2)
        return duration_us / 1_000_000

    @classmethod
    def _observed_traffic(
        cls,
        canonical: NetworkTrafficLedger,
        timing: NetworkSensorObservationTiming,
        sensor_identity: str,
        transaction_id: str,
        protocol: str,
    ) -> NetworkTrafficLedger:
        if protocol.lower() != "tcp":
            # The canonical ledger does not retain individual datagram sizes.
            # Fractional byte loss would fabricate a rewritten UDP/ICMP packet
            # while leaving packet counts and analyzer content unchanged.
            return canonical
        rng = random.Random(
            _stable_seed(
                f"network-capture-loss:{timing.profile_name}:{sensor_identity}:{transaction_id}"
            )
        )
        if (
            timing.capture_loss_probability <= 0
            or timing.capture_loss_max_fraction <= 0
            or timing.capture_loss_max_missed_bytes <= 0
            or rng.random() >= timing.capture_loss_probability
        ):
            return canonical
        orig = canonical.orig
        resp = canonical.resp
        missed_orig = 0
        missed_resp = 0
        has_orig = canonical.orig.payload_bytes > 0
        has_resp = canonical.resp.payload_bytes > 0
        if has_orig and has_resp:
            # Capture gaps usually affect one observed direction (asymmetric
            # routing, SPAN pressure, receive-buffer loss). Reserve paired gaps
            # for the smaller class of sensor-wide loss episodes.
            shape_roll = rng.random()
            lose_orig = shape_roll < 0.44 or shape_roll >= 0.88
            lose_resp = 0.44 <= shape_roll < 0.88 or shape_roll >= 0.88
        else:
            lose_orig = has_orig
            lose_resp = has_resp
        if lose_orig:
            orig, missed_orig = cls._lose_direction(canonical.orig, timing, rng)
        if lose_resp:
            resp, missed_resp = cls._lose_direction(canonical.resp, timing, rng)
        if missed_orig + missed_resp <= 0:
            return canonical
        return NetworkTrafficLedger(
            orig=orig,
            resp=resp,
            missed_orig_bytes=canonical.missed_orig_bytes + missed_orig,
            missed_resp_bytes=canonical.missed_resp_bytes + missed_resp,
        )

    @staticmethod
    def _lose_direction(
        canonical: DirectionalTrafficLedger,
        timing: NetworkSensorObservationTiming,
        rng: random.Random,
    ) -> tuple[DirectionalTrafficLedger, int]:
        if canonical.payload_bytes <= 0:
            return canonical, 0
        fraction = rng.uniform(
            timing.capture_loss_min_fraction,
            timing.capture_loss_max_fraction,
        )
        missed = min(
            canonical.payload_bytes,
            timing.capture_loss_max_missed_bytes,
            max(1, int(round(canonical.payload_bytes * fraction))),
        )
        payload = canonical.payload_bytes - missed
        lost_packets = min(
            canonical.packets,
            max(1, int(round(canonical.packets * fraction))),
        )
        packets = canonical.packets - lost_packets
        header_bytes = max(0, canonical.ip_bytes - canonical.payload_bytes)
        lost_headers = min(
            header_bytes,
            int(round(header_bytes * fraction)),
        )
        ip_bytes = canonical.ip_bytes - missed - lost_headers
        if ip_bytes > 0 and packets == 0:
            packets = 1
        return DirectionalTrafficLedger(payload, packets, max(payload, ip_bytes)), missed


RUNTIME_OWNED_ZEEK_FORMATS = frozenset(
    {
        "zeek_conn",
        "zeek_dhcp",
        "zeek_dns",
        "zeek_files",
        "zeek_http",
        "zeek_ntp",
        "zeek_ocsp",
        "zeek_pe",
        "zeek_smtp",
        "zeek_ssl",
        "zeek_x509",
    }
)


def compatibility_network_source_time(
    event: CanonicalOccurrence,
    key: str,
) -> datetime:
    """Plan one direct-caller source time outside an emitter instance.

    Production dispatch always attaches sensor observations. This adapter keeps
    low-level emitter APIs deterministic without restoring module-global
    planners or mutable emitter timing state.
    """

    if event.network is None:
        return _compatibility_context_source_time(event, key)
    source_times, _source_durations = _compatibility_protocol_timing(event)
    return dict(source_times).get(key, ensure_utc(event.timestamp))


def compatibility_network_source_duration(
    event: CanonicalOccurrence,
    key: str,
) -> float | None:
    """Plan one direct-caller source duration outside an emitter instance."""

    _source_times, source_durations = _compatibility_protocol_timing(event)
    duration = dict(source_durations).get(key)
    network = event.network
    if (
        key == network_source_timing_key("zeek_conn")
        and network is not None
        and network.protocol == "tcp"
        and network.dst_port == 443
        and network.conn_state == "SF"
        and (event.protocol.ssl is not None or network.service == "ssl")
    ):
        canonical = max(0.0, float(network.duration or 0.0))
        window = get_timing_window(
            "network.tls_completed_min_duration",
            default_min_ms=800,
            default_max_ms=2500,
            default_position="after",
            default_class="same_observation",
        )
        floor_seconds = window.min_ms / 1_000
        if canonical <= floor_seconds or abs(canonical - 1.2) < 0.000001:
            runtime = _compatibility_runtime(event)
            scope = _compatibility_scope(event)
            slack_us = runtime.sampler.sample_microseconds(
                NetworkObservationPlanner._right_skew_distribution(15_000, 650_000),
                relationship_key="network.tls_completed.duration_slack",
                scope=scope,
                sample_key="direct",
            )
            return max(canonical, floor_seconds) + slack_us / 1_000_000
    return duration


def _compatibility_protocol_timing(
    event: CanonicalOccurrence,
) -> tuple[tuple[tuple[str, datetime], ...], tuple[tuple[str, float], ...]]:
    """Return one stateless direct-emitter protocol timing plan."""

    network = event.network
    if network is None:
        return (), ()
    canonical_start = ensure_utc(event.timestamp)
    observed_close = (
        canonical_start + timedelta(seconds=network.duration)
        if network.duration is not None
        else None
    )
    runtime = _compatibility_runtime(event)
    timing = network_sensor_observation_timing("well_synced")
    return NetworkObservationPlanner._source_native_protocol_timing(
        event,
        canonical_start=canonical_start,
        observed_start=canonical_start,
        observed_close=observed_close,
        sensor_identity="__direct__",
        path_role="direct",
        visible_formats=set(RUNTIME_OWNED_ZEEK_FORMATS),
        timing=timing,
        runtime=runtime,
    )


def _compatibility_context_source_time(
    event: CanonicalOccurrence,
    key: str,
) -> datetime:
    """Plan direct protocol-context timing when no transport was supplied."""

    runtime = _compatibility_runtime(event)
    scope = _compatibility_scope(event)
    anchor = ensure_utc(event.timestamp)
    ssl_time = NetworkObservationPlanner._sample_after_within(
        anchor,
        None,
        minimum_us=3_000,
        maximum_us=650_000,
        relationship_key="source.zeek_ssl_analyzer",
        scope=scope,
        sample_key="ssl",
        runtime=runtime,
    )
    if key == network_source_timing_key("zeek_ssl"):
        return ssl_time
    certificates = event.protocol.x509_chain or (
        (event.protocol.leaf_certificate,) if event.protocol.leaf_certificate is not None else ()
    )
    previous_file = ssl_time
    previous_x509 = ssl_time
    for position, certificate in enumerate(certificates):
        file_time = NetworkObservationPlanner._sample_after_within(
            previous_file,
            None,
            minimum_us=2_103,
            maximum_us=24_853,
            relationship_key="source.zeek_tls_certificate_file",
            scope=scope,
            sample_key=f"cert-file:{position}:{certificate.fuid}",
            runtime=runtime,
        )
        x509_time = NetworkObservationPlanner._sample_after_within(
            max(file_time, previous_x509),
            None,
            minimum_us=2_137,
            maximum_us=24_919,
            relationship_key="source.zeek_x509_analyzer",
            scope=scope,
            sample_key=f"x509:{position}:{certificate.fuid}",
            runtime=runtime,
        )
        if key == network_source_timing_key("zeek_files", certificate.fuid):
            return file_time
        if key == network_source_timing_key("zeek_x509", certificate.fuid):
            return x509_time
        previous_file = file_time
        previous_x509 = x509_time
    return anchor


def _compatibility_runtime(event: CanonicalOccurrence) -> TimingRuntime:
    reference = ensure_utc(event.timestamp).replace(hour=0, minute=0, second=0, microsecond=0)
    return TimingRuntime(reference_time=reference)


def _compatibility_scope(event: CanonicalOccurrence) -> TimingScope:
    network = event.network
    return TimingScope(
        stable_id=(
            network.stable_id or network.zeek_uid
            if network is not None
            else event.timestamp.isoformat()
        ),
        source="__direct__",
        lifecycle_id="direct",
    )
