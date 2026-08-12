# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Plan frozen per-sensor observations from canonical network transactions."""

from __future__ import annotations

import hashlib
import random
import string
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
    network_sensor_observation_timing,
)
from evidenceforge.generation.activity.tls_realism import certificate_file_size
from evidenceforge.utils.ids import _has_synthetic_marker
from evidenceforge.utils.rng import _stable_seed

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


class NetworkObservationPlanner:
    """Project canonical network truth through configured sensor behavior."""

    def __init__(
        self,
        visibility_engine: NetworkVisibilityEngine | None,
        output_end_time: datetime | None = None,
    ) -> None:
        self.visibility_engine = visibility_engine
        self.output_end_time = output_end_time

    def plan(
        self,
        event: CanonicalOccurrence,
        visible_formats: set[str],
    ) -> tuple[NetworkSensorObservation, ...]:
        """Return deterministic observations for every visible network sensor."""

        network = event.network
        if network is None:
            return ()
        transaction = network
        sensor_formats = self._sensor_formats(event, visible_formats)
        canonical_file_ids = self._canonical_file_ids(event)
        canonical_connection_ids = self._canonical_connection_ids(event)
        observations: list[NetworkSensorObservation] = []
        for sensor_identity, formats in sorted(sensor_formats.items()):
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
            observed_start = self._observed_time(
                transaction.started_at,
                timing,
                sensor_identity,
                path_role,
            )
            observed_close = (
                self._observed_time(
                    transaction.closed_at,
                    timing,
                    sensor_identity,
                    path_role,
                )
                if transaction.closed_at is not None
                else None
            )
            if observed_close is not None:
                canonical_duration = transaction.closed_at - transaction.started_at
                observed_close = max(
                    observed_close,
                    observed_start + canonical_duration,
                )
            firewall_reason, firewall_teardown = self._firewall_teardown_plan(
                event,
                formats,
                sensor_identity,
                observed_start,
                observed_close,
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
                    visible_formats=frozenset(formats),
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
                )
            )
        return tuple(observations)

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

    @staticmethod
    def _firewall_teardown_plan(
        event: CanonicalOccurrence,
        formats: set[str],
        sensor_identity: str,
        observed_start: datetime,
        observed_close: datetime | None,
    ) -> tuple[str, datetime | None]:
        """Plan ASA lifecycle semantics from canonical state and device policy."""

        if "cisco_asa" not in formats:
            return "", None
        network = event.network
        if network is None or network.protocol != "tcp":
            return "", observed_close or observed_start
        timing: FirewallObservationTiming = firewall_observation_timing(sensor_identity)
        state = network.conn_state
        traffic = network.traffic
        payload_bytes = traffic.orig.payload_bytes + traffic.resp.payload_bytes
        if state in {"S0", "S1", "SH", "SHR"} and payload_bytes == 0:
            return (
                "SYN Timeout",
                observed_start + timedelta(seconds=timing.tcp_embryonic_timeout_seconds),
            )
        reason = {
            "REJ": "TCP Reset-O",
            "RSTO": "TCP Reset-O",
            "RSTR": "TCP Reset-I",
            "OTH": "TCP Reset-O",
        }.get(state, "TCP FINs")
        return reason, observed_close or observed_start

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

    @classmethod
    def _observed_time(
        cls,
        canonical_time: datetime,
        timing: NetworkSensorObservationTiming,
        sensor_identity: str,
        path_role: str,
    ) -> datetime:
        offset_us = cls._bounded_int(
            "clock-offset",
            timing.clock_offset_min_us,
            timing.clock_offset_max_us,
            sensor_identity,
        )
        drift_ppm = cls._bounded_int(
            "clock-drift",
            timing.clock_drift_min_ppm,
            timing.clock_drift_max_ppm,
            sensor_identity,
        )
        day_start = canonical_time.replace(hour=0, minute=0, second=0, microsecond=0)
        drift_us = int((canonical_time - day_start).total_seconds() * drift_ppm)
        route_delay_us = cls._bounded_int(
            "route-delay",
            timing.route_delay_min_us,
            timing.route_delay_max_us,
            sensor_identity,
            path_role,
        )
        clock_wander_us = cls._clock_wander_us(
            canonical_time,
            timing.event_jitter_min_us,
            timing.event_jitter_max_us,
            sensor_identity,
        )
        return canonical_time + timedelta(
            microseconds=offset_us + drift_us + route_delay_us + clock_wander_us
        )

    @classmethod
    def _clock_wander_us(
        cls,
        canonical_time: datetime,
        minimum: int,
        maximum: int,
        sensor_identity: str,
    ) -> int:
        """Return slowly varying sensor clock noise, never per-flow timestamp jitter."""

        if maximum <= minimum:
            return minimum
        bucket_seconds = 300
        day_start = canonical_time.replace(hour=0, minute=0, second=0, microsecond=0)
        seconds_since_day_start = (canonical_time - day_start).total_seconds()
        bucket = int(seconds_since_day_start // bucket_seconds)
        fraction = (seconds_since_day_start % bucket_seconds) / bucket_seconds
        day_key = day_start.date().isoformat()
        current = cls._bounded_int(
            "clock-wander",
            minimum,
            maximum,
            sensor_identity,
            day_key,
            str(bucket),
        )
        following = cls._bounded_int(
            "clock-wander",
            minimum,
            maximum,
            sensor_identity,
            day_key,
            str(bucket + 1),
        )
        return round(current + ((following - current) * fraction))

    @staticmethod
    def _bounded_int(label: str, minimum: int, maximum: int, *parts: str) -> int:
        if maximum <= minimum:
            return minimum
        seed = _stable_seed(":".join((label, *parts)))
        return minimum + (seed % (maximum - minimum + 1))

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
