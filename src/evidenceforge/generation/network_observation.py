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
from evidenceforge.utils.ids import _has_synthetic_marker
from evidenceforge.utils.rng import _stable_seed

if TYPE_CHECKING:
    from evidenceforge.events.base import SecurityEvent
    from evidenceforge.generation.network_visibility import NetworkVisibilityEngine


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

    def __init__(self, visibility_engine: NetworkVisibilityEngine | None) -> None:
        self.visibility_engine = visibility_engine

    def plan(
        self,
        event: SecurityEvent,
        visible_formats: set[str],
    ) -> tuple[NetworkSensorObservation, ...]:
        """Return deterministic observations for every visible network sensor."""

        network = event.network
        if network is None or network.transaction is None:
            return ()
        transaction = network.transaction
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
            tuple_view = self._tuple_view(event, sensor_identity)
            observed_start = self._observed_time(
                transaction.started_at,
                timing,
                sensor_identity,
                path_role,
                transaction.stable_id,
            )
            observed_close = (
                self._observed_time(
                    transaction.closed_at,
                    timing,
                    sensor_identity,
                    path_role,
                    transaction.stable_id,
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
                    local_orig=bool(
                        event._nat_swaps_by_sensor.get(sensor_identity, {}).get(
                            "local_orig",
                            network.local_orig,
                        )
                    ),
                    local_resp=bool(
                        event._nat_swaps_by_sensor.get(sensor_identity, {}).get(
                            "local_resp",
                            network.local_resp,
                        )
                    ),
                    observed_start_time=observed_start,
                    observed_close_time=observed_close,
                    traffic=self._observed_traffic(
                        transaction.traffic,
                        timing,
                        sensor_identity,
                        transaction.stable_id,
                    ),
                    visible_formats=frozenset(formats),
                    firewall_teardown_reason=firewall_reason,
                    firewall_teardown_time=firewall_teardown,
                )
            )
        return tuple(observations)

    @staticmethod
    def _firewall_teardown_plan(
        event: SecurityEvent,
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
        state = (
            network.transaction.conn_state
            if network.transaction is not None
            else network.conn_state
        )
        traffic = network.transaction.traffic if network.transaction is not None else None
        payload_bytes = (
            traffic.orig.payload_bytes + traffic.resp.payload_bytes
            if traffic is not None
            else max(0, network.orig_bytes or 0) + max(0, network.resp_bytes or 0)
        )
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
        event: SecurityEvent,
        visible_formats: set[str],
    ) -> dict[str, set[str]]:
        sensor_formats: dict[str, set[str]] = {}
        for format_name, sensor_identities in event._sensor_hostnames_by_format.items():
            if format_name not in visible_formats:
                continue
            for sensor_identity in sensor_identities:
                sensor_formats.setdefault(sensor_identity, set()).add(format_name)
        return sensor_formats

    @staticmethod
    def _tuple_view(event: SecurityEvent, sensor_identity: str) -> NetworkTuple:
        transaction = event.network.transaction
        swaps = event._nat_swaps_by_sensor.get(sensor_identity, {})
        return NetworkTuple(
            src_ip=str(swaps.get("src_ip", transaction.src_ip)),
            src_port=int(swaps.get("src_port", transaction.src_port)),
            dst_ip=str(swaps.get("dst_ip", transaction.dst_ip)),
            dst_port=int(swaps.get("dst_port", transaction.dst_port)),
            protocol=transaction.protocol,
        )

    @staticmethod
    def _canonical_file_ids(event: SecurityEvent) -> tuple[str, ...]:
        values: list[str] = []

        def add(candidate: object) -> None:
            if isinstance(candidate, str) and candidate and candidate not in values:
                values.append(candidate)

        if event.file_transfer is not None:
            add(event.file_transfer.fuid)
        for transfer in event.file_transfers:
            add(transfer.fuid)
        if event.ssl is not None:
            for value in event.ssl.cert_chain_fuids:
                add(value)
        if event.http is not None:
            for value in event.http.resp_fuids:
                add(value)
        if event.smtp is not None:
            for value in event.smtp.fuids:
                add(value)
        if event.x509 is not None:
            add(event.x509.fuid)
        for certificate in event.x509_chain:
            add(certificate.fuid)
        if event.ocsp is not None:
            add(event.ocsp.id)
        if event.pe is not None:
            add(event.pe.id)
        return tuple(values)

    @staticmethod
    def _canonical_connection_ids(event: SecurityEvent) -> tuple[str, ...]:
        values = [event.network.transaction.zeek_uid]
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
        transaction_id: str,
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
        jitter_us = cls._bounded_int(
            "event-jitter",
            timing.event_jitter_min_us,
            timing.event_jitter_max_us,
            sensor_identity,
            transaction_id,
        )
        return canonical_time + timedelta(
            microseconds=offset_us + drift_us + route_delay_us + jitter_us
        )

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
    ) -> NetworkTrafficLedger:
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
        orig, missed_orig = cls._lose_direction(canonical.orig, timing, rng)
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
