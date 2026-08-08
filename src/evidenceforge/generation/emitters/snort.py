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

"""Snort/Suricata alert emitter with deferred sensor-local filtering."""

import json
import os
import sqlite3
import tempfile
from dataclasses import asdict
from datetime import UTC, datetime
from pathlib import Path
from threading import Lock
from typing import Any

from evidenceforge.events.base import CanonicalOccurrence
from evidenceforge.events.contexts import (
    IdsAlertPolicyContext,
    IdsDetectionFilterContext,
    IdsEventFilterContext,
)
from evidenceforge.events.ids_evaluation import new_ids_digest, update_ids_digest
from evidenceforge.generation.emitters.zeek_base import SensorMultiplexEmitter
from evidenceforge.generation.ids_filtering import IdsAlertCandidate, IdsAlertFilterEngine


class SnortEmitter(SensorMultiplexEmitter):
    """Emitter for Snort/Suricata fast alert format.

    Per-sensor directory routing: each IDS sensor gets its own alert file.

    Handles canonical occurrences with IdsAlertPlan entries (fan-out from connection events
    through IDS sensors) and raw dict events from baseline false-positive
    alert generation.
    """

    _log_filename = "snort_alert.log"
    _flat_filename = "snort_alert.log"
    _sort_before_flush: bool = True
    _include_sensor_identity: bool = True

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self._spool_lock = Lock()
        self._spool_connection: sqlite3.Connection | None = None
        self._spool_path: Path | None = None
        self._ids_alert_summary: dict[str, dict[int, dict[str, Any]]] = {}
        self._ids_evaluation_summary: dict[str, dict[str, dict[str, Any]]] = {}

    def can_handle(self, event: CanonicalOccurrence) -> bool:
        """Handle physical canonical transports that carry an IdsAlertPlan."""
        return (
            event.network is not None
            and bool(event.ids_alerts)
            and not event.network.application_layer_only
        )

    def emit(self, event: CanonicalOccurrence) -> None:
        """Render IdsAlertPlan to Snort fast alert format."""
        net = event.network
        for ids in event.ids_alerts:
            event_data = {
                "timestamp": event.timestamp,
                "gid": ids.gid,
                "sid": ids.sid,
                "rev": ids.rev,
                "message": ids.message,
                "classification": ids.classification,
                "priority": ids.priority,
                "protocol": (net.protocol or "TCP").upper() if net else "TCP",
                "src_ip": net.src_ip if net else "",
                "src_port": net.src_port if net else 0,
                "dst_ip": net.dst_ip if net else "",
                "dst_port": net.dst_port if net else 0,
                "_ids_candidate": True,
                "_ids_policy": asdict(ids.policy) if ids.policy is not None else None,
                "_cluster_id": event.storyline_cluster_id or event.occurrence_id,
                "_occurrence_id": event.occurrence_id,
                "_source_observation_status": getattr(
                    event, "_source_observation_status", "visible"
                ),
                "_ids_origin": ids.origin,
                **self._sensor_metadata(event, "snort_alert"),
            }
            self.emit_event(event_data)

    def _render_event(self, event_data: dict[str, Any]) -> str | None:
        """Render Snort/Suricata alert to fast alert format.

        Returns None if the event lacks required IDS alert fields (sid, message),
        which means it's a plain connection event that should not generate an
        IDS alert. The caller must handle None returns.
        """
        if event_data.pop("_ids_candidate", False):
            self._spool_candidate(event_data)
            return None
        rendered = self._render_alert(event_data)
        if rendered is not None:
            sensor = str(event_data.get("_sensor_identity", "__direct__"))
            self._record_evaluation_emission(
                sensor,
                event_data,
                origin=str(event_data.get("_ids_origin", "raw")),
                observation_status=str(event_data.get("_source_observation_status", "visible")),
                count_candidate=True,
            )
        return rendered

    def emit_raw(self, event_data: dict[str, Any]) -> None:
        """Render an unchanged raw Snort entry while recording its authorized origin."""

        payload = dict(event_data)
        payload["_ids_origin"] = "raw"
        super().emit_raw(payload)

    def _render_alert(self, event_data: dict[str, Any]) -> str | None:
        """Render one already-admitted alert or an unchanged raw Snort entry."""
        if not event_data.get("sid") and not event_data.get("message"):
            return None

        proto = event_data.get("protocol") or event_data.get("proto")

        context = {
            "timestamp": event_data.get("timestamp") or event_data.get("ts"),
            "gid": event_data.get("gid", 1),
            "sid": event_data.get("sid"),
            "rev": event_data.get("rev", 1),
            "classification": event_data.get("classification"),
            "priority": event_data.get("priority"),
            "protocol": proto.upper() if proto else None,
            "src_ip": event_data.get("src_ip") or event_data.get("id.orig_h"),
            "src_port": event_data.get("src_port") or event_data.get("id.orig_p"),
            "dst_ip": event_data.get("dst_ip") or event_data.get("id.resp_h"),
            "dst_port": event_data.get("dst_port") or event_data.get("id.resp_p"),
            "message": event_data.get("message"),
        }

        rendered = self._template.render(**context)
        return rendered.strip()

    def _open_spool(self) -> sqlite3.Connection:
        """Create the bounded-memory, disk-backed candidate store lazily."""
        if self._spool_connection is not None:
            return self._spool_connection
        descriptor, raw_path = tempfile.mkstemp(prefix="evidenceforge-ids-", suffix=".sqlite3")
        os.close(descriptor)
        self._spool_path = Path(raw_path)
        connection = sqlite3.connect(raw_path, check_same_thread=False)
        connection.execute(
            """CREATE TABLE candidates (
                sequence INTEGER PRIMARY KEY AUTOINCREMENT,
                sensor TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                gid INTEGER NOT NULL,
                sid INTEGER NOT NULL,
                payload TEXT NOT NULL,
                policy TEXT,
                cluster_id TEXT NOT NULL,
                occurrence_id TEXT NOT NULL,
                observation_status TEXT NOT NULL,
                origin TEXT NOT NULL
            )"""
        )
        self._spool_connection = connection
        return connection

    def _spool_candidate(self, event_data: dict[str, Any]) -> None:
        """Persist one post-observation candidate without retaining it in memory."""
        payload = {
            key: value.isoformat() if isinstance(value, datetime) else value
            for key, value in event_data.items()
            if not key.startswith("_")
        }
        timestamp = event_data.get("timestamp")
        if not isinstance(timestamp, datetime):
            timestamp = datetime.fromisoformat(str(timestamp).replace("Z", "+00:00"))
        timestamp = (
            timestamp.replace(tzinfo=UTC) if timestamp.tzinfo is None else timestamp.astimezone(UTC)
        )
        with self._spool_lock:
            connection = self._open_spool()
            connection.execute(
                """INSERT INTO candidates
                (sensor, timestamp, gid, sid, payload, policy, cluster_id, occurrence_id,
                 observation_status, origin)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    str(event_data.get("_sensor_identity", "__direct__")),
                    timestamp.isoformat(),
                    int(event_data["gid"]),
                    int(event_data["sid"]),
                    json.dumps(payload, sort_keys=True),
                    json.dumps(event_data.get("_ids_policy"), sort_keys=True),
                    str(event_data.get("_cluster_id", "")),
                    str(event_data.get("_occurrence_id", "")),
                    str(event_data.get("_source_observation_status", "visible")),
                    str(event_data.get("_ids_origin", "built_in")),
                ),
            )

    @staticmethod
    def _policy_from_json(value: str) -> IdsAlertPolicyContext | None:
        data = json.loads(value)
        if data is None:
            return None
        detection = data.get("detection_filter")
        event_filter = data.get("event_filter")
        return IdsAlertPolicyContext(
            detection_filter=(
                IdsDetectionFilterContext(**detection) if detection is not None else None
            ),
            event_filter=(
                IdsEventFilterContext(**event_filter) if event_filter is not None else None
            ),
        )

    @staticmethod
    def _summary_policy(policy: IdsAlertPolicyContext | None) -> str | dict[str, Any]:
        return "every" if policy is None else asdict(policy)

    def _finalize_candidates(self) -> None:
        """Sort and filter all candidates, then write admitted alerts."""
        connection = self._spool_connection
        if connection is None:
            return
        connection.commit()
        filter_engine = IdsAlertFilterEngine()
        rows = connection.execute(
            """SELECT sensor, timestamp, gid, sid, payload, policy, cluster_id,
            observation_status, origin
            FROM candidates
            ORDER BY timestamp, sensor, occurrence_id, gid, sid, sequence"""
        )
        for (
            sensor,
            timestamp,
            gid,
            sid,
            payload_json,
            policy_json,
            cluster_id,
            observation_status,
            origin,
        ) in rows:
            payload = json.loads(payload_json)
            payload["timestamp"] = datetime.fromisoformat(timestamp)
            policy = self._policy_from_json(policy_json)
            candidate = IdsAlertCandidate(
                sensor=sensor,
                timestamp=payload["timestamp"],
                gid=gid,
                sid=sid,
                src_ip=payload.get("src_ip", ""),
                dst_ip=payload.get("dst_ip", ""),
                policy=policy,
            )
            sid_summary = self._ids_alert_summary.setdefault(cluster_id, {}).setdefault(
                sid,
                {
                    "sid": sid,
                    "effective_policy": self._summary_policy(policy),
                    "candidate": 0,
                    "emitted": 0,
                    "policy_filtered": 0,
                    "emitted_visible": 0,
                    "emitted_delayed": 0,
                },
            )
            sid_summary["candidate"] += 1
            evaluation = self._evaluation_signature(sensor, gid, sid)
            evaluation["candidate"] += 1
            if not filter_engine.admit(candidate):
                sid_summary["policy_filtered"] += 1
                evaluation["policy_filtered"] += 1
                continue
            rendered = self._render_alert(payload)
            if rendered is not None:
                self._get_writer("" if sensor == "__direct__" else sensor).write(rendered)
                sid_summary["emitted"] += 1
                status_key = (
                    "emitted_delayed" if observation_status == "delayed" else "emitted_visible"
                )
                sid_summary[status_key] += 1
                self._record_evaluation_emission(
                    sensor,
                    payload,
                    origin=origin,
                    observation_status=observation_status,
                    count_candidate=False,
                )

    def _evaluation_signature(self, sensor: str, gid: int, sid: int) -> dict[str, Any]:
        signatures = self._ids_evaluation_summary.setdefault(sensor, {})
        return signatures.setdefault(
            f"{gid}:{sid}",
            {
                "gid": gid,
                "sid": sid,
                "candidate": 0,
                "emitted": 0,
                "policy_filtered": 0,
                "emitted_visible": 0,
                "emitted_delayed": 0,
                "origins": {},
                "_digest": new_ids_digest(),
            },
        )

    def _record_evaluation_emission(
        self,
        sensor: str,
        payload: dict[str, Any],
        *,
        origin: str,
        observation_status: str,
        count_candidate: bool,
    ) -> None:
        summary = self._evaluation_signature(
            sensor, int(payload.get("gid", 1)), int(payload["sid"])
        )
        if count_candidate:
            summary["candidate"] += 1
        summary["emitted"] += 1
        status_key = "emitted_delayed" if observation_status == "delayed" else "emitted_visible"
        summary[status_key] += 1
        origins = summary["origins"]
        origins[origin] = origins.get(origin, 0) + 1
        update_ids_digest(summary["_digest"], sensor, payload)

    def flush(self) -> None:
        """Commit deferred candidates and flush already-rendered raw alerts."""
        with self._spool_lock:
            if self._spool_connection is not None:
                self._spool_connection.commit()
        super().flush()

    def close(self) -> None:
        """Drain, filter, render, and always remove the temporary candidate spool."""
        if self.threaded:
            self.stop_thread()
        try:
            with self._spool_lock:
                self._finalize_candidates()
            super().close()
        finally:
            with self._spool_lock:
                if self._spool_connection is not None:
                    self._spool_connection.close()
                    self._spool_connection = None
                if self._spool_path is not None:
                    self._spool_path.unlink(missing_ok=True)
                    self._spool_path = None

    @property
    def ids_alert_summary(self) -> dict[str, dict[int, dict[str, Any]]]:
        """Return per-storyline-event, per-SID candidate and filtering totals."""
        return self._ids_alert_summary

    @property
    def ids_evaluation_summary(self) -> dict[str, dict[str, dict[str, Any]]]:
        """Return bounded sensor/SID totals and expected rendered-alert digests."""

        return {
            sensor: {
                key: {
                    name: (value.hexdigest() if name == "_digest" else value)
                    for name, value in summary.items()
                    if name != "_digest"
                }
                | {"emitted_sha256": summary["_digest"].hexdigest()}
                for key, summary in signatures.items()
            }
            for sensor, signatures in self._ids_evaluation_summary.items()
        }
