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

"""Ground truth documentation generator for attack scenarios."""

from __future__ import annotations

import hashlib
import html
import ipaddress
import logging
from datetime import UTC, datetime
from pathlib import Path

from evidenceforge.events.ground_truth import (
    GROUND_TRUTH_SCHEMA_VERSION,
    GroundTruthDocument,
    GroundTruthEvent,
    write_ground_truth_document,
)
from evidenceforge.models.scenario import Scenario
from evidenceforge.utils.paths import safe_write_text
from evidenceforge.utils.time import resolve_time_window

logger = logging.getLogger(__name__)

_EVENT_BASE_KEYS = {
    "time",
    "actor",
    "system",
    "activity",
    "type",
    "storyline_cluster_id",
    "explanation",
    "skipped_reason",
}


def _redact_secret(value: str) -> str:
    """Return a short, non-reversible preview of a (synthetic) secret value."""
    if not value:
        return "(empty)"
    if len(value) <= 8:
        return value[:2] + "***"
    return f"{value[:4]}…{value[-2:]} ({len(value)} chars)"


def _serialize_attr_value(value):
    """Convert runtime values into stable JSON-serializable ground-truth fields."""
    if value is None or isinstance(value, (bool, int, float, str)):
        return value
    if isinstance(value, Path):
        return str(value)
    if isinstance(value, datetime):
        timestamp = value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)
        return timestamp.strftime("%Y-%m-%dT%H:%M:%SZ")
    if isinstance(value, dict):
        return {str(key): _serialize_attr_value(val) for key, val in value.items()}
    if isinstance(value, (list, tuple)):
        return [_serialize_attr_value(item) for item in value]
    if isinstance(value, set):
        return sorted(_serialize_attr_value(item) for item in value)
    return str(value)


class GroundTruthGenerator:
    """Builds canonical ground truth JSON and renders Markdown from it."""

    def __init__(
        self,
        scenario: Scenario,
        malicious_events: list[dict],
        red_herring_events: list[dict] | None = None,
        source_evidence_status: dict[str, dict[str, dict[str, int]]] | None = None,
    ):
        self.scenario = scenario
        self.malicious_events = malicious_events
        self.red_herring_events = red_herring_events or []
        self.source_evidence_status = source_evidence_status or {}

    def build_document(self) -> GroundTruthDocument:
        """Build the canonical machine-readable ground-truth document."""
        generated_at = self.scenario.time_window.end or self.scenario.time_window.start
        generated_at = (
            generated_at.replace(tzinfo=UTC) if generated_at.tzinfo is None else generated_at
        )
        generated_at = generated_at.replace(microsecond=0)
        document = GroundTruthDocument.model_validate(
            {
                "schema_version": GROUND_TRUTH_SCHEMA_VERSION,
                "scenario_name": self.scenario.name,
                "scenario_description": self.scenario.description,
                "generated_at": generated_at,
                "observation_profile": self.scenario.observation_profile,
                "collection_window": self._collection_window(),
                "source_evidence_status": self._sorted_source_evidence_status(),
                "storyline_steps": self._build_storyline_steps(),
                "red_herring_steps": self._build_red_herring_steps(),
                "events": self._build_event_records(),
            }
        )
        return document

    def write_json(
        self,
        output_path: Path,
        document: GroundTruthDocument | None = None,
    ) -> GroundTruthDocument:
        """Write the canonical machine-readable ground-truth document."""
        doc = document or self.build_document()
        write_ground_truth_document(output_path, doc)
        logger.info("Canonical ground truth written: %s", output_path)
        return doc

    def generate(
        self,
        output_path: Path,
        document: GroundTruthDocument | None = None,
    ) -> GroundTruthDocument:
        """Generate GROUND_TRUTH.md from the canonical document."""
        doc = document or self.build_document()
        logger.info("Generating ground truth documentation: %s", output_path)

        content = []
        content.append(f"# Ground Truth: {doc.scenario_name}\n")
        content.append(f"**Scenario:** {doc.scenario_description}\n")
        content.append(
            f"**Generated:** {doc.generated_at.astimezone(UTC).strftime('%Y-%m-%d %H:%M:%S UTC')}\n"
        )

        content.append("\n## Attack Summary\n")
        content.append(self._create_narrative(doc))

        content.append("\n## Timeline\n")
        content.append(self._create_timeline(doc))

        if self._include_source_evidence_status(doc):
            content.append("\n## Source Evidence Status\n")
            content.append(self._create_source_evidence_status_section(doc))

        content.append("\n## Indicators of Compromise (IOCs)\n")
        content.append(self._format_iocs(self._extract_iocs(doc)))

        if doc.red_herring_steps:
            content.append("\n## Red Herrings\n")
            content.append(
                "The following events appear suspicious but are benign. "
                "They are included to make the dataset more realistic.\n"
            )
            content.append(self._create_red_herring_section(doc))

        safe_write_text(output_path, "\n".join(content))
        logger.info("Ground truth documentation written: %s", output_path)
        return doc

    def _build_storyline_steps(self) -> list[dict]:
        if not (self.scenario.storyline or []):
            return [
                {
                    "storyline_id": event.get("storyline_cluster_id") or f"event-{index}",
                    "index": index,
                    "actor": event["actor"],
                    "system": event["system"],
                    "activity": event.get("activity", ""),
                    "ground_truth_section": "storyline",
                    "event_types": [event.get("type", "raw")],
                }
                for index, event in enumerate(self.malicious_events)
                if {"actor", "system"} <= set(event)
            ]
        return [
            {
                "storyline_id": event.id,
                "index": index,
                "actor": event.actor,
                "system": event.system,
                "activity": event.activity,
                "ground_truth_section": "storyline",
                "event_types": sorted({spec.type for spec in event.events}),
            }
            for index, event in enumerate(self.scenario.storyline or [])
        ]

    def _build_red_herring_steps(self) -> list[dict]:
        if not (self.scenario.red_herrings or []):
            return [
                {
                    "storyline_id": event.get("storyline_cluster_id") or f"red-herring-{index}",
                    "index": index,
                    "actor": event["actor"],
                    "system": event["system"],
                    "activity": event.get("activity", ""),
                    "ground_truth_section": "red_herring",
                    "event_types": [event.get("type", "process")],
                    "explanation": event.get("explanation"),
                }
                for index, event in enumerate(self.red_herring_events)
                if {"actor", "system"} <= set(event)
            ]
        return [
            {
                "storyline_id": event.id,
                "index": index,
                "actor": event.actor,
                "system": event.system,
                "activity": event.activity,
                "ground_truth_section": "red_herring",
                "event_types": sorted({spec.type for spec in event.events}),
                "explanation": event.explanation,
            }
            for index, event in enumerate(self.scenario.red_herrings or [])
        ]

    def _build_event_records(self) -> list[dict]:
        records: list[dict] = []
        for section, events in (
            ("storyline", self.malicious_events),
            ("red_herring", self.red_herring_events),
        ):
            for event in events:
                records.append(self._build_event_record(event, section=section))

        records.sort(
            key=lambda record: (
                record.get("storyline_id") or "",
                record["time"],
                record["kind"],
                record["ground_truth_section"],
            )
        )

        seen: dict[str, int] = {}
        for record in records:
            sid = record["storyline_id"] or ""
            n = seen.get(sid, 0)
            seen[sid] = n + 1
            record["record_id"] = f"{sid}#{n}"
        return records

    def _build_event_record(self, event: dict, *, section: str) -> dict:
        ts = event["time"]
        ts = ts.replace(tzinfo=UTC) if ts.tzinfo is None else ts
        ts = ts.astimezone(UTC).replace(microsecond=0)
        attributes = {
            key: _serialize_attr_value(value)
            for key, value in event.items()
            if key not in _EVENT_BASE_KEYS
        }
        if event.get("type") in ("spillage", "adversarial_payload"):
            if event.get("skipped_reason"):
                for field in ("value", "value_sha256", "rendered_value", "rendered_sha256"):
                    attributes.pop(field, None)
            else:
                value = str(attributes.get("value") or "")
                rendered = str(attributes.get("rendered_value") or value)
                attributes["value_sha256"] = hashlib.sha256(value.encode("utf-8")).hexdigest()
                attributes["rendered_sha256"] = hashlib.sha256(rendered.encode("utf-8")).hexdigest()
        record = {
            "record_id": "",
            "kind": event["type"],
            "storyline_id": event.get("storyline_cluster_id"),
            "time": ts,
            "actor": event["actor"],
            "system": event["system"],
            "activity": event.get("activity", ""),
            "ground_truth_section": section,
            "emitted": not bool(event.get("skipped_reason")),
            "attributes": attributes,
        }
        if event.get("skipped_reason"):
            record["skipped_reason"] = event["skipped_reason"]
        if section == "red_herring" and event.get("explanation"):
            record["explanation"] = event["explanation"]
        return record

    def _collection_window(self) -> dict[str, str | None]:
        start, end = resolve_time_window(self.scenario.time_window)
        start = start.replace(tzinfo=UTC) if start.tzinfo is None else start.astimezone(UTC)
        end = (
            end.replace(tzinfo=UTC)
            if end and end.tzinfo is None
            else (end.astimezone(UTC) if end else None)
        )
        return {
            "start": start.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "end": end.strftime("%Y-%m-%dT%H:%M:%SZ") if end else None,
        }

    def _sorted_source_evidence_status(self) -> dict[str, dict[str, dict[str, int]]]:
        return {
            cluster_id: {
                source: {status: count for status, count in sorted(counts.items())}
                for source, counts in sorted(source_status.items())
            }
            for cluster_id, source_status in sorted(self.source_evidence_status.items())
        }

    def _storyline_event_dicts(self, document: GroundTruthDocument) -> list[dict]:
        return [
            self._flatten_event(event)
            for event in document.events
            if event.ground_truth_section == "storyline"
        ]

    def _red_herring_event_dicts(self, document: GroundTruthDocument) -> list[dict]:
        return [
            self._flatten_event(event)
            for event in document.events
            if event.ground_truth_section == "red_herring"
        ]

    @staticmethod
    def _flatten_event(event: GroundTruthEvent) -> dict:
        payload = event.model_dump(mode="python", exclude_none=True)
        attributes = payload.pop("attributes", {})
        payload["type"] = payload.pop("kind")
        payload.update(attributes)
        return payload

    def _create_narrative(self, document: GroundTruthDocument | None = None) -> str:
        if document is None:
            if not self.scenario.storyline:
                return "*No malicious activities in this scenario.*\n"
            narrative = ["This scenario simulates the following attack sequence:\n"]
            for index, event in enumerate(self.scenario.storyline, 1):
                narrative.append(
                    f"{index}. **{event.actor}** on **{event.system}**: {event.activity}"
                )
            return "\n".join(narrative) + "\n"
        if not document.storyline_steps:
            return "*No malicious activities in this scenario.*\n"

        narrative = ["This scenario simulates the following attack sequence:\n"]
        for index, step in enumerate(document.storyline_steps, 1):
            narrative.append(f"{index}. **{step.actor}** on **{step.system}**: {step.activity}")
        return "\n".join(narrative) + "\n"

    def _create_timeline(self, document: GroundTruthDocument | None = None) -> str:
        events = (
            self.malicious_events if document is None else self._storyline_event_dicts(document)
        )
        if not events:
            return "*No malicious events were generated.*\n"

        sorted_events = sorted(events, key=lambda event: event["time"])
        lines = [
            "| Timestamp | Actor | System | Event Type | Details |",
            "|-----------|-------|--------|------------|---------|",
        ]
        for event in sorted_events:
            timestamp = event["time"].strftime("%Y-%m-%d %H:%M:%S UTC")
            lines.append(
                f"| {timestamp} | {event['actor']} | {event['system']} | "
                f"{event['type'].title()} | {self._format_event_details(event)} |"
            )
        return "\n".join(lines) + "\n"

    def _format_event_details(self, event: dict) -> str:
        event_type = event["type"]
        skipped_reason = event.get("skipped_reason")
        if skipped_reason:
            reason = str(skipped_reason).replace("_", " ")
            target = event.get("target_process")
            if target:
                return f"Skipped ({reason}); no evidence emitted for target {target}"
            return f"Skipped ({reason}); no evidence emitted"

        if event_type == "logon":
            return (
                f"Network logon from {event.get('source_ip', 'N/A')} "
                f"(LogonID: {event.get('logon_id', 'N/A')})"
            )
        if event_type == "process":
            cmd = event.get("command_line", "")
            if len(cmd) > 50:
                cmd = cmd[:47] + "..."
            return (
                f"Process: {event.get('process_name', 'N/A')} "
                f"(PID: {event.get('pid', 'N/A')}) - `{cmd}`"
            )
        if event_type == "connection":
            return (
                f"Connection to {event.get('dst_ip', 'N/A')}:{event.get('dst_port', 'N/A')} "
                f"(UID: {event.get('uid', 'N/A')})"
            )
        if event_type == "rdp_session":
            return (
                f"RDP session to {event.get('dst_ip', 'N/A')}:3389 (UID: {event.get('uid', 'N/A')})"
            )
        if event_type == "ssh_session":
            return (
                f"SSH session to {event.get('dst_ip', 'N/A')}:22 (UID: {event.get('uid', 'N/A')})"
            )
        if event_type == "service_installed":
            return f"Service installed: {event.get('service_name', 'N/A')} ({event.get('service_file_name', 'N/A')})"
        if event_type == "scheduled_task_created":
            return f"Scheduled task created: {event.get('task_name', 'N/A')}"
        if event_type == "create_remote_thread":
            return f"Remote thread injection into {event.get('target_process', 'N/A')}"
        if event_type in ("account_created", "account_deleted"):
            action = "created" if event_type == "account_created" else "deleted"
            return f"Account {action}: {event.get('target_username', 'N/A')}"
        if event_type == "group_member_added":
            return (
                f"Added {event.get('member_name', 'N/A')} to group {event.get('group_name', 'N/A')}"
            )
        if event_type == "port_scan":
            return (
                f"Port scan: {event.get('target_count', 'N/A')} targets, ports {event.get('ports', [])}, "
                f"{event.get('total_connections', 'N/A')} denied connections + ASA threat detection alert (733100)"
            )
        if event_type == "beacon":
            label = "Denied beacon" if event.get("action", "allow") == "deny" else "Beacon"
            return (
                f"{label} to {event.get('dst_ip', 'N/A')}:{event.get('dst_port', 'N/A')} "
                f"({event.get('attempt_count', 'N/A')} attempts, {event.get('termination', 'N/A')})"
            )
        if event_type == "dns_query":
            return (
                f"DNS query: {event.get('query', 'N/A')} "
                f"({event.get('qtype', 'A')}, {event.get('rcode', 'NOERROR')})"
            )
        if event_type == "email_message":
            recipients = event.get("recipients", [])
            shown = ", ".join(recipients[:3])
            if len(recipients) > 3:
                shown += f", +{len(recipients) - 3} more"
            artifact = event.get("artifact_path") or "metadata-only"
            return (
                f"Email {event.get('outcome', 'delivered')}: "
                f"{event.get('sender', 'N/A')} -> {shown or 'N/A'}; "
                f"subject '{event.get('subject', 'N/A')}' ({artifact})"
            )
        if event_type == "email_read":
            return (
                f"Mailbox read: {event.get('mailbox', 'N/A')} via "
                f"{event.get('protocol', 'N/A')} on {event.get('server', 'N/A')} "
                f"(UID: {event.get('uid', 'N/A')})"
            )
        if event_type == "web_scan":
            return (
                f"Web scan ({event.get('preset', 'custom')}) against "
                f"{event.get('dst_ip', 'N/A')}:{event.get('dst_port', 'N/A')} "
                f"({event.get('request_count', 'N/A')} requests)"
            )
        if event_type == "credential_spray":
            result = (
                f"Credential {event.get('pattern', 'spray')}: {event.get('attempt_count', 'N/A')} "
                f"attempts against {len(event.get('target_accounts', []))} accounts"
            )
            if event.get("success_account"):
                result += (
                    f" (success: {event['success_account']} at attempt "
                    f"{event.get('success_at_attempt', '?')})"
                )
            return result
        if event_type == "dga_queries":
            sample = event.get("domain_sample", [])
            return (
                f"DGA queries: {event.get('total_queries', 'N/A')} total "
                f"({event.get('nxdomain_count', 'N/A')} NXDOMAIN, TLD: {event.get('tld', '.com')}, "
                f"sample: {sample[:3]})"
            )
        if event_type == "dns_tunnel":
            return (
                f"DNS tunnel via {event.get('base_domain', 'N/A')} "
                f"({event.get('encoding', 'hex')}, {event.get('total_queries', 'N/A')} queries, "
                f"{event.get('bytes_exfiltrated', 0)} bytes exfiltrated)"
            )
        if event_type == "explicit_credentials":
            return (
                f"Explicit credentials: RunAs {event.get('target_username', 'N/A')} "
                f"on {event.get('target_server', 'N/A')}"
            )
        if event_type in ("workstation_lock", "workstation_unlock"):
            action = "Locked" if event_type == "workstation_lock" else "Unlocked"
            return f"Workstation {action}"
        if event_type == "spillage":
            value = event.get("value", "")
            digest = hashlib.sha256(value.encode("utf-8")).hexdigest() if value else ""
            return (
                f"Spillage ({event.get('family') or 'literal'}) to {event.get('surface', 'N/A')}: "
                f"{_redact_secret(value)} (sha256:{digest[:12]})"
            )
        if event_type == "adversarial_payload":
            surface = event.get("surface", "N/A")
            family = event.get("family") or "literal"
            encoding = event.get("encoding", "raw")
            value = event.get("value", "")
            digest = hashlib.sha256(value.encode("utf-8")).hexdigest() if value else ""
            # An adversarial payload is an inert, marker-bearing test artifact (NOT a
            # secret), so show the FULL value — an analyst must recognize it to score a
            # detection. Escape control bytes, Markdown table delimiters, and raw HTML so the
            # payload cannot corrupt/inject the table or execute in Markdown renderers;
            # truncate only a very long (oversized) one.
            shown = html.escape(
                value.encode("unicode_escape").decode("ascii", "replace").replace("|", "\\|"),
                quote=True,
            )
            if len(shown) > 200:
                shown = shown[:200] + f"…(+{len(shown) - 200} more chars)"
            # Surface the on-wire IDS alert a network sensor should fire on (compact
            # correlation metadata; the full weakness_class / pass-criterion live in the
            # canonical JSON). Present only for cleartext-http, signature-mapped families.
            ids_alert = event.get("ids_alert") or {}
            ids_suffix = ""
            if ids_alert:
                msg = html.escape(str(ids_alert.get("message", "")).replace("|", "\\|"), quote=True)
                ids_suffix = f" [IDS {ids_alert.get('sid')}: {msg}]"
            return (
                f"Adversarial payload ({family}) to {surface} [{encoding}]: "
                f"{shown} (sha256:{digest[:12]}){ids_suffix}"
            )
        return event.get("activity", "N/A")

    def _include_source_evidence_status(self, document: GroundTruthDocument | None = None) -> bool:
        source_evidence_status = (
            self.source_evidence_status if document is None else document.source_evidence_status
        )
        observation_profile = (
            self.scenario.observation_profile if document is None else document.observation_profile
        )
        if not source_evidence_status:
            return False
        if observation_profile != "complete":
            return True
        for source_status in source_evidence_status.values():
            for counts in source_status.values():
                if any(status != "visible" and count for status, count in counts.items()):
                    return True
        return False

    def _create_source_evidence_status_section(
        self, document: GroundTruthDocument | None = None
    ) -> str:
        source_evidence_status = (
            self.source_evidence_status if document is None else document.source_evidence_status
        )
        lines = [
            "Canonical ground truth remains authoritative. Source rows may be "
            "`visible`, `delayed`, `dropped`, `filtered`, or `out_of_window` depending on "
            "the selected observation profile and sensor placement.\n",
            "| Storyline ID | Source | Status Counts |",
            "|--------------|--------|---------------|",
        ]
        for cluster_id, source_status in sorted(source_evidence_status.items()):
            for source, counts in sorted(source_status.items()):
                rendered_counts = ", ".join(
                    f"{status}: {count}" for status, count in sorted(counts.items()) if count
                )
                if rendered_counts:
                    lines.append(f"| {cluster_id} | {source} | {rendered_counts} |")
        return "\n".join(lines) + "\n"

    def _extract_iocs(self, document: GroundTruthDocument | None = None) -> dict[str, set]:
        iocs = {"network": set(), "processes": set(), "users": set(), "files": set()}
        events = (
            self.malicious_events if document is None else self._storyline_event_dicts(document)
        )
        for event in events:
            if event.get("skipped_reason"):
                continue
            iocs["users"].add(event["actor"])
            if event["type"] == "logon":
                if "source_ip" in event:
                    iocs["network"].add(f"{event['source_ip']} (Attacker IP)")
            elif event["type"] == "process":
                if "process_name" in event:
                    iocs["processes"].add(event["process_name"])
                if "command_line" in event:
                    iocs["processes"].add(f"`{event['command_line']}`")
                if "output_file" in event:
                    iocs["files"].add(event["output_file"])
            elif event["type"] == "connection":
                if "dst_ip" in event:
                    dst_ip = event["dst_ip"]
                    dst_port = event.get("dst_port", "")
                    try:
                        is_internal = ipaddress.ip_address(dst_ip).is_private
                    except (ValueError, TypeError):
                        is_internal = False
                    label = "Internal Server" if is_internal else "C2 Server"
                    iocs["network"].add(
                        f"{dst_ip}:{dst_port} ({label})" if dst_port else f"{dst_ip} ({label})"
                    )
                    uid = event.get("uid", "")
                if uid and uid != "(filtered by sensor placement)":
                    iocs["network"].add(f"Zeek UID: {uid}")
            elif event["type"] == "email_message":
                if event.get("message_id"):
                    iocs["network"].add(f"Message-ID: {event['message_id']}")
                if event.get("artifact_path"):
                    iocs["files"].add(event["artifact_path"])
                for uid in event.get("smtp_uids", []) or []:
                    if uid and uid != "(filtered by sensor placement)":
                        iocs["network"].add(f"SMTP Zeek UID: {uid}")
            elif event["type"] in ("rdp_session", "ssh_session"):
                dst_ip = event.get("dst_ip", "")
                dst_port = event.get("dst_port", "")
                if dst_ip:
                    iocs["network"].add(f"{dst_ip}:{dst_port} (Lateral Movement)")
                uid = event.get("uid", "")
                if uid and uid != "(filtered by sensor placement)":
                    iocs["network"].add(f"Zeek UID: {uid}")
            elif event["type"] == "service_installed":
                if "service_file_name" in event:
                    iocs["files"].add(event["service_file_name"])
                if "service_name" in event:
                    iocs["processes"].add(f"Service: {event['service_name']}")
            elif event["type"] == "scheduled_task_created":
                if "task_name" in event:
                    iocs["processes"].add(f"Scheduled Task: {event['task_name']}")
                if "task_content" in event:
                    import re

                    cmd_match = re.search(r"<Command>(.+?)</Command>", event["task_content"])
                    if cmd_match:
                        iocs["files"].add(cmd_match.group(1))
            elif event["type"] == "create_remote_thread":
                if "target_process" in event:
                    iocs["processes"].add(f"Injection Target: {event['target_process']}")
            elif event["type"] in ("account_created", "account_deleted"):
                if "target_username" in event:
                    iocs["users"].add(event["target_username"])
            elif event["type"] == "group_member_added":
                if "member_name" in event:
                    iocs["users"].add(event["member_name"])
                if "group_name" in event:
                    iocs["users"].add(f"Group: {event['group_name']}")
            elif event["type"] == "port_scan":
                for port in event.get("ports", []):
                    iocs["network"].add(f"Port {port} (scan target)")
            elif event["type"] == "beacon":
                dst_ip = event.get("dst_ip", "")
                dst_port = event.get("dst_port", "")
                label = "Denied Beacon" if event.get("action", "allow") == "deny" else "Beacon"
                if dst_ip:
                    iocs["network"].add(f"{dst_ip}:{dst_port} ({label} Target)")
            elif event["type"] == "dns_query":
                if event.get("query"):
                    iocs["network"].add(f"{event['query']} (Malicious DNS Query)")
            elif event["type"] == "web_scan":
                if event.get("dst_ip"):
                    iocs["network"].add(
                        f"{event['dst_ip']}:{event.get('dst_port', '')} (Web Scan Target)"
                    )
            elif event["type"] == "credential_spray":
                for account in event.get("target_accounts", []):
                    iocs["users"].add(f"{account} (Spray Target)")
            elif event["type"] == "dga_queries":
                for domain in event.get("domain_sample", []):
                    iocs["network"].add(f"{domain} (DGA Domain)")
            elif event["type"] == "dns_tunnel":
                if event.get("base_domain"):
                    iocs["network"].add(f"{event['base_domain']} (DNS Tunnel Endpoint)")
            elif event["type"] == "explicit_credentials":
                if event.get("target_username"):
                    iocs["users"].add(f"{event['target_username']} (Explicit Credential Target)")
        return {category: values for category, values in iocs.items() if values}

    def _create_red_herring_section(self, document: GroundTruthDocument | None = None) -> str:
        events = (
            self.red_herring_events if document is None else self._red_herring_event_dicts(document)
        )
        sorted_events = sorted(events, key=lambda event: event["time"])
        lines = [
            "| Timestamp | Actor | System | Activity | Why It's Benign |",
            "|-----------|-------|--------|----------|-----------------|",
        ]
        for event in sorted_events:
            timestamp = event["time"].strftime("%Y-%m-%d %H:%M:%S UTC")
            lines.append(
                f"| {timestamp} | {event['actor']} | {event['system']} | {event.get('activity', 'N/A')} | "
                f"{event.get('explanation', 'N/A')} |"
            )
        return "\n".join(lines) + "\n"

    def _format_iocs(self, iocs: dict[str, set]) -> str:
        if not iocs or not any(values for values in iocs.values()):
            return "*No IOCs extracted.*\n"

        sections: list[str] = []
        if iocs.get("network"):
            sections.append("### Network IOCs\n")
            sections.extend(f"- {ioc}" for ioc in sorted(iocs["network"]))
            sections.append("")
        if iocs.get("processes"):
            sections.append("### Process IOCs\n")
            sections.extend(f"- {ioc}" for ioc in sorted(iocs["processes"]))
            sections.append("")
        if iocs.get("users"):
            sections.append("### User IOCs\n")
            sections.extend(f"- {ioc} (compromised account)" for ioc in sorted(iocs["users"]))
            sections.append("")
        if iocs.get("files"):
            sections.append("### File IOCs\n")
            sections.extend(f"- {ioc}" for ioc in sorted(iocs["files"]))
            sections.append("")
        return "\n".join(sections)
