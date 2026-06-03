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

"""Ground truth documentation generator for attack scenarios.

This module generates GROUND_TRUTH.md files that document malicious activities,
timelines, and indicators of compromise (IOCs) for threat hunting training.
"""

import hashlib
import ipaddress
import json
import logging
from datetime import UTC
from pathlib import Path

from evidenceforge.models.scenario import Scenario
from evidenceforge.utils.paths import safe_write_text

GROUND_TRUTH_JSONL_FILENAME = "GROUND_TRUTH.jsonl"
GROUND_TRUTH_SCHEMA_VERSION = 1


def _redact_secret(value: str) -> str:
    """Return a short, non-reversible preview of a (synthetic) secret value."""
    if not value:
        return "(empty)"
    if len(value) <= 8:
        return value[:2] + "***"
    return f"{value[:4]}…{value[-2:]} ({len(value)} chars)"


logger = logging.getLogger(__name__)


class GroundTruthGenerator:
    """Generates GROUND_TRUTH.md documentation for attack scenarios.

    Creates comprehensive documentation of malicious activities including:
    - Attack narrative (high-level description)
    - Timeline of key events with timestamps and record IDs
    - Indicators of Compromise (IOCs) organized by category

    Attributes:
        scenario: Scenario object with storyline
        malicious_events: List of malicious event dicts from generation
    """

    def __init__(
        self,
        scenario: Scenario,
        malicious_events: list[dict],
        red_herring_events: list[dict] | None = None,
        source_evidence_status: dict[str, dict[str, dict[str, int]]] | None = None,
    ):
        """Initialize ground truth generator.

        Args:
            scenario: Scenario object with storyline
            malicious_events: List of malicious event dicts tracked during generation
            red_herring_events: List of red herring event dicts (suspicious but benign)
        """
        self.scenario = scenario
        self.malicious_events = malicious_events
        self.red_herring_events = red_herring_events or []
        self.source_evidence_status = source_evidence_status or {}

    def generate(self, output_path: Path) -> None:
        """Generate GROUND_TRUTH.md file.

        Args:
            output_path: Path to write GROUND_TRUTH.md
        """
        logger.info(f"Generating ground truth documentation: {output_path}")

        content = []

        # Header
        generated_at = self.scenario.time_window.end or self.scenario.time_window.start
        generated_at = (
            generated_at.replace(tzinfo=UTC) if generated_at.tzinfo is None else generated_at
        )
        content.append(f"# Ground Truth: {self.scenario.name}\n")
        content.append(f"**Scenario:** {self.scenario.description}\n")
        content.append(
            f"**Generated:** {generated_at.astimezone(UTC).strftime('%Y-%m-%d %H:%M:%S UTC')}\n"
        )

        # 1. Attack Summary (narrative from storyline)
        content.append("\n## Attack Summary\n")
        content.append(self._create_narrative())

        # 2. Timeline of Key Events
        content.append("\n## Timeline\n")
        content.append(self._create_timeline())

        # 3. Source evidence status for profiles with imperfect observation.
        if self._include_source_evidence_status():
            content.append("\n## Source Evidence Status\n")
            content.append(self._create_source_evidence_status_section())

        # 3. Indicators of Compromise
        content.append("\n## Indicators of Compromise (IOCs)\n")
        iocs = self._extract_iocs()
        content.append(self._format_iocs(iocs))

        # 4. Red Herrings (if present)
        if self.red_herring_events:
            content.append("\n## Red Herrings\n")
            content.append(
                "The following events appear suspicious but are benign. "
                "They are included to make the dataset more realistic.\n"
            )
            content.append(self._create_red_herring_section())

        # Write to file
        safe_write_text(output_path, "\n".join(content))
        logger.info(f"Ground truth documentation written: {output_path}")

    def build_jsonl_records(self) -> list[dict]:
        """Build machine-readable ground-truth records for the GROUND_TRUTH.jsonl sidecar.

        Scope: in v1 this sidecar contains structured records for **spillage labels
        only** (``kind: "spillage"``) — it is NOT yet a complete machine-readable
        mirror of GROUND_TRUTH.md. The ``schema_version`` + ``kind`` fields are
        deliberately general so other ground-truth record kinds can be added later
        without breaking existing consumers.

        One record per malicious event that exposes a canonical value on a semantic
        surface. Byte offsets are intentionally omitted: emitters stream output, so
        a value's position is not known at ground-truth-writing time.
        """
        records: list[dict] = []
        for event in self.malicious_events:
            if "surface" not in event or event.get("skipped_reason"):
                continue
            value = event.get("value", "")
            # rendered_value is the exact on-disk byte form (surface-encoded);
            # match THIS against the logs. value is the canonical secret.
            rendered = event.get("rendered_value", value)
            ts = event["time"]
            ts = ts.replace(tzinfo=UTC) if ts.tzinfo is None else ts
            records.append(
                {
                    "schema_version": GROUND_TRUTH_SCHEMA_VERSION,
                    "kind": event["type"],
                    "storyline_id": event.get("storyline_cluster_id"),
                    "time": ts.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
                    "actor": event["actor"],
                    "system": event["system"],
                    "surface": event["surface"],
                    "family": event.get("family") or None,
                    "value": value,
                    "value_sha256": hashlib.sha256(value.encode("utf-8")).hexdigest(),
                    "rendered_value": rendered,
                    "rendered_sha256": hashlib.sha256(rendered.encode("utf-8")).hexdigest(),
                    "expected_sources": list(event.get("expected_sources", [])),
                    # Web surfaces land on a destination server's access log, not
                    # the actor's host; record where so scorers/eval can locate it.
                    **(
                        {"target_system": event["target_system"]}
                        if event.get("target_system")
                        else {}
                    ),
                }
            )
        records.sort(key=lambda r: (r["storyline_id"] or "", r["time"], r["surface"]))
        # Stable per-record id so duplicate positives are individually addressable.
        seen: dict[str, int] = {}
        for record in records:
            sid = record["storyline_id"] or ""
            n = seen.get(sid, 0)
            seen[sid] = n + 1
            record["record_id"] = f"{sid}#{n}"
        return records

    def write_jsonl(self, output_path: Path) -> None:
        """Write the machine-readable ground-truth sidecar, if any records exist."""
        records = self.build_jsonl_records()
        if not records:
            return
        lines = [json.dumps(r, sort_keys=True) for r in records]
        safe_write_text(output_path, "\n".join(lines) + "\n")
        logger.info(f"Machine-readable ground truth written: {output_path}")

    def _create_narrative(self) -> str:
        """Create attack narrative from storyline events.

        Converts storyline events into a cohesive narrative description
        of the attack sequence.

        Returns:
            Formatted narrative string
        """
        if not self.scenario.storyline:
            return "*No malicious activities in this scenario.*\n"

        narrative = []
        narrative.append("This scenario simulates the following attack sequence:\n")

        for i, event in enumerate(self.scenario.storyline, 1):
            narrative.append(f"{i}. **{event.actor}** on **{event.system}**: {event.activity}")

        return "\n".join(narrative) + "\n"

    def _create_timeline(self) -> str:
        """Create timeline of malicious events with timestamps.

        Formats malicious events into a chronological timeline table
        with timestamps, event types, and details.

        Returns:
            Formatted timeline table (Markdown)
        """
        if not self.malicious_events:
            return "*No malicious events were generated.*\n"

        # Sort events by time
        sorted_events = sorted(self.malicious_events, key=lambda e: e["time"])

        # Create table
        lines = []
        lines.append("| Timestamp | Actor | System | Event Type | Details |")
        lines.append("|-----------|-------|--------|------------|---------|")

        for event in sorted_events:
            timestamp = event["time"].strftime("%Y-%m-%d %H:%M:%S UTC")
            actor = event["actor"]
            system = event["system"]
            event_type = event["type"].title()

            # Format details based on event type
            details = self._format_event_details(event)

            lines.append(f"| {timestamp} | {actor} | {system} | {event_type} | {details} |")

        return "\n".join(lines) + "\n"

    def _format_event_details(self, event: dict) -> str:
        """Format event details for timeline table.

        Args:
            event: Malicious event dict

        Returns:
            Formatted details string
        """
        event_type = event["type"]
        skipped_reason = event.get("skipped_reason")
        if skipped_reason:
            reason = str(skipped_reason).replace("_", " ")
            target = event.get("target_process")
            if target:
                return f"Skipped ({reason}); no evidence emitted for target {target}"
            return f"Skipped ({reason}); no evidence emitted"

        if event_type == "logon":
            source_ip = event.get("source_ip", "N/A")
            logon_id = event.get("logon_id", "N/A")
            return f"Network logon from {source_ip} (LogonID: {logon_id})"

        elif event_type == "process":
            process_name = event.get("process_name", "N/A")
            pid = event.get("pid", "N/A")
            # Truncate command line if too long
            cmd = event.get("command_line", "")
            if len(cmd) > 50:
                cmd = cmd[:47] + "..."
            return f"Process: {process_name} (PID: {pid}) - `{cmd}`"

        elif event_type == "connection":
            dst_ip = event.get("dst_ip", "N/A")
            dst_port = event.get("dst_port", "N/A")
            uid = event.get("uid", "N/A")
            return f"Connection to {dst_ip}:{dst_port} (UID: {uid})"

        elif event_type == "rdp_session":
            dst_ip = event.get("dst_ip", "N/A")
            uid = event.get("uid", "N/A")
            return f"RDP session to {dst_ip}:3389 (UID: {uid})"

        elif event_type == "ssh_session":
            dst_ip = event.get("dst_ip", "N/A")
            uid = event.get("uid", "N/A")
            return f"SSH session to {dst_ip}:22 (UID: {uid})"

        elif event_type == "service_installed":
            svc = event.get("service_name", "N/A")
            path = event.get("service_file_name", "N/A")
            return f"Service installed: {svc} ({path})"

        elif event_type == "scheduled_task_created":
            task = event.get("task_name", "N/A")
            return f"Scheduled task created: {task}"

        elif event_type == "create_remote_thread":
            target = event.get("target_process", "N/A")
            return f"Remote thread injection into {target}"

        elif event_type in ("account_created", "account_deleted"):
            target = event.get("target_username", "N/A")
            action = "created" if event_type == "account_created" else "deleted"
            return f"Account {action}: {target}"

        elif event_type == "group_member_added":
            member = event.get("member_name", "N/A")
            group = event.get("group_name", "N/A")
            return f"Added {member} to group {group}"

        elif event_type == "port_scan":
            target_count = event.get("target_count", "N/A")
            ports = event.get("ports", [])
            total = event.get("total_connections", "N/A")
            return (
                f"Port scan: {target_count} targets, ports {ports}, "
                f"{total} denied connections + ASA threat detection alert (733100)"
            )

        elif event_type == "beacon":
            dst = event.get("dst_ip", "N/A")
            port = event.get("dst_port", "N/A")
            attempts = event.get("attempt_count", "N/A")
            action = event.get("action", "allow")
            term = event.get("termination", "N/A")
            label = "Denied beacon" if action == "deny" else "Beacon"
            return f"{label} to {dst}:{port} ({attempts} attempts, {term})"

        elif event_type == "dns_query":
            query = event.get("query", "N/A")
            qtype = event.get("qtype", "A")
            rcode = event.get("rcode", "NOERROR")
            return f"DNS query: {query} ({qtype}, {rcode})"

        elif event_type == "web_scan":
            dst = event.get("dst_ip", "N/A")
            port = event.get("dst_port", "N/A")
            preset = event.get("preset", "custom")
            requests = event.get("request_count", "N/A")
            return f"Web scan ({preset}) against {dst}:{port} ({requests} requests)"

        elif event_type == "credential_spray":
            pattern = event.get("pattern", "spray")
            accounts = event.get("target_accounts", [])
            attempts = event.get("attempt_count", "N/A")
            success = event.get("success_account")
            result = f"Credential {pattern}: {attempts} attempts against {len(accounts)} accounts"
            if success:
                at = event.get("success_at_attempt", "?")
                result += f" (success: {success} at attempt {at})"
            return result

        elif event_type == "dga_queries":
            count = event.get("total_queries", "N/A")
            nxd = event.get("nxdomain_count", "N/A")
            tld = event.get("tld", ".com")
            sample = event.get("domain_sample", [])
            return f"DGA queries: {count} total ({nxd} NXDOMAIN, TLD: {tld}, sample: {sample[:3]})"

        elif event_type == "dns_tunnel":
            domain = event.get("base_domain", "N/A")
            enc = event.get("encoding", "hex")
            queries = event.get("total_queries", "N/A")
            exfil = event.get("bytes_exfiltrated", 0)
            return f"DNS tunnel via {domain} ({enc}, {queries} queries, {exfil} bytes exfiltrated)"

        elif event_type == "explicit_credentials":
            target = event.get("target_username", "N/A")
            server = event.get("target_server", "N/A")
            return f"Explicit credentials: RunAs {target} on {server}"

        elif event_type in ("workstation_lock", "workstation_unlock"):
            action = "Locked" if event_type == "workstation_lock" else "Unlocked"
            return f"Workstation {action}"

        elif event_type == "spillage":
            surface = event.get("surface", "N/A")
            family = event.get("family") or "literal"
            value = event.get("value", "")
            digest = hashlib.sha256(value.encode("utf-8")).hexdigest()
            return (
                f"Spillage ({family}) to {surface}: {_redact_secret(value)} (sha256:{digest[:12]})"
            )

        else:
            return event.get("activity", "N/A")

    def _include_source_evidence_status(self) -> bool:
        """Return True when ground truth should show source observation status."""
        if not self.source_evidence_status:
            return False
        if self.scenario.observation_profile != "complete":
            return True
        for source_status in self.source_evidence_status.values():
            for counts in source_status.values():
                if any(status != "visible" and count for status, count in counts.items()):
                    return True
        return False

    def _create_source_evidence_status_section(self) -> str:
        """Create a compact per-storyline source evidence status table."""
        lines = [
            "Canonical ground truth remains authoritative. Source rows may be "
            "`visible`, `delayed`, `dropped`, `filtered`, or `out_of_window` depending on "
            "the selected observation profile and sensor placement.\n",
            "| Storyline ID | Source | Status Counts |",
            "|--------------|--------|---------------|",
        ]
        for cluster_id, source_status in sorted(self.source_evidence_status.items()):
            for source, counts in sorted(source_status.items()):
                rendered_counts = ", ".join(
                    f"{status}: {count}" for status, count in sorted(counts.items()) if count
                )
                if rendered_counts:
                    lines.append(f"| {cluster_id} | {source} | {rendered_counts} |")
        return "\n".join(lines) + "\n"

    def _extract_iocs(self) -> dict[str, set]:
        """Extract indicators of compromise from malicious events.

        Extracts IOCs organized by category:
        - network: IPs, domains, ports
        - processes: Process names, command lines
        - users: Usernames, accounts
        - files: File paths (if available)

        Returns:
            Dict mapping IOC category to set of IOC strings
        """
        iocs = {
            "network": set(),
            "processes": set(),
            "users": set(),
            "files": set(),
        }

        for event in self.malicious_events:
            if event.get("skipped_reason"):
                continue

            # Extract actor (user)
            iocs["users"].add(event["actor"])

            # Extract based on event type
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
                    # Classify destination: internal server vs external C2
                    try:
                        is_internal = ipaddress.ip_address(dst_ip).is_private
                    except (ValueError, TypeError):
                        is_internal = False
                    label = "Internal Server" if is_internal else "C2 Server"
                    iocs["network"].add(
                        f"{dst_ip}:{dst_port} ({label})" if dst_port else f"{dst_ip} ({label})"
                    )
                    # Include Zeek UID if available and not filtered
                    uid = event.get("uid", "")
                    if uid and uid != "(filtered by sensor placement)":
                        iocs["network"].add(f"Zeek UID: {uid}")

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
                action = event.get("action", "allow")
                label = "Denied Beacon" if action == "deny" else "Beacon"
                if dst_ip:
                    iocs["network"].add(f"{dst_ip}:{dst_port} ({label} Target)")

            elif event["type"] == "dns_query":
                query = event.get("query", "")
                if query:
                    iocs["network"].add(f"{query} (Malicious DNS Query)")

            elif event["type"] == "web_scan":
                dst_ip = event.get("dst_ip", "")
                dst_port = event.get("dst_port", "")
                if dst_ip:
                    iocs["network"].add(f"{dst_ip}:{dst_port} (Web Scan Target)")

            elif event["type"] == "credential_spray":
                for account in event.get("target_accounts", []):
                    iocs["users"].add(f"{account} (Spray Target)")

            elif event["type"] == "dga_queries":
                for domain in event.get("domain_sample", []):
                    iocs["network"].add(f"{domain} (DGA Domain)")

            elif event["type"] == "dns_tunnel":
                base = event.get("base_domain", "")
                if base:
                    iocs["network"].add(f"{base} (DNS Tunnel Endpoint)")

            elif event["type"] == "explicit_credentials":
                target = event.get("target_username", "")
                if target:
                    iocs["users"].add(f"{target} (Explicit Credential Target)")

        # Remove empty categories
        iocs = {category: values for category, values in iocs.items() if values}

        return iocs

    def _create_red_herring_section(self) -> str:
        """Create documentation of red herring events with explanations.

        Returns:
            Formatted red herring section (Markdown)
        """
        sorted_events = sorted(self.red_herring_events, key=lambda e: e["time"])

        lines = []
        lines.append("| Timestamp | Actor | System | Activity | Why It's Benign |")
        lines.append("|-----------|-------|--------|----------|-----------------|")

        for event in sorted_events:
            timestamp = event["time"].strftime("%Y-%m-%d %H:%M:%S UTC")
            actor = event["actor"]
            system = event["system"]
            activity = event.get("activity", "N/A")
            explanation = event.get("explanation", "N/A")
            lines.append(f"| {timestamp} | {actor} | {system} | {activity} | {explanation} |")

        return "\n".join(lines) + "\n"

    def _format_iocs(self, iocs: dict[str, set]) -> str:
        """Format IOCs into Markdown sections.

        Args:
            iocs: Dict mapping IOC category to set of IOC strings

        Returns:
            Formatted IOC sections (Markdown)
        """
        if not iocs or not any(values for values in iocs.values()):
            return "*No IOCs extracted.*\n"

        sections = []

        # Network IOCs
        if iocs.get("network"):
            sections.append("### Network IOCs\n")
            for ioc in sorted(iocs["network"]):
                sections.append(f"- {ioc}")
            sections.append("")

        # Process IOCs
        if iocs.get("processes"):
            sections.append("### Process IOCs\n")
            for ioc in sorted(iocs["processes"]):
                sections.append(f"- {ioc}")
            sections.append("")

        # User IOCs
        if iocs.get("users"):
            sections.append("### User IOCs\n")
            for ioc in sorted(iocs["users"]):
                sections.append(f"- {ioc} (compromised account)")
            sections.append("")

        # File IOCs
        if iocs.get("files"):
            sections.append("### File IOCs\n")
            for ioc in sorted(iocs["files"]):
                sections.append(f"- {ioc}")
            sections.append("")

        return "\n".join(sections)
