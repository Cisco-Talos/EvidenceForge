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

import ipaddress
import logging
from datetime import datetime
from pathlib import Path

from evidenceforge.models.scenario import Scenario

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

    def generate(self, output_path: Path) -> None:
        """Generate GROUND_TRUTH.md file.

        Args:
            output_path: Path to write GROUND_TRUTH.md
        """
        logger.info(f"Generating ground truth documentation: {output_path}")

        content = []

        # Header
        content.append(f"# Ground Truth: {self.scenario.name}\n")
        content.append(f"**Scenario:** {self.scenario.description}\n")
        content.append(f"**Generated:** {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}\n")

        # 1. Attack Summary (narrative from storyline)
        content.append("\n## Attack Summary\n")
        content.append(self._create_narrative())

        # 2. Timeline of Key Events
        content.append("\n## Timeline\n")
        content.append(self._create_timeline())

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
        output_path.write_text("\n".join(content))
        logger.info(f"Ground truth documentation written: {output_path}")

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

        else:
            return event.get("activity", "N/A")

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
        if not iocs:
            return "*No IOCs extracted.*\n"

        sections = []

        # Network IOCs
        if "network" in iocs:
            sections.append("### Network IOCs\n")
            for ioc in sorted(iocs["network"]):
                sections.append(f"- {ioc}")
            sections.append("")

        # Process IOCs
        if "processes" in iocs:
            sections.append("### Process IOCs\n")
            for ioc in sorted(iocs["processes"]):
                sections.append(f"- {ioc}")
            sections.append("")

        # User IOCs
        if "users" in iocs:
            sections.append("### User IOCs\n")
            for ioc in sorted(iocs["users"]):
                sections.append(f"- {ioc} (compromised account)")
            sections.append("")

        # File IOCs
        if "files" in iocs:
            sections.append("### File IOCs\n")
            for ioc in sorted(iocs["files"]):
                sections.append(f"- {ioc}")
            sections.append("")

        return "\n".join(sections)
