"""Ground truth documentation generator for attack scenarios.

This module generates GROUND_TRUTH.md files that document malicious activities,
timelines, and indicators of compromise (IOCs) for threat hunting training.
"""

import ipaddress
import logging
from datetime import datetime
from pathlib import Path
from typing import Optional

from evidenceforge.models.scenario import Scenario, StorylineEvent

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

    def __init__(self, scenario: Scenario, malicious_events: list[dict]):
        """Initialize ground truth generator.

        Args:
            scenario: Scenario object with storyline
            malicious_events: List of malicious event dicts tracked during generation
        """
        self.scenario = scenario
        self.malicious_events = malicious_events

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

        # Write to file
        output_path.write_text('\n'.join(content))
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

        return '\n'.join(narrative) + '\n'

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
        sorted_events = sorted(self.malicious_events, key=lambda e: e['time'])

        # Create table
        lines = []
        lines.append("| Timestamp | Actor | System | Event Type | Details |")
        lines.append("|-----------|-------|--------|------------|---------|")

        for event in sorted_events:
            timestamp = event['time'].strftime('%Y-%m-%d %H:%M:%S UTC')
            actor = event['actor']
            system = event['system']
            event_type = event['type'].title()

            # Format details based on event type
            details = self._format_event_details(event)

            lines.append(f"| {timestamp} | {actor} | {system} | {event_type} | {details} |")

        return '\n'.join(lines) + '\n'

    def _format_event_details(self, event: dict) -> str:
        """Format event details for timeline table.

        Args:
            event: Malicious event dict

        Returns:
            Formatted details string
        """
        event_type = event['type']

        if event_type == 'logon':
            source_ip = event.get('source_ip', 'N/A')
            logon_id = event.get('logon_id', 'N/A')
            return f"Network logon from {source_ip} (LogonID: {logon_id})"

        elif event_type == 'process':
            process_name = event.get('process_name', 'N/A')
            pid = event.get('pid', 'N/A')
            # Truncate command line if too long
            cmd = event.get('command_line', '')
            if len(cmd) > 50:
                cmd = cmd[:47] + '...'
            return f"Process: {process_name} (PID: {pid}) - `{cmd}`"

        elif event_type == 'connection':
            dst_ip = event.get('dst_ip', 'N/A')
            dst_port = event.get('dst_port', 'N/A')
            uid = event.get('uid', 'N/A')
            return f"Connection to {dst_ip}:{dst_port} (UID: {uid})"

        else:
            return event.get('activity', 'N/A')

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
            'network': set(),
            'processes': set(),
            'users': set(),
            'files': set(),
        }

        for event in self.malicious_events:
            # Extract actor (user)
            iocs['users'].add(event['actor'])

            # Extract based on event type
            if event['type'] == 'logon':
                if 'source_ip' in event:
                    iocs['network'].add(f"{event['source_ip']} (Attacker IP)")

            elif event['type'] == 'process':
                if 'process_name' in event:
                    iocs['processes'].add(event['process_name'])
                if 'command_line' in event:
                    iocs['processes'].add(f"`{event['command_line']}`")
                if 'output_file' in event:
                    iocs['files'].add(event['output_file'])

            elif event['type'] == 'connection':
                if 'dst_ip' in event:
                    dst_ip = event['dst_ip']
                    dst_port = event.get('dst_port', '')
                    # Classify destination: internal server vs external C2
                    try:
                        is_internal = ipaddress.ip_address(dst_ip).is_private
                    except (ValueError, TypeError):
                        is_internal = False
                    label = 'Internal Server' if is_internal else 'C2 Server'
                    iocs['network'].add(f"{dst_ip}:{dst_port} ({label})" if dst_port else f"{dst_ip} ({label})")
                    # Include Zeek UID if available and not filtered
                    uid = event.get('uid', '')
                    if uid and uid != '(filtered by sensor placement)':
                        iocs['network'].add(f"Zeek UID: {uid}")

        # Remove empty categories
        iocs = {category: values for category, values in iocs.items() if values}

        return iocs

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
        if 'network' in iocs:
            sections.append("### Network IOCs\n")
            for ioc in sorted(iocs['network']):
                sections.append(f"- {ioc}")
            sections.append("")

        # Process IOCs
        if 'processes' in iocs:
            sections.append("### Process IOCs\n")
            for ioc in sorted(iocs['processes']):
                sections.append(f"- {ioc}")
            sections.append("")

        # User IOCs
        if 'users' in iocs:
            sections.append("### User IOCs\n")
            for ioc in sorted(iocs['users']):
                sections.append(f"- {ioc} (compromised account)")
            sections.append("")

        # File IOCs
        if 'files' in iocs:
            sections.append("### File IOCs\n")
            for ioc in sorted(iocs['files']):
                sections.append(f"- {ioc}")
            sections.append("")

        return '\n'.join(sections)
