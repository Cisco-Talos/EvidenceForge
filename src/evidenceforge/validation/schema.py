"""Cross-reference and logical validation for scenarios.

This module provides validation beyond Pydantic's schema validation:
- Cross-references between users, systems, personas, groups
- Uniqueness constraints (usernames, hostnames, IPs)
- Logical consistency checks
"""

import ipaddress
from dataclasses import dataclass
from typing import Optional

from log_generator.models import Scenario


@dataclass
class ValidationIssue:
    """Represents a validation issue found in a scenario.

    Attributes:
        severity: "error" (blocks generation) or "warning" (informational)
        field_path: Dot-separated path to the problematic field
        message: Human-readable description of the issue
        suggestion: Optional actionable suggestion to fix the issue
    """

    severity: str  # "error" | "warning"
    field_path: str
    message: str
    suggestion: Optional[str] = None


class ScenarioValidator:
    """Validates cross-references and logical consistency in scenarios."""

    def __init__(self, scenario: Scenario):
        """Initialize validator with a scenario.

        Args:
            scenario: The scenario to validate
        """
        self.scenario = scenario
        self.issues: list[ValidationIssue] = []

        # Build lookup sets for fast reference checking
        self._build_lookups()

    def _build_lookups(self) -> None:
        """Build lookup dictionaries for users, systems, personas, groups."""
        self.usernames = {user.username for user in self.scenario.environment.users}
        self.hostnames = {
            system.hostname for system in self.scenario.environment.systems
        }
        self.ips = {system.ip for system in self.scenario.environment.systems}
        self.persona_names = {persona.name for persona in self.scenario.personas}
        self.group_names = (
            {group.name for group in self.scenario.environment.groups}
            if self.scenario.environment.groups
            else set()
        )
        self.segment_names = (
            {seg.name for seg in self.scenario.environment.network.segments}
            if self.scenario.environment.network
            else set()
        )

    def validate(self) -> list[ValidationIssue]:
        """Run all validation checks and return issues found.

        Returns:
            List of validation issues (errors and warnings)
        """
        self._validate_user_persona_references()
        self._validate_system_user_references()
        self._validate_user_primary_system_references()
        self._validate_group_member_references()
        self._validate_storyline_references()
        self._validate_uniqueness()
        self._validate_expanded_activities()
        self._validate_event_sequences()
        self._validate_network_segments()
        self._validate_network_sensors()
        return self.issues

    def has_errors(self) -> bool:
        """Check if any error-level issues were found.

        Returns:
            True if any errors found, False otherwise
        """
        return any(issue.severity == "error" for issue in self.issues)

    def _validate_user_persona_references(self) -> None:
        """Check that user persona references exist in personas list."""
        for idx, user in enumerate(self.scenario.environment.users):
            if user.persona and user.persona not in self.persona_names:
                available = (
                    ", ".join(sorted(self.persona_names))
                    if self.persona_names
                    else "none defined"
                )
                self.issues.append(
                    ValidationIssue(
                        severity="error",
                        field_path=f"environment.users.{idx}.persona",
                        message=f"User '{user.username}' references undefined persona '{user.persona}'",
                        suggestion=f"Available personas: {available}",
                    )
                )

    def _validate_system_user_references(self) -> None:
        """Check that system assigned_user references exist in users list."""
        for idx, system in enumerate(self.scenario.environment.systems):
            if system.assigned_user and system.assigned_user not in self.usernames:
                self.issues.append(
                    ValidationIssue(
                        severity="error",
                        field_path=f"environment.systems.{idx}.assigned_user",
                        message=f"System '{system.hostname}' references undefined user '{system.assigned_user}'",
                        suggestion=f"Available users: {', '.join(sorted(self.usernames))}",
                    )
                )

    def _validate_user_primary_system_references(self) -> None:
        """Check that user primary_system references exist in systems list."""
        for idx, user in enumerate(self.scenario.environment.users):
            if user.primary_system and user.primary_system not in self.hostnames:
                self.issues.append(
                    ValidationIssue(
                        severity="error",
                        field_path=f"environment.users.{idx}.primary_system",
                        message=f"User '{user.username}' references undefined system '{user.primary_system}'",
                        suggestion=f"Available systems: {', '.join(sorted(self.hostnames))}",
                    )
                )

    def _validate_group_member_references(self) -> None:
        """Check that group members exist in users list."""
        if not self.scenario.environment.groups:
            return

        for idx, group in enumerate(self.scenario.environment.groups):
            for member_idx, member in enumerate(group.members):
                if member not in self.usernames:
                    self.issues.append(
                        ValidationIssue(
                            severity="error",
                            field_path=f"environment.groups.{idx}.members.{member_idx}",
                            message=f"Group '{group.name}' references undefined member '{member}'",
                            suggestion=f"Available users: {', '.join(sorted(self.usernames))}",
                        )
                    )

    def _validate_storyline_references(self) -> None:
        """Check that storyline actor/system references are valid."""
        if not self.scenario.storyline:
            return

        for idx, event in enumerate(self.scenario.storyline):
            # Validate actor (must be user or "attacker")
            if event.actor not in self.usernames and event.actor != "attacker":
                self.issues.append(
                    ValidationIssue(
                        severity="error",
                        field_path=f"storyline.{idx}.actor",
                        message=f"Storyline event references undefined actor '{event.actor}'",
                        suggestion=f"Available users: {', '.join(sorted(self.usernames))}, or use 'attacker'",
                    )
                )

            # Validate system
            if event.system not in self.hostnames:
                self.issues.append(
                    ValidationIssue(
                        severity="error",
                        field_path=f"storyline.{idx}.system",
                        message=f"Storyline event references undefined system '{event.system}'",
                        suggestion=f"Available systems: {', '.join(sorted(self.hostnames))}",
                    )
                )

    def _validate_uniqueness(self) -> None:
        """Check for duplicate usernames, hostnames, and IPs."""
        # Check duplicate usernames
        seen_usernames = set()
        for idx, user in enumerate(self.scenario.environment.users):
            if user.username in seen_usernames:
                self.issues.append(
                    ValidationIssue(
                        severity="error",
                        field_path=f"environment.users.{idx}.username",
                        message=f"Duplicate username '{user.username}' found",
                        suggestion="Usernames must be unique across all users",
                    )
                )
            seen_usernames.add(user.username)

        # Check duplicate hostnames
        seen_hostnames = set()
        for idx, system in enumerate(self.scenario.environment.systems):
            if system.hostname in seen_hostnames:
                self.issues.append(
                    ValidationIssue(
                        severity="error",
                        field_path=f"environment.systems.{idx}.hostname",
                        message=f"Duplicate hostname '{system.hostname}' found",
                        suggestion="Hostnames must be unique across all systems",
                    )
                )
            seen_hostnames.add(system.hostname)

        # Check duplicate IPs
        seen_ips = set()
        for idx, system in enumerate(self.scenario.environment.systems):
            if system.ip in seen_ips:
                self.issues.append(
                    ValidationIssue(
                        severity="error",
                        field_path=f"environment.systems.{idx}.ip",
                        message=f"Duplicate IP address '{system.ip}' found",
                        suggestion="IP addresses must be unique across all systems",
                    )
                )
            seen_ips.add(system.ip)

    def _validate_expanded_activities(self) -> None:
        """Validate persona expanded_activities structure if present."""
        if not self.scenario.personas:
            return

        for idx, persona in enumerate(self.scenario.personas):
            if persona.expanded_activities is None:
                continue
            for act_idx, activity in enumerate(persona.expanded_activities):
                if "activity_type" not in activity:
                    self.issues.append(
                        ValidationIssue(
                            severity="error",
                            field_path=f"personas.{idx}.expanded_activities.{act_idx}",
                            message=f"Persona '{persona.name}': expanded_activities[{act_idx}] missing 'activity_type'",
                            suggestion="Each expanded activity must have an 'activity_type' field",
                        )
                    )
                if "sequence" in activity and not isinstance(activity["sequence"], list):
                    self.issues.append(
                        ValidationIssue(
                            severity="error",
                            field_path=f"personas.{idx}.expanded_activities.{act_idx}.sequence",
                            message=f"Persona '{persona.name}': expanded_activities[{act_idx}].sequence must be a list",
                            suggestion="The 'sequence' field should be a list of action steps",
                        )
                    )

    def _validate_event_sequences(self) -> None:
        """Validate storyline event_sequence structure if present."""
        if not self.scenario.storyline:
            return

        for idx, event in enumerate(self.scenario.storyline):
            if event.event_sequence is None:
                continue
            for seq_idx, sub_event in enumerate(event.event_sequence):
                if "sub_event_type" not in sub_event:
                    self.issues.append(
                        ValidationIssue(
                            severity="error",
                            field_path=f"storyline.{idx}.event_sequence.{seq_idx}",
                            message=f"Storyline event at {event.time}: event_sequence[{seq_idx}] missing 'sub_event_type'",
                            suggestion="Each sub-event must have a 'sub_event_type' field",
                        )
                    )

    def _validate_network_segments(self) -> None:
        """Validate network segment cross-references."""
        if not self.scenario.environment.network:
            return

        for idx, segment in enumerate(self.scenario.environment.network.segments):
            network = ipaddress.ip_network(segment.cidr, strict=False)

            for sys_idx, hostname in enumerate(segment.systems):
                if hostname not in self.hostnames:
                    self.issues.append(
                        ValidationIssue(
                            severity="error",
                            field_path=f"environment.network.segments.{idx}.systems.{sys_idx}",
                            message=f"Segment '{segment.name}' references undefined system '{hostname}'",
                            suggestion=f"Available systems: {', '.join(sorted(self.hostnames))}",
                        )
                    )
                else:
                    system_ip = self._get_system_ip(hostname)
                    if system_ip and ipaddress.ip_address(system_ip) not in network:
                        self.issues.append(
                            ValidationIssue(
                                severity="warning",
                                field_path=f"environment.network.segments.{idx}.systems.{sys_idx}",
                                message=f"System '{hostname}' (IP: {system_ip}) not in segment CIDR {segment.cidr}",
                                suggestion="Check IP assignment or segment CIDR",
                            )
                        )

    def _validate_network_sensors(self) -> None:
        """Validate network sensor cross-references."""
        if not self.scenario.environment.network:
            return

        known_formats = {"zeek_conn", "snort_alert", "web_access"}

        for idx, sensor in enumerate(self.scenario.environment.network.sensors):
            for seg_idx, seg_name in enumerate(sensor.monitoring_segments):
                if seg_name not in self.segment_names:
                    self.issues.append(
                        ValidationIssue(
                            severity="error",
                            field_path=f"environment.network.sensors.{idx}.monitoring_segments.{seg_idx}",
                            message=f"Sensor '{sensor.name}' references undefined segment '{seg_name}'",
                            suggestion=f"Available segments: {', '.join(sorted(self.segment_names))}",
                        )
                    )

            for fmt_idx, fmt in enumerate(sensor.log_formats):
                if fmt not in known_formats:
                    self.issues.append(
                        ValidationIssue(
                            severity="warning",
                            field_path=f"environment.network.sensors.{idx}.log_formats.{fmt_idx}",
                            message=f"Sensor '{sensor.name}' uses unknown log format '{fmt}'",
                            suggestion=f"Known network formats: {', '.join(sorted(known_formats))}",
                        )
                    )

    def _get_system_ip(self, hostname: str) -> str | None:
        """Get IP address for a system by hostname."""
        for system in self.scenario.environment.systems:
            if system.hostname == hostname:
                return system.ip
        return None
