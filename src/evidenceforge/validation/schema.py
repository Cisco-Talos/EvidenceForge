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

"""Cross-reference and logical validation for scenarios.

This module provides validation beyond Pydantic's schema validation:
- Cross-references between users, systems, personas, groups
- Uniqueness constraints (usernames, hostnames, IPs)
- Logical consistency checks
- OS/format compatibility
- Storyline plausibility
"""

import ipaddress
import logging
from dataclasses import dataclass
from datetime import UTC

from evidenceforge.models import Scenario

logger = logging.getLogger(__name__)

# Well-known OS built-in accounts that are always valid as storyline actors
# without needing to be defined in the environment users list.
BUILTIN_ACCOUNTS = {
    # Windows
    "SYSTEM",
    "NT AUTHORITY\\SYSTEM",
    "LOCAL SERVICE",
    "NETWORK SERVICE",
    # Linux/macOS
    "root",
    "nobody",
    "daemon",
    "www-data",
    # Common service accounts
    "mysql",
    "postgres",
    "apache",
    "nginx",
}

# OS detection patterns (mirrors evaluation/visibility.py)
_WINDOWS_PATTERNS = ["windows"]
_LINUX_PATTERNS = ["linux", "ubuntu", "centos", "debian", "rhel"]

# Formats that are bound to a specific OS
_OS_BOUND_FORMATS: dict[str, str] = {
    "windows_event_security": "windows",
    "windows_event_sysmon": "windows",
    "syslog": "linux",
    "bash_history": "linux",
}

# Reverse: OS → expected host-local formats
_OS_EXPECTED_FORMATS: dict[str, set[str]] = {
    "windows": {"windows_event_security", "windows_event_sysmon"},
    "linux": {"syslog", "bash_history"},
}

# Event types that are Windows-specific
_WINDOWS_EVENT_TYPES = {
    "service_installed",
    "scheduled_task_created",
    "log_cleared",
    "create_remote_thread",
    "process_access",
}

# Event types that imply Linux/SSH
_LINUX_EVENT_TYPES = {"ssh_session"}

# Process command patterns indicating wrong OS
_WINDOWS_COMMAND_INDICATORS = {"powershell.exe", "cmd.exe", "reg.exe", "net.exe"}
_LINUX_PATH_PREFIXES = ("/usr/", "/bin/", "/etc/", "/opt/", "/var/")

# Eval volume targets by baseline intensity (noise-to-signal ratio)
_VOLUME_TARGETS: dict[str, int] = {"low": 500, "medium": 5000, "high": 10000}


def _get_os_category(os_string: str) -> str:
    """Detect OS category from OS string.

    Args:
        os_string: OS name/version string (e.g., "Windows 10", "Linux Ubuntu 20.04")

    Returns:
        "windows", "linux", or "unknown"
    """
    os_lower = os_string.lower()
    if any(p in os_lower for p in _WINDOWS_PATTERNS):
        return "windows"
    if any(p in os_lower for p in _LINUX_PATTERNS):
        return "linux"
    return "unknown"


@dataclass
class ValidationIssue:
    """Represents a validation issue found in a scenario.

    Attributes:
        severity: "error" (blocks generation) or "warning" (informational)
        field_path: Dot-separated path to the problematic field
        message: Human-readable description of the issue
        suggestion: Optional actionable suggestion to fix the issue
    """

    severity: str  # "error" | "warning" | "info"
    field_path: str
    message: str
    suggestion: str | None = None


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
        self.hostnames = {system.hostname for system in self.scenario.environment.systems}
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
        self.service_accounts = set(self.scenario.environment.service_accounts)

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
        self._validate_output_formats()
        # Eval-informed checks
        self._validate_format_os_compatibility()
        self._validate_segment_sensor_coverage()
        self._validate_service_account_collisions()
        self._validate_stale_account_collisions()
        self._validate_red_herring_references()
        self._validate_storyline_actor_work_hours()
        self._validate_noise_feasibility()
        self._validate_storyline_format_coverage()
        self._validate_storyline_os_plausibility()
        self._validate_storyline_linkability()
        self._validate_storyline_causal_order()
        self._validate_storyline_event_ids()
        self._validate_expansion_redundancy()
        self._sort_issues()
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
                    ", ".join(sorted(self.persona_names)) if self.persona_names else "none defined"
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

        valid_actors = self.usernames | BUILTIN_ACCOUNTS | self.service_accounts

        for idx, event in enumerate(self.scenario.storyline):
            # Validate actor (must be a defined user, built-in account, or service account)
            if event.actor not in valid_actors:
                parts = [f"Available users: {', '.join(sorted(self.usernames))}"]
                if self.service_accounts:
                    parts.append(f"Service accounts: {', '.join(sorted(self.service_accounts))}")
                parts.append(f"Built-in accounts: {', '.join(sorted(BUILTIN_ACCOUNTS))}")
                self.issues.append(
                    ValidationIssue(
                        severity="error",
                        field_path=f"storyline.{idx}.actor",
                        message=f"Storyline event references undefined actor '{event.actor}'",
                        suggestion=". ".join(parts),
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
        """Validate typed event declarations (Phase 8.4).

        Per-event-type field validation is handled by Pydantic models (EventSpec).
        This method performs cross-reference checks that Pydantic can't do.
        """
        if not self.scenario.storyline:
            return

        _KNOWN_FORMATS = {
            "windows_event_security",
            "windows_event_sysmon",
            "zeek_conn",
            "zeek_dns",
            "zeek_http",
            "zeek_ssl",
            "zeek_files",
            "zeek_dhcp",
            "zeek_ntp",
            "zeek_weird",
            "zeek_x509",
            "zeek_ocsp",
            "zeek_pe",
            "zeek_packet_filter",
            "zeek_reporter",
            "ecar",
            "syslog",
            "bash_history",
            "snort_alert",
            "web_access",
            "proxy_access",
        }

        for idx, event in enumerate(self.scenario.storyline):
            for spec_idx, spec in enumerate(event.events):
                # Validate connection dst_ip is a valid IP
                if hasattr(spec, "dst_ip") and spec.dst_ip:
                    try:
                        import ipaddress

                        ipaddress.ip_address(spec.dst_ip)
                    except ValueError:
                        self.issues.append(
                            ValidationIssue(
                                severity="error",
                                field_path=f"storyline.{idx}.events.{spec_idx}.dst_ip",
                                message=f"Invalid IP address: {spec.dst_ip}",
                                suggestion="Use a valid IPv4 or IPv6 address",
                            )
                        )

                # Validate raw event target_format
                if hasattr(spec, "target_format") and spec.target_format:
                    if spec.target_format not in _KNOWN_FORMATS:
                        self.issues.append(
                            ValidationIssue(
                                severity="warning",
                                field_path=f"storyline.{idx}.events.{spec_idx}.target_format",
                                message=f"Unknown target format: {spec.target_format}",
                                suggestion=f"Use one of: {', '.join(sorted(_KNOWN_FORMATS))}",
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

        from evidenceforge.events.dispatcher import FORMAT_GROUPS

        # Valid sensor log_formats: group names + standalone non-group formats
        known_sensor_formats = set(FORMAT_GROUPS.keys()) | {"snort_alert"}
        # Individual emitter names that must use their group instead
        _group_members = {}
        for group, members in FORMAT_GROUPS.items():
            for member in members:
                _group_members[member] = group

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
                if fmt in _group_members:
                    self.issues.append(
                        ValidationIssue(
                            severity="error",
                            field_path=f"environment.network.sensors.{idx}.log_formats.{fmt_idx}",
                            message=f"Sensor '{sensor.name}' uses individual format '{fmt}'",
                            suggestion=f"Use the group name '{_group_members[fmt]}' instead",
                        )
                    )
                elif fmt not in known_sensor_formats:
                    self.issues.append(
                        ValidationIssue(
                            severity="warning",
                            field_path=f"environment.network.sensors.{idx}.log_formats.{fmt_idx}",
                            message=f"Sensor '{sensor.name}' uses unknown log format '{fmt}'",
                            suggestion=f"Known formats: {', '.join(sorted(known_sensor_formats))}",
                        )
                    )

    def _validate_output_formats(self) -> None:
        """Validate output.logs format names."""
        from evidenceforge.events.dispatcher import FORMAT_GROUPS

        known_output_formats = set(FORMAT_GROUPS.keys()) | {
            "ecar",
            "syslog",
            "bash_history",
            "snort_alert",
            "web_access",
            "proxy_access",
        }
        _group_members = {}
        for group, members in FORMAT_GROUPS.items():
            for member in members:
                _group_members[member] = group

        for idx, log_spec in enumerate(self.scenario.output.logs):
            fmt = log_spec.get("format", "")
            if fmt in _group_members:
                self.issues.append(
                    ValidationIssue(
                        severity="error",
                        field_path=f"output.logs.{idx}.format",
                        message=f"Individual format '{fmt}' not allowed in output.logs",
                        suggestion=f"Use the group name '{_group_members[fmt]}' instead",
                    )
                )
            elif fmt and fmt not in known_output_formats:
                self.issues.append(
                    ValidationIssue(
                        severity="warning",
                        field_path=f"output.logs.{idx}.format",
                        message=f"Unknown output format '{fmt}'",
                        suggestion=f"Known formats: {', '.join(sorted(known_output_formats))}",
                    )
                )

    def _get_system_ip(self, hostname: str) -> str | None:
        """Get IP address for a system by hostname."""
        for system in self.scenario.environment.systems:
            if system.hostname == hostname:
                return system.ip
        return None

    def _get_system(self, hostname: str):
        """Get System object by hostname."""
        for system in self.scenario.environment.systems:
            if system.hostname == hostname:
                return system
        return None

    def _get_expanded_formats(self) -> set[str]:
        """Get all expanded output format names from output.logs."""
        from evidenceforge.events.dispatcher import FORMAT_GROUPS

        formats: set[str] = set()
        for log_spec in self.scenario.output.logs:
            fmt = log_spec.get("format", "")
            if fmt in FORMAT_GROUPS:
                formats.update(FORMAT_GROUPS[fmt])
            elif fmt:
                formats.add(fmt)
        return formats

    def _validate_format_os_compatibility(self) -> None:
        """Check that OS-bound formats have matching systems and vice versa."""
        expanded_formats = self._get_expanded_formats()
        os_categories = {
            system.hostname: _get_os_category(system.os)
            for system in self.scenario.environment.systems
        }
        os_present = set(os_categories.values())

        # Error: OS-bound format requested but no matching-OS systems
        for fmt, required_os in _OS_BOUND_FORMATS.items():
            if fmt in expanded_formats and required_os not in os_present:
                self.issues.append(
                    ValidationIssue(
                        severity="error",
                        field_path="output.logs",
                        message=(
                            f"Format '{fmt}' requires {required_os} systems but none are defined"
                        ),
                        suggestion=(
                            f"Add a {required_os} system or remove '{fmt}' from output formats"
                        ),
                    )
                )

        # Warning: system OS has no corresponding format in output
        for hostname, os_cat in os_categories.items():
            if os_cat == "unknown":
                continue
            expected = _OS_EXPECTED_FORMATS.get(os_cat, set())
            if expected and not (expected & expanded_formats):
                self.issues.append(
                    ValidationIssue(
                        severity="warning",
                        field_path="output.logs",
                        message=(
                            f"System '{hostname}' is {os_cat} but no {os_cat} log formats in output"
                        ),
                        suggestion=(
                            f"Add a {os_cat} format group (e.g., {', '.join(sorted(expected))})"
                        ),
                    )
                )

    def _validate_segment_sensor_coverage(self) -> None:
        """Check that network segments with systems have sensor coverage."""
        if not self.scenario.environment.network:
            return

        monitored_segments: set[str] = set()
        for sensor in self.scenario.environment.network.sensors:
            monitored_segments.update(sensor.monitoring_segments)

        for idx, segment in enumerate(self.scenario.environment.network.segments):
            if segment.systems and segment.name not in monitored_segments:
                self.issues.append(
                    ValidationIssue(
                        severity="warning",
                        field_path=f"environment.network.segments.{idx}",
                        message=(
                            f"Segment '{segment.name}' has systems but no sensor monitoring it"
                        ),
                        suggestion="Add a sensor with this segment in monitoring_segments",
                    )
                )

    def _validate_service_account_collisions(self) -> None:
        """Check for collisions between service accounts and user accounts."""
        collisions = self.service_accounts & self.usernames
        for name in sorted(collisions):
            self.issues.append(
                ValidationIssue(
                    severity="warning",
                    field_path="environment.service_accounts",
                    message=(
                        f"Service account '{name}' collides with a user account of the same name"
                    ),
                    suggestion="Rename one to avoid ambiguity in log attribution",
                )
            )

    def _validate_stale_account_collisions(self) -> None:
        """Check that stale accounts don't collide with active users or service accounts."""
        stale_usernames = {sa.username for sa in self.scenario.environment.stale_accounts}
        # Collisions with active users
        for name in sorted(stale_usernames & self.usernames):
            self.issues.append(
                ValidationIssue(
                    severity="error",
                    field_path="environment.stale_accounts",
                    message=(
                        f"Stale account '{name}' collides with an active user of the same name"
                    ),
                    suggestion="Stale accounts must have unique usernames — remove from users or stale_accounts",
                )
            )
        # Collisions with service accounts
        for name in sorted(stale_usernames & self.service_accounts):
            self.issues.append(
                ValidationIssue(
                    severity="error",
                    field_path="environment.stale_accounts",
                    message=(
                        f"Stale account '{name}' collides with a service account of the same name"
                    ),
                    suggestion="Stale accounts must not overlap with service_accounts",
                )
            )

    def _validate_red_herring_references(self) -> None:
        """Check that red herring actors and systems exist in the environment."""
        valid_actors = self.usernames | self.service_accounts | BUILTIN_ACCOUNTS
        for idx, rh in enumerate(self.scenario.red_herrings):
            if rh.actor not in valid_actors:
                self.issues.append(
                    ValidationIssue(
                        severity="error",
                        field_path=f"red_herrings[{idx}].actor",
                        message=(
                            f"Red herring actor '{rh.actor}' is not a defined user, "
                            f"service account, or built-in account"
                        ),
                        suggestion="Add the actor to environment.users or environment.service_accounts",
                    )
                )
            if rh.system not in self.hostnames:
                self.issues.append(
                    ValidationIssue(
                        severity="error",
                        field_path=f"red_herrings[{idx}].system",
                        message=(f"Red herring system '{rh.system}' is not a defined system"),
                        suggestion="Add the system to environment.systems",
                    )
                )

    def _validate_storyline_actor_work_hours(self) -> None:
        """Check that storyline actors have personas with work_hours defined."""
        if not self.scenario.storyline:
            return

        user_persona_map: dict[str, str | None] = {
            user.username: user.persona for user in self.scenario.environment.users
        }
        persona_map = {p.name: p for p in self.scenario.personas}
        checked_actors: set[str] = set()

        for _idx, event in enumerate(self.scenario.storyline):
            actor = event.actor
            if actor in checked_actors or actor in BUILTIN_ACCOUNTS:
                continue
            if actor in self.service_accounts:
                continue
            checked_actors.add(actor)

            persona_name = user_persona_map.get(actor)
            if not persona_name:
                continue  # No persona assigned — other validators catch this
            persona = persona_map.get(persona_name)
            if persona and not persona.work_hours_parsed:
                self.issues.append(
                    ValidationIssue(
                        severity="warning",
                        field_path=f"personas.{persona_name}.work_hours",
                        message=(
                            f"Storyline actor '{actor}' has persona "
                            f"'{persona_name}' but work_hours could not be parsed"
                        ),
                        suggestion=(
                            "Use a format like '9am-5pm' or '8:30am-5:30pm (lunch 12pm-1pm)'"
                        ),
                    )
                )

    def _validate_noise_feasibility(self) -> None:
        """Check that noise-to-signal ratio is feasible for baseline intensity."""
        if not self.scenario.storyline:
            return

        signal_count = len(self.scenario.storyline)
        intensity = self.scenario.baseline_activity.intensity
        target_ratio = _VOLUME_TARGETS.get(intensity, 5000)

        # With very many storyline events and low intensity, the ratio can't
        # be met. Warn if signal > 10% of target total volume.
        signal_count * target_ratio
        # A rough check: if the time window can't support this volume
        # we warn. Simpler: just warn if signal count is very high for low
        # intensity.
        if intensity == "low" and signal_count > 50:
            self.issues.append(
                ValidationIssue(
                    severity="warning",
                    field_path="baseline_activity.intensity",
                    message=(
                        f"Baseline intensity is 'low' but storyline has "
                        f"{signal_count} events — noise-to-signal ratio "
                        f"target ({target_ratio}:1) may be unreachable"
                    ),
                    suggestion="Consider increasing intensity to 'medium' or 'high'",
                )
            )
        elif intensity == "medium" and signal_count > 200:
            self.issues.append(
                ValidationIssue(
                    severity="warning",
                    field_path="baseline_activity.intensity",
                    message=(
                        f"Baseline intensity is 'medium' but storyline has "
                        f"{signal_count} events — noise-to-signal ratio "
                        f"target ({target_ratio}:1) may be unreachable"
                    ),
                    suggestion="Consider increasing intensity to 'high'",
                )
            )

    def _validate_storyline_format_coverage(self) -> None:
        """Check storyline systems have appropriate format coverage."""
        if not self.scenario.storyline:
            return

        expanded_formats = self._get_expanded_formats()
        checked_systems: set[str] = set()

        for idx, event in enumerate(self.scenario.storyline):
            hostname = event.system
            if hostname in checked_systems or hostname not in self.hostnames:
                continue
            checked_systems.add(hostname)

            system = self._get_system(hostname)
            if not system:
                continue

            os_cat = _get_os_category(system.os)
            expected = _OS_EXPECTED_FORMATS.get(os_cat, set())
            missing = expected - expanded_formats
            if missing:
                self.issues.append(
                    ValidationIssue(
                        severity="warning",
                        field_path=f"storyline.{idx}.system",
                        message=(
                            f"[{event.id}] Storyline system '{hostname}' ({os_cat}) "
                            f"expects formats {sorted(missing)} but they "
                            f"are not in output.logs"
                        ),
                        suggestion="Add the missing formats to output.logs",
                    )
                )

    def _validate_storyline_os_plausibility(self) -> None:
        """Check storyline event types are plausible for target system OS."""
        if not self.scenario.storyline:
            return

        for idx, event in enumerate(self.scenario.storyline):
            system = self._get_system(event.system)
            if not system:
                continue
            os_cat = _get_os_category(system.os)
            if os_cat == "unknown":
                continue

            for spec_idx, spec in enumerate(event.events):
                event_type = spec.type

                # Windows-only events on Linux
                if os_cat == "linux" and event_type in _WINDOWS_EVENT_TYPES:
                    self.issues.append(
                        ValidationIssue(
                            severity="warning",
                            field_path=(f"storyline.{idx}.events.{spec_idx}"),
                            message=(
                                f"[{event.id}] Event type '{event_type}' is Windows-specific "
                                f"but system '{event.system}' is {os_cat}"
                            ),
                            suggestion=(
                                "Change the target system to a Windows host "
                                "or use a different event type"
                            ),
                        )
                    )

                # Linux-specific events on Windows
                if os_cat == "windows" and event_type in _LINUX_EVENT_TYPES:
                    self.issues.append(
                        ValidationIssue(
                            severity="warning",
                            field_path=(f"storyline.{idx}.events.{spec_idx}"),
                            message=(
                                f"[{event.id}] Event type '{event_type}' is Linux-specific "
                                f"but system '{event.system}' is {os_cat}"
                            ),
                            suggestion=(
                                "Change the target system to a Linux host "
                                "or use a different event type"
                            ),
                        )
                    )

                # Process command OS mismatch
                if event_type == "process" and hasattr(spec, "command_line"):
                    cmd = spec.command_line or spec.process_name
                    cmd_lower = cmd.lower()

                    if os_cat == "linux":
                        for indicator in _WINDOWS_COMMAND_INDICATORS:
                            if indicator in cmd_lower:
                                self.issues.append(
                                    ValidationIssue(
                                        severity="warning",
                                        field_path=(
                                            f"storyline.{idx}.events.{spec_idx}.command_line"
                                        ),
                                        message=(
                                            f"[{event.id}] Command contains Windows "
                                            f"indicator '{indicator}' but "
                                            f"system '{event.system}' is "
                                            f"{os_cat}"
                                        ),
                                        suggestion=(
                                            "Use a Linux-compatible command "
                                            "or change the target system"
                                        ),
                                    )
                                )
                                break

                    elif os_cat == "windows":
                        for prefix in _LINUX_PATH_PREFIXES:
                            if cmd_lower.startswith(prefix):
                                self.issues.append(
                                    ValidationIssue(
                                        severity="warning",
                                        field_path=(
                                            f"storyline.{idx}.events.{spec_idx}.command_line"
                                        ),
                                        message=(
                                            f"[{event.id}] Command starts with Linux "
                                            f"path '{prefix}' but system "
                                            f"'{event.system}' is {os_cat}"
                                        ),
                                        suggestion=(
                                            "Use a Windows-compatible path "
                                            "or change the target system"
                                        ),
                                    )
                                )
                                break

    def _validate_storyline_linkability(self) -> None:
        """Check consecutive storyline events share a pivotable indicator.

        Suppressed when time gap > 4 hours (natural break). Remaining
        issues are info-level since the check is inherently fuzzy.
        """
        if not self.scenario.storyline or len(self.scenario.storyline) < 2:
            return

        _GAP_THRESHOLD_SECS = 4 * 3600  # 4 hours

        for idx in range(len(self.scenario.storyline) - 1):
            curr = self.scenario.storyline[idx]
            nxt = self.scenario.storyline[idx + 1]

            # Skip if large time gap (natural break)
            curr_secs = self._resolve_event_time(curr)
            nxt_secs = self._resolve_event_time(nxt)
            if (
                curr_secs is not None
                and nxt_secs is not None
                and (nxt_secs - curr_secs) > _GAP_THRESHOLD_SECS
            ):
                continue

            # Shared if same actor, same system, or overlapping IPs
            shared = False
            if curr.actor == nxt.actor:
                shared = True
            elif curr.system == nxt.system:
                shared = True
            else:
                # Check IP overlap from event specs
                curr_ips = self._extract_ips(curr)
                nxt_ips = self._extract_ips(nxt)
                curr_sys_ip = self._get_system_ip(curr.system)
                nxt_sys_ip = self._get_system_ip(nxt.system)
                all_curr = curr_ips | ({curr_sys_ip} if curr_sys_ip else set())
                all_nxt = nxt_ips | ({nxt_sys_ip} if nxt_sys_ip else set())
                if all_curr & all_nxt:
                    shared = True

            if not shared:
                self.issues.append(
                    ValidationIssue(
                        severity="info",
                        field_path=f"storyline.{idx}",
                        message=(
                            f"[{curr.id}] → [{nxt.id}] share no obvious "
                            f"pivot indicator (actor, system, or IP)"
                        ),
                        suggestion=(
                            "Ensure consecutive events share at least one "
                            "field a hunter could pivot on"
                        ),
                    )
                )

    def _extract_ips(self, event) -> set[str]:
        """Extract all IPs from a storyline event's typed event specs."""
        ips: set[str] = set()
        for spec in event.events:
            if hasattr(spec, "source_ip") and spec.source_ip:
                ips.add(spec.source_ip)
            if hasattr(spec, "dst_ip") and spec.dst_ip:
                ips.add(spec.dst_ip)
        return ips

    def _validate_storyline_causal_order(self) -> None:
        """Check causal ordering of storyline event types.

        Verifies that events requiring prior state (e.g., process execution
        requires a prior logon) are correctly ordered. Only checks events
        with valid actor/system references.
        """
        if not self.scenario.storyline:
            return

        valid_actors = self.usernames | BUILTIN_ACCOUNTS | self.service_accounts

        # Parse grace period
        from evidenceforge.utils.time import parse_duration

        try:
            grace_td = parse_duration(self.scenario.logon_grace_period)
            grace_seconds = grace_td.total_seconds()
        except (ValueError, TypeError):
            grace_seconds = 1800  # fallback 30 minutes

        # Track logons per (actor, system) pair
        _LOGON_TYPES = {"logon", "ssh_session", "rdp_session"}
        logons: dict[tuple[str, str], int] = {}  # (actor, system) → first idx
        created_accounts: set[str] = set()

        for idx, event in enumerate(self.scenario.storyline):
            actor = event.actor
            system = event.system

            # Skip events with invalid references (other validators handle those)
            if actor not in valid_actors or system not in self.hostnames:
                continue

            has_logon = False
            has_process = False
            has_logoff = False

            for spec in event.events:
                event_type = spec.type

                if event_type in _LOGON_TYPES:
                    key = (actor, system)
                    if key not in logons:
                        logons[key] = idx
                    has_logon = True
                elif event_type == "process":
                    has_process = True
                elif event_type == "logoff":
                    has_logoff = True

                elif event_type == "account_created":
                    target = getattr(spec, "target_username", None)
                    if target:
                        created_accounts.add(target)

                elif event_type == "account_deleted":
                    target = getattr(spec, "target_username", None)
                    if target and target not in created_accounts:
                        self.issues.append(
                            ValidationIssue(
                                severity="warning",
                                field_path=f"storyline.{idx}",
                                message=(
                                    f"[{event.id}] Account deletion for "
                                    f"'{target}' with no prior "
                                    f"account_created event"
                                ),
                                suggestion=(
                                    "Add an account_created event before "
                                    "deleting this account, or this may be "
                                    "an existing account deletion"
                                ),
                            )
                        )

            # Check process/logoff after processing all specs in this event
            key = (actor, system)
            skip_actor = actor in BUILTIN_ACCOUNTS or actor in self.service_accounts

            # Suppress logon warnings within the grace period
            event_secs = self._resolve_event_time(event)
            in_grace = event_secs is not None and event_secs < grace_seconds

            if (
                has_process
                and not has_logon
                and key not in logons
                and not skip_actor
                and not in_grace
            ):
                self.issues.append(
                    ValidationIssue(
                        severity="warning",
                        field_path=f"storyline.{idx}",
                        message=(
                            f"[{event.id}] Process event for '{actor}' on "
                            f"'{system}' with no prior logon"
                        ),
                        suggestion=(
                            "Add a logon/ssh_session/rdp_session event before this process event"
                        ),
                    )
                )

            if (
                has_logoff
                and not has_logon
                and key not in logons
                and not skip_actor
                and not in_grace
            ):
                self.issues.append(
                    ValidationIssue(
                        severity="warning",
                        field_path=f"storyline.{idx}",
                        message=(
                            f"[{event.id}] Logoff for '{actor}' on '{system}' with no prior logon"
                        ),
                        suggestion=("Add a logon event before this logoff event"),
                    )
                )

    def _validate_storyline_event_ids(self) -> None:
        """Check that all storyline events have unique IDs."""
        if not self.scenario.storyline:
            return

        seen_ids: dict[str, int] = {}
        for idx, event in enumerate(self.scenario.storyline):
            if event.id in seen_ids:
                self.issues.append(
                    ValidationIssue(
                        severity="error",
                        field_path=f"storyline.{idx}.id",
                        message=(
                            f"Duplicate event ID '{event.id}' "
                            f"(first seen at storyline.{seen_ids[event.id]})"
                        ),
                        suggestion="Each storyline event must have a unique ID",
                    )
                )
            else:
                seen_ids[event.id] = idx

    def _resolve_event_time(self, event) -> float | None:
        """Resolve a storyline event time to seconds from window start.

        Returns:
            Seconds from time_window.start, or None if unparseable.
        """
        from evidenceforge.utils.time import parse_duration

        time_str = event.time
        if time_str.startswith("+"):
            try:
                td = parse_duration(time_str[1:])
                return td.total_seconds()
            except (ValueError, TypeError):
                return None
        else:
            # Absolute ISO 8601
            try:
                from datetime import datetime

                dt = datetime.fromisoformat(time_str.replace("Z", "+00:00"))
                start = self.scenario.time_window.start
                if start.tzinfo is None:
                    start = start.replace(tzinfo=UTC)
                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=UTC)
                return (dt - start).total_seconds()
            except (ValueError, TypeError):
                return None

    def _validate_expansion_redundancy(self) -> None:
        """Warn when scenario manually specifies events the causal expansion engine auto-generates.

        Detects patterns where authors have manually specified prerequisite events
        (DNS queries, Kerberos TGT/TGS) that the causal expansion engine would
        auto-generate, creating potential duplicates.
        """
        if not self.scenario.storyline:
            return

        for step_idx, step in enumerate(self.scenario.storyline):
            event_types = [e.type for e in step.events]

            # Check for manual DNS + connection to same destination
            has_connection = False
            connection_dst_ips = set()
            has_dns_connection = False

            for event in step.events:
                if event.type == "connection":
                    if event.dst_port == 53:
                        has_dns_connection = True
                    else:
                        has_connection = True
                        connection_dst_ips.add(getattr(event, "dst_ip", None))

            if has_dns_connection and has_connection:
                self.issues.append(
                    ValidationIssue(
                        severity="warning",
                        field_path=f"storyline.{step_idx}.events",
                        message=(
                            "Storyline step contains both a DNS query (port 53 connection) "
                            "and a TCP connection. The causal expansion engine auto-generates "
                            "DNS lookups before TCP connections."
                        ),
                        suggestion=(
                            "Remove the manual DNS connection unless it is part of the "
                            "attack narrative (e.g., DNS tunneling). The engine will "
                            "auto-generate DNS evidence for the TCP connection."
                        ),
                    )
                )

            # Check for manual Kerberos events alongside logon
            has_logon = "logon" in event_types
            has_kerberos = any(
                t in event_types for t in ("kerberos_tgt", "kerberos_service_ticket")
            )

            if has_logon and has_kerberos:
                self.issues.append(
                    ValidationIssue(
                        severity="warning",
                        field_path=f"storyline.{step_idx}.events",
                        message=(
                            "Storyline step contains both a logon event and explicit "
                            "Kerberos TGT/TGS events. The causal expansion engine "
                            "auto-generates Kerberos events for domain logons."
                        ),
                        suggestion=(
                            "Remove the manual Kerberos events unless they are part of "
                            "the attack narrative (e.g., golden ticket forging). The "
                            "engine will auto-generate Kerberos evidence for the logon."
                        ),
                    )
                )

            # Check for RDP decomposition (rdp_session + separate connection/logon)
            has_rdp = "rdp_session" in event_types
            has_rdp_connection = any(
                e.type == "connection" and getattr(e, "dst_port", 0) == 3389 for e in step.events
            )
            has_rdp_logon = any(
                e.type == "logon" and getattr(e, "logon_type", 0) == 10 for e in step.events
            )

            if has_rdp and (has_rdp_connection or has_rdp_logon):
                self.issues.append(
                    ValidationIssue(
                        severity="warning",
                        field_path=f"storyline.{step_idx}.events",
                        message=(
                            "Storyline step contains an rdp_session event alongside "
                            "a separate port 3389 connection or type 10 logon. "
                            "The rdp_session event already generates both."
                        ),
                        suggestion=(
                            "Use either rdp_session (which auto-generates connection + logon) "
                            "or manually specify the connection and logon separately, not both."
                        ),
                    )
                )

    def _sort_issues(self) -> None:
        """Sort issues by storyline index, with non-storyline issues first."""
        import re

        def sort_key(issue: ValidationIssue) -> tuple[int, int, str]:
            match = re.match(r"storyline\.(\d+)", issue.field_path)
            if match:
                return (1, int(match.group(1)), issue.field_path)
            return (0, 0, issue.field_path)

        self.issues.sort(key=sort_key)
