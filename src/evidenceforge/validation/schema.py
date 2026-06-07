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
    "explicit_credentials",
    "workstation_lock",
    "workstation_unlock",
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


def _is_full_process_path(process_name: str) -> bool:
    """Return whether process_name looks like a full OS path."""
    return "/" in process_name or "\\" in process_name


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

    def __init__(self, scenario: Scenario, oob_hosts: tuple[str, ...] = ()):
        """Initialize validator with a scenario.

        Args:
            scenario: The scenario to validate
            oob_hosts: Operator-registered live-callback host(s) (from
                ``eforge generate --oob-host``) accepted by adversarial_payload literal
                value safety checks, so a fuzzer payload pointing at the operator's
                out-of-band server validates instead of being rejected as a real host.
        """
        self.scenario = scenario
        self.oob_hosts = tuple(oob_hosts)
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
        self._validate_proxy_output_topology()
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
        self._validate_spillage_events()
        self._validate_adversarial_payload_events()
        self._validate_storyline_linkability()
        self._validate_storyline_causal_order()
        self._validate_storyline_event_ids()
        self._validate_storyline_time_window()
        self._validate_expansion_redundancy()
        self._validate_process_network_pairing()
        self._validate_firewall_config()
        self._validate_observation_profile()
        self._sort_issues()
        return self.issues

    def has_errors(self) -> bool:
        """Check if any error-level issues were found.

        Returns:
            True if any errors found, False otherwise
        """
        return any(issue.severity == "error" for issue in self.issues)

    def _validate_observation_profile(self) -> None:
        """Validate that the scenario references a configured observation profile."""
        from evidenceforge.config.observation_profiles import observation_profile_names

        available = observation_profile_names()
        profile = self.scenario.observation_profile
        if profile not in available:
            self.issues.append(
                ValidationIssue(
                    severity="error",
                    field_path="observation_profile",
                    message=f"Unknown observation_profile: {profile}",
                    suggestion=(
                        "Use one of the configured observation profiles: "
                        f"{', '.join(sorted(available))}"
                    ),
                )
            )

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
        # Build set of users who have a system assigned to them
        assigned_users = {
            s.assigned_user for s in self.scenario.environment.systems if s.assigned_user
        }

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
            elif (
                not user.primary_system
                and user.username not in assigned_users
                and user.enabled
                and user.persona
            ):
                self.issues.append(
                    ValidationIssue(
                        severity="warning",
                        field_path=f"environment.users.{idx}.primary_system",
                        message=f"User '{user.username}' has no primary_system and no system is assigned to them",
                        suggestion="Assign a primary_system to ensure realistic logon/process ordering",
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
            "cisco_asa",
            "web_access",
            "proxy_access",
        }

        process_refs: set[tuple[str, str, str]] = set()
        incompatible_payload_states = {"S0", "REJ", "S1", "SH", "SHR", "RSTO", "RSTR"}

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

                if getattr(spec, "type", "") in {"connection", "beacon"}:
                    conn_state = getattr(spec, "conn_state", None)
                    has_payload_override = (
                        getattr(spec, "orig_bytes", None) is not None
                        or getattr(spec, "resp_bytes", None) is not None
                    )
                    if has_payload_override and conn_state in incompatible_payload_states:
                        self.issues.append(
                            ValidationIssue(
                                severity="warning",
                                field_path=f"storyline.{idx}.events.{spec_idx}.conn_state",
                                message=(
                                    f"{spec.type} specifies byte overrides with conn_state "
                                    f"'{conn_state}', but that state cannot reliably carry "
                                    "application payload bytes"
                                ),
                                suggestion=(
                                    "Use conn_state: SF for explicit payload sizing, or omit "
                                    "orig_bytes/resp_bytes for failed/handshake-only flows."
                                ),
                            )
                        )

                if getattr(spec, "type", "") == "process":
                    ref_key_base = (event.system, event.actor)
                    parent_ref = getattr(spec, "parent_ref", None)
                    if parent_ref is not None and (*ref_key_base, parent_ref) not in process_refs:
                        self.issues.append(
                            ValidationIssue(
                                severity="warning",
                                field_path=f"storyline.{idx}.events.{spec_idx}.parent_ref",
                                message=(
                                    f"Process parent_ref '{parent_ref}' has no earlier matching "
                                    "process_ref for the same storyline actor and system"
                                ),
                                suggestion=(
                                    "Define the parent process earlier with process_ref, or omit "
                                    "parent_ref to use the default shell/service parent inference."
                                ),
                            )
                        )
                    process_ref = getattr(spec, "process_ref", None)
                    if process_ref is not None:
                        ref_key = (*ref_key_base, process_ref)
                        if ref_key in process_refs:
                            self.issues.append(
                                ValidationIssue(
                                    severity="warning",
                                    field_path=f"storyline.{idx}.events.{spec_idx}.process_ref",
                                    message=(
                                        f"Duplicate process_ref '{process_ref}' for the same "
                                        "storyline actor and system"
                                    ),
                                    suggestion=(
                                        "Use unique process_ref values when later events need "
                                        "unambiguous parentage."
                                    ),
                                )
                            )
                        process_refs.add(ref_key)

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

        # Warn if externally exposed systems lack public_hostnames
        for segment in self.scenario.environment.network.segments:
            if segment.exposure not in ("external", "both"):
                continue
            for hostname in segment.systems:
                system = next(
                    (s for s in self.scenario.environment.systems if s.hostname == hostname),
                    None,
                )
                if system and not system.public_hostnames:
                    has_inbound_role = system.type in ("server", "domain_controller") or any(
                        r in (system.roles or [])
                        for r in ("web_server", "mail_server", "app_server")
                    )
                    if has_inbound_role:
                        self.issues.append(
                            ValidationIssue(
                                severity="info",
                                field_path=f"environment.systems[{hostname}].public_hostnames",
                                message=(
                                    f"Server '{hostname}' is on externally exposed segment "
                                    f"'{segment.name}' but has no public_hostnames. "
                                    f"Inbound HTTPS will have no TLS SNI or HTTP Host header."
                                ),
                                suggestion="Add public_hostnames for realistic external traffic",
                            )
                        )

    def _validate_network_sensors(self) -> None:
        """Validate network sensor cross-references."""
        if not self.scenario.environment.network:
            return

        from evidenceforge.events.dispatcher import FORMAT_GROUPS

        # Valid sensor log_formats: group aliases plus concrete emitter names.
        # This preserves "zeek" as the full-group alias while allowing narrow
        # sensor scopes such as "zeek_conn" and "zeek_dns".
        known_sensor_formats = set(FORMAT_GROUPS.keys()) | {"snort_alert", "cisco_asa"}
        for members in FORMAT_GROUPS.values():
            known_sensor_formats.update(members)

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
                if fmt not in known_sensor_formats:
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

        # Accept both group names (zeek, windows) and individual format names (zeek_conn)
        known_output_formats = set(FORMAT_GROUPS.keys()) | {
            "ecar",
            "syslog",
            "bash_history",
            "snort_alert",
            "cisco_asa",
            "web_access",
            "proxy_access",
        }
        for members in FORMAT_GROUPS.values():
            known_output_formats.update(members)

        for idx, log_spec in enumerate(self.scenario.output.logs):
            fmt = log_spec.get("format", "")
            if fmt and fmt not in known_output_formats:
                self.issues.append(
                    ValidationIssue(
                        severity="warning",
                        field_path=f"output.logs.{idx}.format",
                        message=f"Unknown output format '{fmt}'",
                        suggestion=f"Known formats: {', '.join(sorted(known_output_formats))}",
                    )
                )

    def _validate_proxy_output_topology(self) -> None:
        """Warn when proxy logs are requested but proxy topology/config is incomplete."""
        expanded_formats = self._get_expanded_formats()
        if "proxy_access" not in expanded_formats:
            return

        has_forward_proxy = any(
            "forward_proxy" in (system.roles or []) for system in self.scenario.environment.systems
        )
        if not has_forward_proxy:
            self.issues.append(
                ValidationIssue(
                    severity="warning",
                    field_path="output.logs",
                    message=(
                        "Format 'proxy_access' is requested but no system has "
                        "roles: [forward_proxy], so proxy access logs will not be generated"
                    ),
                    suggestion=(
                        "Add a proxy system with roles: [forward_proxy] and an appropriate "
                        "proxy service label such as forward_proxy or remove proxy_access "
                        "from output.logs"
                    ),
                )
            )
            return

        proxy_config = self.scenario.environment.proxy
        if "proxy" not in self.scenario.environment.model_fields_set:
            self.issues.append(
                ValidationIssue(
                    severity="warning",
                    field_path="environment.proxy",
                    message=(
                        "proxy_access is requested but environment.proxy is not set; "
                        "defaulting to transparent proxy mode"
                    ),
                    suggestion=(
                        "Add environment.proxy.mode: transparent or explicit. Use explicit "
                        "for PAC/browser-configured forward proxies."
                    ),
                )
            )

        if proxy_config.mode == "explicit" and "listener_port" not in proxy_config.model_fields_set:
            self.issues.append(
                ValidationIssue(
                    severity="warning",
                    field_path="environment.proxy.listener_port",
                    message=(
                        "Explicit proxy mode is configured without listener_port; "
                        "defaulting to 8080"
                    ),
                    suggestion=(
                        "Set environment.proxy.listener_port to the client-visible proxy "
                        "port, such as 8080 or a product-specific value."
                    ),
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
        link_local_span_segments: set[str] = set()
        for sensor in self.scenario.environment.network.sensors:
            from evidenceforge.events.dispatcher import expand_formats

            expanded_sensor_formats = expand_formats(sensor.log_formats)
            monitored_segments.update(sensor.monitoring_segments)
            if (
                sensor.type != "firewall"
                and sensor.placement == "span"
                and sensor.direction in {"bidirectional", "outbound"}
                and "zeek_conn" in expanded_sensor_formats
            ):
                link_local_span_segments.update(sensor.monitoring_segments)

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
            if segment.systems and segment.name not in link_local_span_segments:
                self.issues.append(
                    ValidationIssue(
                        severity="warning",
                        field_path=f"environment.network.segments.{idx}",
                        message=(
                            f"Segment '{segment.name}' has no SPAN-style Zeek sensor for "
                            "link-local traffic such as DHCP broadcast"
                        ),
                        suggestion=(
                            "Use placement: span on a Zeek sensor monitoring this segment if "
                            "you expect DHCP lease evidence from hosts there"
                        ),
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
                    process_name = getattr(spec, "process_name", "")

                    if process_name and not _is_full_process_path(process_name):
                        self.issues.append(
                            ValidationIssue(
                                severity="info",
                                field_path=f"storyline.{idx}.events.{spec_idx}.process_name",
                                message=(
                                    f"[{event.id}] Process name '{process_name}' is bare; "
                                    "generation will normalize it to a canonical full path"
                                ),
                                suggestion=(
                                    "Use a full path when you know it; otherwise a bare executable "
                                    "name is acceptable and will be resolved from EvidenceForge config"
                                ),
                            )
                        )
                    elif process_name:
                        from evidenceforge.generation.activity.application_catalog import (
                            resolve_image_path,
                        )

                        basename = process_name.rsplit("\\", 1)[-1].rsplit("/", 1)[-1]
                        resolved = resolve_image_path(basename, os_cat)
                        if resolved != basename and resolved.lower() != process_name.lower():
                            self.issues.append(
                                ValidationIssue(
                                    severity="warning",
                                    field_path=(f"storyline.{idx}.events.{spec_idx}.process_name"),
                                    message=(
                                        f"[{event.id}] Process path '{process_name}' differs "
                                        f"from configured canonical path '{resolved}'"
                                    ),
                                    suggestion=(
                                        "Prefer the configured canonical path, or add an "
                                        "application_catalog/system_processes overlay if this "
                                        "environment uses a different install path"
                                    ),
                                )
                            )

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

                # web_scan preset name cross-reference
                if event_type == "web_scan" and hasattr(spec, "preset") and spec.preset:
                    from evidenceforge.config.web_scan_presets import get_preset, list_preset_names

                    if get_preset(spec.preset) is None:
                        available = list_preset_names()
                        has_paths = hasattr(spec, "paths") and spec.paths
                        self.issues.append(
                            ValidationIssue(
                                severity="warning" if has_paths else "error",
                                field_path=f"storyline.{idx}.events.{spec_idx}.preset",
                                message=(
                                    f"[{event.id}] web_scan preset '{spec.preset}' not found "
                                    f"(available: {available})"
                                ),
                                suggestion="Check the preset name or provide explicit paths",
                            )
                        )

    def _validate_spillage_events(self) -> None:
        """Validate spillage events: surface/OS fit, family, value safety, formats."""
        if not self.scenario.storyline:
            return
        if not any(spec.type == "spillage" for ev in self.scenario.storyline for spec in ev.events):
            return  # nothing to do — avoid importing the generator below

        from evidenceforge.config.secret_families import family_names

        # Canonical non-interactive bash-user set, reused so the validator cannot
        # drift from the generator's actual bash-history suppression behaviour.
        from evidenceforge.generation.activity.generator import _NONINTERACTIVE_BASH_USERS
        from evidenceforge.generation.spillage import (
            HTTP_SURFACES,
            LINUX_ONLY_SURFACES,
            SURFACE_FORMATS,
            SpillageSafetyError,
            check_spillage_safety,
            choose_web_spillage_scheme,
            web_server_supported_schemes,
        )

        known_families = family_names()
        expanded_formats = self._get_expanded_formats()
        # http_* surfaces leak into a web server's access log, so one must exist.
        web_servers = [
            s for s in self.scenario.environment.systems if web_server_supported_schemes(s)
        ]
        has_web_server = bool(web_servers)

        for idx, event in enumerate(self.scenario.storyline):
            system = self._get_system(event.system)
            os_cat = _get_os_category(system.os) if system else "unknown"
            for spec_idx, spec in enumerate(event.events):
                if spec.type != "spillage":
                    continue
                field_path = f"storyline.{idx}.events.{spec_idx}"

                # shell_history/syslog are Linux-modeled; emitting them on Windows
                # would silently drop the credential while still labeling it in
                # ground truth — a phantom positive — so this is a hard error.
                # (process_command_line is cross-OS, so it is exempt.)
                if os_cat == "windows" and spec.surface in LINUX_ONLY_SURFACES:
                    self.issues.append(
                        ValidationIssue(
                            severity="error",
                            field_path=field_path,
                            message=(
                                f"[{event.id}] Spillage surface '{spec.surface}' is "
                                f"Linux-modeled but system '{event.system}' is windows; the "
                                "credential would not be emitted"
                            ),
                            suggestion="Target a Linux host for this spillage surface",
                        )
                    )

                # The credential is lost (but still ground-truthed) if the
                # surface's output format is not collected — phantom positive.
                required_fmt = SURFACE_FORMATS.get(spec.surface)
                if required_fmt and required_fmt not in expanded_formats:
                    self.issues.append(
                        ValidationIssue(
                            severity="error",
                            field_path=field_path,
                            message=(
                                f"[{event.id}] Spillage surface '{spec.surface}' needs output "
                                f"format '{required_fmt}' but it is not in output.logs; the "
                                "credential would not be emitted"
                            ),
                            suggestion=f"Add '{required_fmt}' to output.logs",
                        )
                    )

                # An http_* surface needs a web_server-role host to receive the
                # request and write the access log; without one the credential is
                # lost but still ground-truthed — phantom positive.
                if spec.surface in HTTP_SURFACES and not has_web_server:
                    self.issues.append(
                        ValidationIssue(
                            severity="error",
                            field_path=field_path,
                            message=(
                                f"[{event.id}] Spillage surface '{spec.surface}' needs a host "
                                "with role 'web_server' to record the request, but none exists; "
                                "the credential would not be emitted"
                            ),
                            suggestion="Add a system with roles: [web_server] to the environment",
                        )
                    )
                elif spec.surface in HTTP_SURFACES:
                    compatible_targets = [
                        s for s in web_servers if choose_web_spillage_scheme(s, spec.scheme)
                    ]
                    if not compatible_targets:
                        scheme_text = spec.scheme or "auto-selected http/https"
                        self.issues.append(
                            ValidationIssue(
                                severity="error",
                                field_path=field_path,
                                message=(
                                    f"[{event.id}] Spillage surface '{spec.surface}' needs a "
                                    f"web_server host compatible with scheme '{scheme_text}', "
                                    "but none exists; the credential would not be emitted"
                                ),
                                suggestion=(
                                    "Add a compatible service marker such as 'http', 'https', "
                                    "or both to a roles: [web_server] host"
                                ),
                            )
                        )

                # Non-interactive service accounts get no bash history, so a
                # shell_history spill for them would never land.
                if (
                    spec.surface == "shell_history"
                    and event.actor.lower() in _NONINTERACTIVE_BASH_USERS
                ):
                    self.issues.append(
                        ValidationIssue(
                            severity="error",
                            field_path=field_path,
                            message=(
                                f"[{event.id}] Spillage surface 'shell_history' actor "
                                f"'{event.actor}' is a non-interactive service account with no "
                                "bash history; the credential would not be emitted"
                            ),
                            suggestion="Use an interactive user actor for shell_history spillage",
                        )
                    )

                if spec.family is not None and spec.family not in known_families:
                    self.issues.append(
                        ValidationIssue(
                            severity="error",
                            field_path=field_path,
                            message=(
                                f"[{event.id}] Unknown spillage family '{spec.family}' "
                                f"(known: {sorted(known_families)})"
                            ),
                            suggestion="Use a known family or add one to the secret_families overlay",
                        )
                    )

                if spec.value is not None:
                    try:
                        check_spillage_safety(spec.value, family=None)
                    except SpillageSafetyError as exc:
                        self.issues.append(
                            ValidationIssue(
                                severity="error",
                                field_path=field_path,
                                message=f"[{event.id}] Unsafe spillage value: {exc}",
                                suggestion=(
                                    "Mark the value with a poison marker (e.g. "
                                    "EvidenceForgeFake) or use a vendor-published fake"
                                ),
                            )
                        )

    def _validate_adversarial_payload_events(self) -> None:
        """Validate adversarial_payload events: surface/OS fit, family↔surface, safety.

        Mirrors :meth:`_validate_spillage_events`, with one extra gate: a named
        family only models on the surfaces it declares, so a family/surface mismatch
        is rejected here rather than raising mid-generation.
        """
        if not self.scenario.storyline:
            return
        if not any(
            spec.type == "adversarial_payload"
            for ev in self.scenario.storyline
            for spec in ev.events
        ):
            return  # nothing to do — avoid importing the generator below

        from evidenceforge.config.payload_families import family_names, get_family
        from evidenceforge.generation.adversarial_payload import (
            HTTP_SURFACES,
            LINUX_ONLY_SURFACES,
            SURFACE_FORMATS,
            AdversarialPayloadSafetyError,
            check_payload_safety,
        )
        from evidenceforge.generation.spillage import (
            choose_web_spillage_scheme,
            web_server_supported_schemes,
        )

        known_families = family_names()
        expanded_formats = self._get_expanded_formats()
        # http_* surfaces leak into a web server's access log; one supporting a
        # compatible scheme must exist.
        web_servers = [
            s for s in self.scenario.environment.systems if web_server_supported_schemes(s)
        ]
        has_web_server = bool(web_servers)

        for idx, event in enumerate(self.scenario.storyline):
            system = self._get_system(event.system)
            os_cat = _get_os_category(system.os) if system else "unknown"
            for spec_idx, spec in enumerate(event.events):
                if spec.type != "adversarial_payload":
                    continue
                field_path = f"storyline.{idx}.events.{spec_idx}"

                # syslog_message is Linux-modeled; on Windows the payload would be
                # ground-truthed but never emitted — a phantom positive.
                if os_cat == "windows" and spec.surface in LINUX_ONLY_SURFACES:
                    self.issues.append(
                        ValidationIssue(
                            severity="error",
                            field_path=field_path,
                            message=(
                                f"[{event.id}] Adversarial payload surface '{spec.surface}' is "
                                f"Linux-modeled but system '{event.system}' is windows; the "
                                "payload would not be emitted"
                            ),
                            suggestion="Target a Linux host for this payload surface",
                        )
                    )

                # The payload is lost (but still ground-truthed) if the surface's
                # output format is not collected — phantom positive.
                required_fmt = SURFACE_FORMATS.get(spec.surface)
                if required_fmt and required_fmt not in expanded_formats:
                    self.issues.append(
                        ValidationIssue(
                            severity="error",
                            field_path=field_path,
                            message=(
                                f"[{event.id}] Adversarial payload surface '{spec.surface}' needs "
                                f"output format '{required_fmt}' but it is not in output.logs; the "
                                "payload would not be emitted"
                            ),
                            suggestion=f"Add '{required_fmt}' to output.logs",
                        )
                    )

                # An http_* surface needs a web_server-role host to record the request.
                if spec.surface in HTTP_SURFACES and not has_web_server:
                    self.issues.append(
                        ValidationIssue(
                            severity="error",
                            field_path=field_path,
                            message=(
                                f"[{event.id}] Adversarial payload surface '{spec.surface}' needs "
                                "a host with role 'web_server' to record the request, but none "
                                "exists; the payload would not be emitted"
                            ),
                            suggestion="Add a system with roles: [web_server] to the environment",
                        )
                    )
                elif spec.surface in HTTP_SURFACES:
                    # A web server exists, but it must serve the requested (or any
                    # auto-selectable) scheme, else the payload is labeled but never
                    # emitted — a phantom positive.
                    compatible_targets = [
                        s for s in web_servers if choose_web_spillage_scheme(s, spec.scheme)
                    ]
                    if not compatible_targets:
                        scheme_text = spec.scheme or "auto-selected http/https"
                        self.issues.append(
                            ValidationIssue(
                                severity="error",
                                field_path=field_path,
                                message=(
                                    f"[{event.id}] Adversarial payload surface '{spec.surface}' "
                                    f"needs a web_server host compatible with scheme "
                                    f"'{scheme_text}', but none exists; the payload would not be "
                                    "emitted"
                                ),
                                suggestion=(
                                    "Add a compatible service marker such as 'http', 'https', "
                                    "or both to a roles: [web_server] host"
                                ),
                            )
                        )

                if spec.family is not None and spec.family not in known_families:
                    self.issues.append(
                        ValidationIssue(
                            severity="error",
                            field_path=field_path,
                            message=(
                                f"[{event.id}] Unknown adversarial payload family '{spec.family}' "
                                f"(known: {sorted(known_families)})"
                            ),
                            suggestion=(
                                "Use a known family or add one to the payload_families overlay"
                            ),
                        )
                    )
                elif spec.family is not None:
                    # A family only models on the surfaces it declares; a mismatch
                    # would raise AdversarialPayloadSafetyError mid-generation.
                    fam = get_family(spec.family) or {}
                    fam_surfaces = set(fam.get("surfaces") or ())
                    if spec.surface not in fam_surfaces:
                        self.issues.append(
                            ValidationIssue(
                                severity="error",
                                field_path=field_path,
                                message=(
                                    f"[{event.id}] Adversarial payload family '{spec.family}' does "
                                    f"not model surface '{spec.surface}' "
                                    f"(declared: {sorted(fam_surfaces)})"
                                ),
                                suggestion=(
                                    "Choose a surface the family declares, or add it to the "
                                    "family's 'surfaces' in the payload_families overlay"
                                ),
                            )
                        )
                    if fam.get("proposed"):
                        self.issues.append(
                            ValidationIssue(
                                severity="warning",
                                field_path=field_path,
                                message=(
                                    f"[{event.id}] Adversarial payload family '{spec.family}' is "
                                    "marked 'proposed' (pending maintainer sign-off); it may "
                                    "change or be removed"
                                ),
                                suggestion=(
                                    "Use a locked family, or accept the proposed family knowingly"
                                ),
                            )
                        )

                if spec.value is not None:
                    try:
                        check_payload_safety(spec.value, family=None, oob_hosts=self.oob_hosts)
                    except AdversarialPayloadSafetyError as exc:
                        self.issues.append(
                            ValidationIssue(
                                severity="error",
                                field_path=field_path,
                                message=f"[{event.id}] Unsafe adversarial payload value: {exc}",
                                suggestion=(
                                    "Mark every line with a poison marker (e.g. EFORGE_TEST) and "
                                    "point any host at an RFC-reserved domain (e.g. .invalid)"
                                ),
                            )
                        )

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

    def _time_window_seconds(self) -> float | None:
        """Return configured generation window length in seconds, if resolvable."""
        from evidenceforge.utils.time import parse_duration

        if self.scenario.time_window.duration:
            try:
                return parse_duration(self.scenario.time_window.duration).total_seconds()
            except (ValueError, TypeError):
                return None
        if self.scenario.time_window.end:
            start = self.scenario.time_window.start
            end = self.scenario.time_window.end
            if start.tzinfo is None:
                start = start.replace(tzinfo=UTC)
            if end.tzinfo is None:
                end = end.replace(tzinfo=UTC)
            return (end - start).total_seconds()
        return None

    def _validate_storyline_time_window(self) -> None:
        """Warn when storyline steps are scheduled outside the generation window."""
        if not self.scenario.storyline:
            return

        window_seconds = self._time_window_seconds()
        if window_seconds is None:
            return

        for idx, event in enumerate(self.scenario.storyline):
            event_seconds = self._resolve_event_time(event)
            if event_seconds is None:
                continue
            if event_seconds < 0 or event_seconds > window_seconds:
                window_label = (
                    self.scenario.time_window.duration
                    if self.scenario.time_window.duration
                    else self.scenario.time_window.end
                )
                self.issues.append(
                    ValidationIssue(
                        severity="warning",
                        field_path=f"storyline.{idx}.time",
                        message=(
                            f"Storyline event time '{event.time}' falls outside "
                            f"the configured time_window ({window_label})"
                        ),
                        suggestion=(
                            "Extend time_window so baseline and all storyline evidence share "
                            "the same collection horizon, or move the storyline step inside it."
                        ),
                    )
                )

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

    def _validate_process_network_pairing(self) -> None:
        """Warn when process commands contain URLs without sibling connection events.

        A process event whose command line references a domain (e.g.,
        Invoke-WebRequest -Uri 'https://cdn-assets-update.com/...') should
        be accompanied by a connection event with ``hostname`` set so that
        DNS, SSL, and proxy logs are generated for that domain.
        """
        from evidenceforge.validation.url_extractor import extract_hostnames_from_command

        for step_idx, entry in enumerate(self.scenario.storyline):
            process_domains: set[str] = set()
            connection_hostnames: set[str] = set()
            for event in entry.events:
                if event.type == "process" and getattr(event, "command_line", None):
                    process_domains |= extract_hostnames_from_command(event.command_line)
                if event.type == "connection" and getattr(event, "hostname", None):
                    connection_hostnames.add(event.hostname.lower())
            missing = process_domains - connection_hostnames
            for domain in sorted(missing):
                self.issues.append(
                    ValidationIssue(
                        severity="warning",
                        field_path=f"storyline.{step_idx}.events",
                        message=(
                            f"Process command references '{domain}' but no sibling "
                            f"connection event has hostname: {domain}"
                        ),
                        suggestion=(
                            "Add a connection event with hostname set to ensure "
                            "the domain appears in DNS, SSL, HTTP, and proxy logs."
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

    def _validate_firewall_config(self) -> None:
        """Validate firewall-specific configuration on network sensors."""
        if not self.scenario.environment.network or not self.scenario.environment.network.sensors:
            return

        import ipaddress

        segment_names = {seg.name for seg in self.scenario.environment.network.segments}
        # Special keywords accepted in policy src/dst
        _SPECIAL_KEYWORDS = {"external", "any"}

        for idx, sensor in enumerate(self.scenario.environment.network.sensors):
            prefix = f"environment.network.sensors.{idx}"

            # Firewall without cisco_asa
            if sensor.type == "firewall" and "cisco_asa" not in sensor.log_formats:
                self.issues.append(
                    ValidationIssue(
                        severity="warning",
                        field_path=f"{prefix}.log_formats",
                        message=(
                            f"Firewall sensor '{sensor.name}' does not include "
                            f"'cisco_asa' in log_formats"
                        ),
                        suggestion="Add 'cisco_asa' to log_formats to generate firewall logs",
                    )
                )

            # Non-firewall with NAT rules
            if sensor.type != "firewall" and sensor.nat_rules:
                self.issues.append(
                    ValidationIssue(
                        severity="warning",
                        field_path=f"{prefix}.nat_rules",
                        message=(
                            f"Sensor '{sensor.name}' (type={sensor.type}) has "
                            f"nat_rules but only firewall-type sensors support NAT"
                        ),
                        suggestion="Set type to 'firewall' or remove nat_rules",
                    )
                )

            # Non-firewall with policy
            if sensor.type != "firewall" and sensor.policy:
                self.issues.append(
                    ValidationIssue(
                        severity="warning",
                        field_path=f"{prefix}.policy",
                        message=(
                            f"Sensor '{sensor.name}' (type={sensor.type}) has "
                            f"firewall policy rules but is not type 'firewall'"
                        ),
                        suggestion="Set type to 'firewall' or remove the policy",
                    )
                )

            # Validate interface mapping keys
            for iface_key in sensor.interfaces:
                if iface_key == "_default":
                    continue
                if iface_key not in segment_names:
                    self.issues.append(
                        ValidationIssue(
                            severity="warning",
                            field_path=f"{prefix}.interfaces.{iface_key}",
                            message=(
                                f"Interface mapping key '{iface_key}' does not "
                                f"match any defined network segment"
                            ),
                            suggestion=(f"Use one of: {', '.join(sorted(segment_names))}"),
                        )
                    )

            # Validate policy rule src/dst references
            for rule_idx, rule in enumerate(sensor.policy):
                for field_name in ("src", "dst"):
                    value = getattr(rule, field_name)
                    if value in _SPECIAL_KEYWORDS:
                        continue
                    if value in segment_names:
                        continue
                    # Check if it's a valid IP or CIDR
                    try:
                        ipaddress.ip_address(value)
                        continue
                    except ValueError:
                        pass
                    try:
                        ipaddress.ip_network(value, strict=False)
                        continue
                    except ValueError:
                        pass
                    self.issues.append(
                        ValidationIssue(
                            severity="warning",
                            field_path=(f"{prefix}.policy.{rule_idx}.{field_name}"),
                            message=(
                                f"Policy rule {field_name} '{value}' is not a "
                                f"known segment name, IP, or CIDR"
                            ),
                            suggestion=(
                                f"Use a segment name ({', '.join(sorted(segment_names))}), "
                                f"'external', 'any', an IP, or CIDR"
                            ),
                        )
                    )

            # Validate NAT rules
            for nat_idx, nat_rule in enumerate(sensor.nat_rules):
                # Warn if NAT rules on sensor without cisco_asa
                if "cisco_asa" not in sensor.log_formats:
                    self.issues.append(
                        ValidationIssue(
                            severity="warning",
                            field_path=f"{prefix}.nat_rules.{nat_idx}",
                            message=(
                                f"Sensor '{sensor.name}' has NAT rules but "
                                f"cisco_asa not in log_formats"
                            ),
                            suggestion="Add 'cisco_asa' to log_formats to emit NAT records",
                        )
                    )
                    break  # Only warn once per sensor

                # Validate src segment references
                for src_entry in nat_rule.src:
                    if src_entry in segment_names:
                        continue
                    try:
                        ipaddress.ip_address(src_entry)
                        continue
                    except ValueError:
                        pass
                    try:
                        ipaddress.ip_network(src_entry, strict=False)
                        continue
                    except ValueError:
                        pass
                    self.issues.append(
                        ValidationIssue(
                            severity="warning",
                            field_path=f"{prefix}.nat_rules.{nat_idx}.src",
                            message=(
                                f"NAT rule src '{src_entry}' references "
                                f"nonexistent segment or invalid IP/CIDR"
                            ),
                            suggestion=(
                                f"Use a segment name ({', '.join(sorted(segment_names))}), "
                                f"an IP, or CIDR"
                            ),
                        )
                    )

                # Static NAT: warn if real_ip is missing
                if nat_rule.type == "static" and not nat_rule.real_ip:
                    self.issues.append(
                        ValidationIssue(
                            severity="warning",
                            field_path=f"{prefix}.nat_rules.{nat_idx}.real_ip",
                            message=(
                                "Static NAT rule missing real_ip — "
                                "cannot determine which host to translate"
                            ),
                            suggestion="Set real_ip to the internal IP of the server",
                        )
                    )

        # Validate public_cidrs: warn if VIPs fall outside declared ranges
        network = self.scenario.environment.network
        if network and network.public_cidrs:
            public_nets = []
            for cidr_str in network.public_cidrs:
                try:
                    public_nets.append(ipaddress.ip_network(cidr_str, strict=False))
                except ValueError:
                    pass
            if public_nets:
                for sensor in network.sensors:
                    if sensor.type != "firewall":
                        continue
                    for nat_rule in sensor.nat_rules:
                        if nat_rule.type == "static" and nat_rule.mapped_ip:
                            try:
                                vip = ipaddress.ip_address(nat_rule.mapped_ip)
                                if not any(vip in net for net in public_nets):
                                    self.issues.append(
                                        ValidationIssue(
                                            severity="warning",
                                            field_path="environment.network.public_cidrs",
                                            message=(
                                                f"Static NAT VIP {nat_rule.mapped_ip} "
                                                f"falls outside declared public_cidrs"
                                            ),
                                            suggestion=(
                                                "Add the VIP's CIDR to public_cidrs or "
                                                "adjust the NAT rule's mapped_ip"
                                            ),
                                        )
                                    )
                            except ValueError:
                                pass
