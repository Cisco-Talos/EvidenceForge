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

"""Visibility model for cross-source coherence evaluation.

Determines which log formats each system should produce (based on OS)
and which network sensors observe traffic between systems.
"""

from evidenceforge.generation.network_visibility import NetworkVisibilityEngine
from evidenceforge.models.scenario import Scenario, System

# OS detection patterns (mirrors generation/activity.py)
_WINDOWS_PATTERNS = ["windows"]
_LINUX_PATTERNS = ["linux", "ubuntu", "centos", "debian", "rhel"]

# Web server service patterns
_WEB_SERVICE_PATTERNS = ["http", "iis", "nginx", "apache", "web"]


def _get_os_category(os_string: str) -> str:
    """Detect OS category from OS string."""
    os_lower = os_string.lower()
    if any(p in os_lower for p in _WINDOWS_PATTERNS):
        return "windows"
    if any(p in os_lower for p in _LINUX_PATTERNS):
        return "linux"
    return "unknown"


def _has_web_service(system: System) -> bool:
    """Check if a system runs a web server."""
    for svc in system.services:
        if any(p in svc.lower() for p in _WEB_SERVICE_PATTERNS):
            return True
    return False


class VisibilityModel:
    """Maps systems to expected log formats based on OS and network topology."""

    def __init__(self, scenario: Scenario, enabled_formats: set[str]):
        self._enabled = enabled_formats
        self._systems = {s.hostname: s for s in scenario.environment.systems}
        self._os_map: dict[str, str] = {}
        self._host_formats: dict[str, set[str]] = {}
        # Map FQDN variants back to bare hostname for lookups
        self._fqdn_to_bare: dict[str, str] = {}

        # Detect domain from scenario (same logic as generator)
        domain = getattr(scenario.environment, "domain", None)
        if not domain and scenario.environment.users:
            email = scenario.environment.users[0].email
            if email and "@" in email:
                domain = email.split("@", 1)[1]

        # Build per-host format expectations
        for system in scenario.environment.systems:
            os_cat = _get_os_category(system.os)
            self._os_map[system.hostname] = os_cat
            # Register lowercased bare hostname for case-insensitive lookups
            bare_lower = system.hostname.lower()
            if bare_lower != system.hostname:
                self._os_map[bare_lower] = os_cat
                self._fqdn_to_bare[bare_lower] = system.hostname

            # Also register FQDN variant
            if domain:
                fqdn = f"{system.hostname}.{domain}"
                self._os_map[fqdn] = os_cat
                self._fqdn_to_bare[fqdn] = system.hostname
                self._fqdn_to_bare[fqdn.lower()] = system.hostname
                self._systems[fqdn] = system

            formats: set[str] = set()
            if os_cat == "windows":
                formats.add("windows_event_security")
            elif os_cat == "linux":
                formats.add("syslog")
                formats.add("bash_history")

            # eCAR is optional on any OS
            if "ecar" in enabled_formats:
                formats.add("ecar")

            # Web access for web servers
            if _has_web_service(system) and "web_access" in enabled_formats:
                formats.add("web_access")

            # Only include formats that are actually enabled in the scenario
            resolved_formats = formats & enabled_formats
            self._host_formats[system.hostname] = resolved_formats
            if domain:
                self._host_formats[f"{system.hostname}.{domain}"] = resolved_formats

        # Network visibility engine
        self._network_engine = NetworkVisibilityEngine(
            network_config=scenario.environment.network,
            systems=scenario.environment.systems,
        )

    def resolve_hostname(self, hostname: str) -> str | None:
        """Resolve any hostname variant to the canonical bare hostname.

        Handles FQDN, bare hostname, and case-insensitive matching.
        Returns None if hostname is not recognized.
        """
        # Direct match (bare or FQDN)
        if hostname in self._systems:
            return self._fqdn_to_bare.get(hostname, hostname)
        # Case-insensitive / FQDN-to-bare via pre-built mappings
        lower = hostname.lower()
        if lower in self._fqdn_to_bare:
            return self._fqdn_to_bare[lower]
        return None

    def get_expected_formats(self, hostname: str) -> set[str]:
        """Get expected host-level log formats for a system."""
        result = self._host_formats.get(hostname)
        if result is not None:
            return result
        resolved = self.resolve_hostname(hostname)
        return self._host_formats.get(resolved, set()) if resolved else set()

    def get_expected_format_groups(
        self, hostname: str, event_types: list[str]
    ) -> list[tuple[str, set[str]]]:
        """Get format groups applicable to a storyline event on this host.

        Returns a list of (group_name, formats) tuples. The event should appear
        in at least one format from each applicable group.

        Groups:
          - host_local: formats installed on the host (windows_event_security,
            syslog, bash_history, ecar)
          - network: sensor-based network formats (zeek_*, snort, web_access,
            proxy_access)

        Event type determines which groups apply:
          - connection → host_local + network
          - ssh_session, rdp_session → host_local only (syslog/windows logs)
          - All other types → host_local only
        """
        host_formats = self._host_formats.get(hostname)
        if host_formats is None:
            resolved = self.resolve_hostname(hostname)
            host_formats = self._host_formats.get(resolved, set()) if resolved else set()
        if not host_formats:
            return []

        _HOST_LOCAL = {
            "windows_event_security",
            "windows_event_sysmon",
            "syslog",
            "bash_history",
            "ecar",
        }
        _NETWORK = {
            "zeek_conn",
            "zeek_dns",
            "zeek_http",
            "zeek_ssl",
            "zeek_dhcp",
            "snort_alert",
            "cisco_asa",
            "web_access",
            "proxy_access",
        }

        host_local = host_formats & _HOST_LOCAL
        # Network types apply if connection events are present
        network_types = {
            "connection",
            "dhcp_lease",
            "port_scan",
            "beacon",
            "dns_query",
            "web_scan",
            "credential_spray",
            "dga_queries",
            "dns_tunnel",
        }

        groups: list[tuple[str, set[str]]] = []
        if host_local:
            groups.append(("host_local", host_local))
        if network_types & set(event_types):
            # Include network group — these won't be in host_formats but
            # should be checked in the records if available
            groups.append(("network", _NETWORK))

        return groups

    def get_network_formats(self, src_ip: str, dst_ip: str) -> set[str]:
        """Get network log formats that should observe a connection."""
        formats = self._network_engine.get_log_formats_for_connection(src_ip, dst_ip)
        return formats & self._enabled

    def get_os_category(self, hostname: str) -> str:
        """Get OS category for a hostname (supports bare and FQDN)."""
        result = self._os_map.get(hostname)
        if result:
            return result
        # Try case-insensitive
        return self._os_map.get(hostname.lower(), "unknown")

    def get_system(self, hostname: str) -> System | None:
        """Get System object by hostname."""
        return self._systems.get(hostname)

    @property
    def hostnames(self) -> set[str]:
        """All known hostnames."""
        return set(self._systems.keys())
