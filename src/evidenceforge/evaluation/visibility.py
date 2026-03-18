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

    def get_expected_formats(self, hostname: str) -> set[str]:
        """Get expected host-level log formats for a system."""
        return self._host_formats.get(hostname, set())

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
