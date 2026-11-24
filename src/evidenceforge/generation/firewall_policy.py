"""Evaluate the same ordered firewall rules for legacy and routed traffic."""

from collections.abc import Mapping
from ipaddress import IPv4Network, IPv6Network

from evidenceforge.models.scenario import NetworkSensor


def evaluate_firewall_policy(
    src_ip: str,
    dst_ip: str,
    dst_port: int,
    sensor: NetworkSensor,
    segment_cidrs: Mapping[str, IPv4Network | IPv6Network],
) -> str:
    """Return the first matching policy action or the firewall default."""
    import ipaddress as _ipaddress

    def _resolve_segment(ip: str) -> str:
        """Resolve an IP to a segment name, or 'external' if not in any."""
        for seg_name, cidr in segment_cidrs.items():
            try:
                if _ipaddress.ip_address(ip) in cidr:
                    return seg_name
            except (ValueError, KeyError):
                continue
        return "external"

    def _matches_specifier(ip: str, ip_segment: str, spec: str) -> bool:
        """Check if an IP/segment matches a rule specifier."""
        if spec == "any":
            return True
        if spec == "external":
            return ip_segment == "external"
        if spec == ip_segment:
            return True
        # Try IP match
        try:
            if _ipaddress.ip_address(ip) == _ipaddress.ip_address(spec):
                return True
        except ValueError:
            pass
        # Try CIDR match
        try:
            if _ipaddress.ip_address(ip) in _ipaddress.ip_network(spec, strict=False):
                return True
        except ValueError:
            pass
        return False

    src_seg = _resolve_segment(src_ip)
    dst_seg = _resolve_segment(dst_ip)

    for rule in sensor.policy:
        if not _matches_specifier(src_ip, src_seg, rule.src):
            continue
        if not _matches_specifier(dst_ip, dst_seg, rule.dst):
            continue
        # Check port (empty list = any)
        if rule.ports:
            port_list = [int(p) if isinstance(p, int) else p for p in rule.ports]
            if "any" not in port_list and dst_port not in port_list:
                continue
        return rule.action

    return sensor.default_action
