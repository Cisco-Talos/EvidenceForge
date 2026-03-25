"""Activity generation package for log events.

Re-exports all public symbols so that existing imports like
``from evidenceforge.generation.activity import ActivityGenerator``
continue to work unchanged.
"""

from .generator import (
    _CONN_HISTORY,
    _CONN_STATES,
    _CONN_WEIGHTS,
    _TCP_CONN_ENTRIES,
    _TCP_CONN_WEIGHTS,
    _UDP_CONN_ENTRIES,
    _UDP_CONN_WEIGHTS,
    BASELINE_PATTERNS,
    CONN_STATE_DISTRIBUTION,
    PERSONA_APP_INDICES,
    PERSONA_APP_INDICES_LINUX,
    PERSONA_PROCESS_WEIGHTS,
    PROCESS_TEMPLATES,
    PROCESS_TEMPLATES_LINUX,
    TCP_CONN_STATE_DISTRIBUTION,
    UDP_CONN_STATE_DISTRIBUTION,
    ActivityGenerator,
)
from .helpers import (
    _QUERY_PARAMS,
    _QUERY_PARAMS_LINUX,
    _get_os_category,
    _get_rng,
    _parameterize_command,
)
from .network import (
    _AD_SRV_QUERIES,
    _CDN_RANGES,
    _HTTP_URI_STATUS_CACHE,
    _IPV6_MAP,
    _PROVIDER_IP_GROUPS,
    _SRV_PORT_MAP,
    EXTERNAL_IPS,
    REVERSE_DNS,
    _detect_ip_provider,
    _generate_internal_hostname,
    _generate_random_external_ip,
    _generate_random_hostname,
    _generate_rdns_name,
    _get_http_status,
    _ipv4_to_fake_ipv6,
    _is_invalid_network_connection,
    _is_private_ip,
)

__all__ = [
    "ActivityGenerator",
    "BASELINE_PATTERNS",
    "PROCESS_TEMPLATES",
    "PROCESS_TEMPLATES_LINUX",
    "PERSONA_PROCESS_WEIGHTS",
    "PERSONA_APP_INDICES",
    "PERSONA_APP_INDICES_LINUX",
    "TCP_CONN_STATE_DISTRIBUTION",
    "UDP_CONN_STATE_DISTRIBUTION",
    "CONN_STATE_DISTRIBUTION",
    "EXTERNAL_IPS",
    "REVERSE_DNS",
    "_get_rng",
    "_get_os_category",
    "_is_private_ip",
    "_is_invalid_network_connection",
    "_generate_random_external_ip",
    "_generate_random_hostname",
]
