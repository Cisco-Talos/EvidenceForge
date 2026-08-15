# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Authoritative inventory of supported project-local configuration overlays."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import asdict, dataclass
from types import MappingProxyType
from typing import Literal

OverlayOwnership = Literal["project-only"]
OverlayMergeMode = Literal[
    "append-list",
    "deep-mapping",
    "keyed-entry",
    "mixed",
    "named-object-replace",
    "persona-deep-merge",
    "specialized-safety",
    "whole-section-replace",
]


@dataclass(frozen=True, slots=True)
class ConfigOverlayFamily:
    """Stable metadata for one supported project-local overlay family."""

    relative_path: str
    ownership: OverlayOwnership
    merge_mode: OverlayMergeMode
    validation: str
    reference: str
    summary: str


_VALIDATION_COMMAND = "eforge validate-config"


def _family(
    relative_path: str,
    merge_mode: OverlayMergeMode,
    reference: str,
    summary: str,
) -> ConfigOverlayFamily:
    """Build one immutable project-overlay family record."""

    return ConfigOverlayFamily(
        relative_path=relative_path,
        ownership="project-only",
        merge_mode=merge_mode,
        validation=_VALIDATION_COMMAND,
        reference=reference,
        summary=summary,
    )


_FAMILIES = (
    _family(
        "personas/*.yaml",
        "persona-deep-merge",
        "config-personas.md",
        "Persona activity, work-hour, risk, and application-use defaults.",
    ),
    _family(
        "activity/application_catalog.yaml",
        "keyed-entry",
        "config-apps-processes.md",
        "Application identities, platform commands, modules, and selection constraints.",
    ),
    _family(
        "activity/auth_noise.yaml",
        "deep-mapping",
        "config-host-activity.md",
        "Scheduled stale credentials and service-account delegation noise.",
    ),
    _family(
        "activity/bash_commands.yaml",
        "deep-mapping",
        "config-host-activity.md",
        "Linux command pools shared by persona and role names.",
    ),
    _family(
        "activity/beacon_profiles.yaml",
        "deep-mapping",
        "config-dns-network.md",
        "Deterministic command-and-control beacon traffic profiles.",
    ),
    _family(
        "activity/calltrace_patterns.yaml",
        "whole-section-replace",
        "config-apps-processes.md",
        "Windows ProcessAccess CallTrace patterns and source families.",
    ),
    _family(
        "activity/command_parameter_pools.yaml",
        "deep-mapping",
        "config-dns-network.md",
        "Command-template URL, host, and query parameter pools.",
    ),
    _family(
        "activity/create_remote_thread_patterns.yaml",
        "mixed",
        "config-apps-processes.md",
        "CreateRemoteThread pair, start-location, and target override pools.",
    ),
    _family(
        "activity/dns_registry.yaml",
        "mixed",
        "config-dns-network.md",
        "DNS domains, tags, long-tail behavior, and address pools.",
    ),
    _family(
        "activity/edr_pools.yaml",
        "whole-section-replace",
        "config-apps-processes.md",
        "Endpoint file, registry, software, identity, and ownership pools.",
    ),
    _family(
        "activity/email_background.yaml",
        "keyed-entry",
        "config-dns-network.md",
        "Baseline email domains and local-part identity pools.",
    ),
    _family(
        "activity/endpoint_noise.yaml",
        "deep-mapping",
        "config-host-activity.md",
        "Endpoint registry, process, flow-identity, and file-churn noise.",
    ),
    _family(
        "activity/external_actor_profiles.yaml",
        "keyed-entry",
        "config-dns-network.md",
        "External actor IP pools used when scenarios omit concrete identities.",
    ),
    _family(
        "activity/extra_syslog_messages.yaml",
        "append-list",
        "config-host-activity.md",
        "Additional parameterized baseline syslog program messages.",
    ),
    _family(
        "activity/host_activity_profiles.yaml",
        "deep-mapping",
        "config-host-activity.md",
        "Host-, role-, persona-, and artifact-specific activity rates.",
    ),
    _family(
        "activity/http_file_profiles.yaml",
        "deep-mapping",
        "config-dns-network.md",
        "HTTP file types, request profiles, and multipart behavior.",
    ),
    _family(
        "activity/ids_signatures.yaml",
        "keyed-entry",
        "config-ids.md",
        "Curated source-native IDS signatures and default cadence policies.",
    ),
    _family(
        "activity/kerberos_realism.yaml",
        "deep-mapping",
        "config-host-activity.md",
        "Kerberos outcome, certificate, and transport realism profiles.",
    ),
    _family(
        "activity/mail_public_identities.yaml",
        "mixed",
        "config-dns-network.md",
        "Public SMTP provider and reserved-domain replacement identities.",
    ),
    _family(
        "activity/network_params.yaml",
        "mixed",
        "config-dns-network.md",
        "Network identity, DNS, NTP, scanner, tunnel, proxy, and SMB-owner pools.",
    ),
    _family(
        "activity/observation_profiles.yaml",
        "deep-mapping",
        "config-host-activity.md",
        "Source collection coverage and delay profiles.",
    ),
    _family(
        "activity/payload_families.yaml",
        "specialized-safety",
        "config-host-activity.md",
        "Safe adversarial payload fixture families and poison markers.",
    ),
    _family(
        "activity/process_access_patterns.yaml",
        "append-list",
        "config-apps-processes.md",
        "Benign Windows ProcessAccess source-target pairs.",
    ),
    _family(
        "activity/process_network_map.yaml",
        "append-list",
        "config-apps-processes.md",
        "Process-to-network correlation mappings.",
    ),
    _family(
        "activity/proxy_phase_profiles.yaml",
        "deep-mapping",
        "config-dns-network.md",
        "Explicit-proxy resolver and transaction phase timing.",
    ),
    _family(
        "activity/proxy_uri_templates.yaml",
        "deep-mapping",
        "config-dns-network.md",
        "Domain-, tag-, and generic proxy URI templates.",
    ),
    _family(
        "activity/proxy_user_agents.yaml",
        "deep-mapping",
        "config-dns-network.md",
        "Proxy User-Agent pools and domain-specific overrides.",
    ),
    _family(
        "activity/public_dns_profiles.yaml",
        "mixed",
        "config-dns-network.md",
        "Public nameserver, mail, and AAAA answer profiles.",
    ),
    _family(
        "activity/rsat_tools.yaml",
        "keyed-entry",
        "config-apps-processes.md",
        "Remote Server Administration Tools metadata and activity weights.",
    ),
    _family(
        "activity/secret_families.yaml",
        "specialized-safety",
        "config-host-activity.md",
        "Safe synthetic secret fixture families and network allowlists.",
    ),
    _family(
        "activity/site_maps.yaml",
        "deep-mapping",
        "config-dns-network.md",
        "Domain-, tag-, and generic web navigation paths.",
    ),
    _family(
        "activity/snort_classifications.yaml",
        "whole-section-replace",
        "config-ids.md",
        "Snort classtype display descriptions.",
    ),
    _family(
        "activity/smb_profiles.yaml",
        "deep-mapping",
        "config-host-activity.md",
        "SMB client processes, Samba daemon identity, wire filesystems, and audit profiles.",
    ),
    _family(
        "activity/service_process_profiles.yaml",
        "deep-mapping",
        "config-apps-processes.md",
        "Resident service manager and worker process ancestry profiles.",
    ),
    _family(
        "activity/spawn_rules.yaml",
        "deep-mapping",
        "config-apps-processes.md",
        "OS-specific process spawn relationships and command templates.",
    ),
    _family(
        "activity/storage_catalog.yaml",
        "deep-mapping",
        "config-dns-network.md",
        "SMB storage population sizes and portable file vocabulary.",
    ),
    _family(
        "activity/suspicious_benign.yaml",
        "keyed-entry",
        "config-dns-network.md",
        "Benign suspicious-looking DNS and connection destinations.",
    ),
    _family(
        "activity/sysmon_filters.yaml",
        "whole-section-replace",
        "config-apps-processes.md",
        "Sysmon source-observation filters by event family.",
    ),
    _family(
        "activity/system_processes.yaml",
        "deep-mapping",
        "config-apps-processes.md",
        "System process, service, module, and scheduled-task pools.",
    ),
    _family(
        "activity/systemd_schedules.yaml",
        "append-list",
        "config-host-activity.md",
        "Linux service timer and cron-style schedules.",
    ),
    _family(
        "activity/timing_profiles.yaml",
        "deep-mapping",
        "config-host-activity.md",
        "Cross-source timing relationships and observation envelopes.",
    ),
    _family(
        "activity/tls_issuers.yaml",
        "mixed",
        "config-dns-network.md",
        "TLS issuer profiles and domain-to-CA mappings.",
    ),
    _family(
        "activity/tls_realism.yaml",
        "deep-mapping",
        "config-dns-network.md",
        "TLS SAN, serial, OCSP, chain, and destination realism.",
    ),
    _family(
        "activity/traffic_profiles.yaml",
        "deep-mapping",
        "config-dns-network.md",
        "Role- and persona-specific baseline connection profiles.",
    ),
    _family(
        "activity/traffic_rates.yaml",
        "deep-mapping",
        "config-host-activity.md",
        "Low, medium, and high baseline activity rates.",
    ),
    _family(
        "activity/web_scan_presets.yaml",
        "named-object-replace",
        "config-dns-network.md",
        "Named web scanner paths, rates, User-Agents, and IDS metadata.",
    ),
    _family(
        "activity/web_session_profiles.yaml",
        "deep-mapping",
        "config-dns-network.md",
        "Web visitor classes, methods, paths, headers, and User-Agent pools.",
    ),
    _family(
        "activity/windows_auth_realism.yaml",
        "deep-mapping",
        "config-host-activity.md",
        "Windows lock, policy refresh, failed-logon, and privilege behavior.",
    ),
)

CONFIG_OVERLAY_FAMILIES: Mapping[str, ConfigOverlayFamily] = MappingProxyType(
    {family.relative_path: family for family in _FAMILIES}
)


def config_family_inventory() -> dict[str, dict[str, str]]:
    """Return a deterministic JSON-compatible copy of the overlay-family registry."""

    return {
        relative_path: asdict(CONFIG_OVERLAY_FAMILIES[relative_path])
        for relative_path in sorted(CONFIG_OVERLAY_FAMILIES)
    }
