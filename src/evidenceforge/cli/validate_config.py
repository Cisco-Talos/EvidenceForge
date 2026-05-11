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

"""Validate EvidenceForge config files for integrity and cross-references.

Runs integrity checks across all config YAML files (activity, personas,
formats, evaluation) and reports errors, warnings, and info items.
"""

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from evidenceforge.config import (
    get_activity_directory,
    get_evaluation_directory,
    get_formats_directory,
    get_personas_directory,
)

VALID_RISK_PROFILES = frozenset({"low", "medium", "high"})
VALID_BROWSING_INTENSITIES = frozenset({"light", "normal", "heavy"})

REQUIRED_PERSONA_FIELDS = frozenset(
    {
        "name",
        "description",
        "typical_activities",
        "work_hours",
        "application_usage",
        "risk_profile",
        "browsing_intensity",
    }
)


@dataclass
class Issue:
    """A single validation issue."""

    severity: str  # ERROR, WARNING, INFO
    file: str
    message: str


@dataclass
class ValidationResult:
    """Result of config validation."""

    issues: list[Issue] = field(default_factory=list)
    files_checked: int = 0

    @property
    def errors(self) -> list[Issue]:
        return [i for i in self.issues if i.severity == "ERROR"]

    @property
    def warnings(self) -> list[Issue]:
        return [i for i in self.issues if i.severity == "WARNING"]

    @property
    def infos(self) -> list[Issue]:
        return [i for i in self.issues if i.severity == "INFO"]


def _safe_load_yaml(path: Path) -> tuple[Any, str | None]:
    """Load YAML file, returning (data, error_message)."""
    try:
        with open(path) as f:
            data = yaml.safe_load(f)
        return data, None
    except Exception as e:
        return None, str(e)


def validate_config() -> ValidationResult:
    """Run all 27 validation checks across config files.

    Uses the same loader paths the engine uses (including overlay merges).
    """
    result = ValidationResult()
    activity_dir = get_activity_directory()
    personas_dir = get_personas_directory()
    formats_dir = get_formats_directory()
    evaluation_dir = get_evaluation_directory()

    # --- Pre-check: Validate overlay files first ---
    # Overlay files must parse cleanly before merged loaders use them.
    # If an overlay file has bad YAML, report it as an error rather than
    # letting it crash the merged loaders.
    from evidenceforge.config.overlay import get_overlay_directory

    overlay_dir = get_overlay_directory()
    overlay_yaml_files: list[Path] = []
    if overlay_dir and overlay_dir.is_dir():
        overlay_yaml_files = sorted(overlay_dir.rglob("*.yaml"))

    # File-scoped overlay structure schemas.
    # Maps overlay file path → expected field types.
    # "list_fields": {field_name: key_field_or_None} — must be list of dicts
    # "dict_fields": {field_names} — must be dicts
    _OVERLAY_FILE_SCHEMAS: dict[str, dict] = {
        "activity/dns_registry.yaml": {
            "list_fields": {"domains": "domain", "cdn_ranges": None},
            "dict_fields": {"valid_tags", "long_tail", "ipv6_map"},
        },
        "activity/application_catalog.yaml": {
            "list_fields": {"applications": "id"},
        },
        "activity/traffic_profiles.yaml": {
            "dict_fields": {"role_traffic", "persona_traffic"},
        },
        "activity/spawn_rules.yaml": {
            "dict_fields": {"windows", "linux"},
        },
        "activity/proxy_uri_templates.yaml": {
            "dict_fields": {"domains", "tags", "generic", "search_terms"},
        },
        "activity/proxy_user_agents.yaml": {
            "dict_fields": {"domain_overrides", "workstation", "server"},
        },
        "activity/site_maps.yaml": {
            "dict_fields": {"domains", "tags", "generic", "search_terms"},
        },
        "activity/process_network_map.yaml": {
            "list_fields": {"mappings": None},
        },
        "activity/process_access_patterns.yaml": {
            "list_fields": {"baseline_pairs": None},
        },
        "activity/create_remote_thread_patterns.yaml": {
            "list_fields": {"baseline_pairs": None},
            "dict_fields": {"start_locations", "target_overrides"},
        },
        "activity/system_processes.yaml": {
            "dict_fields": {
                "system_services",
                "system_binaries",
                "common_loaded_modules",
                "process_loaded_modules",
            },
            "list_fields": {"scheduled_tasks": None},
        },
        "activity/systemd_schedules.yaml": {
            "list_fields": {"schedules": "service"},
        },
        "activity/extra_syslog_messages.yaml": {
            "list_fields": {"programs": None},
        },
        "activity/tls_issuers.yaml": {
            "list_fields": {"issuers": "name"},
            "dict_fields": {"domain_ca_overrides"},
        },
        "activity/tls_realism.yaml": {
            "dict_fields": {"san", "ocsp", "certificate_chains", "destinations"},
        },
        "activity/smb_file_transfers.yaml": {
            "list_fields": {"mime_types": None, "analyzer_sets": None},
        },
        "activity/network_params.yaml": {
            "list_fields": {"oui_prefixes": None, "public_ntp_servers": "name"},
        },
        "activity/windows_auth_realism.yaml": {
            "dict_fields": {"workstation_lock"},
        },
        "activity/bash_commands.yaml": {
            # All top-level keys are valid (persona/role names + common/params/keyboard_adjacency)
            # No structural constraints — skip unexpected-key check
        },
        "activity/sysmon_filters.yaml": {
            "dict_fields": {
                "network_connect",
                "image_loaded",
                "file_create",
                "registry_event",
                "dns_query",
            },
        },
        "activity/calltrace_patterns.yaml": {
            "list_fields": {"patterns": None},
        },
        "activity/edr_pools.yaml": {
            "list_fields": {"file_side_effect_profiles": None},
            "string_list_fields": {
                "file_paths_windows",
                "file_paths_linux",
                "dll_pool",
            },
        },
        "activity/ids_signatures.yaml": {
            "list_fields": {"signatures": None},
        },
        "activity/web_scan_presets.yaml": {
            "dict_fields": {"presets"},
        },
        "activity/traffic_rates.yaml": {
            "dict_fields": {"low", "medium", "high"},
        },
        "activity/timing_profiles.yaml": {
            "dict_fields": {"relationships", "windows_event_time"},
        },
    }

    overlay_errors = False
    for path in overlay_yaml_files:
        data, err = _safe_load_yaml(path)
        rel_path = str(path.relative_to(overlay_dir))
        if err:
            result.issues.append(Issue("ERROR", f"overlay/{rel_path}", f"YAML parse error: {err}"))
            overlay_errors = True
        elif data is None:
            result.issues.append(Issue("ERROR", f"overlay/{rel_path}", "File is empty"))
            overlay_errors = True
        elif not isinstance(data, dict):
            result.issues.append(
                Issue(
                    "ERROR",
                    f"overlay/{rel_path}",
                    f"Expected a YAML mapping at root, got {type(data).__name__}",
                )
            )
            overlay_errors = True
        else:
            # Look up file-specific schema
            file_schema = _OVERLAY_FILE_SCHEMAS.get(rel_path)

            # Reject unknown overlay files (personas/ handled separately below)
            if file_schema is None and not rel_path.startswith("personas/"):
                result.issues.append(
                    Issue(
                        "ERROR",
                        f"overlay/{rel_path}",
                        "Unknown overlay file — not a recognized config path. Check filename for typos.",
                    )
                )
                overlay_errors = True
                continue

            if file_schema is None:
                continue  # personas handled in separate pre-check

            list_fields = file_schema.get("list_fields", {})
            dict_fields = file_schema.get("dict_fields", set())

            # Reject unexpected top-level keys (they will be silently ignored by the engine)
            string_list_fields = file_schema.get("string_list_fields", set())
            known_keys = set(list_fields.keys()) | dict_fields | set(string_list_fields)
            if known_keys:
                for key in data:
                    if key not in known_keys and key != "_replace":
                        result.issues.append(
                            Issue(
                                "ERROR",
                                f"overlay/{rel_path}",
                                f'Unexpected top-level key "{key}" — this will be ignored by the engine. Check for typos.',
                            )
                        )
                        overlay_errors = True

            # Check list fields for correct structure
            for field_name, key_field in list_fields.items():
                if field_name in data:
                    value = data[field_name]
                    if not isinstance(value, list):
                        result.issues.append(
                            Issue(
                                "ERROR",
                                f"overlay/{rel_path}",
                                f'Field "{field_name}" should be a list, got {type(value).__name__}',
                            )
                        )
                        overlay_errors = True
                    else:
                        for i, item in enumerate(value):
                            if not isinstance(item, dict):
                                result.issues.append(
                                    Issue(
                                        "ERROR",
                                        f"overlay/{rel_path}",
                                        f'"{field_name}" entry #{i + 1} should be a mapping, got {type(item).__name__}',
                                    )
                                )
                                overlay_errors = True
                            elif key_field and key_field not in item:
                                result.issues.append(
                                    Issue(
                                        "ERROR",
                                        f"overlay/{rel_path}",
                                        f'"{field_name}" entry #{i + 1} missing required "{key_field}" field',
                                    )
                                )
                                overlay_errors = True

                        # Check for duplicate keys within this overlay list
                        if key_field:
                            seen_overlay_keys: dict[str, int] = {}
                            for j, item in enumerate(value):
                                if isinstance(item, dict) and key_field in item:
                                    k = item[key_field]
                                    if k in seen_overlay_keys:
                                        result.issues.append(
                                            Issue(
                                                "ERROR",
                                                f"overlay/{rel_path}",
                                                f'Duplicate {key_field}="{k}" in "{field_name}" (entries #{seen_overlay_keys[k]} and #{j + 1}) — last entry wins, first is lost',
                                            )
                                        )
                                        overlay_errors = True
                                    seen_overlay_keys[k] = j + 1

            # Check dict fields for correct structure
            for field_name in dict_fields:
                if field_name in data and not isinstance(data[field_name], dict):
                    result.issues.append(
                        Issue(
                            "ERROR",
                            f"overlay/{rel_path}",
                            f'Field "{field_name}" should be a mapping, got {type(data[field_name]).__name__}',
                        )
                    )
                    overlay_errors = True

            # Check string list fields (lists of plain strings, e.g., edr_pools paths)
            for field_name in string_list_fields:
                if field_name in data:
                    value = data[field_name]
                    if not isinstance(value, list):
                        result.issues.append(
                            Issue(
                                "ERROR",
                                f"overlay/{rel_path}",
                                f'Field "{field_name}" should be a list, got {type(value).__name__}',
                            )
                        )
                        overlay_errors = True
                    else:
                        for i, item in enumerate(value):
                            if not isinstance(item, str):
                                result.issues.append(
                                    Issue(
                                        "ERROR",
                                        f"overlay/{rel_path}",
                                        f'"{field_name}" entry #{i + 1} should be a string, got {type(item).__name__}',
                                    )
                                )
                                overlay_errors = True

    # Validate overlay persona files specifically (one-file-per-persona pattern)
    if overlay_dir:
        overlay_personas_dir = overlay_dir / "personas"
        if overlay_personas_dir.is_dir():
            for persona_file in sorted(overlay_personas_dir.glob("*.yaml")):
                rel_path = str(persona_file.relative_to(overlay_dir))
                pdata, perr = _safe_load_yaml(persona_file)
                if perr:
                    continue  # Already caught in YAML health check above
                if pdata is None:
                    continue  # Already caught above
                if not isinstance(pdata, dict):
                    result.issues.append(
                        Issue(
                            "ERROR",
                            f"overlay/{rel_path}",
                            f"Persona file should be a mapping, got {type(pdata).__name__}",
                        )
                    )
                    overlay_errors = True
                elif "name" not in pdata:
                    result.issues.append(
                        Issue(
                            "ERROR",
                            f"overlay/{rel_path}",
                            'Persona file missing required "name" field — it will be silently ignored by the loader',
                        )
                    )
                    overlay_errors = True
                elif pdata["name"] != persona_file.stem:
                    result.issues.append(
                        Issue(
                            "ERROR",
                            f"overlay/{rel_path}",
                            f'Persona name "{pdata["name"]}" does not match filename "{persona_file.stem}" — filename must match the name field',
                        )
                    )
                    overlay_errors = True

    if overlay_errors:
        # Cannot proceed with merged loading — overlay files would crash loaders
        result.files_checked = len(overlay_yaml_files)
        return result

    # Load all data through overlay-aware loaders for consistency.
    # Every config file should be loaded via its loader (not raw yaml.safe_load)
    # so that overlay customizations are visible to validation.
    from evidenceforge.generation.activity.application_catalog import load_catalog
    from evidenceforge.generation.activity.create_remote_thread_patterns import (
        load_create_remote_thread_config,
        load_create_remote_thread_patterns,
    )
    from evidenceforge.generation.activity.dns_registry import load_dns_registry
    from evidenceforge.generation.activity.ids_signatures import load_ids_signatures
    from evidenceforge.generation.activity.process_access_patterns import (
        load_process_access_patterns,
    )
    from evidenceforge.generation.activity.process_network import load_process_network_map
    from evidenceforge.generation.activity.proxy_uri import load_proxy_uri_templates
    from evidenceforge.generation.activity.proxy_user_agents import load_proxy_user_agents
    from evidenceforge.generation.activity.site_maps import load_site_maps
    from evidenceforge.generation.activity.spawn_rules import load_spawn_rules
    from evidenceforge.generation.activity.system_processes import load_system_processes
    from evidenceforge.generation.activity.timing_profiles import load_timing_profiles
    from evidenceforge.generation.activity.tls_realism import load_tls_realism
    from evidenceforge.generation.activity.traffic_profiles import load_traffic_profiles
    from evidenceforge.generation.activity.windows_auth_realism import load_windows_auth_realism

    dns_data = load_dns_registry()
    ids_data = load_ids_signatures()
    catalog_data = load_catalog()
    traffic_data = load_traffic_profiles()
    spawn_data = load_spawn_rules()
    process_net_data = load_process_network_map()
    process_access_data = load_process_access_patterns()
    create_remote_thread_data = load_create_remote_thread_patterns()
    create_remote_thread_config = load_create_remote_thread_config()
    proxy_data = load_proxy_uri_templates()
    proxy_ua_data = load_proxy_user_agents()
    site_data = load_site_maps()
    sys_proc_data = load_system_processes()
    tls_realism_data = load_tls_realism()
    windows_auth_data = load_windows_auth_realism()
    timing_profiles_data = load_timing_profiles()

    # Collect file count (package + overlay)
    yaml_files: list[Path] = []
    for d in [activity_dir, personas_dir, formats_dir, evaluation_dir]:
        if d.is_dir():
            yaml_files.extend(d.glob("*.yaml"))
    result.files_checked = len(yaml_files) + len(overlay_yaml_files)

    # --- Checks 1-2: YAML Health (package files) ---
    for path in yaml_files:
        data, err = _safe_load_yaml(path)
        if err:
            result.issues.append(Issue("ERROR", path.name, f"YAML parse error: {err}"))
        elif data is None:
            result.issues.append(Issue("ERROR", path.name, "File is empty"))

    # --- Checks 3-6: DNS Registry Integrity ---
    # Read valid tags from the YAML data (data-driven, extensible via overlay)
    valid_dns_tags = frozenset(dns_data.get("valid_tags", {}).keys())
    domains = dns_data.get("domains", [])
    seen_domains: dict[str, int] = {}
    dns_domain_set: set[str] = set()
    all_dns_tags: set[str] = set()

    for i, entry in enumerate(domains):
        domain = entry.get("domain", "")
        tags = entry.get("tags", [])
        ips = entry.get("ips", [])

        # Check 3: Duplicate domains
        if domain in seen_domains:
            result.issues.append(
                Issue("ERROR", "dns_registry.yaml", f'Duplicate domain "{domain}"')
            )
        seen_domains[domain] = i
        dns_domain_set.add(domain)

        # Check 4: Empty tags
        if not tags:
            result.issues.append(
                Issue("ERROR", "dns_registry.yaml", f'Domain "{domain}" has empty tags')
            )

        # Check 5: Empty IPs
        if not ips:
            result.issues.append(
                Issue("ERROR", "dns_registry.yaml", f'Domain "{domain}" has empty IPs')
            )

        # Check 6: Invalid tags
        for tag in tags:
            all_dns_tags.add(tag)
            if tag not in valid_dns_tags:
                result.issues.append(
                    Issue(
                        "WARNING", "dns_registry.yaml", f'Domain "{domain}" has invalid tag "{tag}"'
                    )
                )

    # --- IDS Signature Integrity ---
    for i, sig in enumerate(ids_data.get("signatures", [])):
        sid = sig.get("sid", f"entry #{i + 1}") if isinstance(sig, dict) else f"entry #{i + 1}"
        if not isinstance(sig, dict):
            result.issues.append(
                Issue("ERROR", "ids_signatures.yaml", f"Signature {sid} must be a mapping")
            )
            continue
        for required in ("sid", "rev", "message", "classification", "priority", "proto"):
            if required not in sig:
                result.issues.append(
                    Issue(
                        "ERROR",
                        "ids_signatures.yaml",
                        f"Signature {sid} missing required field {required}",
                    )
                )
        proto = sig.get("proto")
        if proto not in {"tcp", "udp", "icmp"}:
            result.issues.append(
                Issue(
                    "ERROR",
                    "ids_signatures.yaml",
                    f"Signature {sid} has invalid proto {proto!r}",
                )
            )
        templates = sig.get("dns_query_templates")
        if templates is not None:
            if proto not in {"udp", "tcp"} or sig.get("dst_port") != 53:
                result.issues.append(
                    Issue(
                        "ERROR",
                        "ids_signatures.yaml",
                        f"Signature {sid} defines dns_query_templates but is not a DNS signature",
                    )
                )
            elif not isinstance(templates, list) or not templates:
                result.issues.append(
                    Issue(
                        "ERROR",
                        "ids_signatures.yaml",
                        f"Signature {sid} dns_query_templates must be a non-empty list",
                    )
                )
            else:
                for template in templates:
                    if not isinstance(template, str) or "{token}" not in template:
                        result.issues.append(
                            Issue(
                                "ERROR",
                                "ids_signatures.yaml",
                                f"Signature {sid} DNS template {template!r} must contain {{token}}",
                            )
                        )

    # --- Checks 7-10: DNS → Downstream Cascade ---
    # proxy_data and site_data loaded above via overlay-aware loaders
    proxy_domains = (
        set(proxy_data.get("domains", {}).keys())
        if isinstance(proxy_data.get("domains"), dict)
        else set()
    )
    site_domains = (
        set(site_data.get("domains", {}).keys())
        if isinstance(site_data.get("domains"), dict)
        else set()
    )
    site_referenced_hosts: set[str] = set()
    if isinstance(site_data.get("domains"), dict):
        for site_domain, site_config in site_data.get("domains", {}).items():
            site_referenced_hosts.add(site_domain)
            if not isinstance(site_config, dict):
                continue
            site_referenced_hosts.update(
                str(host) for host in site_config.get("cdn_domains", []) if host
            )
            for page in site_config.get("pages", []):
                if not isinstance(page, dict):
                    continue
                for subresource in page.get("subresources", []):
                    if isinstance(subresource, dict) and subresource.get("host"):
                        site_referenced_hosts.add(str(subresource["host"]))

    # Check 7: Orphaned proxy templates
    for domain in proxy_domains - dns_domain_set:
        result.issues.append(
            Issue(
                "WARNING",
                "proxy_uri_templates.yaml",
                f'Domain "{domain}" not found in dns_registry',
            )
        )
    _INFRA_PROXY_CLASSES = {
        "crl",
        "ocsp",
        "software_update",
        "telemetry",
        "windows_trust_list",
        "windows_update",
    }
    _GENERIC_BROWSER_PATHS = {
        "/login",
        "/signin",
        "/favicon.ico",
        "/assets/main.css",
        "/assets/app.js",
        "/dashboard",
    }
    _INFRA_CONTENT_TYPES = {
        "ocsp": {"application/ocsp-response"},
        "crl": {"application/pkix-crl"},
        "windows_update": {
            "application/octet-stream",
            "application/vnd.ms-cab-compressed",
            "application/x-cab",
        },
        "windows_trust_list": {
            "application/vnd.ms-cab-compressed",
            "application/octet-stream",
        },
        "software_update": {
            "application/json",
            "application/octet-stream",
        },
        "telemetry": {"application/json"},
    }
    for domain, entry in proxy_data.get("domains", {}).items():
        if not isinstance(entry, dict):
            result.issues.append(
                Issue(
                    "ERROR",
                    "proxy_uri_templates.yaml",
                    f'Domain "{domain}" entry must be a mapping',
                )
            )
            continue
        paths = entry.get("paths", [])
        methods = entry.get("methods", [])
        content_types = entry.get("content_types")
        domain_class = entry.get("domain_class")
        referrer_policy = entry.get("referrer_policy", "normal")
        if not isinstance(paths, list) or not paths:
            result.issues.append(
                Issue(
                    "ERROR",
                    "proxy_uri_templates.yaml",
                    f'Domain "{domain}" must define a non-empty paths list',
                )
            )
        if not isinstance(methods, list) or not methods:
            result.issues.append(
                Issue(
                    "ERROR",
                    "proxy_uri_templates.yaml",
                    f'Domain "{domain}" must define a non-empty methods list',
                )
            )
        if content_types is not None and (
            not isinstance(content_types, list) or len(content_types) != len(paths)
        ):
            result.issues.append(
                Issue(
                    "ERROR",
                    "proxy_uri_templates.yaml",
                    f'Domain "{domain}" content_types must be a list matching paths length',
                )
            )
        if referrer_policy not in {"normal", "none"}:
            result.issues.append(
                Issue(
                    "ERROR",
                    "proxy_uri_templates.yaml",
                    f'Domain "{domain}" has invalid referrer_policy "{referrer_policy}"',
                )
            )
        if domain_class in _INFRA_PROXY_CLASSES:
            if referrer_policy != "none":
                result.issues.append(
                    Issue(
                        "ERROR",
                        "proxy_uri_templates.yaml",
                        f'Domain "{domain}" class "{domain_class}" must set referrer_policy: none',
                    )
                )
            default_content_type = entry.get("content_type", "")
            allowed_types = _INFRA_CONTENT_TYPES[domain_class]
            observed_types = set(content_types or [default_content_type])
            for content_type in observed_types:
                if content_type not in allowed_types:
                    result.issues.append(
                        Issue(
                            "ERROR",
                            "proxy_uri_templates.yaml",
                            f'Domain "{domain}" class "{domain_class}" has unsuitable content type "{content_type}"',
                        )
                    )
            for path in paths:
                if path in _GENERIC_BROWSER_PATHS or path.endswith(
                    (".css", ".js", ".ico", ".jpeg", ".jpg", ".png", ".webp", ".woff2")
                ):
                    result.issues.append(
                        Issue(
                            "ERROR",
                            "proxy_uri_templates.yaml",
                            f'Domain "{domain}" class "{domain_class}" uses browser-like path "{path}"',
                        )
                    )
    proxy_ua_hosts: set[str] = set()
    if isinstance(proxy_ua_data.get("domain_overrides"), dict):
        for override in proxy_ua_data.get("domain_overrides", {}).values():
            if not isinstance(override, dict):
                continue
            proxy_ua_hosts.update(str(host) for host in override.get("hosts", []) if host)
    for domain in proxy_ua_hosts - dns_domain_set:
        result.issues.append(
            Issue(
                "WARNING",
                "proxy_user_agents.yaml",
                f'Domain override host "{domain}" not found in dns_registry',
            )
        )
    ocsp_responder_hosts: set[str] = set()
    for responder in tls_realism_data.get("ocsp", {}).get("responders", []):
        if not isinstance(responder, dict):
            continue
        ocsp_responder_hosts.update(str(host) for host in responder.get("domains", []) if host)
    for domain in ocsp_responder_hosts - dns_domain_set:
        result.issues.append(
            Issue(
                "WARNING",
                "tls_realism.yaml",
                f'OCSP responder host "{domain}" not found in dns_registry',
            )
        )

    # --- Timing profile integrity ---
    valid_timing_classes = {
        "same_observation",
        "source_latency",
        "causal_prerequisite",
        "human_workflow",
        "burst_fanout",
        "periodic",
        "teardown",
    }
    relationships = timing_profiles_data.get("relationships", {})
    if not isinstance(relationships, dict):
        result.issues.append(
            Issue("ERROR", "timing_profiles.yaml", "relationships must be a mapping")
        )
    else:
        for rel_name, rel_data in relationships.items():
            if not isinstance(rel_data, dict):
                result.issues.append(
                    Issue(
                        "ERROR",
                        "timing_profiles.yaml",
                        f'Relationship "{rel_name}" must be a mapping',
                    )
                )
                continue
            rel_class = rel_data.get("class")
            if rel_class not in valid_timing_classes:
                result.issues.append(
                    Issue(
                        "ERROR",
                        "timing_profiles.yaml",
                        f'Relationship "{rel_name}" has invalid class "{rel_class}"',
                    )
                )
            position = rel_data.get("position")
            if position not in {"before", "after"}:
                result.issues.append(
                    Issue(
                        "ERROR",
                        "timing_profiles.yaml",
                        f'Relationship "{rel_name}" has invalid position "{position}"',
                    )
                )
            min_ms = rel_data.get("min_ms")
            max_ms = rel_data.get("max_ms")
            if not isinstance(min_ms, int) or min_ms < 0:
                result.issues.append(
                    Issue(
                        "ERROR",
                        "timing_profiles.yaml",
                        f'Relationship "{rel_name}" min_ms must be a non-negative integer',
                    )
                )
            if not isinstance(max_ms, int) or max_ms < 0:
                result.issues.append(
                    Issue(
                        "ERROR",
                        "timing_profiles.yaml",
                        f'Relationship "{rel_name}" max_ms must be a non-negative integer',
                    )
                )
            if isinstance(min_ms, int) and isinstance(max_ms, int) and max_ms < min_ms:
                result.issues.append(
                    Issue(
                        "ERROR",
                        "timing_profiles.yaml",
                        f'Relationship "{rel_name}" max_ms must be greater than or equal to min_ms',
                    )
                )
    spacing = timing_profiles_data.get("windows_event_time", {}).get("collision_spacing", {})
    if not isinstance(spacing, dict):
        result.issues.append(
            Issue(
                "ERROR",
                "timing_profiles.yaml",
                "windows_event_time.collision_spacing must be a mapping",
            )
        )
    else:
        _spacing_minimums = {
            "near_zero_until": 0,
            "near_gap_min_us": 1,
            "near_gap_max_us": 1,
            "large_gap_min_ms": 1,
            "large_gap_max_ms": 1,
        }
        for field_name, minimum in _spacing_minimums.items():
            value = spacing.get(field_name)
            if not isinstance(value, int) or value < minimum:
                result.issues.append(
                    Issue(
                        "ERROR",
                        "timing_profiles.yaml",
                        f"windows_event_time.collision_spacing.{field_name} must be an integer >= {minimum}",
                    )
                )
        if (
            isinstance(spacing.get("near_gap_min_us"), int)
            and isinstance(spacing.get("near_gap_max_us"), int)
            and spacing["near_gap_max_us"] < spacing["near_gap_min_us"]
        ):
            result.issues.append(
                Issue(
                    "ERROR",
                    "timing_profiles.yaml",
                    "windows_event_time.collision_spacing.near_gap_max_us must be >= near_gap_min_us",
                )
            )
        if (
            isinstance(spacing.get("large_gap_min_ms"), int)
            and isinstance(spacing.get("large_gap_max_ms"), int)
            and spacing["large_gap_max_ms"] < spacing["large_gap_min_ms"]
        ):
            result.issues.append(
                Issue(
                    "ERROR",
                    "timing_profiles.yaml",
                    "windows_event_time.collision_spacing.large_gap_max_ms must be >= large_gap_min_ms",
                )
            )

    # Check 8: Orphaned site maps
    for domain in site_domains - dns_domain_set:
        result.issues.append(
            Issue("WARNING", "site_maps.yaml", f'Domain "{domain}" not found in dns_registry')
        )
    for domain in site_referenced_hosts - dns_domain_set:
        result.issues.append(
            Issue(
                "WARNING",
                "site_maps.yaml",
                f'Referenced host "{domain}" not found in dns_registry',
            )
        )

    # Checks 9-10: Missing proxy templates / site maps for web/saas domains
    web_saas_domains = {
        entry["domain"] for entry in domains if set(entry.get("tags", [])) & {"web", "saas"}
    }
    for domain in web_saas_domains - proxy_domains:
        result.issues.append(
            Issue(
                "INFO",
                "dns_registry.yaml",
                f'Domain "{domain}" (web/saas) has no proxy_uri_templates entry',
            )
        )

    for domain in web_saas_domains - site_domains:
        result.issues.append(
            Issue(
                "INFO", "dns_registry.yaml", f'Domain "{domain}" (web/saas) has no site_maps entry'
            )
        )

    # --- Checks 11-13: Traffic Profile Integrity ---
    role_traffic = traffic_data.get("role_traffic", {})
    persona_traffic = traffic_data.get("persona_traffic", {})

    # Collect all dns_tags used in traffic profiles
    all_traffic_entries = []
    for _role_name, role_data in role_traffic.items():
        for direction in ["outbound", "inbound"]:
            entries = role_data.get(direction, []) if isinstance(role_data, dict) else []
            all_traffic_entries.extend(entries)
    for _persona_name, persona_entries in persona_traffic.items():
        if isinstance(persona_entries, dict):
            for direction in ["outbound", "inbound"]:
                all_traffic_entries.extend(persona_entries.get(direction, []))
        elif isinstance(persona_entries, list):
            all_traffic_entries.extend(persona_entries)

    # Check 11: Orphaned dns_tags
    for entry in all_traffic_entries:
        for tag in entry.get("dns_tags", []):
            if tag not in all_dns_tags:
                result.issues.append(
                    Issue(
                        "WARNING",
                        "traffic_profiles.yaml",
                        f'dns_tag "{tag}" not used by any domain in dns_registry',
                    )
                )
    for entry in process_net_data:
        for tag in entry.get("dns_tags", []):
            if tag not in all_dns_tags:
                result.issues.append(
                    Issue(
                        "WARNING",
                        "process_network_map.yaml",
                        f'dns_tag "{tag}" not used by any domain in dns_registry',
                    )
                )
    tls_destination_profiles = tls_realism_data.get("destinations", {}).get("profiles", [])
    for profile in tls_destination_profiles:
        for tag in profile.get("dns_tags", []):
            if tag not in all_dns_tags:
                result.issues.append(
                    Issue(
                        "WARNING",
                        "tls_realism.yaml",
                        f'tls destination profile "{profile.get("name", "")}" references '
                        f'dns_tag "{tag}" not used by any domain in dns_registry',
                    )
                )
        for override in profile.get("os_overrides", {}).values():
            if not isinstance(override, dict):
                continue
            for tag in override.get("dns_tags", []):
                if tag not in all_dns_tags:
                    result.issues.append(
                        Issue(
                            "WARNING",
                            "tls_realism.yaml",
                            f'tls destination profile "{profile.get("name", "")}" references '
                            f'override dns_tag "{tag}" not used by any domain in dns_registry',
                        )
                    )

    # Check 12: Orphaned persona_traffic keys
    persona_names = _get_persona_names(personas_dir)
    for persona_name in persona_traffic:
        if persona_name not in persona_names and not persona_name.startswith("_"):
            result.issues.append(
                Issue(
                    "WARNING",
                    "traffic_profiles.yaml",
                    f'persona_traffic key "{persona_name}" has no matching persona file',
                )
            )

    # Check 13: Missing required fields in connection entries
    for entry in all_traffic_entries:
        for field_name in ["role", "port", "weight"]:
            if field_name not in entry and entry.get("proto") != "icmp":
                result.issues.append(
                    Issue(
                        "ERROR",
                        "traffic_profiles.yaml",
                        f"Connection entry missing required field: {field_name}",
                    )
                )

    # --- Checks 14-17: Application Catalog Integrity ---
    apps = catalog_data.get("applications", [])
    seen_app_ids: set[str] = set()
    all_app_ids: set[str] = set()

    for app in apps:
        app_id = app.get("id", "")

        # Check 14: Duplicate app IDs
        if app_id in seen_app_ids:
            result.issues.append(
                Issue("ERROR", "application_catalog.yaml", f'Duplicate app id "{app_id}"')
            )
        seen_app_ids.add(app_id)
        all_app_ids.add(app_id)

        # Check 15: Orphaned persona references
        for persona in app.get("personas", []):
            if persona not in persona_names and persona != "default":
                result.issues.append(
                    Issue(
                        "WARNING",
                        "application_catalog.yaml",
                        f'App "{app_id}" references persona "{persona}" with no matching file',
                    )
                )

        # Check: system_types values are valid
        _VALID_SYSTEM_TYPES = {"workstation", "server", "domain_controller"}
        for st in app.get("system_types", []):
            if st not in _VALID_SYSTEM_TYPES:
                result.issues.append(
                    Issue(
                        "ERROR",
                        "application_catalog.yaml",
                        f'App "{app_id}" has invalid system_type "{st}" (valid: {sorted(_VALID_SYSTEM_TYPES)})',
                    )
                )

        # Check 16-17: Image paths
        for os_name, platform in app.get("platforms", {}).items():
            image_path = platform.get("image_path", "")
            if not image_path:
                # Check 16: Missing image path
                result.issues.append(
                    Issue(
                        "ERROR",
                        "application_catalog.yaml",
                        f'App "{app_id}" missing image_path for {os_name}',
                    )
                )
            elif "/" not in image_path and "\\" not in image_path:
                # Check 17: Bare filename
                result.issues.append(
                    Issue(
                        "WARNING",
                        "application_catalog.yaml",
                        f'App "{app_id}" has bare filename image_path for {os_name}: "{image_path}"',
                    )
                )

    # --- Checks 18-20: Process Chain ---
    # Collect all exe basenames from spawn rules
    spawn_children: set[str] = set()
    for os_rules in [spawn_data.get("windows", {}), spawn_data.get("linux", {})]:
        for _parent, parent_data in os_rules.items():
            if isinstance(parent_data, dict):
                for child in parent_data.get("children", []):
                    spawn_children.add(child)

    # Collect all exe basenames from app catalog
    catalog_exes: set[str] = set()
    for app in apps:
        for platform in app.get("platforms", {}).values():
            image_path = platform.get("image_path", "")
            if image_path:
                basename = image_path.rsplit("\\", 1)[-1].rsplit("/", 1)[-1]
                catalog_exes.add(basename)

    # sys_proc_data loaded above via overlay-aware loader
    system_exes: set[str] = set()
    if sys_proc_data:
        for task in sys_proc_data.get("scheduled_tasks", []):
            image = task.get("image", "")
            if image:
                system_exes.add(image.rsplit("\\", 1)[-1].rsplit("/", 1)[-1])
        for role_data in sys_proc_data.get("system_services", {}).values():
            if isinstance(role_data, list):
                for proc in role_data:
                    image = proc.get("image", "")
                    if image:
                        system_exes.add(image.rsplit("\\", 1)[-1].rsplit("/", 1)[-1])
        # system_binaries section: explicit exe name → path mappings
        for os_binaries in sys_proc_data.get("system_binaries", {}).values():
            if isinstance(os_binaries, list):
                for entry in os_binaries:
                    exe = entry.get("exe", "")
                    if exe:
                        system_exes.add(exe)

    known_exes = catalog_exes | system_exes
    # Case-insensitive lookup for Windows exe matching
    known_exes_lower = {e.lower() for e in known_exes}

    # Check 18: Orphaned spawn rule children (case-insensitive)
    for child in spawn_children:
        if child.lower() not in known_exes_lower:
            result.issues.append(
                Issue(
                    "WARNING",
                    "spawn_rules.yaml",
                    f'Child "{child}" not found in application_catalog or system_processes',
                )
            )

    # Check 19: Missing spawn rules (apps not in any spawn rule, case-insensitive)
    spawn_all_entries: set[str] = set()
    for os_rules in [spawn_data.get("windows", {}), spawn_data.get("linux", {})]:
        spawn_all_entries.update(os_rules.keys())
        for parent_data in os_rules.values():
            if isinstance(parent_data, dict):
                spawn_all_entries.update(parent_data.get("children", []))
    spawn_all_entries_lower = {e.lower() for e in spawn_all_entries}

    for exe in catalog_exes:
        if exe.lower() not in spawn_all_entries_lower:
            result.issues.append(
                Issue(
                    "INFO",
                    "application_catalog.yaml",
                    f'App exe "{exe}" not listed in any spawn rule',
                )
            )

    # Check 20: Orphaned process_network_map entries (case-insensitive)
    pnm_exes: set[str] = set()
    if isinstance(process_net_data, list):
        for mapping in process_net_data:
            pnm_exes.update(mapping.get("exe", []))
    for exe in pnm_exes:
        if exe.lower() not in known_exes_lower:
            result.issues.append(
                Issue(
                    "WARNING",
                    "process_network_map.yaml",
                    f'Exe "{exe}" not found in application_catalog or system_processes',
                )
            )

    # --- Checks 22-25: Persona Integrity ---
    # Validate MERGED persona data (package + overlay) so partial overlay
    # personas that modify a few fields don't fail for missing required fields.
    # Check 21 (filename/name mismatch) removed — not applicable with merged data.
    from evidenceforge.utils.personas import load_builtin_personas

    all_merged_personas = load_builtin_personas()
    for persona in all_merged_personas:
        name = persona.get("name", "<unnamed>")

        # Check 22: Missing required fields
        for req_field in REQUIRED_PERSONA_FIELDS:
            if req_field not in persona:
                result.issues.append(
                    Issue("ERROR", f"persona:{name}", f"Missing required field: {req_field}")
                )

        # Check 23: Invalid risk_profile
        risk = persona.get("risk_profile", "")
        if risk and risk not in VALID_RISK_PROFILES:
            result.issues.append(
                Issue("ERROR", f"persona:{name}", f'Invalid risk_profile: "{risk}"')
            )

        # Check 24: Invalid browsing_intensity
        intensity = persona.get("browsing_intensity", "")
        if intensity and intensity not in VALID_BROWSING_INTENSITIES:
            result.issues.append(
                Issue("ERROR", f"persona:{name}", f'Invalid browsing_intensity: "{intensity}"')
            )

    # Check 25: Phantom personas (referenced but no file)
    all_referenced_personas: set[str] = set()
    for app in apps:
        all_referenced_personas.update(app.get("personas", []))
    for persona_name in persona_traffic:
        all_referenced_personas.add(persona_name)
    all_referenced_personas.discard("default")
    # Underscore-prefixed names are internal profiles, not actual personas
    all_referenced_personas = {p for p in all_referenced_personas if not p.startswith("_")}

    for persona in all_referenced_personas - persona_names:
        result.issues.append(
            Issue(
                "WARNING",
                "application_catalog/traffic_profiles",
                f'Persona "{persona}" referenced but no persona file exists',
            )
        )

    # --- Checks 28-30: Defined But Unreachable ---

    # Collect all dns_tags referenced by generation config. Traffic profiles
    # drive role/persona baseline traffic; process_network_map drives
    # process-correlated external app traffic (for example Teams→M365).
    all_traffic_dns_tags: set[str] = set()
    for entry in all_traffic_entries:
        all_traffic_dns_tags.update(entry.get("dns_tags", []))
    for entry in process_net_data:
        all_traffic_dns_tags.update(entry.get("dns_tags", []))

    # Check 28: DNS tags on domains that no generation config references
    # Tags that reach domains through other mechanisms (not dns_tags):
    #   cdn — loaded as subresources via site_maps
    #   internal — reached via role-based connections (database, file_server, etc.)
    _TAGS_REACHED_WITHOUT_DNS_TAGS = {"cdn", "internal"}
    for tag in all_dns_tags - _TAGS_REACHED_WITHOUT_DNS_TAGS:
        if tag not in all_traffic_dns_tags:
            domains_with_tag = [e["domain"] for e in domains if tag in e.get("tags", [])]
            if domains_with_tag:
                example = domains_with_tag[0]
                count = len(domains_with_tag)
                result.issues.append(
                    Issue(
                        "INFO",
                        "dns_registry.yaml",
                        f'Tag "{tag}" used by {count} domain(s) (e.g., "{example}") but no generation config references it via dns_tags — these domains will never receive traffic',
                    )
                )

    # Check 29: Personas not in any application's personas list
    all_app_personas: set[str] = set()
    for app in apps:
        all_app_personas.update(app.get("personas", []))
    for persona in persona_names:
        if persona not in all_app_personas and "default" not in all_app_personas:
            result.issues.append(
                Issue(
                    "INFO",
                    f"personas/{persona}.yaml",
                    f'Persona "{persona}" is not in any application\'s personas list — this persona will never spawn user apps',
                )
            )

    # Check 30: Bash command roles with no matching persona
    # Special keys that aren't persona roles:
    #   common — shared commands for all roles
    #   params — placeholder pools for template resolution
    #   keyboard_adjacency — typo model data
    #   dba, webadmin, security — sub-role pools mapped from personas by _get_role_pool()
    _BASH_SPECIAL_KEYS = {
        "common",
        "params",
        "keyboard_adjacency",
        "typo_model",
        "dba",
        "webadmin",
        "security",
    }
    from evidenceforge.generation.activity.bash_commands import load_bash_commands

    bash_data = load_bash_commands()
    if bash_data:
        typo_model = bash_data.get("typo_model", {})
        if not isinstance(typo_model, dict):
            result.issues.append(
                Issue("ERROR", "bash_commands.yaml", "typo_model must be a mapping")
            )
        else:
            max_rate = typo_model.get("max_rate", 0.08)
            correction_probability = typo_model.get("correction_probability", 0.85)
            short_history_threshold = typo_model.get("short_history_threshold", 8)
            short_history_max_typos = typo_model.get("short_history_max_typos", 1)
            for field_name, value in {
                "max_rate": max_rate,
                "correction_probability": correction_probability,
            }.items():
                if not isinstance(value, int | float) or not 0 <= float(value) <= 1:
                    result.issues.append(
                        Issue(
                            "ERROR",
                            "bash_commands.yaml",
                            f"typo_model.{field_name} must be a number between 0 and 1",
                        )
                    )
            for field_name, value in {
                "short_history_threshold": short_history_threshold,
                "short_history_max_typos": short_history_max_typos,
            }.items():
                if not isinstance(value, int) or value < 0:
                    result.issues.append(
                        Issue(
                            "ERROR",
                            "bash_commands.yaml",
                            f"typo_model.{field_name} must be a non-negative integer",
                        )
                    )
        for role_key in bash_data:
            if role_key in _BASH_SPECIAL_KEYS:
                continue
            if role_key not in persona_names:
                result.issues.append(
                    Issue(
                        "INFO",
                        "bash_commands.yaml",
                        f'Role "{role_key}" has no matching persona — these commands will never be generated',
                    )
                )

    # --- Checks 26-27: Evaluation Rule Integrity ---
    format_names = {f.stem for f in formats_dir.glob("*.yaml")}
    format_fields: dict[str, set[str]] = {}
    for fmt_file in formats_dir.glob("*.yaml"):
        fmt_data, _ = _safe_load_yaml(fmt_file)
        if fmt_data:
            fields = set()
            # Top-level fields
            for f in fmt_data.get("fields", []):
                if isinstance(f, dict) and "name" in f:
                    fields.add(f["name"])
            # Per-EventID variant fields (e.g., windows_event_security)
            for variant in fmt_data.get("variants", []):
                for f in variant.get("fields", []):
                    if isinstance(f, dict) and "name" in f:
                        fields.add(f["name"])
            format_fields[fmt_file.stem] = fields

    for eval_file in evaluation_dir.glob("*.yaml"):
        eval_data, err = _safe_load_yaml(eval_file)
        if err or not eval_data:
            continue

        if eval_file.stem in {"thresholds", "timing_bounds", "cross_source_pairs"}:
            # These files use non-format-keyed schemas; skip format-key validation
            continue

        if eval_file.stem == "causal_pairs":
            # causal_pairs has a different structure
            for pair in eval_data.get("pairs", []):
                for direction in ["before", "after"]:
                    fmt = pair.get(direction, {}).get("format", "")
                    if fmt and fmt not in format_names:
                        result.issues.append(
                            Issue(
                                "ERROR",
                                eval_file.name,
                                f'Causal pair references unknown format "{fmt}"',
                            )
                        )
        else:
            # co_occurrence and distributions are keyed by format name
            for fmt_key in eval_data:
                # Check 27: Invalid format references
                if fmt_key not in format_names:
                    result.issues.append(
                        Issue(
                            "ERROR", eval_file.name, f'Rules under unknown format key "{fmt_key}"'
                        )
                    )
                    continue

                # Check 26: Invalid field references
                known_fields = format_fields.get(fmt_key, set())
                if not known_fields:
                    continue

                rules = eval_data[fmt_key]
                if isinstance(rules, list):
                    for rule in rules:
                        # co_occurrence rules reference fields in condition and checks
                        for check_field in _extract_field_refs(rule):
                            if check_field not in known_fields:
                                result.issues.append(
                                    Issue(
                                        "WARNING",
                                        eval_file.name,
                                        f'Rule references field "{check_field}" not in {fmt_key} format',
                                    )
                                )

    # --- Schema validation: validate merged entries against Pydantic models ---
    from evidenceforge.config.schemas import (
        ApplicationEntry,
        ConnectionEntry,
        CreateRemoteThreadPatternEntry,
        DnsEntry,
        DnsTunnelRttConfig,
        EdrFileSideEffectProfile,
        KerberosRealismConfig,
        OuiEntry,
        PersonaEntry,
        ProcessAccessPatternEntry,
        ProcessNetworkEntry,
        ProxyUserAgentOverrideEntry,
        PublicNtpServerEntry,
        RemoteThreadStartLocationEntry,
        ScheduledTaskEntry,
        SmbFileTransferConfig,
        SpawnRuleEntry,
        SyslogProgramEntry,
        SystemBinaryEntry,
        SystemdScheduleEntry,
        SystemServiceEntry,
        TlsIssuerEntry,
        TlsRealismConfig,
        WindowsAuthRealismConfig,
        validate_entry,
    )

    _SCHEMA_CHECKS: list[tuple[list, type, str]] = [
        (domains, DnsEntry, "dns_registry.yaml"),
        (apps, ApplicationEntry, "application_catalog.yaml"),
        (all_merged_personas, PersonaEntry, "personas"),
    ]

    # system_processes.yaml: scheduled_tasks, system_services, system_binaries
    if sys_proc_data:
        _SCHEMA_CHECKS.append(
            (
                sys_proc_data.get("scheduled_tasks", []),
                ScheduledTaskEntry,
                "system_processes.yaml (scheduled_tasks)",
            )
        )
        for role_name, role_entries in sys_proc_data.get("system_services", {}).items():
            if isinstance(role_entries, list):
                _SCHEMA_CHECKS.append(
                    (
                        role_entries,
                        SystemServiceEntry,
                        f"system_processes.yaml (system_services.{role_name})",
                    )
                )
        for os_name, os_binaries in sys_proc_data.get("system_binaries", {}).items():
            if isinstance(os_binaries, list):
                _SCHEMA_CHECKS.append(
                    (
                        os_binaries,
                        SystemBinaryEntry,
                        f"system_processes.yaml (system_binaries.{os_name})",
                    )
                )

    # process_network_map.yaml
    if isinstance(process_net_data, list):
        _SCHEMA_CHECKS.append((process_net_data, ProcessNetworkEntry, "process_network_map.yaml"))

    # process_access_patterns.yaml
    if isinstance(process_access_data, list):
        _SCHEMA_CHECKS.append(
            (process_access_data, ProcessAccessPatternEntry, "process_access_patterns.yaml")
        )
    if isinstance(create_remote_thread_data, list):
        _SCHEMA_CHECKS.append(
            (
                create_remote_thread_data,
                CreateRemoteThreadPatternEntry,
                "create_remote_thread_patterns.yaml",
            )
        )
    remote_thread_locations = []
    for locations in (create_remote_thread_config.get("start_locations") or {}).values():
        if isinstance(locations, list):
            remote_thread_locations.extend(locations)
    for override in (create_remote_thread_config.get("target_overrides") or {}).values():
        if isinstance(override, dict) and isinstance(override.get("start_locations"), list):
            remote_thread_locations.extend(override["start_locations"])
    _SCHEMA_CHECKS.append(
        (
            remote_thread_locations,
            RemoteThreadStartLocationEntry,
            "create_remote_thread_patterns.yaml start_locations",
        )
    )

    from evidenceforge.generation.activity.edr_pools import load_edr_pools

    edr_pools_data = load_edr_pools()
    if edr_pools_data:
        _SCHEMA_CHECKS.append(
            (
                edr_pools_data.get("file_side_effect_profiles", []),
                EdrFileSideEffectProfile,
                "edr_pools.yaml (file_side_effect_profiles)",
            )
        )

    # traffic_profiles.yaml: connection entries
    all_traffic_connection_entries = []
    for _rn, role_data in traffic_data.get("role_traffic", {}).items():
        if isinstance(role_data, dict):
            for direction in ["outbound", "inbound"]:
                all_traffic_connection_entries.extend(role_data.get(direction, []))
    for _pn, persona_entries in traffic_data.get("persona_traffic", {}).items():
        if isinstance(persona_entries, dict):
            for direction in ["outbound", "inbound"]:
                all_traffic_connection_entries.extend(persona_entries.get(direction, []))
        elif isinstance(persona_entries, list):
            all_traffic_connection_entries.extend(persona_entries)
    _SCHEMA_CHECKS.append(
        (all_traffic_connection_entries, ConnectionEntry, "traffic_profiles.yaml")
    )

    # spawn_rules.yaml: spawn rule entries
    all_spawn_entries = []
    for os_rules in [spawn_data.get("windows", {}), spawn_data.get("linux", {})]:
        for _parent, parent_data in os_rules.items():
            if isinstance(parent_data, dict):
                all_spawn_entries.append(parent_data)
    _SCHEMA_CHECKS.append((all_spawn_entries, SpawnRuleEntry, "spawn_rules.yaml"))

    # tls_issuers.yaml
    from evidenceforge.generation.activity.tls_issuers import load_tls_issuers

    tls_data = load_tls_issuers()
    if tls_data:
        _SCHEMA_CHECKS.append((tls_data.get("issuers", []), TlsIssuerEntry, "tls_issuers.yaml"))

    # tls_realism.yaml
    from evidenceforge.generation.activity.tls_realism import load_tls_realism

    tls_realism_data = load_tls_realism()
    if tls_realism_data:
        _SCHEMA_CHECKS.append(([tls_realism_data], TlsRealismConfig, "tls_realism.yaml"))

    # kerberos_realism.yaml
    from evidenceforge.generation.activity.kerberos_realism import load_kerberos_realism

    kerberos_realism_data = load_kerberos_realism()
    if kerberos_realism_data:
        _SCHEMA_CHECKS.append(
            ([kerberos_realism_data], KerberosRealismConfig, "kerberos_realism.yaml")
        )

    # smb_file_transfers.yaml
    from evidenceforge.generation.activity.smb_file_transfers import load_smb_file_transfers

    smb_file_transfer_data = load_smb_file_transfers()
    if smb_file_transfer_data:
        _SCHEMA_CHECKS.append(
            ([smb_file_transfer_data], SmbFileTransferConfig, "smb_file_transfers.yaml")
        )

    # extra_syslog_messages.yaml
    from evidenceforge.generation.activity.extra_syslog import load_extra_syslog_messages

    syslog_data = load_extra_syslog_messages()
    if syslog_data:
        _SCHEMA_CHECKS.append((syslog_data, SyslogProgramEntry, "extra_syslog_messages.yaml"))

    # systemd_schedules.yaml
    from evidenceforge.generation.engine.baseline import _load_systemd_schedules

    schedules = _load_systemd_schedules()
    if schedules:
        _SCHEMA_CHECKS.append((schedules, SystemdScheduleEntry, "systemd_schedules.yaml"))

    # network_params.yaml
    from evidenceforge.generation.activity.network_params import load_network_params

    net_params = load_network_params()
    if net_params:
        _SCHEMA_CHECKS.append((net_params.get("oui_prefixes", []), OuiEntry, "network_params.yaml"))
        _SCHEMA_CHECKS.append(
            (
                net_params.get("public_ntp_servers", []),
                PublicNtpServerEntry,
                "network_params.yaml (public_ntp_servers)",
            )
        )
        err = validate_entry(
            net_params.get("dns_tunnel_rtt", {}),
            DnsTunnelRttConfig,
            "network_params.yaml (dns_tunnel_rtt)",
        )
        if err:
            result.issues.append(Issue("ERROR", "network_params.yaml (dns_tunnel_rtt)", err))
        templates = net_params.get("dns_tunnel_response_templates", [])
        if not isinstance(templates, list) or not templates:
            result.issues.append(
                Issue(
                    "ERROR",
                    "network_params.yaml (dns_tunnel_response_templates)",
                    "dns_tunnel_response_templates must be a non-empty list",
                )
            )
        else:
            for idx, template in enumerate(templates):
                if not isinstance(template, str) or "{token}" not in template:
                    result.issues.append(
                        Issue(
                            "ERROR",
                            "network_params.yaml (dns_tunnel_response_templates)",
                            f"entry {idx} must be a string containing '{{token}}'",
                        )
                    )

    err = validate_entry(windows_auth_data, WindowsAuthRealismConfig, "windows_auth_realism.yaml")
    if err:
        result.issues.append(Issue("ERROR", "windows_auth_realism.yaml", err))

    if isinstance(proxy_ua_data.get("domain_overrides"), dict):
        _SCHEMA_CHECKS.append(
            (
                list(proxy_ua_data.get("domain_overrides", {}).values()),
                ProxyUserAgentOverrideEntry,
                "proxy_user_agents.yaml (domain_overrides)",
            )
        )

    # Run all schema validations
    for entries, schema, file_name in _SCHEMA_CHECKS:
        if not isinstance(entries, list):
            continue
        for entry in entries:
            if not isinstance(entry, dict):
                continue
            err = validate_entry(entry, schema, file_name)
            if err:
                entry_id = (
                    entry.get("domain")
                    or entry.get("id")
                    or entry.get("name")
                    or entry.get("service")
                    or entry.get("app")
                    or entry.get("exe")
                    or "?"
                )
                result.issues.append(Issue("ERROR", file_name, f'Entry "{entry_id}": {err}'))

    # Deduplicate issues (some checks may flag the same thing multiple times)
    # --- Check: Web scan preset IDS configuration ---
    from evidenceforge.config.web_scan_presets import (
        list_preset_names,
        load_web_scan_presets,
        parse_positive_finite_rate,
    )

    scan_data = load_web_scan_presets()
    presets = scan_data.get("presets", {})
    _IDS_REQUIRED_FIELDS = {"sid", "message"}
    for name in list_preset_names():
        preset = presets.get(name, {})
        max_effective_rate = preset.get("max_effective_rate")
        if (
            max_effective_rate is not None
            and parse_positive_finite_rate(max_effective_rate) is None
        ):
            result.issues.append(
                Issue(
                    "ERROR",
                    "web_scan_presets.yaml",
                    f'Preset "{name}" max_effective_rate must be a positive finite number, got {max_effective_rate}',
                )
            )
        # Validate ids_ua
        if "ids_ua" in preset:
            ids_ua = preset["ids_ua"]
            for field in _IDS_REQUIRED_FIELDS:
                if field not in ids_ua:
                    result.issues.append(
                        Issue(
                            "ERROR",
                            "web_scan_presets.yaml",
                            f'Preset "{name}" ids_ua missing required field "{field}"',
                        )
                    )
        # Validate ids_rate
        if "ids_rate" in preset:
            ids_rate = preset["ids_rate"]
            for field in _IDS_REQUIRED_FIELDS:
                if field not in ids_rate:
                    result.issues.append(
                        Issue(
                            "ERROR",
                            "web_scan_presets.yaml",
                            f'Preset "{name}" ids_rate missing required field "{field}"',
                        )
                    )
            threshold = ids_rate.get("threshold")
            if threshold is not None and (not isinstance(threshold, int) or threshold < 1):
                result.issues.append(
                    Issue(
                        "WARNING",
                        "web_scan_presets.yaml",
                        f'Preset "{name}" ids_rate threshold must be a positive integer, got {threshold}',
                    )
                )
        # Validate per-path ids entries
        for i, path_entry in enumerate(preset.get("paths", [])):
            if isinstance(path_entry, dict) and "ids" in path_entry:
                path_ids = path_entry["ids"]
                for field in _IDS_REQUIRED_FIELDS:
                    if field not in path_ids:
                        result.issues.append(
                            Issue(
                                "ERROR",
                                "web_scan_presets.yaml",
                                f'Preset "{name}" path #{i + 1} ({path_entry.get("uri", "?")}) ids missing "{field}"',
                            )
                        )

    # --- RSAT tools validation ---
    from evidenceforge.generation.activity.rsat_tools import load_rsat_tools

    rsat_tools = load_rsat_tools()
    _RSAT_REQUIRED = {"id", "snap_in", "command_line", "target_ports", "weight"}
    for tool in rsat_tools:
        tool_id = tool.get("id", "<unnamed>")
        missing = _RSAT_REQUIRED - set(tool.keys())
        if missing:
            result.issues.append(
                Issue(
                    "ERROR",
                    "rsat_tools.yaml",
                    f'Tool "{tool_id}" missing fields: {sorted(missing)}',
                )
            )
        if not isinstance(tool.get("weight", 0), int) or tool.get("weight", 0) < 1:
            result.issues.append(
                Issue(
                    "ERROR",
                    "rsat_tools.yaml",
                    f'Tool "{tool_id}" weight must be a positive integer',
                )
            )
        for i, port_info in enumerate(tool.get("target_ports", [])):
            if "port" not in port_info or "service" not in port_info:
                result.issues.append(
                    Issue(
                        "ERROR",
                        "rsat_tools.yaml",
                        f'Tool "{tool_id}" target_ports[{i}] missing port or service',
                    )
                )
        for i, mod in enumerate(tool.get("loaded_modules", [])):
            if "path" not in mod:
                result.issues.append(
                    Issue(
                        "ERROR",
                        "rsat_tools.yaml",
                        f'Tool "{tool_id}" loaded_modules[{i}] missing path',
                    )
                )
            elif "\\" not in mod["path"]:
                result.issues.append(
                    Issue(
                        "WARNING",
                        "rsat_tools.yaml",
                        f'Tool "{tool_id}" loaded_modules[{i}] path does not look like a Windows path',
                    )
                )

    seen_issues: set[tuple[str, str, str]] = set()
    deduped: list[Issue] = []
    for issue in result.issues:
        key = (issue.severity, issue.file, issue.message)
        if key not in seen_issues:
            seen_issues.add(key)
            deduped.append(issue)
    result.issues = deduped

    return result


def _get_persona_names(personas_dir: Path) -> set[str]:
    """Get set of all persona names from the personas directory."""
    from evidenceforge.utils.personas import load_builtin_personas

    return {p["name"] for p in load_builtin_personas() if "name" in p}


def _extract_field_refs(rule: dict) -> list[str]:
    """Extract field name references from a co_occurrence or distribution rule."""
    fields = []
    # Distribution rules have a "field" key
    if "field" in rule:
        fields.append(rule["field"])
    # Co-occurrence rules have "condition" fields and "checks" with "field"
    if "condition" in rule:
        for key in rule["condition"]:
            if key != "exclude":
                fields.append(key)
    if "checks" in rule:
        for check in rule["checks"]:
            if "field" in check:
                fields.append(check["field"])
    return fields
