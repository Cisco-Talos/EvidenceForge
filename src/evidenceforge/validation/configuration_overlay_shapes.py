# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Static partial-overlay shapes; merged validators own full entry semantics."""

# File-scoped overlay structure schemas.
# Maps overlay file path → expected field types.
# "list_fields": {field_name: key_field_or_None} — must be list of dicts
# "dict_fields": {field_names} — must be dicts
# "string_list_fields": {field_names} — must be lists of strings
# "value_list_fields": {field_names} — must be lists; merged validation owns item shape
# "fixed_string_sequence_fields": {field_name: length} — list of fixed-length string sequences
# "string_dict_fields": mappings whose keys and values must be non-empty strings
# "string_fields" / "number_fields": scalar root fields with explicit primitive types
OVERLAY_FILE_SCHEMAS: dict[str, dict] = {
    "activity/dns_registry.yaml": {
        "list_fields": {"domains": "domain"},
        "dict_fields": {"valid_tags", "long_tail", "ipv6_map", "ipv6_prefixes"},
        "value_list_fields": {"cdn_ranges"},
    },
    "activity/application_catalog.yaml": {
        "list_fields": {"applications": "id"},
        "dict_fields": {"default_deployment"},
        "scalar_fields": {"schema_version": int},
    },
    "activity/traffic_profiles.yaml": {
        "dict_fields": {"role_traffic", "persona_traffic"},
    },
    "activity/spawn_rules.yaml": {
        "dict_fields": {"windows", "linux"},
    },
    "activity/proxy_uri_templates.yaml": {
        "dict_fields": {"domains", "tags", "generic"},
        "string_list_fields": {"search_terms"},
        "string_fields": {"default_http_policy"},
    },
    "activity/proxy_user_agents.yaml": {
        "dict_fields": {"domain_overrides", "workstation", "server"},
    },
    "activity/beacon_profiles.yaml": {
        "dict_fields": {"profiles"},
    },
    "activity/site_maps.yaml": {
        "dict_fields": {"domains", "tags", "generic"},
        "string_list_fields": {"search_terms"},
    },
    "activity/process_network_map.yaml": {
        "list_fields": {"mappings": None},
    },
    "activity/email_background.yaml": {
        "list_fields": {
            "external_domains": "domain",
            "inbound_local_parts": "local_part",
            "outbound_local_parts": "local_part",
        },
    },
    "activity/mail_public_identities.yaml": {
        "list_fields": {"providers": "name"},
        "string_list_fields": {"reserved_replacement_domains"},
    },
    "activity/external_actor_profiles.yaml": {
        "list_fields": {
            "logon_source_ips": "ip",
            "failed_logon_source_ips": "ip",
            "connection_c2_ips": "ip",
        },
    },
    "activity/public_identity_profiles.yaml": {
        "list_fields": {"providers": "id", "roles": "id"},
        "string_list_fields": {"reserved_replacement_domains"},
        "scalar_fields": {"schema_version": str},
    },
    "activity/suspicious_benign.yaml": {
        "list_fields": {"dns_hosts": "hostname", "unusual_connections": "hostname"},
    },
    "activity/command_parameter_pools.yaml": {
        "dict_fields": {"general", "query", "linux_query"},
    },
    "activity/process_access_patterns.yaml": {
        "list_fields": {"baseline_pairs": None},
    },
    "activity/auth_noise.yaml": {
        "dict_fields": {"scheduled_stale_credentials", "service_account_delegation"},
    },
    "activity/create_remote_thread_patterns.yaml": {
        "list_fields": {"baseline_pairs": None},
        "dict_fields": {"baseline_noise", "start_locations", "target_overrides"},
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
    "activity/secret_families.yaml": {
        "list_fields": {"families": "name"},
        "dict_fields": {"network_allowlist"},
        "string_list_fields": {"poison_markers", "vendor_fakes"},
    },
    "activity/payload_families.yaml": {
        "list_fields": {"families": "name"},
        "dict_fields": {"network_allowlist"},
        "string_list_fields": {"markers"},
        "string_fields": {"default_marker", "canary_host"},
    },
    "activity/tls_issuers.yaml": {
        "list_fields": {"issuers": "name"},
        "dict_fields": {"domain_ca_overrides"},
    },
    "activity/tls_realism.yaml": {
        "dict_fields": {"san", "serial_numbers", "ocsp", "certificate_chains", "destinations"},
    },
    "activity/public_dns_profiles.yaml": {
        "list_fields": {
            "nameserver_profiles": "name",
            "mail_profiles": "name",
            "aaaa_profiles": "name",
        },
        "number_fields": {"generic_aaaa_probability"},
    },
    "activity/network_params.yaml": {
        "list_fields": {
            "oui_prefixes": None,
            "public_dns_resolvers": "name",
            "public_ntp_servers": "name",
            "external_scanner_port_profiles": "name",
            "linux_smb_connection_owners": "role",
        },
        "dict_fields": {
            "dns_tunnel_rtt",
            "dns_tunnel_rcode_weights",
            "nmap_command_probe",
            "proxy_connect_status_messages",
        },
        "string_list_fields": {
            "dns_tunnel_response_templates",
            "external_client_excluded_cidrs",
        },
        "value_list_fields": {"dns_tunnel_ttl_choices"},
    },
    "activity/windows_auth_realism.yaml": {
        "dict_fields": {
            "workstation_lock",
            "group_policy_refresh",
            "remote_auth_transport",
            "anonymous_smb_baseline",
            "failed_logon",
            "special_privileges",
        },
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
        "dict_fields": {"source_families"},
    },
    "activity/edr_pools.yaml": {
        "list_fields": {
            "file_side_effect_profiles": None,
            "file_ownership_rules": None,
            "registry_ownership_rules": None,
            "installed_software_products": None,
        },
        "string_list_fields": {
            "linux_service_users",
            "group_policy_extension_guids",
            "file_paths_windows",
            "file_paths_linux",
            "dll_pool",
            "runmru_commands",
        },
        "fixed_string_sequence_fields": {
            "registry_keys_hkcu": 3,
            "registry_keys_hklm": 3,
        },
    },
    "activity/endpoint_noise.yaml": {
        "dict_fields": {
            "windows_scheduled_processes",
            "registry_noise",
            "ecar_flow_identity",
            "ecar_file_churn",
        },
    },
    "activity/host_activity_profiles.yaml": {
        "dict_fields": {
            "rate_families",
            "host_types",
            "role_profiles",
            "persona_profiles",
            "artifact_variants",
            "firewall_deny",
        },
    },
    "activity/http_file_profiles.yaml": {
        "dict_fields": {"extension_mime_types", "request_profiles", "multipart"},
    },
    "activity/ids_signatures.yaml": {
        "list_fields": {"signatures": None},
    },
    "activity/web_scan_presets.yaml": {
        "dict_fields": {"presets"},
    },
    "activity/web_session_profiles.yaml": {
        "dict_fields": {"visitor_classes", "user_agent_pools"},
    },
    "activity/traffic_rates.yaml": {
        "dict_fields": {"low", "medium", "high"},
    },
    "activity/timing_profiles.yaml": {
        "dict_fields": {
            "relationships",
            "ssh_authentication",
            "endpoint_clock",
            "windows_startup_modules",
            "windows_event_time",
            "network_sensor_observation",
            "firewall_observation",
            "sysmon_event_envelope",
        },
    },
    "activity/smb_profiles.yaml": {
        "dict_fields": {
            "advertised_filesystem_defaults",
            "client_defaults",
            "client_profiles",
            "samba_audit",
            "server_defaults",
            "server_profiles",
        },
        "scalar_fields": {"schema_version": int},
    },
    "activity/service_process_profiles.yaml": {
        "dict_fields": {"families"},
    },
    "activity/kerberos_realism.yaml": {
        "dict_fields": {
            "tgt_success",
            "tgt_failure",
            "certificate_profiles",
            "transport_profiles",
        },
    },
    "activity/observation_profiles.yaml": {
        "dict_fields": {"profiles"},
        "scalar_fields": {"schema_version": int},
    },
    "activity/proxy_phase_profiles.yaml": {
        "list_fields": {"resolver_mixture": "name"},
        "dict_fields": {"phase_timing"},
    },
    "activity/rsat_tools.yaml": {
        "list_fields": {"tools": "id"},
    },
    "activity/snort_classifications.yaml": {
        "string_dict_fields": {"classifications"},
    },
    "activity/storage_catalog.yaml": {
        "dict_fields": {"population_counts", "profiles"},
    },
}
