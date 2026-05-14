# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Regression test: eforge validate-config must ship 100% clean."""

from evidenceforge.cli.validate_config import validate_config


class TestValidateConfig:
    def test_validate_config_clean(self):
        result = validate_config()
        assert result.issues == [], (
            f"validate-config has {len(result.issues)} issues:\n"
            + "\n".join(f"  [{i.severity}] {i.file}: {i.message}" for i in result.issues)
        )

    def test_validate_config_rejects_invalid_web_scan_rate_cap(self, monkeypatch):
        from evidenceforge.config import web_scan_presets

        def load_invalid_web_scan_presets():
            return {
                "presets": {
                    "nikto": {
                        "max_effective_rate": 0,
                        "paths": [{"uri": "/", "status": 200}],
                    }
                }
            }

        monkeypatch.setattr(
            web_scan_presets, "load_web_scan_presets", load_invalid_web_scan_presets
        )
        monkeypatch.setattr(web_scan_presets, "list_preset_names", lambda: ["nikto"])

        result = validate_config()

        assert any(
            issue.severity == "ERROR"
            and issue.file == "web_scan_presets.yaml"
            and 'Preset "nikto" max_effective_rate must be a positive finite number'
            in issue.message
            for issue in result.issues
        )

    def test_validate_config_rejects_invalid_endpoint_noise_bounds(self, monkeypatch):
        from evidenceforge.generation.activity import endpoint_noise

        def load_invalid_endpoint_noise():
            return {
                "windows_scheduled_processes": {
                    "count_min": 5,
                    "count_max": 2,
                    "trigger_window_start_seconds": 3510,
                    "trigger_window_end_seconds": 90,
                    "slot_spacing_seconds": 300,
                    "host_phase_window_seconds": 900,
                    "jitter_seconds_min": 20,
                    "jitter_seconds_max": -20,
                    "skip_probability": 0.05,
                },
                "registry_noise": {
                    "dhcp_interface_values": {
                        "value_names": ["DhcpIPAddress"],
                        "require_dhcp_state": True,
                        "emit_on_lease_events": True,
                        "suppress_system_types": ["server", "domain_controller"],
                        "suppress_roles": ["domain_controller"],
                    }
                },
            }

        monkeypatch.setattr(endpoint_noise, "load_endpoint_noise", load_invalid_endpoint_noise)

        result = validate_config()

        assert any(
            issue.severity == "ERROR"
            and issue.file == "endpoint_noise.yaml"
            and "count_min must be <= count_max" in issue.message
            for issue in result.issues
        )

    def test_validate_config_rejects_third_party_module_with_microsoft_identity(self, monkeypatch):
        from evidenceforge.generation.activity import application_catalog

        real_catalog_loader = application_catalog.load_catalog

        def load_invalid_catalog():
            data = real_catalog_loader()
            apps = [dict(app) for app in data.get("applications", [])]
            windows = dict(apps[0]["platforms"]["windows"])
            windows["loaded_modules"] = [
                {
                    "path": r"C:\Program Files\Google\Chrome\Application\chrome_elf.dll",
                    "signature": "Microsoft Windows",
                }
            ]
            apps[0] = {
                **apps[0],
                "platforms": {**apps[0]["platforms"], "windows": windows},
            }
            return {**data, "applications": apps}

        monkeypatch.setattr(application_catalog, "load_catalog", load_invalid_catalog)

        result = validate_config()

        assert any(
            issue.severity == "ERROR"
            and issue.file == "application_catalog.yaml"
            and "must use a native signer" in issue.message
            for issue in result.issues
        )

    def test_validate_config_rejects_incompatible_tls_subject_key_profile(self, monkeypatch):
        from evidenceforge.generation.activity import tls_realism

        real_tls_loader = tls_realism.load_tls_realism

        def load_invalid_tls_realism():
            data = real_tls_loader()
            certificate_chains = dict(data.get("certificate_chains", {}))
            certificate_chains["subject_key_profiles"] = [
                {
                    "subject_patterns": ["CN=Invalid ECDSA CA*"],
                    "issuer_family": "invalid_ecdsa",
                    "key_type": "ecdsa",
                    "key_length": 256,
                    "child_signature_algorithms": ["sha256WithRSAEncryption"],
                }
            ]
            return {**data, "certificate_chains": certificate_chains}

        monkeypatch.setattr(tls_realism, "load_tls_realism", load_invalid_tls_realism)

        result = validate_config()

        assert any(
            issue.severity == "ERROR"
            and issue.file == "tls_realism.yaml"
            and "ecdsa issuer profiles cannot use RSA child signature algorithms" in issue.message
            for issue in result.issues
        )

    def test_validate_config_warns_for_unknown_ocsp_responder(self, monkeypatch):
        from evidenceforge.generation.activity import dns_registry, tls_realism

        real_dns_loader = dns_registry.load_dns_registry
        real_tls_loader = tls_realism.load_tls_realism

        def load_dns_without_test_responder():
            data = real_dns_loader()
            return {
                **data,
                "domains": [
                    entry
                    for entry in data.get("domains", [])
                    if entry.get("domain") != "ocsp.missing.example"
                ],
            }

        def load_tls_with_unknown_responder():
            data = real_tls_loader()
            ocsp = dict(data.get("ocsp", {}))
            ocsp["responders"] = list(ocsp.get("responders", [])) + [
                {"issuer_patterns": ["*Test CA*"], "domains": ["ocsp.missing.example"]}
            ]
            return {**data, "ocsp": ocsp}

        monkeypatch.setattr(dns_registry, "load_dns_registry", load_dns_without_test_responder)
        monkeypatch.setattr(tls_realism, "load_tls_realism", load_tls_with_unknown_responder)

        result = validate_config()

        assert any(
            issue.file == "tls_realism.yaml"
            and 'OCSP responder host "ocsp.missing.example" not found in dns_registry'
            in issue.message
            for issue in result.issues
        )

    def test_validate_config_rejects_pkinit_without_certificate_profile(self, monkeypatch):
        from evidenceforge.generation.activity import kerberos_realism

        def load_invalid_kerberos_realism():
            return {
                "tgt_success": {
                    "pre_auth_types": {
                        "pkinit": {
                            "value": 15,
                            "weight": 1,
                            "certificate_required": True,
                        }
                    },
                    "ticket_options": {"default": {"value": "0x40810010", "weight": 1}},
                    "encryption_types": {"aes256": {"value": "0x12", "weight": 1}},
                },
                "certificate_profiles": {},
            }

        monkeypatch.setattr(
            kerberos_realism, "load_kerberos_realism", load_invalid_kerberos_realism
        )

        result = validate_config()

        assert any(
            issue.severity == "ERROR"
            and issue.file == "kerberos_realism.yaml"
            and "PreAuthType 15 must reference a certificate_profile" in issue.message
            for issue in result.issues
        )

    def test_validate_config_rejects_improbable_preauth_distribution(self, monkeypatch):
        from evidenceforge.generation.activity import kerberos_realism

        def load_invalid_kerberos_realism():
            return {
                "tgt_success": {
                    "pre_auth_types": {
                        "encrypted_timestamp": {
                            "value": 2,
                            "weight": 1,
                            "certificate_required": False,
                        },
                        "none_or_legacy": {
                            "value": 0,
                            "weight": 1,
                            "certificate_required": False,
                        },
                    },
                    "ticket_options": {"default": {"value": "0x40810010", "weight": 1}},
                    "encryption_types": {"aes256": {"value": "0x12", "weight": 1}},
                },
                "certificate_profiles": {},
            }

        monkeypatch.setattr(
            kerberos_realism, "load_kerberos_realism", load_invalid_kerberos_realism
        )

        result = validate_config()

        assert any(
            issue.severity == "ERROR"
            and issue.file == "kerberos_realism.yaml"
            and "PreAuthType 0/no-preauth weight must not exceed 5%" in issue.message
            for issue in result.issues
        )

    def test_validate_config_rejects_improbable_kerberos_failure_preauth(self, monkeypatch):
        from evidenceforge.generation.activity import kerberos_realism

        real_loader = kerberos_realism.load_kerberos_realism

        def load_invalid_kerberos_realism():
            data = real_loader()
            failure = dict(data["tgt_failure"])
            failure["pre_auth_types"] = {
                "none_or_legacy": {"value": 0, "weight": 50},
                "encrypted_timestamp": {"value": 2, "weight": 50},
            }
            return {**data, "tgt_failure": failure}

        monkeypatch.setattr(
            kerberos_realism, "load_kerberos_realism", load_invalid_kerberos_realism
        )

        result = validate_config()

        assert any(
            issue.severity == "ERROR"
            and issue.file == "kerberos_realism.yaml"
            and "4771 failure PreAuthType 0/no-preauth weight must not exceed 10%" in issue.message
            for issue in result.issues
        )

    def test_validate_config_rejects_browser_like_proxy_infra_template(self, monkeypatch):
        from evidenceforge.generation.activity import proxy_uri

        real_loader = proxy_uri.load_proxy_uri_templates

        def load_invalid_proxy_templates():
            data = real_loader()
            domains = dict(data.get("domains", {}))
            domains["ocsp.pki.goog"] = {
                "domain_class": "ocsp",
                "paths": ["/login"],
                "content_type": "text/html",
                "methods": ["GET"],
            }
            return {**data, "domains": domains}

        monkeypatch.setattr(proxy_uri, "load_proxy_uri_templates", load_invalid_proxy_templates)

        result = validate_config()

        assert any(
            issue.severity == "ERROR"
            and issue.file == "proxy_uri_templates.yaml"
            and "browser-like path" in issue.message
            for issue in result.issues
        )
        assert any(
            issue.severity == "ERROR"
            and issue.file == "proxy_uri_templates.yaml"
            and "unsuitable content type" in issue.message
            for issue in result.issues
        )

    def test_validate_config_rejects_invalid_timing_profile_window(self, monkeypatch):
        from evidenceforge.generation.activity import timing_profiles

        def load_invalid_timing_profiles():
            return {
                "relationships": {
                    "network.dns_before_tcp": {
                        "class": "causal_prerequisite",
                        "position": "before",
                        "min_ms": 500,
                        "max_ms": 100,
                    }
                },
                "windows_event_time": {
                    "collision_spacing": {
                        "near_zero_until": 25,
                        "near_gap_min_us": 50,
                        "near_gap_max_us": 500,
                        "large_gap_min_ms": 1000,
                        "large_gap_max_ms": 4000,
                    }
                },
            }

        monkeypatch.setattr(timing_profiles, "load_timing_profiles", load_invalid_timing_profiles)

        result = validate_config()

        assert any(
            issue.severity == "ERROR"
            and issue.file == "timing_profiles.yaml"
            and 'Relationship "network.dns_before_tcp" max_ms must be greater than or equal to min_ms'
            in issue.message
            for issue in result.issues
        )

    def test_validate_config_rejects_invalid_edr_side_effect_profile(self, monkeypatch):
        from evidenceforge.generation.activity import edr_pools

        real_loader = edr_pools.load_edr_pools

        def load_invalid_edr_pools():
            data = real_loader()
            return {
                **data,
                "file_side_effect_profiles": [
                    {
                        "name": "bad",
                        "actions": ["modify"],
                        "paths_windows": [r"C:\Temp\x.tmp"],
                    }
                ],
            }

        monkeypatch.setattr(edr_pools, "load_edr_pools", load_invalid_edr_pools)

        result = validate_config()

        assert any(
            issue.severity == "ERROR"
            and issue.file == "edr_pools.yaml (file_side_effect_profiles)"
            and "profile must define executables" in issue.message
            for issue in result.issues
        )

    def test_validate_config_rejects_invalid_windows_collision_spacing(self, monkeypatch):
        from evidenceforge.generation.activity import timing_profiles

        def load_invalid_timing_profiles():
            return {
                "relationships": {
                    "network.dns_before_tcp": {
                        "class": "causal_prerequisite",
                        "position": "before",
                        "min_ms": 20,
                        "max_ms": 1500,
                    }
                },
                "windows_event_time": {
                    "collision_spacing": {
                        "near_zero_until": 25,
                        "near_gap_min_us": 500,
                        "near_gap_max_us": 50,
                        "large_gap_min_ms": 4000,
                        "large_gap_max_ms": 1000,
                    }
                },
            }

        monkeypatch.setattr(timing_profiles, "load_timing_profiles", load_invalid_timing_profiles)

        result = validate_config()

        assert any(
            issue.severity == "ERROR"
            and issue.file == "timing_profiles.yaml"
            and "near_gap_max_us must be >= near_gap_min_us" in issue.message
            for issue in result.issues
        )
        assert any(
            issue.severity == "ERROR"
            and issue.file == "timing_profiles.yaml"
            and "large_gap_max_ms must be >= large_gap_min_ms" in issue.message
            for issue in result.issues
        )

    def test_validate_config_rejects_invalid_dns_tunnel_response_template(self, monkeypatch):
        from evidenceforge.generation.activity import network_params

        real_loader = network_params.load_network_params

        def load_invalid_network_params():
            data = real_loader()
            return {
                **data,
                "dns_tunnel_response_templates": ["ack-sequence"],
            }

        monkeypatch.setattr(network_params, "load_network_params", load_invalid_network_params)

        result = validate_config()

        assert any(
            issue.severity == "ERROR"
            and issue.file == "network_params.yaml (dns_tunnel_response_templates)"
            for issue in result.issues
        )

    def test_validate_config_rejects_invalid_dns_tunnel_rcode_weights(self, monkeypatch):
        from evidenceforge.generation.activity import network_params

        real_loader = network_params.load_network_params

        def load_invalid_network_params():
            data = real_loader()
            return {
                **data,
                "dns_tunnel_rcode_weights": {"NOERROR": 0, "BOGUS": 1},
            }

        monkeypatch.setattr(network_params, "load_network_params", load_invalid_network_params)

        result = validate_config()

        assert any(
            issue.severity == "ERROR"
            and issue.file == "network_params.yaml (dns_tunnel_rcode_weights)"
            for issue in result.issues
        )

    def test_validate_config_rejects_invalid_dns_tunnel_ttl_choices(self, monkeypatch):
        from evidenceforge.generation.activity import network_params

        real_loader = network_params.load_network_params

        def load_invalid_network_params():
            data = real_loader()
            return {
                **data,
                "dns_tunnel_ttl_choices": [{"value": -1, "weight": 0}],
            }

        monkeypatch.setattr(network_params, "load_network_params", load_invalid_network_params)

        result = validate_config()

        assert any(
            issue.severity == "ERROR"
            and issue.file == "network_params.yaml (dns_tunnel_ttl_choices)"
            for issue in result.issues
        )

    def test_validate_config_rejects_invalid_auth_noise_ranges(self, monkeypatch):
        from evidenceforge.generation.activity import auth_noise

        def load_invalid_auth_noise_config():
            return {
                "scheduled_stale_credentials": {
                    "account_base_names": ["svc_backup"],
                    "host_count_min": 3,
                    "host_count_max": 1,
                    "interval_ranges": [{"min_minutes": 120, "max_minutes": 60, "weight": 1}],
                    "first_occurrence_seconds_min": 0,
                    "first_occurrence_seconds_max": 2700,
                    "jitter_seconds_min": -420,
                    "jitter_seconds_max": 780,
                    "skip_probability": 0.10,
                    "backoff_probability": 0.10,
                    "backoff_seconds_min": 900,
                    "backoff_seconds_max": 3600,
                }
            }

        monkeypatch.setattr(auth_noise, "load_auth_noise_config", load_invalid_auth_noise_config)

        result = validate_config()

        assert any(
            issue.severity == "ERROR"
            and issue.file == "auth_noise.yaml"
            and (
                "max_minutes must be greater than or equal to min_minutes" in issue.message
                or "host_count_max must be greater than or equal to host_count_min" in issue.message
            )
            for issue in result.issues
        )

    def test_validate_config_rejects_too_short_workstation_unlock_gap(self, monkeypatch):
        from evidenceforge.generation.activity import windows_auth_realism

        def load_invalid_windows_auth_realism():
            return {"workstation_lock": {"min_unlock_gap_seconds": 10}}

        monkeypatch.setattr(
            windows_auth_realism,
            "load_windows_auth_realism",
            load_invalid_windows_auth_realism,
        )

        result = validate_config()

        assert any(
            issue.severity == "ERROR"
            and issue.file == "windows_auth_realism.yaml"
            and "min_unlock_gap_seconds must be at least 60" in issue.message
            for issue in result.issues
        )

    def test_validate_config_rejects_too_large_workstation_unlock_gap(self, monkeypatch):
        from evidenceforge.generation.activity import windows_auth_realism

        def load_invalid_windows_auth_realism():
            return {"workstation_lock": {"min_unlock_gap_seconds": 1_000_000}}

        monkeypatch.setattr(
            windows_auth_realism,
            "load_windows_auth_realism",
            load_invalid_windows_auth_realism,
        )

        result = validate_config()

        assert any(
            issue.severity == "ERROR"
            and issue.file == "windows_auth_realism.yaml"
            and "min_unlock_gap_seconds must be at most 86400" in issue.message
            for issue in result.issues
        )

    def test_validate_config_rejects_empty_failed_auth_validation_path(self, monkeypatch):
        from evidenceforge.generation.activity import windows_auth_realism

        def load_invalid_windows_auth_realism():
            return {
                "workstation_lock": {"min_unlock_gap_seconds": 127},
                "failed_logon": {
                    "local_interactive": {
                        "logon_process_name": "User32",
                        "authentication_package_name": "Negotiate",
                        "process_name": r"C:\Windows\System32\winlogon.exe",
                    },
                    "network": {
                        "validation_path_weights": {
                            "none": {"emit_4776": False, "emit_4771": False, "weight": 1}
                        },
                        "logon_process_weights": {
                            "ntlm": {
                                "logon_process_name": "NtLmSsp",
                                "authentication_package_name": "NTLM",
                                "lm_package_name": "NTLM V2",
                                "weight": 1,
                            }
                        },
                        "emit_network_connection_probability": 1.0,
                        "network_ports": {"smb": {"port": 445, "weight": 1}},
                    },
                },
                "special_privileges": {
                    "profiles": {
                        "service_account": {
                            "privileges": ["SeChangeNotifyPrivilege"],
                            "weight": 1,
                        },
                        "domain_admin": {"privileges": ["SeDebugPrivilege"], "weight": 1},
                        "workstation_admin": {
                            "privileges": ["SeBackupPrivilege"],
                            "weight": 1,
                        },
                        "uac_elevated_user": {
                            "privileges": ["SeChangeNotifyPrivilege"],
                            "weight": 1,
                        },
                    }
                },
            }

        monkeypatch.setattr(
            windows_auth_realism,
            "load_windows_auth_realism",
            load_invalid_windows_auth_realism,
        )

        result = validate_config()

        assert any(
            issue.severity == "ERROR"
            and issue.file == "windows_auth_realism.yaml"
            and "validation path must emit at least one DC-side event" in issue.message
            for issue in result.issues
        )

    def test_validate_config_rejects_invalid_special_privilege_name(self, monkeypatch):
        from evidenceforge.generation.activity import windows_auth_realism

        def load_invalid_windows_auth_realism():
            return {
                "workstation_lock": {"min_unlock_gap_seconds": 127},
                "failed_logon": {
                    "local_interactive": {
                        "logon_process_name": "User32",
                        "authentication_package_name": "Negotiate",
                        "process_name": r"C:\Windows\System32\winlogon.exe",
                    },
                    "network": {
                        "validation_path_weights": {
                            "ntlm": {"emit_4776": True, "emit_4771": False, "weight": 1}
                        },
                        "logon_process_weights": {
                            "ntlm": {
                                "logon_process_name": "NtLmSsp",
                                "authentication_package_name": "NTLM",
                                "lm_package_name": "NTLM V2",
                                "weight": 1,
                            }
                        },
                        "emit_network_connection_probability": 1.0,
                        "network_ports": {"smb": {"port": 445, "weight": 1}},
                    },
                },
                "special_privileges": {
                    "profiles": {
                        "service_account": {
                            "privileges": ["SeChangeNotifyPrivilege"],
                            "weight": 1,
                        },
                        "domain_admin": {"privileges": ["Debug"], "weight": 1},
                        "workstation_admin": {
                            "privileges": ["SeBackupPrivilege"],
                            "weight": 1,
                        },
                        "uac_elevated_user": {
                            "privileges": ["SeChangeNotifyPrivilege"],
                            "weight": 1,
                        },
                    }
                },
            }

        monkeypatch.setattr(
            windows_auth_realism,
            "load_windows_auth_realism",
            load_invalid_windows_auth_realism,
        )

        result = validate_config()

        assert any(
            issue.severity == "ERROR"
            and issue.file == "windows_auth_realism.yaml"
            and "Windows privileges must use Se*Privilege names" in issue.message
            for issue in result.issues
        )

    def test_validate_config_rejects_dns_ids_template_on_non_dns_signature(self, monkeypatch):
        from evidenceforge.generation.activity import ids_signatures

        def load_invalid_ids_signatures():
            return {
                "signatures": [
                    {
                        "sid": 999001,
                        "rev": 1,
                        "message": "ET TEST Non-DNS",
                        "classification": "misc-activity",
                        "priority": 3,
                        "proto": "tcp",
                        "dst_port": 80,
                        "direction": "out",
                        "dns_query_templates": ["bad-{token}.example"],
                    }
                ]
            }

        monkeypatch.setattr(ids_signatures, "load_ids_signatures", load_invalid_ids_signatures)

        result = validate_config()

        assert any(
            issue.severity == "ERROR"
            and issue.file == "ids_signatures.yaml"
            and "defines dns_query_templates but is not a DNS signature" in issue.message
            for issue in result.issues
        )

    def test_validate_config_rejects_unsafe_dns_ids_template(self, monkeypatch):
        from evidenceforge.generation.activity import ids_signatures

        def load_invalid_ids_signatures():
            return {
                "signatures": [
                    {
                        "sid": 999002,
                        "rev": 1,
                        "message": "ET TEST DNS",
                        "classification": "misc-activity",
                        "priority": 3,
                        "proto": "udp",
                        "dst_port": 53,
                        "direction": "out",
                        "dns_query_templates": ["{token}{missing}.example"],
                    }
                ]
            }

        monkeypatch.setattr(ids_signatures, "load_ids_signatures", load_invalid_ids_signatures)
        result = validate_config()
        assert any(
            issue.severity == "ERROR"
            and issue.file == "ids_signatures.yaml"
            and "may only reference {token}" in issue.message
            for issue in result.issues
        )

    def test_validate_config_rejects_conflicting_ids_rule_identity(self, monkeypatch):
        from evidenceforge.generation.activity import ids_signatures

        def load_conflicting_ids_signatures():
            return {
                "signatures": [
                    {
                        "sid": 999003,
                        "rev": 1,
                        "message": "ET TEST First Meaning",
                        "classification": "misc-activity",
                        "priority": 3,
                        "proto": "tcp",
                        "dst_port": 80,
                        "direction": "in",
                    },
                    {
                        "sid": 999003,
                        "rev": 2,
                        "message": "ET TEST Different Meaning",
                        "classification": "misc-activity",
                        "priority": 3,
                        "proto": "tcp",
                        "dst_port": 443,
                        "direction": "in",
                    },
                ]
            }

        monkeypatch.setattr(ids_signatures, "load_ids_signatures", load_conflicting_ids_signatures)

        result = validate_config()

        assert any(
            issue.severity == "ERROR"
            and issue.file == "ids_signatures.yaml"
            and "IDS rule gid/sid [1:999003] message conflicts" in issue.message
            for issue in result.issues
        )

    def test_validate_config_rejects_boot_only_process_in_system_services(self, monkeypatch):
        from evidenceforge.generation.activity import system_processes

        real_loader = system_processes.load_system_processes

        def load_invalid_system_processes():
            data = real_loader()
            services = {
                role: [dict(entry) for entry in entries]
                for role, entries in data.get("system_services", {}).items()
            }
            services.setdefault("domain_controller", []).append(
                {
                    "image": r"C:\Windows\System32\lsass.exe",
                    "command_templates": [r"C:\Windows\system32\lsass.exe"],
                    "parent": "wininit",
                }
            )
            return {**data, "system_services": services}

        monkeypatch.setattr(
            system_processes, "load_system_processes", load_invalid_system_processes
        )

        result = validate_config()

        assert any(
            issue.severity == "ERROR"
            and issue.file == "system_processes.yaml"
            and 'Boot-only Windows process "lsass.exe"' in issue.message
            for issue in result.issues
        )

    def test_validate_config_rejects_command_template_escaped_brace_leaks(self, monkeypatch):
        from evidenceforge.generation.activity import application_catalog

        real_loader = application_catalog.load_catalog

        def load_invalid_catalog():
            data = real_loader()
            apps = []
            for app in data.get("applications", []):
                app_copy = dict(app)
                platforms = {
                    name: dict(platform) for name, platform in app.get("platforms", {}).items()
                }
                if app_copy.get("id") == "docker":
                    windows = dict(platforms["windows"])
                    windows["command_templates"] = [
                        'docker.exe images --format "table {{{{.Repository}}}}"'
                    ]
                    platforms["windows"] = windows
                app_copy["platforms"] = platforms
                apps.append(app_copy)
            return {**data, "applications": apps}

        monkeypatch.setattr(application_catalog, "load_catalog", load_invalid_catalog)

        result = validate_config()

        assert any(
            issue.severity == "ERROR"
            and issue.file == "application_catalog.yaml"
            and 'App "docker" command template for windows contains escaped literal braces'
            in issue.message
            for issue in result.issues
        )

    def test_validate_config_rejects_recurring_syslog_startup_banner(self, monkeypatch):
        from evidenceforge.generation.activity import extra_syslog

        def load_invalid_extra_syslog_messages():
            return [
                {
                    "app": "accounts-daemon",
                    "messages": ["started daemon version 22.08.8"],
                }
            ]

        monkeypatch.setattr(
            extra_syslog, "load_extra_syslog_messages", load_invalid_extra_syslog_messages
        )

        result = validate_config()

        assert any(
            issue.severity == "ERROR"
            and issue.file == "extra_syslog_messages.yaml"
            and 'Persistent app "accounts-daemon" has recurring startup banner' in issue.message
            for issue in result.issues
        )

    def test_validate_config_rejects_cron_hourly_in_extra_syslog_noise(self, monkeypatch):
        from evidenceforge.generation.activity import extra_syslog

        def load_invalid_extra_syslog_messages():
            return [
                {
                    "app": "cron",
                    "transient": True,
                    "messages": [
                        "(root) CMD (test -x /usr/sbin/anacron || "
                        "( cd / && run-parts /etc/cron.hourly ))"
                    ],
                }
            ]

        monkeypatch.setattr(
            extra_syslog, "load_extra_syslog_messages", load_invalid_extra_syslog_messages
        )

        result = validate_config()

        assert any(
            issue.severity == "ERROR"
            and issue.file == "extra_syslog_messages.yaml"
            and "cron.hourly" in issue.message
            for issue in result.issues
        )

    def test_validate_config_rejects_nonpositive_extra_syslog_weight(self, monkeypatch):
        from evidenceforge.generation.activity import extra_syslog

        def load_invalid_extra_syslog_messages():
            return [
                {
                    "app": "sudo",
                    "transient": True,
                    "weight": 0,
                    "messages": ["admin : TTY=pts/0 ; USER=root ; COMMAND=/usr/bin/id"],
                }
            ]

        monkeypatch.setattr(
            extra_syslog, "load_extra_syslog_messages", load_invalid_extra_syslog_messages
        )

        result = validate_config()

        assert any(
            issue.severity == "ERROR"
            and issue.file == "extra_syslog_messages.yaml"
            and "weight" in issue.message
            for issue in result.issues
        )

    def test_validate_config_rejects_networkmanager_same_state_transition(self, monkeypatch):
        from evidenceforge.generation.activity import extra_syslog

        def load_invalid_extra_syslog_messages():
            return [
                {
                    "app": "NetworkManager",
                    "messages": [
                        "<info>  [{}] device (ens160): state change: activated -> activated"
                    ],
                }
            ]

        monkeypatch.setattr(
            extra_syslog, "load_extra_syslog_messages", load_invalid_extra_syslog_messages
        )

        result = validate_config()

        assert any(
            issue.severity == "ERROR"
            and issue.file == "extra_syslog_messages.yaml"
            and "NetworkManager state transition must change states" in issue.message
            for issue in result.issues
        )

    def test_validate_config_rejects_invalid_4672_emission_probability(self, monkeypatch):
        from evidenceforge.generation.activity import windows_auth_realism

        real_loader = windows_auth_realism.load_windows_auth_realism

        def load_invalid_windows_auth_realism():
            data = real_loader()
            special_privileges = dict(data["special_privileges"])
            probabilities = dict(special_privileges.get("emission_probabilities", {}))
            probabilities["service_account"] = 1.5
            special_privileges["emission_probabilities"] = probabilities
            return {**data, "special_privileges": special_privileges}

        monkeypatch.setattr(
            windows_auth_realism,
            "load_windows_auth_realism",
            load_invalid_windows_auth_realism,
        )

        result = validate_config()

        assert any(
            issue.severity == "ERROR"
            and issue.file == "windows_auth_realism.yaml"
            and "emission_probabilities" in issue.message
            for issue in result.issues
        )
