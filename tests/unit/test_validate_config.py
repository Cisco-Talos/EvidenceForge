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
