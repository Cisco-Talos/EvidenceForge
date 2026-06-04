# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Regression test: eforge validate-config must ship 100% clean."""

import random

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

    def test_validate_config_rejects_non_mapping_web_scan_ids_ua(self, monkeypatch):
        from evidenceforge.config import web_scan_presets

        def load_invalid_web_scan_presets():
            return {
                "presets": {
                    "nikto": {
                        "ids_ua": [],
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
            and 'Preset "nikto" ids_ua must be a mapping, got list' in issue.message
            for issue in result.issues
        )

    def test_validate_config_rejects_non_mapping_web_scan_path_ids(self, monkeypatch):
        from evidenceforge.config import web_scan_presets

        def load_invalid_web_scan_presets():
            return {
                "presets": {
                    "nikto": {
                        "paths": [{"uri": "/cgi-bin/test", "status": 404, "ids": []}],
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
            and 'Preset "nikto" path #1 (/cgi-bin/test) ids must be a mapping, got list'
            in issue.message
            for issue in result.issues
        )

    def test_validate_config_rejects_non_numeric_web_scan_ids_fields(self, monkeypatch):
        from evidenceforge.config import web_scan_presets

        def load_invalid_web_scan_presets():
            return {
                "presets": {
                    "nikto": {
                        "ids_ua": {"sid": "bad", "message": "ua", "rev": "x"},
                        "ids_rate": {"sid": 200001, "message": "rate", "priority": "high"},
                        "paths": [
                            {
                                "uri": "/cgi-bin/test",
                                "status": 404,
                                "ids": {"sid": "oops", "message": "path"},
                            }
                        ],
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
            and 'Preset "nikto" ids_ua sid must be a positive integer' in issue.message
            for issue in result.issues
        )
        assert any(
            issue.severity == "ERROR"
            and issue.file == "web_scan_presets.yaml"
            and 'Preset "nikto" ids_rate priority must be a positive integer' in issue.message
            for issue in result.issues
        )
        assert any(
            issue.severity == "ERROR"
            and issue.file == "web_scan_presets.yaml"
            and 'Preset "nikto" path #1 (/cgi-bin/test) ids sid must be a positive integer'
            in issue.message
            for issue in result.issues
        )

    def test_validate_config_rejects_non_numeric_ids_signature_fields(self, monkeypatch):
        from evidenceforge.generation.activity import ids_signatures

        def load_invalid_ids_signatures():
            return {
                "signatures": [
                    {
                        "sid": "bad-sid",
                        "rev": "bad-rev",
                        "message": "bad numeric fields",
                        "classification": "misc-activity",
                        "priority": "bad-priority",
                        "proto": "tcp",
                        "gid": "bad-gid",
                    }
                ]
            }

        monkeypatch.setattr(ids_signatures, "load_ids_signatures", load_invalid_ids_signatures)

        result = validate_config()

        assert any(
            issue.severity == "ERROR"
            and issue.file == "ids_signatures.yaml"
            and "sid must be a positive integer" in issue.message
            for issue in result.issues
        )
        assert any(
            issue.severity == "ERROR"
            and issue.file == "ids_signatures.yaml"
            and "rev must be a positive integer" in issue.message
            for issue in result.issues
        )
        assert any(
            issue.severity == "ERROR"
            and issue.file == "ids_signatures.yaml"
            and "priority must be a positive integer" in issue.message
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
                "ecar_flow_identity": {
                    "user_process_probability": 0.88,
                    "service_process_probability": 0.48,
                    "root_process_probability": 0.42,
                    "inbound_listener_probability": 0.36,
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

    def test_validate_config_rejects_invalid_observation_profile_source(self, monkeypatch):
        from evidenceforge.config import observation_profiles

        def load_invalid_observation_profiles():
            return {
                "profiles": {
                    "complete": {
                        "description": "bad",
                        "default": {
                            "missingness": 0.0,
                            "delay_ms": {"min_ms": 0, "max_ms": 0},
                            "host_missingness_multiplier": {"min": 1.0, "max": 1.0},
                        },
                        "sources": {"zeek_http": {"missingness": 0.1}},
                    }
                }
            }

        monkeypatch.setattr(
            observation_profiles,
            "load_observation_profiles",
            load_invalid_observation_profiles,
        )

        result = validate_config()

        assert any(
            issue.severity == "ERROR"
            and issue.file == "observation_profiles.yaml"
            and "unknown observation source families" in issue.message
            for issue in result.issues
        )

    def test_validate_config_rejects_unknown_host_activity_family(self, monkeypatch):
        from evidenceforge.generation.activity import host_activity_profiles

        real_loader = host_activity_profiles.load_host_activity_profiles

        def load_invalid_host_activity_profiles():
            data = real_loader()
            host_types = dict(data["host_types"])
            workstation = dict(host_types["workstation"])
            workstation["families"] = {**workstation.get("families", {}), "zeek_magic": 1.5}
            host_types["workstation"] = workstation
            return {**data, "host_types": host_types}

        monkeypatch.setattr(
            host_activity_profiles,
            "load_host_activity_profiles",
            load_invalid_host_activity_profiles,
        )

        result = validate_config()

        assert any(
            issue.severity == "ERROR"
            and issue.file == "host_activity_profiles.yaml"
            and "unknown activity families" in issue.message
            for issue in result.issues
        )

    def test_validate_config_rejects_invalid_bash_workflow_model(self, monkeypatch):
        from evidenceforge.generation.activity import bash_commands

        real_loader = bash_commands.load_bash_commands

        def load_invalid_bash_commands():
            data = real_loader()
            return {
                **data,
                "workflow_model": {"selection_probability": 1.5},
                "workflows": {
                    **data.get("workflows", {}),
                    "sysadmin": [{"name": "bad", "weight": 1, "steps": [[]]}],
                },
            }

        monkeypatch.setattr(bash_commands, "load_bash_commands", load_invalid_bash_commands)

        result = validate_config()

        assert any(
            issue.severity == "ERROR"
            and issue.file == "bash_commands.yaml"
            and "workflow_model.selection_probability must be a number between 0 and 1"
            in issue.message
            for issue in result.issues
        )
        assert any(
            issue.severity == "ERROR"
            and issue.file == "bash_commands.yaml"
            and "steps[1] must be a command string or non-empty list" in issue.message
            for issue in result.issues
        )

    def test_validate_config_rejects_invalid_package_manager_model(self, monkeypatch):
        from evidenceforge.generation.activity import bash_commands

        real_loader = bash_commands.load_bash_commands

        def load_invalid_bash_commands():
            data = real_loader()
            return {
                **data,
                "package_manager_model": {
                    "families": {
                        "debian": {
                            "os_keywords": ["ubuntu"],
                            "command_prefixes": ["apt "],
                        },
                        "rpm": {
                            "os_keywords": ["centos"],
                            "command_prefixes": ["apt "],
                        },
                    }
                },
            }

        monkeypatch.setattr(bash_commands, "load_bash_commands", load_invalid_bash_commands)

        result = validate_config()

        assert any(
            issue.severity == "ERROR"
            and issue.file == "bash_commands.yaml"
            and "package-manager command prefix 'apt '" in issue.message
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

    def test_validate_config_rejects_inverted_tls_authority_profile(self, monkeypatch):
        from evidenceforge.generation.activity import tls_realism

        real_tls_loader = tls_realism.load_tls_realism

        def load_invalid_tls_realism():
            data = real_tls_loader()
            certificate_chains = dict(data.get("certificate_chains", {}))
            certificate_chains["authority_profiles"] = [
                {
                    "subject": "CN=Bad Root CA, O=Example, C=US",
                    "issuer": "CN=Bad Root CA, O=Example, C=US",
                    "not_valid_before": 200,
                    "not_valid_after": 100,
                    "key_type": "rsa",
                    "key_length": 2048,
                }
            ]
            return {**data, "certificate_chains": certificate_chains}

        monkeypatch.setattr(tls_realism, "load_tls_realism", load_invalid_tls_realism)

        result = validate_config()

        assert any(
            issue.severity == "ERROR"
            and issue.file == "tls_realism.yaml"
            and "authority profile not_valid_after must be after not_valid_before" in issue.message
            for issue in result.issues
        )

    def test_validate_config_rejects_child_ca_validity_outside_parent_window(self, monkeypatch):
        from evidenceforge.generation.activity import tls_realism

        real_tls_loader = tls_realism.load_tls_realism

        def load_invalid_tls_realism():
            data = real_tls_loader()
            certificate_chains = dict(data.get("certificate_chains", {}))
            certificate_chains["authority_profiles"] = [
                {
                    "subject": "CN=Parent Root CA, O=Example, C=US",
                    "issuer": "CN=Parent Root CA, O=Example, C=US",
                    "not_valid_before": 100,
                    "not_valid_after": 500,
                    "key_type": "rsa",
                    "key_length": 2048,
                },
                {
                    "subject": "CN=Child Issuing CA, O=Example, C=US",
                    "issuer": "CN=Parent Root CA, O=Example, C=US",
                    "not_valid_before": 200,
                    "not_valid_after": 600,
                    "key_type": "rsa",
                    "key_length": 2048,
                },
            ]
            return {**data, "certificate_chains": certificate_chains}

        monkeypatch.setattr(tls_realism, "load_tls_realism", load_invalid_tls_realism)

        result = validate_config()

        assert any(
            issue.severity == "ERROR"
            and issue.file == "tls_realism.yaml"
            and "authority profile validity must fit within issuer validity window" in issue.message
            for issue in result.issues
        )

    def test_validate_config_rejects_invalid_ocsp_request_path_bounds(self, monkeypatch):
        from evidenceforge.generation.activity import tls_realism

        real_tls_loader = tls_realism.load_tls_realism

        def load_invalid_tls_realism():
            data = real_tls_loader()
            ocsp = dict(data.get("ocsp", {}))
            ocsp["request_path"] = {
                "min_encoded_chars": 160,
                "max_encoded_chars": 40,
                "include_padding_probability": 0.35,
                "der_prefixes": ["MFE"],
            }
            return {**data, "ocsp": ocsp}

        monkeypatch.setattr(tls_realism, "load_tls_realism", load_invalid_tls_realism)

        result = validate_config()

        assert any(
            issue.severity == "ERROR"
            and issue.file == "tls_realism.yaml"
            and "max_encoded_chars must be >= min_encoded_chars" in issue.message
            for issue in result.issues
        )

    def test_validate_config_rejects_invalid_public_dns_profile(self, monkeypatch):
        from evidenceforge.generation.activity import public_dns_profiles

        def load_invalid_public_dns_profiles():
            return {
                "nameserver_profiles": [
                    {
                        "name": "bad",
                        "weight": -1,
                        "answer_sets": [["ns1.example.net"]],
                    }
                ],
                "mail_profiles": [],
                "aaaa_profiles": [
                    {
                        "name": "valid_aaaa",
                        "weight": 0,
                        "match_suffixes": ["example.com"],
                        "answer_sets": [["2606:4700::6810:84e5"]],
                    }
                ],
            }

        monkeypatch.setattr(
            public_dns_profiles,
            "load_public_dns_profiles",
            load_invalid_public_dns_profiles,
        )

        result = validate_config()

        assert any(
            issue.severity == "ERROR"
            and issue.file == "public_dns_profiles.yaml"
            and "weight must be non-negative" in issue.message
            for issue in result.issues
        )
        assert any(
            issue.severity == "ERROR"
            and issue.file == "public_dns_profiles.yaml"
            and "mail_profiles must not be empty" in issue.message
            for issue in result.issues
        )

    def test_validate_config_rejects_invalid_proxy_user_agent_stickiness(self, monkeypatch):
        from evidenceforge.generation.activity import proxy_user_agents

        real_loader = proxy_user_agents.load_proxy_user_agents

        def load_invalid_proxy_user_agents():
            data = real_loader()
            domain_overrides = dict(data.get("domain_overrides", {}))
            windows_update = dict(domain_overrides["windows_update"])
            windows_update["stickiness"] = "session"
            domain_overrides["windows_update"] = windows_update
            return {**data, "domain_overrides": domain_overrides}

        monkeypatch.setattr(
            proxy_user_agents,
            "load_proxy_user_agents",
            load_invalid_proxy_user_agents,
        )

        result = validate_config()

        assert any(
            issue.severity == "ERROR"
            and issue.file == "proxy_user_agents.yaml (domain_overrides)"
            and "Input should be 'request' or 'source_host'" in issue.message
            for issue in result.issues
        )

    def test_validate_config_rejects_unsafe_public_dns_templates(self, monkeypatch):
        from evidenceforge.generation.activity import public_dns_profiles

        def load_invalid_public_dns_profiles():
            return {
                "nameserver_profiles": [
                    {
                        "name": "bad_ns",
                        "weight": 1,
                        "answer_sets": [["{missing}"]],
                        "soa_rnames": ["{domain:1000000000}"],
                    }
                ],
                "mail_profiles": [
                    {
                        "name": "bad_mx",
                        "weight": 1,
                        "answer_sets": [["0 {domain_hyphen}.mail.example.net"]],
                    }
                ],
                "aaaa_profiles": [
                    {
                        "name": "bad_aaaa",
                        "weight": 0,
                        "match_suffixes": ["example.com"],
                        "answer_sets": [["{domain.__class__}"]],
                    }
                ],
            }

        monkeypatch.setattr(
            public_dns_profiles,
            "load_public_dns_profiles",
            load_invalid_public_dns_profiles,
        )

        result = validate_config()

        assert any(
            issue.severity == "ERROR"
            and issue.file == "public_dns_profiles.yaml"
            and "public DNS answer templates may only use" in issue.message
            for issue in result.issues
        )
        assert any(
            issue.severity == "ERROR"
            and issue.file == "public_dns_profiles.yaml"
            and "public DNS answer templates must not use format specifiers" in issue.message
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

    def test_validate_config_rejects_empty_kerberos_transport_profile(self, monkeypatch):
        from evidenceforge.generation.activity import kerberos_realism

        real_loader = kerberos_realism.load_kerberos_realism

        def load_invalid_kerberos_realism():
            data = real_loader()
            transport_profiles = dict(data["transport_profiles"])
            transport_profiles["default"] = {"udp": 0, "tcp": 0}
            return {**data, "transport_profiles": transport_profiles}

        monkeypatch.setattr(
            kerberos_realism, "load_kerberos_realism", load_invalid_kerberos_realism
        )

        result = validate_config()

        assert any(
            issue.severity == "ERROR"
            and issue.file == "kerberos_realism.yaml"
            and "transport profile must have a positive total weight" in issue.message
            for issue in result.issues
        )

    def test_validate_config_rejects_oversized_kerberos_transport_weight(self, monkeypatch):
        from evidenceforge.generation.activity import kerberos_realism

        real_loader = kerberos_realism.load_kerberos_realism

        def load_invalid_kerberos_realism():
            data = real_loader()
            transport_profiles = dict(data["transport_profiles"])
            transport_profiles["default"] = {"udp": 1_000_001, "tcp": 1}
            return {**data, "transport_profiles": transport_profiles}

        monkeypatch.setattr(
            kerberos_realism, "load_kerberos_realism", load_invalid_kerberos_realism
        )

        result = validate_config()

        assert any(
            issue.severity == "ERROR"
            and issue.file == "kerberos_realism.yaml"
            and "transport weights must be less than or equal to 1000000" in issue.message
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

    def test_validate_config_rejects_invalid_proxy_source_system_type(self, monkeypatch):
        from evidenceforge.generation.activity import proxy_uri

        real_loader = proxy_uri.load_proxy_uri_templates

        def load_invalid_proxy_templates():
            data = real_loader()
            domains = dict(data.get("domains", {}))
            domains["desktop.dropbox.com"] = {
                **domains["desktop.dropbox.com"],
                "source_system_types": ["laptop"],
            }
            return {**data, "domains": domains}

        monkeypatch.setattr(proxy_uri, "load_proxy_uri_templates", load_invalid_proxy_templates)

        result = validate_config()

        assert any(
            issue.severity == "ERROR"
            and issue.file == "proxy_uri_templates.yaml"
            and "invalid source_system_types" in issue.message
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

    def test_validate_config_rejects_invalid_edr_file_path_pools(self, monkeypatch):
        from evidenceforge.generation.activity import edr_pools

        real_loader = edr_pools.load_edr_pools

        def load_invalid_edr_pools():
            data = real_loader()
            return {
                **data,
                "file_paths_windows": [
                    r"C:\Windows\Prefetch\SVCHOST.EXE-{rand}.pf",
                ],
                "file_paths_linux": [
                    "/proc/{rand}/status",
                    "/etc/passwd",
                    "/var/lib/dpkg/status",
                    "/tmp/systemd-private-12345-apache2.service",
                ],
            }

        monkeypatch.setattr(edr_pools, "load_edr_pools", load_invalid_edr_pools)

        result = validate_config()

        assert any(
            issue.severity == "ERROR"
            and issue.file == "edr_pools.yaml (file_paths_windows)"
            and "Prefetch templates" in issue.message
            for issue in result.issues
        )
        assert any(
            issue.severity == "ERROR"
            and issue.file == "edr_pools.yaml (file_paths_linux)"
            and "/proc/<pid>/status" in issue.message
            for issue in result.issues
        )
        assert any(
            issue.severity == "ERROR"
            and issue.file == "edr_pools.yaml (file_paths_linux)"
            and "/etc/passwd" in issue.message
            for issue in result.issues
        )
        assert any(
            issue.severity == "ERROR"
            and issue.file == "edr_pools.yaml (file_paths_linux)"
            and "package-manager state paths" in issue.message
            for issue in result.issues
        )
        assert any(
            issue.severity == "ERROR"
            and issue.file == "edr_pools.yaml (file_paths_linux)"
            and "apache2 systemd-private" in issue.message
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

    def test_validate_config_rejects_dns_tunnel_ttl_response_template(self, monkeypatch):
        from evidenceforge.generation.activity import network_params

        real_loader = network_params.load_network_params

        def load_invalid_network_params():
            data = real_loader()
            return {
                **data,
                "dns_tunnel_response_templates": ["slot-{seq}-t{ttl}-{token}"],
            }

        monkeypatch.setattr(network_params, "load_network_params", load_invalid_network_params)

        result = validate_config()

        assert any(
            issue.severity == "ERROR"
            and issue.file == "network_params.yaml (dns_tunnel_response_templates)"
            and "ttl" in issue.message
            for issue in result.issues
        )

    def test_validate_config_rejects_readable_dns_tunnel_response_template(self, monkeypatch):
        from evidenceforge.generation.activity import network_params

        real_loader = network_params.load_network_params

        def load_invalid_network_params():
            data = real_loader()
            return {
                **data,
                "dns_tunnel_response_templates": ["xid:{token}:path-{edge}:n{seq}"],
            }

        monkeypatch.setattr(network_params, "load_network_params", load_invalid_network_params)

        result = validate_config()

        assert any(
            issue.severity == "ERROR"
            and issue.file == "network_params.yaml (dns_tunnel_response_templates)"
            and "readable literal text" in issue.message
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

    def test_validate_config_rejects_invalid_proxy_connect_status_messages(self, monkeypatch):
        from evidenceforge.generation.activity import network_params

        real_loader = network_params.load_network_params

        def load_invalid_network_params():
            data = real_loader()
            return {
                **data,
                "proxy_connect_status_messages": {407: []},
            }

        monkeypatch.setattr(network_params, "load_network_params", load_invalid_network_params)

        result = validate_config()

        assert any(
            issue.severity == "ERROR"
            and issue.file == "network_params.yaml (proxy_connect_status_messages)"
            for issue in result.issues
        )

    def test_validate_config_rejects_dns_tunnel_rcode_weight_overflow(self, monkeypatch):
        from evidenceforge.generation.activity import network_params

        real_loader = network_params.load_network_params

        def load_invalid_network_params():
            data = real_loader()
            return {
                **data,
                "dns_tunnel_rcode_weights": {"NOERROR": 1.0e308, "NXDOMAIN": 1.0e308},
            }

        monkeypatch.setattr(network_params, "load_network_params", load_invalid_network_params)

        result = validate_config()

        assert any(
            issue.severity == "ERROR"
            and issue.file == "network_params.yaml (dns_tunnel_rcode_weights)"
            and "positive finite total" in issue.message
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

    def test_validate_config_rejects_non_finite_dns_tunnel_ttl_weight(self, monkeypatch):
        from evidenceforge.generation.activity import network_params

        real_loader = network_params.load_network_params

        def load_invalid_network_params():
            data = real_loader()
            return {
                **data,
                "dns_tunnel_ttl_choices": [{"value": 9, "weight": float("inf")}],
            }

        monkeypatch.setattr(network_params, "load_network_params", load_invalid_network_params)

        result = validate_config()

        assert any(
            issue.severity == "ERROR"
            and issue.file == "network_params.yaml (dns_tunnel_ttl_choices)"
            for issue in result.issues
        )

    def test_validate_config_rejects_invalid_external_scanner_profile(self, monkeypatch):
        from evidenceforge.generation.activity import network_params

        real_loader = network_params.load_network_params

        def load_invalid_network_params():
            data = real_loader()
            return {
                **data,
                "external_scanner_port_profiles": [
                    {"name": "bad", "weight": 1, "ports": [{"port": 70000, "weight": 1}]}
                ],
            }

        monkeypatch.setattr(network_params, "load_network_params", load_invalid_network_params)

        result = validate_config()

        assert any(
            issue.severity == "ERROR"
            and issue.file == "network_params.yaml (external_scanner_port_profiles)"
            and "less than or equal to 65535" in issue.message
            for issue in result.issues
        )

    def test_validate_config_rejects_overflowing_dns_tunnel_ttl_weight_total(self, monkeypatch):
        from evidenceforge.generation.activity import network_params

        real_loader = network_params.load_network_params

        def load_invalid_network_params():
            data = real_loader()
            return {
                **data,
                "dns_tunnel_ttl_choices": [
                    {"value": 9, "weight": 1e308},
                    {"value": 10, "weight": 1e308},
                ],
            }

        monkeypatch.setattr(network_params, "load_network_params", load_invalid_network_params)

        result = validate_config()

        assert any(
            issue.severity == "ERROR"
            and issue.file == "network_params.yaml (dns_tunnel_ttl_choices)"
            and "total" in issue.message
            for issue in result.issues
        )

    def test_validate_config_rejects_overflowing_external_scanner_profile_weights(
        self, monkeypatch
    ):
        from evidenceforge.generation.activity import network_params

        real_loader = network_params.load_network_params

        def load_invalid_network_params():
            data = real_loader()
            return {
                **data,
                "external_scanner_port_profiles": [
                    {"name": "a", "weight": 1e308, "ports": [{"port": 443, "weight": 1}]},
                    {"name": "b", "weight": 1e308, "ports": [{"port": 8443, "weight": 1}]},
                ],
            }

        monkeypatch.setattr(network_params, "load_network_params", load_invalid_network_params)

        result = validate_config()

        assert any(
            issue.severity == "ERROR"
            and issue.file == "network_params.yaml (external_scanner_port_profiles)"
            and "total external_scanner_port_profiles weight must be finite" in issue.message
            for issue in result.issues
        )

    def test_validate_config_rejects_overflowing_external_scanner_port_weights(self, monkeypatch):
        from evidenceforge.generation.activity import network_params

        real_loader = network_params.load_network_params

        def load_invalid_network_params():
            data = real_loader()
            return {
                **data,
                "external_scanner_port_profiles": [
                    {
                        "name": "bad_ports",
                        "weight": 1.0,
                        "ports": [
                            {"port": 443, "weight": 1e308},
                            {"port": 8443, "weight": 1e308},
                        ],
                    }
                ],
            }

        monkeypatch.setattr(network_params, "load_network_params", load_invalid_network_params)

        result = validate_config()

        assert any(
            issue.severity == "ERROR"
            and issue.file == "network_params.yaml (external_scanner_port_profiles)"
            and "entry 0 has non-finite cumulative port weight" in issue.message
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

    def test_validate_config_rejects_invalid_auth_noise_account_names(self, monkeypatch):
        from evidenceforge.generation.activity import auth_noise

        def load_invalid_auth_noise_config():
            return {
                "scheduled_stale_credentials": {
                    "account_base_names": ["svc_backup", "bad name", "svc/foo"],
                    "host_count_min": 1,
                    "host_count_max": 1,
                    "interval_ranges": [{"min_minutes": 60, "max_minutes": 120, "weight": 1}],
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
            and "account_base_names entries must match scenario username syntax" in issue.message
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

    def test_validate_config_reports_invalid_extra_syslog_messages_schema(self, monkeypatch):
        from evidenceforge.generation.activity import extra_syslog

        def load_invalid_extra_syslog_messages():
            return [
                {
                    "app": "attacker-controlled-null-app",
                    "messages": None,
                },
                {
                    "app": "attacker-controlled-scalar-app",
                    "messages": 123,
                },
            ]

        monkeypatch.setattr(
            extra_syslog, "load_extra_syslog_messages", load_invalid_extra_syslog_messages
        )

        result = validate_config()

        assert any(
            issue.severity == "ERROR"
            and issue.file == "extra_syslog_messages.yaml"
            and 'Entry "attacker-controlled-null-app"' in issue.message
            and "messages" in issue.message
            for issue in result.issues
        )
        assert any(
            issue.severity == "ERROR"
            and issue.file == "extra_syslog_messages.yaml"
            and 'Entry "attacker-controlled-scalar-app"' in issue.message
            and "messages" in issue.message
            for issue in result.issues
        )

    def test_validate_config_reports_extra_syslog_params_type_errors_without_crashing(
        self, monkeypatch
    ):
        from evidenceforge.generation.activity import extra_syslog

        def load_invalid_extra_syslog_messages():
            return [
                {
                    "app": "attacker-controlled-bad-params",
                    "messages": ["ordinary message"],
                    "params": {"bad": 1},
                }
            ]

        monkeypatch.setattr(
            extra_syslog, "load_extra_syslog_messages", load_invalid_extra_syslog_messages
        )

        result = validate_config()

        assert any(
            issue.severity == "ERROR"
            and issue.file == "extra_syslog_messages.yaml"
            and 'Entry "attacker-controlled-bad-params"' in issue.message
            and "params" in issue.message
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

    def test_validate_config_rejects_invalid_extra_syslog_system_type(self, monkeypatch):
        from evidenceforge.generation.activity import extra_syslog

        def load_invalid_extra_syslog_messages():
            return [
                {
                    "app": "packagekitd",
                    "system_types": ["laptop"],
                    "messages": ["search-names transaction /12345"],
                }
            ]

        monkeypatch.setattr(
            extra_syslog, "load_extra_syslog_messages", load_invalid_extra_syslog_messages
        )

        result = validate_config()

        assert any(
            issue.severity == "ERROR"
            and issue.file == "extra_syslog_messages.yaml"
            and 'App "packagekitd" has invalid system_type "laptop"' in issue.message
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

    def test_extra_syslog_sudo_templates_render_contextual_services(self):
        from evidenceforge.generation.activity.extra_syslog import render_extra_syslog_message

        entry = {
            "app": "sudo",
            "messages": [
                "{sudo_user} : TTY={tty} ; PWD={cwd} ; USER=root ; COMMAND={sudo_command}"
            ],
            "params": {
                "sudo_user": ["deploy"],
                "tty": ["pts/1"],
                "cwd": ["/srv/app"],
                "service": ["ssh"],
                "sudo_command": ["/bin/systemctl status {service}"],
            },
        }

        message = render_extra_syslog_message(
            entry,
            random.Random(5),
            positional_value=123456,
            system_services=["nginx"],
        )

        assert message == (
            "deploy : TTY=pts/1 ; PWD=/srv/app ; USER=root ; COMMAND=/bin/systemctl status nginx"
        )

    def test_extra_syslog_treats_contextual_services_as_literals(self):
        from evidenceforge.generation.activity.extra_syslog import render_extra_syslog_message

        entry = {
            "app": "sudo",
            "messages": [
                "{sudo_user} : TTY={tty} ; PWD={cwd} ; USER=root ; COMMAND={sudo_command}"
            ],
            "params": {
                "sudo_user": ["deploy"],
                "tty": ["pts/1"],
                "cwd": ["/srv/app"],
                "service": ["ssh"],
                "sudo_command": ["/bin/systemctl status {service}"],
            },
        }

        missing_placeholder = render_extra_syslog_message(
            entry,
            random.Random(5),
            positional_value=123456,
            system_services=["{missing}"],
        )
        unmatched_brace = render_extra_syslog_message(
            entry,
            random.Random(5),
            positional_value=123456,
            system_services=["{"],
        )

        assert missing_placeholder.endswith("COMMAND=/bin/systemctl status {missing}")
        assert unmatched_brace.endswith("COMMAND=/bin/systemctl status {")

    def test_extra_syslog_explicit_values_override_yaml_params(self):
        from evidenceforge.generation.activity.extra_syslog import render_extra_syslog_message

        message = render_extra_syslog_message(
            {
                "app": "rsyslogd",
                "params": {"fd": ["695673"]},
                "messages": [
                    "imuxsock: Acquired UNIX socket '/run/systemd/journal/syslog' fd {fd}"
                ],
            },
            random.Random(5),
            positional_value=123456,
            values={"fd": 9},
        )

        assert message.endswith(" fd 9")
        assert "695673" not in message

    def test_extra_syslog_filters_by_system_type_and_excluded_roles(self):
        from evidenceforge.generation.activity.extra_syslog import filter_syslog_message_entries

        programs = [
            {
                "app": "packagekitd",
                "system_types": ["workstation"],
                "messages": ["search-names transaction /{}"],
            },
            {
                "app": "multipathd",
                "system_types": ["server"],
                "roles": ["database"],
                "messages": ["{device}: add missing path"],
            },
            {
                "app": "accounts-daemon",
                "exclude_roles": ["database"],
                "messages": ["user 'admin' has logged in"],
            },
        ]

        db_server = filter_syslog_message_entries(
            programs,
            is_rhel_like=False,
            host_roles=["database"],
            system_type="server",
        )
        workstation = filter_syslog_message_entries(
            programs,
            is_rhel_like=False,
            host_roles=[],
            system_type="workstation",
        )

        assert [entry["app"] for entry in db_server] == ["multipathd"]
        assert [entry["app"] for entry in workstation] == ["packagekitd", "accounts-daemon"]

    def test_extra_syslog_high_volume_daemons_avoid_exact_boilerplate(self):
        from evidenceforge.generation.activity.extra_syslog import (
            load_extra_syslog_messages,
            render_extra_syslog_message,
        )

        programs = load_extra_syslog_messages()
        high_volume_apps = {
            "dbus-daemon",
            "polkitd",
            "rsyslogd",
            "unattended-upgr",
            "systemd-resolved",
            "irqbalance",
        }
        old_exact_messages = {
            "[system] Activating via systemd: service name='org.freedesktop.hostname1'",
            "[system] Successfully activated service 'org.freedesktop.resolve1'",
            "[system] Activating via systemd: service name='org.freedesktop.timedate1'",
            '[origin software="rsyslogd"] rsyslogd was HUPed',
            "Allowed origins are: o=Ubuntu,a=jammy",
            "No packages found that can be upgraded unattended",
            "dpkg --status-fd: processing triggers for man-db",
            "Positive Trust Anchors: . IN DS 20326",
            "Balancing is ineffective IRQs are pinned and balanced",
            "Operator of unix-process:{} successfully authenticated as 'root'",
        }

        checked_apps = set()
        for entry in programs:
            app = entry.get("app")
            if app not in high_volume_apps:
                continue
            checked_apps.add(app)
            messages = entry.get("messages", [])
            assert not old_exact_messages.intersection(messages)
            assert any("{" in message for message in messages)
            if app == "systemd-resolved":
                assert "trust_anchor" not in (entry.get("params") or {})
                assert all("Positive Trust Anchors" not in message for message in messages)
            if app == "irqbalance":
                assert all("{}" not in message and "{0}" not in message for message in messages)
                assert all("from CPU" not in message for message in messages)
            if app == "polkitd":
                assert any("action {action_id}" in message for message in messages)
                assert all(
                    "AuthenticationAgent" in message or "action" in message for message in messages
                )
            for message in messages:
                rendered = render_extra_syslog_message(
                    {**entry, "messages": [message]},
                    random.Random(5),
                    positional_value=123456,
                    system_services=["sshd", "nginx"],
                    values={"dns_server": "10.10.2.10"},
                )
                assert "{" not in rendered
                assert "}" not in rendered
                if app == "systemd-resolved":
                    assert "UDP+EDNS0 instead of UDP+EDNS0" not in rendered

        assert checked_apps == high_volume_apps

    def test_extra_syslog_linux_maintenance_texture_excludes_schedule_native_cron(self):
        from evidenceforge.generation.activity.extra_syslog import load_extra_syslog_messages

        programs = load_extra_syslog_messages()
        apps = {entry["app"]: entry for entry in programs}

        assert "cron" not in apps
        assert "anacron" in apps

        sudo_entry = next(
            entry
            for entry in programs
            if entry["app"] == "sudo" and "sudo_command" in (entry.get("params") or {})
        )
        sudo_commands = sudo_entry["params"]["sudo_command"]
        service_commands = [command for command in sudo_commands if "{service}" in command]
        non_service_commands = [command for command in sudo_commands if "{service}" not in command]

        assert len(non_service_commands) >= len(service_commands) * 3
        assert any("list-timers" in command for command in non_service_commands)
        assert any("apt-get -s upgrade" in command for command in non_service_commands)
        assert any("vmstat" in command for command in non_service_commands)

        rendered_messages = []
        for entry in programs:
            if entry["app"] == "anacron":
                continue
            rendered_messages.extend(entry.get("messages", []))
            rendered_messages.extend(
                value
                for values in (entry.get("params") or {}).values()
                for value in values
                if isinstance(value, str)
            )
        schedule_native_patterns = (
            "apt.systemd.daily",
            "cron.daily",
            "cron.hourly",
            "debian-sa1",
            "logrotate /etc/logrotate.conf",
            "update-motd-reboot-required",
            "/tmp -xdev -type f -mtime",
        )
        assert not any(
            pattern in message.lower()
            for message in rendered_messages
            for pattern in schedule_native_patterns
        )

    def test_extra_syslog_web_sudo_denial_profile_is_sparse_and_not_over_thematic(self):
        from evidenceforge.generation.activity.extra_syslog import load_extra_syslog_messages

        programs = load_extra_syslog_messages()
        web_sudo = next(
            entry
            for entry in programs
            if entry["app"] == "sudo" and entry.get("roles") == ["web_server", "forward_proxy"]
        )
        denied_commands = web_sudo["params"]["denied_command"]

        assert web_sudo["max_per_host_window"] == 1
        assert not any("169.254.169.254" in command for command in denied_commands)
        assert not any("/etc/shadow" in command for command in denied_commands)
        assert any("/var/www" in command for command in denied_commands)

    def test_systemd_schedule_contains_sysstat_cron_cadence(self):
        from evidenceforge.generation.engine.baseline import _load_systemd_schedules

        debian_sa1 = next(
            schedule
            for schedule in _load_systemd_schedules()
            if schedule["service"] == "debian-sa1"
        )

        assert debian_sa1["type"] == "cron"
        assert debian_sa1["frequency"] == "30min"
        assert debian_sa1["cron_user"] == "sysstat"
        assert "debian-sa1" in debian_sa1["cron_commands"]["debian"]

    def test_extra_syslog_unattended_upgrades_bounds_phased_percentage(self):
        from evidenceforge.generation.activity.extra_syslog import (
            load_extra_syslog_messages,
            render_extra_syslog_message,
        )

        programs = load_extra_syslog_messages()
        unattended = next(entry for entry in programs if entry["app"] == "unattended-upgr")
        percentage_values = unattended["params"]["phased_percentage"]

        assert unattended["max_per_host_window"] <= 8
        assert all(0 <= int(value) <= 100 for value in percentage_values)
        assert not any(
            "phased update percentage {}" in message for message in unattended["messages"]
        )

        message = render_extra_syslog_message(
            {
                **unattended,
                "messages": [
                    "Package {package_name} kept back for phased update percentage {phased_percentage}"
                ],
            },
            random.Random(5),
            positional_value=981234,
        )
        percentage = int(message.rsplit(" ", 1)[-1])

        assert 0 <= percentage <= 100
        assert "981234" not in message

    def test_extra_syslog_anacron_uses_date_placeholder_and_no_weekly_pool(self):
        from evidenceforge.generation.activity.extra_syslog import (
            load_extra_syslog_messages,
            render_extra_syslog_message,
        )

        programs = load_extra_syslog_messages()
        anacron = next(entry for entry in programs if entry["app"] == "anacron")

        assert "cron.weekly" not in anacron["params"]["job_name"]
        assert "Anacron 2.3 started on {}" not in anacron["messages"]
        message = render_extra_syslog_message(
            {**anacron, "messages": ["Anacron 2.3 started on {anacron_date}"]},
            random.Random(5),
            positional_value=123456,
            values={"anacron_date": "2024-03-18"},
        )

        assert message == "Anacron 2.3 started on 2024-03-18"

    def test_systemd_schedule_filters_by_role_and_service_state(self):
        from types import SimpleNamespace

        from evidenceforge.generation.engine.baseline import _schedule_applies_to_system

        sched = {
            "service": "phpsessionclean",
            "roles": ["web_server"],
            "exclude_roles": ["forward_proxy"],
            "services_any": ["php-fpm"],
            "host_probability": 1.0,
        }

        php_web = SimpleNamespace(
            hostname="WEB-EXT-01",
            roles=["web_server"],
            services=["apache2", "php-fpm"],
        )
        nginx_only = SimpleNamespace(
            hostname="APP-INT-01",
            roles=["web_server"],
            services=["nginx", "systemd"],
        )
        proxy = SimpleNamespace(
            hostname="PROXY-01",
            roles=["forward_proxy"],
            services=["squid", "php-fpm"],
        )

        assert _schedule_applies_to_system(sched, php_web, has_web_role=True)
        assert not _schedule_applies_to_system(sched, nginx_only, has_web_role=True)
        assert not _schedule_applies_to_system(sched, proxy, has_web_role=True)
        assert not _schedule_applies_to_system(
            {**sched, "host_probability": 0.0},
            php_web,
            has_web_role=True,
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

    def test_validate_config_rejects_unsafe_web_session_profile_fields(self, monkeypatch):
        from evidenceforge.generation.activity import web_session_profiles

        real_loader = web_session_profiles.load_web_session_profiles

        def load_invalid_web_session_profiles():
            data = real_loader()
            visitor_classes = dict(data["visitor_classes"])
            probe = dict(visitor_classes["opportunistic_probe"])
            requests = [dict(request) for request in probe["requests"]]
            requests[0] = {
                **requests[0],
                "path": "/wp-login.php\nforged",
                "method": "GET\nPOST",
                "status": "not-an-int",
                "type": "text/html\nforged",
            }
            probe["requests"] = requests
            visitor_classes["opportunistic_probe"] = probe
            user_agent_pools = dict(data["user_agent_pools"])
            user_agent_pools["scanner"] = [*user_agent_pools["scanner"], "BadUA\nForged"]
            return {
                **data,
                "visitor_classes": visitor_classes,
                "user_agent_pools": user_agent_pools,
            }

        monkeypatch.setattr(
            web_session_profiles, "load_web_session_profiles", load_invalid_web_session_profiles
        )

        result = validate_config()

        assert any(
            issue.severity == "ERROR"
            and issue.file == "web_session_profiles.yaml"
            and "path must be a single-line path" in issue.message
            for issue in result.issues
        )
        assert any(
            issue.severity == "ERROR"
            and issue.file == "web_session_profiles.yaml"
            and "method must be a supported single-line HTTP method" in issue.message
            for issue in result.issues
        )
        assert any(
            issue.severity == "ERROR"
            and issue.file == "web_session_profiles.yaml"
            and "status must be an integer from 100 to 599" in issue.message
            for issue in result.issues
        )
        assert any(
            issue.severity == "ERROR"
            and issue.file == "web_session_profiles.yaml"
            and "type must be a single-line MIME type" in issue.message
            for issue in result.issues
        )
        assert any(
            issue.severity == "ERROR"
            and issue.file == "web_session_profiles.yaml"
            and "must be a non-empty single-line string" in issue.message
            for issue in result.issues
        )
