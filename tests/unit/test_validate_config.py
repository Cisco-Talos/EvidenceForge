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
