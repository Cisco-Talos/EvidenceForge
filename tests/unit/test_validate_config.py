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
