# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Tests for data-driven Kerberos realism profiles."""

import random

from evidenceforge.generation.activity import kerberos_realism


def test_default_tgt_success_profile_mostly_uses_encrypted_timestamp():
    rng = random.Random(7)

    counts: dict[int, int] = {}
    for _ in range(1000):
        fields = kerberos_realism.pick_tgt_success_fields(rng)
        counts[fields["pre_auth_type"]] = counts.get(fields["pre_auth_type"], 0) + 1

    assert counts[2] > 900
    assert counts.get(15, 0) < 60


def test_pkinit_profile_populates_certificate_fields(monkeypatch):
    def load_pkinit_only_config():
        return {
            "tgt_success": {
                "pre_auth_types": {
                    "pkinit": {
                        "value": 15,
                        "weight": 1,
                        "certificate_required": True,
                        "certificate_profile": "enterprise_user",
                    }
                },
                "ticket_options": {"default": {"value": "0x40810010", "weight": 1}},
                "encryption_types": {"aes256": {"value": "0x12", "weight": 1}},
            },
            "certificate_profiles": {
                "enterprise_user": {
                    "issuer_names": ["CN=Acme Enterprise Issuing CA, O=Acme Corp, C=US"],
                    "serial_hex_bytes": 16,
                    "thumbprint_hex_chars": 40,
                }
            },
        }

    monkeypatch.setattr(kerberos_realism, "load_kerberos_realism", load_pkinit_only_config)

    fields = kerberos_realism.pick_tgt_success_fields(random.Random(3))

    assert fields["pre_auth_type"] == 15
    assert fields["cert_issuer_name"] == "CN=Acme Enterprise Issuing CA, O=Acme Corp, C=US"
    assert len(fields["cert_serial_number"]) == 32
    assert len(fields["cert_thumbprint"]) == 40


def test_non_pkinit_profile_leaves_certificate_fields_empty(monkeypatch):
    def load_encrypted_timestamp_only_config():
        return {
            "tgt_success": {
                "pre_auth_types": {
                    "encrypted_timestamp": {
                        "value": 2,
                        "weight": 1,
                        "certificate_required": False,
                    }
                },
                "ticket_options": {"default": {"value": "0x40810010", "weight": 1}},
                "encryption_types": {"aes256": {"value": "0x12", "weight": 1}},
            },
            "certificate_profiles": {},
        }

    monkeypatch.setattr(
        kerberos_realism, "load_kerberos_realism", load_encrypted_timestamp_only_config
    )

    fields = kerberos_realism.pick_tgt_success_fields(random.Random(3))

    assert fields["pre_auth_type"] == 2
    assert fields["cert_issuer_name"] == ""
    assert fields["cert_serial_number"] == ""
    assert fields["cert_thumbprint"] == ""


def test_kerberos_realism_overlay_overrides_nested_weight(tmp_path, monkeypatch):
    overlay_dir = tmp_path / ".eforge" / "config" / "activity"
    overlay_dir.mkdir(parents=True)
    (overlay_dir / "kerberos_realism.yaml").write_text(
        "tgt_success:\n  pre_auth_types:\n    encrypted_timestamp:\n      weight: 1\n",
        encoding="utf-8",
    )

    monkeypatch.chdir(tmp_path)
    kerberos_realism.reset_kerberos_realism_cache()

    data = kerberos_realism.load_kerberos_realism()

    assert data["tgt_success"]["pre_auth_types"]["encrypted_timestamp"]["value"] == 2
    assert data["tgt_success"]["pre_auth_types"]["encrypted_timestamp"]["weight"] == 1
    kerberos_realism.reset_kerberos_realism_cache()
