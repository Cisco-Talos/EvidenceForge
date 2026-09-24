# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Tests for data-driven Kerberos realism profiles."""

import random

from evidenceforge.generation.activity import kerberos_realism


def _scoped_pkinit_config() -> dict:
    """Return user/machine PKINIT profiles for credential-identity tests."""

    return {
        "tgt_success": {
            "pre_auth_types": {
                "user_pkinit": {
                    "value": 15,
                    "weight": 1,
                    "certificate_required": True,
                    "certificate_profile": "enterprise_user",
                    "principal_scopes": ["user"],
                },
                "machine_pkinit": {
                    "value": 15,
                    "weight": 1,
                    "certificate_required": True,
                    "certificate_profile": "enterprise_machine",
                    "principal_scopes": ["machine"],
                },
            },
            "ticket_options": {
                "first": {"value": "0x40810010", "weight": 1},
                "second": {"value": "0x40810000", "weight": 1},
            },
            "encryption_types": {
                "aes256": {"value": "0x12", "weight": 1},
                "aes128": {"value": "0x11", "weight": 1},
            },
        },
        "certificate_profiles": {
            "enterprise_user": {
                "issuer_names": ["CN=Acme Enterprise Smartcard CA, O=Acme Corp, C=US"],
                "serial_hex_bytes": 16,
                "thumbprint_hex_chars": 40,
                "credential_epoch": "user-v1",
                "principal_scopes": ["user"],
            },
            "enterprise_machine": {
                "issuer_names": ["CN=Acme Enterprise Device CA, O=Acme Corp, C=US"],
                "serial_hex_bytes": 16,
                "thumbprint_hex_chars": 40,
                "credential_epoch": "machine-v1",
                "principal_scopes": ["machine"],
            },
        },
    }


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


def test_pkinit_profile_adapts_placeholder_issuer_to_ad_domain(monkeypatch):
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
                    "issuer_names": ["CN=Acme Enterprise Smartcard CA, O=Acme Corp, C=US"],
                    "serial_hex_bytes": 16,
                    "thumbprint_hex_chars": 40,
                }
            },
        }

    monkeypatch.setattr(kerberos_realism, "load_kerberos_realism", load_pkinit_only_config)

    fields = kerberos_realism.pick_tgt_success_fields(random.Random(3), "meridianhcs.local")

    assert fields["cert_issuer_name"] == (
        "CN=Meridianhcs Enterprise Smartcard CA, O=Meridianhcs, C=US"
    )


def test_pkinit_credential_identity_is_sid_stable_across_requests_and_dcs(monkeypatch):
    """One directory principal reuses its certificate independent of request/DC RNG order."""

    monkeypatch.setattr(
        kerberos_realism,
        "load_kerberos_realism",
        _scoped_pkinit_config,
    )
    first = kerberos_realism.pick_tgt_success_fields(
        random.Random(3),
        "meridianhcs.local",
        principal_sid="S-1-5-21-101-202-303-1104",
        principal_scope="user",
    )
    second = kerberos_realism.pick_tgt_success_fields(
        random.Random(987),
        "MERIDIANHCS.LOCAL",
        principal_sid="s-1-5-21-101-202-303-1104",
        principal_scope="user",
    )

    certificate_fields = ("cert_issuer_name", "cert_serial_number", "cert_thumbprint")
    assert tuple(first[field] for field in certificate_fields) == tuple(
        second[field] for field in certificate_fields
    )
    assert first["encryption_type"] != second["encryption_type"]


def test_pkinit_credentials_are_distinct_by_canonical_sid(monkeypatch):
    """Different principals retain deterministic credential diversity."""

    monkeypatch.setattr(
        kerberos_realism,
        "load_kerberos_realism",
        _scoped_pkinit_config,
    )
    first = kerberos_realism.pick_tgt_success_fields(
        random.Random(5),
        principal_sid="S-1-5-21-101-202-303-1104",
        principal_scope="user",
    )
    second = kerberos_realism.pick_tgt_success_fields(
        random.Random(5),
        principal_sid="S-1-5-21-101-202-303-1105",
        principal_scope="user",
    )

    assert first["cert_thumbprint"] != second["cert_thumbprint"]
    assert first["cert_serial_number"] != second["cert_serial_number"]


def test_pkinit_profile_selection_is_principal_scope_aware(monkeypatch):
    """User and machine accounts use only certificate profiles eligible for their scope."""

    monkeypatch.setattr(
        kerberos_realism,
        "load_kerberos_realism",
        _scoped_pkinit_config,
    )
    user = kerberos_realism.pick_tgt_success_fields(
        random.Random(8),
        "meridianhcs.local",
        principal_sid="S-1-5-21-101-202-303-1104",
        principal_scope="user",
    )
    machine = kerberos_realism.pick_tgt_success_fields(
        random.Random(8),
        "meridianhcs.local",
        principal_sid="S-1-5-21-101-202-303-2104",
        principal_scope="machine",
    )

    assert "Smartcard CA" in user["cert_issuer_name"]
    assert "Device CA" in machine["cert_issuer_name"]


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


def test_non_pkinit_request_fields_are_unaffected_by_canonical_principal(monkeypatch):
    """Adding canonical credential identity must not perturb password-based TGT fields."""

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

    legacy = kerberos_realism.pick_tgt_success_fields(random.Random(13))
    canonical = kerberos_realism.pick_tgt_success_fields(
        random.Random(13),
        principal_sid="S-1-5-21-101-202-303-1104",
        principal_scope="user",
    )

    assert canonical == legacy


def test_tgt_success_no_preauth_requires_explicit_account_policy(monkeypatch):
    """A type-0 success profile is selectable only for an explicitly exempt account."""

    def load_no_preauth_only_config():
        return {
            "tgt_success": {
                "pre_auth_types": {
                    "none": {
                        "value": 0,
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
        kerberos_realism,
        "load_kerberos_realism",
        load_no_preauth_only_config,
    )

    ordinary = kerberos_realism.pick_tgt_success_fields(random.Random(3))
    exempt = kerberos_realism.pick_tgt_success_fields(
        random.Random(3),
        allow_no_preauth=True,
    )

    assert ordinary["pre_auth_type"] == 2
    assert exempt["pre_auth_type"] == 0


def test_bad_password_failure_requires_encrypted_timestamp_preauth(monkeypatch):
    """KDC_ERR_PREAUTH_FAILED cannot claim that no pre-authentication was supplied."""

    def load_failure_config():
        return {
            "tgt_failure": {
                "pre_auth_types": {
                    "none": {"value": 0, "weight": 100},
                    "encrypted_timestamp": {"value": 2, "weight": 1},
                },
                "ticket_options": {"default": {"value": "0x40810010", "weight": 1}},
            }
        }

    monkeypatch.setattr(kerberos_realism, "load_kerberos_realism", load_failure_config)

    for seed in range(20):
        fields = kerberos_realism.pick_tgt_failure_fields(random.Random(seed), "0x18")
        assert fields["pre_auth_type"] == 2


def test_kerberos_transport_profile_picks_udp_and_tcp(monkeypatch):
    def load_transport_config():
        return {
            "transport_profiles": {
                "default": {
                    "udp": 3,
                    "tcp": 1,
                }
            }
        }

    monkeypatch.setattr(kerberos_realism, "load_kerberos_realism", load_transport_config)

    picks = {kerberos_realism.pick_kerberos_transport(random.Random(seed)) for seed in range(40)}

    assert picks == {"udp", "tcp"}


def test_kerberos_transport_profile_falls_back_to_tcp(monkeypatch):
    monkeypatch.setattr(kerberos_realism, "load_kerberos_realism", lambda: {})

    assert kerberos_realism.pick_kerberos_transport(random.Random(1)) == "tcp"


def test_kerberos_transport_profile_clamps_huge_weights(monkeypatch):
    def load_transport_config():
        return {
            "transport_profiles": {
                "default": {
                    "udp": 10**1000,
                    "tcp": 1,
                }
            }
        }

    monkeypatch.setattr(kerberos_realism, "load_kerberos_realism", load_transport_config)

    assert kerberos_realism.pick_kerberos_transport(random.Random(1)) in {"udp", "tcp"}


def test_kerberos_transport_profile_skips_non_finite_weights(monkeypatch):
    def load_transport_config():
        return {
            "transport_profiles": {
                "default": {
                    "udp": float("inf"),
                    "tcp": "bad",
                }
            }
        }

    monkeypatch.setattr(kerberos_realism, "load_kerberos_realism", load_transport_config)

    assert kerberos_realism.pick_kerberos_transport(random.Random(1)) == "tcp"


def test_kerberos_weighted_profile_skips_malformed_weights(monkeypatch):
    def load_config():
        return {
            "tgt_success": {
                "pre_auth_types": {
                    "bad": {"value": 15, "weight": float("inf")},
                    "good": {"value": 2, "weight": 1},
                },
                "ticket_options": {"default": {"value": "0x40810010", "weight": 1}},
                "encryption_types": {"aes256": {"value": "0x12", "weight": 10**500}},
            },
            "certificate_profiles": {},
        }

    monkeypatch.setattr(kerberos_realism, "load_kerberos_realism", load_config)

    fields = kerberos_realism.pick_tgt_success_fields(random.Random(1))

    assert fields["pre_auth_type"] == 2
    assert fields["encryption_type"] == "0x12"


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
