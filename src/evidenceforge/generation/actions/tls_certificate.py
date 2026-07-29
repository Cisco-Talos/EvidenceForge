# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Canonical TLS certificate identity and presentation planning."""

from __future__ import annotations

import fnmatch
import random
from datetime import datetime
from typing import Any

from evidenceforge.events.contexts import X509Context
from evidenceforge.events.cryptography import (
    CertificateAuthorityMaterial,
    CertificateIdentityPlan,
    TlsCertificatePresentationPlan,
)
from evidenceforge.generation.activity.tls_realism import (
    certificate_authority_profile,
    certificate_chain_config,
    certificate_subject_key_profile,
    chain_template_for_issuer,
    signature_algorithm_for_issuer,
)
from evidenceforge.generation.cryptographic_material import CryptographicMaterialRegistry
from evidenceforge.utils.ids import generate_stable_zeek_uid
from evidenceforge.utils.rng import _stable_seed


class TlsCertificatePlanner:
    """Plan stable certificate identities and per-handshake chain presentation."""

    def __init__(self, registry: CryptographicMaterialRegistry) -> None:
        self._registry = registry

    @staticmethod
    def _validity_window(
        *,
        identity: str,
        event_time: datetime,
        validity_days_min: int,
        validity_days_max: int,
        not_before_max_days: int,
    ) -> tuple[int, int]:
        """Return an order-independent certificate-rotation window containing the event."""

        rng = random.Random(_stable_seed(f"tls_certificate_validity:{identity}"))
        validity_days = rng.randint(validity_days_min, max(validity_days_min, validity_days_max))
        rotation_days = max(1, int(validity_days * 0.72))
        event_day = int(event_time.timestamp()) // 86400
        bucket_start_day = (event_day // rotation_days) * rotation_days
        available_overlap = max(1, validity_days - rotation_days)
        max_back_days = max(1, min(not_before_max_days, available_overlap))
        not_before_days = rng.randint(1, max_back_days)
        not_valid_before = (bucket_start_day - not_before_days) * 86400 + rng.randint(0, 86399)
        not_valid_after = not_valid_before + validity_days * 86400
        if not_valid_before >= int(event_time.timestamp()):
            not_valid_before = (bucket_start_day - 1) * 86400
            not_valid_after = not_valid_before + validity_days * 86400
        return not_valid_before, not_valid_after

    @staticmethod
    def _bound_to_issuer(
        validity: tuple[int, int],
        issuer_name: str,
        event_time: datetime,
    ) -> tuple[int, int]:
        """Keep a child validity interval within a configured active issuer interval."""

        profile = certificate_authority_profile(issuer_name)
        if profile is None:
            return validity
        issuer_start = int(profile["not_valid_before"])
        issuer_end = int(profile["not_valid_after"])
        event_epoch = int(event_time.timestamp())
        if not (issuer_start < event_epoch < issuer_end):
            return validity
        start = max(validity[0], issuer_start)
        end = min(validity[1], issuer_end)
        start = min(start, event_epoch - 1)
        end = max(end, event_epoch + 1)
        return (start, end) if end > start else validity

    def plan(
        self,
        *,
        backend_identity: str,
        cert_name: str,
        issuer_config: dict[str, Any],
        event_time: datetime,
        connection_identity: str,
        key_type: str,
        key_size: int,
        san_dns: tuple[str, ...],
    ) -> TlsCertificatePresentationPlan:
        """Return final stable chain composition and per-handshake file identities."""

        issuer_name = str(issuer_config["name"])
        validity_fallback = int(issuer_config.get("validity_days", 397))
        validity = self._validity_window(
            identity=f"leaf:{backend_identity}:{cert_name}:{issuer_name}:{key_type}:{key_size}",
            event_time=event_time,
            validity_days_min=int(issuer_config.get("validity_days_min", validity_fallback)),
            validity_days_max=int(issuer_config.get("validity_days_max", validity_fallback)),
            not_before_max_days=int(issuer_config.get("not_before_max_days", 300)),
        )
        validity = self._bound_to_issuer(validity, issuer_name, event_time)
        leaf = self._registry.resolve_certificate(
            backend_identity=backend_identity,
            subject_name=f"CN={cert_name}",
            issuer_name=issuer_name,
            not_valid_before=validity[0],
            not_valid_after=validity[1],
            key_type=key_type,
            key_size=key_size,
            signature_algorithm=signature_algorithm_for_issuer(
                issuer_name,
                fallback_type=key_type,
                fallback_length=key_size,
            ),
            san_dns=san_dns,
        )
        certificates = [leaf]
        config = certificate_chain_config()
        if not self._is_ip_literal(cert_name) and self._include_intermediate(
            backend_identity=backend_identity,
            leaf=leaf,
            issuer_name=issuer_name,
            probability=float(config.get("include_intermediate_probability", 0.86)),
        ):
            issuer_certificate = self._authority_certificate(issuer_name, event_time)
            if issuer_certificate.subject_name != issuer_certificate.issuer_name or bool(
                config.get("present_trust_anchor", False)
            ):
                certificates.append(issuer_certificate)
            if (
                bool(config.get("present_trust_anchor", False))
                and issuer_certificate.subject_name != issuer_certificate.issuer_name
                and self._include_second_authority(
                    backend_identity=backend_identity,
                    leaf=leaf,
                    probability=float(config.get("include_second_intermediate_probability", 0.08)),
                )
            ):
                parent = self._authority_certificate(issuer_certificate.issuer_name, event_time)
                if parent.subject_name != issuer_certificate.subject_name:
                    certificates.append(parent)

        transmit_trust_anchor = bool(config.get("present_trust_anchor", False))
        fuids = tuple(
            generate_stable_zeek_uid(
                "F",
                f"tls_certificate_fuid:{connection_identity}:{index}:{certificate.fingerprint}",
            )
            for index, certificate in enumerate(certificates)
        )
        return TlsCertificatePresentationPlan(
            backend_identity=backend_identity,
            certificates=tuple(certificates),
            certificate_fuids=fuids,
            transmit_trust_anchor=transmit_trust_anchor,
        )

    @staticmethod
    def _is_ip_literal(value: str) -> bool:
        from ipaddress import ip_address

        try:
            ip_address(value)
            return True
        except ValueError:
            return False

    @staticmethod
    def _include_intermediate(
        *,
        backend_identity: str,
        leaf: CertificateIdentityPlan,
        issuer_name: str,
        probability: float,
    ) -> bool:
        rng = random.Random(
            _stable_seed(
                f"tls_presentation_intermediate:{backend_identity}:{leaf.fingerprint}:{issuer_name}"
            )
        )
        return rng.random() < max(0.0, min(probability, 1.0))

    @staticmethod
    def _include_second_authority(
        *,
        backend_identity: str,
        leaf: CertificateIdentityPlan,
        probability: float,
    ) -> bool:
        rng = random.Random(
            _stable_seed(f"tls_presentation_second:{backend_identity}:{leaf.fingerprint}")
        )
        return rng.random() < max(0.0, min(probability, 1.0))

    def authority_material(self, issuer_name: str) -> CertificateAuthorityMaterial:
        """Return the exact issuer-name and public-key material used by OCSP planning."""

        profile = certificate_authority_profile(issuer_name)
        if profile is not None:
            authority_issuer = str(profile["issuer"])
            key_type = str(profile["key_type"])
            key_size = int(profile["key_length"])
        else:
            authority_issuer = issuer_name
            key_type, key_size = certificate_subject_key_profile(issuer_name)
        return self._registry.resolve_authority(
            subject_name=issuer_name,
            issuer_name=authority_issuer,
            key_type=key_type,
            key_size=key_size,
        )

    def _authority_certificate(
        self,
        subject_name: str,
        event_time: datetime,
    ) -> CertificateIdentityPlan:
        profile = certificate_authority_profile(subject_name)
        if profile is not None:
            issuer_name = str(profile["issuer"])
            key_type = str(profile["key_type"])
            key_size = int(profile["key_length"])
            validity = (int(profile["not_valid_before"]), int(profile["not_valid_after"]))
        else:
            template = chain_template_for_issuer(subject_name)
            parents = [str(value) for value in template.get("intermediates", []) if value]
            issuer_name = next(
                (parent for parent in parents if not fnmatch.fnmatch(subject_name, parent)),
                subject_name,
            )
            key_type, key_size = certificate_subject_key_profile(subject_name)
            config = certificate_chain_config()
            validity = self._validity_window(
                identity=f"authority:{subject_name}:{issuer_name}:{key_type}:{key_size}",
                event_time=event_time,
                validity_days_min=int(config.get("intermediate_validity_days_min", 1825)),
                validity_days_max=int(config.get("intermediate_validity_days_max", 3650)),
                not_before_max_days=int(config.get("intermediate_not_before_max_days", 1460)),
            )
        return self._registry.resolve_certificate(
            backend_identity=f"certificate-authority:{subject_name}",
            subject_name=subject_name,
            issuer_name=issuer_name,
            not_valid_before=validity[0],
            not_valid_after=validity[1],
            key_type=key_type,
            key_size=key_size,
            signature_algorithm=signature_algorithm_for_issuer(
                issuer_name,
                fallback_type=key_type,
                fallback_length=key_size,
            ),
            basic_constraints_ca=True,
            host_certificate=False,
        )

    @staticmethod
    def x509_contexts(plan: TlsCertificatePresentationPlan) -> list[X509Context]:
        """Project finalized certificate truth into compatibility X.509 contexts."""

        contexts: list[X509Context] = []
        for certificate, fuid in zip(plan.certificates, plan.certificate_fuids, strict=True):
            is_ecdsa = certificate.key_type == "ecdsa"
            contexts.append(
                X509Context(
                    fuid=fuid,
                    fingerprint=certificate.fingerprint,
                    certificate_version=3,
                    certificate_serial=certificate.serial_number,
                    certificate_subject=certificate.subject_name,
                    certificate_issuer=certificate.issuer_name,
                    certificate_not_valid_before=certificate.not_valid_before,
                    certificate_not_valid_after=certificate.not_valid_after,
                    certificate_key_alg="id-ecPublicKey" if is_ecdsa else "rsaEncryption",
                    certificate_sig_alg=certificate.signature_algorithm,
                    certificate_key_type=certificate.key_type,
                    certificate_key_length=certificate.key_size,
                    certificate_exponent="" if is_ecdsa else "65537",
                    san_dns=list(certificate.san_dns),
                    basic_constraints_ca=certificate.basic_constraints_ca,
                    host_cert=certificate.host_certificate,
                    client_cert=certificate.client_certificate,
                )
            )
        return contexts

    @staticmethod
    def validate_projection(
        plan: TlsCertificatePresentationPlan,
        contexts: list[X509Context],
    ) -> None:
        """Reject mutations that make compatibility X.509 fields diverge from the plan."""

        if len(contexts) != len(plan.certificates):
            raise ValueError("X.509 compatibility chain length diverged from TLS presentation")
        for certificate, fuid, context in zip(
            plan.certificates,
            plan.certificate_fuids,
            contexts,
            strict=True,
        ):
            if (
                context.fuid != fuid
                or context.fingerprint != certificate.fingerprint
                or context.certificate_serial != certificate.serial_number
                or context.certificate_subject != certificate.subject_name
                or context.certificate_issuer != certificate.issuer_name
                or tuple(context.san_dns) != certificate.san_dns
            ):
                raise ValueError("X.509 compatibility fields diverged from canonical TLS truth")
