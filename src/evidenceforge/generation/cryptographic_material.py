# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Deterministic standards-valid public cryptographic material registry."""

from __future__ import annotations

import base64
import fnmatch
import hashlib
import random
import re
from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa

from evidenceforge.events.cryptography import (
    CertificateAuthorityMaterial,
    CertificateIdentityPlan,
    CertificateKeyType,
    DkimKeyPlan,
    OcspCertificateStatus,
)
from evidenceforge.utils.rng import _stable_seed

_EC_ORDERS = {
    256: int("FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551", 16),
    384: int(
        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC7634D81F4372DDF"
        "581A0DB248B0A77AECEC196ACCC52973",
        16,
    ),
}


def _distinguished_name_der(name: str) -> bytes:
    """Return DER for the project's readable comma-and-space DN convention."""

    normalized = re.sub(r",\s+", ",", name.strip())
    return x509.Name.from_rfc4514_string(normalized).public_bytes()


def _read_der_length(data: bytes, offset: int) -> tuple[int, int]:
    """Return a DER length and the offset of its value."""

    if offset >= len(data):
        raise ValueError("Truncated DER length")
    first = data[offset]
    offset += 1
    if first < 0x80:
        return first, offset
    octets = first & 0x7F
    if octets == 0 or octets > 4 or offset + octets > len(data):
        raise ValueError("Invalid DER length encoding")
    return int.from_bytes(data[offset : offset + octets], "big"), offset + octets


def _read_der_tlv(data: bytes, offset: int) -> tuple[int, bytes, int]:
    """Return a DER tag, value, and next offset."""

    if offset >= len(data):
        raise ValueError("Truncated DER element")
    tag = data[offset]
    length, value_offset = _read_der_length(data, offset + 1)
    next_offset = value_offset + length
    if next_offset > len(data):
        raise ValueError("Truncated DER value")
    return tag, data[value_offset:next_offset], next_offset


def subject_public_key_bitstring(spki_der: bytes) -> bytes:
    """Extract the RFC 6960 subjectPublicKey bits from SubjectPublicKeyInfo DER."""

    outer_tag, outer_value, outer_end = _read_der_tlv(spki_der, 0)
    if outer_tag != 0x30 or outer_end != len(spki_der):
        raise ValueError("SubjectPublicKeyInfo must be one DER sequence")
    algorithm_tag, _algorithm_value, key_offset = _read_der_tlv(outer_value, 0)
    if algorithm_tag != 0x30:
        raise ValueError("SubjectPublicKeyInfo algorithm must be a DER sequence")
    key_tag, key_value, key_end = _read_der_tlv(outer_value, key_offset)
    if key_tag != 0x03 or key_end != len(outer_value) or not key_value:
        raise ValueError("SubjectPublicKeyInfo must end with one BIT STRING")
    if key_value[0] != 0:
        raise ValueError("Only octet-aligned subject public keys are supported")
    return key_value[1:]


def certificate_serial_number(seed: str) -> str:
    """Return a stable positive serial using the configured RFC 5280 length profile."""

    from evidenceforge.config.schemas import TLS_SERIAL_LENGTH_MAX_WEIGHT
    from evidenceforge.generation.activity.tls_realism import serial_number_config

    configured_lengths = serial_number_config().get("byte_lengths", [])
    weighted_lengths: dict[int, int] = {}
    for entry in configured_lengths:
        if not isinstance(entry, dict):
            continue
        try:
            byte_length = int(entry.get("bytes", 0))
            weight = int(entry.get("weight", 0))
        except (OverflowError, TypeError, ValueError):
            continue
        if 1 <= byte_length <= 20 and 0 < weight <= TLS_SERIAL_LENGTH_MAX_WEIGHT:
            weighted_lengths[byte_length] = min(
                weighted_lengths.get(byte_length, 0) + weight,
                TLS_SERIAL_LENGTH_MAX_WEIGHT,
            )
    if weighted_lengths:
        lengths = list(weighted_lengths)
        weights = list(weighted_lengths.values())
    else:
        lengths = [8, 9, 10, 12, 16, 18, 20]
        weights = [8, 6, 6, 14, 40, 12, 14]
    length_rng = random.Random(_stable_seed(f"crypto_serial_length:{seed}"))
    byte_length = length_rng.choices(lengths, weights=weights, k=1)[0]
    digest = hashlib.shake_256(f"crypto_serial_value:{seed}".encode()).digest(byte_length)
    serial = int.from_bytes(digest, "big") >> 1
    return f"{max(1, serial):0{byte_length * 2}X}"


class CryptographicMaterialRegistry:
    """Resolve deterministic public material once and reuse it across all consumers."""

    def __init__(self) -> None:
        self._public_keys: dict[tuple[str, CertificateKeyType, int], bytes] = {}
        self._authorities: dict[
            tuple[str, str, CertificateKeyType, int], CertificateAuthorityMaterial
        ] = {}
        self._certificates: dict[tuple[Any, ...], CertificateIdentityPlan] = {}
        self._dkim_keys: dict[tuple[str, str, int], DkimKeyPlan] = {}
        self._ocsp_statuses: dict[
            tuple[str, str, tuple[Any, ...]], tuple[OcspCertificateStatus, str | None]
        ] = {}

    @staticmethod
    def _normalize_key_profile(
        key_type: str,
        key_size: int,
    ) -> tuple[CertificateKeyType, int]:
        normalized_type: CertificateKeyType = "ecdsa" if key_type.lower() == "ecdsa" else "rsa"
        if normalized_type == "rsa":
            normalized_size = min(
                (2048, 3072, 4096), key=lambda candidate: abs(candidate - key_size)
            )
        else:
            normalized_size = 384 if key_size >= 384 else 256
        return normalized_type, normalized_size

    def public_key_spki(
        self,
        identity: str,
        *,
        key_type: str,
        key_size: int,
    ) -> bytes:
        """Return deterministic, parseable SubjectPublicKeyInfo DER."""

        normalized_type, normalized_size = self._normalize_key_profile(key_type, key_size)
        cache_key = (identity, normalized_type, normalized_size)
        cached = self._public_keys.get(cache_key)
        if cached is not None:
            return cached

        seed = f"cryptographic_public_key:{identity}:{normalized_type}:{normalized_size}"
        if normalized_type == "rsa":
            modulus = bytearray(hashlib.shake_256(seed.encode()).digest(normalized_size // 8))
            modulus[0] |= 0x80
            modulus[-1] |= 0x01
            public_key = rsa.RSAPublicNumbers(65537, int.from_bytes(modulus, "big")).public_key()
        else:
            order = _EC_ORDERS[normalized_size]
            scalar_bytes = hashlib.sha512(seed.encode()).digest()
            scalar = (int.from_bytes(scalar_bytes, "big") % (order - 1)) + 1
            curve = ec.SECP384R1() if normalized_size == 384 else ec.SECP256R1()
            public_key = ec.derive_private_key(scalar, curve).public_key()
        spki = public_key.public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        loaded = serialization.load_der_public_key(spki)
        if (
            loaded.public_bytes(
                serialization.Encoding.DER,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            )
            != spki
        ):
            raise ValueError("Cryptographic public-key DER failed round-trip validation")
        subject_public_key_bitstring(spki)
        self._public_keys[cache_key] = spki
        return spki

    def resolve_authority(
        self,
        *,
        subject_name: str,
        issuer_name: str,
        key_type: str,
        key_size: int,
    ) -> CertificateAuthorityMaterial:
        """Return stable public identity material for a certificate authority."""

        normalized_type, normalized_size = self._normalize_key_profile(key_type, key_size)
        cache_key = (subject_name, issuer_name, normalized_type, normalized_size)
        cached = self._authorities.get(cache_key)
        if cached is not None:
            return cached
        try:
            subject_name_der = _distinguished_name_der(subject_name)
        except ValueError as exc:
            raise ValueError(f"Invalid certificate-authority name {subject_name!r}: {exc}") from exc
        spki = self.public_key_spki(
            f"certificate_authority:{subject_name}",
            key_type=normalized_type,
            key_size=normalized_size,
        )
        authority = CertificateAuthorityMaterial(
            subject_name=subject_name,
            issuer_name=issuer_name,
            subject_name_der=subject_name_der,
            public_key_spki_der=spki,
            public_key_bitstring=subject_public_key_bitstring(spki),
            key_type=normalized_type,
            key_size=normalized_size,
        )
        self._authorities[cache_key] = authority
        return authority

    def resolve_certificate(
        self,
        *,
        backend_identity: str,
        subject_name: str,
        issuer_name: str,
        not_valid_before: int,
        not_valid_after: int,
        key_type: str,
        key_size: int,
        signature_algorithm: str,
        san_dns: tuple[str, ...] = (),
        basic_constraints_ca: bool = False,
        host_certificate: bool = True,
        client_certificate: bool = False,
    ) -> CertificateIdentityPlan:
        """Return one stable certificate identity with parseable public-key material."""

        normalized_type, normalized_size = self._normalize_key_profile(key_type, key_size)
        normalized_sans = tuple(dict.fromkeys(name.rstrip(".").lower() for name in san_dns if name))
        cache_key = (
            backend_identity,
            subject_name,
            issuer_name,
            not_valid_before,
            not_valid_after,
            normalized_type,
            normalized_size,
            signature_algorithm,
            normalized_sans,
            basic_constraints_ca,
            host_certificate,
            client_certificate,
        )
        cached = self._certificates.get(cache_key)
        if cached is not None:
            return cached
        identity_seed = "|".join(str(part) for part in cache_key)
        spki = self.public_key_spki(
            f"certificate:{backend_identity}:{subject_name}",
            key_type=normalized_type,
            key_size=normalized_size,
        )
        serial_number = certificate_serial_number(identity_seed)
        fingerprint = hashlib.sha1(
            b"certificate_identity\x00" + identity_seed.encode() + b"\x00" + spki,
            usedforsecurity=False,
        ).hexdigest()
        certificate = CertificateIdentityPlan(
            backend_identity=backend_identity,
            subject_name=subject_name,
            issuer_name=issuer_name,
            serial_number=serial_number,
            fingerprint=fingerprint,
            not_valid_before=not_valid_before,
            not_valid_after=not_valid_after,
            public_key_spki_der=spki,
            key_type=normalized_type,
            key_size=normalized_size,
            signature_algorithm=signature_algorithm,
            san_dns=normalized_sans,
            basic_constraints_ca=basic_constraints_ca,
            host_certificate=host_certificate,
            client_certificate=client_certificate,
        )
        self._certificates[cache_key] = certificate
        return certificate

    def resolve_dkim_key(
        self,
        domain: str,
        selector: str,
        *,
        key_size: int = 2048,
    ) -> DkimKeyPlan:
        """Return one selector-stable RSA SubjectPublicKeyInfo identity."""

        normalized_domain = domain.rstrip(".").lower()
        normalized_selector = selector.rstrip(".").lower()
        normalized_size = 3072 if key_size >= 3072 else 2048
        cache_key = (normalized_domain, normalized_selector, normalized_size)
        cached = self._dkim_keys.get(cache_key)
        if cached is not None:
            return cached
        spki = self.public_key_spki(
            f"dkim:{normalized_domain}:{normalized_selector}",
            key_type="rsa",
            key_size=normalized_size,
        )
        loaded = serialization.load_der_public_key(spki)
        if not isinstance(loaded, rsa.RSAPublicKey):
            raise ValueError("DKIM registry produced a non-RSA public key")
        numbers = loaded.public_numbers()
        if loaded.key_size != normalized_size or numbers.e != 65537:
            raise ValueError("DKIM registry produced an invalid RSA size or exponent")
        plan = DkimKeyPlan(
            domain=normalized_domain,
            selector=normalized_selector,
            public_key_spki_der=spki,
            public_key_base64=base64.b64encode(spki).decode("ascii"),
            key_size=normalized_size,
            exponent=numbers.e,
        )
        self._dkim_keys[cache_key] = plan
        return plan

    def resolve_ocsp_status(
        self,
        certificate: CertificateIdentityPlan,
        profiles: list[dict[str, Any]],
    ) -> tuple[OcspCertificateStatus, str | None]:
        """Return the durable status identity assigned to one certificate."""

        matching = [
            profile
            for profile in profiles
            if any(
                fnmatch.fnmatch(certificate.subject_name.removeprefix("CN="), str(pattern))
                or fnmatch.fnmatch(certificate.subject_name, str(pattern))
                for pattern in profile.get("certificate_patterns", [])
            )
        ]
        matching.sort(
            key=lambda profile: all(
                str(pattern) == "*" for pattern in profile.get("certificate_patterns", [])
            )
        )
        profile = matching[0] if matching else None
        if profile is None:
            return "good", None
        weights = profile.get("status_weights", {})
        ordered: tuple[OcspCertificateStatus, ...] = ("good", "unknown", "revoked")
        numeric_weights = tuple(max(0, int(weights.get(status, 0))) for status in ordered)
        if sum(numeric_weights) <= 0:
            return "good", None
        reasons = tuple(str(reason) for reason in profile.get("revocation_reasons", []) if reason)
        profile_identity = (
            str(profile.get("name", "")),
            tuple(str(pattern) for pattern in profile.get("certificate_patterns", [])),
            numeric_weights,
            reasons,
        )
        cache_key = (certificate.fingerprint, certificate.serial_number, profile_identity)
        cached = self._ocsp_statuses.get(cache_key)
        if cached is not None:
            return cached
        rng = random.Random(
            _stable_seed(
                "ocsp_certificate_status:"
                f"{profile_identity}:{certificate.fingerprint}:{certificate.serial_number}"
            )
        )
        status = rng.choices(ordered, weights=numeric_weights, k=1)[0]
        if status == "revoked":
            if not reasons:
                raise ValueError("Revoked OCSP profiles require at least one revocation reason")
            result = (status, rng.choice(reasons))
        else:
            result = (status, None)
        self._ocsp_statuses[cache_key] = result
        return result


_SHARED_REGISTRY = CryptographicMaterialRegistry()


def shared_cryptographic_material_registry() -> CryptographicMaterialRegistry:
    """Return the process-wide registry used by source-independent DNS helpers."""

    return _SHARED_REGISTRY
