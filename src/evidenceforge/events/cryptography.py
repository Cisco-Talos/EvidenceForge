# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Immutable canonical cryptographic material and protocol payload types."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Literal

CertificateKeyType = Literal["rsa", "ecdsa"]
OcspCertificateStatus = Literal["good", "unknown", "revoked"]


@dataclass(frozen=True, slots=True)
class CertificateAuthorityMaterial:
    """Stable public material for one certificate authority identity."""

    subject_name: str
    issuer_name: str
    subject_name_der: bytes
    public_key_spki_der: bytes
    public_key_bitstring: bytes
    key_type: CertificateKeyType
    key_size: int

    def __post_init__(self) -> None:
        """Reject incomplete or internally inconsistent authority material."""

        if not self.subject_name or not self.issuer_name:
            raise ValueError("Certificate authorities require subject and issuer names")
        if not self.subject_name_der or not self.public_key_spki_der:
            raise ValueError("Certificate authorities require DER name and public-key material")
        if not self.public_key_bitstring:
            raise ValueError("Certificate authorities require a subject-public-key bit string")
        if self.key_type == "rsa" and self.key_size not in {2048, 3072, 4096}:
            raise ValueError("RSA certificate-authority keys must be 2048, 3072, or 4096 bits")
        if self.key_type == "ecdsa" and self.key_size not in {256, 384}:
            raise ValueError("ECDSA certificate-authority keys must be P-256 or P-384")

    @property
    def is_trust_anchor(self) -> bool:
        """Return whether this authority is self-issued."""

        return self.subject_name == self.issuer_name


@dataclass(frozen=True, slots=True)
class CertificateIdentityPlan:
    """Stable certificate identity independent of a particular sensor observation."""

    backend_identity: str
    subject_name: str
    issuer_name: str
    serial_number: str
    fingerprint: str
    not_valid_before: int
    not_valid_after: int
    public_key_spki_der: bytes
    key_type: CertificateKeyType
    key_size: int
    signature_algorithm: str
    san_dns: tuple[str, ...] = ()
    basic_constraints_ca: bool = False
    host_certificate: bool = True
    client_certificate: bool = False

    def __post_init__(self) -> None:
        """Validate immutable certificate identity semantics."""

        if not self.backend_identity or not self.subject_name or not self.issuer_name:
            raise ValueError("Certificate identities require backend, subject, and issuer")
        if not self.serial_number or int(self.serial_number, 16) <= 0:
            raise ValueError("Certificate serial numbers must be positive hexadecimal values")
        if len(self.fingerprint) != 40:
            raise ValueError("Certificate fingerprints must be SHA-1 hexadecimal values")
        if self.not_valid_after <= self.not_valid_before:
            raise ValueError("Certificate validity windows must be ordered")
        if not self.public_key_spki_der:
            raise ValueError("Certificate identities require SubjectPublicKeyInfo DER")

    @property
    def serial_number_int(self) -> int:
        """Return the positive integer serial represented by the source-native hex field."""

        return int(self.serial_number, 16)


@dataclass(frozen=True, slots=True)
class TlsCertificatePresentationPlan:
    """Final certificate-chain composition for one visible TLS handshake."""

    backend_identity: str
    certificates: tuple[CertificateIdentityPlan, ...]
    certificate_fuids: tuple[str, ...]
    transmit_trust_anchor: bool = False

    def __post_init__(self) -> None:
        """Validate presented-chain and observation identifier invariants."""

        if not self.backend_identity or not self.certificates:
            raise ValueError("TLS presentations require a backend and leaf certificate")
        if len(self.certificates) != len(self.certificate_fuids):
            raise ValueError("Every presented certificate requires one canonical file ID")
        if len(set(self.certificate_fuids)) != len(self.certificate_fuids):
            raise ValueError("TLS certificate file IDs must be unique within a presentation")
        if self.certificates[0].basic_constraints_ca:
            raise ValueError("The first TLS presentation certificate must be the leaf")
        if not self.transmit_trust_anchor and any(
            certificate.basic_constraints_ca and certificate.subject_name == certificate.issuer_name
            for certificate in self.certificates[1:]
        ):
            raise ValueError("TLS presentations cannot transmit a trust anchor by default")

    @property
    def leaf(self) -> CertificateIdentityPlan:
        """Return the presented leaf certificate identity."""

        return self.certificates[0]


@dataclass(frozen=True, slots=True)
class DkimKeyPlan:
    """Stable standards-valid DKIM public-key identity for one selector."""

    domain: str
    selector: str
    public_key_spki_der: bytes
    public_key_base64: str
    key_size: int
    exponent: int = 65537

    def __post_init__(self) -> None:
        """Validate selector scope and RSA metadata."""

        if not self.domain or not self.selector:
            raise ValueError("DKIM key plans require normalized domain and selector identities")
        if not self.public_key_spki_der or not self.public_key_base64:
            raise ValueError("DKIM key plans require DER and Base64 public-key material")
        if self.key_size not in {2048, 3072} or self.exponent != 65537:
            raise ValueError("DKIM keys must use 2048/3072-bit RSA with exponent 65537")


@dataclass(frozen=True, slots=True)
class OcspTransactionPlan:
    """Final request/response relationship for one OCSP-over-HTTP transaction."""

    stable_id: str
    certificate: CertificateIdentityPlan
    issuer: CertificateAuthorityMaterial
    responder: str
    request_der: bytes
    request_path: str
    hash_algorithm: Literal["sha1", "sha256"]
    issuer_name_hash: bytes
    issuer_key_hash: bytes
    certificate_status: OcspCertificateStatus
    this_update: int
    next_update: int
    file_id: str
    response_size: int
    requested_at: datetime
    responded_at: datetime
    revocation_time: int | None = None
    revocation_reason: str | None = None

    def __post_init__(self) -> None:
        """Validate request identity, timing, and status constraints."""

        if not self.stable_id or not self.responder or not self.request_der:
            raise ValueError("OCSP transactions require stable identity, responder, and DER")
        if not self.request_path.startswith("/") or not self.file_id:
            raise ValueError("OCSP transactions require a GET path and response file identity")
        expected_hash_length = 20 if self.hash_algorithm == "sha1" else 32
        if len(self.issuer_name_hash) != expected_hash_length:
            raise ValueError("OCSP issuer-name hash length does not match its algorithm")
        if len(self.issuer_key_hash) != expected_hash_length:
            raise ValueError("OCSP issuer-key hash length does not match its algorithm")
        if self.next_update <= self.this_update:
            raise ValueError("OCSP next_update must follow this_update")
        if self.response_size <= 0 or self.responded_at < self.requested_at:
            raise ValueError("OCSP response size and phase timing must be positive and ordered")
        if self.certificate_status == "revoked":
            if self.revocation_time is None or not self.revocation_reason:
                raise ValueError("Revoked OCSP status requires time and reason metadata")
        elif self.revocation_time is not None or self.revocation_reason is not None:
            raise ValueError("Only revoked OCSP status may carry revocation metadata")
