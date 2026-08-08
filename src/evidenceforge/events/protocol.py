# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Immutable application-protocol truth composed for one canonical occurrence."""

from __future__ import annotations

from dataclasses import dataclass

from evidenceforge.events.contexts import (
    FileTransferContext,
    HttpContext,
    OcspContext,
    PeContext,
    ProxyContext,
    SslContext,
    X509Context,
)
from evidenceforge.events.cryptography import (
    OcspTransactionPlan,
    TlsCertificatePresentationPlan,
)


@dataclass(frozen=True, slots=True)
class ProtocolTransactionPlan:
    """Final protocol, certificate, and transferred-object truth for one occurrence.

    The plan composes typed protocol subplans. It is intentionally neither one
    model per rendered row nor a universal bag of event fields: the occurrence
    owns one aggregate, while each domain retains its own strongly typed plan.
    """

    ssl: SslContext | None = None
    http: HttpContext | None = None
    file_transfers: tuple[FileTransferContext, ...] = ()
    x509_chain: tuple[X509Context, ...] = ()
    tls_presentation: TlsCertificatePresentationPlan | None = None
    ocsp: OcspContext | None = None
    ocsp_transaction: OcspTransactionPlan | None = None
    pe: PeContext | None = None
    proxy: ProxyContext | None = None

    def __post_init__(self) -> None:
        """Reject duplicate or contradictory protocol ownership."""

        transfer_ids = tuple(transfer.fuid for transfer in self.file_transfers)
        if any(not fuid for fuid in transfer_ids):
            raise ValueError("Protocol file transfers require canonical file IDs")
        if len(transfer_ids) != len(set(transfer_ids)):
            raise ValueError("Protocol file-transfer IDs must be unique")

        certificate_ids = tuple(certificate.fuid for certificate in self.x509_chain)
        if any(not fuid for fuid in certificate_ids):
            raise ValueError("Protocol certificate observations require canonical file IDs")
        if len(certificate_ids) != len(set(certificate_ids)):
            raise ValueError("Protocol certificate file IDs must be unique")

        if self.ssl is not None and self.ssl.cert_chain_fuids:
            if self.ssl.cert_chain_fuids != certificate_ids:
                raise ValueError("TLS certificate references must match the canonical X.509 chain")

        presentation = self.tls_presentation
        if presentation is not None:
            if presentation.certificate_fuids != certificate_ids:
                raise ValueError("TLS presentation file IDs must match the canonical X.509 chain")
            if len(presentation.certificates) != len(self.x509_chain):
                raise ValueError("TLS presentation and X.509 chain lengths must match")
            for identity, certificate in zip(
                presentation.certificates,
                self.x509_chain,
                strict=True,
            ):
                if (
                    identity.fingerprint != certificate.fingerprint
                    or identity.serial_number != certificate.certificate_serial
                ):
                    raise ValueError(
                        "TLS presentation identities must match their X.509 projections"
                    )

        if self.http is not None:
            unknown_response_ids = set(self.http.resp_fuids) - set(transfer_ids)
            if unknown_response_ids:
                raise ValueError("HTTP response file IDs must reference canonical transfers")

        if self.ocsp_transaction is not None:
            if self.ocsp is None:
                raise ValueError("OCSP transaction plans require an OCSP response projection")
            if self.ocsp_transaction.file_id != self.ocsp.id:
                raise ValueError("OCSP transaction and response file IDs must match")
            if self.ocsp_transaction.file_id not in transfer_ids:
                raise ValueError("OCSP response file ID must reference a canonical transfer")
            if self.ocsp_transaction.certificate.serial_number != self.ocsp.serial_number:
                raise ValueError("OCSP transaction and response certificate serials must match")
            if self.ocsp_transaction.certificate_status != self.ocsp.cert_status:
                raise ValueError("OCSP transaction and response status must match")

        if self.pe is not None and self.pe.id not in transfer_ids:
            raise ValueError("PE analysis must reference a canonical file transfer")

    @classmethod
    def compose(
        cls,
        *,
        ssl: SslContext | None = None,
        http: HttpContext | None = None,
        file_transfer: FileTransferContext | None = None,
        file_transfers: tuple[FileTransferContext, ...] | list[FileTransferContext] = (),
        x509: X509Context | None = None,
        x509_chain: tuple[X509Context, ...] | list[X509Context] = (),
        tls_presentation: TlsCertificatePresentationPlan | None = None,
        ocsp: OcspContext | None = None,
        ocsp_transaction: OcspTransactionPlan | None = None,
        pe: PeContext | None = None,
        proxy: ProxyContext | None = None,
    ) -> ProtocolTransactionPlan:
        """Collapse construction-only singular/list views into canonical tuples."""

        transfers = list(file_transfers)
        if file_transfer is not None:
            if not transfers or file_transfer not in transfers:
                transfers.insert(0, file_transfer)

        certificates = list(x509_chain)
        if x509 is not None:
            if certificates and x509 != certificates[0]:
                raise ValueError("The singular X.509 leaf must equal the first chain certificate")
            if not certificates:
                certificates.append(x509)

        return cls(
            ssl=ssl,
            http=http,
            file_transfers=tuple(transfers),
            x509_chain=tuple(certificates),
            tls_presentation=tls_presentation,
            ocsp=ocsp,
            ocsp_transaction=ocsp_transaction,
            pe=pe,
            proxy=proxy,
        )

    @property
    def primary_file_transfer(self) -> FileTransferContext | None:
        """Return the occurrence's primary transferred object, when one exists."""

        return self.file_transfers[0] if self.file_transfers else None

    @property
    def leaf_certificate(self) -> X509Context | None:
        """Return the presented leaf certificate, when one exists."""

        return self.x509_chain[0] if self.x509_chain else None
