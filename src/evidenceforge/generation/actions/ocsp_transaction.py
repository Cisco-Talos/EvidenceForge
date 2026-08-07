# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Standards-valid OCSP request planning and correlated HTTP action bundle."""

from __future__ import annotations

import base64
import hashlib
import math
import random
from dataclasses import dataclass
from datetime import timedelta
from typing import Any, Protocol
from urllib.parse import quote

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509.ocsp import OCSPRequestBuilder, load_der_ocsp_request

from evidenceforge.events.base import SecurityEvent
from evidenceforge.events.contexts import FileTransferContext, HttpContext, OcspContext
from evidenceforge.events.cryptography import (
    CertificateAuthorityMaterial,
    CertificateIdentityPlan,
    OcspTransactionPlan,
)
from evidenceforge.generation.actions.tls_certificate import TlsCertificatePlanner
from evidenceforge.generation.activity.dns_registry import resolve_domain_ip
from evidenceforge.generation.activity.proxy_user_agents import pick_proxy_user_agent
from evidenceforge.generation.activity.tls_realism import ocsp_config, pick_ocsp_responder
from evidenceforge.generation.cryptographic_material import CryptographicMaterialRegistry
from evidenceforge.utils.ids import generate_stable_zeek_uid
from evidenceforge.utils.rng import _stable_seed


@dataclass(frozen=True, slots=True)
class OcspTransactionRequest:
    """Intent to query the status of one presented certificate."""

    tls_event: SecurityEvent
    certificate: CertificateIdentityPlan
    issuer: CertificateAuthorityMaterial
    cert_name: str

    @property
    def stable_id(self) -> str:
        """Return the durable OCSP action-group identity."""

        net = self.tls_event.network
        transaction_id = net.transaction.stable_id if net and net.transaction else ""
        seed = _stable_seed(
            "action_bundle:ocsp_transaction:"
            f"{transaction_id}:{self.certificate.fingerprint}:{self.certificate.serial_number}"
        )
        return f"ocsp-{seed:016x}"


class OcspTransactionExecutor(Protocol):
    """Activity services required by the OCSP action bundle."""

    _ip_to_system: dict[str, Any]

    def generate_connection(self, **kwargs: Any) -> str:
        """Emit the canonical OCSP HTTP transaction."""


class OcspTransactionPlanner:
    """Build parseable OCSP request bytes and their response relationship."""

    def __init__(
        self,
        registry: CryptographicMaterialRegistry,
        tls_certificate_planner: TlsCertificatePlanner,
    ) -> None:
        self._registry = registry
        self._tls_certificate_planner = tls_certificate_planner

    def plan(self, request: OcspTransactionRequest) -> OcspTransactionPlan:
        """Return a frozen request/response plan whose identifiers round-trip."""

        config = ocsp_config()
        algorithm_name = str(config.get("request_hash_algorithm", "sha1")).lower()
        if algorithm_name not in {"sha1", "sha256"}:
            raise ValueError("OCSP request_hash_algorithm must be sha1 or sha256")
        algorithm = hashes.SHA256() if algorithm_name == "sha256" else hashes.SHA1()
        issuer_name_hash = self._digest(request.issuer.subject_name_der, algorithm_name)
        issuer_key_hash = self._digest(request.issuer.public_key_bitstring, algorithm_name)
        builder = OCSPRequestBuilder().add_certificate_by_hash(
            issuer_name_hash,
            issuer_key_hash,
            request.certificate.serial_number_int,
            algorithm,
        )
        request_der = builder.build().public_bytes(serialization.Encoding.DER)
        parsed = load_der_ocsp_request(request_der)
        if (
            parsed.serial_number != request.certificate.serial_number_int
            or parsed.issuer_name_hash != issuer_name_hash
            or parsed.issuer_key_hash != issuer_key_hash
            or parsed.hash_algorithm.name != algorithm_name
        ):
            raise ValueError("Generated OCSP request failed identity round-trip validation")

        request_path = "/" + quote(base64.b64encode(request_der).decode("ascii"), safe="")
        responder = pick_ocsp_responder(
            request.certificate.issuer_name,
            random.Random(
                _stable_seed(
                    "ocsp_responder:"
                    f"{request.certificate.issuer_name}:{request.certificate.serial_number}"
                )
            ),
        )
        bucket_seconds = max(60, int(config.get("cache_bucket_seconds", 4 * 60 * 60)))
        event_epoch = int(request.tls_event.timestamp.timestamp())
        bucket_start = event_epoch - (event_epoch % bucket_seconds)
        window_rng = random.Random(
            _stable_seed(
                "ocsp_window:"
                f"{request.certificate.fingerprint}:{request.certificate.serial_number}:"
                f"{bucket_start}"
            )
        )
        max_skew = max(0, int(config.get("this_update_max_skew_seconds", 3600)))
        next_min = max(1, int(config.get("next_update_min_seconds", 8 * 3600)))
        next_max = max(next_min, int(config.get("next_update_max_seconds", 7 * 86400)))
        this_update = bucket_start - window_rng.randint(0, max_skew)
        next_update = bucket_start + bucket_seconds + window_rng.randint(next_min, next_max)
        profiles = [
            profile
            for profile in config.get("certificate_status_profiles", [])
            if isinstance(profile, dict)
        ]
        status, revocation_reason = self._registry.resolve_ocsp_status(
            request.certificate,
            profiles,
        )
        revocation_time = None
        if status == "revoked":
            revocation_time = this_update - window_rng.randint(86400, 90 * 86400)

        phase_rng = random.Random(_stable_seed(f"ocsp_phase:{request.stable_id}:{bucket_start}"))
        requested_at = request.tls_event.timestamp + timedelta(
            milliseconds=phase_rng.randint(900, 4500)
        )
        response_config = config.get("response", {})
        size_min = max(1, int(response_config.get("size_bytes_min", 900)))
        size_max = max(size_min, int(response_config.get("size_bytes_max", 2500)))
        response_size = phase_rng.randint(size_min, size_max)
        throughput_min = max(
            1.0,
            float(response_config.get("throughput_bytes_per_second_min", 40_000)),
        )
        throughput_max = max(
            throughput_min,
            float(response_config.get("throughput_bytes_per_second_max", 400_000)),
        )
        source_ip = request.tls_event.network.src_ip if request.tls_event.network else ""
        responder_rng = random.Random(
            _stable_seed(f"ocsp_responder_transport:{responder}:{source_ip}")
        )
        scoped_throughput = math.exp(
            responder_rng.uniform(math.log(throughput_min), math.log(throughput_max))
        )
        effective_throughput = scoped_throughput * phase_rng.uniform(0.78, 1.22)
        duration_floor = max(
            0.0001,
            float(response_config.get("file_duration_floor_ms", 3.0)) / 1000.0,
        )
        response_file_duration = max(
            duration_floor * phase_rng.uniform(0.85, 1.35),
            response_size / effective_throughput,
        )
        latency_min = max(0.001, float(response_config.get("latency_ms_min", 18.0)) / 1000.0)
        latency_max = max(
            latency_min,
            float(response_config.get("latency_ms_max", 240.0)) / 1000.0,
        )
        response_latency = phase_rng.uniform(latency_min, latency_max)
        responded_at = requested_at + timedelta(seconds=response_latency + response_file_duration)
        file_id = generate_stable_zeek_uid(
            "F",
            f"ocsp_response:{request.stable_id}:{bucket_start}:{request_der.hex()}",
        )
        return OcspTransactionPlan(
            stable_id=request.stable_id,
            certificate=request.certificate,
            issuer=request.issuer,
            responder=responder,
            request_der=request_der,
            request_path=request_path,
            hash_algorithm=algorithm_name,
            issuer_name_hash=issuer_name_hash,
            issuer_key_hash=issuer_key_hash,
            certificate_status=status,
            this_update=this_update,
            next_update=next_update,
            file_id=file_id,
            response_size=response_size,
            response_file_duration=response_file_duration,
            requested_at=requested_at,
            responded_at=responded_at,
            revocation_time=revocation_time,
            revocation_reason=revocation_reason,
        )

    @staticmethod
    def _digest(value: bytes, algorithm_name: str) -> bytes:
        algorithm = hashlib.sha256 if algorithm_name == "sha256" else hashlib.sha1
        return algorithm(value, usedforsecurity=False).digest()


class OcspTransactionActionBundle:
    """Render finalized OCSP truth through canonical DNS/network/proxy contracts."""

    def __init__(
        self,
        executor: OcspTransactionExecutor,
        planner: OcspTransactionPlanner,
        request: OcspTransactionRequest,
    ) -> None:
        self._executor = executor
        self._planner = planner
        self._request = request

    def execute(self) -> OcspTransactionPlan:
        """Plan and emit one correlated OCSP HTTP response transaction."""

        plan = self._planner.plan(self._request)
        tls_network = self._request.tls_event.network
        if tls_network is None:
            raise ValueError("OCSP action bundles require an owning TLS network transaction")
        responder_ip = resolve_domain_ip(plan.responder, src_host=tls_network.src_ip)
        source_system = self._executor._ip_to_system.get(tls_network.src_ip)
        source_os = str(getattr(source_system, "os", "") or "")
        user_agent = pick_proxy_user_agent(
            random.Random(
                _stable_seed(f"ocsp_user_agent:{plan.responder}:{tls_network.src_ip}:{source_os}")
            ),
            source_system,
            hostname=plan.responder,
        )
        duration = max(0.001, (plan.responded_at - plan.requested_at).total_seconds())
        http = HttpContext(
            method="GET",
            host=plan.responder,
            uri=plan.request_path,
            version="1.1",
            user_agent=user_agent,
            request_body_len=0,
            response_body_len=plan.response_size,
            status_code=200,
            status_msg="OK",
            resp_mime_types=["application/ocsp-response"],
            resp_fuids=[plan.file_id],
            tags=["ocsp"],
        )
        file_transfer = FileTransferContext(
            fuid=plan.file_id,
            source="HTTP",
            depth=0,
            analyzers=[],
            mime_type="application/ocsp-response",
            duration=plan.response_file_duration,
            local_orig=responder_ip.startswith(("10.", "172.", "192.168.")),
            is_orig=False,
            seen_bytes=plan.response_size,
            total_bytes=plan.response_size,
        )
        ocsp = OcspContext(
            id=plan.file_id,
            hash_algorithm=plan.hash_algorithm,
            issuer_name_hash=plan.issuer_name_hash.hex(),
            issuer_key_hash=plan.issuer_key_hash.hex(),
            serial_number=plan.certificate.serial_number,
            cert_status=plan.certificate_status,
            this_update=float(plan.this_update),
            next_update=float(plan.next_update),
            revoketime=(float(plan.revocation_time) if plan.revocation_time is not None else None),
            revokereason=plan.revocation_reason,
        )
        parent_group_id = (
            self._request.tls_event.lifecycle.group_id
            if self._request.tls_event.lifecycle is not None
            else None
        )
        self._executor.generate_connection(
            src_ip=tls_network.src_ip,
            dst_ip=responder_ip,
            time=plan.requested_at,
            dst_port=80,
            proto="tcp",
            service="http",
            duration=duration,
            orig_bytes=max(320, len(plan.request_der) + 220),
            resp_bytes=plan.response_size,
            emit_dns=True,
            pid=tls_network.initiating_pid,
            source_system=source_system,
            conn_state="SF",
            http=http,
            file_transfer=file_transfer,
            ocsp=ocsp,
            ocsp_transaction=plan,
            hostname=plan.responder,
            parent_action_group_id=parent_group_id,
        )
        return plan
