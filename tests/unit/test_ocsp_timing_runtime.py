# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Focused contracts for runtime-owned OCSP response timing."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import textwrap
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime
from pathlib import Path

import pytest

from evidenceforge.events.base import OccurrenceBuilder
from evidenceforge.events.cryptography import OcspTransactionPlan
from evidenceforge.generation.actions.ocsp_transaction import (
    OcspTransactionPlanner,
    OcspTransactionRequest,
)
from evidenceforge.generation.actions.tls_certificate import TlsCertificatePlanner
from evidenceforge.generation.cryptographic_material import CryptographicMaterialRegistry
from evidenceforge.generation.source_timing import SourceTimingPlanner
from evidenceforge.generation.timing import TimingRuntime
from tests.network_factories import network_plan

_EVENT_TIME = datetime(2024, 10, 14, 12, tzinfo=UTC)
_ISSUER_CONFIG = {
    "name": "CN=R3, O=Let's Encrypt, C=US",
    "validity_days_min": 90,
    "validity_days_max": 90,
    "not_before_max_days": 30,
}
_RELATIONSHIPS = {
    "ocsp.response.responder_throughput_log",
    "ocsp.response.transaction_throughput_multiplier",
    "ocsp.response.file_duration_floor_multiplier",
    "ocsp.response.latency_seconds",
}
_PROJECT_ROOT = Path(__file__).parents[2]


def _requests(
    registry: CryptographicMaterialRegistry,
    count: int,
) -> tuple[OcspTransactionRequest, ...]:
    """Return distinct transaction identities sharing one certificate and responder."""

    certificate_planner = TlsCertificatePlanner(registry)
    presentation = certificate_planner.plan(
        backend_identity="www.example.com",
        cert_name="www.example.com",
        issuer_config=_ISSUER_CONFIG,
        event_time=_EVENT_TIME,
        connection_identity="CTestOcspCertificate",
        key_type="rsa",
        key_size=2048,
        san_dns=("www.example.com",),
    )
    issuer = certificate_planner.authority_material(presentation.leaf.issuer_name)
    return tuple(
        OcspTransactionRequest(
            tls_event=OccurrenceBuilder(
                timestamp=_EVENT_TIME,
                event_type="connection",
                network=network_plan(
                    src_ip="10.0.10.25",
                    src_port=51000 + ordinal,
                    dst_ip="93.184.216.34",
                    dst_port=443,
                    protocol="tcp",
                    service="ssl",
                    zeek_uid=f"CTestOcsp{ordinal:03d}",
                ),
                tls_presentation=presentation,
            ),
            certificate=presentation.leaf,
            issuer=issuer,
            cert_name="www.example.com",
        )
        for ordinal in range(count)
    )


def _planner(
    registry: CryptographicMaterialRegistry,
    runtime: TimingRuntime,
) -> OcspTransactionPlanner:
    """Return an OCSP planner whose TLS owner carries the exact runtime."""

    return OcspTransactionPlanner(
        registry,
        TlsCertificatePlanner(registry, timing_runtime=runtime),
    )


def _signature(plan: OcspTransactionPlan) -> tuple[str, str, float, int]:
    """Return only response timing and its deterministic transaction texture."""

    return (
        plan.requested_at.isoformat(),
        plan.responded_at.isoformat(),
        plan.response_file_duration,
        plan.response_size,
    )


def test_ocsp_direct_and_prepared_timing_commit_are_identical() -> None:
    """The active SourceTiming overlay stages four samples and commits direct parity."""

    registry = CryptographicMaterialRegistry()
    request = _requests(registry, 1)[0]
    direct_runtime = TimingRuntime(reference_time=_EVENT_TIME, namespace="ocsp-prepared-parity")
    direct = _planner(registry, direct_runtime).plan(request)

    staged_runtime = TimingRuntime(reference_time=_EVENT_TIME, namespace="ocsp-prepared-parity")
    staged_planner = _planner(registry, staged_runtime)
    timing_owner = SourceTimingPlanner(timing_runtime=staged_runtime)
    before_digest = staged_runtime.state_digest()
    with timing_owner.prepared_planning() as preparation:
        staged = staged_planner.plan(request)
        assert preparation.staged_audit_operations == 4
        assert staged_runtime.state_digest() == before_digest

    with preparation.claimed_commit():
        preparation.commit_no_fail()

    assert staged == direct
    assert staged_runtime.audit.snapshot() == direct_runtime.audit.snapshot()
    audit = staged_runtime.audit.snapshot()
    assert audit.sample_counts == {relationship: 1 for relationship in _RELATIONSHIPS}
    assert audit.distribution_counts == {"mixture": 4}


def test_ocsp_rejected_preparation_leaves_zero_audit_residue() -> None:
    """A rejected OCSP plan discards all four staged timing observations."""

    registry = CryptographicMaterialRegistry()
    request = _requests(registry, 1)[0]
    runtime = TimingRuntime(reference_time=_EVENT_TIME, namespace="ocsp-prepared-cancel")
    planner = _planner(registry, runtime)
    timing_owner = SourceTimingPlanner(timing_runtime=runtime)
    before_digest = runtime.state_digest()

    with pytest.raises(RuntimeError, match="reject OCSP plan"):
        with timing_owner.prepared_planning() as preparation:
            planner.plan(request)
            assert preparation.staged_audit_operations == 4
            raise RuntimeError("reject OCSP plan")

    assert runtime.state_digest() == before_digest
    assert runtime.audit.snapshot().sample_counts == {}


def test_ocsp_lost_return_retry_replays_identical_frozen_relationships() -> None:
    """Retrying the same semantic request cannot advance a private RNG cursor."""

    registry = CryptographicMaterialRegistry()
    request = _requests(registry, 1)[0]
    runtime = TimingRuntime(reference_time=_EVENT_TIME, namespace="ocsp-lost-return")
    planner = _planner(registry, runtime)

    lost_return = planner.plan(request)
    retry = planner.plan(request)

    assert retry == lost_return
    assert runtime.audit.snapshot().sample_counts == {
        relationship: 2 for relationship in _RELATIONSHIPS
    }


def _worker_population(
    workers: int,
    *,
    reverse: bool,
) -> tuple[dict[str, tuple[str, str, float, int]], dict[str, int]]:
    """Return response relationships under one worker topology."""

    registry = CryptographicMaterialRegistry()
    requests = _requests(registry, 32)
    submitted = tuple(reversed(requests)) if reverse else requests
    runtime = TimingRuntime(reference_time=_EVENT_TIME, namespace="ocsp-worker-parity")
    planner = _planner(registry, runtime)

    def plan(request: OcspTransactionRequest) -> tuple[str, tuple[str, str, float, int]]:
        result = planner.plan(request)
        return request.stable_id, _signature(result)

    if workers == 1:
        values = map(plan, submitted)
    else:
        with ThreadPoolExecutor(max_workers=workers) as executor:
            values = executor.map(plan, submitted)
    return dict(values), dict(runtime.audit.snapshot().sample_counts)


def test_ocsp_timing_is_order_and_worker_deterministic() -> None:
    """Stable scopes make all response timing independent of worker arrival order."""

    single = _worker_population(1, reverse=False)
    parallel = _worker_population(8, reverse=True)
    assert single == parallel
    assert single[1] == {relationship: 32 for relationship in _RELATIONSHIPS}


def test_ocsp_timing_is_pythonhashseed_deterministic() -> None:
    """OCSP response timing cannot inherit interpreter hash randomization."""

    script = textwrap.dedent(
        """
        import json
        from tests.unit.test_ocsp_timing_runtime import _worker_population

        values, audit = _worker_population(8, reverse=True)
        print(json.dumps([values, audit], sort_keys=True, separators=(",", ":")))
        """
    )
    outputs: list[str] = []
    for hash_seed in ("1", "8675309"):
        environment = dict(os.environ)
        environment["PYTHONHASHSEED"] = hash_seed
        environment["PYTHONPATH"] = str(_PROJECT_ROOT / "src")
        result = subprocess.run(
            [sys.executable, "-c", script],
            cwd=_PROJECT_ROOT,
            env=environment,
            check=True,
            capture_output=True,
            text=True,
        )
        outputs.append(result.stdout.strip())

    assert outputs[0] == outputs[1]
    values, audit = json.loads(outputs[0])
    assert len(values) == 32
    assert set(audit) == _RELATIONSHIPS
