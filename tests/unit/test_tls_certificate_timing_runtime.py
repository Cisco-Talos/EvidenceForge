# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Engine-owned timing contracts for TLS certificate validity placement."""

from __future__ import annotations

import ast
import inspect
import json
import os
import subprocess
import sys
import textwrap
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

from evidenceforge.events.cryptography import TlsCertificatePresentationPlan
from evidenceforge.generation.actions import tls_certificate as tls_certificate_module
from evidenceforge.generation.actions.tls_certificate import TlsCertificatePlanner
from evidenceforge.generation.activity.generator import ActivityGenerator
from evidenceforge.generation.cryptographic_material import CryptographicMaterialRegistry
from evidenceforge.generation.source_timing import SourceTimingPlanner
from evidenceforge.generation.state_manager import StateManager
from evidenceforge.generation.timing import TimingRuntime

_EVENT_TIME = datetime(2026, 8, 17, 12, tzinfo=UTC)
_ISSUER_NAME = "CN=Runtime Test Issuing CA, O=Example Corp, C=US"
_ISSUER_START = _EVENT_TIME - timedelta(hours=10)
_ISSUER_END = _EVENT_TIME + timedelta(days=3650)
_ISSUER_CONFIG = {
    "name": _ISSUER_NAME,
    "validity_days": 90,
    "validity_days_min": 90,
    "validity_days_max": 90,
    "not_before_max_days": 89,
}
_BOUND_RELATIONSHIP = "tls.certificate.validity.bound_to_issuer"
_DURATION_RELATIONSHIP = "tls.certificate.validity.duration_days"
_NOT_BEFORE_DAYS_RELATIONSHIP = "tls.certificate.validity.not_before_days"
_NOT_BEFORE_SECOND_RELATIONSHIP = "tls.certificate.validity.not_before_second"
_VALIDITY_RELATIONSHIPS = {
    _BOUND_RELATIONSHIP,
    _DURATION_RELATIONSHIP,
    _NOT_BEFORE_DAYS_RELATIONSHIP,
    _NOT_BEFORE_SECOND_RELATIONSHIP,
}
_PROJECT_ROOT = Path(__file__).parents[2]


def _issuer_profile(_issuer_name: str) -> dict[str, Any]:
    """Return a profile that forces the child-validity placement branch."""

    return {
        "subject": _ISSUER_NAME,
        "issuer": _ISSUER_NAME,
        "not_valid_before": int(_ISSUER_START.timestamp()),
        "not_valid_after": int(_ISSUER_END.timestamp()),
        "key_type": "ecdsa",
        "key_length": 256,
    }


@pytest.fixture(autouse=True)
def _force_issuer_bound(monkeypatch: pytest.MonkeyPatch) -> None:
    """Exercise the sole migrated timing branch with a fixed issuer interval."""

    monkeypatch.setattr(
        tls_certificate_module,
        "certificate_authority_profile",
        _issuer_profile,
    )


def _plan(
    registry: Any,
    runtime: Any,
    *,
    backend_identity: str = "203.0.113.40",
    connection_identity: str = "C-runtime-owned",
) -> TlsCertificatePresentationPlan:
    """Plan one leaf-only TLS presentation through the supplied owners."""

    return TlsCertificatePlanner(registry, timing_runtime=runtime).plan(
        backend_identity=backend_identity,
        cert_name="203.0.113.40",
        issuer_config=_ISSUER_CONFIG,
        event_time=_EVENT_TIME,
        connection_identity=connection_identity,
        key_type="ecdsa",
        key_size=256,
        san_dns=(),
    )


def _assert_validity_bounds(not_valid_before: int, not_valid_after: int) -> None:
    """Assert issuer containment without a boundary-copy artifact."""

    issuer_start = int(_ISSUER_START.timestamp())
    issuer_end = int(_ISSUER_END.timestamp())
    event_epoch = int(_EVENT_TIME.timestamp())
    assert issuer_start + 3600 <= not_valid_before <= event_epoch - 1
    assert not_valid_before < event_epoch < not_valid_after <= issuer_end


def test_direct_and_prepared_crypto_planning_commit_identical_runtime_sample() -> None:
    """The crypto overlay stages one sample and commits exactly like direct planning."""

    direct_runtime = TimingRuntime(
        reference_time=_EVENT_TIME,
        namespace="tls-certificate-prepared-parity",
    )
    direct_registry = CryptographicMaterialRegistry()
    direct = _plan(direct_registry, direct_runtime)

    staged_runtime = TimingRuntime(
        reference_time=_EVENT_TIME,
        namespace="tls-certificate-prepared-parity",
    )
    timing_owner = SourceTimingPlanner(timing_runtime=staged_runtime)
    staged_registry = CryptographicMaterialRegistry()
    crypto_owner = object()
    crypto_preparation = staged_registry.begin_tls_preparation(owner=crypto_owner)
    before_timing = staged_runtime.state_digest()
    before_crypto = staged_registry.state_digest()

    with timing_owner.prepared_planning() as timing_preparation:
        staged = _plan(
            crypto_preparation,
            timing_preparation.planning_runtime,
        )
        assert timing_preparation.staged_audit_operations == 4
        assert staged_runtime.state_digest() == before_timing
        assert staged_registry.state_digest() == before_crypto
        crypto_token = crypto_preparation.seal(owner=crypto_owner)

    with staged_registry.prepared_tls_material(crypto_token) as crypto_commit:
        crypto_receipt = crypto_commit.commit_no_fail()
    with timing_preparation.claimed_commit():
        timing_preparation.commit_no_fail()

    assert staged == direct
    assert staged_registry.authenticates_tls_preparation_receipt(
        crypto_receipt,
        token=crypto_token,
    )
    assert staged_registry.state_digest() == direct_registry.state_digest()
    assert staged_registry.census() == direct_registry.census()
    assert staged_runtime.audit.snapshot() == direct_runtime.audit.snapshot()
    audit = staged_runtime.audit.snapshot()
    assert audit.sample_counts == {relationship: 1 for relationship in _VALIDITY_RELATIONSHIPS}
    assert audit.distribution_counts == {"constant": 1, "mixture": 3}
    _assert_validity_bounds(
        staged.leaf.not_valid_before,
        staged.leaf.not_valid_after,
    )


def _worker_population(worker_count: int) -> tuple[dict[str, tuple[int, int, str]], dict[str, int]]:
    """Return validity identities and audit counts under one worker topology."""

    runtime = TimingRuntime(
        reference_time=_EVENT_TIME,
        namespace="tls-certificate-worker-parity",
    )
    registry = CryptographicMaterialRegistry()
    backends = tuple(f"tls-backend-{ordinal:03d}" for ordinal in range(64))

    def plan(backend: str) -> tuple[str, tuple[int, int, str]]:
        presentation = _plan(
            registry,
            runtime,
            backend_identity=backend,
            connection_identity=f"C-{backend}",
        )
        leaf = presentation.leaf
        return backend, (leaf.not_valid_before, leaf.not_valid_after, leaf.fingerprint)

    with ThreadPoolExecutor(max_workers=worker_count) as executor:
        results = dict(executor.map(plan, reversed(backends)))
    return results, dict(runtime.audit.snapshot().sample_counts)


def test_certificate_validity_is_worker_deterministic() -> None:
    """Runtime scopes make placement independent of worker arrival order."""

    single = _worker_population(1)
    parallel = _worker_population(8)
    assert single == parallel
    assert single[1] == {relationship: 64 for relationship in _VALIDITY_RELATIONSHIPS}
    assert all(
        int(_ISSUER_START.timestamp()) < not_before < int(_EVENT_TIME.timestamp())
        for not_before, _not_after, _fingerprint in single[0].values()
    )


def test_certificate_validity_is_pythonhashseed_deterministic() -> None:
    """Certificate placement cannot inherit interpreter hash randomization."""

    script = textwrap.dedent(
        f"""
        import json
        from concurrent.futures import ThreadPoolExecutor
        from datetime import UTC, datetime

        from evidenceforge.generation.actions import tls_certificate as tls_module
        from evidenceforge.generation.actions.tls_certificate import TlsCertificatePlanner
        from evidenceforge.generation.cryptographic_material import CryptographicMaterialRegistry
        from evidenceforge.generation.timing import TimingRuntime

        event_time = datetime.fromisoformat({_EVENT_TIME.isoformat()!r})
        issuer_name = {_ISSUER_NAME!r}
        profile = {_issuer_profile(_ISSUER_NAME)!r}
        issuer_config = {_ISSUER_CONFIG!r}
        tls_module.certificate_authority_profile = lambda _name: profile
        runtime = TimingRuntime(
            reference_time=event_time,
            namespace="tls-certificate-hash-seed",
        )
        registry = CryptographicMaterialRegistry()

        def plan(ordinal):
            backend = f"hash-backend-{{ordinal:03d}}"
            leaf = TlsCertificatePlanner(registry, timing_runtime=runtime).plan(
                backend_identity=backend,
                cert_name="203.0.113.40",
                issuer_config=issuer_config,
                event_time=event_time,
                connection_identity=f"C-{{backend}}",
                key_type="ecdsa",
                key_size=256,
                san_dns=(),
            ).leaf
            return backend, (leaf.not_valid_before, leaf.not_valid_after, leaf.fingerprint)

        with ThreadPoolExecutor(max_workers=8) as executor:
            values = dict(executor.map(plan, reversed(range(32))))
        print(json.dumps(values, sort_keys=True, separators=(",", ":")))
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
    assert len(json.loads(outputs[0])) == 32


def test_validity_window_is_stable_within_identity_rotation_bucket() -> None:
    """Identity and rotation-bucket scopes keep issuance placement stable."""

    def validity(event_time: datetime) -> tuple[int, int]:
        runtime = TimingRuntime(
            reference_time=_EVENT_TIME,
            namespace="tls-certificate-bucket-parity",
        )
        planner = TlsCertificatePlanner(CryptographicMaterialRegistry(), timing_runtime=runtime)
        result = planner._validity_window(
            identity="leaf:bucket-stable",
            backend_identity="bucket-stable.example",
            subject_name="CN=bucket-stable.example",
            event_time=event_time,
            validity_days_min=90,
            validity_days_max=397,
            not_before_max_days=89,
        )
        assert runtime.audit.snapshot().sample_counts == {
            _DURATION_RELATIONSHIP: 1,
            _NOT_BEFORE_DAYS_RELATIONSHIP: 1,
            _NOT_BEFORE_SECOND_RELATIONSHIP: 1,
        }
        return result

    first = validity(_EVENT_TIME)
    assert first == validity(_EVENT_TIME + timedelta(hours=1))
    assert first[0] < int(_EVENT_TIME.timestamp()) < first[1]
    assert 90 * 86400 <= first[1] - first[0] <= 397 * 86400


def test_production_planners_inject_canonical_and_prepared_runtime() -> None:
    """No production planner construction may silently select compatibility timing."""

    runtime = TimingRuntime(
        reference_time=_EVENT_TIME,
        namespace="tls-certificate-production-owner",
    )
    generator = ActivityGenerator(StateManager(), {}, timing_runtime=runtime)
    assert generator._tls_certificate_planner.timing_runtime is runtime

    generator_path = _PROJECT_ROOT / "src/evidenceforge/generation/activity/generator.py"
    tree = ast.parse(generator_path.read_text(encoding="utf-8"), filename=str(generator_path))
    calls = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "TlsCertificatePlanner"
    ]
    assert len(calls) == 2
    assert all(any(keyword.arg == "timing_runtime" for keyword in call.keywords) for call in calls)
    runtime_values = {
        ast.unparse(keyword.value)
        for call in calls
        for keyword in call.keywords
        if keyword.arg == "timing_runtime"
    }
    assert "self.timing_runtime" in runtime_values
    assert any(
        "timing_runtime if timing_runtime is not None else self.timing_runtime" in value
        for value in runtime_values
    )

    bound_source = inspect.getsource(TlsCertificatePlanner._bound_to_issuer)
    validity_source = inspect.getsource(TlsCertificatePlanner._validity_window)
    assert "random.Random" not in bound_source
    assert "_stable_seed" not in bound_source
    assert "random.Random" not in validity_source
    assert "_stable_seed" not in validity_source
