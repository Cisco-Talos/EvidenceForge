"""Contracts frozen before the nine-item simplification pass."""

from __future__ import annotations

import hashlib
import json
from copy import deepcopy
from typing import Any
from unittest.mock import Mock

import pytest

from evidenceforge.generation.application_channels import _MutationGate as ApplicationGate
from evidenceforge.generation.checkpoints import fingerprint
from evidenceforge.generation.deployment_registry import _ArtifactRegistryGate as ArtifactGate
from evidenceforge.generation.http_channels import _HttpMutationGate as HttpGate
from evidenceforge.generation.lifecycle_registry import _MutationGate as LifecycleGate
from evidenceforge.generation.proxy_channels import _SidecarMutationGate as ProxyGate
from evidenceforge.generation.rdp_sessions import _MutationGate as RdpGate
from evidenceforge.generation.smb_channels import _SmbMutationGate as SmbGate
from evidenceforge.generation.ssh_channels import _MutationGate as SshGate

GATES = (
    ApplicationGate,
    ArtifactGate,
    HttpGate,
    LifecycleGate,
    ProxyGate,
    RdpGate,
    SmbGate,
    SshGate,
)


def _encode(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()


def test_fingerprint_projections_preserve_unicode_order_and_input_payload(monkeypatch: Any) -> None:
    payload = {
        "formats": ["zeek", "windows"],
        "resolved": {"name": "caf\u00e9", "events": [{"id": 2}, {"id": 1}]},
        "checkpoint_schema": 7,
        "dependencies": {"z": "2", "a": "1"},
    }
    original = deepcopy(payload)
    monkeypatch.setattr(fingerprint, "run_fingerprint_payload", lambda *a, **kw: deepcopy(payload))
    options = {"output_target": "default", "formats": [], "oob_hosts": ()}
    actual = fingerprint.run_fingerprint(Mock(), **options)
    components = fingerprint.run_fingerprint_components(Mock(), **options)
    assert actual == hashlib.sha256(_encode(original)).hexdigest()
    assert components == {key: value for key, value in original.items() if key != "resolved"} | {
        "resolved_sha256": hashlib.sha256(_encode(original["resolved"])).hexdigest()
    }
    assert payload == original


def test_fingerprint_operations_observe_changed_payloads(monkeypatch: Any) -> None:
    payload: dict[str, Any] = {"resolved": {"name": "initial"}, "build": "first"}
    monkeypatch.setattr(fingerprint, "run_fingerprint_payload", lambda *a, **kw: deepcopy(payload))
    options = {"output_target": "default", "formats": [], "oob_hosts": ()}
    initial = fingerprint.run_fingerprint(Mock(), **options)
    payload["build"] = "second"
    assert fingerprint.run_fingerprint(Mock(), **options) != initial
    assert fingerprint.run_fingerprint_components(Mock(), **options)["build"] == "second"


def test_combined_fingerprint_discovers_once_without_mutating_snapshot(monkeypatch: Any) -> None:
    payload = {"resolved": {"name": "caf\u00e9"}, "build": "first"}
    original = deepcopy(payload)
    discover = Mock(return_value=payload)
    monkeypatch.setattr(fingerprint, "run_fingerprint_payload", discover)
    options = {"output_target": "default", "formats": [], "oob_hosts": ()}
    identity, components = fingerprint.run_fingerprint_details(Mock(), **options)
    assert discover.call_count == 1
    assert payload == original
    assert identity == hashlib.sha256(_encode(original)).hexdigest()
    assert components == {
        "build": "first",
        "resolved_sha256": hashlib.sha256(_encode(original["resolved"])).hexdigest(),
    }
    payload["build"] = "second"
    second, components = fingerprint.run_fingerprint_details(Mock(), **options)
    assert second != identity
    assert components["build"] == "second"
    assert discover.call_count == 2


def test_combined_fingerprint_scans_installed_build_once_per_operation(monkeypatch: Any) -> None:
    scan = Mock(side_effect=["build-one", "build-two"])
    monkeypatch.setattr(fingerprint, "installed_build_digest", scan)
    monkeypatch.setattr(fingerprint, "behavior_fingerprint_components", lambda: {})
    monkeypatch.setattr(
        fingerprint, "semantic_resolved_payload", lambda compiled: {"name": "fixed"}
    )
    options = {"output_target": "default", "formats": ["zeek"], "oob_hosts": ()}
    first, components = fingerprint.run_fingerprint_details(Mock(), **options)
    assert scan.call_count == 1
    assert components["evidenceforge_build_sha256"] == "build-one"
    second, components = fingerprint.run_fingerprint_details(Mock(), **options)
    assert scan.call_count == 2
    assert components["evidenceforge_build_sha256"] == "build-two"
    assert first != second


@pytest.mark.parametrize("gate_type", GATES)
def test_registry_gate_releases_mutation_after_primary_error(gate_type: Any) -> None:
    gate = gate_type()
    with pytest.raises(ValueError, match="primary"):
        with gate.mutation():
            assert gate._readers == 1
            assert gate._writer is False
            raise ValueError("primary")
    assert gate._readers == 0
    with gate.watermark():
        assert gate._writer is True
    assert gate._writer is False


@pytest.mark.parametrize("gate_type", GATES)
def test_registry_gate_releases_watermark_after_primary_error(gate_type: Any) -> None:
    gate = gate_type()
    with pytest.raises(ValueError, match="primary"):
        with gate.watermark():
            assert gate._readers == 0
            assert gate._waiting_writers == 0
            raise ValueError("primary")
    assert gate._writer is False
    with gate.mutation():
        assert gate._readers == 1
    assert gate._readers == 0
