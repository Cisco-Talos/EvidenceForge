# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT
"""Canonical native generation resolution consumes history before observation."""

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from evidenceforge.generation.macos_audit_identity import MacosAuditIdentityLedger
from evidenceforge.generation.state_manager import StateManager
from evidenceforge.models.exceptions import StateError
from evidenceforge.utils.rng import generation_seed_scope

T0 = datetime(2026, 11, 2, 13, tzinfo=UTC)


def test_ledger_resolves_history_chronologically_and_shares_every_reference() -> None:
    ledger = MacosAuditIdentityLedger(lambda key, value: None)
    ledger["MAC", 1] = (T0 + timedelta(minutes=2), "future")
    ledger["MAC", 2] = (T0, "earlier")
    ledger["MAC", 3] = (T0 + timedelta(seconds=1), "exec")
    ledger["OTHER", 1] = (T0, "other")

    def history(host: str, at: datetime) -> int:
        return (1000 if host == "MAC" else 200) + int((at - T0).total_seconds()) * 10

    ledger.seal(history_offset=history)
    assert [ledger.resolve("MAC", key) for key in (2, 3, 1)] == [1001, 1012, 2203]
    assert ledger.resolve("OTHER", 1) == 201
    original = {
        "process": {"audit_token": {"pidversion": 2}},
        "event": {
            "exec": {
                "target": {
                    "audit_token": {"pidversion": 3},
                    "parent_audit_token": {"pidversion": 2},
                    "responsible_audit_token": [0, 0, 0, 0, 0, 0, 0, 1],
                }
            }
        },
    }
    projected = ledger.project_native("MAC", original)
    assert projected["process"]["audit_token"]["pidversion"] == 1001
    target = projected["event"]["exec"]["target"]
    assert target["audit_token"]["pidversion"] == 1012
    assert target["parent_audit_token"]["pidversion"] == 1001
    assert target["responsible_audit_token"][-1] == 2203
    assert original["process"]["audit_token"]["pidversion"] == 2
    normalized = json.loads(
        ledger.project_ecar(
            json.dumps(
                {"hostname": "MAC", "properties": {"previous_pid_version": "2", "pid_version": 3}}
            )
        )
    )
    assert normalized["properties"] == {"previous_pid_version": "1001", "pid_version": 1012}


@pytest.mark.parametrize("invalid", ["negative", "boolean", "overflow", "decreasing"])
def test_ledger_rejects_invalid_history_atomically_and_can_retry(invalid: str) -> None:
    ledger = MacosAuditIdentityLedger(lambda key, value: None)
    ledger["MAC", 1] = (T0, "one")
    ledger["MAC", 2] = (T0 + timedelta(seconds=1), "two")

    def history(host: str, at: datetime) -> int:
        if invalid == "negative":
            return -1
        if invalid == "boolean":
            return True
        if invalid == "overflow":
            return 2**32
        return 10 if at == T0 else 9

    with pytest.raises(StateError):
        ledger.seal(history_offset=history)
    with pytest.raises(StateError, match="sealed"):
        ledger.resolve("MAC", 1)
    ledger.seal()
    assert [ledger.resolve("MAC", key) for key in (1, 2)] == [1, 2]


def test_ledger_history_spans_multiple_bounded_pages_without_source_rows() -> None:
    ledger = MacosAuditIdentityLedger(lambda key, value: None)
    for ordinal in reversed(range(4097)):
        ledger["MAC", ordinal + 1] = (T0 + timedelta(seconds=ordinal), f"execution-{ordinal}")
        ledger.drain_before_planning()
    ledger.seal(history_offset=lambda host, at: 100 + int((at - T0).total_seconds()) * 2)
    assert ledger.resolve("MAC", 1) == 101
    assert ledger.resolve("MAC", 4097) == 100 + 4096 * 2 + 4097


def _modeled_state(*, known_boot: bool = True) -> tuple[StateManager, list[int]]:

    state = StateManager()
    boot = T0 - timedelta(days=12)
    if known_boot:
        state.register_boot_time("MAC", boot)
    handles: list[int] = []
    for ordinal, at in enumerate((boot, T0, T0 + timedelta(minutes=1))):
        state.set_current_time(at)
        plan = state.plan_process_materialization(
            system="MAC",
            parent_pid=0 if ordinal == 0 else 1,
            fixed_pid=1 if ordinal == 0 else None,
            image="/sbin/launchd" if ordinal == 0 else "/bin/zsh",
            command_line="launchd" if ordinal == 0 else "zsh",
            username="root" if ordinal == 0 else "casey",
            integrity_level="Medium",
            os_category="macos",
            start_time=at,
        )
        state.materialize_process(plan)
        assert plan.identity.audit_pid_version is not None
        handles.append(plan.identity.audit_pid_version)
    return state, handles


@pytest.mark.parametrize("seed", [42, 137])
def test_state_history_uses_existing_births_and_rebuilds_identically_after_checkpoint(
    seed: int,
) -> None:
    from evidenceforge.generation.checkpoints.state_manager_head import StateManagerParticipant

    with generation_seed_scope(seed):
        state, handles = _modeled_state()
    original_facts = dict(state._macos_audit_identity_intents.items())
    checkpoint = StateManagerParticipant(state).prepare_checkpoint(1)
    restored = StateManager()
    StateManagerParticipant(restored).restore_checkpoint(
        checkpoint.head.payload, tuple(segment.payload for segment in checkpoint.segments)
    )
    results = []
    for owner in (state, restored):
        owner.seal_macos_audit_identities(require_known_boot=True)
        values = [owner._macos_audit_identity_intents.resolve("MAC", handle) for handle in handles]
        assert values[0] == 1
        prefix = owner._linux_pid_weekly_churn_prefixes["MAC"]
        boot = owner.get_boot_time("MAC")
        assert boot is not None
        hidden_births = owner._linux_pid_hidden_churn_from_prefix(
            prefix, int((T0 - boot).total_seconds())
        )
        assert hidden_births > 0 and values[1] > hidden_births
        assert values[2] > values[1] + 1
        assert dict(owner._macos_audit_identity_intents.items()) == original_facts
        results.append(values)
    assert results[0] == results[1]


def test_missing_frozen_history_policy_keeps_legacy_dense_resolution(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from evidenceforge.generation.activity import macos_execution_metadata

    profile = macos_execution_metadata.load_macos_execution_metadata_profile()
    assert profile is not None
    data = profile.model_dump()
    data.pop("native_generation_history", None)
    legacy = type(profile).model_validate(data)
    monkeypatch.setattr(
        macos_execution_metadata, "load_macos_execution_metadata_profile", lambda: legacy
    )
    state, handles = _modeled_state()
    state.seal_macos_audit_identities(require_known_boot=True)
    assert [state._macos_audit_identity_intents.resolve("MAC", handle) for handle in handles] == [
        1,
        2,
        3,
    ]


def test_unknown_boot_is_legacy_only_and_engine_requirement_fails_closed() -> None:
    state, handles = _modeled_state(known_boot=False)
    with pytest.raises(StateError, match="modeled Mac boot"):
        state.seal_macos_audit_identities(require_known_boot=True)
    state.seal_macos_audit_identities()
    assert [state._macos_audit_identity_intents.resolve("MAC", handle) for handle in handles] == [
        1,
        2,
        3,
    ]


@pytest.mark.slow
def test_ecar_only_partial_profile_uses_host_history_without_native_ingress(tmp_path: Path) -> None:
    import yaml

    from evidenceforge.generation.engine import GenerationEngine
    from evidenceforge.models.scenario import Scenario

    # Complete modeled native coverage intentionally requires the native source.
    # This separate supported eCAR-only profile verifies the other seal entry.
    data = yaml.safe_load(
        Path("scenarios/macos-persistence-example/native-system-job.yaml").read_text()
    )
    data["macos_process_coverage"] = "partial"
    data["generation_seed"] = 372
    data["output"]["logs"] = [{"format": "ecar"}]
    engine = GenerationEngine(Scenario.model_validate(data), tmp_path)
    engine.generate()
    ledger = engine.state_manager._macos_audit_identity_intents
    assert ledger._sealed
    reserved_handles = [key[1] for key in ledger]
    assert reserved_handles
    versions = []
    for path in tmp_path.rglob("ecar.json"):
        for line in path.read_text().splitlines():
            row = json.loads(line)
            if row.get("object") == "PROCESS":
                value = row.get("properties", {}).get("pid_version")
                if value is not None:
                    versions.append(int(value))
    assert versions
    # The export uses native host history, rather than opaque reservation handles
    # or a dense index over retained records, even with the ES source disabled.
    assert max(versions) > max(reserved_handles)
