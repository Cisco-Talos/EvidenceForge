# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Canonical allocations preserve native chronology independently of planning order."""

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from evidenceforge.generation.checkpoints.state_manager_head import StateManagerParticipant
from evidenceforge.generation.emitters.sorted_writer import ExternalSortedLineWriter
from evidenceforge.generation.macos_audit_identity import MacosAuditIdentityLedger
from evidenceforge.generation.state_manager import StateManager
from evidenceforge.models.exceptions import StateError
from tests.unit.test_macos_process_relationship_projection import _family

T0 = datetime(2026, 11, 2, 13, tzinfo=UTC)


def _ledger() -> MacosAuditIdentityLedger:
    return MacosAuditIdentityLedger(lambda key, value: None)


def test_chronological_projection_covers_hosts_old_references_and_all_token_positions() -> None:
    ledger = _ledger()
    # A future action can be planned first. The old actor remains old afterward.
    ledger["MAC", 1] = (T0 + timedelta(minutes=2), "future:exec:0")
    ledger["MAC", 2] = (T0, "child:exec:0")
    ledger["MAC", 3] = (T0 + timedelta(seconds=1), "child:exec:1")
    ledger["OTHER", 1] = (T0 + timedelta(days=1), "other:exec:0")
    ledger.seal()
    assert [ledger.resolve("MAC", i) for i in (2, 3, 1)] == [1, 2, 3]
    assert ledger.resolve("OTHER", 1) == 1
    payload = {
        "process": {"audit_token": {"pidversion": 2}},
        "event": {
            "fork": {
                "child": {
                    "audit_token": {"pidversion": 1},
                    "parent_audit_token": {"pidversion": 2},
                    "responsible_audit_token": {"pidversion": 3},
                }
            }
        },
    }
    native = ledger.project_native("MAC", payload)
    assert native["process"]["audit_token"]["pidversion"] == 1
    child = native["event"]["fork"]["child"]
    assert child["audit_token"]["pidversion"] == 3
    assert child["parent_audit_token"]["pidversion"] == 1
    assert child["responsible_audit_token"]["pidversion"] == 2
    assert payload["process"]["audit_token"]["pidversion"] == 2
    ecar = ledger.project_ecar(
        json.dumps({"hostname": "MAC", "properties": {"previous_pid_version": 2, "pid_version": 3}})
    )
    assert json.loads(ecar)["properties"] == {"previous_pid_version": 1, "pid_version": 2}


def test_unselected_and_prewindow_allocations_participate_without_rendered_source_events() -> None:
    first, second = _ledger(), _ledger()
    facts = [(("MAC", 1), (T0, "one")), (("MAC", 2), (T0 - timedelta(hours=1), "hidden"))]
    for key, value in facts:
        first[key] = value
    for key, value in reversed(facts):
        second[key] = value
    first.seal()
    second.seal()
    assert first.resolve("MAC", 1) == second.resolve("MAC", 1) == 2
    assert first.project_ecar('{"hostname":"WIN","properties":{}}') == (
        '{"hostname":"WIN","properties":{}}'
    )
    with pytest.raises(StateError, match="no canonical allocation"):
        first.resolve("MAC", 999)
    with pytest.raises(StateError, match="sealed"):
        first["MAC", 3] = (T0, "late")


def test_state_manager_checkpoint_restores_allocations_and_records_subsequent_deltas() -> None:
    state, _, _, _ = _family()
    participant = StateManagerParticipant(state)
    first = participant.prepare_checkpoint(1)
    participant.checkpoint_committed(1)
    restored = StateManager()
    owner = StateManagerParticipant(restored)
    owner.restore_checkpoint(first.head.payload, tuple(s.payload for s in first.segments))
    key = ("test-mac", state._macos_audit_pid_versions["test-mac"] + 1)
    restored._macos_audit_identity_intents[key] = (T0, "invented:exec:0")
    second = owner.prepare_checkpoint(2)
    owner.checkpoint_committed(2)
    again = StateManager()
    StateManagerParticipant(again).restore_checkpoint(
        second.head.payload,
        tuple(s.payload for seal in (first, second) for s in seal.segments),
    )
    assert dict(again._macos_audit_identity_intents.items()) == dict(
        restored._macos_audit_identity_intents.items()
    )
    again._macos_audit_identity_intents.seal()
    restored._macos_audit_identity_intents.seal()
    assert again._macos_audit_identity_intents.resolve(*key) == (
        restored._macos_audit_identity_intents.resolve(*key)
    )


def test_rollback_tombstone_survives_spill_and_checkpoint() -> None:
    state = StateManager()
    owner = StateManagerParticipant(state)
    ledger = state._macos_audit_identity_intents
    ledger["MAC", 1] = (T0, "rejected")
    ledger.flush()
    del ledger["MAC", 1]
    seal = owner.prepare_checkpoint(1)
    restored = StateManager()
    StateManagerParticipant(restored).restore_checkpoint(
        seal.head.payload, tuple(s.payload for s in seal.segments)
    )
    assert len(restored._macos_audit_identity_intents) == 0


def test_external_publication_projects_once_after_compaction_and_retries_atomically(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    ledger = _ledger()
    ledger["MAC", 1] = (T0 + timedelta(seconds=1), "later")
    ledger["MAC", 2] = (T0, "earlier")
    ledger.seal()
    output = tmp_path / "ecar.json"
    writer = ExternalSortedLineWriter(
        output,
        sort_key=lambda line: json.loads(line)["n"],
        buffer_size=1,
        merge_fan_in=2,
        defer_publication=True,
    )
    for n in range(12):
        writer.write(json.dumps({"n": n, "hostname": "MAC", "properties": {"pid_version": 1}}))
    writer.flush()
    assert not output.exists()
    writer.set_export_projection(ledger.project_ecar)
    original = ledger.project_ecar
    calls = 0

    def fail_once(line: str) -> str:
        nonlocal calls
        calls += 1
        if calls == 3:
            raise OSError("invented export failure")
        return original(line)

    writer._export_projection = fail_once
    with pytest.raises(OSError, match="invented export failure"):
        writer.close()
    assert not output.exists()
    writer._export_projection = original
    writer.close()
    rows = [json.loads(line) for line in output.read_text().splitlines()]
    assert len(rows) == 12 and [r["n"] for r in rows] == list(range(12))
    assert {r["properties"]["pid_version"] for r in rows} == {2}


def test_legacy_native_array_tokens_and_ecar_sort_keys_use_same_projection() -> None:
    from evidenceforge.generation.emitters.ecar import _ecar_sort_key

    ledger = _ledger()
    ledger["MAC", 1] = (T0 + timedelta(seconds=1), "later")
    ledger["MAC", 2] = (T0, "earlier")
    ledger.seal()
    payload = {"process": {"audit_token": [501, 501, 20, 501, 20, 42, 100, 1]}}
    result = ledger.project_native("MAC", payload)
    assert result["process"]["audit_token"] == [501, 501, 20, 501, 20, 42, 100, 2]
    raw = json.dumps(
        {
            "id": "occurrence",
            "hostname": "MAC",
            "timestamp_ms": 1000,
            "properties": {"pid_version": 1},
        }
    )
    assert _ecar_sort_key(raw) == _ecar_sort_key(ledger.project_ecar(raw))


def test_real_provisional_fork_and_exec_rollback_remove_canonical_allocations() -> None:
    state, _, _, subject = _family()
    before = dict(state._macos_audit_identity_intents.items())
    participant = StateManagerParticipant(state)
    builder = state.begin_action_cohort_materialization()
    fork = builder.fork_process(subject, forked_at=subject.started_at + timedelta(seconds=5))
    plan = builder.seal()
    with state.prepared_action_cohort_materialization(plan) as claim:
        claim.certify_composite_commit(claim.expected_result)
        claim.apply_provisional()
        assert (
            subject.hostname,
            fork.identity.audit_pid_version,
        ) in state._macos_audit_identity_intents
    assert dict(state._macos_audit_identity_intents.items()) == before
    seal = participant.prepare_checkpoint(1)
    restored = StateManager()
    StateManagerParticipant(restored).restore_checkpoint(
        seal.head.payload, tuple(s.payload for s in seal.segments)
    )
    assert dict(restored._macos_audit_identity_intents.items()) == before
    state.materialize_action_cohort(plan)
    assert len(state._macos_audit_identity_intents) == len(before) + 1
    before_exec = dict(state._macos_audit_identity_intents.items())
    child = state.get_process_identity(subject.hostname, fork.identity.pid)
    builder = state.begin_action_cohort_materialization()
    after = builder.execute_process(
        child,
        image="/usr/bin/new-helper",
        command_line="new-helper",
        executed_at=child.started_at + timedelta(seconds=2),
    )
    execution_plan = builder.seal()
    with state.prepared_action_cohort_materialization(execution_plan) as claim:
        claim.certify_composite_commit(claim.expected_result)
        claim.apply_provisional()
        assert (after.hostname, after.audit_pid_version) in state._macos_audit_identity_intents
    assert dict(state._macos_audit_identity_intents.items()) == before_exec
    state.materialize_action_cohort(execution_plan)
    assert len(state._macos_audit_identity_intents) == len(before_exec) + 1
    # The internal process reservation and proof remain unchanged after projection.
    current = state.get_process_identity(subject.hostname, fork.identity.pid)
    state._macos_audit_identity_intents.seal()
    assert state.get_process_identity(subject.hostname, fork.identity.pid) == current


@pytest.mark.parametrize("as_string", [True, False])
def test_ecar_adapter_preserves_native_property_type(as_string: bool) -> None:
    ledger = _ledger()
    ledger["MAC", 1] = (T0 + timedelta(seconds=1), "later")
    ledger["MAC", 2] = (T0, "earlier")
    ledger.seal()
    before = {
        "hostname": "MAC",
        "properties": {
            "pid_version": "1" if as_string else 1,
            "previous_pid_version": "2" if as_string else 2,
        },
    }
    after = json.loads(ledger.project_ecar(json.dumps(before)))
    assert after["properties"] == (
        {"pid_version": "2", "previous_pid_version": "1"}
        if as_string
        else {"pid_version": 2, "previous_pid_version": 1}
    )
