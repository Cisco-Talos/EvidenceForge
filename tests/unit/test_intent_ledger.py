# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Tests for the independent authored-intent ledger scaffold."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import pytest

from evidenceforge.events.contracts import OccurrenceRole, SemanticOccurrenceKey
from evidenceforge.generation.intent_ledger import (
    AuthoredIntentLedger,
    IntentExecutionLedger,
    IntentSection,
)
from evidenceforge.models.scenario import LogonEventSpec, ProcessEventSpec


def _scenario(*events: object) -> SimpleNamespace:
    step = SimpleNamespace(
        id="initial-access",
        time="+10m",
        actor="alice",
        system="WS-01",
        activity="Initial access",
        events=list(events),
    )
    red_herring = SimpleNamespace(
        id="benign-admin",
        time="+20m",
        actor="admin",
        system="SRV-01",
        activity="Routine administration",
        events=[ProcessEventSpec(process_name="whoami.exe")],
    )
    return SimpleNamespace(
        name="intent-ledger-test",
        storyline=[step],
        red_herrings=[red_herring],
    )


def test_ledger_retains_storyline_and_red_herring_intent() -> None:
    """The authored oracle is captured before any planner or occurrence output exists."""

    ledger = AuthoredIntentLedger.from_scenario(
        _scenario(
            LogonEventSpec(logon_type=3),
            ProcessEventSpec(process_name="cmd.exe", command_line="cmd.exe /c whoami"),
        )
    )

    assert len(ledger.intents) == 3
    assert {intent.section for intent in ledger.intents} == {
        IntentSection.STORYLINE,
        IntentSection.RED_HERRING,
    }
    assert {intent.event_type for intent in ledger.intents} == {"logon", "process"}


def test_semantic_intent_id_survives_unrelated_sibling_insertion() -> None:
    """Adding an unrelated sibling does not renumber an existing intent."""

    process = ProcessEventSpec(process_name="cmd.exe", command_line="cmd.exe /c whoami")
    original = AuthoredIntentLedger.from_scenario(_scenario(process))
    expanded = AuthoredIntentLedger.from_scenario(_scenario(LogonEventSpec(logon_type=3), process))

    original_process_id = next(
        intent.intent_id
        for intent in original.intents
        if intent.section is IntentSection.STORYLINE and intent.event_type == "process"
    )
    expanded_process_id = next(
        intent.intent_id
        for intent in expanded.intents
        if intent.section is IntentSection.STORYLINE and intent.event_type == "process"
    )

    assert expanded_process_id == original_process_id


def test_documentation_metadata_does_not_change_semantic_intent_id() -> None:
    """Technique and description edits do not rewrite execution identity."""

    plain = ProcessEventSpec(process_name="cmd.exe")
    documented = ProcessEventSpec(
        process_name="cmd.exe",
        technique="T1059.003",
        description="Windows command shell",
    )

    plain_ledger = AuthoredIntentLedger.from_scenario(_scenario(plain))
    documented_ledger = AuthoredIntentLedger.from_scenario(_scenario(documented))

    assert plain_ledger.intents[0].intent_id == documented_ledger.intents[0].intent_id


def test_reconciliation_exposes_missing_and_unexpected_plans() -> None:
    """Planning omissions cannot disappear from a projection-derived oracle."""

    ledger = AuthoredIntentLedger.from_scenario(
        _scenario(
            LogonEventSpec(logon_type=3),
            ProcessEventSpec(process_name="cmd.exe"),
        )
    )
    acknowledged = ledger.intents[0].intent_id

    result = ledger.reconcile([acknowledged, "not-authored"])

    assert not result.complete
    assert result.planned_intent_ids == {acknowledged, "not-authored"}
    assert result.unexpected_intent_ids == {"not-authored"}
    assert result.missing_intent_ids == ledger.intent_ids - {acknowledged}


def test_intent_at_preserves_typed_step_position() -> None:
    """Storyline execution can bind each typed spec to its independent authored ID."""

    ledger = AuthoredIntentLedger.from_scenario(
        _scenario(
            LogonEventSpec(logon_type=3),
            ProcessEventSpec(process_name="cmd.exe"),
        )
    )

    first = ledger.intent_at(IntentSection.STORYLINE, "initial-access", 0)
    second = ledger.intent_at(IntentSection.STORYLINE, "initial-access", 1)

    assert first.event_type == "logon"
    assert second.event_type == "process"


def test_execution_snapshot_links_occurrence_and_observation() -> None:
    """The mutable recorder freezes stable action, occurrence, and source decisions."""

    authored = AuthoredIntentLedger.from_scenario(_scenario(LogonEventSpec(logon_type=3)))
    intent = authored.intent_at(IntentSection.STORYLINE, "initial-access", 0)
    execution = IntentExecutionLedger(authored)
    occurrence_key = SemanticOccurrenceKey(
        action_id="action-1",
        role=OccurrenceRole.PRIMARY,
        instance_key="session-1",
    )

    execution.mark_planned(intent.intent_id)
    execution.record_occurrence(intent.intent_id, occurrence_key)
    execution.record_observation(intent.intent_id, "windows_security", "visible")
    snapshot = next(item for item in execution.snapshot() if item.intent_id == intent.intent_id)

    assert snapshot.planned
    assert snapshot.action_ids == ("action-1",)
    assert snapshot.occurrence_ids == (occurrence_key.occurrence_id,)
    assert snapshot.source_status == {"windows_security": {"visible": 1}}


def test_execution_snapshot_retains_unexpected_evidence() -> None:
    """Unexpected occurrence/observation IDs cannot disappear from frozen reconciliation."""

    authored = AuthoredIntentLedger.from_scenario(_scenario(LogonEventSpec(logon_type=3)))
    execution = IntentExecutionLedger(authored)

    occurrence_key = SemanticOccurrenceKey(
        action_id="unexpected-action",
        role=OccurrenceRole.PRIMARY,
        instance_key="unexpected-occurrence",
    )
    execution.record_occurrence("unexpected-intent", occurrence_key)
    execution.record_observation("unexpected-intent", "ecar", "visible")

    unexpected = next(
        snapshot for snapshot in execution.snapshot() if snapshot.intent_id == "unexpected-intent"
    )
    assert unexpected.planned is False
    assert unexpected.occurrence_ids == (occurrence_key.occurrence_id,)
    assert unexpected.source_status == {"ecar": {"visible": 1}}


def test_execution_ledger_reports_fixed_windows_and_bounded_hot_deduplication() -> None:
    """Watermarks bound exact IDs while lifetime counts and fixed windows remain truthful."""

    authored = AuthoredIntentLedger.from_scenario(_scenario(LogonEventSpec(logon_type=3)))
    intent = authored.intent_at(IntentSection.STORYLINE, "initial-access", 0)
    execution = IntentExecutionLedger(authored, hot_identity_capacity=16)
    watermark = datetime(2026, 8, 16, 12, tzinfo=UTC)
    offsets = (-31 * 24, -29 * 24, -6 * 24, -23, 0)
    for index, hours in enumerate(offsets):
        execution.record_occurrence(
            intent.intent_id,
            SemanticOccurrenceKey(
                action_id="window-action",
                role=OccurrenceRole.DEPENDENT,
                instance_key=f"window-{index}",
            ),
            watermark + timedelta(hours=hours),
        )

    snapshot = next(item for item in execution.snapshot() if item.intent_id == intent.intent_id)
    diagnostics = execution.diagnostics()

    assert snapshot.occurrence_reference_count == 5
    assert snapshot.occurrence_window_counts == {"24h": 2, "7d": 3, "30d": 4}
    assert diagnostics.watermark == watermark
    assert diagnostics.hot_identity_count == 3
    assert diagnostics.hot_horizon_seconds == 7 * 24 * 60 * 60
    assert diagnostics.window_bucket_count == 4


def test_duplicate_truth_is_exact_only_inside_the_declared_hot_horizon() -> None:
    """A repeated hot occurrence is counted, while an expired identity is not retained."""

    authored = AuthoredIntentLedger.from_scenario(_scenario(LogonEventSpec(logon_type=3)))
    intent = authored.intent_at(IntentSection.STORYLINE, "initial-access", 0)
    execution = IntentExecutionLedger(authored)
    timestamp = datetime(2026, 8, 1, tzinfo=UTC)
    occurrence = SemanticOccurrenceKey(
        action_id="duplicate-action",
        role=OccurrenceRole.PRIMARY,
        instance_key="duplicate-instance",
    )

    execution.record_occurrence(intent.intent_id, occurrence, timestamp)
    execution.record_occurrence(intent.intent_id, occurrence, timestamp + timedelta(days=1))
    execution.advance_watermark(timestamp + timedelta(days=8))
    execution.record_occurrence(intent.intent_id, occurrence, timestamp + timedelta(days=8))

    snapshot = next(item for item in execution.snapshot() if item.intent_id == intent.intent_id)
    assert snapshot.occurrence_reference_count == 3
    assert snapshot.duplicate_occurrence_count == 1


def _digest_snapshot(worker_count: int, reverse: bool = False) -> tuple[object, ...]:
    authored = AuthoredIntentLedger.from_scenario(_scenario(LogonEventSpec(logon_type=3)))
    intent = authored.intent_at(IntentSection.STORYLINE, "initial-access", 0)
    execution = IntentExecutionLedger(authored, hot_identity_capacity=32)
    timestamp = datetime(2026, 8, 16, 12, tzinfo=UTC)
    indices = list(range(256))
    if reverse:
        indices.reverse()

    def record(index: int) -> None:
        execution.record_occurrence(
            intent.intent_id,
            SemanticOccurrenceKey(
                action_id=f"action-{index % 11}",
                role=OccurrenceRole.DEPENDENT,
                instance_key=f"instance-{index}",
            ),
            timestamp - timedelta(hours=index % 48),
        )

    with ThreadPoolExecutor(max_workers=worker_count) as executor:
        tuple(executor.map(record, indices))
    snapshot = next(item for item in execution.snapshot() if item.intent_id == intent.intent_id)
    return (
        snapshot.action_reference_count,
        snapshot.occurrence_reference_count,
        snapshot.action_digest,
        snapshot.occurrence_digest,
        snapshot.action_ids,
        snapshot.occurrence_ids,
        snapshot.occurrence_window_counts,
    )


def test_execution_digest_is_stable_across_order_and_worker_counts() -> None:
    """Commutative aggregates do not depend on scheduling or insertion order."""

    expected = _digest_snapshot(1)
    assert _digest_snapshot(4, reverse=True) == expected
    assert _digest_snapshot(8) == expected


def test_execution_digest_is_stable_across_python_hash_seeds() -> None:
    """Digest and deterministic samples are independent of Python hash randomization."""

    script = """
import json
from datetime import UTC, datetime
from evidenceforge.events.contracts import OccurrenceRole, SemanticOccurrenceKey
from evidenceforge.generation.intent_ledger import AuthoredIntentLedger, IntentExecutionLedger

ledger = IntentExecutionLedger(AuthoredIntentLedger("seed-test", ()), hot_identity_capacity=16)
for index in set(range(64)):
    ledger.record_occurrence(
        "unexpected-intent",
        SemanticOccurrenceKey(f"action-{index % 5}", OccurrenceRole.DEPENDENT, f"item-{index}"),
        datetime(2026, 8, 16, tzinfo=UTC),
    )
snapshot = ledger.snapshot()[0]
print(json.dumps({
    "action_digest": snapshot.action_digest,
    "occurrence_digest": snapshot.occurrence_digest,
    "action_ids": snapshot.action_ids,
    "occurrence_ids": snapshot.occurrence_ids,
}, sort_keys=True))
"""
    outputs = []
    for hash_seed in ("1", "77"):
        environment = dict(os.environ)
        environment["PYTHONHASHSEED"] = hash_seed
        result = subprocess.run(
            [sys.executable, "-c", script],
            check=True,
            capture_output=True,
            text=True,
            env=environment,
        )
        outputs.append(json.loads(result.stdout))

    assert outputs[0] == outputs[1]


@pytest.mark.soak
def test_million_occurrence_one_intent_skew_has_bounded_candidates_and_bytes() -> None:
    """One million unique occurrences plateau at the explicit hot/sample/window bounds."""

    authored = AuthoredIntentLedger.from_scenario(_scenario(LogonEventSpec(logon_type=3)))
    intent = authored.intent_at(IntentSection.STORYLINE, "initial-access", 0)
    execution = IntentExecutionLedger(authored)
    timestamp = datetime(2026, 8, 16, 12, tzinfo=UTC)
    first_plateau = None
    for index in range(1_000_000):
        execution.record_occurrence(
            intent.intent_id,
            SemanticOccurrenceKey(
                action_id="million-action",
                role=OccurrenceRole.DEPENDENT,
                instance_key=f"occurrence-{index}",
            ),
            timestamp,
        )
        if index == 99_999:
            first_plateau = execution.diagnostics()

    final = execution.diagnostics()
    snapshot = next(item for item in execution.snapshot() if item.intent_id == intent.intent_id)

    assert first_plateau is not None
    assert snapshot.occurrence_reference_count == 1_000_000
    assert len(snapshot.action_ids) <= 8
    assert len(snapshot.occurrence_ids) <= 8
    assert final.hot_identity_count == final.hot_identity_capacity
    assert final.retained_candidate_count == first_plateau.retained_candidate_count
    assert final.retained_bytes <= int(first_plateau.retained_bytes * 1.10)
