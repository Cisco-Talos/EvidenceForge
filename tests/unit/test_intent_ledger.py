# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Tests for the independent authored-intent ledger scaffold."""

from types import SimpleNamespace

from evidenceforge.generation.intent_ledger import AuthoredIntentLedger, IntentSection
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
