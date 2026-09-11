# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Tests for allocation-free command execution/effect planning contracts."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import textwrap
from concurrent.futures import ThreadPoolExecutor
from dataclasses import FrozenInstanceError, replace
from datetime import UTC, datetime

import pytest

from evidenceforge.events.contracts import (
    EffectOccurrenceKind,
    EffectOccurrenceOwner,
    EffectOccurrenceProvenance,
    OccurrenceRole,
    OwnedEffectOccurrencePlan,
)
from evidenceforge.generation.actions.base import ActionAnchor
from evidenceforge.generation.actions.command_effects import (
    ChildProcessEffectIntent,
    CommandEffectIntent,
    EffectActorRef,
    EffectExecutionOutcome,
    EffectKind,
    EffectOutcomeStatus,
    EffectRequirement,
    ExecutionEffectAuditCounter,
    ExecutionEffectNode,
    ExecutionEffectPlan,
    ExecutionEffectPlanError,
    ExecutionEffectPlanErrorCode,
    ExecutionEffectReconciliation,
    FileEffectAction,
    FileEffectIntent,
    NetworkEffectIntent,
    RegistryEffectAction,
    RegistryEffectIntent,
    ScannerEffectIntent,
    ScheduledTaskEffectAction,
    ScheduledTaskEffectIntent,
    ServiceEffectAction,
    ServiceEffectIntent,
    SessionEffectAction,
    SessionEffectIntent,
    TransferEffectIntent,
    UnplannedEffectFailure,
    WindowsAuditEffectIntent,
    WindowsAuditEffectKind,
)


def _anchor() -> ActionAnchor:
    return ActionAnchor(
        family="process_execution",
        stable_id="host-a:alice:2026-08-16T12:00:00Z:curl",
        source="unit_test",
    )


def test_effect_intents_are_frozen_and_validate_cardinality() -> None:
    intent = FileEffectIntent(FileEffectAction.READ, "/tmp/source.bin")

    with pytest.raises(FrozenInstanceError):
        intent.path = "/tmp/changed.bin"  # type: ignore[misc]

    with pytest.raises(ExecutionEffectPlanError) as exc_info:
        ScannerEffectIntent(tool="nmap", target="10.0.0.0/24", probe_count=0)

    assert exc_info.value.code == ExecutionEffectPlanErrorCode.INVALID_INTENT


def test_network_intent_rejects_invalid_destination_port() -> None:
    with pytest.raises(ExecutionEffectPlanError) as exc_info:
        NetworkEffectIntent(destination="db.internal", destination_port=0)

    assert exc_info.value.code == ExecutionEffectPlanErrorCode.INVALID_INTENT


@pytest.mark.parametrize(
    "intent",
    [
        ChildProcessEffectIntent("/usr/bin/gzip", "gzip /tmp/source"),
        FileEffectIntent(FileEffectAction.READ, "/tmp/source"),
        RegistryEffectIntent(RegistryEffectAction.MODIFY, r"HKCU\Software\Example"),
        NetworkEffectIntent("db.internal", 5432, service="postgresql"),
        TransferEffectIntent("scp", "/tmp/source", "host-a", "/tmp/destination"),
        ScannerEffectIntent("nmap", "10.0.0.0/24", 1_270),
        ScheduledTaskEffectIntent(ScheduledTaskEffectAction.CREATE, r"\Daily Sync"),
        SessionEffectIntent(SessionEffectAction.START, "new_credentials", "alice"),
        ServiceEffectIntent(ServiceEffectAction.INSTALL, "HealthMonitorSvc"),
        WindowsAuditEffectIntent(WindowsAuditEffectKind.ACCOUNT_CREATED, "staging-admin"),
    ],
)
def test_all_typed_intents_have_stable_semantics_and_positive_cardinality(
    intent: CommandEffectIntent,
) -> None:
    assert intent.semantic_key == intent.semantic_key
    assert intent.occurrence_cardinality > 0


def test_effect_node_identity_is_action_relative_and_order_independent() -> None:
    anchor = _anchor()
    intent = FileEffectIntent(FileEffectAction.CREATE, "/tmp/result.txt")

    first = ExecutionEffectNode.create(anchor, intent)
    repeated = ExecutionEffectNode.create(anchor, intent)
    second_instance = ExecutionEffectNode.create(anchor, intent, instance_key="retry-2")

    assert first.node_id == repeated.node_id
    assert first.node_id != second_instance.node_id
    assert first.expected_node_id(anchor.action_id) == first.node_id


def test_plan_rejects_manual_node_identity_drift() -> None:
    anchor = _anchor()
    node = ExecutionEffectNode.create(
        anchor,
        FileEffectIntent(FileEffectAction.CREATE, "/tmp/result.txt"),
    )

    with pytest.raises(ExecutionEffectPlanError) as exc_info:
        ExecutionEffectPlan(anchor=anchor, nodes=(replace(node, node_id="manual-id"),))

    assert exc_info.value.code == ExecutionEffectPlanErrorCode.UNSTABLE_NODE_ID


def test_plan_orders_dependency_and_child_actor_edges_deterministically() -> None:
    anchor = _anchor()
    prerequisite = ExecutionEffectNode.create(
        anchor,
        NetworkEffectIntent("auth.internal", 88, service="kerberos"),
        role=OccurrenceRole.PREREQUISITE,
        actor=EffectActorRef.session(),
    )
    child = ExecutionEffectNode.create(
        anchor,
        ChildProcessEffectIntent("/usr/bin/gzip", "gzip -c /tmp/source"),
    )
    network = ExecutionEffectNode.create(
        anchor,
        NetworkEffectIntent("archive.internal", 443, service="ssl"),
        actor=EffectActorRef.effect_process(child.node_id),
    )
    file_create = ExecutionEffectNode.create(
        anchor,
        FileEffectIntent(FileEffectAction.CREATE, "/tmp/archive.gz"),
        depends_on=(network.node_id,),
    )
    closure = ExecutionEffectNode.create(
        anchor,
        FileEffectIntent(FileEffectAction.DELETE, "/tmp/source"),
        role=OccurrenceRole.CLOSURE,
        depends_on=(file_create.node_id,),
    )

    forward = ExecutionEffectPlan(anchor, (child, network, prerequisite, file_create, closure))
    reversed_plan = ExecutionEffectPlan(
        anchor,
        (closure, file_create, prerequisite, network, child),
    )
    ordered_ids = [node.node_id for node in forward.ordered_nodes]

    assert ordered_ids == [node.node_id for node in reversed_plan.ordered_nodes]
    assert ordered_ids[0] == prerequisite.node_id
    assert ordered_ids.index(child.node_id) < ordered_ids.index(network.node_id)
    assert ordered_ids.index(network.node_id) < ordered_ids.index(file_create.node_id)
    assert ordered_ids.index(file_create.node_id) < ordered_ids.index(closure.node_id)
    assert forward.prerequisites == (prerequisite,)
    assert forward.dependents == (child, network, file_create)
    assert forward.closures == (closure,)


def test_plan_rejects_duplicate_nodes_and_missing_dependencies() -> None:
    anchor = _anchor()
    node = ExecutionEffectNode.create(
        anchor,
        FileEffectIntent(FileEffectAction.CREATE, "/tmp/result.txt"),
    )

    with pytest.raises(ExecutionEffectPlanError) as duplicate_exc:
        ExecutionEffectPlan(anchor, (node, node))
    assert duplicate_exc.value.code == ExecutionEffectPlanErrorCode.DUPLICATE_NODE_ID

    with pytest.raises(ExecutionEffectPlanError) as dependency_exc:
        ExecutionEffectPlan(anchor, (replace(node, depends_on=("missing-node",)),))
    assert dependency_exc.value.code == ExecutionEffectPlanErrorCode.MISSING_DEPENDENCY


def test_plan_rejects_non_process_actor_reference() -> None:
    anchor = _anchor()
    file_node = ExecutionEffectNode.create(
        anchor,
        FileEffectIntent(FileEffectAction.READ, "/tmp/source"),
    )
    network_node = ExecutionEffectNode.create(
        anchor,
        NetworkEffectIntent("upload.internal", 443, service="ssl"),
        actor=EffectActorRef.effect_process(file_node.node_id),
    )

    with pytest.raises(ExecutionEffectPlanError) as exc_info:
        ExecutionEffectPlan(anchor, (file_node, network_node))

    assert exc_info.value.code == ExecutionEffectPlanErrorCode.INVALID_ACTOR


def test_plan_rejects_cycles_and_backward_phase_edges() -> None:
    anchor = _anchor()
    first = ExecutionEffectNode.create(
        anchor,
        FileEffectIntent(FileEffectAction.READ, "/tmp/source"),
    )
    second = ExecutionEffectNode.create(
        anchor,
        FileEffectIntent(FileEffectAction.CREATE, "/tmp/result"),
        instance_key="result",
    )

    with pytest.raises(ExecutionEffectPlanError) as cycle_exc:
        ExecutionEffectPlan(
            anchor,
            (
                replace(first, depends_on=(second.node_id,)),
                replace(second, depends_on=(first.node_id,)),
            ),
        )
    assert cycle_exc.value.code == ExecutionEffectPlanErrorCode.CYCLIC_DEPENDENCY

    prerequisite = ExecutionEffectNode.create(
        anchor,
        NetworkEffectIntent("auth.internal", 88, service="kerberos"),
        role=OccurrenceRole.PREREQUISITE,
        actor=EffectActorRef.session(),
        depends_on=(first.node_id,),
    )
    with pytest.raises(ExecutionEffectPlanError) as phase_exc:
        ExecutionEffectPlan(anchor, (first, prerequisite))
    assert phase_exc.value.code == ExecutionEffectPlanErrorCode.INVALID_PHASE_EDGE


def test_prerequisite_effect_cannot_reference_unallocated_root_process() -> None:
    anchor = _anchor()
    prerequisite = ExecutionEffectNode.create(
        anchor,
        NetworkEffectIntent("auth.internal", 88, service="kerberos"),
        role=OccurrenceRole.PREREQUISITE,
    )

    with pytest.raises(ExecutionEffectPlanError) as exc_info:
        ExecutionEffectPlan(anchor, (prerequisite,))

    assert exc_info.value.code == ExecutionEffectPlanErrorCode.INVALID_ACTOR


def test_plan_summary_counts_requirements_and_occurrence_cardinality() -> None:
    anchor = _anchor()
    scan = ExecutionEffectNode.create(
        anchor,
        ScannerEffectIntent("nmap", "10.0.0.0/24", probe_count=1_270),
    )
    registry = ExecutionEffectNode.create(
        anchor,
        RegistryEffectIntent(
            RegistryEffectAction.MODIFY,
            r"HKCU\Software\Example",
            "LastRun",
        ),
        requirement=EffectRequirement.OPTIONAL,
    )
    task = ExecutionEffectNode.create(
        anchor,
        ScheduledTaskEffectIntent(ScheduledTaskEffectAction.CREATE, r"\Daily Sync"),
        requirement=EffectRequirement.EXTERNALLY_OWNED,
    )

    summary = ExecutionEffectPlan(anchor, (task, registry, scan)).summary

    assert summary.node_count == 3
    assert summary.required_count == 1
    assert summary.optional_count == 1
    assert summary.externally_owned_count == 1
    assert summary.estimated_occurrences == 1_273
    assert summary.as_dict()["estimated_occurrences"] == 1_273


def test_reconciliation_accepts_realized_suppressed_and_linked_outcomes() -> None:
    anchor = _anchor()
    required = ExecutionEffectNode.create(
        anchor,
        FileEffectIntent(FileEffectAction.CREATE, "/tmp/result"),
    )
    optional = ExecutionEffectNode.create(
        anchor,
        RegistryEffectIntent(RegistryEffectAction.MODIFY, r"HKCU\Software\Example"),
        requirement=EffectRequirement.OPTIONAL,
    )
    external = ExecutionEffectNode.create(
        anchor,
        ScheduledTaskEffectIntent(ScheduledTaskEffectAction.CREATE, r"\Daily Sync"),
        requirement=EffectRequirement.EXTERNALLY_OWNED,
    )
    plan = ExecutionEffectPlan(anchor, (external, optional, required))
    completed_at = datetime(2026, 8, 16, 12, 0, 5, tzinfo=UTC)

    reconciliation = plan.reconcile(
        (
            EffectExecutionOutcome(
                required.node_id,
                EffectOutcomeStatus.REALIZED,
                completed_at=completed_at,
            ),
            EffectExecutionOutcome(
                optional.node_id,
                EffectOutcomeStatus.SUPPRESSED,
                reason="profile roll omitted ambient registry enrichment",
            ),
            EffectExecutionOutcome(
                external.node_id,
                EffectOutcomeStatus.LINKED,
                child_action_id="authored-task-action-id",
            ),
        )
    )

    assert reconciliation.complete
    assert reconciliation.missing_required_node_ids == ()
    assert reconciliation.summary.realized_count == 1
    assert reconciliation.summary.suppressed_count == 1
    assert reconciliation.summary.linked_count == 1
    assert reconciliation.summary.complete
    assert reconciliation.summary.as_dict()["planned_count"] == 3
    assert (
        next(
            outcome.completed_at
            for outcome in reconciliation.outcomes
            if outcome.node_id == required.node_id
        )
        == completed_at
    )
    reconciliation.require_complete()


def test_reconciliation_reports_missing_unexpected_and_policy_invalid_outcomes() -> None:
    anchor = _anchor()
    required = ExecutionEffectNode.create(
        anchor,
        FileEffectIntent(FileEffectAction.CREATE, "/tmp/result"),
    )
    external = ExecutionEffectNode.create(
        anchor,
        ScheduledTaskEffectIntent(ScheduledTaskEffectAction.CREATE, r"\Daily Sync"),
        requirement=EffectRequirement.EXTERNALLY_OWNED,
    )
    plan = ExecutionEffectPlan(anchor, (required, external))

    reconciliation = plan.reconcile(
        (
            EffectExecutionOutcome(external.node_id, EffectOutcomeStatus.REALIZED),
            EffectExecutionOutcome("unexpected-node", EffectOutcomeStatus.REALIZED),
        )
    )

    assert not reconciliation.complete
    assert reconciliation.missing_node_ids == (required.node_id,)
    assert reconciliation.missing_required_node_ids == (required.node_id,)
    assert reconciliation.unexpected_node_ids == ("unexpected-node",)
    assert reconciliation.invalid_outcome_node_ids == (external.node_id,)
    assert reconciliation.summary.missing_count == 1
    assert reconciliation.summary.unexpected_count == 1
    assert reconciliation.summary.invalid_count == 1
    with pytest.raises(ExecutionEffectPlanError) as exc_info:
        reconciliation.require_complete()
    assert exc_info.value.code == ExecutionEffectPlanErrorCode.RECONCILIATION_INCOMPLETE


def test_optional_effects_require_explicit_suppression_outcomes() -> None:
    anchor = _anchor()
    optional = ExecutionEffectNode.create(
        anchor,
        RegistryEffectIntent(RegistryEffectAction.MODIFY, r"HKCU\Software\Example"),
        requirement=EffectRequirement.OPTIONAL,
    )

    reconciliation = ExecutionEffectPlan(anchor, (optional,)).reconcile(())

    assert not reconciliation.complete
    assert reconciliation.missing_node_ids == (optional.node_id,)
    assert reconciliation.missing_required_node_ids == ()


def test_outcome_contract_rejects_implicit_links_and_suppression() -> None:
    with pytest.raises(ExecutionEffectPlanError) as linked_exc:
        EffectExecutionOutcome("node-a", EffectOutcomeStatus.LINKED)
    assert linked_exc.value.code == ExecutionEffectPlanErrorCode.INVALID_OUTCOME

    with pytest.raises(ExecutionEffectPlanError) as suppressed_exc:
        EffectExecutionOutcome("node-a", EffectOutcomeStatus.SUPPRESSED)
    assert suppressed_exc.value.code == ExecutionEffectPlanErrorCode.INVALID_OUTCOME


def test_reconciliation_rejects_duplicate_outcomes() -> None:
    anchor = _anchor()
    node = ExecutionEffectNode.create(
        anchor,
        FileEffectIntent(FileEffectAction.CREATE, "/tmp/result"),
    )
    outcome = EffectExecutionOutcome(node.node_id, EffectOutcomeStatus.REALIZED)

    with pytest.raises(ExecutionEffectPlanError) as exc_info:
        ExecutionEffectPlan(anchor, (node,)).reconcile((outcome, outcome))

    assert exc_info.value.code == ExecutionEffectPlanErrorCode.DUPLICATE_OUTCOME


def test_scanner_reconciliation_requires_exact_canonical_probe_cardinality() -> None:
    anchor = _anchor()
    scanner = ExecutionEffectNode.create(
        anchor,
        ScannerEffectIntent("nmap", "10.0.0.0/24", probe_count=254),
    )
    plan = ExecutionEffectPlan(anchor, (scanner,))

    exact = plan.reconcile(
        (
            EffectExecutionOutcome(
                scanner.node_id,
                EffectOutcomeStatus.REALIZED,
                canonical_occurrence_count=254,
            ),
        )
    )
    missing_count = plan.reconcile(
        (EffectExecutionOutcome(scanner.node_id, EffectOutcomeStatus.REALIZED),)
    )
    wrong_count = plan.reconcile(
        (
            EffectExecutionOutcome(
                scanner.node_id,
                EffectOutcomeStatus.REALIZED,
                canonical_occurrence_count=253,
            ),
        )
    )

    assert exact.complete
    assert exact.summary.realized_occurrence_count == 254
    assert missing_count.invalid_outcome_node_ids == (scanner.node_id,)
    assert wrong_count.invalid_outcome_node_ids == (scanner.node_id,)


@pytest.mark.parametrize(
    "intent",
    [
        ChildProcessEffectIntent("/usr/bin/gzip", "gzip /tmp/source", occurrence_cardinality=2),
        FileEffectIntent(FileEffectAction.CREATE, "/tmp/result", occurrence_cardinality=2),
        RegistryEffectIntent(
            RegistryEffectAction.MODIFY,
            r"HKCU\Software\Example",
            occurrence_cardinality=2,
        ),
        NetworkEffectIntent("db.internal", 5432, occurrence_cardinality=2),
        TransferEffectIntent(
            "scp",
            "/tmp/source",
            "host-a",
            "/tmp/destination",
            occurrence_cardinality=2,
        ),
        ScannerEffectIntent("nmap", "10.0.0.0/24", probe_count=2),
        ScheduledTaskEffectIntent(
            ScheduledTaskEffectAction.CREATE,
            r"\Daily Sync",
            occurrence_cardinality=2,
        ),
        SessionEffectIntent(
            SessionEffectAction.START,
            "new_credentials",
            "alice",
            occurrence_cardinality=2,
        ),
        ServiceEffectIntent(
            ServiceEffectAction.INSTALL,
            "HealthMonitorSvc",
            occurrence_cardinality=2,
        ),
        WindowsAuditEffectIntent(
            WindowsAuditEffectKind.ACCOUNT_CREATED,
            "staging-admin",
            occurrence_cardinality=2,
        ),
    ],
    ids=lambda intent: intent.kind.value,
)
@pytest.mark.parametrize(
    ("requirement", "status"),
    [
        (EffectRequirement.REQUIRED, EffectOutcomeStatus.REALIZED),
        (EffectRequirement.REQUIRED, EffectOutcomeStatus.LINKED),
        (EffectRequirement.EXTERNALLY_OWNED, EffectOutcomeStatus.LINKED),
    ],
    ids=("required-realized", "required-linked", "external-linked"),
)
def test_multi_occurrence_required_and_external_effects_require_exact_counts(
    intent: CommandEffectIntent,
    requirement: EffectRequirement,
    status: EffectOutcomeStatus,
) -> None:
    anchor = _anchor()
    node = ExecutionEffectNode.create(anchor, intent, requirement=requirement)
    plan = ExecutionEffectPlan(anchor, (node,))
    child_action_id = "linked-action" if status == EffectOutcomeStatus.LINKED else ""

    missing_count = plan.reconcile(
        (
            EffectExecutionOutcome(
                node.node_id,
                status,
                child_action_id=child_action_id,
            ),
        )
    )
    wrong_count = plan.reconcile(
        (
            EffectExecutionOutcome(
                node.node_id,
                status,
                child_action_id=child_action_id,
                canonical_occurrence_count=1,
            ),
        )
    )
    exact_count = plan.reconcile(
        (
            EffectExecutionOutcome(
                node.node_id,
                status,
                child_action_id=child_action_id,
                canonical_occurrence_count=2,
            ),
        )
    )

    assert missing_count.invalid_outcome_node_ids == (node.node_id,)
    assert wrong_count.invalid_outcome_node_ids == (node.node_id,)
    assert exact_count.complete


def test_failed_outcomes_report_bounded_actionable_reasons() -> None:
    anchor = _anchor()
    node = ExecutionEffectNode.create(
        anchor,
        FileEffectIntent(FileEffectAction.CREATE, "/tmp/result"),
    )
    outcome = EffectExecutionOutcome(
        node.node_id,
        EffectOutcomeStatus.FAILED,
        reason="disk quota rejected the canonical file creation\n" + ("detail " * 80),
    )
    reconciliation = ExecutionEffectPlan(anchor, (node,)).reconcile((outcome,))

    assert len(outcome.reason) == 160
    assert "\n" not in outcome.reason
    assert reconciliation.failed_outcome_node_ids == (node.node_id,)
    assert reconciliation.invalid_outcome_node_ids == ()
    assert reconciliation.summary.failed_count == 1
    with pytest.raises(ExecutionEffectPlanError) as exc_info:
        reconciliation.require_complete()
    message = str(exc_info.value)
    assert "failed=" in message
    assert node.node_id in message
    assert "disk quota rejected the canonical file creation" in message
    assert len(message) < 400


def test_unplanned_effect_failures_report_kind_and_reason_without_fake_node_ids() -> None:
    failure = UnplannedEffectFailure(
        effect_kind=EffectKind.SCANNER,
        canonical_occurrence_count=3,
        reason="nmap emitted probes for an explicit no-effect plan",
    )
    reconciliation = ExecutionEffectPlan(_anchor()).reconcile(
        (),
        unplanned_failures=(failure,),
    )

    assert reconciliation.unexpected_node_ids == ()
    assert reconciliation.summary.unplanned_failure_count == 1
    with pytest.raises(ExecutionEffectPlanError) as exc_info:
        reconciliation.require_complete()
    message = str(exc_info.value)
    assert "unplanned=scanner count=3" in message
    assert failure.reason in message
    assert "unplanned-scanner:" not in message


def test_execution_effect_audit_counter_retains_only_bounded_totals() -> None:
    anchor = _anchor()
    scanner = ExecutionEffectNode.create(
        anchor,
        ScannerEffectIntent("nmap", "10.0.0.0/24", probe_count=254),
    )
    realized = ExecutionEffectPlan(anchor, (scanner,)).reconcile(
        (
            EffectExecutionOutcome(
                scanner.node_id,
                EffectOutcomeStatus.REALIZED,
                canonical_occurrence_count=254,
            ),
        )
    )
    no_effect = ExecutionEffectPlan(anchor).reconcile(())
    counter = ExecutionEffectAuditCounter()

    counter.record(realized)
    counter.record(no_effect)
    snapshot = counter.snapshot()

    assert snapshot.plan_count == 2
    assert snapshot.no_effect_plan_count == 1
    assert snapshot.planned_node_count == 1
    assert snapshot.planned_effect_occurrence_count == 254
    assert snapshot.realized_node_count == 1
    assert snapshot.realized_effect_occurrence_count == 254
    assert snapshot.incomplete_reconciliation_count == 0
    assert snapshot.complete
    assert len(snapshot.reconciliation_digest) == 64
    assert set(snapshot.as_dict()) == {
        *ExecutionEffectAuditCounter._KEYS,
        "complete",
        "effect_occurrence_digest",
        "reconciliation_digest",
    }


def test_execution_effect_audit_matches_independent_file_publication_denominator() -> None:
    anchor = _anchor()
    file_node = ExecutionEffectNode.create(
        anchor,
        FileEffectIntent(FileEffectAction.CREATE, "/tmp/result"),
    )
    reconciliation = ExecutionEffectPlan(anchor, (file_node,)).reconcile(
        (
            EffectExecutionOutcome(
                file_node.node_id,
                EffectOutcomeStatus.REALIZED,
                canonical_occurrence_count=1,
            ),
        )
    )
    provenance = EffectOccurrenceProvenance.planned(
        kind=EffectOccurrenceKind.FILE,
        root_action_id=anchor.action_id,
        plan_action_id=anchor.action_id,
        node_id=file_node.node_id,
        occurrence_ordinal=0,
    )
    counter = ExecutionEffectAuditCounter()

    counter.record_published_effect_occurrence(
        provenance,
        effect_kind=EffectOccurrenceKind.FILE,
    )
    assert not counter.snapshot().complete
    counter.record(reconciliation)

    snapshot = counter.snapshot()
    assert snapshot.complete
    assert snapshot.reconciled_effect_occurrence_count == 1
    assert snapshot.published_effect_occurrence_count == 1
    assert snapshot.effect_publication_mismatch_count == 0
    assert snapshot.unprovenanced_effect_occurrence_count == 0


def test_execution_effect_audit_reconciles_bounded_family_owned_root() -> None:
    plan = OwnedEffectOccurrencePlan(
        owner=EffectOccurrenceOwner.SMB_PROTOCOL_FILE_PHASE,
        kind=EffectOccurrenceKind.FILE,
        root_action_id="smb-action-1",
        instance_key="read:share/report.csv",
        occurrence_count=2,
    )
    counter = ExecutionEffectAuditCounter()

    counter.record_owned_effect_plan(plan)
    assert not counter.snapshot().complete
    for ordinal in reversed(range(plan.occurrence_count)):
        counter.record_published_effect_occurrence(
            plan.provenance(ordinal),
            effect_kind=EffectOccurrenceKind.FILE,
        )

    snapshot = counter.snapshot()
    assert snapshot.complete
    assert snapshot.owned_effect_plan_count == 1
    assert snapshot.owned_effect_expected_occurrence_count == 2
    assert snapshot.owned_effect_published_occurrence_count == 2
    assert snapshot.reconciled_effect_occurrence_count == 2
    assert snapshot.published_effect_occurrence_count == 2
    assert snapshot.exempt_effect_occurrence_count == 0


def test_execution_effect_audit_rejects_missing_excess_and_unregistered_owned_roots() -> None:
    plan = OwnedEffectOccurrencePlan(
        owner=EffectOccurrenceOwner.BASELINE_DHCP_REGISTRY_ROOT,
        kind=EffectOccurrenceKind.REGISTRY,
        root_action_id="dhcp-action-1",
        instance_key="lease-registry",
        occurrence_count=1,
    )

    missing = ExecutionEffectAuditCounter()
    missing.record_owned_effect_plan(plan)
    assert not missing.snapshot().complete

    excess = ExecutionEffectAuditCounter()
    excess.record_owned_effect_plan(plan)
    for _ in range(2):
        excess.record_published_effect_occurrence(
            plan.provenance(0),
            effect_kind=EffectOccurrenceKind.REGISTRY,
        )
    assert not excess.snapshot().complete

    unregistered = ExecutionEffectAuditCounter()
    unregistered.record_published_effect_occurrence(
        plan.provenance(0),
        effect_kind=EffectOccurrenceKind.REGISTRY,
    )
    assert not unregistered.snapshot().complete


def test_execution_effect_audit_rejects_legacy_exempt_publication() -> None:
    counter = ExecutionEffectAuditCounter()
    counter.record_published_effect_occurrence(
        EffectOccurrenceProvenance.exempt(
            kind=EffectOccurrenceKind.FILE,
            reason="legacy-only",
            root_action_id="legacy-root",
        ),
        effect_kind=EffectOccurrenceKind.FILE,
    )

    snapshot = counter.snapshot()
    assert snapshot.exempt_effect_occurrence_count == 1
    assert not snapshot.complete
    with pytest.raises(ExecutionEffectPlanError):
        snapshot.require_complete()


def test_owned_effect_occurrence_plan_has_stable_bounded_identity() -> None:
    plan = OwnedEffectOccurrencePlan(
        owner=EffectOccurrenceOwner.HTTP_UPLOAD_LOCAL_READ,
        kind=EffectOccurrenceKind.FILE,
        root_action_id="http-upload-1",
        instance_key="source-read",
        occurrence_count=1,
    )
    assert plan == replace(plan)
    assert plan.provenance(0).reconciliation_key
    with pytest.raises(ValueError, match="outside its plan"):
        plan.provenance(1)
    with pytest.raises(ValueError, match="positive integer"):
        replace(plan, occurrence_count=0)
    with pytest.raises(ValueError, match="not stable"):
        replace(plan, node_id="forged")


def test_owned_effect_occurrence_owner_contract_is_finite_and_exact() -> None:
    """New family-owned roots require an intentional contract and policy update."""

    assert {owner.value for owner in EffectOccurrenceOwner} == {
        "http_upload_local_read",
        "baseline_dhcp_registry_root",
        "baseline_ambient_file_root",
        "baseline_system_process_registry_root",
        "smb_protocol_file_phase",
        "email_attachment_file_root",
        "http_multipart_local_read",
    }


def test_execution_effect_audit_rejects_unprovenanced_effect_publication() -> None:
    counter = ExecutionEffectAuditCounter()

    counter.record_published_effect_occurrence(
        None,
        effect_kind=EffectOccurrenceKind.FILE,
    )

    snapshot = counter.snapshot()
    assert snapshot.unprovenanced_effect_occurrence_count == 1
    assert not snapshot.complete
    with pytest.raises(ExecutionEffectPlanError):
        snapshot.require_complete()


def test_execution_effect_audit_exposes_missing_required_and_cardinality_truth() -> None:
    anchor = _anchor()
    scanner = ExecutionEffectNode.create(
        anchor,
        ScannerEffectIntent("nmap", "10.0.0.0/24", probe_count=254),
    )
    plan = ExecutionEffectPlan(anchor, (scanner,))
    missing = plan.reconcile(())
    wrong_cardinality = plan.reconcile(
        (
            EffectExecutionOutcome(
                scanner.node_id,
                EffectOutcomeStatus.REALIZED,
                canonical_occurrence_count=253,
            ),
        )
    )
    counter = ExecutionEffectAuditCounter()

    counter.record(missing)
    counter.record(wrong_cardinality)
    snapshot = counter.snapshot()

    assert snapshot.missing_node_count == 1
    assert snapshot.missing_required_node_count == 1
    assert snapshot.cardinality_mismatch_count == 1
    assert snapshot.invalid_outcome_node_count == 1
    assert not snapshot.complete
    with pytest.raises(ExecutionEffectPlanError) as exc_info:
        snapshot.require_complete()
    assert exc_info.value.code == ExecutionEffectPlanErrorCode.RECONCILIATION_INCOMPLETE


def test_execution_effect_audit_digest_is_reconciliation_order_independent() -> None:
    anchor = _anchor()
    required = ExecutionEffectNode.create(
        anchor,
        FileEffectIntent(FileEffectAction.CREATE, "/tmp/result"),
    )
    realized = ExecutionEffectPlan(anchor, (required,)).reconcile(
        (EffectExecutionOutcome(required.node_id, EffectOutcomeStatus.REALIZED),)
    )
    no_effect = ExecutionEffectPlan(anchor).reconcile(())

    forward = ExecutionEffectAuditCounter()
    reverse = ExecutionEffectAuditCounter()
    for reconciliation in (realized, no_effect):
        forward.record(reconciliation)
    for reconciliation in (no_effect, realized):
        reverse.record(reconciliation)

    assert forward.snapshot() == reverse.snapshot()


def test_execution_effect_audit_digest_is_worker_count_independent() -> None:
    """Concurrent 1/4/8-worker publication and reconciliation retain exact truth."""

    rows = []
    for ordinal in range(256):
        anchor = ActionAnchor(
            family="process_execution",
            stable_id=f"worker-digest:{ordinal}",
            source="unit_test",
        )
        node = ExecutionEffectNode.create(
            anchor,
            FileEffectIntent(FileEffectAction.CREATE, f"/tmp/result-{ordinal}"),
        )
        reconciliation = ExecutionEffectPlan(anchor, (node,)).reconcile(
            (
                EffectExecutionOutcome(
                    node.node_id,
                    EffectOutcomeStatus.REALIZED,
                    canonical_occurrence_count=1,
                ),
            )
        )
        provenance = EffectOccurrenceProvenance.planned(
            kind=EffectOccurrenceKind.FILE,
            root_action_id=anchor.action_id,
            plan_action_id=anchor.action_id,
            node_id=node.node_id,
            occurrence_ordinal=0,
        )
        rows.append((reconciliation, provenance))

    snapshots = []
    for worker_count in (1, 4, 8):
        counter = ExecutionEffectAuditCounter()

        def record(
            row: tuple[ExecutionEffectReconciliation, EffectOccurrenceProvenance],
            *,
            audit: ExecutionEffectAuditCounter = counter,
        ) -> None:
            reconciliation, provenance = row
            audit.record_published_effect_occurrence(
                provenance,
                effect_kind=EffectOccurrenceKind.FILE,
            )
            audit.record(reconciliation)

        with ThreadPoolExecutor(max_workers=worker_count) as executor:
            tuple(executor.map(record, reversed(rows)))
        snapshots.append(counter.snapshot())

    assert snapshots[0] == snapshots[1] == snapshots[2]
    assert snapshots[0].complete
    assert snapshots[0].published_effect_occurrence_count == 256


def test_execution_effect_audit_digest_ignores_python_hash_seed() -> None:
    """Audit digests are stable across interpreter hash randomization."""

    script = textwrap.dedent(
        """
        import json
        from evidenceforge.events.contracts import EffectOccurrenceKind, EffectOccurrenceProvenance
        from evidenceforge.generation.actions.base import ActionAnchor
        from evidenceforge.generation.actions.command_effects import (
            EffectExecutionOutcome,
            EffectOutcomeStatus,
            ExecutionEffectAuditCounter,
            ExecutionEffectNode,
            ExecutionEffectPlan,
            FileEffectAction,
            FileEffectIntent,
        )

        counter = ExecutionEffectAuditCounter()
        for ordinal_text in {"7", "3", "11", "1", "5"}:
            ordinal = int(ordinal_text)
            anchor = ActionAnchor(
                family="process_execution",
                stable_id=f"hash-seed:{ordinal}",
                source="subprocess_test",
            )
            node = ExecutionEffectNode.create(
                anchor,
                FileEffectIntent(FileEffectAction.CREATE, f"/tmp/result-{ordinal}"),
            )
            counter.record_published_effect_occurrence(
                EffectOccurrenceProvenance.planned(
                    kind=EffectOccurrenceKind.FILE,
                    root_action_id=anchor.action_id,
                    plan_action_id=anchor.action_id,
                    node_id=node.node_id,
                    occurrence_ordinal=0,
                ),
                effect_kind=EffectOccurrenceKind.FILE,
            )
            counter.record(
                ExecutionEffectPlan(anchor, (node,)).reconcile(
                    (EffectExecutionOutcome(
                        node.node_id,
                        EffectOutcomeStatus.REALIZED,
                        canonical_occurrence_count=1,
                    ),)
                )
            )
        print(json.dumps(counter.snapshot().as_dict(), sort_keys=True))
        """
    )
    outputs = []
    for seed in ("1", "77"):
        result = subprocess.run(
            [sys.executable, "-c", script],
            check=True,
            capture_output=True,
            text=True,
            env={**os.environ, "PYTHONHASHSEED": seed},
        )
        outputs.append(json.loads(result.stdout))

    assert outputs[0] == outputs[1]


def test_execution_effect_audit_empty_plan_digest_ignores_root_identity() -> None:
    """No-effect roots cannot make the effect-only digest renderer-dependent."""

    first = ExecutionEffectPlan(_anchor()).reconcile(())
    second = ExecutionEffectPlan(
        ActionAnchor(
            family="process_execution",
            stable_id="same-canonical-process-with-a-different-source-visible-anchor",
            source="unit_test",
        )
    ).reconcile(())
    first_counter = ExecutionEffectAuditCounter()
    second_counter = ExecutionEffectAuditCounter()

    first_counter.record(first)
    second_counter.record(second)

    assert first_counter.snapshot() == second_counter.snapshot()


def test_execution_effect_audit_records_duplicate_outcome_rejection() -> None:
    anchor = _anchor()
    required = ExecutionEffectNode.create(
        anchor,
        FileEffectIntent(FileEffectAction.CREATE, "/tmp/result"),
    )
    outcome = EffectExecutionOutcome(required.node_id, EffectOutcomeStatus.REALIZED)
    counter = ExecutionEffectAuditCounter()

    with pytest.raises(ExecutionEffectPlanError) as exc_info:
        ExecutionEffectPlan(anchor, (required,)).reconcile((outcome, outcome))
    counter.record_rejected_outcomes(exc_info.value)

    snapshot = counter.snapshot()
    assert snapshot.duplicate_outcome_count == 1
    assert not snapshot.complete
