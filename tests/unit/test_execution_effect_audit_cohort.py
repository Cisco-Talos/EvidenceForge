# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Atomic prepared action-cohort coverage for the execution-effect audit."""

from __future__ import annotations

from collections import Counter
from copy import copy
from dataclasses import replace
from datetime import datetime, timedelta, tzinfo
from threading import Thread

import pytest

from evidenceforge.events.contracts import (
    EffectOccurrenceKind,
    EffectOccurrenceOwner,
    EffectOccurrenceProvenance,
    OwnedEffectOccurrencePlan,
)
from evidenceforge.generation.actions.base import ActionAnchor
from evidenceforge.generation.actions.command_effects import (
    EffectExecutionOutcome,
    EffectOutcomeStatus,
    EffectRequirement,
    ExecutionEffectAuditCohortEntry,
    ExecutionEffectAuditCounter,
    ExecutionEffectNode,
    ExecutionEffectPlan,
    ExecutionEffectPlanError,
    FileEffectAction,
    FileEffectIntent,
    RegistryEffectAction,
    RegistryEffectIntent,
)

_ROOT_ACTION_ID = "action-cohort-root"


def _effect_entry(
    stable_id: str,
    *,
    kind: EffectOccurrenceKind = EffectOccurrenceKind.FILE,
    occurrence_count: int = 1,
    report_occurrence_count: bool = True,
    completed_at: datetime | None = None,
) -> tuple[ExecutionEffectAuditCohortEntry, tuple[EffectOccurrenceProvenance, ...]]:
    anchor = ActionAnchor(
        family="process_execution",
        stable_id=stable_id,
        source="unit_test",
    )
    if kind == EffectOccurrenceKind.FILE:
        intent = FileEffectIntent(
            FileEffectAction.CREATE,
            f"/tmp/{stable_id}",
            occurrence_cardinality=occurrence_count,
        )
    else:
        intent = RegistryEffectIntent(
            RegistryEffectAction.MODIFY,
            rf"HKLM\Software\EvidenceForge\{stable_id}",
            occurrence_cardinality=occurrence_count,
        )
    node = ExecutionEffectNode.create(anchor, intent)
    plan = ExecutionEffectPlan(anchor, (node,))
    reconciliation = plan.reconcile(
        (
            EffectExecutionOutcome(
                node.node_id,
                EffectOutcomeStatus.REALIZED,
                completed_at=completed_at,
                canonical_occurrence_count=(occurrence_count if report_occurrence_count else None),
            ),
        )
    )
    entry = ExecutionEffectAuditCohortEntry(plan, reconciliation)
    provenances = tuple(
        EffectOccurrenceProvenance.planned(
            kind=kind,
            root_action_id=_ROOT_ACTION_ID,
            plan_action_id=plan.action_id,
            node_id=node.node_id,
            occurrence_ordinal=ordinal,
        )
        for ordinal in range(occurrence_count)
    )
    return entry, provenances


def _owned_plan(*, occurrence_count: int = 2) -> OwnedEffectOccurrencePlan:
    return OwnedEffectOccurrencePlan(
        owner=EffectOccurrenceOwner.HTTP_UPLOAD_LOCAL_READ,
        kind=EffectOccurrenceKind.FILE,
        root_action_id=_ROOT_ACTION_ID,
        instance_key="multipart-local-read",
        occurrence_count=occurrence_count,
    )


def _commit(counter: ExecutionEffectAuditCounter, preparation: object) -> object:
    with counter.claimed_action_cohort(preparation) as claimed:
        assert claimed.receipt is None
        receipt = claimed.commit_no_fail()
        assert claimed.receipt is receipt
        return receipt


def test_empty_cohort_is_invalid_but_zero_node_plan_is_a_valid_member() -> None:
    counter = ExecutionEffectAuditCounter()
    initial = counter.snapshot()

    with pytest.raises(ExecutionEffectPlanError, match="cannot be empty"):
        counter.prepare_action_cohort(_ROOT_ACTION_ID, ())
    assert counter.snapshot() == initial
    assert counter.action_cohort_preparation_census().active == 0

    plan = ExecutionEffectPlan(ActionAnchor("process_execution", "zero-node", source="unit_test"))
    entry = ExecutionEffectAuditCohortEntry(plan, plan.reconcile(()))
    preparation = counter.prepare_action_cohort(_ROOT_ACTION_ID, (entry,))

    assert counter.snapshot() == initial
    assert counter.action_cohort_preparation_census().prepared == 1
    assert counter.authenticates_action_cohort_preparation(
        preparation,
        root_action_id=_ROOT_ACTION_ID,
        entries=(entry,),
        owned_plans=(),
        published_provenances=(),
    )
    assert not counter.authenticates_action_cohort_preparation(
        preparation,
        entries=(replace(entry),),
    )
    receipt = _commit(counter, preparation)

    snapshot = counter.snapshot()
    assert snapshot.complete
    assert snapshot.plan_count == 1
    assert snapshot.no_effect_plan_count == 1
    assert preparation.committed
    assert counter.action_cohort_preparation_census().active == 0
    assert counter.authenticates_action_cohort_receipt(
        receipt,
        preparation=preparation,
        root_action_id=_ROOT_ACTION_ID,
        entries=(entry,),
        owned_plans=(),
        published_provenances=(),
    )


def test_owned_plan_only_cohort_supports_multipart_publication() -> None:
    counter = ExecutionEffectAuditCounter()
    plan = _owned_plan()
    provenances = tuple(plan.provenance(ordinal) for ordinal in reversed(range(2)))

    preparation = counter.prepare_action_cohort(
        _ROOT_ACTION_ID,
        (),
        owned_plans=(plan,),
        published_provenances=provenances,
    )
    assert counter.snapshot().owned_effect_plan_count == 0
    receipt = _commit(counter, preparation)

    snapshot = counter.snapshot()
    assert snapshot.complete
    assert snapshot.plan_count == 0
    assert snapshot.owned_effect_plan_count == 1
    assert snapshot.owned_effect_expected_occurrence_count == 2
    assert snapshot.owned_effect_published_occurrence_count == 2
    assert counter.authenticates_action_cohort_receipt(
        receipt,
        preparation=preparation,
        owned_plans=(plan,),
        published_provenances=provenances,
    )


def test_preparation_capacity_counts_claimed_entries_and_reopens_after_cleanup() -> None:
    counter = ExecutionEffectAuditCounter(action_cohort_preparation_capacity=2)
    entry, provenances = _effect_entry("bounded-preparations")
    first = counter.prepare_action_cohort(
        _ROOT_ACTION_ID,
        (entry,),
        published_provenances=provenances,
    )
    second = counter.prepare_action_cohort(
        _ROOT_ACTION_ID,
        (entry,),
        published_provenances=provenances,
    )
    initial = counter.snapshot()

    census = counter.action_cohort_preparation_census()
    assert census.prepared == 2
    assert census.claimed == 0
    assert census.active == census.capacity == 2
    assert census.retained_members > 0
    assert census.retained_bytes > 0
    with pytest.raises(ExecutionEffectPlanError, match=r"capacity \(2\) is exhausted"):
        counter.prepare_action_cohort(
            _ROOT_ACTION_ID,
            (entry,),
            published_provenances=provenances,
        )
    assert counter.snapshot() == initial
    assert counter.action_cohort_preparation_census() == census

    with counter.claimed_action_cohort(first) as claimed:
        claimed_census = counter.action_cohort_preparation_census()
        assert claimed_census.prepared == 1
        assert claimed_census.claimed == 1
        assert claimed_census.active == claimed_census.capacity == 2
        with pytest.raises(ExecutionEffectPlanError, match=r"capacity \(2\) is exhausted"):
            counter.prepare_action_cohort(
                _ROOT_ACTION_ID,
                (entry,),
                published_provenances=provenances,
            )
        claimed.commit_no_fail()

    replacement = counter.prepare_action_cohort(
        _ROOT_ACTION_ID,
        (entry,),
        published_provenances=provenances,
    )
    assert counter.action_cohort_preparation_census().active == 2
    counter.cancel_action_cohort(second)
    counter.cancel_action_cohort(replacement)
    final_census = counter.action_cohort_preparation_census()
    assert final_census.active == 0
    assert final_census.retained_members == 0
    assert final_census.retained_bytes == 0


@pytest.mark.parametrize(
    "capacity_name",
    (
        "action_cohort_preparation_capacity",
        "action_cohort_member_capacity",
        "action_cohort_byte_capacity",
        "action_cohort_retained_member_capacity",
        "action_cohort_retained_byte_capacity",
    ),
)
@pytest.mark.parametrize("capacity", (0, -1, True))
def test_all_cohort_capacities_must_be_positive_integers(
    capacity_name: str,
    capacity: object,
) -> None:
    with pytest.raises(ValueError, match="must be a positive integer"):
        ExecutionEffectAuditCounter(**{capacity_name: capacity})  # type: ignore[arg-type]


def test_per_cohort_member_byte_and_pre_expansion_caps_reject_without_residue(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    entry, provenances = _effect_entry("per-cohort-cap")
    probe = ExecutionEffectAuditCounter()
    measured = probe.prepare_action_cohort(
        _ROOT_ACTION_ID,
        (entry,),
        published_provenances=provenances,
    )
    usage = probe.action_cohort_preparation_census()
    probe.cancel_action_cohort(measured)

    member_bounded = ExecutionEffectAuditCounter(
        action_cohort_member_capacity=usage.retained_members - 1,
    )
    with pytest.raises(ExecutionEffectPlanError, match="cohort member capacity"):
        member_bounded.prepare_action_cohort(
            _ROOT_ACTION_ID,
            (entry,),
            published_provenances=provenances,
        )
    assert member_bounded.action_cohort_preparation_census().retained_members == 0

    owned_plan = _owned_plan(occurrence_count=1)
    owned_provenances = (owned_plan.provenance(0),)
    owned_member_bounded = ExecutionEffectAuditCounter(action_cohort_member_capacity=1)
    with pytest.raises(ExecutionEffectPlanError, match="cohort member capacity"):
        owned_member_bounded.prepare_action_cohort(
            _ROOT_ACTION_ID,
            (),
            owned_plans=(owned_plan,),
            published_provenances=owned_provenances,
        )
    owned_census = owned_member_bounded.action_cohort_preparation_census()
    assert owned_census.active == 0
    assert owned_census.retained_members == 0
    assert owned_census.retained_bytes == 0

    exact_owned_boundary = ExecutionEffectAuditCounter(action_cohort_member_capacity=2)
    exact_preparation = exact_owned_boundary.prepare_action_cohort(
        _ROOT_ACTION_ID,
        (),
        owned_plans=(owned_plan,),
        published_provenances=owned_provenances,
    )
    _commit(exact_owned_boundary, exact_preparation)
    assert exact_owned_boundary.action_cohort_preparation_census().active == 0
    assert exact_owned_boundary.snapshot().complete

    byte_bounded = ExecutionEffectAuditCounter(
        action_cohort_byte_capacity=usage.retained_bytes - 1,
    )
    with pytest.raises(ExecutionEffectPlanError, match="cohort byte capacity"):
        byte_bounded.prepare_action_cohort(
            _ROOT_ACTION_ID,
            (entry,),
            published_provenances=provenances,
        )
    assert byte_bounded.action_cohort_preparation_census().retained_bytes == 0

    expansive_plan = _owned_plan(occurrence_count=33)

    def forbidden_expansion(_self: object, _ordinal: int) -> EffectOccurrenceProvenance:
        raise AssertionError("member preflight must reject before provenance expansion")

    monkeypatch.setattr(OwnedEffectOccurrencePlan, "provenance", forbidden_expansion)
    expansion_bounded = ExecutionEffectAuditCounter(action_cohort_member_capacity=32)
    with pytest.raises(ExecutionEffectPlanError, match="occurrence expansion"):
        expansion_bounded.prepare_action_cohort(
            _ROOT_ACTION_ID,
            (),
            owned_plans=(expansive_plan,),
        )
    expansion_census = expansion_bounded.action_cohort_preparation_census()
    assert expansion_census.active == 0
    assert expansion_census.retained_members == 0
    assert expansion_census.retained_bytes == 0


def test_aggregate_member_and_byte_caps_count_claims_then_reopen_after_cleanup() -> None:
    entry, provenances = _effect_entry("aggregate-cap")
    probe = ExecutionEffectAuditCounter()
    measured = probe.prepare_action_cohort(
        _ROOT_ACTION_ID,
        (entry,),
        published_provenances=provenances,
    )
    usage = probe.action_cohort_preparation_census()
    probe.cancel_action_cohort(measured)

    member_bounded = ExecutionEffectAuditCounter(
        action_cohort_preparation_capacity=2,
        action_cohort_retained_member_capacity=usage.retained_members,
    )
    first = member_bounded.prepare_action_cohort(
        _ROOT_ACTION_ID,
        (entry,),
        published_provenances=provenances,
    )
    with member_bounded.claimed_action_cohort(first) as claimed:
        claimed_census = member_bounded.action_cohort_preparation_census()
        assert claimed_census.claimed == 1
        assert claimed_census.retained_members == usage.retained_members
        with pytest.raises(ExecutionEffectPlanError, match="aggregate retained-member"):
            member_bounded.prepare_action_cohort(
                _ROOT_ACTION_ID,
                (entry,),
                published_provenances=provenances,
            )
        claimed.commit_no_fail()
    replacement = member_bounded.prepare_action_cohort(
        _ROOT_ACTION_ID,
        (entry,),
        published_provenances=provenances,
    )
    member_bounded.cancel_action_cohort(replacement)
    assert member_bounded.action_cohort_preparation_census().retained_members == 0

    byte_bounded = ExecutionEffectAuditCounter(
        action_cohort_preparation_capacity=2,
        action_cohort_retained_byte_capacity=usage.retained_bytes,
    )
    first = byte_bounded.prepare_action_cohort(
        _ROOT_ACTION_ID,
        (entry,),
        published_provenances=provenances,
    )
    with pytest.raises(ExecutionEffectPlanError, match="aggregate retained-byte"):
        byte_bounded.prepare_action_cohort(
            _ROOT_ACTION_ID,
            (entry,),
            published_provenances=provenances,
        )
    byte_bounded.cancel_action_cohort(first)
    replacement = byte_bounded.prepare_action_cohort(
        _ROOT_ACTION_ID,
        (entry,),
        published_provenances=provenances,
    )
    byte_bounded.cancel_action_cohort(replacement)
    final_census = byte_bounded.action_cohort_preparation_census()
    assert final_census.active == 0
    assert final_census.retained_bytes == 0


def test_cohort_delta_matches_direct_paths_and_is_commutative() -> None:
    file_entry, file_provenances = _effect_entry("file", occurrence_count=2)
    registry_entry, registry_provenances = _effect_entry(
        "registry",
        kind=EffectOccurrenceKind.REGISTRY,
    )
    entries = (file_entry, registry_entry)
    provenances = file_provenances + registry_provenances

    forward = ExecutionEffectAuditCounter()
    forward_preparation = forward.prepare_action_cohort(
        _ROOT_ACTION_ID,
        entries,
        published_provenances=provenances,
    )
    assert forward.authenticates_action_cohort_preparation(
        forward_preparation,
        entries=entries,
        published_provenances=provenances,
    )
    assert not forward.authenticates_action_cohort_preparation(
        forward_preparation,
        entries=tuple(reversed(entries)),
    )
    assert not forward.authenticates_action_cohort_preparation(
        forward_preparation,
        published_provenances=tuple(reversed(provenances)),
    )
    _commit(forward, forward_preparation)

    reverse = ExecutionEffectAuditCounter()
    reverse_preparation = reverse.prepare_action_cohort(
        _ROOT_ACTION_ID,
        tuple(reversed(entries)),
        published_provenances=tuple(reversed(provenances)),
    )
    _commit(reverse, reverse_preparation)

    direct = ExecutionEffectAuditCounter()
    for provenance in reversed(provenances):
        direct.record_published_effect_occurrence(
            provenance,
            effect_kind=provenance.kind,
        )
    for entry in reversed(entries):
        direct.record(entry.reconciliation)

    assert forward.snapshot() == reverse.snapshot() == direct.snapshot()
    assert forward.snapshot().complete
    assert forward_preparation.binding_token != reverse_preparation.binding_token


def test_invalid_cohorts_leave_no_counter_or_transient_residue() -> None:
    entry, provenances = _effect_entry("invalid")
    provenance = provenances[0]
    incomplete_anchor = ActionAnchor("process_execution", "missing", source="unit_test")
    incomplete_node = ExecutionEffectNode.create(
        incomplete_anchor,
        FileEffectIntent(FileEffectAction.CREATE, "/tmp/missing"),
    )
    incomplete_plan = ExecutionEffectPlan(incomplete_anchor, (incomplete_node,))
    incomplete_entry = ExecutionEffectAuditCohortEntry(
        incomplete_plan,
        incomplete_plan.reconcile(()),
    )
    missing_count_entry, missing_count_provenances = _effect_entry(
        "missing-count",
        report_occurrence_count=False,
    )
    wrong_owned_plan = OwnedEffectOccurrencePlan(
        owner=EffectOccurrenceOwner.EMAIL_ATTACHMENT_FILE_ROOT,
        kind=EffectOccurrenceKind.FILE,
        root_action_id=_ROOT_ACTION_ID,
        instance_key="wrong-owned-plan",
        occurrence_count=1,
    )
    exempt = EffectOccurrenceProvenance.exempt(
        kind=EffectOccurrenceKind.FILE,
        root_action_id=_ROOT_ACTION_ID,
        reason="legacy path is forbidden in an atomic cohort",
    )
    cases = (
        lambda counter: counter.prepare_action_cohort(
            _ROOT_ACTION_ID,
            [entry],  # type: ignore[arg-type]
        ),
        lambda counter: counter.prepare_action_cohort(
            _ROOT_ACTION_ID,
            (object(),),  # type: ignore[arg-type]
        ),
        lambda counter: counter.prepare_action_cohort(
            _ROOT_ACTION_ID,
            (incomplete_entry,),
        ),
        lambda counter: counter.prepare_action_cohort(_ROOT_ACTION_ID, (entry,)),
        lambda counter: counter.prepare_action_cohort(
            _ROOT_ACTION_ID,
            (entry,),
            published_provenances=(provenance, provenance),
        ),
        lambda counter: counter.prepare_action_cohort(
            _ROOT_ACTION_ID,
            (entry,),
            published_provenances=(
                provenance,
                replace(provenance, occurrence_ordinal=1),
            ),
        ),
        lambda counter: counter.prepare_action_cohort(
            _ROOT_ACTION_ID,
            (entry,),
            published_provenances=(replace(provenance, occurrence_ordinal=1),),
        ),
        lambda counter: counter.prepare_action_cohort(
            _ROOT_ACTION_ID,
            (entry,),
            published_provenances=(replace(provenance, kind=EffectOccurrenceKind.REGISTRY),),
        ),
        lambda counter: counter.prepare_action_cohort(
            _ROOT_ACTION_ID,
            (entry,),
            published_provenances=(replace(provenance, root_action_id="foreign-root"),),
        ),
        lambda counter: counter.prepare_action_cohort(
            _ROOT_ACTION_ID,
            (missing_count_entry,),
            published_provenances=missing_count_provenances,
        ),
        lambda counter: counter.prepare_action_cohort(
            _ROOT_ACTION_ID,
            (),
            published_provenances=(exempt,),
        ),
        lambda counter: counter.prepare_action_cohort(
            _ROOT_ACTION_ID,
            (),
            owned_plans=(wrong_owned_plan,),
            published_provenances=(provenance,),
        ),
    )

    for invoke in cases:
        counter = ExecutionEffectAuditCounter()
        initial = counter.snapshot()
        with pytest.raises(ExecutionEffectPlanError):
            invoke(counter)
        assert counter.snapshot() == initial
        assert counter.action_cohort_preparation_census().active == 0


def test_uncommitted_cancelled_copied_and_foreign_capabilities_cleanup_exactly() -> None:
    counter = ExecutionEffectAuditCounter()
    foreign = ExecutionEffectAuditCounter()
    entry, provenances = _effect_entry("capability")
    preparation = counter.prepare_action_cohort(
        _ROOT_ACTION_ID,
        (entry,),
        published_provenances=provenances,
    )
    token = preparation.binding_token
    copied_preparation = copy(preparation)
    copied_token = copy(token)

    assert not counter.authenticates_action_cohort_preparation(copied_preparation)
    assert not counter.authenticates_action_cohort_binding_token(copied_token)
    assert not foreign.authenticates_action_cohort_binding_token(token)
    with pytest.raises(ExecutionEffectPlanError, match="copied"):
        with counter.claimed_action_cohort(copied_preparation):
            pytest.fail("a copied capability must never enter the claim body")
    assert counter.action_cohort_preparation_census().prepared == 1

    with pytest.raises(ExecutionEffectPlanError, match="without commit_no_fail"):
        with counter.claimed_action_cohort(preparation):
            assert counter.action_cohort_preparation_census().claimed == 1
    assert counter.action_cohort_preparation_census().active == 0
    assert not counter.authenticates_action_cohort_binding_token(token)
    assert counter.snapshot().plan_count == 0

    cancelled = counter.prepare_action_cohort(
        _ROOT_ACTION_ID,
        (entry,),
        published_provenances=provenances,
    )
    counter.cancel_action_cohort(cancelled)
    assert counter.action_cohort_preparation_census().active == 0
    with pytest.raises(ExecutionEffectPlanError, match="stale"):
        counter.cancel_action_cohort(cancelled)


def test_double_claim_wrong_thread_and_double_commit_are_rejected() -> None:
    counter = ExecutionEffectAuditCounter()
    entry, provenances = _effect_entry("one-shot")
    preparation = counter.prepare_action_cohort(
        _ROOT_ACTION_ID,
        (entry,),
        published_provenances=provenances,
    )
    errors: list[ExecutionEffectPlanError] = []

    with counter.claimed_action_cohort(preparation) as claimed:
        with pytest.raises(ExecutionEffectPlanError, match="already claimed"):
            with counter.claimed_action_cohort(preparation):
                pytest.fail("a double claim must never enter the claim body")

        def commit_from_foreign_thread() -> None:
            try:
                claimed.commit_no_fail()
            except ExecutionEffectPlanError as error:
                errors.append(error)

        thread = Thread(target=commit_from_foreign_thread)
        thread.start()
        thread.join()
        assert len(errors) == 1
        assert isinstance(errors[0], ExecutionEffectPlanError)
        assert claimed.receipt is None
        receipt = claimed.commit_no_fail()

    assert counter.authenticates_action_cohort_receipt(
        receipt,
        preparation=preparation,
    )
    with pytest.raises(ExecutionEffectPlanError, match="stale"):
        preparation.commit_no_fail()


def test_injected_precommit_failure_is_all_or_none() -> None:
    class FailingCopyCounter(Counter[str]):
        def copy(self) -> Counter[str]:
            raise RuntimeError("injected before canonical replacement")

    counter = ExecutionEffectAuditCounter()
    entry, provenances = _effect_entry("injected-precommit")
    preparation = counter.prepare_action_cohort(
        _ROOT_ACTION_ID,
        (entry,),
        published_provenances=provenances,
    )
    initial = counter.snapshot()
    counter._counts = FailingCopyCounter(counter._counts)

    with pytest.raises(RuntimeError, match="injected before canonical replacement"):
        with counter.claimed_action_cohort(preparation) as claimed:
            claimed.commit_no_fail()

    assert counter.snapshot() == initial
    assert counter.action_cohort_preparation_census().active == 0
    assert preparation.receipt is None


@pytest.mark.parametrize(
    "malformation",
    ("actor", "dependencies", "linked_outcome", "suppressed_outcome"),
)
def test_nested_actor_node_and_outcome_invariants_are_reconstructed(
    malformation: str,
) -> None:
    counter = ExecutionEffectAuditCounter()
    entry, provenances = _effect_entry(f"nested-{malformation}")
    node = entry.plan.nodes[0]
    outcome = entry.reconciliation.outcomes[0]

    if malformation == "actor":
        isolated_actor = replace(node.actor)
        object.__setattr__(node, "actor", isolated_actor)
        object.__setattr__(isolated_actor, "node_id", "forged-root-actor-node")
    elif malformation == "dependencies":
        object.__setattr__(node, "depends_on", ("duplicate", "duplicate"))
    elif malformation == "linked_outcome":
        object.__setattr__(outcome, "status", EffectOutcomeStatus.LINKED)
        object.__setattr__(outcome, "child_action_id", "")
    else:
        object.__setattr__(node, "requirement", EffectRequirement.OPTIONAL)
        object.__setattr__(outcome, "status", EffectOutcomeStatus.SUPPRESSED)
        object.__setattr__(outcome, "reason", "")

    initial = counter.snapshot()
    with pytest.raises(ExecutionEffectPlanError, match="malformed"):
        counter.prepare_action_cohort(
            _ROOT_ACTION_ID,
            (entry,),
            published_provenances=provenances,
        )
    assert counter.snapshot() == initial
    census = counter.action_cohort_preparation_census()
    assert census.active == 0
    assert census.retained_members == 0
    assert census.retained_bytes == 0


def test_hostile_stateful_timezone_is_canonicalized_once_before_retention() -> None:
    counter = ExecutionEffectAuditCounter()

    class ReentrantStatefulTimezone(tzinfo):
        def __init__(self) -> None:
            self.calls = 0

        def utcoffset(self, _value: datetime | None) -> timedelta:
            assert not counter._lock.locked(), "caller tzinfo ran under the audit lock"
            counter.snapshot()
            self.calls += 1
            return timedelta(minutes=30 + self.calls)

        def dst(self, _value: datetime | None) -> timedelta:
            return timedelta(0)

        def tzname(self, _value: datetime | None) -> str:
            return "HOSTILE"

        def __repr__(self) -> str:
            raise AssertionError("the audit must never repr caller timezone objects")

    callback_timezone = ReentrantStatefulTimezone()
    completed_at = datetime(2026, 8, 17, 12, 30, tzinfo=callback_timezone)
    entry, provenances = _effect_entry(
        "callback-free-time",
        completed_at=completed_at,
    )
    isolated_actor = replace(entry.plan.nodes[0].actor)
    object.__setattr__(entry.plan.nodes[0], "actor", isolated_actor)
    preparation = counter.prepare_action_cohort(
        _ROOT_ACTION_ID,
        (entry,),
        published_provenances=provenances,
    )
    assert callback_timezone.calls == 1
    assert type(preparation._binding.canonical_payload) is bytes
    assert not hasattr(preparation._binding, "entries")

    class ForbiddenLateTimezone(tzinfo):
        def utcoffset(self, _value: datetime | None) -> timedelta:
            raise AssertionError("late caller timestamp was consulted after preparation")

        def dst(self, _value: datetime | None) -> timedelta:
            return timedelta(0)

    late_timestamp = datetime(2030, 1, 1, tzinfo=ForbiddenLateTimezone())
    object.__setattr__(entry.reconciliation.outcomes[0], "completed_at", late_timestamp)
    object.__setattr__(isolated_actor, "node_id", "late-forged-actor-node")

    assert counter.authenticates_action_cohort_preparation(
        preparation,
        entries=(entry,),
        published_provenances=provenances,
    )
    assert counter.authenticates_action_cohort_binding_token(preparation.binding_token)
    receipt = _commit(counter, preparation)
    assert counter.authenticates_action_cohort_receipt(
        receipt,
        preparation=preparation,
        entries=(entry,),
        published_provenances=provenances,
    )
    assert callback_timezone.calls == 1
    assert counter.snapshot().complete


def test_late_caller_graph_replacement_cannot_change_the_sealed_cohort() -> None:
    counter = ExecutionEffectAuditCounter()
    entry, provenances = _effect_entry("late-caller-graph")
    preparation = counter.prepare_action_cohort(
        _ROOT_ACTION_ID,
        (entry,),
        published_provenances=provenances,
    )
    copied_node = replace(entry.plan.nodes[0])
    object.__setattr__(entry.plan, "nodes", (copied_node,))

    assert not counter.authenticates_action_cohort_preparation(
        preparation,
        entries=(entry,),
    )
    assert counter.authenticates_action_cohort_binding_token(preparation.binding_token)
    receipt = _commit(counter, preparation)
    assert counter.authenticates_action_cohort_receipt(
        receipt,
        preparation=preparation,
    )
    assert not counter.authenticates_action_cohort_receipt(
        receipt,
        preparation=preparation,
        entries=(entry,),
    )
    assert counter.snapshot().complete


@pytest.mark.parametrize(
    "tamper_target",
    ("token", "delta", "canonical_payload", "identity_digest"),
)
def test_precommit_tampering_rejects_with_zero_mutation_and_cleanup(
    tamper_target: str,
) -> None:
    counter = ExecutionEffectAuditCounter()
    entry, provenances = _effect_entry(f"tamper-{tamper_target}")
    preparation = counter.prepare_action_cohort(
        _ROOT_ACTION_ID,
        (entry,),
        published_provenances=provenances,
    )
    initial = counter.snapshot()

    if tamper_target == "token":
        object.__setattr__(preparation.binding_token, "_preparation_id", "forged")
    elif tamper_target == "delta":
        object.__setattr__(
            preparation,
            "_delta",
            replace(
                preparation._delta,
                published_occurrence_count=(preparation._delta.published_occurrence_count + 1),
            ),
        )
    elif tamper_target == "canonical_payload":
        object.__setattr__(
            preparation,
            "_binding",
            replace(preparation._binding, canonical_payload=b'{"forged":true}'),
        )
    else:
        object.__setattr__(
            preparation,
            "_binding",
            replace(preparation._binding, entry_identity_digest="0" * 64),
        )

    assert not counter.authenticates_action_cohort_preparation(preparation)
    with pytest.raises(ExecutionEffectPlanError, match="integrity"):
        with counter.claimed_action_cohort(preparation):
            pytest.fail("a tampered capability must never enter the claim body")
    assert counter.snapshot() == initial
    census = counter.action_cohort_preparation_census()
    assert census.active == 0
    assert census.retained_members == 0
    assert census.retained_bytes == 0
    assert preparation.receipt is None


def test_hostile_retained_member_tamper_rejects_without_callback_or_census_leak() -> None:
    class HostileRetainedMembers:
        def __eq__(self, _other: object) -> bool:
            raise AssertionError("hostile retained-member equality ran under the audit lock")

        def __repr__(self) -> str:
            raise AssertionError("hostile retained-member repr was invoked")

    counter = ExecutionEffectAuditCounter()
    entry, provenances = _effect_entry("hostile-retained-members")
    preparation = counter.prepare_action_cohort(
        _ROOT_ACTION_ID,
        (entry,),
        published_provenances=provenances,
    )
    initial = counter.snapshot()
    object.__setattr__(
        preparation._binding,
        "retained_members",
        HostileRetainedMembers(),
    )

    assert not counter.authenticates_action_cohort_preparation(preparation)
    with pytest.raises(ExecutionEffectPlanError, match="integrity"):
        with counter.claimed_action_cohort(preparation):
            pytest.fail("a malformed retained-member binding must not be claimable")

    assert counter.snapshot() == initial
    census = counter.action_cohort_preparation_census()
    assert census.active == 0
    assert census.retained_members == 0
    assert census.retained_bytes == 0
    assert preparation.receipt is None


def test_receipt_is_exact_one_shot_and_authenticators_are_total() -> None:
    class Hostile:
        def __eq__(self, other: object) -> bool:
            raise AssertionError("an authenticator invoked hostile equality")

        def __repr__(self) -> str:
            raise AssertionError("an authenticator repr'd an arbitrary object")

    counter = ExecutionEffectAuditCounter()
    entry, provenances = _effect_entry("receipt")
    preparation = counter.prepare_action_cohort(
        _ROOT_ACTION_ID,
        (entry,),
        published_provenances=provenances,
    )
    assert not counter.authenticates_action_cohort_preparation(
        preparation,
        root_action_id=Hostile(),
    )
    assert not counter.authenticates_action_cohort_preparation(Hostile())
    assert not counter.authenticates_action_cohort_binding_token(Hostile())
    assert not counter.authenticates_action_cohort_receipt(
        Hostile(),
        preparation=Hostile(),
    )

    receipt = _commit(counter, preparation)
    assert not counter.authenticates_action_cohort_receipt(
        copy(receipt),
        preparation=preparation,
    )
    assert not counter.authenticates_action_cohort_receipt(
        receipt,
        preparation=copy(preparation),
    )
    assert counter.authenticates_action_cohort_receipt(
        receipt,
        preparation=preparation,
        entries=(entry,),
        published_provenances=provenances,
    )

    original_root_action_id = preparation._binding.root_action_id
    object.__setattr__(preparation._binding, "root_action_id", "tampered-root")
    assert not counter.authenticates_action_cohort_receipt(
        receipt,
        preparation=preparation,
    )
    object.__setattr__(preparation._binding, "root_action_id", original_root_action_id)
    original_retained_members = preparation._binding.retained_members
    object.__setattr__(
        preparation._binding,
        "retained_members",
        original_retained_members + 1,
    )
    assert not counter.authenticates_action_cohort_receipt(
        receipt,
        preparation=preparation,
    )
    object.__setattr__(
        preparation._binding,
        "retained_members",
        original_retained_members,
    )
    object.__setattr__(receipt, "_integrity", Hostile())
    assert not counter.authenticates_action_cohort_receipt(
        receipt,
        preparation=preparation,
    )
