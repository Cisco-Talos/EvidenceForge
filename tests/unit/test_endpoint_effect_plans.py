"""Contracts for process-owned file, registry, and transfer effect plans."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from evidenceforge.events.contracts import OccurrenceRole
from evidenceforge.generation.actions.base import ActionAnchor
from evidenceforge.generation.actions.command_effects import (
    EffectExecutionOutcome,
    EffectOutcomeStatus,
    EffectRequirement,
    ExecutionEffectPlanError,
    FileEffectAction,
    FileEffectIntent,
    RegistryEffectAction,
    RegistryEffectIntent,
    TransferEffectIntent,
)
from evidenceforge.generation.actions.endpoint_effects import (
    EndpointEffectExecutionPlan,
    EndpointEffectPreparedCommit,
    EndpointEffectSpec,
    EndpointStateDisposition,
    ExactProcessEffectActor,
    PreparedEndpointEffect,
    PreparedFileEffectPayload,
    PreparedProcessEffectActor,
    PreparedProcessEndpointEffectPlan,
    ProcessOwnedEndpointEffectActionBundle,
    ProcessOwnedEndpointEffectRequest,
    bind_prepared_process_endpoint_effect_plan,
)

_START = datetime(2024, 3, 18, 16, 0, tzinfo=UTC)


def _actor() -> ExactProcessEffectActor:
    return ExactProcessEffectActor(
        hostname="WS-001",
        pid=4242,
        process_object_id="process-object-4242",
        lifecycle_id="process-life-4242",
        image=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
        command_line="powershell.exe -File collect.ps1",
        username="alice",
        logon_id="0x12001",
        started_at=_START,
        closes_at=_START + timedelta(minutes=10),
    )


def _request() -> ProcessOwnedEndpointEffectRequest:
    retention_end = _START + timedelta(hours=2)
    specs = (
        EndpointEffectSpec(
            intent=TransferEffectIntent(
                protocol="https",
                source_path=r"C:\Temp\case.zip",
                destination="files.example.net",
                destination_path="/upload/case.zip",
            ),
            occurrence_times=(_START + timedelta(seconds=5),),
            instance_key="transfer",
            depends_on=("source-read",),
        ),
        EndpointEffectSpec(
            intent=RegistryEffectIntent(
                RegistryEffectAction.MODIFY,
                r"HKCU\Software\Example",
                "LastArchive",
            ),
            occurrence_times=(_START + timedelta(seconds=7),),
            instance_key="registry-final",
            depends_on=("transfer",),
            state_disposition=EndpointStateDisposition.DURABLE_FINAL,
            retention_deadline=retention_end,
        ),
        EndpointEffectSpec(
            intent=FileEffectIntent(FileEffectAction.READ, r"C:\Temp\case.zip"),
            occurrence_times=(_START + timedelta(seconds=3),),
            instance_key="source-read",
        ),
    )
    return ProcessOwnedEndpointEffectRequest(
        actor=_actor(),
        anchor_time=_START + timedelta(seconds=1),
        window_end=_START + timedelta(minutes=10),
        retention_horizon_end=retention_end,
        specs=specs,
    )


def _prepared_plan(*, optional_outside_window: bool = False) -> PreparedProcessEndpointEffectPlan:
    actor = PreparedProcessEffectActor(
        hostname="WS-001",
        image=r"C:\Windows\System32\cmd.exe",
        command_line="cmd.exe /c type case.zip",
        username="alice",
        logon_id="0x12001",
        lifecycle_id="process-life-4242",
        started_at=_START,
        session_deadline=_START + timedelta(minutes=10),
    )
    occurrence = (
        _START + timedelta(minutes=10) if optional_outside_window else _START + timedelta(seconds=4)
    )
    spec = EndpointEffectSpec(
        intent=FileEffectIntent(FileEffectAction.READ, r"C:\Temp\case.zip"),
        occurrence_times=(occurrence,),
        instance_key="read",
        requirement=(
            EffectRequirement.OPTIONAL if optional_outside_window else EffectRequirement.REQUIRED
        ),
    )
    return PreparedProcessEndpointEffectPlan(
        root_anchor=ActionAnchor(
            family="process_execution",
            stable_id="root-process-intent",
            source="test",
        ),
        actor=actor,
        window_end=_START + timedelta(minutes=10),
        retention_horizon_end=_START + timedelta(minutes=10),
        effects=(
            PreparedEndpointEffect(
                spec=spec,
                event_type="file_read",
                payload=PreparedFileEffectPayload(
                    path=r"C:\Temp\case.zip",
                    action=FileEffectAction.READ,
                ),
            ),
        ),
    )


class _Executor:
    def __init__(self, *, drift: bool = False, exact_counts: bool = True) -> None:
        self.drift = drift
        self.exact_counts = exact_counts
        self.preflight_count = 0
        self.prepare_count = 0
        self.commit_count = 0

    def _preflight_process_owned_endpoint_effects(
        self,
        request: ProcessOwnedEndpointEffectRequest,
        _anchor: object,
    ) -> EndpointEffectExecutionPlan:
        self.preflight_count += 1
        assert request.execution_plan is not None
        if self.drift:
            return replace(
                request.execution_plan,
                window_end=request.execution_plan.window_end - timedelta(microseconds=1),
            )
        return request.execution_plan

    def _prepare_process_owned_endpoint_effects(
        self,
        request: ProcessOwnedEndpointEffectRequest,
    ) -> EndpointEffectPreparedCommit:
        self.prepare_count += 1
        assert request.execution_plan is not None
        outcomes = tuple(
            EffectExecutionOutcome(
                node_id=node.node_id,
                status=EffectOutcomeStatus.REALIZED,
                canonical_occurrence_count=(
                    node.intent.occurrence_cardinality if self.exact_counts else None
                ),
            )
            for node in request.execution_plan.effects.nodes
        )
        return EndpointEffectPreparedCommit.create(request.execution_plan, outcomes)

    def _commit_process_owned_endpoint_effects(
        self,
        request: ProcessOwnedEndpointEffectRequest,
        prepared: EndpointEffectPreparedCommit,
    ) -> None:
        assert request.execution_plan is not None
        assert prepared.action_id == request.execution_plan.effects.action_id
        self.commit_count += 1


def _plan_fingerprint(request: ProcessOwnedEndpointEffectRequest) -> str:
    assert request.execution_plan is not None
    return json.dumps(
        {
            "action": request.execution_plan.effects.action_id,
            "nodes": [
                {
                    "id": node.node_id,
                    "key": node.instance_key,
                    "deps": node.depends_on,
                }
                for node in request.execution_plan.effects.ordered_nodes
            ],
            "occurrences": [
                (
                    occurrence.occurrence_id,
                    occurrence.subject_id,
                    occurrence.actor_process_object_id,
                    occurrence.actor_lifecycle_id,
                )
                for occurrence in request.execution_plan.occurrences()
            ],
        },
        sort_keys=True,
    )


def _prepared_fingerprint(plan: PreparedProcessEndpointEffectPlan) -> str:
    assert plan.execution_plan is not None
    return json.dumps(
        {
            "stable_id": plan.stable_id,
            "actor": plan.actor.stable_id,
            "action": plan.execution_plan.action_id,
            "nodes": [node.node_id for node in plan.execution_plan.ordered_nodes],
            "suppressed": plan.suppressed_instance_keys,
        },
        sort_keys=True,
    )


def test_endpoint_plan_freezes_exact_actor_subjects_dependencies_and_retention() -> None:
    request = _request()
    plan = request.execution_plan
    assert plan is not None
    assert tuple(spec.instance_key for spec in plan.specs) == (
        "registry-final",
        "source-read",
        "transfer",
    )
    assert len(plan.effects.nodes) == 3
    assert len(plan.durable_node_ids) == 1
    occurrences = tuple(plan.occurrences())
    assert len(occurrences) == 3
    assert {occurrence.actor_process_object_id for occurrence in occurrences} == {
        "process-object-4242"
    }
    assert {occurrence.actor_lifecycle_id for occurrence in occurrences} == {"process-life-4242"}
    assert len({occurrence.occurrence_id for occurrence in occurrences}) == 3
    assert len({occurrence.subject_id for occurrence in occurrences}) == 3
    nodes = {node.instance_key: node for node in plan.effects.nodes}
    assert nodes["transfer"].depends_on == (nodes["source-read"].node_id,)
    assert nodes["registry-final"].depends_on == (nodes["transfer"].node_id,)


def test_ephemeral_mutation_requires_exact_post_order_delete() -> None:
    create = EndpointEffectSpec(
        intent=FileEffectIntent(FileEffectAction.CREATE, r"C:\Temp\scratch.bin"),
        occurrence_times=(_START + timedelta(seconds=2),),
        instance_key="create",
        state_disposition=EndpointStateDisposition.EPHEMERAL,
    )
    with pytest.raises(ExecutionEffectPlanError, match="exactly one dependent delete"):
        ProcessOwnedEndpointEffectRequest(
            actor=_actor(),
            anchor_time=_START + timedelta(seconds=1),
            window_end=_START + timedelta(minutes=5),
            retention_horizon_end=_START + timedelta(minutes=5),
            specs=(create,),
        )

    closure = EndpointEffectSpec(
        intent=FileEffectIntent(FileEffectAction.DELETE, r"C:\Temp\scratch.bin"),
        occurrence_times=(_START + timedelta(seconds=4),),
        instance_key="delete",
        role=OccurrenceRole.CLOSURE,
        depends_on=("create",),
    )
    request = ProcessOwnedEndpointEffectRequest(
        actor=_actor(),
        anchor_time=_START + timedelta(seconds=1),
        window_end=_START + timedelta(minutes=5),
        retention_horizon_end=_START + timedelta(minutes=5),
        specs=(closure, create),
    )
    assert request.execution_plan is not None
    assert len(request.execution_plan.effects.closures) == 1


@pytest.mark.parametrize(
    ("timestamp", "match"),
    [
        (_START, "escapes"),
        (_START + timedelta(minutes=10), "escapes"),
    ],
)
def test_near_window_rejection_happens_before_executor_mutation(
    timestamp: datetime,
    match: str,
) -> None:
    spec = EndpointEffectSpec(
        intent=FileEffectIntent(FileEffectAction.READ, r"C:\Temp\case.zip"),
        occurrence_times=(timestamp,),
        instance_key="read",
    )
    with pytest.raises(ExecutionEffectPlanError, match=match):
        ProcessOwnedEndpointEffectRequest(
            actor=_actor(),
            anchor_time=_START + timedelta(seconds=1),
            window_end=_START + timedelta(minutes=10),
            retention_horizon_end=_START + timedelta(minutes=10),
            specs=(spec,),
        )


def test_preflight_drift_never_calls_mutating_executor() -> None:
    executor = _Executor(drift=True)
    bundle = ProcessOwnedEndpointEffectActionBundle(executor, _request())
    with pytest.raises(ExecutionEffectPlanError, match="drifted"):
        bundle.execute()
    assert executor.preflight_count == 1
    assert executor.prepare_count == 0
    assert executor.commit_count == 0


def test_execution_reconciles_exact_cardinality_without_phantom_links() -> None:
    executor = _Executor()
    reconciliation = ProcessOwnedEndpointEffectActionBundle(executor, _request()).execute()
    assert reconciliation.complete
    assert reconciliation.summary.realized_count == 3
    assert reconciliation.summary.realized_occurrence_count == 3
    assert executor.prepare_count == 1
    assert executor.commit_count == 1

    missing_counts = _Executor(exact_counts=False)
    with pytest.raises(
        ExecutionEffectPlanError,
        match="exact canonical occurrence cardinality",
    ):
        ProcessOwnedEndpointEffectActionBundle(missing_counts, _request()).execute()
    assert missing_counts.prepare_count == 1
    assert missing_counts.commit_count == 0

    plan = _request().execution_plan
    assert plan is not None
    transfer = next(node for node in plan.effects.nodes if node.instance_key == "transfer")
    with pytest.raises(ExecutionEffectPlanError, match="linked outcomes require child_action_id"):
        EffectExecutionOutcome(
            node_id=transfer.node_id,
            status=EffectOutcomeStatus.LINKED,
            canonical_occurrence_count=1,
        )


def test_external_transfer_link_requires_exact_child_and_count() -> None:
    request = _request()
    assert request.execution_plan is not None
    transfer_spec = next(spec for spec in request.specs if spec.instance_key == "transfer")
    linked_transfer = replace(transfer_spec, requirement=EffectRequirement.EXTERNALLY_OWNED)
    linked_request = replace(
        request,
        specs=tuple(
            linked_transfer if spec.instance_key == "transfer" else spec for spec in request.specs
        ),
        execution_plan=None,
    )
    assert linked_request.execution_plan is not None
    node = next(
        node
        for node in linked_request.execution_plan.effects.nodes
        if node.instance_key == "transfer"
    )
    reconciliation = linked_request.execution_plan.effects.reconcile(
        tuple(
            EffectExecutionOutcome(
                node_id=candidate.node_id,
                status=(
                    EffectOutcomeStatus.LINKED
                    if candidate.node_id == node.node_id
                    else EffectOutcomeStatus.REALIZED
                ),
                child_action_id="ssh-channel-action" if candidate.node_id == node.node_id else "",
                canonical_occurrence_count=candidate.intent.occurrence_cardinality,
            )
            for candidate in linked_request.execution_plan.effects.nodes
        )
    )
    reconciliation.require_complete()


def test_prepared_optional_near_window_has_explicit_suppressed_outcome() -> None:
    prepared = _prepared_plan(optional_outside_window=True)
    assert prepared.suppressed_instance_keys == ("read",)
    assert prepared.admitted_effects == ()
    assert prepared.earliest_admitted_occurrence is None
    assert prepared.latest_admitted_occurrence is None

    actor = ExactProcessEffectActor(
        hostname=prepared.actor.hostname,
        pid=4242,
        process_object_id="process-object-4242",
        lifecycle_id=prepared.actor.lifecycle_id,
        image=prepared.actor.image,
        command_line=prepared.actor.command_line,
        username=prepared.actor.username,
        logon_id=prepared.actor.logon_id,
        started_at=prepared.actor.started_at,
    )
    request = bind_prepared_process_endpoint_effect_plan(prepared, actor)
    assert request.execution_plan is not None
    assert tuple(request.execution_plan.occurrences()) == ()
    node = request.execution_plan.effects.nodes[0]
    reconciliation = request.execution_plan.effects.reconcile(
        (
            EffectExecutionOutcome(
                node_id=node.node_id,
                status=EffectOutcomeStatus.SUPPRESSED,
                reason="optional endpoint effect omitted outside its prepared interval",
                canonical_occurrence_count=0,
            ),
        )
    )
    reconciliation.require_complete()
    assert reconciliation.summary.suppressed_count == 1


def test_plan_is_identical_across_one_four_and_eight_workers() -> None:
    expected = (_plan_fingerprint(_request()), _prepared_fingerprint(_prepared_plan()))
    for workers in (1, 4, 8):
        with ThreadPoolExecutor(max_workers=workers) as pool:
            fingerprints = tuple(
                pool.map(
                    lambda _index: (
                        _plan_fingerprint(_request()),
                        _prepared_fingerprint(_prepared_plan()),
                    ),
                    range(32),
                )
            )
        assert set(fingerprints) == {expected}


def test_plan_is_python_hash_seed_independent() -> None:
    script = """
import json
from datetime import UTC, datetime, timedelta
from evidenceforge.generation.actions.base import ActionAnchor
from evidenceforge.generation.actions.command_effects import FileEffectAction, FileEffectIntent
from evidenceforge.generation.actions.endpoint_effects import (
    EndpointEffectSpec, ExactProcessEffectActor, PreparedEndpointEffect,
    PreparedFileEffectPayload, PreparedProcessEffectActor,
    PreparedProcessEndpointEffectPlan, ProcessOwnedEndpointEffectRequest,
)
start = datetime(2024, 3, 18, 16, 0, tzinfo=UTC)
actor = ExactProcessEffectActor(
    hostname='WS-001', pid=4242, process_object_id='obj', lifecycle_id='life',
    image='cmd.exe', command_line='cmd.exe /c type case.zip', username='alice',
    logon_id='0x12001', started_at=start, closes_at=start + timedelta(minutes=5),
)
spec = EndpointEffectSpec(
    intent=FileEffectIntent(FileEffectAction.READ, r'C:\\Temp\\case.zip'),
    occurrence_times=(start + timedelta(seconds=2),), instance_key='read',
)
request = ProcessOwnedEndpointEffectRequest(
    actor=actor, anchor_time=start + timedelta(seconds=1),
    window_end=start + timedelta(minutes=5),
    retention_horizon_end=start + timedelta(minutes=5), specs=(spec,),
)
plan = request.execution_plan
prepared_actor = PreparedProcessEffectActor(
    hostname='WS-001', image='cmd.exe', command_line='cmd.exe /c type case.zip',
    username='alice', logon_id='0x12001', lifecycle_id='life', started_at=start,
    session_deadline=start + timedelta(minutes=5),
)
prepared = PreparedProcessEndpointEffectPlan(
    root_anchor=ActionAnchor(family='process_execution', stable_id='root', source='test'),
    actor=prepared_actor, window_end=start + timedelta(minutes=5),
    retention_horizon_end=start + timedelta(minutes=5),
    effects=(PreparedEndpointEffect(
        spec=spec, event_type='file_read',
        payload=PreparedFileEffectPayload(
            path=r'C:\\Temp\\case.zip', action=FileEffectAction.READ,
        ),
    ),),
)
print(json.dumps({
    'action': plan.effects.action_id,
    'nodes': [node.node_id for node in plan.effects.ordered_nodes],
    'occurrences': [row.occurrence_id for row in plan.occurrences()],
    'prepared': prepared.stable_id,
    'prepared_nodes': [node.node_id for node in prepared.execution_plan.ordered_nodes],
}, sort_keys=True))
"""
    outputs = []
    for seed in ("1", "99991"):
        env = os.environ.copy()
        env["PYTHONHASHSEED"] = seed
        outputs.append(
            subprocess.check_output(
                [sys.executable, "-c", script],
                cwd=Path(__file__).parents[2],
                env=env,
                text=True,
            ).strip()
        )
    assert outputs[0] == outputs[1]


def test_effect_occurrence_budget_is_explicitly_bounded() -> None:
    count = 4097
    spec = EndpointEffectSpec(
        intent=FileEffectIntent(
            FileEffectAction.READ,
            r"C:\Temp\case.zip",
            occurrence_cardinality=count,
        ),
        occurrence_times=tuple(
            _START + timedelta(microseconds=index + 1) for index in range(count)
        ),
        instance_key="read",
    )
    with pytest.raises(ExecutionEffectPlanError, match="cannot exceed 4096"):
        ProcessOwnedEndpointEffectRequest(
            actor=_actor(),
            anchor_time=_START,
            window_end=_START + timedelta(minutes=5),
            retention_horizon_end=_START + timedelta(minutes=5),
            specs=(spec,),
        )
