# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Detached lifecycle network-receipt issuance-authority contracts."""

import copy
import gc
import random
import weakref
from dataclasses import fields
from datetime import UTC, datetime, timedelta
from threading import Event, Thread
from unittest.mock import Mock

import pytest

import evidenceforge.generation.lifecycle_authority as lifecycle_authority_module
from evidenceforge.events.contexts import HttpContext
from evidenceforge.events.lifecycle import LifecycleHold
from evidenceforge.events.network import NetworkTrafficLedger, NetworkTransactionPlan
from evidenceforge.generation.actions.network_connection import (
    NetworkConnectionIdentityCapture,
    NetworkConnectionPublicationOutcome,
)
from evidenceforge.generation.activity import ActivityGenerator
from evidenceforge.generation.application_channels import ApplicationChannelRegistry
from evidenceforge.generation.cryptographic_material import CryptographicMaterialRegistry
from evidenceforge.generation.http_channels import (
    HttpApplicationChannelManager,
    HttpChannelAffinity,
    HttpChannelReuse,
)
from evidenceforge.generation.lifecycle_authority import (
    GeneratorLifecycleAuthority,
    LifecyclePreparedNetworkReceipt,
    LifecyclePreparedNetworkResult,
)
from evidenceforge.generation.lifecycle_production_adapters import (
    LifecycleProductionAdapter,
    closed_transport_publication_plan,
)
from evidenceforge.generation.lifecycle_registry import (
    LifecycleClosedTransportAdmissionToken,
    LifecycleRegistry,
)
from evidenceforge.generation.lifecycle_shadow import LifecycleShadow
from evidenceforge.generation.network_runtime import (
    NetworkTransactionRuntime,
    PreparedNetworkTransactionRoot,
)
from evidenceforge.generation.source_timing import SourceTimingPlanner, SourceTimingPreparation
from evidenceforge.generation.state_manager import (
    ConnectionMaterializationMode,
    ProcessActivityPatch,
    SessionActivityPatch,
    StateManager,
)
from evidenceforge.models.exceptions import StateError
from evidenceforge.models.scenario import System

_START = datetime(2026, 8, 19, 13, 0, tzinfo=UTC)
_END = _START + timedelta(days=2)

_SOURCE_SCALAR_PATHS: tuple[tuple[str, ...], ...] = (
    ("_runtime_publication_token",),
    ("_state_publication_token",),
    ("_transaction_id",),
    ("_materialization_mode",),
    ("_lifecycle_mode",),
    ("_result_digest",),
    ("_integrity_token",),
    ("_physical_transport", "transport_id"),
    ("_physical_transport", "tuple_key"),
    ("_connection_receipt", "_integrity_token"),
    ("_runtime_receipt", "_runtime_token"),
    ("_runtime_receipt", "_integrity_token"),
    ("_runtime_receipt", "cryptographic_receipt", "_integrity_token"),
    ("_timing_binding_token", "_integrity"),
    ("_timing_receipt", "_integrity"),
)


def _transaction(
    *,
    conn_id: str,
    zeek_uid: str,
    stable_id: str,
    src_port: int = 50_001,
    started_at: datetime = _START,
    duration: float = 30.0,
    application_layer_only: bool = False,
) -> NetworkTransactionPlan:
    closed_at = started_at + timedelta(seconds=duration)
    return NetworkTransactionPlan(
        stable_id=stable_id,
        hostname="files.example.test",
        outcome="success",
        phase_times=(("transport_start", started_at), ("transport_close", closed_at)),
        started_at=started_at,
        closed_at=closed_at,
        src_ip="10.0.0.10",
        src_port=src_port,
        dst_ip="10.0.0.20",
        dst_port=445,
        protocol="tcp",
        service="smb",
        zeek_uid=zeek_uid,
        conn_id=conn_id,
        duration=duration,
        conn_state="SF",
        history="ShADadFf",
        traffic=NetworkTrafficLedger(),
        application_layer_only=application_layer_only,
    )


def _prepare_root(
    authority: GeneratorLifecycleAuthority,
    runtime: NetworkTransactionRuntime,
    timing: SourceTimingPlanner,
    *,
    stable_id: str,
    lifecycle_rich: bool = False,
    src_port: int = 50_001,
) -> tuple[
    PreparedNetworkTransactionRoot,
    SourceTimingPreparation,
    random.Random,
    LifecycleClosedTransportAdmissionToken,
]:
    owner_rng = random.Random(stable_id)
    preparation = runtime.begin(
        owner_rng=owner_rng,
        stable_id=stable_id,
        linearization_time=_START,
    )
    identity = preparation.reserve_physical_identity()
    transaction = _transaction(
        conn_id=identity.conn_id,
        zeek_uid=identity.zeek_uid,
        stable_id=stable_id,
        src_port=src_port,
    )
    batch = None
    process_activity: tuple[ProcessActivityPatch, ...] = ()
    session_activity: tuple[SessionActivityPatch, ...] = ()
    if lifecycle_rich:
        batch_builder = authority._state_manager.begin_materialization_batch()
        session = batch_builder.plan_session(
            username="analyst",
            system="WS-01",
            logon_type=2,
            source_ip="-",
            start_time=_START,
            session_kind="interactive",
        )
        process = batch_builder.plan_process(
            system="WS-01",
            parent_pid=0,
            image="/usr/bin/smbclient",
            command_line="smbclient //files/share",
            username="analyst",
            integrity_level="Medium",
            os_category="linux",
            logon_id=session.identity.logon_id,
            start_time=_START + timedelta(milliseconds=1),
            require_session=True,
            session_plan=session,
            auth_session_id=session.identity.session_id,
            auth_logon_type=2,
        )
        batch = batch_builder.seal()
        process_activity = (ProcessActivityPatch(process.identity, transaction.closed_at),)
        session_activity = (SessionActivityPatch(session.identity, transaction.closed_at),)
    root = preparation.seal(
        transaction=transaction,
        lifecycle_mode="network",
        materialization_mode=ConnectionMaterializationMode.PHYSICAL,
        source_system="WS-01",
        source_hostname="ws-01.example.test",
        hostname="files.example.test",
        initiating_pid=-1,
        batch=batch,
        process_activity=process_activity,
        session_activity=session_activity,
    )
    lifecycle_plan = closed_transport_publication_plan(
        transaction=transaction,
        authority_hostname="WS-01",
        src_hostname="WS-01",
        dst_hostname="FS-01",
        action_id=f"{stable_id}-lifecycle",
    )
    start_members = authority.connection_composite_start_members(root.state_plan)
    process_holds: tuple[LifecycleHold, ...] = ()
    if lifecycle_rich:
        process_member = start_members[-1]
        process_holds = (
            LifecycleHold(
                hold_id=f"{stable_id}-process-hold",
                subject=process_member.request.identity.ref,
                acquired_at=_START + timedelta(milliseconds=1),
                hold_until=transaction.closed_at,
                action_id=f"{stable_id}-process-hold-action",
                reason="canonical_transport_close",
            ),
        )
    registry = authority._registry
    lifecycle_token = LifecycleProductionAdapter(registry).prepare_closed_transport_publication(
        lifecycle_plan,
        start_members=start_members,
        process_holds=process_holds,
    )
    with timing.prepared_planning() as timing_preparation:
        pass
    return root, timing_preparation, owner_rng, lifecycle_token


def _prepared_fixture(
    *,
    stable_id: str = "detached-smb-transport",
    lifecycle_rich: bool = False,
    preparation_authority_capacity: int = 4_096,
) -> tuple[
    GeneratorLifecycleAuthority,
    NetworkTransactionRuntime,
    SourceTimingPlanner,
    PreparedNetworkTransactionRoot,
    SourceTimingPreparation,
    random.Random,
    LifecycleClosedTransportAdmissionToken,
]:
    state = StateManager()
    registry = LifecycleRegistry(shard_count=8)
    authority = GeneratorLifecycleAuthority(
        state,
        LifecycleShadow(state, registry),
        shard_count=8,
        prepared_network_receipt_issuance_capacity=preparation_authority_capacity,
    )
    runtime = NetworkTransactionRuntime(
        state_manager=state,
        cryptographic_material=CryptographicMaterialRegistry(),
        window_start=_START,
        window_end=_END,
    )
    timing = SourceTimingPlanner(
        preparation_authority_capacity=preparation_authority_capacity,
    )
    authority.bind_network_transaction_runtime(runtime)
    authority.bind_source_timing_planner(timing)
    return (
        authority,
        runtime,
        timing,
        *_prepare_root(
            authority,
            runtime,
            timing,
            stable_id=stable_id,
            lifecycle_rich=lifecycle_rich,
        ),
    )


def _committed_receipt(
    *,
    stable_id: str = "detached-smb-transport",
    lifecycle_rich: bool = False,
    authenticate: bool = True,
) -> tuple[GeneratorLifecycleAuthority, LifecyclePreparedNetworkReceipt]:
    authority, _runtime, _planner, root, timing, owner_rng, lifecycle_token = _prepared_fixture(
        stable_id=stable_id, lifecycle_rich=lifecycle_rich
    )
    result = authority.materialize_prepared_network_transaction(
        root,
        owner_rng,
        source_timing_preparation=timing,
        lifecycle_token=lifecycle_token,
    )
    if authenticate:
        assert authority.authenticates_prepared_network_receipt(root, result.receipt)
    authority.acknowledge_prepared_network_transaction(root, result)
    return authority, result.receipt


def _source_path_target(root: object, path: tuple[str, ...]) -> tuple[object, str]:
    target = root
    for field_name in path[:-1]:
        target = object.__getattribute__(target, field_name)
    return target, path[-1]


def _different_exact_scalar(value: object) -> object:
    if type(value) is str:
        return "b" * 64 if len(value) == 64 else f"{value}-mutated"
    if type(value) is int:
        return value + 1
    if type(value) is tuple:
        return (*value[:-1], f"{value[-1]}-mutated")
    if type(value) is ConnectionMaterializationMode:
        return ConnectionMaterializationMode.APPLICATION_CHILD
    raise AssertionError(f"unsupported test scalar {type(value)!r}")


def test_detached_network_binding_authenticates_complete_scalar_truth() -> None:
    authority, receipt = _committed_receipt()

    binding = authority.detach_prepared_network_receipt(receipt)

    assert authority.authenticates_detached_network_receipt_binding(binding)
    assert binding.transaction_id == receipt.transaction_id
    assert binding.state_publication_token == receipt.connection_receipt._state_publication_token
    assert binding.runtime_publication_token == receipt.runtime_receipt.publication_token
    assert binding.materialization_mode == "physical"
    assert binding.lifecycle_mode == "network"
    assert binding.physical_transport_id == receipt.physical_transport_id
    assert binding.conn_id == receipt.connection_receipt.conn_id
    assert binding.zeek_uid == receipt.connection_receipt.zeek_uid
    assert binding.tuple_key == ("10.0.0.10", 50_001, "10.0.0.20", 445, "tcp")
    assert binding.started_at == _START
    assert binding.closed_at == _START + timedelta(seconds=30)
    assert all(
        len(value) == 64
        for value in (
            binding.network_result_digest,
            binding.timing_binding_digest,
            binding.timing_receipt_digest,
            binding.runtime_receipt_digest,
            binding.connection_receipt_digest,
            binding.source_receipt_token,
            binding.proof_token,
        )
    )


def test_detached_network_binding_authenticates_lifecycle_rich_receipt() -> None:
    authority, receipt = _committed_receipt(
        stable_id="detached-smb-lifecycle-rich",
        lifecycle_rich=True,
    )
    lifecycle_receipt = receipt.connection_receipt._lifecycle_receipt
    assert lifecycle_receipt is not None
    assert lifecycle_receipt.request.start_members
    assert lifecycle_receipt.request.process_holds
    assert lifecycle_receipt.session_snapshots
    assert lifecycle_receipt.process_snapshots

    binding = authority.detach_prepared_network_receipt(receipt)

    assert authority.authenticates_detached_network_receipt_binding(binding)
    assert binding.physical_transport_id == receipt.physical_transport_id


def test_detached_network_binding_authenticates_canonical_http_application_child() -> None:
    authority, runtime, timing, root, timing_preparation, owner_rng, lifecycle_token = (
        _prepared_fixture(stable_id="detached-http-parent")
    )
    application_registry = ApplicationChannelRegistry(
        window_start=_START,
        window_end=_END,
        shard_count=8,
    )
    http = HttpApplicationChannelManager(
        window_start=_START,
        window_end=_END,
        registry=application_registry,
    )
    authority.bind_http_channel_manager(http)
    affinity = HttpChannelAffinity.from_request(
        src_ip="10.0.0.10",
        dst_ip="10.0.0.20",
        dst_port=445,
        http_host="files.example.test",
        user_agent="Mozilla/5.0",
        transport_security="tls",
    )
    transaction = root.transaction
    assert transaction.closed_at is not None
    open_token = http.prepare_open_transport(
        affinity,
        transport_id=root.state_plan.physical_transport_id,
        zeek_uid=transaction.zeek_uid,
        conn_id=transaction.conn_id,
        src_port=transaction.src_port,
        opened_at=transaction.started_at,
        closes_at=transaction.closed_at,
        initial_request_time=transaction.started_at + timedelta(milliseconds=100),
        orig_budget=1_000,
        resp_budget=5_000,
        initial_request_body_bytes=10,
        initial_response_body_bytes=100,
        operation_budget=4,
    )
    assert open_token is not None
    parent = authority.materialize_prepared_network_transaction(
        root,
        owner_rng,
        source_timing_preparation=timing_preparation,
        lifecycle_token=lifecycle_token,
        application_token=open_token,
    )
    reuse = http.prepare_reuse(
        affinity,
        requested_at=_START + timedelta(seconds=1),
        required_until=_START + timedelta(seconds=1, milliseconds=100),
        request_body_bytes=20,
        response_body_bytes=200,
    )
    assert reuse is not None
    assert isinstance(reuse.result, HttpChannelReuse)
    child_rng = random.Random("detached-http-child")
    child_preparation = runtime.begin(
        owner_rng=child_rng,
        stable_id=reuse.result.operation_id,
        linearization_time=reuse.result.canonical_request_time,
    )
    child_transaction = _transaction(
        conn_id=transaction.conn_id,
        zeek_uid=transaction.zeek_uid,
        stable_id=reuse.result.operation_id,
        started_at=reuse.result.canonical_request_time,
        duration=0.1,
        application_layer_only=True,
    )
    child_root = child_preparation.seal(
        transaction=child_transaction,
        lifecycle_mode="application_child",
        materialization_mode=ConnectionMaterializationMode.APPLICATION_CHILD,
    )
    with timing.prepared_planning() as child_timing:
        pass
    child = authority.materialize_prepared_network_transaction(
        child_root,
        child_rng,
        source_timing_preparation=child_timing,
        application_token=reuse,
    )

    binding = authority.detach_prepared_network_receipt(child.receipt)

    assert binding.materialization_mode == "application_child"
    assert binding.lifecycle_mode == "application_child"
    assert binding.physical_transport_id == parent.receipt.physical_transport_id
    assert authority.authenticates_detached_network_receipt_binding(binding)


def test_detached_network_binding_retains_only_exact_builtin_scalars() -> None:
    authority, receipt = _committed_receipt()

    binding = authority.detach_prepared_network_receipt(receipt)

    retained = tuple(getattr(binding, member.name) for member in fields(binding))
    assert retained
    assert all(type(value) in {str, int, type(None)} for value in retained)
    assert all(value is not receipt for value in retained)
    assert all(value is not receipt.runtime_receipt for value in retained)
    assert all(value is not receipt.timing_receipt for value in retained)
    assert all(value is not receipt.timing_binding_token for value in retained)
    assert all(value is not receipt.connection_receipt for value in retained)


def test_detached_network_binding_rejects_foreign_authority_copy_and_wrong_type() -> None:
    authority, receipt = _committed_receipt(stable_id="local-transport")
    foreign, _foreign_receipt = _committed_receipt(stable_id="foreign-transport")
    binding = authority.detach_prepared_network_receipt(receipt)

    assert not foreign.authenticates_detached_network_receipt_binding(binding)

    assert not authority.authenticates_detached_network_receipt_binding(copy.copy(binding))
    assert not authority.authenticates_detached_network_receipt_binding(object())


def test_detached_network_binding_value_copy_is_not_an_owner_issued_handle() -> None:
    authority, receipt = _committed_receipt()
    binding = authority.detach_prepared_network_receipt(receipt)

    copied = copy.copy(binding)

    assert copied is not binding
    assert copied == binding
    assert not authority.authenticates_detached_network_receipt_binding(copied)


@pytest.mark.parametrize("path", _SOURCE_SCALAR_PATHS)
def test_detach_uses_issuance_facts_after_exact_source_scalar_tamper(
    path: tuple[str, ...],
) -> None:
    authority, receipt = _committed_receipt(stable_id=f"issuance-tamper-{path[-1]}")
    expected = authority.detach_prepared_network_receipt(receipt)
    target, field_name = _source_path_target(receipt, path)
    retained = object.__getattribute__(target, field_name)
    object.__setattr__(target, field_name, _different_exact_scalar(retained))

    observed = authority.detach_prepared_network_receipt(receipt)

    assert observed is not expected
    assert observed == expected
    assert authority.authenticates_detached_network_receipt_binding(observed)


def test_detach_exact_source_tamper_never_invokes_nested_callbacks() -> None:
    authority, receipt = _committed_receipt(stable_id="issuance-callback-tamper")
    expected = authority.detach_prepared_network_receipt(receipt)
    timing_receipt = object.__getattribute__(receipt, "_timing_receipt")
    runtime_receipt = object.__getattribute__(receipt, "_runtime_receipt")
    callback_count = 0

    class CallbackSpy:
        def __repr__(self) -> str:
            nonlocal callback_count
            callback_count += 1
            raise AssertionError("detach traversed caller receipt repr")

        def __eq__(self, _other: object) -> bool:
            nonlocal callback_count
            callback_count += 1
            raise AssertionError("detach traversed caller receipt equality")

        def __hash__(self) -> int:
            nonlocal callback_count
            callback_count += 1
            raise AssertionError("detach traversed caller receipt hash")

    hostile = CallbackSpy()
    object.__setattr__(receipt, "_result_digest", hostile)
    object.__setattr__(timing_receipt, "_integrity", hostile)
    object.__setattr__(runtime_receipt, "_runtime_token", hostile)

    observed = authority.detach_prepared_network_receipt(receipt)

    assert observed == expected
    assert callback_count == 0


def test_concurrent_source_tamper_cannot_drift_issuance_facts_or_add_callback() -> None:
    authority, receipt = _committed_receipt(stable_id="concurrent-issuance-tamper")
    expected = authority.detach_prepared_network_receipt(receipt)
    runtime_receipt = object.__getattribute__(receipt, "_runtime_receipt")
    ready = Event()
    stop = Event()
    callback_count = 0

    class CallbackSpy:
        def __repr__(self) -> str:
            nonlocal callback_count
            callback_count += 1
            raise AssertionError("detach rendered a concurrently changing source field")

        def __eq__(self, _other: object) -> bool:
            nonlocal callback_count
            callback_count += 1
            raise AssertionError("detach compared a concurrently changing source field")

    hostile = CallbackSpy()

    def mutate_source() -> None:
        ready.set()
        while not stop.is_set():
            object.__setattr__(receipt, "_result_digest", hostile)
            object.__setattr__(runtime_receipt, "_runtime_token", hostile)
            object.__setattr__(receipt, "_result_digest", "b" * 64)
            object.__setattr__(runtime_receipt, "_runtime_token", 7)

    mutation = Thread(target=mutate_source)
    mutation.start()
    assert ready.wait(timeout=1)
    try:
        observed = tuple(authority.detach_prepared_network_receipt(receipt) for _ in range(100))
    finally:
        stop.set()
        mutation.join(timeout=1)

    assert not mutation.is_alive()
    assert all(binding == expected for binding in observed)
    assert callback_count == 0


def test_detach_rejects_copied_and_foreign_source_receipt_identity() -> None:
    authority, receipt = _committed_receipt(stable_id="issuance-source-identity")
    foreign, foreign_receipt = _committed_receipt(stable_id="foreign-source-identity")

    with pytest.raises(StateError, match="authentic prepared-network receipt"):
        authority.detach_prepared_network_receipt(copy.copy(receipt))
    with pytest.raises(StateError, match="authentic prepared-network receipt"):
        authority.detach_prepared_network_receipt(foreign_receipt)
    with pytest.raises(StateError, match="authentic prepared-network receipt"):
        foreign.detach_prepared_network_receipt(receipt)


@pytest.mark.parametrize("__dunder__", ["__repr__", "__eq__", "__hash__", "__getattribute__"])
def test_detach_never_invokes_mutated_source_class_behavior(
    monkeypatch: pytest.MonkeyPatch,
    __dunder__: str,
) -> None:
    authority, receipt = _committed_receipt(stable_id=f"source-class-{__dunder__}")
    expected = authority.detach_prepared_network_receipt(receipt)
    callback_count = 0

    def hostile(*_args: object, **_kwargs: object) -> object:
        nonlocal callback_count
        callback_count += 1
        raise AssertionError("detach invoked live source class behavior")

    monkeypatch.setattr(LifecyclePreparedNetworkReceipt, __dunder__, hostile)

    assert authority.detach_prepared_network_receipt(receipt) == expected
    assert callback_count == 0


def test_detach_ignores_obsolete_caller_graph_helper_aliases(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    authority, receipt = _committed_receipt(stable_id="obsolete-graph-aliases")
    expected = authority.detach_prepared_network_receipt(receipt)
    callback_count = 0

    def hostile(*_args: object, **_kwargs: object) -> object:
        nonlocal callback_count
        callback_count += 1
        raise AssertionError("obsolete caller-graph helper ran")

    for name in (
        "_detached_network_receipt_preflight",
        "_detached_network_receipt_graph_preflight",
        "_detached_network_binding_capture",
        "_lifecycle_detached_network_receipt_binding_values_payload",
        "_detached_network_binding_digest",
    ):
        monkeypatch.setattr(lifecycle_authority_module, name, hostile, raising=False)
    monkeypatch.setattr(
        GeneratorLifecycleAuthority,
        "_authenticate_detached_network_receipt_capture",
        hostile,
        raising=False,
    )
    monkeypatch.setattr(
        GeneratorLifecycleAuthority,
        "_detached_network_receipt_binding_values",
        hostile,
        raising=False,
    )
    monkeypatch.setattr(
        authority,
        "_construct_detached_network_receipt_binding",
        hostile,
    )
    monkeypatch.setattr(
        authority,
        "authenticates_detached_network_receipt_binding",
        hostile,
    )

    assert authority.detach_prepared_network_receipt(receipt) == expected
    assert callback_count == 0


def test_prepared_receipt_issuance_uses_safe_shell_and_frozen_helpers(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    callback_count = 0

    def hostile(*_args: object, **_kwargs: object) -> object:
        nonlocal callback_count
        callback_count += 1
        raise AssertionError("live prepared-receipt allocator or helper ran")

    with monkeypatch.context() as context:
        context.setattr(LifecyclePreparedNetworkReceipt, "__init__", hostile)
        context.setattr(LifecyclePreparedNetworkReceipt, "_issue", classmethod(hostile))
        context.setattr(LifecyclePreparedNetworkReceipt, "_integrity_for", staticmethod(hostile))
        context.setattr(
            lifecycle_authority_module,
            "_allocate_prepared_network_receipt_shell",
            hostile,
        )
        authority, receipt = _committed_receipt(
            stable_id="safe-receipt-shell",
            authenticate=False,
        )
        binding = authority.detach_prepared_network_receipt(receipt)

    assert callback_count == 0
    assert authority.authenticates_detached_network_receipt_binding(binding)


def test_detach_lost_return_reconstructs_an_equal_fresh_binding() -> None:
    authority, receipt = _committed_receipt(stable_id="detached-lost-return")
    lost = authority.detach_prepared_network_receipt(receipt)
    expected = copy.copy(lost)
    del lost

    observed = authority.detach_prepared_network_receipt(receipt)

    assert observed is not expected
    assert observed == expected
    assert authority.authenticates_detached_network_receipt_binding(observed)


def test_weak_issuance_authority_reclaims_without_census_change() -> None:
    authority, receipt = _committed_receipt(stable_id="issuance-authority-gc")
    receipt_reference = weakref.ref(receipt)
    census = authority.census()
    authorities = authority._prepared_network_receipt_authorities

    assert len(authorities) == 1
    authority.detach_prepared_network_receipt(receipt)
    assert authority.census() == census

    del receipt
    gc.collect()

    assert receipt_reference() is None
    assert authorities == {}
    assert authority.census() == census


def test_issuance_authority_capacity_gc_and_reuse_matrix() -> None:
    (
        authority,
        runtime,
        planner,
        first_root,
        first_timing,
        first_rng,
        first_lifecycle,
    ) = _prepared_fixture(
        stable_id="authority-capacity-first",
        preparation_authority_capacity=1,
    )
    first_result = authority.materialize_prepared_network_transaction(
        first_root,
        first_rng,
        source_timing_preparation=first_timing,
        lifecycle_token=first_lifecycle,
    )
    records = authority._prepared_network_receipt_authorities
    issuances = authority._prepared_network_receipt_issuances
    assert len(records) == 1
    assert len(issuances) == 1

    second_root, second_timing, second_rng, second_lifecycle = _prepare_root(
        authority,
        runtime,
        planner,
        stable_id="authority-capacity-second",
        src_port=50_002,
    )
    with pytest.raises(StateError, match="capacity"):
        authority.materialize_prepared_network_transaction(
            second_root,
            second_rng,
            source_timing_preparation=second_timing,
            lifecycle_token=second_lifecycle,
        )
    assert len(records) == 1
    assert len(issuances) == 1
    assert authority._state_manager.materialization_version == 1

    authority.acknowledge_prepared_network_transaction(first_root, first_result)
    assert issuances == {}
    first_receipt_ref = weakref.ref(first_result.receipt)
    del first_lifecycle, first_result, first_rng, first_root, first_timing
    gc.collect()
    assert first_receipt_ref() is None
    assert records == {}

    third_root, third_timing, third_rng, third_lifecycle = _prepare_root(
        authority,
        runtime,
        planner,
        stable_id="authority-capacity-third",
        src_port=50_003,
    )
    third_result = authority.materialize_prepared_network_transaction(
        third_root,
        third_rng,
        source_timing_preparation=third_timing,
        lifecycle_token=third_lifecycle,
    )
    assert len(records) == 1
    assert authority.authenticates_detached_network_receipt_binding(
        authority.detach_prepared_network_receipt(third_result.receipt)
    )


def test_detach_count_does_not_grow_authority_or_public_census() -> None:
    authority, receipt = _committed_receipt(stable_id="bounded-detach-count")
    census = authority.census()
    records = authority._prepared_network_receipt_authorities
    retained_record = next(iter(records.values()))

    bindings = tuple(authority.detach_prepared_network_receipt(receipt) for _ in range(1_000))

    assert len(records) == 1
    assert next(iter(records.values())) is retained_record
    assert authority.census() == census
    assert all(authority.authenticates_detached_network_receipt_binding(item) for item in bindings)


def test_acknowledged_issuance_retains_no_root_or_timing_preparation() -> None:
    authority, _runtime, _planner, root, timing, owner_rng, lifecycle_token = _prepared_fixture(
        stable_id="no-root-or-timing-retention"
    )
    timing_reference = weakref.ref(timing)
    result = authority.materialize_prepared_network_transaction(
        root,
        owner_rng,
        source_timing_preparation=timing,
        lifecycle_token=lifecycle_token,
    )
    record = next(iter(authority._prepared_network_receipt_authorities.values()))
    carrier = next(iter(authority._prepared_network_receipt_issuances.values()))
    assert carrier.root is root
    assert type(record.detached_values) is tuple
    assert all(type(value) in {str, int, type(None)} for value in record.detached_values)
    assert not any(
        isinstance(
            object.__getattribute__(record, member.name),
            (PreparedNetworkTransactionRoot, SourceTimingPreparation),
        )
        for member in fields(record)
    )

    binding = authority.detach_prepared_network_receipt(result.receipt)
    authority.acknowledge_prepared_network_transaction(root, result)
    assert authority._prepared_network_receipt_issuances == {}
    del lifecycle_token, owner_rng, root, timing
    gc.collect()

    assert timing_reference() is None
    assert authority.authenticates_detached_network_receipt_binding(binding)


def test_uncommitted_or_tampered_private_record_fails_closed() -> None:
    authority, receipt = _committed_receipt(stable_id="private-record-fail-closed")
    record = next(iter(authority._prepared_network_receipt_authorities.values()))
    object.__setattr__(record, "committed", False)

    with pytest.raises(StateError, match="authentic prepared-network receipt"):
        authority.detach_prepared_network_receipt(receipt)


def test_reclaimed_source_authority_is_stale_and_rejected() -> None:
    authority, receipt = _committed_receipt(stable_id="reclaimed-source-authority")
    records = authority._prepared_network_receipt_authorities
    records.pop(id(receipt))

    with pytest.raises(StateError, match="authentic prepared-network receipt"):
        authority.detach_prepared_network_receipt(receipt)


@pytest.mark.parametrize(
    "lost_return_seam",
    (
        "_issue_prepared_network_receipt_recoverably",
        "_commit_prepared_network_receipt_authority",
    ),
)
def test_prepared_network_issuance_tail_lost_return_adopts_exact_terminal_receipt(
    monkeypatch: pytest.MonkeyPatch,
    lost_return_seam: str,
) -> None:
    (
        authority,
        _runtime,
        planner,
        root,
        timing,
        owner_rng,
        lifecycle_token,
    ) = _prepared_fixture(stable_id=f"issuance-tail-lost-{lost_return_seam}")
    original = object.__getattribute__(authority, lost_return_seam)
    lost_receipt_reference: weakref.ReferenceType[LifecyclePreparedNetworkReceipt] | None = None
    callback_count = 0

    def call_original_then_raise(*args: object, **kwargs: object) -> object:
        nonlocal callback_count, lost_receipt_reference
        callback_count += 1
        returned = original(*args, **kwargs)
        receipt = (
            returned
            if type(returned) is LifecyclePreparedNetworkReceipt
            else kwargs.get("receipt_shell", args[0] if args else None)
        )
        assert type(receipt) is LifecyclePreparedNetworkReceipt
        lost_receipt_reference = weakref.ref(receipt)
        raise RuntimeError(f"lost return after {lost_return_seam}")

    with monkeypatch.context() as context:
        context.setattr(authority, lost_return_seam, call_original_then_raise)
        with pytest.raises(RuntimeError, match="lost return"):
            authority.materialize_prepared_network_transaction(
                root,
                owner_rng,
                source_timing_preparation=timing,
                lifecycle_token=lifecycle_token,
            )

    assert callback_count == 1
    assert authority._state_manager.materialization_version == 1
    assert lost_receipt_reference is not None
    gc.collect()
    lost_receipt = lost_receipt_reference()
    assert lost_receipt is not None

    result = authority.materialize_prepared_network_transaction(
        root,
        owner_rng,
        source_timing_preparation=timing,
        lifecycle_token=lifecycle_token,
    )

    assert authority._state_manager.materialization_version == 1
    assert result.receipt is lost_receipt
    assert len(authority._prepared_network_receipt_issuances) == 1
    assert len(authority._prepared_network_receipt_authorities) == 1
    assert planner.preparation_authority_census().retained_receipts == 1

    authority.acknowledge_prepared_network_transaction(root, result)
    receipt_reference = weakref.ref(result.receipt)
    del lifecycle_token, lost_receipt, owner_rng, result, root, timing
    gc.collect()

    assert receipt_reference() is None
    assert authority._prepared_network_receipt_issuances == {}
    assert authority._prepared_network_receipt_authorities == {}
    assert planner.preparation_authority_census().retained_receipts == 0


@pytest.mark.parametrize(
    "altered_argument_seam",
    (
        "_issue_prepared_network_receipt_recoverably",
        "_commit_prepared_network_receipt_authority",
    ),
)
def test_prepared_network_issuance_tail_rejects_altered_arguments_before_sidecar_commit(
    monkeypatch: pytest.MonkeyPatch,
    altered_argument_seam: str,
) -> None:
    (
        authority,
        _runtime,
        _planner,
        root,
        timing,
        owner_rng,
        lifecycle_token,
    ) = _prepared_fixture(stable_id=f"issuance-tail-altered-{altered_argument_seam}")
    original = object.__getattribute__(authority, altered_argument_seam)
    callback_count = 0

    def alter_then_call(*args: object, **kwargs: object) -> object:
        nonlocal callback_count
        callback_count += 1
        if altered_argument_seam == "_issue_prepared_network_receipt_recoverably":
            changed = dict(kwargs)
            changed["transaction_id"] = "attacker-selected-transaction"
            return original(*args, **changed)
        changed_args = list(args)
        assert len(changed_args) == 6
        changed_args[2] = int(changed_args[2]) + 1
        return original(*changed_args, **kwargs)

    with monkeypatch.context() as context:
        context.setattr(authority, altered_argument_seam, alter_then_call)
        with pytest.raises(AssertionError, match="authority changed before seal"):
            authority.materialize_prepared_network_transaction(
                root,
                owner_rng,
                source_timing_preparation=timing,
                lifecycle_token=lifecycle_token,
            )

    assert callback_count == 1
    assert authority._state_manager.materialization_version == 1
    carrier = next(iter(authority._prepared_network_receipt_issuances.values()))
    receipt = carrier.receipt
    sidecar = authority._prepared_network_receipt_authorities[id(receipt)]
    assert not sidecar.committed
    assert sidecar.detached_values is None
    assert sidecar.detached_proof == ""

    result = authority.materialize_prepared_network_transaction(
        root,
        owner_rng,
        source_timing_preparation=timing,
        lifecycle_token=lifecycle_token,
    )

    assert authority._state_manager.materialization_version == 1
    assert result.receipt is receipt
    assert sidecar.detached_proof == object.__getattribute__(receipt, "_integrity_token")
    binding = authority.detach_prepared_network_receipt(result.receipt)
    assert binding.transaction_id == root.transaction.stable_id
    assert authority.authenticates_detached_network_receipt_binding(binding)
    authority.acknowledge_prepared_network_transaction(root, result)


@pytest.mark.parametrize(
    "skipped_seam",
    (
        "_issue_prepared_network_receipt_recoverably",
        "_commit_prepared_network_receipt_authority",
    ),
)
def test_prepared_network_issuance_tail_skip_original_recovers_same_carrier(
    monkeypatch: pytest.MonkeyPatch,
    skipped_seam: str,
) -> None:
    (
        authority,
        _runtime,
        _planner,
        root,
        timing,
        owner_rng,
        lifecycle_token,
    ) = _prepared_fixture(stable_id=f"issuance-tail-skip-{skipped_seam}")
    callback_count = 0

    def skip_original(*args: object, **kwargs: object) -> object:
        nonlocal callback_count
        callback_count += 1
        if skipped_seam == "_issue_prepared_network_receipt_recoverably":
            return kwargs["receipt_shell"]
        return None

    with monkeypatch.context() as context:
        context.setattr(authority, skipped_seam, skip_original)
        with pytest.raises(AssertionError, match="did not seal"):
            authority.materialize_prepared_network_transaction(
                root,
                owner_rng,
                source_timing_preparation=timing,
                lifecycle_token=lifecycle_token,
            )

    assert callback_count == 1
    assert authority._state_manager.materialization_version == 1
    carrier = next(iter(authority._prepared_network_receipt_issuances.values()))
    receipt = carrier.receipt
    sidecar = authority._prepared_network_receipt_authorities[id(receipt)]
    assert not sidecar.committed

    result = authority.materialize_prepared_network_transaction(
        root,
        owner_rng,
        source_timing_preparation=timing,
        lifecycle_token=lifecycle_token,
    )

    assert authority._state_manager.materialization_version == 1
    assert result.receipt is receipt
    assert authority.authenticates_prepared_network_receipt(root, result.receipt)
    authority.acknowledge_prepared_network_transaction(root, result)


def test_prepared_network_issuance_tail_fake_return_keeps_original_terminal(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    (
        authority,
        _runtime,
        _planner,
        root,
        timing,
        owner_rng,
        lifecycle_token,
    ) = _prepared_fixture(stable_id="issuance-tail-fake-return")
    original = authority._issue_prepared_network_receipt_recoverably
    original_receipt_reference: weakref.ReferenceType[LifecyclePreparedNetworkReceipt] | None = None

    def return_copy_after_original(*args: object, **kwargs: object) -> object:
        nonlocal original_receipt_reference
        receipt = original(*args, **kwargs)
        original_receipt_reference = weakref.ref(receipt)
        return copy.copy(receipt)

    with monkeypatch.context() as context:
        context.setattr(
            authority,
            "_issue_prepared_network_receipt_recoverably",
            return_copy_after_original,
        )
        with pytest.raises(AssertionError, match="shell identity changed"):
            authority.materialize_prepared_network_transaction(
                root,
                owner_rng,
                source_timing_preparation=timing,
                lifecycle_token=lifecycle_token,
            )

    assert authority._state_manager.materialization_version == 1
    assert original_receipt_reference is not None
    receipt = original_receipt_reference()
    assert receipt is not None
    carrier = next(iter(authority._prepared_network_receipt_issuances.values()))
    assert carrier.terminal
    assert carrier.receipt is receipt

    result = authority.materialize_prepared_network_transaction(
        root,
        owner_rng,
        source_timing_preparation=timing,
        lifecycle_token=lifecycle_token,
    )

    assert authority._state_manager.materialization_version == 1
    assert result.receipt is receipt
    assert authority.authenticates_prepared_network_receipt(root, result.receipt)
    authority.acknowledge_prepared_network_transaction(root, result)


@pytest.mark.parametrize(
    "commit_argument",
    (
        "receipt",
        "timing",
        "generation",
        "detached_values",
        "detached_proof",
    ),
)
def test_prepared_network_sidecar_validates_every_carrier_argument_before_mutation(
    monkeypatch: pytest.MonkeyPatch,
    commit_argument: str,
) -> None:
    (
        authority,
        _runtime,
        _planner,
        root,
        timing,
        owner_rng,
        lifecycle_token,
    ) = _prepared_fixture(stable_id=f"sidecar-argument-{commit_argument}")
    original = authority._commit_prepared_network_receipt_authority

    def alter_one_argument(*args: object, **kwargs: object) -> object:
        changed = list(args)
        assert len(changed) == 6
        if commit_argument == "receipt":
            changed[0] = copy.copy(changed[0])
        elif commit_argument == "timing":
            changed[1] = copy.copy(changed[1])
        elif commit_argument == "generation":
            changed[2] = int(changed[2]) + 1
        elif commit_argument == "detached_values":
            values = list(changed[3])
            values[15] = "b" * 64
            changed[3] = tuple(values)
        elif commit_argument == "detached_proof":
            changed[4] = "b" * 64
        return original(*changed, **kwargs)

    with monkeypatch.context() as context:
        context.setattr(
            authority,
            "_commit_prepared_network_receipt_authority",
            alter_one_argument,
        )
        with pytest.raises(AssertionError, match="authority changed before seal"):
            authority.materialize_prepared_network_transaction(
                root,
                owner_rng,
                source_timing_preparation=timing,
                lifecycle_token=lifecycle_token,
            )

    assert authority._state_manager.materialization_version == 1
    carrier = next(iter(authority._prepared_network_receipt_issuances.values()))
    sidecar = authority._prepared_network_receipt_authorities[id(carrier.receipt)]
    assert carrier.authority_record is sidecar
    assert not sidecar.committed
    assert sidecar.detached_values is None

    result = authority.materialize_prepared_network_transaction(
        root,
        owner_rng,
        source_timing_preparation=timing,
        lifecycle_token=lifecycle_token,
    )

    assert authority._state_manager.materialization_version == 1
    assert result.receipt is carrier.receipt
    assert authority._prepared_network_receipt_authorities[id(carrier.receipt)] is sidecar
    assert authority.authenticates_prepared_network_receipt(root, result.receipt)
    authority.acknowledge_prepared_network_transaction(root, result)


def test_prepared_network_acknowledgement_is_exact_and_generation_cas() -> None:
    authority, _runtime, _planner, root, timing, owner_rng, lifecycle_token = _prepared_fixture(
        stable_id="issuance-exact-ack"
    )
    result = authority.materialize_prepared_network_transaction(
        root,
        owner_rng,
        source_timing_preparation=timing,
        lifecycle_token=lifecycle_token,
    )
    copied_result = copy.copy(result)
    foreign = _prepared_fixture(stable_id="issuance-foreign-ack")[0]

    with pytest.raises(StateError, match="not canonical"):
        authority.acknowledge_prepared_network_transaction(root, copied_result)
    with pytest.raises(StateError, match="not retained"):
        foreign.acknowledge_prepared_network_transaction(root, result)

    authority.acknowledge_prepared_network_transaction(root, result)

    assert authority._prepared_network_receipt_issuances == {}
    assert authority._prepared_network_receipt_issuance_generations == {}
    assert authority._prepared_network_receipt_issuance_receipts == {}
    assert not authority.acknowledge_prepared_network_transaction_if_retained(root, result)
    with pytest.raises(StateError, match="root failed|timing capability"):
        authority.materialize_prepared_network_transaction(
            root,
            owner_rng,
            source_timing_preparation=timing,
            lifecycle_token=lifecycle_token,
        )


def test_prepared_network_authentication_is_repeatable_and_read_only() -> None:
    authority, _runtime, _planner, root, timing, owner_rng, lifecycle_token = _prepared_fixture(
        stable_id="authentication-read-only"
    )
    result = authority.materialize_prepared_network_transaction(
        root,
        owner_rng,
        source_timing_preparation=timing,
        lifecycle_token=lifecycle_token,
    )
    retained = next(iter(authority._prepared_network_receipt_issuances.values()))

    assert authority.authenticates_prepared_network_receipt(root, result.receipt)
    assert authority.authenticates_prepared_network_receipt(root, result.receipt)
    assert next(iter(authority._prepared_network_receipt_issuances.values())) is retained

    authority.acknowledge_prepared_network_transaction(root, result)


@pytest.mark.soak
def test_production_handoff_retires_capacity_one_carrier_for_repeated_transactions() -> None:
    (
        authority,
        runtime,
        planner,
        root,
        timing,
        owner_rng,
        lifecycle_token,
    ) = _prepared_fixture(
        stable_id="production-retirement-0",
        preparation_authority_capacity=1,
    )

    for index in range(1_000):
        if index:
            root, timing, owner_rng, lifecycle_token = _prepare_root(
                authority,
                runtime,
                planner,
                stable_id=f"production-retirement-{index}",
                src_port=51_000 + index,
            )
        result = authority.materialize_prepared_network_transaction(
            root,
            owner_rng,
            source_timing_preparation=timing,
            lifecycle_token=lifecycle_token,
        )
        assert authority.authenticates_prepared_network_receipt(root, result.receipt)
        authority.acknowledge_prepared_network_transaction(root, result)
        assert authority._prepared_network_receipt_issuances == {}
        del lifecycle_token, owner_rng, result, root, timing
        gc.collect()
        assert authority._prepared_network_receipt_authorities == {}
        assert planner.preparation_authority_census().retained_receipts == 0


def test_prepared_network_sidecar_constructor_is_zero_callback(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    authority, _runtime, _planner, root, timing, owner_rng, lifecycle_token = _prepared_fixture(
        stable_id="sidecar-constructor-zero-callback"
    )
    callback_count = 0

    def hostile_constructor(*_args: object, **_kwargs: object) -> None:
        nonlocal callback_count
        callback_count += 1
        raise AssertionError("live sidecar constructor ran")

    monkeypatch.setattr(
        lifecycle_authority_module._PreparedNetworkReceiptAuthority,
        "__init__",
        hostile_constructor,
    )

    result = authority.materialize_prepared_network_transaction(
        root,
        owner_rng,
        source_timing_preparation=timing,
        lifecycle_token=lifecycle_token,
    )

    assert callback_count == 0
    assert authority.authenticates_prepared_network_receipt(root, result.receipt)


def test_prepared_network_sidecar_never_decrefs_under_timing_lock(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    authority, _runtime, planner, root, timing, owner_rng, lifecycle_token = _prepared_fixture(
        stable_id="sidecar-decref-outside-lock"
    )
    authority_lock = planner._preparation_authority_lock
    destructor_calls = 0
    under_lock_calls = 0

    def observe_destructor(_record: object) -> None:
        nonlocal destructor_calls, under_lock_calls
        destructor_calls += 1
        if authority_lock._is_owned():
            under_lock_calls += 1

    monkeypatch.setattr(
        lifecycle_authority_module._PreparedNetworkReceiptAuthority,
        "__del__",
        observe_destructor,
        raising=False,
    )

    result = authority.materialize_prepared_network_transaction(
        root,
        owner_rng,
        source_timing_preparation=timing,
        lifecycle_token=lifecycle_token,
    )
    authority.acknowledge_prepared_network_transaction(root, result)
    del result
    gc.collect()

    assert destructor_calls >= 1
    assert under_lock_calls == 0


def _production_generator(
    family: str,
) -> tuple[ActivityGenerator, Mock, System | None]:
    """Return a real planner owner with a capacity-one recovery carrier."""

    state = StateManager()
    state.set_current_time(_START)
    emitter = Mock()
    emitter.can_handle.return_value = True
    generator = ActivityGenerator(
        state,
        {
            "zeek_conn": emitter,
            "zeek_dns": emitter,
            "zeek_http": emitter,
            "zeek_ssl": emitter,
            "proxy_access": emitter,
        },
        generation_window_start=_START - timedelta(hours=1),
        generation_window_end=_END,
    )
    generator._lifecycle_authority._prepared_network_receipt_issuance_capacity = 1
    if family != "proxy":
        return generator, emitter, None

    workstation = System(
        hostname="WKS-01",
        ip="10.0.1.10",
        os="Windows 11",
        type="workstation",
        assigned_user="alex.morgan",
    )
    proxy = System(
        hostname="PROXY-01",
        ip="10.0.3.10",
        os="Linux Ubuntu 22.04",
        type="server",
        roles=["forward_proxy"],
    )
    generator._ip_to_system = {
        workstation.ip: workstation,
        proxy.ip: proxy,
    }
    generator._proxy_routes = {workstation.ip: [proxy]}
    generator._proxy_mode = "explicit"
    generator._proxy_listener_port = 8080
    generator._ad_domain = "example.org"

    return generator, emitter, workstation


def _publish_production_connection(
    generator: ActivityGenerator,
    *,
    family: str,
    index: int,
    source_system: System | None,
    capture: NetworkConnectionIdentityCapture | None,
) -> str:
    """Run one ordinary, HTTP, or explicit-proxy production planner transaction."""

    started_at = _START + timedelta(seconds=index * 10)
    if family == "proxy":
        assert source_system is not None
        return generator.generate_connection(
            src_ip=source_system.ip,
            dst_ip="93.184.216.34",
            time=started_at,
            dst_port=443,
            proto="tcp",
            service="https",
            duration=1.0,
            orig_bytes=500,
            resp_bytes=5_000,
            source_system=source_system,
            hostname=f"origin-{index}.example.test",
            conn_state="SF",
            identity_capture=capture,
        )

    return generator.generate_connection(
        src_ip="10.0.0.10",
        src_port=50_000 + index,
        dst_ip="203.0.113.20",
        time=started_at,
        dst_port=80 if family == "http" else 8_443,
        proto="tcp",
        service="http" if family == "http" else "",
        duration=0.25,
        orig_bytes=64,
        resp_bytes=128,
        conn_state="SF",
        hostname="example.test" if family == "http" else "",
        preserve_start_time=True,
        suppress_application_side_effects=family != "http",
        suppress_source_pid_inference=True,
        preserve_explicit_payload=True,
        suppress_prereq_dns=True,
        http=(
            HttpContext(
                method="GET",
                host="example.test",
                uri=f"/{index}",
                status_code=200,
            )
            if family == "http"
            else None
        ),
        identity_capture=capture,
    )


@pytest.mark.soak
@pytest.mark.parametrize("family", ("ordinary", "http", "proxy"))
def test_production_planner_retires_capacity_one_carrier_for_one_thousand_handoffs(
    family: str,
) -> None:
    generator, emitter, source_system = _production_generator(family)
    authority = generator._lifecycle_authority
    planner = generator._source_timing_planner

    for index in range(1_000):
        capture = NetworkConnectionIdentityCapture()
        _publish_production_connection(
            generator,
            family=family,
            index=index,
            source_system=source_system,
            capture=capture,
        )
        if family != "proxy":
            root = capture.require_prepared_root()
            receipt = capture.require_receipt()
            assert authority.authenticates_prepared_network_receipt(root, receipt)
            assert authority.authenticates_prepared_network_receipt(root, receipt)
        assert authority._prepared_network_receipt_issuances == {}
        assert authority._prepared_network_receipt_issuance_generations == {}
        assert authority._prepared_network_receipt_issuance_receipts == {}

    del capture
    if family != "proxy":
        del receipt, root
    emitter.reset_mock()
    gc.collect()
    assert authority._prepared_network_receipt_authorities == {}
    assert planner.preparation_authority_census().retained_receipts == 0


@pytest.mark.parametrize("failing_authentication_call", (1, 2))
def test_production_authentication_lost_return_preserves_exact_retry_owner(
    monkeypatch: pytest.MonkeyPatch,
    failing_authentication_call: int,
) -> None:
    generator, _emitter, _source_system = _production_generator("ordinary")
    authority = generator._lifecycle_authority
    capture = NetworkConnectionIdentityCapture()
    original = authority.authenticates_prepared_network_receipt
    callback_count = 0

    def authenticate_then_lose(root: object, receipt: object) -> bool:
        nonlocal callback_count
        callback_count += 1
        authenticated = original(root, receipt)
        if callback_count == failing_authentication_call:
            raise RuntimeError("lost authentication return")
        return authenticated

    monkeypatch.setattr(
        authority,
        "authenticates_prepared_network_receipt",
        authenticate_then_lose,
    )
    with pytest.raises(RuntimeError, match="lost authentication"):
        _publish_production_connection(
            generator,
            family="ordinary",
            index=failing_authentication_call,
            source_system=None,
            capture=capture,
        )
    monkeypatch.delattr(authority, "authenticates_prepared_network_receipt")

    carrier = next(iter(authority._prepared_network_receipt_issuances.values()))
    assert authority.state_manager.materialization_version == 1
    assert capture.require_prepared_root() is carrier.root
    assert capture.require_receipt() is carrier.receipt

    recovered = authority.materialize_prepared_network_transaction(
        carrier.root,
        random.Random(0),
        source_timing_preparation=None,
        lifecycle_token=None,
    )
    assert recovered is carrier.result
    assert recovered.receipt is carrier.receipt
    assert authority.authenticates_prepared_network_receipt(
        carrier.root,
        recovered.receipt,
    )
    authority.acknowledge_prepared_network_transaction(carrier.root, recovered)


@pytest.mark.parametrize("capture_field", ("_prepared_root", "_receipt", "_outcome"))
def test_production_capture_drift_before_ack_retains_exact_retry_owner(
    monkeypatch: pytest.MonkeyPatch,
    capture_field: str,
) -> None:
    generator, _emitter, _source_system = _production_generator("ordinary")
    authority = generator._lifecycle_authority
    runtime = authority._network_runtime
    planner = generator._source_timing_planner
    assert runtime is not None
    capture = NetworkConnectionIdentityCapture()
    original = runtime.authenticates_preparation_receipt
    token_authentication_calls = 0

    def authenticate_then_erase_capture_receipt(
        receipt: object,
        *args: object,
        _capture: NetworkConnectionIdentityCapture = capture,
        **kwargs: object,
    ) -> bool:
        nonlocal token_authentication_calls
        authenticated = original(receipt, *args, **kwargs)
        if kwargs.get("token") is not None:
            token_authentication_calls += 1
            if token_authentication_calls == 2:
                object.__setattr__(_capture, capture_field, None)
        return authenticated

    monkeypatch.setattr(
        runtime,
        "authenticates_preparation_receipt",
        authenticate_then_erase_capture_receipt,
    )
    with pytest.raises(StateError, match="durable identity capture") as raised:
        _publish_production_connection(
            generator,
            family="ordinary",
            index=22,
            source_system=None,
            capture=capture,
        )
    monkeypatch.undo()

    assert token_authentication_calls == 2
    carrier = next(iter(authority._prepared_network_receipt_issuances.values()))
    assert authority.state_manager.materialization_version == 1
    assert object.__getattribute__(capture, capture_field) is None

    expected_capture_value = {
        "_prepared_root": carrier.root,
        "_receipt": carrier.receipt,
        "_outcome": NetworkConnectionPublicationOutcome.PUBLISHED,
    }[capture_field]
    object.__setattr__(capture, capture_field, expected_capture_value)
    assert capture.require_prepared_root() is carrier.root
    assert capture.require_receipt() is carrier.receipt
    recovered = authority.materialize_prepared_network_transaction(
        carrier.root,
        random.Random(0),
        source_timing_preparation=None,
        lifecycle_token=None,
    )
    assert recovered is carrier.result
    assert authority.state_manager.materialization_version == 1
    assert authority.authenticates_prepared_network_receipt(carrier.root, carrier.receipt)
    authority.acknowledge_prepared_network_transaction(carrier.root, recovered)

    del (
        authenticate_then_erase_capture_receipt,
        capture,
        carrier,
        expected_capture_value,
        raised,
        recovered,
    )
    gc.collect()
    assert authority._prepared_network_receipt_issuances == {}
    assert authority._prepared_network_receipt_issuance_generations == {}
    assert authority._prepared_network_receipt_issuance_receipts == {}
    assert authority._prepared_network_receipt_authorities == {}
    assert planner.preparation_authority_census().retained_receipts == 0


def test_production_ack_callback_revalidates_durable_capture_before_cas(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    generator, _emitter, _source_system = _production_generator("ordinary")
    authority = generator._lifecycle_authority
    capture = NetworkConnectionIdentityCapture()
    original = authority.acknowledge_prepared_network_transaction
    callback_count = 0

    def alter_capture_then_acknowledge(
        root: PreparedNetworkTransactionRoot,
        result: LifecyclePreparedNetworkResult,
        **_kwargs: object,
    ) -> None:
        nonlocal callback_count
        callback_count += 1
        object.__setattr__(capture, "_receipt", None)
        original(root, result)

    monkeypatch.setattr(
        authority,
        "acknowledge_prepared_network_transaction",
        alter_capture_then_acknowledge,
    )
    with pytest.raises(StateError, match="acknowledgement is not canonical"):
        _publish_production_connection(
            generator,
            family="ordinary",
            index=23,
            source_system=None,
            capture=capture,
        )
    monkeypatch.delattr(authority, "acknowledge_prepared_network_transaction")

    assert callback_count == 1
    carrier = next(iter(authority._prepared_network_receipt_issuances.values()))
    assert authority.state_manager.materialization_version == 1
    assert capture.require_receipt() is carrier.receipt
    recovered = authority.materialize_prepared_network_transaction(
        carrier.root,
        random.Random(0),
        source_timing_preparation=None,
        lifecycle_token=None,
    )
    assert recovered is carrier.result
    assert authority.state_manager.materialization_version == 1
    authority.acknowledge_prepared_network_transaction(carrier.root, recovered)
    assert authority._prepared_network_receipt_issuances == {}


@pytest.mark.parametrize("capture_field", ("_prepared_root", "_receipt", "_outcome"))
def test_production_post_ack_capture_drift_is_repaired_before_success(
    monkeypatch: pytest.MonkeyPatch,
    capture_field: str,
) -> None:
    generator, emitter, _source_system = _production_generator("ordinary")
    authority = generator._lifecycle_authority
    planner = generator._source_timing_planner
    capture = NetworkConnectionIdentityCapture()
    original = authority.acknowledge_prepared_network_transaction
    callback_count = 0

    def acknowledge_then_alter_capture(
        root: PreparedNetworkTransactionRoot,
        result: LifecyclePreparedNetworkResult,
        _capture: NetworkConnectionIdentityCapture = capture,
        **_kwargs: object,
    ) -> None:
        nonlocal callback_count
        original(root, result)
        callback_count += 1
        object.__setattr__(_capture, capture_field, None)

    monkeypatch.setattr(
        authority,
        "acknowledge_prepared_network_transaction",
        acknowledge_then_alter_capture,
    )
    connection_id = _publish_production_connection(
        generator,
        family="ordinary",
        index=24,
        source_system=None,
        capture=capture,
    )
    monkeypatch.undo()

    assert type(connection_id) is str
    assert connection_id
    assert callback_count == 1
    root = capture.require_prepared_root()
    receipt = capture.require_receipt()
    assert capture.require_outcome() is NetworkConnectionPublicationOutcome.PUBLISHED
    assert authority.authenticates_prepared_network_receipt(root, receipt)
    assert authority.state_manager.materialization_version == 1
    assert authority._prepared_network_receipt_issuances == {}
    assert authority._prepared_network_receipt_issuance_generations == {}
    assert authority._prepared_network_receipt_issuance_receipts == {}

    del acknowledge_then_alter_capture, capture, connection_id, receipt, root
    emitter.reset_mock()
    gc.collect()
    assert authority._prepared_network_receipt_authorities == {}
    assert planner.preparation_authority_census().retained_receipts == 0


def test_production_acknowledgement_lost_return_uses_durable_capture(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    generator, _emitter, _source_system = _production_generator("ordinary")
    authority = generator._lifecycle_authority
    capture = NetworkConnectionIdentityCapture()
    original = authority.acknowledge_prepared_network_transaction
    callback_count = 0

    def acknowledge_then_lose(
        root: PreparedNetworkTransactionRoot,
        result: LifecyclePreparedNetworkResult,
        _capture: NetworkConnectionIdentityCapture = capture,
        **_kwargs: object,
    ) -> None:
        nonlocal callback_count
        original(root, result)
        callback_count += 1
        object.__setattr__(_capture, "_receipt", None)
        raise RuntimeError("lost acknowledgement return")

    monkeypatch.setattr(
        authority,
        "acknowledge_prepared_network_transaction",
        acknowledge_then_lose,
    )
    with pytest.raises(RuntimeError, match="lost acknowledgement"):
        _publish_production_connection(
            generator,
            family="ordinary",
            index=3,
            source_system=None,
            capture=capture,
        )

    assert callback_count == 1
    root = capture.require_prepared_root()
    receipt = capture.require_receipt()
    assert capture.require_outcome() is NetworkConnectionPublicationOutcome.PUBLISHED
    assert authority.authenticates_prepared_network_receipt(root, receipt)
    assert authority.state_manager.materialization_version == 1
    assert authority._prepared_network_receipt_issuances == {}
    assert authority._prepared_network_receipt_issuance_generations == {}
    assert authority._prepared_network_receipt_issuance_receipts == {}

    monkeypatch.undo()
    del acknowledge_then_lose, capture, receipt, root
    gc.collect()
    assert authority._prepared_network_receipt_authorities == {}
    assert generator._source_timing_planner.preparation_authority_census().retained_receipts == 0


def test_production_postcommit_failure_attaches_exact_completed_owner_without_capture() -> None:
    generator, emitter, _source_system = _production_generator("ordinary")
    authority = generator._lifecycle_authority
    emitter.emit.side_effect = RuntimeError("downstream publication failed")

    with pytest.raises(RuntimeError, match="downstream publication") as raised:
        _publish_production_connection(
            generator,
            family="ordinary",
            index=4,
            source_system=None,
            capture=None,
        )

    failure = raised.value
    root = object.__getattribute__(failure, "prepared_network_root")
    materialization = object.__getattribute__(
        failure,
        "prepared_network_materialization",
    )
    assert authority.state_manager.materialization_version == 1
    assert authority.authenticates_prepared_network_receipt(
        root,
        materialization.receipt,
    )
    assert authority._prepared_network_receipt_issuances == {}
    assert authority._prepared_network_receipt_issuance_generations == {}
    assert authority._prepared_network_receipt_issuance_receipts == {}

    emitter.emit.side_effect = None


def test_prepared_network_authentication_rejects_exact_receipt_copy_before_and_after_ack() -> None:
    authority, _runtime, _planner, root, timing, owner_rng, lifecycle_token = _prepared_fixture(
        stable_id="prepared-receipt-copy-replay"
    )
    result = authority.materialize_prepared_network_transaction(
        root,
        owner_rng,
        source_timing_preparation=timing,
        lifecycle_token=lifecycle_token,
    )
    copied = copy.copy(result.receipt)

    assert copied is not result.receipt
    assert not authority.authenticates_prepared_network_receipt(root, copied)

    authority.acknowledge_prepared_network_transaction(root, result)

    assert not authority.authenticates_prepared_network_receipt(root, copied)


def test_runtime_authenticator_call_original_then_mutate_cannot_authenticate_drift(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    authority, runtime, _planner, root, timing, owner_rng, lifecycle_token = _prepared_fixture(
        stable_id="prepared-receipt-auth-toctou"
    )
    result = authority.materialize_prepared_network_transaction(
        root,
        owner_rng,
        source_timing_preparation=timing,
        lifecycle_token=lifecycle_token,
    )
    receipt = result.receipt
    original = runtime.authenticates_preparation_receipt
    calls = 0

    def authenticate_then_alter(
        supplied: object,
        *args: object,
        **kwargs: object,
    ) -> bool:
        nonlocal calls
        calls += 1
        authentic = original(supplied, *args, **kwargs)
        if kwargs.get("token") is not None:
            object.__setattr__(
                receipt,
                "_transaction_id",
                "altered-after-runtime-authentication",
            )
        return authentic

    monkeypatch.setattr(runtime, "authenticates_preparation_receipt", authenticate_then_alter)

    assert not authority.authenticates_prepared_network_receipt(root, receipt)
    assert calls == 1
    assert receipt.transaction_id != root.transaction.stable_id


def test_connection_materialization_lost_return_recovers_prebound_terminal_facts(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    authority, _runtime, _planner, root, timing, owner_rng, lifecycle_token = _prepared_fixture(
        stable_id="connection-materialization-lost-return"
    )
    original = authority.materialize_connection_composite
    calls = 0

    def materialize_then_lose(*args: object, **kwargs: object) -> object:
        nonlocal calls
        calls += 1
        original(*args, **kwargs)
        raise RuntimeError("lost connection materialization return")

    monkeypatch.setattr(authority, "materialize_connection_composite", materialize_then_lose)
    with pytest.raises(RuntimeError, match="lost connection materialization"):
        authority.materialize_prepared_network_transaction(
            root,
            owner_rng,
            source_timing_preparation=timing,
            lifecycle_token=lifecycle_token,
        )
    assert calls == 1
    assert authority._state_manager.materialization_version == 1
    carrier = next(iter(authority._prepared_network_receipt_issuances.values()))
    assert carrier.issuance_values is not None

    monkeypatch.delattr(authority, "materialize_connection_composite")
    recovered = authority.materialize_prepared_network_transaction(
        root,
        owner_rng,
        source_timing_preparation=timing,
        lifecycle_token=lifecycle_token,
    )

    assert authority._state_manager.materialization_version == 1
    assert recovered is carrier.result
    assert recovered.receipt is carrier.receipt
    assert authority.authenticates_prepared_network_receipt(root, recovered.receipt)


def test_detached_verifier_reads_secret_from_exact_instance_namespace(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    authority, _runtime, _planner, root, timing, owner_rng, lifecycle_token = _prepared_fixture(
        stable_id="detached-secret-descriptor"
    )
    result = authority.materialize_prepared_network_transaction(
        root,
        owner_rng,
        source_timing_preparation=timing,
        lifecycle_token=lifecycle_token,
    )
    binding = authority.detach_prepared_network_receipt(result.receipt)
    secret = object.__getattribute__(authority, "__dict__")["_receipt_secret"]
    callbacks: list[str] = []

    class HostileSecretDescriptor:
        def __get__(self, instance: object, owner: object) -> bytes:
            callbacks.append("get")
            return secret

        def __set__(self, instance: object, value: object) -> None:
            raise AssertionError("unexpected secret write")

    monkeypatch.setattr(
        GeneratorLifecycleAuthority,
        "_receipt_secret",
        HostileSecretDescriptor(),
        raising=False,
    )

    assert authority.authenticates_detached_network_receipt_binding(binding)
    assert callbacks == []
