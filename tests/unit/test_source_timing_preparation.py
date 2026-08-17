# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Atomicity gates for staged source timing and runtime publication."""

from __future__ import annotations

import ast
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from threading import Event

import pytest

from evidenceforge.events.base import OccurrenceBuilder
from evidenceforge.events.content_identity import UnresolvedBinaryIdentity
from evidenceforge.events.contexts import (
    AuthContext,
    HostContext,
    HttpContext,
    ProcessContext,
    ProxyContext,
)
from evidenceforge.events.lifecycle import ActionLifecycleContext
from evidenceforge.generation.actions.proxy_phase_planner import ProxyPhasePlanner
from evidenceforge.generation.actions.proxy_transaction import ProxyTransactionRequest
from evidenceforge.generation.activity.tls_realism import ssl_analyzer_delay_ms
from evidenceforge.generation.source_timing import (
    SourceTimingPlanner,
    SourceTimingPreparationReceipt,
)
from evidenceforge.generation.timing import TimingRuntime
from evidenceforge.models.exceptions import StateError
from evidenceforge.models.scenario import System

T0 = datetime(2026, 8, 16, 12, 0, tzinfo=UTC)


def _planner(namespace: str = "source-timing-preparation") -> SourceTimingPlanner:
    """Return one isolated production-shaped timing owner."""

    return SourceTimingPlanner(
        "enterprise_standard",
        timing_runtime=TimingRuntime(
            reference_time=T0 - timedelta(hours=1),
            namespace=namespace,
            max_clock_cache_entries=8,
        ),
    )


def _host() -> HostContext:
    return HostContext(
        hostname="WIN-01",
        fqdn="win-01.example.test",
        ip="10.20.30.40",
        os="Windows 11",
        os_category="windows",
        system_type="workstation",
        domain="example.test",
        netbios_domain="EXAMPLE",
    )


def _logon_batch() -> list[OccurrenceBuilder]:
    """Return one logon and its winlogon/userinit/explorer process family."""

    host = _host()
    lifecycle_id = "windows-logon-batch-0001"
    events = [
        OccurrenceBuilder(
            timestamp=T0,
            event_type="logon",
            src_host=host,
            auth=AuthContext(
                username="analyst",
                user_sid="S-1-5-21-1-2-3-1105",
                logon_id="0x4f210",
                logon_type=2,
            ),
            lifecycle=ActionLifecycleContext(
                group_id=lifecycle_id,
                canonical_start=T0,
                phase="start",
            ),
        )
    ]
    for ordinal, image in enumerate(("winlogon.exe", "userinit.exe", "explorer.exe"), start=1):
        started_at = T0 + timedelta(milliseconds=ordinal * 11)
        native_path = rf"C:\Windows\System32\{image}"
        events.append(
            OccurrenceBuilder(
                timestamp=started_at,
                event_type="process_create",
                src_host=host,
                process=ProcessContext(
                    pid=1_200 + ordinal,
                    parent_pid=4 if ordinal == 1 else 1_199 + ordinal,
                    image=native_path,
                    command_line=native_path,
                    username="EXAMPLE\\analyst",
                    logon_id="0x4f210",
                    start_time=started_at,
                    binary_identity=UnresolvedBinaryIdentity(
                        platform="windows",
                        native_path=native_path,
                        reason="direct timing atomicity fixture",
                    ),
                ),
                lifecycle=ActionLifecycleContext(
                    group_id=f"{lifecycle_id}:process:{ordinal}",
                    parent_group_id=lifecycle_id,
                    canonical_start=started_at,
                    phase="dependent",
                ),
            )
        )
    return events


def _plan_batch(
    planner: SourceTimingPlanner,
    events: list[OccurrenceBuilder],
) -> None:
    """Plan every endpoint projection in deterministic dispatcher order."""

    for event in events:
        formats = (
            ("windows_event_security", "ecar")
            if event.event_type == "logon"
            else ("windows_event_security", "windows_event_sysmon", "ecar")
        )
        for format_name in formats:
            planner.plan_event(
                event,
                format_name,
                source_instance=f"{format_name}:win-01:agent",
                source_hostname="win-01",
            )


def test_rejected_logon_batch_preserves_full_planner_and_runtime_state() -> None:
    """Four rejected prepared dispatches must leave no timing or diagnostic residue."""

    planner = _planner()
    before_digest = planner.state_digest()
    before_census = planner.census(estimate_bytes=True)
    before_audit = planner.timing_runtime.audit.snapshot()

    with planner.prepared_planning() as preparation:
        assert planner.is_active_preparation(preparation)
        _plan_batch(planner, _logon_batch())
        assert preparation.staged_cache_operations > 0
        assert preparation.staged_audit_operations > 0
        assert planner.state_digest() == before_digest
        assert planner.census(estimate_bytes=True) == before_census
        assert planner.timing_runtime.audit.snapshot() == before_audit

    assert not planner.is_active_preparation(preparation)
    assert planner.authenticates_preparation(preparation)
    preparation.cancel()
    assert planner.state_digest() == before_digest
    assert planner.census(estimate_bytes=True) == before_census
    assert planner.timing_runtime.audit.snapshot() == before_audit


def test_successful_preparation_matches_direct_planning_exactly() -> None:
    """Staged success must retain source values, clocks, indexes, and counters exactly."""

    direct = _planner("source-timing-success-parity")
    staged = _planner("source-timing-success-parity")
    direct_events = _logon_batch()
    staged_events = _logon_batch()
    _plan_batch(direct, direct_events)

    with staged.prepared_planning() as preparation:
        token = preparation.binding_token
        _plan_batch(staged, staged_events)
        assert preparation.binding_token is token
    with preparation.claimed_commit():
        preparation.commit_no_fail()

    assert preparation.committed
    assert staged.authenticates_preparation(preparation)
    assert staged.authenticates_preparation_receipt(preparation.receipt)
    assert [event.source_timing for event in staged_events] == [
        event.source_timing for event in direct_events
    ]
    assert staged.state_digest() == direct.state_digest()
    assert staged.census(estimate_bytes=True) == direct.census(estimate_bytes=True)
    assert staged.timing_runtime.audit.snapshot() == direct.timing_runtime.audit.snapshot()


def test_direct_source_time_routes_through_active_runtime_overlay() -> None:
    """Process-start preplanning must stage direct source-time samples and audit writes."""

    direct = _planner("direct-source-time-preparation")
    staged = _planner("direct-source-time-preparation")
    direct_event = _logon_batch()[1]
    staged_event = _logon_batch()[1]
    seed_parts = (
        staged_event.src_host.hostname,
        staged_event.process.pid,
        staged_event.process.start_time,
    )
    expected = direct.source_time(
        direct_event,
        "source.sysmon_process_create",
        seed_parts=seed_parts,
        not_before=direct_event.timestamp,
    )
    before_digest = staged.state_digest()
    before_census = staged.census(estimate_bytes=True)
    before_audit = staged.timing_runtime.audit.snapshot()

    with staged.prepared_planning() as preparation:
        actual = staged.source_time(
            staged_event,
            "source.sysmon_process_create",
            seed_parts=seed_parts,
            not_before=staged_event.timestamp,
        )
        assert actual == expected
        assert preparation.staged_audit_operations > 0
        assert staged.state_digest() == before_digest
        assert staged.census(estimate_bytes=True) == before_census
        assert staged.timing_runtime.audit.snapshot() == before_audit

    with preparation.claimed_commit():
        preparation.commit_no_fail()
    assert staged.state_digest() == direct.state_digest()
    assert staged.census(estimate_bytes=True) == direct.census(estimate_bytes=True)
    assert staged.timing_runtime.audit.snapshot() == direct.timing_runtime.audit.snapshot()


def test_planning_runtime_is_non_owning_and_expires_when_preparation_seals() -> None:
    """The public runtime view exposes planning only while its owner is open."""

    planner = _planner("source-timing-public-planning-runtime")
    with planner.prepared_planning() as preparation:
        planning_runtime = preparation.planning_runtime
        assert planning_runtime.sampler is not planner.timing_runtime.sampler
        assert planning_runtime.clocks is planning_runtime.source_clock_registry
        assert not hasattr(planning_runtime, "cancel")
        assert not hasattr(planning_runtime, "claimed_commit")
        assert not hasattr(planning_runtime, "commit_no_fail")

    with pytest.raises(StateError, match="not open for planning"):
        _ = preparation.planning_runtime
    with pytest.raises(StateError, match="no longer open"):
        _ = planning_runtime.sampler

    preparation.cancel()
    with pytest.raises(StateError, match="no longer open"):
        _ = planning_runtime.audit


def test_tls_and_proxy_planners_use_the_exact_non_owning_staged_runtime() -> None:
    """Network timing consumers stage samples without gaining commit/cancel authority."""

    planner = _planner("source-timing-network-consumers")
    before_digest = planner.state_digest()
    before_audit = planner.timing_runtime.audit.snapshot()
    proxy_system = System(
        hostname="PROXY-01",
        ip="10.0.3.10",
        os="Ubuntu 24.04",
        type="server",
        roles=["forward_proxy"],
    )
    request = ProxyTransactionRequest(
        src_ip="10.0.1.10",
        dst_ip="203.0.113.20",
        time=T0,
        dst_port=443,
        proto="tcp",
        service="ssl",
        duration=1.0,
        orig_bytes=900,
        resp_bytes=4_000,
        src_port=50_000,
        pid=-1,
        source_system=None,
        conn_state="SF",
        dns=None,
        http=HttpContext(method="GET", host="example.test", uri="/"),
        file_transfer=None,
        ocsp=None,
        proxy=None,
        firewall=None,
        hostname="example.test",
        process_image=None,
        proxy_chain=[proxy_system],
        preserve_explicit_proxy_dst_ip=False,
        caller_provided_conn_state=True,
        ad_domain="example.test",
    )
    proxy_context = ProxyContext(
        client_ip=request.src_ip,
        method="GET",
        url="https://example.test/",
        host="example.test",
        status_code=200,
        sc_bytes=4_000,
        cs_bytes=900,
        cache_result="MISS",
        proxy_fqdn="proxy-01.example.test",
    )

    with planner.prepared_planning() as preparation:
        runtime = preparation.planning_runtime
        tls_delay = ssl_analyzer_delay_ms(
            zeek_uid="C-network-staged-runtime",
            event_timestamp=T0,
            timing_runtime=runtime,
        )
        proxy_plan = ProxyPhasePlanner(runtime).plan(request, proxy_context, T0)

        assert tls_delay > 0
        assert proxy_plan.close_at > proxy_plan.client_connect_at
        assert preparation.staged_audit_operations > 0
        assert planner.state_digest() == before_digest
        assert planner.timing_runtime.audit.snapshot() == before_audit
        assert not hasattr(runtime, "cancel")
        assert not hasattr(runtime, "claimed_commit")
        assert not hasattr(runtime, "commit_no_fail")

    preparation.cancel()
    assert planner.state_digest() == before_digest
    assert planner.timing_runtime.audit.snapshot() == before_audit


def test_runtime_preparation_private_field_stays_source_timing_internal() -> None:
    """Production consumers must use the public non-owning planning capability."""

    repository_root = Path(__file__).resolve().parents[2]
    production_root = repository_root / "src" / "evidenceforge"
    external_accesses: list[Path] = []
    for path in production_root.rglob("*.py"):
        if path.name == "source_timing.py":
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        if any(
            isinstance(node, ast.Attribute) and node.attr == "_runtime_preparation"
            for node in ast.walk(tree)
        ):
            external_accesses.append(path.relative_to(repository_root))

    assert external_accesses == []


def test_preparation_tokens_are_admin_only_unique_and_cancellation_is_noncanonical() -> None:
    """Monotonic anti-ABA token allocation must not contaminate canonical timing state."""

    planner = _planner()
    before = planner.state_digest()
    with planner.prepared_planning() as first:
        first_token = first.binding_token
    first.cancel()
    with planner.prepared_planning() as second:
        second_token = second.binding_token
    second.cancel()

    assert first_token.preparation_id + 1 == second_token.preparation_id
    assert first_token != second_token
    assert planner.authenticates_binding_token(first_token)
    assert planner.authenticates_binding_token(second_token)
    assert planner.state_digest() == before


def test_tampered_wrong_owner_and_double_commit_are_rejected() -> None:
    """Binding and commit authentication must reject forged or reused authority."""

    planner = _planner()
    wrong_owner = _planner()
    with planner.prepared_planning() as preparation:
        _plan_batch(planner, _logon_batch())

    forged_token = replace(preparation.binding_token, _integrity="0" * 64)
    assert not planner.authenticates_binding_token(forged_token)
    assert not wrong_owner.authenticates_binding_token(preparation.binding_token)

    with preparation.claimed_commit():
        assert preparation.receipt is None
        assert getattr(preparation, "_prepared_receipt", None) is None
        precommit_candidate = SourceTimingPreparationReceipt(
            binding_token=preparation.binding_token,
            overlay_digest=preparation.overlay_digest,
            committed_state_digest=preparation._commit_state_digest,
            _integrity="",
        )
        assert not planner.authenticates_preparation_receipt(precommit_candidate)
        preparation.commit_no_fail()
        with pytest.raises(StateError, match="not claimed"):
            preparation.commit_no_fail()

    receipt = preparation.receipt
    assert receipt is not None
    forged_receipt = replace(receipt, _integrity="f" * 64)
    same_fields_without_authority = SourceTimingPreparationReceipt(
        binding_token=receipt.binding_token,
        overlay_digest=receipt.overlay_digest,
        committed_state_digest=receipt.committed_state_digest,
        _integrity="",
    )
    assert planner.authenticates_preparation_receipt(receipt)
    assert not planner.authenticates_preparation_receipt(forged_receipt)
    assert not planner.authenticates_preparation_receipt(same_fields_without_authority)
    assert not wrong_owner.authenticates_preparation_receipt(receipt)
    with pytest.raises(StateError, match="must be sealed"):
        with preparation.claimed_commit():
            pass


def test_stale_and_aba_cache_or_runtime_mutations_reject_before_commit() -> None:
    """Any intervening cache/audit mutation must invalidate the sealed snapshot."""

    cache_planner = _planner("source-timing-stale-cache")
    with cache_planner.prepared_planning() as cache_preparation:
        _plan_batch(cache_planner, _logon_batch())
    cache = cache_planner._ecar_process_create_times
    cache["temporary-aba-key"] = T0
    cache.pop("temporary-aba-key")
    assert cache_planner.census().live_entries == 0
    with pytest.raises(StateError, match="stale"):
        with cache_preparation.claimed_commit():
            pass

    runtime_planner = _planner("source-timing-stale-runtime")
    with runtime_planner.prepared_planning() as runtime_preparation:
        _plan_batch(runtime_planner, _logon_batch())
    runtime_planner.timing_runtime.audit.record_fallback("external-runtime-write")
    with pytest.raises(Exception, match="stale"):
        with runtime_preparation.claimed_commit():
            pass


def test_preparation_census_is_bounded_and_watermark_waits_for_claim() -> None:
    """Overlay retention is batch-bounded and watermark cannot cross a held claim."""

    planner = _planner("source-timing-preparation-bounds")
    with planner.prepared_planning() as preparation:
        for ordinal in range(64):
            event = _logon_batch()[1]
            event.process.pid += ordinal
            event.timestamp += timedelta(microseconds=ordinal)
            event.process.start_time = event.timestamp
            planner.plan_event(
                event,
                "ecar",
                source_instance="ecar:win-01:agent",
                source_hostname="win-01",
            )
    census = preparation.census()
    assert census.cache_family_count == 16
    assert 0 < census.staged_cache_keys <= census.staged_cache_operations <= 256
    assert census.clock_live_entries <= census.clock_capacity == 8
    assert planner.census().live_entries == 0

    started = Event()
    finished = Event()

    def advance() -> None:
        started.set()
        planner.advance_watermark(T0 + timedelta(days=3))
        finished.set()

    with ThreadPoolExecutor(max_workers=1) as executor:
        with preparation.claimed_commit():
            future = executor.submit(advance)
            assert started.wait(timeout=1)
            assert not finished.wait(timeout=0.05)
            preparation.commit_no_fail()
        future.result(timeout=2)
    assert finished.is_set()


def test_production_claim_site_enforces_global_timing_before_authority_lock_order() -> None:
    """Every production claim must surround authority commit and its timing callback."""

    repository_root = Path(__file__).resolve().parents[2]
    production_root = repository_root / "src" / "evidenceforge"
    claim_sites: list[tuple[Path, str, ast.With]] = []
    for path in production_root.rglob("*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for function in (
            node
            for node in ast.walk(tree)
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        ):
            for node in ast.walk(function):
                if not isinstance(node, ast.With):
                    continue
                if any(
                    isinstance(item.context_expr, ast.Call)
                    and isinstance(item.context_expr.func, ast.Attribute)
                    and item.context_expr.func.attr == "claimed_commit"
                    for item in node.items
                ):
                    claim_sites.append((path.relative_to(repository_root), function.name, node))

    expected_sites = {
        (
            "src/evidenceforge/generation/lifecycle_authority.py",
            "materialize_prepared_network_transaction",
        ): "materialize_connection_composite",
    }
    assert {
        (path.as_posix(), function): expected_sites[(path.as_posix(), function)]
        for path, function, _node in claim_sites
    } == expected_sites

    for path, function, claim_body in claim_sites:
        materialize_name = expected_sites[(path.as_posix(), function)]
        assert not any(
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "_finalize_due_process_lifetimes"
            for statement in claim_body.body
            for node in ast.walk(statement)
        )
        materialize_calls = [
            node
            for statement in claim_body.body
            for node in ast.walk(statement)
            if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == materialize_name
        ]
        assert len(materialize_calls) == 1
        callback = next(
            keyword.value
            for keyword in materialize_calls[0].keywords
            if keyword.arg == "finalize_external_no_fail"
        )
        if isinstance(callback, ast.Attribute):
            assert callback.attr == "commit_no_fail"
            continue
        assert isinstance(callback, ast.Name)
        callback_definitions = [
            node
            for statement in claim_body.body
            for node in ast.walk(statement)
            if isinstance(node, ast.FunctionDef) and node.name == callback.id
        ]
        assert len(callback_definitions) == 1
        assert any(
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "commit_no_fail"
            for node in ast.walk(callback_definitions[0])
        )
