# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Focused source-timing preparation seams used by action-cohort publication."""

import ast
import gc
import inspect
from contextvars import copy_context
from copy import copy
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from textwrap import dedent
from threading import Event, Thread

import pytest

from evidenceforge.events.base import OccurrenceBuilder
from evidenceforge.events.contexts import HostContext, ProcessContext
from evidenceforge.generation.source_timing import SourceTimingPlanner, SourceTimingPreparation
from evidenceforge.generation.timing import (
    ConstantDistribution,
    SourceClockKey,
    SourceClockSpec,
    TimingDistributionError,
    TimingRuntime,
    TruncatedNormalDistribution,
)
from evidenceforge.models.exceptions import StateError

_START = datetime(2026, 8, 17, 14, 0, tzinfo=UTC)


def _planner() -> SourceTimingPlanner:
    return SourceTimingPlanner(
        "enterprise_standard",
        timing_runtime=TimingRuntime(
            reference_time=_START - timedelta(hours=1),
            namespace="action-cohort-source-timing",
        ),
    )


def _event() -> OccurrenceBuilder:
    host = HostContext(
        hostname="LINUX-01",
        fqdn="linux-01.example.test",
        ip="10.20.30.40",
        os="Ubuntu 24.04",
        os_category="linux",
        system_type="server",
        domain="example.test",
    )
    return OccurrenceBuilder(
        timestamp=_START,
        event_type="process_create",
        src_host=host,
        process=ProcessContext(
            pid=4_242,
            parent_pid=1,
            image="/usr/bin/id",
            command_line="id",
            username="operator",
            logon_id="0x1001",
            start_time=_START,
        ),
    )


def test_admitted_event_stages_neutrally_and_expected_receipt_is_exact() -> None:
    planner = _planner()
    before = planner.state_digest()

    with planner.prepared_planning() as preparation:
        planned = preparation.plan_event(_event(), "ecar")
        preparation.record_admitted_source_event(planned, "ecar")
        assert planner.state_digest() == before

    assert planner.authenticates_preparation(preparation)
    with preparation.claimed_commit() as claimed:
        expected = claimed.expected_receipt
        receipt = claimed.commit_no_fail()
        assert receipt is expected
        assert claimed.receipt is expected

    assert planner.authenticates_preparation_receipt(expected)
    assert planner.state_digest() != before


def test_admitted_event_rejects_sealed_and_cancelled_preparations() -> None:
    planner = _planner()
    event = _event()

    with planner.prepared_planning() as sealed:
        sealed.plan_event(event, "ecar")
    with pytest.raises(StateError, match="sealed"):
        sealed.record_admitted_source_event(event, "ecar")
    with pytest.raises(StateError, match="expected receipt"):
        _ = sealed.expected_receipt
    sealed.cancel()
    with pytest.raises(StateError, match="sealed"):
        sealed.record_admitted_source_event(event, "ecar")
    with pytest.raises(StateError, match="expected receipt"):
        _ = sealed.expected_receipt


def test_composite_certification_is_exact_one_shot_and_commit_is_primitive_only(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    planner = _planner()
    with planner.prepared_planning() as preparation:
        preparation.plan_event(_event(), "ecar")

    with preparation.claimed_commit() as claimed:
        expected = claimed.expected_receipt
        with pytest.raises(StateError, match="expected receipt"):
            claimed.certify_composite_commit(replace(expected, overlay_digest="tampered"))
        claimed.certify_composite_commit(expected)
        with pytest.raises(StateError, match="already certified"):
            claimed.certify_composite_commit(expected)

        def forbidden_authentication(_receipt: object) -> bool:
            raise AssertionError("certified commit performed receipt authentication")

        monkeypatch.setattr(
            planner,
            "authenticates_preparation_receipt",
            forbidden_authentication,
        )
        monkeypatch.setattr(
            planner,
            "authenticates_expected_preparation_receipt",
            forbidden_authentication,
        )

        def forbidden_preimage(_record: object) -> bool:
            raise AssertionError("certified commit repeated preimage validation")

        def forbidden_public_mutation(*_args: object, **_kwargs: object) -> None:
            raise AssertionError("primitive commit called a public runtime mutation")

        monkeypatch.setattr(
            planner,
            "_claim_record_matches_current_state",
            forbidden_preimage,
        )
        monkeypatch.setattr(
            planner.timing_runtime.audit,
            "record_sample",
            forbidden_public_mutation,
        )
        monkeypatch.setattr(
            planner.timing_runtime.clocks,
            "state",
            forbidden_public_mutation,
        )
        assert claimed.commit_no_fail() is expected


def test_composite_certification_is_claim_thread_bound() -> None:
    planner = _planner()
    with planner.prepared_planning() as preparation:
        preparation.plan_event(_event(), "ecar")

    with pytest.raises(RuntimeError, match="leave claim uncommitted"):
        with preparation.claimed_commit() as claimed:
            expected = claimed.expected_receipt
            failures: list[BaseException] = []

            def certify_on_foreign_thread() -> None:
                try:
                    claimed.certify_composite_commit(expected)
                except BaseException as exc:
                    failures.append(exc)

            thread = Thread(target=certify_on_foreign_thread)
            thread.start()
            thread.join(timeout=5)
            assert not thread.is_alive()
            assert len(failures) == 1
            assert isinstance(failures[0], StateError)
            assert "claiming thread" in str(failures[0])
            raise RuntimeError("leave claim uncommitted")


def test_claim_locator_rejects_copies_before_and_after_certification() -> None:
    planner = _planner()
    with planner.prepared_planning() as preparation:
        preparation.plan_event(_event(), "ecar")

    with preparation.claimed_commit() as claimed:
        expected = claimed.expected_receipt
        copied_before = copy(claimed)
        assert not planner.authenticates_preparation(copied_before)
        with pytest.raises(StateError, match="not claimed"):
            copied_before.commit_no_fail()

        claimed.certify_composite_commit(expected)
        copied_after = copy(claimed)
        assert not planner.authenticates_preparation(copied_after)
        with pytest.raises(StateError, match="not claimed"):
            copied_after.commit_no_fail()
        assert claimed.commit_no_fail() is expected

    assert not planner.authenticates_preparation_receipt(copy(expected))
    with pytest.raises(StateError, match="not claimed"):
        preparation.commit_no_fail()


def test_copied_preparation_cannot_cancel_the_exact_owner() -> None:
    planner = _planner()
    with planner.prepared_planning() as preparation:
        preparation.plan_event(_event(), "ecar")

    copied = copy(preparation)
    with pytest.raises(StateError, match="exact active owner"):
        copied.cancel()

    assert planner.authenticates_preparation(preparation)
    with preparation.claimed_commit() as claimed:
        claimed.commit_no_fail()
    assert copied.staged_cache_operations == 0
    assert copied.staged_audit_operations == 0
    assert copied.census().clock_live_entries == 0


def test_retained_runtime_capabilities_reject_mutation_after_plan_freeze() -> None:
    planner = _planner()
    key = SourceClockKey(kind="endpoint", identity="retained-clock")
    spec = SourceClockSpec(
        offset_microseconds=ConstantDistribution(0),
        drift_ppm=ConstantDistribution(0),
    )
    with planner.prepared_planning() as preparation:
        runtime = preparation.planning_runtime
        retained_audit = runtime.audit
        retained_clocks = runtime.clocks
        runtime_owner_ref = retained_clocks._owner_preparation
        assert runtime_owner_ref is not None
        retained_clocks.state(key, spec)

    staged_operations = preparation.staged_audit_operations
    with pytest.raises(TimingDistributionError, match="outside its active source timing claim"):
        retained_audit.record_fallback("after-freeze")
    with pytest.raises(TimingDistributionError, match="outside its active source timing claim"):
        retained_clocks.clear_cache()
    assert preparation.staged_audit_operations == staged_operations

    with preparation.claimed_commit() as claimed:
        claimed.certify_composite_commit(claimed.expected_receipt)
        with pytest.raises(
            TimingDistributionError,
            match="not open for staging",
        ):
            retained_clocks.state(key, spec)
        claimed.commit_no_fail()

    assert runtime_owner_ref() is None
    assert retained_audit.operation_count == 0
    assert retained_clocks.cache_size == 0
    committed_digest = planner.state_digest()
    with pytest.raises(TimingDistributionError, match="not open for staging"):
        retained_audit.record_fallback("after-commit")
    with pytest.raises(TimingDistributionError, match="not open for staging"):
        retained_clocks.clear_cache()
    assert planner.state_digest() == committed_digest


def test_copied_context_cannot_stage_on_a_foreign_thread() -> None:
    planner = _planner()
    key = SourceClockKey(kind="endpoint", identity="foreign-context-clock")
    spec = SourceClockSpec(
        offset_microseconds=ConstantDistribution(0),
        drift_ppm=ConstantDistribution(0),
    )
    failures: list[BaseException] = []

    with planner.prepared_planning() as preparation:
        retained_clocks = preparation.planning_runtime.clocks
        foreign_context = copy_context()

        def stage_on_foreign_thread() -> None:
            try:
                foreign_context.run(retained_clocks.state, key, spec)
            except BaseException as error:
                failures.append(error)

        thread = Thread(target=stage_on_foreign_thread)
        thread.start()
        thread.join(timeout=5)
        assert not thread.is_alive()
        assert len(failures) == 1
        assert isinstance(failures[0], TimingDistributionError)
        assert "outside its active source timing claim" in str(failures[0])
        assert preparation.staged_audit_operations == 0
        retained_clocks.state(key, spec)

    with preparation.claimed_commit() as claimed:
        claimed.certify_composite_commit(claimed.expected_receipt)
        claimed.commit_no_fail()
    assert planner.timing_runtime.clocks.cache_size == 1


def test_public_runtime_mutation_is_rejected_through_certified_commit() -> None:
    planner = _planner()
    with planner.prepared_planning() as preparation:
        pass

    with preparation.claimed_commit() as claimed:
        expected = claimed.expected_receipt
        claimed.certify_composite_commit(expected)
        with pytest.raises(TimingDistributionError, match="active owner claim"):
            planner.timing_runtime.audit.record_sample(
                "source-timing-public-reentrant",
                "constant",
            )
        assert planner.authenticates_expected_preparation_receipt(
            expected,
            preparation=claimed,
        )
        claimed.commit_no_fail()

    audit = planner.timing_runtime.audit.snapshot()
    assert "source-timing-public-reentrant" not in audit.sample_counts


@pytest.mark.parametrize(
    ("relationship_key", "distribution_kind"),
    [
        ("valid-relationship", []),
        ([], "constant"),
        ("valid-relationship", "unbounded-public-kind"),
        ("invalid-\ud800", "constant"),
    ],
)
def test_invalid_public_audit_input_fails_before_any_staged_or_canonical_write(
    relationship_key: object,
    distribution_kind: object,
) -> None:
    planner = _planner()
    before = planner.state_digest()

    with pytest.raises(TimingDistributionError):
        planner.timing_runtime.audit.record_sample(relationship_key, distribution_kind)
    assert planner.state_digest() == before

    with pytest.raises(TimingDistributionError):
        with planner.prepared_planning() as preparation:
            preparation.planning_runtime.audit.record_sample(
                relationship_key,
                distribution_kind,
            )
    assert planner.state_digest() == before
    planner.timing_runtime.audit.record_sample("valid-relationship", "constant")


def test_invalid_public_clock_input_fails_before_audit_or_cache_write() -> None:
    planner = _planner()
    spec = SourceClockSpec(
        offset_microseconds=ConstantDistribution(0),
        drift_ppm=ConstantDistribution(0),
    )
    invalid_key: object = []
    before = planner.state_digest()

    with pytest.raises(TimingDistributionError, match="non-empty string"):
        SourceClockKey(kind=["endpoint"], identity=["host"])
    with pytest.raises(TimingDistributionError, match="valid UTF-8"):
        SourceClockKey(kind="endpoint", identity="host-\ud800")

    with pytest.raises(TimingDistributionError, match="exact SourceClockKey"):
        planner.timing_runtime.clocks.state(invalid_key, spec)
    assert planner.state_digest() == before

    with pytest.raises(TimingDistributionError, match="exact SourceClockKey"):
        with planner.prepared_planning() as preparation:
            preparation.planning_runtime.clocks.state(invalid_key, spec)
    assert planner.state_digest() == before


def test_unsampleable_public_clock_spec_has_zero_canonical_or_staged_residue() -> None:
    planner = _planner()
    key = SourceClockKey(kind="endpoint", identity="unsampleable-clock")
    spec = SourceClockSpec(
        offset_microseconds=TruncatedNormalDistribution(
            mean=0,
            standard_deviation=1,
            minimum=100,
            maximum=101,
        ),
        drift_ppm=ConstantDistribution(0),
    )
    before = planner.state_digest()

    with pytest.raises(TimingDistributionError, match="representable"):
        planner.timing_runtime.clocks.state(key, spec)
    assert planner.state_digest() == before

    with planner.prepared_planning() as preparation:
        with pytest.raises(TimingDistributionError, match="representable"):
            preparation.planning_runtime.clocks.state(key, spec)
        assert preparation.staged_audit_operations == 0
        assert preparation.planning_runtime.clocks.cache_size == 0
    with preparation.claimed_commit() as claimed:
        claimed.commit_no_fail()
    assert planner.state_digest() == before


def test_seal_failure_cancels_exact_state_and_releases_both_lanes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    planner = _planner()
    before = planner.state_digest()
    original_seal = SourceTimingPreparation.seal

    def fail_seal(_preparation: SourceTimingPreparation) -> None:
        raise RuntimeError("ordinary seal failure")

    monkeypatch.setattr(SourceTimingPreparation, "seal", fail_seal)
    with pytest.raises(RuntimeError, match="ordinary seal failure"):
        with planner.prepared_planning():
            pass
    assert planner.state_digest() == before
    planner.timing_runtime.audit.record_fallback("after-seal-failure")

    monkeypatch.setattr(SourceTimingPreparation, "seal", original_seal)
    with planner.prepared_planning() as retry:
        pass
    retry.cancel()


def test_public_watermark_advance_is_rejected_through_certified_commit() -> None:
    planner = _planner()
    with planner.prepared_planning() as preparation:
        pass

    before = planner.state_digest()
    with preparation.claimed_commit() as claimed:
        expected = claimed.expected_receipt
        claimed.certify_composite_commit(expected)
        with pytest.raises(StateError, match="active owner claim"):
            assert planner.advance_watermark(_START + timedelta(hours=1)) == 0
        assert planner.state_digest() == before
        claimed.commit_no_fail()

    assert planner.advance_watermark(_START + timedelta(hours=1)) == 0
    assert planner.authenticates_preparation(preparation)


def test_certification_and_standalone_commit_revalidate_every_preimage(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    planner = _planner()
    matcher_calls: list[object] = []
    match_current_state = planner._claim_record_matches_current_state

    def recording_matcher(record: object) -> bool:
        matcher_calls.append(record)
        return match_current_state(record)

    monkeypatch.setattr(planner, "_claim_record_matches_current_state", recording_matcher)
    with planner.prepared_planning() as certified:
        certified.plan_event(_event(), "ecar")
    with certified.claimed_commit() as claimed:
        before_certification = len(matcher_calls)
        claimed.certify_composite_commit(claimed.expected_receipt)
        assert len(matcher_calls) > before_certification
        claimed.commit_no_fail()

    with planner.prepared_planning() as standalone:
        standalone.plan_event(_event(), "ecar")
    with standalone.claimed_commit() as claimed:
        before_commit = len(matcher_calls)
        claimed.commit_no_fail()
        assert len(matcher_calls) > before_commit

    tree = ast.parse(
        inspect.cleandoc(inspect.getsource(SourceTimingPlanner._claim_record_matches_current_state))
    )
    checked_attributes = {node.attr for node in ast.walk(tree) if isinstance(node, ast.Attribute)}
    assert {"_watermark", "_mutation_version", "audit", "clocks"} <= checked_attributes


def test_preparation_authority_capacity_bounds_live_receipts_before_mutation() -> None:
    planner = SourceTimingPlanner(
        "enterprise_standard",
        timing_runtime=TimingRuntime(
            reference_time=_START - timedelta(hours=1),
            namespace="bounded-action-cohort-source-timing",
        ),
        preparation_authority_capacity=1,
    )
    with planner.prepared_planning() as first:
        pass
    with first.claimed_commit() as claimed:
        expected = claimed.expected_receipt
        assert claimed.commit_no_fail() is expected

    census = planner.preparation_authority_census()
    assert census.retained_preparations == 1
    assert census.retained_receipts == 1
    assert census.capacity == 1

    with planner.prepared_planning() as second:
        pass
    with pytest.raises(StateError, match="receipt capacity is exhausted"):
        with second.claimed_commit():
            raise AssertionError("capacity failure must occur before claim publication")

    assert planner.authenticates_preparation(second)
    assert planner.preparation_authority_census() == census
    second.cancel()


def test_plan_event_clock_watermark_and_nested_claims_share_one_early_lane() -> None:
    planner = _planner()
    key = SourceClockKey(kind="endpoint", identity="LINUX-01", profile="enterprise")
    spec = SourceClockSpec(
        offset_microseconds=ConstantDistribution(0),
        drift_ppm=ConstantDistribution(0),
    )

    with planner.prepared_planning() as preparation:
        preparation.plan_event(_event(), "ecar")
        with pytest.raises(StateError, match="Nested source timing preparations"):
            with planner.prepared_planning():
                pass

    before = planner.state_digest()
    with pytest.raises(StateError, match="active owner claim"):
        planner.plan_event(_event(), "ecar")
    with pytest.raises(TimingDistributionError, match="active owner claim"):
        planner.timing_runtime.clocks.state(key, spec)
    with pytest.raises(TimingDistributionError, match="active owner claim"):
        planner.timing_runtime.clocks.clear_cache()
    with pytest.raises(TimingDistributionError, match="active owner claim"):
        planner.timing_runtime.prepared()
    with pytest.raises(StateError, match="active owner claim"):
        planner.advance_watermark(_START + timedelta(hours=1))
    with pytest.raises(StateError, match="active owner claim"):
        with planner.prepared_planning():
            pass
    assert planner.state_digest() == before

    with preparation.claimed_commit() as claimed:
        expected = claimed.expected_receipt
        claimed.certify_composite_commit(expected)
        with pytest.raises(StateError, match="active owner claim"):
            planner.plan_event(_event(), "ecar")
        with pytest.raises(TimingDistributionError, match="active owner claim"):
            planner.timing_runtime.clocks.state(key, spec)
        with pytest.raises(TimingDistributionError, match="active owner claim"):
            planner.timing_runtime.prepared()
        claimed.commit_no_fail()


def test_claim_lane_rejects_concurrent_public_mutation_without_blocking() -> None:
    planner = _planner()
    with planner.prepared_planning() as preparation:
        pass

    failures: list[BaseException] = []

    def audit_write() -> None:
        try:
            planner.timing_runtime.audit.record_fallback("concurrent-write")
        except BaseException as error:
            failures.append(error)

    def watermark_write() -> None:
        try:
            planner.advance_watermark(_START + timedelta(minutes=1))
        except BaseException as error:
            failures.append(error)

    threads = [Thread(target=audit_write), Thread(target=watermark_write)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=5)
        assert not thread.is_alive()

    assert len(failures) == 2
    assert any(isinstance(error, TimingDistributionError) for error in failures)
    assert any(isinstance(error, StateError) for error in failures)
    with preparation.claimed_commit() as claimed:
        claimed.commit_no_fail()


def test_certified_abort_releases_lane_and_preserves_primary_state() -> None:
    planner = _planner()
    before = planner.state_digest()
    with planner.prepared_planning() as preparation:
        pass

    with pytest.raises(RuntimeError, match="outer owner failed"):
        with preparation.claimed_commit() as claimed:
            claimed.certify_composite_commit(claimed.expected_receipt)
            raise RuntimeError("outer owner failed")

    assert preparation.census().state == "cancelled"
    assert planner.state_digest() == before
    census = planner.preparation_authority_census()
    assert census.active_claims == 0
    assert census.terminal_preparations == 0
    assert census.retained_receipts == 0
    assert census.retained_plan_operations == 0
    planner.timing_runtime.audit.record_fallback("after-abort")
    assert planner.timing_runtime.audit.snapshot().fallback_counts["after-abort"] == 1


def test_failure_after_primitive_commit_keeps_receipt_and_releases_lane() -> None:
    planner = _planner()
    with planner.prepared_planning() as preparation:
        preparation.plan_event(_event(), "ecar")

    receipt = None
    with pytest.raises(RuntimeError, match="later owner failed"):
        with preparation.claimed_commit() as claimed:
            claimed.certify_composite_commit(claimed.expected_receipt)
            receipt = claimed.commit_no_fail()
            raise RuntimeError("later owner failed")

    assert receipt is not None
    assert planner.authenticates_preparation_receipt(receipt)
    assert planner.authenticates_preparation(preparation)
    planner.timing_runtime.audit.record_fallback("after-commit")


def test_runtime_lane_stays_closed_until_planner_cleanup_completes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    planner = _planner()
    cleanup_entered = Event()
    allow_runtime_release = Event()
    original_release = planner.timing_runtime._release_owner_lane

    def delayed_release(marker: object) -> None:
        cleanup_entered.set()
        assert allow_runtime_release.wait(timeout=5)
        original_release(marker)

    monkeypatch.setattr(planner.timing_runtime, "_release_owner_lane", delayed_release)
    failures: list[BaseException] = []

    def commit() -> None:
        try:
            with planner.prepared_planning() as preparation:
                pass
            with preparation.claimed_commit() as claimed:
                claimed.commit_no_fail()
        except BaseException as error:
            failures.append(error)

    thread = Thread(target=commit)
    thread.start()
    assert cleanup_entered.wait(timeout=5)
    with pytest.raises(TimingDistributionError, match="active owner claim"):
        planner.timing_runtime.audit.record_fallback("during-cleanup")
    allow_runtime_release.set()
    thread.join(timeout=5)
    assert not thread.is_alive()
    assert failures == []

    planner.timing_runtime.audit.record_fallback("after-cleanup")
    audit = planner.timing_runtime.audit.snapshot()
    assert "during-cleanup" not in audit.fallback_counts
    assert audit.fallback_counts["after-cleanup"] == 1


def test_terminal_authority_is_bounded_and_discards_commit_plans() -> None:
    planner = SourceTimingPlanner(
        timing_runtime=TimingRuntime(reference_time=_START, namespace="terminal-capacity"),
        preparation_authority_capacity=2,
    )
    retained = []
    for _ordinal in range(2):
        with planner.prepared_planning() as preparation:
            preparation.plan_event(_event(), "ecar")
        with preparation.claimed_commit() as claimed:
            claimed.commit_no_fail()
        retained.append(preparation)

    census = planner.preparation_authority_census()
    assert census.retained_preparations == 2
    assert census.active_claims == 0
    assert census.terminal_preparations == 2
    assert census.retained_receipts == 2
    assert census.retained_plan_operations == 0
    assert census.high_water_preparations == 2
    assert census.high_water_receipts == 2

    with planner.prepared_planning() as rejected:
        pass
    with pytest.raises(StateError, match="receipt capacity is exhausted"):
        with rejected.claimed_commit():
            pass
    rejected.cancel()

    retained.pop(0)
    gc.collect()
    with planner.prepared_planning() as replacement:
        pass
    with replacement.claimed_commit() as claimed:
        claimed.commit_no_fail()
    assert planner.preparation_authority_census().retained_preparations == 2


@pytest.mark.parametrize("hours", [24, 24 * 7, 24 * 30])
def test_terminal_authority_plateaus_across_duration(hours: int) -> None:
    planner = SourceTimingPlanner(
        timing_runtime=TimingRuntime(reference_time=_START, namespace=f"plateau-{hours}"),
        preparation_authority_capacity=4,
    )
    for _ordinal in range(hours):
        with planner.prepared_planning() as preparation:
            pass
        with preparation.claimed_commit() as claimed:
            claimed.commit_no_fail()
        del claimed
        del preparation
    gc.collect()

    census = planner.preparation_authority_census()
    assert census.retained_preparations == 0
    assert census.retained_receipts == 0
    assert census.retained_plan_operations == 0
    assert census.high_water_preparations <= 1
    assert census.high_water_receipts <= 1


def test_large_prewarmed_claim_and_commit_plan_are_operation_native() -> None:
    planner = SourceTimingPlanner(
        timing_runtime=TimingRuntime(
            reference_time=_START,
            namespace="large-prewarmed-delta",
            max_clock_cache_entries=2_048,
        )
    )
    for family in (spec.name for spec in planner.index_family_specs):
        for ordinal in range(256):
            planner.load_probe_entry(family, ordinal, _START)
    clock_spec = SourceClockSpec(
        offset_microseconds=ConstantDistribution(0),
        drift_ppm=ConstantDistribution(0),
    )
    for ordinal in range(2_048):
        planner.timing_runtime.clocks.state(
            SourceClockKey(kind="endpoint", identity=f"host-{ordinal}"),
            clock_spec,
        )

    with planner.prepared_planning() as preparation:
        preparation.plan_event(_event(), "ecar")
    with preparation.claimed_commit() as claimed:
        record = planner._active_preparation_claim_record(claimed)
        assert record is not None
        assert sum(len(plan.operations) for plan in record.cache_plans) == (
            claimed.staged_cache_operations
        )
        runtime_plan = record.runtime_plan
        runtime_preparation = claimed._runtime_preparation
        assert runtime_plan is not None
        assert runtime_preparation is not None
        assert runtime_plan.audit_delta.operation_count == claimed.staged_audit_operations
        assert runtime_plan.clock_states is runtime_preparation.clocks._states
        assert record.retained_plan_operations < 512
        claimed.certify_composite_commit(claimed.expected_receipt)
        claimed.commit_no_fail()

    census = planner.preparation_authority_census()
    assert census.retained_plan_operations == 0
    tree = ast.parse(
        inspect.cleandoc(inspect.getsource(SourceTimingPreparation._freeze_claim_record))
    )
    assert not any(isinstance(node, ast.Name) and node.id == "deepcopy" for node in ast.walk(tree))
    assert not any(
        isinstance(node, ast.Attribute)
        and node.attr in {"_records", "_deadlines", "items", "values"}
        for node in ast.walk(tree)
    )
    for method in (
        SourceTimingPlanner._install_preparation_claim_record,
        SourceTimingPlanner._retain_expected_preparation_receipt,
        SourceTimingPlanner.preparation_authority_census,
    ):
        authority_tree = ast.parse(dedent(inspect.getsource(method)))
        assert not any(
            isinstance(
                node,
                (ast.For, ast.ListComp, ast.SetComp, ast.DictComp, ast.GeneratorExp),
            )
            for node in ast.walk(authority_tree)
        )
