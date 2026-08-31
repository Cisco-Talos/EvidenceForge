# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Adversarial coverage for local-artifact prepared-publication capabilities."""

from __future__ import annotations

import copy
import gc
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from weakref import ref

import pytest

import evidenceforge.generation.deployment_registry as deployment_registry_module
from evidenceforge.events.content_identity import (
    FileContentIdentity,
    LocalArtifactBinaryIdentity,
    LocalArtifactIdentity,
    LocalArtifactVersionRecord,
)
from evidenceforge.generation.deployment_registry import (
    LocalArtifactCapacityError,
    LocalArtifactPreparedCommit,
    LocalArtifactVersionRegistry,
)
from evidenceforge.generation.indexes import ExpiringIndex, ReferenceLeaseIndex
from evidenceforge.models.exceptions import StateError

_START = datetime(2026, 8, 17, 12, 0, tzinfo=UTC)


def _record(label: str) -> LocalArtifactVersionRecord:
    content = FileContentIdentity(
        file_object_id=f"file-object-{label}",
        version=1,
        size_bytes=4_096,
        mime_type="application/vnd.microsoft.portable-executable",
        seed_ref=f"content-seed-{label}",
    )
    artifact = LocalArtifactIdentity(
        hostname="WS-01",
        principal="ALICE",
        platform="windows",
        user_profile_id="profile-alice",
        application_profile_id="application-profile-browser",
        application_id="browser",
        family="download",
        source_object_id=f"download-{label}",
        native_path=rf"C:\Users\alice\Downloads\{label}.exe",
        content_id=content.content_id,
    )
    binary = LocalArtifactBinaryIdentity(
        artifact_version_id=artifact.artifact_version_id,
        content_id=content.content_id,
        digests=content.digests,
        platform="windows",
        architecture="x64",
        artifact_name=f"{label}.exe",
    )
    return LocalArtifactVersionRecord(artifact=artifact, content=content, binary=binary)


def _assert_empty_preparation_census(registry: LocalArtifactVersionRegistry) -> None:
    census = registry.census()
    assert census.prepared_publications == 0
    assert census.claimed_publications == 0
    assert census.reserved_slots == 0
    assert census.prepared_retained_members == 0
    assert census.prepared_retained_bytes == 0
    assert census.prepared_capability_locators == 0
    assert census.committing_publications == 0


def test_prepared_publication_authenticates_exact_object_and_committed_receipt() -> None:
    record = _record("alpha")
    registry = LocalArtifactVersionRegistry(capacity=2)
    foreign = LocalArtifactVersionRegistry(capacity=2)
    token = registry.prepare_publish_version(record, _START)
    copied = copy.copy(token)
    caller_built = LocalArtifactPreparedCommit(registry, token)

    assert registry.authenticates_prepared_publication(token)
    assert not registry.authenticates_prepared_publication(copied)
    assert not foreign.authenticates_prepared_publication(token)
    with pytest.raises(StateError, match="stale or already consumed"):
        caller_built.commit_no_fail()
    assert not registry.cancel_prepared(copied)
    assert registry.authenticates_prepared_publication(token)

    publication_token = token.publication_token
    with registry.prepared_publication(token) as publication:
        assert publication.publication_token == publication_token
        expected_receipt = publication.expected_receipt
        assert expected_receipt is not None
        assert registry.authenticates_publication_receipt(
            expected_receipt,
            publication_token=publication_token,
        )
        copied_publication = copy.copy(publication)
        with pytest.raises(StateError, match="stale or already consumed"):
            copied_publication.commit_no_fail()
        receipt = publication.commit_no_fail()
        assert receipt is expected_receipt
        assert publication.receipt is receipt
        assert publication.handle == receipt.handle
        with pytest.raises(StateError, match="already committed"):
            publication.commit()

    assert receipt.artifact_version_id == record.artifact.artifact_version_id
    assert receipt.publication_token == publication_token
    assert receipt.packed_locator >= 0
    assert registry.authenticates_publication_receipt(receipt)
    assert registry.authenticates_publication_receipt(
        receipt,
        publication_token=publication_token,
    )
    assert not foreign.authenticates_publication_receipt(receipt)
    assert not registry.authenticates_publication_receipt(
        replace(receipt, handle=receipt.handle + 1)
    )
    assert not registry.authenticates_prepared_publication(token)
    assert not registry.cancel_prepared(token)
    with pytest.raises(StateError, match="stale or already consumed"):
        with registry.prepared_publication(token):
            pass
    _assert_empty_preparation_census(registry)


def test_claim_finalizer_uses_registry_state_and_preserves_outer_failure() -> None:
    registry = LocalArtifactVersionRegistry(capacity=1)
    token = registry.prepare_publish_version(_record("alpha"), _START)

    with pytest.raises(RuntimeError, match="outer transaction failed"):
        with registry.prepared_publication(token) as publication:
            object.__setattr__(publication, "_committed", True)
            object.__setattr__(token, "_reservation_id", 99_999)
            object.__setattr__(token.record.artifact, "hostname", "retargeted-host")
            raise RuntimeError("outer transaction failed")

    _assert_empty_preparation_census(registry)


def test_claim_is_thread_bound_and_cancel_cannot_race_commit_tail() -> None:
    record = _record("alpha")
    registry = LocalArtifactVersionRegistry(capacity=1)
    token = registry.prepare_publish_version(record, _START)

    with ThreadPoolExecutor(max_workers=1) as executor:
        with registry.prepared_publication(token) as publication:
            assert executor.submit(registry.cancel_prepared, token).result(timeout=2) is False
            with pytest.raises(StateError, match="claiming thread"):
                executor.submit(publication.commit_no_fail).result(timeout=2)
            receipt = publication.commit_no_fail()

    assert registry.resolve_version(record.artifact.artifact_version_id) == record
    assert registry.authenticates_publication_receipt(receipt)
    _assert_empty_preparation_census(registry)


def test_ownerless_and_watermark_stale_preparations_are_pruned() -> None:
    registry = LocalArtifactVersionRegistry(capacity=1, retention=timedelta(minutes=30))
    token = registry.prepare_publish_version(_record("alpha"), _START)
    token_ref = ref(token)
    del token
    gc.collect()

    assert token_ref() is None
    assert registry.prune_prepared_publications() == 1
    _assert_empty_preparation_census(registry)

    stale = registry.prepare_publish_version(_record("bravo"), _START)
    assert registry.advance_watermark(_START + timedelta(minutes=1)) == ()
    assert registry.prune_prepared_publications() == 1
    assert not registry.authenticates_prepared_publication(stale)
    _assert_empty_preparation_census(registry)

    claimed = registry.prepare_publish_version(
        _record("charl"),
        _START + timedelta(minutes=1),
    )
    with registry.prepared_publication(claimed):
        assert registry.prune_prepared_publications() == 0
        assert registry.census().claimed_publications == 1
    _assert_empty_preparation_census(registry)


def test_preparation_member_and_retained_byte_caps_are_exact_and_atomic() -> None:
    first_record = _record("alpha")
    second_record = _record("bravo")
    calibration = LocalArtifactVersionRegistry(capacity=2)
    calibration_token = calibration.prepare_publish_version(first_record, _START)
    request_bytes = calibration.census().prepared_retained_bytes
    assert calibration.cancel_prepared(calibration_token)

    registry = LocalArtifactVersionRegistry(
        capacity=2,
        prepared_byte_capacity=(request_bytes * 2) - 1,
    )
    first = registry.prepare_publish_version(first_record, _START)
    before = registry.census()
    assert before.prepared_retained_members == 1
    assert before.prepared_member_capacity == 2
    assert before.prepared_retained_bytes == request_bytes
    assert before.prepared_byte_capacity == (request_bytes * 2) - 1
    assert before.prepared_capability_locators == 1

    with pytest.raises(LocalArtifactCapacityError, match="retained-byte capacity"):
        registry.prepare_publish_version(second_record, _START)
    assert registry.census() == before
    assert registry.cancel_prepared(first)
    _assert_empty_preparation_census(registry)

    per_request = LocalArtifactVersionRegistry(
        capacity=1,
        prepared_byte_capacity=request_bytes - 1,
    )
    with pytest.raises(LocalArtifactCapacityError, match="request-byte capacity"):
        per_request.prepare_publish_version(first_record, _START)
    _assert_empty_preparation_census(per_request)


def test_prepare_hot_path_does_not_scan_or_sort_live_reservations(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def reject_full_prune(_registry: LocalArtifactVersionRegistry) -> int:
        raise AssertionError("full preparation pruning is forbidden on admission")

    monkeypatch.setattr(
        LocalArtifactVersionRegistry,
        "_prune_prepared_publications_locked",
        reject_full_prune,
    )
    registry = LocalArtifactVersionRegistry(capacity=32)
    tokens = [
        registry.prepare_publish_version(_record(f"item-{index:02d}"), _START)
        for index in range(32)
    ]

    assert registry.census().prepared_retained_members == 32
    for token in tokens:
        assert registry.cancel_prepared(token)
    _assert_empty_preparation_census(registry)


def test_post_publish_failure_rolls_back_canonical_and_reservation_state(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    original_commit = LocalArtifactVersionRegistry._commit_prepared_locked

    def fail_after_publish(
        registry: LocalArtifactVersionRegistry,
        reservation: object,
        plan: object,
    ) -> object:
        original_commit(registry, reservation, plan)  # type: ignore[arg-type]
        raise RuntimeError("injected post-publish failure")

    monkeypatch.setattr(
        LocalArtifactVersionRegistry,
        "_commit_prepared_locked",
        fail_after_publish,
    )
    record = _record("alpha")
    registry = LocalArtifactVersionRegistry(capacity=1)
    token = registry.prepare_publish_version(record, _START)
    later_owner_commits: list[str] = []

    with pytest.raises(RuntimeError, match="injected post-publish failure"):
        with registry.prepared_publication(token) as publication:
            publication.commit_no_fail()
            later_owner_commits.append("state-lifecycle-audit")

    assert later_owner_commits == []
    assert registry.resolve_version(record.artifact.artifact_version_id) is None
    census = registry.census()
    assert census.live_versions == 0
    assert census.leased_versions == 0
    assert census.active_leases == 0
    _assert_empty_preparation_census(registry)


def test_post_lease_failure_rolls_back_artifact_lease_and_reservation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    original_acquire = ReferenceLeaseIndex.acquire
    injected = False

    def fail_after_lease(
        leases: ReferenceLeaseIndex[str, str],
        key: str,
        owner: str,
        *,
        deadline: float,
    ) -> None:
        nonlocal injected
        original_acquire(leases, key, owner, deadline=deadline)
        if not injected:
            injected = True
            raise RuntimeError("injected post-lease failure")

    monkeypatch.setattr(ReferenceLeaseIndex, "acquire", fail_after_lease)
    record = _record("alpha")
    registry = LocalArtifactVersionRegistry(capacity=1, retention=timedelta(hours=1))
    token = registry.prepare_publish_version(
        record,
        _START,
        lease_owner="process:4242",
        lease_until=_START + timedelta(hours=2),
    )

    with pytest.raises(RuntimeError, match="injected post-lease failure"):
        with registry.prepared_publication(token) as publication:
            publication.commit_no_fail()

    assert registry.resolve_version(record.artifact.artifact_version_id) is None
    census = registry.census()
    assert census.live_versions == 0
    assert census.leased_versions == 0
    assert census.active_leases == 0
    _assert_empty_preparation_census(registry)


def test_prepare_and_claim_installation_failures_release_exact_capacity(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    registry = LocalArtifactVersionRegistry(capacity=1)
    baseline = registry.census(estimate_bytes=True)

    def reject_record_preimage(_record: object) -> bytes:
        raise ZeroDivisionError("injected prepare preimage failure")

    monkeypatch.setattr(
        deployment_registry_module,
        "_local_artifact_record_preimage",
        reject_record_preimage,
    )
    with pytest.raises(ZeroDivisionError, match="prepare preimage"):
        registry.prepare_publish_version(_record("alpha"), _START)
    assert registry.census(estimate_bytes=True) == baseline
    _assert_empty_preparation_census(registry)

    monkeypatch.undo()
    original_reservation = deployment_registry_module._LocalArtifactPreparedReservation

    def reject_reservation(*_args: object, **_kwargs: object) -> object:
        raise ZeroDivisionError("injected reservation construction failure")

    monkeypatch.setattr(
        deployment_registry_module,
        "_LocalArtifactPreparedReservation",
        reject_reservation,
    )
    with pytest.raises(ZeroDivisionError, match="reservation construction"):
        registry.prepare_publish_version(_record("bravo"), _START)
    assert registry.census(estimate_bytes=True) == baseline
    _assert_empty_preparation_census(registry)

    monkeypatch.setattr(
        deployment_registry_module,
        "_LocalArtifactPreparedReservation",
        original_reservation,
    )
    token = registry.prepare_publish_version(_record("charl"), _START)

    class RejectingLocator(dict[int, int]):
        def __setitem__(self, key: int, value: int) -> None:
            raise ZeroDivisionError("injected claim locator failure")

    registry._prepared_commit_locators = RejectingLocator()  # type: ignore[attr-defined]
    with pytest.raises(ZeroDivisionError, match="claim locator"):
        with registry.prepared_publication(token):
            pass
    assert registry.census(estimate_bytes=True) == baseline
    _assert_empty_preparation_census(registry)


def test_claimed_existing_version_fences_plan_inputs_until_cancel() -> None:
    record = _record("alpha")
    version_id = record.artifact.artifact_version_id
    registry = LocalArtifactVersionRegistry(capacity=1, retention=timedelta(hours=1))
    token = registry.prepare_publish_version(
        record,
        _START,
        lease_owner="process:4242",
        lease_until=_START + timedelta(hours=2),
    )
    with registry.prepared_publication(token) as publication:
        publication.commit_no_fail()

    refresh = registry.prepare_publish_version(record, _START + timedelta(minutes=5))
    with registry.prepared_publication(refresh):
        with pytest.raises(StateError, match="active claimed publication"):
            registry.acquire_lease(
                version_id,
                "process:5150",
                _START + timedelta(hours=3),
            )
        with pytest.raises(StateError, match="active claimed publication"):
            registry.release_lease(version_id, "process:4242")
        assert registry.release_owner("process:4242") == ()
        with pytest.raises(StateError, match="active claimed publication"):
            registry.advance_watermark(_START + timedelta(minutes=1))

    assert registry.census().active_leases == 1
    assert registry.release_owner("process:4242") == (version_id,)
    assert registry.census().active_leases == 0
    _assert_empty_preparation_census(registry)


def test_partial_store_index_failure_is_baseexception_atomic_and_repeatable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    original_add = deployment_registry_module._PackedPrimaryIndex.add

    class InjectedAbort(BaseException):
        pass

    def fail_after_primary_add(
        index: object,
        digest: bytes,
        handle: int,
        digest_for_handle: object,
    ) -> None:
        original_add(index, digest, handle, digest_for_handle)  # type: ignore[arg-type]
        raise InjectedAbort("injected partial primary insertion")

    monkeypatch.setattr(
        deployment_registry_module._PackedPrimaryIndex,
        "add",
        fail_after_primary_add,
    )
    registry = LocalArtifactVersionRegistry(capacity=1)
    baseline = registry.census(estimate_bytes=True)
    baseline_metrics = registry.index_metrics(estimate_bytes=True)

    for index in range(4):
        record = _record(f"fault-{index}")
        token = registry.prepare_publish_version(record, _START)
        with pytest.raises(InjectedAbort, match="partial primary"):
            with registry.prepared_publication(token) as publication:
                publication.commit_no_fail()
        assert registry.resolve_version(record.artifact.artifact_version_id) is None
        assert registry.census(estimate_bytes=True) == baseline
        assert registry.index_metrics(estimate_bytes=True) == baseline_metrics
        _assert_empty_preparation_census(registry)


def test_partial_lease_and_deadline_failures_restore_backing_census(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    registry = LocalArtifactVersionRegistry(capacity=1, retention=timedelta(hours=1))
    baseline = registry.census(estimate_bytes=True)
    baseline_metrics = registry.index_metrics(estimate_bytes=True)

    def fail_before_expiration(
        _expirations: ExpiringIndex[tuple[str, str], bool],
        _pair: tuple[str, str],
        _marker: bool,
        _deadline: float,
    ) -> None:
        raise ZeroDivisionError("injected partial lease insertion")

    monkeypatch.setattr(ExpiringIndex, "set", fail_before_expiration)
    token = registry.prepare_publish_version(
        _record("lease-fault"),
        _START,
        lease_owner="process:4242",
        lease_until=_START + timedelta(hours=2),
    )
    with pytest.raises(ZeroDivisionError, match="partial lease"):
        with registry.prepared_publication(token) as publication:
            publication.commit_no_fail()
    assert registry.census(estimate_bytes=True) == baseline
    assert registry.index_metrics(estimate_bytes=True) == baseline_metrics

    monkeypatch.undo()
    original_set = deployment_registry_module._CompactArtifactDeadlines.set

    def fail_after_deadline(index: object, handle: int, deadline: float) -> None:
        original_set(index, handle, deadline)  # type: ignore[arg-type]
        raise ZeroDivisionError("injected partial deadline insertion")

    monkeypatch.setattr(
        deployment_registry_module._CompactArtifactDeadlines,
        "set",
        fail_after_deadline,
    )
    token = registry.prepare_publish_version(_record("deadline-fault"), _START)
    with pytest.raises(ZeroDivisionError, match="partial deadline"):
        with registry.prepared_publication(token) as publication:
            publication.commit_no_fail()
    assert registry.census(estimate_bytes=True) == baseline
    assert registry.index_metrics(estimate_bytes=True) == baseline_metrics
    _assert_empty_preparation_census(registry)


@pytest.mark.parametrize("fault_prepared_first", (True, False))
def test_disjoint_commit_survives_other_claim_rollback(
    monkeypatch: pytest.MonkeyPatch,
    fault_prepared_first: bool,
) -> None:
    fault_record = _record("fault")
    survivor_record = _record("survivor")
    registry = LocalArtifactVersionRegistry(
        capacity=2,
        shard_count=1,
        retention=timedelta(hours=1),
    )
    if fault_prepared_first:
        fault_token = registry.prepare_publish_version(
            fault_record,
            _START,
            lease_owner="process:fault",
            lease_until=_START + timedelta(hours=2),
        )
        survivor_token = registry.prepare_publish_version(
            survivor_record,
            _START,
            lease_owner="process:survivor",
            lease_until=_START + timedelta(hours=2),
        )
    else:
        survivor_token = registry.prepare_publish_version(
            survivor_record,
            _START,
            lease_owner="process:survivor",
            lease_until=_START + timedelta(hours=2),
        )
        fault_token = registry.prepare_publish_version(
            fault_record,
            _START,
            lease_owner="process:fault",
            lease_until=_START + timedelta(hours=2),
        )

    original_commit = LocalArtifactVersionRegistry._commit_prepared_locked

    def fail_fault_member_after_publish(
        owner: LocalArtifactVersionRegistry,
        reservation: object,
        plan: object,
    ) -> object:
        receipt = original_commit(owner, reservation, plan)  # type: ignore[arg-type]
        canonical = reservation.canonical_token  # type: ignore[attr-defined]
        if canonical.record.artifact.artifact_version_id == (
            fault_record.artifact.artifact_version_id
        ):
            raise ZeroDivisionError("injected disjoint publication failure")
        return receipt

    with registry.prepared_publication(fault_token) as fault_publication:
        with registry.prepared_publication(survivor_token) as survivor_publication:
            survivor_receipt = survivor_publication.commit_no_fail()
        survivor_state = (
            len(registry),
            registry._live_count,  # type: ignore[attr-defined]
            registry._high_water_mark,  # type: ignore[attr-defined]
            registry._shards[0].mutation_version,  # type: ignore[attr-defined]
            len(registry._shards[0].store),  # type: ignore[attr-defined]
            len(registry._shards[0].store._primary),  # type: ignore[attr-defined]
            registry._shards[0].store._high_water,  # type: ignore[attr-defined]
            registry._shards[0].store._compaction_rotations,  # type: ignore[attr-defined]
            registry._shards[0].store._compaction_work,  # type: ignore[attr-defined]
            registry._shards[0].deadlines.metrics(estimate_bytes=True),  # type: ignore[attr-defined]
            registry._shards[0].leases.metrics(estimate_bytes=True),  # type: ignore[attr-defined]
            registry._route_metrics(estimate_bytes=True),  # type: ignore[attr-defined]
        )
        monkeypatch.setattr(
            LocalArtifactVersionRegistry,
            "_commit_prepared_locked",
            fail_fault_member_after_publish,
        )
        with pytest.raises(ZeroDivisionError, match="disjoint publication"):
            fault_publication.commit_no_fail()

    assert registry.resolve_version(survivor_record.artifact.artifact_version_id) == (
        survivor_record
    )
    assert registry.resolve_version(fault_record.artifact.artifact_version_id) is None
    assert registry.authenticates_publication_receipt(survivor_receipt)
    assert (
        len(registry),
        registry._live_count,  # type: ignore[attr-defined]
        registry._high_water_mark,  # type: ignore[attr-defined]
        registry._shards[0].mutation_version,  # type: ignore[attr-defined]
        len(registry._shards[0].store),  # type: ignore[attr-defined]
        len(registry._shards[0].store._primary),  # type: ignore[attr-defined]
        registry._shards[0].store._high_water,  # type: ignore[attr-defined]
        registry._shards[0].store._compaction_rotations,  # type: ignore[attr-defined]
        registry._shards[0].store._compaction_work,  # type: ignore[attr-defined]
        registry._shards[0].deadlines.metrics(estimate_bytes=True),  # type: ignore[attr-defined]
        registry._shards[0].leases.metrics(estimate_bytes=True),  # type: ignore[attr-defined]
        registry._route_metrics(estimate_bytes=True),  # type: ignore[attr-defined]
    ) == survivor_state
    census = registry.census()
    assert census.live_versions == 1
    assert census.leased_versions == 1
    assert census.active_leases == 1
    _assert_empty_preparation_census(registry)


def test_group_commit_is_ordered_authenticated_and_all_or_zero(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    records = (_record("alpha"), _record("bravo"), _record("charl"))
    registry = LocalArtifactVersionRegistry(capacity=3, shard_count=1)
    baseline = registry.census(estimate_bytes=True)
    baseline_metrics = registry.index_metrics(estimate_bytes=True)
    tokens = tuple(registry.prepare_publish_version(record, _START) for record in records)
    original_commit = LocalArtifactVersionRegistry._commit_prepared_locked

    def fail_second_after_publish(
        owner: LocalArtifactVersionRegistry,
        reservation: object,
        plan: object,
    ) -> object:
        receipt = original_commit(owner, reservation, plan)  # type: ignore[arg-type]
        canonical = reservation.canonical_token  # type: ignore[attr-defined]
        if canonical.record.artifact.artifact_version_id == records[1].artifact.artifact_version_id:
            raise RuntimeError("injected group member failure")
        return receipt

    monkeypatch.setattr(
        LocalArtifactVersionRegistry,
        "_commit_prepared_locked",
        fail_second_after_publish,
    )
    with pytest.raises(RuntimeError, match="group member failure"):
        with registry.prepared_publication_group(tokens) as publication:
            assert publication.publication_tokens == tuple(
                token.publication_token for token in tokens
            )
            publication.commit_no_fail()

    assert all(
        registry.resolve_version(record.artifact.artifact_version_id) is None for record in records
    )
    assert registry.census(estimate_bytes=True) == baseline
    assert registry.index_metrics(estimate_bytes=True) == baseline_metrics
    _assert_empty_preparation_census(registry)
    monkeypatch.undo()
    committed_tokens = tuple(
        registry.prepare_publish_version(record, _START) for record in reversed(records)
    )
    with registry.prepared_publication_group(committed_tokens) as publication:
        expected_group_receipt = publication.expected_receipt
        assert registry.authenticates_publication_group_receipt(
            expected_group_receipt,
            publication_tokens=publication.publication_tokens,
        )
        copied = copy.copy(publication)
        with pytest.raises(StateError, match="stale or already consumed"):
            copied.commit_no_fail()
        group_receipt = publication.commit_no_fail()
        assert group_receipt is expected_group_receipt
        assert publication.receipt is group_receipt
        with pytest.raises(StateError, match="already committed"):
            publication.commit()

    publication_tokens = tuple(token.publication_token for token in committed_tokens)
    assert group_receipt.publication_tokens == publication_tokens
    assert tuple(receipt.artifact_version_id for receipt in group_receipt.receipts) == tuple(
        record.artifact.artifact_version_id for record in reversed(records)
    )
    assert registry.authenticates_publication_group_receipt(group_receipt)
    assert registry.authenticates_publication_group_receipt(
        group_receipt,
        publication_tokens=publication_tokens,
    )
    assert not registry.authenticates_publication_group_receipt(
        replace(group_receipt, receipts=tuple(reversed(group_receipt.receipts)))
    )
    _assert_empty_preparation_census(registry)


def test_group_admission_is_nonempty_deduplicated_and_member_bounded() -> None:
    registry = LocalArtifactVersionRegistry(capacity=2, shard_count=1)
    token = registry.prepare_publish_version(_record("alpha"), _START)

    with pytest.raises(ValueError, match="at least one"):
        with registry.prepared_publication_group(()):
            pass
    with pytest.raises(StateError, match="duplicate token"):
        with registry.prepared_publication_group((token, token)):
            pass
    with pytest.raises(LocalArtifactCapacityError, match="member capacity"):
        with registry.prepared_publication_group((token, token, token)):
            pass

    assert registry.authenticates_prepared_publication(token)
    assert registry.cancel_prepared(token)
    _assert_empty_preparation_census(registry)


def test_success_release_failure_cannot_publish_without_returning_receipt(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    registry = LocalArtifactVersionRegistry(capacity=1)
    baseline = registry.census(estimate_bytes=True)
    baseline_metrics = registry.index_metrics(estimate_bytes=True)
    record = _record("alpha")
    token = registry.prepare_publish_version(record, _START)
    original_release = LocalArtifactVersionRegistry._release_prepared_locked
    injected = False

    def fail_after_success_release(
        owner: LocalArtifactVersionRegistry,
        reservation: object,
        *,
        allow_committing: bool = False,
    ) -> bool:
        nonlocal injected
        released = original_release(
            owner,
            reservation,  # type: ignore[arg-type]
            allow_committing=allow_committing,
        )
        if allow_committing and released and not injected:
            injected = True
            raise ZeroDivisionError("injected post-release failure")
        return released

    monkeypatch.setattr(
        LocalArtifactVersionRegistry,
        "_release_prepared_locked",
        fail_after_success_release,
    )
    with pytest.raises(ZeroDivisionError, match="post-release failure"):
        with registry.prepared_publication(token) as publication:
            publication.commit_no_fail()

    assert registry.resolve_version(record.artifact.artifact_version_id) is None
    assert registry.census(estimate_bytes=True) == baseline
    assert registry.index_metrics(estimate_bytes=True) == baseline_metrics
    _assert_empty_preparation_census(registry)


def test_cleanup_failure_preserves_body_error_and_closes_capability(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    registry = LocalArtifactVersionRegistry(capacity=1)
    token = registry.prepare_publish_version(_record("alpha"), _START)
    original_cancel = LocalArtifactVersionRegistry._cancel_claimed

    def fail_after_cancel(
        owner: LocalArtifactVersionRegistry,
        publication: LocalArtifactPreparedCommit,
    ) -> None:
        original_cancel(owner, publication)
        raise ZeroDivisionError("injected finalizer cleanup failure")

    monkeypatch.setattr(
        LocalArtifactVersionRegistry,
        "_cancel_claimed",
        fail_after_cancel,
    )
    capability: LocalArtifactPreparedCommit | None = None
    with pytest.raises(RuntimeError, match="outer owner failed") as exc_info:
        with registry.prepared_publication(token) as publication:
            capability = publication
            raise RuntimeError("outer owner failed")

    assert capability is not None
    assert any(
        "finalizer cleanup failure" in note for note in getattr(exc_info.value, "__notes__", ())
    )
    with pytest.raises(StateError, match="no longer active"):
        capability.commit_no_fail()
    _assert_empty_preparation_census(registry)


@pytest.mark.parametrize("fail_before_release", (True, False))
def test_group_member_release_failure_rolls_back_every_publication(
    monkeypatch: pytest.MonkeyPatch,
    fail_before_release: bool,
) -> None:
    records = (_record("alpha"), _record("bravo"), _record("charl"))
    registry = LocalArtifactVersionRegistry(capacity=3, shard_count=1)
    baseline = registry.census(estimate_bytes=True)
    baseline_metrics = registry.index_metrics(estimate_bytes=True)
    tokens = tuple(registry.prepare_publish_version(record, _START) for record in records)
    target_version = records[1].artifact.artifact_version_id
    original_release = LocalArtifactVersionRegistry._release_prepared_locked
    injected = False

    def fail_middle_release(
        owner: LocalArtifactVersionRegistry,
        reservation: object,
        *,
        allow_committing: bool = False,
        preserve_commit_locator: bool = False,
    ) -> bool:
        nonlocal injected
        is_target = (
            reservation.canonical_token.record.artifact.artifact_version_id  # type: ignore[attr-defined]
            == target_version
        )
        if allow_committing and is_target and not injected and fail_before_release:
            injected = True
            raise ZeroDivisionError("injected group release failure")
        released = original_release(
            owner,
            reservation,  # type: ignore[arg-type]
            allow_committing=allow_committing,
            preserve_commit_locator=preserve_commit_locator,
        )
        if allow_committing and is_target and not injected:
            injected = True
            raise ZeroDivisionError("injected group release failure")
        return released

    monkeypatch.setattr(
        LocalArtifactVersionRegistry,
        "_release_prepared_locked",
        fail_middle_release,
    )
    with pytest.raises(ZeroDivisionError, match="group release failure"):
        with registry.prepared_publication_group(tokens) as publication:
            publication.commit_no_fail()

    assert all(
        registry.resolve_version(record.artifact.artifact_version_id) is None for record in records
    )
    assert registry.census(estimate_bytes=True) == baseline
    assert registry.index_metrics(estimate_bytes=True) == baseline_metrics
    _assert_empty_preparation_census(registry)


def test_group_finalizer_failure_preserves_body_error_closes_and_cleans(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    records = (_record("alpha"), _record("bravo"), _record("charl"))
    registry = LocalArtifactVersionRegistry(capacity=3, shard_count=1)
    baseline = registry.census(estimate_bytes=True)
    tokens = tuple(registry.prepare_publish_version(record, _START) for record in records)
    target_version = records[1].artifact.artifact_version_id
    original_release = LocalArtifactVersionRegistry._release_prepared_locked
    injected = False

    def fail_before_middle_cancel(
        owner: LocalArtifactVersionRegistry,
        reservation: object,
        *,
        allow_committing: bool = False,
        preserve_commit_locator: bool = False,
    ) -> bool:
        nonlocal injected
        is_target = (
            reservation.canonical_token.record.artifact.artifact_version_id  # type: ignore[attr-defined]
            == target_version
        )
        if not allow_committing and is_target and not injected:
            injected = True
            raise ZeroDivisionError("injected group finalizer failure")
        return original_release(
            owner,
            reservation,  # type: ignore[arg-type]
            allow_committing=allow_committing,
            preserve_commit_locator=preserve_commit_locator,
        )

    monkeypatch.setattr(
        LocalArtifactVersionRegistry,
        "_release_prepared_locked",
        fail_before_middle_cancel,
    )
    capability: object | None = None
    with pytest.raises(RuntimeError, match="outer group owner failed") as exc_info:
        with registry.prepared_publication_group(tokens) as publication:
            capability = publication
            raise RuntimeError("outer group owner failed")

    assert capability is not None
    assert any(
        "group finalizer failure" in note for note in getattr(exc_info.value, "__notes__", ())
    )
    with pytest.raises(StateError, match="no longer active"):
        capability.commit_no_fail()  # type: ignore[attr-defined]
    assert registry.census(estimate_bytes=True) == baseline
    _assert_empty_preparation_census(registry)


def test_multishard_group_failure_releases_sorted_claims_without_residue(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    registry = LocalArtifactVersionRegistry(capacity=8, shard_count=2)
    records_by_shard: dict[int, LocalArtifactVersionRecord] = {}
    for index in range(64):
        record = _record(f"shard-{index:02d}")
        shard_id = registry._shard_id_for(record.artifact.artifact_id)  # type: ignore[attr-defined]
        records_by_shard.setdefault(shard_id, record)
        if len(records_by_shard) == 2:
            break
    assert len(records_by_shard) == 2
    records = tuple(records_by_shard[shard_id] for shard_id in sorted(records_by_shard))
    baseline = registry.census(estimate_bytes=True)
    baseline_metrics = registry.index_metrics(estimate_bytes=True)
    tokens = tuple(registry.prepare_publish_version(record, _START) for record in records)
    original_commit = LocalArtifactVersionRegistry._commit_prepared_locked

    def fail_second_shard_after_publish(
        owner: LocalArtifactVersionRegistry,
        reservation: object,
        plan: object,
    ) -> object:
        receipt = original_commit(owner, reservation, plan)  # type: ignore[arg-type]
        canonical = reservation.canonical_token  # type: ignore[attr-defined]
        if canonical.record.artifact.artifact_version_id == records[1].artifact.artifact_version_id:
            raise ZeroDivisionError("injected multishard group failure")
        return receipt

    monkeypatch.setattr(
        LocalArtifactVersionRegistry,
        "_commit_prepared_locked",
        fail_second_shard_after_publish,
    )
    with pytest.raises(ZeroDivisionError, match="multishard group failure"):
        with registry.prepared_publication_group(tokens) as publication:
            publication.commit_no_fail()

    assert all(
        registry.resolve_version(record.artifact.artifact_version_id) is None for record in records
    )
    assert registry.census(estimate_bytes=True) == baseline
    assert registry.index_metrics(estimate_bytes=True) == baseline_metrics
    _assert_empty_preparation_census(registry)


@pytest.mark.parametrize("fail_after_mutation", (False, True))
def test_internal_reserved_handle_release_fault_is_retryable_and_exact(
    monkeypatch: pytest.MonkeyPatch,
    fail_after_mutation: bool,
) -> None:
    class CleanupAbort(BaseException):
        pass

    registry = LocalArtifactVersionRegistry(capacity=1)
    baseline = registry.census(estimate_bytes=True)
    baseline_metrics = registry.index_metrics(estimate_bytes=True)
    token = registry.prepare_publish_version(_record("alpha"), _START)
    original_release = deployment_registry_module._PackedArtifactStore.release_reserved_handle
    injected = False

    def fault_reserved_release(store: object, handle: int) -> None:
        nonlocal injected
        if not injected and not fail_after_mutation:
            injected = True
            raise CleanupAbort("injected pre-release backing fault")
        original_release(store, handle)  # type: ignore[arg-type]
        if not injected:
            injected = True
            raise CleanupAbort("injected post-release backing fault")

    monkeypatch.setattr(
        deployment_registry_module._PackedArtifactStore,
        "release_reserved_handle",
        fault_reserved_release,
    )
    with pytest.raises(CleanupAbort, match="backing fault"):
        registry.cancel_prepared(token)

    assert registry.census(estimate_bytes=True) == baseline
    assert registry.index_metrics(estimate_bytes=True) == baseline_metrics
    _assert_empty_preparation_census(registry)


@pytest.mark.parametrize("fail_after_mutation", (False, True))
def test_internal_free_pool_append_fault_resumes_without_stranding_capacity(
    monkeypatch: pytest.MonkeyPatch,
    fail_after_mutation: bool,
) -> None:
    class CleanupAbort(BaseException):
        pass

    registry = LocalArtifactVersionRegistry(capacity=2, shard_count=1)
    baseline = registry.census(estimate_bytes=True)
    baseline_metrics = registry.index_metrics(estimate_bytes=True)
    first = registry.prepare_publish_version(_record("alpha"), _START)
    keeper = registry.prepare_publish_version(_record("bravo"), _START)
    original_append = deployment_registry_module._PackedArtifactStore._append_free_handle
    injected = False

    def fault_free_pool_append(store: object, handle: int) -> None:
        nonlocal injected
        if not injected and not fail_after_mutation:
            injected = True
            raise CleanupAbort("injected pre-append allocator fault")
        original_append(store, handle)  # type: ignore[arg-type]
        if not injected:
            injected = True
            raise CleanupAbort("injected post-append allocator fault")

    monkeypatch.setattr(
        deployment_registry_module._PackedArtifactStore,
        "_append_free_handle",
        fault_free_pool_append,
    )
    with pytest.raises(CleanupAbort, match="append allocator fault"):
        registry.cancel_prepared(first)

    assert registry.authenticates_prepared_publication(keeper)
    monkeypatch.undo()
    assert registry.cancel_prepared(keeper)
    assert registry.census(estimate_bytes=True) == baseline
    assert registry.index_metrics(estimate_bytes=True) == baseline_metrics
    _assert_empty_preparation_census(registry)


@pytest.mark.parametrize("fail_after_mutation", (False, True))
def test_internal_tail_collapse_fault_resumes_without_stranding_capacity(
    monkeypatch: pytest.MonkeyPatch,
    fail_after_mutation: bool,
) -> None:
    class CleanupAbort(BaseException):
        pass

    registry = LocalArtifactVersionRegistry(capacity=3, shard_count=1)
    baseline = registry.census(estimate_bytes=True)
    baseline_metrics = registry.index_metrics(estimate_bytes=True)
    keeper = registry.prepare_publish_version(_record("alpha"), _START)
    middle = registry.prepare_publish_version(_record("bravo"), _START)
    tail = registry.prepare_publish_version(_record("charl"), _START)
    assert registry.cancel_prepared(middle)
    original_remove = deployment_registry_module._PackedArtifactStore._remove_free_handle
    injected = False

    def fault_tail_collapse_remove(store: object, handle: int) -> None:
        nonlocal injected
        if not injected and not fail_after_mutation:
            injected = True
            raise CleanupAbort("injected pre-remove allocator fault")
        original_remove(store, handle)  # type: ignore[arg-type]
        if not injected:
            injected = True
            raise CleanupAbort("injected post-remove allocator fault")

    monkeypatch.setattr(
        deployment_registry_module._PackedArtifactStore,
        "_remove_free_handle",
        fault_tail_collapse_remove,
    )
    with pytest.raises(CleanupAbort, match="remove allocator fault"):
        registry.cancel_prepared(tail)

    assert registry.authenticates_prepared_publication(keeper)
    monkeypatch.undo()
    assert registry.cancel_prepared(keeper)
    assert registry.census(estimate_bytes=True) == baseline
    assert registry.index_metrics(estimate_bytes=True) == baseline_metrics
    _assert_empty_preparation_census(registry)


@pytest.mark.parametrize("fail_after_mutation", (False, True))
def test_internal_group_consume_fault_rolls_back_every_member(
    monkeypatch: pytest.MonkeyPatch,
    fail_after_mutation: bool,
) -> None:
    class CleanupAbort(BaseException):
        pass

    records = (_record("alpha"), _record("bravo"), _record("charl"))
    registry = LocalArtifactVersionRegistry(capacity=3, shard_count=1)
    baseline = registry.census(estimate_bytes=True)
    baseline_metrics = registry.index_metrics(estimate_bytes=True)
    tokens = tuple(registry.prepare_publish_version(record, _START) for record in records)
    target_reservation_id = registry._prepared_capability_locators[id(tokens[1])]  # type: ignore[attr-defined]
    target_handle = registry._prepared_reservations[  # type: ignore[attr-defined]
        target_reservation_id
    ].reserved_handle
    assert target_handle is not None
    original_consume = deployment_registry_module._PackedArtifactStore.consume_reserved_handle
    injected = False

    def fault_committed_consume(store: object, handle: int) -> None:
        nonlocal injected
        if handle == target_handle and not injected and not fail_after_mutation:
            injected = True
            raise CleanupAbort("injected pre-consume backing fault")
        original_consume(store, handle)  # type: ignore[arg-type]
        if handle == target_handle and not injected:
            injected = True
            raise CleanupAbort("injected post-consume backing fault")

    monkeypatch.setattr(
        deployment_registry_module._PackedArtifactStore,
        "consume_reserved_handle",
        fault_committed_consume,
    )
    with pytest.raises(CleanupAbort, match="consume backing fault"):
        with registry.prepared_publication_group(tokens) as publication:
            publication.commit_no_fail()

    assert all(
        registry.resolve_version(record.artifact.artifact_version_id) is None for record in records
    )
    assert registry.census(estimate_bytes=True) == baseline
    assert registry.index_metrics(estimate_bytes=True) == baseline_metrics
    _assert_empty_preparation_census(registry)


@pytest.mark.parametrize("failure_phase", ("plan", "install"))
def test_group_claim_primary_survives_release_cleanup_fault_without_residue(
    monkeypatch: pytest.MonkeyPatch,
    failure_phase: str,
) -> None:
    class PrimaryAbort(BaseException):
        pass

    class CleanupAbort(BaseException):
        pass

    primary = PrimaryAbort(f"injected group {failure_phase} failure")
    cleanup = CleanupAbort("injected group claim release cleanup")
    records = (_record("alpha"), _record("bravo"), _record("charl"))
    registry = LocalArtifactVersionRegistry(capacity=3, shard_count=1)
    baseline = registry.census(estimate_bytes=True)
    baseline_metrics = registry.index_metrics(estimate_bytes=True)
    tokens = tuple(registry.prepare_publish_version(record, _START) for record in records)

    if failure_phase == "plan":
        original_prepare = LocalArtifactVersionRegistry._prepare_claimed_commit_locked
        prepare_calls = 0

        def fail_second_plan(
            owner: LocalArtifactVersionRegistry,
            reservation: object,
            shard: object,
        ) -> object:
            nonlocal prepare_calls
            prepare_calls += 1
            if prepare_calls == 2:
                raise primary
            return original_prepare(owner, reservation, shard)  # type: ignore[arg-type]

        monkeypatch.setattr(
            LocalArtifactVersionRegistry,
            "_prepare_claimed_commit_locked",
            fail_second_plan,
        )
    else:

        class RejectingLocator(dict[int, tuple[int, ...]]):
            def __setitem__(self, key: int, value: tuple[int, ...]) -> None:
                raise primary

        registry._prepared_commit_locators = RejectingLocator()  # type: ignore[attr-defined]

    original_release = deployment_registry_module._PackedArtifactStore.release_reserved_handle
    cleanup_injected = False

    def fail_first_cleanup_release(store: object, handle: int) -> None:
        nonlocal cleanup_injected
        if not cleanup_injected:
            cleanup_injected = True
            raise cleanup
        original_release(store, handle)  # type: ignore[arg-type]

    monkeypatch.setattr(
        deployment_registry_module._PackedArtifactStore,
        "release_reserved_handle",
        fail_first_cleanup_release,
    )
    with pytest.raises(PrimaryAbort) as exc_info:
        with registry.prepared_publication_group(tokens):
            pass

    assert exc_info.value is primary
    assert any("group claim release cleanup" in note for note in primary.__notes__)
    assert registry.census(estimate_bytes=True) == baseline
    assert registry.index_metrics(estimate_bytes=True) == baseline_metrics
    _assert_empty_preparation_census(registry)


@pytest.mark.parametrize("failure_phase", ("plan", "install"))
def test_single_claim_primary_survives_release_cleanup_fault_without_residue(
    monkeypatch: pytest.MonkeyPatch,
    failure_phase: str,
) -> None:
    class PrimaryAbort(BaseException):
        pass

    class CleanupAbort(BaseException):
        pass

    primary = PrimaryAbort(f"injected single {failure_phase} failure")
    cleanup = CleanupAbort("injected single claim release cleanup")
    registry = LocalArtifactVersionRegistry(capacity=1)
    baseline = registry.census(estimate_bytes=True)
    baseline_metrics = registry.index_metrics(estimate_bytes=True)
    token = registry.prepare_publish_version(_record("alpha"), _START)

    if failure_phase == "plan":

        def fail_plan(
            _owner: LocalArtifactVersionRegistry,
            _reservation: object,
            _shard: object,
        ) -> object:
            raise primary

        monkeypatch.setattr(
            LocalArtifactVersionRegistry,
            "_prepare_claimed_commit_locked",
            fail_plan,
        )
    else:

        class RejectingLocator(dict[int, tuple[int, ...]]):
            def __setitem__(self, key: int, value: tuple[int, ...]) -> None:
                raise primary

        registry._prepared_commit_locators = RejectingLocator()  # type: ignore[attr-defined]

    original_release = deployment_registry_module._PackedArtifactStore.release_reserved_handle
    cleanup_injected = False

    def fail_cleanup_release(store: object, handle: int) -> None:
        nonlocal cleanup_injected
        if not cleanup_injected:
            cleanup_injected = True
            raise cleanup
        original_release(store, handle)  # type: ignore[arg-type]

    monkeypatch.setattr(
        deployment_registry_module._PackedArtifactStore,
        "release_reserved_handle",
        fail_cleanup_release,
    )
    with pytest.raises(PrimaryAbort) as exc_info:
        with registry.prepared_publication(token):
            pass

    assert exc_info.value is primary
    assert any("single claim release cleanup" in note for note in primary.__notes__)
    assert registry.census(estimate_bytes=True) == baseline
    assert registry.index_metrics(estimate_bytes=True) == baseline_metrics
    _assert_empty_preparation_census(registry)
