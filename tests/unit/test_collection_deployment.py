# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Tests for immutable collection/source-deployment foundations."""

from __future__ import annotations

from dataclasses import FrozenInstanceError
from datetime import UTC, datetime, timedelta

import pytest

from evidenceforge.events.collection_policy import (
    CollectionBatchingPolicy,
    CollectionCapability,
    CollectionWindow,
    ProjectionAdmission,
    SourceCollectionOverride,
    SourceCollectionPolicy,
    SourceInstanceIdentity,
    normalize_source_collection_policy,
)
from evidenceforge.generation.collection_deployment import (
    CompiledCollectionDeployment,
    SourceInstanceDeployment,
)

_START = datetime(2026, 8, 16, 12, tzinfo=UTC)


def _source(
    instance: str = "sensor-a",
    *,
    host: str = "edge-01",
    family: str = "zeek",
    capabilities: CollectionCapability = (CollectionCapability.NETWORK | CollectionCapability.DNS),
    windows: tuple[CollectionWindow, ...] = (CollectionWindow(),),
    enabled: bool = True,
) -> SourceInstanceDeployment:
    return SourceInstanceDeployment(
        identity=SourceInstanceIdentity(
            source_instance=instance,
            hostname=host,
            family=family,
        ),
        formats=("zeek_conn", "zeek_dns"),
        policy=SourceCollectionPolicy(
            enabled=enabled,
            capabilities=capabilities,
            windows=windows,
        ),
    )


def test_source_identity_and_formats_are_canonicalized_once() -> None:
    source = SourceInstanceDeployment(
        identity=SourceInstanceIdentity(
            source_instance=" Sensor-A ",
            hostname=" EDGE-01 ",
            family=" Zeek ",
        ),
        formats=(" ZEEK_DNS ", "zeek_conn", "zeek_dns"),
        policy=SourceCollectionPolicy(),
    )

    assert source.identity.canonical_key == ("edge-01", "zeek", "sensor-a")
    assert source.formats == ("zeek_conn", "zeek_dns")


def test_optional_field_names_preserve_source_native_case() -> None:
    policy = SourceCollectionPolicy(
        optional_fields=frozenset({" CommandLine ", "CommandLine", "Hashes"}),
    )

    assert policy.optional_fields == frozenset({"CommandLine", "Hashes"})


def test_policy_precedence_is_defaults_profile_project_pack_scenario() -> None:
    defaults = SourceCollectionPolicy(
        capabilities=CollectionCapability.NETWORK,
        missingness=0.01,
        format_missingness={"zeek_conn": 0.02},
    )
    policy = normalize_source_collection_policy(
        defaults=defaults,
        profile=SourceCollectionOverride(
            missingness=0.1,
            optional_fields=frozenset({"community_id"}),
        ),
        project_pack=SourceCollectionOverride(
            capabilities=CollectionCapability.NETWORK | CollectionCapability.DNS,
            missingness=0.2,
        ),
        scenario=SourceCollectionOverride(
            missingness=0.3,
            batching=CollectionBatchingPolicy(enabled=True, interval_us=250_000),
        ),
    )

    assert policy.missingness == 0.3
    assert policy.missingness_for("zeek_conn") == 0.02
    assert policy.optional_fields == frozenset({"community_id"})
    assert policy.capabilities.covers(
        CollectionCapability.NETWORK
        | CollectionCapability.DNS
        | CollectionCapability.OPTIONAL_FIELDS
        | CollectionCapability.BATCHING
    )


def test_higher_precedence_layer_can_remove_structural_capabilities() -> None:
    base = SourceCollectionPolicy(
        capabilities=CollectionCapability.PROCESS,
        optional_fields=frozenset({"CommandLine"}),
        windows=(CollectionWindow(_START, _START + timedelta(hours=1)),),
        batching=CollectionBatchingPolicy(enabled=True, interval_us=250_000),
    )

    policy = SourceCollectionOverride(
        optional_fields=frozenset(),
        windows=(CollectionWindow(),),
        batching=CollectionBatchingPolicy(),
    ).apply(base)

    assert policy.optional_fields == frozenset()
    assert policy.windows == (CollectionWindow(),)
    assert policy.batching.enabled is False
    assert policy.capabilities == CollectionCapability.PROCESS


def test_from_layers_builds_one_normalized_immutable_deployment() -> None:
    source = SourceInstanceDeployment.from_layers(
        identity=SourceInstanceIdentity("ecar-a", "host-a", "ecar"),
        formats=("ecar",),
        defaults=SourceCollectionPolicy(capabilities=CollectionCapability.PROCESS),
        profile=SourceCollectionOverride(missingness=0.05),
        scenario=SourceCollectionOverride(missingness=0.0),
    )

    assert source.policy.missingness == 0.0
    with pytest.raises(FrozenInstanceError):
        source.policy.enabled = False  # type: ignore[misc]


def test_collection_windows_are_sorted_non_overlapping_and_half_open() -> None:
    early = CollectionWindow(_START, _START + timedelta(minutes=10))
    late = CollectionWindow(_START + timedelta(minutes=20), _START + timedelta(minutes=30))
    deployment = CompiledCollectionDeployment([_source(windows=(late, early))])

    assert deployment.collection_window_at("sensor-a", _START + timedelta(minutes=5)) is early
    assert deployment.collection_window_at("sensor-a", _START + timedelta(minutes=10)) is None
    assert deployment.collection_window_at("sensor-a", _START + timedelta(minutes=20)) is late
    assert deployment.collection_window_at("sensor-a", _START + timedelta(minutes=30)) is None

    with pytest.raises(ValueError, match="must not overlap"):
        SourceCollectionPolicy(
            windows=(
                CollectionWindow(_START, _START + timedelta(minutes=15)),
                CollectionWindow(_START + timedelta(minutes=10), None),
            )
        )


def test_collection_window_rejects_naive_or_empty_bounds() -> None:
    with pytest.raises(ValueError, match="timezone-aware"):
        CollectionWindow(datetime(2026, 1, 1), None)
    with pytest.raises(ValueError, match="earlier than end"):
        CollectionWindow(_START, _START)


def test_exact_indexes_and_host_family_iteration_return_compiled_objects() -> None:
    first = _source("sensor-a")
    second = _source("sensor-b")
    third = _source("ecar-a", host="workstation-01", family="ecar")
    deployment = CompiledCollectionDeployment([first, second, third])

    assert deployment.source_by_instance(" SENSOR-A ") == first
    assert deployment.source_for("EDGE-01", "ZEEK", "SENSOR-B") == second
    assert tuple(deployment.iter_host_family("edge-01", "zeek")) == (first, second)
    assert deployment.count_host_family("edge-01", "zeek") == 2
    assert deployment.source_by_instance("missing") is None


def test_format_index_preserves_compiled_order_without_materializing_all_sources() -> None:
    first = _source("sensor-a")
    second = SourceInstanceDeployment(
        identity=SourceInstanceIdentity("sensor-b", "edge-02", "zeek"),
        formats=("zeek_http",),
        policy=SourceCollectionPolicy(capabilities=CollectionCapability.HTTP),
    )
    third = _source("sensor-c")
    deployment = CompiledCollectionDeployment([first, second, third])

    assert tuple(deployment.iter_format(" ZEEK_CONN ")) == (first, third)
    assert deployment.count_format("zeek_conn") == 2
    assert deployment.count_format("zeek_http") == 1
    assert deployment.count_format("missing") == 0


def test_duplicate_exact_keys_and_instance_ids_fail_during_compile() -> None:
    with pytest.raises(ValueError, match="canonical key"):
        CompiledCollectionDeployment([_source(), _source()])

    with pytest.raises(ValueError, match="globally unique"):
        CompiledCollectionDeployment(
            [
                _source("shared", host="edge-01"),
                _source("shared", host="edge-02"),
            ]
        )


def test_capability_intersection_uses_fixed_bit_flags() -> None:
    available = (
        CollectionCapability.NETWORK
        | CollectionCapability.SOURCE_ENDPOINT
        | CollectionCapability.COHERENT_ACTOR
    )
    deployment = CompiledCollectionDeployment([_source(capabilities=available)])
    requested = CollectionCapability.NETWORK | CollectionCapability.DESTINATION_ENDPOINT

    assert deployment.capability_intersection("sensor-a", requested) == (
        CollectionCapability.NETWORK
    )
    assert deployment.capability_intersection("missing", requested) is CollectionCapability.NONE


@pytest.mark.parametrize(
    ("source", "timestamp", "requested", "expected"),
    [
        (
            _source(),
            _START,
            CollectionCapability.NETWORK,
            ProjectionAdmission.READY,
        ),
        (
            _source(enabled=False),
            _START,
            CollectionCapability.NETWORK,
            ProjectionAdmission.SOURCE_DISABLED,
        ),
        (
            _source(windows=(CollectionWindow(_START + timedelta(hours=1), None),)),
            _START,
            CollectionCapability.NETWORK,
            ProjectionAdmission.OUTSIDE_COLLECTION_WINDOW,
        ),
        (
            _source(),
            _START,
            CollectionCapability.HTTP,
            ProjectionAdmission.MISSING_CAPABILITY,
        ),
    ],
)
def test_projection_envelope_reports_deployment_admission(
    source: SourceInstanceDeployment,
    timestamp: datetime,
    requested: CollectionCapability,
    expected: ProjectionAdmission,
) -> None:
    deployment = CompiledCollectionDeployment([source])

    envelope = deployment.projection_envelope(
        occurrence_id="occ-1",
        target_id="source-row",
        source_instance=source.identity.source_instance,
        canonical_time=timestamp,
        requested_capabilities=requested,
    )

    assert envelope.admission is expected
    assert envelope.admitted is (expected is ProjectionAdmission.READY)
    assert envelope.source == source.identity
    assert envelope.canonical_time == timestamp


def test_ordinal_projection_admission_matches_exact_instance_path() -> None:
    source = _source()
    deployment = CompiledCollectionDeployment([source])

    exact = deployment.projection_envelope(
        occurrence_id="occ-1",
        target_id="source-row",
        source_instance="sensor-a",
        canonical_time=_START,
        requested_capabilities=CollectionCapability.NETWORK,
    )
    ordinal = deployment.projection_envelope_by_ordinal(
        occurrence_id="occ-1",
        target_id="source-row",
        source_ordinal=0,
        canonical_time=_START,
        requested_capabilities=CollectionCapability.NETWORK,
    )

    assert ordinal == exact
    with pytest.raises(KeyError):
        deployment.projection_envelope_by_ordinal(
            occurrence_id="occ-1",
            target_id="source-row",
            source_ordinal=1,
            canonical_time=_START,
            requested_capabilities=CollectionCapability.NETWORK,
        )


def test_finalized_envelope_preserves_canonical_time_and_source_reference() -> None:
    source = _source()
    deployment = CompiledCollectionDeployment([source])
    envelope = deployment.projection_envelope(
        occurrence_id="occ-1",
        target_id="conn-row",
        source_instance="sensor-a",
        canonical_time=_START,
        requested_capabilities=CollectionCapability.NETWORK,
    )
    observed = _START + timedelta(milliseconds=17)

    finalized = envelope.with_observed_time(observed)

    assert finalized.canonical_time == _START
    assert finalized.observed_time == observed
    assert finalized.source == source.identity


def test_census_is_precomputed_and_reports_retained_shape() -> None:
    sources = [_source(f"sensor-{index}", host=f"edge-{index // 4}") for index in range(12)]
    deployment = CompiledCollectionDeployment(sources)

    assert deployment.census.source_instances == 12
    assert deployment.census.collection_windows == 12
    assert deployment.census.exact_identity_keys == 12
    assert deployment.census.host_family_buckets == 3
    assert deployment.census.max_host_family_bucket == 4
    assert deployment.census.capability_words == 12
    assert deployment.census.unique_hostnames == 3
    assert deployment.census.unique_families == 1
    assert deployment.census.unique_format_sets == 1
    assert deployment.census.unique_policies == 1
    assert deployment.census.estimated_bytes > 0
    assert 0 < deployment.census.estimated_index_bytes <= deployment.census.estimated_bytes
    assert deployment.census is deployment.census


def test_content_digest_is_deterministic_and_covers_ordered_public_values() -> None:
    first = _source("sensor-a")
    second = _source("sensor-b", host="edge-02")

    compiled = CompiledCollectionDeployment([first, second])
    equivalent = CompiledCollectionDeployment(
        [
            _source("sensor-a"),
            _source("sensor-b", host="edge-02"),
        ]
    )
    reversed_sources = CompiledCollectionDeployment([second, first])
    changed_policy = CompiledCollectionDeployment(
        [
            first,
            _source(
                "sensor-b",
                host="edge-02",
                capabilities=CollectionCapability.NETWORK,
            ),
        ]
    )

    assert len(compiled.content_digest) == 64
    assert compiled.content_digest == equivalent.content_digest
    assert compiled.content_digest != reversed_sources.content_digest
    assert compiled.content_digest != changed_policy.content_digest


def test_large_deployment_keeps_dense_ordinals_and_exact_lookup() -> None:
    count = 10_000
    deployment = CompiledCollectionDeployment(
        _source(
            f"sensor-{index}",
            host=f"edge-{index % 100}",
        )
        for index in range(count)
    )

    assert len(deployment) == count
    assert deployment.source_by_ordinal(count - 1).identity.source_instance == "sensor-9999"
    assert deployment.source_by_instance("sensor-9999") == deployment.source_by_ordinal(count - 1)
    assert deployment.count_host_family("edge-99", "zeek") == 100
    assert deployment.count_format("zeek_conn") == count
    assert deployment.projection_envelope_by_ordinal(
        occurrence_id="occ-last",
        target_id="conn-row",
        source_ordinal=count - 1,
        canonical_time=_START,
        requested_capabilities=CollectionCapability.NETWORK,
    ).admitted
    assert deployment.census.source_instances == count
    assert deployment.census.unique_hostnames == 100
    assert deployment.census.unique_families == 1
    assert deployment.census.unique_format_sets == 1
    assert deployment.census.unique_policies == 1
    assert deployment.census.exact_index_capacity == count
    assert deployment.census.host_index_capacity < count
    assert deployment.census.host_family_index_capacity < count
    assert deployment.census.estimated_bytes / count <= 256
    assert deployment.census.estimated_index_bytes / count <= 256
    assert (
        max(deployment.exact_lookup_candidates(f"sensor-{index}") for index in range(0, count, 101))
        == 1
    )
    host_candidates = sorted(
        deployment.host_family_lookup_candidates(f"edge-{index}", "zeek") for index in range(100)
    )
    assert host_candidates[94] <= 24
