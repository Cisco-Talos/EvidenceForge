# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Scale and policy tests for process-adjacent bounded runtime caches."""

from __future__ import annotations

import inspect
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

from evidenceforge.generation.process_runtime_cache import (
    ACTIVITY_GENERATOR_MUTABLE_RETENTION_POLICIES,
    PRODUCTION_PROCESS_RUNTIME_CACHE_FAMILIES,
    REMOVED_DEAD_ACTIVITY_GENERATOR_MUTABLE_FIELDS,
    ActivityGeneratorRetentionDisposition,
    BoundedRuntimeCache,
    EmailArtifactManifestSpool,
    build_production_process_runtime_caches,
    discover_activity_generator_mutable_fields,
)

_START = datetime(2024, 1, 1, tzinfo=UTC)


def test_bounded_cache_backlog_is_observationally_eager() -> None:
    cache: BoundedRuntimeCache[int, datetime] = BoundedRuntimeCache(
        default_deadline=lambda value: value
    )
    for key in range(5_000):
        cache[key] = _START

    cache.advance_watermark(_START + timedelta(seconds=1), limit=4_096)

    assert len(cache) == 904
    assert cache.get(4_999) is None
    assert cache.metrics().backing_entries <= 904 * 2

    cache.advance_watermark(_START + timedelta(seconds=1), limit=4_096)
    assert len(cache) == 0
    assert cache.metrics().backing_entries == 0


def _duration_cache_census(hours: int) -> tuple[int, int]:
    cache: BoundedRuntimeCache[tuple[int, int], datetime] = BoundedRuntimeCache(
        default_deadline=lambda value: value
    )
    for hour in range(hours):
        at = _START + timedelta(hours=hour)
        for ordinal in range(40):
            cache[(hour, ordinal)] = at
        cache.advance_watermark(at - timedelta(hours=24), limit=4_096)
    metrics = cache.metrics()
    return metrics.live_entries, metrics.backing_entries


def test_duration_cache_plateaus_from_seven_to_thirty_days() -> None:
    seven_day = _duration_cache_census(24 * 7)
    thirty_day = _duration_cache_census(24 * 30)

    assert abs(thirty_day[0] - seven_day[0]) <= seven_day[0] * 0.10
    assert thirty_day[1] <= thirty_day[0] * 2


def test_sparse_and_skewed_exact_lookups_inspect_one_candidate() -> None:
    cache: BoundedRuntimeCache[tuple[str, int], int] = BoundedRuntimeCache(
        default_deadline=lambda _value: _START + timedelta(days=30)
    )
    for ordinal in range(20_000):
        owner = "skewed-owner" if ordinal < 19_000 else f"owner-{ordinal}"
        cache[(owner, ordinal)] = ordinal

    before = cache.lookup_candidates_inspected
    for ordinal in range(1_000):
        assert cache.get(("skewed-owner", ordinal)) == ordinal
    for ordinal in range(1_000):
        assert cache.get(("missing", ordinal)) is None

    assert cache.lookup_candidates_inspected - before == 1_000


def test_production_cache_bundle_exposes_complete_constant_time_census() -> None:
    bundle = build_production_process_runtime_caches(_START + timedelta(days=30))
    family_names = tuple(spec.name for spec in PRODUCTION_PROCESS_RUNTIME_CACHE_FAMILIES)

    first_keys: dict[str, object] = {}
    for ordinal, family in enumerate(family_names):
        loaded = bundle.load_probe_entry(
            family,
            ordinal,
            _START + timedelta(hours=1),
            owner=f"owner-{ordinal}",
        )
        assert loaded.inserted and not loaded.replaced
        first_keys[family] = loaded.key

    replacement = bundle.load_probe_entry(
        family_names[0],
        0,
        _START + timedelta(hours=1),
        owner="owner-0",
    )
    assert replacement.key == first_keys[family_names[0]]
    assert not replacement.inserted and replacement.replaced

    census = bundle.census(watermark=None, estimate_bytes=True)
    assert census.cache_count == 17
    assert census.live_entries == 17
    assert census.reverse_bindings == 3
    assert census.reverse_subjects == 3
    assert census.physical_records == 20
    assert census.reverse_backing_entries >= census.reverse_bindings
    assert census.reverse_estimated_index_bytes > 0
    assert census.reverse_estimated_bytes > census.reverse_estimated_index_bytes
    assert census.estimated_bytes > census.estimated_index_bytes
    assert tuple(family.name for family in census.families) == family_names
    assert all(family.live_entries == 1 for family in census.families)
    assert all(family.estimated_bytes > 0 for family in census.families)


def _production_duration_census(hours: int) -> tuple[int, int, int]:
    bundle = build_production_process_runtime_caches(_START + timedelta(days=31))
    families = tuple(spec.name for spec in PRODUCTION_PROCESS_RUNTIME_CACHE_FAMILIES)
    ordinal = 0
    for hour in range(hours):
        at = _START + timedelta(hours=hour)
        for family in families:
            bundle.load_probe_entry(
                family,
                ordinal,
                at,
                owner=f"owner-{ordinal}",
            )
            ordinal += 1
        bundle.advance_watermark_page(
            at - timedelta(hours=24),
            limit=4_096,
        )
    census = bundle.census(watermark=_START + timedelta(hours=hours - 25))
    return census.physical_records, census.backing_entries, census.reverse_bindings


def test_production_cache_bundle_plateaus_from_seven_to_thirty_days() -> None:
    seven_day = _production_duration_census(24 * 7)
    thirty_day = _production_duration_census(24 * 30)

    assert abs(thirty_day[0] - seven_day[0]) <= seven_day[0] * 0.10
    assert thirty_day[1] <= thirty_day[0] * 2
    assert thirty_day[2] <= seven_day[2] * 1.10


def test_whole_class_inventory_catches_lazy_alias_dict_and_setattr_initialization() -> None:
    source = """
class ActivityGenerator:
    def __init__(self):
        self.base: dict[str, int] = {}

    def lazy_alias(self):
        cache: dict[str, int] | None = None
        if cache is None:
            cache = {}
            self.lazy = cache

    def dynamic(self):
        self.__dict__["dict_cache"] = {}
        setattr(self, "set_cache", set())
"""

    discoveries = discover_activity_generator_mutable_fields(source)

    assert {row.field_name for row in discoveries} == {
        "base",
        "dict_cache",
        "lazy",
        "set_cache",
    }
    assert {row.field_name for row in discoveries if row.lazy} == {
        "dict_cache",
        "lazy",
        "set_cache",
    }


def test_failed_logon_cadence_fields_have_closed_retention_policies() -> None:
    """The auth-local cache and transient reservation cannot remain migration debt."""

    from evidenceforge.generation.activity.generator import ActivityGenerator

    discovered = {
        row.field_name
        for row in discover_activity_generator_mutable_fields(inspect.getsource(ActivityGenerator))
    }
    policies = {
        policy.field_name: policy for policy in ACTIVITY_GENERATOR_MUTABLE_RETENTION_POLICIES
    }

    assert {"_failed_logon_attempt_times", "_failed_logon_attempt_pending"} <= discovered
    assert policies["_failed_logon_attempt_times"].disposition is (
        ActivityGeneratorRetentionDisposition.BOUNDED
    )
    assert policies["_failed_logon_attempt_pending"].disposition is (
        ActivityGeneratorRetentionDisposition.TRANSIENT
    )


def test_dead_dns_caches_cannot_reenter_generator_retention() -> None:
    """Retired generator DNS caches cannot re-enter the mutable retention inventory."""

    from evidenceforge.generation.activity.generator import ActivityGenerator

    discoveries = discover_activity_generator_mutable_fields(inspect.getsource(ActivityGenerator))
    discovered_fields = {row.field_name for row in discoveries}
    retired_fields = {
        "_dns_observation_cache",
        "_dns_resolver_rrset_cache",
    }

    assert retired_fields.isdisjoint(discovered_fields)
    assert not hasattr(ActivityGenerator, "_dns_observation_cache_hit_or_store")
    policy_fields = {policy.field_name for policy in ACTIVITY_GENERATOR_MUTABLE_RETENTION_POLICIES}
    assert retired_fields.isdisjoint(policy_fields)
    assert retired_fields <= set(REMOVED_DEAD_ACTIVITY_GENERATOR_MUTABLE_FIELDS)


def test_email_manifest_spool_preserves_former_pretty_json_bytes(tmp_path: Path) -> None:
    manifest_path = tmp_path / "ARTIFACTS_MANIFEST.json"
    spool = EmailArtifactManifestSpool(manifest_path)
    rows = [
        {
            "message_id": "<later@example.test>",
            "sender": "z@example.test",
            "to": ("b@example.test",),
            "date": "2024-01-02T00:00:00+00:00",
        },
        {
            "message_id": "<earlier@example.test>",
            "sender": "a@example.test",
            "to": ("a@example.test",),
            "date": "2024-01-01T00:00:00+00:00",
        },
    ]
    for row in rows:
        spool.append(row)

    census = spool.census()
    assert census.logical_rows == census.backing_rows == 2
    assert census.retained_rows == 0
    assert census.database_bytes > 0
    assert census.maximum_append_work == 1
    assert spool.write_manifest(schema_version="1.0") == 2

    expected = (
        json.dumps(
            {
                "schema_version": "1.0",
                "email": {
                    "messages": sorted(
                        rows,
                        key=lambda row: (row["date"], row["message_id"], row["sender"]),
                    )
                },
            },
            indent=2,
            sort_keys=True,
        )
        + "\n"
    )
    assert manifest_path.read_text(encoding="utf-8") == expected
    assert not (tmp_path / ".ARTIFACTS_MANIFEST.json.spool.sqlite3").exists()
