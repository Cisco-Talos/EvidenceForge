#!/usr/bin/env python3
# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Measure process-runtime cache lookup, expiry, memory, and duration plateau."""

from __future__ import annotations

import argparse
import hashlib
import json
import random
import statistics
import tempfile
import time
from dataclasses import asdict
from datetime import UTC, datetime, timedelta
from pathlib import Path

import psutil

from evidenceforge.generation.activity.generator import ActivityGenerator
from evidenceforge.generation.process_runtime_cache import (
    ACTIVITY_GENERATOR_MUTABLE_RETENTION_POLICIES,
    PRODUCTION_PROCESS_RUNTIME_CACHE_FAMILIES,
    REMOVED_DEAD_ACTIVITY_GENERATOR_MUTABLE_FIELDS,
    REMOVED_DURATION_SIZED_ACTIVITY_GENERATOR_FIELDS,
    ActivityGeneratorRetentionDisposition,
    EmailArtifactManifestSpool,
    build_production_process_runtime_caches,
    snapshot_activity_generator_mutable_fields,
)
from evidenceforge.generation.state_manager import StateManager
from evidenceforge.models.scenario import System, User

_START = datetime(2024, 1, 1, tzinfo=UTC)


def _p95(samples: list[float]) -> float:
    return statistics.quantiles(samples, n=100, method="inclusive")[94]


def _lookup_profile(records: int, queries: int, *, skewed: bool) -> dict[str, float | int | str]:
    bundle = build_production_process_runtime_caches(_START + timedelta(days=30))
    families = tuple(spec.name for spec in PRODUCTION_PROCESS_RUNTIME_CACHE_FAMILIES)
    query_ordinals = tuple((query * 104_729) % records for query in range(queries))
    wanted = set(query_ordinals)
    query_keys: dict[int, tuple[str, object]] = {}
    rss_before = psutil.Process().memory_info().rss
    loaded_at = time.perf_counter()
    for ordinal in range(records):
        family = families[ordinal % len(families)]
        family_ordinal = ordinal // len(families)
        owner = "one-owner" if skewed else f"owner-{family_ordinal % 100_000}"
        loaded = bundle.load_probe_entry(family, family_ordinal, _START, owner=owner)
        if ordinal in wanted:
            query_keys[ordinal] = (family, loaded.key)
    load_seconds = time.perf_counter() - loaded_at
    rss_bytes = max(0, psutil.Process().memory_info().rss - rss_before)

    samples: list[float] = []
    digest = hashlib.sha256()
    before_candidates = bundle.census(watermark=None).lookup_candidates_inspected
    for ordinal in query_ordinals:
        family, key = query_keys[ordinal]
        started = time.perf_counter_ns()
        value = bundle.cache(family).get(key)
        samples.append((time.perf_counter_ns() - started) / 1_000.0)
        digest.update(f"{ordinal}:{value}\n".encode())
    census = bundle.census(watermark=None, estimate_bytes=True)
    return {
        "requested_records": records,
        "physical_records": census.physical_records,
        "queries": queries,
        "shape": "single_owner" if skewed else "uniform",
        "load_seconds": load_seconds,
        "lookup_p95_us": _p95(samples),
        "lookup_candidates": census.lookup_candidates_inspected - before_candidates,
        "rss_bytes": rss_bytes,
        "estimated_bytes": census.estimated_bytes,
        "estimated_index_bytes": census.estimated_index_bytes,
        "backing_entries": census.backing_entries + census.reverse_backing_entries,
        "reverse_bindings": census.reverse_bindings,
        "digest": digest.hexdigest(),
    }


def _duration_profile(hours: int, rate: int) -> dict[str, int]:
    bundle = build_production_process_runtime_caches(_START + timedelta(days=31))
    families = tuple(spec.name for spec in PRODUCTION_PROCESS_RUNTIME_CACHE_FAMILIES)
    ordinal = 0
    for hour in range(hours):
        at = _START + timedelta(hours=hour)
        for _ in range(rate):
            family = families[ordinal % len(families)]
            bundle.load_probe_entry(family, ordinal, at, owner=f"owner-{ordinal}")
            ordinal += 1
        bundle.advance_watermark_page(at - timedelta(hours=24), limit=4_096)
    census = bundle.census(watermark=_START + timedelta(hours=hours - 25))
    return {
        "hours": hours,
        "live_entries": census.live_entries,
        "physical_records": census.physical_records,
        "backing_entries": census.backing_entries + census.reverse_backing_entries,
        "high_water_entries": census.high_water_entries + census.reverse_high_water,
    }


def _activity_generator_duration_profile(
    hours: int,
    rate: int,
) -> dict[str, object]:
    """Drive retained families with real owners and production key shapes."""

    generator = ActivityGenerator(
        StateManager(),
        {},
        generation_window_start=_START,
        generation_window_end=_START + timedelta(hours=hours + 48),
    )
    user = User(
        username="analyst",
        full_name="Retention Analyst",
        email="analyst@example.test",
    )
    system = System(
        hostname="LNX-RETENTION-01",
        ip="10.0.0.10",
        os="Ubuntu 24.04",
        type="workstation",
    )
    generator._ad_srv_discovery_cache = set()

    occurrence = 0
    maximum_session_retained_rows = 0
    maximum_queue_rows = 0
    maximum_late_hour_bash_expiry_work = 0
    maximum_late_hour_browser_expiry_work = 0
    maximum_late_hour_privileged_auth_expiry_work = 0
    released_session_rows = 0
    browser_reuse_rejections = 0
    privileged_auth_reuse_rejections = 0
    with tempfile.TemporaryDirectory(prefix="eforge-manifest-spool-") as temp_dir:
        spool = EmailArtifactManifestSpool(Path(temp_dir) / "ARTIFACTS_MANIFEST.json")
        generator._email_artifact_manifest_spool = spool
        for hour in range(hours):
            hour_start = _START + timedelta(hours=hour)
            hour_bucket = int((hour_start + timedelta(seconds=5)).timestamp() // 3_600)
            generator._ad_srv_discovery_cache.add((system.ip, "example.test", hour_bucket))
            for in_hour in range(rate):
                at = hour_start + timedelta(seconds=in_hour * max(1, 3_600 // rate))
                logon_id = f"0x{occurrence + 1:x}"
                source_port = 10_000 + (occurrence % 50_000)
                source_ip = f"10.{(occurrence // 50_000) % 250}.0.10"

                privileged_auth_id = f"auth-{occurrence}"
                if not generator._claim_privileged_auth_occurrence(
                    privileged_auth_id,
                    time=at,
                ):
                    raise AssertionError("fresh privileged-auth occurrence was not claimable")
                if generator._claim_privileged_auth_occurrence(
                    privileged_auth_id,
                    time=at,
                ):
                    raise AssertionError("privileged-auth replay escaped the semantic horizon")
                privileged_auth_reuse_rejections += 1

                # Independently owned open network debt remains visible rather
                # than being credited to this lifecycle/SMTP/browser closure slice.
                generator._remember_kerberos_audit(
                    source_ip,
                    "DC-01",
                    at,
                    source_port=source_port,
                )
                generator.reserve_ssh_source_port(
                    source_ip,
                    "10.0.0.20",
                    source_port,
                    random.Random(occurrence),
                    "linux",
                    time=at,
                )

                bash_key = (system.hostname, user.username, logon_id)
                generator._bash_history_next_time[bash_key] = at + timedelta(seconds=1)
                generator._bash_history_command_counts[bash_key] = 1
                generator._bash_history_quick_streaks[bash_key] = 0
                generator._reserve_bash_history_second(
                    user,
                    system,
                    at,
                    f"printf '%s' {occurrence}",
                )
                generator._linux_local_logon_syslog_sessions.add(logon_id)
                generator._last_workstation_lock_time[
                    (system.hostname, user.username, logon_id)
                ] = at

                requested_tty = f"pts/{occurrence}"
                requested_tty_key = (system.hostname, user.username, requested_tty)
                tty_key = requested_tty_key
                generator._linux_sudo_tty_assignments[requested_tty_key] = requested_tty
                generator._linux_sudo_tty_owners[(system.hostname, requested_tty)] = (
                    requested_tty_key
                )
                generator._linux_sudo_tty_available[tty_key] = at + timedelta(seconds=1)
                generator._remember_linux_sudo_tty_session(tty_key, logon_id)

                browser_uri = f"/duration/{occurrence}"
                if not generator._claim_top_level_browser_launch_target(
                    system=system,
                    username=user.username,
                    logon_id="fixed-browser-session",
                    time=at,
                    image="browser.exe",
                    hostname="example.test",
                    uri=browser_uri,
                ):
                    raise AssertionError("fresh browser URI was not claimable")
                if generator._claim_top_level_browser_launch_target(
                    system=system,
                    username=user.username,
                    logon_id="fixed-browser-session",
                    time=at,
                    image="browser.exe",
                    hostname="example.test",
                    uri=browser_uri,
                ):
                    raise AssertionError("browser URI reuse escaped the semantic horizon")
                browser_reuse_rejections += 1

                queue_state = generator._postfix_queue_state(system, f"QUEUE-{occurrence}")
                maximum_queue_rows = max(
                    maximum_queue_rows,
                    len(generator._postfix_queue_states),
                )
                if not generator._release_postfix_queue_state(
                    system,
                    f"QUEUE-{occurrence}",
                    queue_state,
                ):
                    raise AssertionError("terminal Postfix queue did not release")

                spool.append(
                    {
                        "message_id": f"<{occurrence}@example.test>",
                        "sender": "analyst@example.test",
                        "to": ("recipient@example.test",),
                        "date": at.isoformat(),
                    }
                )

                session_retained_rows = sum(
                    len(value)
                    for value in (
                        generator._bash_history_next_time,
                        generator._bash_history_command_counts,
                        generator._bash_history_quick_streaks,
                        generator._linux_local_logon_syslog_sessions,
                        generator._linux_sudo_tty_assignments,
                        generator._linux_sudo_tty_owners,
                        generator._linux_sudo_tty_sessions,
                        generator._linux_sudo_tty_available,
                        generator._linux_sudo_tty_keys_by_logon_id,
                        generator._last_workstation_lock_time,
                    )
                )
                maximum_session_retained_rows = max(
                    maximum_session_retained_rows,
                    session_retained_rows,
                )
                released_session_rows += generator._release_session_retention_state(
                    hostname=system.hostname,
                    username=user.username,
                    logon_id=logon_id,
                ).total_rows

                # Stable-key controls exercise actual bounded helper paths at
                # the same event cadence without increasing their key universe.
                generator._record_user_process(system, user, occurrence + 1, "/usr/bin/true")
                generator._normalize_failed_logon_attempt_time(
                    hostname=system.hostname,
                    username=user.username,
                    logon_type=2,
                    source_ip="10.0.0.99",
                    requested_time=at,
                )
                generator._reserve_kerberos_source_port(
                    system.ip,
                    "DC-01",
                    at,
                    source_port=45_000,
                )
                generator._disambiguate_icmp_observation_time(
                    system.ip,
                    8,
                    "10.0.0.20",
                    0,
                    at,
                )
                generator._ntp_association_profile(system.ip, "10.0.0.123")
                generator._ntp_server_response_profile("10.0.0.123")
                occurrence += 1

            bash_before = len(generator._bash_history_user_seconds)
            browser_before = len(generator._top_level_browser_launch_targets)
            privileged_auth_before = len(generator._privileged_auth_occurrences)
            generator.advance_process_state_watermark(hour_start - timedelta(hours=24))
            maximum_late_hour_bash_expiry_work = max(
                maximum_late_hour_bash_expiry_work,
                bash_before - len(generator._bash_history_user_seconds),
            )
            maximum_late_hour_browser_expiry_work = max(
                maximum_late_hour_browser_expiry_work,
                browser_before - len(generator._top_level_browser_launch_targets),
            )
            maximum_late_hour_privileged_auth_expiry_work = max(
                maximum_late_hour_privileged_auth_expiry_work,
                privileged_auth_before - len(generator._privileged_auth_occurrences),
            )

        spool_census = asdict(spool.census())
        snapshots = {
            snapshot.field_name: snapshot
            for snapshot in snapshot_activity_generator_mutable_fields(generator)
        }
        spool.close()
        generator._email_artifact_manifest_spool = None

    definite_fields = tuple(
        sorted(
            policy.field_name
            for policy in ACTIVITY_GENERATOR_MUTABLE_RETENTION_POLICIES
            if policy.disposition is ActivityGeneratorRetentionDisposition.DEFINITE_GROWTH
        )
    )
    bounded_controls = (
        "_bash_history_command_counts",
        "_bash_history_next_time",
        "_bash_history_quick_streaks",
        "_bash_history_user_seconds",
        "_failed_logon_attempt_times",
        "_kerberos_source_port_reservations",
        "_last_workstation_lock_time",
        "_linux_local_logon_syslog_sessions",
        "_linux_sudo_tty_assignments",
        "_linux_sudo_tty_available",
        "_linux_sudo_tty_keys_by_logon_id",
        "_linux_sudo_tty_owners",
        "_linux_sudo_tty_sessions",
        "_next_icmp_observation_ts_us",
        "_ntp_association_profiles",
        "_ntp_server_response_profiles",
        "_postfix_queue_states",
        "_privileged_auth_occurrences",
        "_top_level_browser_launch_targets",
        "_user_process_history",
    )
    bash_metrics = generator._bash_history_user_seconds.metrics()
    browser_metrics = generator._top_level_browser_launch_targets.metrics()
    privileged_auth_metrics = generator._privileged_auth_occurrences.metrics()
    return {
        "hours": hours,
        "occurrences": occurrence,
        "open_growth_entries": {
            field_name: snapshots[field_name].entries for field_name in definite_fields
        },
        "open_growth_retained_bytes": {
            field_name: snapshots[field_name].retained_bytes for field_name in definite_fields
        },
        "bounded_control_entries": {
            field_name: snapshots[field_name].entries for field_name in bounded_controls
        },
        "bounded_index_backing": {
            "_bash_history_user_seconds": bash_metrics.backing_entries,
            "_top_level_browser_launch_targets": browser_metrics.backing_entries,
            "_privileged_auth_occurrences": privileged_auth_metrics.backing_entries,
        },
        "bounded_index_lookup_candidates": {
            "_top_level_browser_launch_targets": (
                generator._top_level_browser_launch_targets.lookup_candidates_inspected
            ),
            "_privileged_auth_occurrences": (
                generator._privileged_auth_occurrences.lookup_candidates_inspected
            ),
        },
        "browser_reuse_rejections": browser_reuse_rejections,
        "privileged_auth_reuse_rejections": privileged_auth_reuse_rejections,
        "email_manifest_spool": spool_census,
        "maximum_late_hour_expiry_work": {
            "_bash_history_user_seconds": maximum_late_hour_bash_expiry_work,
            "_top_level_browser_launch_targets": maximum_late_hour_browser_expiry_work,
            "_privileged_auth_occurrences": maximum_late_hour_privileged_auth_expiry_work,
        },
        "maximum_queue_rows": maximum_queue_rows,
        "maximum_session_retained_rows": maximum_session_retained_rows,
        "process_runtime_physical_records": snapshots["_production_process_runtime_caches"].entries,
        "released_session_rows": released_session_rows,
    }


def _expiry_profile(records: int) -> dict[str, float | int]:
    bundle = build_production_process_runtime_caches(_START + timedelta(days=30))
    families = tuple(spec.name for spec in PRODUCTION_PROCESS_RUNTIME_CACHE_FAMILIES)
    for ordinal in range(records):
        family = families[ordinal % len(families)]
        bundle.load_probe_entry(family, ordinal, _START, owner=f"owner-{ordinal}")
    started = time.perf_counter()
    expired = 0
    cutoff = _START + timedelta(days=31)
    while True:
        page = bundle.advance_watermark_page(cutoff, limit=4_096)
        expired += page.processed
        if not page.has_more:
            break
    census = bundle.census(watermark=cutoff)
    return {
        "requested_records": records,
        "expired": expired,
        "seconds": time.perf_counter() - started,
        "physical_records": census.physical_records,
        "backing_entries": census.backing_entries + census.reverse_backing_entries,
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--records", type=int, default=1_000_000)
    parser.add_argument("--queries", type=int, default=20_000)
    parser.add_argument("--expiry-records", type=int, default=100_000)
    parser.add_argument("--duration-rate", type=int, default=40)
    args = parser.parse_args()
    if min(args.records, args.queries, args.expiry_records, args.duration_rate) <= 0:
        raise SystemExit("probe counts must be positive")

    uniform = _lookup_profile(args.records, args.queries, skewed=False)
    single_owner = _lookup_profile(args.records, args.queries, skewed=True)
    expiry = _expiry_profile(args.expiry_records)
    duration = {
        label: _duration_profile(hours, args.duration_rate)
        for label, hours in (("24h", 24), ("7d", 24 * 7), ("30d", 24 * 30))
    }
    generator_duration = {
        label: _activity_generator_duration_profile(hours, args.duration_rate)
        for label, hours in (("24h", 24), ("7d", 24 * 7), ("30d", 24 * 30))
    }
    retention_inventory = {
        disposition.value: tuple(
            sorted(
                policy.field_name
                for policy in ACTIVITY_GENERATOR_MUTABLE_RETENTION_POLICIES
                if policy.disposition is disposition
            )
        )
        for disposition in ActivityGeneratorRetentionDisposition
    }
    million = 1_000_000
    normalized_rss = max(
        int(profile["rss_bytes"]) * million / max(1, int(profile["physical_records"]))
        for profile in (uniform, single_owner)
    )
    normalized_load = max(
        float(profile["load_seconds"]) * million / max(1, int(profile["physical_records"]))
        for profile in (uniform, single_owner)
    )
    maximum_index_bytes_per_record = max(
        int(profile["estimated_index_bytes"]) / max(1, int(profile["physical_records"]))
        for profile in (uniform, single_owner)
    )
    seven_day = int(duration["7d"]["physical_records"])
    thirty_day = int(duration["30d"]["physical_records"])
    bounded_fields = tuple(generator_duration["7d"]["bounded_control_entries"])
    bounded_plateau = all(
        abs(
            int(generator_duration["30d"]["bounded_control_entries"][field_name])
            - int(generator_duration["7d"]["bounded_control_entries"][field_name])
        )
        <= max(
            1,
            int(generator_duration["7d"]["bounded_control_entries"][field_name]),
        )
        * 0.10
        for field_name in bounded_fields
    )
    bounded_backing_ratio = all(
        int(profile["bounded_index_backing"][field_name])
        <= max(1, int(profile["bounded_control_entries"][field_name])) * 2
        for profile in generator_duration.values()
        for field_name in profile["bounded_index_backing"]
    )
    report = {
        "uniform": uniform,
        "single_owner": single_owner,
        "expiry": expiry,
        "duration": duration,
        "activity_generator_retention_inventory": retention_inventory,
        "removed_dead_activity_generator_fields": (REMOVED_DEAD_ACTIVITY_GENERATOR_MUTABLE_FIELDS),
        "removed_duration_sized_activity_generator_fields": (
            REMOVED_DURATION_SIZED_ACTIVITY_GENERATOR_FIELDS
        ),
        "activity_generator_duration_debt": {
            "status": "open",
            "profiles": generator_duration,
            "all_open_fields_grow_7d_to_30d": all(
                int(generator_duration["30d"]["open_growth_entries"][field_name])
                > int(generator_duration["7d"]["open_growth_entries"][field_name])
                for field_name in generator_duration["7d"]["open_growth_entries"]
            ),
        },
        "gates": {
            "lookup_candidates_exact": all(
                int(profile["lookup_candidates"]) == args.queries
                for profile in (uniform, single_owner)
            ),
            "lookup_p95_lte_10us": all(
                float(profile["lookup_p95_us"]) <= 10.0 for profile in (uniform, single_owner)
            ),
            "normalized_rss_per_million_lte_512mib": normalized_rss <= 512 * 1024 * 1024,
            "normalized_load_per_million_lte_60s": normalized_load <= 60.0,
            "index_bytes_per_physical_record_lte_256": (maximum_index_bytes_per_record <= 256.0),
            "expire_100k_lte_2s": (
                args.expiry_records != 100_000 or float(expiry["seconds"]) <= 2.0
            ),
            "expiry_backing_empty": int(expiry["backing_entries"]) == 0,
            "seven_to_thirty_day_plateau_lte_10pct": (
                abs(thirty_day - seven_day) <= max(1, seven_day) * 0.10
            ),
            "activity_generator_bounded_7d_to_30d_plateau_lte_10pct": bounded_plateau,
            "activity_generator_bounded_backing_lte_2x_live": bounded_backing_ratio,
            "activity_generator_late_hour_expiry_work_lt_page": all(
                int(work) < 4_096
                for profile in generator_duration.values()
                for work in profile["maximum_late_hour_expiry_work"].values()
            ),
            "browser_exact_reuse_one_candidate": all(
                int(profile["bounded_index_lookup_candidates"]["_top_level_browser_launch_targets"])
                == int(profile["occurrences"])
                for profile in generator_duration.values()
            ),
            "privileged_auth_exact_reuse_one_candidate": all(
                int(profile["bounded_index_lookup_candidates"]["_privileged_auth_occurrences"])
                == int(profile["occurrences"])
                and int(profile["privileged_auth_reuse_rejections"]) == int(profile["occurrences"])
                for profile in generator_duration.values()
            ),
            "email_manifest_rows_externalized": all(
                int(profile["email_manifest_spool"]["retained_rows"]) == 0
                and int(profile["email_manifest_spool"]["backing_rows"])
                == int(profile["occurrences"])
                and int(profile["email_manifest_spool"]["maximum_append_work"]) <= 1
                for profile in generator_duration.values()
            ),
        },
    }
    print(json.dumps(report, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
