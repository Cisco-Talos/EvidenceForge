"""Explicit persistence inventory for mutable generation state owners."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import fields, is_dataclass

from .errors import CheckpointError
from .participants import OwnerStateField


def _fields(
    *,
    live: tuple[str, ...] = (),
    incremental: tuple[str, ...] = (),
    rebuilt: tuple[str, ...] = (),
    transient: tuple[str, ...] = (),
) -> tuple[OwnerStateField, ...]:
    """Build one duplicate-free, stable structural owner inventory."""

    classified = (
        *((name, "bounded-live-head") for name in live),
        *((name, "immutable-incremental-segments") for name in incremental),
        *((name, "deterministically-rebuilt") for name in rebuilt),
        *((name, "transient-empty-at-barrier") for name in transient),
    )
    names = [name for name, _ in classified]
    if len(names) != len(set(names)):
        raise ValueError("checkpoint owner inventory contains a duplicate field")
    return tuple(
        OwnerStateField(name, disposition)  # type: ignore[arg-type]
        for name, disposition in sorted(classified)
    )


STATE_MANAGER_CHECKPOINT_FIELDS = _fields(
    live=(
        "_active_pid_reservation_counts",
        "_active_sessions",
        "_authoritative_session_ends",
        "_connection_id_counter",
        "_ended_processes_by_key",
        "_ended_processes_by_object_id",
        "_ended_sessions",
        "_ended_sessions_by_system_end",
        "_ended_sessions_by_username_end",
        "_ended_threads",
        "_fixed_pid_reservations",
        "_linux_logind_session_allocations",
        "_linux_logind_session_block_offsets",
        "_linux_logind_session_counters",
        "_linux_logind_session_epochs",
        "_linux_logind_session_initials",
        "_linux_logind_session_last_ids",
        "_linux_pid_allocations",
        "_linux_pid_weekly_churn_prefixes",
        "_logon_id_aliases",
        "_logon_id_aliases_by_target",
        "_logon_id_block_offsets",
        "_logon_id_epochs",
        "_logon_id_host_bases",
        "_logon_id_used_host_bases",
        "_materialization_version",
        "_open_connections",
        "_pid_allocation_count",
        "_pid_allocation_watermark",
        "_pid_bucket_offsets",
        "_pid_candidate_probe_count",
        "_pid_counters",
        "_pid_os",
        "_pid_rngs",
        "_pid_sealed_logical_positions",
        "_pid_time_epochs",
        "_process_object_ids",
        "_processes_by_object_id",
        "_reserved_logon_ids",
        "_running_processes",
        "_running_threads",
        "_smb_file_by_share_path",
        "_smb_file_overlay",
        "_system_boot_times",
        "_terminal_connection_ids",
        "_thread_id_counters",
        "_thread_id_rngs",
        "_transient_pid_reservation_counts",
        "_transient_pid_reservations",
        "_windows_session_id_counters",
        "state",
    ),
    incremental=(
        "_linux_logind_session_used_ids",
        "_logon_id_second_ordinals",
        "_semantic_peer_ordinals",
        "_used_logon_ids",
    ),
    rebuilt=(
        "_connection_expirations",
        "_connection_plan_owner_token",
        "_lock",
        "_materialization_secret",
        "_prepared_state_admission_epoch",
        "_checkpoint_incremental_recorder",
    ),
    transient=(
        "_active_action_cohort_claim",
        "_active_action_cohort_preparations",
        "_active_connection_composite_preparations",
        "_active_connection_preparations",
        "_active_materialization_batch_preparations",
        "_active_materialization_batch_private_rollback",
        "_active_prepared_state_claim",
        "_smb_connection_acknowledging_by_conn_id",
        "_smb_connection_authority_by_conn_id",
        "_smb_connection_conn_id_by_logon_id",
        "_smb_connection_retained_bytes",
        "_smb_file_mutation_acknowledging",
        "_smb_file_mutation_cancelling",
        "_smb_file_mutation_journal_by_operation",
        "_smb_file_mutation_journals",
        "_smb_file_mutation_locator_by_journal_identity",
        "_smb_file_mutation_locator_by_result_identity",
        "_smb_file_mutation_owner_by_file_id",
        "_smb_file_mutation_owner_by_path",
    ),
)


SOURCE_TIMING_PLANNER_CHECKPOINT_FIELDS = _fields(
    live=(
        "_admitted_ecar_remote_transports",
        "_admitted_ecar_smb_transports",
        "_admitted_ecar_ssh_transports",
        "_admitted_ecar_transport_transactions",
        "_admitted_process_create_frontiers",
        "_admitted_windows_remote_transports",
        "_admitted_windows_transport_transactions",
        "_ecar_process_create_times",
        "_ecar_transport_close_deadlines",
        "_kerberos_service_times",
        "_latest_session_dependent_descriptions",
        "_latest_session_dependent_times",
        "_latest_session_start_times",
        "_process_dependent_create_times",
        "_runtime_cross_source_sysmon_create_times",
        "_runtime_process_create_times",
        "_sysmon_process_render_create_times",
        "_watermark",
    ),
    rebuilt=(
        "_detached_binding_capacity",
        "_detached_binding_high_water",
        "_detached_binding_owner_marker",
        "_detached_binding_semantic_bytes",
        "_next_preparation_id",
        "_preparation_admission_lock",
        "_preparation_authority_capacity",
        "_preparation_authority_high_water",
        "_preparation_authority_lock",
        "_preparation_claim_semantic_bytes",
        "_preparation_generation_semantic_bytes",
        "_preparation_lane_epoch",
        "_preparation_lock",
        "_preparation_receipt_high_water",
        "_preparation_receipt_semantic_bytes",
        "_preparation_secret",
        "_retained_preparation_plan_operations",
        "_terminal_preparations",
        "clock_profile_name",
        "timing_runtime",
    ),
    transient=(
        "_action_capacity_by_action",
        "_action_capacity_records",
        "_active_preparation_claims",
        "_committed_preparation_receipts",
        "_detached_binding_by_context",
        "_detached_bindings",
        "_preparation_claim_records",
        "_preparation_lane",
        "_preparation_lane_generation",
        "_preparation_lane_marker",
        "_reserved_detached_binding_slots",
        "_reserved_preparation_claim_slots",
        "_reserved_preparation_receipt_slots",
    ),
)


APPLICATION_CHANNEL_REGISTRY_CHECKPOINT_FIELDS = _fields(
    live=("_shards", "_watermark"),
    rebuilt=(
        "_admission_secret",
        "_closed_grace",
        "_directory_lock",
        "_expiry_compaction_cursor",
        "_gate",
        "_max_reusable_per_affinity",
        "_next_prepared_reservation_id",
        "_prepared_lock",
        "_retired_route_compaction_rotations",
        "_retired_route_compaction_seconds",
        "_retired_route_compaction_work",
        "_route_compaction_cursor",
        "_route_partitions",
        "_route_reclaim_cursor",
        "_shard_compaction_cursor",
        "_shard_count",
        "_watermark_lane",
        "_window_end",
        "_window_start",
    ),
    transient=(
        "_acknowledging_admission_results",
        "_acknowledging_close_results",
        "_admission_receipts",
        "_claimed_reservations",
        "_close_receipts",
        "_mutating_affinity_counts",
        "_mutating_channel_ids",
        "_mutating_operation_ids",
        "_mutating_transport_ids",
        "_prepared_affinity_reservations",
        "_prepared_capabilities",
        "_prepared_channel_ids",
        "_prepared_close_capabilities",
        "_prepared_close_commit_journals",
        "_prepared_close_tokens",
        "_prepared_commit_journals",
        "_prepared_operation_ids",
        "_prepared_reservations",
        "_prepared_transport_ids",
        "_recoverable_admission_receipts",
        "_recoverable_admission_results",
        "_recoverable_admission_slots",
        "_recoverable_close_receipts",
        "_recoverable_close_results",
        "_releasing_reservations",
        "_retirement_proofs",
    ),
)


APPLICATION_CHANNEL_SHARD_CHECKPOINT_FIELDS = _fields(
    live=("channels", "operations", "used_operation_ids"),
    rebuilt=(
        "_accounting",
        "active_expiry",
        "closed_expiry",
        "compaction_cursor",
        "expiry_compaction_cursor",
        "lock",
        "lookup_candidates_inspected",
        "operation_blocker_expiry",
        "operation_deletions",
        "shard_id",
        "used_id_deletions",
    ),
)


INTENT_EXECUTION_LEDGER_CHECKPOINT_FIELDS = _fields(
    live=(
        "_aggregates",
        "_hot_identities",
        "_watermark_us",
    ),
    rebuilt=(
        "_authored",
        "_authored_ids",
        "_batch_ledger_id",
        "_batch_prepared_delta_capacity",
        "_batch_prepared_intent_capacity",
        "_batch_reservation_capacity",
        "_hot_identity_capacity",
        "_hot_identity_heap",
        "_identity_sample_limit",
        "_lock",
        "_next_batch_preparation_id",
    ),
    transient=(
        "_batch_capability_locators",
        "_batch_claimed_preparation_id",
        "_batch_claimed_reservations",
        "_batch_committed_receipts",
        "_batch_prepared_commit_plans",
        "_batch_prepared_deltas",
        "_batch_reservations",
        "_batch_reserved_intents",
        "_batch_retained_bytes",
    ),
)


RDP_MANAGER_CHECKPOINT_FIELDS = _fields(
    live=("_shards", "_watermark"),
    rebuilt=(
        "_admission_secret",
        "_affinity_partitions",
        "_application",
        "_directory_lock",
        "_expiry_compaction_cursor",
        "_gate",
        "_manager_id",
        "_max_leases_per_session",
        "_next_prepared_reservation_id",
        "_post_logout_grace",
        "_prepared_lock",
        "_retention_horizon",
        "_route_compaction_cursor",
        "_shard_compaction_cursor",
        "_shard_count",
        "_watermark_lane",
        "_window_end",
        "_window_start",
    ),
    transient=(
        "_admission_receipts",
        "_claimed_admissions",
        "_mutating_logical_session_ids",
        "_prepared_admissions",
        "_prepared_affinity_routes",
        "_prepared_capabilities",
        "_prepared_logical_session_ids",
    ),
)


RDP_SHARD_CHECKPOINT_FIELDS = _fields(
    live=(
        "generation_high_water_mark",
        "leases",
        "maximum_lease_bucket",
        "operations",
        "sessions",
    ),
    rebuilt=(
        "active_leases",
        "active_operations",
        "blocker_expiry",
        "compaction_cursor",
        "connected_sessions",
        "disconnected_sessions",
        "estimated_value_bytes",
        "expiry_compaction_cursor",
        "lease_expiry",
        "lease_route_deletions",
        "lease_routes",
        "lock",
        "logged_out_sessions",
        "logical_lookup_candidates_inspected",
        "operation_deletions",
        "session_expiry",
        "session_route_deletions",
        "session_routes",
        "shard_id",
        "snapshot_cache",
        "snapshot_cache_value_bytes",
    ),
)


NETWORK_TRANSACTION_RUNTIME_CHECKPOINT_FIELDS = _fields(
    live=(
        "_next_point_ordinal",
        "_next_preparation_id",
        "_next_transport_ordinal",
        "_points",
        "_transport_freshness",
        "_transport_records_by_occurrence",
        "_watermark",
    ),
    rebuilt=(
        "_adaptive_transport_reuses",
        "_expiry_heap",
        "_last_result",
        "_live_points",
        "_live_transport_leases",
        "_lock",
        "_peak_transport_bucket_occupancy",
        "_point_state_xor",
        "_secret",
        "_tombstone_points",
        "_tombstone_retention",
        "_transport_buckets",
        "_transport_candidate_inspections",
        "_transport_endpoint_occurrences",
        "_transport_exhaustions",
        "_transport_freshness_deadlines",
        "_transport_lease_deadlines",
        "_transport_state_xor",
        "_window_end",
        "_window_start",
        "cryptographic_material",
        "state_manager",
    ),
    transient=(
        "_adopted_transport_by_preparation",
        "_claimed_composites",
        "_claimed_point_batch_commits",
        "_claimed_point_batches",
        "_claimed_preparations",
        "_open_capabilities_by_identity",
        "_open_objects",
        "_open_point_batch_capabilities_by_identity",
        "_open_point_batch_objects",
        "_open_point_batches",
        "_open_preparations",
        "_pending_transport_leases",
        "_pending_watermark",
        "_point_batch_capabilities",
        "_point_batch_tokens",
        "_preparation_fences",
        "_prepared_capabilities",
        "_prepared_tokens",
        "_reserved_by_preparation",
        "_reserved_deadlines",
        "_reserved_points",
        "_transport_records_by_preparation",
    ),
)


CRYPTOGRAPHIC_MATERIAL_CHECKPOINT_FIELDS = _fields(
    live=("_next_tls_preparation_id",),
    incremental=(
        "_authorities",
        "_certificates",
        "_dkim_keys",
        "_public_keys",
        "_tls_point_generations",
        "_tls_point_tombstones",
    ),
    rebuilt=(
        "_checkpoint_incremental_recorder",
        "_dkim_key_byte_high_water",
        "_dkim_key_estimated_bytes",
        "_dkim_key_high_water",
        "_dkim_key_state_xor",
        "_tls_canonical_state_xor",
        "_tls_material_capacity",
        "_tls_material_generation_high_water",
        "_tls_material_high_water_bytes",
        "_tls_material_high_water_points",
        "_tls_material_lock",
        "_tls_point_retained_bytes",
        "_tls_preparation_high_water_bytes",
        "_tls_preparation_high_water_overlays",
        "_tls_preparation_secret",
        "_tls_retained_material_bytes",
    ),
    transient=(
        "_tls_claimed_preparations",
        "_tls_claimed_state_components",
        "_tls_claimed_state_xor",
        "_tls_claimed_transactions",
        "_tls_committed_receipts",
        "_tls_dead_claims",
        "_tls_dead_preparations",
        "_tls_new_slot_reservations",
        "_tls_point_reservations",
        "_tls_preparation_retained_bytes",
        "_tls_prepared_capabilities",
        "_tls_prepared_state_components",
        "_tls_prepared_state_xor",
        "_tls_prepared_tokens",
        "_tls_reservation_byte_deltas",
        "_tls_reservation_state_components",
        "_tls_reservation_state_xor",
        "_tls_reserved_material_bytes",
        "_tls_retained_preparation_bytes",
    ),
)


HTTP_CHANNEL_MANAGER_CHECKPOINT_FIELDS = _fields(
    live=("_next_prepared_reservation_id", "_shards", "_watermark"),
    rebuilt=(
        "_admission_secret",
        "_compaction_cursor",
        "_directory_lock",
        "_gate",
        "_manager_id",
        "_operation_budget",
        "_owns_registry",
        "_prepared_lock",
        "_registry",
        "_reuse_guard",
        "_watermark_lane",
    ),
    transient=(
        "_admission_receipts",
        "_claimed_admissions",
        "_prepared_admissions",
        "_prepared_affinity_digests",
        "_prepared_capabilities",
        "_prepared_channel_ids",
    ),
)


HTTP_TRANSPORT_SHARD_CHECKPOINT_FIELDS = _fields(
    live=("transports",),
    rebuilt=("lock", "shard_id", "transport_deletions", "transport_expiry"),
)


HTTP_PACKED_TRANSPORT_STORE_CHECKPOINT_FIELDS = _fields(
    live=("_rows",),
    rebuilt=(
        "_affinity_routes",
        "_channel_routes",
        "_compaction_rotations",
        "_decoded",
        "_decoded_bytes",
        "_lookup_candidates_inspected",
    ),
)


PROXY_CHANNEL_MANAGER_CHECKPOINT_FIELDS = _fields(
    live=("_next_admission_id", "_shards", "_watermark"),
    rebuilt=(
        "_close_guard",
        "_directory_lock",
        "_gate",
        "_idle_timeout",
        "_manager_id",
        "_owns_registry",
        "_prepared_lock",
        "_registry",
        "_shard_count",
        "_window_end",
        "_window_start",
    ),
    transient=(
        "_admission_receipts",
        "_claimed_admissions",
        "_estimated_prepared_bytes",
        "_prepared_admissions",
        "_prepared_affinity_keys",
        "_prepared_capabilities",
        "_prepared_channel_ids",
        "_prepared_origin_transport_ids",
        "_request_snapshots",
    ),
)


PROXY_SIDECAR_SHARD_CHECKPOINT_FIELDS = _fields(
    live=("tunnels",),
    rebuilt=("expiry", "lock", "shard_id"),
)


PROXY_PACKED_TUNNEL_STORE_CHECKPOINT_FIELDS = _fields(
    live=("_rows",),
    rebuilt=(
        "_affinity_routes",
        "_channel_routes",
        "_compaction_rotations",
        "_decoded",
        "_decoded_bytes",
        "_lookup_candidates_inspected",
        "_origin_transport_routes",
    ),
)


RDP_AFFINITY_PARTITION_CHECKPOINT_FIELDS = _fields(
    rebuilt=(
        "deletions",
        "lock",
        "lookup_candidates_inspected",
        "partition_id",
        "routes",
    ),
)


TIMING_RUNTIME_CHECKPOINT_FIELDS = _fields(
    rebuilt=("_owner_lane_epoch", "_owner_lane_lock", "clocks", "sampler"),
    live=("audit",),
    transient=("_owner_lane",),
)


TIMING_AUDIT_CHECKPOINT_FIELDS = _fields(
    live=(
        "_distribution_counts",
        "_fallback_counts",
        "_mutation_version",
        "_repair_counts",
        "_sample_counts",
        "_saturation_counts",
    ),
    rebuilt=("_lock", "_owner_runtime"),
)


TIMING_RELATIONSHIP_COUNTER_CHECKPOINT_FIELDS = _fields(
    live=("_slots", "_total"),
    rebuilt=("_capacity", "_estimated_slot_bytes"),
)


SOURCE_CLOCK_REGISTRY_CHECKPOINT_FIELDS = _fields(
    rebuilt=(
        "_cache_entry_estimated_bytes",
        "_cache_hit_count",
        "_cache_miss_count",
        "_eviction_count",
        "_high_water_mark",
        "_lock",
        "_lookup_count",
        "_max_cache_entries",
        "_mutation_version",
        "_owner_runtime",
        "_reference_time",
        "_sampler",
        "_states",
        "_value_sampler",
    ),
)


GENERATION_ENGINE_CHECKPOINT_FIELDS = _fields(
    live=(
        "_ambient_registry_state",
        "_audit_serials",
        "_baseline_startup_next_age_seconds",
        "_dhcp_lease_state",
        "_extra_syslog_sudo_command_counts",
        "_extra_syslog_sudo_command_host_counts",
        "_hawkes_states",
        "_last_tgt_time",
        "_machine_ids",
        "_ntp_schedule_state",
        "_pending_unlocks",
        "_red_herring_executed",
        "_storyline_executed",
        "_windows_scheduled_task_counts",
        "_windows_scheduled_task_last_seen",
        "malicious_events",
        "red_herring_events",
    ),
    rebuilt=(
        "_ad_domain",
        "_boot_materialization_existing_system_pids",
        "_boot_materialization_state_time",
        "_boot_materialization_terminal_identity",
        "_boot_materialization_terminal_result",
        "_boot_materialization_transaction",
        "_boot_materialization_transaction_identity",
        "_external_scanner_ips",
        "_external_scanner_weights",
        "_generate_owner",
        "_generation_epoch",
        "_host_activity_profile_cache",
        "_identity_directory",
        "_infra_ips",
        "_initialization_complete",
        "_kernel_boot_uptimes",
        "_netbios_domain",
        "_org_cidr_networks",
        "_proxy_routes",
        "_red_herring_by_hour",
        "_scenario_tz",
        "_source_finalization_authority",
        "_source_finalization_coordinator",
        "_storyline_by_hour",
        "_system_pids",
        "_system_service_defaults",
        "_user_time_offsets",
        "activity_generator",
        "allow_large_workload",
        "application_channel_registry",
        "artifact_dir",
        "authored_intent_ledger",
        "checkpoint_hour_callback",
        "checkpoint_hours",
        "compiled_scenario",
        "dispatcher",
        "emitters",
        "end_time",
        "generation_seed",
        "ground_truth_dir",
        "intent_execution_ledger",
        "lifecycle_authority",
        "lifecycle_registry",
        "lifecycle_shadow",
        "network_resolver",
        "oob_hosts",
        "output_dir",
        "output_target",
        "progress_callback",
        "rdp_session_manager",
        "resource_forecast",
        "scenario",
        "scenario_root",
        "source_deployment_compilation",
        "source_timing_planner",
        "start_time",
        "state_manager",
        "storage_world",
        "timing_runtime",
        "warmup_duration",
        "warmup_start_time",
        "workload_estimate",
        "world_model",
        "world_planner",
    ),
    transient=(
        "_application_channels_finalized",
        "_closed_emitter_names",
        "_exact_projection_recoveries_finalized",
        "_exact_projection_recovery_dispatcher",
        "_expected_close_emitters",
        "_finalization_aborted",
        "_finalization_complete",
        "_foreground_lifecycles_finalized",
        "_generation_body_completed",
        "_generation_complete",
        "_ids_alert_summary_applied",
        "_linux_sudo_logoffs_finalized",
        "_persistent_smb_terminal_asserted",
        "_rdp_lifecycles_finalized",
        "_source_coordinator_closed",
        "_ssh_lifecycles_finalized",
        "_terminal_owner_snapshot",
        "_terminal_runtime_cleanup_finalized",
        "_terminal_transient_census_asserted",
    ),
)


LIFECYCLE_REGISTRY_CHECKPOINT_FIELDS = _fields(
    live=(
        "_action_cohort_committed_provenance",
        "_action_cohort_provenance_by_operations",
        "_ledger_floor",
        "_partitions",
        "_watermark",
    ),
    rebuilt=(
        "_action_cohort_operation_capacity",
        "_action_cohort_provenance_capacity",
        "_action_cohort_receipt_authority_capacity",
        "_action_cohort_registry_id",
        "_action_cohort_request_byte_capacity",
        "_action_cohort_reservation_capacity",
        "_action_cohort_reserved_key_capacity",
        "_closed_retention",
        "_closed_transport_preparation_condition",
        "_closed_transport_preparation_lock",
        "_closed_transport_registry_id",
        "_gate",
        "_ledger_detail_retention",
        "_next_action_cohort_preparation_id",
        "_next_closed_transport_preparation_id",
        "_next_service_preparation_id",
        "_routes",
        "_service_registry_id",
        "_shard_count",
        "_snapshot_history_limit",
    ),
    transient=(
        "_action_cohort_capability_locators",
        "_action_cohort_certified_authorizations",
        "_action_cohort_claimed_capabilities",
        "_action_cohort_claimed_reservations",
        "_action_cohort_committing_reservations",
        "_action_cohort_expected_receipt_authorities",
        "_action_cohort_pending_provenance_evictions",
        "_action_cohort_pending_provenance_insertions",
        "_action_cohort_provenance_pins",
        "_action_cohort_receipt_authorities",
        "_action_cohort_committed_receipt_authorities",
        "_action_cohort_reservations",
        "_action_cohort_reserved_keys",
        "_action_cohort_retained_request_bytes",
        "_closed_transport_capability_locators",
        "_closed_transport_claimed_reservations",
        "_closed_transport_mutating_keys",
        "_closed_transport_receipts",
        "_closed_transport_reservations",
        "_closed_transport_reserved_keys",
        "_service_capability_locators",
        "_service_claimed_closures",
        "_service_claimed_publications",
        "_service_closure_receipts",
        "_service_closure_reservations",
        "_service_publication_receipts",
        "_service_publication_reservations",
        "_service_reserved_keys",
    ),
)


LIFECYCLE_PARTITION_CHECKPOINT_FIELDS = _fields(
    live=(
        "_barriers",
        "_children_by_parent",
        "_compacted_holds",
        "_compacted_transitions",
        "_foreground_leases",
        "_holds",
        "_ledger_floor",
        "_leases",
        "_live_service_children",
        "_live_children",
        "_live_session_members",
        "_live_transport_bindings_by_session",
        "_members_by_session",
        "_processes",
        "_resource_lease_deadline_bindings",
        "_resource_lease_max_subject_bindings",
        "_retention_lease_deadline_bindings",
        "_retention_lease_max_subject_bindings",
        "_service_bindings_by_process",
        "_service_children_by_parent",
        "_service_process_bindings",
        "_service_process_tombstones",
        "_service_processes_by_service",
        "_services",
        "_sessions",
        "_singleton_leases",
        "_tickets",
        "_transitions",
        "_transport_bindings_by_session",
        "_transport_session_bindings",
        "_transport_session_tombstones",
        "_transports",
        "_watermark",
    ),
    rebuilt=(
        "_active_service_process_bindings",
        "_active_transport_session_bindings",
        "_catalog_lock",
        "_commit_map_backing_bytes",
        "_commit_map_entries",
        "_dependent_aggregate_candidates_inspected",
        "_evicted_bindings",
        "_evicted_processes",
        "_evicted_services",
        "_evicted_sessions",
        "_evicted_transports",
        "_exact_lookup_candidates_inspected",
        "_foreground_lease_deadlines",
        "_high_water_processes",
        "_high_water_sessions",
        "_hold_compaction_pending",
        "_hold_times",
        "_host_lanes",
        "_index_lock",
        "_lease_deadlines",
        "_live_processes",
        "_live_service_instances",
        "_live_sessions",
        "_live_transports",
        "_process_retention_deadlines",
        "_process_starts",
        "_resource_lease_candidates_inspected",
        "_resource_lease_deadlines",
        "_retention_lease_candidates_inspected",
        "_retention_lease_deadlines",
        "_service_process_tombstone_deadlines",
        "_service_retention_deadlines",
        "_service_starts",
        "_session_retention_deadlines",
        "_session_starts",
        "_singleton_lease_deadlines",
        "_singleton_lease_starts",
        "_snapshot_history_limit",
        "_closed_retention",
        "_ledger_detail_retention",
        "_transition_compaction_pending",
        "_transition_times",
        "_transport_retention_deadlines",
        "_transport_session_tombstone_deadlines",
        "_transport_starts",
        "_watermark_gate",
    ),
    transient=("_route_removals",),
)


def assert_complete_owner_inventory(
    owner: object,
    fields: tuple[OwnerStateField, ...],
    *,
    owner_name: str,
) -> None:
    """Reject an owner whose runtime attributes are absent from its inventory."""

    expected = {field.name for field in fields}
    actual = set(_owner_attributes(owner))
    if expected != actual:
        raise CheckpointError(
            f"checkpoint inventory for {owner_name} is incomplete: "
            f"missing={sorted(actual - expected)}, stale={sorted(expected - actual)}"
        )


def assert_owner_inventory_covers(
    owner: object,
    fields: tuple[OwnerStateField, ...],
    *,
    owner_name: str,
) -> None:
    """Reject materialized owner fields absent from an inventory with optional entries."""

    expected = {field.name for field in fields}
    actual = set(_owner_attributes(owner))
    if actual - expected:
        raise CheckpointError(
            f"checkpoint inventory for {owner_name} is incomplete: "
            f"missing={sorted(actual - expected)}"
        )


def assert_transient_owner_state_empty(
    owner: object,
    fields: tuple[OwnerStateField, ...],
    *,
    owner_name: str,
    allow_unmaterialized: bool = False,
) -> None:
    """Reject a barrier while any field classified as transient still owns state."""

    if allow_unmaterialized:
        assert_owner_inventory_covers(owner, fields, owner_name=owner_name)
    else:
        assert_complete_owner_inventory(owner, fields, owner_name=owner_name)
    nonempty: dict[str, object] = {}
    attributes = _owner_attributes(owner)
    for field in fields:
        if field.disposition != "transient-empty-at-barrier":
            continue
        if field.name not in attributes:
            continue
        value = attributes[field.name]
        if value is None or value is False or value == 0:
            continue
        try:
            empty = len(value) == 0  # type: ignore[arg-type]
        except TypeError:
            empty = False
        if not empty:
            nonempty[field.name] = value
    if nonempty:
        raise CheckpointError(
            f"checkpoint barrier for {owner_name} retains transient state: {sorted(nonempty)}"
        )


def _owner_attributes(owner: object) -> Mapping[str, object]:
    """Return exact stored fields for dictionary- or dataclass-slot-backed owners."""

    try:
        return vars(owner)
    except TypeError:
        if is_dataclass(owner) and not isinstance(owner, type):
            return {field.name: getattr(owner, field.name) for field in fields(owner)}
        slot_names: list[str] = []
        for owner_type in reversed(type(owner).__mro__):
            declared = owner_type.__dict__.get("__slots__", ())
            names = (declared,) if isinstance(declared, str) else declared
            slot_names.extend(
                name
                for name in names
                if name not in {"__dict__", "__weakref__"} and hasattr(owner, name)
            )
        if slot_names:
            return {name: getattr(owner, name) for name in slot_names}
        raise CheckpointError(
            f"checkpoint owner {type(owner).__name__} exposes no inspectable stored fields"
        ) from None
