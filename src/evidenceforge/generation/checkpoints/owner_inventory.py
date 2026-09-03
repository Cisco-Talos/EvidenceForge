"""Explicit persistence inventory for mutable generation state owners."""

from __future__ import annotations

from collections.abc import Mapping

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
    actual = set(vars(owner))
    if expected != actual:
        raise CheckpointError(
            f"checkpoint inventory for {owner_name} is incomplete: "
            f"missing={sorted(actual - expected)}, stale={sorted(expected - actual)}"
        )


def assert_transient_owner_state_empty(
    owner: object,
    fields: tuple[OwnerStateField, ...],
    *,
    owner_name: str,
) -> None:
    """Reject a barrier while any field classified as transient still owns state."""

    assert_complete_owner_inventory(owner, fields, owner_name=owner_name)
    nonempty: dict[str, object] = {}
    attributes: Mapping[str, object] = vars(owner)
    for field in fields:
        if field.disposition != "transient-empty-at-barrier":
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
