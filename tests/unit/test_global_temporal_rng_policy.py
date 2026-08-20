# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Focused repository policy for migrated temporal sampling owners."""

from __future__ import annotations

import ast
from collections import Counter
from pathlib import Path

import evidenceforge.generation as generation_package

_LEGACY_HELPERS = frozenset({"sample_timing_delta", "sample_packet_timing_delta"})
_RAW_TEMPORAL_METHODS = frozenset(
    {
        "betavariate",
        "expovariate",
        "gammavariate",
        "gauss",
        "lognormvariate",
        "normalvariate",
        "paretovariate",
        "randint",
        "randrange",
        "triangular",
        "uniform",
        "vonmisesvariate",
        "weibullvariate",
    }
)

# Exact integration-head ceiling for direct continuous RNG. Thirty-seven calls
# are known byte/count/identity texture; the remaining 322 are deferred temporal
# debt. Keeping the conservative superset here prevents either class from
# growing while allowing any owner to remove a selector or lower its count.
_DIRECT_CONTINUOUS_RNG_CAPS_TEXT = """
4|actions/network_transaction_planner.py|_execute|uniform
1|actions/rdp_session.py|execute|uniform
1|actions/smb_activity.py|_duration|uniform
1|actions/smb_activity.py|_operation_timing|lognormvariate
3|actions/smb_activity.py|_operation_timing|uniform
1|actions/smb_activity.py|_raw_session_setup_seconds|uniform
1|actions/smb_activity.py|_transport_bytes|uniform
1|actions/smb_activity.py|_updated_size|uniform
1|actions/ssh_session.py|_plan_transport|uniform
1|activity/browsing_session.py|_response_size_for_status_code|uniform
8|activity/generator.py|_dns_rtt|uniform
1|activity/generator.py|_email_date_header_for_route|uniform
3|activity/generator.py|_email_smtp_hop_times|uniform
1|activity/generator.py|_emit_ad_srv_discovery|uniform
2|activity/generator.py|_emit_dovecot_imap_syslog|uniform
2|activity/generator.py|_emit_email_route_dns|uniform
2|activity/generator.py|_emit_failed_linux_ssh_network_connection|uniform
2|activity/generator.py|_emit_nmap_discovery_probes|uniform
1|activity/generator.py|_emit_process_network_correlation|uniform
1|activity/generator.py|_emit_recipient_email_endpoint_artifacts|uniform
1|activity/generator.py|_emit_remote_service_control_network_evidence|uniform
1|activity/generator.py|_emit_sender_email_endpoint_artifacts|uniform
1|activity/generator.py|_ensure_browser_http_client_process|uniform
1|activity/generator.py|_ensure_email_client_process|uniform
2|activity/generator.py|_ensure_email_server_process|uniform
2|activity/generator.py|_ensure_explicit_proxy_client_process|uniform
2|activity/generator.py|_ensure_linux_apt_frontend_process|uniform
1|activity/generator.py|_ensure_parent_chain|uniform
2|activity/generator.py|_ensure_system_connection_owner_process|uniform
2|activity/generator.py|_ensure_user_connection_owner_process|uniform
1|activity/generator.py|_ensure_visible_created_account_kerberos_exchange|uniform
1|activity/generator.py|_execute_anonymous_logon_bundle|uniform
1|activity/generator.py|_execute_dhcp_lease_bundle|uniform
5|activity/generator.py|_execute_dns_lookup_bundle|uniform
1|activity/generator.py|_execute_email_access_bundle|uniform
1|activity/generator.py|_execute_email_delivery_bundle|uniform
1|activity/generator.py|_execute_kerberos_preauth_failure_bundle|uniform
1|activity/generator.py|_execute_logoff_bundle|uniform
1|activity/generator.py|_execute_machine_account_logon_bundle|uniform
1|activity/generator.py|_execute_nmap_command_probe_bundle|uniform
1|activity/generator.py|_execute_process_create_bundle|uniform
1|activity/generator.py|_execute_process_termination_bundle|uniform
2|activity/generator.py|_external_sender_received_headers|uniform
1|activity/generator.py|_factory|uniform
1|activity/generator.py|_generate_bounded_foreground_process_termination|uniform
1|activity/generator.py|_held_process_termination_time|uniform
4|activity/generator.py|_jitter_default_connection_duration|uniform
1|activity/generator.py|_maybe_generate_email_recipient_reads|uniform
1|activity/generator.py|_nmap_concurrent_probe_offsets|betavariate
1|activity/generator.py|_nmap_concurrent_probe_offsets|uniform
4|activity/generator.py|_nmap_probe_profile|uniform
1|activity/generator.py|_ntp_payload_accounting|uniform
4|activity/generator.py|_postfix_delays|uniform
1|activity/generator.py|_remember_system_connection_owner_finalizer|uniform
8|activity/generator.py|_schedule_bash_history_time|uniform
2|activity/generator.py|_smtp_transfer_sizes|uniform
1|activity/generator.py|_space_browser_launch|uniform
1|activity/generator.py|_space_interactive_shell_child_launch|uniform
2|activity/generator.py|_space_one_shot_cli_launch|uniform
1|activity/generator.py|_tcp_ip_byte_count|uniform
1|activity/generator.py|ensure_smb_client_process|uniform
6|activity/generator.py|execute_baseline_activity|uniform
1|activity/generator.py|generate_adversarial_payload|uniform
5|activity/generator.py|generate_bash_command_with_noise|uniform
1|activity/host_activity_profiles.py|pick_firewall_deny_offset|gauss
2|activity/host_activity_profiles.py|pick_firewall_deny_offset|uniform
1|activity/host_activity_profiles.py|resolve_host_activity_profile|uniform
3|activity/http_content.py|apply_transfer_size_variance|uniform
2|activity/pack_traffic.py|_burst_times|uniform
1|activity/pack_traffic.py|_periodic_times|uniform
1|activity/pack_traffic.py|_weighted_times|gauss
1|activity/pack_traffic.py|_weighted_times|uniform
6|emitters/windows_record_ids.py|_host_background_rate|uniform
1|emitters/windows_record_ids.py|_sample_poisson|gauss
1|engine/baseline.py|_activity_time_outside_locked_session|uniform
2|engine/baseline.py|_affinity_range_sample|uniform
1|engine/baseline.py|_align_rsat_with_future_workstation_session|uniform
1|engine/baseline.py|_anonymous_smb_event_offsets|uniform
4|engine/baseline.py|_baseline_inbound_ids_probe_profile|uniform
1|engine/baseline.py|_bounded_lognormal_seconds|lognormvariate
1|engine/baseline.py|_bounded_lognormal_seconds|uniform
1|engine/baseline.py|_burst_offset|gauss
1|engine/baseline.py|_burst_offset|uniform
1|engine/baseline.py|_calculate_events_for_hour|gauss
1|engine/baseline.py|_distribute_events_in_hour|uniform
1|engine/baseline.py|_distribute_events_in_hour_uniform|uniform
4|engine/baseline.py|_emit_anacron_lifecycle|uniform
1|engine/baseline.py|_emit_browsing_session|uniform
1|engine/baseline.py|_emit_conn|gauss
1|engine/baseline.py|_emit_conn|uniform
1|engine/baseline.py|_emit_ecar_file_churn|uniform
6|engine/baseline.py|_emit_scheduled_event|uniform
2|engine/baseline.py|_emit_web_server_access|uniform
2|engine/baseline.py|_ensure_service_account_delegation_process|uniform
1|engine/baseline.py|_execute_scheduled_scan_overlap_bundle|uniform
1|engine/baseline.py|_extra_syslog_effective_limit|lognormvariate
1|engine/baseline.py|_generate_baseline_email|uniform
3|engine/baseline.py|_generate_baseline_failed_logons|uniform
1|engine/baseline.py|_generate_inbound_traffic_affinity|uniform
1|engine/baseline.py|_generate_inline_windows_baseline_smb_activity|gauss
4|engine/baseline.py|_generate_inline_windows_baseline_smb_activity|uniform
4|engine/baseline.py|_generate_lateral_movement_noise|uniform
1|engine/baseline.py|_generate_pack_persona_traffic|uniform
3|engine/baseline.py|_generate_profile_traffic|uniform
5|engine/baseline.py|_generate_rsat_sessions|uniform
2|engine/baseline.py|_generate_scheduled_tasks|uniform
3|engine/baseline.py|_generate_stale_account_noise|uniform
3|engine/baseline.py|_generate_suspicious_noise|uniform
6|engine/baseline.py|_generate_system_traffic|gauss
23|engine/baseline.py|_generate_system_traffic|uniform
1|engine/baseline.py|_generate_user_traffic_affinity|uniform
1|engine/baseline.py|_gpo_refresh_interval_seconds|uniform
4|engine/baseline.py|_journald_housekeeping_schedule|uniform
9|engine/baseline.py|_linux_sudo_command_runtime|uniform
2|engine/baseline.py|_machine_account_ntlm_offset_seconds|uniform
1|engine/baseline.py|_ntp_observed_second|uniform
3|engine/baseline.py|_ntp_sync_interval_seconds|uniform
1|engine/baseline.py|_ntp_sync_seconds_for_hour|uniform
2|engine/baseline.py|_pace_interactive_startup_activity|uniform
1|engine/baseline.py|_plan_baseline_smb_activity|gauss
4|engine/baseline.py|_plan_baseline_smb_activity|uniform
1|engine/baseline.py|_plan_logoffs_for_hour|uniform
1|engine/baseline.py|_polkit_process_start_ticks|lognormvariate
3|engine/baseline.py|_sample_lock_duration|triangular
1|engine/baseline.py|_schedule_foreground_process_termination|uniform
3|engine/baseline.py|_service_account_delegation_time_for_hour|uniform
2|engine/baseline.py|_terminate_stale_processes|uniform
1|engine/baseline.py|_windows_background_process_lifetime_seconds|uniform
1|engine/baseline.py|_windows_scheduled_task_offsets|uniform
6|engine/core.py|_initialize|gauss
1|engine/core.py|_initialize|uniform
2|engine/emitter_setup.py|_advance_boot_clock|uniform
1|engine/emitter_setup.py|_emit_dhcp_leases|uniform
1|engine/emitter_setup.py|_emit_sensor_startup|uniform
2|engine/emitter_setup.py|process_time|uniform
1|engine/storyline.py|_apply_storyline_shell_availability|uniform
1|engine/storyline.py|_effective_rate_interval|uniform
4|engine/storyline.py|_emit_linux_storyline_shell_friction|uniform
1|engine/storyline.py|_ensure_storyline_upload_process_for_exfil|uniform
3|engine/storyline.py|_execute_port_scan_bundle|uniform
1|engine/storyline.py|_execute_single_red_herring_event|uniform
1|engine/storyline.py|_execute_single_storyline_event|uniform
1|engine/storyline.py|_execute_storyline|uniform
1|engine/storyline.py|_execute_typed_event|triangular
18|engine/storyline.py|_execute_typed_event|uniform
3|engine/storyline.py|_execute_web_scan_bundle|uniform
1|engine/storyline.py|_iter_dns_tunnel_ticks|expovariate
2|engine/storyline.py|_iter_dns_tunnel_ticks|uniform
1|engine/storyline.py|_iter_periodic_ticks|uniform
4|engine/storyline.py|_port_scan_connection_profile|uniform
1|engine/storyline.py|_resolve_storyline_process_spill_logon_id|uniform
2|engine/storyline.py|_storyline_event_offsets|uniform
1|engine/storyline.py|_web_scan_connection_profile|lognormvariate
5|engine/storyline.py|_web_scan_connection_profile|uniform
1|network_observation.py|_lose_direction|uniform
1|state_manager.py|_allocate_linux_pid|lognormvariate
1|state_manager.py|_allocate_windows_pid|lognormvariate
1|state_manager.py|_preview_linux_pid|lognormvariate
1|state_manager.py|_preview_windows_pid|lognormvariate
3|storage_world.py|_file_size|uniform
1|world_model.py|_align_rdp_source_after_future_workstation_session|uniform
2|world_model.py|_bootstrap_ssh_session|uniform
3|world_model.py|bootstrap_user_session|uniform
4|world_model.py|ensure_connection_process|uniform
""".strip()

_MIGRATED_LEGACY_CALLS = Counter(
    {
        ("actions/ssh_session.py", "_mark_edr_login_readiness", "sample_timing_delta"): 1,
        ("activity/generator.py", "_execute_logon_bundle", "sample_timing_delta"): 1,
        ("activity/generator.py", "_execute_logoff_bundle", "sample_timing_delta"): 5,
        (
            "activity/generator.py",
            "_clamp_after_visible_linux_process_create",
            "sample_timing_delta",
        ): 1,
        (
            "activity/generator.py",
            "_nmap_probe_anchor_after_visible_process_create",
            "sample_timing_delta",
        ): 1,
    }
)

_DIRECT_CONTINUOUS_METHODS = _RAW_TEMPORAL_METHODS - {"randint", "randrange"}


def _enclosing_function(
    node: ast.AST,
    parents: dict[ast.AST, ast.AST],
) -> str:
    """Return the nearest function that owns an AST node."""

    ancestor: ast.AST | None = node
    while ancestor is not None and not isinstance(
        ancestor,
        (ast.FunctionDef, ast.AsyncFunctionDef),
    ):
        ancestor = parents.get(ancestor)
    if isinstance(ancestor, (ast.FunctionDef, ast.AsyncFunctionDef)):
        return ancestor.name
    return ""


def _generation_call_inventory(names: frozenset[str] | set[str]) -> Counter[tuple[str, str, str]]:
    """Count named production calls by exact file/function/call selector."""

    generation_root = Path(generation_package.__file__).parent
    observed: Counter[tuple[str, str, str]] = Counter()
    for path in sorted(generation_root.rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        parents = {
            child: parent for parent in ast.walk(tree) for child in ast.iter_child_nodes(parent)
        }
        relative = path.relative_to(generation_root).as_posix()
        for call in (node for node in ast.walk(tree) if isinstance(node, ast.Call)):
            called = ""
            if isinstance(call.func, ast.Name):
                called = call.func.id
            elif isinstance(call.func, ast.Attribute):
                called = call.func.attr
            if called in names:
                observed[(relative, _enclosing_function(call, parents), called)] += 1
    return observed


def _direct_continuous_rng_caps() -> Counter[tuple[str, str, str]]:
    """Parse the compact, reviewable integration-head selector ceilings."""

    caps: Counter[tuple[str, str, str]] = Counter()
    for line in _DIRECT_CONTINUOUS_RNG_CAPS_TEXT.splitlines():
        count, path, function, method = line.split("|")
        selector = (path, function, method)
        assert selector not in caps
        caps[selector] = int(count)
    return caps


def test_generation_has_no_remaining_legacy_timing_helper_calls() -> None:
    """All nine compatibility callers stay migrated; helper definitions may remain."""

    assert sum(_MIGRATED_LEGACY_CALLS.values()) == 9
    assert _generation_call_inventory(_LEGACY_HELPERS) == Counter()


def test_direct_continuous_rng_inventory_can_only_shrink() -> None:
    """The exact 359-call compatibility census cannot gain selectors or calls."""

    caps = _direct_continuous_rng_caps()
    observed = _generation_call_inventory(_DIRECT_CONTINUOUS_METHODS)

    assert len(caps) == 164
    assert sum(caps.values()) == 359
    assert not observed - caps
    assert len(observed) <= len(caps)
    assert sum(observed.values()) <= sum(caps.values())


def test_smb_composite_has_no_legacy_temporal_sampler_bypass() -> None:
    """The migrated composite relationship must use the injected runtime only."""

    smb_path = Path(generation_package.__file__).parent / "actions" / "smb_activity.py"
    tree = ast.parse(smb_path.read_text(encoding="utf-8"), filename=str(smb_path))
    imported_legacy_helpers = {
        alias.name
        for node in ast.walk(tree)
        if isinstance(node, ast.ImportFrom)
        for alias in node.names
        if alias.name in _LEGACY_HELPERS
    }
    composite = next(
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.FunctionDef) and node.name == "_execute_composite_transfer"
    )
    offenders: list[tuple[int, str]] = []
    for call in (node for node in ast.walk(composite) if isinstance(node, ast.Call)):
        called = ""
        if isinstance(call.func, ast.Name):
            called = call.func.id
        elif isinstance(call.func, ast.Attribute):
            called = call.func.attr
        if called in _LEGACY_HELPERS or called in _RAW_TEMPORAL_METHODS or called == "_stable_seed":
            offenders.append((call.lineno, called))

    assert imported_legacy_helpers == set()
    assert offenders == []
