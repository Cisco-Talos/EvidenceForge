# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Focused terminal-pass admission tests for Linux baseline lifecycle families."""

from __future__ import annotations

import ast
import json
import random
from collections import Counter
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

import evidenceforge.generation.activity.extra_syslog as extra_syslog_module
import evidenceforge.generation.activity.windows_auth_realism as windows_auth_realism_module
import evidenceforge.generation.engine.baseline as baseline_module
import evidenceforge.utils.timing as timing_module
from evidenceforge.events.dispatcher import EventDispatcher
from evidenceforge.events.lifecycle import SessionEndPlan
from evidenceforge.formats.loader import load_format
from evidenceforge.generation.activity import ActivityGenerator
from evidenceforge.generation.emitters.cisco_asa import CiscoAsaEmitter
from evidenceforge.generation.emitters.ecar import EcarEmitter
from evidenceforge.generation.emitters.zeek import ZeekEmitter
from evidenceforge.generation.engine.baseline import BaselineMixin
from evidenceforge.generation.network_visibility import NetworkVisibilityEngine
from evidenceforge.generation.source_timing import SourceTimingPlanner
from evidenceforge.generation.state_manager import StateManager
from evidenceforge.generation.timing import TimingRuntime
from evidenceforge.generation.world_model import SessionPlan, WorldPlanner
from evidenceforge.models import System, User
from evidenceforge.models.scenario import NetworkConfig, NetworkSegment, NetworkSensor

_WINDOW_START = datetime(2024, 3, 18, 10, tzinfo=UTC)


def _minimal_linux_system_traffic(
    end_time: datetime,
) -> tuple[BaselineMixin, Mock, StateManager, System]:
    """Return one real Linux system-traffic pass with unrelated families disabled."""

    system = System(
        hostname="LINUX-01",
        ip="10.0.0.20",
        os="Ubuntu 24.04",
        type="server",
        roles=[],
        services=[],
    )
    activity = Mock()
    activity.timing_runtime = object()
    activity._ip_to_system = {}
    activity._dns_server_ips = []
    activity._rdp_session_lifecycle_frontier.return_value = None
    state_manager = StateManager()

    baseline = BaselineMixin()
    baseline.start_time = _WINDOW_START
    baseline.end_time = end_time
    baseline._scenario_tz = None
    baseline._infra_ips = {"dns": [], "ntp": [], "dc": [], "dc_hostnames": []}
    baseline._system_service_defaults = {system.hostname: []}
    baseline._system_pids = {system.hostname: {"logind": 555}}
    baseline._generation_epoch = _WINDOW_START
    baseline._kernel_boot_uptimes = {system.hostname: 500000.0}
    baseline._dhcp_lease_state = {}
    baseline.generation_seed = 7
    baseline.state_manager = state_manager
    baseline.activity_generator = activity
    baseline.scenario = SimpleNamespace(
        time_window=SimpleNamespace(start=_WINDOW_START),
        environment=SimpleNamespace(
            systems=[system],
            users=[],
            service_accounts=[],
            domain="example.test",
            network=None,
        ),
    )
    baseline._uses_linux_smb_prepass = lambda: False
    baseline._generate_profile_traffic = lambda *_args, **_kwargs: None
    baseline._get_baseline_ssh_users = lambda _system: []
    baseline._authored_rdp_transport_lower_bound = lambda _hour: None
    baseline._execute_baseline_rdp_requests = lambda *_args, **_kwargs: None
    baseline._generate_rsat_sessions = lambda *_args, **_kwargs: None
    baseline._generate_scheduled_tasks = lambda *_args, **_kwargs: None
    baseline._emit_journald_housekeeping = lambda *_args, **_kwargs: None
    baseline._emit_anacron_lifecycle = lambda *_args, **_kwargs: None
    baseline._scaled_randint = lambda *_args, **_kwargs: 1
    return baseline, activity, state_manager, system


def test_terminal_network_admission_census_has_no_unreviewed_canonical_only_owner() -> None:
    """Inventory every literal sink and its reviewed rendered-close owner."""

    tree = ast.parse(Path(baseline_module.__file__).read_text(encoding="utf-8"))
    parents = {child: parent for parent in ast.walk(tree) for child in ast.iter_child_nodes(parent)}

    def _calls(attribute_name: str) -> list[tuple[str, ast.Call]]:
        result: list[tuple[str, ast.Call]] = []
        for node in ast.walk(tree):
            if not (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute)
                and node.func.attr == attribute_name
            ):
                continue
            parent = parents.get(node)
            while parent is not None and not isinstance(
                parent,
                (ast.FunctionDef, ast.AsyncFunctionDef),
            ):
                parent = parents.get(parent)
            assert isinstance(parent, (ast.FunctionDef, ast.AsyncFunctionDef))
            result.append((parent.name, node))
        return result

    def _named_calls(function_name: str) -> list[tuple[str, ast.Call]]:
        result: list[tuple[str, ast.Call]] = []
        for node in ast.walk(tree):
            if not (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Name)
                and node.func.id == function_name
            ):
                continue
            parent = parents.get(node)
            while parent is not None and not isinstance(
                parent,
                (ast.FunctionDef, ast.AsyncFunctionDef),
            ):
                parent = parents.get(parent)
            assert isinstance(parent, (ast.FunctionDef, ast.AsyncFunctionDef))
            result.append((parent.name, node))
        return result

    literal_sinks = _calls("generate_connection")
    assert len(literal_sinks) == 27
    assert Counter(owner for owner, _call in literal_sinks) == Counter(
        {
            "_emit_affinity_event": 1,
            "_emit_browsing_session": 1,
            "_emit_conn": 1,
            "_emit_web_server_access": 1,
            "_execute_scheduled_scan_overlap_bundle": 1,
            "_generate_baseline_smb_activity": 1,
            "_generate_firewall_deny_baseline": 1,
            "_generate_inline_windows_baseline_smb_activity": 1,
            "_generate_lateral_movement_noise": 2,
            "_generate_pack_persona_traffic": 1,
            "_generate_profile_traffic": 4,
            "_generate_rsat_sessions": 1,
            "_generate_suspicious_noise": 2,
            "_generate_system_traffic": 9,
        }
    )
    # Each tuple classifies literal sinks in source order. A new or moved raw
    # connection must be deliberately assigned an admission owner here.
    reviewed_sink_classes = {
        "_emit_affinity_event": ("direct-rendered",),
        "_emit_browsing_session": ("persona-browser-outer",),
        "_emit_conn": ("direct-rendered",),
        "_emit_web_server_access": ("direct-rendered",),
        "_execute_scheduled_scan_overlap_bundle": ("direct-rendered",),
        "_generate_baseline_smb_activity": ("shared-smb-outer",),
        "_generate_firewall_deny_baseline": ("direct-rendered",),
        "_generate_inline_windows_baseline_smb_activity": ("shared-smb-outer",),
        "_generate_lateral_movement_noise": (
            "direct-rendered-radius",
            "direct-rendered-syslog",
        ),
        "_generate_pack_persona_traffic": ("persona-selected-outer",),
        "_generate_profile_traffic": (
            "direct-rendered-role",
            "direct-rendered-inbound-deny",
            "direct-rendered-inbound-allowed",
            "persona-selected-outer",
        ),
        "_generate_rsat_sessions": ("rsat-family-outer",),
        "_generate_suspicious_noise": (
            "direct-rendered-dns",
            "direct-rendered-outbound",
        ),
        "_generate_system_traffic": (
            "direct-rendered-dns",
            "direct-rendered-ntp",
            "direct-rendered-kerberos",
            "direct-rendered-ldap",
            "direct-rendered-dc-kerberos",
            "direct-rendered-dc-tgs",
            "direct-rendered-ufw",
            "direct-rendered-icmp",
            "ids-selected-outer",
        ),
    }
    sinks_by_owner: dict[str, list[ast.Call]] = {}
    for owner, call in literal_sinks:
        sinks_by_owner.setdefault(owner, []).append(call)
    assert set(sinks_by_owner) == set(reviewed_sink_classes)
    for owner, calls in sinks_by_owner.items():
        assert len(calls) == len(reviewed_sink_classes[owner])

    canonical_calls = _calls("_baseline_network_close_bound_seconds")
    assert Counter(owner for owner, _call in canonical_calls) == Counter(
        {
            "_baseline_user_activity_close_bound_seconds": 3,
            "_baseline_persona_connection_close_bounds_seconds": 2,
            "_baseline_ids_connection_close_bound_seconds": 1,
            "_emit_affinity_event": 3,
            "_emit_conn": 1,
            "_emit_web_server_access": 2,
            "_execute_scheduled_scan_overlap_bundle": 1,
            "_generate_baseline_smb_activity": 1,
            "_generate_firewall_deny_baseline": 1,
            "_generate_inline_windows_baseline_smb_activity": 1,
            "_generate_lateral_movement_noise": 2,
            "_generate_profile_traffic": 2,
            "_generate_rsat_sessions": 1,
            "_generate_suspicious_noise": 2,
            "_generate_system_traffic": 8,
        }
    )
    canonical_only_calls = Counter()
    for owner, call in canonical_calls:
        keyword_names = {keyword.arg for keyword in call.keywords}
        if not {"current_hour", "start"} <= keyword_names:
            canonical_only_calls[owner] += 1
    assert canonical_only_calls == Counter(
        {
            "_baseline_ids_connection_close_bound_seconds": 1,
            "_emit_affinity_event": 3,
        }
    )
    assert Counter(
        owner for owner, _call in _calls("_baseline_rendered_network_close_bound_seconds")
    ) == Counter(
        {
            "_baseline_network_close_bound_seconds": 1,
            "_baseline_user_activity_close_bound_seconds": 1,
            "_baseline_ids_connection_close_bound_seconds": 1,
            "_emit_affinity_event": 1,
        }
    )
    assert Counter(
        owner for owner, _call in _calls("_baseline_ids_connection_close_bound_seconds")
    ) == Counter({"_generate_system_traffic": 1})
    assert Counter(
        owner for owner, _call in _calls("_baseline_persona_connection_close_bounds_seconds")
    ) == Counter(
        {
            "_generate_profile_traffic": 2,
            "_generate_pack_persona_traffic": 2,
        }
    )
    assert Counter(
        owner for owner, _call in _calls("_baseline_dhcp_renewal_close_bound_seconds")
    ) == Counter({"_generate_system_traffic": 1})
    assert Counter(owner for owner, _call in _calls("generate_smb_activity")) == Counter(
        {
            "_generate_baseline_smb_activity": 1,
            "_generate_inline_windows_baseline_smb_activity": 1,
        }
    )
    assert Counter(owner for owner, _call in _calls("generate_dhcp_lease")) == Counter(
        {"_generate_system_traffic": 1}
    )
    assert Counter(owner for owner, _call in _named_calls("BrowserSessionActionBundle")) == Counter(
        {
            "_emit_affinity_event": 1,
            "_emit_browsing_session": 1,
            "_emit_web_server_access": 1,
        }
    )


def test_terminal_optional_service_bounds_retain_embryonic_transport_branch() -> None:
    """Optional-service callers do not claim payload before runtime selects state."""

    tree = ast.parse(Path(baseline_module.__file__).read_text(encoding="utf-8"))
    parents = {child: parent for parent in ast.walk(tree) for child in ast.iter_child_nodes(parent)}
    fact_shapes: dict[str, list[tuple[str, str]]] = {}
    for node in ast.walk(tree):
        if not (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "_baseline_network_close_bound_seconds"
        ):
            continue
        parent = parents.get(node)
        while parent is not None and not isinstance(parent, ast.FunctionDef):
            parent = parents.get(parent)
        if not isinstance(parent, ast.FunctionDef) or parent.name not in {
            "_emit_conn",
            "_generate_profile_traffic",
        }:
            continue
        keywords = {keyword.arg: keyword.value for keyword in node.keywords}
        fact_shapes.setdefault(parent.name, []).append(
            (
                ast.unparse(keywords["conn_state"]),
                ast.unparse(keywords["payload_bytes"]),
            )
        )

    assert fact_shapes["_emit_conn"] == [
        ("''", "1 if service is not None else None"),
    ]
    assert fact_shapes["_generate_profile_traffic"] == [
        ("''", "1 if conn_service is not None else None"),
        ("planned_conn_state", "planned_payload_bytes"),
    ]

    baseline = BaselineMixin()
    baseline.start_time = _WINDOW_START
    baseline.end_time = _WINDOW_START + timedelta(minutes=10)
    baseline._baseline_network_close_bound_seconds = Mock(return_value=10.0)
    baseline._baseline_persona_connection_close_bounds_seconds(
        _WINDOW_START,
        start=_WINDOW_START + timedelta(minutes=1),
        src_ip="10.0.0.10",
        dst_ip="10.0.0.20",
        proto="tcp",
        dst_port=8443,
        service=None,
        is_browser_connection=False,
    )
    call = baseline._baseline_network_close_bound_seconds.call_args
    assert call.kwargs["conn_state"] == ""
    assert call.kwargs["payload_bytes"] is None


def test_terminal_affinity_s0_renders_zeek_and_firewall_rows_before_half_open_end(
    tmp_path: Path,
) -> None:
    """Rendered sensor/ASA closure, not only canonical S0 duration, gates admission."""

    pass_end = _WINDOW_START + timedelta(minutes=10)
    source = System(
        hostname="WS-01",
        ip="10.0.0.10",
        os="Windows 11",
        type="workstation",
    )
    target = System(
        hostname="SRV-01",
        ip="10.0.0.20",
        os="Ubuntu 24.04",
        type="server",
    )
    network = NetworkConfig(
        segments=[
            NetworkSegment(
                name="workstations",
                cidr="10.0.0.0/28",
                exposure="internal",
            ),
            NetworkSegment(
                name="servers",
                cidr="10.0.0.16/28",
                exposure="internal",
            ),
        ],
        sensors=[
            NetworkSensor(
                type="firewall",
                name="fw01",
                hostname="fw01",
                monitoring_segments=["workstations", "servers"],
                log_formats=["cisco_asa"],
                interfaces={
                    "workstations": "inside",
                    "servers": "dmz",
                    "_default": "outside",
                },
            ),
            NetworkSensor(
                type="network",
                name="zeek01",
                hostname="zeek01",
                monitoring_segments=["workstations", "servers"],
                log_formats=["zeek"],
            ),
        ],
    )
    visibility = NetworkVisibilityEngine(network_config=network, systems=[source, target])
    zeek_root = tmp_path / "zeek"
    asa_root = tmp_path / "asa"
    zeek = ZeekEmitter(
        load_format("zeek_conn"),
        zeek_root,
        threaded=False,
        sensor_hostnames=["zeek01"],
    )
    asa = CiscoAsaEmitter(
        load_format("cisco_asa"),
        asa_root,
        threaded=False,
        sensor_hostnames=["fw01"],
    )
    asa._segment_config = [
        {"name": "workstations", "cidr": "10.0.0.0/28"},
        {"name": "servers", "cidr": "10.0.0.16/28"},
    ]
    asa._sensor_interfaces = {
        "fw01": {
            "workstations": "inside",
            "servers": "dmz",
            "_default": "outside",
        }
    }
    state_manager = StateManager()
    state_manager.set_current_time(_WINDOW_START)
    timing_runtime = TimingRuntime(
        reference_time=_WINDOW_START,
        namespace="terminal-affinity-s0-rendered-close",
    )
    emitters = {"zeek_conn": zeek, "cisco_asa": asa}
    dispatcher = EventDispatcher(
        state_manager,
        emitters,
        visibility_engine=visibility,
        output_start_time=_WINDOW_START,
        output_end_time=pass_end,
        timing_runtime=timing_runtime,
    )
    activity = ActivityGenerator(
        state_manager,
        emitters,
        dispatcher=dispatcher,
        timing_runtime=timing_runtime,
        generation_window_start=_WINDOW_START,
        generation_window_end=pass_end,
    )
    activity._ip_to_system = {source.ip: source, target.ip: target}
    activity._all_system_ips = [source.ip, target.ip]
    baseline = BaselineMixin()
    baseline.start_time = _WINDOW_START
    baseline.end_time = pass_end
    baseline.state_manager = state_manager
    baseline.activity_generator = activity
    baseline.dispatcher = dispatcher
    baseline._resolve_affinity_endpoint = lambda *_args, **_kwargs: {
        "ip": target.ip,
        "host": target.hostname,
        "tags": [],
    }
    affinity = SimpleNamespace(
        kind="connection",
        connection_profile=SimpleNamespace(
            durations=(7.0, 7.0),
            # The network planner zeroes authored payload for S0. Admission
            # must therefore reserve the embryonic firewall tail even when the
            # profile authored positive byte minima.
            orig_bytes=(200, 200),
            resp_bytes=(500, 500),
            conn_states={"S0": 1.0},
        ),
    )
    endpoint = SimpleNamespace(port=8443, proto="tcp", service="")

    non_embryonic_bound = baseline._baseline_network_close_bound_seconds(
        src_ip=source.ip,
        dst_ip=target.ip,
        proto="tcp",
        dst_port=8443,
        service="",
        requested_duration_max=7.0,
        current_hour=_WINDOW_START,
        start=pass_end,
        conn_state="SF",
        payload_bytes=1,
    )
    non_embryonic_only_start = pass_end - timedelta(seconds=non_embryonic_bound)
    baseline._emit_affinity_event(
        affinity=affinity,
        endpoint=endpoint,
        current_hour=_WINDOW_START,
        src_ip=source.ip,
        source_system=source,
        user_obj=None,
        session=None,
        event_time=non_embryonic_only_start,
        rng=random.Random(7),
        target_system=target,
    )

    assert state_manager.list_open_connections() == []
    assert not tuple(zeek_root.rglob("conn.json"))
    assert not tuple(asa_root.rglob("cisco_asa.log"))

    rendered_close_bound = baseline._baseline_network_close_bound_seconds(
        src_ip=source.ip,
        dst_ip=target.ip,
        proto="tcp",
        dst_port=8443,
        service="",
        requested_duration_max=7.0,
        current_hour=_WINDOW_START,
        start=pass_end,
        conn_state="",
        payload_bytes=None,
    )
    safe_start = pass_end - timedelta(seconds=rendered_close_bound, microseconds=1)
    baseline._emit_affinity_event(
        affinity=affinity,
        endpoint=endpoint,
        current_hour=_WINDOW_START,
        src_ip=source.ip,
        source_system=source,
        user_obj=None,
        session=None,
        event_time=safe_start,
        rng=random.Random(7),
        target_system=target,
    )
    observations = dispatcher._latest_network_observations
    assert observations
    rendered_times = [
        timestamp for observation in observations for _key, timestamp in observation.source_times
    ]
    rendered_times.extend(
        observation.firewall_teardown_time
        for observation in observations
        if observation.firewall_teardown_time is not None
    )

    zeek.close()
    asa.close()

    assert rendered_times
    assert max(rendered_times) < pass_end
    zeek_rows = [
        json.loads(line)
        for output in zeek_root.rglob("conn.json")
        for line in output.read_text(encoding="utf-8").splitlines()
    ]
    asa_lines = [
        line
        for output in asa_root.rglob("cisco_asa.log")
        for line in output.read_text(encoding="utf-8").splitlines()
    ]
    affinity_rows = [row for row in zeek_rows if row["id.resp_p"] == 8443]
    assert len(affinity_rows) == 1
    assert affinity_rows[0]["conn_state"] == "S0"
    assert (
        max(float(row["ts"]) + float(row.get("duration") or 0.0) for row in zeek_rows)
        < pass_end.timestamp()
    )
    assert any("Teardown TCP connection" in line for line in asa_lines)
    asa_times = [
        datetime.strptime(line[5:20], "%b %d %H:%M:%S").replace(
            year=pass_end.year,
            tzinfo=UTC,
        )
        for line in asa_lines
    ]
    assert asa_times
    assert max(asa_times) < pass_end


def test_terminal_rendered_network_bound_includes_transport_open_support(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The exact open-jitter frontier rejects; one microsecond inside is safe."""

    pass_end = _WINDOW_START + timedelta(minutes=10)
    baseline = BaselineMixin()
    baseline.start_time = _WINDOW_START
    baseline.end_time = pass_end
    monkeypatch.setattr(
        baseline_module,
        "get_timing_window",
        lambda *_args, **_kwargs: SimpleNamespace(max_ms=850),
    )

    bound = baseline._baseline_rendered_network_close_bound_seconds(
        _WINDOW_START,
        start=pass_end,
        src_ip="10.0.0.10",
        dst_ip="10.0.0.20",
        proto="tcp",
        conn_state="SF",
        payload_bytes=1,
        canonical_close_bound_seconds=7.0,
    )

    exact_frontier_start = pass_end - timedelta(seconds=7.850997)
    assert bound == pytest.approx(7.850998)
    assert not baseline._baseline_pass_admits(
        _WINDOW_START,
        start=exact_frontier_start,
        end=exact_frontier_start + timedelta(seconds=bound),
    )
    safe_start = exact_frontier_start - timedelta(microseconds=1)
    assert baseline._baseline_pass_admits(
        _WINDOW_START,
        start=safe_start,
        end=safe_start + timedelta(seconds=bound),
    )


def test_terminal_dhcp_bound_includes_sensor_syslog_and_endpoint_projection() -> None:
    """DHCP renewal admission covers both the UDP close and final dhclient row."""

    pass_end = _WINDOW_START + timedelta(minutes=10)
    system = System(
        hostname="LNX-01",
        ip="10.0.0.20",
        os="Ubuntu 24.04",
        type="server",
    )
    source_planner = Mock(spec=SourceTimingPlanner)
    source_planner.endpoint_clock_positive_headroom.return_value = timedelta(seconds=7)
    sensor_headroom = Mock(return_value=timedelta(seconds=2))
    observation_policy = SimpleNamespace(
        delay_bounds=Mock(return_value=(timedelta(0), timedelta(seconds=9)))
    )
    baseline = BaselineMixin()
    baseline.start_time = _WINDOW_START
    baseline.end_time = pass_end
    baseline.source_timing_planner = source_planner
    baseline.dispatcher = SimpleNamespace(
        observation_policy=observation_policy,
        network_observation_planner=SimpleNamespace(
            network_sensor_close_positive_headroom=sensor_headroom,
        ),
    )
    start = pass_end - timedelta(seconds=30)

    bound = baseline._baseline_dhcp_renewal_close_bound_seconds(
        _WINDOW_START,
        start=start,
        system=system,
        server_addr="10.0.0.1",
    )

    assert bound == pytest.approx(19.000001)
    sensor_headroom.assert_called_once_with(
        start + timedelta(seconds=0.5),
        src_ip=system.ip,
        dst_ip="10.0.0.1",
        protocol="udp",
        conn_state="SF",
        payload_bytes=1,
    )
    source_planner.endpoint_clock_positive_headroom.assert_called_once_with(
        start + timedelta(seconds=3),
        "linux",
    )
    observation_policy.delay_bounds.assert_called_once_with("syslog")


def test_terminal_scheduled_scan_rejects_rendered_tail_before_state_mutation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A scan child that cannot render completely never advances State."""

    pass_end = _WINDOW_START + timedelta(minutes=10)
    scanner = System(
        hostname="SCAN-01",
        ip="10.0.0.10",
        os="Ubuntu 24.04",
        type="server",
    )
    target = System(
        hostname="SRV-01",
        ip="10.0.0.20",
        os="Windows Server 2022",
        type="server",
    )
    rng = Mock()
    rng.randint.return_value = 2
    rng.sample.return_value = [22]
    rng.uniform.return_value = 0.0
    state_manager = SimpleNamespace(set_current_time=Mock())
    activity = SimpleNamespace(generate_connection=Mock())
    baseline = BaselineMixin()
    baseline.start_time = _WINDOW_START
    baseline.end_time = pass_end
    baseline.state_manager = state_manager
    baseline.activity_generator = activity
    baseline._baseline_network_close_bound_seconds = Mock(return_value=2.0)
    monkeypatch.setattr(
        baseline_module,
        "_nmap_probe_profile",
        lambda *_args: ("S0", "ssh", 0.1, 0, 0),
    )
    request = baseline_module.ScheduledScanOverlapRequest(
        scanner=scanner,
        targets=(target,),
        time=pass_end - timedelta(seconds=1),
        rng=rng,
    )

    baseline._execute_scheduled_scan_overlap_bundle(request)

    state_manager.set_current_time.assert_not_called()
    activity.generate_connection.assert_not_called()


@pytest.mark.parametrize(
    ("offset_seconds", "expected_calls"),
    [(597.0, 1), (597.5, 0)],
)
def test_terminal_sudo_admission_includes_intrinsic_process_close_tail(
    monkeypatch: pytest.MonkeyPatch,
    offset_seconds: float,
    expected_calls: int,
) -> None:
    """The terminal pass owns the PAM close and parent termination after runtime."""

    end_time = _WINDOW_START + timedelta(minutes=10)
    baseline, activity, _state_manager, _system = _minimal_linux_system_traffic(end_time)
    entry = {
        "app": "sudo",
        "weight": 1,
        "messages": [
            "admin : TTY=pts/1 ; PWD=/srv ; USER=root ; COMMAND=/usr/bin/id",
        ],
    }
    monkeypatch.setattr(baseline_module, "_get_rng", lambda: random.Random(0))
    monkeypatch.setattr(
        baseline_module,
        "_linux_ambient_logind_session_budget",
        lambda *_args: 0,
    )
    monkeypatch.setattr(
        baseline_module,
        "_linux_sudo_command_runtime",
        lambda *_args: timedelta(seconds=2),
    )
    monkeypatch.setattr(
        timing_module,
        "hawkes_timestamps",
        lambda **_kwargs: ([offset_seconds], None),
    )
    monkeypatch.setattr(extra_syslog_module, "load_extra_syslog_messages", lambda: [entry])
    monkeypatch.setattr(
        extra_syslog_module,
        "filter_syslog_message_entries",
        lambda programs, *_args: programs,
    )

    baseline._generate_system_traffic(_WINDOW_START)

    assert activity.generate_linux_sudo_session.call_count == expected_calls
    if expected_calls:
        call = activity.generate_linux_sudo_session.call_args
        assert call.kwargs["time"] == end_time - timedelta(seconds=3)
        assert call.kwargs["runtime"] == timedelta(seconds=2)
        assert call.kwargs["latest_end"] == end_time


@pytest.mark.parametrize(
    ("end_delta", "event_offset_seconds", "expected_count"),
    [
        (timedelta(minutes=10), 570.0, 2),
        (timedelta(minutes=30), 60.0, 4),
    ],
)
def test_terminal_ambient_logind_right_censors_only_future_close(
    monkeypatch: pytest.MonkeyPatch,
    end_delta: timedelta,
    event_offset_seconds: float,
    expected_count: int,
) -> None:
    """Source-local logind opens survive when only their optional close is out of range."""

    end_time = _WINDOW_START + end_delta
    baseline, activity, state_manager, system = _minimal_linux_system_traffic(end_time)
    monkeypatch.setattr(baseline_module, "_get_rng", lambda: random.Random(13))
    monkeypatch.setattr(
        baseline_module,
        "_linux_ambient_logind_session_budget",
        lambda *_args: 1,
    )
    monkeypatch.setattr(
        timing_module,
        "hawkes_timestamps",
        lambda **_kwargs: ([event_offset_seconds], None),
    )

    baseline._generate_system_traffic(_WINDOW_START)

    calls = activity.generate_syslog_event.call_args_list
    messages = [call.kwargs["message"] for call in calls]
    assert len(calls) == expected_count
    assert "session opened" in messages[0]
    assert messages[1].startswith("New session ")
    assert all(_WINDOW_START <= call.kwargs["time"] < end_time for call in calls)
    if expected_count == 2:
        assert not any("session closed" in message for message in messages)
        assert not any(message.startswith("Removed session ") for message in messages)
    else:
        assert "session closed" in messages[2]
        assert messages[3].startswith("Removed session ")
    assert state_manager.get_sessions_on_system(system.hostname) == []


def test_sudo_owner_rejects_busy_shell_shift_before_publishing_family() -> None:
    """The exact owner deadline rejects serialization without a partial sudo family."""

    start = datetime(2024, 3, 18, 13, tzinfo=UTC)
    latest_end = start + timedelta(minutes=1)
    state_manager = StateManager()
    state_manager.set_current_time(start - timedelta(minutes=5))
    ecar = Mock()
    ecar.can_handle.return_value = True
    dispatcher = EventDispatcher(state_manager=state_manager, emitters={"ecar": ecar})
    generator = ActivityGenerator(state_manager, {"ecar": ecar}, dispatcher=dispatcher)
    generator._scenario_start_time = start - timedelta(hours=1)
    generator._scenario_end_time = latest_end
    user = User(
        username="analyst",
        full_name="Alicia Analyst",
        email="analyst@example.test",
    )
    system = System(
        hostname="LNX-01",
        ip="10.10.2.30",
        os="Ubuntu 22.04",
        type="server",
    )
    root_pid = state_manager.create_process(
        system.hostname,
        0,
        "/usr/sbin/sshd",
        "/usr/sbin/sshd",
        "root",
        "System",
    )
    logon_id = state_manager.create_session(
        username=user.username,
        system=system.hostname,
        logon_type=10,
        source_ip="10.10.1.20",
        start_time=start - timedelta(minutes=4),
        session_kind="ssh",
    )
    state_manager.set_current_time(start - timedelta(minutes=3))
    shell_pid = state_manager.create_process(
        system.hostname,
        root_pid,
        "/bin/bash",
        "-bash",
        user.username,
        "Medium",
        logon_id=logon_id,
    )
    session = state_manager.get_session(logon_id)
    assert session is not None
    session.session_shell_pid = shell_pid
    state_manager.update_session_metadata(logon_id, network_close_time=latest_end)
    busy_pid = generator.generate_process(
        user=user,
        system=system,
        time=start,
        logon_id=logon_id,
        process_name="/usr/bin/git",
        command_line="git status --short",
        parent_pid=shell_pid,
        suppress_command_file_effect=True,
    )
    generator._remember_process_connection_hold(
        system=system,
        pid=busy_pid,
        close_time=latest_end + timedelta(seconds=30),
    )
    serialized_start = generator.reserve_linux_foreground_process_start(
        system=system,
        username=user.username,
        logon_id=logon_id,
        parent_pid=shell_pid,
        requested_time=latest_end - timedelta(seconds=30),
        process_name="/usr/bin/sudo",
        command_line="sudo /usr/bin/id",
    )
    assert serialized_start > latest_end
    emitted_before = len(ecar.emit.call_args_list)
    process_ids_before = {
        process.pid for process in state_manager.get_processes_on_system(system.hostname)
    }

    generator.generate_linux_sudo_session(
        system=system,
        time=latest_end - timedelta(seconds=30),
        command_message=("analyst : TTY=pts/1 ; PWD=/srv ; USER=root ; COMMAND=/usr/bin/id"),
        sudo_user=user.username,
        uid=1000,
        runtime=timedelta(seconds=2),
        latest_end=latest_end,
    )

    assert len(ecar.emit.call_args_list) == emitted_before
    assert {
        process.pid for process in state_manager.get_processes_on_system(system.hostname)
    } == process_ids_before
    assert generator._linux_sudo_tty_assignments == {}
    assert generator._linux_sudo_tty_owners == {}
    assert generator._linux_sudo_tty_sessions == {}
    assert generator._linux_sudo_tty_available == {}
    assert generator._linux_sudo_tty_keys_by_logon_id == {}


def test_machine_account_admission_includes_logoff_projection_tail(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A tiny transport overlay cannot hide the paired logoff's visible close tail."""

    monkeypatch.setattr(
        windows_auth_realism_module,
        "remote_auth_transport_max_duration_seconds",
        lambda **_kwargs: 1.0,
    )

    assert windows_auth_realism_module.machine_account_authentication_close_bound_seconds() == 45.0

    baseline = BaselineMixin()
    baseline.start_time = _WINDOW_START
    baseline.end_time = _WINDOW_START + timedelta(minutes=10)
    boundary_start = baseline.end_time - timedelta(seconds=45)
    safe_start = boundary_start - timedelta(microseconds=1)

    assert baseline._baseline_machine_account_admits(_WINDOW_START, start=safe_start)
    assert not baseline._baseline_machine_account_admits(
        _WINDOW_START,
        start=boundary_start,
    )


def test_machine_account_admission_includes_runtime_endpoint_clock_headroom(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Baseline reserves the active clock profile's positive offset at the latest logoff."""

    monkeypatch.setattr(
        windows_auth_realism_module,
        "remote_auth_transport_max_duration_seconds",
        lambda **_kwargs: 1.0,
    )
    planner = Mock(spec=SourceTimingPlanner)
    planner.endpoint_clock_positive_headroom.return_value = timedelta(seconds=7.8)

    baseline = BaselineMixin()
    baseline.start_time = _WINDOW_START
    baseline.end_time = _WINDOW_START + timedelta(minutes=10)
    baseline.activity_generator = SimpleNamespace(_source_timing_planner=planner)
    boundary_start = baseline.end_time - timedelta(seconds=52.8)

    assert baseline._baseline_machine_account_admits(
        _WINDOW_START,
        start=boundary_start - timedelta(microseconds=1),
    )
    assert not baseline._baseline_machine_account_admits(
        _WINDOW_START,
        start=boundary_start,
    )
    assert planner.endpoint_clock_positive_headroom.call_args_list[-1].args == (
        boundary_start + timedelta(seconds=30),
        "windows",
    )


def test_machine_account_admission_includes_selected_route_sensor_headroom(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Baseline reserves the active sensor projection for the selected DC route."""

    monkeypatch.setattr(
        windows_auth_realism_module,
        "remote_auth_transport_max_duration_seconds",
        lambda **_kwargs: 1.0,
    )
    monkeypatch.setattr(
        baseline_module,
        "remote_auth_transport_max_duration_seconds",
        lambda **_kwargs: 1.0,
    )
    resolve_sensor_headroom = Mock(return_value=timedelta(seconds=50))
    baseline = BaselineMixin()
    baseline.start_time = _WINDOW_START
    baseline.end_time = _WINDOW_START + timedelta(minutes=10)
    baseline.dispatcher = SimpleNamespace(
        network_observation_planner=SimpleNamespace(
            network_sensor_close_positive_headroom=resolve_sensor_headroom,
        )
    )
    boundary_start = baseline.end_time - timedelta(seconds=51)

    assert baseline._baseline_machine_account_admits(
        _WINDOW_START,
        start=boundary_start - timedelta(microseconds=1),
        src_ip="10.0.0.20",
        dst_ip="10.0.0.10",
    )
    assert not baseline._baseline_machine_account_admits(
        _WINDOW_START,
        start=boundary_start,
        src_ip="10.0.0.20",
        dst_ip="10.0.0.10",
    )
    resolve_sensor_headroom.assert_called_with(
        boundary_start + timedelta(seconds=1),
        src_ip="10.0.0.20",
        dst_ip="10.0.0.10",
        protocol="tcp",
        conn_state="SF",
        payload_bytes=1,
    )


@pytest.mark.parametrize(
    ("keyword", "headroom"),
    [
        ("endpoint_clock_headroom_seconds", -0.1),
        ("endpoint_clock_headroom_seconds", float("inf")),
        ("network_sensor_headroom_seconds", float("nan")),
    ],
)
def test_machine_account_close_bound_rejects_invalid_runtime_headroom(
    keyword: str,
    headroom: float,
) -> None:
    """The shared owner bound rejects malformed runtime-profile inputs."""

    with pytest.raises(ValueError, match="finite and non-negative"):
        windows_auth_realism_module.machine_account_authentication_close_bound_seconds(
            **{keyword: headroom},
        )


@pytest.mark.parametrize(
    ("duration", "terminal"), [(timedelta(hours=1), True), (timedelta(hours=2), False)]
)
def test_machine_account_baseline_forwards_terminal_exclusive_end(
    monkeypatch: pytest.MonkeyPatch,
    duration: timedelta,
    terminal: bool,
) -> None:
    """Baseline and the direct-call owner enforce the same terminal fence."""

    end_time = _WINDOW_START + duration
    baseline, activity, _state_manager, _linux_system = _minimal_linux_system_traffic(end_time)
    client = System(
        hostname="WS-01",
        ip="10.0.0.20",
        os="Windows 11",
        type="workstation",
        roles=[],
        services=[],
    )
    baseline.scenario.environment.systems = [client]
    baseline._infra_ips = {
        "dns": [],
        "ntp": [],
        "dc": ["10.0.0.10"],
        "dc_hostnames": ["DC-01"],
    }
    baseline._system_service_defaults = {client.hostname: []}
    baseline._system_pids = {
        client.hostname: {
            "services": 400,
            "svchost_netsvcs": 401,
            "lsass": 402,
        }
    }
    baseline.world_model = SimpleNamespace(
        hosts={client.hostname: SimpleNamespace(supports=lambda *_args: False)}
    )
    baseline._activity_multiplier = lambda *_args, **_kwargs: 1.0
    baseline._scaled_randint = lambda _rng, _system, family, *_args: (
        1 if family == "windows_machine_auth" else 0
    )
    baseline._select_windows_scheduled_task = lambda **_kwargs: None
    baseline._plan_windows_scheduled_task = lambda **_kwargs: None
    monkeypatch.setattr(baseline_module, "_get_rng", lambda: random.Random(17))
    monkeypatch.setattr(
        baseline_module,
        "_linux_ambient_logind_session_budget",
        lambda *_args: 0,
    )

    baseline._generate_system_traffic(_WINDOW_START)

    assert activity.generate_machine_account_logon.called
    for call in activity.generate_machine_account_logon.call_args_list:
        assert call.kwargs["exclusive_end"] == (end_time if terminal else None)


@pytest.mark.parametrize("window_duration", [timedelta(minutes=10), timedelta(hours=1)])
def test_terminal_remote_session_plans_keep_only_candidates_that_fit(
    window_duration: timedelta,
) -> None:
    """Partial and exact-hour terminal passes retain safe SSH/RDP requests."""

    baseline = BaselineMixin()
    baseline.start_time = _WINDOW_START
    baseline.end_time = _WINDOW_START + window_duration
    pass_end = baseline.end_time

    ssh_headroom = baseline_module.ssh_action_deadline_transport_headroom_seconds()
    safe_ssh = pass_end - timedelta(seconds=ssh_headroom)
    ssh_plan = baseline._baseline_ssh_terminal_end_plan(
        _WINDOW_START,
        transport_start=safe_ssh,
    )

    assert ssh_plan is not None
    assert ssh_plan.authority == "action_bundle"
    assert ssh_plan.canonical_end == pass_end
    assert (
        baseline._baseline_ssh_terminal_end_plan(
            _WINDOW_START,
            transport_start=safe_ssh + timedelta(microseconds=1),
        )
        is None
    )

    logical_deadline = pass_end - baseline_module.rdp_action_deadline_source_tail()
    rdp_headroom = baseline_module.rdp_action_deadline_transport_headroom_seconds()
    safe_rdp = logical_deadline - timedelta(seconds=rdp_headroom)
    rdp_plan = baseline._baseline_rdp_terminal_end_plan(
        _WINDOW_START,
        transport_start=safe_rdp,
    )
    assert rdp_plan is not None
    assert rdp_plan.authority == "action_bundle"
    assert rdp_plan.canonical_end == pass_end
    assert (
        baseline._baseline_rdp_terminal_end_plan(
            _WINDOW_START,
            transport_start=safe_rdp + timedelta(microseconds=1),
        )
        is None
    )


def test_terminal_remote_session_plans_include_runtime_clock_headroom() -> None:
    """SSH and RDP preflight use the same active clock support as their owners."""

    pass_end = _WINDOW_START + timedelta(minutes=10)
    planner = Mock(spec=SourceTimingPlanner)
    planner.endpoint_clock_positive_headroom.side_effect = lambda _time, os_category: (
        timedelta(seconds=7.8) if os_category == "windows" else timedelta(seconds=6.2)
    )
    planner.endpoint_clock_negative_headroom.side_effect = lambda _time, os_category: (
        timedelta(seconds=4.1) if os_category == "windows" else timedelta(seconds=3.2)
    )
    baseline = BaselineMixin()
    baseline.start_time = _WINDOW_START
    baseline.end_time = pass_end
    baseline.source_timing_planner = planner

    ssh_clock_headroom = timedelta(seconds=7.8)
    safe_ssh = pass_end - timedelta(
        seconds=baseline_module.ssh_action_deadline_transport_headroom_seconds(
            source_clock_headroom=ssh_clock_headroom,
        )
    )
    assert (
        baseline._baseline_ssh_terminal_end_plan(
            _WINDOW_START,
            transport_start=safe_ssh,
        )
        is not None
    )
    assert (
        baseline._baseline_ssh_terminal_end_plan(
            _WINDOW_START,
            transport_start=safe_ssh + timedelta(microseconds=1),
        )
        is None
    )

    rdp_clock_headroom = timedelta(seconds=7.8)
    safe_rdp = (
        pass_end
        - baseline_module.rdp_action_deadline_source_tail(
            source_clock_headroom=rdp_clock_headroom,
        )
        - timedelta(
            seconds=baseline_module.rdp_action_deadline_transport_headroom_seconds(
                source_deadline=pass_end,
                source_timing_planner=planner,
                modeled_source=True,
            )
        )
    )
    assert (
        baseline._baseline_rdp_terminal_end_plan(
            _WINDOW_START,
            transport_start=safe_rdp,
        )
        is not None
    )
    assert (
        baseline._baseline_rdp_terminal_end_plan(
            _WINDOW_START,
            transport_start=safe_rdp + timedelta(microseconds=1),
        )
        is None
    )
    assert (pass_end, "linux") in tuple(
        call.args for call in planner.endpoint_clock_positive_headroom.call_args_list
    )
    assert (pass_end, "windows") in tuple(
        call.args for call in planner.endpoint_clock_positive_headroom.call_args_list
    )
    assert (pass_end, "windows") in tuple(
        call.args for call in planner.endpoint_clock_negative_headroom.call_args_list
    )


def test_terminal_ssh_plan_forwards_active_observation_delay_policy() -> None:
    """Baseline preflight owns the SSH bundle's endpoint observation-delay support."""

    pass_end = _WINDOW_START + timedelta(minutes=10)
    policy = SimpleNamespace(
        delay_bounds=Mock(return_value=(timedelta(0), timedelta(seconds=12))),
        maximum_delay_difference=Mock(return_value=timedelta(seconds=5)),
    )
    baseline = BaselineMixin()
    baseline.start_time = _WINDOW_START
    baseline.end_time = pass_end
    baseline.dispatcher = SimpleNamespace(observation_policy=policy)
    headroom = baseline_module.ssh_action_deadline_transport_headroom_seconds(
        source_deadline=pass_end,
        observation_policy=policy,
    )
    safe_start = pass_end - timedelta(seconds=headroom)

    assert (
        baseline._baseline_ssh_terminal_end_plan(
            _WINDOW_START,
            transport_start=safe_start,
        )
        is not None
    )
    assert (
        baseline._baseline_ssh_terminal_end_plan(
            _WINDOW_START,
            transport_start=safe_start + timedelta(microseconds=1),
        )
        is None
    )
    assert policy.delay_bounds.call_args_list
    assert {call.args for call in policy.delay_bounds.call_args_list} == {
        ("ecar",),
        ("syslog",),
    }
    assert policy.maximum_delay_difference.call_args_list
    assert all(
        call.args == ("ecar", "syslog") for call in policy.maximum_delay_difference.call_args_list
    )


def test_terminal_rdp_execution_consumes_prepared_plan_without_session_reuse() -> None:
    """The terminal path reaches the RDP owner instead of attaching a plan to reused state."""

    user = User(username="admin", full_name="Admin User", email="admin@example.test")
    source = System(
        hostname="ADMIN-01",
        ip="10.0.0.20",
        os="Windows 11",
        type="workstation",
    )
    target = System(
        hostname="SRV-01",
        ip="10.0.0.30",
        os="Windows Server 2022",
        type="server",
    )
    transport_time = _WINDOW_START + timedelta(minutes=5)
    prepared = SimpleNamespace(
        requested_activity_time=transport_time,
        transport_time=transport_time,
    )
    end_plan = SessionEndPlan(
        canonical_end=_WINDOW_START + timedelta(hours=1),
        authority="action_bundle",
    )
    request = baseline_module._BaselineRdpIntent(
        time=transport_time,
        target_system=target,
        user=user,
        source_system=source,
        prepared_bootstrap=prepared,
        session_end_plan=end_plan,
    )
    world_planner = Mock()
    world_planner.bootstrap_user_session.return_value = SimpleNamespace(session=None)
    harness = SimpleNamespace(
        activity_generator=SimpleNamespace(
            _rdp_session_lifecycle_frontier=lambda: _WINDOW_START,
        ),
        world_planner=world_planner,
        state_manager=SimpleNamespace(set_current_time=Mock()),
        _baseline_rdp_cooldown_allows=Mock(return_value=True),
        _remember_baseline_rdp_session=Mock(),
    )

    BaselineMixin._execute_baseline_rdp_requests(harness, (request,), random.Random(3))

    world_planner._bootstrap_prepared_rdp_session.assert_not_called()
    call_kwargs = world_planner.bootstrap_user_session.call_args.kwargs
    assert call_kwargs["_prepared_rdp_bootstrap"] is prepared
    assert call_kwargs["session_end_plan"] is end_plan
    assert call_kwargs["allow_existing"] is False


@pytest.mark.parametrize(("seconds_before_end", "expected_calls"), [(20, 1), (10, 0)])
def test_terminal_user_activity_applies_selected_network_family_bound_before_execution(
    monkeypatch: pytest.MonkeyPatch,
    seconds_before_end: int,
    expected_calls: int,
) -> None:
    """A selected web family uses its TLS/proxy bound instead of a blanket 115 seconds."""

    class SelectionRng:
        """Supply only the draws made while selecting one non-bursty web activity."""

        def __init__(self) -> None:
            self.random_values = iter((0.5, 0.0, 0.5, 0.0))

        @staticmethod
        def shuffle(_values: list[tuple[str, float]]) -> None:
            return

        def random(self) -> float:
            return next(self.random_values)

        @staticmethod
        def randint(_minimum: int, _maximum: int) -> int:
            return 0

        @staticmethod
        def choice(values: list[object]) -> object:
            return values[0]

    user = User(
        username="analyst",
        full_name="Alicia Analyst",
        email="analyst@example.test",
        persona="sysadmin",
    )
    system = System(
        hostname="WS-01",
        ip="10.0.0.20",
        os="Windows 11",
        type="workstation",
    )
    server = System(
        hostname="SRV-01",
        ip="10.0.0.30",
        os="Windows Server 2022",
        type="server",
    )
    end_time = _WINDOW_START + timedelta(minutes=10)
    event_time = end_time - timedelta(seconds=seconds_before_end)
    sessions = [
        SimpleNamespace(
            system=system.hostname,
            logon_id="0x1001",
            logon_type=2,
            session_kind="interactive",
            start_time=event_time - timedelta(minutes=10),
            logoff_time=None,
            end_plan=None,
            network_close_time=None,
            explorer_pid=222,
        )
    ]
    state_manager = SimpleNamespace(
        get_sessions_for_user=lambda _username: sessions,
        set_current_time=Mock(),
    )
    activity = Mock()
    activity._proxy_mode = "transparent"
    activity._proxy_routes = {}
    activity.get_baseline_pattern.return_value = [("connection_web", 1.0)]

    world_planner = Mock()
    baseline = BaselineMixin()
    baseline.start_time = _WINDOW_START
    baseline.end_time = end_time
    baseline.state_manager = state_manager
    baseline.activity_generator = activity
    baseline.world_model = SimpleNamespace(pick_activity_system=lambda *_args: system)
    baseline.world_planner = world_planner
    baseline.scenario = SimpleNamespace(
        environment=SimpleNamespace(systems=[system, server], users=[user]),
        personas=[],
    )
    baseline._get_user_persona = lambda _user: None
    monkeypatch.setattr(baseline_module, "_get_rng", SelectionRng)

    baseline._generate_user_activity(user, event_time, current_hour=_WINDOW_START)

    assert world_planner.ensure_user_session.call_count == 0
    assert activity.execute_baseline_activity.call_count == expected_calls
    activity.generate_explicit_credentials.assert_not_called()


def test_terminal_user_activity_recomputes_rendered_bound_after_startup_pacing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A later realized start re-resolves clock drift before terminal execution."""

    class SelectionRng:
        def __init__(self) -> None:
            self.random_values = iter((0.5, 0.0, 0.5, 0.0))

        @staticmethod
        def shuffle(_values: list[tuple[str, float]]) -> None:
            return

        def random(self) -> float:
            return next(self.random_values)

        @staticmethod
        def randint(_minimum: int, _maximum: int) -> int:
            return 0

        @staticmethod
        def choice(values: list[object]) -> object:
            return values[0]

    user = User(username="analyst", full_name="Alicia Analyst", email="analyst@example.test")
    system = System(hostname="WS-01", ip="10.0.0.20", os="Windows 11", type="workstation")
    pass_end = _WINDOW_START + timedelta(minutes=10)
    initial_time = pass_end - timedelta(seconds=40)
    paced_time = pass_end - timedelta(seconds=20)
    session = SimpleNamespace(
        system=system.hostname,
        logon_id="0x1001",
        logon_type=2,
        session_kind="interactive",
        start_time=_WINDOW_START - timedelta(minutes=10),
        logoff_time=None,
        end_plan=None,
        network_close_time=None,
        explorer_pid=222,
    )
    activity = Mock()
    activity._proxy_mode = "transparent"
    activity._proxy_routes = {}
    activity.get_baseline_pattern.return_value = [("connection_web", 1.0)]
    resolve_sensor_headroom = Mock(
        side_effect=lambda canonical_time, **_kwargs: (
            timedelta(seconds=1)
            if canonical_time < pass_end - timedelta(seconds=15)
            else timedelta(seconds=20)
        )
    )
    baseline = BaselineMixin()
    baseline.start_time = _WINDOW_START
    baseline.end_time = pass_end
    baseline.state_manager = SimpleNamespace(
        get_sessions_for_user=lambda _username: [session],
        set_current_time=Mock(),
    )
    baseline.activity_generator = activity
    baseline.dispatcher = SimpleNamespace(
        network_observation_planner=SimpleNamespace(
            network_sensor_close_positive_headroom=resolve_sensor_headroom,
        )
    )
    baseline.world_model = SimpleNamespace(pick_activity_system=lambda *_args: system)
    baseline.world_planner = Mock()
    baseline.scenario = SimpleNamespace(
        environment=SimpleNamespace(systems=[system], users=[user]),
        personas=[],
    )
    baseline._get_user_persona = lambda _user: None
    baseline._pace_interactive_startup_activity = lambda **_kwargs: paced_time
    monkeypatch.setattr(baseline_module, "_get_rng", SelectionRng)

    baseline._generate_user_activity(user, initial_time, current_hour=_WINDOW_START)

    activity.execute_baseline_activity.assert_not_called()
    resolved_times = [call.args[0] for call in resolve_sensor_headroom.call_args_list]
    assert any(timestamp < pass_end - timedelta(seconds=15) for timestamp in resolved_times)
    assert any(timestamp >= pass_end - timedelta(seconds=15) for timestamp in resolved_times)


def test_terminal_user_activity_does_not_create_unowned_local_session(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A bounded activity cannot create a local session with no terminal logoff owner."""

    class SelectionRng:
        def __init__(self) -> None:
            self.random_values = iter((0.5, 0.0, 0.5))

        @staticmethod
        def shuffle(_values: list[tuple[str, float]]) -> None:
            return

        def random(self) -> float:
            return next(self.random_values)

        @staticmethod
        def randint(_minimum: int, _maximum: int) -> int:
            return 0

    user = User(username="analyst", full_name="Alicia Analyst", email="analyst@example.test")
    system = System(hostname="WS-01", ip="10.0.0.20", os="Windows 11", type="workstation")
    end_time = _WINDOW_START + timedelta(minutes=10)
    activity = Mock()
    activity._proxy_mode = "transparent"
    activity._proxy_routes = {}
    activity.get_baseline_pattern.return_value = [("connection_web", 1.0)]
    world_planner = Mock()
    baseline = BaselineMixin()
    baseline.start_time = _WINDOW_START
    baseline.end_time = end_time
    baseline.state_manager = SimpleNamespace(
        get_sessions_for_user=lambda _username: [],
        set_current_time=Mock(),
    )
    baseline.activity_generator = activity
    baseline.world_model = SimpleNamespace(pick_activity_system=lambda *_args: system)
    baseline.world_planner = world_planner
    baseline.scenario = SimpleNamespace(
        environment=SimpleNamespace(systems=[system], users=[user]),
        personas=[],
    )
    baseline._get_user_persona = lambda _user: None
    monkeypatch.setattr(baseline_module, "_get_rng", SelectionRng)

    baseline._generate_user_activity(
        user,
        end_time - timedelta(seconds=20),
        current_hour=_WINDOW_START,
    )

    world_planner.ensure_user_session.assert_not_called()
    activity.execute_baseline_activity.assert_not_called()


@pytest.mark.parametrize("activity_type", ["logon", "process_build", "process_user_apps"])
def test_terminal_user_activity_omits_families_without_owner_deadlines(
    monkeypatch: pytest.MonkeyPatch,
    activity_type: str,
) -> None:
    """Terminal generic activity cannot realize an unbounded start/lifecycle family."""

    class SelectionRng:
        def __init__(self) -> None:
            self.random_values = iter((0.5, 0.0, 0.5))

        @staticmethod
        def shuffle(_values: list[tuple[str, float]]) -> None:
            return

        def random(self) -> float:
            return next(self.random_values)

        @staticmethod
        def randint(_minimum: int, _maximum: int) -> int:
            return 0

    user = User(username="analyst", full_name="Alicia Analyst", email="analyst@example.test")
    system = System(hostname="WS-01", ip="10.0.0.20", os="Windows 11", type="workstation")
    end_time = _WINDOW_START + timedelta(minutes=10)
    session = SimpleNamespace(
        system=system.hostname,
        logon_id="0x1001",
        logon_type=2,
        session_kind="interactive",
        start_time=_WINDOW_START - timedelta(minutes=10),
        logoff_time=None,
        end_plan=None,
        network_close_time=None,
    )
    activity = Mock()
    activity.get_baseline_pattern.return_value = [(activity_type, 1.0)]
    baseline = BaselineMixin()
    baseline.start_time = _WINDOW_START
    baseline.end_time = end_time
    baseline.state_manager = SimpleNamespace(
        get_sessions_for_user=lambda _username: [session],
        set_current_time=Mock(),
    )
    baseline.activity_generator = activity
    baseline.world_model = SimpleNamespace(pick_activity_system=lambda *_args: system)
    baseline.world_planner = Mock()
    baseline.scenario = SimpleNamespace(
        environment=SimpleNamespace(systems=[system], users=[user]),
        personas=[],
    )
    baseline._get_user_persona = lambda _user: None
    monkeypatch.setattr(baseline_module, "_get_rng", SelectionRng)

    baseline._generate_user_activity(
        user,
        end_time - timedelta(seconds=90),
        current_hour=_WINDOW_START,
    )

    activity.execute_baseline_activity.assert_not_called()


def test_terminal_process_family_is_suppressed_before_real_generator_output(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An unbounded process family cannot mutate real state or render endpoint rows."""

    pass_end = _WINDOW_START + timedelta(minutes=10)
    user = User(username="analyst", full_name="Alicia Analyst", email="analyst@example.test")
    system = System(
        hostname="LNX-01",
        ip="10.0.0.20",
        os="Ubuntu 24.04",
        type="workstation",
    )
    state_manager = StateManager()
    state_manager.set_current_time(_WINDOW_START - timedelta(minutes=20))
    logon_id = state_manager.create_session(
        username=user.username,
        system=system.hostname,
        logon_type=2,
        source_ip=system.ip,
        start_time=_WINDOW_START - timedelta(minutes=20),
        session_kind="interactive",
    )
    shell_pid = state_manager.create_process(
        system.hostname,
        0,
        "/bin/bash",
        "-bash",
        user.username,
        "Medium",
        logon_id=logon_id,
    )
    session = state_manager.get_session(logon_id)
    assert session is not None
    session.session_shell_pid = shell_pid
    ecar = EcarEmitter(load_format("ecar"), tmp_path / "ecar", threaded=False)
    emitters = {"ecar": ecar}
    dispatcher = EventDispatcher(state_manager=state_manager, emitters=emitters)
    activity = ActivityGenerator(
        state_manager,
        emitters,
        dispatcher=dispatcher,
        generation_window_start=_WINDOW_START,
        generation_window_end=pass_end,
    )
    activity._ip_to_system = {system.ip: system}
    activity._all_system_ips = [system.ip]
    monkeypatch.setattr(
        activity,
        "get_baseline_pattern",
        lambda *_args, **_kwargs: [("process_build", 1.0)],
    )
    monkeypatch.setattr(baseline_module, "_get_rng", lambda: random.Random(0))
    baseline = BaselineMixin()
    baseline.start_time = _WINDOW_START
    baseline.end_time = pass_end
    baseline.state_manager = state_manager
    baseline.activity_generator = activity
    baseline.world_model = SimpleNamespace(pick_activity_system=lambda *_args: system)
    baseline.world_planner = Mock()
    baseline.scenario = SimpleNamespace(
        environment=SimpleNamespace(systems=[system], users=[user]),
        personas=[],
    )
    baseline._get_user_persona = lambda _user: None
    process_ids_before = {
        process.pid for process in state_manager.get_processes_on_system(system.hostname)
    }

    try:
        baseline._generate_user_activity(
            user,
            pass_end - timedelta(minutes=3),
            current_hour=_WINDOW_START,
        )
    finally:
        ecar.close()

    assert {
        process.pid for process in state_manager.get_processes_on_system(system.hostname)
    } == process_ids_before
    assert not any(path.read_text(encoding="utf-8") for path in (tmp_path / "ecar").rglob("*.json"))


def test_terminal_generic_ssh_uses_real_owner_and_drains_by_pass_end(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The generic terminal path creates and closes SSH through production owners."""

    pass_end = _WINDOW_START + timedelta(minutes=10)
    source = System(
        hostname="WS-01",
        ip="10.0.0.10",
        os="Windows 11",
        type="workstation",
    )
    target = System(
        hostname="LNX-01",
        ip="10.0.0.20",
        os="Ubuntu 24.04",
        type="server",
        services=["ssh"],
    )
    user = User(username="analyst", full_name="Alicia Analyst", email="analyst@example.test")
    state_manager = StateManager()
    state_manager.set_current_time(_WINDOW_START)
    ecar = EcarEmitter(load_format("ecar"), tmp_path / "ecar", threaded=False)
    zeek = ZeekEmitter(
        load_format("zeek_conn"),
        tmp_path / "zeek_conn.json",
        threaded=False,
    )
    emitters = {"ecar": ecar, "zeek_conn": zeek}
    timing_runtime = TimingRuntime(
        reference_time=_WINDOW_START,
        namespace="terminal-generic-ssh-owner",
    )
    dispatcher = EventDispatcher(
        state_manager=state_manager,
        emitters=emitters,
        timing_runtime=timing_runtime,
    )
    activity = ActivityGenerator(
        state_manager,
        emitters,
        dispatcher=dispatcher,
        timing_runtime=timing_runtime,
        generation_window_start=_WINDOW_START,
        generation_window_end=pass_end,
    )
    activity._ip_to_system = {source.ip: source, target.ip: target}
    activity._all_system_ips = [source.ip, target.ip]

    class SshWorld:
        hosts = {
            source.hostname: SimpleNamespace(os_category="windows"),
            target.hostname: SimpleNamespace(os_category="linux"),
        }

        @staticmethod
        def pick_activity_system(_user: User, _rng: random.Random) -> System:
            return target

        @staticmethod
        def plan_session(**_kwargs: object) -> SessionPlan:
            return SessionPlan(
                target_system=target,
                source_system=source,
                source_ip=source.ip,
                logon_type=10,
                session_kind="ssh",
                requires_transport=True,
            )

    world = SshWorld()
    planner = WorldPlanner(world, state_manager, activity)  # type: ignore[arg-type]
    executed_activity = Mock()
    monkeypatch.setattr(
        activity, "get_baseline_pattern", lambda *_args, **_kwargs: [("connection_email", 1.0)]
    )
    monkeypatch.setattr(activity, "execute_baseline_activity", executed_activity)
    monkeypatch.setattr(baseline_module, "_get_rng", lambda: random.Random(0))
    baseline = BaselineMixin()
    baseline.start_time = _WINDOW_START
    baseline.end_time = pass_end
    baseline.state_manager = state_manager
    baseline.activity_generator = activity
    baseline.world_model = world
    baseline.world_planner = planner
    baseline.scenario = SimpleNamespace(
        environment=SimpleNamespace(systems=[source, target], users=[user]),
        personas=[],
    )
    baseline._get_user_persona = lambda _user: None
    event_time = pass_end - timedelta(
        seconds=baseline_module.ssh_action_deadline_transport_headroom_seconds(
            source_deadline=pass_end,
            source_timing_planner=dispatcher.source_timing_planner,
            network_observation_planner=dispatcher.network_observation_planner,
        )
        + 60.0
    )

    try:
        baseline._generate_user_activity(user, event_time, current_hour=_WINDOW_START)

        sessions = state_manager.get_sessions_for_user(user.username)
        assert len(sessions) == 1
        session = sessions[0]
        assert session.session_kind == "ssh"
        assert session.end_plan == SessionEndPlan(pass_end, "action_bundle")
        assert session.network_close_time is not None
        assert session.network_close_time < pass_end

        activity.finalize_ssh_session_lifecycles(pass_end)

        assert state_manager.get_sessions_for_user(user.username) == []
        assert activity._pending_ssh_session_closures == []
    finally:
        ecar.close()
        zeek.close()


def test_terminal_ids_admission_uses_selected_direction_and_route() -> None:
    """Inbound S0 probes are not charged for an unrelated outbound proxy/TLS path."""

    baseline = BaselineMixin()
    baseline.start_time = _WINDOW_START
    baseline.end_time = _WINDOW_START + timedelta(minutes=10)
    local_ip = "10.0.0.20"
    baseline.activity_generator = SimpleNamespace(
        _proxy_mode="explicit",
        _proxy_routes={local_ip: object()},
    )
    (
        inbound_service,
        inbound_duration,
        inbound_conn_state,
        inbound_payload_bytes,
    ) = baseline_module._baseline_inbound_ids_probe_close_contract(
        proto="tcp",
        dst_port=8443,
        target_system=None,
        policy_denied=False,
        deny_conn_state="S0",
    )
    inbound_bound = baseline._baseline_ids_connection_close_bound_seconds(
        src_ip="203.0.113.10",
        dst_ip=local_ip,
        proto="tcp",
        dst_port=8443,
        service=inbound_service,
        requested_duration_max=inbound_duration,
    )
    outbound_proxy_bound = baseline._baseline_ids_connection_close_bound_seconds(
        src_ip=local_ip,
        dst_ip="198.51.100.20",
        proto="tcp",
        dst_port=443,
        service="ssl",
        requested_duration_max=5.0,
    )

    assert inbound_service == ""
    assert inbound_conn_state == "S0"
    assert inbound_payload_bytes == 0
    assert inbound_bound == 7.0
    assert outbound_proxy_bound > inbound_bound
    start = baseline.end_time - timedelta(seconds=inbound_bound)
    assert baseline._baseline_pass_admits(
        _WINDOW_START,
        start=start,
        end=start + timedelta(seconds=inbound_bound),
    )
    assert not baseline._baseline_pass_admits(
        _WINDOW_START,
        start=start,
        end=start + timedelta(seconds=outbound_proxy_bound),
    )
