# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
#
# SPDX-License-Identifier: MIT

"""Unit tests for the compiled world model and planner layer."""

import random
from datetime import UTC, datetime, timedelta
from unittest.mock import Mock

import pytest

from evidenceforge.events.dispatcher import EventDispatcher
from evidenceforge.generation.actions.rdp_session import RdpSessionActionBundle, RdpSessionRequest
from evidenceforge.generation.activity import ActivityGenerator
from evidenceforge.generation.activity.timing_profiles import get_timing_window
from evidenceforge.generation.state_manager import StateManager
from evidenceforge.generation.world_model import WorldModel, WorldPlanner
from evidenceforge.models.scenario import (
    BaselineActivity,
    Environment,
    Group,
    OutputSpec,
    Scenario,
    System,
    TimeWindow,
    User,
)


def _make_scenario() -> Scenario:
    """Create a scenario with enough topology to exercise world-model planning."""
    return Scenario(
        name="world-model-test",
        description="World model coverage scenario",
        environment=Environment(
            description="Mixed environment",
            users=[
                User(
                    username="alice.admin",
                    full_name="Alice Admin",
                    email="alice@corp.local",
                    persona="sysadmin",
                    primary_system="WKS-01",
                ),
                User(
                    username="dev.user",
                    full_name="Dev User",
                    email="dev@corp.local",
                    persona="developer",
                    primary_system="WKS-02",
                ),
            ],
            systems=[
                System(
                    hostname="WKS-01",
                    ip="10.10.10.50",
                    os="Windows 11",
                    type="workstation",
                    assigned_user="alice.admin",
                ),
                System(
                    hostname="WKS-02",
                    ip="10.10.10.51",
                    os="Windows 11",
                    type="workstation",
                    assigned_user="dev.user",
                    services=["dns-client", "systemd-resolved"],
                ),
                System(
                    hostname="APP-01",
                    ip="10.10.20.10",
                    os="Windows Server 2019",
                    type="server",
                    roles=["application"],
                ),
                System(
                    hostname="DB-01",
                    ip="10.10.30.10",
                    os="Ubuntu 22.04",
                    type="server",
                    services=["postgresql"],
                ),
                System(
                    hostname="PROXY-01",
                    ip="10.10.40.10",
                    os="Ubuntu 22.04",
                    type="server",
                    roles=["proxy"],
                    services=["squid"],
                ),
                System(
                    hostname="DC-01",
                    ip="10.10.100.10",
                    os="Windows Server 2019",
                    type="domain_controller",
                ),
            ],
        ),
        time_window=TimeWindow(start=datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC), duration="2h"),
        baseline_activity=BaselineActivity(description="Normal", intensity="low", variation="low"),
        output=OutputSpec(logs=[{"format": "windows"}, {"format": "zeek"}], destination="./out"),
    )


@pytest.fixture
def scenario() -> Scenario:
    """Scenario fixture for world-model tests."""
    return _make_scenario()


@pytest.fixture
def systems(scenario: Scenario) -> dict[str, System]:
    """Systems indexed by hostname."""
    return {system.hostname: system for system in scenario.environment.systems}


@pytest.fixture
def users(scenario: Scenario) -> dict[str, User]:
    """Users indexed by username."""
    return {user.username: user for user in scenario.environment.users}


@pytest.fixture
def world_model(scenario: Scenario) -> WorldModel:
    """Compiled world model for the scenario."""
    return WorldModel(scenario, "corp.local")


def test_dns_client_services_do_not_make_workstations_dns_servers(world_model: WorldModel):
    """Resolver/client services should not be treated as DNS server roles."""
    dns_hostnames = {system.hostname for system in world_model.dns_servers}

    assert "DC-01" in dns_hostnames
    assert "WKS-02" not in dns_hostnames


@pytest.fixture
def state_manager() -> StateManager:
    """Fresh state manager."""
    return StateManager()


@pytest.fixture
def mock_emitters() -> dict[str, Mock]:
    """Mock emitters that accept all dispatched events."""
    windows = Mock()
    windows.can_handle.return_value = True
    zeek = Mock()
    zeek.can_handle.return_value = True
    return {"windows_event_security": windows, "zeek_conn": zeek}


@pytest.fixture
def activity_generator(
    state_manager: StateManager,
    mock_emitters: dict[str, Mock],
    world_model: WorldModel,
) -> ActivityGenerator:
    """ActivityGenerator wired similarly to the generation engine."""
    dispatcher = EventDispatcher(state_manager=state_manager, emitters=mock_emitters)
    generator = ActivityGenerator(state_manager, mock_emitters, dispatcher=dispatcher)
    generator._ad_domain = world_model.ad_domain
    generator._ip_to_system = dict(world_model.systems_by_ip)
    generator._all_system_ips = [system.ip for system in world_model.scenario.environment.systems]
    return generator


@pytest.fixture
def planner(
    world_model: WorldModel,
    state_manager: StateManager,
    activity_generator: ActivityGenerator,
) -> WorldPlanner:
    """World planner backed by the real ActivityGenerator."""
    return WorldPlanner(world_model, state_manager, activity_generator)


def test_world_model_compiles_roles_and_infrastructure(
    world_model: WorldModel,
    systems: dict[str, System],
) -> None:
    """WorldModel should normalize roles and infer infrastructure endpoints once."""
    db_host = world_model.hosts["DB-01"]
    proxy_host = world_model.hosts["PROXY-01"]
    dc_host = world_model.hosts["DC-01"]

    assert "database" in db_host.canonical_roles
    assert db_host.supports_ssh is True
    assert "forward_proxy" in proxy_host.canonical_roles
    assert "dns_server" in dc_host.canonical_roles

    infra = world_model.to_infrastructure_ips()
    assert infra["dc"] == [systems["DC-01"].ip]
    assert infra["db_servers"] == [
        {"ip": systems["DB-01"].ip, "port": 5432, "service": "postgresql"}
    ]
    assert world_model.proxy_routes[systems["WKS-01"].ip][0].hostname == "PROXY-01"


def test_world_model_plan_session_selects_interactive_ssh_and_rdp(
    world_model: WorldModel,
    systems: dict[str, System],
    users: dict[str, User],
) -> None:
    """Session planning should pick the right access mode for each host type."""
    rng = random.Random(42)
    user = users["alice.admin"]

    workstation_plan = world_model.plan_session(user, systems["WKS-01"], rng)
    assert workstation_plan.session_kind == "interactive"
    assert workstation_plan.logon_type == 2
    assert workstation_plan.source_ip == systems["WKS-01"].ip

    ssh_plan = world_model.plan_session(user, systems["DB-01"], rng)
    assert ssh_plan.session_kind == "ssh"
    assert ssh_plan.logon_type == 10
    assert ssh_plan.source_system is not None
    assert ssh_plan.source_system.hostname == "WKS-01"
    assert ssh_plan.source_ip == systems["WKS-01"].ip

    rdp_plan = world_model.plan_session(user, systems["APP-01"], rng)
    assert rdp_plan.session_kind == "rdp"
    assert rdp_plan.logon_type == 10
    assert rdp_plan.source_system is not None
    assert rdp_plan.source_system.hostname == "WKS-01"


def test_world_model_ssh_admin_roster_is_role_and_group_scoped(scenario: Scenario) -> None:
    """Baseline SSH admin users should be narrower than generic DB access personas."""
    scenario.environment.users.extend(
        [
            User(
                username="data.user",
                full_name="Data User",
                email="data@corp.local",
                persona="data_analyst",
                primary_system="WKS-03",
            ),
            User(
                username="sales.user",
                full_name="Sales User",
                email="sales@corp.local",
                persona="sales",
                primary_system="WKS-04",
            ),
            User(
                username="helpdesk.user",
                full_name="Helpdesk User",
                email="helpdesk@corp.local",
                persona="help_desk",
                primary_system="WKS-05",
            ),
        ]
    )
    scenario.environment.systems.extend(
        [
            System(
                hostname="WKS-03",
                ip="10.10.10.53",
                os="Windows 11",
                type="workstation",
                assigned_user="data.user",
            ),
            System(
                hostname="WKS-04",
                ip="10.10.10.54",
                os="Windows 11",
                type="workstation",
                assigned_user="sales.user",
            ),
            System(
                hostname="WKS-05",
                ip="10.10.10.55",
                os="Windows 11",
                type="workstation",
                assigned_user="helpdesk.user",
            ),
        ]
    )
    scenario.environment.groups = [
        Group(name="it-admins", members=["helpdesk.user"]),
    ]
    model = WorldModel(scenario, "corp.local")

    db_roster = {
        user.username for user in model.get_ssh_admin_users(model.systems_by_hostname["DB-01"])
    }
    web_roster = {
        user.username for user in model.get_ssh_admin_users(model.systems_by_hostname["PROXY-01"])
    }

    assert {"alice.admin", "dev.user", "helpdesk.user"} <= db_roster
    assert "data.user" not in db_roster
    assert "sales.user" not in db_roster
    assert "dev.user" not in web_roster
    assert {"alice.admin", "helpdesk.user"} <= web_roster


def test_world_planner_preallocates_sessions_before_logon_emission(
    world_model: WorldModel,
    state_manager: StateManager,
    systems: dict[str, System],
    users: dict[str, User],
) -> None:
    """Planner-owned session state should not depend on generator side effects."""
    activity_generator = Mock()
    activity_generator.generate_logon.return_value = "0xdeadbeef"
    planner = WorldPlanner(world_model, state_manager, activity_generator)

    result = planner.bootstrap_user_session(
        user=users["alice.admin"],
        target_system=systems["WKS-01"],
        time=datetime(2024, 1, 15, 10, 5, 0, tzinfo=UTC),
        rng=random.Random(7),
        session_kind="interactive",
        allow_existing=False,
    )

    assert result.session.logon_id != "0xdeadbeef"
    assert state_manager.get_session(result.session.logon_id) is result.session
    call_kwargs = activity_generator.generate_logon.call_args.kwargs
    assert call_kwargs["logon_id"] == result.session.logon_id
    assert call_kwargs["logon_type"] == 2


def test_world_planner_reuses_durable_windows_interactive_session(
    planner: WorldPlanner,
    state_manager: StateManager,
    systems: dict[str, System],
    users: dict[str, User],
    mock_emitters: dict[str, Mock],
) -> None:
    """Later workstation activity should not bootstrap another Type 2 session."""
    start_time = datetime(2024, 1, 15, 10, 5, 0, tzinfo=UTC)
    first = planner.bootstrap_user_session(
        user=users["alice.admin"],
        target_system=systems["WKS-01"],
        time=start_time,
        rng=random.Random(17),
        session_kind="interactive",
        allow_existing=False,
    )
    mock_emitters["windows_event_security"].reset_mock()

    second = planner.bootstrap_user_session(
        user=users["alice.admin"],
        target_system=systems["WKS-01"],
        time=start_time + timedelta(minutes=55),
        rng=random.Random(23),
        session_kind="interactive",
    )

    assert second.session.logon_id == first.session.logon_id
    assert state_manager.get_sessions_for_user("alice.admin") == [first.session]
    assert first.session.last_activity_time == start_time + timedelta(minutes=55)
    emitted_types = [
        call.args[0].event_type
        for call in mock_emitters["windows_event_security"].emit.call_args_list
    ]
    assert "logon" not in emitted_types


def test_world_planner_bootstraps_ssh_session(
    planner: WorldPlanner,
    state_manager: StateManager,
    activity_generator: ActivityGenerator,
    mock_emitters: dict[str, Mock],
    systems: dict[str, System],
    users: dict[str, User],
) -> None:
    """SSH bootstrap should create a durable session plus correlated network metadata."""
    seed_time = datetime(2024, 1, 15, 9, 55, 0, tzinfo=UTC)
    state_manager.register_boot_time(
        systems["DB-01"].hostname,
        datetime(2024, 1, 6, 10, 15, 0, tzinfo=UTC),
    )
    state_manager.set_current_time(seed_time)
    systemd_pid = state_manager.create_process(
        systems["DB-01"].hostname,
        0,
        "/usr/lib/systemd/systemd",
        "/usr/lib/systemd/systemd",
        "root",
        "System",
    )
    sshd_pid = state_manager.create_process(
        systems["DB-01"].hostname,
        systemd_pid,
        "/usr/sbin/sshd",
        "/usr/sbin/sshd -D",
        "root",
        "System",
    )
    activity_generator._system_pids = {
        systems["DB-01"].hostname: {"systemd": systemd_pid, "sshd": sshd_pid}
    }

    result = planner.bootstrap_user_session(
        user=users["alice.admin"],
        target_system=systems["DB-01"],
        time=datetime(2024, 1, 15, 10, 15, 0, tzinfo=UTC),
        rng=random.Random(9),
        session_kind="ssh",
        source_system=systems["WKS-01"],
        allow_existing=False,
        required_until=datetime(2024, 1, 15, 10, 45, 0, tzinfo=UTC),
    )

    session = state_manager.get_session(result.session.logon_id)
    assert session is not None
    assert session.session_kind == "ssh"
    assert session.source_ip == systems["WKS-01"].ip
    assert session.source_port > 0
    assert session.transport_pid is not None
    assert session.session_shell_pid is not None
    assert session.source_ready_time is not None
    assert session.network_close_time is not None
    assert session.network_close_time >= datetime(2024, 1, 15, 10, 45, 0, tzinfo=UTC)
    shell = state_manager.get_process(systems["DB-01"].hostname, session.session_shell_pid)
    assert shell is not None
    assert shell.image == "/bin/bash"
    assert shell.logon_id == session.logon_id
    assert shell.start_time >= session.source_ready_time
    assert shell.parent_pid == session.transport_pid
    assert session.process_tree_root == session.transport_pid

    early_command_time = session.source_ready_time - timedelta(seconds=1)
    command_time = activity_generator.generate_bash_command(
        users["alice.admin"],
        systems["DB-01"],
        early_command_time,
        "whoami",
    )
    assert command_time is not None
    assert command_time >= session.source_ready_time

    process_events = [
        call.args[0]
        for call in mock_emitters["windows_event_security"].emit.call_args_list
        if call.args[0].event_type in {"process_create", "system_process_create"}
    ]
    bash_events = [
        event
        for event in process_events
        if event.process is not None and event.process.pid == session.session_shell_pid
    ]
    assert bash_events
    sshd_events = [
        event
        for event in process_events
        if event.process is not None
        and event.process.command_line == f"sshd: {users['alice.admin'].username} [priv]"
    ]
    assert len(sshd_events) == 1
    assert sshd_events[0].process.pid == session.transport_pid
    assert bash_events[0].process.parent_image == "/usr/sbin/sshd"
    assert session.transport_pid > 180_000
    assert result.network_uid


def test_world_planner_materializes_visible_shell_for_reused_ssh_session(
    planner: WorldPlanner,
    state_manager: StateManager,
    activity_generator: ActivityGenerator,
    mock_emitters: dict[str, Mock],
    systems: dict[str, System],
    users: dict[str, User],
) -> None:
    """Reused SSH sessions should not parent visible commands to hidden boot shells."""
    scenario_start = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)
    pre_window_time = scenario_start - timedelta(minutes=20)
    activity_time = scenario_start + timedelta(minutes=35)
    activity_generator._scenario_start_time = scenario_start
    state_manager.register_boot_time(
        systems["DB-01"].hostname,
        datetime(2024, 1, 6, 10, 15, 0, tzinfo=UTC),
    )
    state_manager.set_current_time(pre_window_time)
    systemd_pid = state_manager.create_process(
        systems["DB-01"].hostname,
        0,
        "/usr/lib/systemd/systemd",
        "/usr/lib/systemd/systemd",
        "root",
        "System",
    )
    sshd_pid = state_manager.create_process(
        systems["DB-01"].hostname,
        systemd_pid,
        "/usr/sbin/sshd",
        "/usr/sbin/sshd -D",
        "root",
        "System",
    )
    hidden_bash_pid = state_manager.create_process(
        systems["DB-01"].hostname,
        sshd_pid,
        "/bin/bash",
        "-bash",
        users["alice.admin"].username,
        "Medium",
    )
    logon_id = state_manager.create_session(
        username=users["alice.admin"].username,
        system=systems["DB-01"].hostname,
        logon_type=10,
        source_ip=systems["WKS-01"].ip,
        source_port=51512,
        session_kind="ssh",
        start_time=pre_window_time,
    )
    session = state_manager.get_session(logon_id)
    assert session is not None
    session.session_shell_pid = hidden_bash_pid
    activity_generator._system_pids = {
        systems["DB-01"].hostname: {"systemd": systemd_pid, "sshd": sshd_pid}
    }

    result = planner.bootstrap_user_session(
        user=users["alice.admin"],
        target_system=systems["DB-01"],
        time=activity_time,
        rng=random.Random(11),
        session_kind="ssh",
        allow_existing=True,
    )

    assert result.session is session
    assert session.session_shell_pid is not None
    assert session.session_shell_pid != hidden_bash_pid
    visible_shell = state_manager.get_process(systems["DB-01"].hostname, session.session_shell_pid)
    assert visible_shell is not None
    assert visible_shell.image == "/bin/bash"
    assert visible_shell.start_time >= scenario_start
    assert visible_shell.start_time < activity_time

    process_events = [
        call.args[0]
        for call in mock_emitters["windows_event_security"].emit.call_args_list
        if call.args[0].event_type in {"process_create", "system_process_create"}
    ]
    bash_events = [
        event
        for event in process_events
        if event.process is not None and event.process.pid == session.session_shell_pid
    ]
    assert bash_events
    assert bash_events[0].timestamp >= scenario_start
    assert bash_events[0].timestamp < activity_time


def test_linux_parent_resolution_materializes_visible_shell_for_reused_ssh_logon(
    state_manager: StateManager,
    activity_generator: ActivityGenerator,
    mock_emitters: dict[str, Mock],
    systems: dict[str, System],
    users: dict[str, User],
) -> None:
    """Direct Linux parent resolution should avoid hidden seeded bash parents."""
    scenario_start = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)
    pre_window_time = scenario_start - timedelta(minutes=20)
    activity_time = scenario_start + timedelta(minutes=35)
    activity_generator._scenario_start_time = scenario_start
    state_manager.set_current_time(pre_window_time)
    systemd_pid = state_manager.create_process(
        systems["DB-01"].hostname,
        0,
        "/usr/lib/systemd/systemd",
        "/usr/lib/systemd/systemd",
        "root",
        "System",
    )
    sshd_pid = state_manager.create_process(
        systems["DB-01"].hostname,
        systemd_pid,
        "/usr/sbin/sshd",
        "/usr/sbin/sshd -D",
        "root",
        "System",
    )
    hidden_bash_pid = state_manager.create_process(
        systems["DB-01"].hostname,
        sshd_pid,
        "/bin/bash",
        "-bash",
        users["alice.admin"].username,
        "Medium",
    )
    logon_id = state_manager.create_session(
        username=users["alice.admin"].username,
        system=systems["DB-01"].hostname,
        logon_type=10,
        source_ip=systems["WKS-01"].ip,
        source_port=51512,
        session_kind="ssh",
        start_time=pre_window_time,
    )
    session = state_manager.get_session(logon_id)
    assert session is not None
    session.session_shell_pid = hidden_bash_pid
    activity_generator._system_pids = {
        systems["DB-01"].hostname: {"systemd": systemd_pid, "sshd": sshd_pid}
    }

    parent_pid = activity_generator._resolve_parent(
        systems["DB-01"],
        users["alice.admin"],
        activity_time,
        logon_id,
        "/usr/bin/git",
    )

    assert session.session_shell_pid is not None
    assert parent_pid == session.session_shell_pid
    assert parent_pid != hidden_bash_pid
    visible_shell = state_manager.get_process(systems["DB-01"].hostname, parent_pid)
    assert visible_shell is not None
    assert visible_shell.image == "/bin/bash"
    assert visible_shell.start_time >= scenario_start

    bash_events = [
        call.args[0]
        for call in mock_emitters["windows_event_security"].emit.call_args_list
        if call.args[0].process is not None and call.args[0].process.pid == parent_pid
    ]
    assert bash_events


def test_linux_shell_parent_resolution_ignores_closed_ssh_transport(
    state_manager: StateManager,
    activity_generator: ActivityGenerator,
    systems: dict[str, System],
    users: dict[str, User],
) -> None:
    """Closed SSH transports should not continue owning shell parents."""
    start_time = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)
    close_time = start_time + timedelta(minutes=5)
    late_activity_time = close_time + timedelta(minutes=30)
    state_manager.set_current_time(start_time)
    systemd_pid = state_manager.create_process(
        systems["DB-01"].hostname,
        0,
        "/usr/lib/systemd/systemd",
        "/usr/lib/systemd/systemd",
        "root",
        "System",
    )
    sshd_pid = state_manager.create_process(
        systems["DB-01"].hostname,
        systemd_pid,
        "/usr/sbin/sshd",
        "/usr/sbin/sshd -D",
        "root",
        "System",
    )
    shell_pid = state_manager.create_process(
        systems["DB-01"].hostname,
        sshd_pid,
        "/bin/bash",
        "-bash",
        users["alice.admin"].username,
        "Medium",
    )
    logon_id = state_manager.create_session(
        username=users["alice.admin"].username,
        system=systems["DB-01"].hostname,
        logon_type=10,
        source_ip=systems["WKS-01"].ip,
        source_port=51512,
        session_kind="ssh",
        start_time=start_time,
    )
    state_manager.update_session_metadata(logon_id, network_close_time=close_time)
    session = state_manager.get_session(logon_id)
    assert session is not None
    session.session_shell_pid = shell_pid
    activity_generator._system_pids = {
        systems["DB-01"].hostname: {"systemd": systemd_pid, "sshd": sshd_pid}
    }

    assert (
        activity_generator.ensure_linux_ssh_session_shell(
            user=users["alice.admin"],
            target_system=systems["DB-01"],
            logon_id=logon_id,
            logon_time=start_time,
            activity_time=late_activity_time,
        )
        is None
    )
    assert (
        activity_generator._active_session_shell_pid(
            systems["DB-01"],
            users["alice.admin"],
            late_activity_time,
            logon_id,
        )
        is None
    )
    assert (
        activity_generator.ensure_linux_visible_shell_parent(
            user=users["alice.admin"],
            target_system=systems["DB-01"],
            activity_time=late_activity_time,
            logon_id=logon_id,
            logon_time=start_time,
        )
        is None
    )


def test_world_planner_bootstraps_rdp_session_with_owned_state(
    planner: WorldPlanner,
    state_manager: StateManager,
    systems: dict[str, System],
    users: dict[str, User],
) -> None:
    """RDP bootstrap should keep session and connection ownership aligned."""
    result = planner.bootstrap_user_session(
        user=users["alice.admin"],
        target_system=systems["APP-01"],
        time=datetime(2024, 1, 15, 10, 20, 0, tzinfo=UTC),
        rng=random.Random(11),
        session_kind="rdp",
        source_system=systems["WKS-01"],
        allow_existing=False,
    )

    session = state_manager.get_session(result.session.logon_id)
    assert session is not None
    assert session.logon_type == 10
    assert session.session_kind == "rdp"
    assert session.source_ip == systems["WKS-01"].ip
    assert result.network_uid

    rdp_connections = [
        conn for conn in state_manager.list_open_connections() if conn.dst_port == 3389
    ]
    assert len(rdp_connections) == 1
    assert rdp_connections[0].protocol == "tcp"
    assert rdp_connections[0].initiating_pid > 0
    assert rdp_connections[0].source_system == "WKS-01"


def test_rdp_target_logon_waits_for_endpoint_flow_visibility() -> None:
    """RDP target logon timing should not precede same-tuple eCAR FLOW visibility."""
    scenario = _make_scenario()
    target = next(system for system in scenario.environment.systems if system.hostname == "APP-01")
    user = scenario.environment.users[0]
    base_time = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)
    bundle = RdpSessionActionBundle(
        executor=Mock(),
        request=RdpSessionRequest(
            user=user,
            target_system=target,
            time=base_time,
            source_ip="10.10.10.50",
        ),
    )
    flow_window = get_timing_window(
        "source.ecar_flow",
        default_min_ms=40,
        default_max_ms=300,
        default_position="after",
        default_class="source_latency",
    )

    logon_time = bundle._target_logon_time(
        rng=random.Random(7),
        source_ip="10.10.10.50",
        src_port=52875,
        transport_start_time=base_time,
    )

    assert logon_time > base_time + timedelta(milliseconds=flow_window.max_ms)


def test_world_planner_moves_rdp_source_after_future_workstation_session(
    planner: WorldPlanner,
    state_manager: StateManager,
    systems: dict[str, System],
    users: dict[str, User],
    mock_emitters: dict[str, Mock],
) -> None:
    """Out-of-order RDP source activity should not create an earlier duplicate Type 2 logon."""
    future_session_start = datetime(2024, 1, 15, 10, 8, 0, tzinfo=UTC)
    state_manager.set_current_time(future_session_start)
    source_logon_id = state_manager.create_session(
        username=users["alice.admin"].username,
        system=systems["WKS-01"].hostname,
        logon_type=2,
        source_ip="-",
        start_time=future_session_start,
        session_kind="interactive",
    )
    mock_emitters["windows_event_security"].reset_mock()

    result = planner.bootstrap_user_session(
        user=users["alice.admin"],
        target_system=systems["APP-01"],
        time=datetime(2024, 1, 15, 10, 1, 0, tzinfo=UTC),
        rng=random.Random(11),
        session_kind="rdp",
        source_system=systems["WKS-01"],
        allow_existing=False,
    )

    assert result.session.start_time > future_session_start
    mstsc_processes = [
        proc
        for proc in state_manager.list_running_processes()
        if proc.system == "WKS-01" and proc.image.endswith("mstsc.exe")
    ]
    assert len(mstsc_processes) == 1
    assert mstsc_processes[0].start_time > future_session_start
    assert mstsc_processes[0].logon_id == source_logon_id
    emitted_logons = [
        call.args[0]
        for call in mock_emitters["windows_event_security"].emit.call_args_list
        if call.args[0].event_type == "logon"
    ]
    source_logons = [
        event
        for event in emitted_logons
        if event.dst_host and event.dst_host.hostname == systems["WKS-01"].hostname
    ]
    assert source_logons == []


def test_connection_owner_process_uses_scenario_internal_urls(
    monkeypatch: pytest.MonkeyPatch,
    scenario: Scenario,
    systems: dict[str, System],
    users: dict[str, User],
    state_manager: StateManager,
    mock_emitters: dict[str, Mock],
) -> None:
    """Catalog-owned connection processes should not leak default corp.local URLs."""
    world_model = WorldModel(scenario, "meridianhcs.local")
    dispatcher = EventDispatcher(state_manager=state_manager, emitters=mock_emitters)
    activity_generator = ActivityGenerator(state_manager, mock_emitters, dispatcher=dispatcher)
    activity_generator._ad_domain = world_model.ad_domain
    activity_generator._ip_to_system = dict(world_model.systems_by_ip)
    activity_generator._all_system_ips = [
        system.ip for system in world_model.scenario.environment.systems
    ]
    planner = WorldPlanner(world_model, state_manager, activity_generator)
    session_time = datetime(2024, 1, 15, 10, 20, 0, tzinfo=UTC)
    state_manager.set_current_time(session_time)
    logon_id = state_manager.create_session(
        username=users["dev.user"].username,
        system=systems["WKS-02"].hostname,
        logon_type=2,
        source_ip=systems["WKS-02"].ip,
        session_kind="interactive",
    )
    session = state_manager.get_session(logon_id)
    assert session is not None
    monkeypatch.setattr(
        "evidenceforge.generation.world_model.get_service_to_exes",
        lambda: {"ssl": ["firefox.exe"]},
    )

    pid = planner.ensure_connection_process(
        user=users["dev.user"],
        system=systems["WKS-02"],
        session=session,
        time=session_time,
        service="ssl",
        rng=random.Random(3),
    )

    proc = state_manager.get_process(systems["WKS-02"].hostname, pid)
    assert proc is not None
    assert "meridianhcs.local" in proc.command_line
    assert "corp.local" not in proc.command_line


def test_ldapsearch_connection_process_uses_scenario_base_dn_and_short_lifetime(
    monkeypatch: pytest.MonkeyPatch,
    scenario: Scenario,
    systems: dict[str, System],
    users: dict[str, User],
    state_manager: StateManager,
    mock_emitters: dict[str, Mock],
) -> None:
    """Server-side LDAP helper processes should not leak corp.local or stay open forever."""
    world_model = WorldModel(scenario, "meridianhcs.local")
    dispatcher = EventDispatcher(state_manager=state_manager, emitters=mock_emitters)
    activity_generator = ActivityGenerator(state_manager, mock_emitters, dispatcher=dispatcher)
    activity_generator._ad_domain = world_model.ad_domain
    activity_generator._ip_to_system = dict(world_model.systems_by_ip)
    activity_generator._all_system_ips = [
        system.ip for system in world_model.scenario.environment.systems
    ]
    planner = WorldPlanner(world_model, state_manager, activity_generator)
    session_time = datetime(2024, 1, 15, 10, 20, 0, tzinfo=UTC)
    state_manager.set_current_time(session_time)
    logon_id = state_manager.create_session(
        username=users["alice.admin"].username,
        system=systems["DB-01"].hostname,
        logon_type=11,
        source_ip=systems["WKS-01"].ip,
        session_kind="ssh",
    )
    session = state_manager.get_session(logon_id)
    assert session is not None
    monkeypatch.setattr(
        "evidenceforge.generation.world_model.get_service_to_exes",
        lambda: {"ldap": ["ldapsearch"]},
    )

    pid = planner.ensure_connection_process(
        user=users["alice.admin"],
        system=systems["DB-01"],
        session=session,
        time=session_time,
        service="ldap",
        rng=random.Random(3),
    )
    proc = state_manager.get_process(systems["DB-01"].hostname, pid)
    assert proc is not None
    assert "dc=meridianhcs,dc=local" in proc.command_line
    assert "dc=corp,dc=local" not in proc.command_line

    activity_generator.finalize_foreground_process_lifetimes(session_time + timedelta(minutes=1))
    events = [call.args[0] for call in mock_emitters["windows_event_security"].emit.call_args_list]
    creates = [event for event in events if event.event_type == "process_create"]
    terminates = [event for event in events if event.event_type == "process_terminate"]

    assert any(event.process and event.process.pid == pid for event in creates)
    terminate = next(event for event in terminates if event.process and event.process.pid == pid)
    create = next(event for event in creates if event.process and event.process.pid == pid)
    assert create.timestamp < terminate.timestamp
    assert (terminate.timestamp - session_time).total_seconds() < 10


def test_connection_owner_process_does_not_reuse_linux_shell(
    monkeypatch: pytest.MonkeyPatch,
    scenario: Scenario,
    state_manager: StateManager,
    mock_emitters: dict[str, Mock],
) -> None:
    """Linux web connections should be owned by a client process, not the login shell."""
    user = User(
        username="linux.dev",
        full_name="Linux Dev",
        email="linux.dev@corp.local",
        persona="developer",
        primary_system="LINUX-WS",
    )
    system = System(
        hostname="LINUX-WS",
        ip="10.10.10.60",
        os="Ubuntu 24.04",
        type="workstation",
        assigned_user=user.username,
    )
    scenario.environment.users.append(user)
    scenario.environment.systems.append(system)
    world_model = WorldModel(scenario, "meridianhcs.local")
    dispatcher = EventDispatcher(state_manager=state_manager, emitters=mock_emitters)
    activity_generator = ActivityGenerator(state_manager, mock_emitters, dispatcher=dispatcher)
    activity_generator._ad_domain = world_model.ad_domain
    activity_generator._ip_to_system = dict(world_model.systems_by_ip)
    activity_generator._all_system_ips = [
        system.ip for system in world_model.scenario.environment.systems
    ]
    planner = WorldPlanner(world_model, state_manager, activity_generator)
    session_time = datetime(2024, 1, 15, 10, 20, 0, tzinfo=UTC)
    state_manager.set_current_time(session_time)
    logon_id = state_manager.create_session(
        username=user.username,
        system=system.hostname,
        logon_type=2,
        source_ip=system.ip,
        session_kind="interactive",
    )
    session = state_manager.get_session(logon_id)
    assert session is not None
    systemd_pid = state_manager.create_process(
        system=system.hostname,
        parent_pid=0,
        image="/usr/lib/systemd/systemd",
        command_line="/usr/lib/systemd/systemd",
        username="root",
        integrity_level="System",
    )
    shell_pid = state_manager.create_process(
        system=system.hostname,
        parent_pid=systemd_pid,
        image="/bin/bash",
        command_line="-bash",
        username=user.username,
        integrity_level="Medium",
        logon_id=logon_id,
    )
    activity_generator._record_user_process(system, user, shell_pid, "/bin/bash")
    monkeypatch.setattr(
        "evidenceforge.generation.world_model.get_service_to_exes",
        lambda: {"ssl": ["bash", "curl"]},
    )

    pid = planner.ensure_connection_process(
        user=user,
        system=system,
        session=session,
        time=session_time + timedelta(minutes=5),
        service="ssl",
        rng=random.Random(3),
    )

    proc = state_manager.get_process(system.hostname, pid)
    assert proc is not None
    assert pid != shell_pid
    assert proc.image == "/usr/bin/curl"


def test_generic_linux_web_pid_inference_skips_shell(
    activity_generator: ActivityGenerator,
    systems: dict[str, System],
) -> None:
    """Fallback endpoint FLOW attribution should use a client process, not bash."""
    system = systems["DB-01"]
    activity_generator._system_pids = {
        system.hostname: {
            "bash": 1200,
            "curl": 1208,
        }
    }

    pid = activity_generator._infer_connection_pid(system, "ssl", 443, "tcp")

    assert pid == 1208


def test_linux_local_session_shell_has_visible_terminal_parent(
    activity_generator: ActivityGenerator,
    state_manager: StateManager,
    systems: dict[str, System],
    users: dict[str, User],
) -> None:
    """Local Linux login shells should not render as direct PID 1 children."""
    system = systems["DB-01"]
    user = users["alice.admin"]
    session_time = datetime(2024, 1, 15, 10, 20, 0, tzinfo=UTC)
    activity_time = session_time + timedelta(minutes=3)
    state_manager.set_current_time(session_time)
    logon_id = state_manager.create_session(
        username=user.username,
        system=system.hostname,
        logon_type=2,
        source_ip=system.ip,
        session_kind="interactive",
    )

    shell_pid = activity_generator.ensure_linux_session_shell(
        user=user,
        target_system=system,
        logon_id=logon_id,
        logon_time=session_time,
        activity_time=activity_time,
    )

    assert shell_pid is not None
    shell_proc = state_manager.get_process(system.hostname, shell_pid)
    assert shell_proc is not None
    assert shell_proc.parent_pid != 1
    parent_proc = state_manager.get_process(system.hostname, shell_proc.parent_pid)
    assert parent_proc is not None
    assert parent_proc.image in {"/bin/login", "/usr/libexec/gnome-terminal-server"}


def test_find_user_session_handles_mixed_timezone_start_times(
    planner: WorldPlanner,
    state_manager: StateManager,
) -> None:
    """Session lookup should not crash when start_time mixes naive and aware datetimes."""
    state_manager.set_current_time(datetime(2024, 1, 15, 10, 0, 0))
    state_manager.create_session(
        username="alice.admin",
        system="APP-01",
        logon_type=3,
        source_ip="10.10.10.50",
        session_kind="network",
    )
    state_manager.set_current_time(datetime(2024, 1, 15, 10, 5, 0, tzinfo=UTC))
    latest_id = state_manager.create_session(
        username="alice.admin",
        system="APP-01",
        logon_type=10,
        source_ip="10.10.10.50",
        session_kind="rdp",
    )

    selected = planner._find_user_session("alice.admin", "APP-01")

    assert selected is not None
    assert selected.logon_id == latest_id


def test_find_user_session_ignores_sessions_starting_after_activity_time(
    planner: WorldPlanner,
    state_manager: StateManager,
) -> None:
    """Session lookup should not reuse a future same-hour session."""
    state_manager.set_current_time(datetime(2024, 1, 15, 10, 55, 0, tzinfo=UTC))
    state_manager.create_session(
        username="alice.admin",
        system="APP-01",
        logon_type=10,
        source_ip="10.10.10.50",
        session_kind="rdp",
    )

    selected = planner._find_user_session(
        "alice.admin",
        "APP-01",
        at_time=datetime(2024, 1, 15, 10, 5, 0, tzinfo=UTC),
    )

    assert selected is None


def test_align_rdp_source_after_future_session_preserves_naive_time_awareness(
    planner: WorldPlanner,
    state_manager: StateManager,
    systems: dict[str, System],
) -> None:
    """RDP source alignment should keep naive caller datetimes naive."""
    state_manager.set_current_time(datetime(2024, 1, 1, 10, 0, 30, tzinfo=UTC))
    state_manager.create_session(
        username="alice.admin",
        system=systems["WKS-01"].hostname,
        logon_type=2,
        source_ip=systems["WKS-01"].ip,
        session_kind="interactive",
    )
    source_process_time = datetime(2024, 1, 1, 10, 0, 8)

    aligned = planner._align_rdp_source_after_future_workstation_session(
        username="alice.admin",
        source_system=systems["WKS-01"],
        source_process_time=source_process_time,
        rng=random.Random(0),
    )

    assert aligned.tzinfo is None
