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
from evidenceforge.events.observation import ObservationPolicy
from evidenceforge.generation.actions.rdp_session import RdpSessionActionBundle, RdpSessionRequest
from evidenceforge.generation.activity import ActivityGenerator
from evidenceforge.generation.activity.timing_profiles import get_timing_window
from evidenceforge.generation.source_timing import SourceTimingPlanner
from evidenceforge.generation.state_manager import StateManager
from evidenceforge.generation.world_model import HostCapability, WorldModel, WorldPlanner
from evidenceforge.models.scenario import (
    BaselineActivity,
    Environment,
    Group,
    OutputSpec,
    Scenario,
    StorageConfig,
    StorageServerConfig,
    StorylineEvent,
    System,
    TimeWindow,
    User,
)
from evidenceforge.validation import ScenarioValidator


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
                    services=["dns", "dhcp", "kerberos", "ldap"],
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


@pytest.mark.parametrize("service", ["cifs-utils", "smbclient"])
def test_linux_smb_client_packages_do_not_imply_server_role(service: str) -> None:
    """Linux client packages must not be mistaken for Samba server services."""
    scenario = _make_scenario()
    client = System(
        hostname="LINUX-CLIENT",
        ip="10.10.10.61",
        os="Ubuntu 24.04",
        type="workstation",
        services=[service],
    )
    scenario.environment.systems = [client]

    model = WorldModel(scenario, "corp.local")
    host = model.hosts[client.hostname]

    assert host.supports(HostCapability.SMB_CLIENT)
    assert not host.supports(HostCapability.SMB_SERVER)
    assert "file_server" not in host.canonical_roles


def test_linux_gvfs_is_transport_texture_not_canonical_smb_capability() -> None:
    """GVFS may own opaque TCP/445 but must not schedule typed SMB activity."""
    scenario = _make_scenario()
    client = System(
        hostname="LINUX-DESKTOP",
        ip="10.10.10.62",
        os="Ubuntu 24.04",
        type="workstation",
        services=["gvfs-smb"],
    )
    scenario.environment.systems = [client]

    model = WorldModel(scenario, "corp.local")

    assert not model.hosts[client.hostname].supports(HostCapability.SMB_CLIENT)
    assert not model.hosts[client.hostname].supports(HostCapability.SMB_SERVER)


@pytest.mark.parametrize("service", ["samba", "smbd", "smb-server"])
def test_linux_samba_services_imply_server_not_client(service: str) -> None:
    """Samba daemon labels should declare only the Linux SMB server capability."""
    scenario = _make_scenario()
    server = System(
        hostname="SAMBA-01",
        ip="10.10.20.61",
        os="Ubuntu 24.04",
        type="server",
        services=[service],
    )
    scenario.environment.systems = [server]

    model = WorldModel(scenario, "corp.local")
    host = model.hosts[server.hostname]

    assert host.supports(HostCapability.SMB_SERVER)
    assert not host.supports(HostCapability.SMB_CLIENT)
    assert "file_server" in host.canonical_roles


def test_generic_linux_file_server_role_does_not_imply_samba() -> None:
    """A Linux file-server label alone must not invent a Samba deployment."""
    scenario = _make_scenario()
    server = System(
        hostname="LINUX-FILES-01",
        ip="10.10.20.63",
        os="Ubuntu 24.04",
        type="server",
        roles=["file_server"],
        services=["nfs"],
    )
    scenario.environment.systems = [server]

    model = WorldModel(scenario, "corp.local")

    assert not model.hosts[server.hostname].supports(HostCapability.SMB_SERVER)


def test_generic_linux_smb_label_does_not_choose_client_or_server_capability() -> None:
    """An ambiguous Linux SMB label must be replaced by an explicit client or server marker."""
    scenario = _make_scenario()
    system = System(
        hostname="LINUX-SMB-01",
        ip="10.10.20.64",
        os="Ubuntu 24.04",
        type="server",
        services=["smb"],
    )
    scenario.environment.systems = [system]

    host = WorldModel(scenario, "corp.local").hosts[system.hostname]

    assert not host.supports(HostCapability.SMB_CLIENT)
    assert not host.supports(HostCapability.SMB_SERVER)


def test_storage_server_reference_implies_smb_server_capability() -> None:
    """Explicit storage topology should make a Linux host an SMB server."""
    scenario = _make_scenario()
    server = System(
        hostname="STORAGE-01",
        ip="10.10.20.62",
        os="Rocky Linux 9",
        type="server",
    )
    scenario.environment.systems = [server]
    scenario.environment.storage = StorageConfig(
        servers=[StorageServerConfig(system=server.hostname, presets=["collaboration"])]
    )

    model = WorldModel(scenario, "corp.local")
    host = model.hosts[server.hostname]

    assert host.supports(HostCapability.SMB_SERVER)
    assert "file_server" in host.canonical_roles
    assert "smb-server" in model.service_defaults_by_host[server.hostname]


def test_windows_smb_capability_defaults_are_role_aware() -> None:
    """Windows clients are universal while server capability follows host type."""
    scenario = _make_scenario()
    workstation, server = scenario.environment.systems[0], scenario.environment.systems[2]
    scenario.environment.systems = [workstation, server]

    model = WorldModel(scenario, "corp.local")

    assert model.hosts[workstation.hostname].supports(HostCapability.SMB_CLIENT)
    assert not model.hosts[workstation.hostname].supports(HostCapability.SMB_SERVER)
    assert model.hosts[server.hostname].supports(HostCapability.SMB_CLIENT)
    assert model.hosts[server.hostname].supports(HostCapability.SMB_SERVER)


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
    assert dc_host.supports(HostCapability.DNS_RESOLVER)
    assert dc_host.supports(HostCapability.DHCP_SERVER)
    assert dc_host.supports(HostCapability.DOMAIN_CONTROLLER)
    assert dc_host.supports(HostCapability.RDP_RECEIVER)

    infra = world_model.to_infrastructure_ips()
    assert infra["dc"] == [systems["DC-01"].ip]
    assert infra["dhcp"] == [systems["DC-01"].ip]
    assert infra["db_servers"] == [
        {"ip": systems["DB-01"].ip, "port": 5432, "service": "postgresql"}
    ]
    assert world_model.proxy_routes[systems["WKS-01"].ip][0].hostname == "PROXY-01"


def test_world_model_does_not_collapse_missing_infrastructure_onto_only_host() -> None:
    """A one-host world must keep absent local capabilities empty and use public DNS."""
    scenario = _make_scenario()
    only_host = scenario.environment.systems[0]
    scenario.environment.systems = [only_host]
    model = WorldModel(scenario, "corp.local")

    infra = model.to_infrastructure_ips()

    assert infra["dhcp"] == []
    assert infra["dc"] == []
    assert infra["dc_hostnames"] == []
    assert infra["dns"]
    assert only_host.ip not in infra["dns"]


def test_authored_dhcp_requires_distinct_modeled_server() -> None:
    """Validation should reject DHCP intent when no distinct server owns the action."""
    scenario = _make_scenario()
    target = scenario.environment.systems[0]
    scenario.environment.systems = [target]
    scenario.storyline = [
        StorylineEvent(
            id="dhcp-no-server",
            time="2024-01-15T10:30:00Z",
            actor="alice.admin",
            system=target.hostname,
            activity="Renew a lease",
            events=[{"type": "dhcp_lease"}],
        )
    ]

    issues = ScenarioValidator(scenario).validate()

    assert any(
        issue.severity == "error"
        and issue.field_path == "storyline.0.events.0"
        and "no distinct modeled DHCP server" in issue.message
        for issue in issues
    )


def test_authored_dhcp_accepts_explicit_distinct_server() -> None:
    """A dedicated DHCP capability should satisfy authored lease preflight."""
    scenario = _make_scenario()
    target = scenario.environment.systems[0]
    scenario.environment.systems = [
        target,
        System(
            hostname="DHCP-01",
            ip="10.10.100.20",
            os="Windows Server 2022",
            type="server",
            roles=["dhcp_server"],
            services=["windows-dhcp-server"],
        ),
    ]
    scenario.storyline = [
        StorylineEvent(
            id="dhcp-with-server",
            time="2024-01-15T10:30:00Z",
            actor="alice.admin",
            system=target.hostname,
            activity="Renew a lease",
            events=[{"type": "dhcp_lease"}],
        )
    ]

    issues = ScenarioValidator(scenario).validate()

    assert not any("DHCP lease" in issue.message for issue in issues)


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


def test_world_planner_delegates_session_allocation_to_logon_bundle(
    world_model: WorldModel,
    state_manager: StateManager,
    systems: dict[str, System],
    users: dict[str, User],
) -> None:
    """World planning requests session intent without allocating shadow state."""
    activity_generator = Mock()

    def generate_logon(**kwargs):
        return state_manager.create_session(
            username=kwargs["user"].username,
            system=kwargs["system"].hostname,
            logon_type=kwargs["logon_type"],
            source_ip=kwargs["source_ip"],
            start_time=kwargs["time"],
            lifecycle_group_id="bundle-owned-session",
        )

    activity_generator.generate_logon.side_effect = generate_logon
    planner = WorldPlanner(world_model, state_manager, activity_generator)

    result = planner.bootstrap_user_session(
        user=users["alice.admin"],
        target_system=systems["WKS-01"],
        time=datetime(2024, 1, 15, 10, 5, 0, tzinfo=UTC),
        rng=random.Random(7),
        session_kind="interactive",
        allow_existing=False,
    )

    assert state_manager.get_session(result.session.logon_id) is result.session
    assert result.session.lifecycle_group_id == "bundle-owned-session"
    call_kwargs = activity_generator.generate_logon.call_args.kwargs
    assert "logon_id" not in call_kwargs
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


def test_world_planner_does_not_resurrect_session_ended_during_logon_backdate(
    planner: WorldPlanner,
    state_manager: StateManager,
    systems: dict[str, System],
    users: dict[str, User],
) -> None:
    """A backdated logon must not return a historically valid but ended session."""
    activity_time = datetime(2024, 1, 15, 11, 0, 0, tzinfo=UTC)
    state_manager.set_current_time(activity_time - timedelta(hours=1))
    ended_logon_id = state_manager.create_session(
        username=users["alice.admin"].username,
        system=systems["WKS-01"].hostname,
        logon_type=2,
        source_ip="-",
        session_kind="interactive",
    )
    state_manager.end_session(
        ended_logon_id,
        activity_time - timedelta(milliseconds=250),
    )

    result = planner.bootstrap_user_session(
        user=users["alice.admin"],
        target_system=systems["WKS-01"],
        time=activity_time,
        rng=random.Random(29),
        session_kind="interactive",
    )

    assert result.session.logon_id != ended_logon_id
    assert state_manager.get_session(result.session.logon_id) is result.session


def test_find_windows_interactive_does_not_return_historical_ended_owner(
    planner: WorldPlanner,
    state_manager: StateManager,
    systems: dict[str, System],
    users: dict[str, User],
) -> None:
    """Non-monotonic Windows lookup must not reuse an already-retired owner."""

    session_start = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)
    activity_time = session_start + timedelta(minutes=30)
    state_manager.set_current_time(session_start)
    logon_id = state_manager.create_session(
        username=users["alice.admin"].username,
        system=systems["WKS-01"].hostname,
        logon_type=2,
        source_ip="-",
        session_kind="interactive",
    )
    historical = state_manager.get_session(logon_id)
    assert historical is not None
    state_manager.end_session(logon_id, session_start + timedelta(hours=1))
    historical_activity = historical.last_activity_time

    selected = planner._find_windows_interactive_session(
        users["alice.admin"].username,
        systems["WKS-01"],
        activity_time,
    )

    assert selected is None
    assert historical.last_activity_time == historical_activity


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
    state_manager.register_boot_time(
        systems["WKS-01"].hostname,
        datetime(2024, 1, 15, 9, 50, 0, tzinfo=UTC),
    )
    state_manager.set_current_time(seed_time)
    smss_pid = state_manager.create_process(
        systems["WKS-01"].hostname,
        0,
        r"C:\Windows\System32\smss.exe",
        r"C:\Windows\System32\smss.exe",
        "SYSTEM",
        "System",
    )
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
        systems["WKS-01"].hostname: {"smss": smss_pid},
        systems["DB-01"].hostname: {"systemd": systemd_pid, "sshd": sshd_pid},
    }
    activity_generator._users_by_username = {users["alice.admin"].username: users["alice.admin"]}
    state_manager.create_session(
        username=users["alice.admin"].username,
        system=systems["WKS-01"].hostname,
        logon_type=2,
        source_ip=systems["WKS-01"].ip,
        session_kind="interactive",
        start_time=datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC),
    )

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
    responder_pid = session.transport_pid
    assert session.session_shell_pid is not None
    assert session.source_ready_time is not None
    assert session.network_close_time is not None
    assert session.network_close_time >= datetime(2024, 1, 15, 10, 45, 0, tzinfo=UTC)
    session_shell_pid = session.session_shell_pid
    shell = state_manager.get_process(systems["DB-01"].hostname, session_shell_pid)
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
    session_bash_events = [
        event
        for event in process_events
        if event.process is not None
        and event.process.image == "/bin/bash"
        and event.process.logon_id == session.logon_id
    ]
    assert len(session_bash_events) == 1
    assert bash_events == session_bash_events
    sshd_events = [
        event
        for event in process_events
        if event.process is not None
        and event.process.command_line == f"sshd: {users['alice.admin'].username} [priv]"
    ]
    assert len(sshd_events) == 1
    assert sshd_events[0].process.pid == responder_pid
    assert sshd_events[0].auth.logon_id == "0x3e7"
    assert sshd_events[0].auth.session_id == 0
    assert bash_events[0].process.parent_image == "/usr/sbin/sshd"
    assert session.transport_pid > 180_000
    assert result.network_uid
    assert activity_generator._pending_ssh_session_closures

    connection = state_manager.get_connection_by_zeek_uid(result.network_uid)
    assert connection is not None
    assert connection.close_time is not None
    # The SSH bundle now owns a causally prior source client. It remains safe to
    # attribute the transport without moving TCP open behind authentication.
    assert connection.initiating_pid > 0
    source_client_events = [
        event
        for event in process_events
        if event.src_host is not None
        and event.src_host.hostname == systems["WKS-01"].hostname
        and event.process is not None
        and event.process.pid == connection.initiating_pid
    ]
    assert len(source_client_events) == 1
    assert source_client_events[0].process.image.lower().endswith(("ssh", "ssh.exe"))
    assert source_client_events[0].process.start_time < connection.start_time
    source_terminate_events = [
        call.args[0]
        for call in mock_emitters["windows_event_security"].emit.call_args_list
        if call.args[0].event_type == "process_terminate"
        and call.args[0].src_host is not None
        and call.args[0].src_host.hostname == systems["WKS-01"].hostname
        and call.args[0].process is not None
        and call.args[0].process.image.lower().endswith(("ssh", "ssh.exe"))
    ]
    assert len(source_terminate_events) == 1
    assert connection.close_time < source_terminate_events[0].timestamp
    assert source_terminate_events[0].timestamp <= connection.close_time + timedelta(seconds=2)

    activity_generator.finalize_ssh_session_lifecycles(datetime(2024, 1, 15, 12, 0, 0, tzinfo=UTC))

    assert state_manager.get_session(session.logon_id) is None
    syslog_messages = [
        call.args[0].syslog.message
        for call in mock_emitters["windows_event_security"].emit.call_args_list
        if call.args[0].syslog is not None
    ]
    assert f"pam_unix(sshd:session): session closed for user {session.username}" in syslog_messages
    assert any(message.startswith("Removed session ") for message in syslog_messages)
    shell_terminate_event = next(
        call.args[0]
        for call in mock_emitters["windows_event_security"].emit.call_args_list
        if call.args[0].event_type == "process_terminate"
        and call.args[0].process is not None
        and call.args[0].process.pid == session_shell_pid
    )
    responder_terminate_event = next(
        call.args[0]
        for call in mock_emitters["windows_event_security"].emit.call_args_list
        if call.args[0].event_type == "process_terminate"
        and call.args[0].process is not None
        and call.args[0].process.pid == responder_pid
    )
    session_close_event = next(
        call.args[0]
        for call in mock_emitters["windows_event_security"].emit.call_args_list
        if call.args[0].event_type == "logoff"
        and call.args[0].auth is not None
        and call.args[0].auth.logon_id == session.logon_id
    )
    assert shell_terminate_event.timestamp < session_close_event.timestamp
    assert responder_terminate_event.auth.logon_id == sshd_events[0].auth.logon_id
    assert responder_terminate_event.auth.session_id == sshd_events[0].auth.session_id


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


def test_world_planner_preserves_authored_linux_rdp_source_as_network_only(
    scenario: Scenario,
    mock_emitters: dict[str, Mock],
) -> None:
    """An authored Linux source IP must not become a fabricated Windows RDP client."""

    linux_source = System(
        hostname="LT-MRIVERA-02",
        ip="10.10.1.99",
        os="Ubuntu 24.04",
        type="workstation",
    )
    scenario.environment.systems.append(linux_source)
    world_model = WorldModel(scenario, "corp.local")
    state_manager = StateManager()
    dispatcher = EventDispatcher(state_manager=state_manager, emitters=mock_emitters)
    activity_generator = ActivityGenerator(state_manager, mock_emitters, dispatcher=dispatcher)
    activity_generator._ad_domain = world_model.ad_domain
    activity_generator._ip_to_system = dict(world_model.systems_by_ip)
    activity_generator._all_system_ips = [
        system.ip for system in world_model.scenario.environment.systems
    ]
    planner = WorldPlanner(world_model, state_manager, activity_generator)
    target = world_model.hosts["APP-01"].system
    user = world_model.users["alice.admin"].user

    plan = world_model.plan_session(
        user=user,
        target_system=target,
        rng=random.Random(11),
        session_kind="rdp",
        source_system=linux_source,
        source_ip_override=linux_source.ip,
    )
    assert plan.source_ip == "10.10.1.99"
    assert plan.source_system is None

    result = planner.bootstrap_user_session(
        user=user,
        target_system=target,
        time=datetime(2024, 1, 15, 10, 20, 0, tzinfo=UTC),
        rng=random.Random(11),
        session_kind="rdp",
        source_system=linux_source,
        source_ip_override=linux_source.ip,
        allow_existing=False,
    )

    session = state_manager.get_session(result.session.logon_id)
    assert session is not None
    assert session.source_ip == "10.10.1.99"
    assert session.transport_pid is None
    rdp_connections = [
        connection
        for connection in state_manager.list_open_connections()
        if connection.dst_port == 3389
    ]
    assert len(rdp_connections) == 1
    assert rdp_connections[0].src_ip == "10.10.1.99"
    assert rdp_connections[0].initiating_pid == -1
    assert not any(
        process.image.casefold().endswith("mstsc.exe")
        for process in state_manager.list_running_processes()
    )
    assert not any(connection.source_system.startswith("WKS-") for connection in rdp_connections)


def test_rdp_preserved_network_only_source_skips_modeled_host_rediscovery(
    scenario: Scenario,
) -> None:
    """The RDP bundle must retain the planner's deliberate source-host absence."""

    linux_source = System(
        hostname="LT-MRIVERA-02",
        ip="10.10.1.99",
        os="Ubuntu 24.04",
        type="workstation",
    )
    target = next(system for system in scenario.environment.systems if system.hostname == "APP-01")
    user = next(user for user in scenario.environment.users if user.username == "alice.admin")
    executor = Mock()
    executor._ip_to_system = {linux_source.ip: linux_source, target.ip: target}
    bundle = RdpSessionActionBundle(
        executor=executor,
        request=RdpSessionRequest(
            user=user,
            target_system=target,
            time=datetime(2024, 1, 15, 10, 20, 0, tzinfo=UTC),
            source_ip=linux_source.ip,
            source_system=None,
            source_pid=-1,
            preserve_explicit_source=True,
        ),
    )

    assert bundle._resolve_source(random.Random(11), user) == (linux_source.ip, None, -1)


def test_rdp_target_logon_uses_canonical_transport_phase_gap() -> None:
    """RDP auth without a modeled source should use only the transport phase gap."""
    scenario = _make_scenario()
    target = next(system for system in scenario.environment.systems if system.hostname == "APP-01")
    user = scenario.environment.users[0]
    base_time = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)
    executor = Mock()
    executor._ip_to_system = {}
    bundle = RdpSessionActionBundle(
        executor=executor,
        request=RdpSessionRequest(
            user=user,
            target_system=target,
            time=base_time,
            source_ip="10.10.10.50",
        ),
    )
    logon_time = bundle._target_logon_time(
        source_ip="10.10.10.50",
        src_port=52875,
        transport_start_time=base_time,
    )

    assert base_time + timedelta(milliseconds=900) <= logon_time
    assert logon_time <= base_time + timedelta(milliseconds=1600)


def test_rdp_target_logon_reserves_modeled_source_flow_and_clock_headroom() -> None:
    """Modeled RDP auth must remain after source FLOW across valid endpoint clocks."""

    scenario = _make_scenario()
    source = next(system for system in scenario.environment.systems if system.hostname == "WKS-01")
    target = next(system for system in scenario.environment.systems if system.hostname == "APP-01")
    user = scenario.environment.users[0]
    base_time = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)
    executor = Mock()
    executor.dispatcher.observation_policy = ObservationPolicy("enterprise_standard")
    source_timing_planner = SourceTimingPlanner("enterprise_standard")
    executor._source_timing_planner = source_timing_planner
    executor.dispatcher.source_timing_planner = source_timing_planner
    executor._ip_to_system = {source.ip: source, target.ip: target}
    bundle = RdpSessionActionBundle(
        executor=executor,
        request=RdpSessionRequest(
            user=user,
            target_system=target,
            time=base_time,
            source_ip=source.ip,
            source_system=source,
        ),
    )

    logon_time = bundle._target_logon_time(
        source_ip=source.ip,
        src_port=52875,
        transport_start_time=base_time,
    )

    source_clock_headroom = source_timing_planner.endpoint_clock_positive_headroom(
        base_time,
        "windows",
    )
    target_clock_headroom = source_timing_planner.endpoint_clock_negative_headroom(
        base_time + source_clock_headroom,
        "windows",
    )
    flow_window = get_timing_window(
        "source.ecar_flow",
        default_min_ms=180,
        default_max_ms=1800,
        default_position="after",
        default_class="source_latency",
    )
    assert logon_time > (
        base_time
        + source_clock_headroom
        + target_clock_headroom
        + timedelta(milliseconds=flow_window.max_ms + 25)
    )


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


def test_exact_custom_application_without_system_types_is_eligible(
    monkeypatch: pytest.MonkeyPatch,
    planner: WorldPlanner,
    systems: dict[str, System],
    users: dict[str, User],
    state_manager: StateManager,
) -> None:
    """Omitted custom-process system types allow every supported host type."""

    session_time = datetime(2024, 1, 15, 10, 20, 0, tzinfo=UTC)
    system = systems["WKS-02"]
    user = users["dev.user"]
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
    exact_application = {
        "id": "custom:case-client",
        "personas": [user.persona],
        "platforms": {
            "windows": {
                "image_path": r"C:\Program Files\Case Client\case-client.exe",
                "command_templates": ["case-client.exe --review"],
            }
        },
        "categories": ["user_app"],
        "system_types": None,
        "selection_weight": 7,
        "singleton_per_session": False,
    }
    monkeypatch.setattr(
        "evidenceforge.generation.activity.application_catalog.get_applications_for_ids",
        lambda _application_ids, _os_category: [exact_application],
    )
    monkeypatch.setattr(
        "evidenceforge.generation.activity.application_catalog.get_executables_for_application_ids",
        lambda _application_ids, _os_category: ["case-client.exe"],
    )

    pid = planner.ensure_connection_process(
        user=user,
        system=system,
        session=session,
        time=session_time,
        service="ssl",
        rng=random.Random(11),
        application_ids=["custom:case-client"],
    )

    process = state_manager.get_process(system.hostname, pid)
    assert process is not None
    assert process.image == r"C:\Program Files\Case Client\case-client.exe"
    assert process.command_line == "case-client.exe --review"


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
    user_manager = state_manager.get_process(system.hostname, parent_proc.parent_pid)
    session = state_manager.get_session(logon_id)
    assert user_manager is not None
    assert session is not None
    assert parent_proc.lifecycle_group_id == session.lifecycle_group_id
    assert shell_proc.lifecycle_group_id == session.lifecycle_group_id
    assert (
        activity_generator.foreground_process_termination_time(system.hostname, parent_proc.pid)
        is None
    )
    assert (
        activity_generator.foreground_process_termination_time(system.hostname, shell_proc.pid)
        is None
    )
    if parent_proc.image == "/bin/login":
        assert user_manager.image in {"/sbin/init", "/usr/lib/systemd/systemd"}
        assert user_manager.lifecycle_group_id != session.lifecycle_group_id
    else:
        assert user_manager.lifecycle_group_id == session.lifecycle_group_id

    activity_generator.finalize_foreground_process_lifetimes(activity_time + timedelta(minutes=1))

    assert state_manager.get_process(system.hostname, parent_proc.pid) is parent_proc
    assert state_manager.get_process(system.hostname, shell_proc.pid) is shell_proc


def test_pre_window_linux_session_keeps_login_parent_before_collection(
    activity_generator: ActivityGenerator,
    state_manager: StateManager,
    systems: dict[str, System],
    users: dict[str, User],
) -> None:
    """A lazily materialized shell must not invent an in-window local login."""
    system = systems["DB-01"]
    user = users["alice.admin"]
    scenario_start = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)
    session_time = scenario_start - timedelta(hours=2)
    activity_time = scenario_start + timedelta(minutes=5)
    activity_generator._scenario_start_time = scenario_start
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
    shell = state_manager.get_process(system.hostname, shell_pid)
    assert shell is not None
    login_parent = state_manager.get_process(system.hostname, shell.parent_pid)
    assert login_parent is not None
    assert login_parent.image == "/bin/login"
    assert login_parent.start_time < scenario_start
    assert shell.start_time >= scenario_start


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


def test_ssh_bootstrap_does_not_attach_to_historical_ended_owner(
    world_model: WorldModel,
    state_manager: StateManager,
    systems: dict[str, System],
    users: dict[str, User],
) -> None:
    """Session bootstrap cannot attach new state to an already-closed owner."""

    start_time = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)
    state_manager.set_current_time(start_time)
    logon_id = state_manager.create_session(
        username="alice.admin",
        system=systems["DB-01"].hostname,
        logon_type=10,
        source_ip=systems["WKS-01"].ip,
        session_kind="ssh",
    )
    historical = state_manager.get_session(logon_id)
    assert historical is not None
    state_manager.end_session(logon_id, start_time + timedelta(hours=1))
    historical_activity = historical.last_activity_time

    activity_generator = Mock()

    def execute_ssh_session_bundle(**kwargs):
        replacement_logon_id = state_manager.create_session(
            username=kwargs["user"].username,
            system=kwargs["target_system"].hostname,
            logon_type=10,
            source_ip=kwargs["source_ip"],
            start_time=kwargs["time"],
            session_kind="ssh",
        )
        return "replacement-network-uid", replacement_logon_id

    activity_generator._execute_ssh_session_bundle.side_effect = execute_ssh_session_bundle
    planner = WorldPlanner(world_model, state_manager, activity_generator)

    selected = planner.bootstrap_user_session(
        user=users["alice.admin"],
        target_system=systems["DB-01"],
        source_system=systems["WKS-01"],
        time=start_time + timedelta(minutes=30),
        rng=random.Random(31),
        session_kind="ssh",
    )

    assert selected.session.logon_id != logon_id
    assert historical.last_activity_time == historical_activity
    activity_generator.ensure_linux_ssh_session_shell.assert_called_once()
    assert (
        activity_generator.ensure_linux_ssh_session_shell.call_args.kwargs["logon_id"]
        == selected.session.logon_id
    )


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
